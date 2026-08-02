//! Quality presets, SetEncodings list construction, and the adaptive Auto
//! tuner (PRD/09).
//!
//! [`AutoTuner`] keeps a windowed maximum of measured link capacity, decaying
//! averages of RTT and decode time, walks the tier ladder in §3.2, and applies
//! mandatory hysteresis: a tier change must be sustained for at least
//! [`SUSTAIN`] before it is offered, and switches never happen more often than
//! once per [`COOLDOWN`].

use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::types::{encoding, ColorDepth, QualityPreset, QualitySettings, ServerCapabilities};

/// A tier change must hold this long before it is recommended.
pub const SUSTAIN: Duration = Duration::from_secs(2);
/// Minimum spacing between accepted tier switches.
pub const COOLDOWN: Duration = Duration::from_secs(5);
/// Client decode budget per frame; sustained overruns trigger compression
/// relief (PRD/09 §3.2).
pub const FRAME_BUDGET_MS: f32 = 16.0;

/// EWMA time constant. ~0.7 s gives an effective window of roughly 2 s.
const TAU_S: f64 = 0.7;

/// A burst must gather this many bytes before it is timed: a packet TRAIN
/// (~11 MSS), not a pair.
///
/// Timing one segment measures the *last hop's* line rate, a segment coming
/// off a gigabit NIC always reads gigabit whatever actually fed it. Requiring
/// a train bounds the error from residual buffering to roughly `1 + gap/T`
/// where `T = MIN_BURST_BYTES/rate`: at 1 Mbit/s, T is ~131ms so the error is
/// a few percent; at 1 Gbit/s the bound is meaningless, but the link is
/// already fast so it decides nothing. The slower the true link, the tighter
/// the guarantee.
pub(crate) const MIN_BURST_BYTES: u64 = 16 * 1024;

/// Minimum elapsed time for a completed burst to be trusted.
///
/// Below this we are timing syscall/wakeup overhead, not the wire, AND (the
/// bug this bound used to miss at 100 µs) a kernel socket buffer or an
/// in-process carrier (the SSH tunnel's mpsc channel) can hand a whole
/// backlog to one `poll_read` in well under a millisecond: that backlog was
/// genuinely queued, not delivered, but timing it over a sub-millisecond
/// interval reads it as multi-gigabit regardless of the real link. Several
/// milliseconds is long enough that a kernel/tunnel handoff (microseconds)
/// cannot pass for it, while still being far shorter than any real stall this
/// type needs to see through.
pub(crate) const MIN_BURST_S: f64 = 2e-3;

/// Reject a completed sample above this rate as a measurement artifact rather
/// than fold it into the window: nothing this client is ever plugged into
/// legitimately delivers more than this over the interface being measured, so
/// a "sample" past it is backlog draining, not the wire, and folding it in
/// would let one bad reading pin the ladder at High for up to `2*LINK_WINDOW`
/// (see [`AutoTuner::record_link`]). [`MIN_BURST_S`] already filters most of
/// these; this is the backstop for the ones that still clear it (a large
/// enough backlog can span a few milliseconds and still be absurd).
const PLAUSIBLE_CEILING_BPS: f64 = 2e9;

/// Abandon a burst that has not gathered [`MIN_BURST_BYTES`] within this long,
/// so an idle desktop can't slowly accrue traffic into a fake sample.
const MAX_BURST_S: f64 = 4.0;

/// How long a link-capacity sample stays eligible for the rotating max
/// (see [`AutoTuner::record_link`]).
const LINK_WINDOW: Duration = Duration::from_secs(5);

/// Nominal tier boundaries (PRD/09 §3.2), named so the hysteresis math in
/// [`Tier::from_link`] stays legible.
const HIGH_BPS: f64 = 20e6;
const MEDIUM_BPS: f64 = 5e6;
const LOWISH_BPS: f64 = 1e6;

/// Falling back below a boundary requires dropping under this fraction of
/// it, so a link oscillating right at the nominal value does not flap the
/// tier every sample: clearing the boundary upgrades, but only a genuine
/// drop below 0.8x of it downgrades back.
const DOWNGRADE_HYSTERESIS: f64 = 0.8;

/// Relief (see [`AutoTuner::observe_at`]) only ever engages when the link is
/// demonstrably fast enough that `decode_ms` measuring the CPU rather than
/// the wire is a safe assumption (PRD/09 §3.2, and the module doc on
/// `decode_ms`). `decode_rect` awaits socket reads, so on anything slower,
/// `decode_ms` is mostly telling you the LINK is slow, and reducing
/// compression in response is backwards. This threshold coincides with the
/// High tier's nominal boundary: relief is a High-tier-only behaviour.
const RELIEF_MIN_CAPACITY_BPS: f64 = HIGH_BPS;

/// Relief releases once `decode_ms` falls back under this fraction of
/// [`FRAME_BUDGET_MS`], not the instant it dips under the budget itself, so a
/// decode time hovering right at the budget does not flicker relief on and
/// off every sample.
const RELIEF_OFF_RATIO: f32 = 0.75;

/// Stall-anchored burst sampler (BBR's delivery-rate model, applied to a
/// single TCP read side).
///
/// Soundness argument: if the socket was observed EMPTY at t0, and B bytes
/// have been handed to us by t1, then all B bytes crossed the wire within
/// `[t0, t1]`, so the link carried at least `B / (t1 - t0)`. That is a valid
/// LOWER BOUND on capacity regardless of how slow the server's encoder is,
/// because a slow link cannot physically deliver a fast burst.
///
/// There is deliberately NO stall-classification heuristic here: at 1 Mbit/s
/// an inter-segment gap (~12 ms) and a Raspberry Pi encode stall (~30 ms) are
/// the same order of magnitude, so no threshold reliably tells one from the
/// other. A burst that straddles a server stall just reports a smaller
/// number and loses to the windowed max (see [`AutoTuner::record_link`]);
/// it is never wrong, only less tight.
///
/// Two further bounds keep the anchor itself honest against backlog, not
/// stalls: a completed burst must SPAN at least [`MIN_BURST_S`] of wall
/// clock, so a kernel socket buffer or an in-process carrier (the SSH
/// tunnel's mpsc channel) handing a whole backlog to one read cannot read as
/// an instantaneous, arbitrarily fast transfer; and any sample that still
/// clears that bar but comes out above [`PLAUSIBLE_CEILING_BPS`] is dropped
/// as a measurement artifact rather than folded into the window. Neither
/// bound can make a genuinely slow link look fast: both only ever throw a
/// sample away, never inflate one.
#[derive(Debug, Default)]
pub(crate) struct LinkMeter {
    /// The socket has been observed empty (a `Poll::Pending`) since the last
    /// completed burst.
    drained: bool,
    /// When the current burst started, if one is open.
    started: Option<Instant>,
    /// Bytes accumulated in the current burst.
    bytes: u64,
}

impl LinkMeter {
    /// Record that a poll found the socket empty. Must NOT end a burst in
    /// progress: on a genuinely slow link the socket goes empty between
    /// every segment, so ending bursts on stall would make slow links
    /// unmeasurable, the exact opposite of this type's purpose.
    pub(crate) fn stalled(&mut self) {
        self.drained = true;
    }

    /// Record `n` bytes delivered at `now`. Returns a completed sample in
    /// bits/sec, if this delivery completed one.
    pub(crate) fn received(&mut self, now: Instant, n: usize) -> Option<f64> {
        if n == 0 {
            return None;
        }
        if self.started.is_none() {
            if !self.drained {
                // No burst running and the socket was never observed empty:
                // there is nothing to anchor a start time to.
                return None;
            }
            // The bytes that just ENDED the stall are not counted: they had
            // already queued while we were decoding, and crediting them to an
            // interval they did not cross the wire in is exactly how a slow
            // link reads as gigabit.
            self.drained = false;
            self.started = Some(now);
            self.bytes = 0;
            return None;
        }

        let started = self.started.expect("checked above");
        self.bytes += n as u64;

        // Computed BEFORE the byte-threshold check (and used by it): a
        // delivery that happens to cross MIN_BURST_BYTES after the burst has
        // sat open for MAX_BURST_S must still be abandoned. It used to only
        // be checked in the branch below, so a burst that lingered under
        // threshold for 30 s and then finally crossed it on one delivery
        // completed anyway, timed over the whole 30 s, reading a gigabit LAN
        // as ~5 kbit/s.
        let elapsed = now.saturating_duration_since(started).as_secs_f64();
        if elapsed >= MAX_BURST_S {
            // This burst has been open too long: an idle desktop trickling
            // bytes must not slowly accrue into a fake sample, however this
            // particular delivery happened to land relative to the byte
            // threshold. Start over; a fresh stall is required to open the
            // next one.
            self.started = None;
            self.bytes = 0;
            self.drained = false;
            return None;
        }

        if self.bytes < MIN_BURST_BYTES {
            return None;
        }

        if elapsed < MIN_BURST_S {
            // Too little wall-clock time has passed to trust either the
            // clock or the sample: see `MIN_BURST_S`'s doc for why this also
            // guards against backlog (kernel buffer / SSH tunnel mpsc)
            // draining in a fraction of a millisecond. Keep accumulating.
            return None;
        }

        let bps = self.bytes as f64 * 8.0 / elapsed;
        if bps > PLAUSIBLE_CEILING_BPS {
            // Implausible for any real last-hop this client measures:
            // backlog draining, not the wire. Treat it like a burst that
            // never happened rather than fold it into the window; a fresh
            // stall is required to open the next one.
            self.started = None;
            self.bytes = 0;
            self.drained = false;
            return None;
        }
        // Reset so the next burst also starts from a known-empty socket.
        self.started = None;
        self.bytes = 0;
        self.drained = false;
        Some(bps)
    }
}

/// Resolve a preset to concrete protocol knobs (Auto resolves to its
/// starting point, Medium).
pub fn settings_for(preset: QualityPreset) -> QualitySettings {
    preset.settings()
}

/// Build the SetEncodings list for the given settings + server capabilities,
/// in preference order, followed by the pseudo-encodings the client always
/// wants, plus the JPEG-quality and compression-level pseudo-encodings.
pub fn encodings_for(settings: &QualitySettings, caps: &ServerCapabilities) -> Vec<i32> {
    let mut v = Vec::with_capacity(24);

    // Real encodings, most preferred first.
    v.push(encoding::TIGHT);
    if settings.allow_h264 && caps.supports_h264 {
        v.push(encoding::OPEN_H264);
    }
    v.push(encoding::ZRLE);
    v.push(encoding::COPY_RECT);
    v.push(encoding::HEXTILE);
    v.push(encoding::ZLIB);
    v.push(encoding::RAW);

    // Pseudo-encodings we always advertise.
    v.extend_from_slice(&[
        encoding::PSEUDO_LAST_RECT,
        encoding::PSEUDO_DESKTOP_NAME,
        encoding::PSEUDO_EXTENDED_DESKTOP_SIZE,
        encoding::PSEUDO_CURSOR,
        encoding::PSEUDO_X_CURSOR,
        encoding::PSEUDO_CURSOR_WITH_ALPHA,
        encoding::PSEUDO_FENCE,
        encoding::PSEUDO_CONTINUOUS_UPDATES,
        encoding::PSEUDO_EXTENDED_MOUSE_BUTTONS,
        encoding::PSEUDO_QEMU_EXT_KEY_EVENT,
        encoding::PSEUDO_QEMU_LED_STATE,
        encoding::PSEUDO_EXTENDED_CLIPBOARD,
    ]);

    if settings.allow_jpeg {
        v.push(encoding::jpeg_quality(settings.jpeg_quality.min(9)));
    }
    v.push(encoding::compression_level(settings.compression.min(9)));
    v
}

// ---------------------------------------------------------------------------
// Tier ladder (PRD/09 §3.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    High,
    Medium,
    /// "Low-ish": JPEG q4, 256 colours.
    LowIsh,
    /// Floor: JPEG q2, 64 colours, high compression.
    Low,
}

impl Tier {
    /// `link_bps` is a LOWER BOUND on link capacity from stall-anchored burst
    /// sampling (see [`LinkMeter`]), not achieved throughput: it is what the
    /// link proved it could carry during a burst, never contaminated by how
    /// slowly the server encoded between bursts.
    ///
    /// RTT is deliberately not consulted. RTT is not capacity: a 1 Mbit/s DSL
    /// line has a low RTT and a 100 Mbit/s satellite link has a high one. Our
    /// own fence reply, the only way we obtain RTT, queues behind framebuffer
    /// data on the same TCP stream, so it measures queue depth plus server
    /// responsiveness, which is the very confound this sampling scheme exists
    /// to remove. A "use RTT when available" rule would also split the client
    /// into two algorithms where the untested path is the one most deployed
    /// servers (libvncserver, x11vnc, TightVNC, Vino) actually take.
    ///
    /// `current` is the tier the session is running at now, consulted only
    /// for directional hysteresis (see [`DOWNGRADE_HYSTERESIS`]): clearing a
    /// boundary upgrades into the tier above it, but falling back below that
    /// SAME boundary only downgrades once the value drops under 0.8x of it.
    /// Without this, a link sampled right at a boundary (a real link, e.g. a
    /// 20 Mbit/s cap measured as 19.9 then 20.1) would re-evaluate to a
    /// different tier every sample; `SUSTAIN` alone does not prevent this
    /// because each flip restarts holding the SAME desired point, which
    /// re-satisfies sustain repeatedly.
    fn from_link(link_bps: f64, current: Tier) -> Self {
        // Each boundary's lenient (downgrade) threshold applies ONLY when
        // `current` is the tier immediately above that specific boundary,
        // i.e. the session is actually resting at that edge right now. A
        // boundary two tiers below `current` gets no leniency: there is no
        // oscillation to guard against there, and a link that has genuinely
        // collapsed several tiers at once must not be slowed down reaching
        // the bottom by hysteresis meant for a different edge.
        let high_th = if current == Tier::High {
            HIGH_BPS * DOWNGRADE_HYSTERESIS
        } else {
            HIGH_BPS
        };
        if link_bps > high_th {
            return Tier::High;
        }
        let medium_th = if current == Tier::Medium {
            MEDIUM_BPS * DOWNGRADE_HYSTERESIS
        } else {
            MEDIUM_BPS
        };
        if link_bps > medium_th {
            return Tier::Medium;
        }
        let lowish_th = if current == Tier::LowIsh {
            LOWISH_BPS * DOWNGRADE_HYSTERESIS
        } else {
            LOWISH_BPS
        };
        if link_bps > lowish_th {
            return Tier::LowIsh;
        }
        Tier::Low
    }

    /// The sample that would downgrade AWAY from this tier (the hysteresis
    /// floor below the boundary this tier sits above), or `0.0` for `Low`,
    /// which has nowhere further to fall.
    ///
    /// Used by the fast-downgrade path in [`AutoTuner::observe_at`]: the
    /// windowed max is a max over two [`LINK_WINDOW`]s, so on its own a
    /// single stale fast sample can rule for up to `2*LINK_WINDOW` after the
    /// link has genuinely dropped. A fresh sample that already reads below
    /// the CURRENT tier's own downgrade floor is trusted directly instead of
    /// waiting for that stale sample to age out of the window.
    fn downgrade_threshold_bps(self) -> f64 {
        match self {
            Tier::High => HIGH_BPS * DOWNGRADE_HYSTERESIS,
            Tier::Medium => MEDIUM_BPS * DOWNGRADE_HYSTERESIS,
            Tier::LowIsh => LOWISH_BPS * DOWNGRADE_HYSTERESIS,
            Tier::Low => 0.0,
        }
    }

    /// The automatic ladder moves JPEG quality and compression ONLY, never the
    /// pixel format.
    ///
    /// The lower two tiers used to drop to 256 and then 64 colours, and both
    /// of the things that makes a machine do are ones a user reads as a broken
    /// picture rather than as an adaptation. Posterising a photographic desktop
    /// to 64 colours is drastic and instantly visible, and worse, changing the
    /// format mid-session forces the full-screen redraw documented in
    /// `run_loop::apply_quality`. On a LAN with a server that encodes slowly
    /// (a Raspberry Pi is the standard example) the throughput estimate reads
    /// low even though the link is idle, so the ladder walked all the way down
    /// and the session ended up posterised AND repainting in waves, with the
    /// user moving the mouse around to force the stale regions to redraw.
    ///
    /// Colour-depth reduction still exists, as the explicit `Low` and
    /// `BlackAndWhite` presets. That is the point: it is a big enough change
    /// to be worth choosing, and choosing it is not the same as having it
    /// applied on your behalf by a guess about the link. JPEG quality and
    /// compression give Auto the bandwidth range it needs and need no format
    /// change, so nothing has to be redrawn to apply them.
    fn settings(self) -> QualitySettings {
        match self {
            // NOT `QualityPreset::High.settings()`: the manual High preset
            // disables H.264 (a deliberate choice for the "I picked this
            // explicitly" preset), but Auto's ladder must only ever trade off
            // quality/compression, never the codec. Reusing the manual
            // preset here made Auto silently toggle H.264 on and off every
            // time it crossed the 20 Mbit/s boundary, each toggle costing the
            // decoder a restart and a keyframe.
            Tier::High => QualitySettings {
                jpeg_quality: 9,
                compression: 1,
                pixel_format: ColorDepth::Full,
                allow_jpeg: true,
                allow_h264: true,
                grayscale_levels: None,
            },
            Tier::Medium => QualityPreset::Medium.settings(),
            Tier::LowIsh => QualitySettings {
                jpeg_quality: 4,
                compression: 6,
                pixel_format: ColorDepth::Full,
                allow_jpeg: true,
                allow_h264: true,
                grayscale_levels: None,
            },
            Tier::Low => QualitySettings {
                // TigerVNC's entire automatic range is q6-q8, precisely
                // because its link estimator is untrustworthy. Ours is
                // better but not perfect, and q2 is a setting a user should
                // have to choose deliberately, the identical argument already
                // applied above to colour depth: Auto's floor stops one notch
                // short of the explicit `Low`/`BlackAndWhite` presets.
                jpeg_quality: 3,
                compression: 9,
                // The bottom rung, and the ONLY automatic tier that reduces
                // colour. Below ~1 Mbit/s the 4x saving of 8bpp over 32bpp is
                // worth more than the colours, which is the trade every mature
                // client makes down here. It was briefly removed while a
                // quality inversion elsewhere was being misdiagnosed as
                // format-switch corruption; the inversion was the real cause,
                // and taking a genuine adaptation away from genuinely bad
                // links along with it was the wrong call.
                pixel_format: ColorDepth::Palette256,
                allow_jpeg: true,
                allow_h264: true,
                grayscale_levels: None,
            },
        }
    }

    fn preset(self) -> QualityPreset {
        match self {
            Tier::High => QualityPreset::High,
            Tier::Medium => QualityPreset::Medium,
            Tier::LowIsh | Tier::Low => QualityPreset::Low,
        }
    }
}

// ---------------------------------------------------------------------------
// AutoTuner
// ---------------------------------------------------------------------------

/// Desired operating point: a tier plus whether decode-time relief
/// (reduced compression) is active.
type Desired = (Tier, bool);

#[derive(Debug)]
struct Shared {
    /// Tier the session is currently running at (last taken recommendation).
    current: Tier,
    /// Whether the taken recommendation included compression relief.
    relief_applied: bool,
    /// A desired point differing from current, and since when it has held.
    candidate: Option<(Tier, bool, Instant)>,
    /// When the last recommendation was taken.
    last_switch: Option<Instant>,
    /// Switch that passed hysteresis and awaits `recommended()`.
    ready: Option<Desired>,
}

/// Adaptive quality tuner for the Auto preset (PRD/09 §3).
///
/// Feed it measurements via [`AutoTuner::observe`]; poll
/// [`AutoTuner::recommended`] for a settings change. Taking a recommendation
/// is recorded, so the same switch is never returned twice.
#[derive(Debug)]
pub struct AutoTuner {
    /// Highest link-capacity sample seen in the current [`LINK_WINDOW`].
    link_cur_bps: f64,
    /// Highest sample from the PREVIOUS window, kept so a slow window right
    /// after a fast one does not instantly forget the fast sample.
    link_prev_bps: f64,
    /// When the current window started. `None` means no sample has arrived
    /// yet, windows rotate only when a sample ARRIVES, never on a timer, a
    /// quiet session keeps its estimate because silence is not evidence of
    /// slowness.
    link_window_start: Option<Instant>,
    rtt_ms: f32,
    decode_ms: f32,
    last_observe: Option<Instant>,
    /// Whether any window has ever carried enough traffic to measure capacity.
    /// Until one does, the seeded starting tier stands.
    have_real_sample: bool,
    shared: Mutex<Shared>,
}

impl Default for AutoTuner {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoTuner {
    pub fn new() -> Self {
        Self {
            // Seed inside the Medium band so we do not recommend a change
            // before real measurements arrive (Auto starts at Medium).
            link_cur_bps: 10e6,
            link_prev_bps: 0.0,
            link_window_start: None,
            rtt_ms: 50.0,
            decode_ms: 5.0,
            last_observe: None,
            have_real_sample: false,
            shared: Mutex::new(Shared {
                current: Tier::Medium,
                relief_applied: false,
                candidate: None,
                last_switch: None,
                ready: None,
            }),
        }
    }

    /// The capacity estimate the ladder decides on: the larger of the current
    /// and previous window's maxima. Every sample is a lower bound, so the
    /// correct aggregator is MAX, the tightest bound is the largest; an
    /// average would be biased low by construction.
    fn capacity_bps(&self) -> f64 {
        self.link_cur_bps.max(self.link_prev_bps)
    }

    /// Fold one completed [`LinkMeter`] sample into the two-window rotating
    /// max. Windows rotate only when a sample ARRIVES, never on a timer.
    fn record_link(&mut self, now: Instant, bps: f64) {
        match self.link_window_start {
            None => {
                self.link_window_start = Some(now);
                self.link_cur_bps = bps;
            }
            Some(start) => {
                let age = now.saturating_duration_since(start);
                if age >= LINK_WINDOW * 2 {
                    // Both windows are stale: nothing carries forward.
                    self.link_prev_bps = 0.0;
                    self.link_cur_bps = bps;
                    self.link_window_start = Some(now);
                } else if age >= LINK_WINDOW {
                    // Rotate: the current window becomes the previous one.
                    self.link_prev_bps = self.link_cur_bps;
                    self.link_cur_bps = bps;
                    self.link_window_start = Some(now);
                } else {
                    self.link_cur_bps = self.link_cur_bps.max(bps);
                }
            }
        }
    }

    /// Record one measurement tick: a completed link-capacity sample from
    /// [`LinkMeter`] (or `None` if nothing loaded the link this tick),
    /// current RTT estimate, and decode time of the last update.
    /// Non-positive `rtt_ms`/`decode_ms` are treated as "no sample".
    pub fn observe(&mut self, link_bps: Option<f64>, rtt_ms: f32, decode_ms: f32) {
        self.observe_at(Instant::now(), link_bps, rtt_ms, decode_ms);
    }

    fn observe_at(&mut self, now: Instant, link_bps: Option<f64>, rtt_ms: f32, decode_ms: f32) {
        match self.last_observe {
            Some(prev) => {
                let dt = now.saturating_duration_since(prev).as_secs_f64();
                if dt > 0.0 {
                    let a = 1.0 - (-dt / TAU_S).exp();
                    // Latency and decode cost are meaningful on every sample.
                    if rtt_ms > 0.0 {
                        self.rtt_ms += (a as f32) * (rtt_ms - self.rtt_ms);
                    }
                    if decode_ms > 0.0 {
                        self.decode_ms += (a as f32) * (decode_ms - self.decode_ms);
                    }
                }
            }
            None => {
                // First sample: seed the latency averages directly.
                if rtt_ms > 0.0 {
                    self.rtt_ms = rtt_ms;
                }
                if decode_ms > 0.0 {
                    self.decode_ms = decode_ms;
                }
            }
        }
        self.last_observe = Some(now);

        // A completed burst is a LOWER BOUND on capacity (see [`LinkMeter`]),
        // so fold it into the windowed max. `None` is NOT a low reading, it
        // means nothing loaded the link this tick, not that the link is slow,
        // so the estimate must stand rather than decay toward zero.
        //
        // `fresh_sample` also feeds the fast-downgrade path below: it is only
        // `Some` on a tick that a real burst completed THIS call, never a
        // carried-forward window value.
        let mut fresh_sample: Option<f64> = None;
        if let Some(bps) = link_bps {
            if bps > 0.0 {
                self.record_link(now, bps);
                self.have_real_sample = true;
                fresh_sample = Some(bps);
            }
        }
        if !self.have_real_sample {
            // Never move the ladder before a real capacity sample exists:
            // the seeded starting tier stands.
            return;
        }

        let windowed = self.capacity_bps();

        let mut sh = self.shared.lock();

        // Fast downgrade: `windowed` is a MAX over two `LINK_WINDOW`s, so a
        // single earlier high sample can rule for up to `2*LINK_WINDOW` after
        // the link has genuinely dropped (a real downgrade otherwise takes
        // 12-15 s to act). When the freshest sample already reads below the
        // CURRENT tier's own downgrade floor, trust it directly instead of
        // waiting for the stale high sample to age out of the window. This
        // only changes which capacity number feeds the decision below;
        // SUSTAIN and COOLDOWN still gate whether a switch is actually taken.
        let capacity = match fresh_sample {
            Some(bps) if bps < sh.current.downgrade_threshold_bps() => bps,
            _ => windowed,
        };

        let target = Tier::from_link(capacity, sh.current);

        // Client CPU-bound: sustained decode overruns ask for lower
        // compression at the same tier. Gated on a demonstrably fast link
        // (see `RELIEF_MIN_CAPACITY_BPS`'s doc): `decode_rect` awaits socket
        // reads, so on a slow link `decode_ms` mostly measures the WIRE, and
        // relief would reduce compression exactly when the link can least
        // afford it. Asymmetric on/off thresholds (`FRAME_BUDGET_MS` vs
        // `RELIEF_OFF_RATIO` of it) stop decode time hovering at the budget
        // from flickering relief on and off every sample.
        let fast_link = capacity > RELIEF_MIN_CAPACITY_BPS;
        let relief = fast_link
            && if sh.relief_applied {
                self.decode_ms > FRAME_BUDGET_MS * RELIEF_OFF_RATIO
            } else {
                self.decode_ms > FRAME_BUDGET_MS
            };
        let desired: Desired = (target, relief);

        if desired == (sh.current, sh.relief_applied) {
            // Back where we already are: abandon any pending change.
            sh.candidate = None;
            sh.ready = None;
            return;
        }
        match sh.candidate {
            Some((t, r, since)) if (t, r) == desired => {
                let sustained = now.saturating_duration_since(since) >= SUSTAIN;
                let cooled = sh
                    .last_switch
                    .is_none_or(|ls| now.saturating_duration_since(ls) >= COOLDOWN);
                if sustained && cooled {
                    sh.ready = Some(desired);
                }
            }
            _ => {
                // The desired point changed: restart the sustain clock.
                sh.candidate = Some((desired.0, desired.1, now));
                sh.ready = None;
            }
        }
    }

    /// Recommended settings if a tier change is warranted (hysteresis
    /// applied), else `None`. Returning `Some` records the switch as taken:
    /// the tuner's current tier advances and the cooldown timer restarts.
    pub fn recommended(&self) -> Option<QualitySettings> {
        let mut sh = self.shared.lock();
        let (tier, relief) = sh.ready.take()?;
        sh.current = tier;
        sh.relief_applied = relief;
        sh.candidate = None;
        sh.last_switch = self.last_observe.or_else(|| Some(Instant::now()));
        let mut s = tier.settings();
        if relief {
            s.compression = s.compression.saturating_sub(2);
        }
        Some(s)
    }

    /// The tier the tuner currently considers active (as a preset).
    pub fn current_tier(&self) -> QualityPreset {
        self.shared.lock().current.preset()
    }

    /// Align the tuner's internal bookkeeping to settings applied from
    /// OUTSIDE it (a manual preset via `SetQuality`).
    ///
    /// Without this, a manual preset detour desyncs the tuner: `SetQuality`
    /// applies settings to the wire directly, but `Shared::current` still
    /// holds whatever tier Auto was last at, so switching back to Auto does
    /// nothing until fresh measurements happen to walk the ladder back to
    /// wherever it actually is. Called from the `SetQuality` command arm
    /// whenever quality changes, manual or Auto, so the tuner is never more
    /// than one command stale.
    pub fn resync(&mut self, qs: &QualitySettings) {
        // Presets don't line up with tier settings byte-for-byte (Low's q2
        // vs. the auto floor's q3, for one), so match on the ordinal that
        // actually varies monotonically across the ladder: JPEG quality.
        let tier = if qs.jpeg_quality >= QualityPreset::High.settings().jpeg_quality {
            Tier::High
        } else if qs.jpeg_quality >= QualityPreset::Medium.settings().jpeg_quality {
            Tier::Medium
        } else if qs.jpeg_quality >= Tier::LowIsh.settings().jpeg_quality {
            Tier::LowIsh
        } else {
            Tier::Low
        };
        let mut sh = self.shared.lock();
        sh.current = tier;
        sh.relief_applied = false;
        sh.candidate = None;
        sh.ready = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- encodings_for / settings_for ---------------------------------------

    #[test]
    fn settings_for_mirrors_presets() {
        for p in [
            QualityPreset::Auto,
            QualityPreset::High,
            QualityPreset::Medium,
            QualityPreset::Low,
            QualityPreset::BlackAndWhite,
        ] {
            assert_eq!(settings_for(p), p.settings());
        }
    }

    #[test]
    fn encodings_order_and_pseudo_levels() {
        let caps = ServerCapabilities::default();
        let s = settings_for(QualityPreset::Medium);
        let list = encodings_for(&s, &caps);
        // Preference order without H.264 (server does not support it).
        assert_eq!(
            &list[..7],
            &[
                encoding::TIGHT,
                encoding::ZRLE,
                encoding::COPY_RECT,
                encoding::HEXTILE,
                encoding::ZLIB,
                encoding::RAW,
                encoding::PSEUDO_LAST_RECT,
            ]
        );
        assert!(list.contains(&encoding::PSEUDO_EXTENDED_CLIPBOARD));
        assert!(list.contains(&encoding::PSEUDO_QEMU_EXT_KEY_EVENT));
        assert!(list.contains(&encoding::PSEUDO_EXTENDED_MOUSE_BUTTONS));
        assert!(list.contains(&encoding::PSEUDO_FENCE));
        assert!(list.contains(&encoding::PSEUDO_CONTINUOUS_UPDATES));
        // Medium: JPEG q6 (-29), compression 3 (-250).
        assert!(list.contains(&encoding::jpeg_quality(6)));
        assert!(list.contains(&encoding::compression_level(3)));
        assert!(!list.contains(&encoding::OPEN_H264));
    }

    #[test]
    fn encodings_h264_and_jpeg_gating() {
        let caps = ServerCapabilities {
            supports_h264: true,
            ..Default::default()
        };
        let s = settings_for(QualityPreset::Medium); // allow_h264: true
        let list = encodings_for(&s, &caps);
        assert_eq!(list[1], encoding::OPEN_H264, "H.264 right after Tight");

        // High disallows H.264 even when the server supports it.
        let s = settings_for(QualityPreset::High);
        assert!(!encodings_for(&s, &caps).contains(&encoding::OPEN_H264));

        // B&W disables JPEG entirely: no quality pseudo-encoding at all.
        let s = settings_for(QualityPreset::BlackAndWhite);
        let list = encodings_for(&s, &caps);
        assert!(!list.iter().any(|&e| (-32..=-23).contains(&e)));
        assert!(list.contains(&encoding::compression_level(9)));
    }

    // -- AutoTuner ----------------------------------------------------------

    const STEP: Duration = Duration::from_millis(200);

    #[test]
    fn sustained_fast_link_upgrades_to_high_once() {
        let mut t = AutoTuner::new();
        assert_eq!(t.current_tier(), QualityPreset::Medium);
        let base = Instant::now();
        let mut now = base;
        for _ in 0..30 {
            // 6 s of 60 Mbit/s, 1 ms RTT
            now += STEP;
            t.observe_at(now, Some(60e6), 1.0, 4.0);
        }
        let rec = t.recommended().expect("sustained fast link must upgrade");
        // NOT `QualityPreset::High.settings()`: Auto's High tier keeps
        // `allow_h264: true` (see `Tier::settings`) so the ladder never
        // toggles the codec on its own; only the manual High preset turns
        // H.264 off.
        assert_eq!(
            rec,
            QualitySettings {
                allow_h264: true,
                ..QualityPreset::High.settings()
            }
        );
        assert_eq!(t.current_tier(), QualityPreset::High);
        // Taking the recommendation records it: not returned again.
        assert_eq!(t.recommended(), None);
        // And with unchanged conditions, no new recommendation appears.
        now += STEP;
        t.observe_at(now, Some(60e6), 1.0, 4.0);
        assert_eq!(t.recommended(), None);
    }

    #[test]
    fn sustained_slow_link_downgrades() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        for _ in 0..30 {
            // 6 s of ~200 kbit/s
            now += STEP;
            t.observe_at(now, Some(0.2e6), 300.0, 4.0);
        }
        let rec = t.recommended().expect("sustained slow link must downgrade");
        assert_eq!(rec.jpeg_quality, 3);
        assert!(rec.compression >= 7);
        assert_eq!(t.current_tier(), QualityPreset::Low);
    }

    #[test]
    fn flapping_input_does_not_oscillate() {
        // Alternate 1 s blocks between the Medium band (10 Mbit/s) and the
        // Low band (50 kbit/s). The desired tier flips roughly every second,
        // which never satisfies the 2 s sustain requirement, the tuner must
        // hold steady and recommend nothing.
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        let mut recommendations = 0;
        for block in 0..20 {
            let bps = if block % 2 == 0 { 10e6 } else { 0.05e6 };
            for _ in 0..5 {
                now += STEP;
                t.observe_at(now, Some(bps), 30.0, 5.0);
                if t.recommended().is_some() {
                    recommendations += 1;
                }
            }
        }
        assert_eq!(recommendations, 0, "flapping input must not cause switches");
        assert_eq!(t.current_tier(), QualityPreset::Medium);
    }

    #[test]
    fn cooldown_blocks_rapid_consecutive_switches() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        // Upgrade to High.
        for _ in 0..30 {
            now += STEP;
            t.observe_at(now, Some(60e6), 1.0, 4.0);
        }
        assert!(t.recommended().is_some());
        let switch_time = now;

        // Immediately crash the link, sustained. A single fast sample is not
        // forgotten the instant the link turns slow: the windowed max keeps
        // it alive in BOTH the current and (after one rotation) the previous
        // window, so the desired tier does not even become Low until the
        // fast sample has aged out of both, roughly 2*LINK_WINDOW. Drive it
        // that long (plus COOLDOWN, for headroom) while still asserting the
        // thing this test exists to prove: no switch happens inside the 5 s
        // cooldown from the last one.
        let deadline = 2 * LINK_WINDOW + COOLDOWN;
        loop {
            now += STEP;
            t.observe_at(now, Some(0.05e6), 300.0, 4.0);
            let elapsed = now.duration_since(switch_time);
            if elapsed < COOLDOWN {
                assert_eq!(
                    t.recommended(),
                    None,
                    "no switch may occur within the cooldown ({elapsed:?})"
                );
            }
            if elapsed >= deadline {
                break;
            }
        }
        // Past both windows aging out (and long past sustain/cooldown), the
        // downgrade arrives.
        now += STEP;
        t.observe_at(now, Some(0.05e6), 300.0, 4.0);
        let rec = t
            .recommended()
            .expect("downgrade once the fast sample ages out");
        assert_eq!(t.current_tier(), QualityPreset::Low);
        assert_eq!(rec.jpeg_quality, 3);
    }

    #[test]
    fn sustained_decode_overrun_reduces_compression() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        for _ in 0..30 {
            // `decode_rect` awaits socket reads, so decode_ms only trusts a
            // CPU-bound diagnosis on a link fast enough to rule out the wire
            // (see `RELIEF_MIN_CAPACITY_BPS`): 60 Mbit/s, comfortably above
            // the High tier's 20 Mbit/s floor, decoding 30 ms per frame.
            now += STEP;
            t.observe_at(now, Some(60e6), 5.0, 30.0);
        }
        let rec = t
            .recommended()
            .expect("CPU-bound client on a fast link warrants relief");
        let high = QualityPreset::High.settings();
        assert_eq!(t.current_tier(), QualityPreset::High, "tier: High");
        assert_eq!(rec.jpeg_quality, high.jpeg_quality);
        assert!(
            rec.compression < high.compression,
            "compression must drop when decode exceeds the frame budget"
        );
    }

    /// `decode_rect` awaits socket reads, so on a slow link `decode_ms`
    /// mostly measures the WIRE, not the CPU. Relief must never fire there:
    /// reducing compression on an already-slow link is backwards.
    #[test]
    fn decode_ms_on_a_slow_link_never_triggers_relief() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        for _ in 0..30 {
            // Medium-band link (well under the 20 Mbit/s relief floor) with
            // an "overrun" decode time that is really queueing time.
            now += STEP;
            t.observe_at(now, Some(10e6), 90.0, 30.0);
        }
        assert_eq!(
            t.recommended(),
            None,
            "no relief without a demonstrably fast link, and the tier is already Medium"
        );
        assert_eq!(t.current_tier(), QualityPreset::Medium);
    }

    /// Relief's on/off thresholds are asymmetric: it engages once decode
    /// exceeds `FRAME_BUDGET_MS`, but releases only once decode falls under
    /// `RELIEF_OFF_RATIO` of it, so a decode time hovering right at the
    /// budget does not flicker relief on and off every sample.
    #[test]
    fn relief_off_threshold_is_lower_than_the_on_threshold() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;

        // Engage relief on a fast link with a sustained decode overrun.
        for _ in 0..30 {
            now += STEP;
            t.observe_at(now, Some(60e6), 2.0, 30.0);
        }
        t.recommended().expect("relief should engage");

        // Decode drops to 14 ms: under the 16 ms ON threshold but still
        // above the 12 ms (0.75x) OFF threshold. Relief must hold.
        for _ in 0..30 {
            now += STEP;
            t.observe_at(now, Some(60e6), 2.0, 14.0);
        }
        assert_eq!(
            t.recommended(),
            None,
            "relief must not release the instant decode dips under the ON threshold"
        );

        // Only once decode genuinely falls under the OFF threshold does
        // relief release.
        for _ in 0..30 {
            now += STEP;
            t.observe_at(now, Some(60e6), 2.0, 8.0);
        }
        let rec = t
            .recommended()
            .expect("relief must release once decode is genuinely fast");
        assert_eq!(
            rec.compression,
            QualityPreset::High.settings().compression,
            "compression must return to the un-relieved High value"
        );
    }

    #[test]
    fn no_recommendation_without_measurements() {
        let t = AutoTuner::new();
        assert_eq!(t.recommended(), None);
        assert_eq!(t.current_tier(), QualityPreset::Medium);
    }

    /// The bug the user hit: a gigabit LAN showing a desktop nobody is
    /// touching. No burst ever completes, and the old tuner read wall-clock
    /// idleness as a slow link and walked down to 64 colours, which also
    /// forced a full-screen redraw on every step ("the picture repaints in
    /// waves").
    #[test]
    fn an_idle_fast_link_never_downgrades() {
        let mut t = AutoTuner::new();
        let start = Instant::now();
        // 60 seconds of a static desktop: nothing loads the link, so every
        // tick observes `None` (this guards `have_real_sample`: the seeded
        // starting tier must hold with no real sample ever seen).
        for i in 1..=60 {
            t.observe_at(start + Duration::from_secs(i), None, 0.4, 1.0);
        }
        assert!(
            t.recommended().is_none(),
            "an idle link must not trigger a quality change"
        );
        assert_eq!(t.current_tier(), QualityPreset::Medium);
    }

    /// ...but a link that is genuinely being loaded and genuinely slow must
    /// still be detected, or Auto would be useless.
    #[test]
    fn a_loaded_slow_link_still_downgrades() {
        let mut t = AutoTuner::new();
        let start = Instant::now();
        // ~800 kbit/s sustained with real traffic in every window.
        for i in 1..=12 {
            // 100 KiB that genuinely took a full second to transfer: ~800 kbit/s.
            let bps = (100.0 * 1024.0 * 8.0) / 1.0;
            t.observe_at(start + Duration::from_secs(i), Some(bps), 90.0, 2.0);
        }
        let rec = t.recommended().expect("a loaded slow link must downgrade");
        assert!(
            rec.jpeg_quality <= 4,
            "expected a lower-quality tier, got {rec:?}"
        );
    }

    /// The whole point of switching to stall-anchored burst sampling: a
    /// server whose OWN encoder is slow (a Raspberry Pi is the standard
    /// example) must not read as a slow link just because the socket sits
    /// empty between rects. Every rect here opens on a real stall, then
    /// delivers its data as a fast burst, exactly what a gigabit LAN behind
    /// a slow encoder actually looks like on the wire.
    #[test]
    fn a_slow_server_on_a_fast_link_never_downgrades() {
        let mut t = AutoTuner::new();
        let mut meter = LinkMeter::default();
        let mut now = Instant::now();

        for _ in 0..20 {
            let mut best: Option<f64> = None;
            for _ in 0..5 {
                // The Pi's encoder holds the socket empty for ~30 ms per
                // rect: that time is the SERVER's, not the link's.
                meter.stalled();
                now += Duration::from_millis(30);
                let opening = meter.received(now, 4 * 1024);
                assert_eq!(
                    opening, None,
                    "the bytes that end a stall must not be timed: they \
                     queued during the stall, not while crossing the wire"
                );
                // Once the queued rect starts flowing it arrives as a fast
                // burst (gigabit LAN), which is what proves the link, not
                // the server: enough bytes across enough wall time to clear
                // both MIN_BURST_BYTES and MIN_BURST_S in this one delivery,
                // so the burst completes within THIS rep rather than
                // bleeding into the next one's stall/opening (a burst still
                // open when the next rep starts would swallow its "opening"
                // bytes into an ongoing accumulation instead of discarding
                // them, breaking the assertion above).
                now += Duration::from_micros(2500);
                if let Some(bps) = meter.received(now, 80 * 1024) {
                    best = Some(best.map_or(bps, |b: f64| b.max(bps)));
                }
            }
            let sample = best.expect("a burst must complete every second");
            assert!(
                sample > 100e6,
                "a burst timed on a gigabit LAN must read as fast, got {sample}"
            );
            t.observe_at(now, Some(sample), 1.0, 2.0);
            now += Duration::from_millis(850);
        }

        let medium = QualityPreset::Medium.settings();
        if let Some(rec) = t.recommended() {
            assert!(
                rec.jpeg_quality >= medium.jpeg_quality,
                "must never drop below Medium's quality: {rec:?}"
            );
        }
        assert_ne!(
            t.current_tier(),
            QualityPreset::Low,
            "a Pi's slow encoder must never read as a slow link"
        );
    }

    /// ...but a link that is genuinely slow, not merely fed by a slow
    /// server, must still be caught, driven with realistic segment-sized
    /// deliveries and a stall before every single one, which is exactly what
    /// proves stalls-mid-burst do not truncate a sample: a truly slow link
    /// stalls constantly (the wire itself is the bottleneck), so if a stall
    /// ended a burst this link could never accumulate enough to be measured.
    #[test]
    fn a_genuinely_slow_link_still_downgrades() {
        let mut t = AutoTuner::new();
        let mut meter = LinkMeter::default();
        let start = Instant::now();
        let mut now = start;
        const SEGMENT: usize = 1448; // one Ethernet MSS' worth of payload

        while now.duration_since(start) < Duration::from_secs(20) {
            meter.stalled();
            now += Duration::from_millis(12); // ~965 kbit/s worth of spacing
            if let Some(bps) = meter.received(now, SEGMENT) {
                assert!(
                    bps < 1.5e6,
                    "a ~965 kbit/s link must not read as fast, got {bps}"
                );
                t.observe_at(now, Some(bps), 40.0, 2.0);
            }
        }

        let rec = t
            .recommended()
            .expect("a genuinely slow link must downgrade");
        assert_eq!(rec.jpeg_quality, 3, "must land on the new automatic floor");
        assert_eq!(t.current_tier(), QualityPreset::Low);
    }

    /// A single fast burst (a fluke: a backlog flushing all at once, say)
    /// must not pin the link estimate at high quality forever. The windowed
    /// max keeps it alive for up to 2*LINK_WINDOW, but a link that is
    /// genuinely slow the rest of the time still has to win once the fluke
    /// ages out.
    #[test]
    fn one_fluke_burst_cannot_pin_a_slow_link_at_high_quality() {
        let mut t = AutoTuner::new();
        let start = Instant::now();
        let mut now = start;

        t.observe_at(now, Some(200e6), 1.0, 2.0);

        while now.duration_since(start) < Duration::from_secs(20) {
            now += Duration::from_millis(200);
            t.observe_at(now, Some(0.4e6), 200.0, 2.0);
        }

        let rec = t
            .recommended()
            .expect("the outlier must age out and the link must downgrade");
        assert_eq!(t.current_tier(), QualityPreset::Low);
        assert_eq!(rec.jpeg_quality, 3);
    }

    /// A measured estimate must not erode just because nothing loads the
    /// link for a while: silence is not evidence of slowness. Windows rotate
    /// only when a sample ARRIVES (see `AutoTuner::record_link`), never on a
    /// timer.
    #[test]
    fn a_quiet_spell_does_not_erode_a_measured_estimate() {
        let mut t = AutoTuner::new();
        let start = Instant::now();
        let mut now = start;
        for _ in 0..30 {
            now += STEP;
            t.observe_at(now, Some(60e6), 1.0, 2.0);
        }
        t.recommended()
            .expect("sustained fast burst must upgrade to High");
        assert_eq!(t.current_tier(), QualityPreset::High);

        // A quiet spell: nobody moves the mouse, no burst ever completes, so
        // every tick observes `None`.
        for _ in 0..60 {
            now += Duration::from_secs(1);
            t.observe_at(now, None, 1.0, 2.0);
        }
        assert_eq!(
            t.recommended(),
            None,
            "a quiet spell must not trigger a downgrade"
        );
        assert_eq!(t.current_tier(), QualityPreset::High);
    }

    // -- LinkMeter ------------------------------------------------------

    /// Data that queued while the socket was empty and then all arrives at
    /// once must not be timed as if it crossed the wire in zero time. The
    /// burst that delivery OPENS is then timed normally.
    #[test]
    fn bytes_that_were_already_waiting_are_never_timed() {
        let mut meter = LinkMeter::default();
        let mut now = Instant::now();

        meter.stalled();
        assert_eq!(
            meter.received(now, 64 * 1024),
            None,
            "data that queued during a stall must not be credited to a zero-time interval"
        );

        now += Duration::from_millis(10);
        let bps = meter
            .received(now, 32 * 1024)
            .expect("the burst this opened must complete once it reaches MIN_BURST_BYTES");
        let expected = (32.0 * 1024.0 * 8.0) / 0.010;
        assert!(
            (bps - expected).abs() / expected < 1e-6,
            "got {bps}, expected {expected}"
        );
    }

    /// A stall arriving WHILE a burst is still accumulating must not
    /// truncate or reset it: on a genuinely slow link the socket goes empty
    /// between every segment, so ending bursts on stall would make slow
    /// links unmeasurable, the exact opposite of what this type is for.
    #[test]
    fn a_stall_inside_a_burst_does_not_end_it() {
        let mut meter = LinkMeter::default();
        let mut now = Instant::now();

        meter.stalled();
        assert_eq!(meter.received(now, 4096), None); // opens the burst

        now += Duration::from_millis(1);
        assert_eq!(meter.received(now, 4096), None); // 4 KiB, below the 16 KiB train

        // A stall mid-burst.
        meter.stalled();

        now += Duration::from_millis(1);
        assert_eq!(meter.received(now, 4096), None); // 8 KiB
        now += Duration::from_millis(1);
        assert_eq!(meter.received(now, 4096), None); // 12 KiB

        now += Duration::from_millis(1);
        let bps = meter
            .received(now, 4096)
            .expect("16 KiB reached: the burst completes as ONE continuous interval");
        let expected = (16.0 * 1024.0 * 8.0) / 0.004;
        assert!(
            (bps - expected).abs() / expected < 1e-6,
            "the stall in the middle must not have reset the burst: got {bps}, expected {expected}"
        );
    }

    /// A trickle that never gathers a full packet train must never complete
    /// a burst, or a nearly-idle link would read as an arbitrarily fast one
    /// off a handful of bytes.
    #[test]
    fn an_idle_trickle_never_completes_a_burst() {
        let mut meter = LinkMeter::default();
        let mut now = Instant::now();
        for _ in 0..60 {
            meter.stalled();
            now += Duration::from_secs(1);
            assert_eq!(
                meter.received(now, 300),
                None,
                "a 300 B/s trickle must never complete a burst"
            );
        }
    }

    /// REGRESSION: the MAX_BURST_S abandonment check used to run only in the
    /// under-`MIN_BURST_BYTES` branch, so a delivery that crossed the byte
    /// threshold skipped it entirely: a burst partially filled, then left
    /// idle for MAX_BURST_S, then finally topped up by one more delivery
    /// completed anyway, timed over the WHOLE idle span. That read a
    /// gigabit LAN as ~5 kbit/s and walked Auto all the way down to
    /// `Tier::Low`.
    #[test]
    fn a_burst_left_idle_past_max_burst_s_is_abandoned_even_when_the_next_delivery_crosses_the_threshold(
    ) {
        let mut meter = LinkMeter::default();
        let mut now = Instant::now();

        meter.stalled();
        // Opens the burst; partially fills it, well under MIN_BURST_BYTES.
        assert_eq!(meter.received(now, 4 * 1024), None);

        // Idle far past MAX_BURST_S with the burst still open.
        now += Duration::from_secs(30);

        // This delivery crosses MIN_BURST_BYTES, the branch the bug never
        // checked MAX_BURST_S in. It must still be abandoned, not completed
        // and timed over the full 30 s gap.
        assert_eq!(
            meter.received(now, 16 * 1024),
            None,
            "a burst idle past MAX_BURST_S must be abandoned even on the delivery \
             that crosses MIN_BURST_BYTES, not completed and timed over the whole gap"
        );

        // The abandonment must actually have reset state: a fresh stall can
        // open (and complete) a new, plausible burst right away.
        meter.stalled();
        now += Duration::from_millis(1);
        assert_eq!(meter.received(now, 4 * 1024), None); // opens
        now += Duration::from_millis(4);
        let bps = meter
            .received(now, 16 * 1024)
            .expect("a fresh burst after abandonment must still complete normally");
        assert!(
            bps < 100e6,
            "the fresh burst must be timed on its own short span, not the stale one: got {bps}"
        );
    }

    /// REGRESSION: a kernel socket buffer or an in-process carrier (the SSH
    /// tunnel's mpsc channel) can hand a whole backlog to one `poll_read` in
    /// a slice of a millisecond. That backlog was genuinely QUEUED, not
    /// delivered at that rate; timing it naively reads a 5 Mbit/s link as
    /// multi-gigabit and pins Auto at High via back-pressure. The plausible-
    /// rate ceiling must reject it instead of folding it into the window.
    #[test]
    fn a_backlog_dump_right_after_a_stall_is_rejected_as_implausible() {
        let mut meter = LinkMeter::default();
        let mut now = Instant::now();

        meter.stalled();
        assert_eq!(meter.received(now, 64 * 1024), None); // opens, discarded

        // The rest of a large backlog draining in one shot: 256 MiB in 3 ms
        // is ~700 Gbit/s, comfortably clearing MIN_BURST_S but nowhere near
        // plausible for a real last hop.
        now += Duration::from_millis(3);
        assert_eq!(
            meter.received(now, 256 * 1024 * 1024),
            None,
            "an implausible rate must be rejected as a measurement artifact, \
             not folded into the window"
        );

        // Rejection must reset state: a subsequent stall can still open and
        // complete a fresh, plausible burst.
        meter.stalled();
        now += Duration::from_millis(5);
        assert_eq!(meter.received(now, 4096), None); // opens
        now += Duration::from_millis(5);
        let bps = meter
            .received(now, 32 * 1024)
            .expect("a plausible burst must still complete after the rejection");
        assert!(bps < 1e9, "expected a plausible rate, got {bps}");
    }

    /// REGRESSION: the automatic ladder must never change the pixel format.
    ///
    /// Every tier it can reach has to stay at full colour, because a format
    /// change costs a full-screen redraw (`run_loop::apply_quality`) and
    /// posterising to 64 colours reads as a broken picture, not as an
    /// adaptation. This is what made a Raspberry Pi on a LAN, whose slow
    /// encoder reads as a slow link, end up both pixelated and repainting in
    /// patches as the user moved the mouse.
    #[test]
    fn the_automatic_ladder_never_reduces_colour_depth() {
        // Everything except the bottom rung stays at full colour: a format
        // switch costs a full redraw, so it is reserved for the one tier where
        // the bandwidth saving genuinely outweighs that.
        for tier in [Tier::High, Tier::Medium, Tier::LowIsh] {
            assert_eq!(
                tier.settings().pixel_format,
                ColorDepth::Full,
                "{tier:?} must not change the pixel format"
            );
        }
        assert_eq!(
            Tier::Low.settings().pixel_format,
            ColorDepth::Palette256,
            "the sub-1 Mbit/s rung keeps its colour reduction"
        );
        // The explicit presets go further still:
        // choosing it is not the same as having it chosen for you.
        assert_eq!(
            QualityPreset::Low.settings().pixel_format,
            ColorDepth::Palette256
        );
        assert_eq!(
            QualityPreset::BlackAndWhite.settings().pixel_format,
            ColorDepth::Grayscale
        );
    }

    /// The ladder must still span a real bandwidth range, or Auto cannot
    /// adapt at all once colour depth is off the table.
    #[test]
    fn the_ladder_still_spans_a_useful_quality_range() {
        let q = |t: Tier| t.settings().jpeg_quality;
        assert!(
            q(Tier::High) > q(Tier::Medium)
                && q(Tier::Medium) > q(Tier::LowIsh)
                && q(Tier::LowIsh) > q(Tier::Low),
            "each tier down must actually cost quality"
        );
        let c = |t: Tier| t.settings().compression;
        assert!(
            c(Tier::Low) > c(Tier::High),
            "the slow end must compress harder"
        );
    }

    /// A fast link that is actually being used must be recognised as fast.
    #[test]
    fn a_loaded_fast_link_upgrades() {
        let mut t = AutoTuner::new();
        let start = Instant::now();
        // ~40 Mbit/s with sub-millisecond RTT.
        for i in 1..=12 {
            // 5 MiB in a second of actual transfer: ~40 Mbit/s.
            let bps = (5.0 * 1024.0 * 1024.0 * 8.0) / 1.0;
            t.observe_at(start + Duration::from_secs(i), Some(bps), 0.5, 3.0);
        }
        let rec = t.recommended().expect("a loaded fast link must upgrade");
        assert!(rec.jpeg_quality >= 8, "expected high quality, got {rec:?}");
    }

    // -- Tier hysteresis / relief gating / fast downgrade / resync ----------

    /// Directional hysteresis at a tier boundary: clearing it upgrades, but
    /// only falling below `DOWNGRADE_HYSTERESIS` (0.8x) of it downgrades back.
    /// Without this a link sampled right at the boundary re-evaluates to a
    /// different tier on every sample.
    #[test]
    fn tier_boundary_has_directional_hysteresis() {
        // Once at High, a small dip below 20 Mbit/s (but still above the
        // 16 Mbit/s floor) must not read as a downgrade.
        assert_eq!(Tier::from_link(19e6, Tier::High), Tier::High);
        assert_eq!(Tier::from_link(20.5e6, Tier::High), Tier::High);
        // Falling below the 0.8x floor genuinely downgrades.
        assert_eq!(Tier::from_link(15e6, Tier::High), Tier::Medium);
        // From Medium, climbing back requires clearing the FULL boundary,
        // not just the hysteresis floor a High session would tolerate.
        assert_eq!(Tier::from_link(17e6, Tier::Medium), Tier::Medium);
        assert_eq!(Tier::from_link(20.1e6, Tier::Medium), Tier::High);
    }

    /// A link oscillating 19-21 Mbit/s across a boundary reads, via the
    /// windowed max (every sample is a lower bound, see `capacity_bps`), as
    /// "at least ~21 Mbit/s" continuously, so it correctly settles at High
    /// and stays there for as long as the oscillation continues, which this
    /// confirms; it is `a_link_settled_at_high_does_not_downgrade_from_a_dip_
    /// within_the_hysteresis_band` below, where the 21 Mbit/s samples stop
    /// recurring and the windowed max genuinely converges on 19 Mbit/s, that
    /// isolates what the hysteresis fix actually changes.
    #[test]
    fn an_oscillating_link_near_the_high_boundary_settles_at_high_and_holds() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        let mut recommendations = 0;
        for cycle in 0..20 {
            let bps = if cycle % 2 == 0 { 21e6 } else { 19e6 };
            for _ in 0..7 {
                now += STEP; // ~1.4 s per half-period
                t.observe_at(now, Some(bps), 2.0, 3.0);
                if t.recommended().is_some() {
                    recommendations += 1;
                }
            }
        }
        assert_eq!(
            recommendations, 1,
            "must settle into High once and hold, not flap back and forth"
        );
        assert_eq!(t.current_tier(), QualityPreset::High);
    }

    /// REGRESSION (directional hysteresis): once genuinely settled at High
    /// with the seeding fast sample long aged out of both `LINK_WINDOW`s, a
    /// sustained dip to 19 Mbit/s, below the nominal 20 Mbit/s boundary but
    /// above the 16 Mbit/s (0.8x) floor a High session tolerates, must not
    /// downgrade. The OLD flat-threshold ladder read every sample under
    /// 20 Mbit/s as a downgrade the instant the fast seed aged out.
    #[test]
    fn a_link_settled_at_high_does_not_downgrade_from_a_dip_within_the_hysteresis_band() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        for _ in 0..30 {
            now += STEP;
            t.observe_at(now, Some(60e6), 1.0, 2.0);
        }
        t.recommended().expect("must upgrade to High");
        assert_eq!(t.current_tier(), QualityPreset::High);

        // Sustained at 19 Mbit/s for long enough (> 2*LINK_WINDOW) that the
        // windowed max fully forgets the 60 Mbit/s seed and genuinely
        // converges on 19 Mbit/s.
        let switch_time = now;
        let deadline = 2 * LINK_WINDOW + Duration::from_secs(2);
        while now.duration_since(switch_time) < deadline {
            now += STEP;
            t.observe_at(now, Some(19e6), 2.0, 3.0);
            assert_eq!(
                t.recommended(),
                None,
                "a dip to 19 Mbit/s (above the 0.8x hysteresis floor) must not downgrade High"
            );
        }
        assert_eq!(t.current_tier(), QualityPreset::High);
    }

    /// REGRESSION: `capacity_bps()` is a MAX over two `LINK_WINDOW`s, so a
    /// single spurious high sample used to rule for up to `2*LINK_WINDOW`
    /// even after the link genuinely dropped, taking 12-15 s to react. A
    /// fresh sample already below the CURRENT tier's own downgrade floor must
    /// be trusted directly, downgrading within SUSTAIN + COOLDOWN instead.
    #[test]
    fn a_single_low_sample_downgrades_within_sustain_plus_cooldown_not_two_windows() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        for _ in 0..30 {
            now += STEP;
            t.observe_at(now, Some(60e6), 1.0, 4.0);
        }
        assert!(t.recommended().is_some(), "must upgrade to High first");
        assert_eq!(t.current_tier(), QualityPreset::High);
        let switch_time = now;

        // A single, sustained low sample (2 Mbit/s, well under High's
        // 16 Mbit/s downgrade floor): must rule directly rather than wait for
        // the stale 60 Mbit/s sample to age out of the windowed max.
        let mut rec = None;
        while now.duration_since(switch_time) < SUSTAIN + COOLDOWN + Duration::from_secs(1) {
            now += STEP;
            t.observe_at(now, Some(2e6), 100.0, 4.0);
            if let Some(r) = t.recommended() {
                rec = Some(r);
                break;
            }
        }
        let elapsed = now.duration_since(switch_time);
        assert!(
            elapsed < 2 * LINK_WINDOW,
            "must not wait for the windowed max to age out, took {elapsed:?}"
        );
        assert!(
            rec.is_some(),
            "must downgrade within SUSTAIN + COOLDOWN of the crash, took {elapsed:?}"
        );
        assert_ne!(t.current_tier(), QualityPreset::High);
    }

    /// `resync` must realign the tuner's bookkeeping to settings applied from
    /// OUTSIDE it (a manual `SetQuality`), or a manual detour desyncs Auto:
    /// switching back to it would do nothing until fresh measurements happen
    /// to walk the ladder back to wherever it actually is.
    #[test]
    fn resync_realigns_the_tuner_after_a_manual_preset_detour() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        // Establish Auto at High with real measurements.
        for _ in 0..30 {
            now += STEP;
            t.observe_at(now, Some(60e6), 1.0, 4.0);
        }
        t.recommended().expect("must upgrade to High");
        assert_eq!(t.current_tier(), QualityPreset::High);

        // The user manually detours to Low. Without resync, `current` would
        // still say High.
        t.resync(&QualityPreset::Low.settings());
        assert_eq!(
            t.current_tier(),
            QualityPreset::Low,
            "resync must realign current_tier() to the manual preset"
        );

        // Immediately observing the SAME link that was already High-band
        // must not instantly flip back: resync must also have cleared any
        // stale candidate, so a fresh sustain period is required.
        now += STEP;
        t.observe_at(now, Some(60e6), 1.0, 4.0);
        assert_eq!(
            t.recommended(),
            None,
            "a single sample right after resync must not immediately recommend a switch"
        );
    }
}
