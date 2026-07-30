//! Quality presets, SetEncodings list construction, and the adaptive Auto
//! tuner (PRD/09).
//!
//! [`AutoTuner`] keeps decaying averages of throughput, RTT and decode time,
//! walks the tier ladder in §3.2, and applies mandatory hysteresis: a tier
//! change must be sustained for at least [`SUSTAIN`] before it is offered,
//! and switches never happen more often than once per [`COOLDOWN`].

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

/// Token minimum so a stray byte or two cannot produce a rate.
///
/// It is deliberately tiny. Once throughput is measured against *active
/// transfer time*, byte volume stops being the discriminator: a 50 kbit/s link
/// moves barely a kilobyte per window, and rejecting that would mask exactly
/// the constrained links Auto exists to find. [`MIN_ACTIVE_S`] does the real
/// work, an idle desktop is rejected because the link was busy for a fraction
/// of a millisecond, not because the byte count was low.
const MIN_SAMPLE_BYTES: usize = 256;

/// Minimum *active transfer* time for the sample to mean anything. Below this
/// the clock resolution dominates and the computed rate is noise.
const MIN_ACTIVE_S: f64 = 0.002;

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
    /// `throughput_bps` must be measured over *active transfer time*, not
    /// wall-clock, see [`AutoTuner::observe`].
    ///
    /// RTT is deliberately not consulted: it is only obtainable from fence
    /// probes, and the whole TightVNC/libvncserver family has no Fence support,
    /// so on exactly the servers that matter it is permanently 0 and any rule
    /// built on it silently misfires.
    fn from_link(throughput_bps: f64, _rtt_ms: f32) -> Self {
        if throughput_bps > 20e6 {
            Tier::High
        } else if throughput_bps > 5e6 {
            Tier::Medium
        } else if throughput_bps > 1e6 {
            Tier::LowIsh
        } else {
            Tier::Low
        }
    }

    fn settings(self) -> QualitySettings {
        match self {
            Tier::High => QualityPreset::High.settings(),
            Tier::Medium => QualityPreset::Medium.settings(),
            Tier::LowIsh => QualitySettings {
                jpeg_quality: 4,
                compression: 5,
                pixel_format: ColorDepth::Palette256,
                allow_jpeg: true,
                allow_h264: true,
                grayscale_levels: None,
            },
            Tier::Low => QualitySettings {
                jpeg_quality: 2,
                compression: 8,
                pixel_format: ColorDepth::Rgb222,
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
    throughput_bps: f64,
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
            throughput_bps: 10e6,
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

    /// Record one measurement sample: bytes received since the previous
    /// observation, current RTT estimate, and decode time of the last update.
    /// Non-positive `rtt_ms`/`decode_ms` are treated as "no sample".
    /// `active_s` is the time actually spent transferring during the window, /// NOT the window length. See [`AutoTuner`] for why that distinction is the
    /// whole ballgame.
    pub fn observe(&mut self, bytes: usize, active_s: f64, rtt_ms: f32, decode_ms: f32) {
        self.observe_at(Instant::now(), bytes, active_s, rtt_ms, decode_ms);
    }

    fn observe_at(
        &mut self,
        now: Instant,
        bytes: usize,
        active_s: f64,
        rtt_ms: f32,
        decode_ms: f32,
    ) {
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

                    // Throughput is NOT. You can only measure a link's capacity
                    // while you are actually loading it: a desktop that nobody
                    // is touching sends a few hundred bytes a second, and
                    // feeding that in as "throughput" makes an idle gigabit LAN
                    // look like a modem. That is what previously drove Auto down
                    // to 64 colours on a fast network, and each tier change
                    // forced a full-screen redraw, which reads as the picture
                    // repainting in waves.
                    //
                    // So: only let a sample move the estimate when enough data
                    // moved to say anything. Otherwise keep the last real
                    // measurement and leave the tier alone.
                    // Capacity = bytes / time spent MOVING those bytes. Using
                    // the window length instead is what made an idle desktop on
                    // a fast link report ~500 kbit/s and drag quality to the
                    // floor: the link was busy for 20 ms of every second and
                    // idle for the other 980.
                    if bytes >= MIN_SAMPLE_BYTES && active_s >= MIN_ACTIVE_S {
                        let inst_bps = (bytes as f64 * 8.0) / active_s;
                        self.throughput_bps += a * (inst_bps - self.throughput_bps);
                        self.have_real_sample = true;
                    } else {
                        // Too little moved to say anything about the link.
                        // Crucially this is NOT evidence of slowness, leave the
                        // estimate and the ladder exactly as they were.
                        self.last_observe = Some(now);
                        return;
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

        let target = Tier::from_link(self.throughput_bps, self.rtt_ms);
        // Client CPU-bound: sustained decode overruns ask for lower
        // compression at the same tier.
        let relief = self.decode_ms > FRAME_BUDGET_MS;
        let desired: Desired = (target, relief);

        let mut sh = self.shared.lock();
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

    /// Bytes per STEP that produce `bps` bits/sec instantaneous throughput.
    fn bytes_for(bps: f64) -> usize {
        (bps / 8.0 * STEP.as_secs_f64()) as usize
    }

    #[test]
    fn sustained_fast_link_upgrades_to_high_once() {
        let mut t = AutoTuner::new();
        assert_eq!(t.current_tier(), QualityPreset::Medium);
        let base = Instant::now();
        let mut now = base;
        for _ in 0..30 {
            // 6 s of 60 Mbit/s, 1 ms RTT
            now += STEP;
            t.observe_at(now, bytes_for(60e6), STEP.as_secs_f64(), 1.0, 4.0);
        }
        let rec = t.recommended().expect("sustained fast link must upgrade");
        assert_eq!(rec, QualityPreset::High.settings());
        assert_eq!(t.current_tier(), QualityPreset::High);
        // Taking the recommendation records it: not returned again.
        assert_eq!(t.recommended(), None);
        // And with unchanged conditions, no new recommendation appears.
        now += STEP;
        t.observe_at(now, bytes_for(60e6), STEP.as_secs_f64(), 1.0, 4.0);
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
            t.observe_at(now, bytes_for(0.2e6), STEP.as_secs_f64(), 300.0, 4.0);
        }
        let rec = t.recommended().expect("sustained slow link must downgrade");
        assert_eq!(rec.jpeg_quality, 2);
        assert_eq!(rec.pixel_format, ColorDepth::Rgb222);
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
                t.observe_at(now, bytes_for(bps), STEP.as_secs_f64(), 30.0, 5.0);
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
            t.observe_at(now, bytes_for(60e6), STEP.as_secs_f64(), 1.0, 4.0);
        }
        assert!(t.recommended().is_some());
        let switch_time = now;

        // Immediately crash the link, sustained. The downgrade is warranted
        // after 2 s of sustain but must wait for the 5 s cooldown.
        loop {
            now += STEP;
            t.observe_at(now, bytes_for(0.05e6), STEP.as_secs_f64(), 300.0, 4.0);
            let elapsed = now.duration_since(switch_time);
            if elapsed < COOLDOWN {
                assert_eq!(
                    t.recommended(),
                    None,
                    "no switch may occur within the cooldown ({elapsed:?})"
                );
            } else {
                break;
            }
        }
        // Past the cooldown (and long past sustain), the downgrade arrives.
        now += STEP;
        t.observe_at(now, bytes_for(0.05e6), STEP.as_secs_f64(), 300.0, 4.0);
        let rec = t.recommended().expect("downgrade after cooldown");
        assert_eq!(t.current_tier(), QualityPreset::Low);
        assert_eq!(rec.jpeg_quality, 2);
    }

    #[test]
    fn sustained_decode_overrun_reduces_compression() {
        let mut t = AutoTuner::new();
        let base = Instant::now();
        let mut now = base;
        for _ in 0..30 {
            // Healthy Medium-band link, but decoding takes 30 ms per frame.
            now += STEP;
            t.observe_at(now, bytes_for(10e6), STEP.as_secs_f64(), 30.0, 30.0);
        }
        let rec = t.recommended().expect("CPU-bound client warrants relief");
        let medium = QualityPreset::Medium.settings();
        assert_eq!(t.current_tier(), QualityPreset::Medium, "tier unchanged");
        assert_eq!(rec.jpeg_quality, medium.jpeg_quality);
        assert!(
            rec.compression < medium.compression,
            "compression must drop when decode exceeds the frame budget"
        );
    }

    #[test]
    fn no_recommendation_without_measurements() {
        let t = AutoTuner::new();
        assert_eq!(t.recommended(), None);
        assert_eq!(t.current_tier(), QualityPreset::Medium);
    }

    /// The bug the user hit: a gigabit LAN showing a desktop nobody is
    /// touching. Almost no bytes flow, and the old tuner read that as a slow
    /// link and walked down to 64 colours, which also forced a full-screen
    /// redraw on every step ("the picture repaints in waves").
    #[test]
    fn an_idle_fast_link_never_downgrades() {
        let mut t = AutoTuner::new();
        let start = Instant::now();
        // 60 seconds of a static desktop: a couple of hundred bytes a second
        // of cursor/heartbeat traffic, sub-millisecond RTT.
        for i in 1..=60 {
            // 300 bytes that took 0.4 ms to arrive: the link was busy for a
            // rounding error of each second and idle for the rest.
            t.observe_at(start + Duration::from_secs(i), 300, 0.0004, 0.4, 1.0);
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
            t.observe_at(start + Duration::from_secs(i), 100 * 1024, 1.0, 90.0, 2.0);
        }
        let rec = t.recommended().expect("a loaded slow link must downgrade");
        assert!(
            rec.jpeg_quality <= 4,
            "expected a lower-quality tier, got {rec:?}"
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
            t.observe_at(
                start + Duration::from_secs(i),
                5 * 1024 * 1024,
                1.0,
                0.5,
                3.0,
            );
        }
        let rec = t.recommended().expect("a loaded fast link must upgrade");
        assert!(rec.jpeg_quality >= 8, "expected high quality, got {rec:?}");
    }
}
