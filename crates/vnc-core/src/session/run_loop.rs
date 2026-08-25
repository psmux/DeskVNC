//! The connected-state protocol pump.
//!
//! `tokio::select!` over socket reads, the command channel, a 1-second stats
//! tick, and cancellation. All rectangles of one FramebufferUpdate are
//! coalesced into a single `SessionEvent::FramebufferUpdate` with a unioned
//! damage rect, never per-rect (PRD/02 §5).

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::clipboard::ClipboardState;
use crate::encodings::DecoderState;
use crate::error::{Result, VncError};
use crate::proto::messages::{
    self, ext_clipboard, fence_flags, server_msg, CutTextPayload, Screen,
};
use crate::proto::pseudo::{self, PseudoRect};
use crate::quality::{AutoTuner, LinkMeter, QualityResolve};
use crate::types::{
    encoding, ClientCommand, DecodedRect, PixelFormat, QualityPreset, QualitySettings, Rect,
    ServerCapabilities, SessionEvent, SessionStats,
};
use vnc_transport::BoxedStream;

use super::connection::{pixel_format_for, RunOutcome, SessionSettings};
use super::emit;

/// Declare the peer dead when a fence RTT probe goes unanswered this long
/// while newer traffic would have been expected (PRD/05 §6.4).
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle time after which a lossily-painted region is re-fetched sharp
/// (PRD/09 §3.2, "auto lossless refresh").
///
/// Long enough that it never fires mid-drag, a lossless repaint during motion
/// would waste the bandwidth that made the motion smooth in the first place.
const ALR_IDLE: Duration = Duration::from_millis(900);

/// JPEG quality at or above which a rect is already effectively lossless, so
/// there is nothing for the refresh to improve.
const ALR_QUALITY_FLOOR: u8 = 9;

/// Minimum spacing between lossless refreshes.
///
/// The damage region is a bounding box, so a handful of scattered rects can
/// balloon it to the whole desktop. Without this, a screen with a periodic
/// animation would trigger a full-screen lossless repaint every couple of
/// seconds, reintroducing exactly the "picture washes down the screen" effect
/// the lossy path was chosen to avoid.
const ALR_COOLDOWN: Duration = Duration::from_secs(5);

/// How quiet the stream must be before timing a round trip without Fence.
///
/// The probe is closed by the next FramebufferUpdate, and on a busy screen
/// that is somebody else's: one already in flight ends it after a millisecond,
/// while ours queued behind a full repaint reads as hundreds. Waiting for a
/// gap means the parked incremental request is still parked, so the only
/// update that can arrive is the answer to the probe.
const PROBE_IDLE: Duration = Duration::from_millis(300);

/// Abandon an unanswered no-Fence probe after this, so one lost answer does
/// not stop the reading updating for the rest of the session.
const PROBE_STALE: Duration = Duration::from_secs(5);

/// Weight of a new sample in the reported round trip. Even a well-timed
/// probe carries the server's own scheduling delay, so a single sample is
/// jittery; this keeps the figure honest without it dancing every second.
const RTT_SMOOTHING: f32 = 0.3;

/// Largest update still credible as the answer to a one-pixel probe. Servers
/// may round a request out to a small tile, so this is not exactly 1.
const PROBE_ANSWER_MAX_AREA: usize = 16 * 16;

/// Longest gap between finishing one update and the arrival of the next
/// update's header that still counts as a "busy streak", for the passive
/// round-trip readout (see `passive_rtt`).
///
/// The passive sample is request-to-next-header, and that elapsed time is
/// the server's response time PLUS however long the server sat waiting for
/// something on the desktop to change. The idle wait is the confound: on a
/// still screen it is unbounded, and timing against it reports seconds of
/// "latency" that no user is experiencing.
///
/// A streak filters the idle wait out. If the previous update finished less
/// than this long ago, the server already had damage queued when our request
/// landed, so it started encoding immediately and the elapsed time is the
/// real cost of getting the next picture. 120 ms is comfortably longer than
/// the measured full-screen encode on the 2880x1800 TightVNC-family server
/// (130 to 180 ms is the request cost, and back-to-back updates arrive far
/// closer together than that), and short enough that a human pause between
/// keystrokes breaks the streak instead of poisoning the window.
const BUSY_STREAK_GAP: Duration = Duration::from_millis(120);

/// Passive round-trip samples kept for the median.
///
/// The median, not a mean or an EWMA: one update that happens to carry a
/// full-screen repaint costs an order of magnitude more than the small ones
/// around it, and an average lets that single outlier set the reported
/// figure. 16 samples at typical update rates is a couple of seconds of
/// history, recent enough to follow a link that genuinely degrades.
///
/// The count is only half the bound. Eviction by count alone assumes samples
/// keep arriving, and the busy-streak gate (see `BUSY_STREAK_GAP`) means they
/// stop entirely whenever the desktop goes quiet: nine 400 ms samples from a
/// burst of activity, ten minutes of idle, then eight 20 ms samples from
/// light activity leaves a window whose median is a ten-minute-old number
/// being reported as the current reading (and fed to a quality-tuner cap
/// that can pin quality down on the strength of it). Every sample therefore
/// carries its own instant and is dropped past `RTT_SAMPLE_FRESH`, by age as
/// well as by count.
const PASSIVE_RTT_WINDOW: usize = 16;

/// A passive or probe sample older than this no longer speaks for the link,
/// so a lower-priority source is allowed to take over the reading.
const RTT_SAMPLE_FRESH: Duration = Duration::from_secs(5);

/// Give up waiting for the answer to an always-refresh request after this.
///
/// Without an escape hatch, one lost or unrecognised answer would park the
/// feature for the rest of the session, and the whole point of the switch is
/// that it keeps working on servers whose reporting cannot be trusted.
const REFRESH_ABANDON: Duration = Duration::from_secs(10);

/// Fraction of the framebuffer an update must cover to count as the answer
/// to a full-screen non-incremental refresh request.
///
/// Not 1.0: the damage figure is a union of the rects that arrived, and a
/// server is free to leave out a strip it knows has not changed or to round
/// the region out to its own tile grid. 0.9 is high enough that the small
/// incremental updates this used to be fooled by (a few dirty tiles, well
/// under 1% of a 2880x1800 desktop) cannot reach it.
const REFRESH_ANSWER_COVERAGE: f64 = 0.9;

/// Upper bound on the always-refresh cooldown.
///
/// The cooldown is proportional to how long the last refresh took to answer,
/// so a server in trouble is asked less often. The cap keeps a pathological
/// answer (10.1 s was the worst case measured) from silencing the feature
/// for minutes on end.
const REFRESH_MAX_COOLDOWN: Duration = Duration::from_secs(5);

/// Environment variable that turns the protocol trace on: `DVV_TRACE_PROTOCOL=1`.
const TRACE_ENV: &str = "DVV_TRACE_PROTOCOL";

/// Opt-in protocol instrumentation, off unless `DVV_TRACE_PROTOCOL=1`.
///
/// This exists because the bug that made the auto tuner drive Tight
/// compression to 0 (and saturate the link at 9.9 MB/s) was invisible from
/// inside the app: the stats panel showed throughput, but nothing showed
/// what we were ASKING the server for or at what settings. Reproducing it
/// needed an external RFB proxy. One env var should be enough.
///
/// The flag is read once at construction into a bool, so with the trace off
/// the hot path costs one predictable branch per client message and nothing
/// else: no formatting, no allocation, no `tracing` machinery.
#[derive(Default)]
struct ProtocolTrace {
    enabled: bool,
    /// Incremental FramebufferUpdateRequests sent since the last summary.
    incr_requests: u32,
    /// Non-incremental (full re-fetch) FramebufferUpdateRequests sent since
    /// the last summary. This is the count that exposed the always-refresh
    /// problem: one per second, each one a whole screen.
    full_requests: u32,
    /// Requested area since the last summary, counted in whole screens, so
    /// "2.0" means we asked the server to encode twice the desktop this
    /// second regardless of how it was split up.
    incr_screens: f32,
    full_screens: f32,
    /// Most recent request of each kind, for the region readout.
    last_incr: Option<Rect>,
    last_full: Option<Rect>,
    set_encodings: u32,
    key_events: u32,
    pointer_events: u32,
    other_msgs: u32,
    /// `rects_decoded` at the last summary, for the per-second rate.
    last_rects: u64,
}

impl ProtocolTrace {
    fn new() -> Self {
        Self {
            enabled: std::env::var(TRACE_ENV).as_deref() == Ok("1"),
            ..Default::default()
        }
    }

    /// Log and count one outbound message. Called from `RunLoop::send` with
    /// the exact bytes about to go on the wire, so this sees the protocol as
    /// the server sees it rather than as the call sites intended it.
    fn record_client_message(&mut self, bytes: &[u8], fb_width: u16, fb_height: u16) {
        let Some(&kind) = bytes.first() else {
            return;
        };
        use messages::client_msg as m;
        match kind {
            m::FRAMEBUFFER_UPDATE_REQUEST if bytes.len() >= 10 => {
                let incremental = bytes[1] != 0;
                let rect = Rect::new(
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                    u16::from_be_bytes([bytes[4], bytes[5]]),
                    u16::from_be_bytes([bytes[6], bytes[7]]),
                    u16::from_be_bytes([bytes[8], bytes[9]]),
                );
                let screen = (fb_width as f32 * fb_height as f32).max(1.0);
                let fraction = rect.area() as f32 / screen;
                if incremental {
                    self.incr_requests += 1;
                    self.incr_screens += fraction;
                    self.last_incr = Some(rect);
                } else {
                    self.full_requests += 1;
                    self.full_screens += fraction;
                    self.last_full = Some(rect);
                }
                tracing::info!(
                    incremental,
                    x = rect.x,
                    y = rect.y,
                    w = rect.width,
                    h = rect.height,
                    screen_fraction = fraction,
                    "TX FramebufferUpdateRequest"
                );
            }
            m::SET_ENCODINGS if bytes.len() >= 4 => {
                self.set_encodings += 1;
                let n = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
                // The encoding list carries the JPEG-quality and
                // compression-level pseudo-encodings, which is where the
                // compression-to-0 bug actually lived, so print them.
                let encodings: Vec<i32> = bytes[4..]
                    .chunks_exact(4)
                    .take(n)
                    .map(|c| i32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
                tracing::info!(count = n, ?encodings, "TX SetEncodings");
            }
            m::SET_PIXEL_FORMAT => tracing::info!("TX SetPixelFormat"),
            m::ENABLE_CONTINUOUS_UPDATES if bytes.len() >= 2 => {
                tracing::info!(enable = bytes[1] != 0, "TX EnableContinuousUpdates");
            }
            m::CLIENT_FENCE if bytes.len() >= 8 => {
                tracing::info!(
                    flags = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
                    "TX ClientFence"
                );
            }
            m::SET_DESKTOP_SIZE if bytes.len() >= 6 => {
                tracing::info!(
                    w = u16::from_be_bytes([bytes[2], bytes[3]]),
                    h = u16::from_be_bytes([bytes[4], bytes[5]]),
                    "TX SetDesktopSize"
                );
            }
            // Input is high-rate and rarely the subject of the investigation,
            // so it is counted at INFO and printed only at DEBUG.
            m::KEY_EVENT | m::QEMU => {
                self.key_events += 1;
                tracing::debug!("TX KeyEvent");
            }
            m::POINTER_EVENT => {
                self.pointer_events += 1;
                tracing::debug!("TX PointerEvent");
            }
            m::CLIENT_CUT_TEXT => {
                self.other_msgs += 1;
                tracing::info!(len = bytes.len(), "TX ClientCutText");
            }
            other => {
                self.other_msgs += 1;
                tracing::info!(kind = other, len = bytes.len(), "TX (other)");
            }
        }
    }

    /// One summary line per stats tick, then reset the counters.
    ///
    /// `compression` is the negotiated Tight compression level, which is NOT
    /// in `SessionStats`: it is the number that went to 0 in the bug this
    /// trace was written for, so it is printed alongside the JPEG quality.
    fn summarise(&mut self, dt_s: f64, stats: &SessionStats, rects_total: u64, compression: u8) {
        let rects = rects_total.saturating_sub(self.last_rects);
        self.last_rects = rects_total;
        let fmt_rect = |r: Option<Rect>| match r {
            Some(r) => format!("{}x{}+{}+{}", r.width, r.height, r.x, r.y),
            None => "-".to_string(),
        };
        tracing::info!(
            fbur_incremental = self.incr_requests,
            fbur_full = self.full_requests,
            incremental_screens = self.incr_screens,
            full_screens = self.full_screens,
            last_incremental = fmt_rect(self.last_incr),
            last_full = fmt_rect(self.last_full),
            set_encodings = self.set_encodings,
            key_events = self.key_events,
            pointer_events = self.pointer_events,
            other_messages = self.other_msgs,
            jpeg_quality = stats.jpeg_quality,
            compression,
            bytes_per_sec = stats.throughput_bps / 8.0,
            updates_per_sec = stats.fps,
            rects_per_sec = rects as f64 / dt_s,
            duty_cycle = stats.server_duty_cycle,
            rtt_ms = stats.rtt_ms,
            rtt_source = ?stats.rtt_source,
            "protocol trace"
        );
        self.incr_requests = 0;
        self.full_requests = 0;
        self.incr_screens = 0.0;
        self.full_screens = 0.0;
        self.last_incr = None;
        self.last_full = None;
        self.set_encodings = 0;
        self.key_events = 0;
        self.pointer_events = 0;
        self.other_msgs = 0;
    }
}

/// An `AsyncRead` wrapper that counts every byte received, for stats, and
/// times stall-anchored bursts for the Auto tuner's link-capacity estimate
/// (see [`LinkMeter`]).
///
/// This is the ONLY place in the client that can see whether a poll found
/// data already waiting or an empty socket. Everything above it (the run
/// loop) sees only how long a read took, which is identical in both cases,
/// a slow server and a slow link both make `read()` take a while.
pub(crate) struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
    link_peak: Arc<AtomicU64>,
    meter: LinkMeter,
}

impl<R> CountingReader<R> {
    pub fn new(inner: R, count: Arc<AtomicU64>, link_peak: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            count,
            link_peak,
            meter: LinkMeter::default(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let me = &mut *self;
        let res = Pin::new(&mut me.inner).poll_read(cx, buf);
        match res {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before;
                me.count.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(bps) = me.meter.received(Instant::now(), n) {
                    me.link_peak.fetch_max(bps as u64, Ordering::Relaxed);
                }
            }
            Poll::Pending => me.meter.stalled(),
            Poll::Ready(Err(_)) => {}
        }
        res
    }
}

/// The `AsyncWrite` counterpart of [`CountingReader`]: counts every byte
/// sent, for stats. Wraps the plaintext side of the boxed stream, so TLS
/// framing overhead is not charged to the session.
pub(crate) struct CountingWriter<W> {
    inner: W,
    count: Arc<AtomicU64>,
}

impl<W> CountingWriter<W> {
    pub fn new(inner: W, count: Arc<AtomicU64>) -> Self {
        Self { inner, count }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = &mut *self;
        let res = Pin::new(&mut me.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            me.count.fetch_add(n as u64, Ordering::Relaxed);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type Reader = BufReader<CountingReader<ReadHalf<BoxedStream>>>;
type Writer = CountingWriter<WriteHalf<BoxedStream>>;

enum Step {
    Message(std::io::Result<u8>),
    Command(Option<ClientCommand>),
    Tick,
    Cancelled,
}

pub(crate) struct RunLoop {
    reader: Reader,
    writer: Writer,
    caps: ServerCapabilities,
    pf: PixelFormat,
    decoder: DecoderState,
    clipboard: ClipboardState,
    /// Our Extended Clipboard capabilities message has gone out. The extension
    /// requires BOTH peers to announce caps before any other extended message,
    /// so ours is sent (once) the moment the server's arrives.
    clipboard_caps_sent: bool,
    /// The text most recently offered to the server, kept so a `request` can
    /// be answered. A server that told us it wants no unsolicited data ignores
    /// a bare `provide` and asks for the text instead; with nothing held here
    /// there would be nothing to answer it with.
    clipboard_offered: Option<String>,
    tuner: AutoTuner,
    applied_quality: QualitySettings,

    fb_width: u16,
    fb_height: u16,
    screens: Vec<Screen>,
    /// keysym → keycode for every key we believe is currently pressed.
    pressed: HashMap<u32, Option<u32>>,
    /// Continuous updates negotiated and switched on.
    cu_active: bool,
    /// The stored resize request has been re-applied on this connection.
    resize_reapplied: bool,
    /// The priming non-incremental request is still outstanding.
    ///
    /// While it is, pipelining a second request on top of it makes the server
    /// answer BOTH with the whole screen, 8.2 MB instead of 4.1 MB on a
    /// 2560x1600 desktop, straight down a Wi-Fi link, doubling the time before
    /// the first picture appears.
    priming_update_pending: bool,

    // stats
    bytes_counter: Arc<AtomicU64>,
    last_bytes: u64,
    /// Bytes written to the transport, incremented by [`CountingWriter`], /// the TX mirror of `bytes_counter`.
    sent_counter: Arc<AtomicU64>,
    last_sent: u64,
    frames_since_tick: u32,
    rects_decoded: u64,
    decode_ms_tick: f32,
    /// When the last stats tick actually ran, so per-second rates can divide
    /// by the REAL elapsed time rather than assume exactly 1 s.
    /// `MissedTickBehavior::Skip` makes the interval unbounded whenever one
    /// update blocks the select loop past a tick, understating throughput
    /// and fps whenever that happens (dividing a full second's worth of
    /// bytes by an interval that was actually several seconds long).
    last_tick_at: Option<Instant>,
    /// Highest stall-anchored burst rate (bits/sec) [`CountingReader`]
    /// measured since the last tick, or 0 if none completed. This is a lower
    /// bound on link capacity regardless of how slowly the server encoded
    /// between bursts, see `quality::LinkMeter`.
    link_peak: Arc<AtomicU64>,
    /// Union of everything painted lossily since the last lossless refresh.
    /// Empty means the screen is already sharp.
    lossy_damage: Rect,
    /// When the last framebuffer update arrived, for the idle test.
    last_update_at: Option<Instant>,
    /// When the last lossless refresh was issued, for the cooldown.
    last_alr_at: Option<Instant>,
    /// A lossless refresh's sharp SetEncodings + non-incremental request has
    /// gone out and the adaptive SetEncodings is being withheld until the
    /// ANSWERING update has been fully consumed (see `maybe_lossless_refresh`
    /// and the end of `handle_framebuffer_update`). Sending the restore
    /// back-to-back with the request instead let a server that processes
    /// SetEncodings synchronously but queues the update apply the adaptive
    /// list before it ever serviced the sharp request, so the "sharp"
    /// refresh came back lossy and re-queued itself every ALR_COOLDOWN,
    /// forever, on an otherwise idle screen.
    alr_restore_pending: bool,
    current_encoding: i32,
    rtt_ms: f32,
    /// Outstanding RTT probe for a server with no Fence support: when the
    /// answering update arrives, the round trip is the elapsed time.
    ///
    /// The Fence probe below is exact but needs the extension, and the
    /// libvncserver family (x11vnc among them) does not implement it, so
    /// every such session reported a flat 0 ms forever. A non-incremental
    /// request for a single pixel is the universal equivalent: every RFB
    /// server must answer one, and one pixel costs nothing.
    probe_request_at: Option<Instant>,
    /// When the one-pixel probe last produced a sample. The probe needs a
    /// quiet screen, so on a busy desktop its reading can be minutes old;
    /// past `RTT_SAMPLE_FRESH` the passive readout takes over.
    probe_sample_at: Option<Instant>,
    /// Outstanding fence RTT probe: (payload id, send time).
    probe: Option<(u64, Instant)>,
    /// When the currently outstanding pipelined incremental
    /// FramebufferUpdateRequest went out, for the passive round-trip readout.
    /// Consumed by the next update header.
    ///
    /// Two call sites write it and they sit at opposite ends of an update:
    /// the normal path asks for the next update as soon as the current
    /// header arrives, the priming path waits until the priming update has
    /// been fully consumed (asking sooner makes the server resend the whole
    /// screen). Both go through `arm_pipelined_request`, so the field means
    /// one thing in both cases, "the outstanding request left at this
    /// instant", and `decode_ms_since_request` below is zeroed with it so the
    /// decode subtraction stays correct whichever site armed it.
    pipelined_request_at: Option<Instant>,
    /// Our own decode time, in milliseconds, accumulated since
    /// `pipelined_request_at` was armed.
    ///
    /// This is the client's own contribution to the passive sample, and it is
    /// not small: measured at 42.7% duty at the High quality tier, roughly
    /// 43 ms per sample at ten updates per second against the 100 ms
    /// threshold the tuner cap uses. Worse, it is tier-correlated (heavier at
    /// High, lighter at Medium), so leaving it in lets a slow CLIENT on a
    /// healthy server engage a cap written for slow SERVERS. Subtracted in
    /// `record_passive_rtt`.
    decode_ms_since_request: f32,
    /// When the last FramebufferUpdate finished being read and decoded. The
    /// busy-streak test for a passive sample (see `BUSY_STREAK_GAP`).
    last_update_done_at: Option<Instant>,
    /// Rolling window of passive round-trip samples, oldest first, bounded by
    /// both `PASSIVE_RTT_WINDOW` and `RTT_SAMPLE_FRESH`. The median of the
    /// still-fresh samples is reported.
    passive_rtt: VecDeque<PassiveSample>,
    /// Time spent inside FramebufferUpdate handling since the last stats
    /// tick, for `SessionStats::server_duty_cycle`.
    update_busy_tick: Duration,
    /// An always-refresh (or manual Refresh) full-screen non-incremental
    /// request is outstanding, sent at this instant. See `tick`.
    refresh_request_at: Option<Instant>,
    /// When the last such request was answered, and how long it took. The
    /// pair drives the cooldown that stops always-refresh monopolising the
    /// server's shared encoder.
    refresh_answered_at: Option<Instant>,
    refresh_cost: Duration,
    /// Opt-in protocol trace, `DVV_TRACE_PROTOCOL=1`.
    trace: ProtocolTrace,
    /// Pixel formats sent with a fence-guarded SetPixelFormat whose fence
    /// response has not come back yet, oldest first. Decoding stays in the
    /// old format until the server proves (by answering the fence) that it
    /// has processed the switch; everything it sent before that answer was
    /// encoded in the old format.
    pending_pf: VecDeque<PixelFormat>,
    /// Commands that arrived mid-update and cannot safely run between rects
    /// (they change encodings, format, or session state). Serviced by the
    /// run loop once the update has been fully consumed.
    deferred_cmds: Vec<ClientCommand>,
    /// A Disconnect arrived mid-update: unwind without reading further.
    pending_outcome: Option<RunOutcome>,
    epoch: Instant,
}

/// Fence payload marking the pixel-format-switch guard, distinguishable from
/// the 8-byte RTT probe payload by length alone.
const PF_FENCE_PAYLOAD: &[u8] = b"pf-switch";

impl RunLoop {
    // One constructor called from exactly one place (`connection::run_once`)
    // wiring up every piece of per-connection state; splitting it into a
    // builder would be an abstraction with a single caller.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: Reader,
        writer: Writer,
        caps: ServerCapabilities,
        pf: PixelFormat,
        applied_quality: QualitySettings,
        bytes_counter: Arc<AtomicU64>,
        sent_counter: Arc<AtomicU64>,
        link_peak: Arc<AtomicU64>,
    ) -> Self {
        let (fb_width, fb_height) = (caps.width, caps.height);
        Self {
            reader,
            writer,
            caps,
            pf,
            decoder: DecoderState::new(pf),
            clipboard: ClipboardState::new(),
            clipboard_caps_sent: false,
            clipboard_offered: None,
            tuner: AutoTuner::new(),
            applied_quality,
            fb_width,
            fb_height,
            screens: Vec::new(),
            pressed: HashMap::new(),
            cu_active: false,
            resize_reapplied: false,
            priming_update_pending: true,
            bytes_counter,
            last_bytes: 0,
            sent_counter,
            last_sent: 0,
            frames_since_tick: 0,
            rects_decoded: 0,
            decode_ms_tick: 0.0,
            last_tick_at: None,
            link_peak,
            lossy_damage: Rect::new(0, 0, 0, 0),
            last_update_at: None,
            last_alr_at: None,
            alr_restore_pending: false,
            current_encoding: encoding::RAW,
            rtt_ms: 0.0,
            probe: None,
            probe_request_at: None,
            probe_sample_at: None,
            pipelined_request_at: None,
            decode_ms_since_request: 0.0,
            last_update_done_at: None,
            passive_rtt: VecDeque::with_capacity(PASSIVE_RTT_WINDOW),
            update_busy_tick: Duration::ZERO,
            refresh_request_at: None,
            refresh_answered_at: None,
            refresh_cost: Duration::ZERO,
            trace: ProtocolTrace::new(),
            pending_pf: VecDeque::new(),
            deferred_cmds: Vec::new(),
            pending_outcome: None,
            epoch: Instant::now(),
        }
    }

    fn full_rect(&self) -> Rect {
        Rect::new(0, 0, self.fb_width, self.fb_height)
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        // Every client message funnels through here, so this one branch is
        // the whole client->server side of the protocol trace. With the
        // trace off it is a predictable, never-taken branch: no formatting,
        // no allocation, no tracing machinery.
        if self.trace.enabled {
            let (w, h) = (self.fb_width, self.fb_height);
            self.trace.record_client_message(bytes, w, h);
        }
        self.writer
            .write_all(bytes)
            .await
            .map_err(messages::map_eof)?;
        self.writer.flush().await.map_err(messages::map_eof)?;
        Ok(())
    }

    pub async fn run(
        &mut self,
        settings: &mut SessionSettings,
        events: &mpsc::Sender<SessionEvent>,
        commands: &mut mpsc::Receiver<ClientCommand>,
        cancel: &CancellationToken,
    ) -> Result<RunOutcome> {
        let mut stats_tick = tokio::time::interval(Duration::from_secs(1));
        stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        stats_tick.reset(); // don't fire immediately

        loop {
            let step = tokio::select! {
                biased;
                _ = cancel.cancelled() => Step::Cancelled,
                byte = self.reader.read_u8() => Step::Message(byte),
                cmd = commands.recv() => Step::Command(cmd),
                _ = stats_tick.tick() => Step::Tick,
            };

            match step {
                Step::Cancelled => {
                    // Keyboard safety: never leave stuck modifiers behind.
                    let _ = self.release_all_keys(settings).await;
                    return Err(VncError::Cancelled);
                }
                Step::Message(byte) => {
                    let msg_type = byte.map_err(messages::map_eof)?;
                    self.handle_server_message(msg_type, settings, events, commands)
                        .await?;
                    // A Disconnect that arrived mid-update aborts here, and
                    // state-changing commands parked during the update run
                    // now, before the channel is polled again, so ordering
                    // relative to later commands is preserved.
                    if let Some(outcome) = self.pending_outcome.take() {
                        return Ok(outcome);
                    }
                    for cmd in std::mem::take(&mut self.deferred_cmds) {
                        if let Some(outcome) = self.handle_command(cmd, settings, events).await? {
                            return Ok(outcome);
                        }
                    }
                }
                Step::Command(None) => {
                    // The handle was dropped: nobody can control this session
                    // any more. Treat as cancellation.
                    let _ = self.release_all_keys(settings).await;
                    return Err(VncError::Cancelled);
                }
                Step::Command(Some(cmd)) => {
                    if let Some(outcome) = self.handle_command(cmd, settings, events).await? {
                        return Ok(outcome);
                    }
                }
                Step::Tick => self.tick(settings, events).await?,
            }
        }
    }

    // -----------------------------------------------------------------------
    // Server → client
    // -----------------------------------------------------------------------

    async fn handle_server_message(
        &mut self,
        msg_type: u8,
        settings: &mut SessionSettings,
        events: &mpsc::Sender<SessionEvent>,
        commands: &mut mpsc::Receiver<ClientCommand>,
    ) -> Result<()> {
        tracing::trace!(msg_type, "server message");
        match msg_type {
            server_msg::FRAMEBUFFER_UPDATE => {
                self.handle_framebuffer_update(settings, events, commands)
                    .await
            }
            server_msg::SET_COLOUR_MAP_ENTRIES => {
                let (first, entries) =
                    messages::read_set_colour_map_entries(&mut self.reader).await?;
                // Required for every non-true-colour format we can request: the
                // Low preset asks for palette8, and without the map the
                // decoders take the grayscale identity fallback and paint
                // palette INDICES as grey levels.
                tracing::debug!(first, count = entries.len(), "SetColourMapEntries");
                self.decoder.set_colour_map(first, &entries);
                Ok(())
            }
            server_msg::BELL => Ok(emit(events, SessionEvent::Bell).await?),
            server_msg::SERVER_CUT_TEXT => self.handle_server_cut_text(events).await,
            server_msg::END_OF_CONTINUOUS_UPDATES => {
                self.caps.supports_continuous_updates = true;
                if !self.cu_active {
                    // The server just advertised support: switch it on.
                    let msg = messages::enable_continuous_updates(true, self.full_rect());
                    self.send(&msg).await?;
                    self.cu_active = true;
                    tracing::debug!("continuous updates enabled");
                } else {
                    // Server ended continuous updates: fall back to the
                    // one-outstanding-request pipeline.
                    self.cu_active = false;
                    let msg = messages::framebuffer_update_request(true, self.full_rect());
                    self.send(&msg).await?;
                }
                Ok(())
            }
            server_msg::SERVER_FENCE => self.handle_server_fence().await,
            other => Err(VncError::Protocol(format!(
                "unknown server message type {other}"
            ))),
        }
    }

    /// Wrapper around [`Self::read_framebuffer_update`] that owns the
    /// bookkeeping every update must contribute to no matter how it ends.
    ///
    /// The run loop is single-threaded and parks in `select!` when nothing is
    /// arriving, so the time spent inside this call IS the time the client
    /// spent receiving and decoding framebuffer data. That is what
    /// `SessionStats::server_duty_cycle` reports: a server streaming flat out
    /// keeps us in here permanently (duty -> 1.0), an idle desktop never
    /// enters at all (duty -> 0.0). Charged on the error path too, since the
    /// work happened either way.
    async fn handle_framebuffer_update(
        &mut self,
        settings: &mut SessionSettings,
        events: &mpsc::Sender<SessionEvent>,
        commands: &mut mpsc::Receiver<ClientCommand>,
    ) -> Result<()> {
        let started = Instant::now();
        let res = self
            .read_framebuffer_update(settings, events, commands)
            .await;
        let done = Instant::now();
        self.update_busy_tick += done.saturating_duration_since(started);
        self.last_update_done_at = Some(done);

        // An always-refresh request asks for the WHOLE framebuffer,
        // non-incrementally, so its answer covers the whole framebuffer.
        // Only such an update closes the clock.
        //
        // Closing it on the first update of any kind (which is what this did)
        // measured the wrong thing entirely: on the non-continuous-updates
        // pipelined path an incremental request is ALWAYS already
        // outstanding, so on a busy desktop the server answers that one first
        // (10 ms, a few dirty tiles) and that update recorded a 10 ms refresh
        // cost. A 10 ms cooldown has long expired by the next 1 s tick, so
        // the throttle reverted to exactly the once-per-second full-screen
        // cadence it exists to prevent, on precisely the busy server it was
        // written for.
        //
        // Two residual cases, both bounded. An incremental update whose
        // damage bounding box happens to span the desktop can still be
        // mistaken for the answer, which costs one cycle of throttling, not
        // the feature. A server that splits its answer into several smaller
        // updates never closes the clock at all, and `REFRESH_ABANDON`
        // releases the slot after 10 s.
        //
        // The error path deliberately does not close it either: a torn
        // update is not an answer, and charging its (short) elapsed time as
        // the refresh cost would understate the cooldown.
        if let (Ok(damage), Some(sent)) = (&res, self.refresh_request_at) {
            if answers_full_refresh(*damage, self.full_rect()) {
                self.refresh_request_at = None;
                self.refresh_cost = done.saturating_duration_since(sent);
                self.refresh_answered_at = Some(done);
            }
        }
        res.map(|_| ())
    }

    /// Reads one FramebufferUpdate to completion, returning the union of the
    /// damage it carried. The caller needs that union to decide whether this
    /// update is the answer to an outstanding full-screen refresh request.
    async fn read_framebuffer_update(
        &mut self,
        settings: &mut SessionSettings,
        events: &mpsc::Sender<SessionEvent>,
        commands: &mut mpsc::Receiver<ClientCommand>,
    ) -> Result<Rect> {
        let count = messages::read_framebuffer_update_header(&mut self.reader).await?;
        let header_at = Instant::now();
        // Timed from the header, before any rect is read, so the figure is the
        // round trip and not the time spent decoding what came back. Whether
        // this update is really the probe's answer is decided once its size
        // is known, after the rect loop below.
        let probe_sent = self.probe_request_at.take();
        self.record_passive_rtt(header_at);
        let primed_before = !self.priming_update_pending;

        // Pipelining fallback (PRD/02 §7.2): without continuous updates keep
        // exactly one incremental request outstanding, send the next one the
        // moment an update STARTS arriving, not after render.
        if self.priming_update_pending {
            // This update answers the priming full request. Asking for more
            // before it has even been read just makes the server resend the
            // whole screen; wait until it is consumed.
            self.priming_update_pending = false;
            tracing::trace!(
                rects = count,
                "priming update header (no pipelined request)"
            );
        } else if !self.cu_active {
            let msg = messages::framebuffer_update_request(true, self.full_rect());
            self.send(&msg).await?;
            // The passive round-trip clock starts here, on the normal update
            // path, and stops at the next update header. No probe traffic,
            // so it works on every server including the Fence-less ones.
            // Our decode of THIS update happens inside that window, which is
            // why arming the clock also zeroes the decode accumulator.
            self.arm_pipelined_request(Instant::now());
            tracing::trace!(rects = count, "update header; requested next incremental");
        } else {
            tracing::trace!(rects = count, "update header (continuous updates active)");
        }

        let sentinel = count == 0xffff;
        let mut remaining = count as u32;
        let mut rects: Vec<DecodedRect> = Vec::new();
        let mut damage = Rect::new(0, 0, 0, 0);

        // Per-rect bounds checks alone do NOT bound an update: a hostile server
        // may send 65535 rects that each individually fit the framebuffer (or
        // use the 0xffff sentinel and never send LastRect), accumulating
        // hundreds of gigabytes of decoded RGBA before we ever emit. Cap the
        // total decoded bytes for one update. Four framebuffers' worth is far
        // more than any legitimate update, overlapping repaints of a whole
        // 4K screen are ~33 MB each, with a floor so small desktops still get
        // reasonable headroom.
        let budget = (self.fb_width as u64 * self.fb_height as u64 * 4)
            .saturating_mul(4)
            .max(64 * 1024 * 1024);
        let mut accumulated: u64 = 0;
        // The byte budget alone does not bound a sentinel update: zero-area
        // rects decode to zero bytes, so a hostile server sending 0x0 rect
        // headers forever grows `rects` without ever touching the budget.
        // No legitimate update can carry more rects than a non-sentinel
        // count field could express.
        let mut headers_read: u32 = 0;

        loop {
            if !sentinel {
                if remaining == 0 {
                    break;
                }
                remaining -= 1;
            }
            headers_read += 1;
            if headers_read > u16::MAX as u32 {
                return Err(VncError::Protocol(
                    "framebuffer update exceeded 65535 rects without LastRect".into(),
                ));
            }
            let (rect, enc) = messages::read_rect_header(&mut self.reader).await?;

            if enc == encoding::PSEUDO_LAST_RECT {
                break;
            }
            if pseudo::is_pseudo(enc) {
                let parsed = pseudo::read_pseudo_rect(
                    &mut self.reader,
                    rect,
                    enc,
                    &self.pf,
                    &mut self.decoder,
                )
                .await?;
                if self.handle_pseudo(parsed, settings, events).await? {
                    break; // LastRect
                }
                continue;
            }

            // Data rect: strict bounds check against the current framebuffer.
            let fits = rect.x as u32 + rect.width as u32 <= self.fb_width as u32
                && rect.y as u32 + rect.height as u32 <= self.fb_height as u32;
            if !fits {
                return Err(VncError::Protocol(format!(
                    "rect {}x{}+{}+{} exceeds framebuffer {}x{}",
                    rect.width, rect.height, rect.x, rect.y, self.fb_width, self.fb_height
                )));
            }

            let started = Instant::now();
            let decoded =
                crate::encodings::decode_rect(&mut self.decoder, &mut self.reader, rect, enc)
                    .await?;
            let decode_ms = started.elapsed().as_secs_f32() * 1000.0;
            self.decode_ms_tick += decode_ms;
            // Same measurement, different accounting period: this one is
            // charged against the outstanding pipelined request so it can be
            // taken back out of the passive round-trip sample.
            self.decode_ms_since_request += decode_ms;
            self.current_encoding = enc;
            if let Some(d) = decoded {
                accumulated = accumulated.saturating_add(decoded_payload_len(&d) as u64);
                if accumulated > budget {
                    return Err(VncError::Protocol(format!(
                        "framebuffer update exceeded {budget} decoded bytes after {} rects; \
                         refusing to buffer more",
                        rects.len() + 1
                    )));
                }
                damage = damage.union(&d.rect);
                rects.push(d);
                self.rects_decoded += 1;
            }

            // Keep the remote pointer alive while a large update streams in.
            self.drain_commands_mid_update(commands, settings).await?;
            if self.pending_outcome.is_some() {
                // Disconnect requested: the stream position no longer matters.
                return Ok(damage);
            }
        }

        // The priming update has now been fully read: resume normal
        // pipelining. This site arms the clock at the END of an update where
        // the normal path arms it at the start, so the two would mean
        // different things (one window contains our decode of the
        // intervening update, the other does not) if they did not both zero
        // the decode accumulator. `arm_pipelined_request` is what keeps them
        // saying the same thing.
        if !self.cu_active && !primed_before {
            let msg = messages::framebuffer_update_request(true, self.full_rect());
            self.send(&msg).await?;
            self.arm_pipelined_request(Instant::now());
        }

        // Remember what was painted lossily so it can be re-fetched sharp once
        // the screen settles. Both JPEG and H.264 rects lose information;
        // Tight palette/RLE and CopyRect are already exact.
        //
        // An update that is itself the ANSWER to an outstanding lossless
        // refresh must not feed this: restoring the adaptive encodings now
        // happens after that answer (see below and `maybe_lossless_refresh`),
        // so if the server ignored the sharp SetEncodings (or the two simply
        // raced), the "sharp" answer can still be lossy. Unioning it back in
        // would immediately re-queue the same region and repeat forever.
        // Losing one region for one cycle is the accepted cost; ALR_COOLDOWN
        // already caps how often even a well-behaved server's answer can
        // trigger this path again.
        if !rects.is_empty()
            && !self.alr_restore_pending
            && (self.applied_quality.allow_jpeg || self.applied_quality.allow_h264)
        {
            let lossy = self.applied_quality.jpeg_quality < ALR_QUALITY_FLOOR
                && rects.iter().any(|r| {
                    matches!(
                        r.payload,
                        crate::types::RectPayload::Jpeg(_) | crate::types::RectPayload::H264 { .. }
                    )
                });
            if lossy {
                self.lossy_damage = self.lossy_damage.union(&damage);
            }
        }

        // A no-Fence probe asks for one pixel, so its answer is one pixel. An
        // update carrying real damage is somebody else's and merely happened
        // to arrive first; timing against it reads far too low, which is
        // exactly the "always too low, never too high" that was reported.
        // Such an update spoils the probe rather than completing it, and the
        // next quiet moment tries again.
        if let Some(sent) = probe_sent {
            if damage.area() <= PROBE_ANSWER_MAX_AREA {
                let sample = sent.elapsed().as_secs_f32() * 1000.0;
                self.rtt_ms = if self.rtt_ms > 0.0 {
                    RTT_SMOOTHING * sample + (1.0 - RTT_SMOOTHING) * self.rtt_ms
                } else {
                    sample
                };
                self.probe_sample_at = Some(Instant::now());
            } else {
                tracing::trace!(area = damage.area(), "rtt probe spoiled by real damage");
            }
        }

        if !rects.is_empty() {
            // Only a real repaint counts toward the idle timer: a
            // pseudo-only update (cursor shape, LED state, ...) must not
            // hold auto-lossless-refresh off forever on an otherwise static
            // screen.
            self.last_update_at = Some(Instant::now());
            self.frames_since_tick += 1;
            // Coverage telemetry for the consistency-refresh investigation: a
            // full repaint request that is honoured produces an update whose
            // damage approaches the whole screen; one that is ignored shows
            // only slivers. Distinguishing those from the log is the whole
            // point, so this is INFO for large updates only.
            emit(events, SessionEvent::FramebufferUpdate { rects, damage }).await?;
        }

        // The update following an outstanding lossless-refresh request has
        // now been fully consumed: restore the adaptive SetEncodings. See
        // `alr_restore_pending`'s doc for why this must happen AFTER the
        // answer rather than back-to-back with the request.
        if self.alr_restore_pending {
            self.alr_restore_pending = false;
            let msg = messages::set_encodings(&crate::quality::encodings_for(
                &self.applied_quality,
                &self.caps,
            ));
            self.send(&msg).await?;
        }
        Ok(damage)
    }

    /// Returns true when the pseudo rect ends the update (LastRect).
    async fn handle_pseudo(
        &mut self,
        parsed: PseudoRect,
        settings: &mut SessionSettings,
        events: &mpsc::Sender<SessionEvent>,
    ) -> Result<bool> {
        match parsed {
            PseudoRect::LastRect => return Ok(true),
            PseudoRect::DesktopSize { width, height } => {
                // Only a real size CHANGE invalidates the framebuffer. Servers
                // routinely include -223 in the first update just to announce
                // the geometry we already got from ServerInit; treating that as
                // an invalidation cost a second full-screen repaint on every
                // connect, 8 MB on a 2560x1600 desktop, straight down a Wi-Fi
                // link, before the user sees anything.
                let changed = width != self.fb_width || height != self.fb_height;
                self.apply_resize(width, height, events).await?;
                if changed {
                    // Legacy -223 invalidates the framebuffer and the server
                    // will NOT push a refresh, request one. Never do this for
                    // ExtendedDesktopSize (-308): loop hazard (PRD/02 §9).
                    let msg = messages::framebuffer_update_request(false, self.full_rect());
                    self.send(&msg).await?;
                }
            }
            PseudoRect::ExtendedDesktopSize {
                reason,
                status,
                width,
                height,
                screens,
            } => {
                let first = !self.caps.supports_extended_desktop_size;
                self.caps.supports_extended_desktop_size = true;
                let layout_changed = self.screens != screens;
                self.screens = screens;
                if reason == 1 && status != 0 {
                    // Our own SetDesktopSize was refused; geometry unchanged.
                    let why = match status {
                        1 => "the server prohibits resizing",
                        2 => "the server is out of resources",
                        3 => "the requested layout was invalid",
                        4 => "the request was forwarded (pending)",
                        _ => "unknown error",
                    };
                    emit(events, SessionEvent::Error(format!("Resize failed: {why}"))).await?;
                } else {
                    let changed = (width, height) != (self.fb_width, self.fb_height);
                    self.apply_resize(width, height, events).await?;
                    // The pipelined incremental request for the next update
                    // was sent with the OLD full rect. After a grow, nothing
                    // covers the new strip: if the server has no damage
                    // inside the old rect, no update arrives, no new request
                    // is generated, and the strip stays blank forever. An
                    // INCREMENTAL request for the new geometry is loop-safe
                    // (the PRD/02 §9 hazard is only about non-incremental
                    // requests after our own SetDesktopSize); apply_resize
                    // already re-armed continuous updates when active.
                    if changed && !self.cu_active {
                        let msg = messages::framebuffer_update_request(true, self.full_rect());
                        self.send(&msg).await?;
                    }
                }
                // AFTER the resize: the UI applies a per-monitor view against
                // the framebuffer it already has, so the new geometry must
                // land first.
                if layout_changed {
                    emit(
                        events,
                        SessionEvent::ScreenLayout {
                            screens: self.screens.clone(),
                        },
                    )
                    .await?;
                }
                // Re-apply a stored resize request once per connection, now
                // that the server has proven support (PRD/05 §4).
                if first && !self.resize_reapplied {
                    self.resize_reapplied = true;
                    if let Some((w, h)) = settings.requested_size {
                        if (w, h) != (self.fb_width, self.fb_height) {
                            self.send_set_desktop_size(w, h).await?;
                        }
                    }
                }
            }
            PseudoRect::DesktopName(name) => {
                self.caps.desktop_name = name.clone();
                emit(events, SessionEvent::DesktopName(name)).await?;
            }
            PseudoRect::Cursor(shape) => {
                emit(events, SessionEvent::CursorUpdate(shape)).await?;
            }
            PseudoRect::LedState(state) => {
                tracing::debug!(leds = state, "QEMU LED state");
            }
            PseudoRect::FenceCapable => self.caps.supports_fence = true,
            PseudoRect::ContinuousUpdatesCapable => {
                self.caps.supports_continuous_updates = true;
            }
            PseudoRect::QemuExtKeyCapable => self.caps.supports_qemu_ext_key = true,
            PseudoRect::ExtendedMouseButtonsCapable => {
                self.caps.supports_extended_mouse_buttons = true;
            }
        }
        Ok(false)
    }

    async fn apply_resize(
        &mut self,
        width: u16,
        height: u16,
        events: &mpsc::Sender<SessionEvent>,
    ) -> Result<()> {
        if width == 0 || height == 0 {
            return Err(VncError::Protocol(
                "server resized framebuffer to zero".into(),
            ));
        }
        if (width, height) != (self.fb_width, self.fb_height) {
            self.fb_width = width;
            self.fb_height = height;
            self.caps.width = width;
            self.caps.height = height;
            // Lossy-damage bookkeeping from the old geometry can extend past
            // the new framebuffer after a shrink; a later lossless-refresh
            // request for that region is out of bounds, and servers vary
            // between clamping and erroring.
            self.lossy_damage = self.lossy_damage.intersect(&self.full_rect());
            emit(events, SessionEvent::DesktopResize { width, height }).await?;
            if self.cu_active {
                // Continuous updates were enabled with the OLD full rect. The
                // server only pushes damage inside that region, so after a
                // grow the new strip would never update. Re-arm with the new
                // geometry.
                let msg = messages::enable_continuous_updates(true, self.full_rect());
                self.send(&msg).await?;
            }
        }
        Ok(())
    }

    async fn handle_server_cut_text(&mut self, events: &mpsc::Sender<SessionEvent>) -> Result<()> {
        let payload = messages::read_server_cut_text(&mut self.reader).await?;
        let data = match &payload {
            CutTextPayload::Legacy(d) => d,
            CutTextPayload::Extended(d) => {
                // The server speaks Extended Clipboard.
                self.caps.supports_extended_clipboard = true;
                let flags = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
                // Caps first, and exclusively: an announcement sets a bit for
                // every action the peer supports, notify among them, so testing
                // the action bits in any other order reads a caps message as a
                // notify and answers an offer that was never made.
                if flags & ext_clipboard::ACTION_CAPS != 0 {
                    // Answer the server's announcement with ours. Neither peer
                    // may send notify/request/provide before it has both sent
                    // and received caps, so a server that never hears from us
                    // simply stops offering its clipboard.
                    //
                    // Only ever in reply: an unsolicited negative-length
                    // ClientCutText would reach servers that do not implement
                    // the extension and read as a huge unsigned length.
                    if !self.clipboard_caps_sent {
                        self.clipboard_caps_sent = true;
                        let body = crate::clipboard::encode_caps();
                        let mut msg = Vec::with_capacity(1 + body.len());
                        msg.push(messages::client_msg::CLIENT_CUT_TEXT);
                        msg.extend_from_slice(&body);
                        self.send(&msg).await?;
                    }
                } else if flags & ext_clipboard::ACTION_REQUEST != 0 {
                    // The server is asking for the text we announced. This is
                    // the only way data reaches a server that advertised it
                    // accepts nothing unsolicited, so leaving it unanswered
                    // (as this did) meant the clipboard never arrived there.
                    if flags & crate::clipboard::FORMAT_TEXT != 0 {
                        if let Some(text) = self.clipboard_offered.clone() {
                            let body = crate::clipboard::encode_provide_text(&text);
                            let mut msg = Vec::with_capacity(1 + body.len());
                            msg.push(messages::client_msg::CLIENT_CUT_TEXT);
                            msg.extend_from_slice(&body);
                            self.send(&msg).await?;
                        }
                    }
                } else if flags & ext_clipboard::ACTION_NOTIFY != 0 {
                    emit(
                        events,
                        SessionEvent::ClipboardNotify {
                            formats: flags & ext_clipboard::FORMAT_MASK,
                        },
                    )
                    .await?;
                    // A notify carries no data, it only advertises formats, and
                    // our caps ask the server never to push data unsolicited.
                    // Pull the text now, otherwise nothing the user copies on
                    // the remote ever reaches this side.
                    if flags & crate::clipboard::FORMAT_TEXT != 0 {
                        let msg =
                            messages::extended_clipboard_request(crate::clipboard::FORMAT_TEXT);
                        self.send(&msg).await?;
                    }
                }
                d
            }
        };
        // `messages::read_server_cut_text` has already consumed the padding and
        // the length word, but the clipboard layer parses the whole message
        // BODY (`3 pad + i32 length + payload`), re-frame before handing over,
        // otherwise every inbound clipboard message is silently dropped.
        let length: i32 = match &payload {
            CutTextPayload::Legacy(d) => d.len() as i32,
            CutTextPayload::Extended(d) => -(d.len() as i32),
        };
        let mut framed = Vec::with_capacity(7 + data.len());
        framed.extend_from_slice(&[0, 0, 0]);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(data);
        if let Some(text) = crate::clipboard::handle_server_cut_text(&mut self.clipboard, &framed) {
            emit(events, SessionEvent::ClipboardText(text)).await?;
        }
        Ok(())
    }

    async fn handle_server_fence(&mut self) -> Result<()> {
        let (flags, payload) = messages::read_server_fence(&mut self.reader).await?;
        self.caps.supports_fence = true;
        if flags & fence_flags::REQUEST != 0 {
            // Answer promptly: echo the payload, clear Request and any flags
            // we do not understand (PRD/02 §7.1).
            let reply = messages::client_fence(flags & fence_flags::KNOWN_RESPONSE_MASK, &payload);
            self.send(&reply).await?;
        } else if payload == PF_FENCE_PAYLOAD {
            // The server has processed everything up to the fence and the
            // SetPixelFormat tied to it (BLOCK_BEFORE | SYNC_NEXT): from this
            // byte on, rects are encoded in the new format. NOW the decoder
            // may switch. Oldest first: responses come back in send order.
            if let Some(new_pf) = self.pending_pf.pop_front() {
                self.pf = new_pf;
                self.caps.pixel_format = Some(new_pf);
                self.decoder.set_pixel_format(new_pf);
                tracing::debug!(?new_pf, "pixel format switch synchronised");
            } else {
                tracing::warn!("unmatched pixel-format fence response");
            }
        } else {
            // A response, presumably to our RTT probe.
            if let Some((id, sent)) = self.probe {
                let matches = payload.len() == 8
                    && u64::from_be_bytes(payload[..8].try_into().expect("len checked")) == id;
                if matches {
                    self.rtt_ms = sent.elapsed().as_secs_f32() * 1000.0;
                    self.probe = None;
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Round-trip readout
    // -----------------------------------------------------------------------

    /// Close a passive round-trip sample at the arrival of an update header.
    ///
    /// The clock was started when the pipelined incremental request went out
    /// (see `handle_framebuffer_update`), so the elapsed time is the server's
    /// response PLUS however long it waited for the desktop to change. The
    /// idle wait is the whole problem with this measurement, so a sample is
    /// only kept during a busy streak: the previous update finished less than
    /// `BUSY_STREAK_GAP` ago, meaning the server had damage queued when our
    /// request arrived and started encoding straight away.
    ///
    /// Our own decode of the intervening update is taken back out. The window
    /// from "request sent" to "next header" contains the server's response
    /// plus the transfer plus however long THIS client spent decoding what it
    /// already had, and that last term is not a rounding error: 42.7% duty at
    /// the High quality tier is roughly 43 ms per sample at ten updates per
    /// second, against the 100 ms threshold the tuner cap trips at. It is
    /// also tier-correlated (heavier at High, lighter at Medium), so leaving
    /// it in made a slow CLIENT on a healthy server engage a cap meant for
    /// slow SERVERS, which is the wrong direction entirely.
    ///
    /// What is left after the subtraction still includes transfer time, and
    /// that is correct: moving the bytes IS part of what the server costs us,
    /// and it is the number a user feels. Time spent servicing input between
    /// rects (`drain_commands_mid_update`) is also still in there, but that
    /// is bounded by a handful of small writes.
    fn record_passive_rtt(&mut self, header_at: Instant) {
        // Taken before the early return, so decode charged while no request
        // was outstanding (continuous updates active, or the priming update)
        // is discarded here rather than carried into a later sample.
        let our_decode_ms = std::mem::take(&mut self.decode_ms_since_request);
        let Some(sent) = self.pipelined_request_at.take() else {
            return;
        };
        let Some(sample) =
            passive_sample_ms(sent, header_at, self.last_update_done_at, our_decode_ms)
        else {
            return;
        };
        push_passive_sample(&mut self.passive_rtt, header_at, sample);
    }

    /// Record that a pipelined incremental request has just gone out.
    ///
    /// Both writers (the normal path, at the header of the update being
    /// answered, and the priming path, after that update has been consumed)
    /// come through here so `pipelined_request_at` means the same thing
    /// either way, and so the decode accumulator always covers exactly the
    /// window the next sample will measure.
    fn arm_pipelined_request(&mut self, at: Instant) {
        self.pipelined_request_at = Some(at);
        self.decode_ms_since_request = 0.0;
    }

    /// The round trip to report, and which instrument produced it.
    ///
    /// Order of preference: an exact Fence measurement, then the one-pixel
    /// idle probe while its sample is still fresh, then the passive readout.
    /// Freshness matters because the first two only produce samples under
    /// conditions that may not recur for minutes (Fence needs the extension,
    /// the probe needs a still screen), and a reading that old describes a
    /// link that no longer exists. `rtt_ms` used to sit at 0.0 for entire
    /// sessions against Fence-less servers, which is why the compression bug
    /// went unnoticed: the one instrument that would have shown it was blank.
    fn reported_rtt(&self) -> (f32, crate::types::RttSource) {
        use crate::types::RttSource;
        if self.caps.supports_fence && self.rtt_ms > 0.0 {
            return (self.rtt_ms, RttSource::Fence);
        }
        let probe_fresh = self
            .probe_sample_at
            .is_some_and(|t| t.elapsed() < RTT_SAMPLE_FRESH);
        if probe_fresh && self.rtt_ms > 0.0 {
            return (self.rtt_ms, RttSource::IdleProbe);
        }
        // Per sample, not per window: a window whose NEWEST sample is fresh
        // can still be mostly ancient, and its median then reports a link
        // that stopped existing minutes ago. Only the samples that are
        // themselves fresh get a vote.
        if let Some(median) = fresh_median_ms(&self.passive_rtt, Instant::now()) {
            return (median, RttSource::UpdatePipeline);
        }
        // Nothing fresh from either. A stale figure still beats 0.0, which
        // the UI renders as "no measurement at all".
        if self.rtt_ms > 0.0 {
            return (self.rtt_ms, RttSource::IdleProbe);
        }
        match median_ms(&self.passive_rtt) {
            Some(median) => (median, RttSource::UpdatePipeline),
            None => (0.0, RttSource::None),
        }
    }

    /// Send a full-screen non-incremental request and start the always-refresh
    /// clock, so the answer can be timed and the next one throttled.
    async fn send_full_refresh(&mut self) -> Result<()> {
        let msg = messages::framebuffer_update_request(false, self.full_rect());
        self.send(&msg).await?;
        self.refresh_request_at = Some(Instant::now());
        Ok(())
    }

    /// May always-refresh issue another full-screen non-incremental request?
    ///
    /// It used to fire unconditionally on every 1 s tick. On a 2880x1800
    /// TightVNC-family server one such request costs the server 130 to 180 ms
    /// of its SHARED encoder (a small-region request costs ~12 ms), and a
    /// second client on the same server went from 3 ms to 398 ms median
    /// typing latency, worst case 10.1 s, while this ran. The client was
    /// effectively mounting a denial of service on the server it was
    /// connected to.
    ///
    /// Two rules fix that without weakening the feature, which exists for
    /// servers that under-report damage and so must not be gated on any
    /// inference of ours about whether a repaint is needed:
    ///
    /// 1. Never more than one outstanding. Queuing the next full re-fetch
    ///    before the last was answered is what let the requests pile up
    ///    faster than the server could ever serve them.
    /// 2. After an answer, wait as long again as that answer took. A healthy
    ///    server answers in ~150 ms, so the cooldown expires long before the
    ///    next 1 s tick and the feature keeps its once-per-second cadence
    ///    exactly as before. A server in trouble takes seconds to answer and
    ///    is asked correspondingly less often: the throttle is set by the
    ///    server's own measured cost, not by a number we guessed.
    fn always_refresh_due(&mut self) -> bool {
        let decision = refresh_decision(
            self.refresh_request_at.map(|t| t.elapsed()),
            self.refresh_answered_at.map(|t| t.elapsed()),
            self.refresh_cost,
        );
        match decision {
            RefreshDecision::Send => true,
            RefreshDecision::Wait => false,
            RefreshDecision::Abandon => {
                // Unanswered for a very long time: either the answer was
                // folded into an update we did not attribute to it, or the
                // server ignored the request. Release the slot so the feature
                // survives, but charge the full wait as the cost, so the next
                // attempt backs off instead of retrying hard.
                self.refresh_request_at = None;
                self.refresh_cost = REFRESH_ABANDON;
                self.refresh_answered_at = Some(Instant::now());
                tracing::debug!("always-refresh request went unanswered; backing off");
                false
            }
        }
    }

    // -----------------------------------------------------------------------
    // Client commands
    // -----------------------------------------------------------------------

    /// The commands that may safely run BETWEEN rects of an update: they only
    /// write input messages to the socket and touch no decoder, encoding, or
    /// framebuffer state.
    async fn handle_input_command(
        &mut self,
        cmd: ClientCommand,
        settings: &SessionSettings,
    ) -> Result<()> {
        match cmd {
            ClientCommand::Pointer { x, y, button_mask } => {
                if !settings.view_only {
                    let msg = crate::input::encode_pointer_event(x, y, button_mask);
                    self.send(&msg).await?;
                }
            }
            ClientCommand::Key {
                keysym,
                keycode,
                down,
            } => {
                if !settings.view_only {
                    self.send_key(keysym, keycode, down, settings.prefer_scancodes)
                        .await?;
                    if down {
                        self.pressed.insert(keysym, keycode);
                    } else {
                        self.pressed.remove(&keysym);
                    }
                }
            }
            ClientCommand::ReleaseAllKeys => self.release_all_keys(settings).await?,
            other => {
                debug_assert!(false, "not an input command: {other:?}");
            }
        }
        Ok(())
    }

    /// Service commands that queued while a FramebufferUpdate is being read.
    ///
    /// Reading an update runs to completion before the select loop looks at
    /// the command channel again, and on a slow link one large update takes
    /// seconds. Without this, every pointer and key event queues for that
    /// whole window, so the remote cursor freezes and then jumps, which is
    /// the single most visible latency difference from a native client.
    ///
    /// Input goes straight to the socket (a client message is always legal
    /// between our reads). Anything that changes protocol or session state is
    /// parked for the run loop to service once the update is consumed, and
    /// Disconnect aborts the update: the socket is about to close, stream
    /// position no longer matters.
    async fn drain_commands_mid_update(
        &mut self,
        commands: &mut mpsc::Receiver<ClientCommand>,
        settings: &SessionSettings,
    ) -> Result<()> {
        while let Ok(cmd) = commands.try_recv() {
            match cmd {
                ClientCommand::Pointer { .. }
                | ClientCommand::Key { .. }
                | ClientCommand::ReleaseAllKeys => {
                    self.handle_input_command(cmd, settings).await?;
                }
                ClientCommand::Disconnect => {
                    let _ = self.release_all_keys(settings).await;
                    self.pending_outcome = Some(RunOutcome::UserDisconnect);
                    return Ok(());
                }
                other => self.deferred_cmds.push(other),
            }
        }
        Ok(())
    }

    async fn handle_command(
        &mut self,
        cmd: ClientCommand,
        settings: &mut SessionSettings,
        events: &mpsc::Sender<SessionEvent>,
    ) -> Result<Option<RunOutcome>> {
        match cmd {
            ClientCommand::Disconnect => {
                let _ = self.release_all_keys(settings).await;
                return Ok(Some(RunOutcome::UserDisconnect));
            }
            // Handshake-time commands. If one arrives while connected the
            // prompt has already been answered (or the UI double-sent), so
            // there is nothing to do, never treat it as a protocol error.
            ClientCommand::ProvideCredentials { .. } | ClientCommand::CancelCredentials => {
                tracing::debug!("credential command received while connected; ignoring");
            }
            // A terminal command reaching a framebuffer session means the
            // shell routed one to the wrong protocol. Ignored rather than
            // treated as a protocol error: it is a routing bug, not a wire
            // problem, and killing the user's session over it would be the
            // worse outcome.
            ClientCommand::TerminalInput(_) | ClientCommand::ResizeTerminal { .. } => {
                tracing::debug!("terminal command received by a framebuffer session; ignoring");
            }
            cmd @ (ClientCommand::Pointer { .. }
            | ClientCommand::Key { .. }
            | ClientCommand::ReleaseAllKeys) => {
                self.handle_input_command(cmd, settings).await?;
            }
            ClientCommand::ClipboardText(text) => {
                // Extended peers are ANNOUNCED to first. The provide below is
                // enough for a server that accepts unsolicited data, but one
                // that advertised it does not will drop it and wait to be
                // told there is something to ask for; a notify costs four
                // bytes and is what makes those servers request the text
                // (answered in `handle_server_cut_text`).
                if self.clipboard.extended_supported() {
                    self.clipboard_offered = Some(text.clone());
                    let body = crate::clipboard::encode_notify(
                        &self.clipboard,
                        crate::clipboard::FORMAT_TEXT,
                    );
                    let mut msg = Vec::with_capacity(1 + body.len());
                    msg.push(messages::client_msg::CLIENT_CUT_TEXT);
                    msg.extend_from_slice(&body);
                    self.send(&msg).await?;
                }
                // The clipboard layer returns the message BODY; the
                // ClientCutText (6) type byte is ours to prepend.
                let body = crate::clipboard::encode_client_cut_text(&self.clipboard, &text);
                let mut msg = Vec::with_capacity(1 + body.len());
                msg.push(messages::client_msg::CLIENT_CUT_TEXT);
                msg.extend_from_slice(&body);
                self.send(&msg).await?;
            }
            ClientCommand::ClipboardRequest { formats } => {
                if self.caps.supports_extended_clipboard {
                    let msg = messages::extended_clipboard_request(formats);
                    self.send(&msg).await?;
                }
            }
            ClientCommand::SetQuality(preset) => {
                settings.quality = preset;
                let qs = preset.settings();
                // Keep the Auto tuner's bookkeeping in sync with whatever is
                // actually applied, manual or Auto: without this, a manual
                // preset detour desyncs `AutoTuner::Shared::current`, and
                // switching back to Auto does nothing until fresh
                // measurements happen to walk the ladder back to reality.
                self.tuner.resync(&qs);
                self.apply_quality(qs).await?;
            }
            ClientCommand::RequestResize { width, height } => {
                settings.requested_size = Some((width, height));
                if self.caps.supports_extended_desktop_size {
                    self.send_set_desktop_size(width, height).await?;
                } else {
                    tracing::debug!(
                        "ignoring resize request: server has not sent ExtendedDesktopSize"
                    );
                }
            }
            ClientCommand::Refresh => {
                // Goes through the same accounting as always-refresh, and now
                // through the same GATE. The comment here used to claim the
                // throttle applied while the call bypassed it entirely: a
                // user hammering the button queued a full-screen re-fetch per
                // press, and each press also overwrote `refresh_request_at`
                // with a fresh Instant, which suppressed the automatic
                // always-refresh for as long as the hammering lasted and
                // pushed the 10 s abandon out indefinitely.
                //
                // The gate is the one from `always_refresh_due`, so the first
                // press on a settled session goes out immediately (nothing
                // outstanding, no cooldown running) and feels as responsive
                // as it ever did. Only repeats, while the server still owes
                // us the last full screen, are dropped. Dropped rather than
                // queued: a full re-fetch already in flight is answering the
                // question the second press is asking.
                if self.always_refresh_due() {
                    self.send_full_refresh().await?;
                } else {
                    tracing::debug!(
                        "manual refresh suppressed: a full-screen request is still outstanding"
                    );
                }
            }
            ClientCommand::SetAlwaysRefresh(on) => {
                settings.always_refresh = on;
                tracing::info!(enabled = on, "always-refresh toggled");
                if on && self.always_refresh_due() {
                    // Apply immediately: the point of the switch is to fix a
                    // picture that is wrong RIGHT NOW. Gated for the same
                    // reason as the manual arm above, and with the same
                    // outcome in practice: a session with nothing
                    // outstanding sends it on the spot, and a session that
                    // already has a full screen in flight is about to get
                    // one anyway.
                    self.send_full_refresh().await?;
                }
            }
            ClientCommand::SetViewOnly(v) => {
                settings.view_only = v;
                if v {
                    self.release_all_keys(settings).await?;
                }
            }
            ClientCommand::SetPreferScancodes(v) => {
                // Anything currently held was pressed under the old mode;
                // release it first so its key-up goes out the same way its
                // key-down did, otherwise the remote can be left with a key
                // stuck in whichever encoding it no longer listens to.
                if settings.prefer_scancodes != v {
                    self.release_all_keys(settings).await?;
                    settings.prefer_scancodes = v;
                }
            }
            ClientCommand::TrustCertificate { .. } => {
                // Certificate trust is resolved during the security handshake;
                // nothing to do while connected.
            }
            ClientCommand::ReconnectNow => {
                // Already connected, nothing to do.
            }
        }
        let _ = events; // arms that need the event channel use helpers
        Ok(None)
    }

    async fn send_key(
        &mut self,
        keysym: u32,
        keycode: Option<u32>,
        down: bool,
        prefer_scancodes: bool,
    ) -> Result<()> {
        // A server honouring QEMU Extended Key Event applies its OWN keymap
        // to the scancode and ignores the keysym, so the scancode path types
        // what the REMOTE layout says that physical key is. That is right
        // for one keyboard-layout expectation and wrong for the other, which
        // is why it is a setting rather than a fixed preference.
        let use_qemu = self.caps.supports_qemu_ext_key && prefer_scancodes;
        match keycode {
            Some(kc) if use_qemu => {
                let msg = crate::input::encode_qemu_key_event(keysym, kc, down);
                self.send(&msg).await
            }
            _ => {
                let msg = crate::input::encode_key_event(keysym, down);
                self.send(&msg).await
            }
        }
    }

    /// Send key-up for everything we believe is pressed (blur / disconnect /
    /// view-only safety, PRD/05 §6.3).
    async fn release_all_keys(&mut self, settings: &SessionSettings) -> Result<()> {
        let pressed: Vec<(u32, Option<u32>)> = self.pressed.drain().collect();
        for (keysym, keycode) in pressed {
            self.send_key(keysym, keycode, false, settings.prefer_scancodes)
                .await?;
        }
        Ok(())
    }

    async fn send_set_desktop_size(&mut self, width: u16, height: u16) -> Result<()> {
        // Preserve screen IDs and flags we don't understand (PRD/05 §4). For
        // a single screen, resize it in place; otherwise collapse to the
        // first screen covering the new size (single-monitor request).
        let screen = match self.screens.first() {
            Some(s) => Screen {
                x: 0,
                y: 0,
                width,
                height,
                ..*s
            },
            None => Screen {
                id: 0,
                x: 0,
                y: 0,
                width,
                height,
                flags: 0,
                primary: false,
            },
        };
        let msg = messages::set_desktop_size(width, height, &[screen]);
        self.send(&msg).await
    }

    async fn apply_quality(&mut self, qs: QualitySettings) -> Result<()> {
        if qs == self.applied_quality {
            return Ok(());
        }
        self.applied_quality = qs;
        let encodings = crate::quality::encodings_for(&qs, &self.caps);
        let msg = messages::set_encodings(&encodings);
        self.send(&msg).await?;

        let new_pf = pixel_format_for(qs.pixel_format);
        // Compare against the format the connection is HEADING for, not the
        // one still decoding: with a switch already in flight, self.pf lags
        // until the fence response arrives.
        let effective = self.pending_pf.back().copied().unwrap_or(self.pf);
        if new_pf == effective {
            return Ok(());
        }

        // A mid-stream pixel-format switch is only safe if the server can tell
        // us where the change took effect. Fence + SyncNext does exactly that
        // (PRD/02 §4); without it there is NO way to know which side of the
        // switch an in-flight rectangle was encoded on.
        //
        // Getting this wrong is not subtle: decoding a 3-byte-TPIXEL rect as if
        // it were 1-byte palette makes the expected size 3x too small and the
        // inflate overruns its bound, surfacing to the user as
        // "decoder error in tight: decompressed data exceeds cap". It also
        // forces a full-screen redraw every time, which reads as the picture
        // repainting in waves.
        //
        // The TightVNC / libvncserver family does not implement Fence, so for
        // those servers we keep the negotiated format for the life of the
        // connection and express quality purely through the JPEG-quality and
        // compression-level pseudo-encodings (already sent above). Those need
        // no format change, no redraw, and are what actually drives perceived
        // quality on Tight anyway.
        if !self.caps.supports_fence {
            tracing::debug!(
                "server has no Fence support; keeping the pixel format and tuning \
                 quality via JPEG/compression only"
            );
            return Ok(());
        }

        // REQUEST makes the server answer the fence, and that answer is the
        // synchronisation point: BLOCK_BEFORE means every rect the server sent
        // before its response was encoded in the OLD format, SYNC_NEXT ties
        // the SetPixelFormat that follows to the fence, so everything after
        // the response is in the NEW one. Our decoder therefore switches in
        // `handle_server_fence`, when the response arrives, not here. The old
        // code flipped immediately and mis-decoded every in-flight rect, and
        // the window was widest exactly when the switch fires (a slow link is
        // both why the tuner downgrades and why rects queue up). This is
        // TigerVNC's pendingPFChange model.
        let guard = messages::client_fence(
            fence_flags::REQUEST | fence_flags::BLOCK_BEFORE | fence_flags::SYNC_NEXT,
            PF_FENCE_PAYLOAD,
        );
        self.send(&guard).await?;
        let msg = messages::set_pixel_format(&new_pf);
        self.send(&msg).await?;
        self.pending_pf.push_back(new_pf);
        // Everything on screen is stale once the switch lands; the redraw
        // request is ordered after the SetPixelFormat on the wire, so the
        // server answers it in the new format, after the fence response.
        let msg = messages::framebuffer_update_request(false, self.full_rect());
        self.send(&msg).await?;
        Ok(())
    }

    /// Re-fetch lossily-painted regions at full quality once the screen has
    /// stopped changing ("auto lossless refresh", PRD/09 §3.2).
    ///
    /// Lossy JPEG is the right trade *during* motion, it is what makes a drag
    /// feel instant, but it leaves visible blocking on text once things
    /// settle. So: keep the motion cheap, then quietly repaint the damaged
    /// region sharp when nothing is happening.
    ///
    /// Only the region actually painted lossily is re-requested, so this costs
    /// nothing on a static screen and never repaints the whole desktop (which
    /// is what made the picture appear to wash down the screen).
    async fn maybe_lossless_refresh(&mut self, settings: &SessionSettings) -> Result<()> {
        if !settings.lossless_refresh || self.lossy_damage.is_empty() {
            return Ok(());
        }
        // Never stack a second refresh on an unanswered one: the restore this
        // one is waiting for has not happened yet (see `alr_restore_pending`),
        // so the adaptive encodings are still off; queuing another sharp
        // request now would just extend how long the session stays
        // needlessly sharp.
        if self.alr_restore_pending {
            return Ok(());
        }
        let idle = self
            .last_update_at
            .map(|t| t.elapsed() >= ALR_IDLE)
            .unwrap_or(false);
        if !idle {
            return Ok(());
        }
        if self.last_alr_at.is_some_and(|t| t.elapsed() < ALR_COOLDOWN) {
            return Ok(());
        }

        let region = self.lossy_damage;
        self.lossy_damage = Rect::new(0, 0, 0, 0);
        self.last_alr_at = Some(Instant::now());

        // Ask for this region losslessly: disable BOTH lossy codecs, JPEG
        // and H.264 (see `handle_framebuffer_update`'s "painted lossily"
        // test, which now watches for either).
        let sharp = QualitySettings {
            allow_jpeg: false,
            allow_h264: false,
            ..self.applied_quality
        };
        let msg = messages::set_encodings(&crate::quality::encodings_for(&sharp, &self.caps));
        self.send(&msg).await?;
        let req = messages::framebuffer_update_request(false, region);
        self.send(&req).await?;

        // Do NOT restore the adaptive SetEncodings here. Sent back-to-back
        // with the request above, a server that processes SetEncodings
        // synchronously but queues the update applies the adaptive list
        // before it ever services the sharp request, so the "sharp" refresh
        // comes back lossy and `handle_framebuffer_update` would immediately
        // re-queue it, every ALR_COOLDOWN, forever, on an otherwise idle
        // screen. Restore after the ANSWER instead, at the end of
        // `handle_framebuffer_update`.
        self.alr_restore_pending = true;
        tracing::debug!(
            w = region.width,
            h = region.height,
            "auto lossless refresh requested"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Stats / liveness tick (1 s)
    // -----------------------------------------------------------------------

    async fn tick(
        &mut self,
        settings: &mut SessionSettings,
        events: &mpsc::Sender<SessionEvent>,
    ) -> Result<()> {
        // Dead-peer detection: an unanswered fence probe means the connection
        // is gone even if TCP has not noticed yet.
        if let Some((_, sent)) = self.probe {
            if sent.elapsed() > PROBE_TIMEOUT {
                return Err(VncError::Timeout);
            }
        }

        // The tick timer assumes exactly 1 s between fires, but
        // `MissedTickBehavior::Skip` (see `run`) makes the interval
        // unbounded whenever one update blocks the select loop past a tick:
        // dividing by the REAL elapsed time keeps throughput/fps correct
        // instead of understating them whenever that happens.
        let now = Instant::now();
        let dt_s = match self.last_tick_at {
            Some(prev) => now.saturating_duration_since(prev).as_secs_f64().max(1e-3),
            None => 1.0,
        };
        self.last_tick_at = Some(now);

        let total = self.bytes_counter.load(Ordering::Relaxed);
        let delta = total - self.last_bytes;
        self.last_bytes = total;
        let total_sent = self.sent_counter.load(Ordering::Relaxed);
        let delta_sent = total_sent - self.last_sent;
        self.last_sent = total_sent;

        // Fraction of the tick spent inside FramebufferUpdate handling. The
        // clamp guards the one case where the accounting can exceed the
        // window: `MissedTickBehavior::Skip` means a single update longer
        // than a tick pushes its whole cost into the next one.
        let duty = (self.update_busy_tick.as_secs_f64() / dt_s).clamp(0.0, 1.0) as f32;
        self.update_busy_tick = Duration::ZERO;
        let (rtt_ms, rtt_source) = self.reported_rtt();

        let stats = SessionStats {
            rtt_ms,
            rtt_source,
            server_duty_cycle: duty,
            throughput_bps: delta as f64 * 8.0 / dt_s,
            throughput_up_bps: delta_sent as f64 * 8.0 / dt_s,
            fps: (self.frames_since_tick as f64 / dt_s) as f32,
            decode_ms: if self.frames_since_tick > 0 {
                self.decode_ms_tick / self.frames_since_tick as f32
            } else {
                0.0
            },
            bytes_received: total,
            bytes_sent: total_sent,
            rects_decoded: self.rects_decoded,
            current_encoding: self.current_encoding,
            jpeg_quality: self.applied_quality.jpeg_quality,
        };
        emit(events, SessionEvent::Stats(stats)).await?;

        if self.trace.enabled {
            let (rects, compression) = (self.rects_decoded, self.applied_quality.compression);
            self.trace.summarise(dt_s, &stats, rects, compression);
        }

        // A peak of 0 means no burst completed this tick, NOT a slow link:
        // nothing loaded the socket enough to time it, so the estimate must
        // stand rather than be read as evidence of slowness.
        let link_bps = match self.link_peak.swap(0, Ordering::Relaxed) {
            0 => None,
            v => Some(v as f64),
        };
        // Two different latencies, passed separately on purpose.
        //
        // `self.rtt_ms` stays the tuner's network round trip: the passive
        // readout backing `stats.rtt_ms` on Fence-less servers is dominated by
        // the server's encode time during a busy streak, so feeding it in as
        // RTT would have Auto read every burst of activity as a degraded LINK.
        //
        // But that same encode-dominated number is exactly the right input to
        // the server-bound cap, which asks a different question: not "how fast
        // is the wire" but "is the server keeping up with what we are asking
        // for". Measured on a real server, the High tier sat at 426 to 434 ms
        // here while Medium sat at 18 to 20 ms, for only twice the bandwidth,
        // so the cap has a wide and unambiguous margin to act on. Passing 0.0
        // when nothing has been measured leaves the cap disengaged.
        // ONLY the update-pipeline source may drive the cap, and this
        // restriction is load-bearing rather than cautious.
        //
        // `reported_rtt` has three sources and they are not interchangeable.
        // Fence and the 1x1 idle probe both measure a NETWORK round trip: they
        // carry propagation delay and say nothing about whether the server is
        // keeping up. Feeding either to the cap would pin any link with more
        // than 100 ms of propagation to Medium for the whole session, on a
        // 100 Mbit/s transcontinental or satellite link that genuinely
        // warrants High, and the release threshold of 60 ms is not reachable
        // at the speed of light. That is exactly the "RTT is not capacity"
        // error `Tier::from_link` documents at length, smuggled back in
        // through a different door.
        //
        // The passive update-pipeline figure is the one the cap was designed
        // around, because it is dominated by how long the SERVER took to
        // produce the next update. That is the question the cap asks.
        let server_latency_ms = if stats.rtt_source == crate::types::RttSource::UpdatePipeline {
            stats.rtt_ms
        } else {
            0.0
        };
        self.tuner
            .observe(link_bps, self.rtt_ms, stats.decode_ms, server_latency_ms);
        if settings.quality == QualityPreset::Auto {
            if let Some(recommended) = self.tuner.recommended() {
                self.apply_quality(recommended).await?;
            }
        }

        // Periodic full re-fetch, when the user has asked for it.
        // Deliberately BEFORE the settle/lossless logic and subject to none
        // of it: this switch exists precisely for servers whose damage
        // reports cannot be trusted, so it must not be gated on any inference
        // of ours about whether a repaint is needed.
        //
        // It IS gated on the server keeping up, which is a different thing
        // entirely: see `always_refresh_due` for the measurements (398 ms
        // median typing latency inflicted on another client of the same
        // server, 10.1 s worst case) that made the unconditional version
        // untenable.
        if settings.always_refresh && self.always_refresh_due() {
            self.send_full_refresh().await?;
        }

        // Once the screen settles, repaint whatever was compressed lossily.
        self.maybe_lossless_refresh(settings).await?;

        // Fire the next RTT probe.
        if self.caps.supports_fence {
            if self.probe.is_none() {
                let id = self.epoch.elapsed().as_nanos() as u64;
                let msg = messages::client_fence(fence_flags::REQUEST, &id.to_be_bytes());
                self.send(&msg).await?;
                self.probe = Some((id, Instant::now()));
            }
        } else {
            // No Fence: time a one-pixel non-incremental request instead.
            if self
                .probe_request_at
                .is_some_and(|t| t.elapsed() > PROBE_STALE)
            {
                self.probe_request_at = None;
            }
            let quiet = self
                .last_update_at
                .is_none_or(|t| t.elapsed() >= PROBE_IDLE);
            if self.probe_request_at.is_none() && quiet {
                let msg = messages::framebuffer_update_request(false, Rect::new(0, 0, 1, 1));
                self.send(&msg).await?;
                self.probe_request_at = Some(Instant::now());
            }
        }

        self.frames_since_tick = 0;
        self.decode_ms_tick = 0.0;
        Ok(())
    }
}

/// One passive round-trip sample, with its own timestamp so the window can be
/// bounded by age as well as by count (see `PASSIVE_RTT_WINDOW`).
#[derive(Debug, Clone, Copy)]
struct PassiveSample {
    at: Instant,
    ms: f32,
}

/// One passive round-trip sample in milliseconds, or `None` when the busy
/// streak test rejects it (see [`RunLoop::record_passive_rtt`]).
///
/// `sent` is when the pipelined incremental request went out, `header_at`
/// when the next update header arrived, `last_done` when the previous update
/// finished being read. A sample only counts if the server was demonstrably
/// not idling between the two.
///
/// `our_decode_ms` is this client's own decode time inside that window, and
/// it comes straight back out again: what the caller wants is the server's
/// cost, not ours. Clamped at zero, since the two clocks are read at
/// different points and a pathologically short window could otherwise go
/// negative.
fn passive_sample_ms(
    sent: Instant,
    header_at: Instant,
    last_done: Option<Instant>,
    our_decode_ms: f32,
) -> Option<f32> {
    let done = last_done?;
    if header_at.saturating_duration_since(done) >= BUSY_STREAK_GAP {
        return None;
    }
    let elapsed_ms = header_at.saturating_duration_since(sent).as_secs_f32() * 1000.0;
    Some((elapsed_ms - our_decode_ms).max(0.0))
}

/// Add one sample to the passive window, dropping whatever the window may no
/// longer speak for: samples past `RTT_SAMPLE_FRESH` first, then the oldest
/// survivors if `PASSIVE_RTT_WINDOW` is still full.
///
/// The age pass is the one that matters. Eviction by count alone cannot
/// rotate stale samples out on a desktop that goes quiet, because the
/// busy-streak gate stops producing samples at exactly the same moment (see
/// `PASSIVE_RTT_WINDOW` for the nine-old-plus-eight-fresh case that reported
/// a ten-minute-old 400 ms figure as the current link).
fn push_passive_sample(window: &mut VecDeque<PassiveSample>, at: Instant, ms: f32) {
    while window
        .front()
        .is_some_and(|s| at.saturating_duration_since(s.at) >= RTT_SAMPLE_FRESH)
    {
        window.pop_front();
    }
    while window.len() >= PASSIVE_RTT_WINDOW {
        window.pop_front();
    }
    window.push_back(PassiveSample { at, ms });
}

/// Does this update's damage plausibly answer a full-screen non-incremental
/// refresh request? See the attribution comment in
/// [`RunLoop::handle_framebuffer_update`] for why anything less is not
/// treated as the answer.
///
/// Coverage rather than an exact match: servers round requests out to tile
/// boundaries and may trim a strip they know is unchanged, so the test is
/// "most of the framebuffer" rather than "every last pixel".
fn answers_full_refresh(damage: Rect, framebuffer: Rect) -> bool {
    let screen = framebuffer.area();
    if screen == 0 {
        return false;
    }
    damage.area() as f64 >= screen as f64 * REFRESH_ANSWER_COVERAGE
}

/// What to do about always-refresh on this tick.
#[derive(Debug, PartialEq, Eq)]
enum RefreshDecision {
    /// No request outstanding and the cooldown has expired.
    Send,
    /// A request is still in flight, or the cooldown has not expired.
    Wait,
    /// A request has been outstanding so long it must be written off.
    Abandon,
}

/// The always-refresh throttle, as a pure function of elapsed times so the
/// rules can be tested without a socket. See [`RunLoop::always_refresh_due`]
/// for the measurements behind them.
fn refresh_decision(
    outstanding_for: Option<Duration>,
    since_answer: Option<Duration>,
    last_cost: Duration,
) -> RefreshDecision {
    if let Some(waiting) = outstanding_for {
        return if waiting < REFRESH_ABANDON {
            RefreshDecision::Wait
        } else {
            RefreshDecision::Abandon
        };
    }
    match since_answer {
        Some(idle) if idle < last_cost.min(REFRESH_MAX_COOLDOWN) => RefreshDecision::Wait,
        _ => RefreshDecision::Send,
    }
}

/// Median of the whole passive round-trip window regardless of age, `None` if
/// it is empty. This is the last-resort readout: a stale figure still beats
/// 0.0, which the UI renders as "no measurement at all".
///
/// The median rather than the mean: the window mixes small incremental
/// updates with the occasional full repaint, and one 180 ms outlier among
/// fifteen 15 ms samples drags an average to 26 ms while the median stays at
/// 15 ms, which is what the link is actually doing. For an even count this
/// takes the upper of the two middle samples rather than interpolating; with
/// 16 noisy samples the difference is not worth the arithmetic.
fn median_ms(samples: &VecDeque<PassiveSample>) -> Option<f32> {
    median_of(samples.iter().map(|s| s.ms).collect())
}

/// Median of the samples that are still fresh at `now`, `None` when none are.
///
/// This is what the reported round trip uses. Filtering here as well as on
/// insertion is not belt and braces: insertion only happens when a sample
/// arrives, so a window that stops receiving them would otherwise keep
/// answering with whatever it last held.
fn fresh_median_ms(samples: &VecDeque<PassiveSample>, now: Instant) -> Option<f32> {
    median_of(
        samples
            .iter()
            .filter(|s| now.saturating_duration_since(s.at) < RTT_SAMPLE_FRESH)
            .map(|s| s.ms)
            .collect(),
    )
}

fn median_of(mut values: Vec<f32>) -> Option<f32> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some(values[values.len() / 2])
}

/// Decoded size of one rect, for the per-update accumulation budget.
///
/// `CopyRect` carries no pixels of its own but does cost a full rect once the
/// renderer applies it, so it is charged at its geometry, otherwise a server
/// could send unlimited CopyRects for free.
fn decoded_payload_len(d: &DecodedRect) -> usize {
    use crate::types::RectPayload;
    match &d.payload {
        RectPayload::Rgba(b) | RectPayload::Jpeg(b) => b.len(),
        RectPayload::H264 { data, .. } => data.len(),
        RectPayload::CopyRect { .. } => d.rect.area().saturating_mul(4),
    }
}

#[cfg(test)]
mod rtt_readout_tests {
    use super::*;

    /// A window whose samples all carry the same instant, for the tests that
    /// only care about the median arithmetic.
    fn window(samples: &[f32]) -> VecDeque<PassiveSample> {
        let at = Instant::now();
        samples.iter().map(|&ms| PassiveSample { at, ms }).collect()
    }

    #[test]
    fn median_ignores_a_single_full_screen_outlier() {
        // Fifteen small updates and one full repaint: the mean would be
        // dragged to ~26 ms, the median must stay with the small ones.
        let mut s = vec![15.0f32; 15];
        s.push(180.0);
        let median = median_ms(&window(&s)).expect("non-empty");
        assert_eq!(median, 15.0);
    }

    #[test]
    fn median_of_an_empty_window_is_none() {
        assert!(median_ms(&window(&[])).is_none());
    }

    #[test]
    fn median_sorts_rather_than_taking_the_middle_arrival() {
        // Arrival order must not matter: unsorted middle here is 5.0.
        let median = median_ms(&window(&[100.0, 5.0, 20.0])).expect("non-empty");
        assert_eq!(median, 20.0);
    }

    #[test]
    fn a_sample_during_a_busy_streak_is_kept() {
        let sent = Instant::now();
        let done = sent + Duration::from_millis(20);
        // 10 ms after the previous update finished: the server clearly had
        // damage queued, so this is a real measurement.
        let header = done + Duration::from_millis(10);
        let sample = passive_sample_ms(sent, header, Some(done), 0.0).expect("busy streak");
        assert!((sample - 30.0).abs() < 1.0, "got {sample}");
    }

    #[test]
    fn a_sample_after_an_idle_gap_is_rejected() {
        // This is the whole point of the streak test: an 8 s wait for the
        // user to move the mouse is not 8 s of latency.
        let sent = Instant::now();
        let done = sent + Duration::from_millis(20);
        let header = done + Duration::from_secs(8);
        assert!(passive_sample_ms(sent, header, Some(done), 0.0).is_none());
    }

    #[test]
    fn the_gap_boundary_rejects_rather_than_accepts() {
        let sent = Instant::now();
        let done = sent + Duration::from_millis(5);
        let header = done + BUSY_STREAK_GAP;
        assert!(passive_sample_ms(sent, header, Some(done), 0.0).is_none());
    }

    #[test]
    fn the_first_update_of_a_session_has_no_streak_to_join() {
        let sent = Instant::now();
        let header = sent + Duration::from_millis(10);
        assert!(passive_sample_ms(sent, header, None, 0.0).is_none());
    }

    #[test]
    fn our_own_decode_of_the_intervening_update_is_not_charged_to_the_server() {
        // The measured client cost: 42.7% duty at the High tier, so at ten
        // updates per second roughly 43 ms of a 100 ms window is us, not the
        // server. Leaving it in put a healthy server (57.3 ms) over the
        // 100 ms threshold the tuner cap trips at.
        let sent = Instant::now();
        let done = sent + Duration::from_millis(10);
        let header = sent + Duration::from_millis(100);
        let sample = passive_sample_ms(sent, header, Some(done), 42.7).expect("busy streak");
        assert!((sample - 57.3).abs() < 1.0, "got {sample}");
    }

    #[test]
    fn a_decode_longer_than_the_window_clamps_to_zero_rather_than_going_negative() {
        // The two clocks are read at different points, so the subtraction can
        // overshoot. A negative "round trip" would sort below every real
        // sample and drag the median with it.
        let sent = Instant::now();
        let done = sent + Duration::from_millis(1);
        let header = sent + Duration::from_millis(20);
        let sample = passive_sample_ms(sent, header, Some(done), 500.0).expect("busy streak");
        assert_eq!(sample, 0.0);
    }

    #[test]
    fn a_stale_sample_loses_its_vote_even_while_the_window_looks_fresh() {
        // The reported failure: a burst leaves nine 400 ms samples, the
        // desktop idles for ten minutes (the busy-streak gate rejects
        // everything, so nothing rotates out by count), then light activity
        // adds eight 20 ms samples. The newest sample is fresh, so the window
        // as a whole looks fresh, and the median is the ten-minute-old
        // number, which then feeds the tuner cap.
        let now = Instant::now();
        let mut w: VecDeque<PassiveSample> = VecDeque::new();
        let long_ago = now - Duration::from_secs(600);
        for _ in 0..9 {
            push_passive_sample(&mut w, long_ago, 400.0);
        }
        for i in 0..8 {
            push_passive_sample(&mut w, now - Duration::from_millis(8 - i), 20.0);
        }
        let median = fresh_median_ms(&w, now).expect("fresh samples exist");
        assert_eq!(median, 20.0, "window: {w:?}");
    }

    #[test]
    fn insertion_evicts_by_age_not_only_by_count() {
        // The count bound alone leaves the old samples sitting there: the
        // window is 16 and only 12 samples are involved here.
        let now = Instant::now();
        let mut w: VecDeque<PassiveSample> = VecDeque::new();
        for _ in 0..10 {
            push_passive_sample(&mut w, now - RTT_SAMPLE_FRESH, 400.0);
        }
        push_passive_sample(&mut w, now, 20.0);
        push_passive_sample(&mut w, now, 20.0);
        assert_eq!(w.len(), 2, "stale samples must be dropped on insertion");
    }

    #[test]
    fn a_window_that_stops_receiving_samples_stops_answering() {
        // Nothing arrives to trigger the insertion-time pruning, so the read
        // path has to do it: five seconds after the last update the passive
        // readout has nothing to say and a lower-priority source takes over.
        let now = Instant::now();
        let mut w: VecDeque<PassiveSample> = VecDeque::new();
        push_passive_sample(&mut w, now - Duration::from_secs(30), 42.0);
        assert!(fresh_median_ms(&w, now).is_none());
        // The stale figure is still available to the last-resort readout,
        // which prefers it to reporting 0.0.
        assert_eq!(median_ms(&w), Some(42.0));
    }

    #[test]
    fn the_window_is_still_bounded_by_count_when_every_sample_is_fresh() {
        let now = Instant::now();
        let mut w: VecDeque<PassiveSample> = VecDeque::new();
        for i in 0..(PASSIVE_RTT_WINDOW * 3) {
            push_passive_sample(&mut w, now, i as f32);
        }
        assert_eq!(w.len(), PASSIVE_RTT_WINDOW);
    }
}

#[cfg(test)]
mod always_refresh_tests {
    use super::*;

    #[test]
    fn the_first_refresh_goes_out_immediately() {
        assert_eq!(
            refresh_decision(None, None, Duration::ZERO),
            RefreshDecision::Send
        );
    }

    #[test]
    fn never_two_outstanding_at_once() {
        // The bug: a full-screen non-incremental request every second
        // regardless of whether the server had answered the last one.
        assert_eq!(
            refresh_decision(Some(Duration::from_secs(3)), None, Duration::ZERO),
            RefreshDecision::Wait
        );
    }

    #[test]
    fn a_healthy_server_keeps_the_one_second_cadence() {
        // 150 ms is the measured full-screen answer on the 2880x1800
        // TightVNC-family server, so by the next 1 s tick the cooldown is
        // long gone and the feature behaves exactly as it always did.
        let cost = Duration::from_millis(150);
        assert_eq!(
            refresh_decision(None, Some(Duration::from_secs(1)), cost),
            RefreshDecision::Send
        );
        assert_eq!(
            refresh_decision(None, Some(Duration::from_millis(100)), cost),
            RefreshDecision::Wait
        );
    }

    #[test]
    fn a_struggling_server_is_asked_less_often() {
        // A 4 s answer buys the server 4 s of quiet before we ask again,
        // instead of another full-screen request one second later.
        let cost = Duration::from_secs(4);
        assert_eq!(
            refresh_decision(None, Some(Duration::from_secs(1)), cost),
            RefreshDecision::Wait
        );
        assert_eq!(
            refresh_decision(None, Some(Duration::from_secs(4)), cost),
            RefreshDecision::Send
        );
    }

    #[test]
    fn the_cooldown_is_capped_so_the_feature_never_dies() {
        // Even the 10.1 s worst case measured must not silence the switch
        // for more than REFRESH_MAX_COOLDOWN.
        let cost = Duration::from_secs(30);
        assert_eq!(
            refresh_decision(None, Some(REFRESH_MAX_COOLDOWN), cost),
            RefreshDecision::Send
        );
    }

    #[test]
    fn an_unanswered_request_is_eventually_written_off() {
        assert_eq!(
            refresh_decision(Some(REFRESH_ABANDON), None, Duration::ZERO),
            RefreshDecision::Abandon
        );
    }

    /// The 2880x1800 desktop every measurement in this module was taken on.
    fn desktop() -> Rect {
        Rect::new(0, 0, 2880, 1800)
    }

    #[test]
    fn a_few_dirty_tiles_are_not_the_answer_to_a_full_screen_request() {
        // The bug: on the pipelined path an incremental request is always
        // already outstanding, so on a busy desktop the server answers THAT
        // one first, in about 10 ms, and that update used to close the
        // refresh clock. A 10 ms cooldown has expired by the next 1 s tick,
        // so the throttle silently reverted to the once-per-second
        // full-screen cadence it was written to prevent.
        assert!(!answers_full_refresh(
            Rect::new(100, 100, 64, 64),
            desktop()
        ));
        // Even a fairly large partial repaint (a maximised window's client
        // area, half the screen) is not a whole-framebuffer answer.
        assert!(!answers_full_refresh(Rect::new(0, 0, 2880, 900), desktop()));
    }

    #[test]
    fn a_whole_screen_update_is_the_answer() {
        assert!(answers_full_refresh(desktop(), desktop()));
        // Servers round to their own tile grid and may trim an edge strip,
        // so coverage rather than an exact match: 98% still counts.
        assert!(answers_full_refresh(Rect::new(0, 0, 2880, 1764), desktop()));
    }

    #[test]
    fn an_empty_update_is_never_the_answer() {
        // A pseudo-rect-only update (cursor shape, LED state) carries no
        // damage at all, and a zero-sized framebuffer must not make the
        // coverage test vacuously true.
        assert!(!answers_full_refresh(Rect::new(0, 0, 0, 0), desktop()));
        assert!(!answers_full_refresh(
            Rect::new(0, 0, 0, 0),
            Rect::new(0, 0, 0, 0)
        ));
    }
}

#[cfg(test)]
mod protocol_trace_tests {
    use super::*;

    fn trace() -> ProtocolTrace {
        ProtocolTrace {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn requests_are_split_incremental_from_full() {
        let mut t = trace();
        let full = messages::framebuffer_update_request(false, Rect::new(0, 0, 2880, 1800));
        let incr = messages::framebuffer_update_request(true, Rect::new(0, 0, 2880, 1800));
        t.record_client_message(&full, 2880, 1800);
        t.record_client_message(&incr, 2880, 1800);
        t.record_client_message(&incr, 2880, 1800);
        assert_eq!(t.full_requests, 1);
        assert_eq!(t.incr_requests, 2);
        assert_eq!(t.last_full, Some(Rect::new(0, 0, 2880, 1800)));
    }

    #[test]
    fn requested_area_is_counted_in_whole_screens() {
        let mut t = trace();
        // Half the desktop, twice: one screen's worth of encoding asked for.
        let half = messages::framebuffer_update_request(false, Rect::new(0, 0, 1440, 1800));
        t.record_client_message(&half, 2880, 1800);
        t.record_client_message(&half, 2880, 1800);
        assert!(
            (t.full_screens - 1.0).abs() < 1e-3,
            "got {}",
            t.full_screens
        );
    }

    #[test]
    fn a_zero_sized_framebuffer_does_not_divide_by_zero() {
        let mut t = trace();
        let req = messages::framebuffer_update_request(true, Rect::new(0, 0, 16, 16));
        t.record_client_message(&req, 0, 0);
        assert!(t.incr_screens.is_finite());
    }

    #[test]
    fn input_is_counted_but_not_confused_with_requests() {
        let mut t = trace();
        t.record_client_message(&crate::input::encode_pointer_event(1, 2, 0), 100, 100);
        t.record_client_message(&crate::input::encode_key_event(0x61, true), 100, 100);
        assert_eq!(t.pointer_events, 1);
        assert_eq!(t.key_events, 1);
        assert_eq!(t.incr_requests, 0);
        assert_eq!(t.full_requests, 0);
    }

    #[test]
    fn a_truncated_message_is_ignored_rather_than_panicking() {
        let mut t = trace();
        // Never happens from our own encoders, but the parser reads by index
        // and must not be the thing that takes the session down.
        t.record_client_message(
            &[messages::client_msg::FRAMEBUFFER_UPDATE_REQUEST, 1],
            10,
            10,
        );
        t.record_client_message(&[], 10, 10);
        assert_eq!(t.incr_requests, 0);
    }

    #[test]
    fn the_trace_is_off_unless_the_env_var_says_otherwise() {
        // Guards the zero-cost promise: nothing but an explicit "1" arms it.
        // (The process running the test suite does not set the variable.)
        assert!(!ProtocolTrace::new().enabled || std::env::var(TRACE_ENV).as_deref() == Ok("1"));
    }
}

#[cfg(test)]
mod update_budget_tests {
    use super::*;
    use crate::types::RectPayload;

    fn rect_of(w: u16, h: u16) -> DecodedRect {
        DecodedRect {
            rect: Rect::new(0, 0, w, h),
            payload: RectPayload::Rgba(vec![0u8; w as usize * h as usize * 4]),
        }
    }

    #[test]
    fn rgba_charged_at_payload_size() {
        assert_eq!(decoded_payload_len(&rect_of(64, 64)), 64 * 64 * 4);
    }

    #[test]
    fn copyrect_charged_at_geometry_not_zero() {
        // A CopyRect has an empty payload; charging it 0 would let a server
        // send unbounded rects past the budget.
        let d = DecodedRect {
            rect: Rect::new(0, 0, 128, 128),
            payload: RectPayload::CopyRect { src_x: 0, src_y: 0 },
        };
        assert_eq!(decoded_payload_len(&d), 128 * 128 * 4);
    }

    #[test]
    fn budget_floor_applies_to_small_framebuffers() {
        // 320x240 -> 4 framebuffers is only 1.2 MB, so the 64 MiB floor wins.
        let budget = (320u64 * 240 * 4).saturating_mul(4).max(64 * 1024 * 1024);
        assert_eq!(budget, 64 * 1024 * 1024);
    }

    #[test]
    fn budget_scales_past_the_floor_for_4k() {
        let budget = (3840u64 * 2160 * 4).saturating_mul(4).max(64 * 1024 * 1024);
        assert_eq!(budget, 3840 * 2160 * 4 * 4);
        assert!(budget > 64 * 1024 * 1024);
    }

    #[test]
    fn a_flood_of_full_screen_rects_exceeds_the_budget() {
        // The attack: 65535 rects that each individually pass the per-rect
        // bounds check. We must trip the budget within a handful of them,
        // never after thousands.
        //
        // At 1080p a framebuffer is 8.3 MB, so 4x it is only 33 MB and the
        // 64 MiB floor is what actually applies, ~8 full frames of headroom.
        let budget = (1920u64 * 1080 * 4).saturating_mul(4).max(64 * 1024 * 1024);
        assert_eq!(budget, 64 * 1024 * 1024, "the floor governs at 1080p");

        let per = decoded_payload_len(&rect_of(1920, 1080)) as u64;
        let mut acc = 0u64;
        let mut n = 0;
        while acc <= budget {
            acc = acc.saturating_add(per);
            n += 1;
            assert!(n < 32, "budget must trip quickly, not after thousands");
        }
        assert_eq!(n, 9, "64 MiB / 8.3 MB per frame trips on the 9th rect");
    }
}
