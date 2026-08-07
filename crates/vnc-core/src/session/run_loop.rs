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
use crate::quality::{AutoTuner, LinkMeter};
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
    /// Outstanding fence RTT probe: (payload id, send time).
    probe: Option<(u64, Instant)>,
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
            server_msg::BELL => emit(events, SessionEvent::Bell).await,
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

    async fn handle_framebuffer_update(
        &mut self,
        settings: &mut SessionSettings,
        events: &mpsc::Sender<SessionEvent>,
        commands: &mut mpsc::Receiver<ClientCommand>,
    ) -> Result<()> {
        let count = messages::read_framebuffer_update_header(&mut self.reader).await?;
        // An update answers any outstanding no-Fence probe. Measured at the
        // header, before the rects are read, so the figure is the round trip
        // rather than the time spent decoding what came back.
        if let Some(sent) = self.probe_request_at.take() {
            let sample = sent.elapsed().as_secs_f32() * 1000.0;
            self.rtt_ms = if self.rtt_ms > 0.0 {
                RTT_SMOOTHING * sample + (1.0 - RTT_SMOOTHING) * self.rtt_ms
            } else {
                sample
            };
        }
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
            self.decode_ms_tick += started.elapsed().as_secs_f32() * 1000.0;
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
                return Ok(());
            }
        }

        // The priming update has now been fully read: resume normal pipelining.
        if !self.cu_active && !primed_before {
            let msg = messages::framebuffer_update_request(true, self.full_rect());
            self.send(&msg).await?;
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
        Ok(())
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
                let msg = messages::framebuffer_update_request(false, self.full_rect());
                self.send(&msg).await?;
            }
            ClientCommand::SetAlwaysRefresh(on) => {
                settings.always_refresh = on;
                tracing::info!(enabled = on, "always-refresh toggled");
                if on {
                    // Apply immediately: the point of the switch is to fix a
                    // picture that is wrong RIGHT NOW.
                    let msg = messages::framebuffer_update_request(false, self.full_rect());
                    self.send(&msg).await?;
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

        let stats = SessionStats {
            rtt_ms: self.rtt_ms,
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

        // A peak of 0 means no burst completed this tick, NOT a slow link:
        // nothing loaded the socket enough to time it, so the estimate must
        // stand rather than be read as evidence of slowness.
        let link_bps = match self.link_peak.swap(0, Ordering::Relaxed) {
            0 => None,
            v => Some(v as f64),
        };
        self.tuner.observe(link_bps, self.rtt_ms, stats.decode_ms);
        if settings.quality == QualityPreset::Auto {
            if let Some(recommended) = self.tuner.recommended() {
                self.apply_quality(recommended).await?;
            }
        }

        // Unconditional re-fetch, when the user has asked for it. Deliberately
        // BEFORE the settle/lossless logic and subject to none of it: this
        // switch exists precisely for servers whose damage reports cannot be
        // trusted, so it must not be gated on any inference of ours about
        // whether a repaint is needed.
        if settings.always_refresh {
            let msg = messages::framebuffer_update_request(false, self.full_rect());
            self.send(&msg).await?;
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
