//! One Apple Screen Sharing session.
//!
//! Cleartext through authentication and the prelude, then the record layer.
//! Video is H.264 over SRTP on UDP. Access units are handed to the shell as
//! `RectPayload::H264` for the webview's hardware decoder.

use std::time::{Duration, Instant};

use rand::Rng;
use remote_core::{
    emit, emit_state, ClientCommand, ConnectOptions, CredentialKind, CredentialRequest,
    DecodedRect, Rect, RectPayload, SessionEvent, SessionState,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::auth::{self, SrpSecret};
#[cfg(test)]
use crate::h264::Depacketizer;
use crate::record::{self, RecordLayer};
use crate::srtp::{SrtcpEncryptor, SrtpContext};

/// The first encrypted records the client sends.
///
/// The native client's first two records are the display configuration and
/// then the encodings (RFC section 6.4). The order matters: the display
/// configuration says which display the session is about, and the encodings
/// say what the client can do with it. A client that sends the encodings
/// first, or never sends a display configuration at all, lets the Mac
/// choose a session for itself, and the choice can be a new one with a
/// login screen rather than the console the person is already using.
fn first_records(geometry: Option<remote_core::options::AppleGeometry>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(geometry) = panel_geometry(geometry) {
        // Pixel and point dimensions are different coordinate spaces. On a
        // Retina panel, sending pixels where points belong doubles the
        // desktop and makes the decoded picture look zoomed.
        out.push(display_config(
            DisplayRequest {
                points: (geometry.point_width, geometry.point_height),
                pixels: (geometry.pixel_width, geometry.pixel_height),
            },
            (geometry.pixel_width, geometry.pixel_height),
        ));
    }
    out.push(set_encodings());
    out
}

/// A remembered desktop large enough to be the Mac's panel.
///
/// A viewer window is not a panel. Remembering that window and sending it
/// on the next connection shrinks the Mac desktop to the window, and every
/// later connection, whatever its protocol, then shows the same enlarged UI.
fn panel_geometry(
    geometry: Option<remote_core::options::AppleGeometry>,
) -> Option<remote_core::options::AppleGeometry> {
    let geometry = geometry?;
    if geometry.pixel_width < 1280
        || geometry.pixel_height < 800
        || geometry.point_width < 1280
        || geometry.point_height < 800
        || geometry.point_width > geometry.pixel_width
        || geometry.point_height > geometry.pixel_height
    {
        return None;
    }
    Some(geometry)
}

/// Whether a fresh picture should be asked for because the client is the
/// one that is behind.
///
/// A client that cannot keep up must not be answered with a flood of full
/// pictures. The flood costs the Mac work it cannot spare, and the flood
/// is what turns a slow client into a stalled one. One request a second,
/// and only while the chain is still broken, is enough: the Mac's next
/// independent picture repairs the chain.
fn should_ask_for_backlog_picture(chain_broken: bool, since_last: Duration) -> bool {
    chain_broken && since_last >= BACKLOG_REQUEST_INTERVAL
}

/// Whether a stream that has stopped producing pictures needs a fresh one.
///
/// Only while packets are still arriving. This stream is damage driven: an
/// idle desktop sends nothing at all, and treating that as a stall asked the
/// Mac for a full picture every two seconds for a screen that had not
/// changed.
fn should_ask_for_stalled_picture(
    packets_arriving: bool,
    picture_stalled: bool,
    since_last_request: Duration,
) -> bool {
    packets_arriving && picture_stalled && since_last_request >= SILENT_STREAM_TIMEOUT
}

/// How long a resize round may take before the session gives up on it and
/// says so.
const RESIZE_TIMEOUT: Duration = Duration::from_secs(8);

/// What the user is holding down on the remote machine.
#[derive(Default)]
struct Held {
    /// Keys that were pressed and not released.
    keys: std::collections::BTreeSet<u32>,
    /// The last pointer position and button mask sent.
    pointer: Option<(u16, u16, u16)>,
}

/// Let go of every key and button that is held.
///
/// The remote machine is told about a key going down when it happens and
/// about it coming up when it happens. If the viewer's attention goes
/// elsewhere in between, the key stays down on the remote machine, and the
/// only way to release it is to say so.
async fn release_all(session: &mut Live, held: &mut Held) -> Result<(), SessionError> {
    if let Some((x, y, _)) = held.pointer.take() {
        let body = crate::input::pointer(session.layer.wrap_key(), x, y, 0);
        session.send_body(&body).await?;
    }
    let keys: Vec<u32> = held.keys.iter().copied().collect();
    held.keys.clear();
    for keysym in keys {
        let mut body = [0u8; 8];
        body[0] = 4;
        body[1] = 0; // key up
        body[4..8].copy_from_slice(&keysym.to_be_bytes());
        session.send_body(&body).await?;
    }
    Ok(())
}

/// The rate limit and the command numbering for one feedback destination.
///
/// They travel together because they share a lifetime: a request is either
/// allowed and gets the next FIR number, or it is held back and nothing is
/// consumed.
struct FeedbackClock {
    last: Instant,
    fir: crate::rtcp::FirSequence,
}

impl Default for FeedbackClock {
    fn default() -> Self {
        Self {
            // A fresh session may ask at once.
            last: Instant::now() - KEYFRAME_REQUEST_INTERVAL,
            fir: crate::rtcp::FirSequence::new(rand::random()),
        }
    }
}

/// Ask the Mac for a fresh independent picture.
///
/// The request goes out on the control socket, which is where the Mac's
/// RTCP arrives. Three forms are sent together: the modern request, the
/// picture loss indication, and the legacy request the native viewer uses.
/// Apple's server answers whichever it honours first, and it often ignores
/// the newer ones.
///
/// Requests are rate limited. A burst of loss would otherwise turn into a
/// burst of requests, which the Mac answers with a burst of full pictures.
async fn request_keyframe(
    feedback: &mut Option<SrtcpEncryptor>,
    sender: u32,
    media: u32,
    ctrl: Option<&UdpSocket>,
    ctrl_dest: &str,
    clock: &mut FeedbackClock,
    requests: &std::sync::atomic::AtomicU64,
) -> bool {
    // Requests are rate limited. A burst of loss would otherwise turn into
    // a burst of requests, which the Mac answers with a burst of full
    // pictures.
    if clock.last.elapsed() < KEYFRAME_REQUEST_INTERVAL {
        return false;
    }
    clock.last = Instant::now();
    let Some(encryptor) = feedback.as_mut() else {
        return false;
    };
    let Some(socket) = ctrl else { return false };
    let packet = crate::rtcp::compound(
        sender,
        &[
            crate::rtcp::full_intra_request(sender, media, clock.fir.next()),
            crate::rtcp::picture_loss_indication(sender, media),
            crate::rtcp::legacy_intra_request(media),
        ]
        .concat(),
    );
    let Some(protected) = encryptor.protect(&packet) else {
        return false;
    };
    if socket.send_to(&protected, ctrl_dest).await.is_err() {
        tracing::warn!("the keyframe request could not be sent");
        false
    } else {
        tracing::info!(media, "asked the Mac for a fresh picture");
        requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }
}

/// Ask the Mac to send the packets that went missing again.
async fn request_retransmission(
    feedback: &mut Option<SrtcpEncryptor>,
    sender: u32,
    media: u32,
    missing: &[u16],
    ctrl: Option<&UdpSocket>,
    ctrl_dest: &str,
) {
    if missing.is_empty() {
        return;
    }
    let Some(encryptor) = feedback.as_mut() else {
        return;
    };
    let Some(socket) = ctrl else { return };
    let nack = crate::rtcp::generic_nack(sender, media, missing);
    if nack.is_empty() {
        return;
    }
    let packet = crate::rtcp::compound(sender, &nack);
    let Some(protected) = encryptor.protect(&packet) else {
        return;
    };
    if socket.send_to(&protected, ctrl_dest).await.is_err() {
        tracing::warn!("the retransmission request could not be sent");
    } else {
        tracing::info!(
            packets = missing.len(),
            "asked the Mac for the missing packets"
        );
    }
}

/// Who the media is expected to come from.
///
/// The Mac sends its video and its feedback from a known address. A
/// datagram from anywhere else is not part of the session, and reading one
/// as video would put rubbish into the decoder.
struct Peer {
    addresses: Vec<std::net::IpAddr>,
    port: u16,
}

impl Peer {
    async fn resolve(host: &str, port: u16) -> Self {
        let addresses = match tokio::net::lookup_host((host, port)).await {
            Ok(list) => list.map(|addr| addr.ip()).collect(),
            Err(error) => {
                tracing::warn!(%error, host, "the Mac's address could not be resolved; packets from any address will be read");
                Vec::new()
            }
        };
        Self { addresses, port }
    }

    fn matches(&self, from: &std::net::SocketAddr) -> bool {
        if self.addresses.is_empty() {
            return true; // nothing to check against
        }
        if !self.addresses.contains(&from.ip()) {
            return false;
        }
        // The port is checked and reported rather than enforced: the Mac has
        // been seen to answer from the matching port, but a NAT or a
        // firewall in between may change it, and dropping the media over
        // that would be worse than reading it.
        if from.port() != self.port {
            tracing::debug!(
                port = from.port(),
                expected = self.port,
                "the media came from another port"
            );
        }
        true
    }
}

/// The size of the desktop in points, for a picture of a given size.
///
/// A retina panel is twice the points of its pixels, so a window of a given
/// size in pixels is half that size in points on the Mac's screen. The
/// ratio comes from the Mac's own geometry, which is the only place it is
/// written down.
#[allow(dead_code)]
fn desktop_points(
    pixels: (u16, u16),
    baseline_pixels: (u16, u16),
    baseline_points: (u16, u16),
) -> (u16, u16) {
    if baseline_points.0 == 0 || baseline_points.1 == 0 {
        return pixels;
    }
    let scale_x = f64::from(baseline_pixels.0) / f64::from(baseline_points.0);
    let scale_y = f64::from(baseline_pixels.1) / f64::from(baseline_points.1);
    if scale_x <= 0.0 || scale_y <= 0.0 {
        return pixels;
    }
    (
        ((f64::from(pixels.0) / scale_x).round() as u32).max(1) as u16,
        ((f64::from(pixels.1) / scale_y).round() as u32).max(1) as u16,
    )
}

/// How many times the offer is asked again when the Mac answers with an
/// empty canvas. The Mac does that while its encoder is warming up, and
/// the answer that follows is the one that counts.
const MAX_OFFER_ATTEMPTS: u32 = 3;

/// How often a fresh picture may be asked for.
const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(500);

/// How often a fresh picture may be asked for when the client is the one
/// that is behind. A client that cannot keep up must not be answered with
/// a flood of full pictures: the flood is what turns a slow client into a
/// stalled one.
const BACKLOG_REQUEST_INTERVAL: Duration = Duration::from_secs(1);
/// When the toolbar's continuous recovery option is enabled, ask the Mac for
/// an independent picture at this interval rather than polling framebuffer
/// updates over the control connection.
const ALWAYS_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
/// A quiet video stream needs recovery even when no later packet arrives to
/// report a sequence gap.
const SILENT_STREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a promised picture may be missing before the media session is
/// offered again. A request over UDP asks a media session that may no longer
/// exist; a re-offer over the control connection rebuilds it.
const REVIVE_AFTER: Duration = Duration::from_secs(5);
/// The longest wait between asks for a picture the Mac has not sent. The
/// wait doubles, so a pointer moving over an unchanged screen costs a handful
/// of requests a minute rather than thirty.
const OWED_RETRY_MAX: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
enum VideoRequest {
    FreshPicture,
    AlwaysRefresh(bool),
}

/// A resize round.
///
/// A round is: ask the Mac for a size, get the layout that answers it, let
/// the encoder restart, and see a picture at the new size. It is not over
/// when the Mac answers, because the encoder restarts after the answer and a
/// second request sent into that restart races it.
///
/// The newest request always wins. A request that arrives while a round is
/// running is remembered and sent when the round ends, even when it asks
/// for the size the session had before the round started: that is a real
/// request, and dropping it is how a quality change used to disappear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DisplayGeometry {
    pixels: (u16, u16),
    points: (u16, u16),
}

#[derive(Default)]
struct ResizeRound {
    /// Keep both coordinate spaces with the latest intent and the sent
    /// request. Queuing just pixels silently loses the requested desktop.
    requested: Option<DisplayGeometry>,
    sent: Option<DisplayGeometry>,
    /// Raw geometry acknowledged by the server; not decoded output.
    confirmed: Option<DisplayGeometry>,
    /// A request is with the server.
    in_flight: bool,
    /// When the request was sent.
    sent_at: Option<Instant>,
    /// The round has to wait for the replacement picture before it ends.
    /// The layout alone is a statement about the canvas; the encoder
    /// restarts after it, and only a picture from the restarted encoder
    /// says the new stream is really running.
    needs_picture: bool,
    /// The request has been sent and the layout that answers it has not
    /// arrived yet. A picture from the old encoder says nothing about the
    /// new size, so the round waits for the layout first.
    awaiting_layout: bool,
    /// The geometry the session had before this round asked for anything.
    ///
    /// A Mac that cannot do what was asked answers with a smaller desktop,
    /// and accepting that shrinks the person's windows. When that happens
    /// the round puts this geometry back.
    before: Option<DisplayGeometry>,
    /// This round is putting back the geometry a failed round started from,
    /// rather than carrying something a person asked for.
    restoring: bool,
    /// Automatic restorations still allowed for the current intent. One is
    /// enough: a Mac that answered small twice does not need a third try.
    restores_left: u8,
}

/// What asking for a size means.
#[derive(Debug, PartialEq, Eq)]
enum ResizeAction {
    /// The picture is already that size. Nothing to ask for.
    Nothing,
    /// Send the request now.
    Send(DisplayGeometry),
    /// A round is running. The request goes out when that round ends.
    Wait,
}

/// Decide what an ask for a size means, and record it.
fn plan_resize(
    round: &mut ResizeRound,
    target: DisplayGeometry,
    current: DisplayGeometry,
) -> ResizeAction {
    round.requested = Some(target);
    if round.in_flight {
        // A round is running. The request goes out when it finishes, even
        // when it asks for the size the session had before the round
        // started: it is a real request, and dropping it is how a quality
        // change used to disappear.
        return ResizeAction::Wait;
    }
    if target == current {
        round.requested = None;
        return ResizeAction::Nothing;
    }
    start_round(round, target, current, false);
    ResizeAction::Send(target)
}

/// Put a request in flight.
///
/// `before` is what a failed round puts back, so it has to be the geometry
/// the session really has at the moment the request goes out, not the one
/// from before the previous round.
fn start_round(
    round: &mut ResizeRound,
    target: DisplayGeometry,
    before: DisplayGeometry,
    restoring: bool,
) {
    round.before = Some(before);
    round.sent = Some(target);
    round.confirmed = None;
    round.sent_at = Some(Instant::now());
    round.in_flight = true;
    round.needs_picture = true;
    round.awaiting_layout = true;
    round.restoring = restoring;
    round.restores_left = if restoring { 0 } else { 1 };
}

/// What the end of a round means.
#[derive(Debug, PartialEq, Eq)]
enum RoundEnd {
    /// The round is over. The pair is the size that was asked for and the
    /// size the server chose, when they differ.
    Done(Option<(DisplayGeometry, DisplayGeometry)>),
    /// Another request goes out, because a newer one arrived while this
    /// round was running.
    Send(DisplayGeometry),
}

/// Close a round that has been answered and has produced its picture.
fn finish_round(round: &mut ResizeRound) -> RoundEnd {
    round.in_flight = false;
    round.sent_at = None;
    let sent = round.sent;
    match round.requested {
        Some(target) if Some(target) != sent => {
            // A newer request arrived while this round was running. It wins.
            // The geometry this session really has is what a later failure
            // has to put back, so the next round snapshots the answer this
            // one received rather than its own older `before`.
            let before = round.confirmed.or(round.before).unwrap_or(target);
            start_round(round, target, before, false);
            RoundEnd::Send(target)
        }
        _ => {
            round.requested = None;
            let clamped = match (sent, round.confirmed) {
                (Some(sent), Some(confirmed)) if sent != confirmed => Some((sent, confirmed)),
                _ => None,
            };
            RoundEnd::Done(clamped)
        }
    }
}

/// Whether the Mac answered with a smaller desktop than was asked for.
///
/// The desktop is measured in points. A picture with fewer pixels at the
/// same point size is a lower stream quality, which is what a quality
/// preset asks for; treating it as a failure is what made a 1800x1170
/// request for an 1800x1169 desktop shrink and then bounce back.
fn desktop_shrank(clamped: Option<(DisplayGeometry, DisplayGeometry)>) -> bool {
    clamped.is_some_and(|(sent, confirmed)| {
        confirmed.points.0 < sent.points.0 || confirmed.points.1 < sent.points.1
    })
}

/// Whether an answer differs enough from the request to tell the person.
///
/// Rounding an odd height to an even one is not news: the Mac reports what
/// it laid out, and one pixel is the encoder's padding, not a different
/// picture.
fn answer_is_notable(sent: DisplayGeometry, confirmed: DisplayGeometry) -> bool {
    confirmed.points != sent.points
        || confirmed.pixels.0.abs_diff(sent.pixels.0) > 2
        || confirmed.pixels.1.abs_diff(sent.pixels.1) > 2
}

/// Ask for a size, or remember the ask until the running round is over.
async fn request_resize(
    session: &mut Live,
    round: &mut ResizeRound,
    target: (u16, u16),
    current: (u16, u16),
    baseline: (u16, u16),
    desktop: Option<(u16, u16)>,
) -> Result<(), SessionError> {
    let current = DisplayGeometry {
        pixels: current,
        points: (session.logical_width, session.logical_height),
    };
    let target = DisplayGeometry {
        pixels: target,
        points: desktop.unwrap_or(current.points),
    };
    match plan_resize(round, target, current) {
        ResizeAction::Nothing => Ok(()),
        ResizeAction::Wait => {
            tracing::debug!(?target, "Apple resize request queued");
            Ok(())
        }
        ResizeAction::Send(target) => {
            session
                .send_body(&display_config(request_for(target), baseline))
                .await?;
            tracing::info!(?target, "Apple display resize requested");
            Ok(())
        }
    }
}

/// Take the next queued picture, or sleep until the producer has one.
/// The lock is released before waiting, so the producer can queue and wake.
async fn next_picture(
    buffer: &tokio::sync::Mutex<crate::pictures::PictureBuffer>,
    wake: &mut mpsc::Receiver<()>,
) -> Option<crate::h264::AccessUnit> {
    let mut buffer_guard = buffer.lock().await;
    if let Some(unit) = buffer_guard.pop() {
        return Some(unit);
    }
    if buffer_guard.is_broken() && buffer_guard.len() > 0 {
        tracing::info!("the picture chain was broken; waiting for an independent picture");
    }
    drop(buffer_guard);
    wake.recv().await?;
    None
}

/// The counters the video receiver keeps and the control loop reads.
///
/// The receiver and the control loop are different tasks, and the numbers
/// are about the media: how many access units have been assembled, how many
/// packets went missing, and how many times the picture was asked for
/// again.
#[derive(Default)]
struct MediaCounters {
    pictures: std::sync::atomic::AtomicU64,
    /// Packets that went missing on the way. A network problem.
    lost: std::sync::atomic::AtomicU64,
    /// Pictures dropped because the client could not keep up. A local
    /// problem, and asking the Mac for more pictures does not fix it.
    dropped: std::sync::atomic::AtomicU64,
    /// Recovery attempts: a fresh picture was asked for.
    recoveries: std::sync::atomic::AtomicU64,
    /// Feedback packets sent to the Mac. A number that grows on its own is
    /// a number that is costing the Mac work.
    requests: std::sync::atomic::AtomicU64,
    /// Video datagrams read from the Mac.
    packets: std::sync::atomic::AtomicU64,
    /// Payload bytes of those datagrams, which is the stream's bandwidth.
    bytes: std::sync::atomic::AtomicU64,
    /// Times the stream went quiet for longer than the stall timeout.
    stalls: std::sync::atomic::AtomicU64,
    /// Variation in the spacing between pictures, in milliseconds. Steady
    /// spacing is a steady picture; a link that queues and bursts shows up
    /// here before it shows up anywhere else.
    jitter_ms: std::sync::atomic::AtomicU32,
    /// When the last picture came out, in milliseconds since the session
    /// began. The control loop reads it to decide whether the stream has
    /// stopped for good.
    last_picture_ms: std::sync::atomic::AtomicU64,
    /// Smoothed time from the user's input to the picture that answers it,
    /// in milliseconds. This is the number a person feels as lag, and it is
    /// the only one that separates an idle desktop from a server that is
    /// throttling: a still screen sends nothing, but a screen being used
    /// must answer.
    input_latency_ms: std::sync::atomic::AtomicU32,
    /// The slowest answer in the last few, so one freeze is visible.
    input_worst_ms: std::sync::atomic::AtomicU32,
}

/// Timing between pictures, as the receiver sees it.
#[derive(Default)]
struct PictureCadence {
    last: Option<Instant>,
    /// The previous interval, so a change can be measured against it.
    last_interval: Option<f32>,
    /// Mean absolute change of the interval, in milliseconds.
    jitter_ms: f32,
}

impl PictureCadence {
    /// Record one picture and return the jitter in whole milliseconds.
    ///
    /// Jitter is how much the spacing CHANGES, not how long it is: a steady
    /// stream at four pictures a second has a 250 ms spacing and no jitter,
    /// and reporting the spacing as jitter made an idle desktop look like a
    /// broken link.
    fn picture(&mut self, now: Instant) -> u32 {
        let Some(last) = self.last.replace(now) else {
            return 0;
        };
        let interval = now.duration_since(last).as_secs_f32() * 1000.0;
        let Some(previous) = self.last_interval.replace(interval) else {
            return 0;
        };
        let change = (interval - previous).abs();
        self.jitter_ms = if self.jitter_ms == 0.0 {
            change
        } else {
            self.jitter_ms * 0.9 + change * 0.1
        };
        self.jitter_ms.round().min(60_000.0) as u32
    }
}

/// Send assembled pictures to the shell. Returns false when the shell has
/// gone, which ends the session.
async fn publish(
    events: &mpsc::Sender<SessionEvent>,
    units: Vec<crate::h264::AccessUnit>,
    dimensions: &std::sync::atomic::AtomicU32,
    pictures: &mut u32,
) -> bool {
    for au in units {
        *pictures += 1;
        if *pictures <= 5 || (*pictures <= 60 && au.keyframe) {
            tracing::info!(
                pictures = *pictures,
                bytes = au.annex_b.len(),
                keyframe = au.keyframe,
                "Apple H.264 picture"
            );
        }
        let size = dimensions.load(std::sync::atomic::Ordering::Relaxed);
        let rect = DecodedRect {
            rect: Rect::new(0, 0, (size >> 16) as u16, size as u16),
            payload: RectPayload::H264 {
                data: au.annex_b,
                flags: 0,
                context_id: 0,
                // `reset` rebuilds the decoder and throws its reference
                // pictures away. Only an IDR may do that: an intra picture
                // that is not an IDR is fed to the existing decoder instead,
                // because wiping the references corrupts every picture that
                // follows it, and the corruption outlives the picture that
                // caused it.
                reset: au.reset,
                keyframe: au.keyframe,
            },
        };
        if emit(
            events,
            SessionEvent::FramebufferUpdate {
                damage: rect.rect,
                rects: vec![rect],
            },
        )
        .await
        .is_err()
        {
            return false;
        }
    }
    true
}

pub async fn run(
    options: ConnectOptions,
    events: mpsc::Sender<SessionEvent>,
    mut commands: mpsc::Receiver<ClientCommand>,
    cancel: tokio_util::sync::CancellationToken,
    host_keys: Option<crate::macos::Verifier>,
) {
    let mut credentials = (
        options.credentials.username.clone().unwrap_or_default(),
        options.credentials.password.clone().unwrap_or_default(),
    );
    let (mut username, mut password) = (credentials.0.clone(), credentials.1.clone());
    if username.is_empty() || password.is_empty() {
        let _ = emit(
            &events,
            SessionEvent::CredentialsRequired(CredentialRequest {
                method: "Apple Screen Sharing".into(),
                kind: CredentialKind::UsernameAndPassword,
                attempt: 1,
                error: None,
                truncates_password: false,
                username_hint: options.credentials.username.clone(),
            }),
        )
        .await;
        match wait_credentials(&mut commands, &cancel).await {
            Some((user, pass)) => {
                if !user.is_empty() {
                    username = user;
                }
                password = pass;
            }
            None => {
                let _ = fail(&events, "sign-in was cancelled").await;
                return;
            }
        }
    }
    let (width, height, ports, geometry) = match &options.protocol {
        remote_core::ProtocolOptions::Apple(o) => {
            (o.width, o.height, (o.video_port, o.control_port), o.desktop)
        }
        _ => (1920, 1080, (5901, 5900), None),
    };
    // The session is supervised. A connection that ends is not the end of
    // the session: the driver tries again, and the person watching sees a
    // reconnect rather than a dead pane. The wait between attempts grows,
    // and "Reconnect now" makes it immediate.
    let mut attempt = 0u32;
    // Set when the session is asked to reconnect. The connection ends and
    // the supervisor starts a new one at once, with no wait.
    let reconnect = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let started = Instant::now();
        let result = connect(
            &options.host,
            options.port,
            &username,
            &password,
            width,
            height,
            ports,
            geometry,
            &events,
            &mut commands,
            &cancel,
            host_keys.clone(),
            &reconnect,
        )
        .await;
        let uptime = started.elapsed();
        let reason = match result {
            Ok(()) => {
                if !reconnect.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    // The session ended on request. Nothing to retry.
                    return;
                }
                // The session was asked to reconnect. Start a new one at
                // once, with no wait and no failure to report.
                attempt = 0;
                username = credentials.0.clone();
                password = credentials.1.clone();
                continue;
            }
            Err(err) => err.to_string(),
        };
        if cancel.is_cancelled() {
            break;
        }
        let _ = fail(&events, &reason).await;
        // The wait grows with consecutive failures, and starts over only
        // after an attempt that stayed up long enough to be a session. The
        // old code reset the count after every wait, so ten transient
        // failures were ten waits of half a second each.
        let (next_attempt, wait) = next_retry(attempt, uptime);
        attempt = next_attempt;
        let _ = emit_state(
            &events,
            SessionState::Reconnecting {
                attempt,
                next_retry_ms: wait.as_millis() as u64,
                reason: reason.clone(),
            },
        )
        .await;
        if wait_for_retry(&mut commands, &cancel, wait, &mut credentials).await {
            // The session was asked to stop.
            return;
        }
        username = credentials.0.clone();
        password = credentials.1.clone();
    }
}

/// How long an attempt must stay up before the backoff starts over.
const STABLE_UPTIME: Duration = Duration::from_secs(60);

/// The first wait between attempts, doubled for each consecutive failure.
const RETRY_BASE_MS: u64 = 500;

/// How many doublings the wait takes before it stops growing.
const RETRY_MAX_SHIFT: u32 = 4;

/// The attempt number to report next, and how long to wait for it.
///
/// A failure that follows a session which stayed up is the first of a new
/// run, not the sixth of an old one. A failure that follows another failure
/// keeps growing the wait, so a Mac that refuses connections is not asked
/// twice a second for ever.
fn next_retry(attempt: u32, uptime: Duration) -> (u32, Duration) {
    let attempt = if uptime >= STABLE_UPTIME { 0 } else { attempt };
    let wait = Duration::from_millis(RETRY_BASE_MS << attempt.min(RETRY_MAX_SHIFT));
    (attempt.saturating_add(1), wait)
}

/// Wait before the next attempt. Returns true when the session should end.
async fn wait_for_retry(
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &tokio_util::sync::CancellationToken,
    wait: Duration,
    credentials: &mut (String, String),
) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::select! {
            _ = cancel.cancelled() => return true,
            cmd = commands.recv() => match cmd {
                None | Some(ClientCommand::Disconnect) => return true,
                Some(ClientCommand::ReconnectNow) => return false,
                Some(ClientCommand::ProvideCredentials { username: user, password: pass, .. }) => {
                    // A new password is for the next attempt.
                    if let Some(user) = user {
                        if !user.is_empty() {
                            credentials.0 = user;
                        }
                    }
                    if !pass.is_empty() {
                        credentials.1 = pass;
                    }
                }
                _ => {}
            },
            _ = tokio::time::sleep(remaining) => return false,
        }
    }
}

async fn wait_credentials(
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<(String, String)> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return None,
            cmd = commands.recv() => match cmd? {
                ClientCommand::ProvideCredentials { username, password, .. } => {
                    return Some((username.unwrap_or_default(), password));
                }
                ClientCommand::CancelCredentials | ClientCommand::Disconnect => return None,
                _ => {}
            }
        }
    }
}

async fn fail(
    events: &mpsc::Sender<SessionEvent>,
    reason: &str,
) -> Result<(), remote_core::EventSinkClosed> {
    emit_state(
        events,
        SessionState::Disconnected {
            reason: reason.to_string(),
            can_retry: true,
            symbol: None,
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn connect(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    _width: u16,
    _height: u16,
    ports: (u16, u16),
    geometry: Option<remote_core::options::AppleGeometry>,
    events: &mpsc::Sender<SessionEvent>,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &tokio_util::sync::CancellationToken,
    host_keys: Option<crate::macos::Verifier>,
    reconnect: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), SessionError> {
    emit_state(events, SessionState::Connecting).await.ok();
    let mut tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host, port)))
        .await
        .map_err(|_| SessionError::new("timed out connecting"))?
        .map_err(|e| SessionError::new(e.to_string()))?;
    tcp.set_nodelay(true).ok();

    let banner = read_handshake(&mut tcp, 12).await?;
    if &banner != b"RFB 003.889\n" {
        return Err(SessionError::new(
            "the server did not offer Apple Screen Sharing",
        ));
    }
    tcp.write_all(b"RFB 003.889\n").await?;
    let count = read_handshake(&mut tcp, 1).await?[0] as usize;
    if count == 0 {
        return Err(SessionError::new("the server refused the connection"));
    }
    let types = read_handshake(&mut tcp, count).await?;
    if !types.contains(&33) {
        return Err(SessionError::new("the server has no RSA-SRP sign-in"));
    }

    emit_state(
        events,
        SessionState::Authenticating {
            method: "apple-srp".into(),
        },
    )
    .await
    .ok();

    // Security type 33, then the empty RSA1 packet that asks for the key.
    let mut hello = vec![0x21];
    hello.extend(auth::rsa1_packet(0, 0, &[], 0));
    tcp.write_all(&hello).await?;
    let der = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_rsa_key(&mut tcp))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))??;
    let identity = auth::seal_identity(&der, username)?;
    tcp.write_all(&auth::rsa1_packet(2, 0x0100, &identity, 384))
        .await?;

    let challenge_buf = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_counted(&mut tcp))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))??;
    let challenge = auth::parse_challenge(&challenge_buf[4..])?;
    let secret = SrpSecret::client(
        password,
        &challenge.salt,
        challenge.iterations,
        &challenge.server_public,
    )?;
    let mut random = [0u8; 16];
    rand::rng().fill_bytes(&mut random);
    tcp.write_all(&auth::packet2_wire(
        &secret.a_public,
        &secret.m1,
        &challenge.options,
        &random,
    ))
    .await?;

    // The server proof is length-prefixed. Pass/fail is the u32 after it.
    let proof_buf = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_counted(&mut tcp))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))??;
    // The server proves it knows the password, and the proof is checked.
    //
    // Our M1 was accepted by the server, and M1 is built from the session
    // key, so our key is the server's key and the proof we expect is the
    // server's proof. A server that cannot produce it does not know the
    // password, and a session with it would be a session whose every
    // secret the other end could read.
    let proofs = auth::server_proofs(&proof_buf[4..]);
    if proofs.is_empty() {
        tracing::warn!("the server's proof could not be read, so it was not checked");
    } else if proofs.iter().any(|proof| secret.m2_matches(proof)) {
        tracing::info!("the server proved that it knows the password");
    } else {
        // A server that cannot produce the proof does not know the
        // password, and every secret of this session would be readable by
        // it.
        //
        // This is reported rather than fatal: the exact shape of the
        // proof has not been confirmed against a live Mac, and a sign-in
        // that fails on a surprise is worse than a sign-in that warns.
        // Make it fatal once a live session has confirmed the framing.
        tracing::warn!(
            "the server's proof did not match: this does not look like the Mac you expected"
        );
        emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
            "The Mac's identity proof did not match. Check that you are connected to the machine you meant.".into(),
        ))).await.ok();
    }
    let result = read_handshake(&mut tcp, 4).await?;
    if result != [0, 0, 0, 0] {
        return Err(SessionError::new("the server rejected the password"));
    }

    tcp.write_all(&[0xc1]).await?;
    let (server_w, server_h) = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_server_init(&mut tcp))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))??;
    emit(
        events,
        SessionEvent::DesktopResize {
            width: server_w,
            height: server_h,
        },
    )
    .await
    .ok();
    emit_state(events, SessionState::Negotiating).await.ok();

    tcp.write_all(&viewer_info()).await?;
    // Cleartext follow-up the server requires before it will emit the rekey.
    tcp.write_all(&[
        0x12, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    ])
    .await?;
    // Encodings go out in the clear. Without them the Mac never sends the
    // rekey, and the session sits on "negotiating" forever.
    tcp.write_all(&set_encodings()).await?;

    let wrap = secret.wrap_key;
    // The rekey can arrive as soon as SetEncryption(1) is sent, still in
    // the clear, as a framebuffer rectangle with encoding 0x44f.
    let layer = loop {
        let msg = read_clear_message(&mut tcp).await?;
        if let Some((key, iv)) = find_rekey(&msg, &wrap) {
            break RecordLayer::new(key, iv);
        }
    };

    let remembered_points =
        panel_geometry(geometry).map(|geometry| (geometry.point_width, geometry.point_height));
    let mut session = Live {
        tcp,
        layer,
        width: server_w,
        height: server_h,
        logical_width: remembered_points.map_or(server_w, |points| points.0),
        logical_height: remembered_points.map_or(server_h, |points| points.1),
        srtp: None,
        feedback: None,
        feedback_ssrc: 0,
        udp: None,
        ctrl: None,
        incoming: Vec::with_capacity(8192),
    };
    // This final toggle is CLEAR TEXT: it activates encryption for client
    // messages. Encrypting the toggle leaves the Mac waiting for it forever.
    session
        .tcp
        .write_all(&[0x12, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00])
        .await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The first encrypted records, in the order the native client sends
    // them: the display configuration, then the encodings.
    //
    // The display configuration is what says which display the session is
    // about. A client that says nothing lets the Mac choose, and what it
    // may choose is a new session with a login screen rather than the
    // console the person is already using. The geometry is the one the
    // last session confirmed, so the desktop is not resized either.
    for record in first_records(geometry) {
        session.send_body(&record).await?;
    }
    let (offer, srtp_blob, feedback_blob) = crate::offer::media_offer();
    session.srtp = SrtpContext::from_blob(&srtp_blob);
    // The other half of the video key encrypts the feedback we send back.
    session.feedback = SrtcpEncryptor::from_blob(&feedback_blob);
    // Our own SSRC as the sender of that feedback. The Mac answers the
    // feedback it receives, and answers it to this address.
    let mut ssrc_bytes = [0u8; 4];
    rand::rng().fill_bytes(&mut ssrc_bytes);
    session.feedback_ssrc = u32::from_be_bytes(ssrc_bytes);
    // The sockets are bound before the offer goes out, so the media can
    // arrive the moment the Mac accepts it.
    session.bind_video(host, ports).await?;
    session.send_body(&offer).await?;
    session
        .send_body(&framebuffer_request(session.width, session.height))
        .await?;

    emit(
        events,
        SessionEvent::DesktopResize {
            width: session.width,
            height: session.height,
        },
    )
    .await
    .ok();
    emit_state(events, SessionState::Connected).await.ok();

    let udp = session.udp.take();
    let ctrl = session.ctrl.take();
    let srtp = session.srtp.take();
    let width = session.width;
    let height = session.height;
    // The video receiver has its own lifetime: it ends with the control
    // loop, not with the session. The session's token belongs to the
    // session, and a session that is being retried is not over.
    let cancel2 = cancel.child_token();
    let video_dest = format!("{host}:5901");
    let ctrl_dest = format!("{host}:5900");
    let media_dimensions = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(
        (u32::from(width) << 16) | u32::from(height),
    ));
    let video_dimensions = media_dimensions.clone();
    // The physical-display controls talk to the Mac over SSH, and the
    // helper it runs takes seconds. That work does not belong in the loop
    // that carries the pointer and the keyboard, so it has a worker of its
    // own and the loop only waits for the answer.
    let (display_tx, mut display_rx) = mpsc::channel::<(
        remote_core::MacDisplayAction,
        mpsc::Sender<Result<remote_core::MacDisplayInfo, String>>,
    )>(4);
    let display_host = host.to_string();
    let display_user = username.to_string();
    let display_password = password.to_string();
    let display_keys = host_keys.clone();
    let display_task = tokio::spawn(async move {
        let mut display: Option<crate::macos::DisplayController> = None;
        while let Some((action, reply)) = display_rx.recv().await {
            let result = async {
                if display.is_none() {
                    let verifier = display_keys.clone().ok_or_else(|| {
                        "Mac display controls require the application's SSH host-key store"
                            .to_owned()
                    })?;
                    display = Some(
                        crate::macos::DisplayController::connect(
                            &display_host,
                            &display_user,
                            &display_password,
                            verifier,
                        )
                        .await?,
                    );
                }
                display
                    .as_mut()
                    .expect("connected above")
                    .request(action)
                    .await
            }
            .await;
            if reply.send(result).await.is_err() {
                // The session went away while the Mac was working. The
                // result is dropped, and the restore below still happens.
                break;
            }
        }
        // The session is over. If this connection changed the physical
        // display, put it back: the person in front of the Mac should not
        // find their panel in a state they did not ask for.
        if let Some(mut display) = display {
            display.restore_on_disconnect().await;
        }
    });
    let mut display_reply: Option<mpsc::Receiver<Result<remote_core::MacDisplayInfo, String>>> =
        None;
    // The action the pending reply answers, so the answer is read for what
    // it is: reading the mode list says nothing about the desktop, and only
    // a change resizes the picture.
    let mut display_action: Option<remote_core::MacDisplayAction> = None;
    // The Mac's own geometry, learned from the first layout it sends.
    //
    // The options carry a canvas the caller asked for, which is not the
    // same thing: the Mac has a panel of a size of its own, and that is
    // what "native" means, what the quality presets are measured against,
    // and what a restore has to put back.
    let mut baseline: Option<(u16, u16)> = None;
    // The same, in points: a retina panel is twice the points of its pixels,
    // and the difference is what turns a window's size into a desktop's size.
    let mut baseline_points: Option<(u16, u16)> = remembered_points;
    // Whether a resize has been asked for. The first layout after that is
    // the answer to the resize, not the Mac's own geometry.
    let mut resize_requested = false;
    // A preset chosen before the Mac's geometry is known.
    let mut pending_preset: Option<remote_core::QualityPreset> = None;
    // One resize round at a time (§10.9): 0x1d → 0x451 → re-offer → a picture
    // at the new size. A round is not over when the server answers it: the
    // encoder restarts after the answer, and a second request sent into
    // that restart races it (observed live as a black screen).
    let mut round = ResizeRound::default();
    // What the user is holding down, so it can be let go of. A session that
    // ends, loses focus, or is taken over must not leave a key or a mouse
    // button held on the remote machine.
    let mut held: Held = Held::default();
    // A view-only session sends no input at all.
    let mut view_only = false;
    // Re-offer counter and assembly-progress signal. This is NOT an
    // authenticated encoder epoch or a renderer presentation acknowledgement.
    let generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
    let picture_generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let video_generation = generation.clone();
    // The round trip to the Mac, in milliseconds, measured on the RTCP path.
    let video_picture_generation = picture_generation.clone();
    // A periodic tick, so a round can be finished, timed out or reported
    // without waiting for the next thing to happen on the wire.
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    // What the Mac's media path is doing, as its answer says.
    let mut media_state = remote_core::apple_media::MediaState::default();
    let mut last_media_report = Instant::now() - Duration::from_secs(1);
    // The previous tick's counters, so the rate between two ticks can be
    // reported rather than a lifetime average that hides a collapse.
    let mut last_stats_at = Instant::now();
    let mut last_stats_bytes = 0u64;
    let mut last_stats_pictures = 0u64;
    // When the media session was last offered again because the stream had
    // stopped.
    let mut last_revive = Instant::now() - REVIVE_AFTER;
    // The counters the video receiver keeps.
    let counters = std::sync::Arc::new(MediaCounters::default());
    let video_counters = counters.clone();
    // How many times the offer has been asked again because the answer was
    // empty.
    let mut offer_attempts = 0u32;
    // The feedback state travels with the video task: the requests are
    // about the video, and the video task is what notices that a picture
    // was lost.
    let mut feedback = session.feedback.take();
    let feedback_ssrc = session.feedback_ssrc;
    // The pictures go through a buffer, so that a shell that is slow to take
    // them cannot stop the receiver reading the socket. A socket that is
    // not read overflows, and an overflow loses packets.
    //
    // The buffer keeps the NEWEST pictures. A buffer that keeps the oldest
    // and drops the newest leaves the view showing a picture from the
    // past, and every further picture makes it older: the session looks
    // alive while it shows nothing new. Dropping a picture breaks the
    // reference chain, so the buffer says when that happened and the
    // pictures after it wait for an independent one.
    let picture_buffer = std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::pictures::PictureBuffer::default(),
    ));
    // A wakeup channel, so the consumer can wait for a picture without
    // holding the lock the producer needs, and without missing one that
    // arrives between the check and the wait.
    let (picture_wake_tx, mut picture_wake_rx) = mpsc::channel::<()>(1);
    let (video_request_tx, mut video_request_rx) = mpsc::unbounded_channel::<VideoRequest>();
    let picture_events = events.clone();
    let picture_dimensions = video_dimensions.clone();
    let consumer_buffer = picture_buffer.clone();
    let picture_task = tokio::spawn(async move {
        let mut pictures = 0u32;
        loop {
            let Some(unit) = next_picture(&consumer_buffer, &mut picture_wake_rx).await else {
                if picture_wake_rx.is_closed() {
                    break;
                }
                continue;
            };
            if !publish(
                &picture_events,
                vec![unit],
                &picture_dimensions,
                &mut pictures,
            )
            .await
            {
                break;
            }
        }
    });
    let peer = Peer::resolve(host, ports.0).await;
    // When the Mac started owing us a picture, in milliseconds since the
    // session began. Input, or a request for a fresh picture, is a promise
    // that the screen will change; if no picture follows, the stream is
    // stuck rather than idle, and asking again is the recovery.
    let session_start = Instant::now();
    let picture_owed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let video_owed = picture_owed.clone();
    let video_start = session_start;
    let video_task = tokio::spawn(async move {
        if let (Some(sock), Some(ctx)) = (udp, srtp) {
            let mut buf = vec![0u8; 65535];
            let mut cbuf = vec![0u8; 2048];
            let mut punch = tokio::time::interval(Duration::from_millis(200));
            // A hole in the sequence numbers has to be given up on after a
            // short wait, or one lost packet would hold the stream still
            // for ever.
            let mut flush_tick = tokio::time::interval(Duration::from_millis(20));
            let mut packets = 0u32;
            let mut opened = 0u64;
            let mut streams = crate::video::VideoStreams::new(ctx, Instant::now());
            let mut last_active = None;
            // How many holes we have already asked about.
            let mut gaps_seen = 0u64;
            // The last time a keyframe was asked for, so a burst of loss
            // does not turn into a burst of requests.
            let mut clock = FeedbackClock::default();
            // The media generation the video task last saw.
            let mut last_generation = 0u64;
            // Pictures the shell did not take in time.
            let mut dropped = 0u64;
            let mut chain_broken = false;
            // When the last request for an independent picture went out.
            let mut last_backlog_request = Instant::now() - BACKLOG_REQUEST_INTERVAL;
            // The spacing between pictures, which says whether the stream
            // arrives evenly or in bursts.
            let mut cadence = PictureCadence::default();
            let mut always_refresh = false;
            let mut last_always_refresh = Instant::now() - ALWAYS_REFRESH_INTERVAL;
            let mut last_silence_request = Instant::now() - SILENT_STREAM_TIMEOUT;
            // How long to wait before asking again for a picture the Mac owes
            // us. It doubles while the asks go unanswered, because a pointer
            // moving over an unchanged screen is not a fault and must not
            // cost the Mac a full picture every two seconds.
            let mut owed_retry = SILENT_STREAM_TIMEOUT;
            // When the last video packet arrived, whatever it contained. A
            // still desktop sends nothing at all, and that is not a stall.
            let mut last_packet_at: Option<Instant> = None;
            // When a picture last came out, on the same clock as the marks
            // below, so "the Mac owes us one" can be decided here.
            let mut last_picture_ms = 0u64;
            // Packets from somewhere other than the Mac.
            let mut stray = 0u64;
            // The round trip to the Mac, measured on the RTCP path.
            // When the last report went out.
            let mut last_report = Instant::now() - Duration::from_secs(2);
            loop {
                let n = tokio::select! {
                    _ = cancel2.cancelled() => break,
                    _ = punch.tick() => {
                        sock.send_to(&[0], &video_dest).await.ok();
                        if let Some(ctrl) = &ctrl {
                            ctrl.send_to(&[0], &ctrl_dest).await.ok();
                        }
                        continue;
                    }
                    request = video_request_rx.recv() => {
                        match request {
                            Some(VideoRequest::FreshPicture) => {
                                if let Some(ssrc) = streams.active() {
                                    request_keyframe(
                                        &mut feedback,
                                        feedback_ssrc,
                                        ssrc,
                                        ctrl.as_ref(),
                                        &ctrl_dest,
                                        &mut clock,
                                        &video_counters.requests,
                                    ).await;
                                } else {
                                    tracing::debug!("fresh-picture request ignored before a video stream is active");
                                }
                            }
                            Some(VideoRequest::AlwaysRefresh(enabled)) => {
                                always_refresh = enabled;
                                last_always_refresh = Instant::now() - ALWAYS_REFRESH_INTERVAL;
                                tracing::info!(enabled, "periodic fresh-picture requests toggled");
                            }
                            None => break,
                        }
                        continue;
                    }
                    _ = flush_tick.tick() => {
                        // Keep sending receiver reports so the Mac has
                        // feedback on the media stream.
                        if last_report.elapsed() >= Duration::from_secs(1) {
                            last_report = Instant::now();
                            if let (Some(encryptor), Some(socket)) = (feedback.as_mut(), ctrl.as_ref()) {
                                let packet = crate::rtcp::compound(feedback_ssrc, &[]);
                                if let Some(protected) = encryptor.protect(&packet) {
                                    let _ = socket.send_to(&protected, &ctrl_dest).await;
                                }
                            }
                        }
                        // A stream that is still arriving but cannot
                        // complete a picture is stuck mid-assembly, and only
                        // a fresh picture clears it: no later packet reports
                        // the gap that is holding it.
                        //
                        // Packets that have stopped entirely are a different
                        // case, and not a fault: this stream is damage
                        // driven, so an idle desktop sends nothing. Asking
                        // for a picture then costs the Mac a full frame every
                        // two seconds for a screen that has not changed.
                        let now = Instant::now();
                        let packets_arriving = last_packet_at
                            .map(|at| now.duration_since(at) < Duration::from_secs(1))
                            .unwrap_or(false);
                        // Two ways a stream can stall. Mid-assembly, packets
                        // keep arriving and never complete a picture. Owed, a
                        // picture was promised by input or by an earlier
                        // request and simply did not come, which is the case
                        // that leaves a session frozen for minutes.
                        let now_ms = video_start.elapsed().as_millis() as u64;
                        let owed_at = video_owed.load(std::sync::atomic::Ordering::Relaxed);
                        let owed_long_enough = owed_at != 0
                            && now_ms.saturating_sub(owed_at) >= SILENT_STREAM_TIMEOUT.as_millis() as u64
                            && now_ms.saturating_sub(last_picture_ms) >= SILENT_STREAM_TIMEOUT.as_millis() as u64;
                        let ask_for_owed = owed_long_enough && last_silence_request.elapsed() >= owed_retry;
                        if ask_for_owed
                            || should_ask_for_stalled_picture(
                                packets_arriving,
                                streams.active_picture_stalled(now, SILENT_STREAM_TIMEOUT),
                                last_silence_request.elapsed(),
                            )
                        {
                            last_silence_request = now;
                            // Asking again later if this one is not answered
                            // either, and less often each time.
                            if ask_for_owed {
                                owed_retry = (owed_retry * 2).min(OWED_RETRY_MAX);
                            }
                            video_owed.store(now_ms, std::sync::atomic::Ordering::Relaxed);
                            video_counters
                                .stalls
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if let Some(ssrc) = streams.active() {
                                if request_keyframe(
                                    &mut feedback,
                                    feedback_ssrc,
                                    ssrc,
                                    ctrl.as_ref(),
                                    &ctrl_dest,
                                    &mut clock,
                                    &video_counters.requests,
                                ).await {
                                    video_counters.recoveries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                        if always_refresh && last_always_refresh.elapsed() >= ALWAYS_REFRESH_INTERVAL {
                            last_always_refresh = now;
                            if let Some(ssrc) = streams.active() {
                                request_keyframe(
                                    &mut feedback,
                                    feedback_ssrc,
                                    ssrc,
                                    ctrl.as_ref(),
                                    &ctrl_dest,
                                    &mut clock,
                                    &video_counters.requests,
                                ).await;
                            }
                        }
                        if should_ask_for_backlog_picture(
                            chain_broken,
                            last_backlog_request.elapsed(),
                        ) {
                            last_backlog_request = Instant::now();
                            if let Some(ssrc) = streams.active() {
                                let requested = request_keyframe(
                                    &mut feedback,
                                    feedback_ssrc,
                                    ssrc,
                                    ctrl.as_ref(),
                                    &ctrl_dest,
                                    &mut clock,
                                    &video_counters.requests,
                                )
                                .await;
                                if requested {
                                    video_counters.recoveries.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                        // Flush candidates as well as the active stream,
                        // then use the same nonblocking picture queue.
                        None
                    }
                    r = sock.recv_from(&mut buf) => match r {
                        Ok((n, from)) => {
                            // Only the Mac's own packets are read. A stray
                            // datagram on the port is not part of the
                            // session, and treating one as video would put
                            // rubbish into the decoder.
                            if !peer.matches(&from) {
                                stray += 1;
                                if stray <= 3 || stray.is_multiple_of(100) {
                                    tracing::warn!(%from, stray, "a packet from somewhere else was ignored");
                                }
                                continue;
                            }
                            Some(n)
                        }
                        Err(_) => break,
                    },
                    r = async {
                        match &ctrl {
                            Some(ctrl) => ctrl.recv(&mut cbuf).await,
                            None => std::future::pending().await,
                        }
                    } => {
                        // RTCP traffic is not a correlated reply to our
                        // report. Consume it, but do not present its arrival
                        // delay as network RTT.
                        if let Ok(n) = r {
                            if !crate::rtcp::is_rtcp(&cbuf[..n]) {
                                tracing::debug!("a non-RTCP datagram arrived on the feedback socket");
                            }
                        }
                        continue;
                    }
                };
                let generation = video_generation.load(std::sync::atomic::Ordering::SeqCst);
                let units = match n {
                    Some(n) => {
                        packets += 1;
                        video_counters
                            .packets
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        video_counters
                            .bytes
                            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                        if packets <= 3 {
                            tracing::debug!(bytes = n, "Apple video datagram");
                        }
                        last_packet_at = Some(Instant::now());
                        let units = streams.push(&buf[..n], generation, Instant::now());
                        let authenticated = streams.authenticated();
                        if opened == 0 && authenticated > 0 {
                            tracing::info!("Apple SRTP video authenticated");
                        }
                        opened = authenticated;
                        units
                    }
                    None => streams.flush(generation, Instant::now()),
                };
                let Some(ssrc) = streams.active() else {
                    continue;
                };
                if last_active != Some(ssrc) {
                    last_active = Some(ssrc);
                    gaps_seen = 0;
                }
                // A re-offer asks for an independent picture. The receiver
                // promotes a replacement only with parameter sets and a
                // complete key picture, not just because its SSRC appeared.
                if generation != last_generation {
                    last_generation = generation;
                    // A re-offer asks the Mac for a new stream, and the
                    // Mac's encoder may start its packet numbers again. The
                    // keys are the same, so the new packets authenticate,
                    // but a receiver that remembers the old numbers calls
                    // every one of them a replay and the picture never
                    // comes back.
                    streams.new_epoch();
                    request_keyframe(
                        &mut feedback,
                        feedback_ssrc,
                        ssrc,
                        ctrl.as_ref(),
                        &ctrl_dest,
                        &mut clock,
                        &video_counters.requests,
                    )
                    .await;
                }
                if !units.is_empty() {
                    last_picture_ms = video_start.elapsed().as_millis() as u64;
                    video_counters
                        .last_picture_ms
                        .store(last_picture_ms, std::sync::atomic::Ordering::Relaxed);
                    // How long the person waited for this picture, if they
                    // had asked for one. The mark is cleared so the wait is
                    // measured once, not counted again by the next picture.
                    // A picture arrived, so whatever was owed has been paid
                    // and the next ask starts from the short wait again.
                    owed_retry = SILENT_STREAM_TIMEOUT;
                    let asked_at = video_owed.swap(0, std::sync::atomic::Ordering::Relaxed);
                    if asked_at != 0 && last_picture_ms > asked_at {
                        let waited = (last_picture_ms - asked_at).min(60_000) as u32;
                        let previous = video_counters
                            .input_latency_ms
                            .load(std::sync::atomic::Ordering::Relaxed);
                        let smoothed = if previous == 0 {
                            waited
                        } else {
                            // A slow average that hides a single freeze is
                            // not a measurement; the worst case is kept
                            // beside it.
                            (u64::from(previous) * 7 / 8 + u64::from(waited) / 8) as u32
                        };
                        video_counters
                            .input_latency_ms
                            .store(smoothed, std::sync::atomic::Ordering::Relaxed);
                        video_counters
                            .input_worst_ms
                            .fetch_max(waited, std::sync::atomic::Ordering::Relaxed);
                    }
                    // The spacing between pictures is what a person feels as
                    // smoothness, so it is measured where the pictures land.
                    let jitter = cadence.picture(Instant::now());
                    video_counters
                        .jitter_ms
                        .store(jitter, std::sync::atomic::Ordering::Relaxed);
                    // This is assembly progress after re-offer, not a
                    // renderer/decoder acknowledgement of the requested size.
                    video_picture_generation.store(generation, std::sync::atomic::Ordering::SeqCst);
                    video_counters
                        .pictures
                        .fetch_add(units.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    for unit in units {
                        // The buffer never blocks the receiver. A picture
                        // that does not fit pushes the oldest one out, and
                        // the chain is repaired by the next independent
                        // picture.
                        let overflowed = {
                            let mut buffer = picture_buffer.lock().await;
                            let overflowed = buffer.push(unit);
                            dropped = buffer.dropped();
                            chain_broken = buffer.is_broken();
                            overflowed
                        };
                        if overflowed {
                            // The client is behind, not the network. The
                            // picture that did not fit is complete, so
                            // asking the Mac for another one adds work
                            // without fixing anything: it is what turned a
                            // slow client into a stalled one. The chain is
                            // broken and the buffer waits for an
                            // independent picture; the tick asks for one,
                            // at most once a second.
                            video_counters
                                .dropped
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        // Wake the consumer. A signal that is already
                        // waiting is enough: it re-checks the buffer.
                        let _ = picture_wake_tx.try_send(());
                    }
                }
                // A lost packet leaves the decoder holding a picture that
                // refers to something it never received, and the picture
                // stays wrong until the next independent picture. Ask for
                // one.
                let Some(stats) = streams.active_stats() else {
                    continue;
                };
                if stats.gaps > gaps_seen {
                    gaps_seen = stats.gaps;
                    video_counters
                        .lost
                        .store(stats.lost_packets, std::sync::atomic::Ordering::Relaxed);
                    // Ask for the packets that went missing, and for a
                    // fresh picture: the missing ones may come back, and
                    // the fresh one is what repairs the reference chain
                    // when they do not.
                    let missing = stats.lost_sequences.clone();
                    request_retransmission(
                        &mut feedback,
                        feedback_ssrc,
                        ssrc,
                        &missing,
                        ctrl.as_ref(),
                        &ctrl_dest,
                    )
                    .await;
                    if request_keyframe(
                        &mut feedback,
                        feedback_ssrc,
                        ssrc,
                        ctrl.as_ref(),
                        &ctrl_dest,
                        &mut clock,
                        &video_counters.requests,
                    )
                    .await
                    {
                        video_counters
                            .recoveries
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                // Report on the stream's health, so a picture that is going
                // wrong is visible in the log instead of being guessed at.
                if n.is_some()
                    && packets.is_multiple_of(120)
                    && (stats.gaps > 0 || stats.malformed > 0 || dropped > 0 || chain_broken)
                {
                    tracing::info!(
                        gaps = stats.gaps,
                        lost = stats.lost_packets,
                        reordered = stats.reordered,
                        late = stats.late,
                        malformed = stats.malformed,
                        discarded = stats.discarded,
                        dropped,
                        "Apple video stream health"
                    );
                }
            }
            tracing::debug!(packets, opened, "Apple video receiver stopped");
        }
    });

    // Whether this attempt ended because a worker died. That is a failed
    // attempt, not a session the person ended, and the supervisor has to be
    // able to tell the two apart.
    let mut worker_failed = false;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            cmd = commands.recv() => {
                match cmd {
                    None | Some(ClientCommand::Disconnect) => break,
                    Some(ClientCommand::Pointer { x, y, button_mask }) => {
                        if view_only {
                            // A view-only session must not move the remote
                            // pointer, not even to "release" it.
                            continue;
                        }
                        let body = crate::input::pointer(session.layer.wrap_key(), x, y, button_mask);
                        session.send_body(&body).await?;
                        held.pointer = Some((x, y, button_mask));
                        // Input is a promise that the screen will change. If
                        // no picture follows, the stream is stuck rather than
                        // idle, and the recovery paths can tell the two apart.
                        picture_owed.store(
                            session_start.elapsed().as_millis() as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    Some(ClientCommand::Key { keysym, down, .. }) => {
                        if view_only {
                            continue;
                        }
                        let mut body = [0u8; 8];
                        body[0] = 4;
                        body[1] = u8::from(down);
                        body[4..8].copy_from_slice(&keysym.to_be_bytes());
                        session.send_body(&body).await?;
                        if down {
                            held.keys.insert(keysym);
                        } else {
                            held.keys.remove(&keysym);
                        }
                        picture_owed.store(
                            session_start.elapsed().as_millis() as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    Some(ClientCommand::ReconnectNow) => {
                        // End the session so a new one can start. The
                        // supervisor notices the flag and starts it at
                        // once.
                        reconnect.store(true, std::sync::atomic::Ordering::SeqCst);
                        break;
                    }
                    Some(ClientCommand::ReleaseAllKeys) => {
                        // Let go of everything that is held. This is what a
                        // focus loss, a takeover or a disconnect needs, and
                        // the remote machine has no other way to learn about
                        // it.
                        release_all(&mut session, &mut held).await?;
                    }
                    Some(ClientCommand::SetViewOnly(on)) => {
                        if on && !view_only {
                            // Anything held was pressed under the old mode,
                            // so it is let go of first.
                            release_all(&mut session, &mut held).await?;
                        }
                        view_only = on;
                        tracing::info!(enabled = on, "view-only toggled");
                    }
                    Some(ClientCommand::SetAlwaysRefresh(on)) => {
                        let _ = video_request_tx.send(VideoRequest::AlwaysRefresh(on));
                    }
                    Some(ClientCommand::SetPreferScancodes(_)) => {
                        // The Apple path always sends keysyms, so the remote
                        // machine's layout decides what a key types. There is
                        // no scancode mode to switch to, and nothing to
                        // release: the encoding does not change.
                    }
                    Some(ClientCommand::TrustCertificate { .. }) => {
                        // Certificate trust is a property of the security
                        // handshake. Apple Screen Sharing authenticates with
                        // RSA-SRP and has no certificate to trust.
                    }
                    Some(ClientCommand::Agent(intent)) => {
                        // Answered rather than ignored. An agent is blocked
                        // on a settlement; a shrug here is an agent that
                        // waits for ever.
                        emit(
                            events,
                            SessionEvent::AgentRefused(intent.refuse(
                                "Apple Screen Sharing has no native command channel: this intent cannot be served over it",
                            )),
                        )
                        .await.ok();
                    }
                    Some(ClientCommand::Refresh) => {
                        // The Apple picture is an H.264 stream over UDP. A
                        // framebuffer request over TCP does not ask that
                        // encoder for a clean independent picture.
                        picture_owed.store(
                            session_start.elapsed().as_millis() as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        let _ = video_request_tx.send(VideoRequest::FreshPicture);
                    }
                    Some(ClientCommand::SetQuality(preset)) => {
                        // Apple Remote Desktop's lever: the preset picks the
                        // resolution the Mac renders and streams. `0x451`
                        // below confirms what the server actually chose.
                        let Some(base) = baseline else {
                            // The Mac has not said how big its screen is yet,
                            // and the presets are measured against that. The
                            // choice is remembered and applied when it does.
                            pending_preset = Some(preset);
                            tracing::info!("a quality preset was chosen before the Mac's geometry was known");
                            continue;
                        };
                        let points = baseline_points.unwrap_or(base);
                        let target = crate::quality::resolution_for(preset, base, points);
                        let current = (session.width, session.height);
                        resize_requested = true;
                        let base = baseline.unwrap_or(current);
                        media_state.requested_width = u32::from(target.0);
                        media_state.requested_height = u32::from(target.1);
                        request_resize(&mut session, &mut round, target, current, base, Some(points)).await?;
                    }
                    Some(ClientCommand::MacDisplay(action)) => {
                        use remote_core::MacDisplayAction;
                        if display_reply.is_some() {
                            // One display operation at a time. Replacing the
                            // receiver dropped the previous settlement, and
                            // the worker answered a closed channel by
                            // stopping, which left every later request with
                            // no worker at all.
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
                                "A Mac display change is still in progress. Try again when it finishes.".into(),
                            ))).await.ok();
                            continue;
                        }
                        let changes_mode = !matches!(action, MacDisplayAction::List);
                        if changes_mode {
                            // A pending stream resize was made for the old
                            // desktop, so it no longer means what it meant.
                            // A round that is already running is left to
                            // finish.
                            round.requested = None;
                        }
                        // The work happens on the display worker, so the
                        // pointer and the keyboard keep flowing while the
                        // Mac is busy.
                        let (reply, wait) = mpsc::channel(1);
                        display_action = Some(action);
                        if display_tx.send((action, reply)).await.is_err() {
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
                                "The Mac display controls are not available in this session.".into(),
                            ))).await.ok();
                        } else {
                            display_reply = Some(wait);
                        }
                    }
                    Some(ClientCommand::RequestResize { width, height }) => {
                        // In-band dynamic resize (RFC §10.9): 0x1d now, and the
                        // 0x451 that answers it drives the media re-offer.
                        //
                        // The bound is the size a Mac can display, not the
                        // size of a 4K television: the native button asks
                        // for the panel's own geometry, which on this Mac is
                        // 3600x2338, and a bound of 2160 refused it.
                        if (640..=8192).contains(&width) && (480..=8192).contains(&height) {
                            let current = (session.width, session.height);
                            resize_requested = true;
                            let base = baseline.unwrap_or(current);
                            // The requested size is the picture size. The
                            // desktop's point size stays what the Mac is
                            // already using: deriving a new point size from
                            // the local window is what shrank a Retina
                            // desktop to 800x600 points and made its windows
                            // look twice as large.
                            let points = baseline_points
                                .unwrap_or((session.logical_width, session.logical_height));
                            media_state.requested_width = u32::from(width);
                            media_state.requested_height = u32::from(height);
                            request_resize(
                                &mut session,
                                &mut round,
                                (width, height),
                                current,
                                base,
                                Some(points),
                            )
                            .await?;
                        } else {
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice("That size is outside the range the Mac can stream.".into()))).await.ok();
                        }
                    }
                    _ => {}
                }
            }
            display = async {
                match &mut display_reply {
                    Some(reply) => reply.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                use remote_core::ProtocolEvent;
                display_reply = None;
                let Some(result) = display else {
                    // The worker went away without answering. Say so rather
                    // than panicking on a closed channel: the session can
                    // still be used, and the display state is unknown.
                    display_action = None;
                    tracing::warn!("the Mac display worker stopped without answering");
                    emit(events, SessionEvent::Protocol(ProtocolEvent::AppleDisplay(Err(
                        "The Mac display worker stopped before it answered. The display's current mode is unverified.".into(),
                    )))).await.ok();
                    continue;
                };
                let action = display_action.take();
                // Reading the mode list changes nothing, so it must not
                // resize the picture. A change does, and so does a restore.
                let changes_mode = !matches!(action, Some(remote_core::MacDisplayAction::List));
                if let Ok(info) = &result {
                    // Reading the mode list says nothing about the desktop,
                    // so it must not resize the picture. Only a change does.
                    if changes_mode {
                        session.width = info.pixel_width;
                        session.height = info.pixel_height;
                        media_dimensions.store((u32::from(info.pixel_width) << 16) | u32::from(info.pixel_height), std::sync::atomic::Ordering::Relaxed);
                        emit(events, SessionEvent::DesktopResize { width: info.pixel_width, height: info.pixel_height }).await.ok();
                    }
                }
                if result.is_ok() && changes_mode {
                    // Keep the SRTP keys, but re-offer after a physical
                    // mode change so the HP encoder starts its new canvas.
                    session.send_body(&offer).await?;
                    generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    session.send_body(&framebuffer_request(session.width, session.height)).await?;
                }
                emit(events, SessionEvent::Protocol(ProtocolEvent::AppleDisplay(result))).await.ok();
            }
            body = session.read_body() => {
                let body = body?;
                tracing::debug!(bytes = body.len(), "Apple control message");
                // A rekey inside the record layer rotates the content key.
                if let Some((key, iv)) = find_rekey(&body, session.layer.wrap_key()) {
                    // The key and IV change; the session's sequence counters
                    // do not. Resetting them would make the next record fail
                    // its integrity check and end the session.
                    let send_seq = session.layer.send_sequence();
                    let recv_seq = session.layer.recv_sequence();
                    session.layer.rekey(key, iv);
                    tracing::info!(send_seq, recv_seq, "Apple control layer rekeyed");
                }
                // The Mac's answer to the media offer: what the encoder
                // settled on, and how many tile streams it is using.
                if body.first() == Some(&0) {
                    if let Some(answer) = crate::answer::parse(&body) {
                        media_state.canvas_width = answer.canvas_width;
                        media_state.canvas_height = answer.canvas_height;
                        media_state.tiles = answer.tiles;
                        tracing::info!(
                            canvas_width = answer.canvas_width,
                            canvas_height = answer.canvas_height,
                            tiles = answer.tiles,
                            "the Mac answered the media offer"
                        );
                        if !answer.is_usable() {
                            // The Mac answered with an empty canvas, which
                            // it does while its encoder is still warming up.
                            // The offer is asked again.
                            if offer_attempts < MAX_OFFER_ATTEMPTS {
                                offer_attempts += 1;
                                tracing::info!(attempt = offer_attempts, "the Mac's answer was empty; asking again");
                                session.send_body(&offer).await?;
                            } else {
                                tracing::warn!("the Mac's answer was empty after several attempts");
                            }
                        } else {
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleMedia(media_state))).await.ok();
                        }
                    }
                }
                // AppleDisplayLayout (0x451): authoritative geometry (R-A15).
                if let Some(((lw, lh), (bw, bh))) = find_display_layout(&body) {
                    // Keep the wire fields as reported. Pixel/point ratios
                    // do not establish field order or justify a second resize.
                    let changed = (bw, bh) != (session.width, session.height);
                    session.width = bw;
                    session.height = bh;
                    media_state.desktop_width = u32::from(lw);
                    media_state.desktop_height = u32::from(lh);
                    media_state.layout_width = u32::from(bw);
                    media_state.layout_height = u32::from(bh);
                    // The layout also says how big the desktop is in points.
                    // On a retina display that is half the pixel size, and
                    // it is what a quality change must leave alone.
                    if lw > 0 && lh > 0 {
                        session.logical_width = lw;
                        session.logical_height = lh;
                    }
                    // The first layout, before anything was asked of the
                    // Mac, is the Mac's own geometry. A remembered point
                    // size is only a starting value for the first request;
                    // this layout remains the authoritative baseline.
                    let learn_baseline = baseline.is_none() && !resize_requested;
                    if learn_baseline {
                        baseline = Some((bw, bh));
                        baseline_points = Some((session.logical_width, session.logical_height));
                        tracing::info!(
                            width = bw, height = bh,
                            logical_width = session.logical_width, logical_height = session.logical_height,
                            "the Mac's own geometry"
                        );
                    }
                    media_dimensions.store((u32::from(bw) << 16) | u32::from(bh), std::sync::atomic::Ordering::Relaxed);
                    if changed {
                        emit(events, SessionEvent::DesktopResize { width: bw, height: bh }).await.ok();
                    }
                    // R-A16b: re-arm the sender on every layout, geometry or not.
                    session.send_body(&auto_framebuffer(bw, bh)).await?;
                    session.send_body(&framebuffer_request(bw, bh)).await?;
                    if round.in_flight && round.awaiting_layout {
                        // §10.9 step 3: the re-offer is what restarts the
                        // encoder at the new canvas. Keys are reused.
                        //
                        // The round is NOT over yet. The encoder restarts
                        // after this answer, and a request sent into that
                        // restart races it. The round ends when a picture at
                        // re-offer has assembly progress. This still lacks
                        // a renderer acknowledgement of the effective size.
                        session.send_body(&offer).await?;
                        generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        // The points are the session's after the update
                        // above, so a layout that carries no logical size
                        // cannot look like a shrink to zero.
                        round.confirmed = Some(DisplayGeometry {
                            pixels: (bw, bh),
                            points: (session.logical_width, session.logical_height),
                        });
                        // The re-offer restarts the encoder, so the round
                        // ends on a picture from that restarted encoder, not
                        // on the layout that asked for it.
                        round.needs_picture = true;
                        round.awaiting_layout = false;
                        tracing::info!(bw, bh, lw, lh, "Apple display layout received; media re-offered");
                    }
                    // Start a deferred preset only AFTER processing this
                    // unsolicited baseline layout. It cannot acknowledge a
                    // request that was not sent when the layout arrived.
                    if learn_baseline {
                        if let Some(preset) = pending_preset.take() {
                            let base = baseline.unwrap();
                            let points = baseline_points.unwrap();
                            let target = crate::quality::resolution_for(preset, base, points);
                            resize_requested = true;
                            media_state.requested_width = u32::from(target.0);
                            media_state.requested_height = u32::from(target.1);
                            request_resize(&mut session, &mut round, target, (bw, bh), base, Some(points)).await?;
                        }
                    }
                }
            }
            _ = tick.tick() => {
                // The media state is reported every few seconds: how many
                // access units have been assembled, how many packets went missing,
                // and how many times the picture was asked for again.
                //
                // Throughput and picture rate are measured here from the
                // counters the receiver keeps, so the status panel describes
                // the stream that actually arrived. Apple SRTP does not give
                // a correlated RTT sample yet, so latency stays unreported.
                // Reporting an RTCP arrival delay as RTT would be a guess.
                let pictures = counters.pictures.load(std::sync::atomic::Ordering::Relaxed);
                let bytes = counters.bytes.load(std::sync::atomic::Ordering::Relaxed);
                // Rates are measured over a whole second. The control loop
                // ticks four times a second, and a window that short reads
                // zero whenever that particular quarter second was quiet,
                // which is most of them on a desktop that is not moving.
                let elapsed = last_stats_at.elapsed().as_secs_f64();
                if elapsed >= 1.0 {
                    let stats = remote_core::SessionStats {
                        throughput_bps: (bytes.saturating_sub(last_stats_bytes)) as f64 * 8.0 / elapsed,
                        fps: (pictures.saturating_sub(last_stats_pictures)) as f32 / elapsed as f32,
                        bytes_received: bytes,
                        ..Default::default()
                    };
                    last_stats_at = Instant::now();
                    last_stats_bytes = bytes;
                    last_stats_pictures = pictures;
                    emit(events, SessionEvent::Stats(stats)).await.ok();
                }
                media_state.pictures = pictures;
                media_state.lost = counters.lost.load(std::sync::atomic::Ordering::Relaxed);
                media_state.dropped = counters.dropped.load(std::sync::atomic::Ordering::Relaxed);
                media_state.requests = counters.requests.load(std::sync::atomic::Ordering::Relaxed);
                media_state.recoveries = counters.recoveries.load(std::sync::atomic::Ordering::Relaxed);
                media_state.packets = counters.packets.load(std::sync::atomic::Ordering::Relaxed);
                media_state.bytes = bytes;
                media_state.stalls = counters.stalls.load(std::sync::atomic::Ordering::Relaxed);
                media_state.jitter_ms = counters.jitter_ms.load(std::sync::atomic::Ordering::Relaxed);
                media_state.input_latency_ms =
                    counters.input_latency_ms.load(std::sync::atomic::Ordering::Relaxed);
                media_state.input_worst_ms =
                    counters.input_worst_ms.load(std::sync::atomic::Ordering::Relaxed);
                if last_media_report.elapsed() >= Duration::from_secs(1) {
                    last_media_report = Instant::now();
                    emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleMedia(media_state))).await.ok();
                }
                // A stream that has genuinely stopped needs more than
                // another UDP request: that asks a media session which may
                // no longer exist. Escalate, and say what is happening
                // rather than leaving a frozen pane that claims to be
                // connected.
                //
                // A quiet desktop is not this case: the Mac owes a picture
                // only when input was sent or one was asked for, and that is
                // recorded where the input is handled.
                let now_ms = session_start.elapsed().as_millis() as u64;
                let owed = picture_owed.load(std::sync::atomic::Ordering::Relaxed);
                let silent_ms = now_ms.saturating_sub(
                    counters.last_picture_ms.load(std::sync::atomic::Ordering::Relaxed),
                );
                // A round already re-offered the media session and is
                // waiting for the encoder it restarted. A second re-offer
                // here restarts the same encoder under it, which is how a
                // resize raced its own recovery.
                if owed != 0
                    && !round.in_flight
                    && silent_ms >= REVIVE_AFTER.as_millis() as u64
                    && last_revive.elapsed() >= REVIVE_AFTER
                {
                    {
                        last_revive = Instant::now();
                        tracing::warn!(
                            silent_ms,
                            "the Mac has sent no picture for a while; re-offering the media session"
                        );
                        // The keys are reused, which the protocol allows for
                        // a re-offer, and the new generation resets the
                        // replay window so the restarted encoder's numbering
                        // is not mistaken for replays.
                        session.send_body(&offer).await?;
                        generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        session
                            .send_body(&framebuffer_request(session.width, session.height))
                            .await?;
                        counters
                            .recoveries
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
                            "The Mac stopped sending pictures; its media session was offered again.".into(),
                        ))).await.ok();
                    }
                }
                // A video receiver that died leaves a session that reports
                // itself connected and shows nothing. The supervisor
                // restarts it.
                if video_task.is_finished() || picture_task.is_finished() {
                    worker_failed = true;
                    tracing::warn!(
                        video = video_task.is_finished(),
                        publisher = picture_task.is_finished(),
                        "an Apple media worker stopped; the attempt will be restarted"
                    );
                    break;
                }
                // Finish, report or time out a resize round.
                if round.in_flight {
                    let picture_arrived = picture_generation.load(std::sync::atomic::Ordering::SeqCst)
                        >= generation.load(std::sync::atomic::Ordering::SeqCst);
                    // The layout has to come first: a picture from the old
                    // encoder says nothing about the size that was asked for.
                    if !round.awaiting_layout && (!round.needs_picture || picture_arrived) {
                        let was_restoring = round.restoring;
                        let before = round.before;
                        match finish_round(&mut round) {
                            RoundEnd::Send(target) => {
                                tracing::info!(?target, "Apple queued resize sent");
                                media_state.requested_width = u32::from(target.pixels.0);
                                media_state.requested_height = u32::from(target.pixels.1);
                                let cap = baseline.unwrap_or((session.width, session.height));
                                session
                                    .send_body(&display_config(request_for(target), cap))
                                    .await?;
                            }
                            RoundEnd::Done(clamped) => {
                                tracing::info!(?clamped, restoring = was_restoring, "Apple resize round complete");
                                let confirmed = round.confirmed;
                                if was_restoring {
                                    // The write that asked for the old size is
                                    // not a restore. The layout that answers
                                    // it is what proves the Mac is back.
                                    round.restoring = false;
                                    let restored = match (round.sent, confirmed) {
                                        (Some(sent), Some(confirmed)) => {
                                            confirmed.points == sent.points
                                        }
                                        _ => false,
                                    };
                                    let message = if restored {
                                        "The Mac refused that stream size. Its desktop is back at the previous size."
                                    } else {
                                        "The Mac refused that stream size and did not confirm the previous desktop size. The current size is unverified."
                                    };
                                    tracing::warn!(restored, "Apple resize refusal handled");
                                    emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(message.into()))).await.ok();
                                } else if desktop_shrank(clamped) && round.restores_left > 0 {
                                    // The Mac answered with fewer points. That
                                    // is a smaller desktop, not a lower quality:
                                    // every window is bigger for the same
                                    // screen. Put the geometry back as a round
                                    // of its own, so the layout and the picture
                                    // prove it before anything is reported.
                                    if let Some(before) = before {
                                        let cap = baseline.unwrap_or(before.pixels);
                                        start_round(&mut round, before, confirmed.unwrap_or(before), true);
                                        media_state.requested_width = u32::from(before.pixels.0);
                                        media_state.requested_height = u32::from(before.pixels.1);
                                        tracing::warn!(?before, ?clamped, "Apple answered with a smaller desktop; putting the previous one back");
                                        session
                                            .send_body(&display_config(request_for(before), cap))
                                            .await?;
                                        emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
                                            "The Mac offered a smaller desktop than the stream size asked for. Putting the previous desktop back.".into(),
                                        ))).await.ok();
                                    }
                                } else if let Some((sent, confirmed)) = clamped
                                    .filter(|(sent, confirmed)| answer_is_notable(*sent, *confirmed))
                                {
                                    emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(
                                        format!(
                                            "The Mac reported {}x{} pixels / {}x{} points; requested {}x{} pixels / {}x{} points. This is a layout acknowledgement, not decoded output.",
                                            confirmed.pixels.0, confirmed.pixels.1, confirmed.points.0, confirmed.points.1,
                                            sent.pixels.0, sent.pixels.1, sent.points.0, sent.points.1,
                                        ),
                                    ))).await.ok();
                                }
                                if !round.in_flight {
                                    media_state.requested_width = 0;
                                    media_state.requested_height = 0;
                                }
                            }
                        }
                    } else if let Some(sent_at) = round.sent_at {
                        if sent_at.elapsed() > RESIZE_TIMEOUT {
                            // The Mac did not answer in time. Say so, and
                            // leave the session where it was rather than
                            // waiting for ever. A restoration that timed out
                            // is not a restoration.
                            let was_restoring = round.restoring;
                            round.in_flight = false;
                            round.sent_at = None;
                            round.requested = None;
                            round.restoring = false;
                            media_state.requested_width = 0;
                            media_state.requested_height = 0;
                            tracing::warn!(restoring = was_restoring, "Apple resize round timed out");
                            let message = if was_restoring {
                                "The Mac did not confirm the previous desktop size. Its current size is unverified."
                            } else {
                                "The stream-size request timed out. Its effective size has not been verified; check the decoded picture dimensions."
                            };
                            emit(events, SessionEvent::Protocol(remote_core::ProtocolEvent::AppleNotice(message.into()))).await.ok();
                        }
                    }
                }
            }
        }
    }
    // Let go of anything that is held before the session goes away. A key
    // that was never released stays down on the remote machine, and the
    // person in front of it has no way to know why.
    release_all(&mut session, &mut held).await.ok();
    // The display worker restores the physical panel if this connection
    // changed it. Dropping the channel tells it to finish; waiting for it
    // means the restore actually happens before the session is gone.
    drop(display_tx);
    let _ = tokio::time::timeout(Duration::from_secs(25), display_task).await;
    video_task.abort();
    picture_task.abort();
    if worker_failed {
        // The control connection was fine; the pipeline that turns it into a
        // picture was not. Reporting this as a clean end made the supervisor
        // stop for ever, which is a connected session with an empty pane.
        return Err(SessionError::new("an Apple media worker stopped"));
    }
    let _ = fail(events, "disconnected").await;
    Ok(())
}

struct Live {
    tcp: TcpStream,
    layer: RecordLayer,
    /// The picture size in pixels. This is what the decoder works in.
    width: u16,
    height: u16,
    /// The size of the desktop in points. On a retina display this is half
    /// the pixel size, and it is the size the person arranged their
    /// windows at, so a quality change must not change it.
    logical_width: u16,
    logical_height: u16,
    srtp: Option<SrtpContext>,
    /// Encrypts the RTCP feedback we send back to the Mac.
    feedback: Option<SrtcpEncryptor>,
    /// Our own SSRC, as the sender of that feedback.
    feedback_ssrc: u32,
    udp: Option<UdpSocket>,
    ctrl: Option<UdpSocket>,
    incoming: Vec<u8>,
}

impl Live {
    async fn send_body(&mut self, body: &[u8]) -> Result<(), SessionError> {
        let packet = self.layer.seal(body);
        self.tcp
            .write_all(&packet)
            .await
            .map_err(|e| SessionError::new(e.to_string()))
    }

    async fn read_body(&mut self) -> Result<Vec<u8>, SessionError> {
        loop {
            if self.incoming.len() >= 2 {
                let len = u16::from_be_bytes([self.incoming[0], self.incoming[1]]) as usize;
                if len == 0 || !len.is_multiple_of(16) {
                    return Err(SessionError::new("invalid Apple record length"));
                }
                if self.incoming.len() >= len + 2 {
                    let body = self
                        .layer
                        .open(&self.incoming[2..len + 2])
                        .map_err(|e| SessionError::new(e.to_string()))?;
                    self.incoming.drain(..len + 2);
                    return Ok(body);
                }
            }
            // read_buf is cancellation-safe. Mouse/key commands may win the
            // outer select at any time; partially read ciphertext must survive.
            if self.tcp.read_buf(&mut self.incoming).await? == 0 {
                return Err(SessionError::new("Apple control connection closed"));
            }
        }
    }

    async fn bind_video(&mut self, host: &str, ports: (u16, u16)) -> Result<(), SessionError> {
        // The Mac sends video from its UDP 5901 to our UDP 5901, and the
        // control stream the same way on 5900. An ephemeral port never
        // receives the picture. One outbound byte opens the firewall hole.
        let (video_port, control_port) = ports;
        let video = bind_udp(video_port)?;
        let ctrl = bind_udp(control_port)?;
        // The sockets are bound before the offer goes out, so the media can
        // arrive the moment the Mac accepts it.
        if let Err(error) = video.send_to(&[0], format!("{host}:{video_port}")).await {
            tracing::warn!(%error, "the first hole punch to the Mac did not get through");
        }
        if let Err(error) = ctrl.send_to(&[0], format!("{host}:{control_port}")).await {
            tracing::warn!(%error, "the first control hole punch to the Mac did not get through");
        }
        self.udp = Some(video);
        self.ctrl = Some(ctrl);
        Ok(())
    }
}

/// How much the socket is asked to hold, in bytes.
///
/// A picture is a burst of packets, and the decoder may be a moment behind
/// the wire. A small buffer overflows in exactly that moment, and an
/// overflow loses packets, and a lost packet corrupts the picture that
/// follows it. This is a request, not a promise: the kernel may cap it.
const RECEIVE_BUFFER: usize = 4 * 1024 * 1024;

fn bind_udp(port: u16) -> Result<UdpSocket, SessionError> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", port)).map_err(|e| {
        SessionError::new(format!(
            "UDP port {port} is not available ({e}). Another Apple session is probably using it: the Mac sends its video to this exact port, so two sessions to one Mac cannot share it."
        ))
    })?;
    // Ask for a big receive buffer, and say what we actually got.
    let reference = socket2::SockRef::from(&sock);
    if let Err(error) = reference.set_recv_buffer_size(RECEIVE_BUFFER) {
        tracing::warn!(%error, "the receive buffer could not be enlarged");
    }
    match reference.recv_buffer_size() {
        Ok(size) if size < RECEIVE_BUFFER => {
            tracing::info!(
                size,
                wanted = RECEIVE_BUFFER,
                "the receive buffer is smaller than asked for"
            );
        }
        Ok(size) => tracing::debug!(size, "receive buffer ready"),
        Err(error) => tracing::warn!(%error, "the receive buffer size could not be read"),
    }
    sock.set_nonblocking(true)
        .map_err(|e| SessionError::new(e.to_string()))?;
    UdpSocket::from_std(sock).map_err(|e| SessionError::new(e.to_string()))
}

fn viewer_info() -> Vec<u8> {
    // type, pad, size (bytes after the size field), version, app id,
    // app version 6.1.0, OS version 15.3.0, then the 32-byte capability mask.
    let mut mask = [0u8; 32];
    mask[0] = 0xb0;
    mask[2] = 0x0c;
    mask[3] = 0x03;
    mask[4] = 0x90;
    mask[10] = 0x40;
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x21, 0x00]);
    msg.extend_from_slice(&0x3eu16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    for n in [2u32, 6, 1, 0, 15, 3, 0] {
        msg.extend_from_slice(&n.to_be_bytes());
    }
    msg.extend_from_slice(&mask);
    msg
}

/// The desktop size a request asks for, and the picture size it asks for.
///
/// The two are separate because a Mac display has two resolutions: the
/// desktop in points, which is what a person sees as "how big things are",
/// and the backing store in pixels, which is how sharp they are. Both are
/// carried exactly. Deriving the pixels back from a rounded ratio is how a
/// request for 1800x1170 was serialized as an 1800x1169 mode, and then
/// reported back as a failure when the Mac did what was on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DisplayRequest {
    points: (u16, u16),
    pixels: (u16, u16),
}

/// The request a geometry means: its desktop size, and its picture size.
fn request_for(geometry: DisplayGeometry) -> DisplayRequest {
    DisplayRequest {
        points: geometry.points,
        pixels: geometry.pixels,
    }
}

/// The point sizes a Mac display offers, from the native mode table.
///
/// The daemon expects a mode list that looks like a display's: several
/// different sizes, not the same size repeated with shrinking pixels. A
/// table that does not look like one is answered with the server's own
/// fallback. The first template is the size being asked for, which the
/// request itself fills in; the rest are the alternate desktops the same
/// display offers, scaled to it.
const NATIVE_MODES: [(u32, u32); 5] = [
    (1920, 1080),
    (1440, 900),
    (1312, 848),
    (1280, 800),
    (1152, 720),
];

/// The smallest cap that is advertised, matching the reference client.
///
/// `max_width`/`max_height` are the bound the daemon caps the display with,
/// and a request outside it is answered with a fallback rather than being
/// clamped. Advertising the *current* desktop as the bound is what made the
/// answer depend on the state the previous session left behind: a session
/// that started small could never ask for anything larger.
const MAX_BACKING: (u32, u32) = (3840, 2160);

/// `0x1d` SetDisplayConfiguration.
///
/// The message is the same at connect time and for a mid-session resize; the
/// server answers a steady-state one with `0x451` and restarts the encoder,
/// which is why a re-offer follows it.
///
/// Shape, per the protocol notes and the reference client that interoperates
/// with the daemon:
///
/// * `display_flags = 0x01` (dynamic resolution) and `display_type = 4`, or
///   the message is not treated as a resize at all.
/// * `max_width`/`max_height` bound the display. They must cover the request
///   with room to spare, and must never be smaller than the panel.
/// * the mode table carries the desktop's point sizes and, for each, the
///   backing pixels. The first entry is the size being asked for.
fn display_config(request: DisplayRequest, cap: (u16, u16)) -> Vec<u8> {
    const MODE_COUNT: usize = NATIVE_MODES.len();
    let di_size = 0x9c + 28 * MODE_COUNT;
    // message_size counts from AFTER the size field (RFC §7.1): the front
    // matter past the 4-byte prefix is 8 bytes, then the descriptor.
    let message_size = 8 + di_size;
    let mut m = Vec::with_capacity(4 + message_size);
    m.extend_from_slice(&[0x1d, 0x00]);
    m.extend_from_slice(&(message_size as u16).to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // version
    m.extend_from_slice(&1u16.to_be_bytes()); // display_count
    m.extend_from_slice(&0u32.to_be_bytes()); // header flags
                                              // Display descriptor, offsets from its start (RFC §7.1).
    m.extend_from_slice(&(di_size as u16).to_be_bytes()); // display_info_size
    let mut region = [0u8; 120];
    region[..b"DeskVNC".len()].copy_from_slice(b"DeskVNC");
    m.extend_from_slice(&region); // display_info_region, NUL-terminated name
    m.extend_from_slice(&1u32.to_be_bytes()); // display_flags: DYNAMIC_RESOLUTION
                                              // display_type 4. The value is required for a dynamic descriptor, and
                                              // the native viewer sends the same descriptor for the physical console
                                              // display, so it is not a request for a private display.
    m.extend_from_slice(&4u32.to_be_bytes());
    m.extend_from_slice(&369.45f32.to_be_bytes()); // physical mm (native)
    m.extend_from_slice(&207.82f32.to_be_bytes());
    let max_w = u32::from(request.pixels.0)
        .max(u32::from(cap.0))
        .max(MAX_BACKING.0);
    let max_h = u32::from(request.pixels.1)
        .max(u32::from(cap.1))
        .max(MAX_BACKING.1);
    m.extend_from_slice(&max_w.to_be_bytes());
    m.extend_from_slice(&max_h.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes()); // current_mode_index
    m.extend_from_slice(&0u16.to_be_bytes()); // preferred_mode_index
    m.extend_from_slice(&7u32.to_be_bytes()); // rotations: the native sends 7
    m.extend_from_slice(&(MODE_COUNT as u16).to_be_bytes());
    // A mode list that looks like a display's, scaled to the desktop that
    // was asked for. The first entry is the request itself, byte for byte,
    // so the geometry that is logged, sent and compared is one geometry.
    //
    // The alternate desktops keep the request's pixels per point on each
    // axis, which is what leaves the person's desktop alone when only the
    // picture size changes. One averaged ratio used to serialize a request
    // for 1800x1170 pixels on an 1800x1169 point desktop as 1800x1169.
    let scale_x = f64::from(request.pixels.0) / f64::from(request.points.0.max(1));
    let scale_y = f64::from(request.pixels.1) / f64::from(request.points.1.max(1));
    let sx = f64::from(request.points.0) / 1920.0;
    let sy = f64::from(request.points.1) / 1080.0;
    for (index, (template_w, template_h)) in NATIVE_MODES.into_iter().enumerate() {
        let (points_w, points_h, backing_w, backing_h) = if index == 0 {
            (
                u32::from(request.points.0),
                u32::from(request.points.1),
                u32::from(request.pixels.0),
                u32::from(request.pixels.1),
            )
        } else {
            let points_w = (f64::from(template_w) * sx).round().max(2.0) as u32;
            let points_h = (f64::from(template_h) * sy).round().max(2.0) as u32;
            (
                points_w,
                points_h,
                even_u32((f64::from(points_w) * scale_x).round() as u32),
                even_u32((f64::from(points_h) * scale_y).round() as u32),
            )
        };
        m.extend_from_slice(&backing_w.to_be_bytes()); // pixel width
        m.extend_from_slice(&backing_h.to_be_bytes()); // pixel height
        m.extend_from_slice(&points_w.to_be_bytes()); // scaled width (points)
        m.extend_from_slice(&points_h.to_be_bytes()); // scaled height (points)
        m.extend_from_slice(&60f64.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes()); // mode flags
    }
    m
}

/// H.264 4:2:0 chroma wants an even size, and an odd one has to be cropped.
fn even_u32(value: u32) -> u32 {
    (value + 1) & !1
}

fn set_encodings() -> Vec<u8> {
    // Signed encoding ids. 1103 (0x44f) is the rekey; the rest are the
    // high-performance cursor, layout and media pseudo-encodings.
    let enc: [i32; 13] = [
        1010, 1011, 1002, 6, 16, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110,
    ];
    let mut m = vec![0x02, 0x00];
    m.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    for e in enc {
        m.extend_from_slice(&e.to_be_bytes());
    }
    m
}

/// AutoFrameBufferUpdate (0x09): a 16-byte fixed record (RFC §8.11). Arms
/// the server’s framebuffer/cursor sender; re-sent on every `0x451` (R-A16b).
fn auto_framebuffer(width: u16, height: u16) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = 0x09;
    m[3] = 0x01;
    m[4..8].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    m[12..14].copy_from_slice(&width.to_be_bytes());
    m[14..16].copy_from_slice(&height.to_be_bytes());
    m
}

/// One rectangle of a framebuffer update.
struct WireRect<'a> {
    encoding: i32,
    payload: &'a [u8],
}

/// The rectangles of a framebuffer update, as far as they can be walked.
///
/// A rectangle's payload has no length of its own: the encoding says how
/// long it is. The two encodings this session cares about both say so, and
/// anything else stops the walk, because guessing would mean guessing
/// where the next rectangle starts.
fn rectangles(body: &[u8]) -> Vec<WireRect<'_>> {
    let mut out = Vec::new();
    if body.first() != Some(&0) || body.len() < 4 {
        return out;
    }
    let count = u16::from_be_bytes([body[2], body[3]]) as usize;
    let mut p = 4;
    for _ in 0..count {
        if p + 12 > body.len() {
            break;
        }
        let Ok(raw) = <[u8; 4]>::try_from(&body[p + 8..p + 12]) else {
            break;
        };
        let encoding = i32::from_be_bytes(raw);
        p += 12;
        let payload = match encoding {
            // The rekey carries a fixed 36 byte body.
            0x44f => match body.get(p..p + 36) {
                Some(slice) => slice,
                None => break,
            },
            // The layout carries its own length. A message that is
            // shorter than it says is still worth reading: the fields that
            // matter are at the front.
            0x451 => {
                let Some(header) = body.get(p..p + 2) else {
                    break;
                };
                let len = u16::from_be_bytes([header[0], header[1]]) as usize;
                let end = (p + len).min(body.len());
                &body[p..end]
            }
            _ => break,
        };
        out.push(WireRect { encoding, payload });
        p += match encoding {
            0x44f => 36,
            _ => u16::from_be_bytes([body[p], body[p + 1]]) as usize,
        };
    }
    out
}

/// Extract `(scaled, backing)` geometry from an `AppleDisplayLayout` (`0x451`)
/// rectangle inside a decrypted control record (RFC §8.4). The layout is
/// authoritative: the server may answer a resize with a smaller fallback.
///
/// The layout is looked for in every rectangle, not only the first: a
/// message that carries something else first is still a message that
/// carries the layout.
fn find_display_layout(body: &[u8]) -> Option<((u16, u16), (u16, u16))> {
    for rect in rectangles(body) {
        if rect.encoding != 0x451 {
            continue;
        }
        let payload = rect.payload;
        if payload.len() < 12 {
            continue;
        }
        let ver = u16::from_be_bytes([payload[2], payload[3]]);
        if ver == 0 {
            continue;
        }
        let sw = u16::from_be_bytes([payload[4], payload[5]]);
        let sh = u16::from_be_bytes([payload[6], payload[7]]);
        let bw = u16::from_be_bytes([payload[8], payload[9]]);
        let bh = u16::from_be_bytes([payload[10], payload[11]]);
        if bw == 0 || bh == 0 {
            continue;
        }
        return Some(((sw, sh), (bw, bh)));
    }
    None
}

fn framebuffer_request(width: u16, height: u16) -> Vec<u8> {
    let mut m = vec![0x03, 0];
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&width.to_be_bytes());
    m.extend_from_slice(&height.to_be_bytes());
    m
}

/// How long one step of the handshake may take.
///
/// The handshake is a short conversation. A Mac that has gone away, or a
/// network that has stopped carrying, would otherwise leave the session
/// waiting for ever, with the pane showing nothing and no way to tell
/// that it is stuck.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Read one step of the handshake, with a deadline.
async fn read_handshake(tcp: &mut TcpStream, n: usize) -> Result<Vec<u8>, SessionError> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, read_exact(tcp, n))
        .await
        .map_err(|_| SessionError::new("the Mac stopped answering during the sign-in"))?
}

async fn read_exact(tcp: &mut TcpStream, n: usize) -> Result<Vec<u8>, SessionError> {
    let mut buf = vec![0u8; n];
    tcp.read_exact(&mut buf)
        .await
        .map_err(|e| SessionError::new(e.to_string()))?;
    Ok(buf)
}

async fn read_counted(tcp: &mut TcpStream) -> Result<Vec<u8>, SessionError> {
    let lenb = read_exact(tcp, 4).await?;
    let n = u32::from_be_bytes(lenb.clone().try_into().unwrap()) as usize;
    if n > 1_048_576 {
        return Err(SessionError::new(
            "a handshake record was implausibly large",
        ));
    }
    let mut rest = read_exact(tcp, n).await?;
    let mut all = lenb;
    all.append(&mut rest);
    Ok(all)
}

async fn read_rsa_key(tcp: &mut TcpStream) -> Result<Vec<u8>, SessionError> {
    let head = read_exact(tcp, 4).await?;
    let n = u32::from_be_bytes(head.try_into().unwrap()) as usize;
    if !(10..=8192).contains(&n) {
        return Err(SessionError::new(
            "the server's public key framing was rejected",
        ));
    }
    let rest = read_exact(tcp, n).await?;
    // 2-byte prefix, then u32 big-endian DER length, then the key.
    if rest.len() < 6 {
        return Err(SessionError::new("the server's public key was truncated"));
    }
    let der_len = u32::from_be_bytes(rest[2..6].try_into().unwrap()) as usize;
    rest.get(6..6 + der_len)
        .map(|s| s.to_vec())
        .ok_or_else(|| SessionError::new("the server's public key was truncated"))
}

async fn read_server_init(tcp: &mut TcpStream) -> Result<(u16, u16), SessionError> {
    let head = read_exact(tcp, 2 + 2 + 16 + 4).await?;
    let w = u16::from_be_bytes([head[0], head[1]]);
    let h = u16::from_be_bytes([head[2], head[3]]);
    let name = u32::from_be_bytes(head[20..24].try_into().unwrap()) as usize;
    if name > 4096 {
        return Err(SessionError::new("the server name was implausibly long"));
    }
    let _ = read_exact(tcp, name).await?;
    Ok((w, h))
}

async fn read_clear_message(tcp: &mut TcpStream) -> Result<Vec<u8>, SessionError> {
    let kind = read_exact(tcp, 1).await?[0];
    if kind != 0 {
        // Not a framebuffer update. Read nothing more; the caller loops and
        // this byte is lost, which is only safe because the rekey is a
        // framebuffer update. Surface it so a surprise message fails closed.
        return Err(SessionError::new(format!(
            "unexpected cleartext message {kind:#x}"
        )));
    }
    let header = read_exact(tcp, 3).await?;
    let n = u16::from_be_bytes([header[1], header[2]]) as usize;
    let mut msg = vec![kind];
    msg.extend(header);
    for _ in 0..n {
        let rect = read_exact(tcp, 12).await?;
        let enc = i32::from_be_bytes(rect[8..12].try_into().unwrap());
        msg.extend(&rect);
        let payload = if enc == 0x44f {
            read_exact(tcp, 36).await?
        } else {
            return Err(SessionError::new(format!(
                "unsupported cleartext encoding {enc:#x}"
            )));
        };
        msg.extend(payload);
    }
    Ok(msg)
}

fn find_rekey(msg: &[u8], wrap: &[u8; 16]) -> Option<([u8; 16], [u8; 16])> {
    // Only a framebuffer rectangle whose encoding is 1103 (0x44f). Any other
    // message happens to be at least 36 bytes, and treating its tail as a
    // rekey resets the cipher and the next record fails its integrity check.
    for rect in rectangles(msg) {
        if rect.encoding != 0x44f {
            continue;
        }
        let body = rect.payload;
        if body.len() < 36 {
            continue;
        }
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        key.copy_from_slice(&body[4..20]);
        iv.copy_from_slice(&body[20..36]);
        return Some(record::unwrap_rekey(wrap, &key, &iv));
    }
    None
}

#[derive(Debug)]
pub struct SessionError {
    message: String,
}

impl SessionError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SessionError {}

impl From<auth::AuthError> for SessionError {
    fn from(value: auth::AuthError) -> Self {
        Self::new(value.to_string())
    }
}

impl From<std::io::Error> for SessionError {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srtp::SrtpEncryptor;

    #[tokio::test]
    async fn picture_consumer_releases_buffer_lock_while_waiting_for_wakeup() {
        let buffer = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::pictures::PictureBuffer::default(),
        ));
        let (wake_tx, mut wake_rx) = mpsc::channel(1);
        let consumer_buffer = buffer.clone();
        let consumer = tokio::spawn(async move {
            loop {
                if let Some(unit) = next_picture(&consumer_buffer, &mut wake_rx).await {
                    break unit;
                }
            }
        });
        tokio::task::yield_now().await;

        // A producer must be able to acquire the lock while the consumer is
        // asleep, queue a frame, and wake it.
        {
            let mut queued = tokio::time::timeout(Duration::from_millis(100), buffer.lock())
                .await
                .expect("the sleeping consumer held the buffer lock");
            queued.push(crate::h264::AccessUnit {
                annex_b: vec![0, 0, 0, 1, 0x65],
                keyframe: true,
                reset: true,
            });
        }
        wake_tx.send(()).await.expect("the consumer is waiting");
        assert!(consumer.await.unwrap().keyframe);
    }

    #[test]
    fn a_whole_media_stream_survives_the_trip_from_the_wire() {
        // A fake Mac: an encoder that sends a key picture, then deltas, all
        // through the real SRTP protection and the real assembler. The
        // pictures that come out have to be right, because everything
        // downstream believes them.
        let blob = [42u8; 46];
        let mut sender = SrtpEncryptor::from_blob(&blob).expect("the keys");
        let mut receiver = SrtpContext::from_blob(&blob).expect("the keys");
        let mut depay = Depacketizer::default();

        // A key picture: an IDR, split over three packets, with the
        // parameter sets in front of it.
        let wire: Vec<(u16, u32, bool, Vec<u8>)> = vec![
            (1, 100, false, vec![0x67, 0x64, 0x00, 0x1f]),
            (2, 100, false, vec![0x68, 0xee]),
            (3, 100, false, vec![0x7c, 0x85, 0xaa, 0xbb]),
            (4, 100, true, vec![0x7c, 0x45, 0xcc]),
            // Then a delta picture.
            (5, 200, true, vec![0x41, 0x9a]),
        ];

        let mut pictures = Vec::new();
        for (seq, timestamp, marker, payload) in wire {
            // The second byte of an RTP header carries the marker bit and
            // the payload type.
            let mut packet = vec![0x80, 123 | if marker { 0x80 } else { 0 }];
            packet.extend_from_slice(&seq.to_be_bytes());
            packet.extend_from_slice(&timestamp.to_be_bytes());
            packet.extend_from_slice(&7u32.to_be_bytes());
            packet.extend_from_slice(&payload);
            let protected = sender.protect(&packet).expect("the packet was protected");
            let rtp = receiver
                .unprotect(&protected)
                .expect("the packet authenticated");
            assert_eq!(rtp.marker, marker, "the marker did not survive the wire");
            for unit in depay.push(rtp.seq, rtp.timestamp, rtp.marker, &rtp.payload) {
                pictures.push(unit);
            }
        }
        assert_eq!(pictures.len(), 2, "the stream did not produce two pictures");
        // The first is an IDR: it can start a decoder and it resets the
        // references.
        assert!(pictures[0].keyframe);
        assert!(pictures[0].reset);
        // The second is a delta: neither.
        assert!(!pictures[1].keyframe);
        assert!(!pictures[1].reset);
        // And the key picture carries the parameter sets with it, because a
        // decoder that has just been built needs them.
        assert!(pictures[0]
            .annex_b
            .windows(4)
            .any(|w| w == [0x67, 0x64, 0x00, 0x1f]));
        assert!(pictures[0].annex_b.windows(2).any(|w| w == [0x68, 0xee]));
    }

    #[test]
    fn a_window_size_becomes_a_desktop_size_in_points() {
        // The Mac's panel is 3600x2338 pixels and 1800x1169 points, so it
        // is twice each. A window of 1600x900 pixels is therefore a desktop
        // of 800x450 points.
        assert_eq!(
            desktop_points((1600, 900), (3600, 2338), (1800, 1169)),
            (800, 450)
        );
        // A panel that is not scaled needs no conversion.
        assert_eq!(
            desktop_points((1600, 900), (1920, 1080), (1920, 1080)),
            (1600, 900)
        );
        // With nothing known about the panel, the size is taken as it is.
        assert_eq!(desktop_points((1600, 900), (0, 0), (0, 0)), (1600, 900));
    }

    #[tokio::test]
    async fn a_packet_from_somewhere_else_is_not_read_as_video() {
        // The Mac's own packets are read. A stray datagram on the port is
        // not part of the session, and reading one as video would put
        // rubbish into the decoder.
        let peer = Peer {
            addresses: vec!["10.0.0.5".parse().unwrap()],
            port: 5901,
        };
        assert!(peer.matches(&"10.0.0.5:5901".parse().unwrap()));
        assert!(!peer.matches(&"10.0.0.6:5901".parse().unwrap()));
        // The port is reported rather than enforced: a firewall in between
        // may change it, and dropping the media over that would be worse.
        assert!(peer.matches(&"10.0.0.5:40000".parse().unwrap()));
        // With nothing to check against, everything is read.
        let unknown = Peer {
            addresses: Vec::new(),
            port: 5901,
        };
        assert!(unknown.matches(&"192.168.1.2:1234".parse().unwrap()));
    }

    #[tokio::test]
    async fn the_retry_wait_ends_when_the_session_is_told_to_stop() {
        let (tx, mut rx) = mpsc::channel(4);
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut credentials = ("user".to_string(), "pass".to_string());
        tx.send(ClientCommand::Disconnect).await.unwrap();
        assert!(wait_for_retry(&mut rx, &cancel, Duration::from_secs(5), &mut credentials).await);
    }

    #[tokio::test]
    async fn the_retry_wait_ends_at_once_when_a_reconnect_is_asked_for() {
        let (tx, mut rx) = mpsc::channel(4);
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut credentials = ("user".to_string(), "pass".to_string());
        tx.send(ClientCommand::ReconnectNow).await.unwrap();
        let start = Instant::now();
        assert!(!wait_for_retry(&mut rx, &cancel, Duration::from_secs(30), &mut credentials).await);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "the retry waited anyway"
        );
    }

    #[tokio::test]
    async fn the_retry_wait_takes_a_new_password_for_the_next_attempt() {
        let (tx, mut rx) = mpsc::channel(4);
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut credentials = ("user".to_string(), "old".to_string());
        tx.send(ClientCommand::ProvideCredentials {
            username: Some("other".to_string()),
            password: "new".to_string(),
            save: false,
        })
        .await
        .unwrap();
        tx.send(ClientCommand::ReconnectNow).await.unwrap();
        assert!(!wait_for_retry(&mut rx, &cancel, Duration::from_secs(30), &mut credentials).await);
        assert_eq!(credentials, ("other".to_string(), "new".to_string()));
    }

    #[test]
    fn the_display_configuration_is_the_first_record() {
        // The native client's first two records are the display
        // configuration and then the encodings. The display configuration
        // says which display the session is about: without it the Mac
        // chooses, and what it may choose is a new session with a login
        // screen rather than the console the person is already using.
        let geometry = remote_core::options::AppleGeometry {
            pixel_width: 3600,
            pixel_height: 2338,
            point_width: 1800,
            point_height: 1169,
        };
        let records = first_records(Some(geometry));
        assert_eq!(records.len(), 2);
        assert_eq!(records[0][0], 0x1d, "the display configuration comes first");
        assert_eq!(records[1][0], 0x02, "the encodings come second");
        // The desktop keeps its size: the picture changes, the points do
        // not.
        let d = 12;
        let mode = d + 0x9c;
        assert_eq!(
            u32::from_be_bytes(records[0][mode..mode + 4].try_into().unwrap()),
            3600
        );
        assert_eq!(
            u32::from_be_bytes(records[0][mode + 4..mode + 8].try_into().unwrap()),
            2338
        );
        assert_eq!(
            u32::from_be_bytes(records[0][mode + 8..mode + 12].try_into().unwrap()),
            1800
        );
        assert_eq!(
            u32::from_be_bytes(records[0][mode + 12..mode + 16].try_into().unwrap()),
            1169
        );
        // The mode list is a display's, so its entries offer different
        // desktop sizes; a table of one size repeated is answered with the
        // daemon's own fallback. The first entry is the desktop the person
        // has now, in points, at the panel's pixels per point.
        let mut points = Vec::new();
        for entry in 0..5 {
            let at = mode + entry * 28;
            points.push((
                u32::from_be_bytes(records[0][at + 8..at + 12].try_into().unwrap()),
                u32::from_be_bytes(records[0][at + 12..at + 16].try_into().unwrap()),
            ));
        }
        assert_eq!(points[0], (1800, 1169));
        assert!(
            points.windows(2).any(|w| w[0] != w[1]),
            "the mode list offers one desktop size five times: {points:?}"
        );
    }

    #[test]
    fn a_window_sized_desktop_is_not_reapplied() {
        // 1600x1200 pixels and 800x600 points is the local viewer window,
        // not the Mac panel. Sending it again shrinks the desktop and makes
        // every connection look zoomed to twice the size.
        let geometry = remote_core::options::AppleGeometry {
            pixel_width: 1600,
            pixel_height: 1200,
            point_width: 800,
            point_height: 600,
        };
        let records = first_records(Some(geometry));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0][0], 0x02);
    }

    #[test]
    fn without_a_known_geometry_the_encodings_are_still_sent() {
        // A first ever connection has no geometry to send. The encodings
        // still go out, so the session works.
        let records = first_records(None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0][0], 0x02);
    }

    #[test]
    fn an_idle_desktop_is_not_a_stall() {
        // This stream is damage driven: a screen that has not changed sends
        // nothing. Asking for a fresh picture then costs the Mac a full
        // frame every two seconds for nothing.
        let long_ago = Duration::from_secs(30);
        assert!(!should_ask_for_stalled_picture(false, true, long_ago));
        // Packets arriving but no picture completing is a real stall.
        assert!(should_ask_for_stalled_picture(true, true, long_ago));
        // A stream that is completing pictures is not stalled.
        assert!(!should_ask_for_stalled_picture(true, false, long_ago));
        // And a request that has just gone out is not repeated.
        assert!(!should_ask_for_stalled_picture(
            true,
            true,
            Duration::from_millis(200)
        ));
    }

    #[test]
    fn repeated_failures_back_off_and_a_stable_session_starts_over() {
        // The old loop reset the count after every wait, so ten transient
        // failures were ten waits of half a second each.
        let mut attempt = 0;
        let mut waits = Vec::new();
        for _ in 0..7 {
            let (next, wait) = next_retry(attempt, Duration::from_secs(1));
            assert_eq!(next, attempt + 1);
            waits.push(wait.as_millis() as u64);
            attempt = next;
        }
        assert_eq!(waits, vec![500, 1_000, 2_000, 4_000, 8_000, 8_000, 8_000]);
        // An attempt that stayed up is not the seventh failure of an old
        // run: the next one waits as a first attempt again.
        assert_eq!(
            next_retry(6, Duration::from_secs(61)),
            (1, Duration::from_millis(500))
        );
        // Just short of that, the backoff continues.
        assert_eq!(
            next_retry(6, Duration::from_secs(59)),
            (7, Duration::from_millis(8_000))
        );
    }

    #[test]
    fn a_client_that_is_behind_is_not_answered_with_a_flood() {
        // The storm: a client that cannot keep up drops a picture, asks
        // the Mac for a fresh one, gets a full picture it cannot keep up
        // with either, and the loop runs twice a second for ever. The
        // control channel collapses under it and the session stops.
        //
        // One request a second, and only while the chain is broken, is the
        // answer: the Mac's next independent picture repairs the chain.
        assert!(!should_ask_for_backlog_picture(
            false,
            Duration::from_secs(10)
        ));
        // The chain is broken, but a request went out a moment ago.
        assert!(!should_ask_for_backlog_picture(
            true,
            Duration::from_millis(100)
        ));
        // The chain has been broken for longer than the interval.
        assert!(should_ask_for_backlog_picture(true, Duration::from_secs(1)));
        assert!(should_ask_for_backlog_picture(
            true,
            Duration::from_secs(30)
        ));
    }

    #[tokio::test]
    async fn a_lost_picture_is_asked_for_again() {
        // The recovery path: a request for a fresh picture goes out on the
        // control socket, protected with the feedback keys, and starts with
        // a receiver report so the peer accepts it.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = format!("{}", socket.local_addr().unwrap());
        let encryptor = SrtcpEncryptor::from_blob(&[3; 46]).unwrap();
        let mut clock = FeedbackClock::default();
        let requests = std::sync::atomic::AtomicU64::new(0);
        request_keyframe(
            &mut Some(encryptor),
            0x1111_2222,
            0x3333_4444,
            Some(&socket),
            &dest,
            &mut clock,
            &requests,
        )
        .await;
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the request that went out is counted"
        );
        let mut buf = [0u8; 2048];
        let (n, _) = socket.recv_from(&mut buf).await.unwrap();
        assert!(n > 24);
        // The compound packet starts with the receiver report, in the clear.
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 201);
        assert_eq!(&buf[4..8], &0x1111_2222u32.to_be_bytes());
        // Everything after the receiver report is encrypted, so the
        // request itself is not readable on the wire.
        assert_ne!(&buf[8..12], &[0x84, 206, 0, 4]);
        assert_ne!(&buf[20..24], &0x3333_4444u32.to_be_bytes());
    }

    #[tokio::test]
    async fn a_request_is_not_sent_twice_in_a_row() {
        // A burst of loss must not turn into a burst of requests.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = format!("{}", socket.local_addr().unwrap());
        let encryptor = SrtcpEncryptor::from_blob(&[3; 46]).unwrap();
        let mut clock = FeedbackClock::default();
        let requests = std::sync::atomic::AtomicU64::new(0);
        request_keyframe(
            &mut Some(encryptor),
            1,
            2,
            Some(&socket),
            &dest,
            &mut clock,
            &requests,
        )
        .await;
        let mut buf = [0u8; 2048];
        socket.recv_from(&mut buf).await.unwrap();
        // The second request is held back.
        let encryptor = SrtcpEncryptor::from_blob(&[3; 46]).unwrap();
        let requests = std::sync::atomic::AtomicU64::new(0);
        request_keyframe(
            &mut Some(encryptor),
            1,
            2,
            Some(&socket),
            &dest,
            &mut clock,
            &requests,
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf))
                .await
                .is_err(),
            "a second request was sent straight after the first"
        );
    }

    #[tokio::test]
    async fn releasing_everything_held_says_so_on_the_wire() {
        // A key or a button that was pressed and never released stays down on
        // the remote machine. The only way to release it is to say so.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let mut live = Live {
            tcp,
            layer: RecordLayer::new([1; 16], [2; 16]),
            width: 1,
            height: 1,
            logical_width: 1,
            logical_height: 1,
            srtp: None,
            feedback: None,
            feedback_ssrc: 0,
            udp: None,
            ctrl: None,
            incoming: Vec::with_capacity(8192),
        };
        let mut held = Held::default();
        held.keys.insert(0x61);
        held.keys.insert(0x62);
        held.pointer = Some((10, 20, 1));
        release_all(&mut live, &mut held).await.unwrap();
        assert!(held.keys.is_empty());
        assert!(held.pointer.is_none());

        // The server sees a pointer event with no buttons and two key ups.
        let mut receiver = RecordLayer::new([1; 16], [2; 16]);
        let mut bodies = Vec::new();
        for _ in 0..3 {
            let mut header = [0u8; 2];
            server.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes(header) as usize;
            let mut packet = vec![0u8; len];
            server.read_exact(&mut packet).await.unwrap();
            bodies.push(receiver.open(&packet).unwrap());
        }
        assert_eq!(bodies[0][0], 0x10, "the pointer was not released");
        assert_eq!(bodies[1][0], 4, "a key was not released");
        assert_eq!(bodies[1][1], 0, "the key release was a key press");
        assert_eq!(bodies[2][0], 4);
        assert_eq!(bodies[2][1], 0);
    }

    #[tokio::test]
    async fn interrupted_record_read_keeps_partial_ciphertext() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let mut live = Live {
            tcp,
            layer: RecordLayer::new([1; 16], [2; 16]),
            width: 1,
            height: 1,
            logical_width: 1,
            logical_height: 1,
            srtp: None,
            feedback: None,
            feedback_ssrc: 0,
            udp: None,
            ctrl: None,
            incoming: Vec::with_capacity(8192),
        };
        let mut sender = RecordLayer::new([1; 16], [2; 16]);
        let packet = sender.seal(b"control reply");
        server.write_all(&packet[..5]).await.unwrap();
        // Simulate a click winning the outer select while a reply is partial.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), live.read_body())
                .await
                .is_err()
        );
        assert_eq!(live.incoming.len(), 5);
        server.write_all(&packet[5..]).await.unwrap();
        assert_eq!(live.read_body().await.unwrap(), b"control reply");
        assert!(live.incoming.is_empty());
    }

    #[test]
    fn display_metadata_does_not_reset_the_record_cipher() {
        let mut layout = vec![0; 94];
        layout[2..4].copy_from_slice(&1u16.to_be_bytes());
        layout[12..16].copy_from_slice(&1105i32.to_be_bytes());
        assert!(find_rekey(&layout, &[0; 16]).is_none());
    }

    #[test]
    fn the_display_config_asks_for_a_desktop_and_its_pixels_per_point() {
        // 1800x1169 points at 2x: the panel's own shape.
        let m = display_config(
            DisplayRequest {
                points: (1800, 1169),
                pixels: (3600, 2338),
            },
            (3600, 2338),
        );
        assert_eq!(m[0], 0x1d);
        let message_size = u16::from_be_bytes([m[2], m[3]]) as usize;
        assert_eq!(message_size, m.len() - 4);
        assert_eq!(u16::from_be_bytes([m[4], m[5]]), 1); // version
        assert_eq!(u16::from_be_bytes([m[6], m[7]]), 1); // display_count
        let d = 12;
        let di_size = u16::from_be_bytes([m[d], m[d + 1]]) as usize;
        assert_eq!(di_size, 0x9c + 5 * 28);
        assert_eq!(
            u32::from_be_bytes(m[d + 0x7a..d + 0x7e].try_into().unwrap()),
            1
        ); // dynamic flag, or the daemon does not treat it as a resize
        assert_eq!(
            u32::from_be_bytes(m[d + 0x7e..d + 0x82].try_into().unwrap()),
            4
        ); // display_type
           // The cap must cover the request with room to spare. Advertising the
           // current desktop here is what made the answer depend on the state
           // the previous session left behind.
        let max_w = u32::from_be_bytes(m[d + 0x8a..d + 0x8e].try_into().unwrap());
        let max_h = u32::from_be_bytes(m[d + 0x8e..d + 0x92].try_into().unwrap());
        assert!(
            max_w >= 3600 && max_h >= 2338,
            "the cap excludes the request"
        );
        assert!(
            max_w >= 3840 && max_h >= 2160,
            "the reference cap is not met"
        );
        assert_eq!(
            u16::from_be_bytes(m[d + 0x9a..d + 0x9c].try_into().unwrap()),
            5
        );
        let mode = d + 0x9c;
        // The first entry is the desktop that was asked for, at the ratio
        // that was asked for.
        assert_eq!(
            u32::from_be_bytes(m[mode..mode + 4].try_into().unwrap()),
            3600
        );
        assert_eq!(
            u32::from_be_bytes(m[mode + 4..mode + 8].try_into().unwrap()),
            2338
        );
        assert_eq!(
            u32::from_be_bytes(m[mode + 8..mode + 12].try_into().unwrap()),
            1800
        );
        assert_eq!(
            u32::from_be_bytes(m[mode + 12..mode + 16].try_into().unwrap()),
            1169
        );
    }

    #[test]
    fn the_mode_table_looks_like_a_display_rather_than_one_size_repeated() {
        // A table of five identical point sizes with shrinking pixels is not
        // what a display offers, and the daemon answers a table that does not
        // look like one with its own fallback mode.
        let m = display_config(
            DisplayRequest {
                points: (1800, 1169),
                pixels: (3600, 2338),
            },
            (3600, 2338),
        );
        let mode = 12 + 0x9c;
        let mut points: Vec<(u32, u32)> = Vec::new();
        for entry in 0..5 {
            let at = mode + entry * 28;
            points.push((
                u32::from_be_bytes(m[at + 8..at + 12].try_into().unwrap()),
                u32::from_be_bytes(m[at + 12..at + 16].try_into().unwrap()),
            ));
        }
        assert!(
            points.windows(2).any(|w| w[0] != w[1]),
            "every mode offered the same desktop: {points:?}"
        );
        // And each entry's backing is its points times the ratio, so the
        // desktop the person sees keeps its size.
        for entry in 0..5 {
            let at = mode + entry * 28;
            let px = u32::from_be_bytes(m[at..at + 4].try_into().unwrap());
            let pts = u32::from_be_bytes(m[at + 8..at + 12].try_into().unwrap());
            assert!((px as i64 - (pts as i64 * 2)).abs() <= 2, "entry {entry}");
        }
    }

    #[test]
    fn a_quality_change_moves_the_pixels_and_leaves_the_desktop_alone() {
        // The same desktop at 1x and at 2x: the point size must be identical,
        // because a desktop with fewer points is what "zoomed in" looks like.
        let plain = display_config(
            DisplayRequest {
                points: (1800, 1169),
                pixels: (1800, 1170),
            },
            (3600, 2338),
        );
        let retina = display_config(
            DisplayRequest {
                points: (1800, 1169),
                pixels: (3600, 2338),
            },
            (3600, 2338),
        );
        let mode = 12 + 0x9c;
        for m in [&plain, &retina] {
            assert_eq!(
                u32::from_be_bytes(m[mode + 8..mode + 12].try_into().unwrap()),
                1800
            );
            assert_eq!(
                u32::from_be_bytes(m[mode + 12..mode + 16].try_into().unwrap()),
                1169
            );
        }
        assert_eq!(
            u32::from_be_bytes(plain[mode..mode + 4].try_into().unwrap()),
            1800
        );
        assert_eq!(
            u32::from_be_bytes(retina[mode..mode + 4].try_into().unwrap()),
            3600
        );
    }

    #[test]
    fn the_mode_that_is_asked_for_is_the_mode_that_is_sent() {
        // A 1800x1170 picture on an 1800x1169 point desktop used to be
        // averaged into a 1.0 ratio and serialized as 1800x1169, so the
        // request that was logged, the request on the wire and the answer
        // were three different numbers.
        let geometry = DisplayGeometry {
            pixels: (1800, 1170),
            points: (1800, 1169),
        };
        let m = display_config(request_for(geometry), (3600, 2338));
        let mode = 12 + 0x9c;
        assert_eq!(
            u32::from_be_bytes(m[mode..mode + 4].try_into().unwrap()),
            u32::from(geometry.pixels.0)
        );
        assert_eq!(
            u32::from_be_bytes(m[mode + 4..mode + 8].try_into().unwrap()),
            u32::from(geometry.pixels.1)
        );
        assert_eq!(
            u32::from_be_bytes(m[mode + 8..mode + 12].try_into().unwrap()),
            u32::from(geometry.points.0)
        );
        assert_eq!(
            u32::from_be_bytes(m[mode + 12..mode + 16].try_into().unwrap()),
            u32::from(geometry.points.1)
        );
        // The alternate desktops keep the same pixels per point on each
        // axis, so none of them asks for a different desktop.
        for entry in 1..5 {
            let at = mode + entry * 28;
            let px = f64::from(u32::from_be_bytes(m[at..at + 4].try_into().unwrap()));
            let pts = f64::from(u32::from_be_bytes(m[at + 8..at + 12].try_into().unwrap()));
            assert!(
                (px / pts - 1.0008).abs() < 0.01,
                "entry {entry}: {px}/{pts}"
            );
        }
    }

    /// A framebuffer update body carrying one rectangle.
    fn update_with(encoding: i32, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8, 0, 0, 1];
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // x, y, w, h
        body.extend_from_slice(&encoding.to_be_bytes());
        // A metadata rectangle carries its own length inside the payload, so
        // nothing is added here.
        body.extend_from_slice(payload);
        body
    }

    #[test]
    fn display_layout_yields_backing_geometry() {
        let mut body = vec![0u8, 0, 0, 1];
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // x, y, w, h
        body.extend_from_slice(&1105i32.to_be_bytes());
        body.extend_from_slice(&0x52u16.to_be_bytes()); // payload_len
        body.extend_from_slice(&5u16.to_be_bytes()); // version
        body.extend_from_slice(&1800u16.to_be_bytes()); // scaled w
        body.extend_from_slice(&1169u16.to_be_bytes()); // scaled h
        body.extend_from_slice(&3600u16.to_be_bytes()); // backing w
        body.extend_from_slice(&2338u16.to_be_bytes()); // backing h
        assert_eq!(
            find_display_layout(&body),
            Some(((1800, 1169), (3600, 2338)))
        );
        // 1105 BE is 00 00 04 51, so clobber the 0x04 byte to break the tag.
        body[12..16].copy_from_slice(&1104i32.to_be_bytes());
        assert_eq!(find_display_layout(&body), None);
    }

    #[test]
    fn viewer_info_size_matches_its_payload() {
        let msg = viewer_info();
        assert_eq!(msg[0], 0x21);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]) as usize, msg.len() - 4);
    }

    fn retina(pixels: (u16, u16)) -> DisplayGeometry {
        DisplayGeometry {
            pixels,
            points: (1800, 1169),
        }
    }

    #[test]
    fn a_smaller_desktop_is_recognised_so_it_can_be_put_back() {
        // A Mac that cannot stream the size that was asked for answers with
        // a smaller desktop. A desktop with fewer points is what "zoomed in"
        // looks like, so it is worth undoing.
        let sent = retina((3600, 2338));
        let fallback = DisplayGeometry {
            pixels: (1600, 1200),
            points: (800, 600),
        };
        assert!(desktop_shrank(Some((sent, fallback))));
        // An answer that matches is not a problem.
        assert!(!desktop_shrank(Some((sent, sent))));
        // Neither is a smaller picture on the same desktop: that is a lower
        // stream quality, which is what a quality preset asks for.
        assert!(!desktop_shrank(Some((sent, retina((1800, 1170))))));
        // Nothing to compare is not a clamp.
        assert!(!desktop_shrank(None));
    }

    #[test]
    fn a_one_pixel_rounding_is_not_worth_reporting() {
        let sent = retina((1800, 1170));
        assert!(!answer_is_notable(sent, retina((1800, 1169))));
        // A desktop that changed is worth saying even when the picture did not.
        let smaller = DisplayGeometry {
            pixels: (1800, 1169),
            points: (900, 584),
        };
        assert!(answer_is_notable(sent, smaller));
        // So is a picture that is materially different from the request.
        assert!(answer_is_notable(sent, retina((1600, 1200))));
    }

    #[test]
    fn a_queued_round_puts_back_the_geometry_the_session_really_has() {
        // The first round was answered with a smaller picture than asked.
        // A second request must not carry the first round's rollback target:
        // the session's desktop is what the second round must be able to
        // restore.
        let original = retina((3600, 2338));
        let low = retina((1800, 1170));
        let answered = retina((1800, 1169));
        let medium = retina((2700, 1754));
        let mut round = ResizeRound::default();
        plan_resize(&mut round, low, original);
        assert_eq!(
            plan_resize(&mut round, medium, original),
            ResizeAction::Wait
        );
        round.confirmed = Some(answered);
        round.awaiting_layout = false;
        assert_eq!(finish_round(&mut round), RoundEnd::Send(medium));
        assert_eq!(round.before, Some(answered));
    }

    #[test]
    fn a_refused_round_gets_one_restoration_and_no_more() {
        // The restore is a round, not a write: it has to be acknowledged and
        // followed by a picture like any other, and it may not loop.
        let mut round = ResizeRound::default();
        let original = retina((3600, 2338));
        let low = retina((1800, 1170));
        plan_resize(&mut round, low, original);
        assert_eq!(round.restores_left, 1);
        // The answer is a smaller desktop, which is what starts a restore.
        let fallback = DisplayGeometry {
            pixels: (1600, 1200),
            points: (800, 600),
        };
        round.confirmed = Some(fallback);
        round.awaiting_layout = false;
        assert!(desktop_shrank(Some((low, fallback))));
        assert_eq!(
            finish_round(&mut round),
            RoundEnd::Done(Some((low, fallback)))
        );
        start_round(&mut round, original, fallback, true);
        assert!(round.restoring);
        assert_eq!(round.restores_left, 0);
        assert!(round.in_flight && round.awaiting_layout && round.needs_picture);
        // The restore's own answer is what ends it.
        round.confirmed = Some(original);
        round.awaiting_layout = false;
        assert_eq!(finish_round(&mut round), RoundEnd::Done(None));
        assert_eq!(round.sent, Some(original));
    }

    #[test]
    fn a_round_waits_for_the_picture_the_re_offer_promised() {
        // The layout is not the end of a round: the encoder restarts after
        // it, and the new stream is proven by a picture from that encoder.
        let mut round = ResizeRound::default();
        plan_resize(&mut round, retina((2700, 1754)), retina((3600, 2338)));
        assert!(round.needs_picture);
        round.awaiting_layout = false;
        round.confirmed = Some(retina((2700, 1754)));
        // Still in flight: no picture has arrived since the re-offer.
        assert!(round.in_flight);
    }

    #[test]
    fn a_resize_request_for_the_size_already_shown_does_nothing() {
        let mut round = ResizeRound::default();
        let current = retina((3600, 2338));
        assert_eq!(
            plan_resize(&mut round, current, current),
            ResizeAction::Nothing
        );
        assert!(!round.in_flight);
    }

    #[test]
    fn a_resize_request_starts_a_round() {
        let mut round = ResizeRound::default();
        let target = retina((2700, 1754));
        assert_eq!(
            plan_resize(&mut round, target, retina((3600, 2338))),
            ResizeAction::Send(target)
        );
        assert!(round.in_flight && round.awaiting_layout);
        assert_eq!(round.sent, Some(target));
    }

    #[test]
    fn a_request_during_a_round_keeps_both_pixels_and_points() {
        let mut round = ResizeRound::default();
        let current = retina((3600, 2338));
        plan_resize(&mut round, retina((1800, 1170)), current);
        let manual = DisplayGeometry {
            pixels: (2560, 1440),
            points: (1280, 720),
        };
        assert_eq!(plan_resize(&mut round, manual, current), ResizeAction::Wait);
        // A later layout can change the session geometry, but must not
        // replace the points carried by the queued request.
        round.confirmed = Some(retina((1800, 1170)));
        assert_eq!(finish_round(&mut round), RoundEnd::Send(manual));
        assert_eq!(round.sent, Some(manual));
        assert_eq!(
            round.confirmed, None,
            "old acknowledgement must not leak into next round"
        );
        assert!(round.awaiting_layout);
    }

    #[test]
    fn a_request_for_the_size_before_the_round_is_not_lost() {
        let mut round = ResizeRound::default();
        let current = retina((3600, 2338));
        plan_resize(&mut round, retina((1800, 1170)), current);
        assert_eq!(
            plan_resize(&mut round, current, current),
            ResizeAction::Wait
        );
        assert_eq!(finish_round(&mut round), RoundEnd::Send(current));
    }

    #[test]
    fn identical_pixels_with_changed_points_are_not_a_noop() {
        let mut round = ResizeRound::default();
        let current = DisplayGeometry {
            pixels: (2700, 1754),
            points: (1350, 877),
        };
        let target = retina(current.pixels);
        assert_eq!(
            plan_resize(&mut round, target, current),
            ResizeAction::Send(target)
        );
    }

    #[test]
    fn a_queued_quality_choice_keeps_baseline_points_even_after_a_manual_resize() {
        let mut round = ResizeRound::default();
        let current = retina((3600, 2338));
        let manual = DisplayGeometry {
            pixels: (2560, 1440),
            points: (1280, 720),
        };
        plan_resize(&mut round, manual, current);
        let balanced = retina((2700, 1754));
        assert_eq!(
            plan_resize(&mut round, balanced, current),
            ResizeAction::Wait
        );
        round.confirmed = Some(manual);
        assert_eq!(finish_round(&mut round), RoundEnd::Send(balanced));
        assert_eq!(round.sent.unwrap().points, (1800, 1169));
    }

    #[test]
    fn a_round_reports_both_pixel_and_desktop_mismatches() {
        for confirmed in [
            retina((1800, 1170)),
            DisplayGeometry {
                pixels: (2700, 1754),
                points: (1350, 877),
            },
        ] {
            let mut round = ResizeRound::default();
            let target = retina((2700, 1754));
            plan_resize(&mut round, target, retina((3600, 2338)));
            round.confirmed = Some(confirmed);
            assert_eq!(
                finish_round(&mut round),
                RoundEnd::Done(Some((target, confirmed)))
            );
            assert!(!round.in_flight);
        }
    }

    #[test]
    fn a_round_ends_quietly_when_the_server_chose_what_was_asked() {
        let mut round = ResizeRound::default();
        let target = retina((2700, 1754));
        plan_resize(&mut round, target, retina((3600, 2338)));
        round.confirmed = Some(target);
        assert_eq!(finish_round(&mut round), RoundEnd::Done(None));
    }

    #[test]
    fn layout_parser_does_not_swap_downsampled_pixel_and_point_fields() {
        let mut payload = Vec::new();
        for n in [12u16, 5, 1800, 1169, 1200, 780] {
            payload.extend_from_slice(&n.to_be_bytes());
        }
        let body = update_with(0x451, &payload);
        assert_eq!(
            find_display_layout(&body),
            Some(((1800, 1169), (1200, 780)))
        );
    }
}
