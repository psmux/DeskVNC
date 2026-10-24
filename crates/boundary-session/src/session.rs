use crate::{
    Desktop, Frame, Input, Invitation,
    screen::{self, Rect},
    tools,
    video::{self, Update, VideoEncoder, VideoEncoders, VideoUnit},
    wire::{self, Message, Screens},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use iroh::{
    Endpoint, RelayMode,
    endpoint::{Connection, presets},
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

pub enum Approval {
    Deny,
    View,
    Control,
}
pub enum Event {
    Status(String),
    Invitation(String),
    /// On the host's side: a helper asks to be let in. `tools` is whether
    /// the helper can send commands and file requests. To allow them, call
    /// [`Session::set_tools`] before answering.
    Approval {
        name: String,
        peer: String,
        tools: bool,
        answer: oneshot::Sender<Approval>,
    },
    Connected {
        peer: String,
        control: bool,
    },
    Control(bool),
    /// On the helper's side: the person changed whether commands and files
    /// are allowed.
    Tools(bool),
    /// On the host's side: one line for each command or file request the
    /// helper ran, so the person can see what was done.
    Activity(String),
    /// On the helper's side: the person helped chose to let this helper in
    /// any time. `machine` is the ID to save and connect to later.
    Paired {
        machine: String,
        name: String,
    },
    Finished(Result<()>),
}
/// Observed selected transport. This does not infer a NAT type or failure cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Direct,
    Relay,
    Unknown,
}
#[derive(Clone, Debug, Default)]
pub struct Connectivity {
    pub route: Option<Route>,
    pub rtt: Option<Duration>,
    pub warning: Option<String>,
}
#[derive(Clone)]
pub struct HostOptions {
    /// Public relays carry encrypted QUIC packets. No directory is used.
    pub relay: bool,
    pub relay_url: Option<String>,
    /// Restrict the host to an existing routed interface, with no public fallback.
    pub bind_ip: Option<std::net::IpAddr>,
}
impl Default for HostOptions {
    fn default() -> Self {
        Self {
            relay: true,
            relay_url: None,
            bind_ip: None,
        }
    }
}
#[derive(Clone, Copy)]
struct Permission {
    allowed: bool,
    generation: u64,
}
pub struct Session {
    pub events: mpsc::Receiver<Event>,
    pub frames: watch::Receiver<Option<Arc<Frame>>>,
    pub connectivity: watch::Receiver<Connectivity>,
    damage: Arc<Mutex<Damage>>,
    /// Bytes of screens received, for measuring.
    received: Arc<std::sync::atomic::AtomicU64>,
    input: mpsc::Sender<Input>,
    control: watch::Sender<Permission>,
    /// On the host's side, whether the person allows commands and files. On
    /// the helper's side, what the host last said about it.
    tools: watch::Sender<bool>,
    client: watch::Receiver<Option<tools::Client>>,
    pairing: mpsc::Sender<(String, String)>,
    /// Bumped to ask the host for the whole screen again.
    refresh: watch::Sender<u64>,
    cancel: CancellationToken,
}
/// What a helper can do beyond drawing screens, said in its first message.
#[derive(Clone, Copy, Debug, Default)]
pub struct Abilities {
    /// Send commands and file requests (`crate::tools`).
    pub tools: bool,
    /// Take moving screens as H.264 through [`Session::updates`]. Only a
    /// caller that reads updates that way may say so: [`Session::screen`]
    /// has nowhere to put a picture of video.
    pub video: bool,
}
impl Abilities {
    /// The video codecs to name in the first message.
    pub(crate) fn codecs(&self) -> Vec<String> {
        if self.video {
            vec![wire::H264.into()]
        } else {
            Vec::new()
        }
    }
}
/// Show a screen in the helper's window, with what changed: `None` when it is
/// a whole new picture.
fn show(
    frames: &watch::Sender<Option<Arc<Frame>>>,
    damage: &Mutex<Damage>,
    frame: Arc<Frame>,
    rects: Option<Vec<Rect>>,
) {
    let mut damage = damage.lock().unwrap_or_else(|e| e.into_inner());
    match rects {
        Some(rects) if !damage.whole => damage.rects.extend(rects),
        _ => {
            damage.whole = true;
            damage.rects.clear();
        }
    }
    frames.send_replace(Some(frame));
}
/// What changed on the helper's screen since it was last read.
#[derive(Default)]
struct Damage {
    whole: bool,
    rects: Vec<Rect>,
    /// Rectangles and video that came before the rectangles above, in order,
    /// when video came between them.
    earlier: Vec<Pending>,
}
enum Pending {
    Rects { whole: bool, rects: Vec<Rect> },
    Video(VideoUnit),
}
impl Damage {
    /// Close the rectangles gathered so far, so what comes next is drawn
    /// after them.
    fn seal(&mut self) {
        if self.whole || !self.rects.is_empty() {
            self.earlier.push(Pending::Rects {
                whole: std::mem::take(&mut self.whole),
                rects: std::mem::take(&mut self.rects),
            });
        }
    }
}
/// Hand a picture of video to the helper's window, after whatever came
/// before it.
fn show_video(frames: &watch::Sender<Option<Arc<Frame>>>, damage: &Mutex<Damage>, unit: VideoUnit) {
    let mut damage = damage.lock().unwrap_or_else(|e| e.into_inner());
    damage.seal();
    damage.earlier.push(Pending::Video(unit));
    // The screen itself has not changed, but whoever reads updates has to
    // wake for this.
    frames.send_modify(|_| {});
}
impl Session {
    /// The newest screen and the rectangles that changed since the last
    /// call, or `None` for the rectangles when all of it may have.
    pub fn screen(&mut self) -> Option<(Arc<Frame>, Option<Vec<Rect>>)> {
        let mut damage = self.damage.lock().unwrap_or_else(|e| e.into_inner());
        let frame = self.frames.borrow_and_update().clone()?;
        let mut taken = std::mem::take(&mut *damage);
        // Only a session that said it takes video gets any, so this is only
        // ever rectangles, and they are all drawn from the newest screen.
        for pending in taken.earlier.drain(..) {
            if let Pending::Rects { whole, rects } = pending {
                taken.whole |= whole;
                taken.rects.extend(rects);
            }
        }
        let rects = (!taken.whole && !taken.rects.is_empty()).then_some(taken.rects);
        Some((frame, rects))
    }
    /// Everything to draw since the last call, in order: changed parts of
    /// the screen and pictures of video. For a session opened with
    /// [`Abilities::video`]; without it this is [`Session::screen`] as a list.
    pub fn updates(&mut self) -> Vec<Update> {
        let mut damage = self.damage.lock().unwrap_or_else(|e| e.into_inner());
        let frame = self.frames.borrow_and_update().clone();
        damage.seal();
        std::mem::take(&mut damage.earlier)
            .into_iter()
            .filter_map(|pending| match pending {
                Pending::Video(unit) => Some(Update::Video(unit)),
                Pending::Rects { whole, rects } => frame.clone().map(|frame| Update::Screen {
                    frame,
                    rects: (!whole && !rects.is_empty()).then_some(rects),
                }),
            })
            .collect()
    }
    /// Ask the host for the whole screen again as rectangles, as when what
    /// this side holds went stale under video. Only a host that sends video
    /// is asked, since no other one lets it go stale.
    pub fn refresh(&self) {
        self.refresh.send_modify(|n| *n += 1);
    }
    /// Bytes of screens and video received so far, on the helper's side.
    pub fn received(&self) -> u64 {
        self.received.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub(crate) fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }
    /// On the host's side: allow or stop the helper's commands and file
    /// requests. It takes effect for the next request that arrives, and the
    /// helper is told.
    pub fn set_tools(&self, allowed: bool) {
        self.tools.send_replace(allowed);
    }
    /// On the host's side, whether commands and files are allowed now.
    pub fn tools_allowed(&self) -> bool {
        *self.tools.borrow()
    }
    /// On the helper's side: how to send commands and file requests, once the
    /// host has let this helper in and said it serves them. `None` before
    /// that, after the session ends, and with a host too old to serve them.
    pub fn tools(&self) -> Option<tools::Client> {
        self.client.borrow().clone()
    }
    /// On the host's side, during a session: tell the helper it may connect
    /// any time to the unattended machine `machine`, named `name`. Saving the
    /// helper as trusted is the caller's job, in the same place it keeps the
    /// unattended access list.
    pub fn offer_pairing(&self, machine: String, name: String) -> Result<()> {
        self.pairing
            .try_send((machine, name))
            .map_err(|_| anyhow!("The session has ended"))
    }
    pub fn stop(&self) {
        self.set_control(false);
        self.cancel.cancel();
    }
    pub fn set_control(&self, allowed: bool) {
        self.control.send_modify(|p| {
            p.allowed = allowed;
            p.generation += 1;
        });
    }
    pub fn input(&self, input: Input) -> Result<()> {
        input.validate()?;
        match self.input.try_send(input) {
            Ok(()) => Ok(()),
            // A move is superseded by the next one, so while the link is
            // slow a full queue drops it. Ending the session for it froze
            // the picture for the person moving the mouse.
            Err(mpsc::error::TrySendError::Full(Input::Move { .. })) => Ok(()),
            Err(_) => {
                // Never silently lose a key release when the queue fills.
                self.stop();
                bail!("Input queue is full or disconnected. Session stopped");
            }
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}
pub(crate) struct Worker {
    connectivity: watch::Sender<Connectivity>,
    events: mpsc::Sender<Event>,
    frames: watch::Sender<Option<Arc<Frame>>>,
    damage: Arc<Mutex<Damage>>,
    received: Arc<std::sync::atomic::AtomicU64>,
    input: mpsc::Receiver<Input>,
    control: watch::Receiver<Permission>,
    control_tx: watch::Sender<Permission>,
    pub(crate) tools_tx: watch::Sender<bool>,
    client: watch::Sender<Option<tools::Client>>,
    pairing: mpsc::Receiver<(String, String)>,
    refresh: watch::Receiver<u64>,
    cancel: CancellationToken,
}
pub(crate) fn channels() -> (Session, Worker) {
    let (connectivity_tx, connectivity) = watch::channel(Connectivity::default());
    let (events_tx, events) = mpsc::channel(32);
    let (frames_tx, frames) = watch::channel(None);
    let (input, input_rx) = mpsc::channel(128);
    let (pairing, pairing_rx) = mpsc::channel(4);
    let (refresh, refresh_rx) = watch::channel(0u64);
    let (control, control_rx) = watch::channel(Permission {
        allowed: false,
        generation: 0,
    });
    // Off until somebody says otherwise, on both sides.
    let (tools_tx, _) = watch::channel(false);
    let (client_tx, client) = watch::channel(None);
    let cancel = CancellationToken::new();
    let damage = Arc::new(Mutex::new(Damage::default()));
    let received = Arc::new(std::sync::atomic::AtomicU64::new(0));
    (
        Session {
            connectivity,
            events,
            frames,
            damage: damage.clone(),
            received: received.clone(),
            input,
            control: control.clone(),
            tools: tools_tx.clone(),
            client,
            pairing,
            refresh,
            cancel: cancel.clone(),
        },
        Worker {
            connectivity: connectivity_tx,
            events: events_tx,
            frames: frames_tx,
            damage,
            received,
            input: input_rx,
            control: control_rx,
            control_tx: control.clone(),
            tools_tx,
            client: client_tx,
            pairing: pairing_rx,
            refresh: refresh_rx,
            cancel,
        },
    )
}
impl Worker {
    pub(crate) fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub(crate) async fn emit(&self, event: Event) -> Result<()> {
        self.events
            .send(event)
            .await
            .map_err(|_| anyhow!("Window closed"))
    }
}
pub fn host<F>(options: HostOptions, desktop: F) -> Session
where
    F: FnOnce() -> Result<Box<dyn Desktop>> + Send + 'static,
{
    let (session, mut worker) = channels();
    tokio::spawn(async move {
        let cancel = worker.cancel.clone();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = run_host(&mut worker, options, desktop) => result,
        };
        worker.cancel.cancel();
        let _ = worker.emit(Event::Finished(result)).await;
    });
    session
}
pub fn viewer(ticket: String, name: String, options: HostOptions) -> Session {
    viewer_as(ticket, name, options, None)
}
/// A viewer that connects with a lasting identity, so that if the person
/// being helped pairs this helper, later unattended connections are
/// recognised. `None` is a fresh identity for this session only.
pub fn viewer_as(
    ticket: String,
    name: String,
    options: HostOptions,
    key: Option<iroh::SecretKey>,
) -> Session {
    viewer_with(ticket, name, options, key, Abilities::default())
}
/// [`viewer_as`] for a helper whose tools send commands and file requests,
/// such as DeskVNC's agent plane. The person is asked about those
/// separately, and [`Session::tools`] is how they are sent once allowed.
pub fn viewer_with_tools(
    ticket: String,
    name: String,
    options: HostOptions,
    key: Option<iroh::SecretKey>,
) -> Session {
    viewer_with(
        ticket,
        name,
        options,
        key,
        Abilities {
            tools: true,
            video: false,
        },
    )
}
/// [`viewer_as`] for a helper that says what more it can do.
pub fn viewer_with(
    ticket: String,
    name: String,
    options: HostOptions,
    key: Option<iroh::SecretKey>,
    abilities: Abilities,
) -> Session {
    let (session, mut worker) = channels();
    tokio::spawn(async move {
        let cancel = worker.cancel.clone();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = run_viewer(&mut worker, ticket, name, options, key, abilities) => result,
        };
        worker.cancel.cancel();
        let _ = worker.emit(Event::Finished(result)).await;
    });
    session
}
/// Whether an endpoint's address goes into, or comes out of, the public
/// address directory that lets a machine be reached by its ID alone.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// Attended sessions: the invitation carries the address.
    Off,
    /// An unattended machine, so helpers can find it by ID.
    Publish,
    /// A helper finding an unattended machine by ID. Nothing is published
    /// about the helper.
    Resolve,
}
async fn endpoint(options: &HostOptions) -> Result<Endpoint> {
    endpoint_with(options, None, Lookup::Off).await
}
/// How long a connection may hear nothing before it counts as lost.
///
/// QUIC's own default is thirty seconds, so a helper whose link died looked
/// at a frozen screen for half a minute before anything noticed and connected
/// again. Keep-alives go every five seconds whatever the screen does, so
/// fifteen is three missed in a row: long enough for a cellular blip, short
/// enough that a dead link is found and replaced quickly. Each side uses the
/// lower of the two values, so this holds against older copies too.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// How much a new connection may send before its first acknowledgement.
///
/// QUIC starts at about 14 KB and doubles once a round trip. The first screen
/// is a few hundred kilobytes, so across an ocean, at a quarter of a second a
/// round trip, it took five round trips and arrived nearly two seconds after
/// connecting. Starting at 128 KB, paced rather than sent in a burst, halves
/// that. BBR measured no better than Cubic on the same links, so the default
/// controller stays.
const INITIAL_WINDOW: u64 = 128 * 1024;

fn transport_config() -> Result<iroh::endpoint::QuicTransportConfig> {
    let mut congestion = noq_proto::congestion::CubicConfig::default();
    congestion.initial_window(INITIAL_WINDOW);
    Ok(iroh::endpoint::QuicTransportConfig::builder()
        .max_idle_timeout(Some(
            IDLE_TIMEOUT
                .try_into()
                .map_err(|e| anyhow!("Invalid idle timeout: {e}"))?,
        ))
        .congestion_controller_factory(Arc::new(congestion))
        .build())
}

pub(crate) async fn endpoint_with(
    options: &HostOptions,
    key: Option<iroh::SecretKey>,
    lookup: Lookup,
) -> Result<Endpoint> {
    // A machine waiting for unattended helpers sits on a port people can
    // type, so it can be dialled by address like a VNC server. Somebody else
    // on that port only costs it the address: it still answers by ID.
    if lookup == Lookup::Publish
        && let Ok(endpoint) = bind_endpoint(options, key.clone(), lookup, crate::direct::PORT).await
    {
        return Ok(endpoint);
    }
    bind_endpoint(options, key, lookup, 0).await
}
async fn bind_endpoint(
    options: &HostOptions,
    key: Option<iroh::SecretKey>,
    lookup: Lookup,
    port: u16,
) -> Result<Endpoint> {
    ensure!(
        options.bind_ip.is_none() || !options.relay,
        "Private interface mode cannot enable a relay"
    );
    let relay = if !options.relay {
        RelayMode::Disabled
    } else if let Some(url) = options.relay_url.as_ref().filter(|s| !s.trim().is_empty()) {
        RelayMode::Custom(iroh::RelayMap::from(parse_relay_url(url)?))
    } else {
        RelayMode::Default
    };
    let mut builder = match lookup {
        // The invitation includes the address; publishing a directory entry is unnecessary.
        Lookup::Off => Endpoint::builder(presets::Minimal),
        Lookup::Publish => Endpoint::builder(presets::N0),
        Lookup::Resolve => Endpoint::builder(presets::Minimal)
            .address_lookup(iroh::address_lookup::PkarrResolver::n0_dns())
            .address_lookup(iroh::address_lookup::DnsAddressLookup::n0_dns()),
    };
    builder = builder
        .relay_mode(relay)
        .alpns(vec![wire::ALPN.to_vec()])
        .dns_resolver(crate::dns::resolver())
        .transport_config(transport_config()?);
    if let Some(key) = key {
        builder = builder.secret_key(key);
    }
    if let Some(ip) = options.bind_ip {
        ensure!(
            !ip.is_unspecified() && !ip.is_multicast(),
            "Choose a specific local interface address"
        );
        builder = builder
            .clear_ip_transports()
            .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
            .bind_addr(std::net::SocketAddr::new(ip, port))?;
    } else if port != 0 {
        builder = builder
            .clear_ip_transports()
            .bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))?
            .bind_addr_with_opts(
                std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)),
                iroh::endpoint::BindOpts::default().set_is_required(false),
            )?;
    }
    Ok(builder.bind().await?)
}
pub fn validate_relay_url(value: &str) -> Result<()> {
    parse_relay_url(value).map(|_| ())
}
fn parse_relay_url(value: &str) -> Result<iroh::RelayUrl> {
    let url = value
        .trim()
        .parse::<iroh::RelayUrl>()
        .map_err(|_| anyhow!("Enter a valid HTTP or HTTPS iroh relay URL"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "Use an HTTP or HTTPS iroh relay URL. TURN servers and tunnel hostnames are not interchangeable with iroh relays"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Relay URLs must not contain credentials, query parameters or fragments"
    );
    Ok(url)
}
fn route_snapshot(connection: &Connection) -> (Route, Option<Duration>) {
    let paths = connection.paths();
    match paths.iter().find(|path| path.is_selected()) {
        Some(path) => (
            if path.is_ip() {
                Route::Direct
            } else if path.is_relay() {
                Route::Relay
            } else {
                Route::Unknown
            },
            Some(path.rtt()),
        ),
        None => (Route::Unknown, None),
    }
}
async fn monitor_route(connection: &Connection, updates: &watch::Sender<Connectivity>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = connection.closed() => return,
            _ = tick.tick() => {
                let (route, rtt) = route_snapshot(connection);
                updates.send_modify(|info| { info.route = Some(route); info.rtt = rtt; });
            }
        }
    }
}
struct EndpointGuard(Endpoint);
/// An endpoint a session bound for itself, or one it shares with others.
enum Held {
    Own(#[allow(dead_code)] EndpointGuard),
    Shared(#[allow(dead_code)] crate::shared::Shared),
}
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let endpoint = self.0.clone();
        tokio::spawn(async move {
            endpoint.close().await;
        });
    }
}
/// Takes the tools client away when a helper's session ends, however it ends.
struct ForgetClient<'a>(&'a watch::Sender<Option<tools::Client>>);
impl Drop for ForgetClient<'_> {
    fn drop(&mut self) {
        self.0.send_replace(None);
    }
}
struct Close(Connection);
impl Drop for Close {
    fn drop(&mut self) {
        self.0.close(0u8.into(), b"Session ended");
    }
}

async fn run_host<F>(worker: &mut Worker, options: HostOptions, desktop: F) -> Result<()>
where
    F: FnOnce() -> Result<Box<dyn Desktop>> + Send + 'static,
{
    worker
        .emit(Event::Status("Preparing your invitation".into()))
        .await?;
    let endpoint = endpoint(&options).await?;
    let _endpoint_guard = EndpointGuard(endpoint.clone());
    if options.relay
        && tokio::time::timeout(Duration::from_secs(12), endpoint.online())
            .await
            .is_err()
    {
        worker.connectivity.send_modify(|info| {
            info.warning = Some("Relay unavailable. Only directly reachable addresses may work. Check the relay and network settings before sharing this invitation".into());
        });
    }
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).map_err(|e| anyhow!("Cannot generate invitation: {e}"))?;
    let invite = Invitation {
        version: 1,
        address: endpoint.addr(),
        secret,
        expires: wire::now() + wire::INVITE_SECONDS,
    };
    worker.emit(Event::Invitation(invite.encode()?)).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wire::INVITE_SECONDS);
    loop {
        let incoming = tokio::time::timeout_at(deadline, endpoint.accept())
            .await
            .context("Invitation expired. Create a new invitation")?
            .context("Listener closed")?;
        let handshake = async {
            let connection = incoming.await?;
            let guard = Close(connection.clone());
            let (send, mut recv) = connection.accept_bi().await?;
            let (name, tools, screens) =
                wire::validate_hello(wire::read(&mut recv).await?, &invite)?;
            Ok::<_, anyhow::Error>((guard, send, recv, name, tools, screens))
        };
        let Ok(Ok((guard, mut send, recv, name, tools, screens))) =
            tokio::time::timeout(Duration::from_secs(5), handshake).await
        else {
            continue;
        };
        let connection = &guard.0;
        let peer = connection.remote_id().to_string();
        let (answer, decision) = oneshot::channel();
        // Whatever an earlier helper was allowed is not this one's.
        worker.tools_tx.send_replace(false);
        worker
            .emit(Event::Approval {
                name,
                peer: peer.clone(),
                tools,
                answer,
            })
            .await?;
        let decision = tokio::select! {
            _ = connection.closed() => continue,
            decision = tokio::time::timeout_at(deadline.min(tokio::time::Instant::now() + Duration::from_secs(60)), decision) => decision,
        };
        let allowed = match decision {
            Ok(Ok(Approval::View)) => false,
            Ok(Ok(Approval::Control)) => true,
            _ => {
                let _ = wire::write(&mut send, &Message::Denied).await;
                continue;
            }
        };
        // The invitation is consumed by this session, even if the peer later disconnects.
        let result = serve(
            worker, connection, send, recv, peer, allowed, tools, screens, desktop,
        )
        .await;
        close_served(connection, &result);
        drop(guard);
        endpoint.close().await;
        return result;
    }
}
/// Run one session that has been let in: start the desktop, send screens,
/// apply input within the permission the person set, and stop when either
/// side does. Shared by attended and unattended sessions, so the rules for
/// what a helper can do are written once.
///
/// `tools` is whether the helper said it can send commands and file
/// requests. Whether it may is the session's own tools permission, which the
/// caller set before this and the person can change at any time.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve<F>(
    worker: &mut Worker,
    connection: &Connection,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    peer: String,
    allowed: bool,
    tools: bool,
    screens: Screens,
    desktop: F,
) -> Result<()>
where
    F: FnOnce() -> Result<Box<dyn Desktop>> + Send + 'static,
{
    let mut tools_rx = worker.tools_tx.subscribe();
    if !tools {
        // A helper that cannot send them is never allowed them, whatever was set.
        worker.tools_tx.send_replace(false);
    }
    let tools_now = *tools_rx.borrow_and_update();
    worker.control_tx.send_modify(|p| {
        p.allowed = allowed;
        p.generation += 1;
    });
    let permission_rx = worker.control.clone();
    let input_permission = worker.control.clone();
    let (input_tx, input_rx) = mpsc::channel(128);
    let (screen_tx, screen_rx) = watch::channel(None::<Arc<Frame>>);
    let (shown_tx, shown_rx) = watch::channel(0u64);
    let (refresh_tx, refresh_rx) = watch::channel(0u64);
    let (encoders_tx, encoders_rx) = oneshot::channel();
    let changes: Changes = Arc::new(Mutex::new(Some(Vec::new())));
    let cancel = worker.cancel.clone();
    let capture = tokio::task::spawn_blocking({
        let changes = changes.clone();
        move || {
            desktop_loop(
                desktop,
                input_rx,
                permission_rx,
                screen_tx,
                encoders_tx,
                changes,
                cancel,
            )
        }
    });
    wire::write(
        &mut send,
        &Message::Granted {
            control: allowed,
            tools: tools.then_some(tools_now),
        },
    )
    .await?;
    worker
        .emit(Event::Connected {
            peer,
            control: allowed,
        })
        .await?;
    // Ignore the initial false UI value; subsequent changes are local permission decisions.
    worker.control.borrow_and_update();
    let read_input = async {
        loop {
            let message: Message =
                tokio::time::timeout(Duration::from_secs(5), wire::read(&mut recv))
                    .await
                    .context("Helper stopped responding")??;
            match message {
                Message::Ping => {}
                Message::Refresh if screens == Screens::Video => {
                    refresh_tx.send_modify(|n| *n += 1);
                }
                Message::Shown(seq) if screens.acknowledged() => {
                    shown_tx.send_if_modified(|shown| {
                        let newer = seq > *shown;
                        *shown = (*shown).max(seq);
                        newer
                    });
                }
                Message::Input(input) => {
                    input.validate()?;
                    let permission = *input_permission.borrow();
                    if permission.allowed || matches!(input, Input::Release) {
                        match input_tx.try_send((permission.generation, input)) {
                            Ok(()) => {}
                            // The next move supersedes this one; dropping it
                            // while the screen is busy beats ending the session.
                            Err(mpsc::error::TrySendError::Full((_, Input::Move { .. }))) => {}
                            Err(_) => bail!("Input rate exceeded. Session stopped"),
                        }
                    }
                }
                _ => bail!("Unexpected helper message"),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let write_control = async {
        loop {
            tokio::select! {
                changed = worker.control.changed() => {
                    changed?;
                    let control = worker.control.borrow_and_update().allowed;
                    wire::write(&mut send, &Message::Control(control)).await?;
                }
                Some((machine, name)) = worker.pairing.recv() => {
                    wire::write(&mut send, &Message::Paired { machine, name }).await?;
                }
                changed = tools_rx.changed(), if tools => {
                    changed?;
                    let now = *tools_rx.borrow_and_update();
                    wire::write(&mut send, &Message::Tools(now)).await?;
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let activity = worker.events.clone();
    let serve_tools = async {
        if !tools {
            return std::future::pending::<Result<()>>().await;
        }
        tools::serve(connection, worker.tools_tx.subscribe(), move |line| {
            let activity = activity.clone();
            tokio::spawn(async move {
                let _ = activity.send(Event::Activity(line)).await;
            });
        })
        .await
    };
    // Reading from or writing to the helper failing is the link failing,
    // seen from this end. The helper connects again for that, unlike for a
    // capture that failed here, which another attempt would only repeat.
    let result = tokio::select! {
        _ = monitor_route(connection, &worker.connectivity) => Ok(()),
        result = read_input => result.map_err(link_lost),
        result = write_control => result.map_err(link_lost),
        result = serve_tools => result,
        result = async {
            match screens {
                Screens::Tiles => send_updates(connection, screen_rx, shown_rx, &changes, None).await,
                Screens::Video => {
                    send_updates(
                        connection,
                        screen_rx,
                        shown_rx,
                        &changes,
                        Some((encoders_rx, refresh_rx)),
                    )
                    .await
                }
                _ => send_screens(connection, screen_rx, screens == Screens::Jpeg).await,
            }
        } => result.map_err(link_lost),
        result = capture => result.context("Capture worker failed")?,
        _ = connection.closed() => Ok(()),
    };
    result
}

/// How soon to capture again while the screen is changing or someone is
/// using it: sixty screens a second, as often as a display draws.
const BUSY_CAPTURE: Duration = Duration::from_millis(16);
/// The same for a desktop that says what changed, which costs little to ask.
const POLL_CAPTURE: Duration = Duration::from_millis(2);
/// How soon to capture again on a screen that has stayed still for a while.
const IDLE_CAPTURE: Duration = Duration::from_millis(100);
/// How long a still screen stays on the busy pace after it last changed.
const BUSY_FOR: Duration = Duration::from_secs(1);

fn desktop_loop<F>(
    factory: F,
    mut input: mpsc::Receiver<(u64, Input)>,
    permission: watch::Receiver<Permission>,
    screens: watch::Sender<Option<Arc<Frame>>>,
    encoders: oneshot::Sender<Option<VideoEncoders>>,
    changes: Changes,
    cancel: CancellationToken,
) -> Result<()>
where
    F: FnOnce() -> Result<Box<dyn Desktop>>,
{
    struct Release(Box<dyn Desktop>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    let mut desktop = Release(factory()?);
    let _ = encoders.send(desktop.0.video());
    let mut capture_at = Instant::now();
    let mut last_input = Instant::now();
    let mut last_change = Instant::now();
    let mut last: Option<Arc<Frame>> = None;
    let mut generation = permission.borrow().generation;
    while !cancel.is_cancelled() {
        let current = *permission.borrow();
        if current.generation != generation || last_input.elapsed() > Duration::from_secs(2) {
            desktop.0.release();
            last_input = Instant::now();
        }
        generation = current.generation;
        for _ in 0..128 {
            let Ok((epoch, event)) = input.try_recv() else {
                break;
            };
            if cancel.is_cancelled() {
                break;
            }
            if matches!(event, Input::Release) {
                desktop.0.release();
            } else {
                let current = *permission.borrow();
                if current.allowed && current.generation == epoch {
                    desktop.0.input(event)?;
                    crate::stats::input();
                    // Show what the input did as soon as it is drawn,
                    // rather than at the next turn of the clock.
                    capture_at = Instant::now();
                    last_change = Instant::now();
                }
            }
            last_input = Instant::now();
        }
        if cancel.is_cancelled() {
            break;
        }
        if Instant::now() >= capture_at {
            let started = Instant::now();
            // A still screen is not handed on: sending the same picture
            // again only costs the link.
            // A backend that says what changed saves comparing whole screens.
            let captured = desktop.0.capture_changed()?;
            let damage = desktop.0.capture_damage();
            let told = damage.is_some();
            let changed = captured.as_ref().is_some_and(|frame| {
                damage.as_ref().map_or_else(
                    || last.as_ref().is_none_or(|last| **last != *frame),
                    |rects| !rects.is_empty() || last.is_none(),
                )
            });
            crate::stats::captured(started.elapsed(), changed);
            if let Some(frame) = captured.filter(|_| changed) {
                note_changes(&changes, damage);
                let frame = Arc::new(frame);
                last = Some(frame.clone());
                last_change = Instant::now();
                if !cancel.is_cancelled() {
                    screens.send_replace(Some(frame));
                    crate::stats::produced();
                }
            }
            // A desktop that says what changed answers "nothing" for next to
            // nothing, so while it is busy it is asked eight times as often:
            // a change is then picked up within a few milliseconds of being
            // drawn, not up to a whole screen later.
            let pace = if last_change.elapsed() >= BUSY_FOR {
                IDLE_CAPTURE
            } else if told {
                POLL_CAPTURE
            } else {
                BUSY_CAPTURE
            };
            capture_at = started + pace;
        }
        // Input is looked for at least every millisecond: waiting up to four
        // here held each pointer move and key back two on average.
        let wait = capture_at
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(1));
        std::thread::sleep(wait.max(Duration::from_micros(500)));
    }
    Ok(())
}
/// How long one screen may take to reach the helper before it is given up.
/// A whole screen is several hundred kilobytes, and on a slow uplink, such as
/// a cellular one through a relay, it can take seconds. Giving up sooner threw
/// away nearly every screen there and left the helper looking at a still
/// picture. Only the newest screen is ever waiting, so a slow link gets fewer
/// screens rather than late ones.
const SCREEN_DEADLINE: Duration = Duration::from_secs(15);

/// Whole screens, one stream each, to a helper that does not take updates.
async fn send_screens(
    connection: &Connection,
    mut screens: watch::Receiver<Option<Arc<Frame>>>,
    jpeg: bool,
) -> Result<()> {
    loop {
        if screens.changed().await.is_err() {
            // The capture worker has stopped, and its own result says why.
            // Ending here first reported "channel closed" to the helper
            // instead, and the real reason, such as a missing permission,
            // was lost.
            return std::future::pending().await;
        }
        let frame = screens
            .borrow_and_update()
            .clone()
            .context("Missing screen")?;
        let bytes = tokio::task::spawn_blocking(move || {
            if jpeg {
                frame.encode_jpeg()
            } else {
                frame.encode()
            }
        })
        .await??;
        let mut stream = connection.open_uni().await?;
        let result = tokio::time::timeout(SCREEN_DEADLINE, async {
            stream.write_all(&bytes).await?;
            stream.finish()?;
            stream.stopped().await?;
            Ok::<(), anyhow::Error>(())
        })
        .await;
        match result {
            Ok(result) => result?,
            Err(_) => {
                let _ = stream.reset(1u8.into());
            }
        }
    }
}

/// At most this many updates wait to be shown, however small they are.
const MAX_UPDATES_IN_FLIGHT: usize = 12;
/// The same for pictures of video, which are small and come many a second:
/// twelve held a link with a 300 ms round trip to forty a second. The bytes
/// in flight are still held to the congestion window.
const MAX_VIDEO_IN_FLIGHT: usize = 32;
/// Data allowed on its way before the link has measured itself.
const MIN_BYTES_IN_FLIGHT: u64 = 128 * 1024;

/// Bytes the link carries in one round trip, as its congestion window has
/// measured it.
fn window(connection: &Connection) -> u64 {
    connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map_or(0, |path| path.stats().cwnd)
        .max(MIN_BYTES_IN_FLIGHT)
}

/// JPEG quality of the whole screen sent when motion stops, after video
/// drew over it. Higher than for ordinary tiles: it goes once per stop, and
/// it is the picture that sits there while the person reads.
const SETTLED_QUALITY: u8 = 80;

/// For a helper that decodes video: where the desktop's encoders come from,
/// once it has started, and the helper's requests for the whole screen.
/// What changed on the screen since the sender last took a capture, as the
/// desktop said, or `None` when it did not say and screens must be compared.
type Changes = Arc<Mutex<Option<Vec<Rect>>>>;

/// Add what the desktop said changed in the screen just captured.
fn note_changes(changes: &Mutex<Option<Vec<Rect>>>, damage: Option<Vec<Rect>>) {
    let mut changes = changes.lock().unwrap_or_else(|e| e.into_inner());
    match (changes.as_mut(), damage) {
        // Bounded, for a sender that never takes them, as for whole screens.
        (Some(known), Some(rects)) if known.len() + rects.len() <= 4096 => known.extend(rects),
        _ => *changes = None,
    }
}

type VideoSetup = (
    oneshot::Receiver<Option<VideoEncoders>>,
    watch::Receiver<u64>,
);

/// One video encoder and the screens it was made for.
struct Video {
    encoder: Box<dyn VideoEncoder>,
    width: u32,
    height: u32,
    /// Nothing has been sent from this encoder yet.
    fresh: bool,
    rate: (u32, u32),
}

/// The host's side of a stream of updates: what the helper holds, and
/// whether moving screens go as video. Moved to a blocking thread for each
/// update, since encoding takes milliseconds.
struct Coder {
    tiles: screen::Encoder,
    /// Each message carries a kind, on a stream to a helper that takes video.
    framed: bool,
    encoders: Option<VideoEncoders>,
    video: Option<Video>,
    policy: video::Policy,
    /// The capture before this one, to tell how much of the screen moved.
    last: Option<Arc<Frame>>,
}
enum Work {
    /// A new capture, and what the desktop said changed since the last one
    /// taken, when it said.
    Capture(Arc<Frame>, Option<Vec<Rect>>),
    /// The screen has stopped moving: sharp tiles for what video drew
    /// visibly wrong.
    Settle(Arc<Frame>),
    /// The whole screen, sharp, as when the helper asked.
    Whole(Arc<Frame>),
}
impl Coder {
    fn new(framed: bool) -> Self {
        Self {
            tiles: screen::Encoder::default(),
            framed,
            encoders: None,
            video: None,
            policy: video::Policy::default(),
            last: None,
        }
    }
    /// The message that carries `work` to the helper, or nothing when there
    /// is nothing new to send.
    fn work(
        &mut self,
        work: Work,
        seq: u64,
        rate: (u32, u32),
        now: Instant,
    ) -> Result<Option<Vec<u8>>> {
        match work {
            Work::Settle(frame) => {
                self.policy.settle(now);
                self.last = Some(frame.clone());
                let shown = self
                    .video
                    .as_mut()
                    .filter(|v| v.width == frame.width && v.height == frame.height)
                    .and_then(|v| v.encoder.shown());
                crate::stats::phase("shadow", now.elapsed());
                match shown {
                    Some(shown) => {
                        let stale = video::stale_tiles(&frame, &shown);
                        crate::stats::phase("compare", now.elapsed());
                        let update = self.tiles.refine(frame, &stale, seq, SETTLED_QUALITY)?;
                        crate::stats::phase("tiles", now.elapsed());
                        Ok(update.map(|u| self.kind(u)))
                    }
                    None => {
                        self.tiles.reset();
                        self.tiles(frame, seq, SETTLED_QUALITY)
                    }
                }
            }
            Work::Whole(frame) => {
                self.policy.stop();
                self.tiles.reset();
                self.last = Some(frame.clone());
                self.tiles(frame, seq, SETTLED_QUALITY)
            }
            Work::Capture(frame, damage) => {
                let share = match (&self.last, &damage) {
                    (Some(last), _) if last.width != frame.width || last.height != frame.height => {
                        1.0
                    }
                    (Some(_), Some(rects)) => video::damage_share(rects, frame.width, frame.height),
                    (Some(last), None) => video::changed_share(last, &frame),
                    (None, _) => 1.0,
                };
                self.last = Some(frame.clone());
                let choice = match self.encoders {
                    Some(_) => self.policy.capture(share, now),
                    None => video::Choice::Tiles,
                };
                match choice {
                    video::Choice::Tiles => Ok(self
                        .tiles
                        .update_with(frame, seq, crate::JPEG_QUALITY, damage.as_deref())?
                        .map(|u| self.kind(u))),
                    video::Choice::Video { start } => match {
                        self.tiles.passed();
                        self.video(&frame, seq, rate)
                    } {
                        Ok(bytes) => Ok(bytes),
                        Err(_) => {
                            // An encoder that failed is not tried again in
                            // this session. What video already drew is
                            // replaced by the whole screen as tiles.
                            self.encoders = None;
                            self.video = None;
                            self.policy.stop();
                            if !start {
                                self.tiles.reset();
                            }
                            self.tiles(frame, seq, crate::JPEG_QUALITY)
                        }
                    },
                }
            }
        }
    }
    fn tiles(&mut self, frame: Arc<Frame>, seq: u64, quality: u8) -> Result<Option<Vec<u8>>> {
        Ok(self
            .tiles
            .update_at(frame, seq, quality)?
            .map(|u| self.kind(u)))
    }
    /// A tile update as it goes on this stream.
    fn kind(&self, mut update: Vec<u8>) -> Vec<u8> {
        if self.framed {
            update.insert(0, video::KIND_TILES);
        }
        update
    }
    fn video(&mut self, frame: &Frame, seq: u64, rate: (u32, u32)) -> Result<Option<Vec<u8>>> {
        let video = match self.video.take() {
            Some(v) if v.width == frame.width && v.height == frame.height => v,
            _ => {
                let make = self.encoders.as_ref().context("No video encoder")?;
                Video {
                    encoder: make(frame.width, frame.height)?,
                    width: frame.width,
                    height: frame.height,
                    fresh: true,
                    rate: (0, 0),
                }
            }
        };
        let video = self.video.insert(video);
        // Small swings in the measured link are left alone: an encoder told
        // a new rate every screen spends its bits unevenly.
        let swing = (rate.0 as f64 / video.rate.0.max(1) as f64 - 1.0).abs();
        if video.fresh || swing > 0.15 || rate.1 != video.rate.1 {
            video.encoder.set_rate(rate.0, rate.1);
            video.rate = rate;
        }
        // Only a new encoder starts with a keyframe. When video starts again
        // after the screen settled, the helper's decoder still holds the
        // picture this encoder last made, so the next one follows on from it:
        // a keyframe there cost a third of a second on a slow link before
        // the first moving picture.
        let encoded = video.encoder.encode(frame, video.fresh)?;
        if encoded.data.is_empty() {
            // The encoder skipped this screen to keep to its rate.
            ensure!(!video.fresh, "The video encoder skipped a keyframe");
            return Ok(None);
        }
        ensure!(
            !video.fresh || encoded.keyframe,
            "The video encoder did not start with a keyframe"
        );
        let bytes = video::encode_unit(seq, frame.width, frame.height, &encoded, video.fresh);
        video.fresh = false;
        ensure!(
            bytes.len() <= wire::MAX_FRAME,
            "Encoded screen is too large"
        );
        Ok(Some(bytes))
    }
}

/// The bit rate and screens a second video should aim at on this link now.
fn link_rate(connection: &Connection) -> (u32, u32) {
    let (cwnd, rtt) = connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map_or((MIN_BYTES_IN_FLIGHT, Duration::from_millis(100)), |path| {
            (path.stats().cwnd, path.rtt())
        });
    let bits = video::bitrate(cwnd.max(MIN_BYTES_IN_FLIGHT), rtt);
    (bits, video::frame_rate(bits))
}

/// Changed rectangles, one update after another on a single stream, to a
/// helper that takes them, and video while much of the screen moves to one
/// that decodes it.
///
/// Updates are not waited on one at a time: that cost a round trip per
/// screen, which across an ocean was most of a second. Instead about one
/// round trip of them may be on their way, as the helper's acknowledgements
/// tell. Past that the sender waits, and only the newest capture is encoded
/// when it goes on, so a slow link gets fewer updates rather than late ones.
/// Video follows the same rule, and its bit rate follows the link, so a slow
/// link gets fewer and smaller pictures rather than a queue.
async fn send_updates(
    connection: &Connection,
    mut screens: watch::Receiver<Option<Arc<Frame>>>,
    mut shown: watch::Receiver<u64>,
    changes: &Mutex<Option<Vec<Rect>>>,
    video: Option<VideoSetup>,
) -> Result<()> {
    let framed = video.is_some();
    let (mut encoders, mut refresh) = match video {
        Some((encoders, refresh)) => (Some(encoders), Some(refresh)),
        None => (None, None),
    };
    let mut stream = connection.open_uni().await?;
    stream
        .write_all(if framed {
            screen::MAGIC_VIDEO
        } else {
            screen::MAGIC
        })
        .await?;
    let mut coder = Some(Coder::new(framed));
    let mut seq = 0u64;
    let mut in_flight: VecDeque<(u64, u64)> = VecDeque::new();
    let mut next_video = tokio::time::Instant::now();
    loop {
        loop {
            let acked = *shown.borrow_and_update();
            while in_flight.front().is_some_and(|(s, _)| *s <= acked) {
                in_flight.pop_front();
            }
            let bytes: u64 = in_flight.iter().map(|(_, b)| b).sum();
            let most = if coder.as_ref().is_some_and(|c| c.policy.on_video()) {
                MAX_VIDEO_IN_FLIGHT
            } else {
                MAX_UPDATES_IN_FLIGHT
            };
            if in_flight.is_empty() || (in_flight.len() < most && bytes < window(connection)) {
                break;
            }
            let waiting = Instant::now();
            if shown.changed().await.is_err() {
                return std::future::pending().await;
            }
            crate::stats::waited(waiting.elapsed());
        }
        let mut working = coder.take().context("Screen encoder lost")?;
        // The desktop says what it encodes with as soon as it starts, which
        // is before its first screen.
        if let Some(receiver) = encoders.as_mut()
            && let Ok(found) = receiver.try_recv()
        {
            working.encoders = found;
            encoders = None;
        }
        let settles = working
            .policy
            .settles_at()
            .map(tokio::time::Instant::from_std);
        let on_video = working.policy.on_video();
        coder = Some(working);
        // A capture waiting is looked at before the settle timer: while the
        // link was full nothing was looked at, and the timer ran out on a
        // screen that never stopped moving. That sent a whole sharp screen
        // in the middle of every scroll on a slow link.
        let work = tokio::select! {
            biased;
            // The helper asking for the screen comes first: while the screen
            // keeps moving there is always a capture waiting, and an agent
            // that asked would never be answered.
            Ok(()) = async {
                match refresh.as_mut() {
                    Some(refresh) => refresh.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                match screens.borrow_and_update().clone() {
                    Some(frame) => Work::Whole(frame),
                    None => continue,
                }
            }
            changed = screens.changed() => {
                if changed.is_err() {
                    return std::future::pending().await;
                }
                if on_video {
                    // No more screens a second than the link was given:
                    // wait, then take the newest.
                    tokio::time::sleep_until(next_video).await;
                }
                let frame = screens.borrow_and_update().clone().context("Missing screen")?;
                crate::stats::taken();
                let damage = changes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .replace(Vec::new());
                Work::Capture(frame, damage)
            }
            _ = tokio::time::sleep_until(settles.unwrap_or_else(tokio::time::Instant::now)), if settles.is_some() => {
                match screens.borrow_and_update().clone() {
                    Some(frame) => Work::Settle(frame),
                    None => continue,
                }
            }
        };
        let rate = link_rate(connection);
        let mut working = coder.take().context("Screen encoder lost")?;
        let next = seq + 1;
        let began = tokio::time::Instant::now();
        let (working, update) = tokio::task::spawn_blocking(move || {
            let update = working.work(work, next, rate, Instant::now());
            (working, update)
        })
        .await?;
        crate::stats::encoded(began.elapsed());
        if working.policy.on_video() {
            // From when this screen was taken, not from when its encoding
            // ended: counting from the end added the encoding time to every
            // screen, which held video to 33 to 38 screens a second where
            // it took 10 to 15 ms. A little under the interval, so that a
            // capture landing just before the deadline is not put off a
            // whole screen.
            next_video = began + Duration::from_secs(1) / rate.1.max(1) * 9 / 10;
        }
        coder = Some(working);
        let Some(update) = update? else {
            continue;
        };
        seq = next;
        let writing = Instant::now();
        tokio::time::timeout(SCREEN_DEADLINE, async {
            stream
                .write_all(&(update.len() as u32).to_be_bytes())
                .await?;
            stream.write_all(&update).await
        })
        .await
        .context("The helper stopped taking screens")??;
        crate::stats::sent(writing.elapsed());
        crate::stats::written();
        in_flight.push_back((seq, update.len() as u64));
    }
}
fn viewer_network_options(invitation: &Invitation, mut options: HostOptions) -> HostOptions {
    let advertised = invitation
        .address
        .relay_urls()
        .next()
        .map(ToString::to_string);
    if advertised.is_none() {
        options.relay = false;
        options.relay_url = None;
    } else if options.relay && options.relay_url.is_none() {
        options.relay_url = advertised;
    }
    options
}
async fn run_viewer(
    worker: &mut Worker,
    ticket: String,
    name: String,
    options: HostOptions,
    key: Option<iroh::SecretKey>,
    abilities: Abilities,
) -> Result<()> {
    let invitation = Invitation::decode(&ticket)?;
    // A host without a relay address must not cause the helper to use public relays.
    // For a relayed ticket, use its advertised relay rather than adding n0 defaults.
    let options = viewer_network_options(&invitation, options);
    ensure!(
        !name.trim().is_empty() && name.len() <= 80 && !name.chars().any(char::is_control),
        "Enter a helper name of at most 80 bytes"
    );
    worker
        .emit(Event::Status(
            "Connecting to the person needing help".into(),
        ))
        .await?;
    // With a lasting key, share the endpoint other sessions as that helper
    // already use, so the relay does not drop one for the other.
    let (endpoint, _endpoint_guard) = match key {
        Some(key) => {
            let shared = crate::shared::helper(&options, key).await?;
            ((*shared).clone(), Held::Shared(shared))
        }
        None => {
            let endpoint = endpoint_with(&options, None, Lookup::Off).await?;
            (endpoint.clone(), Held::Own(EndpointGuard(endpoint)))
        }
    };
    let connection = tokio::time::timeout(
        Duration::from_secs(25),
        endpoint.connect(invitation.address, wire::ALPN),
    )
    .await
    .context("Connection timed out")??;
    let guard = Close(connection.clone());
    let (mut send, recv) = connection.open_bi().await?;
    wire::write(
        &mut send,
        &Message::Hello {
            version: 1,
            secret: invitation.secret,
            name,
            tools: abilities.tools,
            jpeg: true,
            tiles: true,
            video: abilities.codecs(),
        },
    )
    .await?;
    let result = watch_session(worker, &connection, send, recv).await;
    drop(guard);
    if matches!(_endpoint_guard, Held::Own(_)) {
        endpoint.close().await;
    }
    result
}
/// The helper's side of a session once its request is on the wire: wait to
/// be let in, then show screens, send input and keep the session alive.
/// Shared by invitations and unattended connections.
pub(crate) async fn watch_session(
    worker: &mut Worker,
    connection: &Connection,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
) -> Result<()> {
    let result = watch(worker, connection, send, recv).await;
    if result.is_err() && connection.close_reason().is_none() {
        // A stream can end a moment before the close that explains it, so
        // give the reason a moment to land rather than report the symptom.
        let _ = tokio::time::timeout(Duration::from_secs(1), connection.closed()).await;
    }
    // The computer's own reason beats whatever read or write noticed first,
    // which is only ever "connection lost" or a stream ending early.
    if let Some(error) = ended_by_host(connection) {
        return Err(error);
    }
    match result {
        Err(error) if !closed_by_peer(connection) && error.downcast_ref::<Refusal>().is_none() => {
            Err(link_lost(error))
        }
        other => other,
    }
}

/// The computer, or the person at it, said no. Read before the computer has
/// closed the connection, so the close cannot be what tells this apart from a
/// link that failed.
#[derive(Debug)]
struct Refusal(String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

/// An error that means the link failed, not that anyone ended the session:
/// a timeout, a reset, a computer that stopped answering. Only this is worth
/// connecting again for. A computer that turned the helper away, or whose
/// person ended the session, closed it on purpose, and connecting again would
/// overrule them.
///
/// It wraps the error rather than adding a line to it, so what the person
/// reads is unchanged.
#[derive(Debug)]
pub struct LinkLost(anyhow::Error);

impl std::fmt::Display for LinkLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for LinkLost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl LinkLost {
    /// Is this error a link failure, worth connecting again for?
    pub fn is(error: &anyhow::Error) -> bool {
        error.downcast_ref::<LinkLost>().is_some()
    }
}

pub(crate) fn link_lost(error: anyhow::Error) -> anyhow::Error {
    if LinkLost::is(&error) {
        error
    } else {
        anyhow::Error::new(LinkLost(error))
    }
}

/// Did the other side close this connection on purpose?
fn closed_by_peer(connection: &Connection) -> bool {
    matches!(
        connection.close_reason(),
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(_))
    )
}

async fn watch(
    worker: &mut Worker,
    connection: &Connection,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
) -> Result<()> {
    worker
        .emit(Event::Status(
            "Waiting for the person to approve sharing".into(),
        ))
        .await?;
    let grant: Message = tokio::time::timeout(Duration::from_secs(65), wire::read(&mut recv))
        .await
        .context("Approval timed out")??;
    let (control, tools) = match grant {
        Message::Granted { control, tools } => (control, tools),
        Message::Refused(reason) => return Err(Refusal(reason).into()),
        _ => return Err(Refusal("The person declined this connection".into()).into()),
    };
    // Only a host that answered about tools serves them. One that did not is
    // older than they are, and a request sent to it would wait on a stream
    // nothing reads.
    if let Some(allowed) = tools {
        worker.tools_tx.send_replace(allowed);
        worker.client.send_replace(Some(tools::Client::new(
            connection.clone(),
            worker.tools_tx.subscribe(),
        )));
    }
    let _forget = ForgetClient(&worker.client);
    worker
        .emit(Event::Connected {
            peer: connection.remote_id().to_string(),
            control,
        })
        .await?;
    let events = worker.events.clone();
    let tools_tx = worker.tools_tx.clone();
    let (shown_tx, mut shown_rx) = watch::channel(0u64);
    // Whether the host's updates said it sends video, the only kind of host
    // that is asked for the screen again.
    let (video_tx, video_rx) = watch::channel(false);
    let refresh = &mut worker.refresh;
    refresh.borrow_and_update();
    let read_control = async {
        loop {
            match wire::read::<Message>(&mut recv).await? {
                Message::Control(value) => {
                    events.send(Event::Control(value)).await?;
                }
                Message::Tools(value) if tools.is_some() => {
                    tools_tx.send_replace(value);
                    events.send(Event::Tools(value)).await?;
                }
                Message::Paired { machine, name } => {
                    events.send(Event::Paired { machine, name }).await?;
                }
                _ => bail!("Unexpected host message"),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let write_input = async {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            let message = tokio::select! {
                event = worker.input.recv() => Message::Input(event.context("Window closed")?),
                Ok(()) = shown_rx.changed() => Message::Shown(*shown_rx.borrow_and_update()),
                Ok(()) = refresh.changed() => {
                    refresh.borrow_and_update();
                    if !*video_rx.borrow() {
                        continue;
                    }
                    Message::Refresh
                }
                _ = tick.tick() => Message::Ping,
            };
            tokio::time::timeout(Duration::from_secs(3), wire::write(&mut send, &message))
                .await
                .context("Input connection stalled")??;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let (frames, damage) = (&worker.frames, &*worker.damage);
    let received = &*worker.received;
    let read_frames = async {
        loop {
            let mut stream = connection.accept_uni().await?;
            let mut head = [0u8; 4];
            match stream.read_exact(&mut head).await {
                Ok(()) => {}
                Err(iroh::endpoint::ReadExactError::ReadError(
                    iroh::endpoint::ReadError::Reset(_),
                )) => continue,
                Err(error) => return Err(error.into()),
            }
            if &head == screen::MAGIC {
                return read_updates(frames, damage, received, stream, &shown_tx, false).await;
            }
            if &head == screen::MAGIC_VIDEO {
                video_tx.send_replace(true);
                return read_updates(frames, damage, received, stream, &shown_tx, true).await;
            }
            let rest = match tokio::time::timeout(
                SCREEN_DEADLINE,
                stream.read_to_end(wire::MAX_FRAME - head.len()),
            )
            .await
            {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(iroh::endpoint::ReadToEndError::Read(
                    iroh::endpoint::ReadError::Reset(_),
                ))) => continue,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {
                    let _ = stream.stop(1u8.into());
                    continue;
                }
            };
            let bytes = [&head[..], &rest].concat();
            received.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
            let frame = tokio::task::spawn_blocking(move || Frame::decode(&bytes)).await??;
            show(frames, damage, Arc::new(frame), None);
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        _ = monitor_route(connection, &worker.connectivity) => Ok(()),
        result = read_control => result,
        result = write_input => result,
        result = read_frames => result,
        _ = connection.closed() => Ok(()),
    }
}

/// Draw each update from a host that sends them, and say when it is shown.
async fn read_updates(
    frames: &watch::Sender<Option<Arc<Frame>>>,
    damage: &Mutex<Damage>,
    received: &std::sync::atomic::AtomicU64,
    mut stream: iroh::endpoint::RecvStream,
    shown: &watch::Sender<u64>,
    video: bool,
) -> Result<()> {
    let mut canvas = Some(screen::Canvas::default());
    loop {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).await?;
        let length = video::bounded(u32::from_be_bytes(length) as usize)?;
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        let mut skip = 0;
        received.fetch_add(length as u64 + 4, std::sync::atomic::Ordering::Relaxed);
        if video {
            match bytes[0] {
                video::KIND_TILES => skip = 1,
                video::KIND_VIDEO => {
                    let (seq, unit) = video::decode_unit(&bytes[1..])?;
                    show_video(frames, damage, unit);
                    shown.send_replace(seq);
                    continue;
                }
                // A kind a newer host sends that this helper does not know
                // carries nothing it has to draw.
                _ => continue,
            }
        }
        let mut drawing = canvas.take().context("Screen lost")?;
        let (drawing, result) = tokio::task::spawn_blocking(move || {
            let result = drawing.apply(&bytes[skip..]);
            (drawing, result)
        })
        .await?;
        canvas = Some(drawing);
        let (seq, frame, rects) = result?;
        show(frames, damage, frame, Some(rects));
        shown.send_replace(seq);
    }
}

/// Close code for a session the shared computer ended because something went
/// wrong there. The close reason carries what, for the helper to read.
const ENDED_WITH_REASON: u8 = 2;

/// Close code for a session the shared computer ended because the link to
/// the helper failed, such as the helper going silent. The helper treats it
/// as a lost link and connects again.
const LINK_FAILED: u8 = 3;

/// Close a session that was served, telling the helper why when it failed.
///
/// Before this, every session closed with the same "Session ended", so a
/// helper whose session was cut short by, say, a Mac without Screen Recording
/// permission saw only "connection lost" while the reason sat on a screen
/// nobody was looking at.
pub(crate) fn close_served(connection: &Connection, result: &Result<()>) {
    match result {
        Ok(()) => connection.close(0u8.into(), b"Session ended"),
        Err(error) => connection.close(
            if LinkLost::is(error) {
                LINK_FAILED
            } else {
                ENDED_WITH_REASON
            }
            .into(),
            close_reason(&format!("{error:#}")).as_bytes(),
        ),
    }
}

/// A reason short enough to fit in the close frame, which has to travel in
/// one packet, cut at a character boundary.
fn close_reason(reason: &str) -> &str {
    const MAX: usize = 400;
    if reason.len() <= MAX {
        return reason;
    }
    let mut end = MAX;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

/// Why the shared computer ended this session, when it said, as the error
/// the helper should report.
fn ended_by_host(connection: &Connection) -> Option<anyhow::Error> {
    match connection.close_reason()? {
        iroh::endpoint::ConnectionError::ApplicationClosed(close)
            if close.error_code == ENDED_WITH_REASON.into() =>
        {
            Some(anyhow!(
                "That computer ended the session: {}",
                String::from_utf8_lossy(&close.reason)
            ))
        }
        iroh::endpoint::ConnectionError::ApplicationClosed(close)
            if close.error_code == LINK_FAILED.into() =>
        {
            Some(link_lost(anyhow!(
                "The connection to that computer was lost: {}",
                String::from_utf8_lossy(&close.reason)
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;

    #[test]
    fn relay_urls_reject_other_protocols_and_embedded_secrets() {
        for bad in [
            "turn:relay.example",
            "ftp://relay.example",
            "https://user:secret@relay.example",
            "https://relay.example?token=secret",
            "https://relay.example/#secret",
        ] {
            assert!(parse_relay_url(bad).is_err());
        }
        assert!(parse_relay_url("https://relay.example").is_ok());
        assert!(parse_relay_url("http://127.0.0.1:3340").is_ok());
    }

    #[tokio::test]
    async fn private_host_advertises_only_bound_address_and_disables_helper_relay() -> Result<()> {
        let ip = "127.0.0.1".parse()?;
        let endpoint = endpoint(&HostOptions {
            relay: false,
            relay_url: None,
            bind_ip: Some(ip),
        })
        .await?;
        let _guard = EndpointGuard(endpoint.clone());
        let address = endpoint.addr();
        ensure!(
            address.relay_urls().next().is_none(),
            "Private host advertised a relay"
        );
        let ips: Vec<_> = address.ip_addrs().collect();
        ensure!(
            !ips.is_empty() && ips.iter().all(|addr| addr.ip() == ip),
            "Private host advertised another interface"
        );
        let invitation = Invitation {
            version: 1,
            address,
            secret: [0; 32],
            expires: wire::now() + 60,
        };
        let viewer = viewer_network_options(&invitation, HostOptions::default());
        ensure!(
            !viewer.relay && viewer.relay_url.is_none(),
            "Private ticket enabled helper relay"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "contacts public n0 relays; run explicitly"]
    async fn public_relay_carries_a_frame_without_direct_ip_transport() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(45), async {
            let host = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Default)
                .clear_ip_transports()
                .alpns(vec![wire::ALPN.to_vec()])
                .bind()
                .await?;
            let _host_guard = EndpointGuard(host.clone());
            let viewer = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Default)
                .clear_ip_transports()
                .bind()
                .await?;
            let _viewer_guard = EndpointGuard(viewer.clone());
            host.online().await;
            viewer.online().await;
            let address = host.addr();
            ensure!(
                address.ip_addrs().next().is_none(),
                "Test must not use a direct address"
            );
            let (sender, receiver) = tokio::try_join!(
                async {
                    viewer
                        .connect(address, wire::ALPN)
                        .await
                        .map_err(anyhow::Error::from)
                },
                async {
                    host.accept()
                        .await
                        .context("Listener closed")?
                        .await
                        .map_err(anyhow::Error::from)
                },
            )?;
            let _sender_guard = Close(sender.clone());
            let _receiver_guard = Close(receiver.clone());
            let expected = Frame {
                width: 2,
                height: 1,
                rgba: vec![12, 34, 56, 255, 7, 8, 9, 255],
            };
            let encoded = expected.encode()?;
            let ((), frame) = tokio::try_join!(
                async {
                    let mut stream = sender.open_uni().await?;
                    stream.write_all(&encoded).await?;
                    stream.finish()?;
                    stream.stopped().await?;
                    Ok::<(), anyhow::Error>(())
                },
                async {
                    let mut stream = receiver.accept_uni().await?;
                    Frame::decode(&stream.read_to_end(wire::MAX_FRAME).await?)
                },
            )?;
            ensure!(frame.rgba == expected.rgba, "Relay corrupted the screen");
            ensure!(
                route_snapshot(&sender).0 == Route::Relay,
                "Expected observed relay route"
            );
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Public relay test timed out")?
    }
}
