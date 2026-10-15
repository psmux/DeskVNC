use crate::{
    Desktop, Frame, Input, Invitation, tools,
    wire::{self, Message},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use iroh::{
    Endpoint, RelayMode,
    endpoint::{Connection, presets},
};
use std::{
    sync::Arc,
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
    input: mpsc::Sender<Input>,
    control: watch::Sender<Permission>,
    /// On the host's side, whether the person allows commands and files. On
    /// the helper's side, what the host last said about it.
    tools: watch::Sender<bool>,
    client: watch::Receiver<Option<tools::Client>>,
    pairing: mpsc::Sender<(String, String)>,
    cancel: CancellationToken,
}
impl Session {
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
    input: mpsc::Receiver<Input>,
    control: watch::Receiver<Permission>,
    control_tx: watch::Sender<Permission>,
    pub(crate) tools_tx: watch::Sender<bool>,
    client: watch::Sender<Option<tools::Client>>,
    pairing: mpsc::Receiver<(String, String)>,
    cancel: CancellationToken,
}
pub(crate) fn channels() -> (Session, Worker) {
    let (connectivity_tx, connectivity) = watch::channel(Connectivity::default());
    let (events_tx, events) = mpsc::channel(32);
    let (frames_tx, frames) = watch::channel(None);
    let (input, input_rx) = mpsc::channel(128);
    let (pairing, pairing_rx) = mpsc::channel(4);
    let (control, control_rx) = watch::channel(Permission {
        allowed: false,
        generation: 0,
    });
    // Off until somebody says otherwise, on both sides.
    let (tools_tx, _) = watch::channel(false);
    let (client_tx, client) = watch::channel(None);
    let cancel = CancellationToken::new();
    (
        Session {
            connectivity,
            events,
            frames,
            input,
            control: control.clone(),
            tools: tools_tx.clone(),
            client,
            pairing,
            cancel: cancel.clone(),
        },
        Worker {
            connectivity: connectivity_tx,
            events: events_tx,
            frames: frames_tx,
            input: input_rx,
            control: control_rx,
            control_tx: control.clone(),
            tools_tx,
            client: client_tx,
            pairing: pairing_rx,
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
    viewer_inner(ticket, name, options, key, false)
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
    viewer_inner(ticket, name, options, key, true)
}
fn viewer_inner(
    ticket: String,
    name: String,
    options: HostOptions,
    key: Option<iroh::SecretKey>,
    tools: bool,
) -> Session {
    let (session, mut worker) = channels();
    tokio::spawn(async move {
        let cancel = worker.cancel.clone();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = run_viewer(&mut worker, ticket, name, options, key, tools) => result,
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
pub(crate) async fn endpoint_with(
    options: &HostOptions,
    key: Option<iroh::SecretKey>,
    lookup: Lookup,
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
        .dns_resolver(crate::dns::resolver());
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
            .bind_addr(std::net::SocketAddr::new(ip, 0))?;
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
            let (name, tools, jpeg) = wire::validate_hello(wire::read(&mut recv).await?, &invite)?;
            Ok::<_, anyhow::Error>((guard, send, recv, name, tools, jpeg))
        };
        let Ok(Ok((guard, mut send, recv, name, tools, jpeg))) =
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
            worker, connection, send, recv, peer, allowed, tools, jpeg, desktop,
        )
        .await;
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
    jpeg: bool,
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
    let (screen_tx, screen_rx) = watch::channel(None::<Arc<Vec<u8>>>);
    let cancel = worker.cancel.clone();
    let capture = tokio::task::spawn_blocking(move || {
        desktop_loop(desktop, input_rx, permission_rx, screen_tx, cancel, jpeg)
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
    let result = tokio::select! {
        _ = monitor_route(connection, &worker.connectivity) => Ok(()),
        result = read_input => result,
        result = write_control => result,
        result = serve_tools => result,
        result = send_screens(connection, screen_rx) => result,
        result = capture => result.context("Capture worker failed")?,
        _ = connection.closed() => Ok(()),
    };
    result
}

fn desktop_loop<F>(
    factory: F,
    mut input: mpsc::Receiver<(u64, Input)>,
    permission: watch::Receiver<Permission>,
    screens: watch::Sender<Option<Arc<Vec<u8>>>>,
    cancel: CancellationToken,
    jpeg: bool,
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
    let mut capture_at = Instant::now();
    let mut last_input = Instant::now();
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
                }
            }
            last_input = Instant::now();
        }
        if cancel.is_cancelled() {
            break;
        }
        if Instant::now() >= capture_at {
            let frame = desktop.0.capture()?;
            let encoded = Arc::new(if jpeg {
                frame.encode_jpeg()?
            } else {
                frame.encode()?
            });
            if !cancel.is_cancelled() {
                screens.send_replace(Some(encoded));
            }
            capture_at = Instant::now() + Duration::from_millis(125);
        }
        std::thread::sleep(Duration::from_millis(8));
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

async fn send_screens(
    connection: &Connection,
    mut screens: watch::Receiver<Option<Arc<Vec<u8>>>>,
) -> Result<()> {
    let mut last: Option<Arc<Vec<u8>>> = None;
    loop {
        screens.changed().await?;
        let bytes = screens
            .borrow_and_update()
            .clone()
            .context("Missing screen")?;
        // A still screen is captured eight times a second; sending the same
        // picture again only costs the link.
        if last.as_ref().is_some_and(|last| **last == *bytes) {
            continue;
        }
        let mut stream = connection.open_uni().await?;
        let result = tokio::time::timeout(SCREEN_DEADLINE, async {
            stream.write_all(&bytes).await?;
            stream.finish()?;
            stream.stopped().await?;
            Ok::<(), anyhow::Error>(())
        })
        .await;
        match result {
            Ok(result) => {
                result?;
                last = Some(bytes);
            }
            Err(_) => {
                let _ = stream.reset(1u8.into());
            }
        }
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
    tools: bool,
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
    let endpoint = endpoint_with(&options, key, Lookup::Off).await?;
    let _endpoint_guard = EndpointGuard(endpoint.clone());
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
            tools,
            jpeg: true,
        },
    )
    .await?;
    let result = watch_session(worker, &connection, send, recv).await;
    drop(guard);
    endpoint.close().await;
    result
}
/// The helper's side of a session once its request is on the wire: wait to
/// be let in, then show screens, send input and keep the session alive.
/// Shared by invitations and unattended connections.
pub(crate) async fn watch_session(
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
        Message::Refused(reason) => bail!("{reason}"),
        _ => bail!("The person declined this connection"),
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
                _ = tick.tick() => Message::Ping,
            };
            tokio::time::timeout(Duration::from_secs(3), wire::write(&mut send, &message))
                .await
                .context("Input connection stalled")??;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let read_frames = async {
        loop {
            let mut stream = connection.accept_uni().await?;
            let bytes =
                match tokio::time::timeout(SCREEN_DEADLINE, stream.read_to_end(wire::MAX_FRAME))
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
            let frame = tokio::task::spawn_blocking(move || Frame::decode(&bytes)).await??;
            worker.frames.send_replace(Some(Arc::new(frame)));
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
