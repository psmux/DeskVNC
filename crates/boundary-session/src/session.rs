use crate::{
    Desktop, Frame, Input, Invitation,
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
    Approval {
        name: String,
        peer: String,
        answer: oneshot::Sender<Approval>,
    },
    Connected {
        peer: String,
        control: bool,
    },
    Control(bool),
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
    cancel: CancellationToken,
}
impl Session {
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
        if self.input.try_send(input).is_err() {
            // Never silently lose a key release when the queue fills.
            self.stop();
            bail!("Input queue is full or disconnected. Session stopped");
        }
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}
struct Worker {
    connectivity: watch::Sender<Connectivity>,
    events: mpsc::Sender<Event>,
    frames: watch::Sender<Option<Arc<Frame>>>,
    input: mpsc::Receiver<Input>,
    control: watch::Receiver<Permission>,
    control_tx: watch::Sender<Permission>,
    cancel: CancellationToken,
}
fn channels() -> (Session, Worker) {
    let (connectivity_tx, connectivity) = watch::channel(Connectivity::default());
    let (events_tx, events) = mpsc::channel(32);
    let (frames_tx, frames) = watch::channel(None);
    let (input, input_rx) = mpsc::channel(128);
    let (control, control_rx) = watch::channel(Permission {
        allowed: false,
        generation: 0,
    });
    let cancel = CancellationToken::new();
    (
        Session {
            connectivity,
            events,
            frames,
            input,
            control: control.clone(),
            cancel: cancel.clone(),
        },
        Worker {
            connectivity: connectivity_tx,
            events: events_tx,
            frames: frames_tx,
            input: input_rx,
            control: control_rx,
            control_tx: control.clone(),
            cancel,
        },
    )
}
impl Worker {
    async fn emit(&self, event: Event) -> Result<()> {
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
    let (session, mut worker) = channels();
    tokio::spawn(async move {
        let cancel = worker.cancel.clone();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = run_viewer(&mut worker, ticket, name, options) => result,
        };
        worker.cancel.cancel();
        let _ = worker.emit(Event::Finished(result)).await;
    });
    session
}
async fn endpoint(options: &HostOptions) -> Result<Endpoint> {
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
    // The invitation includes the address; publishing a directory entry is unnecessary.
    let mut builder = Endpoint::builder(presets::Minimal)
        .relay_mode(relay)
        .alpns(vec![wire::ALPN.to_vec()]);
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
            let name = wire::validate_hello(wire::read(&mut recv).await?, &invite)?;
            Ok::<_, anyhow::Error>((guard, send, recv, name))
        };
        let Ok(Ok((guard, mut send, mut recv, name))) =
            tokio::time::timeout(Duration::from_secs(5), handshake).await
        else {
            continue;
        };
        let connection = &guard.0;
        let peer = connection.remote_id().to_string();
        let (answer, decision) = oneshot::channel();
        worker
            .emit(Event::Approval {
                name,
                peer: peer.clone(),
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
            desktop_loop(desktop, input_rx, permission_rx, screen_tx, cancel)
        });
        wire::write(&mut send, &Message::Granted { control: allowed }).await?;
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
                            input_tx
                                .try_send((permission.generation, input))
                                .map_err(|_| anyhow!("Input rate exceeded. Session stopped"))?;
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
                worker.control.changed().await?;
                let control = worker.control.borrow_and_update().allowed;
                wire::write(&mut send, &Message::Control(control)).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };
        let result = tokio::select! {
            _ = monitor_route(connection, &worker.connectivity) => Ok(()),
            result = read_input => result,
            result = write_control => result,
            result = send_screens(connection, screen_rx) => result,
            result = capture => result.context("Capture worker failed")?,
            _ = connection.closed() => Ok(()),
        };
        drop(guard);
        endpoint.close().await;
        return result;
    }
}
fn desktop_loop<F>(
    factory: F,
    mut input: mpsc::Receiver<(u64, Input)>,
    permission: watch::Receiver<Permission>,
    screens: watch::Sender<Option<Arc<Vec<u8>>>>,
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
            let encoded = Arc::new(frame.encode()?);
            if !cancel.is_cancelled() {
                screens.send_replace(Some(encoded));
            }
            capture_at = Instant::now() + Duration::from_millis(125);
        }
        std::thread::sleep(Duration::from_millis(8));
    }
    Ok(())
}
async fn send_screens(
    connection: &Connection,
    mut screens: watch::Receiver<Option<Arc<Vec<u8>>>>,
) -> Result<()> {
    loop {
        screens.changed().await?;
        let bytes = screens
            .borrow_and_update()
            .clone()
            .context("Missing screen")?;
        let mut stream = connection.open_uni().await?;
        let result = tokio::time::timeout(Duration::from_millis(750), async {
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
    let endpoint = endpoint(&options).await?;
    let _endpoint_guard = EndpointGuard(endpoint.clone());
    let connection = tokio::time::timeout(
        Duration::from_secs(25),
        endpoint.connect(invitation.address, wire::ALPN),
    )
    .await
    .context("Connection timed out")??;
    let guard = Close(connection.clone());
    let (mut send, mut recv) = connection.open_bi().await?;
    wire::write(
        &mut send,
        &Message::Hello {
            version: 1,
            secret: invitation.secret,
            name,
        },
    )
    .await?;
    worker
        .emit(Event::Status(
            "Waiting for the person to approve sharing".into(),
        ))
        .await?;
    let grant: Message = tokio::time::timeout(Duration::from_secs(65), wire::read(&mut recv))
        .await
        .context("Approval timed out")??;
    let Message::Granted { control } = grant else {
        bail!("The person declined this connection");
    };
    worker
        .emit(Event::Connected {
            peer: connection.remote_id().to_string(),
            control,
        })
        .await?;
    let events = worker.events.clone();
    let read_control = async {
        loop {
            match wire::read::<Message>(&mut recv).await? {
                Message::Control(value) => {
                    events.send(Event::Control(value)).await?;
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
            let bytes = match tokio::time::timeout(
                Duration::from_secs(2),
                stream.read_to_end(wire::MAX_FRAME),
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
            let frame = tokio::task::spawn_blocking(move || Frame::decode(&bytes)).await??;
            worker.frames.send_replace(Some(Arc::new(frame)));
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::select! {
        _ = monitor_route(&connection, &worker.connectivity) => Ok(()),
        result = read_control => result,
        result = write_input => result,
        result = read_frames => result,
        _ = connection.closed() => Ok(()),
    };
    drop(guard);
    endpoint.close().await;
    result
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
