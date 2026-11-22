//! The reconnect ladder, the auto reconnect cookie and Server Redirection,
//! end to end over a real socket (PRDRDP/06 §5, §9.3).
//!
//! # What drives the supervisor here
//!
//! `remote_core::reconnect::supervise` is the production ladder and it is
//! what runs in every test in this file. What is stubbed is one step:
//! [`MockConnect::run_once`] opens a plain TCP socket and runs
//! `connection::negotiate_security` and `connection::after_upgrade` itself
//! instead of calling `session::connect::run_once`, because the mock has no
//! certificate and the production path upgrades to TLS between those two
//! calls. `tests/connect.rs` splits the sequence the same way and says so at
//! `crates/rdp-core/tests/common/mock_rdp_server.rs:23`.
//!
//! Everything either side of that step is the real code: the same
//! `RunLoop`, the same cookie store, the same
//! `session::absorb_attempt` the driver uses to decide what a finished
//! attempt means, and the same `ReconnectPolicy` ladder.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use common::mock_rdp_server::{
    utf16z, MockConfig, MockRdpServer, Negotiation, SessionBehaviour, COOKIE_LOGON_ID,
    COOKIE_RANDOM_BITS, HANDOVER_GUID, HANDOVER_PASSWORD, HANDOVER_ROUTING_TOKEN,
    HANDOVER_USERNAME, REDIRECT_ROUTING_TOKEN, REDIRECT_SESSION_ID, REDIRECT_USERNAME,
};
use common::{dial_host, options_for, rdp_half, DEFAULT_TIMEOUT};
use rdp_core::error::RdpError;
use rdp_core::options::ResolvedOptions;
use rdp_core::session::cookie::{security_verifier, CLIENT_RANDOM_ZEROS};
use rdp_core::session::run_loop::RunLoop;
use rdp_core::session::settings::RdpSessionSettings;
use rdp_core::session::{absorb_attempt, Continuity};
use rdp_core::{connection, transport::writer};
use remote_core::reconnect::{ConnectOnce, RunOutcome};
use remote_core::{
    ClientCommand, ConnectOptions, ProtocolEvent, RdpEvent, ReconnectPolicy, SessionEvent,
    SessionState,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vnc_transport::TrustDecision;

/// One attempt against the mock: everything `session::connect::run_once` does
/// except opening the stream and upgrading it.
struct MockConnect {
    options: ConnectOptions,
    settings: RdpSessionSettings,
    carry: Continuity,
    /// How many attempts this implementor has started, so a test can assert
    /// the ladder actually went round.
    attempts: usize,
}

impl MockConnect {
    fn new(options: ConnectOptions) -> Self {
        let settings = RdpSessionSettings::from_options(&options);
        Self {
            options,
            settings,
            carry: Continuity::default(),
            attempts: 0,
        }
    }
}

impl ConnectOnce for MockConnect {
    type Error = RdpError;

    fn policy(&self) -> &ReconnectPolicy {
        &self.options.reconnect
    }

    fn run_once<'a>(
        &'a mut self,
        events: &'a mpsc::Sender<SessionEvent>,
        commands: &'a mut mpsc::Receiver<ClientCommand>,
        cancel: &'a CancellationToken,
        connected_at: &'a mut Option<Instant>,
    ) -> Pin<Box<dyn Future<Output = Result<RunOutcome, RdpError>> + Send + 'a>> {
        Box::pin(async move {
            self.attempts += 1;
            let rdp = rdp_half(&self.options);
            let mut opts =
                ResolvedOptions::resolve(&self.options, &rdp, &mut Vec::new()).expect("valid");
            self.carry.prime(&mut opts);

            // The cookie half of `session::connect::run_once`: offer what is
            // stored and not stale (MS-RDPBCGR 2.2.4.3).
            let arc = self
                .carry
                .cookie
                .as_ref()
                .filter(|c| !c.is_stale(Instant::now()))
                .map(|c| c.client_packet());

            let stream = dial_host(&self.options.host, self.options.port).await?;
            let mut framer =
                rdp_core::transport::framer::Framer::new(stream, Arc::new(AtomicU64::new(0)));
            let selected =
                connection::negotiate_security(&mut framer, &opts, &self.options.credentials)
                    .await?;
            let connected = match connection::after_upgrade(
                &mut framer,
                &opts,
                &mut self.options.credentials.clone(),
                selected,
                None,
                TrustDecision::VerifiedByCa,
                arc,
                events,
                None,
            )
            .await
            {
                Ok(connected) => connected,
                Err(RdpError::Redirected(redirect)) => {
                    self.carry.redirect = Some(*redirect);
                    return Ok(absorb_attempt(
                        &mut self.options,
                        &mut self.carry,
                        rdp_core::session::run_loop::RunOutcome::ServerDisconnect {
                            user_requested: false,
                        },
                    ));
                }
                Err(e) => return Err(e),
            };

            remote_core::emit_state(events, SessionState::Connected).await?;
            *connected_at = Some(Instant::now());

            let (stream, buffered) = framer.into_inner();
            let (read_half, write_half) = tokio::io::split(stream);
            let received = Arc::new(AtomicU64::new(0));
            let sent = Arc::new(AtomicU64::new(0));
            let mut framer = rdp_core::transport::framer::Framer::new(read_half, received.clone());
            framer.prime(buffered);
            let (outbound, rx) = mpsc::channel(writer::WRITER_QUEUE);
            let writer_task = tokio::spawn(writer::writer_task(write_half, rx, sent.clone()));

            let mut run_loop = RunLoop::new(
                framer,
                outbound,
                connected.channels,
                opts.clone(),
                connected.activation,
                self.settings.view_only,
                received,
                sent,
            );
            let outcome = run_loop
                .run(connected.pending, events, commands, cancel)
                .await;

            if run_loop.cookie_discarded() {
                self.carry.cookie = None;
            }
            if let Some(cookie) = run_loop.take_cookie() {
                self.carry.cookie = Some(cookie);
            }
            if let Some(redirect) = run_loop.take_redirect() {
                self.carry.redirect = Some(redirect);
            }
            drop(run_loop);
            let _ = writer_task.await;

            match outcome {
                Ok(attempt) => Ok(absorb_attempt(&mut self.options, &mut self.carry, attempt)),
                Err(e) => {
                    // A redirection recorded by the pump outlives the error
                    // the socket produced afterwards, which is what makes a
                    // redirect followed by a close still a redirect.
                    if self.carry.redirect.is_some() {
                        return Ok(absorb_attempt(
                            &mut self.options,
                            &mut self.carry,
                            rdp_core::session::run_loop::RunOutcome::ServerDisconnect {
                                user_requested: false,
                            },
                        ));
                    }
                    Err(e)
                }
            }
        })
    }

    fn absorb_while_disconnected(&mut self, cmd: &ClientCommand) {
        self.settings.absorb(cmd);
    }
}

/// A ladder with millisecond delays, so a test that has to see two attempts
/// takes milliseconds rather than seconds.
fn fast_ladder(options: &mut ConnectOptions, max_attempts: Option<u32>) {
    options.reconnect = ReconnectPolicy {
        enabled: true,
        max_attempts,
        initial_delay_ms: 1,
        max_delay_ms: 5,
        multiplier: 2.0,
        jitter: 0.0,
    };
}

/// Collect events until the session reaches a terminal state.
async fn drain(rx: &mut mpsc::Receiver<SessionEvent>) -> Vec<SessionEvent> {
    let mut out = Vec::new();
    while let Some(event) = rx.recv().await {
        out.push(event);
    }
    out
}

fn states(events: &[SessionEvent]) -> Vec<&SessionState> {
    events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::StateChanged(s) => Some(s),
            _ => None,
        })
        .collect()
}

/// A connection that drops with no ultimatum is transient, so the supervisor
/// climbs the ladder and comes back. The second connection is a whole session
/// again, which is what "the RDP session reconnects" has to mean.
///
/// This is the test the lane exists for: before it, `rdp-core` ran one attempt
/// and stopped.
#[tokio::test]
async fn a_dropped_connection_is_retried_and_the_second_one_serves() {
    let server = MockRdpServer::start_sequence(vec![
        MockConfig {
            session: SessionBehaviour::CookieThenDrop,
            ..MockConfig::default()
        },
        MockConfig::default(),
    ])
    .await;

    let mut options = options_for(server.addr);
    fast_ladder(&mut options, Some(3));
    let (events_tx, mut events_rx) = mpsc::channel(256);
    let (commands_tx, commands_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();

    let supervisor = tokio::spawn(remote_core::reconnect::supervise(
        "reconnect".into(),
        MockConnect::new(options),
        events_tx,
        commands_rx,
        cancel.clone(),
    ));

    // The second connection serves a picture. Once it has, hang up: the
    // session ended by choice rather than by running out of attempts.
    let mut events = Vec::new();
    let mut connected = 0usize;
    while let Some(event) = events_rx.recv().await {
        let drew = matches!(event, SessionEvent::FramebufferUpdate { .. });
        events.push(event);
        if drew {
            connected += 1;
            commands_tx
                .send(ClientCommand::Disconnect)
                .await
                .expect("the session is listening");
            break;
        }
    }
    assert_eq!(connected, 1, "the second attempt drew the picture");

    events.extend(
        tokio::time::timeout(DEFAULT_TIMEOUT, drain(&mut events_rx))
            .await
            .expect("the session ended inside the timeout"),
    );
    supervisor.await.expect("the supervisor finished");

    let recorded = server.wait_until(|r| r.connections >= 2).await;
    assert_eq!(recorded.connections, 2, "the client came back");

    let saw_reconnecting = states(&events)
        .iter()
        .any(|s| matches!(s, SessionState::Reconnecting { attempt: 1, .. }));
    assert!(saw_reconnecting, "the UI was told a retry was in progress");
}

/// MS-RDPBCGR 2.2.4: the cookie the first connection was given goes out in the
/// second connection's Client Info PDU, with the logon id echoed and the
/// verifier derived per 5.5 step 4.
///
/// Getting the verifier wrong is invisible in the field: the client still
/// connects, it just lands in a new Windows session while the user's old one
/// keeps running with their work in it.
#[tokio::test]
async fn the_second_attempt_offers_the_cookie_the_first_was_given() {
    let server = MockRdpServer::start_sequence(vec![
        MockConfig {
            session: SessionBehaviour::CookieThenDrop,
            ..MockConfig::default()
        },
        MockConfig::default(),
    ])
    .await;

    let mut options = options_for(server.addr);
    fast_ladder(&mut options, Some(2));
    let (events_tx, mut events_rx) = mpsc::channel(256);
    let (commands_tx, commands_rx) = mpsc::channel(16);

    let supervisor = tokio::spawn(remote_core::reconnect::supervise(
        "cookie".into(),
        MockConnect::new(options),
        events_tx,
        commands_rx,
        CancellationToken::new(),
    ));

    let mut armed = false;
    while let Some(event) = events_rx.recv().await {
        if matches!(
            event,
            SessionEvent::Protocol(ProtocolEvent::Rdp(RdpEvent::AutoReconnectArmed))
        ) {
            armed = true;
        }
        if matches!(event, SessionEvent::FramebufferUpdate { .. }) {
            let _ = commands_tx.send(ClientCommand::Disconnect).await;
            break;
        }
    }
    assert!(armed, "the shell was told a fast reconnect became possible");

    let _ = tokio::time::timeout(DEFAULT_TIMEOUT, drain(&mut events_rx)).await;
    supervisor.await.expect("the supervisor finished");

    let recorded = server
        .wait_until(|r| r.auto_reconnect_cookies.len() >= 2)
        .await;
    assert_eq!(
        recorded.auto_reconnect_cookies.len(),
        2,
        "two connections, two client info pdus"
    );
    assert!(
        recorded.auto_reconnect_cookies[0].is_none(),
        "the first attempt has no cookie to offer"
    );
    let offered = recorded.auto_reconnect_cookies[1].expect("the second attempt offered one");
    assert_eq!(offered.logon_id, COOKIE_LOGON_ID, "the logon id is echoed");
    assert_eq!(
        offered.security_verifier,
        security_verifier(&COOKIE_RANDOM_BITS, &CLIENT_RANDOM_ZEROS),
        "SecurityVerifier = HMAC-MD5(ArcRandomBits, 32 zero bytes) (MS-RDPBCGR 5.5 step 4)"
    );
}

/// A redirection that names no target and carries no routing token has
/// nowhere to go, and ends the session with a sentence at once rather than a
/// blank picture until the server gives up on us.
#[tokio::test]
async fn a_redirection_with_nowhere_to_go_stops_with_a_sentence() {
    let server = MockRdpServer::start(MockConfig {
        session: SessionBehaviour::RedirectNowhere,
        ..MockConfig::default()
    })
    .await;

    let mut options = options_for(server.addr);
    fast_ladder(&mut options, Some(2));
    let (events_tx, mut events_rx) = mpsc::channel(256);
    let (_commands_tx, commands_rx) = mpsc::channel(16);

    let supervisor = tokio::spawn(remote_core::reconnect::supervise(
        "handover".into(),
        MockConnect::new(options),
        events_tx,
        commands_rx,
        CancellationToken::new(),
    ));
    let events = tokio::time::timeout(DEFAULT_TIMEOUT, drain(&mut events_rx))
        .await
        .expect("the session ended inside the timeout");
    supervisor.await.expect("the supervisor finished");

    let states = states(&events);
    assert!(
        !states
            .iter()
            .any(|s| matches!(s, SessionState::Reconnecting { .. })),
        "{states:?}"
    );
    match states.last() {
        Some(SessionState::Disconnected { reason, .. }) => {
            assert!(reason.contains("hand this session over"), "{reason}");
        }
        other => panic!("expected a disconnect with a reason, got {other:?}"),
    }
    assert_eq!(server.recorded().connections, 1, "nothing to dial");
}

/// MS-RDPBCGR 2.2.13.1 and 3.2.5.3.1: a broker names another host, and the
/// client hangs up and dials it, presenting the `LoadBalanceInfo` as the
/// routing token of the new Connection Request and using the user name the
/// packet carried.
///
/// The redirect is not a reconnect: no `Reconnecting` state reaches the UI,
/// because the session is not in trouble, it is moving.
#[tokio::test]
async fn a_redirection_is_followed_with_its_routing_token() {
    let server = MockRdpServer::start_sequence(vec![
        MockConfig {
            session: SessionBehaviour::RedirectAfterLogon,
            ..MockConfig::default()
        },
        MockConfig::default(),
    ])
    .await;

    let mut options = options_for(server.addr);
    fast_ladder(&mut options, Some(2));
    let (events_tx, mut events_rx) = mpsc::channel(256);
    let (commands_tx, commands_rx) = mpsc::channel(16);

    let supervisor = tokio::spawn(remote_core::reconnect::supervise(
        "redirect".into(),
        MockConnect::new(options),
        events_tx,
        commands_rx,
        CancellationToken::new(),
    ));

    let mut redirected = None;
    let mut events = Vec::new();
    while let Some(event) = events_rx.recv().await {
        if let SessionEvent::Protocol(ProtocolEvent::Rdp(RdpEvent::Redirected {
            target,
            session_id,
        })) = &event
        {
            redirected = Some((target.clone(), *session_id));
        }
        let drew = matches!(event, SessionEvent::FramebufferUpdate { .. });
        events.push(event);
        if drew {
            let _ = commands_tx.send(ClientCommand::Disconnect).await;
            break;
        }
    }

    events.extend(
        tokio::time::timeout(DEFAULT_TIMEOUT, drain(&mut events_rx))
            .await
            .expect("the session ended inside the timeout"),
    );
    supervisor.await.expect("the supervisor finished");

    let (target, session_id) = redirected.expect("the shell was told about the redirection");
    assert!(target.contains("127.0.0.1"), "{target}");
    assert_eq!(session_id, REDIRECT_SESSION_ID);

    let recorded = server.wait_until(|r| r.connections >= 2).await;
    assert_eq!(recorded.connections, 2, "the client dialled the target");
    assert_eq!(
        recorded.routing_tokens.len(),
        2,
        "one connection request each"
    );
    assert!(
        recorded.routing_tokens[0].is_none(),
        "nothing to route by on the first dial"
    );
    assert_eq!(
        recorded.routing_tokens[1].as_deref(),
        Some(REDIRECT_ROUTING_TOKEN),
        "the LoadBalanceInfo came back as the routing token (MS-RDPBCGR 3.2.5.3.1)"
    );

    let info = recorded.client_info.expect("the second client info pdu");
    assert_eq!(
        info.info.user_name, REDIRECT_USERNAME,
        "the redirection's user name was used for the reconnection"
    );

    assert!(
        !states(&events)
            .iter()
            .any(|s| matches!(s, SessionState::Reconnecting { .. })),
        "a redirection is not a retry: {:?}",
        states(&events)
    );
}

/// GNOME Remote Login (issue #59). Once the user signs in at the remote login
/// screen, gnome-remote-desktop sends a redirection with no address, a
/// `LoadBalanceInfo` of `Cookie: msts=<token>\r\n`, a one time user name, a
/// password flagged `LB_PASSWORD_IS_PK_ENCRYPTED` and a `RedirectionGuid`.
/// The client has to dial the same host again, present the token as the
/// routing token, offer `PROTOCOL_RDSTLS`, and sign in with RDSTLS
/// presenting the GUID, the user name and the password bytes unchanged
/// (MS-RDPBCGR 3.2.5.3.1, 5.4.5.3). The handover daemon refuses anything
/// else, so the session only draws if every one of those is right.
#[tokio::test]
async fn a_gnome_handover_is_followed_to_the_same_host_with_rdstls() {
    let server = MockRdpServer::start_sequence(vec![
        MockConfig {
            session: SessionBehaviour::HandoverWithoutTarget,
            ..MockConfig::default()
        },
        MockConfig {
            negotiation: Negotiation::Rdstls,
            ..MockConfig::default()
        },
    ])
    .await;

    let mut options = options_for(server.addr);
    fast_ladder(&mut options, Some(2));
    let (events_tx, mut events_rx) = mpsc::channel(256);
    let (commands_tx, commands_rx) = mpsc::channel(16);

    let supervisor = tokio::spawn(remote_core::reconnect::supervise(
        "gnome-handover".into(),
        MockConnect::new(options),
        events_tx,
        commands_rx,
        CancellationToken::new(),
    ));

    let mut redirected = None;
    let mut drew = false;
    let mut events = Vec::new();
    let collect = async {
        while let Some(event) = events_rx.recv().await {
            if let SessionEvent::Protocol(ProtocolEvent::Rdp(RdpEvent::Redirected {
                target, ..
            })) = &event
            {
                redirected = Some(target.clone());
            }
            let frame = matches!(event, SessionEvent::FramebufferUpdate { .. });
            events.push(event);
            if frame {
                drew = true;
                let _ = commands_tx.send(ClientCommand::Disconnect).await;
                break;
            }
        }
    };
    tokio::time::timeout(DEFAULT_TIMEOUT, collect)
        .await
        .expect("the handed over session drew inside the timeout");
    events.extend(
        tokio::time::timeout(DEFAULT_TIMEOUT, drain(&mut events_rx))
            .await
            .expect("the session ended inside the timeout"),
    );
    supervisor.await.expect("the supervisor finished");

    assert!(drew, "the handed over session drew: {:?}", states(&events));
    let target = redirected.expect("the shell was told about the handover");
    assert!(target.contains("same server"), "{target}");
    assert!(
        !target.contains("3147902345"),
        "no token in the event: {target}"
    );

    let recorded = server.wait_until(|r| !r.rdstls_requests.is_empty()).await;
    assert_eq!(recorded.connections, 2, "one handover, one more dial");
    assert_eq!(
        recorded.routing_tokens[1].as_deref(),
        Some(HANDOVER_ROUTING_TOKEN),
        "the token went back without a second Cookie: msts= prefix"
    );
    assert_eq!(
        recorded.requested_protocols[0] & rdp_pdu::x224::security_protocol::RDSTLS,
        0,
        "no RDSTLS on the first dial"
    );
    assert_ne!(
        recorded.requested_protocols[1] & rdp_pdu::x224::security_protocol::RDSTLS,
        0,
        "RDSTLS offered after the handover"
    );
    let request = &recorded.rdstls_requests[0];
    assert_eq!(request.username, HANDOVER_USERNAME);
    assert_eq!(request.redirection_guid, utf16z(HANDOVER_GUID));
    assert_eq!(
        request.password.expose(),
        utf16z(HANDOVER_PASSWORD).as_slice()
    );

    let info = recorded.client_info.expect("the second client info pdu");
    assert_eq!(info.info.user_name, HANDOVER_USERNAME);
    assert!(
        info.info.password.is_empty(),
        "the cookie is never sent as a password"
    );
    assert!(
        !states(&events)
            .iter()
            .any(|s| matches!(s, SessionState::Reconnecting { .. })),
        "a handover is not a retry: {:?}",
        states(&events)
    );
}

/// A server that hands every RDSTLS connection over again would send the
/// client round the same host forever. The same host path goes through the
/// supervisor's bound on chained redirections like any other redirection.
#[tokio::test]
async fn a_handover_loop_stops() {
    let server = MockRdpServer::start_sequence(vec![
        MockConfig {
            session: SessionBehaviour::HandoverWithoutTarget,
            ..MockConfig::default()
        },
        MockConfig {
            negotiation: Negotiation::Rdstls,
            session: SessionBehaviour::HandoverWithoutTarget,
            ..MockConfig::default()
        },
    ])
    .await;

    let mut options = options_for(server.addr);
    fast_ladder(&mut options, Some(2));
    let (events_tx, mut events_rx) = mpsc::channel(1024);
    let (_commands_tx, commands_rx) = mpsc::channel(16);

    let supervisor = tokio::spawn(remote_core::reconnect::supervise(
        "redirect-loop".into(),
        MockConnect::new(options),
        events_tx,
        commands_rx,
        CancellationToken::new(),
    ));
    let events = tokio::time::timeout(DEFAULT_TIMEOUT, drain(&mut events_rx))
        .await
        .expect("the loop was stopped inside the timeout");
    supervisor.await.expect("the supervisor finished");

    match states(&events).last() {
        Some(SessionState::Disconnected { reason, .. }) => {
            assert!(reason.contains("kept redirecting"), "{reason}");
        }
        other => panic!("expected a disconnect with a reason, got {other:?}"),
    }
    let max = remote_core::reconnect::MAX_CHAINED_REATTEMPTS as usize;
    let recorded = server.wait_until(|r| r.connections > max).await;
    assert_eq!(
        recorded.connections,
        max + 1,
        "every handover up to the bound was followed, and no more"
    );
    assert_eq!(
        recorded.rdstls_requests.len(),
        max,
        "each one signed in with rdstls"
    );
}
