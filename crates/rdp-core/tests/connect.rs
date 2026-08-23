//! The acceptance test for the lane: drive a session from the first byte on
//! the socket to `Connected`, decode a bitmap, and round trip an input event,
//! over a real TCP socket, against a mock that encodes with the same encoders
//! the client parses with (PRDRDP/12 §8.4).
//!
//! # What this covers and what it cannot
//!
//! The production functions are used unchanged:
//! `connection::negotiate_security` for phase 1, `connection::after_upgrade`
//! for phases 2c to 10, and `RunLoop` for the connected pump. What sits
//! between the first two in a real session is the TLS handshake, and the mock
//! has no certificate to do one with, so the two halves are driven over the
//! same plain socket. That is a real composition rather than a bypass:
//! `connection::connect` calls the same two functions with
//! `transport::upgrade_tls` between them, and the split exists because the
//! handshake needs the whole stream rather than a read half.
//!
//! The missing piece is a committed test key pair
//! (PRDRDP/12 §3.14 `tests/common/certs.rs`), which is what would let the
//! mock stand up a TLS listener and the whole of `connection::connect`, TLS
//! and CredSSP included, run end to end.

mod common;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use common::mock_rdp_server::{
    McsBehaviour, MockConfig, MockRdpServer, Negotiation, SessionBehaviour, BITMAP_AT,
    IO_CHANNEL_ID, MESSAGE_CHANNEL_ID, SERVER_DESKTOP, SHARE_ID, USER_CHANNEL_ID,
};
use common::{options_for, rdp_half, DEFAULT_TIMEOUT};
use rdp_core::connection::{self, Connected, SecurityProtocol};
use rdp_core::options::ResolvedOptions;
use rdp_core::session::run_loop::{RunLoop, RunOutcome};
use rdp_core::transport::framer::Framer;
use rdp_core::transport::writer::{self, WRITER_QUEUE};
use rdp_core::RdpError;
use remote_core::{ClientCommand, Credentials, RectPayload, SessionEvent};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vnc_transport::TrustDecision;

/// Run the connection sequence against a mock and return what it produced.
///
/// Returns whatever the sequence reached: a [`Connected`] for a well behaved
/// server, or the error at the phase that stopped it.
async fn run_sequence(
    config: MockConfig,
    creds: Credentials,
) -> (
    MockRdpServer,
    Vec<SessionEvent>,
    Result<Connected, RdpError>,
) {
    let server = MockRdpServer::start(config).await;
    let mut options = options_for(server.addr);
    options.credentials = creds;
    let rdp = rdp_half(&options);
    let opts = ResolvedOptions::resolve(&options, &rdp, &mut Vec::new()).expect("valid options");

    let (events, mut event_rx) = mpsc::channel(256);
    let result = tokio::time::timeout(DEFAULT_TIMEOUT, async {
        let stream = TcpStream::connect(server.addr)
            .await
            .expect("the mock is up");
        let mut framer = Framer::new(stream, Arc::new(AtomicU64::new(0)));

        let selected =
            connection::negotiate_security(&mut framer, &opts, &options.credentials).await?;

        // In a real session `transport::upgrade_tls` runs here, between the
        // two halves. See this file's module documentation.
        connection::after_upgrade(
            &mut framer,
            &opts,
            &options.credentials,
            selected,
            None,
            TrustDecision::VerifiedByCa,
            &events,
        )
        .await
    })
    .await
    .expect("the sequence finished inside the timeout");

    drop(events);
    let mut drained = Vec::new();
    while let Some(event) = event_rx.recv().await {
        drained.push(event);
    }
    (server, drained, result)
}

/// The lane's acceptance test: every phase of MS-RDPBCGR 1.3.1.1 runs against
/// a real socket and the session reaches `Connected`.
#[tokio::test]
async fn a_session_reaches_connected() {
    let (server, events, result) = run_sequence(
        MockConfig::default(),
        Credentials::user_pass("CORP\\alice", "pw"),
    )
    .await;

    let connected = result.expect("the whole connection sequence completed");
    assert_eq!(connected.selected, SecurityProtocol::Ssl);
    assert_eq!(connected.activation.share_id, SHARE_ID);
    assert_eq!(
        connected.activation.desktop, SERVER_DESKTOP,
        "the desktop size is the server's answer, not our request"
    );

    let recorded = server.recorded();

    // Phase 1. The negotiation asked for TLS and CredSSP and nothing else,
    // and it carried no `mstshash` cookie, because the identifier travels in
    // cleartext ahead of the TLS upgrade (PRDRDP/00 R29).
    let request = recorded
        .connection_request
        .expect("an X.224 Connection Request reached the mock");
    let nego = request.nego.expect("an RDP_NEG_REQ");
    assert_eq!(
        nego.requested_protocols,
        connection::negotiate::REQUESTED_PROTOCOLS
    );
    assert!(request.cookie.is_none(), "the cookie defaults off");
    assert!(request.correlation.is_none());

    // Phase 3. The client's assertion of what was negotiated has to match
    // what the server selected, or a real server aborts (MS-RDPBCGR 2.2.1.3.2).
    let blocks = recorded
        .client_blocks
        .expect("the TS_UD_CS_* blocks reached the mock");
    let core = blocks.core.expect("a TS_UD_CS_CORE block");
    assert_eq!(
        core.server_selected_protocol,
        Some(SecurityProtocol::Ssl.wire())
    );
    // Both words zero is the "I am using an external security protocol"
    // signal, and anything else invites standard RDP security.
    let security = blocks.security.expect("a TS_UD_CS_SEC block");
    assert_eq!(security.encryption_methods, 0);
    assert_eq!(security.ext_encryption_methods, 0);
    let network = blocks.network.expect("a TS_UD_CS_NET block");
    assert_eq!(
        network.channels.len(),
        2,
        "drdynvc and cliprdr, and nothing we cannot handle"
    );
    assert!(blocks.message_channel.is_some(), "we ask for auto detect");

    // Phase 4, in the order MS-RDPBCGR 2.2.1.5 to 2.2.1.9 lists it.
    assert_eq!(recorded.erect_domains, 1);
    assert_eq!(recorded.attach_users, 1);
    assert_eq!(
        recorded.joins,
        vec![
            USER_CHANNEL_ID,
            IO_CHANNEL_ID,
            MESSAGE_CHANNEL_ID,
            1010,
            1011
        ],
        "the user channel, the I/O channel, the message channel, then the virtual channels"
    );

    // Phase 6. The credentials go out even under TLS, because that is what
    // single sign on into the session is, and `INFO_AUTOLOGON` is what makes
    // the session land on the desktop (MS-RDPBCGR 2.2.1.11, PRDRDP/03 §2.7).
    let info = recorded
        .client_info
        .expect("a Client Info PDU reached the mock");
    assert_eq!(info.info.user_name, "alice");
    assert_eq!(info.info.domain, "CORP");
    assert_ne!(
        info.info.flags & rdp_pdu::rdp::client_info::info_flags::AUTOLOGON,
        0
    );
    assert_ne!(
        info.info.flags & rdp_pdu::rdp::client_info::info_flags::UNICODE,
        0
    );

    // Phase 9. The Confirm Active echoes the server's `shareId`, or the server
    // answers `ERRINFO_CONFIRMACTIVEWRONGSHAREID`, and the Surface Commands
    // set is not among what we confirmed (PRDRDP/04 §9.3).
    assert_eq!(recorded.confirmed_share_id, Some(SHARE_ID));
    assert!(!recorded.confirmed_capabilities.is_empty());
    assert!(
        !recorded
            .confirmed_capabilities
            .contains(&rdp_pdu::rdp::capabilities::capability_set_type::SURFACE_COMMANDS),
        "a capability we advertise is one the server will use"
    );

    // Phase 10, in the order MS-RDPBCGR 2.2.1.14 to 2.2.1.18 lists it, all in
    // one write.
    use rdp_pdu::rdp::share::pdu_type2;
    assert_eq!(
        recorded.finalization,
        vec![
            pdu_type2::SYNCHRONIZE,
            pdu_type2::CONTROL,
            pdu_type2::CONTROL,
            pdu_type2::FONT_LIST
        ]
    );

    // The lifecycle states the UI renders. PRDRDP/00 R12 adds no new ones for
    // RDP, so `Negotiating` is what the MCS phases show, and the desktop size
    // the server chose reaches the shell before the first frame does.
    let states: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::StateChanged(s) => Some(s.clone()),
            _ => None,
        })
        .collect();
    assert!(
        states.contains(&remote_core::SessionState::Negotiating),
        "{states:?}"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            SessionEvent::DesktopResize {
                width,
                height
            } if (*width, *height) == SERVER_DESKTOP
        )),
        "{events:?}"
    );
}

/// A server that sends no licensing PDU at all goes straight to the Demand
/// Active. The client has to read that as a Share Control PDU rather than
/// losing four bytes to a security header that is not there, which is the
/// whole point of the classification rule in `connection::activate`.
#[tokio::test]
async fn a_server_that_skips_licensing_still_reaches_connected() {
    let (_, _, result) = run_sequence(
        MockConfig {
            session: SessionBehaviour::ServeWithoutLicensing,
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    let connected = result.expect("no licensing pdu is a legal server");
    assert_eq!(connected.activation.share_id, SHARE_ID);
}

/// A licensing refusal is a sentence, not a number: the user has to be able to
/// tell "this server wants a client access licence" from "the network broke".
#[tokio::test]
async fn a_refused_licence_stops_with_a_sentence() {
    let (_, _, result) = run_sequence(
        MockConfig {
            session: SessionBehaviour::RefuseLicence,
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    match result {
        Err(RdpError::Protocol(msg)) => {
            assert!(msg.contains("licence server"), "{msg}");
        }
        other => panic!("expected a licensing refusal, got {other:?}"),
    }
}

/// The joins are pipelined and the confirms come back in any order, which is
/// what MS-RDPBCGR 2.2.1.9 allows and what saves three round trips on a link
/// with real latency. The mock answers them in reverse for exactly this.
#[tokio::test]
async fn channel_join_confirms_are_accepted_in_any_order() {
    let (server, _, result) = run_sequence(MockConfig::default(), Credentials::default()).await;
    assert!(result.is_ok(), "the joins completed: {result:?}");
    assert_eq!(server.recorded().joins.len(), 5);
}

/// A server with no message channel is one fewer join and nothing else.
#[tokio::test]
async fn a_server_without_a_message_channel_joins_one_fewer() {
    let (server, _, result) = run_sequence(
        MockConfig {
            message_channel: false,
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        server.recorded().joins,
        vec![USER_CHANNEL_ID, IO_CHANNEL_ID, 1010, 1011]
    );
}

/// Standard RDP security is RC4 with a server chosen key, and D6 refuses it.
/// The refusal happens at the Connect Response, before a credential has been
/// sent, which is the property that matters.
#[tokio::test]
async fn a_server_demanding_standard_rdp_security_is_refused() {
    let (_, _, result) = run_sequence(
        MockConfig {
            mcs: McsBehaviour::DemandStandardSecurity,
            ..MockConfig::default()
        },
        Credentials::user_pass("user", "secret"),
    )
    .await;
    match result {
        Err(RdpError::Protocol(msg)) => {
            assert!(msg.contains("standard RDP security"), "{msg}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Every share PDU travels on the I/O channel, so a refused join for it is a
/// connect failure rather than a session with one feature missing.
#[tokio::test]
async fn a_refused_io_channel_join_fails_the_connection() {
    let (_, _, result) = run_sequence(
        MockConfig {
            mcs: McsBehaviour::RefuseIoChannelJoin,
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    match result {
        Err(RdpError::Protocol(msg)) => assert!(msg.contains("I/O channel"), "{msg}"),
        other => panic!("expected a connect failure, got {other:?}"),
    }
}

/// A refused optional channel is a session without a clipboard, not a failed
/// connection. The sequence carries on to the next phase.
#[tokio::test]
async fn a_refused_virtual_channel_join_is_survivable() {
    let (_, _, result) = run_sequence(
        MockConfig {
            mcs: McsBehaviour::RefuseLastVirtualChannelJoin,
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    assert!(
        result.is_ok(),
        "a refused optional channel must not end the connection: {result:?}"
    );
}

/// Run phase 1 and then the MCS phases on their own, so the channel map the
/// sequence built can be asserted directly.
///
/// The tests above see it only through the error the next phase returns,
/// which says the joins finished and nothing about what they produced.
async fn run_mcs(config: MockConfig) -> connection::McsConnected {
    let server = MockRdpServer::start(config).await;
    let options = options_for(server.addr);
    let rdp = rdp_half(&options);
    let opts = ResolvedOptions::resolve(&options, &rdp, &mut Vec::new()).expect("valid options");

    tokio::time::timeout(DEFAULT_TIMEOUT, async {
        let stream = TcpStream::connect(server.addr)
            .await
            .expect("the mock is up");
        let mut framer = Framer::new(stream, Arc::new(AtomicU64::new(0)));
        let selected = connection::negotiate_security(&mut framer, &opts, &options.credentials)
            .await
            .expect("the negotiation succeeded");
        connection::mcs::connect(&mut framer, &opts, selected)
            .await
            .expect("the MCS phases succeeded")
    })
    .await
    .expect("finished inside the timeout")
}

/// The map every later Send Data Request is addressed from and to.
///
/// The user channel comes from the Attach User Confirm, the I/O channel and
/// the virtual channel ids from `TS_UD_SC_NET`, and the names are ours, paired
/// by position because MS-RDPBCGR 2.2.1.4.4 answers in request order.
#[tokio::test]
async fn the_channel_map_names_every_channel_the_session_joined() {
    let connected = run_mcs(MockConfig::default()).await;
    let map = &connected.channels;
    assert_eq!(map.user_channel_id, USER_CHANNEL_ID);
    assert_eq!(map.io_channel_id, IO_CHANNEL_ID);
    assert_eq!(map.message_channel_id, Some(MESSAGE_CHANNEL_ID));
    assert_eq!(map.by_name("drdynvc"), Some(1010));
    assert_eq!(map.by_name("cliprdr"), Some(1011));
    assert_eq!(map.by_name("rdpsnd"), None, "we never asked for audio");
    assert!(!connected.skipped_channel_joins);
}

/// A channel the server refused is struck off the map, so the run loop treats
/// data on it as a server confused about the session rather than as
/// clipboard traffic. Leaving it in would be the worse half of the bug: the
/// session would accept bytes on a channel it does not have.
#[tokio::test]
async fn a_refused_channel_is_struck_off_the_map() {
    let connected = run_mcs(MockConfig {
        mcs: McsBehaviour::RefuseLastVirtualChannelJoin,
        ..MockConfig::default()
    })
    .await;
    let map = &connected.channels;
    assert_eq!(map.by_name("drdynvc"), Some(1010), "the first still joined");
    assert_eq!(map.by_name("cliprdr"), None, "the refused one is gone");
    assert_eq!(
        map.io_channel_id, IO_CHANNEL_ID,
        "the I/O channel is intact"
    );
}

/// Pairing our channel names against a differently sized id array by position
/// would address clipboard traffic to whatever the server put in that slot.
#[tokio::test]
async fn a_channel_count_mismatch_is_refused() {
    let (_, _, result) = run_sequence(
        MockConfig {
            mcs: McsBehaviour::WrongChannelCount,
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    match result {
        Err(RdpError::Protocol(msg)) => assert!(msg.contains("channels"), "{msg}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A refused Attach User leaves nothing to address a Send Data Request from.
#[tokio::test]
async fn a_refused_attach_user_fails_the_connection() {
    let (_, _, result) = run_sequence(
        MockConfig {
            mcs: McsBehaviour::RefuseAttachUser,
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    match result {
        Err(RdpError::Protocol(msg)) => assert!(msg.contains("Attach User"), "{msg}"),
        other => panic!("expected a connect failure, got {other:?}"),
    }
}

/// An MCS Disconnect Provider Ultimatum means the session is over, not that
/// the server sent the wrong PDU. Reporting it as a protocol violation would
/// put a red banner on a server that is merely busy.
#[tokio::test]
async fn a_disconnect_during_the_sequence_is_a_disconnect() {
    let (_, _, result) = run_sequence(
        MockConfig {
            mcs: McsBehaviour::DisconnectDuringConnect,
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    match result {
        Err(RdpError::ServerDisconnect { user_requested }) => {
            assert!(!user_requested, "the mock sends rn-provider-initiated");
        }
        // The mock hangs up straight after, so a race on the close is also a
        // correct answer: both are "the server ended it", and neither is a
        // protocol violation.
        Err(RdpError::ConnectionClosed) | Err(RdpError::Pdu { .. }) => {}
        other => panic!("expected the session to end, got {other:?}"),
    }
}

/// A negotiation failure names what the server said, in a sentence, and stops
/// rather than retrying: the user has to turn something on.
#[tokio::test]
async fn a_negotiation_failure_stops_with_a_sentence() {
    let (_, _, result) = run_sequence(
        MockConfig {
            negotiation: Negotiation::Fail(rdp_pdu::x224::neg_failure::HYBRID_REQUIRED_BY_SERVER),
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    match result {
        Err(e @ RdpError::NegotiationFailed { code, .. }) => {
            assert_eq!(code, rdp_pdu::x224::neg_failure::HYBRID_REQUIRED_BY_SERVER);
            assert!(
                e.to_string().contains("network level authentication"),
                "{e}"
            );
            assert!(!e.is_transient(), "a repeatable refusal is not retried");
            assert!(e.needs_user_action());
        }
        other => panic!("expected a negotiation failure, got {other:?}"),
    }
}

/// A Connection Confirm with no negotiation structure means the server chose
/// standard RDP security, which D6 refuses.
#[tokio::test]
async fn a_server_that_does_not_understand_negotiation_is_refused() {
    let (_, _, result) = run_sequence(
        MockConfig {
            negotiation: Negotiation::NoStructure,
            ..MockConfig::default()
        },
        Credentials::default(),
    )
    .await;
    assert!(
        matches!(result, Err(RdpError::NegotiationInconsistent)),
        "{result:?}"
    );
}

/// A server that selects `PROTOCOL_RDP` is refused for the same reason, and
/// before anything else is sent.
#[tokio::test]
async fn a_server_selecting_standard_rdp_security_is_refused() {
    let (server, _, result) = run_sequence(
        MockConfig {
            negotiation: Negotiation::Select(rdp_pdu::x224::security_protocol::RDP),
            ..MockConfig::default()
        },
        Credentials::user_pass("user", "secret"),
    )
    .await;
    assert!(
        matches!(result, Err(RdpError::NegotiationInconsistent)),
        "{result:?}"
    );
    assert!(
        server.recorded().client_blocks.is_none(),
        "nothing after the Connection Request may reach a server we refused"
    );
}

/// CredSSP binds the credentials to the server's TLS public key
/// (MS-CSSP 3.1.5), so a caller with no certificate has nothing to bind to.
/// This test drives the MCS phases over a plain socket with no upgrade, which
/// is the one path that can reach that state, and asserts the exchange is
/// refused rather than started against nothing. Under `NlaPolicy::Required`
/// the connection fails.
#[tokio::test]
async fn credssp_without_a_certificate_is_refused_rather_than_started() {
    let server = MockRdpServer::start(MockConfig {
        negotiation: Negotiation::Select(rdp_pdu::x224::security_protocol::HYBRID),
        ..MockConfig::default()
    })
    .await;
    let mut options = options_for(server.addr);
    options.rdp_mut().nla = remote_core::NlaPolicy::Required;
    options.credentials = Credentials::user_pass("user", "secret");
    let rdp = rdp_half(&options);
    let opts = ResolvedOptions::resolve(&options, &rdp, &mut Vec::new()).expect("valid");

    let (events, _rx) = mpsc::channel(256);
    let result = tokio::time::timeout(DEFAULT_TIMEOUT, async {
        let stream = TcpStream::connect(server.addr)
            .await
            .expect("the mock is up");
        let mut framer = Framer::new(stream, Arc::new(AtomicU64::new(0)));
        let selected =
            connection::negotiate_security(&mut framer, &opts, &options.credentials).await?;
        assert_eq!(selected, SecurityProtocol::Hybrid);
        connection::after_upgrade(
            &mut framer,
            &opts,
            &options.credentials,
            selected,
            None,
            TrustDecision::VerifiedByCa,
            &events,
        )
        .await
    })
    .await
    .expect("finished inside the timeout");

    match result {
        Err(RdpError::Tls(msg)) => {
            assert!(msg.contains("bind"), "{msg}");
        }
        other => panic!("expected a refusal to bind to nothing, got {other:?}"),
    }
}

/// Drive the whole thing: the connection sequence, then the connected pump
/// over the same socket, with `commands` queued for the loop to act on.
///
/// The split between the two halves is the production one:
/// `session::connect::run_connected` does exactly this, and the reason it is
/// repeated here rather than called is the TLS handshake in the middle of
/// `connection::connect` that the mock cannot do.
async fn run_session(
    commands: Vec<ClientCommand>,
) -> (
    MockRdpServer,
    Vec<SessionEvent>,
    Result<RunOutcome, RdpError>,
) {
    let server = MockRdpServer::start(MockConfig::default()).await;
    let options = options_for(server.addr);
    let rdp = rdp_half(&options);
    let opts = ResolvedOptions::resolve(&options, &rdp, &mut Vec::new()).expect("valid options");

    let (events, mut event_rx) = mpsc::channel(256);
    let (command_tx, mut command_rx) = mpsc::channel(256);
    for command in commands {
        command_tx.send(command).await.expect("the channel is open");
    }

    let outcome = tokio::time::timeout(DEFAULT_TIMEOUT, async {
        let stream = TcpStream::connect(server.addr)
            .await
            .expect("the mock is up");
        let mut framer = Framer::new(stream, Arc::new(AtomicU64::new(0)));
        let selected = connection::negotiate_security(&mut framer, &opts, &options.credentials)
            .await
            .expect("the negotiation succeeded");
        let connected = connection::after_upgrade(
            &mut framer,
            &opts,
            &options.credentials,
            selected,
            None,
            TrustDecision::VerifiedByCa,
            &events,
        )
        .await
        .expect("the connection sequence completed");

        // The stream is split exactly once and the write half never comes
        // back, which is what makes "no write inside a select! arm"
        // structural (PRDRDP/00 R10).
        let (stream, buffered) = framer.into_inner();
        let (read_half, write_half) = tokio::io::split(stream);
        let received = Arc::new(AtomicU64::new(0));
        let sent = Arc::new(AtomicU64::new(0));
        let mut framer = Framer::new(read_half, received.clone());
        framer.prime(buffered);

        let (outbound, rx) = mpsc::channel(WRITER_QUEUE);
        let writer = tokio::spawn(writer::writer_task(write_half, rx, sent.clone()));

        let mut run_loop = RunLoop::new(
            framer,
            outbound,
            connected.channels,
            opts.clone(),
            connected.activation,
            false,
            received,
            sent,
        );
        let outcome = run_loop
            .run(
                connected.pending,
                &events,
                &mut command_rx,
                &CancellationToken::new(),
            )
            .await;
        drop(run_loop);
        let _ = writer.await;
        outcome
    })
    .await
    .expect("the session finished inside the timeout");

    drop(events);
    let mut drained = Vec::new();
    while let Some(event) = event_rx.recv().await {
        drained.push(event);
    }
    (server, drained, outcome)
}

/// The picture. One bitmap update reaches the pump on the fast path and comes
/// out as a `FramebufferUpdate` at the rectangle the server named, with the
/// top left pixel red, which is the bottom up DIB flip of PRDRDP/04 §2.3
/// proved end to end rather than in a unit test over a hand written array.
#[tokio::test]
async fn a_bitmap_update_is_decoded_and_emitted_as_a_dirty_rect() {
    let (_, events, outcome) = run_session(vec![ClientCommand::Disconnect]).await;
    assert_eq!(outcome.expect("a clean end"), RunOutcome::UserDisconnect);

    let frame = events
        .iter()
        .find_map(|e| match e {
            SessionEvent::FramebufferUpdate { rects, damage } => Some((rects, damage)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a framebuffer update: {events:?}"));
    let (rects, damage) = frame;
    assert_eq!(rects.len(), 1, "one TS_BITMAP_DATA is one DecodedRect");
    assert_eq!(rects[0].rect.x, BITMAP_AT.0);
    assert_eq!(rects[0].rect.y, BITMAP_AT.1);
    assert_eq!((rects[0].rect.width, rects[0].rect.height), (2, 2));
    assert_eq!(*damage, rects[0].rect);

    let RectPayload::Rgba(pixels) = &rects[0].payload else {
        panic!("a decoded rect carries its own pixels and never a framebuffer");
    };
    assert_eq!(pixels.len(), 2 * 2 * 4, "exactly this rectangle's pixels");
    assert_eq!(
        &pixels[0..4],
        &[0xff, 0x00, 0x00, 0xff],
        "the top left pixel is red, so the DIB flip happened"
    );
    assert_eq!(
        &pixels[8..12],
        &[0x00, 0x00, 0xff, 0xff],
        "and the bottom row is blue"
    );
}

/// The input path, round trip. A pointer command and a key command become fast
/// path input events on the wire, in the order and with the flags
/// MS-RDPBCGR 2.2.8.1.2.2 defines, and the disconnect releases the key that
/// was still held.
#[tokio::test]
async fn an_input_command_reaches_the_server_as_a_fast_path_event() {
    use rdp_pdu::input::fastpath::{keyboard_flags, FastPathInputEvent};
    use rdp_pdu::input::pointer_flags;

    let (server, _, outcome) = run_session(vec![
        ClientCommand::Pointer {
            x: 100,
            y: 200,
            button_mask: 0b001,
        },
        ClientCommand::Key {
            keysym: 0,
            // `KeyA`, which the webview's table maps to XT set 1 0x1e.
            keycode: Some(0x1e),
            down: true,
        },
        ClientCommand::Disconnect,
    ])
    .await;
    assert_eq!(outcome.expect("a clean end"), RunOutcome::UserDisconnect);

    // The mock reads in its own task, so wait for it to have seen the hang up
    // rather than racing it.
    let recorded = server.wait_until(|r| r.client_disconnect.is_some()).await;
    assert_eq!(
        recorded.input_events,
        vec![
            FastPathInputEvent::Mouse {
                flags: pointer_flags::MOVE,
                x: 100,
                y: 200
            },
            FastPathInputEvent::Mouse {
                flags: pointer_flags::DOWN | pointer_flags::BUTTON1_LEFT,
                x: 100,
                y: 200
            },
            FastPathInputEvent::Scancode {
                flags: 0,
                code: 0x1e
            },
            // The disconnect releases what is held, or the key repeats into
            // the remote session forever (PRDRDP/05 §2.11).
            FastPathInputEvent::Scancode {
                flags: keyboard_flags::RELEASE,
                code: 0x1e
            },
        ]
    );

    // And the teardown was ordered: the ultimatum reached the server after the
    // input did (MS-RDPBCGR 2.2.2.3).
    assert_eq!(
        recorded.client_disconnect,
        Some(rdp_pdu::mcs::disconnect_reason::USER_REQUESTED)
    );
}

/// A session that is handed the wrong protocol's options is caught before a
/// task exists, which is the whole reason `spawn` returns a `Result`.
#[tokio::test]
async fn the_driver_refuses_the_wrong_protocol_before_spawning() {
    use remote_core::{ConnectOptions, ProtocolDriver, ProtocolKind};
    let (events, _rx) = mpsc::channel(1);
    let err = rdp_core::RdpDriver::new()
        .spawn("s1".into(), ConnectOptions::vnc("h", 5900), events)
        .expect_err("VNC options must not reach the RDP session");
    assert_eq!(err.expected, ProtocolKind::Rdp);
    assert_eq!(err.actual, ProtocolKind::Vnc);
}

/// The whole `RdpSession::spawn` path against the mock: the session task
/// starts, runs the sequence, and reports the phase it stopped at through the
/// event stream rather than as a return value, because the shell has already
/// opened a window by then.
///
/// It stops at the TLS handshake, because `connection::connect` does upgrade
/// and the mock is not a TLS server. What this proves is the task topology
/// and the reporting contract, not the sequence, which the tests above cover.
#[tokio::test]
async fn a_spawned_session_reports_its_failure_through_the_event_stream() {
    let server = MockRdpServer::start(MockConfig::default()).await;
    let options = options_for(server.addr);
    let (events, mut rx) = mpsc::channel(256);

    let handle = rdp_core::RdpSession::spawn("s1".into(), options, events);
    assert_eq!(handle.kind, remote_core::ProtocolKind::Rdp);

    let mut last = None;
    let drain = async {
        while let Some(event) = rx.recv().await {
            if let SessionEvent::StateChanged(remote_core::SessionState::Disconnected {
                reason,
                can_retry,
            }) = event
            {
                last = Some((reason, can_retry));
                break;
            }
        }
    };
    tokio::time::timeout(DEFAULT_TIMEOUT, drain)
        .await
        .expect("the session reported inside the timeout");

    let (reason, _) = last.expect("a Disconnected state reached the shell");
    assert!(!reason.is_empty(), "a failure has to say something");
}
