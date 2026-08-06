//! End-to-end handshake tests against a real RFB server socket.
//!
//! Covers version negotiation (3.3 / 3.8 / Apple 003.889), security type
//! selection, and the security properties that matter most: a wrong password
//! must be a hard stop with no retry loop, and an unsupported security offer
//! must fail rather than silently downgrade.

mod common;

use std::time::Duration;

use common::mock_server::*;
use common::*;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use vnc_core::error::VncError;
use vnc_core::proto::{self, ProtocolVersion};
use vnc_core::security::{authenticate, ProtocolVersionInfo};
use vnc_core::types::{ClientCommand, ConnectOptions, SecurityType, SessionEvent, SessionState};

// ---------------------------------------------------------------------------
// A hand-driven handshake, so tests can assert on concrete `VncError` variants
// (the supervised session only exposes user-facing strings).
// ---------------------------------------------------------------------------

struct RawHandshake {
    version: proto::NegotiatedVersion,
    security: SecurityType,
    server_init: proto::ServerInit,
}

async fn raw_handshake(port: u16, opts: &ConnectOptions) -> Result<RawHandshake, VncError> {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let version = proto::version::negotiate(&mut tcp).await?;

    // Read the security offer exactly as `session::connection` does.
    let offered: Vec<u8> = match version.version {
        ProtocolVersion::V3_3 => {
            let ty = tcp.read_u32().await?;
            vec![ty as u8]
        }
        _ => {
            let count = tcp.read_u8().await? as usize;
            let mut buf = vec![0u8; count];
            tcp.read_exact(&mut buf).await?;
            buf
        }
    };

    let info = ProtocolVersionInfo {
        major: version.version.major() as u8,
        minor: version.version.minor() as u8,
        is_apple: version.is_apple_screen_sharing,
    };
    let (mut stream, security) = authenticate(tcp, info, &offered, opts).await?;

    stream.write_all(&[opts.shared as u8]).await?;
    stream.flush().await?;
    let server_init = proto::read_server_init(&mut stream).await?;
    Ok(RawHandshake {
        version,
        security,
        server_init,
    })
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn security_none_reaches_connected() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_NONE])
            .size(1024, 768)
            .name("Living Room Mac"),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // The states leading up to Connected are the documented sequence.
    let states = events.states();
    assert!(matches!(states[0], SessionState::Resolving), "{states:?}");
    assert!(matches!(states[1], SessionState::Connecting), "{states:?}");
    assert!(
        states
            .iter()
            .any(|s| matches!(s, SessionState::Authenticating { .. })),
        "{states:?}"
    );
    assert!(
        states
            .iter()
            .any(|s| matches!(s, SessionState::Negotiating)),
        "{states:?}"
    );

    // Geometry and name are surfaced before Connected.
    assert!(events.any(|e| matches!(
        e,
        SessionEvent::DesktopResize {
            width: 1024,
            height: 768
        }
    )));
    assert!(events.any(|e| matches!(e, SessionEvent::DesktopName(n) if n == "Living Room Mac")));

    // Wire-level: 3.8 banner reply, the selected type echoed, shared flag set.
    assert_eq!(server.version_replies(), vec![*b"RFB 003.008\n"]);
    assert_eq!(server.selected_security(), vec![SEC_NONE]);
    assert_eq!(server.shared_flags(), vec![true]);

    handle.shutdown();
}

#[tokio::test]
async fn vnc_auth_with_correct_password_reaches_connected() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("swordfish"),
    )
    .await;

    let opts = with_password(options(server.port()), "swordfish");
    let (handle, mut events) = spawn_session(opts);
    events.wait_connected(DEFAULT_TIMEOUT).await;

    assert_eq!(server.selected_security(), vec![SEC_VNC_AUTH]);
    assert_eq!(server.connection_count(), 1);
    handle.shutdown();
}

#[tokio::test]
async fn vnc_auth_challenge_response_is_the_des_form_the_server_expects() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("hunter2"),
    )
    .await;

    let opts = with_password(options(server.port()), "hunter2");
    let hs = raw_handshake(server.port(), &opts)
        .await
        .expect("handshake must succeed with the right password");
    assert_eq!(hs.security, SecurityType::VncAuth);
    assert_eq!(hs.server_init.name, "Mock Desktop");
}

// ---------------------------------------------------------------------------
// The critical safety property: a wrong password must NOT retry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_password_is_auth_failed() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("correct-horse"),
    )
    .await;

    let opts = with_password(options(server.port()), "definitely-wrong");
    match raw_handshake(server.port(), &opts).await {
        Err(VncError::AuthFailed(reason)) => {
            assert!(reason.contains("Authentication failed"), "reason: {reason}");
        }
        other => panic!("expected VncError::AuthFailed, got {:?}", other.err()),
    }
}

#[tokio::test]
async fn wrong_password_never_enters_a_retry_loop() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("correct-horse"),
    )
    .await;

    // A 20 ms backoff: if the supervisor retried at all we would see dozens of
    // connections in the observation window below.
    let mut opts = with_password(options(server.port()), "definitely-wrong");
    opts.reconnect.initial_delay_ms = 20;
    opts.reconnect.max_delay_ms = 20;

    let (handle, mut events) = spawn_session(opts);
    let can_retry = events
        .wait_state(DEFAULT_TIMEOUT, "terminal Disconnected", |s| match s {
            SessionState::Disconnected { can_retry, .. } => Some(*can_retry),
            _ => None,
        })
        .await;

    assert!(
        !can_retry,
        "an auth failure needs user action; can_retry must be false"
    );
    assert!(
        events.any(|e| matches!(e, SessionEvent::Error(m) if m.contains("password"))),
        "expected a password error, saw {:?}",
        events.summary()
    );
    assert!(
        !events
            .states()
            .iter()
            .any(|s| matches!(s, SessionState::Reconnecting { .. })),
        "auth failure must never emit Reconnecting: {:?}",
        events.states()
    );

    // Give a hypothetical retry loop plenty of time to show itself.
    events.drain_for(Duration::from_millis(500)).await;
    assert_eq!(
        server.connection_count(),
        1,
        "the supervisor must connect exactly once for a rejected credential"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Version fallbacks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rfb_3_3_server_falls_back_correctly() {
    let server = MockServer::start(
        MockConfig::new()
            .banner(RFB_33)
            .security(&[SEC_NONE])
            .name("Ancient Xvnc"),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // 3.3: the client answers with the same version and sends NO selection
    // byte (the server dictates the type as a u32).
    assert_eq!(server.version_replies(), vec![*b"RFB 003.003\n"]);
    assert!(
        server.selected_security().is_empty(),
        "RFB 3.3 must not echo a security type"
    );
    assert!(events.any(|e| matches!(e, SessionEvent::DesktopName(n) if n == "Ancient Xvnc")));
    handle.shutdown();
}

#[tokio::test]
async fn rfb_3_3_vnc_auth_reads_a_security_result() {
    // On 3.3 there is no SecurityResult for `None`, but there IS one for
    // VncAuth. Getting this wrong hangs the handshake.
    let server = MockServer::start(
        MockConfig::new()
            .banner(RFB_33)
            .security(&[SEC_VNC_AUTH])
            .password("pw"),
    )
    .await;

    let opts = with_password(options(server.port()), "pw");
    let (handle, mut events) = spawn_session(opts);
    events.wait_connected(DEFAULT_TIMEOUT).await;
    assert_eq!(server.version_replies(), vec![*b"RFB 003.003\n"]);
    handle.shutdown();
}

#[tokio::test]
async fn apple_screen_sharing_banner_is_detected() {
    let server = MockServer::start(
        MockConfig::new()
            .banner(RFB_APPLE)
            .security(&[SEC_NONE])
            .size(2880, 1800)
            .name("iMac"),
    )
    .await;

    let opts = options(server.port());
    let hs = raw_handshake(server.port(), &opts)
        .await
        .expect("handshake");
    assert!(hs.version.is_apple_screen_sharing);
    assert_eq!(hs.version.server_minor, 889);

    let caps = proto::build_capabilities(&hs.version, &hs.server_init, hs.security);
    assert!(
        caps.is_apple_screen_sharing,
        "capabilities must report Apple Screen Sharing for RFB 003.889"
    );
    assert_eq!(caps.protocol_version, "3.8", "003.889 speaks 3.8 framing");
    assert_eq!((caps.width, caps.height), (2880, 1800));

    // The client must answer 003.889 with 003.008.
    assert_eq!(server.version_replies(), vec![*b"RFB 003.008\n"]);
}

#[tokio::test]
async fn apple_banner_session_connects() {
    let server = MockServer::start(MockConfig::new().banner(RFB_APPLE).security(&[SEC_NONE])).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Unsupported security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unsupported_security_types_are_rejected() {
    // 250/251 are not real VNC security types and we implement none of them.
    let server = MockServer::start(MockConfig::new().security(&[250, 251])).await;

    let opts = options(server.port());
    match raw_handshake(server.port(), &opts).await {
        Err(VncError::NoSupportedSecurityType(offered)) => {
            assert_eq!(offered, vec![250, 251]);
        }
        other => panic!("expected NoSupportedSecurityType, got {:?}", other.err()),
    }
}

#[tokio::test]
async fn unsupported_security_stops_the_session_without_retrying() {
    let server = MockServer::start(MockConfig::new().security(&[250, 251])).await;

    let mut opts = options(server.port());
    opts.reconnect.initial_delay_ms = 20;
    opts.reconnect.max_delay_ms = 20;
    let (handle, mut events) = spawn_session(opts);

    let (reason, can_retry) = events
        .wait_state(DEFAULT_TIMEOUT, "terminal Disconnected", |s| match s {
            SessionState::Disconnected { reason, can_retry } => Some((reason.clone(), *can_retry)),
            _ => None,
        })
        .await;
    assert!(
        reason.contains("does not support"),
        "unexpected reason: {reason}"
    );
    assert!(
        can_retry,
        "a protocol-level stop may still offer a manual retry button"
    );

    events.drain_for(Duration::from_millis(400)).await;
    assert_eq!(server.connection_count(), 1, "no auto-retry for this class");
    handle.shutdown();
}

/// Issue #1: a server offering only "None" (a stock passwordless `x11vnc`)
/// must connect on the shipping defaults. This used to be refused, and the
/// refusal named a per-host "Allow an unencrypted connection" control that
/// was never built, so the server was simply unreachable.
#[tokio::test]
async fn a_password_less_server_connects_on_the_defaults() {
    let server = MockServer::start(MockConfig::new().security(&[SEC_NONE])).await;
    let opts = options(server.port());
    assert!(!opts.allow_insecure, "the defaults must carry no opt-in");
    let caps = raw_handshake(server.port(), &opts)
        .await
        .expect("a None-only server should connect");
    assert_eq!(caps.security, SecurityType::None);
}

// ---------------------------------------------------------------------------
// Post-handshake negotiation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_negotiates_format_encodings_and_primes_the_pipeline() {
    let server = MockServer::start(MockConfig::new().size(800, 600)).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    assert!(server.wait_for_messages(3, DEFAULT_TIMEOUT).await);
    let msgs = server.messages();

    // SetPixelFormat first, and it must ask for our canonical 32bpp format.
    match &msgs[0] {
        ClientMessage::SetPixelFormat { raw } => {
            assert_eq!(raw.len(), 20);
            assert_eq!(raw[4], 32, "bits per pixel");
            assert_eq!(raw[5], 24, "depth");
        }
        other => panic!("expected SetPixelFormat first, got {other:?}"),
    }

    // Then SetEncodings, offering Tight/ZRLE/Hextile/zlib/Raw plus the
    // pseudo-encodings the session depends on.
    match &msgs[1] {
        ClientMessage::SetEncodings { encodings } => {
            for wanted in [0, 1, 5, 6, 7, 16] {
                assert!(encodings.contains(&wanted), "missing encoding {wanted}");
            }
            for pseudo in [-224, -307, -308, -312, -313] {
                assert!(encodings.contains(&pseudo), "missing pseudo {pseudo}");
            }
        }
        other => panic!("expected SetEncodings second, got {other:?}"),
    }

    // Finally one full non-incremental request covering the whole desktop.
    match &msgs[2] {
        ClientMessage::FramebufferUpdateRequest { incremental, rect } => {
            assert!(!incremental, "the priming request must be non-incremental");
            assert_eq!(rect.width, 800);
            assert_eq!(rect.height, 600);
        }
        other => panic!("expected FramebufferUpdateRequest third, got {other:?}"),
    }

    handle.shutdown();
}

#[tokio::test]
async fn user_disconnect_is_a_clean_terminal_state() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(&handle, ClientCommand::Disconnect).await;
    let (reason, can_retry) = events
        .wait_state(DEFAULT_TIMEOUT, "Disconnected", |s| match s {
            SessionState::Disconnected { reason, can_retry } => Some((reason.clone(), *can_retry)),
            _ => None,
        })
        .await;
    assert_eq!(reason, "Disconnected");
    assert!(can_retry);

    events.drain_for(Duration::from_millis(300)).await;
    assert_eq!(
        server.connection_count(),
        1,
        "a user disconnect must never reconnect"
    );
}
