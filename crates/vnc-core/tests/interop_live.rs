//! Live interoperability tests against a **real** VNC server.
//!
//! These exercise the handshake against whatever is actually listening on
//! `DVV_LIVE_VNC` (default `127.0.0.1:5900`), on a Mac with Screen Sharing
//! enabled that is macOS Screen Sharing, banner `RFB 003.889`, which is the one
//! server the mock cannot faithfully imitate (Apple's security-type offer).
//!
//! ## Rules
//!
//! * **Never authenticate.** Every test stops at the point where credentials
//!   would be sent and closes the socket, exactly like
//!   `vnc_discovery::deep_probe`. No challenge is ever answered, so nothing
//!   here can trip a server-side lockout.
//! * **Skip, never fail, when no server is present.** CI (Linux, no VNC) must
//!   stay green: every test probes the port first and returns early with an
//!   explanatory `eprintln!`.
//! * **Skip the vendor-specific assertions when the server is not Apple.** If
//!   something else answers on 5900 the generic protocol assertions still run;
//!   the `003.889` quirk assertions are reported as skipped instead of failing.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use vnc_core::proto::version::{negotiate, parse_server_banner, ProtocolVersion};
use vnc_core::security::select_security_type;
use vnc_core::types::{ConnectOptions, SecurityType};

/// Apple Remote Desktop / Screen Sharing Diffie-Hellman authentication.
const SEC_APPLE_DH: u8 = 30;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// The address under test: `$DVV_LIVE_VNC`, else `127.0.0.1:5900`.
fn target() -> SocketAddr {
    std::env::var("DVV_LIVE_VNC")
        .unwrap_or_else(|_| "127.0.0.1:5900".to_string())
        .parse()
        .expect("DVV_LIVE_VNC must be host:port")
}

/// Connect and read the 12-byte banner, or `None` if nothing RFB-shaped is
/// listening. Returns the still-open stream so the caller can continue the
/// handshake.
async fn connect_live(what: &str) -> Option<(TcpStream, [u8; 12])> {
    let addr = target();
    let mut stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            eprintln!("SKIP {what}: no VNC server listening on {addr}");
            return None;
        }
    };
    let mut banner = [0u8; 12];
    match timeout(IO_TIMEOUT, stream.read_exact(&mut banner)).await {
        Ok(Ok(_)) => {}
        _ => {
            eprintln!("SKIP {what}: {addr} accepted but sent no RFB banner");
            return None;
        }
    }
    if parse_server_banner(&banner).is_err() {
        eprintln!(
            "SKIP {what}: {addr} is not an RFB server (got {:?})",
            String::from_utf8_lossy(&banner)
        );
        return None;
    }
    Some((stream, banner))
}

/// Read the server's security-type offer (RFB 3.7+ form: `u8 count` then that
/// many type bytes). Panics only on a genuine protocol violation.
async fn read_security_offer(stream: &mut TcpStream) -> Vec<u8> {
    let count = timeout(IO_TIMEOUT, stream.read_u8())
        .await
        .expect("security-type count must arrive")
        .expect("security-type count must read") as usize;
    assert!(
        count > 0,
        "a count of 0 means the server refused the connection outright"
    );
    let mut types = vec![0u8; count];
    timeout(IO_TIMEOUT, stream.read_exact(&mut types))
        .await
        .expect("security-type list must arrive")
        .expect("security-type list must read");
    types
}

/// Close the connection without ever having authenticated.
async fn close_without_auth(mut stream: TcpStream) {
    stream.shutdown().await.ok();
    drop(stream);
}

// ---------------------------------------------------------------------------
// Version handshake
// ---------------------------------------------------------------------------

/// The banner is read and classified. On macOS Screen Sharing (`RFB 003.889`)
/// the quirk flag must be set and the version pinned to 3.8.
#[tokio::test]
async fn live_banner_sets_apple_screen_sharing_quirk() {
    let Some((stream, banner)) = connect_live("live_banner_sets_apple_screen_sharing_quirk").await
    else {
        return;
    };
    let parsed = parse_server_banner(&banner).expect("connect_live validated the banner");
    eprintln!(
        "LIVE {}: banner {:?} -> version {} (apple quirk: {})",
        target(),
        String::from_utf8_lossy(&banner).trim_end(),
        parsed.version,
        parsed.is_apple_screen_sharing
    );

    if parsed.server_minor == 889 {
        assert_eq!(parsed.server_major, 3);
        assert!(
            parsed.is_apple_screen_sharing,
            "RFB 003.889 must set is_apple_screen_sharing"
        );
        assert_eq!(
            parsed.version,
            ProtocolVersion::V3_8,
            "Apple's 003.889 is spoken as 3.8"
        );
        assert_eq!(
            &parsed.client_reply(),
            b"RFB 003.008\n",
            "we must answer Apple with RFB 003.008"
        );
    } else {
        eprintln!(
            "SKIP apple-quirk assertions: server is RFB {}.{}, not 003.889",
            parsed.server_major, parsed.server_minor
        );
        assert!(!parsed.is_apple_screen_sharing);
    }

    close_without_auth(stream).await;
}

/// The full version negotiation: we reply `RFB 003.008` and the server accepts
/// it, proved by it proceeding to the security phase instead of hanging up.
#[tokio::test]
async fn live_version_negotiation_is_accepted() {
    let addr = target();
    let mut stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            eprintln!("SKIP live_version_negotiation_is_accepted: nothing on {addr}");
            return;
        }
    };

    // `negotiate` reads the banner and writes our reply in one step.
    let negotiated = match timeout(IO_TIMEOUT, negotiate(&mut stream)).await {
        Ok(Ok(v)) => v,
        _ => {
            eprintln!("SKIP live_version_negotiation_is_accepted: {addr} is not an RFB server");
            return;
        }
    };
    assert_eq!(
        negotiated.version,
        ProtocolVersion::V3_8,
        "every modern server negotiates 3.8"
    );

    // The server accepted our version if it now sends a security offer.
    let offered = read_security_offer(&mut stream).await;
    eprintln!(
        "LIVE {addr}: negotiated {} (server said {}.{}), server offered security types {offered:?}",
        negotiated.version, negotiated.server_major, negotiated.server_minor
    );
    assert!(!offered.is_empty());

    close_without_auth(stream).await;
}

// ---------------------------------------------------------------------------
// Security offer
// ---------------------------------------------------------------------------

/// The security-type list is read successfully; on macOS it contains Apple's
/// type 30, and our selector picks `AppleDh` for that offer.
#[tokio::test]
async fn live_security_offer_and_selection() {
    let Some((mut stream, banner)) = connect_live("live_security_offer_and_selection").await else {
        return;
    };
    let parsed = parse_server_banner(&banner).expect("validated");

    timeout(IO_TIMEOUT, stream.write_all(&parsed.client_reply()))
        .await
        .expect("version reply must not time out")
        .expect("version reply must write");
    timeout(IO_TIMEOUT, stream.flush())
        .await
        .expect("flush must not time out")
        .expect("flush must succeed");

    let offered = read_security_offer(&mut stream).await;
    let named: Vec<String> = offered
        .iter()
        .map(|&b| format!("{b} ({:?})", SecurityType::from_wire(b)))
        .collect();
    eprintln!("LIVE {}: security types offered: {named:?}", target());

    // --- what we would choose, without sending anything ---------------------
    let mut opts = ConnectOptions::vnc("127.0.0.1", target().port());
    opts.vnc_mut().allow_insecure = false;
    let chosen = select_security_type(&offered, &opts).expect("a usable security type");
    eprintln!("LIVE {}: select_security_type -> {chosen:?}", target());

    if parsed.is_apple_screen_sharing {
        assert!(
            offered.contains(&SEC_APPLE_DH),
            "macOS Screen Sharing must offer Apple DH (30); got {offered:?}"
        );
        assert_eq!(
            chosen,
            SecurityType::AppleDh,
            "Apple DH must win this offer: {offered:?}"
        );
        // VncAuth is commonly offered alongside; it must lose, and must stay
        // gated behind the insecure opt-in.
        if offered.contains(&2) {
            assert_ne!(chosen, SecurityType::VncAuth);
        }
    } else {
        eprintln!("SKIP apple security assertions: not macOS Screen Sharing");
        assert!(vnc_core::security::is_supported(chosen));
    }

    // --- and now we leave, without ever answering a challenge ---------------
    close_without_auth(stream).await;
}

/// The whole flow, closed cleanly before the point of no return: we never write
/// the security-type selection byte, so the server never issues a challenge.
#[tokio::test]
async fn live_connection_closes_cleanly_without_authenticating() {
    let what = "live_connection_closes_cleanly_without_authenticating";
    let Some((mut stream, banner)) = connect_live(what).await else {
        return;
    };
    let parsed = parse_server_banner(&banner).expect("validated");

    let reply = parsed.client_reply();
    timeout(IO_TIMEOUT, stream.write_all(&reply))
        .await
        .expect("version reply must not time out")
        .expect("version reply must write");
    let offered = read_security_offer(&mut stream).await;
    assert!(!offered.is_empty());

    // The only bytes we ever sent are the 12-byte version reply.
    assert_eq!(reply.len(), 12);

    stream.shutdown().await.expect("clean shutdown");
    // A second shutdown on a closed socket is harmless; the point is that the
    // session ended before authentication, with no error surfaced.
    eprintln!(
        "LIVE {}: closed cleanly after reading {} security types, no auth attempted",
        target(),
        offered.len()
    );
}

// ---------------------------------------------------------------------------
// Selection logic pinned to the offer a real Mac makes
// ---------------------------------------------------------------------------

/// A regression pin for the offer observed from macOS Screen Sharing
/// (`[30, 33, 36, 2, 35]`): types 33/35/36 are Apple extensions we do not
/// implement and must be ignored, 30 must beat 2, and the choice must not need
/// the insecure opt-in. Runs everywhere, no server required.
#[test]
fn apple_offer_selection_is_pinned() {
    let offered = [30u8, 33, 36, 2, 35];
    let opts = ConnectOptions::vnc("mac.local", 5900);
    assert!(!opts.vnc_options().unwrap().allow_insecure);
    assert_eq!(
        select_security_type(&offered, &opts).expect("Apple DH is usable"),
        SecurityType::AppleDh
    );

    // Order must not matter.
    let shuffled = [2u8, 35, 36, 33, 30];
    assert_eq!(
        select_security_type(&shuffled, &opts).unwrap(),
        SecurityType::AppleDh
    );

    // Without type 30 the same offer falls back to VncAuth, which now connects
    // without any opt-in (only `None` is gated), the client has to work
    // against servers that offer nothing better.
    let no_apple = [33u8, 36, 2, 35];
    assert_eq!(
        select_security_type(&no_apple, &opts).unwrap(),
        SecurityType::VncAuth
    );

    for t in [33u8, 35, 36] {
        assert!(
            !vnc_core::security::is_supported(SecurityType::from_wire(t)),
            "type {t} is an Apple extension we deliberately do not implement"
        );
    }
}
