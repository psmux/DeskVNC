//! Live logins against a real Mac with Screen Sharing on, for security types
//! 30, 33 and 36 and the encrypted session that follows 33 and 36.
//!
//! Skipped unless all three are set:
//!
//! * `DVV_LIVE_APPLE`, the Mac as `host:port`
//! * `DVV_LIVE_APPLE_USER`, an account on it
//! * `DVV_LIVE_APPLE_PASS`, that account's password
//!
//! These tests DO authenticate, unlike `interop_live.rs`. A wrong guess about
//! the wire format can look like a wrong password to the Mac, and macOS
//! throttles an account after repeated failures, so run them one at a time
//! (`--test-threads=1`) and expect at most one failed attempt per test. The
//! type 36 framing probe makes up to two.
//!
//! Each test prints what it saw with `LIVE` in front, so a run with
//! `--nocapture` doubles as a capture of the facts still marked unconfirmed
//! in `tests/apple_screen_sharing.rs`.

#[allow(unused_imports)]
mod common;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::*;
use vnc_core::security::apple_srp::{self, ProofFraming36};
use vnc_core::types::{ClientCommand, ConnectOptions, Credentials, SessionEvent, SessionState};
use vnc_transport::BoxedStream;

struct Target {
    host: String,
    port: u16,
    user: String,
    pass: String,
}

fn target(what: &str) -> Option<Target> {
    let addr = std::env::var("DVV_LIVE_APPLE").ok();
    let user = std::env::var("DVV_LIVE_APPLE_USER").ok();
    let pass = std::env::var("DVV_LIVE_APPLE_PASS").ok();
    let (Some(addr), Some(user), Some(pass)) = (addr, user, pass) else {
        eprintln!("SKIP {what}: DVV_LIVE_APPLE, DVV_LIVE_APPLE_USER and DVV_LIVE_APPLE_PASS are not all set");
        return None;
    };
    let (host, port) = match addr.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().expect("DVV_LIVE_APPLE port")),
        None => (addr, 5900),
    };
    Some(Target {
        host,
        port,
        user,
        pass,
    })
}

fn live_options(t: &Target, pref: &str) -> ConnectOptions {
    let mut o = ConnectOptions::vnc(&t.host, t.port);
    o.credentials = Credentials::user_pass(&t.user, &t.pass);
    o.connect_timeout = Duration::from_secs(15);
    o.reconnect.enabled = false;
    o.vnc_mut().security_pref = Some(pref.into());
    o
}

/// Banner, our 3.8 reply, and the security offer.
async fn open_to_offer(t: &Target) -> (TcpStream, Vec<u8>) {
    let mut s = TcpStream::connect((t.host.as_str(), t.port))
        .await
        .expect("the Mac accepts a connection");
    let negotiated = vnc_core::proto::version::negotiate(&mut s)
        .await
        .expect("an RFB banner");
    eprintln!(
        "LIVE banner {}.{} (apple: {})",
        negotiated.server_major, negotiated.server_minor, negotiated.is_apple_screen_sharing
    );
    let n = s.read_u8().await.unwrap() as usize;
    let mut offer = vec![0u8; n];
    s.read_exact(&mut offer).await.unwrap();
    eprintln!("LIVE offer {offer:?}");
    (s, offer)
}

/// A full session with one pinned security type: connect, get a picture,
/// move the pointer, disconnect. Prints every event that arrives.
async fn session_with(pref: &str, what: &str) {
    let Some(t) = target(what) else { return };
    let (handle, mut events) = spawn_session(live_options(&t, pref));
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        events.wait_connected(Duration::from_secs(30)).await;
        events.wait_framebuffer(Duration::from_secs(15)).await
    })
    .await;
    events.drain_for(Duration::from_secs(3)).await;
    for line in events.summary() {
        eprintln!("LIVE {what}: {line}");
    }
    let (_, damage) = outcome.unwrap_or_else(|_| panic!("{what}: no picture within 30 s"));
    eprintln!("LIVE {what}: first update damage {damage:?}");

    send(
        &handle,
        ClientCommand::Pointer {
            x: damage.width / 2,
            y: damage.height / 2,
            button_mask: 0,
        },
    )
    .await;
    events.drain_for(Duration::from_secs(2)).await;
    assert!(
        !events.any(|e| matches!(
            e,
            SessionEvent::StateChanged(SessionState::Disconnected { .. })
        )),
        "{what}: the Mac dropped the session after a pointer move: {:?}",
        events.summary()
    );
    send(&handle, ClientCommand::Disconnect).await;
}

/// Without credentials: send type 33 and the host key request, and print the
/// reply. Answers open question one (the request's body) at no risk to the
/// account, since no identity is ever sent.
#[tokio::test]
async fn live_type_33_host_key_request() {
    let Some(t) = target("live_type_33_host_key_request") else {
        return;
    };
    let (mut s, offer) = open_to_offer(&t).await;
    assert!(offer.contains(&33), "the Mac does not offer type 33");
    s.write_all(&[33]).await.unwrap();
    s.write_all(&apple_srp::key_request()).await.unwrap();
    let mut head = [0u8; 4];
    match tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut head)).await {
        Ok(Ok(_)) => {}
        other => panic!("LIVE no answer to the host key request: {other:?}"),
    }
    let len = u32::from_be_bytes(head) as usize;
    eprintln!("LIVE host key reply length word {len}");
    assert!(len < 16 * 1024, "implausible reply length {len}");
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.unwrap();
    eprintln!(
        "LIVE host key reply first bytes {:02x?}",
        &body[..body.len().min(16)]
    );
    let key = apple_srp::parse_key_reply(&body).expect("the reply holds an RSA public key");
    eprintln!(
        "LIVE host key fingerprint {}",
        apple_srp::host_key_fingerprint(&key).unwrap()
    );
}

/// Type 33 end to end through the session.
#[tokio::test]
async fn live_type_33_session() {
    session_with("apple-srp-rsa", "live_type_33_session").await;
}

/// Type 36: the login alone, trying the default proof framing and then the
/// alternative, and reporting which one the Mac accepts.
#[tokio::test]
async fn live_type_36_proof_framing() {
    let Some(t) = target("live_type_36_proof_framing") else {
        return;
    };
    let opts = live_options(&t, "apple-srp");
    let mut accepted = None;
    for framing in [ProofFraming36::Bare, ProofFraming36::Rsa1] {
        let (s, offer) = open_to_offer(&t).await;
        assert!(offer.contains(&36), "the Mac does not offer type 36");
        let stream: BoxedStream = Box::pin(s);
        let r = tokio::time::timeout(
            Duration::from_secs(20),
            apple_srp::login_36_with_framing(stream, &opts, framing),
        )
        .await;
        match r {
            Ok(Ok(_)) => {
                eprintln!("LIVE type 36 accepted with {framing:?} framing");
                accepted = Some(framing);
                break;
            }
            Ok(Err(e)) => eprintln!("LIVE type 36 with {framing:?} framing: {e}"),
            Err(_) => eprintln!("LIVE type 36 with {framing:?} framing: no answer in 20 s"),
        }
    }
    assert!(accepted.is_some(), "neither type 36 framing was accepted");
}

/// Type 36 end to end through the session (default framing).
#[tokio::test]
async fn live_type_36_session() {
    session_with("apple-srp", "live_type_36_session").await;
}

/// Type 30 still gives a plain session, as before this change.
#[tokio::test]
async fn live_type_30_session() {
    session_with("apple-dh", "live_type_30_session").await;
}

/// Auto picks type 33 for a Mac and gets a picture.
#[tokio::test]
async fn live_auto_selects_33() {
    let Some(t) = target("live_auto_selects_33") else {
        return;
    };
    let (s, offer) = open_to_offer(&t).await;
    drop(s);
    let chosen =
        vnc_core::security::select_security_type(&offer, &ConnectOptions::vnc(&t.host, t.port))
            .unwrap();
    eprintln!("LIVE auto selection for {offer:?}: {chosen:?}");
    assert_eq!(chosen, vnc_core::types::SecurityType::AppleRsaSrp);
}
