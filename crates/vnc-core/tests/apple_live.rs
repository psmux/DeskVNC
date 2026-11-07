//! Live logins against a real Mac with Screen Sharing on, for security types
//! 30, 33 and 36 and the encrypted session that follows 33 and 36.
//!
//! Skipped unless all three are set:
//!
//! * `DVV_LIVE_APPLE`, the Mac as `host:port`
//! * `DVV_LIVE_APPLE_USER`, an account on it
//! * `DVV_LIVE_APPLE_PASS`, that account's password
//!
//! or, instead of the last two, `DVV_LIVE_APPLE_CREDS` naming a file with the
//! user on its first line and the password on its second.
//!
//! The tests named `live_probe_*` need only `DVV_LIVE_APPLE`. They never send
//! a password or a real account name, so they cannot count against anyone's
//! login attempts: they look at the offer, the host key and how the Mac
//! answers a user name it does not know.
//!
//! These tests DO authenticate, unlike `interop_live.rs`. A wrong guess about
//! the wire format can look like a wrong password to the Mac, and macOS
//! throttles an account after repeated failures, so run them one at a time
//! (`--test-threads=1`) and expect at most one failed attempt per test.
//!
//! Observed against macOS 26.7.1 (build 25G241) on 2026-11-07, with an
//! account whose password was confirmed valid out of band:
//!
//! * The framing of types 33 and 36 is right. The Mac reads the identity,
//!   sends its SRP challenge, reads the proof, and reaches the point where it
//!   checks the client's evidence (its log: `SRP received 21 bytes` then
//!   `SRP received 682 bytes`, `srp_server_mech_step: 1` then the result).
//! * The proof itself is rejected: `client evidence does not match what we
//!   calculated` (`srp_server_mech_step: -13`). It is rejected the same way
//!   with the identity empty and with the account name as the identity, and
//!   with several forms of `x` (`H(salt, H(":" P2))`, `H(salt, P2)`,
//!   `H(salt, H(P2))`, the RFC 5054 form over the raw password, a 64 byte
//!   PBKDF2 output). So Apple's `x`, `K` or `M1` differs from the inferred
//!   formula in `apple_srp`, and a login cannot be completed until the real
//!   derivation is known (a capture of a native SRP login, or Apple's
//!   corecrypto SRP parameters). The session, input and clipboard steps, and
//!   the stage two 0x1c offer, all sit behind a completed login and so are
//!   still unreached.
//! * Type 30 (Apple DH) cannot log in against this macOS either: see the note
//!   in `apple_dh`. That is a separate finding about the shipped viewer.
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
use vnc_core::security::apple_srp;
use vnc_core::types::{ClientCommand, ConnectOptions, Credentials, SessionEvent, SessionState};

struct Target {
    host: String,
    port: u16,
    user: String,
    pass: String,
}

fn target(what: &str) -> Option<Target> {
    let addr = std::env::var("DVV_LIVE_APPLE").ok();
    let (mut user, mut pass) = (
        std::env::var("DVV_LIVE_APPLE_USER").ok(),
        std::env::var("DVV_LIVE_APPLE_PASS").ok(),
    );
    // Or a file holding the user on its first line and the password on the
    // second, so the secret never has to sit in the environment or a shell.
    if let Ok(path) = std::env::var("DVV_LIVE_APPLE_CREDS") {
        let text = std::fs::read_to_string(&path).expect("DVV_LIVE_APPLE_CREDS is readable");
        let mut lines = text.lines();
        user = lines.next().map(str::to_string);
        pass = lines.next().map(str::to_string);
    }
    let (Some(addr), Some(user), Some(pass)) = (addr, user, pass) else {
        eprintln!("SKIP {what}: DVV_LIVE_APPLE and an account (DVV_LIVE_APPLE_USER and DVV_LIVE_APPLE_PASS, or DVV_LIVE_APPLE_CREDS) are not all set");
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

/// The Mac's address alone, for the probes that need no account.
fn probe_target(what: &str) -> Option<(String, u16)> {
    let Ok(addr) = std::env::var("DVV_LIVE_APPLE") else {
        eprintln!("SKIP {what}: DVV_LIVE_APPLE is not set");
        return None;
    };
    Some(match addr.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().expect("DVV_LIVE_APPLE port")),
        None => (addr, 5900),
    })
}

/// A user name no Mac has, for the probes.
const NO_SUCH_USER: &str = "dvv-probe-no-such-user";

/// Connect, read the banner, answer with `reply`, and return the stream
/// with whatever the server sent next, up to `want` bytes or two seconds.
async fn probe_after_reply(host: &str, port: u16, reply: &[u8; 12]) -> (TcpStream, Vec<u8>) {
    let mut s = TcpStream::connect((host, port)).await.expect("connect");
    let mut banner = [0u8; 12];
    s.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"RFB 003.889\n", "not macOS Screen Sharing");
    s.write_all(reply).await.unwrap();
    let got = read_for(&mut s, Duration::from_secs(2)).await;
    (s, got)
}

/// Everything the server sends within `wait`, stopping early at EOF.
async fn read_for(s: &mut TcpStream, wait: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, s.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return out,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// Banner, the security offer after `RFB 003.889` and after `RFB 003.008`,
/// and what an `RFB 003.003` reply gets.
#[tokio::test]
async fn live_probe_versions_and_offer() {
    let Some((host, port)) = probe_target("live_probe_versions_and_offer") else {
        return;
    };
    for reply in [b"RFB 003.889\n", b"RFB 003.008\n", b"RFB 003.007\n"] {
        let (_s, got) = probe_after_reply(&host, port, reply).await;
        eprintln!(
            "LIVE reply {:?}: server sent {:02x?}",
            String::from_utf8_lossy(reply).trim(),
            got
        );
        assert_eq!(got, [4, 30, 33, 36, 35], "offer after {reply:?}");
    }
    let (_s, got) = probe_after_reply(&host, port, b"RFB 003.003\n").await;
    eprintln!("LIVE reply \"RFB 003.003\": server sent {got:02x?}");
    // RFB 3.3 failure: u32 0, then a u32 length and the reason.
    assert_eq!(&got[..4], &[0, 0, 0, 0]);
    let len = u32::from_be_bytes(got[4..8].try_into().unwrap()) as usize;
    eprintln!(
        "LIVE 3.3 refusal reason {:?}",
        String::from_utf8_lossy(&got[8..8 + len])
    );
}

/// Type 30's parameters. Older Macs sent the 1024-bit group with generator
/// 2; this prints what this one sends.
#[tokio::test]
async fn live_probe_type_30_parameters() {
    let Some((host, port)) = probe_target("live_probe_type_30_parameters") else {
        return;
    };
    let (mut s, offer) = probe_after_reply(&host, port, b"RFB 003.889\n").await;
    assert_eq!(offer, [4, 30, 33, 36, 35]);
    s.write_all(&[30]).await.unwrap();
    let g = s.read_u16().await.unwrap();
    let len = s.read_u16().await.unwrap() as usize;
    let mut p = vec![0u8; len];
    s.read_exact(&mut p).await.unwrap();
    let group = apple_srp::SrpGroup::apple();
    eprintln!(
        "LIVE type 30: generator {g}, {len} byte prime, the RFC 3526 4096-bit prime: {}",
        num_bigint_dig::BigUint::from_bytes_be(&p) == group.n
    );
}

/// The type byte alone, then the host key request in a second write: the
/// Mac closes the connection without answering. Sent together they get the
/// key. This is why the client joins them.
#[tokio::test]
async fn live_probe_type_byte_must_travel_with_the_first_message() {
    let Some((host, port)) =
        probe_target("live_probe_type_byte_must_travel_with_the_first_message")
    else {
        return;
    };
    let (mut s, _) = probe_after_reply(&host, port, b"RFB 003.889\n").await;
    s.set_nodelay(true).unwrap();
    s.write_all(&[33]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.write_all(&apple_srp::key_request()).await.unwrap();
    let apart = read_for(&mut s, Duration::from_secs(2)).await;
    eprintln!(
        "LIVE type byte and key request apart: {} bytes back",
        apart.len()
    );
    assert!(apart.is_empty(), "the Mac answered a split request");

    let (mut s, _) = probe_after_reply(&host, port, b"RFB 003.889\n").await;
    let mut both = vec![33];
    both.extend_from_slice(&apple_srp::key_request());
    s.write_all(&both).await.unwrap();
    let together = read_for(&mut s, Duration::from_secs(2)).await;
    eprintln!(
        "LIVE type byte and key request together: {} bytes back",
        together.len()
    );
    assert!(together.len() > 4, "no host key");
}

/// A whole login as a user the Mac does not have, through the client's own
/// handshake, for types 33 and 36. A Mac answers an unknown name with a
/// challenge of its own making, so this runs every message of the exchange
/// up to the point where the proof fails, without touching a real account.
#[tokio::test]
async fn live_probe_unknown_user() {
    let Some((host, port)) = probe_target("live_probe_unknown_user") else {
        return;
    };
    for pref in ["apple-srp-rsa", "apple-srp"] {
        let (s, offer) = probe_after_reply(&host, port, b"RFB 003.889\n").await;
        assert_eq!(offer, [4, 30, 33, 36, 35]);
        let mut o = ConnectOptions::vnc(&host, port);
        o.credentials = Credentials::user_pass(NO_SUCH_USER, "not a password");
        o.vnc_mut().security_pref = Some(pref.into());
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(
            Duration::from_secs(20),
            vnc_core::security::authenticate_full(
                s,
                vnc_core::security::ProtocolVersionInfo::parse("RFB 003.889\n").unwrap(),
                &offer[1..],
                &o,
                &vnc_core::security::prompt::CredentialSource::none(),
            ),
        )
        .await;
        let r = r.unwrap_or_else(|_| panic!("{pref}: no answer within 20 s"));
        let err = match r {
            Ok(_) => panic!("{pref}: a made up account logged in"),
            Err(e) => e,
        };
        eprintln!(
            "LIVE {pref} unknown user: {err} ({err:?}) after {:?}",
            started.elapsed()
        );
        assert!(
            matches!(err, vnc_core::error::VncError::AuthFailed(_)),
            "{pref}: expected a refused login, got {err:?}"
        );
    }
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
    let mut first = vec![33];
    first.extend_from_slice(&apple_srp::key_request());
    s.write_all(&first).await.unwrap();
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

/// Type 36 end to end through the session.
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
