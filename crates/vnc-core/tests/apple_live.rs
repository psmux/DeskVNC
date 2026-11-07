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
//! * The SRP proof is accepted. `x` was confirmed against the account's
//!   stored verifier, and `M1` once `g` is hashed padded to 512 bytes (found
//!   by solving against Apple's own client); the Mac then answers with its
//!   proof (`srp_server_mech_step: 0 92`) and ours verifies it.
//! * With Remote Management on, a login also needs the account to hold
//!   Remote Management privileges (Observe and Control); without them every
//!   login, by any type and by Apple's own client, is refused after the
//!   password is accepted (`lg level 0`, authresult 1).
//! * A wrong password under type 33 or 36 is refused in place of the Mac's
//!   own proof, about 1.5 to 3 s after the client's proof. A privilege
//!   refusal comes only after that proof, so the two can be told apart.
//!   Under type 30 both end in SecurityResult 1 with the same reason,
//!   "Authentication or authorization failure", so nothing tells them apart
//!   and the viewer adds a Remote Management hint instead.
//! * ViewerInfo has a fixed 62 byte body (version, seven u32 values, the 32
//!   byte capability bitmap), read off Apple's own client through a relay
//!   that logs both legs of a real session. The Mac reads it at that size
//!   whatever its length field says, so the shorter one this client used to
//!   send swallowed the SetEncryption after it and the session never
//!   started. With the native one the session runs, and the Mac also reports
//!   clipboard changes.
//! * The Mac adds a virtual display for a SetDisplayConfiguration, so none is
//!   sent. It drops the opening's full update request while it sets up
//!   screen capture, so the client asks again after the first desktop size
//!   announcement. Types 30, 33 and 36 all give the full picture, and a
//!   disconnect closes cleanly on both sides.
//! * After the first picture a macOS 26 Mac sharing its real displays
//!   pushes nothing on its own, AutoFrameBufferUpdate or not: its clock and
//!   windows changed for minutes and no update came. It answers update
//!   requests, but keeps only the last one, so a one pixel request narrowed
//!   every later answer to a 3x3 corner and an incremental request sent
//!   behind a full one cancelled the full picture. The session now pulls,
//!   one incremental request at a time, after the full picture is in.
//! * Clipboard, as Apple's client does it: the Mac sends MiscStatus 2 when
//!   its pasteboard changes, the viewer answers with ClipboardFetch
//!   (`0b 00 00 00 00 00 00 00`), and the Mac sends a ClipboardSend with the
//!   data (zlib, sync flushed). A fetch with a 1 and a tag gets only the list
//!   of types (a promise). The viewer's clipboard goes to the Mac as a
//!   ClipboardSend in the same layout; a standard ClientCutText reaches only
//!   the classic text flavour. `live_clipboard_both_ways` checks both ways.
//! * Keys, shifted symbols, non ASCII letters, Return, Backspace, arrows,
//!   clicks and cmd+a, cmd+z, cmd+s, cmd+w all arrive:
//!   `live_input_into_own_textedit`.
//! * 0x1c (media) on an Intel Mac: the Mac announces media (a 1010 rectangle)
//!   when 1010 is listed, and answers an offer by loading its video encoder,
//!   then logging `udpVideoStreamWasInitialized 0` and `unable to init media
//!   stream`; it sends no answer message. The offer sent had empty blobs.
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
/// Route the client's own tracing to stderr when `RUST_LOG` is set, so a
/// live run can show what the session saw.
fn init_tracing() {
    if std::env::var("RUST_LOG").is_ok() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .try_init();
    }
}

async fn session_with(pref: &str, what: &str) {
    init_tracing();
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

    // A pointer move is real input on the Mac, so it is opt in: run with
    // DVV_LIVE_APPLE_INPUT=1 only when nobody is using that Mac.
    if std::env::var("DVV_LIVE_APPLE_INPUT").is_ok() {
        send(
            &handle,
            ClientCommand::Pointer {
                x: damage.width / 2,
                y: damage.height / 2,
                button_mask: 0,
            },
        )
        .await;
    }
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

/// A wrong password, sent once per login type: under 33 and 36 the Mac
/// refuses before its own proof, so the viewer says the password was not
/// accepted and asks again; it must not claim the password was right. Type
/// 30 has no such signal and carries the Remote Management hint. Costs one
/// failed attempt per type, so it runs only with DVV_LIVE_APPLE_WRONG=1.
#[tokio::test]
async fn live_wrong_password_says_so() {
    init_tracing();
    if std::env::var("DVV_LIVE_APPLE_WRONG").is_err() {
        eprintln!("SKIP live_wrong_password_says_so: DVV_LIVE_APPLE_WRONG is not set");
        return;
    }
    let Some(mut t) = target("live_wrong_password_says_so") else {
        return;
    };
    t.pass.push_str("-not-it");
    let prefs = std::env::var("DVV_LIVE_APPLE_WRONG_TYPES")
        .unwrap_or_else(|_| "apple-srp-rsa,apple-dh".into());
    for pref in prefs.split(',') {
        let started = std::time::Instant::now();
        let (_handle, mut events) = spawn_session(live_options(&t, pref));
        let reason = events
            .wait_state(Duration::from_secs(30), "the refusal", |s| match s {
                SessionState::Disconnected { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .await;
        eprintln!(
            "LIVE {pref} wrong password: {reason:?} after {} ms",
            started.elapsed().as_millis()
        );
        assert_ne!(reason, vnc_core::security::APPLE_ACCESS_DENIED, "{pref}");
        assert!(
            reason.contains("password was not accepted"),
            "{pref}: {reason}"
        );
        if pref == "apple-dh" {
            assert!(reason.contains("Remote Management, Options"), "{reason}");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
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

/// The Mac's pasteboard as text, through its own `pbpaste`.
fn mac_clipboard() -> String {
    let out = std::process::Command::new("pbpaste")
        .output()
        .expect("pbpaste runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Set the Mac's pasteboard text through its own `pbcopy`.
fn set_mac_clipboard(text: &str) {
    use std::io::Write;
    let mut child = std::process::Command::new("pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("pbcopy runs");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    child.wait().unwrap();
}

/// Puts the Mac's pasteboard text back when dropped, so a failing assertion
/// does not leave a test marker where the owner would paste it.
struct RestoreClipboard(String);

impl Drop for RestoreClipboard {
    fn drop(&mut self) {
        set_mac_clipboard(&self.0);
    }
}

/// Clipboard both ways over the encrypted session (type 33, auto selected).
/// Runs only with `DVV_LIVE_APPLE_LOCAL=1`, meaning the Mac under test is
/// this machine, so its pasteboard can be read and set with `pbpaste` and
/// `pbcopy`. The pasteboard text there before the test is put back after.
#[tokio::test]
async fn live_clipboard_both_ways() {
    init_tracing();
    let what = "live_clipboard_both_ways";
    if std::env::var("DVV_LIVE_APPLE_LOCAL").is_err() {
        eprintln!("SKIP {what}: DVV_LIVE_APPLE_LOCAL is not set");
        return;
    }
    let Some(t) = target(what) else { return };
    let _restore = RestoreClipboard(mac_clipboard());
    let mut o = live_options(&t, "auto");
    o.vnc_mut().security_pref = None;
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(Duration::from_secs(40)).await;
    events.drain_for(Duration::from_secs(2)).await;

    // Viewer to Mac.
    let to_mac = format!("dvv clipboard to the Mac {}", std::process::id());
    send(&handle, ClientCommand::ClipboardText(to_mac.clone())).await;
    let mut seen = String::new();
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        seen = mac_clipboard();
        if seen == to_mac {
            break;
        }
    }
    // Mac to viewer.
    let from_mac = format!("dvv clipboard from the Mac {}", std::process::id());
    set_mac_clipboard(&from_mac);
    events.drain_for(Duration::from_secs(6)).await;
    let got = events.any(|e| matches!(e, SessionEvent::ClipboardText(t) if t.contains(&from_mac)));
    eprintln!("LIVE {what}: viewer got the Mac's text: {got}");

    send(&handle, ClientCommand::Disconnect).await;
    eprintln!(
        "LIVE {what}: Mac pasteboard took the viewer's text: {}",
        seen == to_mac
    );
    assert_eq!(
        seen, to_mac,
        "the Mac's pasteboard did not take the viewer's text"
    );
    assert!(got, "the viewer never got the Mac's pasteboard text");
}

/// Seconds since the Mac last had keyboard or pointer input from anyone.
fn mac_idle_seconds() -> f64 {
    let out = std::process::Command::new("ioreg")
        .args(["-c", "IOHIDSystem"])
        .output()
        .expect("ioreg runs");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.contains("\"HIDIdleTime\""))
        .and_then(|l| l.rsplit('=').next())
        .and_then(|v| v.trim().parse::<f64>().ok())
        .map(|ns| ns / 1e9)
        .unwrap_or(0.0)
}

/// The display name of the frontmost app, from `lsappinfo`, which asks the
/// Mac nothing that could put a permission dialog on its screen.
fn mac_front_app() -> String {
    let front = std::process::Command::new("lsappinfo")
        .arg("front")
        .output()
        .expect("lsappinfo runs");
    let asn = String::from_utf8_lossy(&front.stdout).trim().to_string();
    let info = std::process::Command::new("lsappinfo")
        .args(["info", "-only", "name", &asn])
        .output()
        .expect("lsappinfo runs");
    let text = String::from_utf8_lossy(&info.stdout);
    text.rsplit('=')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .to_string()
}

/// Press and release one keysym, with modifiers held around it.
async fn tap(handle: &vnc_core::SessionHandle, mods: &[u32], keysym: u32) {
    for m in mods {
        send(
            handle,
            ClientCommand::Key {
                keysym: *m,
                keycode: None,
                down: true,
            },
        )
        .await;
    }
    send(
        handle,
        ClientCommand::Key {
            keysym,
            keycode: None,
            down: true,
        },
    )
    .await;
    send(
        handle,
        ClientCommand::Key {
            keysym,
            keycode: None,
            down: false,
        },
    )
    .await;
    for m in mods.iter().rev() {
        send(
            handle,
            ClientCommand::Key {
                keysym: *m,
                keycode: None,
                down: false,
            },
        )
        .await;
    }
    tokio::time::sleep(Duration::from_millis(40)).await;
}

/// Type text one character at a time. Shifted symbols go as their own
/// keysyms with no explicit Shift, which is what the viewer sends.
async fn type_text(handle: &vnc_core::SessionHandle, text: &str) {
    for c in text.chars() {
        let keysym = match c {
            '\n' => 0xff0d,
            c if (c as u32) < 0x100 => c as u32,
            c => 0x0100_0000 | c as u32,
        };
        tap(handle, &[], keysym).await;
    }
}

/// Rebuild the session's picture from its events and save a 1024 pixel wide
/// thumbnail as a PNG. Returns the framebuffer and the thumbnail size.
fn save_picture(
    events: &Events,
    png: &std::path::Path,
) -> (vnc_core::pixel::framebuffer::Framebuffer, u32, u32) {
    let mut fb: Option<vnc_core::pixel::framebuffer::Framebuffer> = None;
    for e in &events.seen {
        match e {
            SessionEvent::DesktopResize { width, height, .. } => {
                fb = Some(vnc_core::pixel::framebuffer::Framebuffer::new(
                    *width, *height,
                ))
            }
            SessionEvent::FramebufferUpdate { rects, .. } => {
                if let Some(f) = fb.as_mut() {
                    for r in rects {
                        f.apply(r);
                    }
                }
            }
            _ => {}
        }
    }
    let fb = fb.expect("a desktop size");
    let (w, h, rgba) = fb.thumbnail_rgba(1024);
    image::save_buffer(png, &rgba, w, h, image::ExtendedColorType::Rgba8).unwrap();
    (fb, w, h)
}

/// Look only: connect, save the picture to , hang up.
/// Sends no input, so it is safe to run while someone uses the Mac.
#[tokio::test]
async fn live_picture() {
    let what = "live_picture";
    let Ok(path) = std::env::var("DVV_LIVE_APPLE_PICTURE") else {
        eprintln!("SKIP {what}: DVV_LIVE_APPLE_PICTURE is not set");
        return;
    };
    let Some(t) = target(what) else { return };
    let mut o = live_options(&t, "auto");
    o.vnc_mut().security_pref = None;
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(Duration::from_secs(40)).await;
    events.drain_for(Duration::from_secs(4)).await;
    save_picture(&events, std::path::Path::new(&path));
    send(&handle, ClientCommand::Disconnect).await;
    eprintln!("LIVE {what}: saved {path}");
}

/// Stop before sending anything if this test's TextEdit window is no longer
/// in front, so no input can land in another app (another agent may raise
/// its own window at any moment).
async fn still_front(handle: &vnc_core::SessionHandle, what: &str) {
    let front = mac_front_app();
    if front != "TextEdit" {
        send(handle, ClientCommand::Disconnect).await;
        panic!("{what}: stopped: {front:?} came to the front");
    }
}

/// Input into a TextEdit document this test opens itself, then the saved file
/// is read back. Needs `DVV_LIVE_APPLE_LOCAL=1` and `DVV_LIVE_APPLE_INPUT=1`.
///
/// Two phases, so a person checks the picture before anything is sent:
/// the test opens its own file in TextEdit, connects, saves the session's
/// picture to `$HOME/work/dvv-input-frame.png`, and waits for
/// `$HOME/work/dvv-input-go` to hold `x y`, a point inside that window in
/// framebuffer pixels. It sends nothing unless TextEdit is frontmost and the
/// Mac has had no input for two minutes.
#[tokio::test]
async fn live_input_into_own_textedit() {
    init_tracing();
    let what = "live_input_into_own_textedit";
    if std::env::var("DVV_LIVE_APPLE_LOCAL").is_err()
        || std::env::var("DVV_LIVE_APPLE_INPUT").is_err()
    {
        eprintln!("SKIP {what}: needs DVV_LIVE_APPLE_LOCAL and DVV_LIVE_APPLE_INPUT");
        return;
    }
    let Some(t) = target(what) else { return };
    let idle = mac_idle_seconds();
    assert!(
        idle > 120.0,
        "{what}: someone used the Mac {idle:.0} s ago; not sending input"
    );

    let work = std::path::PathBuf::from(std::env::var("HOME").unwrap()).join("work");
    let file = work.join("dvv-input-test.txt");
    let go = work.join("dvv-input-go");
    let _ = std::fs::remove_file(&go);
    std::fs::write(&file, "").unwrap();
    std::process::Command::new("open")
        .args(["-a", "TextEdit"])
        .arg(&file)
        .status()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    eprintln!("LIVE {what}: front app after open: {}", mac_front_app());

    let mut o = live_options(&t, "auto");
    o.vnc_mut().security_pref = None;
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(Duration::from_secs(40)).await;
    events.drain_for(Duration::from_secs(4)).await;

    let png = work.join("dvv-input-frame.png");
    let (fb, w, h) = save_picture(&events, &png);
    eprintln!(
        "LIVE {what}: picture {}x{} saved as a {w}x{h} thumbnail; waiting for {}",
        fb.width(),
        fb.height(),
        go.display()
    );

    let mut point = None;
    for _ in 0..360 {
        if let Ok(s) = std::fs::read_to_string(&go) {
            let v: Vec<u16> = s
                .split_whitespace()
                .filter_map(|p| p.parse().ok())
                .collect();
            if v.len() == 2 {
                point = Some((v[0], v[1]));
                break;
            }
        }
        events.drain_for(Duration::from_millis(500)).await;
    }
    let _ = std::fs::remove_file(&go);
    let (x, y) = point.expect("no go file within three minutes");

    let front = mac_front_app();
    let idle = mac_idle_seconds();
    if front != "TextEdit" || idle < 120.0 {
        send(&handle, ClientCommand::Disconnect).await;
        panic!("{what}: not sending input: front app {front:?}, idle {idle:.0} s");
    }

    // Click inside the document to place the caret there.
    still_front(&handle, what).await;
    send(
        &handle,
        ClientCommand::Pointer {
            x,
            y,
            button_mask: 0,
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    send(
        &handle,
        ClientCommand::Pointer {
            x,
            y,
            button_mask: 1,
        },
    )
    .await;
    still_front(&handle, what).await;
    send(
        &handle,
        ClientCommand::Pointer {
            x,
            y,
            button_mask: 0,
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    const SUPER: u32 = 0xffeb;
    still_front(&handle, what).await;
    type_text(&handle, "Hello DeskVNC 123\n").await;
    still_front(&handle, what).await;
    type_text(&handle, "!@#$%^&*()_+{}|:\"<>?~\n").await;
    still_front(&handle, what).await;
    type_text(&handle, "caf\u{e9} \u{fc}ber ma\u{f1}ana\n").await;
    // Backspace: "xyz" then one BackSpace leaves "xy".
    still_front(&handle, what).await;
    type_text(&handle, "xyz").await;
    still_front(&handle, what).await;
    tap(&handle, &[], 0xff08).await;
    still_front(&handle, what).await;
    tap(&handle, &[], 0xff0d).await;
    // Arrows: "AC", Left, "B" gives "ABC".
    still_front(&handle, what).await;
    type_text(&handle, "AC").await;
    still_front(&handle, what).await;
    tap(&handle, &[], 0xff51).await;
    still_front(&handle, what).await;
    type_text(&handle, "B").await;
    still_front(&handle, what).await;
    tap(&handle, &[], 0xff53).await;
    still_front(&handle, what).await;
    tap(&handle, &[], 0xff0d).await;
    // Each shortcut is proven by what it leaves in the saved file. TextEdit
    // capitalises the start of a line on its own, so compare ignoring case.
    let read = || {
        std::fs::read_to_string(&file)
            .unwrap_or_default()
            .to_lowercase()
    };
    let want =
        "hello deskvnc 123\n!@#$%^&*()_+{}|:\"<>?~\ncaf\u{e9} \u{fc}ber ma\u{f1}ana\nxy\nabc\n";
    still_front(&handle, what).await;
    tap(&handle, &[SUPER], 's' as u32).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let typed = read();
    eprintln!("LIVE {what}: after typing and cmd+s the file holds {typed:?}");
    // cmd+a selects everything, so one typed letter replaces it all.
    still_front(&handle, what).await;
    tap(&handle, &[SUPER], 'a' as u32).await;
    type_text(&handle, "Z").await;
    still_front(&handle, what).await;
    tap(&handle, &[SUPER], 's' as u32).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let replaced = read();
    eprintln!("LIVE {what}: after cmd+a, Z and cmd+s: {replaced:?}");
    // cmd+z undoes the replacement.
    still_front(&handle, what).await;
    tap(&handle, &[SUPER], 'z' as u32).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    still_front(&handle, what).await;
    tap(&handle, &[SUPER], 's' as u32).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let undone = read();
    eprintln!("LIVE {what}: after cmd+z and cmd+s: {undone:?}");
    // cmd+w closes the saved document, nothing else.
    still_front(&handle, what).await;
    tap(&handle, &[SUPER], 'w' as u32).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    send(&handle, ClientCommand::Disconnect).await;
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_file(&png);
    assert_eq!(typed, want, "typing");
    assert_eq!(replaced, "z", "cmd+a then Z");
    assert_eq!(undone, want, "cmd+z");
}

/// One click at `DVV_LIVE_APPLE_CLICK` ("x y", framebuffer pixels), and then
/// cmd+w if `DVV_LIVE_APPLE_THEN_CLOSE` is set, only while TextEdit is in
/// front. For finishing what `live_input_into_own_textedit` left open in its
/// own window (a save sheet, the document itself).
#[tokio::test]
async fn live_click_in_own_textedit() {
    let what = "live_click_in_own_textedit";
    let Ok(at) = std::env::var("DVV_LIVE_APPLE_CLICK") else {
        eprintln!("SKIP {what}: DVV_LIVE_APPLE_CLICK is not set");
        return;
    };
    if std::env::var("DVV_LIVE_APPLE_LOCAL").is_err() {
        eprintln!("SKIP {what}: needs DVV_LIVE_APPLE_LOCAL");
        return;
    }
    let v: Vec<u16> = at
        .split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect();
    let (x, y) = (v[0], v[1]);
    let Some(t) = target(what) else { return };
    let mut o = live_options(&t, "auto");
    o.vnc_mut().security_pref = None;
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(Duration::from_secs(40)).await;
    events.drain_for(Duration::from_secs(2)).await;
    still_front(&handle, what).await;
    send(
        &handle,
        ClientCommand::Pointer {
            x,
            y,
            button_mask: 0,
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    send(
        &handle,
        ClientCommand::Pointer {
            x,
            y,
            button_mask: 1,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::Pointer {
            x,
            y,
            button_mask: 0,
        },
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    if std::env::var("DVV_LIVE_APPLE_THEN_CLOSE").is_ok() {
        still_front(&handle, what).await;
        tap(&handle, &[0xffeb], 'w' as u32).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    send(&handle, ClientCommand::Disconnect).await;
    eprintln!("LIVE {what}: clicked at {x},{y}");
}
