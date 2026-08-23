//! Drive a REAL session against a real VNC server and trace every event, to
//! prove whether the interactive credential prompt actually fires end to end.
//!
//! Usage:
//!   cargo run -p vnc-core --example credential_probe -- 127.0.0.1:5900
//!
//! It answers the first `CredentialsRequired` with deliberately wrong dummy
//! credentials, so it never authenticates anywhere. It exists to show WHERE
//! the flow breaks, not to log in.

use std::time::Duration;

use tokio::sync::mpsc;
use vnc_core::{ClientCommand, ConnectOptions, Session, SessionEvent};

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:5900".to_string());
    let (host, port) = target.rsplit_once(':').expect("host:port");
    let port: u16 = port.parse().expect("port");

    println!("== connecting to {host}:{port} with NO stored credentials ==");

    let mut options = ConnectOptions::vnc(host, port);
    // Exactly the state a user is in on a fresh host: nothing saved.
    options.credentials = Default::default();
    options.connect_timeout = Duration::from_secs(10);
    // Do not let the supervisor retry, we want one clean attempt.
    options.reconnect.enabled = false;

    let (event_tx, mut event_rx) = mpsc::channel(64);
    let handle = Session::spawn("probe".into(), options, event_tx);

    let mut prompted = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    loop {
        let ev = tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                println!("\n!! TIMED OUT waiting for events");
                break;
            }
            ev = event_rx.recv() => match ev {
                Some(ev) => ev,
                None => { println!("\n== event stream closed =="); break; }
            }
        };

        match ev {
            SessionEvent::StateChanged(s) => println!("STATE: {s:?}"),
            SessionEvent::CredentialsRequired(req) => {
                prompted = true;
                println!("\n>>> PROMPT FIRED <<<");
                println!("    method   : {}", req.method);
                println!("    kind     : {:?}", req.kind);
                println!("    attempt  : {}", req.attempt);
                println!("    truncates: {}", req.truncates_password);
                println!("    hint     : {:?}", req.username_hint);
                println!("    error    : {:?}\n", req.error);

                // Answer with obviously-wrong dummy credentials.
                let _ = handle
                    .send(ClientCommand::ProvideCredentials {
                        username: Some("probe-user".into()),
                        password: "probe-not-a-real-password".into(),
                        save: false,
                    })
                    .await;
                println!("    -> sent ProvideCredentials (dummy)");
            }
            SessionEvent::Error(e) => println!("ERROR: {e}"),
            SessionEvent::CertificatePrompt { fingerprint, .. } => {
                println!("CERT PROMPT: {fingerprint}")
            }
            SessionEvent::FramebufferUpdate { .. } => println!("FRAMEBUFFER UPDATE"),
            other => println!("event: {}", short(&other)),
        }
    }

    handle.shutdown();
    println!(
        "\n== RESULT: prompt {} ==",
        if prompted {
            "FIRED (core path works)"
        } else {
            "NEVER FIRED (bug is in the core path)"
        }
    );
}

fn short(e: &SessionEvent) -> &'static str {
    match e {
        SessionEvent::DesktopName(_) => "DesktopName",
        SessionEvent::DesktopResize { .. } => "DesktopResize",
        SessionEvent::CursorUpdate(_) => "CursorUpdate",
        SessionEvent::CursorPosition { .. } => "CursorPosition",
        SessionEvent::ClipboardText(_) => "ClipboardText",
        SessionEvent::ClipboardNotify { .. } => "ClipboardNotify",
        SessionEvent::Bell => "Bell",
        SessionEvent::Stats(_) => "Stats",
        _ => "other",
    }
}
