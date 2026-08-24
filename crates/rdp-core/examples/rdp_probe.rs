//! Connect to a real RDP server and report where the sequence stops.
//!
//! The mock server in `tests/` is built from the same reading of MS-RDPBCGR as
//! the client, so a misreading is invisible to it. This example is the other
//! half: it talks to a real Windows host, and everything it finds is a fact
//! rather than an agreement with ourselves.
//!
//! Credentials come from the environment so they are never in a file, in the
//! shell history of a committed script, or in this repository.
//!
//! ```text
//! RDP_HOST=192.168.1.10 RDP_USER=someone RDP_PASS=... \
//!   cargo run -p rdp-core --example rdp_probe
//! ```
//!
//! `RDP_DOMAIN` and `RDP_PORT` are optional. `RUST_LOG` defaults to a level
//! that prints the diagnostic frame dumps, which is the point of running it.

use remote_core::{ConnectOptions, Credentials, SessionEvent};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "rdp_core=debug,rdp_pdu=debug".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    let host = env_or_exit("RDP_HOST");
    let user = env_or_exit("RDP_USER");
    let pass = env_or_exit("RDP_PASS");
    let domain = std::env::var("RDP_DOMAIN").ok().filter(|d| !d.is_empty());
    let port: u16 = std::env::var("RDP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3389);

    println!("connecting to {host}:{port} as {user}");

    let mut options = ConnectOptions::rdp(&host, port);
    options.credentials = match &domain {
        Some(d) => Credentials::domain_user_pass(d, &user, &pass),
        None => Credentials::user_pass(&user, &pass),
    };

    let (events_tx, mut events_rx) = mpsc::channel::<SessionEvent>(256);

    // Drive the real session, the same entry point the application uses, so
    // this exercises the whole path and not just the connection sequence. An
    // earlier version of this probe stopped at `Connected` and therefore
    // proved nothing about the first frame, which is where the next fault was.
    let handle = rdp_core::RdpSession::spawn("probe".to_owned(), options, events_tx);

    let mut frames = 0usize;
    let mut cursors = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);

    while let Some(ev) = events_rx.recv().await {
        match &ev {
            // The picture. Counted rather than printed: a busy desktop sends
            // hundreds and the interesting fact is that any arrived at all.
            SessionEvent::FramebufferUpdate { .. } => {
                frames += 1;
                if frames == 1 {
                    println!("  FIRST FRAME received");
                }
            }
            SessionEvent::CursorUpdate(_) => cursors += 1,
            SessionEvent::CertificatePrompt {
                fingerprint,
                subject,
                scheme,
                ..
            } => {
                println!("  certificate prompt: {subject} {fingerprint}");
                println!("  (probe approves it for this run only)");
                let _ = handle
                    .send(remote_core::ClientCommand::TrustCertificate {
                        fingerprint: fingerprint.clone(),
                        permanent: false,
                        scheme: *scheme,
                    })
                    .await;
            }
            SessionEvent::StateChanged(state) => {
                println!("  state: {state:?}");
                if matches!(state, remote_core::SessionState::Disconnected { .. }) {
                    break;
                }
            }
            other => println!("  event: {other:?}"),
        }
        if std::time::Instant::now() > deadline {
            println!("  (20 seconds elapsed, stopping)");
            let _ = handle.send(remote_core::ClientCommand::Disconnect).await;
            break;
        }
    }

    println!("\nframes: {frames}, cursor updates: {cursors}");
    if frames > 0 {
        println!("the picture arrived");
    } else {
        println!("NO FRAME ARRIVED");
    }
}

fn env_or_exit(key: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("{key} must be set. See this example's module comment.");
            std::process::exit(2);
        }
    }
}
