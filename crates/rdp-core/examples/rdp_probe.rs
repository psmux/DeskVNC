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

use remote_core::{ConnectOptions, Credentials, ProtocolOptions, SessionEvent};
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
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let cancel = tokio_util::sync::CancellationToken::new();

    // Print every event as it arrives, so the phase the sequence reached is
    // visible even when the failure is a disconnect rather than an error.
    // `SessionEvent` derives `Debug`, so this needs no match that would go
    // stale every time a variant is added.
    //
    // This task also answers the certificate prompt, because the sequence
    // parks on it and a probe with nobody to answer just hangs. Approving
    // whatever the host presents is right here and wrong anywhere else: the
    // job is to reach the next phase and report what happened, and the
    // approval is not written to any pin store.
    let printer = tokio::spawn(async move {
        while let Some(ev) = events_rx.recv().await {
            println!("  event: {ev:?}");
            if let SessionEvent::CertificatePrompt {
                fingerprint,
                scheme,
                ..
            } = ev
            {
                println!("  (probe approves {fingerprint} for this run only)");
                let _ = cmd_tx
                    .send(remote_core::ClientCommand::TrustCertificate {
                        fingerprint,
                        permanent: false,
                        scheme,
                    })
                    .await;
            }
        }
    });

    let outcome = run(options, events_tx, cmd_rx, cancel).await;
    match outcome {
        Ok(()) => println!("\nreached Connected"),
        Err(e) => println!("\nstopped: {e}"),
    }
    drop(printer);
}

/// The connect itself, kept separate so the error is one value to report.
async fn run(
    options: ConnectOptions,
    events: mpsc::Sender<SessionEvent>,
    mut commands: mpsc::Receiver<remote_core::ClientCommand>,
    cancel: tokio_util::sync::CancellationToken,
) -> rdp_core::Result<()> {
    let ProtocolOptions::Rdp(rdp) = options.protocol.clone() else {
        unreachable!("ConnectOptions::rdp builds the RDP half")
    };
    let mut warnings = Vec::new();
    let opts = rdp_core::options::ResolvedOptions::resolve(&options, &rdp, &mut warnings)
        .map_err(|e| rdp_core::RdpError::Protocol(e.to_string()))?;
    for w in &warnings {
        println!("  warning: {w}");
    }

    let stream = rdp_core::transport::open_stream(&options, &events).await?;

    // Trust on first use with no stored pin: the probe approves whatever the
    // host presents, because its job is to reach the next phase and report,
    // not to make a trust decision on anybody's behalf.
    let pins = remote_core::CertPins::default();
    let mut creds = options.credentials.clone();
    let prompt = rdp_core::connection::Prompt {
        commands: &mut commands,
        cancel: &cancel,
        ask: &mut Default::default(),
    };
    let arc = None;
    let (_connected, _framer) =
        rdp_core::connection::connect(stream, &opts, &mut creds, &pins, arc, &events, Some(prompt))
            .await?;
    Ok(())
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
