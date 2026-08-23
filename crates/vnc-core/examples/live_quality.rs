//! Live quality diagnostic: connect to a real server and print what Auto
//! decides, once a second, with the measurement it decided on.
//!
//! This exists because the Auto tuner's inputs are invisible from the UI: the
//! session reports the quality it ended up at, never the throughput figure
//! that drove it there, so "the picture is pixelated on a LAN" is impossible
//! to attribute without instrumenting the decision itself.
//!
//! ```sh
//! DVV_HOST=192.168.77.152 DVV_PASS=… cargo run -p vnc-core --example live_quality
//! ```
//!
//! The password is read from the environment, never a file or an argument,
//! so it stays out of shell history and out of the repository.

use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use vnc_core::types::{ConnectOptions, Credentials, QualityPreset, SessionEvent, SessionState};
use vnc_core::Session;

#[tokio::main]
async fn main() {
    // Without this `RUST_LOG` is inert and the protocol tracing that explains
    // WHY a session behaves as it does never reaches the terminal.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let host = std::env::var("DVV_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("DVV_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5900);
    let seconds: u64 = std::env::var("DVV_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let preset = match std::env::var("DVV_QUALITY").as_deref() {
        Ok("high") => QualityPreset::High,
        Ok("medium") => QualityPreset::Medium,
        Ok("low") => QualityPreset::Low,
        _ => QualityPreset::Auto,
    };

    let mut options = ConnectOptions::vnc(host.clone(), port);
    options.quality = preset;
    // Pin the security type when asked: which one a server authenticates you
    // with changes how the credentials are presented, and RealVNC offers
    // three at once.
    options.vnc_mut().security_pref = match std::env::var("DVV_SECURITY").as_deref() {
        Ok("ra2") => Some("ra2".to_string()),
        Ok("ra2-256") => Some("ra2-256".to_string()),
        Ok("vencrypt") => Some("vencrypt".to_string()),
        _ => None,
    };
    // The Pi's server offers VncAuth, which the client refuses by default.
    options.vnc_mut().allow_insecure = true;
    options.credentials = Credentials {
        username: std::env::var("DVV_USER").ok(),
        password: std::env::var("DVV_PASS").ok(),
        domain: None,
    };
    // One attempt: a reconnect loop would muddy the measurement.
    options.reconnect.enabled = false;

    println!("connecting to {host}:{port} as {preset:?} for {seconds}s");
    let (tx, mut rx) = mpsc::channel::<SessionEvent>(256);
    let handle = Session::spawn("live-quality".into(), options, tx);

    let started = Instant::now();
    let deadline = Duration::from_secs(seconds);
    let mut frames = 0u64;
    let mut bytes = 0u64;

    while started.elapsed() < deadline {
        let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await else {
            break;
        };
        match event {
            SessionEvent::StateChanged(SessionState::Connected) => {
                println!("[{:>5.1}s] connected", started.elapsed().as_secs_f32());
            }
            SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                println!("disconnected: {reason}");
                break;
            }
            SessionEvent::Error(e) => println!("error: {e}"),
            SessionEvent::FramebufferUpdate { rects, .. } => {
                frames += 1;
                let _ = rects;
            }
            SessionEvent::Stats(s) => {
                bytes = s.bytes_received;
                // `throughput_bps` is the figure `Tier::from_link` thresholds
                // on: >20 Mbit High, >5 Medium, >1 LowIsh, else Low.
                println!(
                    "[{:>5.1}s] {:>8.2} Mbit/s | jpeg q{} | enc {} | {:>5.1} fps | decode {:>5.1} ms | rtt {:>5.1} ms | {} KiB",
                    started.elapsed().as_secs_f32(),
                    s.throughput_bps / 1e6,
                    s.jpeg_quality,
                    s.current_encoding,
                    s.fps,
                    s.decode_ms,
                    s.rtt_ms,
                    s.bytes_received / 1024,
                );
            }
            _ => {}
        }
    }

    println!(
        "\n{frames} framebuffer updates, {} KiB total in {:.1}s",
        bytes / 1024,
        started.elapsed().as_secs_f32()
    );
    handle.shutdown();
}
