//! Client-added input latency harness (PRD/13 §3.6: < 16 ms).
//!
//! Measures the part of the input path that vnc-core owns: the time from
//! handing a `ClientCommand::Pointer` to the session handle until the encoded
//! PointerEvent has been read off the socket by the server. That covers the
//! command channel, the run loop's select arm, message encoding and the socket
//! write; it deliberately excludes the OS event tap, the webview and the Tauri
//! IPC hop, which live outside this crate.
//!
//! ```text
//! cargo run --release -p vnc-core --example input_latency
//! ```

#[path = "../tests/common/mock_server.rs"]
mod mock_server;

use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use mock_server::{MockConfig, MockServer};
use vnc_core::types::{ClientCommand, ConnectOptions, SessionEvent, SessionState};
use vnc_core::Session;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    // Detection polls the mock's recorded-message log, which is an O(n) scan,
    // so the reported latency includes the harness's own polling cost and is
    // an over-estimate. Keep the sample count modest to bound that overhead.
    let samples: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(200);

    let server = MockServer::start(MockConfig::new().size(1920, 1080).name("Input Bench")).await;
    let mut opts = ConnectOptions::new("127.0.0.1", server.port());
    opts.allow_insecure = true;
    opts.connect_timeout = Duration::from_secs(5);

    let (tx, mut rx) = mpsc::channel(512);
    let handle = Session::spawn("input-bench".into(), opts, tx);

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut connected = false;
    while !connected && Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(SessionEvent::StateChanged(SessionState::Connected))) => connected = true,
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    if !connected {
        eprintln!("failed to connect to the mock server");
        std::process::exit(1);
    }
    // Drain anything the handshake queued so the run loop is genuinely idle.
    tokio::time::sleep(Duration::from_millis(200)).await;
    while rx.try_recv().is_ok() {}

    let mut us: Vec<f64> = Vec::with_capacity(samples);
    let mut seen = server.pointer_events().len();
    for i in 0..samples {
        let x = (i % 1900) as u16;
        let t0 = Instant::now();
        handle
            .send(ClientCommand::Pointer {
                x,
                y: 10,
                button_mask: 0,
            })
            .await
            .expect("session alive");
        // Spin until the server has actually read the event off the wire.
        let target = seen + 1;
        loop {
            let n = server.pointer_events().len();
            if n >= target {
                us.push(t0.elapsed().as_secs_f64() * 1e6);
                seen = n;
                break;
            }
            if t0.elapsed() > Duration::from_secs(1) {
                eprintln!("pointer event {i} never arrived");
                std::process::exit(1);
            }
            tokio::task::yield_now().await;
        }
    }

    us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |q: f64| us[((us.len() as f64 - 1.0) * q) as usize];
    println!("client-added input latency over {} samples", us.len());
    println!("  min    {:8.1} µs", us[0]);
    println!("  median {:8.1} µs", pick(0.50));
    println!("  p95    {:8.1} µs", pick(0.95));
    println!("  p99    {:8.1} µs", pick(0.99));
    println!("  max    {:8.1} µs", us[us.len() - 1]);
    println!();
    println!("budget: client-added input latency < 16 ms (16000 µs)");
}
