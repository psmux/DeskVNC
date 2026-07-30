//! Idle-session RSS and CPU harness (PRD/13 §3.6: < 250 MB RAM, < 2% CPU).
//!
//! Drives a real `Session` against the integration-test mock RFB server over a
//! real loopback socket, so the whole stack, transport, handshake, decoders,
//! run loop, is live. It then measures resident set size and CPU time while
//! the desktop is static.
//!
//! ```text
//! cargo run --release -p vnc-core --example idle_session
//! ```
//!
//! Note this measures *vnc-core only*: the Tauri shell and the WebView2 /
//! WKWebView processes are not included. See docs/PERFORMANCE.md.

// The mock server is shared with the integration tests; include it directly
// rather than duplicating 1100 lines of RFB server.
#[path = "../tests/common/mock_server.rs"]
mod mock_server;

use std::process::Command;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use mock_server::{MockConfig, MockServer, RectSpec, Rgb};
use vnc_core::types::{ConnectOptions, Rect, SessionEvent, SessionState};
use vnc_core::Session;

const W: u16 = 1920;
const H: u16 = 1080;

/// Resident set size of this process, in MiB.
fn rss_mib() -> f64 {
    let pid = std::process::id();
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    let kib: f64 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0.0);
    kib / 1024.0
}

/// Cumulative CPU seconds consumed by this process (`ps -o time=`).
fn cpu_secs() -> f64 {
    let pid = std::process::id();
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // Formats seen: "MM:SS.ss" and "HH:MM:SS".
    let parts: Vec<f64> = s
        .split(':')
        .map(|p| p.parse::<f64>().unwrap_or(0.0))
        .collect();
    match parts.len() {
        3 => parts[0] * 3600.0 + parts[1] * 60.0 + parts[2],
        2 => parts[0] * 60.0 + parts[1],
        _ => 0.0,
    }
}

/// One full-screen initial paint followed by many small rects, cycling every
/// encoding so all six persistent zlib streams are really allocated. This is
/// what a real static desktop looks like: one full frame, then a trickle of
/// tiny updates (clock, cursor trail, caret).
fn queue_updates(mut cfg: MockConfig, small_updates: usize) -> MockConfig {
    let full = Rect::new(0, 0, W, H);
    let grey: Rgb = [40, 44, 52];
    cfg = cfg.update(vec![RectSpec::Raw {
        rect: full,
        colour: grey,
    }]);
    for i in 0..small_updates {
        let x = ((i * 37) % 1800) as u16;
        let y = ((i * 53) % 1000) as u16;
        let r = Rect::new(x, y, 64, 64);
        let c: Rgb = [(i * 7) as u8, (i * 11) as u8, (i * 13) as u8];
        cfg = cfg.update(vec![match i % 5 {
            0 => RectSpec::Raw { rect: r, colour: c },
            1 => RectSpec::Zlib { rect: r, colour: c },
            2 => RectSpec::ZrleSolid { rect: r, colour: c },
            3 => RectSpec::TightFill { rect: r, colour: c },
            _ => RectSpec::Hextile {
                rect: r,
                bg: c,
                fg: None,
                subrects: Vec::new(),
            },
        }]);
    }
    cfg
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let idle_secs: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(10);

    let base_rss = rss_mib();
    println!("baseline RSS (process started, no session): {base_rss:8.1} MiB");

    let server = MockServer::start(queue_updates(
        MockConfig::new().size(W, H).name("Idle Bench"),
        400,
    ))
    .await;

    let mut opts = ConnectOptions::new("127.0.0.1", server.port());
    opts.allow_insecure = true;
    opts.connect_timeout = Duration::from_secs(5);

    let (tx, mut rx) = mpsc::channel(512);
    let handle = Session::spawn("idle-bench".into(), opts, tx);

    // Wait for Connected + the first framebuffer update.
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut connected, mut framed) = (false, false);
    while (!connected || !framed) && Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(SessionEvent::StateChanged(SessionState::Connected))) => connected = true,
            Ok(Some(SessionEvent::FramebufferUpdate { .. })) => framed = true,
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    if !connected {
        eprintln!("failed to connect to the mock server");
        std::process::exit(1);
    }
    println!(
        "after connect + 1080p full frame:         {:8.1} MiB",
        rss_mib()
    );

    // Churn phase: drain the 400 queued small updates. If any decoder scratch
    // buffer grew monotonically this is where RSS would climb.
    let churn_deadline = Instant::now() + Duration::from_secs(5);
    let mut churned = 0usize;
    while Instant::now() < churn_deadline {
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Some(SessionEvent::FramebufferUpdate { .. })) => churned += 1,
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                if churned >= 400 {
                    break;
                }
            }
        }
    }
    let after_churn = rss_mib();
    println!("after {churned} further updates:              {after_churn:8.1} MiB");

    // Idle: the mock has no updates left, so the desktop is static. No `ps`
    // forks inside this window, they would show up as our own CPU.
    let cpu0 = cpu_secs();
    let t0 = Instant::now();
    let idle_deadline = t0 + Duration::from_secs(idle_secs);
    while Instant::now() < idle_deadline {
        let _ = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
    }
    let wall = t0.elapsed().as_secs_f64();
    let cpu = cpu_secs() - cpu0;
    let idle_rss = rss_mib();

    println!("after {idle_secs}s idle:                        {idle_rss:8.1} MiB");
    println!(
        "idle CPU:                                 {:8.2} % of one core ({cpu:.2}s over {wall:.1}s)",
        100.0 * cpu / wall
    );
    println!(
        "growth during idle:                       {:+8.1} MiB",
        idle_rss - after_churn
    );
    println!();
    println!("budget: idle RAM < 250 MB, idle CPU < 2%");

    let _ = handle;
}
