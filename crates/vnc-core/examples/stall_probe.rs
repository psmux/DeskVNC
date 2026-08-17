//! Find the freezes: log every framebuffer update's arrival and size, then
//! report the gap distribution and the worst stalls.
//!
//! This is the real vnc-core client stack with no UI, no webview and no live
//! previews, which is what makes it useful: run it beside a python limb and the
//! gap between the two tells you whether a problem is ours or the server's.
//!
//! It was written to A/B `lossless_refresh`, on the theory that its periodic
//! non-incremental repaint caused the reported freezes. It did not: with the
//! refresh on, 113 updates in 30 s with 58 stalls over 250 ms; with it off,
//! 115 updates and 59 stalls. That null result is worth keeping, because the
//! same shape of hypothesis is easy to reach for again. The real cause was the
//! auto tuner driving Tight compression to 0, found later with the `proxy`
//! limb (see docs/DIAGNOSTICS.md section 5).
//!
//! ```sh
//! DVV_HOST=<server> DVV_PASS=... cargo run --release -p vnc-core --example stall_probe
//! ```
//!
//! Environment:
//!   `DVV_HOST`, `DVV_PORT`, `DVV_SECONDS`, `DVV_USER`, `DVV_PASS`
//!   `DVV_QUALITY=high|medium|low`  pin the tier so Auto's movement does not
//!                                  confound a comparison
//!   `DVV_ALR=0`                    disable auto lossless refresh
//!   `DVV_SLOW=<ms>`                block the consumer per update, standing in
//!                                  for a slow webview, to test whether OUR
//!                                  slowness backpressures the server
//!   `DVV_ALWAYS_REFRESH=1`         turn on the full-screen-per-second toggle,
//!                                  which measurably degrades other clients
//!   `DVV_TRACE_PROTOCOL=1`         with `RUST_LOG=vnc_core=info`, log every
//!                                  client message and a per-second summary
//!
//! The per-second STATS line carries `server_duty_cycle`, which is the honest
//! saturation signal: unlike wall-clock latency it is about our own session and
//! does not swing with how busy the remote desktop happens to be.

use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use vnc_core::{
    ConnectOptions, Credentials, QualityPreset, RectPayload, Session, SessionEvent, SessionState,
};

fn payload_bytes(p: &RectPayload) -> usize {
    match p {
        RectPayload::Rgba(v) | RectPayload::Jpeg(v) => v.len(),
        RectPayload::H264 { data, .. } => data.len(),
        RectPayload::CopyRect { .. } => 0,
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Without a subscriber, `DVV_TRACE_PROTOCOL=1` produces no output at all,
    // which reads as "the trace is broken" rather than "nothing is listening".
    // Default to `warn` so a normal run stays quiet and the STATS lines below
    // are the only output, but honour RUST_LOG so
    // `RUST_LOG=vnc_core=info DVV_TRACE_PROTOCOL=1` does what it looks like it
    // should.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_target(false)
        .init();

    let host = std::env::var("DVV_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("DVV_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5900);
    let secs: u64 = std::env::var("DVV_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let alr = std::env::var("DVV_ALR").as_deref() != Ok("0");
    // Simulate a slow frame consumer (the webview). The shipping app applies
    // each update through a serialized promise chain behind a Tauri eval+fetch
    // IPC hop; this stands in for that cost so the effect on the SERVER can be
    // measured without running the whole UI.
    let slow_ms: u64 = std::env::var("DVV_SLOW")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut o = ConnectOptions::new(host.clone(), port);
    o.credentials = Credentials {
        username: std::env::var("DVV_USER").ok(),
        password: std::env::var("DVV_PASS").ok(),
    };
    o.quality = match std::env::var("DVV_QUALITY").as_deref() {
        Ok("high") => QualityPreset::High,
        Ok("medium") => QualityPreset::Medium,
        Ok("low") => QualityPreset::Low,
        _ => QualityPreset::Auto,
    };
    o.lossless_refresh = alr;
    o.allow_insecure = true;
    o.reconnect.enabled = false;

    println!(
        "connecting to {host}:{port}  lossless_refresh={}  quality={:?}  for {secs}s",
        alr, o.quality
    );

    let (tx, mut rx) = mpsc::channel::<SessionEvent>(256);
    let handle = Session::spawn("stall".into(), o, tx);

    // `always_refresh` is a one-click toolbar toggle that makes the 1 s tick
    // send a full-screen NON-incremental request forever (run_loop.rs:1397).
    // On this server each answer costs 130 to 180 ms of encoder time, which is
    // shared with every other client.
    if std::env::var("DVV_ALWAYS_REFRESH").as_deref() == Ok("1") {
        let h = handle.commands.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let _ = h
                .send(vnc_core::ClientCommand::SetAlwaysRefresh(true))
                .await;
            println!("  >>> always_refresh ENABLED");
        });
    }

    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);

    let mut last: Option<Instant> = None;
    // (gap_ms, rect_count, bytes, since_connect_s)
    let mut gaps: Vec<(f64, usize, usize, f64)> = Vec::new();
    let mut connected_at: Option<Instant> = None;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let ev = match tokio::time::timeout(remaining, rx.recv()).await {
            Err(_) => break,
            Ok(None) => break,
            Ok(Some(e)) => e,
        };
        match ev {
            SessionEvent::StateChanged(SessionState::Connected) => {
                connected_at = Some(Instant::now());
                println!("[{:6.2}s] connected", start.elapsed().as_secs_f64());
            }
            SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                println!("disconnected: {reason}");
                break;
            }
            SessionEvent::Error(e) => println!("error: {e}"),
            SessionEvent::Stats(s) => {
                // `server_duty_cycle` is the fraction of the tick spent
                // receiving and decoding. It is a far better saturation signal
                // than typing latency, which is confounded by how busy the
                // remote desktop happens to be. Near 1.0 means the server is
                // encoding flat out for us and has nothing left for anyone
                // else, including our own input echo.
                println!(
                    "[{:6.2}s] STATS duty {:5.1}%  rtt {:6.1} ms ({:?})  {:6.2} Mbit/s  \
                     {:4.1} fps  decode {:5.2} ms  jpegq {}",
                    start.elapsed().as_secs_f64(),
                    s.server_duty_cycle * 100.0,
                    s.rtt_ms,
                    s.rtt_source,
                    s.throughput_bps / 1e6,
                    s.fps,
                    s.decode_ms,
                    s.jpeg_quality
                );
            }
            SessionEvent::FramebufferUpdate { rects, damage } => {
                if slow_ms > 0 {
                    // Block the consumer, exactly as a busy main thread would.
                    std::thread::sleep(Duration::from_millis(slow_ms));
                }
                let now = Instant::now();
                let bytes: usize = rects.iter().map(|r| payload_bytes(&r.payload)).sum();
                if let Some(prev) = last {
                    let gap = (now - prev).as_secs_f64() * 1000.0;
                    let t = connected_at.map_or(0.0, |c| (now - c).as_secs_f64());
                    gaps.push((gap, rects.len(), bytes, t));
                    // Only shout about the ones a user would actually feel.
                    if gap > 250.0 {
                        println!(
                            "[{:6.2}s] STALL {:7.1} ms  {:4} rects  {:7.0} KiB  damage {}x{}",
                            start.elapsed().as_secs_f64(),
                            gap,
                            rects.len(),
                            bytes as f64 / 1024.0,
                            damage.width,
                            damage.height
                        );
                    }
                }
                last = Some(now);
            }
            _ => {}
        }
    }

    handle.shutdown();

    if gaps.is_empty() {
        println!("\nno updates observed");
        return;
    }

    let mut sorted: Vec<f64> = gaps.iter().map(|g| g.0).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();
    let pct = |p: f64| sorted[((n as f64 * p) as usize).min(n - 1)];

    println!(
        "\n===== {} updates over {}s, lossless_refresh={} =====",
        n, secs, alr
    );
    println!(
        "gap ms : median {:.1}   p90 {:.1}   p99 {:.1}   max {:.1}",
        pct(0.50),
        pct(0.90),
        pct(0.99),
        sorted[n - 1]
    );

    let stalls: Vec<_> = gaps.iter().filter(|g| g.0 > 250.0).collect();
    println!(
        "stalls over 250 ms : {}  ({:.1} per second)",
        stalls.len(),
        stalls.len() as f64 / secs as f64
    );
    let big: Vec<_> = gaps.iter().filter(|g| g.0 > 400.0).collect();
    println!("stalls over 400 ms : {}", big.len());

    // If ALR is the cause, the biggest stalls cluster near multiples of the
    // 5 s cooldown and carry an unusually large payload.
    println!("\nworst 8 stalls (gap, rects, KiB, seconds since connect):");
    let mut worst = gaps.clone();
    worst.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    for (gap, rects, bytes, t) in worst.iter().take(8) {
        println!(
            "  {:7.1} ms  {:4} rects  {:7.0} KiB   at t={:6.2}s",
            gap,
            rects,
            *bytes as f64 / 1024.0,
            t
        );
    }
}
