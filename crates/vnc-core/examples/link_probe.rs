//! Connect to a real server and report what the update stream actually looks
//! like: rect geometry, how much of the screen each update covers, arrival
//! timing, and what the Auto tuner would conclude.
//!
//! Credentials come from the environment so they never reach a shell history
//! or a log line:
//!
//!   DVV_USER=user DVV_PASS=… cargo run -p vnc-core --example link_probe -- 192.168.77.150:5900

use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use vnc_core::{ClientCommand, ConnectOptions, Credentials, Session, SessionEvent};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vnc_core=trace".into()),
        )
        .with_target(false)
        .init();
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:5900".to_string());
    let (host, port) = target.rsplit_once(':').expect("host:port");
    let port: u16 = port.parse().expect("port");

    let user = std::env::var("DVV_USER").ok();
    let pass = std::env::var("DVV_PASS").unwrap_or_default();

    let mut options = ConnectOptions::new(host, port);
    options.credentials = Credentials {
        username: user,
        password: Some(pass),
    };
    options.connect_timeout = Duration::from_secs(10);
    // DVV_PIN=<sha256 spki fingerprint> exercises the trust-on-first-use pin:
    // with the right pin the TOFU prompt must NOT appear. DVV_PIN_SCHEME picks
    // which key it describes (tls, the default, or ra2), they are different
    // keys and are never compared against each other.
    if let Some(pin) = std::env::var("DVV_PIN").ok().filter(|s| !s.is_empty()) {
        let scheme = std::env::var("DVV_PIN_SCHEME")
            .ok()
            .and_then(|s| vnc_core::PinScheme::parse(&s))
            .unwrap_or(vnc_core::PinScheme::Tls);
        options.cert_pins.set(scheme, Some(pin));
    }
    options.reconnect.enabled = false;
    // DVV_SEC=tight|vncauth|vencrypt forces a security type, to see which one
    // a given server actually authenticates against.
    options.security_pref = match std::env::var("DVV_SEC").as_deref() {
        Ok("tight") => Some(vnc_core::SecurityType::Tight),
        Ok("vncauth") => Some(vnc_core::SecurityType::VncAuth),
        Ok("vencrypt") => Some(vnc_core::SecurityType::VeNCrypt),
        _ => None,
    };

    println!("== connecting to {host}:{port} ==");
    let (event_tx, mut event_rx) = mpsc::channel(256);
    let handle = Session::spawn("probe".into(), options, event_tx);

    let started = Instant::now();
    let mut fb_w = 0u32;
    let mut fb_h = 0u32;
    let mut updates = 0u32;
    let mut full_screen_updates = 0u32;
    let mut total_px: u64 = 0;
    let mut last_update: Option<Instant> = None;
    let mut gaps: Vec<f64> = Vec::new();

    let run_for = Duration::from_secs(20);

    loop {
        let ev = tokio::select! {
            _ = tokio::time::sleep_until((started + run_for).into()) => break,
            ev = event_rx.recv() => match ev { Some(e) => e, None => break },
        };
        match ev {
            SessionEvent::StateChanged(s) => {
                println!("[{:>5.1}s] STATE {s:?}", started.elapsed().as_secs_f32())
            }
            SessionEvent::DesktopResize { width, height } => {
                fb_w = width as u32;
                fb_h = height as u32;
                println!("desktop {width}x{height}");
            }
            SessionEvent::FramebufferUpdate { rects, damage } => {
                updates += 1;
                let px: u64 = rects.iter().map(|r| r.rect.area() as u64).sum();
                total_px += px;
                let screen = (fb_w as u64) * (fb_h as u64);
                let cover = if screen > 0 {
                    px as f64 / screen as f64
                } else {
                    0.0
                };
                if cover > 0.8 {
                    full_screen_updates += 1;
                }
                let now = Instant::now();
                if let Some(prev) = last_update {
                    gaps.push(now.duration_since(prev).as_secs_f64() * 1000.0);
                }
                last_update = Some(now);
                if updates <= 25 || cover > 0.8 {
                    println!(
                        "[{:>5.1}s] update #{updates}: {} rects, {px} px ({:.0}% of screen), damage {}x{}+{}+{}",
                        started.elapsed().as_secs_f32(),
                        rects.len(),
                        cover * 100.0,
                        damage.width, damage.height, damage.x, damage.y
                    );
                }
            }
            SessionEvent::Stats(s) => {
                println!(
                    "[{:>5.1}s] STATS rtt={:.1}ms thr={:.0} kbit/s fps={:.0} enc={} jpegq={}",
                    started.elapsed().as_secs_f32(),
                    s.rtt_ms,
                    s.throughput_bps / 1000.0,
                    s.fps,
                    s.current_encoding,
                    s.jpeg_quality
                );
            }
            SessionEvent::Error(e) => println!("ERROR {e}"),
            SessionEvent::CredentialsRequired(r) => {
                println!(
                    "!! server wants credentials again: {} ({:?})",
                    r.method, r.kind
                );
                let _ = handle.send(ClientCommand::CancelCredentials).await;
            }
            _ => {}
        }
    }

    handle.shutdown();

    println!("\n===== SUMMARY over {:.0}s =====", run_for.as_secs_f32());
    println!("framebuffer      : {fb_w}x{fb_h}");
    println!("updates          : {updates}");
    println!("FULL-SCREEN (>80%): {full_screen_updates}   <-- repeated full repaints = 'waves'");
    println!("total pixels      : {total_px}");
    if !gaps.is_empty() {
        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        let mut sorted = gaps.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "update gap ms     : mean {:.0}, median {:.0}, max {:.0}",
            mean,
            sorted[sorted.len() / 2],
            sorted.last().unwrap()
        );
    }
}
