//! Measure Boundary, VNC and RDP against the same stage, the same way.
//!
//! ```sh
//! # Loopback: a Boundary host drawing the stage offscreen in this process.
//! remote-bench loopback [--size 1920x1080] [--label mac-loopback]
//!
//! # A Boundary host on the machine being measured, sharing its real screen.
//! remote-bench host [--bind 10.0.0.9]                 # prints INVITATION
//! remote-bench host --synthetic --control 10.0.0.5:47800  # offscreen stage
//!
//! # The measuring client. Start bench-stage on the host with
//! # --control <this machine>:47800 first.
//! remote-bench run --proto vnc --target 10.0.0.9:5900 [--password p]
//! remote-bench run --proto rdp --target 10.0.0.9:3389 --user u --password p
//! remote-bench run --proto boundary --target <invitation>
//! ```
//!
//! Every run writes `<label>.json` (summary and raw samples) and
//! `<label>.csv` (one row per sample) into `--out`, default
//! `docs/benchmarks/raw`.
mod fb;
mod measure;
mod stage;

use anyhow::{Context, Result, bail};
use boundary_session::{Approval, Event, HostOptions};
use std::time::Duration;

pub fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

pub fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn size(args: &[String]) -> (u32, u32) {
    arg(args, "--size")
        .and_then(|s| {
            let (w, h) = s.split_once('x')?;
            Some((w.parse().ok()?, h.parse().ok()?))
        })
        .unwrap_or((1920, 1080))
}

fn host_options(args: &[String]) -> Result<HostOptions> {
    Ok(match arg(args, "--bind") {
        Some(ip) => HostOptions {
            relay: false,
            relay_url: None,
            bind_ip: Some(ip.parse().context("--bind address")?),
        },
        None => HostOptions::default(),
    })
}

/// Serve a Boundary host, approving control for whoever arrives, and print
/// the invitation on stdout. `desktop` is made when the helper is let in.
fn serve<F>(options: HostOptions, desktop: F) -> tokio::sync::oneshot::Receiver<String>
where
    F: FnOnce() -> Result<Box<dyn boundary_session::Desktop>> + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut session = boundary_session::host(options, desktop);
    tokio::spawn(async move {
        let mut tx = Some(tx);
        while let Some(event) = session.events.recv().await {
            match event {
                Event::Invitation(ticket) => {
                    println!("INVITATION {ticket}");
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(ticket);
                    }
                }
                Event::Approval { answer, .. } => {
                    let _ = answer.send(Approval::Control);
                }
                Event::Finished(result) => {
                    eprintln!("host finished: {result:?}");
                    break;
                }
                _ => {}
            }
        }
    });
    rx
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("loopback") => {
            let (w, h) = size(&args);
            let offscreen = stage::Offscreen::new(w, h);
            let shared = offscreen.clone();
            let ticket = serve(host_options(&args)?, move || {
                Ok(Box::new(stage::OffscreenDesktop::new(shared)))
            })
            .await?;
            let config = measure::Config::from_args(&args, "boundary", ticket)?;
            measure::run(config, async { Ok(stage::Stage::Local(offscreen)) }).await
        }
        Some("host") => {
            let synthetic = flag(&args, "--synthetic");
            let (w, h) = size(&args);
            let _ticket = if synthetic {
                let offscreen = stage::Offscreen::new(w, h);
                // The offscreen stage answers the client's link as the stage
                // window does, so a remote run gets its clocks synced.
                if let Some(addr) = arg(&args, "--control") {
                    stage::dial(addr, offscreen.clone());
                }
                serve(host_options(&args)?, move || {
                    Ok(Box::new(stage::OffscreenDesktop::new(offscreen)))
                })
            } else {
                serve(host_options(&args)?, boundary_platform::open_primary)
            };
            let secs: u64 = arg(&args, "--secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(900);
            tokio::time::sleep(Duration::from_secs(secs)).await;
            Ok(())
        }
        Some("run") => {
            let proto = arg(&args, "--proto").context("--proto vnc|rdp|boundary")?;
            let target = arg(&args, "--target").context("--target")?;
            let config = measure::Config::from_args(&args, &proto, target)?;
            let port: u16 = arg(&args, "--control")
                .and_then(|p| p.parse().ok())
                .unwrap_or(47800);
            // Listen before connecting: over RDP to xrdp, the stage only
            // starts once the login the bench makes creates the desktop.
            let listener = stage::Link::listen(port).await?;
            let link = async move {
                Ok(stage::Stage::Linked(
                    stage::Link::accept(listener, Duration::from_secs(120)).await?,
                ))
            };
            measure::run(config, link).await
        }
        _ => bail!("usage: remote-bench loopback | host | run (see the top of main.rs)"),
    }
}
