//! Check that DeskVNC connects to a saved Boundary computer again by itself
//! after the link to it dies, using two processes on one machine.
//!
//! ```sh
//! # A computer to help, trusting the helper key in <dir>. Prints its ID.
//! cargo run -p boundary-driver --example flap -- host <dir>
//! # DeskVNC's own driver connecting to it, printing every state it reports
//! cargo run -p boundary-driver --example flap -- helper <dir> <machine id>
//! ```
//!
//! Freeze the host with `kill -STOP <pid>` and thaw it with `kill -CONT`: its
//! packets stop the way they do on a link that has died without saying so.
use boundary_driver::BoundaryDriver;
use boundary_session::{
    unattended::{self, Access, Notice},
    Desktop, Frame, HostOptions, Input,
};
use remote_core::{ConnectOptions, ProtocolDriver, SessionEvent, SessionState};
use std::{path::Path, time::Instant};
use tokio::sync::mpsc;

struct Fake;
impl Desktop for Fake {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        Ok(Frame {
            width: 64,
            height: 48,
            rgba: vec![128; 64 * 48 * 4],
        })
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        Ok(())
    }
    fn release(&mut self) {}
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = Path::new(args.get(1).map(String::as_str).unwrap_or("."));
    std::fs::create_dir_all(dir)?;
    let helper = unattended::load_or_create_key(&dir.join("helper.key"))?;
    let started = Instant::now();
    match args.first().map(String::as_str) {
        Some("host") => {
            let machine = unattended::load_or_create_key(&dir.join("machine.key"))?;
            let access_path = dir.join("access.json");
            let mut access = Access::default();
            access.enabled = true;
            access.trust(&helper.public().to_string(), "Flap helper", true)?;
            access.save(&access_path)?;
            println!("machine id {}", unattended::machine_id(&machine));
            println!("pid {}", std::process::id());
            let mut listener =
                unattended::listen(HostOptions::default(), machine, access_path, || {
                    Ok(Box::new(Fake))
                });
            let mut held = Vec::new();
            while let Some(notice) = listener.notices.recv().await {
                match notice {
                    Notice::Connected { name, session, .. } => {
                        println!(
                            "{:>6.1}s host: {name} connected",
                            started.elapsed().as_secs_f32()
                        );
                        held.push(session);
                    }
                    Notice::Status(status) => {
                        println!("{:>6.1}s host: {status}", started.elapsed().as_secs_f32())
                    }
                    Notice::Finished(result) => {
                        println!("host: listener ended: {result:?}");
                        break;
                    }
                    _ => {}
                }
            }
        }
        Some("helper") => {
            let id = args.get(2).cloned().expect("machine id");
            let driver = BoundaryDriver::default();
            driver.set_identity(helper);
            let (tx, mut rx) = mpsc::channel(256);
            let _handle = driver
                .spawn("flap".into(), ConnectOptions::boundary(id), tx)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let mut frames = 0u64;
            while let Some(event) = rx.recv().await {
                let at = started.elapsed().as_secs_f32();
                match event {
                    SessionEvent::StateChanged(state) => {
                        let state = match state {
                            SessionState::Reconnecting {
                                attempt,
                                next_retry_ms,
                                reason,
                            } => {
                                format!("reconnecting, attempt {attempt}, next in {next_retry_ms} ms: {reason}")
                            }
                            other => format!("{other:?}"),
                        };
                        println!("{at:>6.1}s helper: {state} (frames so far {frames})");
                    }
                    SessionEvent::FramebufferUpdate { .. } => frames += 1,
                    _ => {}
                }
            }
            println!("helper: session ended");
        }
        _ => eprintln!("usage: flap host <dir> | flap helper <dir> <machine id>"),
    }
    Ok(())
}
