//! Check an invitation session between two real networks without a screen.
//!
//! ```sh
//! # On the computer being helped: print an invitation, approve the first helper
//! probe host
//! # On the helper: connect with that invitation and report the first frame
//! probe view <invitation>
//! # The same, declaring tools the way DeskVNC does
//! probe tools <invitation>
//! ```
use boundary_session::{Approval, Desktop, Event, Frame, HostOptions, Input, Route};
use std::time::{Duration, Instant};

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
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    match args.first().map(String::as_str) {
        Some("host") => {
            let mut session = boundary_session::host(HostOptions::default(), || Ok(Box::new(Fake)));
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => anyhow::bail!("nobody connected within 300 s"),
                    event = session.events.recv() => match event {
                        Some(Event::Status(s)) => println!("{:?} status: {s}", started.elapsed()),
                        Some(Event::Invitation(t)) => println!("INVITATION {t}"),
                        Some(Event::Approval { name, answer, .. }) => {
                            println!("{:?} approving {name}", started.elapsed());
                            let _ = answer.send(Approval::View);
                        }
                        Some(Event::Connected { .. }) => println!("{:?} connected", started.elapsed()),
                        Some(Event::Finished(result)) => { println!("finished: {result:?}"); break; }
                        None => break,
                        _ => {}
                    },
                }
            }
        }
        Some(mode @ ("view" | "tools")) => {
            // `tools` connects the way DeskVNC does, declaring commands and files.
            let mut session = if mode == "tools" {
                boundary_session::viewer_with_tools(
                    args[1].clone(),
                    "Probe".into(),
                    HostOptions::default(),
                    None,
                )
            } else {
                boundary_session::viewer(args[1].clone(), "Probe".into(), HostOptions::default())
            };
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => anyhow::bail!("no frame within 300 s"),
                    event = session.events.recv() => match event {
                        Some(Event::Status(s)) => println!("{:?} status: {s}", started.elapsed()),
                        Some(Event::Connected { .. }) => println!("{:?} connected", started.elapsed()),
                        Some(Event::Finished(result)) => { println!("finished: {result:?}"); break; }
                        None => break,
                        _ => {}
                    },
                    changed = session.frames.changed() => {
                        if changed.is_err() { continue; }
                        if session.frames.borrow_and_update().is_some() {
                            let route = session.connectivity.borrow().route;
                            println!("{:?} frame received, route {}", started.elapsed(),
                                match route { Some(Route::Direct) => "direct", Some(Route::Relay) => "relay", _ => "unknown" });
                            break;
                        }
                    }
                }
            }
            session.stop();
        }
        _ => eprintln!("usage: probe host | probe view|tools <invitation>"),
    }
    Ok(())
}
