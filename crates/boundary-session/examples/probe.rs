//! Check an invitation session between two real networks without a screen.
//!
//! ```sh
//! # On the computer being helped: print an invitation, approve the first helper
//! probe host
//! # On the helper: connect with that invitation and report the first frame
//! probe view <invitation>
//! # The same, declaring tools the way DeskVNC does
//! probe tools <invitation>
//! # Clipboard text both ways, with a file standing in for the clipboard of
//! # the computer being helped: it gives control, lets the helper see what is
//! # copied, and reports what lands. The helper sends `<text>` once let in
//! # and prints what the person copies, until it has seen `<copies>` of them.
//! probe clip-host <clipboard file>
//! probe clip-view <invitation> <text> <copies>
//! ```
use boundary_session::{Abilities, Approval, Desktop, Event, Frame, HostOptions, Input, Route};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// A screen whose clipboard is a file: writing the file is the person
/// copying, and the helper's text is written to it.
struct FileClipboard {
    path: PathBuf,
    seen: Option<std::time::SystemTime>,
}
impl Desktop for FileClipboard {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        Fake.capture()
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        Ok(())
    }
    fn release(&mut self) {}
    fn has_clipboard(&self) -> bool {
        true
    }
    fn clipboard_changed(&mut self) -> anyhow::Result<Option<String>> {
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        let first = self.seen.is_none();
        if modified == self.seen {
            return Ok(None);
        }
        self.seen = modified;
        if first || modified.is_none() {
            return Ok(None);
        }
        Ok(Some(std::fs::read_to_string(&self.path)?))
    }
    fn set_clipboard(&mut self, text: &str) -> anyhow::Result<()> {
        std::fs::write(&self.path, text)?;
        Ok(())
    }
}

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
        Some("clip-host") => {
            let path = PathBuf::from(&args[1]);
            let mut session = boundary_session::host(HostOptions::default(), move || {
                Ok(Box::new(FileClipboard { path, seen: None }))
            });
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => anyhow::bail!("nobody connected within 300 s"),
                    event = session.events.recv() => match event {
                        Some(Event::Status(s)) => println!("{:?} status: {s}", started.elapsed()),
                        Some(Event::Invitation(t)) => println!("INVITATION {t}"),
                        Some(Event::Approval { name, clipboard, answer, .. }) => {
                            println!("{:?} approving {name} with control, clipboard offered {clipboard}", started.elapsed());
                            session.set_clipboard_read(true);
                            let _ = answer.send(Approval::Control);
                        }
                        Some(Event::Connected { control, .. }) => println!("{:?} connected, control {control}", started.elapsed()),
                        Some(Event::Activity(line)) => println!("{:?} activity: {line}", started.elapsed()),
                        Some(Event::Finished(result)) => { println!("finished: {result:?}"); break; }
                        None => break,
                        _ => {}
                    },
                }
            }
        }
        Some("clip-view") => {
            let (text, copies) = (args[2].clone(), args[3].parse::<usize>()?);
            let mut session = boundary_session::viewer_with(
                args[1].clone(),
                "Probe".into(),
                HostOptions::default(),
                None,
                Abilities {
                    clipboard: true,
                    ..Abilities::default()
                },
            );
            let mut seen = 0;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => anyhow::bail!("not done within 300 s"),
                    event = session.events.recv() => match event {
                        Some(Event::Status(s)) => println!("{:?} status: {s}", started.elapsed()),
                        Some(Event::Connected { control, .. }) => println!("{:?} connected, control {control}", started.elapsed()),
                        Some(Event::ClipboardRights(rights)) => {
                            println!("{:?} rights: {rights:?}", started.elapsed());
                            if rights.write {
                                match session.send_clipboard(text.clone()) {
                                    Ok(()) => println!("{:?} sent {} characters", started.elapsed(), text.chars().count()),
                                    Err(error) => println!("{:?} not sent: {error:#}", started.elapsed()),
                                }
                            }
                        }
                        Some(Event::ClipboardText(copied)) => {
                            println!("{:?} they copied: {copied}", started.elapsed());
                            seen += 1;
                            if seen >= copies { break; }
                        }
                        Some(Event::Finished(result)) => { println!("finished: {result:?}"); break; }
                        None => break,
                        _ => {}
                    },
                }
            }
            session.stop();
        }
        _ => eprintln!(
            "usage: probe host | probe view|tools <invitation> | probe clip-host <file> | probe clip-view <invitation> <text> <copies>"
        ),
    }
    Ok(())
}
