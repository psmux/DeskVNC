//! Drive an unattended computer from a shell, with no window: for testing
//! control where nobody can watch a viewer, such as a Mac at its sign in
//! screen.
//!
//! ```sh
//! drive <machine ID or address> <helper key file> [name] < commands
//! ```
//!
//! The helper key file is the identity the computer paired with, such as
//! DeskVNC's `boundary-helper.key`; it is read, never written. Commands come
//! one to a line on standard input:
//!
//! ```text
//! move <x> <y>       pointer to a fraction of the screen, 0 to 1
//! click [right]      press and release a button where the pointer is
//! key <name>         Escape, Backspace, Enter, Tab, Space, or one letter
//! type <text>        type the text as it is
//! shot <file.png>    save the screen as the helper sees it now
//! wait <seconds>     do nothing for a while
//! quit               end the session
//! ```
//!
//! Every event, notice and command result is printed with the seconds since
//! start, so a run can be read back beside the computer's own log.
use anyhow::{Context, Result, bail};
use boundary_session::unattended::{self, SecretKey};
use boundary_session::{Abilities, Button, Event, HostOptions, Input, Key, Session};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};

fn key(name: &str) -> Result<Key> {
    Ok(match name {
        "Escape" => Key::Escape,
        "Backspace" => Key::Backspace,
        "Enter" => Key::Enter,
        "Tab" => Key::Tab,
        "Space" => Key::Space,
        one if one.chars().count() == 1 => Key::Letter(one.chars().next().unwrap_or(' ')),
        other => bail!("no key called {other}"),
    })
}

fn press(session: &Session, key: Key) -> Result<()> {
    session.input(Input::Key { key, down: true })?;
    session.input(Input::Key { key, down: false })
}

fn run(session: &mut Session, line: &str) -> Result<bool> {
    let (verb, rest) = line.split_once(' ').unwrap_or((line, ""));
    match verb {
        "move" => {
            let mut parts = rest.split_whitespace().map(str::parse::<f32>);
            let (Some(Ok(x)), Some(Ok(y))) = (parts.next(), parts.next()) else {
                bail!("move takes two fractions");
            };
            session.input(Input::Move { x, y })?;
        }
        "click" => {
            let button = if rest.trim() == "right" {
                Button::Right
            } else {
                Button::Left
            };
            session.input(Input::Button { button, down: true })?;
            std::thread::sleep(Duration::from_millis(60));
            session.input(Input::Button {
                button,
                down: false,
            })?;
        }
        "key" => press(session, key(rest.trim())?)?,
        "type" => session.input(Input::Text(rest.to_string()))?,
        "shot" => {
            let (frame, _) = session.screen().context("no screen yet")?;
            image::save_buffer(
                rest.trim(),
                &frame.rgba,
                frame.width,
                frame.height,
                image::ColorType::Rgba8,
            )?;
        }
        "wait" => std::thread::sleep(Duration::from_secs_f32(rest.trim().parse()?)),
        "quit" => return Ok(false),
        "" => {}
        other => bail!("unknown command {other}"),
    }
    Ok(true)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [machine, key_file, rest @ ..] = args.as_slice() else {
        bail!("usage: drive <machine ID or address> <helper key file> [name]");
    };
    let name = rest.first().cloned().unwrap_or_else(|| "drive".into());
    let bytes: [u8; 32] = std::fs::read(key_file)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the key file is not 32 bytes"))?;
    let started = Instant::now();
    let at = move || format!("{:7.2}", started.elapsed().as_secs_f32());
    let mut session = unattended::connect_with(
        machine.clone(),
        name,
        None,
        SecretKey::from_bytes(&bytes),
        HostOptions::default(),
        Abilities {
            notices: true,
            ..Abilities::default()
        },
    );
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut first_frame = true;
    loop {
        tokio::select! {
            event = session.events.recv() => match event {
                Some(Event::Status(s)) => println!("{} status: {s}", at()),
                Some(Event::Connected { control, .. }) => println!("{} connected, control {control}", at()),
                Some(Event::Control(on)) => println!("{} control {on}", at()),
                Some(Event::Notice(notice)) => println!(
                    "{} NOTICE {notice:?}: {}",
                    at(),
                    notice.text().unwrap_or_else(|| "(input back)".into())
                ),
                Some(Event::Finished(result)) => {
                    println!("{} FINISHED {result:?}", at());
                    break;
                }
                Some(_) => {}
                None => break,
            },
            changed = session.frames.changed(), if first_frame => {
                if changed.is_ok() && let Some(frame) = session.frames.borrow().as_ref() {
                    println!("{} first frame {}x{}", at(), frame.width, frame.height);
                    first_frame = false;
                }
            }
            line = lines.next_line() => {
                let Ok(Some(line)) = line else { break };
                match run(&mut session, line.trim()) {
                    Ok(true) => println!("{} ok: {}", at(), line.trim()),
                    Ok(false) => break,
                    Err(error) => println!("{} FAILED {}: {error:#}", at(), line.trim()),
                }
            }
        }
    }
    session.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}
