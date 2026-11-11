//! Type text and turn the wheel on a computer that asked for help, through
//! DeskVNC's own Boundary driver, the way `dvv type` does it: each key down,
//! 4 ms, then its release, as the plane lowers a type with no `wpm`.
//!
//! ```text
//! # On the computer: a session with its real screen, approving the first helper
//! cargo run -p boundary-platform --example clip_host
//! # On the helper, with the invitation clip_host printed
//! cargo run -p boundary-driver --example type_check -- <invitation> text <file>
//! cargo run -p boundary-driver --example type_check -- <invitation> wheel <clicks>
//! ```
//!
//! What arrived is read on the computer, in the program that had the focus.
use boundary_driver::BoundaryDriver;
use remote_core::{ClientCommand, ConnectOptions, ProtocolDriver, SessionEvent, SessionState};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(invitation), Some(what), Some(value)) = (args.first(), args.get(1), args.get(2))
    else {
        anyhow::bail!("usage: type_check <invitation> text <file> | wheel <clicks>");
    };
    let started = Instant::now();
    let driver = BoundaryDriver::default();
    let id = driver.prepare(invitation.clone(), "Type check".into())?;
    let (tx, mut rx) = mpsc::channel(256);
    let handle = driver
        .spawn(id.clone(), ConnectOptions::boundary(id), tx)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let (size_tx, mut size) = watch::channel(None::<(u16, u16)>);
    let (up_tx, mut up) = watch::channel(false);
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                SessionEvent::StateChanged(state) => {
                    println!("{:>6.2}s {state:?}", started.elapsed().as_secs_f32());
                    let _ = up_tx.send(matches!(state, SessionState::Connected));
                }
                SessionEvent::DesktopResize { width, height } => {
                    let _ = size_tx.send(Some((width, height)));
                }
                _ => {}
            }
        }
    });
    up.wait_for(|up| *up).await?;
    let (width, height) = size.wait_for(Option::is_some).await?.unwrap_or((0, 0));
    // The person's approval reaches the driver with the first screen; give
    // control a moment to arrive as well.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    println!("connected to a {width}x{height} screen");
    let send = |command: ClientCommand| {
        let commands = handle.commands.clone();
        async move { commands.send(command).await.map_err(anyhow::Error::from) }
    };
    match what.as_str() {
        "text" => {
            let text = std::fs::read_to_string(value)?;
            let text = text.trim_end_matches(['\r', '\n']);
            let typing = Instant::now();
            for c in text.chars() {
                let keysym = match c {
                    '\n' => 0xff0d,
                    c if (' '..='~').contains(&c) => c as u32,
                    c => 0x0100_0000 | c as u32,
                };
                send(ClientCommand::Key {
                    keysym,
                    keycode: None,
                    down: true,
                })
                .await?;
                tokio::time::sleep(Duration::from_millis(4)).await;
                send(ClientCommand::Key {
                    keysym,
                    keycode: None,
                    down: false,
                })
                .await?;
            }
            println!(
                "sent {} characters in {} ms",
                text.chars().count(),
                typing.elapsed().as_millis()
            );
        }
        "wheel" => {
            let (x, y) = (width / 2, height / 2);
            send(ClientCommand::Pointer {
                x,
                y,
                button_mask: 0,
            })
            .await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            for _ in 0..value.parse::<u32>()? {
                // One click down: RFB button 5 pressed and let go.
                for button_mask in [16, 0] {
                    send(ClientCommand::Pointer { x, y, button_mask }).await?;
                }
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            println!("sent {value} wheel click(s) down at {x},{y}");
        }
        other => anyhow::bail!("unknown check {other}"),
    }
    // Whatever is still on its way to the computer is let arrive.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let _ = handle.commands.send(ClientCommand::Disconnect).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}
