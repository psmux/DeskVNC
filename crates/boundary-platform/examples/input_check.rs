//! Drive the shared desktop the way a helper would, to check input on a
//! machine without a helper. Steps run in order on one session:
//!
//! ```sh
//! input_check move 0.25 0.75          # pointer a quarter across, three quarters down
//! input_check click 0.5 0.5           # move there and click
//! input_check wait 500 type "héllo €" key enter
//! ```
use boundary_session::{Button, Input, Key};
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let id = boundary_platform::displays()?[0].id;
    let mut desktop = boundary_platform::open(id)?;
    let mut i = 0;
    let mut next = || {
        i += 1;
        args.get(i - 1).cloned()
    };
    let num = |s: Option<String>| s.and_then(|s| s.parse::<f32>().ok()).unwrap_or(0.5);
    while let Some(step) = next() {
        match step.as_str() {
            "move" => desktop.input(Input::Move {
                x: num(next()),
                y: num(next()),
            })?,
            "click" => {
                desktop.input(Input::Move {
                    x: num(next()),
                    y: num(next()),
                })?;
                for down in [true, false] {
                    desktop.input(Input::Button {
                        button: Button::Left,
                        down,
                    })?;
                }
            }
            "type" => desktop.input(Input::Text(next().unwrap_or_default()))?,
            "key" => {
                let key = match next().as_deref() {
                    Some("enter") => Key::Enter,
                    Some("tab") => Key::Tab,
                    Some("backspace") => Key::Backspace,
                    Some(s) => Key::Letter(s.chars().next().unwrap_or('a')),
                    None => Key::Enter,
                };
                for down in [true, false] {
                    desktop.input(Input::Key { key, down })?;
                }
            }
            "wait" => std::thread::sleep(Duration::from_millis(num(next()) as u64)),
            other => anyhow::bail!("unknown step {other}: move|click|type|key|wait"),
        }
    }
    // Let the events reach the display before the connection closes.
    std::thread::sleep(Duration::from_millis(300));
    Ok(())
}
