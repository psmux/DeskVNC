//! Drive the shared desktop the way a helper would, to check input on a
//! machine without a helper: move the pointer, click, and type.
//!
//! ```sh
//! input_check move 0.25 0.75      # pointer a quarter across, three quarters down
//! input_check click 0.5 0.5       # move there and click
//! input_check type "héllo €"      # type text, Unicode included
//! input_check key enter
//! ```
use boundary_session::{Button, Input, Key};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let id = boundary_platform::displays()?[0].id;
    let mut desktop = boundary_platform::open(id)?;
    let f = |i: usize| {
        args.get(i)
            .and_then(|s| s.parse::<f32>().ok())
            .unwrap_or(0.5)
    };
    match args.first().map(String::as_str) {
        Some("move") => desktop.input(Input::Move { x: f(1), y: f(2) })?,
        Some("click") => {
            desktop.input(Input::Move { x: f(1), y: f(2) })?;
            desktop.input(Input::Button {
                button: Button::Left,
                down: true,
            })?;
            desktop.input(Input::Button {
                button: Button::Left,
                down: false,
            })?;
        }
        Some("type") => desktop.input(Input::Text(args.get(1).cloned().unwrap_or_default()))?,
        Some("key") => {
            let key = match args.get(1).map(String::as_str) {
                Some("enter") => Key::Enter,
                Some("tab") => Key::Tab,
                Some("backspace") => Key::Backspace,
                Some(s) => Key::Letter(s.chars().next().unwrap_or('a')),
                None => Key::Enter,
            };
            desktop.input(Input::Key { key, down: true })?;
            desktop.input(Input::Key { key, down: false })?;
        }
        _ => anyhow::bail!("input_check move|click|type|key ..."),
    }
    // Let the events reach the display before the connection closes.
    std::thread::sleep(std::time::Duration::from_millis(300));
    Ok(())
}
