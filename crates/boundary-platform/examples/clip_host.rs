//! Host a Boundary session with this computer's real screen and clipboard,
//! the way Support does, and approve the first helper with control and with
//! leave to see what is copied. For checking clipboard text end to end with
//! the helper in `boundary-session`'s probe example:
//!
//! ```text
//! cargo run -p boundary-platform --example clip_host
//! cargo run -p boundary-session --example probe -- clip-view <invitation> <text> <copies>
//! ```
//!
//! It prints the invitation, each activity line and how the session ended,
//! and gives up if nobody connects within five minutes.
use boundary_session::{Approval, Event, HostOptions};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let started = Instant::now();
    let display = boundary_platform::displays()?
        .first()
        .map(|d| d.id)
        .ok_or_else(|| anyhow::anyhow!("no display to share"))?;
    let mut session = boundary_session::host(HostOptions::default(), move || {
        boundary_platform::open(display)
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
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
                Some(Event::Finished(result)) => {
                    println!("finished: {result:?}");
                    break;
                }
                None => break,
                _ => {}
            },
        }
    }
    Ok(())
}
