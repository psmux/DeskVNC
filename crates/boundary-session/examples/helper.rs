//! A Boundary helper on the command line, for checking unattended access
//! against a real machine over the real network.
//!
//! ```sh
//! # This helper's ID, to pair or trust on the machine
//! cargo run -p boundary-session --example helper -- id helper.key
//! # The ID of a machine from its key file
//! cargo run -p boundary-session --example helper -- id "%LOCALAPPDATA%\Boundary\machine.key"
//! # Connect by machine ID, save the first screen, and leave
//! cargo run -p boundary-session --example helper -- connect helper.key <machine id> screen.png [password]
//! # Join a Get help invitation, save the first screen once the person approves, and leave
//! cargo run -p boundary-session --example helper -- join <invitation> screen.png
//! ```
use boundary_session::{Event, HostOptions, Route, Session, unattended};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("id") => {
            let key = unattended::load_or_create_key(std::path::Path::new(&args[1]))?;
            println!("{}", unattended::machine_id(&key));
        }
        Some("connect") => {
            let key = unattended::load_or_create_key(std::path::Path::new(&args[1]))?;
            let started = Instant::now();
            let mut session = unattended::connect(
                args[2].clone(),
                "Command line helper".into(),
                args.get(4).cloned(),
                key,
                HostOptions::default(),
            );
            first_screen(&mut session, &args[3], started).await?;
            session.stop();
        }
        Some("join") => {
            let started = Instant::now();
            let mut session = boundary_session::viewer(
                args[1].trim().to_string(),
                "Command line helper".into(),
                HostOptions::default(),
            );
            first_screen(&mut session, &args[2], started).await?;
            session.stop();
        }
        _ => eprintln!(
            "usage: helper id <key file> | helper connect <key file> <machine id> <out.png> [password] | helper join <invitation> <out.png>"
        ),
    }
    Ok(())
}

/// Waits for the first screen, saves it to `out`, and reports the route it came over.
async fn first_screen(session: &mut Session, out: &str, started: Instant) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => anyhow::bail!("no screen within 60 s"),
            event = session.events.recv() => match event {
                Some(Event::Status(s)) => println!("status: {s}"),
                Some(Event::Connected { control, .. }) => println!("connected after {:?}, control {control}", started.elapsed()),
                Some(Event::Finished(result)) => { result?; anyhow::bail!("ended before a screen arrived"); }
                _ => {}
            },
            changed = session.frames.changed() => {
                if changed.is_err() {
                    // The session ended; its reason is in the events.
                    while let Some(event) = session.events.recv().await {
                        if let Event::Finished(result) = event { result?; }
                    }
                    anyhow::bail!("ended before a screen arrived");
                }
                let frame = session.frames.borrow_and_update().clone();
                if let Some(frame) = frame {
                    image::save_buffer(out, &frame.rgba, frame.width, frame.height, image::ExtendedColorType::Rgba8)?;
                    let route = session.connectivity.borrow().route;
                    println!("screen {}x{} saved to {} after {:?}, route {}", frame.width, frame.height, out, started.elapsed(),
                        match route { Some(Route::Direct) => "direct", Some(Route::Relay) => "relay", _ => "unknown" });
                    break;
                }
            }
        }
    }
    // HELPER_HOLD=<seconds> stays connected that long after the first screen.
    if let Some(seconds) = std::env::var("HELPER_HOLD")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        tokio::time::sleep(Duration::from_secs(seconds)).await;
    }
    Ok(())
}
