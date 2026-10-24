//! Measure someone else's client: it runs full screen on a display of its
//! own, and this reads that display and types into it, as a person in front
//! of it would. The bench's pump sees it as one more session.
//!
//! The display is read whole every time with xcap, so each reading costs a
//! capture. The report carries that cost (`grab_ms`)
//! so a reader can take it off the lag.
use boundary_session::Input;
use remote_core::{
    ClientCommand, DecodedRect, ProtocolKind, Rect, RectPayload, SessionEvent, SessionHandle,
    SessionState, SessionStats,
};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn grab(monitor: &xcap::Monitor) -> anyhow::Result<boundary_session::Frame> {
    let image = monitor.capture_image()?;
    Ok(boundary_session::Frame {
        width: image.width(),
        height: image.height(),
        rgba: image.into_raw(),
    })
}

pub fn spawn(events: mpsc::Sender<SessionEvent>) -> SessionHandle {
    let (commands, mut rx) = mpsc::channel::<ClientCommand>(256);
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    std::thread::spawn(move || {
        let fail = |e: anyhow::Error| {
            let _ = events.blocking_send(SessionEvent::Error(format!("{e:#}")));
        };
        // Input goes in the way the Boundary host puts it in; the picture
        // comes out through xcap, a plain whole screen read with no damage
        // tracking, so nothing about how the client draws can hide a change.
        let mut desktop = match boundary_platform::open_primary() {
            Ok(d) => d,
            Err(e) => return fail(e),
        };
        let monitor = match xcap::Monitor::all()
            .map_err(anyhow::Error::from)
            .and_then(|all| {
                all.into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("no display"))
            }) {
            Ok(m) => m,
            Err(e) => return fail(e),
        };
        let _ = events.blocking_send(SessionEvent::StateChanged(SessionState::Connected));
        let mut size = (0u32, 0u32);
        let mut grabs: Vec<f32> = Vec::new();
        let mut last_stats = Instant::now();
        let mut last: Vec<u8> = Vec::new();
        while !token.is_cancelled() {
            while let Ok(command) = rx.try_recv() {
                let input = match command {
                    // The pointer moves with xdotool, as a hand on a mouse
                    // would: FreeRDP's X11 client forwards a motion only when
                    // the next one arrives, and ignored XTest's moves
                    // outright, so the move is followed by a one pixel nudge
                    // that releases it.
                    ClientCommand::Pointer { x, y, .. } => {
                        let (x, y) = (x.to_string(), (y + 1).to_string());
                        let moved = std::process::Command::new("xdotool")
                            .args(["mousemove", &x, &y, "mousemove", "--sync"])
                            .args([&x, &(y.parse::<u32>().unwrap_or(0) - 1).to_string()])
                            .status();
                        if let Err(e) = moved {
                            fail(anyhow::anyhow!("xdotool: {e}"));
                        }
                        None
                    }
                    ClientCommand::Key {
                        keysym, down: true, ..
                    } => char::from_u32(keysym).map(|c| Input::Text(c.to_string())),
                    ClientCommand::Disconnect => return,
                    _ => None,
                };
                if let Some(input) = input
                    && let Err(e) = desktop.input(input)
                {
                    fail(e);
                }
            }
            let started = Instant::now();
            // A whole reading every time, compared here, rather than the
            // host's damage tracking: another client's drawing is what is
            // being measured, and a reading must not depend on how it draws.
            let shot = grab(&monitor).map(|frame| {
                let changed = frame.rgba != last;
                changed.then_some(frame)
            });
            match shot {
                Ok(Some(frame)) => {
                    last.clone_from(&frame.rgba);
                    grabs.push(started.elapsed().as_secs_f32() * 1000.0);
                    if (frame.width, frame.height) != size {
                        size = (frame.width, frame.height);
                        let _ = events.blocking_send(SessionEvent::DesktopResize {
                            width: size.0 as u16,
                            height: size.1 as u16,
                        });
                    }
                    let whole = Rect::new(0, 0, size.0 as u16, size.1 as u16);
                    let update = SessionEvent::FramebufferUpdate {
                        rects: vec![DecodedRect {
                            rect: whole,
                            payload: RectPayload::Rgba(frame.rgba),
                        }],
                        damage: whole,
                    };
                    if events.blocking_send(update).is_err() {
                        return;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    fail(e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            if last_stats.elapsed() >= Duration::from_secs(1) && !grabs.is_empty() {
                // The mean time one capture took, in the field the other
                // drivers use for their decode time.
                let mean = grabs.iter().sum::<f32>() / grabs.len() as f32;
                grabs.clear();
                last_stats = Instant::now();
                let _ = events.blocking_send(SessionEvent::Stats(SessionStats {
                    decode_ms: mean,
                    ..SessionStats::default()
                }));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    SessionHandle {
        id: "local".into(),
        // Not a protocol at all: whatever client owns the display speaks it.
        kind: ProtocolKind::Rdp,
        commands,
        cancel,
    }
}
