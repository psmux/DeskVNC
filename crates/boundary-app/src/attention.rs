//! Getting a person to the question a helper is waiting on.
//!
//! An approval waits 60 seconds. When it arrives the window may be hidden in
//! the tray, minimized, or behind something else, and bringing it forward is
//! not always possible. On Wayland a client cannot show, unminimize or focus
//! its own window at all (winit ignores all three), so the only things that
//! reach the person there are an attention request and a notification. On
//! Windows the focus change can be refused, and then the taskbar button has
//! to flash until they look.
//!
//! The session's events are taken off the window's thread as they arrive, so
//! a notification goes out even when the window draws nothing, which is the
//! case on Wayland while it is minimized.

use boundary_session::Event;
use eframe::egui;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

/// Bring the window back from the tray, the Dock or the taskbar, and ask for
/// attention in case that was refused or is not possible here.
pub fn raise(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    // Windows flashes the taskbar button until the window is in front, macOS
    // bounces the Dock icon, Wayland marks the window urgent.
    ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
        egui::UserAttentionType::Critical,
    ));
}

/// Whether a background start may hide the window this frame. Never while a
/// question is waiting: the window was just raised for it.
pub fn may_hide(asking: bool) -> bool {
    !asking
}

/// Pass the session's events on as they arrive. A request to connect wakes
/// the window at once and, if the window was last seen without focus, also
/// goes to `notify` with the helper's name, off the window's thread.
pub fn forward(
    mut events: mpsc::Receiver<Event>,
    ctx: egui::Context,
    focused: Arc<AtomicBool>,
    notify: impl Fn(&str) + Send + 'static,
) -> mpsc::Receiver<Event> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            let asking = match &event {
                Event::Approval { name, .. } => Some(name.clone()),
                _ => None,
            };
            if tx.send(event).await.is_err() {
                break;
            }
            ctx.request_repaint();
            if let Some(name) = asking
                && !focused.load(Ordering::Relaxed)
            {
                notify(&name);
            }
        }
    });
    rx
}

/// The notification's text. The name comes from the helper, and some
/// notification servers read markup, so it is escaped.
#[cfg_attr(not(all(unix, not(target_os = "macos"))), allow(dead_code))]
pub fn message(name: &str) -> String {
    let mut safe = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '&' => safe.push_str("&amp;"),
            '<' => safe.push_str("&lt;"),
            '>' => safe.push_str("&gt;"),
            c if c.is_control() => safe.push(' '),
            c => safe.push(c),
        }
    }
    format!("{safe} wants to see your screen. Open DeskVNC Support to answer within a minute.")
}

/// A desktop notification where the window cannot come forward by itself.
/// Linux and the BSDs, through notify-send when it is installed. Elsewhere
/// the attention request is enough.
pub fn notify(name: &str) {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let child = tokio::process::Command::new("notify-send")
            .args([
                "--app-name=DeskVNC Support",
                "--urgency=critical",
                "Approve this helper?",
            ])
            .arg(message(name))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    let _ = name;
}

#[cfg(test)]
mod tests {
    use super::*;
    use boundary_session::Approval;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio::sync::oneshot;

    fn commands(ctx: &egui::Context, f: impl FnOnce(&egui::Context)) -> Vec<egui::ViewportCommand> {
        let output = ctx.run_logic(&egui::RawInput::default(), f);
        output
            .viewport_commands
            .get(&egui::ViewportId::ROOT)
            .cloned()
            .unwrap_or_default()
    }

    #[test]
    fn raising_asks_for_attention_as_well_as_focus() {
        let ctx = egui::Context::default();
        let sent = commands(&ctx, raise);
        assert_eq!(
            sent,
            vec![
                egui::ViewportCommand::Visible(true),
                egui::ViewportCommand::Minimized(false),
                egui::ViewportCommand::Focus,
                egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Critical),
            ]
        );
    }

    #[test]
    fn a_background_start_does_not_hide_a_question() {
        assert!(may_hide(false));
        assert!(!may_hide(true));
    }

    #[test]
    fn helper_names_cannot_carry_markup_into_the_notification() {
        let text = message("<b>Bank</b> & co\nline");
        assert!(text.starts_with("&lt;b&gt;Bank&lt;/b&gt; &amp; co line wants"));
        assert!(!text.contains('<') && !text.contains('\n'));
    }

    struct Seen {
        names: Arc<Mutex<Vec<String>>>,
        repaints: Arc<AtomicUsize>,
    }

    fn harness(focused: bool) -> (mpsc::Sender<Event>, mpsc::Receiver<Event>, Seen) {
        let ctx = egui::Context::default();
        let repaints = Arc::new(AtomicUsize::new(0));
        let counter = repaints.clone();
        ctx.set_request_repaint_callback(move |_| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        let names = Arc::new(Mutex::new(Vec::new()));
        let record = names.clone();
        let (tx, inner) = mpsc::channel(32);
        let rx = forward(inner, ctx, Arc::new(AtomicBool::new(focused)), move |n| {
            record.lock().unwrap().push(n.to_owned())
        });
        (tx, rx, Seen { names, repaints })
    }

    fn approval(name: &str) -> (Event, oneshot::Receiver<Approval>) {
        let (answer, decision) = oneshot::channel();
        let event = Event::Approval {
            name: name.into(),
            peer: "peer".into(),
            tools: false,
            answer,
        };
        (event, decision)
    }

    async fn next(rx: &mut mpsc::Receiver<Event>) -> Event {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("forwarded in time")
            .expect("channel open")
    }

    /// Close the session's side and wait for the forwarder to stop, so all
    /// it did is done.
    async fn finish(tx: mpsc::Sender<Event>, mut rx: mpsc::Receiver<Event>) {
        drop(tx);
        let end = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        assert!(matches!(end, Ok(None)));
    }

    #[tokio::test]
    async fn a_question_reaches_an_unfocused_person_without_the_window_drawing() {
        let (tx, mut rx, seen) = harness(false);
        tx.send(Event::Status("waiting".into())).await.unwrap();
        let (event, mut decision) = approval("Sam");
        tx.send(event).await.unwrap();
        assert!(matches!(next(&mut rx).await, Event::Status(_)));
        let Event::Approval { name, answer, .. } = next(&mut rx).await else {
            panic!("expected the approval");
        };
        assert_eq!(name, "Sam");
        // The forwarded answer still reaches the session.
        assert!(answer.send(Approval::View).is_ok());
        assert!(matches!(decision.try_recv(), Ok(Approval::View)));
        finish(tx, rx).await;
        assert_eq!(*seen.names.lock().unwrap(), vec!["Sam".to_owned()]);
        // egui passes on one request until a pass consumes it, and no pass runs here.
        assert!(seen.repaints.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn a_person_already_at_the_window_gets_no_notification() {
        let (tx, mut rx, seen) = harness(true);
        let (event, _decision) = approval("Sam");
        tx.send(event).await.unwrap();
        assert!(matches!(next(&mut rx).await, Event::Approval { .. }));
        finish(tx, rx).await;
        assert!(seen.names.lock().unwrap().is_empty());
        assert!(seen.repaints.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn the_forwarder_ends_with_the_session() {
        let (tx, rx, _seen) = harness(false);
        finish(tx, rx).await;
    }
}
