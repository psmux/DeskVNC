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

use boundary_session::{Approval, Event};
use eframe::egui;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, oneshot};

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
/// goes to `notify` with the helper's name, off the window's thread. What
/// `notify` returns is held until the question is answered or withdrawn, and
/// dropped then, which takes the notification down.
pub fn forward<N: Send + 'static>(
    mut events: mpsc::Receiver<Event>,
    ctx: egui::Context,
    focused: Arc<AtomicBool>,
    notify: impl Fn(&str) -> N + Send + 'static,
) -> mpsc::Receiver<Event> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        while let Some(mut event) = events.recv().await {
            if let Event::Approval { name, answer, .. } = &mut event {
                let shown = (!focused.load(Ordering::Relaxed)).then(|| notify(name));
                // The window answers through a stand in, so this side sees
                // the answer go by and can take the notification down.
                let (stand_in, decision) = oneshot::channel();
                let answer = std::mem::replace(answer, stand_in);
                tokio::spawn(answered(decision, answer, shown));
            }
            if tx.send(event).await.is_err() {
                break;
            }
            ctx.request_repaint();
        }
    });
    rx
}

/// Pass the window's answer on to the session, or let the window see that
/// the session stopped waiting, then drop `shown`.
async fn answered<N>(
    mut decision: oneshot::Receiver<Approval>,
    mut answer: oneshot::Sender<Approval>,
    shown: N,
) {
    tokio::select! {
        result = &mut decision => {
            if let Ok(approval) = result {
                let _ = answer.send(approval);
            }
        }
        // The helper left or the minute ran out: dropping `decision` closes
        // the window's side too, which takes the question off the screen.
        () = answer.closed() => {}
    }
    drop(shown);
}

/// The notification's text. The name comes from the helper, and some
/// notification servers read markup, so it is escaped.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

/// A desktop notification where the window cannot come forward by itself,
/// on screen until the value returned is dropped. On Linux, over D-Bus.
/// Elsewhere the attention request is enough.
#[cfg(target_os = "linux")]
pub fn notify(name: &str) -> Option<boundary_platform::Notification> {
    boundary_platform::notify(
        crate::APP_ID,
        crate::APP_NAME,
        "Approve this helper?",
        &message(name),
    )
}
#[cfg(not(target_os = "linux"))]
pub fn notify(_: &str) {}

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
            clipboard: false,
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
        let (event, decision) = approval("Sam");
        tx.send(event).await.unwrap();
        assert!(matches!(next(&mut rx).await, Event::Status(_)));
        let Event::Approval { name, answer, .. } = next(&mut rx).await else {
            panic!("expected the approval");
        };
        assert_eq!(name, "Sam");
        // The forwarded answer still reaches the session.
        assert!(answer.send(Approval::View).is_ok());
        let reached = tokio::time::timeout(Duration::from_secs(5), decision).await;
        assert!(matches!(reached, Ok(Ok(Approval::View))));
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

    /// Stands in for a notification on screen: counts itself taken down.
    struct Shown(Arc<AtomicUsize>);
    impl Drop for Shown {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn shown_harness() -> (mpsc::Sender<Event>, mpsc::Receiver<Event>, Arc<AtomicUsize>) {
        let taken_down = Arc::new(AtomicUsize::new(0));
        let counter = taken_down.clone();
        let (tx, inner) = mpsc::channel(32);
        let rx = forward(
            inner,
            egui::Context::default(),
            Arc::new(AtomicBool::new(false)),
            move |_| Shown(counter.clone()),
        );
        (tx, rx, taken_down)
    }

    async fn settle(count: &AtomicUsize, want: usize) {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while count.load(Ordering::Relaxed) < want {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }

    #[tokio::test]
    async fn answering_takes_the_notification_down() {
        let (tx, mut rx, taken_down) = shown_harness();
        let (event, mut decision) = approval("Sam");
        tx.send(event).await.unwrap();
        let Event::Approval { answer, .. } = next(&mut rx).await else {
            panic!("expected the approval");
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(taken_down.load(Ordering::Relaxed), 0, "still asking");
        assert!(answer.send(Approval::Control).is_ok());
        settle(&taken_down, 1).await;
        assert_eq!(taken_down.load(Ordering::Relaxed), 1);
        assert!(matches!(decision.try_recv(), Ok(Approval::Control)));
        finish(tx, rx).await;
    }

    #[tokio::test]
    async fn a_question_the_session_withdraws_leaves_the_screen() {
        let (tx, mut rx, taken_down) = shown_harness();
        let (event, decision) = approval("Sam");
        tx.send(event).await.unwrap();
        let Event::Approval { answer, .. } = next(&mut rx).await else {
            panic!("expected the approval");
        };
        // The helper gave up or the minute ran out.
        drop(decision);
        settle(&taken_down, 1).await;
        assert_eq!(taken_down.load(Ordering::Relaxed), 1);
        // The window sees it too, and drops its question.
        assert!(answer.is_closed());
        finish(tx, rx).await;
    }

    #[tokio::test]
    async fn a_window_that_drops_the_question_takes_the_notification_down() {
        let (tx, mut rx, taken_down) = shown_harness();
        let (event, mut decision) = approval("Sam");
        tx.send(event).await.unwrap();
        let Event::Approval { answer, .. } = next(&mut rx).await else {
            panic!("expected the approval");
        };
        // The window went away without answering.
        drop(answer);
        settle(&taken_down, 1).await;
        assert_eq!(taken_down.load(Ordering::Relaxed), 1);
        assert!(decision.try_recv().is_err());
        finish(tx, rx).await;
    }
}
