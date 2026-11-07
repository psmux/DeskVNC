//! When the window draws.
//!
//! Every frame is drawn in full. On a machine with no graphics driver, such
//! as a virtual machine, that is Mesa's software rasterizer on every core,
//! so a window that redraws ten times a second with nothing on it keeps a
//! quarter of a core busy. The window therefore draws when something happens
//! (input, an event from a session or the listener, a new remote frame), and
//! keeps a timer only while a session or a request is under way, or while a
//! check that has no event behind it is due.

use eframe::egui;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// What the app is doing, for how often it has to look again.
#[derive(Debug, Default, Clone, Copy)]
pub struct Load {
    /// Connected to a helper, or helping, so pictures and timings change.
    pub connected: bool,
    /// Connecting to another computer as its helper.
    pub connecting: bool,
    /// Showing a code and waiting for a helper to use it.
    pub waiting: bool,
    /// A code being registered or looked up.
    pub codes: bool,
    /// Helpers connected through unattended access.
    pub helpers: bool,
    /// A check with nothing to wake the window when its answer changes,
    /// such as a macOS permission or the lock screen handing back the ID.
    pub checks: bool,
}

/// How long the window may wait before drawing again when nothing wakes
/// it, or `None` to wait for the next event however long that is.
pub fn interval(load: Load) -> Option<Duration> {
    if load.connected || load.connecting || load.codes || load.helpers {
        Some(Duration::from_millis(100))
    } else if load.waiting || load.checks {
        Some(Duration::from_secs(1))
    } else {
        None
    }
}

/// Ask for the next frame by what `load` needs. Called once per pass.
pub fn schedule(ctx: &egui::Context, load: Load) {
    if let Some(after) = interval(load) {
        ctx.request_repaint_after(after);
    }
}

/// Pass a channel's items on unchanged, waking the window for each one, so
/// it reads them as they arrive rather than on a timer.
pub fn relay<T: Send + 'static>(
    mut items: mpsc::Receiver<T>,
    ctx: egui::Context,
) -> mpsc::Receiver<T> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        while let Some(item) = items.recv().await {
            if tx.send(item).await.is_err() {
                break;
            }
            ctx.request_repaint();
        }
    });
    rx
}

/// Wake the window whenever `value` changes, until its sender goes away.
pub fn on_change<T: Send + Sync + 'static>(mut value: watch::Receiver<T>, ctx: egui::Context) {
    tokio::spawn(async move {
        while value.changed().await.is_ok() {
            ctx.request_repaint();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The soonest frame `schedule` asks for, or `Duration::MAX` for none.
    fn delay(load: Load) -> Duration {
        let ctx = egui::Context::default();
        let asked = Arc::new(std::sync::Mutex::new(Duration::MAX));
        let seen = asked.clone();
        ctx.set_request_repaint_callback(move |info| {
            let mut soonest = seen.lock().unwrap();
            *soonest = (*soonest).min(info.delay);
        });
        // egui asks for a frame or two of its own after the first ones.
        for _ in 0..3 {
            let _ = ctx.run_logic(&egui::RawInput::default(), |_| {});
        }
        *asked.lock().unwrap() = Duration::MAX;
        let _ = ctx.run_logic(&egui::RawInput::default(), |ctx| schedule(ctx, load));
        *asked.lock().unwrap()
    }

    /// egui takes the expected time to draw a frame off a delay.
    fn near(got: Duration, want: Duration) -> bool {
        got <= want && got + Duration::from_millis(50) >= want
    }

    #[test]
    fn an_idle_window_asks_for_no_frames() {
        assert_eq!(interval(Load::default()), None);
        assert_eq!(delay(Load::default()), Duration::MAX);
    }

    #[test]
    fn sessions_and_requests_keep_the_window_current() {
        for load in [
            Load {
                connected: true,
                ..Load::default()
            },
            Load {
                connecting: true,
                ..Load::default()
            },
            Load {
                codes: true,
                ..Load::default()
            },
            Load {
                helpers: true,
                ..Load::default()
            },
        ] {
            assert!(near(delay(load), Duration::from_millis(100)), "{load:?}");
        }
    }

    #[test]
    fn waiting_and_checks_look_once_a_second() {
        let waiting = Load {
            waiting: true,
            ..Load::default()
        };
        let checks = Load {
            checks: true,
            ..Load::default()
        };
        assert!(near(delay(waiting), Duration::from_secs(1)));
        assert!(near(delay(checks), Duration::from_secs(1)));
    }

    fn counted() -> (egui::Context, Arc<AtomicUsize>) {
        let ctx = egui::Context::default();
        let wakes = Arc::new(AtomicUsize::new(0));
        let counter = wakes.clone();
        ctx.set_request_repaint_callback(move |_| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        (ctx, wakes)
    }

    #[tokio::test]
    async fn an_item_wakes_the_window_and_arrives_unchanged() {
        let (ctx, wakes) = counted();
        let (tx, inner) = mpsc::channel(4);
        let mut rx = relay(inner, ctx);
        tx.send(7u32).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap();
        assert_eq!(got, Some(7));
        drop(tx);
        let end = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap();
        assert_eq!(end, None);
        assert!(wakes.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn a_change_wakes_the_window_and_silence_does_not() {
        let (ctx, wakes) = counted();
        let (tx, rx) = watch::channel(0u32);
        on_change(rx, ctx);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(wakes.load(Ordering::Relaxed), 0);
        tx.send(1).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while wakes.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
