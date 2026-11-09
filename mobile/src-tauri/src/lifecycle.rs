//! Background and foreground, the rule in `mobile/CONTRACT.md`.
//!
//! Going to the background pauses frames: the webview is not drawing, and a
//! Tauri channel keeps every message nobody fetched, so frames sent then
//! would only pile up in memory. Sessions stay connected for up to
//! [`GRACE`], about what iOS allows an app before it is suspended. Coming
//! back inside that window resumes and asks every session for a full screen,
//! since the frames that were dropped are gone. Past it, every session is
//! told it was disconnected (with `can_retry`, so the UI offers the one tap
//! reconnect) and ended.
//!
//! The deadline is checked twice. A timer handles the case where the process
//! keeps running in the background (Android, or iOS within its grace), and
//! the foreground handler handles the case where the process was frozen and
//! the timer never got to run.

use std::time::{Duration, Instant};

use remote_core::ClientCommand;
use tauri::{AppHandle, Manager};

use crate::state::AppState;

/// How long a session survives in the background.
pub const GRACE: Duration = Duration::from_secs(30);

/// What a session is told when the background ended it.
pub const REASON: &str = "DeskVNC was in the background for more than 30 seconds";

// Only the phone gets Suspended; a desktop check build never calls this.
#[cfg_attr(not(mobile), allow(dead_code))]
pub fn backgrounded(app: &AppHandle) {
    let state = app.state::<AppState>();
    let generation = {
        let mut life = state.lifecycle.lock();
        if life.backgrounded_at.is_some() {
            return;
        }
        life.backgrounded_at = Some(Instant::now());
        life.generation += 1;
        life.generation
    };
    for session in state.sessions.lock().values() {
        session
            .paused
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Nothing held down while nobody can let go of it.
        let _ = session
            .handle
            .commands
            .try_send(ClientCommand::ReleaseAllKeys);
    }
    tracing::info!("app in the background, frames paused");
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(GRACE).await;
        let state = app.state::<AppState>();
        let expired = {
            let life = state.lifecycle.lock();
            life.generation == generation && life.backgrounded_at.is_some()
        };
        if expired {
            end_all(&app);
        }
    });
}

pub fn foregrounded(app: &AppHandle) {
    let state = app.state::<AppState>();
    let since = {
        let mut life = state.lifecycle.lock();
        life.generation += 1;
        life.backgrounded_at.take()
    };
    let Some(since) = since else { return };
    if since.elapsed() >= GRACE {
        end_all(app);
        return;
    }
    let sessions = state.sessions.lock();
    for session in sessions.values() {
        session
            .paused
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let _ = session.handle.commands.try_send(ClientCommand::Refresh);
    }
    tracing::info!(
        sessions = sessions.len(),
        "app back in the foreground, resumed"
    );
}

/// End every session. Each one's `ended` event follows from its own pump
/// once the driver has unwound.
fn end_all(app: &AppHandle) {
    let state = app.state::<AppState>();
    let handles: Vec<_> = state
        .sessions
        .lock()
        .values()
        .map(|s| {
            s.background_ended
                .store(true, std::sync::atomic::Ordering::Relaxed);
            s.handle.clone()
        })
        .collect();
    tracing::info!(
        sessions = handles.len(),
        "background grace over, ending sessions"
    );
    for handle in handles {
        let _ = handle.commands.try_send(ClientCommand::Disconnect);
        // Also cancelled outright: a socket the OS froze may never let the
        // driver read its command queue again.
        handle.shutdown();
    }
}
