//! Native shortcut pass-through: Tier 2 keyboard capture (PRD/06 §3).
//!
//! `vnc-input-capture` owns the platform hooks; this module owns the *policy*
//! around them, which session holds the grab, when it is armed and released,
//! and how intercepted keys reach the session's RFB stream.
//!
//! # Data path
//!
//! The capture backend pushes [`CapturedKey`]s onto a crossbeam channel. A
//! forwarder thread turns each one into the same `ClientCommand::Key` the
//! webview's `send_input` path produces, so intercepted shortcuts travel the
//! ordinary route, including `vnc-core`'s QEMU extended-key-event encoding and
//! its pressed-key tracking, which is what makes release-all-on-blur cover
//! captured keys too.
//!
//! # Safety
//!
//! A grab that outlives the user's intent is the worst failure this feature
//! has, so capture is released on **every** exit: session-window blur, window
//! close, session disconnect, app exit, a panic in the capture thread (handled
//! inside the crate), and the `Ctrl+Alt+Shift+Esc` global shortcut.
//!
//! Blur only *disarms*, the session that the user turned pass-through on for
//! is remembered in `desired`, so focusing the window again re-arms it without
//! a second permission dance. Anything that clears `desired` is a real "off".

use std::sync::Arc;

use parking_lot::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
use vnc_core::ClientCommand;
use vnc_input_capture::{
    CaptureController, CaptureStatus, CapturedKey, Error as CaptureError, NoopCapture,
};

use crate::state::AppState;
use crate::windows::validate_session_id;

/// Managed capture state. Held as an `Arc` so commands can hand it to a
/// blocking task without borrowing Tauri's `State`.
pub struct CaptureState {
    controller: Mutex<CaptureController>,
    /// The session the user has pass-through switched ON for. Survives blur so
    /// capture can re-arm on focus; cleared by every real "off".
    desired: Mutex<Option<String>>,
}

impl CaptureState {
    /// Build the capture state and start the forwarder thread.
    ///
    /// Never installs a hook: [`vnc_input_capture::create`] only constructs a
    /// backend, and capture is strictly opt-in (PRD/06 §3, no Accessibility
    /// prompt at first launch).
    pub fn new(app: &AppHandle) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded::<CapturedKey>();
        let backend = match vnc_input_capture::create(tx) {
            Ok(backend) => backend,
            Err(e) => {
                // Degrade to a backend that reports Inactive rather than
                // failing app startup over an optional feature.
                tracing::warn!("keyboard capture unavailable: {e}");
                Box::new(NoopCapture::inactive())
            }
        };

        spawn_forwarder(app.clone(), rx);

        Self {
            controller: Mutex::new(CaptureController::new(backend)),
            desired: Mutex::new(None),
        }
    }

    fn status(&self) -> CaptureStatus {
        self.controller.lock().status()
    }

    /// Session id currently holding the grab.
    fn owner(&self) -> Option<String> {
        self.controller.lock().owner().map(str::to_string)
    }

    /// Session the user wants capture for, grabbed or not.
    fn desired(&self) -> Option<String> {
        self.desired.lock().clone()
    }
}

/// Turn intercepted keys into RFB key events for the owning session.
///
/// Runs until the backend's sender is dropped (app shutdown). Every step is
/// best-effort: a key that arrives while no session owns capture, or for a
/// session that just ended, is dropped rather than queued.
fn spawn_forwarder(app: AppHandle, rx: crossbeam_channel::Receiver<CapturedKey>) {
    let spawned = std::thread::Builder::new()
        .name("vnc-capture-forward".into())
        .spawn(move || {
            while let Ok(key) = rx.recv() {
                let Some(capture) = app.try_state::<Arc<CaptureState>>() else {
                    continue;
                };
                let Some(session_id) = capture.owner() else {
                    continue;
                };
                let Some(state) = app.try_state::<AppState>() else {
                    continue;
                };
                let Ok(sender) = state.command_sender(&session_id) else {
                    continue;
                };
                // `try_send`, like `send_input`: input must never queue
                // unboundedly behind a stalled session.
                let _ = sender.try_send(ClientCommand::Key {
                    keysym: key.keysym,
                    // The XT scancode drives the layout-independent QEMU
                    // extended-key-event path (PRD/06 §2.2).
                    keycode: Some(key.scancode),
                    down: key.down,
                });
            }
            tracing::debug!("capture forwarder stopped");
        });
    if let Err(e) = spawned {
        tracing::error!("could not start the capture forwarder thread: {e}");
    }
}

/// Broadcast a status change so every window's capture indicator agrees
/// (PRD/06 §3: the user must always know their keyboard is grabbed).
fn emit_status(app: &AppHandle, status: CaptureStatus, session_id: Option<&str>) {
    let payload = serde_json::json!({
        "status": status,
        "sessionId": session_id,
    });
    let _ = app.emit("capture://event", payload);
}

/// Map a capture error onto a status the UI can render.
///
/// A missing permission or an unsupported platform is a *state*, not a failure:
/// the UI turns them into the onboarding and "why this can't work here" panels.
/// Only genuine backend faults surface as a rejected command.
fn status_or_error(result: Result<CaptureStatus, CaptureError>) -> Result<CaptureStatus, String> {
    match result {
        Ok(status) => Ok(status),
        Err(CaptureError::PermissionRequired) => Ok(CaptureStatus::PermissionRequired),
        Err(CaptureError::Unsupported(reason)) => Ok(CaptureStatus::Unsupported { reason }),
        Err(CaptureError::Backend(message)) => Err(message),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Turn pass-through ON for a session and grab the keyboard.
///
/// Returns the resulting status; `permission-required` and `unsupported` are
/// normal returns, not errors.
#[tauri::command]
pub async fn capture_start(
    app: AppHandle,
    state: State<'_, Arc<CaptureState>>,
    session_id: String,
) -> Result<CaptureStatus, String> {
    validate_session_id(&session_id)?;
    let capture = state.inner().clone();
    let id = session_id.clone();

    // Installing a hook spawns a thread and waits briefly for it to report;
    // that must not happen on the main thread.
    let status = tauri::async_runtime::spawn_blocking(move || {
        let mut controller = capture.controller.lock();
        let result = controller.start(&id);
        if result.is_ok() {
            *capture.desired.lock() = Some(id.clone());
        }
        status_or_error(result)
    })
    .await
    .map_err(|e| e.to_string())??;

    tracing::info!(session = %session_id, ?status, "keyboard capture requested");
    emit_status(&app, status, Some(&session_id));
    Ok(status)
}

/// Turn pass-through OFF for a session. A stop from a session that does not own
/// capture is a no-op, not an error.
#[tauri::command]
pub async fn capture_stop(
    app: AppHandle,
    state: State<'_, Arc<CaptureState>>,
    session_id: String,
) -> Result<CaptureStatus, String> {
    validate_session_id(&session_id)?;
    let capture = state.inner().clone();
    let id = session_id.clone();

    let status = tauri::async_runtime::spawn_blocking(move || {
        let mut desired = capture.desired.lock();
        if desired.as_deref() == Some(id.as_str()) {
            *desired = None;
        }
        drop(desired);
        capture.controller.lock().stop(&id)
    })
    .await
    .map_err(|e| e.to_string())?;

    tracing::info!(session = %session_id, "keyboard capture released");
    emit_status(&app, status, Some(&session_id));
    Ok(status)
}

/// Current capture status (drives the toolbar indicator).
#[tauri::command]
pub fn capture_status(state: State<'_, Arc<CaptureState>>) -> CaptureStatus {
    state.status()
}

/// Is the OS permission capture needs already granted? Never prompts.
#[tauri::command]
pub fn capture_permission_granted() -> bool {
    vnc_input_capture::permission_granted()
}

/// Ask the OS to prompt for the capture permission (macOS Accessibility).
///
/// Only ever called from the UI's explicit "Open permission settings" action,
/// after the explanation, never at launch (PRD/06 §3).
#[tauri::command]
pub fn capture_request_permission() {
    vnc_input_capture::request_permission();
}

// ---------------------------------------------------------------------------
// Auto-release hooks, called from `lib.rs`
// ---------------------------------------------------------------------------

/// Session id embedded in a session window's label, if it is one.
pub fn session_id_from_label(label: &str) -> Option<&str> {
    label.strip_prefix("session-").filter(|id| !id.is_empty())
}

/// Disarm capture because its window lost focus, keeping the user's intent so
/// focusing the window again re-arms it.
pub fn disarm_for_window(app: &AppHandle, window_label: &str) {
    let Some(session_id) = session_id_from_label(window_label) else {
        return;
    };
    let Some(capture) = app.try_state::<Arc<CaptureState>>() else {
        return;
    };
    if capture.owner().as_deref() != Some(session_id) {
        return;
    }
    let status = capture.controller.lock().release();
    tracing::debug!(session = %session_id, "capture disarmed (window blurred)");
    emit_status(app, status, Some(session_id));
}

/// Re-arm capture when the window the user enabled pass-through for regains
/// focus. Silent on failure, a permission revoked in the meantime shows up
/// through the status event, not an error dialog.
pub fn rearm_for_window(app: &AppHandle, window_label: &str) {
    let Some(session_id) = session_id_from_label(window_label) else {
        return;
    };
    let Some(capture) = app.try_state::<Arc<CaptureState>>() else {
        return;
    };
    if capture.desired().as_deref() != Some(session_id) {
        return;
    }
    let status = match capture.controller.lock().start(session_id) {
        Ok(status) => status,
        Err(e) => {
            tracing::warn!(session = %session_id, "could not re-arm capture: {e}");
            CaptureStatus::Inactive
        }
    };
    emit_status(app, status, Some(session_id));
}

/// Fully release capture for a session (disconnect, window close, view-only).
pub fn release_for_session(app: &AppHandle, session_id: &str) {
    let Some(capture) = app.try_state::<Arc<CaptureState>>() else {
        return;
    };
    let mut desired = capture.desired.lock();
    if desired.as_deref() == Some(session_id) {
        *desired = None;
    }
    drop(desired);
    let status = capture.controller.lock().stop(session_id);
    emit_status(app, status, Some(session_id));
}

/// Fully release capture for whichever session owns it, from any window label.
pub fn release_for_window(app: &AppHandle, window_label: &str) {
    if let Some(session_id) = session_id_from_label(window_label) {
        release_for_session(app, session_id);
    }
}

/// The escape hatch: force-release from anywhere, whoever owns it.
///
/// Wired to `Ctrl+Alt+Shift+Esc` and to app exit. Clears the remembered intent
/// too, so a window regaining focus cannot silently re-grab the keyboard the
/// user just fought free of.
pub fn force_release(app: &AppHandle) {
    let Some(capture) = app.try_state::<Arc<CaptureState>>() else {
        return;
    };
    let was_owned = capture.owner();
    *capture.desired.lock() = None;
    let status = capture.controller.lock().release();
    if was_owned.is_some() {
        tracing::warn!(session = ?was_owned, "keyboard capture force-released");
    }
    emit_status(app, status, was_owned.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_recovered_from_window_labels() {
        assert_eq!(session_id_from_label("session-abc123"), Some("abc123"));
        assert_eq!(session_id_from_label("session-"), None);
        assert_eq!(session_id_from_label("main"), None);
        assert_eq!(session_id_from_label(""), None);
    }

    #[test]
    fn permission_and_unsupported_are_states_not_errors() {
        assert_eq!(
            status_or_error(Err(CaptureError::PermissionRequired)),
            Ok(CaptureStatus::PermissionRequired)
        );
        assert_eq!(
            status_or_error(Err(CaptureError::Unsupported("wayland"))),
            Ok(CaptureStatus::Unsupported { reason: "wayland" })
        );
        assert_eq!(
            status_or_error(Err(CaptureError::Backend("boom".into()))),
            Err("boom".to_string())
        );
        assert_eq!(
            status_or_error(Ok(CaptureStatus::Active)),
            Ok(CaptureStatus::Active)
        );
    }
}
