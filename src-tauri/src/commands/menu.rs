//! Keeping the native menu in step with the session in front.
//!
//! The View and Session menus duplicate the whole floating toolbar, because
//! Preferences can switch that toolbar off, so they have to show which
//! options are actually in force. The webview owns all of that state (and
//! most of the monitor list is computed there rather than read off the wire),
//! so it pushes a snapshot through here.

use tauri::AppHandle;

/// Apply a state snapshot to the native menu.
///
/// `async` deliberately, and not only for form: a synchronous tauri command
/// runs on the main thread, while every menu mutation posts a closure to that
/// same thread and blocks waiting for the answer. Called synchronously it
/// would deadlock the app on the first push.
#[tauri::command]
pub async fn sync_session_menu(
    app: AppHandle,
    update: crate::menu::MenuSync,
) -> Result<(), String> {
    crate::menu::sync(&app, update);
    Ok(())
}
