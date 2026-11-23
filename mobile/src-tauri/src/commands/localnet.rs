//! Android 17's local network permission, for the UI. See `crate::localnet`.

use tauri::AppHandle;

use crate::localnet::{self, LocalNetwork};

/// Whether DeskVNC may use the local network now.
#[tauri::command]
pub async fn local_network_state(app: AppHandle) -> Result<LocalNetwork, String> {
    Ok(localnet::state(&app).await)
}

/// Ask for it with the system prompt, where Android still shows one.
#[tauri::command]
pub async fn local_network_ask(app: AppHandle) -> Result<LocalNetwork, String> {
    Ok(localnet::ask(&app).await)
}

/// Open DeskVNC's page in Android settings, to allow Nearby devices there.
#[tauri::command]
pub async fn app_settings_open(app: AppHandle) -> Result<(), String> {
    localnet::open_settings(&app).await
}
