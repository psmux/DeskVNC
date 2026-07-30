//! Credential commands.
//!
//! SECURITY INVARIANT (PRD/01 §5, PRD/10): **the webview must never receive a
//! password back.** Passwords flow JS → Rust exactly once, at save time, and
//! are loaded internally (in `session::connect_session`, on a blocking
//! thread) when building `ConnectOptions`. There is deliberately no
//! `get_password` command, and `CredentialStore::load` is never exposed here.
//!
//! Keychain / Secret-Service calls are synchronous, so everything hops to a
//! blocking thread via [`super::blocking`].

use tauri::State;
use vnc_store::StoredCredentials;

use crate::state::AppState;

/// Store (or replace) the credentials for a host, keyed by host id, renaming
/// a host never orphans its credential (PRD/03 §5).
#[tauri::command]
pub async fn save_password(
    state: State<'_, AppState>,
    host_id: String,
    creds: StoredCredentials,
) -> Result<(), String> {
    let credentials = state.credentials.clone();
    super::blocking(move || credentials.save(&host_id, &creds)).await
}

/// Whether a credential exists for this host (drives the key icon in the
/// library). The blob is loaded on the Rust side purely for the existence
/// check, only the boolean crosses the IPC boundary.
#[tauri::command]
pub async fn has_password(state: State<'_, AppState>, host_id: String) -> Result<bool, String> {
    let credentials = state.credentials.clone();
    super::blocking(move || credentials.load(&host_id).map(|c| c.is_some())).await
}

#[tauri::command]
pub async fn delete_password(state: State<'_, AppState>, host_id: String) -> Result<(), String> {
    let credentials = state.credentials.clone();
    super::blocking(move || credentials.delete(&host_id)).await
}

/// Which backend is in use (`"OsKeychain"`, `"EncryptedFile"`, or
/// `"Locked"`), so the UI can explain where secrets live and whether an
/// unlock is needed.
#[tauri::command]
pub async fn credential_backend(
    state: State<'_, AppState>,
) -> Result<vnc_store::CredentialBackend, String> {
    let credentials = state.credentials.clone();
    tokio::task::spawn_blocking(move || credentials.backend())
        .await
        .map_err(|e| e.to_string())
}

/// Unlock the encrypted-file fallback store with the master password.
/// The master password flows JS → Rust only; nothing is returned.
#[tauri::command]
pub async fn unlock_credentials(
    state: State<'_, AppState>,
    master_password: String,
) -> Result<(), String> {
    let credentials = state.credentials.clone();
    super::blocking(move || credentials.unlock(&master_password)).await
}
