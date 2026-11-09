//! `hosts_*`: the saved computers.

use tauri::State;

use super::blocking;
use crate::secrets::Secret;
use crate::state::AppState;
use crate::store::{validate_id, Host, HostDraft};
use crate::thumbs;

#[tauri::command]
pub async fn hosts_list(state: State<'_, AppState>) -> Result<Vec<Host>, String> {
    Ok(state.hosts.list())
}

#[tauri::command]
pub async fn hosts_save(state: State<'_, AppState>, host: HostDraft) -> Result<Host, String> {
    let hosts = state.hosts.clone();
    blocking(move || hosts.save(host)).await
}

/// Delete a host, its saved password and its thumbnail.
#[tauri::command]
pub async fn hosts_delete(state: State<'_, AppState>, id: String) -> Result<(), String> {
    validate_id(&id).map_err(|e| e.to_string())?;
    let hosts = state.hosts.clone();
    let secrets = state.secrets.clone();
    let thumbs_dir = state.thumbs_dir.clone();
    blocking(move || {
        hosts.delete(&id).map_err(|e| e.to_string())?;
        thumbs::delete(&thumbs_dir, &id);
        secrets.delete(&id)
    })
    .await
}

/// Set the user name and password for a host.
///
/// `username`: a string sets it, `null` leaves it as it is, and an empty
/// string clears it. `password` follows the same rule: a string is stored in
/// the platform vault, `null` keeps whatever is there, and an empty string
/// forgets it. The user name is also kept on the host itself, since it is
/// not a secret and the host card shows it.
#[tauri::command]
pub async fn hosts_set_secret(
    state: State<'_, AppState>,
    id: String,
    username: Option<String>,
    password: Option<String>,
) -> Result<(), String> {
    validate_id(&id).map_err(|e| e.to_string())?;
    let hosts = state.hosts.clone();
    let secrets = state.secrets.clone();
    blocking(move || {
        if hosts.get(&id).is_none() {
            return Err(format!("unknown host: {id}"));
        }
        let mut secret = secrets.load(&id)?.unwrap_or_default();
        if let Some(name) = &username {
            secret.username = (!name.is_empty()).then(|| name.clone());
        }
        if let Some(pw) = &password {
            secret.password = (!pw.is_empty()).then(|| pw.clone());
        }
        if secret == Secret::default() {
            secrets.delete(&id)?;
        } else {
            secrets.save(&id, &secret)?;
        }
        let has_password = secret.password.is_some();
        hosts
            .update(&id, |h| {
                if username.is_some() {
                    h.username = secret.username.clone();
                }
                h.has_password = has_password;
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
}

/// The host's thumbnail as a `data:image/jpeg;base64,` URL, or `null`.
#[tauri::command]
pub async fn hosts_thumbnail(
    state: State<'_, AppState>,
    id: String,
) -> Result<Option<String>, String> {
    validate_id(&id).map_err(|e| e.to_string())?;
    let dir = state.thumbs_dir.clone();
    blocking(move || thumbs::data_url(&dir, &id)).await
}
