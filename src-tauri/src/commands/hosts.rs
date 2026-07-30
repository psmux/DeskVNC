//! Host-library commands: profiles, groups, tags, history, thumbnails.
//!
//! All storage calls are synchronous SQLite (`vnc_store::Store`), so every
//! command hops to `spawn_blocking` via [`super::blocking`].

use tauri::State;
use vnc_store::{Group, HistoryEntry, HostProfile, Tag};

use crate::state::AppState;

#[tauri::command]
pub async fn list_hosts(state: State<'_, AppState>) -> Result<Vec<HostProfile>, String> {
    let store = state.store.clone();
    super::blocking(move || store.list_hosts()).await
}

#[tauri::command]
pub async fn get_host(
    state: State<'_, AppState>,
    host_id: String,
) -> Result<Option<HostProfile>, String> {
    let store = state.store.clone();
    super::blocking(move || store.get_host(&host_id)).await
}

#[tauri::command]
pub async fn save_host(
    state: State<'_, AppState>,
    profile: HostProfile,
) -> Result<HostProfile, String> {
    let store = state.store.clone();
    let returned = profile.clone();
    super::blocking(move || store.save_host(&profile)).await?;
    Ok(returned)
}

#[tauri::command]
pub async fn delete_host(state: State<'_, AppState>, host_id: String) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.delete_host(&host_id)).await
}

/// Bump `last_connected`/`connect_count` after a successful connect.
#[tauri::command]
pub async fn touch_connected(state: State<'_, AppState>, host_id: String) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.touch_connected(&host_id)).await
}

#[tauri::command]
pub async fn list_groups(state: State<'_, AppState>) -> Result<Vec<Group>, String> {
    let store = state.store.clone();
    super::blocking(move || store.list_groups()).await
}

#[tauri::command]
pub async fn save_group(state: State<'_, AppState>, group: Group) -> Result<Group, String> {
    let store = state.store.clone();
    let returned = group.clone();
    super::blocking(move || store.save_group(&group)).await?;
    Ok(returned)
}

#[tauri::command]
pub async fn delete_group(state: State<'_, AppState>, group_id: String) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.delete_group(&group_id)).await
}

#[tauri::command]
pub async fn list_tags(state: State<'_, AppState>) -> Result<Vec<Tag>, String> {
    let store = state.store.clone();
    super::blocking(move || store.list_tags()).await
}

#[tauri::command]
pub async fn save_tag(state: State<'_, AppState>, tag: Tag) -> Result<Tag, String> {
    let store = state.store.clone();
    let returned = tag.clone();
    super::blocking(move || store.save_tag(&tag)).await?;
    Ok(returned)
}

#[tauri::command]
pub async fn delete_tag(state: State<'_, AppState>, tag_id: String) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.delete_tag(&tag_id)).await
}

/// Replace the full tag set of a host.
#[tauri::command]
pub async fn set_host_tags(
    state: State<'_, AppState>,
    host_id: String,
    tag_ids: Vec<String>,
) -> Result<(), String> {
    let store = state.store.clone();
    super::blocking(move || store.set_host_tags(&host_id, &tag_ids)).await
}

/// Connection history, newest first. `host_id = None` means all hosts.
#[tauri::command]
pub async fn list_history(
    state: State<'_, AppState>,
    host_id: Option<String>,
    limit: Option<u32>,
) -> Result<Vec<HistoryEntry>, String> {
    let store = state.store.clone();
    super::blocking(move || store.list_history(host_id.as_deref(), limit.unwrap_or(100))).await
}

/// Thumbnail PNG for a host tile.
///
/// Returns the raw PNG bytes via `tauri::ipc::Response`, the binary
/// fast path, NOT base64 JSON. The webview receives an `ArrayBuffer`:
/// `new Blob([await invoke("get_thumbnail", { hostId })])`. An empty body
/// means "no thumbnail yet".
#[tauri::command]
pub async fn get_thumbnail(
    state: State<'_, AppState>,
    host_id: String,
) -> Result<tauri::ipc::Response, String> {
    let store = state.store.clone();
    let bytes: Option<Vec<u8>> = super::blocking(move || store.load_thumbnail(&host_id)).await?;
    Ok(tauri::ipc::Response::new(bytes.unwrap_or_default()))
}

/// Read a global app setting from the store's KV table.
///
/// Used for preferences the Rust side must consult at connect time (so they
/// cannot live in the webview's localStorage), e.g. `lossless_refresh`.
#[tauri::command]
pub async fn get_app_setting(
    state: State<'_, AppState>,
    key: String,
) -> Result<Option<String>, String> {
    state.store.get_setting(&key).map_err(|e| e.to_string())
}

/// Write a global app setting.
#[tauri::command]
pub async fn set_app_setting(
    state: State<'_, AppState>,
    key: String,
    value: String,
) -> Result<(), String> {
    state
        .store
        .set_setting(&key, &value)
        .map_err(|e| e.to_string())
}
