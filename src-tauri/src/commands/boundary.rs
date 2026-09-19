//! Boundary invitations stay in the Rust process and never enter window URLs or host storage.
use crate::state::AppState;
use tauri::{AppHandle, State};

#[tauri::command]
pub async fn connect_boundary(
    app: AppHandle,
    state: State<'_, AppState>,
    invitation: String,
    helper_name: String,
) -> Result<super::session::SessionWindowOutcome, String> {
    let address = state
        .protocols
        .boundary
        .prepare(invitation, helper_name)
        .map_err(|e| e.to_string())?;
    let result = super::session::open_session_window(
        app,
        state.clone(),
        None,
        None,
        Some(address.clone()),
        Some(0),
        Some("Boundary support".into()),
        Some("boundary".into()),
        Some(true),
        Some(false),
    )
    .await;
    if result.is_err() {
        state.protocols.boundary.forget(&address);
    }
    result
}
