//! Boundary invitations stay in the Rust process and never enter window URLs or host storage.
use crate::state::AppState;
use tauri::{AppHandle, State};

#[tauri::command]
pub async fn connect_boundary(
    app: AppHandle,
    state: State<'_, AppState>,
    invitation: String,
    helper_name: String,
    code_service: Option<String>,
) -> Result<super::session::SessionWindowOutcome, String> {
    let invitation = if invitation.trim().starts_with("boundary1:") {
        invitation
    } else {
        boundary_codes::Client::new(code_service.as_deref().unwrap_or(""))
            .map_err(|error| error.to_string())?
            .resolve(&invitation)
            .await
            .map_err(|error| error.to_string())?
    };
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

// Requests deliberately have no Debug implementation: they contain credentials.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    provider: boundary_provision::Provider,
    auth_key: String,
    account_id: String,
    team: String,
    emails: Vec<String>,
    configure_account: bool,
    #[serde(default)]
    remove_resources: bool,
}
static PROVIDER_SETUP: std::sync::Mutex<Option<boundary_provision::Setup>> =
    std::sync::Mutex::new(None);

#[tauri::command]
pub async fn boundary_provider_start(request: ProviderRequest) -> Result<(), String> {
    let mut job = PROVIDER_SETUP
        .lock()
        .map_err(|_| "Setup state unavailable")?;
    if job
        .as_ref()
        .is_some_and(|job| !job.progress.borrow().finished)
    {
        return Err("Another provider setup is running".into());
    }
    if request.remove_resources {
        if request.provider != boundary_provision::Provider::Cloudflare {
            return Err("Account resource removal is only available for Cloudflare".into());
        }
        *job = Some(boundary_provision::start_cleanup(
            request.account_id,
            request.auth_key.into(),
        ));
        return Ok(());
    }
    *job = Some(boundary_provision::start(
        boundary_provision::SetupRequest {
            provider: request.provider,
            auth_key: request.auth_key.into(),
            account_id: request.account_id,
            team: request.team,
            emails: request.emails,
            configure_account: request.configure_account,
        },
    ));
    Ok(())
}
#[tauri::command]
pub fn boundary_provider_status() -> Result<Option<boundary_provision::Progress>, String> {
    let job = PROVIDER_SETUP
        .lock()
        .map_err(|_| "Setup state unavailable")?;
    Ok(job.as_ref().map(|job| job.progress.borrow().clone()))
}
#[tauri::command]
pub fn boundary_provider_cancel() -> Result<(), String> {
    let job = PROVIDER_SETUP
        .lock()
        .map_err(|_| "Setup state unavailable")?;
    if let Some(job) = job.as_ref() {
        job.cancel();
    }
    Ok(())
}
