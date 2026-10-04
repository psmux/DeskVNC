//! Boundary invitations stay in the Rust process and never enter window URLs or host storage.
use crate::state::AppState;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};

/// Give Boundary this helper's lasting identity, and save a computer to the
/// Library when the person there lets this helper connect any time.
///
/// The identity is what a paired computer recognises, so it is kept in the
/// app's data folder, readable by this user only, and made once. Without it
/// every session would connect as somebody new and a pairing could never be
/// used.
pub fn install(app: &AppHandle, data_dir: &std::path::Path) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    match boundary_session::unattended::load_or_create_key(&data_dir.join("boundary-helper.key")) {
        Ok(key) => state.protocols.boundary.set_identity(key),
        Err(error) => tracing::warn!("Boundary helper identity unavailable: {error:#}"),
    }
    let app = app.clone();
    state
        .protocols
        .boundary
        .on_paired(Arc::new(move |machine: String, name: String| {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = save_paired(&app, machine, name).await {
                    tracing::warn!("could not save a paired computer: {error}");
                }
            });
        }));
}

/// Put a paired computer in the Library, or rename it if it is there already.
async fn save_paired(app: &AppHandle, machine: String, name: String) -> Result<(), String> {
    let state = app.state::<AppState>();
    let store = state.store.clone();
    let profile = super::blocking(move || {
        let existing = store
            .list_hosts()?
            .into_iter()
            .find(|h| h.protocol == "boundary" && h.address == machine);
        let mut profile = existing.unwrap_or_else(|| vnc_store::HostProfile {
            id: uuid::Uuid::new_v4().to_string(),
            address: machine.clone(),
            port: 0,
            protocol: "boundary".into(),
            ..Default::default()
        });
        profile.friendly_name = name;
        store.save_host(&profile)?;
        Ok::<_, vnc_store::Error>(profile)
    })
    .await?;
    tracing::info!(profile = %profile.id, "saved a computer that paired this helper");
    let _ = app.emit(
        super::session::SESSIONS_EVENT,
        serde_json::json!({
            "type": "host-adopted",
            "profileId": profile.id,
            "address": profile.address,
            "port": profile.port,
            "protocol": profile.protocol,
        }),
    );
    Ok(())
}

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
        None,
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
