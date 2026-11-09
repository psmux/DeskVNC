//! DeskVNC for iPhone, iPad and Android: the Rust side.
//!
//! A thin shell over the same protocol crates the desktop app drives. The
//! command surface is `mobile/CONTRACT.md`, the field names are
//! `mobile/ui/src/api/contract.ts`, and the frame and input bytes are the
//! desktop's (`src-tauri/FRAME_FORMAT.md`).

#[cfg(target_os = "android")]
mod android;
mod codes;
mod commands;
mod events;
mod keys;
mod lifecycle;
mod pins;
mod vault;
mod state;
mod store;
mod thumbs;

/// The desktop shell's frame and input codec, compiled into this crate from
/// the desktop's own file. It is pure code over `vnc-core` and `bytes`, so
/// both shells encode frames and decode input with one implementation and
/// cannot drift, and the desktop file is not touched. The phone does not use
/// the terminal half (`msg_type` 3), hence the allow.
#[path = "../../../src-tauri/src/framing.rs"]
#[allow(dead_code)]
mod framing;

use std::sync::Arc;

use tauri::{Manager, RunEvent};

use state::{AppState, Drivers, Lifecycle};

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .try_init();
}

/// Give Boundary this phone's lasting identity, and save a computer to the
/// list when the person there lets this phone connect any time. The same
/// steps as the desktop's `commands::boundary::install`.
fn install_boundary(state: &AppState) {
    let key_path = state.data_dir.join("boundary-helper.key");
    match boundary_session::unattended::load_or_create_key(&key_path) {
        Ok(key) => state.drivers.boundary.set_identity(key),
        Err(error) => tracing::warn!("Boundary helper identity unavailable: {error:#}"),
    }
    let hosts = state.hosts.clone();
    state
        .drivers
        .boundary
        .on_paired(Arc::new(move |machine: String, name: String| {
            let existing = hosts
                .list()
                .into_iter()
                .find(|h| h.protocol == store::Protocol::Boundary && h.address == machine);
            let draft = store::HostDraft {
                id: existing.as_ref().map(|h| h.id.clone()),
                name: if name.trim().is_empty() {
                    "Boundary computer".into()
                } else {
                    name
                },
                protocol: store::Protocol::Boundary,
                address: machine,
                port: 0,
                username: None,
                os: existing.as_ref().map(|h| h.os).unwrap_or_default(),
                color: existing
                    .as_ref()
                    .map(|h| h.color.clone())
                    .unwrap_or_default(),
                favorite: existing.as_ref().is_some_and(|h| h.favorite),
                domain: None,
                boundary_invitation: None,
            };
            if let Err(error) = hosts.save(draft) {
                tracing::warn!(%error, "could not save a paired computer");
            }
        }));
}

fn build_state(app: &tauri::App) -> Result<AppState, Box<dyn std::error::Error>> {
    let data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    let thumbs_dir = data_dir.join("thumbnails");
    Ok(AppState {
        hosts: Arc::new(store::HostStore::open(&data_dir)?),
        secrets: vault::platform_store(),
        pins: pins::PinStore::open(&data_dir),
        drivers: Drivers {
            vnc: Arc::new(vnc_core::VncDriver::new()),
            rdp: Arc::new(rdp_core::RdpDriver::new()),
            boundary: Arc::new(boundary_driver::BoundaryDriver::default()),
        },
        sessions: Default::default(),
        scan: Default::default(),
        lifecycle: parking_lot::Mutex::new(Lifecycle::default()),
        thumbs_dir,
        data_dir,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    init_logging();
    let app = tauri::Builder::default()
        .setup(|app| {
            let state = build_state(app)?;
            install_boundary(&state);
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::hosts::hosts_list,
            commands::hosts::hosts_save,
            commands::hosts::hosts_delete,
            commands::hosts::hosts_set_secret,
            commands::hosts::hosts_thumbnail,
            commands::scan::scan_start,
            commands::scan::scan_stop,
            commands::session::session_connect,
            commands::session::boundary_resolve,
            commands::session::session_input,
            commands::session::session_text,
            commands::session::session_key_combo,
            commands::session::session_credentials,
            commands::session::session_trust,
            commands::session::session_quality,
            commands::session::session_clipboard,
            commands::session::session_snapshot,
            commands::session::session_disconnect,
        ])
        .build(tauri::generate_context!())
        .expect("error while building DeskVNC");

    app.run(|handle, event| match event {
        // The window events a phone gets when the app leaves and returns.
        // On a desktop check build they never fire.
        #[cfg(mobile)]
        RunEvent::WindowEvent {
            event: tauri::WindowEvent::Suspended,
            ..
        } => lifecycle::backgrounded(handle),
        #[cfg(mobile)]
        RunEvent::WindowEvent {
            event: tauri::WindowEvent::Resumed,
            ..
        } => lifecycle::foregrounded(handle),
        RunEvent::Resumed => lifecycle::foregrounded(handle),
        _ => {}
    });
}
