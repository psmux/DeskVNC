//! Tray icon with recent hosts and Quit.
//!
//! The recent-hosts list is a snapshot taken at startup (rebuilt via
//! [`install`] if we ever want live refresh); clicking one focuses the main
//! window and emits `tray://connect` with the host id so the frontend starts
//! the connection through its normal path.

use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager};

use crate::state::AppState;

const MAX_RECENT: usize = 5;

pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let mut builder = MenuBuilder::new(app)
        .item(&MenuItemBuilder::with_id("tray:open", "Open DeskVNCViewer").build(app)?);

    let recent = recent_hosts(app);
    if !recent.is_empty() {
        builder = builder.separator();
        for (host_id, name) in &recent {
            // Host names are user/server-derived; menu items render plain
            // text natively so no escaping is needed.
            builder = builder
                .item(&MenuItemBuilder::with_id(format!("tray:host:{host_id}"), name).build(app)?);
        }
    }
    let menu = builder
        .separator()
        .item(&MenuItemBuilder::with_id("tray:quit", "Quit DeskVNCViewer").build(app)?)
        .build()?;

    let mut tray = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .tooltip("DeskVNCViewer")
        .on_menu_event(|app, event| handle_tray_event(app, event.id().as_ref()));
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

fn handle_tray_event(app: &AppHandle, id: &str) {
    match id {
        "tray:open" => show_main(app),
        "tray:quit" => app.exit(0),
        host_item if host_item.starts_with("tray:host:") => {
            let host_id = &host_item["tray:host:".len()..];
            show_main(app);
            let _ = app.emit_to(
                "main",
                "tray://connect",
                serde_json::json!({ "hostId": host_id }),
            );
        }
        _ => {}
    }
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Best effort: most recently connected saved hosts, newest first.
fn recent_hosts(app: &AppHandle) -> Vec<(String, String)> {
    let Some(state) = app.try_state::<AppState>() else {
        return Vec::new();
    };
    match state.store.list_hosts() {
        Ok(mut hosts) => {
            hosts.sort_by_key(|h| std::cmp::Reverse(h.last_connected));
            hosts
                .into_iter()
                .filter(|h| h.last_connected.is_some())
                .take(MAX_RECENT)
                .map(|h| (h.id, h.friendly_name))
                .collect()
        }
        Err(e) => {
            tracing::warn!("could not list hosts for tray menu: {e}");
            Vec::new()
        }
    }
}
