//! DeskVNCViewer Tauri shell.
//!
//! Thin adapter over the UI-agnostic crates (PRD/01 §1): `vnc-core` does the
//! protocol work, `vnc-store` persistence/keychain, `vnc-discovery` LAN
//! discovery. This crate wires them to windows, commands, channels, menu,
//! tray, and the capability-scoped IPC surface.

mod commands;
mod framing;
mod menu;
mod state;
mod thumbnail;
mod tray;
mod tunnel;
mod windows;

use std::sync::Arc;

use tauri::{Manager, RunEvent};

use state::AppState;

pub fn run() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,deskvncviewer_lib=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let mut builder = tauri::Builder::default();

    #[cfg(desktop)]
    {
        builder = builder
            // Must be registered first so a second launch is forwarded before
            // any other plugin runs.
            .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }))
            // The ONLY thing the global-shortcut plugin is used for is the
            // capture escape hatch. It is the wrong tool for capture itself
            // (PRD/06 §3: it is `RegisterHotKey`-based and system shortcuts
            // always win) but exactly right for a panic button that must work
            // even while a native hook is swallowing keys.
            .plugin(
                tauri_plugin_global_shortcut::Builder::new()
                    .with_handler(|app, _shortcut, event| {
                        if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                            commands::capture::force_release(app);
                        }
                    })
                    .build(),
            )
            .plugin(tauri_plugin_window_state::Builder::new().build());
    }

    builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .setup(|app| {
            // Storage lives under the per-user Tauri app data dir.
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;

            let store = Arc::new(vnc_store::Store::open(Some(data_dir.clone()))?);
            let credentials = Arc::new(vnc_store::CredentialStore::new(data_dir.clone()));
            app.manage(AppState::new(store, credentials));
            // File-transfer sidecars live in their own managed state so the
            // SFTP registry and the SSH host-key pin store stay independent of
            // the VNC session registry (PRD/08 §2.1).
            app.manage(commands::files::FilesState::new(data_dir));
            // Native shortcut capture (PRD/06 §3 Tier 2). Constructing the
            // backend installs nothing and prompts for nothing, capture is
            // strictly opt-in, per session, from the toolbar toggle.
            app.manage(Arc::new(commands::capture::CaptureState::new(app.handle())));

            menu::install(app.handle())?;
            tray::install(app.handle())?;

            // Escape hatch (PRD/06 §3): force-release capture from anywhere.
            // A stuck grab that swallows the keyboard is unforgivable, so this
            // is registered up front and never unregistered.
            #[cfg(desktop)]
            {
                use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut};
                let release = Shortcut::new(
                    Some(Modifiers::CONTROL | Modifiers::ALT | Modifiers::SHIFT),
                    Code::Escape,
                );
                if let Err(e) = app.global_shortcut().register(release) {
                    // Non-fatal: another app may already own the combo. Capture
                    // still auto-releases on blur/close/exit, and the toolbar
                    // toggle still works.
                    tracing::warn!("could not register the capture release hotkey: {e}");
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            match event {
                // Closing a session window cancels its session(s) so the socket
                // sends a clean RFB close (PRD/01 §6).
                // Every hook here is keyed on what the window actually OWNS,
                // not on its label. A session used to imply a window called
                // `session-<id>`, but in tabbed view sessions live in `main`
                // alongside the library, so `main` closing has to tear its
                // sessions down exactly the way a session window does. Each
                // call is a no-op for a window that owns nothing, which is what
                // `main` is in the one-window-per-session mode.
                tauri::WindowEvent::CloseRequested { .. } => {
                    // Release the keyboard FIRST: whatever else fails, the user
                    // must not be left with a grab held by a window that is
                    // going away.
                    commands::capture::release_for_window(window.app_handle(), window.label());
                    if let Some(state) = window.try_state::<AppState>() {
                        state.shutdown_sessions_for_window(window.label());
                    }
                    // …and cancel any file transfers that window owned.
                    if let Some(files) = window.try_state::<commands::files::FilesState>() {
                        files.shutdown_for_window(window.label());
                    }
                }
                // Capture is only ever held while the window that asked for it
                // is focused (PRD/06 §3). Blur disarms; focus re-arms if the
                // user still has pass-through switched on for that session.
                //
                // There is deliberately no "focus moved elsewhere, force
                // release" branch any more: the owning window's own blur event
                // already disarms, and with tabs the library and the session
                // share one window, so focusing it would have released the grab
                // the user had just asked for.
                tauri::WindowEvent::Focused(focused) => {
                    if *focused {
                        commands::capture::rearm_for_window(window.app_handle(), window.label());
                    } else {
                        commands::capture::disarm_for_window(window.app_handle(), window.label());
                    }
                }
                // A destroyed window can never re-arm, so drop the intent too.
                tauri::WindowEvent::Destroyed => {
                    commands::capture::release_for_window(window.app_handle(), window.label());
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            // hosts / library
            commands::hosts::list_hosts,
            commands::hosts::get_host,
            commands::hosts::save_host,
            commands::hosts::delete_host,
            commands::hosts::touch_connected,
            commands::hosts::list_groups,
            commands::hosts::save_group,
            commands::hosts::delete_group,
            commands::hosts::list_tags,
            commands::hosts::save_tag,
            commands::hosts::delete_tag,
            commands::hosts::set_host_tags,
            commands::hosts::list_history,
            commands::hosts::get_thumbnail,
            commands::about::about_info,
            commands::hosts::get_app_setting,
            commands::hosts::set_app_setting,
            // credentials
            commands::credentials::save_password,
            commands::credentials::has_password,
            commands::credentials::delete_password,
            commands::credentials::credential_backend,
            commands::credentials::unlock_credentials,
            // discovery
            commands::discovery::start_discovery,
            commands::discovery::stop_discovery,
            commands::discovery::scan_network,
            commands::discovery::deep_probe,
            commands::discovery::local_subnets,
            commands::discovery::wake_host,
            // sessions
            commands::session::connect_session,
            commands::session::disconnect_session,
            commands::session::send_input,
            commands::session::set_quality,
            commands::session::request_resize,
            commands::session::refresh_session,
            commands::session::set_view_only,
            commands::session::set_prefer_scancodes,
            commands::session::set_always_refresh,
            commands::session::send_clipboard,
            commands::session::set_local_clipboard,
            commands::session::read_local_clipboard,
            commands::session::reconnect_now,
            commands::session::release_all_keys,
            commands::session::capture_thumbnail,
            commands::session::trust_certificate,
            commands::session::forget_certificate,
            commands::session::provide_credentials,
            commands::session::cancel_credentials,
            commands::session::pending_credential_request,
            commands::session::open_session_window,
            commands::session::release_session_claim,
            commands::session::fullscreen_session,
            commands::session::list_active_sessions,
            // file transfer (SFTP sidecar)
            commands::files::files_probe,
            commands::files::files_connect,
            commands::files::files_disconnect,
            commands::files::files_status,
            commands::files::files_home,
            commands::files::files_list,
            commands::files::files_mkdir,
            commands::files::files_remove,
            commands::files::files_rename,
            commands::files::files_upload,
            commands::files::files_download,
            commands::files::files_cancel,
            commands::files::files_local_home,
            commands::files::files_local_list,
            commands::files::files_local_mkdir,
            commands::files::files_local_rename,
            commands::files::files_local_remove,
            // native keyboard capture (shortcut pass-through)
            commands::capture::capture_start,
            commands::capture::capture_stop,
            commands::capture::capture_status,
            commands::capture::capture_permission_granted,
            commands::capture::capture_request_permission,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build tauri application")
        .run(|app, event| {
            if let RunEvent::ExitRequested { .. } = event {
                // Release the keyboard before anything else can fail: the app
                // must never exit leaving a native hook installed.
                commands::capture::force_release(app);
                // Graceful shutdown: cancel every session, then give the
                // per-session tasks a beat to close their sockets cleanly.
                if let Some(state) = app.try_state::<AppState>() {
                    state.shutdown_all_sessions();
                    state.discovery.cancel_all();
                }
                if let Some(files) = app.try_state::<commands::files::FilesState>() {
                    files.shutdown_all();
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        });
}
