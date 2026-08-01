//! Native application menu bar.
//!
//! Custom items emit a `menu://action` JSON event (`{ id }`) to the focused
//! window, which the frontend routes. The two File items that belong to the
//! library go to the library window instead of the focused one. Window-level
//! actions (fullscreen) are handled natively here.

use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};
use tauri::{AppHandle, Emitter, Manager, WebviewWindow};

#[cfg(target_os = "macos")]
use tauri::menu::AboutMetadata;

/// Kept in step with `ui/src/screens/About.tsx`, which shows the same details
/// in the in-app dialog used on every platform.
const AUTHOR: &str = "Godwin Josh";
const AUTHOR_EMAIL: &str = "godwin@cdtech.in";
const PROJECT_URL: &str = "https://github.com/psmux/DeskVNC";

pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let mut builder = MenuBuilder::new(app);

    #[cfg(target_os = "macos")]
    {
        // The standard macOS About panel. Populated rather than left as
        // AboutMetadata::default(), which shows only the bundle name.
        let about = AboutMetadata {
            name: Some("DeskVNCViewer".into()),
            version: Some(app.package_info().version.to_string()),
            authors: Some(vec![AUTHOR.into()]),
            comments: Some("A fast, native VNC viewer.".into()),
            copyright: Some(format!("© {AUTHOR}")),
            license: Some("MIT OR Apache-2.0".into()),
            website: Some(PROJECT_URL.into()),
            website_label: Some("Project page".into()),
            ..Default::default()
        };
        let app_menu = SubmenuBuilder::new(app, "DeskVNCViewer")
            .about(Some(about))
            .separator()
            .item(
                &MenuItemBuilder::with_id("menu:settings", "Settings…")
                    .accelerator("Cmd+,")
                    .build(app)?,
            )
            .separator()
            .services()
            .separator()
            .hide()
            .hide_others()
            .show_all()
            .separator()
            .quit()
            .build()?;
        builder = builder.item(&app_menu);
    }

    let file = SubmenuBuilder::new(app, "File")
        .item(
            &MenuItemBuilder::with_id("menu:new-host", "New Host…")
                .accelerator("CmdOrCtrl+N")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("menu:quick-connect", "Connect to…")
                .accelerator("CmdOrCtrl+T")
                .build(app)?,
        )
        .separator()
        .close_window()
        .build()?;

    let connection = SubmenuBuilder::new(app, "Connection")
        .item(&MenuItemBuilder::with_id("menu:connect", "Connect").build(app)?)
        .item(
            &MenuItemBuilder::with_id("menu:disconnect", "Disconnect")
                .accelerator("CmdOrCtrl+Shift+D")
                .build(app)?,
        )
        .item(&MenuItemBuilder::with_id("menu:reconnect", "Reconnect Now").build(app)?)
        .separator()
        .item(&MenuItemBuilder::with_id("menu:wake", "Wake with Wake-on-LAN").build(app)?)
        .build()?;

    let view = SubmenuBuilder::new(app, "View")
        .item(
            &MenuItemBuilder::with_id("menu:toggle-fullscreen", "Toggle Fullscreen")
                .accelerator("CmdOrCtrl+Ctrl+F")
                .build(app)?,
        )
        .separator()
        .item(&MenuItemBuilder::with_id("menu:scale-fit", "Fit to Window").build(app)?)
        .item(&MenuItemBuilder::with_id("menu:scale-actual", "Actual Size").build(app)?)
        .separator()
        .item(
            &MenuItemBuilder::with_id("menu:toggle-toolbar", "Show/Hide Toolbar")
                .accelerator("CmdOrCtrl+Shift+M")
                .build(app)?,
        )
        .build()?;

    let session = SubmenuBuilder::new(app, "Session")
        .item(&MenuItemBuilder::with_id("menu:quality:auto", "Quality: Auto").build(app)?)
        .item(&MenuItemBuilder::with_id("menu:quality:high", "Quality: High").build(app)?)
        .item(&MenuItemBuilder::with_id("menu:quality:medium", "Quality: Medium").build(app)?)
        .item(&MenuItemBuilder::with_id("menu:quality:low", "Quality: Low").build(app)?)
        .item(&MenuItemBuilder::with_id("menu:quality:bw", "Quality: Black & White").build(app)?)
        .separator()
        .item(&MenuItemBuilder::with_id("menu:view-only", "View Only").build(app)?)
        .item(&MenuItemBuilder::with_id("menu:refresh", "Refresh Screen").build(app)?)
        .separator()
        .item(&MenuItemBuilder::with_id("menu:send-cad", "Send Ctrl+Alt+Del").build(app)?)
        .item(&MenuItemBuilder::with_id("menu:release-keys", "Release All Keys").build(app)?)
        .build()?;

    // Tab navigation lives on the native menu rather than in the webview
    // because the session's keyboard hook swallows almost everything: a menu
    // accelerator is intercepted by the OS before the page ever sees the key,
    // which is the only way these still work while shortcut pass-through is
    // on. The frontend routes them by `menu://action` id like any other custom
    // item, and ignores them when nothing is open in a tab.
    //
    // `CmdOrCtrl+Shift+W` for Close Tab, not the more usual `CmdOrCtrl+W`:
    // that one belongs to the predefined Close Window item below, and two
    // items cannot share an accelerator.
    let window_menu = SubmenuBuilder::new(app, "Window")
        .item(
            &MenuItemBuilder::with_id("menu:tab:library", "Show Library")
                .accelerator("CmdOrCtrl+Shift+L")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("menu:tab:next", "Next Tab")
                .accelerator("Ctrl+Tab")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("menu:tab:prev", "Previous Tab")
                .accelerator("Ctrl+Shift+Tab")
                .build(app)?,
        )
        .item(
            &MenuItemBuilder::with_id("menu:tab:close", "Close Tab")
                .accelerator("CmdOrCtrl+Shift+W")
                .build(app)?,
        )
        .separator()
        .minimize()
        .maximize()
        .separator()
        .close_window()
        .build()?;

    // "Help" opens the in-app dialog (routed to the frontend) rather than a
    // URL, so it still works with no network. "Project page" is the one that
    // deliberately leaves the app.
    #[allow(unused_mut)] // only reassigned in the non-macOS branch below
    let mut help_builder = SubmenuBuilder::new(app, "Help")
        .item(&MenuItemBuilder::with_id("menu:about", "DeskVNCViewer Help").build(app)?)
        .separator()
        .item(&MenuItemBuilder::with_id("menu:project", "Project Page").build(app)?)
        .item(&MenuItemBuilder::with_id("menu:contact", "Contact Developer…").build(app)?);
    // macOS already carries About in the application menu; everywhere else it
    // belongs under Help.
    #[cfg(not(target_os = "macos"))]
    {
        help_builder = help_builder
            .separator()
            .item(&MenuItemBuilder::with_id("menu:about", "About DeskVNCViewer").build(app)?);
    }
    let help = help_builder.build()?;

    let menu = builder
        .items(&[&file, &connection, &view, &session, &window_menu, &help])
        .build()?;
    app.set_menu(menu)?;

    app.on_menu_event(|app, event| {
        handle_menu_event(app, event.id().as_ref());
    });
    Ok(())
}

fn focused_window(app: &AppHandle) -> Option<WebviewWindow> {
    app.webview_windows()
        .into_values()
        .find(|w| w.is_focused().unwrap_or(false))
}

fn handle_menu_event(app: &AppHandle, id: &str) {
    match id {
        "menu:toggle-fullscreen" => {
            if let Some(window) = focused_window(app) {
                let is_fs = window.is_fullscreen().unwrap_or(false);
                if let Err(e) = crate::windows::set_fullscreen_on_monitor(&window, None, !is_fs) {
                    tracing::warn!("toggle fullscreen failed: {e}");
                }
            }
        }
        "menu:project" | "menu:contact" => {
            use tauri_plugin_opener::OpenerExt;
            let url = if id == "menu:contact" {
                format!("mailto:{AUTHOR_EMAIL}?subject=DeskVNCViewer")
            } else {
                PROJECT_URL.to_string()
            };
            // Opened from Rust rather than the webview: the window capability
            // scopes the opener plugin, and this keeps that scope narrow.
            if let Err(e) = app.opener().open_url(&url, None::<&str>) {
                tracing::warn!("failed to open {url}: {e}");
            }
        }
        "menu:tab:library" | "menu:tab:next" | "menu:tab:prev" | "menu:tab:close" => {
            // The tab strip lives in the library window, so these always go
            // there rather than to whatever is focused: a session window in
            // front must not swallow "next tab" into a webview that has no
            // tabs. Deliberately WITHOUT the show/focus dance below, in the
            // tabbed view the library window is already the focused one, and
            // in the separate-windows view there are no tabs to switch, so
            // raising the library over the session the user is working in
            // would be a jump scare rather than a feature.
            let payload = serde_json::json!({ "id": id });
            let _ = app.emit_to("main", "menu://action", payload);
        }
        "menu:new-host" | "menu:quick-connect" => {
            // Library concerns, not session ones. Sent to the library window
            // wherever the focus happens to be, because the alternative is
            // that Cmd+T does nothing at all whenever a session is in front,
            // which is exactly when reaching for another machine is likeliest.
            let payload = serde_json::json!({ "id": id });
            match app.get_webview_window("main") {
                Some(main) => {
                    // Same three calls the tray and the single-instance hook
                    // use: focusing alone leaves a minimized library in the
                    // Dock, so the address bar would take the keystroke with
                    // nothing on screen to show for it.
                    let _ = main.show();
                    let _ = main.unminimize();
                    let _ = main.set_focus();
                    let _ = app.emit_to("main", "menu://action", payload);
                }
                None => {
                    let _ = app.emit("menu://action", payload);
                }
            }
        }
        custom if custom.starts_with("menu:") => {
            // Route everything else to the frontend of the focused window
            // (falls back to an app-wide emit when nothing is focused).
            let payload = serde_json::json!({ "id": custom });
            match focused_window(app) {
                Some(window) => {
                    let _ = app.emit_to(window.label(), "menu://action", payload);
                }
                None => {
                    let _ = app.emit("menu://action", payload);
                }
            }
        }
        _ => {} // predefined items handle themselves
    }
}
