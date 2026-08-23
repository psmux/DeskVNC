//! Native application menu bar.
//!
//! Custom items emit a `menu://action` JSON event (`{ id }`) to the focused
//! window, which the frontend routes. The two File items that belong to the
//! library go to the library window instead of the focused one. Window-level
//! actions (fullscreen) are handled natively here.
//!
//! The View and Session menus carry everything the floating session toolbar
//! offers, because Preferences can hide that toolbar outright and the menu is
//! then the only way to reach any of it. That makes the menu stateful: it has
//! to show which scaling mode, quality preset and monitor are actually in use,
//! so the session view pushes its state through `sync_session_menu` whenever
//! it changes and whenever its window takes the focus. The handles needed to
//! apply that state are kept in [`SessionMenu`], managed alongside `AppState`.

use std::collections::HashMap;

use parking_lot::Mutex;
use serde::Deserialize;
use tauri::menu::{
    CheckMenuItem, MenuBuilder, MenuItem, MenuItemBuilder, PredefinedMenuItem, Submenu,
    SubmenuBuilder,
};
use tauri::{AppHandle, Emitter, Manager, WebviewWindow, Wry};

/// Kept in step with `ui/src/screens/About.tsx`, which shows the same details
/// in the in-app dialog used on every platform.
const AUTHOR_EMAIL: &str = "godwin@cdtech.in";
const PROJECT_URL: &str = "https://github.com/psmux/DeskVNC";

/// The one check item that means something with no session in front: it is a
/// preference, not a property of a connection, and Preferences is reachable
/// from the library window where nothing is connected at all.
const HIDE_TOOLBAR: &str = "menu:hide-toolbar";

/// Live handles into the parts of the menu that mirror a session.
///
/// Everything here is `Send + Sync` (tauri's menu wrappers hop to the main
/// thread internally), so it can sit behind a plain mutex in managed state.
pub struct SessionMenu {
    /// Rebuilt from the webview's monitor list; see [`rebuild_displays`].
    displays: Submenu<Wry>,
    /// Every check item in the menu, by id.
    checks: HashMap<&'static str, CheckMenuItem<Wry>>,
    /// Plain items that do nothing without a session in front.
    gated_items: Vec<MenuItem<Wry>>,
    /// Submenus in the same position.
    gated_menus: Vec<Submenu<Wry>>,
    /// The File Transfer item, gated on the SSH probe as well as on a session.
    files: MenuItem<Wry>,
    /// The toolbar recall item, disabled while the toolbar is switched off.
    toggle_toolbar: MenuItem<Wry>,
    /// What the Displays submenu was last built from. Tearing the submenu down
    /// and refilling it on every state push would rebuild native menu items
    /// several times a second; the list only actually changes on connect, on a
    /// desktop resize, and when the seam detector finishes.
    displays_sig: String,
}

impl SessionMenu {
    /// Grey out (or restore) everything that needs a session behind it.
    fn set_live(&self, live: bool, files_available: bool) {
        for item in &self.gated_items {
            let _ = item.set_enabled(live);
        }
        for menu in &self.gated_menus {
            let _ = menu.set_enabled(live);
        }
        for (id, check) in &self.checks {
            if *id != HIDE_TOOLBAR {
                let _ = check.set_enabled(live);
            }
        }
        let _ = self.files.set_enabled(live && files_available);
    }

    fn check(&self, id: &str, checked: bool) {
        if let Some(item) = self.checks.get(id) {
            let _ = item.set_checked(checked);
        }
    }

    /// Tick exactly one item of a radio-style group.
    fn radio(&self, prefix: &str, options: &[&str], selected: &str) {
        for option in options {
            self.check(&format!("{prefix}{option}"), *option == selected);
        }
    }
}

/// One row of the Displays submenu, as the webview computed it.
///
/// The list is built in the webview rather than here because most of it does
/// not come off the wire: a server that never describes its monitors gets
/// synthetic cuts and a seam detected from the pixels, neither of which the
/// shell knows anything about.
#[derive(Debug, Deserialize)]
pub struct DisplayEntry {
    id: i64,
    label: String,
}

/// Everything the menu needs to know about the session in front.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMenuState {
    /// `fit`, `aspect-fit`, `actual`, `remote-resize` or `custom`.
    scaling_mode: String,
    /// `auto`, `high`, `medium`, `low` or `bw`.
    quality: String,
    gray_levels: u32,
    /// `standard`, `dot` or `off`.
    local_cursor: String,
    show_remote_cursor: bool,
    view_only: bool,
    passthrough: bool,
    always_refresh: bool,
    zoom_locked: bool,
    edge_pan: bool,
    /// False while the SSH probe is running or when it came back negative.
    files_available: bool,
    /// True when `displays` is the server's own layout rather than guesses,
    /// which is also when re-running the seam detector makes no sense.
    layout_known: bool,
    displays: Vec<DisplayEntry>,
    /// The selected monitor, or `None` for the whole desktop.
    display_id: Option<i64>,
}

/// The payload of `sync_session_menu`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MenuSync {
    /// Preferences ▸ Session, global rather than per session.
    hide_toolbar: bool,
    /// `None` when the window in front has no session in it.
    session: Option<SessionMenuState>,
}

pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let mut builder = MenuBuilder::new(app);
    let mut checks: HashMap<&'static str, CheckMenuItem<Wry>> = HashMap::new();
    let mut gated_items: Vec<MenuItem<Wry>> = Vec::new();
    let mut gated_menus: Vec<Submenu<Wry>> = Vec::new();

    // Build a check item, remember it, and hand it back for the builder.
    // Unchecked and disabled to begin with: nothing is connected when the menu
    // is installed. `HIDE_TOOLBAR` is the exception, being a preference rather
    // than a property of a connection, so it is built enabled and `set_live`
    // leaves it that way.
    macro_rules! check {
        ($id:expr, $label:expr) => {{
            let enabled = $id == HIDE_TOOLBAR;
            let item = CheckMenuItem::with_id(app, $id, $label, enabled, false, None::<&str>)?;
            checks.insert($id, item.clone());
            item
        }};
    }
    macro_rules! action {
        ($id:expr, $label:expr) => {{
            let item = MenuItemBuilder::with_id($id, $label)
                .enabled(false)
                .build(app)?;
            gated_items.push(item.clone());
            item
        }};
    }

    #[cfg(target_os = "macos")]
    {
        // A custom About item routed to the in-app dialog, NOT the native
        // AboutMetadata panel: two About surfaces drift (the native one was
        // showing the version three different ways), and only the in-app
        // dialog carries the build fingerprint and the copy-a-report button
        // that bug reports need.
        let app_menu = SubmenuBuilder::new(app, "DeskVNCViewer")
            .item(&MenuItemBuilder::with_id("menu:about", "About DeskVNCViewer").build(app)?)
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

    // The monitor list is filled in by the first `sync_session_menu`; until
    // then the submenu says what an empty one means rather than sitting there
    // blank.
    let displays = SubmenuBuilder::new(app, "Displays")
        .item(
            &MenuItemBuilder::with_id("menu:displays-none", "No session")
                .enabled(false)
                .build(app)?,
        )
        .build()?;
    gated_menus.push(displays.clone());

    let pointers = SubmenuBuilder::new(app, "Pointers")
        .item(&check!("menu:remote-cursor", "Show the Remote Pointer"))
        .separator()
        .item(&check!(
            "menu:cursor:standard",
            "My Pointer: Standard Arrow"
        ))
        .item(&check!("menu:cursor:dot", "My Pointer: Dot"))
        .item(&check!("menu:cursor:off", "My Pointer: Hidden"))
        .build()?;
    gated_menus.push(pointers.clone());

    let toggle_toolbar = MenuItemBuilder::with_id("menu:toggle-toolbar", "Show/Hide Toolbar")
        .accelerator("CmdOrCtrl+Shift+M")
        .enabled(false)
        .build(app)?;

    // The zoom items deliberately carry no accelerators. A menu accelerator is
    // claimed by the OS before the webview sees the key, so Cmd/Ctrl+= and
    // Cmd/Ctrl+- here would be stolen from every remote application for the
    // life of the app, which is the mistake the fullscreen chord below was
    // already fixed for once.
    let view = SubmenuBuilder::new(app, "View")
        .item(
            // F11 on Windows/Linux, the convention there, and the chord this
            // used to carry ("CmdOrCtrl+Ctrl+F") collapsed to a plain Ctrl+F
            // on those platforms: a shortcut remote applications use for
            // Find, quietly stolen from the desktop being viewed. macOS keeps
            // Cmd+Ctrl+F, which is its own fullscreen convention and is not
            // in the way of anything.
            &MenuItemBuilder::with_id("menu:toggle-fullscreen", "Toggle Fullscreen")
                .accelerator(if cfg!(target_os = "macos") {
                    "CmdOrCtrl+Ctrl+F"
                } else {
                    "F11"
                })
                .build(app)?,
        )
        .separator()
        .item(&check!("menu:scale-fit", "Fit to Window"))
        .item(&check!("menu:scale-aspect", "Aspect Fit"))
        .item(&check!("menu:scale-actual", "Actual Size"))
        .item(&check!("menu:scale-remote", "Remote Resize (Match Window)"))
        .separator()
        .item(&action!("menu:zoom-in", "Zoom In"))
        .item(&action!("menu:zoom-out", "Zoom Out"))
        .item(&action!("menu:zoom-reset", "Zoom to 100%"))
        .item(&check!("menu:lock-zoom", "Lock Zoom (Ignore Pinch)"))
        .item(&check!("menu:edge-pan", "Pan by Moving to Edges"))
        .separator()
        .item(&displays)
        .item(&pointers)
        .separator()
        .item(&toggle_toolbar)
        .item(&check!(HIDE_TOOLBAR, "Hide the Floating Toolbar"))
        .build()?;

    let gray = SubmenuBuilder::new(app, "Gray Levels")
        .item(&check!("menu:gray:256", "256 Levels"))
        .item(&check!("menu:gray:16", "16 Levels"))
        .item(&check!("menu:gray:8", "8 Levels"))
        .item(&check!("menu:gray:4", "4 Levels"))
        .item(&check!("menu:gray:2", "2 Levels"))
        .item(&check!("menu:gray:1", "1-bit (Dithered)"))
        .build()?;

    // The toolbar splits these into "Network" and "Quality" lists that call
    // the same setter with the same five values; one list says the same thing
    // without the duplication, with the link each preset implies in its name.
    let quality = SubmenuBuilder::new(app, "Quality")
        .item(&check!("menu:quality:auto", "Auto (detect from the link)"))
        .item(&check!("menu:quality:high", "High (LAN, no adaptation)"))
        .item(&check!(
            "menu:quality:medium",
            "Medium (WAN, save bandwidth)"
        ))
        .item(&check!("menu:quality:low", "Low"))
        .item(&check!("menu:quality:bw", "Black & White"))
        .separator()
        .item(&gray)
        .separator()
        .item(&check!(
            "menu:always-refresh",
            "Always Request Fresh Frames"
        ))
        .build()?;
    gated_menus.push(quality.clone());

    let keyboard = SubmenuBuilder::new(app, "Keyboard")
        .item(&check!(
            "menu:passthrough",
            "Pass System Shortcuts to Remote"
        ))
        .separator()
        .item(&action!("menu:send-cad", "Send Ctrl+Alt+Del"))
        .item(&action!("menu:send-cmd-tab", "Send Cmd/Alt+Tab"))
        .item(&action!("menu:send-win", "Send Windows/Super Key"))
        .item(&action!("menu:send-alt-f4", "Send Alt+F4"))
        .item(&action!("menu:send-escape", "Send Escape"))
        .separator()
        .item(&action!("menu:release-keys", "Release All Keys"))
        .build()?;
    gated_menus.push(keyboard.clone());

    // Gated on the SSH probe as well as on a session, so it is held out of
    // `gated_items` and enabled by hand in `SessionMenu::set_live`.
    let files = MenuItemBuilder::with_id("menu:files", "File Transfer…")
        .enabled(false)
        .build(app)?;

    let session = SubmenuBuilder::new(app, "Session")
        .item(&action!("menu:connection-info", "Connection Info…"))
        .separator()
        .item(&quality)
        .item(&check!("menu:view-only", "View Only"))
        .item(&action!("menu:refresh", "Refresh Screen"))
        .separator()
        .item(&keyboard)
        .separator()
        .item(&action!("menu:clipboard-send", "Send Clipboard to Remote"))
        .item(&files)
        .item(&action!("menu:screenshot", "Save Screenshot"))
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

    app.manage(Mutex::new(SessionMenu {
        displays,
        checks,
        gated_items,
        gated_menus,
        files,
        toggle_toolbar,
        displays_sig: String::new(),
    }));

    app.on_menu_event(|app, event| {
        handle_menu_event(app, event.id().as_ref());
    });
    Ok(())
}

/// Apply the state the webview just reported (the `sync_session_menu` command).
pub fn sync(app: &AppHandle, update: MenuSync) {
    let Some(state) = app.try_state::<Mutex<SessionMenu>>() else {
        return;
    };
    let mut menu = state.lock();
    tracing::debug!(
        hide_toolbar = update.hide_toolbar,
        live = update.session.is_some(),
        "menu sync"
    );

    menu.check(HIDE_TOOLBAR, update.hide_toolbar);

    let Some(s) = update.session else {
        menu.set_live(false, false);
        return;
    };
    menu.set_live(true, s.files_available);
    // Nothing to recall while the toolbar is switched off entirely.
    let _ = menu.toggle_toolbar.set_enabled(!update.hide_toolbar);

    // "custom" is the zoom slider, which no fixed row represents: passing it
    // through leaves all four unticked, which is exactly right.
    let scaling = match s.scaling_mode.as_str() {
        "fit" => "fit",
        "aspect-fit" => "aspect",
        "actual" => "actual",
        "remote-resize" => "remote",
        _ => "",
    };
    menu.radio(
        "menu:scale-",
        &["fit", "aspect", "actual", "remote"],
        scaling,
    );
    menu.radio(
        "menu:quality:",
        &["auto", "high", "medium", "low", "bw"],
        &s.quality,
    );
    menu.radio(
        "menu:gray:",
        &["256", "16", "8", "4", "2", "1"],
        &s.gray_levels.to_string(),
    );
    menu.radio("menu:cursor:", &["standard", "dot", "off"], &s.local_cursor);
    menu.check("menu:remote-cursor", s.show_remote_cursor);
    menu.check("menu:view-only", s.view_only);
    menu.check("menu:passthrough", s.passthrough);
    menu.check("menu:always-refresh", s.always_refresh);
    menu.check("menu:lock-zoom", s.zoom_locked);
    menu.check("menu:edge-pan", s.edge_pan);

    // Cheap identity for the monitor list, so an unchanged one is left alone.
    let sig = format!(
        "{}|{}|{}",
        s.layout_known,
        s.display_id.map(|id| id.to_string()).unwrap_or_default(),
        s.displays
            .iter()
            .map(|d| format!("{}:{}", d.id, d.label))
            .collect::<Vec<_>>()
            .join(","),
    );
    if sig != menu.displays_sig {
        match rebuild_displays(app, &menu.displays, &s) {
            Ok(()) => menu.displays_sig = sig,
            Err(e) => tracing::warn!("could not rebuild the Displays menu: {e}"),
        }
    }
}

/// Refill the Displays submenu from the webview's list.
///
/// Rebuilt rather than kept in step item by item: the rows are not a fixed
/// set, they change with the desktop's geometry, and a server that describes
/// no layout at all offers a different list again once the seam detector has
/// looked at the pixels.
fn rebuild_displays(
    app: &AppHandle,
    displays: &Submenu<Wry>,
    state: &SessionMenuState,
) -> tauri::Result<()> {
    while displays.remove_at(0)?.is_some() {}

    displays.append(&CheckMenuItem::with_id(
        app,
        "menu:display:all",
        "All Displays",
        true,
        state.display_id.is_none(),
        None::<&str>,
    )?)?;

    if !state.displays.is_empty() {
        displays.append(&PredefinedMenuItem::separator(app)?)?;
    }
    for entry in &state.displays {
        displays.append(&CheckMenuItem::with_id(
            app,
            format!("menu:display:{}", entry.id),
            &entry.label,
            true,
            state.display_id == Some(entry.id),
            None::<&str>,
        )?)?;
    }

    // Detection only exists for the servers that describe nothing; over a real
    // layout there is nothing left to guess at.
    if !state.layout_known {
        displays.append(&PredefinedMenuItem::separator(app)?)?;
        displays.append(
            &MenuItemBuilder::with_id("menu:detect-displays", "Detect Displays Again")
                .build(app)?,
        )?;
    }
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
            //
            // Check items included: muda ticks them itself on click, which is
            // a guess at the new state rather than the truth, so the frontend
            // acts on the action and pushes the real state straight back
            // through `sync_session_menu`.
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
