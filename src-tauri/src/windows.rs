//! Session-window creation and monitor/fullscreen helpers (PRD/05 §5).

use tauri::{
    AppHandle, Manager, PhysicalPosition, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
};

/// Label of the library window, which is also the window that hosts session
/// tabs in tabbed view.
pub const MAIN_WINDOW_LABEL: &str = "main";

/// Window label for a session id.
pub fn session_label(session_id: &str) -> String {
    format!("session-{session_id}")
}

/// Session ids are shell/UI-generated identifiers (uuids). Reject anything
/// else so they can be embedded in window labels and URLs safely.
pub fn validate_session_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 64 {
        return Err("invalid session id".into());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("invalid session id".into());
    }
    Ok(())
}

/// Connection parameters handed to a new session window through its URL.
///
/// The session webview reads these back with `readSessionParams()` (see
/// `ui/src/hooks/useSession.ts`) and passes them straight to `connect_session`,
/// so the key names here are part of the IPC contract.
pub struct SessionWindowParams<'a> {
    pub session_id: &'a str,
    pub profile_id: Option<&'a str>,
    pub address: &'a str,
    pub port: u16,
    pub name: &'a str,
}

/// Percent-encode a query-string value, keeping only the RFC 3986 unreserved
/// set. Host names and desktop titles are user/server supplied, so they must
/// never be spliced into the URL raw.
fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Create (or focus) the viewer window for a session.
///
/// The window loads the same frontend with the connection parameters in the
/// query string so the session view mounts and can connect itself (PRD/01 §6:
/// one `WebviewWindow` per session, label `session-<id>`). `title` is set
/// through the native window API only, server-derived names are untrusted but
/// harmless there (never interpolated into HTML).
pub fn open_session_window(
    app: &AppHandle,
    params: &SessionWindowParams<'_>,
    title: &str,
) -> tauri::Result<WebviewWindow> {
    let label = session_label(params.session_id);
    if let Some(existing) = app.get_webview_window(&label) {
        focus_session_window(app, &label);
        return Ok(existing);
    }

    // `validate_session_id` guarantees the id itself is URL-safe; everything
    // else is percent-encoded.
    let mut query = format!(
        "sessionId={}&address={}&port={}&name={}",
        params.session_id,
        encode_component(params.address),
        params.port,
        encode_component(params.name),
    );
    if let Some(profile_id) = params.profile_id {
        query.push_str("&profileId=");
        query.push_str(&encode_component(profile_id));
    }

    let url = WebviewUrl::App(format!("index.html?{query}").into());
    let window = WebviewWindowBuilder::new(app, &label, url)
        .title(title)
        .inner_size(1280.0, 800.0)
        .min_inner_size(640.0, 480.0)
        .center()
        .build()?;
    Ok(window)
}

/// Bring an existing session window to the front.
///
/// Returns `false` when there is no window with that label, the caller then
/// treats the machine as not-open and connects normally, so a stale registry
/// entry can never become a lockout.
///
/// All three steps matter, in this order: a minimised window will not take
/// focus until it is restored, and a hidden one cannot be raised at all. The
/// calls are individually fault-tolerant because platforms disagree about
/// which of them are no-ops, on macOS `unminimize` on a normal window and
/// `show` on a visible one both do nothing, which is exactly what we want.
///
/// Not handled: a window on another macOS Space (the OS decides whether to
/// switch Spaces or bounce the Dock icon, there is no Tauri API for it), and
/// a window on a monitor that has since been unplugged.
pub fn focus_session_window(app: &AppHandle, label: &str) -> bool {
    let Some(window) = app.get_webview_window(label) else {
        return false;
    };
    if let Err(e) = window.unminimize() {
        tracing::debug!(window = %label, "unminimize failed: {e}");
    }
    if let Err(e) = window.show() {
        tracing::debug!(window = %label, "show failed: {e}");
    }
    if let Err(e) = window.set_focus() {
        // Focus can be refused (another app holds it, or the window is on a
        // Space the compositor won't switch to). The window is at least
        // restored and visible by now.
        tracing::warn!(window = %label, "could not focus the existing session window: {e}");
    }
    true
}

/// Enter/leave fullscreen, optionally on a specific monitor.
///
/// PRD/05 §5 gotcha: `fullscreen(true)` at window-build time only works on the
/// primary monitor. The correct pattern, implemented here, is to *position*
/// the window onto the target monitor first, **then** call
/// `set_fullscreen(true)`.
pub fn set_fullscreen_on_monitor(
    window: &WebviewWindow,
    monitor_index: Option<usize>,
    fullscreen: bool,
) -> Result<(), String> {
    if !fullscreen {
        window.set_fullscreen(false).map_err(|e| e.to_string())?;
        set_menu_visible(window, true);
        return Ok(());
    }

    let target = match monitor_index {
        Some(index) => {
            let monitors = window.available_monitors().map_err(|e| e.to_string())?;
            Some(
                monitors
                    .into_iter()
                    .nth(index)
                    .ok_or_else(|| format!("no monitor at index {index}"))?,
            )
        }
        // No explicit monitor: fullscreen wherever the window currently is.
        None => window.current_monitor().map_err(|e| e.to_string())?,
    };

    if let Some(monitor) = target {
        // Leave any current fullscreen before moving, or the reposition is
        // ignored on some platforms.
        let _ = window.set_fullscreen(false);
        let pos = monitor.position();
        window
            .set_position(PhysicalPosition::new(pos.x, pos.y))
            .map_err(|e| e.to_string())?;
    }
    window.set_fullscreen(true).map_err(|e| e.to_string())?;
    set_menu_visible(window, false);
    Ok(())
}

/// Show or hide the window's menu bar.
///
/// On Windows and Linux the menu is part of the window, so in fullscreen it
/// keeps a strip of the screen that the remote desktop should have had: the
/// point of fullscreen is that the remote fills the display. macOS puts the
/// menu in the system bar, which it hides for fullscreen windows itself, so
/// there is nothing to do and asking would be wrong.
///
/// The toolbar's fullscreen button and its shortcut both remain, which is
/// what gets you back out with the menu gone.
fn set_menu_visible(window: &WebviewWindow, visible: bool) {
    #[cfg(not(target_os = "macos"))]
    {
        let r = if visible {
            window.show_menu()
        } else {
            window.hide_menu()
        };
        if let Err(e) = r {
            tracing::debug!(visible, "could not change menu visibility: {e}");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (window, visible);
    }
}
