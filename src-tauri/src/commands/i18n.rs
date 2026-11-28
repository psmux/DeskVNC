//! The interface language: what was chosen, what the system prefers, and
//! changing it. See `crate::i18n` and `ui/src/i18n/preference.ts`.

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use crate::i18n;
use crate::state::AppState;

/// Sent to every window when the language changes, so a session window open
/// beside the one where Preferences is switches at the same time.
pub const LANGUAGE_CHANGED: &str = "i18n://changed";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanguageState {
    /// `system`, or a language code.
    preference: &'static str,
    /// The operating system's preferred languages, most preferred first.
    system: Vec<String>,
    /// What is shown.
    language: &'static str,
}

fn read(state: &AppState) -> LanguageState {
    let stored = state.store.get_setting(i18n::SETTING_KEY).ok().flatten();
    let preference = i18n::normalize_preference(stored.as_deref());
    let system = i18n::system_languages();
    let language = i18n::resolve(preference, &system);
    LanguageState {
        preference,
        system,
        language,
    }
}

/// Apply the stored choice at startup, before the menus are built.
pub fn load(state: &AppState) {
    let current = read(state);
    tracing::info!(
        preference = current.preference,
        language = current.language,
        "interface language"
    );
    i18n::set_current(current.language);
}

#[tauri::command]
pub async fn ui_language(state: State<'_, AppState>) -> Result<LanguageState, String> {
    Ok(read(&state))
}

/// Save a new choice, rebuild the native menus in it and tell every window.
///
/// `async` for the same reason as `sync_session_menu`: rebuilding the menu
/// posts work to the main thread and waits for it.
#[tauri::command]
pub async fn set_ui_language(
    app: AppHandle,
    state: State<'_, AppState>,
    preference: String,
) -> Result<LanguageState, String> {
    let preference = i18n::normalize_preference(Some(&preference));
    state
        .store
        .set_setting(i18n::SETTING_KEY, preference)
        .map_err(|e| e.to_string())?;
    let current = read(&state);
    i18n::set_current(current.language);
    if let Err(e) = crate::menu::relabel(&app) {
        tracing::warn!("could not rebuild the menu in the new language: {e}");
    }
    if let Err(e) = crate::tray::relabel(&app) {
        tracing::warn!("could not rebuild the tray menu in the new language: {e}");
    }
    let _ = app.emit(
        LANGUAGE_CHANGED,
        serde_json::json!({ "language": current.language }),
    );
    Ok(current)
}
