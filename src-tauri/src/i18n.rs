//! The interface language, for the parts of it built in Rust.
//!
//! The native menus and the tray are built here, before any webview has
//! loaded, so they cannot ask the webview what to say. They read the same
//! catalog files the webview does (`ui/src/i18n/locales/*.json`, included at
//! compile time), keyed by the English text, and fall back to the English for
//! anything a catalog does not have. See `ui/src/i18n/index.ts` for the other
//! half.
//!
//! The choice is stored as the app setting [`SETTING_KEY`]: `system`, or a
//! language code. `system`, the default, follows the operating system's
//! preferred languages, read with `sys-locale` because a webview's
//! `navigator.languages` is not a faithful reading of them on macOS.

use std::collections::HashMap;
use std::sync::OnceLock;

use parking_lot::RwLock;

/// The app setting that holds the choice.
pub const SETTING_KEY: &str = "ui_language";

/// The languages there is a catalog for, besides English.
const CATALOGS: &[(&str, &str)] = &[(
    "zh-CN",
    include_str!("../../ui/src/i18n/locales/zh-CN.json"),
)];

/// Every language the interface can be shown in.
pub const LANGUAGES: &[&str] = &["en", "zh-CN"];

static CURRENT: RwLock<&'static str> = RwLock::new("en");

fn catalogs() -> &'static HashMap<&'static str, HashMap<String, String>> {
    static PARSED: OnceLock<HashMap<&'static str, HashMap<String, String>>> = OnceLock::new();
    PARSED.get_or_init(|| {
        CATALOGS
            .iter()
            .map(|(code, text)| (*code, parse_catalog(text)))
            .collect()
    })
}

/// A catalog's entries. A plural entry (an object of forms) contributes its
/// `other` form, which is the one every language has.
fn parse_catalog(text: &str) -> HashMap<String, String> {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!("a translation catalog does not parse: {e}");
            return HashMap::new();
        }
    };
    let Some(entries) = value.as_object() else {
        return HashMap::new();
    };
    entries
        .iter()
        .filter_map(|(english, value)| {
            let text = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Object(forms) => forms.get("other")?.as_str()?.to_string(),
                _ => return None,
            };
            Some((english.clone(), text))
        })
        .collect()
}

/// The supported language a BCP 47 tag means, if any. The same rules as
/// `matchLanguage` in the webview: Simplified Chinese by script or region,
/// Traditional left alone so the next preferred language gets its turn.
pub fn match_language(tag: &str) -> Option<&'static str> {
    let tag = tag.trim().replace('_', "-").to_ascii_lowercase();
    let mut parts = tag.split('-');
    match parts.next()? {
        "en" => Some("en"),
        "zh" => {
            let rest: Vec<&str> = parts.collect();
            if rest.contains(&"hant") {
                None
            } else if rest.contains(&"hans") {
                Some("zh-CN")
            } else if rest.iter().any(|p| matches!(*p, "tw" | "hk" | "mo")) {
                None
            } else {
                Some("zh-CN")
            }
        }
        _ => None,
    }
}

/// The language to show for a stored choice and the system's languages.
pub fn resolve(preference: &str, system: &[String]) -> &'static str {
    if let Some(chosen) = LANGUAGES.iter().find(|code| **code == preference) {
        return chosen;
    }
    system
        .iter()
        .find_map(|tag| match_language(tag))
        .unwrap_or("en")
}

/// A stored value read back, anything unknown being `system`.
pub fn normalize_preference(raw: Option<&str>) -> &'static str {
    match raw {
        Some(value) => LANGUAGES
            .iter()
            .find(|code| **code == value)
            .copied()
            .unwrap_or("system"),
        None => "system",
    }
}

/// The operating system's preferred languages, most preferred first.
pub fn system_languages() -> Vec<String> {
    sys_locale::get_locales().collect()
}

pub fn current() -> &'static str {
    *CURRENT.read()
}

pub fn set_current(language: &'static str) {
    *CURRENT.write() = language;
}

/// `english` in the language in use, or the English itself.
pub fn tr(english: &str) -> String {
    tr_in(current(), english)
}

fn tr_in(language: &str, english: &str) -> String {
    catalogs()
        .get(language)
        .and_then(|catalog| catalog.get(english))
        .cloned()
        .unwrap_or_else(|| english.to_string())
}

/// [`tr`] with `{count}` filled in.
pub fn tr_count(english: &str, count: u32) -> String {
    tr(english).replace("{count}", &count.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn langs(tags: &[&str]) -> Vec<String> {
        tags.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn follows_the_first_system_language_there_is_a_catalog_for() {
        assert_eq!(resolve("system", &langs(&["zh-Hans-CN", "en-US"])), "zh-CN");
        assert_eq!(resolve("system", &langs(&["fr-FR", "zh-CN"])), "zh-CN");
        assert_eq!(resolve("system", &langs(&["zh_CN"])), "zh-CN");
        assert_eq!(resolve("system", &langs(&["fr-FR", "en-GB", "zh-CN"])), "en");
        assert_eq!(resolve("system", &langs(&["zh-TW"])), "en");
        assert_eq!(resolve("system", &langs(&["zh-Hant-HK", "zh-CN"])), "zh-CN");
        assert_eq!(resolve("system", &[]), "en");
    }

    #[test]
    fn a_chosen_language_wins_over_the_system() {
        assert_eq!(resolve("en", &langs(&["zh-CN"])), "en");
        assert_eq!(resolve("zh-CN", &langs(&["en-US"])), "zh-CN");
    }

    #[test]
    fn an_unknown_stored_value_means_follow_the_system() {
        assert_eq!(normalize_preference(None), "system");
        assert_eq!(normalize_preference(Some("klingon")), "system");
        assert_eq!(normalize_preference(Some("zh-CN")), "zh-CN");
    }

    #[test]
    fn falls_back_to_the_english_for_anything_untranslated() {
        assert_eq!(tr_in("zh-CN", "No such menu item, ever"), "No such menu item, ever");
        assert_eq!(tr_in("en", "Disconnect"), "Disconnect");
        assert_ne!(tr_in("zh-CN", "Disconnect"), "Disconnect");
    }

    /// Every label the menus and the tray ask for is in every catalog, so a
    /// new menu item in English fails here until it is translated.
    #[test]
    fn every_menu_label_is_translated() {
        let sources = [include_str!("menu.rs"), include_str!("tray.rs")];
        let mut labels = Vec::new();
        for source in sources {
            for call in ["tr(\"", "tr_count(\""] {
                let mut rest = source;
                while let Some(at) = rest.find(call) {
                    // `tr(` inside `tr_count(` and the like is skipped.
                    let before = rest[..at].chars().last();
                    rest = &rest[at + call.len()..];
                    if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                        continue;
                    }
                    let end = rest.find('"').expect("unterminated label");
                    labels.push(rest[..end].to_string());
                }
            }
        }
        assert!(labels.len() > 50, "found only {} labels", labels.len());
        for (code, _) in CATALOGS {
            let catalog = &catalogs()[code];
            let missing: Vec<&String> = labels.iter().filter(|l| !catalog.contains_key(*l)).collect();
            assert!(missing.is_empty(), "{code} is missing {missing:?}");
        }
    }
}
