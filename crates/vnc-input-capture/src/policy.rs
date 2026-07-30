//! Which key events capture swallows, and which it lets the local machine keep.
//!
//! # Why this is selective rather than "grab everything"
//!
//! A native hook that swallows *every* key would have to re-implement the whole
//! typing path (dead keys, IME, AltGr, Unicode) that the webview already does
//! correctly (PRD/06 §2.1). It would also make one bug in this crate cost the
//! user their entire keyboard.
//!
//! So the hook swallows exactly the combos the OS would otherwise eat before
//! the webview ever sees them, Cmd+Tab, Cmd+Space, the Windows key, Alt+Tab, //! and forwards those, and only those, to the remote. Everything else falls
//! through to the webview and takes the existing, well-tested Tier 1 path.
//! **Swallowed and forwarded are the same set**, so no key is ever delivered
//! twice.
//!
//! Modifier keys themselves are never swallowed on macOS (the webview needs to
//! see Cmd go down so it can send `Super_L`), but the Windows/Super key *is*
//! swallowed on Windows, because letting it through opens the Start menu and
//! steals focus. In that case we forward the modifier ourselves.
//!
//! This module is pure logic with no platform code, so it is unit-tested on
//! every host.

use crate::keymap::{is_modifier, xt};

/// Local modifier state, tracked from the platform hook's modifier events.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    /// Command on macOS, Windows/Super key elsewhere.
    pub meta: bool,
}

impl Modifiers {
    /// The escape-hatch chord (PRD/06 §3 Tier 2): `Ctrl+Alt+Shift+Esc` force
    /// releases capture and must therefore *never* be swallowed, on any
    /// platform, in any state.
    fn is_release_hotkey(&self, key: u32) -> bool {
        self.ctrl && self.alt && self.shift && key == xt::ESCAPE
    }
}

/// The OS whose shortcuts we are stealing (always the *local* machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOs {
    MacOs,
    Windows,
    Linux,
}

impl HostOs {
    /// The OS this binary was built for.
    pub const fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            HostOs::MacOs
        }
        #[cfg(target_os = "windows")]
        {
            HostOs::Windows
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            HostOs::Linux
        }
    }
}

/// Should this key event be swallowed locally and forwarded to the remote?
///
/// `key` is an XT set-1 scancode; `mods` is the modifier state *including* this
/// event (a modifier key's own press has already been folded in).
pub fn should_intercept(os: HostOs, key: u32, mods: Modifiers) -> bool {
    // Escape hatch first, nothing below can override it.
    if mods.is_release_hotkey(key) {
        return false;
    }

    match os {
        HostOs::MacOs => intercept_macos(key, mods),
        HostOs::Windows => intercept_windows(key, mods),
        // X11 pass-through is done with XGrabKeyboard, which redirects events
        // to our own window rather than handing them to us out-of-band, so
        // nothing is ever swallowed here (see `linux.rs`).
        HostOs::Linux => false,
    }
}

/// macOS: everything the WindowServer or WKWebView would eat first.
///
/// - **Any Cmd+key.** Covers Cmd+Tab, Cmd+Space, Cmd+Q, Cmd+`, and also fixes
///   the `performKeyEquivalent:` problem noted in PRD/06 §3 Tier 1, where
///   WKWebView silently handles Cmd+C/V/X/A itself.
/// - **Ctrl+arrows**, Mission Control / Spaces switching.
/// - **F3/F4/F11/F12**, Mission Control, Launchpad, Show Desktop, Dashboard.
fn intercept_macos(key: u32, mods: Modifiers) -> bool {
    if is_modifier(key) {
        // Never swallow Command itself: the webview needs the keydown so it
        // sends `Super_L`, and swallowing it would strip the modifier from
        // every combo we *don't* intercept.
        return false;
    }
    if mods.meta {
        return true;
    }
    if mods.ctrl
        && matches!(
            key,
            xt::ARROW_UP | xt::ARROW_DOWN | xt::ARROW_LEFT | xt::ARROW_RIGHT
        )
    {
        return true;
    }
    matches!(key, xt::F3 | xt::F4 | xt::F11 | xt::F12)
}

/// Windows: the shell shortcuts `WH_KEYBOARD_LL` can suppress.
///
/// - **The Windows key itself**, pressed or released, otherwise the Start menu
///   opens and we lose focus. We forward `Super_L` in its place.
/// - **Any Win+key** combo (Win+E, Win+R, Win+D, Win+L is handled by the OS
///   below us and cannot be taken).
/// - **Alt+Tab / Alt+Esc / Alt+Space / Ctrl+Esc.**
///
/// **Ctrl+Alt+Del (SAS) is not interceptable at all**, the Secure Attention
/// Sequence is handled by winlogon in a different desktop session. PRD/06
/// Tier 3 covers it with the toolbar's synthetic-send menu, which is the only
/// way to deliver it to a remote Windows host.
fn intercept_windows(key: u32, mods: Modifiers) -> bool {
    if matches!(key, xt::META_LEFT | xt::META_RIGHT) {
        return true;
    }
    if is_modifier(key) {
        return false;
    }
    if mods.meta {
        return true;
    }
    if mods.alt && matches!(key, xt::TAB | xt::ESCAPE | xt::SPACE) {
        return true;
    }
    mods.ctrl && key == xt::ESCAPE
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Modifiers = Modifiers {
        shift: false,
        ctrl: false,
        alt: false,
        meta: false,
    };
    const META: Modifiers = Modifiers { meta: true, ..NONE };
    const ALT: Modifiers = Modifiers { alt: true, ..NONE };
    const CTRL: Modifiers = Modifiers { ctrl: true, ..NONE };

    // -- the escape hatch ---------------------------------------------------

    #[test]
    fn release_hotkey_is_never_intercepted_on_any_platform() {
        let chord = Modifiers {
            ctrl: true,
            alt: true,
            shift: true,
            meta: false,
        };
        for os in [HostOs::MacOs, HostOs::Windows, HostOs::Linux] {
            assert!(!should_intercept(os, xt::ESCAPE, chord), "{os:?}");
        }
        // …even with Cmd also held, which would otherwise match the macOS rule.
        let chord_with_meta = Modifiers {
            meta: true,
            ..chord
        };
        assert!(!should_intercept(
            HostOs::MacOs,
            xt::ESCAPE,
            chord_with_meta
        ));
    }

    #[test]
    fn plain_escape_is_still_intercepted_under_cmd_on_macos() {
        // Cmd+Option+Esc (Force Quit) must reach the remote.
        let cmd_alt = Modifiers {
            meta: true,
            alt: true,
            ..NONE
        };
        assert!(should_intercept(HostOs::MacOs, xt::ESCAPE, cmd_alt));
    }

    // -- macOS --------------------------------------------------------------

    #[test]
    fn macos_intercepts_command_combos() {
        assert!(should_intercept(HostOs::MacOs, xt::TAB, META)); // Cmd+Tab
        assert!(should_intercept(HostOs::MacOs, xt::SPACE, META)); // Cmd+Space
        assert!(should_intercept(HostOs::MacOs, 0x10, META)); // Cmd+Q
        assert!(should_intercept(HostOs::MacOs, 0x2e, META)); // Cmd+C
    }

    #[test]
    fn macos_intercepts_mission_control_keys() {
        assert!(should_intercept(HostOs::MacOs, xt::ARROW_RIGHT, CTRL));
        assert!(should_intercept(HostOs::MacOs, xt::ARROW_UP, CTRL));
        assert!(should_intercept(HostOs::MacOs, xt::F3, NONE));
        assert!(should_intercept(HostOs::MacOs, xt::F11, NONE));
    }

    #[test]
    fn macos_leaves_ordinary_typing_to_the_webview() {
        assert!(!should_intercept(HostOs::MacOs, 0x1e, NONE)); // 'a'
        assert!(!should_intercept(HostOs::MacOs, xt::TAB, NONE));
        assert!(!should_intercept(HostOs::MacOs, xt::ENTER, NONE));
        assert!(!should_intercept(HostOs::MacOs, 0x1e, CTRL)); // Ctrl+A
        assert!(!should_intercept(HostOs::MacOs, xt::ARROW_LEFT, NONE));
    }

    #[test]
    fn macos_never_swallows_modifiers() {
        for key in [
            xt::META_LEFT,
            xt::META_RIGHT,
            xt::CONTROL_LEFT,
            xt::ALT_LEFT,
            xt::SHIFT_LEFT,
            xt::CAPS_LOCK,
        ] {
            assert!(!should_intercept(HostOs::MacOs, key, META), "{key:#04x}");
        }
    }

    // -- Windows ------------------------------------------------------------

    #[test]
    fn windows_swallows_the_windows_key_itself() {
        assert!(should_intercept(HostOs::Windows, xt::META_LEFT, NONE));
        assert!(should_intercept(HostOs::Windows, xt::META_RIGHT, META));
    }

    #[test]
    fn windows_intercepts_shell_shortcuts() {
        assert!(should_intercept(HostOs::Windows, xt::TAB, ALT)); // Alt+Tab
        assert!(should_intercept(HostOs::Windows, xt::ESCAPE, ALT)); // Alt+Esc
        assert!(should_intercept(HostOs::Windows, xt::SPACE, ALT)); // Alt+Space
        assert!(should_intercept(HostOs::Windows, xt::ESCAPE, CTRL)); // Ctrl+Esc
        assert!(should_intercept(HostOs::Windows, 0x12, META)); // Win+E
    }

    #[test]
    fn windows_leaves_ordinary_typing_and_app_shortcuts_alone() {
        assert!(!should_intercept(HostOs::Windows, 0x1e, NONE)); // 'a'
        assert!(!should_intercept(HostOs::Windows, 0x2e, CTRL)); // Ctrl+C
        assert!(!should_intercept(HostOs::Windows, xt::TAB, NONE));
        assert!(!should_intercept(HostOs::Windows, xt::ALT_LEFT, ALT));
        // Ctrl+Alt+Del is not interceptable by any hook; we must not pretend.
        let ctrl_alt = Modifiers {
            ctrl: true,
            alt: true,
            ..NONE
        };
        assert!(!should_intercept(HostOs::Windows, xt::DELETE, ctrl_alt));
    }

    // -- Linux --------------------------------------------------------------

    #[test]
    fn linux_never_intercepts_because_the_grab_does_the_work() {
        assert!(!should_intercept(HostOs::Linux, xt::TAB, ALT));
        assert!(!should_intercept(HostOs::Linux, xt::META_LEFT, NONE));
    }
}
