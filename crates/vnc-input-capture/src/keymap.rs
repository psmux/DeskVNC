//! Physical-key mapping tables: OS virtual keycode -> XT set-1 scancode +
//! best-effort X11 keysym (PRD/06 §2.2).
//!
//! # Why the numbers live here and not in `vnc-core`
//!
//! `vnc-core` owns the canonical browser `KeyboardEvent.code` -> XT table. This
//! crate cannot depend on it (see the note in `Cargo.toml`), so [`KEYS`] repeats
//! the `(code, XT, keysym)` triples, but *only* as a single table, and
//! `tests/vnc_core_agreement.rs` asserts every row against
//! `vnc_core::input::code_to_xt_scancode` / `code_to_keysym`, so the two can
//! never drift silently.
//!
//! Everything in this module is plain data and compiles on every target, so the
//! Windows and Linux tables are unit-tested on the macOS dev machine too.

/// Canonical physical-key table: `(browser code, XT set-1 scancode, X11 keysym)`.
///
/// The keysym is the **unshifted** US-layout value; capture is a
/// layout-independent scancode path, so the keysym is only ever a hint
/// (PRD/06 §2.2: "Always send the best-guess keysym alongside").
///
/// Extended (`E0`-prefixed) scancodes carry bit 7 set, matching the RFB QEMU
/// extended-key-event convention.
pub const KEYS: &[(&str, u32, u32)] = &[
    // -- main block ---------------------------------------------------------
    ("Escape", 0x01, 0xff1b),
    ("Digit1", 0x02, 0x31),
    ("Digit2", 0x03, 0x32),
    ("Digit3", 0x04, 0x33),
    ("Digit4", 0x05, 0x34),
    ("Digit5", 0x06, 0x35),
    ("Digit6", 0x07, 0x36),
    ("Digit7", 0x08, 0x37),
    ("Digit8", 0x09, 0x38),
    ("Digit9", 0x0a, 0x39),
    ("Digit0", 0x0b, 0x30),
    ("Minus", 0x0c, 0x2d),
    ("Equal", 0x0d, 0x3d),
    ("Backspace", 0x0e, 0xff08),
    ("Tab", 0x0f, 0xff09),
    ("KeyQ", 0x10, 0x71),
    ("KeyW", 0x11, 0x77),
    ("KeyE", 0x12, 0x65),
    ("KeyR", 0x13, 0x72),
    ("KeyT", 0x14, 0x74),
    ("KeyY", 0x15, 0x79),
    ("KeyU", 0x16, 0x75),
    ("KeyI", 0x17, 0x69),
    ("KeyO", 0x18, 0x6f),
    ("KeyP", 0x19, 0x70),
    ("BracketLeft", 0x1a, 0x5b),
    ("BracketRight", 0x1b, 0x5d),
    ("Enter", 0x1c, 0xff0d),
    ("ControlLeft", 0x1d, 0xffe3),
    ("KeyA", 0x1e, 0x61),
    ("KeyS", 0x1f, 0x73),
    ("KeyD", 0x20, 0x64),
    ("KeyF", 0x21, 0x66),
    ("KeyG", 0x22, 0x67),
    ("KeyH", 0x23, 0x68),
    ("KeyJ", 0x24, 0x6a),
    ("KeyK", 0x25, 0x6b),
    ("KeyL", 0x26, 0x6c),
    ("Semicolon", 0x27, 0x3b),
    ("Quote", 0x28, 0x27),
    ("Backquote", 0x29, 0x60),
    ("ShiftLeft", 0x2a, 0xffe1),
    ("Backslash", 0x2b, 0x5c),
    ("KeyZ", 0x2c, 0x7a),
    ("KeyX", 0x2d, 0x78),
    ("KeyC", 0x2e, 0x63),
    ("KeyV", 0x2f, 0x76),
    ("KeyB", 0x30, 0x62),
    ("KeyN", 0x31, 0x6e),
    ("KeyM", 0x32, 0x6d),
    ("Comma", 0x33, 0x2c),
    ("Period", 0x34, 0x2e),
    ("Slash", 0x35, 0x2f),
    ("ShiftRight", 0x36, 0xffe2),
    ("NumpadMultiply", 0x37, 0xffaa),
    ("AltLeft", 0x38, 0xffe9),
    ("Space", 0x39, 0x20),
    ("CapsLock", 0x3a, 0xffe5),
    ("F1", 0x3b, 0xffbe),
    ("F2", 0x3c, 0xffbf),
    ("F3", 0x3d, 0xffc0),
    ("F4", 0x3e, 0xffc1),
    ("F5", 0x3f, 0xffc2),
    ("F6", 0x40, 0xffc3),
    ("F7", 0x41, 0xffc4),
    ("F8", 0x42, 0xffc5),
    ("F9", 0x43, 0xffc6),
    ("F10", 0x44, 0xffc7),
    ("NumLock", 0x45, 0xff7f),
    ("ScrollLock", 0x46, 0xff14),
    ("Numpad7", 0x47, 0xffb7),
    ("Numpad8", 0x48, 0xffb8),
    ("Numpad9", 0x49, 0xffb9),
    ("NumpadSubtract", 0x4a, 0xffad),
    ("Numpad4", 0x4b, 0xffb4),
    ("Numpad5", 0x4c, 0xffb5),
    ("Numpad6", 0x4d, 0xffb6),
    ("NumpadAdd", 0x4e, 0xffab),
    ("Numpad1", 0x4f, 0xffb1),
    ("Numpad2", 0x50, 0xffb2),
    ("Numpad3", 0x51, 0xffb3),
    ("Numpad0", 0x52, 0xffb0),
    ("NumpadDecimal", 0x53, 0xffae),
    // PrintScreen SHOULD be plain 0x54 (Alt+SysRq position) per PRD/06 §2.2.
    ("PrintScreen", 0x54, 0xff61),
    ("IntlBackslash", 0x56, 0x3c),
    ("F11", 0x57, 0xffc8),
    ("F12", 0x58, 0xffc9),
    ("NumpadEqual", 0x59, 0xffbd),
    ("IntlRo", 0x73, 0x5c),
    ("IntlYen", 0x7d, 0xa5),
    ("NumpadComma", 0x7e, 0xffac),
    // -- extended (E0-prefixed) keys: bit 7 set -----------------------------
    ("NumpadEnter", 0x9c, 0xff8d),
    ("ControlRight", 0x9d, 0xffe4),
    ("NumpadDivide", 0xb5, 0xffaf),
    ("AltRight", 0xb8, 0xffea),
    // Pause MUST be 0xc6 per the QEMU extended-key-event spec.
    ("Pause", 0xc6, 0xff13),
    ("Home", 0xc7, 0xff50),
    ("ArrowUp", 0xc8, 0xff52),
    ("PageUp", 0xc9, 0xff55),
    ("ArrowLeft", 0xcb, 0xff51),
    ("ArrowRight", 0xcd, 0xff53),
    ("End", 0xcf, 0xff57),
    ("ArrowDown", 0xd0, 0xff54),
    ("PageDown", 0xd1, 0xff56),
    ("Insert", 0xd2, 0xff63),
    ("Delete", 0xd3, 0xffff),
    ("MetaLeft", 0xdb, 0xffeb),
    ("MetaRight", 0xdc, 0xffec),
    ("ContextMenu", 0xdd, 0xff67),
];

/// XT set-1 scancodes of the modifier keys, used by the interception policy.
pub mod xt {
    pub const ESCAPE: u32 = 0x01;
    pub const TAB: u32 = 0x0f;
    pub const ENTER: u32 = 0x1c;
    pub const CONTROL_LEFT: u32 = 0x1d;
    pub const SHIFT_LEFT: u32 = 0x2a;
    pub const SHIFT_RIGHT: u32 = 0x36;
    pub const ALT_LEFT: u32 = 0x38;
    pub const SPACE: u32 = 0x39;
    pub const CAPS_LOCK: u32 = 0x3a;
    pub const F1: u32 = 0x3b;
    pub const F3: u32 = 0x3d;
    pub const F4: u32 = 0x3e;
    pub const F10: u32 = 0x44;
    pub const F11: u32 = 0x57;
    pub const F12: u32 = 0x58;
    pub const CONTROL_RIGHT: u32 = 0x9d;
    pub const ALT_RIGHT: u32 = 0xb8;
    pub const ARROW_UP: u32 = 0xc8;
    pub const ARROW_LEFT: u32 = 0xcb;
    pub const ARROW_RIGHT: u32 = 0xcd;
    pub const ARROW_DOWN: u32 = 0xd0;
    pub const DELETE: u32 = 0xd3;
    pub const META_LEFT: u32 = 0xdb;
    pub const META_RIGHT: u32 = 0xdc;
}

/// Is `xt` one of the modifier keys (the keys we describe by state rather than
/// intercept as a "the user pressed a shortcut" trigger)?
pub fn is_modifier(xt: u32) -> bool {
    matches!(
        xt,
        xt::CONTROL_LEFT
            | xt::CONTROL_RIGHT
            | xt::SHIFT_LEFT
            | xt::SHIFT_RIGHT
            | xt::ALT_LEFT
            | xt::ALT_RIGHT
            | xt::META_LEFT
            | xt::META_RIGHT
            | xt::CAPS_LOCK
    )
}

/// XT set-1 scancode for a browser `KeyboardEvent.code`.
pub fn code_to_xt(code: &str) -> Option<u32> {
    KEYS.iter()
        .find(|(c, _, _)| *c == code)
        .map(|(_, xt, _)| *xt)
}

/// Best-effort X11 keysym for an XT set-1 scancode.
///
/// `shift` only upper-cases ASCII letters: capture rides the layout-independent
/// scancode path, where the guest keymap decides what the key produces, so a
/// full shifted-symbol table here would be a lie on non-US layouts.
pub fn xt_to_keysym(xt: u32, shift: bool) -> Option<u32> {
    let keysym = KEYS.iter().find(|(_, x, _)| *x == xt).map(|(_, _, k)| *k)?;
    Some(if shift && (0x61..=0x7a).contains(&keysym) {
        keysym - 0x20
    } else {
        keysym
    })
}

/// Browser `KeyboardEvent.code` for an XT set-1 scancode (diagnostics/tests).
pub fn xt_to_code(xt: u32) -> Option<&'static str> {
    KEYS.iter().find(|(_, x, _)| *x == xt).map(|(c, _, _)| *c)
}

// ---------------------------------------------------------------------------
// macOS: kVK_* virtual keycode -> browser code
// ---------------------------------------------------------------------------

/// macOS `kVK_*` virtual keycode -> browser `KeyboardEvent.code`.
///
/// Values from `<Carbon/HIToolbox/Events.h>`; the code names follow the W3C
/// UI Events code table, which is what `KEYS` is keyed on. Keys with no XT
/// equivalent (`kVK_Function`, media keys, `kVK_JIS_Eisu`/`Kana`, F13-F20) are
/// deliberately absent, they map to `None` and are passed through to the local
/// machine rather than being swallowed.
pub const MAC_KVK: &[(u16, &str)] = &[
    (0x00, "KeyA"),
    (0x01, "KeyS"),
    (0x02, "KeyD"),
    (0x03, "KeyF"),
    (0x04, "KeyH"),
    (0x05, "KeyG"),
    (0x06, "KeyZ"),
    (0x07, "KeyX"),
    (0x08, "KeyC"),
    (0x09, "KeyV"),
    (0x0a, "IntlBackslash"), // kVK_ISO_Section
    (0x0b, "KeyB"),
    (0x0c, "KeyQ"),
    (0x0d, "KeyW"),
    (0x0e, "KeyE"),
    (0x0f, "KeyR"),
    (0x10, "KeyY"),
    (0x11, "KeyT"),
    (0x12, "Digit1"),
    (0x13, "Digit2"),
    (0x14, "Digit3"),
    (0x15, "Digit4"),
    (0x16, "Digit6"),
    (0x17, "Digit5"),
    (0x18, "Equal"),
    (0x19, "Digit9"),
    (0x1a, "Digit7"),
    (0x1b, "Minus"),
    (0x1c, "Digit8"),
    (0x1d, "Digit0"),
    (0x1e, "BracketRight"),
    (0x1f, "KeyO"),
    (0x20, "KeyU"),
    (0x21, "BracketLeft"),
    (0x22, "KeyI"),
    (0x23, "KeyP"),
    (0x24, "Enter"),
    (0x25, "KeyL"),
    (0x26, "KeyJ"),
    (0x27, "Quote"),
    (0x28, "KeyK"),
    (0x29, "Semicolon"),
    (0x2a, "Backslash"),
    (0x2b, "Comma"),
    (0x2c, "Slash"),
    (0x2d, "KeyN"),
    (0x2e, "KeyM"),
    (0x2f, "Period"),
    (0x30, "Tab"),
    (0x31, "Space"),
    (0x32, "Backquote"),
    (0x33, "Backspace"), // kVK_Delete is Backspace
    (0x35, "Escape"),
    (0x36, "MetaRight"),
    (0x37, "MetaLeft"),
    (0x38, "ShiftLeft"),
    (0x39, "CapsLock"),
    (0x3a, "AltLeft"), // Option
    (0x3b, "ControlLeft"),
    (0x3c, "ShiftRight"),
    (0x3d, "AltRight"),
    (0x3e, "ControlRight"),
    (0x41, "NumpadDecimal"),
    (0x43, "NumpadMultiply"),
    (0x45, "NumpadAdd"),
    (0x47, "NumLock"), // kVK_ANSI_KeypadClear sits where NumLock does
    (0x4b, "NumpadDivide"),
    (0x4c, "NumpadEnter"),
    (0x4e, "NumpadSubtract"),
    (0x51, "NumpadEqual"),
    (0x52, "Numpad0"),
    (0x53, "Numpad1"),
    (0x54, "Numpad2"),
    (0x55, "Numpad3"),
    (0x56, "Numpad4"),
    (0x57, "Numpad5"),
    (0x58, "Numpad6"),
    (0x59, "Numpad7"),
    (0x5b, "Numpad8"),
    (0x5c, "Numpad9"),
    (0x5d, "IntlYen"),
    (0x5e, "IntlRo"),
    (0x5f, "NumpadComma"),
    (0x60, "F5"),
    (0x61, "F6"),
    (0x62, "F7"),
    (0x63, "F3"),
    (0x64, "F8"),
    (0x65, "F9"),
    (0x67, "F11"),
    (0x6d, "F10"),
    (0x6e, "ContextMenu"),
    (0x6f, "F12"),
    (0x72, "Insert"), // kVK_Help occupies the Insert position
    (0x73, "Home"),
    (0x74, "PageUp"),
    (0x75, "Delete"), // kVK_ForwardDelete
    (0x76, "F4"),
    (0x77, "End"),
    (0x78, "F2"),
    (0x79, "PageDown"),
    (0x7a, "F1"),
    (0x7b, "ArrowLeft"),
    (0x7c, "ArrowRight"),
    (0x7d, "ArrowDown"),
    (0x7e, "ArrowUp"),
];

/// macOS `kVK_*` virtual keycode -> XT set-1 scancode.
pub fn kvk_to_xt(kvk: u16) -> Option<u32> {
    let code = MAC_KVK.iter().find(|(k, _)| *k == kvk).map(|(_, c)| *c)?;
    code_to_xt(code)
}

// ---------------------------------------------------------------------------
// Windows: KBDLLHOOKSTRUCT -> XT
// ---------------------------------------------------------------------------

/// Windows virtual-key codes we need to disambiguate scancodes with.
pub mod vk {
    pub const PAUSE: u32 = 0x13;
    pub const NUMLOCK: u32 = 0x90;
    pub const SNAPSHOT: u32 = 0x2c; // PrintScreen
}

/// `KBDLLHOOKSTRUCT` -> XT set-1 scancode.
///
/// Windows scancodes already *are* XT set-1, so this is mostly the
/// `LLKHF_EXTENDED` bit-7 fold-in. Three keys need the virtual-key code to
/// disambiguate, because the raw scancode alone is ambiguous:
///
/// - `Pause` arrives as `0x45` (same as `NumLock`), the spec pins it at `0xc6`.
/// - `PrintScreen` arrives extended `0x37` (same as `NumpadMultiply` + E0), ///   the spec prefers the plain `0x54` SysRq position.
/// - `NumLock` keeps the plain `0x45`.
pub fn windows_to_xt(vk_code: u32, scan_code: u32, extended: bool) -> Option<u32> {
    match vk_code {
        vk::PAUSE => return Some(0xc6),
        vk::NUMLOCK => return Some(0x45),
        vk::SNAPSHOT => return Some(0x54),
        _ => {}
    }
    let scan = scan_code & 0x7f;
    if scan == 0 {
        // Injected/virtual events carry no scancode; nothing physical to send.
        return None;
    }
    Some(if extended { scan | 0x80 } else { scan })
}

// ---------------------------------------------------------------------------
// Linux: evdev / X11 keycode -> XT
// ---------------------------------------------------------------------------

/// evdev keycodes above the flat range, where evdev and XT set-1 diverge.
const EVDEV_EXTENDED: &[(u32, u32)] = &[
    (96, 0x9c),  // KEY_KPENTER
    (97, 0x9d),  // KEY_RIGHTCTRL
    (98, 0xb5),  // KEY_KPSLASH
    (99, 0x54),  // KEY_SYSRQ / PrintScreen
    (100, 0xb8), // KEY_RIGHTALT
    (102, 0xc7), // KEY_HOME
    (103, 0xc8), // KEY_UP
    (104, 0xc9), // KEY_PAGEUP
    (105, 0xcb), // KEY_LEFT
    (106, 0xcd), // KEY_RIGHT
    (107, 0xcf), // KEY_END
    (108, 0xd0), // KEY_DOWN
    (109, 0xd1), // KEY_PAGEDOWN
    (110, 0xd2), // KEY_INSERT
    (111, 0xd3), // KEY_DELETE
    (117, 0x59), // KEY_KPEQUAL
    (119, 0xc6), // KEY_PAUSE
    (121, 0x7e), // KEY_KPCOMMA
    (125, 0xdb), // KEY_LEFTMETA
    (126, 0xdc), // KEY_RIGHTMETA
    (127, 0xdd), // KEY_COMPOSE / Menu
];

/// evdev keycode -> XT set-1 scancode.
///
/// For 1..=88 (`KEY_ESC`..`KEY_F12`, minus two unassigned slots) evdev *is*
/// XT set-1; above that the two diverge and [`EVDEV_EXTENDED`] applies.
pub fn evdev_to_xt(evdev: u32) -> Option<u32> {
    if (1..=88).contains(&evdev) && evdev != 84 && evdev != 85 {
        return Some(evdev);
    }
    if evdev == 89 {
        return Some(0x73); // KEY_RO
    }
    if evdev == 124 {
        return Some(0x7d); // KEY_YEN
    }
    EVDEV_EXTENDED
        .iter()
        .find(|(e, _)| *e == evdev)
        .map(|(_, xt)| *xt)
}

/// X11 keycode -> XT set-1 scancode. X11 keycodes are evdev + 8 on every
/// modern (XKB/evdev) server, which is the `code - 8` rule from PRD/06 §2.2.
pub fn x11_keycode_to_xt(keycode: u32) -> Option<u32> {
    evdev_to_xt(keycode.checked_sub(8)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn key_table_has_no_duplicate_codes_or_scancodes() {
        let mut codes = HashSet::new();
        let mut scancodes = HashSet::new();
        for (code, xt, _) in KEYS {
            assert!(codes.insert(*code), "duplicate code {code}");
            assert!(
                scancodes.insert(*xt),
                "duplicate scancode {xt:#04x} ({code})"
            );
        }
    }

    #[test]
    fn extended_scancodes_carry_bit7_and_plain_ones_do_not() {
        for (code, xt, _) in KEYS {
            let extended = matches!(
                *code,
                "NumpadEnter"
                    | "ControlRight"
                    | "NumpadDivide"
                    | "AltRight"
                    | "Pause"
                    | "Home"
                    | "ArrowUp"
                    | "PageUp"
                    | "ArrowLeft"
                    | "ArrowRight"
                    | "End"
                    | "ArrowDown"
                    | "PageDown"
                    | "Insert"
                    | "Delete"
                    | "MetaLeft"
                    | "MetaRight"
                    | "ContextMenu"
            );
            assert_eq!(xt & 0x80 != 0, extended, "{code}");
        }
    }

    #[test]
    fn spec_pinned_scancodes() {
        // PRD/06 §2.2: PrintScreen SHOULD be 0x54, Pause MUST be 0xc6.
        assert_eq!(code_to_xt("PrintScreen"), Some(0x54));
        assert_eq!(code_to_xt("Pause"), Some(0xc6));
        assert_eq!(code_to_xt("ArrowRight"), Some(0xcd));
    }

    // -- macOS --------------------------------------------------------------

    #[test]
    fn mac_kvk_table_is_unique_and_fully_resolvable() {
        let mut seen = HashSet::new();
        for (kvk, code) in MAC_KVK {
            assert!(seen.insert(*kvk), "duplicate kVK {kvk:#04x}");
            assert!(
                code_to_xt(code).is_some(),
                "kVK {kvk:#04x} maps to unknown code {code}"
            );
        }
    }

    #[test]
    fn mac_shortcut_keys_map_correctly() {
        assert_eq!(kvk_to_xt(0x30), Some(0x0f)); // kVK_Tab
        assert_eq!(kvk_to_xt(0x31), Some(0x39)); // kVK_Space
        assert_eq!(kvk_to_xt(0x37), Some(0xdb)); // kVK_Command -> MetaLeft
        assert_eq!(kvk_to_xt(0x36), Some(0xdc)); // kVK_RightCommand
        assert_eq!(kvk_to_xt(0x0c), Some(0x10)); // kVK_ANSI_Q
        assert_eq!(kvk_to_xt(0x7e), Some(0xc8)); // kVK_UpArrow
        assert_eq!(kvk_to_xt(0x35), Some(0x01)); // kVK_Escape
    }

    #[test]
    fn mac_delete_keys_are_not_swapped() {
        // The classic macOS trap: kVK_Delete is Backspace, kVK_ForwardDelete
        // is Delete.
        assert_eq!(kvk_to_xt(0x33), code_to_xt("Backspace"));
        assert_eq!(kvk_to_xt(0x75), code_to_xt("Delete"));
    }

    #[test]
    fn mac_unmapped_keys_are_none() {
        assert_eq!(kvk_to_xt(0x3f), None); // kVK_Function
        assert_eq!(kvk_to_xt(0x4a), None); // kVK_Mute
        assert_eq!(kvk_to_xt(0x69), None); // kVK_F13, no XT equivalent here
        assert_eq!(kvk_to_xt(0xffff), None);
    }

    // -- Windows ------------------------------------------------------------

    #[test]
    fn windows_extended_flag_sets_bit7() {
        assert_eq!(windows_to_xt(0x41, 0x1e, false), Some(0x1e)); // 'A'
        assert_eq!(windows_to_xt(0xa3, 0x1d, true), Some(0x9d)); // Right Ctrl
        assert_eq!(windows_to_xt(0xa5, 0x38, true), Some(0xb8)); // Right Alt
        assert_eq!(windows_to_xt(0x5b, 0x5b, true), Some(0xdb)); // Left Win
        assert_eq!(windows_to_xt(0x26, 0x48, true), Some(0xc8)); // Up arrow
    }

    #[test]
    fn windows_ambiguous_keys_use_the_virtual_key() {
        // NumLock and Pause both report scancode 0x45.
        assert_eq!(windows_to_xt(vk::NUMLOCK, 0x45, false), Some(0x45));
        assert_eq!(windows_to_xt(vk::PAUSE, 0x45, false), Some(0xc6));
        // PrintScreen reports extended 0x37, which would collide with
        // NumpadMultiply+E0; the spec wants the plain SysRq position.
        assert_eq!(windows_to_xt(vk::SNAPSHOT, 0x37, true), Some(0x54));
    }

    #[test]
    fn windows_injected_events_without_a_scancode_are_dropped() {
        assert_eq!(windows_to_xt(0x41, 0, false), None);
    }

    #[test]
    fn every_windows_result_is_a_known_scancode() {
        for (_, xt, _) in KEYS {
            let extended = xt & 0x80 != 0;
            let scan = xt & 0x7f;
            if scan == 0 {
                continue;
            }
            // Round trip through the hook representation for the unambiguous keys.
            if matches!(*xt, 0x45 | 0xc6 | 0x54) {
                continue;
            }
            assert_eq!(windows_to_xt(0, scan, extended), Some(*xt));
        }
    }

    // -- Linux --------------------------------------------------------------

    #[test]
    fn evdev_flat_range_is_identity() {
        assert_eq!(evdev_to_xt(1), Some(0x01)); // KEY_ESC
        assert_eq!(evdev_to_xt(30), Some(0x1e)); // KEY_A
        assert_eq!(evdev_to_xt(15), Some(0x0f)); // KEY_TAB
        assert_eq!(evdev_to_xt(56), Some(0x38)); // KEY_LEFTALT
        assert_eq!(evdev_to_xt(88), Some(0x58)); // KEY_F12
    }

    #[test]
    fn evdev_extended_range_maps_to_e0_scancodes() {
        assert_eq!(evdev_to_xt(97), Some(0x9d)); // KEY_RIGHTCTRL
        assert_eq!(evdev_to_xt(100), Some(0xb8)); // KEY_RIGHTALT
        assert_eq!(evdev_to_xt(125), Some(0xdb)); // KEY_LEFTMETA
        assert_eq!(evdev_to_xt(103), Some(0xc8)); // KEY_UP
        assert_eq!(evdev_to_xt(119), Some(0xc6)); // KEY_PAUSE
    }

    #[test]
    fn evdev_unknown_codes_are_none() {
        assert_eq!(evdev_to_xt(0), None);
        assert_eq!(evdev_to_xt(84), None);
        assert_eq!(evdev_to_xt(240), None);
    }

    #[test]
    fn x11_keycodes_are_evdev_plus_eight() {
        assert_eq!(x11_keycode_to_xt(9), evdev_to_xt(1)); // Escape
        assert_eq!(x11_keycode_to_xt(38), evdev_to_xt(30)); // 'A'
        assert_eq!(x11_keycode_to_xt(133), evdev_to_xt(125)); // Super_L
        assert_eq!(x11_keycode_to_xt(4), None); // below the evdev base
    }

    // -- keysyms ------------------------------------------------------------

    #[test]
    fn keysym_lookup_is_shift_aware_for_letters_only() {
        assert_eq!(xt_to_keysym(0x1e, false), Some(0x61)); // a
        assert_eq!(xt_to_keysym(0x1e, true), Some(0x41)); // A
        assert_eq!(xt_to_keysym(0x02, false), Some(0x31)); // 1
        assert_eq!(xt_to_keysym(0x02, true), Some(0x31)); // still 1
        assert_eq!(xt_to_keysym(0xdb, true), Some(0xffeb)); // Super_L
        assert_eq!(xt_to_keysym(0x00, false), None);
    }

    #[test]
    fn modifier_classification() {
        for xt in [0x1d, 0x9d, 0x2a, 0x36, 0x38, 0xb8, 0xdb, 0xdc, 0x3a] {
            assert!(is_modifier(xt), "{xt:#04x} should be a modifier");
        }
        for xt in [0x0f, 0x39, 0x1e, 0x01] {
            assert!(!is_modifier(xt), "{xt:#04x} should not be a modifier");
        }
    }
}
