//! Drift guard: every scancode and keysym this crate can emit must be exactly
//! what `vnc-core` would have produced for the same physical key.
//!
//! `vnc-input-capture` deliberately does not depend on `vnc-core` (see the note
//! in its `Cargo.toml`, it has to cross-compile to Windows/Linux from a macOS
//! host). That means the `(code, XT, keysym)` triples exist in two places, so
//! this test exists to make sure the copies can never disagree in silence. It
//! is a dev-dependency-only integration test, so it never affects the
//! cross-target `cargo check`.

use vnc_core::input::{code_to_keysym, code_to_xt_scancode};
use vnc_input_capture as capture;

#[test]
fn every_scancode_matches_vnc_core() {
    for (code, xt, _) in capture::KEYS {
        assert_eq!(
            code_to_xt_scancode(code),
            Some(*xt),
            "scancode for {code} disagrees with vnc-core"
        );
    }
}

#[test]
fn every_keysym_matches_vnc_core_unshifted() {
    for (code, _, keysym) in capture::KEYS {
        assert_eq!(
            code_to_keysym(code, false),
            Some(*keysym),
            "keysym for {code} disagrees with vnc-core"
        );
    }
}

#[test]
fn shifted_letters_match_vnc_core() {
    for (code, xt, _) in capture::KEYS {
        if !code.starts_with("Key") {
            continue;
        }
        assert_eq!(
            capture::xt_to_keysym(*xt, true),
            code_to_keysym(code, true),
            "shifted keysym for {code} disagrees with vnc-core"
        );
    }
}

#[test]
fn the_capture_table_covers_every_key_vnc_core_knows() {
    // vnc-core's table is the superset of record; if it grows a key this crate
    // cannot express, capture would silently pass that key through to the local
    // machine instead of the remote. Enumerate the codes vnc-core maps and
    // require this crate to map them too.
    let known: Vec<&str> = ALL_CODES
        .iter()
        .copied()
        .filter(|c| code_to_xt_scancode(c).is_some())
        .collect();
    for code in known {
        assert!(
            capture::code_to_xt(code).is_some(),
            "vnc-core maps {code} but vnc-input-capture does not"
        );
    }
}

#[test]
fn macos_virtual_keycodes_resolve_through_vnc_core() {
    for (kvk, code) in capture::MAC_KVK {
        assert_eq!(
            capture::kvk_to_xt(*kvk),
            code_to_xt_scancode(code),
            "kVK {kvk:#04x} ({code}) disagrees with vnc-core"
        );
    }
}

/// Every `KeyboardEvent.code` the UI can produce, from `vnc-core`'s scancode
/// table plus the aliases it accepts. Kept here rather than exported so the
/// production crates stay free of test scaffolding.
const ALL_CODES: &[&str] = &[
    "Escape",
    "Digit1",
    "Digit2",
    "Digit3",
    "Digit4",
    "Digit5",
    "Digit6",
    "Digit7",
    "Digit8",
    "Digit9",
    "Digit0",
    "Minus",
    "Equal",
    "Backspace",
    "Tab",
    "KeyQ",
    "KeyW",
    "KeyE",
    "KeyR",
    "KeyT",
    "KeyY",
    "KeyU",
    "KeyI",
    "KeyO",
    "KeyP",
    "BracketLeft",
    "BracketRight",
    "Enter",
    "ControlLeft",
    "KeyA",
    "KeyS",
    "KeyD",
    "KeyF",
    "KeyG",
    "KeyH",
    "KeyJ",
    "KeyK",
    "KeyL",
    "Semicolon",
    "Quote",
    "Backquote",
    "ShiftLeft",
    "Backslash",
    "KeyZ",
    "KeyX",
    "KeyC",
    "KeyV",
    "KeyB",
    "KeyN",
    "KeyM",
    "Comma",
    "Period",
    "Slash",
    "ShiftRight",
    "NumpadMultiply",
    "AltLeft",
    "Space",
    "CapsLock",
    "F1",
    "F2",
    "F3",
    "F4",
    "F5",
    "F6",
    "F7",
    "F8",
    "F9",
    "F10",
    "NumLock",
    "ScrollLock",
    "Numpad7",
    "Numpad8",
    "Numpad9",
    "NumpadSubtract",
    "Numpad4",
    "Numpad5",
    "Numpad6",
    "NumpadAdd",
    "Numpad1",
    "Numpad2",
    "Numpad3",
    "Numpad0",
    "NumpadDecimal",
    "PrintScreen",
    "IntlBackslash",
    "F11",
    "F12",
    "NumpadEqual",
    "IntlRo",
    "IntlYen",
    "NumpadComma",
    "NumpadEnter",
    "ControlRight",
    "NumpadDivide",
    "AltRight",
    "Pause",
    "Home",
    "ArrowUp",
    "PageUp",
    "ArrowLeft",
    "ArrowRight",
    "End",
    "ArrowDown",
    "PageDown",
    "Insert",
    "Delete",
    "MetaLeft",
    "MetaRight",
    "ContextMenu",
];
