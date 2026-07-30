//! Browser `KeyboardEvent.code` -> XT set-1 scancode, for the QEMU Extended
//! Key Event path (PRD/06 §2.2).
//!
//! Extended (`E0`-prefixed) keys are returned with bit 7 set on the low byte
//! (`0xe0 xx` -> `0x80 | xx`), the RFB QEMU extended-key-event convention.
//! Per the spec: PrintScreen SHOULD be `0x54`, Pause MUST be `0xc6`.

/// Browser `KeyboardEvent.code` (physical key) -> XT set-1 scancode.
///
/// Returns `None` for keys with no XT scancode mapping.
pub fn code_to_xt_scancode(code: &str) -> Option<u32> {
    Some(match code {
        // -- main block (plain set-1 codes) ---------------------------------
        "Escape" => 0x01,
        "Digit1" => 0x02,
        "Digit2" => 0x03,
        "Digit3" => 0x04,
        "Digit4" => 0x05,
        "Digit5" => 0x06,
        "Digit6" => 0x07,
        "Digit7" => 0x08,
        "Digit8" => 0x09,
        "Digit9" => 0x0a,
        "Digit0" => 0x0b,
        "Minus" => 0x0c,
        "Equal" => 0x0d,
        "Backspace" => 0x0e,
        "Tab" => 0x0f,
        "KeyQ" => 0x10,
        "KeyW" => 0x11,
        "KeyE" => 0x12,
        "KeyR" => 0x13,
        "KeyT" => 0x14,
        "KeyY" => 0x15,
        "KeyU" => 0x16,
        "KeyI" => 0x17,
        "KeyO" => 0x18,
        "KeyP" => 0x19,
        "BracketLeft" => 0x1a,
        "BracketRight" => 0x1b,
        "Enter" => 0x1c,
        "ControlLeft" => 0x1d,
        "KeyA" => 0x1e,
        "KeyS" => 0x1f,
        "KeyD" => 0x20,
        "KeyF" => 0x21,
        "KeyG" => 0x22,
        "KeyH" => 0x23,
        "KeyJ" => 0x24,
        "KeyK" => 0x25,
        "KeyL" => 0x26,
        "Semicolon" => 0x27,
        "Quote" => 0x28,
        "Backquote" => 0x29,
        "ShiftLeft" => 0x2a,
        "Backslash" => 0x2b,
        "KeyZ" => 0x2c,
        "KeyX" => 0x2d,
        "KeyC" => 0x2e,
        "KeyV" => 0x2f,
        "KeyB" => 0x30,
        "KeyN" => 0x31,
        "KeyM" => 0x32,
        "Comma" => 0x33,
        "Period" => 0x34,
        "Slash" => 0x35,
        "ShiftRight" => 0x36,
        "NumpadMultiply" => 0x37,
        "AltLeft" => 0x38,
        "Space" => 0x39,
        "CapsLock" => 0x3a,
        "F1" => 0x3b,
        "F2" => 0x3c,
        "F3" => 0x3d,
        "F4" => 0x3e,
        "F5" => 0x3f,
        "F6" => 0x40,
        "F7" => 0x41,
        "F8" => 0x42,
        "F9" => 0x43,
        "F10" => 0x44,
        "NumLock" => 0x45,
        "ScrollLock" => 0x46,
        "Numpad7" => 0x47,
        "Numpad8" => 0x48,
        "Numpad9" => 0x49,
        "NumpadSubtract" => 0x4a,
        "Numpad4" => 0x4b,
        "Numpad5" => 0x4c,
        "Numpad6" => 0x4d,
        "NumpadAdd" => 0x4e,
        "Numpad1" => 0x4f,
        "Numpad2" => 0x50,
        "Numpad3" => 0x51,
        "Numpad0" => 0x52,
        "NumpadDecimal" => 0x53,
        // PrintScreen SHOULD be plain 0x54 (Alt+SysRq position) per PRD/06.
        "PrintScreen" => 0x54,
        "IntlBackslash" => 0x56, // ISO 102nd key
        "F11" => 0x57,
        "F12" => 0x58,
        "NumpadEqual" => 0x59,
        "IntlRo" => 0x73,
        "IntlYen" => 0x7d,
        "NumpadComma" => 0x7e,

        // -- extended (E0-prefixed) keys: bit 7 set -------------------------
        "NumpadEnter" => 0x9c,
        "ControlRight" => 0x9d,
        "NumpadDivide" => 0xb5,
        "AltRight" => 0xb8,
        // Pause MUST be 0xc6 per the QEMU extended-key-event spec.
        "Pause" => 0xc6,
        "Home" => 0xc7,
        "ArrowUp" => 0xc8,
        "PageUp" => 0xc9,
        "ArrowLeft" => 0xcb,
        "ArrowRight" => 0xcd,
        "End" => 0xcf,
        "ArrowDown" => 0xd0,
        "PageDown" => 0xd1,
        "Insert" => 0xd2,
        "Delete" => 0xd3,
        "MetaLeft" | "OSLeft" => 0xdb,
        "MetaRight" | "OSRight" => 0xdc,
        "ContextMenu" => 0xdd,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_block_codes() {
        assert_eq!(code_to_xt_scancode("Escape"), Some(0x01));
        assert_eq!(code_to_xt_scancode("KeyA"), Some(0x1e));
        assert_eq!(code_to_xt_scancode("KeyQ"), Some(0x10));
        assert_eq!(code_to_xt_scancode("Digit1"), Some(0x02));
        assert_eq!(code_to_xt_scancode("Digit0"), Some(0x0b));
        assert_eq!(code_to_xt_scancode("Enter"), Some(0x1c));
        assert_eq!(code_to_xt_scancode("Space"), Some(0x39));
        assert_eq!(code_to_xt_scancode("F1"), Some(0x3b));
        assert_eq!(code_to_xt_scancode("F12"), Some(0x58));
        assert_eq!(code_to_xt_scancode("PrintScreen"), Some(0x54));
    }

    #[test]
    fn extended_keys_have_bit7_set() {
        let extended = [
            ("ArrowRight", 0xcd),
            ("ArrowLeft", 0xcb),
            ("ArrowUp", 0xc8),
            ("ArrowDown", 0xd0),
            ("Insert", 0xd2),
            ("Delete", 0xd3),
            ("Home", 0xc7),
            ("End", 0xcf),
            ("PageUp", 0xc9),
            ("PageDown", 0xd1),
            ("NumpadEnter", 0x9c),
            ("ControlRight", 0x9d),
            ("AltRight", 0xb8),
            ("NumpadDivide", 0xb5),
            ("MetaLeft", 0xdb),
            ("MetaRight", 0xdc),
            ("ContextMenu", 0xdd),
            ("Pause", 0xc6),
        ];
        for (code, want) in extended {
            let got = code_to_xt_scancode(code).unwrap();
            assert_eq!(got, want, "{code}");
            assert_ne!(got & 0x80, 0, "{code} must carry the E0 marker bit");
        }
    }

    #[test]
    fn plain_keys_do_not_have_bit7() {
        for code in [
            "KeyA",
            "Enter",
            "ControlLeft",
            "AltLeft",
            "NumpadMultiply",
            "Numpad0",
        ] {
            let got = code_to_xt_scancode(code).unwrap();
            assert_eq!(got & 0x80, 0, "{code} must not carry the E0 marker bit");
        }
    }

    #[test]
    fn unknown_codes_are_none() {
        assert_eq!(code_to_xt_scancode("MediaPlayPause"), None);
        assert_eq!(code_to_xt_scancode(""), None);
    }
}
