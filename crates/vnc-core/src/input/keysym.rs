//! X11 keysym constants and the browser `KeyboardEvent.code` -> keysym table.
//!
//! Mapping policy (PRD/06 §2.1): we map the *physical* key (`code`) to a
//! keysym using a US-layout base, shift-aware for the printable keys. Case is
//! significant on the wire, shifted `a` is sent as `A` (0x41) and the server
//! fakes Shift as needed.

// ---------------------------------------------------------------------------
// Keysym constants (TTY / motion / function / modifier groups)
// ---------------------------------------------------------------------------

pub const XK_SPACE: u32 = 0x20;

pub const XK_BACKSPACE: u32 = 0xff08;
pub const XK_TAB: u32 = 0xff09;
pub const XK_RETURN: u32 = 0xff0d;
pub const XK_PAUSE: u32 = 0xff13;
pub const XK_SCROLL_LOCK: u32 = 0xff14;
pub const XK_ESCAPE: u32 = 0xff1b;

pub const XK_HOME: u32 = 0xff50;
pub const XK_LEFT: u32 = 0xff51;
pub const XK_UP: u32 = 0xff52;
pub const XK_RIGHT: u32 = 0xff53;
pub const XK_DOWN: u32 = 0xff54;
pub const XK_PAGE_UP: u32 = 0xff55;
pub const XK_PAGE_DOWN: u32 = 0xff56;
pub const XK_END: u32 = 0xff57;

pub const XK_PRINT: u32 = 0xff61;
pub const XK_INSERT: u32 = 0xff63;
pub const XK_MENU: u32 = 0xff67;
pub const XK_NUM_LOCK: u32 = 0xff7f;

pub const XK_KP_ENTER: u32 = 0xff8d;
pub const XK_KP_MULTIPLY: u32 = 0xffaa;
pub const XK_KP_ADD: u32 = 0xffab;
pub const XK_KP_SEPARATOR: u32 = 0xffac;
pub const XK_KP_SUBTRACT: u32 = 0xffad;
pub const XK_KP_DECIMAL: u32 = 0xffae;
pub const XK_KP_DIVIDE: u32 = 0xffaf;
pub const XK_KP_0: u32 = 0xffb0;
pub const XK_KP_EQUAL: u32 = 0xffbd;

/// F1. F2..F24 are consecutive (`XK_F1 + n - 1`).
pub const XK_F1: u32 = 0xffbe;

pub const XK_SHIFT_L: u32 = 0xffe1;
pub const XK_SHIFT_R: u32 = 0xffe2;
pub const XK_CONTROL_L: u32 = 0xffe3;
pub const XK_CONTROL_R: u32 = 0xffe4;
pub const XK_CAPS_LOCK: u32 = 0xffe5;
pub const XK_META_L: u32 = 0xffe7;
pub const XK_META_R: u32 = 0xffe8;
pub const XK_ALT_L: u32 = 0xffe9;
pub const XK_ALT_R: u32 = 0xffea;
pub const XK_SUPER_L: u32 = 0xffeb;
pub const XK_SUPER_R: u32 = 0xffec;

pub const XK_DELETE: u32 = 0xffff;

/// Offset added to a Unicode codepoint that has no legacy keysym.
pub const UNICODE_KEYSYM_OFFSET: u32 = 0x0100_0000;

#[inline]
fn sel(shift: bool, base: u32, shifted: u32) -> u32 {
    if shift {
        shifted
    } else {
        base
    }
}

/// Browser `KeyboardEvent.code` (physical key) -> X11 keysym.
///
/// `shift` selects the shifted variant for printable keys (US layout base).
/// Returns `None` for codes we do not map (media keys, IME keys, `Fn`, …).
pub fn code_to_keysym(code: &str, shift: bool) -> Option<u32> {
    // F1..F24
    if let Some(n) = code.strip_prefix('F').and_then(|s| s.parse::<u32>().ok()) {
        if (1..=24).contains(&n) {
            return Some(XK_F1 + n - 1);
        }
        return None;
    }

    // Letters: KeyA..KeyZ, lowercase base, uppercase when shifted.
    if let Some(rest) = code.strip_prefix("Key") {
        let b = rest.as_bytes();
        if b.len() == 1 && b[0].is_ascii_uppercase() {
            return Some(if shift {
                b[0] as u32
            } else {
                b[0] as u32 + 0x20
            });
        }
        return None;
    }

    Some(match code {
        // Digit row (US layout shifted symbols)
        "Digit1" => sel(shift, 0x31, 0x21), // 1 !
        "Digit2" => sel(shift, 0x32, 0x40), // 2 @
        "Digit3" => sel(shift, 0x33, 0x23), // 3 #
        "Digit4" => sel(shift, 0x34, 0x24), // 4 $
        "Digit5" => sel(shift, 0x35, 0x25), // 5 %
        "Digit6" => sel(shift, 0x36, 0x5e), // 6 ^
        "Digit7" => sel(shift, 0x37, 0x26), // 7 &
        "Digit8" => sel(shift, 0x38, 0x2a), // 8 *
        "Digit9" => sel(shift, 0x39, 0x28), // 9 (
        "Digit0" => sel(shift, 0x30, 0x29), // 0 )

        // Punctuation (US layout)
        "Minus" => sel(shift, 0x2d, 0x5f),         // - _
        "Equal" => sel(shift, 0x3d, 0x2b),         // = +
        "BracketLeft" => sel(shift, 0x5b, 0x7b),   // [ {
        "BracketRight" => sel(shift, 0x5d, 0x7d),  // ] }
        "Backslash" => sel(shift, 0x5c, 0x7c),     // \ |
        "Semicolon" => sel(shift, 0x3b, 0x3a),     // ; :
        "Quote" => sel(shift, 0x27, 0x22),         // ' "
        "Backquote" => sel(shift, 0x60, 0x7e),     // ` ~
        "Comma" => sel(shift, 0x2c, 0x3c),         // , <
        "Period" => sel(shift, 0x2e, 0x3e),        // . >
        "Slash" => sel(shift, 0x2f, 0x3f),         // / ?
        "IntlBackslash" => sel(shift, 0x3c, 0x3e), // ISO key: < >
        "IntlRo" => sel(shift, 0x5c, 0x5f),        // JIS Ro: \ _
        "IntlYen" => sel(shift, 0xa5, 0x7c),       // JIS Yen: ¥ |
        "Space" => XK_SPACE,

        // Editing / whitespace
        "Enter" => XK_RETURN,
        "Tab" => XK_TAB,
        "Backspace" => XK_BACKSPACE,
        "Escape" => XK_ESCAPE,
        "Insert" => XK_INSERT,
        "Delete" => XK_DELETE,

        // Motion
        "Home" => XK_HOME,
        "End" => XK_END,
        "PageUp" => XK_PAGE_UP,
        "PageDown" => XK_PAGE_DOWN,
        "ArrowLeft" => XK_LEFT,
        "ArrowUp" => XK_UP,
        "ArrowRight" => XK_RIGHT,
        "ArrowDown" => XK_DOWN,

        // Modifiers. Meta/OS is sent as Super, macOS servers accept both
        // Super and Meta for Command (PRD/06 §4).
        "ShiftLeft" => XK_SHIFT_L,
        "ShiftRight" => XK_SHIFT_R,
        "ControlLeft" => XK_CONTROL_L,
        "ControlRight" => XK_CONTROL_R,
        "AltLeft" => XK_ALT_L,
        "AltRight" => XK_ALT_R,
        "MetaLeft" | "OSLeft" => XK_SUPER_L,
        "MetaRight" | "OSRight" => XK_SUPER_R,

        // Locks and system keys
        "CapsLock" => XK_CAPS_LOCK,
        "NumLock" => XK_NUM_LOCK,
        "ScrollLock" => XK_SCROLL_LOCK,
        "PrintScreen" => XK_PRINT,
        "Pause" => XK_PAUSE,
        "ContextMenu" => XK_MENU,

        // Numpad
        "Numpad0" => XK_KP_0,
        "Numpad1" => XK_KP_0 + 1,
        "Numpad2" => XK_KP_0 + 2,
        "Numpad3" => XK_KP_0 + 3,
        "Numpad4" => XK_KP_0 + 4,
        "Numpad5" => XK_KP_0 + 5,
        "Numpad6" => XK_KP_0 + 6,
        "Numpad7" => XK_KP_0 + 7,
        "Numpad8" => XK_KP_0 + 8,
        "Numpad9" => XK_KP_0 + 9,
        "NumpadDecimal" => XK_KP_DECIMAL,
        "NumpadDivide" => XK_KP_DIVIDE,
        "NumpadMultiply" => XK_KP_MULTIPLY,
        "NumpadSubtract" => XK_KP_SUBTRACT,
        "NumpadAdd" => XK_KP_ADD,
        "NumpadEnter" => XK_KP_ENTER,
        "NumpadEqual" => XK_KP_EQUAL,
        "NumpadComma" => XK_KP_SEPARATOR,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_are_shift_aware() {
        assert_eq!(code_to_keysym("KeyA", false), Some(0x61)); // 'a'
        assert_eq!(code_to_keysym("KeyA", true), Some(0x41)); // 'A'
        assert_eq!(code_to_keysym("KeyZ", false), Some(0x7a));
        assert_eq!(code_to_keysym("KeyZ", true), Some(0x5a));
    }

    #[test]
    fn digits_and_shifted_symbols() {
        assert_eq!(code_to_keysym("Digit1", false), Some(0x31)); // '1'
        assert_eq!(code_to_keysym("Digit1", true), Some(0x21)); // '!'
        assert_eq!(code_to_keysym("Digit2", true), Some(0x40)); // '@'
        assert_eq!(code_to_keysym("Digit0", true), Some(0x29)); // ')'
        assert_eq!(code_to_keysym("Minus", true), Some(0x5f)); // '_'
        assert_eq!(code_to_keysym("Slash", true), Some(0x3f)); // '?'
    }

    #[test]
    fn arrows() {
        assert_eq!(code_to_keysym("ArrowLeft", false), Some(0xff51));
        assert_eq!(code_to_keysym("ArrowUp", false), Some(0xff52));
        assert_eq!(code_to_keysym("ArrowRight", false), Some(0xff53));
        assert_eq!(code_to_keysym("ArrowDown", false), Some(0xff54));
    }

    #[test]
    fn modifiers() {
        assert_eq!(code_to_keysym("ShiftLeft", false), Some(0xffe1));
        assert_eq!(code_to_keysym("ShiftRight", false), Some(0xffe2));
        assert_eq!(code_to_keysym("ControlLeft", false), Some(0xffe3));
        assert_eq!(code_to_keysym("ControlRight", false), Some(0xffe4));
        assert_eq!(code_to_keysym("AltLeft", false), Some(0xffe9));
        assert_eq!(code_to_keysym("AltRight", false), Some(0xffea));
        assert_eq!(code_to_keysym("MetaLeft", false), Some(0xffeb));
        assert_eq!(code_to_keysym("MetaRight", false), Some(0xffec));
        assert_eq!(code_to_keysym("CapsLock", false), Some(0xffe5));
    }

    #[test]
    fn function_keys() {
        assert_eq!(code_to_keysym("F1", false), Some(0xffbe));
        assert_eq!(code_to_keysym("F12", false), Some(0xffc9));
        assert_eq!(code_to_keysym("F24", false), Some(0xffd5));
        assert_eq!(code_to_keysym("F25", false), None);
        assert_eq!(code_to_keysym("F0", false), None);
    }

    #[test]
    fn navigation_and_editing() {
        assert_eq!(code_to_keysym("Home", false), Some(0xff50));
        assert_eq!(code_to_keysym("End", false), Some(0xff57));
        assert_eq!(code_to_keysym("PageUp", false), Some(0xff55));
        assert_eq!(code_to_keysym("PageDown", false), Some(0xff56));
        assert_eq!(code_to_keysym("Insert", false), Some(0xff63));
        assert_eq!(code_to_keysym("Delete", false), Some(0xffff));
        assert_eq!(code_to_keysym("Enter", false), Some(0xff0d));
        assert_eq!(code_to_keysym("Tab", true), Some(0xff09)); // shifted Tab is still Tab
        assert_eq!(code_to_keysym("Escape", false), Some(0xff1b));
        assert_eq!(code_to_keysym("Backspace", false), Some(0xff08));
        assert_eq!(code_to_keysym("Space", false), Some(0x20));
    }

    #[test]
    fn numpad() {
        assert_eq!(code_to_keysym("Numpad0", false), Some(0xffb0));
        assert_eq!(code_to_keysym("Numpad9", false), Some(0xffb9));
        assert_eq!(code_to_keysym("NumpadEnter", false), Some(0xff8d));
        assert_eq!(code_to_keysym("NumpadAdd", false), Some(0xffab));
        assert_eq!(code_to_keysym("NumpadDivide", false), Some(0xffaf));
        assert_eq!(code_to_keysym("NumpadDecimal", false), Some(0xffae));
    }

    #[test]
    fn unknown_codes_are_none() {
        assert_eq!(code_to_keysym("MediaPlayPause", false), None);
        assert_eq!(code_to_keysym("", false), None);
        assert_eq!(code_to_keysym("KeyAA", false), None);
    }
}
