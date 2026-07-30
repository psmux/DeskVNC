//! Input mapping and wire encoding: keysyms, XT scancodes, pointer events,
//! and pressed-key tracking (PRD/06).
//!
//! All encoders here are pure functions producing complete client-to-server
//! RFB messages (message type byte included), big-endian.

mod keysym;
mod scancode;

pub use keysym::*;
pub use scancode::code_to_xt_scancode;

/// Pointer button-mask bits (PRD/06 §1.1). The base wire mask is a u8; bits
/// 8/9 are our extension carrying Back/Forward for the ExtendedMouseButtons
/// pseudo-encoding (−316).
pub mod buttons {
    pub const LEFT: u16 = 1 << 0;
    pub const MIDDLE: u16 = 1 << 1;
    pub const RIGHT: u16 = 1 << 2;
    pub const WHEEL_UP: u16 = 1 << 3;
    pub const WHEEL_DOWN: u16 = 1 << 4;
    pub const WHEEL_LEFT: u16 = 1 << 5;
    pub const WHEEL_RIGHT: u16 = 1 << 6;
    /// Bit 7 is the legacy Back button, reused as the extended-message marker
    /// once ExtendedMouseButtons has been negotiated.
    pub const LEGACY_BACK: u16 = 1 << 7;
    /// Back, when using [`crate::input::encode_extended_pointer_event`].
    pub const BACK: u16 = 1 << 8;
    /// Forward, when using [`crate::input::encode_extended_pointer_event`].
    pub const FORWARD: u16 = 1 << 9;
}

/// KeyEvent (message 4): `[4, down, pad, pad, keysym:u32]`.
pub fn encode_key_event(keysym: u32, down: bool) -> [u8; 8] {
    let k = keysym.to_be_bytes();
    [4, down as u8, 0, 0, k[0], k[1], k[2], k[3]]
}

/// PointerEvent (message 5): `[5, mask:u8, x:u16, y:u16]`.
///
/// The standard wire mask is a u8; we accept a u16 so callers can hold
/// extended-button state in one value, but only the low byte is written here.
/// Use [`encode_extended_pointer_event`] once ExtendedMouseButtons (−316) has
/// been negotiated and Back/Forward are involved.
pub fn encode_pointer_event(x: u16, y: u16, mask: u16) -> [u8; 6] {
    let xb = x.to_be_bytes();
    let yb = y.to_be_bytes();
    [5, (mask & 0xff) as u8, xb[0], xb[1], yb[0], yb[1]]
}

/// Extended PointerEvent for ExtendedMouseButtons (−316): bit 7 of the wire
/// mask is set as the extension marker and one extra byte follows
/// (bit 0 = Back, bit 1 = Forward), taken from mask bits 8/9.
pub fn encode_extended_pointer_event(x: u16, y: u16, mask: u16) -> Vec<u8> {
    let xb = x.to_be_bytes();
    let yb = y.to_be_bytes();
    let low = ((mask & 0x7f) as u8) | 0x80;
    let extra = ((mask >> 8) & 0x03) as u8;
    vec![5, low, xb[0], xb[1], yb[0], yb[1], extra]
}

/// QEMU Extended Key Event (message 255, submessage 0):
/// `[255, 0, down:u16, keysym:u32, keycode:u32]` where keycode is an XT set-1
/// scancode (see [`code_to_xt_scancode`]).
pub fn encode_qemu_key_event(keysym: u32, keycode: u32, down: bool) -> [u8; 12] {
    let d = (down as u16).to_be_bytes();
    let k = keysym.to_be_bytes();
    let c = keycode.to_be_bytes();
    [
        255, 0, d[0], d[1], k[0], k[1], k[2], k[3], c[0], c[1], c[2], c[3],
    ]
}

/// Unicode codepoint -> keysym.
///
/// ASCII printable and Latin-1 high range map directly (keysym == codepoint);
/// a handful of control characters map to their TTY keysyms; everything else
/// uses the `0x01000000 + codepoint` rule (PRD/06 §2.1).
pub fn char_to_keysym(c: char) -> u32 {
    let cp = c as u32;
    match cp {
        0x20..=0x7e | 0xa0..=0xff => cp,
        0x08 => XK_BACKSPACE,
        0x09 => XK_TAB,
        0x0a | 0x0d => XK_RETURN,
        0x1b => XK_ESCAPE,
        0x7f => XK_DELETE,
        _ => UNICODE_KEYSYM_OFFSET + cp,
    }
}

/// Tracks keysyms we believe are currently held down on the server, so we can
/// release everything on blur/disconnect (the stuck-modifier fix, PRD/06 §2.1).
#[derive(Debug, Default)]
pub struct PressedKeys {
    /// Insertion-ordered; no duplicates.
    keys: Vec<u32>,
}

impl PressedKeys {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Record a key-down. Idempotent (client-side auto-repeat sends repeated
    /// downs).
    pub fn press(&mut self, keysym: u32) {
        if !self.keys.contains(&keysym) {
            self.keys.push(keysym);
        }
    }

    /// Record a key-up.
    pub fn release(&mut self, keysym: u32) {
        self.keys.retain(|&k| k != keysym);
    }

    /// Remove and return every held key, most-recently-pressed first, so
    /// chords unwind in reverse order (character before modifier).
    pub fn drain_all(&mut self) -> Vec<u32> {
        let mut out = std::mem::take(&mut self.keys);
        out.reverse();
        out
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_event_layout() {
        // 'a' down
        assert_eq!(encode_key_event(0x61, true), [4, 1, 0, 0, 0, 0, 0, 0x61]);
        // Left arrow up
        assert_eq!(
            encode_key_event(0xff51, false),
            [4, 0, 0, 0, 0, 0, 0xff, 0x51]
        );
        // Unicode keysym round-trips all four bytes
        assert_eq!(
            encode_key_event(0x0101_f600, true),
            [4, 1, 0, 0, 0x01, 0x01, 0xf6, 0x00]
        );
    }

    #[test]
    fn pointer_event_layout() {
        assert_eq!(
            encode_pointer_event(0x1234, 0x0203, buttons::LEFT),
            [5, 0x01, 0x12, 0x34, 0x02, 0x03]
        );
        // Only the low byte of the mask is written in the base message.
        assert_eq!(encode_pointer_event(0, 0, 0x0101), [5, 0x01, 0, 0, 0, 0]);
        assert_eq!(encode_pointer_event(0, 0, 0), [5, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn extended_pointer_event_sets_marker_and_extra_byte() {
        let msg = encode_extended_pointer_event(1, 2, buttons::LEFT | buttons::BACK);
        assert_eq!(msg, vec![5, 0x81, 0, 1, 0, 2, 0x01]);
        let msg = encode_extended_pointer_event(0, 0, buttons::FORWARD);
        assert_eq!(msg, vec![5, 0x80, 0, 0, 0, 0, 0x02]);
        // Legacy bit 7 in the input never leaks through as a button.
        let msg = encode_extended_pointer_event(0, 0, buttons::LEGACY_BACK);
        assert_eq!(msg[1], 0x80);
        assert_eq!(msg[6], 0x00);
    }

    #[test]
    fn qemu_key_event_layout() {
        // AltRight down: keysym Alt_R, XT scancode 0xb8 (E0-extended).
        assert_eq!(
            encode_qemu_key_event(0xffea, 0xb8, true),
            [255, 0, 0, 1, 0, 0, 0xff, 0xea, 0, 0, 0, 0xb8]
        );
        assert_eq!(
            encode_qemu_key_event(0x61, 0x1e, false),
            [255, 0, 0, 0, 0, 0, 0, 0x61, 0, 0, 0, 0x1e]
        );
    }

    #[test]
    fn char_to_keysym_rules() {
        assert_eq!(char_to_keysym('a'), 0x61);
        assert_eq!(char_to_keysym('A'), 0x41);
        assert_eq!(char_to_keysym(' '), 0x20);
        assert_eq!(char_to_keysym('é'), 0xe9); // Latin-1 direct
        assert_eq!(char_to_keysym('€'), 0x0100_20ac); // Unicode rule
        assert_eq!(char_to_keysym('😀'), 0x0101_f600);
        assert_eq!(char_to_keysym('\n'), 0xff0d);
        assert_eq!(char_to_keysym('\t'), 0xff09);
    }

    #[test]
    fn pressed_keys_tracking() {
        let mut pk = PressedKeys::new();
        assert!(pk.is_empty());
        pk.press(XK_CONTROL_L);
        pk.press(0x61);
        pk.press(0x61); // auto-repeat: no duplicate
        assert!(!pk.is_empty());
        pk.release(0x61);
        pk.press(0x63);
        // Release-all unwinds most-recent first.
        assert_eq!(pk.drain_all(), vec![0x63, XK_CONTROL_L]);
        assert!(pk.is_empty());
        assert_eq!(pk.drain_all(), Vec::<u32>::new());
    }
}
