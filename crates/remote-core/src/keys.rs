//! The named key table, and the type an agent names a physical key with.
//!
//! This is vocabulary, not policy, and it sits here for the reason
//! [`crate::intent`] does: `IntentKind::Press` and `IntentKind::Click` hold
//! `&'static NamedKey`, so the type has to be reachable from the command side
//! or `ClientCommand::Agent` cannot be written at all (`PRDAgentPlug/00 R28`,
//! `00 R47a`). [`NamedKey::lookup`] is an inherent method and Rust only lets
//! it live in the crate that defines the type, so the table it reads came with
//! it.
//!
//! What did NOT come with it is the LOWERING: `keysym_for_char`,
//! `type_keysyms`, `lower_type` and `lower_press` are still `limb_core::keys`,
//! because turning an intent into a run of `ClientCommand`s is a decision
//! about how a limb behaves and nothing in this crate calls it. Read the module
//! comment there before touching any of it; it is the keysym versus scancode
//! trap and it is the subtlest correctness bug in the set.

/// A key an agent may press by name, with both identifiers.
///
/// Both, because `Press` is for physical chords: `sendKeyCombo` used to send
/// keycode 0 for every key, so Ctrl+Alt+Del from the toolbar degraded to a
/// keysym only KeyEvent and did nothing at all on a server that only
/// understands scancodes (`ui/src/render/keysyms.ts:170`). A chord genuinely
/// is a set of key positions, so it carries positions.
///
/// That is the whole difference between [`IntentKind::Press`] and
/// [`IntentKind::Type`], and it is why they are separate intents with separate
/// vocabularies rather than one intent with a flag.
///
/// [`IntentKind::Press`]: crate::intent::IntentKind::Press
/// [`IntentKind::Type`]: crate::intent::IntentKind::Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedKey {
    /// The name an agent uses. These are the DOM `code` and `key` spellings,
    /// because those are the names the webview's own tables are keyed on and a
    /// second set of names for the same keys is how the two drift.
    pub name: &'static str,
    pub keysym: u32,
    /// XT (PC set 1) scancode for the QEMU Extended Key Event. `0` when the
    /// tree has none, which makes the session fall back to the plain keysym
    /// only KeyEvent, exactly as `KeyIds` documents
    /// (`ui/src/render/keysyms.ts:121`).
    ///
    /// The extended (grey) keys carry the `0xE0` prefix as BIT 7 of the single
    /// byte rather than as a second byte, which is why ArrowRight is `0xcd`
    /// and not `0xe04d`. Sending two bytes in a one byte field made a server
    /// that masks it see `0x4d`, which is Numpad4. The tree records that bug
    /// at `ui/src/render/keysyms.ts:99` and this table is copied from the
    /// fixed version.
    pub scancode: u32,
}

impl NamedKey {
    /// Look a key up by name, ignoring ASCII case.
    ///
    /// Case insensitive because an agent writing `escape` for `Escape` has
    /// made no meaningful error, and a refusal there teaches it nothing. No
    /// two names in the table differ only in case, which a test asserts, so
    /// the relaxation cannot make a lookup ambiguous.
    ///
    /// A name outside the table returns `None`, and the caller turns that into
    /// `UNKNOWN_KEY` before an intent is built. A numeric code outside the
    /// table is a DIFFERENT action needing `limb_core::Capability::Scancode`,
    /// which is in no bundle (`00 R30`).
    pub fn lookup(name: &str) -> Option<&'static NamedKey> {
        let name = name.trim();
        NAMED_KEYS
            .iter()
            .find(|k| k.name.eq_ignore_ascii_case(name))
    }
}

/// The fixed named key table.
///
/// Copied from `ui/src/render/keysyms.ts`, which holds the keysyms in
/// `KEY_TO_KEYSYM` and `CODE_TO_KEYSYM` and the scancodes in
/// `CODE_TO_XT_SCANCODE`. It is a copy rather than a generated artefact
/// because there is no build step between TypeScript and Rust here, and a
/// test asserts the two properties that matter: no duplicate names, and no key
/// whose keysym is zero.
///
/// It is deliberately a FIXED table with no aliases. `Control` is not a key,
/// `ControlLeft` and `ControlRight` are, and a plane that quietly resolved the
/// first to the second would be choosing a physical key on the agent's behalf
/// in the one intent whose entire purpose is to name a physical key.
pub static NAMED_KEYS: &[NamedKey] = &[
    // Editing and control, keyed by DOM `key` in the webview.
    NamedKey {
        name: "Backspace",
        keysym: 0xff08,
        scancode: 0x0e,
    },
    NamedKey {
        name: "Tab",
        keysym: 0xff09,
        scancode: 0x0f,
    },
    NamedKey {
        name: "Clear",
        keysym: 0xff0b,
        scancode: 0x00,
    },
    NamedKey {
        name: "Enter",
        keysym: 0xff0d,
        scancode: 0x1c,
    },
    NamedKey {
        name: "Pause",
        keysym: 0xff13,
        scancode: 0xc6,
    },
    NamedKey {
        name: "ScrollLock",
        keysym: 0xff14,
        scancode: 0x46,
    },
    NamedKey {
        name: "Escape",
        keysym: 0xff1b,
        scancode: 0x01,
    },
    NamedKey {
        name: "Space",
        keysym: 0x0020,
        scancode: 0x39,
    },
    NamedKey {
        name: "Delete",
        keysym: 0xffff,
        scancode: 0xd3,
    },
    NamedKey {
        name: "Home",
        keysym: 0xff50,
        scancode: 0xc7,
    },
    NamedKey {
        name: "ArrowLeft",
        keysym: 0xff51,
        scancode: 0xcb,
    },
    NamedKey {
        name: "ArrowUp",
        keysym: 0xff52,
        scancode: 0xc8,
    },
    NamedKey {
        name: "ArrowRight",
        keysym: 0xff53,
        scancode: 0xcd,
    },
    NamedKey {
        name: "ArrowDown",
        keysym: 0xff54,
        scancode: 0xd0,
    },
    NamedKey {
        name: "PageUp",
        keysym: 0xff55,
        scancode: 0xc9,
    },
    NamedKey {
        name: "PageDown",
        keysym: 0xff56,
        scancode: 0xd1,
    },
    NamedKey {
        name: "End",
        keysym: 0xff57,
        scancode: 0xcf,
    },
    NamedKey {
        name: "Insert",
        keysym: 0xff63,
        scancode: 0xd2,
    },
    NamedKey {
        name: "ContextMenu",
        keysym: 0xff67,
        scancode: 0xdd,
    },
    NamedKey {
        name: "PrintScreen",
        keysym: 0xff61,
        scancode: 0x54,
    },
    NamedKey {
        name: "NumLock",
        keysym: 0xff7f,
        scancode: 0x45,
    },
    NamedKey {
        name: "CapsLock",
        keysym: 0xffe5,
        scancode: 0x3a,
    },
    // Function keys. F13 upward have no XT scancode in the tree, so they go
    // out keysym only, which is what `KeyIds` says a zero means.
    NamedKey {
        name: "F1",
        keysym: 0xffbe,
        scancode: 0x3b,
    },
    NamedKey {
        name: "F2",
        keysym: 0xffbf,
        scancode: 0x3c,
    },
    NamedKey {
        name: "F3",
        keysym: 0xffc0,
        scancode: 0x3d,
    },
    NamedKey {
        name: "F4",
        keysym: 0xffc1,
        scancode: 0x3e,
    },
    NamedKey {
        name: "F5",
        keysym: 0xffc2,
        scancode: 0x3f,
    },
    NamedKey {
        name: "F6",
        keysym: 0xffc3,
        scancode: 0x40,
    },
    NamedKey {
        name: "F7",
        keysym: 0xffc4,
        scancode: 0x41,
    },
    NamedKey {
        name: "F8",
        keysym: 0xffc5,
        scancode: 0x42,
    },
    NamedKey {
        name: "F9",
        keysym: 0xffc6,
        scancode: 0x43,
    },
    NamedKey {
        name: "F10",
        keysym: 0xffc7,
        scancode: 0x44,
    },
    NamedKey {
        name: "F11",
        keysym: 0xffc8,
        scancode: 0x57,
    },
    NamedKey {
        name: "F12",
        keysym: 0xffc9,
        scancode: 0x58,
    },
    NamedKey {
        name: "F13",
        keysym: 0xffca,
        scancode: 0x00,
    },
    NamedKey {
        name: "F14",
        keysym: 0xffcb,
        scancode: 0x00,
    },
    NamedKey {
        name: "F15",
        keysym: 0xffcc,
        scancode: 0x00,
    },
    NamedKey {
        name: "F16",
        keysym: 0xffcd,
        scancode: 0x00,
    },
    NamedKey {
        name: "F17",
        keysym: 0xffce,
        scancode: 0x00,
    },
    NamedKey {
        name: "F18",
        keysym: 0xffcf,
        scancode: 0x00,
    },
    NamedKey {
        name: "F19",
        keysym: 0xffd0,
        scancode: 0x00,
    },
    NamedKey {
        name: "F20",
        keysym: 0xffd1,
        scancode: 0x00,
    },
    // Modifiers. Left and right are different keysyms, which is why the
    // webview keys these off `event.code` rather than `event.key`.
    NamedKey {
        name: "ShiftLeft",
        keysym: 0xffe1,
        scancode: 0x2a,
    },
    NamedKey {
        name: "ShiftRight",
        keysym: 0xffe2,
        scancode: 0x36,
    },
    NamedKey {
        name: "ControlLeft",
        keysym: 0xffe3,
        scancode: 0x1d,
    },
    NamedKey {
        name: "ControlRight",
        keysym: 0xffe4,
        scancode: 0x9d,
    },
    NamedKey {
        name: "AltLeft",
        keysym: 0xffe9,
        scancode: 0x38,
    },
    NamedKey {
        name: "AltRight",
        keysym: 0xffea,
        scancode: 0xb8,
    },
    NamedKey {
        name: "MetaLeft",
        keysym: 0xffeb,
        scancode: 0xdb,
    },
    NamedKey {
        name: "MetaRight",
        keysym: 0xffec,
        scancode: 0xdc,
    },
    // Numpad.
    NamedKey {
        name: "NumpadEnter",
        keysym: 0xff8d,
        scancode: 0x9c,
    },
    NamedKey {
        name: "NumpadMultiply",
        keysym: 0xffaa,
        scancode: 0x37,
    },
    NamedKey {
        name: "NumpadAdd",
        keysym: 0xffab,
        scancode: 0x4e,
    },
    NamedKey {
        name: "NumpadSubtract",
        keysym: 0xffad,
        scancode: 0x4a,
    },
    NamedKey {
        name: "NumpadDecimal",
        keysym: 0xffae,
        scancode: 0x53,
    },
    NamedKey {
        name: "NumpadDivide",
        keysym: 0xffaf,
        scancode: 0xb5,
    },
    NamedKey {
        name: "Numpad0",
        keysym: 0xffb0,
        scancode: 0x52,
    },
    NamedKey {
        name: "Numpad1",
        keysym: 0xffb1,
        scancode: 0x4f,
    },
    NamedKey {
        name: "Numpad2",
        keysym: 0xffb2,
        scancode: 0x50,
    },
    NamedKey {
        name: "Numpad3",
        keysym: 0xffb3,
        scancode: 0x51,
    },
    NamedKey {
        name: "Numpad4",
        keysym: 0xffb4,
        scancode: 0x4b,
    },
    NamedKey {
        name: "Numpad5",
        keysym: 0xffb5,
        scancode: 0x4c,
    },
    NamedKey {
        name: "Numpad6",
        keysym: 0xffb6,
        scancode: 0x4d,
    },
    NamedKey {
        name: "Numpad7",
        keysym: 0xffb7,
        scancode: 0x47,
    },
    NamedKey {
        name: "Numpad8",
        keysym: 0xffb8,
        scancode: 0x48,
    },
    NamedKey {
        name: "Numpad9",
        keysym: 0xffb9,
        scancode: 0x49,
    },
];
