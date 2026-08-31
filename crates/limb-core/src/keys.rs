//! Typing, and the named key table.
//!
//! This module exists because of one bug, and the bug is the subtlest
//! correctness trap in the whole set (`00 R8`, `06 R6-1`, `15 §4.4`).
//!
//! A keysym is what a key PRODUCES: `0x61` is `a`, `0xff0d` is Return,
//! `0x01000000 + codepoint` is anything above Latin-1, and it is layout
//! resolved before it leaves us. A scancode is a PHYSICAL KEY POSITION: `0x1e`
//! is where `A` sits on a US keyboard, whatever that key types on the remote's
//! layout. The routing is one line,
//! `crates/vnc-core/src/session/run_loop.rs:1733`, and a server honouring QEMU
//! Extended Key Event applies its OWN keymap to the scancode and ignores the
//! keysym.
//!
//! So a model asking to type `a`, lowered to the scancode at position `0x1e`,
//! types `q` on an AZERTY remote and types `a` on a Dvorak remote only by
//! accident. The machine accepts it, the character appears, and NOTHING
//! ANYWHERE REPORTS AN ERROR. It is silent in the way that matters: the
//! agent's next observation shows a text field with characters in it, so the
//! loop proceeds and the wrong text is committed.
//!
//! That is why [`lower_type`] sends `keycode: None` and why this comment is
//! long. It is exactly the kind of thing that gets optimised later by somebody
//! who does not know, and there is no test on a developer's machine that
//! catches it, because a developer's remote is usually US layout.
//!
//! The strongest argument that keysym only is right is that it already ships.
//! `forwardText` (`ui/src/render/input.ts:964`) is this loop, and it is the
//! path dictation, IME commits and accessibility insertions already take.

use remote_core::commands::ClientCommand;

/// The named key table, and the type that names one key.
///
/// Moved to [`remote_core::keys`] and re-exported here at its old path.
/// [`IntentKind::Press`] holds `&'static NamedKey`, so the type had to travel
/// with the intent vocabulary or `ClientCommand::Agent` could not be written
/// (`00 R28`, `00 R47a`); [`NamedKey::lookup`] is an inherent method, which
/// Rust only lets live in the crate that defines the type, so the table it
/// reads travelled with it.
///
/// Everything BELOW this line stayed, and the module comment above says why it
/// matters. Lowering is a decision about how a limb behaves, `remote-core` has
/// no caller for it, and the keysym only rule is the kind of thing that gets
/// optimised away by somebody who has not read the argument.
///
/// [`IntentKind::Press`]: crate::intent::IntentKind::Press
pub use remote_core::keys::{NamedKey, NAMED_KEYS};

/// The keysym one character types.
///
/// `codePointToKeysym` (`ui/src/render/keysyms.ts:137`) is the rule for
/// everything printable: a code point below `0x100` is its own keysym, and
/// above that the Unicode keysym convention is `0x01000000 + codepoint`. This
/// mirrors it exactly rather than approximating it, because a second, slightly
/// different rule for the same characters would show up as an emoji that types
/// on one path and not the other.
///
/// Four control characters are handled first, and that is the ONE place this
/// differs from the webview's function. The webview never reaches
/// `codePointToKeysym` with a newline: Enter arrives as a `KeyboardEvent` and
/// resolves through `KEY_TO_KEYSYM`. An agent typing a two line string has no
/// `KeyboardEvent`, and `codePointToKeysym('\n')` alone would return `0x0a`,
/// which is not a keysym at all and types nothing on either protocol. So the
/// four that a string genuinely contains are mapped to the same keysyms
/// `KEY_TO_KEYSYM` gives them.
pub fn keysym_for_char(c: char) -> u32 {
    match c {
        // Both spellings of a line ending become Return. A caller pasting
        // Windows text sends "\r\n" and must not press Return twice.
        '\n' | '\r' => 0xff0d,
        '\t' => 0xff09,
        '\u{8}' => 0xff08,
        '\u{1b}' => 0xff1b,
        _ => {
            let cp = c as u32;
            if cp < 0x100 {
                cp
            } else {
                0x0100_0000 + cp
            }
        }
    }
}

/// The keysym for each code point of a string, paired with the character it
/// came from.
///
/// Returned as pairs so a caller can settle a half typed string honestly. A
/// `type` interrupted by a lease change settles as superseded with the count
/// of characters that WENT (`02 §6.2`), and a count is only truthful if the
/// sequence was consumed one code point at a time. `.chars()` is code points
/// and not UTF-16 units, so an astral character is one iteration rather than a
/// surrogate pair, which is the bug `keyEventToIds` had to fix on the webview
/// side (`ui/src/render/keysyms.ts:147`).
pub fn type_keysyms(text: &str) -> impl Iterator<Item = (char, u32)> + '_ {
    text.chars().map(|c| (c, keysym_for_char(c)))
}

/// Lower a `type` intent into the commands a driver already understands.
///
/// One press and one release per code point, `keycode: None` on every one of
/// them. Read the module comment before changing that: a scancode here types
/// what the REMOTE layout says the key is, so an agent asking for `a` types
/// `q` on an AZERTY remote and nothing anywhere reports an error.
///
/// Three consequences a naive implementation gets wrong, all from `06 §2.4`.
/// **No Shift for uppercase**: `G` is keysym `0x47`, not Shift plus `0x67`,
/// because the keysym IS the character and reaching for a modifier
/// reintroduces the layout problem for no gain. **No dead keys**: an agent
/// already knows the composed character, so it sends `0x00e9` rather than
/// composing an acute accent and then `e`. **No AltGr**: `handleAltGrPair`
/// (`ui/src/render/input.ts:985`) exists because Windows synthesises AltGr as
/// a local keyboard hook artefact, and there is no local keyboard on the agent
/// path.
///
/// The `wpm` throttle is not applied here. This function is pure and the
/// pacing needs a clock, so the plane walks the returned commands on a timer;
/// the boundary between each pair is where it may stop.
pub fn lower_type(text: &str) -> Vec<ClientCommand> {
    let mut out = Vec::with_capacity(text.chars().count() * 2);
    for (_, keysym) in type_keysyms(text) {
        out.push(ClientCommand::Key {
            keysym,
            keycode: None,
            down: true,
        });
        out.push(ClientCommand::Key {
            keysym,
            keycode: None,
            down: false,
        });
    }
    out
}

/// Lower a `press` intent into the commands a driver already understands.
///
/// Every key down in the order given, then every key up in the REVERSE order,
/// which is how a person's hand actually releases a chord: Ctrl+Alt+Del is
/// pressed outside in and released inside out, and a server that sees Ctrl
/// released before Del sees a different gesture.
///
/// Unlike [`lower_type`] this carries the scancode, and the difference is
/// argued on [`NamedKey`]. A zero scancode is passed as `None` rather than as
/// `Some(0)`, because zero is the table's "we do not know" and sending it as a
/// keycode would put a real XT scancode of 0 on the wire.
pub fn lower_press(keys: &[&'static NamedKey]) -> Vec<ClientCommand> {
    let mut out = Vec::with_capacity(keys.len() * 2);
    for key in keys {
        out.push(ClientCommand::Key {
            keysym: key.keysym,
            keycode: (key.scancode != 0).then_some(key.scancode),
            down: true,
        });
    }
    for key in keys.iter().rev() {
        out.push(ClientCommand::Key {
            keysym: key.keysym,
            keycode: (key.scancode != 0).then_some(key.scancode),
            down: false,
        });
    }
    out
}
