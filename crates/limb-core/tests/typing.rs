//! Typing is keysyms and never a scancode (`00 R8`).
//!
//! This is the test that stands between the product and its worst silent
//! failure. A scancode types what the REMOTE layout says that key is, so an
//! agent asking for `a` types `q` on an AZERTY remote. The machine accepts it,
//! the character appears, nothing anywhere reports an error, and the agent's
//! next observation shows a text field with characters in it, so the loop
//! proceeds and the wrong text is committed.
//!
//! No developer's machine catches this, because a developer's remote is
//! usually US layout, which is exactly why it is asserted here rather than
//! left to a review.

use limb_core::{keysym_for_char, lower_press, lower_type, ClientCommand, NamedKey, NAMED_KEYS};

/// Pull `(keysym, keycode, down)` out, and fail on anything that is not a key
/// event at all.
fn keys(commands: &[ClientCommand]) -> Vec<(u32, Option<u32>, bool)> {
    commands
        .iter()
        .map(|c| match c {
            ClientCommand::Key {
                keysym,
                keycode,
                down,
            } => (*keysym, *keycode, *down),
            other => panic!("typing produced {other:?}, which is not a key event"),
        })
        .collect()
}

#[test]
fn typing_never_puts_a_scancode_on_the_wire() {
    // Deliberately a string with a capital, an accent, a digit and a symbol in
    // it, because each of those is a place somebody might reach for a modifier
    // or a physical key.
    let commands = lower_type("Hé9!");
    for (keysym, keycode, _) in keys(&commands) {
        assert_eq!(
            keycode, None,
            "keysym {keysym:#x} went out with a scancode; read the module comment on keys.rs"
        );
    }
}

#[test]
fn every_code_point_is_one_press_and_one_release_in_order() {
    let commands = lower_type("ab");
    let events = keys(&commands);
    assert_eq!(
        events,
        vec![
            (0x61, None, true),
            (0x61, None, false),
            (0x62, None, true),
            (0x62, None, false),
        ]
    );
}

#[test]
fn an_uppercase_letter_is_its_own_keysym_and_not_shift_plus_a_lowercase_one() {
    // `G` is keysym 0x47. Synthesising Shift plus 0x67 would reintroduce the
    // layout problem for no gain: the keysym IS the character (`06 §2.4`).
    let events = keys(&lower_type("G"));
    assert_eq!(events, vec![(0x47, None, true), (0x47, None, false)]);
    assert_eq!(events.len(), 2, "no modifier was synthesised");
}

#[test]
fn the_keysym_rule_matches_the_one_the_webview_already_ships() {
    // `codePointToKeysym` (ui/src/render/keysyms.ts:137): below 0x100 a code
    // point is its own keysym, above it the Unicode keysym convention is
    // 0x01000000 + the code point. A second, slightly different rule for the
    // same characters shows up as an emoji that types on one path and not the
    // other.
    assert_eq!(keysym_for_char('a'), 0x61);
    assert_eq!(keysym_for_char(' '), 0x20);
    assert_eq!(keysym_for_char('é'), 0xe9);
    assert_eq!(keysym_for_char('ÿ'), 0xff);
    assert_eq!(keysym_for_char('Ā'), 0x0100_0000 + 0x100);
    assert_eq!(keysym_for_char('€'), 0x0100_0000 + 0x20ac);
    // An astral character is one code point and not a surrogate pair, which is
    // the bug `keyEventToIds` had to fix on the webview side.
    assert_eq!(keysym_for_char('😀'), 0x0100_0000 + 0x1_f600);
    assert_eq!(lower_type("😀").len(), 2);
}

#[test]
fn the_four_control_characters_a_string_can_contain_become_real_keysyms() {
    // `codePointToKeysym('\n')` alone returns 0x0a, which is not a keysym and
    // types nothing on either protocol. An agent typing a two line string has
    // no KeyboardEvent to resolve Enter through, so this is the one place the
    // rule differs from the webview's and it differs deliberately.
    assert_eq!(keysym_for_char('\n'), 0xff0d);
    assert_eq!(keysym_for_char('\r'), 0xff0d);
    assert_eq!(keysym_for_char('\t'), 0xff09);
    assert_eq!(keysym_for_char('\u{8}'), 0xff08);
    assert_eq!(keysym_for_char('\u{1b}'), 0xff1b);

    // A caller pasting Windows text must not press Return twice.
    let events = keys(&lower_type("\r\n"));
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|(keysym, ..)| *keysym == 0xff0d));
}

#[test]
fn a_named_key_press_carries_both_identifiers_and_releases_the_chord_backwards() {
    let ctrl = NamedKey::lookup("ControlLeft").unwrap();
    let alt = NamedKey::lookup("AltLeft").unwrap();
    let del = NamedKey::lookup("Delete").unwrap();

    let events = keys(&lower_press(&[ctrl, alt, del]));
    assert_eq!(
        events,
        vec![
            // Down, outside in.
            (0xffe3, Some(0x1d), true),
            (0xffe9, Some(0x38), true),
            (0xffff, Some(0xd3), true),
            // Up, inside out, the way a hand actually releases a chord. A
            // server that sees Ctrl released before Del sees a different
            // gesture.
            (0xffff, Some(0xd3), false),
            (0xffe9, Some(0x38), false),
            (0xffe3, Some(0x1d), false),
        ]
    );
}

#[test]
fn a_key_with_no_scancode_goes_out_keysym_only_rather_than_with_a_zero() {
    // Zero is the table's "we do not know", and sending it as a keycode would
    // put a real XT scancode of 0 on the wire (`ui/src/render/keysyms.ts:121`).
    let f13 = NamedKey::lookup("F13").unwrap();
    assert_eq!(f13.scancode, 0);
    for (_, keycode, _) in keys(&lower_press(&[f13])) {
        assert_eq!(keycode, None);
    }
}

#[test]
fn the_named_key_table_is_unambiguous() {
    for key in NAMED_KEYS {
        assert_ne!(key.keysym, 0, "{} has no keysym", key.name);
        let matches = NAMED_KEYS
            .iter()
            .filter(|other| other.name.eq_ignore_ascii_case(key.name))
            .count();
        assert_eq!(
            matches, 1,
            "{} appears more than once, so a case insensitive lookup is ambiguous",
            key.name
        );
    }
}

#[test]
fn a_key_name_outside_the_table_is_refused_rather_than_guessed_at() {
    assert!(NamedKey::lookup("escape").is_some(), "case is forgiven");
    assert!(NamedKey::lookup("  Escape ").is_some(), "so is whitespace");

    // `Control` is not a key. `ControlLeft` and `ControlRight` are, and a
    // plane that quietly resolved the first to the second would be choosing a
    // physical key on the agent's behalf in the one intent whose entire
    // purpose is to name a physical key.
    assert!(NamedKey::lookup("Control").is_none());
    assert!(NamedKey::lookup("Any").is_none());
    assert!(NamedKey::lookup("0x1e").is_none());
}
