//! The phone keyboard and the key bar, as `ClientCommand`s.
//!
//! Both are lowered by `limb_core::keys`, the code the agent plane already
//! types and presses chords with, so a phone and an agent cannot disagree on
//! what a character or a chord sends. Read that module's comment before
//! changing anything here: text goes as keysyms with no scancode, so what
//! the phone typed is what appears whatever the remote keyboard layout is,
//! and a chord goes as physical keys with scancodes, because a chord is a set
//! of key positions.

use remote_core::keys::NamedKey;
use remote_core::ClientCommand;
use serde::Deserialize;

/// `KeyCombo` in `contract.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyCombo {
    CtrlAltDel,
    Win,
    AltTab,
    CmdTab,
    CtrlC,
    CtrlV,
    Esc,
}

impl KeyCombo {
    /// The keys of the chord, outside in, as `NamedKey` names.
    pub fn key_names(self) -> &'static [&'static str] {
        match self {
            KeyCombo::CtrlAltDel => &["ControlLeft", "AltLeft", "Delete"],
            KeyCombo::Win => &["MetaLeft"],
            KeyCombo::AltTab => &["AltLeft", "Tab"],
            // Command is the Meta key to a VNC server on a Mac.
            KeyCombo::CmdTab => &["MetaLeft", "Tab"],
            KeyCombo::CtrlC => &["ControlLeft", "KeyC"],
            KeyCombo::CtrlV => &["ControlLeft", "KeyV"],
            KeyCombo::Esc => &["Escape"],
        }
    }
}

/// The commands for one chord: every key down in order, then every key up
/// in reverse, with scancodes.
pub fn combo_commands(combo: KeyCombo) -> Result<Vec<ClientCommand>, String> {
    let keys: Vec<&'static NamedKey> = combo
        .key_names()
        .iter()
        .map(|name| NamedKey::lookup(name).ok_or_else(|| format!("no key named {name}")))
        .collect::<Result<_, _>>()?;
    Ok(limb_core::keys::lower_press(&keys))
}

/// The most text one `session_text` call may type. A phone keyboard commits
/// a word or a paste at a time; this only stops a runaway caller from
/// queueing an unbounded run of key events.
pub const MAX_TEXT_CHARS: usize = 4096;

/// The commands that type `text`: a press and a release per character, as
/// keysyms only. An empty string types nothing.
pub fn text_commands(text: &str) -> Result<Vec<ClientCommand>, String> {
    if text.chars().count() > MAX_TEXT_CHARS {
        return Err(format!(
            "Type at most {MAX_TEXT_CHARS} characters at a time"
        ));
    }
    Ok(limb_core::keys::lower_type(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(cmds: &[ClientCommand]) -> Vec<(u32, Option<u32>, bool)> {
        cmds.iter()
            .map(|c| match c {
                ClientCommand::Key {
                    keysym,
                    keycode,
                    down,
                } => (*keysym, *keycode, *down),
                other => panic!("not a key: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn every_combo_resolves() {
        for combo in [
            KeyCombo::CtrlAltDel,
            KeyCombo::Win,
            KeyCombo::AltTab,
            KeyCombo::CmdTab,
            KeyCombo::CtrlC,
            KeyCombo::CtrlV,
            KeyCombo::Esc,
        ] {
            let cmds = combo_commands(combo).unwrap();
            assert_eq!(cmds.len(), combo.key_names().len() * 2, "{combo:?}");
        }
    }

    #[test]
    fn ctrl_alt_del_presses_outside_in_and_releases_inside_out() {
        let k = keys(&combo_commands(KeyCombo::CtrlAltDel).unwrap());
        // Control_L, Alt_L, Delete keysyms.
        let syms: Vec<_> = k.iter().map(|(s, _, d)| (*s, *d)).collect();
        assert_eq!(
            syms,
            vec![
                (0xffe3, true),
                (0xffe9, true),
                (0xffff, true),
                (0xffff, false),
                (0xffe9, false),
                (0xffe3, false),
            ]
        );
        // A chord carries scancodes, so a scancode only server still sees it.
        assert!(k.iter().all(|(_, code, _)| code.is_some()));
    }

    #[test]
    fn combo_names_parse_from_the_wire() {
        let c: KeyCombo = serde_json::from_str("\"ctrl-alt-del\"").unwrap();
        assert_eq!(c, KeyCombo::CtrlAltDel);
        let c: KeyCombo = serde_json::from_str("\"cmd-tab\"").unwrap();
        assert_eq!(c, KeyCombo::CmdTab);
        assert!(serde_json::from_str::<KeyCombo>("\"ctrl-z\"").is_err());
    }

    #[test]
    fn text_is_keysyms_without_scancodes() {
        let k = keys(&text_commands("aZ\n").unwrap());
        assert_eq!(
            k,
            vec![
                (0x61, None, true),
                (0x61, None, false),
                (0x5a, None, true),
                (0x5a, None, false),
                (0xff0d, None, true),
                (0xff0d, None, false),
            ]
        );
    }

    #[test]
    fn latin1_and_unicode_keysyms() {
        let k = keys(&text_commands("é€😀").unwrap());
        let downs: Vec<u32> = k
            .iter()
            .filter(|(_, _, d)| *d)
            .map(|(s, _, _)| *s)
            .collect();
        // Latin-1 is its own keysym, everything above is 0x0100_0000 + code point,
        // and an emoji is one character, not a surrogate pair.
        assert_eq!(downs, vec![0xe9, 0x0100_20ac, 0x0101_f600]);
    }

    #[test]
    fn empty_and_oversized_text() {
        assert!(text_commands("").unwrap().is_empty());
        assert!(text_commands(&"x".repeat(MAX_TEXT_CHARS)).is_ok());
        assert!(text_commands(&"x".repeat(MAX_TEXT_CHARS + 1)).is_err());
    }
}
