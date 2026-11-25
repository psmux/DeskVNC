//! Which key types which character, on the keyboard layout the sign in
//! screen uses.
//!
//! The virtual keyboard sends key positions, and the compositor turns them
//! into characters through its own layout. To type a helper's text right
//! on, say, a German or French machine, the service reads the layout the
//! system is set to (what GDM's screen starts with) and asks xkbcommon,
//! loaded when first needed, which key and modifiers give each character.
//! Without xkbcommon it types as a US keyboard would.

use super::egl::{api, open_library, symbol};
use anyhow::{Context, Result, ensure};
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_void};

/// The system's keyboard layout, as XKB names it.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Layout {
    pub model: String,
    pub layout: String,
    pub variant: String,
    pub options: String,
}

impl Layout {
    /// What the system is set to, from the files localed and Debian's
    /// keyboard-configuration keep; US where none says.
    pub fn configured() -> Self {
        let read = |p: &str| std::fs::read_to_string(p).ok();
        let found = read("/etc/default/keyboard")
            .map(|t| from_shell(&t))
            .filter(|l| !l.layout.is_empty())
            .or_else(|| {
                read("/etc/X11/xorg.conf.d/00-keyboard.conf")
                    .map(|t| from_xorg(&t))
                    .filter(|l| !l.layout.is_empty())
            })
            .or_else(|| {
                read("/etc/vconsole.conf")
                    .map(|t| from_shell(&t))
                    .filter(|l| !l.layout.is_empty())
            });
        found.unwrap_or_else(|| Self {
            layout: "us".into(),
            ..Default::default()
        })
    }

    /// The first of several layouts, which is the one a fresh sign in
    /// screen starts with.
    fn first(&self) -> (String, String) {
        let first = |s: &str| s.split(',').next().unwrap_or("").trim().to_string();
        (first(&self.layout), first(&self.variant))
    }
}

/// `XKBLAYOUT="de"` lines, as /etc/default/keyboard and vconsole.conf
/// write them.
fn from_shell(text: &str) -> Layout {
    let mut l = Layout::default();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
        match key.trim() {
            "XKBMODEL" => l.model = value,
            "XKBLAYOUT" => l.layout = value,
            "XKBVARIANT" => l.variant = value,
            "XKBOPTIONS" => l.options = value,
            _ => {}
        }
    }
    l
}

/// `Option "XkbLayout" "de"` lines, as localed writes for X11.
fn from_xorg(text: &str) -> Layout {
    let mut l = Layout::default();
    for line in text.lines() {
        let parts: Vec<&str> = line.split('"').collect();
        if !line.trim_start().starts_with("Option") || parts.len() < 4 {
            continue;
        }
        let value = parts[3].to_string();
        match parts[1] {
            "XkbModel" => l.model = value,
            "XkbLayout" => l.layout = value,
            "XkbVariant" => l.variant = value,
            "XkbOptions" => l.options = value,
            _ => {}
        }
    }
    l
}

/// The key to press for a character, and which modifiers to hold.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Stroke {
    /// The evdev key code.
    pub code: u16,
    pub shift: bool,
    /// AltGr, the third level.
    pub level3: bool,
}

/// Characters to keys, on one layout.
pub(crate) struct Keymap {
    keys: HashMap<char, Stroke>,
    /// The key that selects the third level, when the layout has one.
    pub level3_key: Option<u16>,
    /// What it is, for the log.
    pub name: String,
}

const KEY_RIGHTALT: u16 = 100;
const ISO_LEVEL3_SHIFT: u32 = 0xfe03;

#[repr(C)]
struct RuleNames {
    rules: *const c_char,
    model: *const c_char,
    layout: *const c_char,
    variant: *const c_char,
    options: *const c_char,
}

type Ptr = *mut c_void;

api!(Xkb {
    xkb_context_new: fn(i32) -> Ptr;
    xkb_context_unref: fn(Ptr);
    xkb_keymap_new_from_names: fn(Ptr, *const RuleNames, i32) -> Ptr;
    xkb_keymap_unref: fn(Ptr);
    xkb_keymap_min_keycode: fn(Ptr) -> u32;
    xkb_keymap_max_keycode: fn(Ptr) -> u32;
    xkb_keymap_num_levels_for_key: fn(Ptr, u32, u32) -> u32;
    xkb_keymap_key_get_syms_by_level: fn(Ptr, u32, u32, u32, *mut *const u32) -> i32;
    xkb_keymap_key_get_mods_for_level: fn(Ptr, u32, u32, u32, *mut u32, usize) -> usize;
    xkb_keymap_mod_get_index: fn(Ptr, *const c_char) -> u32;
    xkb_keysym_to_utf32: fn(u32) -> u32;
});

/// How much less a key is wanted than its modifiers say: the keypad, whose
/// meaning hangs on Num Lock, and the extra key by the left Shift that a
/// US keyboard lacks, are used only for what has no other key.
fn detour(code: u16) -> u32 {
    match code {
        55 | 71..=83 | 96 | 98 | 117 | 121 => 2,
        86 => 1,
        _ => 0,
    }
}

impl Keymap {
    /// The system's layout, or US with the reason it is not.
    pub fn configured() -> Self {
        let layout = Layout::configured();
        match Self::load(&layout) {
            Ok(map) => map,
            Err(error) => {
                let mut map = Self::us();
                map.name = format!("us, as {} could not be read ({error:#})", layout.layout);
                map
            }
        }
    }

    /// A US keyboard, which needs nothing installed.
    pub fn us() -> Self {
        let mut keys = HashMap::new();
        for c in (' '..='~').chain(['\n', '\t']) {
            if let Some((code, shift)) = super::uinput::key_for(c) {
                keys.insert(
                    c,
                    Stroke {
                        code,
                        shift,
                        level3: false,
                    },
                );
            }
        }
        Self {
            keys,
            level3_key: None,
            name: "us".into(),
        }
    }

    pub fn load(layout: &Layout) -> Result<Self> {
        let lib = open_library(&[c"libxkbcommon.so.0", c"libxkbcommon.so"])?;
        // SAFETY: names and signatures from xkbcommon.h, 1.0 and later.
        let xkb = unsafe { Xkb::load(&symbol(lib)) }?;
        let (name, variant) = layout.first();
        let c = |s: &str| CString::new(s).context("A layout name with a NUL in it");
        let (rules, model, lay, var, opts) = (
            c("evdev")?,
            c(&layout.model)?,
            c(&name)?,
            c(&variant)?,
            c(&layout.options)?,
        );
        let names = RuleNames {
            rules: rules.as_ptr(),
            model: model.as_ptr(),
            layout: lay.as_ptr(),
            variant: var.as_ptr(),
            options: opts.as_ptr(),
        };
        // SAFETY: xkbcommon calls on a context and keymap made here and
        // released before returning; arrays sized as passed.
        unsafe {
            let ctx = (xkb.xkb_context_new)(0);
            ensure!(!ctx.is_null(), "xkbcommon would not start");
            let keymap = (xkb.xkb_keymap_new_from_names)(ctx, &names, 0);
            if keymap.is_null() {
                (xkb.xkb_context_unref)(ctx);
                anyhow::bail!("xkbcommon has no layout {name:?} {variant:?}");
            }
            let shift = 1u32 << (xkb.xkb_keymap_mod_get_index)(keymap, c"Shift".as_ptr());
            let mod5 = (xkb.xkb_keymap_mod_get_index)(keymap, c"Mod5".as_ptr());
            let level3 = if mod5 < 32 { 1u32 << mod5 } else { 0 };
            let mut best: HashMap<char, (u32, Stroke)> = HashMap::new();
            let mut level3_key = None;
            let (min, max) = (
                (xkb.xkb_keymap_min_keycode)(keymap),
                (xkb.xkb_keymap_max_keycode)(keymap),
            );
            for kc in min.max(9)..=max.min(127 + 8) {
                let code = (kc - 8) as u16;
                for level in 0..(xkb.xkb_keymap_num_levels_for_key)(keymap, kc, 0) {
                    let mut syms: *const u32 = std::ptr::null();
                    let n = (xkb.xkb_keymap_key_get_syms_by_level)(keymap, kc, 0, level, &mut syms);
                    if n <= 0 || syms.is_null() {
                        continue;
                    }
                    let syms = std::slice::from_raw_parts(syms, n as usize);
                    if level == 0 && syms.contains(&ISO_LEVEL3_SHIFT) && level3_key.is_none() {
                        level3_key = Some(code);
                    }
                    let mut masks = [0u32; 16];
                    let m = (xkb.xkb_keymap_key_get_mods_for_level)(
                        keymap,
                        kc,
                        0,
                        level,
                        masks.as_mut_ptr(),
                        masks.len(),
                    );
                    // The simplest way to reach this level with only Shift
                    // and AltGr; Caps Lock and Num Lock are left as they are.
                    let Some(mask) = masks[..m.min(16)]
                        .iter()
                        .copied()
                        .filter(|&mask| mask & !(shift | level3) == 0)
                        .min_by_key(|mask| mask.count_ones())
                    else {
                        continue;
                    };
                    let stroke = Stroke {
                        code,
                        shift: mask & shift != 0,
                        level3: mask & level3 != 0,
                    };
                    let cost = mask.count_ones() + detour(code);
                    for &sym in syms {
                        let Some(ch) = char::from_u32((xkb.xkb_keysym_to_utf32)(sym)) else {
                            continue;
                        };
                        if ch == '\0' || (ch.is_control() && ch != '\t' && ch != '\r') {
                            continue;
                        }
                        let ch = if ch == '\r' { '\n' } else { ch };
                        if best.get(&ch).is_none_or(|(c, _)| cost < *c) {
                            best.insert(ch, (cost, stroke));
                        }
                    }
                }
            }
            (xkb.xkb_keymap_unref)(keymap);
            (xkb.xkb_context_unref)(ctx);
            let mut keys: HashMap<char, Stroke> =
                best.into_iter().map(|(c, (_, s))| (c, s)).collect();
            // A layout whose third level has no key of its own falls back
            // to right Alt, which is where it is on every common layout.
            if level3_key.is_none() && keys.values().any(|s| s.level3) {
                level3_key = Some(KEY_RIGHTALT);
            }
            ensure!(keys.contains_key(&'a') || keys.len() > 20, "An empty layout");
            keys.entry('\n').or_insert(Stroke {
                code: 28,
                shift: false,
                level3: false,
            });
            let label = if variant.is_empty() {
                name
            } else {
                format!("{name} ({variant})")
            };
            Ok(Self {
                keys,
                level3_key,
                name: label,
            })
        }
    }

    pub fn stroke(&self, c: char) -> Option<Stroke> {
        self.keys.get(&c).copied().filter(|s| !s.level3 || self.level3_key.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_is_read_from_the_system_files() {
        let debian = "# KEYBOARD CONFIGURATION FILE\nXKBMODEL=\"pc105\"\nXKBLAYOUT=\"de,us\"\nXKBVARIANT=\"nodeadkeys,\"\nXKBOPTIONS=\"\"\n";
        let l = from_shell(debian);
        assert_eq!(l.model, "pc105");
        assert_eq!(l.first(), ("de".into(), "nodeadkeys".into()));
        let xorg = "Section \"InputClass\"\n        Identifier \"system-keyboard\"\n        MatchIsKeyboard \"on\"\n        Option \"XkbLayout\" \"fr\"\n        Option \"XkbVariant\" \"azerty\"\nEndSection\n";
        let l = from_xorg(xorg);
        assert_eq!((l.layout.as_str(), l.variant.as_str()), ("fr", "azerty"));
        assert_eq!(from_shell("KEYMAP=us\nXKBLAYOUT=gb\n").layout, "gb");
    }

    #[test]
    fn the_us_fallback_types_as_before() {
        let us = Keymap::us();
        let s = |c| us.stroke(c).map(|s| (s.code, s.shift));
        assert_eq!(s('a'), Some((30, false)));
        assert_eq!(s('A'), Some((30, true)));
        assert_eq!(s('@'), Some((3, true)));
        assert_eq!(s('\n'), Some((28, false)));
        assert_eq!(s('é'), None);
    }

    /// Skipped where xkbcommon or its layouts are not installed, which
    /// says so on stderr.
    #[test]
    fn other_layouts_type_through_xkbcommon() {
        let load = |layout: &str, variant: &str| {
            Keymap::load(&Layout {
                layout: layout.into(),
                variant: variant.into(),
                ..Default::default()
            })
        };
        let de = match load("de", "") {
            Ok(map) => map,
            Err(error) => {
                eprintln!("skipped: {error:#}");
                return;
            }
        };
        let key = |m: &Keymap, c| m.stroke(c).map(|s| (s.code, s.shift, s.level3));
        // German: Y and Z swap, @ is AltGr Q, and the umlauts have keys.
        assert_eq!(key(&de, 'z'), Some((21, false, false)));
        assert_eq!(key(&de, 'y'), Some((44, false, false)));
        assert_eq!(key(&de, 'Z'), Some((21, true, false)));
        assert_eq!(key(&de, '@'), Some((16, false, true)));
        assert_eq!(key(&de, 'ö'), Some((39, false, false)));
        assert_eq!(key(&de, '"'), Some((3, true, false)));
        assert_eq!(de.level3_key, Some(KEY_RIGHTALT));
        // French: A and Q swap, digits need Shift.
        let fr = load("fr", "").unwrap();
        assert_eq!(key(&fr, 'a'), Some((16, false, false)));
        assert_eq!(key(&fr, '1'), Some((2, true, false)));
        assert_eq!(key(&fr, 'é'), Some((3, false, false)));
        // And US is what it always was.
        let us = load("us", "").unwrap();
        for c in (' '..='~').chain(['\n', '\t']) {
            assert_eq!(
                us.stroke(c).map(|s| (s.code, s.shift)),
                Keymap::us().stroke(c).map(|s| (s.code, s.shift)),
                "{c:?}"
            );
        }
        assert!(load("no-such-layout", "").is_err());
    }
}
