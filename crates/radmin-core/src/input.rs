//! Physical PC input, translated into the recovered Radmin control events.
use super::desktop::tlv;
use std::collections::BTreeMap;

// Radmin forwards Windows key-message VK values, not GetKeyState's sided
// VK_L*/VK_R* variants. The scan byte and E0 flag distinguish modifier sides.
const VK_SHIFT: u8 = 0x10;
const VK_CONTROL: u8 = 0x11;
const VK_MENU: u8 = 0x12;

#[derive(Clone, Copy)]
struct Key {
    vk: u8,
    scan: u8,
    extended: bool,
    system: bool,
}
#[derive(Default)]
pub struct Input {
    keys: BTreeMap<(u32, u32), Key>,
    buttons: u16,
    point: (u16, u16),
}
impl Input {
    /// Native Viewer's Ctrl+Alt+Del action: one input event, not three keys.
    /// See ../SECURE_ATTENTION.md for resource/dispatcher/serializer evidence.
    pub fn secure_attention() -> Vec<u8> {
        tlv(0x70000000, &[0x0e])
    }
    pub fn pointer(&mut self, x: u16, y: u16, mask: u16, size: (u16, u16)) -> Vec<u8> {
        let (x, y) = (
            x.min(size.0.saturating_sub(1)),
            y.min(size.1.saturating_sub(1)),
        );
        self.point = (x, y);
        let mut data = vec![0x0b];
        data.extend(x.to_le_bytes());
        data.extend(y.to_le_bytes());
        for (bit, down, up, extra) in [
            (1, 8, 7, 0u16),
            (2, 10, 9, 0),
            (4, 6, 5, 0),
            (128, 17, 16, 1),
            (256, 17, 16, 2),
        ] {
            if (mask ^ self.buttons) & bit != 0 {
                data.push(if mask & bit != 0 { down } else { up });
                if extra != 0 {
                    data.extend(extra.to_le_bytes());
                }
                data.extend(x.to_le_bytes());
                data.extend(y.to_le_bytes());
            }
        }
        for (bit, delta) in [(8, 120i16), (16, -120i16)] {
            if mask & bit != 0 {
                data.push(15);
                data.extend(delta.to_le_bytes());
                data.extend(x.to_le_bytes());
                data.extend(y.to_le_bytes());
            }
        }
        self.buttons = mask & (1 | 2 | 4 | 128 | 256);
        tlv(0x70000000, &data)
    }
    pub fn key(&mut self, sym: u32, code: Option<u32>, down: bool) -> Vec<u8> {
        let code = code.unwrap_or(0);
        let identity = if code != 0 { (code, 0) } else { (0, sym) };
        let held = self.keys.get(&identity).copied();
        if !down && held.is_none() {
            return vec![];
        }
        let Some(mut key) = held.or_else(|| key_identity(sym, code)) else {
            return vec![];
        };
        let alt = self.keys.values().any(|k| k.vk == VK_MENU) || (down && key.vk == VK_MENU);
        if held.is_none() {
            key.system = alt || key.vk == VK_MENU;
        }
        let flags = 1
            | ((key.scan as u32) << 16)
            | ((key.extended as u32) << 24)
            | ((alt as u32) << 29)
            | ((held.is_some() as u32) << 30)
            | ((!down as u32) << 31);
        let mut data = vec![(if down { 0 } else { 2 }) + key.system as u8, key.vk];
        data.extend(flags.to_le_bytes());
        if down {
            self.keys.insert(identity, key);
        } else {
            self.keys.remove(&identity);
        }
        tlv(0x70000000, &data)
    }
    pub fn release(&mut self) -> Vec<u8> {
        let mut data = Vec::new();
        for key in self.keys.values() {
            data.extend([2, key.vk]);
            data.extend(((key.extended as u32) << 24).to_le_bytes());
        }
        self.keys.clear();
        for (bit, code, extra) in [
            (4, 5, 0u16),
            (1, 7, 0),
            (2, 9, 0),
            (128, 16, 1),
            (256, 16, 2),
        ] {
            if self.buttons & bit != 0 {
                data.push(code);
                if extra != 0 {
                    data.extend(extra.to_le_bytes());
                }
                data.extend(self.point.0.to_le_bytes());
                data.extend(self.point.1.to_le_bytes());
            }
        }
        self.buttons = 0;
        if data.is_empty() {
            data
        } else {
            tlv(0x70000000, &data)
        }
    }
}

fn key_identity(sym: u32, code: u32) -> Option<Key> {
    let scan = (code & 0x7f) as u8;
    let extended = code & 0x80 != 0;
    let vk = if (1..=255).contains(&code) {
        if extended {
            match scan {
                28 => 13,
                29 => VK_CONTROL,
                53 => 0x6f,
                55 => 0x2c,
                56 => VK_MENU,
                71 => 0x24,
                72 => 0x26,
                73 => 0x21,
                75 => 0x25,
                77 => 0x27,
                79 => 0x23,
                80 => 0x28,
                81 => 0x22,
                82 => 0x2d,
                83 => 0x2e,
                91 => 0x5b,
                92 => 0x5c,
                93 => 0x5d,
                _ => 0,
            }
        } else {
            match scan {
                2..=11 => b"1234567890"[(scan - 2) as usize],
                16..=25 => b"QWERTYUIOP"[(scan - 16) as usize],
                30..=38 => b"ASDFGHJKL"[(scan - 30) as usize],
                44..=50 => b"ZXCVBNM"[(scan - 44) as usize],
                59..=68 => 0x70 + scan - 59,
                1 => 27,
                12 => 0xbd,
                13 => 0xbb,
                14 => 8,
                15 => 9,
                26 => 0xdb,
                27 => 0xdd,
                28 => 13,
                29 => VK_CONTROL,
                39 => 0xba,
                40 => 0xde,
                41 => 0xc0,
                42 => VK_SHIFT,
                43 => 0xdc,
                51 => 0xbc,
                52 => 0xbe,
                53 => 0xbf,
                54 => VK_SHIFT,
                55 => 0x6a,
                56 => VK_MENU,
                57 => 32,
                58 => 0x14,
                69 => 0x90,
                70 => 0x91,
                71 => 0x67,
                72 => 0x68,
                73 => 0x69,
                74 => 0x6d,
                75 => 0x64,
                76 => 0x65,
                77 => 0x66,
                78 => 0x6b,
                79 => 0x61,
                80 => 0x62,
                81 => 0x63,
                82 => 0x60,
                83 => 0x6e,
                86 => 0xe2,
                87 => 0x7a,
                88 => 0x7b,
                _ => 0,
            }
        }
    } else {
        0
    };
    if vk != 0 {
        return Some(Key {
            vk,
            scan,
            extended,
            system: false,
        });
    }
    let vk = match sym {
        0x61..=0x7a => (sym - 32) as u8,
        0x30..=0x39 | 0x41..=0x5a | 32 => sym as u8,
        0xffbe..=0xffd5 => (0x70 + sym - 0xffbe) as u8,
        0xff08 => 8,
        0xff09 => 9,
        0xff0d => 13,
        0xff1b => 27,
        0xff13 => 0x13,
        0xffff => 0x2e,
        0xff50 => 0x24,
        0xff57 => 0x23,
        0xff51 => 0x25,
        0xff52 => 0x26,
        0xff53 => 0x27,
        0xff54 => 0x28,
        0xff55 => 0x21,
        0xff56 => 0x22,
        0xff63 => 0x2d,
        0xffe1 | 0xffe2 => VK_SHIFT,
        0xffe3 | 0xffe4 => VK_CONTROL,
        0xffe9 | 0xffea => VK_MENU,
        0xffeb => 0x5b,
        0xffec => 0x5c,
        _ => return None,
    };
    Some(Key {
        vk,
        scan: match sym {
            0xffe1 => 0x2a,
            0xffe2 => 0x36,
            0xffe3 | 0xffe4 => 0x1d,
            0xffe9 | 0xffea => 0x38,
            _ => 0,
        },
        extended: matches!(sym, 0xffe4 | 0xffea | 0xffeb | 0xffec),
        system: false,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secure_attention_is_the_native_one_byte_command() {
        assert_eq!(Input::secure_attention(), [0x70, 0, 0, 1, 0x0e]);
    }
    #[test]
    fn physical_identity_repeat_and_release_survive_layout_changes() {
        let mut input = Input::default();
        assert_eq!(
            hex::encode(input.key(97, Some(0x1e), true)),
            "70000006004101001e00"
        );
        let repeat = input.key(0x010005d0, Some(0x1e), true);
        assert_eq!(repeat[5], 0x41);
        assert_ne!(repeat[9] & 0x40, 0);
        let up = input.key(0x010005d0, Some(0x1e), false);
        assert_eq!(up[5], 0x41);
        assert_ne!(up[9] & 0x80, 0);
        assert!(input.release().is_empty());
    }
    #[test]
    fn native_focus_loss_releases_buttons_and_keys() {
        let mut input = Input::default();
        input.pointer(20, 30, 1, (100, 100));
        input.key(0xffe3, Some(0x1d), true);
        assert_eq!(
            hex::encode(input.release()),
            "7000000b0211000000000714001e00"
        );
        assert!(input.release().is_empty());
    }

    #[test]
    fn ctrl_escape_matches_recovered_native_shortcut_packets() {
        // Literal fixtures retained by radmin-compatible-viewer's input tests,
        // recovered from the native viewer's Ctrl+Esc shortcut implementation.
        let mut input = Input::default();
        let packets = [
            input.key(0xffe3, Some(0x1d), true),
            input.key(0xff1b, Some(0x01), true),
            input.key(0xff1b, Some(0x01), false),
            input.key(0xffe3, Some(0x1d), false),
        ];
        assert_eq!(
            packets.map(hex::encode),
            [
                "70000006001101001d00",
                "70000006001b01000100",
                "70000006021b010001c0",
                "70000006021101001dc0",
            ]
        );
        assert!(input.release().is_empty());
    }

    #[test]
    fn send_menu_alt_tab_and_alt_f4_include_generic_alt_and_system_flags() {
        // Same (keysym, XT scan) pairs and down/reverse-up ordering as KEY_COMBO.
        for (sym, scan, down, up) in [
            (0xff09, 0x0f, "70000006010901000f20", "70000006030901000fe0"),
            (0xffc1, 0x3e, "70000006017301003e20", "70000006037301003ee0"),
        ] {
            let mut input = Input::default();
            assert_eq!(
                hex::encode(input.key(0xffe9, Some(0x38), true)),
                "70000006011201003820"
            );
            assert_eq!(hex::encode(input.key(sym, Some(scan), true)), down);
            assert_eq!(hex::encode(input.key(sym, Some(scan), false)), up);
            assert_eq!(
                hex::encode(input.key(0xffe9, Some(0x38), false)),
                "700000060312010038e0"
            );
            assert!(input.release().is_empty());
        }
    }

    #[test]
    fn modifier_sides_use_scan_and_extended_flag_in_both_input_paths() {
        for (sym, code, vk, scan, extended) in [
            (0xffe1, 0x2a, 0x10, 0x2a, false),
            (0xffe2, 0x36, 0x10, 0x36, false),
            (0xffe3, 0x1d, 0x11, 0x1d, false),
            (0xffe4, 0x9d, 0x11, 0x1d, true),
            (0xffe9, 0x38, 0x12, 0x38, false),
            (0xffea, 0xb8, 0x12, 0x38, true),
        ] {
            for keycode in [Some(code), None] {
                let mut input = Input::default();
                let packet = input.key(sym, keycode, true);
                assert_eq!(packet[5], vk);
                assert_eq!(packet[8], scan);
                assert_eq!(packet[9] & 1, extended as u8);
                assert_eq!(input.key(sym, keycode, false)[5], vk);
                assert!(input.release().is_empty());
            }
        }
    }
}
