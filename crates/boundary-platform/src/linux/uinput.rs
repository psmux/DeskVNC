//! A virtual keyboard and absolute pointer, through the kernel's uinput.
//!
//! The Wayland sign in screen takes input from no program, only from input
//! devices, so this makes one. The compositor sees it as a new mouse and
//! keyboard, the way it sees QEMU's tablet. Text is typed through the
//! system's keyboard layout ([`super::xkb`]), US where that cannot be read;
//! a character the layout has no key for is skipped.

use super::xkb::{Keymap, Stroke};
use anyhow::{Context, Result};
use boundary_session::{Button, Input, Key};
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;

const fn io(nr: u32) -> libc::c_ulong {
    ((b'U' as u32) << 8 | nr) as libc::c_ulong
}
const fn iow(nr: u32, size: usize) -> libc::c_ulong {
    ((1u32 << 30) | ((size as u32) << 16) | ((b'U' as u32) << 8) | nr) as libc::c_ulong
}

#[repr(C)]
struct Setup {
    bustype: u16,
    vendor: u16,
    product: u16,
    version: u16,
    name: [u8; 80],
    ff_effects_max: u32,
}
#[repr(C)]
struct AbsSetup {
    code: u16,
    value: i32,
    minimum: i32,
    maximum: i32,
    fuzz: i32,
    flat: i32,
    resolution: i32,
}

const UI_DEV_CREATE: libc::c_ulong = io(1);
const UI_DEV_SETUP: libc::c_ulong = iow(3, size_of::<Setup>());
const UI_ABS_SETUP: libc::c_ulong = iow(4, size_of::<AbsSetup>());
const UI_SET_EVBIT: libc::c_ulong = iow(100, size_of::<libc::c_int>());
const UI_SET_KEYBIT: libc::c_ulong = iow(101, size_of::<libc::c_int>());
const UI_SET_RELBIT: libc::c_ulong = iow(102, size_of::<libc::c_int>());
const UI_SET_ABSBIT: libc::c_ulong = iow(103, size_of::<libc::c_int>());

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const EV_ABS: u16 = 3;
const REL_WHEEL: u16 = 8;
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const KEY_LEFTSHIFT: u16 = 42;
/// The pointer's range on each axis.
const SPAN: i32 = 65535;

/// The evdev key for a character on a US keyboard, and whether it needs
/// Shift.
pub(crate) fn key_for(c: char) -> Option<(u16, bool)> {
    const ROW1: &str = "1234567890-=";
    const ROW1_SHIFT: &str = "!@#$%^&*()_+";
    const QWERTY: &str = "qwertyuiop[]";
    const QWERTY_SHIFT: &str = "QWERTYUIOP{}";
    const HOME: &str = "asdfghjkl;'`";
    const HOME_SHIFT: &str = "ASDFGHJKL:\"~";
    const BOTTOM: &str = "zxcvbnm,./";
    const BOTTOM_SHIFT: &str = "ZXCVBNM<>?";
    let find = |row: &str, first: u16| row.chars().position(|r| r == c).map(|i| first + i as u16);
    match c {
        ' ' => Some((57, false)),
        '\n' | '\r' => Some((28, false)),
        '\t' => Some((15, false)),
        '\\' => Some((43, false)),
        '|' => Some((43, true)),
        _ => find(ROW1, 2)
            .map(|k| (k, false))
            .or_else(|| find(ROW1_SHIFT, 2).map(|k| (k, true)))
            .or_else(|| find(QWERTY, 16).map(|k| (k, false)))
            .or_else(|| find(QWERTY_SHIFT, 16).map(|k| (k, true)))
            .or_else(|| find(HOME, 30).map(|k| (k, false)))
            .or_else(|| find(HOME_SHIFT, 30).map(|k| (k, true)))
            .or_else(|| find(BOTTOM, 44).map(|k| (k, false)))
            .or_else(|| find(BOTTOM_SHIFT, 44).map(|k| (k, true))),
    }
}

fn named(key: Key, keymap: &Keymap) -> Option<(u16, bool)> {
    Some(match key {
        Key::Enter => (28, false),
        Key::Tab => (15, false),
        Key::Escape => (1, false),
        Key::Backspace => (14, false),
        Key::Delete => (111, false),
        Key::Left => (105, false),
        Key::Right => (106, false),
        Key::Up => (103, false),
        Key::Down => (108, false),
        Key::Home => (102, false),
        Key::End => (107, false),
        Key::PageUp => (104, false),
        Key::PageDown => (109, false),
        Key::Shift => (KEY_LEFTSHIFT, false),
        Key::Control => (29, false),
        Key::Alt => (56, false),
        Key::Meta => (125, false),
        Key::Space => (57, false),
        Key::Letter(c) => {
            let lower = c.to_lowercase().next().unwrap_or(c);
            return keymap
                .stroke(lower)
                .filter(|s| !s.level3)
                .map(|s| (s.code, s.shift));
        }
    })
}

pub(crate) struct Uinput {
    dev: File,
    /// Where the pointer was last put, in the device's range.
    at: (i32, i32),
    /// Keys and buttons held down, let go of on release.
    held: Vec<u16>,
    keymap: Keymap,
}

impl Uinput {
    pub fn new() -> Result<Self> {
        let dev = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/uinput")
            .context("Cannot open /dev/uinput; this needs root")?;
        let set = |request, value: libc::c_int| {
            // SAFETY: these uinput requests take a plain int.
            let rc = unsafe { libc::ioctl(dev.as_raw_fd(), request, value) };
            if rc < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        for ev in [EV_KEY, EV_REL, EV_ABS] {
            set(UI_SET_EVBIT, ev as libc::c_int)?;
        }
        for key in 1..=127 {
            set(UI_SET_KEYBIT, key)?;
        }
        for button in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE] {
            set(UI_SET_KEYBIT, button as libc::c_int)?;
        }
        set(UI_SET_RELBIT, REL_WHEEL as libc::c_int)?;
        for axis in 0..2 {
            set(UI_SET_ABSBIT, axis)?;
            let abs = AbsSetup {
                code: axis as u16,
                value: 0,
                minimum: 0,
                maximum: SPAN,
                fuzz: 0,
                flat: 0,
                resolution: 0,
            };
            // SAFETY: the struct the request's size encodes.
            let rc = unsafe { libc::ioctl(dev.as_raw_fd(), UI_ABS_SETUP, &abs) };
            anyhow::ensure!(rc >= 0, "uinput: {}", std::io::Error::last_os_error());
        }
        let mut name = [0u8; 80];
        let label = b"DeskVNC Support remote input";
        name[..label.len()].copy_from_slice(label);
        let setup = Setup {
            bustype: 0x06, // virtual
            vendor: 0x1d6b,
            product: 0x0105,
            version: 1,
            name,
            ff_effects_max: 0,
        };
        // SAFETY: as above.
        unsafe {
            anyhow::ensure!(
                libc::ioctl(dev.as_raw_fd(), UI_DEV_SETUP, &setup) >= 0
                    && libc::ioctl(dev.as_raw_fd(), UI_DEV_CREATE) >= 0,
                "uinput: {}",
                std::io::Error::last_os_error()
            );
        }
        // The compositor finds a new device through udev; input sent before
        // it opens the device is lost.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let keymap = Keymap::configured();
        eprintln!("Typing on the sign in screen as keyboard layout {}", keymap.name);
        Ok(Self {
            dev,
            at: (SPAN / 2, SPAN / 2),
            held: Vec::new(),
            keymap,
        })
    }

    fn emit(&mut self, events: &[(u16, u16, i32)]) -> Result<()> {
        let mut bytes = Vec::with_capacity((events.len() + 1) * 24);
        for &(ty, code, value) in events.iter().chain([(EV_SYN, 0, 0)].iter()) {
            bytes.extend_from_slice(&[0u8; 16]); // the kernel fills the time
            bytes.extend_from_slice(&ty.to_ne_bytes());
            bytes.extend_from_slice(&code.to_ne_bytes());
            bytes.extend_from_slice(&value.to_ne_bytes());
        }
        self.dev.write_all(&bytes).context("uinput write")?;
        Ok(())
    }

    fn key(&mut self, code: u16, down: bool) -> Result<()> {
        if down {
            self.held.push(code);
        } else {
            self.held.retain(|&k| k != code);
        }
        self.emit(&[(EV_KEY, code, down as i32)])
    }

    fn tap(&mut self, stroke: Stroke) -> Result<()> {
        let mut mods = Vec::new();
        if stroke.shift {
            mods.push(KEY_LEFTSHIFT);
        }
        if stroke.level3
            && let Some(k) = self.keymap.level3_key
        {
            mods.push(k);
        }
        for &m in &mods {
            self.key(m, true)?;
        }
        self.key(stroke.code, true)?;
        self.key(stroke.code, false)?;
        for &m in mods.iter().rev() {
            self.key(m, false)?;
        }
        Ok(())
    }

    pub fn input(&mut self, input: Input) -> Result<()> {
        match input {
            Input::Move { x, y } => {
                let at = |f: f32| (f.clamp(0.0, 1.0) * SPAN as f32).round() as i32;
                self.at = (at(x), at(y));
                self.emit(&[(EV_ABS, 0, self.at.0), (EV_ABS, 1, self.at.1)])
            }
            Input::Button { button, down } => self.key(
                match button {
                    Button::Left => BTN_LEFT,
                    Button::Middle => BTN_MIDDLE,
                    Button::Right => BTN_RIGHT,
                },
                down,
            ),
            Input::Key { key, down } => match named(key, &self.keymap) {
                Some((code, true)) if down => self.tap(Stroke {
                    code,
                    shift: true,
                    level3: false,
                }),
                Some((code, _)) => self.key(code, down),
                None => Ok(()),
            },
            Input::Text(text) => {
                for c in text.chars() {
                    if let Some(stroke) = self.keymap.stroke(c) {
                        self.tap(stroke)?;
                        std::thread::sleep(std::time::Duration::from_millis(8));
                    }
                }
                Ok(())
            }
            Input::Scroll { lines } => self.emit(&[(EV_REL, REL_WHEEL, -lines)]),
            Input::Release => self.release(),
        }
    }

    /// Nudge the pointer and put it back, which wakes a blank screen
    /// without typing or clicking anything.
    pub fn wake(&mut self) -> Result<()> {
        let (x, y) = self.at;
        let nudge = if x < SPAN { x + 64 } else { x - 64 };
        self.emit(&[(EV_ABS, 0, nudge), (EV_ABS, 1, y)])?;
        self.emit(&[(EV_ABS, 0, x), (EV_ABS, 1, y)])
    }

    pub fn release(&mut self) -> Result<()> {
        for code in std::mem::take(&mut self.held) {
            self.emit(&[(EV_KEY, code, 0)])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_as_a_us_keyboard() {
        assert_eq!(key_for('a'), Some((30, false)));
        assert_eq!(key_for('A'), Some((30, true)));
        assert_eq!(key_for('1'), Some((2, false)));
        assert_eq!(key_for('!'), Some((2, true)));
        assert_eq!(key_for('q'), Some((16, false)));
        assert_eq!(key_for('m'), Some((50, false)));
        assert_eq!(key_for('?'), Some((53, true)));
        assert_eq!(key_for(' '), Some((57, false)));
        assert_eq!(key_for('é'), None);
        assert_eq!(size_of::<Setup>(), 92);
        assert_eq!(size_of::<AbsSetup>(), 28);
        assert_eq!(UI_DEV_SETUP, 0x405c_5503);
        assert_eq!(UI_ABS_SETUP, 0x401c_5504);
        assert_eq!(UI_DEV_CREATE, 0x5501);
    }
}
