//! The input path: [`remote_core::ClientCommand`] into fast path input events
//! (MS-RDPBCGR 2.2.8.1.2, PRDRDP/05 §2 and §3).
//!
//! # Why there is no keyboard table here
//!
//! The webview sends a single byte XT set 1 scancode with bit 7 set for the
//! keys a PC keyboard prefixes with `E0`, which is the RFB QEMU Extended Key
//! Event convention (`crates/vnc-core/src/input/scancode.rs:1`). RDP wants the
//! bare code in the payload byte and the prefix as a flag on the event
//! (MS-RDPBCGR 2.2.8.1.2.2.1). Those are the same information packed
//! differently, so the whole XT to RDP mapping is [`split_scancode`], one line,
//! plus three exceptions that have each cost a different client a bug report:
//! Pause, PrintScreen and the held modifier state that decides between them.
//!
//! That is why D5 calls RDP scancode native and why this file has no lookup
//! table of its own to drift from the one the RFB path uses.
//!
//! # What is deliberately not here
//!
//! No socket and no channel. Every method returns events, and the run loop
//! encodes and queues them, which is what keeps "no write inside a `select!`
//! arm" structural (PRDRDP/00 R10) and what lets every rule below be tested
//! against a `Vec` with no runtime.

use std::collections::HashSet;

use bytes::Bytes;
use rdp_pdu::input::fastpath::{encode_fastpath_input, fastpath_input_size, FastPathInputEvent};
use rdp_pdu::input::{pointer_flags, pointer_x_flags, wheel_rotation_flags, WHEEL_DELTA};
use rdp_pdu::io::Writer;
use rdp_pdu::rdp::capabilities::input_flags;

use crate::error::Result;

/// The transport byte the webview sends for the Pause key.
///
/// `0xC6` decodes to `(extended, 0x46)`, which is ScrollLock with an `E0`
/// prefix, and that is not what Windows expects. The QEMU Extended Key Event
/// specification fixes Pause at `0xC6` and MS-RDPBCGR 2.2.8.1.2.2.1 transmits
/// it as a pair, so the two conventions have to be bridged here and nowhere
/// else (PRDRDP/05 §2.4).
pub const XT_PAUSE: u8 = 0xc6;

/// The transport byte for PrintScreen, which arrives as the plain SysRq code.
///
/// Real hardware sends `E0 2A E0 37` with no modifier, `E0 37` with Ctrl or
/// Shift, and plain `0x54` with Alt held. FreeRDP resolves it by defining
/// PrintScreen as extended `0x37` and SysRq as plain `0x54`, and Windows hosts
/// behave as that split predicts (PRDRDP/05 §2.5).
pub const XT_PRINT_SCREEN: u8 = 0x54;

/// The extended scancode PrintScreen becomes when Alt is not held.
const XT_PRINT_SCREEN_EXTENDED: u8 = 0x37;

/// Plain `0x38` is AltLeft and extended `0x38` is AltRight
/// (`crates/vnc-core/src/input/scancode.rs`).
const XT_ALT: u8 = 0x38;

/// The mask bits the webview uses for the wheel: 3 is up, 4 is down, 5 is
/// left and 6 is right (`crates/vnc-core/src/input/mod.rs:16`).
const WHEEL_BITS: u16 = 0b0111_1000;

/// Bit 7 is an RFB wire artefact, the extension marker of the extended
/// pointer event, and is never a button. It is masked off before anything
/// looks at the mask (PRDRDP/05 §3.4).
const LEGACY_BACK_BIT: u16 = 1 << 7;

/// Webview transport byte into the pair RDP wants: the `E0` prefix as a flag
/// and the bare make code as the payload byte (MS-RDPBCGR 2.2.8.1.2.2.1).
///
/// Base XT set 1 codes never reach `0x80`, the highest either table uses being
/// `0x7E`, so bit 7 means "extended" and nothing else (PRDRDP/05 §2.1).
#[must_use]
pub fn split_scancode(kc: u32) -> Option<(bool, u8)> {
    let kc = u8::try_from(kc).ok()?;
    Some((kc & 0x80 != 0, kc & 0x7f))
}

/// The key a `keys_down` entry describes: the extended bit and the code
/// together, never the code alone.
///
/// NumLock is plain `0x45` and the second half of Pause is also `0x45`, so a
/// held key set that folds the two together releases the wrong one
/// (PRDRDP/05 §2.2, §2.12 row 20).
const fn key_id(extended: bool, code: u8) -> u16 {
    ((extended as u16) << 8) | code as u16
}

/// The input half of one connection.
///
/// Holds the four pieces of state the rules below need between commands: the
/// held key set, the Pause flag that is deliberately not in it, the last
/// pointer mask, and the last position.
#[derive(Debug)]
pub struct Input {
    /// The desktop size, which every coordinate is clamped to. A resize race
    /// can produce a coordinate one frame out of date, and some servers treat
    /// an out of range pointer as a protocol error rather than clamping.
    desktop: (u16, u16),
    /// The server's `TS_INPUT_CAPABILITYSET.inputFlags`, which gates the
    /// horizontal wheel and the extended buttons (MS-RDPBCGR 2.2.7.1.6).
    server_flags: u16,
    /// Suppress every input event.
    view_only: bool,
    /// Held keys, indexed by [`key_id`].
    keys_down: HashSet<u16>,
    /// Pause has its own flag rather than a `keys_down` entry, because its
    /// second scancode collides with NumLock (PRDRDP/05 §2.4).
    pause_down: bool,
    /// The last button mask we acted on, for the edge computation.
    last_mask: u16,
    /// The last position we sent, so a move to where the pointer already is
    /// costs nothing.
    last_pos: Option<(u16, u16)>,
}

impl Input {
    /// A fresh input state for a desktop of this size and a server with these
    /// input capabilities.
    #[must_use]
    pub fn new(desktop: (u16, u16), server_flags: u16, view_only: bool) -> Self {
        Self {
            desktop,
            server_flags,
            view_only,
            keys_down: HashSet::new(),
            pause_down: false,
            last_mask: 0,
            last_pos: None,
        }
    }

    /// Adopt a new desktop size after a Deactivate All and a fresh capability
    /// exchange.
    pub fn set_desktop(&mut self, desktop: (u16, u16)) {
        self.desktop = desktop;
        self.last_pos = None;
    }

    /// Turn input off or on.
    pub fn set_view_only(&mut self, view_only: bool) {
        self.view_only = view_only;
    }

    /// Whether input is suppressed.
    #[must_use]
    pub const fn view_only(&self) -> bool {
        self.view_only
    }

    /// True when the server advertised the extended pointer event
    /// (`INPUT_FLAG_MOUSEX`).
    #[must_use]
    const fn wants_mousex(&self) -> bool {
        self.server_flags & input_flags::MOUSEX != 0
    }

    /// True when the server advertised the horizontal wheel
    /// (`TS_INPUT_FLAG_MOUSE_HWHEEL`). Windows Server 2008 R2 and older do
    /// not.
    #[must_use]
    const fn wants_hwheel(&self) -> bool {
        self.server_flags & input_flags::MOUSE_HWHEEL != 0
    }

    /// One `ClientCommand::Key` (PRDRDP/05 §2.3 to §2.6).
    ///
    /// A second press of a key already held is emitted as a bare repeat press
    /// with no synthetic release in front of it, which is what a physical
    /// keyboard does and what Windows expects.
    #[must_use]
    pub fn key(
        &mut self,
        keysym: u32,
        keycode: Option<u32>,
        down: bool,
    ) -> Vec<FastPathInputEvent> {
        if self.view_only {
            return Vec::new();
        }
        let Some(kc) = keycode.filter(|kc| *kc != 0) else {
            // No XT mapping: a composed character, a dead key result, an IME
            // commit or dictation. The unicode event carries what the user
            // meant even though no physical key describes it (PRDRDP/05 §2.6).
            return self.unicode(keysym, down);
        };

        if kc == u32::from(XT_PAUSE) {
            self.pause_down = down;
            return FastPathInputEvent::pause(down).to_vec();
        }

        let Some((mut extended, mut code)) = split_scancode(kc) else {
            tracing::trace!(kc, "a key code wider than one byte has no XT scancode");
            return Vec::new();
        };

        // PrintScreen arrives as SysRq. With Alt held it stays SysRq, so
        // Alt+SysRq keeps working; without it, it is extended 0x37.
        if !extended && code == XT_PRINT_SCREEN && !self.alt_held() {
            extended = true;
            code = XT_PRINT_SCREEN_EXTENDED;
        }

        if down {
            self.keys_down.insert(key_id(extended, code));
        } else {
            self.keys_down.remove(&key_id(extended, code));
        }
        match FastPathInputEvent::key(u16::from(code), down, extended, false) {
            Ok(event) => vec![event],
            Err(e) => {
                tracing::debug!(error = %e, code, "a key event that cannot be encoded");
                Vec::new()
            }
        }
    }

    /// True when either Alt key is held. Plain `0x38` is AltLeft and extended
    /// `0x38` is AltRight.
    fn alt_held(&self) -> bool {
        self.keys_down.contains(&key_id(false, XT_ALT))
            || self.keys_down.contains(&key_id(true, XT_ALT))
    }

    /// A character with no physical key behind it, as UTF-16 code units
    /// (MS-RDPBCGR 2.2.8.1.2.2.2).
    ///
    /// A press is followed immediately by its release, because there is no
    /// such thing as holding a unicode character.
    fn unicode(&mut self, keysym: u32, down: bool) -> Vec<FastPathInputEvent> {
        if !down {
            // The press already carried its own release.
            return Vec::new();
        }
        let Some(ch) = keysym_char(keysym) else {
            tracing::trace!(keysym, "a keysym with no scancode and no character");
            return Vec::new();
        };
        let mut events = Vec::with_capacity(4);
        let mut buf = [0u16; 2];
        for unit in ch.encode_utf16(&mut buf) {
            events.push(FastPathInputEvent::Unicode {
                flags: 0,
                code: *unit,
            });
            events.push(FastPathInputEvent::Unicode {
                flags: rdp_pdu::input::fastpath::keyboard_flags::RELEASE,
                code: *unit,
            });
        }
        events
    }

    /// Release every key and every button we believe is held
    /// (PRDRDP/05 §2.11).
    ///
    /// Called on blur, on turning view only on, and before a disconnect. A key
    /// the server thinks is held when the window loses focus repeats into the
    /// remote session forever.
    ///
    /// The buttons matter for the same reason and were missing. This used to
    /// release keys only and leave `last_mask` alone, so a button held at the
    /// moment focus went away stayed held on the server, and `last_mask` kept
    /// claiming it was: the next press of that button was no longer a
    /// transition, so it produced nothing at all, and the release after it
    /// arrived on its own. A right button stuck that way turns an ordinary
    /// left click into a left press underneath a held right button, which the
    /// desktop shows as a context menu.
    #[must_use]
    pub fn release_all(&mut self) -> Vec<FastPathInputEvent> {
        let mut events = Vec::with_capacity(self.keys_down.len() + 5);
        // Buttons before keys: a modifier that is still held while the button
        // goes up is what the server saw when it went down, so the gesture
        // ends the way it began.
        let (x, y) = self.last_pos.unwrap_or((0, 0));
        for (bit, kind) in [
            (0u16, ButtonKind::Left),
            (1, ButtonKind::Middle),
            (2, ButtonKind::Right),
        ] {
            if self.last_mask & (1 << bit) != 0 {
                events.push(button_event(kind, false, x, y));
            }
        }
        if self.wants_mousex() {
            for (bit, flag) in [
                (8u16, pointer_x_flags::BUTTON1_BACK),
                (9, pointer_x_flags::BUTTON2_FORWARD),
            ] {
                if self.last_mask & (1 << bit) != 0 {
                    events.push(FastPathInputEvent::MouseX { flags: flag, x, y });
                }
            }
        }
        self.last_mask = 0;
        // Sorted, so the wire is reproducible and a capture file diff means
        // something. A `HashSet` iterates in an order that changes per run.
        let mut held: Vec<u16> = self.keys_down.drain().collect();
        held.sort_unstable();
        for id in held {
            let extended = id & 0x100 != 0;
            let code = (id & 0xff) as u8;
            if let Ok(event) = FastPathInputEvent::key(u16::from(code), false, extended, false) {
                events.push(event);
            }
        }
        if self.pause_down {
            self.pause_down = false;
            events.extend(FastPathInputEvent::pause(false));
        }
        events
    }

    /// One `ClientCommand::Pointer` (PRDRDP/05 §3.2 to §3.4).
    ///
    /// The order inside one PDU is fixed and is not a preference: a move, then
    /// a release for every button that cleared, then a press for every button
    /// that set, then the wheel. A mask change from left to right in one event
    /// is a button swap, and pressing the new button before releasing the old
    /// one is a drag the user did not make.
    #[must_use]
    pub fn pointer(&mut self, x: u16, y: u16, mask: u16) -> Vec<FastPathInputEvent> {
        if self.view_only {
            // Nothing goes out, so nothing is held: remembering a mask we
            // never sent would make the first press after view only is turned
            // off compute its transitions against a fiction.
            self.last_mask = 0;
            return Vec::new();
        }
        let (max_x, max_y) = self.desktop;
        let x = x.min(max_x.saturating_sub(1));
        let y = y.min(max_y.saturating_sub(1));
        let mask = mask & !LEGACY_BACK_BIT;

        let mut events = Vec::new();
        if self.last_pos != Some((x, y)) {
            events.push(FastPathInputEvent::Mouse {
                flags: pointer_flags::MOVE,
                x,
                y,
            });
            self.last_pos = Some((x, y));
        }

        let cleared = self.last_mask & !mask;
        let set = mask & !self.last_mask;
        for (bit, event) in [
            (0u16, ButtonKind::Left),
            (1, ButtonKind::Middle),
            (2, ButtonKind::Right),
        ] {
            if cleared & (1 << bit) != 0 {
                events.push(button_event(event, false, x, y));
            }
        }
        for (bit, event) in [
            (0u16, ButtonKind::Left),
            (1, ButtonKind::Middle),
            (2, ButtonKind::Right),
        ] {
            if set & (1 << bit) != 0 {
                events.push(button_event(event, true, x, y));
            }
        }
        if self.wants_mousex() {
            for (bit, flag) in [
                (8u16, pointer_x_flags::BUTTON1_BACK),
                (9, pointer_x_flags::BUTTON2_FORWARD),
            ] {
                if cleared & (1 << bit) != 0 {
                    events.push(FastPathInputEvent::MouseX { flags: flag, x, y });
                }
            }
            for (bit, flag) in [
                (8u16, pointer_x_flags::BUTTON1_BACK),
                (9, pointer_x_flags::BUTTON2_FORWARD),
            ] {
                if set & (1 << bit) != 0 {
                    events.push(FastPathInputEvent::MouseX {
                        flags: pointer_x_flags::DOWN | flag,
                        x,
                        y,
                    });
                }
            }
        }

        // The wheel reacts to the rising edge only. The webview writes a
        // press and a release pair for one detent, which is the RFB
        // convention, and a falling wheel edge means nothing in RDP.
        for (bit, horizontal, delta) in [
            (3u16, false, WHEEL_DELTA),
            (4, false, -WHEEL_DELTA),
            (5, true, -WHEEL_DELTA),
            (6, true, WHEEL_DELTA),
        ] {
            if set & (1 << bit) == 0 {
                continue;
            }
            if horizontal && !self.wants_hwheel() {
                // Dropped silently rather than sent: a server that did not
                // advertise the horizontal wheel may treat the event as
                // malformed (PRDRDP/05 §3.3).
                continue;
            }
            match wheel_rotation_flags(delta, horizontal) {
                Ok(flags) => events.push(FastPathInputEvent::Mouse { flags, x, y }),
                Err(e) => tracing::debug!(error = %e, "a wheel rotation that cannot be encoded"),
            }
        }

        // The wheel bits are not buttons and must never become one, so they
        // are kept out of the remembered mask entirely.
        self.last_mask = mask & !WHEEL_BITS;
        events
    }

    /// The keys this input state believes are held, for a test and for a
    /// trace. Sorted, so it can be compared.
    #[must_use]
    pub fn held_keys(&self) -> Vec<u16> {
        let mut held: Vec<u16> = self.keys_down.iter().copied().collect();
        held.sort_unstable();
        held
    }
}

/// Which of the three ordinary buttons an event carries.
///
/// A named enum rather than a raw flag, because the specification's own names
/// read backwards: `PTRFLAGS_BUTTON2` is the **right** button and
/// `PTRFLAGS_BUTTON3` is the **middle** one, and getting them the other way
/// round swaps middle click and right click, which is the kind of bug that
/// survives a demo (PRDRDP/05 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ButtonKind {
    Left,
    Middle,
    Right,
}

fn button_event(button: ButtonKind, down: bool, x: u16, y: u16) -> FastPathInputEvent {
    let flag = match button {
        ButtonKind::Left => pointer_flags::BUTTON1_LEFT,
        ButtonKind::Middle => pointer_flags::BUTTON3_MIDDLE,
        ButtonKind::Right => pointer_flags::BUTTON2_RIGHT,
    };
    FastPathInputEvent::Mouse {
        flags: if down {
            pointer_flags::DOWN | flag
        } else {
            flag
        },
        x,
        y,
    }
}

/// The character an X11 keysym stands for, or `None` for a named key that has
/// none.
///
/// Two forms reach us: a keysym below `0x100` is the Latin-1 code point
/// itself, and `0x01000000 + cp` is the Unicode form the webview builds for
/// anything above it (`ui/src/render/keysyms.ts:132`). Everything in the
/// `0xff00` block is a named key and has a scancode instead.
#[must_use]
pub fn keysym_char(keysym: u32) -> Option<char> {
    /// The offset the RFB and X11 convention adds to a Unicode code point.
    const UNICODE_OFFSET: u32 = 0x0100_0000;
    let cp = if keysym >= UNICODE_OFFSET {
        keysym - UNICODE_OFFSET
    } else if (0x20..0x100).contains(&keysym) {
        keysym
    } else {
        return None;
    };
    char::from_u32(cp)
}

/// Encode a batch of events into one Fast-Path Input Event PDU
/// (MS-RDPBCGR 2.2.8.1.2).
///
/// Fast path input is its own framing: no TPKT, no X.224 and no MCS wrapper,
/// which is why this does not go through
/// [`crate::connection::activate::send_data_request`].
///
/// # Errors
///
/// [`RdpError::Pdu`](crate::error::RdpError::Pdu) when the batch cannot be
/// framed, which the caller has already made impossible by chunking.
pub fn encode(events: &[FastPathInputEvent]) -> Result<Bytes> {
    let mut out = Vec::with_capacity(fastpath_input_size(events)?);
    encode_fastpath_input(&mut Writer::new(&mut out), events)?;
    Ok(Bytes::from(out))
}

/// The most events one Fast-Path Input Event PDU can carry
/// (MS-RDPBCGR 2.2.8.1.2).
///
/// The run loop chunks a longer batch rather than returning an error into the
/// pump. A full keyboard release plus five buttons cannot reach it, so the
/// chunking is defensive only.
pub const MAX_EVENTS: usize = rdp_pdu::input::MAX_INPUT_EVENTS;

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input {
        Input::new(
            (1920, 1080),
            input_flags::MOUSEX | input_flags::MOUSE_HWHEEL,
            false,
        )
    }

    /// The whole XT to RDP mapping, in one assertion. Bit 7 of the transport
    /// byte is the `E0` prefix and nothing else.
    #[test]
    fn the_transport_byte_splits_into_the_prefix_flag_and_the_make_code() {
        assert_eq!(split_scancode(0x1e), Some((false, 0x1e)), "KeyA");
        assert_eq!(split_scancode(0xcd), Some((true, 0x4d)), "ArrowRight");
        assert_eq!(split_scancode(0x9c), Some((true, 0x1c)), "NumpadEnter");
        assert_eq!(split_scancode(0xdb), Some((true, 0x5b)), "MetaLeft");
        assert_eq!(split_scancode(0x1_00), None, "wider than the field");
    }

    /// Pause is one key and two RDP events, and it never enters the held key
    /// set: its second scancode is `0x45`, which is also NumLock, and a
    /// release all over a shared set would release the wrong one
    /// (PRDRDP/05 §2.4).
    #[test]
    fn pause_is_a_pair_and_stays_out_of_the_held_key_set() {
        use rdp_pdu::input::fastpath::keyboard_flags as k;
        let mut i = input();

        let down = i.key(0, Some(u32::from(XT_PAUSE)), true);
        assert_eq!(
            down,
            vec![
                FastPathInputEvent::Scancode {
                    flags: k::EXTENDED1,
                    code: 0x1d
                },
                FastPathInputEvent::Scancode {
                    flags: 0,
                    code: 0x45
                },
            ]
        );
        assert!(i.held_keys().is_empty(), "pause has its own flag");

        // NumLock is plain 0x45 and must not be confused with it.
        let _ = i.key(0, Some(0x45), true);
        assert_eq!(i.held_keys(), vec![0x0045]);

        let all = i.release_all();
        assert!(all.contains(&FastPathInputEvent::Scancode {
            flags: k::RELEASE,
            code: 0x45
        }));
        assert!(all.contains(&FastPathInputEvent::Scancode {
            flags: k::RELEASE | k::EXTENDED1,
            code: 0x1d
        }));
    }

    /// PrintScreen arrives as SysRq and becomes extended `0x37` unless Alt is
    /// held, which is the split FreeRDP defines and Windows hosts behave as
    /// (PRDRDP/05 §2.5).
    #[test]
    fn print_screen_becomes_extended_unless_alt_is_held() {
        use rdp_pdu::input::fastpath::keyboard_flags as k;
        let mut i = input();

        assert_eq!(
            i.key(0, Some(u32::from(XT_PRINT_SCREEN)), true),
            vec![FastPathInputEvent::Scancode {
                flags: k::EXTENDED,
                code: 0x37
            }]
        );
        let _ = i.key(0, Some(u32::from(XT_PRINT_SCREEN)), false);

        let _ = i.key(0, Some(u32::from(XT_ALT)), true);
        assert_eq!(
            i.key(0, Some(u32::from(XT_PRINT_SCREEN)), true),
            vec![FastPathInputEvent::Scancode {
                flags: 0,
                code: 0x54
            }],
            "alt+sysrq keeps working"
        );
    }

    /// A button held when everything is released does not stay held, and is
    /// pressable again afterwards.
    ///
    /// Releasing keys only was the whole of this method, and it left
    /// `last_mask` claiming the button was down. The next press then computed
    /// no transition and sent nothing, so the button appeared dead, and its
    /// release arrived later on its own. On the right button that reads as an
    /// ordinary left click opening a context menu.
    #[test]
    fn releasing_everything_releases_a_held_button_too() {
        let mut i = input();
        let _ = i.pointer(10, 10, 0b100);

        assert_eq!(
            i.release_all(),
            vec![FastPathInputEvent::Mouse {
                flags: pointer_flags::BUTTON2_RIGHT,
                x: 10,
                y: 10
            }],
            "the held right button goes up"
        );

        assert_eq!(
            i.pointer(10, 10, 0b100),
            vec![FastPathInputEvent::Mouse {
                flags: pointer_flags::DOWN | pointer_flags::BUTTON2_RIGHT,
                x: 10,
                y: 10
            }],
            "and pressing it again is a fresh press, not a no-op"
        );
    }

    /// View only remembers nothing, because it sends nothing.
    ///
    /// Holding a button while view only is on and letting go before it is
    /// turned off used to leave `last_mask` set from a press that never went
    /// out. The first real press afterwards then carried a release for a
    /// button the server never saw go down.
    #[test]
    fn view_only_does_not_remember_a_mask_it_never_sent() {
        let mut i = input();
        i.set_view_only(true);
        assert!(i.pointer(10, 10, 0b100).is_empty());
        i.set_view_only(false);

        assert_eq!(
            i.pointer(10, 10, 0b001),
            vec![
                FastPathInputEvent::Mouse {
                    flags: pointer_flags::MOVE,
                    x: 10,
                    y: 10
                },
                FastPathInputEvent::Mouse {
                    flags: pointer_flags::DOWN | pointer_flags::BUTTON1_LEFT,
                    x: 10,
                    y: 10
                }
            ],
            "a left press, with no phantom right release in front of it"
        );
    }

    /// Release before press, in that order, inside one batch. A mask change
    /// from left to right is a button swap, and the other order is a drag the
    /// user did not make.
    #[test]
    fn a_button_swap_releases_before_it_presses() {
        let mut i = input();
        let _ = i.pointer(10, 10, 0b001);
        let events = i.pointer(10, 10, 0b100);
        assert_eq!(
            events,
            vec![
                FastPathInputEvent::Mouse {
                    flags: pointer_flags::BUTTON1_LEFT,
                    x: 10,
                    y: 10
                },
                FastPathInputEvent::Mouse {
                    flags: pointer_flags::DOWN | pointer_flags::BUTTON2_RIGHT,
                    x: 10,
                    y: 10
                },
            ],
            "no move, because the position did not change"
        );
    }

    /// The specification's own constant names read backwards, so the mask each
    /// of our buttons produces is pinned here. Middle is `BUTTON3` and right
    /// is `BUTTON2`.
    #[test]
    fn middle_and_right_are_not_swapped() {
        let mut i = input();
        let events = i.pointer(0, 0, 0b010);
        assert!(events.contains(&FastPathInputEvent::Mouse {
            flags: pointer_flags::DOWN | pointer_flags::BUTTON3_MIDDLE,
            x: 0,
            y: 0
        }));
    }

    /// One detent up is `+120` and one down is `-120`, the sign living in the
    /// rotation's own top bit. Only the rising edge produces anything, so the
    /// press and release pair the webview writes is one wheel event.
    #[test]
    fn the_wheel_fires_on_the_rising_edge_only() {
        use rdp_pdu::input::wheel_rotation;
        let mut i = input();
        let _ = i.pointer(5, 5, 0);

        let up = i.pointer(5, 5, 1 << 3);
        assert_eq!(up.len(), 1, "{up:?}");
        let FastPathInputEvent::Mouse { flags, .. } = up[0] else {
            panic!("a wheel event");
        };
        assert_ne!(flags & pointer_flags::WHEEL, 0);
        assert_eq!(wheel_rotation(flags), WHEEL_DELTA);

        // The falling edge of the same pair produces nothing at all, and the
        // wheel bit never becomes a button press.
        assert!(i.pointer(5, 5, 0).is_empty());

        let down = i.pointer(5, 5, 1 << 4);
        let FastPathInputEvent::Mouse { flags, .. } = down[0] else {
            panic!("a wheel event");
        };
        assert_eq!(wheel_rotation(flags), -WHEEL_DELTA);
    }

    /// A capability the server did not advertise is dropped silently rather
    /// than sent: a server that did not ask for the horizontal wheel or the
    /// extended buttons may treat the event as malformed.
    #[test]
    fn capabilities_the_server_did_not_advertise_are_dropped() {
        let mut i = Input::new((800, 600), 0, false);
        let _ = i.pointer(1, 1, 0);
        assert!(
            i.pointer(1, 1, 1 << 5).is_empty(),
            "no horizontal wheel without TS_INPUT_FLAG_MOUSE_HWHEEL"
        );
        assert!(
            i.pointer(1, 1, 1 << 8).is_empty(),
            "no extended buttons without INPUT_FLAG_MOUSEX"
        );

        let mut i = input();
        let _ = i.pointer(1, 1, 0);
        let back = i.pointer(1, 1, 1 << 8);
        assert_eq!(
            back,
            vec![FastPathInputEvent::MouseX {
                flags: pointer_x_flags::DOWN | pointer_x_flags::BUTTON1_BACK,
                x: 1,
                y: 1
            }]
        );
    }

    /// Bit 7 is an RFB wire artefact and must never become a button.
    #[test]
    fn the_legacy_back_marker_is_not_a_button() {
        let mut i = input();
        let _ = i.pointer(2, 2, 0);
        assert!(i.pointer(2, 2, LEGACY_BACK_BIT).is_empty());
    }

    /// A coordinate one frame out of date is clamped rather than sent: some
    /// servers treat an out of range pointer as a protocol error.
    #[test]
    fn a_coordinate_past_the_desktop_is_clamped() {
        let mut i = Input::new((640, 480), 0, false);
        let events = i.pointer(9999, 9999, 0);
        assert_eq!(
            events,
            vec![FastPathInputEvent::Mouse {
                flags: pointer_flags::MOVE,
                x: 639,
                y: 479
            }]
        );
        // And a move to where the pointer already is costs nothing.
        assert!(i.pointer(639, 479, 0).is_empty());
    }

    /// A key with no XT mapping still types, through the unicode event, with
    /// its release in the same batch: there is no such thing as holding a
    /// unicode character (PRDRDP/05 §2.6).
    #[test]
    fn a_key_with_no_scancode_becomes_a_unicode_event_pair() {
        use rdp_pdu::input::fastpath::keyboard_flags as k;
        let mut i = input();
        // U+00E9, e acute, which a dead key composes and no scancode names.
        let events = i.key(0x0100_00e9, None, true);
        assert_eq!(
            events,
            vec![
                FastPathInputEvent::Unicode {
                    flags: 0,
                    code: 0x00e9
                },
                FastPathInputEvent::Unicode {
                    flags: k::RELEASE,
                    code: 0x00e9
                },
            ]
        );
        assert!(i.key(0x0100_00e9, None, false).is_empty());

        // A character outside the BMP is a surrogate pair, in order.
        let events = i.key(0x0100_0000 + 0x1_f600, None, true);
        assert_eq!(events.len(), 4);

        // A named key with no scancode and no character produces nothing
        // rather than a wrong keystroke.
        assert!(i.key(0xff08, None, true).is_empty(), "XK_BackSpace");
    }

    /// View only suppresses every input PDU, which is the whole of the
    /// setting.
    #[test]
    fn view_only_suppresses_everything() {
        let mut i = input();
        i.set_view_only(true);
        assert!(i.key(0, Some(0x1e), true).is_empty());
        assert!(i.pointer(1, 2, 0b001).is_empty());
    }

    /// The batch reaches the wire as one Fast-Path Input Event PDU, and the
    /// framer reads it back as a fast path frame.
    #[test]
    fn a_batch_encodes_into_one_fast_path_pdu() {
        let mut i = input();
        let events = i.pointer(100, 200, 0b001);
        let bytes = encode(&events).expect("encodes");
        assert_eq!(bytes[0] & 0x03, 0, "action FASTPATH");

        use rdp_pdu::io::Decode;
        let decoded =
            rdp_pdu::input::fastpath::FastPathInputPdu::decode(&mut rdp_pdu::Reader::new(&bytes))
                .expect("parses");
        assert_eq!(decoded.events, events);
    }
}
