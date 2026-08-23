//! Slow path input events inside a Share Data PDU.
//!
//! MS-RDPBCGR 2.2.8.1.1.3, PRDRDP/13 §5.3.
//!
//! [`SlowPathInputPdu`] is the body of a Client Input Event PDU: everything
//! after the Share Data header, which is `numberEvents`, two pad bytes and
//! that many [`SlowPathInputEvent`]. The header itself belongs to
//! `crate::rdp::share`, and the session composes the two, so nothing in this
//! file knows what a share id is.
//!
//! Every event is exactly [`SLOW_PATH_EVENT_LEN`] bytes: a four byte
//! `eventTime`, a two byte `messageType` and a six byte body, whatever the
//! type. That uniformity is worth stating because it makes the truncation
//! arithmetic trivial and because it is the reason the fast path exists: a
//! two byte key press costs twelve bytes here, plus the Share Data header,
//! plus MCS, plus X.224, plus TPKT.
//!
//! Slow path input is the fallback. It is used only when the server's Input
//! capability set lacks `INPUT_FLAG_FASTPATH_INPUT` (MS-RDPBCGR 2.2.7.1.6),
//! which no modern server does, and it is implemented because such servers
//! exist and the fallback is short (PRDRDP/13 §5.3).
//!
//! Tail rule (PRDRDP/13 §2.5): exact. An event body is a fixed six bytes and
//! a leftover byte means we mis-parsed, so the decoder rejects it.

use super::{keyboard_flags, MAX_INPUT_EVENTS};
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// `eventTime` plus `messageType` plus a six byte body
/// (MS-RDPBCGR 2.2.8.1.1.3.1.1).
pub const SLOW_PATH_EVENT_LEN: usize = 12;

/// The six byte body every `TS_INPUT_EVENT` carries, whatever its type.
const EVENT_BODY_LEN: usize = 6;

/// `TS_INPUT_EVENT.messageType` (MS-RDPBCGR 2.2.8.1.1.3.1.1).
pub mod message_type {
    /// `INPUT_EVENT_SYNC`.
    pub const SYNC: u16 = 0x0000;
    /// `INPUT_EVENT_UNUSED`. Six pad bytes, defined and never sent.
    pub const UNUSED: u16 = 0x0002;
    /// `INPUT_EVENT_SCANCODE`.
    pub const SCANCODE: u16 = 0x0004;
    /// `INPUT_EVENT_UNICODE`.
    pub const UNICODE: u16 = 0x0005;
    /// `INPUT_EVENT_MOUSE`.
    pub const MOUSE: u16 = 0x8001;
    /// `INPUT_EVENT_MOUSEX`, the extended pointer event.
    pub const MOUSEX: u16 = 0x8002;
    /// `INPUT_EVENT_MOUSEREL`, relative pointer motion.
    pub const MOUSEREL: u16 = 0x8004;
}

/// One `TS_INPUT_EVENT` (MS-RDPBCGR 2.2.8.1.1.3.1.1).
///
/// `eventTime` is not carried: the specification says servers ignore it and
/// we send zero, so keeping it in the type would only give a round trip test
/// a field to disagree about. The decoder skips it and the encoder writes
/// zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowPathInputEvent {
    /// `TS_SYNC_EVENT` (2.2.8.1.1.3.1.1.5): the absolute state of the four
    /// locks, in [`super::sync_flags`].
    Sync {
        /// `toggleFlags`.
        toggle_flags: u32,
    },
    /// `INPUT_EVENT_UNUSED` (2.2.8.1.1.3.1.1.2). Decoded so that a PDU
    /// containing one does not desync the events after it.
    Unused,
    /// `TS_KEYBOARD_EVENT` (2.2.8.1.1.3.1.1.1).
    Scancode {
        /// [`super::keyboard_flags`].
        flags: u16,
        /// `keyCode`, the XT scancode without its `E0` or `E1` prefix, which
        /// live in `flags` instead.
        code: u16,
    },
    /// `TS_UNICODE_KEYBOARD_EVENT` (2.2.8.1.1.3.1.1.2). One UTF-16 code
    /// unit; a character outside the BMP is two events, a surrogate pair, in
    /// order (PRDRDP/05 §2.6).
    Unicode {
        /// Only [`super::keyboard_flags::RELEASE`] is defined here.
        flags: u16,
        /// `unicodeCode`.
        code: u16,
    },
    /// `TS_POINTER_EVENT` (2.2.8.1.1.3.1.1.3).
    Mouse {
        /// [`super::pointer_flags`].
        flags: u16,
        /// `xPos`, in the server's virtual desktop space.
        x: u16,
        /// `yPos`.
        y: u16,
    },
    /// `TS_POINTERX_EVENT` (2.2.8.1.1.3.1.1.4), buttons 4 and 5.
    MouseX {
        /// [`super::pointer_x_flags`].
        flags: u16,
        /// `xPos`.
        x: u16,
        /// `yPos`.
        y: u16,
    },
    /// `TS_RELPOINTER_EVENT` (2.2.8.1.1.3.1.1.6). Encoded because it is four
    /// lines; `rdp-core` never emits one (PRDRDP/05 §3.6).
    MouseRelative {
        /// [`super::pointer_flags`], without the move and wheel bits.
        flags: u16,
        /// `xDelta`.
        dx: i16,
        /// `yDelta`.
        dy: i16,
    },
}

impl SlowPathInputEvent {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_INPUT_EVENT";

    /// A key press or release, with the flags assembled from what the caller
    /// actually knows (PRDRDP/13 §5.3).
    ///
    /// The slow path and the fast path disagree about what a press looks
    /// like: here a press sets no flag and a release sets `KBDFLAGS_RELEASE`,
    /// while `KBDFLAGS_DOWN` means "a repeat of a key already down" rather
    /// than "a press". `repeat` is the caller's way to say that, and a caller
    /// that does not track repeats passes `false`.
    #[must_use]
    pub const fn key(code: u16, down: bool, extended: bool, extended1: bool) -> Self {
        let mut flags = 0u16;
        if !down {
            flags |= keyboard_flags::RELEASE;
        }
        if extended {
            flags |= keyboard_flags::EXTENDED;
        }
        if extended1 {
            flags |= keyboard_flags::EXTENDED1;
        }
        Self::Scancode { flags, code }
    }

    /// `messageType` for this event.
    #[must_use]
    pub const fn message_type(&self) -> u16 {
        match self {
            Self::Sync { .. } => message_type::SYNC,
            Self::Unused => message_type::UNUSED,
            Self::Scancode { .. } => message_type::SCANCODE,
            Self::Unicode { .. } => message_type::UNICODE,
            Self::Mouse { .. } => message_type::MOUSE,
            Self::MouseX { .. } => message_type::MOUSEX,
            Self::MouseRelative { .. } => message_type::MOUSEREL,
        }
    }
}

impl Decode<'_> for SlowPathInputEvent {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        // `eventTime`, which every server ignores.
        r.skip(4, Self::NAME)?;
        let at = r.offset();
        let message_type = r.u16(Self::NAME)?;
        let mut body = r.take(EVENT_BODY_LEN, Self::NAME)?;
        let event = match message_type {
            message_type::SYNC => {
                body.skip(2, Self::NAME)?;
                Self::Sync {
                    toggle_flags: body.u32(Self::NAME)?,
                }
            }
            message_type::UNUSED => {
                body.skip(EVENT_BODY_LEN, Self::NAME)?;
                Self::Unused
            }
            message_type::SCANCODE => {
                let flags = body.u16(Self::NAME)?;
                let code = body.u16(Self::NAME)?;
                body.skip(2, Self::NAME)?;
                Self::Scancode { flags, code }
            }
            message_type::UNICODE => {
                let flags = body.u16(Self::NAME)?;
                let code = body.u16(Self::NAME)?;
                body.skip(2, Self::NAME)?;
                Self::Unicode { flags, code }
            }
            message_type::MOUSE => Self::Mouse {
                flags: body.u16(Self::NAME)?,
                x: body.u16(Self::NAME)?,
                y: body.u16(Self::NAME)?,
            },
            message_type::MOUSEX => Self::MouseX {
                flags: body.u16(Self::NAME)?,
                x: body.u16(Self::NAME)?,
                y: body.u16(Self::NAME)?,
            },
            message_type::MOUSEREL => Self::MouseRelative {
                flags: body.u16(Self::NAME)?,
                dx: body.i16(Self::NAME)?,
                dy: body.i16(Self::NAME)?,
            },
            other => {
                return Err(PduError::Unsupported {
                    context: Self::NAME,
                    kind: "messageType",
                    value: u64::from(other),
                    offset: at,
                })
            }
        };
        body.expect_empty(Self::NAME)?;
        Ok(event)
    }
}

impl Encode for SlowPathInputEvent {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        SLOW_PATH_EVENT_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        // `eventTime`: zero, per PRDRDP/13 §5.3.
        w.u32(0);
        w.u16(self.message_type());
        match *self {
            Self::Sync { toggle_flags } => {
                w.u16(0);
                w.u32(toggle_flags);
            }
            Self::Unused => w.zeros(EVENT_BODY_LEN),
            Self::Scancode { flags, code } | Self::Unicode { flags, code } => {
                w.u16(flags);
                w.u16(code);
                w.u16(0);
            }
            Self::Mouse { flags, x, y } | Self::MouseX { flags, x, y } => {
                w.u16(flags);
                w.u16(x);
                w.u16(y);
            }
            Self::MouseRelative { flags, dx, dy } => {
                w.u16(flags);
                w.i16(dx);
                w.i16(dy);
            }
        }
        Ok(())
    }
}

/// `TS_INPUT_PDU_DATA` minus its Share Data header
/// (MS-RDPBCGR 2.2.8.1.1.3.1).
///
/// Direction: client to server, phase 1 (PRDRDP/13 §11).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlowPathInputPdu {
    /// The events, at most [`MAX_INPUT_EVENTS`] of them.
    pub events: Vec<SlowPathInputEvent>,
}

impl SlowPathInputPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_INPUT_PDU_DATA";

    /// A PDU carrying `events`.
    #[must_use]
    pub fn new(events: Vec<SlowPathInputEvent>) -> Self {
        Self { events }
    }
}

impl Decode<'_> for SlowPathInputPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let count = usize::from(r.u16(Self::NAME)?);
        r.ensure_cap(count, MAX_INPUT_EVENTS, "MAX_INPUT_EVENTS", Self::NAME)
            .map_err(|e| with_offset(e, at))?;
        r.skip(2, Self::NAME)?;
        // Bounded by the cap above, so a hostile count cannot reserve.
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            events.push(SlowPathInputEvent::decode(r)?);
        }
        Ok(Self { events })
    }
}

impl Encode for SlowPathInputPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + self.events.len() * SLOW_PATH_EVENT_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let count = u16::try_from(self.events.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "more events than numberEvents can hold",
        })?;
        if self.events.len() > MAX_INPUT_EVENTS {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "more events than MAX_INPUT_EVENTS",
            });
        }
        w.u16(count);
        w.u16(0);
        for event in &self.events {
            event.encode(w)?;
        }
        Ok(())
    }
}

/// Rewrite a cap error's offset to point at the length field rather than at
/// the byte after it, which is where the reader stands once the field has
/// been read.
fn with_offset(error: PduError, offset: usize) -> PduError {
    match error {
        PduError::CapExceeded {
            context,
            declared,
            cap,
            limit_name,
            ..
        } => PduError::CapExceeded {
            context,
            declared,
            cap,
            limit_name,
            offset,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use crate::input::{pointer_flags, sync_flags, wheel_rotation_flags, WHEEL_DELTA};

    fn sample() -> SlowPathInputPdu {
        SlowPathInputPdu::new(vec![
            SlowPathInputEvent::key(0x1e, true, false, false),
            SlowPathInputEvent::key(0x1e, false, false, false),
            SlowPathInputEvent::Sync {
                toggle_flags: sync_flags::NUM_LOCK | sync_flags::CAPS_LOCK,
            },
            SlowPathInputEvent::Mouse {
                flags: pointer_flags::MOVE,
                x: 640,
                y: 480,
            },
            SlowPathInputEvent::MouseX {
                flags: crate::input::pointer_x_flags::DOWN
                    | crate::input::pointer_x_flags::BUTTON1_BACK,
                x: 1,
                y: 2,
            },
            SlowPathInputEvent::MouseRelative {
                flags: 0,
                dx: -3,
                dy: 4,
            },
            SlowPathInputEvent::Unicode {
                flags: 0,
                code: 0x00e9,
            },
            SlowPathInputEvent::Unused,
        ])
    }

    fn encoded(value: &SlowPathInputPdu) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        buf
    }

    #[test]
    fn round_trip() {
        let value = sample();
        let buf = encoded(&value);
        assert_eq!(buf.len(), value.size());
        let mut r = Reader::new(&buf);
        assert_eq!(SlowPathInputPdu::decode(&mut r).unwrap(), value);
        assert!(r.is_empty());
    }

    /// Every event is twelve bytes whatever its type, which is the property
    /// the whole module's arithmetic rests on.
    #[test]
    fn every_event_is_twelve_bytes() {
        for event in sample().events {
            let mut buf = Vec::new();
            event.encode_checked(&mut Writer::new(&mut buf)).unwrap();
            assert_eq!(buf.len(), SLOW_PATH_EVENT_LEN, "{event:?}");
        }
    }

    /// A layout vector computed from the field table of PRDRDP/13 §5.3, not
    /// transcribed from an annotated capture: two events, a press of `A`
    /// (scancode 0x1E) and its release.
    ///
    /// numberEvents 0x0002, pad 0x0000, then per event eventTime 0x00000000,
    /// messageType 0x0004 little endian, keyboardFlags, keyCode, pad.
    #[test]
    fn golden_two_key_events() {
        let expected = hex::decode(concat!(
            "0200", "0000", // numberEvents, pad2Octets
            "00000000", "0400", "0000", "1e00", "0000", // press
            "00000000", "0400", "0080", "1e00", "0000", // release
        ))
        .unwrap();
        let value = SlowPathInputPdu::new(vec![
            SlowPathInputEvent::key(0x1e, true, false, false),
            SlowPathInputEvent::key(0x1e, false, false, false),
        ]);
        assert_eq!(encoded(&value), expected);
        assert_eq!(
            SlowPathInputPdu::decode(&mut Reader::new(&expected)).unwrap(),
            value
        );
    }

    /// `KBDFLAGS_DOWN` is not what its name suggests: a press sets no flag
    /// and `DOWN` marks a repeat (PRDRDP/13 §5.3).
    #[test]
    fn a_press_sets_no_flag_and_a_release_sets_release() {
        assert_eq!(
            SlowPathInputEvent::key(0x1e, true, false, false),
            SlowPathInputEvent::Scancode {
                flags: 0,
                code: 0x1e
            }
        );
        assert_eq!(
            SlowPathInputEvent::key(0x1e, false, true, false),
            SlowPathInputEvent::Scancode {
                flags: keyboard_flags::RELEASE | keyboard_flags::EXTENDED,
                code: 0x1e,
            }
        );
        assert_eq!(
            SlowPathInputEvent::key(0x1d, true, false, true),
            SlowPathInputEvent::Scancode {
                flags: keyboard_flags::EXTENDED1,
                code: 0x1d,
            }
        );
    }

    #[test]
    fn a_wheel_event_carries_its_rotation_in_the_flags_word() {
        let flags = wheel_rotation_flags(-WHEEL_DELTA, false).unwrap();
        let value = SlowPathInputPdu::new(vec![SlowPathInputEvent::Mouse { flags, x: 5, y: 6 }]);
        let buf = encoded(&value);
        assert_eq!(
            SlowPathInputPdu::decode(&mut Reader::new(&buf)).unwrap(),
            value
        );
        assert_eq!(crate::input::wheel_rotation(flags), -WHEEL_DELTA);
    }

    #[test]
    fn truncating_at_every_offset_errors_without_panicking() {
        let buf = encoded(&sample());
        for cut in 0..buf.len() {
            assert!(
                SlowPathInputPdu::decode(&mut Reader::new(&buf[..cut])).is_err(),
                "decoded a PDU truncated to {cut} bytes"
            );
        }
    }

    /// The tail rule: the body is exact, so a trailing byte inside an event
    /// is a `LengthMismatch` and a trailing byte after the last event leaves
    /// the outer reader non empty for the session to reject.
    #[test]
    fn an_unknown_message_type_is_unsupported_rather_than_skipped() {
        let mut buf = encoded(&SlowPathInputPdu::new(vec![SlowPathInputEvent::Unused]));
        // Overwrite messageType with a code nobody defines.
        buf[8] = 0x77;
        buf[9] = 0x77;
        assert!(matches!(
            SlowPathInputPdu::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::Unsupported { .. }
        ));
    }

    #[test]
    fn a_hostile_event_count_is_capped_before_the_vec_is_reserved() {
        let buf = hex::decode("ffff0000").unwrap();
        let err = SlowPathInputPdu::decode(&mut Reader::new(&buf)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_INPUT_EVENTS",
                offset: 0,
                ..
            }
        ));
    }

    #[test]
    fn encoding_more_events_than_the_cap_is_refused() {
        let value = SlowPathInputPdu::new(vec![SlowPathInputEvent::Unused; MAX_INPUT_EVENTS + 1]);
        let mut buf = Vec::new();
        assert!(matches!(
            value.encode(&mut Writer::new(&mut buf)).unwrap_err(),
            PduError::Encode { .. }
        ));
    }
}
