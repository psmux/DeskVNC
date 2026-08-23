//! Fast path input events and their framing.
//!
//! MS-RDPBCGR 2.2.8.1.2, PRDRDP/13 §5.4.
//!
//! Fast path replaces TPKT, X.224 and MCS with two or three bytes, so a key
//! press costs four bytes on the wire instead of twenty six. The header is
//! one byte holding the action, the event count and the security flags, then
//! a one or two byte big endian length covering the whole PDU.
//!
//! The length is big endian, which is the opposite of nearly everything else
//! in RDP. The mnemonic is that it replaces the TPKT length and inherits its
//! endianness (PRDRDP/13 §5.4). [`read_fastpath_length`] and
//! [`write_fastpath_length`] are shared with the fast path *output* header of
//! 2.2.9.1.2, which §5.5 defines as "as in §5.4"; `crate::update::fastpath`
//! calls them rather than restating the encoding.
//!
//! Byte zero of any inbound PDU decides the framing for the whole read loop:
//! `0x03` is TPKT version 3, whose low two bits are
//! [`action::X224`], and anything with action bits `00` is fast path. One
//! `peek_u8` is the entire decision (PRDRDP/13 §5.4).
//!
//! Tail rule (PRDRDP/13 §2.5): exact. [`FastPathInputPdu::decode`] bounds the
//! events by the declared length and rejects a leftover byte.

use super::MAX_INPUT_EVENTS;
use crate::io::limits::MAX_FASTPATH_LEN;
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// The two bit `action` field in bits 0 and 1 of the header byte
/// (MS-RDPBCGR 2.2.8.1.2).
pub mod action {
    /// `FASTPATH_INPUT_ACTION_FASTPATH`.
    pub const FASTPATH: u8 = 0x0;
    /// `FASTPATH_INPUT_ACTION_X224`. The value is 3 because byte zero of a
    /// slow path PDU is the TPKT version, `0x03`, whose low two bits are 3.
    pub const X224: u8 = 0x3;
    /// The mask that extracts the action from the header byte.
    pub const MASK: u8 = 0x03;
}

/// The two bit `flags` field in bits 6 and 7 of the header byte, shared by
/// the input header (2.2.8.1.2) and the output header (2.2.9.1.2).
///
/// Both are about standard RDP security, which PRDRDP/03 §13.1 refuses, so
/// neither is ever set on a connection this client makes. They are named
/// because the decoder has to recognise them in order to refuse them: the
/// `fipsInformation` and `dataSignature` fields they imply sit between the
/// length and the payload, and a decoder that ignores the flags reads a
/// signature as an event.
pub mod header_flags {
    /// `FASTPATH_INPUT_SECURE_CHECKSUM` / `FASTPATH_OUTPUT_SECURE_CHECKSUM`.
    pub const SECURE_CHECKSUM: u8 = 0x1;
    /// `FASTPATH_INPUT_ENCRYPTED` / `FASTPATH_OUTPUT_ENCRYPTED`.
    pub const ENCRYPTED: u8 = 0x2;
    /// Where the field sits in the header byte.
    pub const SHIFT: u8 = 6;
}

/// `eventCode`, bits 5 to 7 of an event header byte (MS-RDPBCGR 2.2.8.1.2.2).
pub mod event_code {
    /// `FASTPATH_INPUT_EVENT_SCANCODE`.
    pub const SCANCODE: u8 = 0x0;
    /// `FASTPATH_INPUT_EVENT_MOUSE`.
    pub const MOUSE: u8 = 0x1;
    /// `FASTPATH_INPUT_EVENT_MOUSEX`.
    pub const MOUSEX: u8 = 0x2;
    /// `FASTPATH_INPUT_EVENT_SYNC`.
    pub const SYNC: u8 = 0x3;
    /// `FASTPATH_INPUT_EVENT_UNICODE`.
    pub const UNICODE: u8 = 0x4;
    /// `FASTPATH_INPUT_EVENT_RELMOUSE`.
    pub const RELMOUSE: u8 = 0x5;
    /// `FASTPATH_INPUT_EVENT_QOE_TIMESTAMP`.
    pub const QOE_TIMESTAMP: u8 = 0x6;
    /// Where the code sits in the event header byte.
    pub const SHIFT: u8 = 5;
    /// The mask that extracts `eventFlags`, bits 0 to 4.
    pub const FLAGS_MASK: u8 = 0x1f;
}

/// `eventFlags` of a fast path keyboard event
/// (MS-RDPBCGR 2.2.8.1.2.2.1).
///
/// Note the absence of a down flag. A press sets nothing and a release sets
/// [`RELEASE`](keyboard_flags::RELEASE), where the slow path form of the
/// same event has a `KBDFLAGS_DOWN` that means something else again
/// ([`super::keyboard_flags::DOWN`]).
pub mod keyboard_flags {
    /// `FASTPATH_INPUT_KBDFLAGS_RELEASE`.
    pub const RELEASE: u8 = 0x01;
    /// `FASTPATH_INPUT_KBDFLAGS_EXTENDED`, the `E0` prefix.
    pub const EXTENDED: u8 = 0x02;
    /// `FASTPATH_INPUT_KBDFLAGS_EXTENDED1`, the `E1` prefix, Pause only.
    pub const EXTENDED1: u8 = 0x04;
}

/// Bit 7 of `length1` selects the two byte form of the length
/// (MS-RDPBCGR 2.2.8.1.2, 2.2.9.1.2).
pub const FASTPATH_LONG_LENGTH: u8 = 0x80;

/// The largest PDU the one byte length form can describe.
pub const MAX_SHORT_FASTPATH_LEN: usize = 0x7f;

/// The number of events one header byte can state without the extension
/// byte (MS-RDPBCGR 2.2.8.1.2, PRDRDP/05 §2.3: a four bit field).
pub const MAX_COMPACT_EVENTS: usize = 15;

/// Read the one or two byte big endian length, returning the whole PDU's
/// length including the header byte and the length bytes themselves
/// (MS-RDPBCGR 2.2.8.1.2, 2.2.9.1.2).
pub fn read_fastpath_length(r: &mut Reader<'_>, context: &'static str) -> PduResult<usize> {
    let at = r.offset();
    let first = r.u8(context)?;
    let length = if first & FASTPATH_LONG_LENGTH == 0 {
        usize::from(first)
    } else {
        let second = r.u8(context)?;
        (usize::from(first & !FASTPATH_LONG_LENGTH) << 8) | usize::from(second)
    };
    r.ensure_cap(length, MAX_FASTPATH_LEN, "MAX_FASTPATH_LEN", context)?;
    // The header byte plus at least one length byte are already spent, so a
    // PDU shorter than that is a length field that disagrees with itself.
    let minimum = if first & FASTPATH_LONG_LENGTH == 0 {
        2
    } else {
        3
    };
    if length < minimum {
        return Err(PduError::InvalidField {
            context,
            field: "length",
            value: length as u64,
            offset: at,
        });
    }
    Ok(length)
}

/// The total PDU length and the width of its length field, for a PDU whose
/// header byte and payload come to `inner` bytes.
///
/// The choice is self referential, because the length counts itself: a body
/// that fits the short form in one arithmetic does not fit it in the other.
/// Doing it in one place is what stops the encoder and [`Encode::size`]
/// disagreeing by a byte.
pub fn fastpath_frame(inner: usize, context: &'static str) -> PduResult<(usize, usize)> {
    let short = inner + 1;
    if short <= MAX_SHORT_FASTPATH_LEN {
        return Ok((short, 1));
    }
    let long = inner + 2;
    if long > MAX_FASTPATH_LEN {
        return Err(PduError::Encode {
            context,
            reason: "PDU longer than the fifteen bit fast path length",
        });
    }
    Ok((long, 2))
}

/// Write the length [`fastpath_frame`] chose.
pub fn write_fastpath_length(
    w: &mut Writer<'_>,
    total: usize,
    prefix_len: usize,
    context: &'static str,
) -> PduResult<()> {
    match prefix_len {
        1 if total <= MAX_SHORT_FASTPATH_LEN => {
            w.u8(total as u8);
            Ok(())
        }
        2 if total <= MAX_FASTPATH_LEN => {
            w.u8(FASTPATH_LONG_LENGTH | (total >> 8) as u8);
            w.u8(total as u8);
            Ok(())
        }
        _ => Err(PduError::Encode {
            context,
            reason: "fast path length does not fit the chosen field width",
        }),
    }
}

/// One fast path input event (MS-RDPBCGR 2.2.8.1.2.2).
///
/// The bodies are one to six bytes, against the slow path's uniform six, and
/// the keyboard event drops the high byte of the scancode entirely: the
/// prefix that would have set it lives in `eventFlags` instead
/// (PRDRDP/13 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPathInputEvent {
    /// `TS_FP_KEYBOARD_EVENT` (2.2.8.1.2.2.1). Two bytes.
    Scancode {
        /// [`keyboard_flags`].
        flags: u8,
        /// `keyCode`, one byte.
        code: u8,
    },
    /// `TS_FP_POINTER_EVENT` (2.2.8.1.2.2.3). Seven bytes.
    Mouse {
        /// [`super::pointer_flags`].
        flags: u16,
        /// `xPos`.
        x: u16,
        /// `yPos`.
        y: u16,
    },
    /// `TS_FP_POINTERX_EVENT` (2.2.8.1.2.2.4), buttons 4 and 5.
    MouseX {
        /// [`super::pointer_x_flags`].
        flags: u16,
        /// `xPos`.
        x: u16,
        /// `yPos`.
        y: u16,
    },
    /// `TS_FP_SYNC_EVENT` (2.2.8.1.2.2.5). One byte: the toggle state is the
    /// event header's own flag bits, so there is no body at all.
    Sync {
        /// The four lock bits of [`super::sync_flags`], which fit the five
        /// flag bits available.
        toggle_flags: u8,
    },
    /// `TS_FP_UNICODE_KEYBOARD_EVENT` (2.2.8.1.2.2.2). Three bytes.
    Unicode {
        /// Only [`keyboard_flags::RELEASE`] is defined here.
        flags: u8,
        /// One UTF-16 code unit.
        code: u16,
    },
    /// `TS_FP_RELPOINTER_EVENT` (2.2.8.1.2.2.6). Carried because it is four
    /// lines; `rdp-core` never emits one (PRDRDP/05 §3.6).
    RelativeMouse {
        /// [`super::pointer_flags`], without the move and wheel bits.
        flags: u16,
        /// `xDelta`.
        dx: i16,
        /// `yDelta`.
        dy: i16,
    },
    /// `TS_FP_QOETIMESTAMP_EVENT` (2.2.8.1.2.2.7). Five bytes. The server
    /// echoes the timestamp so the client can measure the round trip without
    /// an auto detect exchange.
    QoeTimestamp {
        /// `timestamp`, in milliseconds, on the client's own clock.
        timestamp: u32,
    },
}

impl FastPathInputEvent {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FP_INPUT_EVENT";

    /// A key press or release (PRDRDP/13 §5.4, PRDRDP/05 §2.3).
    ///
    /// Takes a `u16` so a caller holding an XT scancode cannot lose its high
    /// byte silently: a code above `0xFF` is [`PduError::Encode`] here rather
    /// than a keystroke that arrives as a different key. The fast path form
    /// has no down flag, so a press sets only the prefix bits.
    pub fn key(code: u16, down: bool, extended: bool, extended1: bool) -> PduResult<Self> {
        let code = u8::try_from(code).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "scancode above 0xFF does not fit the fast path key code",
        })?;
        let mut flags = 0u8;
        if !down {
            flags |= keyboard_flags::RELEASE;
        }
        if extended {
            flags |= keyboard_flags::EXTENDED;
        }
        if extended1 {
            flags |= keyboard_flags::EXTENDED1;
        }
        Ok(Self::Scancode { flags, code })
    }

    /// The pair of events the Pause key is transmitted as
    /// (MS-RDPBCGR 2.2.8.1.2.2.1, PRDRDP/05 §2.4).
    ///
    /// Pause is not one event. It is scancode `0x1D` with `EXTENDED1`
    /// followed by scancode `0x45` with no flags, and the matching pair with
    /// `RELEASE` on the way up. Decoding `0xC6` as ScrollLock with an `E0`
    /// prefix, which is what the transport code looks like, sends the wrong
    /// key.
    #[must_use]
    pub const fn pause(down: bool) -> [Self; 2] {
        let release = if down { 0 } else { keyboard_flags::RELEASE };
        [
            Self::Scancode {
                flags: release | keyboard_flags::EXTENDED1,
                code: 0x1d,
            },
            Self::Scancode {
                flags: release,
                code: 0x45,
            },
        ]
    }

    /// `eventCode` for this event.
    #[must_use]
    pub const fn event_code(&self) -> u8 {
        match self {
            Self::Scancode { .. } => event_code::SCANCODE,
            Self::Mouse { .. } => event_code::MOUSE,
            Self::MouseX { .. } => event_code::MOUSEX,
            Self::Sync { .. } => event_code::SYNC,
            Self::Unicode { .. } => event_code::UNICODE,
            Self::RelativeMouse { .. } => event_code::RELMOUSE,
            Self::QoeTimestamp { .. } => event_code::QOE_TIMESTAMP,
        }
    }

    /// `eventFlags` for this event, the five low bits of its header byte.
    #[must_use]
    pub const fn event_flags(&self) -> u8 {
        match *self {
            Self::Scancode { flags, .. } | Self::Unicode { flags, .. } => flags,
            Self::Sync { toggle_flags } => toggle_flags,
            Self::Mouse { .. }
            | Self::MouseX { .. }
            | Self::RelativeMouse { .. }
            | Self::QoeTimestamp { .. } => 0,
        }
    }
}

impl Decode<'_> for FastPathInputEvent {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let header = r.u8(Self::NAME)?;
        let flags = header & event_code::FLAGS_MASK;
        match header >> event_code::SHIFT {
            event_code::SCANCODE => Ok(Self::Scancode {
                flags,
                code: r.u8(Self::NAME)?,
            }),
            event_code::MOUSE => Ok(Self::Mouse {
                flags: r.u16(Self::NAME)?,
                x: r.u16(Self::NAME)?,
                y: r.u16(Self::NAME)?,
            }),
            event_code::MOUSEX => Ok(Self::MouseX {
                flags: r.u16(Self::NAME)?,
                x: r.u16(Self::NAME)?,
                y: r.u16(Self::NAME)?,
            }),
            event_code::SYNC => Ok(Self::Sync {
                toggle_flags: flags,
            }),
            event_code::UNICODE => Ok(Self::Unicode {
                flags,
                code: r.u16(Self::NAME)?,
            }),
            event_code::RELMOUSE => Ok(Self::RelativeMouse {
                flags: r.u16(Self::NAME)?,
                dx: r.i16(Self::NAME)?,
                dy: r.i16(Self::NAME)?,
            }),
            event_code::QOE_TIMESTAMP => Ok(Self::QoeTimestamp {
                timestamp: r.u32(Self::NAME)?,
            }),
            other => Err(PduError::Unsupported {
                context: Self::NAME,
                kind: "eventCode",
                value: u64::from(other),
                offset: at,
            }),
        }
    }
}

impl Encode for FastPathInputEvent {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        1 + match self {
            Self::Sync { .. } => 0,
            Self::Scancode { .. } => 1,
            Self::Unicode { .. } => 2,
            Self::QoeTimestamp { .. } => 4,
            Self::Mouse { .. } | Self::MouseX { .. } | Self::RelativeMouse { .. } => 6,
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let flags = self.event_flags();
        if flags & !event_code::FLAGS_MASK != 0 {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "event flags do not fit the five bits of the event header",
            });
        }
        w.u8((self.event_code() << event_code::SHIFT) | flags);
        match *self {
            Self::Scancode { code, .. } => w.u8(code),
            Self::Unicode { code, .. } => w.u16(code),
            Self::Sync { .. } => {}
            Self::QoeTimestamp { timestamp } => w.u32(timestamp),
            Self::Mouse { flags, x, y } | Self::MouseX { flags, x, y } => {
                w.u16(flags);
                w.u16(x);
                w.u16(y);
            }
            Self::RelativeMouse { flags, dx, dy } => {
                w.u16(flags);
                w.i16(dx);
                w.i16(dy);
            }
        }
        Ok(())
    }
}

/// A whole Fast-Path Input Event PDU (MS-RDPBCGR 2.2.8.1.2).
///
/// Direction: client to server, phase 1 (PRDRDP/13 §11).
///
/// The header byte's four bit `numberEvents` covers 1 to 15. A batch larger
/// than that puts zero there and the real count in an extension byte after
/// the length, which only a server advertising `INPUT_FLAG_FASTPATH_INPUT2`
/// reads (MS-RDPBCGR 2.2.7.1.6). This type picks the compact form whenever
/// the batch fits it, so `rdp-core` chunks at fifteen events for a server
/// without the capability and leaves the choice alone otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FastPathInputPdu {
    /// The events, at most [`MAX_INPUT_EVENTS`] of them.
    pub events: Vec<FastPathInputEvent>,
}

impl FastPathInputPdu {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_FP_INPUT_PDU";

    /// A PDU carrying `events`.
    #[must_use]
    pub fn new(events: Vec<FastPathInputEvent>) -> Self {
        Self { events }
    }
}

/// The encoded size of a PDU carrying `events`, or [`PduError::Encode`] when
/// the batch cannot be framed.
///
/// Exposed alongside [`encode_fastpath_input`] so `rdp-core` can size a send
/// buffer from a slice without building a [`Vec`] on the input path.
pub fn fastpath_input_size(events: &[FastPathInputEvent]) -> PduResult<usize> {
    let inner = fastpath_input_inner(events)?;
    Ok(fastpath_frame(inner, FastPathInputPdu::NAME)?.0)
}

/// The header byte plus the optional count byte plus the events, which is
/// everything the length field covers except itself.
fn fastpath_input_inner(events: &[FastPathInputEvent]) -> PduResult<usize> {
    if events.len() > MAX_INPUT_EVENTS {
        return Err(PduError::Encode {
            context: FastPathInputPdu::NAME,
            reason: "more events than one fast path PDU can carry",
        });
    }
    let extension = usize::from(events.len() > MAX_COMPACT_EVENTS);
    let body: usize = events.iter().map(Encode::size).sum();
    Ok(1 + extension + body)
}

/// Write a whole Fast-Path Input Event PDU from a slice of events
/// (MS-RDPBCGR 2.2.8.1.2).
pub fn encode_fastpath_input(w: &mut Writer<'_>, events: &[FastPathInputEvent]) -> PduResult<()> {
    const NAME: &str = FastPathInputPdu::NAME;
    let inner = fastpath_input_inner(events)?;
    let (total, prefix_len) = fastpath_frame(inner, NAME)?;
    let compact = events.len() <= MAX_COMPACT_EVENTS;
    // action is FASTPATH (0), flags are clear: we never negotiate standard
    // RDP security, so there is no signature and no FIPS block.
    let count_field = if compact { events.len() as u8 } else { 0 };
    w.u8(count_field << 2);
    write_fastpath_length(w, total, prefix_len, NAME)?;
    if !compact {
        w.u8(events.len() as u8);
    }
    for event in events {
        event.encode(w)?;
    }
    Ok(())
}

impl Decode<'_> for FastPathInputPdu {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let header = r.u8(Self::NAME)?;
        if header & action::MASK != action::FASTPATH {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "action",
                value: u64::from(header & action::MASK),
                offset: at,
            });
        }
        let flags = header >> header_flags::SHIFT;
        if flags != 0 {
            // The `fipsInformation` and `dataSignature` fields these imply
            // sit between the length and the first event. We never negotiate
            // the security that produces them (PRDRDP/03 §13.1), so refusing
            // is honest where skipping would guess at a field width.
            return Err(PduError::Unsupported {
                context: Self::NAME,
                kind: "fpInputHeader flags",
                value: u64::from(flags),
                offset: at,
            });
        }
        let mut count = usize::from((header >> 2) & 0x0f);
        let length = read_fastpath_length(r, Self::NAME)?;
        let consumed = r.offset() - at;
        let body_len = length
            .checked_sub(consumed)
            .ok_or(PduError::LengthMismatch {
                context: Self::NAME,
                declared: length,
                actual: consumed,
                offset: at,
            })?;
        let mut body = r.take(body_len, Self::NAME)?;
        if count == 0 {
            count = usize::from(body.u8(Self::NAME)?);
        }
        body.ensure_cap(count, MAX_INPUT_EVENTS, "MAX_INPUT_EVENTS", Self::NAME)?;
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            events.push(FastPathInputEvent::decode(&mut body)?);
        }
        body.expect_empty(Self::NAME)?;
        Ok(Self { events })
    }
}

impl Encode for FastPathInputPdu {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        // A PDU that cannot be framed has no size; `encode` reports the same
        // condition as an error, and `encode_checked` compares the two only
        // on the paths where both succeed.
        fastpath_input_size(&self.events).unwrap_or(0)
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        encode_fastpath_input(w, &self.events)
    }
}

/// The total length of the fast path PDU whose header starts `bytes`, or
/// `None` when fewer than three bytes have arrived.
///
/// The framer's fast path entry point, the twin of
/// [`crate::x224::peek_tpkt_length`]. Three bytes are asked for rather than
/// two because the short form cannot be distinguished from the long one
/// until `length1` has been read, and reading three is free once the socket
/// has any data at all.
pub fn peek_fastpath_length(bytes: &[u8]) -> PduResult<Option<usize>> {
    let needed = if bytes.get(1).is_some_and(|l| l & FASTPATH_LONG_LENGTH == 0) {
        2
    } else {
        3
    };
    if bytes.len() < needed {
        return Ok(None);
    }
    let mut r = Reader::new(bytes);
    r.skip(1, "TS_FP_HEADER")?;
    Ok(Some(read_fastpath_length(&mut r, "TS_FP_HEADER")?))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use crate::input::{pointer_flags, sync_flags, wheel_rotation_flags, WHEEL_DELTA};

    fn sample() -> FastPathInputPdu {
        FastPathInputPdu::new(vec![
            FastPathInputEvent::key(0x1e, true, false, false).unwrap(),
            FastPathInputEvent::key(0x1e, false, true, false).unwrap(),
            FastPathInputEvent::Sync {
                toggle_flags: (sync_flags::CAPS_LOCK | sync_flags::NUM_LOCK) as u8,
            },
            FastPathInputEvent::Unicode {
                flags: 0,
                code: 0x00e9,
            },
            FastPathInputEvent::Mouse {
                flags: pointer_flags::MOVE,
                x: 1024,
                y: 768,
            },
            FastPathInputEvent::MouseX {
                flags: crate::input::pointer_x_flags::DOWN
                    | crate::input::pointer_x_flags::BUTTON2_FORWARD,
                x: 3,
                y: 4,
            },
            FastPathInputEvent::RelativeMouse {
                flags: 0,
                dx: -7,
                dy: 8,
            },
            FastPathInputEvent::QoeTimestamp {
                timestamp: 0x1234_5678,
            },
        ])
    }

    fn encoded(value: &FastPathInputPdu) -> Vec<u8> {
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
        assert_eq!(FastPathInputPdu::decode(&mut r).unwrap(), value);
        assert!(r.is_empty());
    }

    /// A layout vector computed from the field tables of PRDRDP/13 §5.4 and
    /// PRDRDP/05 §2.3, not transcribed from an annotated capture.
    ///
    /// One key press. The header byte carries `numberEvents` 1 in bits 2 to
    /// 5, so `0x04`. The PDU is four bytes (header, length, event header,
    /// key code), which the short length form holds, so `length1` is `0x04`.
    /// The event header is `0x00`: event code 0 in bits 5 to 7 and no flags.
    #[test]
    fn golden_one_key_press() {
        let expected = hex::decode("0404001e").unwrap();
        let value = FastPathInputPdu::new(vec![FastPathInputEvent::Scancode {
            flags: 0,
            code: 0x1e,
        }]);
        // Four bytes total: header, length, event header, key code.
        assert_eq!(encoded(&value), expected);
        assert_eq!(
            FastPathInputPdu::decode(&mut Reader::new(&expected)).unwrap(),
            value
        );
    }

    /// The two shapes PRDRDP/13 §5.4 asks for a golden of: fifteen events in
    /// the compact form, sixteen in the extension form.
    #[test]
    fn fifteen_events_are_compact_and_sixteen_use_the_extension_byte() {
        let event = FastPathInputEvent::Scancode {
            flags: 0,
            code: 0x1e,
        };

        let fifteen = FastPathInputPdu::new(vec![event; 15]);
        let buf = encoded(&fifteen);
        assert_eq!(buf[0] >> 2, 15, "the count is in the header byte");
        // 1 header + 1 length + 30 event bytes.
        assert_eq!(buf.len(), 32);
        assert_eq!(usize::from(buf[1]), buf.len());
        assert_eq!(
            FastPathInputPdu::decode(&mut Reader::new(&buf)).unwrap(),
            fifteen
        );

        let sixteen = FastPathInputPdu::new(vec![event; 16]);
        let buf = encoded(&sixteen);
        assert_eq!(buf[0] >> 2, 0, "the count moved to the extension byte");
        assert_eq!(buf[2], 16, "the extension byte follows the length");
        // 1 header + 1 length + 1 extension + 32 event bytes.
        assert_eq!(buf.len(), 35);
        assert_eq!(
            FastPathInputPdu::decode(&mut Reader::new(&buf)).unwrap(),
            sixteen
        );
    }

    /// The length is big endian, unlike nearly everything else in RDP, and
    /// it counts itself.
    #[test]
    fn the_long_length_form_is_big_endian_and_counts_itself() {
        // 40 pointer events are 280 bytes, past the short form.
        let events = vec![
            FastPathInputEvent::Mouse {
                flags: pointer_flags::MOVE,
                x: 1,
                y: 2,
            };
            40
        ];
        let mut buf = Vec::new();
        encode_fastpath_input(&mut Writer::new(&mut buf), &events).unwrap();
        assert_eq!(buf[1] & FASTPATH_LONG_LENGTH, FASTPATH_LONG_LENGTH);
        let declared = (usize::from(buf[1] & 0x7f) << 8) | usize::from(buf[2]);
        assert_eq!(declared, buf.len());
        assert_eq!(peek_fastpath_length(&buf).unwrap(), Some(buf.len()));
        let decoded = FastPathInputPdu::decode(&mut Reader::new(&buf)).unwrap();
        assert_eq!(decoded.events, events);
    }

    #[test]
    fn peek_reports_none_until_the_length_has_arrived() {
        let buf = encoded(&sample());
        assert_eq!(peek_fastpath_length(&[]).unwrap(), None);
        assert_eq!(peek_fastpath_length(&buf[..1]).unwrap(), None);
        assert_eq!(peek_fastpath_length(&buf).unwrap(), Some(buf.len()));
        // The short form needs only two bytes.
        let short = hex::decode("0304001e").unwrap();
        assert_eq!(peek_fastpath_length(&short[..2]).unwrap(), Some(4));
    }

    /// Byte zero disambiguates fast path from TPKT, which is the whole
    /// framing decision of the read loop (PRDRDP/13 §5.4).
    #[test]
    fn a_tpkt_first_byte_is_not_a_fast_path_pdu() {
        assert_eq!(crate::x224::TPKT_VERSION & action::MASK, action::X224);
        let err =
            FastPathInputPdu::decode(&mut Reader::new(&[0x03, 0x00, 0x00, 0x0b])).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "action",
                ..
            }
        ));
    }

    #[test]
    fn a_header_claiming_encryption_is_refused_rather_than_guessed_at() {
        let mut buf = encoded(&sample());
        buf[0] |= header_flags::ENCRYPTED << header_flags::SHIFT;
        assert!(matches!(
            FastPathInputPdu::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::Unsupported {
                kind: "fpInputHeader flags",
                ..
            }
        ));
    }

    #[test]
    fn pause_is_a_pair_and_not_a_prefixed_scroll_lock() {
        let down = FastPathInputEvent::pause(true);
        assert_eq!(
            down,
            [
                FastPathInputEvent::Scancode {
                    flags: keyboard_flags::EXTENDED1,
                    code: 0x1d
                },
                FastPathInputEvent::Scancode {
                    flags: 0,
                    code: 0x45
                },
            ]
        );
        let up = FastPathInputEvent::pause(false);
        assert_eq!(
            up[0].event_flags() & keyboard_flags::RELEASE,
            keyboard_flags::RELEASE
        );
        assert_eq!(up[1].event_flags(), keyboard_flags::RELEASE);
    }

    /// The fast path key code is one byte, so a caller holding a two byte XT
    /// code is told rather than losing the high byte (PRDRDP/13 §5.4).
    #[test]
    fn a_scancode_above_a_byte_is_an_encode_error() {
        assert!(FastPathInputEvent::key(0x1e, true, false, false).is_ok());
        assert!(matches!(
            FastPathInputEvent::key(0x011d, true, false, false).unwrap_err(),
            PduError::Encode { .. }
        ));
    }

    #[test]
    fn a_sync_event_is_one_byte_with_the_state_in_its_header() {
        let value = FastPathInputPdu::new(vec![FastPathInputEvent::Sync {
            toggle_flags: sync_flags::ALL as u8,
        }]);
        let buf = encoded(&value);
        assert_eq!(buf, [0x04, 0x03, (event_code::SYNC << 5) | 0x0f]);
        assert_eq!(
            FastPathInputPdu::decode(&mut Reader::new(&buf)).unwrap(),
            value
        );
    }

    #[test]
    fn a_wheel_event_survives_the_round_trip_with_its_sign() {
        let flags = wheel_rotation_flags(-WHEEL_DELTA, false).unwrap();
        let value = FastPathInputPdu::new(vec![FastPathInputEvent::Mouse { flags, x: 0, y: 0 }]);
        let buf = encoded(&value);
        let back = FastPathInputPdu::decode(&mut Reader::new(&buf)).unwrap();
        assert_eq!(back, value);
        match back.events[0] {
            FastPathInputEvent::Mouse { flags, .. } => {
                assert_eq!(crate::input::wheel_rotation(flags), -WHEEL_DELTA);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn truncating_at_every_offset_errors_without_panicking() {
        let buf = encoded(&sample());
        for cut in 0..buf.len() {
            assert!(
                FastPathInputPdu::decode(&mut Reader::new(&buf[..cut])).is_err(),
                "decoded a PDU truncated to {cut} bytes"
            );
        }
    }

    /// The tail rule for an exact structure: one byte more than the events
    /// need, inside the declared length, is a `LengthMismatch`.
    #[test]
    fn a_trailing_byte_inside_the_declared_length_is_rejected() {
        let value = FastPathInputPdu::new(vec![FastPathInputEvent::Scancode {
            flags: 0,
            code: 0x1e,
        }]);
        let mut buf = encoded(&value);
        buf.push(0xff);
        buf[1] += 1;
        assert!(matches!(
            FastPathInputPdu::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn a_length_shorter_than_the_header_is_rejected() {
        assert!(FastPathInputPdu::decode(&mut Reader::new(&[0x04, 0x01])).is_err());
        assert!(FastPathInputPdu::decode(&mut Reader::new(&[0x04, 0x00])).is_err());
    }

    #[test]
    fn the_frame_helper_picks_the_width_that_makes_the_length_fit() {
        // 126 inner bytes plus a one byte length is 127, the largest short
        // form. One more inner byte tips it into the long form and the total
        // grows by two, not one.
        assert_eq!(fastpath_frame(126, "t").unwrap(), (127, 1));
        assert_eq!(fastpath_frame(127, "t").unwrap(), (129, 2));
        assert!(fastpath_frame(MAX_FASTPATH_LEN, "t").is_err());
    }
}
