//! Slow path update PDUs inside a Share Data PDU.
//!
//! MS-RDPBCGR 2.2.9.1.1, PRDRDP/13 §5.6.
//!
//! Two PDUs live here and they are different `pduType2` values, not two forms
//! of one thing. A Server Graphics Update PDU (2.2.9.1.1.3) carries
//! [`GraphicsUpdate`] behind a `u16` `updateType`; a Server Pointer Update
//! PDU (2.2.9.1.1.4) carries [`PointerPdu`] behind a `u16` `messageType` and
//! two pad bytes. Both sit inside a Share Data header that
//! `crate::rdp::share` owns, and neither type in this file knows that header
//! exists.
//!
//! [`GraphicsUpdate::decode_body`] and [`GraphicsUpdate::encode_body`] are
//! the halves the fast path calls: §5.6 says each body decoder is written
//! once and called from both dispatchers, and this is that.
//!
//! **Where the `updateType` field lives.** It appears once, here, and the
//! fast path replaces it with the four bit update code of its own header.
//! PRDRDP/13 §5.6.1 says instead that it is "repeated inside the body in the
//! slow path form", which contradicts PRDRDP/04 §2.1's statement that
//! `TS_UPDATE_BITMAP_DATA` in the slow path and the fast path bitmap update
//! body "are the same bytes". Two extra bytes on the wire either way, so the
//! disagreement is not cosmetic. This crate follows PRDRDP/04, and the
//! decision is one line: [`Decode`] reads the field and hands the rest to
//! [`GraphicsUpdate::decode_body`].
//!
//! Tail rule (PRDRDP/13 §2.5): exact for the pointer PDU, whose bodies are
//! fixed. A graphics update's orders body is opaque and takes whatever is
//! left, because we never advertise orders and cannot parse one.

use super::{BitmapUpdate, PaletteUpdate, PointerKind, PointerUpdate};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `updateType` of a Server Graphics Update PDU (MS-RDPBCGR 2.2.9.1.1.3.1).
///
/// The values are the same numbers as the fast path update codes of
/// 2.2.9.1.2.1, which is why one code path serves both.
pub mod update_type {
    /// `UPDATETYPE_ORDERS`.
    pub const ORDERS: u16 = 0x0000;
    /// `UPDATETYPE_BITMAP`.
    pub const BITMAP: u16 = 0x0001;
    /// `UPDATETYPE_PALETTE`.
    pub const PALETTE: u16 = 0x0002;
    /// `UPDATETYPE_SYNCHRONIZE`.
    pub const SYNCHRONIZE: u16 = 0x0003;
}

/// `messageType` of a Server Pointer Update PDU (MS-RDPBCGR 2.2.9.1.1.4.1).
pub mod pointer_message_type {
    /// `TS_PTRMSGTYPE_SYSTEM`.
    pub const SYSTEM: u16 = 0x0001;
    /// `TS_PTRMSGTYPE_POSITION`.
    pub const POSITION: u16 = 0x0003;
    /// `TS_PTRMSGTYPE_COLOR`.
    pub const COLOR: u16 = 0x0006;
    /// `TS_PTRMSGTYPE_CACHED`.
    pub const CACHED: u16 = 0x0007;
    /// `TS_PTRMSGTYPE_POINTER`.
    pub const POINTER: u16 = 0x0008;
    /// `TS_PTRMSGTYPE_LARGE_POINTER`.
    pub const LARGE_POINTER: u16 = 0x0009;
}

/// One graphics update, in the form both paths share
/// (MS-RDPBCGR 2.2.9.1.1.3.1).
///
/// Direction: server to client, phase 1 (PRDRDP/13 §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphicsUpdate<'a> {
    /// `UPDATETYPE_ORDERS`, primary and secondary drawing orders.
    ///
    /// We never advertise order support, so this should not arrive, and it
    /// is carried rather than rejected because its length is known and
    /// PRDRDP/13 §2.7 rule 3 says a decoder preserves what it can rather
    /// than desyncing the stream. Refusing it is `rdp-core`'s decision
    /// (PRDRDP/04 §8.4).
    Orders(Payload<'a>),
    /// `UPDATETYPE_BITMAP` (2.2.9.1.1.3.1.2).
    Bitmap(BitmapUpdate<'a>),
    /// `UPDATETYPE_PALETTE` (2.2.9.1.1.3.1.1).
    ///
    /// Boxed because the entries are 768 bytes and this enum is moved on
    /// every frame: keeping the palette inline would make a bitmap update
    /// carry 776 bytes of mostly nothing. A palette update allocates once,
    /// which is the one place PRDRDP/13 §10.1 statement 2 is traded for
    /// statement 1, and it arrives at most once a session.
    Palette(Box<PaletteUpdate>),
    /// `UPDATETYPE_SYNCHRONIZE` (2.2.9.1.1.2), two pad bytes and no meaning.
    /// A server sends it after a Deactivate All cycle.
    Synchronize,
}

impl<'a> GraphicsUpdate<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_GRAPHICS_UPDATE";

    /// The `updateType` that names this update, which is also its fast path
    /// update code.
    #[must_use]
    pub const fn update_type(&self) -> u16 {
        match self {
            Self::Orders(_) => update_type::ORDERS,
            Self::Bitmap(_) => update_type::BITMAP,
            Self::Palette(_) => update_type::PALETTE,
            Self::Synchronize => update_type::SYNCHRONIZE,
        }
    }

    /// Read the body of an update whose type the caller has already read,
    /// from `updateType` in the slow path or from the update code in the
    /// fast path.
    ///
    /// `synchronize_padded` says whether the two pad bytes of
    /// `TS_UPDATE_SYNCHRONIZE` are expected. The slow path always has them.
    /// The fast path form is documented as a zero length body, and servers
    /// have been observed sending both, so the fast path dispatcher passes
    /// `false` and this tolerates either.
    pub fn decode_body(
        r: &mut Reader<'a>,
        update_type: u16,
        synchronize_padded: bool,
    ) -> PduResult<Self> {
        let at = r.offset();
        match update_type {
            update_type::ORDERS => Ok(Self::Orders(Payload::new(r.rest()))),
            update_type::BITMAP => Ok(Self::Bitmap(BitmapUpdate::decode(r)?)),
            update_type::PALETTE => Ok(Self::Palette(Box::new(PaletteUpdate::decode(r)?))),
            update_type::SYNCHRONIZE => {
                if synchronize_padded || r.remaining() >= 2 {
                    r.skip(2, Self::NAME)?;
                }
                Ok(Self::Synchronize)
            }
            other => Err(PduError::Unsupported {
                context: Self::NAME,
                kind: "updateType",
                value: u64::from(other),
                offset: at,
            }),
        }
    }

    /// The encoded size of the body alone, without the `updateType` field.
    #[must_use]
    pub fn body_size(&self) -> usize {
        match self {
            Self::Orders(payload) => payload.len(),
            Self::Bitmap(update) => update.size(),
            Self::Palette(update) => update.size(),
            Self::Synchronize => 2,
        }
    }

    /// Write the body alone, without the `updateType` field.
    ///
    /// The synchronize update is written with its two pad bytes, which is the
    /// slow path form. The fast path dispatcher writes a zero length body
    /// instead, so it does not call this for a synchronize.
    pub fn encode_body(&self, w: &mut Writer<'_>) -> PduResult<()> {
        match self {
            Self::Orders(payload) => {
                w.bytes(payload.as_slice());
                Ok(())
            }
            Self::Bitmap(update) => update.encode(w),
            Self::Palette(update) => update.encode(w),
            Self::Synchronize => {
                w.u16(0);
                Ok(())
            }
        }
    }
}

impl<'a> Decode<'a> for GraphicsUpdate<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let update_type = r.u16(Self::NAME)?;
        Self::decode_body(r, update_type, true)
    }
}

impl Encode for GraphicsUpdate<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        2 + self.body_size()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.update_type());
        self.encode_body(w)
    }
}

/// `TS_POINTER_PDU` minus its Share Data header (MS-RDPBCGR 2.2.9.1.1.4.1).
///
/// Direction: server to client, phase 1 (PRDRDP/13 §11).
///
/// The fast path carries the same bodies with the message type replaced by
/// the update code and the two pad bytes dropped, which is why
/// [`PointerUpdate`] rather than this type is what
/// `crate::update::fastpath` hands back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerPdu<'a> {
    /// The body, already named by `messageType`.
    pub update: PointerUpdate<'a>,
}

impl PointerPdu<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_POINTER_PDU";

    /// The `messageType` that names this update.
    #[must_use]
    pub const fn message_type(&self) -> u16 {
        match self.update.kind() {
            PointerKind::System => pointer_message_type::SYSTEM,
            PointerKind::Position => pointer_message_type::POSITION,
            PointerKind::Color => pointer_message_type::COLOR,
            PointerKind::Cached => pointer_message_type::CACHED,
            PointerKind::New => pointer_message_type::POINTER,
            PointerKind::Large => pointer_message_type::LARGE_POINTER,
        }
    }
}

/// The [`PointerKind`] a slow path `messageType` names, or an error naming
/// the code we do not implement.
pub fn pointer_kind(message_type: u16, offset: usize) -> PduResult<PointerKind> {
    match message_type {
        pointer_message_type::SYSTEM => Ok(PointerKind::System),
        pointer_message_type::POSITION => Ok(PointerKind::Position),
        pointer_message_type::COLOR => Ok(PointerKind::Color),
        pointer_message_type::CACHED => Ok(PointerKind::Cached),
        pointer_message_type::POINTER => Ok(PointerKind::New),
        pointer_message_type::LARGE_POINTER => Ok(PointerKind::Large),
        other => Err(PduError::Unsupported {
            context: PointerPdu::NAME,
            kind: "messageType",
            value: u64::from(other),
            offset,
        }),
    }
}

impl<'a> Decode<'a> for PointerPdu<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let message_type = r.u16(Self::NAME)?;
        r.skip(2, Self::NAME)?;
        let kind = pointer_kind(message_type, at)?;
        Ok(Self {
            update: PointerUpdate::decode_body(r, kind)?,
        })
    }
}

impl Encode for PointerPdu<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + self.update.body_size()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.message_type());
        w.u16(0);
        self.update.encode_body(w)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use crate::update::tests::{bitmap_update, color_pointer};
    use crate::update::{system_pointer, Point16};

    fn encoded<T: Encode>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        buf
    }

    fn graphics_samples() -> Vec<GraphicsUpdate<'static>> {
        vec![
            GraphicsUpdate::Bitmap(bitmap_update()),
            GraphicsUpdate::Palette(Box::<PaletteUpdate>::default()),
            GraphicsUpdate::Synchronize,
            GraphicsUpdate::Orders(Payload::new(&[0xde, 0xad, 0xbe, 0xef])),
        ]
    }

    fn pointer_samples() -> Vec<PointerPdu<'static>> {
        vec![
            PointerPdu {
                update: PointerUpdate::System(system_pointer::NULL),
            },
            PointerPdu {
                update: PointerUpdate::Position(Point16 { x: 800, y: 600 }),
            },
            PointerPdu {
                update: PointerUpdate::Cached(11),
            },
            PointerPdu {
                update: PointerUpdate::Color(color_pointer()),
            },
            PointerPdu {
                update: PointerUpdate::New {
                    xor_bpp: 32,
                    pointer: color_pointer(),
                },
            },
            PointerPdu {
                update: PointerUpdate::Large {
                    xor_bpp: 24,
                    pointer: color_pointer(),
                },
            },
        ]
    }

    #[test]
    fn graphics_updates_round_trip() {
        for value in graphics_samples() {
            let buf = encoded(&value);
            assert_eq!(buf.len(), value.size(), "{value:?}");
            let mut r = Reader::new(&buf);
            assert_eq!(GraphicsUpdate::decode(&mut r).unwrap(), value);
            assert!(r.is_empty(), "{value:?}");
        }
    }

    #[test]
    fn pointer_pdus_round_trip() {
        for value in pointer_samples() {
            let buf = encoded(&value);
            assert_eq!(buf.len(), value.size(), "{value:?}");
            let mut r = Reader::new(&buf);
            assert_eq!(PointerPdu::decode(&mut r).unwrap(), value);
            assert!(r.is_empty(), "{value:?}");
        }
    }

    /// The `updateType` appears exactly once, at the front, and the bitmap
    /// body starts at `numberRectangles`. This is the test that pins the
    /// PRDRDP/13 §5.6.1 against PRDRDP/04 §2.1 disagreement recorded above.
    #[test]
    fn the_update_type_is_written_once_and_the_body_follows_immediately() {
        let value = GraphicsUpdate::Bitmap(bitmap_update());
        let buf = encoded(&value);
        assert_eq!(&buf[..2], &[0x01, 0x00], "updateType, once");
        assert_eq!(&buf[2..4], &[0x02, 0x00], "numberRectangles, immediately");
    }

    /// A layout vector for the shortest slow path update there is, computed
    /// from PRDRDP/13 §5.6.3: `updateType` 0x0003 then two pad bytes.
    #[test]
    fn golden_synchronize_update() {
        let expected = hex::decode("03000000").unwrap();
        assert_eq!(encoded(&GraphicsUpdate::Synchronize), expected);
        assert_eq!(
            GraphicsUpdate::decode(&mut Reader::new(&expected)).unwrap(),
            GraphicsUpdate::Synchronize
        );
    }

    /// A layout vector for a pointer position update, computed from
    /// PRDRDP/13 §5.6.4: `messageType` 0x0003, two pad bytes, then a
    /// `TS_POINT16` of (5, 7).
    #[test]
    fn golden_pointer_position() {
        let expected = hex::decode(concat!("0300", "0000", "0500", "0700")).unwrap();
        let value = PointerPdu {
            update: PointerUpdate::Position(Point16 { x: 5, y: 7 }),
        };
        assert_eq!(encoded(&value), expected);
        assert_eq!(
            PointerPdu::decode(&mut Reader::new(&expected)).unwrap(),
            value
        );
    }

    #[test]
    fn an_unknown_update_type_is_unsupported_rather_than_skipped() {
        let buf = hex::decode("77770000").unwrap();
        assert!(matches!(
            GraphicsUpdate::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::Unsupported {
                kind: "updateType",
                ..
            }
        ));
    }

    #[test]
    fn an_unknown_pointer_message_type_is_unsupported() {
        let buf = hex::decode("0400000000000000").unwrap();
        let err = PointerPdu::decode(&mut Reader::new(&buf)).unwrap_err();
        assert!(matches!(
            err,
            PduError::Unsupported {
                kind: "messageType",
                offset: 0,
                ..
            }
        ));
    }

    #[test]
    fn truncating_at_every_offset_errors_without_panicking() {
        for value in graphics_samples() {
            let buf = encoded(&value);
            for cut in 0..buf.len() {
                // An orders body is opaque and takes whatever is left, so a
                // truncated one is a shorter payload rather than an error.
                if matches!(value, GraphicsUpdate::Orders(_)) && cut >= 2 {
                    continue;
                }
                assert!(
                    GraphicsUpdate::decode(&mut Reader::new(&buf[..cut])).is_err(),
                    "{value:?} truncated to {cut} bytes decoded"
                );
            }
        }
        for value in pointer_samples() {
            let buf = encoded(&value);
            for cut in 0..buf.len() {
                assert!(
                    PointerPdu::decode(&mut Reader::new(&buf[..cut])).is_err(),
                    "{value:?} truncated to {cut} bytes decoded"
                );
            }
        }
    }
}
