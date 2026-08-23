//! Surface commands, the EGFX era bitmap path.
//!
//! MS-RDPBCGR 2.2.9.2, PRDRDP/13 §5.7.
//!
//! A `FASTPATH_UPDATETYPE_SURFCMDS` update, or a slow path update of the same
//! kind, carries a sequence of `TS_SURFCMD` running until the update's bytes
//! are exhausted. There is no count, so [`SurfaceCommandIter`] loops while the
//! reader is non empty and a truncated final command is a `Truncated` error
//! rather than a silent stop.
//!
//! The destination rectangle here is [`RectExclusive`], where the bitmap
//! update of §5.6.1 is inclusive. Two conventions in one protocol, in
//! structures that arrive on the same channel, which is why the two are
//! distinct types (PRDRDP/13 §5.7).
//!
//! Surface Bits bitmaps are top down, unlike the bottom up rows of a legacy
//! bitmap update (PRDRDP/04 §2.8). That is the decoder's business and not
//! this module's; what this module guarantees is that `bitmapData` starts at
//! the right byte.
//!
//! Tail rule (PRDRDP/13 §2.5): exact. `bitmapDataLength` bounds the payload
//! and the next command starts immediately after it.

use super::RectExclusive;
use crate::io::limits::MAX_BITMAP_DATA;
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `TS_SURFCMD.cmdType` (MS-RDPBCGR 2.2.9.2).
pub mod cmd_type {
    /// `CMDTYPE_SET_SURFACE_BITS` (2.2.9.2.1).
    pub const SET_SURFACE_BITS: u16 = 0x0001;
    /// `CMDTYPE_FRAME_MARKER` (2.2.9.2.3).
    pub const FRAME_MARKER: u16 = 0x0004;
    /// `CMDTYPE_STREAM_SURFACE_BITS` (2.2.9.2.2), which has the same layout
    /// as Set Surface Bits and a different id.
    pub const STREAM_SURFACE_BITS: u16 = 0x0006;
}

/// `TS_FRAME_MARKER.frameAction` (MS-RDPBCGR 2.2.9.2.3).
pub mod frame_action {
    /// `SURFACECMD_FRAMEACTION_BEGIN`.
    pub const BEGIN: u16 = 0x0000;
    /// `SURFACECMD_FRAMEACTION_END`. PRDRDP/04 §3.6's frame pacing and
    /// decision R33's "one framebuffer update per frame, cut at `EndFrame`"
    /// are built on this pair.
    pub const END: u16 = 0x0001;
}

/// `TS_BITMAP_DATA_EX.flags` (MS-RDPBCGR 2.2.9.2.1.1).
pub mod bitmap_data_ex_flags {
    /// `EX_COMPRESSED_BITMAP_HEADER_PRESENT`: the twenty four byte
    /// `TS_COMPRESSED_BITMAP_HEADER_EX` sits between the length and the
    /// payload.
    pub const COMPRESSED_BITMAP_HEADER_PRESENT: u8 = 0x01;
}

/// `TS_COMPRESSED_BITMAP_HEADER_EX` (MS-RDPBCGR 2.2.9.2.1.1.1).
///
/// Twenty four bytes that exist for a persistent bitmap cache we do not
/// implement. They are parsed so the payload starts at the right byte and
/// then ignored (PRDRDP/13 §5.7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompressedBitmapHeaderEx {
    /// `highUniqueId`.
    pub high_unique_id: u32,
    /// `lowUniqueId`.
    pub low_unique_id: u32,
    /// `tmMilliseconds`.
    pub tm_milliseconds: u64,
    /// `tmSeconds`.
    pub tm_seconds: u64,
}

impl CompressedBitmapHeaderEx {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_COMPRESSED_BITMAP_HEADER_EX";

    /// Twenty four bytes, always.
    pub const LEN: usize = 24;
}

impl Decode<'_> for CompressedBitmapHeaderEx {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            high_unique_id: r.u32(Self::NAME)?,
            low_unique_id: r.u32(Self::NAME)?,
            tm_milliseconds: r.u64(Self::NAME)?,
            tm_seconds: r.u64(Self::NAME)?,
        })
    }
}

impl Encode for CompressedBitmapHeaderEx {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.high_unique_id);
        w.u32(self.low_unique_id);
        w.u64(self.tm_milliseconds);
        w.u64(self.tm_seconds);
        Ok(())
    }
}

/// `TS_BITMAP_DATA_EX` (MS-RDPBCGR 2.2.9.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapDataEx<'a> {
    /// `bpp`.
    pub bpp: u8,
    /// [`bitmap_data_ex_flags`].
    pub flags: u8,
    /// `codecID`, the id assigned in the Bitmap Codecs capability set
    /// (MS-RDPBCGR 2.2.7.2.10). Zero is uncompressed. A codec id we did not
    /// advertise is `rdp-core`'s error to raise, not this decoder's
    /// (PRDRDP/04 §2.8).
    pub codec_id: u8,
    /// `width`.
    pub width: u16,
    /// `height`.
    pub height: u16,
    /// `exBitmapDataHeader`, present only when the flag says so.
    pub header: Option<CompressedBitmapHeaderEx>,
    /// `bitmapData`, borrowed from the receive buffer and handed to whichever
    /// `rdp-codecs` decoder `codec_id` selects.
    pub data: Payload<'a>,
}

impl BitmapDataEx<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAP_DATA_EX";

    /// `bpp`, `flags`, `reserved`, `codecID`, `width`, `height` and the four
    /// byte `bitmapDataLength`.
    const FIXED_LEN: usize = 4 + 2 + 2 + 4;
}

impl<'a> Decode<'a> for BitmapDataEx<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let bpp = r.u8(Self::NAME)?;
        let flags = r.u8(Self::NAME)?;
        // `reserved`, which no server sets.
        r.skip(1, Self::NAME)?;
        let codec_id = r.u8(Self::NAME)?;
        let width = r.u16(Self::NAME)?;
        let height = r.u16(Self::NAME)?;
        let length = r.u32(Self::NAME)? as usize;
        r.ensure_cap(length, MAX_BITMAP_DATA, "MAX_BITMAP_DATA", Self::NAME)?;
        // `bitmapDataLength` counts `bitmapData` alone; the twenty four byte
        // header is a separate field ahead of it (MS-RDPBCGR 2.2.9.2.1.1).
        let header = if flags & bitmap_data_ex_flags::COMPRESSED_BITMAP_HEADER_PRESENT != 0 {
            Some(CompressedBitmapHeaderEx::decode(r)?)
        } else {
            None
        };
        Ok(Self {
            bpp,
            flags,
            codec_id,
            width,
            height,
            header,
            data: Payload::new(r.slice(length, Self::NAME)?),
        })
    }
}

impl Encode for BitmapDataEx<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::FIXED_LEN + self.header.map_or(0, |_| CompressedBitmapHeaderEx::LEN) + self.data.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let length = u32::try_from(self.data.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "bitmap longer than bitmapDataLength",
        })?;
        let flag_set = self.flags & bitmap_data_ex_flags::COMPRESSED_BITMAP_HEADER_PRESENT != 0;
        if flag_set != self.header.is_some() {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "EX_COMPRESSED_BITMAP_HEADER_PRESENT disagrees with the header",
            });
        }
        w.u8(self.bpp);
        w.u8(self.flags);
        w.u8(0);
        w.u8(self.codec_id);
        w.u16(self.width);
        w.u16(self.height);
        w.u32(length);
        if let Some(header) = self.header {
            header.encode(w)?;
        }
        w.bytes(self.data.as_slice());
        Ok(())
    }
}

/// The body of `CMDTYPE_SET_SURFACE_BITS` and of
/// `CMDTYPE_STREAM_SURFACE_BITS`, which are the same layout
/// (MS-RDPBCGR 2.2.9.2.1, 2.2.9.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceBits<'a> {
    /// Where the bitmap goes, with **exclusive** right and bottom edges.
    pub dest: RectExclusive,
    /// The bitmap and its codec id.
    pub bitmap: BitmapDataEx<'a>,
}

/// `TS_FRAME_MARKER` (MS-RDPBCGR 2.2.9.2.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameMarker {
    /// [`frame_action`].
    pub frame_action: u16,
    /// `frameId`, echoed in a Frame Acknowledge when that capability set was
    /// negotiated.
    pub frame_id: u32,
}

/// One `TS_SURFCMD` (MS-RDPBCGR 2.2.9.2).
///
/// Direction: server to client, phase 1 (PRDRDP/13 §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceCommand<'a> {
    /// `CMDTYPE_SET_SURFACE_BITS`.
    SetSurfaceBits(SurfaceBits<'a>),
    /// `CMDTYPE_STREAM_SURFACE_BITS`.
    StreamSurfaceBits(SurfaceBits<'a>),
    /// `CMDTYPE_FRAME_MARKER`.
    FrameMarker(FrameMarker),
}

impl SurfaceCommand<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SURFCMD";

    /// The `cmdType` that names this command.
    #[must_use]
    pub const fn cmd_type(&self) -> u16 {
        match self {
            Self::SetSurfaceBits(_) => cmd_type::SET_SURFACE_BITS,
            Self::StreamSurfaceBits(_) => cmd_type::STREAM_SURFACE_BITS,
            Self::FrameMarker(_) => cmd_type::FRAME_MARKER,
        }
    }
}

impl<'a> Decode<'a> for SurfaceCommand<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let cmd_type = r.u16(Self::NAME)?;
        match cmd_type {
            cmd_type::SET_SURFACE_BITS => Ok(Self::SetSurfaceBits(decode_surface_bits(r)?)),
            cmd_type::STREAM_SURFACE_BITS => Ok(Self::StreamSurfaceBits(decode_surface_bits(r)?)),
            cmd_type::FRAME_MARKER => Ok(Self::FrameMarker(FrameMarker {
                frame_action: r.u16(Self::NAME)?,
                frame_id: r.u32(Self::NAME)?,
            })),
            other => Err(PduError::Unsupported {
                context: Self::NAME,
                kind: "cmdType",
                value: u64::from(other),
                offset: at,
            }),
        }
    }
}

impl Encode for SurfaceCommand<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        2 + match self {
            Self::SetSurfaceBits(bits) | Self::StreamSurfaceBits(bits) => {
                RectExclusive::LEN + bits.bitmap.size()
            }
            Self::FrameMarker(_) => 6,
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.cmd_type());
        match self {
            Self::SetSurfaceBits(bits) | Self::StreamSurfaceBits(bits) => {
                bits.dest.encode(w)?;
                bits.bitmap.encode(w)
            }
            Self::FrameMarker(marker) => {
                w.u16(marker.frame_action);
                w.u32(marker.frame_id);
                Ok(())
            }
        }
    }
}

/// Read the body shared by Set Surface Bits and Stream Surface Bits.
fn decode_surface_bits<'a>(r: &mut Reader<'a>) -> PduResult<SurfaceBits<'a>> {
    Ok(SurfaceBits {
        dest: RectExclusive::decode(r)?,
        bitmap: BitmapDataEx::decode(r)?,
    })
}

/// Walk the commands of a surface commands update.
///
/// There is no count in the wire format, so this yields a `PduResult` per
/// command and stops when the payload is exhausted. A malformed command ends
/// the iteration after reporting itself, so a caller that collects into a
/// `PduResult<Vec<_>>` sees the first error and nothing after it.
#[derive(Debug, Clone, Copy)]
pub struct SurfaceCommandIter<'a> {
    r: Reader<'a>,
    done: bool,
}

impl<'a> SurfaceCommandIter<'a> {
    /// Walk the commands in `payload`, which is the body of a
    /// `FASTPATH_UPDATETYPE_SURFCMDS` update.
    #[must_use]
    pub const fn new(payload: Payload<'a>) -> Self {
        Self {
            r: Reader::new(payload.as_slice()),
            done: false,
        }
    }
}

impl<'a> Iterator for SurfaceCommandIter<'a> {
    type Item = PduResult<SurfaceCommand<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.r.is_empty() {
            return None;
        }
        let item = SurfaceCommand::decode(&mut self.r);
        if item.is_err() {
            self.done = true;
        }
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn uncompressed_bits() -> SurfaceCommand<'static> {
        SurfaceCommand::SetSurfaceBits(SurfaceBits {
            dest: RectExclusive {
                left: 0,
                top: 0,
                right: 4,
                bottom: 2,
            },
            bitmap: BitmapDataEx {
                bpp: 32,
                flags: 0,
                codec_id: 0,
                width: 4,
                height: 2,
                header: None,
                data: Payload::new(&[0x55; 32]),
            },
        })
    }

    fn cached_bits() -> SurfaceCommand<'static> {
        SurfaceCommand::StreamSurfaceBits(SurfaceBits {
            dest: RectExclusive {
                left: 16,
                top: 16,
                right: 32,
                bottom: 32,
            },
            bitmap: BitmapDataEx {
                bpp: 32,
                flags: bitmap_data_ex_flags::COMPRESSED_BITMAP_HEADER_PRESENT,
                codec_id: 3,
                width: 16,
                height: 16,
                header: Some(CompressedBitmapHeaderEx {
                    high_unique_id: 1,
                    low_unique_id: 2,
                    tm_milliseconds: 3,
                    tm_seconds: 4,
                }),
                data: Payload::new(&[0xaa, 0xbb, 0xcc]),
            },
        })
    }

    fn samples() -> Vec<SurfaceCommand<'static>> {
        vec![
            uncompressed_bits(),
            cached_bits(),
            SurfaceCommand::FrameMarker(FrameMarker {
                frame_action: frame_action::BEGIN,
                frame_id: 0x1234_5678,
            }),
            SurfaceCommand::FrameMarker(FrameMarker {
                frame_action: frame_action::END,
                frame_id: 0x1234_5678,
            }),
        ]
    }

    fn encoded<T: Encode>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        buf
    }

    #[test]
    fn every_command_round_trips() {
        for value in samples() {
            let buf = encoded(&value);
            assert_eq!(buf.len(), value.size(), "{value:?}");
            let mut r = Reader::new(&buf);
            assert_eq!(SurfaceCommand::decode(&mut r).unwrap(), value);
            assert!(r.is_empty(), "{value:?}");
        }
    }

    /// A layout vector for a frame marker, computed from the field table of
    /// PRDRDP/13 §5.7: `cmdType` 0x0004, `frameAction` 0x0001, `frameId`.
    #[test]
    fn golden_frame_marker_end() {
        let expected = hex::decode(concat!("0400", "0100", "78563412")).unwrap();
        let value = SurfaceCommand::FrameMarker(FrameMarker {
            frame_action: frame_action::END,
            frame_id: 0x1234_5678,
        });
        assert_eq!(encoded(&value), expected);
        assert_eq!(
            SurfaceCommand::decode(&mut Reader::new(&expected)).unwrap(),
            value
        );
    }

    /// The surface rectangle is exclusive where the bitmap update's is
    /// inclusive, and the two convert only through the named methods.
    #[test]
    fn the_surface_rectangle_is_exclusive() {
        let SurfaceCommand::SetSurfaceBits(bits) = uncompressed_bits() else {
            panic!("the sample is a set surface bits command");
        };
        assert_eq!(bits.dest.width(), Some(4));
        assert_eq!(bits.dest.height(), Some(2));
        assert_eq!(bits.dest.width(), Some(u32::from(bits.bitmap.width)));
        // The same numbers read as an inclusive rectangle are one bigger.
        let inclusive = bits.dest.to_inclusive().unwrap();
        assert_eq!(inclusive.right, 3);
        assert_eq!(inclusive.width(), Some(4));
    }

    /// The twenty four byte header sits between the length and the payload,
    /// and `bitmapDataLength` counts only the payload
    /// (MS-RDPBCGR 2.2.9.2.1.1).
    #[test]
    fn the_extended_header_does_not_count_towards_the_length() {
        let buf = encoded(&cached_bits());
        // cmdType, rectangle, then the fixed part of TS_BITMAP_DATA_EX.
        let at = 2 + RectExclusive::LEN + 8;
        let declared = u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        assert_eq!(declared, 3, "bitmapDataLength counts bitmapData alone");
        assert_eq!(
            buf.len(),
            2 + RectExclusive::LEN + 12 + CompressedBitmapHeaderEx::LEN + 3
        );
    }

    #[test]
    fn a_header_flag_without_a_header_is_an_encode_error() {
        let SurfaceCommand::SetSurfaceBits(mut bits) = uncompressed_bits() else {
            panic!("the sample is a set surface bits command");
        };
        bits.bitmap.flags = bitmap_data_ex_flags::COMPRESSED_BITMAP_HEADER_PRESENT;
        let mut buf = Vec::new();
        assert!(matches!(
            SurfaceCommand::SetSurfaceBits(bits)
                .encode(&mut Writer::new(&mut buf))
                .unwrap_err(),
            PduError::Encode { .. }
        ));
    }

    /// The command sequence has no count, so the loop is over the bytes and
    /// a truncated final command is an error rather than a silent stop.
    #[test]
    fn the_iterator_walks_until_the_payload_is_exhausted() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            for value in samples() {
                value.encode_checked(&mut w).unwrap();
            }
        }
        let commands: Vec<SurfaceCommand<'_>> = SurfaceCommandIter::new(Payload::new(&buf))
            .collect::<PduResult<_>>()
            .unwrap();
        assert_eq!(commands, samples());

        let short = &buf[..buf.len() - 1];
        let outcome: PduResult<Vec<SurfaceCommand<'_>>> =
            SurfaceCommandIter::new(Payload::new(short)).collect();
        assert!(
            outcome.is_err(),
            "a truncated final command stopped silently"
        );
    }

    #[test]
    fn an_unknown_command_type_is_unsupported_rather_than_skipped() {
        let buf = hex::decode("0700000000000000").unwrap();
        assert!(matches!(
            SurfaceCommand::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::Unsupported {
                kind: "cmdType",
                ..
            }
        ));
    }

    #[test]
    fn a_hostile_bitmap_length_is_capped_before_the_slice_is_taken() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            w.u16(cmd_type::SET_SURFACE_BITS);
            w.u16(0);
            w.u16(0);
            w.u16(1);
            w.u16(1);
            w.u8(32); // bpp
            w.u8(0); // flags
            w.u8(0); // reserved
            w.u8(0); // codecID
            w.u16(1);
            w.u16(1);
            w.u32(u32::MAX);
        }
        assert!(matches!(
            SurfaceCommand::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_BITMAP_DATA",
                ..
            }
        ));
    }

    #[test]
    fn truncating_at_every_offset_errors_without_panicking() {
        for value in samples() {
            let buf = encoded(&value);
            for cut in 0..buf.len() {
                assert!(
                    SurfaceCommand::decode(&mut Reader::new(&buf[..cut])).is_err(),
                    "{value:?} truncated to {cut} bytes decoded"
                );
            }
        }
    }
}
