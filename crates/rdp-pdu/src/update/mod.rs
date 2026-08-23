//! Update PDUs, slow path and fast path.
//!
//! PRDRDP/13 §5.5 to §5.7.
//!
//! The two paths carry the same bodies. The slow path names the update with a
//! `u16` `updateType` inside a Share Data PDU; the fast path names it with the
//! four bit `updateCode` of its own header (MS-RDPBCGR 2.2.9.1.1 against
//! 2.2.9.1.2). Everything after that field is byte for byte identical, so the
//! bodies live here and the two dispatchers in [`slowpath`] and [`fastpath`]
//! do nothing but choose one.
//!
//! Every pixel payload in this module is a [`Payload`], which is a borrowed
//! view of the receive buffer. Nothing here copies a bitmap, a cursor mask or
//! a codec bitstream; the only allocation is the `Vec` of a bitmap update's
//! rectangles, bounded by [`MAX_BITMAP_RECTS`] (PRDRDP/13 §10.1).
//!
//! Two rectangle conventions arrive on the same channel. [`RectInclusive`] is
//! what `TS_BITMAP_DATA` uses and [`RectExclusive`] is what a surface command
//! uses, so they are separate types with explicit conversions and a caller
//! cannot pass one where the other belongs (PRDRDP/13 §5.7).

pub mod fastpath;
pub mod slowpath;
pub mod surface;

use crate::io::limits::{MAX_BITMAP_RECTS, MAX_COLOR_POINTER_DIM, MAX_POINTER_DIM};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `TS_BITMAP_DATA.flags` (MS-RDPBCGR 2.2.9.1.1.3.1.2.2).
pub mod bitmap_flags {
    /// `BITMAP_COMPRESSION`. The payload is interleaved RLE
    /// (MS-RDPBCGR 2.2.9.1.1.3.1.2.4), which `rdp-codecs` decodes.
    pub const COMPRESSION: u16 = 0x0001;
    /// `NO_BITMAP_COMPRESSION_HDR`. The eight byte `TS_CD_HEADER` is absent
    /// even though the payload is compressed. We ask for this in the General
    /// capability set, so the header should never arrive, and the decoder
    /// handles both because "should never" is not a bound on a hostile
    /// server (PRDRDP/13 §5.6.1).
    pub const NO_COMPRESSION_HDR: u16 = 0x0400;
}

/// `TS_SYSTEMPOINTERATTRIBUTE.systemPointerType`
/// (MS-RDPBCGR 2.2.9.1.1.4.3).
pub mod system_pointer {
    /// `SYSPTR_NULL`: hide the pointer.
    pub const NULL: u32 = 0x0000_0000;
    /// `SYSPTR_DEFAULT`: the platform's own arrow.
    pub const DEFAULT: u32 = 0x0000_7f00;
}

/// `TS_POINT16` (MS-RDPBCGR 2.2.9.1.1.4.1), a pointer hotspot or position.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Point16 {
    /// `xPos`.
    pub x: u16,
    /// `yPos`.
    pub y: u16,
}

impl Point16 {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_POINT16";

    /// Four bytes, always.
    pub const LEN: usize = 4;
}

impl Decode<'_> for Point16 {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            x: r.u16(Self::NAME)?,
            y: r.u16(Self::NAME)?,
        })
    }
}

impl Encode for Point16 {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.x);
        w.u16(self.y);
        Ok(())
    }
}

/// A rectangle whose right and bottom edges are **inclusive**, which is what
/// `TS_BITMAP_DATA` uses (MS-RDPBCGR 2.2.9.1.1.3.1.2.2).
///
/// A one pixel rectangle therefore has `right == left`, and the width is
/// `right - left + 1`. There is no way to express an empty rectangle, so
/// `right < left` is a malformed structure rather than an empty update.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RectInclusive {
    /// `destLeft`.
    pub left: u16,
    /// `destTop`.
    pub top: u16,
    /// `destRight`, inclusive.
    pub right: u16,
    /// `destBottom`, inclusive.
    pub bottom: u16,
}

impl RectInclusive {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAP_DATA rectangle";

    /// Eight bytes, always.
    pub const LEN: usize = 8;

    /// `right - left + 1`, or `None` when the edges are inverted.
    #[must_use]
    pub const fn width(&self) -> Option<u32> {
        if self.right < self.left {
            return None;
        }
        Some((self.right as u32) - (self.left as u32) + 1)
    }

    /// `bottom - top + 1`, or `None` when the edges are inverted.
    #[must_use]
    pub const fn height(&self) -> Option<u32> {
        if self.bottom < self.top {
            return None;
        }
        Some((self.bottom as u32) - (self.top as u32) + 1)
    }

    /// The same rectangle with exclusive edges, or `None` when an edge would
    /// leave the `u16` field.
    #[must_use]
    pub const fn to_exclusive(self) -> Option<RectExclusive> {
        match (self.right.checked_add(1), self.bottom.checked_add(1)) {
            (Some(right), Some(bottom)) => Some(RectExclusive {
                left: self.left,
                top: self.top,
                right,
                bottom,
            }),
            _ => None,
        }
    }
}

impl Decode<'_> for RectInclusive {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            left: r.u16(Self::NAME)?,
            top: r.u16(Self::NAME)?,
            right: r.u16(Self::NAME)?,
            bottom: r.u16(Self::NAME)?,
        })
    }
}

impl Encode for RectInclusive {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.left);
        w.u16(self.top);
        w.u16(self.right);
        w.u16(self.bottom);
        Ok(())
    }
}

/// A rectangle whose right and bottom edges are **exclusive**, which is what
/// a surface command uses (MS-RDPBCGR 2.2.9.2.1).
///
/// An off by one in a full screen update is invisible and an off by one in a
/// 16 by 16 update is a visible seam, which is why this is a separate type
/// rather than a comment (PRDRDP/13 §5.7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RectExclusive {
    /// `destLeft`.
    pub left: u16,
    /// `destTop`.
    pub top: u16,
    /// `destRight`, exclusive.
    pub right: u16,
    /// `destBottom`, exclusive.
    pub bottom: u16,
}

impl RectExclusive {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SURFCMD rectangle";

    /// Eight bytes, always.
    pub const LEN: usize = 8;

    /// `right - left`, or `None` when the edges are inverted.
    #[must_use]
    pub const fn width(&self) -> Option<u32> {
        if self.right < self.left {
            return None;
        }
        Some((self.right as u32) - (self.left as u32))
    }

    /// `bottom - top`, or `None` when the edges are inverted.
    #[must_use]
    pub const fn height(&self) -> Option<u32> {
        if self.bottom < self.top {
            return None;
        }
        Some((self.bottom as u32) - (self.top as u32))
    }

    /// The same rectangle with inclusive edges, or `None` when it is empty
    /// and therefore has no inclusive form.
    #[must_use]
    pub const fn to_inclusive(self) -> Option<RectInclusive> {
        match (self.right.checked_sub(1), self.bottom.checked_sub(1)) {
            (Some(right), Some(bottom)) if right >= self.left && bottom >= self.top => {
                Some(RectInclusive {
                    left: self.left,
                    top: self.top,
                    right,
                    bottom,
                })
            }
            _ => None,
        }
    }
}

impl Decode<'_> for RectExclusive {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            left: r.u16(Self::NAME)?,
            top: r.u16(Self::NAME)?,
            right: r.u16(Self::NAME)?,
            bottom: r.u16(Self::NAME)?,
        })
    }
}

impl Encode for RectExclusive {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.left);
        w.u16(self.top);
        w.u16(self.right);
        w.u16(self.bottom);
        Ok(())
    }
}

/// `TS_CD_HEADER` (MS-RDPBCGR 2.2.9.1.1.3.1.2.3), the eight bytes that
/// precede a compressed bitmap unless `NO_BITMAP_COMPRESSION_HDR` said they
/// would not.
///
/// `cbCompFirstRowSize` is not carried: the specification fixes it at zero
/// and the decoder rejects anything else, so a field for it would only give a
/// round trip test something to disagree about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompressedDataHeader {
    /// `cbCompMainBodySize`, the real compressed length. `bitmapLength`
    /// counts these eight header bytes as well, so this is the smaller
    /// number (PRDRDP/13 §5.6.1).
    pub main_body_size: u16,
    /// `cbScanWidth`, the row stride in pixels, a multiple of four. When the
    /// header is present this is authoritative and the formula in
    /// PRDRDP/04 §2.3 is not used.
    pub scan_width: u16,
    /// `cbUncompressedSize`.
    pub uncompressed_size: u16,
}

impl CompressedDataHeader {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_CD_HEADER";

    /// Eight bytes, always.
    pub const LEN: usize = 8;
}

impl Decode<'_> for CompressedDataHeader {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let first_row = r.u16(Self::NAME)?;
        if first_row != 0 {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "cbCompFirstRowSize",
                value: u64::from(first_row),
                offset: at,
            });
        }
        Ok(Self {
            main_body_size: r.u16(Self::NAME)?,
            scan_width: r.u16(Self::NAME)?,
            uncompressed_size: r.u16(Self::NAME)?,
        })
    }
}

impl Encode for CompressedDataHeader {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(0);
        w.u16(self.main_body_size);
        w.u16(self.scan_width);
        w.u16(self.uncompressed_size);
        Ok(())
    }
}

/// One `TS_BITMAP_DATA` (MS-RDPBCGR 2.2.9.1.1.3.1.2.2).
///
/// Tail rule (PRDRDP/13 §2.5): exact. `bitmapLength` bounds the payload and
/// the next rectangle starts immediately after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapData<'a> {
    /// Where the bitmap goes, with **inclusive** right and bottom edges.
    pub dest: RectInclusive,
    /// `width` of the encoded bitmap, which may be larger than the
    /// destination rectangle.
    pub width: u16,
    /// `height` of the encoded bitmap.
    pub height: u16,
    /// `bitsPerPixel`: 1, 8, 15, 16, 24 or 32. Per bitmap, not per session:
    /// a server that negotiated 32 bpp may still send an 8 bpp bitmap
    /// (PRDRDP/04 §2.2).
    pub bits_per_pixel: u16,
    /// [`bitmap_flags`].
    pub flags: u16,
    /// `TS_CD_HEADER`, present only when the payload is compressed and
    /// `NO_BITMAP_COMPRESSION_HDR` is clear.
    pub compression_header: Option<CompressedDataHeader>,
    /// `bitmapDataStream`, borrowed from the receive buffer and handed to
    /// `rdp-codecs` without a copy (PRDRDP/13 §10.1).
    pub data: Payload<'a>,
}

impl BitmapData<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_BITMAP_DATA";

    /// The fixed fields: the rectangle, four `u16` and `bitmapLength`.
    const FIXED_LEN: usize = RectInclusive::LEN + 10;

    /// True when the payload is interleaved RLE rather than raw pixels.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags & bitmap_flags::COMPRESSION != 0
    }
}

impl<'a> Decode<'a> for BitmapData<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let dest = RectInclusive::decode(r)?;
        let width = r.u16(Self::NAME)?;
        let height = r.u16(Self::NAME)?;
        let bits_per_pixel = r.u16(Self::NAME)?;
        let flags = r.u16(Self::NAME)?;
        let at_length = r.offset();
        let bitmap_length = usize::from(r.u16(Self::NAME)?);

        // The destination may be smaller than the encoded bitmap, in which
        // case the bitmap is clipped and `rdp-core` does the clipping
        // (PRDRDP/04 §2.2). It may never be larger: a server that disagrees
        // with itself in that direction makes a naive decoder write outside
        // the pixels it decoded (PRDRDP/13 §5.6.1).
        let (Some(dest_w), Some(dest_h)) = (dest.width(), dest.height()) else {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "destRight",
                value: u64::from(dest.right),
                offset: at,
            });
        };
        if dest_w > u32::from(width) || dest_h > u32::from(height) {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "destination larger than the encoded bitmap",
                value: (u64::from(dest_w) << 32) | u64::from(dest_h),
                offset: at,
            });
        }

        let compressed = flags & bitmap_flags::COMPRESSION != 0;
        let header_present = compressed && flags & bitmap_flags::NO_COMPRESSION_HDR == 0;
        let mut compression_header = None;
        let mut payload_len = bitmap_length;
        if header_present {
            // `bitmapLength` counts the eight header bytes, so the payload is
            // what is left of it (PRDRDP/13 §5.6.1).
            payload_len = bitmap_length.checked_sub(CompressedDataHeader::LEN).ok_or(
                PduError::LengthMismatch {
                    context: Self::NAME,
                    declared: bitmap_length,
                    actual: CompressedDataHeader::LEN,
                    offset: at_length,
                },
            )?;
            compression_header = Some(CompressedDataHeader::decode(r)?);
        }
        let data = Payload::new(r.slice(payload_len, Self::NAME)?);
        Ok(Self {
            dest,
            width,
            height,
            bits_per_pixel,
            flags,
            compression_header,
            data,
        })
    }
}

impl Encode for BitmapData<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::FIXED_LEN
            + self
                .compression_header
                .map_or(0, |_| CompressedDataHeader::LEN)
            + self.data.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let header_len = self
            .compression_header
            .map_or(0, |_| CompressedDataHeader::LEN);
        let bitmap_length =
            u16::try_from(header_len + self.data.len()).map_err(|_| PduError::Encode {
                context: Self::NAME,
                reason: "bitmap longer than the bitmapLength field",
            })?;
        self.dest.encode(w)?;
        w.u16(self.width);
        w.u16(self.height);
        w.u16(self.bits_per_pixel);
        w.u16(self.flags);
        w.u16(bitmap_length);
        if let Some(header) = self.compression_header {
            header.encode(w)?;
        }
        w.bytes(self.data.as_slice());
        Ok(())
    }
}

/// `TS_UPDATE_BITMAP_DATA` without its `updateType`
/// (MS-RDPBCGR 2.2.9.1.1.3.1.2.1).
///
/// Direction: server to client, phase 1 (PRDRDP/13 §11).
///
/// The `updateType` field is the slow path dispatcher's, and the fast path
/// replaces it with the four bit update code, so it is read once by whichever
/// path is in play and never appears here. PRDRDP/13 §5.6.1 says instead that
/// the field is "repeated inside the body in the slow path form", which
/// disagrees with PRDRDP/04 §2.1's "`TS_UPDATE_BITMAP_DATA` in the slow path
/// and the fast path bitmap update body are the same bytes". They cannot both
/// be right, and this crate implements the second: the field appears once, in
/// the slow path only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapUpdate<'a> {
    /// The rectangles, at most [`MAX_BITMAP_RECTS`] of them.
    pub rectangles: Vec<BitmapData<'a>>,
}

impl BitmapUpdate<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UPDATE_BITMAP_DATA";
}

impl<'a> Decode<'a> for BitmapUpdate<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let count = usize::from(r.u16(Self::NAME)?);
        r.ensure_cap(count, MAX_BITMAP_RECTS, "MAX_BITMAP_RECTS", Self::NAME)?;
        let mut rectangles = Vec::with_capacity(count);
        for _ in 0..count {
            rectangles.push(BitmapData::decode(r)?);
        }
        Ok(Self { rectangles })
    }
}

impl Encode for BitmapUpdate<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        2 + self.rectangles.iter().map(Encode::size).sum::<usize>()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let count = u16::try_from(self.rectangles.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "more rectangles than numberRectangles can hold",
        })?;
        w.u16(count);
        for rect in &self.rectangles {
            rect.encode(w)?;
        }
        Ok(())
    }
}

/// One `TS_PALETTE_ENTRY` (MS-RDPBCGR 2.2.9.1.1.3.1.1.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PaletteEntry {
    /// `red`.
    pub red: u8,
    /// `green`.
    pub green: u8,
    /// `blue`.
    pub blue: u8,
}

/// The number of entries `TS_UPDATE_PALETTE_DATA.numberColors` must state
/// (MS-RDPBCGR 2.2.9.1.1.3.1.1.1).
pub const PALETTE_ENTRIES: usize = 256;

/// `TS_UPDATE_PALETTE_DATA` without its `updateType`
/// (MS-RDPBCGR 2.2.9.1.1.3.1.1.1).
///
/// Direction: server to client, phase 1 (PRDRDP/13 §11).
///
/// The palette applies to 8 bpp indexed bitmaps and to 8 bpp pointer images
/// and to nothing else (PRDRDP/04 §2.7). A normal session never sees one; it
/// is implemented because xrdp and old terminal servers still emit it and a
/// decoder that panics on an unexpected palette is a denial of service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaletteUpdate {
    /// Exactly [`PALETTE_ENTRIES`] entries, which is what the specification
    /// requires `numberColors` to say.
    pub entries: [PaletteEntry; PALETTE_ENTRIES],
}

impl PaletteUpdate {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_UPDATE_PALETTE_DATA";

    /// `pad2Octets`, `numberColors` and 256 three byte entries.
    pub const LEN: usize = 2 + 4 + PALETTE_ENTRIES * 3;
}

impl Default for PaletteUpdate {
    fn default() -> Self {
        Self {
            entries: [PaletteEntry::default(); PALETTE_ENTRIES],
        }
    }
}

impl Decode<'_> for PaletteUpdate {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        r.skip(2, Self::NAME)?;
        let at = r.offset();
        let count = r.u32(Self::NAME)?;
        if count != PALETTE_ENTRIES as u32 {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "numberColors",
                value: u64::from(count),
                offset: at,
            });
        }
        let mut entries = [PaletteEntry::default(); PALETTE_ENTRIES];
        for entry in &mut entries {
            *entry = PaletteEntry {
                red: r.u8(Self::NAME)?,
                green: r.u8(Self::NAME)?,
                blue: r.u8(Self::NAME)?,
            };
        }
        Ok(Self { entries })
    }
}

impl Encode for PaletteUpdate {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(0);
        w.u32(PALETTE_ENTRIES as u32);
        for entry in &self.entries {
            w.u8(entry.red);
            w.u8(entry.green);
            w.u8(entry.blue);
        }
        Ok(())
    }
}

/// Which pointer structure a body holds, which the slow path reads from
/// `messageType` and the fast path from `updateCode`
/// (MS-RDPBCGR 2.2.9.1.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerKind {
    /// `TS_PTRMSGTYPE_SYSTEM`.
    System,
    /// `TS_PTRMSGTYPE_POSITION`.
    Position,
    /// `TS_PTRMSGTYPE_COLOR`.
    Color,
    /// `TS_PTRMSGTYPE_CACHED`.
    Cached,
    /// `TS_PTRMSGTYPE_POINTER`, the "new" pointer with its own bit depth.
    New,
    /// `TS_PTRMSGTYPE_LARGE_POINTER`.
    Large,
}

/// The number of bytes one row of an XOR mask occupies
/// (MS-RDPBCGR 2.2.9.1.1.4.4): the pixels, rounded up to a byte, then padded
/// to a two byte boundary.
#[must_use]
// `usize::div_ceil` is const stable only from Rust 1.83 and the workspace
// MSRV is 1.82, so the rounding is written out.
#[allow(clippy::manual_div_ceil)]
pub const fn xor_mask_row_len(width: u16, bits_per_pixel: u16) -> usize {
    let bits = (width as usize) * (bits_per_pixel as usize);
    let bytes = (bits + 7) / 8;
    (bytes + 1) & !1
}

/// The number of bytes a whole XOR mask occupies.
#[must_use]
pub const fn xor_mask_len(width: u16, height: u16, bits_per_pixel: u16) -> usize {
    xor_mask_row_len(width, bits_per_pixel) * (height as usize)
}

/// The number of bytes one row of the 1 bpp AND mask occupies, padded to a
/// two byte boundary (MS-RDPBCGR 2.2.9.1.1.4.4).
#[must_use]
pub const fn and_mask_row_len(width: u16) -> usize {
    xor_mask_row_len(width, 1)
}

/// The number of bytes a whole AND mask occupies.
#[must_use]
pub const fn and_mask_len(width: u16, height: u16) -> usize {
    and_mask_row_len(width) * (height as usize)
}

/// `TS_COLORPOINTERATTRIBUTE` (MS-RDPBCGR 2.2.9.1.1.4.4), and the body of
/// both `TS_POINTERATTRIBUTE` and `TS_LARGEPOINTERATTRIBUTE`.
///
/// The two masks are written in the reverse of the order their lengths are:
/// the lengths are `lengthAndMask` then `lengthXorMask`, and the data is
/// `xorMaskData` then `andMaskData`. That is the field ordering bug everyone
/// writes once, so this module's tests carry a vector whose masks have
/// different lengths and would fail if they were swapped (PRDRDP/13 §5.6.4).
///
/// Both masks are bottom up with rows padded to two bytes, and both are
/// [`Payload`]. Turning them into RGBA is PRDRDP/04 §6.7's topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorPointer<'a> {
    /// `cacheIndex`.
    pub cache_index: u16,
    /// `hotSpot`.
    pub hot_spot: Point16,
    /// `width`.
    pub width: u16,
    /// `height`.
    pub height: u16,
    /// `xorMaskData`, the colour, at the bit depth the enclosing structure
    /// states (24 for a plain colour pointer).
    pub xor_mask: Payload<'a>,
    /// `andMaskData`, 1 bpp transparency.
    pub and_mask: Payload<'a>,
}

impl<'a> ColorPointer<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_COLORPOINTERATTRIBUTE";

    /// `cacheIndex`, `hotSpot`, `width`, `height`.
    const HEADER_LEN: usize = 2 + Point16::LEN + 2 + 2;

    /// Read one, with `u16` mask lengths and the dimension cap of a colour or
    /// new pointer.
    ///
    /// `xor_bpp` is 24 for `TS_COLORPOINTERATTRIBUTE` and whatever
    /// `TS_POINTERATTRIBUTE.xorBpp` said otherwise; it is what the declared
    /// mask length is checked against.
    pub fn decode_short(r: &mut Reader<'a>, xor_bpp: u16) -> PduResult<Self> {
        Self::decode_inner(r, xor_bpp, MAX_COLOR_POINTER_DIM, false)
    }

    /// Read one with `u32` mask lengths and the large pointer dimension cap
    /// (MS-RDPBCGR 2.2.9.1.1.4.7).
    ///
    /// The widening of the two lengths from `u16` to `u32` is the only
    /// structural difference between a large pointer and a new one, and it is
    /// the one that breaks a copy pasted decoder (PRDRDP/13 §5.6.4).
    pub fn decode_long(r: &mut Reader<'a>, xor_bpp: u16) -> PduResult<Self> {
        Self::decode_inner(r, xor_bpp, MAX_POINTER_DIM, true)
    }

    fn decode_inner(
        r: &mut Reader<'a>,
        xor_bpp: u16,
        max_dim: usize,
        long_lengths: bool,
    ) -> PduResult<Self> {
        let cache_index = r.u16(Self::NAME)?;
        let hot_spot = Point16::decode(r)?;
        let at_dims = r.offset();
        let width = r.u16(Self::NAME)?;
        let height = r.u16(Self::NAME)?;
        if usize::from(width) > max_dim || usize::from(height) > max_dim {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "width or height",
                value: (u64::from(width) << 16) | u64::from(height),
                offset: at_dims,
            });
        }
        let at_lengths = r.offset();
        let (and_len, xor_len) = if long_lengths {
            let and = r.u32(Self::NAME)? as usize;
            let xor = r.u32(Self::NAME)? as usize;
            (and, xor)
        } else {
            let and = usize::from(r.u16(Self::NAME)?);
            let xor = usize::from(r.u16(Self::NAME)?);
            (and, xor)
        };
        // The dimensions bound the masks, so a pointer claiming a 40 KB AND
        // mask for a 32 by 32 cursor is refused before anything is
        // allocated (PRDRDP/13 §5.6.4). A shorter mask than the dimensions
        // imply is left to `rdp-core`: it cannot make us read out of bounds,
        // and a server that pads its last row differently still paints.
        let and_expected = and_mask_len(width, height);
        let xor_expected = xor_mask_len(width, height, xor_bpp);
        if and_len > and_expected {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "lengthAndMask",
                value: and_len as u64,
                offset: at_lengths,
            });
        }
        if xor_len > xor_expected {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "lengthXorMask",
                value: xor_len as u64,
                offset: at_lengths,
            });
        }
        // The data is in the reverse order of the lengths.
        let xor_mask = Payload::new(r.slice(xor_len, Self::NAME)?);
        let and_mask = Payload::new(r.slice(and_len, Self::NAME)?);
        Ok(Self {
            cache_index,
            hot_spot,
            width,
            height,
            xor_mask,
            and_mask,
        })
    }

    /// The encoded size with `u16` mask lengths.
    #[must_use]
    pub fn size_short(&self) -> usize {
        Self::HEADER_LEN + 4 + self.xor_mask.len() + self.and_mask.len()
    }

    /// The encoded size with `u32` mask lengths.
    #[must_use]
    pub fn size_long(&self) -> usize {
        Self::HEADER_LEN + 8 + self.xor_mask.len() + self.and_mask.len()
    }

    /// Write one with `u16` mask lengths.
    pub fn encode_short(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let and = u16::try_from(self.and_mask.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "AND mask longer than lengthAndMask",
        })?;
        let xor = u16::try_from(self.xor_mask.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "XOR mask longer than lengthXorMask",
        })?;
        self.encode_header(w)?;
        w.u16(and);
        w.u16(xor);
        self.encode_masks(w);
        Ok(())
    }

    /// Write one with `u32` mask lengths.
    pub fn encode_long(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let and = u32::try_from(self.and_mask.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "AND mask longer than lengthAndMask",
        })?;
        let xor = u32::try_from(self.xor_mask.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "XOR mask longer than lengthXorMask",
        })?;
        self.encode_header(w)?;
        w.u32(and);
        w.u32(xor);
        self.encode_masks(w);
        Ok(())
    }

    fn encode_header(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.cache_index);
        self.hot_spot.encode(w)?;
        w.u16(self.width);
        w.u16(self.height);
        Ok(())
    }

    fn encode_masks(&self, w: &mut Writer<'_>) {
        w.bytes(self.xor_mask.as_slice());
        w.bytes(self.and_mask.as_slice());
    }
}

/// One pointer update body, normalised across the two paths
/// (MS-RDPBCGR 2.2.9.1.1.4).
///
/// Direction: server to client, phase 1 (PRDRDP/13 §11).
///
/// The fast path's `FASTPATH_UPDATETYPE_PTR_NULL` and `_PTR_DEFAULT` are the
/// same thing as a slow path system pointer with `SYSPTR_NULL` or
/// `SYSPTR_DEFAULT`, so both arrive here as [`PointerUpdate::System`] and a
/// caller has one case to handle rather than three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerUpdate<'a> {
    /// `TS_SYSTEMPOINTERATTRIBUTE` (2.2.9.1.1.4.3), one of
    /// [`system_pointer`].
    System(u32),
    /// `TS_POINTERPOSATTRIBUTE` (2.2.9.1.1.4.2).
    Position(Point16),
    /// `TS_COLORPOINTERATTRIBUTE` (2.2.9.1.1.4.4), whose XOR mask is 24 bpp.
    Color(ColorPointer<'a>),
    /// `TS_CACHEDPOINTERATTRIBUTE` (2.2.9.1.1.4.6), a cache index.
    Cached(u16),
    /// `TS_POINTERATTRIBUTE` (2.2.9.1.1.4.5): a colour pointer with its own
    /// bit depth, which is how a 32 bpp cursor with a real alpha channel
    /// arrives.
    New {
        /// `xorBpp`: 1, 8, 16, 24 or 32.
        xor_bpp: u16,
        /// The masks and the hotspot.
        pointer: ColorPointer<'a>,
    },
    /// `TS_LARGEPOINTERATTRIBUTE` (2.2.9.1.1.4.7): a new pointer with `u32`
    /// mask lengths and dimensions up to
    /// [`MAX_POINTER_DIM`].
    Large {
        /// `xorBpp`.
        xor_bpp: u16,
        /// The masks and the hotspot.
        pointer: ColorPointer<'a>,
    },
}

/// The XOR bit depth `TS_COLORPOINTERATTRIBUTE` implies, which it does not
/// state (MS-RDPBCGR 2.2.9.1.1.4.4, PRDRDP/04 §6.2).
pub const COLOR_POINTER_BPP: u16 = 24;

impl<'a> PointerUpdate<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_POINTER_PDU body";

    /// Which structure this is.
    #[must_use]
    pub const fn kind(&self) -> PointerKind {
        match self {
            Self::System(_) => PointerKind::System,
            Self::Position(_) => PointerKind::Position,
            Self::Color(_) => PointerKind::Color,
            Self::Cached(_) => PointerKind::Cached,
            Self::New { .. } => PointerKind::New,
            Self::Large { .. } => PointerKind::Large,
        }
    }

    /// Read the body of a pointer update of a kind the caller has already
    /// read from `messageType` or from the fast path update code.
    ///
    /// `TS_COLORPOINTERATTRIBUTE` and `TS_POINTERATTRIBUTE` may carry one
    /// trailing pad byte, which the specification documents as optional
    /// without saying when it is there, so it is consumed if the bounded
    /// reader still holds exactly one byte. The encoder never emits it.
    pub fn decode_body(r: &mut Reader<'a>, kind: PointerKind) -> PduResult<Self> {
        let update = match kind {
            PointerKind::System => Self::System(r.u32(Self::NAME)?),
            PointerKind::Position => Self::Position(Point16::decode(r)?),
            PointerKind::Cached => Self::Cached(r.u16(Self::NAME)?),
            PointerKind::Color => Self::Color(ColorPointer::decode_short(r, COLOR_POINTER_BPP)?),
            PointerKind::New => {
                let xor_bpp = r.u16(Self::NAME)?;
                Self::New {
                    xor_bpp,
                    pointer: ColorPointer::decode_short(r, xor_bpp)?,
                }
            }
            PointerKind::Large => {
                let xor_bpp = r.u16(Self::NAME)?;
                Self::Large {
                    xor_bpp,
                    pointer: ColorPointer::decode_long(r, xor_bpp)?,
                }
            }
        };
        if matches!(kind, PointerKind::Color | PointerKind::New) && r.remaining() == 1 {
            r.skip(1, Self::NAME)?;
        }
        Ok(update)
    }

    /// The encoded size of the body.
    #[must_use]
    pub fn body_size(&self) -> usize {
        match self {
            Self::System(_) => 4,
            Self::Position(_) => Point16::LEN,
            Self::Cached(_) => 2,
            Self::Color(p) => p.size_short(),
            Self::New { pointer, .. } => 2 + pointer.size_short(),
            Self::Large { pointer, .. } => 2 + pointer.size_long(),
        }
    }

    /// Write the body, without the `messageType` or update code that names
    /// it.
    pub fn encode_body(&self, w: &mut Writer<'_>) -> PduResult<()> {
        match self {
            Self::System(kind) => {
                w.u32(*kind);
                Ok(())
            }
            Self::Position(point) => point.encode(w),
            Self::Cached(index) => {
                w.u16(*index);
                Ok(())
            }
            Self::Color(pointer) => pointer.encode_short(w),
            Self::New { xor_bpp, pointer } => {
                w.u16(*xor_bpp);
                pointer.encode_short(w)
            }
            Self::Large { xor_bpp, pointer } => {
                w.u16(*xor_bpp);
                pointer.encode_long(w)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// A 2 by 2 colour pointer whose two masks are deliberately different
    /// lengths, so swapping `xorMaskData` and `andMaskData` fails
    /// (PRDRDP/13 §5.6.4).
    ///
    /// At 24 bpp one XOR row is `2 * 3 = 6` bytes, already even, so the mask
    /// is 12 bytes. One AND row is one bit per pixel rounded to a byte, then
    /// padded to two, so 2 bytes and a 4 byte mask.
    pub(crate) const XOR_2X2_24BPP: &[u8] = &[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // bottom row
        0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, // top row
    ];
    /// The AND mask matching [`XOR_2X2_24BPP`].
    pub(crate) const AND_2X2: &[u8] = &[0x40, 0x00, 0x80, 0x00];

    pub(crate) fn color_pointer() -> ColorPointer<'static> {
        ColorPointer {
            cache_index: 3,
            hot_spot: Point16 { x: 1, y: 0 },
            width: 2,
            height: 2,
            xor_mask: Payload::new(XOR_2X2_24BPP),
            and_mask: Payload::new(AND_2X2),
        }
    }

    pub(crate) fn bitmap_update() -> BitmapUpdate<'static> {
        BitmapUpdate {
            rectangles: vec![
                BitmapData {
                    dest: RectInclusive {
                        left: 0,
                        top: 0,
                        right: 15,
                        bottom: 7,
                    },
                    width: 16,
                    height: 8,
                    bits_per_pixel: 16,
                    flags: 0,
                    compression_header: None,
                    data: Payload::new(&[0xab; 256]),
                },
                BitmapData {
                    dest: RectInclusive {
                        left: 16,
                        top: 0,
                        right: 31,
                        bottom: 7,
                    },
                    width: 16,
                    height: 8,
                    bits_per_pixel: 16,
                    flags: bitmap_flags::COMPRESSION,
                    compression_header: Some(CompressedDataHeader {
                        main_body_size: 4,
                        scan_width: 16,
                        uncompressed_size: 256,
                    }),
                    data: Payload::new(&[1, 2, 3, 4]),
                },
            ],
        }
    }

    fn encoded<T: Encode>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        buf
    }

    #[test]
    fn the_two_rectangle_conventions_convert_explicitly() {
        let inclusive = RectInclusive {
            left: 10,
            top: 20,
            right: 10,
            bottom: 24,
        };
        assert_eq!(inclusive.width(), Some(1));
        assert_eq!(inclusive.height(), Some(5));
        let exclusive = inclusive.to_exclusive().unwrap();
        assert_eq!(exclusive.width(), Some(1));
        assert_eq!(exclusive.height(), Some(5));
        assert_eq!(exclusive.to_inclusive(), Some(inclusive));

        // An empty exclusive rectangle has no inclusive form.
        let empty = RectExclusive {
            left: 5,
            top: 5,
            right: 5,
            bottom: 5,
        };
        assert_eq!(empty.width(), Some(0));
        assert_eq!(empty.to_inclusive(), None);

        // An inclusive rectangle touching the edge of the field cannot widen.
        let edge = RectInclusive {
            left: 0,
            top: 0,
            right: u16::MAX,
            bottom: 0,
        };
        assert_eq!(edge.to_exclusive(), None);
    }

    #[test]
    fn bitmap_update_round_trip() {
        let value = bitmap_update();
        let buf = encoded(&value);
        assert_eq!(buf.len(), value.size());
        let mut r = Reader::new(&buf);
        assert_eq!(BitmapUpdate::decode(&mut r).unwrap(), value);
        assert!(r.is_empty());
    }

    /// `bitmapLength` counts the eight header bytes when the header is there
    /// and only the payload when it is not (PRDRDP/13 §5.6.1).
    #[test]
    fn bitmap_length_counts_the_compression_header() {
        let value = bitmap_update();
        let buf = encoded(&value);
        // Second rectangle: 18 fixed bytes for the first, plus its 256 byte
        // payload, then 16 bytes into the second is `bitmapLength`.
        let at = 2 + 18 + 256 + 16;
        let declared = u16::from_le_bytes([buf[at], buf[at + 1]]);
        assert_eq!(declared, (CompressedDataHeader::LEN + 4) as u16);
    }

    #[test]
    fn a_destination_larger_than_the_bitmap_is_refused() {
        let mut value = bitmap_update();
        value.rectangles[0].dest.right = 63;
        let buf = encoded(&value);
        assert!(matches!(
            BitmapUpdate::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::InvalidField { .. }
        ));
    }

    /// A destination smaller than the encoded bitmap is legal: the bitmap is
    /// clipped, not scaled, and `rdp-core` does the clipping
    /// (PRDRDP/04 §2.2).
    #[test]
    fn a_destination_smaller_than_the_bitmap_decodes() {
        let mut value = bitmap_update();
        value.rectangles[0].dest.right = 7;
        let buf = encoded(&value);
        let back = BitmapUpdate::decode(&mut Reader::new(&buf)).unwrap();
        assert_eq!(back.rectangles[0].dest.width(), Some(8));
        assert_eq!(back.rectangles[0].width, 16);
    }

    #[test]
    fn an_inverted_destination_is_refused_rather_than_wrapping() {
        let mut value = bitmap_update();
        value.rectangles[0].dest.right = 0;
        value.rectangles[0].dest.left = 15;
        let buf = encoded(&value);
        assert!(BitmapUpdate::decode(&mut Reader::new(&buf)).is_err());
    }

    #[test]
    fn a_compression_header_claiming_a_first_row_is_refused() {
        let mut buf = encoded(&bitmap_update());
        // `cbCompFirstRowSize` of the second rectangle, 18 bytes in plus its
        // payload plus the second rectangle's 18 fixed bytes.
        let at = 2 + 18 + 256 + 18;
        buf[at] = 0x01;
        assert!(matches!(
            BitmapUpdate::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::InvalidField {
                field: "cbCompFirstRowSize",
                ..
            }
        ));
    }

    #[test]
    fn a_hostile_rectangle_count_is_capped_before_the_vec_is_reserved() {
        let buf = hex::decode("ffff").unwrap();
        assert!(matches!(
            BitmapUpdate::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_BITMAP_RECTS",
                ..
            }
        ));
    }

    #[test]
    fn bitmap_update_truncated_at_every_offset_errors_without_panicking() {
        let buf = encoded(&bitmap_update());
        for cut in 0..buf.len() {
            assert!(
                BitmapUpdate::decode(&mut Reader::new(&buf[..cut])).is_err(),
                "decoded a bitmap update truncated to {cut} bytes"
            );
        }
    }

    #[test]
    fn palette_round_trip_and_size() {
        let mut value = PaletteUpdate::default();
        for (i, entry) in value.entries.iter_mut().enumerate() {
            *entry = PaletteEntry {
                red: i as u8,
                green: (i as u8).wrapping_add(1),
                blue: (i as u8).wrapping_add(2),
            };
        }
        let buf = encoded(&value);
        // pad2Octets, numberColors, 256 three byte entries. PRDRDP/13 §5.6.2
        // calls this 772 bytes, which is two short of the fields it lists.
        assert_eq!(buf.len(), 774);
        assert_eq!(
            PaletteUpdate::decode(&mut Reader::new(&buf)).unwrap(),
            value
        );
    }

    #[test]
    fn a_palette_that_is_not_256_colours_is_refused() {
        let mut buf = encoded(&PaletteUpdate::default());
        buf[2] = 0x80;
        assert!(matches!(
            PaletteUpdate::decode(&mut Reader::new(&buf)).unwrap_err(),
            PduError::InvalidField {
                field: "numberColors",
                ..
            }
        ));
    }

    #[test]
    fn palette_truncated_at_every_offset_errors_without_panicking() {
        let buf = encoded(&PaletteUpdate::default());
        for cut in 0..buf.len() {
            assert!(PaletteUpdate::decode(&mut Reader::new(&buf[..cut])).is_err());
        }
    }

    /// The mask row padding rules of MS-RDPBCGR 2.2.9.1.1.4.4, which every
    /// length check in the pointer decoders rests on.
    #[test]
    fn mask_lengths_follow_the_two_byte_row_padding() {
        // 24 bpp, 2 pixels: 6 bytes, already even.
        assert_eq!(xor_mask_row_len(2, 24), 6);
        assert_eq!(xor_mask_len(2, 2, 24), 12);
        // 1 bpp, 2 pixels: 1 byte, padded to 2.
        assert_eq!(and_mask_row_len(2), 2);
        assert_eq!(and_mask_len(2, 2), 4);
        // 1 bpp, 32 pixels: 4 bytes, already even.
        assert_eq!(and_mask_row_len(32), 4);
        // 32 bpp, 33 pixels: 132 bytes, already even.
        assert_eq!(xor_mask_row_len(33, 32), 132);
        // 24 bpp, 3 pixels: 9 bytes, padded to 10.
        assert_eq!(xor_mask_row_len(3, 24), 10);
    }

    /// The vector whose masks are different lengths: swapping the two data
    /// fields changes the bytes and the decode.
    #[test]
    fn golden_colour_pointer_masks_are_not_interchangeable() {
        let value = PointerUpdate::Color(color_pointer());
        let mut buf = Vec::new();
        value.encode_body(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.body_size());

        let expected = hex::decode(concat!(
            "0300",                     // cacheIndex
            "0100",                     // hotSpot.x
            "0000",                     // hotSpot.y
            "0200",                     // width
            "0200",                     // height
            "0400",                     // lengthAndMask, four bytes
            "0c00",                     // lengthXorMask, twelve bytes
            "112233445566778899aabbcc", // xorMaskData first
            "40008000",                 // andMaskData second
        ))
        .unwrap();
        assert_eq!(buf, expected);

        let back = PointerUpdate::decode_body(&mut Reader::new(&buf), PointerKind::Color).unwrap();
        assert_eq!(back, value);
        match back {
            PointerUpdate::Color(p) => {
                assert_eq!(p.xor_mask.len(), 12);
                assert_eq!(p.and_mask.len(), 4);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn every_pointer_kind_round_trips() {
        let samples = [
            PointerUpdate::System(system_pointer::NULL),
            PointerUpdate::System(system_pointer::DEFAULT),
            PointerUpdate::Position(Point16 { x: 640, y: 480 }),
            PointerUpdate::Cached(7),
            PointerUpdate::Color(color_pointer()),
            PointerUpdate::New {
                xor_bpp: 24,
                pointer: color_pointer(),
            },
            PointerUpdate::Large {
                xor_bpp: 24,
                pointer: color_pointer(),
            },
        ];
        for value in samples {
            let mut buf = Vec::new();
            value.encode_body(&mut Writer::new(&mut buf)).unwrap();
            assert_eq!(buf.len(), value.body_size(), "{value:?}");
            let mut r = Reader::new(&buf);
            let back = PointerUpdate::decode_body(&mut r, value.kind()).unwrap();
            assert_eq!(back, value);
            assert!(r.is_empty(), "{value:?}");

            for cut in 0..buf.len() {
                let mut r = Reader::new(&buf[..cut]);
                assert!(
                    PointerUpdate::decode_body(&mut r, value.kind()).is_err(),
                    "{value:?} truncated to {cut} bytes decoded"
                );
            }
        }
    }

    /// The large pointer's `u32` lengths are the one structural difference
    /// from the new pointer, and a decoder that copied the `u16` form reads
    /// the masks four bytes early.
    #[test]
    fn a_large_pointer_uses_four_byte_mask_lengths() {
        let value = PointerUpdate::Large {
            xor_bpp: 24,
            pointer: color_pointer(),
        };
        let mut buf = Vec::new();
        value.encode_body(&mut Writer::new(&mut buf)).unwrap();
        // xorBpp, cacheIndex, hotSpot, width, height, then two u32 lengths.
        assert_eq!(&buf[12..16], &[0x04, 0x00, 0x00, 0x00]);
        assert_eq!(&buf[16..20], &[0x0c, 0x00, 0x00, 0x00]);
        // Reading it as a new pointer, whose lengths are u16, misreads both
        // masks and leaves sixteen bytes of cursor behind. It does not fail,
        // which is exactly why the two forms are separate decoders.
        let mut r = Reader::new(&buf);
        let misread = PointerUpdate::decode_body(&mut r, PointerKind::New).unwrap();
        match misread {
            PointerUpdate::New { pointer, .. } => {
                assert!(
                    pointer.xor_mask.is_empty(),
                    "the XOR length was read from padding"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            r.remaining(),
            16,
            "the misread left most of the cursor unread"
        );
    }

    #[test]
    fn a_pointer_larger_than_its_cap_is_refused_before_any_arithmetic() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.u16(0); // cacheIndex
        w.u16(0); // hotSpot.x
        w.u16(0); // hotSpot.y
        w.u16(97); // width, one past the colour pointer cap
        w.u16(97);
        w.u16(0);
        w.u16(0);
        assert!(matches!(
            PointerUpdate::decode_body(&mut Reader::new(&buf), PointerKind::Color).unwrap_err(),
            PduError::InvalidField {
                field: "width or height",
                ..
            }
        ));
        // The large pointer's own cap is 384.
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.u16(24); // xorBpp
        w.u16(0);
        w.u16(0);
        w.u16(0);
        w.u16(385);
        w.u16(385);
        w.u32(0);
        w.u32(0);
        assert!(PointerUpdate::decode_body(&mut Reader::new(&buf), PointerKind::Large).is_err());
    }

    /// The check that stops a 40 KB AND mask for a 32 by 32 cursor
    /// (PRDRDP/13 §5.6.4).
    #[test]
    fn a_mask_longer_than_the_dimensions_imply_is_refused() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.u16(0);
        w.u16(0);
        w.u16(0);
        w.u16(32);
        w.u16(32);
        w.u16(40_000); // lengthAndMask
        w.u16(0);
        assert!(matches!(
            PointerUpdate::decode_body(&mut Reader::new(&buf), PointerKind::Color).unwrap_err(),
            PduError::InvalidField {
                field: "lengthAndMask",
                ..
            }
        ));
    }

    /// The optional trailing pad byte of 2.2.9.1.1.4.4, which the
    /// specification documents without saying when it is present.
    #[test]
    fn a_colour_pointer_tolerates_its_optional_pad_byte() {
        let value = PointerUpdate::Color(color_pointer());
        let mut buf = Vec::new();
        value.encode_body(&mut Writer::new(&mut buf)).unwrap();
        buf.push(0x00);
        let mut r = Reader::new(&buf);
        assert_eq!(
            PointerUpdate::decode_body(&mut r, PointerKind::Color).unwrap(),
            value
        );
        assert!(r.is_empty());
    }
}
