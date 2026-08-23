//! The RFB wire pixel format (RFB §7.4).
//!
//! Moved out of `vnc-core/src/types.rs` with the conversion routines that take
//! it. It loses its `Serialize`/`Deserialize` derives on the way: this crate
//! has no dependencies at all, which is the property that lets `rdp-codecs`
//! take it without acquiring tokio (PRDRDP/02 §13 commit 1b). Nothing in the
//! workspace serialized a `PixelFormat`.
//!
//! [`Format`], below, is the other half: the closed set of seven layouts RDP
//! defines (PRDRDP/04 §4.2). The two live in one module because they answer
//! the same question, "how is a wire pixel laid out", and they are separate
//! types because RFB's answer is open ended and RDP's is not.

use crate::dst::PixelError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    /// 32bpp true colour, little endian, BGRA byte order in memory, our
    /// canonical local format (matches what the WebGL renderer expects after
    /// conversion to RGBA).
    pub const fn bgra8888() -> Self {
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }

    /// 8-bit palette (256 colours), used by the Low quality preset.
    pub const fn palette8() -> Self {
        Self {
            bits_per_pixel: 8,
            depth: 8,
            big_endian: false,
            true_colour: false,
            red_max: 0,
            green_max: 0,
            blue_max: 0,
            red_shift: 0,
            green_shift: 0,
            blue_shift: 0,
        }
    }

    /// rgb222-64 colours.
    pub const fn rgb222() -> Self {
        Self {
            bits_per_pixel: 8,
            depth: 6,
            big_endian: false,
            true_colour: true,
            red_max: 3,
            green_max: 3,
            blue_max: 3,
            red_shift: 4,
            green_shift: 2,
            blue_shift: 0,
        }
    }

    pub fn bytes_per_pixel(&self) -> usize {
        (self.bits_per_pixel as usize) / 8
    }

    /// True when Tight/ZRLE may use the compact 3-byte CPIXEL/TPIXEL form.
    pub fn is_compact_3byte(&self) -> bool {
        self.bits_per_pixel == 32
            && self.depth == 24
            && self.red_max == 255
            && self.green_max == 255
            && self.blue_max == 255
    }
}

// ---------------------------------------------------------------------------
// The closed RDP layout set (PRDRDP/04 §4.2)
// ---------------------------------------------------------------------------

/// A closed set of wire pixel layouts. RDP has these and nothing else
/// (PRDRDP/04 §4.2).
///
/// Moved here from `crates/rdp-codecs/src/dst.rs`, where it was called
/// `PixelFormat` while this crate was still the verbatim RFB move
/// (PRDRDP/00 R37). It is `Format` here because [`PixelFormat`] above is the
/// open ended RFB layout and the two are different things: RFB negotiates
/// arbitrary channel maxima and shifts, RDP has seven fixed layouts and no
/// way to describe an eighth. `rdp-codecs` re-exports this one under its old
/// name so no call site there changed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// 32 bpp, byte order B, G, R, X in memory. The common case.
    BgrX32,
    /// 32 bpp with a meaningful alpha byte (the EGFX alpha codec, 32 bpp
    /// pointers).
    BgrA32,
    /// 24 bpp, byte order B, G, R.
    Bgr24,
    /// 16 bpp little endian, 5-6-5.
    Rgb565,
    /// 15 bpp little endian, 5-5-5, top bit ignored.
    Rgb555,
    /// 8 bpp palette index; needs the session palette (PRDRDP/04 §2.7).
    Palette8,
    /// 1 bpp, MSB first, 0 is black and 1 is white. Legal in
    /// `TS_BITMAP_DATA` and in pointer masks.
    Mono1,
}

impl Format {
    /// The `bitsPerPixel` field of `TS_BITMAP_DATA`
    /// (MS-RDPBCGR 2.2.9.1.1.3.1.2.2) mapped onto a layout.
    ///
    /// 16 is 5-6-5 and 15 is 5-5-5; a server that means 5-5-5 says 15, and
    /// there is no in band way to tell them apart at 16, which is why the
    /// field is trusted rather than sniffed.
    pub fn from_legacy_bpp(bits_per_pixel: u8) -> Result<Self, PixelError> {
        match bits_per_pixel {
            1 => Ok(Format::Mono1),
            8 => Ok(Format::Palette8),
            15 => Ok(Format::Rgb555),
            16 => Ok(Format::Rgb565),
            24 => Ok(Format::Bgr24),
            32 => Ok(Format::BgrX32),
            other => Err(PixelError::Range {
                what: "bitsPerPixel",
                got: u32::from(other),
            }),
        }
    }

    /// Bits per wire pixel.
    pub fn bits(self) -> usize {
        match self {
            Format::BgrX32 | Format::BgrA32 => 32,
            Format::Bgr24 => 24,
            Format::Rgb565 | Format::Rgb555 => 16,
            Format::Palette8 => 8,
            Format::Mono1 => 1,
        }
    }

    /// Bytes a scanline of `width` pixels really occupies, before any padding.
    pub fn row_bytes(self, width: u16) -> usize {
        (usize::from(width) * self.bits()).div_ceil(8)
    }

    /// The smallest source a [`convert_image`](crate::convert_image) call with
    /// this geometry can accept.
    ///
    /// The last row's trailing padding is not required to be present. Windows
    /// always sends it, and accepting a stream without it costs nothing and
    /// removes one reason to reject a rect from a server we have not met
    /// (PRDRDP/04 §2.3).
    pub fn min_src_len(self, src_stride: usize, width: u16, height: u16) -> usize {
        match usize::from(height).checked_sub(1) {
            None => 0,
            Some(n) => n * src_stride + self.row_bytes(width),
        }
    }
}
