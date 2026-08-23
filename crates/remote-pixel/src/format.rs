//! The RFB wire pixel format (RFB §7.4).
//!
//! Moved out of `vnc-core/src/types.rs` with the conversion routines that take
//! it. It loses its `Serialize`/`Deserialize` derives on the way: this crate
//! has no dependencies at all, which is the property that lets `rdp-codecs`
//! take it without acquiring tokio (PRDRDP/02 §13 commit 1b). Nothing in the
//! workspace serialized a `PixelFormat`.

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
