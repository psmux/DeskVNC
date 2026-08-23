//! The destination a decoder writes through, and the wire pixel layouts it
//! reads from (PRDRDP/04 §4.2).
//!
//! ## Why the decoders take a `DstView` rather than nine loose arguments
//!
//! PRDRDP/04 §4.2 puts three things on every destination write: a caller owned
//! buffer, a stride, and a row order. §2.3 adds the rule that makes the row
//! order load bearing: legacy `TS_BITMAP_DATA` is a DIB body and its rows are
//! stored bottom to top, while Surface Bits (§2.8) and every EGFX codec are
//! top down. Getting that backwards inverts the picture in a way that is
//! obvious on screen and invisible to a unit test with a symmetric pattern.
//!
//! Bundling them buys three things. The buffer length is proved once in
//! [`DstView::new`] instead of once per row, so the row loops index a subslice
//! that cannot be short (PRDRDP/04 §4.6.8 rule two). The flip lives in exactly
//! one expression, [`DstView::row`], which keeps §4.2's rule that no decoder
//! reverses its own rows: both interleaved RLE and planar predict from the
//! previously decoded scanline, and a decoder that wrote its rows in reverse
//! to save the flip would predict from the wrong neighbour and produce a
//! picture that looks almost right. And it keeps the argument list of a decode
//! call at four or five, which matters because every one of them is a `usize`
//! and a transposed pair compiles.
//!
//! ## Where this goes when `remote-pixel` lands
//!
//! PRDRDP/00 R37 moves pixel conversion into `crates/remote-pixel` with
//! exactly this shape: `Format`, `RowOrder`, `Palette`, `convert_row` and
//! `convert_image`. That crate is a stub at the time of writing, so the row
//! converter here is the interim implementation and the names deliberately
//! match §4.2's listing so the swap is mechanical: [`PixelFormat`] becomes
//! `remote_pixel::Format` and [`uncompressed::decode`] delegates its inner
//! loop rather than owning it.
//!
//! [`uncompressed::decode`]: crate::uncompressed::decode

use crate::DecodeError;

/// Bytes per destination pixel. The destination is always 32 bits per pixel:
/// `RectPayload::Rgba` for a framebuffer rect, BGRA for an EGFX surface.
pub const DST_BPP: usize = 4;

/// Source row order relative to the destination, which is always top down.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowOrder {
    /// Row zero of the bitstream is the top row. EGFX and Surface Bits
    /// (PRDRDP/04 §2.8).
    TopDown,
    /// Row zero of the bitstream is the bottom row. The legacy DIB body
    /// (PRDRDP/04 §2.3).
    BottomUp,
}

/// Destination channel order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutFormat {
    /// `RectPayload::Rgba`, what the framing layer and the WebGL renderer
    /// take.
    Rgba,
    /// An EGFX surface, stored BGRA8888 (PRDRDP/04 §3.3).
    Bgra,
}

/// A closed set of wire pixel layouts. RDP has these and nothing else
/// (PRDRDP/04 §4.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PixelFormat {
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

impl PixelFormat {
    /// The `bitsPerPixel` field of `TS_BITMAP_DATA`
    /// (MS-RDPBCGR 2.2.9.1.1.3.1.2.2) mapped onto a layout.
    ///
    /// 16 is 5-6-5 and 15 is 5-5-5; a server that means 5-5-5 says 15, and
    /// there is no in band way to tell them apart at 16, which is why the
    /// field is trusted rather than sniffed.
    pub fn from_legacy_bpp(bits_per_pixel: u8) -> Result<Self, DecodeError> {
        match bits_per_pixel {
            1 => Ok(PixelFormat::Mono1),
            8 => Ok(PixelFormat::Palette8),
            15 => Ok(PixelFormat::Rgb555),
            16 => Ok(PixelFormat::Rgb565),
            24 => Ok(PixelFormat::Bgr24),
            32 => Ok(PixelFormat::BgrX32),
            other => Err(DecodeError::Range {
                what: "bitsPerPixel",
                got: u32::from(other),
            }),
        }
    }

    /// Bits per wire pixel.
    pub fn bits(self) -> usize {
        match self {
            PixelFormat::BgrX32 | PixelFormat::BgrA32 => 32,
            PixelFormat::Bgr24 => 24,
            PixelFormat::Rgb565 | PixelFormat::Rgb555 => 16,
            PixelFormat::Palette8 => 8,
            PixelFormat::Mono1 => 1,
        }
    }

    /// Bytes a scanline of `width` pixels really occupies, before any padding.
    pub fn row_bytes(self, width: u16) -> usize {
        (usize::from(width) * self.bits()).div_ceil(8)
    }
}

/// A 256 entry RGBA table. The RDP palette (`TS_UPDATE_PALETTE`,
/// MS-RDPBCGR 2.2.9.1.1.3.1.1.1) and the RFB colour map are the same thing
/// once built.
#[derive(Clone)]
pub struct Palette([[u8; 4]; 256]);

impl Palette {
    /// Replace one entry from a `TS_PALETTE_ENTRY`.
    pub fn set(&mut self, index: u8, red: u8, green: u8, blue: u8) {
        self.0[usize::from(index)] = [red, green, blue, 0xFF];
    }

    /// Load from the `TS_UPDATE_PALETTE` body, which is `{red, green, blue}`
    /// bytes per entry. A short list leaves the remaining entries alone,
    /// because a server is allowed to send fewer than 256.
    pub fn load_rgb_triplets(&mut self, entries: &[u8]) {
        for (i, e) in entries.chunks_exact(3).take(256).enumerate() {
            self.0[i] = [e[0], e[1], e[2], 0xFF];
        }
    }

    fn entry(&self, index: u8) -> [u8; 4] {
        self.0[usize::from(index)]
    }
}

impl Default for Palette {
    /// A grayscale identity ramp, the same defensive default as
    /// `crates/vnc-core/src/pixel/convert.rs:15` builds for `ColourMap`
    /// (PRDRDP/04 §2.7). A server that sends indexed pixels before its palette
    /// then produces a legible grey picture rather than a black screen.
    fn default() -> Self {
        let mut t = [[0u8; 4]; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let v = i as u8;
            *e = [v, v, v, 0xFF];
        }
        Palette(t)
    }
}

/// The caller owned destination, with its stride, its geometry and the row
/// order to apply on the way out.
///
/// The buffer is validated once at construction. Every row handed out by
/// [`DstView::row`] is exactly `width * 4` bytes and is proved to be inside
/// the buffer, so the per pixel loops that consume it carry no bounds check.
pub struct DstView<'a> {
    buf: &'a mut [u8],
    stride: usize,
    width: u16,
    height: u16,
    format: OutFormat,
    order: RowOrder,
}

impl<'a> DstView<'a> {
    /// Wrap a destination.
    ///
    /// `stride` is in bytes and lets a decoder write a rectangle into a larger
    /// framebuffer without a second copy, which is the D9 zero copy invariant
    /// applied to the output side: the decode into the destination is the only
    /// copy per bitmap rect.
    pub fn new(
        buf: &'a mut [u8],
        stride: usize,
        width: u16,
        height: u16,
        format: OutFormat,
        order: RowOrder,
    ) -> Result<Self, DecodeError> {
        let row = usize::from(width) * DST_BPP;
        if stride < row {
            return Err(DecodeError::Dst {
                need: row,
                have: stride,
            });
        }
        // The last row does not need its trailing padding to be present.
        let need = match usize::from(height).checked_sub(1) {
            None => 0,
            Some(n) => n * stride + row,
        };
        if buf.len() < need {
            return Err(DecodeError::Dst {
                need,
                have: buf.len(),
            });
        }
        Ok(Self {
            buf,
            stride,
            width,
            height,
            format,
            order,
        })
    }

    /// A tightly packed destination, the common case for a decoded rect that
    /// becomes a `RectPayload::Rgba` of its own.
    pub fn packed(
        buf: &'a mut [u8],
        width: u16,
        height: u16,
        format: OutFormat,
        order: RowOrder,
    ) -> Result<Self, DecodeError> {
        Self::new(
            buf,
            usize::from(width) * DST_BPP,
            width,
            height,
            format,
            order,
        )
    }

    /// Width in pixels.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Height in pixels.
    pub fn height(&self) -> u16 {
        self.height
    }

    /// Destination channel order.
    pub fn format(&self) -> OutFormat {
        self.format
    }

    /// Row `y` counted from the top of the *image*, exactly `width * 4` bytes.
    ///
    /// This is the only place [`RowOrder::BottomUp`] exists in the crate
    /// (PRDRDP/04 §4.2). The whole implementation of the flip is the one index
    /// expression below, and it costs nothing because it is per row.
    ///
    /// # Panics
    ///
    /// Never on remote input: `y` comes from a decoder's own row loop, which
    /// is bounded by [`DstView::height`], and the slice was proved to exist in
    /// [`DstView::new`]. A `y` past the end is a bug in this crate, and the
    /// debug assertion is there to name it.
    pub(crate) fn row(&mut self, y: usize) -> &mut [u8] {
        debug_assert!(y < usize::from(self.height), "row {y} past the destination");
        let phys = match self.order {
            RowOrder::TopDown => y,
            RowOrder::BottomUp => usize::from(self.height) - 1 - y,
        };
        let off = phys * self.stride;
        &mut self.buf[off..off + usize::from(self.width) * DST_BPP]
    }
}

/// Store one pixel into a four byte destination chunk.
///
/// `BGRA` is a const generic rather than a runtime flag so the branch is
/// resolved at monomorphisation and the row loops stay branch free
/// (PRDRDP/04 §4.6.8 rule one). The indices are constants, and the chunk came
/// from `chunks_exact_mut(4)`, so there is no bounds check here either.
#[inline(always)]
pub(crate) fn put<const BGRA: bool>(d: &mut [u8], r: u8, g: u8, b: u8, a: u8) {
    if BGRA {
        d[0] = b;
        d[1] = g;
        d[2] = r;
    } else {
        d[0] = r;
        d[1] = g;
        d[2] = b;
    }
    d[3] = a;
}

/// Expand a 5 bit channel to 8 bits by bit replication, which is what
/// `convert.rs:96` does for the general case and what the fixed 5-6-5 and
/// 5-5-5 layouts collapse to. 0x1F maps to 0xFF, so white stays white.
#[inline(always)]
pub(crate) fn expand5(v: u16) -> u8 {
    let v = (v & 0x1F) as u8;
    (v << 3) | (v >> 2)
}

/// Expand a 6 bit channel to 8 bits by bit replication.
#[inline(always)]
pub(crate) fn expand6(v: u16) -> u8 {
    let v = (v & 0x3F) as u8;
    (v << 2) | (v >> 4)
}

/// One source row into one RGBA or BGRA destination row.
///
/// `src` is cut to the row's real bytes by the caller, so the DIB padding of
/// PRDRDP/04 §2.3 is never read. `dst` is exactly `w * 4`.
///
/// A short `src` does not panic: the tail is opaque black. That is the policy
/// `crates/vnc-core/src/pixel/convert.rs:216` already applies, and it is the
/// second line of defence behind the length check every decoder does up front.
pub(crate) fn convert_row(
    fmt: PixelFormat,
    src: &[u8],
    dst: &mut [u8],
    out: OutFormat,
    pal: &Palette,
) {
    match out {
        OutFormat::Rgba => convert_row_impl::<false>(fmt, src, dst, pal),
        OutFormat::Bgra => convert_row_impl::<true>(fmt, src, dst, pal),
    }
}

fn convert_row_impl<const BGRA: bool>(fmt: PixelFormat, src: &[u8], dst: &mut [u8], pal: &Palette) {
    let want = dst.len() / DST_BPP;
    // How many pixels the source really carries. Everything past this is the
    // opaque black tail.
    let have = match fmt {
        PixelFormat::Mono1 => src.len() * 8,
        other => src.len() / (other.bits() / 8),
    };
    let n = want.min(have);
    // Slice once, with a length proved here, so neither loop below can panic
    // partway through. LLVM will not vectorise a loop that can
    // (PRDRDP/04 §4.6.8 rule two).
    let (head, tail) = dst.split_at_mut(n * DST_BPP);

    match fmt {
        // The canonical 32 bpp path: a pure byte swizzle, measured at
        // 6332 MPix/s in the VNC crate (docs/PERFORMANCE.md §3.2). RDP's
        // 32 bpp wire format is exactly this layout.
        PixelFormat::BgrX32 => {
            for (s, d) in src.chunks_exact(4).zip(head.chunks_exact_mut(DST_BPP)) {
                put::<BGRA>(d, s[2], s[1], s[0], 0xFF);
            }
        }
        PixelFormat::BgrA32 => {
            for (s, d) in src.chunks_exact(4).zip(head.chunks_exact_mut(DST_BPP)) {
                put::<BGRA>(d, s[2], s[1], s[0], s[3]);
            }
        }
        PixelFormat::Bgr24 => {
            for (s, d) in src.chunks_exact(3).zip(head.chunks_exact_mut(DST_BPP)) {
                put::<BGRA>(d, s[2], s[1], s[0], 0xFF);
            }
        }
        // The channel maxima are compile time constants here, unlike the RFB
        // path which has to handle arbitrary maxima, so the shift and mask
        // sequence is inlined instead of going through a lookup table
        // (PRDRDP/04 §4.2).
        PixelFormat::Rgb565 => {
            for (s, d) in src.chunks_exact(2).zip(head.chunks_exact_mut(DST_BPP)) {
                let v = u16::from_le_bytes([s[0], s[1]]);
                put::<BGRA>(d, expand5(v >> 11), expand6(v >> 5), expand5(v), 0xFF);
            }
        }
        PixelFormat::Rgb555 => {
            for (s, d) in src.chunks_exact(2).zip(head.chunks_exact_mut(DST_BPP)) {
                let v = u16::from_le_bytes([s[0], s[1]]);
                put::<BGRA>(d, expand5(v >> 10), expand5(v >> 5), expand5(v), 0xFF);
            }
        }
        PixelFormat::Palette8 => {
            for (s, d) in src.iter().zip(head.chunks_exact_mut(DST_BPP)) {
                let e = pal.entry(*s);
                put::<BGRA>(d, e[0], e[1], e[2], e[3]);
            }
        }
        // MSB first within each byte, so bit 7 is the leftmost pixel.
        PixelFormat::Mono1 => {
            for (i, d) in head.chunks_exact_mut(DST_BPP).enumerate() {
                let byte = src[i / 8];
                let v = if byte & (0x80 >> (i % 8)) != 0 {
                    0xFF
                } else {
                    0x00
                };
                put::<BGRA>(d, v, v, v, 0xFF);
            }
        }
    }

    for d in tail.chunks_exact_mut(DST_BPP) {
        put::<BGRA>(d, 0, 0, 0, 0xFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bottom_up_flip_is_the_only_difference_between_the_two_orders() {
        // An asymmetric pattern, because a symmetric one cannot tell the two
        // apart. PRDRDP/04 §2.3 makes exactly this point about fixtures.
        let mut top = vec![0u8; 2 * 3 * DST_BPP];
        let mut bottom = vec![0u8; 2 * 3 * DST_BPP];
        {
            let mut t =
                DstView::packed(&mut top, 2, 3, OutFormat::Rgba, RowOrder::TopDown).unwrap();
            let mut b =
                DstView::packed(&mut bottom, 2, 3, OutFormat::Rgba, RowOrder::BottomUp).unwrap();
            for y in 0..3usize {
                t.row(y).fill(y as u8);
                b.row(y).fill(y as u8);
            }
        }
        assert_eq!(top[0], 0);
        assert_eq!(top[2 * DST_BPP * 2], 2);
        assert_eq!(bottom[0], 2, "bottom up must place image row 0 last");
        assert_eq!(bottom[2 * DST_BPP * 2], 0);
    }

    #[test]
    fn stride_wider_than_the_row_leaves_the_padding_alone() {
        let mut buf = vec![0xAAu8; 3 * 16];
        {
            let mut v =
                DstView::new(&mut buf, 16, 2, 3, OutFormat::Rgba, RowOrder::TopDown).unwrap();
            for y in 0..3usize {
                v.row(y).fill(0x11);
            }
        }
        for y in 0..3 {
            assert_eq!(&buf[y * 16..y * 16 + 8], &[0x11; 8]);
            assert_eq!(&buf[y * 16 + 8..y * 16 + 16], &[0xAA; 8]);
        }
    }

    #[test]
    fn short_destination_is_an_error_not_a_panic() {
        let mut buf = vec![0u8; 4];
        assert!(matches!(
            DstView::packed(&mut buf, 4, 4, OutFormat::Rgba, RowOrder::TopDown),
            Err(DecodeError::Dst { .. })
        ));
        assert!(matches!(
            DstView::new(&mut buf, 3, 4, 1, OutFormat::Rgba, RowOrder::TopDown),
            Err(DecodeError::Dst { .. })
        ));
    }

    #[test]
    fn channel_expansion_hits_the_endpoints() {
        assert_eq!(expand5(0), 0);
        assert_eq!(expand5(0x1F), 0xFF);
        assert_eq!(expand6(0), 0);
        assert_eq!(expand6(0x3F), 0xFF);
    }

    #[test]
    fn short_source_row_pads_with_opaque_black() {
        let mut dst = [0u8; 4 * 4];
        convert_row(
            PixelFormat::BgrX32,
            &[1, 2, 3, 0],
            &mut dst,
            OutFormat::Rgba,
            &Palette::default(),
        );
        assert_eq!(&dst[0..4], &[3, 2, 1, 0xFF]);
        assert_eq!(&dst[4..16], &[0, 0, 0, 0xFF, 0, 0, 0, 0xFF, 0, 0, 0, 0xFF]);
    }

    #[test]
    fn mono1_is_msb_first() {
        let mut dst = [0u8; 8 * 4];
        convert_row(
            PixelFormat::Mono1,
            &[0b1000_0001],
            &mut dst,
            OutFormat::Rgba,
            &Palette::default(),
        );
        assert_eq!(dst[0], 0xFF);
        assert_eq!(dst[4], 0x00);
        assert_eq!(dst[7 * 4], 0xFF);
    }

    #[test]
    fn rgb565_and_rgb555_agree_on_white_and_black() {
        let pal = Palette::default();
        for fmt in [PixelFormat::Rgb565, PixelFormat::Rgb555] {
            let mut dst = [0u8; 8];
            convert_row(
                fmt,
                &[0xFF, 0xFF, 0x00, 0x00],
                &mut dst,
                OutFormat::Rgba,
                &pal,
            );
            assert_eq!(&dst[0..4], &[0xFF, 0xFF, 0xFF, 0xFF], "{fmt:?} white");
            assert_eq!(&dst[4..8], &[0x00, 0x00, 0x00, 0xFF], "{fmt:?} black");
        }
    }

    #[test]
    fn bgra_output_swaps_red_and_blue() {
        let pal = Palette::default();
        let mut rgba = [0u8; 4];
        let mut bgra = [0u8; 4];
        convert_row(
            PixelFormat::Bgr24,
            &[0x10, 0x20, 0x30],
            &mut rgba,
            OutFormat::Rgba,
            &pal,
        );
        convert_row(
            PixelFormat::Bgr24,
            &[0x10, 0x20, 0x30],
            &mut bgra,
            OutFormat::Bgra,
            &pal,
        );
        assert_eq!(rgba, [0x30, 0x20, 0x10, 0xFF]);
        assert_eq!(bgra, [0x10, 0x20, 0x30, 0xFF]);
    }
}
