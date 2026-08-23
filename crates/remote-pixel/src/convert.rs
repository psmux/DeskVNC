//! Pixel format conversion to RGBA8888.
//!
//! Two halves that share one destination abstraction.
//!
//! The RFB half handles 8/16/24/32 bpp, true-colour with arbitrary max/shift
//! values, both endiannesses, and indexed-colour (colour map) mode. It returns
//! a `Vec` per call, which is what the RFB decoders in `vnc-core/src/encodings/`
//! want.
//!
//! The RDP half is [`convert_row`] and [`convert_image`], moved from
//! `crates/rdp-codecs/src/dst.rs` (PRDRDP/00 R37, PRDRDP/04 §4.2). It writes
//! through a [`DstView`](crate::DstView) into a caller owned buffer and never
//! allocates, because §4.2's single copy rule says a pixel is written to its
//! final destination exactly once.

use crate::dst::{put, DstView, OutFormat, PixelError, DST_BPP};
use crate::format::{Format, PixelFormat};

/// Server colour map (SetColourMapEntries, RFB §7.6.2), used when the pixel
/// format is not true-colour.
//
// Note on visibility: `raw_pixel_value`, `scale_channel`, `value_to_rgba`,
// `pixel_to_rgba` and `cpixel_to_rgba` were `pub(crate)` while this file lived
// inside vnc-core. The RFB decoders in `vnc-core/src/encodings/` call them
// directly, so crossing a crate boundary makes them `pub`. They are the only
// widening in the move.
#[derive(Debug, Clone)]
pub struct ColourMap {
    entries: [[u8; 3]; 256],
}

impl Default for ColourMap {
    fn default() -> Self {
        // Grayscale identity ramp, a sane fallback if a buggy server sends
        // indexed pixels before the map.
        let mut entries = [[0u8; 3]; 256];
        for (i, e) in entries.iter_mut().enumerate() {
            *e = [i as u8; 3];
        }
        Self { entries }
    }
}

impl ColourMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install entries starting at `first`. Out-of-range entries are ignored.
    pub fn set_entries(&mut self, first: usize, rgb: &[[u8; 3]]) {
        for (i, e) in rgb.iter().enumerate() {
            if let Some(slot) = self.entries.get_mut(first + i) {
                *slot = *e;
            }
        }
    }

    #[inline]
    pub fn lookup(&self, index: u8) -> [u8; 3] {
        self.entries[index as usize]
    }
}

/// Assemble a raw pixel value from `len` bytes honouring endianness.
#[inline]
pub fn raw_pixel_value(bytes: &[u8], big_endian: bool) -> u32 {
    let mut v: u32 = 0;
    if big_endian {
        for &b in bytes {
            v = (v << 8) | b as u32;
        }
    } else {
        for &b in bytes.iter().rev() {
            v = (v << 8) | b as u32;
        }
    }
    v
}

/// Scale a channel value in `0..=max` to `0..=255` with rounding.
#[inline]
pub fn scale_channel(c: u32, max: u16) -> u8 {
    if max == 0 {
        0
    } else {
        ((c * 255 + (max as u32) / 2) / max as u32) as u8
    }
}

/// Convert one raw pixel value (already endian-assembled) to RGBA.
#[inline]
pub fn value_to_rgba(v: u32, pf: &PixelFormat, map: Option<&ColourMap>) -> [u8; 4] {
    if pf.true_colour {
        let r = scale_channel((v >> pf.red_shift) & pf.red_max as u32, pf.red_max);
        let g = scale_channel((v >> pf.green_shift) & pf.green_max as u32, pf.green_max);
        let b = scale_channel((v >> pf.blue_shift) & pf.blue_max as u32, pf.blue_max);
        [r, g, b, 255]
    } else {
        let idx = (v & 0xff) as u8;
        let [r, g, b] = match map {
            Some(m) => m.lookup(idx),
            None => [idx; 3],
        };
        [r, g, b, 255]
    }
}

/// Convert one raw wire pixel (`pf.bytes_per_pixel()` bytes) to RGBA.
#[inline]
pub fn pixel_to_rgba(bytes: &[u8], pf: &PixelFormat, map: Option<&ColourMap>) -> [u8; 4] {
    value_to_rgba(raw_pixel_value(bytes, pf.big_endian), pf, map)
}

/// Convert a compact 3-byte CPIXEL (ZRLE/TRLE) to RGBA.
///
/// The three bytes are the bytes of the 4-byte pixel that actually contain
/// colour data, in the pixel format's byte order (RFB ZRLE spec).
#[inline]
pub fn cpixel_to_rgba(bytes: &[u8; 3], pf: &PixelFormat) -> [u8; 4] {
    // Do the colour bits live in the least significant 3 bytes?
    let fits_low = pf.red_shift <= 16 && pf.green_shift <= 16 && pf.blue_shift <= 16;
    let [b0, b1, b2] = bytes.map(|b| b as u32);
    let v = if pf.big_endian {
        if fits_low {
            (b0 << 16) | (b1 << 8) | b2
        } else {
            (b0 << 24) | (b1 << 16) | (b2 << 8)
        }
    } else if fits_low {
        b0 | (b1 << 8) | (b2 << 16)
    } else {
        (b0 << 8) | (b1 << 16) | (b2 << 24)
    };
    value_to_rgba(v, pf, None)
}

/// Convert `count` packed wire pixels to RGBA8888.
///
/// The output is always `count * 4` bytes; if `src` is shorter than
/// `count * bytes_per_pixel` the remainder is opaque black (callers are
/// expected to have validated lengths, this function never panics).
pub fn convert_to_rgba(src: &[u8], pf: &PixelFormat, count: usize) -> Vec<u8> {
    convert_to_rgba_mapped(src, pf, count, None)
}

/// Largest channel `max` for which the scaling division is hoisted into a
/// lookup table. Covers every real-world layout (5/6/8/10-bit channels).
const LUT_LEN: usize = 1024;
/// Below this pixel count, building the tables costs more than it saves.
const LUT_MIN_PIXELS: usize = 512;

/// Per-channel `0..=max` -> `0..=255` tables, so the generic path does three
/// array reads per pixel instead of three integer divisions.
struct ChannelLuts {
    r: [u8; LUT_LEN],
    g: [u8; LUT_LEN],
    b: [u8; LUT_LEN],
}

impl ChannelLuts {
    fn build(pf: &PixelFormat) -> Option<Self> {
        let (rm, gm, bm) = (pf.red_max, pf.green_max, pf.blue_max);
        if rm as usize >= LUT_LEN || gm as usize >= LUT_LEN || bm as usize >= LUT_LEN {
            return None;
        }
        let mut luts = Self {
            r: [0; LUT_LEN],
            g: [0; LUT_LEN],
            b: [0; LUT_LEN],
        };
        for (max, lut) in [(rm, &mut luts.r), (gm, &mut luts.g), (bm, &mut luts.b)] {
            for (c, slot) in lut.iter_mut().enumerate().take(max as usize + 1) {
                *slot = scale_channel(c as u32, max);
            }
        }
        Some(luts)
    }
}

/// Endian-assemble each `bpp`-byte wire pixel and write `f(value)` to `dst`.
///
/// The `(bpp, big_endian)` decision is made once, outside the loop, so each
/// specialisation is a straight `chunks_exact` walk with no bounds checks and
/// no per-pixel branching.
#[inline]
fn map_pixels<F: Fn(u32) -> [u8; 4]>(src: &[u8], dst: &mut [u8], bpp: usize, be: bool, f: F) {
    macro_rules! walk {
        ($n:expr, $get:expr) => {{
            let get = $get;
            for (s, d) in src.chunks_exact($n).zip(dst.chunks_exact_mut(4)) {
                d.copy_from_slice(&f(get(s)));
            }
        }};
    }
    match (bpp, be) {
        (1, _) => walk!(1, |s: &[u8]| s[0] as u32),
        (2, false) => walk!(2, |s: &[u8]| u16::from_le_bytes([s[0], s[1]]) as u32),
        (2, true) => walk!(2, |s: &[u8]| u16::from_be_bytes([s[0], s[1]]) as u32),
        (3, false) => walk!(3, |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], 0])),
        (3, true) => walk!(3, |s: &[u8]| u32::from_be_bytes([0, s[0], s[1], s[2]])),
        (4, false) => walk!(4, |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]])),
        (4, true) => walk!(4, |s: &[u8]| u32::from_be_bytes([s[0], s[1], s[2], s[3]])),
        _ => {}
    }
}

/// True for 32bpp little-endian BGRA, the format we always try to negotiate.
#[inline]
fn is_canonical_bgra(pf: &PixelFormat) -> bool {
    pf.true_colour
        && pf.bits_per_pixel == 32
        && !pf.big_endian
        && pf.red_max == 255
        && pf.green_max == 255
        && pf.blue_max == 255
        && pf.red_shift == 16
        && pf.green_shift == 8
        && pf.blue_shift == 0
}

/// As [`convert_to_rgba`] but with an optional colour map for indexed mode.
pub fn convert_to_rgba_mapped(
    src: &[u8],
    pf: &PixelFormat,
    count: usize,
    map: Option<&ColourMap>,
) -> Vec<u8> {
    let bpp = pf.bytes_per_pixel();
    let mut out = vec![0u8; count * 4];
    if bpp == 0 || bpp > 4 {
        return out;
    }
    let n = count.min(src.len() / bpp);
    // Pixels the (short) input does not cover stay opaque black.
    for i in n..count {
        out[i * 4 + 3] = 255;
    }
    if n == 0 {
        return out;
    }
    let src = &src[..n * bpp];
    let dst = &mut out[..n * 4];

    // Fast path: 32bpp little-endian BGRA (our canonical negotiated format), // a pure byte swizzle, no shifting or scaling at all.
    if is_canonical_bgra(pf) {
        for (s, d) in src.chunks_exact(4).zip(dst.chunks_exact_mut(4)) {
            d[0] = s[2];
            d[1] = s[1];
            d[2] = s[0];
            d[3] = 255;
        }
        return out;
    }

    // Indexed colour: collapse the map into one 256-entry RGBA table.
    if !pf.true_colour {
        let mut table = [[0u8; 4]; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            let [r, g, b] = match map {
                Some(m) => m.lookup(i as u8),
                None => [i as u8; 3],
            };
            *slot = [r, g, b, 255];
        }
        map_pixels(src, dst, bpp, pf.big_endian, |v| table[(v & 0xff) as usize]);
        return out;
    }

    let (rs, gs, bs) = (pf.red_shift, pf.green_shift, pf.blue_shift);
    let (rm, gm, bm) = (pf.red_max as u32, pf.green_max as u32, pf.blue_max as u32);

    // 8-bit channels need no rescaling: `scale_channel(c, 255) == c`.
    if rm == 255 && gm == 255 && bm == 255 {
        map_pixels(src, dst, bpp, pf.big_endian, |v| {
            [
                ((v >> rs) & 255) as u8,
                ((v >> gs) & 255) as u8,
                ((v >> bs) & 255) as u8,
                255,
            ]
        });
        return out;
    }

    // Narrow channels: hoist the three per-pixel divisions into tables. The
    // extra `& (LUT_LEN - 1)` is a no-op for in-range values but lets the
    // compiler drop the bounds check.
    if n >= LUT_MIN_PIXELS {
        if let Some(luts) = ChannelLuts::build(pf) {
            map_pixels(src, dst, bpp, pf.big_endian, |v| {
                [
                    luts.r[((v >> rs) & rm) as usize & (LUT_LEN - 1)],
                    luts.g[((v >> gs) & gm) as usize & (LUT_LEN - 1)],
                    luts.b[((v >> bs) & bm) as usize & (LUT_LEN - 1)],
                    255,
                ]
            });
            return out;
        }
    }

    map_pixels(src, dst, bpp, pf.big_endian, |v| {
        [
            scale_channel((v >> rs) & rm, pf.red_max),
            scale_channel((v >> gs) & gm, pf.green_max),
            scale_channel((v >> bs) & bm, pf.blue_max),
            255,
        ]
    });
    out
}

// ---------------------------------------------------------------------------
// The RDP half: caller owned destination, explicit stride and row order
// (PRDRDP/04 §4.2, moved from crates/rdp-codecs/src/dst.rs by PRDRDP/00 R37)
// ---------------------------------------------------------------------------

/// A 256 entry RGBA table. The RDP palette (`TS_UPDATE_PALETTE`,
/// MS-RDPBCGR 2.2.9.1.1.3.1.1.1) and the RFB colour map are the same thing
/// once built.
///
/// [`ColourMap`] above is the RFB spelling of the same table and it stays
/// separate: it stores three bytes per entry and is filled by
/// `SetColourMapEntries` (RFB §7.6.2), where this one stores four and is
/// filled by a `TS_UPDATE_PALETTE` body. Merging them would put a conversion
/// in the per pixel path of one protocol to save a type in the other.
#[derive(Clone)]
pub struct Palette([[u8; 4]; 256]);

impl Palette {
    /// Replace one entry from a `TS_PALETTE_ENTRY`
    /// (MS-RDPBCGR 2.2.9.1.1.3.1.1.1).
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

    #[inline]
    fn entry(&self, index: u8) -> [u8; 4] {
        self.0[usize::from(index)]
    }
}

impl Default for Palette {
    /// A grayscale identity ramp, the same defensive default [`ColourMap`]
    /// builds a few lines above (PRDRDP/04 §2.7). A server that sends indexed
    /// pixels before its palette then produces a legible grey picture rather
    /// than a black screen.
    fn default() -> Self {
        let mut t = [[0u8; 4]; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let v = i as u8;
            *e = [v, v, v, 0xFF];
        }
        Palette(t)
    }
}

/// Expand a 5 bit channel to 8 bits by bit replication, which is what
/// [`scale_channel`] does for the general case and what the fixed 5-6-5 and
/// 5-5-5 layouts of PRDRDP/04 §4.2 collapse to. 0x1F maps to 0xFF, so white
/// stays white.
#[inline(always)]
pub fn expand5(v: u16) -> u8 {
    let v = (v & 0x1F) as u8;
    (v << 3) | (v >> 2)
}

/// Expand a 6 bit channel to 8 bits by bit replication (PRDRDP/04 §4.2).
#[inline(always)]
pub fn expand6(v: u16) -> u8 {
    let v = (v & 0x3F) as u8;
    (v << 2) | (v >> 4)
}

/// One source row into one RGBA or BGRA destination row (PRDRDP/04 §4.2).
///
/// `src` is cut to the row's real bytes by the caller, so the DIB padding of
/// PRDRDP/04 §2.3 is never read. `dst` is exactly `w * 4`.
///
/// A short `src` does not panic: the tail is opaque black. That is the policy
/// [`convert_to_rgba_mapped`] already applies to a short RFB input, and it is
/// the second line of defence behind the length check every decoder does up
/// front.
///
/// `#[inline]` because the callers are in `rdp-codecs` now, and the per row
/// dispatch has to fold into their row loops the way it did when the two
/// lived in one crate.
#[inline]
pub fn convert_row(fmt: Format, src: &[u8], dst: &mut [u8], out: OutFormat, pal: &Palette) {
    match out {
        OutFormat::Rgba => convert_row_impl::<false>(fmt, src, dst, pal),
        OutFormat::Bgra => convert_row_impl::<true>(fmt, src, dst, pal),
    }
}

fn convert_row_impl<const BGRA: bool>(fmt: Format, src: &[u8], dst: &mut [u8], pal: &Palette) {
    let want = dst.len() / DST_BPP;
    // How many pixels the source really carries. Everything past this is the
    // opaque black tail.
    let have = match fmt {
        Format::Mono1 => src.len() * 8,
        other => src.len() / (other.bits() / 8),
    };
    let n = want.min(have);
    // Slice once, with a length proved here, so neither loop below can panic
    // partway through. LLVM will not vectorise a loop that can
    // (PRDRDP/04 §4.6.8 rule two).
    let (head, tail) = dst.split_at_mut(n * DST_BPP);

    match fmt {
        // The canonical 32 bpp path: a pure byte swizzle, measured at
        // 6332 MPix/s through the RFB entry point of this same file
        // (docs/PERFORMANCE.md §3.2). RDP's 32 bpp wire format is exactly
        // that layout.
        Format::BgrX32 => {
            for (s, d) in src.chunks_exact(4).zip(head.chunks_exact_mut(DST_BPP)) {
                put::<BGRA>(d, s[2], s[1], s[0], 0xFF);
            }
        }
        Format::BgrA32 => {
            for (s, d) in src.chunks_exact(4).zip(head.chunks_exact_mut(DST_BPP)) {
                put::<BGRA>(d, s[2], s[1], s[0], s[3]);
            }
        }
        Format::Bgr24 => {
            for (s, d) in src.chunks_exact(3).zip(head.chunks_exact_mut(DST_BPP)) {
                put::<BGRA>(d, s[2], s[1], s[0], 0xFF);
            }
        }
        // The channel maxima are compile time constants here, unlike the RFB
        // path above which has to handle arbitrary maxima, so the shift and
        // mask sequence is inlined instead of going through [`ChannelLuts`]
        // (PRDRDP/04 §4.2).
        Format::Rgb565 => {
            for (s, d) in src.chunks_exact(2).zip(head.chunks_exact_mut(DST_BPP)) {
                let v = u16::from_le_bytes([s[0], s[1]]);
                put::<BGRA>(d, expand5(v >> 11), expand6(v >> 5), expand5(v), 0xFF);
            }
        }
        Format::Rgb555 => {
            for (s, d) in src.chunks_exact(2).zip(head.chunks_exact_mut(DST_BPP)) {
                let v = u16::from_le_bytes([s[0], s[1]]);
                put::<BGRA>(d, expand5(v >> 10), expand5(v >> 5), expand5(v), 0xFF);
            }
        }
        Format::Palette8 => {
            for (s, d) in src.iter().zip(head.chunks_exact_mut(DST_BPP)) {
                let e = pal.entry(*s);
                put::<BGRA>(d, e[0], e[1], e[2], e[3]);
            }
        }
        // MSB first within each byte, so bit 7 is the leftmost pixel.
        Format::Mono1 => {
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

/// A whole image, with an explicit source stride and a caller owned
/// destination (PRDRDP/04 §4.2).
///
/// `src_stride` is the byte distance between the starts of two consecutive
/// wire scanlines: the four byte aligned DIB stride for a legacy bitmap
/// (PRDRDP/04 §2.3), `width * 4` for EGFX. The row order, the destination
/// stride and the destination channel order all live in `dst`, because each
/// of the three is a property of the destination mapping rather than of the
/// source data.
///
/// Errors with [`PixelError::Truncated`] if `src` is shorter than
/// [`Format::min_src_len`], and with [`PixelError::Range`] if `src_stride` is
/// narrower than one scanline. It cannot panic on any input.
///
/// This is the function `rdp_codecs::uncompressed::decode` delegates to, with
/// its signature unchanged.
#[inline]
pub fn convert_image(
    fmt: Format,
    src: &[u8],
    src_stride: usize,
    pal: &Palette,
    dst: &mut DstView<'_>,
) -> Result<(), PixelError> {
    let (w, h) = (dst.width(), dst.height());
    let row_bytes = fmt.row_bytes(w);
    if src_stride < row_bytes {
        return Err(PixelError::Range {
            what: "source stride",
            got: src_stride as u32,
        });
    }
    if src.len() < fmt.min_src_len(src_stride, w, h) {
        return Err(PixelError::Truncated {
            what: "uncompressed bitmap",
        });
    }
    let out = dst.format();
    for y in 0..usize::from(h) {
        // Cut to the row's real bytes so the DIB padding is never read, and
        // slice once per row rather than once per pixel.
        let start = y * src_stride;
        let row = &src[start..(start + row_bytes).min(src.len())];
        convert_row(fmt, row, dst.row(y), out, pal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_32bpp_bgra_le() {
        let pf = PixelFormat::bgra8888();
        // One pixel: B=0x10 G=0x20 R=0x30 X=0x00 in memory (little endian,
        // red_shift 16 => red is byte 2).
        let src = [0x10u8, 0x20, 0x30, 0x00];
        let rgba = convert_to_rgba(&src, &pf, 1);
        assert_eq!(rgba, vec![0x30, 0x20, 0x10, 255]);
    }

    #[test]
    fn convert_32bpp_big_endian() {
        let mut pf = PixelFormat::bgra8888();
        pf.big_endian = true;
        // Big endian: value 0x00301020 -> bytes [00,30,10,20]
        let src = [0x00u8, 0x30, 0x10, 0x20];
        let rgba = convert_to_rgba(&src, &pf, 1);
        assert_eq!(rgba, vec![0x30, 0x10, 0x20, 255]);
    }

    #[test]
    fn convert_16bpp_rgb565() {
        let pf = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            big_endian: false,
            true_colour: true,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
        };
        // Pure red: 31 << 11 = 0xF800 -> LE bytes [0x00, 0xF8]
        let rgba = convert_to_rgba(&[0x00, 0xF8], &pf, 1);
        assert_eq!(rgba, vec![255, 0, 0, 255]);
        // Pure green: 63 << 5 = 0x07E0 -> LE bytes [0xE0, 0x07]
        let rgba = convert_to_rgba(&[0xE0, 0x07], &pf, 1);
        assert_eq!(rgba, vec![0, 255, 0, 255]);
    }

    #[test]
    fn convert_8bpp_rgb222() {
        let pf = PixelFormat::rgb222();
        // r=3 g=1 b=2 -> (3<<4)|(1<<2)|2 = 0x36
        let rgba = convert_to_rgba(&[0x36], &pf, 1);
        assert_eq!(rgba, vec![255, 85, 170, 255]);
    }

    #[test]
    fn convert_8bpp_palette() {
        let pf = PixelFormat::palette8();
        let mut map = ColourMap::new();
        map.set_entries(7, &[[10, 20, 30]]);
        let rgba = convert_to_rgba_mapped(&[7u8], &pf, 1, Some(&map));
        assert_eq!(rgba, vec![10, 20, 30, 255]);
        // Without a map: grayscale identity fallback.
        let rgba = convert_to_rgba(&[0x40], &pf, 1);
        assert_eq!(rgba, vec![0x40, 0x40, 0x40, 255]);
    }

    /// Every fast path must agree, pixel for pixel, with the scalar reference
    /// `pixel_to_rgba` across a spread of awkward formats and both sizes
    /// (below and above the LUT threshold).
    #[test]
    fn fast_paths_match_scalar_reference() {
        let formats = [
            PixelFormat::bgra8888(),
            PixelFormat::rgb222(),
            PixelFormat::palette8(),
            // 32bpp RGBX little endian (not our canonical order).
            PixelFormat {
                bits_per_pixel: 32,
                depth: 24,
                big_endian: false,
                true_colour: true,
                red_max: 255,
                green_max: 255,
                blue_max: 255,
                red_shift: 0,
                green_shift: 8,
                blue_shift: 16,
            },
            // 32bpp big endian, 10-bit channels (LUT path).
            PixelFormat {
                bits_per_pixel: 32,
                depth: 30,
                big_endian: true,
                true_colour: true,
                red_max: 1023,
                green_max: 1023,
                blue_max: 1023,
                red_shift: 20,
                green_shift: 10,
                blue_shift: 0,
            },
            // 16-bit channels: too wide for the LUT, must fall back.
            PixelFormat {
                bits_per_pixel: 32,
                depth: 32,
                big_endian: false,
                true_colour: true,
                red_max: 4095,
                green_max: 4095,
                blue_max: 4095,
                red_shift: 0,
                green_shift: 12,
                blue_shift: 20,
            },
            // rgb565 big endian.
            PixelFormat {
                bits_per_pixel: 16,
                depth: 16,
                big_endian: true,
                true_colour: true,
                red_max: 31,
                green_max: 63,
                blue_max: 31,
                red_shift: 11,
                green_shift: 5,
                blue_shift: 0,
            },
            // 24bpp true colour, big endian.
            PixelFormat {
                bits_per_pixel: 24,
                depth: 24,
                big_endian: true,
                true_colour: true,
                red_max: 255,
                green_max: 255,
                blue_max: 255,
                red_shift: 0,
                green_shift: 8,
                blue_shift: 16,
            },
            // 24bpp true colour.
            PixelFormat {
                bits_per_pixel: 24,
                depth: 24,
                big_endian: false,
                true_colour: true,
                red_max: 255,
                green_max: 255,
                blue_max: 255,
                red_shift: 16,
                green_shift: 8,
                blue_shift: 0,
            },
        ];
        let mut map = ColourMap::new();
        for i in 0..256 {
            map.set_entries(i, &[[(i * 3) as u8, (i * 5) as u8, (i * 7) as u8]]);
        }

        for pf in formats {
            let bpp = pf.bytes_per_pixel();
            for count in [7usize, 4096] {
                let src: Vec<u8> = (0..count * bpp)
                    .map(|i| (i.wrapping_mul(97)) as u8)
                    .collect();
                let got = convert_to_rgba_mapped(&src, &pf, count, Some(&map));
                let mut want = Vec::with_capacity(count * 4);
                for i in 0..count {
                    want.extend_from_slice(&pixel_to_rgba(
                        &src[i * bpp..(i + 1) * bpp],
                        &pf,
                        Some(&map),
                    ));
                }
                assert_eq!(got, want, "mismatch for {pf:?} count={count}");
            }
        }
    }

    #[test]
    fn short_input_pads_black() {
        let pf = PixelFormat::bgra8888();
        let rgba = convert_to_rgba(&[1, 2, 3, 4], &pf, 3);
        assert_eq!(rgba.len(), 12);
        assert_eq!(&rgba[4..], &[0, 0, 0, 255, 0, 0, 0, 255]);
    }
}

/// The tests that came with [`convert_row`] from `crates/rdp-codecs/src/dst.rs`
/// (PRDRDP/00 R37). They are a second module rather than additions to the one
/// above because the two halves of this file have separate fixtures.
#[cfg(test)]
mod rdp_tests {
    use super::*;
    use crate::dst::RowOrder;

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
            Format::BgrX32,
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
            Format::Mono1,
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
        for fmt in [Format::Rgb565, Format::Rgb555] {
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
            Format::Bgr24,
            &[0x10, 0x20, 0x30],
            &mut rgba,
            OutFormat::Rgba,
            &pal,
        );
        convert_row(
            Format::Bgr24,
            &[0x10, 0x20, 0x30],
            &mut bgra,
            OutFormat::Bgra,
            &pal,
        );
        assert_eq!(rgba, [0x30, 0x20, 0x10, 0xFF]);
        assert_eq!(bgra, [0x10, 0x20, 0x30, 0xFF]);
    }

    /// The destination stride PRDRDP/04 §4.2's published signature left out:
    /// a rect written straight into a wider framebuffer, which is the case
    /// that would otherwise need a packed scratch and a second copy.
    #[test]
    fn a_rect_converts_into_a_wider_framebuffer_without_a_scratch() {
        // A 4 pixel wide framebuffer, two rows, holding a 2x2 rect at x = 1.
        const FB_STRIDE: usize = 4 * DST_BPP;
        let mut fb = [0xAAu8; FB_STRIDE * 2];
        let src = [
            0x10u8, 0x20, 0x30, 0x00, 0x11, 0x21, 0x31, 0x00, // wire row 0
            0x12, 0x22, 0x32, 0x00, 0x13, 0x23, 0x33, 0x00, // wire row 1
        ];
        {
            // The rect starts at column 1 of the framebuffer.
            let at = DST_BPP;
            let mut v = DstView::new(
                &mut fb[at..],
                FB_STRIDE,
                2,
                2,
                OutFormat::Rgba,
                RowOrder::TopDown,
            )
            .unwrap();
            convert_image(Format::BgrX32, &src, 8, &Palette::default(), &mut v).unwrap();
        }
        // Columns 1 and 2 of both rows carry the rect, and nothing else moved.
        assert_eq!(&fb[0..4], &[0xAA; 4], "column 0 must be untouched");
        assert_eq!(
            &fb[4..12],
            &[0x30, 0x20, 0x10, 0xFF, 0x31, 0x21, 0x11, 0xFF]
        );
        assert_eq!(&fb[12..16], &[0xAA; 4], "column 3 must be untouched");
        assert_eq!(&fb[FB_STRIDE..FB_STRIDE + 4], &[0xAA; 4]);
        assert_eq!(
            &fb[FB_STRIDE + 4..FB_STRIDE + 12],
            &[0x32, 0x22, 0x12, 0xFF, 0x33, 0x23, 0x13, 0xFF]
        );
    }

    /// The stride check and the truncation check are the two errors
    /// [`convert_image`] can return, and neither is a panic (PRDRDP/04 §4.1
    /// rule five).
    #[test]
    fn a_narrow_stride_and_a_short_source_are_errors_not_panics() {
        let mut out = vec![0u8; 4 * 4];
        let mut v = DstView::packed(&mut out, 2, 2, OutFormat::Rgba, RowOrder::TopDown).unwrap();
        assert!(matches!(
            convert_image(Format::BgrX32, &[0; 32], 4, &Palette::default(), &mut v),
            Err(PixelError::Range {
                what: "source stride",
                ..
            })
        ));
        assert!(matches!(
            convert_image(Format::BgrX32, &[0; 8], 8, &Palette::default(), &mut v),
            Err(PixelError::Truncated { .. })
        ));
    }
}
