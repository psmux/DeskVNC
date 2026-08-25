//! The planar codec, the RDP 6.0 bitmap stream (MS-RDPEGDI 2.2.2.5.1 for the
//! format, MS-RDPEGDI 3.1.9.2 for the decoding rules).
//!
//! This is the workhorse for text and window chrome: a Windows server with
//! EGFX chooses planar for the parts of the screen that are text and RemoteFX
//! or AVC for the parts that are photographic. So planar throughput matters at
//! least as much as RemoteFX throughput (PRDRDP/04 §4.5).
//!
//! ## Shape of the decode
//!
//! One format header byte, then three or four planes, each optionally run
//! length encoded and, when it is, delta encoded against the scanline above.
//! Planes are decoded into a caller pooled [`PlanarScratch`] and then
//! interleaved into the destination in one pass that also applies the inverse
//! colour transform, the chroma upsample, the alpha fill and the row flip. So
//! planar costs one destination write per pixel and no extra copy, which is
//! the D9 zero copy invariant.
//!
//! ## The rule that must not be broken
//!
//! The plane data is stored in the same row order as the bitmap it belongs to:
//! bottom up inside a legacy `TS_BITMAP_DATA`, top down inside an EGFX
//! `WIRE_TO_SURFACE_1`. The delta predictor always references the previously
//! *decoded* scanline, whichever of the two that is. So the flip happens on
//! the way out and never on the way in (PRDRDP/04 §4.5.4). A decoder that
//! wrote its rows in reverse to save the flip would silently predict from the
//! wrong neighbour and the picture would look almost right, which is the worst
//! possible failure. [`crate::DstView`] owns the flip and this module never
//! touches it.

use remote_pixel::{put, DstView, OutFormat};

use crate::{DecodeError, Reader};

/// Colour loss level, bits 0 to 2 of the format header.
const HDR_CLL: u8 = 0x07;
/// Chroma subsampling, bit 3.
const HDR_CS: u8 = 0x08;
/// Planes are RLE and delta encoded, bit 4.
const HDR_RLE: u8 = 0x10;
/// No alpha plane, bit 5.
const HDR_NA: u8 = 0x20;
/// Bits 6 and 7, which must be zero.
const HDR_RESERVED: u8 = 0xC0;

/// Some encoders append one zero byte after the last plane. We accept one byte
/// of slack and refuse more. That is a behaviour note (PRDRDP/04 §4.15) rather
/// than a rule in MS-RDPEGDI, and it is cheap insurance against a server we
/// have not met.
const TRAILING_SLACK: usize = 1;

/// The plane buffers, allocated once and reused.
///
/// This is the only cross call state in phase 1a, and it is not codec state:
/// nothing in it survives a decode, so [`PlanarScratch::reset`] exists for
/// symmetry with the caches the later codecs keep rather than because a decode
/// depends on it (PRDRDP/04 §4.1 rule three).
#[derive(Default)]
pub struct PlanarScratch {
    buf: Vec<u8>,
}

impl PlanarScratch {
    /// An empty scratch, which grows to fit on its first decode.
    pub fn new() -> Self {
        Self::default()
    }

    /// A scratch already sized for a bitmap of this geometry, so the first
    /// decode does not allocate either.
    pub fn with_capacity(width: u16, height: u16) -> Self {
        let mut s = Self::new();
        s.grow(usize::from(width) * usize::from(height));
        s
    }

    /// Drop the buffer. The caller pools these per session, so this is how a
    /// session that shrank its desktop gives the memory back.
    pub fn reset(&mut self) {
        self.buf = Vec::new();
    }

    /// Bytes currently held, for the memory accounting in PRDRDP/04 §11.3.
    pub fn bytes(&self) -> usize {
        self.buf.capacity()
    }

    /// Four planes of `plane_len` bytes. The one allocation happens here, on
    /// the first decode of a given size and never again, so a steady state
    /// decode loop allocates nothing (PRDRDP/04 §4.1 rule two).
    fn grow(&mut self, plane_len: usize) {
        let need = plane_len * 4;
        if self.buf.len() < need {
            self.buf.resize(need, 0);
        }
    }

    fn planes(&mut self, plane_len: usize) -> [&mut [u8]; 4] {
        let (a, rest) = self.buf.split_at_mut(plane_len);
        let (p1, rest) = rest.split_at_mut(plane_len);
        let (p2, rest) = rest.split_at_mut(plane_len);
        [a, p1, p2, &mut rest[..plane_len]]
    }
}

/// Geometry and the header flags, carried together so the interleave does not
/// take nine loose `usize` arguments.
struct Geom {
    w: usize,
    h: usize,
    /// Chroma plane width, `ceil(w / 2)` when subsampled and `w` otherwise.
    sw: usize,
    cs: bool,
    /// Colour loss level. Zero means the planes are R, G and B directly.
    cll: u8,
}

/// The decoded planes, in the order MS-RDPEGDI 2.2.2.5.1 stores them: alpha
/// when present, then luma or red, then orange chroma or green, then green
/// chroma or blue. That naming is the specification's and it is kept here so
/// the mapping is checkable against the document rather than against memory.
struct Planes<'a> {
    alpha: Option<&'a [u8]>,
    p1: &'a [u8],
    p2: &'a [u8],
    p3: &'a [u8],
}

/// Decode one RLE plane, scanline by scanline (MS-RDPEGDI 2.2.2.5.1.1, "RDP
/// 6.0 RLE Segments").
///
/// ```text
/// control    = next_u8()
/// cRawBytes  = control >> 4
/// nRunLength = control & 0x0F
/// if nRunLength == 1 { nRunLength = cRawBytes + 16; cRawBytes = 0 }
/// if nRunLength == 2 { nRunLength = cRawBytes + 32; cRawBytes = 0 }
/// ```
///
/// Two things about that. The nibble assignment is the opposite way round from
/// what most people guess: the **high** nibble is the raw byte count and the
/// **low** nibble is the run length. And the two escapes steal the raw count
/// to extend the run, so a run length of one or two never means "a run of one
/// or two"; those are encoded as literals.
///
/// A segment never crosses a scanline boundary, so a segment that would
/// overrun the scanline is a [`DecodeError::Range`] rather than a wrap into
/// the next row.
fn decode_plane_rle(
    r: &mut Reader<'_>,
    plane: &mut [u8],
    w: usize,
    h: usize,
) -> Result<(), DecodeError> {
    for y in 0..h {
        // One bounds proof per scanline, not per byte: everything below writes
        // inside `row`, whose length is exactly w (PRDRDP/04 §4.6.8 rule two).
        let row = &mut plane[y * w..][..w];
        let mut x = 0usize;
        while x < w {
            let control = r.u8()?;
            let mut raw = usize::from(control >> 4);
            let mut run = usize::from(control & 0x0F);
            if run == 1 {
                run = raw + 16;
                raw = 0;
            } else if run == 2 {
                run = raw + 32;
                raw = 0;
            }
            // A control byte of zero describes nothing and would let a crafted
            // stream spin without advancing the scanline.
            if raw == 0 && run == 0 {
                return Err(DecodeError::Range {
                    what: "planar rle control",
                    got: 0,
                });
            }
            if raw + run > w - x {
                return Err(DecodeError::Range {
                    what: "planar rle segment",
                    got: (raw + run) as u32,
                });
            }
            if raw > 0 {
                row[x..x + raw].copy_from_slice(r.take(raw)?);
                x += raw;
            }
            if run > 0 {
                // "the last byte written into this scanline", which is zero
                // when the run begins the scanline.
                let last = if x == 0 { 0 } else { row[x - 1] };
                row[x..x + run].fill(last);
                x += run;
            }
        }
    }
    Ok(())
}

/// Undo the delta encoding of MS-RDPEGDI 3.1.9.2.
///
/// Scanlines after the first hold deltas against the scanline above; the first
/// scanline is raw. That single exception is what a straightforward loop gets
/// wrong by running the delta pass over row zero as well, which produces a
/// picture that is right at the top and progressively wrong downward.
///
/// The delta byte is sign and magnitude with the sign in bit 0, and the
/// arithmetic wraps.
///
/// The dependency here is **vertical only**: every byte in a row depends on
/// the byte above it and on nothing to its left. So the inner loop over a row
/// is a plain elementwise pass over two disjoint slices of proved equal length
/// and it vectorises fully. PRDRDP/04 §4.5.3 calls this "a per row, per plane
/// serial dependency" that "does not vectorise along a row" and compares it to
/// Tight's gradient filter; that comparison is wrong, and the correction is
/// reported to the owner. Tight's filter predicts from the pixel to the left
/// as well as the one above, which is what makes it serial.
fn undo_delta(plane: &mut [u8], w: usize, h: usize) {
    for y in 1..h {
        let (above, cur) = plane[(y - 1) * w..(y + 1) * w].split_at_mut(w);
        for (c, &a) in cur.iter_mut().zip(above.iter()) {
            let d = *c;
            *c = if d & 1 != 0 {
                a.wrapping_sub((d >> 1) + 1)
            } else {
                a.wrapping_add(d >> 1)
            };
        }
    }
}

fn decode_plane(
    r: &mut Reader<'_>,
    plane: &mut [u8],
    w: usize,
    h: usize,
    rle: bool,
) -> Result<(), DecodeError> {
    if rle {
        decode_plane_rle(r, plane, w, h)?;
        undo_delta(plane, w, h);
    } else {
        // Raw planes carry no delta encoding at all (MS-RDPEGDI 3.1.9.2).
        plane[..w * h].copy_from_slice(r.take(w * h)?);
    }
    Ok(())
}

/// The inverse YCoCg transform, on chroma the caller has already scaled
/// (MS-RDPEGDI 3.1.9.2, MS-RDPNSC 3.1.8.1.2).
///
/// This is the plain form, `T = Y - Cg; R = T - Co; G = Y + Cg; B = T + Co`,
/// not the reversible lifting form. The two are algebraically the same
/// transform at different chroma scales, and choosing between them is not a
/// matter of taste once the scale is fixed: see [`chroma`] for why the scale
/// is what it is, and `docs/RDP_SPEC_NOTES.md` §1.8 for how it was settled.
///
/// NSCodec defines Co with the opposite sign and negates it at the call site
/// rather than growing a flag here.
#[inline(always)]
pub(crate) fn ycocg_to_rgb_scaled(y: u8, co: i16, cg: i16) -> (u8, u8, u8) {
    let y = i16::from(y);
    let t = y - cg;
    let (r, g, b) = (t - co, y + cg, t + co);
    // Clamping with `clamp` rather than with branches lowers to a pair of
    // packing instructions on both x86-64 and aarch64 (PRDRDP/04 §4.6.8
    // rule four).
    (
        r.clamp(0, 255) as u8,
        g.clamp(0, 255) as u8,
        b.clamp(0, 255) as u8,
    )
}

/// Undo a codec's colour loss: shift back inside eight bits, then read signed.
///
/// `shift` is one less than the colour loss field on the wire, for both codecs
/// that use this. The planar `ColorLossLevel` counts the bits the encoder
/// discarded and the non lifting form above folds one halving of its own into
/// the scale; NSCodec's field runs from 1 with 1 meaning no loss. They arrive
/// at the same arithmetic from different definitions.
///
/// Two things here are easy to get wrong and both produce a picture that looks
/// almost right.
///
/// The shift happens in eight bits and the result is read as signed only
/// afterwards. Widening to `i16` first keeps the bits the encoder's own shift
/// left above the meaningful ones and scales them as though they were signal.
///
/// And the shift is `field - 1`, not `field`. Shifting one place too far
/// doubles every chroma sample, so any sample in the top half of its range
/// overflows eight bits and wraps, which flips its sign. That is not a subtle
/// error in a corner: against a Windows 11 host at `ColorLossLevel` 3, 15.7%
/// of all chroma bytes wrapped, and each one became a hard edged patch of
/// roughly the complementary hue in the most saturated parts of the image.
/// At `field - 1` not one byte of 15,728,640 lost a bit, which is the check
/// worth keeping: a correct scale never discards a set bit, so any loss at all
/// means the scale is wrong.
#[inline(always)]
pub(crate) fn chroma(v: u8, shift: u8) -> i16 {
    i16::from((v << shift) as i8)
}

/// The shift for a planar `ColorLossLevel`. Zero means the planes are RGB and
/// never reach the transform, so the saturation is a guard, not a case.
#[inline(always)]
pub(crate) fn planar_shift(cll: u8) -> u8 {
    cll.saturating_sub(1)
}

fn interleave<const BGRA: bool>(planes: &Planes<'_>, geom: &Geom, dst: &mut DstView<'_>) {
    let (w, h) = (geom.w, geom.h);
    for y in 0..h {
        let d = dst.row(y);
        if geom.cll == 0 {
            // R, G and B directly. Four slices of proved length w zipped
            // against the destination row: no indexing, no branch, no bounds
            // check in the loop body (PRDRDP/04 §4.6.8 rules one and two).
            let (rp, gp, bp) = (
                &planes.p1[y * w..],
                &planes.p2[y * w..],
                &planes.p3[y * w..],
            );
            for (((&r, &g), &b), o) in rp[..w]
                .iter()
                .zip(&gp[..w])
                .zip(&bp[..w])
                .zip(d.chunks_exact_mut(4))
            {
                put::<BGRA>(o, r, g, b, 0xFF);
            }
        } else if geom.cs {
            // Chroma is ceil(w/2) by ceil(h/2) and is upsampled by 2 by 2
            // pixel replication. Replication and not interpolation: the
            // encoder took a point sample, so interpolating would be inventing
            // detail. Odd widths and heights replicate the last column and row
            // by construction, since the index is a halving.
            let co = &planes.p2[(y / 2) * geom.sw..][..geom.sw];
            let cg = &planes.p3[(y / 2) * geom.sw..][..geom.sw];
            for (x, (&yy, o)) in planes.p1[y * w..][..w]
                .iter()
                .zip(d.chunks_exact_mut(4))
                .enumerate()
            {
                let s = planar_shift(geom.cll);
                let (r, g, b) =
                    ycocg_to_rgb_scaled(yy, chroma(co[x >> 1], s), chroma(cg[x >> 1], s));
                put::<BGRA>(o, r, g, b, 0xFF);
            }
        } else {
            let (yp, cop, cgp) = (
                &planes.p1[y * w..],
                &planes.p2[y * w..],
                &planes.p3[y * w..],
            );
            for (((&yy, &co), &cg), o) in yp[..w]
                .iter()
                .zip(&cop[..w])
                .zip(&cgp[..w])
                .zip(d.chunks_exact_mut(4))
            {
                let s = planar_shift(geom.cll);
                let (r, g, b) = ycocg_to_rgb_scaled(yy, chroma(co, s), chroma(cg, s));
                put::<BGRA>(o, r, g, b, 0xFF);
            }
        }
        // The alpha pass is separate so the colour loops above stay four
        // slices wide. It touches a row that is already in L1 and it only runs
        // when there is a decoded alpha plane to apply, which the legacy
        // bitmap path never has.
        if let Some(a) = planes.alpha {
            let d = dst.row(y);
            for (&av, o) in a[y * w..][..w].iter().zip(d.chunks_exact_mut(4)) {
                o[3] = av;
            }
        }
    }
}

/// The two decode stages of PRDRDP/04 §11.2, exposed so the `rdp_stage/*`
/// benches can time `planar_rle` and `planar_delta` separately rather than
/// inferring them from a difference of whole codec numbers. Gated with the
/// reference encoders, so neither the shipped surface nor the fuzz surface
/// grows.
#[cfg(any(test, feature = "encode"))]
pub mod stages {
    use super::{DecodeError, Reader};

    /// Run length decode one plane, without the delta pass.
    pub fn plane_rle(src: &[u8], plane: &mut [u8], w: usize, h: usize) -> Result<(), DecodeError> {
        let mut r = Reader::new(src, "planar plane");
        super::decode_plane_rle(&mut r, plane, w, h)
    }

    /// Undo the delta encoding of an already run length decoded plane.
    pub fn plane_delta(plane: &mut [u8], w: usize, h: usize) {
        super::undo_delta(plane, w, h);
    }
}

/// Bytes of scratch a decode of this geometry needs, so a caller can size a
/// pool without decoding first.
pub fn scratch_len(width: u16, height: u16) -> usize {
    usize::from(width) * usize::from(height) * 4
}

/// Decode an `RDP6_BITMAP_STREAM` into the caller's destination.
///
/// `want_alpha` asks for the decoded alpha plane to be applied. It is false
/// for a legacy `TS_BITMAP_DATA`, whose alpha byte is meaningless, and true
/// for the EGFX paths that carry a real one. When there is no alpha plane, or
/// when it is not wanted, the interleave writes a constant 255 rather than
/// leaving the byte alone: a stray zero alpha is invisible on screen, because
/// the renderer draws the framebuffer quad with `u_texAlpha = 0`
/// (`ui/src/render/WebGLRenderer.ts:900`), but it is wrong in
/// `readFramebufferRGBA` and in thumbnails (PRDRDP/04 §2.5).
///
/// The row order lives in `dst`. Every error is a [`DecodeError`]; no input
/// makes this panic or loop.
pub fn decode(
    src: &[u8],
    want_alpha: bool,
    scratch: &mut PlanarScratch,
    dst: &mut DstView<'_>,
) -> Result<(), DecodeError> {
    let (w, h) = (usize::from(dst.width()), usize::from(dst.height()));
    let mut r = Reader::new(src, "planar bitmap");
    let hdr = r.u8()?;
    if hdr & HDR_RESERVED != 0 {
        return Err(DecodeError::Range {
            what: "planar FormatHeader",
            got: u32::from(hdr),
        });
    }
    let cll = hdr & HDR_CLL;
    let cs = hdr & HDR_CS != 0;
    let rle = hdr & HDR_RLE != 0;
    let na = hdr & HDR_NA != 0;
    // Subsampling an R, G or B plane is not defined, so `cs` without `cll` is
    // a malformed stream rather than something to guess at.
    if cs && cll == 0 {
        return Err(DecodeError::Range {
            what: "planar cs without cll",
            got: u32::from(hdr),
        });
    }
    if w == 0 || h == 0 {
        return Ok(());
    }

    let (sw, sh) = if cs {
        (w.div_ceil(2), h.div_ceil(2))
    } else {
        (w, h)
    };
    let plane_len = w * h;
    scratch.grow(plane_len);
    let [alpha, p1, p2, p3] = scratch.planes(plane_len);

    // Plane order on the wire: alpha when present, then the three colour
    // planes (MS-RDPEGDI 2.2.2.5.1).
    if !na {
        decode_plane(&mut r, alpha, w, h, rle)?;
    }
    decode_plane(&mut r, p1, w, h, rle)?;
    decode_plane(&mut r, p2, sw, sh, rle)?;
    decode_plane(&mut r, p3, sw, sh, rle)?;
    if r.remaining() > TRAILING_SLACK {
        return Err(DecodeError::Range {
            what: "planar trailing bytes",
            got: r.remaining() as u32,
        });
    }

    let planes = Planes {
        alpha: if want_alpha && !na {
            Some(&alpha[..plane_len])
        } else {
            None
        },
        p1,
        p2,
        p3,
    };
    let geom = Geom { w, h, sw, cs, cll };
    match dst.format() {
        OutFormat::Rgba => interleave::<false>(&planes, &geom, dst),
        OutFormat::Bgra => interleave::<true>(&planes, &geom, dst),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uncompressed::dst_len;
    use remote_pixel::RowOrder;

    fn view<'a>(buf: &'a mut [u8], w: u16, h: u16, order: RowOrder) -> DstView<'a> {
        DstView::packed(buf, w, h, OutFormat::Rgba, order).unwrap()
    }

    /// Raw planes, no RLE, no delta, no alpha, no colour loss. A 2 by 2
    /// bitmap: header 0x20 is NA alone, then three planes of four bytes in the
    /// order red, green, blue.
    #[test]
    fn raw_planes_are_three_full_size_planes_in_rgb_order() {
        let mut src = vec![HDR_NA];
        src.extend_from_slice(&[10, 11, 12, 13]); // red
        src.extend_from_slice(&[20, 21, 22, 23]); // green
        src.extend_from_slice(&[30, 31, 32, 33]); // blue

        let mut out = vec![0u8; dst_len(2, 2)];
        let mut v = view(&mut out, 2, 2, RowOrder::TopDown);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        assert_eq!(&out[0..8], &[10, 20, 30, 0xFF, 11, 21, 31, 0xFF]);
        assert_eq!(&out[8..16], &[12, 22, 32, 0xFF, 13, 23, 33, 0xFF]);
    }

    /// The same bytes with a bottom up destination put wire row 0 last. This
    /// is PRDRDP/04 §2.3's asymmetry and the fixture is deliberately not
    /// symmetric.
    #[test]
    fn bottom_up_flips_on_the_way_out_only() {
        let mut src = vec![HDR_NA];
        src.extend_from_slice(&[10, 11, 12, 13]);
        src.extend_from_slice(&[20, 21, 22, 23]);
        src.extend_from_slice(&[30, 31, 32, 33]);

        let mut out = vec![0u8; dst_len(2, 2)];
        let mut v = view(&mut out, 2, 2, RowOrder::BottomUp);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        assert_eq!(&out[0..8], &[12, 22, 32, 0xFF, 13, 23, 33, 0xFF]);
        assert_eq!(&out[8..16], &[10, 20, 30, 0xFF, 11, 21, 31, 0xFF]);
    }

    /// An alpha plane comes first, and `want_alpha` decides whether it is
    /// applied or replaced with an opaque 255.
    #[test]
    fn the_alpha_plane_is_first_and_optional() {
        let mut src = vec![0x00]; // no NA, so four planes
        src.extend_from_slice(&[0x40, 0x80]); // alpha
        src.extend_from_slice(&[10, 11]);
        src.extend_from_slice(&[20, 21]);
        src.extend_from_slice(&[30, 31]);

        let mut out = vec![0u8; dst_len(2, 1)];
        let mut v = view(&mut out, 2, 1, RowOrder::TopDown);
        decode(&src, true, &mut PlanarScratch::new(), &mut v).unwrap();
        assert_eq!(out, [10, 20, 30, 0x40, 11, 21, 31, 0x80]);

        let mut out = vec![0u8; dst_len(2, 1)];
        let mut v = view(&mut out, 2, 1, RowOrder::TopDown);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        assert_eq!(out, [10, 20, 30, 0xFF, 11, 21, 31, 0xFF]);
    }

    /// The RLE segment encoding, MS-RDPEGDI 2.2.2.5.1.1.
    ///
    /// `0x1F` is `cRawBytes = 1`, `nRunLength = 15`: one literal, then fifteen
    /// copies of it, which fills a scanline of sixteen. The high nibble is the
    /// raw count and the low nibble is the run, which is the way round most
    /// people guess wrong.
    #[test]
    fn rle_segments_split_the_control_byte_high_nibble_first() {
        let src = [HDR_NA | HDR_RLE, 0x1F, 0x10, 0x1F, 0x20, 0x1F, 0x30];
        let mut out = vec![0u8; dst_len(16, 1)];
        let mut v = view(&mut out, 16, 1, RowOrder::TopDown);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        for px in out.chunks_exact(4) {
            assert_eq!(px, [0x10, 0x20, 0x30, 0xFF]);
        }
    }

    /// The two escapes. `nRunLength == 1` means `cRawBytes + 16` and
    /// `nRunLength == 2` means `cRawBytes + 32`, in both cases with the raw
    /// count taken to zero. So a run of one or two is never encoded as a run.
    ///
    /// Per plane: `0x02` is a run of 32 zeros (the run begins the scanline, so
    /// the last byte written is zero), then `0x20` is two literals. That is a
    /// scanline of 34.
    #[test]
    fn rle_run_length_escapes_steal_the_raw_count() {
        let mut src = vec![HDR_NA | HDR_RLE];
        for lit in [(0x11u8, 0x12u8), (0x21, 0x22), (0x31, 0x32)] {
            src.extend_from_slice(&[0x02, 0x20, lit.0, lit.1]);
        }
        let mut out = vec![0u8; dst_len(34, 1)];
        let mut v = view(&mut out, 34, 1, RowOrder::TopDown);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        assert_eq!(&out[0..4], &[0, 0, 0, 0xFF]);
        assert_eq!(&out[31 * 4..32 * 4], &[0, 0, 0, 0xFF]);
        assert_eq!(&out[32 * 4..33 * 4], &[0x11, 0x21, 0x31, 0xFF]);
        assert_eq!(&out[33 * 4..34 * 4], &[0x12, 0x22, 0x32, 0xFF]);
    }

    /// Delta encoding, and the no delta on the first row rule.
    ///
    /// A 2 by 3 red plane. Row 0 is raw at 100. Row 1's bytes are `0x04`,
    /// which is even, so `d = 2` and the value is `100 + 2 = 102`. Row 2's
    /// bytes are `0x05`, which is odd, so `d = 2` and the value is
    /// `102 - (2 + 1) = 99`. Green and blue carry the same pattern from
    /// different bases.
    #[test]
    fn delta_applies_to_every_row_but_the_first() {
        let mut src = vec![HDR_NA | HDR_RLE];
        for base in [100u8, 150, 200] {
            src.extend_from_slice(&[0x20, base, base]); // row 0, two literals
            src.extend_from_slice(&[0x20, 0x04, 0x04]); // row 1, delta +2
            src.extend_from_slice(&[0x20, 0x05, 0x05]); // row 2, delta -3
        }
        let mut out = vec![0u8; dst_len(2, 3)];
        let mut v = view(&mut out, 2, 3, RowOrder::TopDown);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        assert_eq!(&out[0..4], &[100, 150, 200, 0xFF]);
        assert_eq!(&out[8..12], &[102, 152, 202, 0xFF]);
        assert_eq!(&out[16..20], &[99, 149, 199, 0xFF]);
    }

    #[test]
    fn delta_arithmetic_wraps_rather_than_saturating() {
        let mut src = vec![HDR_NA | HDR_RLE];
        for base in [0u8, 255, 0] {
            src.extend_from_slice(&[0x10, base]); // row 0
            src.extend_from_slice(&[0x10, 0x03]); // row 1, delta -2
        }
        let mut out = vec![0u8; dst_len(1, 2)];
        let mut v = view(&mut out, 1, 2, RowOrder::TopDown);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        assert_eq!(&out[0..4], &[0, 255, 0, 0xFF]);
        assert_eq!(&out[4..8], &[254, 253, 254, 0xFF]);
    }

    /// The inverse colour transform, hand computed at `cll = 1`.
    ///
    /// `cll` of 1 is a shift of 0, so the stored bytes are the chroma.
    ///
    /// Pixel 0: Y = 128, Co = 0, Cg = 0. `T = 128` and every channel is 128,
    /// so a neutral grey survives untouched.
    ///
    /// Pixel 1: Y = 128, Co byte `0x20` which is +32, Cg byte `0xF0` which is
    /// -16. `T = 128 + 16 = 144`, `R = 144 - 32 = 112`, `G = 128 - 16 = 112`
    /// and `B = 144 + 32 = 176`. Nothing clamps, which is the point: a YCoCg
    /// triple that came from a real pixel always converts back in range.
    #[test]
    fn ycocg_inverse_matches_the_hand_computed_pixels() {
        let src = [
            HDR_NA | 0x01, // cll = 1, so a shift of 0
            128,
            128, // Y
            0,
            0x20, // Co
            0,
            0xF0, // Cg
        ];
        let mut out = vec![0u8; dst_len(2, 1)];
        let mut v = view(&mut out, 2, 1, RowOrder::TopDown);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        assert_eq!(&out[0..4], &[128, 128, 128, 0xFF]);
        assert_eq!(&out[4..8], &[112, 112, 176, 0xFF]);
    }

    /// The colour loss is undone by `cll - 1` places, inside eight bits.
    ///
    /// These are the bytes a Windows 11 host actually sent: `cll = 3`, and a
    /// tile of flat water whose first pixel is Y = 96 with stored chroma
    /// `0x12` and `0x3B`. At a shift of two those are `0x48`, which is +72,
    /// and `0xEC`, which is -20, and the pixel comes out a mid blue.
    ///
    /// Both ways of getting this wrong were shipped, and both look almost
    /// right. Shifting one place too far doubles every sample, so `0x12`
    /// overflows eight bits and comes back as -112: the sign flips, and the
    /// pixel turns roughly complementary. Widening to `i16` before shifting
    /// instead keeps the bits above the meaningful ones, and `0x3B` reads as
    /// +472, which no 8 bit pixel can produce.
    #[test]
    fn colour_loss_is_undone_by_one_less_than_the_level() {
        assert_eq!((chroma(0x12, 2), chroma(0x3B, 2)), (72, -20));
        assert_eq!(
            ycocg_to_rgb_scaled(96, chroma(0x12, 2), chroma(0x3B, 2)),
            (44, 76, 188)
        );

        // One place too far: +72 becomes -112, a sign flip rather than a
        // rounding error.
        assert_eq!(chroma(0x12, 3), -112);
        // Widening first: outside anything an 8 bit pixel can produce.
        assert_eq!(i16::from(0x3Bu8) << 2, 236);
        assert_eq!(i16::from(0x3Bu8) << 3, 472);
    }

    /// A correct scale never discards a set bit.
    ///
    /// This is the property that settled the transform, and it is worth a test
    /// of its own because it needs no reference picture and no server. The
    /// encoder can only emit a quantized chroma that fits in `8 - shift` bits;
    /// shifting it back by `shift` must therefore land inside eight bits
    /// exactly. Shifting one place too far, which is what shipped in 0.13.3,
    /// breaks this for every value in the top half of the range and flips its
    /// sign rather than merely rounding it.
    #[test]
    fn the_shift_never_discards_a_bit_the_encoder_could_have_set() {
        for shift in 0..=6u8 {
            let span = 1i32 << (7 - shift);
            for q in -span..span {
                let byte = q as i8 as u8;
                assert_eq!(
                    chroma(byte, shift),
                    (q << shift) as i16,
                    "shift {shift}, quantized {q} came back wrong"
                );
            }
        }
    }

    /// The planar colour loss level is a count of discarded bits and the
    /// non lifting transform folds one halving into the scale, so the shift is
    /// one less than the field. Zero is guarded rather than meaningful: those
    /// planes are RGB and never reach the transform.
    #[test]
    fn the_planar_shift_is_one_less_than_the_level() {
        assert_eq!(planar_shift(3), 2);
        assert_eq!(planar_shift(1), 0);
        assert_eq!(planar_shift(0), 0);
    }

    /// Chroma subsampling replicates 2 by 2. A 4 by 2 bitmap has a 2 by 1
    /// chroma plane, so both destination rows read chroma row 0 and each
    /// chroma sample covers two columns.
    ///
    /// With Y = 100 and Cg = 0 everywhere, and a Co byte of 64 for the left
    /// sample and 0 for the right: `cll = 1` is a shift of 0, so that byte is
    /// +64 and the left two pixels are `T = 100`, `R = 100 - 64 = 36`,
    /// `G = 100` and `B = 100 + 64 = 164`, while the right two are grey.
    #[test]
    fn chroma_subsampling_replicates_two_by_two() {
        let mut src = vec![HDR_NA | HDR_CS | 0x01];
        src.extend_from_slice(&[100; 8]); // Y, 4 by 2
        src.extend_from_slice(&[64, 0]); // Co, 2 by 1
        src.extend_from_slice(&[0, 0]); // Cg, 2 by 1
        let mut out = vec![0u8; dst_len(4, 2)];
        let mut v = view(&mut out, 4, 2, RowOrder::TopDown);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        for row in out.chunks_exact(16) {
            assert_eq!(&row[0..4], &[36, 100, 164, 0xFF]);
            assert_eq!(&row[4..8], &[36, 100, 164, 0xFF]);
            assert_eq!(&row[8..12], &[100, 100, 100, 0xFF]);
            assert_eq!(&row[12..16], &[100, 100, 100, 0xFF]);
        }
    }

    #[test]
    fn odd_geometry_subsamples_with_a_ceiling() {
        // 3 by 3 with cs gives a 2 by 2 chroma plane.
        let mut src = vec![HDR_NA | HDR_CS | 0x01];
        src.extend_from_slice(&[100; 9]);
        src.extend_from_slice(&[0; 4]);
        src.extend_from_slice(&[0; 4]);
        let mut out = vec![0u8; dst_len(3, 3)];
        let mut v = view(&mut out, 3, 3, RowOrder::TopDown);
        decode(&src, false, &mut PlanarScratch::new(), &mut v).unwrap();
        for px in out.chunks_exact(4) {
            assert_eq!(px, [100, 100, 100, 0xFF]);
        }
    }

    #[test]
    fn one_trailing_byte_is_tolerated_and_two_are_not() {
        let mut src = vec![HDR_NA, 10, 20, 30];
        assert!(decode_ok(&src));
        src.push(0);
        assert!(
            decode_ok(&src),
            "one byte of slack is a known encoder quirk"
        );
        src.push(0);
        assert!(!decode_ok(&src));
    }

    fn decode_ok(src: &[u8]) -> bool {
        let mut out = vec![0u8; dst_len(1, 1)];
        let mut v = view(&mut out, 1, 1, RowOrder::TopDown);
        decode(src, false, &mut PlanarScratch::new(), &mut v).is_ok()
    }

    #[test]
    fn reserved_header_bits_and_illegal_flag_combinations_are_errors() {
        for hdr in [0x40u8, 0x80, 0xC0] {
            assert!(matches!(
                decode_one(&[hdr]),
                Err(DecodeError::Range {
                    what: "planar FormatHeader",
                    ..
                })
            ));
        }
        // Subsampling without colour loss.
        assert!(matches!(
            decode_one(&[HDR_NA | HDR_CS]),
            Err(DecodeError::Range {
                what: "planar cs without cll",
                ..
            })
        ));
    }

    #[test]
    fn a_control_byte_of_zero_cannot_stall_the_decoder() {
        let src = [HDR_NA | HDR_RLE, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(
            decode_one(&src),
            Err(DecodeError::Range {
                what: "planar rle control",
                ..
            })
        ));
    }

    #[test]
    fn a_segment_that_overruns_its_scanline_is_a_range_error() {
        // A run of 32 into a scanline of two.
        let src = [HDR_NA | HDR_RLE, 0x02];
        let mut out = vec![0u8; dst_len(2, 1)];
        let mut v = view(&mut out, 2, 1, RowOrder::TopDown);
        assert!(matches!(
            decode(&src, false, &mut PlanarScratch::new(), &mut v),
            Err(DecodeError::Range {
                what: "planar rle segment",
                ..
            })
        ));
    }

    fn decode_one(src: &[u8]) -> Result<(), DecodeError> {
        let mut out = vec![0u8; dst_len(1, 1)];
        let mut v = view(&mut out, 1, 1, RowOrder::TopDown);
        decode(src, false, &mut PlanarScratch::new(), &mut v)
    }

    /// Every prefix of a valid stream returns an error rather than panicking
    /// (PRDRDP/04 §4.1 rule five). Both the raw and the RLE plane paths, and
    /// the alpha and no alpha shapes, because they read different amounts.
    #[test]
    fn truncation_returns_err_and_never_panics() {
        let mut rle = vec![HDR_RLE]; // four planes, RLE and delta
        for base in [10u8, 20, 30, 40] {
            rle.extend_from_slice(&[0x40, base, base, base, base]); // row 0
            rle.extend_from_slice(&[0x13, 0x02]); // row 1, one literal plus a run of 3
        }
        let mut raw = vec![HDR_NA];
        raw.extend_from_slice(&[7u8; 4 * 3]);

        for (src, w, h) in [(rle.as_slice(), 4u16, 2u16), (raw.as_slice(), 4, 1)] {
            let mut out = vec![0u8; dst_len(w, h)];
            {
                let mut v = view(&mut out, w, h, RowOrder::BottomUp);
                assert!(
                    decode(src, true, &mut PlanarScratch::new(), &mut v).is_ok(),
                    "fixture must decode"
                );
            }
            for k in 0..src.len() {
                let mut v = view(&mut out, w, h, RowOrder::BottomUp);
                assert!(
                    decode(&src[..k], true, &mut PlanarScratch::new(), &mut v).is_err(),
                    "prefix of {k} bytes decoded a whole bitmap"
                );
            }
        }
    }

    /// Adversarial headers over adversarial bodies, to prove termination.
    #[test]
    fn adversarial_streams_terminate() {
        let mut scratch = PlanarScratch::new();
        let mut out = vec![0u8; dst_len(16, 16)];
        for hdr in 0u8..=255 {
            for body in [
                vec![hdr],
                vec![hdr, 0x00],
                vec![hdr, 0xFF, 0xFF, 0xFF, 0xFF],
                vec![hdr, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02],
                vec![hdr; 40],
            ] {
                let mut v = view(&mut out, 16, 16, RowOrder::BottomUp);
                let _ = decode(&body, true, &mut scratch, &mut v);
            }
        }
    }

    #[test]
    fn the_scratch_allocates_once_and_reports_its_size() {
        let mut s = PlanarScratch::with_capacity(64, 64);
        assert!(s.bytes() >= 64 * 64 * 4);
        let before = s.bytes();
        let mut src = vec![HDR_NA];
        src.extend_from_slice(&[1u8; 3 * 64 * 64]);
        let mut out = vec![0u8; dst_len(64, 64)];
        {
            let mut v = view(&mut out, 64, 64, RowOrder::TopDown);
            decode(&src, false, &mut s, &mut v).unwrap();
        }
        assert_eq!(
            s.bytes(),
            before,
            "a decode at the pooled size must not allocate"
        );
        s.reset();
        assert_eq!(s.bytes(), 0);
    }
}
