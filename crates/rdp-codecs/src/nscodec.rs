//! NSCodec (MS-RDPNSC 2.2 for the bitstream, 3.1.8 for the decoding rules).
//!
//! Four planes (Y, Co, Cg and alpha), each optionally run length encoded,
//! with chroma subsampling and a colour loss level, decoded through the
//! inverse YCoCg transform.
//!
//! We implement NSCodec and we do not advertise `CODEC_GUID_NSCODEC`
//! (PRDRDP/04 §2.8), so the path that reaches it in practice is
//! [`crate::clear`]'s subcodec layer, which can carry an NSCodec rectangle
//! inside a ClearCodec bitmap. That is why this module exposes a row emitter
//! as well as a whole bitmap entry point: ClearCodec needs to place the
//! result at an offset inside a larger destination and a second copy through
//! a scratch would be the copy PRDRDP/04 §4.2 forbids.
//!
//! ## The plane RLE, and the four bytes that are never a run
//!
//! MS-RDPNSC 3.1.8's run length encoding is a different scheme from
//! [`crate::planar`]'s and from ClearCodec's, which is why the three live in
//! three files. Two bytes of the same value signal a run:
//!
//! ```text
//! while more than four output bytes remain:
//!     v = next byte
//!     if exactly five output bytes remain { emit v; continue }
//!     if v == the next byte:
//!         consume the duplicate
//!         len = next byte
//!         if len < 0xFF { len += 2 } else { len = next u32 }
//!         emit len copies of v
//!     else:
//!         emit v
//! emit the last four bytes of the plane verbatim
//! ```
//!
//! The loop counts **output** bytes, not input bytes. That is the reading
//! that makes the scheme decodable at all, because nothing else tells the
//! decoder where a plane ends. The last four bytes of every plane are stored
//! raw and are never part of a run, which is the detail a decoder written
//! from prose alone misses; it produces a four pixel error in the bottom
//! right corner of every tile, invisible until someone screenshots a window
//! border (PRDRDP/04 §4.7).
//!
//! A plane whose byte count equals its uncompressed size is stored raw with
//! no run length encoding at all. There is no flag for it: the equality is
//! the signal.

use remote_pixel::{put, DstView, OutFormat};

use crate::planar::{chroma, ycocg_to_rgb_scaled};
use crate::{DecodeError, Reader};

/// `NSCODEC_BITMAP_STREAM`'s fixed header (MS-RDPNSC 2.2).
const HEADER_LEN: usize = 4 * 4 + 1 + 1 + 2;

/// Output bytes at the end of a plane that are stored raw.
const RAW_TAIL: usize = 4;

/// The alignment the luma plane width is rounded up to when chroma
/// subsampling is on.
///
/// BEHAVIOUR: MS-RDPNSC 2.2 says the luma plane is padded when
/// `ChromaSubsamplingLevel` is one and does not state the alignment in a form
/// that survives paraphrase. Eight is what the encoders in the wild use and
/// what PRDRDP/04 §4.7 records as the reading to pin against the MS-RDPNSC §4
/// vector. The failure mode if it is wrong is a shear: every row after the
/// first is offset by a few pixels, which is unmistakable on screen, so this
/// is a assumption that announces itself rather than one that hides.
const LUMA_ALIGN: usize = 8;

/// Geometry of one decoded bitmap, worked out from the header and the
/// destination.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Geom {
    w: usize,
    h: usize,
    /// Luma plane pitch, `w` rounded up to [`LUMA_ALIGN`] when subsampled.
    luma_w: usize,
    chroma_w: usize,
    chroma_h: usize,
    cll: u8,
    css: bool,
    has_alpha: bool,
}

impl Geom {
    fn luma_len(&self) -> usize {
        self.luma_w * self.h
    }
    fn chroma_len(&self) -> usize {
        self.chroma_w * self.chroma_h
    }
    fn alpha_len(&self) -> usize {
        self.w * self.h
    }
    fn total(&self) -> usize {
        self.luma_len() + 2 * self.chroma_len() + self.alpha_len()
    }
}

/// The four plane buffers, allocated once and reused
/// (PRDRDP/04 §4.1 rule two).
///
/// One flat `Vec` rather than four, because the four sizes are known
/// together and one allocation that grows to the largest bitmap a session
/// sees is cheaper than four that each do.
#[derive(Default)]
pub struct NscScratch {
    buf: Vec<u8>,
}

impl NscScratch {
    /// An empty scratch, which grows to fit on its first decode.
    pub fn new() -> Self {
        Self::default()
    }

    /// A scratch already sized for a bitmap of this geometry.
    pub fn with_capacity(width: u16, height: u16) -> Self {
        let mut s = Self::new();
        s.buf.resize(scratch_len(width, height), 0);
        s
    }

    /// Give the memory back.
    pub fn reset(&mut self) {
        self.buf = Vec::new();
    }

    /// Bytes currently held, for the accounting in PRDRDP/04 §11.3.
    pub fn bytes(&self) -> usize {
        self.buf.capacity()
    }

    fn grow(&mut self, need: usize) {
        if self.buf.len() < need {
            self.buf.resize(need, 0);
        }
    }

    fn planes(&mut self, g: &Geom) -> [&mut [u8]; 4] {
        let (y, rest) = self.buf.split_at_mut(g.luma_len());
        let (co, rest) = rest.split_at_mut(g.chroma_len());
        let (cg, rest) = rest.split_at_mut(g.chroma_len());
        [y, co, cg, &mut rest[..g.alpha_len()]]
    }
}

/// Bytes of scratch a decode of this geometry needs, so a caller can size a
/// pool without decoding first.
pub fn scratch_len(width: u16, height: u16) -> usize {
    let w = usize::from(width);
    let h = usize::from(height);
    // The subsampled case is the larger of the two, because the luma plane is
    // padded and the two chroma planes are a quarter each.
    let luma_w = w.next_multiple_of(LUMA_ALIGN);
    let chroma = (luma_w / 2) * (h.div_ceil(2));
    luma_w * h + 2 * chroma + w * h
}

/// Decode one plane, run length encoded or raw (MS-RDPNSC 3.1.8).
fn decode_plane(src: &[u8], plane: &mut [u8]) -> Result<(), DecodeError> {
    let n = plane.len();
    if src.len() == n {
        // No flag says so: a byte count equal to the uncompressed size is
        // itself the signal that the plane is stored raw.
        plane.copy_from_slice(src);
        return Ok(());
    }

    let mut r = Reader::new(src, "nscodec plane");
    let mut at = 0usize;

    while n - at > RAW_TAIL {
        let v = r.u8()?;
        if n - at == RAW_TAIL + 1 {
            // The byte before the raw tail is always a literal, never the
            // first half of a run pair.
            plane[at] = v;
            at += 1;
            continue;
        }
        // A run is signalled by the same byte twice. `remaining` is zero only
        // at the very end of the input, where a truncated stream lands.
        let dup = r.clone().u8()?;
        if dup != v {
            plane[at] = v;
            at += 1;
            continue;
        }
        let _ = r.u8()?;
        let first = r.u8()?;
        let len = if first < 0xFF {
            usize::from(first) + 2
        } else {
            r.u32_le()? as usize
        };
        // A zero length run would leave `at` where it was and the loop would
        // never end. The escape form is the only one that can express it.
        if len == 0 {
            return Err(DecodeError::Range {
                what: "nscodec run length",
                got: 0,
            });
        }
        // The tail is not part of any run, so a run that reaches into it is
        // as malformed as one that overruns the plane.
        if len > n - RAW_TAIL - at {
            return Err(DecodeError::Range {
                what: "nscodec run overruns the plane",
                got: len as u32,
            });
        }
        plane[at..at + len].fill(v);
        at += len;
    }

    plane[n - RAW_TAIL..].copy_from_slice(r.take(RAW_TAIL)?);
    Ok(())
}

/// Parse the header, work out the geometry and decode all four planes into
/// the scratch.
pub(crate) fn decode_planes(
    src: &[u8],
    width: u16,
    height: u16,
    scratch: &mut NscScratch,
) -> Result<Geom, DecodeError> {
    let mut r = Reader::new(src, "nscodec bitmap");
    let luma_bytes = r.u32_le()? as usize;
    let co_bytes = r.u32_le()? as usize;
    let cg_bytes = r.u32_le()? as usize;
    let alpha_bytes = r.u32_le()? as usize;
    let cll = r.u8()?;
    let css = r.u8()?;
    let _reserved = r.u16_le()?;
    debug_assert_eq!(src.len() - r.remaining(), HEADER_LEN);

    // MS-RDPNSC 2.2 defines the colour loss level over 1 to 7 and the
    // subsampling level over 0 and 1. Anything else is a stream for a codec
    // we do not have rather than one to guess at.
    if !(1..=7).contains(&cll) {
        return Err(DecodeError::Range {
            what: "NSCodec ColorLossLevel",
            got: u32::from(cll),
        });
    }
    if css > 1 {
        return Err(DecodeError::Range {
            what: "NSCodec ChromaSubsamplingLevel",
            got: u32::from(css),
        });
    }

    let w = usize::from(width);
    let h = usize::from(height);
    let css = css == 1;
    let (luma_w, chroma_w, chroma_h) = if css {
        let lw = w.next_multiple_of(LUMA_ALIGN);
        (lw, lw / 2, h.div_ceil(2))
    } else {
        (w, w, h)
    };
    let g = Geom {
        w,
        h,
        luma_w,
        chroma_w,
        chroma_h,
        cll,
        css,
        has_alpha: alpha_bytes != 0,
    };

    if w == 0 || h == 0 {
        return Ok(g);
    }
    scratch.grow(g.total());
    let [y, co, cg, alpha] = scratch.planes(&g);

    // The planes are laid out in the order the header counted them.
    let mut body = Reader::new(r.take(r.remaining())?, "nscodec planes");
    for (count, plane, fill) in [
        (luma_bytes, &mut *y, 0u8),
        (co_bytes, &mut *co, 0),
        (cg_bytes, &mut *cg, 0),
        (alpha_bytes, &mut *alpha, 0xFF),
    ] {
        if count == 0 {
            // An absent plane. For alpha that means opaque, which is the
            // common case; for the other three it means a flat component.
            plane.fill(fill);
            continue;
        }
        decode_plane(body.take(count)?, plane)?;
    }
    Ok(g)
}

/// Write one row of the decoded bitmap into `dst`, which is exactly four
/// bytes per pixel (MS-RDPNSC 3.1.6).
///
/// The chroma upsample at `ChromaSubsamplingLevel = 1` is 2 by 2 pixel
/// replication rather than interpolation, for the same reason
/// `planar::interleave` replicates: the encoder took a point sample, so
/// interpolating would be inventing detail. Odd widths and heights replicate
/// the last column and row by construction, because the index is a halving.
pub(crate) fn emit_row<const BGRA: bool>(
    scratch: &mut NscScratch,
    g: &Geom,
    y: usize,
    dst: &mut [u8],
) {
    debug_assert!(y < g.h);
    debug_assert_eq!(dst.len(), g.w * 4);
    let [yp, cop, cgp, ap] = scratch.planes(g);
    let (cy, shift) = if g.css { (y / 2, 1u32) } else { (y, 0) };
    let luma = &yp[y * g.luma_w..][..g.w];
    let co = &cop[cy * g.chroma_w..][..g.chroma_w];
    let cg = &cgp[cy * g.chroma_w..][..g.chroma_w];
    let alpha = &ap[y * g.w..][..g.w];

    for (x, ((&yv, &av), o)) in luma
        .iter()
        .zip(alpha)
        .zip(dst.chunks_exact_mut(4))
        .enumerate()
    {
        let cx = x >> shift;
        // MS-RDPNSC 2.2 defines ColorLossLevel over 1 to 7 with 1 meaning no
        // loss, so the bits discarded are one fewer than the field, the same
        // arithmetic the planar codec arrives at from the other direction.
        //
        // The negation is the one real difference between the two: NSCodec's
        // Co carries the opposite sign, `R = Y + Co - Cg` against planar's
        // `R = Y - Cg - Co`. Negating here keeps the shared transform free of
        // a flag.
        let sh = g.cll - 1;
        let (r, gg, b) = ycocg_to_rgb_scaled(yv, -chroma(co[cx], sh), chroma(cg[cx], sh));
        put::<BGRA>(o, r, gg, b, if g.has_alpha { av } else { 0xFF });
    }
}

/// Decode an `NSCODEC_BITMAP_STREAM` into the caller's destination
/// (MS-RDPNSC 2.2, 3.1.8).
///
/// The geometry comes from `dst`, because NSCodec's own header carries the
/// plane byte counts and not the width and height: an outer structure always
/// supplies those, either a `TS_SURFACE_BITS` or ClearCodec's subcodec
/// rectangle. The row order lives in `dst` as well.
///
/// This signature differs from the sketch in PRDRDP/04 §4.7, which passes
/// `w`, `h` and a bare `&mut [u8]`. [`DstView`] carries all three plus the
/// destination stride and channel order, which is what lets a caller decode
/// straight into a larger framebuffer without the second copy §4.2 forbids.
///
/// Every error is a [`DecodeError`]; no input makes this panic or loop.
pub fn decode(
    src: &[u8],
    scratch: &mut NscScratch,
    dst: &mut DstView<'_>,
) -> Result<(), DecodeError> {
    let g = decode_planes(src, dst.width(), dst.height(), scratch)?;
    if g.w == 0 || g.h == 0 {
        return Ok(());
    }
    let bgra = matches!(dst.format(), OutFormat::Bgra);
    for y in 0..g.h {
        let row = dst.row(y);
        if bgra {
            emit_row::<true>(scratch, &g, y, row);
        } else {
            emit_row::<false>(scratch, &g, y, row);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode;
    use crate::uncompressed::dst_len;
    use remote_pixel::RowOrder;

    fn view<'a>(buf: &'a mut [u8], w: u16, h: u16) -> DstView<'a> {
        DstView::packed(buf, w, h, OutFormat::Rgba, RowOrder::TopDown).unwrap()
    }

    /// Hand assembled, not a specification transcription: MS-RDPNSC §4 was
    /// not available to this lane. The arithmetic is shown so it can be
    /// checked without it.
    ///
    /// A ten byte plane. The first six bytes are produced by the loop and the
    /// last four are the raw tail:
    ///
    /// ```text
    /// 0x41                literal, one byte out
    /// 0x42 0x42 0x00      a run: length byte 0, so 0 + 2 = 2 bytes of 0x42
    /// 0x43 0x43 0x01      a run of 1 + 2 = 3 bytes of 0x43
    /// 0x51 0x52 0x53 0x54 the raw tail
    /// ```
    #[test]
    fn the_plane_rle_decodes_literals_runs_and_the_raw_tail() {
        let src = [
            0x41, 0x42, 0x42, 0x00, 0x43, 0x43, 0x01, 0x51, 0x52, 0x53, 0x54,
        ];
        let mut plane = [0u8; 10];
        decode_plane(&src, &mut plane).unwrap();
        assert_eq!(
            plane,
            [0x41, 0x42, 0x42, 0x43, 0x43, 0x43, 0x51, 0x52, 0x53, 0x54]
        );
    }

    /// The escape form: a length byte of 0xFF means the real length is the
    /// four bytes after it. A short run through the escape must decode the
    /// same as the same run through the short form, which is what pins the
    /// `+ 2` to the short form alone.
    #[test]
    fn the_long_run_escape_carries_its_own_length() {
        let mut src = vec![0x77, 0x77, 0xFF];
        src.extend_from_slice(&5u32.to_le_bytes());
        src.extend_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4]);
        let mut plane = [0u8; 9];
        decode_plane(&src, &mut plane).unwrap();
        assert_eq!(
            plane,
            [0x77; 5]
                .iter()
                .chain(&[0xA1, 0xA2, 0xA3, 0xA4])
                .copied()
                .collect::<Vec<_>>()[..]
        );
    }

    /// The byte immediately before the raw tail is a literal even when it
    /// equals the byte after it. Reading it as the start of a run is the
    /// mistake the "exactly five bytes remain" clause exists to prevent.
    #[test]
    fn the_byte_before_the_tail_is_never_a_run() {
        let src = [0x60, 0x60, 0x60, 0x60, 0x60];
        let mut plane = [0u8; 5];
        decode_plane(&src, &mut plane).unwrap();
        assert_eq!(plane, [0x60; 5]);
    }

    #[test]
    fn a_plane_whose_byte_count_matches_its_size_is_raw() {
        let src: Vec<u8> = (0..16).collect();
        let mut plane = [0u8; 16];
        decode_plane(&src, &mut plane).unwrap();
        assert_eq!(&plane[..], &src[..]);
    }

    #[test]
    fn a_run_that_overruns_the_plane_is_a_range_error() {
        let src = [0x11, 0x11, 0xFE, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut plane = [0u8; 12];
        assert!(matches!(
            decode_plane(&src, &mut plane),
            Err(DecodeError::Range { .. })
        ));
    }

    #[test]
    fn a_zero_length_run_is_refused_rather_than_looping() {
        let mut src = vec![0x11, 0x11, 0xFF];
        src.extend_from_slice(&0u32.to_le_bytes());
        src.extend_from_slice(&[1, 2, 3, 4]);
        let mut plane = [0u8; 12];
        assert_eq!(
            decode_plane(&src, &mut plane),
            Err(DecodeError::Range {
                what: "nscodec run length",
                got: 0
            })
        );
    }

    #[test]
    fn a_truncated_plane_is_an_error_not_a_panic() {
        let full = [0x41, 0x42, 0x42, 0x03, 0x51, 0x52, 0x53, 0x54];
        for n in 0..full.len() {
            let mut plane = [0u8; 9];
            let _ = decode_plane(&full[..n], &mut plane);
        }
    }

    /// A whole bitmap, no subsampling, no alpha. The reference encoder emits
    /// raw planes and run length encoded planes from the same pixels, so the
    /// two paths are checked against one image.
    #[test]
    fn a_bitmap_round_trips_through_both_plane_forms() {
        let (w, h) = (37usize, 19usize);
        let px: Vec<[u8; 3]> = (0..w * h)
            .map(|i| {
                let x = (i % w) as u8;
                let y = (i / w) as u8;
                [x.wrapping_mul(7), y.wrapping_mul(13), 200 - x]
            })
            .collect();
        for rle in [false, true] {
            let src = encode::nscodec(&px, w, h, 1, false, rle);
            let mut buf = vec![0u8; dst_len(w as u16, h as u16)];
            {
                let mut v = view(&mut buf, w as u16, h as u16);
                let mut scratch = NscScratch::new();
                decode(&src, &mut scratch, &mut v).unwrap();
            }
            for (i, out) in buf.chunks_exact(4).enumerate() {
                for c in 0..3 {
                    assert!(
                        (i32::from(out[c]) - i32::from(px[i][c])).abs() <= 2,
                        "pixel {i} channel {c}: got {out:?} want {:?} (rle {rle})",
                        px[i]
                    );
                }
                assert_eq!(out[3], 0xFF);
            }
        }
    }

    /// The colour loss level shifts Co and Cg back on decode, so a bitmap
    /// encoded at each of the seven levels must come back inside the error
    /// that level allows.
    ///
    /// The bound is arithmetic rather than empirical. The encoder chooses the
    /// luma from the already quantized chroma, so blue and the luma come back
    /// exactly and the whole error is the chroma quantization: red is off by
    /// `co - (co >> cll << cll)` and green by the same expression in `cg`,
    /// both under `2^cll`. That is why the tolerance is a function of the
    /// level rather than a constant, and why a decoder bug shows here as a
    /// failure at every level rather than only at the coarse ones.
    #[test]
    fn every_colour_loss_level_round_trips_inside_its_own_error() {
        let (w, h) = (16usize, 8usize);
        let px: Vec<[u8; 3]> = (0..w * h)
            .map(|i| [(i * 3) as u8, (i * 5) as u8, (i * 7) as u8])
            .collect();
        for cll in 1..=7u8 {
            let src = encode::nscodec(&px, w, h, cll, false, true);
            let mut buf = vec![0u8; dst_len(w as u16, h as u16)];
            {
                let mut v = view(&mut buf, w as u16, h as u16);
                let mut scratch = NscScratch::new();
                decode(&src, &mut scratch, &mut v).unwrap();
            }
            let tol = 1i32 << cll;
            for (i, out) in buf.chunks_exact(4).enumerate() {
                for c in 0..3 {
                    assert!(
                        (i32::from(out[c]) - i32::from(px[i][c])).abs() <= tol,
                        "cll {cll} pixel {i} channel {c}: got {out:?} want {:?}",
                        px[i]
                    );
                }
            }
        }
    }

    /// Chroma subsampling. The encoder point samples the chroma of every
    /// second pixel, so a decoder that replicates 2 by 2 reproduces the
    /// sampled pixels exactly and its neighbours approximately. A luma plane
    /// that is not padded to a multiple of eight shears the picture, so the
    /// width here is deliberately not a multiple of eight.
    #[test]
    fn chroma_subsampling_replicates_two_by_two() {
        let (w, h) = (13usize, 7usize);
        let px: Vec<[u8; 3]> = (0..w * h)
            .map(|i| {
                let x = i % w;
                let y = i / w;
                // Flat 2 by 2 blocks, so subsampling loses nothing.
                let v = ((x / 2) * 20 + (y / 2) * 30) as u8;
                [v, v.wrapping_add(40), v.wrapping_add(80)]
            })
            .collect();
        let src = encode::nscodec(&px, w, h, 1, true, true);
        let mut buf = vec![0u8; dst_len(w as u16, h as u16)];
        {
            let mut v = view(&mut buf, w as u16, h as u16);
            let mut scratch = NscScratch::new();
            decode(&src, &mut scratch, &mut v).unwrap();
        }
        for (i, out) in buf.chunks_exact(4).enumerate() {
            for c in 0..3 {
                assert!(
                    (i32::from(out[c]) - i32::from(px[i][c])).abs() <= 3,
                    "pixel {i} ({}, {}) channel {c}: got {out:?} want {:?}",
                    i % w,
                    i / w,
                    px[i]
                );
            }
        }
    }

    #[test]
    fn an_alpha_plane_is_applied_and_an_absent_one_is_opaque() {
        let (w, h) = (8usize, 4usize);
        let px: Vec<[u8; 3]> = (0..w * h).map(|_| [10, 20, 30]).collect();
        let alpha: Vec<u8> = (0..w * h).map(|i| (i * 8) as u8).collect();
        let src = encode::nscodec_alpha(&px, &alpha, w, h, 1, false, true);
        let mut buf = vec![0u8; dst_len(w as u16, h as u16)];
        {
            let mut v = view(&mut buf, w as u16, h as u16);
            let mut scratch = NscScratch::new();
            decode(&src, &mut scratch, &mut v).unwrap();
        }
        for (i, out) in buf.chunks_exact(4).enumerate() {
            assert_eq!(out[3], alpha[i], "pixel {i}");
        }

        let src = encode::nscodec(&px, w, h, 1, false, true);
        let mut buf = vec![0u8; dst_len(w as u16, h as u16)];
        {
            let mut v = view(&mut buf, w as u16, h as u16);
            let mut scratch = NscScratch::new();
            decode(&src, &mut scratch, &mut v).unwrap();
        }
        assert!(buf.chunks_exact(4).all(|p| p[3] == 0xFF));
    }

    #[test]
    fn the_header_fields_are_range_checked() {
        let (w, h) = (4u16, 4u16);
        let px: Vec<[u8; 3]> = (0..16).map(|_| [1, 2, 3]).collect();
        let mut src = encode::nscodec(&px, 4, 4, 1, false, false);
        let mut buf = vec![0u8; dst_len(w, h)];
        let mut scratch = NscScratch::new();

        src[16] = 0; // ColorLossLevel
        {
            let mut v = view(&mut buf, w, h);
            assert_eq!(
                decode(&src, &mut scratch, &mut v),
                Err(DecodeError::Range {
                    what: "NSCodec ColorLossLevel",
                    got: 0
                })
            );
        }
        src[16] = 8;
        {
            let mut v = view(&mut buf, w, h);
            assert!(decode(&src, &mut scratch, &mut v).is_err());
        }
        src[16] = 1;
        src[17] = 2; // ChromaSubsamplingLevel
        {
            let mut v = view(&mut buf, w, h);
            assert_eq!(
                decode(&src, &mut scratch, &mut v),
                Err(DecodeError::Range {
                    what: "NSCodec ChromaSubsamplingLevel",
                    got: 2
                })
            );
        }
    }

    /// The truncation sweep: every prefix of a valid bitstream returns an
    /// error or succeeds, and never panics.
    #[test]
    fn every_prefix_is_handled() {
        let (w, h) = (12usize, 9usize);
        let px: Vec<[u8; 3]> = (0..w * h).map(|i| [i as u8, 0, 255 - i as u8]).collect();
        let src = encode::nscodec(&px, w, h, 3, true, true);
        let mut buf = vec![0u8; dst_len(w as u16, h as u16)];
        let mut scratch = NscScratch::new();
        for n in 0..src.len() {
            let mut v = view(&mut buf, w as u16, h as u16);
            let _ = decode(&src[..n], &mut scratch, &mut v);
        }
        let mut v = view(&mut buf, w as u16, h as u16);
        assert!(decode(&src, &mut scratch, &mut v).is_ok());
    }

    /// The adversarial sweep over leading bytes. The first four bytes are the
    /// luma plane byte count, so this reaches every combination of "the
    /// header says the plane is longer than the payload" and "the header says
    /// it is raw".
    #[test]
    fn every_leading_byte_terminates() {
        let (w, h) = (8usize, 8usize);
        let px: Vec<[u8; 3]> = (0..w * h).map(|i| [i as u8, 1, 2]).collect();
        let base = encode::nscodec(&px, w, h, 1, false, true);
        let mut buf = vec![0u8; dst_len(w as u16, h as u16)];
        let mut scratch = NscScratch::new();
        for lead in 0u16..=255 {
            let mut src = base.clone();
            src[0] = lead as u8;
            let mut v = view(&mut buf, w as u16, h as u16);
            let _ = decode(&src, &mut scratch, &mut v);
        }
    }

    #[test]
    fn the_scratch_reports_and_releases_its_memory() {
        let mut s = NscScratch::with_capacity(64, 64);
        assert_eq!(s.bytes(), scratch_len(64, 64));
        s.reset();
        assert_eq!(s.bytes(), 0);
    }

    #[test]
    fn a_zero_sized_destination_decodes_to_nothing() {
        let mut buf = [0u8; 0];
        let mut v = DstView::packed(&mut buf, 0, 0, OutFormat::Rgba, RowOrder::TopDown).unwrap();
        let mut scratch = NscScratch::new();
        let src = vec![0u8; HEADER_LEN + 4];
        let mut hdr = src.clone();
        hdr[16] = 1;
        assert!(decode(&hdr, &mut scratch, &mut v).is_ok());
    }
}
