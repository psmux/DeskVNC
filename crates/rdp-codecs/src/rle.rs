//! Interleaved RLE (MS-RDPBCGR 2.2.9.1.1.3.1.2.4 for the bitstream,
//! MS-RDPBCGR 3.1.9 for the decoding rules).
//!
//! A byte oriented run length scheme over the previously decoded scanline,
//! defined for 8, 15, 16 and 24 bits per pixel. There is no 32 bpp form, so a
//! compressed 32 bpp legacy bitmap is planar ([`crate::planar`]) or the update
//! is malformed (PRDRDP/04 §2.4, §2.5).
//!
//! ## Why the destination here is wire pixels and not RGBA
//!
//! Every order except the colour orders reads the pixel one scanline above the
//! one it is writing. So the decoder needs its own previous row in **wire
//! format**, and the destination it writes is a scratch of `w * h *
//! bytes_per_pixel` in **wire row order**. Converting in place would be
//! strictly worse: the previous row lookups would read RGBA and have to
//! convert back (PRDRDP/04 §2.4).
//!
//! That gives one write of the wire pixels plus one conversion write per
//! pixel, which is the minimum for a codec that predicts from its previous
//! row, and it keeps the D9 zero copy invariant: the conversion write is the
//! single copy into the destination. The caller pools the scratch
//! ([`crate::uncompressed::packed_len`] sizes it) and finishes with
//! [`crate::uncompressed::decode`], which is PRDRDP/04 §4.2's `convert_image`
//! and which owns the bottom up flip.
//!
//! The scratch takes no stride argument, unlike the RGBA destination. A stride
//! would buy nothing (the caller sizes the scratch, so it is always tight), it
//! would cost a multiply per row, and it would break the invariant that makes
//! the run splitting cheap: the pixel one row above index `p` is at `p - w`,
//! full stop, including across a row boundary.
//!
//! ## Generic over the pixel width, written once
//!
//! One decoder monomorphised into `u8`, `u16` and [`Rgb24`]. Writing it three
//! times is how an implementation ends up with three subtly different bugs
//! (PRDRDP/04 §4.4.4). `Rgb24` is a `u32` with the top byte masked off, so the
//! whole decoder works in registers and only the store knows about three byte
//! packing, which keeps the previous row lookup a single load.

use core::marker::PhantomData;

use crate::{DecodeError, Reader};

// Order codes, after ExtractCodeId (MS-RDPBCGR 3.1.9).
const REGULAR_BG_RUN: u8 = 0x0;
const REGULAR_FG_RUN: u8 = 0x1;
const REGULAR_FGBG_IMAGE: u8 = 0x2;
const REGULAR_COLOR_RUN: u8 = 0x3;
const REGULAR_COLOR_IMAGE: u8 = 0x4;
const LITE_SET_FG_FG_RUN: u8 = 0xC;
const LITE_SET_FG_FGBG_IMAGE: u8 = 0xD;
const LITE_DITHERED_RUN: u8 = 0xE;
const MEGA_MEGA_BG_RUN: u8 = 0xF0;
const MEGA_MEGA_FG_RUN: u8 = 0xF1;
const MEGA_MEGA_FGBG_IMAGE: u8 = 0xF2;
const MEGA_MEGA_COLOR_RUN: u8 = 0xF3;
const MEGA_MEGA_COLOR_IMAGE: u8 = 0xF4;
const MEGA_MEGA_SET_FG_RUN: u8 = 0xF6;
const MEGA_MEGA_SET_FGBG_IMAGE: u8 = 0xF7;
const MEGA_MEGA_DITHERED_RUN: u8 = 0xF8;
const SPECIAL_FGBG_1: u8 = 0xF9;
const SPECIAL_FGBG_2: u8 = 0xFA;
const WHITE: u8 = 0xFD;
const BLACK: u8 = 0xFE;

/// The mask `SPECIAL_FGBG_1` stands in for: an FGBG image of eight pixels.
const SPECIAL_MASK_1: u8 = 0x03;
/// The mask `SPECIAL_FGBG_2` stands in for.
const SPECIAL_MASK_2: u8 = 0x05;

/// One wire pixel, in registers.
trait Px: Copy + Eq {
    const BYTES: usize;
    const BLACK: Self;
    const WHITE: Self;

    /// `src.len() >= Self::BYTES`, which every call site proves by taking the
    /// slice from `chunks_exact` or from [`Reader::take`].
    fn read_le(src: &[u8]) -> Self;
    fn write_le(self, dst: &mut [u8]);
    fn xor(self, other: Self) -> Self;

    /// Fill `dst` with copies of `px`. `dst.len()` is a multiple of `BYTES`.
    ///
    /// Overridden at 8 bpp, where the whole thing is `slice::fill` and lowers
    /// to a `memset`.
    fn fill_slice(dst: &mut [u8], px: Self) {
        for d in dst.chunks_exact_mut(Self::BYTES) {
            px.write_le(d);
        }
    }

    /// `dst[i] = src[i] ^ px`, pixel by pixel over two equal length slices.
    fn xor_slice(src: &[u8], dst: &mut [u8], px: Self) {
        for (s, d) in src
            .chunks_exact(Self::BYTES)
            .zip(dst.chunks_exact_mut(Self::BYTES))
        {
            Self::read_le(s).xor(px).write_le(d);
        }
    }
}

impl Px for u8 {
    const BYTES: usize = 1;
    const BLACK: Self = 0x00;
    const WHITE: Self = 0xFF;

    fn read_le(src: &[u8]) -> Self {
        src[0]
    }
    fn write_le(self, dst: &mut [u8]) {
        dst[0] = self;
    }
    fn xor(self, other: Self) -> Self {
        self ^ other
    }
    fn fill_slice(dst: &mut [u8], px: Self) {
        dst.fill(px);
    }
    fn xor_slice(src: &[u8], dst: &mut [u8], px: Self) {
        // Byte for byte, so this is the loop the autovectoriser likes best:
        // two slices of proved equal length, no indexing, no early exit
        // (PRDRDP/04 §4.6.8 rule two).
        for (s, d) in src.iter().zip(dst.iter_mut()) {
            *d = *s ^ px;
        }
    }
}

impl Px for u16 {
    const BYTES: usize = 2;
    const BLACK: Self = 0x0000;
    /// At 15 bpp the pixel is still sixteen bits wide on the wire with the top
    /// bit unused, so all ones is 0xFFFF and the spare bit is discarded by
    /// [`crate::PixelFormat::Rgb555`] on conversion (PRDRDP/04 §4.4.3).
    const WHITE: Self = 0xFFFF;

    fn read_le(src: &[u8]) -> Self {
        u16::from_le_bytes([src[0], src[1]])
    }
    fn write_le(self, dst: &mut [u8]) {
        dst[..2].copy_from_slice(&self.to_le_bytes());
    }
    fn xor(self, other: Self) -> Self {
        self ^ other
    }
}

/// A 24 bpp pixel held as a `u32` with the top byte masked off.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rgb24(u32);

impl Px for Rgb24 {
    const BYTES: usize = 3;
    const BLACK: Self = Rgb24(0x0000_0000);
    const WHITE: Self = Rgb24(0x00FF_FFFF);

    fn read_le(src: &[u8]) -> Self {
        Rgb24(u32::from(src[0]) | u32::from(src[1]) << 8 | u32::from(src[2]) << 16)
    }
    fn write_le(self, dst: &mut [u8]) {
        dst[0] = self.0 as u8;
        dst[1] = (self.0 >> 8) as u8;
        dst[2] = (self.0 >> 16) as u8;
    }
    fn xor(self, other: Self) -> Self {
        Rgb24(self.0 ^ other.0)
    }
}

/// The wire format scratch, plus the cursor and the first scanline flag.
struct Out<'a, P: Px> {
    dst: &'a mut [u8],
    w: usize,
    total: usize,
    p: usize,
    /// True until an order starts at or past the end of the first scanline.
    /// MS-RDPBCGR 3.1.9 checks and clears this once per order, not once per
    /// pixel, so an order that begins on row zero treats its whole length as
    /// first line even when it runs into row one. Windows encoders rely on
    /// that, so the check stays where the specification puts it.
    first_line: bool,
    _px: PhantomData<P>,
}

impl<'a, P: Px> Out<'a, P> {
    fn new(dst: &'a mut [u8], w: usize, total: usize) -> Self {
        Out {
            dst,
            w,
            total,
            p: 0,
            first_line: true,
            _px: PhantomData,
        }
    }

    fn room(&self, n: usize) -> Result<(), DecodeError> {
        if n > self.total - self.p {
            return Err(DecodeError::Range {
                what: "interleaved rle run",
                got: n as u32,
            });
        }
        Ok(())
    }

    /// Walk `n` output pixels in chunks that never overlap the previous row.
    ///
    /// The callback gets the previous row's bytes for the chunk (`None` on the
    /// first scanline, where the previous row is black by definition), the
    /// chunk's destination bytes, and how many pixels of the run came before
    /// it. Both slices have a length proved here, once per chunk, so the
    /// callback's loop carries no bounds check (PRDRDP/04 §4.6.8 rule two).
    ///
    /// The chunking is what makes a run longer than one scanline correct: the
    /// destination range then overlaps the source range, `dst[i] = dst[i - w]`
    /// has to be evaluated in order, and a single `copy_from_slice` would give
    /// the wrong answer. Capping each chunk at `w` makes the two ranges
    /// disjoint, so each chunk is a straight memcpy and a run of several rows
    /// replicates the way it should.
    fn chunked<F>(&mut self, n: usize, mut f: F) -> Result<(), DecodeError>
    where
        F: FnMut(Option<&[u8]>, &mut [u8], usize),
    {
        self.room(n)?;
        let (w, bpp, first_line) = (self.w, P::BYTES, self.first_line);
        let mut done = 0;
        while done < n {
            let chunk = if first_line {
                n - done
            } else {
                (n - done).min(w)
            };
            let at = self.p * bpp;
            let (above, here) = self.dst.split_at_mut(at);
            // `first_line` is cleared only once `p >= w`, so `at >= w * bpp`
            // whenever this branch is taken, and `chunk <= w` keeps the source
            // range inside `above`.
            let prev = if first_line {
                None
            } else {
                Some(&above[at - w * bpp..][..chunk * bpp])
            };
            f(prev, &mut here[..chunk * bpp], done);
            self.p += chunk;
            done += chunk;
        }
        Ok(())
    }

    /// Background run: copy `n` pixels from the previous row, or black on the
    /// first scanline.
    fn copy_prev(&mut self, n: usize) -> Result<(), DecodeError> {
        self.chunked(n, |prev, dst, _| match prev {
            Some(p) => dst.copy_from_slice(p),
            None => P::fill_slice(dst, P::BLACK),
        })
    }

    /// Foreground run: `n` pixels of `previous ^ fg`, or `fg` on the first
    /// scanline (black XOR fg is fg, so the two arms agree).
    fn xor_prev(&mut self, n: usize, fg: P) -> Result<(), DecodeError> {
        self.chunked(n, |prev, dst, _| match prev {
            Some(p) => P::xor_slice(p, dst, fg),
            None => P::fill_slice(dst, fg),
        })
    }

    /// FGBG image: `n` pixels driven by a bitmask, LSB first within each byte.
    /// A set bit writes `previous ^ fg` and a clear bit writes `previous`.
    fn fgbg(&mut self, n: usize, fg: P, mask: &[u8]) -> Result<(), DecodeError> {
        let bpp = P::BYTES;
        self.chunked(n, |prev, dst, done| {
            for (i, d) in dst.chunks_exact_mut(bpp).enumerate() {
                let bit = done + i;
                // Branch free: XOR with black leaves the previous pixel alone,
                // so the mask bit selects the operand rather than the branch.
                let sel = if mask[bit / 8] & (1 << (bit % 8)) != 0 {
                    fg
                } else {
                    P::BLACK
                };
                match prev {
                    Some(p) => P::read_le(&p[i * bpp..]).xor(sel).write_le(d),
                    None => sel.write_le(d),
                }
            }
        })
    }

    /// Colour run, and the one pixel WHITE and BLACK orders.
    fn fill(&mut self, n: usize, px: P) -> Result<(), DecodeError> {
        self.room(n)?;
        let at = self.p * P::BYTES;
        P::fill_slice(&mut self.dst[at..at + n * P::BYTES], px);
        self.p += n;
        Ok(())
    }

    /// Dithered run: the pair (a, b) written `n` times, so `2n` pixels.
    fn fill_pair(&mut self, n: usize, a: P, b: P) -> Result<(), DecodeError> {
        let pixels = n * 2;
        self.room(pixels)?;
        let bpp = P::BYTES;
        let at = self.p * bpp;
        for pair in self.dst[at..at + pixels * bpp].chunks_exact_mut(2 * bpp) {
            a.write_le(&mut pair[..bpp]);
            b.write_le(&mut pair[bpp..]);
        }
        self.p += pixels;
        Ok(())
    }

    /// Colour image: `n` raw wire pixels, which are already in the scratch's
    /// format, so this is a memcpy and not a conversion.
    fn copy_raw(&mut self, n: usize, src: &[u8]) -> Result<(), DecodeError> {
        self.room(n)?;
        let at = self.p * P::BYTES;
        self.dst[at..at + n * P::BYTES].copy_from_slice(src);
        self.p += n;
        Ok(())
    }
}

/// The three way header test of MS-RDPBCGR 3.1.9 `ExtractCodeId`.
fn extract_code_id(hdr: u8) -> u8 {
    if hdr & 0xC0 != 0xC0 {
        hdr >> 5 // regular form, three bits
    } else if hdr & 0xF0 == 0xF0 {
        hdr // mega mega form, the whole byte
    } else {
        hdr >> 4 // lite form, four bits
    }
}

/// Run length extraction, MS-RDPBCGR 3.1.9.
///
/// The escape rules differ per order class and this is where most
/// implementation bugs live. The `* 8` on the FGBG image forms is the trap:
/// the length there counts **mask bytes multiplied out into pixels**, so a
/// value of three means twenty four pixels and three mask bytes, while the
/// escape form counts pixels directly and needs `ceil(n / 8)` mask bytes.
fn run_length(code: u8, hdr: u8, r: &mut Reader<'_>) -> Result<usize, DecodeError> {
    let n = match code {
        REGULAR_FGBG_IMAGE => {
            let n = usize::from(hdr & 0x1F);
            if n == 0 {
                usize::from(r.u8()?) + 1
            } else {
                n * 8
            }
        }
        LITE_SET_FG_FGBG_IMAGE => {
            let n = usize::from(hdr & 0x0F);
            if n == 0 {
                usize::from(r.u8()?) + 1
            } else {
                n * 8
            }
        }
        REGULAR_BG_RUN | REGULAR_FG_RUN | REGULAR_COLOR_RUN | REGULAR_COLOR_IMAGE => {
            let n = usize::from(hdr & 0x1F);
            if n == 0 {
                usize::from(r.u8()?) + 32
            } else {
                n
            }
        }
        LITE_SET_FG_FG_RUN | LITE_DITHERED_RUN => {
            let n = usize::from(hdr & 0x0F);
            if n == 0 {
                usize::from(r.u8()?) + 16
            } else {
                n
            }
        }
        MEGA_MEGA_BG_RUN..=MEGA_MEGA_DITHERED_RUN => usize::from(r.u16_le()?),
        other => {
            return Err(DecodeError::Range {
                what: "interleaved rle order",
                got: u32::from(other),
            })
        }
    };
    Ok(n)
}

fn read_px<P: Px>(r: &mut Reader<'_>) -> Result<P, DecodeError> {
    Ok(P::read_le(r.take(P::BYTES)?))
}

fn decode_px<P: Px>(src: &[u8], dst: &mut [u8], w: usize, h: usize) -> Result<(), DecodeError> {
    let total = w * h;
    let need = total * P::BYTES;
    if dst.len() < need {
        return Err(DecodeError::Dst {
            need,
            have: dst.len(),
        });
    }
    // Slice once, to a length proved here, so every write below indexes a
    // buffer that cannot be short (PRDRDP/04 §4.6.8 rule two).
    let dst = &mut dst[..need];
    if total == 0 {
        return Ok(());
    }

    let mut r = Reader::new(src, "interleaved rle");
    let mut out = Out::<P>::new(dst, w, total);
    // MS-RDPBCGR 3.1.9 initialises the foreground pixel to all ones.
    let mut fg = P::WHITE;
    let mut insert_fg = false;

    while out.p < total {
        // "Watch out for the end of the first scanline", MS-RDPBCGR 3.1.9.
        // Clearing insert_fg here as well is part of that rule.
        if out.first_line && out.p >= w {
            out.first_line = false;
            insert_fg = false;
        }

        let hdr = r.u8()?;
        let code = extract_code_id(hdr);

        match code {
            REGULAR_BG_RUN | MEGA_MEGA_BG_RUN => {
                let mut n = run_length(code, hdr, &mut r)?;
                if insert_fg {
                    // The first pixel of the run carries the foreground
                    // instead. Two consecutive background runs are therefore
                    // not the same as one longer one, which is precisely the
                    // case a hand written fixture forgets.
                    out.xor_prev(1, fg)?;
                    n = n.saturating_sub(1);
                }
                out.copy_prev(n)?;
                insert_fg = true;
                continue;
            }
            REGULAR_FG_RUN | MEGA_MEGA_FG_RUN => {
                let n = run_length(code, hdr, &mut r)?;
                out.xor_prev(n, fg)?;
            }
            LITE_SET_FG_FG_RUN | MEGA_MEGA_SET_FG_RUN => {
                // The length comes first and the new foreground after it,
                // which is the order MS-RDPBCGR 3.1.9's pseudo code reads them
                // in: ExtractRunLength advances the cursor before the body
                // reads its pixel.
                let n = run_length(code, hdr, &mut r)?;
                fg = read_px::<P>(&mut r)?;
                out.xor_prev(n, fg)?;
            }
            REGULAR_FGBG_IMAGE | MEGA_MEGA_FGBG_IMAGE => {
                let n = run_length(code, hdr, &mut r)?;
                let mask = r.take(n.div_ceil(8))?;
                out.fgbg(n, fg, mask)?;
            }
            LITE_SET_FG_FGBG_IMAGE | MEGA_MEGA_SET_FGBG_IMAGE => {
                let n = run_length(code, hdr, &mut r)?;
                fg = read_px::<P>(&mut r)?;
                let mask = r.take(n.div_ceil(8))?;
                out.fgbg(n, fg, mask)?;
            }
            REGULAR_COLOR_RUN | MEGA_MEGA_COLOR_RUN => {
                let n = run_length(code, hdr, &mut r)?;
                let px = read_px::<P>(&mut r)?;
                out.fill(n, px)?;
            }
            REGULAR_COLOR_IMAGE | MEGA_MEGA_COLOR_IMAGE => {
                let n = run_length(code, hdr, &mut r)?;
                // Bound the take against the output before asking the reader
                // for it, so a mega length of 65535 on a small bitmap is a
                // Range error rather than a 192 KB read.
                out.room(n)?;
                let raw = r.take(n * P::BYTES)?;
                out.copy_raw(n, raw)?;
            }
            LITE_DITHERED_RUN | MEGA_MEGA_DITHERED_RUN => {
                let n = run_length(code, hdr, &mut r)?;
                let a = read_px::<P>(&mut r)?;
                let b = read_px::<P>(&mut r)?;
                // The pair is written n times, so 2n pixels. Forgetting the
                // doubling produces a picture that is half width and obviously
                // wrong, which is the good kind of bug.
                out.fill_pair(n, a, b)?;
            }
            SPECIAL_FGBG_1 => out.fgbg(8, fg, &[SPECIAL_MASK_1])?,
            SPECIAL_FGBG_2 => out.fgbg(8, fg, &[SPECIAL_MASK_2])?,
            WHITE => out.fill(1, P::WHITE)?,
            BLACK => out.fill(1, P::BLACK)?,
            other => {
                return Err(DecodeError::Range {
                    what: "interleaved rle order",
                    got: u32::from(other),
                })
            }
        }
        insert_fg = false;
    }
    Ok(())
}

/// Bytes of scratch a decode of this geometry needs.
pub fn scratch_len(bits_per_pixel: u8, width: u16, height: u16) -> Result<usize, DecodeError> {
    let bpp = match bits_per_pixel {
        8 => 1,
        15 | 16 => 2,
        24 => 3,
        other => {
            return Err(DecodeError::Range {
                what: "interleaved rle bitsPerPixel",
                got: u32::from(other),
            })
        }
    };
    Ok(usize::from(width) * usize::from(height) * bpp)
}

/// Decode an interleaved RLE bitmap into a wire format scratch.
///
/// `dst` holds `width * height` pixels of `bits_per_pixel` in **wire row
/// order**, tightly packed; [`scratch_len`] sizes it. The caller converts it
/// into the real destination with [`crate::uncompressed::decode`], which is
/// where the bottom up flip of PRDRDP/04 §2.3 happens.
///
/// 15 and 16 bits per pixel decode identically here, because at this layer a
/// pixel is two opaque little endian bytes; the difference is a conversion
/// concern.
///
/// Returns [`DecodeError::Truncated`] if the stream ends before the bitmap is
/// full and [`DecodeError::Range`] if an order would run past its end. It
/// cannot panic and it cannot loop without consuming input, because every
/// iteration reads at least the one header byte.
pub fn decode_bpp(
    bits_per_pixel: u8,
    src: &[u8],
    dst: &mut [u8],
    width: u16,
    height: u16,
) -> Result<(), DecodeError> {
    let (w, h) = (usize::from(width), usize::from(height));
    match bits_per_pixel {
        8 => decode_px::<u8>(src, dst, w, h),
        15 | 16 => decode_px::<u16>(src, dst, w, h),
        24 => decode_px::<Rgb24>(src, dst, w, h),
        other => Err(DecodeError::Range {
            what: "interleaved rle bitsPerPixel",
            got: u32::from(other),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_extraction_covers_all_three_forms() {
        assert_eq!(extract_code_id(0x00), REGULAR_BG_RUN);
        assert_eq!(extract_code_id(0x1F), REGULAR_BG_RUN);
        assert_eq!(extract_code_id(0x20), REGULAR_FG_RUN);
        assert_eq!(extract_code_id(0x8F), REGULAR_COLOR_IMAGE);
        assert_eq!(extract_code_id(0xC5), LITE_SET_FG_FG_RUN);
        assert_eq!(extract_code_id(0xE0), LITE_DITHERED_RUN);
        assert_eq!(extract_code_id(0xF0), MEGA_MEGA_BG_RUN);
        assert_eq!(extract_code_id(0xFD), WHITE);
        assert_eq!(extract_code_id(0xFE), BLACK);
    }

    /// Hand assembled, 8 bpp, 4 wide by 3 high. The working, order by order:
    ///
    /// * `0x83` is `0b100_00011`: regular form, code 4 (COLOR_IMAGE), length
    ///   3. Three raw pixels 0x11 0x22 0x33 into row 0.
    /// * `0x61` is `0b011_00001`: regular form, code 3 (COLOR_RUN), length 1,
    ///   pixel 0x44. Row 0 is now 11 22 33 44 and the cursor is at row 1.
    /// * `0x04` is `0b000_00100`: regular form, code 0 (BG_RUN), length 4.
    ///   insert_fg is clear, so four pixels copied from row 0. Row 1 is
    ///   11 22 33 44.
    /// * `0x24` is `0b001_00100`: regular form, code 1 (FG_RUN), length 4, and
    ///   fg is still the initial all ones 0xFF. Row 2 is row 1 XOR 0xFF, so
    ///   EE DD CC BB.
    #[test]
    fn hand_assembled_8bpp_vector() {
        let src = [0x83, 0x11, 0x22, 0x33, 0x61, 0x44, 0x04, 0x24];
        let mut dst = [0u8; 12];
        decode_bpp(8, &src, &mut dst, 4, 3).unwrap();
        assert_eq!(&dst[0..4], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&dst[4..8], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&dst[8..12], &[0xEE, 0xDD, 0xCC, 0xBB]);
    }

    /// The insert_fg rule of MS-RDPBCGR 3.1.9, and its scanline reset.
    ///
    /// A 2 by 2 bitmap at 8 bpp:
    ///
    /// * `0x81 0xAA` is COLOR_IMAGE of one pixel. Row 0 pixel 0 is AA, the
    ///   cursor is at pixel 1, still on the first scanline.
    /// * `0x01` is BG_RUN of one. The first scanline has no row above it, so
    ///   black is written. insert_fg becomes true and the cursor reaches the
    ///   end of row 0.
    /// * The next order's first act is the "watch out for the end of the first
    ///   scanline" check, which clears both the first line flag **and**
    ///   insert_fg. So this `0x01` BG_RUN of one is an ordinary copy from the
    ///   row above: row 0 pixel 0, which is AA. insert_fg becomes true again.
    /// * The last `0x01` BG_RUN of one now does insert: the pixel is
    ///   `row0[1] ^ fg`, and fg is still the initial all ones, so `00 ^ FF` is
    ///   FF. That consumes one of the run's pixels and leaves none.
    ///
    /// Two consecutive background runs are therefore not the same as one
    /// longer one, which is precisely the case a hand written fixture forgets.
    #[test]
    fn consecutive_background_runs_insert_the_foreground_pixel() {
        let src = [0x81, 0xAA, 0x01, 0x01, 0x01];
        let mut dst = [0u8; 4];
        decode_bpp(8, &src, &mut dst, 2, 2).unwrap();
        assert_eq!(dst, [0xAA, 0x00, 0xAA, 0xFF]);
    }

    /// Dithered runs write the pair `n` times, so `2n` pixels
    /// (MS-RDPBCGR 3.1.9). `0xE2` is the lite form, code 0xE, length 2.
    #[test]
    fn dithered_run_writes_two_pixels_per_unit_of_length() {
        let src = [0xE2, 0x11, 0x22];
        let mut dst = [0u8; 4];
        decode_bpp(8, &src, &mut dst, 4, 1).unwrap();
        assert_eq!(dst, [0x11, 0x22, 0x11, 0x22]);
    }

    /// `SPECIAL_FGBG_1` is an FGBG image of eight pixels with mask 0x03, LSB
    /// first, so the low two pixels take the foreground and the rest the
    /// background. On the first scanline the background is black, so the
    /// result is FF FF 00 00 00 00 00 00 with the initial all ones foreground.
    #[test]
    fn special_fgbg_orders_expand_to_their_fixed_masks() {
        let mut dst = [0u8; 8];
        decode_bpp(8, &[SPECIAL_FGBG_1], &mut dst, 8, 1).unwrap();
        assert_eq!(dst, [0xFF, 0xFF, 0, 0, 0, 0, 0, 0]);

        let mut dst = [0u8; 8];
        decode_bpp(8, &[SPECIAL_FGBG_2], &mut dst, 8, 1).unwrap();
        assert_eq!(dst, [0xFF, 0, 0xFF, 0, 0, 0, 0, 0]);
    }

    /// The FGBG length trap: a non zero nibble counts mask bytes multiplied
    /// out into pixels. `0x41` is the regular form, code 2, length nibble 1,
    /// so eight pixels and one mask byte.
    #[test]
    fn fgbg_length_nibble_counts_mask_bytes_times_eight() {
        let src = [0x41, 0b0000_1111];
        let mut dst = [0u8; 8];
        decode_bpp(8, &src, &mut dst, 8, 1).unwrap();
        assert_eq!(dst, [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);

        // The escape form counts pixels: length nibble 0, then a byte of
        // (pixels - 1). Three pixels, one mask byte.
        let src = [0x40, 0x02, 0b0000_0101];
        let mut dst = [0u8; 3];
        decode_bpp(8, &src, &mut dst, 3, 1).unwrap();
        assert_eq!(dst, [0xFF, 0x00, 0xFF]);
    }

    /// A background run longer than one scanline replicates the row above it,
    /// which only comes out right if the copy is evaluated in order. This is
    /// the case a single `copy_from_slice` gets wrong.
    #[test]
    fn a_run_spanning_rows_replicates_the_previous_row() {
        // Row 0: four raw pixels. Then a background run of eight, which fills
        // rows 1 and 2 by replicating row 0 and then row 1.
        let src = [0x84, 0x01, 0x02, 0x03, 0x04, 0x08];
        let mut dst = [0u8; 12];
        decode_bpp(8, &src, &mut dst, 4, 3).unwrap();
        assert_eq!(&dst[0..4], &[1, 2, 3, 4]);
        assert_eq!(&dst[4..8], &[1, 2, 3, 4]);
        assert_eq!(&dst[8..12], &[1, 2, 3, 4]);
    }

    #[test]
    fn sixteen_bit_pixels_are_little_endian_on_the_wire() {
        // COLOR_RUN of two pixels 0xBEEF, then a foreground run of two with
        // the initial 0xFFFF foreground over the row above.
        let src = [0x62, 0xEF, 0xBE, 0x22];
        let mut dst = [0u8; 8];
        decode_bpp(16, &src, &mut dst, 2, 2).unwrap();
        assert_eq!(&dst[0..4], &[0xEF, 0xBE, 0xEF, 0xBE]);
        assert_eq!(&dst[4..8], &[0x10, 0x41, 0x10, 0x41]);
    }

    #[test]
    fn twenty_four_bit_pixels_keep_three_byte_packing() {
        let src = [0x62, 0x11, 0x22, 0x33, 0x22];
        let mut dst = [0u8; 12];
        decode_bpp(24, &src, &mut dst, 2, 2).unwrap();
        assert_eq!(&dst[0..6], &[0x11, 0x22, 0x33, 0x11, 0x22, 0x33]);
        assert_eq!(&dst[6..12], &[0xEE, 0xDD, 0xCC, 0xEE, 0xDD, 0xCC]);
    }

    #[test]
    fn white_and_black_orders_write_one_pixel_each() {
        let mut dst = [0u8; 4];
        decode_bpp(16, &[WHITE, BLACK], &mut dst, 2, 1).unwrap();
        assert_eq!(dst, [0xFF, 0xFF, 0x00, 0x00]);
    }

    #[test]
    fn a_run_past_the_end_of_the_bitmap_is_a_range_error() {
        // COLOR_RUN of 32 pixels into a bitmap of 4.
        let src = [0x60, 0x00, 0x77];
        let mut dst = [0u8; 4];
        assert!(matches!(
            decode_bpp(8, &src, &mut dst, 4, 1),
            Err(DecodeError::Range { .. })
        ));
    }

    #[test]
    fn an_undefined_order_is_a_range_error() {
        // 0xA0 is the regular form with code 5, which no order uses.
        let mut dst = [0u8; 4];
        assert!(matches!(
            decode_bpp(8, &[0xA0], &mut dst, 4, 1),
            Err(DecodeError::Range { .. })
        ));
        // 0xFF is in the mega range and is not an order either.
        assert!(matches!(
            decode_bpp(8, &[0xFF], &mut dst, 4, 1),
            Err(DecodeError::Range { .. })
        ));
    }

    #[test]
    fn a_short_destination_is_an_error_not_a_panic() {
        let mut dst = [0u8; 3];
        assert!(matches!(
            decode_bpp(8, &[0x84, 1, 2, 3, 4], &mut dst, 4, 1),
            Err(DecodeError::Dst { .. })
        ));
    }

    #[test]
    fn unsupported_depths_are_rejected() {
        let mut dst = [0u8; 16];
        assert!(decode_bpp(32, &[], &mut dst, 2, 2).is_err());
        assert!(decode_bpp(4, &[], &mut dst, 2, 2).is_err());
        assert!(scratch_len(32, 2, 2).is_err());
        assert_eq!(scratch_len(24, 2, 2).unwrap(), 12);
    }

    /// Every prefix of a valid stream must return an error rather than
    /// panicking or looping (PRDRDP/04 §4.1 rule five).
    #[test]
    fn truncation_returns_err_and_never_panics() {
        // A stream that exercises every order class with a length field.
        let valid: Vec<u8> = vec![
            0x84,
            0x01,
            0x02,
            0x03,
            0x04, // colour image, 4 raw
            0x60,
            0x00,
            0x09, // colour run, escape length 32
            0xC2,
            0x5A, // lite set fg fg run, 2 pixels, fg 0x5A
            0x41,
            0b1010_1010, // fgbg image, 8 pixels, 1 mask byte
            0xE1,
            0x07,
            0x08, // dithered run, 2 pixels
            0xF3,
            0x08,
            0x00,
            0x0B, // mega colour run, 8 pixels
            0x0A, // bg run, 10
            WHITE,
            BLACK, // 2 pixels
            0x60,
            0x00,
            0x0C, // colour run, 32
        ];
        // 4 + 32 + 2 + 8 + 2 + 8 + 10 + 1 + 1 + 32 is 100, so the stream
        // describes the bitmap exactly and every prefix falls short of it.
        let (w, h) = (10u16, 10u16);
        let mut dst = vec![0u8; usize::from(w) * usize::from(h)];
        assert!(
            decode_bpp(8, &valid, &mut dst, w, h).is_ok(),
            "fixture must decode"
        );
        for k in 0..valid.len() {
            let r = decode_bpp(8, &valid[..k], &mut dst, w, h);
            assert!(r.is_err(), "prefix of {k} bytes decoded a whole bitmap");
        }
    }

    /// Adversarial input: the decoder must terminate on anything, including
    /// streams built to make an order claim a huge length.
    #[test]
    fn adversarial_streams_terminate() {
        let mut dst = vec![0u8; 64 * 64];
        for b in 0u8..=255 {
            for tail in [
                vec![b],
                vec![b, 0xFF],
                vec![b, 0xFF, 0xFF],
                vec![b, 0xFF, 0xFF, 0xFF, 0xFF],
                vec![b, 0x00, 0x00, 0x00, 0x00],
                vec![b, b, b, b, b, b, b, b],
            ] {
                let _ = decode_bpp(8, &tail, &mut dst, 64, 64);
                let _ = decode_bpp(16, &tail, &mut dst, 32, 32);
                let _ = decode_bpp(24, &tail, &mut dst, 16, 16);
            }
        }
    }
}
