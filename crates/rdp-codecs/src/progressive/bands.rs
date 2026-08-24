//! The two progressive subband layouts, the LL3 differential decode and the
//! progressive inverse quantization (MS-RDPEGFX 2.2.4.2.1.4 for the
//! `RFX_DWT_REDUCE_EXTRAPOLATE` flag, 2.2.4.2.1.5.1 for
//! `RFX_COMPONENT_CODEC_QUANT`, 3.3.7 for the order the stages run in).
//!
//! ## Why there are two layouts and not one
//!
//! `RFX_PROGRESSIVE_CONTEXT.flags` carries `RFX_DWT_REDUCE_EXTRAPOLATE`. With
//! it clear the wavelet is the one [`crate::remotefx`] already implements and
//! the ten subbands are the ten [`crate::remotefx::quant::BANDS`] names, at
//! the same offsets and with the same quantization nibble indices. With it
//! set the transform extrapolates one extra sample per axis before the
//! forward wavelet and then discards the final high pass coefficient, which
//! makes the low and high halves 33 and 31 rather than 32 and 32, and every
//! subband a different size. Windows sets it, so [`Layout::Extrapolate`] is
//! the one that matters in practice.
//!
//! ## The extrapolate table proves itself
//!
//! Every number in [`EXTRAPOLATE`] is forced, which is what makes a
//! transcription of it checkable without a vector. One axis of length `n`
//! splits into `nl = n / 2 + 1` low and `nh = n / 2 - 1` high at level 1, and
//! into `ceil(n / 2)` and `floor(n / 2)` at the two odd length levels below
//! it. So:
//!
//! ```text
//! level 1: 64 -> 33 low, 31 high     HL1 31x33, LH1 33x31, HH1 31x31, LL1 33x33
//! level 2: 33 -> 17 low, 16 high     HL2 16x17, LH2 17x16, HH2 16x16, LL2 17x17
//! level 3: 17 ->  9 low,  8 high     HL3  8x9,  LH3  9x8,  HH3  8x8,  LL3  9x9
//! ```
//!
//! `1023 + 1023 + 961 + 1089 = 4096`, `272 + 272 + 256 + 289 = 1089` and
//! `72 + 72 + 64 + 81 = 289`. Three sums with no slack in any of them, and
//! the offsets follow from the sizes, so a single wrong entry breaks the
//! total. [`tests::the_extrapolate_bands_tile_the_buffer_exactly_once`] is
//! that arithmetic as a test.
//!
//! HL is the band that is high pass **horizontally** and low pass vertically,
//! which is why it is `nh` wide and `nl` tall. That reading is not a guess:
//! it is the one [`crate::remotefx::dwt`] already implements, where the
//! horizontal pass pairs LL with HL.

use crate::remotefx::quant::COEFS;
use crate::DecodeError;

/// One subband: where it starts in the flat 4096 coefficient buffer, its
/// dimensions, and which nibble of a `RFX_COMPONENT_CODEC_QUANT` scales it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Band {
    /// First coefficient, as an index into the 4096 long buffer.
    pub off: usize,
    /// Width in coefficients.
    pub w: usize,
    /// Height in coefficients.
    pub h: usize,
    /// Nibble index inside the quantization value, in the LL3, LH3, HL3, HH3,
    /// LH2, HL2, HH2, LH1, HL1, HH1 order of MS-RDPEGFX 2.2.4.2.1.5.1.
    pub q: usize,
}

impl Band {
    /// Coefficients in this band.
    ///
    /// Named `count` rather than `len` because a `len` without an `is_empty`
    /// is a clippy lint and a band is never empty.
    pub const fn count(&self) -> usize {
        self.w * self.h
    }
}

/// The plain layout, identical to [`crate::remotefx::quant::BANDS`].
///
/// It is written out rather than derived from that table because the shape
/// here carries a width and a height and that one carries a count, and
/// [`tests::the_plain_layout_is_the_remotefx_one`] pins the two together so
/// they cannot drift.
pub const PLAIN: [Band; 10] = [
    band(0, 32, 32, 8),    // HL1
    band(1024, 32, 32, 7), // LH1
    band(2048, 32, 32, 9), // HH1
    band(3072, 16, 16, 5), // HL2
    band(3328, 16, 16, 4), // LH2
    band(3584, 16, 16, 6), // HH2
    band(3840, 8, 8, 2),   // HL3
    band(3904, 8, 8, 1),   // LH3
    band(3968, 8, 8, 3),   // HH3
    band(4032, 8, 8, 0),   // LL3
];

/// The `RFX_DWT_REDUCE_EXTRAPOLATE` layout (MS-RDPEGFX 2.2.4.2.1.4).
pub const EXTRAPOLATE: [Band; 10] = [
    band(0, 31, 33, 8),    // HL1, 1023
    band(1023, 33, 31, 7), // LH1, 1023
    band(2046, 31, 31, 9), // HH1, 961
    band(3007, 16, 17, 5), // HL2, 272
    band(3279, 17, 16, 4), // LH2, 272
    band(3551, 16, 16, 6), // HH2, 256
    band(3807, 8, 9, 2),   // HL3, 72
    band(3879, 9, 8, 1),   // LH3, 72
    band(3951, 8, 8, 3),   // HH3, 64
    band(4015, 9, 9, 0),   // LL3, 81
];

const fn band(off: usize, w: usize, h: usize, q: usize) -> Band {
    Band { off, w, h, q }
}

/// Which wavelet and therefore which subband layout a tile was coded with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `RFX_DWT_REDUCE_EXTRAPOLATE` clear. The RemoteFX layout.
    Plain,
    /// `RFX_DWT_REDUCE_EXTRAPOLATE` set. What Windows sends.
    Extrapolate,
}

impl Layout {
    /// The ten subbands, coarsest quantization index last.
    pub fn bands(self) -> &'static [Band; 10] {
        match self {
            Layout::Plain => &PLAIN,
            Layout::Extrapolate => &EXTRAPOLATE,
        }
    }

    /// The LL3 band, which is the one the differential decode covers.
    pub fn ll3(self) -> Band {
        self.bands()[9]
    }
}

/// Undo the DPCM coding of the LL3 band (MS-RDPEGFX 3.3.7, and
/// MS-RDPRFX 3.1.8.1.6 for the same pass in the plain layout).
///
/// [`Layout::Plain`] hands this straight to
/// [`crate::remotefx::quant::differential_ll3`], because the band is the same
/// 64 coefficients at the same offset and running a second copy of a three
/// line loop is how two implementations of one rule start to differ. The
/// extrapolate layout has 81 coefficients at 4015 instead, in raster order,
/// so it needs the general form.
pub fn differential_ll3(buf: &mut [i16], layout: Layout) {
    match layout {
        Layout::Plain => crate::remotefx::quant::differential_ll3(buf),
        Layout::Extrapolate => {
            let ll3 = layout.ll3();
            let band = &mut buf[ll3.off..ll3.off + ll3.count()];
            for i in 1..band.len() {
                band[i] = band[i].wrapping_add(band[i - 1]);
            }
        }
    }
}

/// Inverse quantization with a progressive bit position table
/// (MS-RDPEGFX 3.3.7).
///
/// `bit_pos` is the sum of the tile's `RFX_COMPONENT_CODEC_QUANT` nibble and
/// the `RFX_PROGRESSIVE_CODEC_QUANT` nibble its `quality` index selected, per
/// band. The shift is that sum less one, which is the same "factor less one"
/// [`crate::remotefx::quant::dequantize`] applies, for the same reason: five
/// fractional bits reach the colour stage and it shifts exactly five back
/// out. A progressive quantization of zero in every band therefore reduces
/// this function to the RemoteFX one, and that is the property that makes
/// `WBT_TILE_SIMPLE` and a RemoteFX tile the same thing.
///
/// The plain layout delegates, which is real reuse rather than a copy: the
/// bands are identical and the summed nibbles fit a `u8` because both halves
/// are four bit fields.
///
/// A summed bit position of zero would be a shift of minus one, so it is a
/// [`DecodeError::Range`] rather than something to guess at, and it is
/// refused before anything is written.
pub fn dequantize(buf: &mut [i16], layout: Layout, bit_pos: &[u8; 10]) -> Result<(), DecodeError> {
    if let Layout::Plain = layout {
        return crate::remotefx::quant::dequantize(buf, bit_pos);
    }
    debug_assert!(buf.len() >= COEFS);
    for &f in bit_pos.iter() {
        if f == 0 {
            return Err(DecodeError::Range {
                what: "RFX_PROGRESSIVE bit position",
                got: 0,
            });
        }
    }
    for b in EXTRAPOLATE {
        let shift = u32::from(bit_pos[b.q] - 1);
        // One elementwise shift over a slice whose length was proved once,
        // outside the loop, with no computed index in the body: PRDRDP/04
        // §4.6.8 rules two and three, the same shape the RemoteFX
        // dequantization uses. `wrapping_shl` because a malformed nibble pair
        // can push a coefficient out of `i16` and the fuzzer runs with
        // overflow checks on.
        for c in &mut buf[b.off..b.off + b.count()] {
            *c = c.wrapping_shl(shift);
        }
    }
    Ok(())
}

/// The per band sum of a component quantization value and a progressive one.
///
/// Both are four bit fields, so the sum is at most 30 and cannot overflow the
/// `u8` it is returned in.
pub fn bit_positions(quant: &[u8; 10], prog: &[u8; 10]) -> [u8; 10] {
    let mut out = [0u8; 10];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = quant[i].saturating_add(prog[i]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain layout has to be the RemoteFX one entry for entry, or the
    /// reuse claimed by [`differential_ll3`] and [`dequantize`] is not reuse.
    #[test]
    fn the_plain_layout_is_the_remotefx_one() {
        for (a, b) in PLAIN.iter().zip(crate::remotefx::quant::BANDS) {
            assert_eq!((a.off, a.count(), a.q), b);
        }
        assert_eq!(PLAIN[9].off, crate::remotefx::quant::LL3);
    }

    /// The arithmetic of the module comment, as a test. No gap, no overlap,
    /// and the total is exactly 4096, which is what makes the table
    /// self proving rather than a transcription anyone has to trust.
    #[test]
    fn the_extrapolate_bands_tile_the_buffer_exactly_once() {
        let mut covered = [0u8; COEFS];
        for b in EXTRAPOLATE {
            for c in &mut covered[b.off..b.off + b.count()] {
                *c += 1;
            }
        }
        assert!(covered.iter().all(|&c| c == 1));
    }

    /// Each level's four bands are contiguous and its output lands exactly
    /// where the next level reads its LL band, which is the property that
    /// lets the whole three level transform run in one buffer.
    #[test]
    fn each_extrapolate_level_writes_where_the_next_reads_its_ll() {
        // Level 3: HL3, LH3, HH3, LL3 span 3807 to 4096 and its 17 by 17
        // output is 289 coefficients, so it fills exactly that span.
        assert_eq!(EXTRAPOLATE[6].off, 3807);
        assert_eq!(3807 + 17 * 17, COEFS);
        // Level 2: its three detail bands start at 3007 and its LL is the
        // level 3 output at 3807. 33 by 33 is 1089 and 3007 + 1089 is 4096.
        assert_eq!(EXTRAPOLATE[3].off, 3007);
        assert_eq!(3007 + 33 * 33, COEFS);
        // Level 1: detail bands at 0, LL at 3007, output the whole tile.
        assert_eq!(EXTRAPOLATE[0].off, 0);
        assert_eq!(64 * 64, COEFS);
    }

    /// Every quantization nibble index is used exactly once in both layouts.
    /// A duplicated index scales one band with another band's factor, which
    /// produces a picture with the wrong sharpness rather than obvious
    /// corruption.
    #[test]
    fn every_quant_index_is_used_once_in_both_layouts() {
        for table in [PLAIN, EXTRAPOLATE] {
            let mut seen = [0u8; 10];
            for b in table {
                seen[b.q] += 1;
            }
            assert!(seen.iter().all(|&c| c == 1));
        }
    }

    #[test]
    fn the_differential_decode_covers_the_right_band_in_each_layout() {
        for layout in [Layout::Plain, Layout::Extrapolate] {
            let ll3 = layout.ll3();
            let mut buf = vec![0i16; COEFS];
            for c in &mut buf[ll3.off..ll3.off + ll3.count()] {
                *c = 3;
            }
            differential_ll3(&mut buf, layout);
            assert_eq!(buf[ll3.off], 3);
            assert_eq!(buf[ll3.off + ll3.count() - 1], 3 * ll3.count() as i16);
            assert!(buf[..ll3.off].iter().all(|&c| c == 0));
        }
        assert_eq!(Layout::Plain.ll3().count(), 64);
        assert_eq!(Layout::Extrapolate.ll3().count(), 81);
    }

    /// With every progressive nibble zero the two layouts' dequantization is
    /// the RemoteFX one, band for band. This is the check that the "factor
    /// less one" scale is the same in both codecs, which is what keeps the
    /// colour stage's five fractional bits honest.
    #[test]
    fn a_zero_progressive_quant_is_the_remotefx_shift() {
        let quant = [6u8; 10];
        let pos = bit_positions(&quant, &[0; 10]);
        assert_eq!(pos, quant);

        let mut a = vec![1i16; COEFS];
        let mut b = vec![1i16; COEFS];
        dequantize(&mut a, Layout::Plain, &pos).unwrap();
        crate::remotefx::quant::dequantize(&mut b, &quant).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_progressive_quant_shifts_further_than_the_component_one_alone() {
        let pos = bit_positions(&[6; 10], &[3; 10]);
        assert_eq!(pos, [9u8; 10]);
        let mut buf = vec![1i16; COEFS];
        dequantize(&mut buf, Layout::Extrapolate, &pos).unwrap();
        assert!(buf.iter().all(|&c| c == 1 << 8));
    }

    #[test]
    fn a_zero_bit_position_is_refused_before_anything_is_written() {
        for layout in [Layout::Plain, Layout::Extrapolate] {
            let mut buf = vec![1i16; COEFS];
            let mut pos = [6u8; 10];
            pos[4] = 0;
            assert!(dequantize(&mut buf, layout, &pos).is_err());
            assert!(buf.iter().all(|&c| c == 1));
        }
    }

    /// The widest legal pair of nibbles is 15 and 15, so the shift is 29. A
    /// `wrapping_shl` of an `i16` by 29 is a shift by 29 modulo 16, which is
    /// defined and does not panic, and that is the property remote input
    /// needs. Nothing legal reaches it.
    #[test]
    fn the_widest_summed_shift_wraps_rather_than_panicking() {
        let mut buf = vec![4i16; COEFS];
        dequantize(&mut buf, Layout::Extrapolate, &[30u8; 10]).unwrap();
        let mut buf = vec![4i16; COEFS];
        dequantize(&mut buf, Layout::Plain, &[30u8; 10]).unwrap();
    }
}
