//! The subband layout, the LL3 differential decode and the inverse
//! quantization (MS-RDPRFX 2.2.2.1.6 for `TS_RFX_CODEC_QUANT`, 3.1.8.1.5 for
//! the dequantization, 3.1.8.1.6 for the differential decode).
//!
//! These two passes are the cheap stage of RemoteFX: PRDRDP/04 §11.2 gives
//! them 0.3 ms of the 5.2 ms budget together, at 20 Gcoef/s. Both are plain
//! elementwise passes over `i16` and both vectorise, which is why they share
//! a file and one bench line.

use crate::DecodeError;

/// Coefficients per component in a 64 by 64 tile.
pub const COEFS: usize = 4096;

/// A tile edge in pixels. MS-RDPRFX 2.2.2.3.4 fixes `tileSize` at 0x40 and we
/// refuse anything else, because every offset in [`BANDS`] is derived from it.
pub const TILE: usize = 64;

/// The ten subbands of a 64 by 64 tile, as `(offset, count, quant index)`
/// into the flat 4096 coefficient buffer.
///
/// The order is HL, LH, HH at each level from the finest to the coarsest,
/// then LL3 last (MS-RDPRFX 2.2.2.3.4 for the buffer order, 3.1.8.1.4 for the
/// transform that consumes it). It is that order because the inverse DWT
/// reconstructs coarsest first and writes its result exactly where the next
/// level's LL band belongs: level 3 writes 16 by 16 into offset 3840, which
/// is where level 2 reads its LL from, and level 2 writes 32 by 32 into
/// offset 3072, which is where level 1 reads its LL from. That property is
/// what makes the whole three level transform work in one buffer with no
/// copies, and it is a good check that a transcription of this table is
/// right.
///
/// The third column is the one that gets transcribed wrong. The nibble order
/// inside `TS_RFX_CODEC_QUANT` is LL3, LH3, HL3, HH3, LH2, HL2, HH2, LH1,
/// HL1, HH1, which is a different order from the buffer's, deliberately. A
/// decoder that assumes the two match produces a picture with the wrong
/// sharpness rather than obvious corruption (PRDRDP/04 §4.6.2).
pub const BANDS: [(usize, usize, usize); 10] = [
    (0, 1024, 8),    // HL1
    (1024, 1024, 7), // LH1
    (2048, 1024, 9), // HH1
    (3072, 256, 5),  // HL2
    (3328, 256, 4),  // LH2
    (3584, 256, 6),  // HH2
    (3840, 64, 2),   // HL3
    (3904, 64, 1),   // LH3
    (3968, 64, 3),   // HH3
    (4032, 64, 0),   // LL3
];

/// Where LL3 starts in the flat buffer. The differential decode of
/// MS-RDPRFX 3.1.8.1.6 covers exactly this band.
pub const LL3: usize = 4032;

/// One `TS_RFX_CODEC_QUANT`: five bytes holding ten four bit factors, low
/// nibble first (MS-RDPRFX 2.2.2.1.6).
///
/// The nibble order is LL3, LH3, HL3, HH3, LH2, HL2, HH2, LH1, HL1, HH1, so
/// index `i` of the returned array is the factor [`BANDS`] names in its third
/// column.
pub fn parse_quant(b: &[u8]) -> [u8; 10] {
    debug_assert!(b.len() >= 5);
    let mut q = [0u8; 10];
    for (i, slot) in q.iter_mut().enumerate() {
        let byte = b[i / 2];
        *slot = if i % 2 == 0 { byte & 0x0F } else { byte >> 4 };
    }
    q
}

/// Undo the DPCM coding of the LL3 band (MS-RDPRFX 3.1.8.1.6).
///
/// The last 64 coefficients of the buffer are differences against their
/// predecessor. This runs **before** dequantization, which is the step people
/// reorder (PRDRDP/04 §4.6.3), and the arithmetic wraps in `i16`.
///
/// Serial by construction: each coefficient depends on the one to its left.
/// It is 64 values out of 4096, so it does not need to vectorise and there is
/// no way to make it.
pub fn differential_ll3(buf: &mut [i16]) {
    debug_assert!(buf.len() >= COEFS);
    let band = &mut buf[LL3..COEFS];
    for i in 1..band.len() {
        band[i] = band[i].wrapping_add(band[i - 1]);
    }
}

/// Inverse quantization: left shift every coefficient of a band by that
/// band's factor less one (MS-RDPRFX 3.1.8.1.5).
///
/// The "less one" is not a typo and not a rounding convenience. The wire
/// factors sit around six, the encoder's own step is `factor - 6`, and the
/// difference of five is where the five fractional bits of PRDRDP/04 §4.6.6
/// come from: the colour conversion at the end of the pipeline shifts right
/// by exactly those five bits and offsets Y by `128 << 5`. So this shift
/// carries the fixed point scale of the whole tile and it is checkable
/// against the colour stage rather than only against a vector.
///
/// A factor of zero is not a legal `TS_RFX_CODEC_QUANT` value and would mean
/// a shift of minus one, so it is a [`DecodeError::Range`] rather than
/// something to guess at.
///
/// The loop is a slice of proved length shifted elementwise, which is
/// PRDRDP/04 §4.6.8 rules two and three: one width, no computed index, no
/// panic path for LLVM to preserve. `wrapping_shl` rather than `<<` because
/// a malformed factor can push a coefficient out of `i16` and a debug build
/// would otherwise panic on remote input.
pub fn dequantize(buf: &mut [i16], q: &[u8; 10]) -> Result<(), DecodeError> {
    debug_assert!(buf.len() >= COEFS);
    for &f in q.iter() {
        if f == 0 {
            return Err(DecodeError::Range {
                what: "TS_RFX_CODEC_QUANT factor",
                got: 0,
            });
        }
    }
    for (off, n, qi) in BANDS {
        let shift = u32::from(q[qi] - 1);
        for c in &mut buf[off..off + n] {
            *c = c.wrapping_shl(shift);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The band table has to tile the buffer exactly, with no gap and no
    /// overlap, or the dequantization silently skips coefficients the DWT
    /// then reads. Checking it here is cheaper than finding it in a picture.
    #[test]
    fn the_bands_tile_the_buffer_exactly_once() {
        let mut covered = [0u8; COEFS];
        for (off, n, _) in BANDS {
            for c in &mut covered[off..off + n] {
                *c += 1;
            }
        }
        assert!(covered.iter().all(|&c| c == 1));
    }

    /// Every quant nibble index is used exactly once, which is the other half
    /// of the transcription check: a duplicated index means a band is scaled
    /// with another band's factor.
    #[test]
    fn every_quant_index_is_used_once() {
        let mut seen = [0u8; 10];
        for (_, _, qi) in BANDS {
            seen[qi] += 1;
        }
        assert!(seen.iter().all(|&c| c == 1));
    }

    /// Each level's output lands where the next level reads its LL band, and
    /// the three levels are 16 by 16, 32 by 32 and 64 by 64. This encodes the
    /// property the doc comment claims, so a reordering of `BANDS` fails here.
    #[test]
    fn each_level_writes_where_the_next_reads_its_ll() {
        // Level 3 covers HL3, LH3, HH3, LL3 at 3840 and produces 16 by 16.
        assert_eq!(BANDS[6].0, 3840);
        assert_eq!(3840 + 16 * 16, COEFS);
        // Level 2 covers HL2, LH2, HH2 at 3072 with its LL at 3840.
        assert_eq!(BANDS[3].0, 3072);
        assert_eq!(3072 + 32 * 32, COEFS);
        // Level 1 covers HL1, LH1, HH1 at 0 with its LL at 3072.
        assert_eq!(BANDS[0].0, 0);
        assert_eq!(64 * 64, COEFS);
    }

    /// The nibble order of MS-RDPRFX 2.2.2.1.6 is low nibble first. Five
    /// bytes of 0x21, 0x43, 0x65, 0x87, 0xA9 therefore read out as
    /// 1, 2, 3, 4, 5, 6, 7, 8, 9, 10.
    #[test]
    fn quant_nibbles_come_out_low_first() {
        let q = parse_quant(&[0x21, 0x43, 0x65, 0x87, 0xA9]);
        assert_eq!(q, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn differential_decode_is_a_running_sum_and_wraps() {
        let mut buf = vec![0i16; COEFS];
        buf[LL3] = 100;
        buf[LL3 + 1] = 10;
        buf[LL3 + 2] = -5;
        buf[LL3 + 3] = i16::MAX;
        differential_ll3(&mut buf);
        assert_eq!(buf[LL3], 100);
        assert_eq!(buf[LL3 + 1], 110);
        assert_eq!(buf[LL3 + 2], 105);
        // 105 + 32767 wraps rather than panicking in a debug build.
        assert_eq!(buf[LL3 + 3], 105i16.wrapping_add(i16::MAX));
        // Nothing outside LL3 moved.
        assert!(buf[..LL3].iter().all(|&c| c == 0));
    }

    #[test]
    fn dequantize_shifts_each_band_by_its_own_factor_less_one() {
        let mut buf = vec![1i16; COEFS];
        // Factor `i + 1` at nibble index `i`, so band with quant index `qi`
        // shifts by `qi`.
        let q = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        dequantize(&mut buf, &q).unwrap();
        for (off, n, qi) in BANDS {
            let want = 1i16.wrapping_shl(qi as u32);
            assert!(
                buf[off..off + n].iter().all(|&c| c == want),
                "band at {off} with quant index {qi}"
            );
        }
    }

    #[test]
    fn a_zero_quant_factor_is_a_range_error() {
        let mut buf = vec![1i16; COEFS];
        let q = [6u8, 6, 6, 6, 6, 6, 6, 6, 0, 6];
        assert_eq!(
            dequantize(&mut buf, &q),
            Err(DecodeError::Range {
                what: "TS_RFX_CODEC_QUANT factor",
                got: 0
            })
        );
        // And it refused before touching anything, so a caller that ignores
        // the error still sees a defined buffer.
        assert!(buf.iter().all(|&c| c == 1));
    }

    /// The widest legal factor is 15, so the shift is 14 and a coefficient of
    /// 1 becomes 16384. A coefficient of 4 wraps, and wrapping rather than
    /// panicking is the property remote input needs.
    #[test]
    fn the_widest_shift_wraps_instead_of_panicking() {
        let mut buf = vec![4i16; COEFS];
        let q = [15u8; 10];
        dequantize(&mut buf, &q).unwrap();
        assert_eq!(buf[0], 4i16.wrapping_shl(14));
    }
}
