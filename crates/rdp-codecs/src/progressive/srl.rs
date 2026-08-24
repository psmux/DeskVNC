//! The upgrade pass: SRL coded new coefficients and raw coded refinements
//! (MS-RDPEGFX 2.2.4.2.1.6.3 for `RFX_PROGRESSIVE_TILE_UPGRADE`, 3.3.7 for
//! the decode).
//!
//! An upgrade pass carries two bitstreams per component and every coefficient
//! of every band takes its bits from exactly one of them:
//!
//! * A coefficient that is **already non zero** in the tile state is being
//!   refined, so the pass simply appends the next `numBits` bits of its
//!   magnitude. Those come from the raw stream, `numBits` at a time, with no
//!   framing at all.
//! * A coefficient that is **still zero** either stays zero or becomes non
//!   zero here, which is a sparse yes or no per coefficient. Those come from
//!   the SRL stream, which is a run length code over the zeros.
//!
//! ## Why the arithmetic below is derivable rather than transcribed
//!
//! This is the part of progressive that a reader should be able to check
//! without a vector, so here is the algebra. Write a coefficient as a sign
//! and a magnitude `m` at some bit position. The tile state holds
//! `± m_old << (posOld - 1)`, because [`super::bands::dequantize`] shifts by
//! the bit position less one. This pass brings `posNew`, so
//! `numBits = posOld - posNew` more bits of the same magnitude arrive, and
//!
//! ```text
//! m_new = (m_old << numBits) | v
//! ± m_new << (posNew - 1) = ± m_old << (posOld - 1)  +  ± v << (posNew - 1)
//! ```
//!
//! So refining is one add of `v << (posNew - 1)` with the coefficient's
//! existing sign, and nothing has to be unpacked or rescaled. A coefficient
//! that was zero has no existing sign, which is exactly why its sign travels
//! with its value in the SRL stream and not in the raw one.
//!
//! It also settles how wide an SRL magnitude is. A coefficient that was zero
//! at `posOld` has `|c| < 2^posOld`, so at the new scale its magnitude is
//! below `2^numBits` and at least one. `numBits` bits hold every such value
//! and no fewer do, so the SRL value is a sign bit and `numBits` magnitude
//! bits. **That is a reconstruction and not a transcription**
//! (`docs/RDP_SPEC_NOTES.md` §1.7). The competing reading is that the leading
//! one is implied and only `numBits - 1` bits are sent; it is ruled out by
//! `numBits = 3, m = 1`, which that form cannot represent. MS-RDPEGFX 4.1.2
//! settles the bit order, and a capture from an xrdp 0.10 GFX session is the
//! second source `PRDRDP/09 §2.4.1` points at.
//!
//! ## What is shared with RLGR and what is not
//!
//! The run coder **is** RLGR1's run mode, not something like it: a zero bit
//! means another `1 << k` zeros and raises `kp` by [`UP_GR`], a one bit ends
//! the run and is followed by `k` bits of remainder and a drop of [`DN_GR`],
//! and `k` is `kp >> `[`LSGR`] throughout. Those four constants are imported
//! from [`crate::remotefx::rlgr`] rather than restated. What is not shared is
//! the symbol at the end of the run: RLGR1 codes it as a sign and a Golomb
//! Rice magnitude with its own adaptive `kr`, and SRL codes it as a sign and
//! a fixed `numBits` field, because the width is already known from the two
//! bit positions. There is no Golomb Rice mode in SRL and no `krp`.
//!
//! ## Why this cannot fail
//!
//! Same contract as [`crate::remotefx::rlgr::decode`] and for the same
//! reason: [`crate::remotefx::rlgr::BitReader`] reads zeros past the end of
//! its input, so a short stream refines its own prefix and leaves the rest of
//! the tile at the quality it already had. Truncation is caught one layer up,
//! where the six declared lengths of `RFX_PROGRESSIVE_TILE_UPGRADE` are taken
//! out of the block before anything is decoded.

use crate::remotefx::rlgr::{BitReader, DN_GR, KPMAX, LSGR, UP_GR};

use super::bands::Layout;

/// The run coder state, carried across every band of one component.
///
/// It is per component and not per band: the bands are decoded back to back
/// out of one SRL stream, so a run of zeros that starts in HL1 can end in
/// LH1, and resetting `kp` at a band boundary would desynchronise the stream
/// from the second band onward. Stated because it is the kind of thing that
/// looks like a detail and is not.
struct Srl<'a> {
    bits: BitReader<'a>,
    /// The adaptation accumulator, `k` is `kp >> LSGR`.
    kp: i32,
    k: u32,
    /// Zeros still owed from the run in progress.
    nz: u32,
    /// A run has been framed and its terminating value is still owed.
    pending: bool,
}

impl<'a> Srl<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            bits: BitReader::new(src),
            // The same start as RLGR's run mode: `kp = 1 << LSGR`, so `k` is
            // one and the first zero bit means a pair of zeros.
            kp: 1 << LSGR,
            k: 1,
            nz: 0,
            pending: false,
        }
    }

    /// The next coefficient of a band whose new bits are `num_bits` wide.
    ///
    /// Returns a signed magnitude at the new scale, zero when the coefficient
    /// is still zero.
    #[inline]
    fn next(&mut self, num_bits: u32) -> i32 {
        if self.nz > 0 {
            self.nz -= 1;
            return 0;
        }
        if !self.pending {
            if self.bits.bit() == 0 {
                // A full block of `1 << k` zeros, and `k` grows.
                self.nz = 1u32 << self.k.min(31);
                self.kp = (self.kp + UP_GR).min(KPMAX);
                self.k = (self.kp >> LSGR) as u32;
                self.nz -= 1;
                return 0;
            }
            // The run ends here: `k` bits of remainder, then a value.
            self.nz = self.bits.bits(self.k);
            self.kp = (self.kp - DN_GR).max(0);
            self.k = (self.kp >> LSGR) as u32;
            self.pending = true;
            if self.nz > 0 {
                self.nz -= 1;
                return 0;
            }
        }
        self.pending = false;
        let sign = self.bits.bit();
        let mag = self.bits.bits(num_bits) as i32;
        if sign != 0 {
            -mag
        } else {
            mag
        }
    }
}

/// Refine one component's coefficients in place (MS-RDPEGFX 3.3.7).
///
/// `old` is the per band bit position the tile currently holds and `new` is
/// the one this pass brings, both already summed from the component and
/// progressive quantization values by [`super::bands::bit_positions`]. Bands
/// are visited in buffer order, which is the order the two streams are packed
/// in.
///
/// A band whose bit position did not improve takes no bits from either
/// stream. That covers `new == old`, which a server sends when only some
/// bands improve, and it covers `new > old`, which no legal stream contains;
/// skipping is the tolerant reading and the alternative, refusing the frame,
/// would drop a session over a band that carries nothing.
///
/// # Panics
///
/// Never on remote input. The debug assertion names a caller that did not
/// check `new` for a zero bit position, which
/// [`super::bands::dequantize`] refuses and the tile walk checks before
/// calling this.
pub fn upgrade_component(
    buf: &mut [i16],
    layout: Layout,
    old: &[u8; 10],
    new: &[u8; 10],
    srl_data: &[u8],
    raw_data: &[u8],
) {
    let mut srl = Srl::new(srl_data);
    let mut raw = BitReader::new(raw_data);

    for b in layout.bands() {
        let num_bits = u32::from(old[b.q].saturating_sub(new[b.q]));
        if num_bits == 0 {
            continue;
        }
        debug_assert!(new[b.q] >= 1, "the caller checks for a zero bit position");
        let shift = u32::from(new[b.q].max(1) - 1);
        let band = &mut buf[b.off..b.off + b.count()];
        for c in band.iter_mut() {
            if *c != 0 {
                // Already significant: the sign is the one the tile holds and
                // the raw stream carries only magnitude.
                // `i64` because a malformed bit position pair can ask for 29
                // bits shifted by 29, which is outside `i32`. A legal stream
                // never leaves `i16`; the clamp is what keeps a malformed one
                // from wrapping a bright pixel to a dark one, which is the
                // same rule `rlgr::put` follows.
                let v = i64::from(raw.bits(num_bits)) << shift.min(31);
                let refined = if *c > 0 {
                    i64::from(*c).saturating_add(v)
                } else {
                    i64::from(*c).saturating_sub(v)
                };
                *c = refined.clamp(i16::MIN as i64, i16::MAX as i64) as i16;
            } else {
                let v = srl.next(num_bits);
                if v != 0 {
                    let scaled = (v as i64) << shift.min(31);
                    *c = scaled.clamp(i16::MIN as i64, i16::MAX as i64) as i16;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::BitWriter;
    use crate::remotefx::quant::COEFS;

    fn from_bits(s: &str) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bits(s);
        w.finish()
    }

    /// The run coder, hand assembled from the rules in the module comment.
    /// Not a specification transcription; the arithmetic is shown.
    ///
    /// `kp` starts at 8 so `k` is 1.
    ///
    /// ```text
    /// 1     the run ends immediately
    /// 0     one bit of remainder, so no extra zeros
    /// 0     sign, positive
    /// 011   three magnitude bits, so the value is 3
    /// ```
    #[test]
    fn the_srl_run_coder_emits_one_value_after_an_empty_run() {
        let src = from_bits("1 0 0 011");
        let mut s = Srl::new(&src);
        assert_eq!(s.next(3), 3);
    }

    /// A zero bit is a whole block of `1 << k` zeros. With `k = 1` that is
    /// two, then `kp` is 12 and `k` is still 1, then a one bit ends the run
    /// with a remainder of 1, so one more zero, and then the value.
    #[test]
    fn a_zero_bit_is_a_block_of_zeros_and_lengthens_the_run() {
        let src = from_bits("0 1 1 1 101");
        let mut s = Srl::new(&src);
        assert_eq!(s.next(3), 0);
        assert_eq!(s.next(3), 0);
        assert_eq!(s.next(3), 0);
        // Sign bit 1, magnitude 101, so minus five.
        assert_eq!(s.next(3), -5);
    }

    /// The value owed at the end of a framed run survives the zeros in
    /// between, which is what the `pending` flag is for. Without it the
    /// decoder reads the sign bit as the start of the next run.
    /// `kp` starts at 8 and `k` at 1.
    ///
    /// ```text
    /// 1     the run ends here
    /// 1     the k = 1 remainder, so one zero before the value
    ///       kp drops to 2, so k is now 0
    /// 1 010 sign then three magnitude bits, so minus two
    /// 1     the next run ends immediately
    ///       k is 0, so there are no remainder bits at all
    /// 0 001 sign then three magnitude bits, so plus one
    /// ```
    #[test]
    fn a_framed_run_still_owes_its_value_after_its_zeros() {
        let src = from_bits("1 1  1 010  1  0 001");
        let mut s = Srl::new(&src);
        assert_eq!(s.next(3), 0);
        assert_eq!(s.next(3), -2);
        // A second symbol, framed from scratch with the adapted `k`.
        assert_eq!(s.next(3), 1);
    }

    /// An empty stream refines nothing and leaves every coefficient alone,
    /// which is the property that makes a truncated upgrade a loss of sharpness
    /// rather than a corrupt tile.
    #[test]
    fn an_empty_upgrade_leaves_the_tile_alone() {
        let mut buf = vec![0i16; COEFS];
        for (i, c) in buf.iter_mut().enumerate() {
            *c = (i % 7) as i16 - 3;
        }
        let before = buf.clone();
        upgrade_component(&mut buf, Layout::Plain, &[8; 10], &[8; 10], &[], &[]);
        assert_eq!(buf, before);
    }

    /// A refinement adds bits below what the tile already holds and never
    /// flips a sign. This is the algebra of the module comment, checked
    /// directly: a coefficient of `m << (posOld - 1)` with `numBits` more bits
    /// `v` has to become `((m << numBits) | v) << (posNew - 1)`.
    #[test]
    fn a_refinement_appends_bits_below_what_the_tile_holds() {
        let (pos_old, pos_new) = (8u8, 5u8);
        let num_bits = u32::from(pos_old - pos_new);
        let m = 5i32;
        let v = 0b011i32;
        let mut buf = vec![0i16; COEFS];
        buf[0] = (m << (pos_old - 1)) as i16;
        buf[1] = -((m << (pos_old - 1)) as i16);
        // Three raw bits per coefficient, twice, and no SRL stream because
        // both coefficients are already significant. Every other coefficient
        // of HL1 is zero, so the SRL stream's padding zeros carry them.
        let raw = from_bits("011 011");
        upgrade_component(
            &mut buf,
            Layout::Plain,
            &[pos_old; 10],
            &[pos_new; 10],
            &[],
            &raw,
        );
        let want = (((m << num_bits) | v) << (pos_new - 1)) as i16;
        assert_eq!(buf[0], want);
        assert_eq!(buf[1], -want);
    }

    /// A coefficient that was zero takes its sign and its whole magnitude
    /// from the SRL stream, at the new scale.
    #[test]
    fn a_new_coefficient_arrives_whole_from_the_srl_stream() {
        let mut buf = vec![0i16; COEFS];
        // Run ends immediately, no remainder, positive, three bits of 5.
        let srl = from_bits("1 0 0 101");
        upgrade_component(&mut buf, Layout::Plain, &[8; 10], &[5; 10], &srl, &[]);
        assert_eq!(buf[0], 5 << 4);
        assert_eq!(buf[1], 0);
    }

    /// Every prefix of both streams must terminate, must not panic, and must
    /// leave a defined buffer. The upgrade path reads two independent
    /// bitstreams, so both are swept.
    #[test]
    fn every_prefix_of_both_streams_terminates() {
        let srl: Vec<u8> = (0u8..48).map(|i| i.wrapping_mul(29) ^ 0x3C).collect();
        let raw: Vec<u8> = (0u8..48).map(|i| i.wrapping_mul(53) ^ 0xA1).collect();
        for layout in [Layout::Plain, Layout::Extrapolate] {
            for n in 0..srl.len() {
                let mut buf = vec![1i16; COEFS];
                upgrade_component(&mut buf, layout, &[10; 10], &[4; 10], &srl[..n], &raw[..n]);
                assert_eq!(buf.len(), COEFS);
            }
        }
    }

    /// The adversarial patterns. All ones is the worst case for the run
    /// escape and all zeros for the other polarity, and a `k` at its ceiling
    /// asks for a run of `1 << 10` zeros in a band of 1024.
    #[test]
    fn pathological_bit_patterns_terminate() {
        for fill in [0x00u8, 0xFF, 0xAA, 0x55] {
            for len in [1usize, 2, 7, 64, 1024] {
                let src = vec![fill; len];
                for layout in [Layout::Plain, Layout::Extrapolate] {
                    let mut buf = vec![0i16; COEFS];
                    upgrade_component(&mut buf, layout, &[15; 10], &[1; 10], &src, &src);
                }
            }
        }
    }

    /// Every leading byte over a fixed tail, the sweep the other decoders in
    /// this crate carry.
    #[test]
    fn every_leading_byte_terminates() {
        for lead in 0u16..=255 {
            let mut src = vec![lead as u8];
            src.extend_from_slice(&[0x9C, 0x3F, 0x00, 0xE1, 0x77]);
            let mut buf = vec![-1i16; COEFS];
            upgrade_component(
                &mut buf,
                Layout::Extrapolate,
                &[9; 10],
                &[3; 10],
                &src,
                &src,
            );
        }
    }

    /// A band whose bit position did not improve consumes nothing, so a pass
    /// that improves only the coarse bands leaves the fine ones untouched and
    /// the two streams stay in step.
    #[test]
    fn a_band_that_did_not_improve_consumes_nothing() {
        let mut old = [8u8; 10];
        let mut new = [8u8; 10];
        // Improve only the LL3 nibble, which is quant index zero.
        new[0] = 5;
        let mut buf = vec![0i16; COEFS];
        let srl = from_bits("1 0 0 111");
        upgrade_component(&mut buf, Layout::Plain, &old, &new, &srl, &[]);
        // LL3 is the last band in buffer order, at 4032.
        assert_eq!(buf[4032], 7 << 4);
        assert!(buf[..4032].iter().all(|&c| c == 0));

        // And a pass that improves nothing at all is a no op.
        old[0] = 5;
        let mut buf = vec![3i16; COEFS];
        upgrade_component(&mut buf, Layout::Plain, &old, &new, &srl, &[]);
        assert!(buf.iter().all(|&c| c == 3));
    }
}
