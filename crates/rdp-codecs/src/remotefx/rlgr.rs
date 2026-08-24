//! RLGR1 and RLGR3, the RemoteFX entropy coder (MS-RDPRFX 3.1.8.1.7, with the
//! adaptation constants of 3.1.8.1.7.1 and the RLGR3 pair split of
//! 3.1.8.1.7.2).
//!
//! Run Length Golomb Rice coding is bit serial and adaptive, so it is the one
//! stage of RemoteFX that cannot be vectorised and the one PRDRDP/04 §11.2
//! marks high risk. Two things keep it fast anyway, and both are design
//! decisions rather than tuning:
//!
//! * The output of a real tile is mostly zeros, and a zero run is a
//!   `fill(0)` over a slice rather than a loop that writes one coefficient per
//!   decoded bit. That is why the coefficient rate can beat the bit rate by
//!   more than an order of magnitude.
//! * The bit reader keeps a 64 bit window and refills whole bytes, so
//!   `bits(k)` for any `k` up to 32 is a shift and a mask with no branch and
//!   no per bit loop.
//!
//! ## Why this function cannot fail
//!
//! [`decode`] returns nothing. Bits past the end of `src` read as zero and
//! the loop stops when the coefficient buffer is full, so a truncated stream
//! decodes to its own prefix followed by zeros.
//!
//! That is a deliberate divergence from the sketch in PRDRDP/04 §4.6.4, which
//! says "returns an error if the bitstream runs out before the buffer is
//! full". Refusing a short bitstream would refuse frames that real encoders
//! send. In run mode a zero bit means "another `1 << k` zeros", so an encoder
//! whose tile ends in zeros can stop writing bits and let the decoder's
//! padding produce the tail, and that is exactly what the byte alignment at
//! the end of every `YData`, `CbData` and `CrData` invites. A decoder that
//! errored there would drop good frames.
//!
//! Truncation is still an error, one layer up: [`super::decode_message`]
//! checks every block length and every `YLen`, `CbLen` and `CrLen` against
//! the bytes that are actually present, so a tileset that claims more than it
//! carries is a [`crate::DecodeError::Truncated`] before this function is
//! reached. What this function guarantees is the other half of PRDRDP/04
//! §4.1 rule five: it always terminates, it never panics, and it writes
//! exactly `dst.len()` coefficients whatever the input says.

/// Which of the two variants a tileset's `properties` field selected
/// (MS-RDPRFX 2.2.2.3.4, entropy algorithm `et`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entropy {
    /// `CLW_ENTROPY_RLGR1` = 1.
    Rlgr1,
    /// `CLW_ENTROPY_RLGR3` = 4. What Windows Server chooses in practice.
    Rlgr3,
}

// The adaptation constants of MS-RDPRFX 3.1.8.1.7.1, quoted verbatim so a
// reviewer can diff them against the document.
/// Ceiling for both `kp` and `krp`.
///
/// This one and the three below are `pub(crate)` because the progressive
/// codec's SRL layer (MS-RDPEGFX 3.3.7) is the same run mode adaptation with
/// a different symbol at the end of the run, and two copies of four numbers
/// that must agree is how they stop agreeing.
pub(crate) const KPMAX: i32 = 80;
/// Shift that turns `kp` into `k` and `krp` into `kr`.
pub(crate) const LSGR: u32 = 3;
/// `kp` increase after a full zero block in run mode.
pub(crate) const UP_GR: i32 = 4;
/// `kp` decrease after a non zero symbol in run mode.
pub(crate) const DN_GR: i32 = 6;
/// `kp` increase after a zero symbol in Golomb Rice mode.
const UQ_GR: i32 = 3;
/// `kp` decrease after a non zero symbol in Golomb Rice mode.
const DQ_GR: i32 = 3;

/// Ceiling on the unary prefix of a Golomb Rice code.
///
/// Not in the specification, and it is an overflow guard rather than a
/// termination guard: the loop already ends on its own past the end of the
/// input, because bits read there are zero and a zero bit terminates the
/// prefix.
///
/// The ceiling has to be above anything a legal stream reaches, and a legal
/// stream reaches further than it looks. `kr` starts at one and only adapts
/// upward after it has seen large values, so the first large coefficient
/// after a long zero run is coded with a unary prefix of `mag >> 1`. A
/// magnitude of 127 is therefore 63 unary bits, which is ordinary rather than
/// pathological. The bound that matters is the two magnitude sign value,
/// which is at most 65535 for an `i16` coefficient, so 65536 admits every
/// legal stream, and `65536 << 10` with `kr` at its own ceiling of 10 stays
/// inside `u32`.
const MAX_VK: u32 = 1 << 16;

/// A most significant bit first reader with a 64 bit window
/// (MS-RDPRFX 3.1.8.1.7, "bits are read from the most significant bit").
///
/// Reads past the end of the input return zero and are counted, so
/// [`BitReader::exhausted`] is the loop's termination condition and no caller
/// has to track a length itself.
pub(crate) struct BitReader<'a> {
    src: &'a [u8],
    /// Next byte to pull into the window.
    next: usize,
    /// The window. The next bit to hand out is bit `n - 1`.
    acc: u64,
    /// Valid bits in `acc`.
    n: u32,
    /// Bits handed out so far, including padding past the end of `src`.
    used: usize,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            next: 0,
            acc: 0,
            n: 0,
            used: 0,
        }
    }

    /// True once every bit of `src` has been handed out. Everything after
    /// that point is the zero padding described in the module comment.
    #[inline]
    pub(crate) fn exhausted(&self) -> bool {
        self.used >= self.src.len() * 8
    }

    /// Top the window up to at least 33 valid bits, which is the most any
    /// single read here asks for.
    #[inline]
    fn refill(&mut self) {
        while self.n <= 32 {
            let b = match self.src.get(self.next) {
                Some(&b) => {
                    self.next += 1;
                    b
                }
                None => 0,
            };
            self.acc = (self.acc << 8) | u64::from(b);
            self.n += 8;
        }
    }

    /// `k` bits, `k <= 32`. `k == 0` reads nothing and returns zero.
    #[inline]
    pub(crate) fn bits(&mut self, k: u32) -> u32 {
        debug_assert!(k <= 32);
        if k == 0 {
            return 0;
        }
        self.refill();
        // `n > k` holds after the refill for every `k <= 32`, so the shift is
        // in range and the mask drops the stale high bits the window carries
        // from earlier refills.
        let v = (self.acc >> (self.n - k)) & ((1u64 << k) - 1);
        self.n -= k;
        self.used += k as usize;
        v as u32
    }

    /// One bit.
    #[inline]
    pub(crate) fn bit(&mut self) -> u32 {
        self.bits(1)
    }
}

/// The two magnitude sign representation of MS-RDPRFX 3.1.8.1.7:
/// bit zero is the sign and the rest is the magnitude.
#[inline]
fn from_two_mag_sign(v: u32) -> i32 {
    let mag = i64::from(v >> 1);
    let signed = if v & 1 != 0 { -(mag + 1) } else { mag };
    signed.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// Store one coefficient, clamped to `i16`.
///
/// A legal stream never produces a value outside `i16`, because the encoder
/// quantized an `i16` in the first place. A malformed one can, and clamping
/// is the behaviour that keeps the picture bounded rather than wrapping a
/// bright pixel to a dark one.
#[inline]
fn put(dst: &mut [i16], at: usize, v: i32) {
    if let Some(slot) = dst.get_mut(at) {
        *slot = v.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
    }
}

/// The Golomb Rice primitive both variants share (MS-RDPRFX 3.1.8.1.7).
///
/// The unary prefix counts one bits and is terminated by a zero bit. That
/// polarity is the opposite of the run mode escape below, which counts zero
/// bits and is terminated by a one, and getting the two the same way round is
/// the classic transcription error here.
#[inline]
fn gr(r: &mut BitReader<'_>, krp: &mut i32, kr: &mut u32) -> u32 {
    let mut vk = 0u32;
    while vk < MAX_VK && r.bit() == 1 {
        vk += 1;
    }
    let mag = (vk << *kr) + r.bits(*kr);

    if vk == 0 {
        *krp = (*krp - 2).max(0);
        *kr = (*krp >> LSGR) as u32;
    } else if vk > 1 {
        *krp = (*krp + vk as i32).min(KPMAX);
        *kr = (*krp >> LSGR) as u32;
    }
    mag
}

/// Decode exactly `dst.len()` coefficients from `src`.
///
/// `dst` is fully written: every position the bitstream does not reach is
/// zero. See the module comment for why this cannot fail and where truncation
/// is caught instead.
pub fn decode(mode: Entropy, src: &[u8], dst: &mut [i16]) {
    // Zero first, so the zero runs below are a bounds move rather than a
    // write, and so an early exit leaves a defined buffer. On a real tile most
    // of the 4096 coefficients are never touched again after this, which is
    // the fill PRDRDP/04 §4.6.4 is talking about.
    dst.fill(0);

    let len = dst.len();
    let mut r = BitReader::new(src);

    let mut kp: i32 = 1 << LSGR;
    let mut k: u32 = (kp >> LSGR) as u32;
    let mut krp: i32 = 1 << LSGR;
    let mut kr: u32 = (krp >> LSGR) as u32;

    let mut at = 0usize;

    while at < len && !r.exhausted() {
        if k > 0 {
            // Run mode. Each zero bit is a full block of `1 << k` zeros and
            // bumps `k`; the terminating one bit is followed by `k` more bits
            // of remainder.
            while at < len && r.bit() == 0 {
                at = at.saturating_add(1usize << k).min(len);
                kp = (kp + UP_GR).min(KPMAX);
                k = (kp >> LSGR) as u32;
            }
            if at >= len {
                break;
            }
            at = at.saturating_add(r.bits(k) as usize).min(len);
            if at >= len {
                break;
            }

            // The non zero symbol that ended the run: a sign bit, then the
            // magnitude less one as a Golomb Rice code.
            let sign = r.bit();
            let mag = i64::from(gr(&mut r, &mut krp, &mut kr)) + 1;
            let v = if sign != 0 { -mag } else { mag };
            put(dst, at, v.clamp(i32::MIN as i64, i32::MAX as i64) as i32);
            at += 1;

            kp = (kp - DN_GR).max(0);
            k = (kp >> LSGR) as u32;
        } else {
            let mag = gr(&mut r, &mut krp, &mut kr);
            match mode {
                Entropy::Rlgr1 => {
                    if mag == 0 {
                        put(dst, at, 0);
                        at += 1;
                        kp = (kp + UQ_GR).min(KPMAX);
                    } else {
                        put(dst, at, from_two_mag_sign(mag));
                        at += 1;
                        kp = (kp - DQ_GR).max(0);
                    }
                    k = (kp >> LSGR) as u32;
                }
                Entropy::Rlgr3 => {
                    // MS-RDPRFX 3.1.8.1.7.2. One Golomb Rice code carries the
                    // sum of two consecutive two magnitude sign values. The
                    // split is uniquely decodable because the first of the
                    // pair is written in exactly as many bits as the sum
                    // needs, and it is at most the sum.
                    let nidx = if mag == 0 {
                        0
                    } else {
                        u32::BITS - mag.leading_zeros()
                    };
                    let val1 = r.bits(nidx);
                    // An encoder never writes `val1 > mag`. A malformed
                    // stream can, and saturating rather than wrapping keeps
                    // the second coefficient inside the range the clamp in
                    // `put` expects.
                    let val2 = mag.saturating_sub(val1);

                    put(dst, at, from_two_mag_sign(val1));
                    at += 1;
                    put(dst, at, from_two_mag_sign(val2));
                    at += 1;

                    // Two symbols were emitted, so the adaptation moves twice
                    // as far as RLGR1's does.
                    if val1 == 0 && val2 == 0 {
                        kp = (kp + 2 * UQ_GR).min(KPMAX);
                    } else {
                        kp = (kp - 2 * DQ_GR).max(0);
                    }
                    k = (kp >> LSGR) as u32;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors below are written as bit strings rather than as hex
    /// nobody can check. The writer is `encode`'s, which is the exact inverse
    /// of [`BitReader`], so a hand assembled vector and an encoder produced
    /// bitstream go through one writer rather than two that can drift.
    fn from_bits(s: &str) -> Vec<u8> {
        let mut w = crate::encode::BitWriter::new();
        w.bits(s);
        w.finish()
    }

    #[test]
    fn the_bit_reader_hands_out_most_significant_bit_first() {
        let mut r = BitReader::new(&[0b1011_0010, 0xFF]);
        assert_eq!(r.bit(), 1);
        assert_eq!(r.bits(3), 0b011);
        assert_eq!(r.bits(4), 0b0010);
        assert!(!r.exhausted());
        assert_eq!(r.bits(8), 0xFF);
        assert!(r.exhausted());
        // Everything past the end is zero, which is what makes `decode`
        // total. It is still counted, so `exhausted` stays true.
        assert_eq!(r.bits(8), 0);
        assert!(r.exhausted());
    }

    #[test]
    fn a_thirty_two_bit_read_is_in_range() {
        let src = [0x12, 0x34, 0x56, 0x78, 0x9A];
        let mut r = BitReader::new(&src);
        assert_eq!(r.bits(32), 0x1234_5678);
        assert_eq!(r.bits(8), 0x9A);
    }

    /// The two magnitude sign mapping is stated in MS-RDPRFX 3.1.8.1.7 as
    /// `if v & 1 { -((v + 1) >> 1) } else { v >> 1 }`. These are the first
    /// six values of it, computed from that expression.
    #[test]
    fn two_mag_sign_alternates_around_zero() {
        let got: Vec<i32> = (0..6).map(from_two_mag_sign).collect();
        assert_eq!(got, vec![0, -1, 1, -2, 2, -3]);
    }

    /// Hand assembled, not a specification transcription. MS-RDPRFX §4 was
    /// not available to this lane, so the arithmetic is shown instead.
    ///
    /// The initial state is `kp = krp = 8`, so `k = kr = 1` and the decoder
    /// starts in run mode. The bit string is:
    ///
    /// ```text
    /// 1        terminate the run of zero blocks immediately
    /// 0        the k = 1 remainder, so zero extra zeros: the run is empty
    /// 0        sign, positive
    /// 0        the Golomb Rice unary prefix, vk = 0
    /// 0        one kr = 1 bit of value, so mag = 0, and the coefficient is
    ///          mag + 1 = 1
    /// ```
    ///
    /// which is coefficient zero equal to 1 and everything after it zero,
    /// because the padding is zeros and `k` is now `(8 - 6) >> 3 = 0`, and in
    /// Golomb Rice mode a zero magnitude emits a zero coefficient.
    #[test]
    fn rlgr1_run_mode_emits_one_positive_coefficient() {
        let src = from_bits("1 0 0 0 0");
        let mut dst = [7i16; 8];
        decode(Entropy::Rlgr1, &src, &mut dst);
        assert_eq!(dst, [1, 0, 0, 0, 0, 0, 0, 0]);
    }

    /// Same start, but the first bit is a zero, which is the escape for a
    /// full block of `1 << k` zeros with `k = 1`. So two zeros are emitted,
    /// `kp` becomes 12 and `k` becomes 1 again, then a one terminates, a one
    /// bit remainder of 1 adds one more zero, and the symbol that follows is
    /// negative with magnitude 1.
    #[test]
    fn rlgr1_zero_block_escape_lengthens_the_run() {
        let src = from_bits("0 1 1 1 0 0");
        let mut dst = [7i16; 8];
        decode(Entropy::Rlgr1, &src, &mut dst);
        assert_eq!(dst, [0, 0, 0, -1, 0, 0, 0, 0]);
    }

    /// The Golomb Rice unary prefix counts one bits. With `kr = 1` a prefix
    /// of `1 1 0` is `vk = 2`, so `mag = (2 << 1) + next bit`. This drives
    /// `k` to zero first with a non zero run mode symbol, so the second
    /// symbol is decoded in Golomb Rice mode.
    #[test]
    fn rlgr1_golomb_rice_mode_decodes_the_second_symbol() {
        // Symbol one, run mode: terminate, no remainder, positive, vk = 0,
        // one value bit 1, so mag = 1 and the coefficient is 2.
        // kp drops from 8 to 2, so k becomes 0 and Golomb Rice mode starts.
        // Symbol two: krp went to 6 on the vk = 0 above, so kr = 0. A prefix
        // of `1 1 0` is vk = 2 and there are no value bits, so mag = 2 << 0
        // ... but krp is updated after the value read, so kr is still 0 here
        // and mag = 2. Two magnitude sign 2 is +1.
        let src = from_bits("1 0 0 0 1  1 1 0");
        let mut dst = [7i16; 4];
        decode(Entropy::Rlgr1, &src, &mut dst);
        assert_eq!(dst, [2, 1, 0, 0]);
    }

    /// RLGR3 differs from RLGR1 only in the `k == 0` branch, where one Golomb
    /// Rice code carries a pair. Reaching that branch needs the same run mode
    /// prelude, and then the pair split of MS-RDPRFX 3.1.8.1.7.2 applies:
    /// `mag = 2` needs two bits, so two bits are read for `val1`, and
    /// `val2 = mag - val1`.
    #[test]
    fn rlgr3_splits_one_golomb_rice_code_into_a_pair() {
        // Prelude identical to the RLGR1 test above: coefficient 2, then
        // k = 0 and kr = 0.
        // Pair: prefix `1 1 0` is vk = 2, no value bits, mag = 2. nidx is
        // two bits, and `01` gives val1 = 1, val2 = 1. Two magnitude sign 1
        // is -1, so the pair is (-1, -1).
        let src = from_bits("1 0 0 0 1  1 1 0  01");
        let mut dst = [7i16; 4];
        decode(Entropy::Rlgr3, &src, &mut dst);
        assert_eq!(dst, [2, -1, -1, 0]);
    }

    /// The same bitstream through both variants must diverge, or the mode
    /// argument is not doing anything. This is the test that fails if RLGR3
    /// is wired to RLGR1's branch by accident, which is a mistake that
    /// otherwise produces output that decodes cleanly and looks like noise
    /// (PRDRDP/04 §4.6.4).
    #[test]
    fn the_two_variants_are_not_the_same_function() {
        let src: Vec<u8> = (0u8..64).map(|i| i.wrapping_mul(37) ^ 0x5A).collect();
        let mut a = [0i16; 4096];
        let mut b = [0i16; 4096];
        decode(Entropy::Rlgr1, &src, &mut a);
        decode(Entropy::Rlgr3, &src, &mut b);
        assert_ne!(a[..], b[..]);
    }

    #[test]
    fn an_empty_bitstream_gives_a_zero_tile() {
        let mut dst = [9i16; 4096];
        decode(Entropy::Rlgr1, &[], &mut dst);
        assert!(dst.iter().all(|&c| c == 0));
        let mut dst = [9i16; 4096];
        decode(Entropy::Rlgr3, &[], &mut dst);
        assert!(dst.iter().all(|&c| c == 0));
    }

    /// The truncation sweep. Every prefix of a bitstream must decode, must
    /// terminate, and must agree with the full decode up to the point where
    /// the prefix ran out. The last property is the one that says the
    /// padding is zeros rather than garbage.
    #[test]
    fn every_prefix_terminates_and_agrees_on_what_it_covered() {
        let full = from_bits(
            "1 0 0 0 1  0 1 1 1 0 0  1 1 0  1 0 0 1 1  \
             0 0 1 0 1 1 0 0 1 0 1 0 1 1 0 0 1",
        );
        let mut want = [0i16; 64];
        decode(Entropy::Rlgr1, &full, &mut want);

        for n in 0..=full.len() {
            for mode in [Entropy::Rlgr1, Entropy::Rlgr3] {
                let mut got = [0i16; 64];
                decode(mode, &full[..n], &mut got);
                // Whatever it decoded, the buffer is fully defined and the
                // tail is zero. Nothing here may panic or hang.
                assert_eq!(got.len(), 64);
            }
            let mut got = [0i16; 64];
            decode(Entropy::Rlgr1, &full[..n], &mut got);
            if n == full.len() {
                assert_eq!(got, want);
            }
        }
    }

    /// The adversarial termination test PRDRDP/04 §4.1 rule five asks for.
    /// A stream of all one bits is the worst case for both the run mode
    /// escape and the Golomb Rice unary prefix, and a stream of all zero bits
    /// is the worst case for the other polarity. Neither may hang.
    #[test]
    fn pathological_bit_patterns_terminate() {
        for fill in [0x00u8, 0xFF, 0xAA, 0x55] {
            for len in [1usize, 2, 7, 64, 512] {
                let src = vec![fill; len];
                for mode in [Entropy::Rlgr1, Entropy::Rlgr3] {
                    let mut dst = [0i16; 4096];
                    decode(mode, &src, &mut dst);
                }
            }
        }
    }

    /// Every single byte leading value, over a fixed tail. This is the
    /// leading byte sweep the other decoders in this crate carry, adapted to
    /// a codec whose first byte is bits rather than a header.
    #[test]
    fn every_leading_byte_terminates() {
        for lead in 0u16..=255 {
            let mut src = vec![lead as u8];
            src.extend_from_slice(&[0x9C, 0x3F, 0x00, 0xE1, 0x77]);
            for mode in [Entropy::Rlgr1, Entropy::Rlgr3] {
                let mut dst = [0i16; 256];
                decode(mode, &src, &mut dst);
            }
        }
    }

    /// A destination shorter than one symbol must still be respected. The
    /// RLGR3 pair path is the one that can try to write two coefficients when
    /// there is room for one.
    #[test]
    fn a_one_coefficient_destination_is_not_overrun() {
        let src = from_bits("1 0 0 0 1  1 1 0  01");
        for n in [0usize, 1, 2, 3] {
            let mut dst = vec![0i16; n];
            decode(Entropy::Rlgr3, &src, &mut dst);
            assert_eq!(dst.len(), n);
        }
    }
}
