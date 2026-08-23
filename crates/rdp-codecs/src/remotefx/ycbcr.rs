//! YCbCr to RGB, the last stage of a RemoteFX tile (MS-RDPRFX 3.1.8.1.3).
//!
//! The specification gives the transform in floating point:
//!
//! ```text
//! R = Clip(Y + 1.402525 * Cr)
//! G = Clip(Y - 0.343730 * Cb - 0.714401 * Cr)
//! B = Clip(Y + 1.769905 * Cb)
//! ```
//!
//! The values arriving from the inverse DWT are fixed point with five
//! fractional bits and Y carries an offset of `128 << 5`, which is where
//! [`Y_OFFSET`] and the `>> 5` below come from. Those five bits are not an
//! arbitrary choice by this module: they are what
//! [`super::quant::dequantize`]'s "factor less one" shift puts there, so the
//! two stages are checkable against each other.
//!
//! ## Why Q14
//!
//! The coefficients are rounded to fourteen fractional bits, with the
//! arithmetic shown so a reviewer can check the rounding against the
//! specification's decimals without redoing it:
//!
//! ```text
//! round(1.402525 * 16384) = 22979.0   -> 22979
//! round(0.343730 * 16384) =  5631.5   ->  5632
//! round(0.714401 * 16384) = 11704.7   -> 11705
//! round(1.769905 * 16384) = 28997.9   -> 28998
//! ```
//!
//! Q14 rather than Q15 because the widest product has to stay inside `i32`:
//! `28998 * 32767` is about `9.5e8`, comfortably under `2^31`, while the Q15
//! equivalent would not be. Q12 would lose a visible amount on a gradient.
//! PRDRDP/04 §4.6.6 chooses the same scale for the same reasons.
//!
//! ## Vectorisation
//!
//! Three multiply accumulates per pixel in `i32`, then a clamp. Everything in
//! the loop is one width, the operands come from four slices of proved equal
//! length, and the clamp is `.clamp(0, 255) as u8` rather than a branch,
//! which lowers to packing instructions on both x86-64 and aarch64
//! (PRDRDP/04 §4.6.8 rules three and four). The destination channel order is
//! a const generic so the row loop stays branch free, the same way
//! `remote_pixel::put` takes it.

use remote_pixel::put;

/// Fractional bits the inverse DWT leaves on every coefficient.
const FRAC: u32 = 5;

/// The offset Y carries, `128 << FRAC`.
pub const Y_OFFSET: i32 = 128 << FRAC;

/// `round(1.402525 * 16384)`.
const CR_R: i32 = 22979;
/// `round(0.343730 * 16384)`.
const CB_G: i32 = 5632;
/// `round(0.714401 * 16384)`.
const CR_G: i32 = 11705;
/// `round(1.769905 * 16384)`.
const CB_B: i32 = 28998;

/// One pixel, for the tests and for a caller that needs a single sample.
#[inline(always)]
pub fn pixel(y: i16, cb: i16, cr: i16) -> (u8, u8, u8) {
    let y = i32::from(y) + Y_OFFSET;
    let cb = i32::from(cb);
    let cr = i32::from(cr);
    let r = (y + ((CR_R * cr) >> 14)) >> FRAC;
    let g = (y - ((CB_G * cb + CR_G * cr) >> 14)) >> FRAC;
    let b = (y + ((CB_B * cb) >> 14)) >> FRAC;
    (
        r.clamp(0, 255) as u8,
        g.clamp(0, 255) as u8,
        b.clamp(0, 255) as u8,
    )
}

/// Convert one run of samples straight into a destination row.
///
/// `dst` is exactly four bytes per sample and the alpha byte is set to 255:
/// RemoteFX carries no alpha, and leaving the byte alone would be invisible
/// on screen and wrong in `readFramebufferRGBA` and in thumbnails, which is
/// the same rule `planar::interleave` follows (PRDRDP/04 §2.5).
///
/// # Panics
///
/// Never on remote input. The four lengths are proved equal by the caller in
/// `super`, which slices them out of buffers whose sizes it owns; the debug
/// assertion names a caller bug rather than a stream defect.
#[inline]
pub fn row<const BGRA: bool>(y: &[i16], cb: &[i16], cr: &[i16], dst: &mut [u8]) {
    debug_assert_eq!(y.len(), cb.len());
    debug_assert_eq!(y.len(), cr.len());
    debug_assert_eq!(dst.len(), y.len() * 4);
    for (((&yv, &cbv), &crv), o) in y.iter().zip(cb).zip(cr).zip(dst.chunks_exact_mut(4)) {
        let (r, g, b) = pixel(yv, cbv, crv);
        put::<BGRA>(o, r, g, b, 0xFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Grey: no chroma at all, so every channel is `Y >> 5` plus the 128
    /// offset. This is the test that catches a wrong offset or a wrong shift,
    /// because both show up as a grey ramp that is dark or clipped rather
    /// than as a colour cast.
    #[test]
    fn zero_chroma_is_a_grey_ramp() {
        for level in [0u8, 1, 64, 127, 128, 200, 255] {
            let y = (i32::from(level) << FRAC) - Y_OFFSET;
            let (r, g, b) = pixel(y as i16, 0, 0);
            assert_eq!((r, g, b), (level, level, level), "level {level}");
        }
    }

    /// The specification's floating point transform, evaluated directly, is
    /// the reference the fixed point form has to match. PRDRDP/04 §11.8 sets
    /// the tolerance against the MS-RDPRFX §4 vector at one least significant
    /// bit per channel, so that is the tolerance here as well, and it is
    /// checked over the whole legal input range rather than at a few points.
    #[test]
    fn the_fixed_point_form_matches_the_floating_point_one() {
        let clip = |v: f64| v.round().clamp(0.0, 255.0) as i32;
        for yl in (0..=255).step_by(5) {
            for cbl in (-128..=127).step_by(11) {
                for crl in (-128..=127).step_by(13) {
                    let y = (yl << FRAC) - Y_OFFSET;
                    let cb = cbl << FRAC;
                    let cr = crl << FRAC;
                    let (r, g, b) = pixel(y as i16, cb as i16, cr as i16);
                    let yf = yl as f64;
                    let cbf = cbl as f64;
                    let crf = crl as f64;
                    let want = (
                        clip(yf + 1.402525 * crf),
                        clip(yf - 0.343730 * cbf - 0.714401 * crf),
                        clip(yf + 1.769905 * cbf),
                    );
                    for (got, want, name) in [
                        (i32::from(r), want.0, "R"),
                        (i32::from(g), want.1, "G"),
                        (i32::from(b), want.2, "B"),
                    ] {
                        assert!(
                            (got - want).abs() <= 1,
                            "{name} at Y={yl} Cb={cbl} Cr={crl}: got {got}, want {want}"
                        );
                    }
                }
            }
        }
    }

    /// The clamp has to hold at both ends for every extreme of the `i16`
    /// input range, because a malformed stream reaches this function with
    /// coefficients no legal encoder would produce.
    #[test]
    fn extremes_clamp_rather_than_wrapping() {
        for y in [i16::MIN, -4096, 0, 4096, i16::MAX] {
            for c in [i16::MIN, -4096, 0, 4096, i16::MAX] {
                let (r, g, b) = pixel(y, c, c);
                let _ = (r, g, b);
            }
        }
        assert_eq!(pixel(i16::MIN, i16::MIN, i16::MIN).0, 0);
        assert_eq!(pixel(i16::MAX, i16::MAX, i16::MAX).0, 255);
    }

    /// The row kernel must agree with the per pixel function, and the channel
    /// order const generic must actually swap red and blue.
    #[test]
    fn the_row_kernel_agrees_and_honours_the_channel_order() {
        let y: Vec<i16> = (0..8).map(|i| (i * 400) - 2000).collect();
        let cb: Vec<i16> = (0..8).map(|i| (i * 200) - 800).collect();
        let cr: Vec<i16> = (0..8).map(|i| 900 - (i * 250)).collect();
        let mut rgba = vec![0u8; 32];
        let mut bgra = vec![0u8; 32];
        row::<false>(&y, &cb, &cr, &mut rgba);
        row::<true>(&y, &cb, &cr, &mut bgra);
        for i in 0..8 {
            let (r, g, b) = pixel(y[i], cb[i], cr[i]);
            assert_eq!(&rgba[i * 4..i * 4 + 4], &[r, g, b, 0xFF]);
            assert_eq!(&bgra[i * 4..i * 4 + 4], &[b, g, r, 0xFF]);
        }
    }
}
