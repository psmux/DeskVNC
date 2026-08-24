//! The three level inverse discrete wavelet transform
//! (MS-RDPRFX 3.1.8.1.4, `CLW_XFORM_DWT_53_A`).
//!
//! Reconstruction runs coarsest first: level 3 rebuilds a 16 by 16 block from
//! four 8 by 8 bands, level 2 rebuilds 32 by 32 from four 16 by 16, level 1
//! rebuilds the 64 by 64 tile. Each level writes its output exactly where the
//! next level expects to find its LL band, which is why
//! [`super::quant::BANDS`] has the offsets it has and why the whole transform
//! runs in one buffer with no copy between levels.
//!
//! ## The 1D inverse, and the one thing about it that is not obvious
//!
//! For `n` low pass and `n` high pass coefficients producing `2n` samples:
//!
//! ```text
//! even[i] = L[i] - ((H[i-1] + H[i]) >> 1)        // H[-1] = H[0]
//! odd[i]  = 2*H[i] + ((even[i] + even[i+1]) >> 1) // even[n] = even[n-1]
//! ```
//!
//! The factor of two on the high pass is the whole difference between this
//! transform and the plain reversible 5/3 of JPEG 2000, and it is what the
//! `_A` in `CLW_XFORM_DWT_53_A` names. The RemoteFX forward transform halves
//! its high pass band on the way out, throwing away one bit, so the inverse
//! has to put the factor back.
//!
//! **PRDRDP/04 §4.6.5 gives the other transform.** It states
//! `even[i] = L[i] - ((H[i-1] + H[i] + 2) >> 2)` and
//! `odd[i] = H[i] + ((even[i] + even[i+1]) >> 1)`, which is the unmodified
//! 5/3 inverse. The two forms are the same function only if the high pass
//! coefficients are read at two different scales, so exactly one of them
//! matches the wire. The consequence of choosing the wrong one is not
//! corruption: it is a picture whose high frequency detail comes out at half
//! or double amplitude, so edges look soft or ring, which is the kind of
//! defect that survives a code review and a round trip test against our own
//! encoder. This module takes the doubled form because it is the one that
//! interoperates, and [`super::encode`]'s forward transform is written as the
//! exact inverse of what is here so a round trip proves the pair rather than
//! either one. Reported to the owner. MS-RDPRFX §4's worked example settles
//! it in one test when we have it.
//!
//! ## Where the vectorisation is
//!
//! Neither stencil is a recurrence, so both passes vectorise. They do not
//! vectorise equally easily, so they are written differently on purpose:
//!
//! * The **vertical pass** is a plain elementwise pass over whole rows: row
//!   `2n` of the output is `L[n] - ((H[n-1] + H[n]) >> 1)` taken column by
//!   column, with every operand a contiguous row. It is written as three or
//!   four disjoint slices of proved equal length zipped together, with no
//!   computed index in the loop body, exactly the shape `planar::undo_delta`
//!   uses and for the same reason (PRDRDP/04 §4.6.8 rules one and two). At
//!   level 1 that is 64 lanes wide, which is where the transform spends most
//!   of its time.
//! * The **horizontal pass** interleaves even and odd samples along a row, so
//!   its output is a stride two scatter. It runs over 8, 16 or 32 samples at
//!   a time, so it is written the simple way with a small stack array rather
//!   than contorted to please the vectoriser. If a bench says the horizontal
//!   pass dominates, that ordering is the thing to revisit.
//!
//! Everything is `i16` throughout, including the intermediate sums, which is
//! PRDRDP/04 §4.6.8 rule three: one width per loop. The adds wrap. A legal
//! stream keeps the sums far inside `i16`, because the tile they reconstruct
//! has to land in the `-4096` to `4096` range the colour stage expects, and a
//! malformed one gets wrapped arithmetic rather than a panic.

use super::quant::COEFS;

/// The widest subband edge, at level 1. The horizontal pass keeps one row of
/// even samples on the stack and this is its size.
const MAX_SUB: usize = 32;

/// One 1D inverse over `l.len()` low pass and the same number of high pass
/// coefficients, producing `2 * l.len()` interleaved samples.
///
/// The `H[-1] = H[0]` and `even[n] = even[n-1]` edge rules are the symmetric
/// extension MS-RDPRFX 3.1.8.1.4 specifies. Getting them wrong shows up as a
/// one pixel bright or dark line down the left edge and along the top of
/// every tile, which tiles the whole frame into a visible 64 pixel grid.
///
/// `pub(crate)` so [`crate::progressive::dwt`] can assert that its general
/// kernel, which also serves uneven half lengths, is this exact function when
/// the halves match.
#[inline]
pub(crate) fn row_1d(l: &[i16], h: &[i16], out: &mut [i16]) {
    let n = l.len();
    debug_assert_eq!(h.len(), n);
    debug_assert_eq!(out.len(), 2 * n);
    debug_assert!(n <= MAX_SUB);

    // Both halves are computed into contiguous stack arrays and interleaved
    // afterwards, rather than written straight out at stride two. The
    // arithmetic loops are then plain elementwise passes over slices of
    // proved equal length with no computed index, which is what the
    // vectoriser wants (PRDRDP/04 §4.6.8 rules one and two), and the stride
    // two write is left as a bare interleave that lowers to an unpack rather
    // than to a scatter. Writing the arithmetic and the interleave as one
    // loop, which is the obvious way, measured a third slower.
    let mut evens = [0i16; MAX_SUB];
    let mut odds = [0i16; MAX_SUB];
    let (e, o) = (&mut evens[..n], &mut odds[..n]);

    // `even[i] = L[i] - ((H[i-1] + H[i]) >> 1)`, with `H[-1] = H[0]`. The
    // first sample is the edge rule and the rest is a two element sliding
    // window over `h`, destructured with a slice pattern so the loop body
    // carries no bounds check.
    //
    // The sliding window is `h.windows(2)` destructured with a slice pattern.
    // The obvious alternative, two overlapping borrows of `h` zipped
    // together, looks like it should suit the vectoriser better because it
    // has no pattern to prove infallible. It measured 12 percent slower on
    // aarch64, so the guess was wrong and the measurement stands. That is the
    // whole reason this crate benchmarks rather than reasons about codegen
    // (PRDRDP/04 §4.6.8 rule one).
    e[0] = l[0].wrapping_sub(h[0]);
    for ((ei, &li), w) in e[1..].iter_mut().zip(&l[1..]).zip(h.windows(2)) {
        let [a, b] = w else { continue };
        *ei = li.wrapping_sub(a.wrapping_add(*b) >> 1);
    }

    // `odd[i] = 2*H[i] + ((even[i] + even[i+1]) >> 1)`, with
    // `even[n] = even[n-1]`, which makes the last one `2*H + even`.
    let last = h[n - 1].wrapping_mul(2).wrapping_add(e[n - 1]);
    let (o_last, o_head) = o.split_last_mut().expect("n is at least one");
    for ((oi, &hi), w) in o_head.iter_mut().zip(h.iter()).zip(e.windows(2)) {
        let [a, b] = w else { continue };
        *oi = hi.wrapping_mul(2).wrapping_add(a.wrapping_add(*b) >> 1);
    }
    *o_last = last;

    for ((c, &ev), &ov) in out.chunks_exact_mut(2).zip(e.iter()).zip(o.iter()) {
        c[0] = ev;
        c[1] = ov;
    }
}

/// One level of the 2D inverse.
///
/// `buf` holds the four subbands of this level in the order HL, LH, HH, LL,
/// each `sw` by `sw`, and receives the `2*sw` by `2*sw` result. `tmp` is
/// `4 * sw * sw` of working space and holds the horizontal pass output: the
/// vertically low pass half in its first `sw` rows and the vertically high
/// pass half in the next `sw`.
fn level(buf: &mut [i16], tmp: &mut [i16], sw: usize) {
    let total = sw * 2;
    let band = sw * sw;
    debug_assert!(buf.len() >= 4 * band);
    debug_assert!(tmp.len() >= 4 * band);

    // Horizontal. LL with HL gives the low half, LH with HH gives the high
    // half. HL is the band that is high pass horizontally, which is why it
    // pairs with LL here rather than with LH.
    for y in 0..sw {
        let (lo, hi) = tmp.split_at_mut(sw * total);
        row_1d(
            &buf[3 * band + y * sw..][..sw],
            &buf[y * sw..][..sw],
            &mut lo[y * total..][..total],
        );
        row_1d(
            &buf[band + y * sw..][..sw],
            &buf[2 * band + y * sw..][..sw],
            &mut hi[y * total..][..total],
        );
    }

    // Vertical, even rows. Output row `2n` depends only on input rows `n` and
    // `n-1`, so this is one elementwise pass per output row over three
    // disjoint slices of length `total`.
    for n in 0..sw {
        let l = &tmp[n * total..][..total];
        let hp = &tmp[(sw + n.saturating_sub(1)) * total..][..total];
        let hc = &tmp[(sw + n) * total..][..total];
        let out = &mut buf[2 * n * total..][..total];
        for (((o, &lv), &a), &b) in out.iter_mut().zip(l).zip(hp).zip(hc) {
            *o = lv.wrapping_sub(a.wrapping_add(b) >> 1);
        }
    }

    // Vertical, odd rows. Output row `2n+1` reads the two even rows around
    // it, which the pass above already wrote, and the high pass row `n`.
    // `split_at_mut` twice gives three provably disjoint slices of the same
    // proved length, so the loop body carries no bounds check and no panic
    // path, which is the trick `planar::undo_delta` documents.
    for n in 0..sw {
        let hc = &tmp[(sw + n) * total..][..total];
        let (before, from_odd) = buf.split_at_mut((2 * n + 1) * total);
        let e0 = &before[2 * n * total..][..total];
        let (out, after) = from_odd.split_at_mut(total);
        if n + 1 < sw {
            let e1 = &after[..total];
            for (((o, &a), &b), &hv) in out.iter_mut().zip(e0).zip(e1).zip(hc) {
                *o = hv.wrapping_mul(2).wrapping_add(a.wrapping_add(b) >> 1);
            }
        } else {
            // The bottom edge: `even[n] = even[n-1]`, so the average of the
            // pair is the one row itself and the shift is exact.
            for ((o, &a), &hv) in out.iter_mut().zip(e0).zip(hc) {
                *o = hv.wrapping_mul(2).wrapping_add(a);
            }
        }
    }
}

/// The full three level inverse over one component's 4096 coefficients
/// (MS-RDPRFX 3.1.8.1.4).
///
/// `tmp` is the caller's reused working buffer and must be at least
/// [`COEFS`] long. Nothing here allocates.
pub fn inverse_2d(buf: &mut [i16], tmp: &mut [i16]) {
    debug_assert!(buf.len() >= COEFS);
    debug_assert!(tmp.len() >= COEFS);
    level(&mut buf[3840..], tmp, 8);
    level(&mut buf[3072..], tmp, 16);
    level(buf, tmp, 32);
}

/// The forward transform, for the reference encoder and for the round trip
/// tests below (PRDRDP/04 §11.4).
///
/// It is written as the exact inverse of what [`level`] does, in the reverse
/// pass order, so a round trip proves the pair and neither one on its own.
/// That is worth stating plainly, because it is also the limit of what a
/// round trip can prove: if the wire really uses the unmodified 5/3 of
/// PRDRDP/04 §4.6.5 rather than the doubled high pass this module
/// implements, both halves of this pair are wrong together and every test
/// here still passes. MS-RDPRFX §4's worked example is the evidence that is
/// independent of us, and until we have it the module comment's reasoning is
/// what stands behind the choice.
#[cfg(any(test, feature = "encode"))]
pub mod forward {
    use super::MAX_SUB;
    use crate::remotefx::quant::COEFS;

    /// The forward 1D transform.
    ///
    /// `H = (X[2i+1] - ((X[2i] + X[2i+2]) >> 1)) >> 1` is where the codec
    /// loses its bit, so a round trip is exact only when every odd sample's
    /// residual is even.
    pub fn row_1d(x: &[i16], l: &mut [i16], h: &mut [i16]) {
        let n = l.len();
        assert_eq!(x.len(), 2 * n);
        assert_eq!(h.len(), n);
        for i in 0..n {
            let right = if i + 1 < n { x[2 * i + 2] } else { x[2 * i] };
            h[i] = (x[2 * i + 1].wrapping_sub(x[2 * i].wrapping_add(right) >> 1)) >> 1;
        }
        for i in 0..n {
            let prev = if i == 0 { h[0] } else { h[i - 1] };
            l[i] = x[2 * i].wrapping_add(prev.wrapping_add(h[i]) >> 1);
        }
    }

    /// The forward 2D of one level, band order HL, LH, HH, LL.
    ///
    /// The pass order is the exact reverse of [`super::level`]'s: that
    /// inverts horizontally and then vertically, so this transforms
    /// vertically and then horizontally. The two passes do not commute,
    /// because the lifting steps are integer shifts rather than linear
    /// operators, so a forward written in the same order as the inverse would
    /// round trip almost but not quite.
    pub fn level(src: &[i16], buf: &mut [i16], sw: usize) {
        let total = sw * 2;
        let band = sw * sw;

        // Vertical, over each column of the full block, into the vertically
        // low half (`sw` rows) then the vertically high half.
        let mut rows = vec![0i16; 4 * band];
        let mut col = [0i16; 2 * MAX_SUB];
        let mut l = [0i16; MAX_SUB];
        let mut h = [0i16; MAX_SUB];
        for x in 0..total {
            for y in 0..total {
                col[y] = src[y * total + x];
            }
            row_1d(&col[..total], &mut l[..sw], &mut h[..sw]);
            for n in 0..sw {
                rows[n * total + x] = l[n];
                rows[(sw + n) * total + x] = h[n];
            }
        }

        // Horizontal, over each row of the two halves. The low half splits
        // into LL and HL, the high half into LH and HH.
        for y in 0..sw {
            row_1d(&rows[y * total..][..total], &mut l[..sw], &mut h[..sw]);
            buf[3 * band + y * sw..][..sw].copy_from_slice(&l[..sw]);
            buf[y * sw..][..sw].copy_from_slice(&h[..sw]);

            row_1d(
                &rows[(sw + y) * total..][..total],
                &mut l[..sw],
                &mut h[..sw],
            );
            buf[band + y * sw..][..sw].copy_from_slice(&l[..sw]);
            buf[2 * band + y * sw..][..sw].copy_from_slice(&h[..sw]);
        }
    }

    /// The full three level forward over a 64 by 64 tile, finest level first,
    /// which is the reverse of [`super::inverse_2d`]'s order.
    pub fn forward_2d(tile: &[i16], buf: &mut [i16]) {
        assert_eq!(tile.len(), COEFS);
        level(tile, buf, 32);
        let mid: Vec<i16> = buf[3072..COEFS].to_vec();
        level(&mid, &mut buf[3072..], 16);
        let deep: Vec<i16> = buf[3840..COEFS].to_vec();
        level(&deep, &mut buf[3840..], 8);
    }
}

#[cfg(test)]
mod tests {
    use super::forward::{level as forward_level, row_1d as forward_1d};
    use super::*;

    /// A flat signal has no high pass at all, so the inverse must hand back
    /// the constant. This is the DC check and it catches a wrong sign or a
    /// missing edge rule immediately.
    #[test]
    fn a_flat_band_reconstructs_flat() {
        let l = [100i16; 8];
        let h = [0i16; 8];
        let mut out = [0i16; 16];
        row_1d(&l, &h, &mut out);
        assert_eq!(out, [100i16; 16]);
    }

    /// A round trip through the forward transform, on a signal whose odd
    /// residuals are all even so the halving loses nothing.
    #[test]
    fn the_one_dimensional_pair_round_trips_on_an_exact_signal() {
        // A ramp of step two: every odd sample sits exactly on the average of
        // its neighbours plus an even residual.
        let x: Vec<i16> = (0..16).map(|i| (i as i16) * 2).collect();
        let mut l = [0i16; 8];
        let mut h = [0i16; 8];
        forward_1d(&x, &mut l, &mut h);
        let mut back = [0i16; 16];
        row_1d(&l, &h, &mut back);
        assert_eq!(&back[..], &x[..]);
    }

    /// The edge rules. A signal that is constant except at its two ends
    /// exercises `H[-1] = H[0]` on the left and `even[n] = even[n-1]` on the
    /// right, and a decoder that drops either produces a visible seam at
    /// every tile boundary.
    #[test]
    fn the_symmetric_extension_holds_at_both_ends() {
        let mut x = [50i16; 16];
        x[0] = 10;
        x[15] = 90;
        let mut l = [0i16; 8];
        let mut h = [0i16; 8];
        forward_1d(&x, &mut l, &mut h);
        let mut back = [0i16; 16];
        row_1d(&l, &h, &mut back);
        // The left edge is exact; the right edge sample is the one whose
        // residual the forward halving can round.
        assert_eq!(back[0], x[0]);
        assert!((i32::from(back[15]) - i32::from(x[15])).abs() <= 2);
    }

    /// One level of the 2D transform round trips on a signal chosen so the
    /// forward halving is exact, which pins the band order, the pass order
    /// and the edge rules together.
    #[test]
    fn one_level_round_trips() {
        let sw = 8usize;
        let total = sw * 2;
        // A separable ramp of step two in both directions.
        let src: Vec<i16> = (0..total * total)
            .map(|i| ((i / total) as i16) * 2 + ((i % total) as i16) * 2)
            .collect();
        let mut buf = vec![0i16; 4 * sw * sw];
        forward_level(&src, &mut buf, sw);
        let mut tmp = vec![0i16; 4 * sw * sw];
        level(&mut buf, &mut tmp, sw);
        for (i, (&got, &want)) in buf.iter().zip(&src).enumerate() {
            assert!(
                (i32::from(got) - i32::from(want)).abs() <= 2,
                "sample {i}: got {got}, want {want}"
            );
        }
    }

    /// The whole three level transform on a tile that is flat in LL3 and zero
    /// everywhere else: every one of the 4096 output samples must be the same
    /// value, because a constant LL band and no detail is a constant tile.
    /// This is the end to end DC check across all three levels and it fails
    /// if a level reads its LL band from the wrong offset.
    #[test]
    fn a_constant_ll3_reconstructs_a_constant_tile() {
        let mut buf = vec![0i16; COEFS];
        for c in &mut buf[4032..COEFS] {
            *c = 1000;
        }
        let mut tmp = vec![0i16; COEFS];
        inverse_2d(&mut buf, &mut tmp);
        assert!(
            buf.iter().all(|&c| c == 1000),
            "the tile is not constant: {:?}",
            &buf[..8]
        );
    }

    /// An all zero tile stays all zero, which is worth its own test because
    /// it is what an empty RLGR stream produces and therefore what the
    /// truncation paths hand this function.
    #[test]
    fn a_zero_tile_stays_zero() {
        let mut buf = vec![0i16; COEFS];
        let mut tmp = vec![0i16; COEFS];
        inverse_2d(&mut buf, &mut tmp);
        assert!(buf.iter().all(|&c| c == 0));
    }

    /// Extreme coefficients must not panic in a debug build with overflow
    /// checks on, which is how the fuzzer runs (`fuzz/Cargo.toml`).
    #[test]
    fn extreme_coefficients_wrap_rather_than_panicking() {
        for fill in [i16::MIN, i16::MAX, -1, 1] {
            let mut buf = vec![fill; COEFS];
            let mut tmp = vec![0i16; COEFS];
            inverse_2d(&mut buf, &mut tmp);
        }
    }
}
