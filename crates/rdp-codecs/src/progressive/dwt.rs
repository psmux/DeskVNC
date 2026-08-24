//! The `RFX_DWT_REDUCE_EXTRAPOLATE` inverse wavelet
//! (MS-RDPEGFX 2.2.4.2.1.4 for the flag, 3.3.7 for the transform).
//!
//! **The plain variant is not here.** A progressive tile whose context did
//! not set `RFX_DWT_REDUCE_EXTRAPOLATE` goes straight through
//! [`crate::remotefx::dwt::inverse_2d`], because it is the same wavelet over
//! the same subband offsets. That is the largest single piece of RemoteFX
//! this codec reuses and it is reused as a call, not as a copy.
//!
//! ## What "reduce extrapolate" changes, and what it does not
//!
//! The lifting steps are unchanged. This module runs the same 1D inverse
//! [`crate::remotefx::dwt`] documents, including the factor of two on the
//! high pass that its module comment argues for at length and that
//! `docs/RDP_SPEC_NOTES.md` §1.2 records as settled only by a vector.
//! **Progressive inherits that uncertainty exactly.** If §1.2 is decided the
//! other way this module is wrong in the same way and by the same factor, and
//! [`tests::the_general_kernel_is_the_remotefx_one_when_the_halves_match`] is
//! what makes that a single edit rather than two.
//!
//! What changes is the length of the two halves. The forward transform
//! extends each 64 sample axis to 65 by extrapolating one sample, which
//! yields 33 low and 32 high, and then discards the last high coefficient,
//! which is where "reduce" comes from. So the inverse is handed 33 low and 31
//! high and has to reconstruct 64 samples.
//!
//! ## Why the discarded coefficient can be discarded
//!
//! This is arithmetic rather than a citation, and it is the reason the edge
//! rules below are what they are. Take the extrapolation to be linear,
//! `X[64] = 2 * X[63] - X[62]`, which is the only extension that makes the
//! word "extrapolate" mean anything for a 5/3 lifting step. Then
//!
//! ```text
//! H[31] = (X[63] - ((X[62] + X[64]) >> 1)) >> 1
//!       = (X[63] - ((X[62] + 2*X[63] - X[62]) >> 1)) >> 1
//!       = (X[63] - X[63]) >> 1
//!       = 0
//! ```
//!
//! identically, for every input. A coefficient that is always zero carries no
//! information, so the encoder drops it and the decoder supplies it. That is
//! the whole content of the flag, and it is why the tail of a level 1 row is
//! written with `H[nh] = 0` while the tails of levels 2 and 3, which are
//! ordinary odd length transforms, use the symmetric extension
//! `H[nh] = H[nh-1]`.
//!
//! **Stated as a reconstruction, not as a transcription** (the standard
//! `docs/RDP_SPEC_NOTES.md` §1.7 sets). MS-RDPEGFX 4.1.2 settles it, and
//! `PRDRDP/09 §2.4.1` warns that that example is small. What
//! supports it meanwhile is that it is forced from three directions at once:
//! it is the only extension for which the dropped coefficient is identically
//! zero, the resulting band sizes are the only ones that sum to 4096 (see
//! [`super::bands`]), and with equal halves the same kernel collapses onto
//! the RemoteFX one that is already in the tree.
//!
//! ## Where the vectorisation is
//!
//! The same split [`crate::remotefx::dwt`] uses and for the same measured
//! reason: the vertical pass is an elementwise pass over whole rows and is
//! written as disjoint slices of proved equal length with no computed index
//! in the body, and the horizontal pass is a stride two interleave over at
//! most 64 samples and is written the simple way. At level 1 the vertical
//! pass is 64 lanes wide and it is where the transform spends its time.

use crate::remotefx::quant::COEFS;

use super::bands::{Band, EXTRAPOLATE};

/// The longest axis a level produces, so the horizontal pass can keep one row
/// of each parity on the stack.
const MAX_ROW: usize = 64;

/// The most low pass coefficients on one axis, at level 1.
const MAX_HALF: usize = 33;

/// One level of the extrapolate inverse, as offsets into the flat buffer.
///
/// Everything here is derived from [`EXTRAPOLATE`] in
/// [`tests::the_level_table_is_derived_from_the_band_table`], so the two
/// cannot drift.
#[derive(Clone, Copy)]
struct Level {
    hl: Band,
    lh: Band,
    hh: Band,
    ll: Band,
    /// Where the `total` by `total` result is written.
    out: usize,
    /// Low pass coefficients per axis.
    nl: usize,
    /// High pass coefficients per axis.
    nh: usize,
}

/// The three levels, coarsest first, which is the order reconstruction runs
/// in and the order that lets each level's output be the next one's LL band.
const LEVELS: [Level; 3] = [
    Level {
        hl: EXTRAPOLATE[6],
        lh: EXTRAPOLATE[7],
        hh: EXTRAPOLATE[8],
        ll: EXTRAPOLATE[9],
        out: 3807,
        nl: 9,
        nh: 8,
    },
    Level {
        hl: EXTRAPOLATE[3],
        lh: EXTRAPOLATE[4],
        hh: EXTRAPOLATE[5],
        ll: Band {
            off: 3807,
            w: 17,
            h: 17,
            q: 0,
        },
        out: 3007,
        nl: 17,
        nh: 16,
    },
    Level {
        hl: EXTRAPOLATE[0],
        lh: EXTRAPOLATE[1],
        hh: EXTRAPOLATE[2],
        ll: Band {
            off: 3007,
            w: 33,
            h: 33,
            q: 0,
        },
        out: 0,
        nl: 33,
        nh: 31,
    },
];

/// The high pass coefficient at index `j` of a half of length `nh`, given
/// that the low half has length `nl`.
///
/// Past the end there are two rules and which one applies is decided by how
/// far apart the halves are, which is the whole difference between an
/// ordinary odd length 5/3 inverse and the reduced extrapolated one:
///
/// * `nl == nh + 1` is an odd length axis with no coefficient dropped, so the
///   extension is the usual whole point symmetry, `H[nh] = H[nh-1]`.
/// * `nl == nh + 2` is the reduced axis, so the missing coefficient is the
///   identically zero one the module comment derives.
/// * `nl == nh` never reads past the end at all.
#[inline]
fn h_at(h: &[i16], j: usize, nl: usize) -> i16 {
    let nh = h.len();
    if j < nh {
        h[j]
    } else if nl == nh + 1 {
        h[nh - 1]
    } else {
        0
    }
}

/// One 1D inverse over `l.len()` low pass and `h.len()` high pass
/// coefficients, producing `l.len() + h.len()` samples of which the last
/// `l.len() - h.len() - 1` are the extrapolated tail and are dropped.
///
/// `out.len()` is `l.len() + h.len()` for every level of both layouts, which
/// is the identity that lets one kernel serve 32 and 32, 9 and 8, 17 and 16,
/// and 33 and 31.
///
/// With `l.len() == h.len()` this is exactly [`crate::remotefx::dwt::row_1d`],
/// which a test asserts rather than assumes.
fn row_1d(l: &[i16], h: &[i16], out: &mut [i16]) {
    let nl = l.len();
    let nh = h.len();
    let total = out.len();
    debug_assert_eq!(total, nl + nh);
    debug_assert!(nl <= MAX_HALF && total <= MAX_ROW);
    debug_assert!(nl == nh || nl == nh + 1 || nl == nh + 2);
    debug_assert!(
        nh >= 1,
        "h_at mirrors h[nh - 1] and no level has an empty half"
    );

    // Even and odd samples are computed into contiguous stack arrays and
    // interleaved afterwards rather than written straight out at stride two.
    // That ordering is not a preference: `remotefx::dwt` measured the obvious
    // one loop form a third slower and its comment records it, and this
    // kernel is the same arithmetic over the same lengths.
    let mut evens = [0i16; MAX_HALF];
    let mut odds = [0i16; MAX_HALF];

    // Even outputs kept, odd outputs, and the evens actually needed: one more
    // than the odds when the low half has one to spare, because the last odd
    // sample averages the even sample past the end of the output.
    let ne = total.div_ceil(2);
    let no = total / 2;
    let n_even = (no + 1).min(nl);

    // The high pass, extended once into a local array rather than through
    // [`h_at`] inside each loop.
    //
    // This is the one optimisation in the module that measured, and it
    // measured large: 5.69 microseconds per tile with `h_at` called per
    // coefficient against 3.43 with the extension materialised, which is 40
    // percent off the whole three level transform. Two branches per
    // coefficient is what the uneven halves cost over the RemoteFX kernel,
    // and 33 `i16` copied once buys all of it back. With that done, the two
    // arithmetic loops below are the same slice pattern shape
    // `remotefx::dwt::row_1d` measured fastest.
    let mut hx = [0i16; MAX_HALF + 1];
    for (j, slot) in hx[..n_even + 1].iter_mut().enumerate() {
        *slot = h_at(h, j, nl);
    }

    // `even[i] = L[i] - ((H[i-1] + H[i]) >> 1)`, with `H[-1] = H[0]`. The
    // first sample is the edge rule and the rest is a two element sliding
    // window destructured with a slice pattern, so the loop body carries no
    // bounds check. That is the exact shape `remotefx::dwt::row_1d` measured
    // fastest and it is used here for the same reason.
    evens[0] = l[0].wrapping_sub(hx[0]);
    for ((ei, &li), w) in evens[1..n_even]
        .iter_mut()
        .zip(&l[1..n_even])
        .zip(hx[..n_even].windows(2))
    {
        let [a, b] = w else { continue };
        *ei = li.wrapping_sub(a.wrapping_add(*b) >> 1);
    }

    // `odd[i] = 2*H[i] + ((even[i] + even[i+1]) >> 1)`, with the bottom edge
    // rule `even[n] = even[n-1]` when the low half ran out. The edge case is
    // pulled out of the loop rather than clamped inside it.
    let flat = no.min(n_even - 1);
    for ((oi, &hv), w) in odds[..flat]
        .iter_mut()
        .zip(&hx[..flat])
        .zip(evens[..n_even].windows(2))
    {
        let [a, b] = w else { continue };
        *oi = hv.wrapping_mul(2).wrapping_add(a.wrapping_add(*b) >> 1);
    }
    for i in flat..no {
        odds[i] = hx[i]
            .wrapping_mul(2)
            .wrapping_add(evens[n_even - 1].wrapping_add(evens[n_even - 1]) >> 1);
    }

    for (c, (&ev, &ov)) in out
        .chunks_exact_mut(2)
        .zip(evens[..no].iter().zip(odds[..no].iter()))
    {
        c[0] = ev;
        c[1] = ov;
    }
    // An odd length output has one more even sample than odd. Levels 2 and 3
    // are 33 and 17 samples wide, so this is not a corner case.
    if ne > no {
        out[total - 1] = evens[ne - 1];
    }
}

/// One row of high pass coefficients, by the same two rules [`h_at`] applies
/// along a row: past the end of the high half an odd length axis mirrors its
/// last row and a reduced axis reads zeros.
#[inline]
#[allow(clippy::too_many_arguments)]
fn h_row<'a>(
    tmp: &'a [i16],
    zeros: &'a [i16],
    nl: usize,
    nh: usize,
    total: usize,
    n: usize,
) -> &'a [i16] {
    if n < nh {
        &tmp[(nl + n) * total..][..total]
    } else if nl == nh + 1 {
        &tmp[(nl + nh - 1) * total..][..total]
    } else {
        &zeros[..total]
    }
}

/// One level of the 2D extrapolate inverse.
///
/// `tmp` holds the horizontal pass output: the vertically low pass `nl` rows
/// first, then the vertically high pass `nh` rows, each `total` wide.
fn level(buf: &mut [i16], tmp: &mut [i16], lv: &Level) {
    let (nl, nh) = (lv.nl, lv.nh);
    let total = nl + nh;
    debug_assert!(tmp.len() >= total * total);

    // Horizontal. LL pairs with HL because HL is the horizontally high pass
    // band, and LH pairs with HH for the same reason one level down.
    //
    // The two halves are split once, outside the loops, so each row is
    // written straight into `tmp` rather than through a stack buffer.
    //
    // The first version went through a `[i16; 64]` and a `copy_from_slice`,
    // and removing that copy **measured no change at all**: 5.50 against
    // 5.69 microseconds per tile, which is inside the run to run swing the
    // bench file's own caveat warns about. It is kept because it is one
    // fewer thing, not because it is faster, and saying so is the point.
    {
        let (lo, hi) = tmp.split_at_mut(nl * total);
        for y in 0..nl {
            let l = &buf[lv.ll.off + y * lv.ll.w..][..nl];
            let h = &buf[lv.hl.off + y * lv.hl.w..][..nh];
            row_1d(l, h, &mut lo[y * total..][..total]);
        }
        for y in 0..nh {
            let l = &buf[lv.lh.off + y * lv.lh.w..][..nl];
            let h = &buf[lv.hh.off + y * lv.hh.w..][..nh];
            row_1d(l, h, &mut hi[y * total..][..total]);
        }
    }

    let ne = total.div_ceil(2);
    let no = total / 2;
    let n_even = (no + 1).min(nl);
    let zeros = [0i16; MAX_ROW];
    // The vertical pass only reads the horizontal pass output, so `tmp` is
    // reborrowed immutably here and `buf` stays mutable alongside it.
    let tmp: &[i16] = tmp;

    // Vertical, even rows. Output row `2n` depends only on input rows `n` and
    // `n-1`, so this is one elementwise pass per output row over three
    // disjoint slices of length `total` with no computed index in the body.
    // This is the wide pass and it is where the level's time goes.
    let mut spare = [0i16; MAX_ROW];
    for n in 0..n_even {
        let l = &tmp[n * total..][..total];
        let hp = h_row(tmp, &zeros, nl, nh, total, n.saturating_sub(1));
        let hc = h_row(tmp, &zeros, nl, nh, total, n);
        if n < ne {
            let out = &mut buf[lv.out + 2 * n * total..][..total];
            for (((o, &lv0), &a), &b) in out.iter_mut().zip(l).zip(hp).zip(hc) {
                *o = lv0.wrapping_sub(a.wrapping_add(b) >> 1);
            }
        } else {
            // The one even sample past the last output row. It is not part of
            // the picture, it is the extrapolated row, and the last odd row
            // still needs it.
            for (((o, &lv0), &a), &b) in spare[..total].iter_mut().zip(l).zip(hp).zip(hc) {
                *o = lv0.wrapping_sub(a.wrapping_add(b) >> 1);
            }
        }
    }

    // Vertical, odd rows. Row `2n+1` reads the two even rows around it, which
    // the pass above already wrote, so the borrows are split rather than
    // aliased: `split_at_mut` twice gives three disjoint slices of one proved
    // length and the loop body carries no bounds check.
    for n in 0..no {
        let hc = h_row(tmp, &zeros, nl, nh, total, n);
        let (before, from_odd) = buf[lv.out..].split_at_mut((2 * n + 1) * total);
        let e0 = &before[2 * n * total..][..total];
        let (out, after) = from_odd.split_at_mut(total);
        if n + 1 < ne {
            let e1 = &after[..total];
            for (((o, &a), &b), &hv) in out.iter_mut().zip(e0).zip(e1).zip(hc) {
                *o = hv.wrapping_mul(2).wrapping_add(a.wrapping_add(b) >> 1);
            }
        } else if n + 1 < n_even {
            let e1 = &spare[..total];
            for (((o, &a), &b), &hv) in out.iter_mut().zip(e0).zip(e1).zip(hc) {
                *o = hv.wrapping_mul(2).wrapping_add(a.wrapping_add(b) >> 1);
            }
        } else {
            // `even[n] = even[n-1]`, so the average of the pair is the row
            // itself and the shift is exact.
            for ((o, &a), &hv) in out.iter_mut().zip(e0).zip(hc) {
                *o = hv.wrapping_mul(2).wrapping_add(a);
            }
        }
    }
}

/// The full three level extrapolate inverse over one component's 4096
/// coefficients (MS-RDPEGFX 3.3.7).
///
/// `tmp` is the caller's reused working buffer and must be at least
/// [`COEFS`] long. Nothing here allocates.
pub fn inverse_2d(buf: &mut [i16], tmp: &mut [i16]) {
    debug_assert!(buf.len() >= COEFS);
    debug_assert!(tmp.len() >= COEFS);
    for lv in &LEVELS {
        level(buf, tmp, lv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The level table must be exactly the band table, or the two can drift
    /// and the offsets stop chaining.
    #[test]
    fn the_level_table_is_derived_from_the_band_table() {
        for (i, lv) in LEVELS.iter().enumerate() {
            let base = 6 - i * 3;
            assert_eq!(lv.hl, EXTRAPOLATE[base]);
            assert_eq!(lv.lh, EXTRAPOLATE[base + 1]);
            assert_eq!(lv.hh, EXTRAPOLATE[base + 2]);
            // The LL band of a level is the previous level's output, and of
            // the coarsest level it is LL3 itself.
            if i == 0 {
                assert_eq!(lv.ll, EXTRAPOLATE[9]);
            } else {
                assert_eq!(lv.ll.off, LEVELS[i - 1].out);
                assert_eq!(lv.ll.w, LEVELS[i - 1].nl + LEVELS[i - 1].nh);
            }
            // Every level fills the buffer from its output offset to the end.
            let total = lv.nl + lv.nh;
            assert_eq!(lv.out + total * total, COEFS);
            // The three detail bands have the sizes the halves force.
            assert_eq!((lv.hl.w, lv.hl.h), (lv.nh, lv.nl));
            assert_eq!((lv.lh.w, lv.lh.h), (lv.nl, lv.nh));
            assert_eq!((lv.hh.w, lv.hh.h), (lv.nh, lv.nh));
        }
    }

    /// With equal halves this kernel and the RemoteFX one are the same
    /// function, sample for sample. That is the test that makes the shared
    /// wavelet reading of `docs/RDP_SPEC_NOTES.md` §1.2 one decision rather
    /// than two: if §1.2 is settled the other way, both modules change and
    /// this test is what proves they changed together.
    #[test]
    fn the_general_kernel_is_the_remotefx_one_when_the_halves_match() {
        for n in [8usize, 16, 32] {
            let l: Vec<i16> = (0..n).map(|i| (i as i16) * 37 - 400).collect();
            let h: Vec<i16> = (0..n).map(|i| 250 - (i as i16) * 61).collect();
            let mut mine = vec![0i16; 2 * n];
            let mut theirs = vec![0i16; 2 * n];
            row_1d(&l, &h, &mut mine);
            crate::remotefx::dwt::row_1d(&l, &h, &mut theirs);
            assert_eq!(mine, theirs, "half length {n}");
        }
    }

    /// A flat signal has no high pass at all, so the inverse hands back the
    /// constant whatever the two half lengths are. This is the DC check and
    /// it catches a wrong sign, a wrong edge rule or a wrong `h_at` branch
    /// immediately.
    #[test]
    fn a_flat_band_reconstructs_flat_at_every_level_shape() {
        for (nl, nh) in [(8usize, 8usize), (9, 8), (17, 16), (33, 31), (32, 32)] {
            let l = vec![100i16; nl];
            let h = vec![0i16; nh];
            let mut out = vec![0i16; nl + nh];
            row_1d(&l, &h, &mut out);
            assert!(
                out.iter().all(|&v| v == 100),
                "halves {nl} and {nh} gave {out:?}"
            );
        }
    }

    /// The whole three level transform on a tile that is flat in LL3 and zero
    /// everywhere else. Every one of the 4096 samples has to be the same
    /// value, which fails if a level reads a band from the wrong offset, uses
    /// the wrong width for a row, or gets a half length wrong.
    #[test]
    fn a_constant_ll3_reconstructs_a_constant_tile() {
        let ll3 = EXTRAPOLATE[9];
        let mut buf = vec![0i16; COEFS];
        for c in &mut buf[ll3.off..ll3.off + ll3.count()] {
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

    /// A single non zero coefficient in the finest horizontal band has to
    /// stay in its own neighbourhood. If the level 1 widths were wrong by one
    /// the energy would smear diagonally across the tile, which is the defect
    /// a flat test cannot see.
    #[test]
    fn one_high_pass_coefficient_stays_local() {
        let mut buf = vec![0i16; COEFS];
        // HH1 is 31 by 31 at 2046. Put a spike at its centre, row 15
        // column 15, which lands near the middle of the tile.
        buf[2046 + 15 * 31 + 15] = 1000;
        let mut tmp = vec![0i16; COEFS];
        inverse_2d(&mut buf, &mut tmp);
        for (i, &v) in buf.iter().enumerate() {
            if v == 0 {
                continue;
            }
            let (x, y) = (i % 64, i / 64);
            assert!(
                x.abs_diff(31) <= 3 && y.abs_diff(31) <= 3,
                "energy at ({x}, {y}) is {v}, which is not local to the spike"
            );
        }
    }

    #[test]
    fn a_zero_tile_stays_zero() {
        let mut buf = vec![0i16; COEFS];
        let mut tmp = vec![0i16; COEFS];
        inverse_2d(&mut buf, &mut tmp);
        assert!(buf.iter().all(|&c| c == 0));
    }

    /// Extreme coefficients must not panic in a debug build with overflow
    /// checks on, which is how the fuzzer runs.
    #[test]
    fn extreme_coefficients_wrap_rather_than_panicking() {
        for fill in [i16::MIN, i16::MAX, -1, 1] {
            let mut buf = vec![fill; COEFS];
            let mut tmp = vec![0i16; COEFS];
            inverse_2d(&mut buf, &mut tmp);
        }
    }
}
