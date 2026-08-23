//! Uncompressed legacy bitmaps and the row conversion behind them
//! (PRDRDP/04 §2.3 and §4.3, AGENT_BRIEF D11).
//!
//! Two entry points, because they fail differently. `decode_legacy` computes
//! the DIB stride and the bottom up order itself, so the only thing an
//! attacker controls there is the depth and the payload. `decode` takes the
//! source stride as an argument, which is the EGFX shape, so it has to survive
//! a stride narrower than one scanline and a stride far larger than the
//! payload.
//!
//! `bits_per_pixel` is drawn as a whole byte rather than picked from the six
//! legal values, because `Format::from_legacy_bpp` rejecting the other 250 is
//! part of what is under test.

#![no_main]

mod common;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use rdp_codecs::{uncompressed, PixelFormat};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(mut canvas) = common::Canvas::draw(&mut u) else {
        return;
    };
    let Ok(pal) = common::palette(&mut u) else {
        return;
    };
    let Ok(bits) = u8::arbitrary(&mut u) else {
        return;
    };
    let Ok(stride_pick) = u8::arbitrary(&mut u) else {
        return;
    };
    let src = u.take_rest();

    // The legacy path: a DIB body with its four byte row padding.
    {
        let mut v = canvas.view();
        let _ = uncompressed::decode_legacy(bits, src, &pal, &mut v);
    }
    canvas.check();

    // The explicit stride path. Half the picks are narrower than a scanline,
    // which must be a `Range` error rather than a short row read, and half are
    // a scanline plus padding, which is the DIB and EGFX case.
    if let Ok(fmt) = PixelFormat::from_legacy_bpp(bits) {
        let row = fmt.row_bytes(canvas.width());
        let half = usize::from(stride_pick >> 1);
        let stride = if stride_pick & 1 == 0 {
            half
        } else {
            row + half
        };
        let mut v = canvas.view();
        let _ = uncompressed::decode(fmt, src, stride, &pal, &mut v);
    }
    canvas.check();
});
