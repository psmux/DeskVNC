//! Interleaved RLE, at every colour depth it is defined for
//! (MS-RDPBCGR 2.2.9.1.1.3.1.2.4, PRDRDP/04 §4.4, AGENT_BRIEF D11).
//!
//! Every execution runs the same payload at 8, 15, 16 and 24 bits per pixel
//! rather than drawing one depth from the input. The four are genuinely
//! different decoders: the pixel width changes the run arithmetic, the FGBG
//! mask stride and the previous scanline the predictor reads, and 24 bpp is
//! the only one whose pixel is not a machine integer. Drawing the depth would
//! make coverage of the other three a question of whether the fuzzer happened
//! to flip that byte, which is not a question worth leaving open for the cost
//! of three more executions of a decoder this cheap.
//!
//! One drawn byte is fed in as well, so the rejection path for the 252
//! undefined depths is exercised too.
//!
//! The codec is two stages (PRDRDP/04 §11.2), and both are here: the order
//! decode into the wire format scratch, then the conversion into the real
//! destination, which is where the bottom up flip happens.

#![no_main]

mod common;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use rdp_codecs::{rle, uncompressed, PixelFormat};

/// The depths MS-RDPBCGR 2.2.9.1.1.3.1.2.4 defines. There is no 32 bpp form.
const DEPTHS: [u8; 4] = [8, 15, 16, 24];

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(mut canvas) = common::Canvas::draw(&mut u) else {
        return;
    };
    let Ok(pal) = common::palette(&mut u) else {
        return;
    };
    let Ok(undefined) = u8::arbitrary(&mut u) else {
        return;
    };
    let src = u.take_rest();
    let (w, h) = (canvas.width(), canvas.height());

    for bits in DEPTHS.iter().copied().chain([undefined]) {
        let Ok(len) = rle::scratch_len(bits, w, h) else {
            // An undefined depth, rejected before anything was allocated.
            continue;
        };
        let mut scratch = vec![0u8; len];
        if rle::decode_bpp(bits, src, &mut scratch, w, h).is_err() {
            // A failed order decode must not reach the destination, so there
            // is nothing further to check for this depth.
            continue;
        }
        // Stage two. The scratch is tightly packed in wire row order, which is
        // what `src_stride = row_bytes` means here.
        if let Ok(fmt) = PixelFormat::from_legacy_bpp(bits) {
            let stride = fmt.row_bytes(w);
            let mut v = canvas.view();
            let _ = uncompressed::decode(fmt, &scratch, stride, &pal, &mut v);
        }
        canvas.check();
    }
});
