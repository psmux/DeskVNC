//! The planar codec, all four modes (MS-RDPEGDI 2.2.2.5.1 and 3.1.9.2,
//! PRDRDP/04 §4.5, AGENT_BRIEF D11).
//!
//! The format header byte is the first byte of the payload, so the fuzzer
//! reaches raw, RLE, subsampled and alpha bearing streams by mutating one
//! byte. It is deliberately not drawn through `arbitrary`: a capture of a real
//! planar bitmap appended to a short geometry prefix is then a usable seed.
//!
//! Two decodes per execution, through the same [`PlanarScratch`]. The scratch
//! is the only cross call state in phase 1a (PRDRDP/04 §4.1 rule three), and a
//! decode that grows it, fails partway and leaves stale plane bytes behind is
//! exactly the bug a single shot harness would never see.
//!
//! [`PlanarScratch`]: rdp_codecs::planar::PlanarScratch

#![no_main]

mod common;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use rdp_codecs::planar;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(mut first) = common::Canvas::draw(&mut u) else {
        return;
    };
    let Ok(mut second) = common::Canvas::draw(&mut u) else {
        return;
    };
    let Ok(want_alpha) = bool::arbitrary(&mut u) else {
        return;
    };
    let src = u.take_rest();

    let mut scratch = planar::PlanarScratch::new();
    {
        let mut v = first.view();
        let _ = planar::decode(src, want_alpha, &mut scratch, &mut v);
    }
    first.check();

    // The same scratch, a different geometry, and the alpha decision flipped.
    // A decoder that sized its planes from the previous call rather than from
    // this destination reads stale bytes here.
    {
        let mut v = second.view();
        let _ = planar::decode(src, !want_alpha, &mut scratch, &mut v);
    }
    second.check();

    // `reset` is part of the published state contract, and a reset scratch
    // must still serve a decode.
    scratch.reset();
    {
        let mut v = second.view();
        let _ = planar::decode(src, want_alpha, &mut scratch, &mut v);
    }
    second.check();
});
