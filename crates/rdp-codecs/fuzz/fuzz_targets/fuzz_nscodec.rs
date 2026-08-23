//! NSCodec, the four plane YCoCg codec (MS-RDPNSC 2.2 and 3.1.8,
//! PRDRDP/04 §4.7, AGENT_BRIEF D11).
//!
//! The header is four plane byte counts, a colour loss level and a
//! subsampling level, all of which the fuzzer reaches by mutating the first
//! eighteen bytes. Three things in there interact badly on purpose:
//!
//! * a plane byte count that equals the plane's uncompressed size switches
//!   that plane to the raw form, so a single byte flips a whole parse;
//! * the subsampling level changes every plane's dimensions, including the
//!   luma padding, so the same payload has to be read at two geometries;
//! * a run length inside a plane can claim more output than the plane has,
//!   or reach into the four raw tail bytes that are never part of a run.
//!
//! Two decodes per execution through one scratch, because the scratch is
//! sized from the previous geometry and a decoder that reads it back without
//! resizing hands out stale pixels.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use rdp_codecs::nscodec::{self, NscScratch};

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut first) = common::Canvas::draw(&mut u) else {
        return;
    };
    let Ok(mut second) = common::Canvas::draw(&mut u) else {
        return;
    };
    let src = u.take_rest();

    let mut scratch = NscScratch::new();
    {
        let mut v = first.view();
        let _ = nscodec::decode(src, &mut scratch, &mut v);
    }
    first.check();
    {
        let mut v = second.view();
        let _ = nscodec::decode(src, &mut scratch, &mut v);
    }
    second.check();

    scratch.reset();
    {
        let mut v = second.view();
        let _ = nscodec::decode(src, &mut scratch, &mut v);
    }
    second.check();
});
