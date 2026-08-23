//! ClearCodec, three layers and three caches (MS-RDPEGFX 2.2.4.1 and
//! 3.3.8.1.3, PRDRDP/04 §4.8, AGENT_BRIEF D11).
//!
//! This is the target with real cross call state, so a single shot harness
//! would miss most of what can go wrong. One [`ClearDecoder`] serves several
//! decodes per execution, which is what reaches:
//!
//! * a glyph stored at one geometry and hit at another;
//! * a VBar cache hit against an index nothing ever wrote, and against one
//!   that was written and then lapped by the arena;
//! * a sequence number gap, which must clear the caches and leave the decoder
//!   usable rather than wedged;
//! * `CACHE_RESET` in the middle of all of it.
//!
//! The stream header's first byte is `glyphFlags`, so mutating one byte
//! switches between four completely different parses, and the fuzzer finds
//! that without help.
//!
//! [`ClearDecoder`]: rdp_codecs::clear::ClearDecoder

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use rdp_codecs::clear::ClearDecoder;

fuzz_target!(|data: &[u8]| {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(mut first) = common::Canvas::draw(&mut u) else {
        return;
    };
    let Ok(mut second) = common::Canvas::draw(&mut u) else {
        return;
    };
    let src = u.take_rest();

    let mut dec = ClearDecoder::new();
    for _ in 0..3 {
        {
            let mut v = first.view();
            let _ = dec.decode(src, &mut v);
        }
        first.check();
        {
            let mut v = second.view();
            let _ = dec.decode(src, &mut v);
        }
        second.check();
    }

    // A reset decoder must still serve a decode, and the caches it dropped
    // must not leave a dangling index behind.
    dec.reset();
    {
        let mut v = first.view();
        let _ = dec.decode(src, &mut v);
    }
    first.check();
});
