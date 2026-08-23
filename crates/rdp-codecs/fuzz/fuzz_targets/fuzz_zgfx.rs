//! RDP 8.0 bulk decompression (MS-RDPEGFX 2.2.5.1 and MS-RDPBCGR 3.1.8.4.2,
//! PRDRDP/04 §4.12, AGENT_BRIEF D11).
//!
//! The only target here whose destination is a `Vec` rather than a
//! `common::Canvas`, because ZGFX produces bytes rather than pixels. So the
//! property it proves is different: not "nothing was written outside the
//! rectangle" but "the output stayed inside its budget and the history ring
//! index stayed inside the ring".
//!
//! Three decompressions per execution through one decompressor, because the
//! 2.5 MB history persists across calls by design and a match in the third
//! message reaches into what the first one wrote. A decompressor that let a
//! failed message leave its write index past the end of the ring would panic
//! on the next one, and only a multi call harness sees it.
//!
//! The output `Vec` is reused rather than reallocated, which is what
//! `rdp-core` does, so a decompressor that forgot to clear it would show up
//! as unbounded growth here.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rdp_codecs::zgfx::{Rdp8Decompressor, MAX_EGFX_MESSAGE};

fuzz_target!(|data: &[u8]| {
    let mut d = Rdp8Decompressor::new();
    let mut out = Vec::new();

    // Three slices of the same input, so the second and third messages
    // decompress against a history the first one seeded.
    let cuts = [data.len(), data.len() / 2, data.len() / 3];
    for cut in cuts {
        let _ = d.decompress(&data[..cut], &mut out);
        assert!(out.len() <= MAX_EGFX_MESSAGE, "output past its budget");
    }

    d.reset();
    let _ = d.decompress(data, &mut out);
    assert!(out.len() <= MAX_EGFX_MESSAGE, "output past its budget");
});
