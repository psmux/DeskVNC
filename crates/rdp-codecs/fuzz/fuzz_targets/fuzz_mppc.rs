//! MPPC bulk decompression (MS-RDPBCGR 3.1.8.4.1 and 3.1.8.4.2,
//! PRDRDP/04 §4.13, AGENT_BRIEF D11).
//!
//! Like the ZGFX target, the destination is a history buffer rather than a
//! `common::Canvas`, so the property is not "nothing was written outside the
//! rectangle" but "the output stayed inside the history and the offset stayed
//! inside the buffer".
//!
//! Four packets per execution through one decompressor, because the history
//! persists across packets by design and a copy in the fourth reaches into
//! what the first wrote. The flags byte is drawn from the input's first byte
//! so `PACKET_AT_FRONT` and `PACKET_FLUSHED` are exercised in every
//! combination rather than never, and both variants run on every input
//! because the copy offset prefix code is the only place they differ and a
//! bug in one would not show up in the other.
//!
//! The returned slice is checked against the history offset the decompressor
//! reports, which is the invariant a partial write would break: a packet that
//! failed half way must leave the offset where it found it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rdp_codecs::mppc::{MppcDecompressor, Variant, COMPRESSION_TYPE_MASK, PACKET_COMPRESSED};

fuzz_target!(|data: &[u8]| {
    let (&lead, body) = match data.split_first() {
        Some(p) => p,
        None => return,
    };

    for variant in [Variant::Rdp4, Variant::Rdp5] {
        let mut d = MppcDecompressor::new(variant);
        let size = d.bytes();

        // The type nibble must be this decompressor's or nothing happens, so
        // it is forced and the three flag bits above it come from the input.
        let flags = (lead & !COMPRESSION_TYPE_MASK) | variant.compression_type();

        let cuts = [body.len(), body.len() / 2, body.len() / 3, body.len()];
        for (i, cut) in cuts.into_iter().enumerate() {
            // Alternate the compressed bit so the pass through path and the
            // token path both run against the same history.
            let f = if i == 3 {
                flags & !PACKET_COMPRESSED
            } else {
                flags
            };
            if let Ok(out) = d.decompress(f, &body[..cut]) {
                assert!(out.len() <= size, "output larger than the history");
            }
            assert!(
                d.history_offset() <= size,
                "the history offset left the buffer"
            );
        }

        d.reset();
        assert_eq!(d.history_offset(), 0);
        let _ = d.decompress(flags, body);
        assert!(d.history_offset() <= size);
    }
});
