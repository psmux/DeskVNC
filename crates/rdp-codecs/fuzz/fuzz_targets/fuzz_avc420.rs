//! AVC420 metablock parsing and the Annex B IDR scan (MS-RDPEGFX 2.2.4.4,
//! 2.2.4.5, PRDRDP/04 §4.10, AGENT_BRIEF D11).
//!
//! No `common::Canvas` here, because nothing in this module writes a pixel:
//! the whole module produces borrowed slices and one boolean. So the
//! properties are about the borrows rather than about a destination.
//!
//! 1. Whatever `parse` accepts is self consistent: the region iterator yields
//!    exactly `len` items, and the two arrays plus the bitstream account for
//!    the whole input with nothing overlapping and nothing lost.
//! 2. The bitstream is a subslice of the input, at the offset the metablock
//!    ends at. If that ever stopped being true, AVC420 would have silently
//!    grown the copy that PRDRDP/04 §4.14 counts it as not having.
//! 3. `contains_idr` terminates on arbitrary bytes. Its start code scanner
//!    skips eight bytes at a time and a skip that overshoots would miss a NAL
//!    rather than crash, so the second half of the target feeds the raw input
//!    to it directly as well, where the fuzzer's own corpus of near start
//!    codes is worth more than any generated one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rdp_codecs::avc420;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = avc420::parse(data) {
        let count = s.len();
        assert_eq!(s.regions().count(), count, "the region arrays disagree");

        // The bitstream must be a borrow of the input, starting exactly where
        // the metablock ends.
        let base = data.as_ptr() as usize;
        let at = s.bitstream.as_ptr() as usize;
        assert!(at >= base, "the bitstream is not inside the input");
        assert_eq!(
            at - base,
            avc420::metablock_len(count),
            "the bitstream does not begin at the end of the metablock"
        );
        assert_eq!(
            avc420::metablock_len(count) + s.bitstream.len(),
            data.len(),
            "the metablock and the bitstream do not account for the input"
        );

        // The damage rectangle must be inside the union of the regions it was
        // built from, which is the property `rdp-core` translates to screen
        // space and clips.
        if let Some(b) = s.bounds() {
            assert!(!b.is_empty(), "an empty damage rectangle was reported");
            for r in s.regions() {
                if r.rect.is_empty() {
                    continue;
                }
                assert!(r.rect.left >= b.left && r.rect.top >= b.top);
                assert!(r.rect.right <= b.right && r.rect.bottom <= b.bottom);
            }
        } else {
            assert!(
                s.regions().all(|r| r.rect.is_empty()),
                "no damage from a non empty region"
            );
        }

        let _ = avc420::contains_idr(s.bitstream);
    }

    // The scanner on its own, over the whole input.
    let _ = avc420::contains_idr(data);
});
