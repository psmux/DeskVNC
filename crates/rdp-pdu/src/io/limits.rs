//! The cap table (PRDRDP/13 §2.8).
//!
//! Every cap is a named constant with a comment saying what it protects
//! against and where the number came from.
//! [`PduError::CapExceeded`](crate::PduError::CapExceeded) carries the
//! constant's name so a log line names the knob rather than a bare number.
//!
//! Two kinds of number live here and the difference matters when one is
//! changed. Some are the wire type's own bound restated so the check is
//! visible at the call site (`MAX_TPKT_LEN` is what a `u16` can hold). The
//! rest are ours, chosen larger than anything a real server sends and small
//! enough to bound an allocation. Raising one of ours is a design decision;
//! raising one of the protocol's is a bug.
//!
//! PRDRDP/05 cites this table rather than defining its own caps.

/// TPKT `length` is a big endian `u16` covering the whole packet including
/// the four header bytes (MS-RDPBCGR 2.2.1.1, RFC 1006 §6).
pub const MAX_TPKT_LEN: usize = 65535;

/// The fast path output header's `length2`/`length1` pair carries 15 bits
/// (MS-RDPBCGR 2.2.9.1.2).
pub const MAX_FASTPATH_LEN: usize = 32767;

/// The concatenated GCC user data blocks of a Connect Initial or Connect
/// Response (MS-RDPBCGR 2.2.1.3, 2.2.1.4). Larger than any real one; a server
/// sending more is confused or hostile.
pub const MAX_GCC_USER_DATA: usize = 8192;

/// `TS_UD_CS_NET.channelCount` (MS-RDPBCGR 2.2.1.3.4) states the limit.
pub const MAX_CHANNELS: usize = 31;

/// `TS_UD_CS_MONITOR.monitorCount` (MS-RDPBCGR 2.2.1.3.6) states the limit.
pub const MAX_MONITORS: usize = 16;

/// MS-RDPBCGR 2.2.7 defines about thirty capability sets. Sixty four leaves
/// room for later ones and bounds the loop over `numberCapabilities`.
pub const MAX_CAPABILITY_SETS: usize = 64;

/// One capability set body (MS-RDPBCGR 2.2.7.1). The largest real set is
/// `TS_BITMAPCODECS_CAPABILITYSET` with its codec property blobs.
pub const MAX_CAPSET_LEN: usize = 8192;

/// `TS_UPDATE_BITMAP_DATA.numberRectangles` is a `u16` (MS-RDPBCGR
/// 2.2.9.1.1.3.1.2). Four thousand rects of 64x64 already covers a 4K
/// desktop, so this bounds the `Vec` without bounding any real server.
pub const MAX_BITMAP_RECTS: usize = 4096;

/// One `TS_BITMAP_DATA.bitmapDataStream` (MS-RDPBCGR 2.2.9.1.1.3.1.2.2).
pub const MAX_BITMAP_DATA: usize = 16 * 1024 * 1024;

/// MS-RDPBCGR 2.2.9.1.1.4.7 caps a large pointer at 384 by 384.
pub const MAX_POINTER_DIM: usize = 384;

/// The largest a `TS_COLORPOINTERATTRIBUTE` or `TS_POINTERATTRIBUTE` cursor
/// may be (MS-RDPBCGR 2.2.9.1.1.4.4, 2.2.9.1.1.4.5).
///
/// Only `TS_LARGEPOINTERATTRIBUTE` reaches [`MAX_POINTER_DIM`], and only when
/// the Large Pointer capability set negotiated it (2.2.7.2.7). Both numbers
/// are the specification's own, so raising either is a bug.
pub const MAX_COLOR_POINTER_DIM: usize = 96;

/// The most events this crate will put in, or take out of, one input PDU.
///
/// The fast path count is a byte, so 255 is the wire's own bound
/// (MS-RDPBCGR 2.2.8.1.2, PRDRDP/05 §2.3: "holds 1 to 255 events"). The slow
/// path field is a `u16` and the same cap is applied to it, because the
/// client is the only sender of input and it never batches more than a
/// pointer move plus a handful of edges. It bounds the decoder's `Vec`
/// (PRDRDP/13 §10.1 statement 2).
pub const MAX_INPUT_EVENTS: usize = 255;

/// One `CHANNEL_PDU_HEADER` chunk (MS-RDPBCGR 2.2.6.1.1). The reassembled
/// total is bounded separately by [`MAX_VC_REASSEMBLED`].
pub const MAX_VC_CHUNK: usize = 65535;

/// A reassembled static virtual channel message.
///
/// PRDRDP/00 §3 records a published static virtual channel implementation
/// whose chunk processor reassembles into an unbounded `Vec`. That is a
/// behaviour learned by reading it, in the D3 sense, and never its code. This
/// constant is what stops us repeating it (D11).
pub const MAX_VC_REASSEMBLED: usize = 16 * 1024 * 1024;

/// A reassembled fast path output update (MS-RDPBCGR 2.2.9.1.2.1).
///
/// Its own constant rather than a borrowed [`MAX_VC_REASSEMBLED`], because
/// the two bound different things and one of them is advertised on the wire.
/// This number is what
/// [`MultifragmentUpdateCapabilitySet::client`](crate::rdp::capabilities::MultifragmentUpdateCapabilitySet::client)
/// puts in `MaxRequestSize` (2.2.7.2.6) and what
/// [`FastPathReassembler`](crate::update::fastpath::FastPathReassembler)
/// enforces, and PRDRDP/13 §4.8.3 requires the advertised budget and the
/// enforced one to be the same value: advertising more than we accept invites
/// an update we then refuse, which reads to a user as a server that hangs.
/// The `const` assertion in this file's tests is what keeps the pair honest.
pub const MAX_FASTPATH_REASSEMBLED: usize = 16 * 1024 * 1024;

/// One drdynvc message after reassembly (MS-RDPEDYC 2.2).
pub const MAX_DVC_PDU: usize = 4 * 1024 * 1024;

/// `RDPGFX_HEADER.pduLength` is a `u32` (MS-RDPEGFX 2.2.1.5). A wire to
/// surface command for a 4K surface is far below this.
pub const MAX_EGFX_PDU: usize = 64 * 1024 * 1024;

/// `RDP_SEGMENTED_DATA.segmentCount` is a `u16` (MS-RDPEGFX 2.2.5.1).
pub const MAX_SEGMENT_COUNT: usize = 65535;

/// The declared output size of a bulk compressed blob, checked here before
/// `rdp-codecs` allocates it (MS-RDPEGFX 3.1.9).
pub const MAX_UNCOMPRESSED_SIZE: usize = 64 * 1024 * 1024;

/// The longest string field in any PDU we parse is `UserName` at 512 bytes
/// (MS-RDPBCGR 2.2.10.1.1.1).
pub const MAX_STRING_UTF16: usize = 512;

/// Any one field of `RDP_SERVER_REDIRECTION_PACKET` (MS-RDPBCGR 2.2.13.1).
/// The specification states no cap of its own, which PRDRDP/11 §5.3 records
/// as an erratum.
pub const MAX_REDIRECTION_FIELD: usize = 64 * 1024;

/// `TARGET_NET_ADDRESSES.addressCount` (MS-RDPBCGR 2.2.13.1.1). The field is
/// a `u32` and the specification states no bound; a broker offers one address
/// per network the target is on, so this is ours and bounds the `Vec`. It is
/// also below what [`MAX_REDIRECTION_FIELD`] can hold at the six bytes an
/// empty entry costs, so the byte cap can never be the looser of the two.
pub const MAX_REDIRECTION_ADDRESSES: usize = 64;

/// One `LICENSE_BINARY_BLOB` (MS-RDPBCGR 2.2.1.12.1.2). `wBlobLen` is a
/// `u16`, so this is the wire type's own bound restated: the largest blob a
/// licence server sends is the `ServerCertificate` of a `LICENSE_REQUEST`,
/// which is a certificate chain and still fits.
pub const MAX_LICENSE_BLOB: usize = 65535;

/// `SCOPE_LIST.ScopeCount` (MS-RDPELE 2.2.2.1.1). The field is a `u32` and
/// the specification states no bound; a real licence server offers one or two
/// scopes, so this is ours and bounds the `Vec`.
pub const MAX_LICENSE_SCOPES: usize = 64;

/// `sourceDescriptor` of a Demand Active, Confirm Active or Deactivate All
/// (MS-RDPBCGR 2.2.1.13.1.1). `lengthSourceDescriptor` is a `u16`; every
/// server sends a short ASCII name and mstsc sends `"MSTSC"`, so this is ours.
pub const MAX_SOURCE_DESCRIPTOR: usize = 256;

/// `TS_BITMAPCODECS.bitmapCodecCount` (MS-RDPBCGR 2.2.7.2.10). The field is a
/// `u8`; four codecs are defined and this leaves room without letting a
/// hostile server make us allocate 255 property blobs.
pub const MAX_BITMAP_CODECS: usize = 32;

/// The total entries of a Client Persistent Key List PDU (MS-RDPBCGR
/// 2.2.1.17.1), summed over its five caches. We advertise no persistent cache
/// so we never send one, and we decode it for the mock server; the cap bounds
/// that decode. Each entry is eight bytes.
pub const MAX_PERSISTENT_KEYS: usize = 16384;

/// `CHANNEL_DEF.name` is eight bytes and a dynamic channel name is not
/// bounded by the specification at all (MS-RDPEDYC 2.2.2.1). PRDRDP/05 §5.2
/// fixes the rule we enforce: a name longer than this, or one with no
/// terminator, is a protocol error. The name is NUL terminated inside the
/// PDU, so this bounds the search and the `String` it produces.
pub const MAX_DVC_CHANNEL_NAME: usize = 255;

/// `RDPGFX_SOLIDFILL.rectCount`, `RDPGFX_SURFACE_TO_SURFACE.destPtsCount` and
/// `RDPGFX_CACHE_TO_SURFACE.destPtsCount` are each a `u16` (MS-RDPEGFX
/// 2.2.2.4, 2.2.2.5, 2.2.2.7). Four thousand rectangles in one command is
/// already more than a 4K desktop of 64 by 64 tiles, so this bounds the `Vec`
/// without bounding any real server. Same number and same reasoning as
/// [`MAX_BITMAP_RECTS`].
pub const MAX_EGFX_RECTS: usize = 4096;

/// `RDPGFX_CAPS_ADVERTISE_PDU.capsSetCount` (MS-RDPEGFX 2.2.2.18). Eleven
/// capability versions are defined (2.2.3.1 to 2.2.3.11) and we advertise
/// two, so thirty two leaves room for a newer server's list and bounds the
/// loop.
pub const MAX_EGFX_CAPSETS: usize = 32;

/// One `RDPGFX_CAPSET.capsDataLength` (MS-RDPEGFX 2.2.1.6). Every defined
/// body is four bytes of flags except version 10.1's sixteen reserved bytes
/// (2.2.3.4), so this is ours and is generous by two orders of magnitude.
pub const MAX_EGFX_CAPSET_LEN: usize = 1024;

/// `RDPGFX_CACHE_IMPORT_OFFER_PDU.cacheEntriesCount` and
/// `RDPGFX_CACHE_IMPORT_REPLY_PDU.importedEntriesCount` (MS-RDPEGFX 2.2.2.16,
/// 2.2.2.17). The specification states 5462 for the offer, which is what fits
/// a 65535 byte PDU at twelve bytes an entry, and the reply is bounded by the
/// offer it answers.
pub const MAX_CACHE_IMPORT_ENTRIES: usize = 5462;

/// `RFX_AVC420_METABLOCK.numRegionRects` (MS-RDPEGFX 2.2.4.4). The field is a
/// `u32` and the specification states no bound; the metablock is followed by
/// an H.264 stream and one region rectangle per macroblock row of a 4K frame
/// is far under this, so the number is ours.
pub const MAX_AVC420_REGION_RECTS: usize = 4096;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// The caps that restate a wire type's own bound must equal that bound,
    /// which is the only one of these a test can check.
    #[test]
    fn protocol_bounds_match_their_field_widths() {
        assert_eq!(MAX_TPKT_LEN, u16::MAX as usize);
        assert_eq!(MAX_VC_CHUNK, u16::MAX as usize);
        assert_eq!(MAX_SEGMENT_COUNT, u16::MAX as usize);
        assert_eq!(MAX_FASTPATH_LEN, (1 << 15) - 1);
        assert_eq!(MAX_LICENSE_BLOB, u16::MAX as usize);
        assert_eq!(MAX_INPUT_EVENTS, u8::MAX as usize);
    }

    /// The advertised fast path reassembly budget and the enforced one are
    /// one number. `MaxRequestSize` is a `u32` on the wire, so the cap has to
    /// fit one.
    #[test]
    fn the_fast_path_budget_is_advertisable() {
        assert_eq!(
            crate::rdp::capabilities::MultifragmentUpdateCapabilitySet::client().max_request_size
                as usize,
            MAX_FASTPATH_REASSEMBLED
        );
        assert!(u32::try_from(MAX_FASTPATH_REASSEMBLED).is_ok());
    }

    /// A chunk cannot be larger than the buffer it is reassembled into, and a
    /// bitmap cannot be larger than the segmented blob that may carry it.
    /// Const blocks, so raising one cap and not its neighbour fails the build
    /// rather than a test run.
    #[test]
    fn the_caps_are_ordered_consistently() {
        const { assert!(MAX_VC_CHUNK < MAX_VC_REASSEMBLED) };
        const { assert!(MAX_FASTPATH_LEN < MAX_FASTPATH_REASSEMBLED) };
        const { assert!(MAX_COLOR_POINTER_DIM <= MAX_POINTER_DIM) };
        const { assert!(MAX_BITMAP_DATA <= MAX_UNCOMPRESSED_SIZE) };
        const { assert!(MAX_CAPSET_LEN <= MAX_GCC_USER_DATA) };
        const { assert!(MAX_SOURCE_DESCRIPTOR < MAX_CAPSET_LEN) };
        const { assert!(MAX_DVC_PDU <= MAX_EGFX_PDU) };
        const { assert!(MAX_EGFX_CAPSET_LEN <= MAX_EGFX_PDU) };
    }
}
