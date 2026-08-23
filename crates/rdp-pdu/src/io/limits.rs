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
    }

    /// A chunk cannot be larger than the buffer it is reassembled into, and a
    /// bitmap cannot be larger than the segmented blob that may carry it.
    /// Const blocks, so raising one cap and not its neighbour fails the build
    /// rather than a test run.
    #[test]
    fn the_caps_are_ordered_consistently() {
        const { assert!(MAX_VC_CHUNK < MAX_VC_REASSEMBLED) };
        const { assert!(MAX_BITMAP_DATA <= MAX_UNCOMPRESSED_SIZE) };
        const { assert!(MAX_CAPSET_LEN <= MAX_GCC_USER_DATA) };
    }
}
