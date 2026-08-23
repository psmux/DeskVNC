//! Virtual channels: static chunking, drdynvc, EGFX and the RDP 8.0
//! segmented bulk data envelope.
//!
//! PRDRDP/13 §6.
//!
//! Four layers, each one wrapped in the one above it. Reading a graphics
//! command off the wire means unwrapping all four, and skipping any of them
//! produces bytes that look like a different protocol (PRDRDP/13 §6.3):
//!
//! ```text
//! MCS Send Data Indication on the channel's id
//!   -> static_vc: CHANNEL_PDU_HEADER, chunks of at most 1600 bytes,
//!      reassembled into one channel PDU              (MS-RDPBCGR 2.2.6.1)
//!   -> dvc: the drdynvc header byte, DATA_FIRST and DATA reassembled into
//!      one dynamic channel message                   (MS-RDPEDYC 2.2)
//!   -> segment: RDP_SEGMENTED_DATA, one or more bulk segments, which
//!      rdp-codecs decompresses                       (MS-RDPEGFX 2.2.5)
//!   -> egfx: a concatenation of RDPGFX_HEADER PDUs   (MS-RDPEGFX 2.2.2)
//! ```
//!
//! Three of those layers reassemble, and all three follow the pattern
//! [`FastPathReassembler`](crate::update::fastpath::FastPathReassembler) set
//! in §5.5: a declared total checked against a cap before anything is
//! reserved, a running total that may not exceed it, and a single fragment
//! message that returns a borrow of the caller's own slice without touching
//! the buffer at all (PRDRDP/13 §10.1).
//!
//! Nothing in this module decides policy. A compressed static channel chunk
//! is an error here because we cannot decompress it and there is no honest
//! value to return; a `DYNVC_DATA_COMPRESSED` is decoded with a flag set and
//! what to do about it is `rdp-core`'s call; an unknown EGFX `cmdId` is
//! preserved because `pduLength` tells us how long it is (PRDRDP/13 §2.7).
//!
//! # What is next door
//!
//! `rdp-codecs` owns everything after the first byte of a codec bitstream:
//! the RDP 8.0 decompressor and its 2.5 MB history window, RemoteFX,
//! ClearCodec, planar, and the H.264 stream behind an
//! [`Avc420Metablock`](egfx::Avc420Metablock). The boundary is
//! [`CompressedSegment`](segment::CompressedSegment) on one side and
//! [`EgfxPdu::WireToSurface1`](egfx::EgfxPdu::WireToSurface1)'s `bitmapData`
//! on the other, and this crate never reads a byte past either
//! (PRDRDP/12 §2.2.2).

pub mod dvc;
pub mod egfx;
pub mod segment;
pub mod static_vc;
