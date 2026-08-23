//! `CHANNEL_PDU_HEADER` and static channel chunking.
//!
//! MS-RDPBCGR 2.2.6.1, PRDRDP/13 §6.1.
//!
//! Static virtual channel data arrives as an MCS Send Data Indication on the
//! channel's own id. Under TLS or CredSSP there is no RDP security header on
//! that body, so it begins directly with [`ChannelPduHeader`] followed by one
//! chunk of the channel PDU (PRDRDP/05 §5.1).
//!
//! The header's `length` is the length of the whole reassembled channel PDU,
//! repeated identically in every chunk and never counting the eight header
//! bytes. That repetition is what lets [`ChannelReassembler`] check the cap
//! on the first chunk, before it reserves anything.
//!
//! Tail rule (PRDRDP/13 §2.5): the chunk runs to the end of the MCS body, so
//! there is no trailing byte to classify. What the header declares is the
//! total across chunks, not the size of this one.

use crate::io::limits::{MAX_VC_CHUNK, MAX_VC_REASSEMBLED};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `CHANNEL_PDU_HEADER.flags` (MS-RDPBCGR 2.2.6.1.1).
pub mod channel_flags {
    /// `CHANNEL_FLAG_FIRST`: the first chunk of a channel PDU.
    pub const FIRST: u32 = 0x0000_0001;
    /// `CHANNEL_FLAG_LAST`: the last chunk. A one chunk PDU sets both.
    pub const LAST: u32 = 0x0000_0002;
    /// `CHANNEL_FLAG_SHOW_PROTOCOL`: hand the header to the channel handler
    /// rather than stripping it. We parse the header either way, so the flag
    /// is tolerated and ignored (PRDRDP/05 §5.1).
    pub const SHOW_PROTOCOL: u32 = 0x0000_0010;
    /// `CHANNEL_FLAG_SUSPEND`. Ignored.
    pub const SUSPEND: u32 = 0x0000_0020;
    /// `CHANNEL_FLAG_RESUME`. Ignored.
    pub const RESUME: u32 = 0x0000_0040;
    /// `CHANNEL_FLAG_SHADOW_PERSISTENT`. Ignored.
    pub const SHADOW_PERSISTENT: u32 = 0x0000_0080;
    /// `CHANNEL_PACKET_COMPRESSED`: the chunk is bulk compressed. We never
    /// set `CHANNEL_OPTION_COMPRESS_RDP`, so this arriving means the server
    /// ignored our declaration (PRDRDP/05 §5.1 rule 1).
    pub const PACKET_COMPRESSED: u32 = 0x0020_0000;
    /// `CHANNEL_PACKET_AT_FRONT`: a compression history hint for
    /// `rdp-codecs` (PRDRDP/13 §7).
    pub const PACKET_AT_FRONT: u32 = 0x0040_0000;
    /// `CHANNEL_PACKET_FLUSHED`: the other compression history hint.
    pub const PACKET_FLUSHED: u32 = 0x0080_0000;
    /// `CompressionTypeMask`, holding a
    /// [`CompressionType`](crate::codes::CompressionType) shifted left by
    /// [`COMPRESSION_TYPE_SHIFT`].
    pub const COMPRESSION_TYPE_MASK: u32 = 0x000F_0000;
    /// How far left the compression type sits inside `flags`. The fast path
    /// keeps the same four bits in the low nibble of a byte (2.2.9.1.2.1),
    /// which is why the shift is spelled out here rather than assumed.
    pub const COMPRESSION_TYPE_SHIFT: u32 = 16;
}

/// `CHANNEL_CHUNK_LENGTH`, the chunk size MS-RDPBCGR 3.1.5.2 fixes as the
/// default when the server's Virtual Channel capability set (2.2.7.1.10) does
/// not name one.
pub const CHANNEL_CHUNK_LENGTH: usize = 1600;

/// The smallest `VCChunkSize` we will honour from a server, which is the
/// default itself (PRDRDP/05 §5.1).
pub const MIN_VC_CHUNK_SIZE: usize = 1600;

/// The largest `VCChunkSize` we will honour from a server (PRDRDP/05 §5.1).
/// Above this the value is treated as absent and [`CHANNEL_CHUNK_LENGTH`] is
/// used instead.
pub const MAX_VC_CHUNK_SIZE: usize = 16256;

/// `CHANNEL_PDU_HEADER` (MS-RDPBCGR 2.2.6.1.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelPduHeader {
    /// The length of the whole reassembled channel PDU, excluding every
    /// chunk's own eight header bytes and repeated identically in each chunk.
    pub length: u32,
    /// [`channel_flags`].
    pub flags: u32,
}

impl ChannelPduHeader {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "CHANNEL_PDU_HEADER";

    /// Eight bytes, always.
    pub const LEN: usize = 8;

    /// The header of a channel PDU that fits in one chunk.
    #[must_use]
    pub const fn single(length: u32) -> Self {
        Self {
            length,
            flags: channel_flags::FIRST | channel_flags::LAST,
        }
    }

    /// `CHANNEL_FLAG_FIRST`.
    #[must_use]
    pub const fn is_first(&self) -> bool {
        self.flags & channel_flags::FIRST != 0
    }

    /// `CHANNEL_FLAG_LAST`.
    #[must_use]
    pub const fn is_last(&self) -> bool {
        self.flags & channel_flags::LAST != 0
    }

    /// `CHANNEL_PACKET_COMPRESSED`.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags & channel_flags::PACKET_COMPRESSED != 0
    }

    /// The bulk compression type in `CompressionTypeMask`, meaningful only
    /// when [`ChannelPduHeader::is_compressed`] is true (PRDRDP/13 §7).
    #[must_use]
    pub fn compression_type(&self) -> crate::codes::CompressionType {
        let nibble = (self.flags & channel_flags::COMPRESSION_TYPE_MASK)
            >> channel_flags::COMPRESSION_TYPE_SHIFT;
        crate::codes::CompressionType::from_u8(nibble as u8)
    }
}

impl Decode<'_> for ChannelPduHeader {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            length: r.u32(Self::NAME)?,
            flags: r.u32(Self::NAME)?,
        })
    }
}

impl Encode for ChannelPduHeader {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.length);
        w.u32(self.flags);
        Ok(())
    }
}

/// One chunk on the wire: the header and the bytes that follow it, borrowed
/// from the receive buffer (MS-RDPBCGR 2.2.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelChunk<'a> {
    /// The chunk's header.
    pub header: ChannelPduHeader,
    /// This chunk's slice of the channel PDU. Not the whole PDU unless the
    /// header sets both `FIRST` and `LAST`.
    pub data: Payload<'a>,
}

impl<'a> ChannelChunk<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "CHANNEL_PDU";
}

impl<'a> Decode<'a> for ChannelChunk<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let header = ChannelPduHeader::decode(r)?;
        let data = r.rest();
        r.ensure_cap(data.len(), MAX_VC_CHUNK, "MAX_VC_CHUNK", Self::NAME)?;
        Ok(Self {
            header,
            data: Payload::new(data),
        })
    }
}

impl Encode for ChannelChunk<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        ChannelPduHeader::LEN + self.data.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        self.header.encode(w)?;
        w.bytes(self.data.as_slice());
        Ok(())
    }
}

/// Split a whole channel PDU into chunks of at most `chunk_size` bytes.
///
/// Every chunk carries the same `length` (the total), the first carries
/// `CHANNEL_FLAG_FIRST`, the last carries `CHANNEL_FLAG_LAST`, and a PDU that
/// fits in one chunk carries both (MS-RDPBCGR 2.2.6.1, PRDRDP/05 §5.1). An
/// empty payload still produces one chunk, because a zero length channel PDU
/// is a message the handler above is entitled to send.
///
/// `chunk_size` is clamped into [`MIN_VC_CHUNK_SIZE`] to [`MAX_VC_CHUNK_SIZE`]
/// so a caller cannot ask for a one byte chunk and turn a paste into a
/// million MCS PDUs. Choosing the number from the server's capability set is
/// `rdp-core`'s job, not this function's.
#[must_use]
pub fn chunk_channel_pdu(payload: &[u8], chunk_size: usize) -> ChannelChunks<'_> {
    ChannelChunks {
        total: payload.len(),
        rest: payload,
        chunk_size: chunk_size.clamp(MIN_VC_CHUNK_SIZE, MAX_VC_CHUNK_SIZE),
        first: true,
        done: false,
    }
}

/// The iterator [`chunk_channel_pdu`] returns.
#[derive(Debug, Clone, Copy)]
pub struct ChannelChunks<'a> {
    total: usize,
    rest: &'a [u8],
    chunk_size: usize,
    first: bool,
    done: bool,
}

impl<'a> Iterator for ChannelChunks<'a> {
    type Item = ChannelChunk<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let take = self.rest.len().min(self.chunk_size);
        let (head, tail) = self.rest.split_at(take);
        self.rest = tail;
        let mut flags = 0;
        if self.first {
            flags |= channel_flags::FIRST;
            self.first = false;
        }
        if self.rest.is_empty() {
            flags |= channel_flags::LAST;
            self.done = true;
        }
        Some(ChannelChunk {
            header: ChannelPduHeader {
                // `total` is the caller's own buffer length, so the cast is
                // lossless on every target this crate builds for. A payload
                // above `u32::MAX` cannot reach here: the caller is bounded
                // by MAX_VC_REASSEMBLED long before it gets a chunker.
                length: self.total.min(u32::MAX as usize) as u32,
                flags,
            },
            data: Payload::new(head),
        })
    }
}

/// Reassembles a static virtual channel PDU from its chunks.
///
/// One instance per channel, held by `rdp-core`'s channel map. The rules, in
/// the order PRDRDP/05 §5.1 states them and the order [`Self::push`] checks
/// them:
///
/// 1. `CHANNEL_PACKET_COMPRESSED` on any chunk is
///    [`PduError::Unsupported`]. We decline `CHANNEL_OPTION_COMPRESS_RDP` in
///    every phase, so a compressed chunk means the server ignored the
///    declaration and there is nothing honest to hand the handler.
/// 2. `CHANNEL_FLAG_FIRST` while a reassembly is in progress is an error, and
///    so is a chunk without it while nothing is in progress.
/// 3. On the first chunk `length` is checked against
///    [`MAX_VC_REASSEMBLED`] before anything is
///    reserved, and the reservation is `min(length, 64 KiB)` so a lying
///    header buys nothing.
/// 4. Every chunk is checked against the declared `length`: the running total
///    may never exceed it, `length` may not change mid message, and `LAST`
///    must bring the total to exactly it.
/// 5. A chunk with both `FIRST` and `LAST` never touches the buffer. It
///    returns a borrow of the caller's own slice, which is the D9 zero copy
///    invariant applied to the case that covers nearly all clipboard and
///    dynamic channel traffic (PRDRDP/13 §10.1).
#[derive(Debug, Default)]
pub struct ChannelReassembler {
    buf: Vec<u8>,
    /// The `length` every chunk of the message in progress must repeat, and
    /// the total the last one must reach. `None` when nothing is in progress.
    expected: Option<usize>,
    cap: usize,
}

impl ChannelReassembler {
    /// The name errors from this type carry.
    pub const NAME: &'static str = "CHANNEL_PDU reassembly";

    /// The reservation made on the first chunk, whatever the header declared.
    /// A legitimate 8 MiB clipboard PDU grows into its buffer rather than
    /// forcing an 8 MiB reservation from a header that might be lying
    /// (PRDRDP/05 §5.1 rule 3).
    pub const FIRST_RESERVE: usize = 64 * 1024;

    /// A reassembler capped at [`MAX_VC_REASSEMBLED`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(MAX_VC_REASSEMBLED)
    }

    /// A reassembler with a smaller cap than the crate wide one.
    ///
    /// PRDRDP/05 §5.1 gives each static channel its own number (`cliprdr`
    /// 16 MiB, `drdynvc` 4 MiB, `rdpsnd` 256 KiB), and choosing between them
    /// is the channel map's job. The cap is clamped down to
    /// [`MAX_VC_REASSEMBLED`], so no caller can raise it.
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            expected: None,
            cap: cap.min(MAX_VC_REASSEMBLED),
        }
    }

    /// True while a `CHANNEL_FLAG_FIRST` has been seen and its `LAST` has
    /// not.
    #[must_use]
    pub const fn in_progress(&self) -> bool {
        self.expected.is_some()
    }

    /// Bytes accumulated so far, which is zero unless a multi chunk message
    /// is in progress.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Drop any partial reassembly, keeping the buffer for the next message.
    /// The session calls this when the channel is torn down or the connection
    /// is reactivated (PRDRDP/05 §5.1 rule 6).
    pub fn reset(&mut self) {
        self.buf.clear();
        self.expected = None;
    }

    /// Feed one chunk, returning the whole channel PDU on the chunk carrying
    /// `CHANNEL_FLAG_LAST`.
    pub fn push<'a>(
        &'a mut self,
        header: ChannelPduHeader,
        chunk: &'a [u8],
    ) -> PduResult<Option<&'a [u8]>> {
        if header.is_compressed() {
            return Err(PduError::Unsupported {
                context: Self::NAME,
                kind: "CHANNEL_PACKET_COMPRESSED",
                value: u64::from(header.flags),
                offset: 0,
            });
        }
        let declared = header.length as usize;

        if header.is_first() {
            if self.in_progress() {
                return Err(PduError::InvalidField {
                    context: Self::NAME,
                    field: "CHANNEL_FLAG_FIRST while a reassembly is in progress",
                    value: u64::from(header.flags),
                    offset: self.buf.len(),
                });
            }
            // Rule 3: the cap is checked here, before a byte is reserved.
            if declared > self.cap {
                return Err(PduError::CapExceeded {
                    context: Self::NAME,
                    declared,
                    cap: self.cap,
                    limit_name: "MAX_VC_REASSEMBLED",
                    offset: 0,
                });
            }
            if chunk.len() > declared {
                return Err(PduError::LengthMismatch {
                    context: Self::NAME,
                    declared,
                    actual: chunk.len(),
                    offset: 0,
                });
            }
            if header.is_last() {
                // Rule 5. The whole PDU is here, so nothing is copied.
                if chunk.len() != declared {
                    return Err(PduError::LengthMismatch {
                        context: Self::NAME,
                        declared,
                        actual: chunk.len(),
                        offset: 0,
                    });
                }
                return Ok(Some(chunk));
            }
            self.buf.clear();
            self.buf.reserve(declared.min(Self::FIRST_RESERVE));
            self.buf.extend_from_slice(chunk);
            self.expected = Some(declared);
            return Ok(None);
        }

        let Some(expected) = self.expected else {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "chunk without a preceding CHANNEL_FLAG_FIRST",
                value: u64::from(header.flags),
                offset: 0,
            });
        };
        if declared != expected {
            return Err(PduError::LengthMismatch {
                context: Self::NAME,
                declared,
                actual: expected,
                offset: self.buf.len(),
            });
        }
        let total = self.buf.len().saturating_add(chunk.len());
        if total > expected {
            return Err(PduError::LengthMismatch {
                context: Self::NAME,
                declared: expected,
                actual: total,
                offset: self.buf.len(),
            });
        }
        self.buf.extend_from_slice(chunk);
        if !header.is_last() {
            return Ok(None);
        }
        if self.buf.len() != expected {
            let actual = self.buf.len();
            self.reset();
            return Err(PduError::LengthMismatch {
                context: Self::NAME,
                declared: expected,
                actual,
                offset: 0,
            });
        }
        self.expected = None;
        Ok(Some(&self.buf))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn header_bytes(length: u32, flags: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        ChannelPduHeader { length, flags }
            .encode_checked(&mut Writer::new(&mut buf))
            .unwrap();
        buf
    }

    #[test]
    fn channel_pdu_header_round_trip() {
        let value = ChannelPduHeader {
            length: 0x0001_2345,
            flags: channel_flags::FIRST | channel_flags::SHOW_PROTOCOL,
        };
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size());
        assert_eq!(
            ChannelPduHeader::decode(&mut Reader::new(&buf)).unwrap(),
            value
        );
    }

    /// The field order and endianness, stated as bytes so a transposed pair
    /// fails here rather than against a Windows server.
    #[test]
    fn channel_pdu_header_golden() {
        let bytes = header_bytes(0x0000_0400, channel_flags::FIRST | channel_flags::LAST);
        assert_eq!(bytes, [0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn channel_pdu_header_truncated_at_every_prefix_errors() {
        let full = header_bytes(9, channel_flags::FIRST);
        for cut in 0..full.len() {
            assert!(
                ChannelPduHeader::decode(&mut Reader::new(&full[..cut])).is_err(),
                "prefix of {cut} bytes decoded"
            );
        }
    }

    #[test]
    fn a_chunk_carries_its_payload_without_copying_it() {
        let frame = bytes::Bytes::from_static(&[
            0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, b'a', b'b', b'c',
        ]);
        let chunk = ChannelChunk::decode(&mut Reader::new(&frame)).unwrap();
        assert_eq!(chunk.header.length, 3);
        assert!(chunk.header.is_first() && chunk.header.is_last());
        assert_eq!(chunk.data.as_slice(), b"abc");
        let owned = chunk.data.to_bytes(&frame);
        assert_eq!(
            owned.as_ptr() as usize - frame.as_ptr() as usize,
            ChannelPduHeader::LEN
        );
    }

    #[test]
    fn chunk_round_trips_and_truncates() {
        let value = ChannelChunk {
            header: ChannelPduHeader::single(4),
            data: Payload::new(b"wxyz"),
        };
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size());
        assert_eq!(ChannelChunk::decode(&mut Reader::new(&buf)).unwrap(), value);
        // Only the header can truncate: the payload runs to the end of the
        // MCS body, so a short payload is a short payload and not an error.
        for cut in 0..ChannelPduHeader::LEN {
            assert!(ChannelChunk::decode(&mut Reader::new(&buf[..cut])).is_err());
        }
    }

    #[test]
    fn compression_type_comes_out_of_the_mask() {
        let header = ChannelPduHeader {
            length: 0,
            flags: channel_flags::PACKET_COMPRESSED
                | (0x1 << channel_flags::COMPRESSION_TYPE_SHIFT),
        };
        assert!(header.is_compressed());
        assert_eq!(
            header.compression_type(),
            crate::codes::CompressionType::Mppc64K
        );
    }

    #[test]
    fn one_chunk_is_returned_without_touching_the_buffer() {
        let mut re = ChannelReassembler::new();
        let payload = b"a whole clipboard response";
        let out = re
            .push(
                ChannelPduHeader::single(payload.len() as u32),
                payload.as_slice(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(out.as_ptr(), payload.as_ptr(), "single chunk was copied");
        assert!(!re.in_progress());
        assert_eq!(re.buffered(), 0);
    }

    #[test]
    fn a_message_split_across_three_chunks_reassembles() {
        let mut re = ChannelReassembler::new();
        let total = 9u32;
        assert!(re
            .push(
                ChannelPduHeader {
                    length: total,
                    flags: channel_flags::FIRST
                },
                b"abc"
            )
            .unwrap()
            .is_none());
        assert!(re
            .push(
                ChannelPduHeader {
                    length: total,
                    flags: 0
                },
                b"def"
            )
            .unwrap()
            .is_none());
        let out = re
            .push(
                ChannelPduHeader {
                    length: total,
                    flags: channel_flags::LAST,
                },
                b"ghi",
            )
            .unwrap()
            .unwrap();
        assert_eq!(out, b"abcdefghi");
        assert!(!re.in_progress());
    }

    #[test]
    fn a_total_larger_than_the_cap_is_refused_on_the_first_chunk() {
        let mut re = ChannelReassembler::new();
        let err = re
            .push(
                ChannelPduHeader {
                    length: (MAX_VC_REASSEMBLED + 1) as u32,
                    flags: channel_flags::FIRST,
                },
                b"x",
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_VC_REASSEMBLED",
                ..
            }
        ));
        assert_eq!(re.buffered(), 0, "the buffer grew before the cap check");
    }

    #[test]
    fn a_per_channel_cap_can_be_smaller_and_never_larger() {
        let mut re = ChannelReassembler::with_cap(1024);
        assert!(re
            .push(
                ChannelPduHeader {
                    length: 2048,
                    flags: channel_flags::FIRST
                },
                b"x"
            )
            .is_err());
        let wide = ChannelReassembler::with_cap(usize::MAX);
        assert_eq!(wide.cap, MAX_VC_REASSEMBLED);
    }

    #[test]
    fn a_first_chunk_after_a_first_chunk_is_an_error() {
        let mut re = ChannelReassembler::new();
        let first = ChannelPduHeader {
            length: 6,
            flags: channel_flags::FIRST,
        };
        assert!(re.push(first, b"abc").unwrap().is_none());
        assert!(matches!(
            re.push(first, b"def").unwrap_err(),
            PduError::InvalidField { .. }
        ));
    }

    #[test]
    fn a_continuation_without_a_first_is_an_error() {
        let mut re = ChannelReassembler::new();
        assert!(matches!(
            re.push(
                ChannelPduHeader {
                    length: 3,
                    flags: channel_flags::LAST
                },
                b"abc"
            )
            .unwrap_err(),
            PduError::InvalidField { .. }
        ));
    }

    #[test]
    fn the_declared_total_must_not_change_between_chunks() {
        let mut re = ChannelReassembler::new();
        assert!(re
            .push(
                ChannelPduHeader {
                    length: 6,
                    flags: channel_flags::FIRST
                },
                b"abc"
            )
            .unwrap()
            .is_none());
        assert!(matches!(
            re.push(
                ChannelPduHeader {
                    length: 7,
                    flags: channel_flags::LAST
                },
                b"def"
            )
            .unwrap_err(),
            PduError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn overrunning_the_declared_total_is_an_error() {
        let mut re = ChannelReassembler::new();
        assert!(re
            .push(
                ChannelPduHeader {
                    length: 4,
                    flags: channel_flags::FIRST
                },
                b"ab"
            )
            .unwrap()
            .is_none());
        assert!(matches!(
            re.push(
                ChannelPduHeader {
                    length: 4,
                    flags: 0
                },
                b"cde"
            )
            .unwrap_err(),
            PduError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn a_last_chunk_that_falls_short_of_the_total_is_an_error() {
        let mut re = ChannelReassembler::new();
        assert!(re
            .push(
                ChannelPduHeader {
                    length: 9,
                    flags: channel_flags::FIRST
                },
                b"abc"
            )
            .unwrap()
            .is_none());
        assert!(matches!(
            re.push(
                ChannelPduHeader {
                    length: 9,
                    flags: channel_flags::LAST
                },
                b"de"
            )
            .unwrap_err(),
            PduError::LengthMismatch { .. }
        ));
        assert!(!re.in_progress(), "a failed message stayed in progress");
    }

    #[test]
    fn a_single_chunk_whose_total_disagrees_with_its_payload_is_an_error() {
        let mut re = ChannelReassembler::new();
        assert!(matches!(
            re.push(ChannelPduHeader::single(4), b"abc").unwrap_err(),
            PduError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn a_compressed_chunk_is_refused_rather_than_delivered() {
        let mut re = ChannelReassembler::new();
        let err = re
            .push(
                ChannelPduHeader {
                    length: 3,
                    flags: channel_flags::FIRST
                        | channel_flags::LAST
                        | channel_flags::PACKET_COMPRESSED,
                },
                b"abc",
            )
            .unwrap_err();
        assert!(matches!(
            err,
            PduError::Unsupported {
                kind: "CHANNEL_PACKET_COMPRESSED",
                ..
            }
        ));
    }

    #[test]
    fn show_protocol_and_the_history_hints_are_tolerated() {
        let mut re = ChannelReassembler::new();
        let out = re
            .push(
                ChannelPduHeader {
                    length: 3,
                    flags: channel_flags::FIRST
                        | channel_flags::LAST
                        | channel_flags::SHOW_PROTOCOL
                        | channel_flags::SUSPEND
                        | channel_flags::RESUME
                        | channel_flags::SHADOW_PERSISTENT
                        | channel_flags::PACKET_AT_FRONT
                        | channel_flags::PACKET_FLUSHED,
                },
                b"abc",
            )
            .unwrap();
        assert_eq!(out, Some(&b"abc"[..]));
    }

    #[test]
    fn reset_drops_a_partial_message() {
        let mut re = ChannelReassembler::new();
        assert!(re
            .push(
                ChannelPduHeader {
                    length: 6,
                    flags: channel_flags::FIRST
                },
                b"abc"
            )
            .unwrap()
            .is_none());
        re.reset();
        assert!(!re.in_progress());
        assert!(re
            .push(ChannelPduHeader::single(3), b"xyz")
            .unwrap()
            .is_some());
    }

    #[test]
    fn the_chunker_and_the_reassembler_are_inverses() {
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut re = ChannelReassembler::new();
        let mut chunks = 0;
        let mut done = None;
        for chunk in chunk_channel_pdu(&payload, CHANNEL_CHUNK_LENGTH) {
            chunks += 1;
            assert_eq!(chunk.header.length as usize, payload.len());
            assert!(chunk.data.len() <= CHANNEL_CHUNK_LENGTH);
            if let Some(out) = re.push(chunk.header, chunk.data.as_slice()).unwrap() {
                done = Some(out.to_vec());
            }
        }
        assert_eq!(chunks, 4, "5000 bytes at 1600 is four chunks");
        assert_eq!(done.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn a_payload_that_fits_produces_one_chunk_flagged_first_and_last() {
        let chunks: Vec<_> = chunk_channel_pdu(b"short", CHANNEL_CHUNK_LENGTH).collect();
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].header.is_first() && chunks[0].header.is_last());
        assert_eq!(chunks[0].header.length, 5);
    }

    #[test]
    fn an_empty_payload_still_produces_one_chunk() {
        let chunks: Vec<_> = chunk_channel_pdu(&[], CHANNEL_CHUNK_LENGTH).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].header.length, 0);
        assert!(chunks[0].data.is_empty());
    }

    #[test]
    fn an_absurd_chunk_size_is_clamped_rather_than_honoured() {
        let payload = [0u8; 4000];
        assert_eq!(chunk_channel_pdu(&payload, 1).count(), 3);
        assert_eq!(chunk_channel_pdu(&payload, usize::MAX).count(), 1);
    }
}
