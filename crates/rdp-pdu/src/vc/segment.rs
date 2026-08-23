//! RDP 8.0 segmented bulk data.
//!
//! MS-RDPEGFX 2.2.5 and 3.1.9, MS-RDPBCGR 3.1.8.4.2, PRDRDP/13 §6.4.
//!
//! MS-RDPEGFX 3.1.9 says the whole EGFX payload of a dynamic channel message
//! is wrapped in `RDP_SEGMENTED_DATA` before it is sent. So the receive path
//! is: static channel reassembly (§6.1) gives a `drdynvc` message, DVC
//! reassembly (§6.2) gives an EGFX message, this module unwraps it into
//! segments, `rdp-codecs` decompresses each, and the concatenation is a
//! sequence of `RDPGFX_HEADER` PDUs ([`crate::vc::egfx`]). Skipping this layer
//! produces a first EGFX PDU whose `cmdId` looks like garbage, which is the
//! standard first day EGFX bug.
//!
//! The split with `rdp-codecs` is exactly at [`CompressedSegment`]: this crate
//! reads the descriptor, the segment lengths and each segment's one byte of
//! compression flags, and never looks at a byte after those flags (PRDRDP/13
//! §7).
//!
//! Tail rule (PRDRDP/13 §2.5): exact for the MULTIPART form, whose segment
//! sizes must tile the message, and "runs to the end" for the SINGLE form.

use crate::codes::CompressionType;
use crate::io::limits::{MAX_SEGMENT_COUNT, MAX_UNCOMPRESSED_SIZE};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `RDP_SEGMENTED_DATA.descriptor` (MS-RDPEGFX 2.2.5.1).
pub mod descriptor {
    /// `SINGLE`: one blob running to the end of the message, with no segment
    /// count and no declared output size.
    pub const SINGLE: u8 = 0xE0;
    /// `MULTIPART`: a segment count, the total output size, and that many
    /// `RDP_DATA_SEGMENT`.
    pub const MULTIPART: u8 = 0xE1;
}

/// The first byte of every `bulkData`, the RDP 8.0 form of the bulk
/// compression flags (MS-RDPBCGR 3.1.8.4.2, PRDRDP/13 §6.4).
pub mod rdp8_flags {
    /// `PACKET_COMPRESSED`. Clear means the rest of the segment is literal.
    pub const PACKET_COMPRESSED: u8 = 0x20;
    /// `PACKET_AT_FRONT`: restart the history buffer at its front. An
    /// instruction to `rdp-codecs`, carried through unread (PRDRDP/13 §7).
    pub const PACKET_AT_FRONT: u8 = 0x40;
    /// `PACKET_FLUSHED`: reset the history buffer. Also `rdp-codecs`'.
    pub const PACKET_FLUSHED: u8 = 0x80;
    /// `CompressionTypeMask`, the low four bits, which for this envelope is
    /// always `PACKET_COMPR_TYPE_RDP8` (0x04).
    pub const TYPE_MASK: u8 = 0x0f;
}

/// One `bulkData` blob: its flags byte and the bytes after it (MS-RDPEGFX
/// 2.2.5.2).
///
/// The name follows the specification's framing rather than the content:
/// `PACKET_COMPRESSED` may be clear on a segment of a MULTIPART message, and
/// the data is then literal. `rdp-codecs` still has to see it, because RDP 8.0
/// feeds literal output into the same history buffer a later segment matches
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedSegment<'a> {
    /// [`rdp8_flags`].
    pub flags: u8,
    /// Everything after the flags byte, borrowed from the receive buffer.
    pub data: Payload<'a>,
}

impl<'a> CompressedSegment<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDP_DATA_SEGMENT bulkData";

    /// `PACKET_COMPRESSED`.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags & rdp8_flags::PACKET_COMPRESSED != 0
    }

    /// The compression type in the low four bits, which the caller checks is
    /// [`CompressionType::Rdp8`] before handing the segment to a
    /// decompressor.
    #[must_use]
    pub fn compression_type(&self) -> CompressionType {
        CompressionType::from_u8(self.flags & rdp8_flags::TYPE_MASK)
    }
}

/// A parsed `RDP_SEGMENTED_DATA` (MS-RDPEGFX 2.2.5.1).
///
/// PRDRDP/13 §6.4 draws this type with `Literal(Payload<'a>)` and with
/// `uncompressed_size: usize`. Two deviations, both because the document's
/// own prose contradicts its sketch:
///
/// * [`Segmented::Literal`] keeps the flags byte. §6.4 drops it, and dropping
///   it loses `PACKET_AT_FRONT` and `PACKET_FLUSHED`, which are instructions
///   to a history buffer that an uncompressed segment still contributes to
///   (MS-RDPBCGR 3.1.8.4.2). A decompressor that never hears about the
///   literal segments decodes the next compressed one against the wrong
///   history.
/// * `uncompressed_size` is an [`Option`]. §6.4's own paragraph says it "is
///   not on the wire, so it is `None` there", which the `usize` in its sketch
///   cannot express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segmented<'a> {
    /// A SINGLE message whose `PACKET_COMPRESSED` is clear: literal bytes,
    /// with no work for `rdp-codecs` beyond the history buffer. The common
    /// case for the small EGFX commands, and worth the branch.
    Literal {
        /// [`rdp8_flags`], with `PACKET_COMPRESSED` clear.
        flags: u8,
        /// The literal bytes.
        data: Payload<'a>,
    },
    /// A SINGLE message that is compressed, or any MULTIPART message.
    Compressed {
        /// The segments in wire order. A SINGLE message has exactly one.
        segments: Vec<CompressedSegment<'a>>,
        /// `uncompressedSize` for MULTIPART, so the caller allocates exactly
        /// once. `None` for SINGLE, where the size is not on the wire and the
        /// decompressor grows against
        /// [`MAX_UNCOMPRESSED_SIZE`].
        uncompressed_size: Option<usize>,
    },
}

impl<'a> Segmented<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDP_SEGMENTED_DATA";

    /// The segments, as one slice, for a caller that treats the literal case
    /// as a segment with nothing to do.
    #[must_use]
    pub fn segments(&self) -> &[CompressedSegment<'a>] {
        match self {
            Self::Literal { .. } => &[],
            Self::Compressed { segments, .. } => segments,
        }
    }

    /// `uncompressedSize` when the wire carried one.
    #[must_use]
    pub const fn uncompressed_size(&self) -> Option<usize> {
        match self {
            Self::Literal { .. } => None,
            Self::Compressed {
                uncompressed_size, ..
            } => *uncompressed_size,
        }
    }
}

impl<'a> Decode<'a> for Segmented<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let desc = r.u8(Self::NAME)?;
        match desc {
            descriptor::SINGLE => {
                let flags = r.u8("RDP_SEGMENTED_DATA bulkData flags")?;
                let data = Payload::new(r.rest());
                if flags & rdp8_flags::PACKET_COMPRESSED == 0 {
                    return Ok(Self::Literal { flags, data });
                }
                Ok(Self::Compressed {
                    segments: vec![CompressedSegment { flags, data }],
                    uncompressed_size: None,
                })
            }
            descriptor::MULTIPART => {
                let count_at = r.offset();
                let count = usize::from(r.u16("RDP_SEGMENTED_DATA segmentCount")?);
                r.ensure_cap(count, MAX_SEGMENT_COUNT, "MAX_SEGMENT_COUNT", Self::NAME)?;
                let uncompressed_size = r.u32("RDP_SEGMENTED_DATA uncompressedSize")? as usize;
                r.ensure_cap(
                    uncompressed_size,
                    MAX_UNCOMPRESSED_SIZE,
                    "MAX_UNCOMPRESSED_SIZE",
                    Self::NAME,
                )?;
                if count == 0 {
                    return Err(PduError::InvalidField {
                        context: Self::NAME,
                        field: "segmentCount",
                        value: 0,
                        offset: count_at,
                    });
                }
                // `count` is capped and each segment costs at least five
                // bytes, so the reservation is bounded by what is actually
                // left rather than by a hostile count (PRDRDP/13 §10.1).
                let mut segments = Vec::with_capacity(count.min(r.remaining() / 5 + 1));
                for _ in 0..count {
                    let size = r.u32("RDP_DATA_SEGMENT size")? as usize;
                    if size == 0 {
                        return Err(PduError::InvalidField {
                            context: "RDP_DATA_SEGMENT",
                            field: "size",
                            value: 0,
                            offset: r.offset(),
                        });
                    }
                    let mut body = r.take(size, "RDP_DATA_SEGMENT")?;
                    let flags = body.u8("RDP_DATA_SEGMENT bulkData flags")?;
                    segments.push(CompressedSegment {
                        flags,
                        data: Payload::new(body.rest()),
                    });
                }
                r.expect_empty(Self::NAME)?;
                Ok(Self::Compressed {
                    segments,
                    uncompressed_size: Some(uncompressed_size),
                })
            }
            other => Err(PduError::InvalidField {
                context: Self::NAME,
                field: "descriptor",
                value: u64::from(other),
                offset: at,
            }),
        }
    }
}

impl Encode for Segmented<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        match self {
            Self::Literal { data, .. } => 2 + data.len(),
            Self::Compressed {
                segments,
                uncompressed_size,
            } => {
                if uncompressed_size.is_none() {
                    2 + segments.first().map_or(0, |s| s.data.len())
                } else {
                    1 + 2 + 4 + segments.iter().map(|s| 4 + 1 + s.data.len()).sum::<usize>()
                }
            }
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        match self {
            Self::Literal { flags, data } => {
                w.u8(descriptor::SINGLE);
                w.u8(flags & !rdp8_flags::PACKET_COMPRESSED);
                w.bytes(data.as_slice());
                Ok(())
            }
            Self::Compressed {
                segments,
                uncompressed_size,
            } => match uncompressed_size {
                // No declared size means the SINGLE form, which holds exactly
                // one segment and has nowhere to put a second.
                None => {
                    let [only] = segments.as_slice() else {
                        return Err(PduError::Encode {
                            context: Self::NAME,
                            reason: "the SINGLE form carries exactly one segment",
                        });
                    };
                    w.u8(descriptor::SINGLE);
                    w.u8(only.flags);
                    w.bytes(only.data.as_slice());
                    Ok(())
                }
                Some(total) => {
                    let count = u16::try_from(segments.len()).map_err(|_| PduError::Encode {
                        context: Self::NAME,
                        reason: "more segments than segmentCount can hold",
                    })?;
                    let total = u32::try_from(*total).map_err(|_| PduError::Encode {
                        context: Self::NAME,
                        reason: "uncompressedSize does not fit its u32 field",
                    })?;
                    w.u8(descriptor::MULTIPART);
                    w.u16(count);
                    w.u32(total);
                    for segment in segments {
                        let size = u32::try_from(segment.data.len() + 1).map_err(|_| {
                            PduError::Encode {
                                context: "RDP_DATA_SEGMENT",
                                reason: "segment longer than its u32 size field",
                            }
                        })?;
                        w.u32(size);
                        w.u8(segment.flags);
                        w.bytes(segment.data.as_slice());
                    }
                    Ok(())
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn encoded(value: &Segmented<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    fn round_trip(value: Segmented<'_>) {
        let buf = encoded(&value);
        assert_eq!(Segmented::decode(&mut Reader::new(&buf)).unwrap(), value);
    }

    /// MS-RDPEGFX 2.2.5.1: descriptor `SINGLE`, then one blob whose first
    /// byte is the RDP 8.0 compression flags. `0x04` is
    /// `PACKET_COMPR_TYPE_RDP8` with `PACKET_COMPRESSED` clear.
    #[test]
    fn a_single_uncompressed_blob_is_literal_and_borrows_the_frame() {
        let frame = bytes::Bytes::from_static(&[0xe0, 0x04, b'h', b'i']);
        let value = Segmented::decode(&mut Reader::new(&frame)).unwrap();
        let Segmented::Literal { flags, data } = value else {
            panic!("expected a literal");
        };
        assert_eq!(flags, 0x04);
        assert_eq!(data.as_slice(), b"hi");
        assert_eq!(
            data.to_bytes(&frame).as_ptr() as usize - frame.as_ptr() as usize,
            2
        );
        assert_eq!(encoded(&value), frame.as_ref());
    }

    #[test]
    fn a_single_compressed_blob_is_one_segment_with_no_declared_size() {
        let bytes = [0xe0, 0x24, 0xaa, 0xbb];
        let value = Segmented::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            value,
            Segmented::Compressed {
                segments: vec![CompressedSegment {
                    flags: 0x24,
                    data: Payload::new(&[0xaa, 0xbb]),
                }],
                uncompressed_size: None,
            }
        );
        assert!(value.segments()[0].is_compressed());
        assert_eq!(
            value.segments()[0].compression_type(),
            CompressionType::Rdp8
        );
        assert_eq!(value.uncompressed_size(), None);
        assert_eq!(encoded(&value), bytes);
    }

    /// MULTIPART: descriptor, `segmentCount`, `uncompressedSize`, then each
    /// segment as a `u32` size and that many bytes starting with the flags.
    #[test]
    fn a_multipart_message_golden() {
        let bytes = [
            0xe1, // MULTIPART
            0x02, 0x00, // segmentCount = 2
            0x0a, 0x00, 0x00, 0x00, // uncompressedSize = 10
            0x03, 0x00, 0x00, 0x00, // size = 3
            0x24, 0x01, 0x02, // flags then two bytes
            0x02, 0x00, 0x00, 0x00, // size = 2
            0x04, 0x03, // flags then one byte
        ];
        let value = Segmented::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            value,
            Segmented::Compressed {
                segments: vec![
                    CompressedSegment {
                        flags: 0x24,
                        data: Payload::new(&[0x01, 0x02]),
                    },
                    CompressedSegment {
                        flags: 0x04,
                        data: Payload::new(&[0x03]),
                    },
                ],
                uncompressed_size: Some(10),
            }
        );
        assert!(value.segments()[0].is_compressed());
        assert!(
            !value.segments()[1].is_compressed(),
            "an uncompressed segment inside a MULTIPART still reaches rdp-codecs"
        );
        assert_eq!(encoded(&value), bytes);
    }

    #[test]
    fn all_three_shapes_round_trip() {
        round_trip(Segmented::Literal {
            flags: 0x04,
            data: Payload::new(b"plain"),
        });
        round_trip(Segmented::Compressed {
            segments: vec![CompressedSegment {
                flags: 0x24,
                data: Payload::new(b"squeezed"),
            }],
            uncompressed_size: None,
        });
        round_trip(Segmented::Compressed {
            segments: vec![
                CompressedSegment {
                    flags: 0x24,
                    data: Payload::new(b"a"),
                },
                CompressedSegment {
                    flags: 0xa4,
                    data: Payload::new(b"bc"),
                },
            ],
            uncompressed_size: Some(64),
        });
    }

    #[test]
    fn a_multipart_message_truncated_at_every_prefix_errors() {
        let full = encoded(&Segmented::Compressed {
            segments: vec![
                CompressedSegment {
                    flags: 0x24,
                    data: Payload::new(b"abc"),
                },
                CompressedSegment {
                    flags: 0x24,
                    data: Payload::new(b"de"),
                },
            ],
            uncompressed_size: Some(32),
        });
        for cut in 0..full.len() {
            assert!(
                Segmented::decode(&mut Reader::new(&full[..cut])).is_err(),
                "prefix of {cut} bytes decoded"
            );
        }
    }

    #[test]
    fn an_unknown_descriptor_is_an_invalid_field() {
        assert!(matches!(
            Segmented::decode(&mut Reader::new(&[0xe2, 0x00])).unwrap_err(),
            PduError::InvalidField {
                field: "descriptor",
                ..
            }
        ));
        // The descriptor alone, with no flags byte, is truncated.
        assert!(Segmented::decode(&mut Reader::new(&[0xe0])).is_err());
    }

    #[test]
    fn a_declared_output_size_past_the_cap_is_refused_before_the_segments() {
        let mut bytes = vec![0xe1, 0x01, 0x00];
        bytes.extend_from_slice(&((MAX_UNCOMPRESSED_SIZE + 1) as u32).to_le_bytes());
        bytes.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x24, 0x00]);
        assert!(matches!(
            Segmented::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::CapExceeded {
                limit_name: "MAX_UNCOMPRESSED_SIZE",
                ..
            }
        ));
    }

    #[test]
    fn a_zero_length_segment_has_no_flags_byte_and_is_refused() {
        let bytes = [
            0xe1, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(
            Segmented::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField { field: "size", .. }
        ));
    }

    #[test]
    fn a_zero_segment_count_is_refused() {
        let bytes = [0xe1, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00];
        assert!(matches!(
            Segmented::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField {
                field: "segmentCount",
                ..
            }
        ));
    }

    #[test]
    fn a_segment_that_overruns_the_message_is_truncated_rather_than_clamped() {
        let bytes = [
            0xe1, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x24,
        ];
        assert!(matches!(
            Segmented::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::Truncated { .. }
        ));
    }

    #[test]
    fn bytes_after_the_last_segment_are_a_length_mismatch() {
        let mut bytes = encoded(&Segmented::Compressed {
            segments: vec![CompressedSegment {
                flags: 0x24,
                data: Payload::new(b"ab"),
            }],
            uncompressed_size: Some(8),
        });
        bytes.push(0x00);
        assert!(matches!(
            Segmented::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn the_single_form_cannot_encode_two_segments() {
        let value = Segmented::Compressed {
            segments: vec![
                CompressedSegment {
                    flags: 0x24,
                    data: Payload::new(b"a"),
                },
                CompressedSegment {
                    flags: 0x24,
                    data: Payload::new(b"b"),
                },
            ],
            uncompressed_size: None,
        };
        let mut buf = Vec::new();
        assert!(matches!(
            value.encode(&mut Writer::new(&mut buf)).unwrap_err(),
            PduError::Encode { .. }
        ));
    }
}
