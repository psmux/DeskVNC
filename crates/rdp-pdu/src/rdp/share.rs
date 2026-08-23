//! Share Control and Share Data headers (MS-RDPBCGR 2.2.8.1.1.1, PRDRDP/13
//! §5.1).
//!
//! Every slow path PDU after the capability exchange sits inside a Share
//! Control header, and most of them inside a Share Data header inside that.
//! Six bytes and twelve bytes, and the twelve are counted by the six, which
//! is where the off by four and off by eighteen mistakes come from.
//!
//! # The flow control exception
//!
//! A `totalLength` of `0x8000` is not a PDU of 32 KiB. It is the flow control
//! PDU of T.128, whose first field sits where `totalLength` sits and whose
//! value is a marker rather than a length (MS-RDPBCGR 2.2.8.1.1.1.1). The
//! correct response is to skip it, so [`read_share_control`] returns
//! [`ShareControl::FlowControl`] and consumes the rest of the payload rather
//! than trying to parse a body. A decoder that misses this reads 32 KiB that
//! are not there and reports a truncation it cannot explain.

use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// `TS_SHARECONTROLHEADER`: `totalLength`, `pduType`, `PDUSource`
/// (MS-RDPBCGR 2.2.8.1.1.1.1).
pub const SHARE_CONTROL_HEADER_LEN: usize = 6;

/// `TS_SHAREDATAHEADER` including the Share Control header it starts with
/// (MS-RDPBCGR 2.2.8.1.1.1.2). The twelve bytes this module writes after the
/// control header are `SHARE_DATA_HEADER_LEN - SHARE_CONTROL_HEADER_LEN`.
pub const SHARE_DATA_HEADER_LEN: usize = 18;

/// `TS_PROTOCOL_VERSION`, the version field of `pduType`, already sitting in
/// bits 4 to 15 (MS-RDPBCGR 2.2.8.1.1.1.1).
///
/// The specification calls the version 1 and puts it in the high twelve bits,
/// and every implementation writes the constant as `0x0010`, which is that 1
/// already shifted. So it is combined into `pduType` with an `or` and never
/// with a shift, and a Share Data PDU's `pduType` reads `0x0017` on the wire.
/// PRDRDP/13 §5.1 writes "high 12 bits: version (0x0010)", which is the same
/// number described as though it still needed shifting.
pub const TS_PROTOCOL_VERSION: u16 = 0x0010;

/// The `totalLength` value that marks a flow control PDU rather than a
/// length (MS-RDPBCGR 2.2.8.1.1.1.1).
pub const FLOW_CONTROL_MARKER: u16 = 0x8000;

/// The low four bits of `TS_SHARECONTROLHEADER.pduType` (MS-RDPBCGR
/// 2.2.8.1.1.1.1).
pub mod pdu_type {
    /// `PDUTYPE_DEMANDACTIVEPDU`.
    pub const DEMAND_ACTIVE: u16 = 0x1;
    /// `PDUTYPE_CONFIRMACTIVEPDU`.
    pub const CONFIRM_ACTIVE: u16 = 0x3;
    /// `PDUTYPE_DEACTIVATEALLPDU`.
    pub const DEACTIVATE_ALL: u16 = 0x6;
    /// `PDUTYPE_DATAPDU`, which carries everything in
    /// [`pdu_type2`](super::pdu_type2).
    pub const DATA: u16 = 0x7;
    /// `PDUTYPE_SERVER_REDIR_PKT`, the standard Server Redirection PDU
    /// (MS-RDPBCGR 2.2.13.2).
    pub const SERVER_REDIR_PKT: u16 = 0xa;
}

/// `TS_SHAREDATAHEADER.pduType2` (MS-RDPBCGR 2.2.8.1.1.1.2).
pub mod pdu_type2 {
    /// `PDUTYPE2_UPDATE`, the slow path update PDU.
    pub const UPDATE: u8 = 0x02;
    /// `PDUTYPE2_CONTROL`.
    pub const CONTROL: u8 = 0x14;
    /// `PDUTYPE2_POINTER`.
    pub const POINTER: u8 = 0x1b;
    /// `PDUTYPE2_INPUT`, slow path input.
    pub const INPUT: u8 = 0x1c;
    /// `PDUTYPE2_SYNCHRONIZE`.
    pub const SYNCHRONIZE: u8 = 0x1f;
    /// `PDUTYPE2_REFRESH_RECT`.
    pub const REFRESH_RECT: u8 = 0x21;
    /// `PDUTYPE2_PLAY_SOUND`.
    pub const PLAY_SOUND: u8 = 0x22;
    /// `PDUTYPE2_SUPPRESS_OUTPUT`.
    pub const SUPPRESS_OUTPUT: u8 = 0x23;
    /// `PDUTYPE2_SHUTDOWN_REQUEST`.
    pub const SHUTDOWN_REQUEST: u8 = 0x24;
    /// `PDUTYPE2_SHUTDOWN_DENIED`.
    pub const SHUTDOWN_DENIED: u8 = 0x25;
    /// `PDUTYPE2_SAVE_SESSION_INFO`.
    pub const SAVE_SESSION_INFO: u8 = 0x26;
    /// `PDUTYPE2_FONTLIST`.
    pub const FONT_LIST: u8 = 0x27;
    /// `PDUTYPE2_FONTMAP`, the PDU that ends the connection sequence.
    pub const FONT_MAP: u8 = 0x28;
    /// `PDUTYPE2_SET_KEYBOARD_INDICATORS`.
    pub const SET_KEYBOARD_INDICATORS: u8 = 0x29;
    /// `PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST`.
    pub const BITMAPCACHE_PERSISTENT_LIST: u8 = 0x2b;
    /// `PDUTYPE2_BITMAPCACHE_ERROR_PDU`.
    pub const BITMAPCACHE_ERROR: u8 = 0x2c;
    /// `PDUTYPE2_SET_KEYBOARD_IME_STATUS`.
    pub const SET_KEYBOARD_IME_STATUS: u8 = 0x2d;
    /// `PDUTYPE2_OFFSCRCACHE_ERROR_PDU`.
    pub const OFFSCRCACHE_ERROR: u8 = 0x2e;
    /// `PDUTYPE2_SET_ERROR_INFO_PDU`.
    pub const SET_ERROR_INFO: u8 = 0x2f;
    /// `PDUTYPE2_DRAWNINEGRID_ERROR_PDU`.
    pub const DRAWNINEGRID_ERROR: u8 = 0x30;
    /// `PDUTYPE2_DRAWGDIPLUS_ERROR_PDU`.
    pub const DRAWGDIPLUS_ERROR: u8 = 0x31;
    /// `PDUTYPE2_ARC_STATUS_PDU`.
    pub const ARC_STATUS: u8 = 0x32;
    /// `PDUTYPE2_STATUS_INFO_PDU`.
    pub const STATUS_INFO: u8 = 0x36;
    /// `PDUTYPE2_MONITOR_LAYOUT_PDU`.
    pub const MONITOR_LAYOUT: u8 = 0x37;
}

/// `TS_SHAREDATAHEADER.streamId` (MS-RDPBCGR 2.2.8.1.1.1.2).
pub mod stream_id {
    /// `STREAM_UNDEFINED`, which some servers send.
    pub const UNDEFINED: u8 = 0;
    /// `STREAM_LOW`.
    pub const LOW: u8 = 1;
    /// `STREAM_MED`, what a client sends on everything.
    pub const MED: u8 = 2;
    /// `STREAM_HI`.
    pub const HI: u8 = 4;
}

/// `TS_SHAREDATAHEADER.compressedType` (MS-RDPBCGR 2.2.8.1.1.1.2, 3.1.8).
pub mod compression_flags {
    /// The low four bits, a [`CompressionType`](crate::codes::CompressionType).
    pub const TYPE_MASK: u8 = 0x0f;
    /// `PACKET_COMPRESSED`: the body is compressed and this crate hands it on
    /// rather than decoding it (PRDRDP/13 §7).
    pub const COMPRESSED: u8 = 0x20;
    /// `PACKET_AT_FRONT`: restart the history buffer at its front.
    pub const AT_FRONT: u8 = 0x40;
    /// `PACKET_FLUSHED`: the history buffer was reset.
    pub const FLUSHED: u8 = 0x80;
}

/// `TS_SHARECONTROLHEADER` (MS-RDPBCGR 2.2.8.1.1.1.1).
///
/// Fixed, six bytes. `pdu_type` is kept as it arrived, version bits and all,
/// because a server that sends a version we do not expect is worth logging
/// exactly rather than after we have masked the evidence away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareControlHeader {
    /// `totalLength`, the whole PDU including these six bytes.
    pub total_length: u16,
    /// `pduType`: the low four bits are one of [`pdu_type`] and the rest is
    /// [`TS_PROTOCOL_VERSION`], so a Share Data PDU reads `0x0017`.
    pub pdu_type: u16,
    /// `PDUSource`, the sender's MCS channel id. Zero in a Deactivate All
    /// from some servers.
    pub pdu_source: u16,
}

impl ShareControlHeader {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SHARECONTROLHEADER";

    /// The low four bits of `pduType`, which is the PDU's type.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        self.pdu_type & 0x000f
    }

    /// The version bits of `pduType`, masked in place so they compare
    /// against [`TS_PROTOCOL_VERSION`] directly.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.pdu_type & 0xfff0
    }
}

impl Encode for ShareControlHeader {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        SHARE_CONTROL_HEADER_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(self.total_length);
        w.u16(self.pdu_type);
        w.u16(self.pdu_source);
        Ok(())
    }
}

impl Decode<'_> for ShareControlHeader {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        Ok(Self {
            total_length: r.u16(Self::NAME)?,
            pdu_type: r.u16(Self::NAME)?,
            pdu_source: r.u16(Self::NAME)?,
        })
    }
}

/// What [`read_share_control`] found.
#[derive(Debug, Clone, Copy)]
pub enum ShareControl<'a> {
    /// A flow control PDU, whose `totalLength` is [`FLOW_CONTROL_MARKER`] and
    /// whose correct handling is to ignore it (MS-RDPBCGR 2.2.8.1.1.1.1).
    FlowControl,
    /// A real PDU: the header, and a reader bounded by `totalLength`.
    Pdu {
        /// The six byte header.
        header: ShareControlHeader,
        /// The body, `totalLength - 6` bytes.
        body: Reader<'a>,
    },
}

/// Read a Share Control header and return a bounded reader over its body.
///
/// The body reader stops at `totalLength`, so a body decoder that reads too
/// far cannot reach the PDU after it, and the outer reader has advanced past
/// the whole PDU whatever the body decoder did (PRDRDP/13 §2.5).
pub fn read_share_control<'a>(r: &mut Reader<'a>) -> PduResult<ShareControl<'a>> {
    let at = r.offset();
    let total_length = r.u16(ShareControlHeader::NAME)?;
    if total_length == FLOW_CONTROL_MARKER {
        // The rest of this MCS payload is the flow control PDU. Consuming it
        // is what "skip it" means here, and it leaves the outer reader empty
        // rather than pointing at a body that does not exist.
        let _ = r.rest();
        return Ok(ShareControl::FlowControl);
    }
    let total = usize::from(total_length);
    if total < SHARE_CONTROL_HEADER_LEN {
        return Err(PduError::InvalidField {
            context: ShareControlHeader::NAME,
            field: "totalLength",
            value: u64::from(total_length),
            offset: at,
        });
    }
    let header = ShareControlHeader {
        total_length,
        pdu_type: r.u16(ShareControlHeader::NAME)?,
        pdu_source: r.u16(ShareControlHeader::NAME)?,
    };
    let body = r.take(total - SHARE_CONTROL_HEADER_LEN, ShareControlHeader::NAME)?;
    Ok(ShareControl::Pdu { header, body })
}

/// Write a Share Control header around `f`, back patching `totalLength`.
///
/// `pdu_type` is one of [`pdu_type`] without the version bits;
/// [`TS_PROTOCOL_VERSION`] is added here so no call site can forget it.
pub fn write_share_control_with<F>(
    w: &mut Writer<'_>,
    pdu_type: u16,
    pdu_source: u16,
    f: F,
) -> PduResult<()>
where
    F: FnOnce(&mut Writer<'_>) -> PduResult<()>,
{
    w.with_len_u16(true, ShareControlHeader::NAME, |w| {
        w.u16(TS_PROTOCOL_VERSION | (pdu_type & 0x000f));
        w.u16(pdu_source);
        f(w)
    })
}

/// The twelve bytes of `TS_SHAREDATAHEADER` that follow the Share Control
/// header (MS-RDPBCGR 2.2.8.1.1.1.2).
///
/// Fixed, so [`Decode`] here reads exactly twelve bytes and the caller keeps
/// the rest of the body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShareDataHeader {
    /// `shareId`, the value the Demand Active assigned.
    pub share_id: u32,
    /// `streamId`, one of [`stream_id`].
    pub stream_id: u8,
    /// `uncompressedLength`: the body length before decompression plus the
    /// eighteen header bytes. Kept exactly as it arrived, because Windows and
    /// several other servers disagree about whether it counts the header and
    /// re-deriving it would change a PDU we are only forwarding.
    pub uncompressed_length: u16,
    /// `pduType2`, one of [`pdu_type2`].
    pub pdu_type2: u8,
    /// `compressedType`, the flags of [`compression_flags`].
    pub compressed_type: u8,
    /// `compressedLength`, zero when the body is not compressed.
    pub compressed_length: u16,
}

impl ShareDataHeader {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SHAREDATAHEADER";

    /// True when the body is compressed and this crate is handing it on
    /// rather than parsing it (PRDRDP/13 §7).
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.compressed_type & compression_flags::COMPRESSED != 0
    }

    /// The bulk compression type from the low four bits of `compressedType`.
    #[must_use]
    pub const fn compression_type(&self) -> crate::codes::CompressionType {
        crate::codes::CompressionType::from_u8(self.compressed_type & compression_flags::TYPE_MASK)
    }

    /// The size `rdp-codecs` should expect the body to decompress to, which
    /// is `uncompressedLength` less the eighteen header bytes it counts.
    ///
    /// [`None`] when the field is smaller than the header it claims to
    /// include, which several servers do by sending zero, and which is not an
    /// error: it means "I am not telling you".
    #[must_use]
    pub fn expected_uncompressed_len(&self) -> Option<usize> {
        usize::from(self.uncompressed_length).checked_sub(SHARE_DATA_HEADER_LEN)
    }
}

impl Encode for ShareDataHeader {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        SHARE_DATA_HEADER_LEN - SHARE_CONTROL_HEADER_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.share_id);
        w.u8(0);
        w.u8(self.stream_id);
        w.u16(self.uncompressed_length);
        w.u8(self.pdu_type2);
        w.u8(self.compressed_type);
        w.u16(self.compressed_length);
        Ok(())
    }
}

impl Decode<'_> for ShareDataHeader {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let share_id = r.u32(Self::NAME)?;
        // `pad1`, which no server sets and nothing reads.
        r.skip(1, Self::NAME)?;
        Ok(Self {
            share_id,
            stream_id: r.u8(Self::NAME)?,
            uncompressed_length: r.u16(Self::NAME)?,
            pdu_type2: r.u8(Self::NAME)?,
            compressed_type: r.u8(Self::NAME)?,
            compressed_length: r.u16(Self::NAME)?,
        })
    }
}

/// Write a complete Share Data PDU: the control header, the data header, and
/// `body`.
///
/// `uncompressedLength` is computed here as `body.size() + 18`, which is what
/// the field means when nothing is compressed, and `totalLength` is back
/// patched. This is the function the session calls for every PDU it sends
/// after the capability exchange, so neither length has a second call site to
/// get wrong.
pub fn write_share_data_pdu(
    w: &mut Writer<'_>,
    pdu_source: u16,
    share_id: u32,
    pdu_type2: u8,
    body: &impl Encode,
) -> PduResult<()> {
    let uncompressed_length =
        u16::try_from(body.size() + SHARE_DATA_HEADER_LEN).map_err(|_| PduError::Encode {
            context: ShareDataHeader::NAME,
            reason: "share data PDU longer than its uncompressedLength field",
        })?;
    let header = ShareDataHeader {
        share_id,
        stream_id: stream_id::MED,
        uncompressed_length,
        pdu_type2,
        compressed_type: 0,
        compressed_length: 0,
    };
    write_share_control_with(w, pdu_type::DATA, pdu_source, |w| {
        header.encode(w)?;
        body.encode(w)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    #[test]
    fn the_control_header_round_trips() {
        let header = ShareControlHeader {
            total_length: 0x0027,
            pdu_type: TS_PROTOCOL_VERSION | pdu_type::DATA,
            pdu_source: 0x03ea,
        };
        let bytes = encode(&header);
        assert_eq!(bytes, [0x27, 0x00, 0x17, 0x00, 0xea, 0x03]);
        assert_eq!(
            ShareControlHeader::decode(&mut Reader::new(&bytes)).unwrap(),
            header
        );
        assert_eq!(header.kind(), pdu_type::DATA);
        assert_eq!(header.version(), TS_PROTOCOL_VERSION);
    }

    #[test]
    fn the_data_header_round_trips() {
        let header = ShareDataHeader {
            share_id: 0x0010_3ea9,
            stream_id: stream_id::MED,
            uncompressed_length: 22,
            pdu_type2: pdu_type2::SYNCHRONIZE,
            compressed_type: 0,
            compressed_length: 0,
        };
        let bytes = encode(&header);
        assert_eq!(
            bytes.len(),
            SHARE_DATA_HEADER_LEN - SHARE_CONTROL_HEADER_LEN
        );
        assert_eq!(
            ShareDataHeader::decode(&mut Reader::new(&bytes)).unwrap(),
            header
        );
        assert_eq!(header.expected_uncompressed_len(), Some(4));
        assert!(!header.is_compressed());
    }

    /// The version bits are added by the writer, so a caller that passes a
    /// bare `PDUTYPE_*` still produces the word a server accepts.
    #[test]
    fn the_writer_adds_the_protocol_version_to_the_pdu_type() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            write_share_control_with(&mut w, pdu_type::CONFIRM_ACTIVE, 0x03ea, |w| {
                w.u32(0xdead_beef);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(
            buf,
            [0x0a, 0x00, 0x13, 0x00, 0xea, 0x03, 0xef, 0xbe, 0xad, 0xde]
        );

        let ShareControl::Pdu { header, mut body } =
            read_share_control(&mut Reader::new(&buf)).unwrap()
        else {
            panic!("not a flow control PDU");
        };
        assert_eq!(header.kind(), pdu_type::CONFIRM_ACTIVE);
        assert_eq!(header.total_length, 10);
        assert_eq!(body.u32("t").unwrap(), 0xdead_beef);
    }

    /// The exception that costs an afternoon if it is unknown.
    #[test]
    fn a_flow_control_pdu_is_recognised_and_skipped() {
        let bytes = [0x00, 0x80, 0x00, 0x00, 0x00, 0xea, 0x03, 0x00];
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            read_share_control(&mut r).unwrap(),
            ShareControl::FlowControl
        ));
        assert!(r.is_empty(), "the flow control PDU was not consumed");
    }

    #[test]
    fn a_total_length_below_the_header_is_an_invalid_field() {
        let bytes = [0x03, 0x00, 0x17, 0x00, 0xea, 0x03];
        let err = read_share_control(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "totalLength",
                ..
            }
        ));
    }

    /// The whole point of the bounded body: a body decoder cannot reach the
    /// next PDU, and the outer reader advances by exactly `totalLength`.
    #[test]
    fn the_body_reader_stops_at_total_length() {
        let mut bytes = vec![0x08, 0x00, 0x17, 0x00, 0xea, 0x03, 0xaa, 0xbb];
        bytes.extend_from_slice(&[0xcc, 0xdd]);
        let mut r = Reader::new(&bytes);
        let ShareControl::Pdu { mut body, .. } = read_share_control(&mut r).unwrap() else {
            panic!("flow control");
        };
        assert_eq!(body.remaining(), 2);
        assert_eq!(body.rest(), &[0xaa, 0xbb]);
        assert_eq!(r.remaining(), 2);
    }

    /// Both lengths at once, against a hand computed value: four body bytes
    /// give a `totalLength` of 22 and an `uncompressedLength` of 22.
    #[test]
    fn write_share_data_pdu_computes_both_lengths() {
        #[derive(Debug)]
        struct Body;
        impl Encode for Body {
            const NAME: &'static str = "TEST_BODY";
            fn size(&self) -> usize {
                4
            }
            fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
                w.u16(0x0001);
                w.u16(0x03ea);
                Ok(())
            }
        }

        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            write_share_data_pdu(&mut w, 0x03ea, 0x0010_3ea9, pdu_type2::SYNCHRONIZE, &Body)
                .unwrap();
        }
        assert_eq!(buf.len(), SHARE_DATA_HEADER_LEN + 4);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 22);
        // `uncompressedLength` sits at offset 12 and counts the eighteen
        // header bytes as well as the four body bytes.
        assert_eq!(u16::from_le_bytes([buf[12], buf[13]]), 22);

        let ShareControl::Pdu { header, mut body } =
            read_share_control(&mut Reader::new(&buf)).unwrap()
        else {
            panic!("flow control");
        };
        assert_eq!(header.kind(), pdu_type::DATA);
        let data = ShareDataHeader::decode(&mut body).unwrap();
        assert_eq!(data.pdu_type2, pdu_type2::SYNCHRONIZE);
        assert_eq!(data.expected_uncompressed_len(), Some(4));
        assert_eq!(body.remaining(), 4);
    }

    /// A zero `uncompressedLength`, which several servers send, is "I am not
    /// telling you" and not an error.
    #[test]
    fn a_short_uncompressed_length_is_not_an_error() {
        let header = ShareDataHeader {
            uncompressed_length: 0,
            ..ShareDataHeader::default()
        };
        assert_eq!(header.expected_uncompressed_len(), None);
    }

    #[test]
    fn the_compression_flags_decode_into_a_type() {
        let header = ShareDataHeader {
            compressed_type: compression_flags::COMPRESSED | 0x01,
            ..ShareDataHeader::default()
        };
        assert!(header.is_compressed());
        assert_eq!(
            header.compression_type(),
            crate::codes::CompressionType::Mppc64K
        );
    }

    #[test]
    fn every_prefix_of_a_share_data_pdu_errors_rather_than_panicking() {
        let bytes = [
            0x16, 0x00, 0x17, 0x00, 0xea, 0x03, 0xa9, 0x3e, 0x10, 0x00, 0x00, 0x02, 0x16, 0x00,
            0x1f, 0x00, 0x00, 0x00, 0x01, 0x00, 0xea, 0x03,
        ];
        for cut in 0..bytes.len() {
            let prefix = &bytes[..cut];
            let mut r = Reader::new(prefix);
            match read_share_control(&mut r) {
                Err(_) | Ok(ShareControl::FlowControl) => {}
                Ok(ShareControl::Pdu { mut body, .. }) => {
                    // A truncated PDU must not produce a full data header.
                    assert!(
                        ShareDataHeader::decode(&mut body).is_err(),
                        "prefix of {cut} bytes decoded a whole header"
                    );
                }
            }
        }
    }
}
