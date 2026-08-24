//! GCC: the Conference Create Request and Response, and the user data blocks
//! inside them (PRDRDP/13 §3.3, §4.3 and §4.4, T.124 §8.7, MS-RDPBCGR 2.2.1.3
//! and 2.2.1.4).
//!
//! The conference PDUs are aligned PER and their shape is fixed, so the
//! wrapper below is a constant with two length determinants and one variable
//! field in it. PRDRDP/13 §3.3 states the trade this makes: the decoder
//! checks the prefix bytes it knows and rejects a structurally different but
//! legal PER encoding of the same PDU, because the alternative is a general
//! PER decoder driven by an ASN.1 schema, which D3 rules out.
//!
//! # Where the prefix bytes come from
//!
//! The request's fourteen byte wrapper is derived here rather than quoted,
//! because a reader who cannot check it cannot maintain it. Reading X.691
//! with T.124 §8.7's grammar in hand:
//!
//! ```text
//! ConnectGCCPDU CHOICE, 8 alternatives and an extension marker:
//!     1 extension bit + 3 index bits, conferenceCreateRequest = 0    0 000
//! ConferenceCreateRequest SEQUENCE, extension marker and 8 OPTIONAL
//! members, of which only userData is present:
//!     1 extension bit + 8 optional bits                    0 0000 0001
//! ConferenceName CHOICE, numeric:                                     0 0
//!     15 bits so far, padded to the octet boundary the length
//!     determinant of a constrained NumericString needs:        00 08
//! SimpleNumericString "1": length 1 as an offset from the
//! lower bound of 1, then the digit in four bits, padded:       00 10
//! lockedConference, listedConference, conductibleConference,
//! each one bit, and terminationMethod, a CHOICE of two with an
//! extension marker, two bits: five zero bits, padded:             00
//! userData SET OF, one member:                                    01
//! the member's OPTIONAL `value` is present (1) and its Key
//! CHOICE selects h221NonStandard (1), padded:                     c0
//! H221NonStandardIdentifier is OCTET STRING (SIZE(4..255)), so
//! its length is a constrained integer offset from 4:              00
//! "Duca":                                                44 75 63 61
//! userData.value OCTET STRING, unconstrained, so a length
//! determinant:                                          81 <len_lo>
//! ```
//!
//! That is `00 08 00 10 00 01 c0 00 44 75 63 61 81 1c` for a 284 byte block
//! list, which is the byte walk PRDRDP/13 §3.3 prints. Two notes on that
//! walk. It labels `00 01` as the `SET OF` count, where the derivation above
//! makes the `00` the three BOOLEANs and `terminationMethod` and only the
//! `01` the count; the bytes are the same either way. And it writes the two
//! octet length determinant as three octets, `81 <hi> <lo>`, where X.691
//! §10.9.3.7 gives two, `(0x80 | hi) lo`; the walk's own arithmetic proves
//! the two octet form, since `81 2a` is 298 and 298 is the 284 byte user data
//! plus this fourteen byte wrapper.

pub mod cert;
pub mod client;
pub mod server;

pub use cert::{parse_server_certificate, ServerCertificate};
pub use client::ClientGccBlocks;
pub use server::ServerGccBlocks;

use crate::asn1::per;
use crate::io::limits::MAX_GCC_USER_DATA;
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// The client to server H.221 non standard key (MS-RDPBCGR 2.2.1.3).
pub const H221_CLIENT_KEY: &[u8] = b"Duca";

/// The server to client H.221 non standard key (MS-RDPBCGR 2.2.1.4).
pub const H221_SERVER_KEY: &[u8] = b"McDn";

/// `ConnectData ::= SEQUENCE { key Key, ... }` where `Key` is a CHOICE of two
/// and the `object` alternative is index 0 (T.124 §8.7).
const KEY_CHOICE_COUNT: u8 = 2;

/// `TS_UD_HEADER`: `type` and `length`, four bytes, and `length` counts them
/// (MS-RDPBCGR 2.2.1.3.1).
pub const BLOCK_HEADER_LEN: usize = 4;

/// The `type` field of a `TS_UD_HEADER` (MS-RDPBCGR 2.2.1.3.1 and 2.2.1.4.1).
pub mod block_type {
    /// `TS_UD_CS_CORE` (2.2.1.3.2).
    pub const CS_CORE: u16 = 0xc001;
    /// `TS_UD_CS_SEC` (2.2.1.3.3).
    pub const CS_SECURITY: u16 = 0xc002;
    /// `TS_UD_CS_NET` (2.2.1.3.4).
    pub const CS_NET: u16 = 0xc003;
    /// `TS_UD_CS_CLUSTER` (2.2.1.3.5).
    pub const CS_CLUSTER: u16 = 0xc004;
    /// `TS_UD_CS_MONITOR` (2.2.1.3.6).
    pub const CS_MONITOR: u16 = 0xc005;
    /// `TS_UD_CS_MCS_MSGCHANNEL` (2.2.1.3.7).
    pub const CS_MCS_MSGCHANNEL: u16 = 0xc006;
    /// `TS_UD_CS_MONITOR_EX` (2.2.1.3.9).
    pub const CS_MONITOR_EX: u16 = 0xc008;
    /// `TS_UD_CS_MULTITRANSPORT` (2.2.1.3.8).
    pub const CS_MULTITRANSPORT: u16 = 0xc00a;
    /// `TS_UD_SC_CORE` (2.2.1.4.2).
    pub const SC_CORE: u16 = 0x0c01;
    /// `TS_UD_SC_SEC1` (2.2.1.4.3).
    pub const SC_SECURITY: u16 = 0x0c02;
    /// `TS_UD_SC_NET` (2.2.1.4.4).
    pub const SC_NET: u16 = 0x0c03;
    /// `TS_UD_SC_MCS_MSGCHANNEL` (2.2.1.4.5).
    pub const SC_MCS_MSGCHANNEL: u16 = 0x0c04;
    /// `TS_UD_SC_MULTITRANSPORT` (2.2.1.4.6).
    pub const SC_MULTITRANSPORT: u16 = 0x0c08;
}

/// The `type` of the block the reader is positioned at, without consuming it.
///
/// [`Reader`] is `Copy`, so the probe costs two words and the dispatcher in
/// [`client`] and [`server`] stays a plain `match`.
pub fn peek_block_type(r: &Reader<'_>, context: &'static str) -> PduResult<u16> {
    let mut probe = *r;
    probe.u16(context)
}

/// Read a `TS_UD_HEADER`, require its `type`, and return a bounded sub reader
/// over the block's body.
///
/// Every user data block is classified extensible under PRDRDP/13 §2.5, so
/// none of the decoders below calls `expect_empty` and a block longer than
/// the fields we know is tolerated. That is not laziness about the fixed
/// length blocks: `TS_UD_SC_CORE` gained two fields, `TS_UD_CS_CORE` gained
/// nine, and MS-RDPBCGR 2.2.1.3.9 was added to the document by an erratum in
/// 2023 (PRDRDP/11 §5.3 item 8). A client that rejects a longer block is a
/// client that breaks on the next revision. The sub reader is what keeps that
/// tolerance safe: a block that reads too far cannot reach the block after
/// it, and the outer reader advances by the declared length either way.
pub fn read_block<'a>(
    r: &mut Reader<'a>,
    expected: u16,
    context: &'static str,
) -> PduResult<Reader<'a>> {
    let at = r.offset();
    let block_type = r.u16(context)?;
    if block_type != expected {
        return Err(PduError::InvalidField {
            context,
            field: "TS_UD_HEADER.type",
            value: u64::from(block_type),
            offset: at,
        });
    }
    read_block_body(r, context)
}

/// Read the `length` of a `TS_UD_HEADER` whose `type` has already been
/// consumed, and return a bounded sub reader over the body.
fn read_block_body<'a>(r: &mut Reader<'a>, context: &'static str) -> PduResult<Reader<'a>> {
    let at = r.offset();
    let length = usize::from(r.u16(context)?);
    if length < BLOCK_HEADER_LEN {
        return Err(PduError::InvalidField {
            context,
            field: "TS_UD_HEADER.length",
            value: length as u64,
            offset: at,
        });
    }
    r.take(length - BLOCK_HEADER_LEN, context)
}

/// Skip a block whose `type` we do not implement.
///
/// The length is known, so an unknown block is preserved rather than
/// rejected (PRDRDP/13 §2.7 rule 3). PRDRDP/11 §5.3 item 8 is why this
/// matters: `CS_UNUSED1` (0xC00C) and MS-RDPBCGR 2.2.1.3.9 were added by the
/// erratum of 2023-08-16, and Windows clients had been sending the
/// undocumented block for years before the document admitted it existed. A
/// client that rejects what it does not recognise here is a client that
/// breaks on the next such block.
pub fn skip_unknown_block(r: &mut Reader<'_>, context: &'static str) -> PduResult<u16> {
    let block_type = r.u16(context)?;
    let mut body = read_block_body(r, context)?;
    let _ = body.rest();
    tracing::trace!(block_type, "skipping an unrecognised GCC user data block");
    Ok(block_type)
}

/// Write a `TS_UD_HEADER` whose `length` counts the four header bytes.
pub fn write_block_header(
    w: &mut Writer<'_>,
    block_type: u16,
    total_len: usize,
    context: &'static str,
) -> PduResult<()> {
    let length = u16::try_from(total_len).map_err(|_| PduError::Encode {
        context,
        reason: "user data block longer than its u16 length field",
    })?;
    w.u16(block_type);
    w.u16(length);
    Ok(())
}

/// Reject a user data length larger than the cap, naming the constant.
fn check_user_data_len(r: &Reader<'_>, len: usize, context: &'static str) -> PduResult<()> {
    r.ensure_cap(len, MAX_GCC_USER_DATA, "MAX_GCC_USER_DATA", context)
}

/// The GCC Conference Create Request, `ConnectData` and all
/// (T.124 §8.7, MS-RDPBCGR 2.2.1.3). Client to server, inside the
/// `userData` of a Connect Initial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConferenceCreateRequest<'a> {
    /// The concatenated `TS_UD_CS_*` blocks, which
    /// [`ClientGccBlocks`] encodes.
    pub user_data: &'a [u8],
}

impl ConferenceCreateRequest<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "ConferenceCreateRequest";

    /// The fixed part of the `connectPDU`, everything but the user data and
    /// its own length determinant. See the module doc for the derivation.
    const WRAPPER_LEN: usize = 12;

    /// The length the `connectPDU` determinant carries.
    fn connect_pdu_len(&self) -> usize {
        Self::WRAPPER_LEN
            + per::length_determinant_size(self.user_data.len())
            + self.user_data.len()
    }
}

impl Encode for ConferenceCreateRequest<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        let connect_pdu = self.connect_pdu_len();
        // The `Key` CHOICE index, the OID with its determinant, then the
        // connectPDU determinant and the connectPDU itself.
        1 + 1 + per::T124_IDENTIFIER.len() + per::length_determinant_size(connect_pdu) + connect_pdu
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        per::write_choice_index(w, 0, KEY_CHOICE_COUNT, Self::NAME)?;
        per::write_object_identifier(w, per::T124_IDENTIFIER, Self::NAME)?;
        per::write_length_determinant(w, self.connect_pdu_len(), Self::NAME)?;
        w.u8(0x00);
        w.u8(0x08);
        per::write_numeric_string(w, "1", 1, Self::NAME)?;
        w.u8(0x00);
        w.u8(0x01);
        w.u8(0xc0);
        w.u8(0x00);
        per::write_octet_string(w, H221_CLIENT_KEY, 4, 4, Self::NAME)?;
        per::write_length_determinant(w, self.user_data.len(), Self::NAME)?;
        w.bytes(self.user_data);
        Ok(())
    }
}

/// Read the `ConnectData` prefix both directions share: the `Key` CHOICE, the
/// `t124Identifier` OID and the `connectPDU` length determinant. Returns a
/// bounded sub reader over the `connectPDU`.
fn read_connect_data<'a>(r: &mut Reader<'a>, context: &'static str) -> PduResult<Reader<'a>> {
    per::read_choice_index(r, KEY_CHOICE_COUNT, context)?;
    let at = r.offset();
    let oid = per::read_object_identifier(r, context)?;
    if oid != per::T124_IDENTIFIER {
        return Err(PduError::InvalidField {
            context,
            field: "t124Identifier",
            value: oid.len() as u64,
            offset: at,
        });
    }
    let at = r.offset();
    let declared = per::read_length_determinant(r, context)?;
    check_user_data_len(r, declared, context)?;

    // The declared length is read and then deliberately not used as the bound.
    //
    // A real Windows host understates it. Measured against Windows 11
    // (DESKTOP-H21K47C, 2026-08-24) the server's `connectPDU` said 42 where
    // the content was 60, and the missing 18 are exactly its own
    // `TS_UD_SC_NET` (12) and `TS_UD_SC_MCS_MSGCHANNEL` (6): the length covers
    // the response up to the security block and not the two blocks appended
    // after it. Honouring it truncates the reader mid `userData` and the
    // failure reads as a malformed response from a server that is fine.
    //
    // Taking the rest is bounded twice over and so is not a licence to read
    // anything: this reader is already the MCS `userData` OCTET STRING, whose
    // length the Connect Response gave and which `MAX_GCC_USER_DATA` has
    // already capped. The inner `userData` length determinant is checked
    // against what is actually present a few lines below.
    let available = r.remaining();
    if declared != available {
        tracing::debug!(
            declared,
            available,
            offset = at,
            "the gcc connectPDU length disagrees with the bytes present, using the bytes"
        );
    }
    r.take(available, context)
}

/// Require the next `expected.len()` bytes to equal `expected`.
///
/// This is where PRDRDP/13 §3.3's trade is cashed in: the prefix of a GCC
/// conference PDU is a constant in every implementation, and comparing it is
/// what lets this crate skip a general PER decoder.
fn expect_bytes(
    r: &mut Reader<'_>,
    expected: &[u8],
    field: &'static str,
    context: &'static str,
) -> PduResult<()> {
    let at = r.offset();
    let found = r.slice(expected.len(), context)?;
    if found != expected {
        return Err(PduError::InvalidField {
            context,
            field,
            value: found.first().copied().map_or(0, u64::from),
            offset: at,
        });
    }
    Ok(())
}

impl<'a> Decode<'a> for ConferenceCreateRequest<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let mut pdu = read_connect_data(r, Self::NAME)?;
        expect_bytes(
            &mut pdu,
            &[0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00],
            "ConferenceCreateRequest prefix",
            Self::NAME,
        )?;
        expect_bytes(&mut pdu, H221_CLIENT_KEY, "h221NonStandard", Self::NAME)?;
        let len = per::read_length_determinant(&mut pdu, Self::NAME)?;
        check_user_data_len(&pdu, len, Self::NAME)?;
        let user_data = pdu.slice(len, Self::NAME)?;
        pdu.expect_empty(Self::NAME)?;
        Ok(Self { user_data })
    }
}

/// The GCC Conference Create Response (T.124 §8.7, MS-RDPBCGR 2.2.1.4).
/// Server to client, inside the `userData` of a Connect Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConferenceCreateResponse<'a> {
    /// `nodeID`, a `UserID` and so already offset back by 1001.
    pub node_id: u16,
    /// `tag`, an unconstrained INTEGER that every server sets to 1.
    pub tag: u32,
    /// `result`, where 0 is success. Three bits on the wire, so 0 to 7.
    pub result: u8,
    /// The concatenated `TS_UD_SC_*` blocks, which [`ServerGccBlocks`]
    /// decodes.
    pub user_data: &'a [u8],
}

impl ConferenceCreateResponse<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "ConferenceCreateResponse";

    /// `result` is an ENUMERATED of five values behind an extension marker,
    /// so three bits.
    const RESULT_COUNT: u8 = 5;

    /// The first octet: the ConnectGCCPDU CHOICE index 1 and the
    /// ConferenceCreateResponse preamble with `userData` present, padded to
    /// the boundary `nodeID` needs. See the module doc for the same
    /// derivation on the request side.
    const PREFIX: u8 = 0x14;

    fn connect_pdu_len(&self) -> usize {
        // The prefix octet, nodeID, the tag, the result octet, the SET OF
        // count, the two choice octets, the key, and the user data with its
        // determinant.
        1 + 2
            + per::unconstrained_int_size(self.tag)
            + 1
            + 3
            + H221_SERVER_KEY.len()
            + per::length_determinant_size(self.user_data.len())
            + self.user_data.len()
    }
}

impl Encode for ConferenceCreateResponse<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        let connect_pdu = self.connect_pdu_len();
        1 + 1 + per::T124_IDENTIFIER.len() + per::length_determinant_size(connect_pdu) + connect_pdu
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if self.result >= Self::RESULT_COUNT {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "conference create result is outside the ENUMERATED",
            });
        }
        per::write_choice_index(w, 0, KEY_CHOICE_COUNT, Self::NAME)?;
        per::write_object_identifier(w, per::T124_IDENTIFIER, Self::NAME)?;
        per::write_length_determinant(w, self.connect_pdu_len(), Self::NAME)?;
        w.u8(Self::PREFIX);
        per::write_constrained_int(
            w,
            u32::from(self.node_id),
            crate::mcs::MCS_USER_ID_BASE,
            65535,
            Self::NAME,
        )?;
        per::write_unconstrained_int(w, self.tag, Self::NAME)?;
        // The extension bit, the three bit result, and four padding bits.
        w.u8(self.result << 4);
        w.u8(0x01);
        w.u8(0xc0);
        w.u8(0x00);
        per::write_octet_string(w, H221_SERVER_KEY, 4, 4, Self::NAME)?;
        per::write_length_determinant(w, self.user_data.len(), Self::NAME)?;
        w.bytes(self.user_data);
        Ok(())
    }
}

impl<'a> Decode<'a> for ConferenceCreateResponse<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let mut pdu = read_connect_data(r, Self::NAME)?;
        expect_bytes(
            &mut pdu,
            &[Self::PREFIX],
            "ConferenceCreateResponse prefix",
            Self::NAME,
        )?;
        let node_id =
            per::read_constrained_int(&mut pdu, crate::mcs::MCS_USER_ID_BASE, 65535, Self::NAME)?;
        let tag = per::read_unconstrained_int(&mut pdu, Self::NAME)?;
        let at = pdu.offset();
        let packed = pdu.u8(Self::NAME)?;
        if packed & 0x80 != 0 {
            // The extension bit of the ENUMERATED. A server that sets it is
            // sending a result this version of T.124 does not define.
            return Err(PduError::Unsupported {
                context: Self::NAME,
                kind: "ConferenceCreateResponse result",
                value: u64::from(packed),
                offset: at,
            });
        }
        let result = (packed >> 4) & 0x07;
        expect_bytes(
            &mut pdu,
            &[0x01, 0xc0, 0x00],
            "userData SET OF prefix",
            Self::NAME,
        )?;
        expect_bytes(&mut pdu, H221_SERVER_KEY, "h221NonStandard", Self::NAME)?;
        let len = per::read_length_determinant(&mut pdu, Self::NAME)?;
        check_user_data_len(&pdu, len, Self::NAME)?;
        let user_data = pdu.slice(len, Self::NAME)?;
        pdu.expect_empty(Self::NAME)?;
        Ok(Self {
            // The constraint's upper bound is 65535, so this cannot truncate.
            node_id: node_id as u16,
            tag,
            result,
            user_data,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// PRDRDP/13 §3.3's byte walk, with the two octet length determinant
    /// X.691 §10.9.3.7 requires rather than the three octet form the walk
    /// prints. 284 bytes of user data and a 298 byte connectPDU, which is the
    /// arithmetic the walk itself states.
    #[test]
    fn the_request_wrapper_is_the_byte_walk_of_section_3_3() {
        let user_data = vec![0x00; 284];
        let ccr = ConferenceCreateRequest {
            user_data: &user_data,
        };
        let mut buf = Vec::new();
        ccr.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), ccr.size());
        assert_eq!(
            &buf[..23],
            &[
                0x00, // ConnectData: Key CHOICE index 0, object
                0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, // the t124 OID
                0x81, 0x2a, // connectPDU length 298
                0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, // the wrapper
                0x44, 0x75, 0x63, 0x61, // "Duca"
                0x81, 0x1c, // userData.value length 284
            ]
        );
        // Fourteen wrapper bytes plus the user data is the connectPDU.
        assert_eq!(buf.len(), 9 + 14 + 284);
        assert_eq!(
            ConferenceCreateRequest::decode(&mut Reader::new(&buf)).unwrap(),
            ccr
        );
    }

    /// A short block list takes the one octet determinant in both places, and
    /// the wrapper shrinks to thirteen bytes.
    #[test]
    fn a_short_request_uses_the_one_octet_determinants() {
        let user_data = [0xaa; 4];
        let ccr = ConferenceCreateRequest {
            user_data: &user_data,
        };
        let mut buf = Vec::new();
        ccr.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf[7], (13 + 4) as u8);
        assert_eq!(buf.len(), 8 + 13 + 4);
        assert_eq!(
            ConferenceCreateRequest::decode(&mut Reader::new(&buf)).unwrap(),
            ccr
        );
    }

    /// PRDRDP/13 §3.3's response prefix: the same `t124Identifier`, then
    /// `14 <nodeID> 01 01 00 01 c0 00 4d 63 44 6e` and a determinant.
    #[test]
    fn the_response_wrapper_is_the_byte_walk_of_section_3_3() {
        let user_data = vec![0x00; 8];
        let ccrsp = ConferenceCreateResponse {
            node_id: 0x79f3,
            tag: 1,
            result: 0,
            user_data: &user_data,
        };
        let mut buf = Vec::new();
        ccrsp.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), ccrsp.size());
        assert_eq!(
            buf,
            [
                0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, // the same key
                0x16, // connectPDU length 22
                0x14, // conferenceCreateResponse, userData present
                0x76, 0x0a, // nodeID 0x79f3 less 1001
                0x01, 0x01, // tag, one octet, value 1
                0x00, // result 0 and the padding that aligns what follows
                0x01, 0xc0, 0x00, // one set, value present, h221NonStandard
                0x4d, 0x63, 0x44, 0x6e, // "McDn"
                0x08, // userData.value length 8
                0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            ConferenceCreateResponse::decode(&mut Reader::new(&buf)).unwrap(),
            ccrsp
        );
    }

    #[test]
    fn every_conference_result_round_trips() {
        for result in 0..ConferenceCreateResponse::RESULT_COUNT {
            let ccrsp = ConferenceCreateResponse {
                node_id: 1001,
                tag: 1,
                result,
                user_data: &[],
            };
            let mut buf = Vec::new();
            ccrsp.encode_checked(&mut Writer::new(&mut buf)).unwrap();
            assert_eq!(
                ConferenceCreateResponse::decode(&mut Reader::new(&buf)).unwrap(),
                ccrsp
            );
        }
    }

    #[test]
    fn a_wrong_h221_key_is_rejected_in_both_directions() {
        let user_data = [0u8; 4];
        let mut buf = Vec::new();
        ConferenceCreateRequest {
            user_data: &user_data,
        }
        .encode(&mut Writer::new(&mut buf))
        .unwrap();
        // "Duca" starts at the twelfth wrapper byte.
        let at = buf.len() - 4 - 1 - 4;
        buf[at] = b'X';
        assert!(ConferenceCreateRequest::decode(&mut Reader::new(&buf)).is_err());

        let mut buf = Vec::new();
        ConferenceCreateResponse {
            node_id: 1001,
            tag: 1,
            result: 0,
            user_data: &user_data,
        }
        .encode(&mut Writer::new(&mut buf))
        .unwrap();
        let at = buf.len() - 4 - 1 - 4;
        buf[at] = b'X';
        assert!(ConferenceCreateResponse::decode(&mut Reader::new(&buf)).is_err());
    }

    #[test]
    fn a_wrong_t124_identifier_is_rejected() {
        let mut buf = Vec::new();
        ConferenceCreateRequest { user_data: &[0; 4] }
            .encode(&mut Writer::new(&mut buf))
            .unwrap();
        buf[3] = 0x7d;
        assert!(ConferenceCreateRequest::decode(&mut Reader::new(&buf)).is_err());
    }

    #[test]
    fn user_data_past_the_cap_is_refused_by_name() {
        // A connectPDU determinant of 16383, which is past MAX_GCC_USER_DATA.
        let bytes = [
            0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0xbf, 0xff, 0x00, 0x08,
        ];
        let err = ConferenceCreateRequest::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_GCC_USER_DATA",
                ..
            }
        ));
    }

    #[test]
    fn every_prefix_of_both_wrappers_errors_without_panicking() {
        let user_data = [0x11; 20];
        let mut request = Vec::new();
        ConferenceCreateRequest {
            user_data: &user_data,
        }
        .encode(&mut Writer::new(&mut request))
        .unwrap();
        let mut response = Vec::new();
        ConferenceCreateResponse {
            node_id: 1002,
            tag: 1,
            result: 0,
            user_data: &user_data,
        }
        .encode(&mut Writer::new(&mut response))
        .unwrap();
        for cut in 0..request.len() {
            assert!(ConferenceCreateRequest::decode(&mut Reader::new(&request[..cut])).is_err());
        }
        for cut in 0..response.len() {
            assert!(ConferenceCreateResponse::decode(&mut Reader::new(&response[..cut])).is_err());
        }
    }

    #[test]
    fn a_block_header_shorter_than_itself_is_rejected() {
        let bytes = [0x01, 0xc0, 0x02, 0x00];
        assert!(read_block(&mut Reader::new(&bytes), block_type::CS_CORE, "t").is_err());
        let bytes = [0x01, 0xc0, 0x00, 0x00];
        assert!(read_block(&mut Reader::new(&bytes), block_type::CS_CORE, "t").is_err());
    }
}
