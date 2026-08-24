//! The `DomainMCSPDU` CHOICE in aligned PER (PRDRDP/13 §4.2.3, T.125 §7,
//! MS-RDPBCGR 2.2.1.5 to 2.2.1.9, 2.2.1.13 and 2.2.2.3).
//!
//! Every PDU here is tiny and every one of them is bit packed at the front,
//! so the first octet or two are derived below field by field rather than
//! quoted as a magic number. The rules, all from X.691:
//!
//! * The CHOICE index takes the smallest number of bits that covers the
//!   alternatives (§23). `DomainMCSPDU` has fewer than 64 and no extension
//!   marker, so the index is six bits at the top of the first octet.
//! * A SEQUENCE with OPTIONAL members is preceded by one bit per optional
//!   member (§18.2). Those bits follow the CHOICE index in the same octet.
//! * An ENUMERATED takes the smallest number of bits that covers its values
//!   (§14). `Result` has sixteen values and takes four bits, `Reason` has
//!   five and takes three, and both of them straddle an octet boundary here.
//! * A constrained integer wider than one octet is aligned, so the encoding
//!   pads to the next octet boundary before it (§13.2.6).
//!
//! Put together, an Attach User Confirm is `2E 00 00 06`: `001011` is choice
//! eleven, `1` says `initiator` is present, `0` is the top bit of a
//! `rt-successful` result, `000` is the rest of it, `00000` is the padding
//! that aligns the `initiator`, and `00 06` is the user id less 1001.

use super::{choice, disconnect_reason, result_code, MCS_USER_ID_BASE};
use crate::asn1::per;
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `dataPriority` (2 bits) and `segmentation` (2 bits) packed into the top
/// nibble of one octet (T.125 §7). This is what we write: `high` priority
/// with `begin` and `end` both set.
const SEND_DATA_PRIORITY_SEGMENTATION: u8 = 0x70;

/// The `segmentation` bits alone, which are the only two the decoder checks.
///
/// Both set means the PDU is whole. Anything else is an MCS PDU fragmented
/// across several Send Data Indications, and reassembling one would need
/// state in a crate that has none, so that is [`PduError::Unsupported`]
/// (PRDRDP/13 §4.2.3).
///
/// `dataPriority` is deliberately not checked. It is the sender's scheduling
/// hint and means nothing to a decoder. Comparing the whole octet against
/// `0x70` also pinned the priority to `high`, and a real Windows 11 host
/// (DESKTOP-H21K47C, 2026-08-24) sends `top`, so its first Send Data
/// Indication after the Demand Active was refused as an unsupported
/// segmentation when nothing was fragmented at all.
const SEGMENTATION_MASK: u8 = 0x30;

/// `begin` and `end` both set: one whole PDU in one indication.
const SEGMENTATION_BEGIN_END: u8 = 0x30;

/// `ChannelId ::= INTEGER (0..65535)` (T.125 §7).
const CHANNEL_ID_MAX: u32 = 65535;

/// `UserId ::= INTEGER (1001..65535)` (T.125 §7).
const USER_ID_MAX: u32 = 65535;

/// One MCS domain PDU.
///
/// The CHOICE is the PDU: T.125 gives no framing above it and the index is
/// the first six bits of the first octet, so a per alternative `Encode` would
/// either repeat that octet or omit it. The session matches on this enum and
/// `rdp-core`'s state machine drives it (PRDRDP/03 §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainMcsPdu<'a> {
    /// Erect Domain Request (MS-RDPBCGR 2.2.1.5). Client to server, and
    /// unacknowledged: the client sends it and moves straight on.
    ErectDomainRequest {
        /// `subHeight`, zero from every client.
        sub_height: u32,
        /// `subInterval`, zero from every client.
        sub_interval: u32,
    },
    /// Attach User Request (MS-RDPBCGR 2.2.1.6). Client to server, no fields.
    AttachUserRequest,
    /// Attach User Confirm (MS-RDPBCGR 2.2.1.7). Server to client.
    AttachUserConfirm {
        /// `result`, one of [`result_code`].
        result: u8,
        /// The user channel id, already offset back by 1001. Absent when the
        /// server refused, which is what the OPTIONAL in T.125 §7 is for.
        initiator: Option<u16>,
    },
    /// Channel Join Request (MS-RDPBCGR 2.2.1.8). Client to server.
    ChannelJoinRequest {
        /// The user channel id from the Attach User Confirm.
        initiator: u16,
        /// The channel to join.
        channel_id: u16,
    },
    /// Channel Join Confirm (MS-RDPBCGR 2.2.1.9). Server to client.
    ChannelJoinConfirm {
        /// `result`, one of [`result_code`].
        result: u8,
        /// The user channel id.
        initiator: u16,
        /// The channel the request asked for.
        requested: u16,
        /// The channel actually joined, absent on a refusal.
        channel_id: Option<u16>,
    },
    /// Send Data Request (MS-RDPBCGR 2.2.1.13.2.1). Client to server.
    SendDataRequest {
        /// The user channel id.
        initiator: u16,
        /// The channel the payload travels on.
        channel_id: u16,
        /// The payload, borrowed from the frame.
        payload: Payload<'a>,
    },
    /// Send Data Indication (MS-RDPBCGR 2.2.1.13.3.1). Server to client.
    SendDataIndication {
        /// The user channel id the server attributes the data to.
        initiator: u16,
        /// The channel the payload arrived on.
        channel_id: u16,
        /// The payload, borrowed from the frame.
        payload: Payload<'a>,
    },
    /// Disconnect Provider Ultimatum (MS-RDPBCGR 2.2.2.3). Either direction.
    DisconnectProviderUltimatum {
        /// One of [`disconnect_reason`].
        reason: u8,
    },
}

impl DomainMcsPdu<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "DomainMCSPDU";

    /// The CHOICE index of this alternative.
    #[must_use]
    pub const fn choice_index(&self) -> u8 {
        match self {
            Self::ErectDomainRequest { .. } => choice::ERECT_DOMAIN_REQUEST,
            Self::AttachUserRequest => choice::ATTACH_USER_REQUEST,
            Self::AttachUserConfirm { .. } => choice::ATTACH_USER_CONFIRM,
            Self::ChannelJoinRequest { .. } => choice::CHANNEL_JOIN_REQUEST,
            Self::ChannelJoinConfirm { .. } => choice::CHANNEL_JOIN_CONFIRM,
            Self::SendDataRequest { .. } => choice::SEND_DATA_REQUEST,
            Self::SendDataIndication { .. } => choice::SEND_DATA_INDICATION,
            Self::DisconnectProviderUltimatum { .. } => choice::DISCONNECT_PROVIDER_ULTIMATUM,
        }
    }

    /// The payload of a Send Data Request or Indication, for a caller that
    /// does not care which direction it came from.
    #[must_use]
    pub const fn user_data(&self) -> Option<(u16, Payload<'_>)> {
        match self {
            Self::SendDataRequest {
                channel_id,
                payload,
                ..
            }
            | Self::SendDataIndication {
                channel_id,
                payload,
                ..
            } => Some((*channel_id, *payload)),
            _ => None,
        }
    }
}

/// The first octet of a PDU whose alternative starts with an OPTIONAL bitmap
/// and a four bit `Result`.
///
/// `index` occupies bits 7 to 2, `present` is bit 1, and bit 0 is the top bit
/// of `result`. The remaining three bits of `result` sit at the top of the
/// second octet, whose low five bits are the padding that aligns whatever
/// follows.
fn write_result_prefix(w: &mut Writer<'_>, index: u8, present: bool, result: u8) {
    w.u8((index << 2) | (u8::from(present) << 1) | (result >> 3));
    w.u8((result & 0x07) << 5);
}

/// The inverse of [`write_result_prefix`], given the first octet already
/// read.
///
/// The five padding bits of the second octet are not checked. X.691 §10.1
/// requires them to be zero and nothing is gained by rejecting a server that
/// sets one: the fields we need are all above them.
fn read_result_suffix(r: &mut Reader<'_>, first: u8) -> PduResult<(bool, u8)> {
    let second = r.u8(DomainMcsPdu::NAME)?;
    let present = (first >> 1) & 0x01 == 1;
    let result = ((first & 0x01) << 3) | (second >> 5);
    Ok((present, result))
}

fn write_user_id(w: &mut Writer<'_>, id: u16) -> PduResult<()> {
    per::write_constrained_int(
        w,
        u32::from(id),
        MCS_USER_ID_BASE,
        USER_ID_MAX,
        DomainMcsPdu::NAME,
    )
}

fn read_user_id(r: &mut Reader<'_>) -> PduResult<u16> {
    let v = per::read_constrained_int(r, MCS_USER_ID_BASE, USER_ID_MAX, DomainMcsPdu::NAME)?;
    // The constraint's upper bound is 65535, so this cannot truncate.
    Ok(v as u16)
}

fn write_channel_id(w: &mut Writer<'_>, id: u16) -> PduResult<()> {
    per::write_constrained_int(w, u32::from(id), 0, CHANNEL_ID_MAX, DomainMcsPdu::NAME)
}

fn read_channel_id(r: &mut Reader<'_>) -> PduResult<u16> {
    let v = per::read_constrained_int(r, 0, CHANNEL_ID_MAX, DomainMcsPdu::NAME)?;
    Ok(v as u16)
}

impl Encode for DomainMcsPdu<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        match self {
            Self::ErectDomainRequest {
                sub_height,
                sub_interval,
            } => {
                1 + per::unconstrained_int_size(*sub_height)
                    + per::unconstrained_int_size(*sub_interval)
            }
            Self::AttachUserRequest => 1,
            Self::AttachUserConfirm { initiator, .. } => {
                2 + if initiator.is_some() { 2 } else { 0 }
            }
            Self::ChannelJoinRequest { .. } => 5,
            Self::ChannelJoinConfirm { channel_id, .. } => {
                6 + if channel_id.is_some() { 2 } else { 0 }
            }
            Self::SendDataRequest { payload, .. } | Self::SendDataIndication { payload, .. } => {
                6 + per::length_determinant_size(payload.len()) + payload.len()
            }
            Self::DisconnectProviderUltimatum { .. } => 2,
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let index = self.choice_index();
        match self {
            Self::ErectDomainRequest {
                sub_height,
                sub_interval,
            } => {
                // No optional members and no leading ENUMERATED, so the two
                // bits below the index are padding and the integers that
                // follow are octet aligned.
                w.u8(index << 2);
                per::write_unconstrained_int(w, *sub_height, Self::NAME)?;
                per::write_unconstrained_int(w, *sub_interval, Self::NAME)?;
            }
            Self::AttachUserRequest => w.u8(index << 2),
            Self::AttachUserConfirm { result, initiator } => {
                check_result(*result)?;
                write_result_prefix(w, index, initiator.is_some(), *result);
                if let Some(id) = initiator {
                    write_user_id(w, *id)?;
                }
            }
            Self::ChannelJoinRequest {
                initiator,
                channel_id,
            } => {
                w.u8(index << 2);
                write_user_id(w, *initiator)?;
                write_channel_id(w, *channel_id)?;
            }
            Self::ChannelJoinConfirm {
                result,
                initiator,
                requested,
                channel_id,
            } => {
                check_result(*result)?;
                write_result_prefix(w, index, channel_id.is_some(), *result);
                write_user_id(w, *initiator)?;
                write_channel_id(w, *requested)?;
                if let Some(id) = channel_id {
                    write_channel_id(w, *id)?;
                }
            }
            Self::SendDataRequest {
                initiator,
                channel_id,
                payload,
            }
            | Self::SendDataIndication {
                initiator,
                channel_id,
                payload,
            } => {
                w.u8(index << 2);
                write_user_id(w, *initiator)?;
                write_channel_id(w, *channel_id)?;
                w.u8(SEND_DATA_PRIORITY_SEGMENTATION);
                per::write_length_determinant(w, payload.len(), Self::NAME)?;
                w.bytes(payload.as_slice());
            }
            Self::DisconnectProviderUltimatum { reason } => {
                if *reason >= disconnect_reason::COUNT {
                    return Err(PduError::Encode {
                        context: Self::NAME,
                        reason: "disconnect reason is outside the ENUMERATED",
                    });
                }
                // Three bits of `Reason` after the six index bits: two in
                // this octet, one at the top of the next.
                w.u8((index << 2) | (reason >> 1));
                w.u8((reason & 0x01) << 7);
            }
        }
        Ok(())
    }
}

fn check_result(result: u8) -> PduResult<()> {
    if result >= result_code::COUNT {
        return Err(PduError::Encode {
            context: DomainMcsPdu::NAME,
            reason: "MCS result is outside the ENUMERATED",
        });
    }
    Ok(())
}

impl<'a> Decode<'a> for DomainMcsPdu<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let first = r.u8(Self::NAME)?;
        let index = first >> 2;
        let pdu = match index {
            choice::ERECT_DOMAIN_REQUEST => Self::ErectDomainRequest {
                sub_height: per::read_unconstrained_int(r, Self::NAME)?,
                sub_interval: per::read_unconstrained_int(r, Self::NAME)?,
            },
            choice::ATTACH_USER_REQUEST => Self::AttachUserRequest,
            choice::ATTACH_USER_CONFIRM => {
                let (present, result) = read_result_suffix(r, first)?;
                Self::AttachUserConfirm {
                    result,
                    initiator: if present {
                        Some(read_user_id(r)?)
                    } else {
                        None
                    },
                }
            }
            choice::CHANNEL_JOIN_REQUEST => Self::ChannelJoinRequest {
                initiator: read_user_id(r)?,
                channel_id: read_channel_id(r)?,
            },
            choice::CHANNEL_JOIN_CONFIRM => {
                let (present, result) = read_result_suffix(r, first)?;
                Self::ChannelJoinConfirm {
                    result,
                    initiator: read_user_id(r)?,
                    requested: read_channel_id(r)?,
                    channel_id: if present {
                        Some(read_channel_id(r)?)
                    } else {
                        None
                    },
                }
            }
            choice::SEND_DATA_REQUEST | choice::SEND_DATA_INDICATION => {
                let initiator = read_user_id(r)?;
                let channel_id = read_channel_id(r)?;
                let at_seg = r.offset();
                let segmentation = r.u8(Self::NAME)?;
                if segmentation & SEGMENTATION_MASK != SEGMENTATION_BEGIN_END {
                    return Err(PduError::Unsupported {
                        context: Self::NAME,
                        kind: "dataPriority and segmentation",
                        value: u64::from(segmentation),
                        offset: at_seg,
                    });
                }
                let len = per::read_length_determinant(r, Self::NAME)?;
                let payload = Payload::new(r.slice(len, Self::NAME)?);
                if index == choice::SEND_DATA_REQUEST {
                    Self::SendDataRequest {
                        initiator,
                        channel_id,
                        payload,
                    }
                } else {
                    Self::SendDataIndication {
                        initiator,
                        channel_id,
                        payload,
                    }
                }
            }
            choice::DISCONNECT_PROVIDER_ULTIMATUM => {
                let second = r.u8(Self::NAME)?;
                Self::DisconnectProviderUltimatum {
                    reason: ((first & 0x03) << 1) | (second >> 7),
                }
            }
            _ => {
                return Err(PduError::Unsupported {
                    context: Self::NAME,
                    kind: "DomainMCSPDU choice",
                    value: u64::from(index),
                    offset: at,
                });
            }
        };
        Ok(pdu)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// The wire bytes MS-RDPBCGR 2.2.1.5 to 2.2.1.9 and 2.2.2.3 produce, as
    /// PRDRDP/13 §4.2.3 tabulates them. The user channel id in the annotated
    /// examples of MS-RDPBCGR 4.1.7 to 4.1.9 is 1007, which is `00 06` on the
    /// wire once the 1001 offset is applied.
    fn vectors() -> Vec<(&'static str, DomainMcsPdu<'static>, &'static [u8])> {
        vec![
            (
                "erect domain request",
                DomainMcsPdu::ErectDomainRequest {
                    sub_height: 0,
                    sub_interval: 0,
                },
                &[0x04, 0x01, 0x00, 0x01, 0x00],
            ),
            (
                "attach user request",
                DomainMcsPdu::AttachUserRequest,
                &[0x28],
            ),
            (
                "attach user confirm",
                DomainMcsPdu::AttachUserConfirm {
                    result: result_code::RT_SUCCESSFUL,
                    initiator: Some(1007),
                },
                &[0x2e, 0x00, 0x00, 0x06],
            ),
            (
                "channel join request",
                DomainMcsPdu::ChannelJoinRequest {
                    initiator: 1007,
                    channel_id: 1007,
                },
                &[0x38, 0x00, 0x06, 0x03, 0xef],
            ),
            (
                "channel join confirm",
                DomainMcsPdu::ChannelJoinConfirm {
                    result: result_code::RT_SUCCESSFUL,
                    initiator: 1007,
                    requested: 1007,
                    channel_id: Some(1007),
                },
                &[0x3e, 0x00, 0x00, 0x06, 0x03, 0xef, 0x03, 0xef],
            ),
            (
                "send data request",
                DomainMcsPdu::SendDataRequest {
                    initiator: 1007,
                    channel_id: 1003,
                    payload: Payload::new(&[0xde, 0xad]),
                },
                &[0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x02, 0xde, 0xad],
            ),
            (
                "send data indication",
                DomainMcsPdu::SendDataIndication {
                    initiator: 1002,
                    channel_id: 1003,
                    payload: Payload::new(&[0x01]),
                },
                &[0x68, 0x00, 0x01, 0x03, 0xeb, 0x70, 0x01, 0x01],
            ),
            (
                "disconnect provider ultimatum",
                DomainMcsPdu::DisconnectProviderUltimatum {
                    reason: disconnect_reason::USER_REQUESTED,
                },
                &[0x21, 0x80],
            ),
        ]
    }

    #[test]
    fn every_domain_pdu_encodes_to_the_bytes_the_specification_tabulates() {
        for (name, pdu, expected) in vectors() {
            let mut buf = Vec::new();
            pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
            assert_eq!(buf, expected, "{name} encoded wrongly");
            assert_eq!(buf.len(), pdu.size(), "{name}: size() disagrees");
            let back = DomainMcsPdu::decode(&mut Reader::new(&buf)).unwrap();
            assert_eq!(back, pdu, "{name} did not round trip");
        }
    }

    /// A refusal drops the OPTIONAL fields, which changes the bitmap bit and
    /// so the first octet.
    #[test]
    fn a_refused_confirm_omits_its_optional_fields() {
        let pdu = DomainMcsPdu::AttachUserConfirm {
            result: result_code::RT_USER_REJECTED,
            initiator: None,
        };
        let mut buf = Vec::new();
        pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        // 001011 0 1 : index 11, no initiator, top bit of result 15.
        assert_eq!(buf, [0x2d, 0xe0]);
        assert_eq!(DomainMcsPdu::decode(&mut Reader::new(&buf)).unwrap(), pdu);

        let pdu = DomainMcsPdu::ChannelJoinConfirm {
            result: 3,
            initiator: 1007,
            requested: 1004,
            channel_id: None,
        };
        let mut buf = Vec::new();
        pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(DomainMcsPdu::decode(&mut Reader::new(&buf)).unwrap(), pdu);
    }

    /// Every disconnect reason survives the three bit split across two
    /// octets.
    #[test]
    fn every_disconnect_reason_round_trips() {
        for reason in 0..disconnect_reason::COUNT {
            let pdu = DomainMcsPdu::DisconnectProviderUltimatum { reason };
            let mut buf = Vec::new();
            pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
            assert_eq!(buf.len(), 2);
            assert_eq!(DomainMcsPdu::decode(&mut Reader::new(&buf)).unwrap(), pdu);
        }
    }

    /// Every `Result` value survives the four bit split across two octets.
    #[test]
    fn every_result_value_round_trips() {
        for result in 0..result_code::COUNT {
            let pdu = DomainMcsPdu::AttachUserConfirm {
                result,
                initiator: Some(1001),
            };
            let mut buf = Vec::new();
            pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
            assert_eq!(DomainMcsPdu::decode(&mut Reader::new(&buf)).unwrap(), pdu);
        }
    }

    /// PRDRDP/13 §4.2.3: writing the one octet determinant for a payload of
    /// 128 bytes or more produces a PDU Windows reads as truncated. The
    /// boundary is tested at 127, 128 and the largest determinant PER allows.
    #[test]
    fn the_send_data_length_determinant_changes_width_at_128() {
        for len in [0usize, 1, 127, 128, 129, per::MAX_LENGTH_DETERMINANT] {
            let body = vec![0x5a; len];
            let pdu = DomainMcsPdu::SendDataRequest {
                initiator: 1002,
                channel_id: 1003,
                payload: Payload::new(&body),
            };
            let mut buf = Vec::new();
            pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
            let expected_determinant = if len < 128 { 1 } else { 2 };
            assert_eq!(buf.len(), 6 + expected_determinant + len, "len {len}");
            assert_eq!(DomainMcsPdu::decode(&mut Reader::new(&buf)).unwrap(), pdu);
        }
    }

    /// A payload past the two octet determinant needs the fragmented form,
    /// which this crate refuses in both directions.
    #[test]
    fn a_payload_past_the_determinant_is_an_encode_error() {
        let body = vec![0u8; per::MAX_LENGTH_DETERMINANT + 1];
        let pdu = DomainMcsPdu::SendDataRequest {
            initiator: 1002,
            channel_id: 1003,
            payload: Payload::new(&body),
        };
        let mut buf = Vec::new();
        assert!(pdu.encode(&mut Writer::new(&mut buf)).is_err());
    }

    #[test]
    fn a_fragmented_send_data_is_unsupported_rather_than_mis_parsed() {
        // segmentation = begin only, which no server sends.
        let bytes = [0x68, 0x00, 0x01, 0x03, 0xeb, 0x60, 0x01, 0x01];
        let err = DomainMcsPdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(err, PduError::Unsupported { .. }));
    }

    #[test]
    fn an_unknown_choice_index_is_unsupported() {
        // Choice 30, which T.125 defines and this crate does not implement.
        let err = DomainMcsPdu::decode(&mut Reader::new(&[30 << 2, 0x00])).unwrap_err();
        assert!(matches!(
            err,
            PduError::Unsupported {
                kind: "DomainMCSPDU choice",
                ..
            }
        ));
    }

    /// A user id below the constraint's lower bound cannot be encoded, and a
    /// raw wire value of 0xFFFF would decode to 66536, which the constraint
    /// check rejects.
    #[test]
    fn a_user_id_outside_the_constraint_is_rejected_in_both_directions() {
        let pdu = DomainMcsPdu::ChannelJoinRequest {
            initiator: 1000,
            channel_id: 0,
        };
        let mut buf = Vec::new();
        assert!(pdu.encode(&mut Writer::new(&mut buf)).is_err());
        assert!(DomainMcsPdu::decode(&mut Reader::new(&[0x38, 0xff, 0xff, 0x00, 0x00])).is_err());
    }

    #[test]
    fn every_prefix_of_every_domain_pdu_errors_without_panicking() {
        for (name, _, bytes) in vectors() {
            for cut in 0..bytes.len() {
                assert!(
                    DomainMcsPdu::decode(&mut Reader::new(&bytes[..cut])).is_err(),
                    "{name} truncated to {cut} bytes decoded"
                );
            }
        }
    }
}
