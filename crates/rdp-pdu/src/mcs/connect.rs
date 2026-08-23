//! `Connect-Initial` and `Connect-Response`, the BER envelope around the GCC
//! conference PDUs (PRDRDP/13 §4.2.1 and §4.2.2, T.125 §7, MS-RDPBCGR
//! 2.2.1.3.1 and 2.2.1.4.1).
//!
//! Both structures are BER with definite lengths and one nesting level below
//! `SEQUENCE`, which is the whole of [`crate::asn1::ber`]'s scope. The
//! `userData` OCTET STRING is handed out as a borrowed slice, so the GCC
//! decoder reads the conference PDU out of the receive buffer without a copy
//! (D9).

use crate::asn1::ber::{self, BerTag};
use crate::asn1::{definite_len_size, tag};
use crate::io::limits::MAX_GCC_USER_DATA;
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// `DomainParameters ::= [APPLICATION 30] IMPLICIT SEQUENCE` of eight
/// INTEGERs (T.125 §7).
///
/// A Connect Initial carries three of these and the server picks a set that
/// satisfies all three, so the three constants below are a negotiation
/// position rather than a preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainParameters {
    /// `maxChannelIds`.
    pub max_channel_ids: u32,
    /// `maxUserIds`.
    pub max_user_ids: u32,
    /// `maxTokenIds`.
    pub max_token_ids: u32,
    /// `numPriorities`.
    pub num_priorities: u32,
    /// `minThroughput`.
    pub min_throughput: u32,
    /// `maxHeight`, the domain hierarchy depth, one for a two party domain.
    pub max_height: u32,
    /// `maxMCSPDUsize`.
    pub max_mcs_pdu_size: u32,
    /// `protocolVersion`, 2 for the version RDP uses.
    pub protocol_version: u32,
}

impl DomainParameters {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "DomainParameters";

    /// `targetParameters`: what we would like, and what every client sends
    /// (PRDRDP/13 §4.2.1).
    pub const TARGET: Self = Self {
        max_channel_ids: 34,
        max_user_ids: 2,
        max_token_ids: 0,
        num_priorities: 1,
        min_throughput: 0,
        max_height: 1,
        max_mcs_pdu_size: 65535,
        protocol_version: 2,
    };

    /// `minimumParameters`: the floor below which we will not connect.
    pub const MINIMUM: Self = Self {
        max_channel_ids: 1,
        max_user_ids: 1,
        max_token_ids: 1,
        num_priorities: 1,
        min_throughput: 0,
        max_height: 1,
        max_mcs_pdu_size: 1056,
        protocol_version: 2,
    };

    /// `maximumParameters`: the ceiling.
    pub const MAXIMUM: Self = Self {
        max_channel_ids: 65535,
        max_user_ids: 64535,
        max_token_ids: 65535,
        num_priorities: 1,
        min_throughput: 0,
        max_height: 1,
        max_mcs_pdu_size: 65535,
        protocol_version: 2,
    };

    /// The eight values in the order T.125 §7 declares them.
    const fn fields(&self) -> [u32; 8] {
        [
            self.max_channel_ids,
            self.max_user_ids,
            self.max_token_ids,
            self.num_priorities,
            self.min_throughput,
            self.max_height,
            self.max_mcs_pdu_size,
            self.protocol_version,
        ]
    }

    /// The length of the eight INTEGERs, without the `[APPLICATION 30]`
    /// header.
    fn content_len(&self) -> usize {
        self.fields().iter().copied().map(ber_int_size).sum()
    }
}

/// The number of octets [`ber::write_u32`] writes for `value`, tag and
/// length included.
fn ber_int_size(value: u32) -> usize {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    let significant = bytes.len() - first;
    let pad = usize::from(bytes.get(first).is_some_and(|b| *b & 0x80 != 0));
    // Tag and length are one octet each: no INTEGER here reaches 128 octets.
    2 + significant + pad
}

/// The size of a complete element: identifier, definite length and content.
fn element_size(tag: BerTag, content_len: usize) -> usize {
    tag.size() + definite_len_size(content_len) + content_len
}

impl Encode for DomainParameters {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        element_size(BerTag::DOMAIN_PARAMETERS, self.content_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        ber::write_tag_len(w, BerTag::DOMAIN_PARAMETERS, self.content_len());
        for value in self.fields() {
            ber::write_u32(w, BerTag::INTEGER, value);
        }
        Ok(())
    }
}

impl Decode<'_> for DomainParameters {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut body = ber::expect(r, BerTag::DOMAIN_PARAMETERS, Self::NAME)?;
        let parsed = Self {
            max_channel_ids: ber::read_u32(&mut body, Self::NAME)?,
            max_user_ids: ber::read_u32(&mut body, Self::NAME)?,
            max_token_ids: ber::read_u32(&mut body, Self::NAME)?,
            num_priorities: ber::read_u32(&mut body, Self::NAME)?,
            min_throughput: ber::read_u32(&mut body, Self::NAME)?,
            max_height: ber::read_u32(&mut body, Self::NAME)?,
            max_mcs_pdu_size: ber::read_u32(&mut body, Self::NAME)?,
            protocol_version: ber::read_u32(&mut body, Self::NAME)?,
        };
        // Exactly eight INTEGERs and no extension marker (T.125 §7), so a
        // ninth element means we are looking at something else.
        body.expect_empty(Self::NAME)?;
        Ok(parsed)
    }
}

/// The one octet domain selector every RDP client and server sends
/// (MS-RDPBCGR 2.2.1.3.1).
pub const DOMAIN_SELECTOR: &[u8] = &[0x01];

/// `Connect-Initial ::= [APPLICATION 101] IMPLICIT SEQUENCE` (T.125 §7),
/// MS-RDPBCGR 2.2.1.3.1. Client to server, phase 3 of the connection
/// sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectInitial<'a> {
    /// `callingDomainSelector`, one byte of `0x01`.
    pub calling_domain_selector: &'a [u8],
    /// `calledDomainSelector`, one byte of `0x01`.
    pub called_domain_selector: &'a [u8],
    /// `upwardFlag`, always true from a client.
    pub upward_flag: bool,
    /// What we would like.
    pub target_parameters: DomainParameters,
    /// The floor.
    pub minimum_parameters: DomainParameters,
    /// The ceiling.
    pub maximum_parameters: DomainParameters,
    /// The GCC Conference Create Request, encoded by
    /// [`crate::gcc::ConferenceCreateRequest`].
    pub user_data: &'a [u8],
}

impl<'a> ConnectInitial<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "Connect-Initial";

    /// A Connect Initial carrying `user_data`, with the three parameter sets
    /// of PRDRDP/13 §4.2.1 and the fields every client fixes.
    #[must_use]
    pub const fn new(user_data: &'a [u8]) -> Self {
        Self {
            calling_domain_selector: DOMAIN_SELECTOR,
            called_domain_selector: DOMAIN_SELECTOR,
            upward_flag: true,
            target_parameters: DomainParameters::TARGET,
            minimum_parameters: DomainParameters::MINIMUM,
            maximum_parameters: DomainParameters::MAXIMUM,
            user_data,
        }
    }

    fn content_len(&self) -> usize {
        element_size(BerTag::OCTET_STRING, self.calling_domain_selector.len())
            + element_size(BerTag::OCTET_STRING, self.called_domain_selector.len())
            + element_size(BerTag::BOOLEAN, 1)
            + self.target_parameters.size()
            + self.minimum_parameters.size()
            + self.maximum_parameters.size()
            + element_size(BerTag::OCTET_STRING, self.user_data.len())
    }
}

impl Encode for ConnectInitial<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        element_size(BerTag::CONNECT_INITIAL, self.content_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        ber::write_tag_len(w, BerTag::CONNECT_INITIAL, self.content_len());
        ber::write_octet_string(w, self.calling_domain_selector);
        ber::write_octet_string(w, self.called_domain_selector);
        ber::write_bool(w, self.upward_flag);
        self.target_parameters.encode(w)?;
        self.minimum_parameters.encode(w)?;
        self.maximum_parameters.encode(w)?;
        ber::write_octet_string(w, self.user_data);
        Ok(())
    }
}

impl<'a> Decode<'a> for ConnectInitial<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let mut body = ber::expect(r, BerTag::CONNECT_INITIAL, Self::NAME)?;
        let calling_domain_selector = ber::read_octet_string(&mut body, Self::NAME)?;
        let called_domain_selector = ber::read_octet_string(&mut body, Self::NAME)?;
        let upward_flag = ber::read_bool(&mut body, Self::NAME)?;
        let target_parameters = DomainParameters::decode(&mut body)?;
        let minimum_parameters = DomainParameters::decode(&mut body)?;
        let maximum_parameters = DomainParameters::decode(&mut body)?;
        let at = body.offset();
        let user_data = ber::read_octet_string(&mut body, Self::NAME)?;
        if user_data.len() > MAX_GCC_USER_DATA {
            return Err(PduError::CapExceeded {
                context: Self::NAME,
                declared: user_data.len(),
                cap: MAX_GCC_USER_DATA,
                limit_name: "MAX_GCC_USER_DATA",
                offset: at,
            });
        }
        body.expect_empty(Self::NAME)?;
        Ok(Self {
            calling_domain_selector,
            called_domain_selector,
            upward_flag,
            target_parameters,
            minimum_parameters,
            maximum_parameters,
            user_data,
        })
    }
}

/// `Connect-Response ::= [APPLICATION 102] IMPLICIT SEQUENCE` (T.125 §7),
/// MS-RDPBCGR 2.2.1.4.1. Server to client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectResponse<'a> {
    /// `result`, one of [`super::result_code`]. A non zero value is decoded
    /// and preserved rather than rejected here: PRDRDP/03 maps it to a
    /// message, and a wire layer that turns a refusal into a parse error
    /// loses the reason.
    pub result: u32,
    /// `calledConnectId`.
    pub called_connect_id: u32,
    /// The parameter set the server chose.
    pub domain_parameters: DomainParameters,
    /// The GCC Conference Create Response, decoded by
    /// [`crate::gcc::ConferenceCreateResponse`].
    pub user_data: &'a [u8],
}

impl ConnectResponse<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "Connect-Response";

    fn content_len(&self) -> usize {
        element_size(BerTag::ENUMERATED, enumerated_content_len(self.result))
            + ber_int_size(self.called_connect_id)
            + self.domain_parameters.size()
            + element_size(BerTag::OCTET_STRING, self.user_data.len())
    }
}

/// The content length of an ENUMERATED, which [`ber::write_u32`] encodes the
/// same way it encodes an INTEGER.
fn enumerated_content_len(value: u32) -> usize {
    ber_int_size(value) - 2
}

impl Encode for ConnectResponse<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        element_size(BerTag::CONNECT_RESPONSE, self.content_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        ber::write_tag_len(w, BerTag::CONNECT_RESPONSE, self.content_len());
        ber::write_u32(w, BerTag::ENUMERATED, self.result);
        ber::write_u32(w, BerTag::INTEGER, self.called_connect_id);
        self.domain_parameters.encode(w)?;
        ber::write_octet_string(w, self.user_data);
        Ok(())
    }
}

impl<'a> Decode<'a> for ConnectResponse<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let mut body = ber::expect(r, BerTag::CONNECT_RESPONSE, Self::NAME)?;
        let result = ber::read_enumerated(&mut body, Self::NAME)?;
        let called_connect_id = ber::read_u32(&mut body, Self::NAME)?;
        let domain_parameters = DomainParameters::decode(&mut body)?;
        let at = body.offset();
        let user_data = ber::read_octet_string(&mut body, Self::NAME)?;
        if user_data.len() > MAX_GCC_USER_DATA {
            return Err(PduError::CapExceeded {
                context: Self::NAME,
                declared: user_data.len(),
                cap: MAX_GCC_USER_DATA,
                limit_name: "MAX_GCC_USER_DATA",
                offset: at,
            });
        }
        body.expect_empty(Self::NAME)?;
        Ok(Self {
            result,
            called_connect_id,
            domain_parameters,
            user_data,
        })
    }
}

/// The universal tag numbers this module names, re-stated so a reader of the
/// encoder can check them against X.690 §8 without leaving the file.
const _: () = {
    assert!(tag::OCTET_STRING == 0x04);
    assert!(tag::BOOLEAN == 0x01);
};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// The three parameter sets of PRDRDP/13 §4.2.1, as
    /// `crates/rdp-pdu/src/asn1/ber.rs`'s own golden already asserts for the
    /// target set.
    #[test]
    fn the_target_parameters_encode_to_the_bytes_every_client_sends() {
        let mut buf = Vec::new();
        DomainParameters::TARGET
            .encode_checked(&mut Writer::new(&mut buf))
            .unwrap();
        assert_eq!(
            buf,
            [
                0x7e, 0x1a, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
                0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff, 0xff, 0x02, 0x01, 0x02,
            ]
        );
        assert_eq!(
            DomainParameters::decode(&mut Reader::new(&buf)).unwrap(),
            DomainParameters::TARGET
        );
    }

    #[test]
    fn all_three_parameter_sets_round_trip() {
        for params in [
            DomainParameters::TARGET,
            DomainParameters::MINIMUM,
            DomainParameters::MAXIMUM,
        ] {
            let mut buf = Vec::new();
            params.encode_checked(&mut Writer::new(&mut buf)).unwrap();
            assert_eq!(buf.len(), params.size());
            assert_eq!(
                DomainParameters::decode(&mut Reader::new(&buf)).unwrap(),
                params
            );
        }
    }

    #[test]
    fn a_connect_initial_round_trips_with_its_user_data_borrowed() {
        let user_data = vec![0xab; 300];
        let pdu = ConnectInitial::new(&user_data);
        let mut buf = Vec::new();
        pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), pdu.size());
        // [APPLICATION 101] in the high tag number form, then a long form
        // length: the whole PDU is well past 128 bytes.
        assert_eq!(&buf[..2], &[0x7f, 0x65]);
        let back = ConnectInitial::decode(&mut Reader::new(&buf)).unwrap();
        assert_eq!(back, pdu);
        // Zero copy: the decoded user data is the tail of the buffer itself
        // rather than a copy of it.
        assert_eq!(
            back.user_data.as_ptr() as usize - buf.as_ptr() as usize,
            buf.len() - user_data.len()
        );
    }

    #[test]
    fn a_connect_response_round_trips_and_keeps_a_refusal() {
        let user_data = vec![0x5a; 40];
        let pdu = ConnectResponse {
            result: 1,
            called_connect_id: 0,
            domain_parameters: DomainParameters::TARGET,
            user_data: &user_data,
        };
        let mut buf = Vec::new();
        pdu.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), pdu.size());
        assert_eq!(&buf[..2], &[0x7f, 0x66]);
        assert_eq!(
            ConnectResponse::decode(&mut Reader::new(&buf)).unwrap(),
            pdu
        );
    }

    /// A `userData` longer than the cap is refused with the constant's name
    /// in the error, before anything downstream allocates against it.
    #[test]
    fn user_data_past_the_cap_is_refused_by_name() {
        let user_data = vec![0u8; MAX_GCC_USER_DATA + 1];
        let pdu = ConnectInitial::new(&user_data);
        let mut buf = Vec::new();
        pdu.encode(&mut Writer::new(&mut buf)).unwrap();
        let err = ConnectInitial::decode(&mut Reader::new(&buf)).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_GCC_USER_DATA",
                ..
            }
        ));
    }

    /// A ninth INTEGER inside `DomainParameters` means we mis-parsed the
    /// structure, which is PRDRDP/13 §2.5's exact case.
    #[test]
    fn a_ninth_integer_in_the_domain_parameters_is_a_length_mismatch() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let params = DomainParameters::TARGET;
            ber::write_tag_len(&mut w, BerTag::DOMAIN_PARAMETERS, params.content_len() + 3);
            for value in params.fields() {
                ber::write_u32(&mut w, BerTag::INTEGER, value);
            }
            ber::write_u32(&mut w, BerTag::INTEGER, 7);
        }
        let err = DomainParameters::decode(&mut Reader::new(&buf)).unwrap_err();
        assert!(matches!(err, PduError::LengthMismatch { .. }));
    }

    #[test]
    fn every_prefix_of_the_connect_exchange_errors_without_panicking() {
        let user_data = vec![0xcd; 64];
        let initial = {
            let mut buf = Vec::new();
            ConnectInitial::new(&user_data)
                .encode(&mut Writer::new(&mut buf))
                .unwrap();
            buf
        };
        let response = {
            let mut buf = Vec::new();
            ConnectResponse {
                result: 0,
                called_connect_id: 0,
                domain_parameters: DomainParameters::TARGET,
                user_data: &user_data,
            }
            .encode(&mut Writer::new(&mut buf))
            .unwrap();
            buf
        };
        for cut in 0..initial.len() {
            assert!(ConnectInitial::decode(&mut Reader::new(&initial[..cut])).is_err());
        }
        for cut in 0..response.len() {
            assert!(ConnectResponse::decode(&mut Reader::new(&response[..cut])).is_err());
        }
    }
}
