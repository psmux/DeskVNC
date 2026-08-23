//! Multitransport bootstrapping (MS-RDPBCGR 2.2.15, PRDRDP/03 §2.9).
//!
//! Two PDUs, both behind a basic security header, and this client answers the
//! first with the second and does nothing else.
//!
//! We send the Client Multitransport Channel Data block (MS-RDPBCGR
//! 2.2.1.3.8) with `flags = 0`, which says the client understands
//! multitransport bootstrapping and wants neither `TRANSPORTTYPE_UDPFECR` nor
//! `TRANSPORTTYPE_UDPFECL`. A conforming server that reads it never sends a
//! request. A server that sends one anyway used to be refused by silence,
//! because no type existed to answer it with; PRDRDP/03 §2.9 says the answer
//! is a Client Initiate Multitransport Response carrying `E_ABORT`, which is
//! the specification's own way of saying "I am not doing this", after which
//! the TCP connection carries on untouched.
//!
//! # The signed HRESULT
//!
//! MS-RDPBCGR 2.2.15.2 documents `hrResponse` as an HRESULT, which its own
//! type definition calls unsigned. `E_ABORT` is `0x80004004`, whose top bit
//! is the HRESULT severity bit, so every real value on this field has that
//! bit set and every implementation treats the field as signed. PRDRDP/11
//! §5.3 carries the erratum beside the identical one on the time zone
//! `Bias` fields. [`hresult`] holds the two values as `i32` for that reason,
//! and the field is written as its two's complement bit pattern and never as
//! a decimal.
//!
//! There is no UDP transport in this workspace and none planned, so nothing
//! here builds one: the request is decoded to learn the `requestId` that has
//! to be echoed, and the response says no.

use crate::codes::MultitransportProtocol;
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

use super::security::{security_flags, BasicSecurityHeader, BASIC_SECURITY_HEADER_LEN};

/// The `hrResponse` values of a Client Initiate Multitransport Response
/// (MS-RDPBCGR 2.2.15.2).
///
/// Signed for the reason this module's comment gives.
pub mod hresult {
    /// `S_OK`, which this client never sends: it would commit us to a UDP
    /// transport we do not implement.
    pub const S_OK: i32 = 0x0000_0000;

    /// `E_ABORT` (`0x80004004`), the refusal PRDRDP/03 §2.9 chose.
    ///
    /// Written as the bit pattern the wire carries. As an unsigned word that
    /// is 2147500036 and as a signed one it is -2147467260, and only the
    /// hexadecimal form is legible, which is why the cast is here and not at
    /// the call site.
    pub const E_ABORT: i32 = 0x8000_4004_u32 as i32;
}

/// The `securityCookie` of a Server Initiate Multitransport Request
/// (MS-RDPBCGR 2.2.15.1), sixteen bytes.
pub const SECURITY_COOKIE_LEN: usize = 16;

/// The Server Initiate Multitransport Request PDU (MS-RDPBCGR 2.2.15.1).
///
/// Decoded so the response can echo `requestId`, and for nothing else. The
/// `securityCookie` is what a client would put in the UDP handshake it is
/// being invited to make; we make none, so the sixteen bytes are carried,
/// never inspected and never logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerInitiateMultitransportRequest {
    /// `requestId`, echoed by the response and matched by the server.
    pub request_id: u32,
    /// `requestedProtocol`.
    pub requested_protocol: MultitransportProtocol,
    /// `reserved`, which the specification requires to be zero and which is
    /// kept rather than checked, because a non zero value here changes
    /// nothing we do.
    pub reserved: u16,
    /// `securityCookie`.
    pub security_cookie: [u8; SECURITY_COOKIE_LEN],
}

impl ServerInitiateMultitransportRequest {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDP_INITIATE_MULTITRANSPORT_REQUEST";

    /// `requestId`, `requestedProtocol`, `reserved` and `securityCookie`,
    /// behind the basic security header.
    pub const BODY_LEN: usize = 4 + 2 + 2 + SECURITY_COOKIE_LEN;

    /// The refusal this client answers with, `requestId` echoed.
    #[must_use]
    pub const fn refuse(&self) -> ClientInitiateMultitransportResponse {
        ClientInitiateMultitransportResponse::abort(self.request_id)
    }
}

impl Encode for ServerInitiateMultitransportRequest {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BASIC_SECURITY_HEADER_LEN + Self::BODY_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        BasicSecurityHeader::new(security_flags::TRANSPORT_REQ).encode(w)?;
        w.u32(self.request_id);
        w.u16(self.requested_protocol.to_u16());
        w.u16(self.reserved);
        w.bytes(&self.security_cookie);
        Ok(())
    }
}

impl Decode<'_> for ServerInitiateMultitransportRequest {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let header = BasicSecurityHeader::decode(r)?;
        if !header.has(security_flags::TRANSPORT_REQ) {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "flags (SEC_TRANSPORT_REQ)",
                value: u64::from(header.flags),
                offset: at,
            });
        }
        Ok(Self {
            request_id: r.u32(Self::NAME)?,
            // An unnamed protocol is preserved rather than rejected: the
            // length is fixed, so nothing can desync, and the answer is
            // `E_ABORT` whatever was asked for (PRDRDP/13 §2.7 rule 3).
            requested_protocol: MultitransportProtocol::from_u16(r.u16(Self::NAME)?),
            reserved: r.u16(Self::NAME)?,
            security_cookie: r.array::<SECURITY_COOKIE_LEN>(Self::NAME)?,
        })
    }
}

/// The Client Initiate Multitransport Response PDU (MS-RDPBCGR 2.2.15.2).
///
/// Eight bytes behind a basic security header carrying `SEC_TRANSPORT_RSP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientInitiateMultitransportResponse {
    /// `requestId`, copied from the request being answered.
    pub request_id: u32,
    /// `hrResponse`, from [`hresult`].
    pub hr_response: i32,
}

impl ClientInitiateMultitransportResponse {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "RDP_INITIATE_MULTITRANSPORT_RESPONSE";

    /// `requestId` and `hrResponse`, behind the basic security header.
    pub const BODY_LEN: usize = 8;

    /// The one response this client sends: `E_ABORT`, `requestId` echoed
    /// (PRDRDP/03 §2.9).
    #[must_use]
    pub const fn abort(request_id: u32) -> Self {
        Self {
            request_id,
            hr_response: hresult::E_ABORT,
        }
    }

    /// True when this response declines the transport, which is every
    /// response this client builds.
    ///
    /// An HRESULT is a failure exactly when its top bit is set (the severity
    /// bit), so this is the general test and not a comparison against
    /// `E_ABORT`.
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        self.hr_response < 0
    }
}

impl Encode for ClientInitiateMultitransportResponse {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BASIC_SECURITY_HEADER_LEN + Self::BODY_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        BasicSecurityHeader::new(security_flags::TRANSPORT_RSP).encode(w)?;
        w.u32(self.request_id);
        w.i32(self.hr_response);
        Ok(())
    }
}

impl Decode<'_> for ClientInitiateMultitransportResponse {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let header = BasicSecurityHeader::decode(r)?;
        if !header.has(security_flags::TRANSPORT_RSP) {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "flags (SEC_TRANSPORT_RSP)",
                value: u64::from(header.flags),
                offset: at,
            });
        }
        Ok(Self {
            request_id: r.u32(Self::NAME)?,
            hr_response: r.i32(Self::NAME)?,
        })
    }
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

    fn a_request() -> ServerInitiateMultitransportRequest {
        ServerInitiateMultitransportRequest {
            request_id: 0x0000_0001,
            requested_protocol: MultitransportProtocol::UdpFecR,
            reserved: 0,
            security_cookie: [0x5a; SECURITY_COOKIE_LEN],
        }
    }

    /// Hand computed from MS-RDPBCGR 2.2.15.1. `SEC_TRANSPORT_REQ` is 0x0002,
    /// so `flags` is `02 00` and `flagsHi` is `00 00`. `requestId` 1 is
    /// `01 00 00 00`, `requestedProtocol` `INITIATE_REQUEST_PROTOCOL_UDPFECR`
    /// is `01 00`, `reserved` is `00 00`, then sixteen cookie bytes. Four
    /// header bytes plus four plus two plus two plus sixteen is twenty eight.
    #[test]
    fn the_request_is_the_bytes_the_specification_states() {
        let bytes = encode(&a_request());
        assert_eq!(bytes.len(), 4 + 4 + 2 + 2 + 16);
        assert_eq!(bytes.len(), 28);
        assert_eq!(
            &bytes[..12],
            &[0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(&bytes[12..], &[0x5a; 16]);
        assert_eq!(
            ServerInitiateMultitransportRequest::decode(&mut Reader::new(&bytes)).unwrap(),
            a_request()
        );
    }

    /// The answer PRDRDP/03 §2.9 chose, byte for byte. `SEC_TRANSPORT_RSP` is
    /// 0x0004, so `flags` is `04 00`. `requestId` echoes the request's 1.
    /// `hrResponse` is `E_ABORT` 0x80004004, little endian, so `04 40 00 80`.
    /// Twelve bytes in all.
    #[test]
    fn the_refusal_is_e_abort_with_the_requests_own_id() {
        let response = a_request().refuse();
        assert_eq!(response.request_id, 1);
        assert_eq!(response.hr_response, hresult::E_ABORT);
        assert!(response.is_refusal());

        let bytes = encode(&response);
        assert_eq!(
            bytes,
            [0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x40, 0x00, 0x80]
        );
        assert_eq!(bytes.len(), 12);
        assert_eq!(
            ClientInitiateMultitransportResponse::decode(&mut Reader::new(&bytes)).unwrap(),
            response
        );
    }

    /// The erratum of PRDRDP/11 §5.3: `hrResponse` is documented unsigned and
    /// is signed, so the same thirty two bits have to read back as the
    /// negative value and re-encode to the same word.
    #[test]
    fn the_hresult_survives_the_sign_it_is_documented_not_to_have() {
        assert_eq!(hresult::E_ABORT, -2_147_467_260);
        assert_eq!(hresult::E_ABORT as u32, 0x8000_4004);
        // The severity bit is the sign bit, which is the whole erratum.
        // A `const` block, so getting it wrong fails the build rather than a
        // test run.
        const { assert!(hresult::E_ABORT < 0) };
        assert!(!ClientInitiateMultitransportResponse {
            request_id: 1,
            hr_response: hresult::S_OK,
        }
        .is_refusal());

        let bytes = encode(&ClientInitiateMultitransportResponse::abort(0xdead_beef));
        let back = ClientInitiateMultitransportResponse::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back.hr_response, hresult::E_ABORT);
        assert_eq!(back.request_id, 0xdead_beef);
        assert_eq!(encode(&back), bytes);
    }

    /// An unnamed `requestedProtocol` is preserved: the structure is fixed
    /// width so nothing desyncs, and the answer is the same either way.
    #[test]
    fn an_unknown_requested_protocol_is_carried_rather_than_rejected() {
        let mut bytes = encode(&a_request());
        bytes[8] = 0x09;
        let request =
            ServerInitiateMultitransportRequest::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(
            request.requested_protocol,
            MultitransportProtocol::Unknown(0x0009)
        );
        assert_eq!(encode(&request), bytes);
        assert_eq!(request.refuse().hr_response, hresult::E_ABORT);
    }

    #[test]
    fn a_pdu_without_its_class_flag_is_refused() {
        let mut bytes = encode(&a_request());
        bytes[0] = 0x04;
        assert!(matches!(
            ServerInitiateMultitransportRequest::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField {
                field: "flags (SEC_TRANSPORT_REQ)",
                ..
            }
        ));

        let mut bytes = encode(&ClientInitiateMultitransportResponse::abort(1));
        bytes[0] = 0x02;
        assert!(matches!(
            ClientInitiateMultitransportResponse::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField {
                field: "flags (SEC_TRANSPORT_RSP)",
                ..
            }
        ));
    }

    #[test]
    fn every_prefix_errors_rather_than_panicking() {
        let request = encode(&a_request());
        for cut in 0..request.len() {
            assert!(
                ServerInitiateMultitransportRequest::decode(&mut Reader::new(&request[..cut]))
                    .is_err(),
                "a {cut} byte prefix of the request decoded"
            );
        }
        let response = encode(&ClientInitiateMultitransportResponse::abort(1));
        for cut in 0..response.len() {
            assert!(
                ClientInitiateMultitransportResponse::decode(&mut Reader::new(&response[..cut]))
                    .is_err(),
                "a {cut} byte prefix of the response decoded"
            );
        }
    }
}
