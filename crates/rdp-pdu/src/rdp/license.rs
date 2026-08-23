//! The licensing exchange, client side (MS-RDPBCGR 2.2.1.12, MS-RDPELE,
//! PRDRDP/13 §4.7).
//!
//! Every licensing PDU is a Send Data Request or Indication on the I/O
//! channel carrying a basic security header with `SEC_LICENSE_PKT`, then a
//! four byte [`LicensePreamble`], then a message.
//!
//! # What actually happens under TLS or CredSSP
//!
//! MS-RDPELE's full exchange is encrypted with RC4 keys derived from a
//! premaster secret the client encrypts under the server certificate of
//! `TS_UD_SC_SEC1` (MS-RDPELE 3.1.5.1, 5.1). Under an external security
//! protocol that certificate is absent (MS-RDPBCGR 2.2.1.4.3), so those keys
//! cannot exist, and Windows sends exactly one licensing PDU: an
//! `ERROR_ALERT` with `dwErrorCode = STATUS_VALID_CLIENT` and
//! `dwStateTransition = ST_NO_TRANSITION`, which means "no licence is
//! required, proceed to the capability exchange". That is the path phase 1
//! needs and the only one it completes.
//!
//! So this module decodes [`LicenseErrorMessage`] in full, walks the outer
//! structure of the four server messages so that a real licence server's
//! `LICENSE_REQUEST` is reported as "this server requires a Terminal Services
//! client access licence" rather than as a parse error, and encodes exactly
//! one client message: [`LicensePdu::client_error_alert`].
//!
//! # No cryptography, and none of the derivation either
//!
//! There is no RC4, no RSA and no hash in this file (PRDRDP/00 R54, V3-A).
//! The blobs of a `LICENSE_REQUEST` are carried as borrowed views and nothing
//! is derived from them. `ServerRandom` is a nonce rather than a secret; the
//! premaster secret and client random appear only in the client messages this
//! module does not encode, which is why nothing here needs zeroizing.
//!
//! PRDRDP/03 §2.8 says phase 1 also answers a `LICENSE_REQUEST` with a
//! `NEW_LICENSE_REQUEST`. PRDRDP/13 §4.7 says the opposite and gives the
//! reason: a `NEW_LICENSE_REQUEST` we cannot follow through on leaves the
//! server waiting and the user looking at a blank screen. This module
//! implements §4.7, and the contradiction is recorded rather than reconciled
//! silently.

use super::security::{security_flags, BasicSecurityHeader};
use crate::codes::{LicenseError, LicenseStateTransition};
use crate::io::limits::{MAX_LICENSE_BLOB, MAX_LICENSE_SCOPES};
use crate::io::{Decode, Encode, Payload, PduError, PduResult, Reader, Writer};

/// `LICENSE_PREAMBLE`: `bMsgType`, `flags`, `wMsgSize` (MS-RDPBCGR
/// 2.2.1.12.1.1).
pub const LICENSE_PREAMBLE_LEN: usize = 4;

/// `LICENSE_BINARY_BLOB`'s header: `wBlobType` and `wBlobLen` (MS-RDPBCGR
/// 2.2.1.12.1.2).
pub const LICENSE_BLOB_HEADER_LEN: usize = 4;

/// `LICENSE_PREAMBLE.bMsgType` (MS-RDPBCGR 2.2.1.12.1.1).
pub mod message_type {
    /// `LICENSE_REQUEST`, server to client (MS-RDPELE 2.2.2.1).
    pub const LICENSE_REQUEST: u8 = 0x01;
    /// `PLATFORM_CHALLENGE`, server to client (MS-RDPELE 2.2.2.4).
    pub const PLATFORM_CHALLENGE: u8 = 0x02;
    /// `NEW_LICENSE`, server to client (MS-RDPELE 2.2.2.6).
    pub const NEW_LICENSE: u8 = 0x03;
    /// `UPGRADE_LICENSE`, server to client (MS-RDPELE 2.2.2.7).
    pub const UPGRADE_LICENSE: u8 = 0x04;
    /// `LICENSE_INFO`, client to server (MS-RDPELE 2.2.2.2).
    pub const LICENSE_INFO: u8 = 0x12;
    /// `NEW_LICENSE_REQUEST`, client to server (MS-RDPELE 2.2.2.3).
    pub const NEW_LICENSE_REQUEST: u8 = 0x13;
    /// `PLATFORM_CHALLENGE_RESPONSE`, client to server (MS-RDPELE 2.2.2.5).
    pub const PLATFORM_CHALLENGE_RESPONSE: u8 = 0x15;
    /// `ERROR_ALERT`, either direction (MS-RDPBCGR 2.2.1.12.1.3).
    pub const ERROR_ALERT: u8 = 0xff;
}

/// `LICENSE_PREAMBLE.flags` (MS-RDPBCGR 2.2.1.12.1.1).
pub mod preamble_flags {
    /// `LicenseProtocolVersionMask`, the low nibble.
    pub const VERSION_MASK: u8 = 0x0f;
    /// `PREAMBLE_VERSION_2_0`.
    pub const VERSION_2_0: u8 = 0x02;
    /// `PREAMBLE_VERSION_3_0`, what every current server and client sends.
    pub const VERSION_3_0: u8 = 0x03;
    /// `EXTENDED_ERROR_MSG_SUPPORTED`.
    pub const EXTENDED_ERROR_MSG_SUPPORTED: u8 = 0x80;
}

/// `LICENSE_BINARY_BLOB.wBlobType` (MS-RDPBCGR 2.2.1.12.1.2).
pub mod blob_type {
    /// `BB_ANY_BLOB`.
    pub const ANY: u16 = 0x0000;
    /// `BB_DATA_BLOB`.
    pub const DATA: u16 = 0x0001;
    /// `BB_RANDOM_BLOB`.
    pub const RANDOM: u16 = 0x0002;
    /// `BB_CERTIFICATE_BLOB`.
    pub const CERTIFICATE: u16 = 0x0003;
    /// `BB_ERROR_BLOB`.
    pub const ERROR: u16 = 0x0004;
    /// `BB_ENCRYPTED_DATA_BLOB`.
    pub const ENCRYPTED_DATA: u16 = 0x0009;
    /// `BB_KEY_EXCHG_ALG_BLOB`.
    pub const KEY_EXCHG_ALG: u16 = 0x000d;
    /// `BB_SCOPE_BLOB`.
    pub const SCOPE: u16 = 0x000e;
    /// `BB_CLIENT_USER_NAME_BLOB`.
    pub const CLIENT_USER_NAME: u16 = 0x000f;
    /// `BB_CLIENT_MACHINE_NAME_BLOB`.
    pub const CLIENT_MACHINE_NAME: u16 = 0x0010;
}

/// `SERVER_LICENSE_REQUEST.ServerRandom` (MS-RDPELE 2.2.2.1).
pub const SERVER_RANDOM_LEN: usize = 32;

/// `LICENSE_PREAMBLE` (MS-RDPBCGR 2.2.1.12.1.1).
///
/// Fixed, four bytes, and `wMsgSize` counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicensePreamble {
    /// `bMsgType`, one of [`message_type`].
    pub msg_type: u8,
    /// `flags`, from [`preamble_flags`].
    pub flags: u8,
    /// `wMsgSize`, the whole message including these four bytes.
    pub msg_size: u16,
}

impl LicensePreamble {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "LICENSE_PREAMBLE";

    /// The licence protocol version from the low nibble of `flags`.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.flags & preamble_flags::VERSION_MASK
    }
}

impl Encode for LicensePreamble {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        LICENSE_PREAMBLE_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u8(self.msg_type);
        w.u8(self.flags);
        w.u16(self.msg_size);
        Ok(())
    }
}

impl Decode<'_> for LicensePreamble {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let msg_type = r.u8(Self::NAME)?;
        let flags = r.u8(Self::NAME)?;
        let at = r.offset();
        let msg_size = r.u16(Self::NAME)?;
        if usize::from(msg_size) < LICENSE_PREAMBLE_LEN {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "wMsgSize",
                value: u64::from(msg_size),
                offset: at,
            });
        }
        Ok(Self {
            msg_type,
            flags,
            msg_size,
        })
    }
}

/// `LICENSE_BINARY_BLOB` (MS-RDPBCGR 2.2.1.12.1.2).
///
/// The data is a borrowed view of the receive buffer. Nothing in this crate
/// interprets a blob's contents: the ones that matter carry a certificate or
/// an encrypted challenge, and both belong to a phase that is not written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicenseBinaryBlob<'a> {
    /// `wBlobType`, from [`blob_type`].
    pub blob_type: u16,
    /// `blobData`, `wBlobLen` bytes.
    pub data: Payload<'a>,
}

impl<'a> LicenseBinaryBlob<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "LICENSE_BINARY_BLOB";

    /// An empty blob of the given type, which is what a client sends when it
    /// has nothing to put in one.
    #[must_use]
    pub const fn empty(blob_type: u16) -> Self {
        Self {
            blob_type,
            data: Payload::new(&[]),
        }
    }

    /// Read one blob, capped by
    /// [`MAX_LICENSE_BLOB`](crate::io::limits::MAX_LICENSE_BLOB).
    pub fn read(r: &mut Reader<'a>, context: &'static str) -> PduResult<Self> {
        let blob_type = r.u16(context)?;
        let len = usize::from(r.u16(context)?);
        r.ensure_cap(len, MAX_LICENSE_BLOB, "MAX_LICENSE_BLOB", context)?;
        Ok(Self {
            blob_type,
            data: Payload::new(r.slice(len, context)?),
        })
    }
}

impl Encode for LicenseBinaryBlob<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        LICENSE_BLOB_HEADER_LEN + self.data.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let len = u16::try_from(self.data.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "blob longer than its wBlobLen field",
        })?;
        w.u16(self.blob_type);
        w.u16(len);
        w.bytes(self.data.as_slice());
        Ok(())
    }
}

/// `LICENSE_ERROR_MESSAGE` (MS-RDPBCGR 2.2.1.12.1.3).
///
/// Fixed rather than extensible per PRDRDP/13 §2.5: the three fields are all
/// there is, so a leftover byte means we mis-parsed and [`Self::read`] says
/// so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicenseErrorMessage<'a> {
    /// `dwErrorCode`.
    pub error_code: LicenseError,
    /// `dwStateTransition`.
    pub state_transition: LicenseStateTransition,
    /// `bbErrorInfo`, usually empty.
    pub error_info: LicenseBinaryBlob<'a>,
}

impl<'a> LicenseErrorMessage<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "LICENSE_ERROR_MESSAGE";

    /// True for the one message a TLS or CredSSP session actually sees:
    /// `STATUS_VALID_CLIENT` with `ST_NO_TRANSITION`, meaning "no licence is
    /// required, carry on" (PRDRDP/03 §2.8).
    #[must_use]
    pub const fn is_valid_client(&self) -> bool {
        matches!(self.error_code, LicenseError::StatusValidClient)
    }

    /// Read the body of an `ERROR_ALERT`, the preamble already consumed.
    pub fn read(r: &mut Reader<'a>) -> PduResult<Self> {
        let out = Self {
            error_code: LicenseError::from_u32(r.u32(Self::NAME)?),
            state_transition: LicenseStateTransition::from_u32(r.u32(Self::NAME)?),
            error_info: LicenseBinaryBlob::read(r, Self::NAME)?,
        };
        r.expect_empty(Self::NAME)?;
        Ok(out)
    }
}

impl Encode for LicenseErrorMessage<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + 4 + self.error_info.size()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.error_code.to_u32());
        w.u32(self.state_transition.to_u32());
        self.error_info.encode(w)
    }
}

/// `PRODUCT_INFO` (MS-RDPELE 2.2.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductInfo<'a> {
    /// `dwVersion`.
    pub version: u32,
    /// `pbCompanyName`, UTF-16LE text we do not decode.
    pub company_name: Payload<'a>,
    /// `pbProductId`, UTF-16LE text we do not decode.
    pub product_id: Payload<'a>,
}

impl<'a> ProductInfo<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "PRODUCT_INFO";

    /// Walk one, which is all a client that declines the exchange needs.
    pub fn read(r: &mut Reader<'a>) -> PduResult<Self> {
        let version = r.u32(Self::NAME)?;
        let cb_company_name = r.u32(Self::NAME)? as usize;
        r.ensure_cap(
            cb_company_name,
            MAX_LICENSE_BLOB,
            "MAX_LICENSE_BLOB",
            Self::NAME,
        )?;
        let company_name = Payload::new(r.slice(cb_company_name, Self::NAME)?);
        let cb_product_id = r.u32(Self::NAME)? as usize;
        r.ensure_cap(
            cb_product_id,
            MAX_LICENSE_BLOB,
            "MAX_LICENSE_BLOB",
            Self::NAME,
        )?;
        let product_id = Payload::new(r.slice(cb_product_id, Self::NAME)?);
        Ok(Self {
            version,
            company_name,
            product_id,
        })
    }
}

/// `SERVER_LICENSE_REQUEST` (MS-RDPELE 2.2.2.1).
///
/// Walked rather than understood. Every field is a length prefixed blob, so
/// the whole message can be traversed without any of the cryptography that
/// would be needed to answer it, and the session can tell the user that this
/// server wants a real client access licence (PRDRDP/03 §2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerLicenseRequest<'a> {
    /// `ServerRandom`, a nonce and not a secret.
    pub server_random: Payload<'a>,
    /// `ProductInfo`.
    pub product_info: ProductInfo<'a>,
    /// `KeyExchangeList`.
    pub key_exchange_list: LicenseBinaryBlob<'a>,
    /// `ServerCertificate`, which `rdp-auth` would need for a real exchange.
    pub server_certificate: LicenseBinaryBlob<'a>,
    /// `ScopeList`, one blob per scope.
    pub scopes: Vec<LicenseBinaryBlob<'a>>,
}

impl<'a> ServerLicenseRequest<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "SERVER_LICENSE_REQUEST";

    /// Walk one, the preamble already consumed.
    ///
    /// Extensible per PRDRDP/13 §2.5: MS-RDPELE has added fields to this
    /// message and a client that rejects a longer one is a client that breaks
    /// on the next revision, so there is no `expect_empty` here.
    pub fn read(r: &mut Reader<'a>) -> PduResult<Self> {
        let server_random = Payload::new(r.slice(SERVER_RANDOM_LEN, Self::NAME)?);
        let product_info = ProductInfo::read(r)?;
        let key_exchange_list = LicenseBinaryBlob::read(r, Self::NAME)?;
        let server_certificate = LicenseBinaryBlob::read(r, Self::NAME)?;
        let scope_count = r.u32(Self::NAME)? as usize;
        r.ensure_cap(
            scope_count,
            MAX_LICENSE_SCOPES,
            "MAX_LICENSE_SCOPES",
            Self::NAME,
        )?;
        let mut scopes = Vec::with_capacity(scope_count);
        for _ in 0..scope_count {
            scopes.push(LicenseBinaryBlob::read(r, Self::NAME)?);
        }
        Ok(Self {
            server_random,
            product_info,
            key_exchange_list,
            server_certificate,
            scopes,
        })
    }
}

/// One licensing PDU, security header and preamble included (MS-RDPBCGR
/// 2.2.1.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseMessage<'a> {
    /// `ERROR_ALERT`, the only message this client sends and the only one a
    /// TLS session normally receives.
    ErrorAlert(LicenseErrorMessage<'a>),
    /// `LICENSE_REQUEST`, walked far enough to report it.
    LicenseRequest(Box<ServerLicenseRequest<'a>>),
    /// A server message we do not implement, carried whole so the session can
    /// name it and decline. Its length is known, so preserving it is right
    /// (PRDRDP/13 §2.7 rule 3).
    Unimplemented {
        /// `bMsgType`.
        msg_type: u8,
        /// Everything after the preamble.
        body: Payload<'a>,
    },
}

/// A licensing PDU: the basic security header, the preamble, and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicensePdu<'a> {
    /// The preamble, kept so the session can log `wMsgSize` and the version.
    pub preamble: LicensePreamble,
    /// The message itself.
    pub message: LicenseMessage<'a>,
}

impl<'a> LicensePdu<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "LICENSE_PDU";

    /// The one client message this crate encodes: an `ERROR_ALERT` with
    /// `ERR_INVALID_CLIENT` and `ST_TOTAL_ABORT`, which declines a real
    /// licence exchange cleanly (PRDRDP/13 §4.7).
    #[must_use]
    pub fn client_error_alert() -> Self {
        let message = LicenseErrorMessage {
            error_code: LicenseError::InvalidClient,
            state_transition: LicenseStateTransition::TotalAbort,
            error_info: LicenseBinaryBlob::empty(blob_type::ANY),
        };
        Self {
            preamble: LicensePreamble {
                msg_type: message_type::ERROR_ALERT,
                flags: preamble_flags::VERSION_3_0,
                msg_size: (LICENSE_PREAMBLE_LEN + message.size()) as u16,
            },
            message: LicenseMessage::ErrorAlert(message),
        }
    }

    /// True when this is the "no licence needed, carry on" message.
    #[must_use]
    pub const fn is_valid_client(&self) -> bool {
        match &self.message {
            LicenseMessage::ErrorAlert(error) => error.is_valid_client(),
            _ => false,
        }
    }
}

impl Encode for LicensePdu<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        let body = match &self.message {
            LicenseMessage::ErrorAlert(error) => error.size(),
            LicenseMessage::LicenseRequest(_) => {
                usize::from(self.preamble.msg_size).saturating_sub(LICENSE_PREAMBLE_LEN)
            }
            LicenseMessage::Unimplemented { body, .. } => body.len(),
        };
        super::security::BASIC_SECURITY_HEADER_LEN + LICENSE_PREAMBLE_LEN + body
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        BasicSecurityHeader::new(security_flags::LICENSE_PKT).encode(w)?;
        self.preamble.encode(w)?;
        match &self.message {
            LicenseMessage::ErrorAlert(error) => error.encode(w),
            LicenseMessage::Unimplemented { body, .. } => {
                w.bytes(body.as_slice());
                Ok(())
            }
            // A walked `LICENSE_REQUEST` cannot be rebuilt from its parts
            // without keeping every byte, and nothing needs to: we never send
            // one. Saying so is better than emitting a message that looks
            // right and is short by a scope.
            LicenseMessage::LicenseRequest(_) => Err(PduError::Encode {
                context: Self::NAME,
                reason: "SERVER_LICENSE_REQUEST is decoded only; this client never sends one",
            }),
        }
    }
}

impl<'a> Decode<'a> for LicensePdu<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let header = BasicSecurityHeader::decode(r)?;
        if !header.has(security_flags::LICENSE_PKT) {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "flags (SEC_LICENSE_PKT)",
                value: u64::from(header.flags),
                offset: at,
            });
        }
        let preamble = LicensePreamble::decode(r)?;
        let mut body = r.take(
            usize::from(preamble.msg_size) - LICENSE_PREAMBLE_LEN,
            Self::NAME,
        )?;
        let message = match preamble.msg_type {
            message_type::ERROR_ALERT => {
                LicenseMessage::ErrorAlert(LicenseErrorMessage::read(&mut body)?)
            }
            message_type::LICENSE_REQUEST => {
                LicenseMessage::LicenseRequest(Box::new(ServerLicenseRequest::read(&mut body)?))
            }
            msg_type => {
                tracing::trace!(
                    msg_type,
                    "a licensing message this client does not implement"
                );
                LicenseMessage::Unimplemented {
                    msg_type,
                    body: Payload::new(body.rest()),
                }
            }
        };
        Ok(Self { preamble, message })
    }
}

/// Read a licensing message body, the preamble already consumed and `body`
/// bounded by `wMsgSize`.
///
/// Public because [`decode_io_pdu`](super::decode_io_pdu) reads the preamble
/// itself, and two copies of this dispatch would drift.
pub fn read_message<'a>(body: &mut Reader<'a>, msg_type: u8) -> PduResult<LicenseMessage<'a>> {
    Ok(match msg_type {
        message_type::ERROR_ALERT => LicenseMessage::ErrorAlert(LicenseErrorMessage::read(body)?),
        message_type::LICENSE_REQUEST => {
            LicenseMessage::LicenseRequest(Box::new(ServerLicenseRequest::read(body)?))
        }
        other => {
            tracing::trace!(
                msg_type = other,
                "a licensing message this client does not implement"
            );
            LicenseMessage::Unimplemented {
                msg_type: other,
                body: Payload::new(body.rest()),
            }
        }
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

    /// The one licensing PDU a TLS session sees: a basic security header with
    /// `SEC_LICENSE_PKT`, the preamble, then `STATUS_VALID_CLIENT` with
    /// `ST_NO_TRANSITION` and an empty error blob.
    ///
    /// These twenty bytes are built from the field definitions above and
    /// match the annotated Server License Error PDU of MS-RDPBCGR 4.1.12.
    /// PRDRDP/13 §9.5 Q6 wants every golden to record the document revision
    /// it was transcribed from, and this one cannot until somebody checks it
    /// against the PDF in hand; until then it is a hand built vector that
    /// happens to agree with the example, not a transcription.
    const VALID_CLIENT: &[u8] = &[
        0x80, 0x00, 0x00, 0x00, // SEC_LICENSE_PKT
        0xff, 0x03, 0x10, 0x00, // ERROR_ALERT, PREAMBLE_VERSION_3_0, 16 bytes
        0x07, 0x00, 0x00, 0x00, // STATUS_VALID_CLIENT
        0x02, 0x00, 0x00, 0x00, // ST_NO_TRANSITION
        0x04, 0x00, 0x00, 0x00, // BB_ERROR_BLOB, empty
    ];

    #[test]
    fn the_valid_client_alert_decodes_and_says_carry_on() {
        let pdu = LicensePdu::decode(&mut Reader::new(VALID_CLIENT)).unwrap();
        assert_eq!(pdu.preamble.msg_type, message_type::ERROR_ALERT);
        assert_eq!(pdu.preamble.version(), preamble_flags::VERSION_3_0);
        assert_eq!(pdu.preamble.msg_size, 16);
        assert!(pdu.is_valid_client());
        let LicenseMessage::ErrorAlert(error) = &pdu.message else {
            panic!("not an error alert");
        };
        assert_eq!(error.error_code, LicenseError::StatusValidClient);
        assert_eq!(error.state_transition, LicenseStateTransition::NoTransition);
        assert_eq!(error.error_info.blob_type, blob_type::ERROR);
        assert!(error.error_info.data.is_empty());
        assert_eq!(encode(&pdu), VALID_CLIENT);
    }

    #[test]
    fn the_client_error_alert_is_the_only_message_we_encode() {
        let pdu = LicensePdu::client_error_alert();
        let bytes = encode(&pdu);
        assert_eq!(
            bytes,
            [
                0x80, 0x00, 0x00, 0x00, 0xff, 0x03, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
        let back = LicensePdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back, pdu);
        assert!(!back.is_valid_client());
    }

    /// A real licence server's request is walked, not answered, and every
    /// blob comes back intact so the session can say what was asked for.
    #[test]
    fn a_license_request_is_walked_far_enough_to_report_it() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xaa; SERVER_RANDOM_LEN]);
        // PRODUCT_INFO: dwVersion, then two length prefixed strings.
        body.extend_from_slice(&0x0006_0000_u32.to_le_bytes());
        body.extend_from_slice(&4_u32.to_le_bytes());
        body.extend_from_slice(b"M\0S\0");
        body.extend_from_slice(&2_u32.to_le_bytes());
        body.extend_from_slice(b"A\0");
        // KeyExchangeList, ServerCertificate.
        body.extend_from_slice(&blob_type::KEY_EXCHG_ALG.to_le_bytes());
        body.extend_from_slice(&4_u16.to_le_bytes());
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(&blob_type::CERTIFICATE.to_le_bytes());
        body.extend_from_slice(&3_u16.to_le_bytes());
        body.extend_from_slice(&[0x30, 0x82, 0x01]);
        // ScopeList with one scope.
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(&blob_type::SCOPE.to_le_bytes());
        body.extend_from_slice(&5_u16.to_le_bytes());
        body.extend_from_slice(b"micro");

        let mut pdu = vec![0x80, 0x00, 0x00, 0x00, message_type::LICENSE_REQUEST, 0x03];
        let msg_size = (LICENSE_PREAMBLE_LEN + body.len()) as u16;
        pdu.extend_from_slice(&msg_size.to_le_bytes());
        pdu.extend_from_slice(&body);

        let decoded = LicensePdu::decode(&mut Reader::new(&pdu)).unwrap();
        let LicenseMessage::LicenseRequest(request) = &decoded.message else {
            panic!("not a license request");
        };
        assert_eq!(request.server_random.len(), SERVER_RANDOM_LEN);
        assert_eq!(request.product_info.version, 0x0006_0000);
        assert_eq!(request.product_info.company_name.as_slice(), b"M\0S\0");
        assert_eq!(
            request.server_certificate.data.as_slice(),
            &[0x30, 0x82, 0x01]
        );
        assert_eq!(request.scopes.len(), 1);
        assert_eq!(request.scopes[0].data.as_slice(), b"micro");
        assert!(!decoded.is_valid_client());
        // And it is decode only: we never send one.
        let mut buf = Vec::new();
        assert!(decoded.encode(&mut Writer::new(&mut buf)).is_err());
    }

    /// A message we do not implement is carried whole rather than rejected,
    /// because its length is known.
    #[test]
    fn an_unimplemented_message_is_preserved() {
        let bytes = [
            0x80,
            0x00,
            0x00,
            0x00,
            message_type::PLATFORM_CHALLENGE,
            0x03,
            0x08,
            0x00,
            0xde,
            0xad,
            0xbe,
            0xef,
        ];
        let pdu = LicensePdu::decode(&mut Reader::new(&bytes)).unwrap();
        let LicenseMessage::Unimplemented { msg_type, body } = &pdu.message else {
            panic!("not preserved");
        };
        assert_eq!(*msg_type, message_type::PLATFORM_CHALLENGE);
        assert_eq!(body.as_slice(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(encode(&pdu), bytes);
    }

    /// `LICENSE_ERROR_MESSAGE` is fixed, so a trailing byte is a mis-parse
    /// and not an extension (PRDRDP/13 §2.5).
    #[test]
    fn a_trailing_byte_on_an_error_alert_is_a_length_mismatch() {
        let mut bytes = VALID_CLIENT.to_vec();
        bytes.push(0xff);
        // `wMsgSize` covers the extra byte, so the body reader hands it to
        // the error message decoder, which refuses it.
        bytes[6] = 0x11;
        let err = LicensePdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(err, PduError::LengthMismatch { .. }), "{err:?}");
    }

    #[test]
    fn a_msg_size_below_the_preamble_is_an_invalid_field() {
        let mut bytes = VALID_CLIENT.to_vec();
        bytes[6] = 0x03;
        let err = LicensePdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "wMsgSize",
                ..
            }
        ));
    }

    #[test]
    fn a_missing_license_flag_is_an_invalid_field() {
        let mut bytes = VALID_CLIENT.to_vec();
        bytes[0] = 0x40;
        let err = LicensePdu::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "flags (SEC_LICENSE_PKT)",
                ..
            }
        ));
    }

    #[test]
    fn every_prefix_errors_rather_than_panicking() {
        for bytes in [VALID_CLIENT, &encode(&LicensePdu::client_error_alert())] {
            for cut in 0..bytes.len() {
                assert!(
                    LicensePdu::decode(&mut Reader::new(&bytes[..cut])).is_err(),
                    "a {cut} byte prefix decoded successfully"
                );
            }
        }
    }
}
