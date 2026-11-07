//! The licensing exchange, client side (MS-RDPBCGR 2.2.1.12, MS-RDPELE,
//! PRDRDP/13 §4.7).
//!
//! Every licensing PDU is a Send Data Request or Indication on the I/O
//! channel carrying a basic security header with `SEC_LICENSE_PKT`, then a
//! four byte [`LicensePreamble`], then a message.
//!
//! # What actually happens under TLS or CredSSP
//!
//! A Windows host with no Remote Desktop licensing configured, every client
//! edition of Windows included, sends exactly one licensing PDU: an
//! `ERROR_ALERT` with `dwErrorCode = STATUS_VALID_CLIENT` and
//! `dwStateTransition = ST_NO_TRANSITION`, which means "no licence is
//! required, proceed to the capability exchange".
//!
//! An RD Session Host with a licence server sends a `LICENSE_REQUEST`
//! instead, and it does so under TLS and CredSSP too. The `TS_UD_SC_SEC1`
//! certificate is absent under an external security protocol (MS-RDPBCGR
//! 2.2.1.4.3), so the request's own `ServerCertificate` blob carries the key
//! the premaster secret is encrypted under (MS-RDPELE 3.1.5.1). The client
//! then sends a `NEW_LICENSE_REQUEST` or, holding a licence from an earlier
//! connection, a `LICENSE_INFO`; the server answers with a
//! `PLATFORM_CHALLENGE`, the client with a `PLATFORM_CHALLENGE_RESPONSE`,
//! and the server ends the exchange with `NEW_LICENSE`, `UPGRADE_LICENSE` or
//! `STATUS_VALID_CLIENT` (MS-RDPELE 1.3.3).
//!
//! # No cryptography here
//!
//! There is no RC4, no RSA and no hash in this file (PRDRDP/00 R54, V3-A).
//! Encrypted blobs are carried as bytes in both directions; `rdp-auth`'s
//! `licensing` module derives the keys and does the encryption, and
//! `rdp-core` decides what to send. Every structure here is plain layout.

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

/// `ClientRandom` of the two client requests (MS-RDPELE 2.2.2.2, 2.2.2.3).
pub const CLIENT_RANDOM_LEN: usize = 32;

/// Every `MACData` field in MS-RDPELE is sixteen bytes.
pub const LICENSE_MAC_LEN: usize = 16;

/// `CLIENT_HARDWARE_ID` (MS-RDPELE 2.2.2.3.1): `PlatformId` and four
/// `DataN` fields, twenty bytes in all.
pub const HARDWARE_ID_LEN: usize = 20;

/// `KEY_EXCHANGE_ALG_RSA`, the only key exchange algorithm MS-RDPELE
/// defines (2.2.2.2).
pub const KEY_EXCHANGE_ALG_RSA: u32 = 0x0000_0001;

/// `PlatformId` of the client requests (MS-RDPELE 2.2.2.2): the operating
/// system identifier in the high byte and the ISV in the next. FreeRDP and
/// mstsc both send `CLIENT_OS_ID_WINNT_POST_52 | CLIENT_IMAGE_ID_MICROSOFT`.
pub const PLATFORM_ID: u32 = 0x0400_0000 | 0x0001_0000;

/// `PLATFORM_CHALLENGE_RESPONSE_DATA.wVersion` (MS-RDPELE 2.2.2.5.1).
pub const PLATFORM_CHALLENGE_RESPONSE_VERSION: u16 = 0x0100;

/// `wClientType`: `OTHER_PLATFORM_CHALLENGE_TYPE` (MS-RDPELE 2.2.2.5.1).
pub const OTHER_PLATFORM_CHALLENGE_TYPE: u16 = 0xff00;

/// `wLicenseDetailLevel`: `LICENSE_DETAIL_DETAIL` (MS-RDPELE 2.2.2.5.1).
pub const LICENSE_DETAIL_DETAIL: u16 = 0x0003;

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
    /// `LICENSE_REQUEST` (MS-RDPELE 2.2.2.1).
    LicenseRequest(Box<ServerLicenseRequest<'a>>),
    /// `PLATFORM_CHALLENGE` (MS-RDPELE 2.2.2.4).
    PlatformChallenge(ServerPlatformChallenge<'a>),
    /// `NEW_LICENSE` or `UPGRADE_LICENSE` (MS-RDPELE 2.2.2.6, 2.2.2.7). The
    /// two have the same layout; `upgrade` says which one arrived.
    NewLicense {
        /// True for `UPGRADE_LICENSE`.
        upgrade: bool,
        /// The message.
        license: ServerNewLicense<'a>,
    },
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
            LicenseMessage::PlatformChallenge(challenge) => challenge.size(),
            LicenseMessage::NewLicense { license, .. } => license.size(),
            LicenseMessage::Unimplemented { body, .. } => body.len(),
        };
        super::security::BASIC_SECURITY_HEADER_LEN + LICENSE_PREAMBLE_LEN + body
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        BasicSecurityHeader::new(security_flags::LICENSE_PKT).encode(w)?;
        self.preamble.encode(w)?;
        match &self.message {
            LicenseMessage::ErrorAlert(error) => error.encode(w),
            LicenseMessage::PlatformChallenge(challenge) => challenge.encode(w),
            LicenseMessage::NewLicense { license, .. } => license.encode(w),
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
        let message = read_message(&mut body, preamble.msg_type)?;
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
        message_type::PLATFORM_CHALLENGE => {
            LicenseMessage::PlatformChallenge(ServerPlatformChallenge::read(body)?)
        }
        message_type::NEW_LICENSE | message_type::UPGRADE_LICENSE => LicenseMessage::NewLicense {
            upgrade: msg_type == message_type::UPGRADE_LICENSE,
            license: ServerNewLicense::read(body)?,
        },
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

/// Write a blob whose type is fixed by its position, the way every field of
/// the client messages is.
fn write_blob(
    w: &mut Writer<'_>,
    blob_type: u16,
    data: &[u8],
    context: &'static str,
) -> PduResult<()> {
    let len = u16::try_from(data.len()).map_err(|_| PduError::Encode {
        context,
        reason: "blob longer than its wBlobLen field",
    })?;
    w.u16(blob_type);
    w.u16(len);
    w.bytes(data);
    Ok(())
}

/// `SERVER_PLATFORM_CHALLENGE` (MS-RDPELE 2.2.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerPlatformChallenge<'a> {
    /// `ConnectFlags`, reserved.
    pub connect_flags: u32,
    /// `EncryptedPlatformChallenge`, RC4 under the licensing encryption key.
    /// Windows sends it as `BB_ANY_BLOB`, so the type is not checked.
    pub encrypted_challenge: LicenseBinaryBlob<'a>,
    /// `MACData` over the decrypted challenge.
    pub mac: [u8; LICENSE_MAC_LEN],
}

impl<'a> ServerPlatformChallenge<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "SERVER_PLATFORM_CHALLENGE";

    /// Read one, the preamble already consumed.
    pub fn read(r: &mut Reader<'a>) -> PduResult<Self> {
        let out = Self {
            connect_flags: r.u32(Self::NAME)?,
            encrypted_challenge: LicenseBinaryBlob::read(r, Self::NAME)?,
            mac: r.array(Self::NAME)?,
        };
        r.expect_empty(Self::NAME)?;
        Ok(out)
    }
}

impl Encode for ServerPlatformChallenge<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + self.encrypted_challenge.size() + LICENSE_MAC_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.connect_flags);
        self.encrypted_challenge.encode(w)?;
        w.bytes(&self.mac);
        Ok(())
    }
}

/// `SERVER_NEW_LICENSE` and `SERVER_UPGRADE_LICENSE` (MS-RDPELE 2.2.2.6,
/// 2.2.2.7), which share one layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerNewLicense<'a> {
    /// `EncryptedLicenseInfo`: a [`NewLicenseInfo`] under RC4. Windows
    /// Server 2003 sends it with a type other than `BB_ENCRYPTED_DATA_BLOB`
    /// (FreeRDP records the same), so the type is not checked.
    pub encrypted_license_info: LicenseBinaryBlob<'a>,
    /// `MACData` over the decrypted licence information.
    pub mac: [u8; LICENSE_MAC_LEN],
}

impl<'a> ServerNewLicense<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "SERVER_NEW_LICENSE";

    /// Read one, the preamble already consumed.
    pub fn read(r: &mut Reader<'a>) -> PduResult<Self> {
        let out = Self {
            encrypted_license_info: LicenseBinaryBlob::read(r, Self::NAME)?,
            mac: r.array(Self::NAME)?,
        };
        r.expect_empty(Self::NAME)?;
        Ok(out)
    }
}

impl Encode for ServerNewLicense<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        self.encrypted_license_info.size() + LICENSE_MAC_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        self.encrypted_license_info.encode(w)?;
        w.bytes(&self.mac);
        Ok(())
    }
}

/// `NEW_LICENSE_INFO` (MS-RDPELE 2.2.2.6.1), the plaintext of
/// [`ServerNewLicense::encrypted_license_info`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewLicenseInfo<'a> {
    /// `dwVersion`: the minor version in the low word, the major in the high.
    pub version: u32,
    /// `pbScope`, a NUL terminated ANSI string.
    pub scope: &'a [u8],
    /// `pbCompanyName`, UTF-16LE.
    pub company_name: &'a [u8],
    /// `pbProductId`, UTF-16LE.
    pub product_id: &'a [u8],
    /// `pbLicenseInfo`: the licence itself, which the client stores as it is
    /// and presents in `LICENSE_INFO` on the next connection.
    pub license_info: &'a [u8],
}

impl<'a> NewLicenseInfo<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "NEW_LICENSE_INFO";

    fn counted(r: &mut Reader<'a>) -> PduResult<&'a [u8]> {
        let len = r.u32(Self::NAME)? as usize;
        r.ensure_cap(len, MAX_LICENSE_BLOB, "MAX_LICENSE_BLOB", Self::NAME)?;
        r.slice(len, Self::NAME)
    }

    /// Read the decrypted licence information. Extensible per PRDRDP/13
    /// §2.5, so trailing bytes are ignored rather than refused.
    pub fn read(r: &mut Reader<'a>) -> PduResult<Self> {
        Ok(Self {
            version: r.u32(Self::NAME)?,
            scope: Self::counted(r)?,
            company_name: Self::counted(r)?,
            product_id: Self::counted(r)?,
            license_info: Self::counted(r)?,
        })
    }
}

impl Encode for NewLicenseInfo<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + 4 * 4
            + self.scope.len()
            + self.company_name.len()
            + self.product_id.len()
            + self.license_info.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u32(self.version);
        for field in [
            self.scope,
            self.company_name,
            self.product_id,
            self.license_info,
        ] {
            let len = u32::try_from(field.len()).map_err(|_| PduError::Encode {
                context: Self::NAME,
                reason: "field longer than its u32 length",
            })?;
            w.u32(len);
            w.bytes(field);
        }
        Ok(())
    }
}

/// The fields `NEW_LICENSE_REQUEST` and `LICENSE_INFO` open with.
fn write_client_preface(
    w: &mut Writer<'_>,
    client_random: &[u8; CLIENT_RANDOM_LEN],
    encrypted_premaster_secret: &[u8],
    context: &'static str,
) -> PduResult<()> {
    w.u32(KEY_EXCHANGE_ALG_RSA);
    w.u32(PLATFORM_ID);
    w.bytes(client_random);
    write_blob(w, blob_type::RANDOM, encrypted_premaster_secret, context)
}

/// `CLIENT_NEW_LICENSE_REQUEST` (MS-RDPELE 2.2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientNewLicenseRequest<'a> {
    /// `ClientRandom`.
    pub client_random: [u8; CLIENT_RANDOM_LEN],
    /// `EncryptedPreMasterSecret`: the RSA output, little endian, already
    /// padded with the eight zero bytes MS-RDPELE 2.2.2.3 asks for.
    pub encrypted_premaster_secret: &'a [u8],
    /// `ClientUserName`, NUL terminated ANSI.
    pub user_name: &'a [u8],
    /// `ClientMachineName`, NUL terminated ANSI.
    pub machine_name: &'a [u8],
}

impl ClientNewLicenseRequest<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "CLIENT_NEW_LICENSE_REQUEST";
}

impl Encode for ClientNewLicenseRequest<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + 4
            + CLIENT_RANDOM_LEN
            + LICENSE_BLOB_HEADER_LEN * 3
            + self.encrypted_premaster_secret.len()
            + self.user_name.len()
            + self.machine_name.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_client_preface(
            w,
            &self.client_random,
            self.encrypted_premaster_secret,
            Self::NAME,
        )?;
        write_blob(w, blob_type::CLIENT_USER_NAME, self.user_name, Self::NAME)?;
        write_blob(
            w,
            blob_type::CLIENT_MACHINE_NAME,
            self.machine_name,
            Self::NAME,
        )
    }
}

/// `CLIENT_LICENSE_INFO` (MS-RDPELE 2.2.2.2): the licence from an earlier
/// connection, presented instead of a new request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientLicenseInfo<'a> {
    /// `ClientRandom`.
    pub client_random: [u8; CLIENT_RANDOM_LEN],
    /// `EncryptedPreMasterSecret`, as in [`ClientNewLicenseRequest`].
    pub encrypted_premaster_secret: &'a [u8],
    /// `LicenseInfo`: the stored licence, exactly as the server issued it.
    pub license_info: &'a [u8],
    /// `EncryptedHWID`: the [`HARDWARE_ID_LEN`] byte hardware id under RC4.
    pub encrypted_hwid: &'a [u8],
    /// `MACData` over the plaintext hardware id.
    pub mac: [u8; LICENSE_MAC_LEN],
}

impl ClientLicenseInfo<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "CLIENT_LICENSE_INFO";
}

impl Encode for ClientLicenseInfo<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        4 + 4
            + CLIENT_RANDOM_LEN
            + LICENSE_BLOB_HEADER_LEN * 3
            + self.encrypted_premaster_secret.len()
            + self.license_info.len()
            + self.encrypted_hwid.len()
            + LICENSE_MAC_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_client_preface(
            w,
            &self.client_random,
            self.encrypted_premaster_secret,
            Self::NAME,
        )?;
        write_blob(w, blob_type::DATA, self.license_info, Self::NAME)?;
        write_blob(
            w,
            blob_type::ENCRYPTED_DATA,
            self.encrypted_hwid,
            Self::NAME,
        )?;
        w.bytes(&self.mac);
        Ok(())
    }
}

/// `PLATFORM_CHALLENGE_RESPONSE_DATA` (MS-RDPELE 2.2.2.5.1), the plaintext
/// the client encrypts into its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformChallengeResponseData<'a> {
    /// `pbChallenge`: the decrypted platform challenge, echoed.
    pub challenge: &'a [u8],
}

impl PlatformChallengeResponseData<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "PLATFORM_CHALLENGE_RESPONSE_DATA";
}

impl Encode for PlatformChallengeResponseData<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        8 + self.challenge.len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let len = u16::try_from(self.challenge.len()).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "challenge longer than cbChallenge",
        })?;
        w.u16(PLATFORM_CHALLENGE_RESPONSE_VERSION);
        w.u16(OTHER_PLATFORM_CHALLENGE_TYPE);
        w.u16(LICENSE_DETAIL_DETAIL);
        w.u16(len);
        w.bytes(self.challenge);
        Ok(())
    }
}

/// `CLIENT_PLATFORM_CHALLENGE_RESPONSE` (MS-RDPELE 2.2.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientPlatformChallengeResponse<'a> {
    /// `EncryptedPlatformChallengeResponse`: a
    /// [`PlatformChallengeResponseData`] under RC4.
    pub encrypted_response: &'a [u8],
    /// `EncryptedHWID`.
    pub encrypted_hwid: &'a [u8],
    /// `MACData` over the plaintext response data followed by the plaintext
    /// hardware id.
    pub mac: [u8; LICENSE_MAC_LEN],
}

impl ClientPlatformChallengeResponse<'_> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "CLIENT_PLATFORM_CHALLENGE_RESPONSE";
}

impl Encode for ClientPlatformChallengeResponse<'_> {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        LICENSE_BLOB_HEADER_LEN * 2
            + self.encrypted_response.len()
            + self.encrypted_hwid.len()
            + LICENSE_MAC_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        write_blob(
            w,
            blob_type::ENCRYPTED_DATA,
            self.encrypted_response,
            Self::NAME,
        )?;
        write_blob(
            w,
            blob_type::ENCRYPTED_DATA,
            self.encrypted_hwid,
            Self::NAME,
        )?;
        w.bytes(&self.mac);
        Ok(())
    }
}

/// A client licensing PDU: the basic security header with `SEC_LICENSE_PKT`,
/// a preamble, and one of the client messages above.
///
/// `EXTENDED_ERROR_MSG_SUPPORTED` is set, as mstsc and FreeRDP set it: it
/// tells the server the client understands an `ERROR_ALERT` in the middle of
/// the exchange (MS-RDPBCGR 2.2.1.12.1.1).
///
/// # Errors
///
/// [`PduError::Encode`] when the message does not fit `wMsgSize`.
pub fn encode_client_message(msg_type: u8, message: &impl Encode) -> PduResult<Vec<u8>> {
    let msg_size =
        u16::try_from(LICENSE_PREAMBLE_LEN + message.size()).map_err(|_| PduError::Encode {
            context: LicensePdu::NAME,
            reason: "licensing message longer than wMsgSize",
        })?;
    let preamble = LicensePreamble {
        msg_type,
        flags: preamble_flags::VERSION_3_0 | preamble_flags::EXTENDED_ERROR_MSG_SUPPORTED,
        msg_size,
    };
    let mut out =
        Vec::with_capacity(super::security::BASIC_SECURITY_HEADER_LEN + usize::from(msg_size));
    let mut w = Writer::new(&mut out);
    BasicSecurityHeader::new(security_flags::LICENSE_PKT).encode(&mut w)?;
    preamble.encode(&mut w)?;
    message.encode_checked(&mut w)?;
    Ok(out)
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
            message_type::LICENSE_INFO,
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
        assert_eq!(*msg_type, message_type::LICENSE_INFO);
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

    /// A hex dump from `testdata/`, whitespace separated.
    fn hex_file(text: &str) -> Vec<u8> {
        text.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    /// The examples of MS-RDPELE section 4 (revision 18.0) are licensing
    /// messages without the security header, so each one gets the four
    /// bytes of `SEC_LICENSE_PKT` in front.
    fn with_header(message: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x00, 0x00, 0x00];
        out.extend_from_slice(message);
        out
    }

    const SPEC_4_1: &str = include_str!("../../testdata/rdpele-4.1-license-request.hex");
    const SPEC_4_2: &str = include_str!("../../testdata/rdpele-4.2-new-license-request.hex");

    /// MS-RDPELE 4.1, a Windows licence server's `LICENSE_REQUEST`, decodes
    /// in full, and the RSA key the premaster secret goes under comes out of
    /// the last certificate of its X.509 chain.
    #[test]
    fn the_specification_license_request_decodes_and_yields_its_key() {
        let bytes = with_header(&hex_file(SPEC_4_1));
        let pdu = LicensePdu::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(pdu.preamble.msg_size, 0x0898);
        let LicenseMessage::LicenseRequest(request) = &pdu.message else {
            panic!("not a license request");
        };
        assert_eq!(
            request.server_random.as_slice()[..4],
            [0x84, 0xef, 0xae, 0x20]
        );
        assert_eq!(request.product_info.version, 0x0006_0000);
        assert_eq!(request.product_info.company_name.len(), 0x2c);
        assert_eq!(request.key_exchange_list.data.as_slice(), &[1, 0, 0, 0]);
        assert_eq!(request.server_certificate.blob_type, blob_type::CERTIFICATE);
        assert_eq!(request.server_certificate.data.len(), 0x812);
        assert_eq!(request.scopes.len(), 1);
        assert_eq!(request.scopes[0].data.len(), 14);

        let cert = crate::gcc::parse_server_certificate(request.server_certificate.data.as_slice())
            .unwrap();
        let crate::gcc::ServerCertificate::X509Chain(chain) = &cert else {
            panic!("not a chain");
        };
        assert_eq!(chain.certificates.len(), 2);
        let crate::gcc::RsaKeyBytes::BigEndian { modulus, exponent } =
            cert.rsa_public_key().unwrap()
        else {
            panic!("not an X.509 key");
        };
        // 2048 bits behind DER's sign byte, and F4.
        assert_eq!(modulus.len(), 257);
        assert_eq!(modulus[..3], [0x00, 0xc8, 0x90]);
        assert_eq!(exponent, &[0x01, 0x00, 0x01]);
    }

    /// MS-RDPELE 4.2 rebuilt from its own fields is the specification's
    /// bytes exactly, preamble flags included.
    #[test]
    fn a_new_license_request_encodes_to_the_specification_bytes() {
        let spec = hex_file(SPEC_4_2);
        let mut client_random = [0u8; CLIENT_RANDOM_LEN];
        client_random.copy_from_slice(&spec[0x0c..0x2c]);
        let request = ClientNewLicenseRequest {
            client_random,
            encrypted_premaster_secret: &spec[0x30..0x138],
            user_name: &spec[0x13c..0x14a],
            machine_name: &spec[0x14e..],
        };
        let bytes = encode_client_message(message_type::NEW_LICENSE_REQUEST, &request).unwrap();
        assert_eq!(bytes, with_header(&spec));
    }

    /// MS-RDPELE 4.4, verbatim.
    const SPEC_4_4: &[u8] = &[
        0x02, 0x03, 0x26, 0x00, 0xff, 0xff, 0xff, 0xff, 0x50, 0xf7, 0x0a, 0x00, 0x46, 0x37, 0x85,
        0x54, 0x8e, 0xc5, 0x91, 0x34, 0x97, 0x5d, 0x78, 0x94, 0xad, 0x3b, 0x81, 0xda, 0x88, 0x18,
        0x56, 0x0f, 0x3a, 0xd1, 0xf1, 0x03, 0xef, 0x35,
    ];

    #[test]
    fn the_specification_platform_challenge_decodes() {
        let bytes = with_header(SPEC_4_4);
        let pdu = LicensePdu::decode(&mut Reader::new(&bytes)).unwrap();
        let LicenseMessage::PlatformChallenge(challenge) = &pdu.message else {
            panic!("not a platform challenge");
        };
        assert_eq!(challenge.connect_flags, 0xffff_ffff);
        // The blob type is 0xf750 in the example, which is why it is not
        // checked.
        assert_eq!(challenge.encrypted_challenge.blob_type, 0xf750);
        assert_eq!(
            challenge.encrypted_challenge.data.as_slice(),
            &SPEC_4_4[12..22]
        );
        assert_eq!(challenge.mac[..], SPEC_4_4[22..]);
        assert_eq!(encode(&pdu), bytes);
    }

    /// MS-RDPELE 4.5 rebuilt from its fields. The example's two blobs carry
    /// type `BB_DATA_BLOB`, which the section marks as ignored; this client
    /// sends `BB_ENCRYPTED_DATA_BLOB` as 2.2.2.5 specifies and as FreeRDP
    /// does, so those two fields are the only difference.
    #[test]
    fn a_platform_challenge_response_encodes_to_the_specification_bytes() {
        let mut spec: Vec<u8> = vec![
            0x15, 0x83, 0x42, 0x00, 0x01, 0x00, 0x12, 0x00, 0xfa, 0xb4, 0xe8, 0x24, 0xcf, 0x56,
            0xb2, 0x4e, 0x80, 0x02, 0xbd, 0xb6, 0x61, 0xfc, 0xdf, 0xe9, 0x6c, 0x44, 0x01, 0x00,
            0x14, 0x00, 0xf8, 0xb5, 0xe8, 0x25, 0x3d, 0x0f, 0x3f, 0x70, 0x1d, 0xda, 0x60, 0x19,
            0x16, 0xfe, 0x73, 0x1a, 0x45, 0x7e, 0x02, 0x71, 0x38, 0x23, 0x62, 0x5d, 0x10, 0x8b,
            0x93, 0xc3, 0xf1, 0xe4, 0x67, 0x1f, 0x4a, 0xb6, 0x00, 0x0a,
        ];
        let mut mac = [0u8; LICENSE_MAC_LEN];
        mac.copy_from_slice(&spec[0x32..]);
        let response = ClientPlatformChallengeResponse {
            encrypted_response: &spec[0x08..0x1a],
            encrypted_hwid: &spec[0x1e..0x32],
            mac,
        };
        let bytes =
            encode_client_message(message_type::PLATFORM_CHALLENGE_RESPONSE, &response).unwrap();
        spec[0x04] = 0x09;
        spec[0x1a] = 0x09;
        assert_eq!(bytes, with_header(&spec));
    }

    /// The plaintext of MS-RDPELE 4.5's response: version, client type,
    /// detail level, the challenge length, then the challenge.
    #[test]
    fn platform_challenge_response_data_lays_out_as_2_2_2_5_1() {
        let challenge = b"T\0E\0S\0T\0\0\0";
        let data = PlatformChallengeResponseData { challenge };
        let mut buf = Vec::new();
        data.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        let mut want = vec![0x00, 0x01, 0x00, 0xff, 0x03, 0x00, 0x0a, 0x00];
        want.extend_from_slice(challenge);
        assert_eq!(buf, want);
    }

    /// `NEW_LICENSE_INFO` with the field sizes of MS-RDPELE 4.6.
    #[test]
    fn new_license_info_round_trips() {
        let licence = [0x30u8, 0x82, 0x07, 0x95, 0x06, 0x09];
        let info = NewLicenseInfo {
            version: 0x0006_0000,
            scope: b"example.test\0",
            company_name: b"A\0B\0\0\0",
            product_id: b"A\x000\x002\0\0\0",
            license_info: &licence,
        };
        let mut buf = Vec::new();
        info.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf[..8], [0x00, 0x00, 0x06, 0x00, 0x0d, 0x00, 0x00, 0x00]);
        let back = NewLicenseInfo::read(&mut Reader::new(&buf)).unwrap();
        assert_eq!(back, info);
        for cut in 0..buf.len() {
            assert!(NewLicenseInfo::read(&mut Reader::new(&buf[..cut])).is_err());
        }
    }

    #[test]
    fn a_new_and_an_upgrade_license_decode_to_the_same_shape() {
        for (msg_type, upgrade) in [
            (message_type::NEW_LICENSE, false),
            (message_type::UPGRADE_LICENSE, true),
        ] {
            let mut bytes = vec![0x80, 0x00, 0x00, 0x00, msg_type, 0x03, 0x1b, 0x00];
            bytes.extend_from_slice(&[0x09, 0x00, 0x03, 0x00, 0xaa, 0xbb, 0xcc]);
            bytes.extend_from_slice(&[0x5a; LICENSE_MAC_LEN]);
            let pdu = LicensePdu::decode(&mut Reader::new(&bytes)).unwrap();
            let LicenseMessage::NewLicense {
                upgrade: got,
                license,
            } = &pdu.message
            else {
                panic!("not a new license");
            };
            assert_eq!(*got, upgrade);
            assert_eq!(
                license.encrypted_license_info.data.as_slice(),
                &[0xaa, 0xbb, 0xcc]
            );
            assert_eq!(license.mac, [0x5a; LICENSE_MAC_LEN]);
            assert_eq!(encode(&pdu), bytes);
            for cut in 0..bytes.len() {
                assert!(LicensePdu::decode(&mut Reader::new(&bytes[..cut])).is_err());
            }
        }
    }
}
