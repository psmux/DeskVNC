//! RDSTLS, the sign in a client uses after a Server Redirection
//! (MS-RDPBCGR 2.2.17, 5.4.5.3).
//!
//! A server selects `PROTOCOL_RDSTLS` in the Connection Confirm, the TLS
//! handshake runs as it would for `PROTOCOL_SSL`, and then, inside the
//! tunnel and before the Basic Settings Exchange, three PDUs go back and
//! forth:
//!
//! 1. the server sends **Capabilities** (2.2.17.1),
//! 2. the client sends an **Authentication Request** with the credentials the
//!    redirection handed it (2.2.17.2), here the password form,
//! 3. the server answers with an **Authentication Response** holding a result
//!    code (2.2.17.3).
//!
//! None of the three carries a length header of its own. Capabilities and the
//! response are fixed size, which is why [`CAPABILITIES_LEN`] and
//! [`AUTH_RESPONSE_LEN`] exist: the reader knows how many bytes to wait for.
//!
//! The password field is whatever the redirection's `Password` held, byte for
//! byte. When the redirection set `LB_PASSWORD_IS_PK_ENCRYPTED` the bytes are
//! opaque to the client and only the server that issued them can read them;
//! the client presents them unchanged. It is a [`SecretBytes`], so a `Debug`
//! line cannot print it.

use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};
use crate::rdp::SecretBytes;

/// `RDSTLS_VERSION_1`, the only version a password request may use.
pub const VERSION_1: u16 = 0x0001;

/// `PduType` values (MS-RDPBCGR 2.2.17).
pub mod pdu_type {
    /// `RDSTLS_TYPE_CAPABILITIES`.
    pub const CAPABILITIES: u16 = 0x0001;
    /// `RDSTLS_TYPE_AUTHREQ`.
    pub const AUTH_REQUEST: u16 = 0x0002;
    /// `RDSTLS_TYPE_AUTHRSP`.
    pub const AUTH_RESPONSE: u16 = 0x0004;
}

/// `DataType` values. Each `PduType` has its own numbering, which is why
/// several share the value one.
pub mod data_type {
    /// `RDSTLS_DATA_CAPABILITIES`, inside a Capabilities PDU.
    pub const CAPABILITIES: u16 = 0x0001;
    /// `RDSTLS_DATA_PASSWORD_CREDS`, inside an Authentication Request.
    pub const PASSWORD_CREDS: u16 = 0x0001;
    /// `RDSTLS_DATA_AUTORECONNECT_COOKIE`, inside an Authentication Request.
    pub const AUTORECONNECT_COOKIE: u16 = 0x0002;
    /// `RDSTLS_DATA_RESULT_CODE`, inside an Authentication Response.
    pub const RESULT_CODE: u16 = 0x0001;
}

/// `ResultCode` values of the Authentication Response (2.2.17.3).
pub mod result_code {
    /// `RDSTLS_RESULT_SUCCESS`.
    pub const SUCCESS: u32 = 0x0000_0000;
    /// `RDSTLS_RESULT_ACCESS_DENIED`.
    pub const ACCESS_DENIED: u32 = 0x0000_0005;
    /// `RDSTLS_RESULT_LOGON_FAILURE`.
    pub const LOGON_FAILURE: u32 = 0x0000_052e;
    /// `RDSTLS_RESULT_INVALID_LOGON_HOURS`.
    pub const INVALID_LOGON_HOURS: u32 = 0x0000_0530;
    /// `RDSTLS_RESULT_PASSWORD_EXPIRED`.
    pub const PASSWORD_EXPIRED: u32 = 0x0000_0532;
    /// `RDSTLS_RESULT_ACCOUNT_DISABLED`.
    pub const ACCOUNT_DISABLED: u32 = 0x0000_0533;
    /// `RDSTLS_RESULT_PASSWORD_MUST_CHANGE`.
    pub const PASSWORD_MUST_CHANGE: u32 = 0x0000_0773;
    /// `RDSTLS_RESULT_ACCOUNT_LOCKED_OUT`.
    pub const ACCOUNT_LOCKED_OUT: u32 = 0x0000_0775;
}

/// The Capabilities PDU is always eight bytes.
pub const CAPABILITIES_LEN: usize = 8;

/// The Authentication Response PDU is always ten bytes.
pub const AUTH_RESPONSE_LEN: usize = 10;

/// The longest field an Authentication Request can carry: every length in it
/// is a `u16`.
const MAX_FIELD: usize = u16::MAX as usize;

/// `RDSTLS_CAPABILITIES_PDU` (2.2.17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdstlsCapabilities {
    /// `SupportedVersions`, a bit mask of the versions the server speaks.
    pub supported_versions: u16,
}

impl RdstlsCapabilities {
    const CONTEXT: &'static str = "RDSTLS_CAPABILITIES_PDU";

    /// True when the server will take a version 1 request, which is the
    /// only kind a password request can be.
    #[must_use]
    pub const fn supports_version_1(&self) -> bool {
        self.supported_versions & VERSION_1 != 0
    }
}

impl Decode<'_> for RdstlsCapabilities {
    const NAME: &'static str = Self::CONTEXT;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        // The header's own version is the one the PDU is written in, and a
        // server that writes its capabilities in a version we do not know is
        // one we cannot talk to.
        let version = r.u16(Self::CONTEXT)?;
        if version != VERSION_1 {
            return Err(PduError::InvalidField {
                context: Self::CONTEXT,
                field: "Version",
                value: u64::from(version),
                offset: at,
            });
        }
        expect_u16(r, Self::CONTEXT, "PduType", pdu_type::CAPABILITIES)?;
        expect_u16(r, Self::CONTEXT, "DataType", data_type::CAPABILITIES)?;
        let supported_versions = r.u16(Self::CONTEXT)?;
        Ok(Self { supported_versions })
    }
}

impl Encode for RdstlsCapabilities {
    const NAME: &'static str = Self::CONTEXT;

    fn size(&self) -> usize {
        CAPABILITIES_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(VERSION_1);
        w.u16(pdu_type::CAPABILITIES);
        w.u16(data_type::CAPABILITIES);
        w.u16(self.supported_versions);
        Ok(())
    }
}

/// `RDSTLS_AUTHREQ` with password credentials (2.2.17.2.1).
///
/// The field order is the specification's, and it is the order FreeRDP's
/// client and server both use: the redirection GUID, the user name, the
/// domain, the password.
#[derive(Clone, PartialEq, Eq)]
pub struct RdstlsPasswordRequest {
    /// `RedirectionGuid`, as the redirection's field carried it (for
    /// gnome-remote-desktop, UTF-16LE text of a Base64 string).
    pub redirection_guid: Vec<u8>,
    /// `UserName`, written as UTF-16LE with a terminator.
    pub username: String,
    /// `Domain`, written as UTF-16LE with a terminator, which for an empty
    /// domain is the terminator alone.
    pub domain: String,
    /// `Password`, the redirection's `Password` field unchanged.
    pub password: SecretBytes,
}

impl RdstlsPasswordRequest {
    const CONTEXT: &'static str = "RDSTLS_AUTHREQ";
}

/// `Debug` shows the lengths and the user name. The GUID and the password are
/// what admit a connection to a session, so neither is printed.
impl core::fmt::Debug for RdstlsPasswordRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdstlsPasswordRequest")
            .field("redirection_guid_len", &self.redirection_guid.len())
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("password", &self.password)
            .finish()
    }
}

fn utf16z(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

fn from_utf16z(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn field_len(len: usize) -> PduResult<u16> {
    if len > MAX_FIELD {
        return Err(PduError::Encode {
            context: RdstlsPasswordRequest::CONTEXT,
            reason: "a field is longer than a u16 length can say",
        });
    }
    Ok(len as u16)
}

impl Encode for RdstlsPasswordRequest {
    const NAME: &'static str = Self::CONTEXT;

    fn size(&self) -> usize {
        // Version, PduType, DataType, then four length prefixed fields.
        6 + 2
            + self.redirection_guid.len()
            + 2
            + (self.username.encode_utf16().count() + 1) * 2
            + 2
            + (self.domain.encode_utf16().count() + 1) * 2
            + 2
            + self.password.expose().len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let user = utf16z(&self.username);
        let domain = utf16z(&self.domain);
        w.u16(VERSION_1);
        w.u16(pdu_type::AUTH_REQUEST);
        w.u16(data_type::PASSWORD_CREDS);
        for field in [
            self.redirection_guid.as_slice(),
            &user,
            &domain,
            self.password.expose(),
        ] {
            w.u16(field_len(field.len())?);
            w.bytes(field);
        }
        Ok(())
    }
}

impl Decode<'_> for RdstlsPasswordRequest {
    const NAME: &'static str = Self::CONTEXT;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        expect_u16(r, Self::CONTEXT, "Version", VERSION_1)?;
        expect_u16(r, Self::CONTEXT, "PduType", pdu_type::AUTH_REQUEST)?;
        expect_u16(r, Self::CONTEXT, "DataType", data_type::PASSWORD_CREDS)?;
        let field = |r: &mut Reader<'_>| -> PduResult<Vec<u8>> {
            let len = r.u16(Self::CONTEXT)?;
            Ok(r.slice(usize::from(len), Self::CONTEXT)?.to_vec())
        };
        let redirection_guid = field(r)?;
        let username = from_utf16z(&field(r)?);
        let domain = from_utf16z(&field(r)?);
        let password = SecretBytes::new(field(r)?);
        Ok(Self {
            redirection_guid,
            username,
            domain,
            password,
        })
    }
}

/// `RDSTLS_AUTHRSP` (2.2.17.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdstlsAuthResponse {
    /// `ResultCode`, one of [`result_code`].
    pub result_code: u32,
}

impl RdstlsAuthResponse {
    const CONTEXT: &'static str = "RDSTLS_AUTHRSP";
}

impl Decode<'_> for RdstlsAuthResponse {
    const NAME: &'static str = Self::CONTEXT;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        expect_u16(r, Self::CONTEXT, "Version", VERSION_1)?;
        expect_u16(r, Self::CONTEXT, "PduType", pdu_type::AUTH_RESPONSE)?;
        expect_u16(r, Self::CONTEXT, "DataType", data_type::RESULT_CODE)?;
        let result_code = r.u32(Self::CONTEXT)?;
        Ok(Self { result_code })
    }
}

impl Encode for RdstlsAuthResponse {
    const NAME: &'static str = Self::CONTEXT;

    fn size(&self) -> usize {
        AUTH_RESPONSE_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        w.u16(VERSION_1);
        w.u16(pdu_type::AUTH_RESPONSE);
        w.u16(data_type::RESULT_CODE);
        w.u32(self.result_code);
        Ok(())
    }
}

fn expect_u16(
    r: &mut Reader<'_>,
    context: &'static str,
    field: &'static str,
    want: u16,
) -> PduResult<()> {
    let at = r.offset();
    let got = r.u16(context)?;
    if got != want {
        return Err(PduError::InvalidField {
            context,
            field,
            value: u64::from(got),
            offset: at,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(value: &impl Encode) -> Vec<u8> {
        let mut out = Vec::new();
        value
            .encode_checked(&mut Writer::new(&mut out))
            .expect("encodes");
        out
    }

    /// The eight bytes FreeRDP's server writes: version 1, capabilities,
    /// capabilities, versions supported.
    #[test]
    fn capabilities_round_trip_through_the_wire_form() {
        let wire = [0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00];
        let caps = RdstlsCapabilities::decode(&mut Reader::new(&wire)).expect("decodes");
        assert!(caps.supports_version_1());
        assert_eq!(bytes(&caps), wire);

        // A server that also speaks version 2 (the FedAuth form) still takes
        // a version 1 password request.
        let wire = [0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x00];
        let caps = RdstlsCapabilities::decode(&mut Reader::new(&wire)).expect("decodes");
        assert!(caps.supports_version_1());
    }

    #[test]
    fn a_pdu_of_the_wrong_type_is_refused() {
        // An Authentication Response where the capabilities belong.
        let wire = [0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert!(RdstlsCapabilities::decode(&mut Reader::new(&wire)).is_err());
    }

    /// The layout of 2.2.17.2.1, byte for byte, with an empty domain written
    /// as its terminator alone, which is what FreeRDP's client sends.
    #[test]
    fn the_password_request_is_laid_out_as_the_specification_says() {
        let request = RdstlsPasswordRequest {
            redirection_guid: vec![0xaa, 0xbb],
            username: "u".to_owned(),
            domain: String::new(),
            password: SecretBytes::new(vec![0x70, 0x00, 0x00, 0x00]),
        };
        let wire = bytes(&request);
        assert_eq!(
            wire,
            [
                0x01, 0x00, 0x02, 0x00, 0x01, 0x00, // version, authreq, password
                0x02, 0x00, 0xaa, 0xbb, // guid
                0x04, 0x00, b'u', 0x00, 0x00, 0x00, // user name
                0x02, 0x00, 0x00, 0x00, // domain
                0x04, 0x00, 0x70, 0x00, 0x00, 0x00, // password
            ]
        );
        assert_eq!(request.size(), wire.len());
        let back = RdstlsPasswordRequest::decode(&mut Reader::new(&wire)).expect("decodes");
        assert_eq!(back, request);
    }

    #[test]
    fn debug_carries_neither_the_password_nor_the_guid() {
        let request = RdstlsPasswordRequest {
            redirection_guid: b"GUIDGUID".to_vec(),
            username: "someone".to_owned(),
            domain: String::new(),
            password: SecretBytes::new(b"hunter2".to_vec()),
        };
        let shown = format!("{request:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(!shown.contains("GUIDGUID"), "{shown}");
    }

    #[test]
    fn the_response_round_trips() {
        let rsp = RdstlsAuthResponse {
            result_code: result_code::LOGON_FAILURE,
        };
        let wire = bytes(&rsp);
        assert_eq!(wire.len(), AUTH_RESPONSE_LEN);
        assert_eq!(
            RdstlsAuthResponse::decode(&mut Reader::new(&wire)).expect("decodes"),
            rsp
        );
    }
}
