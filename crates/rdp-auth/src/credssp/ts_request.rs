//! `TSRequest`, MS-CSSP 2.2.1 (revision 21.0, 23 April 2024).
//!
//! Every CredSSP message on the wire is one of these and nothing else. There
//! is no RDP header on it: between the end of the TLS handshake and the MCS
//! Connect Initial the stream carries TSRequest DER and nothing else
//! (MS-RDPBCGR 5.4.5.2, PRDRDP/14 §3.1).
//!
//! ```asn1
//! TSRequest ::= SEQUENCE {
//!         version     [0] INTEGER,
//!         negoTokens  [1] NegoData      OPTIONAL,
//!         authInfo    [2] OCTET STRING  OPTIONAL,
//!         pubKeyAuth  [3] OCTET STRING  OPTIONAL,
//!         errorCode   [4] INTEGER       OPTIONAL,
//!         clientNonce [5] OCTET STRING  OPTIONAL
//! }
//!
//! NegoData ::= SEQUENCE OF SEQUENCE {
//!         negoToken [0] OCTET STRING
//! }
//! ```
//!
//! ## Two things in that grammar that are easy to get wrong
//!
//! The tags are EXPLICIT. MS-CSSP's ASN.1 module is `DEFINITIONS EXPLICIT
//! TAGS`, so `version [0] INTEGER` is `A0 03 02 01 06`, a whole INTEGER
//! element inside a `[0]` constructed element, and not `80 01 06`. A
//! TSRequest with implicit tags is dropped by Windows with no reply, and the
//! symptom is a TLS connection that hangs rather than an error
//! (PRDRDP/14 §3.2).
//!
//! `NegoData` is a `SEQUENCE OF SEQUENCE`, so there are three nested layers
//! before the token bytes: `A1 <len> 30 <len> 30 <len> A0 <len> 04 <len>
//! <token>`. We encode exactly one element, because neither NTLM nor SPNEGO
//! ever produces two tokens for one round. On decode we accept a list, keep
//! the first, and warn about the rest rather than refusing: refusing would be
//! an interop risk for no security gain, since only the first is ever fed to
//! a mechanism.
//!
//! ## `errorCode` is five octets, not four
//!
//! Every unsuccessful NTSTATUS has bit 31 set, and X.690 §8.3.2 forbids a
//! DER INTEGER whose first nine bits are all ones or all zeros, so
//! `0xC000006D` encodes as `02 05 00 C0 00 00 6D`. A reader that requires
//! four content octets rejects every real error code from Windows, and it
//! only does so on the failure path, which is to say only when a user has
//! typed the wrong password. We read through
//! [`der::read_int_i64`](rdp_pdu::asn1::der::read_int_i64), which sign
//! extends, and then accept either the padded positive form or the four octet
//! negative form a non Microsoft server might send.

use rdp_pdu::asn1::{context, der, tag};

use crate::error::AuthError;

/// The version we advertise in every TSRequest we send (PRDRDP/14 §3.4).
pub const CLIENT_VERSION: u32 = 6;

/// The lowest server version we will complete against (PRDRDP/14 §8.7).
///
/// MS-CSSP 2.2.1: "Valid values for this field are 2, 3, 4, 5, and 6." A
/// server claiming 0 or 1 is either broken or steering us at a construction
/// that does not exist.
pub const MIN_SERVER_VERSION: u32 = 2;

/// `clientNonce` is "a 32-byte array of cryptographically random bytes"
/// (MS-CSSP 2.2.1).
pub const NONCE_LEN: usize = 32;

const TAG_VERSION: u8 = context(0);
const TAG_NEGO_TOKENS: u8 = context(1);
const TAG_AUTH_INFO: u8 = context(2);
const TAG_PUB_KEY_AUTH: u8 = context(3);
const TAG_ERROR_CODE: u8 = context(4);
const TAG_CLIENT_NONCE: u8 = context(5);
/// `negoToken [0] OCTET STRING`, the innermost tag of `NegoData`.
const TAG_NEGO_TOKEN: u8 = context(0);

/// One CredSSP message.
///
/// The three `OCTET STRING` fields hold ciphertext, which MS-CSSP 2.2.1 says
/// "carries the message signature and then the encrypted data". Ciphertext is
/// not a secret and these are plain `Vec<u8>`; the plaintext on either side of
/// them is `Zeroizing` (PRDRDP/14 §8.2).
#[derive(Default, Clone, PartialEq, Eq)]
pub struct TsRequest {
    /// The sender's highest supported version. Ours is always
    /// [`CLIENT_VERSION`].
    pub version: u32,
    /// The mechanism tokens. We send zero or one; we accept a list.
    pub nego_tokens: Vec<Vec<u8>>,
    /// `E(TSCredentials)`, message 5 only.
    pub auth_info: Option<Vec<u8>>,
    /// `E(binding)`, messages 3 and 4.
    pub pub_key_auth: Option<Vec<u8>>,
    /// An NTSTATUS from the server (MS-CSSP 2.2.1, MS-ERREF 2.3).
    pub error_code: Option<u32>,
    /// The 32 random bytes of MS-CSSP 3.1.5 step 3, version 5 and 6 only.
    pub client_nonce: Option<Vec<u8>>,
}

impl TsRequest {
    /// An otherwise empty request at our version.
    #[must_use]
    pub fn new(version: u32) -> Self {
        TsRequest {
            version,
            ..TsRequest::default()
        }
    }

    /// The DER encoding, MS-CSSP 2.2.1.
    ///
    /// Fields are written in tag order and absent fields are omitted, which
    /// is what DER requires of an OPTIONAL field (X.690 §11).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        der::write_nested(&mut out, tag::SEQUENCE, |body| {
            der::write_nested(body, TAG_VERSION, |v| {
                der::write_int(v, tag::INTEGER, i64::from(self.version));
            });
            if !self.nego_tokens.is_empty() {
                der::write_nested(body, TAG_NEGO_TOKENS, |nego| {
                    // NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] ... }.
                    // Three layers, and the outer SEQUENCE OF is the one that
                    // gets forgotten.
                    der::write_nested(nego, tag::SEQUENCE, |list| {
                        for token in &self.nego_tokens {
                            der::write_nested(list, tag::SEQUENCE, |item| {
                                der::write_nested(item, TAG_NEGO_TOKEN, |inner| {
                                    der::write_tlv(inner, tag::OCTET_STRING, token);
                                });
                            });
                        }
                    });
                });
            }
            if let Some(auth_info) = &self.auth_info {
                der::write_nested(body, TAG_AUTH_INFO, |v| {
                    der::write_tlv(v, tag::OCTET_STRING, auth_info);
                });
            }
            if let Some(pub_key_auth) = &self.pub_key_auth {
                der::write_nested(body, TAG_PUB_KEY_AUTH, |v| {
                    der::write_tlv(v, tag::OCTET_STRING, pub_key_auth);
                });
            }
            if let Some(code) = self.error_code {
                der::write_nested(body, TAG_ERROR_CODE, |v| {
                    // i64 so the pad octet of X.690 §8.3.2 appears for a
                    // value with bit 31 set, which every NTSTATUS failure has.
                    der::write_int(v, tag::INTEGER, i64::from(code));
                });
            }
            if let Some(nonce) = &self.client_nonce {
                der::write_nested(body, TAG_CLIENT_NONCE, |v| {
                    der::write_tlv(v, tag::OCTET_STRING, nonce);
                });
            }
        });
        out
    }

    /// Parse one TSRequest, MS-CSSP 2.2.1.
    ///
    /// Every field is bounds checked by `rdp_pdu::asn1::der`, which rejects
    /// multi byte tags, the indefinite length form, and any length that runs
    /// past the buffer. Unknown context tags are ignored with a log line
    /// rather than refused, because a later CredSSP revision adding a `[6]`
    /// must not break a client that does not need it.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] naming the field that failed, never
    /// its contents (PRDRDP/00 R63).
    pub fn decode(bytes: &[u8]) -> Result<Self, AuthError> {
        let (outer, trailing) = read(bytes, "TSRequest")?;
        if outer.tag != tag::SEQUENCE {
            return Err(AuthError::MalformedMessage("TSRequest is not a SEQUENCE"));
        }
        if !trailing.is_empty() {
            // The session frames on the SEQUENCE header's own length, so a
            // trailing byte means the framing and the encoding disagree.
            return Err(AuthError::MalformedMessage(
                "trailing bytes after TSRequest",
            ));
        }

        let mut out = TsRequest::default();
        let mut have_version = false;
        let mut rest = outer.content;
        while !rest.is_empty() {
            let (field, next) = read(rest, "TSRequest field")?;
            rest = next;
            match field.tag {
                TAG_VERSION => {
                    reject_duplicate(have_version, "version")?;
                    let (version, extra) = der::read_int_u32(field.content)
                        .ok_or(AuthError::MalformedMessage("TSRequest version"))?;
                    end_of_field(extra, "version")?;
                    out.version = version;
                    have_version = true;
                }
                TAG_NEGO_TOKENS => {
                    reject_duplicate(!out.nego_tokens.is_empty(), "negoTokens")?;
                    out.nego_tokens = decode_nego_data(field.content)?;
                }
                TAG_AUTH_INFO => {
                    reject_duplicate(out.auth_info.is_some(), "authInfo")?;
                    out.auth_info = Some(octet_string(field.content, "authInfo")?);
                }
                TAG_PUB_KEY_AUTH => {
                    reject_duplicate(out.pub_key_auth.is_some(), "pubKeyAuth")?;
                    out.pub_key_auth = Some(octet_string(field.content, "pubKeyAuth")?);
                }
                TAG_ERROR_CODE => {
                    reject_duplicate(out.error_code.is_some(), "errorCode")?;
                    out.error_code = Some(decode_error_code(field.content)?);
                }
                TAG_CLIENT_NONCE => {
                    reject_duplicate(out.client_nonce.is_some(), "clientNonce")?;
                    out.client_nonce = Some(octet_string(field.content, "clientNonce")?);
                }
                other => {
                    tracing::debug!(
                        tag = format_args!("{other:#04x}"),
                        len = field.content.len(),
                        "ignoring an unknown TSRequest field"
                    );
                }
            }
        }
        if !have_version {
            // MS-CSSP 2.2.1 makes version the one field that is not OPTIONAL.
            return Err(AuthError::MalformedMessage("TSRequest has no version"));
        }
        Ok(out)
    }
}

impl std::fmt::Debug for TsRequest {
    /// Lengths and the version, never contents. `authInfo` is the encrypted
    /// password and `negoTokens` carries the user name, so neither may reach
    /// a log (PRDRDP/14 §8.4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsRequest")
            .field("version", &self.version)
            .field(
                "nego_tokens",
                &self.nego_tokens.iter().map(Vec::len).collect::<Vec<_>>(),
            )
            .field("auth_info", &self.auth_info.as_ref().map(Vec::len))
            .field("pub_key_auth", &self.pub_key_auth.as_ref().map(Vec::len))
            .field("error_code", &self.error_code.map(|c| format!("{c:#010x}")))
            .field("client_nonce", &self.client_nonce.as_ref().map(Vec::len))
            .finish()
    }
}

/// `NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }`,
/// MS-CSSP 2.2.1.1.
fn decode_nego_data(content: &[u8]) -> Result<Vec<Vec<u8>>, AuthError> {
    let (list, extra) = read(content, "NegoData")?;
    if list.tag != tag::SEQUENCE {
        return Err(AuthError::MalformedMessage("NegoData is not a SEQUENCE"));
    }
    end_of_field(extra, "negoTokens")?;

    let mut tokens = Vec::new();
    let mut items = list.content;
    while !items.is_empty() {
        let (item, next) = read(items, "NegoData item")?;
        items = next;
        if item.tag != tag::SEQUENCE {
            return Err(AuthError::MalformedMessage(
                "NegoData item is not a SEQUENCE",
            ));
        }
        let (wrapper, extra) = read(item.content, "negoToken")?;
        if wrapper.tag != TAG_NEGO_TOKEN {
            return Err(AuthError::MalformedMessage("negoToken is not [0]"));
        }
        end_of_field(extra, "NegoData item")?;
        let (token, extra) = der::expect_tag(wrapper.content, tag::OCTET_STRING).ok_or(
            AuthError::MalformedMessage("negoToken is not an OCTET STRING"),
        )?;
        end_of_field(extra, "negoToken")?;
        tokens.push(token.to_vec());
    }
    if tokens.is_empty() {
        // An empty SEQUENCE OF is legal ASN.1 and useless here: the field
        // exists to carry a token.
        return Err(AuthError::MalformedMessage("NegoData is empty"));
    }
    if tokens.len() > 1 {
        tracing::warn!(
            count = tokens.len(),
            "the server sent more than one negoToken; using the first"
        );
    }
    Ok(tokens)
}

/// An `errorCode [4] INTEGER` carrying an NTSTATUS (MS-ERREF 2.3).
///
/// Windows sends the padded positive form, `02 05 00 C0 00 00 6D` for
/// `STATUS_LOGON_FAILURE`. A four octet encoding of the same bit pattern is a
/// negative ASN.1 integer, `-1073741715`, and some non Microsoft servers send
/// it. Both mean the same 32 bit status, so both are accepted and anything
/// outside 32 bits is refused.
fn decode_error_code(content: &[u8]) -> Result<u32, AuthError> {
    let (value, extra) =
        der::read_int_i64(content).ok_or(AuthError::MalformedMessage("TSRequest errorCode"))?;
    end_of_field(extra, "errorCode")?;
    if let Ok(code) = u32::try_from(value) {
        return Ok(code);
    }
    if let Ok(signed) = i32::try_from(value) {
        // The same 32 bits read as unsigned. `from_le_bytes(to_le_bytes())`
        // rather than `as`, so nothing here is a numeric conversion that a
        // reader has to check the width of.
        return Ok(u32::from_le_bytes(signed.to_le_bytes()));
    }
    Err(AuthError::MalformedMessage(
        "errorCode is not a 32 bit status",
    ))
}

/// The contents of an `OCTET STRING` inside an explicit context tag.
fn octet_string(content: &[u8], what: &'static str) -> Result<Vec<u8>, AuthError> {
    let (bytes, extra) =
        der::expect_tag(content, tag::OCTET_STRING).ok_or(AuthError::MalformedMessage(what))?;
    end_of_field(extra, what)?;
    Ok(bytes.to_vec())
}

fn read<'a>(buf: &'a [u8], what: &'static str) -> Result<(der::Tlv<'a>, &'a [u8]), AuthError> {
    der::read_tlv(buf).ok_or(AuthError::MalformedMessage(what))
}

/// An explicit context tag holds exactly one element (X.690 §8.14).
fn end_of_field(extra: &[u8], what: &'static str) -> Result<(), AuthError> {
    if extra.is_empty() {
        Ok(())
    } else {
        tracing::debug!(what, extra = extra.len(), "extra bytes inside a field");
        Err(AuthError::MalformedMessage(what))
    }
}

fn reject_duplicate(seen: bool, what: &'static str) -> Result<(), AuthError> {
    if seen {
        // DER has no repeated field in a SEQUENCE. A duplicate is a parser
        // confusion attempt: the first value passes a check and the second
        // is the one a later reader uses.
        Err(AuthError::MalformedMessage(what))
    } else {
        Ok(())
    }
}
