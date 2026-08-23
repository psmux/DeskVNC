//! `TSCredentials` and `TSPasswordCreds`, MS-CSSP 2.2.1.2 and 2.2.1.2.1.
//!
//! This is the password, and it is the only thing in the whole exchange that
//! an attacker who has already impersonated the server actually wants. It is
//! sent last, in message 5, after the server has proved possession of the
//! private key of the certificate we pinned (PRDRDP/14 §3.5, §8.6).
//!
//! ```asn1
//! TSCredentials ::= SEQUENCE {
//!         credType    [0] INTEGER,
//!         credentials [1] OCTET STRING
//! }
//!
//! TSPasswordCreds ::= SEQUENCE {
//!         domainName [0] OCTET STRING,
//!         userName   [1] OCTET STRING,
//!         password   [2] OCTET STRING
//! }
//! ```
//!
//! ## Three nestings, every one an OCTET STRING whose contents are DER
//!
//! ```text
//! TSPasswordCreds                     DER
//!   -> TSCredentials.credentials      an OCTET STRING holding that DER
//!     -> E(TSCredentials)             the whole thing, wrapped
//!       -> TSRequest.authInfo         an OCTET STRING holding the ciphertext
//! ```
//!
//! MS-CSSP section 4's one published byte dump is the outer two layers of
//! that, for a smart card credential, and `tests/credssp_der.rs` parses it.
//!
//! ## The strings are UTF-16LE
//!
//! MS-CSSP 2.2.1.2.1 says only "an ASN.1 OCTET STRING that contains the
//! user's account name". The encoding is in footnote 15 of the same section
//! and nowhere else: "Where data is a text string, Windows uses a Unicode
//! string defined by a UNICODE_STRING structure to encode to ASN.1 OCTET
//! STRING format." That means UTF-16LE, no byte order mark and no NUL
//! terminator. A UTF-8 slip here produces a logon that fails for every
//! password containing a character outside ASCII and works for every other,
//! which is the worst possible bug report.
//!
//! A zero length `domainName` is legal and is what a local account or a user
//! principal name logon sends (PRDRDP/14 §6.2). Restricted Admin mode sends
//! all three fields empty (MS-CSSP 3.1.5); we do not offer that mode in phase
//! 1, and the encoder handles it anyway because the empty domain path has to
//! work, so there is a test keeping the option open.
//!
//! Every buffer here is `Zeroizing`, including the intermediate UTF-16
//! encodings (PRDRDP/14 §8.2). The ciphertext produced from them is not
//! sensitive and is a plain `Vec<u8>`.

use rdp_pdu::asn1::{context, der, tag};
use zeroize::Zeroizing;

use crate::error::AuthError;
use crate::identity::Identity;
use crate::ntlm::crypto::unicode;

/// `credType` 1: the `credentials` field holds a `TSPasswordCreds`
/// (MS-CSSP 2.2.1.2). 2 is `TSSmartCardCreds` and 6 is `TSRemoteGuardCreds`;
/// we send 1 and nothing else.
pub const CRED_TYPE_PASSWORD: i64 = 1;

const TAG_CRED_TYPE: u8 = context(0);
const TAG_CREDENTIALS: u8 = context(1);
const TAG_DOMAIN_NAME: u8 = context(0);
const TAG_USER_NAME: u8 = context(1);
const TAG_PASSWORD: u8 = context(2);

/// `TSPasswordCreds`, MS-CSSP 2.2.1.2.1.
///
/// The three strings go on the wire as UTF-16LE. This takes them as `&str`
/// and does the conversion, so no caller can supply the wrong encoding.
#[must_use]
pub fn encode_password_creds(domain: &str, user: &str, password: &str) -> Zeroizing<Vec<u8>> {
    let domain = Zeroizing::new(unicode(domain));
    let user = Zeroizing::new(unicode(user));
    let password = Zeroizing::new(unicode(password));

    let mut out = Zeroizing::new(Vec::new());
    der::write_nested(&mut out, tag::SEQUENCE, |body| {
        der::write_nested(body, TAG_DOMAIN_NAME, |v| {
            der::write_tlv(v, tag::OCTET_STRING, &domain);
        });
        der::write_nested(body, TAG_USER_NAME, |v| {
            der::write_tlv(v, tag::OCTET_STRING, &user);
        });
        der::write_nested(body, TAG_PASSWORD, |v| {
            der::write_tlv(v, tag::OCTET_STRING, &password);
        });
    });
    out
}

/// `TSCredentials`, MS-CSSP 2.2.1.2, around an already encoded inner
/// structure.
///
/// `cred_type` is a parameter rather than a constant so the decoder's tests
/// can round trip MS-CSSP section 4's published smart card example, which is
/// `credType` 2. Nothing in this crate encodes anything but
/// [`CRED_TYPE_PASSWORD`].
#[must_use]
pub fn encode_credentials(cred_type: i64, credentials: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    der::write_nested(&mut out, tag::SEQUENCE, |body| {
        der::write_nested(body, TAG_CRED_TYPE, |v| {
            der::write_int(v, tag::INTEGER, cred_type);
        });
        der::write_nested(body, TAG_CREDENTIALS, |v| {
            der::write_tlv(v, tag::OCTET_STRING, credentials);
        });
    });
    out
}

/// The whole plaintext of `authInfo` for one identity: a `TSPasswordCreds`
/// inside a `TSCredentials` (MS-CSSP 2.2.1.2, 3.1.5 step 5).
///
/// The intermediate `TSPasswordCreds` encoding is `Zeroizing` and drops at
/// the end of this function, so the password exists in exactly two buffers
/// after this returns: the `Identity` and the value handed to `wrap`.
#[must_use]
pub fn encode_for(identity: &Identity) -> Zeroizing<Vec<u8>> {
    let creds = encode_password_creds(&identity.domain, &identity.user, &identity.password);
    encode_credentials(CRED_TYPE_PASSWORD, &creds)
}

/// `TSCredentials` as parsed: the type and the inner DER, still wrapped.
///
/// Decoding exists for the round trip tests, for MS-CSSP section 4's
/// published example, and for the mock server side of PRDRDP/14 §9.3. The
/// client never decodes one.
pub struct Credentials {
    /// 1, 2 or 6 (MS-CSSP 2.2.1.2).
    pub cred_type: i64,
    /// The contents of the `credentials` OCTET STRING, which for
    /// [`CRED_TYPE_PASSWORD`] is a `TSPasswordCreds` encoding.
    pub credentials: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("cred_type", &self.cred_type)
            .field(
                "credentials",
                &format_args!("{} bytes", self.credentials.len()),
            )
            .finish()
    }
}

/// The three strings of a `TSPasswordCreds`, decoded from UTF-16LE.
pub struct PasswordCreds {
    /// May be empty: a local account or a UPN logon sends no domain.
    pub domain: Zeroizing<String>,
    /// The account name.
    pub user: Zeroizing<String>,
    /// The password.
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for PasswordCreds {
    /// Follows `Identity`: the user and the domain print, the password does
    /// not (PRDRDP/14 §8.3).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordCreds")
            .field("domain", &*self.domain)
            .field("user", &*self.user)
            .field("password", &"***")
            .finish()
    }
}

/// Parse a `TSCredentials`, MS-CSSP 2.2.1.2.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] naming the field that failed.
pub fn decode_credentials(bytes: &[u8]) -> Result<Credentials, AuthError> {
    let (outer, trailing) = read(bytes, "TSCredentials")?;
    if outer.tag != tag::SEQUENCE || !trailing.is_empty() {
        return Err(AuthError::MalformedMessage(
            "TSCredentials is not a SEQUENCE",
        ));
    }
    let (cred_type_field, rest) = read(outer.content, "credType")?;
    if cred_type_field.tag != TAG_CRED_TYPE {
        return Err(AuthError::MalformedMessage("credType is not [0]"));
    }
    let (cred_type, extra) = der::read_int_i64(cred_type_field.content)
        .ok_or(AuthError::MalformedMessage("credType"))?;
    if !extra.is_empty() {
        return Err(AuthError::MalformedMessage("credType"));
    }
    let (credentials_field, extra) = read(rest, "credentials")?;
    if credentials_field.tag != TAG_CREDENTIALS || !extra.is_empty() {
        return Err(AuthError::MalformedMessage("credentials is not [1]"));
    }
    let (credentials, extra) = der::expect_tag(credentials_field.content, tag::OCTET_STRING)
        .ok_or(AuthError::MalformedMessage("credentials"))?;
    if !extra.is_empty() {
        return Err(AuthError::MalformedMessage("credentials"));
    }
    Ok(Credentials {
        cred_type,
        credentials: Zeroizing::new(credentials.to_vec()),
    })
}

/// Parse a `TSPasswordCreds`, MS-CSSP 2.2.1.2.1.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] naming the field that failed. An odd
/// length OCTET STRING is not UTF-16 and is refused rather than being
/// silently truncated.
pub fn decode_password_creds(bytes: &[u8]) -> Result<PasswordCreds, AuthError> {
    let (outer, trailing) = read(bytes, "TSPasswordCreds")?;
    if outer.tag != tag::SEQUENCE || !trailing.is_empty() {
        return Err(AuthError::MalformedMessage(
            "TSPasswordCreds is not a SEQUENCE",
        ));
    }
    let (domain, rest) = string_field(outer.content, TAG_DOMAIN_NAME, "domainName")?;
    let (user, rest) = string_field(rest, TAG_USER_NAME, "userName")?;
    let (password, extra) = string_field(rest, TAG_PASSWORD, "password")?;
    if !extra.is_empty() {
        return Err(AuthError::MalformedMessage("TSPasswordCreds"));
    }
    Ok(PasswordCreds {
        domain,
        user,
        password,
    })
}

/// One `[n] OCTET STRING` holding UTF-16LE.
fn string_field<'a>(
    buf: &'a [u8],
    want: u8,
    what: &'static str,
) -> Result<(Zeroizing<String>, &'a [u8]), AuthError> {
    let (field, rest) = read(buf, what)?;
    if field.tag != want {
        return Err(AuthError::MalformedMessage(what));
    }
    let (bytes, extra) = der::expect_tag(field.content, tag::OCTET_STRING)
        .ok_or(AuthError::MalformedMessage(what))?;
    if !extra.is_empty() {
        return Err(AuthError::MalformedMessage(what));
    }
    if bytes.len() % 2 != 0 {
        return Err(AuthError::MalformedMessage(what));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16(&units).map_err(|_| AuthError::MalformedMessage(what))?;
    Ok((Zeroizing::new(text), rest))
}

fn read<'a>(buf: &'a [u8], what: &'static str) -> Result<(der::Tlv<'a>, &'a [u8]), AuthError> {
    der::read_tlv(buf).ok_or(AuthError::MalformedMessage(what))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_strings_are_utf16le_with_no_bom_and_no_terminator() {
        let der_bytes = encode_password_creds("", "u", "p");
        // SEQUENCE { [0] OCTET STRING "", [1] OCTET STRING "u", [2] ... "p" }
        assert_eq!(
            &*der_bytes,
            &[
                0x30, 0x10, // SEQUENCE, 16 content bytes
                0xa0, 0x02, 0x04, 0x00, // [0] domainName, OCTET STRING, empty
                0xa1, 0x04, 0x04, 0x02, b'u', 0x00, // [1] userName, "u"
                0xa2, 0x04, 0x04, 0x02, b'p', 0x00, // [2] password, "p"
            ]
        );
    }

    #[test]
    fn a_cyrillic_password_and_a_dotted_domain_round_trip() {
        // Catches both a UTF-8 slip and a length miscount (PRDRDP/14 §3.9).
        let creds = encode_password_creds(
            "corp.example.com",
            "\u{412}\u{430}\u{43d}\u{44f}",
            "\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c}!",
        );
        let parsed = decode_password_creds(&creds).unwrap();
        assert_eq!(&*parsed.domain, "corp.example.com");
        assert_eq!(&*parsed.user, "\u{412}\u{430}\u{43d}\u{44f}");
        assert_eq!(
            &*parsed.password,
            "\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c}!"
        );
    }

    #[test]
    fn a_password_outside_the_basic_multilingual_plane_survives_the_surrogate_pair() {
        // A single code point that needs two UTF-16 units. A length computed
        // from `chars().count()` rather than from the encoding is wrong here
        // and nowhere else.
        let creds = encode_password_creds("", "u", "pass\u{1f600}word");
        let parsed = decode_password_creds(&creds).unwrap();
        assert_eq!(&*parsed.password, "pass\u{1f600}word");
    }

    #[test]
    fn the_all_empty_restricted_admin_shape_encodes() {
        // MS-CSSP 3.1.5. Not a mode we offer in phase 1; the encoder handles
        // it because the empty domain path has to work anyway.
        let creds = encode_password_creds("", "", "");
        let parsed = decode_password_creds(&creds).unwrap();
        assert!(parsed.domain.is_empty());
        assert!(parsed.user.is_empty());
        assert!(parsed.password.is_empty());
    }

    #[test]
    fn the_two_layers_nest_the_way_ms_cssp_2_2_1_2_says() {
        let identity = Identity::from_prompt("CORP\\alice", "", "hunter2").unwrap();
        let outer = encode_for(&identity);
        let creds = decode_credentials(&outer).unwrap();
        assert_eq!(creds.cred_type, CRED_TYPE_PASSWORD);
        let inner = decode_password_creds(&creds.credentials).unwrap();
        assert_eq!(&*inner.domain, "CORP");
        assert_eq!(&*inner.user, "alice");
        assert_eq!(&*inner.password, "hunter2");
    }

    #[test]
    fn the_debug_renderings_hide_the_password() {
        let identity = Identity::from_prompt("alice", "CORP", "hunter2").unwrap();
        let outer = encode_for(&identity);
        let creds = decode_credentials(&outer).unwrap();
        assert!(!format!("{creds:?}").contains("hunter2"));
        let inner = decode_password_creds(&creds.credentials).unwrap();
        let rendered = format!("{inner:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("***"), "{rendered}");
        assert!(rendered.contains("alice"), "the user name is not a secret");
    }

    #[test]
    fn an_odd_length_string_is_refused_rather_than_truncated() {
        let mut bytes = encode_password_creds("", "u", "p").to_vec();
        // Lengthen the password OCTET STRING by one without adding a byte.
        let last = bytes.len() - 1;
        bytes[last - 2] = 0x03;
        assert!(decode_password_creds(&bytes).is_err());
    }

    #[test]
    fn every_truncation_is_refused_and_none_panics() {
        let full = encode_for(&Identity::from_prompt("alice", "CORP", "hunter2").unwrap());
        for n in 0..full.len() {
            assert!(
                decode_credentials(&full[..n]).is_err(),
                "a {n} byte prefix decoded"
            );
        }
        let inner = encode_password_creds("CORP", "alice", "hunter2");
        for n in 0..inner.len() {
            assert!(
                decode_password_creds(&inner[..n]).is_err(),
                "a {n} byte prefix decoded"
            );
        }
    }
}
