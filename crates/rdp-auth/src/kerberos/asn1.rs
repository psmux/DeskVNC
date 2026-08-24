//! The RFC 4120 §5 structures, in DER.
//!
//! Every byte here goes through `rdp_pdu::asn1::der`, which is the workspace's
//! one X.690 implementation (PRDRDP/12 §2.1 rule 3, PRDRDP/00 R45). Nothing in
//! this file walks a length octet or a tag byte on its own. What it owns is
//! which tag holds which field, in which order, which is exactly what RFC 4120
//! §5 specifies and nothing more.
//!
//! ## What the DER subset needed, and what it did not have
//!
//! `der` already provides `read_tlv`, `expect_tag`, `read_int_i64`,
//! `read_int_u32`, `read_bit_string`, `write_tlv`, `write_int` and
//! `write_nested`, and `asn1::context(n)` builds the `[n]` identifier octet.
//! That is the whole of what Kerberos needs on the reading side and all but
//! two constants on the writing side. Kerberos uses two universal types that
//! `asn1::tag` does not name, `GeneralString` and `GeneralizedTime`, and both
//! are one identifier octet each ([`GENERAL_STRING`] and
//! [`GENERALIZED_TIME`] below). They are declared here rather than in
//! `rdp-pdu` because a constant is not a codec and `rdp-pdu` is not this
//! lane's to edit; moving them one crate down would be tidier and is a
//! one line change in each place.
//!
//! `[APPLICATION n]` is the other thing Kerberos uses that CredSSP does not.
//! Its identifier octet is `0x40 | 0x20 | n`, the application class bit with
//! the constructed bit set (X.690 §8.1.2.2), which is [`application`]. Every
//! value Kerberos uses is 30 or below, so none reaches the multi byte tag
//! form that `der::read_tlv` refuses.
//!
//! ## Everything here parses bytes a KDC chose
//!
//! Every reader returns `Result` and no reader indexes. The truncation sweep
//! in `tests/vectors_kerberos.rs` cuts every message this module can produce
//! at every offset and requires an error rather than a panic.

use rdp_pdu::asn1::der::{expect_tag, read_int_i64, read_tlv, write_int, write_nested, write_tlv};
use rdp_pdu::asn1::{context, tag};
use zeroize::Zeroizing;

use crate::error::AuthError;

use super::crypto::Enctype;

/// `GeneralString`, universal 27, primitive (X.690 §8.20). RFC 4120 §5.2.1
/// defines `KerberosString ::= GeneralString (IA5String)`.
pub const GENERAL_STRING: u8 = 0x1b;

/// `GeneralizedTime`, universal 24, primitive (X.690 §8.25). RFC 4120 §5.2.3
/// defines `KerberosTime ::= GeneralizedTime` with no fractional seconds.
pub const GENERALIZED_TIME: u8 = 0x18;

/// The identifier octet of an `[APPLICATION n]` constructed tag
/// (X.690 §8.1.2.2: class bits 01, constructed bit set).
///
/// RFC 4120 wraps nine of its messages in one: `Ticket` is `[APPLICATION 1]`,
/// `Authenticator` is 2, `AS-REQ` is 10, `AS-REP` is 11, `TGS-REQ` is 12,
/// `TGS-REP` is 13, `AP-REQ` is 14, `EncASRepPart` is 25, `EncTGSRepPart` is
/// 26 and `KRB-ERROR` is 30.
#[must_use]
pub const fn application(n: u8) -> u8 {
    0x60 | (n & 0x1f)
}

/// The `[APPLICATION n]` numbers of RFC 4120 §5.
pub mod app {
    /// `Ticket ::= [APPLICATION 1] SEQUENCE` (RFC 4120 §5.3).
    pub const TICKET: u8 = 1;
    /// `Authenticator ::= [APPLICATION 2] SEQUENCE` (RFC 4120 §5.5.1).
    pub const AUTHENTICATOR: u8 = 2;
    /// `AS-REQ ::= [APPLICATION 10] KDC-REQ` (RFC 4120 §5.4.1).
    pub const AS_REQ: u8 = 10;
    /// `AS-REP ::= [APPLICATION 11] KDC-REP` (RFC 4120 §5.4.2).
    pub const AS_REP: u8 = 11;
    /// `TGS-REQ ::= [APPLICATION 12] KDC-REQ` (RFC 4120 §5.4.1).
    pub const TGS_REQ: u8 = 12;
    /// `TGS-REP ::= [APPLICATION 13] KDC-REP` (RFC 4120 §5.4.2).
    pub const TGS_REP: u8 = 13;
    /// `AP-REQ ::= [APPLICATION 14] SEQUENCE` (RFC 4120 §5.5.1).
    pub const AP_REQ: u8 = 14;
    /// `EncASRepPart ::= [APPLICATION 25] EncKDCRepPart` (RFC 4120 §5.4.2).
    pub const ENC_AS_REP_PART: u8 = 25;
    /// `EncTGSRepPart ::= [APPLICATION 26] EncKDCRepPart` (RFC 4120 §5.4.2).
    pub const ENC_TGS_REP_PART: u8 = 26;
    /// `KRB-ERROR ::= [APPLICATION 30] SEQUENCE` (RFC 4120 §5.9.1).
    pub const KRB_ERROR: u8 = 30;
}

/// `msg-type` values (RFC 4120 §7.5.7).
pub mod msg_type {
    /// `KRB_AS_REQ`.
    pub const AS_REQ: i64 = 10;
    /// `KRB_AS_REP`.
    pub const AS_REP: i64 = 11;
    /// `KRB_TGS_REQ`.
    pub const TGS_REQ: i64 = 12;
    /// `KRB_TGS_REP`.
    pub const TGS_REP: i64 = 13;
    /// `KRB_AP_REQ`.
    pub const AP_REQ: i64 = 14;
    /// `KRB_ERROR`.
    pub const KRB_ERROR: i64 = 30;
}

/// `pvno`, the Kerberos protocol version, 5 everywhere (RFC 4120 §5.4.1).
pub const PVNO: i64 = 5;

/// Principal name types (RFC 4120 §6.2).
pub mod name_type {
    /// `NT-UNKNOWN`. What a KDC reply usually carries and what we accept.
    pub const UNKNOWN: i64 = 0;
    /// `NT-PRINCIPAL`, "just the name of the principal". A plain account.
    pub const PRINCIPAL: i64 = 1;
    /// `NT-SRV-INST`, "service and other unique instance (krbtgt)". The two
    /// part name `krbtgt/REALM`.
    pub const SRV_INST: i64 = 2;
    /// `NT-SRV-HST`, "service with host name as instance". `TERMSRV/host`.
    pub const SRV_HST: i64 = 3;
    /// `NT-ENTERPRISE`, "enterprise name, may be mapped to principal name".
    /// A user principal name, `user@corp.example.com`, logged on whole.
    pub const ENTERPRISE: i64 = 10;
}

/// Pre-authentication data types (RFC 4120 §7.5.2).
pub mod padata_type {
    /// `PA-TGS-REQ`, an AP-REQ carried in a TGS-REQ's padata.
    pub const TGS_REQ: i64 = 1;
    /// `PA-ENC-TIMESTAMP`, the encrypted timestamp of RFC 4120 §5.2.7.2.
    pub const ENC_TIMESTAMP: i64 = 2;
    /// `PA-PW-SALT`, a bare salt with no etype. Older than
    /// [`ETYPE_INFO2`](self::ETYPE_INFO2) and still sent beside it by Active
    /// Directory.
    pub const PW_SALT: i64 = 3;
    /// `PA-ETYPE-INFO`, superseded. RFC 4120 §5.2.7.5 says a KDC supporting
    /// an enctype defined after RFC 1510 MUST use `PA-ETYPE-INFO2`, and both
    /// AES enctypes are, so this one is read only to be ignored.
    pub const ETYPE_INFO: i64 = 11;
    /// `PA-ETYPE-INFO2`, the salt and the string-to-key parameters
    /// (RFC 4120 §5.2.7.5).
    pub const ETYPE_INFO2: i64 = 19;
}

/// The `KDCOptions` bits we set (RFC 4120 §5.4.1).
///
/// The numbering is X.690's BIT STRING numbering: bit 0 is the most
/// significant bit of the first octet. `KDCOptions` is a `KerberosFlags`,
/// which RFC 4120 §5.2.8 fixes at 32 bits, so the encoding is always four
/// octets with no unused bits.
pub mod kdc_option {
    /// `forwardable(1)`. Asked for because Windows asks for it and because a
    /// non forwardable TGT is refused by some policies outright.
    pub const FORWARDABLE: u32 = 1;
    /// `renewable(8)`.
    pub const RENEWABLE: u32 = 8;
    /// `renewable-ok(27)`. If the KDC cannot give the lifetime asked for, a
    /// renewable ticket with a shorter one is acceptable.
    pub const RENEWABLE_OK: u32 = 27;
}

/// `KerberosFlags` as its four octets, from a list of set bit numbers
/// (RFC 4120 §5.2.8).
#[must_use]
pub fn kerberos_flags(bits: &[u32]) -> [u8; 4] {
    let mut word: u32 = 0;
    for bit in bits {
        if *bit < 32 {
            // X.690 BIT STRING numbering: bit 0 is the most significant bit
            // of the first octet, which is bit 31 of a big endian u32.
            word |= 1u32 << (31 - bit);
        }
    }
    word.to_be_bytes()
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

/// `KerberosString`, RFC 4120 §5.2.1. A `GeneralString` holding IA5 text.
pub fn write_kerberos_string(out: &mut Vec<u8>, value: &str) {
    write_tlv(out, GENERAL_STRING, value.as_bytes());
}

/// `KerberosTime`, RFC 4120 §5.2.3: a `GeneralizedTime` with no fractional
/// seconds, no separators, and the `Z` zone.
///
/// The RFC's own example is "19960607212627Z" for 6 minutes 27 seconds after
/// 9 pm on 6 June 1996. `time` is [`KerberosTime`], which is built from a
/// Unix timestamp by the caller: this crate owns no clock, because a crate
/// with no I/O has no business reading one (PRDRDP/12 §2.1), and the session
/// hands the time in.
pub fn write_kerberos_time(out: &mut Vec<u8>, time: KerberosTime) {
    write_tlv(out, GENERALIZED_TIME, time.as_str().as_bytes());
}

/// `PrincipalName`, RFC 4120 §5.2.2.
///
/// ```text
/// PrincipalName ::= SEQUENCE {
///         name-type   [0] Int32,
///         name-string [1] SEQUENCE OF KerberosString
/// }
/// ```
pub fn write_principal_name(out: &mut Vec<u8>, name_type: i64, components: &[&str]) {
    write_nested(out, tag::SEQUENCE, |seq| {
        write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, name_type));
        write_nested(seq, context(1), |list| {
            write_nested(list, tag::SEQUENCE, |items| {
                for component in components {
                    write_kerberos_string(items, component);
                }
            });
        });
    });
}

/// `EncryptedData`, RFC 4120 §5.2.9.
///
/// ```text
/// EncryptedData ::= SEQUENCE {
///         etype  [0] Int32,
///         kvno   [1] UInt32 OPTIONAL,
///         cipher [2] OCTET STRING
/// }
/// ```
///
/// `kvno` is omitted on everything a client sends. RFC 4120 §5.2.9 says it is
/// present only in messages encrypted under a long lasting key, and a KDC
/// finds the right version of the client key from the principal without it.
pub fn write_encrypted_data(out: &mut Vec<u8>, enctype: Enctype, cipher: &[u8]) {
    write_nested(out, tag::SEQUENCE, |seq| {
        write_nested(seq, context(0), |t| {
            write_int(t, tag::INTEGER, i64::from(enctype.etype()));
        });
        write_nested(seq, context(2), |t| {
            write_tlv(t, tag::OCTET_STRING, cipher);
        });
    });
}

/// `Checksum`, RFC 4120 §5.2.9.
///
/// ```text
/// Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING }
/// ```
pub fn write_checksum(out: &mut Vec<u8>, cksumtype: i64, value: &[u8]) {
    write_nested(out, tag::SEQUENCE, |seq| {
        write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, cksumtype));
        write_nested(seq, context(1), |t| write_tlv(t, tag::OCTET_STRING, value));
    });
}

/// `PA-DATA`, RFC 4120 §5.2.7. The first tag is `[1]`, not `[0]`, which the
/// RFC calls out in a comment inside the definition because it is the one
/// structure in the document that does not start at zero.
pub fn write_padata(out: &mut Vec<u8>, padata_type: i64, value: &[u8]) {
    write_nested(out, tag::SEQUENCE, |seq| {
        write_nested(seq, context(1), |t| write_int(t, tag::INTEGER, padata_type));
        write_nested(seq, context(2), |t| write_tlv(t, tag::OCTET_STRING, value));
    });
}

/// `PA-ENC-TS-ENC`, RFC 4120 §5.2.7.2.
///
/// ```text
/// PA-ENC-TS-ENC ::= SEQUENCE {
///         patimestamp [0] KerberosTime,
///         pausec      [1] Microseconds OPTIONAL
/// }
/// ```
///
/// `pausec` is omitted. RFC 4120 §5.2.7.2 says it "MAY be omitted if a client
/// will not generate more than one request per second", and a client that
/// authenticates once per connection will not.
#[must_use]
pub fn encode_pa_enc_ts_enc(timestamp: KerberosTime) -> Vec<u8> {
    let mut out = Vec::new();
    write_nested(&mut out, tag::SEQUENCE, |seq| {
        write_nested(seq, context(0), |t| write_kerberos_time(t, timestamp));
    });
    out
}

// ---------------------------------------------------------------------------
// KerberosTime
// ---------------------------------------------------------------------------

/// A `KerberosTime`, RFC 4120 §5.2.3: `YYYYMMDDHHMMSSZ`, UTC, no fractional
/// seconds and no separators.
///
/// Built from a Unix timestamp rather than from a clock. This crate reads no
/// clock: it has no I/O (PRDRDP/12 §2.1), and a clock is I/O in every sense
/// that matters to a test. The session passes the time in, which is also what
/// makes the clock skew retry of RFC 4120 §5.4.1 testable, because a test can
/// hand it a time five minutes wrong on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KerberosTime {
    /// `YYYYMMDDHHMMSSZ`, fifteen ASCII octets.
    text: [u8; 15],
}

impl KerberosTime {
    /// A `KerberosTime` from seconds since the Unix epoch.
    ///
    /// The civil date arithmetic is Howard Hinnant's `days_from_civil`
    /// inverse, which is the standard closed form for the proleptic Gregorian
    /// calendar and is exact for every year this protocol will see. Kerberos
    /// has no leap seconds to worry about: a Unix timestamp does not count
    /// them either, so the two agree by construction.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for a timestamp before 1 January 1970
    /// or beyond the year 9999, neither of which a working clock produces and
    /// both of which would encode to something a KDC cannot parse.
    pub fn from_unix_seconds(seconds: i64) -> Result<Self, AuthError> {
        if !(0..=253_402_300_799).contains(&seconds) {
            return Err(AuthError::MalformedMessage("KerberosTime out of range"));
        }
        let days = seconds / 86_400;
        let secs_of_day = seconds % 86_400;
        let (year, month, day) = civil_from_days(days);
        let hour = secs_of_day / 3600;
        let minute = (secs_of_day % 3600) / 60;
        let second = secs_of_day % 60;

        let mut text = [b'0'; 15];
        write_digits(&mut text, 0, 4, year);
        write_digits(&mut text, 4, 2, month);
        write_digits(&mut text, 6, 2, day);
        write_digits(&mut text, 8, 2, hour);
        write_digits(&mut text, 10, 2, minute);
        write_digits(&mut text, 12, 2, second);
        if let Some(slot) = text.get_mut(14) {
            *slot = b'Z';
        }
        Ok(KerberosTime { text })
    }

    /// The fifteen octets as they go on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Every octet was written by `from_unix_seconds` from a digit table
        // or is the literal `Z`, so this is ASCII by construction.
        std::str::from_utf8(&self.text).unwrap_or("19700101000000Z")
    }

    /// Parse the `stime` of a `KRB-ERROR`, so the clock skew retry of
    /// RFC 4120 §5.4.1 can measure the offset.
    ///
    /// Accepts exactly the DER form: fifteen octets, fourteen digits and a
    /// trailing `Z`. A `GeneralizedTime` with a fractional part or an offset
    /// zone is legal BER and illegal DER, and RFC 4120 §5.2.3 forbids both
    /// here, so it is refused rather than guessed at.
    ///
    /// The digits are also checked to name a real date, here rather than in
    /// [`to_unix_seconds`](Self::to_unix_seconds), so that a `KerberosTime`
    /// that exists is a `KerberosTime` that means something. The check is the
    /// round trip through the calendar: 31 February encodes to a day count
    /// that decodes back to 3 March, and a value that does not come back as
    /// itself is refused. A KDC answering `KRB_AP_ERR_SKEW` with a date that
    /// does not exist would otherwise produce a clock offset of months.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for anything else.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthError> {
        let bad = || AuthError::MalformedMessage("KerberosTime");
        if bytes.len() != 15 || bytes.last() != Some(&b'Z') {
            return Err(bad());
        }
        if !bytes
            .get(..14)
            .ok_or_else(bad)?
            .iter()
            .all(u8::is_ascii_digit)
        {
            return Err(bad());
        }
        let mut text = [b'0'; 15];
        for (slot, byte) in text.iter_mut().zip(bytes) {
            *slot = *byte;
        }
        let candidate = KerberosTime { text };
        let (year, month, day, hour, minute, second) = candidate.fields();
        if !(1..=12).contains(&month) || day < 1 || hour > 23 || minute > 59 || second > 59 {
            return Err(bad());
        }
        if civil_from_days(days_from_civil(year, month, day)) != (year, month, day) {
            return Err(bad());
        }
        Ok(candidate)
    }

    /// Seconds since the Unix epoch, for the skew arithmetic.
    ///
    /// Infallible: every `KerberosTime` was built either from a timestamp in
    /// range or by [`parse`](Self::parse), which refuses a date that is not
    /// a real one.
    #[must_use]
    pub fn to_unix_seconds(self) -> i64 {
        let (year, month, day, hour, minute, second) = self.fields();
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
    }

    /// The six decimal fields, as numbers.
    fn fields(self) -> (i64, i64, i64, i64, i64, i64) {
        let field = |from: usize, len: usize| -> i64 {
            let mut value: i64 = 0;
            for byte in self.text.get(from..from + len).unwrap_or(&[]) {
                value = value * 10 + i64::from(byte.wrapping_sub(b'0'));
            }
            value
        };
        (
            field(0, 4),
            field(4, 2),
            field(6, 2),
            field(8, 2),
            field(10, 2),
            field(12, 2),
        )
    }
}

/// Write `count` decimal digits of `value` at `at`, most significant first.
fn write_digits(out: &mut [u8; 15], at: usize, count: usize, value: i64) {
    let mut remaining = value;
    for i in (0..count).rev() {
        if let Some(slot) = out.get_mut(at + i) {
            *slot = b'0' + u8::try_from(remaining % 10).unwrap_or(0);
        }
        remaining /= 10;
    }
}

/// Days since the Unix epoch to a civil `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, the standard closed form for the
/// proleptic Gregorian calendar. It is date arithmetic, not a protocol
/// decision, and it is here rather than in a dependency because the one
/// dependency that would supply it is `chrono` or `time`, and neither belongs
/// in a crate whose whole point is that it does no I/O and reads no clock.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Shift the epoch to 1 March 0000, so a leap day falls at the end of the
    // year and every month has a fixed length from the start of the era.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The inverse of [`civil_from_days`].
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

/// One `[n]` field of a SEQUENCE, or `None` when the next element is not it.
///
/// Kerberos SEQUENCEs are mostly optional fields in ascending tag order, so
/// the reading shape is "if the next tag is the one I want, take it, else
/// leave it alone and try the next field". Returns the content of the `[n]`
/// wrapper and the remaining bytes.
fn take_context(buf: &[u8], n: u8) -> (Option<&[u8]>, &[u8]) {
    match read_tlv(buf) {
        Some((tlv, rest)) if tlv.tag == context(n) => (Some(tlv.content), rest),
        _ => (None, buf),
    }
}

/// The content of a required `[n]` field.
fn required_context<'a>(
    buf: &'a [u8],
    n: u8,
    field: &'static str,
) -> Result<(&'a [u8], &'a [u8]), AuthError> {
    match take_context(buf, n) {
        (Some(content), rest) => Ok((content, rest)),
        (None, _) => Err(AuthError::MalformedMessage(field)),
    }
}

/// An `Int32` or `UInt32` inside a `[n]` wrapper.
fn read_tagged_int(buf: &[u8], field: &'static str) -> Result<i64, AuthError> {
    read_int_i64(buf)
        .map(|(value, _)| value)
        .ok_or(AuthError::MalformedMessage(field))
}

/// An `OCTET STRING` inside a `[n]` wrapper.
fn read_tagged_octets<'a>(buf: &'a [u8], field: &'static str) -> Result<&'a [u8], AuthError> {
    expect_tag(buf, tag::OCTET_STRING)
        .map(|(content, _)| content)
        .ok_or(AuthError::MalformedMessage(field))
}

/// A `KerberosString` inside a `[n]` wrapper.
///
/// The bytes are returned as a `String` through `from_utf8_lossy`. RFC 4120
/// §5.2.1 restricts `KerberosString` to IA5, and then says implementations
/// "MAY choose to accept GeneralString values that contain characters other
/// than those permitted by IA5String". A realm name that is not ASCII is
/// something we display and compare, never something we execute, so lossy is
/// the right failure: replacing an octet is better than refusing a ticket.
fn read_tagged_string(buf: &[u8], field: &'static str) -> Result<String, AuthError> {
    let (tlv, _) = read_tlv(buf).ok_or(AuthError::MalformedMessage(field))?;
    if tlv.tag != GENERAL_STRING {
        return Err(AuthError::MalformedMessage(field));
    }
    Ok(String::from_utf8_lossy(tlv.content).into_owned())
}

/// A parsed `PrincipalName` (RFC 4120 §5.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalName {
    /// `name-type`, one of [`name_type`].
    pub name_type: i64,
    /// `name-string`. Untrusted text from a KDC: render it, never execute it.
    pub components: Vec<String>,
}

impl PrincipalName {
    /// Read a `PrincipalName` from the content of its `[n]` wrapper.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for anything that is not the shape
    /// RFC 4120 §5.2.2 defines.
    pub fn read(buf: &[u8]) -> Result<Self, AuthError> {
        let bad = AuthError::MalformedMessage("PrincipalName");
        let (body, _) = expect_tag(buf, tag::SEQUENCE).ok_or(bad)?;
        let (type_field, rest) = required_context(body, 0, "PrincipalName.name-type")?;
        let name_type = read_tagged_int(type_field, "PrincipalName.name-type")?;
        let (list_field, _) = required_context(rest, 1, "PrincipalName.name-string")?;
        let (mut items, _) = expect_tag(list_field, tag::SEQUENCE).ok_or(bad)?;

        let mut components = Vec::new();
        while !items.is_empty() {
            let (tlv, next) = read_tlv(items).ok_or(bad)?;
            if tlv.tag != GENERAL_STRING {
                return Err(bad);
            }
            components.push(String::from_utf8_lossy(tlv.content).into_owned());
            // A KDC that claims a thousand components is not describing a
            // principal. The longest real one is three.
            if components.len() > 16 {
                return Err(bad);
            }
            items = next;
        }
        Ok(PrincipalName {
            name_type,
            components,
        })
    }

    /// `component/component/...`, for a log line and an error message.
    #[must_use]
    pub fn display(&self) -> String {
        self.components.join("/")
    }
}

/// A parsed `EncryptedData` (RFC 4120 §5.2.9).
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// `etype`. Kept as the raw value rather than an [`Enctype`], because a
    /// KDC may name one we do not implement and the error for that is
    /// "the domain controller does not support AES Kerberos encryption"
    /// rather than a parse failure.
    pub etype: i64,
    /// `cipher`, the enciphered text.
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    /// Read an `EncryptedData` from the content of its `[n]` wrapper.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for anything that is not the shape
    /// RFC 4120 §5.2.9 defines.
    pub fn read(buf: &[u8]) -> Result<Self, AuthError> {
        let bad = AuthError::MalformedMessage("EncryptedData");
        let (body, _) = expect_tag(buf, tag::SEQUENCE).ok_or(bad)?;
        let (etype_field, rest) = required_context(body, 0, "EncryptedData.etype")?;
        let etype = read_tagged_int(etype_field, "EncryptedData.etype")?;
        // kvno [1] is optional and we do not use it: it names which version
        // of the server's own key encrypted the ticket, which is the server's
        // business.
        let (_kvno, rest) = take_context(rest, 1);
        let (cipher_field, _) = required_context(rest, 2, "EncryptedData.cipher")?;
        Ok(EncryptedData {
            etype,
            cipher: read_tagged_octets(cipher_field, "EncryptedData.cipher")?.to_vec(),
        })
    }
}

/// A parsed `EncryptionKey` (RFC 4120 §5.2.9). The key octets are
/// `Zeroizing`; this is a session key.
pub struct EncryptionKey {
    /// `keytype`, which RFC 4120 §5.2.9 notes "actually specifies an
    /// encryption type" despite its name.
    pub keytype: i64,
    /// `keyvalue`.
    pub keyvalue: Zeroizing<Vec<u8>>,
}

impl EncryptionKey {
    /// Read an `EncryptionKey` from the content of its `[n]` wrapper.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for anything that is not the shape
    /// RFC 4120 §5.2.9 defines.
    pub fn read(buf: &[u8]) -> Result<Self, AuthError> {
        let bad = AuthError::MalformedMessage("EncryptionKey");
        let (body, _) = expect_tag(buf, tag::SEQUENCE).ok_or(bad)?;
        let (type_field, rest) = required_context(body, 0, "EncryptionKey.keytype")?;
        let keytype = read_tagged_int(type_field, "EncryptionKey.keytype")?;
        let (value_field, _) = required_context(rest, 1, "EncryptionKey.keyvalue")?;
        Ok(EncryptionKey {
            keytype,
            keyvalue: Zeroizing::new(
                read_tagged_octets(value_field, "EncryptionKey.keyvalue")?.to_vec(),
            ),
        })
    }
}

impl std::fmt::Debug for EncryptionKey {
    /// PRDRDP/14 §8.3: no secret in any `Debug`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("keytype", &self.keytype)
            .field(
                "keyvalue",
                &format_args!("{} bytes, redacted", self.keyvalue.len()),
            )
            .finish()
    }
}

/// A `Ticket` (RFC 4120 §5.3), kept as the bytes it arrived in.
///
/// `enc-part` is encrypted under the service's own key and is opaque to a
/// client, so there is nothing to parse inside it and nothing to gain from
/// rebuilding the outside: a ticket goes into an AP-REQ exactly as it came
/// out of the KDC reply. Keeping the original encoding also sidesteps the
/// class of bug where a re-serialisation differs from the original by a
/// length octet and the service's own signature check fails.
#[derive(Clone)]
pub struct Ticket {
    /// The whole `[APPLICATION 1]` element, tag and length included.
    der: Vec<u8>,
    /// `realm`, for diagnostics and for the AP-REQ's own realm check.
    pub realm: String,
    /// `sname`, so an error can name the SPN the ticket is actually for.
    pub sname: PrincipalName,
}

impl Ticket {
    /// Read a `Ticket` from the front of `buf`, returning it and the rest.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for anything that is not the shape
    /// RFC 4120 §5.3 defines.
    pub fn read(buf: &[u8]) -> Result<(Self, &[u8]), AuthError> {
        let bad = AuthError::MalformedMessage("Ticket");
        let (tlv, rest) = read_tlv(buf).ok_or(bad)?;
        if tlv.tag != application(app::TICKET) {
            return Err(bad);
        }
        let (body, _) = expect_tag(tlv.content, tag::SEQUENCE).ok_or(bad)?;
        let (vno_field, body) = required_context(body, 0, "Ticket.tkt-vno")?;
        if read_tagged_int(vno_field, "Ticket.tkt-vno")? != PVNO {
            return Err(AuthError::MalformedMessage("Ticket.tkt-vno"));
        }
        let (realm_field, body) = required_context(body, 1, "Ticket.realm")?;
        let realm = read_tagged_string(realm_field, "Ticket.realm")?;
        let (sname_field, body) = required_context(body, 2, "Ticket.sname")?;
        let sname = PrincipalName::read(sname_field)?;
        // enc-part [3] is present and opaque; requiring it catches a truncated
        // ticket here rather than in the service.
        let (_enc, _) = required_context(body, 3, "Ticket.enc-part")?;
        Ok((
            Ticket {
                der: tlv.full.to_vec(),
                realm,
                sname,
            },
            rest,
        ))
    }

    /// The ticket's own DER, for placing in an AP-REQ.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticket")
            .field("realm", &self.realm)
            .field("sname", &self.sname.display())
            .field("der", &format_args!("{} bytes", self.der.len()))
            .finish()
    }
}

/// One `PA-DATA` element (RFC 4120 §5.2.7).
#[derive(Debug, Clone)]
pub struct PaData {
    /// `padata-type`, one of [`padata_type`].
    pub padata_type: i64,
    /// `padata-value`.
    pub value: Vec<u8>,
}

/// Read a `SEQUENCE OF PA-DATA` from the content of its `[n]` wrapper.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] for anything that is not the shape
/// RFC 4120 §5.2.7 defines.
pub fn read_padata_list(buf: &[u8]) -> Result<Vec<PaData>, AuthError> {
    let bad = AuthError::MalformedMessage("PA-DATA");
    let (mut items, _) = expect_tag(buf, tag::SEQUENCE).ok_or(bad)?;
    let mut out = Vec::new();
    while !items.is_empty() {
        let (tlv, next) = read_tlv(items).ok_or(bad)?;
        items = next;
        if tlv.tag != tag::SEQUENCE {
            return Err(bad);
        }
        let (type_field, rest) = required_context(tlv.content, 1, "PA-DATA.padata-type")?;
        let padata_type = read_tagged_int(type_field, "PA-DATA.padata-type")?;
        let (value_field, _) = required_context(rest, 2, "PA-DATA.padata-value")?;
        out.push(PaData {
            padata_type,
            value: read_tagged_octets(value_field, "PA-DATA.padata-value")?.to_vec(),
        });
        // A KDC offering more than this many pre-authentication methods is
        // not describing a login.
        if out.len() > 32 {
            return Err(bad);
        }
    }
    Ok(out)
}

/// One `ETYPE-INFO2-ENTRY` (RFC 4120 §5.2.7.5).
#[derive(Debug, Clone)]
pub struct EtypeInfo2Entry {
    /// `etype`.
    pub etype: i64,
    /// `salt`, as octets. RFC 4120 §5.2.7.5 types it `KerberosString` and
    /// then says "existing installations might have locale-specific
    /// characters stored in salt strings", so it is kept as bytes and fed to
    /// PBKDF2 as bytes. Decoding it to a `String` and re-encoding would be a
    /// silent transformation of a value the whole key depends on.
    pub salt: Option<Vec<u8>>,
    /// `s2kparams`. For RFC 3962 this is four octets holding the iteration
    /// count in big endian order (RFC 3962 §4).
    pub s2kparams: Option<Vec<u8>>,
}

impl EtypeInfo2Entry {
    /// The iteration count this entry names, or RFC 3962 §4's default of
    /// 4096 when it names none.
    ///
    /// RFC 3962 §4: "If the value is 00 00 00 00, the number of iterations to
    /// be performed is 4,294,967,296 (2**32)." That count is refused rather
    /// than attempted; `crypto::string_to_key` caps it and the message says
    /// the domain controller asked for something unreasonable.
    #[must_use]
    pub fn iterations(&self) -> u32 {
        match self.s2kparams.as_deref() {
            Some([a, b, c, d]) => {
                let count = u32::from_be_bytes([*a, *b, *c, *d]);
                if count == 0 {
                    // 2**32 does not fit a u32. Hand back the value that
                    // `string_to_key` will refuse, so the refusal happens in
                    // one place with one message.
                    u32::MAX
                } else {
                    count
                }
            }
            _ => super::crypto::DEFAULT_ITERATIONS,
        }
    }
}

/// Read an `ETYPE-INFO2` (RFC 4120 §5.2.7.5) from a `padata-value`.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] for anything that is not the shape the
/// section defines.
pub fn read_etype_info2(buf: &[u8]) -> Result<Vec<EtypeInfo2Entry>, AuthError> {
    let bad = AuthError::MalformedMessage("ETYPE-INFO2");
    let (mut items, _) = expect_tag(buf, tag::SEQUENCE).ok_or(bad)?;
    let mut out = Vec::new();
    while !items.is_empty() {
        let (tlv, next) = read_tlv(items).ok_or(bad)?;
        items = next;
        if tlv.tag != tag::SEQUENCE {
            return Err(bad);
        }
        let (etype_field, rest) = required_context(tlv.content, 0, "ETYPE-INFO2-ENTRY.etype")?;
        let etype = read_tagged_int(etype_field, "ETYPE-INFO2-ENTRY.etype")?;
        let (salt_field, rest) = take_context(rest, 1);
        let salt = match salt_field {
            Some(content) => {
                let (tlv, _) = read_tlv(content).ok_or(bad)?;
                if tlv.tag != GENERAL_STRING {
                    return Err(bad);
                }
                Some(tlv.content.to_vec())
            }
            None => None,
        };
        let (params_field, _) = take_context(rest, 2);
        let s2kparams = match params_field {
            Some(content) => {
                Some(read_tagged_octets(content, "ETYPE-INFO2-ENTRY.s2kparams")?.to_vec())
            }
            None => None,
        };
        out.push(EtypeInfo2Entry {
            etype,
            salt,
            s2kparams,
        });
        if out.len() > 32 {
            return Err(bad);
        }
    }
    Ok(out)
}

/// A parsed `KDC-REP`, AS or TGS (RFC 4120 §5.4.2).
#[derive(Debug)]
pub struct KdcRep {
    /// `msg-type`: 11 for an AS-REP, 13 for a TGS-REP.
    pub msg_type: i64,
    /// `padata`, which an AS-REP uses to carry the salt it actually used.
    pub padata: Vec<PaData>,
    /// `crealm`.
    pub crealm: String,
    /// `cname`.
    pub cname: PrincipalName,
    /// `ticket`.
    pub ticket: Ticket,
    /// `enc-part`, still encrypted.
    pub enc_part: EncryptedData,
}

impl KdcRep {
    /// Read an AS-REP or a TGS-REP, requiring the `[APPLICATION n]` wrapper
    /// `expected_app` and the matching `msg-type`.
    ///
    /// Both are checked because they are two independent statements of the
    /// same thing and a KDC that disagrees with itself is not one to take a
    /// session key from.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for anything that is not the shape
    /// RFC 4120 §5.4.2 defines.
    pub fn read(buf: &[u8], expected_app: u8, expected_msg_type: i64) -> Result<Self, AuthError> {
        let bad = AuthError::MalformedMessage("KDC-REP");
        let (tlv, _) = read_tlv(buf).ok_or(bad)?;
        if tlv.tag != application(expected_app) {
            return Err(bad);
        }
        let (body, _) = expect_tag(tlv.content, tag::SEQUENCE).ok_or(bad)?;

        let (pvno_field, body) = required_context(body, 0, "KDC-REP.pvno")?;
        if read_tagged_int(pvno_field, "KDC-REP.pvno")? != PVNO {
            return Err(AuthError::MalformedMessage("KDC-REP.pvno"));
        }
        let (type_field, body) = required_context(body, 1, "KDC-REP.msg-type")?;
        let msg_type = read_tagged_int(type_field, "KDC-REP.msg-type")?;
        if msg_type != expected_msg_type {
            return Err(AuthError::MalformedMessage("KDC-REP.msg-type"));
        }
        let (padata_field, body) = take_context(body, 2);
        let padata = match padata_field {
            Some(content) => read_padata_list(content)?,
            None => Vec::new(),
        };
        let (crealm_field, body) = required_context(body, 3, "KDC-REP.crealm")?;
        let crealm = read_tagged_string(crealm_field, "KDC-REP.crealm")?;
        let (cname_field, body) = required_context(body, 4, "KDC-REP.cname")?;
        let cname = PrincipalName::read(cname_field)?;
        let (ticket_field, body) = required_context(body, 5, "KDC-REP.ticket")?;
        let (ticket, _) = Ticket::read(ticket_field)?;
        let (enc_field, _) = required_context(body, 6, "KDC-REP.enc-part")?;
        let enc_part = EncryptedData::read(enc_field)?;

        Ok(KdcRep {
            msg_type,
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        })
    }
}

/// The fields of an `EncKDCRepPart` a client acts on (RFC 4120 §5.4.2).
///
/// `last-req`, `key-expiration`, `authtime`, `starttime`, `renew-till` and
/// `caddr` are read past rather than kept. A client that shows none of them
/// has no use for them, and a field that is parsed but never read is a parser
/// with no test behind it.
pub struct EncKdcRepPart {
    /// `key`, the session key. Secret.
    pub key: EncryptionKey,
    /// `nonce`, which must equal the one we sent.
    pub nonce: i64,
    /// `endtime`, so the session can tell how long the ticket is good for.
    pub endtime: KerberosTime,
    /// `srealm`.
    pub srealm: String,
    /// `sname`, so a ticket for the wrong service is caught here.
    pub sname: PrincipalName,
}

impl EncKdcRepPart {
    /// Read an `EncASRepPart` or an `EncTGSRepPart`.
    ///
    /// Both application tags are accepted for either reply, because Windows
    /// and MIT have both been observed to answer an AS-REQ with an
    /// `[APPLICATION 26]` body and RFC 4120 §5.4.2's own text does not forbid
    /// it. What matters is the contents, and the contents are the same
    /// `EncKDCRepPart` either way.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for anything that is not the shape
    /// RFC 4120 §5.4.2 defines.
    pub fn read(buf: &[u8]) -> Result<Self, AuthError> {
        let bad = AuthError::MalformedMessage("EncKDCRepPart");
        let (tlv, _) = read_tlv(buf).ok_or(bad)?;
        if tlv.tag != application(app::ENC_AS_REP_PART)
            && tlv.tag != application(app::ENC_TGS_REP_PART)
        {
            return Err(bad);
        }
        let (body, _) = expect_tag(tlv.content, tag::SEQUENCE).ok_or(bad)?;

        let (key_field, body) = required_context(body, 0, "EncKDCRepPart.key")?;
        let key = EncryptionKey::read(key_field)?;
        let (_last_req, body) = required_context(body, 1, "EncKDCRepPart.last-req")?;
        let (nonce_field, body) = required_context(body, 2, "EncKDCRepPart.nonce")?;
        let nonce = read_tagged_int(nonce_field, "EncKDCRepPart.nonce")?;
        let (_key_expiration, body) = take_context(body, 3);
        let (_flags, body) = required_context(body, 4, "EncKDCRepPart.flags")?;
        let (_authtime, body) = required_context(body, 5, "EncKDCRepPart.authtime")?;
        let (_starttime, body) = take_context(body, 6);
        let (endtime_field, body) = required_context(body, 7, "EncKDCRepPart.endtime")?;
        let endtime = read_kerberos_time(endtime_field, "EncKDCRepPart.endtime")?;
        let (_renew_till, body) = take_context(body, 8);
        let (srealm_field, body) = required_context(body, 9, "EncKDCRepPart.srealm")?;
        let srealm = read_tagged_string(srealm_field, "EncKDCRepPart.srealm")?;
        let (sname_field, _) = required_context(body, 10, "EncKDCRepPart.sname")?;
        let sname = PrincipalName::read(sname_field)?;

        Ok(EncKdcRepPart {
            key,
            nonce,
            endtime,
            srealm,
            sname,
        })
    }
}

impl std::fmt::Debug for EncKdcRepPart {
    /// PRDRDP/14 §8.3. `key` redacts itself and is named here so the omission
    /// is visible rather than looking like an oversight.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncKdcRepPart")
            .field("key", &self.key)
            .field("nonce", &self.nonce)
            .field("endtime", &self.endtime.as_str())
            .field("srealm", &self.srealm)
            .field("sname", &self.sname.display())
            .finish()
    }
}

/// A `KerberosTime` inside a `[n]` wrapper.
fn read_kerberos_time(buf: &[u8], field: &'static str) -> Result<KerberosTime, AuthError> {
    let (tlv, _) = read_tlv(buf).ok_or(AuthError::MalformedMessage(field))?;
    if tlv.tag != GENERALIZED_TIME {
        return Err(AuthError::MalformedMessage(field));
    }
    KerberosTime::parse(tlv.content)
}

/// A parsed `KRB-ERROR` (RFC 4120 §5.9.1).
#[derive(Debug, Clone)]
pub struct KrbError {
    /// `stime`, the KDC's own clock, which is what makes the skew retry of
    /// RFC 4120 §5.4.1 possible.
    pub stime: KerberosTime,
    /// `error-code`, one of [`error_code`].
    pub error_code: i64,
    /// `e-data`, which for `KDC_ERR_PREAUTH_REQUIRED` is a `SEQUENCE OF
    /// PA-DATA` carrying the `PA-ETYPE-INFO2` we need.
    pub e_data: Vec<u8>,
}

impl KrbError {
    /// Read a `KRB-ERROR`.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for anything that is not the shape
    /// RFC 4120 §5.9.1 defines.
    pub fn read(buf: &[u8]) -> Result<Self, AuthError> {
        let bad = AuthError::MalformedMessage("KRB-ERROR");
        let (tlv, _) = read_tlv(buf).ok_or(bad)?;
        if tlv.tag != application(app::KRB_ERROR) {
            return Err(bad);
        }
        let (body, _) = expect_tag(tlv.content, tag::SEQUENCE).ok_or(bad)?;

        let (pvno_field, body) = required_context(body, 0, "KRB-ERROR.pvno")?;
        if read_tagged_int(pvno_field, "KRB-ERROR.pvno")? != PVNO {
            return Err(AuthError::MalformedMessage("KRB-ERROR.pvno"));
        }
        let (type_field, body) = required_context(body, 1, "KRB-ERROR.msg-type")?;
        if read_tagged_int(type_field, "KRB-ERROR.msg-type")? != msg_type::KRB_ERROR {
            return Err(AuthError::MalformedMessage("KRB-ERROR.msg-type"));
        }
        let (_ctime, body) = take_context(body, 2);
        let (_cusec, body) = take_context(body, 3);
        let (stime_field, body) = required_context(body, 4, "KRB-ERROR.stime")?;
        let stime = read_kerberos_time(stime_field, "KRB-ERROR.stime")?;
        let (_susec, body) = required_context(body, 5, "KRB-ERROR.susec")?;
        let (code_field, body) = required_context(body, 6, "KRB-ERROR.error-code")?;
        let error_code = read_tagged_int(code_field, "KRB-ERROR.error-code")?;
        let (_crealm, body) = take_context(body, 7);
        let (_cname, body) = take_context(body, 8);
        let (_realm, body) = required_context(body, 9, "KRB-ERROR.realm")?;
        let (_sname, body) = required_context(body, 10, "KRB-ERROR.sname")?;
        let (_e_text, body) = take_context(body, 11);
        let (e_data_field, _) = take_context(body, 12);
        let e_data = match e_data_field {
            Some(content) => read_tagged_octets(content, "KRB-ERROR.e-data")?.to_vec(),
            None => Vec::new(),
        };

        Ok(KrbError {
            stime,
            error_code,
            e_data,
        })
    }
}

/// The `error-code` values of RFC 4120 §7.5.9 that this client acts on.
///
/// The rest reach the user through the table in
/// [`super::kdc::user_message_for_error`], which turns a code into a sentence
/// and never into a number the user has to look up.
pub mod error_code {
    /// Error code 6: The client principal is not in the KDC database.
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i64 = 6;
    /// Error code 7: The service principal is not in the KDC database. This is what a
    /// missing `TERMSRV/<host>` SPN looks like (PRDRDP/14 §7.2).
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i64 = 7;
    /// Error code 12: KDC policy rejects the request.
    pub const KDC_ERR_POLICY: i64 = 12;
    /// Error code 14: The KDC supports none of the enctypes we offered.
    pub const KDC_ERR_ETYPE_NOSUPP: i64 = 14;
    /// Error code 18: The client's credentials have been revoked: disabled, locked out
    /// or expired.
    pub const KDC_ERR_CLIENT_REVOKED: i64 = 18;
    /// Error code 23: The password has expired.
    pub const KDC_ERR_KEY_EXPIRED: i64 = 23;
    /// Error code 24: Pre-authentication failed, which for `PA-ENC-TIMESTAMP` means the
    /// password is wrong.
    pub const KDC_ERR_PREAUTH_FAILED: i64 = 24;
    /// Error code 25: Additional pre-authentication required. Not a failure: it is the
    /// KDC handing us the salt (RFC 4120 §3.1.1).
    pub const KDC_ERR_PREAUTH_REQUIRED: i64 = 25;
    /// Error code 31: The integrity check on the decrypted field failed.
    pub const KRB_AP_ERR_BAD_INTEGRITY: i64 = 31;
    /// Error code 32: The ticket has expired.
    pub const KRB_AP_ERR_TKT_EXPIRED: i64 = 32;
    /// Error code 37: Clock skew too great. Carries the KDC's own time in `stime`
    /// (RFC 4120 §5.4.1).
    pub const KRB_AP_ERR_SKEW: i64 = 37;
    /// Error code 52: The response is too big for UDP. We are on TCP already, so this
    /// arriving means something else is wrong (PRDRDP/14 §7.1 item 10).
    pub const KRB_ERR_RESPONSE_TOO_BIG: i64 = 52;
    /// Error code 68: The request is for the wrong realm.
    pub const KDC_ERR_WRONG_REALM: i64 = 68;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4120 §5.2.3's own example: "The only valid format for UTC time 6
    /// minutes, 27 seconds after 9 pm on 6 June 1996 is 19960607212627Z."
    ///
    /// The RFC publishes the text and not the timestamp, so the timestamp is
    /// derived here and the arithmetic is written out, which is what
    /// `docs/RDP_SPEC_NOTES.md` §1.7 asks for when no vector exists.
    ///
    /// Days from 1970-01-01 to 1996-01-01: twenty six years of 365 days is
    /// 9490, plus one leap day each for 1972, 1976, 1980, 1984, 1988 and
    /// 1992, which is six. 1996 is a leap year and its leap day is 29
    /// February, after 1 January, so it does not count here. That is 9496.
    /// Days from 1996-01-01 to 1996-06-01: 31 + 29 + 31 + 30 + 31 = 152,
    /// giving 9648. Six more days to 1996-06-07 gives 9654.
    /// 9654 * 86400 = 834_105_600 for midnight, and 21:26:27 is
    /// 21 * 3600 + 26 * 60 + 27 = 77_187 seconds, so the instant is
    /// 834_182_787.
    ///
    /// The first version of this test said 9655 and 834_269_187, and the
    /// calendar answered `19960608212627Z`. The calendar was right.
    #[test]
    fn kerberos_time_matches_the_example_in_rfc_4120_section_5_2_3() {
        let t = KerberosTime::from_unix_seconds(834_182_787).expect("in range");
        assert_eq!(t.as_str(), "19960607212627Z");
        assert_eq!(t.to_unix_seconds(), 834_182_787);
    }

    /// The calendar round trips across every boundary that has ever broken a
    /// date routine: the epoch, the end of a leap year, the leap day of a
    /// century that is a leap year, and one that is not.
    #[test]
    fn the_calendar_round_trips_at_the_awkward_dates() {
        for (seconds, text) in [
            (0i64, "19700101000000Z"),
            (86_399, "19700101235959Z"),
            (951_782_400, "20000229000000Z"), // 2000 is a leap year
            (4_107_542_400, "21000301000000Z"), // 2100 is not
            (1_709_164_800, "20240229000000Z"),
            (2_147_483_647, "20380119031407Z"), // the 32 bit boundary
        ] {
            let t = KerberosTime::from_unix_seconds(seconds).expect("in range");
            assert_eq!(t.as_str(), text, "{seconds}");
            assert_eq!(t.to_unix_seconds(), seconds, "{text}");
        }
    }

    /// RFC 4120 §5.2.3 forbids a fractional part and requires the `Z` zone,
    /// and DER forbids the other `GeneralizedTime` forms outright.
    #[test]
    fn a_generalized_time_that_is_not_der_is_refused() {
        assert!(KerberosTime::parse(b"19960607212627Z").is_ok());
        assert!(KerberosTime::parse(b"19960607212627").is_err());
        assert!(KerberosTime::parse(b"19960607212627.5Z").is_err());
        assert!(KerberosTime::parse(b"19960607212627+0100").is_err());
        assert!(KerberosTime::parse(b"1996060721262Z").is_err());
        assert!(KerberosTime::parse(b"1996060721262aZ").is_err());
        assert!(KerberosTime::parse(b"").is_err());
        // Fifteen octets and a trailing Z, but the digits are not a date.
        assert!(KerberosTime::parse(b"19961307212627Z").is_err(), "month 13");
        assert!(KerberosTime::parse(b"19960600212627Z").is_err(), "day 0");
        assert!(KerberosTime::parse(b"19960607252627Z").is_err(), "hour 25");
        assert!(
            KerberosTime::parse(b"19960607216027Z").is_err(),
            "minute 60"
        );
        assert!(
            KerberosTime::parse(b"19960607212660Z").is_err(),
            "second 60"
        );
        // 1996 is a leap year, so 29 February exists; 1997 is not.
        assert!(KerberosTime::parse(b"19960229000000Z").is_ok());
        assert!(KerberosTime::parse(b"19970229000000Z").is_err());
        assert!(
            KerberosTime::parse(b"19960231000000Z").is_err(),
            "31 February"
        );
        assert!(KerberosTime::parse(b"19960431000000Z").is_err(), "31 April");
    }

    /// X.690's BIT STRING numbering, which is the opposite way round from a
    /// machine word and is the single easiest thing in `KDCOptions` to get
    /// backwards.
    #[test]
    fn kerberos_flags_number_bits_from_the_most_significant_end() {
        assert_eq!(kerberos_flags(&[0]), [0x80, 0, 0, 0]);
        assert_eq!(kerberos_flags(&[1]), [0x40, 0, 0, 0]);
        assert_eq!(kerberos_flags(&[8]), [0x00, 0x80, 0, 0]);
        assert_eq!(kerberos_flags(&[31]), [0, 0, 0, 0x01]);
        assert_eq!(
            kerberos_flags(&[
                kdc_option::FORWARDABLE,
                kdc_option::RENEWABLE,
                kdc_option::RENEWABLE_OK
            ]),
            [0x40, 0x80, 0x00, 0x10]
        );
        // Out of range bits are ignored rather than wrapping into a flag that
        // means something else.
        assert_eq!(kerberos_flags(&[32, 99]), [0, 0, 0, 0]);
    }

    /// X.690 §8.1.2.2: the application class is bits 01 and the constructed
    /// bit is 0x20, so `[APPLICATION 1]` is `0x61`.
    #[test]
    fn the_application_tags_are_the_ones_rfc_4120_uses() {
        assert_eq!(application(app::TICKET), 0x61);
        assert_eq!(application(app::AUTHENTICATOR), 0x62);
        assert_eq!(application(app::AS_REQ), 0x6a);
        assert_eq!(application(app::AS_REP), 0x6b);
        assert_eq!(application(app::TGS_REQ), 0x6c);
        assert_eq!(application(app::TGS_REP), 0x6d);
        assert_eq!(application(app::AP_REQ), 0x6e);
        assert_eq!(application(app::ENC_AS_REP_PART), 0x79);
        assert_eq!(application(app::ENC_TGS_REP_PART), 0x7a);
        assert_eq!(application(app::KRB_ERROR), 0x7e);
        // None of them reaches the multi byte tag form, which
        // `der::read_tlv` refuses.
        for n in [
            app::TICKET,
            app::AUTHENTICATOR,
            app::AS_REQ,
            app::AS_REP,
            app::TGS_REQ,
            app::TGS_REP,
            app::AP_REQ,
            app::ENC_AS_REP_PART,
            app::ENC_TGS_REP_PART,
            app::KRB_ERROR,
        ] {
            assert_ne!(application(n) & 0x1f, 0x1f, "APPLICATION {n}");
        }
    }

    /// A `PrincipalName` written here reads back as itself.
    #[test]
    fn a_principal_name_round_trips() {
        let mut out = Vec::new();
        write_principal_name(&mut out, name_type::SRV_HST, &["TERMSRV", "host.corp"]);
        let parsed = PrincipalName::read(&out).expect("round trip");
        assert_eq!(parsed.name_type, name_type::SRV_HST);
        assert_eq!(parsed.components, ["TERMSRV", "host.corp"]);
        assert_eq!(parsed.display(), "TERMSRV/host.corp");

        for cut in 0..out.len() {
            let prefix = out.get(..cut).expect("in range");
            assert!(PrincipalName::read(prefix).is_err(), "cut {cut}");
        }
    }

    /// RFC 4120 §5.2.9, and the `kvno [1]` we skip.
    #[test]
    fn encrypted_data_round_trips_and_skips_an_optional_kvno() {
        let mut out = Vec::new();
        write_encrypted_data(&mut out, Enctype::Aes256CtsHmacSha1_96, b"ciphertext");
        let parsed = EncryptedData::read(&out).expect("round trip");
        assert_eq!(parsed.etype, 18);
        assert_eq!(parsed.cipher, b"ciphertext");

        // The same structure with a kvno in the middle, which a KDC sends and
        // we never do.
        let mut with_kvno = Vec::new();
        write_nested(&mut with_kvno, tag::SEQUENCE, |seq| {
            write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, 18));
            write_nested(seq, context(1), |t| write_int(t, tag::INTEGER, 7));
            write_nested(seq, context(2), |t| {
                write_tlv(t, tag::OCTET_STRING, b"ciphertext");
            });
        });
        let parsed = EncryptedData::read(&with_kvno).expect("kvno is skipped");
        assert_eq!(parsed.etype, 18);
        assert_eq!(parsed.cipher, b"ciphertext");
    }

    /// RFC 4120 §5.2.7's note that "first tag is [1], not [0]", which is the
    /// one place in the document where the numbering does not start at zero.
    #[test]
    fn padata_starts_at_tag_one() {
        let mut out = Vec::new();
        write_nested(&mut out, tag::SEQUENCE, |list| {
            write_padata(list, padata_type::ENC_TIMESTAMP, b"value");
        });
        assert_eq!(
            out.get(4),
            Some(&context(1)),
            "PA-DATA's first field is [1] and not [0]"
        );
        let parsed = read_padata_list(&out).expect("round trip");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].padata_type, padata_type::ENC_TIMESTAMP);
        assert_eq!(parsed[0].value, b"value");
    }

    /// RFC 3962 §4's iteration count rules, read off `s2kparams`.
    #[test]
    fn the_iteration_count_follows_rfc_3962_section_4() {
        let entry = |params: Option<Vec<u8>>| EtypeInfo2Entry {
            etype: 18,
            salt: None,
            s2kparams: params,
        };
        // "If the string-to-key parameters are not supplied, the value used
        // is 00 00 10 00 (decimal 4,096)."
        assert_eq!(entry(None).iterations(), 4096);
        assert_eq!(entry(Some(vec![0, 0, 0x10, 0])).iterations(), 4096);
        assert_eq!(entry(Some(vec![0, 0, 0x04, 0xb0])).iterations(), 1200);
        // "If the value is 00 00 00 00, the number of iterations ... is
        // 4,294,967,296 (2**32)", which does not fit and is refused
        // downstream rather than silently becoming zero or one.
        assert_eq!(entry(Some(vec![0, 0, 0, 0])).iterations(), u32::MAX);
        // A malformed s2kparams falls back to the default rather than to a
        // guess.
        assert_eq!(entry(Some(vec![1, 2])).iterations(), 4096);
    }
}
