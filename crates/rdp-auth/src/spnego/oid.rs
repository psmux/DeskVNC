//! The mechanism OIDs, as DER OBJECT IDENTIFIER contents.
//!
//! Contents only, with no tag and no length, which is what
//! [`GssMechanism::oid`](crate::gss::GssMechanism::oid) returns and what a
//! comparison against a `mechType` from the wire is against. The writer adds
//! the `06 <len>` header (RFC 4178 §4.1, MS-SPNG 1.9).
//!
//! Every value here is transcribed from the arc it encodes and checked by the
//! test at the bottom, which decodes each one back to its dotted form. A
//! mistyped OID is a mechanism the server has never heard of, and the failure
//! is a `reject` with nothing to inspect.

/// SPNEGO itself, `1.3.6.1.5.5.2` (RFC 4178 §4.1). Goes in the
/// `InitialContextToken` wrapper, never in `mechTypes`.
pub const SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// Kerberos V5, `1.2.840.113554.1.2.2` (RFC 4121 §4.1).
pub const KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// Microsoft's legacy Kerberos OID, `1.2.840.48018.1.2.2` (MS-SPNG 1.9).
///
/// It means the same mechanism as [`KRB5`] and differs from it in one byte,
/// `0x82` against `0x86`, because 48018 and 113554 differ in their leading
/// base 128 digit. Windows lists this one first in its own `mechTypes` and
/// some Windows versions answer `supportedMech` with it, so a client that
/// recognises only [`KRB5`] concludes the server picked something unknown
/// (PRDRDP/14 §4.7).
pub const MS_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// NTLM, `1.3.6.1.4.1.311.2.2.10` (MS-SPNG 1.9). The same constant as
/// [`ntlm::NTLM_MECH_OID`](crate::ntlm::NTLM_MECH_OID).
pub const NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

/// The dotted form, for a log line and for the test below.
///
/// X.690 §8.19: the first octet encodes the first two arcs as `40 * a + b`,
/// and every later arc is base 128 with the continuation bit set on all but
/// the last octet. Returns `None` for a truncated or over long encoding.
#[must_use]
pub fn dotted(contents: &[u8]) -> Option<String> {
    let (first, rest) = contents.split_first()?;
    let mut out = format!("{}.{}", first / 40, first % 40);
    let mut value: u64 = 0;
    let mut pending = false;
    for byte in rest {
        value = value
            .checked_mul(128)?
            .checked_add(u64::from(byte & 0x7f))?;
        pending = true;
        if byte & 0x80 == 0 {
            out.push('.');
            out.push_str(&value.to_string());
            value = 0;
            pending = false;
        }
    }
    if pending {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_oid_decodes_to_the_arc_its_comment_names() {
        assert_eq!(dotted(SPNEGO).as_deref(), Some("1.3.6.1.5.5.2"));
        assert_eq!(dotted(KRB5).as_deref(), Some("1.2.840.113554.1.2.2"));
        assert_eq!(dotted(MS_KRB5).as_deref(), Some("1.2.840.48018.1.2.2"));
        assert_eq!(dotted(NTLMSSP).as_deref(), Some("1.3.6.1.4.1.311.2.2.10"));
    }

    #[test]
    fn the_two_kerberos_oids_differ_in_exactly_one_byte() {
        assert_eq!(KRB5.len(), MS_KRB5.len());
        let differences = KRB5.iter().zip(MS_KRB5).filter(|(a, b)| a != b).count();
        assert_eq!(differences, 1);
    }

    #[test]
    fn the_ntlm_oid_is_the_one_the_ntlm_module_already_has() {
        assert_eq!(NTLMSSP, crate::ntlm::NTLM_MECH_OID);
    }

    #[test]
    fn a_truncated_oid_does_not_decode() {
        // The last octet of a multi byte arc has its continuation bit clear,
        // so an encoding that ends mid arc is incomplete.
        assert_eq!(dotted(&[]), None);
        assert_eq!(dotted(&[0x2a, 0x86]), None);
    }
}
