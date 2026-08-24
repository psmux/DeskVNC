//! `KRB-ERROR.error-code`: the RFC 4120 §7.5.9 values we translate.
//!
//! The Kerberos half of what `credssp::nstatus` does for NTSTATUS. A KDC that
//! refuses a request says why in one integer, and the difference between
//! "authentication failed" and a sentence a user can act on is this table
//! (PRDRDP/14 §3.10 states the principle for the NTLM path; it is the same
//! principle).
//!
//! ## Why this module is not behind the `kerberos` feature
//!
//! [`AuthError`](crate::error::AuthError) is one enum for the whole crate and
//! it does not change shape with a feature. Cargo unifies features across a
//! dependency graph, so an enum whose variants appear and disappear with one
//! is an enum whose `match` arms have to be `cfg`ed at every call site in
//! `rdp-core`, for a variant that is unreachable rather than absent. So
//! [`AuthError::KdcRefused`](crate::error::AuthError::KdcRefused) exists in
//! every build and this table, which is a transcription of a published list
//! of integers and needs no cryptography, exists with it. Everything else
//! under `kerberos` is behind the feature.
//!
//! ## Why it does not reuse `nstatus::StatusKind`
//!
//! It would be the obvious reuse and it was considered. `StatusKind` groups
//! seventeen NTSTATUS values into the nine things a user can do about them,
//! and six of the codes below map onto it cleanly. Three do not:
//! `KDC_ERR_S_PRINCIPAL_UNKNOWN` (the domain has no Remote Desktop service
//! registered for that computer), `KRB_AP_ERR_TKT_EXPIRED` and
//! `KDC_ERR_WRONG_REALM` have no NTLM equivalent and no honest home in that
//! enum. Widening `StatusKind` for them would edit the NTLM path to serve the
//! Kerberos one, and forcing them into an existing variant would put a wrong
//! grouping in front of a user. This table carries the class and the sentence
//! directly, which is all either caller needs, and `StatusKind` is left
//! alone. If the shell ever groups the two mechanisms together, that is the
//! moment to unify them, with both tables in front of whoever does it.
//!
//! [`classify`] returning `None` is a real answer. RFC 4120 §7.5.9 assigns
//! about sixty codes and this table has fourteen; an unrecognised one is
//! rendered with the generic message and classed [`Class::Fatal`], because we
//! do not know that a retry is safe.

use crate::error::Class;

/// One row of the table.
pub struct KdcStatus {
    /// The value as it arrives in `KRB-ERROR.error-code` (RFC 4120 §5.9.1).
    pub code: i32,
    /// The RFC 4120 §7.5.9 symbol. For the log line only (PRDRDP/14 §8.4).
    pub symbol: &'static str,
    /// PRDRDP/06 §4.3's class, which decides what the supervisor does.
    pub class: Class,
    /// The sentence the user reads. No symbol, no number, no field name.
    pub message: &'static str,
}

/// The codes a Remote Desktop logon actually meets, transcribed from
/// RFC 4120 §7.5.9.
///
/// No row is [`Class::Transient`]. PRDRDP/00 R46: no failure that says
/// anything about an account may be retried automatically, because the retry
/// walks a stale password into a lockout. A KDC that does not answer at all
/// is a transport failure and never reaches this table.
pub const TABLE: &[KdcStatus] = &[
    KdcStatus {
        code: 6,
        symbol: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        class: Class::User,
        message: "That account does not exist in the domain.",
    },
    KdcStatus {
        code: 7,
        symbol: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        class: Class::Fatal,
        message: "The domain has no Remote Desktop service registered for that computer.",
    },
    KdcStatus {
        code: 11,
        symbol: "KDC_ERR_NEVER_VALID",
        class: Class::Fatal,
        message: "The domain controller rejected the requested ticket lifetime.",
    },
    KdcStatus {
        code: 12,
        symbol: "KDC_ERR_POLICY",
        class: Class::Fatal,
        message: "Policy in the domain does not allow this account to sign in.",
    },
    KdcStatus {
        code: 13,
        symbol: "KDC_ERR_BADOPTION",
        class: Class::Fatal,
        message:
            "The domain controller could not issue a ticket of the kind this connection needs.",
    },
    KdcStatus {
        code: 14,
        symbol: "KDC_ERR_ETYPE_NOSUPP",
        class: Class::Fatal,
        message: "The domain controller does not support AES Kerberos encryption.",
    },
    KdcStatus {
        code: 18,
        symbol: "KDC_ERR_CLIENT_REVOKED",
        class: Class::Fatal,
        message: "That account is disabled, locked out, or expired.",
    },
    KdcStatus {
        code: 23,
        symbol: "KDC_ERR_KEY_EXPIRED",
        class: Class::Fatal,
        message: "The password has expired and must be changed before signing in.",
    },
    KdcStatus {
        code: 24,
        symbol: "KDC_ERR_PREAUTH_FAILED",
        class: Class::User,
        message: "The user name or password is incorrect.",
    },
    // Not a failure in the ordinary run: it is how a KDC hands the client the
    // salt (RFC 4120 §3.1.1), and `kdc.rs` consumes it rather than raising
    // it. Reaching a user means it arrived a second time, after we had
    // already sent the pre-authentication it asked for, which is a KDC we
    // cannot satisfy.
    KdcStatus {
        code: 25,
        symbol: "KDC_ERR_PREAUTH_REQUIRED",
        class: Class::Fatal,
        message: "The domain controller asked for a form of sign in this client cannot provide.",
    },
    KdcStatus {
        code: 31,
        symbol: "KRB_AP_ERR_BAD_INTEGRITY",
        class: Class::User,
        message: "The user name or password is incorrect.",
    },
    KdcStatus {
        code: 32,
        symbol: "KRB_AP_ERR_TKT_EXPIRED",
        class: Class::Fatal,
        message: "The sign in took too long and has to be started again.",
    },
    // The skew path has its own variant, because the measured difference is
    // worth telling the user and a bare code is not. This row is what an
    // unexpected skew error outside that path renders as.
    KdcStatus {
        code: 37,
        symbol: "KRB_AP_ERR_SKEW",
        class: Class::Fatal,
        message: "The clocks on this computer and the domain controller are too far apart.",
    },
    KdcStatus {
        code: 52,
        symbol: "KRB_ERR_RESPONSE_TOO_BIG",
        class: Class::Fatal,
        message: "The domain controller's reply was too large for this connection.",
    },
    KdcStatus {
        code: 68,
        symbol: "KDC_ERR_WRONG_REALM",
        class: Class::Fatal,
        message: "That account belongs to a different domain from the one this computer is in.",
    },
];

/// The row for `code`, or `None` for one this table does not carry.
#[must_use]
pub fn classify(code: i32) -> Option<&'static KdcStatus> {
    TABLE.iter().find(|row| row.code == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PRDRDP/00 R46: nothing here is retried automatically.
    #[test]
    fn no_kdc_refusal_is_transient() {
        for row in TABLE {
            assert_ne!(row.class, Class::Transient, "{} is Transient", row.symbol);
        }
    }

    /// A duplicate row is a table where the second one is dead and nobody
    /// notices, which is how a wrong message ships.
    #[test]
    fn every_code_appears_once() {
        for (i, row) in TABLE.iter().enumerate() {
            for other in TABLE.iter().skip(i + 1) {
                assert_ne!(row.code, other.code, "{} is listed twice", row.symbol);
            }
        }
    }

    /// PRDRDP/14 §8.4: the symbol goes in the log line, never in the
    /// sentence, and a message is a sentence.
    #[test]
    fn a_message_is_a_sentence_and_never_names_a_symbol() {
        for row in TABLE {
            assert!(row.message.ends_with('.'), "{}", row.symbol);
            assert!(!row.message.contains("KDC_ERR"), "{}", row.symbol);
            assert!(!row.message.contains("KRB_AP"), "{}", row.symbol);
            assert!(
                !row.message.contains(&row.code.to_string()),
                "{} names its own number",
                row.symbol
            );
        }
    }

    /// The codes RFC 4120 §7.5.9 assigns to the outcomes this client acts on,
    /// spot checked against the section's own table so a transposed digit
    /// fails here rather than producing a confident wrong sentence.
    #[test]
    fn the_codes_are_the_ones_rfc_4120_assigns() {
        let symbol = |code: i32| classify(code).map(|r| r.symbol);
        assert_eq!(symbol(6), Some("KDC_ERR_C_PRINCIPAL_UNKNOWN"));
        assert_eq!(symbol(7), Some("KDC_ERR_S_PRINCIPAL_UNKNOWN"));
        assert_eq!(symbol(14), Some("KDC_ERR_ETYPE_NOSUPP"));
        assert_eq!(symbol(24), Some("KDC_ERR_PREAUTH_FAILED"));
        assert_eq!(symbol(25), Some("KDC_ERR_PREAUTH_REQUIRED"));
        assert_eq!(symbol(37), Some("KRB_AP_ERR_SKEW"));
        assert_eq!(symbol(52), Some("KRB_ERR_RESPONSE_TOO_BIG"));
        // 0 is KDC_ERR_NONE, "no error", which never arrives in a KRB-ERROR.
        assert_eq!(symbol(0), None);
        assert_eq!(symbol(-1), None);
    }
}
