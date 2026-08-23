//! `TSRequest.errorCode`: the NTSTATUS values we translate, MS-CSSP 2.2.1 and
//! MS-ERREF 2.3.
//!
//! MS-CSSP 3.1.5: "If the SPNEGO handshake fails on the server side and the
//! client sent a version of 3 or greater, the server SHOULD send a TSRequest
//! structure back to the client for which the errorCode field is populated
//! with an unsuccessful NTSTATUS code. ... If the client receives a TSRequest
//! message with the errorCode present, it MUST immediately fail with the
//! provided status code and cease all further processing."
//!
//! This field is the difference between "authentication failed" and a
//! sentence that tells the user what to do, which is why it is worth a table
//! (PRDRDP/14 §3.10).
//!
//! ## What the table is for, and what it is not
//!
//! [`StatusKind`] is coarser than the symbol on purpose. The difference a
//! user can act on is "retype your password" against "an administrator has to
//! act", and that is a grouping of seventeen symbols into nine kinds. The
//! symbol itself goes in the `tracing` line and never in the sentence
//! (PRDRDP/14 §8.4).
//!
//! [`classify`] returning `None` is a real answer, not a gap. Windows has
//! hundreds of NTSTATUS values and this table has seventeen; an unrecognised
//! one is rendered as its hex value with the generic message and classed
//! [`Class::Fatal`], because we do not know that a retry is safe.
//!
//! ## Version note
//!
//! MS-CSSP 2.2.1 says the field is used "if the negotiated protocol version
//! is 3, 4, or 6", which leaves out 5, and footnote 12 says the field is not
//! implemented at all on Windows 8 and earlier. We do not gate on the version:
//! a present `errorCode` is honoured whatever version negotiated, because a
//! server that took the trouble to say why is telling the truth about a
//! failure it has already decided on.

use crate::error::Class;

/// The grouping a user can act on (PRDRDP/14 §3.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    /// The credentials were wrong. Ask again.
    AuthFailed,
    /// The credentials were right and policy says no.
    AccountRestricted,
    /// The password has to be changed on the remote computer first.
    PasswordMustChange,
    /// Too many attempts already.
    AccountLockedOut,
    /// No domain controller answered. Nothing about the account is known.
    DomainUnreachable,
    /// The two clocks disagree by more than Kerberos allows.
    ClockSkew,
    /// The remote computer wants a credential type we do not offer.
    Unsupported,
    /// The server refused the exchange as a possible downgrade attack.
    Downgrade,
    /// The account exists and may not sign in remotely.
    AccessDenied,
}

/// One row of the table.
pub struct NtStatus {
    /// The 32 bit value as it arrives in `errorCode`.
    pub code: u32,
    /// The MS-ERREF symbol. For the log line only (PRDRDP/14 §8.4).
    pub symbol: &'static str,
    /// The grouping.
    pub kind: StatusKind,
    /// PRDRDP/06 §4.3's class, which decides what the supervisor does.
    pub class: Class,
    /// The sentence the user reads. No symbol, no hex, no field name.
    pub message: &'static str,
}

/// The seventeen values of PRDRDP/14 §3.10, transcribed with their MS-ERREF
/// 2.3 codes.
///
/// One `Transient` row, and it is deliberate. PRDRDP/00 R46 stops the
/// supervisor retrying a stale password into a lockout, and
/// `STATUS_NO_LOGON_SERVERS` is not a statement about the account: no domain
/// controller answered, so nothing checked the password and no lockout
/// counter moved. Retrying is the right thing and it is safe. Every other row
/// is `User` or `Fatal`.
///
/// PRDRDP/14 §3.10 states both readings, one sentence apart ("Every one of
/// these is `User` or `Fatal`, never `Transient`", then
/// "`STATUS_NO_LOGON_SERVERS` is the one Transient entry"). Its own table
/// column says `Transient` and gives the reason, so the table is the half we
/// follow.
pub const TABLE: &[NtStatus] = &[
    NtStatus {
        code: 0xC000_006D,
        symbol: "STATUS_LOGON_FAILURE",
        kind: StatusKind::AuthFailed,
        class: Class::User,
        message: "The user name or password is incorrect.",
    },
    NtStatus {
        code: 0xC000_006A,
        symbol: "STATUS_WRONG_PASSWORD",
        kind: StatusKind::AuthFailed,
        class: Class::User,
        message: "The user name or password is incorrect.",
    },
    NtStatus {
        code: 0xC000_0064,
        symbol: "STATUS_NO_SUCH_USER",
        kind: StatusKind::AuthFailed,
        class: Class::User,
        message: "That account does not exist on the remote computer.",
    },
    NtStatus {
        code: 0xC000_006E,
        symbol: "STATUS_ACCOUNT_RESTRICTION",
        kind: StatusKind::AccountRestricted,
        class: Class::Fatal,
        message: "Policy on the remote computer does not allow this account to sign in.",
    },
    NtStatus {
        code: 0xC000_006F,
        symbol: "STATUS_INVALID_LOGON_HOURS",
        kind: StatusKind::AccountRestricted,
        class: Class::Fatal,
        message: "This account is not allowed to sign in at this time of day.",
    },
    NtStatus {
        code: 0xC000_0070,
        symbol: "STATUS_INVALID_WORKSTATION",
        kind: StatusKind::AccountRestricted,
        class: Class::Fatal,
        message: "This account is not allowed to sign in from this computer.",
    },
    NtStatus {
        code: 0xC000_0071,
        symbol: "STATUS_PASSWORD_EXPIRED",
        kind: StatusKind::PasswordMustChange,
        class: Class::Fatal,
        message: "The password has expired and must be changed on the remote computer.",
    },
    NtStatus {
        code: 0xC000_0072,
        symbol: "STATUS_ACCOUNT_DISABLED",
        kind: StatusKind::AccountRestricted,
        class: Class::Fatal,
        message: "That account is disabled.",
    },
    NtStatus {
        code: 0xC000_0193,
        symbol: "STATUS_ACCOUNT_EXPIRED",
        kind: StatusKind::AccountRestricted,
        class: Class::Fatal,
        message: "That account has expired.",
    },
    NtStatus {
        code: 0xC000_0224,
        symbol: "STATUS_PASSWORD_MUST_CHANGE",
        kind: StatusKind::PasswordMustChange,
        class: Class::Fatal,
        message: "The password must be changed before signing in.",
    },
    NtStatus {
        code: 0xC000_0234,
        symbol: "STATUS_ACCOUNT_LOCKED_OUT",
        kind: StatusKind::AccountLockedOut,
        class: Class::Fatal,
        message: "That account is locked out. Wait before trying again.",
    },
    NtStatus {
        code: 0xC000_015B,
        symbol: "STATUS_LOGON_TYPE_NOT_GRANTED",
        kind: StatusKind::AccountRestricted,
        class: Class::Fatal,
        message: "This account does not have permission to sign in remotely.",
    },
    NtStatus {
        code: 0xC000_005E,
        symbol: "STATUS_NO_LOGON_SERVERS",
        kind: StatusKind::DomainUnreachable,
        class: Class::Transient,
        message: "No domain controller could be reached.",
    },
    NtStatus {
        code: 0xC000_0133,
        symbol: "STATUS_TIME_DIFFERENCE_AT_DC",
        kind: StatusKind::ClockSkew,
        class: Class::Fatal,
        message: "The clocks on the two computers are too far apart.",
    },
    NtStatus {
        code: 0xC000_02FA,
        symbol: "STATUS_SMARTCARD_LOGON_REQUIRED",
        kind: StatusKind::Unsupported,
        class: Class::Fatal,
        message: "The remote computer requires a smart card.",
    },
    NtStatus {
        code: 0xC000_0388,
        symbol: "STATUS_DOWNGRADE_DETECTED",
        kind: StatusKind::Downgrade,
        class: Class::Fatal,
        message: "The remote computer refused the authentication as a possible downgrade attack.",
    },
    NtStatus {
        code: 0xC000_0022,
        symbol: "STATUS_ACCESS_DENIED",
        kind: StatusKind::AccessDenied,
        class: Class::Fatal,
        message: "That account is not allowed to sign in remotely.",
    },
];

/// The row for a status, or `None` for one we do not recognise.
#[must_use]
pub fn classify(code: u32) -> Option<&'static NtStatus> {
    TABLE.iter().find(|row| row.code == code)
}

/// True when the top bit is set, which MS-ERREF 2.3 makes the severity field
/// `STATUS_SEVERITY_ERROR`.
///
/// An `errorCode` of `0x00000000`, or any value with the top bit clear, is a
/// success indication and is ignored. Windows does not send one; a non
/// Microsoft server might (PRDRDP/14 §3.10).
#[must_use]
pub fn is_failure(code: u32) -> bool {
    code & 0x8000_0000 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_is_a_failure_code_and_a_sentence() {
        // Table driven, so a typo in a hex constant fails a test rather than
        // a support ticket (PRDRDP/14 §3.10).
        for row in TABLE {
            assert!(
                is_failure(row.code),
                "{} is not an unsuccessful NTSTATUS",
                row.symbol
            );
            assert!(row.symbol.starts_with("STATUS_"), "{}", row.symbol);
            assert!(
                row.message.ends_with('.'),
                "{} has no sentence: {}",
                row.symbol,
                row.message
            );
            assert!(
                !row.message.contains("STATUS_") && !row.message.contains("0x"),
                "{} leaks the symbol into the user message",
                row.symbol
            );
            assert_eq!(classify(row.code).map(|r| r.symbol), Some(row.symbol));
        }
    }

    #[test]
    fn no_code_appears_twice() {
        for (i, row) in TABLE.iter().enumerate() {
            for other in TABLE.iter().skip(i + 1) {
                assert_ne!(row.code, other.code, "{} and {}", row.symbol, other.symbol);
            }
        }
    }

    #[test]
    fn only_no_logon_servers_is_transient() {
        for row in TABLE {
            let expected = if row.symbol == "STATUS_NO_LOGON_SERVERS" {
                Class::Transient
            } else if row.kind == StatusKind::AuthFailed {
                Class::User
            } else {
                Class::Fatal
            };
            assert_eq!(row.class, expected, "{}", row.symbol);
        }
    }

    #[test]
    fn an_unknown_status_is_not_guessed_at() {
        assert!(classify(0xC000_0001).is_none());
        assert!(classify(0x0000_0000).is_none());
        assert!(!is_failure(0x0000_0000));
        assert!(!is_failure(0x4000_0000));
        assert!(is_failure(0xC000_0000));
        assert!(is_failure(0x8000_0000));
    }
}
