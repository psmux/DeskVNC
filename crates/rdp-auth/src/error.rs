//! The error type, its four way class, and the sentence a user reads.
//!
//! PRDRDP/06 §4.3 is the authority for the class (R32); PRDRDP/14 §6.4 says
//! which authentication outcome falls in which class and why. `rdp-core`
//! converts through one `From` impl, so this crate depends on neither
//! `remote-core` nor `vnc-core`.
//!
//! ## No variant carries remote bytes
//!
//! Every variant is either a unit variant or carries a `&'static str`. That is
//! deliberate and PRDRDP/00 R63 settles it as a rule rather than advice: an
//! error variant that carries "the token we could not parse" for debugging
//! will happily carry an `authInfo` blob into a log file (PRDRDP/14 §8.3). A
//! `&'static str` is a literal in this source file and cannot hold a secret.
//! Offsets, lengths and hex go in the `tracing` event beside the failure.

/// The four way error class of PRDRDP/06 §4.3 (R32).
///
/// An authentication failure is never `Transient` (R46), so the session
/// supervisor stops rather than retrying a stale password into a lockout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Worth retrying on its own. No authentication outcome is ever this.
    Transient,
    /// The connection cannot proceed and retrying will not help.
    Fatal,
    /// The user can fix it, usually by typing a different password.
    User,
    /// A normal end, not a failure.
    Expected,
}

/// Everything that can go wrong inside `rdp-auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// A message from the peer did not parse. The `&'static str` names the
    /// field, never its contents.
    #[error("the authentication message was malformed: {0}")]
    MalformedMessage(&'static str),

    /// The peer asked for a construction we refuse: NTLMv1, no extended
    /// session security, no `MsvAvTimestamp`, or the OEM codepage path
    /// (MS-NLMP 3.1.5.1.2, PRDRDP/14 §8.5).
    #[error("the remote computer asked for an outdated form of authentication")]
    LegacyServerRefused,

    /// A token arrived in a state that has nothing to do with it, or a third
    /// NTLM message arrived when there are only ever two rounds.
    #[error("an unexpected authentication token arrived")]
    UnexpectedToken,

    /// `wrap`, `unwrap`, `mic` or `verify_mic` was called before the context
    /// was established. This is the check that stops a coding error in the
    /// CredSSP layer from encrypting the password under a key nobody agreed.
    #[error("the authentication context is not established yet")]
    ContextNotEstablished,

    /// The sequence number in a signature did not match the one we expected
    /// (MS-NLMP 3.4.4).
    #[error("an authentication message arrived out of sequence")]
    MessageOutOfSequence,

    /// A MAC did not verify. Compared through `subtle`; the variant carries no
    /// offset, because an offset that exists only for a log line is a forgery
    /// oracle's other half (PRDRDP/14 §8.1).
    #[error("the signature on an authentication message did not verify")]
    SignatureMismatch,

    /// No user name was supplied. Anonymous authentication is refused
    /// (PRDRDP/14 §8.5).
    #[error("a user name is required")]
    NoUserName,

    /// The state machine has already failed. Calling `step` again returns this
    /// rather than restarting.
    #[error("the authentication exchange already failed")]
    AlreadyFailed,
}

impl AuthError {
    /// Which of PRDRDP/06 §4.3's four classes this outcome falls in.
    #[must_use]
    pub fn class(self) -> Class {
        match self {
            AuthError::NoUserName => Class::User,
            AuthError::MalformedMessage(_)
            | AuthError::LegacyServerRefused
            | AuthError::UnexpectedToken
            | AuthError::ContextNotEstablished
            | AuthError::MessageOutOfSequence
            | AuthError::SignatureMismatch
            | AuthError::AlreadyFailed => Class::Fatal,
        }
    }

    /// The sentence the user reads.
    ///
    /// It never contains a token, a hash, a hex dump or an NTSTATUS symbol.
    /// The symbol goes in the log line (PRDRDP/14 §6.4, §8.4).
    #[must_use]
    pub fn user_message(self) -> String {
        match self {
            AuthError::NoUserName => "A user name is required to sign in.".to_owned(),
            AuthError::LegacyServerRefused => {
                "The remote computer asked for an outdated form of authentication that is not \
                 safe to use."
                    .to_owned()
            }
            AuthError::SignatureMismatch | AuthError::MessageOutOfSequence => {
                "The remote computer's authentication could not be verified. The connection may \
                 be intercepted."
                    .to_owned()
            }
            AuthError::MalformedMessage(_)
            | AuthError::UnexpectedToken
            | AuthError::ContextNotEstablished
            | AuthError::AlreadyFailed => {
                "The remote computer sent an authentication message this client could not use."
                    .to_owned()
            }
        }
    }

    /// The NTSTATUS symbol behind this failure, for the log line only.
    ///
    /// Always `None` in phase 1a. The values come from the CredSSP
    /// `errorCode` field and the table lives in `credssp::nstatus`
    /// (MS-CSSP 2.2.1, PRDRDP/14 §3.10), which is not written yet.
    #[must_use]
    pub fn nt_status_symbol(self) -> Option<&'static str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_authentication_failure_is_transient() {
        // R46: the supervisor must never retry a stale password into a lockout.
        for e in [
            AuthError::MalformedMessage("field"),
            AuthError::LegacyServerRefused,
            AuthError::UnexpectedToken,
            AuthError::ContextNotEstablished,
            AuthError::MessageOutOfSequence,
            AuthError::SignatureMismatch,
            AuthError::NoUserName,
            AuthError::AlreadyFailed,
        ] {
            assert_ne!(e.class(), Class::Transient, "{e:?} was classed Transient");
        }
    }
}
