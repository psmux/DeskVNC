//! The error type, its four way class, and the sentence a user reads.
//!
//! PRDRDP/06 §4.3 is the authority for the class (R32); PRDRDP/14 §6.4 says
//! which authentication outcome falls in which class and why. `rdp-core`
//! converts through one `From` impl, so this crate depends on neither
//! `remote-core` nor `vnc-core`.
//!
//! ## No variant carries remote bytes
//!
//! Every variant is a unit variant, carries a `&'static str`, or carries the
//! four byte NTSTATUS the server put in `TSRequest.errorCode`. That is
//! deliberate and PRDRDP/00 R63 settles it as a rule rather than advice: an
//! error variant that carries "the token we could not parse" for debugging
//! will happily carry an `authInfo` blob into a log file (PRDRDP/14 §8.3). A
//! `&'static str` is a literal in this source file and cannot hold a secret.
//! Offsets, lengths and hex go in the `tracing` event beside the failure.
//!
//! The one exception is [`AuthError::ServerStatus`], and it is an exception
//! for a stated reason: MS-CSSP 3.1.5 says the client "MUST immediately fail
//! with the provided status code", the table in `credssp::nstatus` covers
//! seventeen values and Windows has hundreds, so a code we do not recognise
//! still has to reach the user as a hex number. Four bytes of status cannot
//! hold a token, a key or a password, which is the property R63 exists to
//! preserve.

/// The four way error class of PRDRDP/06 §4.3 (R32).
///
/// No failure that says anything about an account is ever `Transient` (R46),
/// so the session supervisor stops rather than retrying a stale password into
/// a lockout. The one `Transient` outcome in the crate is
/// `STATUS_NO_LOGON_SERVERS` reaching us through
/// [`AuthError::ServerStatus`]: no domain controller answered, so no password
/// was checked and no lockout counter moved (PRDRDP/14 §3.10).
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

    /// `TSRequest.errorCode`, MS-CSSP 2.2.1 and MS-ERREF 2.3. An unsuccessful
    /// NTSTATUS, kept verbatim. The table is `credssp::nstatus`
    /// (PRDRDP/14 §3.10).
    #[error("the remote computer refused the sign in with status {0:#010x}")]
    ServerStatus(u32),

    /// The server's `pubKeyAuth` did not match what we computed
    /// (MS-CSSP 3.1.5 step 5). An interception indicator, and a different
    /// thing from an authentication failure.
    ///
    /// A unit variant with no offset and no payload: an offset that exists
    /// only for a log line is a forgery oracle's other half
    /// (PRDRDP/00 R63, PRDRDP/14 §8.1).
    #[error("the remote computer did not prove it holds the certificate's private key")]
    PublicKeyMismatch,

    /// The remote computer rejected the sign in and said nothing else: no
    /// `pubKeyAuth`, no `errorCode` (PRDRDP/14 §3.11).
    #[error("the remote computer rejected the sign in without saying why")]
    AuthFailed,

    /// The server's CredSSP version is below the lowest we will complete
    /// against, which is 2 (PRDRDP/14 §8.7).
    #[error("the remote computer's authentication is too old to be used safely")]
    UnsupportedCredSspVersion,

    /// The server refused every mechanism we offered, or picked one we did
    /// not offer (RFC 4178 §4.2.2, PRDRDP/14 §4.4).
    #[error("the remote computer refused every authentication mechanism we offered")]
    NoCommonMechanism,

    /// More negotiation rounds than any real mechanism needs
    /// (PRDRDP/14 §3.13).
    #[error("the authentication exchange did not finish")]
    TooManyRounds,
}

impl AuthError {
    /// Which of PRDRDP/06 §4.3's four classes this outcome falls in.
    #[must_use]
    pub fn class(self) -> Class {
        match self {
            // The overwhelmingly likely cause of a bare rejection is a wrong
            // password, and we want the credential prompt back rather than a
            // red banner (PRDRDP/14 §3.11).
            AuthError::NoUserName | AuthError::AuthFailed => Class::User,
            // The one place a class comes from the wire. Every row of the
            // table is `User` or `Fatal` except `STATUS_NO_LOGON_SERVERS`,
            // which is `Transient` because no domain controller answered, so
            // nothing checked the password and no lockout counter moved.
            AuthError::ServerStatus(code) => {
                crate::credssp::nstatus::classify(code).map_or(Class::Fatal, |row| row.class)
            }
            AuthError::MalformedMessage(_)
            | AuthError::LegacyServerRefused
            | AuthError::UnexpectedToken
            | AuthError::ContextNotEstablished
            | AuthError::MessageOutOfSequence
            | AuthError::SignatureMismatch
            | AuthError::AlreadyFailed
            | AuthError::PublicKeyMismatch
            | AuthError::UnsupportedCredSspVersion
            | AuthError::NoCommonMechanism
            | AuthError::TooManyRounds => Class::Fatal,
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
            AuthError::PublicKeyMismatch => {
                "The remote computer could not prove it is the computer its certificate names. \
                 The connection may be intercepted."
                    .to_owned()
            }
            AuthError::AuthFailed => {
                "The remote computer rejected the sign in and did not say why. The user name or \
                 password is probably wrong."
                    .to_owned()
            }
            AuthError::UnsupportedCredSspVersion => {
                "The remote computer's authentication is too old to be used safely.".to_owned()
            }
            AuthError::NoCommonMechanism => {
                "The remote computer refused every way this client can sign in.".to_owned()
            }
            AuthError::TooManyRounds => {
                "The remote computer did not finish the sign in.".to_owned()
            }
            // The hex code is appended for a status we do not recognise, so a
            // support ticket carries something searchable. The symbol never
            // appears here; it goes in the log line (PRDRDP/14 §8.4).
            AuthError::ServerStatus(code) => crate::credssp::nstatus::classify(code).map_or_else(
                || format!("The remote computer refused the sign in ({code:#010x})."),
                |row| row.message.to_owned(),
            ),
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
    /// `None` for everything except [`AuthError::ServerStatus`], and `None`
    /// for a status the table in `credssp::nstatus` does not carry
    /// (MS-CSSP 2.2.1, PRDRDP/14 §3.10). The symbol never reaches a user
    /// message (§8.4).
    #[must_use]
    pub fn nt_status_symbol(self) -> Option<&'static str> {
        match self {
            AuthError::ServerStatus(code) => {
                crate::credssp::nstatus::classify(code).map(|row| row.symbol)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_authentication_failure_is_transient() {
        // R46: the supervisor must never retry a stale password into a lockout.
        // `ServerStatus` is excluded and tested by `credssp::nstatus`, which
        // owns the one Transient row and the reason it is safe.
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
