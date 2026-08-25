//! Failures of the SSH carrier itself.
//!
//! Everything here is about getting a authenticated connection to a machine.
//! What a caller then *does* with the connection (SFTP, a `direct-tcpip`
//! channel, a shell) has its own error type, which converts from this one.
//!
//! Endpoints in messages go through [`crate::config::host_port`] so an IPv6
//! address reads `[::1]:22` and not `::1:22`.

/// Something went wrong bringing up or using the SSH carrier.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ssh error: {0}")]
    Ssh(String),

    #[error("could not connect to {}: {reason}", crate::config::host_port(.host, *.port))]
    Connect {
        host: String,
        port: u16,
        reason: String,
    },

    #[error("connection timed out")]
    Timeout,

    #[error("ssh authentication failed for user {user}")]
    Auth { user: String },

    #[error("could not read ssh key {path}: {reason}")]
    Key { path: String, reason: String },

    #[error("no ssh agent is available: {0}")]
    Agent(String),

    /// Trust-on-first-use: we have never seen this machine before. The shell
    /// prompts, persists the pin, and retries. Not a failure in itself.
    #[error("unknown ssh host key for {}: {key_type} {fingerprint}", crate::config::host_port(.host, *.port))]
    HostKeyUnknown {
        host: String,
        port: u16,
        key_type: String,
        fingerprint: String,
    },

    /// The machine's key is not the one we pinned. This is a **hard stop**
    /// with no "continue anyway" path: either the machine was rebuilt, or
    /// something is sitting in the middle of the connection, and we cannot
    /// tell which. The user has to remove the pin deliberately.
    #[error(
        "the ssh host key for {} changed (expected {expected}, got {actual})",
        crate::config::host_port(.host, *.port)
    )]
    HostKeyChanged {
        host: String,
        port: u16,
        expected: String,
        actual: String,
    },

    /// The user saw the fingerprint prompt and said no.
    #[error("the ssh host key was rejected")]
    HostKeyRejected,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// The two variants the UI renders as a fingerprint dialog rather than as
    /// an error toast.
    pub fn is_host_key_issue(&self) -> bool {
        matches!(
            self,
            Error::HostKeyUnknown { .. } | Error::HostKeyChanged { .. }
        )
    }

    /// Could another attempt plausibly get past this?
    ///
    /// Drives the auto-reconnect supervisor in `ssh-core`. A refused dial or
    /// a timeout is worth retrying; a wrong password or a changed host key
    /// will fail identically every time until a human intervenes, and
    /// retrying those just locks the account out or spams the prompt.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Error::Io(_) | Error::Ssh(_) | Error::Connect { .. } | Error::Timeout
        )
    }

    /// Will this keep happening until a human does something?
    pub fn needs_user_action(&self) -> bool {
        matches!(
            self,
            Error::Auth { .. }
                | Error::Key { .. }
                | Error::Agent(_)
                | Error::HostKeyUnknown { .. }
                | Error::HostKeyChanged { .. }
                | Error::HostKeyRejected
        )
    }

    /// A stable identifier for this failure, for a UI that wants to match on
    /// the *kind* of problem and supply its own sentence. Matching on the
    /// message instead makes every copy edit a silent behaviour change.
    pub fn symbol(&self) -> Option<&'static str> {
        Some(match self {
            Error::Timeout => "ssh-timeout",
            Error::Auth { .. } => "ssh-auth-failed",
            Error::Key { .. } => "ssh-key-unreadable",
            Error::Agent(_) => "ssh-agent-unavailable",
            Error::HostKeyUnknown { .. } => "ssh-host-key-unknown",
            Error::HostKeyChanged { .. } => "ssh-host-key-changed",
            Error::HostKeyRejected => "ssh-host-key-rejected",
            Error::Connect { .. } => "ssh-connect-failed",
            _ => return None,
        })
    }

    /// Construct an [`Error::Ssh`] from anything printable.
    ///
    /// Public, unlike the `pub(crate)` constructor this replaces: crates
    /// building on the carrier need to report russh failures of their own
    /// (opening a channel, requesting a PTY) in the same shape.
    pub fn ssh(e: impl std::fmt::Display) -> Self {
        Error::Ssh(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three classifications must partition cleanly enough that the
    /// supervisor never both retries and stops on the same failure.
    #[test]
    fn no_error_is_both_transient_and_in_need_of_a_human() {
        let cases = [
            Error::Timeout,
            Error::Auth { user: "u".into() },
            Error::Agent("none".into()),
            Error::HostKeyRejected,
            Error::Connect {
                host: "h".into(),
                port: 22,
                reason: "refused".into(),
            },
            Error::Ssh("broken pipe".into()),
        ];
        for e in cases {
            assert!(
                !(e.is_transient() && e.needs_user_action()),
                "{e} is classified both ways"
            );
        }
    }

    #[test]
    fn a_changed_host_key_is_never_retried() {
        let e = Error::HostKeyChanged {
            host: "h".into(),
            port: 22,
            expected: "SHA256:aaa".into(),
            actual: "SHA256:bbb".into(),
        };
        assert!(!e.is_transient());
        assert!(e.needs_user_action());
        assert!(e.is_host_key_issue());
    }

    /// An IPv6 endpoint has to stay readable in the message, otherwise the
    /// host and the port cannot be told apart in a log.
    #[test]
    fn an_ipv6_endpoint_is_bracketed_in_the_message() {
        let e = Error::Connect {
            host: "::1".into(),
            port: 22,
            reason: "refused".into(),
        };
        assert!(e.to_string().contains("[::1]:22"), "{e}");
    }
}
