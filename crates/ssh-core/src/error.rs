//! Terminal-session failures, classified for the supervisor.
//!
//! The carrier's own failures arrive as [`ssh_transport::Error`] and keep
//! their classification; what this adds is the handful of things that can go
//! wrong *after* there is a connection: the server refusing a PTY, the shell
//! dying, a session name that is not fit to put on a command line.

use remote_core::reconnect::RetryClassify;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Anything the SSH carrier itself reported.
    #[error(transparent)]
    Transport(#[from] ssh_transport::Error),

    /// The server would not give us a PTY.
    ///
    /// Almost always a locked-down account (`command=` in `authorized_keys`,
    /// or `PermitTTY no`), which no amount of retrying will change.
    #[error("the ssh server refused a pty: {0}")]
    PtyRefused(String),

    /// The server accepted the channel but refused to start a shell or the
    /// requested command.
    #[error("the ssh server refused to start a shell: {0}")]
    ShellRefused(String),

    /// The remote shell exited. Not a failure in itself, a user typing
    /// `exit` produces one, and the supervisor treats it as a clean end
    /// rather than something to reconnect around.
    #[error("the remote shell exited with status {0}")]
    ShellExited(u32),

    /// The link stopped answering. This is the hang that plain `ssh` leaves
    /// you sitting in front of, caught by the keepalive probes instead.
    #[error("the connection stopped responding")]
    Unresponsive,

    /// Bad configuration, caught before it reached the network.
    #[error("{0}")]
    Config(String),

    /// The session was torn down deliberately.
    #[error("the session was cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// True for the two host-key outcomes the UI renders as a fingerprint
    /// dialog rather than an error toast.
    pub fn is_host_key_issue(&self) -> bool {
        matches!(self, Error::Transport(e) if e.is_host_key_issue())
    }
}

/// How the supervisor should treat each failure.
///
/// The interesting entries are [`Error::Unresponsive`], which is transient by
/// definition (the whole point of detecting a hang is to reconnect through
/// it), and [`Error::PtyRefused`], which is not: a server configured to deny
/// PTYs will deny the next one identically, and retrying just hammers it.
impl RetryClassify for Error {
    fn is_cancelled(&self) -> bool {
        matches!(self, Error::Cancelled)
    }

    fn is_transient(&self) -> bool {
        match self {
            Error::Transport(e) => e.is_transient(),
            // A hang and a dropped shell are exactly what auto-reconnect is
            // for. With a multiplexer on the far side the user does not even
            // lose their work.
            Error::Unresponsive | Error::ShellRefused(_) => true,
            Error::ShellExited(_)
            | Error::PtyRefused(_)
            | Error::Config(_)
            | Error::Cancelled
            | Error::Other(_) => false,
        }
    }

    fn needs_user_action(&self) -> bool {
        match self {
            Error::Transport(e) => e.needs_user_action(),
            // Someone has to change the server's config or the session name;
            // no retry will do it for them.
            Error::PtyRefused(_) | Error::Config(_) => true,
            _ => false,
        }
    }

    fn user_message(&self) -> String {
        self.to_string()
    }

    fn symbol(&self) -> Option<&'static str> {
        match self {
            Error::Transport(e) => e.symbol(),
            Error::PtyRefused(_) => Some("ssh-pty-refused"),
            Error::ShellRefused(_) => Some("ssh-shell-refused"),
            Error::ShellExited(_) => Some("ssh-shell-exited"),
            Error::Unresponsive => Some("ssh-unresponsive"),
            Error::Config(_) => Some("ssh-bad-config"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::options::ReconnectPolicy;
    use remote_core::reconnect::{classify, Decision};

    /// The hang this whole module exists to catch must lead to a reconnect,
    /// not to a stopped session. If this ever flips, a frozen link becomes a
    /// dead window instead of a blip.
    #[test]
    fn an_unresponsive_link_is_retried() {
        let policy = ReconnectPolicy::default();
        assert_eq!(
            classify(&Error::Unresponsive, &policy, 0),
            Decision::Retry,
            "a detected hang must reconnect"
        );
    }

    /// A server that denies PTYs denies them every time. Retrying is a loop
    /// that never terminates and never tells the user what is wrong.
    #[test]
    fn a_refused_pty_stops_the_session_instead_of_looping() {
        let policy = ReconnectPolicy::default();
        assert_eq!(
            classify(&Error::PtyRefused("PermitTTY no".into()), &policy, 0),
            Decision::Stop { can_retry: false }
        );
    }

    /// Typing `exit` is not a network failure. Reconnecting the user into a
    /// shell they deliberately closed would be maddening.
    #[test]
    fn a_shell_the_user_exited_is_not_reconnected() {
        let policy = ReconnectPolicy::default();
        assert_eq!(
            classify(&Error::ShellExited(0), &policy, 0),
            Decision::Stop { can_retry: true }
        );
    }

    /// A changed host key is a hard stop wherever it appears, and it appears
    /// here by way of the carrier.
    #[test]
    fn a_changed_host_key_survives_the_conversion_as_a_hard_stop() {
        let e = Error::from(ssh_transport::Error::HostKeyChanged {
            host: "h".into(),
            port: 22,
            expected: "SHA256:a".into(),
            actual: "SHA256:b".into(),
        });
        assert!(e.is_host_key_issue());
        assert!(e.needs_user_action());
        assert!(!e.is_transient());
        assert_eq!(
            classify(&e, &ReconnectPolicy::default(), 0),
            Decision::Stop { can_retry: false }
        );
    }

    /// A dropped socket is the ordinary case: reconnect, quietly.
    #[test]
    fn a_dropped_socket_is_retried() {
        let e = Error::from(ssh_transport::Error::Ssh("broken pipe".into()));
        assert_eq!(
            classify(&e, &ReconnectPolicy::default(), 0),
            Decision::Retry
        );
    }

    #[test]
    fn no_error_is_classified_both_ways() {
        let cases = [
            Error::Unresponsive,
            Error::PtyRefused("x".into()),
            Error::ShellRefused("x".into()),
            Error::ShellExited(1),
            Error::Config("x".into()),
            Error::Cancelled,
            Error::from(ssh_transport::Error::Timeout),
        ];
        for e in cases {
            assert!(
                !(e.is_transient() && e.needs_user_action()),
                "{e} is classified both ways"
            );
        }
    }
}
