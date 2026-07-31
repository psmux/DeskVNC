//! Crate error type. Nothing in `vnc-files` panics: every fallible path ends
//! up here and the Tauri layer stringifies it for the webview.
//!
//! The endpoint in a message goes through [`host_port`] rather than a plain
//! `{host}:{port}`, so an IPv6 host reads as `[::1]:22` and the user can see
//! where the address stops and the port starts.

use crate::config::host_port;

/// Everything that can go wrong in the SFTP sidecar.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ssh error: {0}")]
    Ssh(String),

    #[error("sftp error: {0}")]
    Sftp(String),

    #[error("could not connect to {}: {reason}", host_port(host, *port))]
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

    /// First contact with this host: the UI must show a TOFU prompt and, if
    /// the user accepts, persist the pin and reconnect.
    #[error("the ssh host key for {} is not yet trusted", host_port(host, *port))]
    HostKeyUnknown {
        host: String,
        port: u16,
        key_type: String,
        fingerprint: String,
    },

    /// HARD STOP (PRD/08 §4, PRD/10 §4.3). Never retried, never promptable.
    #[error(
        "the ssh host key for {} CHANGED (expected {expected}, got {actual}), \
         refusing to connect",
        host_port(host, *port)
    )]
    HostKeyChanged {
        host: String,
        port: u16,
        expected: String,
        actual: String,
    },

    #[error("the ssh host key was rejected")]
    HostKeyRejected,

    /// A path failed the traversal/normalisation checks in [`crate::path`].
    /// Server-supplied listings are untrusted input; this is the wall.
    #[error("unsafe path rejected: {0}")]
    UnsafePath(String),

    #[error("no file-transfer session for {0}")]
    NotConnected(String),

    #[error("transfer cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// True for the two host-key outcomes the UI has to render specially.
    pub fn is_host_key_issue(&self) -> bool {
        matches!(
            self,
            Error::HostKeyUnknown { .. } | Error::HostKeyChanged { .. }
        )
    }

    pub(crate) fn ssh(e: impl std::fmt::Display) -> Self {
        Error::Ssh(e.to_string())
    }

    pub(crate) fn sftp(e: impl std::fmt::Display) -> Self {
        Error::Sftp(e.to_string())
    }
}
