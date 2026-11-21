//! Error types for the VNC core.
//!
//! `VncError::is_transient()` drives the auto-reconnect policy described in
//! PRD/05-session-ux.md §6.1: transient failures are retried automatically,
//! fatal ones stop the session and surface to the user.

use std::io;

/// Result alias used throughout the core.
pub type Result<T> = std::result::Result<T, VncError>;

#[derive(Debug, thiserror::Error)]
pub enum VncError {
    // ---- transport / transient -------------------------------------------
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("connection closed by peer")]
    ConnectionClosed,

    #[error("connection timed out")]
    Timeout,

    #[error("connection refused by {0}")]
    ConnectionRefused(String),

    #[error("dns resolution failed for {0}")]
    ResolveFailed(String),

    // ---- protocol --------------------------------------------------------
    #[error("unsupported RFB protocol version: {0}")]
    UnsupportedVersion(String),

    #[error("malformed protocol data: {0}")]
    Protocol(String),

    #[error("unsupported encoding: {0}")]
    UnsupportedEncoding(i32),

    #[error("decoder error in {encoding}: {message}")]
    Decode {
        encoding: &'static str,
        message: String,
    },

    // ---- security --------------------------------------------------------
    #[error("no mutually supported security type (server offered: {0:?})")]
    NoSupportedSecurityType(Vec<u8>),

    #[error("unsupported security type: {0}")]
    UnsupportedSecurityType(u8),

    /// Authentication was rejected by the server. NEVER auto-retried.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// The server accepted the credentials but refused this account access.
    /// NEVER auto-retried, and asking for the password again would not help.
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// The encrypted handshake failed before any credential was sent: the
    /// server hung up during the key exchange or could not prove it holds
    /// its key. Never a verdict on the user name or password, so it must not
    /// be shown as one, and never retried, since the same server does the
    /// same thing again.
    #[error("key exchange failed: {0}")]
    KeyExchange(String),

    /// Credentials are required but were not supplied (prompt the user).
    #[error("credentials required: {0}")]
    CredentialsRequired(String),

    #[error("tls error: {0}")]
    Tls(String),

    /// The server's only VeNCrypt subtypes are the anonymous TLS ones
    /// (TLSNone, TLSVnc, TLSPlain), which rustls cannot complete. It is
    /// raised after the client has committed to VeNCrypt, so the session
    /// tries once more on a fresh connection without VeNCrypt when the server
    /// offered anything else beside it (`session::connection`).
    #[error(
        "the server offers only anonymous TLS (VeNCrypt TLSNone, TLSVnc or TLSPlain), \
         which DeskVNC cannot use; add VncAuth, X509Vnc or RA2 to its SecurityTypes"
    )]
    AnonymousTlsOnly,

    /// Server certificate fingerprint differs from the pinned one.
    /// Hard stop, never auto-retried (PRD/10 §4.3).
    #[error("server identity changed: expected {expected}, got {actual}")]
    CertificateMismatch { expected: String, actual: String },

    #[error("server certificate not trusted: {0}")]
    CertificateUntrusted(String),

    // ---- lifecycle -------------------------------------------------------
    #[error("session cancelled by user")]
    Cancelled,

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("{0}")]
    Other(String),
}

/// A closed event sink means the shell went away, which unwinds the session
/// through the same path a cancellation does. This `From` is what keeps the
/// forty `emit(..).await?` call sites in `connection.rs` and `run_loop.rs` a
/// zero line diff across the remote-core extraction (PRDRDP/02 §11.1).
impl From<remote_core::EventSinkClosed> for VncError {
    fn from(_: remote_core::EventSinkClosed) -> Self {
        VncError::Cancelled
    }
}

/// The session task is gone. `SessionHandle::send` used to report this as
/// `ConnectionClosed`, so it still does.
impl From<remote_core::SessionGone> for VncError {
    fn from(_: remote_core::SessionGone) -> Self {
        VncError::ConnectionClosed
    }
}

impl VncError {
    /// Whether the auto-reconnect loop should retry after this error.
    ///
    /// Auth failures, certificate mismatches, unsupported protocol features and
    /// user cancellation are terminal; everything network-shaped is transient.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            VncError::Io(_)
                | VncError::ConnectionClosed
                | VncError::Timeout
                | VncError::ConnectionRefused(_)
                | VncError::ResolveFailed(_)
        )
    }

    /// Whether this error requires user interaction before any retry.
    pub fn needs_user_action(&self) -> bool {
        matches!(
            self,
            VncError::AuthFailed(_)
                | VncError::AccessDenied(_)
                | VncError::CredentialsRequired(_)
                | VncError::CertificateMismatch { .. }
                | VncError::CertificateUntrusted(_)
        )
    }

    /// Short, user-facing explanation with a suggested next step.
    pub fn user_message(&self) -> String {
        match self {
            VncError::ConnectionRefused(addr) => format!(
                "Connection refused by {addr}. The VNC server may not be running on that port."
            ),
            VncError::Timeout => {
                "The computer did not respond. It may be asleep or unreachable.".into()
            }
            VncError::ResolveFailed(h) => format!("Could not find a computer named \"{h}\"."),
            VncError::AuthFailed(r) if r == crate::security::APPLE_DH_REFUSED => {
                format!(
                    "The password was not accepted. {}",
                    crate::security::APPLE_DH_HINT
                )
            }
            VncError::AuthFailed(_) => "The password was not accepted.".into(),
            VncError::AccessDenied(r) => r.clone(),
            VncError::KeyExchange(r) => r.clone(),
            VncError::CredentialsRequired(_) => "This computer requires a password.".into(),
            VncError::CertificateMismatch { .. } => {
                "This computer's identity has changed. This could indicate a security problem."
                    .into()
            }
            VncError::CertificateUntrusted(_) => {
                "This computer's identity was not trusted, so no name or password was sent to it."
                    .into()
            }
            VncError::AnonymousTlsOnly => {
                "This computer's VNC server only offers TLSVnc or TLSNone, a kind of \
                 encryption DeskVNC cannot use. Add VncAuth, X509Vnc or RA2 to its \
                 SecurityTypes setting."
                    .into()
            }
            VncError::NoSupportedSecurityType(_) => {
                "This server uses an authentication method DeskVNCViewer does not support.".into()
            }
            other => other.to_string(),
        }
    }
}
