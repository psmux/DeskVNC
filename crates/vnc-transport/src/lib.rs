//! # vnc-transport
//!
//! Byte-stream transports for DeskVNCViewer: plain TCP, and TLS (for VeNCrypt
//! X509 subtypes) with trust-on-first-use certificate pinning.
//!
//! SSH tunnelling for the RFB connection does not live here either, it would
//! drag an SSH stack into every consumer, but it plugs in through
//! [`StreamConnector`]: `vnc-files` owns the SSH connection (it already speaks
//! SSH for SFTP) and hands the protocol layer an opened channel as a
//! [`BoxedStream`].
//!
//! The core protocol code is generic over [`Stream`], so upgrading a plain TCP
//! connection to TLS mid-handshake (as VeNCrypt requires) is transparent.

// This crate parses bytes controlled by a remote peer. Memory safety here is
// enforced by the compiler rather than by review.
#![forbid(unsafe_code)]

use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod tcp;
pub mod tls;
#[cfg(feature = "legacy-tls")]
pub mod tls_legacy;

// The TLS handshake's result type and the backend selector are re-exported at
// the crate root because both are part of this crate's contract with
// `rdp-core` rather than details of the rustls module (PRDRDP/03 §4.7.1,
// PRDRDP/12 §3.8).
pub use tls::{TlsBackend, TlsUpgrade};

/// Any bidirectional byte stream a VNC session can run over.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Boxed stream, used where the concrete transport varies at runtime.
pub type BoxedStream = Pin<Box<dyn Stream>>;

/// A boxed connect future, the shape [`StreamConnector`] implementations
/// return (object-safe async without an `async_trait` dependency).
pub type ConnectFuture<'a> =
    Pin<Box<dyn std::future::Future<Output = Result<BoxedStream>> + Send + 'a>>;

/// An alternative way of opening the byte stream a VNC session runs over.
///
/// The session core dials plain TCP itself; anything else, today an SSH
/// tunnel, is injected as one of these. `host`/`port` are the VNC endpoint
/// *as the connector should interpret it*: for an SSH tunnel that means the
/// address is resolved by the remote SSH server, which is the whole point,
/// `localhost:5900` names the loopback of the tunnelled machine, not ours.
///
/// Called once per connection attempt, so the auto-reconnect supervisor
/// exercises it again after a drop; implementations must be prepared to
/// re-establish whatever carrier they run over. `timeout` is the session's
/// connect budget for the whole attempt.
pub trait StreamConnector: Send + Sync {
    fn connect(&self, host: &str, port: u16, timeout: std::time::Duration) -> ConnectFuture<'_>;

    /// Short, secret-free label for logs and the `Connecting` state.
    fn describe(&self) -> String {
        "custom transport".to_string()
    }
}

/// Outcome of verifying a server certificate against the TOFU store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// Chains to a system root and the hostname matches.
    VerifiedByCa,
    /// Fingerprint matches the stored pin.
    PinnedMatch,
    /// No pin stored yet, the UI must prompt the user.
    Unknown {
        fingerprint: String,
        subject: String,
    },
    /// Pin exists but differs. HARD STOP (PRD/10 §4.3).
    Changed { expected: String, actual: String },
}

/// SHA-256 fingerprint of a certificate's SubjectPublicKeyInfo, hex encoded
/// with colons, the form shown to users.
pub fn format_fingerprint(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Normalise a user- or database-supplied fingerprint for comparison:
/// strip separators, uppercase.
pub fn normalize_fingerprint(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Transport-level failures. `vnc-core` converts these into `VncError`.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection timed out")]
    Timeout,

    #[error("connection refused by {0}")]
    Refused(String),

    #[error("dns resolution failed for {0}")]
    Resolve(String),

    #[error("tls error: {0}")]
    Tls(String),

    /// The peer presented a different key than the stored pin. Never retried.
    #[error("server identity changed: expected {expected}, got {actual}")]
    CertificateMismatch { expected: String, actual: String },
}

pub type Result<T> = std::result::Result<T, TransportError>;

impl From<TransportError> for std::io::Error {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Io(e) => e,
            TransportError::Timeout => {
                std::io::Error::new(std::io::ErrorKind::TimedOut, e.to_string())
            }
            TransportError::Refused(_) => {
                std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string())
            }
            other => std::io::Error::other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_formatting() {
        assert_eq!(format_fingerprint(&[0xde, 0xad, 0xbe, 0xef]), "DE:AD:BE:EF");
    }

    #[test]
    fn fingerprint_normalisation_round_trips() {
        let raw = [0xde, 0xad, 0xbe, 0xef];
        let shown = format_fingerprint(&raw);
        assert_eq!(normalize_fingerprint(&shown), "DEADBEEF");
        assert_eq!(normalize_fingerprint("de:ad:be:ef"), "DEADBEEF");
        assert_eq!(normalize_fingerprint("de ad be ef"), "DEADBEEF");
        assert_eq!(
            normalize_fingerprint(&shown),
            normalize_fingerprint("DeAdBeEf")
        );
    }

    #[test]
    fn empty_fingerprint_is_empty() {
        assert_eq!(format_fingerprint(&[]), "");
    }
}
