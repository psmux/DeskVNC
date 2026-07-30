//! # vnc-transport
//!
//! Byte-stream transports for DeskVNCViewer: plain TCP, and TLS (for VeNCrypt
//! X509 subtypes) with trust-on-first-use certificate pinning.
//!
//! SSH tunnelling for the RFB connection is not implemented here yet. Host
//! profiles already carry an `ssh_tunnel` column and an `ssh_passphrase`
//! credential slot, and `vnc-files` speaks SSH for SFTP, but nothing routes the
//! protocol stream through a tunnel. Adding it belongs behind [`Stream`].
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

/// Any bidirectional byte stream a VNC session can run over.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Boxed stream, used where the concrete transport varies at runtime.
pub type BoxedStream = Pin<Box<dyn Stream>>;

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
