//! Error types for the discovery crate.

use std::net::SocketAddr;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by discovery operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A subnet was too large to scan politely (prefix shorter than the
    /// minimum) and no explicit opt-in was given.
    #[error("refusing to scan {network}/{prefix}: prefix shorter than /{min} ({hosts} hosts) is too large without explicit opt-in")]
    SubnetTooLarge {
        /// Network base address.
        network: std::net::Ipv4Addr,
        /// CIDR prefix length.
        prefix: u8,
        /// Minimum allowed prefix length.
        min: u8,
        /// Number of host addresses implied.
        hosts: u64,
    },

    /// The MAC address string could not be parsed.
    #[error("invalid MAC address: {0:?}")]
    InvalidMac(String),

    /// Failed to bring up the mDNS daemon.
    #[error("mDNS error: {0}")]
    Mdns(String),

    /// A deep probe failed to complete the RFB version handshake.
    #[error("probe of {addr} failed: {reason}")]
    Probe {
        /// Address that was probed.
        addr: SocketAddr,
        /// Human-readable reason.
        reason: String,
    },

    /// Wrapped I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
