//! Persistence layer for DeskVNCViewer.
//!
//! - [`Store`]: SQLite-backed host profiles, groups, tags, history, settings,
//!   TOFU certificate pins, and a file-based thumbnail cache.
//! - [`CredentialStore`]: secrets in the OS keychain, with an encrypted-file
//!   fallback (Argon2id + XChaCha20-Poly1305) when no keychain is available.
//!
//! No secret is ever written to the SQLite database; `hosts.has_password` is
//! only a flag. Credentials are keyed by the host profile UUID so renaming a
//! host never orphans a credential.
//!
//! All APIs are synchronous. Keychain and Argon2 calls block, callers on an
//! async runtime must wrap them in `tokio::task::spawn_blocking`.

// This crate parses bytes controlled by a remote peer. Memory safety here is
// enforced by the compiler rather than by review.
#![forbid(unsafe_code)]

mod creds;
mod error;
mod models;
mod store;
mod thumbs;

pub use creds::{CredentialBackend, CredentialStore, KEYRING_SERVICE, MAX_CREDENTIAL_BLOB};
pub use error::{Error, Result};
pub use models::{CertPin, Group, HistoryEntry, HostProfile, StoredCredentials, Tag};
pub use store::{normalize_address, Store};

pub(crate) fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod lib_tests {
    #[test]
    fn store_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<crate::Store>();
        assert_send_sync::<crate::CredentialStore>();
    }
}
