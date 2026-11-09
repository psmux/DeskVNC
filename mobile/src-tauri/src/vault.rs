//! Passwords, in the platform vault and nowhere else.
//!
//! * iOS: the Keychain, through `apple-native-keyring-store`'s protected data
//!   store, which is the only keychain iOS has.
//! * Android: `android-native-keyring-store`, which encrypts each value with
//!   an AES key that lives in the Android Keystore and keeps only the
//!   ciphertext in the app's private preferences. It finds the Android
//!   context through `ndk-context`, which Tauri fills in at start.
//! * Any other target: memory only. A desktop build of this crate exists for
//!   `cargo check` and the unit tests, never for people, and writing a
//!   password to a file there would be exactly the plaintext this module is
//!   here to prevent.
//!
//! One vault entry per host, keyed by host id, holding a small JSON blob so a
//! user name typed at a prompt can travel with the password it belongs to.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// The service name every entry is filed under.
#[cfg_attr(not(any(target_os = "ios", target_os = "android")), allow(dead_code))]
pub const SERVICE: &str = "com.psmux.deskvnc.mobile";

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("username", &self.username.as_ref().map(|_| "***"))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .finish()
    }
}

/// Where secrets go. A trait so the tests and the desktop build share the
/// logic above it with the phone, and only the backend differs.
pub trait SecretStore: Send + Sync {
    fn load(&self, host_id: &str) -> Result<Option<Secret>, String>;
    fn save(&self, host_id: &str, secret: &Secret) -> Result<(), String>;
    fn delete(&self, host_id: &str) -> Result<(), String>;
}

/// Memory only. Used by the tests, and by a desktop build of this crate.
#[derive(Default)]
pub struct MemoryStore {
    map: Mutex<HashMap<String, Secret>>,
}

impl SecretStore for MemoryStore {
    fn load(&self, host_id: &str) -> Result<Option<Secret>, String> {
        Ok(self.map.lock().get(host_id).cloned())
    }
    fn save(&self, host_id: &str, secret: &Secret) -> Result<(), String> {
        self.map.lock().insert(host_id.into(), secret.clone());
        Ok(())
    }
    fn delete(&self, host_id: &str) -> Result<(), String> {
        self.map.lock().remove(host_id);
        Ok(())
    }
}

/// The platform vault, through `keyring-core`'s default store.
#[cfg(any(target_os = "ios", target_os = "android"))]
pub struct VaultStore;

#[cfg(any(target_os = "ios", target_os = "android"))]
impl VaultStore {
    fn entry(host_id: &str) -> Result<keyring_core::Entry, String> {
        keyring_core::Entry::new(SERVICE, host_id).map_err(|e| e.to_string())
    }
}

#[cfg(any(target_os = "ios", target_os = "android"))]
impl SecretStore for VaultStore {
    fn load(&self, host_id: &str) -> Result<Option<Secret>, String> {
        match Self::entry(host_id)?.get_password() {
            Ok(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| format!("a saved password could not be read: {e}")),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    fn save(&self, host_id: &str, secret: &Secret) -> Result<(), String> {
        let json = serde_json::to_string(secret).map_err(|e| e.to_string())?;
        Self::entry(host_id)?
            .set_password(&json)
            .map_err(|e| e.to_string())
    }
    fn delete(&self, host_id: &str) -> Result<(), String> {
        match Self::entry(host_id)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// The store this build uses. On a phone it registers the platform vault as
/// `keyring-core`'s default first; if that fails the app still runs, with
/// passwords kept for this launch only, and says so in the log.
pub fn platform_store() -> Arc<dyn SecretStore> {
    #[cfg(target_os = "ios")]
    {
        match apple_native_keyring_store::protected::Store::new() {
            Ok(store) => {
                keyring_core::set_default_store(store);
                return Arc::new(VaultStore);
            }
            Err(error) => tracing::error!(%error, "the iOS Keychain is unavailable"),
        }
    }
    #[cfg(target_os = "android")]
    {
        match android_native_keyring_store::Store::new() {
            Ok(store) => {
                keyring_core::set_default_store(store);
                return Arc::new(VaultStore);
            }
            Err(error) => tracing::error!(%error, "the Android Keystore is unavailable"),
        }
    }
    Arc::new(MemoryStore::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_a_secret() {
        let s = Secret {
            username: Some("alice".into()),
            password: Some("hunter2".into()),
        };
        let printed = format!("{s:?}");
        assert!(!printed.contains("alice") && !printed.contains("hunter2"));
    }

    #[test]
    fn memory_store_round_trip() {
        let store = MemoryStore::default();
        assert_eq!(store.load("a").unwrap(), None);
        let s = Secret {
            username: None,
            password: Some("pw".into()),
        };
        store.save("a", &s).unwrap();
        assert_eq!(store.load("a").unwrap(), Some(s));
        store.delete("a").unwrap();
        store.delete("a").unwrap();
        assert_eq!(store.load("a").unwrap(), None);
    }
}
