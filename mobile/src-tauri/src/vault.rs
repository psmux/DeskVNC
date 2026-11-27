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
//! A host that connects through an SSH tunnel has a second entry, keyed
//! `<host id>.ssh`, for the tunnel's password or private key. It is separate
//! so that saving the computer's own password, which replaces that entry
//! whole, can never drop the tunnel's.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::tunnel::TunnelSecret;

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
    fn load_tunnel(&self, host_id: &str) -> Result<Option<TunnelSecret>, String>;
    fn save_tunnel(&self, host_id: &str, secret: &TunnelSecret) -> Result<(), String>;
    fn delete_tunnel(&self, host_id: &str) -> Result<(), String>;
}

/// The vault account a host's tunnel secret is filed under. A host id never
/// holds a dot (`store::validate_id`), so this cannot be another host's.
#[cfg_attr(not(any(target_os = "ios", target_os = "android")), allow(dead_code))]
pub fn tunnel_account(host_id: &str) -> String {
    format!("{host_id}.ssh")
}

/// Memory only. Used by the tests, and by a desktop build of this crate.
#[derive(Default)]
pub struct MemoryStore {
    map: Mutex<HashMap<String, Secret>>,
    tunnels: Mutex<HashMap<String, TunnelSecret>>,
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
    fn load_tunnel(&self, host_id: &str) -> Result<Option<TunnelSecret>, String> {
        Ok(self.tunnels.lock().get(host_id).cloned())
    }
    fn save_tunnel(&self, host_id: &str, secret: &TunnelSecret) -> Result<(), String> {
        self.tunnels.lock().insert(host_id.into(), secret.clone());
        Ok(())
    }
    fn delete_tunnel(&self, host_id: &str) -> Result<(), String> {
        self.tunnels.lock().remove(host_id);
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

    fn load_json<T: serde::de::DeserializeOwned>(account: &str) -> Result<Option<T>, String> {
        match Self::entry(account)?.get_password() {
            Ok(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| format!("a saved password could not be read: {e}")),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn save_json<T: Serialize>(account: &str, value: &T) -> Result<(), String> {
        let json = serde_json::to_string(value).map_err(|e| e.to_string())?;
        Self::entry(account)?
            .set_password(&json)
            .map_err(|e| e.to_string())
    }

    fn delete_account(account: &str) -> Result<(), String> {
        match Self::entry(account)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(any(target_os = "ios", target_os = "android"))]
impl SecretStore for VaultStore {
    fn load(&self, host_id: &str) -> Result<Option<Secret>, String> {
        Self::load_json(host_id)
    }
    fn save(&self, host_id: &str, secret: &Secret) -> Result<(), String> {
        Self::save_json(host_id, secret)
    }
    fn delete(&self, host_id: &str) -> Result<(), String> {
        Self::delete_account(host_id)
    }
    fn load_tunnel(&self, host_id: &str) -> Result<Option<TunnelSecret>, String> {
        Self::load_json(&tunnel_account(host_id))
    }
    fn save_tunnel(&self, host_id: &str, secret: &TunnelSecret) -> Result<(), String> {
        Self::save_json(&tunnel_account(host_id), secret)
    }
    fn delete_tunnel(&self, host_id: &str) -> Result<(), String> {
        Self::delete_account(&tunnel_account(host_id))
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

    /// The tunnel's secret is its own entry: saving or forgetting the
    /// computer's password leaves it alone.
    #[test]
    fn the_tunnel_secret_is_kept_apart_from_the_sign_in() {
        let store = MemoryStore::default();
        let t = TunnelSecret {
            key: Some("KEY".into()),
            ..Default::default()
        };
        store.save_tunnel("a", &t).unwrap();
        store
            .save(
                "a",
                &Secret {
                    username: None,
                    password: Some("pw".into()),
                },
            )
            .unwrap();
        store.delete("a").unwrap();
        assert_eq!(store.load_tunnel("a").unwrap(), Some(t));
        store.delete_tunnel("a").unwrap();
        assert_eq!(store.load_tunnel("a").unwrap(), None);
        assert_eq!(tunnel_account("6f1c"), "6f1c.ssh");
        assert!(
            crate::store::validate_id("6f1c.ssh").is_err(),
            "a tunnel account can never be a host id"
        );
    }
}
