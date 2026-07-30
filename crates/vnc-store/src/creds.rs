//! Credential storage: OS keychain first, encrypted file as fallback.
//!
//! All calls are blocking (the OS keychain APIs and Argon2 are synchronous).
//! Callers on an async runtime must wrap them in
//! `tokio::task::spawn_blocking`, never call these on the render path.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use parking_lot::Mutex;
use zeroize::Zeroizing;

use crate::{Error, Result, StoredCredentials};

/// Keychain service name. The account is always the host profile UUID, /// never `user@host`, so renaming a host never orphans a credential and no
/// host data leaks into the keychain index.
pub const KEYRING_SERVICE: &str = "com.deskvncviewer.app";

/// Windows Credential Manager hard cap (`CRED_MAX_CREDENTIAL_BLOB_SIZE`).
/// Enforced on every platform so profiles stay portable.
pub const MAX_CREDENTIAL_BLOB: usize = 2560;

const PROBE_ACCOUNT: &str = "__deskvnc_probe__";

const CRED_FILE: &str = "credentials.enc";
const MAGIC: &[u8; 4] = b"DVCV";
const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
/// magic(4) + version(1) + m_cost(4) + t_cost(4) + p(4) + salt(16) + nonce(24)
const HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;

const DEFAULT_M_COST: u32 = 65536; // KiB => 64 MiB
const DEFAULT_T_COST: u32 = 3;
const DEFAULT_P_COST: u32 = 4;

/// Which backend currently serves credentials (for the UI status chip).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CredentialBackend {
    /// The OS keychain is available and in use.
    OsKeychain,
    /// The encrypted-file fallback is in use and unlocked.
    EncryptedFile,
    /// The encrypted-file fallback is required but not yet unlocked with the
    /// master password.
    Locked,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Backend {
    Unknown,
    Keychain,
    File,
}

/// Derived key + decrypted entries of the encrypted-file fallback.
struct Vault {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    entries: HashMap<String, StoredCredentials>,
}

struct Inner {
    backend: Backend,
    /// `Some` while the file fallback is unlocked.
    vault: Option<Vault>,
    /// Session cache for keychain-backed credentials, so repeated loads do
    /// not hit the keychain.
    cache: HashMap<String, StoredCredentials>,
    /// KDF parameters used when *creating* a new credential file (existing
    /// files carry their parameters in the header).
    kdf: (u32, u32, u32),
}

/// Secret storage for host credentials.
///
/// Primary backend is the OS keychain (`keyring`); if the platform store is
/// unavailable (headless Linux, locked keyring, unsigned dev build on macOS,
/// ...) it falls back to `data_dir/credentials.enc`, encrypted with
/// XChaCha20-Poly1305 under an Argon2id-derived key.
pub struct CredentialStore {
    data_dir: PathBuf,
    inner: Mutex<Inner>,
}

impl CredentialStore {
    /// Uses the OS keychain; falls back to an encrypted file if unavailable.
    /// Backend detection is lazy (first call that needs it).
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            inner: Mutex::new(Inner {
                backend: Backend::Unknown,
                vault: None,
                cache: HashMap::new(),
                kdf: (DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST),
            }),
        }
    }

    /// Forces the encrypted-file backend, bypassing the OS keychain. Used
    /// when the user explicitly opts out of the keychain, and by tests.
    pub fn new_with_file_backend(data_dir: PathBuf) -> Self {
        let store = Self::new(data_dir);
        store.inner.lock().backend = Backend::File;
        store
    }

    #[cfg(test)]
    pub(crate) fn set_kdf_params_for_tests(&self, m_cost: u32, t_cost: u32, p_cost: u32) {
        self.inner.lock().kdf = (m_cost, t_cost, p_cost);
    }

    /// The backend currently in effect (probing the keychain on first call).
    pub fn backend(&self) -> CredentialBackend {
        let mut inner = self.inner.lock();
        self.resolve_backend(&mut inner);
        match inner.backend {
            Backend::Keychain => CredentialBackend::OsKeychain,
            Backend::File if inner.vault.is_some() => CredentialBackend::EncryptedFile,
            _ => CredentialBackend::Locked,
        }
    }

    /// `true` when the encrypted-file fallback is in use and not yet
    /// unlocked. Always `false` when the OS keychain is available.
    pub fn is_locked(&self) -> bool {
        self.backend() == CredentialBackend::Locked
    }

    /// Saves (or replaces) the credentials for a host profile.
    pub fn save(&self, host_id: &str, creds: &StoredCredentials) -> Result<()> {
        let json = serde_json::to_string(creds)?;
        if json.len() > MAX_CREDENTIAL_BLOB {
            return Err(Error::CredentialTooLarge {
                size: json.len(),
                limit: MAX_CREDENTIAL_BLOB,
            });
        }
        let mut inner = self.inner.lock();
        self.resolve_backend(&mut inner);
        if inner.backend == Backend::Keychain {
            match keychain_set(host_id, &json) {
                Ok(()) => {
                    inner.cache.insert(host_id.to_string(), creds.clone());
                    return Ok(());
                }
                Err(e) if is_unavailable(&e) => {
                    tracing::warn!(error = %e, "keychain became unavailable; falling back to encrypted file");
                    inner.backend = Backend::File;
                }
                Err(e) => return Err(e.into()),
            }
        }
        // Encrypted-file path.
        let vault = inner.vault.as_mut().ok_or(Error::Locked)?;
        vault.entries.insert(host_id.to_string(), creds.clone());
        self.write_vault(vault)
    }

    /// Loads the credentials for a host profile (`None` if none stored).
    pub fn load(&self, host_id: &str) -> Result<Option<StoredCredentials>> {
        let mut inner = self.inner.lock();
        self.resolve_backend(&mut inner);
        if inner.backend == Backend::Keychain {
            if let Some(hit) = inner.cache.get(host_id) {
                return Ok(Some(hit.clone()));
            }
            match keychain_get(host_id) {
                Ok(Some(json)) => {
                    let creds: StoredCredentials = serde_json::from_str(&json)?;
                    inner.cache.insert(host_id.to_string(), creds.clone());
                    return Ok(Some(creds));
                }
                Ok(None) => return Ok(None),
                Err(e) if is_unavailable(&e) => {
                    tracing::warn!(error = %e, "keychain became unavailable; falling back to encrypted file");
                    inner.backend = Backend::File;
                }
                Err(e) => return Err(e.into()),
            }
        }
        let vault = inner.vault.as_ref().ok_or(Error::Locked)?;
        Ok(vault.entries.get(host_id).cloned())
    }

    /// Deletes the credentials for a host profile. Missing entries are not
    /// an error.
    pub fn delete(&self, host_id: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        self.resolve_backend(&mut inner);
        inner.cache.remove(host_id);
        if inner.backend == Backend::Keychain {
            match keychain_delete(host_id) {
                Ok(()) => return Ok(()),
                Err(e) if is_unavailable(&e) => {
                    tracing::warn!(error = %e, "keychain became unavailable; falling back to encrypted file");
                    inner.backend = Backend::File;
                }
                Err(e) => return Err(e.into()),
            }
        }
        let vault = inner.vault.as_mut().ok_or(Error::Locked)?;
        if vault.entries.remove(host_id).is_some() {
            self.write_vault(vault)?;
        }
        Ok(())
    }

    /// Unlocks the encrypted-file fallback with the master password.
    /// No-op when the OS keychain is in use. Creates the credential file on
    /// first unlock; on later unlocks a wrong password fails with
    /// [`Error::InvalidMasterPassword`].
    pub fn unlock(&self, master_password: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        self.resolve_backend(&mut inner);
        if inner.backend == Backend::Keychain {
            return Ok(());
        }
        let path = self.data_dir.join(CRED_FILE);
        let vault = if path.exists() {
            let bytes = std::fs::read(&path)?;
            open_vault(&bytes, master_password)?
        } else {
            // First unlock: create a fresh vault and persist an (empty)
            // credential file so later unlocks verify the password.
            let mut salt = [0u8; SALT_LEN];
            rand_fill(&mut salt);
            let (m_cost, t_cost, p_cost) = inner.kdf;
            let key = derive_key(master_password, &salt, m_cost, t_cost, p_cost)?;
            Vault {
                key,
                salt,
                m_cost,
                t_cost,
                p_cost,
                entries: HashMap::new(),
            }
        };
        self.write_vault(&vault)?;
        inner.vault = Some(vault);
        Ok(())
    }

    /// Re-locks the encrypted-file fallback, dropping the derived key and
    /// decrypted entries from memory. No-op when the keychain is in use.
    pub fn lock(&self) {
        let mut inner = self.inner.lock();
        // Vault::key is Zeroizing, dropping wipes the derived key.
        inner.vault = None;
    }

    fn resolve_backend(&self, inner: &mut Inner) {
        if inner.backend == Backend::Unknown {
            inner.backend = if keychain_available() {
                Backend::Keychain
            } else {
                Backend::File
            };
            if inner.backend == Backend::File {
                tracing::info!("no usable OS keychain; using encrypted-file credential fallback");
            }
        }
    }

    /// Encrypts and atomically writes the vault to `credentials.enc`
    /// (mode 0600 on unix). A fresh random nonce is used for every write and
    /// the whole cleartext header is bound as AAD, so the KDF parameters
    /// cannot be downgraded without breaking authentication.
    fn write_vault(&self, vault: &Vault) -> Result<()> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&vault.entries)?);

        let mut nonce = [0u8; NONCE_LEN];
        rand_fill(&mut nonce);
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(FORMAT_VERSION);
        header.extend_from_slice(&vault.m_cost.to_le_bytes());
        header.extend_from_slice(&vault.t_cost.to_le_bytes());
        header.extend_from_slice(&vault.p_cost.to_le_bytes());
        header.extend_from_slice(&vault.salt);
        header.extend_from_slice(&nonce);
        debug_assert_eq!(header.len(), HEADER_LEN);

        let cipher = XChaCha20Poly1305::new((&*vault.key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &header,
                },
            )
            .map_err(|_| Error::Crypto("encryption failed".into()))?;

        std::fs::create_dir_all(&self.data_dir)?;
        let tmp = self.data_dir.join(format!("{CRED_FILE}.tmp"));
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(&header)?;
            f.write_all(&ciphertext)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.data_dir.join(CRED_FILE))?;
        Ok(())
    }
}

/// Parses + decrypts a credential file with the given master password.
fn open_vault(bytes: &[u8], master_password: &str) -> Result<Vault> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::MalformedCredentialFile("file too short".into()));
    }
    let (header, ciphertext) = bytes.split_at(HEADER_LEN);
    if &header[0..4] != MAGIC {
        return Err(Error::MalformedCredentialFile("bad magic".into()));
    }
    if header[4] != FORMAT_VERSION {
        return Err(Error::MalformedCredentialFile(format!(
            "unsupported format version {}",
            header[4]
        )));
    }
    let le_u32 = |off: usize| -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&header[off..off + 4]);
        u32::from_le_bytes(b)
    };
    let m_cost = le_u32(5);
    let t_cost = le_u32(9);
    let p_cost = le_u32(13);
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&header[17..17 + SALT_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&header[17 + SALT_LEN..HEADER_LEN]);

    let key = derive_key(master_password, &salt, m_cost, t_cost, p_cost)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| Error::InvalidMasterPassword)?;
    let plaintext = Zeroizing::new(plaintext);
    let entries: HashMap<String, StoredCredentials> = serde_json::from_slice(&plaintext)?;
    Ok(Vault {
        key,
        salt,
        m_cost,
        t_cost,
        p_cost,
        entries,
    })
}

/// Argon2id KDF. The password bytes are copied into a zeroized buffer; the
/// returned key is zeroized on drop.
fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| Error::Crypto(format!("bad Argon2 params: {e}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let pw = Zeroizing::new(password.as_bytes().to_vec());
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(&pw, salt, key.as_mut())
        .map_err(|e| Error::Crypto(format!("Argon2 failure: {e}")))?;
    Ok(key)
}

fn rand_fill(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}

// ---- keychain helpers ------------------------------------------------------

/// Errors that mean "this platform's secure storage is not usable" and should
/// trigger the encrypted-file fallback (vs. per-entry errors like NoEntry).
fn is_unavailable(err: &keyring::Error) -> bool {
    matches!(
        err,
        keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_)
    )
}

/// Cheap availability probe: reading a nonexistent entry. `NoEntry` proves
/// the store answered; platform/access failures mean fallback.
fn keychain_available() -> bool {
    match keyring::Entry::new(KEYRING_SERVICE, PROBE_ACCOUNT) {
        Ok(entry) => match entry.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => true,
            Err(e) => !is_unavailable(&e),
        },
        Err(_) => false,
    }
}

fn keychain_set(host_id: &str, json: &str) -> std::result::Result<(), keyring::Error> {
    keyring::Entry::new(KEYRING_SERVICE, host_id)?.set_password(json)
}

fn keychain_get(host_id: &str) -> std::result::Result<Option<String>, keyring::Error> {
    match keyring::Entry::new(KEYRING_SERVICE, host_id)?.get_password() {
        Ok(json) => Ok(Some(json)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e),
    }
}

fn keychain_delete(host_id: &str) -> std::result::Result<(), keyring::Error> {
    match keyring::Entry::new(KEYRING_SERVICE, host_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_store(dir: &std::path::Path) -> CredentialStore {
        let store = CredentialStore::new_with_file_backend(dir.to_path_buf());
        // Weak KDF params keep the test fast; the format/logic is identical.
        store.set_kdf_params_for_tests(8, 1, 1);
        store
    }

    fn sample_creds() -> StoredCredentials {
        StoredCredentials {
            vnc_password: Some("vnc-pass-123".into()),
            vencrypt_user: Some("alice".into()),
            vencrypt_pass: Some("tls-pass-456".into()),
            ssh_passphrase: Some("ssh-pass-789".into()),
        }
    }

    #[test]
    fn locked_until_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        assert!(store.is_locked());
        assert_eq!(store.backend(), CredentialBackend::Locked);
        assert!(matches!(store.load("x"), Err(Error::Locked)));
        assert!(matches!(
            store.save("x", &sample_creds()),
            Err(Error::Locked)
        ));
        assert!(matches!(store.delete("x"), Err(Error::Locked)));
    }

    #[test]
    fn encrypted_file_save_lock_unlock_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        store.unlock("correct horse battery staple").unwrap();
        assert!(!store.is_locked());
        assert_eq!(store.backend(), CredentialBackend::EncryptedFile);

        store.save("host-1", &sample_creds()).unwrap();
        assert!(dir.path().join("credentials.enc").exists());

        store.lock();
        assert!(store.is_locked());
        assert!(matches!(store.load("host-1"), Err(Error::Locked)));

        store.unlock("correct horse battery staple").unwrap();
        let got = store
            .load("host-1")
            .unwrap()
            .expect("credentials survive lock cycle");
        assert_eq!(got.vnc_password.as_deref(), Some("vnc-pass-123"));
        assert_eq!(got.vencrypt_user.as_deref(), Some("alice"));
        assert_eq!(got.vencrypt_pass.as_deref(), Some("tls-pass-456"));
        assert_eq!(got.ssh_passphrase.as_deref(), Some("ssh-pass-789"));
        assert!(store.load("unknown-host").unwrap().is_none());

        // A fresh store instance (new process) can also unlock and read.
        let store2 = file_store(dir.path());
        store2.unlock("correct horse battery staple").unwrap();
        assert!(store2.load("host-1").unwrap().is_some());

        // Delete removes and persists.
        store2.delete("host-1").unwrap();
        assert!(store2.load("host-1").unwrap().is_none());
        let store3 = file_store(dir.path());
        store3.unlock("correct horse battery staple").unwrap();
        assert!(store3.load("host-1").unwrap().is_none());
    }

    #[test]
    fn wrong_master_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        store.unlock("right-password").unwrap();
        store.save("host-1", &sample_creds()).unwrap();
        store.lock();

        assert!(matches!(
            store.unlock("wrong-password"),
            Err(Error::InvalidMasterPassword)
        ));
        assert!(store.is_locked());

        let fresh = file_store(dir.path());
        assert!(matches!(
            fresh.unlock("also-wrong"),
            Err(Error::InvalidMasterPassword)
        ));
    }

    #[test]
    fn tampered_header_fails_authentication() {
        // Flipping a KDF-parameter byte in the cleartext header must break
        // the AAD check (downgrade protection), not silently rescale.
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        store.unlock("pw").unwrap();
        store.save("host-1", &sample_creds()).unwrap();
        store.lock();

        let path = dir.path().join("credentials.enc");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[5] ^= 0xff; // low byte of m_cost
                          // Re-derive would use the tampered params, so decryption must fail
                          // regardless of which password is supplied.
        assert!(open_vault(&bytes, "pw").is_err());
    }

    #[test]
    fn oversize_blob_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        store.unlock("pw").unwrap();
        let big = StoredCredentials {
            vnc_password: Some("x".repeat(MAX_CREDENTIAL_BLOB + 1)),
            ..Default::default()
        };
        match store.save("host-1", &big) {
            Err(Error::CredentialTooLarge { size, limit }) => {
                assert!(size > limit);
                assert_eq!(limit, MAX_CREDENTIAL_BLOB);
            }
            other => panic!("expected CredentialTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn credential_file_has_no_plaintext_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        store.unlock("pw").unwrap();
        store.save("host-1", &sample_creds()).unwrap();

        let path = dir.path().join("credentials.enc");
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[0..4], b"DVCV");
        for secret in [
            "vnc-pass-123",
            "tls-pass-456",
            "ssh-pass-789",
            "alice",
            "host-1",
        ] {
            let needle = secret.as_bytes();
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "plaintext {secret:?} leaked into credentials.enc"
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "credential file must be 0600");
        }
    }

    /// Exercises the real OS keychain. Ignored by default: CI environments
    /// often have no usable keychain, and this writes to the developer's
    /// real credential store. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "touches the real OS keychain"]
    fn os_keychain_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = CredentialStore::new(dir.path().to_path_buf());
        if store.backend() != CredentialBackend::OsKeychain {
            eprintln!("skipping: no usable OS keychain on this machine");
            return;
        }
        let host_id = format!("test-{}", uuid::Uuid::new_v4());
        store.save(&host_id, &sample_creds()).unwrap();
        let got = store.load(&host_id).unwrap().unwrap();
        assert_eq!(got.vnc_password.as_deref(), Some("vnc-pass-123"));
        store.delete(&host_id).unwrap();
        // Cache was cleared too, so this is a real keychain miss.
        assert!(store.load(&host_id).unwrap().is_none());
    }
}
