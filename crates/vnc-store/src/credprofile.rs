//! Saved credentials a host can point at (issue #98).
//!
//! A saved credential is a named user name and password, or a user name and
//! an SSH key file with an optional passphrase. A host either keeps its own
//! credential, as every host did before this existed, or names one of these
//! in `hosts.credential_id`. Changing the saved one changes every host that
//! names it, because nothing is copied: the host is resolved against it each
//! time it connects.
//!
//! The row in `credentials` holds nothing secret. The password or passphrase
//! is in the same [`CredentialStore`] a host's own secret is in, under the
//! account `credential:<id>`, so it gets the keychain, the encrypted file
//! fallback, the parked save while locked and the 2560 byte cap without a
//! second implementation of any of them.

use remote_core::options::{SshAuthKind, SshOptions};
use remote_core::ProtocolKind;
use zeroize::Zeroize;

use crate::{
    now_ts, CredentialStore, Error, HostProfile, Result, SshSettings, Store, StoredCredentials,
};

/// The prefix of the credential store account a saved credential's secret
/// lives under. A host id is a bare UUID, so the two can never collide.
pub const CREDENTIAL_ACCOUNT_PREFIX: &str = "credential:";

/// What a saved credential holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// A user name and a password. Signs in to VNC, RDP and SSH.
    Password,
    /// A user name and a private key file, with the key's passphrase as the
    /// secret when it has one. SSH only.
    SshKey,
}

impl CredentialKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "password" => Some(Self::Password),
            "ssh-key" => Some(Self::SshKey),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::SshKey => "ssh-key",
        }
    }
}

/// One saved credential, the `credentials` row. Never contains a secret.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProfile {
    pub id: String,
    /// What the person calls it in the picker: "Office admin", "Lab key".
    pub name: String,
    /// `"password"` or `"ssh-key"`, text for the same reason
    /// `HostProfile::protocol` is text.
    pub kind: String,
    /// The account. `None` asks at the prompt for VNC and RDP, and means
    /// "the same user as here" for SSH, as it does on a host.
    #[serde(default)]
    pub username: Option<String>,
    /// Windows logon domain, RDP only. A host's own configured domain still
    /// wins over it, as it wins over a domain typed at a prompt.
    #[serde(default)]
    pub domain: Option<String>,
    /// Private key file for an `ssh-key` credential. A path, read on the
    /// Rust side at connect time, like the host editor's key file.
    #[serde(default)]
    pub key_path: Option<String>,
    /// A password or passphrase is in the credential store for it. Only a
    /// flag, like `hosts.has_password`; the webview never sees the secret.
    #[serde(default)]
    pub has_secret: bool,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

impl Default for CredentialProfile {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: String::new(),
            kind: CredentialKind::Password.as_str().to_string(),
            username: None,
            domain: None,
            key_path: None,
            has_secret: false,
            created_at: 0,
            updated_at: 0,
        }
    }
}

fn filled(v: &Option<String>) -> Option<String> {
    v.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl CredentialProfile {
    pub fn credential_kind(&self) -> Option<CredentialKind> {
        CredentialKind::parse(&self.kind)
    }

    /// The credential store account for a saved credential's secret.
    pub fn secret_account(id: &str) -> String {
        format!("{CREDENTIAL_ACCOUNT_PREFIX}{id}")
    }

    /// Whether this credential can sign in to a host speaking `protocol`.
    /// The host editor offers only these, and resolution ignores a link that
    /// does not fit (a host switched from SSH to VNC after it was linked to a
    /// key), so a key is never sent where a password is wanted.
    pub fn fits(&self, protocol: ProtocolKind) -> bool {
        match self.credential_kind() {
            Some(CredentialKind::Password) => matches!(
                protocol,
                ProtocolKind::Vnc | ProtocolKind::Rdp | ProtocolKind::Ssh
            ),
            Some(CredentialKind::SshKey) => protocol == ProtocolKind::Ssh,
            None => false,
        }
    }

    /// Write this credential over the fields a `protocol` session reads.
    ///
    /// Every field the protocol reads is set, to `None` where the credential
    /// has nothing, so a user name the host saved for itself before it was
    /// linked cannot pair up with the shared password. Fields the protocol
    /// does not read are left alone: an RD Gateway password, or the SSH
    /// tunnel passphrase of a VNC host, still come from the host.
    pub fn apply(&self, protocol: ProtocolKind, secret: Option<&str>, out: &mut StoredCredentials) {
        let user = filled(&self.username);
        let secret = secret.filter(|s| !s.is_empty()).map(str::to_string);
        match (self.credential_kind(), protocol) {
            (Some(CredentialKind::Password), ProtocolKind::Vnc) => {
                // The plain VNC password is filled either way, so a host on
                // "VNC password only" uses it too.
                out.vnc_password = secret.clone();
                match user {
                    Some(user) => {
                        out.vencrypt_user = Some(user);
                        out.vencrypt_pass = secret;
                    }
                    None => {
                        out.vencrypt_user = None;
                        out.vencrypt_pass = None;
                    }
                }
            }
            (Some(CredentialKind::Password), ProtocolKind::Rdp) => {
                out.rdp_user = user;
                out.rdp_domain = filled(&self.domain);
                out.rdp_password = secret;
            }
            (Some(_), ProtocolKind::Ssh) => {
                // The terminal reads its one secret slot as a password or a
                // key passphrase by the auth kind, and the Files sidecar reads
                // the passphrase slot, so both carry it.
                out.ssh_user = user;
                out.ssh_password = secret.clone();
                out.ssh_passphrase = secret;
            }
            _ => {}
        }
    }

    /// Point an SSH host's settings at this credential: a key credential
    /// signs in with its key file, a password credential with a password.
    /// Everything else in the settings (multiplexer, terminal) is the host's.
    pub fn apply_ssh_options(&self, ssh: &mut SshOptions) {
        match self.credential_kind() {
            Some(CredentialKind::SshKey) => {
                if let Some(path) = filled(&self.key_path) {
                    ssh.auth = SshAuthKind::KeyFile;
                    ssh.key_path = Some(path);
                }
            }
            Some(CredentialKind::Password) => ssh.auth = SshAuthKind::Password,
            None => {}
        }
    }
}

/// The saved credential a host signs in with, when it names one that exists
/// and fits its protocol. `None` means the host uses its own entry.
pub fn linked_credential(store: &Store, host: &HostProfile) -> Result<Option<CredentialProfile>> {
    let Some(id) = host.credential_id.as_deref().filter(|id| !id.is_empty()) else {
        return Ok(None);
    };
    let Some(cred) = store.get_credential(id)? else {
        tracing::warn!(host = %host.id, "the saved credential this host names is gone; using its own");
        return Ok(None);
    };
    match host.protocol_kind() {
        Some(kind) if cred.fits(kind) => Ok(Some(cred)),
        _ => {
            tracing::warn!(host = %host.id, "the saved credential this host names does not fit its protocol; using its own");
            Ok(None)
        }
    }
}

/// An SSH host's `ssh_settings` blob as its connect should read it: with the
/// key file of the saved credential it names, when it names one. For a
/// caller that passes the blob on rather than parsing it (the Files
/// sidecar). A blob that does not parse is returned as it is, so the caller
/// reports that the way it always has.
pub fn effective_ssh_settings(store: &Store, host: &HostProfile) -> Option<String> {
    let cred = match linked_credential(store, host) {
        Ok(Some(cred)) => cred,
        _ => return host.ssh_settings.clone(),
    };
    let Ok(parsed) = SshSettings::parse(host.ssh_settings.as_deref()) else {
        return host.ssh_settings.clone();
    };
    let mut settings = parsed.unwrap_or_default();
    cred.apply_ssh_options(&mut settings.options);
    settings
        .to_json()
        .ok()
        .or_else(|| host.ssh_settings.clone())
}

/// The credential a connect for `host_id` should use: the host's own entry,
/// with the saved credential it names written over the fields its protocol
/// reads. This is the one function every connect path asks, so a host linked
/// to a saved credential signs in the same way from the terminal, the
/// desktop session, the Files panel and an agent.
///
/// A host that is not in the library (an ad hoc session) or names nothing is
/// exactly `creds.load(host_id)`, so nothing changes for a host that never
/// used a saved credential.
pub fn resolve_host_credentials(
    store: &Store,
    creds: &CredentialStore,
    host_id: &str,
) -> Result<Option<StoredCredentials>> {
    let own = creds.load(host_id)?;
    let Some(host) = store.get_host(host_id)? else {
        return Ok(own);
    };
    let Some(cred) = linked_credential(store, &host)? else {
        return Ok(own);
    };
    let Some(kind) = host.protocol_kind() else {
        return Ok(own);
    };
    let mut shared = if cred.has_secret {
        creds.load(&CredentialProfile::secret_account(&cred.id))?
    } else {
        None
    };
    let secret = shared.as_mut().and_then(|s| s.secret.take());
    if let Some(mut rest) = shared {
        rest.zeroize();
    }
    let mut out = own.unwrap_or_default();
    // A secret field on a host's own entry is never read; dropping it here
    // keeps it out of everything downstream.
    out.secret = None;
    cred.apply(kind, secret.as_deref(), &mut out);
    if let Some(mut s) = secret {
        s.zeroize();
    }
    Ok(Some(out))
}

/// Saves a credential's row and, when `secret` is given and not empty, its
/// password or passphrase. An absent secret keeps the stored one, as an
/// empty password box does in the host editor, except when the kind changed:
/// a password is not a key passphrase, so it is forgotten rather than reused.
///
/// The row is written first. When the credential store is locked the secret
/// waits for the unlock (see [`CredentialStore::save`]) and this returns
/// [`Error::Locked`], with the row already saved and `has_secret` set.
pub fn save_credential_profile(
    store: &Store,
    creds: &CredentialStore,
    profile: &CredentialProfile,
    secret: Option<&str>,
) -> Result<CredentialProfile> {
    let mut row = profile.clone();
    row.username = filled(&row.username);
    row.domain = filled(&row.domain);
    row.key_path = filled(&row.key_path);
    let existing = store.get_credential(&row.id)?;
    let secret = secret.filter(|s| !s.is_empty());
    let account = CredentialProfile::secret_account(&row.id);
    let kind_changed = existing.as_ref().is_some_and(|e| e.kind != row.kind);
    row.has_secret = match (&existing, secret) {
        (_, Some(_)) => true,
        (Some(e), None) => e.has_secret && !kind_changed,
        (None, None) => false,
    };
    if let Some(e) = &existing {
        row.created_at = e.created_at;
    } else if row.created_at <= 0 {
        row.created_at = now_ts();
    }
    store.save_credential(&row)?;
    if kind_changed && secret.is_none() {
        creds.delete(&account)?;
    }
    if let Some(secret) = secret {
        creds.save(
            &account,
            &StoredCredentials {
                secret: Some(secret.to_string()),
                ..Default::default()
            },
        )?;
    }
    Ok(store.get_credential(&row.id)?.unwrap_or(row))
}

/// Deletes a saved credential and its secret, unlinking every host that
/// used it, and returns those hosts' ids.
///
/// With `keep_on_hosts`, each of those hosts first gets its own copy of what
/// it was signing in with (and, for a key, the key file in its SSH
/// settings), so it keeps connecting without a prompt. Without it, each
/// falls back to whatever it held itself, which for a host that was set up
/// with the saved credential is nothing: it asks on the next connect.
///
/// A copy that cannot be written (the store is locked) fails the whole call
/// before anything is deleted.
pub fn delete_credential_profile(
    store: &Store,
    creds: &CredentialStore,
    id: &str,
    keep_on_hosts: bool,
) -> Result<Vec<String>> {
    let mut copied = Vec::new();
    if keep_on_hosts {
        let cred = store.get_credential(id)?;
        for (host_id, _) in store.hosts_using_credential(id)? {
            let Some(mut host) = store.get_host(&host_id)? else {
                continue;
            };
            let Some(resolved) = resolve_host_credentials(store, creds, &host_id)? else {
                continue;
            };
            creds.save(&host_id, &resolved)?;
            let kind = host.protocol_kind();
            host.has_password = kind.is_some_and(|k| resolved.has_for(k)) || host.has_password;
            if let (Some(ProtocolKind::Ssh), Some(cred)) = (kind, cred.as_ref()) {
                if let Ok(settings) = SshSettings::parse(host.ssh_settings.as_deref()) {
                    let mut settings = settings.unwrap_or_default();
                    cred.apply_ssh_options(&mut settings.options);
                    host.ssh_settings = Some(settings.to_json()?);
                }
            }
            host.credential_id = None;
            store.save_host(&host)?;
            copied.push(host_id);
        }
    }
    let mut unlinked = store.delete_credential(id)?;
    unlinked.extend(copied);
    unlinked.sort();
    match creds.delete(&CredentialProfile::secret_account(id)) {
        Ok(()) => {}
        // The row is gone, so nothing will ever read the secret again; a
        // locked store keeps it until it is unlocked and is not worth failing
        // a delete the person already confirmed.
        Err(Error::Locked) => {
            tracing::info!("the credential store is locked; a deleted credential's secret stays until it is unlocked")
        }
        Err(e) => return Err(e),
    }
    Ok(unlinked)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway secret made at run time, so no password sits in the source.
    fn test_secret() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn stores() -> (tempfile::TempDir, Store, CredentialStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
        let creds = CredentialStore::new_with_file_backend(dir.path().to_path_buf());
        creds.set_kdf_params_for_tests(8, 1, 1);
        creds.unlock(&test_secret()).unwrap();
        (dir, store, creds)
    }

    fn host(name: &str, protocol: ProtocolKind) -> HostProfile {
        HostProfile {
            friendly_name: name.into(),
            address: format!("{}.example.com", name.to_lowercase()),
            ..HostProfile::for_protocol(protocol)
        }
    }

    fn admin() -> CredentialProfile {
        CredentialProfile {
            name: "Office admin".into(),
            username: Some("admin".into()),
            domain: Some("CORP".into()),
            ..Default::default()
        }
    }

    #[test]
    fn a_saved_credential_round_trips_without_its_secret_in_the_row() {
        let (_dir, store, creds) = stores();
        let saved = save_credential_profile(&store, &creds, &admin(), Some("hunter2")).unwrap();
        assert!(saved.has_secret);
        assert!(saved.created_at > 0);
        let listed = store.list_credentials().unwrap();
        assert_eq!(listed, vec![saved.clone()]);
        let json = serde_json::to_string(&listed).unwrap();
        assert!(
            !json.contains("hunter2"),
            "the row never carries the secret: {json}"
        );
        let blob = creds
            .load(&CredentialProfile::secret_account(&saved.id))
            .unwrap()
            .unwrap();
        assert_eq!(blob.secret.as_deref(), Some("hunter2"));
    }

    #[test]
    fn a_save_without_a_secret_keeps_the_stored_one() {
        let (_dir, store, creds) = stores();
        let saved = save_credential_profile(&store, &creds, &admin(), Some("one")).unwrap();
        let renamed = CredentialProfile {
            name: "Renamed".into(),
            has_secret: false, // what a confused webview might send
            ..saved.clone()
        };
        let again = save_credential_profile(&store, &creds, &renamed, None).unwrap();
        assert!(again.has_secret);
        assert_eq!(again.name, "Renamed");
        assert_eq!(again.created_at, saved.created_at);
        let blob = creds
            .load(&CredentialProfile::secret_account(&saved.id))
            .unwrap()
            .unwrap();
        assert_eq!(blob.secret.as_deref(), Some("one"));
    }

    #[test]
    fn changing_the_kind_forgets_a_password_rather_than_using_it_as_a_passphrase() {
        let (_dir, store, creds) = stores();
        let saved = save_credential_profile(&store, &creds, &admin(), Some("pw")).unwrap();
        let key = CredentialProfile {
            kind: "ssh-key".into(),
            key_path: Some("/keys/id_ed25519".into()),
            ..saved.clone()
        };
        let again = save_credential_profile(&store, &creds, &key, None).unwrap();
        assert!(!again.has_secret);
        assert!(creds
            .load(&CredentialProfile::secret_account(&saved.id))
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_credential_needs_a_name_and_a_known_kind() {
        let (_dir, store, creds) = stores();
        let nameless = CredentialProfile::default();
        assert!(save_credential_profile(&store, &creds, &nameless, None).is_err());
        let odd = CredentialProfile {
            name: "x".into(),
            kind: "smartcard".into(),
            ..Default::default()
        };
        assert!(save_credential_profile(&store, &creds, &odd, None).is_err());
    }

    /// The point of the feature: one change reaches every host that uses it.
    #[test]
    fn changing_a_shared_password_changes_it_for_every_host() {
        let (_dir, store, creds) = stores();
        let cred = save_credential_profile(&store, &creds, &admin(), Some("old")).unwrap();
        let mut rdp = host("Desk", ProtocolKind::Rdp);
        rdp.credential_id = Some(cred.id.clone());
        let mut ssh = host("Box", ProtocolKind::Ssh);
        ssh.credential_id = Some(cred.id.clone());
        let mut vnc = host("Pi", ProtocolKind::Vnc);
        vnc.credential_id = Some(cred.id.clone());
        for h in [&rdp, &ssh, &vnc] {
            store.save_host(h).unwrap();
        }

        let got = resolve_host_credentials(&store, &creds, &rdp.id)
            .unwrap()
            .unwrap();
        assert_eq!(got.rdp_user.as_deref(), Some("admin"));
        assert_eq!(got.rdp_domain.as_deref(), Some("CORP"));
        assert_eq!(got.rdp_password.as_deref(), Some("old"));

        save_credential_profile(&store, &creds, &cred, Some("new")).unwrap();

        let rdp_now = resolve_host_credentials(&store, &creds, &rdp.id)
            .unwrap()
            .unwrap();
        assert_eq!(rdp_now.rdp_password.as_deref(), Some("new"));
        let ssh_now = resolve_host_credentials(&store, &creds, &ssh.id)
            .unwrap()
            .unwrap();
        assert_eq!(ssh_now.ssh_user.as_deref(), Some("admin"));
        assert_eq!(ssh_now.ssh_password.as_deref(), Some("new"));
        let vnc_now = resolve_host_credentials(&store, &creds, &vnc.id)
            .unwrap()
            .unwrap();
        assert_eq!(vnc_now.vencrypt_user.as_deref(), Some("admin"));
        assert_eq!(vnc_now.vencrypt_pass.as_deref(), Some("new"));
        assert_eq!(vnc_now.vnc_password.as_deref(), Some("new"));
        for c in [&rdp_now, &ssh_now, &vnc_now] {
            assert!(
                c.secret.is_none(),
                "the raw secret slot never leaves resolution"
            );
        }
    }

    #[test]
    fn a_host_with_its_own_password_is_untouched() {
        let (_dir, store, creds) = stores();
        save_credential_profile(&store, &creds, &admin(), Some("shared")).unwrap();
        let own = host("Own", ProtocolKind::Vnc);
        store.save_host(&own).unwrap();
        let mut mine = StoredCredentials::default();
        let mine_pw = test_secret();
        mine.set_vnc_credential(None, &mine_pw);
        creds.save(&own.id, &mine).unwrap();
        let got = resolve_host_credentials(&store, &creds, &own.id)
            .unwrap()
            .unwrap();
        assert_eq!(got.vnc_password.as_deref(), Some(mine_pw.as_str()));
        assert!(got.vencrypt_user.is_none());
    }

    /// A linked host keeps the parts of its own entry the credential does
    /// not cover, and loses the ones it does, so an old user name of its own
    /// never pairs with the shared password.
    #[test]
    fn the_shared_credential_replaces_identity_fields_and_keeps_the_rest() {
        let (_dir, store, creds) = stores();
        let cred = save_credential_profile(
            &store,
            &creds,
            &CredentialProfile {
                name: "No domain".into(),
                username: Some("bob".into()),
                ..Default::default()
            },
            Some("shared"),
        )
        .unwrap();
        let mut rdp = host("Gw", ProtocolKind::Rdp);
        rdp.credential_id = Some(cred.id.clone());
        store.save_host(&rdp).unwrap();
        let mut own = StoredCredentials::default();
        let gateway_pw = test_secret();
        own.set_rdp_identity(Some("old"), Some("OLDDOM"), &test_secret());
        own.rdg_password = Some(gateway_pw.clone());
        creds.save(&rdp.id, &own).unwrap();

        let got = resolve_host_credentials(&store, &creds, &rdp.id)
            .unwrap()
            .unwrap();
        assert_eq!(got.rdp_user.as_deref(), Some("bob"));
        assert_eq!(got.rdp_domain, None, "a stale domain does not survive");
        assert_eq!(got.rdp_password.as_deref(), Some("shared"));
        assert_eq!(got.rdg_password.as_deref(), Some(gateway_pw.as_str()));
    }

    #[test]
    fn a_key_credential_signs_in_with_its_file_and_passphrase() {
        let (_dir, store, creds) = stores();
        let key = save_credential_profile(
            &store,
            &creds,
            &CredentialProfile {
                name: "Lab key".into(),
                kind: "ssh-key".into(),
                username: Some("ops".into()),
                key_path: Some("/keys/lab".into()),
                ..Default::default()
            },
            Some("pass"),
        )
        .unwrap();
        let mut ssh = host("Lab", ProtocolKind::Ssh);
        ssh.credential_id = Some(key.id.clone());
        store.save_host(&ssh).unwrap();

        let got = resolve_host_credentials(&store, &creds, &ssh.id)
            .unwrap()
            .unwrap();
        assert_eq!(got.ssh_user.as_deref(), Some("ops"));
        assert_eq!(got.ssh_passphrase.as_deref(), Some("pass"));

        let mut options = SshOptions::default();
        assert_eq!(options.auth, SshAuthKind::Agent);
        key.apply_ssh_options(&mut options);
        assert_eq!(options.auth, SshAuthKind::KeyFile);
        assert_eq!(options.key_path.as_deref(), Some("/keys/lab"));
    }

    /// Only credentials compatible with the host's protocol apply. A key on a
    /// VNC host (the host was switched after it was linked) is ignored.
    #[test]
    fn a_credential_that_does_not_fit_the_protocol_is_ignored() {
        let key = CredentialProfile {
            name: "k".into(),
            kind: "ssh-key".into(),
            ..Default::default()
        };
        assert!(key.fits(ProtocolKind::Ssh));
        assert!(!key.fits(ProtocolKind::Vnc));
        assert!(!key.fits(ProtocolKind::Rdp));
        assert!(!key.fits(ProtocolKind::Boundary));
        assert!(admin().fits(ProtocolKind::Vnc));
        assert!(admin().fits(ProtocolKind::Rdp));
        assert!(admin().fits(ProtocolKind::Ssh));
        assert!(!admin().fits(ProtocolKind::Boundary));

        let (_dir, store, creds) = stores();
        let key = save_credential_profile(&store, &creds, &key, Some("kp")).unwrap();
        let mut vnc = host("Switched", ProtocolKind::Vnc);
        vnc.credential_id = Some(key.id.clone());
        store.save_host(&vnc).unwrap();
        assert!(resolve_host_credentials(&store, &creds, &vnc.id)
            .unwrap()
            .is_none());
    }

    /// A host whose credential is gone (a row restored from a backup, or a
    /// delete from a build that did not unlink) is still a host: it falls
    /// back to its own entry and asks.
    #[test]
    fn a_host_whose_credential_is_gone_falls_back_to_its_own() {
        let (_dir, store, creds) = stores();
        let mut h = host("Orphan", ProtocolKind::Rdp);
        h.credential_id = Some("no-such-credential".into());
        store.save_host(&h).unwrap();
        assert!(resolve_host_credentials(&store, &creds, &h.id)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .get_host(&h.id)
                .unwrap()
                .unwrap()
                .credential_id
                .as_deref(),
            Some("no-such-credential"),
            "listing and editing it still works"
        );
    }

    #[test]
    fn deleting_a_credential_unlinks_its_hosts_and_removes_the_secret() {
        let (_dir, store, creds) = stores();
        let cred = save_credential_profile(&store, &creds, &admin(), Some("pw")).unwrap();
        let mut a = host("A", ProtocolKind::Rdp);
        a.credential_id = Some(cred.id.clone());
        let b = host("B", ProtocolKind::Rdp);
        store.save_host(&a).unwrap();
        store.save_host(&b).unwrap();
        assert_eq!(
            store.hosts_using_credential(&cred.id).unwrap(),
            vec![(a.id.clone(), "A".to_string())]
        );

        let unlinked = delete_credential_profile(&store, &creds, &cred.id, false).unwrap();
        assert_eq!(unlinked, vec![a.id.clone()]);
        assert!(store.get_credential(&cred.id).unwrap().is_none());
        assert_eq!(store.get_host(&a.id).unwrap().unwrap().credential_id, None);
        assert!(creds
            .load(&CredentialProfile::secret_account(&cred.id))
            .unwrap()
            .is_none());
        // Nothing to sign in with now: the next connect asks.
        assert!(resolve_host_credentials(&store, &creds, &a.id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn deleting_with_keep_gives_each_host_its_own_copy() {
        let (_dir, store, creds) = stores();
        let cred = save_credential_profile(&store, &creds, &admin(), Some("pw")).unwrap();
        let key = save_credential_profile(
            &store,
            &creds,
            &CredentialProfile {
                name: "Key".into(),
                kind: "ssh-key".into(),
                username: Some("ops".into()),
                key_path: Some("/keys/k".into()),
                ..Default::default()
            },
            Some("kp"),
        )
        .unwrap();
        let mut rdp = host("Desk", ProtocolKind::Rdp);
        rdp.credential_id = Some(cred.id.clone());
        let mut ssh = host("Term", ProtocolKind::Ssh);
        ssh.credential_id = Some(key.id.clone());
        store.save_host(&rdp).unwrap();
        store.save_host(&ssh).unwrap();

        assert_eq!(
            delete_credential_profile(&store, &creds, &cred.id, true).unwrap(),
            vec![rdp.id.clone()],
            "the hosts that were given a copy are the ones unlinked"
        );
        delete_credential_profile(&store, &creds, &key.id, true).unwrap();

        let rdp_row = store.get_host(&rdp.id).unwrap().unwrap();
        assert_eq!(rdp_row.credential_id, None);
        assert!(rdp_row.has_password);
        let own = creds.load(&rdp.id).unwrap().unwrap();
        assert_eq!(own.rdp_user.as_deref(), Some("admin"));
        assert_eq!(own.rdp_password.as_deref(), Some("pw"));

        let ssh_row = store.get_host(&ssh.id).unwrap().unwrap();
        let settings = SshSettings::parse(ssh_row.ssh_settings.as_deref())
            .unwrap()
            .unwrap();
        assert_eq!(settings.options.auth, SshAuthKind::KeyFile);
        assert_eq!(settings.options.key_path.as_deref(), Some("/keys/k"));
        let own = creds.load(&ssh.id).unwrap().unwrap();
        assert_eq!(own.ssh_user.as_deref(), Some("ops"));
        assert_eq!(own.ssh_passphrase.as_deref(), Some("kp"));
        assert!(store.list_credentials().unwrap().is_empty());
    }

    #[test]
    fn a_locked_store_stops_a_keep_delete_before_it_deletes_anything() {
        let (_dir, store, creds) = stores();
        let cred = save_credential_profile(&store, &creds, &admin(), Some("pw")).unwrap();
        let mut a = host("A", ProtocolKind::Rdp);
        a.credential_id = Some(cred.id.clone());
        store.save_host(&a).unwrap();
        creds.lock();
        assert!(delete_credential_profile(&store, &creds, &cred.id, true).is_err());
        assert!(store.get_credential(&cred.id).unwrap().is_some());
        assert_eq!(
            store
                .get_host(&a.id)
                .unwrap()
                .unwrap()
                .credential_id
                .as_deref(),
            Some(cred.id.as_str())
        );
    }
}
