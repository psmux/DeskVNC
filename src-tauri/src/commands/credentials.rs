//! Credential commands.
//!
//! SECURITY INVARIANT (PRD/01 §5, PRD/10): **the webview must never receive a
//! password back.** Passwords flow JS → Rust exactly once, at save time, and
//! are loaded internally (in `session::connect_session`, on a blocking
//! thread) when building `ConnectOptions`. There is deliberately no
//! `get_password` command, and `CredentialStore::load` is never exposed here.
//!
//! Keychain / Secret-Service calls are synchronous, so everything hops to a
//! blocking thread via [`super::blocking`].

use tauri::State;
use vnc_store::StoredCredentials;

use crate::state::AppState;

/// Store credentials for a host, keyed by host id, renaming a host never
/// orphans its credential (PRD/03 §5).
///
/// MERGES field-by-field rather than replacing the blob: only the fields the
/// caller sent (non-null) are overwritten. A host can hold a VNC password
/// *and* an SSH passphrase (used by the Files panel and the SSH tunnel), and
/// they are saved from different places in the UI; replacing wholesale meant
/// saving one silently erased the other. This is the same rule the
/// post-connect save applies (`PendingCredentialSave::merge_into`). Removing
/// credentials is `delete_password`, which drops the whole entry.
#[tauri::command]
pub async fn save_password(
    state: State<'_, AppState>,
    host_id: String,
    creds: StoredCredentials,
) -> Result<(), String> {
    let credentials = state.credentials.clone();
    let store = state.store.clone();
    super::blocking(move || {
        let existing = match credentials.load(&host_id) {
            Ok(existing) => existing.unwrap_or_default(),
            Err(e) => {
                // An unreadable (e.g. locked) store must not eat the new
                // secret; save what was sent rather than failing the dialog.
                tracing::warn!("could not read existing credentials before save: {e}");
                StoredCredentials::default()
            }
        };
        let merged = merge_dialog_write(creds, existing);
        credentials.save(&host_id, &merged)?;
        // The library row carries the flag the editor and the key icon read.
        // Only a successful connect used to set it, so a password saved in
        // the editor came back looking blank the next time it was opened.
        if holds_password(&merged) {
            mark_saved(&store, &host_id, true);
        }
        Ok::<(), vnc_store::Error>(())
    })
    .await
}

/// A password of any kind. An SSH key passphrase alone does not count: the
/// key icon has always meant "you will not be asked for a password".
fn holds_password(creds: &StoredCredentials) -> bool {
    creds.vnc_password.is_some()
        || creds.vencrypt_pass.is_some()
        || creds.rdp_password.is_some()
        || creds.ssh_password.is_some()
}

/// Set the library row's `has_password`. A failure here is logged and not
/// returned: the secret itself is already where it belongs.
fn mark_saved(store: &vnc_store::Store, host_id: &str, saved: bool) {
    match store.get_host(host_id) {
        Ok(Some(mut profile)) if profile.has_password != saved => {
            profile.has_password = saved;
            if let Err(e) = store.save_host(&profile) {
                tracing::warn!(host = %host_id, "could not update has_password: {e}");
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(host = %host_id, "could not load host: {e}"),
    }
}

/// The account names saved for a host, so the editor can show them. A user
/// name is not a secret; the passwords beside it still never leave Rust.
#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedUserNames {
    pub vnc_user: Option<String>,
    pub rdp_user: Option<String>,
    pub rdp_domain: Option<String>,
    pub ssh_user: Option<String>,
}

impl From<&StoredCredentials> for SavedUserNames {
    fn from(c: &StoredCredentials) -> Self {
        Self {
            vnc_user: c.vencrypt_user.clone(),
            rdp_user: c.rdp_user.clone(),
            rdp_domain: c.rdp_domain.clone(),
            ssh_user: c.ssh_user.clone(),
        }
    }
}

#[tauri::command]
pub async fn saved_user_names(
    state: State<'_, AppState>,
    host_id: String,
) -> Result<SavedUserNames, String> {
    let credentials = state.credentials.clone();
    super::blocking(move || {
        credentials
            .load(&host_id)
            .map(|blob: Option<StoredCredentials>| {
                blob.as_ref().map(SavedUserNames::from).unwrap_or_default()
            })
    })
    .await
}

/// Fill the stored blob in with what the host editor sent.
///
/// Every field is `sent.or(stored)`, and the literal is exhaustive on
/// purpose: adding a credential field to the store breaks this line rather
/// than silently defaulting the new field away, which is what forces a
/// decision about the merge rule here (PRDRDP/08 §3.4).
///
/// `.or` is the rule for THIS caller and not for every caller. This is a
/// dialog write, and a dialog that did not show a field must not erase it.
/// The post-connect save is the other case: it runs after a handshake with a
/// complete set, so it replaces rather than fills in, and it lives in
/// `PendingCredentialSave::merge_into`.
fn merge_dialog_write(creds: StoredCredentials, existing: StoredCredentials) -> StoredCredentials {
    StoredCredentials {
        vnc_password: creds.vnc_password.or(existing.vnc_password),
        vencrypt_user: creds.vencrypt_user.or(existing.vencrypt_user),
        vencrypt_pass: creds.vencrypt_pass.or(existing.vencrypt_pass),
        ssh_passphrase: creds.ssh_passphrase.or(existing.ssh_passphrase),
        rdp_user: creds.rdp_user.or(existing.rdp_user),
        rdp_domain: creds.rdp_domain.or(existing.rdp_domain),
        rdp_password: creds.rdp_password.or(existing.rdp_password),
        ssh_user: creds.ssh_user.or(existing.ssh_user),
        ssh_password: creds.ssh_password.or(existing.ssh_password),
    }
}

/// Whether a credential exists for this host (drives the key icon in the
/// library). The blob is loaded on the Rust side purely for the existence
/// check, only the boolean crosses the IPC boundary.
///
/// `protocol` narrows the question to "a credential this protocol could
/// use". Without it the answer is "any credential at all", which is what the
/// key icon has always meant and which stays the behaviour when the argument
/// is absent. With two protocols the coarse answer starts lying: a host with
/// only an SSH passphrase, or with only a VNC password on a profile that has
/// since been switched to RDP, would claim to have what it needs.
#[tauri::command]
pub async fn has_password(
    state: State<'_, AppState>,
    host_id: String,
    protocol: Option<vnc_store::ProtocolKind>,
) -> Result<bool, String> {
    let credentials = state.credentials.clone();
    super::blocking(move || {
        credentials
            .load(&host_id)
            .map(|blob| match (blob, protocol) {
                (Some(creds), Some(kind)) => creds.has_for(kind),
                (blob, _) => blob.is_some(),
            })
    })
    .await
}

#[tauri::command]
pub async fn delete_password(state: State<'_, AppState>, host_id: String) -> Result<(), String> {
    let credentials = state.credentials.clone();
    let store = state.store.clone();
    super::blocking(move || {
        credentials.delete(&host_id)?;
        // Without this the key icon came back on the next start.
        mark_saved(&store, &host_id, false);
        Ok::<(), vnc_store::Error>(())
    })
    .await
}

/// Which backend is in use (`"OsKeychain"`, `"EncryptedFile"`, or
/// `"Locked"`), so the UI can explain where secrets live and whether an
/// unlock is needed.
#[tauri::command]
pub async fn credential_backend(
    state: State<'_, AppState>,
) -> Result<vnc_store::CredentialBackend, String> {
    let credentials = state.credentials.clone();
    tokio::task::spawn_blocking(move || credentials.backend())
        .await
        .map_err(|e| e.to_string())
}

/// Unlock the encrypted-file fallback store with the master password.
/// The master password flows JS → Rust only; nothing is returned.
#[tauri::command]
pub async fn unlock_credentials(
    state: State<'_, AppState>,
    master_password: String,
) -> Result<(), String> {
    let credentials = state.credentials.clone();
    super::blocking(move || credentials.unlock(&master_password)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payload exactly as `vncCredentialPayload` in
    /// `ui/src/lib/hostDraft.ts` sends it over IPC.
    fn sent(json: &str) -> StoredCredentials {
        serde_json::from_str(json).expect("the IPC shape parses")
    }

    #[test]
    fn a_vnc_user_name_from_the_editor_is_stored_beside_its_password() {
        let merged = merge_dialog_write(
            sent(r#"{"vencryptUser":"godwin","vencryptPass":"secret"}"#),
            StoredCredentials::default(),
        );
        assert_eq!(merged.vencrypt_user.as_deref(), Some("godwin"));
        assert_eq!(merged.vencrypt_pass.as_deref(), Some("secret"));
        assert_eq!(merged.vnc_password, None);
    }

    #[test]
    fn a_user_name_typed_alone_keeps_the_saved_password() {
        let existing = StoredCredentials {
            vnc_password: Some("old".into()),
            ssh_passphrase: Some("key".into()),
            ..Default::default()
        };
        let merged = merge_dialog_write(sent(r#"{"vencryptUser":"godwin"}"#), existing);
        assert_eq!(merged.vencrypt_user.as_deref(), Some("godwin"));
        assert_eq!(merged.vnc_password.as_deref(), Some("old"));
        assert_eq!(merged.ssh_passphrase.as_deref(), Some("key"));
    }

    #[test]
    fn a_passphrase_alone_is_not_a_saved_password() {
        let key = sent(r#"{"sshPassphrase":"k"}"#);
        assert!(!holds_password(&key));
        assert!(holds_password(&sent(
            r#"{"vencryptUser":"a","vencryptPass":"p"}"#
        )));
        assert!(holds_password(&sent(r#"{"rdpPassword":"p"}"#)));
    }

    #[test]
    fn saved_user_names_carry_no_password() {
        let names = SavedUserNames::from(&sent(
            r#"{"vencryptUser":"alice","vencryptPass":"p","rdpUser":"bob","rdpDomain":"CORP","rdpPassword":"q"}"#,
        ));
        let json = serde_json::to_string(&names).unwrap();
        assert_eq!(
            json,
            r#"{"vncUser":"alice","rdpUser":"bob","rdpDomain":"CORP","sshUser":null}"#
        );
    }

    #[test]
    fn a_password_typed_alone_keeps_the_saved_user_name() {
        let existing = StoredCredentials {
            vencrypt_user: Some("godwin".into()),
            vencrypt_pass: Some("old".into()),
            ..Default::default()
        };
        let merged = merge_dialog_write(sent(r#"{"vencryptPass":"new"}"#), existing);
        assert_eq!(merged.vencrypt_user.as_deref(), Some("godwin"));
        assert_eq!(merged.vencrypt_pass.as_deref(), Some("new"));
    }
}
