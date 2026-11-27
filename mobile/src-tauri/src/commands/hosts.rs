//! `hosts_*`: the saved computers.

use tauri::State;

use super::blocking;
use crate::state::AppState;
use crate::store::{validate_id, Host, HostDraft};
use crate::thumbs;
use crate::tunnel::{TunnelSecret, MAX_KEY};
use crate::vault::Secret;

#[tauri::command]
pub async fn hosts_list(state: State<'_, AppState>) -> Result<Vec<Host>, String> {
    Ok(state.hosts.list())
}

#[tauri::command]
pub async fn hosts_save(state: State<'_, AppState>, host: HostDraft) -> Result<Host, String> {
    let hosts = state.hosts.clone();
    blocking(move || hosts.save(host)).await
}

/// Delete a host, its saved password, its tunnel's secret and its
/// thumbnail. The SSH key trusted for its tunnel is forgotten too, which is
/// how a person gets past "the SSH computer's key changed" after that
/// computer was set up again: remove it and add it back.
#[tauri::command]
pub async fn hosts_delete(state: State<'_, AppState>, id: String) -> Result<(), String> {
    validate_id(&id).map_err(|e| e.to_string())?;
    if let Some(host) = state.hosts.get(&id) {
        if let Some(tunnel) = &host.ssh_tunnel {
            if let Err(error) = state
                .known_hosts
                .forget(&tunnel.gateway(&host.address), tunnel.port)
            {
                tracing::warn!(%error, "could not forget a tunnel's host key");
            }
        }
    }
    let hosts = state.hosts.clone();
    let secrets = state.secrets.clone();
    let thumbs_dir = state.thumbs_dir.clone();
    blocking(move || {
        hosts.delete(&id).map_err(|e| e.to_string())?;
        thumbs::delete(&thumbs_dir, &id);
        secrets.delete_tunnel(&id)?;
        secrets.delete(&id)
    })
    .await
}

/// Set the SSH tunnel's password, or its private key and passphrase.
///
/// Each value follows the `hosts_set_secret` rule: a string is stored in the
/// platform vault, `null` keeps what is there, and an empty string forgets
/// it. A new password and a new key replace each other, since a tunnel signs
/// in one way. Nothing secret ever comes back to the webview; the host only
/// says `hasSshSecret`.
#[tauri::command]
pub async fn hosts_set_ssh_secret(
    state: State<'_, AppState>,
    id: String,
    password: Option<String>,
    key: Option<String>,
    passphrase: Option<String>,
) -> Result<(), String> {
    validate_id(&id).map_err(|e| e.to_string())?;
    let hosts = state.hosts.clone();
    let secrets = state.secrets.clone();
    blocking(move || {
        if hosts.get(&id).is_none() {
            return Err(format!("unknown host: {id}"));
        }
        let secret = apply_tunnel_secret(
            secrets.load_tunnel(&id)?.unwrap_or_default(),
            password,
            key,
            passphrase,
        )?;
        if secret == TunnelSecret::default() {
            secrets.delete_tunnel(&id)?;
        } else {
            secrets.save_tunnel(&id, &secret)?;
        }
        let has = secret.password.is_some() || secret.key.is_some();
        hosts
            .update(&id, |h| h.has_ssh_secret = has)
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
}

/// The rule of `hosts_set_ssh_secret`, apart from the vault so it is testable.
pub fn apply_tunnel_secret(
    mut secret: TunnelSecret,
    password: Option<String>,
    key: Option<String>,
    passphrase: Option<String>,
) -> Result<TunnelSecret, String> {
    if key.as_ref().is_some_and(|k| k.len() > MAX_KEY) {
        return Err("That private key is far too long to be one".into());
    }
    if let Some(pw) = password {
        secret.password = (!pw.is_empty()).then_some(pw);
        if secret.password.is_some() {
            secret.key = None;
            secret.passphrase = None;
        }
    }
    if let Some(k) = key {
        let k = k.trim().to_string();
        secret.key = (!k.is_empty()).then_some(k);
        if secret.key.is_some() {
            secret.password = None;
        }
    }
    if let Some(pp) = passphrase {
        secret.passphrase = (!pp.is_empty()).then_some(pp);
    }
    Ok(secret)
}

/// Set the user name and password for a host.
///
/// `username`: a string sets it, `null` leaves it as it is, and an empty
/// string clears it. `password` follows the same rule: a string is stored in
/// the platform vault, `null` keeps whatever is there, and an empty string
/// forgets it. The user name is also kept on the host itself, since it is
/// not a secret and the host card shows it.
#[tauri::command]
pub async fn hosts_set_secret(
    state: State<'_, AppState>,
    id: String,
    username: Option<String>,
    password: Option<String>,
) -> Result<(), String> {
    validate_id(&id).map_err(|e| e.to_string())?;
    let hosts = state.hosts.clone();
    let secrets = state.secrets.clone();
    blocking(move || {
        if hosts.get(&id).is_none() {
            return Err(format!("unknown host: {id}"));
        }
        let mut secret = secrets.load(&id)?.unwrap_or_default();
        if let Some(name) = &username {
            secret.username = (!name.is_empty()).then(|| name.clone());
        }
        if let Some(pw) = &password {
            secret.password = (!pw.is_empty()).then(|| pw.clone());
        }
        if secret == Secret::default() {
            secrets.delete(&id)?;
        } else {
            secrets.save(&id, &secret)?;
        }
        let has_password = secret.password.is_some();
        hosts
            .update(&id, |h| {
                if username.is_some() {
                    h.username = secret.username.clone();
                }
                h.has_password = has_password;
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
}

/// The host's thumbnail as a `data:image/jpeg;base64,` URL, or `null`.
#[tauri::command]
pub async fn hosts_thumbnail(
    state: State<'_, AppState>,
    id: String,
) -> Result<Option<String>, String> {
    validate_id(&id).map_err(|e| e.to_string())?;
    let dir = state.thumbs_dir.clone();
    blocking(move || thumbs::data_url(&dir, &id)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tunnel_secret_is_set_kept_replaced_and_forgotten() {
        let s =
            apply_tunnel_secret(TunnelSecret::default(), Some("pw".into()), None, None).unwrap();
        assert_eq!(s.password.as_deref(), Some("pw"));
        // null keeps what is there.
        let s = apply_tunnel_secret(s, None, None, None).unwrap();
        assert_eq!(s.password.as_deref(), Some("pw"));
        // A key replaces the password, trimmed of what pasting adds.
        let s = apply_tunnel_secret(s, None, Some("\n KEY \n".into()), Some("pp".into())).unwrap();
        assert_eq!(
            (
                s.password.as_deref(),
                s.key.as_deref(),
                s.passphrase.as_deref()
            ),
            (None, Some("KEY"), Some("pp"))
        );
        // A password replaces the key and its passphrase.
        let s = apply_tunnel_secret(s, Some("pw2".into()), None, None).unwrap();
        assert_eq!((s.key.as_deref(), s.passphrase.as_deref()), (None, None));
        // Empty strings forget.
        let s = apply_tunnel_secret(s, Some(String::new()), None, None).unwrap();
        assert_eq!(s, TunnelSecret::default());
        assert!(apply_tunnel_secret(
            TunnelSecret::default(),
            None,
            Some("k".repeat(MAX_KEY + 1)),
            None
        )
        .is_err());
    }
}
