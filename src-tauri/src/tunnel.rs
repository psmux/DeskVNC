//! SSH tunnelling for the RFB stream: the shell half.
//!
//! A host profile's `ssh_tunnel` column holds the JSON blob
//! [`SshTunnelSettings`]. When it is present and enabled, `connect_session`
//! calls [`establish`] before spawning the session; the returned connector is
//! injected into `vnc_core::ConnectOptions`, and every connection attempt,
//! including the supervisor's automatic reconnects, then runs over a
//! `direct-tcpip` channel instead of a local TCP socket (see
//! `vnc_files::tunnel`).
//!
//! SECURITY INVARIANTS (same as the SFTP sidecar, `commands/files.rs`):
//! - The webview only ever picks an auth *kind*; passwords/passphrases are
//!   loaded from the keychain here in Rust and never cross back into JS.
//! - Host keys are trust-on-first-use against the same pin store the Files
//!   panel uses. An unknown key becomes a prompt outcome; a *changed* key is
//!   a hard stop with no "continue anyway".

use std::sync::Arc;

use tauri::{AppHandle, Manager};
use vnc_files::{Error as FilesError, FileTransferConfig, SshTunnel};
use vnc_transport::{BoxedStream, ConnectFuture, StreamConnector, TransportError};

use crate::commands::files::{build_auth, local_username, AuthKind, FilesState};

/// The `hosts.ssh_tunnel` JSON blob (camelCase, written by the host editor).
///
/// Unknown fields are ignored so a blob written by a newer build still parses;
/// a blob that fails to parse fails the connect instead of silently skipping
/// the tunnel, connecting in the clear when the user asked for a tunnel is
/// exactly the failure mode this feature exists to prevent.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshTunnelSettings {
    #[serde(default)]
    pub enabled: bool,
    /// SSH gateway host. Empty means "the profile's VNC address", the common
    /// case where VNC and SSH live on the same machine.
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Remote user. Empty means "same as the local user".
    #[serde(default)]
    pub user: String,
    #[serde(default = "default_auth")]
    pub auth: AuthKind,
    /// Private key path for `key-file` auth.
    #[serde(default)]
    pub key_path: Option<String>,
}

fn default_ssh_port() -> u16 {
    vnc_files::DEFAULT_SSH_PORT
}

fn default_auth() -> AuthKind {
    AuthKind::Stored
}

impl SshTunnelSettings {
    /// Parse the stored blob. `None` when the column is empty/null-ish.
    pub fn parse(raw: &str) -> Result<Option<Self>, String> {
        let raw = raw.trim();
        if raw.is_empty() || raw == "null" {
            return Ok(None);
        }
        serde_json::from_str(raw)
            .map(Some)
            .map_err(|e| format!("the ssh tunnel settings could not be read: {e}"))
    }
}

/// What [`establish`] produced.
pub enum TunnelOutcome {
    /// Tunnel up; inject this into `ConnectOptions::connector`.
    Ready(vnc_core::Connector),
    /// First contact with the gateway's host key: the UI must prompt, then
    /// call `connect_session` again with `acceptSshHostKey`.
    HostKeyPrompt {
        host: String,
        port: u16,
        key_type: String,
        fingerprint: String,
    },
    /// The pinned gateway key changed. HARD STOP.
    HostKeyChanged {
        host: String,
        port: u16,
        expected: String,
        actual: String,
    },
}

/// Dial the SSH gateway for a tunnelled profile and wrap it as a connector.
///
/// `accept_host_key` mirrors `files_connect`: when it equals the fingerprint
/// of a first-contact prompt the key is pinned (persistently) and the dial is
/// retried exactly once.
pub async fn establish(
    app: &AppHandle,
    settings: &SshTunnelSettings,
    vnc_address: &str,
    profile_id: Option<&str>,
    accept_host_key: Option<&str>,
) -> Result<TunnelOutcome, String> {
    let auth = build_auth(app, settings.auth, settings.key_path.as_deref(), profile_id).await?;
    let username = if settings.user.trim().is_empty() {
        local_username()?
    } else {
        settings.user.clone()
    };
    let gateway = if settings.host.trim().is_empty() {
        vnc_address.to_string()
    } else {
        settings.host.trim().to_string()
    };

    let mut cfg = FileTransferConfig::new(gateway, username);
    cfg.port = settings.port;
    cfg.auth = auth;

    let files = app.state::<FilesState>();
    let pins = files.host_key_verifier();

    let tunnel = match SshTunnel::connect(cfg.clone(), pins.clone()).await {
        Ok(tunnel) => tunnel,
        Err(FilesError::HostKeyUnknown {
            host,
            port,
            key_type,
            fingerprint,
        }) => {
            // The user already saw this fingerprint and accepted it: pin and
            // retry exactly once, the same dance as `files_connect`.
            if accept_host_key == Some(fingerprint.as_str()) {
                files.trust_host_key(&host, port, &key_type, &fingerprint);
                SshTunnel::connect(cfg.clone(), pins)
                    .await
                    .map_err(|e| e.to_string())?
            } else {
                return Ok(TunnelOutcome::HostKeyPrompt {
                    host,
                    port,
                    key_type,
                    fingerprint,
                });
            }
        }
        // HARD STOP. Never promptable, never retried (PRD/08 §4, PRD/10 §4.3).
        Err(FilesError::HostKeyChanged {
            host,
            port,
            expected,
            actual,
        }) => {
            tracing::error!(%host, port, "ssh host key CHANGED, refusing to tunnel");
            return Ok(TunnelOutcome::HostKeyChanged {
                host,
                port,
                expected,
                actual,
            });
        }
        Err(e) => return Err(e.to_string()),
    };

    // A successful connect means the pin verified; refresh last-seen.
    files.touch_host_key(&cfg.host, cfg.port);

    Ok(TunnelOutcome::Ready(vnc_core::Connector(Arc::new(
        TunnelConnector {
            tunnel: Arc::new(tunnel),
        },
    ))))
}

/// Adapter: a [`SshTunnel`] as the session core's [`StreamConnector`].
///
/// Lives here rather than in `vnc-files` so that crate stays free of a
/// `vnc-transport` dependency; the shell is the one place that knows both.
struct TunnelConnector {
    tunnel: Arc<SshTunnel>,
}

impl StreamConnector for TunnelConnector {
    fn connect(&self, host: &str, port: u16, timeout: std::time::Duration) -> ConnectFuture<'_> {
        let host = host.to_string();
        Box::pin(async move {
            let opening = self.tunnel.open_stream(&host, port);
            let stream = match tokio::time::timeout(timeout, opening).await {
                Err(_) => return Err(TransportError::Timeout),
                Ok(Ok(stream)) => stream,
                Ok(Err(FilesError::Timeout)) => return Err(TransportError::Timeout),
                Ok(Err(e)) => return Err(TransportError::Io(std::io::Error::other(e.to_string()))),
            };
            Ok(Box::pin(stream) as BoxedStream)
        })
    }

    fn describe(&self) -> String {
        format!("ssh tunnel via {}", self.tunnel.endpoint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_null_blob_means_no_tunnel() {
        assert!(SshTunnelSettings::parse("").unwrap().is_none());
        assert!(SshTunnelSettings::parse("  ").unwrap().is_none());
        assert!(SshTunnelSettings::parse("null").unwrap().is_none());
    }

    #[test]
    fn a_full_blob_parses_with_camel_case_keys() {
        let settings = SshTunnelSettings::parse(
            r#"{ "enabled": true, "host": "gate.example.com", "port": 2222,
                 "user": "pi", "auth": "key-file", "keyPath": "/home/pi/.ssh/id_ed25519" }"#,
        )
        .unwrap()
        .unwrap();
        assert!(settings.enabled);
        assert_eq!(settings.host, "gate.example.com");
        assert_eq!(settings.port, 2222);
        assert_eq!(settings.user, "pi");
        assert_eq!(settings.auth, AuthKind::KeyFile);
        assert_eq!(
            settings.key_path.as_deref(),
            Some("/home/pi/.ssh/id_ed25519")
        );
    }

    #[test]
    fn defaults_cover_everything_but_enabled() {
        let settings = SshTunnelSettings::parse(r#"{ "enabled": true }"#)
            .unwrap()
            .unwrap();
        assert!(settings.enabled);
        assert_eq!(settings.host, "");
        assert_eq!(settings.port, 22);
        assert_eq!(settings.user, "");
        assert_eq!(settings.auth, AuthKind::Stored);
        assert!(settings.key_path.is_none());

        let disabled = SshTunnelSettings::parse(r#"{}"#).unwrap().unwrap();
        assert!(!disabled.enabled);
    }

    /// A malformed blob must fail the connect, not silently skip the tunnel:
    /// connecting in the clear when a tunnel was asked for is the one failure
    /// mode this feature exists to prevent.
    #[test]
    fn a_malformed_blob_is_an_error_not_a_silent_skip() {
        assert!(SshTunnelSettings::parse("{not json").is_err());
        assert!(SshTunnelSettings::parse(r#"{"enabled": "maybe"}"#).is_err());
    }

    /// A blob written by a newer build with extra fields must still parse.
    #[test]
    fn unknown_fields_are_tolerated() {
        let settings =
            SshTunnelSettings::parse(r#"{ "enabled": true, "hopCount": 3, "host": "h" }"#)
                .unwrap()
                .unwrap();
        assert!(settings.enabled);
        assert_eq!(settings.host, "h");
    }
}
