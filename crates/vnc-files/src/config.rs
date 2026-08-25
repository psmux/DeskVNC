//! Connection configuration for the SFTP sidecar.
//!
//! The SSH half lives in [`ssh_transport::SshConfig`]; this adds only what the
//! *file* feature needs on top. It is `#[serde(flatten)]`ed rather than nested
//! so the IPC shape is unchanged from before the extraction: the webview still
//! sends one flat object and never learns the carrier was factored out. See
//! IPC_CONTRACT.md "Files".
//!
//! SECURITY: `SshAuth` carries secrets. It deserializes (JS → Rust) but
//! deliberately does **not** serialize, so a password or passphrase can never
//! be handed back to the webview, the same invariant `StoredCredentials`
//! holds for VNC passwords.

pub use ssh_transport::config::{
    canonical_host, host_port, resolver_host, SshAuth, SshConfig, DEFAULT_SSH_PORT,
};

/// Everything needed to open the sidecar. Built in Rust from the host profile
/// plus the keychain; the webview supplies host/port/user/auth-kind only.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTransferConfig {
    /// Where to dial, who to be, how long to wait. Flattened, so the wire
    /// shape stays `{host, port, username, auth, connectTimeoutMs, …}`.
    #[serde(flatten)]
    pub ssh: SshConfig,
    /// Where the file panel and drag-and-drop uploads start (PRD/08 §3.1).
    /// `None` means "the remote user's home directory".
    #[serde(default)]
    pub default_remote_dir: Option<String>,
    /// What to do when a destination file already exists.
    #[serde(default)]
    pub conflict: crate::transfer::ConflictPolicy,
}

impl FileTransferConfig {
    /// Minimal config: password-less agent auth against the VNC host.
    pub fn new(host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            ssh: SshConfig::new(host, username),
            default_remote_dir: None,
            conflict: crate::transfer::ConflictPolicy::default(),
        }
    }

    pub fn connect_timeout(&self) -> std::time::Duration {
        self.ssh.connect_timeout()
    }

    /// `user@host:port`, for logs and window titles. Never contains secrets.
    pub fn endpoint(&self) -> String {
        self.ssh.endpoint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::ConflictPolicy;
    use std::path::PathBuf;

    /// The whole point of `#[serde(flatten)]` here: this is the exact JSON the
    /// webview sent before the SSH half moved into its own crate, and it must
    /// keep deserializing unchanged.
    #[test]
    fn deserializes_the_camelcase_ipc_shape() {
        let cfg: FileTransferConfig = serde_json::from_str(
            r#"{
                 "host": "example.local",
                 "port": 2222,
                 "username": "testuser",
                 "auth": { "kind": "password", "value": "hunter2" },
                 "connectTimeoutMs": 5000,
                 "defaultRemoteDir": "~/Desktop",
                 "conflict": "overwrite"
               }"#,
        )
        .unwrap();
        assert_eq!(cfg.ssh.host, "example.local");
        assert_eq!(cfg.ssh.port, 2222);
        assert_eq!(cfg.connect_timeout().as_millis(), 5000);
        assert_eq!(cfg.default_remote_dir.as_deref(), Some("~/Desktop"));
        assert_eq!(cfg.conflict, ConflictPolicy::Overwrite);
        assert_eq!(cfg.ssh.auth.label(), "password");
        assert_eq!(cfg.endpoint(), "testuser@example.local:2222");
    }

    /// Defaults have to survive the flatten too. `serde(flatten)` routes
    /// through a content buffer, which is exactly where a missing field with a
    /// `default` fn is easiest to get wrong.
    #[test]
    fn port_and_timeout_have_defaults() {
        let cfg: FileTransferConfig = serde_json::from_str(
            r#"{ "host": "h", "username": "u", "auth": { "kind": "agent" } }"#,
        )
        .unwrap();
        assert_eq!(cfg.ssh.port, DEFAULT_SSH_PORT);
        assert_eq!(cfg.ssh.connect_timeout_ms, 15_000);
        assert_eq!(cfg.conflict, ConflictPolicy::Resume);
        assert!(cfg.default_remote_dir.is_none());
    }

    #[test]
    fn key_file_auth_round_trips() {
        let cfg: FileTransferConfig = serde_json::from_str(
            r#"{ "host": "h", "username": "u",
                 "auth": { "kind": "key-file",
                           "value": { "path": "/home/user/.ssh/id_ed25519",
                                      "passphrase": "s3cret" } } }"#,
        )
        .unwrap();
        match &cfg.ssh.auth {
            SshAuth::KeyFile { path, passphrase } => {
                assert_eq!(path, &PathBuf::from("/home/user/.ssh/id_ed25519"));
                assert_eq!(passphrase.as_deref(), Some("s3cret"));
            }
            other => panic!("expected KeyFile, got {other:?}"),
        }
    }

    #[test]
    fn secrets_never_appear_in_debug_output() {
        let cfg: FileTransferConfig = serde_json::from_str(
            r#"{ "host": "h", "username": "u",
                 "auth": { "kind": "password", "value": "hunter2" } }"#,
        )
        .unwrap();
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn the_endpoint_label_survives_an_ipv6_host() {
        let mut cfg = FileTransferConfig::new("::1", "u");
        assert_eq!(cfg.endpoint(), "u@[::1]:22");
        cfg.ssh.host = "[fe80::1]".into();
        assert_eq!(cfg.endpoint(), "u@[fe80::1]:22");
    }
}
