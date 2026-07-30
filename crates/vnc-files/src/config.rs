//! Connection configuration for the SFTP sidecar.
//!
//! SECURITY: `SshAuth` carries secrets. It deserializes (JS → Rust) but
//! deliberately does **not** serialize, so a password or passphrase can never
//! be handed back to the webview, the same invariant `StoredCredentials`
//! holds for VNC passwords (see IPC_CONTRACT.md "Credentials").

use std::path::PathBuf;

/// Default SSH port; also the default file-transfer port when a host profile
/// does not override it.
pub const DEFAULT_SSH_PORT: u16 = 22;

/// How to authenticate the SSH sidecar connection.
///
/// Adjacently tagged so the JS side sends `{ kind, value }`:
/// `{"kind":"password","value":"…"}`,
/// `{"kind":"key-file","value":{"path":"…","passphrase":"…"}}`,
/// `{"kind":"agent"}`.
#[derive(Clone, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum SshAuth {
    Password(String),
    #[serde(rename_all = "camelCase")]
    KeyFile {
        path: PathBuf,
        #[serde(default)]
        passphrase: Option<String>,
    },
    /// ssh-agent (unix socket), Pageant or the Windows OpenSSH named pipe.
    Agent,
}

impl SshAuth {
    /// Short, secret-free label for logs and the UI.
    pub fn label(&self) -> &'static str {
        match self {
            SshAuth::Password(_) => "password",
            SshAuth::KeyFile { .. } => "key",
            SshAuth::Agent => "agent",
        }
    }
}

/// `Debug` never prints secrets, these values end up in tracing spans.
impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshAuth::Password(_) => f.write_str("Password(<redacted>)"),
            SshAuth::KeyFile { path, passphrase } => f
                .debug_struct("KeyFile")
                .field("path", path)
                .field("passphrase", &passphrase.as_ref().map(|_| "<redacted>"))
                .finish(),
            SshAuth::Agent => f.write_str("Agent"),
        }
    }
}

/// Everything needed to open the sidecar. Built in Rust from the host profile
/// plus the keychain; the webview supplies host/port/user/auth-kind only.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTransferConfig {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    /// Connect + authenticate deadline, milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Where the file panel and drag-and-drop uploads start (PRD/08 §3.1).
    /// `None` means "the remote user's home directory".
    #[serde(default)]
    pub default_remote_dir: Option<String>,
    /// What to do when a destination file already exists.
    #[serde(default)]
    pub conflict: crate::transfer::ConflictPolicy,
}

fn default_ssh_port() -> u16 {
    DEFAULT_SSH_PORT
}

fn default_connect_timeout_ms() -> u64 {
    15_000
}

impl FileTransferConfig {
    /// Minimal config: password-less agent auth against the VNC host.
    pub fn new(host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: DEFAULT_SSH_PORT,
            username: username.into(),
            auth: SshAuth::Agent,
            connect_timeout_ms: default_connect_timeout_ms(),
            default_remote_dir: None,
            conflict: crate::transfer::ConflictPolicy::default(),
        }
    }

    pub fn connect_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.connect_timeout_ms.clamp(1_000, 120_000))
    }

    /// `user@host:port`, for logs and window titles. Never contains secrets.
    pub fn endpoint(&self) -> String {
        format!("{}@{}:{}", self.username, self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::ConflictPolicy;

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
        assert_eq!(cfg.host, "example.local");
        assert_eq!(cfg.port, 2222);
        assert_eq!(cfg.connect_timeout().as_millis(), 5000);
        assert_eq!(cfg.default_remote_dir.as_deref(), Some("~/Desktop"));
        assert_eq!(cfg.conflict, ConflictPolicy::Overwrite);
        assert_eq!(cfg.auth.label(), "password");
        assert_eq!(cfg.endpoint(), "testuser@example.local:2222");
    }

    #[test]
    fn port_and_timeout_have_defaults() {
        let cfg: FileTransferConfig = serde_json::from_str(
            r#"{ "host": "h", "username": "u", "auth": { "kind": "agent" } }"#,
        )
        .unwrap();
        assert_eq!(cfg.port, DEFAULT_SSH_PORT);
        assert_eq!(cfg.connect_timeout_ms, 15_000);
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
        match &cfg.auth {
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

        let key: SshAuth = serde_json::from_str(
            r#"{ "kind": "key-file", "value": { "path": "/k", "passphrase": "pp" } }"#,
        )
        .unwrap();
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("pp"), "{rendered}");
    }

    #[test]
    fn timeouts_are_clamped_to_something_sane() {
        let mut cfg = FileTransferConfig::new("h", "u");
        cfg.connect_timeout_ms = 0;
        assert_eq!(cfg.connect_timeout().as_millis(), 1_000);
        cfg.connect_timeout_ms = u64::MAX;
        assert_eq!(cfg.connect_timeout().as_millis(), 120_000);
    }
}
