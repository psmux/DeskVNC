//! Connection configuration for an SSH carrier.
//!
//! SECURITY: [`SshAuth`] carries secrets. It deserializes (JS → Rust) but
//! deliberately does **not** serialize, so a password or passphrase can never
//! be handed back to the webview, the same invariant `StoredCredentials`
//! holds for VNC passwords (see IPC_CONTRACT.md "Credentials").

use std::path::PathBuf;

/// Default SSH port; also the default port for any feature that rides the
/// carrier when a host profile does not override it.
pub const DEFAULT_SSH_PORT: u16 = 22;

/// Join a host and port into the usual `host:port` form.
///
/// A bare IPv6 literal has to be bracketed first: `::1` and `22` would
/// otherwise concatenate to `::1:22`, which is ambiguous with the address
/// itself, so anything reading it back gets the wrong answer and a human
/// reading it in a log cannot tell where the address ends. A DNS name can
/// never contain a colon, so a colon means "IPv6 literal", and a leading `[`
/// means the caller already bracketed it (users do type `[::1]`, and
/// double-bracketing would be just as wrong).
///
/// Deliberately a local copy of `vnc_transport::tcp`'s rule rather than a
/// shared helper: `ssh-transport` does not otherwise depend on
/// `vnc-transport`, and one six-line string function is not worth a crate
/// edge.
pub fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The host as a resolver wants it, with any user-typed brackets removed.
///
/// `russh::client::connect` and `TcpStream::connect` take `(host, port)` as a
/// tuple, which parses the host as an `IpAddr` and otherwise resolves it as a
/// DNS name. `[::1]` is neither, so a bracketed literal would fail every
/// lookup. Brackets only exist to delimit an address inside a *joined*
/// string, so they have no business here. `vnc-transport` accepts both
/// spellings for the VNC connection; the carrier has to accept the same ones
/// or a profile connects but its sidecar does not.
pub fn resolver_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

/// The canonical form of a host, for deciding whether two spellings mean the
/// same machine.
///
/// Deliberately the same rule as `vnc_store::normalize_address` (trim, drop
/// the trailing dot mDNS puts on a fully-qualified name, ASCII-lowercase),
/// plus the bracket stripping this crate needs because a user-typed `[::1]`
/// reaches the carrier: [`host_port`] re-adds the brackets wherever a joined
/// string is wanted, so carrying them in an identity would split one machine
/// into two. "The same machine" has to mean the same thing on both sides of
/// the app or a profile pins its host key twice.
///
/// Copied rather than shared for the reason given on [`host_port`]:
/// `ssh-transport` has no other need of `vnc-store`, and one line is not
/// worth a crate edge.
pub fn canonical_host(host: &str) -> String {
    resolver_host(host.trim())
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// How to authenticate the SSH connection.
///
/// Adjacently tagged so the JS side sends `{ kind, value }`:
/// `{"kind":"password","value":"…"}`,
/// `{"kind":"key-file","value":{"path":"…","passphrase":"…"}}`,
/// `{"kind":"agent"}`.
#[derive(Clone, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum SshAuth {
    Password(String),
    /// A private key file on this machine. The format is detected from the
    /// file's contents, not its name: OpenSSH containers and the older
    /// PEM/PKCS#8 files go to russh, PuTTY `.ppk` files (v2 and v3) go to
    /// [`crate::ppk`]. `passphrase` is ignored for a key that is not
    /// encrypted, so a caller holding a stored secret need not know which
    /// kind it has.
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

/// Everything needed to bring up the carrier: where to dial, who to be, and
/// how long to wait. Built in Rust from the host profile plus the keychain;
/// the webview supplies host/port/user/auth-kind only.
///
/// Every feature riding the carrier embeds one of these with
/// `#[serde(flatten)]`, which keeps its own IPC shape flat: the webview sends
/// `{host, port, username, auth, connectTimeoutMs, …}` in one object and
/// never learns that the SSH half was factored out.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfig {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    /// Connect + authenticate deadline, milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
}

fn default_ssh_port() -> u16 {
    DEFAULT_SSH_PORT
}

fn default_connect_timeout_ms() -> u64 {
    15_000
}

impl SshConfig {
    /// Minimal config: password-less agent auth against `host`.
    pub fn new(host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: DEFAULT_SSH_PORT,
            username: username.into(),
            auth: SshAuth::Agent,
            connect_timeout_ms: default_connect_timeout_ms(),
        }
    }

    /// The dial deadline, clamped so neither a zero nor a `u64::MAX` from a
    /// malformed profile can turn into "give up instantly" or "hang forever".
    pub fn connect_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.connect_timeout_ms.clamp(1_000, 120_000))
    }

    /// `user@host:port`, for logs and window titles. Never contains secrets.
    pub fn endpoint(&self) -> String {
        format!("{}@{}", self.username, host_port(&self.host, self.port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_the_camelcase_ipc_shape() {
        let cfg: SshConfig = serde_json::from_str(
            r#"{
                 "host": "example.local",
                 "port": 2222,
                 "username": "testuser",
                 "auth": { "kind": "password", "value": "hunter2" },
                 "connectTimeoutMs": 5000
               }"#,
        )
        .unwrap();
        assert_eq!(cfg.host, "example.local");
        assert_eq!(cfg.port, 2222);
        assert_eq!(cfg.connect_timeout().as_millis(), 5000);
        assert_eq!(cfg.auth.label(), "password");
        assert_eq!(cfg.endpoint(), "testuser@example.local:2222");
    }

    #[test]
    fn port_and_timeout_have_defaults() {
        let cfg: SshConfig = serde_json::from_str(
            r#"{ "host": "h", "username": "u", "auth": { "kind": "agent" } }"#,
        )
        .unwrap();
        assert_eq!(cfg.port, DEFAULT_SSH_PORT);
        assert_eq!(cfg.connect_timeout_ms, 15_000);
    }

    #[test]
    fn key_file_auth_round_trips() {
        let cfg: SshConfig = serde_json::from_str(
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
        let cfg: SshConfig = serde_json::from_str(
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

    /// Guards the one property every host+port join in this crate depends on:
    /// the result can be read back apart again, whatever spelling of the
    /// address the profile happens to hold.
    #[test]
    fn a_bare_ipv6_literal_is_bracketed_before_the_port_is_appended() {
        assert_eq!(host_port("::1", 22), "[::1]:22");
        assert_eq!(host_port("fe80::1", 22), "[fe80::1]:22");
        assert_eq!(host_port("2001:db8::5", 2222), "[2001:db8::5]:2222");

        // Already bracketed, IPv4 and DNS names must pass through untouched.
        assert_eq!(host_port("[::1]", 22), "[::1]:22");
        assert_eq!(host_port("192.0.2.10", 22), "192.0.2.10:22");
        assert_eq!(
            host_port("files.example.com", 2222),
            "files.example.com:2222"
        );
    }

    #[test]
    fn the_endpoint_label_survives_an_ipv6_host() {
        let mut cfg = SshConfig::new("::1", "u");
        assert_eq!(cfg.endpoint(), "u@[::1]:22");
        cfg.host = "[fe80::1]".into();
        assert_eq!(cfg.endpoint(), "u@[fe80::1]:22");
    }

    /// The mirror image: brackets are punctuation for a joined string, and a
    /// resolver that is handed host and port separately must never see them.
    #[test]
    fn brackets_are_stripped_before_the_host_reaches_a_resolver() {
        assert_eq!(resolver_host("[::1]"), "::1");
        assert_eq!(resolver_host("[2001:db8::5]"), "2001:db8::5");

        assert_eq!(resolver_host("::1"), "::1");
        assert_eq!(resolver_host("192.0.2.10"), "192.0.2.10");
        assert_eq!(resolver_host("files.example.com"), "files.example.com");
    }

    /// One machine, one spelling: whatever a profile or an mDNS record calls
    /// a host, everything keyed on it has to agree they are the same box.
    #[test]
    fn every_spelling_of_one_machine_canonicalises_to_the_same_string() {
        assert_eq!(canonical_host("[::1]"), "::1");
        assert_eq!(canonical_host("::1"), "::1");
        assert_eq!(canonical_host("[FE80::1]"), "fe80::1");

        assert_eq!(canonical_host("studio.local."), "studio.local");
        assert_eq!(canonical_host("Studio.Local"), "studio.local");
        assert_eq!(canonical_host("  studio.local.  "), "studio.local");

        // Different machines must stay different.
        assert_ne!(canonical_host("::1"), canonical_host("::2"));
        assert_ne!(canonical_host("studio.local"), canonical_host("den.local"));
    }

    /// The rule is `vnc_store::normalize_address` plus bracket stripping; if
    /// the two ever drift, the VNC side and the carrier disagree about which
    /// machine a profile points at.
    #[test]
    fn canonicalisation_matches_the_store_rule_for_unbracketed_hosts() {
        for host in ["studio.local.", "Studio.Local", " den.local ", "192.0.2.10"] {
            let store_rule = host.trim().trim_end_matches('.').to_ascii_lowercase();
            assert_eq!(canonical_host(host), store_rule, "{host}");
        }
    }

    #[test]
    fn timeouts_are_clamped_to_something_sane() {
        let mut cfg = SshConfig::new("h", "u");
        cfg.connect_timeout_ms = 0;
        assert_eq!(cfg.connect_timeout().as_millis(), 1_000);
        cfg.connect_timeout_ms = u64::MAX;
        assert_eq!(cfg.connect_timeout().as_millis(), 120_000);
    }
}
