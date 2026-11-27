//! An SSH tunnel for a saved computer, the phone's half (issue #91).
//!
//! The desktop has had this for a long time: a host can say "reach me
//! through SSH", and the VNC or RDP session then runs over a `direct-tcpip`
//! channel the SSH server opens on its own side, so a VNC server that only
//! listens on the remote machine's loopback is reachable. The phone uses the
//! same carrier (`ssh-transport`) and the same connector shape; only the
//! storage is the phone's own:
//!
//! * the settings ride on the host in `hosts.json` ([`TunnelSettings`]),
//! * the SSH password or private key lives in the platform vault, in its own
//!   entry beside the host's sign in ([`TunnelSecret`], `crate::vault`),
//! * SSH host keys are trusted on first use, in `ssh_known_hosts.json`
//!   ([`KnownHosts`]). An unknown key stops the connect with a prompt the UI
//!   shows; a key that changed is a hard stop, as on the desktop.
//!
//! A phone has no key files and no ssh-agent, so the key is pasted once and
//! kept as text in the vault, and handed to the carrier as
//! `SshAuth::KeyData`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use remote_core::transport::{BoxedStream, ConnectFuture, StreamConnector, TransportError};
use serde::{Deserialize, Serialize};
use ssh_transport::{Error as SshError, HostKeyStore, SshAuth, SshConfig, SshTunnel};

/// `SshTunnel` in `contract.ts`, stored on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelSettings {
    #[serde(default)]
    pub enabled: bool,
    /// The SSH computer. Empty means the computer's own address, the common
    /// case where SSH and VNC run on the same machine.
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// The SSH user name. A phone has no local user to fall back on, so an
    /// enabled tunnel needs one.
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub auth: TunnelAuth,
}

fn default_port() -> u16 {
    ssh_transport::DEFAULT_SSH_PORT
}

/// How the tunnel signs in. The secret itself is in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelAuth {
    #[default]
    Password,
    Key,
}

/// The vault entry for a tunnel: the password, or the private key text and
/// its passphrase.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelSecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}

impl std::fmt::Debug for TunnelSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelSecret")
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("key", &self.key.as_ref().map(|_| "***"))
            .field("passphrase", &self.passphrase.as_ref().map(|_| "***"))
            .finish()
    }
}

/// The longest private key the vault takes. An RSA 16384 key in OpenSSH form
/// is about 12 KB; anything far past that is not a key.
pub const MAX_KEY: usize = 32 * 1024;

impl TunnelSettings {
    /// What a save must hold to be usable later. Only an enabled tunnel is
    /// checked, so a half filled form that was switched off still saves.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.user.trim().is_empty() {
            return Err("Enter the user name for the SSH tunnel".into());
        }
        if self.port == 0 {
            return Err("The SSH port must be between 1 and 65535".into());
        }
        if self.host.len() > 512 || self.user.len() > 512 {
            return Err("A field is too long".into());
        }
        Ok(())
    }

    /// The SSH computer to dial: the tunnel's own host, or the computer's.
    pub fn gateway(&self, address: &str) -> String {
        let host = self.host.trim();
        if host.is_empty() {
            address.trim().to_string()
        } else {
            host.to_string()
        }
    }

    /// The carrier configuration for this tunnel, with its secret.
    pub fn ssh_config(&self, address: &str, secret: &TunnelSecret) -> Result<SshConfig, String> {
        self.validate()?;
        let auth = match self.auth {
            TunnelAuth::Password => SshAuth::Password(
                secret
                    .password
                    .clone()
                    .filter(|p| !p.is_empty())
                    .ok_or(NO_PASSWORD)?,
            ),
            TunnelAuth::Key => SshAuth::KeyData {
                key: secret
                    .key
                    .clone()
                    .filter(|k| !k.trim().is_empty())
                    .ok_or(NO_KEY)?,
                passphrase: secret.passphrase.clone().filter(|p| !p.is_empty()),
            },
        };
        let mut cfg = SshConfig::new(self.gateway(address), self.user.trim());
        cfg.port = self.port;
        cfg.auth = auth;
        Ok(cfg)
    }
}

pub const NO_PASSWORD: &str =
    "This computer connects through SSH, but no SSH password is saved. Edit it and fill in the SSH password under More options.";
pub const NO_KEY: &str =
    "This computer connects through SSH, but no private key is saved. Edit it and paste the key under More options.";

/// The first words of the error `session_connect` gives when the SSH
/// computer's key is new. The rest is JSON, see [`HostKeyPrompt`]. The UI
/// (`ui/src/api/contract.ts`) recognises it and asks the person.
pub const HOST_KEY_PROMPT: &str = "ssh-host-key-prompt:";

/// What the UI shows before the first connect through an SSH computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyPrompt {
    pub host: String,
    pub port: u16,
    pub key_type: String,
    pub fingerprint: String,
}

impl HostKeyPrompt {
    pub fn to_error(&self) -> String {
        format!(
            "{HOST_KEY_PROMPT}{}",
            serde_json::to_string(self).unwrap_or_default()
        )
    }
}

/// SSH host keys the person trusted, one file in the app's data folder.
/// A fingerprint is public, so this is an ordinary file, like `pins.json`.
pub struct KnownHosts {
    path: PathBuf,
    store: Arc<Mutex<HostKeyStore>>,
}

impl KnownHosts {
    pub fn open(dir: &Path) -> Self {
        let path = dir.join("ssh_known_hosts.json");
        let mut store: HostKeyStore = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        store.collapse_duplicates();
        Self {
            path,
            store: Arc::new(Mutex::new(store)),
        }
    }

    /// The pin store as the carrier's verifier.
    pub fn verifier(&self) -> Arc<Mutex<HostKeyStore>> {
        self.store.clone()
    }

    pub fn trust(&self, host: &str, port: u16, key_type: &str, fingerprint: &str) -> Result<(), String> {
        self.store
            .lock()
            .trust(host, port, key_type, fingerprint, crate::store::now_ms());
        self.persist()
    }

    /// Forget a key, so the next connect asks again. For a computer that
    /// was removed, which is how a person recovers from a reinstalled SSH
    /// server whose key changed.
    pub fn forget(&self, host: &str, port: u16) -> Result<(), String> {
        if self.store.lock().forget(host, port) {
            self.persist()?;
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&*self.store.lock()).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }
}

/// Dial the SSH computer, check its key and sign in, and wrap the result as
/// the session's connector. `accept` is the fingerprint the person agreed to
/// on the prompt this returned last time; it is pinned, and the dial retried
/// once.
pub async fn establish(
    cfg: SshConfig,
    known: &KnownHosts,
    accept: Option<&str>,
) -> Result<remote_core::Connector, String> {
    let tunnel = match SshTunnel::connect(cfg.clone(), known.verifier()).await {
        Ok(tunnel) => tunnel,
        Err(SshError::HostKeyUnknown {
            host,
            port,
            key_type,
            fingerprint,
        }) => {
            if accept != Some(fingerprint.as_str()) {
                return Err(HostKeyPrompt {
                    host,
                    port,
                    key_type,
                    fingerprint,
                }
                .to_error());
            }
            known.trust(&host, port, &key_type, &fingerprint)?;
            SshTunnel::connect(cfg, known.verifier())
                .await
                .map_err(|e| e.to_string())?
        }
        // Never promptable and never retried, the same rule as the desktop.
        Err(SshError::HostKeyChanged {
            host,
            port,
            expected,
            actual,
        }) => {
            tracing::error!(%host, port, "ssh host key changed, refusing to tunnel");
            return Err(format!(
                "The SSH computer {} answered with a different key than the one you trusted before ({expected}, now {actual}). Someone may be in between, so DeskVNC did not connect. If that computer was set up again, remove it here and add it again.",
                ssh_transport::host_port(&host, port)
            ));
        }
        Err(e) => return Err(format!("The SSH tunnel did not open: {e}")),
    };
    Ok(remote_core::Connector(Arc::new(TunnelConnector {
        tunnel: Arc::new(tunnel),
    })))
}

/// A [`SshTunnel`] as the session core's [`StreamConnector`], the same
/// adapter as `src-tauri/src/tunnel.rs` on the desktop.
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
                Ok(Err(SshError::Timeout)) => return Err(TransportError::Timeout),
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

    fn settings() -> TunnelSettings {
        TunnelSettings {
            enabled: true,
            host: String::new(),
            port: 22,
            user: "pi".into(),
            auth: TunnelAuth::Password,
        }
    }

    #[test]
    fn wire_shape_matches_the_contract_and_has_defaults() {
        let t: TunnelSettings = serde_json::from_str(r#"{"enabled":true,"user":"pi"}"#).unwrap();
        assert_eq!(t.port, 22);
        assert_eq!(t.auth, TunnelAuth::Password);
        assert_eq!(t.host, "");
        let t: TunnelSettings =
            serde_json::from_str(r#"{"enabled":true,"host":"gate.example.com","port":2222,"user":"u","auth":"key","later":1}"#).unwrap();
        assert_eq!(t.auth, TunnelAuth::Key);
        let json = serde_json::to_value(&t).unwrap();
        for key in ["enabled", "host", "port", "user", "auth"] {
            assert!(json.get(key).is_some(), "missing {key}");
        }
        assert_eq!(json["auth"], "key");
    }

    #[test]
    fn the_gateway_defaults_to_the_computer() {
        let mut t = settings();
        assert_eq!(t.gateway(" 192.0.2.10 "), "192.0.2.10");
        t.host = "gate.example.com".into();
        assert_eq!(t.gateway("localhost"), "gate.example.com");
    }

    #[test]
    fn an_enabled_tunnel_needs_a_user_and_a_port() {
        let mut t = settings();
        t.user = " ".into();
        assert!(t.validate().is_err());
        t.enabled = false;
        assert!(t.validate().is_ok(), "a switched off tunnel saves as typed");
        let mut t = settings();
        t.port = 0;
        assert!(t.validate().is_err());
    }

    #[test]
    fn password_auth_needs_the_saved_password() {
        let t = settings();
        assert_eq!(t.ssh_config("192.0.2.10", &TunnelSecret::default()).unwrap_err(), NO_PASSWORD);
        let cfg = t
            .ssh_config(
                "192.0.2.10",
                &TunnelSecret {
                    password: Some("pw".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(cfg.endpoint(), "pi@192.0.2.10:22");
        assert!(matches!(cfg.auth, SshAuth::Password(ref p) if p == "pw"));
    }

    #[test]
    fn key_auth_hands_the_key_text_to_the_carrier() {
        let mut t = settings();
        t.auth = TunnelAuth::Key;
        t.host = "gate.example.com".into();
        t.port = 2222;
        assert_eq!(t.ssh_config("localhost", &TunnelSecret::default()).unwrap_err(), NO_KEY);
        let cfg = t
            .ssh_config(
                "localhost",
                &TunnelSecret {
                    key: Some("KEYTEXT".into()),
                    passphrase: Some(String::new()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(cfg.endpoint(), "pi@gate.example.com:2222");
        match cfg.auth {
            SshAuth::KeyData { key, passphrase } => {
                assert_eq!(key, "KEYTEXT");
                assert_eq!(passphrase, None, "an empty passphrase means none");
            }
            other => panic!("expected KeyData, got {other:?}"),
        }
    }

    #[test]
    fn debug_never_prints_a_tunnel_secret() {
        let s = TunnelSecret {
            password: Some("hunter2".into()),
            key: Some("BEGIN KEY".into()),
            passphrase: Some("pp".into()),
        };
        let printed = format!("{s:?}");
        assert!(!printed.contains("hunter2") && !printed.contains("BEGIN") && !printed.contains("pp\""));
    }

    #[test]
    fn the_host_key_prompt_round_trips_through_the_error_text() {
        let p = HostKeyPrompt {
            host: "192.0.2.10".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            fingerprint: "SHA256:abc".into(),
        };
        let e = p.to_error();
        let json = e.strip_prefix(HOST_KEY_PROMPT).unwrap();
        let back: HostKeyPrompt = serde_json::from_str(json).unwrap();
        assert_eq!(back, p);
        assert!(json.contains("\"keyType\""));
    }

    /// A real SSH server in the test, made with russh's own server half: it
    /// accepts one public key and answers `direct-tcpip` by dialling the
    /// target from its side. No key material is in the repository; both keys
    /// come from fixed seeds here.
    mod server {
        use russh::keys::ssh_key::private::Ed25519Keypair;
        use russh::keys::PrivateKey;
        use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session, VerifiedPublicKey};
        use russh::Channel;
        use std::sync::Arc;

        pub fn key(seed: u8) -> PrivateKey {
            PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
        }

        struct Gate {
            allowed: russh::keys::PublicKey,
        }

        impl Handler for Gate {
            type Error = russh::Error;

            async fn auth_publickey(&mut self, _user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
                Ok(if key.public_key.key_data() == self.allowed.key_data() {
                    Auth::Accept
                } else {
                    Auth::reject()
                })
            }

            async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
                Ok(if user == "pi" && password == "pw" { Auth::Accept } else { Auth::reject() })
            }

            async fn channel_open_direct_tcpip(
                &mut self,
                channel: Channel<Msg>,
                host: &str,
                port: u32,
                _originator: &str,
                _originator_port: u32,
                reply: ChannelOpenHandle,
                _session: &mut Session,
            ) -> Result<(), Self::Error> {
                let target = format!("{host}:{port}");
                tokio::spawn(async move {
                    let Ok(mut tcp) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    reply.accept().await;
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                });
                Ok(())
            }
        }

        /// Start the server; returns its port.
        pub async fn start(host_key: PrivateKey, allowed: russh::keys::PublicKey) -> u16 {
            let config = Arc::new(russh::server::Config {
                keys: vec![host_key],
                auth_rejection_time: std::time::Duration::from_millis(10),
                auth_rejection_time_initial: Some(std::time::Duration::ZERO),
                ..Default::default()
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else { return };
                    let config = config.clone();
                    let allowed = allowed.clone();
                    tokio::spawn(async move {
                        if let Ok(running) = russh::server::run_stream(config, socket, Gate { allowed }).await {
                            let _ = running.await;
                        }
                    });
                }
            });
            port
        }
    }

    /// A stand in for a VNC server that only listens on the SSH computer's
    /// loopback: it sends a greeting, then echoes.
    async fn loopback_service() -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    socket.write_all(b"RFB 003.008\n").await.unwrap();
                    let mut buf = [0u8; 64];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    /// The whole path a phone takes: the first dial asks about the key, the
    /// accepted key is pinned, the pasted private key signs in, and the
    /// session's connector reaches a service that only the SSH computer can
    /// reach, then a changed key is refused.
    #[tokio::test]
    async fn a_key_tunnel_asks_once_then_carries_the_session() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let client_key = server::key(7);
        let ssh_port = server::start(server::key(9), client_key.public_key().clone()).await;
        let vnc_port = loopback_service().await;

        let dir = tempfile::tempdir().unwrap();
        let known = KnownHosts::open(dir.path());
        let mut t = settings();
        t.host = "127.0.0.1".into();
        t.port = ssh_port;
        t.auth = TunnelAuth::Key;
        let secret = TunnelSecret {
            key: Some(client_key.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap().to_string()),
            ..Default::default()
        };
        // The VNC address as the SSH computer sees it.
        let cfg = t.ssh_config("localhost", &secret).unwrap();

        let Err(asked) = establish(cfg.clone(), &known, None).await else {
            panic!("an unknown key must be asked about first");
        };
        let prompt: HostKeyPrompt = serde_json::from_str(asked.strip_prefix(HOST_KEY_PROMPT).expect(&asked)).unwrap();
        assert_eq!(prompt.port, ssh_port);
        assert!(prompt.fingerprint.starts_with("SHA256:"));

        let connector = establish(cfg.clone(), &known, Some(&prompt.fingerprint)).await.unwrap();
        let mut stream = connector.0.connect("127.0.0.1", vnc_port, std::time::Duration::from_secs(10)).await.unwrap();
        let mut greeting = [0u8; 12];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"RFB 003.008\n");
        stream.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
        assert!(connector.0.describe().contains("ssh tunnel via pi@127.0.0.1"));

        // Pinned now: the next connect goes straight through.
        let reopened = KnownHosts::open(dir.path());
        assert!(establish(cfg.clone(), &reopened, None).await.is_ok());

        // A different key at the same address is a hard stop, never a prompt.
        let other = tempfile::tempdir().unwrap();
        let tampered = KnownHosts::open(other.path());
        tampered.trust("127.0.0.1", ssh_port, "ssh-ed25519", "SHA256:not-this-one").unwrap();
        let Err(refused) = establish(cfg, &tampered, None).await else {
            panic!("a changed key must not connect");
        };
        assert!(!refused.starts_with(HOST_KEY_PROMPT), "{refused}");
        assert!(refused.contains("different key"), "{refused}");
    }

    #[tokio::test]
    async fn a_password_tunnel_signs_in_and_a_wrong_password_says_so() {
        let ssh_port = server::start(server::key(11), server::key(12).public_key().clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let known = KnownHosts::open(dir.path());
        let mut t = settings();
        t.port = ssh_port;
        let good = TunnelSecret {
            password: Some("pw".into()),
            ..Default::default()
        };
        let cfg = t.ssh_config("127.0.0.1", &good).unwrap();
        let asked = establish(cfg.clone(), &known, None).await.err().unwrap();
        let prompt: HostKeyPrompt = serde_json::from_str(asked.strip_prefix(HOST_KEY_PROMPT).unwrap()).unwrap();
        assert!(establish(cfg, &known, Some(&prompt.fingerprint)).await.is_ok());

        let bad = TunnelSecret {
            password: Some("nope".into()),
            ..Default::default()
        };
        let err = establish(t.ssh_config("127.0.0.1", &bad).unwrap(), &known, None).await.err().unwrap();
        assert!(err.starts_with("The SSH tunnel did not open"), "{err}");
    }

    #[test]
    fn known_hosts_persist_and_forget() {
        let dir = tempfile::tempdir().unwrap();
        let known = KnownHosts::open(dir.path());
        known.trust("Gate.example.com", 22, "ssh-ed25519", "SHA256:aa").unwrap();
        let reopened = KnownHosts::open(dir.path());
        use ssh_transport::{HostKeyDecision, HostKeyVerifier};
        let v = reopened.verifier();
        assert_eq!(v.verify("gate.example.com", 22, "ssh-ed25519", "SHA256:aa"), HostKeyDecision::Trusted);
        assert!(matches!(
            v.verify("gate.example.com", 22, "ssh-ed25519", "SHA256:bb"),
            HostKeyDecision::Changed { .. }
        ));
        reopened.forget("gate.example.com", 22).unwrap();
        let again = KnownHosts::open(dir.path());
        assert!(matches!(
            again.verifier().verify("gate.example.com", 22, "ssh-ed25519", "SHA256:bb"),
            HostKeyDecision::Unknown { .. }
        ));
    }
}
