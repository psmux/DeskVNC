//! Dial, verify, authenticate. The front half of every SSH feature.
//!
//! Host-key verification happens in [`ClientHandler::check_server_key`] and is
//! strictly trust-on-first-use: an unknown key aborts the connect with
//! [`Error::HostKeyUnknown`] so the shell can prompt, and a *changed* key
//! aborts with [`Error::HostKeyChanged`], which is a hard stop with no
//! "continue anyway" path.
//!
//! ## Why `check_server_key` never returns `Err`
//!
//! russh's handler reports a rejected key as a plain connect failure, which
//! on its own would reach the user as "connection closed by remote host" and
//! tell them nothing. So the handler stashes *why* it said no in a shared
//! slot, and [`connect_and_authenticate`] reads that slot back out when the
//! connect fails, turning a useless network error into the exact prompt the
//! situation calls for.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{HashAlg, PrivateKey, PublicKey};

use crate::config::{resolver_host, SshAuth, SshConfig};
use crate::error::{Error, Result};
use crate::hostkey::{HostKeyDecision, HostKeyVerifier};

/// A `Send` future with a concrete region.
///
/// Several russh futures hold a shared reference across an await over a type
/// whose `Send`ness is not provable *higher-ranked* (`&Channel<Msg>`,
/// `&mpsc::Sender<Msg>`). Left as opaque `async fn` return types those
/// propagate outwards and make the caller's future non-`Send`, which a
/// `#[tauri::command]` rejects. Boxing at the boundary pins the region and the
/// bound becomes provable. Do not "simplify" these back into plain `async fn`s.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// How aggressively to prove the peer is still there.
///
/// SSH over TCP will happily sit in a half-open connection for the better part
/// of an hour: if the peer's kernel never sends a FIN (it was unplugged, it
/// panicked, a NAT box silently dropped the flow) the socket stays "connected"
/// until TCP's own retransmit budget runs out. Nothing arrives, nothing
/// errors, and the session simply hangs. That is the single most annoying
/// failure mode of plain `ssh`, and the only cure is to send something
/// periodically and give up when the answers stop.
///
/// russh implements this as `SSH_MSG_GLOBAL_REQUEST` keepalives (the same
/// mechanism OpenSSH's `ServerAliveInterval` uses) and counts unanswered ones
/// against `keepalive_max`, exactly as `ServerAliveCountMax` does. Note the
/// detail from russh's own loop: *any* inbound traffic resets the counter, so
/// a busy session never pays for the probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keepalive {
    /// How often to probe when the link is otherwise silent.
    pub interval: Option<Duration>,
    /// How many probes may go unanswered before the link is declared dead.
    /// Zero means "never give up", which is almost always the wrong answer.
    pub max_missed: u32,
    /// Hard cap on total silence, independent of the probes. `None` for an
    /// interactive session: a shell sitting at a prompt overnight is idle,
    /// not broken, and the keepalives already prove the peer is alive.
    pub inactivity_timeout: Option<Duration>,
}

impl Keepalive {
    /// The sidecar profile: probe every 30 seconds and never time out on
    /// inactivity. This is byte-for-byte the behaviour the SFTP sidecar and
    /// the RFB tunnel shipped with before this crate existed, kept so the
    /// extraction changed nothing for them.
    ///
    /// `max_missed` is 3, which is russh's own default and gives a 90 second
    /// worst case. Fine for a background file transfer, far too slow for a
    /// human staring at a frozen prompt, which is what [`Self::interactive`]
    /// is for.
    pub const fn sidecar() -> Self {
        Self {
            interval: Some(Duration::from_secs(30)),
            max_missed: 3,
            inactivity_timeout: None,
        }
    }

    /// The interactive profile, for a remote shell.
    ///
    /// Five seconds between probes and three misses, so a dead link is called
    /// within about 15 seconds instead of the several minutes TCP would take
    /// on its own. That is quick enough that a reconnect feels like a hiccup
    /// rather than a hang, and slow enough that a satellite link or a laptop
    /// waking from sleep is not torn down for one late reply.
    pub const fn interactive() -> Self {
        Self {
            interval: Some(Duration::from_secs(5)),
            max_missed: 3,
            inactivity_timeout: None,
        }
    }

    /// The worst case time to notice a dead peer, for logs and for tests that
    /// need to wait it out.
    pub fn detection_window(&self) -> Option<Duration> {
        self.interval
            .map(|i| i.saturating_mul(self.max_missed.max(1)))
    }
}

impl Default for Keepalive {
    fn default() -> Self {
        Self::sidecar()
    }
}

/// The russh client handler. Its only job is the host-key decision.
pub struct ClientHandler {
    host: String,
    port: u16,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
    decision: Arc<Mutex<Option<HostKeyDecision>>>,
}

// russh 0.62 declares `Handler` with return-position `impl Future` rather than
// `#[async_trait]`, so a plain `async fn` in the impl is what matches now.
impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let fingerprint = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        let key_type = server_public_key.algorithm().as_str().to_string();
        let decision = self
            .verifier
            .verify(&self.host, self.port, &key_type, &fingerprint);
        let accept = matches!(decision, HostKeyDecision::Trusted);
        if !accept {
            tracing::warn!(
                host = %self.host, port = self.port, %key_type,
                "ssh host key not accepted: {decision:?}"
            );
        }
        *self.decision.lock() = Some(decision);
        Ok(accept)
    }
}

/// An authenticated SSH connection, ready for channels.
pub type SshHandle = russh::client::Handle<ClientHandler>;

/// Dial the SSH server, verify its host key (TOFU) and authenticate, using
/// the [`Keepalive::sidecar`] profile.
///
/// The host-key outcomes come back as the dedicated error variants
/// ([`Error::HostKeyUnknown`] / [`Error::HostKeyChanged`]) so the shell can
/// prompt or hard-stop; everything else is a plain connect failure. Boxed for
/// the region reason documented on [`BoxFuture`].
pub fn connect_and_authenticate<'a>(
    cfg: &'a SshConfig,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
) -> BoxFuture<'a, Result<SshHandle>> {
    connect_and_authenticate_with(cfg, verifier, Keepalive::sidecar())
}

/// As [`connect_and_authenticate`], but with an explicit liveness profile.
///
/// A remote shell wants [`Keepalive::interactive`]: a human notices a frozen
/// terminal in seconds, so waiting 90 for the transport to admit it is dead
/// is the difference between a blip and a bug report.
pub fn connect_and_authenticate_with<'a>(
    cfg: &'a SshConfig,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
    keepalive: Keepalive,
) -> BoxFuture<'a, Result<SshHandle>> {
    Box::pin(connect_and_authenticate_inner(cfg, verifier, keepalive))
}

/// Decide the server's host key and nothing else: dial, let the key
/// verification in the handler run, and drop the connection.
///
/// This exists so a caller can get the trust decision (and therefore the
/// fingerprint to show somebody) BEFORE it commits to a session. It stops
/// after the key exchange, which is where the host key is presented, so it
/// costs no authentication attempt: no key is decrypted, no agent is asked,
/// and no server's failed-auth counter moves. `Ok(())` means the key is
/// already trusted.
///
/// Prefer it to a throwaway [`connect_and_authenticate`] when the only
/// question is the host key.
pub fn check_host_key<'a>(
    cfg: &'a SshConfig,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        // Dropping the handle tears the transport down; there is nothing to
        // close politely, the connection never got past the handshake.
        let _handle = connect_only(cfg, verifier, Keepalive::sidecar()).await?;
        Ok(())
    })
}

async fn connect_and_authenticate_inner(
    cfg: &SshConfig,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
    keepalive: Keepalive,
) -> Result<SshHandle> {
    let mut ssh = connect_only(cfg, verifier, keepalive).await?;
    authenticate(&mut ssh, cfg).await?;
    Ok(ssh)
}

/// The handshake half of a connect: everything up to and including the host
/// key decision, with no authentication.
async fn connect_only(
    cfg: &SshConfig,
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
    keepalive: Keepalive,
) -> Result<SshHandle> {
    let decision = Arc::new(Mutex::new(None));
    let handler = ClientHandler {
        host: cfg.host.clone(),
        port: cfg.port,
        verifier,
        decision: decision.clone(),
    };

    let ssh_config = Arc::new(russh::client::Config {
        inactivity_timeout: keepalive.inactivity_timeout,
        keepalive_interval: keepalive.interval,
        keepalive_max: keepalive.max_missed as usize,
        ..Default::default()
    });

    let connecting =
        russh::client::connect(ssh_config, (resolver_host(&cfg.host), cfg.port), handler);
    let ssh = match tokio::time::timeout(cfg.connect_timeout(), connecting).await {
        Err(_) => return Err(Error::Timeout),
        Ok(Ok(handle)) => handle,
        Ok(Err(e)) => {
            // A failed connect is usually a network problem, but if the
            // handler rejected the key we have a much better answer.
            return Err(match decision.lock().take() {
                Some(HostKeyDecision::Unknown {
                    key_type,
                    fingerprint,
                }) => Error::HostKeyUnknown {
                    host: cfg.host.clone(),
                    port: cfg.port,
                    key_type,
                    fingerprint,
                },
                Some(HostKeyDecision::Changed {
                    expected, actual, ..
                }) => Error::HostKeyChanged {
                    host: cfg.host.clone(),
                    port: cfg.port,
                    expected,
                    actual,
                },
                _ => Error::Connect {
                    host: cfg.host.clone(),
                    port: cfg.port,
                    reason: e.to_string(),
                },
            });
        }
    };
    Ok(ssh)
}

/// Boxed for the region reason documented on [`BoxFuture`]: russh's
/// `authenticate_*` futures hold `&mpsc::Sender<client::Msg>` across an await,
/// which is not higher-ranked `Send`. Pinning the region here keeps the
/// caller's future `Send`, which Tauri commands require.
fn authenticate<'a>(ssh: &'a mut SshHandle, cfg: &'a SshConfig) -> BoxFuture<'a, Result<()>> {
    Box::pin(authenticate_inner(ssh, cfg))
}

async fn authenticate_inner(ssh: &mut SshHandle, cfg: &SshConfig) -> Result<()> {
    let ok = match &cfg.auth {
        // russh 0.62 returns `AuthResult` (which can also report "accepted but
        // more factors required") instead of a bare bool. Only outright
        // success counts here.
        SshAuth::Password(password) => ssh
            .authenticate_password(cfg.username.clone(), password.clone())
            .await
            .map_err(Error::ssh)?
            .success(),
        SshAuth::KeyFile { path, passphrase } => {
            let path = path.clone();
            let passphrase = passphrase.clone();
            let display = path.display().to_string();
            // Reading and decrypting a key is blocking, CPU-bound work, and
            // a v3 PPK deliberately makes it more so: Argon2 with PuTTY's
            // default parameters is tens of milliseconds of pure CPU.
            let key =
                tokio::task::spawn_blocking(move || load_key_file(&path, passphrase.as_deref()))
                    .await
                    .map_err(|e| Error::Other(e.to_string()))?
                    .map_err(|reason| Error::Key {
                        path: display,
                        reason,
                    })?;
            authenticate_with_key(ssh, &cfg.username, Arc::new(key)).await?
        }
        SshAuth::Agent => authenticate_with_agent(ssh, &cfg.username).await?,
    };
    if !ok {
        return Err(Error::Auth {
            user: cfg.username.clone(),
        });
    }
    Ok(())
}

/// Read a private key file in whichever format it is actually in.
///
/// PuTTY's `.ppk` is decided by content, not by the extension: these files
/// get renamed, and a key that works in PuTTY should not stop working here
/// because someone dropped the suffix. Everything else goes to russh, which
/// covers the OpenSSH container and the older PEM/PKCS#8 files.
///
/// Returns the reason as a plain string because the two loaders have
/// unrelated error types and the caller only ever shows this to a person.
pub fn load_key_file(
    path: &Path,
    passphrase: Option<&str>,
) -> std::result::Result<PrivateKey, String> {
    let path = expand_home(path);
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    if crate::ppk::is_ppk(&bytes) {
        return crate::ppk::load(&bytes, passphrase).map_err(|e| e.to_string());
    }
    russh::keys::decode_secret_key(
        &String::from_utf8(bytes).map_err(|_| "not a text key file".to_string())?,
        passphrase,
    )
    .map_err(|e| e.to_string())
}

/// Turn a leading `~` into the home directory.
///
/// `~/.ssh/id_ed25519` is how everybody writes the path to a key, including
/// every piece of documentation and the placeholder in this app's own host
/// editor. Nothing below this expands it: a shell does that before the path
/// ever reaches a program, and a path typed into a text box has no shell in
/// front of it, so it arrives as a literal `~` directory that does not exist.
///
/// Only a leading `~/` (or a bare `~`) is expanded. `~user` is a different
/// lookup with different answers per platform, and guessing at it would turn
/// a wrong path into a *different* wrong path.
fn expand_home(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    let rest = if text == "~" {
        ""
    } else if let Some(rest) = text.strip_prefix("~/").or_else(|| text.strip_prefix("~\\")) {
        rest
    } else {
        return path.to_path_buf();
    };
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    match home {
        Some(home) if rest.is_empty() => home,
        Some(home) => home.join(rest),
        None => path.to_path_buf(),
    }
}

/// RSA keys need an explicit signature hash: `ssh-rsa` (SHA-1) is refused by
/// every current OpenSSH, so try SHA-512 then SHA-256 before giving up.
fn authenticate_with_key<'a>(
    ssh: &'a mut SshHandle,
    username: &'a str,
    key: Arc<russh::keys::PrivateKey>,
) -> BoxFuture<'a, Result<bool>> {
    Box::pin(authenticate_with_key_inner(ssh, username, key))
}

async fn authenticate_with_key_inner(
    ssh: &mut SshHandle,
    username: &str,
    key: Arc<russh::keys::PrivateKey>,
) -> Result<bool> {
    let hashes: &[Option<HashAlg>] = if key.algorithm().is_rsa() {
        &[Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]
    } else {
        &[None]
    };
    for hash in hashes {
        // `PrivateKeyWithHashAlg::new` is infallible as of russh 0.62; it used
        // to return a Result.
        let with_hash = PrivateKeyWithHashAlg::new(key.clone(), *hash);
        match ssh
            .authenticate_publickey(username.to_string(), with_hash)
            .await
        {
            Ok(result) if result.success() => return Ok(true),
            Ok(_) => continue,
            Err(e) => return Err(Error::ssh(e)),
        }
    }
    Ok(false)
}

fn authenticate_with_agent<'a>(
    ssh: &'a mut SshHandle,
    username: &'a str,
) -> BoxFuture<'a, Result<bool>> {
    Box::pin(authenticate_with_agent_inner(ssh, username))
}

async fn authenticate_with_agent_inner(ssh: &mut SshHandle, username: &str) -> Result<bool> {
    let mut agent = connect_agent().await?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| Error::Agent(e.to_string()))?;
    if identities.is_empty() {
        return Err(Error::Agent("the ssh agent holds no identities".into()));
    }
    for identity in identities {
        // russh 0.62 hands back `AgentIdentity`, which may wrap a certificate
        // rather than a bare key, and `authenticate_publickey_with` now takes
        // the public key plus an explicit signature hash. `None` lets the
        // agent pick, which is what we want for every algorithm it holds.
        let key = identity.public_key().into_owned();
        // Boxed for the region reason documented on `BoxFuture`.
        let attempt: BoxFuture<
            '_,
            std::result::Result<russh::client::AuthResult, russh::AgentAuthError>,
        > = Box::pin(ssh.authenticate_publickey_with(username.to_string(), key, None, &mut agent));
        match attempt.await {
            Ok(result) if result.success() => return Ok(true),
            Ok(_) => continue,
            Err(e) => {
                tracing::debug!("agent identity rejected: {e}");
                continue;
            }
        }
    }
    Ok(false)
}

#[cfg(unix)]
async fn connect_agent() -> Result<
    russh::keys::agent::client::AgentClient<
        Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin + 'static>,
    >,
> {
    russh::keys::agent::client::AgentClient::connect_env()
        .await
        .map(|c| c.dynamic())
        .map_err(|e| Error::Agent(format!("SSH_AUTH_SOCK: {e}")))
}

/// Windows has two agents in the wild: the OpenSSH service on a named pipe and
/// Pageant. Try the pipe first, then fall back.
#[cfg(windows)]
async fn connect_agent() -> Result<
    russh::keys::agent::client::AgentClient<
        Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin + 'static>,
    >,
> {
    use russh::keys::agent::client::AgentClient;
    const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
    match AgentClient::connect_named_pipe(OPENSSH_PIPE).await {
        Ok(client) => Ok(client.dynamic()),
        Err(e) => {
            tracing::debug!("openssh agent pipe unavailable: {e}");
            // russh 0.62 made `connect_pageant` fallible; it used to return the
            // client directly. Pageant is the fallback, so a failure here means
            // neither agent is reachable.
            let pageant = AgentClient::connect_pageant()
                .await
                .map_err(|e| Error::Agent(format!("no SSH agent available: {e}")))?;
            Ok(pageant.dynamic())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sidecar profile must stay exactly what the SFTP and tunnel code
    /// used before this crate existed, or the extraction silently changed the
    /// behaviour of a shipping feature.
    #[test]
    fn the_sidecar_profile_is_the_pre_extraction_behaviour() {
        let k = Keepalive::sidecar();
        assert_eq!(k.interval, Some(Duration::from_secs(30)));
        assert_eq!(k.inactivity_timeout, None);
    }

    /// The whole point of the interactive profile: a human must not sit in
    /// front of a frozen terminal for a minute and a half.
    #[test]
    fn an_interactive_link_is_declared_dead_within_twenty_seconds() {
        let window = Keepalive::interactive()
            .detection_window()
            .expect("interactive keepalive must probe");
        assert!(
            window <= Duration::from_secs(20),
            "detection window {window:?} is too slow for a shell"
        );
    }

    /// An idle shell at a prompt overnight is not a broken shell. Only the
    /// unanswered probes may end a session, never mere silence.
    #[test]
    fn neither_profile_tears_down_a_merely_idle_session() {
        assert_eq!(Keepalive::sidecar().inactivity_timeout, None);
        assert_eq!(Keepalive::interactive().inactivity_timeout, None);
    }

    /// A key path typed into a text box never met a shell, so the `~` that
    /// every piece of SSH documentation writes has to be expanded here.
    #[test]
    fn a_leading_tilde_becomes_the_home_directory() {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return;
        };
        assert_eq!(
            expand_home(Path::new("~/.ssh/id_ed25519")),
            home.join(".ssh/id_ed25519")
        );
        assert_eq!(expand_home(Path::new("~")), home);
    }

    /// Everything else is left exactly as written: an absolute path is
    /// already an answer, and `~user` is a lookup this deliberately does not
    /// guess at.
    #[test]
    fn other_paths_are_left_alone() {
        for path in ["/etc/keys/id_rsa", "keys/id_rsa", "~someone/.ssh/id_rsa"] {
            assert_eq!(expand_home(Path::new(path)), PathBuf::from(path));
        }
    }
}
