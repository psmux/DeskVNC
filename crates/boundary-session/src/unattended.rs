//! Unattended access: reaching a machine when nobody is there to approve.
//!
//! An attended session is let in by a person clicking Allow. Here nobody is
//! there, so the machine decides from what it was told beforehand, kept in an
//! access file beside its identity key:
//!
//! * **Paired helpers.** During an ordinary attended session the person being
//!   helped can choose to let that helper in any time. The helper is recorded
//!   by the key it connected with. The encrypted handshake proves that key on
//!   every connection, so a paired helper sends no password and there is no
//!   secret to steal from it in transit or in a chat log.
//! * **A password**, optional, for a first connection when pairing in person
//!   was not possible. It is checked against an Argon2id hash, travels only
//!   inside a connection to a key the helper already named, and five wrong
//!   attempts lock password access for fifteen minutes.
//!
//! The machine keeps one identity for good, so its ID is something a helper
//! can save, and it publishes its current address to the n0 address
//! directory under that ID, which is how a helper finds it with nothing but
//! the ID. Only one session runs at a time.

use crate::{
    Desktop, Event, HostOptions, Session,
    session::{self, Lookup},
    wire::{self, Message},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use iroh::{EndpointAddr, EndpointId, SecretKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// The shortest unattended password accepted.
pub const MIN_PASSWORD: usize = 10;
const LOCKOUT_FAILURES: usize = 5;
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
// OWASP's Argon2id baseline: 19 MiB, two passes, one lane.
const ARGON_MEMORY_KIB: u32 = 19_456;
const ARGON_PASSES: u32 = 2;

/// Load this machine's or this helper's lasting key, making one the first
/// time. The file holds the key in hex and is readable by its owner only.
pub fn load_or_create_key(path: &Path) -> Result<SecretKey> {
    if let Ok(text) = std::fs::read_to_string(path) {
        let bytes: [u8; 32] = hex_decode(text.trim())
            .and_then(|b| b.try_into().ok())
            .context("The identity file is damaged. Remove it to make a new identity")?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let key = SecretKey::generate();
    write_private(path, hex_encode(&key.to_bytes()).as_bytes())?;
    Ok(key)
}

/// The ID a helper connects to, for this key.
pub fn machine_id(key: &SecretKey) -> String {
    key.public().to_string()
}

/// Who may come in unattended, and whether anyone may at all.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Access {
    /// Off means every unattended connection is refused, paired or not.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub helpers: Vec<Helper>,
    /// Argon2id, as `salt$hash` in hex. Never the password itself.
    #[serde(default)]
    password: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Helper {
    /// The helper's key, as proved by the handshake.
    pub id: String,
    /// The name the helper gave when they were paired.
    pub name: String,
    /// Whether they may use mouse and keyboard, or only watch.
    #[serde(default = "yes")]
    pub control: bool,
    /// Unix seconds.
    pub added: u64,
}
fn yes() -> bool {
    true
}
impl Access {
    /// Read the access file. A missing file is no access at all.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).context("The unattended access settings are damaged")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).context("Cannot read the unattended access settings"),
        }
    }
    /// Write the access file, readable by its owner only, replacing it whole
    /// so a crash mid write never leaves half a list.
    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(path, &serde_json::to_vec_pretty(self)?)
    }
    /// Let this helper in any time. Replaces an earlier entry for the same key.
    pub fn trust(&mut self, id: &str, name: &str, control: bool) -> Result<()> {
        EndpointId::from_str(id.trim()).map_err(|_| anyhow!("That is not a helper ID"))?;
        ensure!(
            !name.trim().is_empty() && name.len() <= 80 && !name.chars().any(char::is_control),
            "Enter a helper name of at most 80 bytes"
        );
        self.helpers.retain(|h| h.id != id.trim());
        self.helpers.push(Helper {
            id: id.trim().to_string(),
            name: name.trim().to_string(),
            control,
            added: wire::now(),
        });
        Ok(())
    }
    pub fn forget(&mut self, id: &str) {
        self.helpers.retain(|h| h.id != id);
    }
    /// Set the unattended password, or remove it with `None`.
    pub fn set_password(&mut self, password: Option<&str>) -> Result<()> {
        let Some(password) = password else {
            self.password = None;
            return Ok(());
        };
        ensure!(
            password.chars().count() >= MIN_PASSWORD,
            "Use at least {MIN_PASSWORD} characters for an unattended password"
        );
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| anyhow!("Cannot make a salt: {e}"))?;
        let hash = derive(password, &salt)?;
        self.password = Some(format!("{}${}", hex_encode(&salt), hex_encode(&hash)));
        Ok(())
    }
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }
    fn helper(&self, id: &str) -> Option<&Helper> {
        self.helpers.iter().find(|h| h.id == id)
    }
    fn password_matches(&self, password: &str) -> bool {
        use subtle::ConstantTimeEq;
        let Some((salt, hash)) = self.password.as_deref().and_then(|p| p.split_once('$')) else {
            return false;
        };
        let (Some(salt), Some(hash)) = (hex_decode(salt), hex_decode(hash)) else {
            return false;
        };
        derive(password, &salt).is_ok_and(|candidate| bool::from(candidate.ct_eq(&hash)))
    }
}
fn derive(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(ARGON_MEMORY_KIB, ARGON_PASSES, 1, Some(32))
        .map_err(|e| anyhow!("{e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(out)
}

/// What an unattended machine reports while it listens.
pub enum Notice {
    /// Listening, and reachable by `machine`. `address` is the full current
    /// address, for a helper on the same network or a test.
    Ready {
        machine: String,
        address: EndpointAddr,
    },
    Status(String),
    /// A helper is in. Whoever holds `session` owns it: dropping it, or
    /// calling `stop`, ends it, and `set_control` changes what the helper
    /// may do, exactly as in an attended session.
    Connected {
        name: String,
        peer: String,
        control: bool,
        session: Session,
    },
    /// A helper was turned away, and why.
    Refused {
        name: String,
        peer: String,
        reason: String,
    },
    /// The listener stopped, for good.
    Finished(Result<()>),
}
pub struct Listener {
    pub notices: mpsc::Receiver<Notice>,
    cancel: CancellationToken,
}
impl Listener {
    /// Stop listening. A session in progress ends with it.
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Listen for unattended helpers as the machine `key` names. `access_path`
/// is read again on every knock, so a change made in another window or by
/// another process applies to the next connection with nothing restarted.
pub fn listen<F>(options: HostOptions, key: SecretKey, access_path: PathBuf, desktop: F) -> Listener
where
    F: Fn() -> Result<Box<dyn Desktop>> + Send + Sync + 'static,
{
    let (notices_tx, notices) = mpsc::channel(32);
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let desktop = Arc::new(desktop);
    tokio::spawn(async move {
        let result = tokio::select! {
            biased;
            _ = stop.cancelled() => Ok(()),
            result = run_listener(&notices_tx, &stop, options, key, &access_path, desktop) => result,
        };
        let _ = notices_tx.send(Notice::Finished(result)).await;
    });
    Listener { notices, cancel }
}

async fn run_listener<F>(
    notices: &mpsc::Sender<Notice>,
    stop: &CancellationToken,
    options: HostOptions,
    key: SecretKey,
    access_path: &Path,
    desktop: Arc<F>,
) -> Result<()>
where
    F: Fn() -> Result<Box<dyn Desktop>> + Send + Sync + 'static,
{
    let machine = machine_id(&key);
    let endpoint = session::endpoint_with(&options, Some(key), Lookup::Publish).await?;
    let _close = Closing(endpoint.clone());
    if options.relay
        && tokio::time::timeout(Duration::from_secs(12), endpoint.online())
            .await
            .is_err()
    {
        let _ = notices
            .send(Notice::Status(
                "The relay is not reachable yet. Helpers on other networks may not get through until it is".into(),
            ))
            .await;
    }
    notices
        .send(Notice::Ready {
            machine,
            address: endpoint.addr(),
        })
        .await
        .map_err(|_| anyhow!("Nobody is listening for notices"))?;
    let mut throttle = Throttle::default();
    loop {
        let incoming = endpoint.accept().await.context("The listener closed")?;
        let knock = async {
            let connection = incoming.await?;
            let (send, mut recv) = connection.accept_bi().await?;
            let message: Message = wire::read(&mut recv).await?;
            Ok::<_, anyhow::Error>((connection, send, recv, message))
        };
        let Ok(Ok((connection, send, recv, message))) =
            tokio::time::timeout(Duration::from_secs(5), knock).await
        else {
            continue;
        };
        let peer = connection.remote_id().to_string();
        let Message::Knock {
            version: 2,
            name,
            password,
        } = message
        else {
            refuse(connection, send, "This computer accepts only unattended connections on this ID. Ask for an invitation instead".into());
            continue;
        };
        let name =
            if !name.trim().is_empty() && name.len() <= 80 && !name.chars().any(char::is_control) {
                name.trim().to_string()
            } else {
                "Unnamed helper".to_string()
            };
        let decision = match Access::load(access_path) {
            Ok(access) => authorize(&access, &peer, password.as_deref(), &mut throttle).await,
            Err(error) => Err(format!("{error:#}")),
        };
        let control = match decision {
            Ok(control) => control,
            Err(reason) => {
                refuse(connection, send, reason.clone());
                let _ = notices.send(Notice::Refused { name, peer, reason }).await;
                continue;
            }
        };
        let (session, mut worker) = session::channels();
        let desktop = desktop.clone();
        // The session ends when whoever holds it lets go, or when this
        // listener stops: either cancels the same token.
        let ended = session.cancel_token();
        notices
            .send(Notice::Connected {
                name: name.clone(),
                peer: peer.clone(),
                control,
                session,
            })
            .await
            .map_err(|_| anyhow!("Nobody is listening for notices"))?;
        let result = tokio::select! {
            _ = stop.cancelled() => Ok(()),
            _ = ended.cancelled() => Ok(()),
            result = session::serve(&mut worker, &connection, send, recv, peer, control, move || desktop()) => result,
        };
        connection.close(0u8.into(), b"Session ended");
        if let Err(error) = result {
            let _ = notices
                .send(Notice::Status(format!("The last session ended: {error:#}")))
                .await;
        }
    }
}

/// Tell a helper why it was turned away, and close once it has heard.
///
/// Closing at once could beat the message to the helper, which then saw only
/// "connection lost" and no reason. The helper closes when it reads the
/// refusal; three seconds is the most this waits for it, off the listener so
/// the next knock is not held up.
fn refuse(
    connection: iroh::endpoint::Connection,
    mut send: iroh::endpoint::SendStream,
    reason: String,
) {
    tokio::spawn(async move {
        let _ = wire::write(&mut send, &Message::Refused(reason)).await;
        let _ = send.finish();
        let _ = tokio::time::timeout(Duration::from_secs(3), connection.closed()).await;
        connection.close(0u8.into(), b"refused");
    });
}

/// Let a helper in, and with what, or say why not.
async fn authorize(
    access: &Access,
    peer: &str,
    password: Option<&str>,
    throttle: &mut Throttle,
) -> std::result::Result<bool, String> {
    if !access.enabled {
        return Err("Unattended access is switched off on that computer".into());
    }
    if let Some(helper) = access.helper(peer) {
        return Ok(helper.control);
    }
    match password {
        Some(password) if access.has_password() => {
            if throttle.locked() {
                return Err(
                    "Too many wrong passwords. Password access to that computer is paused for 15 minutes"
                        .into(),
                );
            }
            let access = access.clone();
            let password = password.to_string();
            // Argon2 is deliberately slow; keep it off the async threads.
            let matches = tokio::task::spawn_blocking(move || access.password_matches(&password))
                .await
                .unwrap_or(false);
            if matches {
                Ok(true)
            } else {
                throttle.failed();
                // A wrong guess costs the guesser time as well as an attempt.
                tokio::time::sleep(Duration::from_secs(1)).await;
                Err("Wrong password for that computer".into())
            }
        }
        _ => Err("This helper is not allowed on that computer. Ask the person there to pair you during a support session, or use the unattended password".into()),
    }
}

/// Wrong passwords over the last fifteen minutes, from anyone. Counted
/// across helpers because a guesser can make a new key for every attempt.
#[derive(Default)]
struct Throttle {
    failures: VecDeque<Instant>,
}
impl Throttle {
    fn prune(&mut self) {
        while self
            .failures
            .front()
            .is_some_and(|at| at.elapsed() > LOCKOUT)
        {
            self.failures.pop_front();
        }
    }
    fn locked(&mut self) -> bool {
        self.prune();
        self.failures.len() >= LOCKOUT_FAILURES
    }
    fn failed(&mut self) {
        self.prune();
        self.failures.push_back(Instant::now());
    }
}

/// Connect to an unattended machine by its ID, as the helper `key`.
/// `password` is only needed when this helper has not been paired.
pub fn connect(
    machine: String,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
) -> Session {
    let target = EndpointId::from_str(machine.trim())
        .map(EndpointAddr::from)
        .map_err(|_| {
            anyhow!(
                "That is not a machine ID. Copy it from the computer's unattended access settings"
            )
        });
    connect_to(target, name, password, key, options)
}

/// [`connect`] with a full address, for a helper that already knows where
/// the machine is, such as one on the same network, or a test.
pub fn connect_to(
    target: Result<EndpointAddr>,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
) -> Session {
    let (session, mut worker) = session::channels();
    tokio::spawn(async move {
        let cancel = worker.cancel_token();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = run_connect(&mut worker, target, name, password, key, options) => result,
        };
        cancel.cancel();
        let _ = worker.emit(Event::Finished(result)).await;
    });
    session
}
async fn run_connect(
    worker: &mut session::Worker,
    target: Result<EndpointAddr>,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
) -> Result<()> {
    let target = target?;
    ensure!(
        !name.trim().is_empty() && name.len() <= 80 && !name.chars().any(char::is_control),
        "Enter a helper name of at most 80 bytes"
    );
    worker
        .emit(Event::Status("Finding the computer".into()))
        .await?;
    let endpoint = session::endpoint_with(&options, Some(key), Lookup::Resolve).await?;
    let _close = Closing(endpoint.clone());
    let connection = tokio::time::timeout(Duration::from_secs(30), endpoint.connect(target, wire::ALPN))
        .await
        .context("The computer did not answer. It may be off, asleep, offline, or its unattended access may be switched off")?
        .context("Cannot reach the computer")?;
    let (mut send, recv) = connection.open_bi().await?;
    wire::write(
        &mut send,
        &Message::Knock {
            version: 2,
            name,
            password,
        },
    )
    .await?;
    let result = session::watch_session(worker, &connection, send, recv).await;
    connection.close(0u8.into(), b"Session ended");
    result
}

struct Closing(iroh::Endpoint);
impl Drop for Closing {
    fn drop(&mut self) {
        let endpoint = self.0.clone();
        tokio::spawn(async move { endpoint.close().await });
    }
}

/// Write a file only its owner can read, replacing any old one whole.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("The settings path has no folder")?;
    std::fs::create_dir_all(dir).with_context(|| format!("Cannot create {}", dir.display()))?;
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("Cannot write {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("Cannot replace {}", path.display()))?;
    Ok(())
}
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Reject anything but the expected machine, so a helper is never let into
/// the wrong computer by a confused address.
pub fn validate_machine_id(text: &str) -> Result<()> {
    if EndpointId::from_str(text.trim()).is_err() {
        bail!("That is not a machine ID");
    }
    Ok(())
}
