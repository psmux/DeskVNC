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
    Approval, Desktop, Event, HostOptions, Session,
    session::{self, Lookup},
    wire::{self, Message},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
/// A lasting identity, for a machine or a helper.
pub use iroh::SecretKey;
use iroh::{EndpointAddr, EndpointId};
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
    /// Whether their tools may run commands and copy files. Off unless the
    /// person turned it on for this helper, including for every helper paired
    /// before it existed.
    #[serde(default)]
    pub tools: bool,
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
            tools: false,
            added: wire::now(),
        });
        Ok(())
    }
    /// Allow or stop a paired helper's commands and file requests. `false`
    /// when no helper has that ID.
    pub fn allow_tools(&mut self, id: &str, allowed: bool) -> bool {
        match self.helpers.iter_mut().find(|h| h.id == id.trim()) {
            Some(helper) => {
                helper.tools = allowed;
                true
            }
            None => false,
        }
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

/// How long the person at the computer has to answer a helper who asks.
/// The helper waits a little longer than this for the grant.
pub const ASK_TIMEOUT: Duration = Duration::from_secs(60);

/// The person's answer to a helper who asked to come in.
pub struct Asked {
    pub approval: Approval,
    /// Let their tools run commands and copy files.
    pub tools: bool,
    /// Pair them, so they come in later without asking.
    pub pair: bool,
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
    /// A helper that is not paired, and has no password, asks to come in.
    /// The person at the computer answers on `answer`. Nobody answering
    /// within a minute, or dropping it, turns the helper away.
    Ask {
        name: String,
        peer: String,
        /// The helper can send commands and file requests.
        tools: bool,
        answer: tokio::sync::oneshot::Sender<Asked>,
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
    spawn_listener(options, key, access_path, false, desktop)
}

/// Listen as [`listen`] does, on a computer where nobody has signed in yet.
/// Nobody is there to approve a helper who is not paired, so one is turned
/// away rather than asked about, and nothing is offered to a helper's tools:
/// at the sign in screen a command would run as the system, not as a person.
pub fn listen_at_login<F>(
    options: HostOptions,
    key: SecretKey,
    access_path: PathBuf,
    desktop: F,
) -> Listener
where
    F: Fn() -> Result<Box<dyn Desktop>> + Send + Sync + 'static,
{
    spawn_listener(options, key, access_path, true, desktop)
}

fn spawn_listener<F>(
    options: HostOptions,
    key: SecretKey,
    access_path: PathBuf,
    login: bool,
    desktop: F,
) -> Listener
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
            result = run_listener(&notices_tx, &stop, options, key, &access_path, login, desktop) => result,
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
    login: bool,
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
    let seats = Arc::new(tokio::sync::Semaphore::new(MAX_HELPERS));
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
            tools,
            jpeg,
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
            Err(error) => Decision::Refuse(format!("{error:#}")),
        };
        let decision = match decision {
            Decision::Ask if login => Decision::Refuse(
                "Nobody has signed in on that computer, so nobody can approve you. Ask to be paired, or use its unattended password".into(),
            ),
            Decision::Ask => ask(notices, access_path, &name, &peer, tools).await,
            other => other,
        };
        let tools = tools && !login;
        let (control, allowed_tools) = match decision {
            Decision::Grant(control, tools) => (control, tools),
            Decision::Ask => unreachable!("answered above"),
            Decision::Refuse(reason) => {
                refuse(connection, send, reason.clone());
                let _ = notices.send(Notice::Refused { name, peer, reason }).await;
                continue;
            }
        };
        let Ok(seat) = seats.clone().try_acquire_owned() else {
            let reason = format!(
                "That computer already has {MAX_HELPERS} helpers connected. Try again when one leaves"
            );
            refuse(connection, send, reason.clone());
            let _ = notices.send(Notice::Refused { name, peer, reason }).await;
            continue;
        };
        let (session, mut worker) = session::channels();
        worker.tools_tx.send_replace(tools && allowed_tools);
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
        // Each helper is served on its own, so a second one is answered while
        // the first is still in, instead of finding the computer silent.
        let stop = stop.clone();
        let notices = notices.clone();
        tokio::spawn(async move {
            let _seat = seat;
            let result = tokio::select! {
                _ = stop.cancelled() => Ok(()),
                _ = ended.cancelled() => Ok(()),
                result = session::serve(&mut worker, &connection, send, recv, peer, control, tools, jpeg, move || desktop()) => result,
            };
            connection.close(0u8.into(), b"Session ended");
            // Whoever holds the session hears that it ended, so a banner
            // saying the helper is in does not outlive the helper.
            let reason = result.as_ref().err().map(|error| format!("{error:#}"));
            let _ = worker
                .emit(Event::Finished(match &reason {
                    Some(reason) => Err(anyhow!("{reason}")),
                    None => Ok(()),
                }))
                .await;
            if let Some(reason) = reason {
                let _ = notices
                    .send(Notice::Status(format!("{name}'s session ended: {reason}")))
                    .await;
            }
        });
    }
}

/// How many helpers may be connected unattended at once.
pub const MAX_HELPERS: usize = 8;

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

/// What happens to a helper that knocks.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// In, with control or not, and with its tools allowed or not.
    Grant(bool, bool),
    /// Not paired and no password: the person at the computer decides.
    Ask,
    Refuse(String),
}

/// Ask the person at the computer about a helper, and pair it if they say so.
async fn ask(
    notices: &mpsc::Sender<Notice>,
    access_path: &Path,
    name: &str,
    peer: &str,
    tools: bool,
) -> Decision {
    let (answer, reply) = tokio::sync::oneshot::channel();
    if notices
        .send(Notice::Ask {
            name: name.to_string(),
            peer: peer.to_string(),
            tools,
            answer,
        })
        .await
        .is_err()
    {
        return Decision::Refuse("Nobody is at that computer to approve you".into());
    }
    let asked = match tokio::time::timeout(ASK_TIMEOUT, reply).await {
        Ok(Ok(asked)) => asked,
        Ok(Err(_)) => return Decision::Refuse("The person at that computer did not answer".into()),
        Err(_) => return Decision::Refuse("Nobody answered at that computer within a minute. Ask the person there to approve you, or to pair you".into()),
    };
    let control = match asked.approval {
        Approval::Deny => {
            return Decision::Refuse("The person at that computer declined this connection".into());
        }
        Approval::View => false,
        Approval::Control => true,
    };
    let tools = tools && asked.tools;
    if asked.pair {
        // A failed save still lets this session in; it only means the next
        // one asks again.
        let saved = Access::load(access_path).and_then(|mut access| {
            access.trust(peer, name, control)?;
            access.allow_tools(peer, tools);
            access.save(access_path)
        });
        if let Err(error) = saved {
            let _ = notices
                .send(Notice::Status(format!("Could not pair {name}: {error:#}")))
                .await;
        }
    }
    Decision::Grant(control, tools)
}

/// Let a helper in, and with what, or say why not: whether it may control,
/// and whether its tools may run commands and copy files. A password never
/// grants the second; only a paired helper's own entry, or the person at the
/// computer, can.
async fn authorize(
    access: &Access,
    peer: &str,
    password: Option<&str>,
    throttle: &mut Throttle,
) -> Decision {
    use Decision::{Ask, Grant, Refuse};
    if !access.enabled {
        return Refuse("Unattended access is switched off on that computer".into());
    }
    if let Some(helper) = access.helper(peer) {
        return Grant(helper.control, helper.tools);
    }
    match password {
        Some(password) if access.has_password() => {
            if throttle.locked() {
                return Refuse(
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
                Grant(true, false)
            } else {
                throttle.failed();
                // A wrong guess costs the guesser time as well as an attempt.
                tokio::time::sleep(Duration::from_secs(1)).await;
                Refuse("Wrong password for that computer".into())
            }
        }
        // No password, or one sent to a computer that has none: whoever is
        // there decides, the same way they would for an invitation.
        _ => Ask,
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
    open(machine_addr(&machine), name, password, key, options, false)
}
/// [`connect`] for a helper whose tools send commands and file requests,
/// such as DeskVNC's agent plane. They run only if the computer allows them
/// for this helper.
pub fn connect_with_tools(
    machine: String,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
) -> Session {
    open(machine_addr(&machine), name, password, key, options, true)
}
fn machine_addr(machine: &str) -> Result<EndpointAddr> {
    EndpointId::from_str(machine.trim())
        .map(EndpointAddr::from)
        .map_err(|_| {
            anyhow!(
                "That is not a machine ID. Copy it from the computer's unattended access settings"
            )
        })
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
    open(target, name, password, key, options, false)
}
/// [`connect_to`] for a helper whose tools send commands and file requests.
pub fn connect_to_with_tools(
    target: Result<EndpointAddr>,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
) -> Session {
    open(target, name, password, key, options, true)
}
fn open(
    target: Result<EndpointAddr>,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
    tools: bool,
) -> Session {
    let (session, mut worker) = session::channels();
    tokio::spawn(async move {
        let cancel = worker.cancel_token();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = run_connect(&mut worker, target, name, password, key, options, tools) => result,
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
    tools: bool,
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
            tools,
            jpeg: true,
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
