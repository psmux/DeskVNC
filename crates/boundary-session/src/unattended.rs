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
    Abilities, Approval, Desktop, Event, HostOptions, Session,
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
    /// Whether they see what the person copies while they are connected.
    /// Off unless the person turned it on for this helper, including for
    /// every helper paired before it existed, and always off at the sign in
    /// screen.
    #[serde(default)]
    pub clipboard: bool,
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
            clipboard: false,
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
    /// Let a paired helper see what the person copies, or stop it. `false`
    /// when no helper has that ID.
    pub fn allow_clipboard(&mut self, id: &str, allowed: bool) -> bool {
        match self.helpers.iter_mut().find(|h| h.id == id.trim()) {
            Some(helper) => {
                helper.clipboard = allowed;
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
    /// Let them see what the person copies.
    pub clipboard: bool,
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
        /// The helper can carry clipboard text, so the person can be asked
        /// whether it may see what they copy.
        clipboard: bool,
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
    // A helper being served holds a seat until it has been told how its
    // session ended, so the endpoint closes only after that.
    let seats = Arc::new(tokio::sync::Semaphore::new(MAX_HELPERS));
    let _close = Closing(endpoint.clone(), seats.clone());
    // Say which computer this is to a helper that dialled the address. On
    // the random port of a machine that could not have the usual one this
    // costs nothing and still serves a helper told the port.
    let sockets = endpoint.bound_sockets();
    let answering = crate::direct::answer(sockets.clone(), endpoint.id(), stop.child_token());
    // Tell the local network too, so a scan lists this machine even on a
    // random port. Only where it answers by address anyway: a machine held
    // to one private interface stays off the LAN's multicast.
    let _advertised = match sockets.first() {
        Some(socket) if answering > 0 && options.bind_ip.is_none() => {
            let name = crate::nearby::computer_name();
            crate::nearby::advertise(endpoint.id(), socket.port(), &name)
        }
        _ => None,
    };
    if answering == 0 || !sockets.iter().any(|s| s.port() == crate::direct::PORT) {
        let _ = notices
            .send(Notice::Status(format!(
                "Port {} is taken, so helpers must connect by machine ID",
                crate::direct::PORT
            )))
            .await;
    }
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
    let door = Arc::new(Door {
        notices: notices.clone(),
        stop: stop.clone(),
        access_path: access_path.to_path_buf(),
        login,
        desktop,
        throttle: tokio::sync::Mutex::new(Throttle::default()),
        seats,
        asking: Arc::new(tokio::sync::Mutex::new(())),
    });
    loop {
        let incoming = endpoint.accept().await.context("The listener closed")?;
        // Each knock is read, checked and asked about on its own, so one
        // that is slow to speak, or one the person is still deciding about,
        // leaves the computer answering everyone else.
        let door = door.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = stop.cancelled() => {}
                _ = knock(door, incoming) => {}
            }
        });
    }
}

/// What every knock on an unattended computer shares.
struct Door<F> {
    notices: mpsc::Sender<Notice>,
    stop: CancellationToken,
    access_path: PathBuf,
    login: bool,
    desktop: Arc<F>,
    /// Wrong passwords, counted across every helper.
    throttle: tokio::sync::Mutex<Throttle>,
    seats: Arc<tokio::sync::Semaphore>,
    /// Held while the person is asked about a helper. They answer one at a
    /// time, so a second helper is told they are busy rather than given a
    /// prompt that would replace the first under their hand.
    asking: Arc<tokio::sync::Mutex<()>>,
}

async fn knock<F>(door: Arc<Door<F>>, incoming: iroh::endpoint::Incoming)
where
    F: Fn() -> Result<Box<dyn Desktop>> + Send + Sync + 'static,
{
    let Door {
        notices,
        stop,
        access_path,
        login,
        desktop,
        throttle,
        seats,
        asking,
    } = &*door;
    let login = *login;
    let knock = async {
        let connection = incoming.await?;
        let (send, mut recv) = connection.accept_bi().await?;
        let message: Message = wire::read(&mut recv).await?;
        Ok::<_, anyhow::Error>((connection, send, recv, message))
    };
    let Ok(Ok((connection, send, recv, message))) =
        tokio::time::timeout(Duration::from_secs(5), knock).await
    else {
        return;
    };
    let peer = connection.remote_id().to_string();
    let Message::Knock {
        version: 2,
        name,
        password,
        tools,
        jpeg,
        tiles,
        video,
        clipboard,
    } = message
    else {
        refuse(connection, send, "This computer accepts only unattended connections on this ID. Ask for an invitation instead".into());
        return;
    };
    let name = if !name.trim().is_empty() && name.len() <= 80 && !name.chars().any(char::is_control)
    {
        name.trim().to_string()
    } else {
        "Unnamed helper".to_string()
    };
    let decision = match Access::load(access_path) {
        Ok(access) => authorize(&access, &peer, password.as_deref(), throttle).await,
        Err(error) => Decision::Refuse(format!("{error:#}")),
    };
    let decision = match decision {
        Decision::Ask if login => Decision::Refuse(
            "Nobody has signed in on that computer, so nobody can approve you. Ask to be paired, or use its unattended password".into(),
        ),
        Decision::Ask => {
            ask(
                notices,
                asking,
                &connection,
                access_path,
                &name,
                &peer,
                Offered { tools, clipboard },
            )
            .await
        }
        other => other,
    };
    // At the sign in screen a command would run as the system, and whatever
    // is copied there is most likely a password.
    let tools = tools && !login;
    let clipboard_read = clipboard && !login;
    let (control, allowed_tools, allowed_clipboard) = match decision {
        Decision::Grant(Granted {
            control,
            tools,
            clipboard,
        }) => (control, tools, clipboard),
        Decision::Ask => unreachable!("answered above"),
        Decision::Refuse(reason) => {
            refuse(connection, send, reason.clone());
            let _ = notices.send(Notice::Refused { name, peer, reason }).await;
            return;
        }
    };
    let Ok(seat) = seats.clone().try_acquire_owned() else {
        let reason = format!(
            "That computer already has {MAX_HELPERS} helpers connected. Try again when one leaves"
        );
        refuse(connection, send, reason.clone());
        let _ = notices.send(Notice::Refused { name, peer, reason }).await;
        return;
    };
    let (session, mut worker) = session::channels();
    worker.tools_tx.send_replace(tools && allowed_tools);
    worker
        .clipboard_read
        .send_replace(clipboard_read && allowed_clipboard);
    let desktop = desktop.clone();
    // The session ends when whoever holds it lets go, or when this
    // listener stops: either cancels the same token.
    let ended = session.cancel_token();
    if notices
        .send(Notice::Connected {
            name: name.clone(),
            peer: peer.clone(),
            control,
            session,
        })
        .await
        .is_err()
    {
        // Nobody holds the listener any more, so it is stopping.
        return;
    }
    // Each helper is served on its own, so a second one is answered while
    // the first is still in, instead of finding the computer silent.
    let stop = stop.clone();
    let notices = notices.clone();
    tokio::spawn(async move {
        let _seat = seat;
        let result = tokio::select! {
            _ = stop.cancelled() => Ok(()),
            _ = ended.cancelled() => Ok(()),
            result = session::serve(&mut worker, &connection, send, recv, peer, session::Offer { control, tools, clipboard }, wire::Screens::from_hello(jpeg, tiles, &video), move || desktop()) => result,
        };
        // The app stopping, for an update or a restart, ends nothing the
        // person decided, so the helper is told the link went and
        // connects again once the computer is back. Quitting also drops
        // whoever holds the session, so the session may have ended as
        // closed a moment before this saw the stop: the stop still wins.
        let result = if stop.is_cancelled() {
            Err(session::link_lost(anyhow!(
                "DeskVNC Support on that computer stopped"
            )))
        } else {
            result
        };
        session::close_served(&connection, &result);
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
    /// In, with what it may do.
    Grant(Granted),
    /// Not paired and no password: the person at the computer decides.
    Ask,
    Refuse(String),
}

/// What a helper let in may do.
#[derive(Debug, PartialEq, Eq)]
struct Granted {
    control: bool,
    /// Its tools may run commands and copy files.
    tools: bool,
    /// It sees what the person copies.
    clipboard: bool,
}
/// What a helper said it can do beyond the screen, which the person is asked
/// about.
struct Offered {
    tools: bool,
    clipboard: bool,
}

/// Ask the person at the computer about a helper, and pair it if they say so.
///
/// The question is withdrawn if the helper leaves first: dropping the
/// reply closes the answer, which is how the window knows to take it down.
async fn ask(
    notices: &mpsc::Sender<Notice>,
    asking: &tokio::sync::Mutex<()>,
    connection: &iroh::endpoint::Connection,
    access_path: &Path,
    name: &str,
    peer: &str,
    offered: Offered,
) -> Decision {
    let Offered { tools, clipboard } = offered;
    let Ok(_asking) = asking.try_lock() else {
        return Decision::Refuse("The person at that computer is already answering another helper. Try again in a minute".into());
    };
    let (answer, reply) = tokio::sync::oneshot::channel();
    if notices
        .send(Notice::Ask {
            name: name.to_string(),
            peer: peer.to_string(),
            tools,
            clipboard,
            answer,
        })
        .await
        .is_err()
    {
        return Decision::Refuse("Nobody is at that computer to approve you".into());
    }
    let answered = tokio::select! {
        _ = connection.closed() => return Decision::Refuse("The helper left before anyone answered".into()),
        answered = tokio::time::timeout(ASK_TIMEOUT, reply) => answered,
    };
    let asked = match answered {
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
    let clipboard = clipboard && asked.clipboard;
    if asked.pair {
        // A failed save still lets this session in; it only means the next
        // one asks again.
        let saved = Access::load(access_path).and_then(|mut access| {
            access.trust(peer, name, control)?;
            access.allow_tools(peer, tools);
            access.allow_clipboard(peer, clipboard);
            access.save(access_path)
        });
        if let Err(error) = saved {
            let _ = notices
                .send(Notice::Status(format!("Could not pair {name}: {error:#}")))
                .await;
        }
    }
    Decision::Grant(Granted {
        control,
        tools,
        clipboard,
    })
}

/// Let a helper in, and with what, or say why not: whether it may control,
/// and whether its tools may run commands and copy files. A password never
/// grants the second; only a paired helper's own entry, or the person at the
/// computer, can.
async fn authorize(
    access: &Access,
    peer: &str,
    password: Option<&str>,
    throttle: &tokio::sync::Mutex<Throttle>,
) -> Decision {
    use Decision::{Ask, Grant, Refuse};
    if !access.enabled {
        return Refuse("Unattended access is switched off on that computer".into());
    }
    if let Some(helper) = access.helper(peer) {
        return Grant(Granted {
            control: helper.control,
            tools: helper.tools,
            clipboard: helper.clipboard,
        });
    }
    match password {
        Some(password) if access.has_password() => {
            // One password at a time, as when knocks were read one by one:
            // a burst of guesses all counts before the next is tried.
            let mut throttle = throttle.lock().await;
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
                Grant(Granted {
                    control: true,
                    tools: false,
                    clipboard: false,
                })
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
    open(
        Dial::Text(machine),
        name,
        password,
        key,
        options,
        Abilities::default(),
    )
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
    open(
        Dial::Text(machine),
        name,
        password,
        key,
        options,
        Abilities {
            tools: true,
            video: false,
            clipboard: false,
        },
    )
}
/// [`connect`] for a helper that says what more it can do, such as take
/// moving screens as video.
pub fn connect_with(
    machine: String,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
    abilities: Abilities,
) -> Session {
    open(Dial::Text(machine), name, password, key, options, abilities)
}
/// What [`open`] dials: an address already worked out, or what the helper
/// typed, which may be an ID or an address and is resolved once the session
/// has started so a slow lookup shows as "Finding the computer".
enum Dial {
    Addr(Result<EndpointAddr>),
    Text(String),
}
impl Dial {
    /// A mistyped target is the helper's to fix; a lookup that fails is a
    /// network that may come back, so only that is worth trying again.
    async fn resolve(self) -> Result<EndpointAddr> {
        match self {
            Self::Addr(addr) => addr,
            Self::Text(text) => crate::direct::resolve(target(&text)?)
                .await
                .map_err(session::link_lost),
        }
    }
}
fn target(text: &str) -> Result<crate::direct::Target> {
    crate::direct::Target::parse(text).map_err(|error| {
        anyhow!(
            "{error}. Enter the machine ID from the computer's unattended access settings, or its address"
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
    open(
        Dial::Addr(target),
        name,
        password,
        key,
        options,
        Abilities::default(),
    )
}
/// [`connect_to`] for a helper whose tools send commands and file requests.
pub fn connect_to_with_tools(
    target: Result<EndpointAddr>,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
) -> Session {
    open(
        Dial::Addr(target),
        name,
        password,
        key,
        options,
        Abilities {
            tools: true,
            video: false,
            clipboard: false,
        },
    )
}
/// [`connect_to`] for a helper that says what more it can do.
pub fn connect_to_with(
    target: Result<EndpointAddr>,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
    abilities: Abilities,
) -> Session {
    open(Dial::Addr(target), name, password, key, options, abilities)
}
fn open(
    target: Dial,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
    abilities: Abilities,
) -> Session {
    let (session, mut worker) = session::channels();
    tokio::spawn(async move {
        let cancel = worker.cancel_token();
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = run_connect(&mut worker, target, name, password, key, options, abilities) => result,
        };
        cancel.cancel();
        let _ = worker.emit(Event::Finished(result)).await;
    });
    session
}
async fn run_connect(
    worker: &mut session::Worker,
    target: Dial,
    name: String,
    password: Option<String>,
    key: SecretKey,
    options: HostOptions,
    abilities: Abilities,
) -> Result<()> {
    ensure!(
        !name.trim().is_empty() && name.len() <= 80 && !name.chars().any(char::is_control),
        "Enter a helper name of at most 80 bytes"
    );
    worker
        .emit(Event::Status("Finding the computer".into()))
        .await?;
    let target = target.resolve().await?;
    let endpoint = crate::shared::helper(&options, key).await?;
    let result = visit(worker, &endpoint, target, name, password, abilities).await;
    // A lost link is dialled again in a moment. Binding a new endpoint for
    // that and finding the relay again cost 1 to 3 seconds of the 4 to 7 it
    // took to get back to a restarted computer, so this one is kept a while.
    if result.as_ref().is_err_and(session::LinkLost::is) {
        let kept = endpoint.clone();
        tokio::spawn(async move {
            tokio::time::sleep(KEEP_ENDPOINT).await;
            drop(kept);
        });
    }
    result
}
/// How long a helper's endpoint outlives a session whose link was lost.
const KEEP_ENDPOINT: Duration = Duration::from_secs(30);
async fn visit(
    worker: &mut session::Worker,
    endpoint: &iroh::Endpoint,
    target: EndpointAddr,
    name: String,
    password: Option<String>,
    abilities: Abilities,
) -> Result<()> {
    let connection = tokio::time::timeout(Duration::from_secs(30), endpoint.connect(target, wire::ALPN))
        .await
        .context("The computer did not answer. It may be off, asleep, offline, or its unattended access may be switched off")
        .map_err(session::link_lost)?
        .context("Cannot reach the computer")
        .map_err(session::link_lost)?;
    // Nothing has been asked yet, so failing here is the link failing.
    let (mut send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| session::link_lost(e.into()))?;
    wire::write(
        &mut send,
        &Message::Knock {
            version: 2,
            name,
            password,
            tools: abilities.tools,
            jpeg: true,
            tiles: true,
            video: abilities.codecs(),
            clipboard: abilities.clipboard,
        },
    )
    .await
    .map_err(session::link_lost)?;
    let result =
        session::watch_session(worker, &connection, send, recv, session::UNATTENDED_WAIT).await;
    connection.close(0u8.into(), b"Session ended");
    result
}

struct Closing(iroh::Endpoint, Arc<tokio::sync::Semaphore>);
impl Drop for Closing {
    fn drop(&mut self) {
        let endpoint = self.0.clone();
        let seats = self.1.clone();
        tokio::spawn(async move {
            // Closing the endpoint closes every connection as a plain end,
            // which would beat the sessions telling their helpers the
            // computer went away. Wait for them, but not forever.
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                seats.acquire_many(MAX_HELPERS as u32),
            )
            .await;
            endpoint.close().await
        });
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
pub fn validate_target(text: &str) -> Result<()> {
    target(text).map(|_| ())
}
/// Accept only a machine ID, for places that must not take an address.
pub fn validate_machine_id(text: &str) -> Result<()> {
    if EndpointId::from_str(text.trim()).is_err() {
        bail!("That is not a machine ID");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_saved_before_clipboard_never_read_it() {
        let saved = br#"{"enabled":true,"helpers":[{"id":"x","name":"Friend","control":true,"tools":true,"added":1}]}"#;
        let access: Access = serde_json::from_slice(saved).unwrap();
        assert!(!access.helpers[0].clipboard);
        let mut access = access;
        assert!(access.allow_clipboard("x", true));
        assert!(access.helpers[0].clipboard);
        assert!(!access.allow_clipboard("nobody", true));
        let back: Access = serde_json::from_slice(&serde_json::to_vec(&access).unwrap()).unwrap();
        assert!(back.helpers[0].clipboard);
    }

    #[tokio::test]
    async fn a_password_never_lets_a_helper_read() {
        let mut access = Access {
            enabled: true,
            ..Access::default()
        };
        access.set_password(Some("correct horse battery")).unwrap();
        let throttle = tokio::sync::Mutex::new(Throttle::default());
        let decision = authorize(
            &access,
            "stranger",
            Some("correct horse battery"),
            &throttle,
        )
        .await;
        assert_eq!(
            decision,
            Decision::Grant(Granted {
                control: true,
                tools: false,
                clipboard: false,
            })
        );
    }
}
