//! One plane, and the seam where sessions come from.
//!
//! ## The honest constraint, stated in the type system
//!
//! `agent-plane` drives limbs; it does not create them. [`Attach`] wants an
//! `Arc<dyn Limb>` and a live `SessionHandle`, and the only thing in this
//! product that can produce those is the shell, through `ProtocolRegistry` and
//! `connect_session`, which resolve a stored credential from the keychain on a
//! blocking thread. So the place that plugs into is a trait,
//! [`SessionSource`], with two implementations today:
//!
//! * [`ShellSource`], which speaks `dvvp.v1` over the unix socket. It attaches
//!   to sessions DeskVNCViewer already has, and where there is none it ASKS the
//!   application to open the machine, which is the same path a person's click
//!   takes. **The credential never crosses this process** (`00 R19`, `09 §4`):
//!   an agent names a saved machine, and the shell resolves the secret from the
//!   keychain exactly as it does for a click.
//! * [`crate::fake::FakeSource`], which builds a limb with a recorder on the
//!   other end of its command channel, so the entire MCP round trip is provable
//!   end to end with no server anywhere.
//!
//! Nothing above this file knows which one it is on. That is `04 §1.1`'s ruling
//! working: MCP is an adapter, the CLI is another, and the contract is
//! underneath both.
//!
//! ## What this struct holds that the plane does not, and why that is allowed
//!
//! `04 §1.3` forbids a skin from holding a lease, a session id mapping the
//! plane does not know about, or a queue of input. This holds three things and
//! none of them is on that list.
//!
//! * **The in flight intent ids.** The plane has its own table and no accessor
//!   for it, and both `dvv watch` and the stop path need to name what is
//!   running. Ours is a mirror of ids we minted, not a second opinion.
//! * **The lease id we were given.** `agent_lease::LeaseId` is a staleness
//!   token that a party quotes back on release, and `LeaseId::from_u64`'s own
//!   doc comment says it is public precisely so a caller can. Holding it is not
//!   holding the lease.
//! * **The geometry generation of the last observation we served.** This is the
//!   one that needs an argument, and `00 R10` is the argument. An actuation
//!   computed against a stale geometry is refused and nothing is delivered,
//!   which requires the agent to carry the generation back. A stateless
//!   protocol gives it nowhere to carry it on turn one, and refusing every
//!   first click would be correct and useless. So the adapter stamps the
//!   generation of the last observation IT SERVED, which is the only generation
//!   the coordinate can have come from, and a resize since then still refuses.
//!   An explicit `generation` from the caller always wins.

use crate::clock;
use crate::error::{codes, ToolError};
use crate::observation::{FrameBlock, Geometry, LeaseBlock, Observation, Screen, Space, SCHEMA};
use crate::watch::{command_name, WatchEvent, WATCH_BUFFER};
use agent_lease::{AcquireRequest, HolderKind, LeaseId, LeaseOutcome, LeaseView, Party, PartyId};
use agent_plane::{
    Attach, AttachedLimb, Damage, Frame, FrameSource, Grant, LimbRegistry, PerceptionUnavailable,
    PlaneConfig, Settlement,
};
use limb_core::availability::SignalReport;
use limb_core::capability::Capability;
use limb_core::fence::GeometryGeneration;
use limb_core::identity::{LimbId, Slot};
use limb_core::intent::{AgentIntent, IntentKind};
use limb_core::limb::Grounding;
use limb_core::observation::Timestamp;
use limb_core::{ProtocolKind, Rect};
use remote_core::state::SessionState;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::broadcast;

/// Take a lock, recovering from poisoning rather than panicking.
///
/// The same trade `agent-plane` records: what is behind these locks is
/// bookkeeping, a set of ids and a counter, and none of it is left in a state a
/// reader cannot make sense of. A panic here would take the stop path down with
/// it, and the stop path is the one that has to work when something has already
/// gone wrong.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// A saved machine, or one discovery found. **Never a secret.**
///
/// There is no `password`, no `passphrase` and no `username` field, and there
/// never will be. D7 says credentials never reach the agent, and the way to
/// enforce that is not a capability check, it is not having a field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostRecord {
    pub host_id: String,
    pub label: String,
    pub address: String,
    pub port: u16,
    pub protocol: String,
    /// Whether a credential is stored for this machine. A boolean, never the
    /// credential: an agent needs to know whether a connection will pause for a
    /// person, and nothing more.
    pub credential_stored: bool,
    /// True for a machine discovery found rather than one somebody saved.
    pub discovered: bool,
}

/// What to open, as `dvv_open`'s schema already refuses to describe it.
///
/// There is no `username`, no `password` and no `domain` here and there never
/// will be (`04 §4.3`). An agent asks for a saved host by id and the shell
/// resolves the secret from the keychain inside `connect_session`, exactly as
/// it does today for a person.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenRequest {
    pub host_id: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    /// Required with `address`. With `host_id` it is read from the saved
    /// machine and this field is refused, because overriding it would dial the
    /// wrong protocol at an endpoint somebody configured for something else.
    pub protocol: Option<ProtocolKind>,
    /// Which concurrent session against that machine. Slot 0 attaches to
    /// whatever is already live, so an agent asking for a host a person already
    /// has open in a pane gets THAT session and the two watch the same thing.
    pub slot: Slot,
    /// Whether to pay for a framebuffer mirror on this limb (`04 §8` OQ-3).
    /// Opt in per session, so an agent asks for what it needs and pays for
    /// that, rather than a group of eight 4K sessions costing 264 MB before
    /// anything is decoded.
    pub perceive: bool,
}

/// Where limbs come from.
///
/// The seam. Everything above it is the same whether a limb is a real RDP
/// session or a recorder in a test, which is the property that makes the MCP
/// round trip provable today.
pub trait SessionSource: Send + Sync {
    /// The saved machines and the discovered ones.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when the library is not reachable.
    fn hosts(&self) -> Result<Vec<HostRecord>, ToolError>;

    /// Everything needed to bring one machine under the plane.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] naming what is missing, never a stub that pretends.
    fn open(&self, request: &OpenRequest) -> Result<Attach, ToolError>;

    /// What lifecycle state this limb is in, as the source last saw it.
    ///
    /// The plane deliberately does not subscribe to `SessionEvent` itself: the
    /// shell owns that stream and a second subscriber would be a second opinion
    /// about what state a limb is in
    /// (`agent_plane::AttachedLimb::note_state` says so). So the source, which
    /// is the thing that has the stream, is asked, and the plane holds a copy
    /// so it can refuse an intent while a limb is negotiating with the retry
    /// time in the refusal rather than putting a click on a reconnecting
    /// socket.
    ///
    /// `None` means the source has nothing new to say and the plane keeps what
    /// it had.
    fn state(&self, limb: &LimbId) -> Option<SessionState> {
        let _ = limb;
        None
    }

    /// One sentence for `dvv doctor`, so a person can tell which source a
    /// running `dvv` is on without reading the code.
    fn describe(&self) -> &'static str;
}

// Named here rather than at the top of the file because they belong to the
// socket client and to nothing else in this module: the machine key is what a
// limb id is derived from, and `ClientCommand` is what the relay encodes.
use limb_core::identity::MachineKey;
use limb_core::ClientCommand;

/// The source that IS the shell, reached over the `dvvp.v1` unix socket.
///
/// ## What changed, and what did not
///
/// This used to refuse every call with a sentence naming the listener that did
/// not exist. The listener exists (`src-tauri/src/agent/`), and opening a
/// machine it does not already have is served now too: [`ShellSource::open`]
/// attaches when there is a live session at the slot and calls `limb.open`
/// when there is not, which asks the application to open the machine the way a
/// person's click does, window and all.
///
/// One refusal is left and it is a refusal rather than an error on purpose: a
/// socket that is not there at all. `04 §4.1`'s habit is that an agent told
/// "not implemented" with the reason stops asking, and an agent told "error"
/// retries.
///
/// ## Why the transport is one blocking socket
///
/// [`SessionSource`] is a synchronous trait: `hosts`, `open` and `state` all
/// return without awaiting. That is not an oversight, it is what lets the same
/// source serve the CLI, the MCP server and a test, and it decides the shape
/// here: one `UnixStream`, one request, one reply, under one lock. There is no
/// second connection, no reader task and no notification path, so there is
/// nothing that can interleave a push into the middle of a reply.
///
/// The cost is that the plane learns a limb's lifecycle by asking rather than
/// by being told, which is exactly what [`SessionSource::state`] is for and
/// what its own doc comment already describes: the shell owns the event
/// stream, and a second subscriber would be a second opinion about what state
/// a limb is in.
///
/// ## Why the connection is a process global
///
/// `ShellSource` is constructed as a unit value in several places, so it is a
/// handle to the one socket this process has rather than the owner of a
/// socket. One connection per process is also what the shell's audit trail
/// wants: one `hello`, one attachment id, one line naming who attached.
pub struct ShellSource;

/// The protocol string, which is a hard gate on both sides (`04 §2.7`).
const DVVP: &str = "dvvp.v1";

/// The control lane's `msg_type` (`04 §2.2`). Nothing in this build sends or
/// expects any other, and anything else that arrives is ignored, which is the
/// rule that lets the plane and this client ship in separate commits.
const MSG_JSONRPC: u8 = 0;

/// The largest reply this client will read, matching the plane's own cap.
const MAX_PAYLOAD: u32 = 8 * 1024 * 1024;

/// The one connection, and what it costs to say it is not there.
struct Link {
    #[cfg(unix)]
    stream: std::os::unix::net::UnixStream,
    next_id: u64,
    /// The attachment id the plane minted for this connection. Held so a
    /// refusal can name it, which is what makes an audit line joinable.
    attachment_id: String,
}

fn link() -> &'static Mutex<Option<Link>> {
    static LINK: std::sync::OnceLock<Mutex<Option<Link>>> = std::sync::OnceLock::new();
    LINK.get_or_init(|| Mutex::new(None))
}

/// The sentence an agent gets when there is no socket at all.
///
/// It names the path, because the first thing a person does is look for the
/// file, and it names both reasons it can be missing, because "the app is not
/// running" and "the plane is switched off" need different fixes.
fn no_socket() -> ToolError {
    ToolError::not_implemented(format!(
        "there is no agent plane socket at {}. Either DeskVNCViewer is not running, or its agent plane is switched off, which is the default: it is a setting in the application and a person has to turn it on. Nothing is saved and nothing is lost by this call failing. Run `dvv doctor` for the path this build expects",
        crate::cli::socket_path()
    ))
}

/// Is there a socket to talk to?
fn socket_present() -> bool {
    std::path::Path::new(&crate::cli::socket_path()).exists()
}

/// One request, one reply, on the one connection.
///
/// Reconnects and says hello when there is no link, and drops the link on any
/// I/O failure so the next call reconnects rather than talking into a socket
/// the application has closed.
#[cfg(unix)]
fn call(method: &str, params: serde_json::Value) -> Result<serde_json::Value, ToolError> {
    let mut guard = lock(link());
    if guard.is_none() {
        *guard = Some(connect()?);
    }
    let outcome = {
        let held = guard.as_mut().expect("just connected");
        request(held, method, params)
    };
    match outcome {
        Ok(value) => Ok(value),
        Err(error) => {
            // A transport failure invalidates the connection, and a
            // REFUSAL does not. Telling them apart here is what keeps a
            // policy refusal from silently costing the attachment its
            // identity, which would look to the shell like an agent that
            // detached and came back.
            if error.code == codes::LIMB_GONE {
                *guard = None;
            }
            Err(error)
        }
    }
}

#[cfg(not(unix))]
fn call(_method: &str, _params: serde_json::Value) -> Result<serde_json::Value, ToolError> {
    Err(ToolError::not_implemented(
        "the dvvp.v1 surface is a unix socket, and 00 R18 ships a unix socket and stdio in version 1 and nothing else. The named pipe 04 §2.1 specifies for Windows, with an ACL granting only the creating user, is not written on either side",
    ))
}

#[cfg(unix)]
fn connect() -> Result<Link, ToolError> {
    use std::io::ErrorKind;

    let path = crate::cli::socket_path();
    let stream = std::os::unix::net::UnixStream::connect(&path).map_err(|e| match e.kind() {
        ErrorKind::NotFound | ErrorKind::ConnectionRefused => no_socket(),
        _ => ToolError::new(
            codes::LIMB_GONE,
            format!("the agent plane socket at {path} could not be reached: {e}"),
        ),
    })?;
    let mut link = Link {
        stream,
        next_id: 0,
        attachment_id: String::new(),
    };
    let hello = request(
        &mut link,
        "hello",
        serde_json::json!({
            "protocol": DVVP,
            "client": { "name": "dvv", "version": crate::DVV_VERSION },
        }),
    )?;
    link.attachment_id = hello
        .get("attachmentId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(link)
}

/// Write one framed request and read the reply that matches its id.
#[cfg(unix)]
fn request(
    link: &mut Link,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, ToolError> {
    use std::io::{Read, Write};

    link.next_id += 1;
    let id = link.next_id;
    let body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": method, "params": params,
    }))
    .map_err(|e| ToolError::bad_request(format!("that request could not be encoded: {e}")))?;

    let mut framed = Vec::with_capacity(8 + body.len());
    framed.push(MSG_JSONRPC);
    // `flags`, then `reserved`, both zero and both ignored on receipt.
    framed.push(0);
    framed.extend_from_slice(&0u16.to_le_bytes());
    framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
    framed.extend_from_slice(&body);
    link.stream.write_all(&framed).map_err(transport)?;
    link.stream.flush().map_err(transport)?;

    loop {
        let mut header = [0u8; 8];
        link.stream.read_exact(&mut header).map_err(transport)?;
        let msg_type = header[0];
        let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if len > MAX_PAYLOAD {
            return Err(transport(std::io::Error::other(format!(
                "the plane sent {len} bytes, which is above this client's cap"
            ))));
        }
        let mut payload = vec![0u8; len as usize];
        link.stream.read_exact(&mut payload).map_err(transport)?;
        // An unknown `msg_type` is ignored rather than refused, which is what
        // lets the plane grow the pixel lane without this client changing.
        if msg_type != MSG_JSONRPC {
            continue;
        }
        let message: serde_json::Value = serde_json::from_slice(&payload).map_err(|e| {
            transport(std::io::Error::other(format!(
                "the plane sent something that is not JSON: {e}"
            )))
        })?;
        // A notification carries no id and is not this call's answer.
        if message.get("id").and_then(serde_json::Value::as_u64) != Some(id) {
            continue;
        }
        if let Some(error) = message.get("error") {
            return Err(from_rpc_error(error));
        }
        return Ok(message
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null));
    }
}

#[cfg(unix)]
fn transport(error: std::io::Error) -> ToolError {
    ToolError::new(
        codes::LIMB_GONE,
        format!(
            "the connection to DeskVNCViewer's agent plane failed: {error}. The next call reconnects; if it keeps failing the application has gone away or its plane was switched off"
        ),
    )
}

/// Map the plane's refusal onto this crate's vocabulary.
///
/// The plane tags its application errors (`LEASE_REVOKED`, `LIMB_GONE`,
/// `NOT_ATTACHED`) beside the sentence, and the tag is what an agent branches
/// on, so it is carried through rather than flattened into one code. `04 §4.4`
/// is why: the model has to get one decision right and only one, and that
/// decision is whether a PERSON took the machine.
#[cfg(unix)]
fn from_rpc_error(error: &serde_json::Value) -> ToolError {
    let message = error
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("the agent plane refused and said nothing")
        .to_string();
    let tag = error
        .get("data")
        .and_then(|d| d.get("code"))
        .and_then(serde_json::Value::as_str);
    let code = match tag {
        Some("LEASE_REVOKED") => codes::LEASE_REVOKED,
        Some("LIMB_GONE") | Some("NOT_ATTACHED") => codes::LIMB_GONE,
        Some("NO_SUCH_MACHINE") => codes::BAD_REQUEST,
        // A JSON-RPC protocol error rather than an application one. `-32601`
        // is an unknown method, which under `04 §2.7` rule 2 is how a client
        // discovers that this plane is older than it is.
        _ => match error.get("code").and_then(serde_json::Value::as_i64) {
            Some(-32601) => codes::NOT_IMPLEMENTED,
            _ => codes::BAD_REQUEST,
        },
    };
    ToolError::new(code, message)
}

/// The limb id to session id map, so [`SessionSource::state`] can name the
/// session the shell knows.
///
/// `04 §1.3` forbids a skin from holding "a session id mapping the plane does
/// not know about". This is not one: both ids are the plane's, the mapping was
/// handed over by the plane in the attach reply, and it is a cache of an
/// answer rather than an opinion.
fn limb_sessions() -> &'static Mutex<BTreeMap<String, String>> {
    static SESSIONS: std::sync::OnceLock<Mutex<BTreeMap<String, String>>> =
        std::sync::OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Which attachment is waiting to be told how a native intent ended, per
/// session.
///
/// `00 R51b`'s last hop on this side. `AttachedLimb::note_served` is what wakes
/// the dispatch that is blocked on an `exec`, and it hangs off the ATTACHMENT
/// rather than off a limb id, deliberately: `agent-plane`'s own answer table
/// says why, which is that a limb id names a machine at a slot and is
/// reproducible on purpose, so two registries in one process would share one.
/// The relay thread that carries the intent over the socket has neither, only
/// a session id, so this is where the two meet.
///
/// `04 §1.3` forbids a skin from holding state the plane does not know about.
/// This is not that: both ends are the plane's own, the mapping was handed over
/// by the plane in the attach reply, and it is a handle rather than an opinion.
#[cfg(unix)]
fn answerable() -> &'static Mutex<BTreeMap<String, AttachedLimb>> {
    static ANSWERABLE: std::sync::OnceLock<Mutex<BTreeMap<String, AttachedLimb>>> =
        std::sync::OnceLock::new();
    ANSWERABLE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Note where a native intent's answer goes for this limb.
///
/// Keyed on the session id, because that is what the relay thread has. A limb
/// the socket did not produce is not in [`limb_sessions`] and registers
/// nothing, which is correct: a fake source answers its own intents and never
/// reaches this path.
#[cfg(unix)]
fn register_answerable(limb: &AttachedLimb) {
    let session = lock(limb_sessions()).get(limb.id().as_str()).cloned();
    if let Some(session) = session {
        lock(answerable()).insert(session, limb.clone());
    }
}

/// Forget it, so a closed limb does not keep an attachment alive.
#[cfg(unix)]
fn forget_answerable(limb_id: &str) {
    let session = lock(limb_sessions()).remove(limb_id);
    if let Some(session) = session {
        lock(answerable()).remove(&session);
    }
}

#[cfg(not(unix))]
fn register_answerable(_limb: &AttachedLimb) {}

#[cfg(not(unix))]
fn forget_answerable(_limb_id: &str) {}

impl SessionSource for ShellSource {
    fn hosts(&self) -> Result<Vec<HostRecord>, ToolError> {
        if !socket_present() {
            return Err(no_socket());
        }
        let answer = call("hosts.list", serde_json::json!({}))?;
        let rows = answer
            .get("hosts")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(rows
            .iter()
            .map(|row| HostRecord {
                host_id: string(row, "hostId"),
                label: string(row, "label"),
                address: string(row, "address"),
                port: row
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as u16,
                protocol: string(row, "protocol"),
                credential_stored: boolean(row, "credentialStored"),
                discovered: boolean(row, "discovered"),
            })
            .collect())
    }

    fn open(&self, request: &OpenRequest) -> Result<Attach, ToolError> {
        if !socket_present() {
            return Err(no_socket());
        }
        let mut params = serde_json::json!({
            "slot": request.slot.0,
            "perceive": request.perceive,
        });
        match (&request.host_id, &request.address) {
            (Some(host_id), _) => params["hostId"] = serde_json::json!(host_id),
            (None, Some(address)) => {
                let protocol = request.protocol.ok_or_else(|| {
                    ToolError::bad_request(
                        "protocol is required with address: a value this build does not know is a hard error and never a fallback, because falling back to VNC would dial the wrong protocol at an endpoint somebody configured for something else",
                    )
                })?;
                params["address"] = serde_json::json!(address);
                params["protocol"] = serde_json::json!(protocol.as_str());
                if let Some(port) = request.port {
                    params["port"] = serde_json::json!(port);
                }
            }
            (None, None) => {
                return Err(ToolError::bad_request(
                    "dvv_open needs a hostId from dvv_hosts, or an address with a protocol",
                ))
            }
        }
        // Attach first, always. Slot 0 adopts whatever is already live
        // (`02 §4.4`), so an agent asking for a machine a person already has in
        // a pane gets THAT session and the two watch the same thing. Opening
        // first would give the person a second window they did not ask for.
        let attached = match call("limb.attach", params.clone()) {
            Ok(attached) => attached,
            // Nothing is open at that slot. `LIMB_GONE` is the plane's tag for
            // it and the only one worth opening on: a refusal for a machine
            // that is not on offer, or for a capability this attachment does
            // not hold, is answered by opening nothing.
            Err(gone) if gone.code == codes::LIMB_GONE => {
                let opened = call("limb.open", params.clone())?;
                // Opening is asynchronous by design: the reply comes back when
                // the session is SPAWNED, which is before it has negotiated and
                // before a person has answered any prompt it stops at. So the
                // attach that follows waits for the session to appear rather
                // than assuming it already has.
                await_session(&opened, &params)?
            }
            Err(other) => return Err(other),
        };
        build_attach(&attached, request.slot)
    }

    fn state(&self, limb: &LimbId) -> Option<SessionState> {
        let session_id = lock(limb_sessions()).get(limb.as_str()).cloned()?;
        let answer = call(
            "limb.status",
            serde_json::json!({ "sessionId": session_id }),
        )
        .ok()?;
        serde_json::from_value(answer.get("state")?.clone()).ok()
    }

    fn describe(&self) -> &'static str {
        if socket_present() {
            "the shell, over the dvvp.v1 unix socket, driving the sessions DeskVNCViewer already has open"
        } else {
            "the shell, over the dvvp.v1 unix socket (no socket at that path: DeskVNCViewer is not running, or its agent plane is switched off, which is the default)"
        }
    }
}

/// How long this client waits for a machine it asked the shell to open to turn
/// into a session it can attach to.
///
/// Not for it to connect. `limb.open` returns when the session is spawned, and
/// the attach below only needs the shell's registry to have the entry, which is
/// the hop between the window opening and its webview calling `connect_session`.
/// A machine still negotiating attaches fine and every intent against it is
/// refused with `NOT_READY` until the state says otherwise, which is the right
/// way round.
#[cfg(unix)]
const ATTACH_AFTER_OPEN: std::time::Duration = std::time::Duration::from_secs(20);

/// Attach to the session `limb.open` just spawned, once it exists.
///
/// Polled rather than pushed, because that is the shape [`SessionSource`] is:
/// one blocking socket, request and reply, with no reader task a notification
/// could arrive on. The poll is cheap (`limb.attach` against a machine with
/// nothing live is one registry scan) and it is BOUNDED, because a machine
/// that stopped to ask a person for a password could otherwise hold this
/// thread until they came back from lunch.
///
/// # Errors
///
/// A [`ToolError`] naming the session that was opened, so an agent that gave up
/// here can still find it with `dvv_limbs` rather than opening a second one.
#[cfg(unix)]
fn await_session(
    opened: &serde_json::Value,
    params: &serde_json::Value,
) -> Result<serde_json::Value, ToolError> {
    let session_id = string(opened, "sessionId");
    let deadline = std::time::Instant::now() + ATTACH_AFTER_OPEN;
    let mut last = None;
    while std::time::Instant::now() < deadline {
        match call("limb.attach", params.clone()) {
            Ok(attached) => return Ok(attached),
            Err(gone) if gone.code == codes::LIMB_GONE => last = Some(gone),
            Err(other) => return Err(other),
        }
        // A tenth of a second. Short enough that a machine on a LAN is
        // attached about as fast as a person's own window mounts, long enough
        // that this is not a spin on the shell's session lock.
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(ToolError::new(
        codes::LIMB_GONE,
        format!(
            "DeskVNCViewer opened {session_id} and it had not registered a live session after {} seconds. It may be waiting for the PERSON to answer a credential or a host key prompt, which is the one thing an agent cannot answer (D7). The window is open: ask the user to look at it, then call dvv_limbs rather than opening the machine again. The last refusal was: {}",
            ATTACH_AFTER_OPEN.as_secs(),
            last.map(|e| e.message).unwrap_or_default(),
        ),
    ))
}

#[cfg(not(unix))]
fn await_session(
    _opened: &serde_json::Value,
    _params: &serde_json::Value,
) -> Result<serde_json::Value, ToolError> {
    Err(ToolError::not_implemented(
        "00 R18 ships a unix socket and stdio in version 1, and this platform has neither wired",
    ))
}

fn string(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn boolean(value: &serde_json::Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Turn the plane's attach reply into everything `agent-plane` needs.
///
/// The one interesting part is the command channel. [`Attach`] wants a live
/// `SessionHandle`, which is an `mpsc::Sender<ClientCommand>`, and the real
/// receiver is inside the application. So this end mints a channel and hands
/// the receiver to a thread that relays every command over the socket. The
/// plane above it sends into an ordinary channel and knows nothing about a
/// socket, which is `04 §1.1`'s ruling holding: the lowering, the lease and
/// the fencing are all unchanged by where the session actually lives.
#[cfg(unix)]
fn build_attach(attached: &serde_json::Value, slot: Slot) -> Result<Attach, ToolError> {
    let session_id = string(attached, "sessionId");
    let protocol = ProtocolKind::parse(&string(attached, "protocol")).ok_or_else(|| {
        ToolError::new(
            codes::WRONG_PROTOCOL,
            format!(
                "the plane reported {session_id} as protocol `{}`, which this build of dvv does not know. It is refused rather than guessed at: driving a machine with the wrong vocabulary is the failure this whole design is built to avoid",
                string(attached, "protocol")
            ),
        )
    })?;
    let machine = machine_from(attached.get("machine"))?;
    let host = match &machine {
        MachineKey::Endpoint { address, .. } => address.clone(),
        MachineKey::Profile(_) => string(attached, "address"),
    };
    let size = attached
        .get("size")
        .and_then(|s| {
            Some((
                s.get("width")?.as_u64()? as u16,
                s.get("height")?.as_u64()? as u16,
            ))
        })
        .unwrap_or((0, 0));

    let limb_id = LimbRegistry::resolve(protocol, &machine, slot);
    lock(limb_sessions()).insert(limb_id.to_string(), session_id.clone());

    // The mirror, if the shell attached one. `perception.mirror` is the
    // shell's claim that a framebuffer mirror EXISTS for this session, which
    // is a different claim from `perception.frames`, the claim that it has
    // been painted and can be read right now. This is the first: an
    // observatory over a priming mirror is correct, and every read of it
    // refuses with PRIMING until the refresh lands (`03 §9 A3`).
    let frames = attached
        .get("perception")
        .and_then(|p| p.get("mirror"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    // 256, matching VNC's own intent channel. The plane reserves half of
    // whatever it is handed for the webview's input path, and a smaller number
    // here would make the plane shed for reasons that are this file's fault.
    let (commands, receiver) = tokio::sync::mpsc::channel(256);
    relay(session_id.clone(), receiver);
    // The agent holds this limb from the shell's point of view the moment it
    // attaches, and a pane has to say so, visibly, always (`08 §5.5`). Sent
    // once here rather than per command, because a report per pointer event
    // would be a notification storm in a webview.
    let _ = call(
        "control.report",
        serde_json::json!({
            "sessionId": session_id,
            "held": true,
            "phase": "held",
            "holderKind": "agent",
            "holderLabel": "dvv",
            "humanTookOver": false,
            "inflight": Vec::<String>::new(),
        }),
    );

    Ok(Attach {
        driver: Arc::new(RemoteLimb::new(protocol, frames)),
        machine,
        slot,
        host,
        handle: remote_core::driver::SessionHandle {
            id: limb_id.to_string(),
            kind: protocol,
            commands,
            // Cancelling this token cancels nothing: the session lives in the
            // application and closing it is `limb.detach`'s job, not a
            // token's. A token that looked like a shutdown and was not would
            // be worse than one that is visibly inert.
            cancel: Default::default(),
        },
        size,
        // The mirror lives in the SHELL, not here, and this is a handle to it.
        //
        // `04 §2.2` gives pixels their own binary lanes and neither side
        // carries one, and that is the right answer rather than a gap:
        // [`SessionSource`] is synchronous request and reply over one blocking
        // socket, so there is no reader task a push could arrive on. A frame
        // is therefore the ANSWER to a call, and `ShellFrames` is that call.
        // `00 R6` is answered on the far side, before a mirror is allocated:
        // see `src-tauri/src/agent/mirror.rs`.
        frames: frames.then(|| {
            Arc::new(ShellFrames {
                session_id: session_id.clone(),
            }) as Arc<dyn FrameSource>
        }),
    })
}

/// The shell's mirror, reached over the same one socket everything else uses.
///
/// It holds a session id and nothing else. There is no cached frame, no
/// generation of its own and no damage queue here, and the absences are the
/// design: `04 §1.3` forbids a skin from holding a second opinion about the
/// plane's state, and a cached screenshot is exactly that. Every call goes to
/// the shell, which owns the mirror, the coverage and the geometry counter.
#[cfg(unix)]
struct ShellFrames {
    session_id: String,
}

#[cfg(unix)]
impl FrameSource for ShellFrames {
    fn frame(
        &self,
        region: Option<Rect>,
        scale: Option<f32>,
        _at: Timestamp,
    ) -> Result<Frame, PerceptionUnavailable> {
        let mut params = serde_json::json!({ "sessionId": self.session_id });
        match (region, scale) {
            // Rung 3 is a rectangle at native resolution, scale 1.0, with no
            // rounding to argue about. A caller asking for a scaled region is
            // refused rather than served one: `00 R43` (WA-11) says never send
            // an image the provider will resize, and a region we scaled
            // ourselves and a region a provider scaled are indistinguishable
            // once the factor is lost.
            (Some(_), Some(s)) if (s - 1.0).abs() > f32::EPSILON => {
                return Err(PerceptionUnavailable(format!(
                    "a region read is native resolution and this one asked for scale {s}; ask for the region at 1.0 and downscale nothing, or ask for the whole frame at a long edge"
                )))
            }
            (Some(rect), _) => {
                params["kind"] = serde_json::json!("region");
                params["rect"] = serde_json::json!({
                    "x": rect.x, "y": rect.y, "width": rect.width, "height": rect.height,
                });
            }
            (None, scale) => {
                params["kind"] = serde_json::json!("frame");
                if let Some(s) = scale {
                    // Relative to the framebuffer, which the shell knows and
                    // this side would have to keep a second copy of. Sent as
                    // a fraction of the long edge so the shell does the
                    // arithmetic against the size it is authoritative for.
                    params["scale"] = serde_json::json!(s);
                }
            }
        }
        let answer = call("screen.read", params).map_err(|e| PerceptionUnavailable(e.message))?;

        // "Nothing changed" is an answer and not a failure, and it has to stay
        // one through this layer: an agent that receives an error for it will
        // retry immediately rather than wait.
        if answer
            .get("unchanged")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(Frame {
                bytes: crate::into_bytes(Vec::new()),
                covers: Rect::new(0, 0, 0, 0),
                generation: generation_of(answer.get("geometryGeneration")),
                complete: true,
            });
        }

        let observation = answer.get("observation").ok_or_else(|| {
            PerceptionUnavailable(
                "the plane answered screen.read with neither an observation nor `unchanged`, which is a plane older than this client".to_string(),
            )
        })?;
        // The WHOLE observation travels, base64 image included, because
        // `03 §9 A8` requires `space`, `scale`, `screens`, `primary_known`,
        // the geometry generation and `coverage` on every response at every
        // rung, and a response missing one is a bug rather than a compact
        // form. `00 R43` is the sharp half: the scale factor rides inside
        // `image.space` beside the pixels it belongs to, because a scale that
        // can be separated from its image will be.
        let described = serde_json::to_vec(observation)
            .map_err(|e| PerceptionUnavailable(format!("the frame could not be described: {e}")))?;
        let covers = observation
            .get("image")
            .and_then(|i| i.get("space"))
            .and_then(|s| s.get("region"))
            .map(rect_of)
            .unwrap_or_else(|| Rect::new(0, 0, 0, 0));
        Ok(Frame {
            bytes: crate::into_bytes(described),
            covers,
            generation: generation_of(observation.get("geometry_generation")),
            // `00 R6`. A partial frame names every rectangle it cannot vouch
            // for, and this is the boolean the plane above reads to know that.
            complete: observation
                .get("coverage")
                .and_then(serde_json::Value::as_str)
                == Some("complete"),
        })
    }

    fn damage(&self) -> Option<Damage> {
        let answer = call(
            "screen.damage",
            serde_json::json!({ "sessionId": self.session_id }),
        )
        .ok()?;
        // `00 R39b`. THE list, in the order the server sent them. The bounding
        // box comes beside it rather than instead of it: sizing a read from
        // the box would re-read a whole 4K frame to find two moved pixels.
        let rects: Vec<Rect> = answer
            .get("rects")
            .and_then(serde_json::Value::as_array)?
            .iter()
            .map(rect_of)
            .collect();
        if rects.is_empty() {
            // Not "the screen is still". A server whose damage tracking cannot
            // be trusted sends nothing either, which is why
            // `ClientCommand::SetAlwaysRefresh` exists.
            return None;
        }
        let bounds = answer.get("bounds").map(rect_of)?;
        Some(Damage {
            coverage: coverage_of(&rects, bounds),
            rects,
            bounds,
            generation: generation_of(answer.get("geometryGeneration")),
        })
    }
}

/// The share of the damage bounding box the rectangles actually touch.
///
/// Summed rather than unioned, because two rects in opposite corners union to
/// the whole screen and would report a coverage of one for four moved pixels.
/// Overlapping rects are double counted and the result is clamped, which
/// overstates rather than understates: a reader deciding whether a partial
/// read is worth it should be given the pessimistic number.
#[cfg(unix)]
fn coverage_of(rects: &[Rect], bounds: Rect) -> f32 {
    let touched: u64 = rects
        .iter()
        .map(|r| u64::from(r.width) * u64::from(r.height))
        .sum();
    let area = u64::from(bounds.width) * u64::from(bounds.height);
    if touched == 0 || area == 0 {
        return 0.0;
    }
    (touched as f32 / area as f32).min(1.0)
}

#[cfg(unix)]
fn rect_of(value: &serde_json::Value) -> Rect {
    let field = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            .min(u64::from(u16::MAX)) as u16
    };
    Rect::new(field("x"), field("y"), field("width"), field("height"))
}

/// How far this client will count to reach a generation the shell named.
///
/// A session that has resized a million times is not a real situation, and the
/// cap is what stops a plane that answered with four billion from making this
/// process count to it. Anything above it is clamped, which turns an absurd
/// generation into a stale one: every value above the plane's current
/// generation is equally not current, and the comparison is for equality.
#[cfg(unix)]
const MAX_GENERATION: u64 = 1_000_000;

/// A geometry generation the shell sent.
///
/// `GeometryGeneration` has no constructor from a `u32`, deliberately: the
/// counter is minted by the fence that owns it, and a public constructor would
/// let a client invent one. Stepping up from `FIRST` is the only honest way to
/// name a value that arrived over a wire.
#[cfg(unix)]
fn generation_of(value: Option<&serde_json::Value>) -> GeometryGeneration {
    let want = value
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1)
        .min(MAX_GENERATION) as u32;
    let mut generation = GeometryGeneration::FIRST;
    while generation.get() < want {
        let next = generation.next();
        if next == generation {
            break;
        }
        generation = next;
    }
    generation
}

#[cfg(not(unix))]
fn build_attach(_attached: &serde_json::Value, _slot: Slot) -> Result<Attach, ToolError> {
    Err(ToolError::not_implemented(
        "00 R18 ships a unix socket and stdio in version 1, and this platform has neither wired",
    ))
}

/// Rebuild the machine key the shell computed.
fn machine_from(value: Option<&serde_json::Value>) -> Result<MachineKey, ToolError> {
    let value = value.ok_or_else(|| {
        ToolError::new(
            codes::BAD_REQUEST,
            "the plane's attach reply carried no machine key, so there is no identity to derive a limb id from. That is a plane older than this client, and 04 §2.7's answer is that the missing feature does not exist rather than that something is broken",
        )
    })?;
    match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("profile") => Ok(MachineKey::profile(string(value, "id"))),
        Some("endpoint") => {
            let protocol = ProtocolKind::parse(&string(value, "protocol")).ok_or_else(|| {
                ToolError::new(
                    codes::WRONG_PROTOCOL,
                    "the plane named a protocol this build does not know",
                )
            })?;
            Ok(MachineKey::endpoint(
                protocol,
                // ALREADY normalised, by the shell, which is the side that
                // owns `vnc_store::normalize_address`. Applying a second,
                // private copy of that rule here is exactly how the plane's
                // idea of "the same machine" and the window de-duplication's
                // idea of it would drift apart.
                string(value, "address"),
                value
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as u16,
            ))
        }
        other => Err(ToolError::new(
            codes::BAD_REQUEST,
            format!(
                "the plane named a machine key of kind {other:?}, which this build cannot rebuild"
            ),
        )),
    }
}

/// Drain one limb's command channel onto the socket, for the life of the limb.
///
/// A plain OS thread and `blocking_recv`, not a tokio task, and the reason is
/// the trait: [`SessionSource::open`] is synchronous and may be called with no
/// runtime in scope, so a `tokio::spawn` here would panic in exactly the
/// configuration a test uses. The thread ends when the plane drops the sender,
/// which is what `Plane::close` does.
#[cfg(unix)]
fn relay(session_id: String, mut receiver: tokio::sync::mpsc::Receiver<ClientCommand>) {
    std::thread::spawn(move || {
        // The last intent name reported, so a drag of two hundred pointer
        // events is one line in a pane and not two hundred. `00 R24` is about
        // never dropping something silently, and this drops nothing: what is
        // coalesced is the NOTICE, and the commands themselves all go.
        let mut reported: Option<&'static str> = None;
        while let Some(command) = receiver.blocking_recv() {
            // `00 R28`. An intent the driver serves natively is the one thing
            // on this channel with somebody blocked on the far end of it, so it
            // takes a method of its own and its ANSWER is the reply. Handled
            // before `encode_command` rather than inside it, because that
            // function's contract is one command onto a wire and this is a
            // request that waits.
            if let ClientCommand::Agent(intent) = command {
                serve_intent(&session_id, &intent);
                continue;
            }
            let name = command_kind(&command);
            let encoded = match encode_command(&command) {
                Some(encoded) => encoded,
                None => {
                    // Refused rather than dropped. A command this surface does
                    // not carry has to reach somebody as a sentence, because a
                    // command that ends silently makes an agent wait instead
                    // of retrying (`00 R7`).
                    tracing::warn!(
                        session = %session_id,
                        "dvvp.v1 does not carry {name}, so it was not sent"
                    );
                    continue;
                }
            };
            if reported != Some(name) {
                reported = Some(name);
                let _ = call(
                    "control.report",
                    serde_json::json!({
                        "sessionId": session_id,
                        "held": true,
                        "phase": "held",
                        "holderKind": "agent",
                        "holderLabel": "dvv",
                        "humanTookOver": false,
                        "inflight": [name],
                    }),
                );
            }
            if let Err(error) = call(
                "limb.command",
                serde_json::json!({ "sessionId": session_id, "command": encoded }),
            ) {
                tracing::warn!(session = %session_id, "{name} was refused: {}", error.message);
                if error.code == codes::LEASE_REVOKED || error.code == codes::LIMB_GONE {
                    // Nothing further of this attachment's will be accepted,
                    // so the thread stops rather than spinning a refusal per
                    // command for the rest of the session.
                    return;
                }
            }
        }
    });
}

/// Carry one native intent over the socket, and hand the answer back to the
/// dispatch that is blocked on it.
///
/// `00 R51b` closing on this side. The shell's `limb.exec` is synchronous:
/// it puts the intent on the session's wire, waits for the driver's
/// `AgentServed` or `AgentRefused`, and answers with it. So this thread blocks
/// for as long as the command runs, which is what the relay thread is for.
///
/// **Every path ends in an answer.** A refusal, a decode failure and a socket
/// failure all reach `note_refused`, because the alternative is a dispatch that
/// waits out its whole deadline for an answer that already exists, which is
/// exactly the failure `00 R28` is about.
#[cfg(unix)]
fn serve_intent(session_id: &str, intent: &limb_core::intent::AgentIntent) {
    let Some(limb) = lock(answerable()).get(session_id).cloned() else {
        // Nothing to answer to. The plane registers the attachment before any
        // intent can be submitted against it, so this is unreachable rather
        // than a case; it is logged rather than ignored because if it ever
        // happens it is an intent that will time out for a reason nobody wrote
        // down.
        tracing::warn!(
            session = %session_id,
            "an intent reached the relay for a session no attachment is registered against"
        );
        return;
    };
    let Some(params) = exec_params(session_id, intent) else {
        limb.note_refused(intent.refuse(format!(
            "dvvp.v1 carries `exec` natively and nothing else: {} is refused here rather than sent, because an intent that arrives somewhere nothing answers it makes an agent wait instead of retrying (00 R7)",
            intent.kind.name()
        )));
        return;
    };
    match call("limb.exec", params) {
        Ok(answer) => match run_from(&answer) {
            Ok(run) => {
                limb.note_served(intent.serve(remote_core::intent::ServedAnswer::Ran(run)));
            }
            // The far side answered something this build cannot describe,
            // which is a plane newer than this client (`04 §2.7`). Its own
            // words go in the refusal rather than being replaced by ours, so
            // whatever it did say still reaches the agent.
            Err(why) => {
                limb.note_refused(intent.refuse(format!(
                    "DeskVNCViewer answered that command in a shape this build of dvv cannot read, so nothing is reported rather than a guessed exit status (05 §3): {why}"
                )));
            }
        },
        Err(refused) => {
            limb.note_refused(intent.refuse(refused.message));
        }
    }
}

/// One `exec` intent, as `limb.exec`'s parameters.
///
/// `None` for every other intent, and the caller turns that into a refusal.
/// There is no arm here for `pty_run` or `declare`: `ssh-core` refuses both
/// with reasons of its own, and a second, weaker copy of that refusal here
/// would be a place for the two to disagree.
#[cfg(unix)]
fn exec_params(
    session_id: &str,
    intent: &limb_core::intent::AgentIntent,
) -> Option<serde_json::Value> {
    use base64::Engine as _;
    let limb_core::intent::IntentKind::Exec { spec } = &intent.kind else {
        return None;
    };
    let mut params = serde_json::json!({
        "sessionId": session_id,
        "command": spec.command,
        // Milliseconds, and required on the far side too. `05 §4.1` gives this
        // no default anywhere it appears, and the reason travels with it: a
        // command with no timeout on a machine an agent cannot see is a hang
        // nobody notices.
        "timeoutMs": spec.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
        "env": spec.env.iter().map(|(k, v)| serde_json::json!([k, v])).collect::<Vec<_>>(),
    });
    if let Some(cwd) = &spec.cwd {
        params["cwd"] = serde_json::json!(cwd);
    }
    if let Some(cap) = spec.max_output_bytes {
        params["maxOutputBytes"] = serde_json::json!(cap);
    }
    if let Some(stdin) = &spec.stdin {
        params["stdinBase64"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(stdin));
    }
    Some(params)
}

/// The shell's answer to a `limb.exec`, as [`remote_core::intent::CommandRun`].
///
/// **Nothing here invents a status** (`00 R7`, `05 §3`). An absent code stays
/// absent, a signal is never coerced into `128 + signum`, and a tier name this
/// build does not know is an error rather than the nearest tier: `exec` is the
/// far side's own `exit-status` off the wire and a sentinel is a number scraped
/// from a prompt, and a caller told the second was the first would trust a
/// number it should have questioned.
///
/// # Errors
///
/// A sentence naming what could not be read, which the caller turns into a
/// refusal carrying it.
#[cfg(unix)]
fn run_from(answer: &serde_json::Value) -> Result<remote_core::intent::CommandRun, String> {
    use base64::Engine as _;
    use remote_core::intent::{CommandExit, CommandRun, Dropped, ExitTier, Truncation, Unanswered};

    let status = answer
        .get("status")
        .ok_or("the answer carried no `status`, and an exit status is one of the five things 05 §4.1 requires of one")?;
    let source = match status.get("source").and_then(serde_json::Value::as_str) {
        Some("exec") => ExitTier::Exec,
        Some("osc133") => ExitTier::Osc133,
        Some("sentinel") => ExitTier::Sentinel,
        Some("helper") => ExitTier::Helper,
        other => {
            return Err(format!(
                "`status.source` was {other:?}, which is a provenance this build does not know. It is refused rather than mapped onto the nearest tier, because the tiers are not equivalent"
            ))
        }
    };
    let unanswered = match status.get("unanswered").and_then(serde_json::Value::as_str) {
        None => None,
        Some("deadline") => Some(Unanswered::Deadline),
        Some("link-lost") => Some(Unanswered::LinkLost),
        Some("tier") => Some(Unanswered::Tier),
        Some(other) => {
            return Err(format!(
                "`status.unanswered` was {other:?}, which is a reason this build does not know"
            ))
        }
    };
    let code = match status.get("code") {
        Some(serde_json::Value::Null) | None => None,
        Some(value) => Some(
            value
                .as_i64()
                .and_then(|c| i32::try_from(c).ok())
                .ok_or("`status.code` is not an exit code")?,
        ),
    };
    let signal = status
        .get("signal")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    // `crate::into_bytes` rather than a `bytes` dependency line, which is the
    // trick that function exists for and explains: this crate's manifest is
    // deliberately small and the type is inferred off the field it lands in.
    let decode = |field: &str| -> Result<_, String> {
        let text = answer
            .get(field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map(crate::into_bytes)
            .map_err(|e| format!("`{field}` is not base64: {e}"))
    };
    let dropped = answer.get("dropped");
    let stream = |field: &str| -> Dropped {
        let value = dropped.and_then(|d| d.get(field));
        Dropped {
            bytes: value
                .and_then(|v| v.get("bytes"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            lines: value
                .and_then(|v| v.get("lines"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        }
    };
    Ok(CommandRun {
        status: CommandExit {
            code,
            signal,
            source,
            unanswered,
        },
        stdout: decode("stdoutBase64")?,
        stderr: decode("stderrBase64")?,
        dropped: Truncation {
            cap: dropped
                .and_then(|d| d.get("cap"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            stdout: stream("stdout"),
            stderr: stream("stderr"),
        },
        duration: std::time::Duration::from_millis(
            answer
                .get("durationMs")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        ),
    })
}

/// How long the plane should wait for a driver's answer to this intent.
///
/// `None` for everything the plane lowers, where the plane's own default is
/// the right number and this crate has no better one. `Some` for the two that
/// carry a command, because their answer cannot arrive before the command has
/// finished and the command's own timeout is a number the CALLER chose.
///
/// The slack covers the socket round trip and the driver's wind down. It is
/// deliberately larger than the shell's own slack on the same command, so that
/// the shell's timeout report is what reaches the agent rather than this side
/// giving up first and reporting a timeout of its own for the same wait.
fn answer_window(kind: &IntentKind) -> Option<std::time::Duration> {
    match kind {
        IntentKind::Exec { spec } | IntentKind::PtyRun { spec } => Some(
            spec.timeout
                .saturating_add(std::time::Duration::from_secs(10)),
        ),
        _ => None,
    }
}

/// One [`ClientCommand`], as the wire spells it.
///
/// An exhaustive match with NO wildcard, deliberately. `ClientCommand` does
/// not derive `Serialize` precisely so that a new variant is a compile error
/// where somebody has to decide what happens to it
/// (`crates/remote-core/src/commands.rs`), and putting a `_ =>` here would
/// throw that away at the one boundary where it matters most.
///
/// `None` means "this surface does not carry that", which the caller reports
/// rather than swallows.
#[cfg(unix)]
fn encode_command(command: &ClientCommand) -> Option<serde_json::Value> {
    use serde_json::json;
    Some(match command {
        ClientCommand::Pointer { x, y, button_mask } => {
            json!({ "kind": "pointer", "x": x, "y": y, "buttonMask": button_mask })
        }
        ClientCommand::Key {
            keysym,
            keycode,
            down,
        } => json!({ "kind": "key", "keysym": keysym, "keycode": keycode, "down": down }),
        ClientCommand::ReleaseAllKeys => json!({ "kind": "release-all-keys" }),
        ClientCommand::ClipboardText(text) => json!({ "kind": "clipboard-text", "text": text }),
        ClientCommand::ClipboardRequest { formats } => {
            json!({ "kind": "clipboard-request", "formats": formats })
        }
        ClientCommand::SetQuality(preset) => {
            json!({ "kind": "set-quality", "preset": quality_name(*preset) })
        }
        ClientCommand::RequestResize { width, height } => {
            json!({ "kind": "request-resize", "width": width, "height": height })
        }
        ClientCommand::Refresh => json!({ "kind": "refresh" }),
        ClientCommand::SetAlwaysRefresh(on) => json!({ "kind": "set-always-refresh", "on": on }),
        ClientCommand::SetViewOnly(on) => json!({ "kind": "set-view-only", "on": on }),
        ClientCommand::SetPreferScancodes(on) => {
            json!({ "kind": "set-prefer-scancodes", "on": on })
        }
        ClientCommand::TerminalInput(bytes) => {
            json!({ "kind": "terminal-input", "bytes": bytes.to_vec() })
        }
        ClientCommand::ResizeTerminal { cols, rows } => {
            json!({ "kind": "resize-terminal", "cols": cols, "rows": rows })
        }
        // The three a person owns and an agent must never send (D7), plus the
        // two that are the shell's own lifecycle rather than an intent. None
        // of them is reachable from the lowering, and none of them gets an arm
        // that could later be filled in by accident.
        ClientCommand::ProvideCredentials { .. }
        | ClientCommand::CancelCredentials
        | ClientCommand::TrustCertificate { .. }
        | ClientCommand::ReconnectNow
        | ClientCommand::Disconnect => return None,
        // `00 R28`: an agent intent the driver serves natively. It does not go
        // on `limb.command` at all, because that method answers "delivered"
        // and an intent's answer is the whole point of sending it. [`relay`]
        // takes this variant before it reaches here and calls
        // [`serve_intent`], so this arm is unreachable and is written anyway,
        // because the day somebody encodes a command from somewhere else this
        // is the arm that stops an intent going out with nothing listening.
        ClientCommand::Agent(_) => return None,
    })
}

#[cfg(unix)]
fn quality_name(preset: remote_core::options::QualityPreset) -> &'static str {
    use remote_core::options::QualityPreset;
    match preset {
        QualityPreset::Auto => "auto",
        QualityPreset::High => "high",
        QualityPreset::Medium => "medium",
        QualityPreset::Low => "low",
        QualityPreset::BlackAndWhite => "bw",
    }
}

/// One word for a command, for a log line and for the in flight notice.
#[cfg(unix)]
fn command_kind(command: &ClientCommand) -> &'static str {
    match command {
        ClientCommand::Pointer { .. } => "pointer",
        ClientCommand::Key { .. } => "key",
        ClientCommand::ReleaseAllKeys => "release-all-keys",
        ClientCommand::ClipboardText(_) => "clipboard-text",
        ClientCommand::ClipboardRequest { .. } => "clipboard-request",
        ClientCommand::TerminalInput(_) => "terminal-input",
        ClientCommand::ResizeTerminal { .. } => "resize-terminal",
        _ => "settings",
    }
}

/// A limb the application owns, described from this side of the socket.
///
/// Everything on [`limb_core::limb::Limb`]'s card is `&'static str`, which is
/// the right shape for a limb author and the wrong shape for a description
/// that arrived over a wire. So the card is chosen by protocol here rather
/// than carried on the socket, and the socket carries only what genuinely
/// varies per session: the state, the size and the machine.
struct RemoteLimb {
    kind: ProtocolKind,
    grounding: Grounding,
    /// Whether the shell attached a framebuffer mirror to this session.
    ///
    /// Carried on the limb rather than only on the observatory because the
    /// CARD has to agree with it: a card that offers `capture` on a limb with
    /// no mirror is a card promising a screenshot every call refuses, and an
    /// agent reads the card before it reads a refusal.
    has_mirror: bool,
}

impl RemoteLimb {
    fn new(kind: ProtocolKind, has_mirror: bool) -> RemoteLimb {
        RemoteLimb {
            kind,
            grounding: match kind {
                ProtocolKind::Ssh => Grounding::Cells,
                _ => Grounding::Pixels,
            },
            has_mirror,
        }
    }
}

impl remote_core::driver::ProtocolDriver for RemoteLimb {
    fn kind(&self) -> ProtocolKind {
        self.kind
    }

    /// Nothing here spawns a session, and that is the honest answer rather
    /// than a gap: the session already exists, inside the application, and
    /// this limb is a handle to it. Implemented rather than left as a panic
    /// because `Limb` is a supertrait of `ProtocolDriver` and a panic in a
    /// required method is a landmine for the first caller who reaches it.
    fn spawn(
        &self,
        _id: String,
        _options: remote_core::options::ConnectOptions,
        _events: tokio::sync::mpsc::Sender<remote_core::events::SessionEvent>,
    ) -> Result<remote_core::driver::SessionHandle, remote_core::driver::OptionsMismatch> {
        Err(remote_core::driver::OptionsMismatch {
            expected: self.kind,
            actual: self.kind,
        })
    }
}

impl limb_core::limb::Limb for RemoteLimb {
    fn describe(&self) -> limb_core::limb::LimbDescription {
        use limb_core::limb::{LimbDescription, Preference};
        match self.grounding {
            Grounding::Cells => LimbDescription {
                what: "A login shell on a PTY, on a machine DeskVNCViewer has open.",
                coordinates: "Character cells, columns and rows.",
                settling: "Settled means no output for the quiet window, which is exact about the wire and silent about whether the far side is thinking.",
                preference: Preference::Preferred,
                preference_reason: "Text is the one modality where an agent is not guessing.",
                steer_away: None,
            },
            _ if self.has_mirror => LimbDescription {
                what: "A remote desktop, on a machine DeskVNCViewer has open.",
                coordinates: "Framebuffer pixels, one space for the whole desktop, origin top left.",
                settling: "Settled means the server has reported no damage for the quiet window, which is exact about what the server said and silent about whether the far side is still working.",
                preference: Preference::Fallback,
                preference_reason: "Pixels cost more than text and say less: read a machine over SSH where it answers there, and act here.",
                steer_away: Some(
                    "If this machine also answers over SSH, read there and act here. Reading changed regions is far cheaper than a full frame: ask for a screen read with no region after an action, not a whole desktop.",
                ),
            },
            _ => LimbDescription {
                what: "A remote desktop, on a machine DeskVNCViewer has open.",
                coordinates: "Framebuffer pixels, one space for the whole desktop, origin top left.",
                settling: "Settled cannot be answered on this limb: it was opened without a framebuffer mirror, so there is no damage here to wait on.",
                preference: Preference::Fallback,
                preference_reason: "Pixels cost more than text and say less, and on this limb they were not paid for.",
                steer_away: Some(
                    "This limb was opened without perception, so it can be typed at and clicked and not looked at. Open it again with perceive set, or read the machine over SSH if it answers there.",
                ),
            },
        }
    }

    /// What this limb can EVER offer, before the grant is intersected with it.
    ///
    /// `Capture` appears only on a limb the shell actually attached a mirror
    /// to, and its absence everywhere else is the design: a card that offered
    /// it with no mirror behind it would be a card promising a screenshot that
    /// every call refuses.
    ///
    /// `Exec` appears on a TERMINAL limb and nowhere else, for the same reason
    /// read the other way. `ssh-core` opens a second channel per RFC 4254 §6.5
    /// and reads the far side's own `exit-status` per §6.10, so a shell limb
    /// can genuinely offer it; nothing behind a framebuffer can, and offering
    /// it there would be a card promising a command that every call refuses.
    /// Being on the card is not being granted it: `exec` is in no role bundle
    /// (`00 R19`), so it is still only reachable by a grant naming the string.
    fn capabilities(&self) -> &'static [Capability] {
        match self.grounding {
            Grounding::Cells => &[
                Capability::View,
                Capability::Control,
                Capability::Close,
                Capability::HostsRead,
                Capability::TerminalRead,
                Capability::TerminalWrite,
                Capability::Exec,
            ],
            _ if self.has_mirror => &[
                Capability::View,
                Capability::Capture,
                Capability::Control,
                Capability::Close,
                Capability::HostsRead,
                Capability::ClipboardRead,
                Capability::ClipboardWrite,
            ],
            _ => &[
                Capability::View,
                Capability::Control,
                Capability::Close,
                Capability::HostsRead,
                Capability::ClipboardRead,
                Capability::ClipboardWrite,
            ],
        }
    }

    fn supports(&self, intent: limb_core::intent::IntentName) -> limb_core::limb::Support {
        use limb_core::intent::IntentName::*;
        use limb_core::limb::Support;
        match intent {
            Type | Press | Tune => Support::Lowered,
            ClipboardGet | ClipboardSet => match self.grounding {
                Grounding::Cells => Support::Unsupported {
                    because: "a PTY has no clipboard of its own; paste into it with send bytes instead",
                },
                _ => Support::Lowered,
            },
            SendBytes => match self.grounding {
                Grounding::Cells => Support::Lowered,
                _ => Support::Unsupported {
                    because: "raw bytes are a terminal's input; on a desktop use type, which becomes key events the server's own keymap reads",
                },
            },
            Move | Click | Drag | Scroll => match self.grounding {
                Grounding::Pixels => Support::Lowered,
                _ => Support::Unsupported {
                    because: "a PTY has no pointer; type instead, or act on the desktop limb for the same machine",
                },
            },
            Wait | Cancel => Support::Observed,
            ReadScreen | Capture if self.has_mirror => Support::Observed,
            ReadScreen | Capture => Support::Unsupported {
                because: "this limb was opened without a framebuffer mirror, so there are no pixels behind it to read. Open the machine again with perceive set, ask the user to look at the window, or read the machine over SSH if it answers there",
            },
            Scancode => Support::Unsupported {
                because: "this limb refuses raw scancodes outright, whatever the grant carries: a scancode types what the remote layout says that key is, and nothing anywhere reports the difference",
            },
            // `00 R51b`. A shell limb serves this itself: the intent goes to
            // `ssh-core` whole, which opens a second channel (RFC 4254 §6.5)
            // and reads the far side's own `exit-status` (§6.10), and the
            // answer comes back over `limb.exec` as the reply to the request
            // that sent it. On a desktop limb there is no such channel and no
            // honest way to invent one.
            Exec => match self.grounding {
                Grounding::Cells => Support::Native,
                _ => Support::Unsupported {
                    because: "a framebuffer has no command channel: an exec needs a shell, so run it on the SSH limb for this machine. Typing a command into a terminal window on the desktop is not the same thing and has no exit status",
                },
            },
            // Both refused by `ssh-core` with reasons of its own, and named
            // here so an agent is told before it spends a round trip finding
            // out. A second, weaker copy of those reasons is not written here;
            // the driver's own sentence is what an agent sees if it asks.
            PtyRun => Support::Unsupported {
                because: "running a command on the PTY the person is watching is not served on this build: the exit status would have to be scraped from a prompt, and exec on the same machine answers with the far side's own status instead",
            },
            Declare => Support::Unsupported {
                because: "this build declares no working directory or environment between commands: a second SSH channel inherits nothing, so pass cwd and env with each exec (05 §3.3)",
            },
            // `IntentName` is `#[non_exhaustive]`. An intent added after this
            // build is refused with a sentence rather than accepted and
            // dropped, because an intent that ends silently makes an agent
            // wait rather than retry.
            _ => Support::Unsupported {
                because: "this limb was written before that intent existed",
            },
        }
    }

    fn perception(&self) -> limb_core::limb::PerceptionSet {
        limb_core::limb::PerceptionSet {
            // A claim about this SURFACE and not about the machine. The
            // framebuffer always exists; whether any of it is readable through
            // dvvp.v1 depends on whether a mirror was paid for at open time,
            // which is `04 §8` OQ-3's opt in per session: eight 4K sessions
            // would be 264 MB of mirror before anything is decoded.
            frames: self.has_mirror,
            cells: matches!(self.grounding, Grounding::Cells),
            // `00 R42`. There are no window fields on this surface and there
            // will not be inferred ones: an inferred tree that is not labelled
            // inferred is a fabrication.
            structure: false,
        }
    }

    fn grounding(&self) -> Grounding {
        self.grounding
    }

    fn quiescence(&self) -> limb_core::limb::QuiescencePolicy {
        use limb_core::limb::{Confidence, QuiescencePolicy, QuiescenceSignal};
        QuiescencePolicy {
            signal: match self.grounding {
                Grounding::Cells => QuiescenceSignal::OutputBytes,
                // `Damage` only where a mirror was paid for. The rectangles
                // reach this side by asking (`screen.damage`) rather than by
                // being pushed, which is the shape [`SessionSource`] is, and
                // a limb with no mirror has nothing to ask about: claiming to
                // watch damage there would be a wait that never settles and
                // never says why.
                _ if self.has_mirror => QuiescenceSignal::Damage,
                _ => QuiescenceSignal::None,
            },
            default_quiet: std::time::Duration::from_millis(750),
            confidence: Confidence::Inferred,
        }
    }

    fn limits(&self) -> limb_core::limb::LimbLimits {
        limb_core::limb::LimbLimits {
            max_in_flight: 1,
            pointer_per_sec: 60,
            keys_per_sec: 60,
            bytes_per_sec: 1_000_000,
            // The application decides which sessions exist, so there is no
            // ceiling to state here: a slot nobody has open is refused by the
            // plane, by name, with the count it does have.
            max_slots: None,
        }
    }

    fn degraded(&self, _stats: &limb_core::SessionStats) -> Option<limb_core::limb::Degraded> {
        None
    }
}

/// Which limb a tool is aimed at (`04 §4.1`).
///
/// The trio, adopted from BrowserGlass's `targetSelectorProperties()`
/// wholesale, and the reason is theirs: **an agent must never need a different
/// tool because its target happens to be in a group.**
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selector {
    pub limb_id: Option<String>,
    pub group_id: Option<String>,
    /// An index into the group, or a limb id. Required when `group_id` is
    /// given.
    pub member: Option<String>,
}

/// One limb, as `dvv_limbs` and `dvv_status` report it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LimbCard {
    pub limb_id: String,
    pub protocol: String,
    pub host: String,
    pub slot: u16,
    pub state: serde_json::Value,
    pub size: Size,
    /// `pixels` on a desktop limb, `cells` on a terminal one, `none` on a limb
    /// that can be typed at and not pointed at.
    pub grounding: &'static str,
    pub geometry_generation: u32,
    /// What this limb can EVER offer, before it is intersected with the grant.
    pub offers: Vec<String>,
    /// What this attachment may ACTUALLY do here: the intersection of the two.
    /// This is the whole of "capabilities per limb", and it is why nothing in
    /// this crate matches on a protocol kind.
    pub allows: Vec<String>,
    pub lease: LeaseBlock,
    /// One noun phrase, from the limb's own card. Model facing prose, written
    /// by the limb author for a reader who has never seen this product.
    pub what: &'static str,
    /// The sentence that tells an agent when NOT to use this limb. A desktop
    /// limb names its terminal sibling; a terminal limb has nothing cheaper to
    /// steer toward and says nothing.
    pub steer_away: Option<&'static str>,
    /// Whether pixels can be read here at all. False means `dvv_screen` will
    /// refuse, and saying so up front is cheaper than a refused call.
    pub has_mirror: bool,
}

/// A size, in the unit `grounding` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Size {
    pub width: u16,
    pub height: u16,
}

/// The stand down trailer (`04 §4.4`).
///
/// The thing MCP forces us to add. D5 says a human outranks an agent and taking
/// the wheel needs no application code, and `agent-lease` implements that. But
/// an agent driving through MCP has no callbacks: it sees tool results and
/// nothing else, and a yield that exists only as a callback is a yield the most
/// likely consumer cannot observe at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlYield {
    pub limb_id: String,
    pub reason: String,
    pub by_label: Option<String>,
    /// A spelled out boolean rather than a `reason` string to pattern match.
    /// The model has to get one decision right and only one.
    pub human_took_over: bool,
    /// What this call had started and did not finish.
    pub interrupted: Vec<String>,
    pub advice: &'static str,
}

/// What a control call did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlReport {
    pub limb_id: String,
    pub action: String,
    pub outcome: String,
    /// The staleness token to quote back on release. `None` when nothing was
    /// granted.
    pub lease_id: Option<u64>,
    pub held: bool,
    pub view: LeaseView,
    /// What the plane put on the wire to discharge the release a lease change
    /// owes the limb (`00 R11`). Reported rather than logged, so a caller can
    /// assert the ordering.
    pub released: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_yield: Option<ControlYield>,
}

/// What the stop path did (`00 R13`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StopReport {
    pub limb_id: String,
    /// In order. A zero mask pointer, then every key.
    pub released: Vec<String>,
    /// Which in flight intents were withdrawn.
    pub cancelled: Vec<u64>,
    pub phase: String,
    /// Always false. Stopping revokes the wheel; it does not close the machine.
    /// `04 §5.4`: a revoked agent that had a build running should not take the
    /// build with it.
    pub limb_closed: bool,
}

/// One attachment's view of the world.
pub struct Plane {
    registry: LimbRegistry,
    grant: Grant,
    source: Arc<dyn SessionSource>,
    watch: broadcast::Sender<WatchEvent>,
    /// Intent ids this attachment has on the wire, per limb.
    inflight: Mutex<BTreeMap<String, BTreeSet<u64>>>,
    /// The staleness token per limb, for the release.
    leases: Mutex<BTreeMap<String, LeaseId>>,
    /// The generation of the last observation this adapter served, per limb.
    /// See the module comment for why this is allowed to live here.
    observed_at: Mutex<BTreeMap<String, GeometryGeneration>>,
    groups: Mutex<BTreeMap<String, Vec<LimbId>>>,
    group_seq: Mutex<u64>,
    /// The size this crate handed to [`Attach`], per limb. See [`Plane::size_of`].
    sizes: Mutex<BTreeMap<String, (u16, u16)>>,
    /// The label everyone else is shown when this attachment holds a lease.
    /// `08 §5.5` makes it a safety property rather than a nicety: a pane whose
    /// limb is held by an agent says so, visibly, always.
    label: String,
}

impl Plane {
    /// A plane over one grant and one source.
    pub fn new(grant: Grant, source: Arc<dyn SessionSource>, config: PlaneConfig) -> Plane {
        let (watch, _) = broadcast::channel(WATCH_BUFFER);
        let label = format!("agent {}", grant.id());
        Plane {
            registry: LimbRegistry::new(config),
            grant,
            source,
            watch,
            inflight: Mutex::new(BTreeMap::new()),
            leases: Mutex::new(BTreeMap::new()),
            observed_at: Mutex::new(BTreeMap::new()),
            groups: Mutex::new(BTreeMap::new()),
            group_seq: Mutex::new(0),
            sizes: Mutex::new(BTreeMap::new()),
            label,
        }
    }

    /// A plane over this source, granted over the hosts the source publishes.
    ///
    /// **This is not the grant `04 §5` specifies and it does not pretend to
    /// be.** That one is minted by a person clicking Approve in
    /// DeskVNCViewer, written to a file at mode 0600, and referenced by path so
    /// the secret never crosses argv or the environment. None of that exists
    /// until the shell wiring lands, and a build that invented a token would be
    /// building the one thing `04 §5.2` is careful to say a client must not:
    /// authority nobody approved.
    ///
    /// So the scope here is the hosts the SOURCE already publishes and nothing
    /// else: the saved library plus whatever DeskVNCViewer already has open.
    /// With no plane running that list is empty, a placeholder that matches no
    /// real machine takes its place, and every call fails at the host check
    /// naming the host, which is the correct failure.
    ///
    /// That scope is what [`Plane::open`] checks BEFORE it asks the source for
    /// anything, and the ordering matters now that a source can genuinely open
    /// a machine: `00 R19` says an agent may only touch a machine somebody
    /// allowed it to, and a check made on the way back is a check made after
    /// the connection.
    ///
    /// The capabilities are the operator bundle plus `exec` named literally.
    /// `exec` is in no role bundle by design and can only be granted by naming
    /// the string, which is BrowserGlass's treatment of `evaluate` copied for
    /// the same reason: a capability nobody can ever hold is a capability
    /// nobody reviews.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when the grant cannot be issued.
    pub fn local(source: Arc<dyn SessionSource>) -> Result<Plane, ToolError> {
        let hosts: Vec<String> = source
            .hosts()
            .unwrap_or_default()
            .into_iter()
            .map(|host| host.address)
            .collect();
        let hosts = if hosts.is_empty() {
            // `Grant::issue` refuses a grant over no machines, and correctly: a
            // grant that can do nothing, issued silently, presents later as
            // every intent being refused for a reason nobody wrote down.
            vec!["no-machine.invalid".to_string()]
        } else {
            hosts
        };
        let capabilities = limb_core::capability::RoleBundle::Operator
            .expand()
            .with(Capability::Exec);
        Grant::issue("att_local", capabilities, hosts)
            .map(|grant| Plane::new(grant, source, PlaneConfig::default()))
            .map_err(|error| ToolError::new(codes::POLICY_DENIED, error.to_string()))
    }

    /// What this attachment may do, and where.
    pub fn grant(&self) -> &Grant {
        &self.grant
    }

    /// One sentence naming where limbs come from in this process.
    pub fn source_description(&self) -> &'static str {
        self.source.describe()
    }

    /// A new watcher. Every event from now on, and a lag report if it falls
    /// behind (`00 R24`: never silently).
    pub fn subscribe(&self) -> broadcast::Receiver<WatchEvent> {
        self.watch.subscribe()
    }

    /// This attachment, as arbitration sees it.
    ///
    /// [`HolderKind::Agent`], which is the bottom of the ladder, and that is
    /// the point: a person outranks an agent by default, so "the human takes
    /// the wheel" needs no application code anywhere above `agent-lease`.
    pub fn party(&self) -> Party {
        Party::new(
            self.grant.id().clone(),
            HolderKind::Agent,
            self.label.clone(),
        )
    }

    fn party_id(&self) -> &PartyId {
        self.grant.id()
    }

    /// Saved machines and discovered ones, never a secret.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when the grant does not carry `hosts.read`, or when the
    /// source cannot reach the library.
    pub fn hosts(&self) -> Result<Vec<HostRecord>, ToolError> {
        self.require(Capability::HostsRead, "reading the machine library")?;
        self.source.hosts()
    }

    /// Every limb this attachment can see.
    pub fn limbs(&self) -> Vec<LimbCard> {
        self.registry
            .list()
            .iter()
            .map(|limb| self.card(limb))
            .collect()
    }

    /// Bring one machine under the plane.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] from the source, or from the plane's own admission
    /// control, the host check and the slot check, each naming what the caller
    /// can do about it.
    pub fn open(&self, request: &OpenRequest) -> Result<LimbCard, ToolError> {
        if request.host_id.is_some() && request.protocol.is_some() {
            return Err(ToolError::bad_request(
                "protocol is refused beside hostId: with a saved machine the protocol is read from the machine, and overriding it would dial the wrong protocol at an endpoint somebody configured for something else",
            ));
        }
        // BEFORE the source is asked, and that ordering is the whole point now
        // that a source can genuinely open a machine. `LimbRegistry::attach`
        // makes both of these checks too, but it makes them on the way back,
        // which was harmless while an open could only adopt a session somebody
        // had already opened and is not harmless when it dials. `00 R19`: a
        // host outside the grant is refused before anything connects.
        self.require(Capability::Open, "opening a limb")?;
        let host = self.host_for(request)?;
        if !self.grant.allows_host(&host) {
            let refusal = self.grant.host_refusal(&host);
            return Err(ToolError::new(codes::POLICY_DENIED, refusal.to_string()));
        }
        let attach = self.source.open(request)?;
        let host = attach.host.clone();
        let size = attach.size;
        let attached = self.registry.attach(&self.grant, attach)?;
        // `00 R51b`'s last hop. The relay thread carrying a native intent over
        // the socket needs somewhere to deliver the driver's answer, and this
        // is the attachment it delivers to. Registered here rather than in
        // `build_attach` because this is the first point at which the
        // attachment exists at all.
        register_answerable(&attached);
        lock(&self.sizes).insert(attached.id().to_string(), size);
        self.refresh(&attached);
        let _ = self.watch.send(WatchEvent::Attached {
            limb_id: attached.id().to_string(),
            protocol: attached.protocol().to_string(),
            host,
        });
        Ok(self.card(&attached))
    }

    /// Take a limb out of the registry.
    ///
    /// Every outstanding intent is withdrawn first, because `02 §6.2` owes a
    /// settlement on a close and an intent that ends silently forces every
    /// agent to carry its own timeout for every call.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when nothing is attached under that id, or when the
    /// grant does not carry `close`.
    pub fn close(&self, id: &str) -> Result<(), ToolError> {
        let limb_id = LimbId::from_caller(id)
            .map_err(|e| ToolError::new(codes::BAD_REQUEST, e.to_string()))?;
        if let Some(limb) = self.registry.get(&limb_id) {
            for intent in self.inflight_ids(limb.id().as_str()) {
                limb.cancel_running(limb_core::intent::IntentId(intent));
            }
        }
        self.registry.detach(&self.grant, &limb_id)?;
        forget_answerable(id);
        lock(&self.leases).remove(id);
        lock(&self.inflight).remove(id);
        lock(&self.observed_at).remove(id);
        lock(&self.sizes).remove(id);
        let _ = self.watch.send(WatchEvent::Detached {
            limb_id: id.to_string(),
        });
        Ok(())
    }

    /// Which limb a call is aimed at.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] naming `dvv_limbs` when the selector picks nothing, and
    /// naming `dvv_group_list` when a group member index is out of range. Never
    /// a default guess: acting on the wrong machine is the failure this whole
    /// design is built to avoid.
    pub fn resolve(&self, selector: &Selector) -> Result<AttachedLimb, ToolError> {
        if let Some(id) = &selector.limb_id {
            let limb_id = LimbId::from_caller(id)
                .map_err(|e| ToolError::new(codes::BAD_REQUEST, e.to_string()))?;
            return self.registry.get(&limb_id).ok_or_else(|| {
                ToolError::new(
                    codes::LIMB_GONE,
                    format!("no limb is attached as {id}; call dvv_limbs for the current ids"),
                )
            });
        }
        if let Some(group) = &selector.group_id {
            let member = selector.member.as_deref().ok_or_else(|| {
                ToolError::bad_request(
                    "member is required when groupId is given: it is an index from dvv_group_list, or a limbId",
                )
            })?;
            return self.group_member(group, member);
        }
        let mut limbs = self.registry.list();
        match limbs.len() {
            1 => Ok(limbs.remove(0)),
            0 => Err(ToolError::new(
                codes::LIMB_GONE,
                "no limb is attached, so there is nothing to act on. Open one with dvv_open, or ask the user to open a machine in DeskVNCViewer",
            )),
            n => Err(ToolError::bad_request(format!(
                "limbId is required: {n} limbs are attached and defaulting would act on the wrong machine. Call dvv_limbs and name one"
            ))),
        }
    }

    /// Take whatever the source has learned about this limb's lifecycle.
    ///
    /// Called before every read and every dispatch rather than on a timer,
    /// because a state that is only refreshed on a timer is a state that is
    /// wrong for the length of the timer, and the thing it decides is whether
    /// to put a click on a reconnecting socket.
    pub fn refresh(&self, limb: &AttachedLimb) {
        if let Some(state) = self.source.state(limb.id()) {
            limb.note_state(state);
        }
    }

    /// One limb, as a card.
    pub fn card(&self, limb: &AttachedLimb) -> LimbCard {
        self.refresh(limb);
        let offered = limb.offered();
        let allows = offered.intersect(self.grant.capabilities());
        let card = limb.limb().describe();
        let (width, height) = self.size_of(limb);
        LimbCard {
            limb_id: limb.id().to_string(),
            protocol: limb.protocol().to_string(),
            host: limb.host().to_string(),
            slot: limb.slot().0,
            state: state_json(&limb.state()),
            size: Size { width, height },
            grounding: grounding_name(limb.limb().grounding()),
            geometry_generation: limb.generation().get(),
            offers: offered.iter().map(|c| c.to_string()).collect(),
            allows: allows.iter().map(|c| c.to_string()).collect(),
            lease: self.lease_block(limb),
            what: card.what,
            steer_away: card.steer_away,
            has_mirror: limb.observatory().has_frames(),
        }
    }

    /// The full observation object (`15 §2.2`).
    ///
    /// Serving one records the generation it carried, which is what a later
    /// unfenced actuation is stamped with. See the module comment.
    pub fn observe(&self, limb: &AttachedLimb, frame: Option<FrameBlock>) -> Observation {
        self.refresh(limb);
        let generation = limb.generation();
        lock(&self.observed_at).insert(limb.id().to_string(), generation);
        let (width, height) = self.size_of(limb);
        let perception = limb.limb().perception();
        Observation {
            schema: SCHEMA,
            limb_id: limb.id().to_string(),
            protocol: limb.protocol().to_string(),
            captured_at: clock::unix_millis(),
            state: state_json(&limb.state()),
            geometry: Geometry {
                generation: generation.get(),
                space: Space {
                    width,
                    height,
                    unit: match limb.limb().grounding() {
                        Grounding::Cells => "cells",
                        _ => "pixels",
                    },
                },
                // Empty until the shell hands the plane a `ScreenLayout`, and
                // an empty list means the whole framebuffer is one display,
                // which is what a server without ExtendedDesktopSize gives.
                screens: Vec::<Screen>::new(),
                // False, always, until the shell wiring lands. On VNC it is
                // false for ever: RFB never says which monitor is primary, and
                // an agent reading three screens all false as "no primary
                // monitor" has made a wrong decision from a true field.
                primary_known: false,
            },
            frame,
            locks: Observation::pending(),
            damage: match limb.observatory().damage_now() {
                Some(damage) => limb_core::availability::Availability::live(
                    crate::observation::Damage {
                        union: damage.bounds.into(),
                        rects: damage.rects.len() as u32,
                        coverage: damage.coverage,
                    },
                ),
                None => limb_core::availability::Availability::unknown(
                    "no damage has arrived on this limb yet, and an absence of damage is not evidence the screen is still: a server whose damage tracking cannot be trusted sends nothing either",
                ),
            },
            desktop_name: Observation::pending(),
            session: None,
            terminal: perception.cells.then(|| crate::observation::TerminalBlock {
                cols: width,
                rows: height,
                alt_screen: Observation::pending(),
                bracketed_paste: Observation::pending(),
                mouse_reporting: Observation::pending(),
            }),
            last_error: Observation::pending(),
            lease: self.lease_block(limb),
            signals: self.signals(limb),
            untrusted: true,
        }
    }

    /// Which negotiated signals this session has (`00 R34`).
    ///
    /// Every entry `unknown` in this build except `window_structure`, which is
    /// absent and cannot be anything else. Reported rather than omitted,
    /// because "we do not know yet" and "the far side does not do it" are
    /// different claims and an agent should treat them differently: the first
    /// may resolve and the second is permanent for this session.
    pub fn signals(&self, limb: &AttachedLimb) -> SignalReport {
        let mut report = SignalReport::default();
        let perception = limb.limb().perception();
        if !perception.cells {
            report.alt_screen = limb_core::availability::SignalState::absent(
                "this limb has no character grid, so there is no alternate screen to be in",
            );
        }
        if limb.protocol() != ProtocolKind::Rdp {
            report.errinfo = limb_core::availability::SignalState::absent(
                "the ERRINFO_ space is RDP's and does not exist on this protocol",
            );
        }
        report
    }

    /// Ask for the wheel.
    ///
    /// Acquire and discharge in one call, which is what a caller almost always
    /// wants and what `agent-plane` already offers as `take_control`. The
    /// release the transition owes the limb goes out before the new holder's
    /// first intent, buttons before keys, and what went is in the report so a
    /// caller can assert it rather than trust it.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when the grant does not carry `control`, or when
    /// arbitration refused.
    pub async fn acquire(
        &self,
        limb: &AttachedLimb,
        reason: Option<String>,
        no_queue: bool,
    ) -> Result<ControlReport, ToolError> {
        self.require(Capability::Control, "holding the control lease")?;
        let now = clock::lease_now();
        let expiries = limb.tick(now);
        self.honour(limb, &expiries, now).await;

        let mut request = AcquireRequest::new(self.party());
        if let Some(reason) = reason {
            request = request.reason(reason);
        }
        if no_queue {
            request = request.no_queue();
        }
        let transition = limb.acquire(request, now).map_err(|e| {
            ToolError::new(
                codes::LEASE_NOT_HELD,
                format!("{e}; nothing was sent to {}", limb.id()),
            )
        })?;
        let released = self.honour(limb, &transition, now).await;

        let lease_id = match &transition.outcome {
            LeaseOutcome::Granted { lease_id, .. } | LeaseOutcome::Renewed { lease_id } => {
                lock(&self.leases).insert(limb.id().to_string(), *lease_id);
                Some(lease_id.as_u64())
            }
            _ => None,
        };
        Ok(self.control_report(
            limb,
            "acquire",
            outcome_name(&transition.outcome),
            lease_id,
            released,
        ))
    }

    /// Let go.
    ///
    /// A release from a party that no longer holds the lease is an ordinary
    /// unchanged result, not an error, because a cleanup path has to be safe to
    /// call twice.
    pub async fn release(&self, limb: &AttachedLimb) -> ControlReport {
        let now = clock::lease_now();
        let held = lock(&self.leases).remove(limb.id().as_str());
        let transition = match held {
            Some(lease_id) => limb.release_lease(self.party_id(), lease_id, now),
            // Quoting a lease id we were never given would be a fencing check
            // reimplemented outside the crate that owns it, so a release with
            // nothing held asks arbitration with a token it cannot match and
            // gets `Unchanged`, which is the honest answer.
            None => limb.release_lease(self.party_id(), LeaseId::from_u64(0), now),
        };
        let released = self.honour(limb, &transition, now).await;
        self.control_report(
            limb,
            "release",
            outcome_name(&transition.outcome),
            None,
            released,
        )
    }

    /// Where the lease is, with no side effect but the tick.
    pub async fn control_status(&self, limb: &AttachedLimb) -> ControlReport {
        let now = clock::lease_now();
        let expiries = limb.tick(now);
        let released = self.honour(limb, &expiries, now).await;
        self.control_report(limb, "status", "unchanged", None, released)
    }

    /// The panic chord, for one limb (`00 R13`).
    ///
    /// **A revocation, not a request.** The holder is gone the moment
    /// `force_release` returns and the queue is emptied, so every in flight
    /// intent stops at its next step rather than finishing the word. Then the
    /// release goes out: a zero mask pointer FIRST, then every key.
    ///
    /// There is no grace window, and BrowserGlass's own demo is why: it
    /// measures 2,008 ms for a polite handover, which is two seconds of
    /// somebody pressing a button labelled stop while nothing happens.
    ///
    /// The order inside this method is the whole of the ruling and it is worth
    /// reading in order:
    ///
    /// 1. `force_release`, which flips the fence synchronously. `dispatch`
    ///    re-checks the fence before EVERY command, so nothing more of the
    ///    holder's reaches the wire from this instant.
    /// 2. cancel every intent we know is running, so each settles rather than
    ///    ending silently.
    /// 3. `honour`, which sends the release the transition owes the limb.
    ///
    /// Step 1 before step 3 is not an optimisation. A release sent while the
    /// holder could still dispatch would be a release the holder's next
    /// keystroke undoes.
    pub async fn stop(&self, limb: &AttachedLimb) -> StopReport {
        let now = clock::lease_now();
        let transition = limb.force_release(now);

        let cancelled = self.inflight_ids(limb.id().as_str());
        for intent in &cancelled {
            limb.cancel_running(limb_core::intent::IntentId(*intent));
        }

        let released = self.honour(limb, &transition, now).await;
        lock(&self.leases).remove(limb.id().as_str());

        let _ = self.watch.send(WatchEvent::Stopped {
            limb_id: limb.id().to_string(),
            released: released.clone(),
            at: clock::unix_millis(),
        });
        StopReport {
            limb_id: limb.id().to_string(),
            released,
            cancelled,
            phase: format!("{:?}", transition.to).to_lowercase(),
            limb_closed: false,
        }
    }

    /// Dispatch one intent and answer for it.
    ///
    /// Never returns a settlement that did not happen: `AttachedLimb::dispatch`
    /// produces one on every path, and this method's only additions are the
    /// intent id, the fence, and telling the watchers.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] only for a coordinate intent with no generation and no
    /// prior observation. Everything else is a settlement, including a refusal,
    /// because a refusal is an ANSWER.
    pub async fn submit(
        &self,
        limb: &AttachedLimb,
        kind: IntentKind,
        generation: Option<u32>,
    ) -> Result<Settlement, ToolError> {
        self.refresh(limb);
        let now = clock::lease_now();
        let expiries = limb.tick(now);
        self.honour(limb, &expiries, now).await;

        let fence = self.fence_for(limb, &kind, generation)?;
        let intent = AgentIntent {
            id: limb.mint(),
            grant: self.grant.id().clone(),
            // How long the plane waits for a NATIVE answer, which is a
            // different question from how long a lowered plan takes and only
            // one intent answers it. `agent-plane` waits five seconds by
            // default, which is right for an intent whose answer is a driver
            // saying yes or no and wrong for a `run` the caller gave sixty
            // seconds to: without this, a command that finished in fifty
            // settles as a timeout for an answer that arrived. The slack is
            // the round trip over the socket, and the command's own timeout is
            // still the thing that ends the command (`05 §4.1`).
            deadline: answer_window(&kind),
            fence,
            kind,
        };
        let id = intent.id.0;
        let name = intent.kind.name().to_string();

        self.note_inflight(limb.id().as_str(), id, true);
        let _ = self.watch.send(WatchEvent::IntentStarted {
            limb_id: limb.id().to_string(),
            intent: id,
            kind: name.clone(),
            at: clock::unix_millis(),
        });

        let settlement = limb.dispatch(&self.grant, intent, now).await;

        self.note_inflight(limb.id().as_str(), id, false);
        let _ = self.watch.send(WatchEvent::Settled {
            limb_id: limb.id().to_string(),
            intent: id,
            kind: name,
            outcome: outcome_word(&settlement.outcome).to_string(),
            code: settlement.reason.map(|r| r.as_str().to_string()),
            progress: format!("{:?}", settlement.progress),
            lost_state: settlement.gaps.lost_state(),
            at: clock::unix_millis(),
        });
        Ok(settlement)
    }

    /// Open a group and address its members together.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] from the first member that could not be opened. Nothing
    /// is left half open: a failure detaches whatever this call attached, so a
    /// retry is not fighting a partial group.
    pub fn group_open(
        &self,
        requests: &[OpenRequest],
    ) -> Result<(String, Vec<LimbCard>), ToolError> {
        if requests.is_empty() {
            return Err(ToolError::bad_request(
                "a group needs at least one machine; prefer the smallest group the task needs, because every member is a real connection",
            ));
        }
        let mut opened = Vec::new();
        let mut cards = Vec::new();
        for request in requests {
            match self.open(request) {
                Ok(card) => {
                    if let Ok(id) = LimbId::from_caller(&card.limb_id) {
                        opened.push(id);
                    }
                    cards.push(card);
                }
                Err(error) => {
                    for id in &opened {
                        let _ = self.close(id.as_str());
                    }
                    return Err(error);
                }
            }
        }
        let id = {
            let mut seq = lock(&self.group_seq);
            *seq += 1;
            format!("grp_{seq}")
        };
        lock(&self.groups).insert(id.clone(), opened);
        Ok((id, cards))
    }

    /// Open groups, or one group's members.
    pub fn group_list(&self, id: Option<&str>) -> Result<Vec<(String, Vec<LimbCard>)>, ToolError> {
        let groups = lock(&self.groups);
        let names: Vec<String> = match id {
            Some(id) => {
                if !groups.contains_key(id) {
                    return Err(ToolError::bad_request(format!("no group is open as {id}")));
                }
                vec![id.to_string()]
            }
            None => groups.keys().cloned().collect(),
        };
        Ok(names
            .into_iter()
            .map(|name| {
                let members = groups
                    .get(&name)
                    .map(|ids| {
                        ids.iter()
                            .filter_map(|id| self.registry.get(id))
                            .map(|limb| self.card(&limb))
                            .collect()
                    })
                    .unwrap_or_default();
                (name, members)
            })
            .collect())
    }

    /// Add members to an open group.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when the group is not open, or from the open itself.
    pub fn group_grow(
        &self,
        id: &str,
        requests: &[OpenRequest],
    ) -> Result<Vec<LimbCard>, ToolError> {
        if !lock(&self.groups).contains_key(id) {
            return Err(ToolError::bad_request(format!("no group is open as {id}")));
        }
        let mut cards = Vec::new();
        for request in requests {
            let card = self.open(request)?;
            if let Ok(limb_id) = LimbId::from_caller(&card.limb_id) {
                if let Some(members) = lock(&self.groups).get_mut(id) {
                    members.push(limb_id);
                }
            }
            cards.push(card);
        }
        Ok(cards)
    }

    /// Close the n most recently added members.
    ///
    /// Fails rather than clamping if n is larger than the group holds, because
    /// a clamp turns "close three" into "close everything" silently.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when the group is not open or n is too large.
    pub fn group_shrink(&self, id: &str, n: usize) -> Result<Vec<String>, ToolError> {
        let doomed = {
            let mut groups = lock(&self.groups);
            let members = groups
                .get_mut(id)
                .ok_or_else(|| ToolError::bad_request(format!("no group is open as {id}")))?;
            if n > members.len() {
                return Err(ToolError::bad_request(format!(
                    "group {id} holds {} member(s) and shrinking by {n} would close more than it has; this is refused rather than clamped",
                    members.len()
                )));
            }
            members.split_off(members.len() - n)
        };
        let mut closed = Vec::new();
        for member in doomed {
            self.close(member.as_str())?;
            closed.push(member.to_string());
        }
        Ok(closed)
    }

    /// Close every member and forget the group.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when the group is not open.
    pub fn group_close(&self, id: &str) -> Result<Vec<String>, ToolError> {
        let members = lock(&self.groups)
            .remove(id)
            .ok_or_else(|| ToolError::bad_request(format!("no group is open as {id}")))?;
        let mut closed = Vec::new();
        for member in members {
            // A member that is already gone is not an error: closing a limb
            // that has gone away is an ordinary success, so a group close after
            // a disconnect does not fail halfway and leave the rest open.
            let _ = self.close(member.as_str());
            closed.push(member.to_string());
        }
        Ok(closed)
    }

    /// Every member of a group, in index order.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when the group is not open.
    pub fn group_members(&self, id: &str) -> Result<Vec<AttachedLimb>, ToolError> {
        let ids = lock(&self.groups)
            .get(id)
            .cloned()
            .ok_or_else(|| ToolError::bad_request(format!("no group is open as {id}")))?;
        Ok(ids
            .iter()
            .filter_map(|limb_id| self.registry.get(limb_id))
            .collect())
    }

    fn group_member(&self, group: &str, member: &str) -> Result<AttachedLimb, ToolError> {
        let members = self.group_members(group)?;
        if let Ok(index) = member.parse::<usize>() {
            return members.into_iter().nth(index).ok_or_else(|| {
                ToolError::bad_request(format!(
                    "group {group} has no member {index}; call dvv_group_list for the indices"
                ))
            });
        }
        members
            .into_iter()
            .find(|limb| limb.id().as_str() == member)
            .ok_or_else(|| {
                ToolError::bad_request(format!("{member} is not a member of group {group}"))
            })
    }

    /// The generation to fence an actuation at.
    ///
    /// An explicit one always wins, and a stale one is refused downstream,
    /// which is the whole mechanism. An absent one falls back to the last
    /// observation this adapter served, and to a refusal when there has been
    /// none, because the alternative is stamping the current generation onto a
    /// coordinate that came from a screen the agent has never seen.
    fn fence_for(
        &self,
        limb: &AttachedLimb,
        kind: &IntentKind,
        generation: Option<u32>,
    ) -> Result<Option<GeometryGeneration>, ToolError> {
        if !kind.is_grounded() {
            // A fence on an ungrounded intent would be compared and could go
            // stale for no reason: there is nothing about a keystroke that a
            // resize invalidates.
            return Ok(None);
        }
        if let Some(generation) = generation {
            return Ok(Some(generation_from(generation, limb)));
        }
        match lock(&self.observed_at).get(limb.id().as_str()).copied() {
            Some(seen) => Ok(Some(seen)),
            None => Err(ToolError::new(
                "UNFENCED",
                format!(
                    "this action carries a coordinate and nothing has been observed on {} yet, so there is no geometry generation the coordinate could have come from. Call dvv_screen or dvv_status first and send its geometry.generation back as generation",
                    limb.id()
                ),
            )),
        }
    }

    /// Discharge the release a lease change owes the limb, and tell the
    /// watchers.
    ///
    /// Every lease call in this file goes through here, so there is no path
    /// where a transition's obligation is dropped. `LeaseTransition` is
    /// `#[must_use]` for exactly that reason and this is where the `must` is
    /// satisfied.
    async fn honour(
        &self,
        limb: &AttachedLimb,
        transition: &agent_lease::LeaseTransition,
        now: agent_lease::LeaseInstant,
    ) -> Vec<String> {
        let sent = limb.honour(transition, now).await;
        let released: Vec<String> = sent.iter().map(command_name).collect();
        if transition.changed() || !released.is_empty() {
            let view = limb.lease_view(self.party_id());
            let _ = self.watch.send(WatchEvent::LeaseChanged {
                limb_id: limb.id().to_string(),
                phase: phase_name(view.phase),
                holder_kind: view.holder_kind.map(|k| format!("{k:?}").to_lowercase()),
                holder_label: view.holder_label.clone(),
                human_took_over: took_over(&view),
                queue_depth: view.queue_depth,
                released: released.clone(),
            });
        }
        released
    }

    fn control_report(
        &self,
        limb: &AttachedLimb,
        action: &str,
        outcome: &str,
        lease_id: Option<u64>,
        released: Vec<String>,
    ) -> ControlReport {
        let view = limb.lease_view(self.party_id());
        let human_took_over = took_over(&view);
        ControlReport {
            limb_id: limb.id().to_string(),
            action: action.to_string(),
            outcome: outcome.to_string(),
            lease_id,
            held: view.you_hold,
            control_yield: (!view.you_hold).then(|| ControlYield {
                limb_id: limb.id().to_string(),
                reason: if human_took_over {
                    "human_takeover".to_string()
                } else {
                    phase_name(view.phase)
                },
                by_label: view.holder_label.clone(),
                human_took_over,
                interrupted: self
                    .inflight_ids(limb.id().as_str())
                    .iter()
                    .map(|id| format!("intent {id}"))
                    .collect(),
                advice: if human_took_over {
                    "A person is driving this machine. Do not act on it and do not acquire control. Report back to the user instead."
                } else {
                    "This attachment does not hold the wheel. Call dvv_control with action acquire before acting."
                },
            }),
            view,
            released,
        }
    }

    fn lease_block(&self, limb: &AttachedLimb) -> LeaseBlock {
        let view = limb.lease_view(self.party_id());
        LeaseBlock {
            held: view.you_hold,
            phase: phase_name(view.phase),
            holder_kind: view.holder_kind.map(|k| format!("{k:?}").to_lowercase()),
            holder_label: view.holder_label.clone(),
            queue_depth: view.queue_depth,
            queue_position: view.queue_position,
            human_took_over: took_over(&view),
        }
    }

    /// Which host an open is aimed at, as the GRANT spells hosts.
    ///
    /// `Plane::local` scopes a grant to the addresses the source publishes, so
    /// this has to answer an address and not an id. A `hostId` is resolved
    /// through the source's own library, which is the same lookup the shell
    /// makes, so the two cannot disagree about which machine an id names.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] when neither a host id nor an address was given, or when
    /// the id names nothing.
    fn host_for(&self, request: &OpenRequest) -> Result<String, ToolError> {
        if let Some(address) = &request.address {
            return Ok(address.clone());
        }
        let host_id = request.host_id.as_deref().ok_or_else(|| {
            ToolError::bad_request(
                "dvv_open needs a hostId from dvv_hosts, or an address with a protocol",
            )
        })?;
        self.source
            .hosts()?
            .into_iter()
            .find(|host| host.host_id == host_id)
            .map(|host| host.address)
            .ok_or_else(|| {
                ToolError::bad_request(format!(
                    "no saved machine is called {host_id}; call dvv_hosts for the ids"
                ))
            })
    }

    fn require(&self, capability: Capability, operation: &str) -> Result<(), ToolError> {
        if self
            .grant
            .allows_all(limb_core::capability::CapabilitySet::of(&[capability]))
        {
            return Ok(());
        }
        Err(ToolError::new(
            codes::POLICY_DENIED,
            format!(
                "{operation} needs {capability} and grant {} does not carry it; a grant's capabilities are fixed when a person approves it, so tell the user which one is missing rather than retrying",
                self.grant.id()
            ),
        ))
    }

    /// How big this limb is, in the unit its grounding names.
    ///
    /// `agent-plane` has no size accessor: the framebuffer size lives on the
    /// private lowering context, where it is used to reject a coordinate
    /// outside it, and adding a second copy inside that crate would be a second
    /// answer to the same question. So this crate remembers the number it
    /// handed to `Attach`, which is the same number by construction because
    /// this crate built the `Attach`.
    ///
    /// A limb attached by some other path reports zeroes, and a zero size is
    /// visibly wrong rather than plausibly wrong, which is the right way for
    /// this to fail.
    fn size_of(&self, limb: &AttachedLimb) -> (u16, u16) {
        lock(&self.sizes)
            .get(limb.id().as_str())
            .copied()
            .unwrap_or((0, 0))
    }

    fn inflight_ids(&self, limb: &str) -> Vec<u64> {
        lock(&self.inflight)
            .get(limb)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    fn note_inflight(&self, limb: &str, intent: u64, running: bool) {
        let mut table = lock(&self.inflight);
        let entry = table.entry(limb.to_string()).or_default();
        if running {
            entry.insert(intent);
        } else {
            entry.remove(&intent);
        }
    }
}

/// A generation a caller sent back, rebuilt.
///
/// `GeometryGeneration` has no constructor from a raw number, deliberately: it
/// exists to be compared and the comparison lives in one place. What a caller
/// quotes back is therefore matched against the limb's current value here, and
/// anything that is not the current one is passed through as the limb's own
/// `FIRST`, which the fence then rejects as stale. That is the honest shape: a
/// number this build cannot rebuild cannot be admitted, and it must be refused
/// rather than silently treated as current.
fn generation_from(quoted: u32, limb: &AttachedLimb) -> GeometryGeneration {
    let current = limb.generation();
    if current.get() == quoted {
        current
    } else {
        GeometryGeneration::FIRST
    }
}

fn grounding_name(grounding: Grounding) -> &'static str {
    match grounding {
        Grounding::Pixels => "pixels",
        Grounding::Cells => "cells",
        Grounding::None => "none",
    }
}

fn phase_name(phase: agent_lease::LeasePhase) -> String {
    format!("{phase:?}")
        .chars()
        .flat_map(|c| {
            if c.is_ascii_uppercase() {
                vec!['-', c.to_ascii_lowercase()]
            } else {
                vec![c]
            }
        })
        .collect::<String>()
        .trim_start_matches('-')
        .to_string()
}

/// Did a PERSON take this machine?
///
/// The one decision the model has to get right. True only when somebody else
/// holds the wheel AND that somebody is person shaped, so an agent preempted by
/// another agent is told to retry and an agent preempted by a person is told to
/// stop.
fn took_over(view: &LeaseView) -> bool {
    !view.you_hold
        && view
            .holder_kind
            .map(agent_lease::HolderKind::is_person)
            .unwrap_or(false)
}

fn outcome_name(outcome: &LeaseOutcome) -> &'static str {
    match outcome {
        LeaseOutcome::Unchanged => "unchanged",
        LeaseOutcome::Granted { .. } => "granted",
        LeaseOutcome::Renewed { .. } => "renewed",
        LeaseOutcome::Queued { .. } => "queued",
        LeaseOutcome::PreemptionStarted { .. } => "preemption-started",
        LeaseOutcome::WaitCancelled => "wait-cancelled",
        LeaseOutcome::PreemptionAbandoned => "preemption-abandoned",
        LeaseOutcome::Unheld => "unheld",
        LeaseOutcome::HandoverComplete { .. } => "handover-complete",
    }
}

/// The settlement's outcome as one word an agent matches on.
pub fn outcome_word(outcome: &limb_core::observation::Outcome) -> &'static str {
    use limb_core::observation::Outcome;
    match outcome {
        Outcome::Done {
            delivered: true, ..
        } => "delivered",
        Outcome::Done { .. } => "partial",
        Outcome::TimedOut { .. } => "timed-out",
        Outcome::Superseded { .. } => "superseded",
        Outcome::Cancelled => "cancelled",
        Outcome::Refused { .. } => "refused",
        Outcome::LinkLost { .. } => "link-lost",
        // `Outcome` is `#[non_exhaustive]`. An outcome added by a later build
        // is reported as unknown rather than as one of the eight, because
        // mapping it onto the nearest is how an agent gets told a link loss was
        // a success.
        _ => "unknown",
    }
}

/// `SessionState` as JSON, through its own serde representation.
///
/// Not re-encoded by hand. That representation is a contract with
/// `ui/src/lib/types.ts` and a second encoder here would be a second answer to
/// what state a limb is in.
pub fn state_json(state: &SessionState) -> serde_json::Value {
    serde_json::to_value(state).unwrap_or_else(|_| serde_json::json!({ "state": "idle" }))
}
