//! The `dvvp.v1` server: one local socket, and the verbs an agent reaches the
//! live session registry through.
//!
//! ## What this is a server for
//!
//! `04 §1.1` rules that MCP is an adapter and that underneath it there is
//! exactly one native surface. This is that surface's shell half. `dvv` speaks
//! it, `dvv mcp` speaks it through `dvv`, and neither reaches past it into
//! `ProtocolRegistry`, into [`SessionEntry`] or into a driver.
//!
//! ## Slot semantics are built here, because nothing else builds them
//!
//! `00 B7`. `AppState::existing_window_for_machine` is called from exactly one
//! place, `open_session_window`, and **`connect_session` never consults it**.
//! So de duplication is a WINDOW rule and a limb the plane reaches is de
//! duplicated by nothing at all. [`sessions_for_machine`] is this module's
//! answer: live sessions for one machine, oldest first, and the slot is the
//! index. Slot 0 is therefore the session a person opened first, which is also
//! the only session on the overwhelming majority of machines, and that is what
//! `02 §4.4`'s "slot 0 attaches to whatever is already live" means here.
//!
//! ## Opening a machine, without a frame channel
//!
//! `connect_session` takes a `tauri::ipc::Channel` captured from a webview,
//! because that channel is where the decoded frames go, and a socket has no
//! channel to hand it. That fact has not changed and [`limb_open`] does not
//! work around it: it asks the APPLICATION to open the machine, which is the
//! same path a person's click takes through `open_session_window`, window and
//! all, and the webview that appears captures the channel exactly as it always
//! did. The limb then attaches to the session that appears.
//!
//! Three rules survive that, and each is checked before anything dials:
//!
//! * **The credential comes from the keychain and never from the agent**
//!   (`00 R19`, `09 §4`). An agent names a saved machine;
//!   [`wire::refuse_credentials`] refuses the fields that would carry a secret,
//!   by name.
//! * **The grant names its hosts** (`00 R19`). This socket's version of that
//!   list is the one [`hosts_list`] publishes: machines somebody saved, plus
//!   the ones already open. An address outside it is refused before a socket
//!   is opened to it.
//! * **Opening is asynchronous.** The reply comes back when the session is
//!   SPAWNED and says so, because a call that blocked until a machine had
//!   authenticated would be a call that blocks on a person typing a password.
//!
//! ## Files, and why they ride the control lane too
//!
//! The `files.*` verbs move bytes over the SFTP sidecar `PRD/08` already built
//! for the Files panel, and they move them base64 inside the JSON envelope for
//! the same reason [`screen_read`] answers with an image on it: there is one
//! lane, and a request and reply shape with nothing that can interleave. What
//! that costs is the third base64 adds and a cap this file enforces
//! ([`MAX_FILE_CHUNK`]); what it buys is that an installer crosses in windows
//! and arrives byte for byte, with the size of the whole file beside every
//! window so the caller can see it has all of it.
//!
//! The sidecar is opened on FIRST USE and there is no connect verb, because a
//! connect verb is a round trip an agent has to know to make. Two things it
//! will not do on an agent's behalf: accept an unknown SSH host key, which is
//! a decision only a person can make, and continue past a CHANGED one, which
//! nobody may.
//!
//! ## What it deliberately cannot do
//!
//! **Carry a credential.** `crate::agent::wire::decode_command` has no arm for
//! one (D7). The `files.*` verbs keep that rule by naming no endpoint at all:
//! a file call names a session it is already attached to, and the address, the
//! port and the keychain lookup are the shell's, exactly as they are for a
//! person opening the Files panel.
//!
//! ## How pixels get out
//!
//! `04 §2.2` gives pixels their own binary lanes, `msg_type` 1 and 4, and this
//! build carries neither. That is not the gap it looks like. A push lane is
//! the wrong shape for this surface: `dvv`'s [`SessionSource`] is a
//! SYNCHRONOUS request and reply trait over one blocking socket, with no
//! reader task and nothing that can interleave a push into the middle of a
//! reply, and giving it one would be a rewrite of the transport to serve a
//! frame nobody asked for.
//!
//! So **a frame is the answer to [`screen_read`]**, on the control lane, with
//! the encoded image base64'd beside the observation that describes it. The
//! cost is the third that base64 adds and a cap this file enforces
//! ([`MAX_IMAGE_BYTES`]); what it buys is that the coordinate transform
//! (`00 R43`) travels in the same object as the pixels it belongs to, which is
//! the property `EncodedImage` exists to keep. When `msg_type` 4 is built, the
//! shape of the answer does not change: only where the bytes ride does.
//!
//! `crate::agent::mirror` owns the `00 R6` half, which is the part that would
//! be silently wrong rather than merely absent.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_perception::{
    EncodeOptions, ImageFormat, PerceptionError, Read, ReadKind, ReadRequest, StalePolicy,
    DEFAULT_LONG_EDGE, DEFAULT_MARGIN, HIGH_RES_LONG_EDGE,
};
use base64::Engine as _;
use limb_core::capability::{Capability, CapabilitySet};
use parking_lot::Mutex;
use remote_core::events::SessionEvent;
use remote_core::intent::{AgentIntent, IntentId, IntentKind, IntentRefused, IntentServed};
use serde_json::{json, Value};
use vnc_core::{ClientCommand, ProtocolKind, QualityPreset, Rect};

use crate::agent::mirror::{self, MirrorStatus, Perceive};
use crate::agent::wire;
use crate::agent::{AgentPlane, Attachment, PROTOCOL};
use crate::state::{MachineKey, SessionEntry};

/// The largest encoded image this surface will put in one reply.
///
/// The envelope caps a payload at [`wire::MAX_PAYLOAD`] and base64 costs a
/// third, so the image itself has to fit in three quarters of that with room
/// left for the observation around it. **Over this it REFUSES**, and names the
/// number: `00 R5`'s rule is that a perception layer never quietly gives back
/// something other than what was asked for, and silently dropping the long
/// edge would produce agents that click in the wrong place with nobody able to
/// reproduce it.
pub const MAX_IMAGE_BYTES: usize = (wire::MAX_PAYLOAD as usize / 4) * 3 - 64 * 1024;

/// Everything a request is answered from.
///
/// Deliberately not an `AppHandle`. The whole dispatch is testable without a
/// running Tauri app because of it, which is the only way the test that proves
/// an attach reaches a real [`SessionEntry`] can exist at all.
pub struct Ctx {
    pub sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    pub store: Arc<vnc_store::Store>,
    pub plane: Arc<AgentPlane>,
    /// Where an `agent://event` goes. A closure rather than an `AppHandle` for
    /// the reason above.
    pub emit: Arc<dyn Fn(Value) + Send + Sync>,
    /// How a `files.*` verb reaches the SFTP sidecar, which lives in
    /// `crate::commands::files` behind `State<'_, FilesState>` and therefore
    /// behind an `AppHandle` this struct will not hold.
    ///
    /// A closure for the same reason `emit` is one, and a FIELD rather than
    /// the process global [`install_opener`] uses, which is a deliberate
    /// difference: a global installed by one test is still installed for the
    /// next, so a test that wanted to prove a file verb behaves without a
    /// sidecar would be at the mercy of whichever test ran before it. Every
    /// [`Ctx`] carries its own.
    pub files: Filer,
}

/// One connection's own state.
///
/// `hello` is not optional and it is not idempotent: a connection that has not
/// said hello has no attachment id, so there is nothing to key an audit line
/// on and nothing to revoke, and `04 §2.3` says the connection is useless
/// until it has happened.
#[derive(Default)]
pub struct Peer {
    pub attachment_id: Option<String>,
    pub client: Option<String>,
    /// What this connection may do, fixed at `hello` and never widened.
    ///
    /// `00 R5` gates perception on capabilities and `R48e` splits it in two:
    /// pixels cost [`Capability::Capture`] and damage rectangles cost only
    /// [`Capability::View`], because damage leaks geometry and timing and no
    /// content at all. Deny by default, no hierarchy and no wildcard (D4), so
    /// holding `view` never implies `capture`.
    pub capabilities: CapabilitySet,
    /// This connection's row in the plane's client table, held for as long as
    /// the connection is.
    ///
    /// Dropping the `Peer` is what makes "agents connected" fall, so it falls
    /// however the connection ends and whatever transport it arrived on: a
    /// transport that builds a `Peer` and calls [`dispatch`] is counted with
    /// no further work.
    pub connection: Option<crate::agent::ConnectionGuard>,
}

/// A refusal, as JSON-RPC spells it.
pub struct RpcError {
    pub code: i64,
    pub message: String,
    /// A short machine readable tag beside the sentence, so an agent can
    /// branch on `LEASE_REVOKED` without matching prose.
    pub tag: Option<&'static str>,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> RpcError {
        RpcError {
            code,
            message: message.into(),
            tag: None,
        }
    }

    fn tagged(tag: &'static str, message: impl Into<String>) -> RpcError {
        RpcError {
            // The application error band. JSON-RPC reserves -32768 to -32000
            // for the protocol itself and -32000 is the first of the
            // implementation defined ones.
            code: -32000,
            message: message.into(),
            tag: Some(tag),
        }
    }

    /// `04 §2.7` rule 2: an unknown method is `-32601`, so a client probes for
    /// a method by calling it.
    fn unknown_method(method: &str) -> RpcError {
        RpcError::new(
            -32601,
            format!("this build of the dvvp.v1 plane has no method `{method}`"),
        )
    }

    fn bad_params(message: impl Into<String>) -> RpcError {
        RpcError::new(-32602, message)
    }

    pub fn to_json(&self) -> Value {
        let mut error = json!({ "code": self.code, "message": self.message });
        if let Some(tag) = self.tag {
            error["data"] = json!({ "code": tag });
        }
        error
    }
}

/// Answer one request.
///
/// # Errors
///
/// An [`RpcError`] naming what the caller can do about it. Never a silent
/// success: `00 R7` applies to this surface as much as to an intent.
pub async fn dispatch(
    ctx: &Ctx,
    peer: &mut Peer,
    method: &str,
    params: &Value,
) -> Result<Value, RpcError> {
    if method != "hello" && peer.attachment_id.is_none() {
        return Err(RpcError::new(
            -32600,
            "say hello first: a connection with no attachment id has nothing to key an audit line on and nothing to revoke (04 §2.3)",
        ));
    }
    match method {
        "hello" => hello(ctx, peer, params),
        "hosts.list" => hosts_list(ctx).await,
        "limb.list" => Ok(json!({ "limbs": limb_records(ctx) })),
        "limb.open" => limb_open(ctx, peer, params).await,
        "limb.attach" => limb_attach(ctx, peer, params),
        "limb.detach" => limb_detach(ctx, peer, params),
        "limb.status" => limb_status(ctx, peer, params),
        "limb.command" => limb_command(ctx, peer, params),
        // `00 R28`, `00 R51b`. An intent the driver serves natively gets a
        // method of its own rather than an arm in `limb.command`, because the
        // answer is the reply: a `{ "delivered": true }` for a command
        // somebody is blocked on is a silence with a success on it.
        "limb.exec" => limb_exec(ctx, peer, params).await,
        // The SFTP sidecar (`PRD/08`), one verb per operation for the same
        // reason `limb.exec` has one: the answer to "list that directory" is
        // the listing, and a `{ "delivered": true }` for a call somebody is
        // blocked on is a silence with a success on it. The sidecar is
        // connected on first use rather than by a verb of its own, so an agent
        // that wants a file asks for the file (see [`FileAsk`]).
        "files.home" => files_home(ctx, peer, params).await,
        "files.list" => files_list(ctx, peer, params).await,
        "files.get" => files_get(ctx, peer, params).await,
        "files.put" => files_put(ctx, peer, params).await,
        "files.mkdir" => files_mkdir(ctx, peer, params).await,
        "files.remove" => files_remove(ctx, peer, params).await,
        "files.rename" => files_rename(ctx, peer, params).await,
        "control.report" => control_report(ctx, peer, params),
        // The perception pair, split the way `00 R5` splits it: pixels and
        // rectangles are two different powers and the weaker one does not
        // imply the stronger.
        "screen.read" => screen_read(ctx, peer, params),
        "screen.damage" => screen_damage(ctx, peer, params),
        other => Err(RpcError::unknown_method(other)),
    }
}

/// The capabilities this socket will honour at all.
///
/// Deny by default, no hierarchy and no wildcard (D4). `scancode` and `admin`
/// are absent because nothing here implements them.
///
/// The file pair is here and it is split, which is the point of it rather than
/// a formality. `files.read` lists and downloads; `files.write` uploads,
/// renames, removes and makes directories. Neither implies the other and
/// `control` implies neither, because the SFTP sidecar reaches somebody's disk
/// over a second connection that leaves no mark on the screen a person is
/// watching. The verbs are `files.*` and they connect the sidecar on first
/// use, so an agent that holds neither is refused by [`require`] before
/// anything dials SSH.
///
/// `exec` is here and its presence is the point of `00 R19`'s treatment of it
/// rather than a hole in it. It stays in
/// [`Capability::NEVER_BUNDLED`](limb_core::capability::Capability::NEVER_BUNDLED),
/// so no role bundle expands to it and the only way to hold it is a grant that
/// names the string, which is BrowserGlass's treatment of `evaluate` kept for
/// the same reason: a capability nobody can ever hold is a capability nobody
/// reviews. What changed is that it now reaches something. `crates/ssh-core`
/// opens a second channel per RFC 4254 §6.5 and reads `exit-status` and
/// `exit-signal` per §6.10, and [`limb_exec`] carries that answer back as the
/// reply to the request that started it.
///
/// `open` is here for the same shape of reason: [`limb_open`] asks the
/// application to open a machine the way a person's click does, so the
/// capability is no longer naming something that does not exist.
const GRANTED: &[Capability] = &[
    Capability::View,
    Capability::Capture,
    Capability::Control,
    Capability::Open,
    Capability::Close,
    Capability::HostsRead,
    Capability::ClipboardRead,
    Capability::ClipboardWrite,
    Capability::TerminalRead,
    Capability::TerminalWrite,
    Capability::FilesRead,
    Capability::FilesWrite,
    Capability::Exec,
];

/// May this connection do that?
///
/// # Errors
///
/// An [`RpcError`] tagged `MISSING_CAPABILITY`, naming what is missing and
/// saying plainly that the weaker capability does not imply the stronger, so
/// an agent holding `view` does not spend a turn guessing that `capture` might
/// work if it asks differently.
fn require(peer: &Peer, needed: Capability) -> Result<(), RpcError> {
    if peer.capabilities.allows(needed) {
        return Ok(());
    }
    Err(RpcError::tagged(
        "MISSING_CAPABILITY",
        format!(
            "this connection does not hold `{}`, which it asked not to hold in hello. {}",
            needed.as_str(),
            separate_because(needed),
        ),
    ))
}

/// Why the capability that is missing is a capability of its own.
///
/// One sentence per pair that an agent is likely to have assumed away, and the
/// perception pair as the default because it is the one most callers meet
/// first. It is not decoration: an agent told only "no" spends its next turn
/// asking the same thing a slightly different way, and an agent told which
/// authority it is short of tells the USER which one to add to the grant.
fn separate_because(needed: Capability) -> &'static str {
    match needed {
        Capability::FilesRead => {
            "files.write does not imply files.read. Writing puts something known onto a machine; reading takes a copy of whatever happens to be on somebody's disk, which is an exfiltration path that needs no screen and leaves no mark on one"
        }
        Capability::FilesWrite => {
            "files.read does not imply files.write, and neither does control. Reading a machine's disk is observation; writing to it leaves something behind that is still there tomorrow, and holding the keyboard is not authority over the filesystem"
        }
        _ => {
            "view does not imply capture: damage rectangles leak geometry and timing, and a frame leaks whatever is on somebody's screen"
        }
    }
}

/// Establish, and learn the grant.
///
/// A `protocol` this build does not know is a HARD ERROR and never a
/// downgrade, for the same reason `connect_session` refuses to fall back to
/// VNC when a profile names a protocol it does not know: falling back dials
/// something nobody asked for.
fn hello(ctx: &Ctx, peer: &mut Peer, params: &Value) -> Result<Value, RpcError> {
    let asked = params
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if asked != PROTOCOL {
        return Err(RpcError::new(
            -32600,
            format!(
                "this plane speaks {PROTOCOL} and the client asked for `{asked}`; the protocol string is a hard gate with no negotiation and no shim (04 §2.7)"
            ),
        ));
    }
    let client = params
        .get("client")
        .and_then(|c| c.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unnamed")
        .to_string();
    let attachment_id = ctx.plane.mint_attachment_id();
    peer.attachment_id = Some(attachment_id.clone());
    peer.client = Some(client.clone());
    // One row per CONNECTION, and only the first hello opens it: a client that
    // says hello twice is still one agent, and re-registering would count it
    // twice until it hung up.
    if peer.connection.is_none() {
        peer.connection = Some(ctx.plane.client_connected(&client));
    }
    // A client may ask for LESS and never for more. Intersecting rather than
    // replacing is the whole of it: an unrecognised name narrows nothing and
    // grants nothing, so a newer client naming a capability this build has
    // never heard of gets the rest of its set rather than a refusal.
    peer.capabilities = match params.get("capabilities").and_then(Value::as_array) {
        Some(asked) => {
            let asked = CapabilitySet::of(
                &asked
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(Capability::parse)
                    .collect::<Vec<_>>(),
            );
            CapabilitySet::of(GRANTED).intersect(asked)
        }
        None => CapabilitySet::of(GRANTED),
    };
    Ok(json!({
        "protocol": PROTOCOL,
        "server": { "name": "DeskVNCViewer", "version": env!("CARGO_PKG_VERSION") },
        "attachmentId": attachment_id,
        // Exactly what this connection may do, deny by default, no hierarchy
        // and no wildcard (D4). `capture` is here because a mirror is attached
        // on request and `screen.read` answers from it (00 R5, 00 R6,
        // crate::agent::mirror). `open` and `exec` are here because
        // `limb.open` and `limb.exec` reach real work now, and the file pair
        // is here because the `files.*` verbs reach the SFTP sidecar; a client
        // that does not want any of them asks for less in `capabilities` and
        // gets less.
        "capabilities": peer.capabilities.iter().map(Capability::as_str).collect::<Vec<_>>(),
        // What this build IMPLEMENTS, so a client can tell "not granted" from
        // "not built".
        "protocols": ["vnc", "rdp", "ssh"],
        "client": client,
    }))
}

/// Saved machines. **Never a secret.**
///
/// There is no password field and there never will be. What an agent gets is
/// `credentialStored`, a boolean, because an agent needs to know whether a
/// connection will pause for a person and nothing more.
async fn hosts_list(ctx: &Ctx) -> Result<Value, RpcError> {
    let store = ctx.store.clone();
    // Every storage call is synchronous SQLite, so it hops off the socket task
    // exactly as every Tauri command does.
    let hosts = tokio::task::spawn_blocking(move || store.list_hosts())
        .await
        .map_err(|e| RpcError::new(-32603, format!("the host library lookup panicked: {e}")))?
        .map_err(|e| RpcError::new(-32603, format!("the host library could not be read: {e}")))?;
    let saved: std::collections::HashSet<String> = hosts
        .iter()
        .map(|host| vnc_store::normalize_address(&host.address))
        .collect();
    let mut out: Vec<Value> = hosts
        .into_iter()
        .map(|host| {
            json!({
                "hostId": host.id,
                "label": host.friendly_name,
                "address": host.address,
                "port": host.port,
                "protocol": host.protocol,
                "credentialStored": host.has_password,
                "discovered": false,
            })
        })
        .collect();
    // Every machine that is open but not saved, which is `04 §2.4`'s
    // `hosts.discovered` doing the work it is for. It is not cosmetic: the
    // grant an attachment runs under is scoped to the hosts this list names,
    // so a quick connect the person is looking at right now would otherwise be
    // a live session no agent is allowed to touch, refused for a reason
    // nobody wrote down.
    {
        let sessions = ctx.sessions.lock();
        for (id, entry) in sessions.iter() {
            if !entry.is_live() || saved.contains(&vnc_store::normalize_address(&entry.address)) {
                continue;
            }
            out.push(json!({
                "hostId": id,
                "label": entry.address,
                "address": entry.address,
                "port": entry.port,
                "protocol": entry.protocol(),
                // False, and it has to be: an ad-hoc session's password was
                // typed and never stored, so an agent predicting a pause from
                // this field would predict the wrong one.
                "credentialStored": false,
                "discovered": true,
            }));
        }
    }
    Ok(json!({ "hosts": out }))
}

/// Every live session, with the slot each one sits at.
pub fn limb_records(ctx: &Ctx) -> Vec<Value> {
    let sessions = ctx.sessions.lock();
    let attached = ctx.plane.attached_ids();
    let mut out = Vec::new();
    for (id, entry) in sessions.iter() {
        if !entry.is_live() {
            continue;
        }
        let slot = slot_of(&sessions, id, &entry.machine_key());
        out.push(record(id, entry, slot, attached.get(id).cloned()));
    }
    // Id order, so two calls in a row read the same way and a diff of two
    // `dvv limbs` runs is a diff of what changed.
    out.sort_by(|a, b| a["sessionId"].as_str().cmp(&b["sessionId"].as_str()));
    out
}

fn record(id: &str, entry: &SessionEntry, slot: u16, attachment: Option<String>) -> Value {
    let facts = entry.facts.lock();
    json!({
        "sessionId": id,
        "protocol": entry.protocol(),
        "profileId": entry.profile_id,
        "address": entry.address,
        "port": entry.port,
        "slot": slot,
        "state": facts.state,
        "size": facts.size.map(|(w, h)| json!({ "width": w, "height": h })),
        "attachmentId": attachment,
        "machine": machine_json(&entry.machine_key()),
    })
}

/// The machine key, spelled so the far side can rebuild it exactly.
///
/// Sent rather than left to be inferred from `address` and `port`, and that is
/// the point: normalisation belongs to `vnc_store::normalize_address` and
/// `limb_core::identity::MachineKey::endpoint` takes an address the caller has
/// ALREADY normalised, saying in its own doc comment that an un-normalised one
/// produces a different limb id for the same machine. The shell is the side
/// that holds the rule, so the shell applies it and the client copies the
/// answer, and there is no second implementation to drift.
fn machine_json(key: &MachineKey) -> Value {
    match key {
        MachineKey::Profile(id) => json!({ "kind": "profile", "id": id }),
        MachineKey::Endpoint {
            protocol,
            address,
            port,
        } => json!({
            "kind": "endpoint",
            "protocol": protocol,
            "address": address,
            "port": port,
        }),
    }
}

/// Live sessions against one machine, oldest first.
///
/// The tie break on the id matters: `started_at` is an `Instant` and two
/// sessions opened in the same tick would otherwise order differently on two
/// calls, which would move a slot under an agent that had already been told
/// one. Same rule, same reason, as `find_live_session`'s own `max_by_key`.
fn sessions_for_machine(
    sessions: &HashMap<String, SessionEntry>,
    key: &MachineKey,
) -> Vec<(String, Instant)> {
    let mut found: Vec<(String, Instant)> = sessions
        .iter()
        .filter(|(_, entry)| entry.is_live() && entry.machine_key() == *key)
        .map(|(id, entry)| (id.clone(), entry.started_at))
        .collect();
    found.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    found
}

fn slot_of(sessions: &HashMap<String, SessionEntry>, id: &str, key: &MachineKey) -> u16 {
    sessions_for_machine(sessions, key)
        .iter()
        .position(|(found, _)| found == id)
        .unwrap_or(0) as u16
}

/// Which machine a call names, as the shell already understands the word.
///
/// A `hostId` resolves through the store, which is what makes a saved machine
/// keep its identity when its address moves. An `address` needs a `protocol`,
/// and a value this build does not know is a hard error rather than a fallback
/// to VNC.
fn machine_from(ctx: &Ctx, params: &Value) -> Result<(MachineKey, String), RpcError> {
    if let Some(host_id) = params.get("hostId").and_then(Value::as_str) {
        if params.get("protocol").is_some() {
            return Err(RpcError::bad_params(
                "protocol is refused beside hostId: with a saved machine the protocol is read from the machine, and overriding it would dial the wrong protocol at an endpoint somebody configured for something else",
            ));
        }
        let profile = ctx
            .store
            .get_host(host_id)
            .map_err(|e| RpcError::new(-32603, format!("the host library could not be read: {e}")))?
            .ok_or_else(|| {
                RpcError::tagged(
                    "NO_SUCH_MACHINE",
                    format!("no saved machine is called {host_id}; call hosts.list for the ids"),
                )
            })?;
        let kind = ProtocolKind::parse(&profile.protocol).ok_or_else(|| {
            RpcError::tagged(
                "NO_SUCH_MACHINE",
                format!(
                    "{host_id} is saved as protocol `{}`, which this build does not speak",
                    profile.protocol
                ),
            )
        })?;
        return Ok((
            MachineKey::new(kind, Some(host_id), &profile.address, profile.port),
            profile.address,
        ));
    }
    let address = params
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RpcError::bad_params("this call needs a hostId from hosts.list, or an address")
        })?;
    let protocol = params
        .get("protocol")
        .and_then(Value::as_str)
        .and_then(ProtocolKind::parse)
        .ok_or_else(|| {
            RpcError::bad_params(
                "protocol is required with address, and a value this build does not know is a hard error rather than a fallback to VNC",
            )
        })?;
    let port = params
        .get("port")
        .and_then(Value::as_u64)
        .map(|p| p as u16)
        .unwrap_or_else(|| protocol.default_port());
    Ok((
        MachineKey::new(protocol, None, address, port),
        vnc_store::normalize_address(address),
    ))
}

/// Bring one live session under an attachment.
fn limb_attach(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let attachment_id = peer.attachment_id.clone().unwrap_or_default();
    let (key, address) = machine_from(ctx, params)?;
    let slot = params.get("slot").and_then(Value::as_u64).unwrap_or(0) as u16;

    let (session_id, value) = {
        let sessions = ctx.sessions.lock();
        let candidates = sessions_for_machine(&sessions, &key);
        let (session_id, _) = candidates.get(slot as usize).cloned().ok_or_else(|| {
            RpcError::tagged(
                "LIMB_GONE",
                format!(
                    "{address} has {} live session(s) and slot {slot} is not one of them. limb.attach only attaches to sessions DeskVNCViewer already has open: call limb.open to ask the application to open this machine the way a person's click does, wait for limb.status to report it connected, then attach. A slot above 0 needs that many sessions against the machine already",
                    candidates.len()
                ),
            )
        })?;
        let entry = sessions.get(&session_id).ok_or_else(|| {
            RpcError::tagged(
                "LIMB_GONE",
                "that session ended while this call was running",
            )
        })?;
        let value = record(&session_id, entry, slot, Some(attachment_id.clone()));
        (session_id, value)
    };

    // The mirror, before the attachment is recorded: a mirror the budget
    // refuses must not leave a half attached limb behind, and an attachment
    // recorded first would.
    let want = Perceive::parse(params.get("perceive"));
    let perception = perceive(ctx, peer, &session_id, want)?;

    ctx.plane.attach(
        &session_id,
        Attachment {
            attachment_id: attachment_id.clone(),
            client: peer.client.clone().unwrap_or_default(),
            revoked: false,
            held: false,
            phase: "free".to_string(),
            holder_kind: None,
            holder_label: None,
            human_took_over: false,
            inflight: Vec::new(),
            // Nothing has been observed yet, and the attach reply carries no
            // pixels however `perceive` was set: the mirror is allocated here
            // and the refresh that fills it is still on the wire. So a fresh
            // attachment is fenced out of typing until it reads the screen,
            // which is the whole point.
            observed_content: None,
        },
    );
    (ctx.emit)(json!({
        "type": "attached",
        "sessionId": session_id,
        "attachmentId": attachment_id,
        "client": peer.client.clone().unwrap_or_default(),
    }));

    let mut out = value;
    out["perception"] = perception;
    Ok(out)
}

/// Attach a mirror if one was asked for, put the `03 §3.4` order on the
/// session's wire, and describe what the caller got.
///
/// This is the one place a person's live session is changed on an agent's
/// behalf, and it happens **only when a mirror is actually requested**. See
/// [`crate::agent::mirror`] for what somebody watching the pane sees while it
/// happens.
fn perceive(ctx: &Ctx, peer: &Peer, session_id: &str, want: Perceive) -> Result<Value, RpcError> {
    if want == Perceive::None {
        return Ok(json!({ "mirror": false, "frames": false }));
    }
    // The capability gate comes first, before a byte is allocated and before
    // anything is put on a person's session (`00 R5`, `R48e`).
    require(
        peer,
        match want {
            Perceive::Frames => Capability::Capture,
            _ => Capability::View,
        },
    )?;

    // Read what is needed off the registry and let go of it. The preset lookup
    // below is a synchronous SQLite read and the session registry lock is on
    // `send_input`'s path, so holding one across the other would put a disk
    // read between a person's pointer event and their session.
    let (kind, size, profile_id) = {
        let sessions = ctx.sessions.lock();
        let entry = sessions.get(session_id).ok_or(RpcError {
            code: -32000,
            message: "that session ended while this call was running".to_string(),
            tag: Some("LIMB_GONE"),
        })?;
        // Bound rather than inlined into the tuple: a temporary guard in the
        // tail expression outlives the block's own locals, so the facts lock
        // would still be held when `sessions` is dropped.
        let size = entry.facts.lock().size;
        (entry.protocol(), size, entry.profile_id.clone())
    };
    let restore = connected_preset(ctx, profile_id.as_deref());

    let attached = ctx
        .plane
        .mirrors
        .attach(session_id, want, kind, size, restore, crate::agent::now())
        .map_err(|refused| RpcError::tagged(refused.tag, refused.why))?;

    // `03 §3.4` on the wire, in order. `try_send` and not `send`: this
    // function is synchronous and a full queue means the session is alive and
    // behind, which is a reason to say so rather than to block the socket.
    let mut sent: Vec<&'static str> = Vec::new();
    for command in &attached.negotiate {
        let name = wire::command_name(command);
        if send_now(ctx, session_id, command.clone()).is_err() {
            // The mirror stays: the rectangles that do arrive still composite,
            // and the priming refusal is what tells the agent the picture is
            // not trustworthy yet. Reported rather than swallowed, because an
            // agent that never sees the refresh land needs to know the refresh
            // never went.
            tracing::warn!(
                session = %session_id,
                "the 03 §3.4 priming order could not be sent: {name}"
            );
            break;
        }
        sent.push(name);
    }

    let status = ctx.plane.mirrors.status(session_id);
    Ok(perception_json(&status, Some(&attached.restore), &sent))
}

/// What a caller is told about one session's pixels.
///
/// `frames` is the honest one and it is computed rather than promised: true
/// only once every tile has been painted at least once, which is after the
/// `Refresh` lands. Until then `priming` is true and `screen.read` refuses
/// with `PRIMING`, which [`PerceptionError::is_transient`] marks as worth
/// waiting for. A mirror that reported `frames: true` at the instant of attach
/// would be promising a picture of opaque black (`03 §9 A3`).
fn perception_json(
    status: &MirrorStatus,
    restore: Option<&QualityPreset>,
    negotiated: &[&'static str],
) -> Value {
    if !status.subscribed {
        return json!({ "mirror": false, "frames": false });
    }
    let mut out = json!({
        "mirror": status.mirror,
        "frames": status.mirror && status.primed,
        "priming": status.mirror && !status.primed,
        "size": { "width": status.width, "height": status.height },
        "bytes": status.bytes,
        "geometryGeneration": status.generation.get(),
        // The second counter, [`limb_core::fence::ContentFence`]. It moves
        // when something large repaints, and it is compared, never sent back:
        // see [`admit_typing`] for why the content fence takes no parameter
        // from the agent.
        "contentGeneration": status.content.get(),
        // Non zero on a session that was renegotiated means the renegotiation
        // did not take, and nothing else in this object would show it. Every
        // one of those rectangles poisoned its region (`00 R6`).
        "h264Rects": status.h264_rects,
    });
    if status.mirror && !status.primed {
        out["why"] = json!(
            "the mirror is allocated and the server has not painted it yet: a full refresh is on the wire, and until it lands every read refuses with PRIMING rather than handing back the opaque black the mirror was allocated with (03 §9 A3)"
        );
    }
    if !status.mirror {
        out["why"] = json!(
            "this session is subscribed to damage rectangles and has no framebuffer mirror, so screen.damage answers and screen.read does not: nothing is allocated on behalf of a client that only watches for change (03 §9 A5). Attach again with perceive: \"frames\" to pay for pixels"
        );
    }
    // `negotiated` is what THIS call put on the wire and `wouldNeed` is what a
    // mirror would cost if one were asked for. They are different claims and a
    // second attach on an already mirrored session makes neither: the order
    // went out on the first one, and sending it again would be a second
    // SetEncodings and a second full repaint for nothing.
    if !negotiated.is_empty() {
        out["negotiated"] = json!(negotiated);
    } else if !status.mirror {
        out["wouldNeed"] = json!(mirror::required_order());
    }
    if let Some(preset) = restore {
        out["restoreOnDetach"] = json!(wire::quality_name(*preset));
    }
    out
}

/// The preset a session CONNECTED with, which is what `limb.detach` restores.
///
/// Read from the saved profile rather than from the session, because the
/// session does not publish it: `SessionFacts` carries the lifecycle state and
/// the framebuffer size and nothing else. A quick connect has no profile and
/// gets `Auto`, which is `ConnectOptions`' own default. See
/// [`crate::agent::mirror`] for what this cannot know and why it is named on
/// the wire rather than left implicit.
fn connected_preset(ctx: &Ctx, profile_id: Option<&str>) -> QualityPreset {
    let Some(profile_id) = profile_id else {
        return QualityPreset::Auto;
    };
    ctx.store
        .get_host(profile_id)
        .ok()
        .flatten()
        .and_then(|profile| wire::quality(&profile.quality_pref).ok())
        .unwrap_or(QualityPreset::Auto)
}

/// One command onto a live session's wire, right now.
fn send_now(ctx: &Ctx, session_id: &str, command: ClientCommand) -> Result<(), RpcError> {
    let handle = {
        let sessions = ctx.sessions.lock();
        sessions
            .get(session_id)
            .filter(|entry| entry.is_live())
            .map(|entry| entry.handle.clone())
            .ok_or_else(|| {
                RpcError::tagged(
                    "LIMB_GONE",
                    format!("no live session is registered as {session_id}"),
                )
            })?
    };
    handle.try_send(command).map_err(|e| {
        RpcError::tagged(
            "BACKPRESSURE",
            format!("{session_id} did not take that command: {e}"),
        )
    })
}

fn limb_detach(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    ctx.plane.detach(&session_id);
    // The person gets their session back. `AGENT_BRIEF` D2: the interactive
    // product does not regress because an agent looked once, so the preset the
    // mirror moved is moved back, and the refresh after it repaints whatever
    // the new encoding set changes.
    let restored = match ctx.plane.mirrors.detach(&session_id) {
        Some(preset) => {
            let name = wire::quality_name(preset);
            let ok = send_now(ctx, &session_id, ClientCommand::SetQuality(preset)).is_ok()
                && send_now(ctx, &session_id, ClientCommand::Refresh).is_ok();
            if !ok {
                tracing::warn!(
                    session = %session_id,
                    "could not put the quality preset back to {name}; the session may be gone"
                );
            }
            json!(name)
        }
        None => Value::Null,
    };
    (ctx.emit)(json!({
        "type": "detached",
        "sessionId": session_id,
        "attachmentId": peer.attachment_id,
    }));
    // Detaching something that is already gone is an ordinary success: a
    // cleanup path has to be safe to call twice.
    Ok(json!({ "detached": session_id, "qualityRestored": restored }))
}

fn limb_status(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let (mut out, has_screen) = {
        let sessions = ctx.sessions.lock();
        let entry = sessions
            .get(&session_id)
            .filter(|entry| entry.is_live())
            .ok_or_else(|| {
                RpcError::tagged(
                    "LIMB_GONE",
                    format!("no live session is registered as {session_id}; call limb.list"),
                )
            })?;
        let slot = slot_of(&sessions, &session_id, &entry.machine_key());
        let attached = ctx.plane.attached_ids().get(&session_id).cloned();
        let has_screen = entry.facts.lock().size.is_some();
        (record(&session_id, entry, slot, attached), has_screen)
    };
    // Carried here as well as on the attach reply, because `frames` goes from
    // false to true when the refresh lands and an agent needs somewhere cheap
    // to watch for that. This is rung 0 and costs nothing.
    out["perception"] = perception_json(&ctx.plane.mirrors.status(&session_id), None, &[]);
    // The content fence's answer, BEFORE the agent is refused by it.
    //
    // `04 §4.4`'s rule is that a code is what an agent branches on and the
    // sentence beside it is what an agent acts on, and this is the same pair
    // one call earlier. An adapter that reads this can decline to lower a
    // `Type` at all, so the agent gets a settlement it can read instead of a
    // batch of keystrokes the socket refuses one at a time. It is a report and
    // never the check: the fence itself is applied in `limb.command`, at the
    // last instant before the keystroke reaches the session, because a screen
    // can repaint between this reply and the next call.
    out["typing"] = typing_json(ctx, &session_id, peer, has_screen);
    Ok(out)
}

/// What `limb.status` says about whether text may be sent right now.
///
/// `allowed` is true on a session with no screen because there is no screen to
/// have changed: see [`types_into_focus`] and the terminal note in
/// [`limb_command`].
fn typing_json(ctx: &Ctx, session_id: &str, peer: &Peer, has_screen: bool) -> Value {
    if !has_screen {
        return json!({
            "allowed": true,
            "why": "this session reports no framebuffer, so it is a terminal: there is no screen to have changed under a keystroke and nothing to observe before sending one"
        });
    }
    let attachment_id = peer.attachment_id.clone().unwrap_or_default();
    match admit_typing(ctx, session_id, &attachment_id) {
        Ok(()) => json!({ "allowed": true }),
        Err(refused) => json!({
            "allowed": false,
            "code": refused.tag,
            "why": refused.message,
        }),
    }
}

/// Rungs 2 to 4: pixels.
///
/// The DEFAULT is rung 4, a crop around what changed, and that is `03 §4.5`
/// and `03 §5.2`: a 400x200 crop is 120 visual tokens against 2691 for an
/// unscaled 1080p frame, twenty two times cheaper and legible, because nothing
/// was downscaled. The full frame's job is orientation, once, at the start of
/// a task.
///
/// The crop is chosen from the rect LIST and never from `Rect::union`
/// (`00 R39b`): a union is a bounding box, so two changes in opposite corners
/// union to the whole screen and an agent would re-read a 4K frame to find two
/// moved pixels. `agent_perception::plan_change_crop` is what does it.
fn screen_read(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let attachment_id = peer.attachment_id.clone().unwrap_or_default();
    ctx.plane.check_allowed(&session_id, &attachment_id)?;
    require(peer, Capability::Capture)?;

    let request = read_request(ctx, &session_id, params)?;
    let read = ctx
        .plane
        .mirrors
        .read(&session_id, &request, crate::agent::now())
        .map_err(perception_refusal)?;

    match read {
        // **Not an error.** "Nothing changed" is the answer to "show me what
        // changed", and an agent that receives an error for it retries
        // immediately rather than waiting, which turns the cheapest rung into
        // a spin loop.
        Read::Unchanged { generation, at } => Ok(json!({
            "sessionId": session_id,
            "unchanged": true,
            "geometryGeneration": generation.get(),
            "capturedAt": at.0,
        })),
        Read::Frame(observation) => {
            // The agent has now LOOKED, so the content fence clears for this
            // attachment. Recorded on this arm and on no other, because this is
            // the only arm that hands back pixels: `Read::Unchanged` above says
            // nothing moved since this reader's cursor, which is a true and
            // useful answer and is not a picture, and `screen.damage` is a list
            // of rectangles that says something moved without ever saying what
            // it now reads. An attachment that could clear the fence with
            // either of those would be typing into a screen it had still not
            // seen, which is the whole failure.
            //
            // Read after the mirror answered rather than before, so the number
            // recorded is the one the pixels in this reply were composited at.
            // Recording the pre read value would credit the agent with an
            // observation of a screen that repainted while the read was being
            // encoded.
            ctx.plane.note_observed(
                &session_id,
                &attachment_id,
                ctx.plane.mirrors.status(&session_id).content,
            );
            if observation.image.bytes.len() > MAX_IMAGE_BYTES {
                return Err(RpcError::tagged(
                    "IMAGE_TOO_LARGE",
                    format!(
                        "that read encoded to {} bytes and this lane carries at most {MAX_IMAGE_BYTES}: nothing was sent and no smaller image was substituted (00 R5). Ask for a region, or a smaller longEdge",
                        observation.image.bytes.len()
                    ),
                ));
            }
            let mut described = serde_json::to_value(&*observation).map_err(|e| {
                RpcError::new(
                    -32603,
                    format!("the observation could not be described: {e}"),
                )
            })?;
            // The pixels ride INSIDE the object that describes them, beside
            // `image.space`, which is the whole point of `EncodedImage`:
            // `00 R43` says a scale factor that can be separated from its
            // image will be, and a coordinate transformed with the wrong scale
            // produces a click that lands somewhere plausible.
            described["image"]["base64"] =
                json!(base64::engine::general_purpose::STANDARD.encode(&observation.image.bytes));
            Ok(json!({
                "sessionId": session_id,
                "unchanged": false,
                "observation": described,
            }))
        }
    }
}

/// Rung 1: what changed, as a LIST.
///
/// Costs no framebuffer, which is why it is gated on [`Capability::View`] and
/// not on [`Capability::Capture`]: damage rectangles leak geometry and timing
/// and no content at all (`00 R5`, `R48e`).
fn screen_damage(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let attachment_id = peer.attachment_id.clone().unwrap_or_default();
    ctx.plane.check_allowed(&session_id, &attachment_id)?;
    require(peer, Capability::View)?;

    let (delta, bounds, generation) =
        ctx.plane.mirrors.take_damage(&session_id).ok_or_else(|| {
            RpcError::tagged(
                "NO_MIRROR",
                format!(
                    "nothing on {session_id} is subscribed to damage; attach again with perceive: \"damage\" or perceive: \"frames\""
                ),
            )
        })?;
    Ok(json!({
        "sessionId": session_id,
        // `00 R39b`. THE list, in the order the server sent them. The bounding
        // box is carried BESIDE it and never instead of it: sizing a read from
        // the box would re-read a whole 4K frame to find two moved pixels.
        "rects": delta.rects.iter().map(rect_json).collect::<Vec<_>>(),
        "bounds": rect_json(&delta.bounding_box()),
        "space": { "width": bounds.width, "height": bounds.height },
        "updates": delta.updates,
        // How many rectangles fell off the end of the log before this reader
        // got to them. Reported rather than swallowed: a reader told nothing
        // was dropped when everything was would conclude the screen was still.
        "dropped": delta.dropped,
        "geometryGeneration": generation.get(),
        // An empty list is NOT evidence the screen is still: a server whose
        // damage tracking cannot be trusted sends nothing either, which is why
        // `ClientCommand::SetAlwaysRefresh` exists.
        "quiet": delta.is_empty(),
    }))
}

fn rect_json(rect: &Rect) -> Value {
    json!({ "x": rect.x, "y": rect.y, "width": rect.width, "height": rect.height })
}

/// Build one [`ReadRequest`] from the wire.
///
/// The default kind is `change`, which is `03 §4`'s ordering made real: the
/// surface should make the cheap rungs the obvious ones, so the cheapest
/// useful rung is what a caller that names nothing gets.
fn read_request(ctx: &Ctx, session_id: &str, params: &Value) -> Result<ReadRequest, RpcError> {
    let status = ctx.plane.mirrors.status(session_id);
    let kind = params
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("change");
    let kind = match kind {
        "change" => ReadKind::Change {
            reader: ctx.plane.mirrors.reader(session_id).ok_or_else(|| {
                RpcError::tagged(
                    "NO_MIRROR",
                    format!("nothing on {session_id} is subscribed; attach again with perceive"),
                )
            })?,
            margin: params
                .get("margin")
                .and_then(Value::as_u64)
                .map(|m| m.min(u64::from(u16::MAX)) as u16)
                .unwrap_or(DEFAULT_MARGIN),
        },
        "frame" => ReadKind::Frame {
            long_edge: match (
                params.get("longEdge").and_then(Value::as_u64),
                params.get("scale").and_then(Value::as_f64),
            ) {
                // Capped at the high resolution tier's limit rather than
                // honoured without question. A long edge above it is an image
                // the model provider will resize, and `00 R43` (WA-11) is that
                // the scale factor then belongs to somebody else and cannot be
                // inverted.
                (Some(edge), _) => (edge as u32).clamp(1, HIGH_RES_LONG_EDGE),
                // A scale is relative to the framebuffer, and the shell is the
                // side that knows how big that is. Resolving it here rather
                // than on the client is what keeps a caller from holding a
                // second copy of a size that changes under it.
                (None, Some(scale)) => {
                    let edge = f64::from(status.width.max(status.height));
                    ((edge * scale).round().max(1.0) as u32).clamp(1, HIGH_RES_LONG_EDGE)
                }
                (None, None) => DEFAULT_LONG_EDGE,
            },
        },
        "region" => ReadKind::Region {
            rect: rect_from(params.get("rect"))?,
        },
        other => {
            return Err(RpcError::bad_params(format!(
                "`{other}` is not a read kind; they are change (the default, a crop around what moved), frame (the orientation shot) and region (native resolution, scale 1.0)"
            )))
        }
    };
    Ok(ReadRequest {
        kind,
        fence: params
            .get("generation")
            .and_then(Value::as_u64)
            .map(|g| generation_from(g, status.generation)),
        encode: EncodeOptions {
            format: match params.get("format").and_then(Value::as_str) {
                Some("jpeg") | Some("jpg") => ImageFormat::Jpeg,
                _ => ImageFormat::Png,
            },
            jpeg_quality: params
                .get("jpegQuality")
                .and_then(Value::as_u64)
                .map(|q| q.clamp(1, 100) as u8)
                .unwrap_or(agent_perception::DEFAULT_JPEG_QUALITY),
        },
        // Refuse is the default, because an agent that did not ask to be told
        // about staleness is an agent that will not check (`00 R6`).
        stale: match params.get("stale").and_then(Value::as_str) {
            Some("annotate") => StalePolicy::Annotate,
            _ => StalePolicy::Refuse,
        },
    })
}

/// A generation off the wire.
///
/// `GeometryGeneration` has no constructor from a `u32` on purpose: the
/// counter is minted by the fence that owns it and a public constructor would
/// let a caller invent one. Starting at `FIRST` and stepping is the only
/// honest way to name a value that arrived over a wire.
///
/// The step count is bounded by `current + 1` and the bound is not cosmetic:
/// without it a caller could send four billion and make this socket count to
/// it. Clamping loses nothing, because every generation above `current` is
/// equally not current, and `Mirror::read` compares for equality: an absurd
/// fence is refused with `GEOMETRY_CHANGED` either way.
fn generation_from(
    value: u64,
    current: remote_core::geometry::GeometryGeneration,
) -> remote_core::geometry::GeometryGeneration {
    let want = value.min(u64::from(current.get()).saturating_add(1)) as u32;
    let mut generation = remote_core::geometry::GeometryGeneration::FIRST;
    while generation.get() < want {
        let next = generation.next();
        if next == generation {
            break;
        }
        generation = next;
    }
    generation
}

fn rect_from(value: Option<&Value>) -> Result<Rect, RpcError> {
    let value = value.ok_or_else(|| {
        RpcError::bad_params("a region read needs a `rect` of { x, y, width, height }")
    })?;
    let field = |name: &str| -> Result<u16, RpcError> {
        value
            .get(name)
            .and_then(Value::as_u64)
            .filter(|n| *n <= u64::from(u16::MAX))
            .map(|n| n as u16)
            .ok_or_else(|| {
                RpcError::bad_params(format!(
                    "`rect.{name}` is required and must be a framebuffer coordinate from 0 to 65535"
                ))
            })
    };
    Ok(Rect::new(
        field("x")?,
        field("y")?,
        field("width")?,
        field("height")?,
    ))
}

/// A perception refusal, as this socket spells it.
///
/// The tag `agent-perception` already assigns is carried through unchanged, so
/// an agent branches on `PRIMING` against `STALE_REGION` without matching
/// prose, and `transient` is spelled out beside it because a model that cannot
/// tell a wait from a dead end will do one of the two forever.
fn perception_refusal(error: PerceptionError) -> RpcError {
    let transient = error.is_transient();
    RpcError {
        code: -32000,
        message: format!(
            "{error}{}",
            if transient {
                " (this one resolves on its own: wait and read again)"
            } else {
                ""
            }
        ),
        tag: Some(error.as_str()),
    }
}

/// Put one command on a live session's wire.
///
/// `try_send` rather than `send`, and the two failures are told apart rather
/// than flattened, which is `00 R49a`: full means the session is alive and
/// behind so the caller sheds and reports how much was lost, and closed means
/// the limb is finished so nothing is worth retrying.
fn limb_command(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let attachment_id = peer.attachment_id.clone().unwrap_or_default();
    ctx.plane.check_allowed(&session_id, &attachment_id)?;
    let command = params.get("command").ok_or_else(|| {
        RpcError::bad_params("limb.command needs a `command` object; see IPC_CONTRACT.md")
    })?;
    let command = wire::decode_command(command).map_err(RpcError::bad_params)?;
    let (handle, has_screen) = {
        let sessions = ctx.sessions.lock();
        let entry = sessions
            .get(&session_id)
            .filter(|entry| entry.is_live())
            .ok_or_else(|| {
                RpcError::tagged(
                    "LIMB_GONE",
                    format!("no live session is registered as {session_id}"),
                )
            })?;
        // A framebuffer size is what makes this a session with a screen. A
        // terminal never reports one (`SessionFacts::size`), which is exactly
        // the right test for the content fence below: a PTY has nothing to
        // observe, echoes what it is sent into a stream the agent reads back,
        // and fencing it would refuse every SSH session forever.
        let has_screen = entry.facts.lock().size.is_some();
        (entry.handle.clone(), has_screen)
    };

    // The content fence, and this is the last place it can be applied: below
    // here the command is on the session's own channel and the next thing that
    // touches it is the driver's input pipeline.
    if has_screen && types_into_focus(&command) {
        admit_typing(ctx, &session_id, &attachment_id)?;
    }

    match handle.try_send(command) {
        Ok(()) => Ok(json!({ "delivered": true })),
        Err(vnc_core::TrySendFailed::Full) => Err(RpcError::tagged(
            "BACKPRESSURE",
            format!("{session_id} is alive and its command queue is full; nothing was sent, so shed or wait and report what was lost rather than assuming it landed"),
        )),
        Err(vnc_core::TrySendFailed::Gone) => Err(RpcError::tagged(
            "LIMB_GONE",
            format!("{session_id} is finished; nothing was sent and nothing here is worth retrying"),
        )),
        // `TrySendFailed` is `#[non_exhaustive]`. A failure a later build adds
        // is reported as itself rather than mapped onto the nearest of the
        // two, because mapping it is how an agent gets told a link loss was
        // backpressure and retries into a machine that is gone.
        Err(other) => Err(RpcError::tagged(
            "SEND_FAILED",
            format!("{session_id} refused the command: {other}"),
        )),
    }
}

/// Does this command put a character into whatever currently has focus?
///
/// The reason this is a predicate over `ClientCommand` and not over
/// [`remote_core::intent::IntentKind::is_text_bearing`] is that by the time
/// something reaches this socket it is no longer an intent. `dvv` lowers a
/// `Type` of eleven characters into twenty two `Key` commands and a `Press` of
/// Ctrl+A into four, and the shell sees only the keystrokes. That turns out to
/// be the honest level to check at anyway: on a text editor holding a selection
/// the letter `a`, Enter, Delete and Ctrl+V destroy the document identically,
/// so a rule that fenced `Type` and waved `Press` through would be drawing a
/// line the remote machine does not have.
///
/// **Only the press.** A `Key` going UP is always let through, and that is not
/// an oversight. A release ends something that has already happened, and a
/// refused release leaves a modifier held down on somebody's desktop with
/// nothing that will ever lift it: every subsequent keystroke on that machine,
/// the person's included, arrives with Ctrl or Shift stuck on. Refusing the
/// press is what stops the keystroke; refusing the release only breaks the
/// machine. [`ClientCommand::ReleaseAllKeys`] passes for the same reason, and
/// it is the repair for a modifier stranded some other way.
///
/// [`ClientCommand::ClipboardText`] is not here either. It writes the remote
/// clipboard, which changes no document by itself; what pastes it is a Ctrl+V,
/// and that is a `Key` press and is fenced above.
fn types_into_focus(command: &ClientCommand) -> bool {
    matches!(command, ClientCommand::Key { down: true, .. })
}

/// May this attachment put text on this session's wire right now?
///
/// The plane's content fence (`limb_core::fence::ContentFence`), and the
/// asymmetry it exists to close. A `click` has carried a geometry generation
/// since `00 R10` and is refused when the screen it was computed against has
/// gone. A keystroke carried nothing and was checked against nothing, because
/// [`IntentKind::is_grounded`](remote_core::intent::IntentKind::is_grounded) is
/// false for `Type`, `Press` and `Scancode`: they aim at no coordinate, so
/// there was nothing for a resize to invalidate and the question stopped there.
///
/// It should not have. A keystroke aims at whatever has focus, and focus moves
/// when a window appears. An agent ran `Start-Process notepad` on a remote
/// desktop and typed into it without looking. Notepad had come up holding the
/// person's own file with all 2,378,798 characters selected; the next keystroke
/// would have replaced it. A human caught it by looking at a screenshot before
/// the typing step ran. Nothing in the plane would have.
///
/// So: the mirror counts material repaints, an observation that returned pixels
/// records the count it was read at, and text is refused while the two differ.
/// Both numbers travel in the refusal, the way
/// [`GeometryRejected`](limb_core::fence::GeometryRejected) carries both of its
/// own, because a refusal an agent cannot check against what it thought it knew
/// is a refusal it will retry blind.
///
/// **There is no override and that is deliberate.** A `"blind": true` was
/// considered for the case an agent can honestly make, typing a password into a
/// prompt it triggered itself. It is not built, for three reasons. The prompt
/// an agent triggered is precisely the large repaint that trips this, so the
/// override would be off in the one case it was argued for. The geometry fence
/// has no override, and a plane where one fence is negotiable and the other is
/// not teaches that fences are negotiable. And what the fence costs is a single
/// `screen.read`, so an escape hatch would be one token cheaper than complying,
/// which means a model that meets this refusal once sets the flag for ever
/// after and the fence is gone. If an override is ever added it belongs in the
/// GRANT, decided by the person approving the agent, not in the call.
///
/// # Errors
///
/// An [`RpcError`] tagged `SCREEN_CHANGED`, and nothing was sent.
fn admit_typing(ctx: &Ctx, session_id: &str, attachment_id: &str) -> Result<(), RpcError> {
    let observed = ctx.plane.observed_content(session_id, attachment_id);
    ctx.plane
        .mirrors
        .admit_typing(session_id, observed)
        .map_err(|rejected| {
            // Logged where the refusal is decided rather than left to whatever
            // reads the reply. A person asking why an agent stopped typing at
            // their machine gets both numbers and the session id from the
            // application's own log, without the agent's transcript.
            tracing::info!(
                session = %session_id,
                attachment = %attachment_id,
                "typing refused: {rejected}"
            );
            RpcError::tagged("SCREEN_CHANGED", rejected.to_string())
        })
}

/// One native intent this socket put on a session's wire and is waiting to
/// hear back about.
///
/// Keyed on the SESSION and the id together. The id alone would be wrong for
/// the reason `agent-plane` writes on its own answer table: an intent id is
/// dense and per limb, so two sessions each have an intent 1, and matching on
/// the number alone would hand one machine's answer to the other machine's
/// caller.
struct Pending {
    session_id: String,
    id: IntentId,
    answer: tokio::sync::oneshot::Sender<Answer>,
}

/// A driver's two ways of ending an intent (`00 R28`, `00 R51b`).
enum Answer {
    Served(Box<IntentServed>),
    Refused(IntentRefused),
}

/// Every exec this socket is blocked on, across every connection.
///
/// A process global rather than a field on [`Ctx`], because the event stream
/// that feeds it is owned by `forward_events` in
/// `src-tauri/src/commands/session.rs`, which holds no `Ctx` and should not
/// have to: what it has is a session id and an event, which is exactly what
/// [`note_agent_event`] takes.
fn pending() -> &'static Mutex<Vec<Pending>> {
    static PENDING: std::sync::OnceLock<Mutex<Vec<Pending>>> = std::sync::OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(Vec::new()))
}

/// The intent ids this socket mints.
///
/// Minted HERE and never taken from the request, which matters: the caller's
/// own id is its plane's, two connections would collide on it, and an id a
/// peer chooses is an id a peer can use to claim somebody else's answer. The
/// caller's id never goes on the wire at all; the reply is the answer to the
/// request, so there is nothing to correlate on this socket.
static NEXT_INTENT: AtomicU64 = AtomicU64::new(1);

/// The slack this socket adds to a command's own timeout before it stops
/// waiting.
///
/// The driver owns the deadline: `CommandSpec::timeout` is what `ssh-core`
/// runs the command under, and it answers with `Unanswered::Deadline` and
/// whatever output arrived when it passes. So this wait exists only to cover
/// the round trip and the driver's own wind down, and stopping first would
/// turn the driver's honest partial answer into this file's timeout.
const EXEC_SLACK: Duration = Duration::from_secs(5);

/// Take one intent's answer slot before the command goes out.
///
/// **Before**, not after, and `agent-plane` learned this the same way: a
/// driver's command pump can refuse in the turn it receives the command, so
/// the refusal can be on the event stream before the send call has returned. A
/// refusal that arrives before anybody is listening is a refusal that is
/// dropped, and a dropped refusal is an agent waiting out a deadline for an
/// answer that already happened.
fn listen_for_answer(session_id: &str, id: IntentId) -> tokio::sync::oneshot::Receiver<Answer> {
    let (answer, listening) = tokio::sync::oneshot::channel();
    pending().lock().push(Pending {
        session_id: session_id.to_string(),
        id,
        answer,
    });
    listening
}

/// Give up one intent's answer slot, however its request ended.
fn forget_answer(session_id: &str, id: IntentId) {
    pending()
        .lock()
        .retain(|p| !(p.id == id && p.session_id == session_id));
}

/// **The seam.** One session event, offered to whatever exec is waiting for it.
///
/// `00 R28` and `00 R51b` give a driver two ways to end an intent and both of
/// them travel on the session's own event stream, which this application reads
/// in exactly one place: `forward_events` in
/// `src-tauri/src/commands/session.rs`. The plane deliberately does not
/// subscribe to that stream itself, for the reason `AttachedLimb::note_state`
/// gives: the shell owns it, and a second subscriber would be a second opinion
/// about what a session is doing. So the owner reports, and this is where the
/// report lands.
///
/// Returns whether anything was waiting. A `false` on an `AgentServed` is
/// worth logging and the reason is not symmetric with a refusal: it means real
/// work ran on somebody's machine and the agent that asked for it has already
/// been told the intent timed out.
///
/// # The one line this file cannot write for itself
///
/// `forward_events` has to call this, in the `match &event` beside the two
/// facts it already keeps for the plane:
///
/// ```ignore
/// SessionEvent::AgentServed(_) | SessionEvent::AgentRefused(_) => {
///     crate::agent::server::note_agent_event(&session_id, &event);
/// }
/// ```
///
/// Until it does, `limb.exec` puts the intent on the wire, the driver serves
/// it, and the answer is dropped where `event_json` returns `None` for it, so
/// every exec reports the timeout this function exists to prevent. The
/// `allow` below is what stops that being a compiler warning on every build
/// rather than a fact somebody reads once.
#[allow(dead_code)]
pub fn note_agent_event(session_id: &str, event: &SessionEvent) -> bool {
    let (id, answer) = match event {
        SessionEvent::AgentServed(served) => (served.id, Answer::Served(Box::new(served.clone()))),
        SessionEvent::AgentRefused(refused) => (refused.id, Answer::Refused(refused.clone())),
        _ => return false,
    };
    let waiting = {
        let mut pending = pending().lock();
        pending
            .iter()
            .position(|p| p.id == id && p.session_id == session_id)
            .map(|at| pending.swap_remove(at))
    };
    match waiting {
        Some(slot) => slot.answer.send(answer).is_ok(),
        None => {
            // Named rather than swallowed. An answer nobody was waiting for is
            // the one thing this whole path exists to prevent, so it leaves a
            // line even though there is nowhere left to deliver it.
            tracing::warn!(
                session = %session_id,
                intent = %id,
                "a driver answered an intent no dvvp.v1 request was still waiting for"
            );
            false
        }
    }
}

/// Run one command on a limb, and answer with what running it produced.
///
/// `00 R51b` end to end over this socket. The intent goes out as
/// `ClientCommand::Agent`, the driver serves it or refuses it, and the answer
/// comes back as the REPLY to this request rather than as a push, which is the
/// shape [`crate::agent::wire`] describes: one blocking socket, one request,
/// one reply, nothing that can interleave.
///
/// Three outcomes and each is told apart from the other two, because `05 §3`'s
/// rule is that the plane never invents a status:
///
/// * The driver served it. The exit code is the far side's own, whatever it
///   is: **a non zero exit is a served answer and not a failure to run**, and
///   this returns it as a result rather than as an error for exactly that
///   reason (`06 §5.4`).
/// * The driver refused it. An `INTENT_REFUSED` error carrying the driver's
///   own sentence, because it is the only party that knows why. Nothing went
///   on the wire, which is what `IntentRefused` promises.
/// * Nothing came back in time. A TIMEOUT, reported as one, with the output
///   that arrived beside it (`00 R7`).
///
/// # Errors
///
/// An [`RpcError`] when the connection may not do this, when the request is
/// malformed, or when the driver refused.
async fn limb_exec(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let attachment_id = peer.attachment_id.clone().unwrap_or_default();
    ctx.plane.check_allowed(&session_id, &attachment_id)?;
    // The capability gate first, before the request is even parsed. `exec` is
    // in no role bundle (`00 R19`), so a connection holding it holds it
    // because a grant named the string.
    require(peer, Capability::Exec)?;
    let spec = wire::decode_exec(params).map_err(RpcError::bad_params)?;

    let wait = spec.timeout.saturating_add(EXEC_SLACK);
    let id = IntentId(NEXT_INTENT.fetch_add(1, Ordering::Relaxed));
    let intent = AgentIntent {
        id,
        // The attachment, so an audit line names who ran it. This is the
        // shell's own identifier for the connection and not anything the peer
        // chose.
        grant: attachment_id.as_str().into(),
        // The driver's deadline is the command's own, which is what makes the
        // driver, and not this file, the party that decides a run is over.
        deadline: Some(spec.timeout),
        // `exec` aims at no coordinate, so there is nothing to fence
        // (`00 R10`, `IntentKind::is_grounded`).
        fence: None,
        kind: IntentKind::Exec { spec },
    };

    let listening = listen_for_answer(&session_id, id);
    if let Err(refused) = send_now(ctx, &session_id, ClientCommand::Agent(intent)) {
        // Nothing is on the wire, so nothing will answer. The slot goes back
        // rather than being left to time out five minutes later holding a
        // sender nobody will use.
        forget_answer(&session_id, id);
        return Err(refused);
    }

    let started = Instant::now();
    match tokio::time::timeout(wait, listening).await {
        Ok(Ok(Answer::Served(served))) => {
            let mut out = wire::served_json(&served);
            out["sessionId"] = json!(session_id);
            Ok(out)
        }
        Ok(Ok(Answer::Refused(refused))) => Err(RpcError::tagged(
            "INTENT_REFUSED",
            format!(
                "{} refused that command and nothing went on the wire: {}",
                session_id, refused.reason
            ),
        )),
        // The sender was dropped without an answer, which means the slot was
        // taken by something other than this call. There is no such path
        // today; it is answered as a timeout rather than as a success because
        // that is the claim that is true whatever took it.
        Ok(Err(_)) | Err(_) => {
            forget_answer(&session_id, id);
            let mut out = wire::timed_out_json(started.elapsed());
            out["sessionId"] = json!(session_id);
            out["why"] = json!(
                "no answer reached this socket inside the command's own timeout plus the round trip. The command may still be running on the far side: this is a timeout and not a failure, and nothing here invented an exit status for it (00 R7, 05 §3)"
            );
            Ok(out)
        }
    }
}

/// What the application is asked for when an agent wants a machine opened.
///
/// Deliberately the same three things a person's click carries and nothing
/// else. There is no credential field here and there will not be: the shell
/// resolves the secret from the keychain inside `connect_session`, which is
/// what makes this path identical to a click rather than a second, weaker one
/// (`00 R19`, `09 §4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAsk {
    /// A saved machine's id, when the agent named one.
    pub host_id: Option<String>,
    pub address: String,
    pub port: u16,
    /// The protocol as `ProtocolKind::as_str` spells it.
    pub protocol: String,
}

/// What the application did about an [`OpenAsk`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub session_id: String,
    /// True when a window that was already open was raised instead of a second
    /// connection being made. `00 B7`'s window rule, reported rather than
    /// hidden, because "you got the session somebody was already using" is a
    /// fact an agent should be told.
    pub reused: bool,
}

/// How this socket asks the application to open a machine.
///
/// A callback rather than an `AppHandle` on [`Ctx`], for the reason [`Ctx`]
/// already gives: nothing in this module names a Tauri type, which is what
/// makes the whole dispatch testable with no running application. The
/// installer is the one place that does.
///
/// It takes the ask and a channel rather than returning a future, because
/// `open_session_window` is an async Tauri command and the natural
/// implementation is to spawn it on the application's runtime and send the
/// outcome back.
pub type Opener =
    Arc<dyn Fn(OpenAsk, tokio::sync::oneshot::Sender<Result<Opened, String>>) + Send + Sync>;

fn opener() -> &'static Mutex<Option<Opener>> {
    static OPENER: std::sync::OnceLock<Mutex<Option<Opener>>> = std::sync::OnceLock::new();
    OPENER.get_or_init(|| Mutex::new(None))
}

/// Install the one thing this module cannot build for itself.
///
/// Called once by the layer that holds the `AppHandle`, which is
/// `crate::commands::agent`. Until it is, [`limb_open`] refuses and names this
/// function, which is `04 §4.1`'s habit: a surface that says "not implemented"
/// with the reason stops an agent asking, and one that fails vaguely makes it
/// retry. The `allow` is [`note_agent_event`]'s: unwired is a fact to read
/// once, not a warning on every build.
#[allow(dead_code)]
pub fn install_opener(open: Opener) {
    *opener().lock() = Some(open);
}

/// How long this socket waits for the session to REGISTER after a window is
/// asked for.
///
/// Not for it to connect. `open_session_window` creates the window and the
/// webview that appears calls `connect_session`, which is what puts a
/// [`SessionEntry`] in the registry, and that hop is the only thing this wait
/// covers. A machine still negotiating, still prompting a person for a
/// password, or still failing is a session that exists and is not connected,
/// and the reply says which.
const SPAWN_WINDOW: Duration = Duration::from_secs(15);

/// Open a machine, by asking the application to do what a click does.
///
/// The three rules in the module comment are checked here, in this order, and
/// the order is the point: **a host outside the list is refused before
/// anything connects**, and a credential is refused before that.
///
/// # Errors
///
/// An [`RpcError`] when the connection does not hold `open`, when the request
/// carries a field that would be a secret, when the machine is not one this
/// shell publishes, or when the application could not open it.
async fn limb_open(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    require(peer, Capability::Open)?;
    // Before the machine is even resolved. A request carrying a password is
    // refused whether or not the host exists, because answering "no such
    // machine" to it would tell an agent that the password field was the
    // acceptable part.
    wire::refuse_credentials(params).map_err(|why| RpcError::tagged("CREDENTIAL_REFUSED", why))?;

    let (key, address) = machine_from(ctx, params)?;
    let host_id = params
        .get("hostId")
        .and_then(Value::as_str)
        .map(str::to_string);

    // `00 R19`. The grant names its hosts, and this socket's list of them is
    // the one `hosts.list` publishes: machines somebody saved, plus the ones
    // already open. An agent may only open a machine somebody already allowed
    // it to touch, and an arbitrary address is not that.
    let (port, protocol) = permitted_endpoint(ctx, params, &address).await?;

    // Slot 0 attaches to whatever is already live (`02 §4.4`). A machine the
    // person already has open is not opened twice: the agent is handed that
    // session, which is what makes an agent and a person watch the same thing.
    if let Some((session_id, _)) = {
        let sessions = ctx.sessions.lock();
        sessions_for_machine(&sessions, &key).into_iter().next()
    } {
        return Ok(json!({
            "opened": false,
            "reused": true,
            "sessionId": session_id,
            "why": "that machine is already open in DeskVNCViewer, so nothing was dialled and this is the session that was already there. Call limb.attach for it",
        }));
    }

    let open = opener().lock().clone().ok_or_else(|| {
        RpcError::tagged(
            "NOT_IMPLEMENTED",
            "this build's agent plane was started without an opener, so it can attach to sessions DeskVNCViewer already has and cannot ask it to start one. The application installs one by calling crate::agent::server::install_opener where it holds the AppHandle",
        )
    })?;

    let (tell, told) = tokio::sync::oneshot::channel();
    open(
        OpenAsk {
            host_id,
            address: address.clone(),
            port,
            protocol: protocol.clone(),
        },
        tell,
    );
    let opened = match tokio::time::timeout(SPAWN_WINDOW, told).await {
        Ok(Ok(Ok(opened))) => opened,
        Ok(Ok(Err(why))) => {
            return Err(RpcError::tagged(
                "OPEN_FAILED",
                format!("DeskVNCViewer could not open {address}: {why}"),
            ))
        }
        Ok(Err(_)) | Err(_) => {
            return Err(RpcError::tagged(
                "OPEN_FAILED",
                format!(
                    "DeskVNCViewer was asked to open {address} and had not said whether it did after {} seconds. A window may still be opening: call limb.list rather than asking again, because asking again could open a second session",
                    SPAWN_WINDOW.as_secs()
                ),
            ))
        }
    };

    // Registered is not connected, and the reply says so rather than implying
    // it. `04 §4.3`: an agent told a machine is ready when it is negotiating
    // will put a click on a reconnecting socket.
    let live = ctx
        .sessions
        .lock()
        .get(&opened.session_id)
        .map(SessionEntry::is_live)
        .unwrap_or(false);
    Ok(json!({
        "opened": true,
        "reused": opened.reused,
        "sessionId": opened.session_id,
        "address": address,
        "port": port,
        "protocol": protocol,
        "registered": live,
        "connected": false,
        "why": "opening is asynchronous and this returned as soon as the session was spawned, not when it connected: the machine may still be negotiating, and it may stop to ask the PERSON for a credential, which is the one thing an agent cannot answer. Poll limb.status until state is connected, then limb.attach",
    }))
}

/// Which endpoint this open is allowed to dial, if any.
///
/// The list of machines an agent may open is the one [`hosts_list`] publishes:
/// the saved library, plus whatever is already open. That is `00 R19`'s "the
/// grant names its hosts" as this surface can enforce it, and anything else is
/// refused BY NAME before a socket is opened to it, because an agent that can
/// name an address is otherwise an agent that can reach a machine nobody
/// approved.
///
/// **A saved machine's port and protocol are the SAVED ones and never the
/// agent's.** [`machine_from`] already refuses a protocol beside a `hostId`
/// for that reason, and this keeps the same rule for the port.
///
/// An `address` keeps the protocol and port the caller named, and it has to:
/// the address is what being in the library authorises, and answering an SSH
/// open with a VNC endpoint because a VNC session happens to be up on that box
/// would dial something nobody asked for.
///
/// # Errors
///
/// An [`RpcError`] tagged `NO_SUCH_MACHINE`.
async fn permitted_endpoint(
    ctx: &Ctx,
    params: &Value,
    address: &str,
) -> Result<(u16, String), RpcError> {
    let store = ctx.store.clone();
    let hosts = tokio::task::spawn_blocking(move || store.list_hosts())
        .await
        .map_err(|e| RpcError::new(-32603, format!("the host library lookup panicked: {e}")))?
        .map_err(|e| RpcError::new(-32603, format!("the host library could not be read: {e}")))?;
    let wanted = vnc_store::normalize_address(address);
    let saved = hosts
        .iter()
        .find(|host| vnc_store::normalize_address(&host.address) == wanted);
    if let Some(host_id) = params.get("hostId").and_then(Value::as_str) {
        let profile = hosts
            .iter()
            .find(|host| host.id == host_id)
            .ok_or_else(|| {
                RpcError::tagged(
                    "NO_SUCH_MACHINE",
                    format!("no saved machine is called {host_id}; call hosts.list for the ids"),
                )
            })?;
        return Ok((profile.port, profile.protocol.clone()));
    }

    let known = saved.is_some() || {
        // An address that is not saved but IS already open is one a person
        // quick connected to, and `hosts.list` publishes it for that reason.
        let sessions = ctx.sessions.lock();
        sessions
            .values()
            .any(|entry| entry.is_live() && vnc_store::normalize_address(&entry.address) == wanted)
    };
    if known {
        let protocol = params
            .get("protocol")
            .and_then(Value::as_str)
            .and_then(ProtocolKind::parse)
            .ok_or_else(|| {
                RpcError::bad_params(
                    "protocol is required with address, and a value this build does not know is a hard error rather than a fallback to VNC",
                )
            })?;
        let port = params
            .get("port")
            .and_then(Value::as_u64)
            .map(|p| p as u16)
            .unwrap_or_else(|| protocol.default_port());
        return Ok((port, protocol.as_str().to_string()));
    }
    Err(RpcError::tagged(
        "NO_SUCH_MACHINE",
        format!(
            "{address} is not a machine this DeskVNCViewer knows: it is not in the saved library and it is not open. An agent opens machines somebody already allowed it to touch and never an arbitrary address (00 R19). Nothing was dialled. Call hosts.list for the machines that are on offer, or ask the user to save this one"
        ),
    ))
}

// ---------------------------------------------------------------------------
// `files.*`: the SFTP sidecar, as the plane reaches it.
// ---------------------------------------------------------------------------

/// The largest slice of one file this surface moves in a single call.
///
/// Four megabytes, and the number is derived rather than picked. The envelope
/// caps a payload at [`wire::MAX_PAYLOAD`], which is eight megabytes, and
/// base64 costs a third, so four megabytes of file becomes about five and a
/// half megabytes of text with room left for the path strings and the JSON
/// around them. It is the cap in BOTH directions, because the same envelope
/// carries a `files.put` up and a `files.get` down.
///
/// **A bigger file is not refused, it is windowed.** `files.get` takes an
/// `offset` and answers with `eof`, `files.put` takes an `offset` and
/// truncates only at zero, so a two hundred megabyte installer crosses in
/// fifty calls and arrives byte for byte. What is refused, by name and with
/// the number, is a single call that asked for more than this: the alternative
/// is truncating a payload silently, and a `.exe` that is short by the last
/// kilobyte is a `.exe` that fails at install time on somebody else's machine
/// with nothing to point at.
pub const MAX_FILE_CHUNK: usize = 4 * 1024 * 1024;

/// How long a `files.*` call waits for the application to answer.
///
/// Generous on purpose. Behind this sits an SSH handshake on first use plus a
/// chunk of a file over whatever link the machine is on, and a deadline tuned
/// for a LAN would turn a slow but working transfer into a refusal, which is
/// the failure that costs the most: the operation succeeded and the caller was
/// told it failed.
const FILES_DEADLINE: Duration = Duration::from_secs(120);

/// One file operation, as the application is asked to perform it.
///
/// There is no `Connect` here and that absence is the design. The sidecar is
/// opened on FIRST USE of whichever verb needs it, because a separate connect
/// verb is a round trip an agent has to know to make, and an agent that does
/// not know to make it reads the refusal, guesses, and burns a turn. A person
/// gets the same treatment from the Files panel, which connects when it opens
/// rather than making anybody press Connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileAsk {
    /// Where the remote user's home directory is, which is where a listing
    /// starts when nobody named a path.
    Home,
    List {
        path: String,
    },
    Get {
        path: String,
        offset: u64,
        length: usize,
    },
    Put {
        path: String,
        /// Zero TRUNCATES and anything else writes in place. That is what
        /// makes a chunk loop resumable, and what makes writing a short file
        /// over a long one leave no tail of the old one behind.
        offset: u64,
        bytes: Vec<u8>,
        /// The permission bits, when the caller cares. `0o755` on a script it
        /// intends to run, mostly.
        mode: Option<u32>,
    },
    Mkdir {
        path: String,
    },
    Remove {
        path: String,
        recursive: bool,
    },
    Rename {
        from: String,
        to: String,
    },
}

/// What one of those produced.
///
/// Deliberately not a bare `Value`. The application builds this and this file
/// renders it, so the JSON an agent reads is written in one place and a field
/// cannot quietly change spelling on one path and not the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileAnswer {
    /// A path, resolved on the far side: the answer to `files.home`, and to
    /// every verb whose whole result is "that path, and it is done now".
    Path(String),
    Listing {
        path: String,
        entries: Vec<vnc_files::RemoteEntry>,
    },
    Window {
        path: String,
        offset: u64,
        bytes: Vec<u8>,
        /// The whole file's size, so a caller in a chunk loop knows when it is
        /// finished without a second round trip that could disagree.
        size: u64,
    },
    Wrote {
        path: String,
        offset: u64,
        written: u64,
        size: u64,
    },
}

/// Why a file operation could not happen, in the shape the plane reports it.
///
/// A tag beside the sentence, exactly as [`RpcError::tagged`] carries one, so
/// an agent branches on `FILES_UNAVAILABLE` without matching prose. The two
/// tags are worth telling apart: one says there is no sidecar to be had on
/// that machine at all, which is a fact about the machine and no reason to
/// retry, and the other says the sidecar answered and refused this particular
/// path, which usually is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRefusal {
    pub tag: &'static str,
    pub why: String,
}

impl FileRefusal {
    /// No sidecar, and one could not be opened: no SSH on that machine, an
    /// authentication that failed, or a host key nobody has trusted yet.
    pub fn unavailable(why: impl Into<String>) -> FileRefusal {
        FileRefusal {
            tag: "FILES_UNAVAILABLE",
            why: why.into(),
        }
    }

    /// The sidecar is up and this operation did not work.
    pub fn failed(why: impl Into<String>) -> FileRefusal {
        FileRefusal {
            tag: "FILES_FAILED",
            why: why.into(),
        }
    }
}

/// How this socket asks the application to touch a file.
///
/// A callback rather than an `AppHandle` on [`Ctx`], for the reason [`Ctx`]
/// gives and [`Opener`] repeats: nothing in this module names a Tauri type.
/// It takes the ask and a channel rather than returning a future, because the
/// work behind it is async, lives on the application's runtime, and reaches
/// `State<'_, FilesState>` which is not `Send` across an await.
pub type Filer = Arc<
    dyn Fn(String, FileAsk, tokio::sync::oneshot::Sender<Result<FileAnswer, FileRefusal>>)
        + Send
        + Sync,
>;

/// Do one file operation, with every gate this surface owes it.
///
/// The order is [`limb_exec`]'s and it is the order for the same reasons. The
/// lease check first, so a person who took the wheel stops a download that was
/// about to start. The capability next, so an agent holding neither half of
/// the file pair is refused before a path it named is even parsed, and long
/// before anything dials SSH to a machine.
async fn on_sidecar(
    ctx: &Ctx,
    peer: &Peer,
    session_id: &str,
    needed: Capability,
    ask: FileAsk,
) -> Result<FileAnswer, RpcError> {
    let attachment_id = peer.attachment_id.clone().unwrap_or_default();
    ctx.plane.check_allowed(session_id, &attachment_id)?;
    require(peer, needed)?;

    let (tell, told) = tokio::sync::oneshot::channel();
    (ctx.files)(session_id.to_string(), ask, tell);
    match tokio::time::timeout(FILES_DEADLINE, told).await {
        Ok(Ok(Ok(answer))) => Ok(answer),
        Ok(Ok(Err(refusal))) => Err(RpcError::tagged(refusal.tag, refusal.why)),
        // The sender was dropped without an answer, which means the task
        // carrying it went away: the application is shutting down, or the
        // sidecar's own task panicked. Either way there is no answer coming,
        // and saying so is better than waiting out the deadline for one.
        Ok(Err(_)) => Err(RpcError::tagged(
            "FILES_UNAVAILABLE",
            format!("DeskVNCViewer stopped answering for {session_id} before this file operation finished. It may be shutting down. Nothing here invented an outcome for it: call files.list to see what actually happened on that machine"),
        )),
        Err(_) => Err(RpcError::tagged(
            "FILES_TIMEOUT",
            format!(
                "the SFTP sidecar for {session_id} had not answered after {} seconds. THIS IS A TIMEOUT AND NOT A FAILURE: a put that was in flight may have written part of the file, so check the size with files.list before writing it again rather than assuming nothing happened",
                FILES_DEADLINE.as_secs()
            ),
        )),
    }
}

/// A path argument, which is required and must not be empty.
///
/// Empty is refused rather than treated as the home directory, because the two
/// verbs where that guess would be wrong are `remove` and `rename`, and a
/// guess that resolves to somebody's home directory in a `remove` is the worst
/// possible one.
fn file_path_of(params: &Value, field: &str) -> Result<String, RpcError> {
    match params.get(field).and_then(Value::as_str) {
        Some(path) if !path.trim().is_empty() => Ok(path.to_string()),
        _ => Err(RpcError::bad_params(format!(
            "this call needs a non-empty `{field}`, a path on the REMOTE machine. `~` and `~/thing` are resolved against the remote user's home directory"
        ))),
    }
}

/// The listing, and the path it was taken from.
///
/// Every string in it came off a remote machine and is data rather than
/// instruction (`AGENT_BRIEF` D6). This file does not wrap it: `dvv`'s
/// `format::ok_remote` owns the delimiter and the nonce, and a second wrapper
/// applied here would either double the label or disagree with it.
fn listing_json(session_id: &str, path: &str, entries: &[vnc_files::RemoteEntry]) -> Value {
    json!({
        "sessionId": session_id,
        "path": path,
        "entries": entries,
        "count": entries.len(),
    })
}

async fn files_home(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let answer = on_sidecar(ctx, peer, &session_id, Capability::FilesRead, FileAsk::Home).await?;
    match answer {
        FileAnswer::Path(path) => Ok(json!({ "sessionId": session_id, "path": path })),
        other => Err(unexpected(&other, "files.home")),
    }
}

/// A directory, listed. Defaults to the remote home rather than to the process
/// working directory, which on the far side is whatever SFTP happens to make
/// of `.` and is not a place a person would recognise.
async fn files_list(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let path = params
        .get("path")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty())
        .unwrap_or("~")
        .to_string();
    let answer = on_sidecar(
        ctx,
        peer,
        &session_id,
        Capability::FilesRead,
        FileAsk::List { path },
    )
    .await?;
    match answer {
        FileAnswer::Listing { path, entries } => Ok(listing_json(&session_id, &path, &entries)),
        other => Err(unexpected(&other, "files.list")),
    }
}

/// One window of one file, base64, exactly the bytes that are on the far side.
///
/// `offset` and `length` are how a file bigger than [`MAX_FILE_CHUNK`] crosses
/// at all, and `eof` is how a caller's loop knows to stop. A `length` above
/// the cap is REFUSED and named rather than clamped: a clamp that answered a
/// six megabyte ask with four megabytes and said nothing would produce callers
/// that believe they have a whole file and have three quarters of one.
async fn files_get(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let path = file_path_of(params, "path")?;
    let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let length = match params.get("length").and_then(Value::as_u64) {
        Some(asked) if asked as usize > MAX_FILE_CHUNK => {
            return Err(RpcError::bad_params(format!(
                "length {asked} is above this surface's cap of {MAX_FILE_CHUNK} bytes per call, and it is refused rather than clamped: a clamp nobody was told about produces callers that believe they hold a whole file and hold part of one. Read the file in windows, offset by offset, until eof is true"
            )))
        }
        Some(asked) => asked as usize,
        None => MAX_FILE_CHUNK,
    };
    let answer = on_sidecar(
        ctx,
        peer,
        &session_id,
        Capability::FilesRead,
        FileAsk::Get {
            path,
            offset,
            length,
        },
    )
    .await?;
    match answer {
        FileAnswer::Window {
            path,
            offset,
            bytes,
            size,
        } => {
            let returned = bytes.len() as u64;
            Ok(json!({
                "sessionId": session_id,
                "path": path,
                "offset": offset,
                "returned": returned,
                "size": size,
                "eof": offset.saturating_add(returned) >= size,
                "contentBase64": base64::engine::general_purpose::STANDARD.encode(&bytes),
            }))
        }
        other => Err(unexpected(&other, "files.get")),
    }
}

/// One window of one file, written.
///
/// The bytes arrive base64 and are decoded here, so what reaches the far side
/// is what the caller encoded, byte for byte, and a file is a file rather than
/// a string with an encoding somebody has to guess. Anything that is not valid
/// base64 is refused by name, because the alternative is writing whatever the
/// decoder salvaged.
async fn files_put(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let path = file_path_of(params, "path")?;
    let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let encoded = params
        .get("contentBase64")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RpcError::bad_params(
                "files.put needs `contentBase64`: the bytes to write, base64 encoded, so that a binary file crosses this envelope unchanged. An empty string is a legal value and truncates the file at offset 0",
            )
        })?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| {
            RpcError::bad_params(format!(
                "`contentBase64` is not valid base64 and nothing was written: {e}. It is refused rather than decoded as far as it goes, because a file written from a half decoded payload is corrupt in a way nothing downstream can detect"
            ))
        })?;
    if bytes.len() > MAX_FILE_CHUNK {
        return Err(RpcError::bad_params(format!(
            "that is {} bytes and this surface moves at most {MAX_FILE_CHUNK} per call. Nothing was written. Send the file in windows: offset 0 first, which truncates, then each following offset, which does not",
            bytes.len()
        )));
    }
    let mode = params
        .get("mode")
        .and_then(Value::as_u64)
        .map(|m| m as u32 & 0o7777);
    let answer = on_sidecar(
        ctx,
        peer,
        &session_id,
        Capability::FilesWrite,
        FileAsk::Put {
            path,
            offset,
            bytes,
            mode,
        },
    )
    .await?;
    match answer {
        FileAnswer::Wrote {
            path,
            offset,
            written,
            size,
        } => Ok(json!({
            "sessionId": session_id,
            "path": path,
            "offset": offset,
            "written": written,
            "size": size,
        })),
        other => Err(unexpected(&other, "files.put")),
    }
}

async fn files_mkdir(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let path = file_path_of(params, "path")?;
    let answer = on_sidecar(
        ctx,
        peer,
        &session_id,
        Capability::FilesWrite,
        FileAsk::Mkdir { path },
    )
    .await?;
    match answer {
        FileAnswer::Path(path) => {
            Ok(json!({ "sessionId": session_id, "path": path, "created": true }))
        }
        other => Err(unexpected(&other, "files.mkdir")),
    }
}

/// Delete something. `recursive` is required to delete a directory that is not
/// empty and it is not defaulted to true anywhere on this path.
async fn files_remove(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let path = file_path_of(params, "path")?;
    let recursive = params
        .get("recursive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let answer = on_sidecar(
        ctx,
        peer,
        &session_id,
        Capability::FilesWrite,
        FileAsk::Remove { path, recursive },
    )
    .await?;
    match answer {
        FileAnswer::Path(path) => Ok(json!({
            "sessionId": session_id,
            "path": path,
            "removed": true,
            "recursive": recursive,
        })),
        other => Err(unexpected(&other, "files.remove")),
    }
}

async fn files_rename(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let from = file_path_of(params, "from")?;
    let to = file_path_of(params, "to")?;
    let answer = on_sidecar(
        ctx,
        peer,
        &session_id,
        Capability::FilesWrite,
        FileAsk::Rename {
            from: from.clone(),
            to,
        },
    )
    .await?;
    match answer {
        FileAnswer::Path(path) => Ok(json!({
            "sessionId": session_id,
            "from": from,
            "path": path,
            "renamed": true,
        })),
        other => Err(unexpected(&other, "files.rename")),
    }
}

/// The application answered a file verb with the wrong shape of answer.
///
/// Unreachable through the application's own filer, which answers one variant
/// per ask. It is reported rather than unwrapped because the alternative is a
/// panic inside the socket task, which takes the connection down and tells the
/// agent nothing at all.
fn unexpected(answer: &FileAnswer, method: &str) -> RpcError {
    let got = match answer {
        FileAnswer::Path(_) => "a path",
        FileAnswer::Listing { .. } => "a listing",
        FileAnswer::Window { .. } => "a window of a file",
        FileAnswer::Wrote { .. } => "a write receipt",
    };
    RpcError::new(
        -32603,
        format!("{method} was answered with {got}, which is not the shape that verb produces. This is a bug in DeskVNCViewer and not in the call"),
    )
}

/// The agent telling the shell where its lease is, so a pane can say so.
///
/// The lease itself lives in `agent-lease`, inside the agent's own process,
/// because that is where the plane runs. The shell cannot read it and must not
/// keep a second opinion about it, so the holder REPORTS and the shell renders
/// what it was told. `08 §5.5` makes that a safety property rather than a
/// nicety: a pane whose limb is held by an agent says so, visibly, always.
fn control_report(ctx: &Ctx, peer: &Peer, params: &Value) -> Result<Value, RpcError> {
    let session_id = session_id_of(params)?;
    let attachment_id = peer.attachment_id.clone().unwrap_or_default();
    let held = params
        .get("held")
        .and_then(Value::as_bool)
        .unwrap_or_default();
    let phase = params
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let holder_kind = params
        .get("holderKind")
        .and_then(Value::as_str)
        .map(str::to_string);
    let holder_label = params
        .get("holderLabel")
        .and_then(Value::as_str)
        .map(str::to_string);
    let human_took_over = params
        .get("humanTookOver")
        .and_then(Value::as_bool)
        .unwrap_or_default();
    let inflight: Vec<String> = params
        .get("inflight")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let event = ctx.plane.report(
        &session_id,
        &attachment_id,
        held,
        phase,
        holder_kind,
        holder_label,
        human_took_over,
        inflight,
    );
    match event {
        Some(event) => {
            (ctx.emit)(event);
            Ok(json!({ "recorded": true }))
        }
        // Reporting against a session this attachment never attached is not an
        // error worth failing a control call over, but it is not a success
        // either: saying so lets a client notice it is talking about a limb it
        // let go of.
        None => Ok(json!({ "recorded": false })),
    }
}

fn session_id_of(params: &Value) -> Result<String, RpcError> {
    params
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| RpcError::bad_params("this call needs a `sessionId` from limb.list"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI32;
    use vnc_core::{ClientCommand, SessionHandle, SessionState};

    /// A registry with one live session, plus the receiver that keeps it
    /// looking alive and lets a test read exactly what reached the wire.
    struct Fixture {
        ctx: Ctx,
        commands: tokio::sync::mpsc::Receiver<ClientCommand>,
        events: Arc<Mutex<Vec<Value>>>,
        /// What the fake sidecar holds, so a test can seed a file and then
        /// read back exactly what a `files.put` left behind.
        disk: Arc<Disk>,
        _dir: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        fixture_with_disk(Arc::new(Disk::default()))
    }

    /// The same fixture over a sidecar whose contents a test controls.
    fn fixture_with_disk(disk: Arc<Disk>) -> Fixture {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store =
            Arc::new(vnc_store::Store::open(Some(dir.path().to_path_buf())).expect("a store"));
        let (tx, commands) = tokio::sync::mpsc::channel(16);
        let mut sessions = HashMap::new();
        let entry = SessionEntry {
            handle: SessionHandle {
                id: "s1".into(),
                kind: ProtocolKind::Vnc,
                commands: tx,
                cancel: Default::default(),
            },
            window_label: "session-s1".into(),
            profile_id: None,
            address: "10.0.0.5".into(),
            port: 5900,
            started_at: Instant::now(),
            thumbnails: Default::default(),
            last_pointer_mask: Arc::new(AtomicI32::new(-1)),
            facts: Default::default(),
        };
        entry.facts.lock().state = SessionState::Connected;
        entry.facts.lock().size = Some((1280, 720));
        sessions.insert("s1".to_string(), entry);
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let emit: Arc<dyn Fn(Value) + Send + Sync> = Arc::new(move |value| sink.lock().push(value));
        let sessions = Arc::new(Mutex::new(sessions));
        let plane = Arc::new(AgentPlane::default());
        // The same wiring `commands::agent::install` does, onto the same sink,
        // so a test sees the `counts` payloads a real window would and the two
        // emit paths cannot silently be two.
        plane.wire_counts(sessions.clone(), emit.clone());
        Fixture {
            ctx: Ctx {
                sessions,
                store,
                plane,
                emit,
                files: disk.clone().filer(),
            },
            commands,
            events,
            disk,
            _dir: dir,
        }
    }

    /// A sidecar with a map behind it instead of a machine.
    ///
    /// A map and NOT a filesystem, and the difference is deliberate: there are
    /// no permissions here, no symlinks, no ownership and no disk that can be
    /// full. What these tests are about is the gates this file owns and the
    /// bytes surviving them, and a fake that reimplemented SFTP would be a
    /// second implementation to disagree with the first.
    ///
    /// `vnc_files::SftpSession` is what the real filer talks to and it needs
    /// an SSH server, which is why the seam the plane is written against is a
    /// closure rather than a type: this substitutes for the application, at
    /// the same boundary the application is installed at.
    #[derive(Default)]
    struct Disk {
        /// Absolute path to contents. Byte vectors, never strings, because the
        /// claim being tested is that a `.exe` survives.
        files: Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
        /// Directories that exist without holding anything.
        dirs: Mutex<std::collections::BTreeSet<String>>,
        /// True for a machine with no SSH at all, so the refusal an agent
        /// actually reads can be asserted rather than described.
        offline: bool,
    }

    /// Where `~` goes on the fake machine.
    const FAKE_HOME: &str = "/home/agent";

    impl Disk {
        fn offline() -> Arc<Disk> {
            Arc::new(Disk {
                offline: true,
                ..Disk::default()
            })
        }

        fn put(&self, path: &str, bytes: &[u8]) {
            self.files
                .lock()
                .insert(Disk::resolve(path), bytes.to_vec());
        }

        fn read(&self, path: &str) -> Option<Vec<u8>> {
            self.files.lock().get(&Disk::resolve(path)).cloned()
        }

        /// `~` and a relative path both land under [`FAKE_HOME`], which is
        /// what the real sidecar's `resolve` does with them.
        fn resolve(path: &str) -> String {
            let path = path.trim();
            if path == "~" {
                return FAKE_HOME.to_string();
            }
            if let Some(rest) = path.strip_prefix("~/") {
                return format!("{FAKE_HOME}/{rest}");
            }
            if path.starts_with('/') {
                return path.trim_end_matches('/').to_string();
            }
            format!("{FAKE_HOME}/{path}")
        }

        fn answer(&self, ask: FileAsk) -> Result<FileAnswer, FileRefusal> {
            if self.offline {
                return Err(FileRefusal::unavailable(
                    "no SFTP sidecar could be opened to 10.0.0.5:22: connection refused. File transfer rides SSH on a second connection",
                ));
            }
            match ask {
                FileAsk::Home => Ok(FileAnswer::Path(FAKE_HOME.to_string())),
                FileAsk::List { path } => {
                    let dir = Disk::resolve(&path);
                    let prefix = format!("{dir}/");
                    let entries = self
                        .files
                        .lock()
                        .iter()
                        .filter_map(|(full, bytes)| {
                            let name = full.strip_prefix(&prefix)?;
                            if name.contains('/') {
                                return None;
                            }
                            Some(vnc_files::RemoteEntry {
                                name: name.to_string(),
                                path: full.clone(),
                                is_dir: false,
                                size: bytes.len() as u64,
                                modified: Some(1),
                                mode: 0o644,
                                is_symlink: false,
                            })
                        })
                        .collect();
                    Ok(FileAnswer::Listing { path: dir, entries })
                }
                FileAsk::Get {
                    path,
                    offset,
                    length,
                } => {
                    let full = Disk::resolve(&path);
                    let held = self.files.lock();
                    let bytes = held.get(&full).ok_or_else(|| {
                        FileRefusal::failed(format!("sftp error: no such file: {full}"))
                    })?;
                    let size = bytes.len() as u64;
                    let from = (offset as usize).min(bytes.len());
                    let to = from.saturating_add(length).min(bytes.len());
                    Ok(FileAnswer::Window {
                        path: full,
                        offset,
                        bytes: bytes[from..to].to_vec(),
                        size,
                    })
                }
                FileAsk::Put {
                    path,
                    offset,
                    bytes,
                    mode: _,
                } => {
                    let full = Disk::resolve(&path);
                    let mut held = self.files.lock();
                    let file = held.entry(full.clone()).or_default();
                    // Offset zero truncates and anything else writes in place,
                    // which is the contract `SftpSession::write_at` states and
                    // the whole reason a chunk loop can resume.
                    if offset == 0 {
                        file.clear();
                    }
                    let at = offset as usize;
                    if file.len() < at {
                        file.resize(at, 0);
                    }
                    let end = at + bytes.len();
                    if file.len() < end {
                        file.resize(end, 0);
                    }
                    file[at..end].copy_from_slice(&bytes);
                    Ok(FileAnswer::Wrote {
                        path: full,
                        offset,
                        written: bytes.len() as u64,
                        size: file.len() as u64,
                    })
                }
                FileAsk::Mkdir { path } => {
                    let full = Disk::resolve(&path);
                    self.dirs.lock().insert(full.clone());
                    Ok(FileAnswer::Path(full))
                }
                FileAsk::Remove { path, recursive } => {
                    let full = Disk::resolve(&path);
                    let mut held = self.files.lock();
                    if held.remove(&full).is_none() {
                        let prefix = format!("{full}/");
                        let doomed: Vec<String> = held
                            .keys()
                            .filter(|key| key.starts_with(&prefix))
                            .cloned()
                            .collect();
                        if !doomed.is_empty() && !recursive {
                            return Err(FileRefusal::failed(format!(
                                "sftp error: {full} is not empty; pass recursive"
                            )));
                        }
                        for key in doomed {
                            held.remove(&key);
                        }
                    }
                    self.dirs.lock().remove(&full);
                    Ok(FileAnswer::Path(full))
                }
                FileAsk::Rename { from, to } => {
                    let from = Disk::resolve(&from);
                    let to = Disk::resolve(&to);
                    let mut held = self.files.lock();
                    let bytes = held.remove(&from).ok_or_else(|| {
                        FileRefusal::failed(format!("sftp error: no such file: {from}"))
                    })?;
                    held.insert(to.clone(), bytes);
                    Ok(FileAnswer::Path(to))
                }
            }
        }

        /// The closure the plane holds, at the same boundary the application
        /// installs its own at.
        fn filer(self: Arc<Self>) -> Filer {
            Arc::new(move |_session_id, ask, tell| {
                let _ = tell.send(self.answer(ask));
            })
        }
    }

    async fn call(ctx: &Ctx, peer: &mut Peer, method: &str, params: Value) -> Value {
        dispatch(ctx, peer, method, &params)
            .await
            .unwrap_or_else(|e| panic!("{method} failed: {}", e.message))
    }

    async fn greeted(ctx: &Ctx) -> Peer {
        let mut peer = Peer::default();
        call(
            ctx,
            &mut peer,
            "hello",
            json!({ "protocol": PROTOCOL, "client": { "name": "test" } }),
        )
        .await;
        peer
    }

    /// The thing the whole change exists for: an attach over the socket
    /// resolves a real [`SessionEntry`] in the shell's own registry, and a
    /// command sent against it lands on that session's command channel.
    #[tokio::test]
    async fn an_attach_reaches_a_real_session_entry_and_its_wire() {
        let mut fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;

        let attached = call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "port": 5900, "slot": 0 }),
        )
        .await;
        assert_eq!(attached["sessionId"], "s1");
        assert_eq!(attached["protocol"], "vnc");
        assert_eq!(attached["size"]["width"], 1280);
        assert_eq!(attached["state"]["state"], "connected");

        call(
            &fixture.ctx,
            &mut peer,
            "limb.command",
            json!({
                "sessionId": "s1",
                "command": { "kind": "pointer", "x": 7, "y": 9, "buttonMask": 1 },
            }),
        )
        .await;
        let landed = fixture
            .commands
            .try_recv()
            .expect("the session was sent to");
        assert!(matches!(
            landed,
            ClientCommand::Pointer {
                x: 7,
                y: 9,
                button_mask: 1
            }
        ));

        // …and the shell told every window about it, which is what the pane's
        // agent badge is rendered from.
        let events = fixture.events.lock();
        let attached = events
            .iter()
            .find(|event| event["type"] == "attached")
            .expect("an attached event");
        assert_eq!(attached["sessionId"], "s1");
    }

    #[tokio::test]
    async fn nothing_works_before_hello_and_a_wrong_protocol_is_a_hard_error() {
        let fixture = fixture();
        let mut peer = Peer::default();
        let refused = dispatch(&fixture.ctx, &mut peer, "limb.list", &json!({}))
            .await
            .expect_err("hello first");
        assert!(
            refused.message.contains("hello first"),
            "{}",
            refused.message
        );

        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "hello",
            &json!({ "protocol": "dvvp.v2" }),
        )
        .await
        .expect_err("no negotiation and no shim");
        assert!(refused.message.contains("dvvp.v2"), "{}", refused.message);
        assert!(refused.message.contains(PROTOCOL), "{}", refused.message);
    }

    /// `00 B7`. The slot is the index among live sessions for one machine, and
    /// a slot nobody has open is refused by name rather than silently
    /// collapsing onto slot 0, which would drive the wrong session.
    #[tokio::test]
    async fn a_slot_nobody_has_open_is_refused_by_name() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            &json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 3 }),
        )
        .await
        .expect_err("only one session is open");
        assert_eq!(refused.tag, Some("LIMB_GONE"));
        assert!(refused.message.contains("slot 3"), "{}", refused.message);
        assert!(
            refused.message.contains("limb.open"),
            "the refusal has to say what to do next: {}",
            refused.message
        );
    }

    /// `04 §5.4`. A person taking the wheel revokes the attachment, and the
    /// agent's next command is refused with a tag it can branch on rather than
    /// with prose it has to read.
    #[tokio::test]
    async fn taking_the_wheel_stops_the_next_command() {
        let mut fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
        )
        .await;

        fixture.ctx.plane.revoke("s1");
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "limb.command",
            &json!({ "sessionId": "s1", "command": { "kind": "release-all-keys" } }),
        )
        .await
        .expect_err("a person is driving");
        assert_eq!(refused.tag, Some("LEASE_REVOKED"));
        assert!(
            fixture.commands.try_recv().is_err(),
            "nothing may reach the wire after a revocation"
        );
    }

    #[tokio::test]
    async fn an_unknown_method_answers_the_code_a_client_probes_with() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        let refused = dispatch(&fixture.ctx, &mut peer, "limb.teleport", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(refused.code, -32601);
    }

    /// Paint a mirror the way a real `Refresh` would, then catch the reader
    /// up, so a later rung 4 read is about one change and not about the whole
    /// screen.
    fn paint(ctx: &Ctx, id: &str, size: (u16, u16)) {
        ctx.plane.feed(
            id,
            &[vnc_core::DecodedRect {
                rect: Rect::new(0, 0, size.0, size.1),
                payload: vnc_core::RectPayload::Rgba(
                    [40u8, 80, 160, 255].repeat(size.0 as usize * size.1 as usize),
                ),
            }],
        );
        ctx.plane.mirrors.take_damage(id);
    }

    /// Attaching with a mirror puts the `03 §3.4` order on the person's wire,
    /// in that order, and refuses to call the picture readable until the
    /// refresh has landed.
    ///
    /// The order is the whole of `00 R6`: turning H.264 off without the
    /// refresh leaves every region a live decoder context owned holding
    /// whatever the mirror last put there, which is black.
    #[tokio::test]
    async fn attaching_a_mirror_renegotiates_first_and_reports_frames_only_once_primed() {
        let mut fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        let attached = call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true }),
        )
        .await;

        let perception = &attached["perception"];
        assert_eq!(perception["mirror"], true, "{perception}");
        assert_eq!(
            perception["frames"], false,
            "nothing has been painted, so there is nothing to look at yet"
        );
        assert_eq!(perception["priming"], true);
        assert_eq!(perception["size"]["width"], 1280);
        assert_eq!(perception["bytes"], 1280 * 720 * 4);
        assert_eq!(
            perception["negotiated"],
            json!(["set-quality", "refresh"]),
            "the flag is cleared first and the refresh comes second"
        );
        assert_eq!(perception["restoreOnDetach"], "auto");

        // …and those two are on the session's actual wire, in that order.
        assert!(matches!(
            fixture.commands.try_recv().expect("set quality was sent"),
            ClientCommand::SetQuality(QualityPreset::High)
        ));
        assert!(matches!(
            fixture.commands.try_recv().expect("refresh was sent"),
            ClientCommand::Refresh
        ));

        // A read before the refresh lands is refused, and refused as a WAIT
        // rather than as a dead end.
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            &json!({ "sessionId": "s1", "kind": "frame" }),
        )
        .await
        .expect_err("03 §9 A3: the opaque black is not a screenshot");
        assert_eq!(refused.tag, Some("PRIMING"));
        assert!(
            refused.message.contains("resolves on its own"),
            "{}",
            refused.message
        );

        // …and once it has, `frames` flips, on a call that costs nothing.
        paint(&fixture.ctx, "s1", (1280, 720));
        let status = call(
            &fixture.ctx,
            &mut peer,
            "limb.status",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(status["perception"]["frames"], true, "{status}");
        assert_eq!(status["perception"]["priming"], false);
    }

    /// **The `00 R6` test, end to end over the dispatcher.**
    ///
    /// An H.264 rectangle reaches an attached mirror. `Framebuffer::apply`'s
    /// H.264 arm is a documented no-op and the decoder is in the webview, so
    /// the pixels under that rectangle are whatever was there before. The read
    /// must refuse, or hand back a frame that NAMES the stale region. There is
    /// no third answer where the pixels come back clean.
    #[tokio::test]
    async fn an_h264_rect_never_comes_back_through_the_wire_as_a_clean_frame() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true }),
        )
        .await;
        paint(&fixture.ctx, "s1", (1280, 720));

        // Clean while nothing has poisoned it.
        let clean = call(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            json!({ "sessionId": "s1", "kind": "frame" }),
        )
        .await;
        assert_eq!(clean["observation"]["coverage"], "complete");

        // …and then a video rectangle arrives, which is the default on nearly
        // every server (00 R6).
        fixture.ctx.plane.feed(
            "s1",
            &[vnc_core::DecodedRect {
                rect: Rect::new(100, 100, 320, 240),
                payload: vnc_core::RectPayload::H264 {
                    data: vec![0, 0, 0, 1, 0x65],
                    flags: 0,
                    context_id: 0,
                    reset: false,
                    keyframe: true,
                },
            }],
        );

        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            &json!({ "sessionId": "s1", "kind": "frame" }),
        )
        .await
        .expect_err("the moving region is stale and the read must say so");
        assert_eq!(refused.tag, Some("STALE_REGION"));
        assert!(
            !refused.message.contains("resolves on its own"),
            "staleness is not a wait: it resolves only when the session stops advertising H.264, and that is the plane's job"
        );

        // The other permitted answer, and it is not a clean frame either: the
        // stale rectangles are named on it.
        let annotated = call(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            json!({ "sessionId": "s1", "kind": "frame", "stale": "annotate" }),
        )
        .await;
        assert_eq!(annotated["observation"]["coverage"], "partial");
        let stale = annotated["observation"]["stale_regions"]
            .as_array()
            .expect("every untrustworthy rectangle is named");
        assert!(!stale.is_empty());
        assert_eq!(stale[0]["why"], "h264");

        // …and the count that says the renegotiation did not take is on the
        // cheap call, where a supervisor can watch it.
        let status = call(
            &fixture.ctx,
            &mut peer,
            "limb.status",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(status["perception"]["h264Rects"], 1);
    }

    /// **`00 R43` through the wire.**
    ///
    /// A coordinate the model reads off the image we sent has to come back to
    /// the exact framebuffer pixel it was made from, and everything needed to
    /// do that has to survive the trip: the crop origin, the image size and
    /// the scale. The transform is
    /// `fb_x = rx + floor((mx + 0.5) / s)`, and at `s = 1.0` it degenerates to
    /// `rx + mx` with no rounding at all.
    #[tokio::test]
    async fn the_coordinate_transform_round_trips_through_the_wire() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true }),
        )
        .await;
        paint(&fixture.ctx, "s1", (1280, 720));

        // Rung 3: a rectangle at native resolution, no rounding to argue
        // about, which is why `03 §4.4` says it is the rung to read a dialog
        // from.
        let region = call(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            json!({
                "sessionId": "s1",
                "kind": "region",
                "rect": { "x": 600, "y": 340, "width": 400, "height": 200 },
            }),
        )
        .await;
        let space = space_from(&region["observation"]["image"]["space"]);
        assert!(space.is_unscaled(), "a region read is scale 1.0");
        for mx in [0u32, 1, 199, 399] {
            let point = space.to_framebuffer(mx, 0).expect("inside the image");
            assert_eq!(
                point.x,
                600 + mx as u16,
                "at scale 1.0 the transform is addition and nothing else"
            );
        }
        // Refused, never clamped: a clamped coordinate lands on whatever is at
        // the edge, which is a different action performed silently.
        assert!(space.to_framebuffer(400, 0).is_err());

        // Rung 2: the orientation shot, downscaled by US to a factor we chose
        // and can invert (`00 R43` WA-11).
        let frame = call(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            json!({ "sessionId": "s1", "kind": "frame", "longEdge": 640 }),
        )
        .await;
        let space = space_from(&frame["observation"]["image"]["space"]);
        assert_eq!(space.width, 640);
        assert!(
            !space.is_unscaled(),
            "1280 wide does not fit a 640 long edge"
        );
        for mx in [0u32, 7, 320, 639] {
            let point = space.to_framebuffer(mx, 0).expect("inside the image");
            let expected = ((f64::from(mx) + 0.5) / space.scale).floor() as u16;
            assert_eq!(point.x, expected, "the half source pixel bias is missing");
        }
        // …and it goes back the other way, which is what makes the round trip
        // an assertion rather than an argument.
        let there_and_back = space
            .to_image(space.to_framebuffer(320, 180).expect("inside"))
            .expect("inside the region");
        assert_eq!(there_and_back, (320, 180));

        // The pixels themselves came too, and they are a real PNG.
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(frame["observation"]["image"]["base64"].as_str().unwrap())
            .expect("base64");
        assert_eq!(&bytes[1..4], b"PNG");
        assert_eq!(
            bytes.len(),
            frame["observation"]["image"]["encoded_bytes"]
                .as_u64()
                .unwrap() as usize
        );
    }

    /// Rebuild the transform from what the wire carried, which is the point of
    /// the test above: if a field goes missing this stops compiling or stops
    /// agreeing.
    fn space_from(value: &Value) -> agent_perception::ImageSpace {
        agent_perception::ImageSpace {
            region: Rect::new(
                value["region"]["x"].as_u64().unwrap() as u16,
                value["region"]["y"].as_u64().unwrap() as u16,
                value["region"]["width"].as_u64().unwrap() as u16,
                value["region"]["height"].as_u64().unwrap() as u16,
            ),
            width: value["width"].as_u64().unwrap() as u32,
            height: value["height"].as_u64().unwrap() as u32,
            scale: value["scale"].as_f64().unwrap(),
        }
    }

    /// `00 R5` and `R48e`. Pixels cost `capture` and rectangles cost `view`,
    /// and holding the weaker one never produces the stronger.
    #[tokio::test]
    async fn damage_costs_view_and_pixels_cost_capture() {
        let fixture = fixture();
        let mut peer = Peer::default();
        // A client that asked for the weaker half only.
        call(
            &fixture.ctx,
            &mut peer,
            "hello",
            json!({
                "protocol": PROTOCOL,
                "client": { "name": "an observer" },
                "capabilities": ["view", "control"],
            }),
        )
        .await;
        assert!(peer.capabilities.allows(Capability::View));
        assert!(!peer.capabilities.allows(Capability::Capture));

        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            &json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true }),
        )
        .await
        .expect_err("a frame is content leaving the process");
        assert_eq!(refused.tag, Some("MISSING_CAPABILITY"));

        // …and the weaker half works, with nothing allocated for it.
        let attached = call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": "damage" }),
        )
        .await;
        assert_eq!(attached["perception"]["mirror"], false);
        assert_eq!(attached["perception"]["bytes"], 0);
        assert_eq!(fixture.ctx.plane.mirrors.bytes_in_use(), 0);

        fixture.ctx.plane.feed(
            "s1",
            &[vnc_core::DecodedRect {
                rect: Rect::new(4, 8, 16, 32),
                payload: vnc_core::RectPayload::CopyRect { src_x: 0, src_y: 0 },
            }],
        );
        let damage = call(
            &fixture.ctx,
            &mut peer,
            "screen.damage",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(damage["rects"][0]["x"], 4);
        assert_eq!(damage["rects"][0]["height"], 32);
        assert_eq!(damage["quiet"], false);

        // …and the pixels stay refused.
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            &json!({ "sessionId": "s1", "kind": "frame" }),
        )
        .await
        .expect_err("view does not imply capture");
        assert_eq!(refused.tag, Some("MISSING_CAPABILITY"));
    }

    /// `AGENT_BRIEF` D2. A person watching a pane must not silently lose the
    /// quality preset they connected with because an agent looked once.
    #[tokio::test]
    async fn detaching_puts_the_person_s_quality_preset_back() {
        let mut fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true }),
        )
        .await;
        while fixture.commands.try_recv().is_ok() {}

        let detached = call(
            &fixture.ctx,
            &mut peer,
            "limb.detach",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(detached["qualityRestored"], "auto");
        assert!(matches!(
            fixture.commands.try_recv().expect("the preset went back"),
            ClientCommand::SetQuality(QualityPreset::Auto)
        ));
        assert!(
            matches!(
                fixture.commands.try_recv().expect("and a repaint after it"),
                ClientCommand::Refresh
            ),
            "the encoding set changed again, so the picture has to be redrawn"
        );
        assert_eq!(fixture.ctx.plane.mirrors.bytes_in_use(), 0);

        // A cleanup path has to be safe to call twice, and a second SetQuality
        // would be a second repaint for nothing.
        let again = call(
            &fixture.ctx,
            &mut peer,
            "limb.detach",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(again["qualityRestored"], Value::Null);
        assert!(fixture.commands.try_recv().is_err());
    }

    /// A session that has never reported a framebuffer size cannot be
    /// mirrored, and the refusal names the kind of session that never will.
    #[tokio::test]
    async fn a_session_with_no_geometry_refuses_a_mirror_by_name() {
        let fixture = fixture();
        fixture
            .ctx
            .sessions
            .lock()
            .get("s1")
            .expect("the fixture session")
            .facts
            .lock()
            .size = None;
        let mut peer = greeted(&fixture.ctx).await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            &json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true }),
        )
        .await
        .expect_err("a mirror cannot be sized from nothing");
        assert_eq!(refused.tag, Some("NO_FRAMEBUFFER"));
        assert!(
            refused.message.contains("terminal.read"),
            "{}",
            refused.message
        );
    }

    /// The default read is rung 4, a crop around what changed, chosen from the
    /// rect LIST and never from `Rect::union` (`00 R39b`, `03 §4.5`).
    #[tokio::test]
    async fn the_default_read_is_a_crop_around_what_changed() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true }),
        )
        .await;
        paint(&fixture.ctx, "s1", (1280, 720));

        // Nothing has changed since the paint, and that is an ANSWER. An agent
        // that receives an error for it retries immediately rather than
        // waiting, which turns the cheapest rung into a spin loop.
        let quiet = call(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(quiet["unchanged"], true);
        assert!(quiet["geometryGeneration"].as_u64().is_some());

        // Two small changes in OPPOSITE CORNERS. Their union is the whole
        // screen; their crop is not, and that difference is the ruling.
        for rect in [Rect::new(8, 8, 16, 16), Rect::new(1240, 690, 16, 16)] {
            fixture.ctx.plane.feed(
                "s1",
                &[vnc_core::DecodedRect {
                    rect,
                    payload: vnc_core::RectPayload::Rgba([9u8, 9, 9, 255].repeat(16 * 16)),
                }],
            );
        }
        let changed = call(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            json!({ "sessionId": "s1", "margin": 0 }),
        )
        .await;
        let observation = &changed["observation"];
        assert_eq!(observation["rung"], "change");
        assert_eq!(
            observation["damage"].as_array().map(Vec::len),
            Some(1),
            "the LIST travels, and this crop covers one of the two: {observation}"
        );
        assert_eq!(
            observation["remaining_changes"], 1,
            "the other corner is named as still waiting rather than dragged into the crop"
        );
        assert_eq!(observation["image"]["space"]["region"]["width"], 16);
        assert_eq!(observation["image"]["space"]["scale"], 1.0);
    }

    /// A read is fenced against the screen it was computed for (`00 R10`).
    #[tokio::test]
    async fn a_read_fenced_against_a_screen_that_has_gone_is_refused() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true }),
        )
        .await;
        paint(&fixture.ctx, "s1", (1280, 720));

        fixture.ctx.plane.note_resize("s1", 1920, 1080);
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            &json!({ "sessionId": "s1", "kind": "frame", "generation": 1 }),
        )
        .await
        .expect_err("that screen no longer exists");
        assert_eq!(refused.tag, Some("GEOMETRY_CHANGED"));
    }

    // ---------------------------------------------------------------------
    // The content fence. The screen a keystroke lands in, rather than the
    // coordinate a click lands on.
    //
    // The incident these are written from is real. An agent ran
    // `Start-Process notepad` on a remote Windows desktop and typed into it
    // without looking. Notepad had come up holding the person's own file with
    // all 2,378,798 characters selected, so the next keystroke would have
    // replaced the file, and the only reason it did not is that a human looked
    // at a screenshot before the typing step ran. The plane refused a stale
    // CLICK and delivered that keystroke without a word, because
    // `IntentKind::is_grounded` is false for `Type` and nothing was ever
    // checked for it.
    // ---------------------------------------------------------------------

    /// One server update covering `width` x `height` from the origin, fed the
    /// way `commands::session::forward_events` feeds one.
    ///
    /// Not [`paint`], which also consumes the damage: these tests care about
    /// what the update did to the CONTENT counter and want the damage log left
    /// exactly as a real update would leave it.
    fn repaint(ctx: &Ctx, width: u16, height: u16) {
        ctx.plane.feed(
            "s1",
            &[vnc_core::DecodedRect {
                rect: Rect::new(0, 0, width, height),
                payload: vnc_core::RectPayload::Rgba(
                    [40u8, 80, 160, 255].repeat(width as usize * height as usize),
                ),
            }],
        );
    }

    /// An attachment with a mirror, primed, and nothing observed yet.
    async fn mirrored(fixture: &mut Fixture) -> Peer {
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true }),
        )
        .await;
        paint(&fixture.ctx, "s1", (1280, 720));
        // The `03 §3.4` priming order, off the wire, so a later assertion that
        // nothing was delivered is about the keystroke and not about it.
        while fixture.commands.try_recv().is_ok() {}
        peer
    }

    /// The agent looks. This is the only call that clears the fence.
    async fn look(ctx: &Ctx, peer: &mut Peer) {
        call(
            ctx,
            peer,
            "screen.read",
            json!({ "sessionId": "s1", "kind": "frame" }),
        )
        .await;
    }

    /// One keystroke down, the way a lowered `Type` reaches this socket.
    async fn press_a(ctx: &Ctx, peer: &mut Peer) -> Result<Value, RpcError> {
        dispatch(
            ctx,
            peer,
            "limb.command",
            &json!({
                "sessionId": "s1",
                "command": { "kind": "key", "keysym": 0x61, "down": true },
            }),
        )
        .await
    }

    /// The incident, as a test. A window sized repaint arrived after the agent
    /// last looked, so the keystroke is refused and NOTHING reaches the wire.
    #[tokio::test]
    async fn typing_is_refused_when_something_large_repainted_since_the_last_look() {
        let mut fixture = fixture();
        let mut peer = mirrored(&mut fixture).await;
        look(&fixture.ctx, &mut peer).await;

        // A window. 1280x200 is 27.8 percent of this framebuffer, which is
        // roughly what Notepad coming up costs on a real desktop.
        repaint(&fixture.ctx, 1280, 200);

        let refused = press_a(&fixture.ctx, &mut peer)
            .await
            .expect_err("the screen is not the one that was read");
        assert_eq!(refused.tag, Some("SCREEN_CHANGED"));
        // Both numbers, the way `GeometryRejected` carries both of its own: a
        // refusal an agent cannot check against what it thought it knew is a
        // refusal it will retry blind.
        assert!(
            refused.message.contains("content generation 2")
                && refused.message.contains("now at 3"),
            "both generations have to be in the sentence: {}",
            refused.message
        );
        assert!(
            refused.message.contains("Nothing was typed"),
            "the agent has to be told nothing was delivered: {}",
            refused.message
        );
        assert!(
            fixture.commands.try_recv().is_err(),
            "a refused keystroke must not reach the session"
        );
    }

    /// The one that would make this feature worthless if it failed: the echo
    /// of the agent's own typing must not trip its own fence.
    ///
    /// A glyph is a couple of hundred pixels against nine hundred thousand. A
    /// caret blink is fewer. A fence that moved on those would refuse the
    /// second character of every word and would be switched off within a day.
    #[tokio::test]
    async fn the_echo_of_the_agents_own_keystroke_does_not_trip_the_fence() {
        let mut fixture = fixture();
        let mut peer = mirrored(&mut fixture).await;
        look(&fixture.ctx, &mut peer).await;

        for _ in 0..40 {
            // One glyph cell, then the caret blinking beside it.
            repaint(&fixture.ctx, 12, 20);
            repaint(&fixture.ctx, 2, 20);
            // And a menu opening, which is 6.5 percent of this framebuffer and
            // is usually the direct result of what the agent just did. Typing
            // a letter or an arrow into one is the ordinary next step, so this
            // is on the allowed side of the threshold on purpose.
            repaint(&fixture.ctx, 200, 300);
            press_a(&fixture.ctx, &mut peer).await.unwrap_or_else(|e| {
                panic!("an agent typing must not fence itself out: {}", e.message)
            });
            assert!(
                fixture.commands.try_recv().is_ok(),
                "the keystroke has to reach the session"
            );
        }
    }

    /// Typing blind into a machine nobody has looked at is the failure itself,
    /// so it is refused before the first keystroke rather than after the first
    /// large repaint.
    #[tokio::test]
    async fn an_attachment_that_has_never_looked_cannot_type_at_all() {
        let mut fixture = fixture();
        let mut peer = mirrored(&mut fixture).await;

        let refused = press_a(&fixture.ctx, &mut peer)
            .await
            .expect_err("nothing has ever been observed on this limb");
        assert_eq!(refused.tag, Some("SCREEN_CHANGED"));
        assert!(
            refused.message.contains("never read this screen"),
            "{}",
            refused.message
        );
        assert!(
            refused.message.contains("perceive"),
            "the refusal has to say what to do next: {}",
            refused.message
        );
        assert!(fixture.commands.try_recv().is_err());
    }

    /// The repair, and it is one call.
    ///
    /// Also the half that says WHICH call: `screen.damage` answers with
    /// rectangles and no content, so it must not clear a fence that exists
    /// because the agent does not know what is on the screen.
    #[tokio::test]
    async fn looking_again_clears_the_refusal_and_damage_alone_does_not() {
        let mut fixture = fixture();
        let mut peer = mirrored(&mut fixture).await;
        look(&fixture.ctx, &mut peer).await;
        repaint(&fixture.ctx, 1280, 200);
        press_a(&fixture.ctx, &mut peer)
            .await
            .expect_err("the screen changed");

        // A damage call consumes the rectangles and tells the agent something
        // moved. It does not tell it what is there now.
        call(
            &fixture.ctx,
            &mut peer,
            "screen.damage",
            json!({ "sessionId": "s1" }),
        )
        .await;
        let still = press_a(&fixture.ctx, &mut peer)
            .await
            .expect_err("rectangles are not a picture");
        assert_eq!(still.tag, Some("SCREEN_CHANGED"));

        // Pixels do.
        look(&fixture.ctx, &mut peer).await;
        press_a(&fixture.ctx, &mut peer)
            .await
            .unwrap_or_else(|e| panic!("the agent has seen the new screen: {}", e.message));
        assert!(matches!(
            fixture.commands.try_recv().expect("the keystroke went"),
            ClientCommand::Key { down: true, .. }
        ));
    }

    /// A key going UP is never refused, and neither is releasing everything.
    ///
    /// Refusing a release does not stop a keystroke that has already happened;
    /// it strands a modifier held down on somebody's desktop, and every key
    /// after it, the person's included, arrives with Ctrl stuck on.
    #[tokio::test]
    async fn a_release_is_never_fenced_so_no_modifier_is_ever_stranded() {
        let mut fixture = fixture();
        let mut peer = mirrored(&mut fixture).await;
        repaint(&fixture.ctx, 1280, 720);

        for command in [
            json!({ "kind": "key", "keysym": 0xffe3, "down": false }),
            json!({ "kind": "release-all-keys" }),
        ] {
            call(
                &fixture.ctx,
                &mut peer,
                "limb.command",
                json!({ "sessionId": "s1", "command": command }),
            )
            .await;
            assert!(
                fixture.commands.try_recv().is_ok(),
                "a release has to reach the session whatever the screen did"
            );
        }
    }

    /// No regression on the fence that already existed. A pointer command is
    /// the geometry fence's business and the content fence does not touch it,
    /// on a screen that has changed under an attachment that has never looked.
    #[tokio::test]
    async fn the_content_fence_does_not_reach_a_pointer_command() {
        let mut fixture = fixture();
        let mut peer = mirrored(&mut fixture).await;
        repaint(&fixture.ctx, 1280, 720);

        call(
            &fixture.ctx,
            &mut peer,
            "limb.command",
            json!({
                "sessionId": "s1",
                "command": { "kind": "pointer", "x": 7, "y": 9, "buttonMask": 1 },
            }),
        )
        .await;
        assert!(matches!(
            fixture.commands.try_recv().expect("the pointer event went"),
            ClientCommand::Pointer { x: 7, y: 9, .. }
        ));
    }

    /// The fence that was already here still works, in both directions.
    ///
    /// A regression guard rather than a new rule: the content fence was added
    /// to the same module and the same reply objects, and the failure worth
    /// catching is a geometry generation quietly stopping being enforced
    /// because a second counter appeared beside it.
    #[tokio::test]
    async fn the_geometry_fence_is_untouched_by_the_content_fence() {
        let mut fixture = fixture();
        let mut peer = mirrored(&mut fixture).await;

        // The generation the mirror is actually on still reads.
        let read = call(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            json!({ "sessionId": "s1", "kind": "frame", "generation": 1 }),
        )
        .await;
        assert_eq!(read["unchanged"], false);

        // The two counters are reported side by side and are not each other.
        let status = call(
            &fixture.ctx,
            &mut peer,
            "limb.status",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(status["perception"]["geometryGeneration"], 1);
        assert_eq!(status["perception"]["contentGeneration"], 2);

        // And a coordinate computed against a screen that has gone is still
        // refused with the tag an agent branches on.
        fixture.ctx.plane.note_resize("s1", 1920, 1080);
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "screen.read",
            &json!({ "sessionId": "s1", "kind": "frame", "generation": 1 }),
        )
        .await
        .expect_err("that screen no longer exists");
        assert_eq!(refused.tag, Some("GEOMETRY_CHANGED"));
        assert!(
            refused.message.contains("nothing was delivered"),
            "{}",
            refused.message
        );
    }

    /// `limb.status` answers the question one call before the refusal, so an
    /// adapter can decline to lower a `Type` at all rather than having the
    /// socket refuse forty keystrokes one at a time.
    #[tokio::test]
    async fn limb_status_says_whether_text_may_be_sent_before_any_is() {
        let mut fixture = fixture();
        let mut peer = mirrored(&mut fixture).await;

        let blind = call(
            &fixture.ctx,
            &mut peer,
            "limb.status",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(blind["typing"]["allowed"], false);
        assert_eq!(blind["typing"]["code"], "SCREEN_CHANGED");
        assert_eq!(blind["perception"]["contentGeneration"], 2);

        look(&fixture.ctx, &mut peer).await;
        let seen = call(
            &fixture.ctx,
            &mut peer,
            "limb.status",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(seen["typing"]["allowed"], true);

        repaint(&fixture.ctx, 1280, 200);
        let moved = call(
            &fixture.ctx,
            &mut peer,
            "limb.status",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(moved["typing"]["allowed"], false);
        assert_eq!(moved["perception"]["contentGeneration"], 3);
    }

    /// An attachment that asked to perceive nothing has observed nothing, so
    /// it is fenced out of typing too. There is no cheaper way to be exempt
    /// from looking than not looking.
    #[tokio::test]
    async fn an_attachment_that_asked_for_no_pixels_still_cannot_type() {
        let mut fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
        )
        .await;
        let refused = press_a(&fixture.ctx, &mut peer)
            .await
            .expect_err("nothing has been observed on this limb");
        assert_eq!(refused.tag, Some("SCREEN_CHANGED"));
        assert!(fixture.commands.try_recv().is_err());
    }

    /// Asking for nothing costs nothing, which is the setting every ordinary
    /// attach gets and the one that changes nothing about a person's session.
    #[tokio::test]
    async fn an_attach_that_asks_for_no_pixels_touches_the_session_not_at_all() {
        let mut fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        let attached = call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
        )
        .await;
        assert_eq!(
            attached["perception"],
            json!({ "mirror": false, "frames": false })
        );
        assert!(
            fixture.commands.try_recv().is_err(),
            "not one command reaches a session nobody asked to perceive"
        );
        assert_eq!(fixture.ctx.plane.mirrors.bytes_in_use(), 0);
    }

    /// The event the UI renders its agent badge from, end to end.
    #[tokio::test]
    async fn a_lease_report_becomes_an_event_the_ui_can_render() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
        )
        .await;
        call(
            &fixture.ctx,
            &mut peer,
            "control.report",
            json!({
                "sessionId": "s1",
                "held": true,
                "phase": "held",
                "holderKind": "agent",
                "holderLabel": "agent att_local",
                "humanTookOver": false,
                "inflight": ["type"],
            }),
        )
        .await;
        let events = fixture.events.lock();
        let lease = events
            .iter()
            .find(|event| event["type"] == "lease")
            .expect("a lease event");
        assert_eq!(lease["sessionId"], "s1");
        assert_eq!(lease["held"], true);
        assert_eq!(lease["holderKind"], "agent");
        assert_eq!(lease["inflight"][0], "type");
    }

    // ---------------------------------------------------------------------
    // `exec` over the socket (`00 R28`, `00 R51b`, `00 R19`).
    // ---------------------------------------------------------------------

    use remote_core::intent::{
        CommandExit, CommandRun, ExitTier, IntentName, ServedAnswer, Truncation, Unanswered,
    };

    /// One driver's answer, as the SSH driver would put it on the session's
    /// event stream after RFC 4254 §6.10's `exit-status`.
    fn ran(
        id: IntentId,
        code: Option<i32>,
        stdout: &str,
        unanswered: Option<Unanswered>,
    ) -> SessionEvent {
        SessionEvent::AgentServed(IntentServed {
            id,
            name: IntentName::Exec,
            answer: ServedAnswer::Ran(CommandRun {
                status: CommandExit {
                    code,
                    signal: None,
                    source: ExitTier::Exec,
                    unanswered,
                },
                stdout: bytes::Bytes::from(stdout.to_string()),
                stderr: bytes::Bytes::new(),
                dropped: Truncation::default(),
                duration: Duration::from_millis(12),
            }),
        })
    }

    /// Unwrap an answer, printing the refusal's own sentence when there is
    /// one. [`RpcError`] carries no `Debug` on purpose, so `expect` cannot be
    /// used on it and this is what stands in.
    fn answered(result: Result<Value, RpcError>, why: &str) -> Value {
        result.unwrap_or_else(|e| panic!("{why}, and it refused with: {}", e.message))
    }

    fn stdout_of(answer: &Value) -> String {
        let encoded = answer["stdoutBase64"].as_str().expect("stdout, base64");
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("valid base64"),
        )
        .expect("utf8 in this test's fixture")
    }

    /// Attach, run one command, and answer it the way a driver would.
    ///
    /// The two halves run together on purpose: `limb.exec` is blocked on the
    /// event stream, so a test that dispatched first and answered afterwards
    /// would deadlock, which is itself the property being proved.
    async fn exec_answered_with(
        fixture: Fixture,
        params: Value,
        answer: impl FnOnce(IntentId) -> SessionEvent,
    ) -> Result<Value, RpcError> {
        let Fixture {
            ctx,
            mut commands,
            events: _events,
            disk: _disk,
            _dir,
        } = fixture;
        let mut peer = greeted(&ctx).await;
        call(
            &ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
        )
        .await;

        let asked = dispatch(&ctx, &mut peer, "limb.exec", &params);
        let driver = async {
            let command = commands
                .recv()
                .await
                .expect("the intent reached the session's own wire");
            let ClientCommand::Agent(intent) = command else {
                panic!("an exec travels as ClientCommand::Agent and nothing else");
            };
            assert!(
                matches!(intent.kind, IntentKind::Exec { .. }),
                "limb.exec sends an exec and never anything else"
            );
            // The id is the SHELL's, never the caller's: a peer that could
            // choose it could claim another connection's answer.
            note_agent_event("s1", &answer(intent.id))
        };
        let (asked, delivered) = tokio::join!(asked, driver);
        assert!(
            delivered,
            "the answer reached the request that was waiting for it"
        );
        asked
    }

    /// The whole of gap one in one test. An `exec` crosses the socket, reaches
    /// a driver, and the driver's own exit status comes back as the REPLY.
    #[tokio::test]
    async fn an_exec_comes_back_with_the_far_sides_own_exit_code() {
        let answer = exec_answered_with(
            fixture(),
            json!({ "sessionId": "s1", "command": "uname -a", "timeoutMs": 2000 }),
            |id| ran(id, Some(0), "Linux lab01\n", None),
        )
        .await;
        let answer = answered(answer, "a served command is an answer and not an error");

        assert_eq!(answer["served"], true);
        assert_eq!(answer["timedOut"], false);
        assert_eq!(answer["status"]["code"], 0);
        assert_eq!(answer["status"]["source"], "exec");
        assert_eq!(answer["status"]["unanswered"], Value::Null);
        assert_eq!(stdout_of(&answer), "Linux lab01\n");
        assert_eq!(answer["durationMs"], 12);
        assert_eq!(answer["dropped"]["any"], false);
    }

    /// `06 §5.4`. Neither field on an answer is called success, and this is
    /// why: a command that ran and exited 3 did exactly what it was asked, and
    /// the number is the news. Returned as a RESULT, so an agent reads a
    /// failing test suite as a failing test suite rather than as a broken
    /// machine.
    #[tokio::test]
    async fn a_non_zero_exit_is_a_status_and_not_a_failure_to_run() {
        let answer = exec_answered_with(
            fixture(),
            json!({ "sessionId": "s1", "command": "false", "timeoutMs": 2000 }),
            |id| ran(id, Some(3), "", None),
        )
        .await;
        let answer = answered(answer, "a non zero exit is still an answer");

        assert_eq!(answer["served"], true);
        assert_eq!(answer["status"]["code"], 3);
        assert_eq!(answer["status"]["signal"], Value::Null);
    }

    /// `00 R7`. The driver's own deadline passed with the command still
    /// running, so there is no exit code and the bytes that did arrive are
    /// still the agent's output. Nothing invents a zero and nothing invents a
    /// one.
    #[tokio::test]
    async fn a_driver_deadline_is_a_timeout_carrying_the_output_that_arrived() {
        let answer = exec_answered_with(
            fixture(),
            json!({ "sessionId": "s1", "command": "sleep 60", "timeoutMs": 2000 }),
            |id| {
                ran(
                    id,
                    None,
                    "two lines before it stopped\n",
                    Some(Unanswered::Deadline),
                )
            },
        )
        .await;
        let answer = answered(answer, "a timeout is an ordinary answer and not an error");

        assert_eq!(answer["timedOut"], true);
        assert_eq!(answer["status"]["code"], Value::Null);
        assert_eq!(answer["status"]["signal"], Value::Null);
        assert_eq!(answer["status"]["unanswered"], "deadline");
        assert_eq!(stdout_of(&answer), "two lines before it stopped\n");
    }

    /// `00 R28`. The driver's own sentence, verbatim, and NOTHING on the wire.
    #[tokio::test]
    async fn a_driver_that_refuses_is_reported_as_a_refusal_and_not_as_a_failure() {
        let refused = exec_answered_with(
            fixture(),
            json!({ "sessionId": "s1", "command": "uname", "timeoutMs": 2000 }),
            |id| {
                SessionEvent::AgentRefused(IntentRefused {
                    id,
                    name: IntentName::Exec,
                    reason: "a remote desktop has no command channel".to_string(),
                })
            },
        )
        .await
        .expect_err("a refusal is a refusal");

        assert_eq!(refused.tag, Some("INTENT_REFUSED"));
        assert!(
            refused.message.contains("no command channel"),
            "the driver's own words survive: {}",
            refused.message
        );
    }

    /// Nothing answered at all. The reply is a TIMEOUT and says so, rather
    /// than a success with an invented status or a silence an agent waits out
    /// forever (`00 R7`, `05 §3`).
    ///
    /// The wall clock cost is [`EXEC_SLACK`] and it is paid deliberately: the
    /// thing being proved is that this path ends, and a test that shortened
    /// the wait would be proving a different one.
    #[tokio::test]
    async fn an_answer_that_never_arrives_is_a_timeout_with_no_invented_status() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
        )
        .await;
        let answer = call(
            &fixture.ctx,
            &mut peer,
            "limb.exec",
            json!({ "sessionId": "s1", "command": "uname", "timeoutMs": 1 }),
        )
        .await;

        assert_eq!(answer["served"], false);
        assert_eq!(answer["timedOut"], true);
        assert_eq!(answer["status"]["code"], Value::Null);
        assert_eq!(answer["status"]["signal"], Value::Null);
        assert_eq!(answer["status"]["unanswered"], "deadline");
        assert_eq!(stdout_of(&answer), "");
        assert!(
            answer["why"]
                .as_str()
                .expect("a sentence")
                .contains("still be running"),
            "an agent has to be told the command may have outlived the wait"
        );
    }

    /// `00 R19`. `exec` is in no role bundle, so a connection that did not ask
    /// for it does not hold it, and the refusal names the capability rather
    /// than pretending the method does not exist.
    #[tokio::test]
    async fn exec_is_refused_on_a_connection_whose_grant_does_not_name_it() {
        let fixture = fixture();
        let mut peer = Peer::default();
        let hello = call(
            &fixture.ctx,
            &mut peer,
            "hello",
            json!({
                "protocol": PROTOCOL,
                "client": { "name": "test" },
                "capabilities": ["view", "capture", "control", "close", "hosts.read"],
            }),
        )
        .await;
        let held: Vec<&str> = hello["capabilities"]
            .as_array()
            .expect("an array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(!held.contains(&"exec"), "asked for less, granted less");

        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
        )
        .await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "limb.exec",
            &json!({ "sessionId": "s1", "command": "rm -rf /", "timeoutMs": 1000 }),
        )
        .await
        .expect_err("exec is not held here");
        assert_eq!(refused.tag, Some("MISSING_CAPABILITY"));
        assert!(refused.message.contains("exec"), "{}", refused.message);
        // …and nothing reached the machine.
        let mut fixture = fixture;
        assert!(
            fixture.commands.try_recv().is_err(),
            "a refused exec puts nothing on the wire"
        );
    }

    /// A connection that DOES name it holds it, which is the other half of the
    /// same rule: `exec` is reachable, by a grant that names the string.
    #[tokio::test]
    async fn exec_is_granted_on_a_connection_whose_grant_names_it() {
        let fixture = fixture();
        let mut peer = Peer::default();
        let hello = call(
            &fixture.ctx,
            &mut peer,
            "hello",
            json!({
                "protocol": PROTOCOL,
                "client": { "name": "test" },
                "capabilities": ["view", "control", "terminal.read", "terminal.write", "exec"],
            }),
        )
        .await;
        let held: Vec<&str> = hello["capabilities"]
            .as_array()
            .expect("an array")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(held.contains(&"exec"), "{held:?}");
        assert!(
            !held.contains(&"capture"),
            "asking for exec does not widen anything else: {held:?}"
        );
    }

    /// A command with no timeout is refused rather than given one, because a
    /// timeout this file chose is a timeout the caller cannot reason about
    /// (`05 §4.1`).
    #[tokio::test]
    async fn an_exec_with_no_timeout_is_refused_by_name() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        call(
            &fixture.ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
        )
        .await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "limb.exec",
            &json!({ "sessionId": "s1", "command": "uname" }),
        )
        .await
        .expect_err("timeoutMs has no default");
        assert!(refused.message.contains("timeoutMs"), "{}", refused.message);
    }

    // ---------------------------------------------------------------------
    // `limb.open` (`00 R19`, `09 §4`).
    // ---------------------------------------------------------------------

    /// D7 in one test, on the open path. An agent may not supply a credential,
    /// the refusal says so by name, and it never echoes the value back.
    #[tokio::test]
    async fn an_agent_supplied_password_is_refused_before_anything_is_dialled() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "limb.open",
            &json!({
                "address": "10.0.0.9",
                "protocol": "vnc",
                "password": "hunter2",
            }),
        )
        .await
        .expect_err("credentials never cross this socket");

        assert_eq!(refused.tag, Some("CREDENTIAL_REFUSED"));
        assert!(refused.message.contains("password"), "{}", refused.message);
        assert!(
            !refused.message.contains("hunter2"),
            "a refusal that quotes the secret has copied it into a log line: {}",
            refused.message
        );
        assert!(
            refused.message.contains("keychain"),
            "the refusal has to say where the secret does come from: {}",
            refused.message
        );
    }

    /// `00 R19`. The grant names its hosts, and this socket's list of them is
    /// what `hosts.list` publishes. A machine nobody saved and nobody has open
    /// is refused BEFORE anything connects, which is provable here because the
    /// refusal arrives with no opener installed at all.
    #[tokio::test]
    async fn opening_a_machine_outside_the_library_is_refused_before_connecting() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "limb.open",
            &json!({ "address": "203.0.113.7", "protocol": "vnc" }),
        )
        .await
        .expect_err("an arbitrary address is not a machine on offer");

        assert_eq!(refused.tag, Some("NO_SUCH_MACHINE"));
        assert!(
            refused.message.contains("203.0.113.7"),
            "{}",
            refused.message
        );
        assert!(
            refused.message.contains("Nothing was dialled"),
            "the refusal has to say that nothing happened: {}",
            refused.message
        );
    }

    /// A machine the person already has open is not opened twice. Slot 0
    /// adopts what is live (`02 §4.4`), which is what makes an agent and a
    /// person watch the same window.
    #[tokio::test]
    async fn opening_a_machine_that_is_already_open_hands_back_that_session() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        let answer = call(
            &fixture.ctx,
            &mut peer,
            "limb.open",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "port": 5900 }),
        )
        .await;
        assert_eq!(answer["opened"], false);
        assert_eq!(answer["reused"], true);
        assert_eq!(answer["sessionId"], "s1");
    }

    /// The open path in full. The agent names a machine, the application is
    /// asked for it exactly as a person's click would ask, and the reply comes
    /// back when the session is SPAWNED rather than when it is connected.
    ///
    /// The credential is the interesting absence: [`OpenAsk`] has no field for
    /// one, so there is nothing for this test to assert is empty. That is the
    /// design (`00 R19`, `09 §4`), and the assertion that stands in for it is
    /// on the ask that actually crossed.
    #[tokio::test]
    async fn an_open_asks_the_application_and_answers_as_soon_as_the_session_is_spawned() {
        let asked: Arc<Mutex<Option<OpenAsk>>> = Arc::new(Mutex::new(None));
        let seen = asked.clone();
        install_opener(Arc::new(move |ask: OpenAsk, tell| {
            *seen.lock() = Some(ask);
            let _ = tell.send(Ok(Opened {
                session_id: "s2".to_string(),
                reused: false,
            }));
        }));

        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        // The same address the live session is on, so it is a machine this
        // shell publishes, at a different endpoint, so nothing is live for it.
        let answer = call(
            &fixture.ctx,
            &mut peer,
            "limb.open",
            json!({ "address": "10.0.0.5", "protocol": "ssh", "port": 22 }),
        )
        .await;

        assert_eq!(answer["opened"], true);
        assert_eq!(answer["sessionId"], "s2");
        assert_eq!(answer["reused"], false);
        assert_eq!(
            answer["connected"], false,
            "a spawned session has not connected and this never says it has"
        );
        assert_eq!(
            answer["registered"], false,
            "and the webview has not called connect_session yet either"
        );
        assert!(
            answer["why"]
                .as_str()
                .expect("a sentence")
                .contains("asynchronous"),
            "the reply has to say that opening does not finish here"
        );

        let ask = seen_ask(&asked);
        assert_eq!(ask.address, "10.0.0.5");
        assert_eq!(ask.port, 22);
        assert_eq!(ask.protocol, "ssh");
        assert_eq!(ask.host_id, None, "no saved machine was named");
    }

    fn seen_ask(asked: &Arc<Mutex<Option<OpenAsk>>>) -> OpenAsk {
        asked
            .lock()
            .clone()
            .expect("the application was asked to open a machine")
    }

    /// A connection that did not ask for `open` cannot open, and the refusal
    /// comes before the credential check has anything to refuse.
    #[tokio::test]
    async fn open_is_refused_on_a_connection_whose_grant_does_not_name_it() {
        let fixture = fixture();
        let mut peer = Peer::default();
        call(
            &fixture.ctx,
            &mut peer,
            "hello",
            json!({
                "protocol": PROTOCOL,
                "client": { "name": "test" },
                "capabilities": ["view", "control"],
            }),
        )
        .await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "limb.open",
            &json!({ "address": "10.0.0.5", "protocol": "vnc" }),
        )
        .await
        .expect_err("open is not held here");
        assert_eq!(refused.tag, Some("MISSING_CAPABILITY"));
    }

    // ---------------------------------------------------------------------
    // `files.*` (`02 §5.2`, PRD/08's sidecar).
    // ---------------------------------------------------------------------

    /// A connection holding exactly these capabilities, attached to the one
    /// live session the fixture has.
    async fn attached_holding(ctx: &Ctx, capabilities: &[&str]) -> Peer {
        let mut peer = Peer::default();
        call(
            ctx,
            &mut peer,
            "hello",
            json!({
                "protocol": PROTOCOL,
                "client": { "name": "test" },
                "capabilities": capabilities,
            }),
        )
        .await;
        call(
            ctx,
            &mut peer,
            "limb.attach",
            json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
        )
        .await;
        peer
    }

    /// Reading somebody's disk costs `files.read`, and a connection that did
    /// not ask for it does not get it by holding everything else.
    ///
    /// The interesting half is that `control` IS in the grant here. Holding
    /// the keyboard on a machine is not authority to copy its files off it,
    /// and every read verb refuses with the tag an agent branches on and the
    /// capability named, rather than answering an empty listing that would
    /// read as an empty directory.
    #[tokio::test]
    async fn every_read_verb_is_refused_without_files_read() {
        let disk = Arc::new(Disk::default());
        disk.put("~/notes.txt", b"hello");
        let fixture = fixture_with_disk(disk);
        let mut peer = attached_holding(&fixture.ctx, &["view", "capture", "control"]).await;

        for (method, params) in [
            ("files.home", json!({ "sessionId": "s1" })),
            ("files.list", json!({ "sessionId": "s1", "path": "~" })),
            (
                "files.get",
                json!({ "sessionId": "s1", "path": "~/notes.txt" }),
            ),
        ] {
            let refused = dispatch(&fixture.ctx, &mut peer, method, &params)
                .await
                .expect_err("files.read is not held here");
            assert_eq!(refused.tag, Some("MISSING_CAPABILITY"), "{method}");
            assert!(
                refused.message.contains("files.read"),
                "{method} has to name the capability: {}",
                refused.message
            );
        }
    }

    /// Every verb that changes something costs `files.write`, and holding
    /// `files.read` buys none of it.
    ///
    /// `files.read` is deliberately in the grant for this test. The pair is
    /// split because the two authorities are different, not because writing is
    /// simply more of reading, and a build where one implied the other would
    /// pass a test that only checked the empty grant.
    #[tokio::test]
    async fn every_write_verb_is_refused_on_a_grant_that_only_reads() {
        let disk = Arc::new(Disk::default());
        disk.put("~/keep.txt", b"still here");
        let fixture = fixture_with_disk(disk.clone());
        let mut peer = attached_holding(&fixture.ctx, &["view", "control", "files.read"]).await;

        for (method, params) in [
            (
                "files.put",
                json!({ "sessionId": "s1", "path": "~/keep.txt", "contentBase64": "" }),
            ),
            ("files.mkdir", json!({ "sessionId": "s1", "path": "~/new" })),
            (
                "files.remove",
                json!({ "sessionId": "s1", "path": "~/keep.txt" }),
            ),
            (
                "files.rename",
                json!({ "sessionId": "s1", "from": "~/keep.txt", "to": "~/gone.txt" }),
            ),
        ] {
            let refused = dispatch(&fixture.ctx, &mut peer, method, &params)
                .await
                .expect_err("files.write is not held here");
            assert_eq!(refused.tag, Some("MISSING_CAPABILITY"), "{method}");
            assert!(
                refused.message.contains("files.write"),
                "{method} has to name the capability: {}",
                refused.message
            );
        }

        // …and the machine is untouched. A refusal that had already deleted
        // the file would be the worst possible kind.
        assert_eq!(
            disk.read("~/keep.txt").as_deref(),
            Some(&b"still here"[..]),
            "a refused write must not have happened"
        );
        assert!(
            disk.read("~/gone.txt").is_none(),
            "and must not have happened under another name either"
        );
    }

    /// The path an agent names comes back resolved, and the resolved one is
    /// the one the next call can use.
    ///
    /// `~` is the case worth pinning. An agent listing `~` is told the
    /// absolute directory that was, so the path it puts a file into is a path
    /// it was given rather than one it assembled, and a rename answers with
    /// where the file ended up rather than echoing the argument back.
    #[tokio::test]
    async fn a_path_round_trips_from_home_through_a_listing_and_a_rename() {
        let disk = Arc::new(Disk::default());
        let fixture = fixture_with_disk(disk.clone());
        let mut peer = attached_holding(
            &fixture.ctx,
            &["view", "control", "files.read", "files.write"],
        )
        .await;

        let home = call(
            &fixture.ctx,
            &mut peer,
            "files.home",
            json!({ "sessionId": "s1" }),
        )
        .await;
        assert_eq!(home["path"], FAKE_HOME);

        let wrote = call(
            &fixture.ctx,
            &mut peer,
            "files.put",
            json!({
                "sessionId": "s1",
                "path": "~/report.txt",
                "contentBase64": base64::engine::general_purpose::STANDARD.encode("done"),
            }),
        )
        .await;
        assert_eq!(wrote["path"], format!("{FAKE_HOME}/report.txt"));
        assert_eq!(wrote["written"], 4);
        assert_eq!(wrote["size"], 4);

        let listed = call(
            &fixture.ctx,
            &mut peer,
            "files.list",
            json!({ "sessionId": "s1", "path": "~" }),
        )
        .await;
        assert_eq!(
            listed["path"], FAKE_HOME,
            "a listing says which directory it is of, resolved"
        );
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["entries"][0]["name"], "report.txt");
        assert_eq!(
            listed["entries"][0]["path"],
            format!("{FAKE_HOME}/report.txt"),
            "the entry carries the absolute path, so the next call does not build one"
        );
        assert_eq!(listed["entries"][0]["isDir"], false);
        assert_eq!(
            listed["entries"][0]["size"], 4,
            "the listing is camelCase and carries the size the IPC contract spells"
        );

        // The path off the listing, used verbatim, is the one that works.
        let renamed = call(
            &fixture.ctx,
            &mut peer,
            "files.rename",
            json!({
                "sessionId": "s1",
                "from": listed["entries"][0]["path"],
                "to": "~/report.final.txt",
            }),
        )
        .await;
        assert_eq!(renamed["path"], format!("{FAKE_HOME}/report.final.txt"));
        assert_eq!(renamed["renamed"], true);
        assert!(disk.read("~/report.txt").is_none());
        assert_eq!(
            disk.read("~/report.final.txt").as_deref(),
            Some(&b"done"[..])
        );
    }

    /// The claim the whole feature stands on: a file is BYTES.
    ///
    /// The payload here is deliberately hostile to anything that treats a file
    /// as text. It carries a NUL, a lone `0xFF` which is not valid UTF-8, a
    /// CRLF that a line ending conversion would eat, and a `0x1A` which is
    /// end of file on DOS. A `.exe` short by one byte, or with its line
    /// endings helpfully fixed, is a `.exe` that fails on somebody else's
    /// machine with nothing to point at, so this asserts equality of the whole
    /// vector and not of its length.
    #[tokio::test]
    async fn a_binary_file_survives_the_envelope_byte_for_byte() {
        let mut payload: Vec<u8> = vec![
            0x4D, 0x5A, 0x90, 0x00, 0x00, 0xFF, 0x0D, 0x0A, 0x1A, 0x00, 0xC3, 0x28,
        ];
        // …and every byte value, so nothing can pass by accident.
        payload.extend((0u16..=255).map(|b| b as u8));

        let disk = Arc::new(Disk::default());
        let fixture = fixture_with_disk(disk.clone());
        let mut peer = attached_holding(
            &fixture.ctx,
            &["view", "control", "files.read", "files.write"],
        )
        .await;

        let wrote = call(
            &fixture.ctx,
            &mut peer,
            "files.put",
            json!({
                "sessionId": "s1",
                "path": "~/setup.exe",
                "contentBase64": base64::engine::general_purpose::STANDARD.encode(&payload),
                "mode": 0o755,
            }),
        )
        .await;
        assert_eq!(wrote["written"], payload.len());
        assert_eq!(
            disk.read("~/setup.exe").as_deref(),
            Some(payload.as_slice()),
            "what reached the machine is what the agent sent"
        );

        let got = call(
            &fixture.ctx,
            &mut peer,
            "files.get",
            json!({ "sessionId": "s1", "path": "~/setup.exe" }),
        )
        .await;
        assert_eq!(got["eof"], true);
        assert_eq!(got["size"], payload.len());
        let back = base64::engine::general_purpose::STANDARD
            .decode(got["contentBase64"].as_str().expect("base64 content"))
            .expect("the content decodes");
        assert_eq!(
            back, payload,
            "and what came back is what is on the machine"
        );
    }

    /// A file bigger than one envelope crosses in windows and arrives whole.
    ///
    /// This is the property that makes the cap a cap and not a ceiling on file
    /// size: `offset` zero truncates, every later offset writes in place, and
    /// `eof` is what tells a reader's loop to stop. A build where a second put
    /// truncated would pass every single window test and still deliver a file
    /// holding only its last chunk.
    #[tokio::test]
    async fn a_file_larger_than_one_call_crosses_in_windows_and_arrives_whole() {
        // A pattern rather than a repeat, so a window written at the wrong
        // offset shows up as wrong content and not just as a wrong length.
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let window = 1000;

        let disk = Arc::new(Disk::default());
        let fixture = fixture_with_disk(disk.clone());
        let mut peer = attached_holding(
            &fixture.ctx,
            &["view", "control", "files.read", "files.write"],
        )
        .await;

        let mut offset = 0usize;
        while offset < payload.len() {
            let end = (offset + window).min(payload.len());
            let wrote = call(
                &fixture.ctx,
                &mut peer,
                "files.put",
                json!({
                    "sessionId": "s1",
                    "path": "~/big.bin",
                    "offset": offset,
                    "contentBase64": base64::engine::general_purpose::STANDARD
                        .encode(&payload[offset..end]),
                }),
            )
            .await;
            assert_eq!(wrote["offset"], offset);
            offset = end;
        }
        assert_eq!(
            disk.read("~/big.bin").as_deref(),
            Some(payload.as_slice()),
            "fifty small writes are one whole file"
        );

        let mut read_back = Vec::new();
        loop {
            let got = call(
                &fixture.ctx,
                &mut peer,
                "files.get",
                json!({
                    "sessionId": "s1",
                    "path": "~/big.bin",
                    "offset": read_back.len(),
                    "length": window,
                }),
            )
            .await;
            read_back.extend(
                base64::engine::general_purpose::STANDARD
                    .decode(got["contentBase64"].as_str().expect("base64 content"))
                    .expect("the content decodes"),
            );
            if got["eof"].as_bool().expect("an eof flag") {
                break;
            }
        }
        assert_eq!(read_back, payload);
    }

    /// A window bigger than the envelope is refused BY NAME, in both
    /// directions, and nothing is truncated on the way.
    #[tokio::test]
    async fn a_window_above_the_cap_is_refused_rather_than_clamped() {
        let fixture = fixture();
        let mut peer = attached_holding(
            &fixture.ctx,
            &["view", "control", "files.read", "files.write"],
        )
        .await;

        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "files.get",
            &json!({
                "sessionId": "s1",
                "path": "~/big.bin",
                "length": MAX_FILE_CHUNK + 1,
            }),
        )
        .await
        .expect_err("above the cap");
        assert_eq!(refused.code, -32602);
        assert!(
            refused.message.contains(&MAX_FILE_CHUNK.to_string()),
            "the refusal has to name the number: {}",
            refused.message
        );
        assert!(
            refused.message.contains("windows"),
            "and has to say what to do instead: {}",
            refused.message
        );

        let too_big =
            base64::engine::general_purpose::STANDARD.encode(vec![0u8; MAX_FILE_CHUNK + 1]);
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "files.put",
            &json!({ "sessionId": "s1", "path": "~/big.bin", "contentBase64": too_big }),
        )
        .await
        .expect_err("above the cap");
        assert!(
            refused.message.contains("Nothing was written"),
            "a refused put has to say the file is untouched: {}",
            refused.message
        );
        assert!(
            fixture.disk.read("~/big.bin").is_none(),
            "and it has to be true"
        );
    }

    /// Content that is not base64 is refused and nothing is written.
    ///
    /// Refused rather than decoded as far as it goes: a file written from a
    /// half decoded payload is corrupt in a way nothing downstream detects.
    #[tokio::test]
    async fn a_put_whose_content_is_not_base64_writes_nothing() {
        let fixture = fixture();
        let mut peer = attached_holding(
            &fixture.ctx,
            &["view", "control", "files.read", "files.write"],
        )
        .await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "files.put",
            &json!({ "sessionId": "s1", "path": "~/x.bin", "contentBase64": "not base64!!" }),
        )
        .await
        .expect_err("that is not base64");
        assert_eq!(refused.code, -32602);
        assert!(fixture.disk.read("~/x.bin").is_none());
    }

    /// A machine with no SSH says so, in a sentence naming what is missing and
    /// what to do instead.
    ///
    /// `04 §4.1`'s habit: an agent told "not available, because that machine
    /// runs no SSH server" stops asking, and an agent told "error" retries
    /// until something gives up.
    #[tokio::test]
    async fn a_machine_with_no_sftp_sidecar_is_refused_with_a_reason() {
        let fixture = fixture_with_disk(Disk::offline());
        let mut peer = attached_holding(&fixture.ctx, &["view", "files.read"]).await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "files.list",
            &json!({ "sessionId": "s1", "path": "~" }),
        )
        .await
        .expect_err("no ssh on that machine");
        assert_eq!(refused.tag, Some("FILES_UNAVAILABLE"));
        assert!(refused.message.contains("SSH"), "{}", refused.message);
    }

    /// A person taking the wheel stops a file transfer, exactly as it stops a
    /// command.
    ///
    /// The lease check runs before the capability check and before a path is
    /// parsed, so a revoked attachment cannot read a file by holding the right
    /// capability, and it learns nothing about the machine on the way.
    #[tokio::test]
    async fn taking_the_wheel_stops_the_next_file_call() {
        let disk = Arc::new(Disk::default());
        disk.put("~/secret.txt", b"private");
        let fixture = fixture_with_disk(disk);
        let mut peer = attached_holding(
            &fixture.ctx,
            &["view", "control", "files.read", "files.write"],
        )
        .await;

        fixture.ctx.plane.revoke("s1");
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "files.get",
            &json!({ "sessionId": "s1", "path": "~/secret.txt" }),
        )
        .await
        .expect_err("a person is driving");
        assert_eq!(refused.tag, Some("LEASE_REVOKED"));
    }

    /// A file verb against a session this connection never attached is
    /// refused, so `files.*` is no way around the attachment.
    #[tokio::test]
    async fn a_file_call_against_a_session_this_connection_never_attached_is_refused() {
        let fixture = fixture();
        let mut peer = greeted(&fixture.ctx).await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "files.list",
            &json!({ "sessionId": "s1", "path": "~" }),
        )
        .await
        .expect_err("nothing was attached");
        assert_eq!(refused.tag, Some("NOT_ATTACHED"));
    }

    /// An empty path is refused rather than guessed at.
    ///
    /// The verb that makes this matter is `remove`: a guess that resolved an
    /// empty path to the home directory would delete somebody's home
    /// directory, and there is no version of that which is worth the
    /// convenience.
    #[tokio::test]
    async fn an_empty_path_is_refused_rather_than_read_as_the_home_directory() {
        let fixture = fixture();
        let mut peer = attached_holding(&fixture.ctx, &["view", "files.write"]).await;
        let refused = dispatch(
            &fixture.ctx,
            &mut peer,
            "files.remove",
            &json!({ "sessionId": "s1", "path": "" }),
        )
        .await
        .expect_err("an empty path names nothing");
        assert_eq!(refused.code, -32602);
        assert!(refused.message.contains("path"), "{}", refused.message);
    }

    /// The plane starts from a thread with no reactor in context.
    ///
    /// **A plain `#[test]` on purpose, and it must stay one.** Every other test
    /// in this file is `#[tokio::test]`, which brings a reactor with it, and
    /// that reactor is exactly what hid this: `tokio::net::UnixListener::from_std`
    /// registers the socket with the reactor and PANICS when there is none.
    /// The caller that matters is Tauri's `setup` hook, which runs on the main
    /// thread outside the runtime, and `setup` cannot unwind, so the panic
    /// aborted the process before the first window. The setting that started
    /// the plane is stored, so every launch after that did the same thing and
    /// the application could not be opened at all.
    ///
    /// 2592 tests passed over that bug because not one of them started the
    /// plane the way the product starts it. This one does.
    #[test]
    fn the_plane_starts_from_a_thread_with_no_reactor() {
        let fixture = fixture();
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("agent.sock");
        let plane = fixture.ctx.plane.clone();

        let started = crate::agent::start(&plane, Arc::new(fixture.ctx), path.clone());

        assert!(
            started.is_ok(),
            "the plane refused to start off the runtime: {started:?}"
        );
        assert!(path.exists(), "the socket was not created at {path:?}");
        crate::agent::stop(&plane);
    }
}
