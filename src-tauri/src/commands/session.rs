//! Session commands: connect, event forwarding, input, lifecycle.
//!
//! Data paths (PRD/01 §3, §5):
//! - Framebuffer updates and cursor shapes go to the webview **binary** over
//!   the `tauri::ipc::Channel` captured at connect time
//!   (`InvokeResponseBody::Raw`, framing in `crate::framing` /
//!   `src-tauri/FRAME_FORMAT.md`).
//! - Everything else goes as small JSON via
//!   `emit_to(window_label, "session://event", …)`.
//! - Input comes back as a raw binary body (`send_input`).
//!
//! SECURITY INVARIANT: stored credentials are loaded in Rust (on a blocking
//! thread) while building `ConnectOptions`, they NEVER pass through JS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tauri::ipc::{Channel, InvokeBody, InvokeResponseBody};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::mpsc;
use vnc_core::{
    ClientCommand, ConnectOptions, ProtocolEvent, ProtocolKind, ProtocolOptions, QualityPreset,
    RdpEvent, SessionEvent, SessionState,
};

use crate::state::{AppState, ExistingWindow, MachineKey, PendingCredentialSave, SessionEntry};
use crate::windows::validate_session_id;
use crate::{framing, windows};

/// App-wide session lifecycle broadcast (`emit`, every window), so the Library
/// can track which machines are connected without owning any session window.
///
/// Flat payloads on a `type` discriminator:
/// `{ type: "started", sessionId, profileId, address, port }`,
/// `{ type: "state", sessionId, state }` (`state` is only the kebab-case tag),
/// `{ type: "ended", sessionId }`,
/// `{ type: "host-adopted", sessionId, profileId, address, port }` (an ad-hoc
/// session just gained a host profile, see [`adopt_session_host`]; the Library
/// re-reads its host list on it).
pub const SESSIONS_EVENT: &str = "sessions://event";

/// App-wide per-session stats broadcast (`emit`, 1 Hz per connected session):
/// `{ sessionId, profileId, address, port, stats }`, top-level keys camelCase,
/// `stats` a full snake_case `SessionStats`.
pub const SESSIONS_STATS_EVENT: &str = "sessions://stats";

/// Map a profile's `quality_pref` string (PRD/03 §5 schema) onto the core
/// preset. Unknown values fall back to Auto.
fn parse_quality(pref: &str) -> QualityPreset {
    match pref {
        "high" => QualityPreset::High,
        "medium" => QualityPreset::Medium,
        "low" => QualityPreset::Low,
        "bw" | "black-and-white" => QualityPreset::BlackAndWhite,
        _ => QualityPreset::Auto,
    }
}

/// Convert a non-framebuffer session event to its JSON payload
/// (`session://event`). Returns `None` for events that travel on the binary
/// channel instead. Server-derived strings (desktop name, clipboard, error
/// text) are forwarded verbatim as JSON string values; the UI must render
/// them as text only, never HTML.
fn event_json(session_id: &str, event: &SessionEvent) -> Option<serde_json::Value> {
    use serde_json::json;
    let mut value = match event {
        SessionEvent::StateChanged(s) => json!({ "type": "state-changed", "state": s }),
        SessionEvent::DesktopResize { width, height } => {
            json!({ "type": "desktop-resize", "width": width, "height": height })
        }
        SessionEvent::DesktopName(name) => json!({ "type": "desktop-name", "name": name }),
        SessionEvent::ScreenLayout { screens } => json!({
            "type": "screen-layout",
            // `flags` stays behind: the RFB spec assigns it no meaning yet.
            "screens": screens.iter().map(|s| json!({
                "id": s.id, "x": s.x, "y": s.y, "width": s.width, "height": s.height,
            })).collect::<Vec<_>>(),
        }),
        SessionEvent::CursorPosition { x, y } => {
            json!({ "type": "cursor-position", "x": x, "y": y })
        }
        SessionEvent::ClipboardText(text) => json!({ "type": "clipboard-text", "text": text }),
        SessionEvent::ClipboardNotify { formats } => {
            json!({ "type": "clipboard-notify", "formats": formats })
        }
        SessionEvent::Bell => json!({ "type": "bell" }),
        SessionEvent::CertificatePrompt {
            fingerprint,
            subject,
            is_change,
            scheme,
        } => json!({
            "type": "certificate-prompt",
            "fingerprint": fingerprint,
            "subject": subject,
            "isChange": is_change,
            // Plumbing, not copy: the UI never shows this, it just hands it
            // back to `trust_certificate` so the pin lands under the right key.
            "scheme": scheme,
        }),
        SessionEvent::CredentialsRequired(req) => {
            json!({ "type": "credentials-required", "request": req })
        }
        SessionEvent::Stats(stats) => json!({ "type": "stats", "stats": stats }),
        SessionEvent::Error(message) => json!({ "type": "error", "message": message }),
        // Binary channel traffic, not JSON.
        SessionEvent::FramebufferUpdate { .. } | SessionEvent::CursorUpdate(_) => return None,
        // The samples go to the audio device, never to the webview: a JSON
        // array of PCM is the audio equivalent of shipping a whole
        // framebuffer across IPC. What the UI is told is the FORMAT, and it
        // is told once per change rather than once per packet, which needs
        // state this function does not have; `forward_events` does it.
        SessionEvent::Audio(_) => return None,
        // Addressed to the agent that issued the intent, not to the webview.
        // The person at this window issued nothing and has nothing to do about
        // it, and the agent plane reads the driver's event stream directly, so
        // turning a refusal into a toast would be news for the wrong reader
        // (PRDAgentPlug/00 R28). Dropped HERE and only here: the driver already
        // answered, which is the requirement.
        //
        // A served answer is dropped here for the same reason and one more of
        // its own: it carries what a remote machine printed, and remote output
        // is data, never instruction (AGENT_BRIEF D6). Turning it into a toast
        // would put a remote machine's bytes in our own UI for a person who
        // asked for none of it (PRDAgentPlug/00 R51b).
        SessionEvent::AgentRefused(_) | SessionEvent::AgentServed(_) => return None,
        SessionEvent::Protocol(ProtocolEvent::Rdp(event)) => rdp_event_json(event)?,
        // Terminal bytes never become JSON. They go out on the binary channel
        // (`framing::encode_pty`) for the same reason framebuffer rectangles
        // do: base64 in a JSON envelope costs a third more bytes plus escaping
        // plus a `Value` allocation per chunk, and a fast-scrolling build log
        // makes that the bottleneck. `forward_events` routes them.
        SessionEvent::Protocol(ProtocolEvent::Ssh(
            remote_core::events::SshEvent::Output(_)
            | remote_core::events::SshEvent::ResetTerminal(_),
        )) => return None,
        SessionEvent::Protocol(ProtocolEvent::Ssh(event)) => ssh_event_json(event.clone())?,
        // A protocol this build's `remote-core` knows about and this match
        // does not. Dropped rather than guessed at, and the compiler makes
        // adding one a decision here rather than a silent omission.
        SessionEvent::Protocol(_) => return None,
    };
    if let serde_json::Value::Object(map) = &mut value {
        map.insert("sessionId".into(), json!(session_id));
    }
    Some(value)
}

/// Flatten one `RdpEvent` into the JSON the webview sees.
///
/// The field names on the Rust side are `remote-core`'s and this function
/// does not reshape them; it renames two for the wire (`username` becomes
/// `user`, `session_id` becomes `remoteSessionId`) and adds nothing. Every
/// string in here is SERVER SUPPLIED, so the UI renders it as text and never
/// as HTML, exactly as it already does for `desktop-name`.
///
/// The ERRINFO table is not restated here or in TypeScript: `rdp-pdu` owns
/// it, the driver has already turned the code into a symbol and a sentence,
/// and this passes all three through so a bug report can carry the raw value.
/// The SSH news that is small enough, and rare enough, to be JSON.
///
/// Only the metadata: which multiplexer got attached, whether it resumed real
/// work, and the occasional notice. The byte streams are handled above.
fn ssh_event_json(event: remote_core::events::SshEvent) -> Option<serde_json::Value> {
    use remote_core::events::SshEvent;
    Some(match event {
        SshEvent::Attached {
            multiplexer,
            resumed,
        } => serde_json::json!({
            "type": "ssh-attached",
            // `null` for a plain login shell, either by choice or because the
            // host had no multiplexer. The UI tells those apart by the notice
            // that accompanies the second case.
            "multiplexer": multiplexer.map(|m| serde_json::to_value(m).ok()).unwrap_or(None),
            // True only when the attach found a session already running, which
            // is the case where the user's work survived a drop.
            "resumed": resumed,
        }),
        SshEvent::Notice(message) => {
            serde_json::json!({ "type": "ssh-notice", "message": message })
        }
        // Handled on the binary channel by the caller.
        SshEvent::Output(_) | SshEvent::ResetTerminal(_) => return None,
        // A variant a newer `remote-core` added. Dropped rather than guessed
        // at, the same rule the outer match follows.
        _ => return None,
    })
}

fn rdp_event_json(event: &RdpEvent) -> Option<serde_json::Value> {
    use serde_json::json;
    Some(match event {
        RdpEvent::LogonInfo {
            domain,
            username,
            session_id,
        } => json!({
            "type": "logon-info",
            "domain": domain,
            "user": username,
            "remoteSessionId": session_id,
        }),
        RdpEvent::LogonError {
            notification_type,
            notification_data,
            message,
        } => json!({
            "type": "logon-error",
            "notificationType": notification_type,
            "notificationData": notification_data,
            "message": message,
        }),
        RdpEvent::ErrorInfo {
            code,
            symbol,
            message,
        } => json!({
            "type": "error-info",
            "code": code,
            "symbol": symbol,
            "message": message,
        }),
        RdpEvent::Redirected { target, session_id } => json!({
            // Plumbing for the connecting overlay only: the driver performs
            // the redirect itself, the UI just stops naming the old host.
            "type": "redirect",
            "target": target,
            "remoteSessionId": session_id,
        }),
        // Deliberately payloadless: the cookie is a bearer secret and the
        // UI's only legitimate interest is "a fast reconnect is possible now".
        RdpEvent::AutoReconnectArmed => json!({ "type": "auto-reconnect-armed" }),
        RdpEvent::LicenseWarning { message } => {
            json!({ "type": "license-warning", "message": message })
        }
        // A variant added to `remote-core` since this was written. Ignored
        // rather than half rendered; the UI ignores unknown `type` values for
        // the same reason.
        _ => return None,
    })
}

/// Everything the event-forwarding task needs to settle a "remember this
/// password" intent once (and only once) the server has accepted it.
struct CredentialSaveCtx {
    store: Arc<vnc_store::Store>,
    credentials: Arc<vnc_store::CredentialStore>,
    pending: Arc<Mutex<HashMap<String, PendingCredentialSave>>>,
    /// Outstanding prompts, so a late-subscribing window can recover one.
    prompts: Arc<Mutex<HashMap<String, vnc_core::CredentialRequest>>>,
}

/// Write a proven credential to the keychain and flip the profile's
/// `has_password` flag.
///
/// Only ever called from the `SessionState::Connected` transition, i.e. after
/// the server accepted the password, see [`PendingCredentialSave`]. Keychain
/// and SQLite IO are synchronous, hence `spawn_blocking`.
fn persist_credentials(
    ctx: &CredentialSaveCtx,
    profile_id: String,
    pending: PendingCredentialSave,
) {
    let store = ctx.store.clone();
    let credentials = ctx.credentials.clone();
    tauri::async_runtime::spawn_blocking(move || {
        write_credentials(&store, &credentials, &profile_id, &pending);
    });
}

/// The blocking half of [`persist_credentials`]. Split out so the adopt-a-host
/// path can write the profile and its credential on one blocking thread,
/// in that order.
fn write_credentials(
    store: &vnc_store::Store,
    credentials: &vnc_store::CredentialStore,
    profile_id: &str,
    pending: &PendingCredentialSave,
) {
    // Merge rather than replace: a host may already have an SSH
    // passphrase stored alongside its VNC password.
    let existing = match credentials.load(profile_id) {
        Ok(existing) => existing,
        Err(e) => {
            tracing::warn!("could not read existing credentials before save: {e}");
            None
        }
    };
    let merged = pending.merge_into(existing);
    if let Err(e) = credentials.save(profile_id, &merged) {
        tracing::warn!(profile = %profile_id, "failed to save credentials: {e}");
        return;
    }
    // Mirror the flag the library uses to draw the key icon. A failure
    // here is cosmetic, the secret itself is already stored.
    match store.get_host(profile_id) {
        Ok(Some(mut profile)) => {
            if !profile.has_password {
                profile.has_password = true;
                if let Err(e) = store.save_host(&profile) {
                    tracing::warn!(profile = %profile_id, "failed to set has_password: {e}");
                }
            }
        }
        Ok(None) => {
            tracing::warn!(profile = %profile_id, "profile vanished before has_password update")
        }
        Err(e) => tracing::warn!(profile = %profile_id, "could not load profile: {e}"),
    }
    tracing::info!(profile = %profile_id, "saved credentials after a successful connect");
}

/// Where a proven credential belongs.
///
/// Split out of [`settle_pending_credentials`] so the rule can be tested
/// without a running app, in particular the one that is easy to break: a
/// session that asked for nothing must reach [`CredentialHome::Nowhere`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialHome {
    /// Do nothing. Either nothing was asked for (a plain quick connect must
    /// leave no trace in the library at all) or the session is already gone,
    /// in which case there is no endpoint left to attribute the secret to.
    Nowhere,
    /// The session's saved host profile.
    Profile(String),
    /// An ad-hoc session that asked to be remembered. Credentials are keyed by
    /// host id, so its endpoint has to become a host profile first.
    AdoptEndpoint { address: String, port: u16 },
}

fn credential_home(save_requested: bool, session: Option<&SessionEntry>) -> CredentialHome {
    let Some(entry) = session.filter(|_| save_requested) else {
        return CredentialHome::Nowhere;
    };
    match &entry.profile_id {
        Some(profile_id) => CredentialHome::Profile(profile_id.clone()),
        None => CredentialHome::AdoptEndpoint {
            address: entry.address.clone(),
            port: entry.port,
        },
    }
}

/// Turn an ad-hoc session into a saved host so its remembered password has
/// somewhere to live, then store the password against it.
///
/// Everything after the profile write is deliberately in the same blocking
/// closure: the credential must not be written under an id the hosts table
/// does not have yet, and the Library must not be told about a host before it
/// can read it back.
#[allow(clippy::too_many_arguments)] // internal plumbing fan-out, not an API
fn adopt_session_host(
    app: &AppHandle,
    ctx: &CredentialSaveCtx,
    sessions: &Arc<Mutex<HashMap<String, SessionEntry>>>,
    session_id: &str,
    protocol: ProtocolKind,
    address: String,
    port: u16,
    pending: PendingCredentialSave,
) {
    let app = app.clone();
    let store = ctx.store.clone();
    let credentials = ctx.credentials.clone();
    let sessions = sessions.clone();
    let session_id = session_id.to_string();
    tauri::async_runtime::spawn_blocking(move || {
        // The session's own protocol, not a default: quick connecting to
        // `rdp://box`, ticking remember and getting a saved host that says
        // VNC would be a bug, and the profile would then dial the wrong
        // protocol for ever after.
        let profile = match store.adopt_endpoint_for(protocol, &address, port) {
            Ok(profile) => profile,
            Err(e) => {
                tracing::warn!(session = %session_id, "could not save a host for this session: {e}");
                return;
            }
        };
        // From here this is a saved-host session: thumbnail claiming, cert
        // trust and a later credential change all read `profile_id`, and all
        // of them should now behave as they would for a host the user had
        // added by hand.
        if let Some(entry) = sessions.lock().get_mut(&session_id) {
            entry.profile_id = Some(profile.id.clone());
        }
        // The connection this host was born from is live, so the tile would
        // otherwise claim the machine has never been connected to.
        if let Err(e) = store.touch_connected(&profile.id) {
            tracing::warn!(profile = %profile.id, "failed to record the connection: {e}");
        }
        write_credentials(&store, &credentials, &profile.id, &pending);
        tracing::info!(
            session = %session_id, profile = %profile.id,
            "saved a host profile for an ad-hoc session that remembered its password"
        );
        // The Library owns no session window, so this broadcast is the only
        // way the new host appears without the user reopening the window.
        let _ = app.emit(
            SESSIONS_EVENT,
            serde_json::json!({
                "type": "host-adopted",
                "sessionId": session_id,
                "profileId": profile.id,
                "address": profile.address,
                "port": profile.port,
                "protocol": profile.protocol,
            }),
        );
    });
}

/// Whether reaching `Connected` is proof that the credential was accepted.
///
/// For VNC it always is: every RFB security type either authenticates or
/// fails the handshake. For RDP it is only true when CredSSP ran. With NLA
/// off the credentials go out in the Client Info PDU and Windows evaluates
/// them inside the session, so the connection completes whether the password
/// was right or wrong, and writing it to the keychain there would store a
/// password nothing has ever accepted (PRDRDP/00 R14). Such a session settles
/// later, on the server's own logon notification, or not at all.
///
/// The method strings are `remote-core`'s stable identifiers, `nla-ntlm`,
/// `nla-kerberos` and `tls` (PRDRDP/00 R12), so the test is a prefix rather
/// than a list this file has to keep in step with phase 3.
fn connected_proves_the_credential(protocol: ProtocolKind, auth_method: Option<&str>) -> bool {
    match protocol {
        ProtocolKind::Rdp => auth_method.is_some_and(|m| m.starts_with("nla")),
        _ => true,
    }
}

/// Write whatever this session asked to remember, now that something has
/// proved it. Called from at most one place per session.
fn persist_now(
    app: &AppHandle,
    ctx: &CredentialSaveCtx,
    sessions: &Arc<Mutex<HashMap<String, SessionEntry>>>,
    session_id: &str,
) {
    let pending = ctx.pending.lock().remove(session_id);
    let (home, protocol) = {
        let sessions = sessions.lock();
        let entry = sessions.get(session_id);
        (
            credential_home(pending.is_some(), entry),
            entry.map(SessionEntry::protocol).unwrap_or_default(),
        )
    };
    match (home, pending) {
        (CredentialHome::Profile(profile_id), Some(pending)) => {
            persist_credentials(ctx, profile_id, pending)
        }
        (CredentialHome::AdoptEndpoint { address, port }, Some(pending)) => adopt_session_host(
            app, ctx, sessions, session_id, protocol, address, port, pending,
        ),
        // Nothing asked for, or nothing left to attribute it to.
        _ => {}
    }
}

/// React to a state change for the pending-credential lifecycle.
///
/// `Connected` is the only state that persists anything, and for RDP only
/// when NLA proved the credential; every terminal state drops the intent
/// without touching the keychain.
fn settle_pending_credentials(
    app: &AppHandle,
    ctx: &CredentialSaveCtx,
    sessions: &Arc<Mutex<HashMap<String, SessionEntry>>>,
    session_id: &str,
    state: &SessionState,
    auth_method: Option<&str>,
) {
    match state {
        SessionState::Connected => {
            let protocol = sessions
                .lock()
                .get(session_id)
                .map(SessionEntry::protocol)
                .unwrap_or_default();
            if connected_proves_the_credential(protocol, auth_method) {
                persist_now(app, ctx, sessions, session_id);
            } else {
                // Held, not dropped: the logon notification may still arrive
                // and prove it. The event stream closing drops it unwritten.
                tracing::debug!(
                    session = %session_id,
                    "connected without network level authentication, waiting for a logon before saving"
                );
            }
        }
        SessionState::Disconnected { .. } => {
            // Never persist a password the connection did not survive.
            let dropped = ctx.pending.lock().remove(session_id).is_some();
            if dropped {
                tracing::debug!(session = %session_id, "dropped unsaved credentials (disconnected)");
            }
        }
        _ => {}
    }
}

/// The machine a session is talking to, carried on every [`SESSIONS_EVENT`] /
/// [`SESSIONS_STATS_EVENT`] broadcast so the Library can map a session onto a
/// tile (profile id, or address:port for an ad-hoc connect) without a lookup.
struct SessionEndpoint {
    profile_id: Option<String>,
    address: String,
    port: u16,
    protocol: ProtocolKind,
}

/// The kebab-case tag of a `SessionState`, exactly as serde spells it in the
/// per-window `state-changed` event, extracted from the serialized form so
/// the two can never drift apart.
fn state_tag(state: &SessionState) -> Option<String> {
    let value = serde_json::to_value(state).ok()?;
    Some(value.get("state")?.as_str()?.to_string())
}

/// Forward a session's events until its event stream ends, then clean up the
/// registry entry and tell the UI the session is over.
#[allow(clippy::too_many_arguments)] // internal plumbing fan-out, not an API
fn forward_events(
    app: AppHandle,
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    creds_ctx: CredentialSaveCtx,
    session_id: String,
    window_label: String,
    endpoint: SessionEndpoint,
    mut rx: mpsc::Receiver<SessionEvent>,
    channel: Channel<InvokeResponseBody>,
) {
    tauri::async_runtime::spawn(async move {
        // Two facts this task remembers across events, because the pure
        // `event_json` cannot: how the session authenticated (which decides
        // whether reaching `Connected` proved the password) and the audio
        // format last announced (so a format event is emitted on change
        // rather than once per 20 ms packet).
        let mut auth_method: Option<String> = None;
        let mut audio_format: Option<(u32, u8)> = None;
        while let Some(event) = rx.recv().await {
            if let SessionEvent::StateChanged(SessionState::Authenticating { method }) = &event {
                auth_method = Some(method.clone());
            }
            // Two facts the shell used to forward and forget. The agent plane
            // has no window to hold them for it, and it needs both: it refuses
            // an intent against a limb that is not connected, and it bounds
            // every coordinate against the framebuffer size. See
            // `crate::state::SessionFacts`.
            match &event {
                SessionEvent::StateChanged(state) => {
                    if let Some(entry) = sessions.lock().get(&session_id) {
                        entry.facts.lock().state = state.clone();
                    }
                }
                SessionEvent::DesktopResize { width, height } => {
                    if let Some(entry) = sessions.lock().get(&session_id) {
                        entry.facts.lock().size = Some((*width, *height));
                    }
                    // A resize bumps the geometry generation, which is what
                    // fences an agent's in flight coordinate against a screen
                    // that changed under it (PRDAgentPlug/00 R10). A human
                    // corrects a misplaced click in 50 ms without noticing; an
                    // agent does not, because it is waiting for a result.
                    if let Some(state) = app.try_state::<AppState>() {
                        state.agent.note_resize(&session_id, *width, *height);
                    }
                }
                // A driver's answer to an agent intent. This pump is the only
                // reader of the session's event stream, and the party waiting
                // for the answer is an `AttachedLimb` in the agent's own
                // process on the far side of the socket, so without this arm
                // the command really runs and the answer is dropped here:
                // `dvv_run` would report a timeout for work that succeeded.
                //
                // `event_json` returns `None` for both variants and that stays
                // right (`00 R50c`): they are addressed to the plane, not to
                // the person watching the window, and a served answer carries
                // a remote machine's own bytes.
                SessionEvent::AgentServed(_) | SessionEvent::AgentRefused(_) => {
                    crate::agent::server::note_agent_event(&session_id, &event);
                }
                _ => {}
            }
            if let SessionEvent::StateChanged(state) = &event {
                settle_pending_credentials(
                    &app,
                    &creds_ctx,
                    &sessions,
                    &session_id,
                    state,
                    auth_method.as_deref(),
                );
                // Any state transition means the handshake moved on, so an
                // outstanding prompt is no longer answerable.
                if !matches!(state, SessionState::Authenticating { .. }) {
                    creds_ctx.prompts.lock().remove(&session_id);
                }
                // Forget the button mask `send_input` sheds motion against.
                //
                // A reconnect keeps this registry entry but builds the
                // backend's input state from scratch, and input queued while
                // the session was down is discarded, so the cached mask can
                // outlive the only thing that made it true. A real press whose
                // mask happened to match it would then look like pure motion
                // and be dropped under backpressure. `-1` is no mask at all,
                // so the next pointer event is state changing whatever it
                // carries.
                if let Some(entry) = sessions.lock().get(&session_id) {
                    entry
                        .last_pointer_mask
                        .store(-1, std::sync::atomic::Ordering::Relaxed);
                }
                // App-wide mirror for the Library's connected-machine tracking
                //, only the tag; anyone who needs the full state owns the
                // session window and hears `session://event`.
                if let Some(tag) = state_tag(state) {
                    let _ = app.emit(
                        SESSIONS_EVENT,
                        serde_json::json!({
                            "type": "state",
                            "sessionId": session_id,
                            "state": tag,
                        }),
                    );
                }
            }
            // Bandwidth broadcast for the Library's tile overlays, in
            // addition to the per-window stats event below.
            if let SessionEvent::Stats(stats) = &event {
                let _ = app.emit(
                    SESSIONS_STATS_EVENT,
                    serde_json::json!({
                        "sessionId": session_id,
                        "profileId": endpoint.profile_id,
                        "address": endpoint.address,
                        "port": endpoint.port,
                        "protocol": endpoint.protocol,
                        "stats": stats,
                    }),
                );
            }
            // A non-NLA RDP session cannot prove its password by connecting,
            // so the server's own logon notification is what settles it.
            if let SessionEvent::Protocol(ProtocolEvent::Rdp(RdpEvent::LogonInfo { .. })) = &event {
                persist_now(&app, &creds_ctx, &sessions, &session_id);
            }
            // The samples never become JSON; the format does, once, and again
            // only if the server changes it.
            if let SessionEvent::Audio(packet) = &event {
                let now = (packet.sample_rate, packet.channels);
                if audio_format != Some(now) {
                    audio_format = Some(now);
                    let _ = app.emit_to(
                        &window_label,
                        "session://event",
                        serde_json::json!({
                            "sessionId": session_id,
                            "type": "audio-format",
                            "sampleRate": packet.sample_rate,
                            "channels": packet.channels,
                        }),
                    );
                }
            }
            // Record the question so a window that subscribed late can still
            // ask for it (see AppState::pending_prompts).
            if let SessionEvent::CredentialsRequired(req) = &event {
                creds_ctx
                    .prompts
                    .lock()
                    .insert(session_id.clone(), req.clone());
            }
            match event {
                SessionEvent::FramebufferUpdate { rects, damage } => {
                    // The agent plane is the SECOND consumer of this stream and
                    // it must stay second: the webview's frame is what a person
                    // is looking at, so it goes first and is never delayed by
                    // anything an agent asked for (PRDAgentPlug/03 §2.1). With
                    // no mirror attached this is a lock and a length check.
                    if let Some(state) = app.try_state::<AppState>() {
                        state.agent.feed(&session_id, &rects);
                    }
                    // Binary fast path; framing per FRAME_FORMAT.md (msg_type 1).
                    let bytes = framing::encode_frame(&rects, &damage);
                    if let Err(e) = channel.send(InvokeResponseBody::Raw(bytes)) {
                        tracing::warn!(session = %session_id, "frame channel send failed: {e}");
                    }
                }
                SessionEvent::CursorUpdate(shape) => {
                    // Binary too (msg_type 2), cursor pixels are RGBA blobs.
                    let bytes = framing::encode_cursor(&shape);
                    if let Err(e) = channel.send(InvokeResponseBody::Raw(bytes)) {
                        tracing::warn!(session = %session_id, "cursor channel send failed: {e}");
                    }
                }
                // Terminal bytes take the same binary path as pixels
                // (msg_type 3), and for the same reason: base64 in a JSON
                // envelope costs a third more bytes plus escaping plus a
                // `Value` allocation per chunk, which a fast-scrolling build
                // log turns into the bottleneck. The session has already
                // coalesced these, so one message is a batch of PTY reads.
                SessionEvent::Protocol(ProtocolEvent::Ssh(
                    remote_core::events::SshEvent::Output(data),
                )) => {
                    let bytes = framing::encode_pty(framing::PTY_STREAM_OUTPUT, &data);
                    if let Err(e) = channel.send(InvokeResponseBody::Raw(bytes)) {
                        tracing::warn!(session = %session_id, "pty channel send failed: {e}");
                    }
                }
                // The mode reset travels on its own stream id, not as output.
                // These bytes are the app's correction for a dead session
                // (see `ssh_core::modes`), not something the server said, so a
                // UI that logs or replays output must be able to tell them
                // apart. Without them, a link cut while tmux had mouse
                // reporting on leaves the terminal spraying escape sequences
                // at the prompt on every mouse move.
                SessionEvent::Protocol(ProtocolEvent::Ssh(
                    remote_core::events::SshEvent::ResetTerminal(data),
                )) => {
                    let bytes = framing::encode_pty(framing::PTY_STREAM_RESET, &data);
                    if let Err(e) = channel.send(InvokeResponseBody::Raw(bytes)) {
                        tracing::warn!(session = %session_id, "pty reset send failed: {e}");
                    }
                }
                other => {
                    if let Some(payload) = event_json(&session_id, &other) {
                        let _ = app.emit_to(&window_label, "session://event", payload);
                    }
                }
            }
        }

        // Event stream closed: the session task has fully ended. Any
        // credential the user asked to remember but that never reached
        // `Connected` dies here, unwritten.
        creds_ctx.pending.lock().remove(&session_id);
        let entry = sessions.lock().remove(&session_id);
        // An attachment must not outlive the session it attached to: the id
        // would otherwise still read as agent driven in a pane, and a later
        // session that happened to reuse it would inherit somebody else's
        // revocation.
        if let Some(state) = app.try_state::<AppState>() {
            state.agent.forget(&session_id);
            let _ = app.emit(
                crate::agent::AGENT_EVENT,
                serde_json::json!({ "type": "detached", "sessionId": session_id }),
            );
        }
        let duration_s = entry.map(|e| e.started_at.elapsed().as_secs()).unwrap_or(0);
        let _ = app.emit_to(
            &window_label,
            "session://event",
            serde_json::json!({
                "sessionId": session_id,
                "type": "ended",
                "durationS": duration_s,
            }),
        );
        let _ = app.emit(
            SESSIONS_EVENT,
            serde_json::json!({ "type": "ended", "sessionId": session_id }),
        );
        tracing::info!(session = %session_id, duration_s, "session ended");
    });
}

/// What [`connect_session`] did. `Started` is the normal case; the two
/// ssh-host-key variants only occur for a profile whose `ssh_tunnel` is
/// enabled, before any session is spawned.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum SessionConnectOutcome {
    /// The session task is running; connect progress arrives as events.
    Started { session_id: String },
    /// First contact with the SSH gateway's host key. Show the fingerprint
    /// and, if the user accepts, call `connect_session` again with
    /// `acceptSshHostKey` set to it.
    SshHostKeyPrompt {
        host: String,
        port: u16,
        key_type: String,
        fingerprint: String,
    },
    /// The pinned gateway key changed. **Hard stop**, deliberately not
    /// acceptable from the UI (PRD/08 §4, PRD/10 §4.3).
    SshHostKeyChanged {
        host: String,
        port: u16,
        expected: String,
        actual: String,
    },
}

/// Resolve which protocol this connect is for, from the explicit argument,
/// then the profile, then VNC.
///
/// A value this build does not know is a hard error, never a fallback.
/// Falling back to VNC would send an RFB handshake at an endpoint the user
/// configured for something else, which is the same class of mistake the cert
/// pin loop already refuses to make.
fn resolve_protocol(
    explicit: Option<&str>,
    profile: Option<&vnc_store::HostProfile>,
) -> Result<ProtocolKind, String> {
    match explicit.or(profile.map(|p| p.protocol.as_str())) {
        None => Ok(ProtocolKind::Vnc),
        Some(raw) => ProtocolKind::parse(raw).ok_or_else(|| {
            format!(
                "This computer was saved with a connection type this version of the app \
                 does not support ({raw}). It was probably added by a newer version."
            )
        }),
    }
}

/// The viewport in physical pixels: what the webview measured, or the window.
///
/// Zero in either axis means nothing useful was measured, which is what a
/// window that has not been laid out reports, so it is treated as absent
/// rather than passed on as a desktop no pixels wide.
fn viewport(
    window: &tauri::WebviewWindow,
    width: Option<u16>,
    height: Option<u16>,
) -> Option<(u16, u16)> {
    let measured = match (width, height) {
        (Some(w), Some(h)) => Some((w, h)),
        _ => window.inner_size().ok().map(|s| {
            (
                u16::try_from(s.width).unwrap_or(u16::MAX),
                u16::try_from(s.height).unwrap_or(u16::MAX),
            )
        }),
    };
    measured.filter(|(w, h)| *w > 0 && *h > 0)
}

/// Connect to a remote desktop.
///
/// `on_event` is the binary channel that will receive framebuffer/cursor
/// data; control events go to the *invoking window* via `session://event`,
/// so this should be called from the window that renders the session
/// (the `session-<id>` window created by [`open_session_window`]).
///
/// `session_id` may be pre-generated by the UI (so the session window can be
/// opened first and connect from inside); if omitted a fresh uuid is used.
/// Returns a [`SessionConnectOutcome`]; the session id is in `Started`.
///
/// `ignore_stored_credentials` skips the keychain lookup for this attempt, so
/// the handshake raises an interactive prompt instead. The Reconnect button
/// sets it after an authentication failure: replaying a password the server has
/// already rejected only reproduces the failure (and, on some servers, walks
/// the account towards a lockout).
///
/// For a profile with an enabled `ssh_tunnel`, the SSH gateway is dialled
/// here, before the session spawns, so host-key and auth problems surface as
/// a returned outcome (or error) rather than as an opaque mid-handshake
/// failure. `accept_ssh_host_key` answers a previous `SshHostKeyPrompt`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // the invoke surface is the contract
pub async fn connect_session(
    app: AppHandle,
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    profile_id: Option<String>,
    address: String,
    port: u16,
    session_id: Option<String>,
    // Which protocol to speak, for an ad-hoc connect that has no profile to
    // read it from (quick connect typed `rdp://box`). Absent means "ask the
    // profile, then VNC", so a webview build that predates this argument
    // still invokes successfully. A plain comment, not a doc comment: rustc
    // allows no doc comment on a function parameter.
    protocol: Option<String>,
    ignore_stored_credentials: Option<bool>,
    accept_ssh_host_key: Option<String>,
    // The viewport in physical pixels, so an RDP session can ask for a desktop
    // that fits it instead of the specification's 1024 by 768. The webview
    // measures this because it knows where the canvas actually is; the window
    // is the fallback for a caller that did not, and is close enough because
    // the session view is full bleed. Absent from both leaves the size to the
    // profile, which is what a fixed resolution wants anyway.
    viewport_width: Option<u16>,
    viewport_height: Option<u16>,
    on_event: Channel<InvokeResponseBody>,
) -> Result<SessionConnectOutcome, String> {
    let id = match session_id {
        Some(id) => {
            validate_session_id(&id)?;
            id
        }
        None => uuid::Uuid::new_v4().to_string(),
    };
    // Reconnecting reuses the same session id, the window label is derived
    // from it, so a stale incarnation has to be reaped first. Rejecting
    // outright is what made the Reconnect button fail with "session already
    // exists" whenever it was pressed before the previous session had finished
    // unwinding, which is essentially always: the UI shows the terminal state
    // the moment it asks for the disconnect.
    reap_existing_session(&state, &id).await?;

    // The profile is read once, up front, because the protocol comes out of
    // it and the protocol decides the shape of everything below.
    let profile = match &profile_id {
        Some(pid) => {
            let store = state.store.clone();
            let lookup = pid.clone();
            super::blocking(move || store.get_host(&lookup)).await?
        }
        None => None,
    };
    let kind = resolve_protocol(protocol.as_deref(), profile.as_ref())?;
    let driver = state
        .protocols
        .get(kind)
        .ok_or_else(|| format!("this build cannot speak {kind}"))?
        .clone();

    let mut options = match kind {
        ProtocolKind::Rdp => ConnectOptions::rdp(address, port),
        ProtocolKind::Ssh => ConnectOptions::ssh(address, port),
        _ => ConnectOptions::vnc(address, port),
    };

    // Trust-on-first-use pins.
    //
    // `trust_certificate` writes to the (host, port, scheme)-keyed `cert_pins`
    // table, so that is where they must be read from. Reading only
    // `profile.cert_pin`, a column nothing ever writes, meant "Trust this
    // computer" was stored correctly and then never looked up, so the prompt
    // returned on every connect. Keyed by endpoint, this also works for an
    // ad-hoc session, which has no profile to carry a pin at all.
    //
    // ALL schemes are loaded, not just one: which security type the server
    // will negotiate is unknown until the handshake runs, and each path
    // verifies against its own key. Handing a TLS pin to the RA2 path (or the
    // reverse) would compare unrelated fingerprints and hard stop on a server
    // that changed nothing.
    {
        let store = state.store.clone();
        let host = options.host.clone();
        let port = options.port;
        if let Ok(pins) = super::blocking(move || store.list_cert_pins(&host, port)).await {
            for pin in pins {
                match vnc_core::PinScheme::parse(&pin.scheme) {
                    Some(scheme) => options.cert_pins.set(scheme, Some(pin.sha256_spki)),
                    // A row from a newer build. Ignored, never guessed at, // a pin applied to the wrong key is worse than no pin.
                    None => tracing::warn!(
                        scheme = %pin.scheme,
                        "ignoring a stored pin with an unrecognised scheme"
                    ),
                }
            }
        }
    }

    // The profile's tunnel blob, applied after credentials are loaded so a
    // host-key prompt is the LAST possible early return: nothing below spawns
    // until the tunnel (when there is one) is up.
    let mut ssh_tunnel_raw: Option<String> = None;

    // Common settings every protocol reads the same way.
    if let Some(profile) = &profile {
        options.quality = parse_quality(&profile.quality_pref);
        options.view_only = profile.view_only;
        ssh_tunnel_raw = profile.ssh_tunnel.clone();
    }

    // The protocol specific half.
    match kind {
        ProtocolKind::Ssh => {
            // Same rule as RDP below: a blob that will not parse FAILS the
            // connect rather than falling back to defaults. Silently
            // substituting them would turn a deliberate "attach to this named
            // tmux session" into "start a fresh shell", which loses the user's
            // work in exactly the situation the setting exists to protect.
            let settings = vnc_store::SshSettings::parse(
                profile.as_ref().and_then(|p| p.ssh_settings.as_deref()),
            )
            .map_err(|e| format!("This computer's terminal settings could not be read: {e}"))?
            .unwrap_or_default();
            *options.ssh_mut() = settings.options;
        }
        ProtocolKind::Rdp => {
            // A blob that will not parse FAILS the connect. Substituting
            // defaults would turn a deliberate "network level authentication
            // required" into whatever this build happens to default to.
            let settings = vnc_store::RdpSettings::parse(
                profile.as_ref().and_then(|p| p.rdp_settings.as_deref()),
            )
            .map_err(|e| format!("This computer's Remote Desktop settings could not be read: {e}"))?
            .unwrap_or_default();
            if settings.options.gateway.is_some() {
                return Err("This computer is set up to connect through an RD Gateway, \
                            which this version of the app cannot use yet."
                    .into());
            }
            let mut rdp = settings.options;
            // The name for SNI, the certificate pin and (from phase 3) the
            // Kerberos service name is the address the user configured, never
            // the socket we end up dialling: an SSH tunnel hands back a
            // loopback endpoint, and two tunnelled servers would then collide
            // on one pin key.
            rdp.server_name.get_or_insert_with(|| options.host.clone());
            rdp.window_size = viewport(&window, viewport_width, viewport_height);
            *options.rdp_mut() = rdp;
        }
        _ => {
            let vnc = options.vnc_mut();
            vnc.security_pref = profile.as_ref().and_then(|p| p.security_pref.clone());
            // Auto lossless refresh (PRD/09 §3.2): after motion stops, repaint
            // the regions that were JPEG-compressed at full quality. Global
            // preference, on a metered link the user may prefer to keep the
            // saved bandwidth.
            vnc.lossless_refresh = state
                .store
                .get_setting("lossless_refresh")
                .ok()
                .flatten()
                .map(|v| v != "false")
                .unwrap_or(true);
        }
    }

    // Stored credentials, loaded in Rust on a blocking thread (keychain IO is
    // synchronous); never routed through the webview.
    //
    // Skipped entirely when the caller asked to be prompted: a driver only
    // prompts for a secret it does not already have, so leaving the stored
    // one in place here is exactly what suppresses the dialog.
    if let Some(pid) = &profile_id {
        if ignore_stored_credentials == Some(true) {
            tracing::info!(profile = %pid, "ignoring the stored password for this attempt");
        } else {
            let credentials = state.credentials.clone();
            let lookup = pid.clone();
            match super::blocking(move || credentials.load(&lookup)).await {
                Ok(Some(stored)) => {
                    options.credentials = match kind {
                        ProtocolKind::Rdp => vnc_core::Credentials {
                            username: stored.rdp_user,
                            password: stored.rdp_password,
                            // The profile's configured domain wins over the
                            // stored one: the blob is where a domain typed at
                            // a prompt lands, the setting is where the user
                            // deliberately put one.
                            domain: options
                                .rdp_options()
                                .and_then(|r| r.domain.clone())
                                .filter(|d| !d.is_empty())
                                .or(stored.rdp_domain),
                        },
                        // SSH has no logon domain. The username is the
                        // remote account; an empty one means "the same user
                        // as here", which the driver resolves, so it is left
                        // empty rather than guessed at here.
                        ProtocolKind::Ssh => vnc_core::Credentials {
                            username: stored.ssh_user,
                            // The account password, not the key passphrase:
                            // those unlock different things and conflating
                            // them would offer a passphrase as a password.
                            password: stored.ssh_password,
                            domain: None,
                        },
                        // VeNCrypt user/pass wins when present; the plain VNC
                        // password is the fallback (vnc-core picks what the
                        // negotiated security type needs). RFB has no logon
                        // domain.
                        _ => vnc_core::Credentials {
                            username: stored.vencrypt_user,
                            password: stored.vencrypt_pass.or(stored.vnc_password),
                            domain: None,
                        },
                    };
                }
                Ok(None) => {}
                // A locked/unavailable keychain shouldn't kill the connect, // the session will surface an auth prompt instead.
                Err(e) => tracing::warn!("could not load stored credentials: {e}"),
            }
        }
    }

    // SSH tunnel (PRD/10 §5): dial the gateway now, so an unknown host key or
    // a failed SSH auth is reported to the caller instead of burning a
    // session on it. The connector then serves every attempt the reconnect
    // supervisor makes.
    if let Some(settings) = ssh_tunnel_raw
        .as_deref()
        .map(crate::tunnel::SshTunnelSettings::parse)
        .transpose()?
        .flatten()
        .filter(|s| s.enabled)
    {
        use crate::tunnel::TunnelOutcome;
        match crate::tunnel::establish(
            &app,
            &settings,
            &options.host,
            profile_id.as_deref(),
            accept_ssh_host_key.as_deref(),
        )
        .await?
        {
            TunnelOutcome::Ready(connector) => {
                tracing::info!(session = %id, "the session will run over the ssh tunnel");
                options.connector = Some(connector);
                // VNC ONLY. The SSH layer already encrypts and authenticates
                // this path, and the classic tunnelled setup is a
                // loopback-only server offering security type None; refusing
                // it here would make the recommended configuration unusable.
                //
                // That reasoning does not transfer to RDP. Network level
                // authentication authenticates the SERVER, and an SSH gateway
                // proves the identity of the gateway, not of the Windows
                // machine reached through it, which may be a different box.
                // So an RDP session still does full TLS and NLA inside the
                // tunnel.
                if let ProtocolOptions::Vnc(vnc) = &mut options.protocol {
                    vnc.allow_insecure = true;
                }
            }
            TunnelOutcome::HostKeyPrompt {
                host,
                port,
                key_type,
                fingerprint,
            } => {
                return Ok(SessionConnectOutcome::SshHostKeyPrompt {
                    host,
                    port,
                    key_type,
                    fingerprint,
                })
            }
            TunnelOutcome::HostKeyChanged {
                host,
                port,
                expected,
                actual,
            } => {
                return Ok(SessionConnectOutcome::SshHostKeyChanged {
                    host,
                    port,
                    expected,
                    actual,
                })
            }
        }
    }

    let (event_tx, event_rx) = mpsc::channel::<SessionEvent>(256);
    let address = options.host.clone();
    let handle = driver
        .spawn(id.clone(), options, event_tx)
        .map_err(|e| e.to_string())?;

    let window_label = window.label().to_string();
    state.sessions.lock().insert(
        id.clone(),
        SessionEntry {
            handle,
            window_label: window_label.clone(),
            profile_id: profile_id.clone(),
            address: address.clone(),
            port,
            started_at: Instant::now(),
            thumbnails: Default::default(),
            last_pointer_mask: Arc::new(std::sync::atomic::AtomicI32::new(-1)),
            facts: Default::default(),
        },
    );
    // The window has stopped "opening", from here the registry entry above is
    // what makes this machine count as already open.
    state.opening_windows.lock().remove(&id);
    // Announce the registration app-wide; the matching "ended" comes from the
    // forwarding task when the event stream closes.
    let _ = app.emit(
        SESSIONS_EVENT,
        serde_json::json!({
            "type": "started",
            "sessionId": &id,
            "profileId": &profile_id,
            "address": &address,
            "port": port,
            "protocol": kind,
        }),
    );
    forward_events(
        app,
        state.sessions.clone(),
        CredentialSaveCtx {
            store: state.store.clone(),
            credentials: state.credentials.clone(),
            pending: state.pending_credentials.clone(),
            prompts: state.pending_prompts.clone(),
        },
        id.clone(),
        window_label,
        SessionEndpoint {
            profile_id,
            address,
            port,
            protocol: kind,
        },
        event_rx,
        on_event,
    );
    Ok(SessionConnectOutcome::Started { session_id: id })
}

/// How long a reconnect waits for the previous incarnation of the same session
/// id to finish unwinding before giving up.
const REAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const REAP_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// Shut down any session still registered under `id` and wait for its
/// event-forwarding task to remove the entry.
///
/// Waiting matters: that task is the only thing that removes a session from the
/// registry, so inserting a replacement before it has run would let the old
/// task reap the *new* entry, leaving a live session that no command can
/// reach. Ok(()) means the slot is free.
async fn reap_existing_session(state: &AppState, id: &str) -> Result<(), String> {
    {
        let sessions = state.sessions.lock();
        let Some(entry) = sessions.get(id) else {
            return Ok(());
        };
        tracing::info!(session = %id, "replacing a previous session with the same id");
        entry.handle.shutdown();
    }

    let deadline = Instant::now() + REAP_TIMEOUT;
    while Instant::now() < deadline {
        tokio::time::sleep(REAP_POLL).await;
        if !state.sessions.lock().contains_key(id) {
            return Ok(());
        }
    }
    Err(format!(
        "the previous session ({id}) is still shutting down, try again in a moment"
    ))
}

/// Ask a session to close cleanly (RFB-level close, then task shutdown).
#[tauri::command]
pub async fn disconnect_session(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    let sender = state.command_sender(&session_id)?;
    if sender.send(ClientCommand::Disconnect).await.is_err() {
        // Command loop already gone, force-cancel so the entry gets reaped.
        if let Some(entry) = state.sessions.lock().get(&session_id) {
            entry.handle.shutdown();
        }
    }
    Ok(())
}

/// Raw binary input path (see FRAME_FORMAT.md "Input events").
///
/// Invoke with an `ArrayBuffer` body and an `x-session-id` header:
/// `invoke("send_input", buf, { headers: { "x-session-id": id } })`.
///
/// Never loses state-changing input. Key events, and pointer events whose
/// button mask differs from the last one seen for this session, are awaited
/// onto the command channel: if the 256-slot queue is momentarily full (a
/// stalled session, exactly when a release matters most) this briefly blocks
/// the invoke rather than dropping it, which is acceptable backpressure onto
/// the webview. Only pointer events that merely repeat the current button
/// mask (pure motion) are shed with `try_send` when the queue is full; that
/// is genuine stale-motion, safe to drop.
#[tauri::command]
pub async fn send_input(
    state: State<'_, AppState>,
    request: tauri::ipc::Request<'_>,
) -> Result<(), String> {
    let session_id = request
        .headers()
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing x-session-id header")?
        .to_string();
    let body = match request.body() {
        InvokeBody::Raw(bytes) => bytes.as_slice(),
        InvokeBody::Json(_) => return Err("send_input expects a raw binary body".into()),
    };

    let commands = framing::decode_input(body)?;
    let (sender, last_pointer_mask) = state.command_channel(&session_id)?;
    for command in commands {
        let motion_only = if let ClientCommand::Pointer { button_mask, .. } = &command {
            let mask = *button_mask as i32;
            last_pointer_mask.swap(mask, std::sync::atomic::Ordering::Relaxed) == mask
        } else {
            false
        };
        if motion_only {
            // Pure motion repeating the last-seen button mask: stale, safe to
            // shed under backpressure instead of blocking the invoke.
            if let Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) = sender.try_send(command)
            {
                return Err("session is no longer running".into());
            }
        } else if sender.send(command).await.is_err() {
            // Key events, and pointer events that change the button mask, must
            // never be lost: this awaits room in the queue instead.
            return Err("session is no longer running".into());
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn set_quality(
    state: State<'_, AppState>,
    session_id: String,
    preset: QualityPreset,
) -> Result<(), String> {
    send_command(&state, &session_id, ClientCommand::SetQuality(preset)).await
}

#[tauri::command]
pub async fn request_resize(
    state: State<'_, AppState>,
    session_id: String,
    width: u16,
    height: u16,
) -> Result<(), String> {
    send_command(
        &state,
        &session_id,
        ClientCommand::RequestResize { width, height },
    )
    .await
}

/// Force a full (non-incremental) framebuffer update.
#[tauri::command]
pub async fn refresh_session(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    send_command(&state, &session_id, ClientCommand::Refresh).await
}

/// Keep re-fetching the whole screen every second.
///
/// The manual override for servers whose damage tracking cannot be trusted:
/// no inference of ours decides when the picture is stale, it is simply
/// refetched. Costs real bandwidth, which is why it is a switch and not a
/// default.
#[tauri::command]
pub async fn set_always_refresh(
    state: State<'_, AppState>,
    session_id: String,
    enabled: bool,
) -> Result<(), String> {
    send_command(
        &state,
        &session_id,
        ClientCommand::SetAlwaysRefresh(enabled),
    )
    .await
}

#[tauri::command]
pub async fn set_view_only(
    state: State<'_, AppState>,
    session_id: String,
    view_only: bool,
) -> Result<(), String> {
    send_command(&state, &session_id, ClientCommand::SetViewOnly(view_only)).await
}

/// Keyboard mode: `true` prefers QEMU scancodes ("match the remote layout"),
/// `false` sends layout-aware keysyms only ("match my local layout").
#[tauri::command]
pub async fn set_prefer_scancodes(
    state: State<'_, AppState>,
    session_id: String,
    prefer: bool,
) -> Result<(), String> {
    send_command(
        &state,
        &session_id,
        ClientCommand::SetPreferScancodes(prefer),
    )
    .await
}

/// Push local clipboard text to the remote (text is user data, sent verbatim).
#[tauri::command]
pub async fn send_clipboard(
    state: State<'_, AppState>,
    session_id: String,
    text: String,
) -> Result<(), String> {
    send_command(&state, &session_id, ClientCommand::ClipboardText(text)).await
}

/// Write text the remote copied into the OS clipboard.
///
/// This deliberately does not go through `navigator.clipboard` in the webview:
/// WebKit (macOS/Linux) only honours `writeText()` while a user gesture is
/// still active, and remote clipboard text arrives from the socket, long after
/// any click. The write has to happen natively or it silently does nothing.
#[tauri::command]
pub fn set_local_clipboard(app: AppHandle, text: String) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

/// Read the OS clipboard for a push to the remote. Same reasoning as
/// [`set_local_clipboard`]: `navigator.clipboard.readText()` is gesture- and
/// permission-gated in the webview.
#[tauri::command]
pub fn read_local_clipboard(app: AppHandle) -> Result<String, String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    app.clipboard().read_text().map_err(|e| e.to_string())
}

/// Reset the reconnect backoff and retry immediately.
#[tauri::command]
pub async fn reconnect_now(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    send_command(&state, &session_id, ClientCommand::ReconnectNow).await
}

/// Release every pressed key (window blur / disconnect safety).
#[tauri::command]
pub async fn release_all_keys(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    send_command(&state, &session_id, ClientCommand::ReleaseAllKeys).await
}

/// Accept a server key at the TOFU prompt. When `permanent`, the SHA-256 SPKI
/// pin is also persisted in the (host, port, scheme)-keyed pin table so future
/// connects verify against it.
///
/// `scheme` comes straight back from the prompt that raised it, the UI echoes
/// what it was asked about. It is never inferred here: storing a fingerprint
/// under the wrong scheme would make the next connection over that path see a
/// changed identity for a server that changed nothing.
#[tauri::command]
pub async fn trust_certificate(
    state: State<'_, AppState>,
    session_id: String,
    fingerprint: String,
    permanent: bool,
    scheme: vnc_core::PinScheme,
) -> Result<(), String> {
    // Endpoint captured before awaiting so the registry lock isn't held.
    let endpoint = state
        .sessions
        .lock()
        .get(&session_id)
        .map(|e| (e.address.clone(), e.port));

    send_command(
        &state,
        &session_id,
        ClientCommand::TrustCertificate {
            fingerprint: fingerprint.clone(),
            permanent,
            scheme,
        },
    )
    .await?;

    if permanent {
        if let Some((host, port)) = endpoint {
            let store = state.store.clone();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let pin = vnc_store::CertPin {
                host,
                port,
                scheme: scheme.as_str().to_string(),
                sha256_spki: fingerprint,
                // Subject is refreshed by the transport layer on the next
                // successful verification; the pin itself is the fingerprint.
                subject: String::new(),
                first_trusted_at: now,
                last_seen_at: now,
                security_type: None,
            };
            super::blocking(move || store.save_cert_pin(&pin)).await?;
        }
    }
    Ok(())
}

/// Answer a `credentials-required` prompt (PRD/10 §3.4).
///
/// The session is parked mid-handshake waiting for exactly this; the core
/// resumes authentication with what arrives here. `username` must be `None`
/// for password-only methods.
///
/// SECURITY INVARIANT: `save` does **not** write anything yet. The credential
/// is held in memory as a [`PendingCredentialSave`] and only reaches the
/// keychain when this session reports `SessionState::Connected`, a password
/// the server rejects is never persisted. Nothing is ever returned to the
/// webview; there is deliberately no `get_password` counterpart.
#[tauri::command]
pub async fn provide_credentials(
    state: State<'_, AppState>,
    session_id: String,
    username: Option<String>,
    // Logon domain. `None` for every VNC method, and for an RDP logon with
    // no domain (a local account, or a UPN in `username`). Being an
    // `Option`, a webview build that omits the key still invokes
    // successfully; that is the whole compatibility story for this command.
    domain: Option<String>,
    password: String,
    save: bool,
) -> Result<(), String> {
    // Resolve the sender first so an unknown session id rejects *before* the
    // secret is copied anywhere.
    let (sender, protocol) = {
        let sessions = state.sessions.lock();
        let entry = sessions
            .get(&session_id)
            .ok_or_else(|| format!("unknown session: {session_id}"))?;
        (entry.handle.commands.clone(), entry.protocol())
    };

    // The question has been answered; a late-subscribing window must not be
    // handed a stale prompt.
    state.pending_prompts.lock().remove(&session_id);

    let domain = domain.filter(|d| !d.trim().is_empty());

    if save {
        state.pending_credentials.lock().insert(
            session_id.clone(),
            PendingCredentialSave {
                protocol,
                username: username.clone(),
                domain: domain.clone(),
                password: password.clone(),
            },
        );
    } else {
        // An explicit "don't remember" also revokes an earlier attempt's intent.
        state.pending_credentials.lock().remove(&session_id);
    }

    let result = sender
        .send(ClientCommand::ProvideCredentials {
            username: qualified_username(protocol, username, domain.as_deref()),
            password,
            save,
        })
        .await
        .map_err(|_| "session is no longer running".to_string());
    if result.is_err() {
        state.pending_credentials.lock().remove(&session_id);
    }
    result
}

/// Fold a separate domain back into the user name for the wire.
///
/// `ClientCommand::ProvideCredentials` carries no domain field, and the RDP
/// driver already splits a down-level `DOMAIN\user` before it builds the
/// CredSSP identity, so `DOMAIN\user` is the one shape that survives the
/// existing command unchanged. The keychain still stores the two separately,
/// which is what the host editor shows and what the next connect reads.
///
/// A name that already carries a domain is left alone, and so is a UPN: an
/// RDP server accepts `alice@corp.example` with an empty domain, and pinning
/// a NetBIOS domain in front of one fails against Entra ID and against any
/// forest whose NetBIOS name is not the DNS label.
fn qualified_username(
    protocol: ProtocolKind,
    username: Option<String>,
    domain: Option<&str>,
) -> Option<String> {
    let (ProtocolKind::Rdp, Some(domain), Some(user)) = (protocol, domain, username.as_deref())
    else {
        return username;
    };
    if user.contains('\\') || user.contains('@') || user.is_empty() {
        return username;
    }
    Some(format!("{domain}\\{user}"))
}

/// Dismiss a `credentials-required` prompt: abandon the connection attempt and
/// forget anything the user had asked to remember.
#[tauri::command]
pub async fn cancel_credentials(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    state.pending_credentials.lock().remove(&session_id);
    state.pending_prompts.lock().remove(&session_id);
    send_command(&state, &session_id, ClientCommand::CancelCredentials).await
}

/// The credential prompt this session is currently blocked on, if any.
///
/// Tauri events are fire-and-forget, so a `credentials-required` emitted
/// before the session window finished registering its `listen()` handler is
/// gone for good, and the handshake reaches the prompt within milliseconds on
/// a LAN host. The frontend calls this immediately after subscribing so a
/// missed event still surfaces the dialog instead of hanging until something
/// else disconnects the session.
///
/// Returns only the *question* (method, kind, attempt, error), never an
/// answer, and never a secret.
#[tauri::command]
pub fn pending_credential_request(
    state: State<'_, AppState>,
    session_id: String,
) -> Option<vnc_core::CredentialRequest> {
    state.pending_prompts.lock().get(&session_id).cloned()
}

/// One row of [`list_active_sessions`], the same identity every
/// [`SESSIONS_EVENT`] broadcast carries.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveSession {
    pub session_id: String,
    pub profile_id: Option<String>,
    pub address: String,
    pub port: u16,
    /// `"vnc"` or `"rdp"`. A webview that predates this field ignores it.
    pub protocol: ProtocolKind,
}

/// Every session that is currently live, for the Library to seed its
/// connected-machine map on mount, events only cover changes that happen
/// after it subscribed.
///
/// Entries whose session is already unwinding (`is_live()` false) are
/// filtered out: the registry briefly holds corpses between a session dying
/// and its forwarding task reaping the entry, and those will announce
/// themselves as `ended` shortly anyway.
#[tauri::command]
pub fn list_active_sessions(state: State<'_, AppState>) -> Result<Vec<ActiveSession>, String> {
    Ok(state
        .sessions
        .lock()
        .iter()
        .filter(|(_, entry)| entry.is_live())
        .map(|(id, entry)| ActiveSession {
            session_id: id.clone(),
            profile_id: entry.profile_id.clone(),
            address: entry.address.clone(),
            port: entry.port,
            protocol: entry.protocol(),
        })
        .collect())
}

/// Save a thumbnail for the session's host profile (PRD/03 §3).
///
/// The session window's renderer already holds the current frame, so it
/// sends the raw RGBA pixels here (no extra frame-export API in vnc-core,
/// no base64); `vnc_store` does the SIMD downscale + PNG encode:
/// `invoke("capture_thumbnail", rgbaBuf, { headers: { "x-session-id": id,
/// "x-width": w, "x-height": h } })`.
///
/// Row order is top-down, matching the framebuffer as decoded: the webview's
/// `readFramebufferRGBA()` reads back an FBO whose colour attachment IS the
/// frame texture, so `readPixels` returns rows in texture-upload order and
/// needs no vertical flip.
///
/// Silently does nothing (rather than erroring) when there is no host to
/// attach the image to, ad-hoc sessions, or when the capture arrives inside
/// the debounce window; see [`crate::thumbnail`]. On success every window is
/// told through `library://thumbnail` so the Library can re-read the tile
/// without an app restart.
#[tauri::command]
pub fn capture_thumbnail(
    app: AppHandle,
    state: State<'_, AppState>,
    request: tauri::ipc::Request<'_>,
) -> Result<(), String> {
    fn header(request: &tauri::ipc::Request<'_>, name: &str) -> Result<String, String> {
        request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| format!("missing {name} header"))
    }
    let session_id = header(&request, "x-session-id")?;
    let width: u32 = header(&request, "x-width")?
        .parse()
        .map_err(|_| "invalid x-width header".to_string())?;
    let height: u32 = header(&request, "x-height")?
        .parse()
        .map_err(|_| "invalid x-height header".to_string())?;
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes.clone(),
        InvokeBody::Json(_) => return Err("capture_thumbnail expects a raw RGBA body".into()),
    };
    // Geometry and body are both webview-supplied, bound them and require an
    // exact RGBA8888 length before handing anything to the store.
    crate::thumbnail::validate_frame(width, height, bytes.len())?;

    let Some(profile_id) = state.claim_thumbnail(&session_id, Instant::now()) else {
        return Ok(());
    };
    let store = state.store.clone();
    // Resize + PNG encode is a few ms of CPU, keep it off the IPC path.
    tauri::async_runtime::spawn_blocking(move || {
        if let Err(e) = store.save_thumbnail(&profile_id, &bytes, width, height) {
            tracing::warn!(profile = %profile_id, "failed to save thumbnail: {e}");
            return;
        }
        let captured_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        tracing::debug!(profile = %profile_id, "stored library thumbnail");
        // Broadcast: the Library lives in a different window from the session
        // that captured this, and caches the tile image by host id.
        if let Err(e) = app.emit(
            crate::thumbnail::THUMBNAIL_EVENT,
            serde_json::json!({ "hostId": profile_id, "capturedAt": captured_at }),
        ) {
            tracing::warn!("could not announce the new thumbnail: {e}");
        }
    });
    Ok(())
}

/// Preference key: may one machine have more than one session window open at
/// a time? Default **false**, connecting to a machine that is already open
/// focuses the window it is already in.
///
/// Lives in the store's KV table rather than the webview, because the decision
/// is made here, in `open_session_window`.
pub const ALLOW_MULTIPLE_SESSIONS_KEY: &str = "allow_multiple_sessions_per_host";

/// Interpret the stored value. Anything but an explicit "on" means off, so a
/// missing, empty or corrupt setting lands on the safe default.
fn allow_multiple_sessions(raw: Option<&str>) -> bool {
    matches!(
        raw.map(str::trim),
        Some("true") | Some("1") | Some("yes") | Some("on")
    )
}

/// Should this connect gesture focus an already-open window instead of
/// starting a second session? `lookup` is only run when it could matter.
fn window_to_focus(
    allow_multiple: bool,
    force_new: bool,
    lookup: impl FnOnce() -> Option<ExistingWindow>,
) -> Option<ExistingWindow> {
    if allow_multiple || force_new {
        return None;
    }
    lookup()
}

/// Where the session the user asked for is being shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionTarget {
    /// A window of its own, label `session-<id>`, built by the shell.
    Window,
    /// A tab inside the main window. The shell resolves and claims the session
    /// but builds nothing; the library webview mounts the viewer itself.
    Tab,
}

/// Connection parameters for a session the caller has to mount itself.
///
/// Exactly what [`windows::SessionWindowParams`] puts in a session window's
/// query string, handed back as data instead, because a tab has no URL of its
/// own to read them from.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionTabParams {
    pub profile_id: Option<String>,
    pub address: String,
    pub port: u16,
    pub name: String,
    /// Unconditionally present, unlike the window's query key: this is a
    /// fresh JSON payload with no legacy readers.
    pub protocol: ProtocolKind,
}

/// What [`open_session_window`] did.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionWindowOutcome {
    /// The session id of the window the user is now looking at, the new one,
    /// or the existing one when it was reused.
    pub session_id: String,
    /// True when an already-open window was brought to the front instead of a
    /// second connection being made.
    pub reused: bool,
    /// Window or tab. A reuse reports where the session it found already lives,
    /// which is not necessarily where a new one would have gone.
    pub target: SessionTarget,
    /// Present only for a NEW tab: nothing has connected yet and the caller
    /// needs these to mount the viewer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<SessionTabParams>,
}

/// Create (or focus) the viewer window for a session.
///
/// Called two ways from the library:
///   `invoke("open_session_window", { profileId })`, saved host
///   `invoke("open_session_window", { address, port })`, ad-hoc connect
///
/// For a saved host the endpoint and display name are resolved here from the
/// store, so the webview never has to fetch the profile just to connect. The
/// window loads `index.html?sessionId=…&address=…&port=…&name=…[&profileId=…]`
/// (label `session-<id>`) and connects itself; `CloseRequested` is wired
/// app-wide in `lib.rs` to disconnect the session.
///
/// ONE WINDOW PER MACHINE (default): if that machine already has a live
/// session, its window is restored and focused and no second connection is
/// made, every connect gesture in the UI (double-click, the tile's Connect,
/// the context menu, the palette, quick connect, a Nearby tile) funnels
/// through here, so they all behave the same. `allow_multiple_sessions_per_host`
/// turns that off; `force_new` is the per-call escape hatch behind it, used by
/// the explicit "Connect in new window" command.
///
/// TABBED VIEW (`as_tab`): the caller wants the session shown as a tab inside
/// the library window rather than in a window of its own. Everything above
/// still happens here, profile resolution, the machine key, the one-per-machine
/// rule, claiming the session id, so both modes obey one set of rules and a
/// machine already open in a window is still found when the preference has
/// since been switched to tabs. The only thing that changes is the last step:
/// no window is built, and the resolved parameters come back for the caller to
/// mount the viewer with.
///
/// Returns the session id the user ends up in, whether it was an existing one,
/// and where it is being shown.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // the invoke surface is the contract
pub async fn open_session_window(
    app: AppHandle,
    state: State<'_, AppState>,
    session_id: Option<String>,
    profile_id: Option<String>,
    address: Option<String>,
    port: Option<u16>,
    title: Option<String>,
    // The protocol for an ad-hoc connect. A saved host resolves it from the
    // profile, exactly as it already resolves address, port and name.
    protocol: Option<String>,
    force_new: Option<bool>,
    as_tab: Option<bool>,
) -> Result<SessionWindowOutcome, String> {
    let id = match session_id {
        Some(id) => {
            validate_session_id(&id)?;
            id
        }
        None => uuid::Uuid::new_v4().to_string(),
    };

    // Saved profile: resolve endpoint + name from the store. Explicit
    // address/port arguments still win, so a profile can be dialled at an
    // override endpoint.
    let mut resolved_address = address;
    let mut resolved_port = port;
    let mut name = title;
    let mut resolved_protocol = protocol;
    if let Some(pid) = &profile_id {
        let store = state.store.clone();
        let lookup = pid.clone();
        let profile = super::blocking(move || store.get_host(&lookup))
            .await?
            .ok_or_else(|| format!("unknown host profile: {pid}"))?;
        resolved_address.get_or_insert(profile.address);
        resolved_port.get_or_insert(profile.port);
        name.get_or_insert(profile.friendly_name);
        resolved_protocol.get_or_insert(profile.protocol);
    }
    let kind = resolve_protocol(resolved_protocol.as_deref(), None)?;

    let address = resolved_address.ok_or("open_session_window needs a profileId or an address")?;
    // The registry answers "what port does this protocol default to", so 5900
    // and 3389 live on the protocol rather than as literals here.
    let port = resolved_port.unwrap_or_else(|| {
        state
            .protocols
            .get(kind)
            .map(|d| d.default_port())
            .unwrap_or_else(|| kind.default_port())
    });
    let name = name
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| address.clone());

    let key = MachineKey::new(kind, profile_id.as_deref(), &address, port);

    // One window per machine, unless the user opted out (globally or for this
    // one call). Reading the setting here, not in the webview, is what makes
    // every entry point obey it.
    let allow_multiple = allow_multiple_sessions(
        state
            .store
            .get_setting(ALLOW_MULTIPLE_SESSIONS_KEY)
            .unwrap_or_default()
            .as_deref(),
    );
    let existing = window_to_focus(allow_multiple, force_new == Some(true), || {
        let app = app.clone();
        let window_exists = move |label: &str| app.get_webview_window(label).is_some();
        state.existing_window_for_machine(&key, Instant::now(), &window_exists)
    });
    if let Some(existing) = existing {
        // A session that is already a TAB has no window of its own to raise:
        // the library window is the one it lives in, and selecting the tab is
        // the caller's job. Report it and let them.
        if existing.window_label == windows::MAIN_WINDOW_LABEL {
            windows::focus_session_window(&app, windows::MAIN_WINDOW_LABEL);
            tracing::info!(
                session = %existing.session_id,
                "already connected to this machine, selecting the existing tab"
            );
            return Ok(SessionWindowOutcome {
                session_id: existing.session_id,
                reused: true,
                target: SessionTarget::Tab,
                params: None,
            });
        }
        // Only report it as reused if the window really is still there;
        // `focus_session_window` says so, and anything else falls through to a
        // normal connect rather than leaving the user with nothing.
        if windows::focus_session_window(&app, &existing.window_label) {
            tracing::info!(
                session = %existing.session_id,
                "already connected to this machine, focusing the existing window"
            );
            return Ok(SessionWindowOutcome {
                session_id: existing.session_id,
                reused: true,
                target: SessionTarget::Window,
                params: None,
            });
        }
    }

    // Claim the machine before anything is built: the webview will not call
    // `connect_session` for a few hundred milliseconds, and a second connect
    // gesture inside that gap must find this one.
    if as_tab == Some(true) {
        state.note_opening_window(&id, key, windows::MAIN_WINDOW_LABEL.to_string());
        return Ok(SessionWindowOutcome {
            session_id: id,
            reused: false,
            target: SessionTarget::Tab,
            params: Some(SessionTabParams {
                profile_id,
                address,
                port,
                name,
                protocol: kind,
            }),
        });
    }

    let params = windows::SessionWindowParams {
        session_id: &id,
        profile_id: profile_id.as_deref(),
        address: &address,
        port,
        name: &name,
        protocol: kind,
    };
    state.note_opening_window(&id, key, windows::session_label(&id));
    if let Err(e) = windows::open_session_window(&app, &params, &name) {
        state.opening_windows.lock().remove(&id);
        return Err(e.to_string());
    }
    Ok(SessionWindowOutcome {
        session_id: id,
        reused: false,
        target: SessionTarget::Window,
        params: None,
    })
}

/// Give up a session id that was claimed but never connected.
///
/// `open_session_window` claims the machine before anything is built, so a
/// second connect gesture in the gap before `connect_session` arrives finds the
/// first. A session WINDOW that goes away in that gap releases the claim by
/// ceasing to exist, which is what `find_opening_window`'s window-existence
/// check notices. A tab has no window of its own to disappear: its claim names
/// the library window, which is still very much there, so it would sit on the
/// machine for the full `OPENING_GRACE` and answer the next connect with
/// "already open". Closing a tab calls this instead.
#[tauri::command]
pub fn release_session_claim(state: State<'_, AppState>, session_id: String) {
    state.opening_windows.lock().remove(&session_id);
}

/// Enter/leave fullscreen for a session window, optionally on a specific
/// monitor (position-then-fullscreen pattern, PRD/05 §5).
#[tauri::command]
pub async fn fullscreen_session(
    app: AppHandle,
    state: State<'_, AppState>,
    session_id: String,
    fullscreen: bool,
    monitor_index: Option<usize>,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    // A session shown as a tab has no `session-<id>` window, so the window to
    // put fullscreen is whichever one the session actually registered itself
    // against. Asked which window, NOT defaulted to the library: falling back
    // to `main` unconditionally would throw the library into fullscreen with no
    // session in it whenever this raced a session window closing.
    let label = state
        .sessions
        .lock()
        .get(&session_id)
        .map(|entry| entry.window_label.clone())
        .unwrap_or_else(|| windows::session_label(&session_id));
    let window = app
        .get_webview_window(&label)
        .ok_or_else(|| format!("no window for session {session_id}"))?;
    windows::set_fullscreen_on_monitor(&window, monitor_index, fullscreen)
}

async fn send_command(
    state: &AppState,
    session_id: &str,
    command: ClientCommand,
) -> Result<(), String> {
    let sender = state.command_sender(session_id)?;
    sender
        .send(command)
        .await
        .map_err(|_| "session is no longer running".to_string())
}

#[cfg(test)]
mod tests {

    fn stored_pin(host: &str, port: u16, scheme: &str, spki: &str) -> vnc_store::CertPin {
        vnc_store::CertPin {
            host: host.into(),
            port,
            scheme: scheme.into(),
            sha256_spki: spki.into(),
            subject: "raspberrypi".into(),
            first_trusted_at: 1,
            last_seen_at: 1,
            security_type: None,
        }
    }

    /// Mirrors what `connect_session` does with the rows it reads: every pin
    /// for the endpoint, each landing under its own scheme.
    fn load_pins(store: &vnc_store::Store, host: &str, port: u16) -> vnc_core::CertPins {
        let mut pins = vnc_core::CertPins::default();
        for pin in store.list_cert_pins(host, port).expect("list") {
            if let Some(scheme) = vnc_core::PinScheme::parse(&pin.scheme) {
                pins.set(scheme, Some(pin.sha256_spki));
            }
        }
        pins
    }

    /// The pin must be read from the (host, port, scheme)-keyed `cert_pins`
    /// table, the same place `trust_certificate` writes it.
    ///
    /// This previously read `hosts.cert_pin`, a column nothing ever writes, so
    /// "Trust this computer" was stored correctly and then never looked up and
    /// the TOFU prompt returned on every single connect. Keyed by endpoint, it
    /// also covers ad-hoc sessions, which have no profile to carry a pin.
    #[test]
    fn a_trusted_pin_is_read_back_by_endpoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vnc_store::Store::open(Some(dir.path().to_path_buf())).expect("open");

        store
            .save_cert_pin(&stored_pin("192.168.77.152", 5900, "tls", "D2:10:ED:C2"))
            .expect("save");

        let found = store
            .get_cert_pin("192.168.77.152", 5900, "tls")
            .expect("lookup")
            .expect("a pin trusted at this endpoint must be found again");
        assert_eq!(found.sha256_spki, "D2:10:ED:C2");

        // A different port is a different endpoint.
        assert!(store
            .get_cert_pin("192.168.77.152", 5901, "tls")
            .expect("lookup")
            .is_none());
    }

    /// A server offering VeNCrypt *and* RA2 (wayvnc does) pins two unrelated
    /// keys at one endpoint. Connecting must load both, and each handshake
    /// must see only its own, comparing across schemes reports a changed
    /// identity for a server that changed nothing.
    #[test]
    fn connecting_loads_every_scheme_and_keeps_them_apart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vnc_store::Store::open(Some(dir.path().to_path_buf())).expect("open");

        store
            .save_cert_pin(&stored_pin("192.168.77.152", 5900, "tls", "AA:AA"))
            .expect("save");
        store
            .save_cert_pin(&stored_pin("192.168.77.152", 5900, "ra2", "BB:BB"))
            .expect("save");

        let pins = load_pins(&store, "192.168.77.152", 5900);
        assert_eq!(pins.for_scheme(vnc_core::PinScheme::Tls), Some("AA:AA"));
        assert_eq!(pins.for_scheme(vnc_core::PinScheme::Ra2), Some("BB:BB"));

        // Only TLS trusted: the RA2 path is still first contact, not a mismatch.
        store
            .delete_cert_pin("192.168.77.152", 5900, "ra2")
            .expect("delete");
        let pins = load_pins(&store, "192.168.77.152", 5900);
        assert_eq!(pins.for_scheme(vnc_core::PinScheme::Tls), Some("AA:AA"));
        assert_eq!(pins.for_scheme(vnc_core::PinScheme::Ra2), None);
    }

    /// A pin row written by a newer build with a scheme this one has never
    /// heard of must be ignored, not applied to some other key.
    #[test]
    fn an_unknown_scheme_is_ignored_rather_than_guessed_at() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vnc_store::Store::open(Some(dir.path().to_path_buf())).expect("open");
        store
            .save_cert_pin(&stored_pin("h", 5900, "quantum-kem", "CC:CC"))
            .expect("save");

        let pins = load_pins(&store, "h", 5900);
        assert!(pins.is_empty(), "an unknown scheme must not become a pin");
    }

    /// "Forget saved key" means the machine, not one of its keys.
    #[test]
    fn forgetting_an_endpoint_clears_every_scheme() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vnc_store::Store::open(Some(dir.path().to_path_buf())).expect("open");
        store
            .save_cert_pin(&stored_pin("h", 5900, "tls", "AA:AA"))
            .expect("save");
        store
            .save_cert_pin(&stored_pin("h", 5900, "ra2", "BB:BB"))
            .expect("save");

        assert_eq!(store.delete_cert_pins("h", 5900).expect("forget"), 2);
        assert!(load_pins(&store, "h", 5900).is_empty());
    }

    use super::*;

    fn existing() -> Option<ExistingWindow> {
        Some(ExistingWindow {
            session_id: "s1".into(),
            window_label: "session-s1".into(),
        })
    }

    #[test]
    fn one_window_per_machine_is_the_default() {
        // Nothing stored, junk stored, explicitly off, all mean "reuse".
        for raw in [None, Some("false"), Some(""), Some("maybe"), Some("0")] {
            assert!(
                !allow_multiple_sessions(raw),
                "unexpected opt-in for {raw:?}"
            );
        }
        assert_eq!(
            window_to_focus(false, false, existing),
            existing(),
            "a live session for this machine should be focused"
        );
    }

    #[test]
    fn the_setting_lets_a_machine_have_several_windows() {
        for raw in [Some("true"), Some("1"), Some(" true "), Some("yes")] {
            assert!(allow_multiple_sessions(raw), "expected opt-in for {raw:?}");
        }
        assert_eq!(
            window_to_focus(true, false, existing),
            None,
            "with the setting on, a second connect must open a second window"
        );
    }

    #[test]
    fn connect_in_a_new_window_overrides_the_default_for_one_call() {
        assert_eq!(window_to_focus(false, true, existing), None);
    }

    #[test]
    fn nothing_is_focused_when_the_machine_is_not_open() {
        assert_eq!(window_to_focus(false, false, || None), None);
    }

    /// A registry entry as `connect_session` builds it. The command receiver
    /// is dropped: `credential_home` reads identity, never liveness.
    fn session_entry(profile_id: Option<&str>, address: &str, port: u16) -> SessionEntry {
        let (commands, _rx) = tokio::sync::mpsc::channel(1);
        SessionEntry {
            handle: vnc_core::SessionHandle {
                id: "s1".into(),
                kind: vnc_core::ProtocolKind::Vnc,
                commands,
                cancel: tokio_util::sync::CancellationToken::new(),
            },
            window_label: "session-s1".into(),
            profile_id: profile_id.map(str::to_string),
            address: address.into(),
            port,
            started_at: Instant::now(),
            thumbnails: Default::default(),
            last_pointer_mask: Arc::new(std::sync::atomic::AtomicI32::new(-1)),
            facts: Default::default(),
        }
    }

    /// REGRESSION: ticking "remember" on a quick connect used to do nothing
    /// at all, because there was no host id to key the secret by. The tick has
    /// to reach the library instead.
    #[test]
    fn a_quick_connect_that_saves_its_password_asks_for_a_host_record() {
        let entry = session_entry(None, "studio.local", 5901);
        assert_eq!(
            credential_home(true, Some(&entry)),
            CredentialHome::AdoptEndpoint {
                address: "studio.local".into(),
                port: 5901,
            }
        );
    }

    /// The other half of that: a quick connect that asked for nothing must
    /// stay ad-hoc and leave the library exactly as it found it.
    #[test]
    fn a_quick_connect_that_saves_nothing_leaves_no_trace_in_the_library() {
        let adhoc = session_entry(None, "studio.local", 5901);
        assert_eq!(
            credential_home(false, Some(&adhoc)),
            CredentialHome::Nowhere
        );
        let saved = session_entry(Some("host-a"), "studio.local", 5901);
        assert_eq!(
            credential_home(false, Some(&saved)),
            CredentialHome::Nowhere
        );
    }

    #[test]
    fn a_saved_host_still_stores_its_password_against_its_own_profile() {
        let entry = session_entry(Some("host-a"), "studio.local", 5901);
        assert_eq!(
            credential_home(true, Some(&entry)),
            CredentialHome::Profile("host-a".into()),
            "an existing profile is never duplicated by address"
        );
    }

    /// The registry entry is gone by the time `Connected` is settled (the
    /// window was closed as it connected): there is no endpoint left to
    /// attribute the secret to, so it is dropped rather than guessed at.
    #[test]
    fn a_session_that_is_already_gone_persists_nothing() {
        assert_eq!(credential_home(true, None), CredentialHome::Nowhere);
    }

    fn profile(protocol: &str) -> vnc_store::HostProfile {
        vnc_store::HostProfile {
            protocol: protocol.to_string(),
            ..Default::default()
        }
    }

    /// Mirrors `an_unknown_scheme_is_ignored_rather_than_guessed_at` but
    /// asserts `Err`, because the consequence of guessing is different: an
    /// ignored pin is a prompt, a guessed protocol is an RFB handshake sent
    /// at an endpoint the user configured for something else.
    #[test]
    fn an_unknown_protocol_string_is_refused_rather_than_guessed_at() {
        let err = resolve_protocol(None, Some(&profile("spice")))
            .expect_err("a protocol this build cannot speak must not fall back to VNC");
        assert!(err.contains("spice"), "the message names it: {err}");
        assert!(
            err.contains("newer version"),
            "and says where it came from: {err}"
        );
        assert!(resolve_protocol(Some("spice"), None).is_err());
    }

    /// The three sources, in order.
    #[test]
    fn the_protocol_comes_from_the_argument_then_the_profile_then_vnc() {
        // Nothing said at all: every migrated row is VNC.
        assert_eq!(resolve_protocol(None, None), Ok(ProtocolKind::Vnc));
        // The profile, for a saved host.
        assert_eq!(
            resolve_protocol(None, Some(&profile("rdp"))),
            Ok(ProtocolKind::Rdp)
        );
        // The argument, for an ad-hoc connect, and it wins.
        assert_eq!(
            resolve_protocol(Some("rdp"), Some(&profile("vnc"))),
            Ok(ProtocolKind::Rdp)
        );
    }

    /// Reaching `Connected` proves a VNC password. It proves an RDP one only
    /// when CredSSP ran: with NLA off Windows evaluates the credentials
    /// inside the session and the connection completes either way.
    #[test]
    fn only_an_nla_session_proves_an_rdp_password_by_connecting() {
        assert!(connected_proves_the_credential(ProtocolKind::Vnc, None));
        assert!(connected_proves_the_credential(
            ProtocolKind::Vnc,
            Some("VNC Authentication")
        ));
        assert!(connected_proves_the_credential(
            ProtocolKind::Rdp,
            Some("nla-ntlm")
        ));
        assert!(
            connected_proves_the_credential(ProtocolKind::Rdp, Some("nla-kerberos")),
            "phase 3 must not need a second edit here"
        );
        assert!(!connected_proves_the_credential(
            ProtocolKind::Rdp,
            Some("tls")
        ));
        assert!(!connected_proves_the_credential(ProtocolKind::Rdp, None));
    }

    /// The domain is folded into the user name because the command carries no
    /// domain field, and the driver splits a down-level name before it builds
    /// the CredSSP identity.
    #[test]
    fn a_domain_qualifies_a_bare_name_and_leaves_a_upn_alone() {
        let q = |u: &str, d: Option<&str>| {
            qualified_username(ProtocolKind::Rdp, Some(u.to_string()), d)
        };
        assert_eq!(q("alice", Some("CORP")).as_deref(), Some("CORP\\alice"));
        // A UPN is accepted with an empty domain; pinning a NetBIOS name in
        // front of one fails against Entra ID.
        assert_eq!(
            q("alice@corp.example", Some("CORP")).as_deref(),
            Some("alice@corp.example")
        );
        // Already qualified: the user's own spelling wins.
        assert_eq!(
            q("OTHER\\alice", Some("CORP")).as_deref(),
            Some("OTHER\\alice")
        );
        assert_eq!(q("alice", None).as_deref(), Some("alice"));
        // VNC never qualifies anything.
        assert_eq!(
            qualified_username(ProtocolKind::Vnc, Some("alice".into()), Some("CORP")).as_deref(),
            Some("alice")
        );
    }

    /// A quick connect to `rdp://box` that remembers its password must mint
    /// an RDP profile. One that says VNC would dial the wrong protocol for
    /// ever after.
    #[test]
    fn an_adopted_host_is_created_with_the_sessions_own_protocol() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = vnc_store::Store::open(Some(dir.path().to_path_buf())).expect("open");

        let adopted = store
            .adopt_endpoint_for(ProtocolKind::Rdp, "box.corp.example", 3389)
            .expect("adopt");
        assert_eq!(adopted.protocol, "rdp");
        assert_eq!(adopted.port, 3389);

        // And the same address under the other protocol is a different host,
        // not a second row for the same one.
        let vnc = store
            .adopt_endpoint_for(ProtocolKind::Vnc, "box.corp.example", 5900)
            .expect("adopt");
        assert_ne!(vnc.id, adopted.id);
        assert_eq!(vnc.protocol, "vnc");
    }
}

/// Forget every trusted key pin for an endpoint.
///
/// Every scheme goes, TLS certificate and RA2 key alike. The user is saying
/// "stop trusting this machine", not "stop trusting its TLS certificate
/// specifically", and leaving one behind would keep the endpoint half-trusted
/// with no UI that explains why.
///
/// Without this a pin mismatch is unrecoverable: it is deliberately a hard stop
/// that cannot be clicked through (PRD/10 §4.3), so a server that is
/// legitimately rebuilt, new TLS cert, new RA2 key, would lock the user out
/// of that host permanently with no way back. Forgetting returns it to
/// first-contact state, where the normal trust-on-first-use prompt applies.
///
/// The next connection is therefore unverified again, which is exactly why this
/// is an explicit, deliberate action rather than an automatic recovery.
#[tauri::command]
pub async fn forget_certificate(
    state: State<'_, AppState>,
    host: String,
    port: u16,
) -> Result<(), String> {
    let store = state.store.clone();
    let host_for_log = host.clone();
    let removed = super::blocking(move || store.delete_cert_pins(&host, port)).await?;
    tracing::info!(host = %host_for_log, port, removed, "forgot the stored key pins");
    Ok(())
}
