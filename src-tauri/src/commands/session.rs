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
use vnc_core::{ClientCommand, ConnectOptions, QualityPreset, Session, SessionEvent, SessionState};

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
/// The host editor's "Security type" values (see `ui/src/components/HostDialog.tsx`
/// and the `security_pref` column). `None` means Auto: negotiate the strongest
/// type the server offers.
///
/// This was stored and written for releases without ever being read, so the
/// dropdown did nothing at all; pinning "None" to reach a passwordless server
/// was the workaround suggested for issue #1 and could not have worked.
fn parse_security_pref(pref: Option<&str>) -> Option<vnc_core::types::SecurityType> {
    use vnc_core::types::SecurityType;
    match pref?.trim().to_ascii_lowercase().as_str() {
        "none" => Some(SecurityType::None),
        "vncauth" => Some(SecurityType::VncAuth),
        "tight" => Some(SecurityType::Tight),
        "vencrypt" | "vencrypt-x509" => Some(SecurityType::VeNCrypt),
        "ra2" => Some(SecurityType::Ra2),
        "apple-dh" => Some(SecurityType::AppleDh),
        "ms-logon" | "mslogon" => Some(SecurityType::MsLogonII),
        // "auto", and anything a newer build wrote that this one predates:
        // negotiate rather than guess at what was meant.
        _ => None,
    }
}

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
    };
    if let serde_json::Value::Object(map) = &mut value {
        map.insert("sessionId".into(), json!(session_id));
    }
    Some(value)
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
fn adopt_session_host(
    app: &AppHandle,
    ctx: &CredentialSaveCtx,
    sessions: &Arc<Mutex<HashMap<String, SessionEntry>>>,
    session_id: &str,
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
        let profile = match store.adopt_endpoint(&address, port) {
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
            }),
        );
    });
}

/// React to a state change for the pending-credential lifecycle.
///
/// `Connected` is the ONLY state that persists anything; every terminal state
/// drops the intent without touching the keychain.
fn settle_pending_credentials(
    app: &AppHandle,
    ctx: &CredentialSaveCtx,
    sessions: &Arc<Mutex<HashMap<String, SessionEntry>>>,
    session_id: &str,
    state: &SessionState,
) {
    match state {
        SessionState::Connected => {
            let pending = ctx.pending.lock().remove(session_id);
            let home = {
                let sessions = sessions.lock();
                credential_home(pending.is_some(), sessions.get(session_id))
            };
            match (home, pending) {
                (CredentialHome::Profile(profile_id), Some(pending)) => {
                    persist_credentials(ctx, profile_id, pending)
                }
                (CredentialHome::AdoptEndpoint { address, port }, Some(pending)) => {
                    adopt_session_host(app, ctx, sessions, session_id, address, port, pending)
                }
                // Nothing asked for, or nothing left to attribute it to.
                _ => {}
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
        while let Some(event) = rx.recv().await {
            if let SessionEvent::StateChanged(state) = &event {
                settle_pending_credentials(&app, &creds_ctx, &sessions, &session_id, state);
                // Any state transition means the handshake moved on, so an
                // outstanding prompt is no longer answerable.
                if !matches!(state, SessionState::Authenticating { .. }) {
                    creds_ctx.prompts.lock().remove(&session_id);
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
                        "stats": stats,
                    }),
                );
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

/// Connect to a VNC server.
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
    ignore_stored_credentials: Option<bool>,
    accept_ssh_host_key: Option<String>,
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

    let mut options = ConnectOptions::new(address, port);

    // Auto lossless refresh (PRD/09 §3.2): after motion stops, repaint the
    // regions that were JPEG-compressed at full quality. Global preference, // on a metered link the user may prefer to keep the saved bandwidth.
    options.lossless_refresh = state
        .store
        .get_setting("lossless_refresh")
        .ok()
        .flatten()
        .map(|v| v != "false")
        .unwrap_or(true);

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

    if let Some(pid) = &profile_id {
        // Saved-profile settings.
        let store = state.store.clone();
        let lookup = pid.clone();
        if let Some(profile) = super::blocking(move || store.get_host(&lookup)).await? {
            options.quality = parse_quality(&profile.quality_pref);
            options.view_only = profile.view_only;
            options.security_pref = parse_security_pref(profile.security_pref.as_deref());
            ssh_tunnel_raw = profile.ssh_tunnel;
        }

        // Stored credentials, loaded in Rust on a blocking thread (keychain
        // IO is synchronous); never routed through the webview. VeNCrypt
        // user/pass wins when present; the plain VNC password is the
        // fallback (vnc-core picks what the negotiated security type needs).
        //
        // Skipped entirely when the caller asked to be prompted: `vnc-core`
        // only prompts for a secret it does not already have, so leaving the
        // stored one in place here is exactly what suppresses the dialog.
        if ignore_stored_credentials == Some(true) {
            tracing::info!(profile = %pid, "ignoring the stored password for this attempt");
        } else {
            let credentials = state.credentials.clone();
            let lookup = pid.clone();
            match super::blocking(move || credentials.load(&lookup)).await {
                Ok(Some(stored)) => {
                    options.credentials = vnc_core::Credentials {
                        username: stored.vencrypt_user,
                        password: stored.vencrypt_pass.or(stored.vnc_password),
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
                tracing::info!(session = %id, "rfb stream will run over the ssh tunnel");
                options.connector = Some(connector);
                // The SSH layer already encrypts and authenticates this path,
                // and the classic tunnelled setup is a loopback-only server
                // offering security type None; refusing it here would make
                // the recommended configuration unusable.
                options.allow_insecure = true;
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
    let handle = Session::spawn(id.clone(), options, event_tx);

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
    password: String,
    save: bool,
) -> Result<(), String> {
    // Resolve the sender first so an unknown session id rejects *before* the
    // secret is copied anywhere.
    let sender = state.command_sender(&session_id)?;

    // The question has been answered; a late-subscribing window must not be
    // handed a stale prompt.
    state.pending_prompts.lock().remove(&session_id);

    if save {
        state.pending_credentials.lock().insert(
            session_id.clone(),
            PendingCredentialSave {
                username: username.clone(),
                password: password.clone(),
            },
        );
    } else {
        // An explicit "don't remember" also revokes an earlier attempt's intent.
        state.pending_credentials.lock().remove(&session_id);
    }

    let result = sender
        .send(ClientCommand::ProvideCredentials {
            username,
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
    if let Some(pid) = &profile_id {
        let store = state.store.clone();
        let lookup = pid.clone();
        let profile = super::blocking(move || store.get_host(&lookup))
            .await?
            .ok_or_else(|| format!("unknown host profile: {pid}"))?;
        resolved_address.get_or_insert(profile.address);
        resolved_port.get_or_insert(profile.port);
        name.get_or_insert(profile.friendly_name);
    }

    let address = resolved_address.ok_or("open_session_window needs a profileId or an address")?;
    let port = resolved_port.unwrap_or(5900);
    let name = name
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| address.clone());

    let key = MachineKey::new(profile_id.as_deref(), &address, port);

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
            }),
        });
    }

    let params = windows::SessionWindowParams {
        session_id: &id,
        profile_id: profile_id.as_deref(),
        address: &address,
        port,
        name: &name,
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
