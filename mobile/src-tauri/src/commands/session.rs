//! `session_*` and `boundary_resolve`: a remote desktop on the phone.
//!
//! The protocol work is the desktop's: `vnc-core`, `rdp-core` and
//! `boundary-driver` behind `remote_core::ProtocolDriver`, the same drivers
//! the desktop registry spawns. Frames leave on `onFrame` in the exact byte
//! layout of `src-tauri/FRAME_FORMAT.md`, encoded by the desktop's own
//! `framing.rs`, and input arrives in the desktop `send_input` layout.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use remote_core::{
    ClientCommand, ConnectOptions, Credentials, PinScheme, ProtocolKind, QualityPreset,
    SessionEvent, SessionState,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::ipc::{Channel, InvokeBody, InvokeResponseBody};
use tauri::{AppHandle, Manager, State};
use tokio::sync::mpsc;

use crate::codes::{self, Entered};
use crate::events;
use crate::framing;
use crate::keys::{self, KeyCombo};
use crate::secrets::Secret;
use crate::state::{AppState, Session, Sessions};
use crate::store::{self, Protocol};
use crate::thumbs;

/// `ConnectTarget` in `contract.ts`.
#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum ConnectTarget {
    Saved {
        host_id: String,
    },
    Adhoc {
        protocol: Protocol,
        address: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Boundary {
        invitation: String,
        helper_name: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connected {
    pub session_id: String,
}

#[derive(Serialize)]
pub struct Resolved {
    pub invitation: String,
}

/// The name a phone gives itself to a Boundary computer when the UI did not
/// say, for a saved computer reached by invitation.
const DEFAULT_HELPER_NAME: &str = "DeskVNC on a phone";

/// Turn what the person typed into an invitation: a code goes to the code
/// service, an invitation is checked and returned as is.
#[tauri::command]
pub async fn boundary_resolve(code: String) -> Result<Resolved, String> {
    let invitation = match codes::parse(&code)? {
        Entered::Invitation(invitation) => invitation,
        Entered::Code(code) => boundary_codes::Client::new("")
            .map_err(|e| e.to_string())?
            .resolve(&code)
            .await
            .map_err(|e| format!("{e} (code {})", codes::grouped(&code)))?,
    };
    Ok(Resolved { invitation })
}

#[tauri::command]
pub async fn session_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    target: ConnectTarget,
    on_frame: Channel<InvokeResponseBody>,
    on_event: Channel<Value>,
) -> Result<Connected, String> {
    let (kind, mut options, host_id) = match target {
        ConnectTarget::Saved { host_id } => {
            let host = state
                .hosts
                .get(&host_id)
                .ok_or_else(|| format!("unknown host: {host_id}"))?;
            let secrets = state.secrets.clone();
            let lookup = host_id.clone();
            let secret = super::blocking(move || secrets.load(&lookup))
                .await
                .unwrap_or_else(|error| {
                    // A locked vault must not stop the connect: the server
                    // asks for the password instead.
                    tracing::warn!(%error, "could not read a saved password");
                    None
                })
                .unwrap_or_default();
            let kind = host.protocol.kind();
            let mut options = match host.protocol {
                Protocol::Boundary if host.address.trim().is_empty() => {
                    let invitation = host
                        .boundary_invitation
                        .clone()
                        .ok_or("This Boundary computer has no ID or invitation saved")?;
                    let id = state
                        .drivers
                        .boundary
                        .prepare(invitation, DEFAULT_HELPER_NAME.into())
                        .map_err(|e| e.to_string())?;
                    ConnectOptions::boundary(id)
                }
                _ => options_for(host.protocol, &host.address, host.port),
            };
            if let remote_core::ProtocolOptions::Rdp(rdp) = &mut options.protocol {
                rdp.domain = host.domain.clone();
            }
            options.credentials = Credentials {
                username: secret.username.or(host.username.clone()),
                password: secret.password,
                domain: host.domain.clone(),
            };
            (kind, options, Some(host_id))
        }
        ConnectTarget::Adhoc {
            protocol,
            address,
            port,
            username,
            password,
        } => {
            if address.trim().is_empty() || address.len() > 512 {
                return Err("Enter the computer's address".into());
            }
            let mut options = options_for(protocol, &address, port);
            options.credentials = Credentials {
                username: username.filter(|u| !u.is_empty()),
                password: password.filter(|p| !p.is_empty()),
                domain: None,
            };
            (protocol.kind(), options, None)
        }
        ConnectTarget::Boundary {
            invitation,
            helper_name,
        } => {
            let invitation = match codes::parse(&invitation)? {
                Entered::Invitation(invitation) => invitation,
                Entered::Code(_) => {
                    return Err("Resolve the code with boundary_resolve first".into())
                }
            };
            let helper = if helper_name.trim().is_empty() {
                DEFAULT_HELPER_NAME.to_string()
            } else {
                helper_name.trim().to_string()
            };
            let id = state
                .drivers
                .boundary
                .prepare(invitation, helper)
                .map_err(|e| e.to_string())?;
            (ProtocolKind::Boundary, ConnectOptions::boundary(id), None)
        }
    };

    // Protocol specific settings the desktop also applies.
    match kind {
        ProtocolKind::Rdp => {
            // The name for SNI and the certificate pin is the address the
            // person typed, as on the desktop.
            let host = options.host.clone();
            let rdp = options.rdp_mut();
            rdp.server_name.get_or_insert(host);
            // A licence from an RD licence server belongs to this device.
            rdp.license_dir = app
                .path()
                .app_data_dir()
                .ok()
                .map(|dir| dir.join("rdp-licences"));
        }
        ProtocolKind::Vnc => {
            // The desktop default: repaint lossy regions losslessly once the
            // picture stops moving.
            options.vnc_mut().lossless_refresh = true;
        }
        _ => {}
    }

    // Trust on first use pins, every scheme, as the desktop loads them.
    if kind != ProtocolKind::Boundary {
        for (scheme, pin) in state.pins.for_endpoint(&options.host, options.port) {
            options.cert_pins.set(scheme, Some(pin));
        }
    }

    let driver = state
        .drivers
        .get(kind)
        .ok_or_else(|| format!("this build cannot speak {kind}"))?;
    let id = uuid::Uuid::new_v4().to_string();
    let address = options.host.clone();
    let port = options.port;
    let (event_tx, event_rx) = mpsc::channel::<SessionEvent>(256);
    let handle = driver
        .spawn(id.clone(), options, event_tx)
        .map_err(|e| e.to_string())?;

    // A session that starts while the app is in the background (it should
    // not, but a slow invoke can land late) starts paused.
    let paused = Arc::new(AtomicBool::new(
        state.lifecycle.lock().backgrounded_at.is_some(),
    ));
    let pending_save = Arc::new(Mutex::new(None));
    let background_ended = Arc::new(AtomicBool::new(false));
    state.sessions.lock().insert(
        id.clone(),
        Session {
            handle,
            host_id: host_id.clone(),
            address,
            port,
            started_at: Instant::now(),
            paused: paused.clone(),
            last_pointer_mask: Arc::new(AtomicI32::new(-1)),
            pending_save: pending_save.clone(),
            background_ended: background_ended.clone(),
            last_thumbnail: Mutex::new(None),
        },
    );
    forward_events(Forward {
        app,
        sessions: state.sessions.clone(),
        session_id: id.clone(),
        host_id,
        rx: event_rx,
        frames: on_frame,
        events: on_event,
        paused,
        pending_save,
        background_ended,
    });
    Ok(Connected { session_id: id })
}

fn options_for(protocol: Protocol, address: &str, port: u16) -> ConnectOptions {
    let address = address.trim();
    let port = if port == 0 && protocol != Protocol::Boundary {
        protocol.kind().default_port()
    } else {
        port
    };
    match protocol {
        Protocol::Vnc => ConnectOptions::vnc(address, port),
        Protocol::Rdp => ConnectOptions::rdp(address, port),
        // The port rides along, as on the desktop: zero adds nothing.
        Protocol::Boundary => ConnectOptions {
            port,
            ..ConnectOptions::boundary(address)
        },
    }
}

struct Forward {
    app: AppHandle,
    sessions: Sessions,
    session_id: String,
    host_id: Option<String>,
    rx: mpsc::Receiver<SessionEvent>,
    frames: Channel<InvokeResponseBody>,
    events: Channel<Value>,
    paused: Arc<AtomicBool>,
    pending_save: Arc<Mutex<Option<Secret>>>,
    background_ended: Arc<AtomicBool>,
}

/// Pump one session's events to the UI until the session ends, then say so.
fn forward_events(f: Forward) {
    let Forward {
        app,
        sessions,
        session_id,
        host_id,
        mut rx,
        frames,
        events,
        paused,
        pending_save,
        background_ended,
    } = f;
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let SessionEvent::StateChanged(SessionState::Connected) = &event {
                on_connected(&app, host_id.as_deref(), &pending_save);
            }
            // A new handshake step means an earlier "remember" belonged to
            // an attempt that is over, unless it is the one that connected.
            if let SessionEvent::StateChanged(SessionState::Disconnected { .. }) = &event {
                pending_save.lock().take();
            }
            match event {
                SessionEvent::FramebufferUpdate { rects, damage } => {
                    if paused.load(Ordering::Relaxed) {
                        // Nobody is drawing. Dropped here, and the whole
                        // screen is asked for again on the way back
                        // (`crate::lifecycle`).
                        continue;
                    }
                    let rects = framing::decode_jpeg_rects(rects);
                    let bytes = framing::encode_frame(&rects, &damage);
                    if frames.send(InvokeResponseBody::Raw(bytes)).is_err() {
                        tracing::debug!(session = %session_id, "frame channel closed");
                    }
                }
                SessionEvent::CursorUpdate(shape) => {
                    let bytes = framing::encode_cursor(&shape);
                    let _ = frames.send(InvokeResponseBody::Raw(bytes));
                }
                other => {
                    if let Some(json) = events::event_json(&session_id, &other) {
                        let _ = events.send(json);
                    }
                }
            }
        }
        let entry = sessions.lock().remove(&session_id);
        input_orders().lock().remove(&session_id);
        let duration = entry.map(|e| e.started_at.elapsed().as_secs()).unwrap_or(0);
        if background_ended.load(Ordering::Relaxed) {
            let _ = events.send(events::disconnected(&session_id, crate::lifecycle::REASON));
        }
        let _ = events.send(events::ended(&session_id, duration));
        tracing::info!(session = %session_id, duration, "session ended");
    });
}

/// The server accepted the session: stamp the host and settle a password the
/// person asked to remember. Only now, so a rejected password is never kept.
fn on_connected(app: &AppHandle, host_id: Option<&str>, pending: &Mutex<Option<Secret>>) {
    let Some(host_id) = host_id.map(str::to_string) else {
        pending.lock().take();
        return;
    };
    let save = pending.lock().take();
    let state = app.state::<AppState>();
    let hosts = state.hosts.clone();
    let secrets = state.secrets.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut has_password = None;
        let mut username = None;
        if let Some(secret) = save {
            match secrets.save(&host_id, &secret) {
                Ok(()) => {
                    has_password = Some(secret.password.is_some());
                    username = secret.username.clone();
                }
                Err(error) => tracing::warn!(%error, "could not remember the password"),
            }
        }
        let _ = hosts.update(&host_id, |h| {
            h.last_connected_at = Some(store::now_ms());
            if let Some(p) = has_password {
                h.has_password = p;
            }
            if username.is_some() {
                h.username = username;
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// Orders `session_input` calls by their `x-input-seq` header.
///
/// The same gate as the desktop's `InputOrder` in
/// `src-tauri/src/commands/session.rs`, copied because it is private to that
/// Tauri command module. A call waits until every lower number has been
/// queued, so the UI may have several in flight without a release
/// overtaking its press; a number that never arrives releases the next one
/// after a short timeout instead of wedging input.
struct InputOrder {
    next: parking_lot::Mutex<u64>,
    notify: tokio::sync::Notify,
}

const INPUT_ORDER_TIMEOUT: Duration = Duration::from_millis(750);

impl InputOrder {
    fn new() -> Self {
        Self {
            next: parking_lot::Mutex::new(1),
            notify: tokio::sync::Notify::new(),
        }
    }

    async fn admit(&self, seq: u64, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if *self.next.lock() >= seq {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return false;
            }
        }
    }

    fn done(&self, seq: u64) {
        {
            let mut next = self.next.lock();
            if seq + 1 > *next {
                *next = seq + 1;
            }
        }
        self.notify.notify_waiters();
    }
}

fn input_orders() -> &'static Mutex<HashMap<String, Arc<InputOrder>>> {
    static ORDERS: std::sync::OnceLock<Mutex<HashMap<String, Arc<InputOrder>>>> =
        std::sync::OnceLock::new();
    ORDERS.get_or_init(|| Mutex::new(HashMap::new()))
}

struct InputOrderDone<'a> {
    order: &'a InputOrder,
    seq: u64,
}

impl Drop for InputOrderDone<'_> {
    fn drop(&mut self) {
        self.order.done(self.seq);
    }
}

fn header(request: &tauri::ipc::Request<'_>, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Raw input: body in the desktop `send_input` layout, headers
/// `x-session-id` and `x-input-seq`. Key events and pointer events that
/// change the buttons wait for room in the queue; pure motion is shed when
/// the queue is full.
#[tauri::command]
pub async fn session_input(
    state: State<'_, AppState>,
    request: tauri::ipc::Request<'_>,
) -> Result<(), String> {
    let session_id = header(&request, "x-session-id").ok_or("missing x-session-id header")?;
    let body = match request.body() {
        InvokeBody::Raw(bytes) => bytes.as_slice(),
        InvokeBody::Json(_) => return Err("session_input expects a raw binary body".into()),
    };
    let seq = header(&request, "x-input-seq").and_then(|v| v.parse::<u64>().ok());
    let order = seq.map(|_| {
        input_orders()
            .lock()
            .entry(session_id.clone())
            .or_insert_with(|| Arc::new(InputOrder::new()))
            .clone()
    });
    let _done = match (seq, order.as_deref()) {
        (Some(seq), Some(order)) => {
            if !order.admit(seq, INPUT_ORDER_TIMEOUT).await {
                tracing::warn!(session = %session_id, seq, "input sequence gap");
            }
            Some(InputOrderDone { order, seq })
        }
        _ => None,
    };

    let commands = framing::decode_input(body)?;
    let (sender, last_mask) = {
        let sessions = state.sessions.lock();
        let s = sessions
            .get(&session_id)
            .ok_or_else(|| format!("unknown session: {session_id}"))?;
        (s.handle.commands.clone(), s.last_pointer_mask.clone())
    };
    for command in commands {
        let motion_only = match &command {
            ClientCommand::Pointer { button_mask, .. } => {
                let mask = i32::from(*button_mask);
                last_mask.swap(mask, Ordering::Relaxed) == mask
            }
            _ => false,
        };
        if motion_only {
            if let Err(mpsc::error::TrySendError::Closed(_)) = sender.try_send(command) {
                return Err("session is no longer running".into());
            }
        } else if sender.send(command).await.is_err() {
            return Err("session is no longer running".into());
        }
    }
    Ok(())
}

/// Type a string from the phone keyboard.
#[tauri::command]
pub async fn session_text(
    state: State<'_, AppState>,
    session_id: String,
    text: String,
) -> Result<(), String> {
    let sender = state.command_sender(&session_id)?;
    for command in keys::text_commands(&text)? {
        sender
            .send(command)
            .await
            .map_err(|_| "session is no longer running".to_string())?;
    }
    Ok(())
}

/// Press a chord from the key bar.
#[tauri::command]
pub async fn session_key_combo(
    state: State<'_, AppState>,
    session_id: String,
    combo: KeyCombo,
) -> Result<(), String> {
    let sender = state.command_sender(&session_id)?;
    for command in keys::combo_commands(combo)? {
        sender
            .send(command)
            .await
            .map_err(|_| "session is no longer running".to_string())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

/// Answer `credentials-required`. Both `username` and `password` null means
/// the person cancelled the prompt, and the attempt is abandoned.
///
/// With `save`, the answer is remembered for a saved host, and only once the
/// server accepts it. An ad hoc connect has no host to remember it for.
#[tauri::command]
pub async fn session_credentials(
    state: State<'_, AppState>,
    session_id: String,
    username: Option<String>,
    password: Option<String>,
    save: bool,
) -> Result<(), String> {
    let (sender, pending, has_host) = {
        let sessions = state.sessions.lock();
        let s = sessions
            .get(&session_id)
            .ok_or_else(|| format!("unknown session: {session_id}"))?;
        (
            s.handle.commands.clone(),
            s.pending_save.clone(),
            s.host_id.is_some(),
        )
    };
    let username = username.filter(|u| !u.is_empty());
    if username.is_none() && password.is_none() {
        pending.lock().take();
        return sender
            .send(ClientCommand::CancelCredentials)
            .await
            .map_err(|_| "session is no longer running".to_string());
    }
    let password = password.unwrap_or_default();
    *pending.lock() = (save && has_host).then(|| Secret {
        username: username.clone(),
        password: (!password.is_empty()).then(|| password.clone()),
    });
    sender
        .send(ClientCommand::ProvideCredentials {
            username,
            password,
            save,
        })
        .await
        .map_err(|_| "session is no longer running".to_string())
}

/// Answer `certificate-prompt`. Accepting pins the key for this endpoint
/// under the scheme the prompt named; refusing ends the session.
#[tauri::command]
pub async fn session_trust(
    state: State<'_, AppState>,
    session_id: String,
    fingerprint: String,
    scheme: PinScheme,
    accept: bool,
) -> Result<(), String> {
    if !accept {
        return state.send(&session_id, ClientCommand::Disconnect).await;
    }
    let endpoint = state
        .sessions
        .lock()
        .get(&session_id)
        .map(|s| (s.address.clone(), s.port));
    state
        .send(
            &session_id,
            ClientCommand::TrustCertificate {
                fingerprint: fingerprint.clone(),
                permanent: true,
                scheme,
            },
        )
        .await?;
    if let Some((host, port)) = endpoint {
        state.pins.trust(&host, port, scheme, &fingerprint)?;
    }
    Ok(())
}

/// `Quality` in `contract.ts`, onto the desktop presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Quality {
    Auto,
    Speed,
    Balanced,
    Quality,
}

impl From<Quality> for QualityPreset {
    fn from(q: Quality) -> Self {
        match q {
            Quality::Auto => QualityPreset::Auto,
            Quality::Speed => QualityPreset::Low,
            Quality::Balanced => QualityPreset::Medium,
            Quality::Quality => QualityPreset::High,
        }
    }
}

#[tauri::command]
pub async fn session_quality(
    state: State<'_, AppState>,
    session_id: String,
    quality: Quality,
) -> Result<(), String> {
    state
        .send(&session_id, ClientCommand::SetQuality(quality.into()))
        .await
}

/// The most clipboard text sent in one go.
const MAX_CLIPBOARD: usize = 1024 * 1024;

#[tauri::command]
pub async fn session_clipboard(
    state: State<'_, AppState>,
    session_id: String,
    text: String,
) -> Result<(), String> {
    if text.len() > MAX_CLIPBOARD {
        return Err("That is too much text to send at once".into());
    }
    state
        .send(&session_id, ClientCommand::ClipboardText(text))
        .await
}

/// The shortest gap between two stored thumbnails of one session.
const THUMBNAIL_GAP: Duration = Duration::from_millis(500);

/// Store the host card thumbnail. Raw RGBA body with headers `x-session-id`,
/// `x-width` and `x-height`, the desktop `capture_thumbnail` layout. An ad
/// hoc session has no card, so its snapshot is accepted and dropped.
#[tauri::command]
pub async fn session_snapshot(
    state: State<'_, AppState>,
    request: tauri::ipc::Request<'_>,
) -> Result<(), String> {
    let session_id = header(&request, "x-session-id").ok_or("missing x-session-id header")?;
    let width: u32 = header(&request, "x-width")
        .and_then(|v| v.parse().ok())
        .ok_or("missing or invalid x-width header")?;
    let height: u32 = header(&request, "x-height")
        .and_then(|v| v.parse().ok())
        .ok_or("missing or invalid x-height header")?;
    let rgba = match request.body() {
        InvokeBody::Raw(bytes) => bytes.clone(),
        InvokeBody::Json(_) => return Err("session_snapshot expects a raw RGBA body".into()),
    };
    thumbs::validate(width, height, rgba.len())?;
    let host_id = {
        let sessions = state.sessions.lock();
        let s = sessions
            .get(&session_id)
            .ok_or_else(|| format!("unknown session: {session_id}"))?;
        let mut last = s.last_thumbnail.lock();
        let now = Instant::now();
        if last.is_some_and(|t| now.duration_since(t) < THUMBNAIL_GAP) {
            return Ok(());
        }
        let Some(host_id) = s.host_id.clone() else {
            return Ok(());
        };
        *last = Some(now);
        host_id
    };
    let dir = state.thumbs_dir.clone();
    let hosts = state.hosts.clone();
    super::blocking(move || {
        let jpeg = thumbs::encode(rgba, width, height)?;
        thumbs::save(&dir, &host_id, &jpeg)?;
        hosts
            .update(&host_id, |h| h.has_thumbnail = true)
            .map_err(|e| e.to_string())?;
        Ok::<_, String>(())
    })
    .await
}

/// End a session. Its `ended` event follows on `onEvent`.
#[tauri::command]
pub async fn session_disconnect(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    let handle = {
        let sessions = state.sessions.lock();
        match sessions.get(&session_id) {
            Some(s) => (s.handle.commands.clone(), s.handle.cancel.clone()),
            // Already gone: what the caller wanted.
            None => return Ok(()),
        }
    };
    let (commands, cancel) = handle;
    let _ = commands.try_send(ClientCommand::ReleaseAllKeys);
    if commands.send(ClientCommand::Disconnect).await.is_err() {
        cancel.cancel();
        return Ok(());
    }
    // A driver stuck on a dead socket still has to go.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        cancel.cancel();
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_targets_parse_from_the_wire() {
        let t: ConnectTarget =
            serde_json::from_value(serde_json::json!({ "kind": "saved", "hostId": "h1" })).unwrap();
        assert!(matches!(t, ConnectTarget::Saved { host_id } if host_id == "h1"));
        let t: ConnectTarget = serde_json::from_value(serde_json::json!({
            "kind": "adhoc", "protocol": "rdp", "address": "192.0.2.5", "port": 3389,
            "username": "alice"
        }))
        .unwrap();
        assert!(matches!(
            t,
            ConnectTarget::Adhoc {
                protocol: Protocol::Rdp,
                port: 3389,
                password: None,
                ..
            }
        ));
        let t: ConnectTarget = serde_json::from_value(serde_json::json!({
            "kind": "boundary", "invitation": "boundary1:x", "helperName": "Sam"
        }))
        .unwrap();
        assert!(matches!(t, ConnectTarget::Boundary { helper_name, .. } if helper_name == "Sam"));
    }

    #[test]
    fn quality_maps_onto_the_desktop_presets() {
        let q: Quality = serde_json::from_str("\"speed\"").unwrap();
        assert_eq!(QualityPreset::from(q), QualityPreset::Low);
        let q: Quality = serde_json::from_str("\"quality\"").unwrap();
        assert_eq!(QualityPreset::from(q), QualityPreset::High);
    }

    #[test]
    fn default_ports() {
        assert_eq!(options_for(Protocol::Vnc, " 192.0.2.1 ", 0).port, 5900);
        assert_eq!(options_for(Protocol::Rdp, "192.0.2.1", 0).port, 3389);
        assert_eq!(
            options_for(Protocol::Boundary, "192.0.2.1", 5940).port,
            5940
        );
        assert_eq!(options_for(Protocol::Vnc, "192.0.2.1", 0).host, "192.0.2.1");
    }

    #[tokio::test]
    async fn input_order_admits_in_sequence() {
        let order = Arc::new(InputOrder::new());
        let second = {
            let order = order.clone();
            tokio::spawn(async move { order.admit(2, Duration::from_secs(5)).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!second.is_finished());
        assert!(order.admit(1, Duration::from_secs(1)).await);
        order.done(1);
        assert!(second.await.unwrap());
        // A gap is released by the timeout.
        assert!(!order.admit(5, Duration::from_millis(10)).await);
    }
}
