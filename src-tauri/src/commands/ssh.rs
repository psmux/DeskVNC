//! Remote shell commands: the `ssh-core` session as Tauri IPC.
//!
//! Same shape as `commands/files.rs`, which is the model for a crate-backed
//! feature in this shell:
//! - one entry per session id in [`SshState`], keyed the same way,
//! - every command returns `Result<_, String>`,
//! - output and state changes go to the *session's own window* as flat JSON
//!   on `ssh://event`.
//!
//! SECURITY INVARIANTS (identical to the SFTP sidecar):
//! - The webview only ever picks an auth *kind*. Passwords and passphrases
//!   are loaded from the keychain here in Rust and never cross back into JS.
//! - Host keys are trust-on-first-use against the **same** pin store the
//!   Files panel and the RFB tunnel use, so trusting a machine once covers
//!   all three. An unknown key becomes a prompt outcome; a changed key is a
//!   hard stop with no "continue anyway".
//!
//! ## Why terminal traffic is base64 in a JSON event
//!
//! PTY output is binary: it carries partial UTF-8 sequences at chunk
//! boundaries and raw control bytes, neither of which survives a JSON string.
//! The framebuffer path solves this with the custom binary framing in
//! `framing.rs`, which is worth it for megabytes of pixels sixty times a
//! second. A terminal is three or four orders of magnitude quieter, so the
//! same trick would be a lot of machinery to save a few kilobytes; base64 in
//! the ordinary event channel keeps this feature in one file.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use parking_lot::Mutex;
use ssh_core::{MultiplexerConfig, SshEvent, SshSession, SshTermOptions, TerminalOptions};
use ssh_transport::{Error as SshError, SshConfig};
use tauri::{AppHandle, Emitter, State};

use crate::commands::files::{build_auth, local_username, AuthKind, FilesState};

/// Per-session terminal traffic. Flat JSON, `sessionId` beside `type`.
pub const SSH_EVENT: &str = "ssh://event";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct SshEntry {
    session: Arc<SshSession>,
    /// Window that receives this session's `ssh://event` traffic.
    window_label: String,
}

/// Remote-shell state, `app.manage`d alongside `AppState` and `FilesState`.
///
/// Note what is *not* here: a host-key store. There is exactly one of those
/// in the app, owned by [`FilesState`], and this feature borrows it. A second
/// store would mean a machine the user already trusted prompting again the
/// first time they opened a terminal on it.
#[derive(Default)]
pub struct SshState {
    sessions: Mutex<HashMap<String, Arc<SshEntry>>>,
}

impl SshState {
    pub fn new() -> Self {
        Self::default()
    }

    fn entry(&self, session_id: &str) -> Result<Arc<SshEntry>, String> {
        self.sessions
            .lock()
            .get(session_id)
            .cloned()
            .ok_or_else(|| format!("no terminal session for {session_id}"))
    }

    /// End every terminal bound to a window (window closing).
    pub fn shutdown_for_window(&self, window_label: &str) {
        let doomed: Vec<String> = self
            .sessions
            .lock()
            .iter()
            .filter(|(_, e)| e.window_label == window_label)
            .map(|(id, _)| id.clone())
            .collect();
        for id in doomed {
            let entry = self.sessions.lock().remove(&id);
            if let Some(entry) = entry {
                let session = entry.session.clone();
                tauri::async_runtime::spawn(async move { session.shutdown().await });
            }
        }
    }

    /// End every terminal (app exit).
    pub fn shutdown_all(&self) {
        let all: Vec<Arc<SshEntry>> = self.sessions.lock().drain().map(|(_, e)| e).collect();
        for entry in all {
            let session = entry.session.clone();
            tauri::async_runtime::spawn(async move { session.shutdown().await });
        }
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Connection request from the webview.
///
/// Deliberately *not* [`SshTermOptions`]: that type can carry a password, and
/// nothing the webview sends is allowed to. The webview picks an auth *kind*
/// and the secret is fetched from the keychain in [`build_auth`].
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConnectRequest {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default = "default_auth")]
    pub auth: AuthKind,
    #[serde(default)]
    pub key_path: Option<String>,
    /// Profile whose stored credential to use, for `AuthKind::Stored`.
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub cols: Option<u16>,
    #[serde(default)]
    pub rows: Option<u16>,
    #[serde(default)]
    pub multiplexer: Option<MultiplexerConfig>,
    /// Fingerprint the user has just accepted in the TOFU prompt. Pins it
    /// and retries exactly once, the same dance as `files_connect`.
    #[serde(default)]
    pub accept_host_key: Option<String>,
}

fn default_ssh_port() -> u16 {
    ssh_transport::DEFAULT_SSH_PORT
}

fn default_auth() -> AuthKind {
    AuthKind::Stored
}

/// What [`ssh_connect`] produced.
///
/// The two host-key cases come back as `Ok` rather than `Err`: they are
/// decisions for the user, not failures, and the UI renders a fingerprint
/// dialog for them instead of an error toast.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum SshConnectOutcome {
    Ready {
        endpoint: String,
    },
    HostKeyPrompt {
        host: String,
        port: u16,
        key_type: String,
        fingerprint: String,
    },
    HostKeyChanged {
        host: String,
        port: u16,
        expected: String,
        actual: String,
    },
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Is an SSH server reachable? Drives whether the Terminal button is enabled.
/// Never an error: an unreachable host is an answer.
#[tauri::command]
pub async fn ssh_probe(host: String, port: u16, timeout_ms: Option<u64>) -> Result<bool, String> {
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(1_500).clamp(200, 10_000));
    Ok(ssh_transport::probe_ssh(&host, port, timeout).await)
}

/// Open a supervised remote shell and start pumping its output to `window`.
#[tauri::command]
pub async fn ssh_connect(
    app: AppHandle,
    state: State<'_, SshState>,
    files: State<'_, FilesState>,
    session_id: String,
    window_label: String,
    config: SshConnectRequest,
) -> Result<SshConnectOutcome, String> {
    crate::windows::validate_session_id(&session_id)?;

    // Replacing an existing session is a reconnect, not a second terminal.
    if let Some(existing) = state.sessions.lock().remove(&session_id) {
        let session = existing.session.clone();
        tauri::async_runtime::spawn(async move { session.shutdown().await });
    }

    let auth = build_auth(
        &app,
        config.auth,
        config.key_path.as_deref(),
        config.profile_id.as_deref(),
    )
    .await?;

    // An empty username means "same user as here", the overwhelmingly common
    // case for a personal machine, and better than making the user retype it.
    let username = if config.username.trim().is_empty() {
        local_username()?
    } else {
        config.username.clone()
    };

    let mut options = SshTermOptions::new(SshConfig {
        host: config.host.clone(),
        port: config.port,
        username,
        auth,
        connect_timeout_ms: 15_000,
    });
    options.terminal = TerminalOptions {
        cols: config.cols.unwrap_or(80),
        rows: config.rows.unwrap_or(24),
        ..TerminalOptions::default()
    };
    if let Some(mux) = config.multiplexer.clone() {
        options.multiplexer = mux;
    }

    // A bad session name or an empty custom command must be caught here,
    // before a session is spawned, so the user gets the error rather than a
    // window that opens and dies immediately.
    options.multiplexer.validate().map_err(|e| e.to_string())?;

    let pins = files.host_key_verifier();

    // The host key is verified during the first connect, which happens inside
    // the supervised session. To keep the prompt-then-retry dance the Files
    // panel and the tunnel already use, decide the key here first, with a
    // throwaway carrier connect, and only spawn the session once it passes.
    match ssh_transport::connect_and_authenticate_with(
        &options.ssh,
        Arc::new(pins.clone()),
        ssh_transport::Keepalive::interactive(),
    )
    .await
    {
        Ok(handle) => {
            // The pin verified; refresh last-seen and drop this carrier.
            // Dropping the handle tears the transport down, which is why
            // there is no explicit disconnect here.
            //
            // The session then opens its own connection. That costs one extra
            // handshake per *terminal opened* (never per reconnect) and buys a
            // connect path identical to the Files panel and the RFB tunnel,
            // including the prompt-then-retry dance below.
            files.touch_host_key(&options.ssh.host, options.ssh.port);
            drop(handle);
        }
        Err(SshError::HostKeyUnknown {
            host,
            port,
            key_type,
            fingerprint,
        }) => {
            if config.accept_host_key.as_deref() == Some(fingerprint.as_str()) {
                files.trust_host_key(&host, port, &key_type, &fingerprint);
            } else {
                return Ok(SshConnectOutcome::HostKeyPrompt {
                    host,
                    port,
                    key_type,
                    fingerprint,
                });
            }
        }
        // HARD STOP. Never promptable, never retried (PRD/08 §4, PRD/10 §4.3).
        Err(SshError::HostKeyChanged {
            host,
            port,
            expected,
            actual,
        }) => {
            tracing::error!(%host, port, "ssh host key CHANGED, refusing to open a terminal");
            return Ok(SshConnectOutcome::HostKeyChanged {
                host,
                port,
                expected,
                actual,
            });
        }
        Err(e) => return Err(e.to_string()),
    }

    let endpoint = options.ssh.endpoint();
    let (session, events) = SshSession::spawn(options, pins);
    let session = Arc::new(session);

    state.sessions.lock().insert(
        session_id.clone(),
        Arc::new(SshEntry {
            session,
            window_label: window_label.clone(),
        }),
    );

    spawn_event_pump(app, session_id, window_label, events);

    Ok(SshConnectOutcome::Ready { endpoint })
}

/// Keystrokes and pastes. `data` is base64 because a terminal carries bytes,
/// not text; see the module header.
#[tauri::command]
pub async fn ssh_send(
    state: State<'_, SshState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .map_err(|e| format!("malformed terminal input: {e}"))?;
    state
        .entry(&session_id)?
        .session
        .input(bytes)
        .await
        .map_err(|e| e.to_string())
}

/// The window was resized; forward a `window-change` so remote programs
/// redraw at the new size.
#[tauri::command]
pub async fn ssh_resize(
    state: State<'_, SshState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    state
        .entry(&session_id)?
        .session
        .resize(cols, rows)
        .await
        .map_err(|e| e.to_string())
}

/// Skip the remaining reconnect backoff and try again now.
#[tauri::command]
pub async fn ssh_reconnect_now(
    state: State<'_, SshState>,
    session_id: String,
) -> Result<(), String> {
    state
        .entry(&session_id)?
        .session
        .reconnect_now()
        .await
        .map_err(|e| e.to_string())
}

/// End a terminal session.
#[tauri::command]
pub async fn ssh_disconnect(state: State<'_, SshState>, session_id: String) -> Result<(), String> {
    let entry = state.sessions.lock().remove(&session_id);
    if let Some(entry) = entry {
        entry.session.shutdown().await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Event pump
// ---------------------------------------------------------------------------

/// Forward `SshEvent`s to the session's window as flat JSON on `ssh://event`.
fn spawn_event_pump(
    app: AppHandle,
    session_id: String,
    window_label: String,
    mut events: tokio::sync::mpsc::Receiver<SshEvent>,
) {
    tauri::async_runtime::spawn(async move {
        let b64 = base64::engine::general_purpose::STANDARD;
        while let Some(event) = events.recv().await {
            let mut value = match event {
                SshEvent::Output(bytes) => serde_json::json!({
                    "type": "output",
                    "data": b64.encode(bytes),
                }),
                // Deliberately its own type rather than more `output`: these
                // bytes are the shell's correction for a dead session, not
                // something the server said, and a UI that logs or replays
                // output must be able to tell them apart.
                SshEvent::ResetTerminal(bytes) => serde_json::json!({
                    "type": "reset",
                    "data": b64.encode(bytes),
                }),
                SshEvent::Bell => serde_json::json!({ "type": "bell" }),
                SshEvent::Notice(message) => serde_json::json!({
                    "type": "notice",
                    "message": message,
                }),
                SshEvent::StateChanged(state) => {
                    let mut v = serde_json::to_value(&state)
                        .unwrap_or_else(|_| serde_json::json!({ "state": "disconnected" }));
                    if let Some(map) = v.as_object_mut() {
                        map.insert("type".into(), serde_json::json!("state"));
                    }
                    v
                }
            };

            if let Some(map) = value.as_object_mut() {
                map.insert("sessionId".into(), serde_json::json!(session_id));
            }
            if app.emit_to(&window_label, SSH_EVENT, value).is_err() {
                // The window is gone; nothing left to pump to.
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The IPC contract: kebab-case `status` discriminator, camelCase fields.
    #[test]
    fn the_connect_outcome_is_tagged_in_kebab_case() {
        let v = serde_json::to_value(SshConnectOutcome::HostKeyPrompt {
            host: "box".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            fingerprint: "SHA256:x".into(),
        })
        .unwrap();
        assert_eq!(v["status"], "host-key-prompt");
        assert_eq!(v["keyType"], "ssh-ed25519");
        assert!(v.get("key_type").is_none(), "snake_case leaked: {v}");
    }

    /// The webview sends camelCase keys and may omit everything optional.
    #[test]
    fn the_connect_request_accepts_the_minimal_camelcase_shape() {
        let r: SshConnectRequest = serde_json::from_str(r#"{ "host": "box.local" }"#).unwrap();
        assert_eq!(r.host, "box.local");
        assert_eq!(r.port, 22);
        assert!(r.username.is_empty(), "empty means the local user");
        assert!(r.multiplexer.is_none());
        assert!(r.accept_host_key.is_none());
    }

    #[test]
    fn the_connect_request_reads_a_full_camelcase_payload() {
        let r: SshConnectRequest = serde_json::from_str(
            r#"{ "host": "box.local", "port": 2222, "username": "gj",
                 "auth": "agent", "cols": 120, "rows": 40,
                 "multiplexer": { "kind": "tmux", "sessionName": "work" },
                 "acceptHostKey": "SHA256:abc" }"#,
        )
        .unwrap();
        assert_eq!(r.port, 2222);
        assert_eq!(r.cols, Some(120));
        assert_eq!(
            r.multiplexer.as_ref().map(|m| m.session_name.as_str()),
            Some("work")
        );
        assert_eq!(r.accept_host_key.as_deref(), Some("SHA256:abc"));
    }

    /// Terminal bytes have to survive the round trip exactly: a partial UTF-8
    /// sequence and a raw control byte are both perfectly normal PTY output,
    /// and either would be mangled by a plain JSON string.
    #[test]
    fn arbitrary_terminal_bytes_survive_the_base64_round_trip() {
        let b64 = base64::engine::general_purpose::STANDARD;
        // ESC [ ? 1 0 0 2 h, a lone 0xff, and a truncated UTF-8 lead byte.
        let raw = vec![
            0x1b, b'[', b'?', b'1', b'0', b'0', b'2', b'h', 0xff, 0xe2, 0x82,
        ];
        let decoded = b64.decode(b64.encode(&raw)).unwrap();
        assert_eq!(decoded, raw);
    }
}
