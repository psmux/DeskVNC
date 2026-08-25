//! File-transfer commands: the SFTP sidecar (PRD/08).
//!
//! Shape mirrors `commands/session.rs`:
//! - one entry per session id in shared state,
//! - every command returns `Result<_, String>`,
//! - progress goes to the *session's own window* as JSON on `files://event`,
//!   flat, with `sessionId` alongside a kebab-case `type` tag, exactly like
//!   `session://event` (see `src-tauri/IPC_CONTRACT.md`).
//!
//! SECURITY INVARIANTS
//! 1. Credentials travel JS → Rust only. `files_connect` takes an auth *kind*
//!    plus, for a saved host, nothing at all, the password/passphrase is
//!    loaded from the keychain on a blocking thread inside this module and
//!    never crosses back into the webview (`SshAuth` does not implement
//!    `Serialize`).
//! 2. Every server-supplied path goes through `vnc_files::path` before it is
//!    used. A malicious directory listing cannot write outside the folder the
//!    user picked in the native dialog.
//! 3. Host keys are trust-on-first-use. An unknown key returns a prompt
//!    payload; a *changed* key is a hard stop with no "continue anyway".

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::mpsc;
use vnc_files::{
    Error as FilesError, FileTransferConfig, HostKeyStore, RemoteEntry, SftpSession, SshAuth,
    SshConfig, TransferEvent, TransferQueue, MAX_CONCURRENT_TRANSFERS,
};

/// Filename of the SSH host-key pin store inside the app data directory.
/// Pins are not secrets (they are public-key fingerprints), so plain JSON next
/// to the rest of the app data is the right place, same reasoning as the
/// SQLite `cert_pins` table for TLS.
const PIN_FILE: &str = "ssh_host_keys.json";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// A live SFTP sidecar bound to a VNC session.
pub struct FilesEntry {
    sftp: Arc<SftpSession>,
    queue: Arc<TransferQueue>,
    /// Window that receives this session's `files://event` traffic.
    window_label: String,
    home: String,
}

/// File-transfer state, `app.manage`d alongside `AppState`.
pub struct FilesState {
    sessions: Mutex<HashMap<String, Arc<FilesEntry>>>,
    host_keys: Arc<Mutex<HostKeyStore>>,
    pin_path: PathBuf,
}

impl FilesState {
    /// `data_dir` is the same per-user app data directory the store and
    /// credential vault use.
    pub fn new(data_dir: PathBuf) -> Self {
        let pin_path = data_dir.join(PIN_FILE);
        let mut host_keys = std::fs::read_to_string(&pin_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<HostKeyStore>(&raw).ok())
            .unwrap_or_default();
        // A file written before host keys were pinned on the canonical host
        // can hold one machine twice, e.g. `studio.local` and `studio.local.`.
        // Merging them here keeps one entry per machine, so removing a pin
        // cannot leave a shadow copy behind to hard-stop the next connect.
        // The merged store is written back by the next `persist_pins`, so
        // startup stays read-only.
        let merged = host_keys.collapse_duplicates();
        if merged > 0 {
            tracing::info!("merged {merged} duplicate ssh host-key pin(s)");
        }
        Self {
            sessions: Mutex::new(HashMap::new()),
            host_keys: Arc::new(Mutex::new(host_keys)),
            pin_path,
        }
    }

    fn entry(&self, session_id: &str) -> Result<Arc<FilesEntry>, String> {
        self.sessions
            .lock()
            .get(session_id)
            .cloned()
            .ok_or_else(|| format!("no file-transfer session for {session_id}"))
    }

    fn persist_pins(&self) {
        let snapshot = self.host_keys.lock().clone();
        let path = self.pin_path.clone();
        match serde_json::to_string_pretty(&snapshot) {
            Ok(json) => {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!("could not persist ssh host-key pins: {e}");
                }
            }
            Err(e) => tracing::warn!("could not serialize ssh host-key pins: {e}"),
        }
    }

    /// The shared SSH host-key pin store, in the shape [`SshTunnel`] and
    /// [`SftpSession`] verify against. One store for both features: trusting
    /// a machine once covers its tunnel and its Files panel alike.
    pub fn host_key_verifier(&self) -> Arc<Mutex<HostKeyStore>> {
        self.host_keys.clone()
    }

    /// Pin a host key the user has explicitly accepted, and persist.
    pub fn trust_host_key(&self, host: &str, port: u16, key_type: &str, fingerprint: &str) {
        self.host_keys
            .lock()
            .trust(host, port, key_type, fingerprint, now_secs());
        self.persist_pins();
    }

    /// Refresh a pin's last-seen stamp after a verified connect, and persist.
    pub fn touch_host_key(&self, host: &str, port: u16) {
        self.host_keys.lock().touch(host, port, now_secs());
        self.persist_pins();
    }

    /// Cancel and forget every sidecar bound to a window (window closing).
    pub fn shutdown_for_window(&self, window_label: &str) {
        let doomed: Vec<String> = self
            .sessions
            .lock()
            .iter()
            .filter(|(_, e)| e.window_label == window_label)
            .map(|(id, _)| id.clone())
            .collect();
        for id in doomed {
            if let Some(entry) = self.sessions.lock().remove(&id) {
                entry.queue.cancel_all();
            }
        }
    }

    /// Cancel every sidecar (app exit).
    pub fn shutdown_all(&self) {
        for (_, entry) in self.sessions.lock().drain() {
            entry.queue.cancel_all();
        }
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// One local directory entry (left-hand pane). The Tauri fs plugin is
/// deliberately not enabled (PRD/08 §4), so local browsing goes through this
/// narrow command instead of a broad filesystem capability.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<i64>,
    pub is_symlink: bool,
}

/// Result of `files_connect`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ConnectOutcome {
    /// Connected; the panel can open at `home`.
    #[serde(rename_all = "camelCase")]
    Connected {
        host: String,
        port: u16,
        username: String,
        home: String,
    },
    /// First contact. Show the fingerprint, and if the user accepts call
    /// `files_connect` again with `acceptHostKey` set to this fingerprint.
    #[serde(rename_all = "camelCase")]
    HostKeyPrompt {
        host: String,
        port: u16,
        key_type: String,
        fingerprint: String,
    },
    /// The pinned key changed. **Hard stop**, there is deliberately no way to
    /// accept this from the UI (PRD/08 §4).
    #[serde(rename_all = "camelCase")]
    HostKeyChanged {
        host: String,
        port: u16,
        expected: String,
        actual: String,
    },
}

/// Result of `files_status`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesStatus {
    pub connected: bool,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub home: Option<String>,
    pub active_transfers: usize,
    pub queue_limit: usize,
}

/// The auth choice the webview is allowed to make. The secret itself is never
/// part of this, see the module-level security invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthKind {
    /// Use the stored SSH passphrase / password for this host profile.
    Stored,
    /// Use the given private key file with the stored passphrase.
    KeyFile,
    /// ssh-agent / Pageant / Windows OpenSSH pipe.
    Agent,
}

/// Connection request from the webview. Deliberately *not* `FileTransferConfig`
///, that type carries secrets, and nothing carrying a secret is accepted from
/// JS here.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesConnectRequest {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    #[serde(default = "default_auth")]
    pub auth: AuthKind,
    /// Private key path for `key-file` auth (chosen through the native dialog).
    #[serde(default)]
    pub key_path: Option<String>,
    /// Host profile whose keychain entry holds the password/passphrase.
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub default_remote_dir: Option<String>,
    #[serde(default)]
    pub conflict: vnc_files::ConflictPolicy,
}

fn default_port() -> u16 {
    vnc_files::DEFAULT_SSH_PORT
}

fn default_auth() -> AuthKind {
    AuthKind::Stored
}

// ---------------------------------------------------------------------------
// Commands, connection lifecycle
// ---------------------------------------------------------------------------

/// Is SSH reachable? Drives the enabled/disabled state of the toolbar Files
/// button (PRD/08 §2.1). Never errors: "no" is an answer.
#[tauri::command]
pub async fn files_probe(host: String, port: Option<u16>) -> Result<bool, String> {
    let port = port.unwrap_or(vnc_files::DEFAULT_SSH_PORT);
    Ok(vnc_files::probe_ssh(&host, port, Duration::from_millis(1500)).await)
}

/// Open the SFTP sidecar for a session.
///
/// Call again with `acceptHostKey` set to the fingerprint from a
/// `host-key-prompt` outcome to pin the key and connect.
#[tauri::command]
pub async fn files_connect(
    window: tauri::WebviewWindow,
    app: AppHandle,
    state: State<'_, FilesState>,
    session_id: String,
    config: FilesConnectRequest,
    accept_host_key: Option<String>,
) -> Result<ConnectOutcome, String> {
    crate::windows::validate_session_id(&session_id)?;

    // Already connected to the same endpoint: reuse it, don't stack sidecars.
    if let Ok(existing) = state.entry(&session_id) {
        if existing.sftp.host() == config.host && existing.sftp.port() == config.port {
            return Ok(ConnectOutcome::Connected {
                host: existing.sftp.host().to_string(),
                port: existing.sftp.port(),
                username: existing.sftp.username().to_string(),
                home: existing.home.clone(),
            });
        }
        disconnect_entry(&state, &session_id).await;
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
    let cfg = FileTransferConfig {
        ssh: SshConfig {
            host: config.host.clone(),
            port: config.port,
            username,
            auth,
            connect_timeout_ms: 15_000,
        },
        default_remote_dir: config.default_remote_dir.clone(),
        conflict: config.conflict,
    };

    let pins = state.host_keys.clone();
    let session = match SftpSession::connect(cfg.clone(), pins.clone()).await {
        Ok(session) => session,
        Err(FilesError::HostKeyUnknown {
            host,
            port,
            key_type,
            fingerprint,
        }) => {
            // The user already saw this fingerprint and accepted it: pin and
            // retry exactly once.
            if accept_host_key.as_deref() == Some(fingerprint.as_str()) {
                pins.lock()
                    .trust(&host, port, &key_type, &fingerprint, now_secs());
                state.persist_pins();
                SftpSession::connect(cfg, pins.clone())
                    .await
                    .map_err(|e| e.to_string())?
            } else {
                return Ok(ConnectOutcome::HostKeyPrompt {
                    host,
                    port,
                    key_type,
                    fingerprint,
                });
            }
        }
        // HARD STOP. Never promptable, never retried, a changed host key
        // blocks file transfer just as it blocks tunnels (PRD/08 §4).
        Err(FilesError::HostKeyChanged {
            host,
            port,
            expected,
            actual,
        }) => {
            tracing::error!(%host, port, "ssh host key CHANGED, refusing file transfer");
            return Ok(ConnectOutcome::HostKeyChanged {
                host,
                port,
                expected,
                actual,
            });
        }
        Err(e) => return Err(e.to_string()),
    };

    // A successful connect means the pin verified; refresh last-seen.
    pins.lock().touch(&config.host, config.port, now_secs());
    state.persist_pins();

    let home = session.home_dir().await.unwrap_or_else(|_| ".".to_string());
    let entry = Arc::new(FilesEntry {
        sftp: Arc::new(session),
        queue: Arc::new(TransferQueue::new(MAX_CONCURRENT_TRANSFERS)),
        window_label: window.label().to_string(),
        home: home.clone(),
    });
    state
        .sessions
        .lock()
        .insert(session_id.clone(), entry.clone());

    tracing::info!(session = %session_id, endpoint = %format!("{}:{}", config.host, config.port), "sftp sidecar ready");
    Ok(ConnectOutcome::Connected {
        host: entry.sftp.host().to_string(),
        port: entry.sftp.port(),
        username: entry.sftp.username().to_string(),
        home,
    })
}

/// Close the sidecar and cancel anything still in flight.
#[tauri::command]
pub async fn files_disconnect(
    state: State<'_, FilesState>,
    session_id: String,
) -> Result<(), String> {
    disconnect_entry(&state, &session_id).await;
    Ok(())
}

#[tauri::command]
pub async fn files_status(
    state: State<'_, FilesState>,
    session_id: String,
) -> Result<FilesStatus, String> {
    match state.sessions.lock().get(&session_id) {
        Some(entry) => Ok(FilesStatus {
            connected: true,
            host: Some(entry.sftp.host().to_string()),
            port: Some(entry.sftp.port()),
            username: Some(entry.sftp.username().to_string()),
            home: Some(entry.home.clone()),
            active_transfers: entry.queue.live(),
            queue_limit: entry.queue.limit(),
        }),
        None => Ok(FilesStatus {
            connected: false,
            host: None,
            port: None,
            username: None,
            home: None,
            active_transfers: 0,
            queue_limit: MAX_CONCURRENT_TRANSFERS,
        }),
    }
}

// ---------------------------------------------------------------------------
// Commands, remote browsing
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn files_home(
    state: State<'_, FilesState>,
    session_id: String,
) -> Result<String, String> {
    let entry = state.entry(&session_id)?;
    entry.sftp.home_dir().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_list(
    state: State<'_, FilesState>,
    session_id: String,
    path: String,
) -> Result<Vec<RemoteEntry>, String> {
    let entry = state.entry(&session_id)?;
    entry.sftp.list_dir(&path).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_mkdir(
    state: State<'_, FilesState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let entry = state.entry(&session_id)?;
    entry.sftp.mkdir(&path).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_remove(
    state: State<'_, FilesState>,
    session_id: String,
    path: String,
    recursive: Option<bool>,
) -> Result<(), String> {
    let entry = state.entry(&session_id)?;
    entry
        .sftp
        .remove(&path, recursive.unwrap_or(false))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_rename(
    state: State<'_, FilesState>,
    session_id: String,
    from: String,
    to: String,
) -> Result<(), String> {
    let entry = state.entry(&session_id)?;
    entry
        .sftp
        .rename(&from, &to)
        .await
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Commands, transfers
// ---------------------------------------------------------------------------

/// Queue an upload of each local path into `remoteDir`. Returns one transfer
/// id per path; progress arrives on `files://event`.
#[tauri::command]
pub async fn files_upload(
    app: AppHandle,
    state: State<'_, FilesState>,
    session_id: String,
    local_paths: Vec<String>,
    remote_dir: String,
) -> Result<Vec<String>, String> {
    let entry = state.entry(&session_id)?;
    if local_paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::with_capacity(local_paths.len());
    for local in local_paths {
        let local = PathBuf::from(&local);
        if !local.is_absolute() {
            return Err(format!("local path must be absolute: {}", local.display()));
        }
        if !local.exists() {
            return Err(format!("no such file: {}", local.display()));
        }
        let id = uuid::Uuid::new_v4().to_string();
        spawn_transfer(
            app.clone(),
            entry.clone(),
            session_id.clone(),
            id.clone(),
            Job::Upload {
                local,
                remote_dir: remote_dir.clone(),
            },
        );
        ids.push(id);
    }
    Ok(ids)
}

/// Queue a download of each remote path into `localDir`.
///
/// `localDir` must be a directory the user picked (native dialog). Every
/// destination underneath it is built with `vnc_files::path::local_destination`,
/// so a hostile listing cannot escape it.
#[tauri::command]
pub async fn files_download(
    app: AppHandle,
    state: State<'_, FilesState>,
    session_id: String,
    remote_paths: Vec<String>,
    local_dir: String,
) -> Result<Vec<String>, String> {
    let entry = state.entry(&session_id)?;
    let local_dir = PathBuf::from(&local_dir);
    if !local_dir.is_absolute() {
        return Err("the download directory must be an absolute path".into());
    }
    if !local_dir.is_dir() {
        return Err(format!("not a directory: {}", local_dir.display()));
    }
    // Reject the whole batch before a single byte moves if any path is unsafe.
    let remote_paths =
        vnc_files::transfer::validate_remote_batch(&remote_paths).map_err(|e| e.to_string())?;

    let mut ids = Vec::with_capacity(remote_paths.len());
    for remote in remote_paths {
        let id = uuid::Uuid::new_v4().to_string();
        spawn_transfer(
            app.clone(),
            entry.clone(),
            session_id.clone(),
            id.clone(),
            Job::Download {
                remote,
                local_dir: local_dir.clone(),
            },
        );
        ids.push(id);
    }
    Ok(ids)
}

/// Cancel one queued or running transfer.
#[tauri::command]
pub async fn files_cancel(
    state: State<'_, FilesState>,
    session_id: String,
    transfer_id: String,
) -> Result<bool, String> {
    let entry = state.entry(&session_id)?;
    Ok(entry.queue.cancel(&transfer_id))
}

// ---------------------------------------------------------------------------
// Commands, local pane
// ---------------------------------------------------------------------------

/// The local home directory, where the left-hand pane opens.
#[tauri::command]
pub async fn files_local_home(app: AppHandle) -> Result<String, String> {
    let home = app.path().home_dir().map_err(|e| e.to_string())?;
    Ok(home.to_string_lossy().to_string())
}

/// List a local directory. Narrow by design: the Tauri fs plugin stays off
/// (PRD/08 §4), so this is the only local read path the webview has.
#[tauri::command]
pub async fn files_local_list(
    app: AppHandle,
    path: Option<String>,
) -> Result<Vec<LocalEntry>, String> {
    let dir = match path {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => app.path().home_dir().map_err(|e| e.to_string())?,
    };
    let dir = if dir.is_absolute() {
        dir
    } else {
        return Err("path must be absolute".into());
    };

    let entries = tokio::task::spawn_blocking(move || read_local_dir(&dir))
        .await
        .map_err(|e| e.to_string())??;
    Ok(entries)
}

#[tauri::command]
pub async fn files_local_mkdir(path: String) -> Result<(), String> {
    let path = guard_local_path(&path)?;
    tokio::fs::create_dir(&path)
        .await
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[tauri::command]
pub async fn files_local_rename(from: String, to: String) -> Result<(), String> {
    let from = guard_local_path(&from)?;
    let to = guard_local_path(&to)?;
    tokio::fs::rename(&from, &to)
        .await
        .map_err(|e| format!("{}: {e}", from.display()))
}

#[tauri::command]
pub async fn files_local_remove(path: String, recursive: Option<bool>) -> Result<(), String> {
    let path = guard_local_path(&path)?;
    let meta = tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let result = if meta.is_dir() {
        if recursive.unwrap_or(false) {
            tokio::fs::remove_dir_all(&path).await
        } else {
            tokio::fs::remove_dir(&path).await
        }
    } else {
        tokio::fs::remove_file(&path).await
    };
    result.map_err(|e| format!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

enum Job {
    Upload { local: PathBuf, remote_dir: String },
    Download { remote: String, local_dir: PathBuf },
}

/// Register, queue and run one transfer, forwarding its events to the
/// session's window.
fn spawn_transfer(
    app: AppHandle,
    entry: Arc<FilesEntry>,
    session_id: String,
    id: String,
    job: Job,
) {
    let cancel = entry.queue.register(&id);
    let (tx, mut rx) = mpsc::channel::<TransferEvent>(64);

    // Event pump: TransferEvent -> `files://event` on the session window.
    let window_label = entry.window_label.clone();
    let queue = entry.queue.clone();
    let event_session = session_id.clone();
    let event_id = id.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            let terminal = event.is_terminal();
            match serde_json::to_value(&event) {
                Ok(mut value) => {
                    if let Some(map) = value.as_object_mut() {
                        map.insert("sessionId".into(), json!(event_session));
                    }
                    let _ = app.emit_to(&window_label, "files://event", value);
                }
                Err(e) => tracing::warn!("could not serialize transfer event: {e}"),
            }
            if terminal {
                queue.finish(&event_id);
            }
        }
    });

    // Worker: hold a queue slot for the whole item, so a folder tree occupies
    // one slot however many files it contains (PRD/08 §3.3).
    tauri::async_runtime::spawn(async move {
        let _permit = entry.queue.acquire().await;
        let result = match job {
            Job::Upload { local, remote_dir } => {
                entry
                    .sftp
                    .upload(&local, &remote_dir, id.clone(), tx, cancel)
                    .await
            }
            Job::Download { remote, local_dir } => {
                entry
                    .sftp
                    .download(&remote, &local_dir, id.clone(), tx, cancel)
                    .await
            }
        };
        if let Err(e) = result {
            // The failure event was already emitted by the transfer itself.
            tracing::warn!(transfer = %id, "transfer failed: {e}");
        }
    });
}

async fn disconnect_entry(state: &FilesState, session_id: &str) {
    let entry = state.sessions.lock().remove(session_id);
    let Some(entry) = entry else { return };
    entry.queue.cancel_all();
    // Give in-flight chunk loops a beat to notice the cancellation before the
    // transport goes away, so they emit `cancelled` rather than an i/o error.
    tokio::time::sleep(Duration::from_millis(50)).await;
    if let Some(session) = Arc::into_inner(entry) {
        if let Some(sftp) = Arc::into_inner(session.sftp) {
            let _ = sftp.close().await;
        }
    }
}

/// Build the auth method **in Rust**. The webview picks a kind; the secret
/// comes from the keychain here and never travels back out. Shared with the
/// SSH tunnel (`crate::tunnel`), which authenticates exactly like the sidecar.
pub(crate) async fn build_auth(
    app: &AppHandle,
    auth: AuthKind,
    key_path: Option<&str>,
    profile_id: Option<&str>,
) -> Result<SshAuth, String> {
    match auth {
        AuthKind::Agent => Ok(SshAuth::Agent),
        AuthKind::KeyFile => {
            let path = key_path.ok_or("key-file authentication needs a keyPath")?;
            let passphrase = stored_ssh_secret(app, profile_id).await;
            Ok(SshAuth::KeyFile {
                path: PathBuf::from(path),
                passphrase,
            })
        }
        AuthKind::Stored => match stored_ssh_secret(app, profile_id).await {
            Some(secret) => Ok(SshAuth::Password(secret)),
            // Nothing saved: fall back to the agent rather than failing, which
            // is the common case on a developer machine.
            None => Ok(SshAuth::Agent),
        },
    }
}

/// Load the SSH passphrase saved for a host profile (blocking keychain IO on a
/// blocking thread, exactly like `connect_session`).
async fn stored_ssh_secret(app: &AppHandle, profile_id: Option<&str>) -> Option<String> {
    let profile_id = profile_id?;
    let state = app.try_state::<crate::state::AppState>()?;
    let credentials = state.credentials.clone();
    let lookup = profile_id.to_string();
    match super::blocking(move || credentials.load(&lookup)).await {
        Ok(Some(stored)) => stored.ssh_passphrase,
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("could not load stored ssh credentials: {e}");
            None
        }
    }
}

fn read_local_dir(dir: &Path) -> Result<Vec<LocalEntry>, String> {
    let read = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut entries = Vec::new();
    for item in read.flatten() {
        let path = item.path();
        let Ok(meta) = item.metadata() else { continue };
        let link = std::fs::symlink_metadata(&path).ok();
        entries.push(LocalEntry {
            name: item.file_name().to_string_lossy().to_string(),
            path: path.to_string_lossy().to_string(),
            is_dir: meta.is_dir(),
            size: if meta.is_dir() { 0 } else { meta.len() },
            modified: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
            is_symlink: link.map(|m| m.is_symlink()).unwrap_or(false),
        });
    }
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

/// Local mutations must name an absolute path with a real parent, and must
/// never target a filesystem root. Cheap guard against a malformed request
/// turning `remove` into something catastrophic.
fn guard_local_path(path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err("path must be absolute".into());
    }
    if path.parent().is_none() {
        return Err("refusing to operate on a filesystem root".into());
    }
    if path.file_name().is_none() {
        return Err("path must name a file or directory".into());
    }
    Ok(path)
}

/// The account this app is running as, used when the UI does not know which
/// remote user to log in as.
pub(crate) fn local_username() -> Result<String, String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|u| !u.trim().is_empty())
        .ok_or_else(|| "no ssh user name was given and none could be guessed".to_string())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_outcome_uses_the_ipc_casing() {
        let value = serde_json::to_value(ConnectOutcome::HostKeyPrompt {
            host: "h".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            fingerprint: "SHA256:x".into(),
        })
        .unwrap();
        assert_eq!(value["status"], "host-key-prompt");
        assert_eq!(value["keyType"], "ssh-ed25519");

        let value = serde_json::to_value(ConnectOutcome::Connected {
            host: "h".into(),
            port: 22,
            username: "user".into(),
            home: "/home/user".into(),
        })
        .unwrap();
        assert_eq!(value["status"], "connected");
        assert_eq!(value["home"], "/home/user");
    }

    #[test]
    fn status_is_camel_case() {
        let value = serde_json::to_value(FilesStatus {
            connected: false,
            host: None,
            port: None,
            username: None,
            home: None,
            active_transfers: 0,
            queue_limit: 3,
        })
        .unwrap();
        assert_eq!(value["activeTransfers"], 0);
        assert_eq!(value["queueLimit"], 3);
    }

    #[test]
    fn connect_request_defaults_match_the_contract() {
        let request: FilesConnectRequest =
            serde_json::from_str(r#"{ "host": "h", "username": "user" }"#).unwrap();
        assert_eq!(request.port, 22);
        assert_eq!(request.auth, AuthKind::Stored);
        assert_eq!(request.conflict, vnc_files::ConflictPolicy::Resume);

        let request: FilesConnectRequest = serde_json::from_str(
            r#"{ "host": "h", "port": 2222, "username": "user", "auth": "key-file",
                 "keyPath": "/k", "profileId": "p1", "conflict": "overwrite" }"#,
        )
        .unwrap();
        assert_eq!(request.auth, AuthKind::KeyFile);
        assert_eq!(request.key_path.as_deref(), Some("/k"));
        assert_eq!(request.profile_id.as_deref(), Some("p1"));
    }

    #[test]
    fn local_mutations_refuse_roots_and_relative_paths() {
        assert!(guard_local_path("relative/path").is_err());
        assert!(guard_local_path("/").is_err());
        assert!(guard_local_path("/tmp/thing").is_ok());
    }

    #[test]
    fn a_missing_pin_file_yields_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let state = FilesState::new(dir.path().to_path_buf());
        assert!(state.host_keys.lock().pins.is_empty());

        state
            .host_keys
            .lock()
            .trust("h", 22, "ssh-ed25519", "SHA256:x", 1);
        state.persist_pins();

        let reloaded = FilesState::new(dir.path().to_path_buf());
        assert_eq!(reloaded.host_keys.lock().pins.len(), 1);
        assert_eq!(reloaded.host_keys.lock().pins[0].fingerprint, "SHA256:x");
    }

    /// A pin file written before host keys were keyed on the canonical host
    /// can name one machine twice; loading it must leave a single pin.
    #[test]
    fn loading_merges_duplicate_spellings_of_one_host() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(PIN_FILE),
            r#"{ "pins": [
                   { "host": "studio.local", "port": 22, "keyType": "ssh-ed25519",
                     "fingerprint": "SHA256:old", "firstTrustedAt": 1, "lastSeenAt": 1 },
                   { "host": "studio.local.", "port": 22, "keyType": "ssh-ed25519",
                     "fingerprint": "SHA256:new", "firstTrustedAt": 2, "lastSeenAt": 9 }
                 ] }"#,
        )
        .unwrap();
        let state = FilesState::new(dir.path().to_path_buf());
        let pins = state.host_keys.lock();
        assert_eq!(pins.pins.len(), 1);
        assert_eq!(pins.pins[0].fingerprint, "SHA256:new");
    }

    #[test]
    fn a_corrupt_pin_file_does_not_break_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PIN_FILE), b"{not json").unwrap();
        let state = FilesState::new(dir.path().to_path_buf());
        assert!(state.host_keys.lock().pins.is_empty());
    }
}
