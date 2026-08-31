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
use std::path::Path;
use tauri::{AppHandle, Emitter, Manager, State};

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

/// Which WSL distributions does this host have?
///
/// Connects, asks, and drops the connection. Returns an empty list rather
/// than an error whenever the question cannot be answered: a host with no
/// WSL, no `wsl.exe`, or credentials we do not hold is an ordinary state, and
/// the host editor answers it by showing a plain name field instead of a
/// picker. Failing the call would turn that into an error dialog for
/// something that is not wrong.
#[tauri::command]
pub async fn ssh_list_wsl_distros(
    app: AppHandle,
    files: State<'_, FilesState>,
    config: SshConnectRequest,
) -> Result<Vec<String>, String> {
    let auth = build_auth(
        &app,
        config.auth,
        config.key_path.as_deref(),
        config.profile_id.as_deref(),
    )
    .await?;
    let username = if config.username.trim().is_empty() {
        local_username()?
    } else {
        config.username.clone()
    };

    let cfg = SshConfig {
        host: config.host.clone(),
        port: config.port,
        username,
        auth,
        connect_timeout_ms: 15_000,
    };

    let handle = match ssh_transport::connect_and_authenticate_with(
        &cfg,
        Arc::new(files.host_key_verifier()),
        ssh_transport::Keepalive::interactive(),
    )
    .await
    {
        Ok(h) => h,
        // Includes an untrusted host key. The list is a convenience, and the
        // real connect is where a fingerprint prompt belongs, so this stays
        // quiet rather than raising a dialog from a settings form.
        Err(e) => {
            tracing::debug!("could not list wsl distributions: {e}");
            return Ok(Vec::new());
        }
    };

    let distros = ssh_core::pty::list_wsl_distros(&handle).await;
    drop(handle);
    Ok(distros)
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
// Local key discovery
// ---------------------------------------------------------------------------

/// One private key sitting in the user's `~/.ssh`.
///
/// A path and a label, never key material: the file is read here only far
/// enough to tell a private key from a `known_hosts`, and the bytes are
/// dropped again before this struct is built. The same invariant the rest of
/// this module runs on (secrets stay in Rust) is why `kind` and `comment`
/// come from the *public* half of the pair.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalKey {
    /// Absolute path, which is what goes into `keyPath`.
    pub path: String,
    /// File name on its own, which is what a person recognises.
    pub name: String,
    /// `ed25519`, `rsa`, `ecdsa`, `dsa`, `pkcs8`, or empty when the file is a
    /// private key whose algorithm we cannot name without unlocking it.
    pub kind: String,
    /// The trailing comment on the `.pub` sibling, usually `user@machine`.
    pub comment: Option<String>,
    /// The key is passphrase-protected, so connecting needs the passphrase
    /// saved in the keychain. Drives a hint in the host editor.
    pub encrypted: bool,
}

/// What [`ssh_list_local_keys`] found, and where it looked.
///
/// `dir` travels back even when `keys` is empty: it is what the Browse button
/// opens the native file dialog at, and a first-time user with no keys yet is
/// exactly who needs the dialog to start somewhere useful.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalKeys {
    pub dir: String,
    pub keys: Vec<LocalKey>,
}

/// Names in `~/.ssh` that are never private keys.
const NOT_KEYS: &[&str] = &[
    "config",
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "authorized_keys2",
    "environment",
    "rc",
];

/// List the private keys in `~/.ssh`, so choosing one is a pick from a list
/// rather than a path typed from memory.
///
/// Never an error worth showing: no `~/.ssh` at all is an ordinary state on a
/// machine that has never used SSH, and the editor answers it with the Browse
/// button rather than a red box.
#[tauri::command]
pub async fn ssh_list_local_keys(app: AppHandle) -> Result<LocalKeys, String> {
    let dir = app.path().home_dir().map_err(|e| e.to_string())?.join(".ssh");
    let scan = dir.clone();
    let keys = tokio::task::spawn_blocking(move || scan_key_dir(&scan))
        .await
        .unwrap_or_default();
    Ok(LocalKeys {
        dir: dir.to_string_lossy().to_string(),
        keys,
    })
}

/// Every private key in one directory, sorted by name.
fn scan_key_dir(dir: &Path) -> Vec<LocalKey> {
    let Ok(read) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for item in read.flatten() {
        let name = item.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || name.ends_with(".pub") || NOT_KEYS.contains(&name.as_str()) {
            continue;
        }
        let path = item.path();
        if !item.metadata().map(|m| m.is_file()).unwrap_or(false) {
            continue;
        }
        // Read a head, not the file: a private key's identifying line is its
        // first, and a stray multi-megabyte file in `~/.ssh` should cost this
        // scan one page rather than its whole length.
        let Some(head) = read_head(&path) else {
            continue;
        };
        let Some((kind, encrypted)) = classify_key(&head) else {
            continue;
        };
        let (pub_kind, comment) = read_public_half(&path);
        keys.push(LocalKey {
            path: path.to_string_lossy().to_string(),
            name,
            // The `.pub` sibling names the algorithm exactly and costs
            // nothing to read; the private half's own header only says
            // "OPENSSH", so it is the fallback rather than the source.
            kind: pub_kind.unwrap_or(kind),
            comment,
            encrypted,
        });
    }
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    keys
}

/// The first 4 KiB of a file as lossy UTF-8, or `None` if it cannot be read.
fn read_head(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 4096];
    let read = file.read(&mut buf).ok()?;
    buf.truncate(read);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Is this a private key, and if so what kind, and is it locked?
///
/// Returns `None` for anything that is not a private key at all, which is how
/// the scan filters a directory it does not otherwise understand.
fn classify_key(head: &str) -> Option<(String, bool)> {
    let trimmed = head.trim_start();

    // PuTTY's own format, which this app reads (v2 and v3). The header line
    // names the algorithm and an `Encryption:` line names the cipher.
    if let Some(rest) = trimmed.strip_prefix("PuTTY-User-Key-File-") {
        // `PuTTY-User-Key-File-3: ssh-ed25519`: the version is what the
        // prefix ate, so the algorithm is what follows the colon on that
        // first line and nowhere else.
        let algorithm = rest
            .lines()
            .next()
            .and_then(|line| line.split_once(':'))
            .map(|(_, algorithm)| algorithm.trim())
            .unwrap_or("");
        let encrypted = header_value(head, "Encryption:")
            .map(|c| c != "none")
            .unwrap_or(false);
        return Some((algorithm_name(algorithm), encrypted));
    }

    let begin = trimmed.lines().next()?.trim();
    if !begin.starts_with("-----BEGIN ") || !begin.contains("PRIVATE KEY") {
        return None;
    }

    if begin.contains("OPENSSH") {
        return Some(("".into(), openssh_is_encrypted(head)));
    }
    // The classic PEM formats say what they hold on the BEGIN line, and mark
    // an encrypted body with a `Proc-Type` header rather than in the body.
    let locked = head.contains("Proc-Type: 4,ENCRYPTED");
    if begin.contains("RSA") {
        return Some(("rsa".into(), locked));
    }
    if begin.contains("EC ") {
        return Some(("ecdsa".into(), locked));
    }
    if begin.contains("DSA") {
        return Some(("dsa".into(), locked));
    }
    // PKCS#8, whose BEGIN line says nothing about the algorithm. The
    // ENCRYPTED variant is the only one that is locked.
    Some(("pkcs8".into(), begin.contains("ENCRYPTED")))
}

/// Value of a `Name: value` header line in a PuTTY key file.
fn header_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim)
}

/// Is an `openssh-key-v1` private key passphrase-protected?
///
/// The format puts the cipher name in cleartext at the very start of the
/// base64 body: the magic `openssh-key-v1\0`, then a length-prefixed string
/// which is `none` for an unlocked key. Only the first few lines are decoded,
/// which is more than enough to reach it.
fn openssh_is_encrypted(head: &str) -> bool {
    let body: String = head
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .take(4)
        .flat_map(|l| l.trim().chars())
        .collect();
    // The tail of a 4-line slice is very unlikely to land on a 4-character
    // boundary, so decode the largest prefix that does rather than failing.
    let usable = body.len() - body.len() % 4;
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&body[..usable]) else {
        return false;
    };
    const MAGIC: &[u8] = b"openssh-key-v1\0";
    let Some(rest) = bytes.strip_prefix(MAGIC) else {
        return false;
    };
    if rest.len() < 4 {
        return false;
    }
    let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let Some(cipher) = rest.get(4..4 + len) else {
        return false;
    };
    cipher != b"none"
}

/// The algorithm and comment from a key's `.pub` sibling, when there is one.
///
/// A public key line is `algorithm base64 comment`, and both ends of it are
/// worth showing: the algorithm because `id_rsa` is not always RSA, and the
/// comment because it is usually the only thing distinguishing two keys with
/// generated names.
fn read_public_half(private: &Path) -> (Option<String>, Option<String>) {
    let mut public = private.as_os_str().to_os_string();
    public.push(".pub");
    let Ok(text) = std::fs::read_to_string(Path::new(&public)) else {
        return (None, None);
    };
    let Some(line) = text.lines().next() else {
        return (None, None);
    };
    let mut fields = line.split_whitespace();
    let algorithm = fields.next().map(algorithm_name).filter(|k| !k.is_empty());
    let _base64 = fields.next();
    let comment = fields.collect::<Vec<_>>().join(" ");
    (algorithm, Some(comment).filter(|c| !c.is_empty()))
}

/// `ssh-ed25519` and friends as the short name a person reads.
///
/// The wire names carry prefixes and suffixes that mean something to the
/// protocol and nothing in a dropdown: `sk-` for a hardware key, `ssh-` for
/// the older algorithms, a curve after `ecdsa`, and `@openssh.com` on every
/// vendor extension.
fn algorithm_name(algorithm: &str) -> String {
    let mut short = algorithm.trim();
    short = short.strip_prefix("sk-").unwrap_or(short);
    short = short.strip_prefix("ssh-").unwrap_or(short);
    let short = short.split(['-', '@']).next().unwrap_or(short);
    match short {
        // Only the wire name is `dss`; everything a person reads says DSA.
        "dss" => "dsa".into(),
        s => s.to_string(),
    }
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
            // An answer to an agent intent is for the plane, not the pane, and
            // that is the same decision `event_json` takes for the same two
            // variants (`commands/session.rs`). Two reasons. The payload of a
            // served answer is a remote machine's own bytes, so surfacing it
            // here would put output into somebody's terminal window that they
            // never asked for and did not type. And the only consumer that
            // needs it is the `AttachedLimb` waiting on the intent id, which
            // lives in the agent's own process on the far side of the socket,
            // not in this window.
            //
            // OWED, and deliberately not faked: the socket does not carry
            // `exec` at all yet (`agent/server.rs`'s `GRANTED` says so in
            // terms), so nothing is waiting for these on the other end. When
            // `exec` is granted, the answer has to travel back as the reply to
            // the request that started it, and this is where it gets picked
            // up. Logged rather than dropped in silence, because a driver
            // answering into a void is exactly the failure `00 R28` exists to
            // prevent and it should be visible while it is true.
            let mut value = match event {
                SshEvent::AgentServed(_) | SshEvent::AgentRefused(_) => {
                    tracing::debug!(
                        session = %session_id,
                        "an agent intent was answered by the SSH driver, and nothing is waiting for it yet: the socket does not grant exec"
                    );
                    continue;
                }
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
                // The sidecar terminal is opened from a session that already
                // holds a credential, so an ask here means that credential was
                // refused. Reported as a notice rather than answered: this
                // entry point has no dialog of its own, and the session-level
                // terminal (the SSH *protocol*) is the one with the full
                // prompt flow. Surfacing it tells the user why the shell did
                // not open instead of leaving them with a blank panel.
                SshEvent::CredentialsRequired { method, error, .. } => serde_json::json!({
                    "type": "notice",
                    "message": match error {
                        Some(why) => format!("{method} authentication was refused: {why}"),
                        None => format!("{method} authentication is required"),
                    },
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

    /// The scan has to answer three questions about a directory that holds
    /// far more than keys: which files are private keys at all, what
    /// algorithm each one is, and which of them will need a passphrase.
    ///
    /// The bodies here are shaped like the real formats but hold no key
    /// material: the classifier only ever reads the headers.
    #[test]
    fn the_key_scan_keeps_private_keys_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let at = |name: &str, body: &str| {
            std::fs::write(dir.path().join(name), body).unwrap();
        };

        // An unlocked ed25519 key: `openssh-key-v1\0` then the length-
        // prefixed cipher name `none`, base64-encoded the way the format
        // stores it.
        let mut unlocked = b"openssh-key-v1\0".to_vec();
        unlocked.extend_from_slice(&4u32.to_be_bytes());
        unlocked.extend_from_slice(b"none");
        unlocked.extend_from_slice(&[0u8; 32]);
        let mut locked = b"openssh-key-v1\0".to_vec();
        locked.extend_from_slice(&(b"aes256-ctr".len() as u32).to_be_bytes());
        locked.extend_from_slice(b"aes256-ctr");
        locked.extend_from_slice(&[0u8; 32]);
        let b64 = base64::engine::general_purpose::STANDARD;
        let wrap = |bytes: &[u8]| {
            format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
                b64.encode(bytes)
            )
        };

        at("id_ed25519", &wrap(&unlocked));
        at("id_ed25519.pub", "ssh-ed25519 AAAAC3Nz gj@laptop\n");
        at("work_key", &wrap(&locked));
        at("legacy_rsa", "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nZm9v\n-----END RSA PRIVATE KEY-----\n");
        at("box.ppk", "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: box\n");
        // Everything the scan must ignore.
        at("known_hosts", "box.local ssh-ed25519 AAAAC3Nz\n");
        at("config", "Host box\n  User gj\n");
        at("notes.txt", "remember to rotate these\n");

        let found = scan_key_dir(dir.path());
        let names: Vec<&str> = found.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(names, vec!["box.ppk", "id_ed25519", "legacy_rsa", "work_key"]);

        let by = |name: &str| found.iter().find(|k| k.name == name).unwrap();
        // The `.pub` sibling names the algorithm and the comment.
        assert_eq!(by("id_ed25519").kind, "ed25519");
        assert_eq!(by("id_ed25519").comment.as_deref(), Some("gj@laptop"));
        assert!(!by("id_ed25519").encrypted);
        // No sibling, so no algorithm to show, but the cipher name is still
        // readable and says the key is locked.
        assert_eq!(by("work_key").kind, "");
        assert!(by("work_key").encrypted);
        assert_eq!(by("legacy_rsa").kind, "rsa");
        assert!(by("legacy_rsa").encrypted);
        assert_eq!(by("box.ppk").kind, "ed25519");
        assert!(by("box.ppk").encrypted);
    }

    /// A directory that is not there is an ordinary answer, not an error: a
    /// machine that has never used SSH has no `~/.ssh`.
    #[test]
    fn a_missing_key_directory_lists_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(scan_key_dir(&dir.path().join("nope")).is_empty());
    }

    #[test]
    fn wire_algorithm_names_become_readable_ones() {
        assert_eq!(algorithm_name("ssh-ed25519"), "ed25519");
        assert_eq!(algorithm_name("ecdsa-sha2-nistp256"), "ecdsa");
        assert_eq!(algorithm_name("sk-ssh-ed25519@openssh.com"), "ed25519");
        assert_eq!(algorithm_name("ssh-dss"), "dsa");
        assert_eq!(algorithm_name("ssh-rsa"), "rsa");
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
