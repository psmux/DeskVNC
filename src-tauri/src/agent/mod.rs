//! The agent plane's shell half: one local socket, off by default.
//!
//! ## What is here
//!
//! `PRDAgentPlug/04 §1.1` rules that MCP is an adapter and that underneath it
//! there is exactly one native surface, a JSON-RPC control lane over one local
//! socket, named `dvvp.v1`. [`wire`] is its framing, [`server`] is its verbs,
//! and this file is the switch, the path and the bookkeeping the panes render.
//!
//! ## Off by default, and what "off" has to mean
//!
//! `AGENT_BRIEF` D2 requires the interactive product not to regress and
//! `00 R40`'s DMG constraints require an ordinary install to be unchanged. So
//! the setting lives in the store's KV table beside
//! `ALLOW_MULTIPLE_SESSIONS_KEY` and it is read the same way, and **a build
//! with the plane off creates no socket, spawns no task and opens no file.**
//! That is asserted rather than asserted about: see the tests at the bottom.
//!
//! The setting is `agent_plane_enabled` and it is read at startup and again
//! whenever it is written, so switching it on takes effect without a restart.
//! Switching it off closes the listener and unlinks the socket, which is what
//! makes "off" mean the same thing at any moment rather than only at launch.
//!
//! ## Local only, and no listener on a port
//!
//! `00 R18`. A unix socket and stdio, and nothing else in version 1. There is
//! no TCP listener here and no feature flag for one: a listener that drives
//! desktops is a different product with a different threat model, and MCP's
//! own transport guidance about DNS rebinding is a property of the browser
//! rather than of the protocol, so it does not stop being true because we
//! would rather it did.
//!
//! ## The path
//!
//! Taken from `dvv`'s own `cli::socket_path`, byte for byte, because that is
//! the path `dvv doctor` has been printing to users all along and the two must
//! not disagree. Note that it is NOT `AppHandle::app_data_dir()`: that resolves
//! to the bundle identifier (`com.deskvncviewer.desktop`) while `dvv` publishes
//! the product name (`DeskVNCViewer`). The published path wins, and the
//! directory is created here if it is missing.

pub mod mirror;
pub mod server;
pub mod wire;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::state::SessionEntry;

use parking_lot::Mutex;
use serde_json::{json, Value};

use server::{Ctx, Peer, RpcError};

/// The protocol string, which is a hard gate (`04 §2.7` rule 1).
pub const PROTOCOL: &str = "dvvp.v1";

/// Preference key: is the agent plane switched on? Default **false**, in which
/// case no socket exists at all.
///
/// Lives in the store's KV table rather than the webview for the same reason
/// `ALLOW_MULTIPLE_SESSIONS_KEY` does: the decision is made here, in Rust, and
/// a webview that had to be running for it to take effect would make a
/// headless build impossible to configure.
pub const AGENT_PLANE_ENABLED_KEY: &str = "agent_plane_enabled";

/// App-wide agent lifecycle broadcast (`emit`, every window), so a pane can
/// show who is driving its machine without owning the socket.
///
/// Flat payloads on a `type` discriminator, exactly as `sessions://event`
/// does, and an unknown `type` must be ignored (`IPC_CONTRACT.md`). The full
/// table is in `IPC_CONTRACT.md`.
pub const AGENT_EVENT: &str = "agent://event";

/// Interpret the stored value. Anything but an explicit "on" means off, so a
/// missing, empty or corrupt setting lands on the safe default, which for a
/// surface that drives other people's machines is the only defensible one.
pub fn plane_enabled(raw: Option<&str>) -> bool {
    matches!(
        raw.map(str::trim),
        Some("true") | Some("1") | Some("yes") | Some("on")
    )
}

/// Where the plane's socket lives (`04 §2.1`).
///
/// Quoted from `crates/dvv/src/cli.rs::socket_path`. If one of them moves,
/// move the other: `dvv doctor` prints this path and a person compares it with
/// `ls`.
pub fn socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(format!(
            "{home}/Library/Application Support/DeskVNCViewer/agent.sock"
        ))
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            return PathBuf::from(format!("{runtime}/deskvncviewer/agent.sock"));
        }
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(format!("{home}/.local/share/DeskVNCViewer/agent.sock"))
    }
    #[cfg(target_os = "windows")]
    {
        let user = std::env::var("USERNAME").unwrap_or_default();
        PathBuf::from(format!("\\\\.\\pipe\\deskvncviewer-agent-{user}"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("agent.sock")
    }
}

/// The file name of the agent binary that ships beside the app.
const DVV_FILE_NAME: &str = if cfg!(target_os = "windows") {
    "dvv.exe"
} else {
    "dvv"
};

/// The name the MCP server is registered under, in `claude mcp add` and in
/// every instruction the modal prints.
///
/// One name, defined once: the modal tells a person to look for it in
/// `claude mcp list`, and a second spelling somewhere else would send them
/// looking for a server that is registered under the first.
pub const MCP_SERVER_NAME: &str = "deskvnc";

/// The absolute path of the `dvv` that shipped with this app, or `None`.
///
/// Derived from the running executable rather than composed from a guess:
/// `dvv` is copied into `Contents/MacOS` beside the main binary (see
/// `scripts/package-macos.sh`), so the app can point at it wherever a person
/// dragged the bundle to, including a second copy on an external disk.
///
/// `None` is the honest answer for a `cargo tauri dev` build, which has no
/// bundle. The webview renders a placeholder for exactly that case, and a
/// path that does not resolve on the machine reading it would be worse than
/// no path at all: the connect instructions are meant to be pasted.
pub fn bundled_dvv() -> Option<PathBuf> {
    dvv_beside(std::env::current_exe().ok()?.as_path())
}

/// [`bundled_dvv`] with the executable's location passed in, so a test can
/// build a bundle shaped directory and assert against it without installing
/// anything.
fn dvv_beside(exe: &std::path::Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    // On macOS the shape of the parent directory is the whole test. A dev
    // build has `target/debug/dvv` sitting beside `target/debug/deskvncviewer`
    // because both are workspace binaries, so "a sibling called dvv exists"
    // would answer a path for `cargo tauri dev` too, and the instructions that
    // path appears in are about an INSTALLED app. Only a real bundle counts.
    if cfg!(target_os = "macos") && !in_macos_bundle(dir) {
        return None;
    }
    let candidate = dir.join(DVV_FILE_NAME);
    candidate.is_file().then_some(candidate)
}

/// Is this directory the `Contents/MacOS` of an `.app`?
fn in_macos_bundle(dir: &std::path::Path) -> bool {
    use std::ffi::OsStr;
    let contents = match dir.file_name() {
        Some(name) if name == OsStr::new("MacOS") => match dir.parent() {
            Some(parent) => parent,
            None => return false,
        },
        _ => return false,
    };
    contents.file_name() == Some(OsStr::new("Contents"))
        && contents.parent().and_then(|app| app.extension()) == Some(OsStr::new("app"))
}

/// What `claude mcp add` did (`PRDAgentPlug/00 R41`, the one-click connect).
///
/// A tagged answer and not a boolean, because the webview renders each case
/// differently: a success is a tick, an already registered server is also a
/// tick but with different words, a missing `claude` is an install link, and a
/// failure is the tool's own stderr shown verbatim. A boolean would collapse
/// the last two into "it did not work".
///
/// The tag is kebab-case, as every other discriminator on this surface is.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum RegistrationOutcome {
    /// `claude mcp add` returned success. `argv` is exactly what was run, so
    /// the modal can show the line rather than describe it.
    Registered { claude: String, argv: Vec<String> },
    /// A server of this name was already registered for this user. Not an
    /// error: the person pressed the button twice, or had done it by hand.
    AlreadyRegistered { claude: String },
    /// Claude Code is not installed, or not anywhere this app can see it.
    /// `looked` is every path that was tried, in order.
    ClaudeNotFound { looked: Vec<String> },
    /// This build has no bundled `dvv` to register, which means it is a dev
    /// build. Nothing to offer and nothing broken.
    NoBinary,
    /// `claude` ran and refused. `stderr` is its own words, untrusted text.
    Failed {
        claude: String,
        code: Option<i32>,
        stderr: String,
    },
    /// `claude` was still running when the clock ran out and has been killed.
    TimedOut { claude: String, seconds: u64 },
}

/// How long `claude mcp add` gets. It edits one JSON file, so this is
/// generous; the point is that a hung child cannot hold the button down
/// forever.
const REGISTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// The arguments `claude` is run with, after the program itself.
///
/// A vector and never a shell string. The bundled path can contain a space
/// (`/Volumes/My Disk/DeskVNCViewer.app/...`) and passing it through `sh -c`
/// would both break that path and turn any character in it into something the
/// shell could act on. `argv` has neither problem.
pub fn register_argv(dvv: &std::path::Path) -> Vec<String> {
    vec![
        "mcp".to_string(),
        "add".to_string(),
        "--scope".to_string(),
        "user".to_string(),
        MCP_SERVER_NAME.to_string(),
        // Everything after this separator is the server's own command line,
        // which is why the bundled binary and its flags sit behind it.
        "--".to_string(),
        dvv.display().to_string(),
        "mcp".to_string(),
        "--stdio".to_string(),
    ]
}

/// Every place `claude` might be, in the order they are tried.
///
/// A GUI app on macOS is launched by `launchd` and inherits a PATH of
/// `/usr/bin:/bin:/usr/sbin:/sbin`, not the one a person's shell profile
/// builds. `Command::new("claude")` therefore fails on a machine where Claude
/// Code is installed and works on the developer's, which is the worst kind of
/// bug to be told about. So PATH is tried first, when there is one, and then
/// the locations the published installers actually use.
pub fn claude_candidates(path_var: Option<&str>, home: Option<&str>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |candidate: PathBuf| {
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    };
    let exe = if cfg!(target_os = "windows") {
        "claude.exe"
    } else {
        "claude"
    };
    // `split_paths` and not `split(':')`: the separator is a semicolon on
    // Windows and a colon inside `C:\...` is not one.
    for dir in std::env::split_paths(path_var.unwrap_or_default()) {
        if dir.as_os_str().is_empty() {
            // An empty PATH entry means the current directory, and running
            // whatever `claude` happens to be in it is not something a button
            // should do.
            continue;
        }
        push(dir.join(exe));
    }
    if let Some(home) = home.filter(|home| !home.is_empty()) {
        let home = PathBuf::from(home);
        // The local installer, then the native one, then the runtimes people
        // install the npm package with.
        for rest in [
            ".claude/local/claude",
            ".local/bin/claude",
            ".bun/bin/claude",
            ".volta/bin/claude",
            ".npm-global/bin/claude",
            ".yarn/bin/claude",
        ] {
            push(home.join(rest));
        }
    }
    for dir in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        push(PathBuf::from(dir).join(exe));
    }
    out
}

/// Is this a file this process could execute?
fn is_executable(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Register the bundled `dvv` as an MCP server for this user.
///
/// Blocking, and called from `spawn_blocking`: it waits on a child process.
pub fn register_with_claude() -> RegistrationOutcome {
    let Some(dvv) = bundled_dvv() else {
        return RegistrationOutcome::NoBinary;
    };
    let path_var = std::env::var("PATH").ok();
    let home = std::env::var("HOME").ok();
    let candidates = claude_candidates(path_var.as_deref(), home.as_deref());
    let Some(claude) = candidates.iter().find(|path| is_executable(path)) else {
        return RegistrationOutcome::ClaudeNotFound {
            looked: candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        };
    };
    let argv = register_argv(&dvv);
    let claude_display = claude.display().to_string();
    tracing::info!(claude = %claude_display, dvv = %dvv.display(), "registering the MCP server");

    let mut command = std::process::Command::new(claude);
    command.args(&argv);
    // Claude Code's npm build is a script with a `#!/usr/bin/env node`
    // shebang, so finding `claude` is not enough: the child has to be able to
    // find its own runtime, and the PATH inherited from launchd cannot. Add
    // the directory `claude` was found in and the two package manager prefixes
    // node is installed under.
    if let Some(path) = augmented_path(path_var.as_deref(), claude.parent()) {
        command.env("PATH", path);
    }
    match run_bounded(command, REGISTER_TIMEOUT) {
        Ok(finished) if finished.timed_out => RegistrationOutcome::TimedOut {
            claude: claude_display,
            seconds: REGISTER_TIMEOUT.as_secs(),
        },
        Ok(finished) if finished.code == Some(0) => RegistrationOutcome::Registered {
            claude: claude_display,
            argv,
        },
        Ok(finished) if already_registered(&finished.stdout, &finished.stderr) => {
            RegistrationOutcome::AlreadyRegistered {
                claude: claude_display,
            }
        }
        Ok(finished) => RegistrationOutcome::Failed {
            claude: claude_display,
            code: finished.code,
            // stderr first, and stdout only when stderr is empty: some
            // versions print the refusal on stdout and a message box with
            // nothing in it explains nothing.
            stderr: if finished.stderr.trim().is_empty() {
                finished.stdout
            } else {
                finished.stderr
            },
        },
        // Spawning failed, which after the executable check above is a
        // permission or an architecture mismatch. Report it as the failure it
        // is rather than as a missing tool.
        Err(e) => RegistrationOutcome::Failed {
            claude: claude_display,
            code: None,
            stderr: e.to_string(),
        },
    }
}

/// Did `claude` refuse because the server is already there?
///
/// Matched on the message because the exit code is the same generic failure
/// for every refusal. Two spellings, since the wording has changed across
/// releases and a false negative here is only a worse message.
fn already_registered(stdout: &str, stderr: &str) -> bool {
    let haystack = format!("{stdout}\n{stderr}").to_lowercase();
    haystack.contains("already exists") || haystack.contains("already configured")
}

/// PATH for the child: what this process has, plus where `claude` was found,
/// plus the usual node prefixes.
fn augmented_path(path_var: Option<&str>, claude_dir: Option<&std::path::Path>) -> Option<String> {
    // Unix only, and the colon below is why. Windows processes inherit the
    // user's PATH already, so there is nothing here to repair.
    if cfg!(target_os = "windows") {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    let mut push = |dir: String| {
        if !dir.is_empty() && !parts.contains(&dir) {
            parts.push(dir);
        }
    };
    if let Some(dir) = claude_dir {
        push(dir.display().to_string());
    }
    for dir in path_var.unwrap_or_default().split(':') {
        push(dir.to_string());
    }
    for dir in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"] {
        push(dir.to_string());
    }
    Some(parts.join(":"))
}

/// What a bounded child process left behind.
struct Finished {
    code: Option<i32>,
    timed_out: bool,
    stdout: String,
    stderr: String,
}

/// Run a child with both pipes drained and a deadline.
///
/// The pipes are read on their own threads rather than after the wait: a child
/// that fills a pipe buffer blocks on the write, the parent never sees it
/// exit, and the deadline turns a chatty command into a timeout. Draining
/// concurrently means the only thing that can trip the deadline is a child
/// that really is stuck.
fn run_bounded(
    mut command: std::process::Command,
    limit: std::time::Duration,
) -> std::io::Result<Finished> {
    use std::io::Read;
    use std::process::Stdio;

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let drain = |pipe: Option<&mut dyn Read>| -> String {
        let mut text = String::new();
        if let Some(pipe) = pipe {
            let _ = pipe.read_to_string(&mut text);
        }
        text
    };
    let readers = std::thread::scope(|scope| {
        let out = scope.spawn(|| drain(out.as_mut().map(|p| p as &mut dyn Read)));
        let err = scope.spawn(|| drain(err.as_mut().map(|p| p as &mut dyn Read)));
        let deadline = std::time::Instant::now() + limit;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        // Killing it closes both pipes, which is what lets the
                        // two reader threads finish and this scope end.
                        let _ = child.kill();
                        let _ = child.wait();
                        timed_out = true;
                        break None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(_) => break None,
            }
        };
        (
            status.and_then(|status| status.code()),
            timed_out,
            out.join().unwrap_or_default(),
            err.join().unwrap_or_default(),
        )
    });
    Ok(Finished {
        code: readers.0,
        timed_out: readers.1,
        stdout: readers.2,
        stderr: readers.3,
    })
}

/// What one attachment holds on one session.
///
/// The lease itself is NOT here and cannot be: it lives in `agent-lease`,
/// inside the agent's own process, because that is where the plane runs. What
/// is here is what the holder reported, so a pane can render it. Keeping a
/// second opinion about who holds a lease is how the two drift.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub attachment_id: String,
    pub client: String,
    /// True once a person has taken the wheel. Every further command from this
    /// attachment is refused with `LEASE_REVOKED` (`04 §5.4`).
    pub revoked: bool,
    pub held: bool,
    pub phase: String,
    pub holder_kind: Option<String>,
    pub holder_label: Option<String>,
    pub human_took_over: bool,
    pub inflight: Vec<String>,
}

impl Attachment {
    /// Is an agent DRIVING this machine right now?
    ///
    /// Held, plus a holder that is an agent, and nothing else. Attached and
    /// idle is not driving: a bar that counted every attachment would tell
    /// somebody four machines are being operated when nobody is touching any
    /// of them, which is worse than showing no number at all.
    ///
    /// `revoked` needs no arm here because [`AgentPlane::revoke`] clears
    /// `held` in the same breath, and a revoked attachment cannot report
    /// itself back in (`04 §5.4`, D5).
    fn driving(&self) -> bool {
        self.held && self.holder_kind.as_deref() == Some("agent")
    }
}

/// The three numbers a status bar reads: how many agents are connected, how
/// many machines they are driving right now, and how many sessions are live
/// in total.
///
/// Only the shell knows all three, which is why they are computed here and not
/// assembled in the webview from three separate streams. One struct serves
/// both surfaces, [`crate::commands::agent::agent_status`] and the `counts`
/// payload on [`AGENT_EVENT`], so the command and the stream cannot disagree
/// about what a number means.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCounts {
    /// Distinct clients connected right now, over any transport this plane
    /// serves. A CLIENT and not an attachment: one agent holding four limbs is
    /// one agent.
    pub agents_connected: usize,
    /// Sessions an agent holds the control lease on right now.
    pub sessions_driven: usize,
    /// Every live session in the registry, agent driven or not, so a person
    /// reads "3 of 11" rather than a bare "3".
    pub sessions_live: usize,
}

impl AgentCounts {
    /// The `agent://event` payload.
    ///
    /// Its OWN `type` rather than three more fields on `plane`. The plane's
    /// own state changes when a person toggles a setting, which is roughly
    /// never; these change on every attach, detach, lease move and connection.
    /// Folding them together would wake every consumer that only wants to know
    /// whether the socket exists, on every lease report.
    pub fn event(&self) -> Value {
        json!({
            "type": "counts",
            "agentsConnected": self.agents_connected,
            "sessionsDriven": self.sessions_driven,
            "sessionsLive": self.sessions_live,
        })
    }
}

/// The listener, while it exists.
struct Running {
    path: PathBuf,
    cancel: tokio_util::sync::CancellationToken,
    /// The live session registry, held so that [`stop`] can put back every
    /// quality preset a mirror moved. Sessions outlive the plane: switching it
    /// off closes the socket and leaves every pane exactly where it was, so a
    /// person whose session was renegotiated is given it back here or nowhere.
    ///
    /// The registry and not the whole [`Ctx`], because `Ctx` holds an
    /// `Arc<AgentPlane>` and putting one here would make the plane point at
    /// itself.
    sessions: Arc<Mutex<HashMap<String, crate::state::SessionEntry>>>,
}

/// The plane's shell side state: the socket if it is on, who is attached, and
/// what they can see.
#[derive(Default)]
pub struct AgentPlane {
    running: Mutex<Option<Running>>,
    /// Keyed by the shell's session id, which is the id every window, every
    /// event and every registry entry already uses.
    attachments: Mutex<HashMap<String, Attachment>>,
    next_attachment: AtomicU64,
    /// One row per connected client, keyed by a per connection number, valued
    /// by the name it gave in `hello`.
    ///
    /// A CLIENT and not an attachment. `hello` mints exactly one attachment id
    /// per connection and every attachment, audit line and revocation keys on
    /// that id, so the connection is what "an agent" means on this surface: an
    /// agent holding four limbs is one row here and four in `attachments`.
    ///
    /// Keyed rather than counted because a drop has to be idempotent. [`stop`]
    /// clears the whole table when the plane goes off, and the guards still
    /// open at that moment then remove a row that is already gone instead of
    /// counting past zero.
    connections: Mutex<HashMap<u64, String>>,
    next_connection: AtomicU64,
    /// The registry the live session total is read from, and where a `counts`
    /// event goes. `None` until [`AgentPlane::wire_counts`] installs it, which
    /// is why every announce is a no op in a unit test that has not asked for
    /// one.
    counts_wiring: Mutex<Option<CountsWiring>>,
    /// The last three numbers put on the stream, so the same three are never
    /// put on it twice.
    last_announced: Mutex<Option<AgentCounts>>,
    /// The framebuffer mirrors, one per session that asked to be perceived.
    ///
    /// Public because the shell's own event pump feeds it: see
    /// [`AgentPlane::feed`], which is the seam `00 R22` puts in the plane
    /// rather than behind the webview bridge.
    pub mirrors: mirror::Mirrors,
}

/// What [`AgentPlane::announce`] needs to say anything at all.
///
/// The emitter is a closure and the registry an `Arc`, for the same reason
/// [`Ctx`] takes both that way: nothing under this file names a Tauri type, so
/// every rule in it can be proved without a running application.
struct CountsWiring {
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    emit: Arc<dyn Fn(Value) + Send + Sync>,
}

/// One connected client, for exactly as long as this lives.
///
/// A guard and not a pair of calls: a connection ends at a dozen points, an
/// orderly close, a read error, a cancelled plane, a panic in a handler, and a
/// count that leaked on any one of them would tell a person two agents are
/// connected to an idle machine, forever, with nothing to press to fix it.
pub struct ConnectionGuard {
    plane: Arc<AgentPlane>,
    id: u64,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.plane.connections.lock().remove(&self.id).is_none() {
            // [`stop`] already cleared the table and announced. Saying it
            // twice would be a second wakeup for no change.
            return;
        }
        self.plane.announce();
    }
}

impl AgentPlane {
    /// A fresh attachment id, unique within this process run.
    ///
    /// `att_` prefixed so a log line tells one from a session id at a glance,
    /// which is the same courtesy `LimbId::PREFIX` pays.
    pub fn mint_attachment_id(&self) -> String {
        format!(
            "att_{:x}",
            self.next_attachment.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Is the socket up?
    pub fn is_running(&self) -> bool {
        self.running.lock().is_some()
    }

    /// The socket's path, while there is one.
    pub fn socket(&self) -> Option<PathBuf> {
        self.running.lock().as_ref().map(|r| r.path.clone())
    }

    pub fn attach(&self, session_id: &str, attachment: Attachment) {
        self.attachments
            .lock()
            .insert(session_id.to_string(), attachment);
        self.announce();
    }

    pub fn detach(&self, session_id: &str) {
        let removed = self.attachments.lock().remove(session_id);
        if removed.is_some() {
            self.announce();
        }
    }

    /// Give the plane the registry it counts and the channel it counts onto.
    ///
    /// Installed once at startup, whether or not the plane is switched on,
    /// because the live session total is truthful with the plane off and a
    /// person watching the bar switch the plane off has to see the other two
    /// numbers go to zero as it happens.
    pub fn wire_counts(
        &self,
        sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
        emit: Arc<dyn Fn(Value) + Send + Sync>,
    ) {
        *self.counts_wiring.lock() = Some(CountsWiring { sessions, emit });
    }

    /// Register one connected client. Drop the guard when the connection ends.
    ///
    /// Called from `hello` rather than from the accept loop: a connection that
    /// has not said hello can do nothing at all (`04 §2.3`), so counting it
    /// would put a port scanner in somebody's status bar.
    pub fn client_connected(self: &Arc<Self>, client: &str) -> ConnectionGuard {
        let id = self.next_connection.fetch_add(1, Ordering::Relaxed);
        self.connections.lock().insert(id, client.to_string());
        self.announce();
        ConnectionGuard {
            plane: self.clone(),
            id,
        }
    }

    /// The three numbers, against a session registry the caller has already
    /// locked.
    ///
    /// The caller holds the registry lock, so the order is always registry and
    /// then attachments, which is the order `limb_status` already takes them
    /// in and the only order anything here may take them in.
    ///
    /// **Cheap, because it is read on every attach, detach and lease change.**
    /// Two of the three are a lock and a `len` over maps that hold one row per
    /// connection and one per attached limb, a handful at most. The third is a
    /// pass over the session registry, and it stays cheap because `is_live` is
    /// two atomic loads: no session's own `facts` mutex is taken, so counting
    /// never contends with a session's event pump. A maintained tally would
    /// need a hook where a session is REGISTERED and the plane is not on that
    /// path: it is told when a session ends ([`AgentPlane::forget`]) and never
    /// when one starts, so a tally would drift the first time somebody opened
    /// a machine and there would be nothing to correct it.
    pub fn counts(&self, sessions: &HashMap<String, SessionEntry>) -> AgentCounts {
        AgentCounts {
            agents_connected: self.connections.lock().len(),
            sessions_driven: self
                .attachments
                .lock()
                .values()
                .filter(|attachment| attachment.driving())
                .count(),
            sessions_live: sessions.values().filter(|entry| entry.is_live()).count(),
        }
    }

    /// Emit the counts, once, because something changed.
    ///
    /// **On change and never on a timer.** A bar that repaints once a second
    /// when nothing happened is a wakeup on a machine that should be idle, and
    /// `00 R40` says an ordinary install is unchanged by this feature existing.
    ///
    /// It is also silent when the three numbers have not moved. An attach that
    /// leaves every count where it was is a real event and the pane hears
    /// about it on the `attached` payload; repeating three unchanged numbers
    /// after it would be exactly the pointless repaint above, one step slower.
    ///
    /// Callers must hold NO lock. This takes the session registry and then the
    /// attachments, and `parking_lot`'s mutex is not reentrant.
    fn announce(&self) {
        let wiring = self
            .counts_wiring
            .lock()
            .as_ref()
            .map(|wiring| (wiring.sessions.clone(), wiring.emit.clone()));
        let Some((sessions, emit)) = wiring else {
            return;
        };
        // Held across the read and the emit, so two connections ending at the
        // same moment cannot put their payloads on the stream in the wrong
        // order and leave the bar showing the older pair of numbers.
        let mut last = self.last_announced.lock();
        let counts = {
            let sessions = sessions.lock();
            self.counts(&sessions)
        };
        if *last == Some(counts) {
            return;
        }
        *last = Some(counts);
        emit(counts.event());
    }

    /// Which sessions an agent holds, as session id to attachment id.
    pub fn attached_ids(&self) -> HashMap<String, String> {
        self.attachments
            .lock()
            .iter()
            .map(|(session, held)| (session.clone(), held.attachment_id.clone()))
            .collect()
    }

    /// May this attachment still act on this session?
    ///
    /// # Errors
    ///
    /// An [`RpcError`] tagged `NOT_ATTACHED` or `LEASE_REVOKED`. The tag is
    /// what an agent branches on, because `04 §4.4`'s stand down trailer says
    /// the model has to get one decision right and only one: a person took the
    /// machine, so stop, rather than retry.
    pub fn check_allowed(&self, session_id: &str, attachment_id: &str) -> Result<(), RpcError> {
        let attachments = self.attachments.lock();
        let held = attachments.get(session_id).ok_or_else(|| RpcError {
            code: -32000,
            message: format!(
                "this attachment is not attached to {session_id}; call limb.attach first"
            ),
            tag: Some("NOT_ATTACHED"),
        })?;
        if held.attachment_id != attachment_id {
            return Err(RpcError {
                code: -32000,
                message: format!(
                    "{session_id} is attached by {} and not by this connection",
                    held.attachment_id
                ),
                tag: Some("NOT_ATTACHED"),
            });
        }
        if held.revoked {
            return Err(RpcError {
                code: -32000,
                message: format!(
                    "a person took the wheel on {session_id} in DeskVNCViewer. Nothing was sent. Do not act on this machine and do not try to acquire control: report back to the user instead"
                ),
                tag: Some("LEASE_REVOKED"),
            });
        }
        Ok(())
    }

    /// A person took the wheel (`04 §5.4`, D5).
    ///
    /// A revocation, not a request. The attachment is refused from this
    /// instant, before any grace window, because BrowserGlass's own demo
    /// measures two seconds for a polite handover and two seconds of a button
    /// labelled stop doing nothing is the failure.
    ///
    /// The session itself is untouched: a revoked agent that had a build
    /// running should not take the build with it.
    pub fn revoke(&self, session_id: &str) -> Option<Value> {
        let event = {
            let mut attachments = self.attachments.lock();
            let held = attachments.get_mut(session_id)?;
            held.revoked = true;
            held.held = false;
            held.phase = "revoked".to_string();
            held.holder_kind = Some("human".to_string());
            held.human_took_over = true;
            held.inflight.clear();
            lease_event(session_id, held)
        };
        // The machine just stopped being agent driven, and the agent is still
        // connected. Announced after the lock is back, never while it is held.
        self.announce();
        Some(event)
    }

    /// Record what a holder reported, and produce the event a pane renders.
    ///
    /// `None` when nothing is attached to that session, which is a client
    /// talking about a limb it let go of rather than an error worth failing a
    /// control call over.
    #[allow(clippy::too_many_arguments)] // one report, one row, not an API
    pub fn report(
        &self,
        session_id: &str,
        attachment_id: &str,
        held: bool,
        phase: String,
        holder_kind: Option<String>,
        holder_label: Option<String>,
        human_took_over: bool,
        inflight: Vec<String>,
    ) -> Option<Value> {
        let event = {
            let mut attachments = self.attachments.lock();
            let entry = attachments.get_mut(session_id)?;
            if entry.attachment_id != attachment_id {
                return None;
            }
            // A revoked attachment cannot report itself back into the wheel.
            // The person's decision outranks the agent's opinion of it, which
            // is D5 one layer down from `agent-lease`.
            if entry.revoked {
                return None;
            }
            entry.held = held;
            entry.phase = phase;
            entry.holder_kind = holder_kind;
            entry.holder_label = holder_label;
            entry.human_took_over = human_took_over;
            entry.inflight = inflight;
            lease_event(session_id, entry)
        };
        // A lease moving is the commonest reason the driven count changes, and
        // it is the one the bar exists to show.
        self.announce();
        Some(event)
    }

    /// Every attachment, for a pane that has just mounted.
    ///
    /// Tauri events are fire and forget: anything emitted before a window's
    /// `listen()` registration completes is dropped. The same reasoning that
    /// put `pending_credential_request` on the command surface puts this one
    /// there, and for the same failure: a pane that subscribed a moment late
    /// would show no agent badge for a machine an agent is driving.
    pub fn snapshot(&self) -> Vec<Value> {
        self.attachments
            .lock()
            .iter()
            .map(|(session, held)| lease_event(session, held))
            .collect()
    }

    /// Forget a session that has ended, so its attachment does not outlive it.
    ///
    /// The mirror goes with it, and no quality preset is restored: the session
    /// is over, so there is no wire to put one on and nobody left to see it.
    pub fn forget(&self, session_id: &str) {
        self.attachments.lock().remove(session_id);
        self.mirrors.forget(session_id);
        // The live total just fell, and the driven one may have with it. This
        // is the only session lifecycle edge the plane is told about: a
        // session being OPENED reaches nothing here, so a bar seeds from
        // `agent_status` when `sessions://event` says one started.
        self.announce();
    }

    /// **The seam.** One coalesced `SessionEvent::FramebufferUpdate`, on its
    /// way to the mirror.
    ///
    /// `00 R22` puts the mirror in the plane rather than behind the webview
    /// bridge: in tabbed mode every session shares one bridge and it is not a
    /// fair queue, so eight limbs' frames through it is a starvation bug with
    /// our name on it. The plane is therefore the SECOND consumer of a stream
    /// the webview already consumes, and this is where the shell's event pump
    /// hands it over, beside the binary frame it already sends to the window.
    ///
    /// A session nobody asked to perceive is not in the map and pays a hash
    /// lookup and nothing else, which is the whole of `03 §9 A5`.
    ///
    /// **Nothing in this build calls it, and that is the one hole left in this
    /// feature.** The call site is two lines in
    /// `commands::session::forward_events`, which is owned elsewhere as this
    /// lands:
    ///
    /// ```text
    /// SessionEvent::FramebufferUpdate { rects, damage } => {
    ///     if let Some(state) = app.try_state::<AppState>() {
    ///         state.agent.feed(&session_id, &rects);
    ///     }
    ///     …the existing framing::encode_frame call…
    /// }
    /// ```
    ///
    /// and, in the `match &event` block above it that already keeps
    /// `SessionFacts::size` current, one more beside the resize:
    ///
    /// ```text
    /// SessionEvent::DesktopResize { width, height } => {
    ///     …the existing facts update…
    ///     state.agent.note_resize(&session_id, *width, *height);
    /// }
    /// ```
    ///
    /// Until those exist every mirror stays priming and every `screen.read`
    /// refuses with `PRIMING`, which is the correct behaviour for a mirror
    /// nothing feeds and is not the behaviour anybody wants.
    #[allow(dead_code)]
    pub fn feed(&self, session_id: &str, rects: &[vnc_core::DecodedRect]) {
        self.mirrors.feed(session_id, rects, now());
    }

    /// The remote desktop resized. Bumps the geometry generation a read is
    /// fenced against (`00 R10`) and resizes the mirror under it.
    ///
    /// Unreached for the same reason [`AgentPlane::feed`] is.
    #[allow(dead_code)]
    pub fn note_resize(&self, session_id: &str, width: u16, height: u16) {
        self.mirrors.resize(session_id, width, height);
    }
}

/// Unix milliseconds, for the one place the plane's shell half needs a clock.
///
/// `agent-perception` reads none: every rule in it, including the idle
/// timeout, is a pure function of the time it was handed, which is what makes
/// it testable without a runtime. Owning the clock is the runtime's job and
/// this is the runtime.
pub fn now() -> limb_core::observation::Timestamp {
    limb_core::observation::Timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_default(),
    )
}

fn lease_event(session_id: &str, attachment: &Attachment) -> Value {
    json!({
        "type": "lease",
        "sessionId": session_id,
        "attachmentId": attachment.attachment_id,
        "client": attachment.client,
        "held": attachment.held,
        "phase": attachment.phase,
        "holderKind": attachment.holder_kind,
        "holderLabel": attachment.holder_label,
        "humanTookOver": attachment.human_took_over,
        "revoked": attachment.revoked,
        "inflight": attachment.inflight,
    })
}

/// Bind the socket and start accepting, or say why not.
///
/// Binding happens synchronously, before this returns, so a caller that has
/// been told the plane is on can look at the filesystem and find it there.
/// The accept loop is the only thing that is spawned.
///
/// # Errors
///
/// An [`std::io::Error`] when the directory cannot be made, the socket cannot
/// be bound, or its mode cannot be set. A plane that could not be secured is
/// not started: `04 §2.1` says mode 0600 and this is where that is true.
#[cfg(unix)]
pub fn start(plane: &Arc<AgentPlane>, ctx: Arc<Ctx>, path: PathBuf) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut running = plane.running.lock();
    if running.is_some() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A socket left behind by a process that died holds the address without
    // answering, so a bind over it fails and the plane would never come back
    // up. Connecting to it first is what tells a corpse from a live listener,
    // and a live one means another instance of this application owns the
    // plane, which is reported rather than stolen.
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!(
                    "another DeskVNCViewer is already serving the agent plane on {}",
                    path.display()
                ),
            ));
        }
        std::fs::remove_file(&path)?;
    }
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    // Mode 0600 in a directory the user owns, which with peer identity is the
    // whole of `04 §2.6`'s first gate.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    // INSIDE the runtime, explicitly. `from_std` registers the socket with the
    // reactor and PANICS when there is no reactor in context, and the caller
    // that matters is the Tauri `setup` hook, which runs on the main thread
    // outside it. A panic there is not a failed feature: `setup` cannot unwind,
    // so it aborts, and the application dies before its first window with the
    // setting still stored as on, which means it dies again on every launch
    // after that.
    //
    // The guard rather than `block_on`, because `apply` is also called from a
    // command handler when the setting is written, and that already runs on a
    // runtime thread where `block_on` would panic in its own right. Entering a
    // context is safe from either, and nothing here awaits.
    let listener = {
        let handle = tauri::async_runtime::handle();
        let _guard = handle.inner().enter();
        tokio::net::UnixListener::from_std(listener)?
    };

    let cancel = tokio_util::sync::CancellationToken::new();
    *running = Some(Running {
        path: path.clone(),
        cancel: cancel.clone(),
        sessions: ctx.sessions.clone(),
    });
    drop(running);

    tracing::info!(socket = %path.display(), "agent plane listening (dvvp.v1)");
    tauri::async_runtime::spawn(reaper(plane.clone(), cancel.clone()));
    tauri::async_runtime::spawn(accept_loop(listener, ctx, cancel));
    Ok(())
}

/// How often the idle sweep runs.
///
/// A quarter of the default idle timeout, so a mirror is freed within about
/// fifteen seconds of earning it. The sweep itself is a lock and a subtraction
/// per mirrored session, and there are at most a handful.
#[cfg(unix)]
const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Free mirrors nothing has read for the idle timeout (`00 R5`).
///
/// The clock lives here rather than in `agent-perception`, which starts none:
/// every rule in that crate, the idle timeout included, is a pure function of
/// the time it was handed, which is what makes it testable without a runtime.
/// Owning the clock is the runtime's job and this is the runtime.
///
/// It is tied to the socket's cancellation token, so a plane that is switched
/// off stops sweeping along with everything else it owns.
#[cfg(unix)]
async fn reaper(plane: Arc<AgentPlane>, cancel: tokio_util::sync::CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(REAP_INTERVAL) => {
                let freed = plane.mirrors.reap(now());
                if freed > 0 {
                    tracing::debug!(
                        freed,
                        held = plane.mirrors.bytes_in_use(),
                        "freed idle framebuffer mirrors"
                    );
                }
            }
        }
    }
}

/// `00 R18` says a unix socket and stdio, so there is nothing to bind here
/// yet. The named pipe of `04 §2.1` is real work with its own ACL and it is
/// not written; saying so is better than binding something weaker.
#[cfg(not(unix))]
pub fn start(_plane: &Arc<AgentPlane>, _ctx: Arc<Ctx>, path: PathBuf) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "the agent plane needs a named pipe at {} on this platform, with an ACL granting only the creating user, and this build does not create one",
            path.display()
        ),
    ))
}

/// Close the socket and unlink it.
///
/// Unlinking matters as much as closing: `dvv doctor` reports the plane by
/// looking for the file, so a path left behind would tell every agent the
/// plane is up when it is not.
pub fn stop(plane: &Arc<AgentPlane>) {
    let Some(running) = plane.running.lock().take() else {
        return;
    };
    running.cancel.cancel();
    if let Err(e) = std::fs::remove_file(&running.path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(socket = %running.path.display(), "could not unlink the agent socket: {e}");
        }
    }
    plane.attachments.lock().clear();
    // The socket is gone, so every client on it is gone with it. Cleared here
    // rather than left to each [`ConnectionGuard`] because those drop when the
    // cancelled connection tasks next wake, and a bar that said "1 agent" for
    // a scheduler tick after a person switched the plane off would be read as
    // the switch not having worked.
    plane.connections.lock().clear();
    // Every person whose session was renegotiated for a mirror gets their
    // quality preset back, because the session does not end when the plane
    // does. `AGENT_BRIEF` D2: the interactive product must not be left
    // degraded by a feature somebody switched off.
    for (session_id, preset) in plane.mirrors.detach_all() {
        let handle = running
            .sessions
            .lock()
            .get(&session_id)
            .filter(|entry| entry.is_live())
            .map(|entry| entry.handle.clone());
        let Some(handle) = handle else { continue };
        let _ = handle.try_send(vnc_core::ClientCommand::SetQuality(preset));
        let _ = handle.try_send(vnc_core::ClientCommand::Refresh);
        tracing::info!(
            session = %session_id,
            preset = wire::quality_name(preset),
            "the agent plane stopped: putting the session's quality preset back"
        );
    }
    // After the preset restoring loop, because that loop takes the session
    // registry lock and `announce` takes it too.
    plane.announce();
    tracing::info!(socket = %running.path.display(), "agent plane stopped");
}

#[cfg(unix)]
async fn accept_loop(
    listener: tokio::net::UnixListener,
    ctx: Arc<Ctx>,
    cancel: tokio_util::sync::CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    // `04 §2.6`: peer identity answers "is this the same
                    // human" and nothing more, on a single user desktop. It is
                    // recorded because the audit trail `10` owns needs to name
                    // who attached, and it is not an authorization decision.
                    match stream.peer_cred() {
                        Ok(cred) => tracing::info!(uid = cred.uid(), "agent attached over dvvp.v1"),
                        Err(e) => tracing::warn!("could not read the peer's credentials: {e}"),
                    }
                    let ctx = ctx.clone();
                    let cancel = cancel.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Err(e) = serve(stream, ctx, cancel).await {
                            tracing::debug!("agent connection ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("the agent socket stopped accepting: {e}");
                    return;
                }
            },
        }
    }
}

/// One connection, until it closes.
#[cfg(unix)]
async fn serve(
    stream: tokio::net::UnixStream,
    ctx: Arc<Ctx>,
    cancel: tokio_util::sync::CancellationToken,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut peer = Peer::default();
    loop {
        let message = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            message = wire::read_message(&mut reader) => message?,
        };
        let Some((msg_type, payload)) = message else {
            return Ok(());
        };
        // An unknown `msg_type` is IGNORED, which is the rule `FRAME_FORMAT.md`
        // already states and what lets a newer client and an older plane ship
        // in separate commits.
        if msg_type != wire::MSG_JSONRPC {
            continue;
        }
        let Some(response) = handle_one(&ctx, &mut peer, &payload).await else {
            continue;
        };
        let encoded = serde_json::to_vec(&response).unwrap_or_default();
        writer
            .write_all(&wire::encode(wire::MSG_JSONRPC, &encoded))
            .await?;
        writer.flush().await?;
    }
}

/// One JSON-RPC message in, at most one out.
///
/// `None` for a notification, which by JSON-RPC's own rule is a message with
/// no `id` and gets no reply. Kept separate from [`serve`] so the framing and
/// the semantics can be read one at a time.
async fn handle_one(ctx: &Arc<Ctx>, peer: &mut Peer, payload: &[u8]) -> Option<Value> {
    let request: Value = match serde_json::from_slice(payload) {
        Ok(request) => request,
        Err(e) => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": { "code": -32700, "message": format!("that was not JSON: {e}") },
            }))
        }
    };
    let id = request.get("id").cloned();
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let answer = server::dispatch(ctx, peer, &method, &params).await;
    let id = id?;
    Some(match answer {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error.to_json() }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One live session, plus the receiver that keeps it looking alive:
    /// `SessionEntry::is_live` reads the command channel, so a dropped
    /// receiver is a session that has ended.
    fn live_session(
        id: &str,
    ) -> (
        SessionEntry,
        tokio::sync::mpsc::Receiver<vnc_core::ClientCommand>,
    ) {
        use std::sync::atomic::AtomicI32;
        use std::time::Instant;
        use vnc_core::{ProtocolKind, SessionHandle, SessionState};

        let (commands, receiver) = tokio::sync::mpsc::channel(4);
        let entry = SessionEntry {
            handle: SessionHandle {
                id: id.into(),
                kind: ProtocolKind::Vnc,
                commands,
                cancel: Default::default(),
            },
            window_label: format!("session-{id}"),
            profile_id: None,
            address: "10.0.0.5".into(),
            port: 5900,
            started_at: Instant::now(),
            thumbnails: Default::default(),
            last_pointer_mask: Arc::new(AtomicI32::new(-1)),
            facts: Default::default(),
        };
        entry.facts.lock().state = SessionState::Connected;
        (entry, receiver)
    }

    /// A registry of live sessions. The receivers come back with it and have
    /// to be held for the length of the test.
    #[allow(clippy::type_complexity)] // a map and the receivers that keep it alive
    fn registry(
        ids: &[&str],
    ) -> (
        Arc<Mutex<HashMap<String, SessionEntry>>>,
        Vec<tokio::sync::mpsc::Receiver<vnc_core::ClientCommand>>,
    ) {
        let mut sessions = HashMap::new();
        let mut alive = Vec::new();
        for id in ids {
            let (entry, receiver) = live_session(id);
            sessions.insert((*id).to_string(), entry);
            alive.push(receiver);
        }
        (Arc::new(Mutex::new(sessions)), alive)
    }

    /// What one agent's attachment looks like, driving or merely watching.
    fn attachment_of(attachment_id: &str, driving: bool) -> Attachment {
        Attachment {
            attachment_id: attachment_id.into(),
            client: "dvv".into(),
            revoked: false,
            held: driving,
            phase: if driving { "held" } else { "free" }.into(),
            holder_kind: driving.then(|| "agent".to_string()),
            holder_label: None,
            human_took_over: false,
            inflight: Vec::new(),
        }
    }

    /// Wire a plane to a sink, the way `commands::agent::install` wires it to
    /// a window.
    fn wire_to_sink(
        plane: &AgentPlane,
        sessions: &Arc<Mutex<HashMap<String, SessionEntry>>>,
    ) -> Arc<Mutex<Vec<Value>>> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        plane.wire_counts(
            sessions.clone(),
            Arc::new(move |value| sink.lock().push(value)),
        );
        events
    }

    fn counts_of(
        plane: &AgentPlane,
        sessions: &Mutex<HashMap<String, SessionEntry>>,
    ) -> AgentCounts {
        let sessions = sessions.lock();
        plane.counts(&sessions)
    }

    /// One agent holding four limbs is ONE agent.
    ///
    /// The number a person reads is how many things are talking to their
    /// machine, and an agent that attached four windows has not become four
    /// agents by doing so.
    #[test]
    fn one_agent_holding_several_limbs_is_one_agent() {
        let (sessions, _alive) = registry(&["s1", "s2", "s3", "s4"]);
        let plane = Arc::new(AgentPlane::default());
        let _connected = plane.client_connected("dvv");
        for session in ["s1", "s2", "s3", "s4"] {
            plane.attach(session, attachment_of("att_0", true));
        }

        let counts = counts_of(&plane, &sessions);
        assert_eq!(counts.agents_connected, 1, "four limbs, one client");
        assert_eq!(counts.sessions_driven, 4);
        assert_eq!(counts.sessions_live, 4);

        // A SECOND connection is a second agent, and it stops being one the
        // moment its connection ends however it ends.
        {
            let _second = plane.client_connected("claude");
            assert_eq!(counts_of(&plane, &sessions).agents_connected, 2);
        }
        assert_eq!(counts_of(&plane, &sessions).agents_connected, 1);
    }

    /// Attached and idle is NOT driving.
    ///
    /// Conflating the two would tell somebody four machines are being operated
    /// when nobody is touching any of them, which is the failure this number
    /// exists to avoid.
    #[test]
    fn an_attached_but_idle_agent_is_not_driving_anything() {
        let (sessions, _alive) = registry(&["s1", "s2"]);
        let plane = Arc::new(AgentPlane::default());
        let _connected = plane.client_connected("dvv");
        plane.attach("s1", attachment_of("att_0", false));
        plane.attach("s2", attachment_of("att_0", false));

        let counts = counts_of(&plane, &sessions);
        assert_eq!(counts.agents_connected, 1);
        assert_eq!(counts.sessions_driven, 0, "watching is not driving");
        assert_eq!(counts.sessions_live, 2);

        // A holder that is not an agent is not an agent driving either, even
        // while it holds.
        plane.report(
            "s1",
            "att_0",
            true,
            "held".into(),
            Some("human".into()),
            None,
            false,
            Vec::new(),
        );
        assert_eq!(counts_of(&plane, &sessions).sessions_driven, 0);
    }

    /// A person takes the wheel: the driven count falls and the connected
    /// count does not.
    ///
    /// The agent is still there and still attached (`04 §5.4` revokes the
    /// lease and leaves the session alone), so a bar that dropped it from
    /// "agents connected" would be telling a person the thing had gone away.
    #[test]
    fn a_lease_moving_to_a_human_drops_the_driven_count_only() {
        let (sessions, _alive) = registry(&["s1"]);
        let plane = Arc::new(AgentPlane::default());
        let _connected = plane.client_connected("dvv");
        plane.attach("s1", attachment_of("att_0", true));
        assert_eq!(counts_of(&plane, &sessions).sessions_driven, 1);

        plane.revoke("s1").expect("something was attached");
        let counts = counts_of(&plane, &sessions);
        assert_eq!(counts.sessions_driven, 0, "a person has the machine now");
        assert_eq!(counts.agents_connected, 1, "the agent is still connected");
        assert_eq!(counts.sessions_live, 1, "and the session is still live");
    }

    /// With the plane off: two zeroes and one truthful number.
    ///
    /// The live session total is not a fact about the agent plane, so it stays
    /// right when the plane is off, which is what lets one bar serve an
    /// install that never switches this feature on.
    #[test]
    fn with_the_plane_off_the_agent_numbers_are_zero_and_the_session_total_is_not() {
        let (sessions, _alive) = registry(&["s1", "s2", "s3"]);
        let plane = Arc::new(AgentPlane::default());
        assert!(!plane.is_running());

        let counts = counts_of(&plane, &sessions);
        assert_eq!(counts.agents_connected, 0);
        assert_eq!(counts.sessions_driven, 0);
        assert_eq!(counts.sessions_live, 3, "sessions outlive the plane");

        // An agent could not have connected, but say it had: the numbers are
        // still a fact about what is attached and connected right now, not
        // about the setting.
        let _connected = plane.client_connected("dvv");
        plane.attach("s1", attachment_of("att_0", true));
        assert_eq!(
            counts_of(&plane, &sessions),
            AgentCounts {
                agents_connected: 1,
                sessions_driven: 1,
                sessions_live: 3
            }
        );
    }

    /// Switching a running plane off zeroes the two agent numbers at once, and
    /// leaves the third alone.
    ///
    /// At once, and not when the cancelled connection tasks next wake: a bar
    /// that still said "1 agent" a scheduler tick after a person switched the
    /// plane off would be read as the switch not having worked. The session
    /// total does not move, because sessions outlive the plane (`AGENT_BRIEF`
    /// D2).
    #[cfg(unix)]
    #[tokio::test]
    async fn switching_the_plane_off_zeroes_the_agent_numbers_and_leaves_the_sessions() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store =
            Arc::new(vnc_store::Store::open(Some(dir.path().to_path_buf())).expect("a store"));
        let (sessions, _alive) = registry(&["s1", "s2", "s3"]);
        let plane = Arc::new(AgentPlane::default());
        let events = wire_to_sink(&plane, &sessions);
        let ctx = Arc::new(Ctx {
            sessions: sessions.clone(),
            store,
            plane: plane.clone(),
            emit: Arc::new(|_| {}),
        });
        start(&plane, ctx, dir.path().join("agent.sock")).expect("the plane starts");

        let _connected = plane.client_connected("dvv");
        plane.attach("s1", attachment_of("att_0", true));
        assert_eq!(
            counts_of(&plane, &sessions),
            AgentCounts {
                agents_connected: 1,
                sessions_driven: 1,
                sessions_live: 3
            }
        );

        stop(&plane);
        let off = json!({
            "type": "counts",
            "agentsConnected": 0,
            "sessionsDriven": 0,
            "sessionsLive": 3,
        });
        assert_eq!(events.lock().last().cloned().expect("a counts event"), off);
        assert_eq!(counts_of(&plane, &sessions).event(), off);
    }

    /// The event and the command carry the same three numbers, and the event
    /// is emitted on CHANGE.
    ///
    /// `agent_status` answers with `plane.counts(...)` and the stream carries
    /// `plane.counts(...).event()`, so this holds the one to the other at
    /// every edge that moves a number.
    #[test]
    fn the_counts_event_matches_the_command_and_fires_once_per_change() {
        let (sessions, mut alive) = registry(&["s1", "s2"]);
        let plane = Arc::new(AgentPlane::default());
        let events = wire_to_sink(&plane, &sessions);

        let mut expected = Vec::new();
        let connected = plane.client_connected("dvv");
        expected.push(json!({ "type": "counts", "agentsConnected": 1, "sessionsDriven": 0, "sessionsLive": 2 }));
        // Attaching moves no number: the agent was already connected and it is
        // not driving anything yet. The pane hears about the attach on the
        // `attached` payload, and nothing repaints here.
        plane.attach("s1", attachment_of("att_0", false));
        plane.report(
            "s1",
            "att_0",
            true,
            "held".into(),
            Some("agent".into()),
            None,
            false,
            vec!["type".into()],
        );
        expected.push(json!({ "type": "counts", "agentsConnected": 1, "sessionsDriven": 1, "sessionsLive": 2 }));
        // A session ends. `forget` is called after the registry entry is gone,
        // which is the order `commands::session` ends a session in.
        sessions.lock().remove("s2");
        alive.pop();
        plane.forget("s2");
        expected.push(json!({ "type": "counts", "agentsConnected": 1, "sessionsDriven": 1, "sessionsLive": 1 }));
        // The connection ends. The driven count follows the ATTACHMENT table
        // and so does the pane's own agent badge, so a hung up agent that
        // never let go of its limb is still counted as driving it, exactly as
        // the pane still shows the badge and the take the wheel control for
        // it. Two surfaces reading one table is the point: a bar that was
        // cleverer than the badge would contradict it on screen.
        drop(connected);
        expected.push(json!({ "type": "counts", "agentsConnected": 0, "sessionsDriven": 1, "sessionsLive": 1 }));

        assert_eq!(
            *events.lock(),
            expected,
            "one event per change, and no others"
        );
        // …and the last one is what `agent_status` would answer right now.
        assert_eq!(
            events.lock().last().cloned().unwrap(),
            counts_of(&plane, &sessions).event()
        );
    }

    #[test]
    fn only_an_explicit_on_switches_the_plane_on() {
        assert!(!plane_enabled(None), "the default is off, always");
        assert!(!plane_enabled(Some("")));
        assert!(!plane_enabled(Some("maybe")));
        assert!(!plane_enabled(Some("false")));
        for on in ["true", "1", "yes", "on", " on "] {
            assert!(plane_enabled(Some(on)), "{on}");
        }
    }

    /// The path `dvv doctor` prints. If this test fails, one of the two moved
    /// and a person is being told to look somewhere the socket is not.
    #[test]
    fn the_socket_path_is_the_one_dvv_publishes() {
        let path = socket_path();
        assert!(
            path.to_string_lossy().ends_with("agent.sock")
                || path.to_string_lossy().contains("pipe"),
            "{}",
            path.display()
        );
        #[cfg(target_os = "macos")]
        assert!(
            path.to_string_lossy()
                .contains("Library/Application Support/DeskVNCViewer"),
            "not the bundle identifier directory: dvv publishes the product name path ({})",
            path.display()
        );
    }

    /// An attachment id is minted once per connection and never reused, so an
    /// audit line names one attachment and one only.
    #[test]
    fn attachment_ids_are_unique_within_a_run() {
        let plane = AgentPlane::default();
        let first = plane.mint_attachment_id();
        let second = plane.mint_attachment_id();
        assert_ne!(first, second);
        assert!(first.starts_with("att_"));
    }

    /// A revoked attachment cannot report itself back into the wheel: the
    /// person's decision outranks the agent's opinion of it (D5).
    #[test]
    fn a_revoked_attachment_cannot_report_itself_back_in() {
        let plane = AgentPlane::default();
        plane.attach(
            "s1",
            Attachment {
                attachment_id: "att_0".into(),
                client: "test".into(),
                revoked: false,
                held: true,
                phase: "held".into(),
                holder_kind: Some("agent".into()),
                holder_label: None,
                human_took_over: false,
                inflight: vec!["type".into()],
            },
        );
        let revoked = plane.revoke("s1").expect("something was attached");
        assert_eq!(revoked["humanTookOver"], true);
        assert_eq!(revoked["held"], false);

        assert!(
            plane
                .report(
                    "s1",
                    "att_0",
                    true,
                    "held".into(),
                    Some("agent".into()),
                    None,
                    false,
                    Vec::new(),
                )
                .is_none(),
            "a revocation is not a request"
        );
        let snapshot = plane.snapshot();
        assert_eq!(snapshot[0]["revoked"], true);
    }

    /// The whole of "off", and the whole of "on", over a real socket.
    ///
    /// `AGENT_BRIEF` D2 and `00 R40` want an ordinary install unchanged by
    /// this feature existing, and "unchanged" is a claim about the
    /// filesystem, so it is checked against the filesystem. The same test
    /// then drives one full round trip through the accept loop, the framing
    /// and the dispatcher, because a socket that exists and answers nothing
    /// would pass the first half.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_socket_exists_only_while_the_plane_is_on_and_answers_while_it_is() {
        use serde_json::json;
        use std::collections::HashMap;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::AtomicI32;
        use std::time::Instant;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use vnc_core::{ClientCommand, ProtocolKind, SessionHandle, SessionState};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("agent.sock");
        let store =
            Arc::new(vnc_store::Store::open(Some(dir.path().to_path_buf())).expect("a store"));
        let (commands_tx, mut commands) = tokio::sync::mpsc::channel(16);
        let entry = crate::state::SessionEntry {
            handle: SessionHandle {
                id: "s1".into(),
                kind: ProtocolKind::Vnc,
                commands: commands_tx,
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
        let mut sessions = HashMap::new();
        sessions.insert("s1".to_string(), entry);

        let plane = Arc::new(AgentPlane::default());
        let ctx = Arc::new(Ctx {
            sessions: Arc::new(Mutex::new(sessions)),
            store,
            plane: plane.clone(),
            emit: Arc::new(|_| {}),
        });

        // Off. Nothing exists, and that is the default every install gets.
        assert!(
            !path.exists(),
            "a plane that was never started opens no file"
        );
        assert!(!plane.is_running());

        start(&plane, ctx, path.clone()).expect("the plane starts");
        assert!(path.exists(), "the socket is bound before start() returns");
        assert!(plane.is_running());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "04 §2.1: mode 0600, or the plane is not started at all"
        );

        // …and it answers. One hello, one attach, one command, and the command
        // comes out on a real session's channel.
        let mut client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect");
        let request = |method: &str, params: serde_json::Value| {
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params
            }))
            .unwrap()
        };
        for (method, params) in [
            (
                "hello",
                json!({ "protocol": PROTOCOL, "client": { "name": "the test" } }),
            ),
            (
                "limb.attach",
                json!({ "address": "10.0.0.5", "protocol": "vnc", "slot": 0 }),
            ),
            (
                "limb.command",
                json!({
                    "sessionId": "s1",
                    "command": { "kind": "pointer", "x": 3, "y": 4, "buttonMask": 0 },
                }),
            ),
        ] {
            let body = request(method, params);
            client
                .write_all(&wire::encode(wire::MSG_JSONRPC, &body))
                .await
                .unwrap();
            let mut header = [0u8; wire::HEADER];
            client.read_exact(&mut header).await.unwrap();
            let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
            let mut payload = vec![0u8; len];
            client.read_exact(&mut payload).await.unwrap();
            let answer: Value = serde_json::from_slice(&payload).unwrap();
            assert!(answer.get("error").is_none(), "{method} answered {answer}",);
        }
        let landed = commands.try_recv().expect("the session was sent to");
        assert!(matches!(landed, ClientCommand::Pointer { x: 3, y: 4, .. }));

        // Off again, and off means gone: `dvv doctor` reports the plane by
        // looking for this file, so leaving it would tell every agent the
        // plane is up when it is not.
        stop(&plane);
        assert!(!path.exists());
        assert!(!plane.is_running());
    }

    /// The manual proof, kept in the tree so it can be run again rather than
    /// pasted into a report and forgotten.
    ///
    /// `#[ignore]` because it binds the REAL socket path, the one
    /// [`socket_path`] publishes and `dvv doctor` prints, and shells out to
    /// the `dvv` binary beside it. Both of those are side effects a test suite
    /// should not have: run it deliberately, with the application closed, as
    ///
    /// ```text
    /// cargo build -p dvv
    /// cargo test -p deskvncviewer -- --ignored --nocapture the_doctor
    /// ```
    #[cfg(unix)]
    #[ignore = "binds the real socket path and runs the dvv binary; run it deliberately"]
    // Multi threaded on purpose. The body blocks a thread waiting for a child
    // process, and on a current thread runtime that would starve the accept
    // loop, so the `dvv` it is waiting for would hang against a socket that
    // exists and never answers.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_doctor_stops_saying_not_wired_yet() {
        use std::collections::HashMap;
        use std::sync::atomic::AtomicI32;
        use std::time::Instant;
        use vnc_core::{ProtocolKind, SessionHandle, SessionState};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store =
            Arc::new(vnc_store::Store::open(Some(dir.path().to_path_buf())).expect("a store"));
        // One live session, so `dvv hosts` and `dvv open` have something real
        // to reach. The receiver is held for the length of the test, which is
        // what `SessionEntry::is_live` reads.
        let (commands, _receiver) = tokio::sync::mpsc::channel(16);
        let entry = crate::state::SessionEntry {
            handle: SessionHandle {
                id: "manual-proof".into(),
                kind: ProtocolKind::Vnc,
                commands,
                cancel: Default::default(),
            },
            window_label: "session-manual-proof".into(),
            profile_id: None,
            address: "10.0.0.5".into(),
            port: 5900,
            started_at: Instant::now(),
            thumbnails: Default::default(),
            last_pointer_mask: Arc::new(AtomicI32::new(-1)),
            facts: Default::default(),
        };
        entry.facts.lock().state = SessionState::Connected;
        entry.facts.lock().size = Some((1920, 1080));
        let mut sessions = HashMap::new();
        sessions.insert("manual-proof".to_string(), entry);

        let plane = Arc::new(AgentPlane::default());
        let ctx = Arc::new(Ctx {
            sessions: Arc::new(Mutex::new(sessions)),
            store,
            plane: plane.clone(),
            emit: Arc::new(|_| {}),
        });
        let path = socket_path();
        start(&plane, ctx, path.clone()).expect("the plane starts at its published path");

        let dvv = std::env::current_dir()
            .unwrap()
            .join("../target/debug/dvv")
            .canonicalize()
            .expect("build dvv first: cargo build -p dvv");
        let run = |args: &[&str]| {
            let out = std::process::Command::new(&dvv)
                .args(args)
                .output()
                .expect("dvv runs");
            println!(
                "--- dvv {} ---\n{}{}",
                args.join(" "),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
            (
                out.status.code(),
                String::from_utf8_lossy(&out.stdout).to_string(),
            )
        };

        let (code, doctor) = run(&["doctor"]);
        let (_, hosts) = run(&["hosts"]);
        let (_, opened) = run(&["open", "10.0.0.5:5900", "--protocol", "vnc", "--perceive"]);

        // Paint the mirror `dvv open --perceive` just attached.
        //
        // There is no server behind this session: the handle is a channel with
        // nobody decoding on the other end, so the `Refresh` the attach put on
        // the wire is never answered and the mirror stays priming forever.
        // This stands in for that answer, and it stands in for the ONE line
        // this feature is still missing in the running application: see
        // [`AgentPlane::feed`], which is exactly what a real
        // `SessionEvent::FramebufferUpdate` would reach.
        let mut screen = Vec::with_capacity(1920 * 1080 * 4);
        for y in 0..1080u32 {
            for x in 0..1920u32 {
                // A coarse checkerboard, so a person looking at the decoded
                // PNG can see it is a picture of something rather than a
                // uniform fill that any bug would also produce.
                let on = ((x / 120) + (y / 120)) % 2 == 0;
                screen.extend_from_slice(if on {
                    &[32u8, 48, 96, 255]
                } else {
                    &[216u8, 216, 208, 255]
                });
            }
        }
        plane.feed(
            "manual-proof",
            &[vnc_core::DecodedRect {
                rect: vnc_core::Rect::new(0, 0, 1920, 1080),
                payload: vnc_core::RectPayload::Rgba(screen),
            }],
        );

        // …and read it, over the same socket `dvv` uses, so the transcript is
        // of the wire and not of an internal call.
        let frame = read_one_frame(&path).await;
        let observation = &frame["observation"];
        let space = &observation["image"]["space"];
        println!(
            "--- screen.read on manual-proof ---\n\
             rung             {}\n\
             framebuffer      {}x{}\n\
             coverage         {}\n\
             geometry         generation {}\n\
             image            {} {}x{}, {} bytes encoded\n\
             ImageSpace       region ({}, {}) {}x{}, scale {}\n\
             00 R43 check     a click at image (728, 410) is framebuffer pixel ({}, {})\n",
            observation["rung"],
            observation["space"]["width"],
            observation["space"]["height"],
            observation["coverage"],
            observation["geometry_generation"],
            observation["image"]["format"],
            space["width"],
            space["height"],
            observation["image"]["encoded_bytes"],
            space["region"]["x"],
            space["region"]["y"],
            space["region"]["width"],
            space["region"]["height"],
            space["scale"],
            space["region"]["x"].as_u64().unwrap()
                + ((728.0 + 0.5) / space["scale"].as_f64().unwrap()).floor() as u64,
            space["region"]["y"].as_u64().unwrap()
                + ((410.0 + 0.5) / space["scale"].as_f64().unwrap()).floor() as u64,
        );

        // The whole chain, through `dvv mcp` in ONE process, so `dvv_open` and
        // `dvv_screen` share a limb registry the way a real client does.
        let (_, through_mcp) = run_mcp(&dvv);
        stop(&plane);

        assert!(
            doctor.contains("present"),
            "the socket has to read as present: {doctor}"
        );
        assert!(
            !doctor.contains("not wired yet"),
            "that sentence is what this whole change removes: {doctor}"
        );
        assert_eq!(
            code,
            Some(0),
            "04 §9 acceptance 1: non zero only when the plane is not there"
        );
        assert!(
            hosts.contains("10.0.0.5"),
            "a machine the application has open reaches the CLI: {hosts}"
        );
        assert!(
            opened.contains("lmb_vnc"),
            "an attach over the socket produces a real limb id: {opened}"
        );
        assert_eq!(frame["unchanged"], false, "{frame}");
        assert_eq!(
            observation["coverage"], "complete",
            "a fully painted mirror with no H.264 over it vouches for every pixel"
        );
        assert!(
            observation["image"]["encoded_bytes"].as_u64().unwrap_or(0) > 0,
            "a frame with no bytes in it is a picture that was never taken"
        );
        assert!(
            through_mcp.contains("\"has_mirror\":true"),
            "dvv_limbs has to say the limb can be looked at: {through_mcp}"
        );
    }

    /// One `screen.read` over the real socket, framed the way `dvv` frames it.
    #[cfg(unix)]
    async fn read_one_frame(path: &std::path::Path) -> Value {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut client = tokio::net::UnixStream::connect(path)
            .await
            .expect("the plane is listening");
        let mut answer = Value::Null;
        for (id, method, params) in [
            (
                1,
                "hello",
                json!({ "protocol": PROTOCOL, "client": { "name": "the manual proof" } }),
            ),
            (
                2,
                "limb.attach",
                json!({
                    "address": "10.0.0.5", "protocol": "vnc", "slot": 0, "perceive": true,
                }),
            ),
            (
                3,
                "screen.read",
                json!({ "sessionId": "manual-proof", "kind": "frame" }),
            ),
        ] {
            let body = serde_json::to_vec(
                &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
            )
            .unwrap();
            client
                .write_all(&wire::encode(wire::MSG_JSONRPC, &body))
                .await
                .unwrap();
            let mut header = [0u8; wire::HEADER];
            client.read_exact(&mut header).await.unwrap();
            let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
            let mut payload = vec![0u8; len];
            client.read_exact(&mut payload).await.unwrap();
            let message: Value = serde_json::from_slice(&payload).unwrap();
            assert!(
                message.get("error").is_none(),
                "{method} answered {message}"
            );
            answer = message["result"].clone();
        }
        answer
    }

    /// `dvv mcp --stdio`, driven by hand, one process for both calls.
    ///
    /// One process matters: `LimbRegistry` is per plane and a plane is per
    /// process, so a `dvv_screen` in its own invocation would resolve no limb.
    /// This is what an MCP client does, and it is the path an agent actually
    /// takes.
    #[cfg(unix)]
    fn run_mcp(dvv: &std::path::Path) -> (Option<i32>, String) {
        use std::io::Write;

        let conversation = [
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "dvv_open", "arguments": { "address": "10.0.0.5", "port": 5900, "protocol": "vnc", "perceive": true } } }),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "dvv_limbs", "arguments": {} } }),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "dvv_screen", "arguments": {} } }),
        ];
        let mut child = std::process::Command::new(dvv)
            .args(["mcp", "--stdio"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("dvv mcp runs");
        {
            let stdin = child.stdin.as_mut().expect("a pipe");
            for message in &conversation {
                writeln!(stdin, "{message}").expect("wrote");
            }
        }
        let out = child.wait_with_output().expect("dvv mcp ends");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        println!(
            "--- dvv mcp --stdio (dvv_open --perceive, dvv_limbs, dvv_screen) ---\n{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), stdout)
    }

    /// A bundle shaped tree with a `dvv` in it, and the main binary's path.
    fn fake_bundle(root: &std::path::Path, with_dvv: bool) -> PathBuf {
        let macos = root.join("DeskVNCViewer.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).expect("the bundle directory");
        let exe = macos.join("deskvncviewer");
        std::fs::write(&exe, b"main").expect("the main binary");
        if with_dvv {
            std::fs::write(macos.join(DVV_FILE_NAME), b"sidecar").expect("the sidecar");
        }
        exe
    }

    /// An installed app answers an absolute path that is really there.
    ///
    /// Absolute because the modal's instructions are pasted into a shell with
    /// a working directory nobody controls, and really there because the whole
    /// point of the change is that the path it prints can be run.
    #[test]
    fn a_bundled_app_answers_the_path_of_the_dvv_beside_it() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let exe = fake_bundle(dir.path(), true);
        let found = dvv_beside(&exe).expect("the bundled dvv");
        assert!(found.is_absolute(), "{} is not absolute", found.display());
        assert!(found.is_file(), "{} is not there", found.display());
        assert_eq!(
            found.file_name().and_then(|n| n.to_str()),
            Some(DVV_FILE_NAME)
        );
        assert_eq!(found.parent(), exe.parent(), "beside the main binary");
    }

    /// A bundle that somehow shipped without the sidecar says so.
    #[test]
    fn a_bundle_without_the_sidecar_answers_nothing() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let exe = fake_bundle(dir.path(), false);
        assert_eq!(dvv_beside(&exe), None);
    }

    /// `cargo tauri dev` answers `null`, even though `target/debug/dvv` is
    /// sitting right there.
    ///
    /// It is there because both are workspace binaries, and it is NOT the
    /// answer: the path appears in instructions about an installed app, and a
    /// developer's target directory is not one. The webview renders a
    /// placeholder for this case.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_development_build_answers_nothing_even_with_a_dvv_beside_it() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let target = dir.path().join("target/debug");
        std::fs::create_dir_all(&target).expect("the target directory");
        let exe = target.join("deskvncviewer");
        std::fs::write(&exe, b"main").expect("the main binary");
        std::fs::write(target.join("dvv"), b"sidecar").expect("the dev dvv");
        assert_eq!(dvv_beside(&exe), None, "a dev build has no bundle");
    }

    /// The registration runs exactly this, and a path with a space in it
    /// survives it.
    ///
    /// Asserted as a vector rather than by running `claude`: the shape of the
    /// command line is the contract, and a test that needed Claude Code
    /// installed would pass on one machine and be skipped on every other.
    #[test]
    fn the_registration_builds_the_argv_claude_expects() {
        let dvv = PathBuf::from("/Volumes/My Disk/DeskVNCViewer.app/Contents/MacOS/dvv");
        assert_eq!(
            register_argv(&dvv),
            vec![
                "mcp",
                "add",
                "--scope",
                "user",
                "deskvnc",
                "--",
                "/Volumes/My Disk/DeskVNCViewer.app/Contents/MacOS/dvv",
                "mcp",
                "--stdio",
            ]
        );
        assert_eq!(register_argv(&dvv)[4], MCP_SERVER_NAME);
    }

    /// PATH is searched first and the installers' own locations after it, and
    /// nothing appears twice.
    #[test]
    fn claude_is_looked_for_on_path_and_then_where_the_installers_put_it() {
        let looked = claude_candidates(Some("/opt/homebrew/bin:/usr/bin:"), Some("/Users/x"));
        assert_eq!(
            looked.first(),
            Some(&PathBuf::from("/opt/homebrew/bin/claude"))
        );
        assert!(looked.contains(&PathBuf::from("/Users/x/.claude/local/claude")));
        assert!(looked.contains(&PathBuf::from("/usr/local/bin/claude")));
        let mut unique = looked.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), looked.len(), "a path was searched twice");
        // An empty PATH segment is not the current directory here.
        assert!(!looked.contains(&PathBuf::from("claude")));
        assert!(!claude_candidates(None, None).is_empty());
    }

    /// A machine with no Claude Code reports that, rather than panicking or
    /// blaming the exec.
    #[test]
    fn a_missing_claude_is_a_reported_outcome_and_not_a_panic() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let missing = dir.path().join("claude");
        assert!(!is_executable(&missing), "nothing is installed here");
        std::fs::write(&missing, b"#!/bin/sh\n").expect("a file");
        assert!(!is_executable(&missing), "a file with no execute bit");

        let outcome = RegistrationOutcome::ClaudeNotFound {
            looked: vec![missing.display().to_string()],
        };
        let json = serde_json::to_value(&outcome).expect("it serializes");
        assert_eq!(json["status"], "claude-not-found");
        assert_eq!(json["looked"][0], missing.display().to_string());

        // And the whole command, in a test process that is not a bundle: no
        // binary to register, said plainly.
        assert_eq!(register_with_claude(), RegistrationOutcome::NoBinary);
    }

    /// Every outcome carries a tag the webview can switch on.
    #[test]
    fn each_registration_outcome_has_its_own_tag() {
        for (outcome, tag) in [
            (
                RegistrationOutcome::Registered {
                    claude: "/usr/local/bin/claude".into(),
                    argv: register_argv(std::path::Path::new("/x/dvv")),
                },
                "registered",
            ),
            (
                RegistrationOutcome::AlreadyRegistered {
                    claude: "/usr/local/bin/claude".into(),
                },
                "already-registered",
            ),
            (RegistrationOutcome::NoBinary, "no-binary"),
            (
                RegistrationOutcome::Failed {
                    claude: "/usr/local/bin/claude".into(),
                    code: Some(1),
                    stderr: "no".into(),
                },
                "failed",
            ),
            (
                RegistrationOutcome::TimedOut {
                    claude: "/usr/local/bin/claude".into(),
                    seconds: 20,
                },
                "timed-out",
            ),
        ] {
            let json = serde_json::to_value(&outcome).expect("it serializes");
            assert_eq!(json["status"], tag);
        }
    }

    /// "It already exists" is read out of the tool's own words.
    #[test]
    fn an_existing_server_is_recognised_from_what_claude_said() {
        assert!(already_registered(
            "",
            "Error: MCP server deskvnc already exists in user config"
        ));
        assert!(already_registered(
            "A server named deskvnc is already configured",
            ""
        ));
        assert!(!already_registered(
            "",
            "Error: could not write the config file"
        ));
    }

    /// A child that never ends is killed and reported as a timeout.
    ///
    /// The button cannot be left held down by a hung process, which is the
    /// only reason the deadline exists.
    #[cfg(unix)]
    #[test]
    fn a_child_that_hangs_is_killed_and_reported_as_a_timeout() {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "sleep 30"]);
        let finished =
            run_bounded(command, std::time::Duration::from_millis(200)).expect("the child spawns");
        assert!(finished.timed_out, "the deadline was not enforced");
        assert_eq!(finished.code, None);
    }

    /// Both pipes are read, and the exit code comes back.
    #[cfg(unix)]
    #[test]
    fn a_child_that_fails_hands_back_its_words_and_its_code() {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "echo out; echo err >&2; exit 3"]);
        let finished =
            run_bounded(command, std::time::Duration::from_secs(10)).expect("the child spawns");
        assert!(!finished.timed_out);
        assert_eq!(finished.code, Some(3));
        assert_eq!(finished.stdout.trim(), "out");
        assert_eq!(finished.stderr.trim(), "err");
    }
}
