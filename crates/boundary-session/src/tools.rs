//! Commands and files over a Boundary session.
//!
//! A helper's tools, such as DeskVNC's `dvv_run` and `dvv_files`, need two
//! things a screen cannot give them: a command's own output and exit status,
//! and a file's exact bytes. Over SSH both ride a second channel. Here they
//! ride a second QUIC stream on the connection the session already has, one
//! stream per request, so a slow download never holds up a command and
//! neither touches the control stream that carries input.
//!
//! **Nothing here runs without the person's say so.** The person at the
//! computer allows it separately from viewing and from control, it is off
//! until they do, and they can take it back at any moment. Every request is
//! checked against the permission as it stands when the request arrives, and
//! every one that runs is reported to the host app so the person can see
//! what was done. An unattended computer allows it only for a paired helper
//! whose entry says so, never for a password.
//!
//! Both sides say they speak this before either relies on it: a helper puts
//! `tools` in its hello, and a host that understands answers with `tools` in
//! its grant. A helper talking to an older host is told so in a sentence
//! rather than left waiting on a stream nothing will ever read.

use anyhow::{Context, Result, anyhow, ensure};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

/// The JSON half of a frame. Large enough for a directory of some thousands
/// of entries and a long command with its environment.
pub const MAX_HEADER: usize = 1024 * 1024;
/// The raw half of a frame: a file window, stdin, or a command's output.
/// Above DeskVNC's own four megabyte window so a full window always fits.
pub const MAX_BODY: usize = 9 * 1024 * 1024;
/// The most a run keeps of each output stream, whatever the helper asked.
pub const MAX_OUTPUT: u64 = 4 * 1024 * 1024;
/// The largest file window one request moves.
pub const MAX_WINDOW: u64 = 4 * 1024 * 1024;
/// The longest a single command may run.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// Requests the host works on at once. A helper that sends more waits.
const CONCURRENT: usize = 4;
/// How long a command's output may keep arriving after the command itself
/// has ended. Something it started in the background can hold the output
/// open for good, and that must not hold the answer.
const DRAIN: Duration = Duration::from_secs(2);

/// Something a helper's tools ask the host to do.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    /// Run `command` in the platform shell: `cmd.exe /C` on Windows,
    /// `/bin/sh -c` elsewhere, the same shells an SSH server uses. The frame's
    /// body is the command's standard input, which is closed once written.
    Run {
        command: String,
        cwd: Option<String>,
        env: Vec<(String, String)>,
        timeout_ms: u64,
        max_output: u64,
    },
    Home,
    List {
        path: String,
    },
    Get {
        path: String,
        offset: u64,
        length: u64,
    },
    /// The frame's body is the bytes to write. Offset zero truncates first.
    Put {
        path: String,
        offset: u64,
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
impl Request {
    /// One line for the person at the computer, saying what was asked.
    pub fn summary(&self) -> String {
        match self {
            Self::Run { command, .. } => format!("ran {}", clip(command, 160)),
            Self::Home => "looked up the home folder".into(),
            Self::List { path } => format!("listed {}", clip(path, 160)),
            Self::Get { path, .. } => format!("copied {} from this computer", clip(path, 160)),
            Self::Put { path, .. } => format!("copied {} to this computer", clip(path, 160)),
            Self::Mkdir { path } => format!("made the folder {}", clip(path, 160)),
            Self::Remove { path, .. } => format!("deleted {}", clip(path, 160)),
            Self::Rename { from, to } => {
                format!("renamed {} to {}", clip(from, 80), clip(to, 80))
            }
        }
    }
}
fn clip(text: &str, max: usize) -> String {
    let line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if line.chars().count() <= max {
        line
    } else {
        format!("{}...", line.chars().take(max).collect::<String>())
    }
}

/// One entry of a listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    /// Unix seconds.
    pub modified: Option<i64>,
    /// Permission bits where the platform has them, zero where it does not.
    pub mode: u32,
}

/// The host's answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Reply {
    /// A command ran. The body is its kept standard output followed by its
    /// kept standard error, `stdout` bytes of the first.
    Ran {
        /// `None` when the process was ended by a signal, or did not end
        /// before its deadline. Never a stand in for either.
        code: Option<i32>,
        signal: Option<String>,
        timed_out: bool,
        stdout: u64,
        cap: u64,
        stdout_dropped: u64,
        stdout_dropped_lines: u64,
        stderr_dropped: u64,
        stderr_dropped_lines: u64,
        duration_ms: u64,
    },
    Path(String),
    Listing {
        path: String,
        entries: Vec<Entry>,
    },
    /// The body is the window.
    Window {
        path: String,
        offset: u64,
        size: u64,
    },
    Wrote {
        path: String,
        offset: u64,
        written: u64,
        size: u64,
    },
    /// The person at the computer has not allowed this.
    Refused(String),
    /// It was allowed and did not work, and why.
    Failed(String),
}

async fn write_frame<T: Serialize>(send: &mut SendStream, header: &T, body: &[u8]) -> Result<()> {
    let header = serde_json::to_vec(header)?;
    ensure!(header.len() <= MAX_HEADER, "The tool request is too large");
    ensure!(body.len() <= MAX_BODY, "The tool request body is too large");
    send.write_all(&(header.len() as u32).to_be_bytes()).await?;
    send.write_all(&header).await?;
    send.write_all(&(body.len() as u32).to_be_bytes()).await?;
    send.write_all(body).await?;
    Ok(())
}
async fn read_length(recv: &mut RecvStream, max: usize) -> Result<usize> {
    let mut length = [0; 4];
    recv.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(length <= max, "Tool frame is too large");
    Ok(length)
}
async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<(T, Vec<u8>)> {
    let length = read_length(recv, MAX_HEADER).await?;
    ensure!(length > 0, "Empty tool frame");
    let mut header = vec![0; length];
    recv.read_exact(&mut header).await?;
    let header = serde_json::from_slice(&header)?;
    let length = read_length(recv, MAX_BODY).await?;
    let mut body = vec![0; length];
    recv.read_exact(&mut body).await?;
    Ok((header, body))
}

/// What a helper holds to send requests, for as long as the session lasts.
#[derive(Clone)]
pub struct Client {
    connection: Connection,
    allowed: watch::Receiver<bool>,
}
impl Client {
    pub(crate) fn new(connection: Connection, allowed: watch::Receiver<bool>) -> Self {
        Self {
            connection,
            allowed,
        }
    }
    /// Whether the person at the computer allows commands and files right
    /// now, as last heard. The host checks again on every request, so this
    /// is for saying so early, not for deciding.
    pub fn allowed(&self) -> bool {
        *self.allowed.borrow()
    }
    /// Send one request and wait for its answer. `wait` bounds the whole
    /// exchange, so it should be the command's own timeout plus a margin.
    pub async fn call(
        &self,
        request: &Request,
        body: &[u8],
        wait: Duration,
    ) -> Result<(Reply, Vec<u8>)> {
        tokio::time::timeout(wait, async {
            let (mut send, mut recv) = self
                .connection
                .open_bi()
                .await
                .context("The support session has ended")?;
            write_frame(&mut send, request, body).await?;
            send.finish()?;
            read_frame(&mut recv).await
        })
        .await
        .map_err(|_| anyhow!("The computer did not answer in time"))?
    }
}

/// The host's side: answer every request stream the helper opens, within
/// the permission `allowed` holds at the moment each one arrives. `told` is
/// called with a line for each request that ran, for the person to see.
pub(crate) async fn serve(
    connection: &Connection,
    allowed: watch::Receiver<bool>,
    told: impl Fn(String) + Send + Sync + 'static,
) -> Result<()> {
    let told = Arc::new(told);
    let slots = Arc::new(tokio::sync::Semaphore::new(CONCURRENT));
    loop {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let permit = slots.clone().acquire_owned().await?;
        let allowed = allowed.clone();
        let told = told.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok((request, body))) =
                tokio::time::timeout(Duration::from_secs(30), read_frame::<Request>(&mut recv))
                    .await
            else {
                let _ = send.reset(1u8.into());
                return;
            };
            let (reply, out) = if *allowed.borrow() {
                told(request.summary());
                answer(request, body).await
            } else {
                (Reply::Refused(REFUSED.into()), Vec::new())
            };
            if write_frame(&mut send, &reply, &out).await.is_ok() {
                let _ = send.finish();
                let _ = send.stopped().await;
            }
        });
    }
}
const REFUSED: &str = "The person at that computer has not allowed commands and files for this session. Ask them to tick Allow commands and files in DeskVNC Support, or, for an unattended computer, to allow it for this helper under Settings, Unattended access";

/// Do one allowed request.
pub async fn answer(request: Request, body: Vec<u8>) -> (Reply, Vec<u8>) {
    let result = match request {
        Request::Run {
            command,
            cwd,
            env,
            timeout_ms,
            max_output,
        } => run(command, cwd, env, timeout_ms, max_output, body).await,
        other => tokio::task::spawn_blocking(move || files(other, body))
            .await
            .unwrap_or_else(|e| Err(anyhow!("The file worker failed: {e}"))),
    };
    result.unwrap_or_else(|error| (Reply::Failed(format!("{error:#}")), Vec::new()))
}

/// What one output stream kept, and what it had to let go.
#[derive(Default)]
struct Collector {
    kept: Vec<u8>,
    dropped: u64,
    dropped_lines: u64,
}
impl Collector {
    fn take(&mut self, chunk: &[u8], cap: usize) {
        let room = cap.saturating_sub(self.kept.len()).min(chunk.len());
        self.kept.extend_from_slice(&chunk[..room]);
        let rest = &chunk[room..];
        self.dropped += rest.len() as u64;
        self.dropped_lines += rest.iter().filter(|b| **b == b'\n').count() as u64;
    }
}
fn pump<R: AsyncRead + Unpin + Send + 'static>(
    mut from: R,
    into: Arc<Mutex<Collector>>,
    cap: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0; 64 * 1024];
        while let Ok(n) = from.read(&mut buffer).await {
            if n == 0 {
                break;
            }
            if let Ok(mut c) = into.lock() {
                c.take(&buffer[..n], cap);
            }
        }
    })
}

async fn run(
    command: String,
    cwd: Option<String>,
    env: Vec<(String, String)>,
    timeout_ms: u64,
    max_output: u64,
    stdin: Vec<u8>,
) -> Result<(Reply, Vec<u8>)> {
    ensure!(!command.trim().is_empty(), "There is no command to run");
    ensure!(timeout_ms > 0, "A command needs a timeout");
    let timeout = Duration::from_millis(timeout_ms).min(MAX_TIMEOUT);
    let cap = if max_output == 0 {
        MAX_OUTPUT
    } else {
        max_output.min(MAX_OUTPUT)
    };
    let home = home()?;
    let dir = match cwd.as_deref().filter(|c| !c.trim().is_empty()) {
        Some(cwd) => resolve(&home, cwd),
        None => home,
    };
    let mut shell = shell(&command);
    shell
        .current_dir(&dir)
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = shell
        .spawn()
        .with_context(|| format!("Cannot start the shell in {}", dir.display()))?;
    let started = Instant::now();
    let stdout = Arc::new(Mutex::new(Collector::default()));
    let stderr = Arc::new(Mutex::new(Collector::default()));
    let out = pump(
        child.stdout.take().context("No output pipe")?,
        stdout.clone(),
        cap as usize,
    );
    let err = pump(
        child.stderr.take().context("No error pipe")?,
        stderr.clone(),
        cap as usize,
    );
    if let Some(mut pipe) = child.stdin.take() {
        // Written off to the side and then closed, which is load bearing: a
        // command that reads its input blocks for good on an open pipe.
        tokio::spawn(async move {
            let _ = pipe.write_all(&stdin).await;
            let _ = pipe.shutdown().await;
        });
    }
    let status = tokio::time::timeout(timeout, child.wait()).await;
    let timed_out = status.is_err();
    if timed_out {
        if let Some(id) = child.id() {
            kill_tree(id).await;
        }
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    }
    let drain = DRAIN.min(
        timeout
            .saturating_sub(started.elapsed())
            .max(Duration::from_millis(200)),
    );
    // Readers that are still going after this keep running detached, and
    // what they had collected is taken below either way.
    let _ = tokio::time::timeout(drain, async {
        let _ = out.await;
        let _ = err.await;
    })
    .await;
    let (code, signal) = match status {
        Ok(Ok(status)) => (status.code(), signal_of(&status)),
        Ok(Err(error)) => return Err(anyhow!("Lost track of the command: {error}")),
        Err(_) => (None, None),
    };
    let take = |c: &Arc<Mutex<Collector>>| {
        c.lock()
            .map(|mut c| std::mem::take(&mut *c))
            .unwrap_or_default()
    };
    let (stdout, stderr) = (take(&stdout), take(&stderr));
    let reply = Reply::Ran {
        code,
        signal,
        timed_out,
        stdout: stdout.kept.len() as u64,
        cap,
        stdout_dropped: stdout.dropped,
        stdout_dropped_lines: stdout.dropped_lines,
        stderr_dropped: stderr.dropped,
        stderr_dropped_lines: stderr.dropped_lines,
        duration_ms: started.elapsed().as_millis() as u64,
    };
    let mut body = stdout.kept;
    body.extend_from_slice(&stderr.kept);
    Ok((reply, body))
}

#[cfg(windows)]
fn shell(command: &str) -> tokio::process::Command {
    // No console window: the support app is a windowed program, and every
    // command would otherwise flash one up on the person's screen.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut shell = tokio::process::Command::new("cmd.exe");
    // `/S` takes the outer quotes off and leaves the command as written, so
    // its own quoting reaches cmd untouched rather than escaped a second time.
    shell
        .raw_arg(format!("/D /S /C \"{command}\""))
        .creation_flags(CREATE_NO_WINDOW);
    shell
}
#[cfg(not(windows))]
fn shell(command: &str) -> tokio::process::Command {
    let mut shell = tokio::process::Command::new("/bin/sh");
    // A group of its own, so a deadline can end everything it started.
    shell.arg("-c").arg(command).process_group(0);
    shell
}
/// End a command that ran past its deadline and everything it started.
/// Killing the shell alone leaves its children running, and they hold its
/// output open.
#[cfg(windows)]
async fn kill_tree(id: u32) {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = tokio::process::Command::new("taskkill.exe")
        .args(["/F", "/T", "/PID", &id.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .await;
}
#[cfg(not(windows))]
async fn kill_tree(id: u32) {
    let _ = tokio::process::Command::new("kill")
        .args(["-KILL", "--", &format!("-{id}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}
#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map(|n| {
        match n {
            1 => "HUP",
            2 => "INT",
            3 => "QUIT",
            6 => "ABRT",
            9 => "KILL",
            11 => "SEGV",
            13 => "PIPE",
            14 => "ALRM",
            15 => "TERM",
            _ => return n.to_string(),
        }
        .to_string()
    })
}
#[cfg(not(unix))]
fn signal_of(_: &std::process::ExitStatus) -> Option<String> {
    None
}

fn home() -> Result<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .context("This computer's account has no home folder")
}
/// `~`, `~/x` and relative paths start at the home folder, as they do over
/// SFTP. Anything absolute is taken as written.
fn resolve(home: &Path, path: &str) -> PathBuf {
    let path = path.trim();
    if path == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return home.join(rest);
    }
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        home.join(path)
    }
}
/// A canonical path as a person would write it. Windows' canonical form
/// starts with `\\?\`, which nobody types and few programs accept.
fn shown(path: &Path) -> String {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = path.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(local) = text.strip_prefix(r"\\?\") {
        local.to_string()
    } else {
        text.into_owned()
    }
}
fn entry(path: &Path) -> Result<Entry> {
    let link = std::fs::symlink_metadata(path)?;
    let meta = std::fs::metadata(path).unwrap_or_else(|_| link.clone());
    Ok(Entry {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        path: path.to_string_lossy().into_owned(),
        is_dir: meta.is_dir(),
        is_symlink: link.file_type().is_symlink(),
        size: if meta.is_dir() { 0 } else { meta.len() },
        modified: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64),
        mode: mode_of(&meta),
    })
}
#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
fn mode_of(_: &std::fs::Metadata) -> u32 {
    0
}

fn files(request: Request, body: Vec<u8>) -> Result<(Reply, Vec<u8>)> {
    let home = home()?;
    let named = |path: &str| -> Result<PathBuf> {
        ensure!(!path.trim().is_empty(), "A path is needed");
        Ok(resolve(&home, path))
    };
    let done = |path: &Path| Ok((Reply::Path(shown(path)), Vec::new()));
    match request {
        Request::Home => done(&home),
        Request::List { path } => {
            let dir = named(&path)?;
            let mut entries = Vec::new();
            for item in
                std::fs::read_dir(&dir).with_context(|| format!("Cannot list {}", dir.display()))?
            {
                let Ok(item) = item else { continue };
                if let Ok(entry) = entry(&item.path()) {
                    entries.push(entry);
                }
            }
            entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
            Ok((
                Reply::Listing {
                    path: shown(&dir),
                    entries,
                },
                Vec::new(),
            ))
        }
        Request::Get {
            path,
            offset,
            length,
        } => {
            let file = named(&path)?;
            let mut handle = std::fs::File::open(&file)
                .with_context(|| format!("Cannot open {}", file.display()))?;
            let meta = handle.metadata()?;
            ensure!(!meta.is_dir(), "{} is a folder", file.display());
            let size = meta.len();
            let mut bytes = Vec::new();
            if offset < size {
                handle.seek(SeekFrom::Start(offset))?;
                handle
                    .take(length.min(MAX_WINDOW))
                    .read_to_end(&mut bytes)?;
            }
            Ok((
                Reply::Window {
                    path: shown(&file),
                    offset,
                    size,
                },
                bytes,
            ))
        }
        Request::Put { path, offset, mode } => {
            let file = named(&path)?;
            ensure!(body.len() as u64 <= MAX_WINDOW, "That window is too large");
            let mut options = std::fs::OpenOptions::new();
            options.write(true);
            if offset == 0 {
                options.create(true).truncate(true);
            }
            let mut handle = options
                .open(&file)
                .with_context(|| format!("Cannot write {}", file.display()))?;
            handle.seek(SeekFrom::Start(offset))?;
            handle.write_all(&body)?;
            handle.flush()?;
            #[cfg(unix)]
            if let Some(mode) = mode {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode & 0o7777))?;
            }
            #[cfg(not(unix))]
            let _ = mode;
            let size = handle.metadata()?.len();
            Ok((
                Reply::Wrote {
                    path: shown(&file),
                    offset,
                    written: body.len() as u64,
                    size,
                },
                Vec::new(),
            ))
        }
        Request::Mkdir { path } => {
            let dir = named(&path)?;
            std::fs::create_dir(&dir).with_context(|| format!("Cannot make {}", dir.display()))?;
            done(&dir)
        }
        Request::Remove { path, recursive } => {
            let target = named(&path)?;
            ensure!(target != home, "Refusing to delete the home folder");
            let shown_path = shown(&target);
            let meta = std::fs::symlink_metadata(&target)
                .with_context(|| format!("Cannot find {}", target.display()))?;
            let result = if meta.is_dir() {
                if recursive {
                    std::fs::remove_dir_all(&target)
                } else {
                    std::fs::remove_dir(&target)
                }
            } else {
                // A link to a folder on Windows is removed as a folder.
                std::fs::remove_file(&target)
                    .or_else(|e| std::fs::remove_dir(&target).map_err(|_| e))
            };
            result.with_context(|| format!("Cannot delete {}", target.display()))?;
            Ok((Reply::Path(shown_path), Vec::new()))
        }
        Request::Rename { from, to } => {
            let (from, to) = (named(&from)?, named(&to)?);
            std::fs::rename(&from, &to)
                .with_context(|| format!("Cannot rename {} to {}", from.display(), to.display()))?;
            done(&to)
        }
        Request::Run { .. } => Err(anyhow!("A command is not a file operation")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("boundary-tools-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn tilde_and_relative_paths_start_at_home() {
        let home = Path::new("/home/someone");
        assert_eq!(resolve(home, "~"), home);
        assert_eq!(resolve(home, "~/notes.txt"), home.join("notes.txt"));
        assert_eq!(resolve(home, "notes.txt"), home.join("notes.txt"));
    }

    #[test]
    fn output_past_the_cap_is_counted_not_kept() {
        let mut c = Collector::default();
        c.take(b"abc\ndef\nghi\n", 5);
        assert_eq!(c.kept, b"abc\nd");
        assert_eq!(c.dropped, 7);
        assert_eq!(c.dropped_lines, 2);
    }

    #[tokio::test]
    async fn a_command_answers_with_its_own_output_and_status() {
        let (reply, body) = answer(
            Request::Run {
                command: "echo hello && exit 3".into(),
                cwd: None,
                env: vec![],
                timeout_ms: 20_000,
                max_output: 0,
            },
            Vec::new(),
        )
        .await;
        let Reply::Ran {
            code,
            timed_out,
            stdout,
            ..
        } = reply
        else {
            panic!("{reply:?}");
        };
        assert_eq!(code, Some(3));
        assert!(!timed_out);
        let out = String::from_utf8_lossy(&body[..stdout as usize]);
        assert_eq!(out.trim(), "hello");
    }

    #[tokio::test]
    async fn stdin_reaches_the_command_and_is_closed() {
        let command = if cfg!(windows) { "findstr x" } else { "cat" };
        let (reply, body) = answer(
            Request::Run {
                command: command.into(),
                cwd: None,
                env: vec![],
                timeout_ms: 20_000,
                max_output: 0,
            },
            b"x marks\n".to_vec(),
        )
        .await;
        let Reply::Ran { code, stdout, .. } = reply else {
            panic!("{reply:?}");
        };
        assert_eq!(code, Some(0));
        assert_eq!(
            String::from_utf8_lossy(&body[..stdout as usize]).trim(),
            "x marks"
        );
    }

    #[tokio::test]
    async fn a_command_past_its_deadline_has_no_invented_status() {
        let command = if cfg!(windows) {
            "ping -n 30 127.0.0.1"
        } else {
            "sleep 30"
        };
        let started = Instant::now();
        let (reply, _) = answer(
            Request::Run {
                command: command.into(),
                cwd: None,
                env: vec![],
                timeout_ms: 500,
                max_output: 0,
            },
            Vec::new(),
        )
        .await;
        let Reply::Ran {
            code, timed_out, ..
        } = reply
        else {
            panic!("{reply:?}");
        };
        assert!(timed_out);
        assert_eq!(code, None);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn files_round_trip_in_windows() {
        let dir = scratch("files");
        let file = dir.join("data.bin");
        let path = file.to_string_lossy().to_string();
        let put = |offset, bytes: &[u8]| {
            answer(
                Request::Put {
                    path: path.clone(),
                    offset,
                    mode: None,
                },
                bytes.to_vec(),
            )
        };
        assert!(matches!(
            put(0, b"hello ").await.0,
            Reply::Wrote { size: 6, .. }
        ));
        assert!(matches!(
            put(6, b"world").await.0,
            Reply::Wrote { size: 11, .. }
        ));
        let (reply, bytes) = answer(
            Request::Get {
                path: path.clone(),
                offset: 6,
                length: 100,
            },
            Vec::new(),
        )
        .await;
        assert!(matches!(
            reply,
            Reply::Window {
                size: 11,
                offset: 6,
                ..
            }
        ));
        assert_eq!(bytes, b"world");
        let (reply, _) = answer(
            Request::List {
                path: dir.to_string_lossy().to_string(),
            },
            Vec::new(),
        )
        .await;
        let Reply::Listing { entries, .. } = reply else {
            panic!("{reply:?}");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(
            (entries[0].name.as_str(), entries[0].size),
            ("data.bin", 11)
        );
        let renamed = dir.join("moved.bin").to_string_lossy().to_string();
        assert!(matches!(
            answer(
                Request::Rename {
                    from: path,
                    to: renamed.clone()
                },
                Vec::new()
            )
            .await
            .0,
            Reply::Path(_)
        ));
        assert!(matches!(
            answer(
                Request::Remove {
                    path: renamed,
                    recursive: false
                },
                Vec::new()
            )
            .await
            .0,
            Reply::Path(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
