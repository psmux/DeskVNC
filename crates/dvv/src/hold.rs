//! The holder: one long lived plane that CLI verbs share.
//!
//! Every `dvv` invocation is its own process, and everything a limb means to
//! this crate lives in that process: the registry, the lease, the generation
//! the last screen read was served at. The application keys its typing fence
//! on the attachment id `hello` minted for the connection, so a second process
//! is a second attachment that has never looked at anything. Run as separate
//! commands, `dvv open`, `dvv screen` and `dvv type` were three agents that
//! each saw nothing the others did: the limb was gone by the second command,
//! and even re-adopting it would leave `dvv type` refused with SCREEN_CHANGED
//! forever, because the fence has no override and should not grow one.
//!
//! So `dvv open` starts `dvv hold` when none is running, and every tool verb
//! after it is sent to the holder rather than served in process. The holder is
//! one attachment for as long as it lives, which is exactly the shape
//! `dvv mcp --stdio` already has for an MCP client. It goes away when its last
//! limb is closed, or after [`DEFAULT_IDLE`] with no call at all, so a script
//! that forgot `dvv close` does not leave an agent attached to somebody's
//! machine for ever.
//!
//! The socket sits beside the application's own, in a directory only this
//! user can read, and is created mode 0600. No token: the file permission is
//! the authentication, the same as `agent.sock`. On Windows it is a named
//! pipe beside the plane's, with the same owner only ACL (`local-pipe`).

use crate::mcp::Server;
use crate::plane::Plane;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// How long a holder with nothing to do stays up.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(30 * 60);

/// Where the holder listens: beside `agent.sock`, under the same directory.
#[cfg(not(windows))]
pub fn holder_path() -> PathBuf {
    let app = PathBuf::from(crate::cli::socket_path());
    app.with_file_name("dvv-cli.sock")
}

/// Where the holder listens: a pipe named for this user beside the plane's.
#[cfg(windows)]
pub fn holder_path() -> PathBuf {
    let user = std::env::var("USERNAME").unwrap_or_default();
    PathBuf::from(format!("\\\\.\\pipe\\deskvncviewer-dvv-cli-{user}"))
}

/// One blocking connection to a running holder.
#[cfg(unix)]
fn dial() -> std::io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(holder_path())
}

#[cfg(windows)]
fn dial() -> std::io::Result<std::fs::File> {
    local_pipe::connect(&holder_path().to_string_lossy())
}

/// Send one tool call to a running holder.
///
/// `None` when no holder answers, so the caller can serve the call in
/// process. A holder that answered and then failed mid reply is an error, not
/// a `None`: running the same call again locally would act twice.
#[cfg(any(unix, windows))]
pub fn call(name: &str, arguments: &Value) -> Option<Result<Value, String>> {
    use std::io::{BufRead, BufReader, Write};

    let stream = dial().ok()?;
    let exchange = || -> std::io::Result<Value> {
        let mut writer = stream.try_clone()?;
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
        writer.write_all(serde_json::to_string(&request)?.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line)?;
        let reply: Value = serde_json::from_str(&line)?;
        Ok(reply.get("result").cloned().unwrap_or(reply))
    };
    Some(exchange().map_err(|e| {
        format!(
            "the dvv holder at {} stopped answering: {e}",
            holder_path().display()
        )
    }))
}

#[cfg(not(any(unix, windows)))]
pub fn call(_name: &str, _arguments: &Value) -> Option<Result<Value, String>> {
    None
}

/// Start a holder in the background and wait for it to listen.
///
/// Its own process group, so a Ctrl+C in the terminal that ran `dvv open` does
/// not take the session down with it, and no inherited stdio, so a pipe the
/// caller reads to the end is not held open by it.
#[cfg(unix)]
pub fn spawn() -> Result<u32, String> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe =
        std::env::current_exe().map_err(|e| format!("this binary cannot find itself: {e}"))?;
    let child = Command::new(exe)
        .arg("hold")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("the dvv holder would not start: {e}"))?;
    let path = holder_path();
    for _ in 0..100 {
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            return Ok(child.id());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "the dvv holder started but is not listening at {} after five seconds",
        path.display()
    ))
}

/// Start a holder in the background and wait for it to listen.
///
/// Detached from the console and in a process group of its own, which is the
/// Windows reading of the unix version above: closing the terminal, or a
/// Ctrl+C in it, does not end the session. It also asks to leave the job
/// object the caller runs in, because an agent that runs each shell command
/// in a job killed on close would otherwise take the holder down with the
/// command that started it. A job that forbids leaving is retried without.
#[cfg(windows)]
pub fn spawn() -> Result<u32, String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

    let exe =
        std::env::current_exe().map_err(|e| format!("this binary cannot find itself: {e}"))?;
    let start = |flags: u32| {
        Command::new(&exe)
            .arg("hold")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(flags)
            .spawn()
    };
    // Without this the holder keeps the caller's stdout open, and an agent
    // reading `dvv open`'s output to the end waits for as long as it lives.
    local_pipe::keep_std_handles_private();
    let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    let child = start(flags | CREATE_BREAKAWAY_FROM_JOB)
        .or_else(|_| start(flags))
        .map_err(|e| format!("the dvv holder would not start: {e}"))?;
    let path = holder_path();
    for _ in 0..100 {
        if local_pipe::exists(&path.to_string_lossy()) {
            return Ok(child.id());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "the dvv holder started but is not listening at {} after five seconds",
        path.display()
    ))
}

#[cfg(not(any(unix, windows)))]
pub fn spawn() -> Result<u32, String> {
    Err("a holder needs a local socket, which this platform does not have".into())
}

/// Serve the holder socket until the last limb closes or nothing calls.
#[cfg(unix)]
pub async fn run(plane: Arc<Plane>, idle: Duration) -> i32 {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;
    use tokio::net::UnixListener;
    use tokio::time::Instant;

    let path = holder_path();
    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
        eprintln!("a dvv holder is already listening at {}", path.display());
        return 1;
    }
    // Nothing answered, so whatever is at the path is a socket a holder that
    // crashed left behind.
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("the dvv holder could not listen at {}: {e}", path.display());
            return 1;
        }
    };
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("the dvv holder could not restrict {}: {e}", path.display());
        let _ = std::fs::remove_file(&path);
        return 1;
    }

    let server = Arc::new(Server::new(plane.clone()));
    let last_call = Arc::new(tokio::sync::Mutex::new(Instant::now()));
    let held_any = Arc::new(AtomicBool::new(false));
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let mut tick = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                tokio::spawn(serve(
                    stream,
                    server.clone(),
                    plane.clone(),
                    last_call.clone(),
                    held_any.clone(),
                    done_tx.clone(),
                ));
            }
            _ = done_rx.recv() => break,
            _ = tick.tick() => {
                if last_call.lock().await.elapsed() >= idle {
                    break;
                }
            }
        }
    }
    // Close what is still open, so the application sees the attachment let go
    // rather than an agent that hung up holding the wheel.
    for limb in plane.limbs() {
        let _ = plane.close(&limb.limb_id);
    }
    let _ = std::fs::remove_file(&path);
    0
}

/// Serve the holder pipe until the last limb closes or nothing calls.
///
/// The same loop as the unix one, with a pipe instance in place of an
/// accept: an instance serves one client, so the next is made as soon as one
/// is taken.
#[cfg(windows)]
pub async fn run(plane: Arc<Plane>, idle: Duration) -> i32 {
    use std::sync::atomic::AtomicBool;
    use tokio::time::Instant;

    let path = holder_path().to_string_lossy().into_owned();
    if local_pipe::exists(&path) {
        eprintln!("a dvv holder is already listening at {path}");
        return 1;
    }
    let mut listening = match local_pipe::create(&path, true) {
        Ok(server) => server,
        Err(e) => {
            eprintln!("the dvv holder could not listen at {path}: {e}");
            return 1;
        }
    };

    let server = Arc::new(Server::new(plane.clone()));
    let last_call = Arc::new(tokio::sync::Mutex::new(Instant::now()));
    let held_any = Arc::new(AtomicBool::new(false));
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let mut tick = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            connected = listening.connect() => {
                if connected.is_err() {
                    continue;
                }
                let next = match local_pipe::create(&path, false) {
                    Ok(next) => next,
                    Err(e) => {
                        eprintln!("the dvv holder could not make its next pipe instance: {e}");
                        break;
                    }
                };
                let stream = std::mem::replace(&mut listening, next);
                tokio::spawn(serve(
                    stream,
                    server.clone(),
                    plane.clone(),
                    last_call.clone(),
                    held_any.clone(),
                    done_tx.clone(),
                ));
            }
            _ = done_rx.recv() => break,
            _ = tick.tick() => {
                if last_call.lock().await.elapsed() >= idle {
                    break;
                }
            }
        }
    }
    for limb in plane.limbs() {
        let _ = plane.close(&limb.limb_id);
    }
    0
}

#[cfg(not(any(unix, windows)))]
pub async fn run(_plane: Arc<Plane>, _idle: Duration) -> i32 {
    eprintln!("dvv hold needs a local socket, which this platform does not have");
    2
}

/// One client of the holder, until it hangs up.
///
/// Notes the time of every call for the idle timeout, and says when the last
/// limb has closed after at least one was open, which is the holder's cue to
/// go away.
#[cfg(any(unix, windows))]
async fn serve<S>(
    stream: S,
    server: Arc<Server>,
    plane: Arc<Plane>,
    last_call: Arc<tokio::sync::Mutex<tokio::time::Instant>>,
    held_any: Arc<std::sync::atomic::AtomicBool>,
    done_tx: tokio::sync::mpsc::Sender<()>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    use crate::jsonrpc::Connection;
    use std::sync::atomic::Ordering;

    let (reader, writer) = tokio::io::split(stream);
    let mut connection = Connection::new(tokio::io::BufReader::new(reader), writer);
    while let Ok(Some(Ok(request))) = connection.read().await {
        *last_call.lock().await = tokio::time::Instant::now();
        if let Some(reply) = server.handle(&request).await {
            if connection.write(&reply).await.is_err() {
                break;
            }
        }
        if plane.limbs().is_empty() {
            if held_any.load(Ordering::Relaxed) {
                let _ = done_tx.try_send(());
            }
        } else {
            held_any.store(true, Ordering::Relaxed);
        }
    }
}
