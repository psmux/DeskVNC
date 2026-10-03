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
//! the authentication, the same as `agent.sock`.
//!
//! Unix only, because the shell side of this crate is unix only. On Windows
//! every verb runs in process as before, which is no worse than it was.

use crate::mcp::Server;
use crate::plane::Plane;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// How long a holder with nothing to do stays up.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(30 * 60);

/// Where the holder listens: beside `agent.sock`, under the same directory.
pub fn holder_path() -> PathBuf {
    let app = PathBuf::from(crate::cli::socket_path());
    app.with_file_name("dvv-cli.sock")
}

/// Send one tool call to a running holder.
///
/// `None` when no holder answers, so the caller can serve the call in
/// process. A holder that answered and then failed mid reply is an error, not
/// a `None`: running the same call again locally would act twice.
#[cfg(unix)]
pub fn call(name: &str, arguments: &Value) -> Option<Result<Value, String>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(holder_path()).ok()?;
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

#[cfg(not(unix))]
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

#[cfg(not(unix))]
pub fn spawn() -> Result<u32, String> {
    Err(
        "a holder needs the unix socket the shell side uses, which this platform does not have"
            .into(),
    )
}

/// Serve the holder socket until the last limb closes or nothing calls.
#[cfg(unix)]
pub async fn run(plane: Arc<Plane>, idle: Duration) -> i32 {
    use crate::jsonrpc::Connection;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
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
                let server = server.clone();
                let plane = plane.clone();
                let last_call = last_call.clone();
                let held_any = held_any.clone();
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    let (reader, writer) = stream.into_split();
                    let mut connection = Connection::new(tokio::io::BufReader::new(reader), writer);
                    while let Ok(Some(Ok(request))) = connection.read().await {
                        *last_call.lock().await = Instant::now();
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
                });
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

#[cfg(not(unix))]
pub async fn run(_plane: Arc<Plane>, _idle: Duration) -> i32 {
    eprintln!("dvv hold needs a unix socket, which this platform does not have");
    2
}
