//! Starting DeskVNCViewer when an agent needs it and it is not running.
//!
//! The application holds the sessions and the passwords, so an agent can do
//! nothing without it. Asking the person to open it first was one more step
//! between installing an agent and using it, so `dvv` opens it instead.
//!
//! Where it looks, in order: the path the app recorded the last time it ran;
//! beside this `dvv`, which is where every installer
//! puts the two; then where the installers put the app when this `dvv` is a
//! copy elsewhere, which is how Pi runs it on Windows. On macOS `open -b` asks
//! Launch Services for the bundle id, which finds the app wherever it lives.
//!
//! The app is started detached, in its own process group and outside the
//! caller's job, with no inherited handles: an agent that reads `dvv`'s output
//! to the end must not wait on an app that will run for hours.

#[cfg(not(target_os = "macos"))]
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The bundle id in `tauri.conf.json`.
#[cfg(target_os = "macos")]
const BUNDLE_ID: &str = "com.deskvncviewer.desktop";

/// The application's executable name on Windows and Linux.
#[cfg(not(target_os = "macos"))]
const APP_FILE: &str = if cfg!(windows) {
    "deskvncviewer.exe"
} else {
    "deskvncviewer"
};

/// Start DeskVNCViewer. `true` when something was started; whether its plane
/// comes up is the caller's to wait for.
pub fn start_app() -> bool {
    #[cfg(target_os = "macos")]
    {
        detached(
            Command::new("open")
                .args(["-g", "-b", BUNDLE_ID])
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let Some(app) = find_app() else {
            return false;
        };
        let mut command = Command::new(app);
        // What the app says while starting goes to a file rather than
        // nowhere: an app that will not start is otherwise a thirty second
        // wait and a sentence with no reason in it.
        // Never inherited: on Windows that hands the app the agent's pipe,
        // and the agent waits for an end of output that never comes.
        command.stdout(Stdio::null()).stderr(Stdio::null());
        if let Ok(log) = std::fs::File::create(launch_log()) {
            if let Ok(err) = log.try_clone() {
                command.stdout(log).stderr(err);
            }
        }
        detached(&mut command)
    }
}

/// Where the application is, if it is installed somewhere `dvv` knows.
#[cfg(not(target_os = "macos"))]
pub fn find_app() -> Option<PathBuf> {
    candidates().into_iter().find(|path| path.is_file())
}

/// Where the app last said it was: it writes its own path to `app-path` in
/// its data folder at every start (`src-tauri/src/commands/agent.rs`), and
/// that beats every guess below when two copies are installed.
#[cfg(not(target_os = "macos"))]
fn recorded() -> Option<PathBuf> {
    const IDENTIFIER: &str = "com.deskvncviewer.desktop";
    #[cfg(windows)]
    let data = PathBuf::from(std::env::var_os("APPDATA")?);
    #[cfg(not(windows))]
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
        })?;
    let text = std::fs::read_to_string(data.join(IDENTIFIER).join("app-path")).ok()?;
    Some(PathBuf::from(text.trim()))
}

#[cfg(not(target_os = "macos"))]
fn candidates() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = recorded().into_iter().collect();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join(APP_FILE));
        }
        // A symlink to the installed `dvv`, as on Linux and macOS.
        if let Some(dir) = exe.canonicalize().ok().as_deref().and_then(Path::parent) {
            out.push(dir.join(APP_FILE));
        }
    }
    #[cfg(windows)]
    for var in ["LOCALAPPDATA", "ProgramFiles", "ProgramW6432"] {
        if let Some(base) = std::env::var_os(var) {
            out.push(PathBuf::from(base).join("DeskVNCViewer").join(APP_FILE));
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(paths) = std::env::var_os("PATH") {
            out.extend(std::env::split_paths(&paths).map(|dir| dir.join(APP_FILE)));
        }
        out.push(PathBuf::from("/usr/bin").join(APP_FILE));
    }
    out
}

/// Where the output of an app `dvv` started is kept, for when it did not come
/// up.
pub fn launch_log() -> std::path::PathBuf {
    std::env::temp_dir().join("deskvncviewer-started-by-dvv.log")
}

/// Spawn and let go. Output goes wherever the caller pointed it, nowhere by
/// default.
fn detached(command: &mut Command) -> bool {
    command.stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        local_pipe::keep_std_handles_private();
        let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        command.creation_flags(flags | CREATE_BREAKAWAY_FROM_JOB);
        if command.spawn().is_ok() {
            return true;
        }
        command.creation_flags(flags);
        command.spawn().is_ok()
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        command.spawn().is_ok()
    }
    #[cfg(not(any(windows, unix)))]
    {
        command.spawn().is_ok()
    }
}
