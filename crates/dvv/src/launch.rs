//! Starting DeskVNCViewer when an agent needs it and it is not running.
//!
//! The application holds the sessions and the passwords, so an agent can do
//! nothing without it. Asking the person to open it first was one more step
//! between installing an agent and using it, so `dvv` opens it instead.
//!
//! Where it looks, in order: beside this `dvv`, which is where every installer
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
        detached(Command::new("open").args(["-g", "-b", BUNDLE_ID]))
    }
    #[cfg(not(target_os = "macos"))]
    {
        match find_app() {
            Some(app) => detached(&mut Command::new(app)),
            None => false,
        }
    }
}

/// Where the application is, if it is installed somewhere `dvv` knows.
#[cfg(not(target_os = "macos"))]
pub fn find_app() -> Option<PathBuf> {
    candidates().into_iter().find(|path| path.is_file())
}

#[cfg(not(target_os = "macos"))]
fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
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

/// Spawn and let go.
fn detached(command: &mut Command) -> bool {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
