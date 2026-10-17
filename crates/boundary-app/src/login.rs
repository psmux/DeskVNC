//! Unattended access before anyone signs in.
//!
//! The app the person sees starts when they sign in, so after a restart the
//! computer could not be reached until somebody signed in at it, which is
//! the one moment a helper cannot ask for. This adds a copy with no window
//! that runs at the sign in screen, as the same machine ID and with the same
//! paired helpers and password, read from the person's own data folder.
//!
//! On macOS launchd starts it in the login window session, as root. On
//! Windows a service starts it in the console session, as SYSTEM, whenever
//! nobody is signed in there, and while the session is locked, because the
//! lock screen is out of a person's programs' sight too. Either way it steps
//! aside once somebody signs in or unlocks, and the app in the tray takes
//! over the ID.
//!
//! Nobody is at the sign in screen to approve a helper, so a helper who is
//! not paired and has no password is turned away, and no helper's tools may
//! run anything: they would run as the system.

use anyhow::{Context, Result};
use boundary_session::unattended::{self, Access, Notice};
use std::time::Duration;

/// How often the host looks at whether it should still be running.
const TICK: Duration = Duration::from_secs(2);

/// The host at the sign in screen. Returns when somebody has signed in.
pub fn host() -> Result<()> {
    #[cfg(windows)]
    boundary_platform::system::follow_input_desktop();
    let runtime = tokio::runtime::Runtime::new().context("Cannot start the connection runtime")?;
    runtime.block_on(serve())
}

/// A line in `sign-in-screen.log` beside the machine ID, which is the one
/// place to look when a helper reaches the computer at the sign in screen
/// and sees nothing: nobody is signed in to show an error to.
fn note(dir: &std::path::Path, line: &str) {
    crate::journal::note(dir, "sign-in-screen.log", line);
}

/// Capture one frame and say what came back, so a black screen can be told
/// apart from a screen that has nothing on it.
fn probe(display: u32) -> String {
    let frame = boundary_platform::open(display).and_then(|mut desktop| desktop.capture());
    #[cfg(windows)]
    let desktop = boundary_platform::system::attached_desktop().unwrap_or_else(|| "?".into());
    #[cfg(not(windows))]
    let desktop = "-";
    match frame {
        Ok(frame) => format!(
            "first frame {}x{} on desktop {desktop}, {}",
            frame.width,
            frame.height,
            if frame.rgba.chunks(4).all(|p| p[..3] == [0, 0, 0]) {
                "all black"
            } else {
                "has a picture"
            }
        ),
        Err(error) => format!("capture failed on desktop {desktop}: {error:#}"),
    }
}

async fn serve() -> Result<()> {
    let dir = boundary_provision::platform::data_dir()?;
    let access_path = dir.join("access.json");
    note(&dir, "started");
    // Whoever listens holds this. The app in the tray lets go of it when the
    // screen locks; with fast user switching it may still hold it behind the
    // sign in screen. Two copies listening as one ID push each other off the
    // relay, so this waits its turn.
    let _lock = loop {
        if signed_in() {
            return Ok(());
        }
        if let Ok(Some(lock)) = boundary_provision::platform::claim_unattended() {
            break lock;
        }
        tokio::time::sleep(TICK).await;
    };
    let mut listener = None;
    let mut session = None;
    loop {
        if signed_in() {
            return Ok(());
        }
        let enabled = Access::load(&access_path).is_ok_and(|a| a.enabled);
        if !enabled {
            listener = None;
            session = None;
        } else if listener.is_none() {
            // Created by the app when unattended access was switched on.
            let key = unattended::load_or_create_key(&dir.join("machine.key"))?;
            let display = boundary_platform::displays()
                .ok()
                .and_then(|all| all.first().map(|d| d.id));
            if let Some(display) = display {
                let probed = tokio::task::spawn_blocking(move || probe(display))
                    .await
                    .unwrap_or_default();
                note(&dir, &probed);
                listener = Some(unattended::listen_at_login(
                    boundary_session::HostOptions::default(),
                    key,
                    access_path.clone(),
                    move || boundary_platform::open(display),
                ));
            } else {
                note(&dir, "no display to share");
            }
        }
        let mut finished = false;
        if let Some(l) = listener.as_mut() {
            while let Ok(notice) = l.notices.try_recv() {
                match notice {
                    // Held until it ends; dropping it would end it.
                    Notice::Ready { .. } => note(&dir, "listening"),
                    Notice::Connected {
                        session: s, name, ..
                    } => {
                        note(&dir, &format!("{name} connected"));
                        session = Some(s);
                    }
                    Notice::Refused { name, reason, .. } => {
                        note(&dir, &format!("turned away {name}: {reason}"));
                    }
                    Notice::Finished(result) => {
                        note(&dir, &format!("stopped listening: {result:?}"));
                        finished = true;
                    }
                    _ => {}
                }
            }
        }
        if let Some(s) = session.as_mut() {
            while let Ok(event) = s.events.try_recv() {
                if matches!(event, boundary_session::Event::Finished(_)) {
                    session = None;
                    break;
                }
            }
        }
        if finished {
            // Lost the network, most likely. Start again on the next tick.
            listener = None;
            session = None;
        }
        tokio::time::sleep(TICK).await;
    }
}

/// Whether somebody is signed in at the screen this host is on.
#[cfg(target_os = "macos")]
fn signed_in() -> bool {
    use std::os::unix::fs::MetadataExt;
    // root owns the console while the login window shows it.
    std::fs::metadata("/dev/console").is_ok_and(|m| m.uid() != 0)
}
/// The service stops this host when somebody signs in.
#[cfg(not(target_os = "macos"))]
fn signed_in() -> bool {
    false
}

/// The Windows service: start the host in the console session while nobody
/// is signed in there or it is locked, and stop it otherwise.
#[cfg(windows)]
pub fn service() -> Result<()> {
    boundary_platform::system::run_service(watch)
}

#[cfg(windows)]
fn watch(stop: &'static std::sync::atomic::AtomicBool) {
    use boundary_platform::system;
    use std::sync::atomic::Ordering;
    // The person's local app data folder, which holds the machine ID and who
    // may connect. Given when the service was installed.
    let owner = std::env::args()
        .skip_while(|a| a != "--service")
        .nth(1)
        .unwrap_or_default();
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut child: Option<(u32, system::Child)> = None;
    while !stop.load(Ordering::Relaxed) {
        // Nobody signed in, or locked: either way the screen is the secure
        // desktop, which the app in the tray cannot see.
        let wanted = system::console()
            .filter(|c| !c.signed_in || c.locked)
            .map(|c| c.session);
        let current = child.as_ref().filter(|(_, c)| c.running()).map(|(s, _)| *s);
        if wanted != current {
            if let Some((_, old)) = child.take() {
                old.kill();
            }
            if let Some(session) = wanted {
                child = system::spawn_in_session(
                    session,
                    &exe,
                    "--login-screen",
                    &[("LOCALAPPDATA", owner.as_str())],
                )
                .ok()
                .map(|c| (session, c));
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    if let Some((_, old)) = child.take() {
        old.kill();
    }
}

/// Whether the host is set up to run at the sign in screen.
pub fn enabled() -> bool {
    imp::enabled()
}

/// Set the host up, or take it away. Asks for an administrator.
pub fn set(on: bool) -> Result<()> {
    imp::set(on)
}

/// Whether this platform can run anything at the sign in screen.
pub const SUPPORTED: bool = cfg!(any(target_os = "macos", windows));

#[cfg(target_os = "macos")]
mod imp {
    use anyhow::{Context, Result, ensure};

    const LABEL: &str = "com.psmux.deskvnc.support.login";

    fn plist() -> String {
        format!("/Library/LaunchAgents/{LABEL}.plist")
    }
    pub fn enabled() -> bool {
        std::path::Path::new(&plist()).exists()
    }
    /// Run `script` as root, after macOS asks for an administrator.
    fn as_admin(script: &str) -> Result<()> {
        let output = std::process::Command::new("osascript")
            .args([
                "-e",
                "on run argv",
                "-e",
                "do shell script (item 1 of argv) with administrator privileges",
                "-e",
                "end run",
                script,
            ])
            .output()?;
        ensure!(
            output.status.success(),
            "{}",
            if String::from_utf8_lossy(&output.stderr).contains("-128") {
                "Cancelled".to_string()
            } else {
                format!(
                    "macOS did not accept it: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )
            }
        );
        Ok(())
    }
    pub fn set(on: bool) -> Result<()> {
        if !on {
            return as_admin(&format!("rm -f '{}'", plist()));
        }
        ensure!(
            crate::install::translocated().is_none(),
            "Move DeskVNC Support to Applications first"
        );
        let exe = std::env::current_exe().context("This app cannot find itself")?;
        let home = std::env::var("HOME").context("No home folder")?;
        let escape = |s: &str| {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        };
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>AssociatedBundleIdentifiers</key><string>com.psmux.deskvnc.support</string>
<key>LimitLoadToSessionType</key><string>LoginWindow</string>
<key>ProgramArguments</key><array><string>{}</string><string>--login-screen</string></array>
<key>EnvironmentVariables</key><dict><key>HOME</key><string>{}</string></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ProcessType</key><string>Interactive</string>
</dict></plist>
"#,
            escape(&exe.to_string_lossy()),
            escape(&home)
        );
        let staged = std::env::temp_dir().join(format!("{LABEL}.plist"));
        std::fs::write(&staged, body)?;
        let quote = |s: &str| format!("'{}'", s.replace('\'', r"'\''"));
        let result = as_admin(&format!(
            "install -o root -g wheel -m 644 {} {}",
            quote(&staged.to_string_lossy()),
            quote(&plist())
        ));
        let _ = std::fs::remove_file(&staged);
        result
    }
}

#[cfg(windows)]
mod imp {
    use anyhow::{Context, Result, ensure};
    use boundary_platform::system::SERVICE;
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::Command;

    const NO_WINDOW: u32 = 0x0800_0000;

    pub fn enabled() -> bool {
        Command::new("sc.exe")
            .args(["query", SERVICE])
            .creation_flags(NO_WINDOW)
            .output()
            .is_ok_and(|o| o.status.success())
    }
    /// Run this app again as an administrator with `args`, after Windows
    /// asks, and wait for it.
    fn as_admin(args: &str) -> Result<()> {
        let exe = std::env::current_exe().context("This app cannot find itself")?;
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let script = format!(
            "$p = Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
            quote(&exe.to_string_lossy()),
            quote(args)
        );
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .creation_flags(NO_WINDOW)
            .status()?;
        ensure!(
            status.success(),
            "Windows did not allow it, or it was cancelled"
        );
        Ok(())
    }
    pub fn set(on: bool) -> Result<()> {
        if on {
            let owner = std::env::var("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?;
            as_admin(&format!("--install-service \"{owner}\""))
        } else {
            as_admin("--uninstall-service")
        }
    }

    fn sc(args: &str) -> Result<bool> {
        Ok(Command::new("sc.exe")
            .raw_arg(args)
            .creation_flags(NO_WINDOW)
            .output()?
            .status
            .success())
    }
    /// Where the service runs from. A copy under Program Files, which only
    /// an administrator can change: the service runs as SYSTEM, and running
    /// a file the signed in person could replace would hand them SYSTEM.
    fn installed() -> Result<PathBuf> {
        let base = std::env::var_os("ProgramFiles").context("No Program Files folder")?;
        Ok(PathBuf::from(base)
            .join("DeskVNC Support")
            .join("DeskVNC Support.exe"))
    }
    /// Run elevated, from [`set`].
    pub fn install(owner: &str) -> Result<()> {
        let _ = sc(&format!("stop {SERVICE}"));
        let target = installed()?;
        std::fs::create_dir_all(target.parent().context("No folder")?)?;
        let source = std::env::current_exe()?;
        if source != target {
            // The old copy may still be running for a moment after the stop.
            let mut copied = std::fs::copy(&source, &target);
            for _ in 0..10 {
                if copied.is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
                copied = std::fs::copy(&source, &target);
            }
            copied.context("Cannot copy the app to Program Files")?;
        }
        let path = format!(
            "binPath= \"\\\"{}\\\" --service \\\"{owner}\\\"\"",
            target.display()
        );
        let configured = if enabled() {
            sc(&format!("config {SERVICE} {path} start= auto"))?
        } else {
            sc(&format!(
                "create {SERVICE} {path} start= auto DisplayName= \"DeskVNC Support\""
            ))?
        };
        ensure!(configured, "Windows did not accept the service");
        let _ = sc(&format!(
            "description {SERVICE} \"Lets paired helpers reach this computer before anyone signs in\""
        ));
        let _ = sc(&format!(
            "failure {SERVICE} reset= 86400 actions= restart/5000/restart/5000/restart/30000"
        ));
        sc(&format!("start {SERVICE}"))?;
        Ok(())
    }
    pub fn uninstall() -> Result<()> {
        let _ = sc(&format!("stop {SERVICE}"));
        ensure!(
            sc(&format!("delete {SERVICE}"))?,
            "Windows did not remove the service"
        );
        if let Ok(target) = installed() {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let _ = std::fs::remove_file(&target);
            let _ = target.parent().map(std::fs::remove_dir);
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use imp::{install, uninstall};

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use anyhow::{Result, bail};
    pub fn enabled() -> bool {
        false
    }
    pub fn set(_: bool) -> Result<()> {
        bail!("This system has no way to start the app before sign in")
    }
}
