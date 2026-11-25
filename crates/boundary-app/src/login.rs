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
//! lock screen is out of a person's programs' sight too. On Linux a systemd
//! service starts it while the screen shows the display manager's sign in
//! screen, as the person who set it up (see `service.rs`). Either way it
//! steps aside once somebody signs in or unlocks, and the app in the tray
//! takes over the ID.
//!
//! Nobody is at the sign in screen to approve a helper, so a helper who is
//! not paired and has no password is turned away, and no helper's tools may
//! run anything: they would run as the system.
//!
//! Run as root, it reads and writes the person's folder only through
//! [`boundary_session::owned`]: the log, the lock, who may connect and the
//! machine key. It never follows a link the person put there, makes no
//! folder and no key, and hands back to the person any file root made.

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
    // launchd starts this again whenever it ends. Should it ever do so
    // behind a signed in session, end at once, before writing to the log.
    if signed_in() {
        return Ok(());
    }
    // Linux only: the service says which display, or why there is none.
    let unavailable = unavailable();
    match std::env::var("DISPLAY") {
        Ok(display) if cfg!(target_os = "linux") => {
            note(&dir, &format!("started on X display {display}"))
        }
        _ => note(&dir, "started"),
    }
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
    let mut told_no_key = false;
    loop {
        if signed_in() {
            return Ok(());
        }
        let enabled = Access::load(&access_path).is_ok_and(|a| a.enabled);
        if !enabled {
            listener = None;
            session = None;
        } else if listener.is_none() {
            // Made by the app when unattended access was switched on. This
            // copy runs as root on macOS and makes nothing in the person's
            // folder, so without one it waits for the app to make it.
            let key = match unattended::load_key(&dir.join("machine.key")) {
                Ok(key) => key,
                Err(error) => {
                    if !told_no_key {
                        note(&dir, &format!("no machine ID to listen as: {error:#}"));
                        told_no_key = true;
                    }
                    tokio::time::sleep(TICK).await;
                    continue;
                }
            };
            if let Some(reason) = unavailable.clone() {
                // Listen anyway, so a helper who connects is told why there
                // is no picture instead of waiting on a computer that never
                // answers.
                note(&dir, &format!("cannot show the sign in screen: {reason}"));
                listener = Some(unattended::listen_at_login(
                    boundary_session::HostOptions::default(),
                    key,
                    access_path.clone(),
                    move || Err(anyhow::anyhow!("{reason}")),
                ));
                continue;
            }
            let display = boundary_platform::displays()
                .ok()
                .and_then(|all| all.first().map(|d| d.id));
            if let Some(display) = display {
                let probed = tokio::task::spawn_blocking(move || probe(display))
                    .await
                    .unwrap_or_default();
                note(&dir, &probed);
                // The display is found again when a helper arrives. Its ID
                // can change while this listens: on a Mac with no monitor the
                // screen is a virtual one that is made again after somebody
                // signs out, and holding on to the first ID ended every
                // session with "The selected display is no longer
                // connected".
                listener = Some(unattended::listen_at_login(
                    boundary_session::HostOptions::default(),
                    key,
                    access_path.clone(),
                    boundary_platform::open_primary,
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
                    Notice::Ready { machine, .. } => note(&dir, &format!("listening as {machine}")),
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

/// Why the Linux service could not give this host a screen, which every
/// helper who connects is told.
#[cfg(target_os = "linux")]
fn unavailable() -> Option<String> {
    std::env::var(crate::service::UNAVAILABLE)
        .ok()
        .filter(|r| !r.is_empty())
}
#[cfg(not(target_os = "linux"))]
fn unavailable() -> Option<String> {
    None
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
pub const SUPPORTED: bool = cfg!(any(target_os = "macos", windows, target_os = "linux"));

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
    /// The launchd job that starts the host at the sign in screen.
    ///
    /// Started again whenever it ends, not only after a failure, for as
    /// long as the program exists. At boot launchd can start it before the
    /// window server lets anyone in, and it ended within two seconds with a
    /// clean exit, so a job that restarted only after a failure left the
    /// computer out of reach until somebody signed in and out. Keeping it
    /// alive on the program's path rather than always means an app moved
    /// to the Trash without switching this off leaves a job that does
    /// nothing, not one launchd tries to start every five seconds. macOS
    /// unloads a LoginWindow agent when somebody signs in, and the host
    /// steps aside before it takes the machine ID when somebody is signed
    /// in, so this cannot push the app in the tray off the relay.
    pub(super) fn launch_agent(exe: &str, home: &str) -> String {
        let escape = |s: &str| {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        };
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>AssociatedBundleIdentifiers</key><string>com.psmux.deskvnc.support</string>
<key>LimitLoadToSessionType</key><string>LoginWindow</string>
<key>ProgramArguments</key><array><string>{exe}</string><string>--login-screen</string></array>
<key>EnvironmentVariables</key><dict><key>HOME</key><string>{home}</string></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>PathState</key><dict><key>{exe}</key><true/></dict></dict>
<key>ThrottleInterval</key><integer>5</integer>
<key>ProcessType</key><string>Interactive</string>
</dict></plist>
"#,
            exe = escape(exe),
            home = escape(home)
        )
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
        let body = launch_agent(&exe.to_string_lossy(), &home);
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

#[cfg(target_os = "linux")]
mod imp {
    pub use crate::service::{enabled, set};
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
mod imp {
    use anyhow::{Result, bail};
    pub fn enabled() -> bool {
        false
    }
    pub fn set(_: bool) -> Result<()> {
        bail!("This system has no way to start the app before sign in")
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::imp::launch_agent;

    #[test]
    fn launch_agent_restarts_after_any_exit_and_lints() {
        let body = launch_agent(
            "/Applications/A & B.app/Contents/MacOS/x",
            "/Users/<someone>",
        );
        // A clean exit at boot must bring it back, not only a failure, but
        // only while the program is there to start.
        assert!(body.contains(
            "<key>KeepAlive</key><dict><key>PathState</key><dict>\
             <key>/Applications/A &amp; B.app/Contents/MacOS/x</key><true/></dict></dict>"
        ));
        assert!(!body.contains("SuccessfulExit"));
        assert!(!body.contains("<key>KeepAlive</key><true/>"));
        assert!(body.contains("<key>ThrottleInterval</key><integer>5</integer>"));
        assert!(body.contains("<key>LimitLoadToSessionType</key><string>LoginWindow</string>"));
        assert!(body.contains("A &amp; B.app"));
        assert!(body.contains("/Users/&lt;someone&gt;"));
        let path = std::env::temp_dir().join(format!("launch-agent-{}.plist", std::process::id()));
        std::fs::write(&path, &body).unwrap();
        let lint = std::process::Command::new("plutil")
            .arg("-lint")
            .arg(&path)
            .output();
        // How launchd reads it: the program's own path, unescaped, as the
        // condition that keeps it alive.
        let json = std::process::Command::new("plutil")
            .args(["-convert", "json", "-o", "-"])
            .arg(&path)
            .output();
        let _ = std::fs::remove_file(&path);
        if let Ok(lint) = lint {
            assert!(
                lint.status.success(),
                "{}",
                String::from_utf8_lossy(&lint.stdout)
            );
        }
        if let Ok(json) = json {
            let json = String::from_utf8_lossy(&json.stdout).replace("\\/", "/");
            assert!(
                json.contains(
                    r#""KeepAlive":{"PathState":{"/Applications/A & B.app/Contents/MacOS/x":true}}"#
                ),
                "{json}"
            );
        }
    }
}
