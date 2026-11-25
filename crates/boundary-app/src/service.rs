//! The Linux system service that runs the app at the sign in screen.
//!
//! The app the person sees starts when they sign in, so after a restart, or
//! once they sign out, nobody could reach the computer until somebody signed
//! in at it. This is the Linux side of "Also before anyone signs in". A
//! systemd unit runs `deskvnc-support --service` as root from a copy only
//! root can change. It asks logind which session the screen shows and, while
//! that is the display manager's sign in screen on Xorg, starts the same
//! `--login-screen` host macOS and Windows use, with the same rules: only
//! paired helpers and the unattended password get in, no tools, never the
//! clipboard.
//!
//! The host does not run as root. It runs as the person who set this up,
//! with a copy of the sign in screen's X authority that only they can read,
//! so it reads and writes their own data folder as them (the machine ID,
//! who may connect, `sign-in-screen.log`) and a root process never follows
//! a link that person could plant there. The network and the screen are
//! handled by an ordinary account.
//!
//! Once somebody signs in the host stops, and that person's own DeskVNC
//! Support takes the machine ID over, as on macOS and Windows. When their
//! session is locked or switched away the screen shows the sign in screen
//! again, in a session of its own, and the host comes back.

use std::path::{Path, PathBuf};

/// The unit's name, as `systemctl` and `journalctl -u` take it.
pub const UNIT_NAME: &str = "deskvnc-support-login.service";
/// Where the unit is written.
pub const UNIT: &str = "/etc/systemd/system/deskvnc-support-login.service";
/// The copy the service runs. Under /usr/local, which only root can write:
/// a root service running a file the person could replace would hand them
/// root.
pub const PROGRAM: &str = "/usr/local/lib/deskvnc-support/deskvnc-support";
/// Where the copies of the sign in screen's X authority go, one per
/// session, readable only by the person the host runs as.
const RUN_DIR: &str = "/run/deskvnc-support";
/// Set for a host that cannot show the screen, with the reason a helper is
/// given.
pub const UNAVAILABLE: &str = "DESKVNC_SIGN_IN_SCREEN_UNAVAILABLE";
/// Set for a host whose screen and input the service provides from the
/// display hardware, with the socket to reach it on.
pub const BROKERED: &str = "DESKVNC_SIGN_IN_SCREEN_BROKER";

/// The systemd unit, running `program` for the account `uid` whose data
/// folder is `data`.
pub fn unit(program: &str, uid: u32, data: &Path) -> String {
    // systemd reads `%` as a specifier and splits words on spaces.
    let quote = |s: &str| {
        format!(
            "\"{}\"",
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('%', "%%")
        )
    };
    format!(
        "[Unit]\n\
         Description=DeskVNC Support at the sign in screen\n\
         Documentation=https://github.com/psmux/DeskVNC/blob/main/docs/INSTALL.md\n\
         After=systemd-user-sessions.service systemd-logind.service display-manager.service network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={} --service {uid} {}\n\
         Restart=always\n\
         RestartSec=5\n\
         KillMode=control-group\n\
         \n\
         [Install]\n\
         WantedBy=graphical.target\n",
        quote(program),
        quote(&data.to_string_lossy()),
    )
}

/// The arguments after `--service`: the account and its data folder.
pub fn service_args(args: &[String]) -> Option<(u32, PathBuf)> {
    let at = args.iter().position(|a| a == "--service")?;
    let uid = args.get(at + 1)?.parse().ok()?;
    let data = PathBuf::from(args.get(at + 2)?);
    data.is_absolute().then_some((uid, data))
}

/// One line of the service's log, which systemd keeps in the journal.
fn say(line: &str) {
    eprintln!("{line}");
}

/// What the service last did, so the log says each change once.
fn describe(plan: &crate::seat::Plan) -> String {
    use crate::seat::Plan;
    match plan {
        Plan::Share {
            session, display, ..
        } => format!(
            "Sign in screen on X display {display} (session {session}): sharing it with paired helpers"
        ),
        Plan::Wayland { session } => format!(
            "Sign in screen on Wayland (session {session}): sharing it with paired helpers, read from the display hardware"
        ),
        Plan::Unavailable { session, reason } => {
            format!("Sign in screen (session {session}) cannot be shared: {reason}")
        }
        Plan::StepAside { session, user } => format!(
            "{user} is signed in (session {session}): their own DeskVNC Support answers, so this steps aside"
        ),
        Plan::Idle => "No sign in screen on the screen now".into(),
    }
}

/// (uid, gid, name, home) from one `/etc/passwd` line, as `getent passwd`
/// prints it.
pub fn passwd_entry(line: &str) -> Option<(u32, u32, String, PathBuf)> {
    let fields: Vec<&str> = line.trim_end().split(':').collect();
    if fields.len() < 7 || fields[0].is_empty() {
        return None;
    }
    Some((
        fields[2].parse().ok()?,
        fields[3].parse().ok()?,
        fields[0].to_owned(),
        PathBuf::from(fields[5]),
    ))
}

#[cfg(target_os = "linux")]
pub use imp::*;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::seat::{self, Plan};
    use anyhow::{Context, Result, bail, ensure};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    /// An account, from the system's user database.
    struct Account {
        uid: u32,
        gid: u32,
        name: String,
        home: PathBuf,
    }

    fn account(uid: u32) -> Option<Account> {
        // getent asks NSS, so accounts from LDAP or systemd-homed count too.
        let out = Command::new("getent")
            .args(["passwd", &uid.to_string()])
            .output()
            .ok()?;
        let line = String::from_utf8_lossy(&out.stdout);
        let entry = passwd_entry(line.lines().next()?)?;
        (entry.0 == uid).then_some(Account {
            uid,
            gid: entry.1,
            name: entry.2,
            home: entry.3,
        })
    }

    /// The effective account of this process: whoever owns `/proc/self`.
    fn euid() -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").ok().map(|m| m.uid())
    }

    fn root() -> bool {
        euid() == Some(0)
    }

    /// A warning for the person who just switched the service on, when the
    /// display manager is GDM with its sign in screen on Wayland.
    pub fn greeter_warning() -> Option<&'static str> {
        let manager = std::fs::read_link("/etc/systemd/system/display-manager.service").ok()?;
        let name = manager.file_name()?.to_string_lossy().into_owned();
        if !name.starts_with("gdm") {
            return None;
        }
        let conf = ["/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"]
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default();
        seat::gdm_on_wayland(&conf).then_some(seat::WAYLAND_GREETER_SETUP)
    }

    /// Whether the service is set up.
    pub fn enabled() -> bool {
        Path::new(UNIT).exists()
    }

    /// Set the service up for the person running this, or take it away,
    /// asking for an administrator through polkit.
    pub fn set(on: bool) -> Result<()> {
        let exe = std::env::current_exe().context("This app cannot find itself")?;
        let mut args = vec![exe.to_string_lossy().into_owned()];
        if on {
            ensure!(
                std::env::var_os("APPIMAGE").is_none(),
                "Use the DeskVNC Support tarball to set this up, not an AppImage"
            );
            let uid = euid().context("Cannot tell which account this is")?;
            ensure!(
                uid != 0,
                "Switch this on from the account whose DeskVNC Support helpers should reach, not as root"
            );
            let data = data_home()?;
            args.extend(["--install-service".into(), uid.to_string(), data]);
        } else {
            args.push("--uninstall-service".into());
        }
        if root() {
            return run_elevated(&args[1..]);
        }
        let pkexec = ["/usr/bin/pkexec", "/bin/pkexec"]
            .into_iter()
            .find(|p| Path::new(p).exists());
        let Some(pkexec) = pkexec else {
            bail!(
                "This system has no pkexec to ask for an administrator. In a terminal, run: sudo {}",
                args.join(" ")
            );
        };
        let status = Command::new(pkexec).args(&args).status()?;
        match status.code() {
            Some(0) => Ok(()),
            // pkexec: the dialog was dismissed, or the password refused.
            Some(126) | Some(127) => bail!("Cancelled"),
            _ => bail!(
                "Linux did not accept it. The service's journal may say why: journalctl -u {UNIT_NAME}"
            ),
        }
    }

    /// The person's data folder's parent, as `data_dir` reads it.
    fn data_home() -> Result<String> {
        let dir = boundary_provision::platform::data_dir()?;
        Ok(dir
            .parent()
            .context("No data folder")?
            .to_string_lossy()
            .into_owned())
    }

    /// `--install-service [uid data]` or `--uninstall-service`, as root.
    pub fn run_elevated(args: &[String]) -> Result<()> {
        match args.first().map(String::as_str) {
            Some("--install-service") => install(args.get(1), args.get(2)),
            Some("--uninstall-service") => uninstall(),
            _ => bail!("Nothing to do"),
        }
    }

    fn systemctl(args: &[&str]) -> Result<()> {
        let status = Command::new("systemctl").args(args).status()?;
        ensure!(status.success(), "systemctl {} failed", args.join(" "));
        Ok(())
    }

    /// Copy this program where only root can change it, write the unit and
    /// start it. The account is given, or is whoever ran sudo or pkexec.
    pub fn install(uid: Option<&String>, data: Option<&String>) -> Result<()> {
        ensure!(
            root(),
            "Setting up the service needs an administrator: run sudo {} --install-service",
            std::env::current_exe()?.display()
        );
        let uid: u32 = match uid {
            Some(uid) => uid.parse().context("The account must be a number")?,
            None => std::env::var("PKEXEC_UID")
                .or_else(|_| std::env::var("SUDO_UID"))
                .context("Run this with sudo from the account whose helpers should reach the sign in screen")?
                .parse()?,
        };
        ensure!(
            uid != 0,
            "Run this with sudo from the account whose helpers should reach the sign in screen, not from root itself"
        );
        let owner = account(uid).context("No such account")?;
        let data = match data {
            Some(data) => PathBuf::from(data),
            None => owner.home.join(".local/share"),
        };
        ensure!(data.is_absolute(), "The data folder must be a full path");
        let source = std::env::current_exe()?;
        let target = Path::new(PROGRAM);
        let folder = target.parent().context("No folder")?;
        std::fs::create_dir_all(folder)?;
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o755))?;
        if source.canonicalize().ok() != target.canonicalize().ok() {
            // Written beside it and renamed over it, so a copy that is
            // running keeps running and the unit never starts half a file.
            let partial = folder.join(".deskvnc-support.partial");
            let _ = std::fs::remove_file(&partial);
            std::fs::copy(&source, &partial).context("Cannot copy the program")?;
            std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o755))?;
            std::os::unix::fs::chown(&partial, Some(0), Some(0))?;
            std::fs::rename(&partial, target)?;
        }
        std::fs::write(UNIT, unit(PROGRAM, uid, &data))?;
        std::fs::set_permissions(UNIT, std::fs::Permissions::from_mode(0o644))?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", UNIT_NAME])?;
        systemctl(&["restart", UNIT_NAME])?;
        println!(
            "DeskVNC Support now runs at the sign in screen for {}'s paired helpers.",
            owner.name
        );
        println!("Its log: journalctl -u {UNIT_NAME}");
        if let Some(warning) = greeter_warning() {
            println!("{warning}.");
        }
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        ensure!(
            root(),
            "Removing the service needs an administrator: run sudo {} --uninstall-service",
            std::env::current_exe()?.display()
        );
        let _ = systemctl(&["disable", "--now", UNIT_NAME]);
        let _ = std::fs::remove_file(UNIT);
        let _ = systemctl(&["daemon-reload"]);
        let _ = std::fs::remove_file(PROGRAM);
        let _ = Path::new(PROGRAM).parent().map(std::fs::remove_dir);
        let _ = std::fs::remove_dir_all(RUN_DIR);
        println!("DeskVNC Support no longer runs at the sign in screen.");
        Ok(())
    }

    /// A copy of the sign in screen's X authority that only `owner` can
    /// read, in a folder only root can write.
    fn authority_for(owner: &Account, session: &str, source: &Path) -> Result<PathBuf> {
        let dir = Path::new(RUN_DIR);
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        let path = dir.join(format!("{session}.xauth"));
        let _ = std::fs::remove_file(&path);
        let key =
            std::fs::read(source).with_context(|| format!("Cannot read {}", source.display()))?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        std::io::Write::write_all(&mut file, &key)?;
        std::os::unix::fs::fchown(&file, Some(owner.uid), Some(owner.gid))?;
        Ok(path)
    }

    fn spawn(owner: &Account, data: &Path, plan: &Plan, broker: Option<&Path>) -> Result<Child> {
        let exe = std::env::current_exe()?;
        let mut command = Command::new(exe);
        command
            .arg("--login-screen")
            .env_clear()
            .env("HOME", &owner.home)
            .env("USER", &owner.name)
            .env("LOGNAME", &owner.name)
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("XDG_DATA_HOME", data)
            .env("LANG", "C.UTF-8")
            .current_dir("/")
            .uid(owner.uid)
            .gid(owner.gid);
        match plan {
            Plan::Share {
                session,
                display,
                authority,
            } => {
                let copy = authority_for(owner, session, authority)?;
                command
                    .env("DISPLAY", display)
                    .env("XAUTHORITY", copy)
                    .env("XDG_SESSION_TYPE", "x11");
            }
            Plan::Unavailable { reason, .. } => {
                command.env(UNAVAILABLE, reason);
            }
            Plan::Wayland { .. } => {
                let socket = broker.context("No socket for the Wayland sign in screen")?;
                command.env(BROKERED, socket);
            }
            _ => bail!("Nothing to share"),
        }
        Ok(command.spawn()?)
    }

    /// A socket in the root owned folder that only `owner` may open, served
    /// by a thread that reads the screen and makes input as root until
    /// `stop` is set.
    fn broker(
        owner: &Account,
        session: &str,
        stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<PathBuf> {
        let dir = Path::new(RUN_DIR);
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        let path = dir.join(format!("{session}.sock"));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::chown(&path, Some(owner.uid), Some(owner.gid))?;
        let stop = stop.clone();
        std::thread::spawn(move || boundary_platform::kms_serve(listener, stop));
        Ok(path)
    }

    /// A Wayland sign in screen is shared from the display hardware when
    /// that can be read here, and otherwise explained.
    fn resolve(plan: Plan) -> Plan {
        match plan {
            Plan::Wayland { session } => match boundary_platform::kms_probe() {
                Ok(_) => Plan::Wayland { session },
                Err(error) => Plan::Unavailable {
                    session,
                    reason: format!("{} ({error:#})", seat::WAYLAND_GREETER),
                },
            },
            other => other,
        }
    }

    /// Ask the host to stop, and make sure it has.
    fn stop(mut child: Child) {
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The service itself: follow the session on the screen and keep the
    /// host running while that is the sign in screen.
    pub fn watch(uid: u32, data: &Path) -> Result<()> {
        ensure!(root(), "The service runs as root");
        let owner = account(uid).with_context(|| format!("No account with ID {uid}"))?;
        say(&format!(
            "Started for {}'s paired helpers, with their data in {}",
            owner.name,
            data.display()
        ));
        let mut current = Plan::Idle;
        let mut child: Option<Child> = None;
        // Stops the thread serving the current Wayland sign in screen.
        let mut halt = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut started = Instant::now() - Duration::from_secs(60);
        loop {
            let found = seat::active();
            // Probing the display hardware takes a moment, so only when
            // the session changes.
            let wanted = match (&found, &current) {
                (Plan::Wayland { session }, Plan::Wayland { session: now })
                | (Plan::Wayland { session }, Plan::Unavailable { session: now, .. })
                    if session == now =>
                {
                    current.clone()
                }
                _ => resolve(found),
            };
            let running = child
                .as_mut()
                .is_some_and(|c| matches!(c.try_wait(), Ok(None)));
            if wanted != current {
                say(&describe(&wanted));
            }
            let share = matches!(
                wanted,
                Plan::Share { .. } | Plan::Unavailable { .. } | Plan::Wayland { .. }
            );
            // A host that ended on its own is started again, but not more
            // than every five seconds.
            let restart = share && !running && started.elapsed() > Duration::from_secs(5);
            if wanted != current || restart || (!share && child.is_some()) {
                if let Some(old) = child.take() {
                    stop(old);
                }
                halt.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = std::fs::remove_dir_all(RUN_DIR);
                if share {
                    started = Instant::now();
                    halt = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let socket = match &wanted {
                        Plan::Wayland { session } => match broker(&owner, session, &halt) {
                            Ok(path) => Some(path),
                            Err(error) => {
                                say(&format!(
                                    "Could not open the sign in screen's socket: {error:#}"
                                ));
                                None
                            }
                        },
                        _ => None,
                    };
                    match spawn(&owner, data, &wanted, socket.as_deref()) {
                        Ok(c) => child = Some(c),
                        Err(error) => say(&format!("Could not start the host: {error:#}")),
                    }
                }
                current = wanted;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_runs_the_root_copy_for_one_account() {
        let body = unit(PROGRAM, 1000, Path::new("/home/some one/.local/share"));
        assert!(body.contains(
            "ExecStart=\"/usr/local/lib/deskvnc-support/deskvnc-support\" --service 1000 \"/home/some one/.local/share\"\n"
        ));
        assert!(body.contains("Restart=always\n"));
        assert!(body.contains("WantedBy=graphical.target\n"));
        assert!(body.contains("After=") && body.contains("display-manager.service"));
    }

    #[test]
    fn reads_accounts_as_getent_prints_them() {
        assert_eq!(
            passwd_entry("someone:x:1000:1000:Some One,,,:/home/someone:/bin/bash\n"),
            Some((1000, 1000, "someone".into(), PathBuf::from("/home/someone")))
        );
        assert_eq!(passwd_entry("broken:x:abc:1:::"), None);
        assert_eq!(passwd_entry(""), None);
    }

    #[test]
    fn reads_the_service_arguments() {
        let args = |s: &str| s.split(' ').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            service_args(&args("x --service 1000 /home/a/.local/share")),
            Some((1000, PathBuf::from("/home/a/.local/share")))
        );
        assert_eq!(service_args(&args("x --service 1000 relative")), None);
        assert_eq!(service_args(&args("x --service")), None);
        assert_eq!(service_args(&args("x --service me /a")), None);
    }
}
