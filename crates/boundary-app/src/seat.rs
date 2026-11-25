//! Which graphical session the physical screen shows on Linux, and how to
//! open its X display.
//!
//! The service that runs before anyone signs in has no display of its own.
//! It asks logind which session is active on seat0, and finds that
//! session's X display and the file holding its key (the X authority)
//! from the processes in the session, or from the X server's command line,
//! the way `x11vnc -auth guess` does. Display managers keep that file in
//! different places: LightDM in `/var/run/lightdm/root/:0`, GDM on Xorg in
//! `/run/user/<gdm uid>/gdm/Xauthority`, SDDM in `/var/run/sddm/`.
//!
//! The parsing is plain functions over text so it is tested on any system;
//! only [`active`] reads the running system.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `key=value` lines, as `loginctl show-session` and `show-seat` print them.
pub fn properties(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

/// What kind of picture a session draws with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    X11,
    Wayland,
    /// A text console, or something logind does not name.
    Other,
}

/// One logind session, as far as the service cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    /// The account it runs as: `lightdm`, `gdm`, `sddm` for a sign in screen.
    pub user: String,
    pub uid: u32,
    /// The sign in screen itself, rather than somebody's own session.
    pub greeter: bool,
    pub kind: Kind,
    /// Such as `:0`, when logind knows it. GDM leaves it empty.
    pub display: Option<String>,
    pub vt: Option<u32>,
    pub remote: bool,
}

impl Session {
    /// From `loginctl show-session <id>` output.
    pub fn parse(text: &str) -> Option<Self> {
        let p = properties(text);
        let get = |k: &str| p.get(k).map(String::as_str).unwrap_or("");
        let id = get("Id");
        if id.is_empty() {
            return None;
        }
        Some(Self {
            id: id.to_owned(),
            user: get("Name").to_owned(),
            uid: get("User").parse().unwrap_or(u32::MAX),
            greeter: matches!(get("Class"), "greeter" | "lock-screen"),
            kind: match get("Type") {
                "x11" => Kind::X11,
                "wayland" => Kind::Wayland,
                _ => Kind::Other,
            },
            display: Some(get("Display"))
                .filter(|d| !d.is_empty())
                .map(str::to_owned),
            vt: get("VTNr").parse().ok().filter(|&n| n > 0),
            remote: get("Remote") == "yes",
        })
    }
}

/// `DISPLAY` and `XAUTHORITY` from a `/proc/<pid>/environ`, which separates
/// its entries with NUL bytes.
pub fn environ_display(environ: &[u8]) -> (Option<String>, Option<PathBuf>) {
    let mut display = None;
    let mut authority = None;
    for entry in environ.split(|&b| b == 0) {
        let entry = String::from_utf8_lossy(entry);
        if let Some(value) = entry.strip_prefix("DISPLAY=") {
            display = Some(value.to_owned()).filter(|v| !v.is_empty());
        } else if let Some(value) = entry.strip_prefix("XAUTHORITY=") {
            authority = Some(PathBuf::from(value)).filter(|v| v.is_absolute());
        }
    }
    (display, authority)
}

/// Whether a `/proc/<pid>/cgroup` puts the process in logind session `id`.
pub fn in_session(cgroup: &str, id: &str) -> bool {
    let scope = format!("/session-{id}.scope");
    cgroup
        .lines()
        .any(|line| line.trim_end().ends_with(&scope) || line.contains(&format!("{scope}/")))
}

/// An X server's display and authority file, from its command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server {
    pub display: Option<String>,
    pub vt: Option<u32>,
    pub auth: Option<PathBuf>,
}

/// Read an X server's arguments, or `None` when `argv` is not an X server.
/// LightDM runs `X :0 -seat seat0 -auth /var/run/lightdm/root/:0 ... vt7`;
/// GDM runs `Xorg vt1 -displayfd 3 -auth /run/user/120/gdm/Xauthority ...`
/// and so names no display.
pub fn x_server(argv: &[String]) -> Option<Server> {
    let program = Path::new(argv.first()?).file_name()?.to_str()?;
    if !matches!(program, "X" | "Xorg" | "Xorg.bin" | "Xorg.wrap") {
        return None;
    }
    let mut server = Server {
        display: None,
        vt: None,
        auth: None,
    };
    let mut args = argv.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == "-auth" {
            server.auth = args.next().map(PathBuf::from);
        } else if arg.starts_with(':') && arg[1..].chars().all(|c| c.is_ascii_digit() || c == '.') {
            server.display = Some(arg.clone());
        } else if let Some(n) = arg.strip_prefix("vt").and_then(|n| n.parse().ok()) {
            server.vt = Some(n);
        }
    }
    Some(server)
}

/// The X server behind `session`: the one on its display, or failing that
/// the one on its virtual terminal.
pub fn server_for<'a>(servers: &'a [Server], session: &Session) -> Option<&'a Server> {
    servers
        .iter()
        .find(|s| s.display.is_some() && s.display == session.display)
        .or_else(|| {
            servers
                .iter()
                .find(|s| s.vt.is_some() && s.vt == session.vt)
        })
}

/// Where display managers keep a sign in screen's authority when nothing
/// else said, most likely first.
pub fn known_authorities(display: &str, uid: u32) -> Vec<PathBuf> {
    vec![
        PathBuf::from(format!("/var/run/lightdm/root/{display}")),
        PathBuf::from(format!("/run/lightdm/root/{display}")),
        PathBuf::from(format!("/run/user/{uid}/gdm/Xauthority")),
        PathBuf::from("/var/lib/lightdm/.Xauthority"),
    ]
}

/// What the service should do about the session on the screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Share this X display, opened with this authority.
    Share {
        session: String,
        display: String,
        authority: PathBuf,
    },
    /// The sign in screen runs on Wayland, which shares itself with no
    /// program. Only root can read it, from the display hardware.
    Wayland { session: String },
    /// The sign in screen is there but cannot be shown: say why to anyone
    /// who connects.
    Unavailable { session: String, reason: String },
    /// Somebody is signed in. Their own DeskVNC Support answers, as on
    /// macOS and Windows.
    StepAside { session: String, user: String },
    /// Nothing to share: no session on the screen, or a text console.
    Idle,
}

/// What a helper is told, and what goes in the log, when the sign in screen
/// runs on Wayland.
pub const WAYLAND_GREETER: &str = "The sign in screen on this computer runs on Wayland, which DeskVNC Support cannot show before somebody signs in. To reach it, the computer's administrator can switch the sign in screen to Xorg: set WaylandEnable=false in the [daemon] section of /etc/gdm3/custom.conf (/etc/gdm/custom.conf on some systems) and restart. Once somebody signs in, their own DeskVNC Support answers";

/// Whether GDM's `custom.conf` leaves its sign in screen on Wayland, which
/// it does unless `WaylandEnable=false` is set.
pub fn gdm_on_wayland(custom_conf: &str) -> bool {
    !custom_conf.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#')
            && line
                .split_once('=')
                .is_some_and(|(k, v)| k.trim() == "WaylandEnable" && v.trim() == "false")
    })
}

/// What the person who switches the service on is told when their display
/// manager is GDM with its sign in screen on Wayland.
pub const WAYLAND_GREETER_SETUP: &str = "Set up, but this computer's sign in screen runs on Wayland, which DeskVNC Support cannot show here. Helpers who connect before anyone signs in are told so. To fix it, set WaylandEnable=false in /etc/gdm3/custom.conf and restart";
/// The same, when the sign in screen is read from the display hardware
/// instead, which most graphics drivers allow.
pub const WAYLAND_GREETER_HARDWARE: &str = "Set up. This computer's sign in screen runs on Wayland, so it is read straight from the graphics card. If a helper is told it cannot be shown, set WaylandEnable=false in /etc/gdm3/custom.conf and restart";

/// What a helper is told when the sign in screen's X display cannot be
/// opened.
pub fn no_authority(display: &str) -> String {
    format!(
        "DeskVNC Support found the sign in screen on X display {display} but not the key to open it. See sign-in-screen.log and the deskvnc-support-login service's journal on that computer"
    )
}

/// Decide from the active session, with `display` and `authority` as found
/// for it (both `None` when nothing was found).
pub fn plan(
    session: Option<&Session>,
    display: Option<String>,
    authority: Option<PathBuf>,
) -> Plan {
    let Some(session) = session else {
        return Plan::Idle;
    };
    if session.remote {
        return Plan::Idle;
    }
    if !session.greeter {
        return match session.kind {
            Kind::Other => Plan::Idle,
            _ => Plan::StepAside {
                session: session.id.clone(),
                user: session.user.clone(),
            },
        };
    }
    match session.kind {
        Kind::Wayland => Plan::Wayland {
            session: session.id.clone(),
        },
        Kind::X11 => match (display.or_else(|| session.display.clone()), authority) {
            (Some(display), Some(authority)) => Plan::Share {
                session: session.id.clone(),
                display,
                authority,
            },
            (Some(display), None) => Plan::Unavailable {
                session: session.id.clone(),
                reason: no_authority(&display),
            },
            // X11 with no display yet: the server is still starting.
            (None, _) => Plan::Idle,
        },
        Kind::Other => Plan::Idle,
    }
}

/// The session on seat0's screen now, read from logind and `/proc`.
#[cfg(target_os = "linux")]
pub fn active() -> Plan {
    let loginctl = |args: &[&str]| {
        std::process::Command::new("loginctl")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let Some(id) = loginctl(&["show-seat", "seat0", "-p", "ActiveSession"])
        .and_then(|t| properties(&t).remove("ActiveSession"))
        .filter(|id| !id.is_empty())
    else {
        return Plan::Idle;
    };
    let session = loginctl(&[
        "show-session",
        &id,
        "-p",
        "Id",
        "-p",
        "Name",
        "-p",
        "User",
        "-p",
        "Class",
        "-p",
        "Type",
        "-p",
        "Display",
        "-p",
        "VTNr",
        "-p",
        "Remote",
    ])
    .and_then(|t| Session::parse(&t));
    let (display, authority) = match &session {
        Some(s) if s.greeter && s.kind == Kind::X11 => find_display(s),
        _ => (None, None),
    };
    plan(session.as_ref(), display, authority)
}

/// The display and authority of an X11 session: from its own processes'
/// environment first, then from the X server's command line, then from
/// where display managers usually keep it.
#[cfg(target_os = "linux")]
fn find_display(session: &Session) -> (Option<String>, Option<PathBuf>) {
    let readable = |p: &PathBuf| std::fs::metadata(p).is_ok_and(|m| m.is_file());
    let mut display = session.display.clone();
    let mut authority = None;
    let mut servers = Vec::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let pid = entry.path();
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
        {
            continue;
        }
        if let Ok(cmdline) = std::fs::read(pid.join("cmdline")) {
            let argv: Vec<String> = cmdline
                .split(|&b| b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
            if let Some(server) = x_server(&argv) {
                servers.push(server);
                continue;
            }
        }
        if authority.is_some() {
            continue;
        }
        let ours =
            std::fs::read_to_string(pid.join("cgroup")).is_ok_and(|c| in_session(&c, &session.id));
        if !ours {
            continue;
        }
        if let Ok(environ) = std::fs::read(pid.join("environ")) {
            let (d, a) = environ_display(&environ);
            if d.is_some() && (display.is_none() || d == display) {
                display = display.or(d);
                authority = a.filter(readable);
            }
        }
    }
    if authority.is_none()
        && let Some(server) = server_for(&servers, session)
    {
        display = display.or(server.display.clone());
        authority = server.auth.clone().filter(readable);
    }
    if authority.is_none()
        && let Some(display) = &display
    {
        authority = known_authorities(display, session.uid)
            .into_iter()
            .find(readable);
    }
    (display, authority)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    const LIGHTDM_GREETER: &str =
        "Id=c2\nName=lightdm\nUser=118\nClass=greeter\nType=x11\nDisplay=:0\nVTNr=7\nRemote=no\n";
    const GDM_XORG_GREETER: &str =
        "Id=c1\nName=gdm\nUser=120\nClass=greeter\nType=x11\nDisplay=\nVTNr=1\nRemote=no\n";
    const GDM_WAYLAND_GREETER: &str =
        "Id=c1\nName=gdm\nUser=120\nClass=greeter\nType=wayland\nDisplay=\nVTNr=1\nRemote=no\n";
    const USER_SESSION: &str =
        "Id=3\nName=someone\nUser=1000\nClass=user\nType=x11\nDisplay=:0\nVTNr=7\nRemote=no\n";

    #[test]
    fn reads_loginctl_sessions() {
        let s = Session::parse(LIGHTDM_GREETER).unwrap();
        assert_eq!(s.id, "c2");
        assert_eq!(s.user, "lightdm");
        assert_eq!(s.uid, 118);
        assert!(s.greeter);
        assert_eq!(s.kind, Kind::X11);
        assert_eq!(s.display.as_deref(), Some(":0"));
        assert_eq!(s.vt, Some(7));
        let gdm = Session::parse(GDM_XORG_GREETER).unwrap();
        assert_eq!(gdm.display, None);
        assert_eq!(gdm.vt, Some(1));
        assert!(!Session::parse(USER_SESSION).unwrap().greeter);
        assert_eq!(Session::parse("ActiveSession=\n"), None);
        assert_eq!(
            properties("ActiveSession=c1\n")
                .get("ActiveSession")
                .map(String::as_str),
            Some("c1")
        );
    }

    #[test]
    fn reads_display_and_authority_from_a_process_environment() {
        let environ =
            b"LANG=C\0DISPLAY=:0\0XAUTHORITY=/run/user/120/gdm/Xauthority\0HOME=/var/lib/gdm3\0";
        assert_eq!(
            environ_display(environ),
            (
                Some(":0".into()),
                Some(PathBuf::from("/run/user/120/gdm/Xauthority"))
            )
        );
        // A relative authority is ignored rather than read from wherever
        // the service happens to run.
        assert_eq!(
            environ_display(b"DISPLAY=:1\0XAUTHORITY=.Xauthority\0"),
            (Some(":1".into()), None)
        );
        assert_eq!(environ_display(b"PATH=/bin\0"), (None, None));
    }

    #[test]
    fn tells_which_session_a_process_is_in() {
        let v2 = "0::/user.slice/user-120.slice/session-c1.scope\n";
        assert!(in_session(v2, "c1"));
        assert!(!in_session(v2, "c11"));
        assert!(!in_session(v2, "1"));
        let v1 = "12:pids:/user.slice/user-1000.slice/session-3.scope\n1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n";
        assert!(in_session(v1, "3"));
        assert!(!in_session("0::/system.slice/lightdm.service\n", "c2"));
    }

    #[test]
    fn reads_x_servers_from_their_command_lines() {
        let lightdm = x_server(&argv(
            "/usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch",
        ))
        .unwrap();
        assert_eq!(lightdm.display.as_deref(), Some(":0"));
        assert_eq!(lightdm.vt, Some(7));
        assert_eq!(
            lightdm.auth,
            Some(PathBuf::from("/var/run/lightdm/root/:0"))
        );
        let gdm = x_server(&argv(
            "/usr/lib/xorg/Xorg vt1 -displayfd 3 -auth /run/user/120/gdm/Xauthority -nolisten tcp -background none -noreset -keeptty -novtswitch -verbose 3",
        ))
        .unwrap();
        assert_eq!(gdm.display, None);
        assert_eq!(gdm.vt, Some(1));
        let sddm = x_server(&argv(
            "/usr/bin/X -nolisten tcp -auth /var/run/sddm/{0b3c} -background none -noreset -displayfd 17 -seat seat0 vt2",
        ))
        .unwrap();
        assert_eq!(sddm.auth, Some(PathBuf::from("/var/run/sddm/{0b3c}")));
        // A Wayland sign in screen's Xwayland shows none of it.
        assert_eq!(
            x_server(&argv(
                "/usr/bin/Xwayland :1024 -rootless -noreset -accessx -core -auth /run/user/110/.mutter-Xwaylandauth.9XG7Y3 -listenfd 4"
            )),
            None
        );
        assert_eq!(x_server(&argv("/usr/bin/bash -c X")), None);
        // GDM's greeter has no display in logind, so its server is found by
        // its virtual terminal.
        let servers = vec![lightdm.clone(), gdm.clone()];
        let session = Session::parse(GDM_XORG_GREETER).unwrap();
        assert_eq!(server_for(&servers, &session), Some(&gdm));
        let session = Session::parse(LIGHTDM_GREETER).unwrap();
        assert_eq!(server_for(&servers, &session), Some(&lightdm));
    }

    #[test]
    fn shares_only_the_sign_in_screen() {
        let lightdm = Session::parse(LIGHTDM_GREETER).unwrap();
        assert_eq!(
            plan(
                Some(&lightdm),
                None,
                Some("/var/run/lightdm/root/:0".into())
            ),
            Plan::Share {
                session: "c2".into(),
                display: ":0".into(),
                authority: "/var/run/lightdm/root/:0".into()
            }
        );
        let gdm = Session::parse(GDM_XORG_GREETER).unwrap();
        assert_eq!(
            plan(
                Some(&gdm),
                Some(":0".into()),
                Some("/run/user/120/gdm/Xauthority".into())
            ),
            Plan::Share {
                session: "c1".into(),
                display: ":0".into(),
                authority: "/run/user/120/gdm/Xauthority".into()
            }
        );
        // The X server is not up yet: wait rather than fail.
        assert_eq!(plan(Some(&gdm), None, None), Plan::Idle);
        assert!(matches!(
            plan(Some(&lightdm), None, None),
            Plan::Unavailable { reason, .. } if reason.contains(":0")
        ));
        let wayland = Session::parse(GDM_WAYLAND_GREETER).unwrap();
        assert_eq!(
            plan(Some(&wayland), None, None),
            Plan::Wayland {
                session: "c1".into()
            }
        );
        let user = Session::parse(USER_SESSION).unwrap();
        assert_eq!(
            plan(Some(&user), Some(":0".into()), Some("/x".into())),
            Plan::StepAside {
                session: "3".into(),
                user: "someone".into()
            }
        );
        let mut remote = lightdm.clone();
        remote.remote = true;
        assert_eq!(plan(Some(&remote), None, None), Plan::Idle);
        assert_eq!(plan(None, None, None), Plan::Idle);
        let tty = Session::parse("Id=5\nName=x\nUser=1000\nClass=user\nType=tty\n").unwrap();
        assert_eq!(plan(Some(&tty), None, None), Plan::Idle);
    }

    #[test]
    fn tells_whether_gdm_keeps_its_sign_in_screen_on_wayland() {
        let shipped = "[daemon]\n# Uncomment the line below to force the login screen to use Xorg\n#WaylandEnable=false\n";
        assert!(gdm_on_wayland(shipped));
        assert!(!gdm_on_wayland(
            &shipped.replace("#WaylandEnable", "WaylandEnable")
        ));
        assert!(!gdm_on_wayland("[daemon]\nWaylandEnable = false\n"));
        assert!(gdm_on_wayland("[daemon]\nWaylandEnable=true\n"));
        assert!(gdm_on_wayland(""));
    }

    #[test]
    fn knows_where_display_managers_keep_the_key() {
        let paths = known_authorities(":0", 120);
        assert!(paths.contains(&PathBuf::from("/var/run/lightdm/root/:0")));
        assert!(paths.contains(&PathBuf::from("/run/user/120/gdm/Xauthority")));
    }
}
