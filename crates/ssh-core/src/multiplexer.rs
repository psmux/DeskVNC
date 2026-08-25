//! Finding, and reattaching to, a persistent session on the far side.
//!
//! This is the module that decides whether a reconnect gives the user their
//! work back or an empty prompt, so it is worth being explicit about what it
//! is doing and why.
//!
//! ## Why a multiplexer at all
//!
//! An SSH connection owns the remote PTY. When the link dies the PTY is
//! destroyed, `SIGHUP` goes to every process under it, and the shell and
//! everything it was running die with the socket. Reconnecting automatically
//! does not change that: it just gets the user to a fresh, empty prompt
//! faster. The only thing that actually preserves work is moving the shell's
//! lifetime off the connection and onto the remote machine, which is what
//! tmux, psmux, screen and zellij all do.
//!
//! ## Why detection rather than configuration
//!
//! Requiring the user to declare "this host runs tmux" gets it wrong in both
//! directions: a host that has it gets a plain shell because nobody ticked
//! the box, and a host that does not gets a failed connect. So the default is
//! [`MultiplexerKind::Auto`], which asks the far side what it actually has
//! and takes the best answer. A machine with nothing installed still gets a
//! working terminal, it just gets one without persistence, and it is told so
//! once rather than discovering it after losing something.
//!
//! ## Why the probe is written twice
//!
//! A remote host is not necessarily POSIX. Windows with OpenSSH Server is a
//! first-class target here, and its default shell may be `cmd.exe` or
//! PowerShell, where `command -v` is not a builtin, `2>/dev/null` is not
//! redirection, and `if ...; then` is a syntax error. A POSIX-only probe does
//! not fail loudly there, it fails *silently*: the shell prints an error to
//! stderr, our parser sees nothing it recognises, and the session quietly
//! falls back to a plain shell on exactly the machine the user most wanted
//! persistence on. So there are two probe dialects and the POSIX one is tried
//! first, because the overwhelming majority of hosts answer it.

use crate::error::{Error, Result};

/// Which multiplexer to attach to on the far side.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MultiplexerKind {
    /// Ask the far side what it has and use the best of it, falling back to
    /// a plain login shell when it has nothing. The default, and the only
    /// setting that is right on a mixed fleet.
    #[default]
    Auto,
    /// A plain login shell. Honest about the cost: a drop loses the session.
    None,
    /// psmux, the tmux-compatible multiplexer that runs natively on Windows
    /// (<https://github.com/psmux/psmux>). Speaks tmux's command language, so
    /// everything below treats it as tmux with a different binary name.
    Psmux,
    Tmux,
    Screen,
    Zellij,
    /// A command supplied by the user. `{session}` is substituted; nothing
    /// else is interpreted.
    Custom,
}

impl MultiplexerKind {
    /// The order [`MultiplexerKind::Auto`] tries things in.
    ///
    /// psmux before tmux deliberately. On Windows the two can both be present
    /// (psmux installs a tmux-compatible `tmux` shim), and where a machine has
    /// a real psmux we should name it as psmux: the user picked it, the UI
    /// should say so, and a log that claims "tmux" on a Windows box sends the
    /// next person looking for the wrong thing. On Linux psmux is simply
    /// absent and tmux wins on the next probe.
    ///
    /// screen last of the real multiplexers: it is the most likely to be
    /// installed as a vestige nobody uses, so preferring it over tmux would
    /// regularly pick the one the user does not want.
    pub const AUTO_ORDER: &'static [MultiplexerKind] = &[
        MultiplexerKind::Psmux,
        MultiplexerKind::Tmux,
        MultiplexerKind::Zellij,
        MultiplexerKind::Screen,
    ];

    /// The binary this kind needs on the remote. `None` for the kinds that
    /// need nothing in particular.
    pub fn binary(self) -> Option<&'static str> {
        Some(match self {
            MultiplexerKind::Psmux => "psmux",
            MultiplexerKind::Tmux => "tmux",
            MultiplexerKind::Screen => "screen",
            MultiplexerKind::Zellij => "zellij",
            MultiplexerKind::Auto | MultiplexerKind::None | MultiplexerKind::Custom => return None,
        })
    }

    /// Does this kind speak tmux's command language?
    ///
    /// psmux is a tmux-compatible reimplementation, so every `new-session`,
    /// `has-session` and `kill-session` below is shared. Keeping this as a
    /// predicate rather than duplicating the command strings means a fix to
    /// the tmux invocation cannot be applied to one and forgotten on the
    /// other.
    pub fn is_tmux_compatible(self) -> bool {
        matches!(self, MultiplexerKind::Tmux | MultiplexerKind::Psmux)
    }

    /// The name to show a human. Never a command, never a path.
    pub fn label(self) -> &'static str {
        match self {
            MultiplexerKind::Auto => "auto",
            MultiplexerKind::None => "plain shell",
            MultiplexerKind::Psmux => "psmux",
            MultiplexerKind::Tmux => "tmux",
            MultiplexerKind::Screen => "screen",
            MultiplexerKind::Zellij => "zellij",
            MultiplexerKind::Custom => "custom",
        }
    }
}

/// Which shell dialect the far side answered in.
///
/// Worth remembering per connection: once a host has told us it is Windows,
/// every later probe on that session can skip straight to the dialect that
/// works instead of paying for a failed POSIX attempt each time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShellDialect {
    /// Not yet known. Try POSIX first.
    #[default]
    Unknown,
    /// `sh`, `bash`, `zsh`, and anything else that understands `command -v`.
    Posix,
    /// `cmd.exe` or PowerShell on a Windows host running OpenSSH Server.
    Windows,
}

/// Is `name` safe to paste into a remote command line?
///
/// The session name reaches the remote inside a string its shell will parse,
/// so a name containing `;`, a backtick, `$(`, `%`, `&` or a quote is remote
/// code execution against the user's own account. Rather than trying to quote
/// correctly for a shell we have not identified yet (and the Windows dialects
/// quote differently from POSIX, which is exactly the kind of mismatch that
/// turns into a hole), only ever allow an alphanumeric-ish name. That is all
/// any of these multiplexers accept as a session name anyway: tmux
/// additionally rejects `.` and `:` because they are its own address
/// separators.
///
/// Deny by default. An empty name is rejected too, since `tmux -s ''` and a
/// missing argument are the same thing to a shell.
pub fn is_safe_session_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// How to get to a persistent remote session.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiplexerConfig {
    #[serde(default)]
    pub kind: MultiplexerKind,
    /// The session to attach to or create. One name per profile means the
    /// user comes back to the same place every time.
    #[serde(default = "default_session_name")]
    pub session_name: String,
    /// The command template for [`MultiplexerKind::Custom`].
    #[serde(default)]
    pub custom_command: Option<String>,
    /// Open a plain login shell when nothing suitable is installed, instead
    /// of failing the connection.
    ///
    /// Defaults to true, and [`MultiplexerKind::Auto`] ignores it entirely:
    /// a user who asked for a terminal wants a terminal, and refusing to open
    /// one because a remote box has no tmux would be obnoxious. Setting it
    /// false is for someone who would rather be told than silently lose
    /// persistence, which is a legitimate thing to want on a host you know
    /// should have it.
    #[serde(default = "default_true")]
    pub fallback_to_shell: bool,
}

fn default_session_name() -> String {
    "deskvnc".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for MultiplexerConfig {
    fn default() -> Self {
        Self {
            kind: MultiplexerKind::default(),
            session_name: default_session_name(),
            custom_command: None,
            fallback_to_shell: default_true(),
        }
    }
}

/// What the far side turned out to have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detected {
    /// The multiplexer to actually use, or `None` for a plain login shell.
    pub kind: Option<MultiplexerKind>,
    /// True when the named session was already running, so attaching resumes
    /// real work rather than starting fresh. This is the fact the UI reports
    /// as "reattached", and it must never be guessed.
    pub session_exists: bool,
    /// Which dialect the host answered in, worth carrying forward.
    pub dialect: ShellDialect,
}

impl Detected {
    /// Nothing usable: a plain shell it is.
    pub fn plain(dialect: ShellDialect) -> Self {
        Self {
            kind: None,
            session_exists: false,
            dialect,
        }
    }
}

impl MultiplexerConfig {
    /// Validate the session name once, up front.
    ///
    /// Called before a session is spawned so a bad name is an error the user
    /// sees, rather than a window that opens and immediately dies.
    pub fn validate(&self) -> Result<()> {
        if self.kind == MultiplexerKind::None {
            return Ok(());
        }
        if self.kind == MultiplexerKind::Custom {
            let template = self.custom_command.as_deref().unwrap_or("").trim();
            if template.is_empty() {
                return Err(Error::Config(
                    "the custom multiplexer command is empty".into(),
                ));
            }
        }
        if !is_safe_session_name(&self.session_name) {
            return Err(Error::Config(format!(
                "{:?} is not a usable session name: use letters, digits, dashes and underscores",
                self.session_name
            )));
        }
        Ok(())
    }

    /// The command to run on the far side for a resolved `kind`, or `None`
    /// for "just start the login shell".
    ///
    /// `kind` is passed in rather than read off `self` because [`MultiplexerKind::Auto`]
    /// only becomes a concrete choice after the probe has run.
    pub fn attach_command(&self, kind: Option<MultiplexerKind>) -> Result<Option<String>> {
        let Some(kind) = kind else {
            return Ok(None);
        };
        if kind == MultiplexerKind::None {
            return Ok(None);
        }
        self.validate()?;
        let s = &self.session_name;

        if kind.is_tmux_compatible() {
            let bin = kind.binary().unwrap_or("tmux");
            // `new-session -A` is "attach if it exists, create it if it does
            // not", which is the entire reconnect story in one flag. Without
            // -A a reconnect either errors with "duplicate session" or
            // silently starts a second one beside the user's work.
            return Ok(Some(format!("{bin} new-session -A -s {s}")));
        }

        Ok(Some(match kind {
            // -D detaches whatever else is attached, -R reattaches or
            // creates. Without -D a half-dead previous connection still
            // holding the session makes every reattach fail, which is the
            // common case after a link drop.
            MultiplexerKind::Screen => format!("screen -DR {s}"),
            MultiplexerKind::Zellij => format!("zellij attach --create {s}"),
            MultiplexerKind::Custom => self
                .custom_command
                .as_deref()
                .unwrap_or("")
                .trim()
                .replace("{session}", s),
            // Handled above or returned early.
            MultiplexerKind::Auto
            | MultiplexerKind::None
            | MultiplexerKind::Tmux
            | MultiplexerKind::Psmux => {
                return Err(Error::Config(format!(
                    "{} cannot be resolved to a command here",
                    kind.label()
                )))
            }
        }))
    }

    /// The command that tears the session down, for tests and for an explicit
    /// "end this session" action. `None` when there is nothing to kill.
    pub fn kill_command(&self, kind: Option<MultiplexerKind>) -> Option<String> {
        let kind = kind?;
        if !is_safe_session_name(&self.session_name) {
            return None;
        }
        let s = &self.session_name;
        if kind.is_tmux_compatible() {
            let bin = kind.binary().unwrap_or("tmux");
            return Some(format!("{bin} kill-session -t {s}"));
        }
        match kind {
            MultiplexerKind::Zellij => Some(format!("zellij delete-session {s}")),
            MultiplexerKind::Screen => Some(format!("screen -S {s} -X quit")),
            _ => None,
        }
    }

    /// Which kinds a probe should ask about, in order.
    fn candidates(&self) -> Vec<MultiplexerKind> {
        match self.kind {
            MultiplexerKind::Auto => MultiplexerKind::AUTO_ORDER.to_vec(),
            MultiplexerKind::None | MultiplexerKind::Custom => Vec::new(),
            one => vec![one],
        }
    }

    /// A POSIX `sh` script that reports what is installed and whether the
    /// named session is already running.
    ///
    /// Prints one line per candidate, `name:present`, `name:absent` or
    /// `name:missing`, then `end`. One round trip for the whole question,
    /// because this sits in the path of every connect *and every reconnect*,
    /// and a reconnect is exactly when the user is already waiting.
    ///
    /// Strictly POSIX: the remote login shell might be `dash`, `ksh`, `fish`
    /// or a busybox applet. `command -v` rather than `which` because it is a
    /// builtin and minimal images ship no `which` binary at all. Every branch
    /// prints something, so an unexpected exit status can never be read as a
    /// verdict.
    pub fn posix_probe(&self) -> Option<String> {
        let candidates = self.candidates();
        if candidates.is_empty() {
            return None;
        }
        if !is_safe_session_name(&self.session_name) {
            return None;
        }
        let s = &self.session_name;
        let mut script = String::new();
        for kind in candidates {
            let Some(bin) = kind.binary() else { continue };
            let label = kind.label();
            // Each of these exits 0 when the named session is already running.
            // `screen -ls` exits 1 when there are no sessions at all, hence
            // the grep rather than trusting its status.
            let has_session = if kind.is_tmux_compatible() {
                format!("{bin} has-session -t {s} 2>/dev/null")
            } else if kind == MultiplexerKind::Zellij {
                format!("zellij list-sessions 2>/dev/null | grep -q '^{s}[[:space:]]'")
            } else {
                format!("screen -ls 2>/dev/null | grep -q '[.]{s}[[:space:]]'")
            };
            script.push_str(&format!(
                "if command -v {bin} >/dev/null 2>&1; then \
                   if {has_session}; then echo {label}:present; else echo {label}:absent; fi; \
                 else echo {label}:missing; fi; "
            ));
        }
        script.push_str("echo end");
        Some(script)
    }

    /// The same question in `cmd.exe`, for a Windows host running OpenSSH
    /// Server.
    ///
    /// `where` is the Windows equivalent of `command -v` and sets `errorlevel`
    /// 1 when it finds nothing. `&&` and `||` work in `cmd.exe` with the same
    /// meaning, `2>NUL` is its null device, and `findstr` stands in for grep.
    /// Deliberately avoids `if`/`else` blocks and parentheses: their quoting
    /// and escaping rules inside a single-line remote `exec` are a menagerie,
    /// and a chain of `&&`/`||` needs none of it.
    ///
    /// PowerShell as the default shell also runs this correctly, because it
    /// treats the whole thing as a command line and `where.exe` resolves.
    pub fn windows_probe(&self) -> Option<String> {
        let candidates = self.candidates();
        if candidates.is_empty() {
            return None;
        }
        if !is_safe_session_name(&self.session_name) {
            return None;
        }
        let s = &self.session_name;
        let mut parts = Vec::new();
        for kind in candidates {
            let Some(bin) = kind.binary() else { continue };
            let label = kind.label();
            if kind.is_tmux_compatible() {
                parts.push(format!(
                    "where {bin} >NUL 2>NUL && ({bin} has-session -t {s} >NUL 2>NUL \
                     && echo {label}:present || echo {label}:absent) || echo {label}:missing"
                ));
            } else if kind == MultiplexerKind::Zellij {
                parts.push(format!(
                    "where zellij >NUL 2>NUL && (zellij list-sessions 2>NUL | findstr /b /c:\"{s}\" >NUL \
                     && echo {label}:present || echo {label}:absent) || echo {label}:missing"
                ));
            } else {
                // GNU screen has no native Windows build worth probing for,
                // but reporting it missing costs one command and keeps the
                // two dialects answering the same question.
                parts.push(format!("echo {label}:missing"));
            }
        }
        parts.push("echo end".to_string());
        Some(parts.join(" & "))
    }

    /// Read a probe's output.
    ///
    /// Tolerant on purpose: a login shell may print a banner, an rc file may
    /// be chatty, and a Windows shell echoes the command itself. So lines are
    /// matched rather than the whole buffer parsed, and anything unrecognised
    /// is ignored instead of poisoning the verdict.
    ///
    /// Returns `None` when the output contains no recognisable verdict at all,
    /// which is how the caller knows to try the other dialect.
    pub fn read_probe(&self, output: &str) -> Option<Detected> {
        let candidates = self.candidates();
        let mut best: Option<(usize, MultiplexerKind, bool)> = None;
        let mut saw_any = false;

        for line in output.lines() {
            let line = line.trim();
            let Some((name, verdict)) = line.rsplit_once(':') else {
                continue;
            };
            // A Windows shell echoes the command, and that echo contains the
            // same `label:present` text as a real answer. Take the *last*
            // path component of the name so `echo tmux:present` and a bare
            // `tmux:present` both read as tmux, and require the verdict to be
            // one of the three words.
            let name = name.rsplit([' ', '\\', '/']).next().unwrap_or(name).trim();
            let Some(kind) = candidates.iter().copied().find(|k| k.label() == name) else {
                continue;
            };
            let present = match verdict {
                "present" => true,
                "absent" => false,
                "missing" => {
                    saw_any = true;
                    continue;
                }
                _ => continue,
            };
            saw_any = true;
            let rank = candidates
                .iter()
                .position(|k| *k == kind)
                .unwrap_or(usize::MAX);
            // Prefer an already-running session over a merely-installed one,
            // whatever the order says: reattaching to real work beats
            // creating a fresh session in a tool that happens to rank higher.
            let better = match best {
                None => true,
                Some((best_rank, _, best_present)) => {
                    (present && !best_present) || (present == best_present && rank < best_rank)
                }
            };
            if better {
                best = Some((rank, kind, present));
            }
        }

        if !saw_any {
            return None;
        }
        Some(match best {
            Some((_, kind, session_exists)) => Detected {
                kind: Some(kind),
                session_exists,
                dialect: ShellDialect::Unknown,
            },
            None => Detected::plain(ShellDialect::Unknown),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(kind: MultiplexerKind) -> MultiplexerConfig {
        MultiplexerConfig {
            kind,
            session_name: "work".into(),
            ..MultiplexerConfig::default()
        }
    }

    /// The default has to be the one that is right on a machine nobody has
    /// configured, which is every machine the first time.
    #[test]
    fn the_default_detects_rather_than_assumes() {
        assert_eq!(MultiplexerConfig::default().kind, MultiplexerKind::Auto);
    }

    /// psmux is tmux-compatible, so it must get tmux's commands with its own
    /// binary name and not a second, drifting copy of them.
    #[test]
    fn psmux_speaks_tmux_with_its_own_binary() {
        let c = cfg(MultiplexerKind::Psmux);
        let cmd = c
            .attach_command(Some(MultiplexerKind::Psmux))
            .unwrap()
            .unwrap();
        assert_eq!(cmd, "psmux new-session -A -s work");
        assert!(MultiplexerKind::Psmux.is_tmux_compatible());
        assert!(MultiplexerKind::Tmux.is_tmux_compatible());
    }

    #[test]
    fn tmux_attaches_or_creates_rather_than_starting_a_second_session() {
        let cmd = cfg(MultiplexerKind::Tmux)
            .attach_command(Some(MultiplexerKind::Tmux))
            .unwrap()
            .unwrap();
        assert_eq!(cmd, "tmux new-session -A -s work");
    }

    /// Without -D a half-dead previous connection still holding the session
    /// makes every reattach fail, which is precisely the post-drop case.
    #[test]
    fn screen_detaches_a_stale_attachment_before_reattaching() {
        let cmd = cfg(MultiplexerKind::Screen)
            .attach_command(Some(MultiplexerKind::Screen))
            .unwrap()
            .unwrap();
        assert!(cmd.contains("-DR"), "{cmd}");
    }

    #[test]
    fn a_plain_shell_has_no_command() {
        assert!(cfg(MultiplexerKind::None)
            .attach_command(Some(MultiplexerKind::None))
            .unwrap()
            .is_none());
        assert!(cfg(MultiplexerKind::Auto)
            .attach_command(None)
            .unwrap()
            .is_none());
    }

    /// The session name is pasted into a command line the remote shell
    /// parses. Every one of these would be code execution on the far side,
    /// and the Windows dialect quotes differently from POSIX, which is why
    /// the answer is a strict allowlist rather than quoting.
    #[test]
    fn a_session_name_can_never_carry_shell_metacharacters() {
        for evil in [
            "a; rm -rf ~",
            "a`id`",
            "a$(id)",
            "a'b",
            "a\"b",
            "a b",
            "a|b",
            "a&b",
            "a\nb",
            "a>b",
            "a%USERNAME%",
            "a^b",
            "../../etc/passwd",
            "",
        ] {
            assert!(!is_safe_session_name(evil), "{evil:?} must be rejected");
            let c = MultiplexerConfig {
                session_name: evil.into(),
                ..MultiplexerConfig::default()
            };
            assert!(c.validate().is_err(), "{evil:?} must not validate");
            assert!(c.posix_probe().is_none(), "{evil:?} must not reach a probe");
            assert!(
                c.windows_probe().is_none(),
                "{evil:?} must not reach a probe"
            );
            assert!(
                c.attach_command(Some(MultiplexerKind::Tmux)).is_err(),
                "{evil:?} must not reach a command line"
            );
        }
    }

    #[test]
    fn ordinary_session_names_are_accepted() {
        for ok in ["deskvnc", "work-1", "my_session", "a", "A1"] {
            assert!(is_safe_session_name(ok), "{ok:?} should be usable");
        }
        assert!(!is_safe_session_name(&"a".repeat(65)), "length is capped");
    }

    /// Auto must ask about every candidate in one round trip. This sits in
    /// the path of every reconnect, when the user is already waiting.
    #[test]
    fn the_auto_probe_asks_about_everything_at_once() {
        let script = cfg(MultiplexerKind::Auto).posix_probe().unwrap();
        for bin in ["psmux", "tmux", "zellij", "screen"] {
            assert!(script.contains(bin), "{bin} missing from probe: {script}");
        }
        assert!(script.ends_with("echo end"));
    }

    /// A Windows remote is a first-class target. A POSIX-only probe does not
    /// fail loudly there, it silently reports "no multiplexer" on exactly the
    /// host the user most wanted persistence on.
    #[test]
    fn the_windows_probe_avoids_every_posix_construct() {
        let script = cfg(MultiplexerKind::Auto).windows_probe().unwrap();
        assert!(!script.contains("/dev/null"), "{script}");
        assert!(!script.contains("command -v"), "{script}");
        assert!(!script.contains("; then"), "{script}");
        assert!(!script.contains("fi;"), "{script}");
        assert!(script.contains("where psmux"), "{script}");
        assert!(script.contains(">NUL"), "{script}");
    }

    #[test]
    fn a_present_session_is_recognised_and_preferred_over_a_merely_installed_one() {
        let c = cfg(MultiplexerKind::Auto);
        // psmux ranks first, but tmux is the one with real work in it.
        let d = c
            .read_probe("psmux:absent\ntmux:present\nzellij:missing\nscreen:missing\nend")
            .unwrap();
        assert_eq!(d.kind, Some(MultiplexerKind::Tmux));
        assert!(d.session_exists, "reattaching to real work must win");
    }

    #[test]
    fn with_nothing_running_the_ranking_decides() {
        let c = cfg(MultiplexerKind::Auto);
        let d = c
            .read_probe("psmux:absent\ntmux:absent\nzellij:missing\nscreen:absent\nend")
            .unwrap();
        assert_eq!(d.kind, Some(MultiplexerKind::Psmux));
        assert!(!d.session_exists);
    }

    /// The whole point of "it must work fine for them as well": a host with
    /// nothing installed still gets a terminal.
    #[test]
    fn a_host_with_no_multiplexer_falls_back_to_a_plain_shell() {
        let c = cfg(MultiplexerKind::Auto);
        let d = c
            .read_probe("psmux:missing\ntmux:missing\nzellij:missing\nscreen:missing\nend")
            .unwrap();
        assert_eq!(d.kind, None);
        assert!(!d.session_exists);
        assert!(c.attach_command(d.kind).unwrap().is_none());
    }

    /// A Windows shell echoes the command it is running, and that echo
    /// contains the same `label:present` text as a real answer. This is the
    /// classic way a probe parser reports a tool that is not there.
    #[test]
    fn an_echoed_command_line_is_not_mistaken_for_an_answer() {
        let c = cfg(MultiplexerKind::Auto);
        let noisy = "C:\\Users\\gj>echo tmux:missing\ntmux:missing\n\
                     C:\\Users\\gj>echo psmux:present\npsmux:present\nend";
        let d = c.read_probe(noisy).unwrap();
        assert_eq!(d.kind, Some(MultiplexerKind::Psmux));
        assert!(d.session_exists);
    }

    /// A login banner or a chatty rc file must not change the verdict.
    #[test]
    fn a_login_banner_does_not_confuse_the_parser() {
        let c = cfg(MultiplexerKind::Auto);
        let noisy = "Welcome to Ubuntu 24.04 LTS\n\
                     Last login: Mon Aug 25 21:00:00 2026\n\
                     psmux:missing\ntmux:present\nzellij:missing\nscreen:absent\nend";
        let d = c.read_probe(noisy).unwrap();
        assert_eq!(d.kind, Some(MultiplexerKind::Tmux));
        assert!(d.session_exists);
    }

    /// Output with no verdict at all means the dialect was wrong, and the
    /// caller must be able to tell that apart from "nothing is installed".
    /// Conflating the two is what silently strands a Windows host on a plain
    /// shell.
    #[test]
    fn an_unparseable_answer_is_distinguishable_from_nothing_installed() {
        let c = cfg(MultiplexerKind::Auto);
        assert!(
            c.read_probe("'command' is not recognized as an internal or external command")
                .is_none(),
            "a failed dialect must report None so the other one is tried"
        );
        assert!(c.read_probe("").is_none());
        // Whereas a real "nothing installed" answer is Some(plain).
        let d = c
            .read_probe("psmux:missing\ntmux:missing\nzellij:missing\nscreen:missing")
            .unwrap();
        assert_eq!(d.kind, None);
    }

    /// An explicitly configured kind must not silently become another one.
    #[test]
    fn an_explicit_choice_is_never_substituted() {
        let c = cfg(MultiplexerKind::Screen);
        let script = c.posix_probe().unwrap();
        assert!(script.contains("screen"));
        assert!(!script.contains("tmux"), "{script}");
        // And a probe saying screen is missing yields a plain shell, not tmux.
        let d = c.read_probe("screen:missing\nend").unwrap();
        assert_eq!(d.kind, None);
    }

    #[test]
    fn a_custom_command_gets_the_session_name_substituted() {
        let c = MultiplexerConfig {
            kind: MultiplexerKind::Custom,
            session_name: "work".into(),
            custom_command: Some("zellij attach --create {session}".into()),
            ..MultiplexerConfig::default()
        };
        assert_eq!(
            c.attach_command(Some(MultiplexerKind::Custom))
                .unwrap()
                .unwrap(),
            "zellij attach --create work"
        );
    }

    #[test]
    fn an_empty_custom_command_is_an_error_rather_than_a_bare_shell() {
        let c = MultiplexerConfig {
            kind: MultiplexerKind::Custom,
            custom_command: Some("   ".into()),
            ..MultiplexerConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn the_kill_command_matches_the_multiplexer() {
        let c = cfg(MultiplexerKind::Auto);
        assert_eq!(
            c.kill_command(Some(MultiplexerKind::Psmux)).unwrap(),
            "psmux kill-session -t work"
        );
        assert_eq!(
            c.kill_command(Some(MultiplexerKind::Tmux)).unwrap(),
            "tmux kill-session -t work"
        );
        assert!(c.kill_command(None).is_none());
    }
}
