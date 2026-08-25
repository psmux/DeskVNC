//! What to open, how big, and what to run once it is open.

use ssh_transport::{SshAuth, SshConfig};

pub use crate::multiplexer::{
    is_safe_session_name, Detected, MultiplexerConfig, MultiplexerKind, ShellDialect,
};

pub use remote_core::options::ReconnectPolicy;

/// The `TERM` we advertise.
///
/// `xterm-256color` is the widest-compatible name that still gets colour: it
/// exists in every terminfo database going back decades, so a remote `vim`
/// or `htop` finds an entry and renders properly. Advertising something the
/// remote has never heard of (`alacritty`, `xterm-kitty`) makes ncurses fall
/// back to dumb-terminal behaviour, which looks like a bug in us.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// The PTY geometry and terminal type.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalOptions {
    #[serde(default = "default_term")]
    pub term: String,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_rows")]
    pub rows: u16,
}

fn default_term() -> String {
    DEFAULT_TERM.to_string()
}

// 80x24 is the VT100 default and the only geometry every remote program is
// guaranteed to cope with. The UI overwrites both before the shell starts.
fn default_cols() -> u16 {
    80
}

fn default_rows() -> u16 {
    24
}

impl Default for TerminalOptions {
    fn default() -> Self {
        Self {
            term: default_term(),
            cols: default_cols(),
            rows: default_rows(),
        }
    }
}

impl TerminalOptions {
    /// Geometry clamped to what the SSH `pty-req` and every remote program
    /// can actually represent.
    ///
    /// A zero here is the dangerous one: a webview that measures a hidden or
    /// not-yet-laid-out element reports 0x0, and a PTY 0 columns wide makes
    /// remote programs divide by zero or spin. One column by one row is
    /// useless but harmless, which is the right way to be wrong.
    pub fn clamped(&self) -> (u16, u16) {
        (self.cols.clamp(1, 10_000), self.rows.clamp(1, 10_000))
    }
}

/// Everything needed to open and keep open one remote shell.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshTermOptions {
    /// Where to dial and who to be. Flattened so the IPC shape stays flat.
    #[serde(flatten)]
    pub ssh: SshConfig,
    #[serde(default)]
    pub terminal: TerminalOptions,
    #[serde(default)]
    pub multiplexer: MultiplexerConfig,
    #[serde(default)]
    pub reconnect: ReconnectPolicy,
    /// A command to run instead of the login shell. Runs *inside* the
    /// multiplexer when there is one, so it stays persistent across a drop.
    #[serde(default)]
    pub startup_command: Option<String>,
}

impl SshTermOptions {
    /// Build from the shell's protocol-neutral `ConnectOptions`.
    ///
    /// The two halves come from different places by design: where to dial and
    /// who to be are common to every protocol and live on `ConnectOptions`,
    /// while the terminal and multiplexer settings are the SSH half, stored in
    /// the host profile's `ssh_settings` column.
    ///
    /// **The credentials are read here, and that is the point.** An earlier
    /// version of this function did not, and left a comment claiming the shell
    /// had already turned them into an [`SshAuth`]. Nothing did, so every
    /// profile connected as `Agent` with an empty username and a machine with
    /// no agent identities reported "the ssh agent holds no identities" no
    /// matter what the user had typed. The auth *kind* comes from the profile
    /// and the *secret* from `ConnectOptions::credentials`, which is the split
    /// that keeps secrets out of anything serializable.
    pub fn from_connect_options(options: &remote_core::options::ConnectOptions) -> Self {
        use remote_core::options::SshAuthKind;

        let ssh = options.ssh_options().cloned().unwrap_or_default();
        let creds = &options.credentials;

        // An empty username means "the same account as here", which is the
        // overwhelmingly common case on a personal machine and much better
        // than making the user retype it. Resolved here rather than left
        // empty, because an empty SSH username is not a default, it is a
        // protocol error the server rejects.
        let username = creds
            .username
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(str::to_string)
            .unwrap_or_else(local_username);

        let auth = match ssh.auth {
            SshAuthKind::Password => SshAuth::Password(creds.password.clone().unwrap_or_default()),
            SshAuthKind::KeyFile => SshAuth::KeyFile {
                path: ssh.key_path.clone().unwrap_or_default().into(),
                // The same field carries an account password for
                // `Password` and a key passphrase here. They unlock
                // different things, but only one of them is ever in play
                // for a given profile, so one slot is enough and the auth
                // kind says which it is.
                passphrase: creds.password.clone().filter(|p| !p.is_empty()),
            },
            // Covers `Agent` and any kind a newer build adds: an agent needs
            // nothing stored, so it is the safe reading of a value this build
            // does not recognise.
            _ => SshAuth::Agent,
        };

        let mut cfg = SshConfig::new(options.host.clone(), username);
        cfg.port = options.port;
        cfg.auth = auth;

        let mut out = Self::new(cfg);
        out.terminal.term = ssh.term.clone();
        let (cols, rows) = ssh.clamped();
        out.terminal.cols = cols;
        out.terminal.rows = rows;
        out.multiplexer = MultiplexerConfig {
            kind: crate::driver::from_core_kind(ssh.multiplexer),
            session_name: ssh.session_name.clone(),
            custom_command: ssh.custom_command.clone(),
            fallback_to_shell: ssh.fallback_to_shell,
        };
        out.startup_command = ssh.startup_command.clone();
        out.reconnect = options.reconnect;
        out
    }

    pub fn new(ssh: SshConfig) -> Self {
        Self {
            ssh,
            terminal: TerminalOptions::default(),
            multiplexer: MultiplexerConfig::default(),
            reconnect: ReconnectPolicy::default(),
            startup_command: None,
        }
    }
}

/// The account this machine is logged in as, for an SSH profile that did not
/// name one.
///
/// `USER` on unix, `USERNAME` on Windows. An empty result is left empty
/// rather than guessed at: the server's rejection names the account it was
/// offered, which is a far better clue than a username we invented.
fn local_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A webview that measures a hidden element reports 0x0, and a PTY zero
    /// columns wide makes remote programs divide by zero.
    #[test]
    fn a_zero_sized_terminal_is_clamped_to_something_usable() {
        let t = TerminalOptions {
            cols: 0,
            rows: 0,
            ..Default::default()
        };
        assert_eq!(t.clamped(), (1, 1));
    }

    #[test]
    fn the_ipc_shape_is_flat_and_every_section_is_optional() {
        let o: SshTermOptions = serde_json::from_str(
            r#"{ "host": "h", "username": "u", "auth": { "kind": "agent" } }"#,
        )
        .unwrap();
        assert_eq!(o.ssh.host, "h");
        assert_eq!(o.terminal.term, DEFAULT_TERM);
        // Detection, not an assumption: this is what makes a mixed fleet work.
        assert_eq!(o.multiplexer.kind, MultiplexerKind::Auto);
        assert!(o.reconnect.enabled);
    }

    /// The bug this pins: `from_connect_options` used to ignore
    /// `ConnectOptions::credentials` entirely, so a profile with a saved
    /// username and password still connected as `Agent` with an empty user,
    /// and a machine with no agent identities failed with "the ssh agent
    /// holds no identities" whatever the user had typed.
    #[test]
    fn a_password_profile_actually_uses_the_password() {
        use remote_core::options::{ConnectOptions, SshAuthKind};

        let mut o = ConnectOptions::ssh("box.local", 22);
        o.ssh_mut().auth = SshAuthKind::Password;
        o.credentials = remote_core::credentials::Credentials {
            username: Some("gj".into()),
            password: Some("hunter2".into()),
            domain: None,
        };

        let built = SshTermOptions::from_connect_options(&o);
        assert_eq!(built.ssh.username, "gj");
        assert_eq!(built.ssh.port, 22);
        match &built.ssh.auth {
            ssh_transport::SshAuth::Password(p) => assert_eq!(p, "hunter2"),
            other => panic!("expected password auth, got {other:?}"),
        }
    }

    #[test]
    fn a_key_file_profile_carries_the_path_and_passphrase() {
        use remote_core::options::{ConnectOptions, SshAuthKind};

        let mut o = ConnectOptions::ssh("box.local", 22);
        o.ssh_mut().auth = SshAuthKind::KeyFile;
        o.ssh_mut().key_path = Some("/home/gj/.ssh/id_ed25519".into());
        o.credentials = remote_core::credentials::Credentials {
            username: Some("gj".into()),
            password: Some("pp".into()),
            domain: None,
        };

        match &SshTermOptions::from_connect_options(&o).ssh.auth {
            ssh_transport::SshAuth::KeyFile { path, passphrase } => {
                assert_eq!(path.to_string_lossy(), "/home/gj/.ssh/id_ed25519");
                assert_eq!(passphrase.as_deref(), Some("pp"));
            }
            other => panic!("expected key-file auth, got {other:?}"),
        }
    }

    /// Agent stays the default, and needs no stored secret to work.
    #[test]
    fn an_agent_profile_needs_no_credentials() {
        use remote_core::options::ConnectOptions;

        let o = ConnectOptions::ssh("box.local", 22);
        let built = SshTermOptions::from_connect_options(&o);
        assert!(matches!(built.ssh.auth, ssh_transport::SshAuth::Agent));
    }

    /// An empty username is not a default, it is something the server
    /// rejects. A profile that names no account means "the same one as here".
    #[test]
    fn an_unnamed_account_falls_back_to_the_local_user() {
        use remote_core::options::ConnectOptions;

        let mut o = ConnectOptions::ssh("box.local", 22);
        o.credentials = remote_core::credentials::Credentials {
            username: Some("   ".into()),
            password: None,
            domain: None,
        };
        let built = SshTermOptions::from_connect_options(&o);
        let expected = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default();
        assert_eq!(built.ssh.username, expected);
    }

    #[test]
    fn the_multiplexer_section_deserializes_in_kebab_case() {
        let o: SshTermOptions = serde_json::from_str(
            r#"{ "host": "h", "username": "u", "auth": { "kind": "agent" },
                 "multiplexer": { "kind": "psmux", "sessionName": "work" },
                 "terminal": { "cols": 120, "rows": 40 } }"#,
        )
        .unwrap();
        assert_eq!(o.multiplexer.kind, MultiplexerKind::Psmux);
        assert_eq!(o.multiplexer.session_name, "work");
        assert_eq!(o.terminal.clamped(), (120, 40));
    }
}
