//! What to open, how big, and what to run once it is open.

use ssh_transport::SshConfig;

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
    /// while the terminal and multiplexer settings are the SSH half, stored
    /// in the host profile's `ssh_settings` column.
    ///
    /// Credentials are deliberately *not* read here. `ConnectOptions` carries
    /// them in a non-serializable field and the shell turns them into an
    /// [`ssh_transport::SshAuth`] before this is called, so a secret never
    /// passes through an options struct that could be logged or serialized.
    pub fn from_connect_options(options: &remote_core::options::ConnectOptions) -> Self {
        let ssh = options.ssh_options().cloned().unwrap_or_default();
        let mut out = Self::new(SshConfig::new(options.host.clone(), String::new()));
        out.ssh.port = options.port;
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
