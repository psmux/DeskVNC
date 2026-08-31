//! What the session tells the UI, and what the UI tells the session.
//!
//! The serde shape follows the workspace IPC convention (IPC_CONTRACT.md): a
//! kebab-case `type` discriminator at the top level, camelCase fields, and
//! the shell inserting `sessionId` beside `type` before it emits. A webview
//! that meets a `type` it does not know must ignore it, which is what lets
//! the shell and the UI ship a new event in separate commits.

use crate::options::MultiplexerKind;

/// Where the session is right now.
///
/// Deliberately its own enum rather than `remote_core::SessionState`: that
/// one carries framebuffer geometry and pixel formats, none of which mean
/// anything to a terminal, and it has no way to say "reattached to tmux".
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum TerminalState {
    /// Dialling, verifying the host key, authenticating.
    Connecting { endpoint: String },
    /// A PTY is open and the shell is running.
    Connected {
        endpoint: String,
        /// What is actually running on the far side. `None` means the login
        /// shell, either because that is what was asked for or because the
        /// multiplexer was missing and we fell back.
        multiplexer: Option<MultiplexerKind>,
        /// True when this attach found an existing remote session rather
        /// than creating one, which is the case where the user's work
        /// survived a drop. Worth saying out loud in the UI.
        resumed: bool,
    },
    /// The link went away and we are waiting out the backoff. `attempt` is
    /// 1-based and `delayMs` is how long until the next try, so the UI can
    /// show a countdown instead of a spinner.
    Reconnecting {
        attempt: u32,
        delay_ms: u64,
        reason: String,
    },
    /// The session is over.
    Disconnected {
        reason: String,
        /// Whether offering a manual "reconnect" button makes any sense.
        can_retry: bool,
        /// Stable identifier for the failure, for a UI that wants to match
        /// on the kind of problem and write its own sentence. Matching on
        /// `reason` instead makes every copy edit a behaviour change.
        symbol: Option<&'static str>,
    },
}

/// Everything the session emits.
///
/// `Output` is by far the highest-volume variant, which is why it is bytes
/// rather than a `String`: a remote program can emit a partial UTF-8
/// character at the end of any write, and decoding per chunk would either
/// corrupt it or force this layer to buffer text it has no business
/// understanding. The terminal emulator on the other end does that job.
#[derive(Clone, Debug)]
pub enum SshEvent {
    StateChanged(TerminalState),
    /// Raw bytes from the remote PTY, in order.
    Output(Vec<u8>),
    /// The remote asked the terminal to ring.
    Bell,
    /// The link dropped and these bytes must be written to the local
    /// terminal to undo whatever modes the dead session left on.
    ///
    /// Kept separate from [`SshEvent::Output`] on purpose: this is *our*
    /// correction, not remote output, and a UI that logs or replays output
    /// must not treat it as something the server said. See [`crate::modes`]
    /// for what goes wrong when nobody sends these.
    ResetTerminal(Vec<u8>),
    /// A line for the session log, never for the terminal itself.
    Notice(String),

    /// The session needs credentials from the user and is PAUSED until they
    /// arrive.
    ///
    /// This is what makes an ad-hoc connect possible at all. A saved profile
    /// carries its account and secret, but a Quick Connect target has no
    /// profile to carry anything, so without an ask the only auth that could
    /// ever work is an agent, and a machine with no agent identities simply
    /// failed. The session must ask rather than fail (PRD/10 §3.4 says the
    /// same thing for VNC).
    CredentialsRequired {
        /// Which method is being attempted, for the dialog's title.
        method: String,
        /// 1-based. Greater than 1 means a previous attempt was rejected.
        attempt: u32,
        /// Why the previous attempt failed, when there was one.
        error: Option<String>,
        /// Prefill for the username field.
        username_hint: Option<String>,
    },

    /// An agent intent was served, and this is the answer
    /// (`PRDAgentPlug/00 R51b`).
    ///
    /// Addressed to the agent that asked, never to the terminal: none of this
    /// is output the person at this window typed for, and the bytes inside came
    /// off a remote machine, so putting them on the screen would be a remote
    /// machine writing into our UI. [`crate::driver`] passes it out as
    /// `SessionEvent::AgentServed`.
    ///
    /// Boxed because it is by far the widest thing this enum carries and
    /// [`SshEvent::Output`], which arrives thousands of times a second on a
    /// scrolling build log, would otherwise pay for it on every clone.
    AgentServed(Box<remote_core::intent::IntentServed>),

    /// An agent intent was not served, and nothing went on the wire
    /// (`PRDAgentPlug/00 R28`).
    ///
    /// [`crate::driver`] refuses the intents this session can never serve
    /// before they reach here. This is for the ones it can normally serve and
    /// could not this time: a channel that would not open, a request the far
    /// side rejected, a session that is not connected yet. Boxed with
    /// [`SshEvent::AgentServed`] and for the same reason.
    AgentRefused(Box<remote_core::intent::IntentRefused>),
}

/// What the UI asks of a running session.
#[derive(Clone, Debug)]
pub enum SshCommand {
    /// Keystrokes and pastes, straight through to the remote PTY.
    Input(Vec<u8>),
    /// The window was resized. Sent on every layout change; the session
    /// forwards a `window-change` request so remote programs redraw.
    Resize { cols: u16, rows: u16 },
    /// Skip the remaining backoff and try again now. Also resets the attempt
    /// counter, so a user who knows the network is back does not inherit a
    /// 15 second delay earned while it was down.
    ReconnectNow,
    /// End the session. The shell is asked to exit, then the carrier closes.
    Disconnect,

    /// The user answered a [`SshEvent::CredentialsRequired`] ask.
    ProvideCredentials {
        username: Option<String>,
        password: String,
    },
    /// The user dismissed the credential dialog. Ends the session rather than
    /// retrying: they were asked and declined.
    CancelCredentials,

    /// Run one command on a channel of its own, for an agent that asked
    /// (`PRDAgentPlug/05 §3`).
    ///
    /// Not [`SshCommand::Input`] with a newline on the end, and
    /// [`crate::exec`]'s module header is where that argument lives: typing at
    /// the prompt somebody is watching gives no exit status, no stderr split
    /// and no output bound, which is three of the five things an answer needs.
    ///
    /// The session serves this on a task of its own. A command that takes two
    /// minutes must not be two minutes during which the terminal accepts no
    /// keystrokes, which is the stall the two pump split already exists to
    /// avoid.
    Exec(crate::exec::ExecRequest),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire shape is part of the IPC contract: a kebab-case `state`
    /// discriminator with camelCase fields beside it. The shell adds
    /// `sessionId` to this same flat object.
    #[test]
    fn the_state_serialises_flat_with_a_kebab_case_discriminator() {
        let json = serde_json::to_value(TerminalState::Reconnecting {
            attempt: 2,
            delay_ms: 500,
            reason: "connection reset".into(),
        })
        .unwrap();
        assert_eq!(json["state"], "reconnecting");
        assert_eq!(json["attempt"], 2);
        assert_eq!(json["delayMs"], 500);
        assert!(json.get("delay_ms").is_none(), "snake_case leaked: {json}");
    }

    #[test]
    fn a_resumed_session_says_so_and_names_its_multiplexer() {
        let json = serde_json::to_value(TerminalState::Connected {
            endpoint: "gj@box:22".into(),
            multiplexer: Some(MultiplexerKind::Tmux),
            resumed: true,
        })
        .unwrap();
        assert_eq!(json["state"], "connected");
        assert_eq!(json["multiplexer"], "tmux");
        assert_eq!(json["resumed"], true);
    }

    /// A plain-shell session has no multiplexer, and `null` is how the UI
    /// tells that apart from a missing field.
    #[test]
    fn a_plain_shell_reports_a_null_multiplexer() {
        let json = serde_json::to_value(TerminalState::Connected {
            endpoint: "gj@box:22".into(),
            multiplexer: None,
            resumed: false,
        })
        .unwrap();
        assert!(json["multiplexer"].is_null());
    }

    #[test]
    fn a_disconnect_carries_a_symbol_the_ui_can_match_on() {
        let json = serde_json::to_value(TerminalState::Disconnected {
            reason: "the connection stopped responding".into(),
            can_retry: true,
            symbol: Some("ssh-unresponsive"),
        })
        .unwrap();
        assert_eq!(json["symbol"], "ssh-unresponsive");
        assert_eq!(json["canRetry"], true);
    }
}
