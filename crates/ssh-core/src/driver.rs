//! `ssh-core` as a [`ProtocolDriver`], so a remote shell is a session like
//! any other.
//!
//! Everything the shell already does for a VNC or RDP session (window and tab
//! lifecycle, the session registry, connection history, the reconnect UI, the
//! menu) works on a `SessionHandle` and a `SessionEvent` stream. Implementing
//! the trait means a terminal gets all of it for free rather than growing a
//! parallel copy in the shell, which is the thing that would rot.
//!
//! ## The adapter, and why the crate keeps its own event type
//!
//! Inside, the session speaks [`crate::events::SshEvent`], which is shaped for
//! a terminal. Outward it must speak `remote_core::SessionEvent`, which is
//! shaped for a framebuffer. Most of the mapping is exact:
//! [`crate::events::TerminalState`] is a strict subset of
//! `remote_core::SessionState`, and the byte payloads go through
//! `SessionEvent::Protocol(ProtocolEvent::Ssh(..))`, the escape hatch that
//! already exists for RDP's protocol-specific news.
//!
//! The internal type stays because it carries two facts `SessionState` has no
//! room for and should not grow: which multiplexer was attached, and whether
//! the attach *resumed* existing work. Those ride out as
//! `SshEvent::Attached`.

use std::sync::Arc;

use remote_core::commands::ClientCommand;
use remote_core::driver::{OptionsMismatch, ProtocolDriver, ProtocolKind, SessionHandle};
use remote_core::events::{ProtocolEvent, SessionEvent, SshEvent as OutEvent};
use remote_core::options::ConnectOptions;
use remote_core::state::SessionState;
use ssh_transport::hostkey::HostKeyVerifier;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::events::{SshCommand, SshEvent, TerminalState};
use crate::exec::ExecRequest;
use crate::options::SshTermOptions;
use crate::session::SshSession;
use remote_core::intent::IntentKind;

/// The remote-shell driver.
///
/// Holds the shared host-key pin store, because unlike the other two
/// protocols SSH's trust decision belongs to a store the Files panel and the
/// RFB tunnel also read. Trusting a machine once has to cover all three, so
/// there is exactly one store in the app and the driver is handed it rather
/// than making its own.
pub struct SshDriver {
    verifier: Arc<dyn HostKeyVerifier + Send + Sync + 'static>,
}

impl SshDriver {
    pub fn new(verifier: impl HostKeyVerifier) -> Self {
        Self {
            verifier: Arc::new(verifier),
        }
    }
}

impl std::fmt::Debug for SshDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SshDriver")
    }
}

impl ProtocolDriver for SshDriver {
    fn kind(&self) -> ProtocolKind {
        ProtocolKind::Ssh
    }

    // `default_port` is deliberately not overridden: `ProtocolKind::Ssh`
    // already answers 22 citing RFC 4253 §4, and a second copy of the number
    // is a second place for it to be wrong.

    fn spawn(
        &self,
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> std::result::Result<SessionHandle, OptionsMismatch> {
        let actual = options.kind();
        if actual != ProtocolKind::Ssh {
            return Err(OptionsMismatch {
                expected: ProtocolKind::Ssh,
                actual,
            });
        }

        let term_options = SshTermOptions::from_connect_options(&options);
        let (session, session_events) = SshSession::spawn(term_options, self.verifier.clone());
        let session = Arc::new(session);

        let (commands_tx, commands_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();

        // Two pumps rather than one: commands flow in, events flow out, and
        // neither should be able to stall the other. A terminal that stops
        // accepting keystrokes because its output is backed up is exactly the
        // hang this crate exists to avoid.
        //
        // The command pump takes a clone of the event sink because it has one
        // thing to say: a refused agent intent (PRDAgentPlug/00 R28). It never
        // awaits it in a hot path, so it cannot become the stall the two pump
        // split exists to avoid.
        tokio::spawn(pump_commands(
            session.clone(),
            commands_rx,
            events.clone(),
            cancel.clone(),
        ));
        tokio::spawn(pump_events(session_events, events, cancel.clone()));

        Ok(SessionHandle {
            id,
            kind: ProtocolKind::Ssh,
            commands: commands_tx,
            cancel,
        })
    }
}

/// Why `pty_run` is still refused now that `exec` is not.
///
/// `00 R50a` is closed for `exec`: [`crate::exec`] opens a second channel per
/// RFC 4254 §6.5 and reads the far side's own `exit-status` off it. `pty_run`
/// is a different intent and the difference is the whole argument. It asks for
/// a command to run on the PTY THE PERSON IS WATCHING, which means typing at
/// their prompt and reading the scrollback for an answer, and a scrollback
/// gives no exit status, no stderr split and no output bound: three of the five
/// things `05 §4.1` requires. The only way to produce a status from it is to
/// invent one, and an invented exit status is worse than a refusal because the
/// agent acts on it (`00 R7`).
///
/// So the sentence names the intent that does work. An agent that wanted a
/// command run wants `exec`, and an agent that genuinely wants to drive the
/// person's own terminal wants `dvv_term_send`, which lowers to bytes that
/// exist.
const REFUSE_PTY_RUN: &str =
    "pty_run would type at the terminal a person is watching and read the scrollback for an answer, which gives no exit status, no stderr split and no output bound: use exec, which runs on a channel of its own and returns the far side's real exit status, or send bytes if you meant to drive this terminal";

/// Why `declare` is refused.
///
/// `05 §3.3`'s declared state is per limb and this crate holds none: every
/// `exec` opens a fresh channel that starts in the user's home directory with a
/// fresh environment and inherits nothing, which is exactly why the intent
/// exists. Rather than remember state that would then be invisible in the
/// session the person is looking at, the answer is `05 §3`'s: state the `cwd`
/// and `env` on the request itself, which [`crate::exec::exec_line`]
/// implements and honours.
const REFUSE_DECLARE: &str =
    "this session holds no declared state: every exec runs on a fresh channel that starts in the home directory with a fresh environment, so pass cwd and env on the run itself, where they take effect";

/// What the command pump does with one [`ClientCommand`].
///
/// A separate type, and [`route`] a pure function, so the decision that
/// matters here can be tested without a socket. Before `PRDAgentPlug/00 R28`
/// this was a `match` ending in `_ => continue` inside the pump, and that arm
/// is the one the requirement was written against: nothing outside the pump
/// could see what it swallowed.
#[derive(Debug)]
enum Routed {
    /// Translated into something the PTY session understands.
    Session(SshCommand),
    /// Not servable here, and the asker is told so.
    Refuse(remote_core::intent::IntentRefused),
    /// Meaningless to a PTY and safe to drop in silence, because a person is
    /// watching this window and nothing is waiting on an answer.
    Ignore,
}

/// Decide what one shell command means to a remote shell.
fn route(cmd: ClientCommand) -> Routed {
    match cmd {
        ClientCommand::TerminalInput(bytes) => Routed::Session(SshCommand::Input(bytes.to_vec())),
        ClientCommand::ResizeTerminal { cols, rows } => {
            Routed::Session(SshCommand::Resize { cols, rows })
        }
        ClientCommand::ReconnectNow => Routed::Session(SshCommand::ReconnectNow),
        ClientCommand::Disconnect => Routed::Session(SshCommand::Disconnect),
        ClientCommand::ProvideCredentials {
            username, password, ..
        } => Routed::Session(SshCommand::ProvideCredentials { username, password }),
        ClientCommand::CancelCredentials => Routed::Session(SshCommand::CancelCredentials),
        // `00 R28`. This arm exists so the one below cannot have it. An intent
        // is the one thing in this enum with somebody blocked on the far end
        // of it: the shell fans a quality preset out to every session it owns
        // and nothing is waiting to hear what happened, while an agent that
        // issued an intent is not watching the window, it is waiting for a
        // settlement, and silence is a wait with no end.
        //
        // Matched on the KIND rather than refused wholesale, which is `00 R50a`
        // closing: `exec` is served now, and the two beside it are refused for
        // reasons of their own rather than for want of a channel.
        ClientCommand::Agent(intent) => match &intent.kind {
            IntentKind::Exec { spec } => Routed::Session(SshCommand::Exec(ExecRequest {
                id: intent.id,
                name: intent.kind.name(),
                spec: spec.clone(),
            })),
            IntentKind::PtyRun { .. } => Routed::Refuse(intent.refuse(REFUSE_PTY_RUN)),
            IntentKind::Declare { .. } => Routed::Refuse(intent.refuse(REFUSE_DECLARE)),
            // Everything else is an intent the plane lowers into ordinary
            // commands and never sends whole, so one arriving here is a limb
            // claiming `Support::Native` for something this driver never said
            // it served. Answered with what it is rather than dropped, because
            // the agent is still waiting either way.
            other => Routed::Refuse(intent.refuse(format!(
                "a remote shell does not serve {} natively",
                other.name()
            ))),
        },
        // Everything else in `ClientCommand` is pointer, keysym, pixel format
        // or quality: meaningless to a PTY. Dropped rather than guessed at,
        // and silently, because the shell sends some of them (a quality preset
        // on connect, say) to every session it owns.
        _ => Routed::Ignore,
    }
}

/// Shell commands in, session commands out.
async fn pump_commands(
    session: Arc<SshSession>,
    mut commands: mpsc::Receiver<ClientCommand>,
    events: mpsc::Sender<SessionEvent>,
    cancel: CancellationToken,
) {
    loop {
        let cmd = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            cmd = commands.recv() => match cmd {
                Some(c) => c,
                None => break,
            },
        };

        let translated = match route(cmd) {
            Routed::Session(c) => c,
            Routed::Refuse(refusal) => {
                if events
                    .send(SessionEvent::AgentRefused(refusal))
                    .await
                    .is_err()
                {
                    break;
                }
                continue;
            }
            Routed::Ignore => continue,
        };

        let stop = matches!(translated, SshCommand::Disconnect);
        // Kept so the intent can still be answered if the session has gone.
        // `00 R28` has no exception for "the queue was closed": an agent
        // blocked on a settlement is blocked whatever killed the session, and
        // the plane would otherwise wait out the whole deadline to learn it.
        let asked = match &translated {
            SshCommand::Exec(request) => Some(request.clone()),
            _ => None,
        };
        if session.send_command(translated).await.is_err() {
            if let Some(request) = asked {
                let refusal = request
                    .refuse("the session ended before the command could be started: nothing ran");
                let _ = events.send(SessionEvent::AgentRefused(refusal)).await;
            }
            break;
        }
        if stop {
            break;
        }
    }
    session.shutdown().await;
}

/// Session events out, shell events out.
async fn pump_events(
    mut incoming: mpsc::Receiver<SshEvent>,
    outgoing: mpsc::Sender<SessionEvent>,
    cancel: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            e = incoming.recv() => match e {
                Some(e) => e,
                None => break,
            },
        };

        // `Connected` is two facts, not one: the state the shell tracks, and
        // which multiplexer was attached plus whether it resumed real work.
        // The second has no home in `SessionState` and should not grow one,
        // so it rides alongside as a protocol event, exactly as RDP's logon
        // info does.
        if let SshEvent::StateChanged(TerminalState::Connected {
            multiplexer,
            resumed,
            ..
        }) = &event
        {
            let extra = attached_event((*multiplexer).map(to_core_kind), *resumed);
            if outgoing.send(extra).await.is_err() {
                break;
            }
        }

        let translated = match event {
            SshEvent::StateChanged(state) => match translate_state(state) {
                Some(out) => out,
                None => continue,
            },
            SshEvent::Output(bytes) => {
                SessionEvent::Protocol(ProtocolEvent::Ssh(OutEvent::Output(bytes.into())))
            }
            SshEvent::ResetTerminal(bytes) => {
                SessionEvent::Protocol(ProtocolEvent::Ssh(OutEvent::ResetTerminal(bytes.into())))
            }
            SshEvent::Notice(message) => {
                SessionEvent::Protocol(ProtocolEvent::Ssh(OutEvent::Notice(message)))
            }
            // Not a `ProtocolEvent::Ssh`, and `00 R28` says why: an exit
            // status, a truncation notice and a refusal have the same shape on
            // a Kubernetes exec stream and on an ADB shell, so filing them
            // under one protocol guarantees a second copy the first time a non
            // SSH limb needs them. They are `SessionEvent`'s own variants and
            // travel as themselves.
            SshEvent::AgentServed(served) => SessionEvent::AgentServed(*served),
            SshEvent::AgentRefused(refusal) => SessionEvent::AgentRefused(*refusal),
            // The terminal bell is a first-class `SessionEvent`; VNC has one
            // too, and the UI already knows what to do with it.
            SshEvent::Bell => SessionEvent::Bell,
            // Reuses the shell's existing credential dialog rather than
            // growing an SSH-specific one: the shell already knows how to
            // show this, prefill it, and answer with `ProvideCredentials`.
            SshEvent::CredentialsRequired {
                method,
                attempt,
                error,
                username_hint,
            } => SessionEvent::CredentialsRequired(remote_core::credentials::CredentialRequest {
                method,
                kind: remote_core::credentials::CredentialKind::UsernameAndPassword,
                attempt,
                error,
                // SSH passwords are not DES-truncated the way legacy VNC
                // authentication is, so the UI must not warn about it.
                truncates_password: false,
                username_hint,
            }),
        };

        if outgoing.send(translated).await.is_err() {
            break;
        }
    }
}

/// [`TerminalState`] to `SessionState`, plus the SSH-only facts alongside.
///
/// `Connected` is the interesting one: `SessionState::Connected` is a unit
/// variant with no room for "which multiplexer" or "did this resume real
/// work", and it should not grow them, because they mean nothing to a
/// framebuffer protocol. So the state change and the
/// [`OutEvent::Attached`] fact are emitted as two events and the caller
/// correlates them, which is exactly how RDP already reports its logon info.
fn translate_state(state: TerminalState) -> Option<SessionEvent> {
    Some(match state {
        TerminalState::Connecting { .. } => SessionEvent::StateChanged(SessionState::Connecting),
        TerminalState::Connected { .. } => SessionEvent::StateChanged(SessionState::Connected),
        TerminalState::Reconnecting {
            attempt,
            delay_ms,
            reason,
        } => SessionEvent::StateChanged(SessionState::Reconnecting {
            attempt,
            next_retry_ms: delay_ms,
            reason,
        }),
        TerminalState::Disconnected {
            reason,
            can_retry,
            symbol,
        } => SessionEvent::StateChanged(SessionState::Disconnected {
            reason,
            can_retry,
            symbol: symbol.map(str::to_string),
        }),
    })
}

/// `ssh-core`'s multiplexer kind to `remote-core`'s.
///
/// Two enums for one concept, because the data type has to live in
/// `remote-core` (the store and the host editor serialize it without
/// depending on this crate) while this crate needs its own for the probe and
/// command behaviour hung off it. The mapping is total and exhaustive, so
/// adding a variant to either breaks this and forces a decision.
fn to_core_kind(
    kind: crate::multiplexer::MultiplexerKind,
) -> remote_core::options::MultiplexerKind {
    use crate::multiplexer::MultiplexerKind as Mine;
    use remote_core::options::MultiplexerKind as Theirs;
    match kind {
        Mine::Auto => Theirs::Auto,
        Mine::None => Theirs::None,
        Mine::Psmux => Theirs::Psmux,
        Mine::Tmux => Theirs::Tmux,
        Mine::Screen => Theirs::Screen,
        Mine::Zellij => Theirs::Zellij,
        Mine::Custom => Theirs::Custom,
    }
}

/// The reverse, for options arriving from a host profile.
pub(crate) fn from_core_kind(
    kind: remote_core::options::MultiplexerKind,
) -> crate::multiplexer::MultiplexerKind {
    use crate::multiplexer::MultiplexerKind as Mine;
    use remote_core::options::MultiplexerKind as Theirs;
    match kind {
        Theirs::None => Mine::None,
        Theirs::Psmux => Mine::Psmux,
        Theirs::Tmux => Mine::Tmux,
        Theirs::Screen => Mine::Screen,
        Theirs::Zellij => Mine::Zellij,
        Theirs::Custom => Mine::Custom,
        // `Auto` and anything a newer build adds both mean "work it out",
        // which is the safe reading of a variant this build does not know.
        _ => Mine::Auto,
    }
}

/// The `Attached` fact that rides beside a `Connected` state change.
pub(crate) fn attached_event(
    multiplexer: Option<remote_core::options::MultiplexerKind>,
    resumed: bool,
) -> SessionEvent {
    SessionEvent::Protocol(ProtocolEvent::Ssh(OutEvent::Attached {
        multiplexer,
        resumed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::options::ConnectOptions;

    /// The registry hands options by value and nothing in the type system
    /// stops it handing the wrong protocol's. A typed error beats a panic.
    #[test]
    fn the_driver_refuses_another_protocols_options() {
        let driver = SshDriver::new(crate::test_support::TrustAll);
        let (tx, _rx) = mpsc::channel(1);
        let err = driver
            .spawn("s1".into(), ConnectOptions::vnc("h", 5900), tx)
            .expect_err("vnc options must be refused");
        assert_eq!(err.expected, ProtocolKind::Ssh);
        assert_eq!(err.actual, ProtocolKind::Vnc);
    }

    #[test]
    fn the_driver_reports_its_kind_and_the_registered_port() {
        let driver = SshDriver::new(crate::test_support::TrustAll);
        assert_eq!(driver.kind(), ProtocolKind::Ssh);
        assert_eq!(driver.default_port(), 22);
    }

    /// A terminal has no pointer, no keysyms and no quality preset, but the
    /// shell broadcasts some of those to every session it owns. Dropping them
    /// silently is correct; erroring or panicking would kill the session the
    /// first time the user changed a global setting.
    #[test]
    fn framebuffer_commands_are_dropped_rather_than_failing() {
        for cmd in [
            ClientCommand::Pointer {
                x: 1,
                y: 1,
                button_mask: 0,
            },
            ClientCommand::ReleaseAllKeys,
            ClientCommand::Refresh,
            ClientCommand::SetViewOnly(true),
        ] {
            assert!(
                translate_for_test(cmd).is_none(),
                "framebuffer commands must not reach a pty"
            );
        }
    }

    /// The four that do mean something must survive the trip.
    #[test]
    fn terminal_commands_survive_translation() {
        assert!(matches!(
            translate_for_test(ClientCommand::TerminalInput(b"ls\n".to_vec().into())),
            Some(SshCommand::Input(_))
        ));
        assert!(matches!(
            translate_for_test(ClientCommand::ResizeTerminal {
                cols: 120,
                rows: 40
            }),
            Some(SshCommand::Resize {
                cols: 120,
                rows: 40
            })
        ));
        assert!(matches!(
            translate_for_test(ClientCommand::ReconnectNow),
            Some(SshCommand::ReconnectNow)
        ));
        assert!(matches!(
            translate_for_test(ClientCommand::Disconnect),
            Some(SshCommand::Disconnect)
        ));
    }

    /// A resize in cells must never be confused with a desktop resize in
    /// pixels: 80 columns is not 80 pixels and nothing would catch it.
    #[test]
    fn a_pixel_resize_is_not_a_terminal_resize() {
        assert!(translate_for_test(ClientCommand::RequestResize {
            width: 1920,
            height: 1080
        })
        .is_none());
    }

    /// The state machine the UI drives off must map cleanly, including the
    /// reconnect fields, or a reconnecting terminal shows no countdown.
    #[test]
    fn the_reconnect_state_keeps_its_attempt_and_delay() {
        let out = translate_state(TerminalState::Reconnecting {
            attempt: 3,
            delay_ms: 2000,
            reason: "broken pipe".into(),
        });
        match out {
            Some(SessionEvent::StateChanged(SessionState::Reconnecting {
                attempt,
                next_retry_ms,
                ..
            })) => {
                assert_eq!(attempt, 3);
                assert_eq!(next_retry_ms, 2000);
            }
            other => panic!("expected a reconnecting state, got {other:?}"),
        }
    }

    #[test]
    fn a_disconnect_carries_its_symbol_so_the_ui_can_match_on_it() {
        let out = translate_state(TerminalState::Disconnected {
            reason: "the connection stopped responding".into(),
            can_retry: true,
            symbol: Some("ssh-unresponsive"),
        });
        match out {
            Some(SessionEvent::StateChanged(SessionState::Disconnected {
                symbol,
                can_retry,
                ..
            })) => {
                assert_eq!(symbol.as_deref(), Some("ssh-unresponsive"));
                assert!(can_retry);
            }
            other => panic!("expected a disconnected state, got {other:?}"),
        }
    }

    /// An intent of any shape, for the routing tests below.
    fn intent(kind: remote_core::intent::IntentKind) -> ClientCommand {
        use remote_core::intent::{AgentIntent, IntentId};

        ClientCommand::Agent(AgentIntent {
            id: IntentId(9),
            grant: "att_test".into(),
            deadline: Some(std::time::Duration::from_secs(5)),
            fence: None,
            kind,
        })
    }

    fn a_spec(command: &str) -> remote_core::intent::CommandSpec {
        remote_core::intent::CommandSpec {
            command: command.into(),
            cwd: None,
            env: Vec::new(),
            timeout: std::time::Duration::from_secs(5),
            stdin: None,
            max_output_bytes: None,
        }
    }

    /// `PRDAgentPlug/00 R50a` closing. This used to assert a refusal, because
    /// this crate owned one PTY channel and nothing routed a second one. It
    /// routes one now, and the intent that reaches the session must carry the
    /// id the agent is blocked on: an answer that cannot name its question is
    /// not an answer.
    #[test]
    fn an_exec_intent_reaches_a_channel_of_its_own() {
        use remote_core::intent::{IntentId, IntentKind, IntentName};

        match route(intent(IntentKind::Exec {
            spec: a_spec("whoami"),
        })) {
            Routed::Session(SshCommand::Exec(request)) => {
                assert_eq!(request.id, IntentId(9));
                assert_eq!(request.name, IntentName::Exec);
                assert_eq!(request.spec.command, "whoami");
            }
            other => panic!("exec must reach the session now, got {other:?}"),
        }
    }

    /// `PRDAgentPlug/00 R28`, on the pump the requirement names.
    ///
    /// The two intents this driver still declines must land on
    /// [`Routed::Refuse`]. Landing on [`Routed::Ignore`] is the failure the
    /// whole rule exists to stop: the agent is not watching this window, it is
    /// blocked on a settlement, so a drop is not a lost message, it is a wait
    /// with no end. Delete the `ClientCommand::Agent` arm in [`route`] and both
    /// slide into the catch all below it, and this test says so.
    #[test]
    fn the_intents_this_driver_declines_are_refused_out_loud_and_never_dropped() {
        use remote_core::intent::{IntentId, IntentKind, IntentName};

        let cases = [
            (
                IntentKind::PtyRun {
                    spec: a_spec("make"),
                },
                IntentName::PtyRun,
                REFUSE_PTY_RUN,
            ),
            (
                IntentKind::Declare {
                    cwd: Some("/tmp".into()),
                    env: Vec::new(),
                },
                IntentName::Declare,
                REFUSE_DECLARE,
            ),
        ];

        for (kind, name, reason) in cases {
            match route(intent(kind)) {
                Routed::Refuse(refusal) => {
                    assert_eq!(refusal.id, IntentId(9));
                    assert_eq!(refusal.name, name);
                    assert_eq!(refusal.reason, reason);
                }
                Routed::Ignore => panic!("an intent must never be dropped in silence (00 R28)"),
                Routed::Session(cmd) => panic!("{name} is not served here, got {cmd:?}"),
            }
        }
    }

    /// A refusal has to teach the agent what to do instead, or it is just a
    /// wall. Both of these name the intent that works.
    #[test]
    fn a_refusal_points_at_the_intent_that_does_work() {
        assert!(REFUSE_PTY_RUN.contains("exec"), "{REFUSE_PTY_RUN}");
        assert!(REFUSE_DECLARE.contains("cwd and env"), "{REFUSE_DECLARE}");
    }

    /// The other half of the same rule: the silence is still allowed where it
    /// was always right, so the fix did not turn a global setting broadcast
    /// into an event storm.
    #[test]
    fn only_an_intent_gets_an_answer() {
        assert!(matches!(
            route(ClientCommand::SetQuality(
                remote_core::options::QualityPreset::Low
            )),
            Routed::Ignore
        ));
        assert!(matches!(
            route(ClientCommand::TerminalInput(b"ls\n".to_vec().into())),
            Routed::Session(_)
        ));
    }

    /// The real routing table, narrowed to what the tests above ask of it.
    ///
    /// This used to be a hand copy of the match inside `pump_commands`, which
    /// could not be called without a live session. [`route`] is that match now,
    /// so this is a wrapper and not a second table. The copy is worth naming:
    /// it would have gone on answering `None` for `ClientCommand::Agent`,
    /// which is the very drop the pump stopped doing, and the tests would have
    /// agreed with it.
    fn translate_for_test(cmd: ClientCommand) -> Option<SshCommand> {
        match route(cmd) {
            Routed::Session(c) => Some(c),
            Routed::Refuse(refusal) => panic!("a refusal is not a translation: {refusal}"),
            Routed::Ignore => None,
        }
    }
}
