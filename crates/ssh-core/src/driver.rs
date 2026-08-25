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
use crate::options::SshTermOptions;
use crate::session::SshSession;

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
        tokio::spawn(pump_commands(session.clone(), commands_rx, cancel.clone()));
        tokio::spawn(pump_events(session_events, events, cancel.clone()));

        Ok(SessionHandle {
            id,
            kind: ProtocolKind::Ssh,
            commands: commands_tx,
            cancel,
        })
    }
}

/// Shell commands in, session commands out.
async fn pump_commands(
    session: Arc<SshSession>,
    mut commands: mpsc::Receiver<ClientCommand>,
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

        let translated = match cmd {
            ClientCommand::TerminalInput(bytes) => SshCommand::Input(bytes.to_vec()),
            ClientCommand::ResizeTerminal { cols, rows } => SshCommand::Resize { cols, rows },
            ClientCommand::ReconnectNow => SshCommand::ReconnectNow,
            ClientCommand::Disconnect => SshCommand::Disconnect,
            // Everything else in `ClientCommand` is pointer, keysym, pixel
            // format or quality: meaningless to a PTY. Dropped rather than
            // guessed at, and silently, because the shell sends some of them
            // (a quality preset on connect, say) to every session it owns.
            _ => continue,
        };

        let stop = matches!(translated, SshCommand::Disconnect);
        if session.send_command(translated).await.is_err() {
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
            // The terminal bell is a first-class `SessionEvent`; VNC has one
            // too, and the UI already knows what to do with it.
            SshEvent::Bell => SessionEvent::Bell,
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

    /// Mirrors the match inside `pump_commands`, which cannot be called
    /// directly without a live session.
    fn translate_for_test(cmd: ClientCommand) -> Option<SshCommand> {
        match cmd {
            ClientCommand::TerminalInput(bytes) => Some(SshCommand::Input(bytes.to_vec())),
            ClientCommand::ResizeTerminal { cols, rows } => Some(SshCommand::Resize { cols, rows }),
            ClientCommand::ReconnectNow => Some(SshCommand::ReconnectNow),
            ClientCommand::Disconnect => Some(SshCommand::Disconnect),
            _ => None,
        }
    }
}
