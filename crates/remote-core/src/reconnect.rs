//! The session supervisor, shared by every protocol (PRDRDP/02 §11.2,
//! PRDRDP/06 §5.2).
//!
//! This is `crates/vnc-core/src/session/reconnect.rs` generalised, line for
//! line, with the three substitutions PRDRDP/02 §11.2 names:
//! `connection::run_once(&options, &mut settings, ..)` became
//! [`ConnectOnce::run_once`], `options.reconnect` became
//! [`ConnectOnce::policy`], and `matches!(err, VncError::Cancelled)` became
//! [`RetryClassify::is_cancelled`]. [`STABLE_UPTIME`], [`Decision`] and the
//! order of the tests in [`classify`] are unchanged, which is what makes the
//! RFB behaviour identical to what it was before the move.
//!
//! Loop: attempt a connection, run it to completion, then classify the
//! outcome. Transient failures reconnect with exponential backoff and jitter;
//! authentication and security failures and user actions stop the session.
//! Session settings survive across reconnects, and they do so by living on
//! the [`ConnectOnce`] implementor rather than here: this module never sees a
//! quality preset, a pixel format or an auto reconnect cookie.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::commands::ClientCommand;
use crate::driver::emit_state;
use crate::events::SessionEvent;
use crate::options::ReconnectPolicy;
use crate::state::SessionState;

/// A connection that stayed up at least this long resets the attempt counter.
pub const STABLE_UPTIME: Duration = Duration::from_secs(60);

/// How many attempts in a row may end in [`RunOutcome::Reattempt`] before the
/// supervisor stops treating the peer as honest.
///
/// A `Reattempt` skips the backoff entirely, which is right for one RDP
/// Server Redirection (MS-RDPBCGR 2.2.13.1: a broker sends one and the client
/// reconnects to the machine it names) and wrong for a server that keeps
/// sending them. Without a bound, two servers pointing at each other are an
/// unbounded connect loop that no timer ever slows down. Eight is well above
/// any real chain: a broker redirects once, and a farm that redirects twice is
/// already unusual.
pub const MAX_CHAINED_REATTEMPTS: u32 = 8;

/// What the supervisor should do after a connection attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Schedule another attempt.
    Retry,
    /// Stop the session. `can_retry` hints whether the UI may offer a manual
    /// reconnect button (false for security problems needing user action).
    Stop {
        /// Whether a manual retry is worth offering.
        can_retry: bool,
    },
}

/// How a connection ended when it did not fail.
///
/// Moved here from `crates/vnc-core/src/session/connection.rs:65` with one
/// variant added, which the RFB path never produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// The user asked to disconnect (`ClientCommand::Disconnect`).
    UserDisconnect,
    /// The attempt ended by itself and the next one should start immediately:
    /// no backoff, no attempt counter increment, and no `Reconnecting` state.
    ///
    /// The RDP Server Redirection PDU is what produces one (MS-RDPBCGR
    /// 2.2.13.1). The implementor has already rewritten whatever it needs to,
    /// which for a redirection is the host, the port and the credentials, so
    /// the supervisor's whole job here is to go round again promptly. The
    /// user is watching a session that is about to come back, and a 250 ms
    /// backoff on a redirect the server asked for is 250 ms of nothing.
    ///
    /// Bounded by [`MAX_CHAINED_REATTEMPTS`].
    Reattempt {
        /// One line for the log, from the protocol that asked. Never shown to
        /// the user and never a secret.
        why: String,
    },
}

/// What the supervisor needs to know about one protocol's error type.
///
/// Four methods, which is exactly what `classify` and the supervisor body
/// call on `VncError` today (`crates/vnc-core/src/session/reconnect.rs:36`
/// and `:99`). `VncError` and `RdpError` each already carry three of them as
/// inherent methods, so both impls are wrappers.
pub trait RetryClassify {
    /// The session was cancelled or the shell went away. Stops the session
    /// silently: nobody is waiting for a message.
    fn is_cancelled(&self) -> bool;
    /// A failure that another attempt might get past: a dropped socket, a
    /// refused dial, a name that did not resolve, a timeout.
    fn is_transient(&self) -> bool;
    /// A failure that will happen again until a human does something: a wrong
    /// password, a changed certificate.
    fn needs_user_action(&self) -> bool;
    /// The sentence the user sees.
    fn user_message(&self) -> String;
}

/// One protocol's "make an attempt" half of the supervisor.
///
/// The implementor owns the `ConnectOptions` and whatever per session state
/// must survive a reconnect: for VNC the quality preset, view only, the
/// requested size and the scancode preference; for RDP those plus the auto
/// reconnect cookie (MS-RDPBCGR 2.2.4). remote-core never sees any of it,
/// which is the whole reason this is a trait with state rather than an
/// `async fn` (PRDRDP/02 §11.2).
pub trait ConnectOnce: Send {
    /// The protocol's error type.
    type Error: RetryClassify + std::fmt::Display;

    /// The retry ladder for this session.
    fn policy(&self) -> &ReconnectPolicy;

    /// Run one full attempt.
    ///
    /// `Ok(RunOutcome::UserDisconnect)` only for a user initiated disconnect;
    /// every failure, cancellation included, is an `Err` so the supervisor can
    /// classify it. Sets `connected_at` when the attempt reaches the connected
    /// state, which is what [`STABLE_UPTIME`] is measured from.
    ///
    /// The boxed future is the price of not taking an `async_trait`
    /// dependency and of keeping [`supervise`] usable behind a generic. It
    /// costs one allocation per connection attempt, which against a TCP
    /// connect and a TLS handshake is nothing.
    fn run_once<'a>(
        &'a mut self,
        events: &'a mpsc::Sender<SessionEvent>,
        commands: &'a mut mpsc::Receiver<ClientCommand>,
        cancel: &'a CancellationToken,
        connected_at: &'a mut Option<Instant>,
    ) -> Pin<Box<dyn Future<Output = Result<RunOutcome, Self::Error>> + Send + 'a>>;

    /// A command that arrived while the session was disconnected.
    ///
    /// Replaces the three settings arms of the RFB supervisor's `wait_backoff`
    /// (`crates/vnc-core/src/session/reconnect.rs:86` to `:90`), so "session
    /// settings survive reconnects" stays a protocol concern.
    /// `ReconnectNow`, `Disconnect` and channel closure are handled by the
    /// supervisor and never reach here.
    fn absorb_while_disconnected(&mut self, cmd: &ClientCommand);
}

/// Classify a connection failure against the reconnect policy.
///
/// `attempts_made` is the number of reconnect attempts already performed
/// (0 on the first failure of a fresh or stable connection).
///
/// The order of the four tests is load bearing and is the order the RFB
/// supervisor has always used: cancellation before everything, then the
/// failures a human has to act on, then the ones a retry cannot help, then
/// the policy.
pub fn classify<E: RetryClassify + ?Sized>(
    err: &E,
    policy: &ReconnectPolicy,
    attempts_made: u32,
) -> Decision {
    if err.is_cancelled() {
        return Decision::Stop { can_retry: false };
    }
    if err.needs_user_action() {
        // Wrong password, certificate change, ... never auto-retried.
        return Decision::Stop { can_retry: false };
    }
    if !err.is_transient() {
        // Protocol/feature errors: retrying the same server won't help, but a
        // manual retry is harmless.
        return Decision::Stop { can_retry: true };
    }
    if !policy.enabled {
        return Decision::Stop { can_retry: true };
    }
    if let Some(max) = policy.max_attempts {
        if attempts_made >= max {
            return Decision::Stop { can_retry: true };
        }
    }
    Decision::Retry
}

enum WaitOutcome {
    Elapsed,
    RetryNow,
    Stop,
}

/// Wait out the backoff delay while staying responsive to commands.
/// `ReconnectNow` interrupts the wait and resets the attempt counter.
async fn wait_backoff<C: ConnectOnce>(
    delay: Duration,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
    conn: &mut C,
) -> WaitOutcome {
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return WaitOutcome::Stop,
            _ = &mut sleep => return WaitOutcome::Elapsed,
            cmd = commands.recv() => match cmd {
                None => return WaitOutcome::Stop,
                Some(ClientCommand::ReconnectNow) => return WaitOutcome::RetryNow,
                Some(ClientCommand::Disconnect) => return WaitOutcome::Stop,
                // Keep settings changes made while disconnected, and drop
                // input and clipboard: the protocol decides which is which.
                Some(other) => conn.absorb_while_disconnected(&other),
            },
        }
    }
}

/// The supervised session task, spawned by each protocol's `Session::spawn`.
pub async fn supervise<C: ConnectOnce>(
    id: String,
    mut conn: C,
    events: mpsc::Sender<SessionEvent>,
    mut commands: mpsc::Receiver<ClientCommand>,
    cancel: CancellationToken,
) {
    let mut attempts_made: u32 = 0;
    let mut chained: u32 = 0;

    loop {
        let mut connected_at: Option<Instant> = None;
        let result = conn
            .run_once(&events, &mut commands, &cancel, &mut connected_at)
            .await;

        // A connection that stayed up long enough proves the network is fine
        // again, so backoff starts from scratch on the next drop
        // (PRD/05 §6.2).
        if let Some(t) = connected_at {
            if t.elapsed() >= STABLE_UPTIME {
                attempts_made = 0;
            }
        }

        let err = match result {
            Ok(RunOutcome::UserDisconnect) => {
                tracing::info!(session = %id, "user disconnected");
                let _ = emit_state(
                    &events,
                    SessionState::Disconnected {
                        reason: "Disconnected".into(),
                        can_retry: true,
                    },
                )
                .await;
                return;
            }
            Ok(RunOutcome::Reattempt { why }) => {
                chained += 1;
                if chained > MAX_CHAINED_REATTEMPTS {
                    tracing::warn!(
                        session = %id,
                        chained,
                        "the server asked for another immediate attempt too many times in a row"
                    );
                    let _ = emit_state(
                        &events,
                        SessionState::Disconnected {
                            reason: "The server kept redirecting this session".into(),
                            can_retry: true,
                        },
                    )
                    .await;
                    return;
                }
                tracing::info!(session = %id, chained, why, "reconnecting immediately");
                continue;
            }
            Err(e) => e,
        };
        chained = 0;

        match classify(&err, conn.policy(), attempts_made) {
            Decision::Stop { can_retry } => {
                tracing::warn!(session = %id, error = %err, "session stopped");
                if !err.is_cancelled() {
                    let _ =
                        crate::driver::emit(&events, SessionEvent::Error(err.user_message())).await;
                }
                let _ = emit_state(
                    &events,
                    SessionState::Disconnected {
                        reason: err.user_message(),
                        can_retry,
                    },
                )
                .await;
                return;
            }
            Decision::Retry => {
                attempts_made += 1;
                let delay = conn
                    .policy()
                    .delay_for(attempts_made, rand::random::<f64>());
                tracing::info!(
                    session = %id,
                    attempt = attempts_made,
                    delay_ms = delay.as_millis() as u64,
                    error = %err,
                    "reconnecting"
                );
                if emit_state(
                    &events,
                    SessionState::Reconnecting {
                        attempt: attempts_made,
                        next_retry_ms: delay.as_millis() as u64,
                        reason: err.user_message(),
                    },
                )
                .await
                .is_err()
                {
                    return; // shell is gone
                }
                match wait_backoff(delay, &mut commands, &cancel, &mut conn).await {
                    WaitOutcome::Elapsed => {}
                    WaitOutcome::RetryNow => {
                        // Network came back / user clicked "Retry now": reset
                        // backoff and go immediately.
                        attempts_made = 0;
                    }
                    WaitOutcome::Stop => {
                        let _ = emit_state(
                            &events,
                            SessionState::Disconnected {
                                reason: "Disconnected".into(),
                                can_retry: true,
                            },
                        )
                        .await;
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A protocol error type, standing in for `VncError` and `RdpError` so
    /// remote-core's own tests need no dependency on either. The four
    /// `VncError` specific classification tests stay in vnc-core, where they
    /// test `impl RetryClassify for VncError` rather than this function.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestError {
        Cancelled,
        Transient,
        Fatal,
        NeedsUser,
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{self:?}")
        }
    }

    impl RetryClassify for TestError {
        fn is_cancelled(&self) -> bool {
            matches!(self, TestError::Cancelled)
        }
        fn is_transient(&self) -> bool {
            matches!(self, TestError::Transient)
        }
        fn needs_user_action(&self) -> bool {
            matches!(self, TestError::NeedsUser)
        }
        fn user_message(&self) -> String {
            format!("{self:?}")
        }
    }

    fn policy() -> ReconnectPolicy {
        ReconnectPolicy::default()
    }

    #[test]
    fn transient_errors_retry() {
        assert_eq!(
            classify(&TestError::Transient, &policy(), 0),
            Decision::Retry
        );
    }

    #[test]
    fn user_action_errors_never_retry() {
        assert_eq!(
            classify(&TestError::NeedsUser, &policy(), 0),
            Decision::Stop { can_retry: false }
        );
    }

    #[test]
    fn fatal_errors_stop_but_allow_manual_retry() {
        assert_eq!(
            classify(&TestError::Fatal, &policy(), 0),
            Decision::Stop { can_retry: true }
        );
    }

    #[test]
    fn cancelled_stops_quietly() {
        assert_eq!(
            classify(&TestError::Cancelled, &policy(), 0),
            Decision::Stop { can_retry: false }
        );
    }

    #[test]
    fn disabled_policy_never_retries() {
        let p = ReconnectPolicy {
            enabled: false,
            ..policy()
        };
        assert_eq!(
            classify(&TestError::Transient, &p, 0),
            Decision::Stop { can_retry: true }
        );
    }

    #[test]
    fn max_attempts_respected() {
        let p = ReconnectPolicy {
            max_attempts: Some(3),
            ..policy()
        };
        assert_eq!(classify(&TestError::Transient, &p, 0), Decision::Retry);
        assert_eq!(classify(&TestError::Transient, &p, 2), Decision::Retry);
        assert_eq!(
            classify(&TestError::Transient, &p, 3),
            Decision::Stop { can_retry: true }
        );
    }

    /// A `ConnectOnce` that fails a fixed number of times and then reports
    /// whatever the test asked for, so the supervisor's own state machine can
    /// be driven with no socket.
    struct Scripted {
        policy: ReconnectPolicy,
        script: Vec<Result<RunOutcome, TestError>>,
        absorbed: usize,
    }

    impl ConnectOnce for Scripted {
        type Error = TestError;

        fn policy(&self) -> &ReconnectPolicy {
            &self.policy
        }

        fn run_once<'a>(
            &'a mut self,
            _events: &'a mpsc::Sender<SessionEvent>,
            _commands: &'a mut mpsc::Receiver<ClientCommand>,
            _cancel: &'a CancellationToken,
            _connected_at: &'a mut Option<Instant>,
        ) -> Pin<Box<dyn Future<Output = Result<RunOutcome, TestError>> + Send + 'a>> {
            Box::pin(async move {
                if self.script.is_empty() {
                    return Err(TestError::Fatal);
                }
                self.script.remove(0)
            })
        }

        fn absorb_while_disconnected(&mut self, _cmd: &ClientCommand) {
            self.absorbed += 1;
        }
    }

    fn fast_policy() -> ReconnectPolicy {
        ReconnectPolicy {
            enabled: true,
            max_attempts: Some(2),
            initial_delay_ms: 1,
            max_delay_ms: 5,
            multiplier: 2.0,
            jitter: 0.0,
        }
    }

    async fn states(rx: &mut mpsc::Receiver<SessionEvent>) -> Vec<SessionState> {
        let mut out = Vec::new();
        while let Some(ev) = rx.recv().await {
            if let SessionEvent::StateChanged(s) = ev {
                out.push(s);
            }
        }
        out
    }

    /// The ladder: two transient failures, two `Reconnecting` states, then a
    /// stop at `max_attempts` that still offers a manual retry.
    #[tokio::test]
    async fn the_ladder_climbs_then_stops_at_max_attempts() {
        let (tx, mut rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let conn = Scripted {
            policy: fast_policy(),
            script: vec![
                Err(TestError::Transient),
                Err(TestError::Transient),
                Err(TestError::Transient),
            ],
            absorbed: 0,
        };
        supervise("t".into(), conn, tx, cmd_rx, CancellationToken::new()).await;

        let states = states(&mut rx).await;
        let attempts: Vec<u32> = states
            .iter()
            .filter_map(|s| match s {
                SessionState::Reconnecting { attempt, .. } => Some(*attempt),
                _ => None,
            })
            .collect();
        assert_eq!(attempts, vec![1, 2], "{states:?}");
        assert!(matches!(
            states.last(),
            Some(SessionState::Disconnected {
                can_retry: true,
                ..
            })
        ));
    }

    /// A `Reattempt` skips the backoff and the attempt counter: the next
    /// attempt starts at once and no `Reconnecting` state is emitted, because
    /// the session is not in trouble, it is moving.
    #[tokio::test]
    async fn a_reattempt_goes_round_again_without_backoff_or_a_state_change() {
        let (tx, mut rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let conn = Scripted {
            policy: fast_policy(),
            script: vec![
                Ok(RunOutcome::Reattempt {
                    why: "redirected".into(),
                }),
                Ok(RunOutcome::UserDisconnect),
            ],
            absorbed: 0,
        };
        supervise("t".into(), conn, tx, cmd_rx, CancellationToken::new()).await;

        let states = states(&mut rx).await;
        assert!(
            !states
                .iter()
                .any(|s| matches!(s, SessionState::Reconnecting { .. })),
            "a redirect is not a reconnect: {states:?}"
        );
        assert!(matches!(
            states.last(),
            Some(SessionState::Disconnected { .. })
        ));
    }

    /// A server that redirects forever is stopped rather than followed
    /// forever, and the user is told rather than left watching a blank window.
    #[tokio::test]
    async fn an_endless_redirect_chain_is_broken() {
        let (tx, mut rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let conn = Scripted {
            policy: fast_policy(),
            script: (0..64)
                .map(|_| {
                    Ok(RunOutcome::Reattempt {
                        why: "redirected".into(),
                    })
                })
                .collect(),
            absorbed: 0,
        };
        supervise("t".into(), conn, tx, cmd_rx, CancellationToken::new()).await;

        let states = states(&mut rx).await;
        match states.last() {
            Some(SessionState::Disconnected { reason, can_retry }) => {
                assert!(reason.contains("redirect"), "{reason}");
                assert!(*can_retry);
            }
            other => panic!("expected a terminal state, got {other:?}"),
        }
    }
}
