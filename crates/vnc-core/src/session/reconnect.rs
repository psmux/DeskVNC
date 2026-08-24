//! The session supervisor: auto-retry and fast reconnect (PRD/05 §6).
//!
//! The ladder itself moved to `remote_core::reconnect` in phase 1, generic
//! over a [`ConnectOnce`] implementor, so RFB and RDP share one retry
//! policy instead of two that have to be kept identical by hand
//! (PRDRDP/02 §11.2, PRDRDP/06 §5.2). What is left here is this protocol's
//! three quarters of that trait: which errors are worth retrying
//! ([`RetryClassify`] for [`VncError`]), what one attempt is
//! ([`VncConnect`]), and which settings survive a reconnect. The behaviour is
//! unchanged, which the eight tests below are unchanged in order to say.
//!
//! Loop: attempt a connection, run it to completion, then classify the
//! outcome. Transient failures reconnect with exponential backoff + jitter;
//! auth/security failures and user actions stop the session. Session settings
//! (quality, view-only, requested resolution) survive across reconnects.

use std::future::Future;
use std::pin::Pin;
use std::time::Instant;
// The supervisor tests below drive the ladder with millisecond delays.
#[cfg(test)]
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::VncError;
use crate::types::{ClientCommand, ConnectOptions, ReconnectPolicy, SessionEvent};

use super::connection::{self, SessionSettings};

// The supervisor's own vocabulary, re-exported at the paths this module used
// to define them at, so every caller and every test below is unchanged.
pub(crate) use remote_core::reconnect::{RetryClassify, RunOutcome};
// Only the classification tests below name these now: the ladder that used to
// call `classify` lives in remote-core and calls the generic form directly.
#[cfg(test)]
pub(crate) use remote_core::reconnect::Decision;

/// What the shared supervisor needs to know about an RFB failure.
///
/// Three of the four are the inherent methods `VncError` already had
/// (`crates/vnc-core/src/error.rs:106`, `:118`, `:129`), and the fourth is the
/// `matches!(err, VncError::Cancelled)` the old supervisor body did inline.
impl RetryClassify for VncError {
    fn is_cancelled(&self) -> bool {
        matches!(self, VncError::Cancelled)
    }

    fn is_transient(&self) -> bool {
        VncError::is_transient(self)
    }

    fn needs_user_action(&self) -> bool {
        VncError::needs_user_action(self)
    }

    fn user_message(&self) -> String {
        VncError::user_message(self)
    }
}

/// Classify a connection failure against the reconnect policy.
///
/// `attempts_made` is the number of reconnect attempts already performed
/// (0 on the first failure of a fresh/stable connection).
///
/// A one line call into `remote_core::reconnect::classify`, kept at this path
/// because the four tests below are tests of what `VncError` classifies as,
/// and those are worth keeping next to the error type rather than moving to a
/// crate that cannot name it.
#[cfg(test)]
pub(crate) fn classify(err: &VncError, policy: &ReconnectPolicy, attempts_made: u32) -> Decision {
    remote_core::reconnect::classify(err, policy, attempts_made)
}

/// One RFB connection attempt, and everything about it that survives into the
/// next one.
///
/// `SessionSettings` lives here rather than in remote-core because it is RFB
/// state: a pixel format preference, an encoding list and a lossless refresh
/// flag mean nothing to another protocol (PRDRDP/02 §11.2).
pub(crate) struct VncConnect {
    options: ConnectOptions,
    settings: SessionSettings,
}

impl VncConnect {
    pub(crate) fn new(options: ConnectOptions) -> Self {
        let settings = SessionSettings::from_options(&options);
        Self { options, settings }
    }
}

impl remote_core::reconnect::ConnectOnce for VncConnect {
    type Error = VncError;

    fn policy(&self) -> &ReconnectPolicy {
        &self.options.reconnect
    }

    fn run_once<'a>(
        &'a mut self,
        events: &'a mpsc::Sender<SessionEvent>,
        commands: &'a mut mpsc::Receiver<ClientCommand>,
        cancel: &'a CancellationToken,
        connected_at: &'a mut Option<Instant>,
    ) -> Pin<Box<dyn Future<Output = Result<RunOutcome, VncError>> + Send + 'a>> {
        Box::pin(async move {
            connection::run_once(
                &self.options,
                &mut self.settings,
                events,
                commands,
                cancel,
                connected_at,
            )
            .await
            // RFB has exactly one way for an attempt to end without failing.
            // `RunOutcome::Reattempt` is the RDP redirection case and nothing
            // here produces one.
            .map(|connection::RunOutcome::UserDisconnect| RunOutcome::UserDisconnect)
        })
    }

    fn absorb_while_disconnected(&mut self, cmd: &ClientCommand) {
        // The three arms the old `wait_backoff` carried inline
        // (this file at :86 to :90 before the move). Everything else,
        // input and clipboard while disconnected, is dropped.
        match cmd {
            ClientCommand::SetQuality(q) => self.settings.quality = *q,
            ClientCommand::SetViewOnly(v) => self.settings.view_only = *v,
            ClientCommand::RequestResize { width, height } => {
                self.settings.requested_size = Some((*width, *height));
            }
            _ => {}
        }
    }
}

/// The supervised session task spawned by `Session::spawn`.
pub(crate) async fn supervise(
    id: String,
    options: ConnectOptions,
    events: mpsc::Sender<SessionEvent>,
    commands: mpsc::Receiver<ClientCommand>,
    cancel: CancellationToken,
) {
    remote_core::reconnect::supervise(id, VncConnect::new(options), events, commands, cancel).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{QualityPreset, SessionState};

    fn policy() -> ReconnectPolicy {
        ReconnectPolicy::default()
    }

    // ---- transient vs fatal classification -------------------------------

    #[test]
    fn transient_errors_retry() {
        for err in [
            VncError::ConnectionClosed,
            VncError::Timeout,
            VncError::ConnectionRefused("h:5900".into()),
            VncError::ResolveFailed("h".into()),
            VncError::Io(std::io::Error::other("reset")),
        ] {
            assert_eq!(classify(&err, &policy(), 0), Decision::Retry, "{err}");
        }
    }

    #[test]
    fn user_action_errors_never_retry() {
        for err in [
            VncError::AuthFailed("bad password".into()),
            VncError::CredentialsRequired("password".into()),
            VncError::CertificateMismatch {
                expected: "aa".into(),
                actual: "bb".into(),
            },
            VncError::CertificateUntrusted("unknown ca".into()),
        ] {
            assert_eq!(
                classify(&err, &policy(), 0),
                Decision::Stop { can_retry: false },
                "{err}"
            );
        }
    }

    #[test]
    fn protocol_errors_stop_but_allow_manual_retry() {
        for err in [
            VncError::Protocol("garbage".into()),
            VncError::UnsupportedVersion("RFB 002.000".into()),
            VncError::NoSupportedSecurityType(vec![99]),
            VncError::UnsupportedEncoding(1234),
        ] {
            assert_eq!(
                classify(&err, &policy(), 0),
                Decision::Stop { can_retry: true },
                "{err}"
            );
        }
    }

    #[test]
    fn cancelled_stops_quietly() {
        assert_eq!(
            classify(&VncError::Cancelled, &policy(), 0),
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
            classify(&VncError::Timeout, &p, 0),
            Decision::Stop { can_retry: true }
        );
    }

    #[test]
    fn max_attempts_respected() {
        let p = ReconnectPolicy {
            max_attempts: Some(3),
            ..policy()
        };
        assert_eq!(classify(&VncError::Timeout, &p, 0), Decision::Retry);
        assert_eq!(classify(&VncError::Timeout, &p, 2), Decision::Retry);
        assert_eq!(
            classify(&VncError::Timeout, &p, 3),
            Decision::Stop { can_retry: true }
        );
    }

    // ---- backoff schedule -------------------------------------------------

    #[test]
    fn backoff_schedule_matches_prd() {
        // 250ms -> 500 -> 1s -> 2s -> 4s -> 8s -> capped 15s. rand_unit 0.5
        // lands exactly on the un-jittered value.
        let p = policy();
        let expect = [250, 500, 1000, 2000, 4000, 8000, 15_000, 15_000, 15_000];
        for (i, &ms) in expect.iter().enumerate() {
            let d = p.delay_for(i as u32 + 1, 0.5);
            assert_eq!(d.as_millis() as u64, ms, "attempt {}", i + 1);
        }
    }

    #[test]
    fn backoff_jitter_stays_in_band() {
        let p = policy();
        for attempt in 1..10 {
            for unit in [0.0, 0.25, 0.75, 0.999] {
                let base = p.delay_for(attempt, 0.5).as_millis() as f64;
                let d = p.delay_for(attempt, unit).as_millis() as f64;
                let span = base * p.jitter;
                assert!(d >= base - span - 1.0 && d <= base + span + 1.0);
            }
        }
    }

    // ---- supervisor state machine ----------------------------------------

    async fn drain_states(
        events: &mut mpsc::Receiver<SessionEvent>,
        deadline: Duration,
    ) -> Vec<SessionState> {
        let mut states = Vec::new();
        let end = tokio::time::Instant::now() + deadline;
        loop {
            let ev = tokio::select! {
                _ = tokio::time::sleep_until(end) => break,
                ev = events.recv() => match ev { Some(e) => e, None => break },
            };
            if let SessionEvent::StateChanged(s) = ev {
                let terminal = matches!(s, SessionState::Disconnected { .. });
                states.push(s);
                if terminal {
                    break;
                }
            }
        }
        states
    }

    fn unreachable_options() -> ConnectOptions {
        // Port 1 on localhost: virtually always closed -> fast refusal, which
        // is a transient error.
        let mut o = ConnectOptions::vnc("127.0.0.1", 1);
        o.quality = QualityPreset::Auto;
        o.connect_timeout = Duration::from_secs(2);
        o.reconnect = ReconnectPolicy {
            enabled: true,
            max_attempts: Some(2),
            initial_delay_ms: 1,
            max_delay_ms: 5,
            multiplier: 2.0,
            jitter: 0.0,
        };
        o
    }

    #[tokio::test]
    async fn supervisor_retries_transient_then_stops_at_max_attempts() {
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let sup = tokio::spawn(supervise(
            "test".into(),
            unreachable_options(),
            events_tx,
            cmd_rx,
            cancel,
        ));
        let states = drain_states(&mut events_rx, Duration::from_secs(15)).await;
        sup.await.unwrap();

        let reconnecting: Vec<_> = states
            .iter()
            .filter_map(|s| match s {
                SessionState::Reconnecting { attempt, .. } => Some(*attempt),
                _ => None,
            })
            .collect();
        assert_eq!(reconnecting, vec![1, 2], "states: {states:?}");
        match states.last() {
            Some(SessionState::Disconnected { can_retry, .. }) => assert!(*can_retry),
            other => panic!("expected terminal Disconnected, got {other:?}"),
        }
        // Resolving/Connecting must precede each attempt.
        assert!(matches!(states[0], SessionState::Resolving));
        assert!(matches!(states[1], SessionState::Connecting));
    }

    #[tokio::test]
    async fn reconnect_now_interrupts_backoff_and_resets_attempts() {
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut options = unreachable_options();
        // Enormous backoff: only ReconnectNow can get us to a second attempt
        // quickly.
        options.reconnect = ReconnectPolicy {
            enabled: true,
            max_attempts: None,
            initial_delay_ms: 3_600_000,
            max_delay_ms: 3_600_000,
            multiplier: 1.0,
            jitter: 0.0,
        };
        let cancel2 = cancel.clone();
        let sup = tokio::spawn(supervise(
            "test".into(),
            options,
            events_tx,
            cmd_rx,
            cancel2,
        ));

        // Wait for the first Reconnecting state.
        let mut saw_reconnecting = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events_rx.recv()).await {
            if let SessionEvent::StateChanged(SessionState::Reconnecting { attempt, .. }) = &ev {
                assert_eq!(*attempt, 1);
                saw_reconnecting = true;
                break;
            }
        }
        assert!(saw_reconnecting);

        // Interrupt the (1 hour) wait.
        cmd_tx.send(ClientCommand::ReconnectNow).await.unwrap();

        // We must promptly see a fresh attempt (Resolving) and, after it fails
        // again, a Reconnecting with attempt == 1 (counter was reset).
        let mut saw_resolving = false;
        let mut next_attempt = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events_rx.recv()).await {
            match ev {
                SessionEvent::StateChanged(SessionState::Resolving) => saw_resolving = true,
                SessionEvent::StateChanged(SessionState::Reconnecting { attempt, .. }) => {
                    next_attempt = Some(attempt);
                    break;
                }
                _ => {}
            }
        }
        assert!(
            saw_resolving,
            "ReconnectNow did not trigger an immediate attempt"
        );
        assert_eq!(next_attempt, Some(1), "attempt counter was not reset");

        cancel.cancel();
        let _ = sup.await;
    }

    #[tokio::test]
    async fn cancel_stops_supervisor() {
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let mut options = unreachable_options();
        options.reconnect.max_attempts = None;
        options.reconnect.initial_delay_ms = 3_600_000;
        options.reconnect.max_delay_ms = 3_600_000;
        let sup = tokio::spawn(supervise(
            "test".into(),
            options,
            events_tx,
            cmd_rx,
            cancel.clone(),
        ));
        // Let it fail once and enter backoff, then cancel.
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
        sup.await.unwrap();
        let states = drain_states(&mut events_rx, Duration::from_secs(2)).await;
        assert!(
            matches!(states.last(), Some(SessionState::Disconnected { .. })),
            "states: {states:?}"
        );
    }
}
