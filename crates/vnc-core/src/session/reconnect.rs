//! The session supervisor: auto-retry and fast reconnect (PRD/05 §6).
//!
//! Loop: attempt a connection, run it to completion, then classify the
//! outcome. Transient failures reconnect with exponential backoff + jitter;
//! auth/security failures and user actions stop the session. Session settings
//! (quality, view-only, requested resolution) survive across reconnects.

use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::VncError;
use crate::types::{ClientCommand, ConnectOptions, ReconnectPolicy, SessionEvent, SessionState};

use super::connection::{self, RunOutcome, SessionSettings};
use super::emit_state;

/// A connection that stayed up at least this long resets the attempt counter.
const STABLE_UPTIME: Duration = Duration::from_secs(60);

/// What the supervisor should do after a connection attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Schedule another attempt.
    Retry,
    /// Stop the session. `can_retry` hints whether the UI may offer a manual
    /// reconnect button (false for security problems needing user action).
    Stop { can_retry: bool },
}

/// Classify a connection failure against the reconnect policy.
///
/// `attempts_made` is the number of reconnect attempts already performed
/// (0 on the first failure of a fresh/stable connection).
pub(crate) fn classify(err: &VncError, policy: &ReconnectPolicy, attempts_made: u32) -> Decision {
    if matches!(err, VncError::Cancelled) {
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
async fn wait_backoff(
    delay: Duration,
    commands: &mut mpsc::Receiver<ClientCommand>,
    cancel: &CancellationToken,
    settings: &mut SessionSettings,
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
                // Keep settings changes made while disconnected.
                Some(ClientCommand::SetQuality(q)) => settings.quality = q,
                Some(ClientCommand::SetViewOnly(v)) => settings.view_only = v,
                Some(ClientCommand::RequestResize { width, height }) => {
                    settings.requested_size = Some((width, height));
                }
                // Input/clipboard while disconnected is dropped.
                Some(_) => {}
            },
        }
    }
}

/// The supervised session task spawned by `Session::spawn`.
pub(crate) async fn supervise(
    id: String,
    options: ConnectOptions,
    events: mpsc::Sender<SessionEvent>,
    mut commands: mpsc::Receiver<ClientCommand>,
    cancel: CancellationToken,
) {
    let mut settings = SessionSettings::from_options(&options);
    let mut attempts_made: u32 = 0;

    loop {
        let mut connected_at: Option<Instant> = None;
        let result = connection::run_once(
            &options,
            &mut settings,
            &events,
            &mut commands,
            &cancel,
            &mut connected_at,
        )
        .await;

        // A connection that stayed up long enough proves the network is fine
        // again, start backoff from scratch on the next drop (PRD/05 §6.2).
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
            Err(e) => e,
        };

        match classify(&err, &options.reconnect, attempts_made) {
            Decision::Stop { can_retry } => {
                tracing::warn!(session = %id, error = %err, "session stopped");
                if !matches!(err, VncError::Cancelled) {
                    let _ = super::emit(&events, SessionEvent::Error(err.user_message())).await;
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
                let delay = options
                    .reconnect
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
                match wait_backoff(delay, &mut commands, &cancel, &mut settings).await {
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
        let mut o = ConnectOptions::new("127.0.0.1", 1);
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
