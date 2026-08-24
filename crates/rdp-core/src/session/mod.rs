//! The session task: spawn, one attempt, the pump, and what survives a
//! reconnect (PRDRDP/12 §3.13, PRDRDP/06 §2.1).
//!
//! * [`connect`] performs one connection attempt end to end.
//! * [`cookie`] holds the auto reconnect cookie between attempts.
//! * [`redirect`] follows a Server Redirection to the machine it names.
//! * [`run_loop`] is the connected state pump.
//! * [`graphics`] decodes bitmap and pointer updates into events.
//! * [`input`] turns a [`ClientCommand`] into fast path input events.
//! * [`signal`] is the vocabulary the pump matches on.
//! * [`settings`] is the state that survives a reconnect.
//!
//! # Tasks
//!
//! One tokio task per session, spawned by [`RdpSession::spawn`], exactly as
//! `vnc_core::Session::spawn` does at
//! `crates/vnc-core/src/session/mod.rs:46`: create a bounded command channel
//! of 256, create a `CancellationToken`, build the `SessionHandle`, spawn the
//! supervisor, return the handle.
//!
//! Inside one connection attempt there are two, not one. The session task
//! owns the framer and the dispatcher; the writer task owns the write half of
//! the stream and nothing else. Neither needs to be `Sync` and neither sits
//! behind a lock, because the only state they share is the pair of byte
//! counters and the bounded channel between them, which is the whole point of
//! splitting them (PRDRDP/06 §2.1).

pub mod connect;
pub mod cookie;
pub mod graphics;
pub mod input;
pub mod redirect;
pub mod run_loop;
pub mod settings;
pub mod signal;

use std::future::Future;
use std::pin::Pin;

use remote_core::reconnect::{ConnectOnce, RetryClassify, RunOutcome};
use remote_core::{ClientCommand, ConnectOptions, ProtocolKind, SessionEvent, SessionHandle};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::RdpError;
use crate::session::cookie::ReconnectCookie;
use crate::session::redirect::Redirection;
use crate::session::run_loop::Attempt;
use crate::session::settings::RdpSessionSettings;

/// Slots in the command channel.
///
/// The same value as the RFB path (`crates/vnc-core/src/session/mod.rs:51`),
/// so both protocols drop input under the same pressure. The shell sends
/// input with `try_send`, so a full channel drops a keystroke rather than
/// delaying it, on the reasoning that a keystroke delivered four seconds late
/// is worse than one not delivered.
pub const COMMAND_QUEUE: usize = 256;

/// An RDP session. Spawns a task that connects and runs the protocol loop.
pub struct RdpSession;

impl RdpSession {
    /// Spawn a session. Events flow out through `events`.
    ///
    /// Must be called from within a tokio runtime.
    ///
    /// Kept as an inherent constructor and called by
    /// [`crate::RdpDriver::spawn`], so the integration tests that drive a
    /// session directly do not go through the registry, which is the shape
    /// `vnc_core::Session::spawn` already has.
    pub fn spawn(
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> SessionHandle {
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE);
        let cancel = CancellationToken::new();
        let handle = SessionHandle {
            id: id.clone(),
            kind: ProtocolKind::Rdp,
            commands: commands_tx,
            cancel: cancel.clone(),
        };
        tokio::spawn(supervise(id, options, events, commands_rx, cancel));
        handle
    }
}

/// What the shared supervisor needs to know about an RDP failure.
///
/// Three of the four are the inherent methods [`RdpError`] already carries
/// (`crates/rdp-core/src/error.rs:430`, `:453`, `:485`), which is why this
/// impl is a wrapper: the classification was written before the ladder that
/// consumes it (PRDRDP/06 §5.2).
impl RetryClassify for RdpError {
    fn is_cancelled(&self) -> bool {
        matches!(self, RdpError::Cancelled)
    }

    fn is_transient(&self) -> bool {
        RdpError::is_transient(self)
    }

    fn needs_user_action(&self) -> bool {
        RdpError::needs_user_action(self)
    }

    fn user_message(&self) -> String {
        RdpError::user_message(self)
    }
}

/// One RDP connection attempt, and everything about it that survives into the
/// next one (PRDRDP/06 §5.2, which sketches this struct field for field).
///
/// This is the `ConnectOnce` implementor, and the reason the supervisor takes
/// a trait with state rather than a bare async function: something has to
/// hold the auto reconnect cookie across an attempt, and a redirection has to
/// be able to rewrite the host it dials next (MS-RDPBCGR 2.2.4, 2.2.13.1).
pub struct RdpConnect {
    /// The profile, rewritten in place by a Server Redirection.
    options: ConnectOptions,
    /// What the user changed and must not lose to a dropped connection.
    settings: RdpSessionSettings,
    /// What one attempt hands to the next.
    carry: Continuity,
}

/// What one attempt reads from the last one and writes for the next.
///
/// Three fields, and each is the reason a `ConnectOnce` implementor has to be
/// a struct rather than a bare async function (PRDRDP/02 §11.2).
#[derive(Debug, Default)]
pub struct Continuity {
    /// In: the cookie to offer, when one is stored and not stale. Out: the
    /// cookie the server minted during the attempt, or `None` when it
    /// rejected ours or the user hung up (MS-RDPBCGR 2.2.4, PRDRDP/06 §5.5).
    pub cookie: Option<ReconnectCookie>,
    /// In: the `LoadBalanceInfo` a redirection told us to present in the next
    /// X.224 Connection Request's routing token (MS-RDPBCGR 3.2.5.3.1).
    pub routing_token: Option<Vec<u8>>,
    /// Out: the redirection this attempt was told to follow
    /// (MS-RDPBCGR 2.2.13.1).
    pub redirect: Option<Redirection>,
}

impl RdpConnect {
    /// A fresh session's state, from the host profile.
    #[must_use]
    pub fn new(options: ConnectOptions) -> Self {
        let settings = RdpSessionSettings::from_options(&options);
        Self {
            options,
            settings,
            carry: Continuity::default(),
        }
    }
}

impl ConnectOnce for RdpConnect {
    type Error = RdpError;

    fn policy(&self) -> &remote_core::ReconnectPolicy {
        &self.options.reconnect
    }

    fn run_once<'a>(
        &'a mut self,
        events: &'a mpsc::Sender<SessionEvent>,
        commands: &'a mut mpsc::Receiver<ClientCommand>,
        cancel: &'a CancellationToken,
        connected_at: &'a mut Option<std::time::Instant>,
    ) -> Pin<Box<dyn Future<Output = Result<RunOutcome, RdpError>> + Send + 'a>> {
        Box::pin(async move {
            self.settings.apply(&self.options);
            let outcome = connect::run_once(
                &self.options,
                &mut self.settings,
                &mut self.carry,
                events,
                commands,
                cancel,
                connected_at,
            )
            .await?;
            Ok(absorb_attempt(&mut self.options, &mut self.carry, outcome))
        })
    }

    fn absorb_while_disconnected(&mut self, cmd: &ClientCommand) {
        self.settings.absorb(cmd);
    }
}

/// Turn one attempt's outcome into the supervisor's, applying whatever the
/// attempt learned about where to go next.
///
/// Public because the integration tests drive the supervisor against the mock
/// server, which has no TLS, so they run the connection sequence themselves
/// and then take this decision with the same code the driver does
/// (`crates/rdp-core/tests/connect.rs`). The alternative is a second copy of
/// the redirection rules in a test, which is the copy that goes stale.
#[must_use]
pub fn absorb_attempt(
    options: &mut ConnectOptions,
    carry: &mut Continuity,
    outcome: Attempt,
) -> RunOutcome {
    match carry.redirect.take() {
        Some(redirect) => {
            // The cookie belongs to the session on the machine we are
            // leaving, and offering it to the target would be a wasted round
            // trip and a rejection (PRDRDP/06 §5.5.5).
            carry.cookie = None;
            let why = redirect.describe();
            redirect.apply(options, &mut carry.routing_token);
            RunOutcome::Reattempt { why }
        }
        // A logoff and an administrative close are both deliberate, and
        // reconnecting into a session the far end just ended is a loop. A
        // dropped socket is not this: it arrives as
        // `RdpError::ConnectionClosed`, which classifies as transient and
        // does climb the ladder.
        None => {
            debug_assert!(matches!(
                outcome,
                Attempt::UserDisconnect | Attempt::ServerDisconnect { .. }
            ));
            RunOutcome::UserDisconnect
        }
    }
}

/// The supervised session task spawned by [`RdpSession::spawn`].
///
/// A wrapper around the shared ladder, which is where the retry policy now
/// lives for both protocols (PRDRDP/02 §11.2, PRDRDP/06 §5.2). Before this
/// landed, this function ran one attempt and stopped.
async fn supervise(
    id: String,
    options: ConnectOptions,
    events: mpsc::Sender<SessionEvent>,
    commands: mpsc::Receiver<ClientCommand>,
    cancel: CancellationToken,
) {
    remote_core::reconnect::supervise(id, RdpConnect::new(options), events, commands, cancel).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::SessionState;

    /// The handle carries the protocol so the shell can route a command
    /// without a parallel map, and cancelling it is what closes the session.
    #[tokio::test]
    async fn spawn_returns_a_handle_that_names_the_protocol() {
        let (events, mut rx) = mpsc::channel(64);
        // Port 1 on the loopback: nothing listens, so the attempt fails fast
        // and the task finishes rather than hanging the test.
        let mut options = ConnectOptions::rdp("127.0.0.1", 1);
        options.connect_timeout = std::time::Duration::from_millis(250);
        options.reconnect.enabled = false;

        let handle = RdpSession::spawn("s1".into(), options, events);
        assert_eq!(handle.kind, ProtocolKind::Rdp);
        assert_eq!(handle.id, "s1");

        // Every failure reaches the shell as a state change, never as a
        // return value, because the caller has already opened a window by
        // this point and needs a live event stream to put an error into.
        let mut saw_disconnect = false;
        while let Some(event) = rx.recv().await {
            if let SessionEvent::StateChanged(SessionState::Disconnected { .. }) = event {
                saw_disconnect = true;
                break;
            }
        }
        assert!(saw_disconnect, "a failed attempt has to be reported");
    }

    /// A cancelled session emits nothing and closes its event channel, which
    /// is what the shell's session reaper blocks on.
    #[tokio::test]
    async fn a_cancelled_session_closes_its_event_channel() {
        let (events, mut rx) = mpsc::channel(64);
        let mut options = ConnectOptions::rdp("127.0.0.1", 1);
        options.connect_timeout = std::time::Duration::from_secs(30);

        let handle = RdpSession::spawn("s2".into(), options, events);
        handle.shutdown();

        // The channel closes when the task drops its sender, with or without
        // a final event, and `recv` returning `None` is the signal the shell
        // waits for.
        while rx.recv().await.is_some() {}
    }
}
