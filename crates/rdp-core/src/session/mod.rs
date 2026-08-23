//! The session task: spawn, one attempt, the pump, and what survives a
//! reconnect (PRDRDP/12 §3.13, PRDRDP/06 §2.1).
//!
//! * [`connect`] performs one connection attempt end to end.
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
pub mod graphics;
pub mod input;
pub mod run_loop;
pub mod settings;
pub mod signal;

use remote_core::{
    ClientCommand, ConnectOptions, ProtocolKind, SessionEvent, SessionHandle, SessionState,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::RdpError;
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

/// One attempt, then report what happened.
///
/// PRDRDP/12 §3.13 puts the reconnect ladder in
/// `remote_core::reconnect::supervise`, generic over a `ConnectOnce` trait
/// that PRDRDP/02 §11.2 specifies. Neither exists yet
/// (`crates/remote-core/src/lib.rs` has no `reconnect` module), so this runs
/// one attempt and stops. [`RdpError::is_transient`] and
/// [`RdpError::needs_user_action`] are already written and already tested, so
/// the classification the ladder needs is in place; what is missing is the
/// ladder. The report names it.
async fn supervise(
    id: String,
    options: ConnectOptions,
    events: mpsc::Sender<SessionEvent>,
    mut commands: mpsc::Receiver<ClientCommand>,
    cancel: CancellationToken,
) {
    let mut settings = RdpSessionSettings::from_options(&options);
    let result = connect::run_once(&options, &mut settings, &events, &mut commands, &cancel).await;

    let (reason, can_retry) = match result {
        Ok(outcome) => {
            tracing::info!(session = %id, ?outcome, "the rdp session ended");
            ("Disconnected".to_owned(), true)
        }
        Err(RdpError::Cancelled) => {
            // The window is gone. Nobody is waiting for a message, and
            // emitting one races the shell dropping the receiver.
            tracing::debug!(session = %id, "the rdp session was cancelled");
            return;
        }
        Err(e) => {
            tracing::warn!(session = %id, error = %e, "the rdp session failed");
            let can_retry = !e.needs_user_action();
            (e.user_message(), can_retry)
        }
    };

    // A closed events channel means the shell is already gone, which is the
    // one case where there is nobody to tell.
    let _ =
        remote_core::emit_state(&events, SessionState::Disconnected { reason, can_retry }).await;
}

#[cfg(test)]
mod tests {
    use super::*;

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
