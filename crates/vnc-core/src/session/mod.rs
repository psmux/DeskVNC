//! Session supervision: connect, run, and auto-reconnect.
//!
//! Owned by the session agent. See PRD/05-session-ux.md §6.
//!
//! - [`connection`] performs one connection attempt end-to-end.
//! - [`run_loop`] is the connected-state protocol pump.
//! - [`reconnect`] is the supervisor implementing the auto-reconnect policy.

pub(crate) mod connection;
pub(crate) mod reconnect;
pub(crate) mod run_loop;

use crate::error::Result;
use crate::types::{ClientCommand, ConnectOptions, SessionEvent, SessionState};
use tokio::sync::mpsc;

/// Handle to a running session, held by the shell.
#[derive(Debug)]
pub struct SessionHandle {
    pub id: String,
    pub commands: mpsc::Sender<ClientCommand>,
    pub cancel: tokio_util::sync::CancellationToken,
}

impl SessionHandle {
    pub async fn send(&self, cmd: ClientCommand) -> Result<()> {
        self.commands
            .send(cmd)
            .await
            .map_err(|_| crate::VncError::ConnectionClosed)
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

/// A VNC session. Spawns a supervised task that connects, runs the protocol
/// loop, and reconnects automatically on transient failure.
pub struct Session;

impl Session {
    /// Spawn a supervised session. Events flow out through `events`.
    ///
    /// Must be called from within a tokio runtime.
    pub fn spawn(
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> SessionHandle {
        let (commands_tx, commands_rx) = mpsc::channel(256);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = SessionHandle {
            id: id.clone(),
            commands: commands_tx,
            cancel: cancel.clone(),
        };
        tokio::spawn(reconnect::supervise(
            id,
            options,
            events,
            commands_rx,
            cancel,
        ));
        handle
    }
}

/// Send one event to the shell. A closed events channel means the shell is
/// gone; surface that as `Cancelled` so the session tears down.
pub(crate) async fn emit(events: &mpsc::Sender<SessionEvent>, event: SessionEvent) -> Result<()> {
    events
        .send(event)
        .await
        .map_err(|_| crate::VncError::Cancelled)
}

/// Convenience: emit a state transition.
pub(crate) async fn emit_state(
    events: &mpsc::Sender<SessionEvent>,
    state: SessionState,
) -> Result<()> {
    emit(events, SessionEvent::StateChanged(state)).await
}
