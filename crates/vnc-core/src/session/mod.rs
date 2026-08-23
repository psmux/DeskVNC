//! Session supervision: connect, run, and auto-reconnect.
//!
//! Owned by the session agent. See PRD/05-session-ux.md §6.
//!
//! - [`connection`] performs one connection attempt end-to-end.
//! - [`run_loop`] is the connected-state protocol pump.
//! - [`reconnect`] is the supervisor implementing the auto-reconnect policy.
//!
//! [`SessionHandle`], [`emit`] and [`emit_state`] moved to `remote-core` and
//! are re-exported here at their old paths (PRDRDP/02 §4.2, §11.1).

pub(crate) mod connection;
pub(crate) mod reconnect;
pub(crate) mod run_loop;

use crate::types::{ConnectOptions, SessionEvent};
use remote_core::{OptionsMismatch, ProtocolDriver, ProtocolKind};
use tokio::sync::mpsc;

pub use remote_core::SessionHandle;
// `pub(crate)`, as they were before the move: the run loop and the connection
// path call them, nothing outside this crate ever did.
pub(crate) use remote_core::{emit, emit_state};

/// A VNC session. Spawns a supervised task that connects, runs the protocol
/// loop, and reconnects automatically on transient failure.
pub struct Session;

impl Session {
    /// Spawn a supervised session. Events flow out through `events`.
    ///
    /// Must be called from within a tokio runtime.
    ///
    /// Kept as an inherent constructor, and called by
    /// [`VncDriver::spawn`], so the integration tests and the examples that
    /// drive a session directly do not go through the registry.
    pub fn spawn(
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> SessionHandle {
        let (commands_tx, commands_rx) = mpsc::channel(256);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = SessionHandle {
            id: id.clone(),
            kind: ProtocolKind::Vnc,
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

/// The RFB protocol, as the shell's registry sees it (PRDRDP/02 §4.3).
///
/// Stateless: everything per session lives in the task [`Session::spawn`]
/// starts.
///
/// ```
/// use remote_core::{ProtocolDriver, ProtocolKind};
/// let driver = vnc_core::VncDriver::new();
/// assert_eq!(driver.kind(), ProtocolKind::Vnc);
/// assert_eq!(driver.default_port(), 5900);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct VncDriver;

impl VncDriver {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDriver for VncDriver {
    fn kind(&self) -> ProtocolKind {
        ProtocolKind::Vnc
    }

    fn spawn(
        &self,
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> Result<SessionHandle, OptionsMismatch> {
        let actual = options.kind();
        if actual != ProtocolKind::Vnc {
            return Err(OptionsMismatch {
                expected: ProtocolKind::Vnc,
                actual,
            });
        }
        Ok(Session::spawn(id, options, events))
    }
}

#[cfg(test)]
mod driver_tests {
    use super::*;
    use remote_core::ConnectOptions;

    /// `ConnectOptions` carries its protocol half as data, so nothing in the
    /// type system stops the shell handing RDP options to this driver. It has
    /// to be caught, and caught before a task exists.
    #[test]
    fn the_vnc_driver_refuses_rdp_options() {
        let (events, _rx) = mpsc::channel(1);
        let err = VncDriver::new()
            .spawn("s1".into(), ConnectOptions::rdp("h", 3389), events)
            .expect_err("RDP options must not reach the RFB session");
        assert_eq!(err.expected, ProtocolKind::Vnc);
        assert_eq!(err.actual, ProtocolKind::Rdp);
        assert_eq!(err.to_string(), "vnc driver was given rdp options");
    }
}
