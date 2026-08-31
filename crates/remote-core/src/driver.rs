//! Protocol identity, the session handle, and the event sink.
//!
//! `SessionHandle`, `emit` and `emit_state` move here out of
//! `vnc-core/src/session/mod.rs` (PRDRDP/02 §4.2, §11.1). Their error types
//! change, because remote-core must not know `VncError`; vnc-core converts
//! both back with a `From` impl, so every `emit(..).await?` inside the run
//! loop keeps producing `VncError::Cancelled` exactly as it did.

use crate::commands::ClientCommand;
use crate::events::SessionEvent;
use crate::options::ConnectOptions;
use crate::state::SessionState;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Which wire protocol a session speaks.
///
/// `#[non_exhaustive]` because a third protocol is meant to cost one registry
/// line, and a shell `match` that stops compiling when a variant is added is
/// the point. There are no out of tree consumers, so it is cheap insurance.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProtocolKind {
    /// `Default` is VNC so a host row written before the protocol column
    /// existed reads as VNC with no special casing in vnc-store.
    #[default]
    Vnc,
    Rdp,
    /// A remote shell on a PTY. Unlike the other two this carries a byte
    /// stream rather than a framebuffer, which is why its payload travels as
    /// `ProtocolEvent::Ssh` rather than through the pixel variants.
    Ssh,
}

impl ProtocolKind {
    /// Every protocol, for callers that must handle all of them. A slice
    /// rather than the fixed array `PinScheme::ALL` uses, so adding one is a
    /// one line change.
    pub const ALL: &'static [ProtocolKind] =
        &[ProtocolKind::Vnc, ProtocolKind::Rdp, ProtocolKind::Ssh];

    /// The stored spelling. Matches the serde representation and the
    /// `hosts.protocol` column.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProtocolKind::Vnc => "vnc",
            ProtocolKind::Rdp => "rdp",
            ProtocolKind::Ssh => "ssh",
        }
    }

    /// Parses a stored spelling. `None` for anything unrecognised: a row
    /// written by a newer build is ignored, never guessed at, which is the
    /// rule `PinScheme::parse` already follows.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "vnc" => Some(ProtocolKind::Vnc),
            "rdp" => Some(ProtocolKind::Rdp),
            "ssh" => Some(ProtocolKind::Ssh),
            _ => None,
        }
    }

    /// The port used when the user gives a bare hostname. RFB display 0 is
    /// 5900; RDP is 3389 (MS-RDPBCGR 2.2.1.1, the X.224 Connection Request is
    /// sent to the well known TCP port 3389).
    pub const fn default_port(self) -> u16 {
        match self {
            ProtocolKind::Vnc => 5900,
            ProtocolKind::Rdp => 3389,
            // RFC 4253 §4: the SSH transport runs on TCP 22.
            ProtocolKind::Ssh => 22,
        }
    }

    /// URL scheme accepted by QuickConnect.
    pub const fn url_scheme(self) -> &'static str {
        self.as_str()
    }
}

impl std::fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The session task is gone: its command receiver was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("session is no longer running")]
pub struct SessionGone;

/// Why a non blocking send did not happen.
///
/// `PRDAgentPlug/00 R49a`. [`SessionHandle::try_send`] used to map both of
/// tokio's `TrySendError` cases onto one [`SessionGone`], and for the webview
/// that was fine: a person's next mouse move repairs either one. For the agent
/// plane it is wrong, because `08 §4.3`'s drop policy gives them OPPOSITE
/// repairs. Full means the session is alive and behind, so the caller sheds or
/// waits and reports how much was lost (`00 R24`: never silently). Closed
/// means the limb is finished, so every outstanding intent settles as
/// `LinkLost` and nothing is worth retrying. Flattened, a stalled session looks
/// dead and a dead one looks recoverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TrySendFailed {
    /// The command queue is at its bound. The session is still running.
    #[error("the session's command queue is full")]
    Full,
    /// The session task dropped its receiver.
    #[error("session is no longer running")]
    Gone,
}

impl TrySendFailed {
    /// Is this the unrecoverable one? The question a caller that only ever
    /// cared about "gone" is really asking.
    pub const fn is_gone(self) -> bool {
        matches!(self, TrySendFailed::Gone)
    }
}

/// So a caller whose own error type is already [`SessionGone`] keeps working
/// with a plain `?` and does not churn.
///
/// Lossy on purpose, and only in the direction that was already lossy: a full
/// queue arriving somewhere that has no vocabulary for it is exactly the old
/// behaviour, and a caller that wants better asks for [`TrySendFailed`].
impl From<TrySendFailed> for SessionGone {
    fn from(_: TrySendFailed) -> Self {
        SessionGone
    }
}

/// Handle to a running session, held by the shell.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub id: String,
    /// Which protocol the task on the other end of `commands` speaks. Kept on
    /// the handle rather than in a parallel map, because the shell needs it
    /// wherever it routes a command or labels a window.
    pub kind: ProtocolKind,
    pub commands: mpsc::Sender<ClientCommand>,
    pub cancel: CancellationToken,
}

impl SessionHandle {
    pub async fn send(&self, cmd: ClientCommand) -> Result<(), SessionGone> {
        self.commands.send(cmd).await.map_err(|_| SessionGone)
    }

    /// Non-async, never blocking way in. The input path uses it because input
    /// must never queue unboundedly behind a stalled session
    /// (`src-tauri/src/commands/capture.rs:126` says so on the raw sender).
    ///
    /// That discipline is unchanged. What changed is the answer: the two
    /// failures are told apart rather than flattened, for the reason on
    /// [`TrySendFailed`] (`00 R49a`).
    pub fn try_send(&self, cmd: ClientCommand) -> Result<(), TrySendFailed> {
        self.commands.try_send(cmd).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => TrySendFailed::Full,
            mpsc::error::TrySendError::Closed(_) => TrySendFailed::Gone,
        })
    }

    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

/// A protocol implementation, as the shell sees it.
///
/// One value per protocol, constructed once at startup and kept in the
/// registry. Implementations are stateless: everything per session lives in
/// the task `spawn` starts. Object safe on purpose, the shell stores
/// `Arc<dyn ProtocolDriver>`.
pub trait ProtocolDriver: Send + Sync + 'static {
    fn kind(&self) -> ProtocolKind;

    /// The port used when the user gives a bare hostname. Normally
    /// `self.kind().default_port()`; a driver may override.
    fn default_port(&self) -> u16 {
        self.kind().default_port()
    }

    /// Spawn a supervised session. Must be called from inside a tokio runtime.
    ///
    /// Returns `Err(OptionsMismatch)` when `options.protocol` is not this
    /// driver's kind. Everything else is reported through `events` as a
    /// `SessionState::Disconnected`, never as a return value: the caller has
    /// already opened a window by this point and needs a live event stream to
    /// put an error into.
    fn spawn(
        &self,
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> Result<SessionHandle, OptionsMismatch>;
}

/// A driver was handed another protocol's options.
///
/// `ConnectOptions` carries its protocol half as data, so nothing in the type
/// system stops the shell handing `RdpOptions` to the VNC driver. A caught,
/// typed error beats a `debug_assert` or a silent misparse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{expected} driver was given {actual} options")]
pub struct OptionsMismatch {
    pub expected: ProtocolKind,
    pub actual: ProtocolKind,
}

/// The shell dropped the event receiver. Every caller treats this as "tear
/// this session down", the same as a cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the event sink is closed")]
pub struct EventSinkClosed;

/// Send one event to the shell. A closed events channel means the shell is
/// gone; surface that so the session tears down.
pub async fn emit(
    events: &mpsc::Sender<SessionEvent>,
    event: SessionEvent,
) -> Result<(), EventSinkClosed> {
    events.send(event).await.map_err(|_| EventSinkClosed)
}

/// Convenience: emit a state transition.
pub async fn emit_state(
    events: &mpsc::Sender<SessionEvent>,
    state: SessionState,
) -> Result<(), EventSinkClosed> {
    emit(events, SessionEvent::StateChanged(state)).await
}

#[cfg(test)]
mod protocol_kind_tests {
    use super::*;

    /// The spelling is a stored value: the `hosts.protocol` column, the serde
    /// representation and the URL scheme must all agree.
    #[test]
    fn kind_spelling_is_stable() {
        for kind in ProtocolKind::ALL.iter().copied() {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
            assert_eq!(ProtocolKind::parse(kind.as_str()), Some(kind));
            assert_eq!(kind.url_scheme(), kind.as_str());
            assert_eq!(
                serde_json::from_str::<ProtocolKind>(&json).unwrap(),
                kind,
                "round trip"
            );
        }
        assert_eq!(ProtocolKind::parse(" RDP "), Some(ProtocolKind::Rdp));
    }

    #[test]
    fn an_unknown_protocol_does_not_degrade_into_a_known_one() {
        for junk in ["", "vnc2", "spice", "telnet", "sftp"] {
            assert_eq!(ProtocolKind::parse(junk), None, "{junk:?}");
        }
    }

    #[test]
    fn default_ports_are_the_registered_ones() {
        assert_eq!(ProtocolKind::Vnc.default_port(), 5900);
        assert_eq!(ProtocolKind::Rdp.default_port(), 3389);
        assert_eq!(ProtocolKind::Ssh.default_port(), 22);
        assert_eq!(ProtocolKind::default(), ProtocolKind::Vnc);
    }
}
