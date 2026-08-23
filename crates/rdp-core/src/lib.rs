//! # rdp-core
//!
//! The RDP session: transport, the connection sequence, the channel map, the
//! lifecycle and the stats. Implements [`remote_core::ProtocolDriver`]
//! (AGENT_BRIEF D12, PRDRDP/12 §2.2.4, §3.5).
//!
//! This is the only crate in the RDP set that owns a socket or a tokio task.
//! `rdp-pdu`, `rdp-codecs` and `rdp-auth` are pure: they parse, they encode
//! and they hold state machines over byte slices, and this crate does the
//! I/O for all three.
//!
//! ## Module map
//!
//! | Module         | Responsibility                                           |
//! |----------------|----------------------------------------------------------|
//! | [`options`]    | `RdpOptions` validation and resolution                   |
//! | [`error`]      | [`RdpError`], [`ConnectStage`], the retry classification |
//! | [`transport`]  | Opening the stream, TLS, the framer, the writer task     |
//! | [`connection`] | The connection sequence, X.224 to `Connected`            |
//! | [`channels`]   | The virtual channels: drdynvc, EGFX, the clipboard       |
//! | [`session`]    | The session task, the run loop, the settings             |
//!
//! ## Concurrency
//!
//! Two tasks per session and three channels between them:
//!
//! ```text
//!            shell
//!   events 256 |  ^ commands 256
//!              v  |
//!         session task ---- Outbound, 64 ----> writer task
//!         owns the framer                      owns the write half
//!         owns the dispatcher                  owns the sent counter
//! ```
//!
//! The session task never holds a writer, which is what makes "no write
//! inside a `select!` arm" structural rather than a convention: `write_all`
//! is not cancellation safe and no wrapper makes it so, while the framer's
//! read is cancellation safe by construction (PRDRDP/00 R10,
//! [`transport::framer`]).
//!
//! Backpressure is the bounded channels and nothing else. A slow webview
//! fills the 256 slot event channel, `emit` blocks, the session task stops
//! polling the framer, the TCP receive window closes, and the server slows
//! down. Nothing is dropped and nothing is buffered without bound.
//!
//! ## What works today
//!
//! The whole connection sequence of MS-RDPBCGR 1.3.1.1: X.224 negotiation, the
//! TLS upgrade, CredSSP through [`rdp_auth::CredSspClient`], the MCS Connect
//! Initial with its GCC blocks, the Connect Response, Erect Domain, Attach
//! User and the channel joins, the Client Info PDU, licensing, the capability
//! exchange and the connection finalisation. The session reaches
//! [`remote_core::SessionState::Connected`] when the Font Map arrives.
//!
//! After that the pump decodes legacy bitmap updates on both the fast path and
//! the slow path into dirty rectangles, turns pointer updates into cursor
//! shapes and positions, and sends fast path input. A Deactivate All and the
//! Demand Active that follows it are answered from inside the pump, so a
//! resolution change on the server does not end the session.
//!
//! An unpinned server key, which is what nearly every RDP host serves on first
//! contact, raises `SessionEvent::CertificatePrompt` and parks the sequence on
//! the answer. The prompt completes before CredSSP starts, so nothing that
//! depends on the server's identity leaves the client until the user has
//! approved that identity ([`connection::trust`]).
//!
//! The virtual channels are wired up ([`channels`]): `drdynvc` multiplexes the
//! dynamic channels, the graphics pipeline decodes EGFX into surfaces and
//! acknowledges frames, and `cliprdr` moves text both ways.
//!
//! What is still missing, each reported as a typed error naming its phase
//! rather than as a panic:
//!
//! * The legacy Surface Bits path (MS-RDPBCGR 2.2.9.2.1). The Surface Commands
//!   capability set is still deliberately not advertised, so a server falls
//!   back to Bitmap Updates rather than drawing into a surface we cannot
//!   decode. EGFX is a different negotiation and having it does not change
//!   this ([`connection::activate::client_capabilities`]).
//! * H.264 and RemoteFX Progressive. The graphics channel advertises
//!   capability set versions 8 and 8.1, which have no H.264 in them, and a
//!   progressive rectangle is refused by name because `rdp-codecs` has no
//!   progressive decoder in a default build.
//! * Audio, display control and file clipboard transfer.
//! * `remote_core::reconnect::supervise` and its `ConnectOnce` trait do not
//!   exist, so a failed attempt reports and stops rather than retrying.
//!
//! ## Rules
//!
//! No Tauri, ever: this crate outlives the frontend. No cryptography: TLS
//! comes from `vnc-transport` and NTLM and CredSSP from `rdp-auth`
//! (AGENT_BRIEF V3-A). Whole framebuffers never cross a channel as one
//! value; decoded pixels travel as dirty rects.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod channels;
pub mod connection;
pub mod error;
pub mod options;
pub mod session;
pub mod transport;

pub use error::{ConnectStage, RdpError, Result};
pub use session::RdpSession;

use remote_core::{
    ConnectOptions, OptionsMismatch, ProtocolDriver, ProtocolKind, SessionEvent, SessionHandle,
};
use tokio::sync::mpsc;

/// The RDP protocol, as the shell's registry sees it (PRDRDP/02 §4.3).
///
/// Stateless: everything per session lives in the task [`RdpSession::spawn`]
/// starts.
///
/// ```
/// use remote_core::{ProtocolDriver, ProtocolKind};
/// let driver = rdp_core::RdpDriver::new();
/// assert_eq!(driver.kind(), ProtocolKind::Rdp);
/// assert_eq!(driver.default_port(), 3389);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct RdpDriver;

impl RdpDriver {
    /// The driver. Constructed once at startup and kept in the registry.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolDriver for RdpDriver {
    fn kind(&self) -> ProtocolKind {
        ProtocolKind::Rdp
    }

    // `default_port` is deliberately not overridden: `ProtocolKind::Rdp`
    // already answers 3389, citing MS-RDPBCGR 2.2.1.1
    // (`crates/remote-core/src/driver.rs:66`), and a second copy of the
    // number is a second place for it to be wrong.

    fn spawn(
        &self,
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> std::result::Result<SessionHandle, OptionsMismatch> {
        let actual = options.kind();
        if actual != ProtocolKind::Rdp {
            return Err(OptionsMismatch {
                expected: ProtocolKind::Rdp,
                actual,
            });
        }
        Ok(RdpSession::spawn(id, options, events))
    }
}

#[cfg(test)]
mod driver_tests {
    use super::*;

    /// `ConnectOptions` carries its protocol half as data, so nothing in the
    /// type system stops the shell handing VNC options to this driver. It has
    /// to be caught, and caught before a task exists.
    #[test]
    fn the_rdp_driver_refuses_vnc_options() {
        let (events, _rx) = mpsc::channel(1);
        let err = RdpDriver::new()
            .spawn("s1".into(), ConnectOptions::vnc("h", 5900), events)
            .expect_err("VNC options must not reach the RDP session");
        assert_eq!(err.expected, ProtocolKind::Rdp);
        assert_eq!(err.actual, ProtocolKind::Vnc);
        assert_eq!(err.to_string(), "rdp driver was given vnc options");
    }

    /// The port a bare hostname gets. MS-RDPBCGR 2.2.1.1 sends the X.224
    /// Connection Request to the well known TCP port 3389.
    #[test]
    fn the_default_port_is_3389() {
        assert_eq!(RdpDriver::new().default_port(), 3389);
        assert_eq!(RdpDriver::new().kind(), ProtocolKind::Rdp);
    }
}
