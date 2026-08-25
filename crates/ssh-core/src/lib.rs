//! # ssh-core
//!
//! A remote shell that behaves itself: it reconnects when the link drops,
//! notices when the link hangs instead of sitting there, comes back to the
//! *same* remote session rather than an empty new one, and never leaves the
//! local terminal spraying escape codes when the far side dies mid-`tmux`.
//!
//! Those four are the standing complaints about running `ssh` in a window,
//! and each has a module:
//!
//! | complaint | module |
//! |---|---|
//! | "it dropped and I had to reconnect by hand" | [`session`], over `remote-core`'s backoff policy |
//! | "it hung and I waited minutes to find out" | [`ssh_transport::Keepalive::interactive`] |
//! | "I reconnected and my work was gone" | [`options::MultiplexerConfig`], attach-or-create |
//! | "moving the mouse prints garbage after it died" | [`modes`] |
//!
//! The last one is the least obvious and the most irritating. A program like
//! `tmux` or `vim` switches the terminal into mouse-reporting mode and is
//! expected to switch it back on exit. When the link is severed it never gets
//! to, so the local terminal keeps encoding every mouse movement as an escape
//! sequence and dumping it at the shell prompt. [`modes::ModeTracker`] watches
//! what the remote turned on and turns it back off itself.
//!
//! ```no_run
//! # async fn demo() -> Result<(), ssh_core::Error> {
//! use std::sync::Arc;
//! use parking_lot::Mutex;
//! use ssh_core::{SshSession, SshTermOptions};
//! use ssh_transport::{HostKeyStore, SshConfig};
//!
//! // One pin store answers for the terminal, the Files panel and the RFB
//! // tunnel alike, so trusting a machine once covers all three.
//! let pins = Arc::new(Mutex::new(HostKeyStore::new()));
//!
//! let options = SshTermOptions::new(SshConfig::new("box.local", "gj"));
//! let (session, mut events) = SshSession::spawn(options, pins.clone());
//!
//! session.resize(120, 40).await?;
//! session.input(b"uptime\n".to_vec()).await?;
//!
//! while let Some(event) = events.recv().await {
//!     // Feed `Output` and `ResetTerminal` bytes straight to the emulator.
//!     let _ = event;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Layout
//!
//! | module | responsibility |
//! |---|---|
//! | [`options`] | geometry, `TERM`, the multiplexer, the retry ladder |
//! | [`modes`] | which private modes the remote turned on, and how to undo them |
//! | [`pty`] | the `pty-req`, the pre-flight probe, starting the shell |
//! | [`session`] | the supervisor loop and the byte pump |
//! | [`events`] | the IPC-shaped event and command types |
//! | [`error`] | failures, classified for the supervisor |

#![forbid(unsafe_code)]

pub mod error;
pub mod events;
pub mod modes;
pub mod options;
pub mod pty;
pub mod session;

pub use error::{Error, Result};
pub use events::{SshCommand, SshEvent, TerminalState};
pub use modes::ModeTracker;
pub use multiplexer::{
    parse_wsl_distros, Detected, MultiplexerConfig, MultiplexerKind, ShellDialect, WSL_LIST_COMMAND,
};
pub use options::{ReconnectPolicy, SshTermOptions, TerminalOptions, DEFAULT_TERM};
pub use session::SshSession;
pub mod multiplexer;

pub mod driver;

pub use driver::SshDriver;

#[cfg(test)]
pub(crate) mod test_support {
    use ssh_transport::hostkey::{HostKeyDecision, HostKeyVerifier};

    /// Accepts any host key. Tests here are about the PTY and the supervisor;
    /// TOFU is `ssh-transport`'s and is tested there.
    pub struct TrustAll;

    impl HostKeyVerifier for TrustAll {
        fn verify(&self, _: &str, _: u16, _: &str, _: &str) -> HostKeyDecision {
            HostKeyDecision::Trusted
        }
    }
}
