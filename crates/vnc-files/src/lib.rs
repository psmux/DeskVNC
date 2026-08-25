//! # vnc-files
//!
//! File transfer for DeskVNCViewer, over an **SFTP sidecar** (PRD/08 §2.1).
//!
//! There is no cross-vendor RFB file-transfer standard, TightVNC 1.3,
//! TightVNC 2.x and UltraVNC each invented their own, mutually incompatible,
//! largely undocumented protocol, and TigerVNC has none at all. So instead of
//! reverse-engineering a vendor silo we open a second connection to the same
//! host over SSH and speak SFTP, exactly as Apache Guacamole does. That works
//! against every Linux and macOS box, and any Windows box with OpenSSH Server,
//! whatever VNC server is running.
//!
//! ```no_run
//! # async fn demo() -> Result<(), vnc_files::Error> {
//! use std::sync::Arc;
//! use parking_lot::Mutex;
//! use vnc_files::{FileTransferConfig, HostKeyStore, SftpSession, SshAuth};
//!
//! let pins = Arc::new(Mutex::new(HostKeyStore::new()));
//! let mut cfg = FileTransferConfig::new("living-room.local", "user");
//! cfg.ssh.auth = SshAuth::Agent;
//!
//! // First connect fails with `Error::HostKeyUnknown`; the UI prompts, the
//! // shell calls `HostKeyStore::trust`, and this call is retried.
//! let session = SftpSession::connect(cfg, pins.clone()).await?;
//! let entries = session.list_dir(&session.home_dir().await?).await?;
//! # let _ = entries;
//! # Ok(())
//! # }
//! ```
//!
//! ## Layout
//!
//! | module | responsibility |
//! |---|---|
//! | [`path`] | **the security boundary**, normalises and rejects untrusted server paths |
//! | [`config`] | the file half of the connection config, over `ssh-transport`'s |
//! | [`transfer`] | events, progress throttling, resume offsets, conflict rules |
//! | [`queue`] | concurrency limit + per-item cancellation |
//! | [`session`] | the live SFTP connection and the transfer loops |
//!
//! The SSH carrier itself (dial, host-key TOFU, authentication, tunnelling,
//! reachability probe) lives in `ssh-transport`, which `ssh-core` also builds
//! on. The names below are re-exported so a consumer of this crate does not
//! have to name both.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod path;
pub mod queue;
pub mod session;
pub mod transfer;

pub use config::{
    canonical_host, host_port, resolver_host, FileTransferConfig, SshAuth, SshConfig,
    DEFAULT_SSH_PORT,
};
pub use error::{Error, Result};
pub use queue::{TransferQueue, MAX_CONCURRENT_TRANSFERS};
pub use session::{RemoteEntry, SftpSession};
pub use ssh_transport::{
    probe_ssh, HostKeyDecision, HostKeyPin, HostKeyStore, HostKeyVerifier, SshTunnel, TunnelStream,
};
pub use transfer::{
    eta_secs, ConflictOutcome, ConflictPolicy, Direction, TransferEvent, TransferPlan,
    LARGE_TRANSFER_WARN_BYTES, PROGRESS_EVENTS_PER_SEC,
};
