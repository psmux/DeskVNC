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
//! cfg.auth = SshAuth::Agent;
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
//! | [`hostkey`] | SSH host-key TOFU, same shape as the TLS pinning in `vnc-transport` |
//! | [`config`] | connection config; secrets deserialize in, never out |
//! | [`transfer`] | events, progress throttling, resume offsets, conflict rules |
//! | [`queue`] | concurrency limit + per-item cancellation |
//! | [`session`] | the live SSH+SFTP connection and the transfer loops |
//! | [`probe`] | "is SSH reachable?", for enabling the Files button |

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod hostkey;
pub mod path;
pub mod probe;
pub mod queue;
pub mod session;
pub mod transfer;

pub use config::{FileTransferConfig, SshAuth, DEFAULT_SSH_PORT};
pub use error::{Error, Result};
pub use hostkey::{HostKeyDecision, HostKeyPin, HostKeyStore, HostKeyVerifier};
pub use probe::probe_ssh;
pub use queue::{TransferQueue, MAX_CONCURRENT_TRANSFERS};
pub use session::{RemoteEntry, SftpSession};
pub use transfer::{
    eta_secs, ConflictOutcome, ConflictPolicy, Direction, TransferEvent, TransferPlan,
    LARGE_TRANSFER_WARN_BYTES, PROGRESS_EVENTS_PER_SEC,
};
