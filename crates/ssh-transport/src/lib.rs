//! # ssh-transport
//!
//! The SSH carrier: dial a machine, verify it is the machine we pinned,
//! authenticate, and hand back a connection other crates open channels on.
//!
//! Three features in this workspace need exactly that and nothing more:
//!
//! | crate | what it opens on the carrier |
//! |---|---|
//! | `vnc-files` | the `sftp` subsystem, for the file panel (PRD/08 §2.1) |
//! | `vnc-files` / the shell | `direct-tcpip`, to tunnel RFB (PRD/10 §5) |
//! | `ssh-core` | a PTY and a shell, for the remote terminal |
//!
//! Before this crate existed all of it lived inside `vnc-files`, which meant a
//! terminal would have had to depend on a file-transfer crate to open a
//! socket. This is the same extraction `remote-core` is to `vnc-core`
//! (PRDRDP/02 §11.2): the protocol-neutral half moves down, the feature-
//! specific half stays put, and nothing above notices.
//!
//! ```no_run
//! # async fn demo() -> Result<(), ssh_transport::Error> {
//! use std::sync::Arc;
//! use parking_lot::Mutex;
//! use ssh_transport::{connect_and_authenticate, HostKeyStore, SshAuth, SshConfig};
//!
//! use ssh_transport::HostKeyVerifier;
//!
//! // `Arc<Mutex<HostKeyStore>>` is itself a `HostKeyVerifier` (see the
//! // blanket impl in `hostkey`), which is the shape the shell holds so one
//! // pin store answers for every SSH feature at once. It implements the
//! // trait as a whole, so it is wrapped rather than coerced.
//! let pins = Arc::new(Mutex::new(HostKeyStore::new()));
//! let verifier: Arc<dyn HostKeyVerifier + Send + Sync> = Arc::new(pins.clone());
//!
//! let mut cfg = SshConfig::new("living-room.local", "user");
//! cfg.auth = SshAuth::Agent;
//!
//! // First connect fails with `Error::HostKeyUnknown`; the UI prompts, the
//! // shell calls `HostKeyStore::trust`, and this call is retried.
//! let ssh = connect_and_authenticate(&cfg, verifier).await?;
//! # let _ = ssh;
//! # Ok(())
//! # }
//! ```
//!
//! ## Layout
//!
//! | module | responsibility |
//! |---|---|
//! | [`config`] | where to dial and who to be; secrets deserialize in, never out |
//! | [`hostkey`] | SSH host-key TOFU, same shape as the TLS pinning in `vnc-transport` |
//! | [`connect`] | the dial/verify/authenticate sequence and the liveness profile |
//! | [`tunnel`] | `direct-tcpip` channels, for carrying another protocol |
//! | [`probe`] | "is SSH reachable?", for enabling a feature in the UI |
//! | [`error`] | carrier failures, classified for the reconnect supervisor |

#![forbid(unsafe_code)]

pub mod config;
pub mod connect;
pub mod error;
pub mod hostkey;
pub mod probe;
pub mod tunnel;

pub use config::{canonical_host, host_port, resolver_host, SshAuth, SshConfig, DEFAULT_SSH_PORT};
pub use connect::{
    connect_and_authenticate, connect_and_authenticate_with, BoxFuture, ClientHandler, Keepalive,
    SshHandle,
};
pub use error::{Error, Result};
pub use hostkey::{HostKeyDecision, HostKeyPin, HostKeyStore, HostKeyVerifier};
pub use probe::probe_ssh;
pub use tunnel::{SshTunnel, TunnelStream};
