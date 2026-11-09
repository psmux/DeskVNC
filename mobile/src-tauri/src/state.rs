//! What the phone app keeps while it runs.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use remote_core::{ProtocolDriver, ProtocolKind, SessionHandle};
use tokio_util::sync::CancellationToken;

use crate::pins::PinStore;
use crate::store::HostStore;
use crate::vault::{Secret, SecretStore};

/// One live session.
pub struct Session {
    pub handle: SessionHandle,
    /// The saved host this session belongs to, for a remembered password,
    /// the thumbnail and `lastConnectedAt`. `None` for an ad hoc connect.
    pub host_id: Option<String>,
    /// The endpoint, for certificate pins.
    pub address: String,
    pub port: u16,
    pub started_at: Instant,
    /// True while the app is in the background: frames are dropped instead of
    /// queued for a webview that is not drawing.
    pub paused: Arc<AtomicBool>,
    /// The last pointer button mask sent, so pure motion can be shed when the
    /// queue is full. `-1` means none yet.
    pub last_pointer_mask: Arc<AtomicI32>,
    /// A credential the person asked to remember, written to the vault only
    /// once the server accepts it.
    pub pending_save: Arc<Mutex<Option<Secret>>>,
    /// Set when the background grace ended this session, so its pump tells
    /// the UI why before `ended`.
    pub background_ended: Arc<AtomicBool>,
    /// When the last thumbnail was stored, to bound how often one is encoded.
    pub last_thumbnail: Mutex<Option<Instant>>,
}

pub type Sessions = Arc<Mutex<HashMap<String, Session>>>;

pub struct Drivers {
    pub vnc: Arc<dyn ProtocolDriver>,
    pub rdp: Arc<dyn ProtocolDriver>,
    pub boundary: Arc<boundary_driver::BoundaryDriver>,
}

impl Drivers {
    pub fn get(&self, kind: ProtocolKind) -> Option<Arc<dyn ProtocolDriver>> {
        match kind {
            ProtocolKind::Vnc => Some(self.vnc.clone()),
            ProtocolKind::Rdp => Some(self.rdp.clone()),
            ProtocolKind::Boundary => Some(self.boundary.clone() as Arc<dyn ProtocolDriver>),
            // SSH stays desktop only in version 1 (mobile/README.md).
            _ => None,
        }
    }
}

/// Background bookkeeping for the lifecycle rule in CONTRACT.md.
#[derive(Default)]
pub struct Lifecycle {
    /// When the app last went to the background, while it is there.
    pub backgrounded_at: Option<Instant>,
    /// Bumped on every transition, so a timer armed for an older background
    /// spell knows it is stale.
    pub generation: u64,
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub thumbs_dir: PathBuf,
    pub hosts: Arc<HostStore>,
    pub secrets: Arc<dyn SecretStore>,
    pub pins: PinStore,
    pub drivers: Drivers,
    pub sessions: Sessions,
    pub scan: Mutex<Option<CancellationToken>>,
    pub lifecycle: Mutex<Lifecycle>,
}

impl AppState {
    pub fn command_sender(
        &self,
        session_id: &str,
    ) -> Result<tokio::sync::mpsc::Sender<remote_core::ClientCommand>, String> {
        self.sessions
            .lock()
            .get(session_id)
            .map(|s| s.handle.commands.clone())
            .ok_or_else(|| format!("unknown session: {session_id}"))
    }

    pub async fn send(
        &self,
        session_id: &str,
        command: remote_core::ClientCommand,
    ) -> Result<(), String> {
        self.command_sender(session_id)?
            .send(command)
            .await
            .map_err(|_| "session is no longer running".to_string())
    }
}
