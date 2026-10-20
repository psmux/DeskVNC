//! Apple Screen Sharing, as a DeskVNC protocol driver.
//!
//! The session speaks RFB 003.889, signs in with RSA-SRP, and asks the Mac
//! for one H.264 stream. Frames are emitted as Annex-B access units on the
//! existing H.264 path, so the webview's hardware decoder does the work.

#![forbid(unsafe_code)]

mod answer;
mod auth;
mod h264;
mod input;
mod macos;
mod offer;
mod pictures;
mod plist;
mod quality;
mod record;
mod rtcp;
mod session;
mod srtp;
mod video;

use remote_core::{
    ConnectOptions, OptionsMismatch, ProtocolDriver, ProtocolKind, SessionEvent, SessionHandle,
};
use tokio::sync::mpsc;

/// The Apple driver. One value, built at startup and kept in the registry.
#[derive(Clone, Default)]
pub struct AppleDriver {
    host_keys: Option<macos::Verifier>,
}

impl AppleDriver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_host_keys(verifier: impl ssh_transport::HostKeyVerifier) -> Self {
        Self {
            host_keys: Some(std::sync::Arc::new(verifier)),
        }
    }
}

impl ProtocolDriver for AppleDriver {
    fn kind(&self) -> ProtocolKind {
        ProtocolKind::Apple
    }

    fn spawn(
        &self,
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> Result<SessionHandle, OptionsMismatch> {
        let actual = options.kind();
        if actual != ProtocolKind::Apple {
            return Err(OptionsMismatch {
                expected: ProtocolKind::Apple,
                actual,
            });
        }
        let (commands_tx, commands_rx) = mpsc::channel(64);
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_task = cancel.clone();
        let host_keys = self.host_keys.clone();
        tokio::spawn(async move {
            session::run(options, events, commands_rx, cancel_task, host_keys).await;
        });
        Ok(SessionHandle {
            id,
            kind: ProtocolKind::Apple,
            commands: commands_tx,
            cancel,
        })
    }
}
