//! Session lifecycle state, as the shell and the UI see it.
//!
//! Moved out of `vnc-core/src/types.rs` unchanged (PRDRDP/02 §2.1). The
//! `#[serde(tag = "state", rename_all = "kebab-case")]` representation is a
//! contract with `ui/src/lib/types.ts`, so it does not change here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum SessionState {
    Idle,
    Resolving,
    Connecting,
    Authenticating {
        method: String,
    },
    Negotiating,
    Connected,
    /// Auto-reconnect in progress (PRD/05 §6.3).
    Reconnecting {
        attempt: u32,
        next_retry_ms: u64,
        reason: String,
    },
    Disconnected {
        reason: String,
        can_retry: bool,
    },
}
