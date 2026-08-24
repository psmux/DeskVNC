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
        /// The stable identifier for what went wrong, when the protocol has
        /// one for it (`RetryClassify::symbol`).
        ///
        /// `reason` is a sentence a translator or a copy editor may rewrite at
        /// any time, so a UI that matches on it is matching on prose. This
        /// carries the identifier beside the sentence: the UI matches this and
        /// shows that. `None` for an error with no specific remedy, which is
        /// every RFB failure today.
        ///
        /// Serialized only when it is present, so a VNC disconnect is the same
        /// JSON object it was before the field existed and
        /// `ui/src/lib/types.ts` reads it as optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        symbol: Option<String>,
    },
}
