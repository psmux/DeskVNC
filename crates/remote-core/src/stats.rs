//! Per tick session statistics.
//!
//! Moved out of `vnc-core/src/types.rs` unchanged (PRDRDP/02 §2.1). The struct
//! has no `rename_all`, so its fields stay snake_case on the wire, which is
//! what `ui/src/lib/types.ts` mirrors (PRDRDP/02 §12.1 rule 2).

use serde::{Deserialize, Serialize};

/// Where [`SessionStats::rtt_ms`] came from.
///
/// The three sources are NOT equivalent and a reader that treats them as one
/// number will draw the wrong conclusion, so the source travels with the
/// figure:
///
/// * `Fence` is exact: a ClientFence the server echoes, nothing else in the
///   pipe. Only the TigerVNC family implements it.
/// * `IdleProbe` is a one-pixel non-incremental request timed into a quiet
///   gap. Nearly as clean as a fence, but it only produces a sample when the
///   screen happens to be still, so on a busy desktop it can go minutes
///   without updating.
/// * `UpdatePipeline` is the passive readout taken on the normal update path
///   (see `run_loop`): request-to-next-header during a busy streak. Always
///   available, no extra traffic, but it includes the time this client spent
///   reading the intervening update, so it reads HIGH compared with a fence.
///   Read it as "how long until the next picture", which is what the user
///   actually feels, rather than as a pure network round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RttSource {
    /// No measurement yet; `rtt_ms` is 0.0 and means nothing.
    #[default]
    None,
    Fence,
    IdleProbe,
    UpdatePipeline,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SessionStats {
    /// Round trip in milliseconds, 0.0 until something has been measured.
    /// [`SessionStats::rtt_source`] says which instrument produced it.
    pub rtt_ms: f32,
    /// Which instrument produced `rtt_ms`. Added after the fact, so it is
    /// `#[serde(default)]`: an older peer that omits it reads as `None`.
    #[serde(default)]
    pub rtt_source: RttSource,
    /// Fraction (0.0 to 1.0) of the last stats tick this client spent inside
    /// a FramebufferUpdate: reading its header, pulling its rects off the
    /// socket and decoding them.
    ///
    /// This is the closest thing we have to "how hard is the server working
    /// for us". A server that is streaming flat out leaves the client
    /// permanently inside an update and this approaches 1.0; an idle desktop
    /// leaves the client parked in the select loop and it approaches 0.0.
    /// It is the honest signal for "we are saturating the link or the
    /// server", which is exactly the condition that made the auto tuner
    /// drive Tight compression to 0 and stream 9.9 MB/s unnoticed.
    ///
    /// It does NOT separate a slow link from a slow encoder: both keep the
    /// client inside the update. Pair it with `throughput_bps` to tell them
    /// apart (high duty + high throughput is a loaded link, high duty + low
    /// throughput is a struggling server).
    #[serde(default)]
    pub server_duty_cycle: f32,
    pub throughput_bps: f64,
    /// TX bits/sec over the last stats tick, the upload mirror of
    /// `throughput_bps`.
    pub throughput_up_bps: f64,
    pub fps: f32,
    pub decode_ms: f32,
    pub bytes_received: u64,
    /// Cumulative bytes written to the transport (plaintext side, same layer
    /// as `bytes_received`).
    pub bytes_sent: u64,
    pub rects_decoded: u64,
    pub current_encoding: i32,
    pub jpeg_quality: u8,
}
