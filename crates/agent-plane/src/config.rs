//! The numbers the runtime runs on, gathered so a deployment can move them
//! together and a trace can record which set was in force.
//!
//! Every default here comes from a document and says which one. The ones that
//! are guesses are marked as guesses, following `08 §4.2`, which marks its own.

use agent_lease::LeaseConfig;

/// How many limbs this build will drive at once.
///
/// **Four, not eight** (`00 R21`). `08 §2` audited thirteen shared resources
/// and found five that break at N equal to 8, and the binding one is the
/// single Tokio runtime: decode runs inline on worker threads between await
/// points and `run_loop.rs` already records 42.7 percent duty at the High
/// tier, so eight sessions is 342 percent of a core with the webview's IPC
/// dispatch queued behind it. The symptom is that the user interface hangs,
/// not that the agent is slow, which is why this is a refusal rather than a
/// slowdown.
///
/// The author of `08` puts the breakage at N approximately 4 in `§12` and says
/// plainly that every number in the audit is reasoned from source that was
/// read and none is measured. So four is the honest claim until spike S2
/// writes its table (`00 R27`), and claiming eight while shipping four is the
/// one failure the whole document set was written to avoid.
pub const MAX_DRIVEN_LIMBS: usize = 4;

/// The plane's own settings.
///
/// Not `#[non_exhaustive]`. A caller outside this crate has to be able to
/// write this struct down, which is the lesson `00 R47b` records after
/// `LimbDescription` was marked non exhaustive and stopped compiling for the
/// limb authors it was written for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneConfig {
    /// How many limbs may be attached at once. See [`MAX_DRIVEN_LIMBS`].
    pub max_driven_limbs: usize,

    /// How long a grant's intent may wait for room on the session channel
    /// before the call is refused (`08 §4.3`).
    ///
    /// Await at the plane level does not mean block forever. A grant that has
    /// been blocked for two seconds on a limb is talking to a session that is
    /// not moving, and telling the agent so is more useful than holding its
    /// call open.
    pub intent_block_ms: u64,

    /// The share of the session command channel the plane refuses to consume,
    /// expressed as a divisor of the channel's total capacity.
    ///
    /// Two, so the plane never uses more than half the free slots and at least
    /// 128 of the 256 stay available to the webview's `send_input` path and to
    /// the capture forwarder (`08 §4.5`). This is one line of arithmetic and it
    /// is the difference between "the agent is busy" and "my keyboard stopped
    /// working".
    ///
    /// A divisor of zero is read as one, which reserves the whole channel and
    /// therefore lets the plane send nothing. That is a strange thing to ask
    /// for and it is not a panic.
    pub session_reservation_divisor: usize,

    /// How many intermediate points a drag travels through (`15 §4.5`).
    ///
    /// Eight, on a straight line, parameterised and unmeasured (spike S15-2).
    /// It is not optional: a drag that teleports from origin to target in one
    /// message is not a drag on most toolkits, because drag thresholds and drop
    /// targets are driven by intermediate motion events.
    pub drag_points: u8,

    /// The pause either side of a drag's press and release (`15 §4.5`).
    /// Thirty milliseconds, parameterised, unmeasured.
    pub drag_settle_ms: u64,

    /// The gap between the two press edges of a double click.
    ///
    /// The remote's own double click interval is something we cannot query, so
    /// 250 ms is a default rather than a fact (`15 §4.1`, spike S15-1).
    pub double_click_gap_ms: u64,

    /// The arbitration timers, passed through to `agent-lease` untouched.
    pub lease: LeaseConfig,
}

impl Default for PlaneConfig {
    fn default() -> Self {
        PlaneConfig {
            max_driven_limbs: MAX_DRIVEN_LIMBS,
            intent_block_ms: 2_000,
            session_reservation_divisor: 2,
            drag_points: 8,
            drag_settle_ms: 30,
            double_click_gap_ms: 250,
            lease: LeaseConfig::default(),
        }
    }
}

impl PlaneConfig {
    /// How many free slots on a session channel the plane leaves alone.
    ///
    /// Read off the channel rather than from a constant, because the two
    /// protocol crates do not agree on the bound: VNC's intent channel is 256
    /// (`crates/vnc-core/src/session/mod.rs:42`) and SSH's is 64
    /// (`crates/ssh-core/src/driver.rs:92`). A hard coded 128 would reserve
    /// twice the SSH channel and the plane would never send anything at all.
    pub fn reserved_slots(&self, channel_capacity: usize) -> usize {
        channel_capacity / self.session_reservation_divisor.max(1)
    }
}
