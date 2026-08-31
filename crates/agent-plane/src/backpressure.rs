//! Bounded queues, an explicit drop policy, and the counters that make a drop
//! visible.
//!
//! `08 §4`. The existing discipline in the tree is the precedent and it is a
//! good one, so this extends it rather than replacing it.
//!
//! ## What exists, and what this preserves
//!
//! `SessionHandle::try_send` (`crates/remote-core/src/driver.rs:117`) is the
//! non blocking way into a session, and the comment above it states the reason:
//! input must never queue unboundedly behind a stalled session. The capture
//! forwarder repeats it (`src-tauri/src/commands/capture.rs:124`). `send_input`
//! (`src-tauri/src/commands/session.rs:1197`) refines it, and its policy is the
//! model for everything here: it AWAITS key events and pointer events whose
//! button mask changed, and sheds only pointer events that repeat the current
//! mask, which is to say pure motion.
//!
//! Note what that gets right that a naive design would not. The distinction is
//! not important versus unimportant. It is **stateful versus stateless**. A
//! dropped motion event is corrected by the next motion event. A dropped
//! button release is never corrected by anything.
//!
//! ## The one place this crate cannot use `SessionHandle::try_send`
//!
//! `try_send` maps both `TrySendError::Full` and `TrySendError::Closed` onto
//! one `SessionGone` (`driver.rs:117` to `:119`). For the webview that is
//! fine, because a person's next mouse move repairs either. For the plane it
//! is not: full means wait or shed and say so, closed means the limb is gone
//! and every outstanding intent settles, and the two have opposite repairs.
//! So the dispatcher reaches through to `SessionHandle::commands`, which is a
//! public field, and matches on the real error. The non blocking discipline is
//! preserved exactly; what is not preserved is the flattening, and the
//! flattening is the part that would make this crate guess.
//!
//! ## Never silently
//!
//! `00 R24` and `08 §4.6`. The plane never drops output or input without
//! saying how much it dropped. [`Gaps`] is that count, it rides every
//! settlement, and it is cumulative on the limb as well so an agent that
//! missed a settlement can still see the total.

/// What the plane does with one command when there is no room.
///
/// The table is `08 §4.3` and the rule above it is stated once: **never drop
/// anything that changes state the limb will keep.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SendPolicy {
    /// Stale motion, corrected by the next one. A pointer event whose button
    /// mask matches the last one sent, and nothing else.
    Shed,
    /// An idempotent setting. Three queued `SetQuality` calls mean the last
    /// one, so the plan is folded before it is sent rather than the channel
    /// being asked to carry all three.
    Coalesce,
    /// Block this grant's submission for up to
    /// [`crate::config::PlaneConfig::intent_block_ms`], then refuse the call.
    /// Everything stateful: every key, a pointer whose mask changed, clipboard
    /// text, terminal bytes.
    Await,
    /// Ahead of anything queued, and exempt from the reservation.
    ///
    /// The two release commands and `Disconnect`. A queued repair is not a
    /// repair, and `00 R11` is explicit that the release is exempt from the
    /// rate buckets, because BrowserGlass recorded that a limiter running
    /// before the handler never sees the event kind and therefore silently
    /// defeats the release asymmetry above it.
    Jump,
}

/// What was lost, and how much.
///
/// Cumulative since attach on the limb, and per intent on a settlement, so an
/// agent can both notice a gap without subscribing to anything extra and
/// attribute it to the call that caused it (`08 §4.6`).
///
/// Every field is a count rather than a flag. `08 §4.6` is blunt about why:
/// silent dropping is the failure this design must not ship with, and a
/// boolean saying something was dropped does not say how much, which is the
/// half an agent needs to decide between retrying and reading the screen
/// again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct Gaps {
    /// Pointer events that repeated the current button mask and were shed on
    /// a full channel. The designed path, reported rather than errored
    /// (`08 §4.6`, `intent_shed`).
    pub pointer_moves_shed: u32,
    /// Idempotent settings folded out of a plan before it was sent.
    pub settings_coalesced: u32,
    /// Commands of a stateful kind that never reached the session channel.
    /// This is the number that means something went wrong.
    pub commands_dropped: u32,
    /// Bytes inside those commands. A dropped `TerminalInput` of 64 KiB and a
    /// dropped key event are one command each and are not the same loss.
    pub bytes_dropped: u64,
    /// How long the call spent waiting for room.
    pub blocked_ms: u64,
}

impl Gaps {
    /// Did this call lose anything that will not repair itself?
    ///
    /// Shed motion and coalesced settings do not count. The first is corrected
    /// by the next motion event and the second is idempotent by construction,
    /// which is the whole reason they are allowed to be dropped at all.
    pub const fn lost_state(&self) -> bool {
        self.commands_dropped > 0
    }

    /// Fold another call's counts in, for the cumulative total on a limb.
    pub fn absorb(&mut self, other: Gaps) {
        self.pointer_moves_shed = self
            .pointer_moves_shed
            .saturating_add(other.pointer_moves_shed);
        self.settings_coalesced = self
            .settings_coalesced
            .saturating_add(other.settings_coalesced);
        self.commands_dropped = self.commands_dropped.saturating_add(other.commands_dropped);
        self.bytes_dropped = self.bytes_dropped.saturating_add(other.bytes_dropped);
        self.blocked_ms = self.blocked_ms.saturating_add(other.blocked_ms);
    }

    /// The sentence a settlement carries when something was lost.
    ///
    /// Written here so that every refusal that mentions a drop says it the
    /// same way, with the actual numbers in it, which is `06 §5.5`'s rule.
    pub fn describe(&self) -> String {
        format!(
            "{} command(s) carrying {} byte(s) did not reach the session, {} pointer move(s) were shed and {} setting(s) coalesced, after waiting {} ms for room",
            self.commands_dropped,
            self.bytes_dropped,
            self.pointer_moves_shed,
            self.settings_coalesced,
            self.blocked_ms,
        )
    }
}
