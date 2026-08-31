//! Refusals, each one naming what the caller can do about it.
//!
//! Nothing here is a bug report. Every variant is a state the plane can be in
//! legitimately, and an agent reading one has to be able to decide between
//! retrying, waiting a stated number of milliseconds, and giving up. A
//! refusal that only says "no" makes the agent poll, and an agent polling for
//! a lease is `08 §6.3`'s loop that defeats the panic button.

use crate::clock::Millis;
use crate::party::HolderKind;

/// Why an acquire, or a construction, was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LeaseError {
    /// Shared control was asked for and this version does not build it.
    ///
    /// R12, and it is a refusal rather than a best effort on purpose. A
    /// desktop keyboard carries modifier state: a person holding Shift while
    /// an agent sends a Shift release gets the wrong character on their own
    /// next key, and neither party can see the other's modifiers, because
    /// `vnc-core` tracks pressed keys with exactly one writer's model of the
    /// world in it. BrowserGlass's interleaving hazard is characters, which
    /// produces `hweolrllod` and is recoverable; ours is worse in kind, not
    /// in degree.
    ///
    /// What to do about it: configure the limb [`crate::LeaseMode::Exclusive`]
    /// and let preemption do the job. `08 §5.3` recommends exactly this for
    /// every limb in version 1, terminals included.
    #[error("shared control is not available in this version, configure the limb exclusive")]
    SharedModeUnavailable,

    /// Somebody of equal or higher priority is driving, and the request said
    /// not to queue.
    ///
    /// What to do about it: ask again with queueing enabled, or show the
    /// holder's label to the person and let them decide.
    #[error("the lease is held by {holder_kind:?} ({holder_label})")]
    Held {
        /// The holder's rung on the ladder.
        holder_kind: HolderKind,
        /// The holder's label, which is safe to show to anyone (`08 §5.5`).
        holder_label: String,
    },

    /// The queue is at its cap and refuses to grow.
    ///
    /// A bound that refuses is the whole point of a bound (`08 §4.2`): a
    /// queue that grows turns a contended limb into an unbounded memory
    /// consumer and hands out control in an order nobody chose, long after
    /// every waiter has moved on.
    ///
    /// What to do about it: back off and retry, or act on a different limb.
    #[error("the control queue for this limb is full ({depth} waiting)")]
    QueueFull {
        /// How many parties are already waiting.
        depth: usize,
    },

    /// The priority test passed, but the holder has not held it long enough
    /// yet and the request said not to queue.
    ///
    /// The floor is there so a party mid drag is not yanked out from under
    /// themselves. It does not apply to a person taking over from an agent,
    /// so seeing this at all means the requester is not a person or the
    /// holder is not an agent.
    ///
    /// What to do about it: retry after `retry_after_ms`, or ask with
    /// queueing enabled and be granted it automatically.
    #[error("the holder has not held the lease for the minimum {retry_after_ms} ms yet")]
    MinHoldNotElapsed {
        /// How long until the floor is satisfied.
        retry_after_ms: Millis,
    },

    /// Somebody hit the panic chord and this limb is in its backoff window.
    ///
    /// What to do about it: wait `retry_after_ms`. Do not loop. A person
    /// pressed `Ctrl+Alt+Shift+Esc` because something was wrong, and an agent
    /// that re acquires the instant it is allowed to is the failure the
    /// backoff exists to prevent.
    #[error("control was force released on this limb, refused for another {retry_after_ms} ms")]
    ForceReleased {
        /// How long until acquires are accepted again.
        retry_after_ms: Millis,
    },
}
