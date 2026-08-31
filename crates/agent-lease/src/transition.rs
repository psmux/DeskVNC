//! What a lease change is, as data.
//!
//! This crate sends nothing. It has no channel, no socket and no idea what an
//! intent looks like. What it does is return the *obligation* that a change
//! creates, and R11 says there is always one:
//!
//! > a lease change synthesises `ReleaseAllKeys` toward the limb before the
//! > new holder's first intent, and this is the plane's duty rather than the
//! > departing holder's
//!
//! because an agent that crashed mid chord cannot release anything, and that
//! is precisely when a stuck Ctrl matters. So every call on [`crate::Lease`]
//! that can change who is allowed to dispatch returns a [`LeaseTransition`],
//! and every [`LeaseTransition`] carries a [`ReleaseObligation`]. There is no
//! path through the API that changes the holder without handing the caller
//! the obligation at the same time.

use crate::clock::{LeaseInstant, Millis};
use crate::party::{HolderKind, LeaseId, LimbId, Party, Waiter};
use crate::policy::LeaseMode;

/// Where the lease is, from `08 §5.1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeasePhase {
    /// Nobody is driving.
    Unheld,
    /// One party is driving and its intents dispatch.
    Held,
    /// The holder's transport dropped and the disconnect grace is running.
    /// They keep the lease; nothing dispatches until they are back.
    HeldGrace,
    /// A higher priority party has asked, the holder has been told, and the
    /// holder's dispatch has already stopped.
    ///
    /// The stop is immediate and does not wait for the holder to acknowledge.
    /// This is BrowserGlass's property and it is the one that makes the whole
    /// thing safe: by the time the holder's listener runs, nothing more of
    /// theirs can get through (`08 §6.1` step 5).
    PreemptPending,
    /// A new holder has been chosen and the release owed by R11 has not been
    /// reported as done yet.
    ///
    /// Nobody dispatches in this phase, including the new holder. The lease
    /// leaves it when the caller calls [`crate::Lease::confirm_release`],
    /// which is the caller saying the release reached the limb. This crate
    /// cannot observe that write itself, having no runtime, so the phase is
    /// how it refuses to say "go ahead" until somebody claims responsibility.
    HandingOver,
}

/// The release of held input that a lease change owes the limb.
///
/// Modelled as an enum rather than a `bool` so a call site reads as what it
/// is. The value is returned, never logged and forgotten: a caller that drops
/// it gets a warning from `must_use` on [`LeaseTransition`].
///
/// When it is [`ReleaseObligation::Required`] the caller owes the limb, in
/// this order, before the next holder's first intent:
///
/// 1. a pointer event with an empty button mask, then
/// 2. a release of every key.
///
/// Buttons before keys, following the RDP driver's ordering
/// (`crates/rdp-core/src/session/input.rs`), because a modifier still held
/// when the button goes up matches what the server saw when it went down.
/// The decision log's WA-5 records what happens without the pointer half on a
/// VNC limb: the interrupted gesture *completes* rather than being cancelled,
/// so a dragged file is dropped wherever the next pointer event lands, and
/// for a preempted agent nothing follows at all until the new holder moves,
/// which makes the interval unbounded.
///
/// The release itself must be exempt from the input rate buckets. BrowserGlass
/// records the failure exactly: a limiter that runs before the handler never
/// sees the event kind and therefore silently defeats the release asymmetry
/// above it (R11, `08 §6.2` ruling B).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseObligation {
    /// Nothing changed hands, so there is nothing to release.
    NotRequired,
    /// Release held input toward the limb before the next intent dispatches.
    Required,
}

impl ReleaseObligation {
    /// Does the caller owe the limb a release?
    #[must_use]
    pub const fn is_required(self) -> bool {
        matches!(self, ReleaseObligation::Required)
    }
}

/// Why a party stopped holding the lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepartureCause {
    /// They let go.
    Released,
    /// Somebody of higher priority took it (`08 §6`).
    Preempted,
    /// The hard time to live elapsed.
    Expired,
    /// Connected, renewing, and dispatching nothing. The crashed agent whose
    /// socket is still open.
    IdleRevoked,
    /// Their transport dropped and the disconnect grace ran out.
    DisconnectGraceElapsed,
    /// The panic chord (`08 §6.3`, R13).
    ForceReleased,
}

/// Who lost the lease, and why.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Departure {
    /// The party that lost it.
    pub party: Party,
    /// The grant that ended. A later release quoting this id is a no op.
    pub lease_id: LeaseId,
    /// Why.
    pub cause: DepartureCause,
    /// How long they had it, for the trace and for the pane that wants to say
    /// "the agent drove for 40 seconds".
    pub held_for_ms: Millis,
}

/// What the call did, in the caller's terms.
///
/// The phases in [`LeaseTransition::from`] and [`LeaseTransition::to`] say
/// where the lease is; this says what happened to the party that asked.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum LeaseOutcome {
    /// Nothing moved. A release from a party that no longer holds it lands
    /// here, and that is the point: see [`crate::Lease::release`].
    Unchanged,
    /// The asking party now holds it, once the release owed by R11 is done.
    Granted {
        /// The freshly minted grant.
        lease_id: LeaseId,
        /// Who holds it.
        holder: Party,
    },
    /// The asking party already held it and the timers were pushed forward.
    Renewed {
        /// The grant, unchanged. A renew never mints a new one.
        lease_id: LeaseId,
    },
    /// The asking party is waiting.
    Queued {
        /// Their own position, counted from zero. Per recipient, exactly as
        /// BrowserGlass's `LeaseState.queuePosition` is (`08 §5.5`).
        position: usize,
    },
    /// The priority test passed and the holder has been told to stop. The
    /// requester is not granted yet; it is granted when the preemption
    /// settles, either by the holder releasing or at the deadline.
    PreemptionStarted {
        /// When the lease flips regardless of what the holder does.
        deadline: LeaseInstant,
        /// Who is taking over.
        requester: Party,
    },
    /// The asking party left the queue. It never held anything, so it owes
    /// the limb nothing.
    WaitCancelled,
    /// A pending preemption was called off because the requester withdrew.
    /// The previous holder keeps the lease.
    PreemptionAbandoned,
    /// Nobody holds it now.
    Unheld,
    /// The release owed by R11 was reported done and the new holder's intents
    /// may now dispatch.
    HandoverComplete {
        /// The grant that is now live.
        lease_id: LeaseId,
    },
}

/// One lease change, with the obligation it creates.
///
/// Returned by every state changing call on [`crate::Lease`], including the
/// ones that decide nothing changed, so there is no shape of the API in which
/// a caller learns the holder moved without also learning what it owes the
/// limb. That is R11 expressed in types rather than in a comment somebody has
/// to remember.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[must_use = "a lease change carries a release obligation (R11); dropping it can leave a modifier held on the remote machine"]
pub struct LeaseTransition {
    /// Which limb this is about.
    pub limb: LimbId,
    /// The instant the caller supplied.
    pub at: LeaseInstant,
    /// The phase before.
    pub from: LeasePhase,
    /// The phase after.
    pub to: LeasePhase,
    /// What happened, from the calling party's point of view.
    ///
    /// Flattened, so the tag [`LeaseOutcome`] carries lands as this object's
    /// own `outcome` key and its payload sits beside it. Nested it would
    /// serialise as `"outcome":{"outcome":"granted",...}` and every trace
    /// query in `10 §3` would have to say `outcome.outcome`, which is a key
    /// name somebody would eventually "fix" by renaming one of the two.
    #[serde(flatten)]
    pub outcome: LeaseOutcome,
    /// What the caller now owes the limb. Read this before dispatching
    /// anything.
    pub release: ReleaseObligation,
    /// Who lost the lease, if anyone did.
    pub departed: Option<Departure>,
    /// Waiters dropped during this call, by
    /// [`crate::LeasePolicy::queue_ttl_ms`] or by a force release. Each one is
    /// owed a `queue_expired` message by the plane; none of them ever held
    /// anything, so none of them owes the limb a release.
    pub expired_waiters: Vec<Waiter>,
    /// How many parties are waiting after this call.
    pub queue_depth: usize,
}

impl LeaseTransition {
    /// Does the caller owe the limb a release of held input before the next
    /// intent dispatches?
    #[must_use]
    pub const fn must_release(&self) -> bool {
        self.release.is_required()
    }

    /// Did anything about the lease actually move?
    ///
    /// A dropped waiter counts, because the plane owes that waiter a message
    /// even though the holder did not change.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.from != self.to
            || !matches!(self.outcome, LeaseOutcome::Unchanged)
            || !self.expired_waiters.is_empty()
    }
}

/// Whether a party's intents may be dispatched right now.
///
/// Two values rather than three, and the missing one is the point. There is
/// no "denied": a party that is not the dispatching holder still gets
/// [`Fencing::ReleaseOnly`], because a release has to go through even on a
/// dead or stale lease or a departing driver leaves a button or a modifier
/// stuck (`08 §6.2` ruling B, copied from BrowserGlass's stated asymmetry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fencing {
    /// Dispatch this party's intents.
    Allowed,
    /// Dispatch only intents that release: a key going up, a pointer whose
    /// button mask is empty or a subset of the last mask this party sent, and
    /// a release of everything. Fence the rest.
    ///
    /// The subtlety that is easy to get wrong one layer up: the rate limiter
    /// must not run before this check, or it never sees the kind and silently
    /// defeats the asymmetry it sits above.
    ReleaseOnly,
}

impl Fencing {
    /// May everything this party sends be dispatched?
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Fencing::Allowed)
    }
}

/// What one party is told about the lease (`08 §5.5`).
///
/// Deliberately not the whole [`crate::Lease`]. This is what gets broadcast
/// to every party attached to the limb, so it carries the holder's kind and
/// label but never the holder's id, and it carries the recipient's own queue
/// position rather than the queue. A pane renders it. An agent reads it to
/// decide whether to retry.
///
/// The UI requirement it exists to serve is a safety property and not a
/// nicety: a pane whose limb is held by an agent says so, visibly, always.
/// The keys stay `snake_case`. `kebab-case` on this crate's enums renames
/// variant *spellings*, which is the repository's habit
/// (`crates/remote-core/src/state.rs`); putting the same attribute on a
/// struct renames its *fields*, and `holder-kind` would be the only kebab
/// case object key in the tree. `SessionStats` and the inner fields of
/// `SessionState` are both `snake_case`, so these are too.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeaseView {
    /// Which limb.
    pub limb: LimbId,
    /// Exclusive or shared.
    pub mode: LeaseMode,
    /// Where the lease is.
    pub phase: LeasePhase,
    /// The holder's rung, if there is a holder.
    pub holder_kind: Option<HolderKind>,
    /// The holder's label, if there is a holder.
    pub holder_label: Option<String>,
    /// Whether the recipient is the holder.
    pub you_hold: bool,
    /// How many parties are waiting.
    pub queue_depth: usize,
    /// The recipient's own position, counted from zero, or `None` if they are
    /// not waiting.
    pub queue_position: Option<usize>,
}
