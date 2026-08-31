//! The mode a limb is configured in, and the numbers the timers run on.
//!
//! Every default here is the one `08 §5.4` states. They are gathered in one
//! struct rather than spread as constants so a deployment can move them
//! together and a trace can record which set was in force, which matters the
//! first time somebody asks why a lease vanished after a minute.

use crate::clock::Millis;

/// Exclusive or shared control, fixed when the limb is created.
///
/// Mode is deliberately not a field on an acquire request. The reason is
/// BrowserGlass's and `08 §5.3` adopts it whole: arbitration has to be single
/// valued for a contended resource, and with a per request mode "Alice holds
/// exclusively, Bob asks for shared" has no honest answer. What a caller
/// genuinely chooses is whether to ask for control at all, which it does by
/// asking or not asking.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeaseMode {
    /// One holder at a time, preemptible. The only mode this version builds.
    #[default]
    Exclusive,
    /// Several holders at once. Refused by [`crate::Lease::new`] in this
    /// version; see R12 and the note on
    /// [`crate::LeaseError::SharedModeUnavailable`].
    Shared,
}

/// The timers and bounds from `08 §5.4`.
///
/// All of them are millisecond counts on the caller's clock, and none of them
/// are consulted except by [`crate::Lease::tick`], which is the only place in
/// this crate where time is applied to state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeasePolicy {
    /// Hard expiry. Reset by any dispatched intent and by an explicit renew.
    /// A holder that stops acting loses the lease in a minute.
    pub lease_ttl_ms: Millis,
    /// Idle revocation, measured from the last dispatched intent alone and
    /// never reset by a renew.
    ///
    /// Two timers where one looks like it would do, and the reason is worth
    /// stating because the numbers otherwise look redundant (the shorter one
    /// would always fire first). They measure different things.
    /// [`LeasePolicy::lease_ttl_ms`] catches a party that went quiet
    /// altogether. This one catches a party that is still talking, still
    /// renewing, and has not actually done anything for two minutes, which is
    /// exactly the shape of a crashed agent whose socket is still open. It is
    /// the longer number precisely because a renew is evidence of life and a
    /// silent holder is not.
    pub idle_revoke_ms: Millis,
    /// How long a holder whose transport dropped keeps the lease, so a
    /// reconnect does not lose the wheel.
    pub disconnect_grace_ms: Millis,
    /// How long a waiter stays in the queue before it is dropped.
    ///
    /// A grant of control a minute after it was asked for arrives when the
    /// agent has moved on, which is the same reasoning as refusing rather
    /// than queueing a clipboard write (`08 §2.9`).
    pub queue_ttl_ms: Millis,
    /// The hard cap on the queue. Reached, the next acquire is refused rather
    /// than the queue growing.
    pub max_queue_depth: usize,
    /// The floor under a grant, so a party mid drag is not yanked out from
    /// under themselves.
    ///
    /// Lifted for exactly one pairing, a person requesting against an agent
    /// holder (`08 §6.1` step 3): the floor exists to protect a hand on a
    /// mouse and an agent has no equivalent claim. Lifting it grants no new
    /// preemption right, the priority test still has to pass on its own.
    pub min_hold_ms: Millis,
    /// How long a preempted holder gets to release voluntarily before the
    /// lease is taken anyway.
    ///
    /// The honest number: a person waits one round trip in the good case and
    /// this in the bad case (`08 §6.1` step 7).
    pub agent_preempt_grace_ms: Millis,
    /// After a force release (`08 §6.3`), how long every acquire on this limb
    /// is refused.
    ///
    /// Without it an agent in a loop re acquires before the person who hit
    /// the panic chord can click anything, and the panic button does nothing.
    pub force_release_backoff_ms: Millis,
}

impl Default for LeasePolicy {
    fn default() -> Self {
        LeasePolicy {
            lease_ttl_ms: 60_000,
            idle_revoke_ms: 120_000,
            disconnect_grace_ms: 10_000,
            queue_ttl_ms: 60_000,
            max_queue_depth: 8,
            min_hold_ms: 3_000,
            agent_preempt_grace_ms: 2_000,
            force_release_backoff_ms: 30_000,
        }
    }
}

/// What a limb's lease is built with.
///
/// Both fields are per limb and neither is negotiable afterwards, which is
/// the shape `08 §5.3` requires of the mode and the shape the timers may as
/// well share.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeaseConfig {
    /// Exclusive or shared. See [`LeaseMode`], and note that shared is
    /// refused in this version.
    pub mode: LeaseMode,
    /// The timers and bounds.
    pub policy: LeasePolicy,
}
