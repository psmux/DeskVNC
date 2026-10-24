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

/// The timers and bounds from `08 §5.4`, with the idle numbers cut down after
/// leases were seen holding machines nobody was using.
///
/// All of them are millisecond counts on the caller's clock, and none of them
/// are consulted except by [`crate::Lease::tick`], which is the only place in
/// this crate where time is applied to state. That makes a timer only as good
/// as whoever calls `tick`: the plane that owns a lease has to call it on a
/// timer of its own, not only when a party happens to ask for something,
/// or a forgotten lease looks held to everyone watching until the next call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeasePolicy {
    /// Hard expiry. Reset by any dispatched intent and by an explicit renew.
    /// A holder that stops acting loses the lease in a minute.
    pub lease_ttl_ms: Millis,
    /// How long an agent holder may go without real input (a click, a key, a
    /// drag) before the lease is taken back. Never reset by a renew, a status
    /// call or a screen read: none of those is somebody using the machine.
    ///
    /// Thirty seconds, down from two minutes. An agent thinks for a few
    /// seconds to a few tens of seconds between actions, and the plane asks
    /// for the lease again on the agent's next action, so losing it to this
    /// timer costs the agent one round trip. Holding it costs everyone else
    /// the machine, which is what made two minutes wrong.
    pub idle_revoke_ms: Millis,
    /// How long a person holder may go without input before agents may have
    /// the machine again.
    ///
    /// A person who touches a machine an agent is driving takes it at once.
    /// That used to be for good, and a single click on a pane was enough to
    /// stop an agent for the rest of the day. Twenty seconds is long enough
    /// that somebody reading what is on the screen between two clicks keeps
    /// it, and short enough that somebody who walked away hands it back.
    #[serde(default = "default_person_idle_ms")]
    pub person_idle_ms: Millis,
    /// How long an agent holder may go without input while somebody is
    /// waiting, measured from the later of its last input and the moment the
    /// first waiter arrived. Then the head of the queue takes over.
    ///
    /// Eight seconds: longer than one ordinary action and the screen read
    /// after it, so an agent that is working is never yanked, and short
    /// enough that a waiting agent is not stalled by one that forgot to let
    /// go. The minimum hold still applies on top of it.
    #[serde(default = "default_contended_idle_ms")]
    pub contended_idle_ms: Millis,
    /// How long a holder whose transport dropped keeps the lease, so a
    /// reconnect does not lose the wheel.
    pub disconnect_grace_ms: Millis,
    /// How long a waiter stays in the queue after it last asked.
    ///
    /// A waiter is expected to keep asking while it waits (the plane polls
    /// twice a second), and asking again refreshes this. So the number only
    /// decides how long a waiter that died keeps a place in line, which is
    /// why it is short.
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
    /// The same as the person idle time, so a stop and a takeover both give
    /// the person the same quiet window.
    pub force_release_backoff_ms: Millis,
}

fn default_person_idle_ms() -> Millis {
    LeasePolicy::default().person_idle_ms
}

fn default_contended_idle_ms() -> Millis {
    LeasePolicy::default().contended_idle_ms
}

impl Default for LeasePolicy {
    fn default() -> Self {
        LeasePolicy {
            lease_ttl_ms: 60_000,
            idle_revoke_ms: 30_000,
            person_idle_ms: 20_000,
            contended_idle_ms: 8_000,
            disconnect_grace_ms: 10_000,
            queue_ttl_ms: 15_000,
            max_queue_depth: 8,
            min_hold_ms: 3_000,
            agent_preempt_grace_ms: 2_000,
            force_release_backoff_ms: 20_000,
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
