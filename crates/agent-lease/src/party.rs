//! Who is asking, and what that entitles them to.
//!
//! The priority ladder is copied verbatim from BrowserGlass's
//! `DEFAULT_PRIORITY` (`packages/core/src/control/types.ts`) by way of
//! `08 §5.2`. Copying the numbers rather than inventing our own is the whole
//! point: a person outranks an agent by default, so "the human takes the
//! wheel" (D5) needs no application code anywhere above this crate. If the
//! ladder were configuration with no default, every call site would have to
//! get it right and one of them would not.

use crate::clock::LeaseInstant;

/// What kind of party this is, which is what fixes its default place on the
/// ladder.
///
/// Our mapping, from `08 §5.2`: a window or a pane is [`HolderKind::Human`]
/// unless the application itself is acting, which it is not. A grant is
/// [`HolderKind::Agent`] unless the UI issuing it deliberately marked it
/// [`HolderKind::Owner`], which is for the case where an unattended run must
/// not be interrupted by an accidental click. [`HolderKind::Admin`] is the
/// shell itself and is used only by the force release paths (`08 §6.3`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum HolderKind {
    /// The shell itself. Outranks everything, including a person, because the
    /// panic chord has to work while an agent is holding eight machines.
    Admin,
    /// A person who deliberately said "do not let a stray click interrupt
    /// this". Outranks an ordinary pane.
    Owner,
    /// A person at a pane. The default for anything driven by a window.
    Human,
    /// An agent. The bottom of the ladder, which is the point.
    Agent,
}

impl HolderKind {
    /// The default priority for this kind, from `08 §5.2`.
    #[must_use]
    pub const fn default_priority(self) -> u16 {
        match self {
            HolderKind::Admin => 900,
            HolderKind::Owner => 200,
            HolderKind::Human => 100,
            HolderKind::Agent => 50,
        }
    }

    /// Is there a person behind this party?
    ///
    /// Used for the one pairing where the minimum hold is lifted (`08 §6.1`
    /// step 3). `08 §6.1` names only `human` against `agent`; we widen it to
    /// every person shaped kind, because an [`HolderKind::Admin`] force path
    /// that had to wait three seconds behind an agent would defeat R13, whose
    /// entire complaint is two seconds of somebody pressing a button labelled
    /// stop while nothing happens.
    #[must_use]
    pub const fn is_person(self) -> bool {
        matches!(
            self,
            HolderKind::Admin | HolderKind::Owner | HolderKind::Human
        )
    }
}

/// The identity of a party: a grant id, or a window label.
///
/// Opaque on purpose. This crate arbitrates between parties and must never
/// learn what one is connected to; the plane above it owns that map.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct PartyId(String);

impl PartyId {
    /// The id as text, for a log line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for PartyId {
    fn from(s: &str) -> Self {
        PartyId(s.to_owned())
    }
}

impl From<String> for PartyId {
    fn from(s: String) -> Self {
        PartyId(s)
    }
}

impl std::fmt::Display for PartyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The identity of the contended resource. One lease per limb (`08 §5.1`).
///
/// A string this crate never interprets. It exists so a [`crate::LeaseTransition`]
/// reaching a trace says which limb it belongs to, because a trace of lease
/// changes with no limb on them is not evidence of anything (`10 §3`).
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct LimbId(String);

impl LimbId {
    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for LimbId {
    fn from(s: &str) -> Self {
        LimbId(s.to_owned())
    }
}

impl From<String> for LimbId {
    fn from(s: String) -> Self {
        LimbId(s)
    }
}

impl std::fmt::Display for LimbId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Minted fresh on every grant and never reissued (`08 §5.1`).
///
/// It is what makes [`crate::Lease::release`] safe to call from a cleanup
/// path: a party holding a stale id cannot release the grant that replaced
/// it. Counted per lease rather than drawn from a uuid, because uniqueness
/// within one limb is all the fencing check needs and a dependency for a
/// counter is a dependency for nothing. A caller that wants a globally unique
/// name pairs it with the [`LimbId`].
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct LeaseId(u64);

impl LeaseId {
    /// The raw counter value, for a trace.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Rebuild an id a party quoted back at the plane.
    ///
    /// It has to be public, and the reason is worth stating so nobody
    /// "hardens" it away again. A party releasing a lease quotes the id it was
    /// given, that id arrives over IPC as a number, and without this the plane
    /// could not turn it back into a [`LeaseId`] to hand to
    /// [`crate::Lease::release`]. It would have to compare the number against
    /// the live holder itself, which is the fencing check reimplemented
    /// outside the crate that exists to own it.
    ///
    /// Nothing is given away by that. The id is a staleness token, not a
    /// capability: it says which grant a message belongs to, and whether the
    /// party was allowed to hold the lease at all is the `control` capability
    /// on the grant (`09 §3`), checked above this crate.
    #[must_use]
    pub const fn from_u64(n: u64) -> Self {
        LeaseId(n)
    }
}

/// A party asking for, holding, or waiting for control.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Party {
    /// The grant id or window label.
    pub id: PartyId,
    /// Which rung of the ladder this party starts on.
    pub kind: HolderKind,
    /// What everyone else is shown when this party holds the lease. `08 §5.5`
    /// makes this a safety property rather than a nicety: a pane whose limb is
    /// held by an agent says so, visibly, always.
    pub label: String,
    /// The effective priority. Defaults from [`Party::kind`] and can be
    /// overridden, because deployments differ: a kiosk may want its unattended
    /// agent above a passing click, and a shared lab may want the opposite.
    pub priority: u16,
}

impl Party {
    /// A party at its kind's default priority.
    #[must_use]
    pub fn new(id: impl Into<PartyId>, kind: HolderKind, label: impl Into<String>) -> Self {
        Party {
            id: id.into(),
            kind,
            label: label.into(),
            priority: kind.default_priority(),
        }
    }

    /// Override the priority this party arbitrates at.
    ///
    /// The kind is left alone deliberately. It still decides whether the
    /// minimum hold is lifted (`08 §6.1` step 3) and it is still what the UI
    /// renders, so a deployment that lowers a person below an agent gets what
    /// it asked for without the pane starting to lie about who is driving.
    #[must_use]
    pub fn with_priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }
}

/// The party currently holding the lease, with the timestamps the expiry
/// rules read.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Holder {
    /// Minted at the grant, never reissued.
    pub lease_id: LeaseId,
    /// Who is driving.
    pub party: Party,
    /// When this grant started. The minimum hold is measured from here.
    pub granted_at: LeaseInstant,
    /// The last intent this holder actually dispatched. Idle revocation is
    /// measured from here, and only from here.
    pub last_intent_at: LeaseInstant,
    /// The last explicit renew, or the grant if there has not been one. The
    /// hard time to live is measured from the later of this and
    /// [`Holder::last_intent_at`].
    pub last_renew_at: LeaseInstant,
    /// Is this holder's transport up? A holder whose transport dropped keeps
    /// the lease for `disconnect_grace_ms` so a reconnect does not lose the
    /// wheel.
    pub connected: bool,
    /// When the disconnect grace runs out, set only while the phase is
    /// [`crate::LeasePhase::HeldGrace`].
    pub grace_until: Option<LeaseInstant>,
}

impl Holder {
    /// The instant the hard time to live counts from: the later of the last
    /// dispatched intent and the last explicit renew (`08 §5.4`).
    #[must_use]
    pub fn last_activity(&self) -> LeaseInstant {
        self.last_intent_at.max(self.last_renew_at)
    }
}

/// A party waiting in the queue, or the one party a preemption is pending
/// for.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Waiter {
    /// Who is waiting.
    pub party: Party,
    /// When they asked. The queue time to live is measured from here.
    pub queued_at: LeaseInstant,
    /// What they said they wanted it for, passed through untouched for the
    /// pane and the trace.
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_is_the_one_from_browserglass() {
        assert_eq!(HolderKind::Admin.default_priority(), 900);
        assert_eq!(HolderKind::Owner.default_priority(), 200);
        assert_eq!(HolderKind::Human.default_priority(), 100);
        assert_eq!(HolderKind::Agent.default_priority(), 50);
    }

    #[test]
    fn a_person_outranks_an_agent_without_anyone_configuring_it() {
        assert!(HolderKind::Human.default_priority() > HolderKind::Agent.default_priority());
        assert!(HolderKind::Human.is_person());
        assert!(!HolderKind::Agent.is_person());
    }

    #[test]
    fn an_override_moves_the_priority_and_leaves_the_kind_alone() {
        let p = Party::new("grant-1", HolderKind::Agent, "nightly run").with_priority(500);
        assert_eq!(p.priority, 500);
        assert_eq!(p.kind, HolderKind::Agent);
    }
}
