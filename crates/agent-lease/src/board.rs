//! One lease per session, for a plane that arbitrates between processes.
//!
//! A [`Lease`] is one limb's arbitration and knows nothing about anybody else.
//! That was enough while every agent process kept its own lease, and it is
//! the reason two agent sessions never contended for anything: each one held
//! a lease nobody else could see, the viewer showed whatever the last one to
//! report had said, and a person's click was recorded in a flag that no lease
//! ever heard about. So the viewer keeps the leases now, one per session, in a
//! [`Board`], and every agent process asks it.
//!
//! The board adds three things to a lease and nothing else:
//!
//! * **The tick, for everyone.** [`Board::tick_all`] is what the viewer calls
//!   on a timer, so a forgotten lease frees itself with nobody calling.
//! * **The handover, done in one step.** Every call that grants confirms the
//!   release at once. That is only honest because the caller honours the
//!   obligations in [`Answer::transitions`] before it forwards anything of
//!   the new holder's, in the same call, which is what the viewer does.
//! * **Input as the measure of use.** [`Board::input`] is the only thing that
//!   moves a holder's idle clock. A status call, a renew or a screen read
//!   never does, so a lease is held exactly as long as somebody is using it.

use crate::clock::LeaseInstant;
use crate::error::LeaseError;
use crate::lease::{AcquireRequest, Lease};
use crate::party::{Party, PartyId};
use crate::policy::{LeaseConfig, LeaseMode, LeasePolicy};
use crate::transition::{LeasePhase, LeaseStatus, LeaseTransition};
use std::collections::BTreeMap;

/// What one board call did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// Every lease change the call made, in order. Each carries a release
    /// obligation the caller owes the session before anything else goes to
    /// it.
    pub transitions: Vec<LeaseTransition>,
    /// Where the lease is after the call.
    pub status: LeaseStatus,
    /// Why the party did not get what it asked for, when it did not.
    pub refusal: Option<LeaseError>,
}

impl Answer {
    /// Did anything about the lease move?
    #[must_use]
    pub fn changed(&self) -> bool {
        self.transitions.iter().any(LeaseTransition::changed)
    }
}

/// Every session's lease, keyed by whatever the plane calls a session.
#[derive(Debug, Default)]
pub struct Board {
    policy: LeasePolicy,
    leases: BTreeMap<String, Lease>,
}

impl Board {
    /// An empty board whose leases run on `policy`.
    #[must_use]
    pub fn new(policy: LeasePolicy) -> Self {
        Board {
            policy,
            leases: BTreeMap::new(),
        }
    }

    /// The timers in force.
    #[must_use]
    pub fn policy(&self) -> &LeasePolicy {
        &self.policy
    }

    /// Is there a lease for this session yet?
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.leases.contains_key(key)
    }

    /// The sessions that have a lease.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.leases.keys().map(String::as_str)
    }

    /// Drop a session's lease, for a session that has ended.
    pub fn remove(&mut self, key: &str) {
        self.leases.remove(key);
    }

    fn lease(&mut self, key: &str) -> &mut Lease {
        let policy = self.policy;
        self.leases.entry(key.to_string()).or_insert_with(|| {
            // Exclusive is the only mode this version builds, so `new` cannot
            // fail here; `exclusive` is its infallible spelling.
            let mut lease = Lease::exclusive(key);
            if let Ok(configured) = Lease::new(
                key,
                LeaseConfig {
                    mode: LeaseMode::Exclusive,
                    policy,
                },
            ) {
                lease = configured;
            }
            lease
        })
    }

    /// Where a session's lease is as of the last tick, without applying
    /// elapsed time and without creating a lease for a session that has
    /// none. For a reader that holds other locks and must not change
    /// anything; it can lag a timer by one tick.
    #[must_use]
    pub fn peek(&self, key: &str, now: LeaseInstant) -> Option<LeaseStatus> {
        self.leases.get(key).map(|lease| lease.status(now))
    }

    /// Where a session's lease is, after applying elapsed time.
    pub fn status(&mut self, key: &str, now: LeaseInstant) -> Answer {
        let lease = self.lease(key);
        let mut transitions = Vec::new();
        tick_into(lease, now, &mut transitions);
        Answer {
            transitions,
            status: lease.status(now),
            refusal: None,
        }
    }

    /// Ask for control. Granted when free, a preemption when a person asks
    /// an agent holder, and a place in the queue otherwise.
    ///
    /// Asking again while waiting keeps the place and refreshes it; a waiter
    /// that stops asking is dropped after `queue_ttl_ms`. Asking again while
    /// holding is a renew, which keeps the lease from expiring outright but
    /// does not move its idle clock: only [`Board::input`] does that.
    pub fn ask(&mut self, key: &str, party: Party, now: LeaseInstant) -> Answer {
        let lease = self.lease(key);
        let mut transitions = Vec::new();
        tick_into(lease, now, &mut transitions);
        let refusal = match lease.acquire(AcquireRequest::new(party), now) {
            Ok(transition) => {
                transitions.push(transition);
                confirm_into(lease, now, &mut transitions);
                None
            }
            Err(error) => Some(error),
        };
        Answer {
            transitions,
            status: lease.status(now),
            refusal,
        }
    }

    /// Let go, and stop waiting. Safe to call when the party holds nothing.
    pub fn release(&mut self, key: &str, party: &PartyId, now: LeaseInstant) -> Answer {
        let lease = self.lease(key);
        let mut transitions = Vec::new();
        tick_into(lease, now, &mut transitions);
        if let Some(lease_id) = lease
            .holder()
            .filter(|h| &h.party.id == party)
            .map(|h| h.lease_id)
        {
            transitions.push(lease.release(party, lease_id, now));
        }
        transitions.push(lease.cancel_wait(party, now));
        confirm_into(lease, now, &mut transitions);
        Answer {
            transitions,
            status: lease.status(now),
            refusal: None,
        }
    }

    /// An agent's input is about to go to the session. Allowed when it holds
    /// the lease, or when nobody does, in which case it is granted on the
    /// spot; refused otherwise. Allowed input moves the holder's idle clock.
    ///
    /// The implicit grant is what keeps a client that never asks for control
    /// working: it drives a free machine as before, and it is refused, with
    /// a reason, the moment somebody else holds it.
    pub fn input(&mut self, key: &str, party: Party, now: LeaseInstant) -> Answer {
        let lease = self.lease(key);
        let mut transitions = Vec::new();
        tick_into(lease, now, &mut transitions);
        if lease.phase() == LeasePhase::Unheld {
            match lease.acquire(AcquireRequest::new(party.clone()).no_queue(), now) {
                Ok(transition) => {
                    transitions.push(transition);
                    confirm_into(lease, now, &mut transitions);
                }
                Err(error) => {
                    return Answer {
                        transitions,
                        status: lease.status(now),
                        refusal: Some(error),
                    }
                }
            }
        }
        let refusal = if lease.fence(&party.id).is_allowed() {
            lease.note_intent(&party.id, now);
            None
        } else {
            Some(held_error(lease))
        };
        Answer {
            transitions,
            status: lease.status(now),
            refusal,
        }
    }

    /// A person's input reached the session. A person outranks an agent, so
    /// this takes the lease from an agent holder (the agent is fenced at
    /// once), and keeps it for as long as the input keeps coming.
    pub fn person_input(&mut self, key: &str, person: Party, now: LeaseInstant) -> Answer {
        let lease = self.lease(key);
        let mut transitions = Vec::new();
        tick_into(lease, now, &mut transitions);
        // A person waits for nobody, so this never queues: against a holder
        // of equal rank (another person, from another window) the input goes
        // through as it always did and the lease is left with whoever had it.
        if let Ok(transition) = lease.acquire(AcquireRequest::new(person.clone()).no_queue(), now) {
            transitions.push(transition);
            confirm_into(lease, now, &mut transitions);
        }
        lease.note_intent(&person.id, now);
        Answer {
            transitions,
            status: lease.status(now),
            refusal: None,
        }
    }

    /// A party went away altogether: release whatever it held and drop it
    /// from every queue. Returns only the sessions where something moved.
    pub fn forget_party(&mut self, party: &PartyId, now: LeaseInstant) -> Vec<(String, Answer)> {
        let keys: Vec<String> = self.leases.keys().cloned().collect();
        let mut out = Vec::new();
        for key in keys {
            let answer = self.release(&key, party, now);
            if answer.changed() {
                out.push((key, answer));
            }
        }
        out
    }

    /// Apply elapsed time to every lease. Returns only the sessions where
    /// something moved, which is what a plane emits an event for.
    pub fn tick_all(&mut self, now: LeaseInstant) -> Vec<(String, Answer)> {
        let mut out = Vec::new();
        for (key, lease) in &mut self.leases {
            let mut transitions = Vec::new();
            tick_into(lease, now, &mut transitions);
            if transitions.iter().any(LeaseTransition::changed) {
                out.push((
                    key.clone(),
                    Answer {
                        transitions,
                        status: lease.status(now),
                        refusal: None,
                    },
                ));
            }
        }
        out
    }
}

/// Tick, keeping the transition only when it moved something, and confirm a
/// handover the tick started.
fn tick_into(lease: &mut Lease, now: LeaseInstant, out: &mut Vec<LeaseTransition>) {
    let ticked = lease.tick(now);
    if ticked.changed() || ticked.must_release() {
        out.push(ticked);
    }
    confirm_into(lease, now, out);
}

fn confirm_into(lease: &mut Lease, now: LeaseInstant, out: &mut Vec<LeaseTransition>) {
    if lease.phase() == LeasePhase::HandingOver {
        out.push(lease.confirm_release(now));
    }
}

fn held_error(lease: &Lease) -> LeaseError {
    match lease.holder() {
        Some(holder) => LeaseError::Held {
            holder_kind: holder.party.kind,
            holder_label: holder.party.label.clone(),
        },
        // Unreachable in practice: a fenced party with nobody holding means
        // a force release backoff, which `input` reports before getting here.
        None => LeaseError::ForceReleased {
            retry_after_ms: lease
                .status(LeaseInstant::ORIGIN)
                .refused_for_ms
                .unwrap_or(0),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::party::HolderKind;
    use crate::transition::DepartureCause;

    fn at(ms: u64) -> LeaseInstant {
        LeaseInstant::from_millis(ms)
    }

    fn agent(id: &str) -> Party {
        Party::new(id, HolderKind::Agent, format!("agent {id}"))
    }

    fn person() -> Party {
        Party::new("person", HolderKind::Human, "a person in DeskVNCViewer")
    }

    fn holder(answer: &Answer) -> Option<String> {
        answer.status.holder.as_ref().map(|h| h.id.to_string())
    }

    #[test]
    fn a_free_session_is_granted_and_held_at_once() {
        let mut board = Board::default();
        let answer = board.ask("s1", agent("a"), at(0));
        assert_eq!(holder(&answer).as_deref(), Some("a"));
        assert_eq!(answer.status.phase, LeasePhase::Held);
        assert!(answer.transitions.iter().any(LeaseTransition::must_release));
    }

    #[test]
    fn a_forgotten_lease_frees_itself_on_the_timer_with_no_call_from_anyone() {
        let mut board = Board::default();
        let _ = board.input("s1", agent("a"), at(0));
        assert!(board.tick_all(at(29_999)).is_empty());
        let moved = board.tick_all(at(30_000));
        assert_eq!(moved.len(), 1);
        let (key, answer) = &moved[0];
        assert_eq!(key, "s1");
        assert!(answer.status.holder.is_none());
        let departed = answer.transitions[0]
            .departed
            .as_ref()
            .expect("a departure");
        assert_eq!(departed.cause, DepartureCause::IdleRevoked);
    }

    #[test]
    fn status_calls_and_renews_do_not_keep_a_lease() {
        let mut board = Board::default();
        let _ = board.input("s1", agent("a"), at(0));
        for t in (1_000..30_000).step_by(1_000) {
            let _ = board.status("s1", at(t));
            let _ = board.ask("s1", agent("a"), at(t));
        }
        let answer = board.status("s1", at(30_000));
        assert!(answer.status.holder.is_none(), "{:?}", answer.status);
    }

    #[test]
    fn input_keeps_a_lease() {
        let mut board = Board::default();
        for t in (0..120_000).step_by(10_000) {
            let answer = board.input("s1", agent("a"), at(t));
            assert!(answer.refusal.is_none());
        }
        assert_eq!(
            holder(&board.status("s1", at(125_000))).as_deref(),
            Some("a")
        );
    }

    #[test]
    fn a_waiting_agent_takes_over_when_the_holder_stops_acting() {
        let mut board = Board::default();
        let _ = board.input("s1", agent("a"), at(0));
        let queued = board.ask("s1", agent("b"), at(1_000));
        assert_eq!(queued.status.position_of(&PartyId::from("b")), Some(0));
        assert_eq!(queued.status.changes_in_ms, Some(8_000));
        // b keeps asking, as the plane does while it waits.
        for t in (1_500..9_000).step_by(500) {
            let answer = board.ask("s1", agent("b"), at(t));
            assert_eq!(holder(&answer).as_deref(), Some("a"));
        }
        let answer = board.ask("s1", agent("b"), at(9_000));
        assert_eq!(holder(&answer).as_deref(), Some("b"));
        let departed = answer
            .transitions
            .iter()
            .find_map(|t| t.departed.as_ref())
            .expect("a left");
        assert_eq!(departed.cause, DepartureCause::YieldedToWaiter);
    }

    #[test]
    fn a_holder_that_keeps_acting_is_not_handed_on() {
        let mut board = Board::default();
        let _ = board.input("s1", agent("a"), at(0));
        for t in (1_000..40_000).step_by(1_000) {
            let _ = board.ask("s1", agent("b"), at(t));
            if t % 4_000 == 0 {
                assert!(board.input("s1", agent("a"), at(t)).refusal.is_none());
            }
        }
        assert_eq!(
            holder(&board.status("s1", at(40_000))).as_deref(),
            Some("a")
        );
    }

    #[test]
    fn a_person_takes_over_at_once_and_hands_back_after_going_quiet() {
        let mut board = Board::default();
        let _ = board.input("s1", agent("a"), at(0));
        let taken = board.person_input("s1", person(), at(5_000));
        assert!(taken.status.person_holds());
        assert!(board.input("s1", agent("a"), at(5_001)).refusal.is_some());
        // The preemption grace runs out and the person is the holder.
        let _ = board.tick_all(at(7_000));
        let _ = board.person_input("s1", person(), at(10_000));
        assert_eq!(
            holder(&board.status("s1", at(29_999))).as_deref(),
            Some("person")
        );
        // Twenty seconds after the last input the machine is free again.
        let moved = board.tick_all(at(30_000));
        assert_eq!(moved.len(), 1);
        assert!(moved[0].1.status.holder.is_none());
        assert!(board.input("s1", agent("a"), at(30_001)).refusal.is_none());
    }

    #[test]
    fn an_agent_waiting_behind_a_person_gets_it_when_the_person_goes_quiet() {
        let mut board = Board::default();
        let _ = board.person_input("s1", person(), at(0));
        let mut got = None;
        for t in (0..25_000).step_by(500) {
            let answer = board.ask("s1", agent("a"), at(t));
            if holder(&answer).as_deref() == Some("a") {
                got = Some(t);
                break;
            }
        }
        assert_eq!(got, Some(20_000));
    }

    #[test]
    fn a_waiter_that_stops_asking_loses_its_place() {
        let mut board = Board::default();
        let _ = board.input("s1", agent("a"), at(0));
        let _ = board.ask("s1", agent("b"), at(1_000));
        let _ = board.input("s1", agent("a"), at(5_000));
        let _ = board.input("s1", agent("a"), at(12_000));
        let answer = board.status("s1", at(16_000));
        assert!(answer.status.queue.is_empty());
        assert_eq!(holder(&answer).as_deref(), Some("a"));
    }

    #[test]
    fn a_party_that_goes_away_lets_go_everywhere() {
        let mut board = Board::default();
        let _ = board.input("s1", agent("a"), at(0));
        let _ = board.input("s2", agent("a"), at(0));
        let _ = board.ask("s1", agent("b"), at(1_000));
        let moved = board.forget_party(&PartyId::from("a"), at(2_000));
        assert_eq!(moved.len(), 2);
        assert_eq!(holder(&board.status("s1", at(2_000))).as_deref(), Some("b"));
        assert!(board.status("s2", at(2_000)).status.holder.is_none());
    }

    #[test]
    fn a_second_agent_is_refused_input_with_the_holder_named() {
        let mut board = Board::default();
        let _ = board.input("s1", agent("a"), at(0));
        let refused = board.input("s1", agent("b"), at(10));
        assert_eq!(
            refused.refusal,
            Some(LeaseError::Held {
                holder_kind: HolderKind::Agent,
                holder_label: "agent a".into(),
            })
        );
    }
}
