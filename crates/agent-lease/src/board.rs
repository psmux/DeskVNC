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

/// How long a "not now" from a person keeps answering the same agent on the
/// same session without asking the person again. Long enough that an agent
/// polling for the machine does not raise the request again a second later,
/// short enough that a person who changes their mind is asked again soon.
pub const NOT_NOW_MS: crate::clock::Millis = 60_000;

/// How long a person muted requests from agents for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", tag = "until", content = "at")]
pub enum MuteUntil {
    /// Until this instant on the board's clock.
    At(LeaseInstant),
    /// Until the person stops using every machine they are using, which is
    /// when their last lease frees itself by the person idle time.
    PersonIdle,
}

/// One agent waiting for a machine a person is using, as the person is
/// shown it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The session.
    pub key: String,
    /// The waiting agent.
    pub party: PartyId,
    /// What everyone is shown for it.
    pub label: String,
    /// What it said it wanted the machine for. **Untrusted text.**
    pub reason: Option<String>,
    /// How long since it first asked.
    pub waiting_ms: crate::clock::Millis,
    /// How long until the person's hold frees itself if they send nothing
    /// more, which is when the head of the queue gets the machine anyway.
    pub frees_in_ms: Option<crate::clock::Millis>,
}

/// Every session's lease, keyed by whatever the plane calls a session.
#[derive(Debug, Default)]
pub struct Board {
    policy: LeasePolicy,
    leases: BTreeMap<String, Lease>,
    /// Requests from agents are muted, for machines a person is using.
    mute: Option<MuteUntil>,
    /// "Not now", per session and agent, until the instant it stops
    /// answering for the person.
    declined: BTreeMap<(String, PartyId), LeaseInstant>,
}

impl Board {
    /// An empty board whose leases run on `policy`.
    #[must_use]
    pub fn new(policy: LeasePolicy) -> Self {
        Board {
            policy,
            leases: BTreeMap::new(),
            mute: None,
            declined: BTreeMap::new(),
        }
    }

    /// Does a person hold, or is a person taking, this session?
    fn person_holds(&self, key: &str, now: LeaseInstant) -> bool {
        self.peek(key, now).is_some_and(|s| s.person_holds())
    }

    /// Does a person hold any session at all?
    fn person_holds_any(&self, now: LeaseInstant) -> bool {
        self.leases
            .values()
            .any(|lease| lease.status(now).person_holds())
    }

    /// The mute in force, if any. A mute until a time that has passed, or
    /// until the person goes idle when they hold nothing, is none.
    #[must_use]
    pub fn muted(&self, now: LeaseInstant) -> Option<MuteUntil> {
        match self.mute? {
            MuteUntil::At(until) if now.reached(until) => None,
            MuteUntil::PersonIdle if !self.person_holds_any(now) => None,
            mute => Some(mute),
        }
    }

    /// How long a muted request on this session should wait before asking
    /// again: until the mute ends, or until the person can next go idle.
    pub fn mute_left(&self, key: &str, now: LeaseInstant) -> Option<crate::clock::Millis> {
        match self.muted(now)? {
            MuteUntil::At(until) => Some(until.since(now)),
            MuteUntil::PersonIdle => Some(
                self.peek(key, now)
                    .and_then(|s| s.changes_in_ms)
                    .unwrap_or(self.policy.person_idle_ms),
            ),
        }
    }

    /// How long this agent's "not now" on this session still answers, if it
    /// does.
    #[must_use]
    pub fn not_now_left(
        &self,
        key: &str,
        party: &PartyId,
        now: LeaseInstant,
    ) -> Option<crate::clock::Millis> {
        self.declined
            .get(&(key.to_string(), party.clone()))
            .filter(|until| !now.reached(**until))
            .map(|until| until.since(now))
    }

    /// Mute requests from agents for machines a person is using. Agents
    /// already waiting on those machines are taken out of line, and are told
    /// it is muted when they next ask.
    pub fn mute(&mut self, until: MuteUntil, now: LeaseInstant) -> Vec<(String, Answer)> {
        self.mute = Some(until);
        self.drop_requests(now)
    }

    /// Show requests again.
    pub fn unmute(&mut self) {
        self.mute = None;
    }

    /// The person said "not now" to one agent's request on one session. It
    /// leaves the queue, and asking again is answered the same way for
    /// [`NOT_NOW_MS`] without the person being asked.
    pub fn not_now(&mut self, key: &str, party: &PartyId, now: LeaseInstant) -> Answer {
        self.declined
            .insert((key.to_string(), party.clone()), now.plus(NOT_NOW_MS));
        let lease = self.lease(key);
        let mut transitions = Vec::new();
        tick_into(lease, now, &mut transitions);
        transitions.push(lease.cancel_wait(party, now));
        Answer {
            transitions,
            status: lease.status(now),
            refusal: Some(LeaseError::NotNow {
                retry_after_ms: NOT_NOW_MS,
            }),
        }
    }

    /// "Not now" to every request on every machine a person is using.
    pub fn not_now_all(&mut self, now: LeaseInstant) -> Vec<(String, Answer)> {
        let asked: Vec<(String, PartyId)> = self
            .requests(now)
            .into_iter()
            .map(|r| (r.key, r.party))
            .collect();
        asked
            .into_iter()
            .map(|(key, party)| {
                let answer = self.not_now(&key, &party, now);
                (key, answer)
            })
            .collect()
    }

    /// The person lets this agent have this session now: it goes to the head
    /// of the queue and the person lets go, so it is granted at once.
    /// Refused, with nothing changed, when that agent is not waiting.
    pub fn yield_to(
        &mut self,
        key: &str,
        party: &PartyId,
        person: &PartyId,
        now: LeaseInstant,
    ) -> Answer {
        let lease = self.lease(key);
        let mut transitions = Vec::new();
        tick_into(lease, now, &mut transitions);
        if !lease.promote(party) {
            let refusal = Some(LeaseError::Held {
                holder_kind: crate::party::HolderKind::Human,
                holder_label: "nobody is waiting under that name".to_string(),
            });
            return Answer {
                transitions,
                status: lease.status(now),
                refusal,
            };
        }
        // A person taking over from an agent is a pending preemption, not a
        // holder yet: calling it off hands the wheel straight back.
        transitions.push(lease.cancel_wait(person, now));
        if let Some(lease_id) = lease
            .holder()
            .filter(|h| &h.party.id == person)
            .map(|h| h.lease_id)
        {
            transitions.push(lease.release(person, lease_id, now));
        }
        confirm_into(lease, now, &mut transitions);
        Answer {
            transitions,
            status: lease.status(now),
            refusal: None,
        }
    }

    /// Every agent waiting for a machine a person is using, oldest first.
    /// This is what the person is shown.
    #[must_use]
    pub fn requests(&self, now: LeaseInstant) -> Vec<Request> {
        let mut out: Vec<Request> = self
            .leases
            .iter()
            .filter_map(|(key, lease)| {
                let status = lease.status(now);
                status.person_holds().then_some((key, status))
            })
            .flat_map(|(key, status)| {
                let frees_in_ms = status.changes_in_ms;
                status
                    .queue
                    .into_iter()
                    .filter(|w| !w.kind.is_person())
                    .map(move |w| Request {
                        key: key.clone(),
                        party: w.id,
                        label: w.label,
                        reason: w.reason,
                        waiting_ms: w.waiting_ms,
                        frees_in_ms,
                    })
            })
            .collect();
        out.sort_by(|a, b| b.waiting_ms.cmp(&a.waiting_ms).then(a.key.cmp(&b.key)));
        out
    }

    /// Take every agent out of line on machines a person is using.
    fn drop_requests(&mut self, now: LeaseInstant) -> Vec<(String, Answer)> {
        let asked: Vec<(String, PartyId)> = self
            .requests(now)
            .into_iter()
            .map(|r| (r.key, r.party))
            .collect();
        asked
            .into_iter()
            .map(|(key, party)| {
                let lease = self.lease(&key);
                let transitions = vec![lease.cancel_wait(&party, now)];
                let status = lease.status(now);
                (
                    key,
                    Answer {
                        transitions,
                        status,
                        refusal: None,
                    },
                )
            })
            .collect()
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
    ///
    /// An agent asking for a machine a person is using is a request to that
    /// person. It is refused without being queued while the person has
    /// muted requests ([`LeaseError::Muted`]) or has said "not now" to this
    /// agent on this machine in the last [`NOT_NOW_MS`]
    /// ([`LeaseError::NotNow`]). Neither applies once the person stops using
    /// the machine: then it is an ordinary ask.
    pub fn ask(
        &mut self,
        key: &str,
        party: Party,
        reason: Option<String>,
        now: LeaseInstant,
    ) -> Answer {
        let mut transitions = Vec::new();
        tick_into(self.lease(key), now, &mut transitions);
        if !party.kind.is_person() && self.person_holds(key, now) {
            let gate = self
                .mute_left(key, now)
                .map(|retry_after_ms| LeaseError::Muted { retry_after_ms })
                .or_else(|| {
                    self.not_now_left(key, &party.id, now)
                        .map(|retry_after_ms| LeaseError::NotNow { retry_after_ms })
                });
            if let Some(refusal) = gate {
                let lease = self.lease(key);
                transitions.push(lease.cancel_wait(&party.id, now));
                return Answer {
                    transitions,
                    status: lease.status(now),
                    refusal: Some(refusal),
                };
            }
        }
        let lease = self.lease(key);
        let mut request = AcquireRequest::new(party);
        request.reason = reason;
        let refusal = match lease.acquire(request, now) {
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
        self.declined.retain(|_, until| !now.reached(*until));
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
        // After the leases moved, so a mute until the person goes idle ends
        // on the same tick their last hold freed itself.
        if self.muted(now).is_none() {
            self.mute = None;
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
        let answer = board.ask("s1", agent("a"), None, at(0));
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
            let _ = board.ask("s1", agent("a"), None, at(t));
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
        let queued = board.ask("s1", agent("b"), None, at(1_000));
        assert_eq!(queued.status.position_of(&PartyId::from("b")), Some(0));
        assert_eq!(queued.status.changes_in_ms, Some(8_000));
        // b keeps asking, as the plane does while it waits.
        for t in (1_500..9_000).step_by(500) {
            let answer = board.ask("s1", agent("b"), None, at(t));
            assert_eq!(holder(&answer).as_deref(), Some("a"));
        }
        let answer = board.ask("s1", agent("b"), None, at(9_000));
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
            let _ = board.ask("s1", agent("b"), None, at(t));
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
            let answer = board.ask("s1", agent("a"), None, at(t));
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
        let _ = board.ask("s1", agent("b"), None, at(1_000));
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
        let _ = board.ask("s1", agent("b"), None, at(1_000));
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
