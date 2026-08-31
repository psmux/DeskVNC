//! The arbitration rules from `08 §5` and `§6`, and the R11 obligation that
//! rides on every one of them.
//!
//! Every test here hands the lease its own instants. Nothing sleeps, because
//! a test that sleeps is a test that goes red on a loaded CI box for reasons
//! that have nothing to do with arbitration, and the crate was built clock
//! injected precisely so this file could be written this way.

use agent_lease::{
    AcquireRequest, DepartureCause, Fencing, Lease, LeaseConfig, LeaseError, LeaseInstant,
    LeaseMode, LeaseOutcome, LeasePhase, LeaseTransition, Party, PartyId, ReleaseObligation,
};
use agent_lease::{HolderKind, LeasePolicy};

fn at(ms: u64) -> LeaseInstant {
    LeaseInstant::from_millis(ms)
}

fn pid(id: &str) -> PartyId {
    PartyId::from(id)
}

fn party(id: &str, kind: HolderKind) -> Party {
    Party::new(id, kind, format!("{kind:?} {id}"))
}

fn agent(id: &str) -> Party {
    party(id, HolderKind::Agent)
}

fn human(id: &str) -> Party {
    party(id, HolderKind::Human)
}

/// Acquire and complete the handover, which is what "holds it" means: the
/// grant alone leaves the lease in [`LeasePhase::HandingOver`] with a release
/// outstanding.
fn seat(lease: &mut Lease, who: Party, now: LeaseInstant) {
    let granted = lease
        .acquire(AcquireRequest::new(who), now)
        .expect("the seat should have been free");
    assert!(
        granted.must_release(),
        "R11: a grant owes the limb a release"
    );
    assert_eq!(granted.to, LeasePhase::HandingOver);
    let done = lease.confirm_release(now);
    assert!(!done.must_release());
    assert_eq!(lease.phase(), LeasePhase::Held);
}

fn holder_id(lease: &Lease) -> Option<PartyId> {
    lease.holder().map(|h| h.party.id.clone())
}

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

#[test]
fn shared_control_is_refused_outright() {
    let err = Lease::new(
        "limb-1",
        LeaseConfig {
            mode: LeaseMode::Shared,
            policy: LeasePolicy::default(),
        },
    )
    .expect_err("R12: shared control is not built in this version");
    assert_eq!(err, LeaseError::SharedModeUnavailable);
}

#[test]
fn exclusive_is_the_default_and_is_accepted() {
    let lease = Lease::new("limb-1", LeaseConfig::default()).expect("exclusive is buildable");
    assert_eq!(lease.mode(), LeaseMode::Exclusive);
    assert_eq!(lease.phase(), LeasePhase::Unheld);
}

// ---------------------------------------------------------------------------
// The ladder
// ---------------------------------------------------------------------------

#[test]
fn an_agent_is_preempted_by_a_human() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));

    // Half a second in, well inside the three second floor. The floor is
    // lifted for exactly this pairing (`08 §6.1` step 3).
    let asked = lease
        .acquire(AcquireRequest::new(human("h")), at(500))
        .expect("a person outranks an agent");
    assert!(matches!(
        asked.outcome,
        LeaseOutcome::PreemptionStarted { .. }
    ));
    assert_eq!(asked.to, LeasePhase::PreemptPending);
    assert!(
        asked.must_release(),
        "R11: dispatch stops here, so the release is owed here"
    );

    // The agent's dispatch stopped at once, without acknowledging anything.
    assert_eq!(lease.fence(&pid("a")), Fencing::ReleaseOnly);
    assert_eq!(lease.fence(&pid("h")), Fencing::ReleaseOnly);

    // The bad case: the agent never answers and the grace runs out.
    let flipped = lease.tick(at(2_500));
    let departed = flipped.departed.as_ref().expect("the agent lost it");
    assert_eq!(departed.cause, DepartureCause::Preempted);
    assert_eq!(departed.party.id, pid("a"));
    assert!(flipped.must_release());
    assert_eq!(holder_id(&lease), Some(pid("h")));
    assert_eq!(lease.phase(), LeasePhase::HandingOver);
}

#[test]
fn the_fast_path_flips_as_soon_as_the_agent_lets_go() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    let lease_id = lease.holder().expect("held").lease_id;

    let _ = lease.acquire(AcquireRequest::new(human("h")), at(500));
    let released = lease.release(&pid("a"), lease_id, at(600));

    assert_eq!(
        released
            .departed
            .as_ref()
            .expect("the agent departed")
            .cause,
        DepartureCause::Released
    );
    assert!(released.must_release());
    assert_eq!(holder_id(&lease), Some(pid("h")));
}

#[test]
fn a_human_is_not_preempted_by_an_agent() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, human("h"), at(0));

    let refused = lease
        .acquire(AcquireRequest::new(agent("a")).no_queue(), at(10_000))
        .expect_err("an agent does not outrank a person");
    match refused {
        LeaseError::Held { holder_kind, .. } => assert_eq!(holder_kind, HolderKind::Human),
        other => panic!("expected the lease to be reported held, got {other:?}"),
    }

    // Asking politely puts the agent in the queue and changes nothing else.
    let queued = lease
        .acquire(AcquireRequest::new(agent("a")), at(10_000))
        .expect("queueing is allowed");
    assert_eq!(queued.outcome, LeaseOutcome::Queued { position: 0 });
    assert!(
        !queued.must_release(),
        "a queue entry owes the limb nothing"
    );
    assert_eq!(lease.phase(), LeasePhase::Held);
    assert_eq!(holder_id(&lease), Some(pid("h")));
    assert_eq!(lease.fence(&pid("h")), Fencing::Allowed);

    // And time does not change the answer: the queue does not promote anyone
    // while the holder is still there and still acting.
    lease.note_intent(&pid("h"), at(30_000));
    let quiet = lease.tick(at(31_000));
    assert!(!quiet.changed());
    assert_eq!(holder_id(&lease), Some(pid("h")));
}

#[test]
fn equal_priority_queues_rather_than_steals() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, human("first"), at(0));

    let queued = lease
        .acquire(AcquireRequest::new(human("second")), at(10_000))
        .expect("a peer may wait");
    assert_eq!(queued.outcome, LeaseOutcome::Queued { position: 0 });
    assert!(!queued.must_release());
    assert_eq!(queued.from, LeasePhase::Held);
    assert_eq!(queued.to, LeasePhase::Held);
    assert_eq!(holder_id(&lease), Some(pid("first")));
    assert_eq!(lease.queue_position(&pid("second")), Some(0));
}

/// The whole ladder, in one table. `now` sits past the minimum hold so this
/// measures priority and nothing else.
#[test]
fn the_ladder_decides_who_may_take_the_wheel() {
    use HolderKind::{Admin, Agent, Human, Owner};

    let kinds = [Admin, Owner, Human, Agent];
    for holder in kinds {
        for requester in kinds {
            let mut lease = Lease::exclusive("limb-1");
            seat(&mut lease, party("held", holder), at(0));

            let outcome = lease
                .acquire(AcquireRequest::new(party("asking", requester)), at(10_000))
                .expect("queueing is allowed, so nothing here is refused")
                .outcome;

            let outranks = requester.default_priority() > holder.default_priority();
            if outranks {
                assert!(
                    matches!(outcome, LeaseOutcome::PreemptionStarted { .. }),
                    "{requester:?} ({}) should preempt {holder:?} ({})",
                    requester.default_priority(),
                    holder.default_priority()
                );
            } else {
                assert_eq!(
                    outcome,
                    LeaseOutcome::Queued { position: 0 },
                    "{requester:?} ({}) should wait behind {holder:?} ({})",
                    requester.default_priority(),
                    holder.default_priority()
                );
            }
        }
    }
}

#[test]
fn a_priority_override_moves_a_party_up_the_ladder() {
    let mut lease = Lease::exclusive("limb-1");
    // The unattended run a deployment does not want interrupted by a passing
    // click: an agent placed above `human` on purpose.
    seat(&mut lease, agent("a").with_priority(500), at(0));

    let queued = lease
        .acquire(AcquireRequest::new(human("h")), at(10_000))
        .expect("queueing is allowed");
    assert_eq!(queued.outcome, LeaseOutcome::Queued { position: 0 });
    assert_eq!(holder_id(&lease), Some(pid("a")));
}

// ---------------------------------------------------------------------------
// The minimum hold
// ---------------------------------------------------------------------------

#[test]
fn the_floor_protects_a_hand_on_a_mouse() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, human("first"), at(0));

    let refused = lease
        .acquire(
            AcquireRequest::new(party("boss", HolderKind::Admin)).no_queue(),
            at(1_000),
        )
        .expect_err("the floor has not elapsed");
    assert_eq!(
        refused,
        LeaseError::MinHoldNotElapsed {
            retry_after_ms: 2_000
        }
    );

    // Past the floor, the same request goes through.
    let taken = lease
        .acquire(
            AcquireRequest::new(party("boss", HolderKind::Admin)).no_queue(),
            at(3_000),
        )
        .expect("the floor has elapsed");
    assert!(matches!(
        taken.outcome,
        LeaseOutcome::PreemptionStarted { .. }
    ));
}

#[test]
fn the_floor_is_lifted_for_a_person_taking_over_from_an_agent() {
    for requester in [HolderKind::Human, HolderKind::Owner, HolderKind::Admin] {
        let mut lease = Lease::exclusive("limb-1");
        seat(&mut lease, agent("a"), at(0));
        let taken = lease
            .acquire(
                AcquireRequest::new(party("person", requester)).no_queue(),
                at(1),
            )
            .expect("an agent has no claim on the floor");
        assert!(
            matches!(taken.outcome, LeaseOutcome::PreemptionStarted { .. }),
            "{requester:?} should not have to wait out the floor behind an agent"
        );
    }
}

#[test]
fn an_agent_still_waits_out_the_floor_behind_another_agent() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a").with_priority(10), at(0));
    let refused = lease
        .acquire(AcquireRequest::new(agent("b")).no_queue(), at(1_000))
        .expect_err("the floor applies to every other pairing");
    assert!(matches!(refused, LeaseError::MinHoldNotElapsed { .. }));
}

// ---------------------------------------------------------------------------
// The queue
// ---------------------------------------------------------------------------

#[test]
fn the_queue_refuses_at_its_cap_rather_than_growing() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, human("holder"), at(0));
    let cap = lease.policy().max_queue_depth;

    for n in 0..cap {
        let queued = lease
            .acquire(AcquireRequest::new(agent(&format!("a{n}"))), at(10_000))
            .expect("under the cap");
        assert_eq!(queued.outcome, LeaseOutcome::Queued { position: n });
    }
    assert_eq!(lease.queue_depth(), cap);

    let refused = lease
        .acquire(AcquireRequest::new(agent("one-too-many")), at(10_000))
        .expect_err("the cap refuses rather than growing");
    assert_eq!(refused, LeaseError::QueueFull { depth: cap });
    assert_eq!(lease.queue_depth(), cap, "the refusal did not grow it");
}

#[test]
fn the_queue_is_priority_descending_and_first_come_first_served_within_one() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, party("boss", HolderKind::Admin), at(0));

    for (id, kind) in [
        ("agent-1", HolderKind::Agent),
        ("human-1", HolderKind::Human),
        ("agent-2", HolderKind::Agent),
        ("owner-1", HolderKind::Owner),
        ("human-2", HolderKind::Human),
    ] {
        let _ = lease
            .acquire(AcquireRequest::new(party(id, kind)), at(10_000))
            .expect("under the cap");
    }

    let order: Vec<&str> = lease.queue().iter().map(|w| w.party.id.as_str()).collect();
    assert_eq!(
        order,
        vec!["owner-1", "human-1", "human-2", "agent-1", "agent-2"]
    );
}

#[test]
fn asking_twice_while_queued_reports_the_position_instead_of_taking_a_second_slot() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, human("holder"), at(0));

    let _ = lease
        .acquire(AcquireRequest::new(agent("a")), at(10_000))
        .expect("queued");
    let again = lease
        .acquire(AcquireRequest::new(agent("a")), at(11_000))
        .expect("queued again");
    assert_eq!(again.outcome, LeaseOutcome::Queued { position: 0 });
    assert_eq!(
        lease.queue_depth(),
        1,
        "an agent retrying on a timer must not fill the queue with itself"
    );
}

#[test]
fn a_waiter_that_has_waited_a_minute_is_dropped() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, human("holder"), at(0));
    let _ = lease
        .acquire(AcquireRequest::new(agent("a")), at(1_000))
        .expect("queued");

    // The holder keeps working, so nothing here is the holder's own expiry.
    lease.note_intent(&pid("holder"), at(59_000));

    let early = lease.tick(at(60_000));
    assert!(early.expired_waiters.is_empty(), "one second short");

    let swept = lease.tick(at(61_000));
    assert_eq!(swept.expired_waiters.len(), 1);
    assert_eq!(swept.expired_waiters[0].party.id, pid("a"));
    assert!(
        !swept.must_release(),
        "a waiter never held anything, so it owes the limb nothing"
    );
    assert_eq!(lease.queue_depth(), 0);
    assert_eq!(holder_id(&lease), Some(pid("holder")));
}

#[test]
fn an_expired_waiter_is_never_promoted() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, human("holder"), at(0));
    let _ = lease
        .acquire(AcquireRequest::new(agent("stale")), at(0))
        .expect("queued");

    // The holder's hard expiry and the waiter's queue expiry land on the same
    // instant. The waiter is swept first, so the machine goes to nobody
    // rather than to an agent that stopped asking a minute ago.
    let swept = lease.tick(at(60_000));
    assert_eq!(swept.expired_waiters.len(), 1);
    assert_eq!(swept.outcome, LeaseOutcome::Unheld);
    assert_eq!(lease.phase(), LeasePhase::Unheld);
}

#[test]
fn releasing_hands_the_wheel_to_the_head_of_the_queue() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, human("holder"), at(0));
    let lease_id = lease.holder().expect("held").lease_id;
    let _ = lease
        .acquire(AcquireRequest::new(agent("a")), at(1_000))
        .expect("queued");
    let _ = lease
        .acquire(AcquireRequest::new(human("h2")), at(1_100))
        .expect("queued");

    let released = lease.release(&pid("holder"), lease_id, at(2_000));
    assert!(
        released.must_release(),
        "R11 applies to a voluntary handover too"
    );
    assert_eq!(
        holder_id(&lease),
        Some(pid("h2")),
        "priority order, not arrival order"
    );
    assert_eq!(lease.queue_depth(), 1);
}

#[test]
fn giving_up_waiting_takes_the_party_out_of_the_queue() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, human("holder"), at(0));
    let lease_id = lease.holder().expect("held").lease_id;
    let _ = lease
        .acquire(AcquireRequest::new(agent("a")), at(1_000))
        .expect("queued");

    let gone = lease.cancel_wait(&pid("a"), at(2_000));
    assert_eq!(gone.outcome, LeaseOutcome::WaitCancelled);
    assert!(!gone.must_release());
    assert_eq!(lease.queue_depth(), 0);

    // And the wheel does not go to somebody who stopped asking.
    let released = lease.release(&pid("holder"), lease_id, at(3_000));
    assert_eq!(released.outcome, LeaseOutcome::Unheld);
    assert_eq!(holder_id(&lease), None);
}

#[test]
fn withdrawing_a_preemption_gives_the_holder_the_wheel_back() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    let _ = lease
        .acquire(AcquireRequest::new(human("h")), at(500))
        .expect("preemption started");

    let called_off = lease.cancel_wait(&pid("h"), at(700));
    assert_eq!(called_off.outcome, LeaseOutcome::PreemptionAbandoned);
    assert_eq!(lease.phase(), LeasePhase::Held);
    assert_eq!(holder_id(&lease), Some(pid("a")));
    assert!(
        called_off.must_release(),
        "the agent gets dispatch back, so the limb gets a release first"
    );
    assert_eq!(lease.fence(&pid("a")), Fencing::Allowed);

    // And the deadline that was running is gone with it.
    let quiet = lease.tick(at(10_000));
    assert!(!quiet.changed());
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

#[test]
fn an_expired_holder_frees_the_lease() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));

    let early = lease.tick(at(59_999));
    assert!(!early.changed(), "one millisecond short of the hard expiry");

    let expired = lease.tick(at(60_000));
    let departed = expired.departed.as_ref().expect("the holder went");
    assert_eq!(departed.cause, DepartureCause::Expired);
    assert_eq!(departed.held_for_ms, 60_000);
    assert!(
        expired.must_release(),
        "R11: the crashed agent case is exactly why this obligation exists"
    );
    assert_eq!(expired.outcome, LeaseOutcome::Unheld);
    assert_eq!(lease.phase(), LeasePhase::Unheld);
    assert_eq!(lease.fence(&pid("a")), Fencing::ReleaseOnly);
}

#[test]
fn an_intent_pushes_the_hard_expiry_out() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    lease.note_intent(&pid("a"), at(59_000));

    assert!(!lease.tick(at(60_000)).changed());
    assert_eq!(
        lease
            .tick(at(119_000))
            .departed
            .expect("sixty seconds after the last intent")
            .cause,
        DepartureCause::Expired
    );
}

#[test]
fn a_holder_that_renews_but_never_acts_is_revoked_for_idling() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));

    // The shape of a crashed agent whose socket is still open: a heartbeat
    // every thirty seconds and nothing else. The hard expiry never fires.
    for beat in 1..=4 {
        lease.renew(&pid("a"), at(beat * 30_000));
    }

    let revoked = lease.tick(at(120_000));
    let departed = revoked
        .departed
        .as_ref()
        .expect("two minutes without an intent");
    assert_eq!(departed.cause, DepartureCause::IdleRevoked);
    assert!(revoked.must_release());
    assert_eq!(lease.phase(), LeasePhase::Unheld);
}

#[test]
fn a_dropped_transport_keeps_the_lease_for_the_grace_and_no_longer() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));

    let dropped = lease.set_connected(&pid("a"), false, at(1_000));
    assert_eq!(dropped.to, LeasePhase::HeldGrace);
    assert!(
        dropped.must_release(),
        "dispatch stopped, so the limb is owed a release"
    );
    assert_eq!(lease.fence(&pid("a")), Fencing::ReleaseOnly);
    assert_eq!(
        holder_id(&lease),
        Some(pid("a")),
        "the wheel is still theirs"
    );

    assert!(!lease.tick(at(10_999)).changed());
    let lost = lease.tick(at(11_000));
    assert_eq!(
        lost.departed.as_ref().expect("the grace ran out").cause,
        DepartureCause::DisconnectGraceElapsed
    );
    assert_eq!(lease.phase(), LeasePhase::Unheld);
}

#[test]
fn a_reconnect_inside_the_grace_keeps_the_wheel() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    let _ = lease.set_connected(&pid("a"), false, at(1_000));

    let back = lease.set_connected(&pid("a"), true, at(5_000));
    assert_eq!(back.to, LeasePhase::Held);
    assert!(
        back.must_release(),
        "dispatch resumes, so the release applies"
    );
    assert_eq!(lease.fence(&pid("a")), Fencing::Allowed);
    assert!(!lease.tick(at(11_000)).changed());
}

#[test]
fn a_disconnected_holder_is_taken_over_without_the_polite_grace() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    let _ = lease.set_connected(&pid("a"), false, at(1_000));

    let taken = lease
        .acquire(AcquireRequest::new(human("h")), at(2_000))
        .expect("a person outranks an agent");
    assert!(matches!(taken.outcome, LeaseOutcome::Granted { .. }));
    assert_eq!(
        taken.departed.as_ref().expect("the agent lost it").cause,
        DepartureCause::Preempted
    );
    assert!(taken.must_release());
    assert_eq!(holder_id(&lease), Some(pid("h")));
}

// ---------------------------------------------------------------------------
// Release
// ---------------------------------------------------------------------------

#[test]
fn a_release_from_a_stale_holder_is_a_harmless_no_op() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    let stale = lease.holder().expect("held").lease_id;

    // A person takes over, and only then does the agent's cleanup path run,
    // which is the ordering a crashed agent actually produces.
    let _ = lease
        .acquire(AcquireRequest::new(human("h")), at(500))
        .expect("preemption started");
    let _ = lease.tick(at(2_500));
    let _ = lease.confirm_release(at(2_501));
    assert_eq!(holder_id(&lease), Some(pid("h")));

    let late = lease.release(&pid("a"), stale, at(3_000));
    assert_eq!(late.outcome, LeaseOutcome::Unchanged);
    assert!(!late.changed());
    assert!(!late.must_release());
    assert_eq!(holder_id(&lease), Some(pid("h")), "the new holder kept it");
    assert_eq!(lease.fence(&pid("h")), Fencing::Allowed);
}

#[test]
fn releasing_twice_is_the_same_as_releasing_once() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    let lease_id = lease.holder().expect("held").lease_id;

    let first = lease.release(&pid("a"), lease_id, at(1_000));
    assert_eq!(first.outcome, LeaseOutcome::Unheld);
    let second = lease.release(&pid("a"), lease_id, at(1_001));
    assert_eq!(second.outcome, LeaseOutcome::Unchanged);
    assert!(!second.must_release());
}

#[test]
fn a_renew_keeps_the_lease_id_it_was_granted() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    let lease_id = lease.holder().expect("held").lease_id;

    let renewed = lease
        .acquire(AcquireRequest::new(agent("a")), at(1_000))
        .expect("the holder asking again is a renew");
    assert_eq!(renewed.outcome, LeaseOutcome::Renewed { lease_id });
    assert!(!renewed.must_release());
    assert_eq!(lease.phase(), LeasePhase::Held);

    // The id the party is holding still works, which is the point.
    let released = lease.release(&pid("a"), lease_id, at(2_000));
    assert_eq!(released.outcome, LeaseOutcome::Unheld);
}

// ---------------------------------------------------------------------------
// The handover, which is R11 made structural
// ---------------------------------------------------------------------------

#[test]
fn nobody_dispatches_until_the_release_is_reported_done() {
    let mut lease = Lease::exclusive("limb-1");
    let granted = lease
        .acquire(AcquireRequest::new(human("h")), at(0))
        .expect("free");
    assert!(granted.must_release());
    assert_eq!(lease.phase(), LeasePhase::HandingOver);
    assert_eq!(
        lease.fence(&pid("h")),
        Fencing::ReleaseOnly,
        "even the new holder is fenced until the limb has been released"
    );

    let done = lease.confirm_release(at(1));
    assert!(matches!(
        done.outcome,
        LeaseOutcome::HandoverComplete { .. }
    ));
    assert!(!done.must_release());
    assert_eq!(lease.fence(&pid("h")), Fencing::Allowed);

    // Confirming again changes nothing.
    let again = lease.confirm_release(at(2));
    assert!(!again.changed());
}

#[test]
fn the_idle_clock_starts_at_the_flip_and_not_at_the_grant() {
    let mut lease = Lease::exclusive("limb-1");
    let _ = lease
        .acquire(AcquireRequest::new(agent("a")), at(0))
        .expect("free");
    // A slow release write. The holder could not have dispatched anything in
    // the meantime, so it must not be charged for the wait.
    let _ = lease.confirm_release(at(30_000));
    assert!(!lease.tick(at(80_000)).changed());
    assert_eq!(
        lease
            .tick(at(90_000))
            .departed
            .expect("sixty seconds after the flip")
            .cause,
        DepartureCause::Expired
    );
}

#[test]
fn a_third_party_is_fenced_at_all_times() {
    let mut lease = Lease::exclusive("limb-1");
    assert_eq!(lease.fence(&pid("nobody")), Fencing::ReleaseOnly);
    seat(&mut lease, human("h"), at(0));
    assert_eq!(lease.fence(&pid("nobody")), Fencing::ReleaseOnly);
    let _ = lease.force_release(at(1_000));
    assert_eq!(lease.fence(&pid("nobody")), Fencing::ReleaseOnly);
}

// ---------------------------------------------------------------------------
// The panic chord
// ---------------------------------------------------------------------------

#[test]
fn a_force_release_takes_the_wheel_from_everyone_and_holds_the_door_shut() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    let _ = lease
        .acquire(AcquireRequest::new(agent("b")), at(10_000))
        .expect("queued");

    let forced = lease.force_release(at(11_000));
    assert!(forced.must_release());
    assert_eq!(
        forced
            .departed
            .as_ref()
            .expect("somebody was driving")
            .cause,
        DepartureCause::ForceReleased
    );
    assert_eq!(lease.phase(), LeasePhase::Unheld);
    assert_eq!(
        lease.queue_depth(),
        0,
        "a queue of agents waiting to grab the wheel is what the chord was pressed to stop"
    );
    assert_eq!(forced.expired_waiters.len(), 1);

    // The backoff, without which an agent in a loop re acquires before the
    // person can click anything.
    let refused = lease
        .acquire(AcquireRequest::new(agent("a")), at(12_000))
        .expect_err("the backoff is running");
    assert_eq!(
        refused,
        LeaseError::ForceReleased {
            retry_after_ms: 29_000
        }
    );

    let allowed = lease.acquire(AcquireRequest::new(agent("a")), at(41_000));
    assert!(
        allowed.is_ok(),
        "thirty seconds later the limb is usable again"
    );
}

#[test]
fn the_chord_releases_the_limb_even_when_nobody_was_holding_it() {
    let mut lease = Lease::exclusive("limb-1");
    let forced = lease.force_release(at(0));
    assert!(
        forced.must_release(),
        "a stuck grab is exactly the case where the plane's belief about what is held was wrong"
    );
    assert!(forced.departed.is_none());
}

// ---------------------------------------------------------------------------
// What every party can read
// ---------------------------------------------------------------------------

#[test]
fn the_view_names_the_holder_and_the_recipients_own_position() {
    let mut lease = Lease::exclusive("limb-1");
    seat(&mut lease, agent("a"), at(0));
    let _ = lease
        .acquire(AcquireRequest::new(human("h")), at(10_000))
        .expect("preemption started");

    let watcher = lease.view_for(&pid("someone-else"));
    assert_eq!(watcher.holder_kind, Some(HolderKind::Agent));
    assert_eq!(watcher.holder_label.as_deref(), Some("Agent a"));
    assert!(!watcher.you_hold);
    assert_eq!(watcher.queue_position, None);
    assert_eq!(watcher.phase, LeasePhase::PreemptPending);

    let driver = lease.view_for(&pid("a"));
    assert!(driver.you_hold);
}

// ---------------------------------------------------------------------------
// R11, swept across every path that changes the holder
// ---------------------------------------------------------------------------

/// The invariant, checked over a scripted run rather than one path at a time:
/// whenever the party allowed to dispatch changes, either the transition says
/// the limb is owed a release, or it is the one transition that reports a
/// release was just performed.
#[test]
fn every_change_of_holder_carries_the_release_obligation() {
    let mut lease = Lease::exclusive("limb-1");
    let mut previous: Option<PartyId> = None;

    let check = |lease: &Lease, transition: &LeaseTransition, previous: &mut Option<PartyId>| {
        let now_holding = lease
            .holder()
            .filter(|_| lease.phase() == LeasePhase::Held)
            .map(|h| h.party.id.clone());
        let discharged = matches!(transition.outcome, LeaseOutcome::HandoverComplete { .. });
        if now_holding != *previous && !discharged {
            assert_eq!(
                transition.release,
                ReleaseObligation::Required,
                "R11 violated moving from {previous:?} to {now_holding:?} via {:?}",
                transition.outcome
            );
        }
        *previous = now_holding;
    };

    // Free, then granted, then dispatching.
    let t = lease
        .acquire(AcquireRequest::new(agent("a")), at(0))
        .expect("free");
    check(&lease, &t, &mut previous);
    let t = lease.confirm_release(at(1));
    check(&lease, &t, &mut previous);

    // A person takes over.
    let t = lease
        .acquire(AcquireRequest::new(human("h")), at(1_000))
        .expect("a person outranks an agent");
    check(&lease, &t, &mut previous);
    let t = lease.tick(at(3_000));
    check(&lease, &t, &mut previous);
    let t = lease.confirm_release(at(3_001));
    check(&lease, &t, &mut previous);

    // Their transport drops, comes back, and drops for good.
    let t = lease.set_connected(&pid("h"), false, at(4_000));
    check(&lease, &t, &mut previous);
    let t = lease.set_connected(&pid("h"), true, at(5_000));
    check(&lease, &t, &mut previous);
    let t = lease.set_connected(&pid("h"), false, at(6_000));
    check(&lease, &t, &mut previous);
    let t = lease.tick(at(16_000));
    check(&lease, &t, &mut previous);

    // An agent takes the empty seat, idles, and is revoked.
    let t = lease
        .acquire(AcquireRequest::new(agent("b")), at(17_000))
        .expect("free");
    check(&lease, &t, &mut previous);
    let t = lease.confirm_release(at(17_001));
    check(&lease, &t, &mut previous);
    let t = lease.tick(at(90_000));
    check(&lease, &t, &mut previous);

    assert_eq!(lease.phase(), LeasePhase::Unheld);
}

#[test]
fn a_transition_names_the_limb_and_the_instant_it_was_given() {
    let mut lease = Lease::exclusive("limb-7");
    let granted = lease
        .acquire(AcquireRequest::new(agent("a")), at(1_234))
        .expect("free");
    assert_eq!(granted.limb.as_str(), "limb-7");
    assert_eq!(granted.at, at(1_234));
    assert_eq!(granted.from, LeasePhase::Unheld);
    assert_eq!(granted.to, LeasePhase::HandingOver);
    assert_eq!(granted.queue_depth, 0);
}
