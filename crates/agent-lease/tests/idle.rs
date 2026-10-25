//! The idle timers on the default policy: an agent that stops acting, a
//! person who stops touching the machine, a holder somebody is waiting
//! behind, a waiter that stopped asking, and the stop button's quiet window.
//!
//! Each test hands the lease its own instants, as `arbitration.rs` does, and
//! each one checks the exact millisecond a timer fires and the one before it.

use agent_lease::{
    AcquireRequest, DepartureCause, HolderKind, Lease, LeaseError, LeaseInstant, LeaseOutcome,
    LeasePhase, LeasePolicy, Party, PartyId,
};

fn at(ms: u64) -> LeaseInstant {
    LeaseInstant::from_millis(ms)
}

fn pid(id: &str) -> PartyId {
    PartyId::from(id)
}

fn agent(id: &str) -> Party {
    Party::new(id, HolderKind::Agent, format!("agent {id}"))
}

fn person() -> Party {
    Party::new("person", HolderKind::Human, "a person")
}

fn seat(lease: &mut Lease, who: Party, now: LeaseInstant) {
    let _ = lease
        .acquire(AcquireRequest::new(who), now)
        .expect("the seat was free");
    let _ = lease.confirm_release(now);
    assert_eq!(lease.phase(), LeasePhase::Held);
}

fn holder(lease: &Lease) -> Option<String> {
    lease.holder().map(|h| h.party.id.to_string())
}

#[test]
fn the_defaults_are_short_enough_to_matter() {
    let policy = LeasePolicy::default();
    assert_eq!(policy.idle_revoke_ms, 30_000);
    assert_eq!(policy.person_idle_ms, 20_000);
    assert_eq!(policy.contended_idle_ms, 8_000);
    assert_eq!(policy.queue_ttl_ms, 15_000);
    assert_eq!(policy.force_release_backoff_ms, 20_000);
    // The contended handover never cuts under the floor that protects a drag.
    assert!(policy.contended_idle_ms > policy.min_hold_ms);
}

#[test]
fn an_agent_with_no_input_for_thirty_seconds_loses_the_lease() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, agent("a"), at(0));
    lease.note_intent(&pid("a"), at(5_000));
    assert!(!lease.tick(at(34_999)).changed());
    let gone = lease.tick(at(35_000));
    assert_eq!(
        gone.departed.expect("idle").cause,
        DepartureCause::IdleRevoked
    );
    assert_eq!(lease.phase(), LeasePhase::Unheld);
}

#[test]
fn renewing_does_not_hold_a_lease_nobody_is_using() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, agent("a"), at(0));
    for t in (1_000..30_000).step_by(1_000) {
        lease.renew(&pid("a"), at(t));
        // Asking again as the holder is a renew too.
        let renewed = lease
            .acquire(AcquireRequest::new(agent("a")), at(t))
            .expect("the holder may ask again");
        assert!(matches!(renewed.outcome, LeaseOutcome::Renewed { .. }));
        assert!(!lease.tick(at(t)).changed());
    }
    assert_eq!(
        lease.tick(at(30_000)).departed.expect("idle").cause,
        DepartureCause::IdleRevoked
    );
}

#[test]
fn a_person_keeps_the_machine_while_active_and_hands_it_back_after_twenty_seconds() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, person(), at(0));
    lease.note_intent(&pid("person"), at(10_000));
    assert!(!lease.tick(at(29_999)).changed());
    assert_eq!(
        lease.tick(at(30_000)).departed.expect("idle").cause,
        DepartureCause::IdleRevoked
    );
    // And an agent may have it straight away.
    let granted = lease
        .acquire(AcquireRequest::new(agent("a")), at(30_001))
        .expect("free again");
    assert!(matches!(granted.outcome, LeaseOutcome::Granted { .. }));
}

#[test]
fn an_agent_queued_behind_a_person_is_granted_when_the_person_goes_quiet() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, person(), at(0));
    let queued = lease
        .acquire(AcquireRequest::new(agent("a")), at(1_000))
        .expect("an agent may wait behind a person");
    assert_eq!(queued.outcome, LeaseOutcome::Queued { position: 0 });
    // The agent keeps asking, and the contended rule does not apply to a
    // person: only the person's own idle time hands it on.
    for t in (2_000..20_000).step_by(1_000) {
        let _ = lease.acquire(AcquireRequest::new(agent("a")), at(t));
        assert!(!lease.tick(at(t)).changed() || holder(&lease).as_deref() == Some("person"));
    }
    assert_eq!(holder(&lease).as_deref(), Some("person"));
    let handed = lease.tick(at(20_000));
    assert!(matches!(handed.outcome, LeaseOutcome::Granted { .. }));
    assert_eq!(holder(&lease).as_deref(), Some("a"));
}

#[test]
fn a_waiter_takes_over_eight_seconds_after_it_arrives_if_the_holder_does_nothing() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, agent("a"), at(0));
    // The holder has been quiet for twenty seconds when the waiter arrives,
    // and still gets the whole grace from that moment.
    let _ = lease
        .acquire(AcquireRequest::new(agent("b")), at(20_000))
        .expect("queued");
    let status = lease.status(at(20_000));
    assert_eq!(status.changes_in_ms, Some(8_000));
    assert_eq!(status.queue.len(), 1);
    assert_eq!(status.queue[0].label, "agent b");
    let _ = lease.acquire(AcquireRequest::new(agent("b")), at(27_000));
    assert!(!lease.tick(at(27_999)).changed());
    let handed = lease.tick(at(28_000));
    assert_eq!(
        handed.departed.as_ref().expect("a left").cause,
        DepartureCause::YieldedToWaiter
    );
    assert!(handed.must_release(), "R11 holds on a handover by timeout");
    assert_eq!(holder(&lease).as_deref(), Some("b"));
}

#[test]
fn a_holder_that_acts_while_somebody_waits_keeps_it() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, agent("a"), at(0));
    let _ = lease.acquire(AcquireRequest::new(agent("b")), at(1_000));
    for t in (2_000..60_000).step_by(1_000) {
        let _ = lease.acquire(AcquireRequest::new(agent("b")), at(t));
        if t % 5_000 == 0 {
            lease.note_intent(&pid("a"), at(t));
        }
        let _ = lease.tick(at(t));
        assert_eq!(holder(&lease).as_deref(), Some("a"), "at {t}");
    }
}

#[test]
fn the_contended_handover_waits_out_the_minimum_hold() {
    let policy = LeasePolicy {
        contended_idle_ms: 1_000,
        min_hold_ms: 3_000,
        ..LeasePolicy::default()
    };
    let mut lease = Lease::new(
        "s",
        agent_lease::LeaseConfig {
            mode: agent_lease::LeaseMode::Exclusive,
            policy,
        },
    )
    .expect("exclusive");
    seat(&mut lease, agent("a"), at(0));
    let _ = lease.acquire(AcquireRequest::new(agent("b")), at(100));
    assert!(!lease.tick(at(2_999)).changed());
    assert_eq!(
        lease.tick(at(3_000)).departed.expect("handed on").cause,
        DepartureCause::YieldedToWaiter
    );
}

#[test]
fn a_waiter_that_keeps_asking_keeps_its_place_and_one_that_stops_is_dropped() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, person(), at(0));
    let _ = lease.acquire(AcquireRequest::new(agent("keen")), at(0));
    let _ = lease.acquire(AcquireRequest::new(agent("gone")), at(0));
    for t in (1_000..=15_000).step_by(1_000) {
        lease.note_intent(&pid("person"), at(t));
        let _ = lease.acquire(AcquireRequest::new(agent("keen")), at(t));
    }
    let swept = lease.tick(at(15_000));
    assert_eq!(swept.expired_waiters.len(), 1);
    assert_eq!(swept.expired_waiters[0].party.id, pid("gone"));
    assert_eq!(lease.queue_position(&pid("keen")), Some(0));
    // Waiting time is counted from the first ask, which asking again does not
    // move.
    assert_eq!(lease.status(at(15_000)).queue[0].waiting_ms, 15_000);
}

#[test]
fn the_stop_window_is_twenty_seconds() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, agent("a"), at(0));
    let _ = lease.force_release(at(1_000));
    assert_eq!(
        lease
            .acquire(AcquireRequest::new(agent("a")), at(1_000))
            .expect_err("refused"),
        LeaseError::ForceReleased {
            retry_after_ms: 20_000
        }
    );
    assert_eq!(lease.status(at(11_000)).refused_for_ms, Some(10_000));
    assert!(lease
        .acquire(AcquireRequest::new(agent("a")), at(21_000))
        .is_ok());
}

#[test]
fn status_names_the_holder_its_age_its_idle_time_and_when_it_frees() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, agent("a"), at(1_000));
    lease.note_intent(&pid("a"), at(4_000));
    let status = lease.status(at(10_000));
    let held = status.holder.expect("held");
    assert_eq!(held.kind, HolderKind::Agent);
    assert_eq!(held.label, "agent a");
    assert_eq!(held.since, at(1_000));
    assert_eq!(held.held_for_ms, 9_000);
    assert_eq!(held.idle_for_ms, 6_000);
    // Thirty seconds after the last input.
    assert_eq!(status.changes_in_ms, Some(24_000));
    assert!(status.queue.is_empty());
}

#[test]
fn a_person_asking_preempts_an_agent_rather_than_waiting() {
    let mut lease = Lease::exclusive("s");
    seat(&mut lease, agent("a"), at(0));
    let started = lease
        .acquire(AcquireRequest::new(person()), at(500))
        .expect("a person outranks an agent");
    assert!(matches!(
        started.outcome,
        LeaseOutcome::PreemptionStarted { .. }
    ));
    assert!(lease.status(at(500)).person_holds());
    assert!(!lease.fence(&pid("a")).is_allowed());
}
