//! The serialised shape of a lease is a contract, so pin it literally.
//!
//! Two readers depend on these spellings and neither of them fails to
//! compile when one changes. A pane renders the lease state and must always
//! say when an agent is driving (`08 §5.5`, which `09 §8` makes a refusal to
//! build anything else). A trace stores every lease change in `traces.db`
//! (`10 §3`), and R14 rules that a recorded perception is byte identical to
//! what the agent was handed, which is worth nothing if the record's keys
//! drift underneath it.
//!
//! Modelled on `crates/remote-core/tests/wire_compat.rs`, which exists for
//! exactly this reason. Assertions are on literal strings rather than
//! `to_value` round trips, because a round trip passes happily when both
//! sides are wrong together.

use agent_lease::{
    AcquireRequest, Departure, DepartureCause, Fencing, HolderKind, Lease, LeaseId, LeaseInstant,
    LeaseMode, LeaseOutcome, LeasePhase, LeasePolicy, LeaseTransition, LeaseView, Party, PartyId,
    ReleaseObligation,
};

fn to_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

fn nightly() -> Party {
    Party::new("grant-1", HolderKind::Agent, "nightly run")
}

/// A transition taken from the real thing rather than built by hand, so the
/// pinned shape is the shape callers actually get.
fn sample_transition() -> LeaseTransition {
    let mut lease = Lease::exclusive("limb-1");
    lease
        .acquire(
            AcquireRequest::new(nightly()),
            LeaseInstant::from_millis(1_234),
        )
        .unwrap()
}

// ---------------------------------------------------------------------------
// Spellings
// ---------------------------------------------------------------------------

/// Every enum that crosses the wire is `kebab-case`, matching `remote-core`
/// (`PinScheme`, `RttSource`, `SessionState`). The multi word ones are the
/// ones worth pinning: a default derive would spell them `HeldGrace` and
/// `IdleRevoked`, and nothing would notice until a pane rendered nothing.
#[test]
fn spellings_are_stable() {
    // The ladder, whose names a pane prints next to the machine (`08 §5.2`).
    assert_eq!(to_json(&HolderKind::Admin), "\"admin\"");
    assert_eq!(to_json(&HolderKind::Owner), "\"owner\"");
    assert_eq!(to_json(&HolderKind::Human), "\"human\"");
    assert_eq!(to_json(&HolderKind::Agent), "\"agent\"");

    assert_eq!(to_json(&LeaseMode::Exclusive), "\"exclusive\"");
    assert_eq!(to_json(&LeaseMode::Shared), "\"shared\"");

    // The phases from `08 §5.1`, named there in exactly this order.
    assert_eq!(to_json(&LeasePhase::Unheld), "\"unheld\"");
    assert_eq!(to_json(&LeasePhase::Held), "\"held\"");
    assert_eq!(to_json(&LeasePhase::HeldGrace), "\"held-grace\"");
    assert_eq!(to_json(&LeasePhase::PreemptPending), "\"preempt-pending\"");
    assert_eq!(to_json(&LeasePhase::HandingOver), "\"handing-over\"");

    // R11's obligation. A trace that cannot be filtered on this cannot answer
    // "did the plane release the keys before the handover", which is the one
    // question a stuck modifier incident asks.
    assert_eq!(to_json(&ReleaseObligation::Required), "\"required\"");
    assert_eq!(to_json(&ReleaseObligation::NotRequired), "\"not-required\"");

    assert_eq!(to_json(&DepartureCause::Released), "\"released\"");
    assert_eq!(to_json(&DepartureCause::Preempted), "\"preempted\"");
    assert_eq!(to_json(&DepartureCause::Expired), "\"expired\"");
    assert_eq!(to_json(&DepartureCause::IdleRevoked), "\"idle-revoked\"");
    assert_eq!(
        to_json(&DepartureCause::DisconnectGraceElapsed),
        "\"disconnect-grace-elapsed\""
    );
    assert_eq!(
        to_json(&DepartureCause::ForceReleased),
        "\"force-released\""
    );

    assert_eq!(to_json(&Fencing::Allowed), "\"allowed\"");
    assert_eq!(to_json(&Fencing::ReleaseOnly), "\"release-only\"");
}

/// The variant tags of [`LeaseOutcome`], listed on their own because the
/// internal tagging means these strings are object keys' values rather than
/// bare strings, and a reader greps for them.
#[test]
fn every_outcome_tag_is_kebab_case() {
    let tags = [
        (LeaseOutcome::Unchanged, "unchanged"),
        (
            LeaseOutcome::Renewed {
                lease_id: LeaseId::from_u64(1),
            },
            "renewed",
        ),
        (LeaseOutcome::Queued { position: 0 }, "queued"),
        (LeaseOutcome::WaitCancelled, "wait-cancelled"),
        (LeaseOutcome::PreemptionAbandoned, "preemption-abandoned"),
        (LeaseOutcome::Unheld, "unheld"),
        (
            LeaseOutcome::HandoverComplete {
                lease_id: LeaseId::from_u64(1),
            },
            "handover-complete",
        ),
    ];
    for (outcome, tag) in tags {
        let json = to_json(&outcome);
        assert!(
            json.contains(&format!("\"outcome\":\"{tag}\"")),
            "expected the tag {tag} in {json}"
        );
    }
}

// ---------------------------------------------------------------------------
// The tagged outcome
// ---------------------------------------------------------------------------

/// `LeaseOutcome` is internally tagged on "outcome" with `snake_case` INNER
/// fields, exactly as `remote-core`'s `SessionState` is tagged on "state"
/// (`crates/remote-core/src/state.rs`). Neither half is the serde default and
/// both are easy to lose in a refactor.
#[test]
fn lease_outcome_keeps_its_tag_and_its_inner_field_names() {
    assert_eq!(
        to_json(&LeaseOutcome::Unchanged),
        r#"{"outcome":"unchanged"}"#
    );

    assert_eq!(
        to_json(&LeaseOutcome::Queued { position: 3 }),
        r#"{"outcome":"queued","position":3}"#
    );

    assert_eq!(
        to_json(&LeaseOutcome::Granted {
            lease_id: LeaseId::from_u64(1),
            holder: nightly(),
        }),
        r#"{"outcome":"granted","lease_id":1,"holder":{"id":"grant-1","kind":"agent","label":"nightly run","priority":50}}"#
    );

    // The deadline a person is told they are waiting for (`08 §6.1` step 7).
    // A `LeaseInstant` is transparent over its millisecond count, so it
    // arrives as a bare number and not as `{"0":2000}`.
    assert_eq!(
        to_json(&LeaseOutcome::PreemptionStarted {
            deadline: LeaseInstant::from_millis(2_000),
            requester: Party::new("pane-4", HolderKind::Human, "Alice"),
        }),
        r#"{"outcome":"preemption-started","deadline":2000,"requester":{"id":"pane-4","kind":"human","label":"Alice","priority":100}}"#
    );

    assert_eq!(
        to_json(&LeaseOutcome::HandoverComplete {
            lease_id: LeaseId::from_u64(7),
        }),
        r#"{"outcome":"handover-complete","lease_id":7}"#
    );
}

// ---------------------------------------------------------------------------
// The traced lease change
// ---------------------------------------------------------------------------

/// The keys `10 §3` needs on a traced lease change: which limb, when, where
/// the lease went from and to, what happened, what the plane owed the limb,
/// who lost it and how many were waiting.
#[test]
fn a_traced_lease_change_has_the_keys_ten_needs() {
    assert_eq!(
        to_json(&sample_transition()),
        r#"{"limb":"limb-1","at":1234,"from":"unheld","to":"handing-over","outcome":"granted","lease_id":1,"holder":{"id":"grant-1","kind":"agent","label":"nightly run","priority":50},"release":"required","departed":null,"expired_waiters":[],"queue_depth":0}"#
    );
}

/// The outcome is flattened onto the transition rather than nested under a
/// key of its own name.
///
/// Nested, the tag would land as `"outcome":{"outcome":"granted"}` and every
/// trace query would have to say `outcome.outcome`, which is the kind of key
/// somebody eventually tidies up by renaming one of the two and breaking the
/// other reader.
#[test]
fn the_outcome_is_flattened_onto_the_transition() {
    let json = to_json(&sample_transition());
    assert!(json.contains(r#""outcome":"granted""#), "{json}");
    assert!(!json.contains(r#""outcome":{"#), "{json}");
}

/// `departed` is always present, `null` when nobody lost the lease.
///
/// Deliberately not `skip_serializing_if`. A trace row with a stable key set
/// can be queried with one expression; one whose columns come and go cannot,
/// and this is the field somebody investigating a stuck modifier filters on
/// first.
#[test]
fn a_transition_that_takes_the_wheel_names_who_lost_it() {
    let mut lease = Lease::exclusive("limb-1");
    let _ = lease
        .acquire(AcquireRequest::new(nightly()), LeaseInstant::from_millis(0))
        .unwrap();
    let _ = lease.confirm_release(LeaseInstant::from_millis(0));
    let _ = lease
        .acquire(
            AcquireRequest::new(Party::new("pane-4", HolderKind::Human, "Alice")),
            LeaseInstant::from_millis(500),
        )
        .unwrap();
    let flipped = lease.tick(LeaseInstant::from_millis(2_500));

    let json = to_json(&flipped);
    assert!(
        json.contains(
            r#""departed":{"party":{"id":"grant-1","kind":"agent","label":"nightly run","priority":50},"lease_id":1,"cause":"preempted","held_for_ms":2500}"#
        ),
        "{json}"
    );
    assert!(json.contains(r#""release":"required""#), "{json}");
}

// ---------------------------------------------------------------------------
// What a pane renders
// ---------------------------------------------------------------------------

/// `LeaseView` is the object broadcast to every party on the limb (`08 §5.5`),
/// so its full key set is pinned.
///
/// The keys are `snake_case`. This crate's `kebab-case` renames are on enums,
/// where they change variant *spellings*; the same attribute on a struct
/// changes its *field names*, and `holder-kind` would have been the only
/// kebab case object key in the tree. `SessionStats` and the inner fields of
/// `SessionState` are both `snake_case` and these match them.
#[test]
fn lease_view_is_what_a_pane_renders() {
    let mut lease = Lease::exclusive("limb-1");
    let _ = lease
        .acquire(AcquireRequest::new(nightly()), LeaseInstant::from_millis(0))
        .unwrap();
    let _ = lease.confirm_release(LeaseInstant::from_millis(0));
    let _ = lease
        .acquire(
            AcquireRequest::new(Party::new("pane-4", HolderKind::Human, "Alice")),
            LeaseInstant::from_millis(10_000),
        )
        .unwrap();

    // What a third pane sees. It learns the holder's kind and label, which is
    // what makes "an agent is driving this machine" renderable, and never the
    // holder's id.
    let watching = lease.view_for(&PartyId::from("pane-9"));
    assert_eq!(
        to_json(&watching),
        r#"{"limb":"limb-1","mode":"exclusive","phase":"preempt-pending","holder_kind":"agent","holder_label":"nightly run","you_hold":false,"queue_depth":0,"queue_position":null}"#
    );
    assert!(
        !to_json(&watching).contains("grant-1"),
        "the view must not carry the holder's id"
    );

    // And an empty limb still answers every key, so a pane never has to tell
    // "no holder" apart from "malformed message".
    let empty = Lease::exclusive("limb-2");
    assert_eq!(
        to_json(&empty.view_for(&PartyId::from("pane-9"))),
        r#"{"limb":"limb-2","mode":"exclusive","phase":"unheld","holder_kind":null,"holder_label":null,"you_hold":false,"queue_depth":0,"queue_position":null}"#
    );
}

/// The queue position is per recipient, exactly as BrowserGlass's
/// `LeaseState.queuePosition` is (`08 §5.5`), so two parties reading the same
/// lease get different objects.
#[test]
fn the_view_is_addressed_to_its_recipient() {
    let mut lease = Lease::exclusive("limb-1");
    let _ = lease
        .acquire(
            AcquireRequest::new(Party::new("pane-4", HolderKind::Human, "Alice")),
            LeaseInstant::from_millis(0),
        )
        .unwrap();
    let _ = lease.confirm_release(LeaseInstant::from_millis(0));
    let _ = lease
        .acquire(
            AcquireRequest::new(nightly()),
            LeaseInstant::from_millis(10_000),
        )
        .unwrap();

    let holder = to_json(&lease.view_for(&PartyId::from("pane-4")));
    assert!(holder.contains(r#""you_hold":true"#), "{holder}");
    assert!(holder.contains(r#""queue_position":null"#), "{holder}");

    let waiting = to_json(&lease.view_for(&PartyId::from("grant-1")));
    assert!(waiting.contains(r#""you_hold":false"#), "{waiting}");
    assert!(waiting.contains(r#""queue_position":0"#), "{waiting}");
}

// ---------------------------------------------------------------------------
// Reading it back
// ---------------------------------------------------------------------------

/// `10 §4` replays traces, and a record that can be written and not read is
/// not evidence of anything, so the trace shaped types deserialise too.
#[test]
fn a_departure_round_trips() {
    let departure = Departure {
        party: nightly(),
        lease_id: LeaseId::from_u64(4),
        cause: DepartureCause::IdleRevoked,
        held_for_ms: 120_000,
    };
    let json = to_json(&departure);
    assert_eq!(
        json,
        r#"{"party":{"id":"grant-1","kind":"agent","label":"nightly run","priority":50},"lease_id":4,"cause":"idle-revoked","held_for_ms":120000}"#
    );
    let parsed: Departure = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, departure);
    assert_eq!(parsed.held_for_ms, 120_000);
    assert_eq!(parsed.cause, DepartureCause::IdleRevoked);
}

/// The flattened outcome has to survive the trip back, which is the part of
/// `#[serde(flatten)]` that is easy to get wrong: the tag and the payload are
/// read out of the same map as the transition's own keys.
#[test]
fn a_transition_round_trips_with_its_outcome() {
    let transition = sample_transition();
    let parsed: LeaseTransition = serde_json::from_str(&to_json(&transition)).unwrap();
    assert_eq!(parsed, transition);
    assert!(matches!(parsed.outcome, LeaseOutcome::Granted { .. }));
    assert_eq!(parsed.release, ReleaseObligation::Required);
}

/// A view a pane sent back, or a replayed one, reads as itself.
#[test]
fn a_view_round_trips() {
    let lease = Lease::exclusive("limb-1");
    let view = lease.view_for(&PartyId::from("pane-9"));
    let parsed: LeaseView = serde_json::from_str(&to_json(&view)).unwrap();
    assert_eq!(parsed, view);
}

/// A lease id a party quoted back over IPC arrives as a bare number, which is
/// the whole reason [`LeaseId::from_u64`] is public: without it the plane
/// could not turn what a party sent into the argument
/// `Lease::release` wants.
#[test]
fn a_lease_id_is_a_bare_number_in_both_directions() {
    assert_eq!(to_json(&LeaseId::from_u64(9)), "9");
    let parsed: LeaseId = serde_json::from_str("9").unwrap();
    assert_eq!(parsed, LeaseId::from_u64(9));
    assert_eq!(parsed.as_u64(), 9);
}

// ---------------------------------------------------------------------------
// The numbers
// ---------------------------------------------------------------------------

/// The defaults are quoted in `08 §5.4`, and a deployment that overrides them
/// writes this object. Pinning the keys and the numbers together means a
/// change to either is a change somebody had to make on purpose.
#[test]
fn the_policy_defaults_are_the_numbers_eight_states() {
    assert_eq!(
        to_json(&LeasePolicy::default()),
        r#"{"lease_ttl_ms":60000,"idle_revoke_ms":120000,"disconnect_grace_ms":10000,"queue_ttl_ms":60000,"max_queue_depth":8,"min_hold_ms":3000,"agent_preempt_grace_ms":2000,"force_release_backoff_ms":30000}"#
    );
}
