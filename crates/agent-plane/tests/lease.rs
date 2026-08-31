//! `00 R11` and `00 B8`, asserted on the wire in the one order that is
//! correct.
//!
//! The ordering is not a preference. `release_all_keys`
//! (`crates/vnc-core/src/session/run_loop.rs:1748`) drains a map keyed by
//! `(keysym, Option<keycode>)`, so it is keys only, and the VNC pointer arm
//! encodes whatever mask arrived and remembers nothing. An RFB server holds
//! the last button state it was told until a `PointerEvent` clears the bit. So
//! a preemption between a drag's press and its release leaves the left button
//! held on the remote machine, and for a preempted agent nothing follows at
//! all until the new holder moves the mouse, which makes the interval
//! unbounded. The person who took the wheel gets a machine that rubber band
//! selects across the desktop and nothing in the audit trail explains why.
//!
//! Buttons before keys, following the RDP driver's own ordering and its own
//! reason: a modifier still held while the button goes up is what the server
//! saw when it went down, so the gesture ends the way it began.

mod common;

use agent_lease::{AcquireRequest, HolderKind, LeaseInstant, LeasePhase, Party};
use agent_plane::PlaneConfig;
use common::{as_pointer, connected, drain, fenced, operator, TestLimb};
use limb_core::intent::{IntentKind, Point};
use limb_core::ClientCommand;

#[tokio::test]
async fn a_preemption_releases_the_buttons_before_the_keys() {
    let grant = operator("att_agent", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );

    let t0 = LeaseInstant::from_millis(1_000);
    let agent = Party::new(grant.id().clone(), HolderKind::Agent, "nightly run");
    let granted = limb
        .acquire(AcquireRequest::new(agent), t0)
        .expect("an unheld lease is granted");
    // A grant sits in `HandingOver` until the caller confirms the release, so
    // a caller that ignores the obligation gets a limb nobody can drive rather
    // than a stuck Ctrl (`00 R46c`).
    assert_eq!(granted.to, LeasePhase::HandingOver);
    assert!(granted.must_release());
    limb.honour(&granted, t0).await;
    assert!(limb.fencing(grant.id()).is_allowed());
    drain(&mut rx);

    // Put the pointer somewhere, so the synthesised release is at a coordinate
    // the test chose rather than at the origin by default.
    limb.dispatch(
        &grant,
        fenced(
            &limb,
            &grant,
            IntentKind::Move {
                to: Point::new(640, 400),
            },
        ),
        t0,
    )
    .await;
    assert_eq!(drain(&mut rx).len(), 1);

    // A person clicks into the pane. `human` (100) beats `agent` (50), and the
    // minimum hold is lifted for exactly this pairing, so the preemption
    // starts immediately rather than three seconds later (`08 §6.1` step 3).
    let person = Party::new("win_main", HolderKind::Human, "the pane");
    let preempt = limb
        .acquire(AcquireRequest::new(person), t0.plus(10))
        .expect("a person outranks an agent");
    assert_eq!(preempt.to, LeasePhase::PreemptPending);
    assert!(preempt.must_release());

    // The agent's dispatch stops the instant the phase changes, without being
    // asked and without acknowledging. Nothing it does can let another intent
    // through (`08 §6.1` step 5).
    assert!(!limb.fencing(grant.id()).is_allowed());

    let sent = limb.honour(&preempt, t0.plus(10)).await;
    assert_eq!(
        sent.len(),
        2,
        "one pointer and one release, and nothing else"
    );
    assert_eq!(
        as_pointer(&sent[0]),
        Some((640, 400, 0)),
        "the buttons go first, at the coordinate the pointer was last put"
    );
    assert!(
        matches!(sent[1], ClientCommand::ReleaseAllKeys),
        "and the keys go second: {:?}",
        sent[1]
    );

    // The same two, in the same order, actually on the channel.
    let on_the_wire = drain(&mut rx);
    assert_eq!(as_pointer(&on_the_wire[0]), Some((640, 400, 0)));
    assert!(matches!(on_the_wire[1], ClientCommand::ReleaseAllKeys));
}

#[tokio::test]
async fn the_force_release_owes_the_same_two_commands_even_with_nobody_holding() {
    let grant = operator("att_panic", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(500);

    // The obligation is always required, even when the lease believes nobody
    // was holding anything. A stuck grab is exactly the case where the plane's
    // belief about what is held is the thing that turned out to be wrong, and
    // one redundant release is a price worth paying for a button whose entire
    // job is to work (`08 §6.3`, `00 R13`).
    let transition = limb.force_release(now);
    assert!(transition.must_release());

    let sent = limb.honour(&transition, now).await;
    assert_eq!(sent.len(), 2);
    assert_eq!(as_pointer(&sent[0]).map(|p| p.2), Some(0));
    assert!(matches!(sent[1], ClientCommand::ReleaseAllKeys));
    assert_eq!(drain(&mut rx).len(), 2);
}

#[tokio::test]
async fn an_intent_from_a_party_that_does_not_hold_the_wheel_sends_nothing() {
    let grant = operator("att_watcher", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);

    // Nobody has acquired anything, so the fence says release only.
    let settlement = limb
        .dispatch(
            &grant,
            fenced(
                &limb,
                &grant,
                IntentKind::Move {
                    to: Point::new(10, 10),
                },
            ),
            now,
        )
        .await;
    assert!(settlement.refused());
    assert_eq!(
        settlement.reason.map(|r| r.as_str()),
        Some("LEASE_NOT_HELD")
    );
    assert!(
        drain(&mut rx).is_empty(),
        "refused before anything reached the wire"
    );
}
