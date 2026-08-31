//! `08 §4`, and the one sentence that matters in it: silent dropping is the
//! failure this design must not ship with.
//!
//! Every assertion here is on a NUMBER rather than on a flag. A boolean saying
//! something was dropped does not say how much, and how much is the half an
//! agent needs to decide between retrying and reading the screen again.

mod common;

use agent_lease::{AcquireRequest, HolderKind, LeaseInstant, Party};
use agent_plane::{PlaneConfig, RefusalReason};
use common::{connected, drain, intent, operator, TestLimb};
use limb_core::intent::IntentKind;
use limb_core::observation::{Outcome, Progress};

/// A plane that refuses to wait, so the blocked path is deterministic rather
/// than a race with a timer.
fn impatient() -> PlaneConfig {
    PlaneConfig {
        intent_block_ms: 0,
        ..PlaneConfig::default()
    }
}

#[tokio::test]
async fn a_full_queue_reports_exactly_what_it_dropped() {
    let grant = operator("att_full", "desk.example");
    // Four slots, so the reservation leaves two for the webview's own
    // `send_input` path and the plane may use two. That is `08 §4.5`'s
    // arithmetic at a size a test can count on its fingers: the reservation is
    // the difference between "the agent is busy" and "my keyboard stopped
    // working".
    let (_registry, limb, mut rx) =
        connected(impatient(), &grant, "desk.example", TestLimb::desktop(), 4);
    let now = LeaseInstant::from_millis(1_000);
    let party = Party::new(grant.id().clone(), HolderKind::Agent, "the test");
    let transition = limb.acquire(AcquireRequest::new(party), now).unwrap();
    limb.honour(&transition, now).await;
    drain(&mut rx);

    // Ten commands into a channel that will take two.
    let settlement = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::Type {
                    text: "hello".to_string(),
                    wpm: None,
                },
            ),
            now,
        )
        .await;

    assert_eq!(
        settlement.gaps.commands_dropped, 8,
        "eight of the ten never reached the session, and the agent is told the number"
    );
    assert!(settlement.gaps.lost_state(), "keys are stateful");
    assert_eq!(
        settlement.reason,
        Some(RefusalReason::IntentBlocked),
        "and it is named, not inferred from the counts"
    );
    // `delivered: false` is the honest reading, since the intent as asked was
    // not delivered, and the progress says exactly how much was. An agent
    // author must handle a partial dispatch, and that is stated in the
    // contract rather than smoothed over (`08 §6.2` ruling C).
    assert!(matches!(
        settlement.outcome,
        Outcome::Done {
            delivered: false,
            ..
        }
    ));
    assert_eq!(
        settlement.progress,
        Progress::CodePoints(1),
        "one press and one release went, which is one whole character"
    );
    assert_eq!(drain(&mut rx).len(), 2);

    // Cumulative on the limb as well, so an agent that missed a settlement can
    // still see the total.
    assert_eq!(limb.gaps().commands_dropped, 8);
}

#[tokio::test]
async fn nothing_delivered_is_a_named_refusal_rather_than_a_partial_success() {
    let grant = operator("att_wedged", "desk.example");
    // Two slots, so the reservation keeps one and the plane may use one. A
    // clipboard write is one command, so filling that one slot first leaves
    // nothing.
    let (_registry, limb, mut rx) =
        connected(impatient(), &grant, "desk.example", TestLimb::desktop(), 2);
    let now = LeaseInstant::from_millis(1_000);
    let party = Party::new(grant.id().clone(), HolderKind::Agent, "the test");
    let transition = limb.acquire(AcquireRequest::new(party), now).unwrap();
    // The release pair jumps the queue and is exempt from the reservation, so
    // it fills the channel outright. Left there deliberately: this is the
    // wedged session the section is about.
    limb.honour(&transition, now).await;

    let settlement = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::ClipboardSet {
                    text: "a command somebody would have pasted".to_string(),
                },
            ),
            now,
        )
        .await;

    assert_eq!(settlement.reason, Some(RefusalReason::IntentBlocked));
    assert_eq!(settlement.progress, Progress::None);
    let because = match &settlement.outcome {
        Outcome::Refused { because, .. } => because.clone(),
        other => panic!("nothing went, so this is a refusal: {other:?}"),
    };
    // The sentence carries the actual numbers, which is `06 §5.5`'s rule.
    assert!(because.contains("byte(s)"), "{because}");
    assert!(
        settlement.gaps.bytes_dropped > 0,
        "a dropped paste and a dropped key event are one command each and are not the same loss"
    );

    // Two release commands and nothing of the agent's.
    assert_eq!(drain(&mut rx).len(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_second_batch_from_one_grant_on_one_limb_is_refused() {
    // `08 §7.3`. Two concurrent batches to one limb have no defined
    // interleaving, and an agent that believes it typed `hello` and then
    // `world` would get either, or a mix, and could not tell which.
    let grant = operator("att_race", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig {
            // Long enough that the first dispatch is still in its pause when
            // the second arrives.
            drag_settle_ms: 1_000,
            ..PlaneConfig::default()
        },
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    let party = Party::new(grant.id().clone(), HolderKind::Agent, "the test");
    let transition = limb.acquire(AcquireRequest::new(party), now).unwrap();
    limb.honour(&transition, now).await;
    drain(&mut rx);

    let first = {
        let limb = limb.clone();
        let grant = grant.clone();
        let kind = IntentKind::Drag {
            from: limb_core::intent::Point::new(10, 10),
            to: limb_core::intent::Point::new(20, 20),
            button: limb_core::intent::Button::Left,
        };
        let request = common::fenced(&limb, &grant, kind);
        tokio::spawn(async move { limb.dispatch(&grant, request, now).await })
    };
    // Let the drag get as far as its first settle window.
    tokio::task::yield_now().await;

    let second = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::Type {
                    text: "x".to_string(),
                    wpm: None,
                },
            ),
            now,
        )
        .await;
    assert_eq!(second.reason, Some(RefusalReason::IntentInFlight));

    let first = first.await.expect("the drag finished");
    assert!(!first.refused(), "{:?}", first.outcome);
}
