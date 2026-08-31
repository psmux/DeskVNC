//! `15 §4.5`. The one action in the table whose failure leaves the remote
//! machine in a worse state than it started in.
//!
//! A drag released at an arbitrary point is not a cancelled drag. It is a
//! COMPLETED drag to the wrong place, and a file may have moved. There is no
//! honest way to undo it and nothing above this pretends there is.

mod common;

use agent_lease::{AcquireRequest, HolderKind, LeaseInstant, Party};
use agent_plane::PlaneConfig;
use common::{as_pointer, connected, drain, fenced, operator, TestLimb};
use limb_core::intent::{Button, IntentKind, Point};
use limb_core::observation::{Outcome, Progress};

/// Two intermediate points and no settle window, so the ordering is the only
/// thing under test.
fn tight() -> PlaneConfig {
    PlaneConfig {
        drag_points: 2,
        drag_settle_ms: 0,
        ..PlaneConfig::default()
    }
}

#[tokio::test]
async fn a_drag_arrives_before_it_presses_and_travels_before_it_releases() {
    let grant = operator("att_drag", "desk.example");
    let (_registry, limb, mut rx) =
        connected(tight(), &grant, "desk.example", TestLimb::desktop(), 256);
    let now = LeaseInstant::from_millis(1_000);
    let party = Party::new(grant.id().clone(), HolderKind::Agent, "the test");
    let transition = limb.acquire(AcquireRequest::new(party), now).unwrap();
    limb.honour(&transition, now).await;
    drain(&mut rx);

    let settlement = limb
        .dispatch(
            &grant,
            fenced(
                &limb,
                &grant,
                IntentKind::Drag {
                    from: Point::new(10, 10),
                    to: Point::new(90, 90),
                    button: Button::Left,
                },
            ),
            now,
        )
        .await;
    assert!(matches!(
        settlement.outcome,
        Outcome::Done {
            delivered: true,
            ..
        }
    ));

    let sent: Vec<_> = drain(&mut rx)
        .iter()
        .map(|c| as_pointer(c).expect("a drag is pointer events and nothing else"))
        .collect();

    assert_eq!(
        sent,
        vec![
            // 1. Arrive, no button. Not optional: the mask is applied at
            //    whatever coordinate the message carries, so a press that has
            //    not first moved presses wherever the pointer happened to be.
            (10, 10, 0),
            // 3. Press at the origin.
            (10, 10, 1),
            // 5. Two intermediate points, button held throughout. Not optional
            //    either: drag thresholds and drop targets are driven by
            //    intermediate motion events.
            (37, 37, 1),
            (63, 63, 1),
            // 6. Arrive at the target.
            (90, 90, 1),
            // 8. Release.
            (90, 90, 0),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn a_preemption_mid_drag_releases_the_button_and_says_where_it_landed() {
    let grant = operator("att_interrupted", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig {
            drag_points: 4,
            // A real settle window, so there is a moment for a person to click
            // into. This is the only place a plan can be interrupted, which is
            // why the settle windows are where the marks sit.
            drag_settle_ms: 50,
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

    let running = {
        let limb = limb.clone();
        let grant = grant.clone();
        let request = fenced(
            &limb,
            &grant,
            IntentKind::Drag {
                from: Point::new(100, 100),
                to: Point::new(500, 500),
                button: Button::Left,
            },
        );
        tokio::spawn(async move { limb.dispatch(&grant, request, now).await })
    };

    // Step 1 goes out, then the drag waits its settle window.
    tokio::task::yield_now().await;
    // The window elapses, step 3 presses, and the drag waits again. The button
    // is now held on the remote machine.
    tokio::time::advance(std::time::Duration::from_millis(60)).await;
    tokio::task::yield_now().await;

    // A person hits the panic chord. Dispatch stops on the spot, without being
    // asked and without the agent acknowledging (`08 §6.1` step 5).
    let revoked = limb.force_release(now.plus(20));
    assert!(revoked.must_release());

    tokio::time::advance(std::time::Duration::from_millis(60)).await;
    let settlement = running.await.expect("the drag settled");

    // The settlement names the last point the button was held at, the number
    // of intermediate points delivered, and the fact that the release was
    // synthesised by the plane rather than by the drag (`15 §4.5` WA-6).
    match settlement.progress {
        Progress::Drag {
            released_at,
            points_delivered,
            release_synthesised,
        } => {
            assert!(release_synthesised, "the plane let go, the drag did not");
            assert!(
                points_delivered < 4,
                "it was interrupted before the gesture finished"
            );
            assert_eq!(
                released_at,
                Point::new(100, 100),
                "the drop landed where the button was last known to be, which is not where the agent aimed"
            );
        }
        other => panic!("an interrupted drag settles as a drag: {other:?}"),
    }
    assert!(matches!(settlement.outcome, Outcome::Superseded { .. }));

    // And the button is not left held. This is the whole of `00 B8`: an RFB
    // server holds the last button state it was told until a `PointerEvent`
    // clears the bit, and for a preempted agent nothing follows at all until
    // the new holder moves the mouse, so the interval is unbounded.
    let sent = drain(&mut rx);
    let last = as_pointer(sent.last().expect("something went")).expect("a pointer");
    assert_eq!(last.2, 0, "the last thing on the wire releases the button");
}
