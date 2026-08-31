//! The stop button (`00 R13`).
//!
//! **A revocation, not a request.** BrowserGlass's own demo measures 2,008 ms
//! for a polite handover, which is two seconds of somebody pressing a button
//! labelled stop while nothing happens. So there is no grace window: input
//! dispatch stops synchronously and the release goes out immediately.
//!
//! The ordering inside the release is the other half, and it is `00 B8`. The
//! VNC path's `release_all_keys` drains a map keyed by keysym, so it is KEYS
//! ONLY, and the pointer arm remembers no mask at all. A stop between a drag's
//! press and its release therefore leaves the left button held on the remote
//! machine, and for a preempted agent nothing follows at all until the new
//! holder moves the mouse, so the interval is unbounded: the person who took
//! the wheel gets a machine that rubber band selects across the desktop and
//! nothing in the audit trail explains why.
//!
//! **Buttons before keys.** A zero mask pointer event first, then every key.

mod common;

use common::{fake_plane, open};
use dvv::plane::Selector;
use limb_core::ClientCommand;

#[tokio::test]
async fn the_stop_path_puts_a_zero_mask_pointer_out_before_the_key_releases() {
    let (source, plane) = fake_plane();
    let limb_id = open(&plane, "h_lab01", true);
    let limb = plane
        .resolve(&Selector {
            limb_id: Some(limb_id.clone()),
            ..Selector::default()
        })
        .expect("the limb is attached");

    // Take the wheel and put the pointer somewhere that is not the origin, so
    // the assertion below is about the mask rather than about a default.
    plane
        .acquire(&limb, Some("about to be stopped".to_string()), false)
        .await
        .expect("an unheld lease is granted");
    plane
        .submit(
            &limb,
            limb_core::intent::IntentKind::Move {
                to: limb_core::intent::Point::new(400, 300),
            },
            Some(limb.generation().get()),
        )
        .await
        .expect("a fenced move is dispatched");

    let recorder = source.recorder(&limb_id).expect("a recorder");
    recorder.clear();

    let report = plane.stop(&limb).await;

    let sent = recorder.commands();
    assert!(!sent.is_empty(), "a stop that sends nothing is not a stop");

    let pointer = sent
        .iter()
        .position(|c| matches!(c, ClientCommand::Pointer { .. }))
        .expect("a pointer event went");
    let keys = sent
        .iter()
        .position(|c| matches!(c, ClientCommand::ReleaseAllKeys))
        .expect("the keys were released");
    assert!(
        pointer < keys,
        "buttons before keys, always: {:?}",
        recorder.names()
    );

    match &sent[pointer] {
        ClientCommand::Pointer { x, y, button_mask } => {
            assert_eq!(
                *button_mask, 0,
                "the pointer event that releases carries an EMPTY mask; anything else holds a button on the remote machine"
            );
            assert_eq!(
                (*x, *y),
                (400, 300),
                "the release lands where the button was last known to be, not at the origin"
            );
        }
        other => panic!("expected a pointer event, got {other:?}"),
    }

    assert_eq!(
        report.released,
        vec!["pointer(400,300,mask=0)", "release all keys"],
        "the report says what went, in order, so a caller can assert it rather than trust it"
    );
    assert!(
        !report.limb_closed,
        "stopping revokes the wheel; it does not close somebody's machine"
    );
    assert!(
        plane.limbs().iter().any(|card| card.limb_id == limb_id),
        "and the limb is still there afterwards"
    );
}

#[tokio::test]
async fn a_stop_takes_the_wheel_away_and_the_next_action_is_refused() {
    let (_source, plane) = fake_plane();
    let limb_id = open(&plane, "h_lab01", true);
    let limb = plane
        .resolve(&Selector {
            limb_id: Some(limb_id),
            ..Selector::default()
        })
        .expect("the limb is attached");

    plane
        .acquire(&limb, None, false)
        .await
        .expect("an unheld lease is granted");
    plane.stop(&limb).await;

    // Synchronously. There is no window in which the previous holder's next
    // command still goes.
    let settlement = plane
        .submit(
            &limb,
            limb_core::intent::IntentKind::Type {
                text: "this must not be typed".to_string(),
                wpm: None,
            },
            None,
        )
        .await
        .expect("an intent is always answered");
    assert!(
        settlement.refused(),
        "the holder was revoked, so nothing of theirs dispatches"
    );

    // And re-acquiring is refused for the backoff window, because without it an
    // agent in a loop reacquires before the person who hit the button can click
    // anything, and the button does nothing.
    let reacquired = plane.acquire(&limb, None, false).await;
    assert!(
        reacquired.is_err(),
        "a force release holds a backoff, or the panic chord is decorative"
    );
}
