//! A stale actuation is refused and nothing is delivered (`00 R10`).
//!
//! The defect these tests stand in for is undiagnosable in the field. A
//! `DesktopResize` arrives, a pointer packet already in flight lands against
//! the new framebuffer, and the click hits something the agent did not choose.
//! A person corrects it in 50 ms without noticing. An agent does not, because
//! it is not watching the screen, it is waiting for a result, and the result
//! it gets says the click was delivered, which is true and useless.
//!
//! So the test that matters is not that a fence exists. It is that the
//! comparison is written in exactly one place and that getting past it is a
//! TYPED rejection an agent can read, rather than a boolean somebody can
//! forget to check.

use limb_core::{
    AgentIntent, Button, GeometryChange, GeometryFence, GeometryGeneration, GeometryRejected,
    GrantId, IntentId, IntentKind, Outcome, Point, RefusalCode, ScrollDirection, WaitUntil,
};

fn intent(kind: IntentKind, fence: Option<GeometryGeneration>) -> AgentIntent {
    AgentIntent {
        id: IntentId(1),
        grant: GrantId::from("att_7f3c"),
        deadline: None,
        fence,
        kind,
    }
}

fn a_click() -> IntentKind {
    IntentKind::Click {
        at: Point::new(576, 340),
        button: Button::Left,
        count: 1,
        modifiers: Vec::new(),
    }
}

#[test]
fn a_fresh_limb_starts_at_the_first_generation() {
    let fence = GeometryFence::new();
    assert_eq!(fence.current(), GeometryGeneration::FIRST);
    // One rather than zero, so a defaulted zero somewhere else can never be
    // mistaken for a live generation.
    assert_eq!(GeometryGeneration::FIRST.get(), 1);
}

#[test]
fn an_action_computed_against_the_current_geometry_is_admitted() {
    let fence = GeometryFence::new();
    let action = intent(a_click(), Some(fence.current()));
    assert!(fence.admit(&action).is_ok());
}

#[test]
fn an_action_computed_against_an_old_geometry_is_refused() {
    let mut fence = GeometryFence::new();
    let observed_at = fence.current();

    // The resize the agent did not see.
    fence.changed(GeometryChange::DesktopResize {
        width: 1280,
        height: 1024,
    });

    let action = intent(a_click(), Some(observed_at));
    let rejected = fence.admit(&action).unwrap_err();
    assert_eq!(
        rejected,
        GeometryRejected::Stale {
            fenced_at: observed_at,
            current: fence.current(),
        }
    );

    // And the refusal names both numbers, because an agent told only "stale"
    // cannot tell a resize it missed from a reconnect it missed.
    let sentence = rejected.to_string();
    assert!(sentence.contains("generation 1"), "{sentence}");
    assert!(sentence.contains("now at 2"), "{sentence}");
    assert!(sentence.contains("nothing was delivered"), "{sentence}");
}

#[test]
fn every_grounded_intent_is_fenced_and_no_other_one_is() {
    let fence = GeometryFence::new();

    let grounded = [
        IntentKind::Move {
            to: Point::new(10, 10),
        },
        a_click(),
        IntentKind::Drag {
            from: Point::new(1, 1),
            to: Point::new(2, 2),
            button: Button::Left,
        },
        IntentKind::Scroll {
            at: Point::new(3, 3),
            direction: ScrollDirection::Down,
            clicks: 2,
        },
    ];
    for kind in grounded {
        let name = kind.name();
        assert!(kind.is_grounded(), "{name} aims at a coordinate");
        assert_eq!(
            fence.admit(&intent(kind, None)).unwrap_err(),
            GeometryRejected::Unfenced {
                current: fence.current()
            },
            "{name} arrived with no fence and was let through"
        );
    }

    // Typing has no coordinate for a resize to invalidate, so requiring a
    // fence on it would be ceremony, and ceremony is what gets stripped out
    // later by somebody who cannot see what it was for.
    let ungrounded = [
        IntentKind::Type {
            text: "hello".into(),
            wpm: None,
        },
        IntentKind::Wait {
            until: WaitUntil::ScreenStable,
            quiet: None,
            timeout: None,
        },
        IntentKind::ClipboardGet,
    ];
    for kind in ungrounded {
        let name = kind.name();
        assert!(!kind.is_grounded(), "{name}");
        assert!(fence.admit(&intent(kind, None)).is_ok(), "{name}");
    }
}

#[test]
fn a_stale_fence_becomes_a_refusal_an_agent_can_match_on() {
    let mut fence = GeometryFence::new();
    let observed_at = fence.current();
    fence.changed(GeometryChange::Reconnected);

    let rejected = fence
        .admit(&intent(a_click(), Some(observed_at)))
        .unwrap_err();
    let outcome: Outcome = rejected.into();

    match outcome {
        Outcome::Refused { code, because } => {
            // The code first and in capitals, per `06 §5.5`: a model that has
            // to parse prose to find out what happened will parse it wrong on
            // the day the prose is edited.
            assert_eq!(code, RefusalCode::GeometryChanged);
            assert_eq!(code.as_str(), "GEOMETRY_CHANGED");
            assert!(because.contains("observe again"), "{because}");
        }
        other => panic!("a fence rejection must never soften into {other:?}"),
    }

    let unfenced: Outcome = fence.admit(&intent(a_click(), None)).unwrap_err().into();
    match unfenced {
        Outcome::Refused { code, .. } => assert_eq!(code, RefusalCode::Unfenced),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_generation_increments_on_a_reconnect_even_when_nothing_changed_size() {
    let mut fence = GeometryFence::new();
    let before = fence.current();
    let (after, why) = fence.changed(GeometryChange::Reconnected);

    assert!(after > before);
    assert_eq!(why, GeometryChange::Reconnected);

    // An RDP reconnect may land in a different Windows session, a locked
    // desktop looks nothing like the one the agent was working on, and a
    // screensaver may have started. The size being unchanged says nothing
    // about any of that (`02 §4.6`).
    assert!(fence.admit(&intent(a_click(), Some(before))).is_err());
}
