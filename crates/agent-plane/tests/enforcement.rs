//! Every refusal that has to fire BEFORE a byte reaches a session.
//!
//! The common assertion in this file is not the code that came back. It is
//! that the receiver is empty. A refusal that arrives after the click landed
//! is not a control, it is a log line.

mod common;

use agent_lease::{AcquireRequest, HolderKind, LeaseInstant, Party};
use agent_plane::{pixel_scroll_refusal, Grant, PlaneConfig, RefusalReason};
use common::{connected, drain, exec, fenced, intent, operator, TestLimb};
use limb_core::capability::{Capability, CapabilitySet, RoleBundle};
use limb_core::fence::GeometryChange;
use limb_core::intent::{Button, IntentKind, Point};
use limb_core::observation::RefusalCode;

/// Acquire and discharge, so the lease is never the reason a test refused.
async fn drive(limb: &agent_plane::AttachedLimb, grant: &Grant, now: LeaseInstant) {
    let party = Party::new(grant.id().clone(), HolderKind::Agent, "the test");
    let transition = limb.acquire(AcquireRequest::new(party), now).unwrap();
    limb.honour(&transition, now).await;
}

#[tokio::test]
async fn an_intent_for_a_host_outside_the_grant_never_reaches_a_session() {
    // `00 R19`, and this is the control that does not depend on recognising an
    // injection. An injection saying "connect to the domain controller and run
    // this" dies here, before the model's decision reaches anything.
    let owner = operator("att_owner", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &owner,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    drive(&limb, &owner, now).await;
    drain(&mut rx);

    // A second attachment, approved over a different machine entirely.
    let elsewhere = operator("att_elsewhere", "dc.internal");
    let settlement = limb
        .dispatch(
            &elsewhere,
            fenced(
                &limb,
                &elsewhere,
                IntentKind::Click {
                    at: Point::new(100, 100),
                    button: Button::Left,
                    count: 1,
                    modifiers: Vec::new(),
                },
            ),
            now,
        )
        .await;

    assert_eq!(
        settlement.reason,
        Some(RefusalReason::HostNotInGrant),
        "the host check is first and it is not negotiable"
    );
    assert!(
        drain(&mut rx).is_empty(),
        "nothing may reach a machine the grant does not name"
    );

    // And it says why a retry will not help, because an agent that thinks a
    // different spelling might work will spend its turn finding out.
    let because = match settlement.outcome {
        limb_core::observation::Outcome::Refused { because, .. } => because,
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert!(because.contains("no wildcard"), "{because}");
}

#[test]
fn a_grant_refuses_a_wildcard_at_issue_time() {
    // Caught when a person approves it rather than when an intent arrives. A
    // wildcard caught at use time is a wildcard that was already shown to
    // somebody in a dialog and approved.
    let refused = Grant::issue(
        "att_glob",
        CapabilitySet::of(&[Capability::View]),
        ["*.example".to_string()],
    );
    assert!(refused.is_err(), "there is no wildcard, at all");

    let grant = Grant::issue(
        "att_exact",
        CapabilitySet::of(&[Capability::View]),
        ["Build.Example.".to_string()],
    )
    .expect("a legal grant");
    // Trimmed, lower cased, and the trailing dot an mDNS name carries dropped,
    // because host names are case insensitive and neither should split one
    // machine into two.
    assert!(grant.allows_host("build.example"));
    // No suffix match: a grant over `build.example` does not reach
    // `evil-build.example`.
    assert!(!grant.allows_host("evil-build.example"));
}

#[tokio::test]
async fn a_stale_geometry_generation_is_rejected_and_nothing_is_delivered() {
    // `00 R10`. A `DesktopResize` arrives and a pointer packet already in
    // flight lands against the NEW framebuffer. A person's next move corrects
    // it within 50 ms because a person is watching. An agent's does not,
    // because the agent is waiting for a result.
    let grant = operator("att_fence", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    drive(&limb, &grant, now).await;
    drain(&mut rx);

    let stale = limb.generation();
    limb.geometry_changed(
        GeometryChange::DesktopResize {
            width: 1920,
            height: 1080,
        },
        (1920, 1080),
    );
    assert_ne!(stale, limb.generation());

    let settlement = limb
        .dispatch(
            &grant,
            limb_core::intent::AgentIntent {
                fence: Some(stale),
                ..intent(
                    &limb,
                    &grant,
                    IntentKind::Click {
                        at: Point::new(100, 100),
                        button: Button::Left,
                        count: 1,
                        modifiers: Vec::new(),
                    },
                )
            },
            now,
        )
        .await;

    assert_eq!(
        settlement.reason,
        Some(RefusalReason::Limb(RefusalCode::GeometryChanged))
    );
    assert!(drain(&mut rx).is_empty());

    // And an actuation with NO fence is refused differently, because the two
    // mean different things to an agent: stale says observe again, unfenced
    // says your adapter dropped a field and no amount of retrying fixes it.
    let unfenced = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::Move {
                    to: Point::new(10, 10),
                },
            ),
            now,
        )
        .await;
    assert_eq!(
        unfenced.reason,
        Some(RefusalReason::Limb(RefusalCode::Unfenced))
    );
}

#[test]
fn a_pixel_scroll_is_refused_rather_than_converted() {
    // `00 R47c`. There is no scroll magnitude on the wire: RFB encodes the
    // wheel as button bits 3 to 6 with nowhere to put a number, and the RDP
    // side converts the same bit form into WHEEL_DELTA rotation flags. A ratio
    // invented here would be a number nothing measured, applied silently.
    let refusal = pixel_scroll_refusal(0, -300);
    assert_eq!(refusal.reason.as_str(), "NOT_EXPRESSIBLE");
    assert!(
        refusal.because.contains("clicks"),
        "the refusal has to say what to ask for instead: {}",
        refusal.because
    );
    assert!(
        !refusal.because.contains("approximate"),
        "there is no approximation on offer: {}",
        refusal.because
    );
}

#[tokio::test]
async fn a_coordinate_outside_the_framebuffer_is_rejected_and_never_clamped() {
    let grant = operator("att_bounds", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    drive(&limb, &grant, now).await;
    drain(&mut rx);

    let settlement = limb
        .dispatch(
            &grant,
            fenced(
                &limb,
                &grant,
                IntentKind::Click {
                    at: Point::new(4000, 100),
                    button: Button::Left,
                    count: 1,
                    modifiers: Vec::new(),
                },
            ),
            now,
        )
        .await;
    assert_eq!(
        settlement.reason,
        Some(RefusalReason::Limb(RefusalCode::OutOfBounds))
    );
    // A clamped click lands on whatever is at the edge, which is a different
    // action performed silently.
    assert!(drain(&mut rx).is_empty());
}

#[tokio::test]
async fn an_unservable_intent_is_answered_rather_than_dropped() {
    // `00 R7` and `00 R28`. `ssh-core`'s command pump ends in `_ => continue`,
    // which is correct for a UI and is the worst failure this design can have
    // for an agent: the intent vanishes with no error and the agent does not
    // retry, it WAITS.
    let grant = operator("att_unservable", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    drive(&limb, &grant, now).await;
    drain(&mut rx);

    let settlement = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::Scancode {
                    code: 0x1e,
                    down: true,
                },
            ),
            now,
        )
        .await;

    assert_eq!(
        settlement.reason,
        Some(RefusalReason::Limb(RefusalCode::NotSupported)),
        "answered, with the limb's own sentence"
    );
    let because = match &settlement.outcome {
        limb_core::observation::Outcome::Refused { because, .. } => because.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert!(
        because.contains("raw scancodes"),
        "the sentence is the limb's, verbatim: {because}"
    );
    assert!(drain(&mut rx).is_empty());

    // And there is exactly one settlement for it, which is the rule an agent
    // author will assume without checking.
    let settled = settlement.settled(limb_core::observation::Timestamp(0));
    assert_eq!(settled.variant_name(), "settled");
    assert!(
        settlement
            .accepted(limb_core::observation::Timestamp(0))
            .is_none(),
        "a refusal is never accepted first"
    );
}

#[tokio::test]
async fn a_native_intent_without_the_capability_is_refused_before_the_session() {
    // `00 R19` and `00 R30`. An intent the driver serves itself now reaches it
    // as `ClientCommand::Agent` rather than being refused for a missing wire
    // variant, and the gate it passes on the way is exactly the gate a click
    // passes. `exec` is in NO role bundle: an operator over this machine has
    // every capability a person would tick and still cannot run a command.
    let operator_grant = operator("att_exec_operator", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &operator_grant,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    drive(&limb, &operator_grant, now).await;
    drain(&mut rx);

    let settlement = limb
        .dispatch(
            &operator_grant,
            intent(&limb, &operator_grant, exec("uname -a")),
            now,
        )
        .await;
    assert_eq!(
        settlement.reason,
        Some(RefusalReason::Limb(RefusalCode::MissingCapability)),
        "a native intent is gated by the grant like every other one"
    );
    assert!(
        drain(&mut rx).is_empty(),
        "the refusal fires before anything is handed to the driver"
    );
}

#[tokio::test]
async fn a_native_intent_for_a_host_outside_the_grant_never_reaches_a_session() {
    // The host check is first and the native path does not get its own door.
    // The grant below carries `terminal.write`, which is what `declare` costs,
    // so the only thing that can refuse it is the machine it names.
    let owner = operator("att_declare_owner", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &owner,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);
    drain(&mut rx);

    let elsewhere = operator("att_declare_elsewhere", "dc.internal");
    let settlement = limb
        .dispatch(
            &elsewhere,
            intent(
                &limb,
                &elsewhere,
                IntentKind::Declare {
                    cwd: Some("/tmp".to_string()),
                    env: Vec::new(),
                },
            ),
            now,
        )
        .await;
    assert_eq!(settlement.reason, Some(RefusalReason::HostNotInGrant));
    assert!(
        drain(&mut rx).is_empty(),
        "nothing may reach a machine the grant does not name, whoever serves the intent"
    );
}

#[tokio::test]
async fn a_capability_the_grant_lacks_is_refused_before_the_lowering() {
    // Deny by default, no hierarchy, no wildcard, no inheritance. An observer
    // carries `view` and nothing else, so it cannot type even on a limb that
    // offers `control`.
    let observer = Grant::from_bundle(
        "att_observer",
        RoleBundle::Observer,
        ["desk.example".to_string()],
    )
    .expect("a legal grant");
    let owner = operator("att_owner2", "desk.example");
    let (_registry, limb, mut rx) = connected(
        PlaneConfig::default(),
        &owner,
        "desk.example",
        TestLimb::desktop(),
        256,
    );
    let now = LeaseInstant::from_millis(1_000);

    let settlement = limb
        .dispatch(
            &observer,
            intent(
                &limb,
                &observer,
                IntentKind::Type {
                    text: "rm -rf /".to_string(),
                    wpm: None,
                },
            ),
            now,
        )
        .await;
    assert_eq!(
        settlement.reason,
        Some(RefusalReason::Limb(RefusalCode::MissingCapability))
    );
    assert!(drain(&mut rx).is_empty());
}
