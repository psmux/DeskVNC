//! Slot semantics, identity, and admission control.
//!
//! `00 B7` is the trap: `AppState::existing_window_for_machine` is called from
//! exactly one place, `open_session_window`, and `connect_session` never
//! consults it. So the de-duplication a reader can see in the running product
//! is a WINDOW rule and not a session rule, and both halves of slot semantics
//! are the plane's to build.

mod common;

use agent_plane::{Attach, Grant, LimbRegistry, PlaneConfig, PlaneError};
use common::{connected, fake_session, operator, TestLimb};
use limb_core::capability::{Capability, CapabilitySet, RoleBundle};
use limb_core::identity::{LimbId, MachineKey, Slot};
use remote_core::driver::ProtocolKind;
use std::sync::Arc;

fn machine(host: &str) -> MachineKey {
    MachineKey::endpoint(ProtocolKind::Vnc, host, 5900)
}

fn attach_request(host: &str, slot: Slot, capacity: usize) -> Attach {
    let (handle, rx) = fake_session(host, capacity);
    // The receiver is deliberately kept alive by leaking it: a dropped
    // receiver closes the channel and every subsequent send reports the limb
    // as gone, which would make this file's failures look like transport
    // failures. Nothing here reads what was sent.
    std::mem::forget(rx);
    Attach {
        driver: Arc::new(TestLimb::desktop()),
        machine: machine(host),
        slot,
        host: host.to_string(),
        handle,
        size: (1280, 720),
        frames: None,
    }
}

#[test]
fn the_fifth_concurrent_limb_is_refused_by_name() {
    // `00 R21`. Four, not eight. `08 §2` found five shared resources that
    // break at N equal to 8 and the binding one is the single tokio runtime,
    // where the symptom is that the USER INTERFACE hangs rather than that the
    // agent is slow. Claiming eight and shipping four is the one failure the
    // document set was written to avoid, so this refuses rather than degrades.
    let hosts = [
        "one.example",
        "two.example",
        "three.example",
        "four.example",
        "five.example",
    ];
    let grant = Grant::from_bundle(
        "att_swarm",
        RoleBundle::Operator,
        hosts.iter().map(|h| (*h).to_string()),
    )
    .expect("a legal grant");
    let registry = LimbRegistry::new(PlaneConfig::default());

    for host in &hosts[..4] {
        registry
            .attach(&grant, attach_request(host, Slot::ATTACH, 16))
            .expect("the first four are admitted");
    }
    assert_eq!(registry.len(), 4);

    let refused = registry
        .attach(&grant, attach_request(hosts[4], Slot::ATTACH, 16))
        .expect_err("the fifth is refused");
    assert!(
        matches!(
            refused,
            PlaneError::TooManyLimbs {
                limit: 4,
                attached: 4
            }
        ),
        "{refused:?}"
    );
    // And the refusal says where the number came from, so nobody raises it by
    // guessing.
    let sentence = refused.to_string();
    assert!(sentence.contains("tokio runtime"), "{sentence}");
    assert!(sentence.contains("S2"), "{sentence}");
}

#[test]
fn attaching_the_same_machine_at_the_same_slot_twice_is_one_limb() {
    // `00 R31`: an id is a pure function of the protocol, the machine and the
    // slot, so an agent restarted tomorrow reaches the same machine. Slot 0
    // attaching to what is already live is that same derivation and not a
    // second rule.
    let grant = operator("att_dedupe", "desk.example");
    let registry = LimbRegistry::new(PlaneConfig::default());

    let first = registry
        .attach(&grant, attach_request("desk.example", Slot::ATTACH, 16))
        .expect("attached");
    let second = registry
        .attach(&grant, attach_request("desk.example", Slot::ATTACH, 16))
        .expect("attached again");

    assert_eq!(first.id(), second.id());
    assert_eq!(registry.len(), 1, "no second limb was made");

    // The id is reproducible without attaching anything, which is what makes
    // it usable as an address on turn forty when the caller kept no handle.
    assert_eq!(
        first.id(),
        &LimbRegistry::resolve(ProtocolKind::Vnc, &machine("desk.example"), Slot::ATTACH)
    );
    assert!(first.id().as_str().starts_with(LimbId::PREFIX));
}

#[test]
fn a_slot_above_zero_opens_its_own_and_never_adopts() {
    let grant = operator("att_slots", "desk.example");
    let registry = LimbRegistry::new(PlaneConfig::default());

    let zero = registry
        .attach(&grant, attach_request("desk.example", Slot::ATTACH, 16))
        .expect("attached");
    let one = registry
        .attach(&grant, attach_request("desk.example", Slot(1), 16))
        .expect("attached");

    assert_ne!(zero.id(), one.id());
    assert_eq!(registry.len(), 2);
}

#[test]
fn a_slot_the_protocol_will_not_give_is_refused_with_a_sentence() {
    // Without this refusal an agent asking for eight RDP limbs on one Windows
    // box discovers the server's session policy by watching seven of them
    // disconnect the eighth.
    let grant = operator("att_slotcap", "desk.example");
    let registry = LimbRegistry::new(PlaneConfig::default());
    let refused = registry
        .attach(&grant, attach_request("desk.example", Slot(9), 16))
        .expect_err("the test limb reports four slots");
    assert!(matches!(refused, PlaneError::SlotRefused(_)), "{refused:?}");
}

#[test]
fn attaching_a_host_the_grant_does_not_name_is_refused_before_anything_opens() {
    let grant = operator("att_scope", "desk.example");
    let registry = LimbRegistry::new(PlaneConfig::default());
    let refused = registry
        .attach(&grant, attach_request("dc.internal", Slot::ATTACH, 16))
        .expect_err("the grant names one host and this is not it");
    assert!(
        matches!(refused, PlaneError::HostNotInGrant { .. }),
        "{refused:?}"
    );
    assert!(registry.is_empty());
}

#[test]
fn an_agent_bundle_cannot_open_its_own_machines() {
    // `02 §5.3`: the `agent` bundle carries neither `open` nor `close`. An
    // agent drives what it was given, and an agent that opens its own machines
    // is an operator, which the person granting it should have to say.
    let agent = Grant::from_bundle("att_agent", RoleBundle::Agent, ["desk.example".to_string()])
        .expect("a legal grant");
    let registry = LimbRegistry::new(PlaneConfig::default());
    let refused = registry
        .attach(&agent, attach_request("desk.example", Slot::ATTACH, 16))
        .expect_err("no open capability");
    assert!(
        matches!(refused, PlaneError::MissingCapability { .. }),
        "{refused:?}"
    );
}

#[test]
fn neither_exec_nor_scancode_is_in_any_bundle() {
    // `00 R19`, asserted at the layer that issues grants rather than only at
    // the layer that defines the enum. A sixth bundle added later is covered
    // the day it is added.
    for bundle in RoleBundle::ALL.iter().copied() {
        let grant = Grant::from_bundle("att_bundle", bundle, ["desk.example".to_string()])
            .expect("a legal grant");
        for never in Capability::NEVER_BUNDLED.iter().copied() {
            assert!(
                !grant.allows_all(CapabilitySet::of(&[never])),
                "{bundle} must not carry {never}"
            );
        }
    }
}

#[tokio::test]
async fn a_detach_needs_close_and_the_id_stops_resolving() {
    let grant = operator("att_close", "desk.example");
    let (registry, limb, _rx) = connected(
        PlaneConfig::default(),
        &grant,
        "desk.example",
        TestLimb::desktop(),
        16,
    );
    let id = limb.id().clone();
    assert!(registry.get(&id).is_some());
    registry
        .detach(&grant, &id)
        .expect("operator carries close");
    assert!(registry.get(&id).is_none());
    assert!(matches!(
        registry.detach(&grant, &id),
        Err(PlaneError::NoSuchLimb { .. })
    ));
}
