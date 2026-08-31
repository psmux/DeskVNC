//! A limb id has to be reproducible, opaque, and legal where the shell
//! already constrains an identifier (`00 R31`, `02 AC-7`).
//!
//! The reproducibility test is the one that matters. It is the property that
//! lets an agent restarted tomorrow reach the same machine with no persisted
//! map, and it is the kind of property that survives a refactor only because
//! something asserts it: a well meaning change to the canonical encoding, or
//! to the hash truncation, breaks every stored id at once and breaks it
//! silently, because a wrong id still looks like an id.

use limb_core::{LimbId, LimbIdError, MachineKey, ProtocolKind, Slot};

fn a_machine() -> MachineKey {
    MachineKey::endpoint(ProtocolKind::Vnc, "lab-04.local", 5900)
}

/// `validate_session_id`, reproduced from `src-tauri/src/windows.rs:18`.
///
/// A copy rather than a call, because `src-tauri` sits above every crate here
/// and nothing in the workspace may depend on it. The copy is three lines and
/// the thing it guards against is a limb id that cannot become a window label,
/// which would be discovered at the moment somebody tries to open one.
fn legal_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[test]
fn the_same_machine_yields_the_same_id_every_time() {
    let first = LimbId::derive(ProtocolKind::Vnc, &a_machine(), Slot::ATTACH);
    let second = LimbId::derive(ProtocolKind::Vnc, &a_machine(), Slot::ATTACH);
    assert_eq!(first, second);

    // And the literal value, so that a change to the encoding or to the hash
    // truncation is a failure here rather than a fleet of agents that can no
    // longer find the machines they were working on.
    assert_eq!(first.as_str(), "lmb_vnc_38f74dfb2f2c_0");
}

#[test]
fn a_saved_profile_and_an_endpoint_are_different_machines() {
    // The discriminator byte in the canonical encoding is what makes this
    // true. Without it the two encodings could collide, and a collision
    // between two machines is the one failure the scheme has to be immune to.
    let profile = LimbId::derive(
        ProtocolKind::Vnc,
        &MachineKey::profile("lab-04.local"),
        Slot::ATTACH,
    );
    let endpoint = LimbId::derive(ProtocolKind::Vnc, &a_machine(), Slot::ATTACH);
    assert_ne!(profile, endpoint);
}

#[test]
fn two_protocols_on_one_address_are_two_machines() {
    let vnc = LimbId::derive(
        ProtocolKind::Vnc,
        &MachineKey::endpoint(ProtocolKind::Vnc, "box", 5900),
        Slot::ATTACH,
    );
    let rdp = LimbId::derive(
        ProtocolKind::Rdp,
        &MachineKey::endpoint(ProtocolKind::Rdp, "box", 5900),
        Slot::ATTACH,
    );
    // Somebody who has genuinely put RDP on 5900 must not have their VNC limb
    // handed back instead, which is why `MachineKey::Endpoint` carries the
    // protocol as well as the address (PRDRDP/07 §4.12).
    assert_ne!(vnc, rdp);
}

#[test]
fn slots_are_different_limbs_on_the_same_machine() {
    let machine = a_machine();
    let zero = LimbId::derive(ProtocolKind::Vnc, &machine, Slot::ATTACH);
    let one = LimbId::derive(ProtocolKind::Vnc, &machine, Slot(1));
    let seven = LimbId::derive(ProtocolKind::Vnc, &machine, Slot(7));

    assert_ne!(zero, one);
    assert_ne!(one, seven);

    // The hash half is the machine, so all three share it. That is the
    // property that lets the plane compare the canonical address beside the id
    // and detect a collision rather than acting on one.
    let hash_of = |id: &LimbId| id.as_str().split('_').nth(2).unwrap().to_string();
    assert_eq!(hash_of(&zero), hash_of(&one));
    assert_eq!(hash_of(&zero), hash_of(&seven));
}

#[test]
fn every_derived_id_is_legal_as_a_window_label() {
    for protocol in ProtocolKind::ALL.iter().copied() {
        for slot in [Slot(0), Slot(1), Slot(u16::MAX)] {
            let id = LimbId::derive(protocol, &a_machine(), slot);
            assert!(legal_session_id(id.as_str()), "{id}");
            assert!(
                id.as_str().len() <= LimbId::MAX_LEN,
                "{id} is {} characters and MAX_LEN says {}",
                id.as_str().len(),
                LimbId::MAX_LEN
            );
        }
    }
}

#[test]
fn an_id_taken_back_from_a_caller_is_validated_and_not_trusted() {
    let id = LimbId::derive(ProtocolKind::Ssh, &a_machine(), Slot(3));
    assert_eq!(LimbId::from_caller(id.as_str()).unwrap(), id);

    assert_eq!(LimbId::from_caller(""), Err(LimbIdError::Length { len: 0 }));
    assert_eq!(
        LimbId::from_caller(&"a".repeat(65)),
        Err(LimbIdError::Length { len: 65 })
    );
    // The characters that would make an id dangerous in a window label or a
    // URL are refused before anything downstream sees them.
    for junk in ["lmb_vnc_../../etc_0", "lmb_vnc_'; drop_0", "lmb vnc 0"] {
        assert_eq!(
            LimbId::from_caller(junk),
            Err(LimbIdError::Charset),
            "{junk}"
        );
    }
    assert_eq!(
        LimbId::from_caller("session-7f3c"),
        Err(LimbIdError::NotALimbId)
    );
}

#[test]
fn the_lease_is_keyed_on_the_same_characters_as_the_limb() {
    let id = LimbId::derive(ProtocolKind::Rdp, &a_machine(), Slot(2));
    // If these ever disagree, a lease is held against a limb nobody can find
    // and the force release path has nothing to release.
    assert_eq!(id.lease_key().as_str(), id.as_str());
}
