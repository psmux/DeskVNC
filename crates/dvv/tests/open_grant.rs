//! What an agent may open, and what it may not (`00 R19`).
//!
//! ## Why this is its own file
//!
//! Opening a machine used to be free of consequence on this side: the source
//! could only adopt a session somebody had already opened, so a grant check
//! made on the way back cost nothing. It is not free any more. `limb.open`
//! asks DeskVNCViewer to dial a machine, and a check made after the source has
//! been asked is a check made after the connection.
//!
//! So the claim under test is an ORDERING claim, not just a refusal: the host
//! check and the capability check happen before [`SessionSource::open`] is
//! called at all. `FakeSource` is what makes that provable, because a limb it
//! opened leaves a recorder behind and a limb it never opened leaves nothing.

use dvv::fake::FakeSource;
use dvv::plane::{OpenRequest, Plane, SessionSource};
use limb_core::ProtocolKind;
use std::sync::Arc;

fn plane() -> (Arc<FakeSource>, Plane) {
    let source = Arc::new(FakeSource::two_machines());
    let plane = Plane::local(source.clone() as Arc<dyn SessionSource>)
        .expect("a grant over the two machines the source publishes");
    (source, plane)
}

/// `00 R19`. The grant names its hosts, and an address outside the list is
/// refused before anything is opened.
#[test]
fn a_host_outside_the_grant_is_refused_before_anything_connects() {
    let (source, plane) = plane();
    let refused = plane
        .open(&OpenRequest {
            address: Some("203.0.113.7".to_string()),
            protocol: Some(ProtocolKind::Vnc),
            ..OpenRequest::default()
        })
        .expect_err("that machine is not in this grant");

    assert_eq!(refused.code, "POLICY_DENIED", "{}", refused.message);
    assert!(
        refused.message.contains("203.0.113.7"),
        "the refusal names the machine: {}",
        refused.message
    );
    // Nothing was opened, which is the ordering claim. A limb the source had
    // opened would have a recorder and a card.
    assert!(plane.limbs().is_empty(), "a refused open attaches nothing");
    assert!(
        source.recorder("lmb_vnc_0").is_none(),
        "and puts no session behind it"
    );
}

/// The control. A machine that IS in the grant opens, so the refusal above is
/// the host check and not the open path being broken.
#[test]
fn a_host_inside_the_grant_opens() {
    let (_source, plane) = plane();
    let card = plane
        .open(&OpenRequest {
            address: Some("10.0.0.6".to_string()),
            protocol: Some(ProtocolKind::Ssh),
            ..OpenRequest::default()
        })
        .expect("that machine is one the source publishes");
    assert_eq!(card.host, "10.0.0.6");
    assert_eq!(plane.limbs().len(), 1);
}

/// A saved machine is resolved through the source's own library, which is the
/// same lookup the shell makes, so an id nobody saved is refused by name
/// rather than dialled as if it were an address.
#[test]
fn a_host_id_nobody_saved_is_refused_by_name() {
    let (_source, plane) = plane();
    let refused = plane
        .open(&OpenRequest {
            host_id: Some("h_nothing".to_string()),
            ..OpenRequest::default()
        })
        .expect_err("no machine is called that");
    assert!(refused.message.contains("h_nothing"), "{}", refused.message);
    assert!(plane.limbs().is_empty());
}

/// `exec` is in this grant, and it is there because `Plane::local` names the
/// string. `00 R19` keeps it out of every role bundle, so nothing else could
/// have put it there and a bundle widening later cannot.
///
/// What a LIMB offers is a different question and this file cannot ask it of
/// `RemoteLimb`: the source here is the fake one, whose cards are its own.
/// `tests/exec_over_socket.rs` asks it of the real card over the real socket.
#[test]
fn exec_is_in_the_grant_because_it_was_named_and_not_because_a_bundle_grew() {
    let (_source, plane) = plane();
    let capabilities = plane.grant().capabilities();
    assert!(
        capabilities.allows(limb_core::capability::Capability::Exec),
        "the grant names exec"
    );
    assert!(
        !limb_core::capability::RoleBundle::Operator
            .expand()
            .allows(limb_core::capability::Capability::Exec),
        "and no role bundle would have"
    );
    assert!(
        limb_core::capability::Capability::NEVER_BUNDLED
            .contains(&limb_core::capability::Capability::Exec),
        "which is the rule, written down"
    );
}
