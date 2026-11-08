//! What `dvv open` takes besides a saved machine's id: the address a session
//! that is open and not saved is listed by, and a limb id.
//!
//! The incident: `dvv open boundary-d7e933fa-...`, the address of a Boundary
//! support session a person had open, answered "no saved machine is called
//! 7f4d2f8f-...", an id the caller never passed. The application lists such a
//! session among the hosts under its own session id, labelled with the
//! address. The open found the label, swapped in that session id, and the
//! application then looked the id up among saved machines.

mod common;

use common::{error_code, fake_plane, structured, Client};
use limb_core::ProtocolKind;
use serde_json::json;

const INVITATION: &str = "boundary-d7e933fa-0c55-4e0b-9a59-2f0c3a1d8e64";
const SESSION: &str = "7f4d2f8f-247b-4e5d-a050-1cdcd0eaa960";

#[tokio::test]
async fn a_session_open_by_address_is_attached_by_that_address() {
    let (source, plane) = fake_plane();
    let limb = source.open_unsaved_in_app(INVITATION, ProtocolKind::Boundary, SESSION);
    let mut client = Client::connect(plane);

    let opened = client
        .tool("dvv_open", json!({ "hostId": INVITATION }))
        .await;
    assert_eq!(error_code(&opened), None, "{opened}");
    assert_eq!(structured(&opened)["limb"]["limb_id"], limb.as_str());

    // By the id the hosts list gives it, too.
    let by_id = client.tool("dvv_open", json!({ "hostId": SESSION })).await;
    assert_eq!(error_code(&by_id), None, "{by_id}");
    assert_eq!(structured(&by_id)["limb"]["limb_id"], limb.as_str());
}

#[tokio::test]
async fn a_limb_id_opens_the_session_it_names() {
    let (source, plane) = fake_plane();
    let limb = source.open_unsaved_in_app(INVITATION, ProtocolKind::Boundary, SESSION);
    let theirs = source.open_in_app("h_lab01");
    let mut client = Client::connect(plane);

    for id in [&limb, &theirs] {
        let opened = client.tool("dvv_open", json!({ "hostId": id })).await;
        assert_eq!(error_code(&opened), None, "{opened}");
        assert_eq!(structured(&opened)["limb"]["limb_id"], id.as_str());
    }

    // A limb id nothing has open says so, and says where to look.
    let gone = client
        .tool("dvv_open", json!({ "hostId": "lmb_vnc_000000000000_0" }))
        .await;
    let message = structured(&gone)["message"].as_str().expect("a message");
    assert!(message.contains("lmb_vnc_000000000000_0"), "{message}");
    assert!(message.contains("dvv limbs"), "{message}");
}

#[tokio::test]
async fn a_name_that_matches_nothing_is_named_back() {
    let (source, plane) = fake_plane();
    source.open_unsaved_in_app(INVITATION, ProtocolKind::Boundary, SESSION);
    let mut client = Client::connect(plane);

    let refused = client
        .tool("dvv_open", json!({ "hostId": "boundary-nothing-here" }))
        .await;
    let message = structured(&refused)["message"].as_str().expect("a message");
    assert!(message.contains("boundary-nothing-here"), "{message}");
    assert!(!message.contains(SESSION), "{message}");
    assert!(message.contains("limb id"), "{message}");
}
