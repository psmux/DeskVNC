//! A session the person ended is gone from `dvv_limbs` as soon as
//! `dvv_status` says so.

mod common;

use common::{error_code, fake_plane, open, structured, Client};
use serde_json::json;

/// The incident: the person pressed End session in DeskVNC Support, and for
/// 15 s and more `dvv limbs` listed the Boundary limb as connected while
/// `dvv status` on the same limb answered LIMB_GONE. An agent reading the
/// list went on acting on a machine that had left.
#[tokio::test]
async fn a_session_the_person_ended_leaves_limbs_when_status_says_gone() {
    let (source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", true);
    let mut client = Client::connect(plane);

    // The control: an open limb is listed and its status answers.
    let listed = client.tool("dvv_limbs", json!({})).await;
    assert_eq!(structured(&listed)["limbs"][0]["limbId"], limb, "{listed}");
    let status = client.tool("dvv_status", json!({ "limbId": limb })).await;
    assert_eq!(error_code(&status), None, "{status}");

    source.end_in_app(&limb);

    // Asked first, before anything has looked at the limb since it ended,
    // and again after status has.
    let first = listed_ids(&mut client).await;
    let status = client.tool("dvv_status", json!({ "limbId": limb })).await;
    assert_eq!(error_code(&status), Some("LIMB_GONE"), "{status}");
    let after = listed_ids(&mut client).await;
    for listed in [first, after] {
        assert!(
            !listed.contains(&limb),
            "status says {limb} is gone and limbs still lists it: {listed:?}"
        );
    }
}

async fn listed_ids(client: &mut Client) -> Vec<String> {
    let listed = client.tool("dvv_limbs", json!({})).await;
    structured(&listed)["limbs"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|card| card["limbId"].as_str().map(str::to_string))
        .collect()
}
