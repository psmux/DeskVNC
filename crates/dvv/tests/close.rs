//! What `dvv_close` does to a limb, and to the session behind it.
//!
//! Two things used to be wrong. A limb `dvv_limbs` listed as available, with
//! the promise that it could be passed to any tool, answered `dvv_close` with
//! LIMB_GONE until some other call had attached it. And closing an attached
//! limb only let go of it in this process: DeskVNCViewer was never told, so
//! the answer said "closed" while the machine stayed connected.

mod common;

use common::{error_code, fake_plane, open, structured, Client};
use serde_json::json;

#[tokio::test]
async fn an_available_limb_can_be_closed_without_attaching_it_first() {
    let (source, plane) = fake_plane();
    let limb = source.open_in_app("h_lab01");
    let mut client = Client::connect(plane.clone());

    let listed = client.tool("dvv_limbs", json!({})).await;
    assert_eq!(
        structured(&listed)["available"][0]["limb_id"],
        limb,
        "{listed}"
    );

    let closed = client.tool("dvv_close", json!({ "limbId": limb })).await;
    assert_eq!(error_code(&closed), None, "{closed}");
    assert_eq!(structured(&closed)["sessionClosed"], true, "{closed}");
    assert_eq!(source.closed_sessions(), vec![limb.clone()]);

    let after = client.tool("dvv_limbs", json!({})).await;
    assert_eq!(structured(&after)["available"], json!([]), "{after}");
}

#[tokio::test]
async fn closing_an_attached_limb_ends_its_session_in_the_application() {
    let (source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane.clone());

    let closed = client.tool("dvv_close", json!({ "limbId": limb })).await;
    assert_eq!(error_code(&closed), None, "{closed}");
    assert_eq!(structured(&closed)["sessionClosed"], true, "{closed}");
    assert_eq!(
        source.closed_sessions(),
        vec![limb.clone()],
        "the application was asked to end the session, not only this process to forget it"
    );
    assert!(plane.limbs().is_empty());
}

#[tokio::test]
async fn closing_a_limb_that_is_already_gone_is_an_ordinary_success() {
    let (_source, plane) = fake_plane();
    let mut client = Client::connect(plane);
    let closed = client
        .tool("dvv_close", json!({ "limbId": "lmb_vnc_0123456789ab_0" }))
        .await;
    assert_eq!(error_code(&closed), None, "{closed}");
    assert_eq!(structured(&closed)["closed"], true);
}

/// The CLI holder lets go of its limbs when it idles out, and that must not
/// disconnect the machines: the person may be watching them.
#[tokio::test]
async fn letting_go_of_a_limb_leaves_its_session_open() {
    let (source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    plane.let_go(&limb).expect("let go");
    assert!(source.closed_sessions().is_empty());
    assert!(plane.limbs().is_empty());
}
