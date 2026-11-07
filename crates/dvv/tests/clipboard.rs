//! `dvv_clipboard` with `get`.
//!
//! It used to answer NOT_IMPLEMENTED on every limb, because the machine's
//! answer arrives on the session's event stream and dvv is not subscribed to
//! it. DeskVNCViewer is, and now keeps the last text per session for the
//! agent plane, so the tool returns that, and says plainly when there is none.

mod common;

use common::{error_code, fake_plane, open, structured, Client};
use serde_json::json;

#[tokio::test]
async fn get_returns_what_the_machine_last_copied() {
    let (source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    source.copy_on_far_side(&limb, "copied on the far side");
    let mut client = Client::connect(plane);

    let got = client
        .tool("dvv_clipboard", json!({ "limbId": limb, "action": "get" }))
        .await;
    assert_eq!(error_code(&got), None, "{got}");
    assert_eq!(structured(&got)["text"], "copied on the far side", "{got}");
    assert_eq!(
        structured(&got)["fresh"],
        false,
        "nothing newer arrived in answer, and the result says so"
    );
    let text = got["content"][0]["text"].as_str().expect("a text block");
    assert!(text.contains("REMOTE TEXT"), "{text}");
}

#[tokio::test]
async fn get_with_nothing_copied_says_so_rather_than_inventing_an_empty_clipboard() {
    let (_source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", false);
    let mut client = Client::connect(plane);

    let got = client
        .tool("dvv_clipboard", json!({ "limbId": limb, "action": "get" }))
        .await;
    assert_eq!(error_code(&got), None, "{got}");
    assert_eq!(structured(&got)["text"], serde_json::Value::Null, "{got}");
    let text = got["content"][0]["text"].as_str().expect("a text block");
    assert!(text.contains("not an empty clipboard"), "{text}");
}
