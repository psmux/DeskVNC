//! The two rules `00 R42` fixes about what an agent is allowed to be told.
//!
//! Both are asserted **on the serialised JSON** and not on the Rust types,
//! because both properties only exist at the wire. A type that holds an
//! `Option` and a wire that emits `"value": null` are the same type and
//! opposite contracts.

mod common;

use common::{fake_plane, open, structured, Client};
use serde_json::{json, Value};

/// WA-4. The grep the acceptance criterion asks for, over everything this
/// server can emit.
///
/// Run against the tool manifest, the discovery response and a live observation
/// rather than against one of them, because a fabricated window field would
/// most likely arrive in a schema first: somebody adds `focus_window` to a tool
/// before anything produces it.
#[tokio::test]
async fn no_fabricated_window_field_appears_in_anything_this_server_emits() {
    let (_source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", true);
    let mut client = Client::connect(plane);

    let mut surfaces: Vec<String> = Vec::new();
    surfaces.push(client.call("server/discover", json!({})).await.to_string());
    surfaces.push(client.call("tools/list", json!({})).await.to_string());
    surfaces.push(
        client
            .tool("dvv_status", json!({ "limbId": limb }))
            .await
            .to_string(),
    );
    surfaces.push(
        client
            .tool("dvv_signals", json!({ "limbId": limb }))
            .await
            .to_string(),
    );
    surfaces.push(client.tool("dvv_limbs", json!({})).await.to_string());

    for surface in &surfaces {
        for field in dvv::observation::FORBIDDEN_FIELDS {
            assert!(
                !surface.contains(field),
                "{field} appears in an emitted surface, and 00 R42 rules the five fabricated window fields out of this design entirely: a confidently wrong window tree makes an agent act decisively on a misreading"
            );
        }
    }

    // And the negative is STATED rather than left to be inferred from a missing
    // field, which is the other half of the ruling.
    let signals = client.tool("dvv_signals", json!({ "limbId": limb })).await;
    let window = &structured(&signals)["signals"]["window_structure"];
    assert_eq!(window["availability"], "absent");
    assert!(window["reason"]
        .as_str()
        .expect("an absence carries its reason")
        .contains("per window structure"));
    assert!(
        window.get("value").is_none(),
        "an absence has no value key at all"
    );
}

/// WA-3. A field whose availability is not live has no `value` key.
///
/// The case that decides it: a defaulted Caps Lock of `false` before a password
/// is typed is a lie that costs somebody an account lockout, and there is no way
/// to write that consumer defensively if the wire hands it a boolean either way.
#[tokio::test]
async fn an_envelope_that_is_not_live_has_no_value_key_at_all() {
    let (_source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", true);
    let mut client = Client::connect(plane);

    let status = client.tool("dvv_status", json!({ "limbId": limb })).await;
    let observation = structured(&status);
    assert_eq!(observation["schema"], "dvv.observation.v1");
    assert_eq!(observation["untrusted"], true);

    // `locks` is the Caps Lock case itself.
    let locks = &observation["locks"];
    assert_ne!(locks["availability"], "live", "nothing negotiated it");
    assert!(
        locks.get("value").is_none(),
        "a consumer that forgets to check must get a MISSING KEY rather than a plausible zero: {locks}"
    );
    assert!(
        locks["reason"].as_str().expect("a reason").len() > 20,
        "an absence names why, so an agent knows whether to look again"
    );

    // Every envelope in the object, walked, so a field added without the rule
    // fails here rather than in production.
    let mut checked = 0;
    walk(observation, &mut |value| {
        let Some(availability) = value.get("availability").and_then(Value::as_str) else {
            return;
        };
        checked += 1;
        match availability {
            "live" => assert!(
                value.get("value").is_some()
                    || value.as_object().map(|o| o.len() > 1).unwrap_or(false),
                "a live envelope carries its value: {value}"
            ),
            "absent" | "unknown" => {
                assert!(
                    value.get("value").is_none(),
                    "{availability} carries no value key: {value}"
                );
                assert!(
                    value.get("reason").is_some(),
                    "{availability} carries the reason: {value}"
                );
            }
            other => panic!("{other:?} is a fourth availability and there are only three"),
        }
    });
    assert!(
        checked >= 12,
        "only {checked} envelopes were walked, which is fewer than the signals report alone carries"
    );
}

/// The state a limb reports goes through `SessionState`'s own serde
/// representation, which is a contract with the webview.
///
/// A second encoder here would be a second answer to what state a limb is in,
/// and the two would drift the first time a variant changed.
#[tokio::test]
async fn the_lifecycle_state_is_the_shells_own_representation() {
    let (_source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", true);
    let mut client = Client::connect(plane);

    let status = client.tool("dvv_status", json!({ "limbId": limb })).await;
    assert_eq!(structured(&status)["state"]["state"], "connected");
    assert_eq!(structured(&status)["geometry"]["space"]["unit"], "pixels");
    assert_eq!(structured(&status)["geometry"]["primary_known"], false);
}

/// A terminal limb is addressed in cells and says so.
///
/// 80 columns is not 80 pixels and nothing in the type system catches the mix
/// up, so the unit travels beside the number.
#[tokio::test]
async fn a_terminal_limb_reports_cells_and_not_pixels() {
    let (_source, plane) = fake_plane();
    let limb = open(&plane, "h_lab02", false);
    let mut client = Client::connect(plane);

    let status = client.tool("dvv_status", json!({ "limbId": limb })).await;
    assert_eq!(structured(&status)["protocol"], "ssh");
    assert_eq!(structured(&status)["geometry"]["space"]["unit"], "cells");
    assert!(
        structured(&status)["terminal"].is_object(),
        "a terminal limb carries the terminal block and a desktop one does not"
    );
}

fn walk(value: &Value, visit: &mut impl FnMut(&Value)) {
    visit(value);
    match value {
        Value::Object(map) => {
            for child in map.values() {
                walk(child, visit);
            }
        }
        Value::Array(items) => {
            for child in items {
                walk(child, visit);
            }
        }
        _ => {}
    }
}
