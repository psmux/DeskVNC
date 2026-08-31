//! The availability envelope, asserted on the SERIALISED JSON rather than on
//! the Rust type (`00 R34`, `00 R42` WA-3 and WA-4).
//!
//! The distinction matters and it is the reason these tests exist at all. In
//! Rust the property is free: an enum without a `value` field in that variant
//! cannot produce one, and there is nothing to test. At the wire it is a
//! serde representation decision, and a change to the tag, the rename rule or
//! the variant shape would put a `"value": null` back into an absent envelope
//! without any Rust type changing at all.
//!
//! A `"value": null` is exactly the failure the rule exists to prevent. The
//! concrete case: a consumer reading Caps Lock finds the key, reads it as
//! false, types a password in the wrong case and locks somebody's account. A
//! MISSING KEY makes that consumer crash or branch, and either is better.

use limb_core::{Availability, SignalReport, SignalState, WINDOW_STRUCTURE_REASON};

#[test]
fn a_live_envelope_carries_its_value() {
    let json = serde_json::to_value(Availability::live(true)).unwrap();
    assert_eq!(json["availability"], "live");
    assert_eq!(json["value"], true);
    assert_eq!(json.as_object().unwrap().len(), 2);
}

#[test]
fn an_absent_envelope_has_no_value_key_at_all() {
    // The Caps Lock case, written out, because a reader of this test should
    // see the thing it is protecting.
    let caps_lock: Availability<bool> =
        Availability::absent("QEMU LED state extension not offered by this server");

    let json = serde_json::to_value(&caps_lock).unwrap();
    assert_eq!(json["availability"], "absent");
    assert!(
        json.get("value").is_none(),
        "an absent envelope must have no value key, and this one serialised as {json}"
    );
    // Not merely absent from the map: not present as null either, which is the
    // shape a careless serde attribute would produce and the shape a consumer
    // reading `json.value ?? false` would swallow.
    assert!(!json.to_string().contains("value"));
    assert_eq!(
        json["reason"],
        "QEMU LED state extension not offered by this server"
    );
}

#[test]
fn an_unknown_envelope_has_no_value_key_either_and_is_a_different_claim() {
    let json: serde_json::Value = serde_json::to_value(Availability::<u32>::unknown(
        "nothing has arrived yet this session",
    ))
    .unwrap();
    assert_eq!(json["availability"], "unknown");
    assert!(json.get("value").is_none());

    // `absent` is permanent for this session and `unknown` may resolve, so an
    // agent that treats them the same backs off from a signal that was about
    // to arrive, or waits forever for one that is never coming.
    let absent =
        serde_json::to_value(Availability::<u32>::absent("extension not offered")).unwrap();
    assert_ne!(json["availability"], absent["availability"]);
}

#[test]
fn there_is_no_way_to_read_a_value_out_of_a_missing_one() {
    let absent: Availability<u8> = Availability::absent("not offered");
    assert!(absent.value().is_none());
    assert!(!absent.is_live());
    // There is deliberately no `unwrap_or_default` on this type. If one is
    // ever added, a caller writes `.unwrap_or_default()` on a lock key state
    // and the account lockout is back.
    assert_eq!(Availability::live(3u8).value(), Some(&3));
}

#[test]
fn a_signal_entry_carries_no_value_key_even_when_it_is_live() {
    let json = serde_json::to_value(SignalState::Live).unwrap();
    assert_eq!(json["availability"], "live");
    // The signals report answers "can this session tell me X", not "what is
    // X", so a value key here would be meaningless and a consumer would look
    // for one.
    assert_eq!(json.as_object().unwrap().len(), 1);

    let json = serde_json::to_value(SignalState::absent("extension not offered")).unwrap();
    assert_eq!(json["availability"], "absent");
    assert!(json.get("value").is_none());
}

#[test]
fn window_structure_is_always_an_explicit_absence() {
    let json = serde_json::to_value(SignalReport::default()).unwrap();
    let ws = &json["window_structure"];
    assert_eq!(ws["availability"], "absent");
    assert_eq!(ws["reason"], WINDOW_STRUCTURE_REASON);

    // The entry exists so the negative is stated rather than inferred from a
    // missing field. A consumer that finds no `window_structure` key cannot
    // tell "we do not have it" from "this build forgot to report it".
    assert!(json.as_object().unwrap().contains_key("window_structure"));
}

#[test]
fn a_fresh_session_reports_unknown_rather_than_absent() {
    let json = serde_json::to_value(SignalReport::default()).unwrap();
    for signal in [
        "copy_rect",
        "fence",
        "led_state",
        "cursor_position",
        "cursor_shape",
        "screen_layout",
        "content_hint",
        "errinfo",
        "alt_screen",
        "resize",
    ] {
        assert_eq!(
            json[signal]["availability"], "unknown",
            "{signal} on a session that has negotiated nothing yet"
        );
    }
}

/// `00 R42` (WA-4) rules five field names out of the observation object
/// entirely, with an acceptance criterion that greps for the names. This is
/// that grep.
///
/// It scans this crate's own source rather than a document, because the
/// ruling's force is that the fields cannot be produced, and a name that
/// cannot be found in the vocabulary cannot be filled in by a limb author who
/// thinks they have a way. `desktop_name` is the trap the ruling exists for:
/// it is the name of a whole desktop session and it does not change when a
/// dialog opens, so a reader who wants a window title will reach for one of
/// these five and find nothing.
#[test]
fn the_five_fabricated_window_fields_appear_nowhere_in_this_crate() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0usize;
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        checked += 1;
        for forbidden in [
            "active_window",
            "app_name",
            "foreground_handle",
            "window_list",
            "z_order",
        ] {
            assert!(
                !text.contains(forbidden),
                "{} names {forbidden}, which 00 R42 rules out of the observation object entirely",
                path.display()
            );
        }
    }
    assert!(checked >= 9, "the scan found only {checked} source files");
}
