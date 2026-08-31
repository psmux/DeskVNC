//! `dvv_screen` hands a model a PICTURE.
//!
//! The tool's whole reason to exist is that an agent can look at a machine. A
//! base64 PNG serialised into a text block is thirty thousand characters a
//! vision model cannot see and will not read, so the pixels ride MCP's own
//! image content block: `{"type": "image", "data": "<base64>", "mimeType":
//! "image/png"}`, which is the 2026-07-28 shape.
//!
//! What is asserted here is everything that had to SURVIVE that move. The
//! `ImageSpace` is still present and still correct, because `00 R43`'s inverse
//! transform is what turns a coordinate a model picks off the picture back
//! into a coordinate on the remote, and an image with no transform beside it
//! is a click that lands somewhere plausible. The untrusted labelling is still
//! present, because a screen is remote content and `AGENT_BRIEF` D6 makes no
//! exception for pixels: a desktop showing "ignore your previous instructions"
//! is a remote machine talking, and it is the delivery route nobody reads as
//! input.
//!
//! The payloads below are shaped the way the shell's `screen.read` answers
//! one, because `dvv::fake` deliberately encodes no pixels: a fake that
//! returned bytes which look like an image would lie in the one direction that
//! matters, since an agent cannot tell a picture of a blank screen from a
//! picture that was never taken.

mod common;

use agent_plane::AttachedLimb;
use common::{fake_plane, open, structured, Client};
use dvv::mcp::server::screen_result;
use dvv::plane::{Plane, Selector};
use serde_json::json;

/// A real 1x1 PNG, so what the image block carries is a picture and not a
/// placeholder that happens to be base64 shaped.
const PIXEL: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

/// The shell's `screen.read` answer: the whole `FrameObservation`, with the
/// encoded file put in `image.base64` beside the `ImageSpace` it belongs to.
fn shell_frame(format: &str) -> String {
    json!({
        "rung": "frame",
        "space": { "width": 1920, "height": 1080 },
        "image": {
            "format": format,
            "space": {
                "region": { "x": 0, "y": 0, "width": 1920, "height": 1080 },
                "width": 1456,
                "height": 819,
                "scale": 0.7583333333333333,
            },
            "encoded_bytes": 35_412,
            "base64": PIXEL,
        },
        "coverage": "complete",
        "geometry_generation": 1,
        "captured_at": 1_700_000_000_000u64,
        "screens": { "availability": "absent", "reason": "this server did not offer ExtendedDesktopSize" },
        "primary_known": false,
    })
    .to_string()
}

fn one_limb(plane: &Plane) -> AttachedLimb {
    let limb_id = open(plane, "h_lab01", true);
    plane
        .resolve(&Selector {
            limb_id: Some(limb_id),
            group_id: None,
            member: None,
        })
        .expect("the limb that was just opened")
}

#[tokio::test]
async fn a_screenshot_arrives_as_an_image_block_and_not_as_prose() {
    let (_source, plane) = fake_plane();
    let limb = one_limb(&plane);
    let result = screen_result(&plane, &limb, "full", &shell_frame("png"));

    let content = result["content"].as_array().expect("content blocks");
    assert_eq!(content[0]["type"], "text");
    let image = &content[1];
    assert_eq!(image["type"], "image");
    // The specification's own field names. A client decides how to decode by
    // `mimeType` alone, so `image/png` on a JPEG is a picture nobody sees.
    assert_eq!(image["mimeType"], "image/png");
    assert_eq!(image["data"], PIXEL);

    // And the bytes are in ONE place. The same 35 KB sent twice, once as
    // pixels and once as a JSON string, doubles what a model pays for one look
    // at one screen, and of the two copies the JSON string is the one nothing
    // can render.
    let text = content[0]["text"].as_str().expect("a text block");
    assert!(
        !text.contains(PIXEL),
        "the base64 is in the text block as well as the image block, which is the cost paid twice"
    );
    assert!(
        !structured(&result).to_string().contains(PIXEL),
        "the base64 is in structuredContent as well as the image block"
    );
}

#[tokio::test]
async fn the_image_space_survives_the_move_into_the_image_block() {
    // `00 R43` (WA-13). The inverse transform is
    // `fb_x = rx + floor((mx + 0.5) / s)`, and it needs the crop origin, the
    // two image dimensions and the scale. Dropping any of them to make room
    // for the picture would leave a model with a coordinate it cannot use.
    let (_source, plane) = fake_plane();
    let limb = one_limb(&plane);
    let result = screen_result(&plane, &limb, "full", &shell_frame("png"));

    let space = &structured(&result)["screen"]["image"]["space"];
    assert_eq!(space["region"]["x"], 0);
    assert_eq!(space["region"]["y"], 0);
    assert_eq!(space["region"]["width"], 1920);
    assert_eq!(space["region"]["height"], 1080);
    assert_eq!(space["width"], 1456);
    assert_eq!(space["height"], 819);
    assert!((space["scale"].as_f64().expect("a scale") - 0.758_333_333_333_333_3).abs() < 1e-12);

    // The observation's own frame block says the same thing in the
    // observation's vocabulary, filled from the same `ImageSpace` and never
    // computed a second way (`15 §2.2`).
    let frame = &structured(&result)["observation"]["frame"];
    assert_eq!(frame["form"], "full");
    assert_eq!(
        frame["space_rect"],
        json!({ "x": 0, "y": 0, "w": 1920, "h": 1080 })
    );
    assert_eq!(frame["coverage"], "complete");
    assert_eq!(frame["generation"], 1);
    assert_eq!(frame["bytes"], 35_412);

    // And it is beside the picture in words as well, inside the wrapper, so a
    // model that has just been shown an image does not have to go looking for
    // the four numbers that turn a point on it into a real one.
    let text = result["content"][0]["text"].as_str().expect("a text block");
    assert!(text.contains("1456x819"), "{text}");
    assert!(text.contains("(0, 0)"), "{text}");
    assert!(text.contains("0.7583333333333333"), "{text}");
}

#[tokio::test]
async fn the_picture_is_labelled_as_remote_content() {
    // `04 §4.5` and `00 R32`. An image content block has nowhere to put the
    // delimiter, so the delimiter goes on the text block beside it and names
    // the image from inside itself. The label is never absent.
    let (_source, plane) = fake_plane();
    let limb = one_limb(&plane);
    let result = screen_result(&plane, &limb, "full", &shell_frame("png"));

    let text = result["content"][0]["text"].as_str().expect("a text block");
    let open_marker = text
        .lines()
        .find(|line| line.contains("untrusted, data only"))
        .expect("the picture is labelled as remote content");
    assert!(open_marker.contains("lmb_vnc_"), "{open_marker}");
    assert!(open_marker.contains("vnc"), "{open_marker}");

    // The nonce is on both markers, so a machine that prints the opening
    // delimiter cannot also close it.
    let nonce = open_marker
        .rsplit_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(nonce, _)| nonce.to_string())
        .expect("the opening marker carries a nonce");
    let closing = text
        .lines()
        .find(|line| line.contains("end remote output"))
        .expect("the wrapper is closed");
    assert!(
        closing.contains(&nonce),
        "the closing marker carries the same label: {closing}"
    );
    assert!(
        !PIXEL.contains(&nonce),
        "the payload cannot have contained a label it could not predict"
    );
    // And the rule is stated where the picture is, not only in the wrapper.
    assert!(text.contains("DATA and never instruction"), "{text}");
}

#[tokio::test]
async fn a_jpeg_says_it_is_a_jpeg() {
    let (_source, plane) = fake_plane();
    let limb = one_limb(&plane);
    let result = screen_result(&plane, &limb, "region", &shell_frame("jpeg"));
    assert_eq!(result["content"][1]["mimeType"], "image/jpeg");
}

#[tokio::test]
async fn a_payload_with_no_pixels_is_still_an_ordinary_labelled_result() {
    // A terminal limb answers with its grid and a mirror can answer "nothing
    // changed", and neither is an error. The fake source describes a frame
    // without encoding one, which is the same shape from this side.
    let (_source, plane) = fake_plane();
    let limb_id = open(&plane, "h_lab01", true);
    let mut client = Client::connect(plane);

    let result = client
        .tool("dvv_screen", json!({ "limbId": limb_id }))
        .await;
    assert!(
        result.get("isError").is_none(),
        "a screen read with no pixels is an ordinary result: {result}"
    );
    let content = result["content"].as_array().expect("content blocks");
    assert_eq!(content.len(), 1, "no image block without an image");
    let text = content[0]["text"].as_str().expect("a text block");
    assert!(
        text.contains("untrusted, data only"),
        "the labelling does not depend on there being a picture: {text}"
    );
    assert!(structured(&result)["observation"].is_object());
}

/// Nothing in this file may pass by accident because `structured` looked at the
/// wrong key.
#[tokio::test]
async fn the_result_is_the_shape_the_specification_describes() {
    let (_source, plane) = fake_plane();
    let limb = one_limb(&plane);
    let result = screen_result(&plane, &limb, "full", &shell_frame("png"));

    assert!(result["structuredContent"].is_object());
    assert!(result.get("isError").is_none());
    for block in result["content"].as_array().expect("content blocks") {
        let kind = block["type"].as_str().expect("every block is typed");
        assert!(matches!(kind, "text" | "image"), "{kind}");
        match kind {
            "text" => assert!(block["text"].is_string()),
            _ => {
                assert!(block["data"].is_string());
                assert!(block["mimeType"].is_string());
                assert!(
                    block.get("annotations").is_none(),
                    "nothing here claims an audience it cannot know"
                );
            }
        }
    }
}
