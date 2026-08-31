//! A full JSON-RPC round trip over a pipe, against a limb with no machine
//! behind it.
//!
//! `04 §9` acceptance criterion 11 wants `tools/list` to return the manifest
//! with every tool prefixed and every single limb tool carrying the selector
//! trio. This drives that over the real framing, then drives a click all the way
//! to the recorder on the other end of the session's command channel, so what is
//! asserted is what the plane actually put on the wire and not what a mock said
//! it would.

mod common;

use common::{error_code, fake_plane, open, structured, Client};
use serde_json::json;

#[tokio::test]
async fn the_whole_conversation_works_over_a_pipe() {
    let (source, plane) = fake_plane();
    let mut client = Client::connect(plane.clone());

    // 1. Discover. There is no `initialize` in 2026-07-28 and a server that
    //    wanted one would be speaking the previous revision.
    let discover = client
        .call(
            "server/discover",
            json!({ "_meta": { "protocolVersion": dvv::MCP_PROTOCOL_VERSION } }),
        )
        .await;
    assert_eq!(
        discover["result"]["protocolVersion"],
        dvv::MCP_PROTOCOL_VERSION
    );
    assert_eq!(discover["result"]["serverInfo"]["name"], "deskvnc");

    // 2. The manifest, with the cache headers `04 §4.1` takes for free.
    let list = client.call("tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().expect("an array");
    assert_eq!(
        tools.len(),
        dvv::mcp::TOOL_COUNT,
        "the manifest is 24 tools"
    );
    assert_eq!(list["result"]["ttlMs"], dvv::mcp::TOOLS_TTL_MS);
    assert_eq!(list["result"]["cacheScope"], dvv::mcp::TOOLS_CACHE_SCOPE);
    for tool in tools {
        let name = tool["name"].as_str().expect("a name");
        assert!(name.starts_with(dvv::TOOL_PREFIX), "{name}");
    }

    // 3. Open a machine. The id is derived rather than minted, so it is the
    //    same string on the next run against the same machine at the same slot.
    let opened = client
        .tool("dvv_open", json!({ "hostId": "h_lab01", "perceive": true }))
        .await;
    let limb = structured(&opened)["limb"]["limb_id"]
        .as_str()
        .expect("a limb id")
        .to_string();
    assert!(limb.starts_with("lmb_vnc_"), "{limb}");
    assert_eq!(
        limb,
        open(&plane, "h_lab01", true),
        "opening the same machine at the same slot resolves to the same limb, and does not open a second session"
    );

    // 4. Acting without the wheel is refused, and the refusal names the repair.
    let unleased = client
        .tool(
            "dvv_click",
            json!({ "limbId": limb, "action": "click", "x": 10, "y": 20, "generation": 1 }),
        )
        .await;
    assert_eq!(error_code(&unleased), Some("LEASE_NOT_HELD"), "{unleased}");
    assert!(structured(&unleased)["hint"]
        .as_str()
        .expect("a hint")
        .contains("dvv_control"));

    // 5. Take the wheel. The release the grant owes the limb goes out first.
    let control = client
        .tool(
            "dvv_control",
            json!({ "limbId": limb, "action": "acquire", "reason": "a round trip test" }),
        )
        .await;
    assert_eq!(structured(&control)["held"], true);
    assert_eq!(structured(&control)["outcome"], "granted");

    let recorder = source.recorder(&limb).expect("a recorder for this limb");
    assert_eq!(
        recorder.names(),
        vec!["pointer(0,0,mask=0)", "release all keys"],
        "a lease change owes the limb a release, buttons before keys"
    );
    recorder.clear();

    // 6. Click, and read what actually reached the wire.
    let clicked = client
        .tool(
            "dvv_click",
            json!({ "limbId": limb, "action": "click", "x": 640, "y": 360, "generation": 1 }),
        )
        .await;
    assert_eq!(error_code(&clicked), None, "{clicked}");
    assert_eq!(structured(&clicked)["outcome"], "delivered");
    assert_eq!(
        recorder.names(),
        vec![
            "pointer(640,360,mask=0)",
            "pointer(640,360,mask=1)",
            "pointer(640,360,mask=0)",
        ],
        "a click is a move, a press and a release, in that order"
    );

    // 7. A wait that finds nothing is an ordinary success, not an error.
    let waited = client
        .tool(
            "dvv_wait",
            json!({ "limbId": limb, "until": "screen-changed", "timeoutMs": 60 }),
        )
        .await;
    assert_eq!(error_code(&waited), None, "{waited}");
    assert_eq!(structured(&waited)["settled"], false);
}

/// `04 §9` acceptance criterion 6, asserted by the clock rather than by a field.
///
/// A `dvv_wait` that can exceed the client's own cap turns a successful wait
/// into a client side error, which is the worst possible failure because the
/// operation succeeded and the agent was told it failed. This test costs the
/// full clamp in wall time, and that is the point: a field saying 25000 proves
/// the number was written down, and only the clock proves it was obeyed.
#[tokio::test]
async fn a_ten_minute_wait_comes_back_inside_the_clamp() {
    let (_source, plane) = fake_plane();
    let limb = open(&plane, "h_lab01", true);
    let mut client = Client::connect(plane);

    let started = std::time::Instant::now();
    let clamped = client
        .tool(
            "dvv_wait",
            json!({ "limbId": limb, "until": "screen-changed", "timeoutMs": 600_000 }),
        )
        .await;
    let elapsed = started.elapsed();

    assert_eq!(error_code(&clamped), None, "a timeout is not an error");
    assert_eq!(structured(&clamped)["settled"], false);
    assert_eq!(structured(&clamped)["askedMs"], 600_000);
    assert_eq!(structured(&clamped)["clampedMs"], dvv::mcp::WAIT_CLAMP_MS);
    assert!(
        elapsed.as_millis() < u128::from(dvv::mcp::WAIT_CLAMP_MS) + 2_000,
        "the wait ran for {elapsed:?}, which is past the clamp"
    );
}

#[tokio::test]
async fn an_unknown_method_is_a_protocol_error_and_a_refusal_is_not() {
    let (_source, plane) = fake_plane();
    let mut client = Client::connect(plane);

    let unknown = client.call("resources/list", json!({})).await;
    assert_eq!(unknown["error"]["code"], -32601);

    // The safe behaviour here is the ABSENCE of a feature, and absences are
    // what regress silently, so it is asserted.
    let tasks = client.call("tasks/list", json!({})).await;
    assert_eq!(tasks["error"]["code"], -32601);
    assert!(tasks["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("2026-07-28"));

    // A tool that refused is a RESULT. A model handed a transport failure for a
    // refusal it caused cannot tell the two apart.
    let refused = client
        .tool("dvv_status", json!({ "limbId": "lmb_x" }))
        .await;
    assert_eq!(error_code(&refused), Some("LIMB_GONE"));
}

#[tokio::test]
async fn a_malformed_line_does_not_end_the_session() {
    let (_source, plane) = fake_plane();
    let mut client = Client::connect(plane);

    let broken = client.raw("{not json").await;
    assert_eq!(broken["error"]["code"], -32700);

    // One bad line from a client is not a reason to drop every session that
    // client is driving, so the next call still works.
    let list = client.call("tools/list", json!({})).await;
    assert_eq!(
        list["result"]["tools"].as_array().expect("an array").len(),
        dvv::mcp::TOOL_COUNT
    );
}

#[tokio::test]
async fn a_group_addresses_every_member_through_the_ordinary_tools() {
    // The property `04 §4.1` adopts wholesale: an agent must never need a
    // different tool because its target happens to be in a group.
    let (_source, plane) = fake_plane();
    let mut client = Client::connect(plane);

    let group = client
        .tool(
            "dvv_group_open",
            json!({ "hostIds": ["h_lab01", "h_lab02"], "perceive": true }),
        )
        .await;
    let id = structured(&group)["groupId"]
        .as_str()
        .expect("a group id")
        .to_string();
    assert_eq!(
        structured(&group)["members"]
            .as_array()
            .expect("members")
            .len(),
        2
    );

    // One member, through a single limb tool, with no limbId anywhere.
    let status = client
        .tool("dvv_status", json!({ "groupId": id, "member": 1 }))
        .await;
    assert_eq!(error_code(&status), None, "{status}");
    assert_eq!(structured(&status)["protocol"], "ssh");

    // Every member at once, concurrently.
    let all = client
        .tool(
            "dvv_group_run",
            json!({ "groupId": id, "action": "status" }),
        )
        .await;
    assert_eq!(
        structured(&all)["results"]
            .as_array()
            .expect("results")
            .len(),
        2
    );

    let closed = client
        .tool("dvv_group_close", json!({ "groupId": id }))
        .await;
    assert_eq!(
        structured(&closed)["closed"]
            .as_array()
            .expect("closed")
            .len(),
        2
    );
}
