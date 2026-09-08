//! The handshake every revision before 2026-07-28 opens with, over a pipe.
//!
//! Claude Code, and every client built on the official SDKs, sends
//! `initialize` first and treats method not found as a dead server. The first
//! build answered exactly that, so the one-click registration in the app
//! produced a server no installed client could reach. This drives the
//! conversation such a client has, over the real framing, and asserts that the
//! manifest and a tool call come back the same as they do for a 2026-07-28
//! client, because on the wire they are the same.

mod common;

use common::{fake_plane, Client};
use serde_json::json;

#[tokio::test]
async fn a_client_on_an_earlier_revision_is_answered_and_then_served() {
    let (_source, plane) = fake_plane();
    let mut client = Client::connect(plane);

    // 1. The handshake, as Claude Code sends it.
    let init = client
        .call(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "roots": { "listChanged": true } },
                "clientInfo": { "name": "claude-code", "version": "2.0.0" },
            }),
        )
        .await;
    assert!(init.get("error").is_none(), "{init}");
    assert_eq!(
        init["result"]["protocolVersion"], "2025-06-18",
        "a revision this server knows is answered with the same one"
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "deskvnc");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert!(
        init["result"]["instructions"]
            .as_str()
            .is_some_and(|text| text.contains("dvv_limbs")),
        "the same instructions server/discover carries"
    );

    // 2. The initialized notification gets no reply, which the next call
    //    proves: were one written, it would be read here in its place.
    let list = client
        .raw(concat!(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#
        ))
        .await;
    assert_eq!(list["id"], 7);
    assert_eq!(
        list["result"]["tools"].as_array().expect("an array").len(),
        dvv::mcp::TOOL_COUNT
    );

    // 3. A tool call, with no _meta anywhere, is the ordinary result.
    let limbs = client.tool("dvv_limbs", json!({})).await;
    assert!(limbs["content"].is_array(), "{limbs}");
}

#[tokio::test]
async fn a_revision_this_server_does_not_know_is_answered_with_the_newest_it_does() {
    let (_source, plane) = fake_plane();
    let mut client = Client::connect(plane);
    let init = client
        .call("initialize", json!({ "protocolVersion": "2031-01-01" }))
        .await;
    assert_eq!(
        init["result"]["protocolVersion"],
        dvv::CLASSIC_PROTOCOL_VERSIONS[0],
        "the specification's rule: offer what the server speaks and let the client decide"
    );
    let init = client.call("initialize", json!({})).await;
    assert_eq!(
        init["result"]["protocolVersion"],
        dvv::CLASSIC_PROTOCOL_VERSIONS[0]
    );
}
