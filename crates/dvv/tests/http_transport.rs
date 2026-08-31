//! MCP over Streamable HTTP, over a real socket on an ephemeral port.
//!
//! `00 R52`. Every test here binds `127.0.0.1:0`, reads the port the operating
//! system gave it and talks to it over TCP, because the properties being
//! asserted are properties of a LISTENER: what it refuses, what it binds, and
//! what it does when its port is taken. A test that called the handler directly
//! would prove none of them.
//!
//! The client is written out by hand, ten lines of HTTP/1.1, for the same
//! reason `tests/common` writes the JSON-RPC framing by hand: a client library
//! would negotiate away exactly the mistakes these tests are trying to make.
//! `Connection: close` means the response ends at EOF, so reading it is
//! `read_to_end` and not a parser.

mod common;

use common::fake_plane;
use dvv::http::{
    default_host, exposure_warning, host_from_flag, HttpConfig, HttpServer, HEADER_MISMATCH,
};
use dvv::mcp::Server;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TOKEN: &str = "1e5a2f0c9b8d7e6f5a4b3c2d1e0f9a8b";
const BEARER: &str = "Bearer 1e5a2f0c9b8d7e6f5a4b3c2d1e0f9a8b";

/// A listener over the two fake machines, and the plane behind it.
struct Listening {
    address: SocketAddr,
    plane: Arc<dvv::Plane>,
    /// Held so the accept loop lives as long as the test does.
    _task: tokio::task::JoinHandle<()>,
}

async fn listening(allowed_origins: Vec<String>) -> Listening {
    let (_source, plane) = fake_plane();
    let config = HttpConfig {
        host: default_host(),
        port: 0,
        token: TOKEN.to_string(),
        allowed_origins,
    };
    let listener = HttpServer::bind(config)
        .await
        .expect("an ephemeral loopback port");
    let address = listener.local_addr().expect("the bound address");
    let server = Arc::new(Server::new(Arc::clone(&plane)));
    let task = tokio::spawn(async move {
        let _ = listener.serve(server).await;
    });
    Listening {
        address,
        plane,
        _task: task,
    }
}

struct Answer {
    status: u16,
    body: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|error| {
            panic!("the body is not JSON ({error}): {:?}", self.body);
        })
    }
}

/// One request, one response, one connection.
async fn send(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Answer {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("the listener accepts");
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream
        .write_all(request.as_bytes())
        .await
        .expect("the request goes out");
    stream.flush().await.expect("flushed");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .expect("the response comes back");
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .expect("a response with a header block");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("a status code");
    Answer {
        status,
        body: body.to_string(),
    }
}

/// The headers a conforming 2026-07-28 client sends on a `tools/call`.
fn call_headers(tool: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Authorization", BEARER.to_string()),
        (
            "MCP-Protocol-Version",
            dvv::MCP_PROTOCOL_VERSION.to_string(),
        ),
        ("Mcp-Method", "tools/call".to_string()),
        ("Mcp-Name", tool.to_string()),
    ]
}

fn borrowed<'a>(headers: &'a [(&'static str, String)]) -> Vec<(&'a str, &'a str)> {
    headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

async fn post(address: SocketAddr, headers: &[(&str, &str)], body: &Value) -> Answer {
    send(address, "POST", "/mcp", headers, &body.to_string()).await
}

/// The property the whole transport exists to have: the same request, over
/// HTTP, gets the same answer.
///
/// Both sides run against the same plane, and the stdio side goes over a real
/// pipe through `tests/common`. If HTTP were a second implementation of
/// anything, this is where the two would part company.
#[tokio::test]
async fn a_round_trip_over_http_matches_the_stdio_path_exactly() {
    let live = listening(Vec::new()).await;
    let mut stdio = common::Client::connect(Arc::clone(&live.plane));

    // 1. The manifest.
    let over_stdio = stdio.call("tools/list", json!({})).await;
    let over_http = post(
        live.address,
        &[
            ("Authorization", BEARER),
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/list"),
        ],
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
    )
    .await;
    assert_eq!(over_http.status, 200, "{}", over_http.body);
    assert_eq!(
        over_http.json()["result"],
        over_stdio["result"],
        "the manifest must not depend on how the agent got here"
    );
    assert_eq!(
        over_http.json()["result"]["tools"]
            .as_array()
            .expect("an array")
            .len(),
        dvv::mcp::TOOL_COUNT
    );

    // 2. A tool call. `dvv_hosts` reads the source and changes nothing, so
    //    calling it twice is calling it twice and not a sequence.
    let arguments = json!({ "discovered": false });
    let over_stdio = stdio.tool("dvv_hosts", arguments.clone()).await;
    let headers = call_headers("dvv_hosts");
    let over_http = post(
        live.address,
        &borrowed(&headers),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "dvv_hosts",
                "arguments": arguments,
                "_meta": { "io.modelcontextprotocol/protocolVersion": dvv::MCP_PROTOCOL_VERSION },
            },
        }),
    )
    .await;
    assert_eq!(over_http.status, 200, "{}", over_http.body);
    assert_eq!(over_http.json()["result"], over_stdio);
    assert!(over_http.json()["result"]["structuredContent"]["hosts"]
        .as_array()
        .is_some_and(|hosts| !hosts.is_empty()));
}

/// `00 R52` term 3. On loopback, with no token, and it is still refused.
#[tokio::test]
async fn a_request_with_no_token_is_refused() {
    let live = listening(Vec::new()).await;
    let answer = post(
        live.address,
        &[
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/list"),
        ],
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
    )
    .await;
    assert_eq!(answer.status, 401, "{}", answer.body);
    // The refusal has to carry the argument, because this is the term somebody
    // will try to argue away later.
    assert!(
        answer.body.contains("loopback"),
        "the 401 should say why a token is required on loopback: {}",
        answer.body
    );
    // And nothing of the plane leaked out with it.
    assert!(!answer.body.contains("tools"), "{}", answer.body);
}

#[tokio::test]
async fn a_request_with_the_wrong_token_is_refused() {
    let live = listening(Vec::new()).await;
    for wrong in [
        "Bearer 1e5a2f0c9b8d7e6f5a4b3c2d1e0f9a8c",
        // A prefix of the right one, which is what a timing attack walks
        // towards one byte at a time.
        "Bearer 1e5a2f0c9b8d7e6f5a4b3c2d1e0f9a8",
        "Bearer ",
        "Basic 1e5a2f0c9b8d7e6f5a4b3c2d1e0f9a8b",
        "1e5a2f0c9b8d7e6f5a4b3c2d1e0f9a8b",
    ] {
        let answer = post(
            live.address,
            &[
                ("Authorization", wrong),
                ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/list"),
            ],
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
        )
        .await;
        assert_eq!(
            answer.status, 401,
            "{wrong:?} was accepted: {}",
            answer.body
        );
    }
}

/// The attack that makes "loopback is safe" wrong.
///
/// A page the user visited posts to `127.0.0.1` from their own browser, and the
/// browser attaches that page's origin. Nothing that legitimately drives dvv is
/// a web page, so the default allowlist is empty and every `Origin` is refused,
/// the token notwithstanding.
#[tokio::test]
async fn a_hostile_origin_is_refused_even_with_the_right_token() {
    let live = listening(Vec::new()).await;
    for origin in [
        "https://evil.example",
        "http://localhost:3000",
        "null",
        "http://127.0.0.1:7333",
    ] {
        let answer = post(
            live.address,
            &[
                ("Authorization", BEARER),
                ("Origin", origin),
                ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
                ("Mcp-Method", "tools/list"),
            ],
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
        )
        .await;
        assert_eq!(answer.status, 403, "{origin:?} was served: {}", answer.body);
    }
}

#[tokio::test]
async fn an_origin_the_operator_named_is_served() {
    let live = listening(vec!["https://console.example".to_string()]).await;
    let answer = post(
        live.address,
        &[
            ("Authorization", BEARER),
            ("Origin", "https://console.example"),
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/list"),
        ],
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
    )
    .await;
    assert_eq!(answer.status, 200, "{}", answer.body);
}

/// `00 R52` term 2, over a real socket rather than over the parser.
#[tokio::test]
async fn the_default_bind_is_loopback_and_binding_wider_needs_the_flag() {
    // No flag, no reach: there is no path from an absent `--host` to an address
    // anything off this machine can route to.
    assert!(host_from_flag(None).expect("a default").is_loopback());
    assert!(exposure_warning(&host_from_flag(None).expect("a default")).is_none());

    let live = listening(Vec::new()).await;
    assert!(
        live.address.ip().is_loopback(),
        "{} is not loopback",
        live.address
    );

    // The flag is the whole of the difference, and taking it says so.
    let wide = host_from_flag(Some("0.0.0.0")).expect("an address");
    assert!(!wide.is_loopback());
    let warning = exposure_warning(&wide).expect("a sentence naming the exposure");
    assert!(warning.contains("EXPOSED"), "{warning}");
    assert!(warning.contains("0.0.0.0"), "{warning}");
}

/// `00 R52` term 6. A port already held says which port, and says it in an
/// error rather than in a log line nobody reads.
#[tokio::test]
async fn a_port_already_in_use_fails_loudly() {
    let first = HttpServer::bind(HttpConfig::loopback(0, TOKEN))
        .await
        .expect("an ephemeral loopback port");
    let taken = first.local_addr().expect("the bound address");

    let mut second = HttpConfig::loopback(taken.port(), TOKEN);
    second.host = taken.ip();
    // A match rather than `expect_err`, because `HttpServer` deliberately has
    // no `Debug`: printing one would print its config, and its config carries a
    // live bearer token.
    let error = match HttpServer::bind(second).await {
        Ok(_) => panic!("{taken} was bound twice, so nothing would have told the user"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    let message = error.to_string();
    assert!(
        message.contains(&taken.port().to_string()),
        "the failure must name the port: {message}"
    );
}

/// The 2026-07-28 revision removed the GET stream and the DELETE session, and
/// tells a server of this revision to answer 405 for both. An older client uses
/// exactly that to work out what it is talking to.
#[tokio::test]
async fn the_removed_get_stream_and_delete_session_are_405() {
    let live = listening(Vec::new()).await;
    for method in ["GET", "DELETE"] {
        let answer = send(
            live.address,
            method,
            "/mcp",
            &[("Authorization", BEARER)],
            "",
        )
        .await;
        assert_eq!(answer.status, 405, "{method}: {}", answer.body);
    }
}

/// The header and the body must agree.
///
/// Not a formality: a gateway metering on `Mcp-Name` while this server executes
/// `params.name` is two components acting on two sources of truth, and whoever
/// can make them disagree picks which one each sees.
#[tokio::test]
async fn headers_that_disagree_with_the_body_are_refused() {
    let live = listening(Vec::new()).await;
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "dvv_limbs", "arguments": {} },
    });

    // The name says one tool, the body calls another.
    let lying = post(
        live.address,
        &[
            ("Authorization", BEARER),
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "dvv_hosts"),
        ],
        &body,
    )
    .await;
    assert_eq!(lying.status, 400, "{}", lying.body);
    assert_eq!(lying.json()["error"]["code"], HEADER_MISMATCH);

    // No routing header at all.
    let bare = post(
        live.address,
        &[
            ("Authorization", BEARER),
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
        ],
        &body,
    )
    .await;
    assert_eq!(bare.status, 400, "{}", bare.body);
    assert_eq!(bare.json()["error"]["code"], HEADER_MISMATCH);

    // A version this server does not speak, which is its own code and carries
    // the list of versions that would have worked.
    let old = post(
        live.address,
        &[
            ("Authorization", BEARER),
            ("MCP-Protocol-Version", "2025-11-25"),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "dvv_limbs"),
        ],
        &body,
    )
    .await;
    assert_eq!(old.status, 400, "{}", old.body);
    assert_eq!(old.json()["error"]["code"], -32022);
    assert_eq!(
        old.json()["error"]["data"]["supported"][0],
        dvv::MCP_PROTOCOL_VERSION
    );
}

#[tokio::test]
async fn an_unimplemented_method_is_404_with_a_json_rpc_error_and_a_refusal_is_200() {
    let live = listening(Vec::new()).await;

    // 404 plus -32601, which is what lets a client tell this apart from the 404
    // a legacy HTTP+SSE server gives for a path it does not host.
    let unknown = post(
        live.address,
        &[
            ("Authorization", BEARER),
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "resources/list"),
        ],
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {} }),
    )
    .await;
    assert_eq!(unknown.status, 404, "{}", unknown.body);
    assert_eq!(unknown.json()["error"]["code"], -32601);

    // A tool that refused is an ordinary 200 carrying a RESULT. A model handed
    // a transport failure for a refusal it caused cannot tell the two apart,
    // and HTTP gives it one more way to be confused about that.
    let headers = call_headers("dvv_status");
    let refused = post(
        live.address,
        &borrowed(&headers),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "dvv_status", "arguments": { "limbId": "lmb_nothing" } },
        }),
    )
    .await;
    assert_eq!(refused.status, 200, "{}", refused.body);
    assert_eq!(refused.json()["result"]["isError"], true);
    assert_eq!(
        refused.json()["result"]["structuredContent"]["code"],
        "LIMB_GONE"
    );
}

#[tokio::test]
async fn a_notification_is_accepted_with_no_body_and_a_bad_line_is_not_fatal() {
    let live = listening(Vec::new()).await;

    let notification = post(
        live.address,
        &[
            ("Authorization", BEARER),
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "notifications/cancelled"),
        ],
        &json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": {} }),
    )
    .await;
    assert_eq!(notification.status, 202, "{}", notification.body);
    assert!(notification.body.is_empty(), "{}", notification.body);

    let broken = send(
        live.address,
        "POST",
        "/mcp",
        &[
            ("Authorization", BEARER),
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/list"),
        ],
        "{not json",
    )
    .await;
    assert_eq!(broken.status, 400, "{}", broken.body);
    assert_eq!(broken.json()["error"]["code"], -32700);

    // The listener is still serving: one bad request is not a reason to drop
    // every session the client is driving, which is the same rule stdio keeps.
    let after = post(
        live.address,
        &[
            ("Authorization", BEARER),
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/list"),
        ],
        &json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {} }),
    )
    .await;
    assert_eq!(after.status, 200, "{}", after.body);
}

#[tokio::test]
async fn there_is_one_endpoint_and_it_is_not_the_root() {
    let live = listening(Vec::new()).await;
    let answer = send(
        live.address,
        "POST",
        "/",
        &[
            ("Authorization", BEARER),
            ("MCP-Protocol-Version", dvv::MCP_PROTOCOL_VERSION),
            ("Mcp-Method", "tools/list"),
        ],
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }).to_string(),
    )
    .await;
    assert_eq!(answer.status, 404, "{}", answer.body);
    assert!(answer.body.contains("/mcp"), "{}", answer.body);
}
