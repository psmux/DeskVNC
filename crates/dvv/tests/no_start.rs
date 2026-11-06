//! When `dvv` starts DeskVNCViewer, and when it must not (issue #24).
//!
//! An MCP client starts `dvv mcp --stdio` when it starts, and Codex starts it
//! again for every new session. Building the local grant asked the
//! application for its saved machines, and asking started it: the window came
//! up before `initialize` was even read, and `initialize` waited up to a
//! minute for it. A person who quit the app saw it come back with the next
//! session.
//!
//! The claim here: starting the server, `initialize`, `tools/list` and
//! `dvv_limbs` never try to start the application. `dvv_hosts` does, once.
//!
//! ## One test function, deliberately
//!
//! The socket path, the link and the start counter are process wide, and the
//! environment is set so the socket points at a pipe or file that does not
//! exist. `DVV_NO_START` keeps the attempt that is expected from putting a
//! real window on the screen of whoever runs the tests: the counter is
//! incremented before that is looked at.

mod common;

use common::Client;
use dvv::plane::{self, Need, Plane, SessionSource, ShellSource};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread")]
async fn only_a_call_that_needs_the_app_starts_it() {
    let scratch = std::env::temp_dir().join(format!("dvv-no-start-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("a scratch folder");
    std::env::set_var("USERNAME", format!("dvv-no-start-{}", std::process::id()));
    std::env::set_var("HOME", &scratch);
    std::env::set_var("XDG_RUNTIME_DIR", &scratch);
    std::env::set_var("XDG_DATA_HOME", &scratch);
    std::env::set_var("APPDATA", &scratch);
    std::env::set_var(plane::NO_START_ENV, "1");
    assert!(
        !plane::socket_present(),
        "the socket for this test must not exist: {}",
        dvv::cli::socket_path()
    );

    // The process starting: the grant is built here.
    let began = Instant::now();
    let built = Arc::new(
        Plane::local(Arc::new(ShellSource) as Arc<dyn SessionSource>)
            .expect("a grant, over nothing yet"),
    );
    assert_eq!(
        plane::start_attempts(),
        0,
        "building the grant at startup tried to start DeskVNCViewer"
    );
    assert!(began.elapsed() < Duration::from_secs(5));

    // What an MCP client sends on its own, before any agent asked for anything.
    let mut client = Client::connect(built);
    let init = client
        .call(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "no-start", "version": "0" }
            }),
        )
        .await;
    assert!(init.get("result").is_some(), "{init}");
    let tools = client.call("tools/list", json!({})).await;
    assert!(tools["result"]["tools"].as_array().is_some(), "{tools}");
    let limbs = client
        .call(
            "tools/call",
            json!({ "name": "dvv_limbs", "arguments": {} }),
        )
        .await;
    assert!(limbs.get("result").is_some(), "{limbs}");
    assert_eq!(
        plane::start_attempts(),
        0,
        "initialize, tools/list or dvv_limbs tried to start DeskVNCViewer"
    );

    // An agent asking for the saved machines needs the application.
    let began = Instant::now();
    let hosts = client
        .call(
            "tools/call",
            json!({ "name": "dvv_hosts", "arguments": {} }),
        )
        .await;
    assert_eq!(plane::start_attempts(), 1, "{hosts}");
    assert!(
        began.elapsed() < Duration::from_secs(10),
        "with starting switched off there is nothing to wait for"
    );
    assert!(
        hosts.to_string().contains("no agent plane socket"),
        "the agent is told the app is not there: {hosts}"
    );

    // Once per process: asking again does not start it again.
    let _ = client
        .call(
            "tools/call",
            json!({ "name": "dvv_hosts", "arguments": {} }),
        )
        .await;
    assert_eq!(plane::start_attempts(), 1);

    let _ = std::fs::remove_dir_all(&scratch);
}

/// The decision on its own, which is all macOS adds a path around.
#[test]
fn the_decision() {
    // Not running, needed, first time: start it.
    assert!(plane::starts_app(Need::Start, false, false));
    // Already running: nothing to start.
    assert!(!plane::starts_app(Need::Start, true, false));
    // Tried once in this process already: a plane switched off stays off.
    assert!(!plane::starts_app(Need::Start, false, true));
    // A call that only reads what is open never starts it.
    assert!(!plane::starts_app(Need::Running, false, false));
    assert!(!plane::starts_app(Need::Running, true, false));
    assert!(!plane::starts_app(Need::Running, false, true));
}
