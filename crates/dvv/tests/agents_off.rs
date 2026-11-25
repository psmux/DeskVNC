//! A person who turned AI agents off in DeskVNCViewer is not overruled by an
//! agent (issue #72).
//!
//! OpenCode, Claude Code and Codex start `dvv mcp --stdio` themselves, from
//! their own config, whether or not the app is running. Before, a call that
//! needed the app (`dvv_hosts`, `dvv_open`) opened it even after the person
//! had turned agents off, so turning them off looked like it did nothing. The
//! app now keeps a file in its data folder while agents are off, and `dvv`
//! reads it before it starts anything.
//!
//! Linux only, because it proves the app was not started by pointing
//! `app-path` at a stub that leaves a file behind. On macOS `dvv` asks Launch
//! Services by bundle id, and a test that failed there would open the real
//! app on the screen of whoever ran it.
#![cfg(target_os = "linux")]

mod common;

use common::Client;
use dvv::plane::{self, Plane, SessionSource, ShellSource};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread")]
async fn agents_turned_off_in_the_app_keep_dvv_from_opening_it() {
    let scratch = std::env::temp_dir().join(format!("dvv-agents-off-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("a scratch folder");
    std::env::set_var("HOME", &scratch);
    std::env::set_var("XDG_RUNTIME_DIR", &scratch);
    std::env::set_var("XDG_DATA_HOME", &scratch);
    std::env::remove_var(plane::NO_START_ENV);
    assert!(!plane::socket_present());

    // The app as dvv would find it: a stub that leaves a file when started.
    let data = scratch.join("com.deskvncviewer.desktop");
    std::fs::create_dir_all(&data).expect("the app's data folder");
    let started = scratch.join("app-was-started");
    let stub = scratch.join("stub-app");
    std::fs::write(&stub, format!("#!/bin/sh\ntouch '{}'\n", started.display())).expect("the stub");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(data.join("app-path"), stub.display().to_string()).unwrap();

    // What the app writes when a person turns agents off.
    std::fs::write(data.join("agents-off"), "").unwrap();

    let built = Arc::new(Plane::local(Arc::new(ShellSource) as Arc<dyn SessionSource>).unwrap());
    let mut client = Client::connect(built);
    let _ = client
        .call(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": { "name": "agents-off", "version": "0" } }),
        )
        .await;

    let began = Instant::now();
    let hosts = client
        .call(
            "tools/call",
            json!({ "name": "dvv_hosts", "arguments": {} }),
        )
        .await;
    assert!(
        began.elapsed() < Duration::from_secs(10),
        "dvv waited for an app it should not have started"
    );
    // A started stub runs at once; give it a moment to be sure.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !started.exists(),
        "dvv started DeskVNCViewer although agents are turned off in it"
    );
    let text = hosts.to_string();
    assert!(
        text.contains("AI agents are turned off"),
        "the agent is told why, so it can tell the person: {text}"
    );
    assert!(text.contains("dvv setup --remove"), "{text}");

    let _ = std::fs::remove_dir_all(&scratch);
}
