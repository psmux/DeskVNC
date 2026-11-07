//! What the person's pane is told an agent has in flight, over a real
//! `dvvp.v1` socket.
//!
//! The relay thread reports the kind of command it starts carrying so the
//! pane can say what the agent is doing. It used to report only when a NEW
//! kind started, and never that it had finished, so the last command an agent
//! sent (a `dvv clip get`'s one clipboard request, say) stayed "in flight" in
//! the pane long after it had been carried. The far side here is a stand in
//! for `src-tauri/src/agent/server.rs` that records every `control.report`.
//!
//! One test function, for the reason `exec_over_socket.rs` gives: the
//! connection and `HOME` are process wide.

#![cfg(unix)]

use dvv::plane::{OpenRequest, Plane, Selector, SessionSource, ShellSource};
use limb_core::intent::IntentKind;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MSG_JSONRPC: u8 = 0;

fn read_message(stream: &mut UnixStream) -> Option<Value> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).ok()?;
    serde_json::from_slice(&payload).ok()
}

fn write_message(stream: &mut UnixStream, value: &Value) {
    let body = serde_json::to_vec(value).expect("a reply encodes");
    let mut framed = vec![MSG_JSONRPC, 0, 0, 0];
    framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
    framed.extend_from_slice(&body);
    stream
        .write_all(&framed)
        .expect("the client is still there");
    stream.flush().expect("flushed");
}

fn attached() -> Value {
    json!({
        "sessionId": "s1",
        "protocol": "ssh",
        "profileId": "h_lab01",
        "address": "10.0.0.5",
        "port": 22,
        "slot": 0,
        "state": { "state": "connected" },
        "size": { "width": 80, "height": 24 },
        "attachmentId": "att_1",
        "machine": { "kind": "profile", "id": "h_lab01" },
        "perception": { "mirror": false, "frames": false },
    })
}

/// Answers the methods this conversation needs and records every in flight
/// list it is told.
fn serve(listener: UnixListener, reports: Arc<Mutex<Vec<Vec<String>>>>) {
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connected");
        while let Some(request) = read_message(&mut stream) {
            let id = request["id"].clone();
            let method = request["method"].as_str().unwrap_or_default().to_string();
            let params = request["params"].clone();
            let result = match method.as_str() {
                "hello" => json!({
                    "protocol": "dvvp.v1",
                    "server": { "name": "DeskVNCViewer", "version": "test" },
                    "attachmentId": "att_1",
                    "capabilities": [
                        "view", "control", "open", "close", "hosts.read",
                        "terminal.read", "terminal.write",
                    ],
                    "protocols": ["vnc", "rdp", "ssh"],
                }),
                "hosts.list" => json!({ "hosts": [{
                    "hostId": "h_lab01",
                    "label": "lab01",
                    "address": "10.0.0.5",
                    "port": 22,
                    "protocol": "ssh",
                    "credentialStored": true,
                    "discovered": false,
                }] }),
                "limb.attach" | "limb.status" => attached(),
                "control.report" => {
                    let names = params["inflight"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    reports.lock().unwrap().push(names);
                    json!({ "recorded": true })
                }
                "control.acquire" | "control.status" | "control.release" => json!({
                    "granted": method != "control.release",
                    "youHold": method != "control.release",
                    "dispatching": method != "control.release",
                    "personHolds": false,
                    "holder": null,
                    "queue": [],
                }),
                "limb.command" => json!({ "delivered": true }),
                // Anything else this conversation does not depend on.
                _ => json!({}),
            };
            write_message(
                &mut stream,
                &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            );
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pane_is_told_when_the_last_command_has_gone() {
    let home = std::path::PathBuf::from(format!("/tmp/dvv-inflight-{}", std::process::id()));
    std::env::set_var("HOME", &home);
    std::env::remove_var("XDG_RUNTIME_DIR");
    let socket = std::path::PathBuf::from(dvv::cli::socket_path());
    std::fs::create_dir_all(socket.parent().expect("a directory")).expect("a directory to bind in");
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("nothing else is bound here");
    let reports = Arc::new(Mutex::new(Vec::new()));
    serve(listener, reports.clone());

    let plane = Plane::local(Arc::new(ShellSource) as Arc<dyn SessionSource>)
        .expect("a grant over the machine the shell publishes");
    let card = plane
        .open(&OpenRequest {
            host_id: Some("h_lab01".to_string()),
            ..OpenRequest::default()
        })
        .expect("the shell has this machine open at slot 0");
    let limb = plane
        .resolve(&Selector {
            limb_id: Some(card.limb_id.clone()),
            ..Selector::default()
        })
        .expect("the limb that was just opened");
    let _ = plane.acquire(&limb, None, None).await;

    plane
        .submit(
            &limb,
            IntentKind::SendBytes {
                bytes: dvv::into_bytes(b"ls\n".to_vec()),
            },
            None,
        )
        .await
        .expect("bytes to a terminal need no fence");

    // The relay reports on its own thread; give it a moment to drain.
    let mut last = Vec::new();
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let seen = reports.lock().unwrap().clone();
        if seen.iter().any(|r| r.iter().any(|n| n == "terminal-input")) {
            last = seen.last().cloned().unwrap_or_default();
            if last.is_empty() {
                break;
            }
        }
    }
    let seen = reports.lock().unwrap().clone();
    assert!(
        seen.iter().any(|r| r.iter().any(|n| n == "terminal-input")),
        "the command was reported as it went: {seen:?}"
    );
    assert!(
        last.is_empty(),
        "the pane still shows {last:?} in flight after the command was carried: {seen:?}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
