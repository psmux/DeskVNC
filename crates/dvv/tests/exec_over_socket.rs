//! `dvv run`, end to end over a real `dvvp.v1` unix socket.
//!
//! ## Why this test has a server in it, when the others must not
//!
//! `tests/common/mod.rs` says there is no server anywhere in those tests and
//! there must not be one, and it is right: what they prove is the plane's own
//! behaviour, and a server between the assertion and the thing asserted only
//! adds ways for the test to be wrong.
//!
//! This one proves the opposite thing. `00 R51b` gave a driver a way to say it
//! SERVED an intent, and the question here is whether that answer survives the
//! trip: through `agent-plane`'s dispatch, into the session's command channel,
//! down [`dvv::plane::ShellSource`]'s relay thread, across the envelope, and
//! back as the reply the dispatch is blocked on. Every one of those hops is the
//! thing that was missing, so a test that mocked any of them would be proving
//! the hop it did not mock.
//!
//! So the far side here is a real `UnixListener` speaking the real envelope,
//! standing in for `src-tauri/src/agent/server.rs`. What it is NOT is a second
//! implementation of the plane: it answers six methods with fixed objects and
//! decides nothing.
//!
//! ## One test function, deliberately
//!
//! [`dvv::plane::ShellSource`] holds one process global connection, on purpose
//! (`04 §2.1`: one `hello`, one attachment id, one line naming who attached),
//! and this file sets `HOME` so that `socket_path()` lands in a temporary
//! directory. Both are process wide, so the whole conversation is one test.

#![cfg(unix)]

use dvv::plane::{OpenRequest, Plane, Selector, SessionSource, ShellSource};
use limb_core::intent::IntentKind;
use remote_core::intent::CommandSpec;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

/// The control lane (`04 §2.2`). Nothing else is sent or expected here.
const MSG_JSONRPC: u8 = 0;

/// What the far side ran, and what it answered.
///
/// Held so the assertions can be about the request the plane actually made
/// rather than about what a mock said it would.
#[derive(Default)]
struct Heard {
    commands: Vec<String>,
    timeouts: Vec<u64>,
    /// Every field name that arrived on an exec. Asserted against, because the
    /// interesting claim is which fields are ABSENT (D7).
    exec_fields: Vec<String>,
}

fn read_message(stream: &mut UnixStream) -> Option<Value> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).ok()?;
    assert_eq!(header[0], MSG_JSONRPC, "this build sends one lane");
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

/// A machine that is connected, at slot 0, as `limb.attach` reports one.
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

/// The far side, standing in for `src-tauri/src/agent/server.rs`.
///
/// Answers six methods with fixed objects and decides nothing. The one place
/// it does any work is `limb.exec`, where it answers the command by name so
/// the test can ask for an exit 0 and an exit 3 on the same connection.
fn serve(listener: UnixListener, heard: Arc<std::sync::Mutex<Heard>>) {
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
                        "terminal.read", "terminal.write", "exec",
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
                "limb.attach" => attached(),
                "limb.status" => attached(),
                "control.report" => json!({ "recorded": true }),
                // The release a lease change owes the limb (`00 R11`): a zero
                // mask pointer and every key up, put on the wire by `acquire`
                // before the wheel changes hands.
                "limb.command" => json!({ "delivered": true }),
                "limb.exec" => {
                    let command = params["command"].as_str().unwrap_or_default().to_string();
                    {
                        let mut heard = heard.lock().expect("not poisoned");
                        heard.commands.push(command.clone());
                        heard
                            .timeouts
                            .push(params["timeoutMs"].as_u64().unwrap_or_default());
                        if let Some(object) = params.as_object() {
                            heard.exec_fields = object.keys().cloned().collect();
                        }
                    }
                    exec_answer(&command)
                }
                other => panic!("this stand in was not asked for {other}"),
            };
            write_message(
                &mut stream,
                &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            );
        }
    });
}

/// The three answers this test needs, by the command that asked for them.
fn exec_answer(command: &str) -> Value {
    let base64 = |text: &str| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(text)
    };
    let dropped = json!({
        "cap": 65536,
        "stdout": { "bytes": 0, "lines": 0 },
        "stderr": { "bytes": 0, "lines": 0 },
        "any": false,
    });
    match command {
        "false" => json!({
            "served": true,
            "timedOut": false,
            "status": {
                "code": 3, "signal": Value::Null, "source": "exec", "unanswered": Value::Null,
            },
            "stdoutBase64": "",
            "stderrBase64": "",
            "durationMs": 4,
            "dropped": dropped,
        }),
        "sleep 60" => json!({
            "served": false,
            "timedOut": true,
            "status": {
                "code": Value::Null,
                "signal": Value::Null,
                "source": "exec",
                "unanswered": "deadline",
            },
            "stdoutBase64": base64("half a line before the deadline\n"),
            "stderrBase64": "",
            "durationMs": 1000,
            "dropped": dropped,
        }),
        _ => json!({
            "served": true,
            "timedOut": false,
            "status": {
                "code": 0, "signal": Value::Null, "source": "exec", "unanswered": Value::Null,
            },
            "stdoutBase64": base64("Linux lab01\n"),
            "stderrBase64": "",
            "durationMs": 12,
            "dropped": dropped,
        }),
    }
}

fn spec(command: &str, timeout_ms: u64) -> CommandSpec {
    CommandSpec {
        command: command.to_string(),
        cwd: None,
        env: Vec::new(),
        timeout: Duration::from_millis(timeout_ms),
        stdin: None,
        max_output_bytes: Some(65536),
    }
}

/// One word for a settlement, as `dvv` already spells one.
fn outcome(settlement: &agent_plane::Settlement) -> &'static str {
    dvv::plane::outcome_word(&settlement.outcome)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exec_crosses_the_socket_and_the_answer_comes_back() {
    // A temporary HOME, so `socket_path()` lands somewhere this test owns.
    // Process wide, which is why this file has one test function in it.
    //
    // `/tmp` rather than `std::env::temp_dir()`, and that is not laziness: a
    // unix socket path is capped at `SUN_LEN`, 104 bytes, and macOS answers
    // `/var/folders/…/T/` for the temporary directory, which leaves nothing for
    // the "Library/Application Support/DeskVNCViewer/agent.sock" the real path
    // appends. The bind fails with `path must be shorter than SUN_LEN`.
    let home = std::path::PathBuf::from(format!("/tmp/dvv-exec-{}", std::process::id()));
    std::env::set_var("HOME", &home);
    std::env::remove_var("XDG_RUNTIME_DIR");
    let socket = std::path::PathBuf::from(dvv::cli::socket_path());
    std::fs::create_dir_all(socket.parent().expect("a directory")).expect("a directory to bind in");
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("nothing else is bound here");
    let heard = Arc::new(std::sync::Mutex::new(Heard::default()));
    serve(listener, heard.clone());

    let plane = Plane::local(Arc::new(ShellSource) as Arc<dyn SessionSource>)
        .expect("a grant over the machine the shell publishes");
    // `exec` is in no role bundle (`00 R19`), so its presence here is a grant
    // naming the string and not a bundle quietly widening.
    assert!(
        plane
            .grant()
            .capabilities()
            .allows(limb_core::capability::Capability::Exec),
        "the grant names exec"
    );

    let card = plane
        .open(&OpenRequest {
            host_id: Some("h_lab01".to_string()),
            ..OpenRequest::default()
        })
        .expect("the shell has this machine open at slot 0");
    assert_eq!(card.host, "10.0.0.5");
    assert!(
        card.offers.iter().any(|c| c == "exec"),
        "a terminal limb offers exec now: {:?}",
        card.offers
    );
    assert!(
        card.allows.iter().any(|c| c == "exec"),
        "and this grant is allowed it: {:?}",
        card.allows
    );

    let limb = plane
        .resolve(&Selector {
            limb_id: Some(card.limb_id.clone()),
            ..Selector::default()
        })
        .expect("the limb that was just opened");
    // `exec` needs the control lease (`02 §2.4`'s L column), the same as a
    // click does, and nothing about this path is a way around that.
    let control = plane
        .acquire(&limb, None, false)
        .await
        .expect("nobody else holds this limb");
    assert!(control.held, "the wheel is this attachment's");

    // 1. The far side's own exit code, through the socket, as the answer to
    //    the intent. This is `00 R51b` end to end.
    let settled = plane
        .submit(
            &limb,
            IntentKind::Exec {
                spec: spec("uname -a", 5000),
            },
            None,
        )
        .await
        .expect("an exec needs no geometry fence");
    assert_eq!(outcome(&settled), "delivered", "{:?}", settled.outcome);
    let (status, stdout) = ran_observation(&settled);
    assert_eq!(status.code, Some(0));
    assert_eq!(
        status.source,
        limb_core::observation::ExitSource::Exec,
        "the provenance travels with the number (05 §3)"
    );
    assert!(
        stdout.contains("Linux lab01"),
        "the remote's own output came back: {stdout}"
    );

    // 2. A non zero exit is a STATUS and not a failure to run. `06 §5.4` is
    //    blunt that neither field is called success, and this is the case that
    //    proves the plane agrees: the settlement is done, and the number is
    //    the news.
    let settled = plane
        .submit(
            &limb,
            IntentKind::Exec {
                spec: spec("false", 5000),
            },
            None,
        )
        .await
        .expect("a failing command is still a dispatched intent");
    assert_eq!(
        outcome(&settled),
        "delivered",
        "a command that exited 3 ran: {:?}",
        settled.outcome
    );
    assert_eq!(ran_observation(&settled).0.code, Some(3));

    // 3. A timeout is a timeout, carrying whatever output did arrive, and
    //    NOTHING invents an exit code for it (`00 R7`, `05 §3`).
    let settled = plane
        .submit(
            &limb,
            IntentKind::Exec {
                spec: spec("sleep 60", 1000),
            },
            None,
        )
        .await
        .expect("a timeout is an ordinary result");
    assert_eq!(outcome(&settled), "timed-out", "{:?}", settled.outcome);
    let (status, stdout) = ran_observation(&settled);
    assert_eq!(status.code, None, "nothing invents an exit code");
    assert_eq!(status.signal, None, "and nothing invents a signal");
    assert!(
        stdout.contains("half a line"),
        "the bytes that did arrive are still the agent's output: {stdout}"
    );

    // …and the requests that crossed the socket carried the command and its
    // timeout, and no field that could have been a secret (D7).
    let heard = heard.lock().expect("not poisoned");
    assert_eq!(heard.commands, vec!["uname -a", "false", "sleep 60"]);
    assert_eq!(heard.timeouts, vec![5000, 5000, 1000]);
    for forbidden in ["password", "passphrase", "username", "privateKey"] {
        assert!(
            !heard.exec_fields.iter().any(|f| f == forbidden),
            "an exec carries no {forbidden}: {:?}",
            heard.exec_fields
        );
    }

    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_dir_all(&home);
}

/// The exit status and the stdout of the `ran` observation.
///
/// Cloned and then unwrapped through `into_inner_untrusted`, because that is
/// the only way out and the awkwardness is the design: `AGENT_BRIEF` D6 says
/// remote output is data, so the getter is named to make a reader stop and
/// think about what they are about to do with it.
fn ran_observation(
    settlement: &agent_plane::Settlement,
) -> (limb_core::observation::ExitStatus, String) {
    settlement
        .payload
        .iter()
        .find_map(|observation| match observation.clone() {
            limb_core::observation::Observation::Ran { status, stdout, .. } => Some((
                status,
                String::from_utf8_lossy(&stdout.into_inner_untrusted().bytes).into_owned(),
            )),
            _ => None,
        })
        .expect("every dispatched exec carries a ran observation")
}
