//! The CLI, over the same surface.
//!
//! `04 §7`. `dvv` is one binary: a person uses it to see what is going on, a
//! shell driven agent uses it when it is a loop rather than an MCP client, and
//! `dvv mcp --stdio` is how the MCP server is launched, so there is one thing to
//! install and one thing to sign.
//!
//! ## The rule this file follows, and the reason
//!
//! **One verb, one plane call.** Nothing here composes behaviour the plane does
//! not have, because a composition that exists only in the CLI is a behaviour
//! the MCP server does not get, and then they diverge. This file goes further
//! than the rule requires: every verb is routed through
//! [`crate::mcp::Server::call`], the same function a `tools/call` reaches, so
//! the CLI is not a second client of anything. A bug in a tool is a bug in both
//! and is fixed once.
//!
//! ## `--json` is the contract, the human format is not
//!
//! `04 §7.2`. The human format is for humans and may change between releases.
//! The `--json` output is the plane's own result object, unchanged. A shell
//! driven agent uses `--json` and never parses the human format, which is why
//! every verb takes the flag rather than a chosen few.
//!
//! ## Exit codes are the interface
//!
//! 0 success, 1 a plane error, 2 bad usage, 3 policy denied, 4 lease not held,
//! 5 timed out with nothing settled. `dvv wait` never exits non zero on a
//! timeout: it prints `settled=false` and exits 0, so
//! `until dvv wait box --until idle --json | jq -e .settled; do :; done` is a
//! correct loop rather than a trap.
//!
//! ## No argument parser
//!
//! The manifest has no `clap` and does not need one: this is a verb, some
//! positional arguments and a handful of long flags. `00 R40`'s constraints
//! apply to every dependency the DMG carries, and a parser for this is one of
//! them.

use crate::error::{exit_code_for, ToolError};
use crate::fake::FakeSource;
use crate::jsonrpc::Connection;
use crate::mcp::{manifest, Server};
use crate::plane::{Plane, SessionSource, ShellSource};
use serde_json::{json, Value};
use std::sync::Arc;

/// What every verb was given.
struct Args {
    verb: String,
    positional: Vec<String>,
    flags: std::collections::BTreeMap<String, String>,
    json: bool,
    fake: bool,
}

impl Args {
    fn flag(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(String::as_str)
    }

    fn has(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }

    fn at(&self, index: usize) -> Option<&str> {
        self.positional.get(index).map(String::as_str)
    }
}

/// Parse `argv`, minus the program name.
///
/// Flags are `--name value` or `--name=value`, and a bare `--name` is the empty
/// string, which is how a boolean is spelled. Everything after a bare `--` is
/// positional, which is what makes `dvv run box -- make test` work: the remote
/// command's own flags must not be read as ours.
fn parse(argv: &[String]) -> Args {
    let mut positional = Vec::new();
    let mut flags = std::collections::BTreeMap::new();
    let mut rest_is_positional = false;
    let mut index = 0;
    while index < argv.len() {
        let item = &argv[index];
        if rest_is_positional {
            positional.push(item.clone());
            index += 1;
            continue;
        }
        if item == "--" {
            rest_is_positional = true;
            index += 1;
            continue;
        }
        if let Some(name) = item.strip_prefix("--") {
            if let Some((name, value)) = name.split_once('=') {
                flags.insert(name.to_string(), value.to_string());
                index += 1;
                continue;
            }
            let takes_value = argv
                .get(index + 1)
                .map(|next| !next.starts_with("--"))
                .unwrap_or(false)
                && !matches!(
                    name,
                    "json" | "fake" | "stdio" | "http" | "discovered" | "perceive" | "wait"
                );
            if takes_value {
                flags.insert(name.to_string(), argv[index + 1].clone());
                index += 2;
            } else {
                flags.insert(name.to_string(), String::new());
                index += 1;
            }
            continue;
        }
        positional.push(item.clone());
        index += 1;
    }
    let verb = if positional.is_empty() {
        String::new()
    } else {
        positional.remove(0)
    };
    Args {
        verb,
        positional,
        json: flags.contains_key("json"),
        fake: flags.contains_key("fake"),
        flags,
    }
}

/// Run one invocation and return the process exit code.
pub async fn run(argv: Vec<String>) -> i32 {
    let args = parse(&argv);
    match args.verb.as_str() {
        "" | "help" | "--help" | "-h" => {
            println!("{USAGE}");
            0
        }
        "version" => {
            if args.json {
                println!(
                    "{}",
                    json!({
                        "version": crate::DVV_VERSION,
                        "mcpProtocolVersion": crate::MCP_PROTOCOL_VERSION,
                        "tools": manifest::TOOL_COUNT,
                    })
                );
            } else {
                println!(
                    "dvv {}, MCP {}, {} tools",
                    crate::DVV_VERSION,
                    crate::MCP_PROTOCOL_VERSION,
                    manifest::TOOL_COUNT
                );
            }
            0
        }
        "doctor" => doctor(&args),
        "mcp" => mcp(&args).await,
        "selftest" => selftest(&args).await,
        "watch" => watch(&args).await,
        "stop" => stop(&args).await,
        _ => match tool_call(&args) {
            Ok((tool, arguments)) => {
                let server = match server_for(&args) {
                    Ok(server) => server,
                    Err(error) => return report(&args, &format_error(&error)),
                };
                let result = server.call(&tool, &arguments).await;
                report(&args, &result)
            }
            Err(error) => {
                eprintln!("{}: {}", error.code, error.message);
                eprintln!("{}", error.hint());
                exit_code_for(&error.code)
            }
        },
    }
}

/// Turn a verb into the tool call it is.
///
/// This is the whole of "one verb, one plane call": the mapping is a table and
/// nothing between a verb and a tool does any work.
fn tool_call(args: &Args) -> Result<(String, Value), ToolError> {
    let verb = args.verb.as_str();
    let limb = |index: usize| -> Value {
        match args.at(index) {
            Some(id) => json!(id),
            None => Value::Null,
        }
    };
    let with_limb = |mut object: Value, index: usize| -> Value {
        if let (Some(map), Value::String(id)) = (object.as_object_mut(), limb(index)) {
            map.insert("limbId".to_string(), json!(id));
        }
        object
    };

    Ok(match verb {
        "hosts" => (
            "dvv_hosts".to_string(),
            json!({ "discovered": args.has("discovered") }),
        ),
        "limbs" => ("dvv_limbs".to_string(), json!({})),
        "open" => {
            let target = args.at(0).ok_or_else(|| {
                ToolError::bad_request("dvv open needs a hostId, or an address with --protocol")
            })?;
            let mut object = json!({ "perceive": args.has("perceive") });
            let map = object.as_object_mut().expect("an object");
            if target.contains('.') || target.contains(':') {
                let (address, port) = split_endpoint(target);
                map.insert("address".to_string(), json!(address));
                if let Some(port) = port {
                    map.insert("port".to_string(), json!(port));
                }
            } else {
                map.insert("hostId".to_string(), json!(target));
            }
            if let Some(protocol) = args.flag("protocol") {
                map.insert("protocol".to_string(), json!(protocol));
            }
            if let Some(slot) = args.flag("slot").and_then(|s| s.parse::<u16>().ok()) {
                map.insert("slot".to_string(), json!(slot));
            }
            ("dvv_open".to_string(), object)
        }
        "close" => ("dvv_close".to_string(), json!({ "limbId": limb(0) })),
        "status" => ("dvv_status".to_string(), with_limb(json!({}), 0)),
        "signals" => ("dvv_signals".to_string(), with_limb(json!({}), 0)),
        "control" => {
            let action = args.at(0).ok_or_else(|| {
                ToolError::bad_request(
                    "dvv control needs an action: acquire, release, status, yield or yield_status",
                )
            })?;
            let mut object = json!({ "action": action });
            if let Some(reason) = args.flag("reason") {
                object
                    .as_object_mut()
                    .expect("an object")
                    .insert("reason".to_string(), json!(reason));
            }
            ("dvv_control".to_string(), with_limb(object, 1))
        }
        "click" => {
            let (x, y) = coordinates(args, 1)?;
            let mut object = json!({
                "action": args.flag("action").unwrap_or("click"),
                "x": x,
                "y": y,
            });
            let map = object.as_object_mut().expect("an object");
            if let Some(generation) = args.flag("generation").and_then(|g| g.parse::<u32>().ok()) {
                map.insert("generation".to_string(), json!(generation));
            }
            if let Some(direction) = args.flag("direction") {
                map.insert("direction".to_string(), json!(direction));
            }
            if let Some(clicks) = args.flag("clicks").and_then(|c| c.parse::<u8>().ok()) {
                map.insert("clicks".to_string(), json!(clicks));
            }
            ("dvv_click".to_string(), with_limb(object, 0))
        }
        "type" => {
            let text = args.at(1).ok_or_else(|| {
                ToolError::bad_request("dvv type needs a limbId and the text to type")
            })?;
            (
                "dvv_type".to_string(),
                with_limb(json!({ "text": text }), 0),
            )
        }
        "key" => {
            let keys = args.at(1).ok_or_else(|| {
                ToolError::bad_request("dvv key needs a limbId and a key name or chord")
            })?;
            ("dvv_key".to_string(), with_limb(json!({ "keys": keys }), 0))
        }
        "screen" => {
            let mut object = json!({});
            if let Some(form) = args.flag("form") {
                object
                    .as_object_mut()
                    .expect("an object")
                    .insert("form".to_string(), json!(form));
            }
            ("dvv_screen".to_string(), with_limb(object, 0))
        }
        "wait" => {
            let until = args.flag("until").ok_or_else(|| {
                ToolError::bad_request(
                    "dvv wait needs --until: connected, screen-stable, screen-changed, text, text-gone, idle or exit",
                )
            })?;
            let mut object = json!({ "until": until });
            let map = object.as_object_mut().expect("an object");
            if let Some(text) = args.flag("text") {
                map.insert("text".to_string(), json!(text));
            }
            if let Some(ms) = args.flag("timeout").and_then(|t| t.parse::<u64>().ok()) {
                map.insert("timeoutMs".to_string(), json!(ms));
            }
            if let Some(ms) = args.flag("quiet").and_then(|t| t.parse::<u64>().ok()) {
                map.insert("quietMs".to_string(), json!(ms));
            }
            ("dvv_wait".to_string(), with_limb(object, 0))
        }
        "clip" => {
            let action = args
                .at(0)
                .ok_or_else(|| ToolError::bad_request("dvv clip needs get or set"))?;
            let mut object = json!({ "action": action });
            if let Some(text) = args.at(2) {
                object
                    .as_object_mut()
                    .expect("an object")
                    .insert("text".to_string(), json!(text));
            }
            ("dvv_clipboard".to_string(), with_limb(object, 1))
        }
        "term" => {
            let action = args
                .at(0)
                .ok_or_else(|| ToolError::bad_request("dvv term needs read or send"))?;
            match action {
                "read" => ("dvv_term_read".to_string(), with_limb(json!({}), 1)),
                "send" => {
                    let mut object = json!({});
                    let map = object.as_object_mut().expect("an object");
                    if let Some(hex) = args.flag("hex") {
                        map.insert("bytesHex".to_string(), json!(hex));
                    } else if let Some(text) = args.at(2) {
                        map.insert("text".to_string(), json!(text));
                    }
                    ("dvv_term_send".to_string(), with_limb(object, 1))
                }
                other => {
                    return Err(ToolError::bad_request(format!(
                        "{other:?} is not a term action; it is read or send"
                    )))
                }
            }
        }
        "run" => {
            let command = args.positional[1..].join(" ");
            if command.is_empty() {
                return Err(ToolError::bad_request(
                    "dvv run needs a limbId and a command after --",
                ));
            }
            let timeout = args
                .flag("timeout")
                .and_then(|t| t.parse::<u64>().ok())
                .unwrap_or(30_000);
            (
                "dvv_run".to_string(),
                with_limb(json!({ "command": command, "timeoutMs": timeout }), 0),
            )
        }
        "group" => {
            let action = args.at(0).ok_or_else(|| {
                ToolError::bad_request("dvv group needs open, list, grow, shrink, close or run")
            })?;
            match action {
                "open" => (
                    "dvv_group_open".to_string(),
                    json!({ "hostIds": args.positional[1..], "perceive": args.has("perceive") }),
                ),
                "list" => (
                    "dvv_group_list".to_string(),
                    match args.at(1) {
                        Some(id) => json!({ "groupId": id }),
                        None => json!({}),
                    },
                ),
                "grow" => (
                    "dvv_group_grow".to_string(),
                    json!({ "groupId": args.at(1), "hostIds": args.positional[2..] }),
                ),
                "shrink" => (
                    "dvv_group_shrink".to_string(),
                    json!({
                        "groupId": args.at(1),
                        "n": args.at(2).and_then(|n| n.parse::<u64>().ok()).unwrap_or(1),
                    }),
                ),
                "close" => (
                    "dvv_group_close".to_string(),
                    json!({ "groupId": args.at(1) }),
                ),
                "run" => (
                    "dvv_group_run".to_string(),
                    json!({
                        "groupId": args.at(1),
                        "action": args.flag("action").unwrap_or("status"),
                        "arguments": args.flag("arguments")
                            .and_then(|a| serde_json::from_str::<Value>(a).ok())
                            .unwrap_or_else(|| json!({})),
                    }),
                ),
                other => {
                    return Err(ToolError::bad_request(format!(
                        "{other:?} is not a group action"
                    )))
                }
            }
        }
        other => {
            return Err(ToolError::bad_request(format!(
                "{other:?} is not a verb. Run dvv help"
            )))
        }
    })
}

/// Print a tool result and decide the exit code.
///
/// A wait that timed out exits 0 with `settled=false`, which is the loop
/// property `04 §7.2` asks for and the reason the check is on the payload
/// rather than on the outcome word.
fn report(args: &Args, result: &Value) -> i32 {
    let structured = result
        .get("structuredContent")
        .cloned()
        .unwrap_or(json!({}));
    if args.json {
        println!("{structured}");
    } else if let Some(text) = result["content"][0]["text"].as_str() {
        // Everything ours goes to stdout for a verb a person ran. Remote bytes
        // are inside the wrapper, which is part of the text, so a script that
        // wants only them uses --json and reads the field.
        println!("{text}");
    }
    if result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let code = structured["code"].as_str().unwrap_or("");
        return exit_code_for(code);
    }
    0
}

fn format_error(error: &ToolError) -> Value {
    crate::mcp::format::error(error)
}

/// Speak MCP, over one transport.
///
/// Two, since `00 R52`, and exactly one per process. `--stdio` is what a client
/// that can spawn a subprocess uses and is still the right answer for it: no
/// port, no token, no listener, and the operating system's own process
/// isolation doing the access control. `--http` exists for the clients stdio
/// cannot reach at all, an agent that cannot spawn a subprocess, and it carries
/// the whole of `00 R52`'s security shape with it.
async fn mcp(args: &Args) -> i32 {
    match (args.has("stdio"), args.has("http")) {
        (true, true) => {
            eprintln!(
                "dvv mcp speaks one transport per process. Run --stdio for a client that spawns this binary, or --http for one that cannot, and run two processes if you genuinely want both."
            );
            2
        }
        (true, false) => mcp_stdio(args).await,
        (false, true) => mcp_http(args).await,
        (false, false) => {
            eprintln!(
                "dvv mcp needs --stdio or --http. --stdio is the one to prefer: a client that can spawn this binary needs no port, no token and no listener. --http is for the agents that cannot spawn a subprocess, and it is off unless you ask for it."
            );
            2
        }
    }
}

/// Speak MCP on stdin and stdout.
async fn mcp_stdio(args: &Args) -> i32 {
    let server = match server_for(args) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            return exit_code_for(&error.code);
        }
    };
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let connection = Connection::new(stdin, tokio::io::stdout());
    match server.serve(connection).await {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("the MCP stream ended: {error}");
            1
        }
    }
}

/// Speak MCP over HTTP, on the terms `00 R52` set.
///
/// Everything this prints goes to stderr, including the token, which follows
/// `04 §7.2`'s rule that everything ours is on stderr. It matters more here
/// than elsewhere: a person redirecting stdout to a file must not silently
/// write their bearer token into it.
async fn mcp_http(args: &Args) -> i32 {
    let host = match crate::http::host_from_flag(args.flag("host")) {
        Ok(host) => host,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let port = match args.flag("port") {
        None => crate::http::DEFAULT_PORT,
        Some(text) => match text.trim().parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                eprintln!(
                    "{text:?} is not a port. --port takes a number from 0 to 65535, and 0 asks the operating system for a free one."
                );
                return 2;
            }
        },
    };
    // Refuses rather than starting open, which is `00 R52` term 5.
    let (token, source) = match crate::http::resolve_token(args.flag("token")) {
        Ok(resolved) => resolved,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let allowed_origins = args
        .flag("allow-origin")
        .map(|list| {
            list.split(',')
                .map(|origin| origin.trim().to_string())
                .filter(|origin| !origin.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let server = match server_for(args) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            return exit_code_for(&error.code);
        }
    };

    let config = crate::http::HttpConfig {
        host,
        port,
        token: token.clone(),
        allowed_origins,
    };
    let listener = match crate::http::HttpServer::bind(config).await {
        Ok(listener) => listener,
        Err(error) => {
            // Loud, and non zero (`00 R52` term 6). A listener that could not
            // take its port and said nothing is a client that hangs.
            eprintln!("{error}");
            if error.kind() == std::io::ErrorKind::AddrInUse {
                eprintln!(
                    "Something already holds that port. Pass --port with another number, or --port 0 to let the operating system pick one."
                );
            }
            return 1;
        }
    };
    let url = match listener.url() {
        Ok(url) => url,
        Err(error) => {
            eprintln!("the socket bound but will not name itself: {error}");
            return 1;
        }
    };

    eprintln!("MCP over HTTP, listening on {url}");
    if let Some(warning) = crate::http::exposure_warning(&host) {
        eprintln!("{warning}");
    }
    // The token is printed exactly once, and only when this process minted it.
    // One that came from the environment is not echoed: the whole point of
    // keeping it there is that the value is not on a screen or in a scrollback.
    let header_token = match source {
        crate::http::TokenSource::Generated => {
            eprintln!("bearer token, printed once and stored nowhere: {token}");
            token.as_str()
        }
        crate::http::TokenSource::Flag => {
            eprintln!(
                "bearer token: the one passed to --token. Anything on this machine can read a command line out of ps, so prefer {} for it.",
                crate::http::TOKEN_ENV
            );
            token.as_str()
        }
        crate::http::TokenSource::Environment => {
            eprintln!("bearer token: the one in {}.", crate::http::TOKEN_ENV);
            "$DVV_MCP_TOKEN"
        }
    };
    eprintln!();
    eprintln!("Attach a client with exactly this line:");
    eprintln!();
    eprintln!(
        "  claude mcp add --scope user --transport http deskvnc {url} --header \"Authorization: Bearer {header_token}\""
    );
    eprintln!();

    match listener.serve(Arc::new(server)).await {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("the HTTP listener stopped: {error}");
            1
        }
    }
}

/// A round trip, by hand, printed.
///
/// Drives a real JSON-RPC conversation over an in memory pipe against the fake
/// limb and prints both sides, so a person can see the framing, the manifest and
/// one settled intent without a client, a server or a machine. It is the thing
/// to run first when something looks wrong, because it fails in exactly one
/// place if anything in the adapter is broken.
async fn selftest(args: &Args) -> i32 {
    let source = Arc::new(FakeSource::two_machines());
    let plane = match granted(source.clone() as Arc<dyn SessionSource>) {
        Ok(plane) => plane,
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            return 1;
        }
    };
    let server = Server::new(Arc::new(plane));

    let conversation = vec![
        json!({ "jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": { "_meta": { "protocolVersion": crate::MCP_PROTOCOL_VERSION } } }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "dvv_open", "arguments": { "hostId": "h_lab01", "perceive": true } } }),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "dvv_limbs", "arguments": {} } }),
    ];

    let expected = conversation.len();
    let (client, server_side) = tokio::io::duplex(64 * 1024);
    let (server_read, server_write) = tokio::io::split(server_side);
    let serving = async move {
        let connection = Connection::new(tokio::io::BufReader::new(server_read), server_write);
        let _ = server.serve(connection).await;
    };

    let driving = async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let (read, mut write) = tokio::io::split(client);
        let mut lines = tokio::io::BufReader::new(read).lines();
        let mut replies = Vec::new();
        for message in &conversation {
            let mut line = message.to_string();
            if !args.json {
                println!("-> {line}");
            }
            line.push('\n');
            if write.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            let _ = write.flush().await;
            match lines.next_line().await {
                Ok(Some(reply)) => {
                    if !args.json {
                        println!("<- {reply}");
                    }
                    replies.push(reply);
                }
                _ => break,
            }
        }
        drop(write);
        replies
    };

    let (_, replies) = tokio::join!(serving, driving);
    if args.json {
        println!(
            "{}",
            json!({ "exchanges": replies.len(), "replies": replies })
        );
    }
    if replies.len() == expected {
        0
    } else {
        eprintln!(
            "the round trip stopped after {} of {expected} exchanges",
            replies.len()
        );
        1
    }
}

/// The stop button (`00 R13`).
///
/// **Deliberately not a tool.** `08 §5.2` reserves force release for the
/// shell's own paths and it costs the `admin` capability, which is in no
/// agent's grant: an agent force releasing its own lease is a plain release,
/// and an agent force releasing somebody else's is the thing this whole design
/// exists to prevent. So the revocation is a human affordance, on the CLI, and
/// it is still one plane call.
///
/// It is a REVOCATION AND NOT A REQUEST. There is no grace window, and
/// BrowserGlass's own demo is why: it measures 2,008 ms for a polite handover,
/// which is two seconds of somebody pressing a button labelled stop while
/// nothing happens.
async fn stop(args: &Args) -> i32 {
    let id = match args.at(0) {
        Some(id) => id,
        None => {
            eprintln!("dvv stop needs a limbId. Run dvv limbs.");
            return 2;
        }
    };
    let plane = match plane_for(args) {
        Ok(plane) => plane,
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            return exit_code_for(&error.code);
        }
    };
    let limb = match plane.resolve(&crate::plane::Selector {
        limb_id: Some(id.to_string()),
        ..crate::plane::Selector::default()
    }) {
        Ok(limb) => limb,
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            return exit_code_for(&error.code);
        }
    };
    let report = plane.stop(&limb).await;
    if args.json {
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
    } else {
        println!("{} is revoked. No grace window.", report.limb_id);
        println!("released, in order: {}", report.released.join(" then "));
        println!(
            "{} intent(s) withdrawn. The limb itself is still open: stopping revokes the wheel, it does not close the machine.",
            report.cancelled.len()
        );
    }
    0
}

/// Stream lease changes, intents in flight and settlements across every limb.
///
/// The live view a person keeps while an agent drives, without the GUI. It
/// prints until the input ends or the process is stopped, which is what a person
/// wants from a watch and what a shell agent piping `--json` wants too.
async fn watch(args: &Args) -> i32 {
    // Built here rather than through `plane_for`, because a watcher has to
    // subscribe BEFORE anything opens or it misses the attach it was started to
    // see. That ordering is the whole reason this is three lines rather than
    // one.
    let source: Arc<dyn SessionSource> = if args.fake {
        Arc::new(FakeSource::two_machines())
    } else {
        Arc::new(ShellSource)
    };
    let plane = match granted(source) {
        Ok(plane) => Arc::new(plane),
        Err(error) => {
            eprintln!("{}: {}", error.code, error.message);
            return 1;
        }
    };
    let mut events = plane.subscribe();
    if args.fake {
        // Open the fake machines so there is something to watch. Against a
        // real plane the limbs are already there and this loop does nothing.
        for host in plane.hosts().unwrap_or_default() {
            let _ = plane.open(&crate::plane::OpenRequest {
                host_id: Some(host.host_id),
                perceive: true,
                ..crate::plane::OpenRequest::default()
            });
        }
    }
    if !args.json {
        eprintln!(
            "watching every limb on this plane. Nothing prints until something happens, which on an idle plane is correct rather than broken."
        );
    }
    loop {
        match events.recv().await {
            Ok(event) => {
                if args.json {
                    println!("{}", serde_json::to_string(&event).unwrap_or_default());
                } else {
                    println!("{}", event.human());
                }
            }
            // Never silently. A watcher that fell behind is told how far,
            // because a gap nobody was told about is the failure `00 R24`
            // exists to prevent.
            Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                if args.json {
                    println!("{}", json!({ "type": "lagged", "missed": missed }));
                } else {
                    println!("... {missed} event(s) missed: this watcher fell behind");
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return 0,
        }
    }
}

/// What a person needs to make this work, in one screen.
fn doctor(args: &Args) -> i32 {
    let binary = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "dvv".to_string());
    let socket = socket_path();
    let reachable = std::path::Path::new(&socket).exists();
    let line = format!("claude mcp add --scope user deskvnc -- {binary} mcp --stdio");
    let http = http_report(args);

    if args.json {
        println!(
            "{}",
            json!({
                "version": crate::DVV_VERSION,
                "mcpProtocolVersion": crate::MCP_PROTOCOL_VERSION,
                "tools": manifest::TOOL_COUNT,
                "binary": binary,
                "socket": socket,
                "socketPresent": reachable,
                "source": if args.fake { FakeSource::two_machines().describe() } else { ShellSource.describe() },
                "claudeMcpAdd": line,
                "http": http,
            })
        );
    } else {
        println!("dvv {}", crate::DVV_VERSION);
        println!("MCP protocol      {}", crate::MCP_PROTOCOL_VERSION);
        println!("tools             {}", manifest::TOOL_COUNT);
        println!("binary            {binary}");
        println!("agent socket      {socket}");
        println!(
            "                  {}",
            if reachable {
                "present"
            } else {
                "not present: DeskVNCViewer is not running, or the agent plane is switched off (it is off by default)"
            }
        );
        println!(
            "session source    {}",
            if args.fake {
                FakeSource::two_machines().describe()
            } else {
                ShellSource.describe()
            }
        );
        println!("http listener     off unless asked for: dvv mcp --http");
        println!(
            "http endpoint     {}",
            http["url"].as_str().unwrap_or_default()
        );
        println!(
            "http token        {}",
            if http["tokenSet"].as_bool().unwrap_or(false) {
                format!("set in {}", crate::http::TOKEN_ENV)
            } else {
                format!(
                    "not set in {}: dvv mcp --http mints one and prints it once at startup",
                    crate::http::TOKEN_ENV
                )
            }
        );
        println!();
        println!("Install into Claude Code with exactly this line:");
        println!();
        println!("  {line}");
        println!();
        println!("Or over HTTP, for an agent that cannot spawn a subprocess:");
        println!();
        println!("  {}", http["claudeMcpAdd"].as_str().unwrap_or_default());
        println!();
        println!("Try the surface with no machine anywhere:");
        println!();
        println!("  {binary} selftest");
        println!("  {binary} --fake limbs");
    }
    if reachable {
        0
    } else {
        // Non zero, because `04 §9` acceptance criterion 1 asks for it: on a
        // machine with the application not running, say so and exit non zero.
        1
    }
}

/// What `dvv doctor` says about HTTP, which is never the token.
///
/// Reads the flags a `dvv mcp --http` would read, so the URL printed here is
/// the URL that command would serve on rather than a guess. It cannot report
/// whether a listener is RUNNING, because there is nothing to ask: the
/// transport is stateless and holds no file anywhere. What it reports is what
/// is configured.
fn http_report(args: &Args) -> Value {
    let host = crate::http::host_from_flag(args.flag("host"))
        .unwrap_or_else(|_| crate::http::default_host());
    let port = args
        .flag("port")
        .and_then(|port| port.trim().parse::<u16>().ok())
        .unwrap_or(crate::http::DEFAULT_PORT);
    let url = format!(
        "http://{}{}",
        std::net::SocketAddr::new(host, port),
        crate::http::ENDPOINT
    );
    // The value is tested for emptiness and then dropped. Everything past this
    // line has a bool and could not print the token if it wanted to.
    let token_set = std::env::var(crate::http::TOKEN_ENV)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    http_doctor(&url, token_set)
}

/// The report itself, over a URL and a BOOLEAN.
///
/// The signature is the safety property and not a style choice. People paste
/// `dvv doctor` output into bug reports, so this function is given no token to
/// leak: it is told whether one is set, never what it is, and no amount of
/// editing here can change that without changing the signature.
fn http_doctor(url: &str, token_set: bool) -> Value {
    json!({
        // Off by default, which is `00 R52` term 1 and worth saying in the
        // report rather than only in a header comment.
        "enabled": false,
        "url": url,
        "tokenSet": token_set,
        "tokenEnv": crate::http::TOKEN_ENV,
        "claudeMcpAdd": format!(
            "claude mcp add --scope user --transport http deskvnc {url} --header \"Authorization: Bearer ${}\"",
            crate::http::TOKEN_ENV
        ),
    })
}

/// Where the plane's socket lives (`04 §2.1`).
///
/// The listener `00 R52` added is a second door and not a replacement for this
/// one: stdio over a socket at mode 0600 in a directory the user owns needs no
/// token and no port, so it stays the transport to prefer wherever the client
/// can spawn a subprocess. Between them they cover every attachment `04 §6`
/// works through.
pub fn socket_path() -> String {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/Library/Application Support/DeskVNCViewer/agent.sock")
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            return format!("{runtime}/deskvncviewer/agent.sock");
        }
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.local/share/DeskVNCViewer/agent.sock")
    }
    #[cfg(target_os = "windows")]
    {
        // The pipe carries the user's SID so two users on one machine cannot
        // reach each other's plane, and the ACL grants only the creating user.
        let user = std::env::var("USERNAME").unwrap_or_default();
        format!("\\\\.\\pipe\\deskvncviewer-agent-{user}")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "agent.sock".to_string()
    }
}

fn server_for(args: &Args) -> Result<Server, ToolError> {
    Ok(Server::new(Arc::new(plane_for(args)?)))
}

/// The grant this process runs under. See [`Plane::local`], which is the whole
/// of it and carries the argument for why it is not `04 §5`'s grant.
fn granted(source: Arc<dyn SessionSource>) -> Result<Plane, ToolError> {
    Plane::local(source)
}

/// A plane, with the fake machines already open when the run is a fake one.
///
/// Each CLI invocation is its own process, so a fake plane starts with nothing
/// attached and `dvv --fake limbs` would print an empty list, which
/// demonstrates the framing and nothing else. Against a real plane there is
/// nothing to do here: the limbs are the ones the application already has open,
/// and this binary joins them rather than creating them.
fn plane_for(args: &Args) -> Result<Plane, ToolError> {
    if !args.fake {
        return granted(Arc::new(ShellSource));
    }
    let plane = granted(Arc::new(FakeSource::two_machines()))?;
    for host in plane.hosts().unwrap_or_default() {
        let _ = plane.open(&crate::plane::OpenRequest {
            host_id: Some(host.host_id),
            perceive: true,
            ..crate::plane::OpenRequest::default()
        });
    }
    Ok(plane)
}

fn coordinates(args: &Args, from: usize) -> Result<(u64, u64), ToolError> {
    let x = args.at(from).and_then(|v| v.parse::<u64>().ok());
    let y = args.at(from + 1).and_then(|v| v.parse::<u64>().ok());
    match (x, y) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(ToolError::bad_request(
            "this verb needs x and y in framebuffer pixels; read the size from dvv status first",
        )),
    }
}

fn split_endpoint(target: &str) -> (String, Option<u16>) {
    match target.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(port) => (host.to_string(), Some(port)),
            Err(_) => (target.to_string(), None),
        },
        None => (target.to_string(), None),
    }
}

const USAGE: &str = "\
dvv, the agent plane for DeskVNCViewer.

  dvv mcp --stdio                  speak MCP on stdin and stdout
  dvv mcp --http [--port 7333] [--host 127.0.0.1] [--token T] [--allow-origin O]
                                   speak MCP over HTTP, for an agent that
                                   cannot spawn a subprocess. Off unless asked
                                   for, loopback unless --host says otherwise,
                                   and a bearer token is required on every bind
                                   including loopback: it is printed once at
                                   startup, or read from DVV_MCP_TOKEN.
  dvv selftest                     one full JSON-RPC round trip, printed
  dvv doctor                       what is wired, and the claude mcp add line
  dvv version

  dvv hosts [--discovered]         saved machines, never a secret
  dvv limbs                        every open limb
  dvv open <host|addr[:port]> [--protocol vnc|rdp|ssh] [--slot N] [--perceive]
  dvv close <limbId>
  dvv status <limbId>              the full observation object
  dvv signals <limbId>             which negotiated signals this session has

  dvv control acquire|release|status|yield|yield_status <limbId> [--reason ...]
  dvv stop <limbId>                revoke the wheel: keys released, no grace

  dvv click <limbId> <x> <y> [--action move|click|double|right|middle|drag|scroll]
  dvv type <limbId> \"<text>\"
  dvv key <limbId> ctrl+alt+Delete
  dvv screen <limbId> [--form full|region|damage-crop]
  dvv wait <limbId> --until screen-stable [--quiet 750] [--timeout 8000]

  dvv clip get|set <limbId> [\"<text>\"]
  dvv term read <limbId>
  dvv term send <limbId> \"<text>\" | --hex 03
  dvv run <limbId> -- <command...>

  dvv group open <hostId...>       open several and address them together
  dvv group list|grow|shrink|close|run <groupId> ...

  dvv watch                        lease changes, intents and settlements, live

Flags on everything:
  --json    the plane's own result object, unchanged. This is the contract;
            the human format is for humans and may change between releases.
  --fake    run against a fake limb with no machine behind it, for seeing the
            surface without the application.

Exit codes: 0 success, 1 plane error, 2 bad usage, 3 policy denied,
4 lease not held, 5 timed out with nothing settled. dvv wait NEVER exits non
zero on a timeout: it prints settled=false and exits 0, so a until loop over it
is correct rather than a trap.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_flag_is_a_boolean_and_a_valued_one_takes_the_next_word() {
        let args = parse(&[
            "wait".to_string(),
            "lmb_x".to_string(),
            "--until".to_string(),
            "idle".to_string(),
            "--json".to_string(),
        ]);
        assert_eq!(args.verb, "wait");
        assert_eq!(args.at(0), Some("lmb_x"));
        assert_eq!(args.flag("until"), Some("idle"));
        assert!(args.json);
    }

    #[test]
    fn everything_after_a_bare_separator_is_positional() {
        // The property that makes `dvv run box -- make test --release` work:
        // the remote command's own flags must never be read as ours.
        let args = parse(&[
            "run".to_string(),
            "lmb_x".to_string(),
            "--".to_string(),
            "make".to_string(),
            "--release".to_string(),
        ]);
        assert_eq!(args.positional, vec!["lmb_x", "make", "--release"]);
        assert!(args.flag("release").is_none());
    }

    #[test]
    fn a_verb_maps_to_exactly_one_tool() {
        let args = parse(&[
            "click".to_string(),
            "lmb_x".to_string(),
            "10".to_string(),
            "20".to_string(),
        ]);
        let (tool, arguments) = tool_call(&args).unwrap();
        assert_eq!(tool, "dvv_click");
        assert_eq!(arguments["action"], "click");
        assert_eq!(arguments["x"], 10);
        assert_eq!(arguments["limbId"], "lmb_x");
    }

    #[test]
    fn every_verb_names_a_tool_that_exists() {
        // The failure this guards: a verb wired to a tool name with a typo,
        // which fails only when somebody runs that verb.
        let names = manifest::names();
        for argv in [
            vec!["limbs"],
            vec!["hosts"],
            vec!["status", "lmb_x"],
            vec!["signals", "lmb_x"],
            vec!["close", "lmb_x"],
            vec!["control", "status", "lmb_x"],
            vec!["type", "lmb_x", "hello"],
            vec!["key", "lmb_x", "Enter"],
            vec!["screen", "lmb_x"],
            vec!["clip", "get", "lmb_x"],
            vec!["term", "read", "lmb_x"],
            // `stop` is deliberately absent: it is one plane call and not a
            // tool, because force release costs the admin capability that no
            // agent's grant carries. See `stop` above.
        ] {
            let args = parse(&argv.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            let (tool, _) = tool_call(&args).expect("the verb parses");
            assert!(names.contains(&tool), "{tool} is not in the manifest");
        }
    }

    #[test]
    fn doctor_says_whether_a_token_is_set_and_never_what_it_is() {
        // People paste this output into bug reports. The test is a second line
        // of defence behind `http_doctor`'s signature, which is the first.
        let secret = "0123456789abcdef0123456789abcdef";
        let report = http_doctor("http://127.0.0.1:7333/mcp", true);
        let printed = report.to_string();
        assert_eq!(report["tokenSet"], true);
        assert_eq!(report["enabled"], false);
        assert!(!printed.contains(secret), "{printed}");
        assert!(printed.contains("$DVV_MCP_TOKEN"), "{printed}");
        assert!(report.get("token").is_none(), "{printed}");
    }

    #[test]
    fn the_http_flags_decide_the_url_doctor_prints() {
        let args = parse(&[
            "doctor".to_string(),
            "--port".to_string(),
            "9000".to_string(),
        ]);
        assert_eq!(http_report(&args)["url"], "http://127.0.0.1:9000/mcp");
        let default = parse(&["doctor".to_string()]);
        assert_eq!(http_report(&default)["url"], "http://127.0.0.1:7333/mcp");
    }

    #[test]
    fn http_is_a_boolean_flag_and_does_not_eat_the_next_word() {
        // The failure this guards: `--http` swallowing a following positional
        // and the transport silently not being asked for.
        let args = parse(&[
            "mcp".to_string(),
            "--http".to_string(),
            "--port".to_string(),
            "8080".to_string(),
        ]);
        assert!(args.has("http"));
        assert_eq!(args.flag("http"), Some(""));
        assert_eq!(args.flag("port"), Some("8080"));
    }

    #[test]
    fn the_socket_path_is_under_the_users_own_directory() {
        let path = socket_path();
        assert!(path.contains("agent") || path.contains("pipe"), "{path}");
    }
}
