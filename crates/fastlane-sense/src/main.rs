//! deskvnc-sense: the controls on this computer's screen, as a numbered table.
//!
//! The fast lane decides with a small decision model that reads text, not
//! pixels, so it needs what a person sees as a list: each button, field, menu
//! item and link with its name, value and rectangle. Windows has that list
//! already, in UI Automation, and reading it takes tens of milliseconds where
//! looking at a screenshot takes a large model seconds.
//!
//! Two calls, over HTTP on the LAN, each needing the bearer token:
//!
//! * `GET /snapshot` reads the foreground window and the taskbar now.
//! * `GET /settle?after=<hash>` reads again and again until the table differs
//!   from `after` and then reads the same twice running, so a caller waits
//!   exactly as long as the screen keeps changing and no longer. It returns
//!   early, saying so, when nothing changed within `change_ms` (1000 by
//!   default), and gives up at `max_ms` (5000).
//!
//! Started with the token in `DESKVNC_SENSE_TOKEN` and an optional
//! `--listen host:port` (`0.0.0.0:5942` by default). With `--connect
//! host:port` it dials the controller instead and answers over that one
//! connection, one JSON line per request (`{"op":"snapshot"}` or
//! `{"op":"settle","after":"<hash>"}`), after sending the token as its first
//! line. Dialling out needs no inbound firewall rule, so Windows asks nobody
//! anything, and it saves a TCP handshake on every read. It runs as the signed in
//! user, in their session, because UI Automation only sees the desktop of the
//! session it runs in.

// No console window: it runs in the background of somebody's desktop.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

#[cfg(windows)]
mod uia;

#[cfg(not(windows))]
mod uia {
    //! Only Windows for now; the macOS accessibility tree comes next.
    pub struct Sense;
    impl Sense {
        pub fn new() -> Result<Sense, String> {
            Err("deskvnc-sense reads UI Automation, which only Windows has".into())
        }
        pub fn snapshot(&mut self) -> Result<super::Table, String> {
            Err("unsupported".into())
        }
        pub fn cells(&mut self, _names: &[String]) -> Result<serde_json::Value, String> {
            Err("unsupported".into())
        }
    }
}

/// One read of the screen.
pub struct Table {
    pub hash: u64,
    pub body: Value,
}

/// FNV-1a, enough to tell two tables apart.
pub fn fnv(text: &str) -> u64 {
    text.bytes()
        .fold(0xcbf29ce484222325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100000001b3))
}

fn main() {
    let token = std::env::var("DESKVNC_SENSE_TOKEN").unwrap_or_default();
    if token.len() < 16 {
        eprintln!("set DESKVNC_SENSE_TOKEN to a secret of at least 16 characters");
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().collect();
    let listen = args
        .iter()
        .position(|a| a == "--listen")
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| "0.0.0.0:5942".into());
    let mut sense = match uia::Sense::new() {
        Ok(sense) => sense,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if let Some(controller) = args
        .iter()
        .position(|a| a == "--connect")
        .and_then(|i| args.get(i + 1).cloned())
    {
        loop {
            match TcpStream::connect(&controller) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    if let Err(e) = answer(stream, &token, &mut sense) {
                        eprintln!("controller connection ended: {e}");
                    }
                }
                Err(e) => eprintln!("cannot reach {controller}: {e}"),
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("cannot listen on {listen}: {e}");
        std::process::exit(1);
    });
    eprintln!("deskvnc-sense listening on {listen}");
    // One request at a time, on this thread: UI Automation's objects belong
    // to the thread that made them, and a caller never needs two reads at once.
    for stream in listener.incoming().flatten() {
        let _ = stream.set_nodelay(true);
        if let Err(e) = serve(stream, &token, &mut sense) {
            eprintln!("request failed: {e}");
        }
    }
}

fn serve(stream: TcpStream, token: &str, sense: &mut uia::Sense) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let target = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    let mut authorised = false;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("authorization")
                && value.trim().strip_prefix("Bearer ").is_some_and(|t| t == token)
            {
                authorised = true;
            }
        }
    }
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let param = |key: &str| {
        query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    };
    let (status, body) = if !authorised {
        (401, json!({ "error": "missing or wrong bearer token" }))
    } else {
        match path {
            "/snapshot" => {
                let started = Instant::now();
                match sense.snapshot() {
                    Ok(table) => (200, stamp(table, started, json!({}))),
                    Err(e) => (500, json!({ "error": e })),
                }
            }
            "/settle" => {
                let after = param("after").and_then(|h| h.parse::<u64>().ok());
                let change = param("change_ms").and_then(|v| v.parse().ok()).unwrap_or(1000);
                let max = param("max_ms").and_then(|v| v.parse().ok()).unwrap_or(5000);
                match settle(sense, after, change, max) {
                    Ok(body) => (200, body),
                    Err(e) => (500, json!({ "error": e })),
                }
            }
            _ => (404, json!({ "error": "GET /snapshot or /settle" })),
        }
    };
    let text = body.to_string();
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    )?;
    out.flush()
}

/// The dial out mode: the token, then one JSON line answered per line read.
fn answer(stream: TcpStream, token: &str, sense: &mut uia::Sense) -> std::io::Result<()> {
    let mut out = stream.try_clone()?;
    writeln!(out, "{}", json!({ "hello": "deskvnc-sense", "token": token }))?;
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let request: Value = serde_json::from_str(&line?).unwrap_or(Value::Null);
        let number = |key: &str, default: u64| request[key].as_u64().unwrap_or(default);
        let started = Instant::now();
        let body = match request["op"].as_str() {
            Some("snapshot") => sense
                .snapshot()
                .map(|t| stamp(t, started, json!({})))
                .unwrap_or_else(|e| json!({ "error": e })),
            Some("settle") => {
                let after = request["after"].as_str().and_then(|h| h.parse().ok());
                settle(sense, after, number("change_ms", 1000), number("max_ms", 5000))
                    .unwrap_or_else(|e| json!({ "error": e }))
            }
            Some("cells") => {
                let names: Vec<String> = request["names"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|n| n.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                sense.cells(&names).unwrap_or_else(|e| json!({ "error": e }))
            }
            _ => json!({ "error": "op is snapshot, settle or cells" }),
        };
        writeln!(out, "{body}")?;
    }
    Ok(())
}

fn stamp(table: Table, started: Instant, extra: Value) -> Value {
    let mut body = table.body;
    body["hash"] = json!(table.hash.to_string());
    body["read_ms"] = json!(started.elapsed().as_millis() as u64);
    if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            body.insert(k.clone(), v.clone());
        }
    }
    body
}

/// Read until the table has changed and then held still for one more read.
///
/// No sleeps: the pace is the read itself, so on a quick window this answers
/// within two reads of the screen going still, and a slow one gets as long as
/// it keeps changing, up to `max_ms`.
fn settle(sense: &mut uia::Sense, after: Option<u64>, change_ms: u64, max_ms: u64) -> Result<Value, String> {
    let started = Instant::now();
    let mut reads = 0u32;
    let mut changed_at: Option<u128> = None;
    let mut last = sense.snapshot()?;
    reads += 1;
    loop {
        let elapsed = started.elapsed().as_millis();
        if changed_at.is_none() && after.is_none_or(|h| h != last.hash) {
            changed_at = Some(elapsed);
        }
        let outcome = if changed_at.is_none() && elapsed >= u128::from(change_ms) {
            Some("unchanged")
        } else if elapsed >= u128::from(max_ms) {
            Some("still-changing")
        } else {
            None
        };
        if let Some(outcome) = outcome {
            return Ok(stamp(last, started, json!({ "outcome": outcome, "reads": reads })));
        }
        let next = sense.snapshot()?;
        reads += 1;
        if changed_at.is_some() && next.hash == last.hash {
            return Ok(stamp(
                next,
                started,
                json!({ "outcome": "settled", "reads": reads, "changed_ms": changed_at }),
            ));
        }
        last = next;
    }
}
