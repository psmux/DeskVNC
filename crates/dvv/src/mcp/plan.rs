//! `dvv_plan`: a whole plan of steps in one call.
//!
//! An agent that drives a desktop one tool call at a time pays a turn of its
//! own model per click, seconds each. Here it writes the steps once and the
//! fast lane runner (`fastlane-plan`, rules in `tools/fastlane/spec`) carries
//! them out with no model in the loop, finding each control by name in the
//! table deskvnc-sense reads on that machine.
//!
//! The sense is a separate program on the remote computer. It reads the
//! controls through the operating system's accessibility interface, which the
//! remote desktop protocol has no way to carry, and dials in to this server
//! with a shared token. Without it there is no table, and this tool says so
//! rather than guessing from pixels. The window title and controls it reports
//! come from the machine itself; they are remote content like a screenshot,
//! and nothing in them is invented by this server.
//!
//! The sense listener starts on the first `dvv_plan` call, on
//! `DESKVNC_SENSE_LISTEN` (`0.0.0.0:5942` by default), and accepts a sense only
//! when its first line carries `DESKVNC_SENSE_TOKEN`. With no token set the
//! tool refuses: an open port that anyone on the network could feed a fake
//! screen to is worse than no tool.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fastlane_plan::{Desk, Runner, Step, Table};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::error::ToolError;

/// The code for a plan with no sense to read the screen.
pub const SENSE_ABSENT: &str = "SENSE_ABSENT";

/// How long a plan waits for a sense to dial in. The sense retries every two
/// seconds, so a running one arrives within that.
const ARRIVE_MS: u64 = 5000;

/// How long one sense request may take. A settle is bounded by its own
/// `max_ms`, so this only catches a sense that stopped answering.
const ANSWER_MS: u64 = 15_000;

/// One sense, one request at a time.
pub struct SenseLine {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl SenseLine {
    async fn ask(&mut self, request: Value) -> Result<Value, String> {
        let mut line = request.to_string();
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("the sense went away: {e}"))?;
        let mut answer = String::new();
        let read = tokio::time::timeout(
            Duration::from_millis(ANSWER_MS),
            self.reader.read_line(&mut answer),
        )
        .await;
        match read {
            Ok(Ok(n)) if n > 0 => {}
            Ok(Ok(_)) => return Err("the sense closed the connection".into()),
            Ok(Err(e)) => return Err(format!("the sense went away: {e}")),
            Err(_) => return Err(format!("the sense did not answer within {ANSWER_MS} ms")),
        }
        let value: Value = serde_json::from_str(&answer)
            .map_err(|e| format!("the sense sent something unreadable: {e}"))?;
        match value.get("error").and_then(Value::as_str) {
            Some(e) => Err(format!("the sense could not read the screen: {e}")),
            None => Ok(value),
        }
    }

    async fn table(&mut self, request: Value) -> Result<Table, String> {
        let value = self.ask(request).await?;
        serde_json::from_value(value)
            .map_err(|e| format!("the sense sent a table this runner cannot read: {e}"))
    }
}

/// The senses that have dialled in, by address.
#[derive(Default)]
pub struct Senses {
    listening: Mutex<bool>,
    lines: Mutex<HashMap<IpAddr, Arc<Mutex<SenseLine>>>>,
}

impl Senses {
    /// Start listening, once.
    async fn listen(self: &Arc<Self>) -> Result<(), ToolError> {
        let mut listening = self.listening.lock().await;
        if *listening {
            return Ok(());
        }
        let token = token()?;
        let address =
            std::env::var("DESKVNC_SENSE_LISTEN").unwrap_or_else(|_| "0.0.0.0:5942".into());
        let listener = TcpListener::bind(&address).await.map_err(|e| {
            ToolError::new(SENSE_ABSENT, format!("cannot listen for deskvnc-sense on {address}: {e}. Another dvv may hold the port; set DESKVNC_SENSE_LISTEN to another one and start the sense with --connect pointing at it."))
        })?;
        *listening = true;
        let senses = Arc::clone(self);
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let senses = Arc::clone(&senses);
                let token = token.clone();
                tokio::spawn(async move {
                    if let Some(line) = greet(stream, &token).await {
                        senses
                            .lines
                            .lock()
                            .await
                            .insert(peer.ip(), Arc::new(Mutex::new(line)));
                    }
                });
            }
        });
        Ok(())
    }

    /// The sense on the machine at `host`, or the only one when there is one.
    async fn line_for(self: &Arc<Self>, host: &str) -> Result<Arc<Mutex<SenseLine>>, ToolError> {
        self.listen().await?;
        let host_ip: Option<IpAddr> = host
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip())
            .ok()
            .or_else(|| {
                host.rsplit_once(':')
                    .map_or(host, |(h, _)| h)
                    .trim_matches(['[', ']'])
                    .parse()
                    .ok()
            });
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ARRIVE_MS);
        loop {
            {
                let lines = self.lines.lock().await;
                if let Some(line) = host_ip.and_then(|ip| lines.get(&ip)) {
                    return Ok(Arc::clone(line));
                }
                if lines.len() == 1 {
                    return Ok(Arc::clone(lines.values().next().unwrap()));
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ToolError::new(
                    SENSE_ABSENT,
                    format!("no deskvnc-sense has dialled in from {host}. dvv_plan reads the screen through deskvnc-sense on that machine; without it, drive the machine with dvv_key, dvv_type and dvv_click instead."),
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Forget a sense whose connection broke, so the next plan waits for it
    /// to dial in again.
    async fn drop_line(&self, line: &Arc<Mutex<SenseLine>>) {
        self.lines.lock().await.retain(|_, l| !Arc::ptr_eq(l, line));
    }
}

fn token() -> Result<String, ToolError> {
    match std::env::var("DESKVNC_SENSE_TOKEN") {
        Ok(token) if token.len() >= 16 => Ok(token),
        _ => Err(ToolError::new(
            SENSE_ABSENT,
            "DESKVNC_SENSE_TOKEN is not set for this dvv (it must be a secret of at least 16 characters, the same one the sense was started with). dvv_plan will not listen for a sense without it.",
        )),
    }
}

/// The sense's first line must carry the token.
async fn greet(stream: TcpStream, token: &str) -> Option<SenseLine> {
    let _ = stream.set_nodelay(true);
    let (read, writer) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut hello = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut hello))
        .await
        .ok()?
        .ok()?;
    let hello: Value = serde_json::from_str(&hello).ok()?;
    let sent = hello.get("token")?.as_str()?;
    use subtle::ConstantTimeEq;
    if !bool::from(sent.as_bytes().ct_eq(token.as_bytes())) {
        return None;
    }
    Some(SenseLine { reader, writer })
}

/// A boxed tool call, so a plan can call the server it runs inside.
pub type Call<'a> = Box<
    dyn Fn(&'static str, Value) -> Pin<Box<dyn Future<Output = Value> + Send + 'a>>
        + Send
        + Sync
        + 'a,
>;

/// The desk a plan runs on: the sense for eyes, dvv's own tools for hands.
struct DvvDesk<'a> {
    sense: Arc<Mutex<SenseLine>>,
    call: Call<'a>,
    limb: String,
}

impl DvvDesk<'_> {
    /// One tool call on this limb, its text when it was refused.
    async fn act(&self, name: &'static str, mut args: Value) -> Result<(), (String, String)> {
        args["limbId"] = json!(self.limb);
        let result = (self.call)(name, args).await;
        if result["isError"] == json!(true) {
            let code = result["structuredContent"]["code"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let message = result["structuredContent"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            return Err((code, message));
        }
        Ok(())
    }

    /// DeskVNC refuses keys and text after a large repaint until the screen
    /// has been read. The table is this runner's check, so it reads the
    /// cheapest picture there is and carries on.
    async fn fence(&self) {
        let _ = self.act("dvv_screen", json!({ "scale": 0.1 })).await;
    }
}

impl Desk for DvvDesk<'_> {
    async fn snapshot(&mut self) -> Result<Table, String> {
        self.sense
            .lock()
            .await
            .table(json!({ "op": "snapshot" }))
            .await
    }

    async fn settle(&mut self, after: &str, change_ms: u64, max_ms: u64) -> Result<Table, String> {
        self.sense
            .lock()
            .await
            .table(
                json!({ "op": "settle", "after": after, "change_ms": change_ms, "max_ms": max_ms }),
            )
            .await
    }

    async fn key(&mut self, keys: &str) -> Result<(), String> {
        for _ in 0..5 {
            match self.act("dvv_key", json!({ "keys": keys })).await {
                Ok(()) => return Ok(()),
                Err((code, _)) if code == crate::error::codes::SCREEN_CHANGED => self.fence().await,
                Err((code, message)) => return Err(format!("{code}: {message}")),
            }
        }
        Err(format!("the screen kept changing while pressing {keys}"))
    }

    async fn type_text(&mut self, text: &str) -> Result<(), String> {
        // A repaint while typing is usually the field's own suggestion list:
        // go on from the character DeskVNC stopped at.
        let mut rest: String = text.to_string();
        for _ in 0..20 {
            match self
                .act("dvv_type", json!({ "text": rest, "wpm": 1200 }))
                .await
            {
                Ok(()) => return Ok(()),
                Err((code, message)) if code == crate::error::codes::SCREEN_CHANGED => {
                    let sent = message
                        .strip_prefix("typed ")
                        .and_then(|m| m.split(' ').next())
                        .and_then(|n| n.parse::<usize>().ok())
                        .unwrap_or(0);
                    rest = rest.chars().skip(sent).collect();
                    self.fence().await;
                }
                Err((code, message)) => return Err(format!("{code}: {message}")),
            }
        }
        Err("the screen kept changing while typing".into())
    }

    async fn click(&mut self, x: i64, y: i64) -> Result<(), String> {
        self.act("dvv_click", json!({ "action": "click", "x": x, "y": y }))
            .await
            .map_err(|(code, message)| format!("{code}: {message}"))
    }

    async fn pause(&mut self, ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}

/// Run a plan on one limb. The steps are checked before anything is done.
pub async fn run(
    senses: &Arc<Senses>,
    limb: &str,
    host: &str,
    steps: &Value,
    call: Call<'_>,
) -> Result<Value, ToolError> {
    let steps: Vec<Step> = steps
        .as_array()
        .ok_or_else(|| {
            ToolError::new(
                crate::error::codes::BAD_REQUEST,
                "steps must be an array of steps",
            )
        })?
        .iter()
        .map(|s| Step::parse(s).map_err(|e| ToolError::new(crate::error::codes::BAD_REQUEST, e)))
        .collect::<Result<_, _>>()?;
    let sense = senses.line_for(host).await?;
    let desk = DvvDesk {
        sense: Arc::clone(&sense),
        call,
        limb: limb.to_string(),
    };
    let runner = match Runner::new(desk).await {
        Ok(runner) => runner,
        Err(e) => {
            senses.drop_line(&sense).await;
            return Err(ToolError::new(SENSE_ABSENT, e));
        }
    };
    let outcome = runner.run(&steps).await;
    if outcome
        .failed
        .as_ref()
        .and_then(|f| f.get("error"))
        .and_then(Value::as_str)
        .is_some_and(|e| e.starts_with("the sense"))
    {
        senses.drop_line(&sense).await;
    }
    Ok(outcome.to_json())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn dial(hello: Value) -> Option<SenseLine> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sense = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream
                .write_all(format!("{hello}\n").as_bytes())
                .await
                .unwrap();
            let mut reader = BufReader::new(stream);
            let mut request = String::new();
            reader.read_line(&mut request).await.unwrap();
            let table = json!({"hash": "7", "window": {"title": "Run"}, "elements": [{"i": 1, "area": "window", "role": "button", "name": "OK", "x": 0, "y": 0, "w": 10, "h": 10}]});
            reader
                .get_mut()
                .write_all(format!("{table}\n").as_bytes())
                .await
                .unwrap();
        });
        let (stream, _) = listener.accept().await.unwrap();
        let line = greet(stream, "a secret of sixteen").await;
        if line.is_none() {
            sense.abort();
        }
        line
    }

    #[tokio::test]
    async fn a_sense_with_the_token_is_read_and_one_without_is_turned_away() {
        let mut line = dial(json!({"hello": "deskvnc-sense", "token": "a secret of sixteen"}))
            .await
            .expect("accepted");
        let table = line.table(json!({"op": "snapshot"})).await.unwrap();
        assert_eq!(table.window.title, "Run");
        assert_eq!(table.elements[0].name, "OK");
        assert!(
            dial(json!({"hello": "deskvnc-sense", "token": "a secret of sixteeN"}))
                .await
                .is_none()
        );
        assert!(dial(json!({"hello": "deskvnc-sense"})).await.is_none());
    }
}
