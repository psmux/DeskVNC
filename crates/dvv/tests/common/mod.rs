//! A plane over the fake source, and a JSON-RPC client that speaks to it over a
//! real pipe.
//!
//! There is no server anywhere in these tests and there must not be one. The
//! whole point of `dvv::fake` is that `SessionHandle` is a plain struct over an
//! `mpsc::Sender`, so a fake session is a channel and a `Vec`, and a test reads
//! exactly what the plane put on the wire, in order.
//!
//! The client below writes and reads newline delimited JSON over
//! `tokio::io::duplex`, which is a real pipe with a real buffer. It does not
//! call `Server::handle` directly, and that is deliberate: a test that skips the
//! framing proves the dispatch table and not the server.

#![allow(dead_code)]

use dvv::fake::FakeSource;
use dvv::jsonrpc::Connection;
use dvv::mcp::Server;
use dvv::plane::{OpenRequest, Plane, SessionSource};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{
    AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf, WriteHalf,
};

/// A plane over two fake machines, one desktop and one terminal.
pub fn fake_plane() -> (Arc<FakeSource>, Arc<Plane>) {
    let source = Arc::new(FakeSource::two_machines());
    let plane = Plane::local(source.clone() as Arc<dyn SessionSource>)
        .expect("a grant over the two machines the source publishes");
    (source, Arc::new(plane))
}

/// Open one of the fake machines and return its limb id.
pub fn open(plane: &Plane, host_id: &str, perceive: bool) -> String {
    plane
        .open(&OpenRequest {
            host_id: Some(host_id.to_string()),
            perceive,
            ..OpenRequest::default()
        })
        .expect("the fake source opens this machine")
        .limb_id
}

/// A JSON-RPC client on one end of a pipe, with the server running on the other.
pub struct Client {
    write: WriteHalf<DuplexStream>,
    lines: Lines<BufReader<ReadHalf<DuplexStream>>>,
    next_id: i64,
    /// Kept so the server task lives as long as the client does.
    _server: tokio::task::JoinHandle<()>,
}

impl Client {
    /// Start a server over this plane and connect to it.
    pub fn connect(plane: Arc<Plane>) -> Client {
        let (client, server_side) = tokio::io::duplex(256 * 1024);
        let (server_read, server_write) = tokio::io::split(server_side);
        let server = tokio::spawn(async move {
            let server = Server::new(plane);
            let connection = Connection::new(BufReader::new(server_read), server_write);
            let _ = server.serve(connection).await;
        });
        let (read, write) = tokio::io::split(client);
        Client {
            write,
            lines: BufReader::new(read).lines(),
            next_id: 0,
            _server: server,
        }
    }

    /// One request, and its reply.
    pub async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let message = json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params,
        });
        let mut line = message.to_string();
        line.push('\n');
        self.write
            .write_all(line.as_bytes())
            .await
            .expect("the pipe accepts a request");
        self.write.flush().await.expect("the pipe flushes");
        let reply = self
            .lines
            .next_line()
            .await
            .expect("the pipe yields a line")
            .expect("the server answered");
        serde_json::from_str(&reply).expect("the reply is JSON")
    }

    /// One tool call, unwrapped to the `CallToolResult`.
    pub async fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let reply = self
            .call(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            )
            .await;
        assert!(
            reply.get("error").is_none(),
            "a tool refusal must be a RESULT with isError, never a protocol error: {reply}"
        );
        reply["result"].clone()
    }

    /// Send a raw line, for the tests that are about the framing itself.
    pub async fn raw(&mut self, line: &str) -> Value {
        let mut line = line.to_string();
        line.push('\n');
        self.write
            .write_all(line.as_bytes())
            .await
            .expect("written");
        self.write.flush().await.expect("flushed");
        let reply = self
            .lines
            .next_line()
            .await
            .expect("a line")
            .expect("an answer");
        serde_json::from_str(&reply).expect("the reply is JSON")
    }
}

/// The `structuredContent` of a tool result.
pub fn structured(result: &Value) -> &Value {
    &result["structuredContent"]
}

/// Whether a tool result is an error, and its code.
pub fn error_code(result: &Value) -> Option<&str> {
    if result.get("isError").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    result["structuredContent"]["code"].as_str()
}
