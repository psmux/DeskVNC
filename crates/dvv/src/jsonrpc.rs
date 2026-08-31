//! JSON-RPC 2.0, framed for stdio, written by hand.
//!
//! ## Why by hand
//!
//! The 2026-07-28 revision of MCP is stateless: no `initialize`, no
//! `initialized`, no `Mcp-Session-Id`. A server on stdio is therefore a framed
//! reader, a dispatch table and a writer, and `04 §1` already rules that MCP is
//! an adapter over the native surface rather than the contract, so an SDK here
//! would be a dependency the DMG has to carry (`00 R40`) for about a hundred
//! lines.
//!
//! ## The framing
//!
//! One JSON message per line, UTF-8, newline terminated, which is what the
//! specification's stdio transport says and what every client that speaks it
//! writes. There is no `Content-Length` header on stdio, so the only thing that
//! can go wrong is a message with a newline inside a string, and
//! `serde_json::to_string` never emits a literal newline: it escapes them. A
//! line longer than [`MAX_LINE`] is refused rather than buffered, because a
//! client that sends an unbounded line is a client that can exhaust this
//! process's memory before anything else notices.
//!
//! ## What is deliberately not here
//!
//! Batching. The 2026-07-28 revision removed JSON-RPC batches, and a server
//! that still accepted them would be accepting a shape no current client
//! sends and every future one will not.

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// The longest line this server will read.
///
/// One megabyte. A `tools/call` carrying a clipboard write is the largest
/// legitimate message and is nowhere near it; anything larger is either a
/// mistake or an attempt to make this process allocate.
pub const MAX_LINE: usize = 1024 * 1024;

/// Parse error.
pub const PARSE_ERROR: i64 = -32700;
/// The request object is not valid.
pub const INVALID_REQUEST: i64 = -32600;
/// The method does not exist. A client probes for a method by calling it and
/// reading this, which is `04 §2.7`'s rule for the native surface and the same
/// one here.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// The parameters are wrong.
pub const INVALID_PARAMS: i64 = -32602;
/// Something went wrong inside the server.
pub const INTERNAL_ERROR: i64 = -32603;

/// One incoming message.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// Absent on a notification, which gets no reply at all. A server that
    /// replied to one would break every client that counts outstanding calls.
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
    /// The `_meta` block. Under 2026-07-28 this is where the protocol version
    /// and the client's capabilities travel, because there is no handshake to
    /// carry them. Read, never required: a client that omits it gets served,
    /// since refusing would make this server stricter than the specification
    /// for no safety gained.
    pub meta: Value,
}

impl Request {
    /// Is this a notification, which gets no reply?
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// The protocol version this request claims, if it said.
    pub fn protocol_version(&self) -> Option<&str> {
        self.meta.get("protocolVersion").and_then(Value::as_str)
    }
}

/// A framed JSON-RPC connection over any pair of streams.
///
/// Generic so that the process runs it over stdin and stdout and a test runs it
/// over an in memory pipe, driving the same code. A test that reimplements the
/// framing is a test that proves the reimplementation.
pub struct Connection<R, W> {
    reader: R,
    writer: W,
    line: String,
}

impl<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin> Connection<R, W> {
    /// A connection over these two.
    pub fn new(reader: R, writer: W) -> Connection<R, W> {
        Connection {
            reader,
            writer,
            line: String::new(),
        }
    }

    /// The next message, or `None` at end of input.
    ///
    /// A line that is not JSON is answered with a parse error and reading
    /// continues, because one malformed message from a client is not a reason
    /// to drop every session that client is driving.
    ///
    /// # Errors
    ///
    /// An `io::Error` when the stream itself fails, or when a line exceeds
    /// [`MAX_LINE`].
    pub async fn read(&mut self) -> std::io::Result<Option<Result<Request, RequestError>>> {
        loop {
            self.line.clear();
            let read = self.reader.read_line(&mut self.line).await?;
            if read == 0 {
                return Ok(None);
            }
            if read > MAX_LINE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("a JSON-RPC line of {read} bytes is over the {MAX_LINE} byte limit"),
                ));
            }
            let trimmed = self.line.trim();
            if trimmed.is_empty() {
                continue;
            }
            return Ok(Some(parse(trimmed)));
        }
    }

    /// Write one message and flush it.
    ///
    /// Flushed every time rather than on a timer. A buffered reply is a reply
    /// the client is still waiting for, and this protocol is request and
    /// response over a pipe, so there is nothing to batch it with.
    ///
    /// # Errors
    ///
    /// An `io::Error` from the stream.
    pub async fn write(&mut self, value: &Value) -> std::io::Result<()> {
        let mut line = serde_json::to_string(value).map_err(std::io::Error::other)?;
        line.push('\n');
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await
    }
}

/// A line that arrived but is not a request this server can act on.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestError {
    /// Echoed back where the line carried one, so a client can match the
    /// failure to the call. `Null` when the line was too broken to read an id
    /// out of, which is what the specification requires.
    pub id: Value,
    pub code: i64,
    pub message: String,
}

fn parse(line: &str) -> Result<Request, RequestError> {
    let value: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(error) => {
            return Err(RequestError {
                id: Value::Null,
                code: PARSE_ERROR,
                message: format!("that line is not JSON: {error}"),
            })
        }
    };
    // A batch is an array. Refused with a sentence rather than ignored, because
    // the 2026-07-28 revision removed batching and a client that sends one is
    // speaking an older revision and should be told which.
    if value.is_array() {
        return Err(RequestError {
            id: Value::Null,
            code: INVALID_REQUEST,
            message: "JSON-RPC batches were removed in MCP 2026-07-28 and this server does not accept them; send one message per line".to_string(),
        });
    }
    let id = value.get("id").cloned();
    let echo = id.clone().unwrap_or(Value::Null);
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(RequestError {
            id: echo,
            code: INVALID_REQUEST,
            message: "every message carries \"jsonrpc\": \"2.0\"".to_string(),
        });
    }
    let method = match value.get("method").and_then(Value::as_str) {
        Some(method) => method.to_string(),
        None => {
            return Err(RequestError {
                id: echo,
                code: INVALID_REQUEST,
                message: "this message names no method; a response is not something this server accepts, only requests and notifications".to_string(),
            })
        }
    };
    let params = value.get("params").cloned().unwrap_or_else(|| json!({}));
    let meta = params
        .get("_meta")
        .cloned()
        .or_else(|| value.get("_meta").cloned())
        .unwrap_or_else(|| json!({}));
    Ok(Request {
        id,
        method,
        params,
        meta,
    })
}

/// A successful reply.
pub fn reply(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// A protocol level failure.
///
/// Reserved for a malformed call, per the specification's own division between
/// tool execution errors and protocol errors (`04 §4.4`). A tool that refused
/// is a RESULT with `isError` set, because a model handed a transport failure
/// for a refusal it caused cannot tell the two apart.
pub fn fail(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notification_carries_no_id() {
        let request = parse(r#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#).unwrap();
        assert!(request.is_notification());
    }

    #[test]
    fn meta_travels_on_params_because_there_is_no_handshake() {
        let request = parse(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"protocolVersion":"2026-07-28"}}}"#,
        )
        .unwrap();
        assert_eq!(request.protocol_version(), Some("2026-07-28"));
    }

    #[test]
    fn a_batch_is_refused_with_the_revision_that_removed_it() {
        let error = parse(r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#).unwrap_err();
        assert_eq!(error.code, INVALID_REQUEST);
        assert!(error.message.contains("2026-07-28"));
    }

    #[test]
    fn a_broken_line_still_reports_the_id_when_it_can_read_one() {
        let error = parse(r#"{"id":7,"method":"tools/list"}"#).unwrap_err();
        assert_eq!(error.id, json!(7));
        assert_eq!(error.code, INVALID_REQUEST);
    }

    #[test]
    fn a_line_that_is_not_json_reports_a_null_id() {
        let error = parse("{not json").unwrap_err();
        assert_eq!(error.id, Value::Null);
        assert_eq!(error.code, PARSE_ERROR);
    }
}
