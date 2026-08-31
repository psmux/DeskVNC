//! MCP over Streamable HTTP, the second way in to the same dispatch.
//!
//! ## Why there is a listener at all, when `00 R18` said there would not be
//!
//! `00 R18` ruled local only with no TCP listener in version 1, because a
//! listener that drives desktops is a different product with a different threat
//! model. That ruling is AMENDED by `00 R52` rather than ignored, and the reason
//! is a class of client stdio cannot reach: an agent that cannot spawn a
//! subprocess. A hosted assistant, a container, a browser extension, something
//! on another machine on the user's own LAN. None of them can run
//! `dvv mcp --stdio`, and all of them can open a URL.
//!
//! The terms of the amendment are `00 R52` and every one of them is enforced in
//! this file:
//!
//! 1. Off by default. Nothing here runs unless `dvv mcp --http` was typed.
//! 2. Loopback by default ([`default_host`]). Binding wider is `--host`, an
//!    explicit flag, and taking it prints [`exposure_warning`].
//! 3. A bearer token is required ALWAYS, loopback included, generated when not
//!    supplied and compared in constant time ([`authorised`]).
//! 4. `Origin` is checked ([`origin_refusal`]).
//! 5. No token and no way to mint one is a startup failure, never a warning
//!    ([`resolve_token`]).
//! 6. A bind failure is loud ([`HttpServer::bind`] returns the error with the
//!    address in it, and the CLI exits non zero).
//!
//! ## The term most likely to be argued away later, and why it must not be
//!
//! "It is only on loopback, so who could reach it?" Every web page the user
//! visits. A page at `https://anywhere.example` can POST to `127.0.0.1` from
//! the browser the user already has open, and DNS rebinding turns that into a
//! same origin request. A loopback port with no authentication is not a private
//! service, it is an unauthenticated service reachable by every site in the
//! user's browser. Hence the token on loopback too, and hence the `Origin`
//! check: those two are what stand between a page the user visited and their
//! desktops.
//!
//! ## What this file is NOT
//!
//! It is not a second MCP server. Every request is framed by
//! [`crate::jsonrpc::Connection`], the same reader stdio uses, and answered by
//! [`crate::mcp::Server::handle`], the same dispatch a `tools/call` on stdio
//! reaches. There is no tool logic here and there must never be any: a
//! behaviour that exists on one transport and not the other is how the two
//! diverge, which is the same argument `04 §7.2` makes for the CLI.
//!
//! ## The shape, from the 2026-07-28 specification
//!
//! One endpoint ([`ENDPOINT`]) that accepts POST. One JSON-RPC message per
//! POST. A request is answered with a single JSON object; a notification is
//! answered with `202 Accepted` and no body. `MCP-Protocol-Version`,
//! `Mcp-Method` and (on `tools/call`) `Mcp-Name` mirror body fields into
//! headers so a gateway can route and meter without parsing the body, and the
//! body stays the source of truth: a header that disagrees with it is
//! `400 Bad Request` with [`HEADER_MISMATCH`], because a load balancer routing
//! on the header while this server acts on the body is a security bug and not a
//! cosmetic one.
//!
//! The 2026-07-28 revision removed the GET stream and the `Mcp-Session-Id`
//! session, so GET and DELETE answer `405` here, which is what the
//! specification's own backward compatibility section asks a server of this
//! revision to do.

use crate::jsonrpc::{self, Connection, Request};
use crate::mcp::Server;
use base64::Engine as _;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

/// The one path this server answers on.
///
/// The specification asks for a single MCP endpoint and says nothing about its
/// spelling, so it is `/mcp`, which is what every published example uses and
/// therefore what somebody typing a URL by hand will guess.
pub const ENDPOINT: &str = "/mcp";

/// The port `dvv mcp --http` uses when nobody said.
///
/// Arbitrary, above the privileged range, and deliberately not one of the
/// common development ports (3000, 5173, 8000, 8080): a collision there would
/// make `dvv` the process that broke somebody's dev server.
pub const DEFAULT_PORT: u16 = 7333;

/// Where a token is read from when it is not on the command line.
///
/// An environment variable rather than only a flag, because anything on the
/// machine can read a process's arguments out of `ps`, and a bearer token that
/// drives desktops is not a thing to leave in an argument list.
pub const TOKEN_ENV: &str = "DVV_MCP_TOKEN";

/// `-32020`, the specification's `HeaderMismatch`.
///
/// From the `-32020` to `-32099` sub-range the MCP specification reserves for
/// itself. This build emits exactly two codes from that range and both are
/// defined by the specification, which is the rule for that sub-range.
pub const HEADER_MISMATCH: i64 = -32020;

/// `-32022`, the specification's `UnsupportedProtocolVersion`.
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// Header names, lowercase because `HeaderMap` lookups are case insensitive and
/// a lowercase literal cannot be got wrong twice.
const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const METHOD_HEADER: &str = "mcp-method";
const NAME_HEADER: &str = "mcp-name";

/// Where the protocol version lives in the body under 2026-07-28.
///
/// Two keys are read, not one. The specification's key is the namespaced one;
/// `crate::jsonrpc::Request::protocol_version` reads the short one, and this
/// crate's own selftest sends the short one. A validator that accepted only the
/// namespaced key would refuse messages this repository generates itself, which
/// is a worse failure than being generous about a field the body does not have
/// to carry at all.
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_PROTOCOL_VERSION_SHORT: &str = "protocolVersion";

/// The sentinel a client wraps a header value in when it is not plain ASCII.
const BASE64_PREFIX: &str = "=?base64?";
const BASE64_SUFFIX: &str = "?=";

/// Where a token came from, which decides what is printed and what is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// `--token`. The user already knows it, so printing it back costs nothing.
    Flag,
    /// [`TOKEN_ENV`]. Never printed: the point of the variable is that the
    /// value is not on a screen or in a shell history.
    Environment,
    /// Minted here. Printed exactly once, at startup, because otherwise nobody
    /// can connect.
    Generated,
}

/// Resolve the bearer token, or fail to start.
///
/// `00 R52` term 5: no token and no way to mint one is a startup failure. The
/// generator is the operating system CSPRNG through the fallible `SysRng`, so
/// "the CSPRNG is unreachable" is an error the caller reports rather than a
/// weak token nobody notices.
///
/// # Errors
///
/// A sentence for the user when `--token` was empty, or when the OS CSPRNG
/// could not produce one.
pub fn resolve_token(flag: Option<&str>) -> Result<(String, TokenSource), String> {
    if let Some(supplied) = flag {
        let trimmed = supplied.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "--token was given an empty string. A bearer token is required on every bind including loopback, because any page the user's browser has open can post to a loopback port. Give a token, set {TOKEN_ENV}, or pass neither and dvv will mint one."
            ));
        }
        return Ok((trimmed.to_string(), TokenSource::Flag));
    }
    if let Ok(from_env) = std::env::var(TOKEN_ENV) {
        let trimmed = from_env.trim();
        if !trimmed.is_empty() {
            return Ok((trimmed.to_string(), TokenSource::Environment));
        }
    }
    Ok((generate_token()?, TokenSource::Generated))
}

/// 192 bits of operating system entropy, as hex.
///
/// Hex rather than base64 so the value is always a valid HTTP header value with
/// no encoding rule attached, and so a person can retype it off a terminal
/// without wondering about case or padding.
///
/// # Errors
///
/// A sentence when the OS CSPRNG is unreachable. rand 0.10 replaced the
/// panic-on-failure `OsRng` with the fallible `SysRng`, and this is one of the
/// places where the honest answer is to refuse to start.
pub fn generate_token() -> Result<String, String> {
    use rand::rngs::SysRng;
    use rand::TryRng;
    let mut bytes = [0u8; 24];
    SysRng.try_fill_bytes(&mut bytes).map_err(|error| {
        format!(
            "the operating system CSPRNG is unreachable ({error}), so dvv cannot mint a bearer token. It refuses to start rather than listen with no token: supply one in {TOKEN_ENV} or with --token."
        )
    })?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        // Infallible into a String, and the `let _` says so rather than
        // pretending a formatting error is reachable here.
        let _ = write!(token, "{byte:02x}");
    }
    Ok(token)
}

/// The address a listener binds when nobody said: `127.0.0.1`.
pub fn default_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Read `--host`.
///
/// A literal address only. Resolving a name here would mean a listener whose
/// address depends on a resolver, and "which interface am I on" is exactly the
/// question a person taking this flag has to be able to answer for themselves.
///
/// # Errors
///
/// A sentence naming what was passed when it is not an IP address.
pub fn host_from_flag(flag: Option<&str>) -> Result<IpAddr, String> {
    let Some(text) = flag else {
        return Ok(default_host());
    };
    let trimmed = text.trim();
    if trimmed.eq_ignore_ascii_case("localhost") {
        return Ok(default_host());
    }
    trimmed.parse::<IpAddr>().map_err(|_| {
        format!(
            "{trimmed:?} is not an IP address. --host takes a literal address, 127.0.0.1 or 0.0.0.0 or an interface address, and never a name: a listener that drives desktops must not have its reach decided by a resolver."
        )
    })
}

/// What the user has just exposed, in a sentence, or `None` on loopback.
///
/// `00 R52` term 2. Binding wider is allowed and it is not silent: the person
/// who typed `--host 0.0.0.0` is told what that means in the same breath.
pub fn exposure_warning(host: &IpAddr) -> Option<String> {
    if host.is_loopback() {
        return None;
    }
    Some(format!(
        "EXPOSED: this listener is bound to {host} and not to loopback. Every machine that can route to this address can now reach an MCP server that drives your desktops, and the bearer token is the only thing in the way. It travels in clear over plain HTTP, so on anything but a network you control put a TLS terminator in front of it or bind 127.0.0.1 and use an SSH tunnel. A client elsewhere connects to this machine's own address on that network, which is not the bind address printed above."
    ))
}

/// Everything a listener needs, and nothing about a session, because
/// 2026-07-28 has none.
///
/// `Debug` is written out below rather than derived, and the reason is the
/// token: a derived one puts a live bearer token in any log line, panic message
/// or `dbg!` that ever touches this struct, and that is the sort of leak that
/// happens once and lives in a log file forever.
#[derive(Clone)]
pub struct HttpConfig {
    /// Loopback unless a flag said otherwise.
    pub host: IpAddr,
    /// `0` asks the operating system for an ephemeral port, which is what the
    /// tests use and what somebody running two of these wants.
    pub port: u16,
    /// Required, always. There is no constructor that omits it.
    pub token: String,
    /// Origins this server will answer. Empty by default, which means a request
    /// carrying ANY `Origin` is refused: nothing that legitimately drives this
    /// server is a browser page, so an `Origin` header is by default evidence
    /// of the attack the check exists for.
    pub allowed_origins: Vec<String>,
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            // Whether a token is set, never which one.
            .field("token", &"<redacted>")
            .field("allowed_origins", &self.allowed_origins)
            .finish()
    }
}

impl HttpConfig {
    /// A loopback listener on `port` with this token.
    pub fn loopback(port: u16, token: impl Into<String>) -> HttpConfig {
        HttpConfig {
            host: default_host(),
            port,
            token: token.into(),
            allowed_origins: Vec::new(),
        }
    }

    /// Is this the default, safe bind?
    pub fn is_loopback(&self) -> bool {
        self.host.is_loopback()
    }
}

/// A bound socket, before anything is served on it.
///
/// Bind and serve are two steps so that a failure to bind is reportable (`00
/// R52` term 6) and so a test can read the ephemeral port it was given. A
/// single `serve(config)` call would have to either swallow the address or
/// invent a channel to hand it back.
pub struct HttpServer {
    listener: TcpListener,
    config: Arc<HttpConfig>,
}

impl HttpServer {
    /// Take the port, loudly.
    ///
    /// # Errors
    ///
    /// The `io::Error` from `bind`, with the address in the message. A port
    /// already in use is the common case and the message says which port,
    /// because "address in use" with no address is the least useful error in
    /// systems programming.
    pub async fn bind(config: HttpConfig) -> std::io::Result<HttpServer> {
        let address = SocketAddr::new(config.host, config.port);
        let listener = TcpListener::bind(address).await.map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("dvv could not bind {address}: {error}"),
            )
        })?;
        Ok(HttpServer {
            listener,
            config: Arc::new(config),
        })
    }

    /// The address actually bound, which is the only way to learn an ephemeral
    /// port.
    ///
    /// # Errors
    ///
    /// The `io::Error` from the socket.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The URL a client points at.
    ///
    /// # Errors
    ///
    /// The `io::Error` from the socket.
    pub fn url(&self) -> std::io::Result<String> {
        // `SocketAddr`'s Display brackets an IPv6 address, so this is a URL and
        // not almost a URL.
        Ok(format!("http://{}{ENDPOINT}", self.local_addr()?))
    }

    /// Answer requests until the process ends.
    ///
    /// # Errors
    ///
    /// Nothing today: an accept that fails is logged and the loop continues,
    /// because one refused connection is not a reason to stop serving every
    /// other. The signature keeps the `Result` so a future shutdown path has
    /// somewhere to report from.
    pub async fn serve(self, server: Arc<Server>) -> std::io::Result<()> {
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(error) => {
                    // A hot loop here is the failure mode: EMFILE returns
                    // immediately and forever, so an unpaused retry would spin
                    // a core rather than serve anything.
                    tracing::warn!("dvv http accept failed: {error}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            let config = Arc::clone(&self.config);
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let config = Arc::clone(&config);
                    let server = Arc::clone(&server);
                    async move {
                        Ok::<_, std::convert::Infallible>(respond(&config, &server, request).await)
                    }
                });
                if let Err(error) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    // Debug and not warn. A client that hangs up mid request is
                    // ordinary, and a log line per disconnection is how a log
                    // becomes something nobody reads.
                    tracing::debug!("dvv http connection from {peer} ended: {error}");
                }
            });
        }
    }
}

/// One HTTP request, all the way to the same dispatch stdio reaches.
///
/// The order of the checks is the security argument: `Origin` and the token are
/// decided before the path, before the body is read and before anything is
/// parsed, so an unauthenticated caller cannot make this process allocate or
/// learn which paths exist.
async fn respond(
    config: &HttpConfig,
    server: &Server,
    request: hyper::Request<Incoming>,
) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();

    // GET was the standalone SSE stream and DELETE was the session teardown.
    // The 2026-07-28 revision removed both, and 405 is the answer it tells a
    // server of this revision to give, which is also how an older client
    // detects that it is talking to a newer server.
    if parts.method != Method::POST {
        return message(
            StatusCode::METHOD_NOT_ALLOWED,
            format!(
                "{} is not a method this endpoint has. MCP {} is one JSON-RPC message per POST: the GET stream and the DELETE session were removed by that revision.",
                parts.method,
                crate::MCP_PROTOCOL_VERSION
            ),
        );
    }

    if let Some(refusal) = origin_refusal(config, &parts.headers) {
        return refusal;
    }
    if !authorised(config, &parts.headers) {
        return unauthorised();
    }

    if parts.uri.path() != ENDPOINT {
        return message(
            StatusCode::NOT_FOUND,
            format!(
                "there is nothing at {}. This server has one MCP endpoint and it is {ENDPOINT}.",
                parts.uri.path()
            ),
        );
    }

    // Bounded before it is read. `MAX_LINE` is the same ceiling stdio enforces,
    // so a body that would be refused on one transport is refused on the other.
    let collected = match Limited::new(body, jsonrpc::MAX_LINE).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                Value::Null,
                jsonrpc::INVALID_REQUEST,
                format!(
                    "that body is over the {} byte limit. A client that sends an unbounded body is a client that can exhaust this process before anything else notices.",
                    jsonrpc::MAX_LINE
                ),
                None,
            );
        }
    };

    // The SAME reader stdio uses, over the body instead of over a pipe. A
    // second parser here would be a second place for the two transports to
    // disagree about what a message is.
    let mut framed = Connection::new(&collected[..], tokio::io::sink());
    let message = match framed.read().await {
        Ok(Some(Ok(message))) => message,
        Ok(Some(Err(error))) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                error.id,
                error.code,
                error.message,
                None,
            );
        }
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                jsonrpc::INVALID_REQUEST,
                "the body is empty. Every POST to this endpoint carries exactly one JSON-RPC message.",
                None,
            );
        }
        Err(error) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                jsonrpc::PARSE_ERROR,
                format!("that body is not a JSON-RPC message: {error}"),
                None,
            );
        }
    };

    // Header requirements for a notification POST are not defined by this
    // revision, so a notification is not held to them. A request is.
    if !message.is_notification() {
        if let Some(refusal) = header_refusal(&parts.headers, &message) {
            return refusal;
        }
    }

    match server.handle(&message).await {
        // A notification gets no reply, which over HTTP is 202 with no body.
        None => Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Full::new(Bytes::new()))
            .expect("a response this crate built itself"),
        Some(reply) => json_body(status_for(&reply), &reply),
    }
}

/// The HTTP status a JSON-RPC reply is carried under.
///
/// Only one mapping exists, and the specification asks for it by name: a method
/// this server does not implement is `404` with `-32601` in the body, so a
/// client can tell it apart from the `404` a legacy HTTP+SSE server gives for a
/// path it does not host.
fn status_for(reply: &Value) -> StatusCode {
    match reply["error"]["code"].as_i64() {
        Some(jsonrpc::METHOD_NOT_FOUND) => StatusCode::NOT_FOUND,
        _ => StatusCode::OK,
    }
}

/// Refuse a request carrying an `Origin` this server did not expect.
///
/// This is the DNS rebinding check, and it is the reason "loopback is safe" is
/// wrong. A page the user visited can post here from their browser; the browser
/// puts that page's origin in this header; nothing that legitimately drives
/// this server is a browser page at all. So the allowlist is empty by default
/// and any `Origin` is refused, rather than a list of origins that seem
/// harmless.
fn origin_refusal(config: &HttpConfig, headers: &HeaderMap) -> Option<Response<Full<Bytes>>> {
    let origin = headers.get(ORIGIN)?;
    let allowed = origin
        .to_str()
        .map(|origin| {
            config
                .allowed_origins
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(origin))
        })
        // A header that is not visible ASCII is not an origin this server has
        // ever allowed, so it is refused rather than parsed harder.
        .unwrap_or(false);
    if allowed {
        return None;
    }
    Some(json_error(
        StatusCode::FORBIDDEN,
        Value::Null,
        jsonrpc::INVALID_REQUEST,
        format!(
            "that Origin is not one this server expects, so the request is refused: {}. A browser page posting to a loopback port is the DNS rebinding attack this check exists for. Nothing that legitimately drives dvv is a web page; if yours is, name it with --allow-origin.",
            origin.to_str().unwrap_or("<not ASCII>")
        ),
        None,
    ))
}

/// Is the bearer token right?
///
/// Constant time, because a comparison that stops at the first wrong byte tells
/// an attacker how much of the token they have already guessed, and a loopback
/// port is reachable often enough for that to be worth doing.
fn authorised(config: &HttpConfig, headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some((scheme, token)) = value.split_once(' ') else {
        return false;
    };
    // The scheme is case insensitive per RFC 9110; the token is not.
    if !scheme.eq_ignore_ascii_case("bearer") {
        return false;
    }
    constant_time_eq(token.trim().as_bytes(), config.token.as_bytes())
}

/// Equal, without leaking where they first differ.
///
/// `subtle`'s slice implementation short circuits on LENGTH and on nothing
/// else, which is the right trade: the length of a bearer token is not a
/// secret, and the bytes are.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

/// The headers must agree with the body, or the request is refused.
///
/// The specification requires this and the reason is not cosmetic: a gateway
/// routing or metering on `Mcp-Name` while this server executes `params.name`
/// means two components acting on two different sources of truth, and an
/// attacker who can make them disagree gets to pick which one each component
/// sees.
///
/// `Some` is the refusal and `None` is "these agree", which is the same shape
/// [`origin_refusal`] has. A `Result` would read more naturally and clippy is
/// right to refuse it: a `Response` in the `Err` variant makes every caller's
/// `Result` 144 bytes wide for a value that is only ever returned once.
fn header_refusal(headers: &HeaderMap, message: &Request) -> Option<Response<Full<Bytes>>> {
    let id = message.id.clone().unwrap_or(Value::Null);

    let Some(version) = header_str(headers, PROTOCOL_VERSION_HEADER) else {
        return Some(mismatch(
            id,
            format!(
                "MCP-Protocol-Version is required on every POST to this endpoint. This server speaks MCP {} and nothing earlier, so a request without the header cannot be assumed to be an older client's.",
                crate::MCP_PROTOCOL_VERSION
            ),
        ));
    };
    if version != crate::MCP_PROTOCOL_VERSION {
        return Some(json_error(
            StatusCode::BAD_REQUEST,
            id,
            UNSUPPORTED_PROTOCOL_VERSION,
            format!(
                "this server speaks MCP {} and not {version}. The two are not wire compatible: one has initialize and Mcp-Session-Id, the other has server/discover and _meta.",
                crate::MCP_PROTOCOL_VERSION
            ),
            Some(json!({ "supported": [crate::MCP_PROTOCOL_VERSION] })),
        ));
    }
    if let Some(in_body) = body_protocol_version(message) {
        if in_body != version {
            return Some(mismatch(
                id,
                format!(
                    "MCP-Protocol-Version says {version:?} and the body's _meta says {in_body:?}. The body is the source of truth and the header must mirror it."
                ),
            ));
        }
    }

    let Some(method) = header_str(headers, METHOD_HEADER) else {
        return Some(mismatch(
            id,
            format!(
                "Mcp-Method is required on every request. This one is {:?}, so the header reads Mcp-Method: {}.",
                message.method, message.method
            ),
        ));
    };
    if method != message.method {
        return Some(mismatch(
            id,
            format!(
                "Mcp-Method says {method:?} and the body calls {:?}.",
                message.method
            ),
        ));
    }

    if let Some(field) = mirrored_name_field(&message.method) {
        let in_body = message.params.get(field).and_then(Value::as_str);
        let in_header = header_str(headers, NAME_HEADER).and_then(|raw| decode_header_value(&raw));
        match (in_header, in_body) {
            (Some(header), Some(body)) if header == body => {}
            (Some(header), Some(body)) => {
                return Some(mismatch(
                    id,
                    format!("Mcp-Name says {header:?} and the body's {field} is {body:?}."),
                ));
            }
            (Some(header), None) => {
                return Some(mismatch(
                    id,
                    format!(
                        "Mcp-Name says {header:?} and the body names nothing: a {} carries {field} in its params.",
                        message.method
                    ),
                ));
            }
            (None, _) => {
                return Some(mismatch(
                    id,
                    format!(
                        "Mcp-Name is required on a {} and this request has no usable one.",
                        message.method
                    ),
                ));
            }
        }
    }

    None
}

/// Which params field `Mcp-Name` mirrors, for the methods that mirror one.
///
/// Two of these three are methods this server does not implement. They are
/// listed anyway because the mapping is the specification's, not ours, and a
/// table that is only correct for the methods we happen to have today is a
/// table that will be wrong on the day one is added.
fn mirrored_name_field(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    }
}

/// The protocol version the body claims, under either spelling.
fn body_protocol_version(message: &Request) -> Option<String> {
    message
        .meta
        .get(META_PROTOCOL_VERSION)
        .or_else(|| message.meta.get(META_PROTOCOL_VERSION_SHORT))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
}

/// Undo the `=?base64?...?=` sentinel a client wraps a header value in when it
/// is not plain ASCII.
///
/// Every tool this server has is plain ASCII, so this path is never taken by a
/// conforming client talking to us. It exists so that a comparison against an
/// encoded value is a comparison and not a spurious mismatch, which is the
/// specification's rule: decode, THEN compare.
fn decode_header_value(raw: &str) -> Option<String> {
    let Some(inner) = raw
        .strip_prefix(BASE64_PREFIX)
        .and_then(|rest| rest.strip_suffix(BASE64_SUFFIX))
    else {
        return Some(raw.to_string());
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(inner)
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn mismatch(id: Value, message: impl Into<String>) -> Response<Full<Bytes>> {
    json_error(StatusCode::BAD_REQUEST, id, HEADER_MISMATCH, message, None)
}

fn unauthorised() -> Response<Full<Bytes>> {
    let body = json!({
        "jsonrpc": "2.0",
        "error": {
            "code": jsonrpc::INVALID_REQUEST,
            "message": format!("this endpoint needs Authorization: Bearer <token>. A token is required on every bind including loopback: any page the user's browser has open can post to a loopback port, so \"it is only local\" is not authentication. dvv prints the token once at startup, or reads one from {TOKEN_ENV}."),
        },
    });
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(CONTENT_TYPE, "application/json")
        .header(WWW_AUTHENTICATE, "Bearer realm=\"dvv\"")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("a response this crate built itself")
}

/// A JSON-RPC error response, carried under an HTTP status.
fn json_error(
    status: StatusCode,
    id: Value,
    code: i64,
    text: impl Into<String>,
    data: Option<Value>,
) -> Response<Full<Bytes>> {
    let mut error = json!({ "code": code, "message": text.into() });
    if let (Some(data), Some(object)) = (data, error.as_object_mut()) {
        object.insert("data".to_string(), data);
    }
    json_body(
        status,
        &json!({ "jsonrpc": "2.0", "id": id, "error": error }),
    )
}

/// A refusal that is about HTTP rather than about JSON-RPC.
///
/// Deliberately NOT a JSON-RPC error object: the specification's backward
/// compatibility rule has a client inspect the body of a 400, 404 or 405 to
/// decide whether it is talking to a modern server, and a recognised JSON-RPC
/// error there would tell it the wrong thing about a request that never reached
/// the protocol at all.
fn message(status: StatusCode, text: impl Into<String>) -> Response<Full<Bytes>> {
    json_body(status, &json!({ "error": text.into() }))
}

fn json_body(status: StatusCode, value: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(value.to_string())))
        .expect("a response this crate built itself")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> HttpConfig {
        HttpConfig::loopback(0, "0123456789abcdef")
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                value.parse().expect("a header value"),
            );
        }
        map
    }

    #[test]
    fn the_default_bind_is_loopback_and_says_nothing_about_exposure() {
        assert!(default_host().is_loopback());
        assert!(config().is_loopback());
        assert!(exposure_warning(&default_host()).is_none());
    }

    #[test]
    fn binding_wider_needs_the_flag_and_prints_what_it_exposed() {
        // The flag is the whole of the difference: with no flag there is no way
        // to reach a non loopback address from this function.
        assert!(host_from_flag(None).expect("a default").is_loopback());
        let wide = host_from_flag(Some("0.0.0.0")).expect("an address");
        assert!(!wide.is_loopback());
        let warning = exposure_warning(&wide).expect("a sentence naming the exposure");
        assert!(warning.contains("0.0.0.0"), "{warning}");
        assert!(warning.contains("EXPOSED"), "{warning}");
        assert!(host_from_flag(Some("not-an-address")).is_err());
    }

    #[test]
    fn a_token_is_required_and_an_empty_one_is_not_a_token() {
        assert!(resolve_token(Some("   ")).is_err());
        let (token, source) = resolve_token(Some("abc")).expect("the supplied token");
        assert_eq!(token, "abc");
        assert_eq!(source, TokenSource::Flag);
    }

    #[test]
    fn a_generated_token_is_192_bits_of_hex() {
        let token = generate_token().expect("the OS CSPRNG");
        assert_eq!(token.len(), 48);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(token, generate_token().expect("a second one"));
    }

    #[test]
    fn only_the_right_bearer_is_authorised() {
        let config = config();
        assert!(authorised(
            &config,
            &headers(&[("authorization", "Bearer 0123456789abcdef")])
        ));
        // The scheme is case insensitive and the token is not.
        assert!(authorised(
            &config,
            &headers(&[("authorization", "bearer 0123456789abcdef")])
        ));
        assert!(!authorised(
            &config,
            &headers(&[("authorization", "Bearer 0123456789ABCDEF")])
        ));
        assert!(!authorised(
            &config,
            &headers(&[("authorization", "Basic 0123456789abcdef")])
        ));
        assert!(!authorised(&config, &headers(&[])));
        // A prefix of the right token, which is what a timing attack would be
        // walking towards.
        assert!(!authorised(
            &config,
            &headers(&[("authorization", "Bearer 0123456789abcde")])
        ));
    }

    #[test]
    fn any_origin_is_refused_until_one_is_named() {
        let mut config = config();
        assert!(origin_refusal(&config, &headers(&[])).is_none());
        assert!(origin_refusal(&config, &headers(&[("origin", "https://evil.example")])).is_some());
        // Even a loopback page. A local development server is still a page the
        // browser will post from, and this endpoint drives desktops.
        assert!(
            origin_refusal(&config, &headers(&[("origin", "http://localhost:3000")])).is_some()
        );
        config.allowed_origins = vec!["http://localhost:3000".to_string()];
        assert!(
            origin_refusal(&config, &headers(&[("origin", "http://localhost:3000")])).is_none()
        );
    }

    #[test]
    fn a_header_that_disagrees_with_the_body_is_refused() {
        let message = Request {
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: json!({ "name": "dvv_limbs", "arguments": {} }),
            meta: json!({ "protocolVersion": crate::MCP_PROTOCOL_VERSION }),
        };
        let good = headers(&[
            ("mcp-protocol-version", crate::MCP_PROTOCOL_VERSION),
            ("mcp-method", "tools/call"),
            ("mcp-name", "dvv_limbs"),
        ]);
        assert!(header_refusal(&good, &message).is_none());

        let wrong_name = headers(&[
            ("mcp-protocol-version", crate::MCP_PROTOCOL_VERSION),
            ("mcp-method", "tools/call"),
            ("mcp-name", "dvv_close"),
        ]);
        assert!(header_refusal(&wrong_name, &message).is_some());

        let no_method = headers(&[
            ("mcp-protocol-version", crate::MCP_PROTOCOL_VERSION),
            ("mcp-name", "dvv_limbs"),
        ]);
        assert!(header_refusal(&no_method, &message).is_some());

        let no_version = headers(&[("mcp-method", "tools/call"), ("mcp-name", "dvv_limbs")]);
        assert!(header_refusal(&no_version, &message).is_some());
    }

    #[test]
    fn an_encoded_name_is_decoded_before_it_is_compared() {
        // "dvv_limbs" wrapped in the specification's sentinel. A client only
        // does this for a value it cannot spell in a header, but a comparison
        // against the raw sentinel would be a spurious mismatch.
        assert_eq!(
            decode_header_value("=?base64?ZHZ2X2xpbWJz?="),
            Some("dvv_limbs".to_string())
        );
        assert_eq!(
            decode_header_value("dvv_limbs"),
            Some("dvv_limbs".to_string())
        );
        assert_eq!(decode_header_value("=?base64?not base64?="), None);
    }

    #[test]
    fn an_unimplemented_method_is_a_404_and_a_result_is_not() {
        let not_found = json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": jsonrpc::METHOD_NOT_FOUND, "message": "no" } });
        assert_eq!(status_for(&not_found), StatusCode::NOT_FOUND);
        let refusal = json!({ "jsonrpc": "2.0", "id": 1, "result": { "isError": true } });
        assert_eq!(status_for(&refusal), StatusCode::OK);
    }
}
