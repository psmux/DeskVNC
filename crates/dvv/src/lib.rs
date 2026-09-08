//! # dvv
//!
//! The thing an agent actually connects to. An MCP server over stdio, the same
//! server over HTTP for the agents that cannot spawn a subprocess, a CLI over
//! the same surface, and nothing else (`04 §1`, `04 §7`, `00 R52`).
//!
//! ## Two transports, one dispatch
//!
//! [`http`] is a TRANSPORT and not a second server. It frames with
//! [`jsonrpc::Connection`] and answers with [`mcp::Server::handle`], which are
//! the same reader and the same dispatch table stdio uses, so a tool cannot
//! behave differently depending on how the agent got here. `00 R18` ruled out a
//! listener in version 1 and `00 R52` amends that ruling on named terms, all of
//! which are enforced in [`http`] and argued for at the top of it: off by
//! default, loopback by default, a bearer token always, `Origin` checked, and a
//! refusal to start rather than a start with no token.
//!
//! ## The layering ruling, kept
//!
//! `04 §1.1` rules that MCP is an ADAPTER and not the contract. Everything in
//! [`mcp`] turns one `tools/call` into one call on [`plane::Plane`] and adds
//! nothing, and [`cli`] calls the same methods. Neither reaches past the plane
//! into a driver, a `ProtocolRegistry` or a `SessionEntry`, and neither can:
//! this crate's dependency list has no protocol crate in it and no tauri.
//!
//! The consequence a reader should hold onto: **the CLI is not a second
//! client**. `04 §7.2`'s first rule is one verb, one plane call, because a
//! composition that exists only in the CLI is a behaviour the MCP server does
//! not get, and then they diverge.
//!
//! ## Why the JSON-RPC framing is written by hand
//!
//! The 2026-07-28 revision of MCP is stateless. It removed the
//! `initialize`/`initialized` handshake and the `Mcp-Session-Id` header, so a
//! server is a framed reader, a dispatch table and a writer, and continuity
//! travels as explicit handles passed as ordinary tool arguments (`04 §3.1`).
//! The revisions before it open with `initialize`, and this server answers
//! that too (see [`CLASSIC_PROTOCOL_VERSIONS`]): the handshake is the only
//! thing that differs on the wire for the tools this server has, and every
//! client installed today opens with it.
//! A `limbId` is that handle and [`limb_core::identity::LimbId`] was designed
//! for exactly this: opaque, reproducible, `lmb_<protocol>_<12 hex>_<slot>`.
//! An SDK for that is a dependency the DMG has to carry for a reader and a
//! writer, and `00 R40`'s constraints apply to every dependency.
//!
//! ## What is real today and what is owed
//!
//! `agent-plane` has no live sessions to drive, because the shell wiring that
//! would hand it a `SessionHandle` off `ProtocolRegistry` does not exist yet.
//! So the session source is injected ([`plane::SessionSource`]) and there are
//! two of them: [`plane::ShellSource`], which refuses every open with a
//! sentence naming exactly what is missing, and [`fake::FakeSource`], which
//! builds a limb with a recorder on the other end of its command channel so the
//! whole MCP round trip is provable end to end with no server anywhere.
//!
//! Nothing in this crate pretends. A tool that cannot work today says so in its
//! own description, which is BrowserGlass's habit and the reason `04 §4.1`
//! adopts it: a tool that lies about being implemented burns an agent's turn
//! and its user's money.
//!
//! ## The three rules a reviewer checks
//!
//! 1. **No `active_window`, `app_name`, `foreground_handle`, `window_list` or
//!    `z_order`, anywhere, ever** (`00 R42` WA-4). `signals.window_structure`
//!    carries an explicit absence in their place, and
//!    [`observation::FORBIDDEN_FIELDS`] exists so the grep is a test rather
//!    than a habit.
//! 2. **Every negotiated field is an availability envelope whose `value` key
//!    is absent unless availability is live** (`00 R42` WA-3). The type is
//!    `limb_core::Availability` and this crate does not define a second one,
//!    because a second one is how the two drift.
//! 3. **`terminate` is absorbed by the adapter and never reaches the plane**
//!    (`00 R43` WA-7). [`actions`] is where that is enforced.

// Nothing here touches a raw pointer and nothing here ever will, but every
// crate in this workspace that could carries the attribute and the consistency
// is worth more than the exception.
#![forbid(unsafe_code)]

pub mod actions;
pub mod cli;
pub mod clock;
pub mod error;
pub mod fake;
pub mod http;
pub mod jsonrpc;
pub mod mcp;
pub mod observation;
pub mod plane;
pub mod watch;

pub use error::{ToolError, DVV_VERSION};
pub use plane::{LimbCard, Plane, SessionSource};
pub use watch::WatchEvent;

/// The newest MCP revision this adapter speaks, and the one it describes
/// itself under in `server/discover`.
///
/// `04 §8` OQ-4 recommended keeping a compatibility path for the earlier
/// revisions behind a flag, and the first build did not have one, on the
/// argument that `initialize` plus `Mcp-Session-Id` and `server/discover` plus
/// `_meta` are not wire compatible. That argument was right about the
/// handshake and wrong about what mattered: Claude Code, the client the README
/// tells people to point at this server, opens with `initialize` and was
/// refused with method not found, so the one-click registration produced a
/// server nobody could reach. The handshake is now answered for every
/// revision in [`CLASSIC_PROTOCOL_VERSIONS`] as well, with no flag: a server
/// that must be configured to accept the client in front of it is a server
/// that is not adopted. `tools/list` and `tools/call` are the same shape under
/// every one of them, which is what makes this cheap.
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// The revisions before 2026-07-28, newest first, all of which open with
/// `initialize` and are answered here.
///
/// A client asking for one of these is answered with the same one. A client
/// asking for a version this build does not know, newer or stranger, is
/// answered with the first entry, which is the specification's rule: the
/// server offers what it speaks and the client decides whether to continue.
pub const CLASSIC_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Is this one of the revisions that open with `initialize`?
pub fn is_classic_version(version: &str) -> bool {
    CLASSIC_PROTOCOL_VERSIONS.contains(&version)
}

/// The revision to answer an `initialize` with.
pub fn negotiate_classic_version(asked: Option<&str>) -> &'static str {
    asked
        .and_then(|asked| {
            CLASSIC_PROTOCOL_VERSIONS
                .iter()
                .copied()
                .find(|known| *known == asked)
        })
        .unwrap_or(CLASSIC_PROTOCOL_VERSIONS[0])
}

/// Build a `bytes::Bytes` without naming the crate.
///
/// This crate's manifest does not carry `bytes`, and `04 §1` is why that is
/// right rather than an oversight: the manifest is deliberately small and
/// `00 R40`'s constraints apply to every dependency. Two public types this
/// crate must construct carry a `Bytes` field anyway,
/// `IntentKind::SendBytes` and `agent_plane::Frame`, so the value is built
/// through the `From<Vec<u8>>` impl and inference picks the type off the field
/// it is assigned to.
///
/// It reads as a trick and it is worth the sentence: the alternative is a
/// dependency line for a conversion, or a public API that takes `Vec<u8>` in
/// crates that correctly do not.
pub fn into_bytes<B: From<Vec<u8>>>(bytes: Vec<u8>) -> B {
    B::from(bytes)
}

/// The prefix on every tool, with no exceptions (`04 §4.1`).
///
/// It earns its keep twice. It disambiguates our tools from another server's in
/// an agent's manifest, which was always the reason, and under 2026-07-28 it is
/// the value that goes in the `Mcp-Name` header beside `Mcp-Method`, so a
/// gateway can route and meter without parsing the body. A prefix that is
/// stable and unique is load bearing infrastructure for anyone who puts us
/// behind a proxy.
pub const TOOL_PREFIX: &str = "dvv_";
