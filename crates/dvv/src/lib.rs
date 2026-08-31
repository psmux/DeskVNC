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

/// The MCP revision this adapter speaks.
///
/// One value, not a range. `04 §8` OQ-4 recommends keeping a compatibility
/// path for `2025-11-25` behind a flag, and this build does not have one: the
/// two are not wire compatible, one has `initialize` and `Mcp-Session-Id` and
/// the other has `server/discover` and `_meta`, and shipping half of the older
/// one would be worse than shipping none of it. Recorded here rather than in a
/// plan file, because the person who wonders where `--protocol` went will be
/// reading this constant.
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

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
