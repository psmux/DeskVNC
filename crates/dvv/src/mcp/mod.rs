//! The MCP adapter.
//!
//! `04 §1.1`: **MCP is an adapter. It is not the contract.** Its job is to turn
//! a `tools/call` into one call on [`crate::plane::Plane`], turn the answer into
//! a `CallToolResult`, and add nothing. The three places it does add something
//! are named at the top of [`server`], and each is there because MCP's shape
//! forces it.
//!
//! Written against the 2026-07-28 revision and only that one. `04 §8` OQ-4
//! recommends keeping a compatibility path for `2025-11-25` behind a flag; this
//! build does not have one, and the reason is in [`crate::MCP_PROTOCOL_VERSION`]:
//! the two are not wire compatible, and shipping half of the older one would be
//! worse than shipping none of it.

pub mod format;
pub mod manifest;
pub mod server;

pub use manifest::{TOOLS_CACHE_SCOPE, TOOLS_TTL_MS, TOOL_COUNT};
pub use server::{Server, WAIT_CLAMP_MS};
