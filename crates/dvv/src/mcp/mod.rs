//! The MCP adapter.
//!
//! `04 §1.1`: **MCP is an adapter. It is not the contract.** Its job is to turn
//! a `tools/call` into one call on [`crate::plane::Plane`], turn the answer into
//! a `CallToolResult`, and add nothing. The three places it does add something
//! are named at the top of [`server`], and each is there because MCP's shape
//! forces it.
//!
//! Written against the 2026-07-28 revision, and it answers the `initialize`
//! handshake of every revision before it as well, with no flag. The history of
//! that decision is on [`crate::MCP_PROTOCOL_VERSION`]; the short form is that
//! the client the README names opens with `initialize`, and a server that
//! refused it was a server nobody could reach.

pub mod format;
pub mod manifest;
pub mod server;

pub use manifest::{TOOLS_CACHE_SCOPE, TOOLS_TTL_MS, TOOL_COUNT};
pub use server::{Server, FILE_WINDOW_BYTES, INLINE_GET_BYTES, WAIT_CLAMP_MS};
