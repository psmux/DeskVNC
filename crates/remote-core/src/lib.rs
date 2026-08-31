//! # remote-core
//!
//! The protocol agnostic session contract. Every protocol crate depends on
//! this one; this one depends on no protocol crate, no UI framework and no
//! Tauri. It was extracted from `vnc-core/src/types.rs` in phase 0 of the RDP
//! work (PRDRDP/02), so most of what is here is the same code at a new path.
//!
//! ## Module map
//!
//! | Module          | Responsibility                                          |
//! |-----------------|---------------------------------------------------------|
//! | [`geometry`]    | [`Rect`]                                                |
//! | [`pins`]        | Trust on first use pins, one per key scheme             |
//! | [`credentials`] | Credentials and the interactive credential request      |
//! | [`options`]     | What the shell hands a driver to start a session        |
//! | [`state`]       | [`SessionState`], the lifecycle the UI renders          |
//! | [`events`]      | What a session tells the shell                          |
//! | [`commands`]    | What the shell tells a session                          |
//! | [`intent`]      | What an agent wants done (PRDAgentPlug/00 R28)          |
//! | [`keys`]        | The named key table an intent presses by name           |
//! | [`stats`]       | Per tick measurements                                   |
//! | [`driver`]      | Protocol identity, the session handle, the event sink   |
//! | [`reconnect`]   | The retry ladder, shared by every protocol              |
//!
//! Every public item is re-exported at the crate root, because
//! `vnc_core::types` re-exports this crate with a glob and its call sites are
//! flat (`vnc_core::Rect`, `vnc_core::CertPins`). The modules stay public so a
//! reader has somewhere to look.

// This crate does not parse remote bytes, but every crate in this workspace
// that could carries the attribute and the consistency is worth more than the
// exception.
#![forbid(unsafe_code)]

pub mod commands;
pub mod credentials;
pub mod driver;
pub mod events;
pub mod geometry;
pub mod intent;
pub mod keys;
pub mod options;
pub mod pins;
pub mod reconnect;
pub mod state;
pub mod stats;

pub use commands::*;
pub use credentials::*;
pub use driver::*;
pub use events::*;
pub use geometry::*;
pub use intent::*;
pub use keys::*;
pub use options::*;
pub use pins::*;
pub use state::*;
pub use stats::*;

/// The transport crate, re-exported so a protocol crate needs one dependency
/// line rather than two. It is called `vnc-transport` for historical reasons
/// and is protocol neutral in substance; PRDRDP/00 R30 rules out renaming it
/// before phase 3.
pub use vnc_transport as transport;
pub use vnc_transport::{BoxedStream, Stream, StreamConnector, TrustDecision};
