//! # limb-core
//!
//! The contract a limb implements: what an agent may ask of a protocol, what
//! that protocol may say back, what gates both, and what the thing is called
//! (PRDAgentPlug/02).
//!
//! ## Where this sits
//!
//! `02 §1` was written when `01 §3.1` had collapsed this material into
//! `remote-core` behind a cargo feature. The workspace took the other road and
//! the root `Cargo.toml` records why: `agent-lease` is arbitration and knows
//! nothing about limbs, `limb-core` is the contract and depends only on
//! `remote-core`, and neither depends on tauri so the plane is reachable from
//! a headless binary (`03 §1`). Everything `02` spells `remote_core::agent`
//! is spelled `limb_core` here and nothing else about it changes.
//!
//! This crate depends on `remote-core` and on no protocol crate. It parses no
//! remote bytes, opens no sockets and spawns no tasks. Every decision it makes
//! is a pure function of what it was handed, which is the same discipline
//! `agent-lease` follows for the same reason: the rules are testable without a
//! runtime.
//!
//! ## Module map
//!
//! | Module           | Responsibility                                            |
//! |------------------|-----------------------------------------------------------|
//! | [`identity`]     | [`LimbId`], the reproducible name of a machine at a slot  |
//! | [`fence`]        | [`GeometryGeneration`], and why a stale actuation is typed |
//! | [`capability`]   | [`Capability`], the canonical seventeen (`00 R20`)        |
//! | [`intent`]       | [`AgentIntent`], one wrapping variant (`00 R28`)          |
//! | [`keys`]         | Typing and named keys, keysym only (`00 R8`)              |
//! | [`observation`]  | [`Observation`], and [`Untrusted`] at the boundary        |
//! | [`availability`] | The envelope with no `value` key unless live (`00 R42`)   |
//! | [`limb`]         | The [`Limb`] trait itself                                 |
//! | [`party`]        | Who asked: the two names shared with `agent-lease`        |
//!
//! Every public item is re-exported at the crate root, matching `remote-core`,
//! whose call sites are flat for the same reason.

// Nothing here touches a raw pointer and nothing here ever will, but every
// crate in this workspace that could carries the attribute and the consistency
// is worth more than the exception.
#![forbid(unsafe_code)]

pub mod availability;
pub mod capability;
pub mod fence;
pub mod identity;
pub mod intent;
pub mod keys;
pub mod limb;
pub mod observation;
pub mod party;

pub use availability::*;
pub use capability::*;
pub use fence::*;
pub use identity::*;
pub use intent::*;
pub use keys::*;
pub use limb::*;
pub use observation::*;
pub use party::*;

/// The session contract this one extends, re-exported so a limb crate needs
/// one dependency line rather than two. The same courtesy `remote-core`
/// already does for `vnc-transport`.
pub use remote_core;

// The `remote-core` types that appear in this crate's own public signatures,
// re-exported flat beside them. A caller reading `LimbId::derive` should not
// have to work out which of two crates `ProtocolKind` lives in, and a limb
// author lowering an intent should not have to import `ClientCommand` from a
// different path than the intent it is lowering.
pub use remote_core::commands::ClientCommand;
pub use remote_core::driver::ProtocolKind;
pub use remote_core::events::ScreenInfo;
pub use remote_core::geometry::Rect;
pub use remote_core::options::QualityPreset;
pub use remote_core::stats::SessionStats;
