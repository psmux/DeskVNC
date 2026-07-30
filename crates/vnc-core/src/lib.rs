//! # vnc-core
//!
//! UI-agnostic RFB (VNC) protocol core for DeskVNCViewer.
//!
//! This crate MUST NOT depend on Tauri or any UI framework, it is the durable
//! layer that outlives frontend choices (see PRD/01-architecture.md §1).
//!
//! ## Module map
//!
//! | Module       | Responsibility                                              |
//! |--------------|-------------------------------------------------------------|
//! | [`types`]    | Shared contract types (the integration surface)             |
//! | [`error`]    | Error taxonomy + transient/fatal classification             |
//! | [`pixel`]    | Framebuffer, pixel conversion, damage tracking              |
//! | [`proto`]    | RFB handshake, message framing, read/write loops            |
//! | [`security`] | Authentication: VncAuth, VeNCrypt, RA2, Apple DH, MSLogonII |
//! | [`encodings`]| Rect decoders: Raw, CopyRect, Hextile, zlib, Tight, ZRLE    |
//! | [`input`]    | Keysym mapping, scancodes, pointer encoding                 |
//! | [`clipboard`]| Legacy + Extended Clipboard state machine                   |
//! | [`quality`]  | Preset resolution + adaptive Auto tuner                     |
//! | [`session`]  | Session task, event loop, auto-reconnect supervision         |

// This crate parses bytes controlled by a remote peer. Memory safety here is
// enforced by the compiler rather than by review.
#![forbid(unsafe_code)]

pub mod clipboard;
pub mod encodings;
pub mod error;
pub mod input;
pub mod pixel;
pub mod proto;
pub mod quality;
pub mod security;
pub mod session;
pub mod types;

pub use error::{Result, VncError};
pub use session::{Session, SessionHandle};
pub use types::*;
