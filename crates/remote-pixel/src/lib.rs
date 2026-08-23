//! # remote-pixel
//!
//! Pixel format conversion, shared by every protocol so there is one
//! conversion rather than two that drift (PRDRDP/00 R37, PRDRDP/02 §13
//! commit 1b).
//!
//! This crate has no dependencies at all, deliberately: `rdp-codecs` takes it
//! and may not acquire tokio through it. That constraint is why
//! [`PixelFormat`] lives here rather than in `vnc-core`, and why it carries no
//! serde derives.
//!
//! ## Module map
//!
//! | Module        | Responsibility                                          |
//! |---------------|---------------------------------------------------------|
//! | [`format`]    | [`PixelFormat`], the RFB wire layout (RFB §7.4)         |
//! | [`convert`]   | Wire pixels to RGBA8888, true colour and indexed        |
//! | [`thumbnail`] | Box filter downscale for the host tiles                 |
//!
//! Phase 1 adds the stride, row order and caller owned destination parameters
//! PRDRDP/04 §4.2 specifies. This commit moved code and nothing else.
#![forbid(unsafe_code)]

pub mod convert;
pub mod format;
pub mod thumbnail;

pub use convert::{convert_to_rgba, convert_to_rgba_mapped, ColourMap};
pub use format::PixelFormat;
pub use thumbnail::downscale_rgba;
