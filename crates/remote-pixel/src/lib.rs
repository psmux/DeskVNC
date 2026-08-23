//! # remote-pixel
//!
//! Pixel format conversion, shared by every protocol so there is one
//! conversion rather than two that drift (PRDRDP/00 R37, PRDRDP/02 §13
//! commit 1b).
//!
//! This crate has no dependencies at all, deliberately: `rdp-codecs` takes it
//! and may not acquire tokio through it. That constraint is why
//! [`PixelFormat`] lives here rather than in `vnc-core`, why it carries no
//! serde derives, and why [`PixelError`] is written out by hand rather than
//! derived with `thiserror`.
//!
//! ## Module map
//!
//! | Module        | Responsibility                                          |
//! |---------------|---------------------------------------------------------|
//! | [`format`]    | [`PixelFormat`] (RFB §7.4) and [`Format`] (PRDRDP/04 §4.2) |
//! | [`convert`]   | Wire pixels to RGBA8888 or BGRA8888, true colour and indexed |
//! | [`dst`]       | [`DstView`], the caller owned destination (PRDRDP/04 §4.2) |
//! | [`thumbnail`] | Box filter downscale for the host tiles                 |
//!
//! ## The two entry points, and why there are two
//!
//! [`convert_to_rgba`] returns a `Vec` per call and is what the RFB decoders
//! in `vnc-core/src/encodings/` want, because an RFB rect becomes a `Vec` at
//! the framing layer anyway. [`convert_image`] writes through a [`DstView`]
//! into a buffer the caller owns and pools, which is what PRDRDP/04 §4.2's
//! single copy rule requires of every RDP decoder. They share this crate and
//! nothing else: RFB negotiates arbitrary channel maxima and shifts through
//! [`PixelFormat`], RDP has the seven fixed layouts of [`Format`].
//!
//! ## What PRDRDP/04 §4.2's published signature is missing
//!
//! §4.2 gives `convert_image(fmt, src, src_stride, order, w, h, pal, dst)`.
//! Two parameters the destination side needs are not in it, and both are
//! folded into [`DstView`] here:
//!
//! * a destination channel order, because an EGFX surface is BGRA (§3.3) and
//!   a framebuffer rect is RGBA (§10.3), so without [`OutFormat`] the
//!   conversion needs a red and blue swap pass behind it;
//! * a destination stride, because a rect decoded straight into a larger
//!   framebuffer has a pitch that is not `width * 4`, so without it that case
//!   needs a packed scratch and a copy out.
//!
//! Both of those extra copies are the ones §4.2's own single copy rule
//! forbids, which is why the gaps are read as omissions rather than as
//! decisions.
#![forbid(unsafe_code)]

pub mod convert;
pub mod dst;
pub mod format;
pub mod thumbnail;

pub use convert::{
    convert_image, convert_row, convert_to_rgba, convert_to_rgba_mapped, ColourMap, Palette,
};
pub use dst::{put, DstView, OutFormat, PixelError, RowOrder, DST_BPP};
pub use format::{Format, PixelFormat};
pub use thumbnail::downscale_rgba;
