//! # rdp-codecs
//!
//! RDP bitmap decoders as pure functions over slices into caller owned
//! buffers: interleaved RLE, planar, RemoteFX, ClearCodec, NSCodec,
//! progressive, AVC420 metablock parsing and MPPC (PRDRDP/04 §4, PRDRDP/12
//! §2.2.2).
//!
//! The codec payload boundary: `rdp-pdu` parses down to the first byte of a
//! codec's own bitstream and stops. Everything inside that bitstream is here.
//! The practical test in review is the one PRDRDP/12 §2.2.2 gives: if a
//! structure's length comes from an outer PDU field it belongs to `rdp-pdu`,
//! and if it is self describing inside the payload it belongs here.
//!
//! ## What phase 1a contains
//!
//! Uncompressed legacy bitmaps ([`uncompressed`]), interleaved RLE at 8, 15,
//! 16 and 24 bits per pixel ([`rle`]) and the planar codec with its RLE planes
//! and delta encoding ([`planar`]). Those three put the first pixels on screen
//! (PRDRDP/10 §3.6). RemoteFX, ClearCodec, NSCodec, progressive, AVC420 and
//! MPPC are stubs carrying their spec citations until phase 1b and phase 2.
//!
//! ## The five crate rules (PRDRDP/04 §4.1)
//!
//! 1. Bounds checked by construction. Every read of remote bytes goes through
//!    [`Reader`], whose every method returns `Result` rather than indexing.
//! 2. Pure functions into caller owned buffers. No decoder allocates per call.
//!    The one piece of per codec state phase 1a needs is
//!    [`planar::PlanarScratch`], which the caller pools and reuses.
//! 3. Persistent state is explicit and resettable: `new`, `reset`, `bytes`.
//! 4. `#![forbid(unsafe_code)]`, and therefore no intrinsics. Speed comes from
//!    hoisting the bounds check out of the loop and letting LLVM auto
//!    vectorise (PRDRDP/04 §4.6.8). Each hot loop says in a comment which of
//!    the §4.6.8 rules it is relying on.
//! 5. Every entry point survives a truncated or adversarial input: it returns
//!    `Err`, it never panics, and it never loops without consuming input.
//!    Each decoder module carries the prefix test that proves it.
#![forbid(unsafe_code)]

mod dst;
mod reader;

pub mod planar;
pub mod rle;
pub mod uncompressed;

// Phase 1b and phase 2 stubs. They exist so the shape of the crate is visible
// and so the module a later commit fills in is already named and cited.
pub mod avc420;
pub mod clear;
pub mod mppc;
pub mod nscodec;
#[cfg(feature = "progressive")]
pub mod progressive;
pub mod remotefx;

#[cfg(any(test, feature = "encode"))]
pub mod encode;

pub use dst::{DstView, OutFormat, Palette, PixelFormat, RowOrder};
pub use reader::Reader;

/// Everything that can go wrong inside a codec payload (PRDRDP/04 §4.1).
///
/// One enum for the crate, because a caller that has to match on eleven codec
/// specific error types will match on none of them. `rdp-core` distinguishes
/// exactly one variant: [`DecodeError::StateLost`] means "repaint needed"
/// rather than "fail the session".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The bitstream ended in the middle of a field.
    #[error("input truncated in {what}")]
    Truncated { what: &'static str },
    /// A field parsed cleanly and then said something impossible: a run that
    /// overruns the bitmap, a reserved bit that is set, a colour depth the
    /// codec is not defined for.
    #[error("{what}: value {got} out of range")]
    Range { what: &'static str, got: u32 },
    /// The caller's destination buffer cannot hold the decoded image.
    #[error("output buffer too small: need {need}, have {have}")]
    Dst { need: usize, have: usize },
    /// A configured limit would be exceeded. Phase 1a never returns this; the
    /// ClearCodec and progressive caches do.
    #[error("{0} exceeds the configured budget")]
    Budget(&'static str),
    /// Cross call codec state is missing or out of sequence.
    #[error("codec state lost: {0}")]
    StateLost(&'static str),
}
