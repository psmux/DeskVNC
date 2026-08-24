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
//! (PRDRDP/10 §3.6).
//!
//! ## What phase 2 added
//!
//! [`remotefx`], the wavelet codec, split into the four stages PRDRDP/04
//! §11.2 budgets separately: [`remotefx::rlgr`], [`remotefx::quant`],
//! [`remotefx::dwt`] and [`remotefx::ycbcr`]. [`nscodec`], the planar YCoCg
//! codec ClearCodec's subcodec layer carries. [`clear`], with its glyph cache
//! and its two VBar caches. And [`zgfx`], the RDP 8.0 bulk decompressor every
//! EGFX byte arrives inside, which is why it goes first of the four
//! (PRDRDP/04 §4.12).
//!
//! ## What this commit added
//!
//! [`avc420`] and [`mppc`], the two remaining phase 2 modules.
//!
//! [`avc420`] is the smallest module in the crate and the reason is the point
//! of it: `RFX_AVC420_BITMAP_STREAM` is a metablock and an H.264 Annex B
//! access unit, and **the access unit is not decoded here**. It goes to the
//! webview's WebCodecs decoder over the rect format `src-tauri/FRAME_FORMAT.md`
//! has carried since the VNC side shipped Open H.264 (PRDRDP/04 §5.2,
//! `AGENT_BRIEF` D4). So the module parses four fields into borrowed slices,
//! allocates nothing, and scans the access unit once for an IDR.
//!
//! [`mppc`] is the legacy path's bulk decompressor: RDP 4.0 at 8 KiB of
//! history and RDP 5.0 at 64 KiB, a real bit level decoder over a linear
//! history whose output is the history. RDP 6.0 and RDP 6.1 are a different
//! scheme entirely (MS-RDPEGDI 3.1.8.1 and 3.1.8.2) and are refused by name
//! rather than guessed at; the module comment says why.
//!
//! ## What the progressive commit added
//!
//! [`progressive`], nominally phase 3 and pulled forward because it was the
//! most likely way a real Windows host ends a session. `docs/RDP_SPEC_NOTES.md`
//! §1.6 has the argument: progressive is available from EGFX capability
//! version 8, which is what we advertise, and no capability bit declines it at
//! any version, so a server may simply send it. It is compiled by default for
//! that reason; the `progressive` feature is still there and
//! `--no-default-features` turns it off.
//!
//! It is split the way [`remotefx`] is, with the stages it does not share in
//! their own modules: [`progressive::bands`] for the two subband layouts,
//! [`progressive::dwt`] for the extrapolated wavelet, [`progressive::srl`] for
//! the upgrade pass and [`progressive::state`] for the per tile store. What it
//! does share it shares as calls: RLGR1, the quantization value parsing, the
//! plain layout's differential decode, dequantization and whole inverse
//! wavelet, the clip region, the tile blit, the colour transform and the
//! scratch buffers.
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

mod reader;

pub mod planar;
pub mod rle;
pub mod uncompressed;

// Phase 1b, phase 2, and the one phase 3 module that was pulled forward.
pub mod avc420;
pub mod clear;
pub mod mppc;
pub mod nscodec;
#[cfg(feature = "progressive")]
pub mod progressive;
pub mod remotefx;
pub mod zgfx;

#[cfg(any(test, feature = "encode"))]
pub mod encode;

// The destination abstraction and the pixel conversion live in
// `remote-pixel` (PRDRDP/00 R37, PRDRDP/04 §4.2), which is a leaf crate with
// no dependencies at all, so `rdp-codecs` can take it and still have no tokio
// (D12). They are re-exported here at the names this crate has always used,
// so no call site and no test changed with the move.
//
// `remote_pixel::Format` is `PixelFormat` here because there is only one
// notion of a wire pixel layout inside a codec payload. In `remote-pixel` it
// has to share the module with the open ended RFB `PixelFormat`, which this
// crate never sees.
pub use remote_pixel::Format as PixelFormat;
pub use remote_pixel::{DstView, OutFormat, Palette, PixelError, RowOrder};

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

/// The three [`PixelError`] variants map one for one onto the three
/// [`DecodeError`] variants they came from, so moving the conversion into
/// `remote-pixel` changed no error a caller can observe (PRDRDP/00 R37).
///
/// This impl is why `remote-pixel` can stay dependency free: it carries the
/// error shape and this crate puts the `thiserror` derive on it.
impl From<PixelError> for DecodeError {
    fn from(e: PixelError) -> Self {
        match e {
            PixelError::Truncated { what } => DecodeError::Truncated { what },
            PixelError::Range { what, got } => DecodeError::Range { what, got },
            PixelError::Dst { need, have } => DecodeError::Dst { need, have },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The move to `remote-pixel` (PRDRDP/00 R37) put the destination checks
    /// behind a crate boundary and a `From`. This is the test that the errors
    /// a caller sees did not change on the way: the same three variants, the
    /// same payloads, the same `Display` text `thiserror` generates.
    #[test]
    fn the_pixel_errors_arrive_as_the_decode_errors_they_always_were() {
        assert_eq!(
            DecodeError::from(PixelError::Truncated {
                what: "uncompressed bitmap"
            }),
            DecodeError::Truncated {
                what: "uncompressed bitmap"
            }
        );
        assert_eq!(
            DecodeError::from(PixelError::Range {
                what: "bitsPerPixel",
                got: 7
            }),
            DecodeError::Range {
                what: "bitsPerPixel",
                got: 7
            }
        );
        let e = DecodeError::from(PixelError::Dst { need: 64, have: 4 });
        assert_eq!(e, DecodeError::Dst { need: 64, have: 4 });
        assert_eq!(e.to_string(), "output buffer too small: need 64, have 4");
    }
}
