//! Wire to surface: routing one `bitmapData` to the decoder that owns it
//! (MS-RDPEGFX 2.2.2.1, PRDRDP/04 §3.4).
//!
//! # The boundary
//!
//! `rdp-pdu` parses down to the first byte of a codec's own bitstream and
//! stops (`crates/rdp-pdu/src/vc/mod.rs:39`). Everything past that byte is
//! `rdp-codecs`'. This file is the twenty lines between them: it turns a
//! `codecId` into a call, and it owns nothing else.
//!
//! # The one copy
//!
//! Every arm below hands the decoder two things: a `&[u8]` borrowed from the
//! decompressed EGFX message, and a [`DstView`] over the destination surface
//! carrying the surface's own stride. There is no rectangle sized buffer in
//! between, so the decoder's write into the surface is the only time these
//! pixels are written (D9, PRDRDP/04 §4.2).
//!
//! # Every scratch is allocated once
//!
//! [`Decoders`] is created with the channel and lives as long as it. The
//! RemoteFX coefficient scratch is 4 * 4096 * 2 bytes, ClearCodec carries a
//! glyph cache and two VBar caches, and the planar decoder carries its plane
//! buffers; all of them grow to their working size on the first frame and are
//! reused for every frame after it (PRDRDP/04 §4.1 rule two).

use rdp_codecs::{
    clear, planar, remotefx, uncompressed, DecodeError, DstView, Palette, PixelFormat,
};
use rdp_pdu::vc::egfx::{codec_id, pixel_format};

use crate::error::{RdpError, Result};

/// Every decoder's cross call state, allocated with the channel.
pub struct Decoders {
    /// RemoteFX's negotiated entropy algorithm and tile size, which are per
    /// channel and can change mid session (MS-RDPRFX 2.2.2.2.4).
    rfx: remotefx::RfxContext,
    rfx_scratch: remotefx::RfxScratch,
    planar: planar::PlanarScratch,
    clear: clear::ClearDecoder,
    /// The palette an uncompressed EGFX rectangle never uses.
    ///
    /// [`uncompressed::decode`] takes one because the same function serves the
    /// legacy 8 bit path, and EGFX has no indexed pixel format at all
    /// (MS-RDPEGFX 2.2.2.1 defines only the two 32 bit ones). It is here so
    /// the call site does not build a fresh 1 KiB table per rectangle.
    palette: Palette,
}

/// Hand written because none of the codec state types is `Debug` and none of
/// them should be: printing a 2.5 MB history window or a ClearCodec glyph
/// cache into a log line helps nobody. The same call
/// `crate::session::graphics::Graphics` makes at
/// `crates/rdp-core/src/session/graphics.rs:77`.
impl std::fmt::Debug for Decoders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoders")
            .field("bytes", &self.bytes())
            .finish()
    }
}

impl Default for Decoders {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoders {
    /// Allocate every codec's scratch once.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rfx: remotefx::RfxContext::new(),
            rfx_scratch: remotefx::RfxScratch::with_capacity(),
            planar: planar::PlanarScratch::new(),
            clear: clear::ClearDecoder::new(),
            palette: Palette::default(),
        }
    }

    /// Bytes of decoder state this channel holds, for the stats line.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.rfx.bytes() + self.rfx_scratch.bytes() + self.planar.bytes() + self.clear.bytes()
    }

    /// Drop every cross call cache and keep the buffers.
    ///
    /// `RDPGFX_RESET_GRAPHICS` restarts the graphics session, and a
    /// ClearCodec glyph cache or a RemoteFX context carried across it decodes
    /// the next frame against state the server has already forgotten
    /// (MS-RDPEGFX 3.3.5.13).
    pub fn reset(&mut self) {
        self.rfx.reset();
        self.rfx_scratch.reset();
        self.planar.reset();
        self.clear.reset();
    }
}

/// Decode one `RDPGFX_WIRE_TO_SURFACE_PDU_1` payload into `dst`.
///
/// `surface_alpha` is the destination surface's own pixel format: true for
/// `GFX_PIXEL_FORMAT_ARGB_8888`, where the alpha a codec produces is
/// meaningful. `pixel_fmt` is the one the command itself named, which
/// MS-RDPEGFX 2.2.2.1 allows to differ from the surface's.
///
/// # Errors
///
/// [`RdpError::Protocol`] naming the codec and the geometry, for both a codec
/// this build does not decode and a bitstream the decoder refused. Neither
/// message carries a byte of the bitstream (PRDRDP/12 §6.4).
pub fn wire_to_surface(
    codec: u16,
    pixel_fmt: u8,
    surface_alpha: bool,
    src: &[u8],
    decoders: &mut Decoders,
    dst: &mut DstView<'_>,
) -> Result<()> {
    let (w, h) = (dst.width(), dst.height());
    match codec {
        // MS-RDPEGFX 2.2.2.1: an uncompressed payload is 32 bits per pixel,
        // top down, with rows packed to `width * 4` and no DIB padding.
        codec_id::UNCOMPRESSED => {
            let fmt = if wants_alpha(pixel_fmt, surface_alpha) {
                PixelFormat::BgrA32
            } else {
                PixelFormat::BgrX32
            };
            let stride = usize::from(w) * 4;
            uncompressed::decode(fmt, src, stride, &decoders.palette, dst)
                .map_err(|e| refused("uncompressed", w, h, &e))
        }
        codec_id::PLANAR => planar::decode(
            src,
            wants_alpha(pixel_fmt, surface_alpha),
            &mut decoders.planar,
            dst,
        )
        .map_err(|e| refused("planar", w, h, &e)),
        codec_id::CLEARCODEC => decoders
            .clear
            .decode(src, dst)
            .map_err(|e| refused("clearcodec", w, h, &e)),
        // `RDPGFX_CODECID_CAVIDEO` is RemoteFX (MS-RDPEGFX 2.2.2.1). The
        // frame descriptor it returns is for the caller's damage tracking on
        // the Surface Bits path; inside EGFX the `destRect` already said
        // where the pixels went, so it is dropped here.
        codec_id::CAVIDEO => {
            remotefx::decode_message(src, &mut decoders.rfx, &mut decoders.rfx_scratch, dst)
                .map(|_| ())
                .map_err(|e| refused("remotefx", w, h, &e))
        }
        // H.264 arrived with capability set version 10 and we advertise 8
        // and 8.1 only (`crate::channels::egfx::ADVERTISED`), so a server
        // sending one is drawing with a codec the confirmed capability set
        // does not contain (MS-RDPEGFX 2.2.3.1, PRDRDP/04 §3.2).
        codec_id::AVC420 | codec_id::AVC444 | codec_id::AVC444V2 => {
            Err(RdpError::Protocol(format!(
                "the server sent an H.264 rectangle ({w}x{h}, codec 0x{codec:04x}); this \
                 client advertised graphics capability sets 8 and 8.1, which have no H.264 \
                 (MS-RDPEGFX 2.2.3.1)"
            )))
        }
        // MS-RDPEGFX 2.2.4.4's alpha codec. `rdp-codecs` has no decoder for
        // it, and a server only uses it for a surface it was told carries
        // alpha, so this is reachable and is named rather than guessed at.
        codec_id::ALPHA => Err(RdpError::Protocol(format!(
            "the server sent a {w}x{h} rectangle in the alpha codec, which this build \
             does not decode (MS-RDPEGFX 2.2.4.4)"
        ))),
        other => Err(RdpError::Protocol(format!(
            "the server sent a {w}x{h} rectangle in codec 0x{other:04x}, which this \
             client did not advertise (MS-RDPEGFX 2.2.2.1)"
        ))),
    }
}

/// Whether the alpha byte a codec produces should be kept.
///
/// It is kept only when both the command and the surface say ARGB. A command
/// that names ARGB into an XRGB surface has nowhere for the alpha to be
/// meaningful, and a command that names XRGB into an ARGB surface is telling
/// us its own alpha is padding.
fn wants_alpha(pixel_fmt: u8, surface_alpha: bool) -> bool {
    surface_alpha && pixel_fmt == pixel_format::ARGB_8888
}

/// One codec refusal, named and without a byte of the bitstream in it
/// (PRDRDP/12 §6.4).
///
/// The same shape as the legacy path's `codec_error`
/// (`crates/rdp-core/src/session/graphics.rs:371`), so a support log reads
/// the same whichever path the pixels came down.
fn refused(codec: &str, width: u16, height: u16, e: &DecodeError) -> RdpError {
    RdpError::Protocol(format!(
        "the {codec} decoder refused a {width}x{height} egfx rectangle: {e}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_codecs::{OutFormat, RowOrder};

    fn view(buf: &mut [u8], w: u16, h: u16) -> DstView<'_> {
        DstView::packed(buf, w, h, OutFormat::Rgba, RowOrder::TopDown).expect("view")
    }

    /// The uncompressed arm, which is the one every other test in this module
    /// leans on: 32 bits per pixel, B G R X on the wire, top down, no DIB
    /// padding. Two pixels of one row, so a stride mistake is visible.
    #[test]
    fn an_uncompressed_rectangle_arrives_in_rgba_order() {
        let mut decoders = Decoders::new();
        let mut buf = [0u8; 8];
        let src = [
            0x00, 0x00, 0xFF, 0x00, // blue channel 0, green 0, red 255
            0xFF, 0x00, 0x00, 0x00, // blue 255
        ];
        wire_to_surface(
            codec_id::UNCOMPRESSED,
            pixel_format::XRGB_8888,
            false,
            &src,
            &mut decoders,
            &mut view(&mut buf, 2, 1),
        )
        .expect("decodes");
        assert_eq!(buf, [0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF]);
    }

    /// The alpha byte is honoured only when the command and the surface both
    /// say ARGB, and forced opaque otherwise.
    #[test]
    fn alpha_needs_both_the_command_and_the_surface_to_ask_for_it() {
        assert!(wants_alpha(pixel_format::ARGB_8888, true));
        assert!(!wants_alpha(pixel_format::ARGB_8888, false));
        assert!(!wants_alpha(pixel_format::XRGB_8888, true));

        let mut decoders = Decoders::new();
        let src = [0x10, 0x20, 0x30, 0x40];

        let mut buf = [0u8; 4];
        wire_to_surface(
            codec_id::UNCOMPRESSED,
            pixel_format::ARGB_8888,
            true,
            &src,
            &mut decoders,
            &mut view(&mut buf, 1, 1),
        )
        .expect("decodes");
        assert_eq!(buf[3], 0x40, "the wire alpha survived");

        let mut buf = [0u8; 4];
        wire_to_surface(
            codec_id::UNCOMPRESSED,
            pixel_format::XRGB_8888,
            true,
            &src,
            &mut decoders,
            &mut view(&mut buf, 1, 1),
        )
        .expect("decodes");
        assert_eq!(buf[3], 0xFF, "an XRGB rectangle is opaque");
    }

    /// A truncated bitstream is a named refusal and never a panic, which is
    /// `rdp-codecs` rule five seen from this side of the boundary.
    #[test]
    fn a_truncated_bitstream_is_refused_by_name() {
        let mut decoders = Decoders::new();
        let mut buf = [0u8; 16];
        let err = wire_to_surface(
            codec_id::UNCOMPRESSED,
            pixel_format::XRGB_8888,
            false,
            &[0x00],
            &mut decoders,
            &mut view(&mut buf, 2, 2),
        )
        .expect_err("truncated");
        assert!(err.to_string().contains("uncompressed decoder"), "{err}");
        assert!(err.to_string().contains("2x2"), "{err}");
    }

    /// Every codec this build cannot decode says so by name rather than
    /// drawing nothing and leaving the user with a frozen region.
    #[test]
    fn a_codec_we_do_not_decode_names_itself() {
        let mut decoders = Decoders::new();
        let mut buf = [0u8; 4];
        for (codec, needle) in [
            (codec_id::AVC420, "H.264"),
            (codec_id::AVC444, "H.264"),
            (codec_id::AVC444V2, "H.264"),
            (codec_id::ALPHA, "alpha codec"),
            (0x4242, "0x4242"),
        ] {
            let err = wire_to_surface(
                codec,
                pixel_format::XRGB_8888,
                false,
                &[],
                &mut decoders,
                &mut view(&mut buf, 1, 1),
            )
            .expect_err("unsupported");
            assert!(err.to_string().contains(needle), "{codec:#x}: {err}");
        }
    }

    /// The scratch is allocated with the channel and survives a reset, which
    /// is what makes the per frame path allocation free.
    #[test]
    fn the_decoder_scratch_is_reusable_across_a_reset() {
        let mut decoders = Decoders::new();
        let before = decoders.bytes();
        assert!(before > 0, "the remotefx scratch is preallocated");
        decoders.reset();
        assert!(
            decoders.bytes() > 0,
            "a reset drops the caches and keeps the buffers"
        );
    }
}
