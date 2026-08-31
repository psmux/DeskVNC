//! Turning a piece of the mirror into an image a model can be handed.
//!
//! `03 §5` and `00 R43`. Three decisions are made here and each one is a
//! measurement somebody else published, not a preference.
//!
//! **The long edge is 1456 by default.** A vision model reads an image as
//! 28x28 patches, so it costs `ceil(w / 28) * ceil(h / 28)` visual tokens, and
//! a standard tier model resizes anything over a 1568 px long edge before it
//! looks at it. A 1920x1080 screenshot lands at 1456x819 either way, so 1456
//! is the size at which we hand over the exact image the provider would have
//! made itself, with our box filter instead of theirs and, far more
//! importantly, with a scale factor **we** chose and can invert exactly. That
//! is `00 R43`'s WA-11: never send an image the provider will resize.
//!
//! **A 4K screenshot and a 1080p one cost the same on a standard tier model.**
//! Both land at 1456x819 and 1560 tokens. So sending 4K is pure waste: the
//! same price, worse legibility after a 2.6 times downscale, and 33 MB of
//! pixels pushed through our own pipeline to get there.
//!
//! **PNG by default, JPEG on request.** Format does not change the token
//! count at all, which is a function of pixel dimensions only. It changes
//! bytes on the wire and it changes legibility, and a remote desktop is mostly
//! text and flat chrome, which is JPEG's worst case. The vision documentation
//! warns in terms that heavy JPEG compression makes text hard to read.
//!
//! One honesty note that `03 §5.3` insists on: on a session running Tight with
//! JPEG rects, a PNG of the mirror is a lossless encode of already lossy
//! pixels. We add no generation of loss and we also do not deliver what PNG
//! usually promises.
//!
//! The downscale is `remote_pixel::downscale_rgba`, the same box filter the
//! host tiles already use. `03 §4.3` measures it at 2.9 ms to 25 ms depending
//! on source size, single threaded, which is why the caller must run this off
//! any latency path exactly as `capture_thumbnail` already does
//! (`src-tauri/src/commands/session.rs:1648`).

use crate::transform::ImageSpace;
use image::{ExtendedColorType, ImageEncoder};
use remote_core::geometry::Rect;
use serde::Serialize;

/// `03 §5.2`: the size a standard tier model would have resized us to anyway.
pub const DEFAULT_LONG_EDGE: u32 = 1456;

/// `03 §5.2`: the high resolution tier's limit, opt in and charged for
/// honestly in the tool description.
pub const HIGH_RES_LONG_EDGE: u32 = 2576;

/// The quality `03 §8` spike S3-5 will publish its byte table at, so the
/// default and the measurement describe the same encoder.
pub const DEFAULT_JPEG_QUALITY: u8 = 80;

/// What a model is handed.
///
/// GIF and WebP are the two permitted formats not here. GIF is irrelevant to a
/// desktop. WebP costs a new dependency in a workspace that counts them and
/// its lossy mode has JPEG's text problem, so `03 §5.3` keeps it out of
/// version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageFormat {
    /// Lossless, so text stays crisp. The default.
    Png,
    /// Smaller on photographic content and worse on everything a desktop
    /// mostly shows.
    Jpeg,
}

impl ImageFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            ImageFormat::Png => "png",
            ImageFormat::Jpeg => "jpeg",
        }
    }
}

/// How to encode, kept apart from what to encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOptions {
    pub format: ImageFormat,
    /// Ignored for PNG. A separate field rather than a payload on
    /// [`ImageFormat::Jpeg`] so that the format is one word on the wire, which
    /// is what `03 §4.3`'s response shape says it is.
    pub jpeg_quality: u8,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        EncodeOptions {
            format: ImageFormat::Png,
            jpeg_quality: DEFAULT_JPEG_QUALITY,
        }
    }
}

/// An encoded image and the exact way back to framebuffer coordinates.
///
/// The bytes and the transform are one value on purpose (`00 R43`). An API
/// that returns the image and lets the caller ask for the scale separately is
/// an API where somebody forgets.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EncodedImage {
    pub format: ImageFormat,
    /// Where this came from and how to get back. `03 §9 A8` requires it on
    /// every response at every rung.
    pub space: ImageSpace,
    /// The encoded file. Base64 or otherwise framing it is the attachment
    /// surface's job (`04`), not this crate's.
    #[serde(skip)]
    pub bytes: Vec<u8>,
    /// Length of `bytes`, which is the part worth putting on the wire when the
    /// payload itself is carried out of band.
    pub encoded_bytes: usize,
}

/// Copy a rectangle out of an RGBA8888 framebuffer, tightly packed.
///
/// The rect is expected to be clipped already. It is clipped again here
/// anyway, for the reason `framebuffer.rs` gives in its own module comment: a
/// malformed rect can never read out of bounds, and the caller that forgot is
/// always the next one.
pub fn crop_rgba(src: &[u8], fb_width: u16, fb_height: u16, rect: Rect) -> Vec<u8> {
    let fb = Rect::new(0, 0, fb_width, fb_height);
    let r = rect.intersect(&fb);
    let stride = fb_width as usize * 4;
    let row_bytes = r.width as usize * 4;
    let mut out = vec![0u8; row_bytes * r.height as usize];
    for row in 0..r.height as usize {
        let s = (r.y as usize + row) * stride + r.x as usize * 4;
        if s + row_bytes > src.len() {
            break;
        }
        out[row * row_bytes..(row + 1) * row_bytes].copy_from_slice(&src[s..s + row_bytes]);
    }
    out
}

/// Downscale so that neither edge exceeds `long_edge`, and report the scale.
///
/// `remote_pixel::downscale_rgba` bounds the WIDTH, which is right for a host
/// tile and wrong for a portrait crop, so the target width is derived from the
/// long edge first. A 3 x 1080p desktop is 5760x1080 and its long edge is
/// three screens wide, which is exactly the case `03 §7.2` says a full frame
/// cannot answer: this will happily produce a 1456x273 image, and the honest
/// response to that is `03 §4.4`'s region, not a sharper filter.
///
/// The returned scale is the horizontal one. The box filter derives the output
/// height from the output width by a rounded division, so the vertical scale
/// differs from it by at most half an output pixel, and `00 R43`'s transform
/// takes one `s`. Half an output pixel at 1456 wide is a quarter of a source
/// pixel at 1080p, which is inside the half pixel bias the ruling already
/// accounts for.
pub fn downscale_to_long_edge(
    rgba: &[u8],
    width: u32,
    height: u32,
    long_edge: u32,
) -> (u32, u32, Vec<u8>, f64) {
    if width == 0 || height == 0 || long_edge == 0 {
        return (0, 0, Vec::new(), 1.0);
    }
    if width.max(height) <= long_edge {
        let needed = width as usize * height as usize * 4;
        return (width, height, rgba[..needed.min(rgba.len())].to_vec(), 1.0);
    }
    let max_width = if width >= height {
        long_edge
    } else {
        // Round to nearest so a 1080x1920 portrait crop lands on the long edge
        // rather than one pixel under it.
        (((width as u64 * long_edge as u64) + height as u64 / 2) / height as u64).max(1) as u32
    };
    let (w, h, out) = remote_pixel::downscale_rgba(rgba, width, height, max_width);
    if w == 0 || h == 0 {
        return (0, 0, Vec::new(), 1.0);
    }
    (w, h, out, f64::from(w) / f64::from(width))
}

/// Encode RGBA8888 as PNG or JPEG.
pub fn encode_rgba(
    rgba: &[u8],
    width: u32,
    height: u32,
    options: EncodeOptions,
) -> Result<Vec<u8>, EncodeFailed> {
    let needed = width as usize * height as usize * 4;
    if width == 0 || height == 0 || rgba.len() < needed {
        return Err(EncodeFailed {
            format: options.format,
            width,
            height,
            because: format!(
                "{} bytes of RGBA for a {width}x{height} image, which needs {needed}",
                rgba.len()
            ),
        });
    }
    let mut out = Vec::new();
    let result = match options.format {
        ImageFormat::Png => image::codecs::png::PngEncoder::new(&mut out).write_image(
            &rgba[..needed],
            width,
            height,
            ExtendedColorType::Rgba8,
        ),
        ImageFormat::Jpeg => {
            // JPEG has no alpha channel and `image`'s encoder refuses RGBA
            // rather than dropping it silently, which is the right call and
            // means the drop happens here where it can be explained. A mirror
            // is opaque by construction: `Framebuffer` fills with opaque black
            // and every rect that reaches it is opaque, so nothing is lost.
            let mut rgb = Vec::with_capacity(needed / 4 * 3);
            for px in rgba[..needed].chunks_exact(4) {
                rgb.extend_from_slice(&px[..3]);
            }
            image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, options.jpeg_quality)
                .write_image(&rgb, width, height, ExtendedColorType::Rgb8)
        }
    };
    result.map_err(|e| EncodeFailed {
        format: options.format,
        width,
        height,
        because: e.to_string(),
    })?;
    Ok(out)
}

/// Decode a JPEG rect into RGBA8888.
///
/// The mirror needs this because Tight sends lossy rects and
/// `Framebuffer::apply` composites them (`framebuffer.rs:67`). `03 §2.3` names
/// the cost and it is the expensive part of mirroring, not the memcpy: the
/// webview decodes the same bytes through `createImageBitmap` on hardware
/// while we decode them again in software on the CPU that is already running
/// every other session. Spike S3-1 is that measurement.
pub fn decode_jpeg_to_rgba(bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), DecodeFailed> {
    let decoder = image::codecs::jpeg::JpegDecoder::new(std::io::Cursor::new(bytes))
        .map_err(|e| DecodeFailed(e.to_string()))?;
    let decoded =
        image::DynamicImage::from_decoder(decoder).map_err(|e| DecodeFailed(e.to_string()))?;
    let rgba = decoded.to_rgba8();
    Ok((rgba.width(), rgba.height(), rgba.into_raw()))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("could not encode a {width}x{height} image as {format}: {because}")]
pub struct EncodeFailed {
    pub format: ImageFormat,
    pub width: u32,
    pub height: u32,
    pub because: String,
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A JPEG rect the mirror could not decode.
///
/// It is an error rather than a warning here, and the mirror answers it by
/// marking the region STALE. `Framebuffer::apply` logs and moves on
/// (`framebuffer.rs:83`), which is right for a renderer a person is watching,
/// because the next update repaints it and a person sees the glitch. It is the
/// same silent staleness as `00 R6` for an agent, which is not watching.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("could not decode a JPEG rectangle: {0}")]
pub struct DecodeFailed(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: u32, h: u32, colour: [u8; 4]) -> Vec<u8> {
        colour.repeat(w as usize * h as usize)
    }

    #[test]
    fn png_round_trips_through_the_decoder_it_was_written_for() {
        let rgba = solid(8, 4, [12, 34, 56, 255]);
        let png = encode_rgba(&rgba, 8, 4, EncodeOptions::default()).unwrap();
        assert_eq!(&png[1..4], b"PNG");
    }

    #[test]
    fn jpeg_drops_alpha_rather_than_refusing() {
        let rgba = solid(16, 16, [200, 100, 50, 255]);
        let jpeg = encode_rgba(
            &rgba,
            16,
            16,
            EncodeOptions {
                format: ImageFormat::Jpeg,
                jpeg_quality: DEFAULT_JPEG_QUALITY,
            },
        )
        .unwrap();
        let (w, h, back) = decode_jpeg_to_rgba(&jpeg).unwrap();
        assert_eq!((w, h), (16, 16));
        assert_eq!(back[3], 255);
    }

    #[test]
    fn a_portrait_crop_is_bounded_by_its_long_edge() {
        let rgba = solid(100, 400, [1, 2, 3, 255]);
        let (w, h, _, scale) = downscale_to_long_edge(&rgba, 100, 400, 200);
        assert_eq!(h, 200);
        assert_eq!(w, 50);
        assert!((scale - 0.5).abs() < 1e-9);
    }

    #[test]
    fn an_image_already_small_enough_is_not_touched() {
        let rgba = solid(10, 10, [9, 9, 9, 255]);
        let (w, h, out, scale) = downscale_to_long_edge(&rgba, 10, 10, 1456);
        assert_eq!((w, h, scale), (10, 10, 1.0));
        assert_eq!(out, rgba);
    }
}
