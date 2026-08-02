//! Pseudo-encoding rectangles arriving inside a FramebufferUpdate.
//!
//! These carry no framebuffer pixels; they signal capabilities, resizes,
//! cursor shapes, and similar out-of-band state (PRD/02 §3).

use crate::encodings::DecoderState;
use crate::error::{Result, VncError};
use crate::pixel::convert::pixel_to_rgba;
use crate::pixel::ColourMap;
use crate::proto::messages::{map_eof, read_exact_vec, Screen};
use crate::types::{encoding, CursorShape, PixelFormat, Rect, RectPayload};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Sanity cap on cursor dimensions (pixels). Real cursors are <= 256x256.
const MAX_CURSOR_AREA: usize = 1 << 20;
const MAX_DESKTOP_NAME_LEN: usize = 64 * 1024;

/// A fully parsed pseudo-encoding rectangle.
#[derive(Debug, Clone)]
pub enum PseudoRect {
    /// Legacy DesktopSize (-223). The caller MUST follow this with a
    /// non-incremental FramebufferUpdateRequest (and never do so for -308).
    DesktopSize {
        width: u16,
        height: u16,
    },
    /// ExtendedDesktopSize (-308). `reason`: 0 = server, 1 = this client,
    /// 2 = another client. `status` is meaningful only when reason == 1
    /// (0 ok, 1 prohibited, 2 out of resources, 3 invalid layout, 4 forwarded).
    ExtendedDesktopSize {
        reason: u16,
        status: u16,
        width: u16,
        height: u16,
        screens: Vec<Screen>,
    },
    DesktopName(String),
    LastRect,
    Cursor(CursorShape),
    /// QEMU LED state bitmask (bit0 CapsLock, bit1 NumLock, bit2 ScrollLock).
    LedState(u8),
    /// Capability acks with no payload.
    FenceCapable,
    ContinuousUpdatesCapable,
    QemuExtKeyCapable,
    ExtendedMouseButtonsCapable,
}

/// Whether `enc` is a pseudo-encoding this module handles.
pub fn is_pseudo(enc: i32) -> bool {
    matches!(
        enc,
        encoding::PSEUDO_DESKTOP_SIZE
            | encoding::PSEUDO_EXTENDED_DESKTOP_SIZE
            | encoding::PSEUDO_DESKTOP_NAME
            | encoding::PSEUDO_LAST_RECT
            | encoding::PSEUDO_CURSOR
            | encoding::PSEUDO_X_CURSOR
            | encoding::PSEUDO_CURSOR_WITH_ALPHA
            | encoding::PSEUDO_FENCE
            | encoding::PSEUDO_CONTINUOUS_UPDATES
            | encoding::PSEUDO_QEMU_LED_STATE
            | encoding::PSEUDO_QEMU_EXT_KEY_EVENT
            | encoding::PSEUDO_EXTENDED_MOUSE_BUTTONS
    )
}

/// Read and interpret one pseudo-encoding rectangle. `pf` is the pixel format
/// currently negotiated for the connection (Cursor payloads use it), and
/// `decoder` is the shared decoder state, CursorWithAlpha may share zlib
/// streams with ordinary data rects, so it must run through the same state.
pub async fn read_pseudo_rect<R>(
    reader: &mut R,
    rect: Rect,
    enc: i32,
    pf: &PixelFormat,
    decoder: &mut DecoderState,
) -> Result<PseudoRect>
where
    R: AsyncRead + Unpin + Send,
{
    match enc {
        encoding::PSEUDO_DESKTOP_SIZE => Ok(PseudoRect::DesktopSize {
            width: rect.width,
            height: rect.height,
        }),
        encoding::PSEUDO_EXTENDED_DESKTOP_SIZE => {
            let n = reader.read_u8().await.map_err(map_eof)? as usize;
            let mut pad = [0u8; 3];
            reader.read_exact(&mut pad).await.map_err(map_eof)?;
            let mut screens = Vec::with_capacity(n);
            for _ in 0..n {
                let id = reader.read_u32().await.map_err(map_eof)?;
                let x = reader.read_u16().await.map_err(map_eof)?;
                let y = reader.read_u16().await.map_err(map_eof)?;
                let width = reader.read_u16().await.map_err(map_eof)?;
                let height = reader.read_u16().await.map_err(map_eof)?;
                let flags = reader.read_u32().await.map_err(map_eof)?;
                screens.push(Screen {
                    id,
                    x,
                    y,
                    width,
                    height,
                    flags,
                });
            }
            Ok(PseudoRect::ExtendedDesktopSize {
                reason: rect.x,
                status: rect.y,
                width: rect.width,
                height: rect.height,
                screens,
            })
        }
        encoding::PSEUDO_DESKTOP_NAME => {
            let len = reader.read_u32().await.map_err(map_eof)? as usize;
            if len > MAX_DESKTOP_NAME_LEN {
                return Err(VncError::Protocol(format!(
                    "desktop name length {len} exceeds limit"
                )));
            }
            let bytes = read_exact_vec(reader, len).await?;
            Ok(PseudoRect::DesktopName(
                String::from_utf8_lossy(&bytes).into_owned(),
            ))
        }
        encoding::PSEUDO_LAST_RECT => Ok(PseudoRect::LastRect),
        encoding::PSEUDO_CURSOR => read_rich_cursor(reader, rect, pf, decoder.colour_map()).await,
        encoding::PSEUDO_X_CURSOR => read_x_cursor(reader, rect).await,
        encoding::PSEUDO_CURSOR_WITH_ALPHA => read_cursor_with_alpha(reader, rect, decoder).await,
        encoding::PSEUDO_FENCE => Ok(PseudoRect::FenceCapable),
        encoding::PSEUDO_CONTINUOUS_UPDATES => Ok(PseudoRect::ContinuousUpdatesCapable),
        encoding::PSEUDO_QEMU_LED_STATE => {
            let state = reader.read_u8().await.map_err(map_eof)?;
            Ok(PseudoRect::LedState(state))
        }
        encoding::PSEUDO_QEMU_EXT_KEY_EVENT => Ok(PseudoRect::QemuExtKeyCapable),
        encoding::PSEUDO_EXTENDED_MOUSE_BUTTONS => Ok(PseudoRect::ExtendedMouseButtonsCapable),
        other => Err(VncError::UnsupportedEncoding(other)),
    }
}

fn check_cursor_bounds(rect: Rect) -> Result<()> {
    if rect.area() > MAX_CURSOR_AREA {
        return Err(VncError::Protocol(format!(
            "cursor {}x{} exceeds sanity limit",
            rect.width, rect.height
        )));
    }
    Ok(())
}

/// Clamp a hotspot coordinate into the cursor image bounds. RFB doesn't
/// forbid a server sending a hotspot outside the cursor's own dimensions;
/// letting that through would offset the cursor overlay (and therefore click
/// coordinates) arbitrarily once the hotspot is used to position it.
fn clamp_hotspot(hotspot: u16, dim: u16) -> u16 {
    if dim == 0 {
        0
    } else {
        hotspot.min(dim - 1)
    }
}

/// RichCursor (-239): `w*h` pixels in the connection format followed by a
/// 1-bit transparency bitmask, one row-padded bit per pixel.
async fn read_rich_cursor<R>(
    reader: &mut R,
    rect: Rect,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
) -> Result<PseudoRect>
where
    R: AsyncRead + Unpin,
{
    check_cursor_bounds(rect)?;
    let w = rect.width as usize;
    let h = rect.height as usize;
    let bpp = pf.bytes_per_pixel().max(1);
    let pixels = read_exact_vec(reader, w * h * bpp).await?;
    let mask_row = w.div_ceil(8);
    let mask = read_exact_vec(reader, mask_row * h).await?;

    let mut rgba = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let i = y * w + x;
            // Reuse the framebuffer pixel-conversion helper (colour map and
            // all) instead of a hand-rolled grayscale fallback: with the Low
            // quality preset (palette8, true_colour false) cursors used to
            // render as grey noise because the colour map was never applied.
            let [r, g, b, _] = pixel_to_rgba(&pixels[i * bpp..(i + 1) * bpp], pf, map);
            let visible = (mask[y * mask_row + x / 8] >> (7 - (x % 8))) & 1 == 1;
            let o = i * 4;
            rgba[o] = r;
            rgba[o + 1] = g;
            rgba[o + 2] = b;
            rgba[o + 3] = if visible { 255 } else { 0 };
        }
    }
    Ok(PseudoRect::Cursor(CursorShape {
        width: rect.width,
        height: rect.height,
        hotspot_x: clamp_hotspot(rect.x, rect.width),
        hotspot_y: clamp_hotspot(rect.y, rect.height),
        pixels: rgba,
    }))
}

/// XCursor (-240): two RGB colours + 1-bit bitmap + 1-bit mask.
async fn read_x_cursor<R>(reader: &mut R, rect: Rect) -> Result<PseudoRect>
where
    R: AsyncRead + Unpin,
{
    check_cursor_bounds(rect)?;
    let w = rect.width as usize;
    let h = rect.height as usize;
    if w * h == 0 {
        return Ok(PseudoRect::Cursor(CursorShape {
            width: 0,
            height: 0,
            hotspot_x: clamp_hotspot(rect.x, rect.width),
            hotspot_y: clamp_hotspot(rect.y, rect.height),
            pixels: Vec::new(),
        }));
    }
    let mut colours = [0u8; 6];
    reader.read_exact(&mut colours).await.map_err(map_eof)?;
    let fg = [colours[0], colours[1], colours[2]];
    let bg = [colours[3], colours[4], colours[5]];
    let row = w.div_ceil(8);
    let bitmap = read_exact_vec(reader, row * h).await?;
    let mask = read_exact_vec(reader, row * h).await?;

    let mut rgba = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let bit = |buf: &[u8]| (buf[y * row + x / 8] >> (7 - (x % 8))) & 1 == 1;
            let colour = if bit(&bitmap) { fg } else { bg };
            let o = (y * w + x) * 4;
            rgba[o..o + 3].copy_from_slice(&colour);
            rgba[o + 3] = if bit(&mask) { 255 } else { 0 };
        }
    }
    Ok(PseudoRect::Cursor(CursorShape {
        width: rect.width,
        height: rect.height,
        hotspot_x: clamp_hotspot(rect.x, rect.width),
        hotspot_y: clamp_hotspot(rect.y, rect.height),
        pixels: rgba,
    }))
}

/// Fixed pixel format for CursorWithAlpha inner-encoding payloads (RFB spec):
/// always 32bpp/depth-32 RGBA regardless of the connection's negotiated
/// pixel format, with the alpha channel in the byte the RGB shifts leave
/// free (shift 24). Using this instead of the connection's format matters
/// when that format is compact-3-byte: Tight would then read 3-byte TPIXELs
/// from what is actually a 4-byte-per-pixel stream, scrambling every channel
/// and forcing alpha=255.
fn cursor_alpha_pixel_format() -> PixelFormat {
    PixelFormat {
        bits_per_pixel: 32,
        depth: 32,
        big_endian: false,
        true_colour: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    }
}

/// Un-premultiply alpha in place. The wire format is premultiplied RGBA
/// (RFB spec); every downstream consumer composites assuming straight
/// alpha, so antialiased cursor edges showed a dark fringe without this.
fn unpremultiply(rgba: &mut [u8]) {
    for px in rgba.chunks_exact_mut(4) {
        let a = px[3] as u32;
        for c in px[..3].iter_mut() {
            // `checked_div` returns `None` for alpha == 0 (fully
            // transparent): the spec leaves RGB undefined there, so the
            // wire byte is kept as-is rather than guessed at.
            if let Some(v) = (*c as u32 * 255).checked_div(a) {
                *c = v.min(255) as u8;
            }
        }
    }
}

/// CursorWithAlpha (-314): an inner encoding number followed by cursor pixels
/// encoded with that encoding, always RGBA8888 regardless of connection format.
async fn read_cursor_with_alpha<R>(
    reader: &mut R,
    rect: Rect,
    decoder: &mut DecoderState,
) -> Result<PseudoRect>
where
    R: AsyncRead + Unpin + Send,
{
    check_cursor_bounds(rect)?;
    let inner = reader.read_i32().await.map_err(map_eof)?;
    let w = rect.width as usize;
    let h = rect.height as usize;

    let mut rgba = if inner == encoding::RAW {
        read_exact_vec(reader, w * h * 4).await?
    } else {
        // Decode through the shared state (the payload may share zlib
        // streams with ordinary data rects, PRD/02 §9), but against the
        // fixed pixel format the spec mandates for this payload, not the
        // connection's negotiated one -- see `cursor_alpha_pixel_format`.
        // Non-RAW inner encodings still end up with alpha forced to 255 (the
        // generic pixel-conversion pipeline has no alpha channel to carry),
        // so this only round-trips alpha faithfully for a RAW inner
        // encoding; that's the common case in practice since cursors are
        // tiny and servers rarely bother compressing them.
        let alpha_pf = cursor_alpha_pixel_format();
        let decoded =
            crate::encodings::decode_rect_as(decoder, reader, rect, inner, &alpha_pf).await?;
        match decoded.map(|d| d.payload) {
            Some(RectPayload::Rgba(px)) => px,
            _ => {
                return Err(VncError::Protocol(format!(
                    "cursor-with-alpha inner encoding {inner} did not yield RGBA pixels"
                )))
            }
        }
    };
    if rgba.len() != w * h * 4 {
        return Err(VncError::Protocol(
            "cursor-with-alpha pixel payload has wrong size".into(),
        ));
    }
    unpremultiply(&mut rgba);
    Ok(PseudoRect::Cursor(CursorShape {
        width: rect.width,
        height: rect.height,
        hotspot_x: clamp_hotspot(rect.x, rect.width),
        hotspot_y: clamp_hotspot(rect.y, rect.height),
        pixels: rgba,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoder() -> DecoderState {
        DecoderState::new(PixelFormat::bgra8888())
    }

    #[tokio::test]
    async fn desktop_size_variants() {
        let pf = PixelFormat::bgra8888();
        let mut cur = std::io::Cursor::new(Vec::new());
        let p = read_pseudo_rect(
            &mut cur,
            Rect::new(0, 0, 1024, 768),
            encoding::PSEUDO_DESKTOP_SIZE,
            &pf,
            &mut decoder(),
        )
        .await
        .unwrap();
        match p {
            PseudoRect::DesktopSize { width, height } => {
                assert_eq!((width, height), (1024, 768));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn extended_desktop_size_screen_list() {
        let pf = PixelFormat::bgra8888();
        let mut wire = vec![1u8, 0, 0, 0]; // one screen + padding
        wire.extend_from_slice(&42u32.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&1920u16.to_be_bytes());
        wire.extend_from_slice(&1080u16.to_be_bytes());
        wire.extend_from_slice(&7u32.to_be_bytes());
        let mut cur = std::io::Cursor::new(wire);
        let p = read_pseudo_rect(
            &mut cur,
            Rect::new(1, 0, 1920, 1080), // reason 1 (us), status 0 (ok)
            encoding::PSEUDO_EXTENDED_DESKTOP_SIZE,
            &pf,
            &mut decoder(),
        )
        .await
        .unwrap();
        match p {
            PseudoRect::ExtendedDesktopSize {
                reason,
                status,
                width,
                height,
                screens,
            } => {
                assert_eq!(reason, 1);
                assert_eq!(status, 0);
                assert_eq!((width, height), (1920, 1080));
                assert_eq!(screens.len(), 1);
                assert_eq!(screens[0].id, 42);
                assert_eq!(screens[0].flags, 7);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn rich_cursor_alpha_from_mask() {
        let pf = PixelFormat::bgra8888();
        // 2x1 cursor: white pixel then black pixel, mask = 0b10 -> first visible.
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0xff, 0xff, 0xff, 0x00]); // BGRA white
        wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // black
        wire.push(0b1000_0000);
        let mut cur = std::io::Cursor::new(wire);
        let p = read_pseudo_rect(
            &mut cur,
            Rect::new(0, 0, 2, 1),
            encoding::PSEUDO_CURSOR,
            &pf,
            &mut decoder(),
        )
        .await
        .unwrap();
        match p {
            PseudoRect::Cursor(c) => {
                assert_eq!(c.pixels.len(), 8);
                assert_eq!(&c.pixels[0..4], &[255, 255, 255, 255]);
                assert_eq!(c.pixels[7], 0); // second pixel transparent
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_giant_cursor() {
        let pf = PixelFormat::bgra8888();
        let mut cur = std::io::Cursor::new(Vec::new());
        let r = read_pseudo_rect(
            &mut cur,
            Rect::new(0, 0, 60000, 60000),
            encoding::PSEUDO_CURSOR,
            &pf,
            &mut decoder(),
        )
        .await;
        assert!(matches!(r, Err(VncError::Protocol(_))));
    }

    #[tokio::test]
    async fn cursor_with_alpha_raw_unpremultiplies_wire_pixels() {
        // Wire format is premultiplied RGBA; the decoded pixel must be
        // straight alpha, not the raw wire bytes.
        let pf = PixelFormat::bgra8888();
        let mut wire = Vec::new();
        wire.extend_from_slice(&0i32.to_be_bytes()); // inner encoding: Raw
        wire.extend_from_slice(&[1, 2, 3, 4]); // premultiplied, alpha=4
        let mut cur = std::io::Cursor::new(wire);
        let p = read_pseudo_rect(
            &mut cur,
            Rect::new(0, 0, 1, 1),
            encoding::PSEUDO_CURSOR_WITH_ALPHA,
            &pf,
            &mut decoder(),
        )
        .await
        .unwrap();
        match p {
            // channel = min(255, channel*255/alpha): 1*255/4=63, 2*255/4=127,
            // 3*255/4=191; alpha itself is untouched.
            PseudoRect::Cursor(c) => assert_eq!(c.pixels, vec![63, 127, 191, 4]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn cursor_with_alpha_zero_alpha_keeps_rgb_untouched() {
        let pf = PixelFormat::bgra8888();
        let mut wire = Vec::new();
        wire.extend_from_slice(&0i32.to_be_bytes()); // inner encoding: Raw
        wire.extend_from_slice(&[7, 8, 9, 0]); // fully transparent
        let mut cur = std::io::Cursor::new(wire);
        let p = read_pseudo_rect(
            &mut cur,
            Rect::new(0, 0, 1, 1),
            encoding::PSEUDO_CURSOR_WITH_ALPHA,
            &pf,
            &mut decoder(),
        )
        .await
        .unwrap();
        match p {
            PseudoRect::Cursor(c) => assert_eq!(c.pixels, vec![7, 8, 9, 0]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn cursor_with_alpha_inner_tight_uses_fixed_pixel_format() {
        // The connection's negotiated pixel format is compact-3-byte (our
        // canonical bgra8888), but CursorWithAlpha's inner-encoding payload
        // is always a fixed 32bpp/depth-32 RGBA format per spec. Decoding it
        // against the connection's compact format would make Tight read
        // 3-byte TPIXELs from what is actually a 4-byte-per-pixel stream,
        // scrambling every channel.
        let pf = PixelFormat::bgra8888();
        let mut wire = Vec::new();
        wire.extend_from_slice(&encoding::TIGHT.to_be_bytes()); // inner: Tight
        wire.push(0x80); // Tight control byte: Fill
        wire.extend_from_slice(&[10, 20, 30, 200]); // 4-byte TPIXEL: B,G,R,free
        let mut cur = std::io::Cursor::new(wire);
        let p = read_pseudo_rect(
            &mut cur,
            Rect::new(0, 0, 1, 1),
            encoding::PSEUDO_CURSOR_WITH_ALPHA,
            &pf,
            &mut decoder(),
        )
        .await
        .unwrap();
        match p {
            // red_shift 16 -> byte2 (30), green_shift 8 -> byte1 (20),
            // blue_shift 0 -> byte0 (10); alpha forced opaque by the generic
            // pixel-conversion pipeline (no scrambled 3-byte misread).
            PseudoRect::Cursor(c) => assert_eq!(c.pixels, vec![30, 20, 10, 255]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn cursor_hotspot_clamped_to_bounds() {
        let pf = PixelFormat::bgra8888();
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0xff, 0xff, 0xff, 0x00]); // one white pixel
        wire.push(0b1000_0000); // visible
        let mut cur = std::io::Cursor::new(wire);
        // Hotspot (rect.x/rect.y) far outside the 1x1 cursor's own bounds.
        let p = read_pseudo_rect(
            &mut cur,
            Rect::new(50, 50, 1, 1),
            encoding::PSEUDO_CURSOR,
            &pf,
            &mut decoder(),
        )
        .await
        .unwrap();
        match p {
            PseudoRect::Cursor(c) => {
                assert_eq!(c.hotspot_x, 0);
                assert_eq!(c.hotspot_y, 0);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn rich_cursor_honours_colour_map_on_palette_format() {
        // With the Low quality preset (palette8, true_colour false) cursors
        // used to render as grey noise: RichCursor pixels bypassed the
        // colour map entirely.
        let pf = PixelFormat::palette8();
        let mut state = DecoderState::new(pf);
        // set_colour_map takes 16-bit wire channel values and keeps the high
        // byte (RFB SetColourMapEntries, §7.6.2).
        state.set_colour_map(
            0,
            &[[10 << 8, 20 << 8, 30 << 8], [200 << 8, 150 << 8, 100 << 8]],
        );
        let wire = vec![
            0u8,           // pixel 0 -> palette index 0
            1u8,           // pixel 1 -> palette index 1
            0b1100_0000u8, // both visible
        ];
        let mut cur = std::io::Cursor::new(wire);
        let p = read_pseudo_rect(
            &mut cur,
            Rect::new(0, 0, 2, 1),
            encoding::PSEUDO_CURSOR,
            &pf,
            &mut state,
        )
        .await
        .unwrap();
        match p {
            PseudoRect::Cursor(c) => {
                assert_eq!(&c.pixels[0..4], &[10, 20, 30, 255]);
                assert_eq!(&c.pixels[4..8], &[200, 150, 100, 255]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
