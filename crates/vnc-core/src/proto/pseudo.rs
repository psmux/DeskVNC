//! Pseudo-encoding rectangles arriving inside a FramebufferUpdate.
//!
//! These carry no framebuffer pixels; they signal capabilities, resizes,
//! cursor shapes, and similar out-of-band state (PRD/02 §3).

use crate::encodings::DecoderState;
use crate::error::{Result, VncError};
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
        encoding::PSEUDO_CURSOR => read_rich_cursor(reader, rect, pf).await,
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

/// Assemble one raw pixel value honouring the wire endianness of `pf`.
fn read_pixel_value(pf: &PixelFormat, bytes: &[u8]) -> u32 {
    let mut v: u32 = 0;
    if pf.big_endian {
        for &b in bytes {
            v = (v << 8) | b as u32;
        }
    } else {
        for &b in bytes.iter().rev() {
            v = (v << 8) | b as u32;
        }
    }
    v
}

/// Convert a raw pixel value to 8-bit RGB using the connection pixel format.
/// Non-true-colour formats fall back to a grayscale approximation (cursor
/// rendering without the colour map is better than no cursor).
fn pixel_to_rgb(pf: &PixelFormat, v: u32) -> [u8; 3] {
    if pf.true_colour && pf.red_max > 0 && pf.green_max > 0 && pf.blue_max > 0 {
        let scale = |val: u32, max: u16| -> u8 { ((val * 255) / max as u32).min(255) as u8 };
        let r = scale((v >> pf.red_shift) & pf.red_max as u32, pf.red_max);
        let g = scale((v >> pf.green_shift) & pf.green_max as u32, pf.green_max);
        let b = scale((v >> pf.blue_shift) & pf.blue_max as u32, pf.blue_max);
        [r, g, b]
    } else {
        let g = (v & 0xff) as u8;
        [g, g, g]
    }
}

/// RichCursor (-239): `w*h` pixels in the connection format followed by a
/// 1-bit transparency bitmask, one row-padded bit per pixel.
async fn read_rich_cursor<R>(reader: &mut R, rect: Rect, pf: &PixelFormat) -> Result<PseudoRect>
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
            let raw = read_pixel_value(pf, &pixels[i * bpp..(i + 1) * bpp]);
            let [r, g, b] = pixel_to_rgb(pf, raw);
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
        hotspot_x: rect.x,
        hotspot_y: rect.y,
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
            hotspot_x: rect.x,
            hotspot_y: rect.y,
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
        hotspot_x: rect.x,
        hotspot_y: rect.y,
        pixels: rgba,
    }))
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

    let rgba = if inner == encoding::RAW {
        read_exact_vec(reader, w * h * 4).await?
    } else {
        // Decode through the shared state: the payload may share zlib streams
        // with ordinary data rects (PRD/02 §9).
        let decoded = crate::encodings::decode_rect(decoder, reader, rect, inner).await?;
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
    Ok(PseudoRect::Cursor(CursorShape {
        width: rect.width,
        height: rect.height,
        hotspot_x: rect.x,
        hotspot_y: rect.y,
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
    async fn cursor_with_alpha_raw() {
        let pf = PixelFormat::bgra8888();
        let mut wire = Vec::new();
        wire.extend_from_slice(&0i32.to_be_bytes()); // inner encoding: Raw
        wire.extend_from_slice(&[1, 2, 3, 4]); // one RGBA pixel
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
            PseudoRect::Cursor(c) => assert_eq!(c.pixels, vec![1, 2, 3, 4]),
            other => panic!("unexpected {other:?}"),
        }
    }
}
