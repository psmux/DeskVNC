//! Hextile (5): 16x16 tiles, each with a subencoding mask.
//!
//! Background and foreground colours PERSIST across tiles when not
//! respecified, the classic implementation bug is resetting them per tile.

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{derr, read_exact_vec};
use crate::error::Result;
use crate::pixel::convert::{convert_to_rgba_mapped, pixel_to_rgba};
use crate::pixel::ColourMap;
use crate::types::{PixelFormat, Rect, RectPayload};

const RAW: u8 = 1;
const BACKGROUND_SPECIFIED: u8 = 2;
const FOREGROUND_SPECIFIED: u8 = 4;
const ANY_SUBRECTS: u8 = 8;
const SUBRECTS_COLOURED: u8 = 16;

pub(crate) async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
) -> Result<RectPayload> {
    let bpp = pf.bytes_per_pixel();
    let w = rect.width as usize;
    let h = rect.height as usize;
    let mut out = vec![0u8; w * h * 4];

    // Persist across ALL tiles of the rect.
    let mut bg = [0u8; 4];
    let mut fg = [0u8; 4];
    let mut px_buf = [0u8; 4];

    let mut ty = 0usize;
    while ty < h {
        let th = (h - ty).min(16);
        let mut tx = 0usize;
        while tx < w {
            let tw = (w - tx).min(16);
            let sub = reader.read_u8().await?;

            if sub & RAW != 0 {
                let data = read_exact_vec(reader, tw * th * bpp, "hextile").await?;
                let rgba = convert_to_rgba_mapped(&data, pf, tw * th, map);
                blit(&mut out, w, tx, ty, tw, th, &rgba);
                tx += tw;
                continue;
            }

            if sub & BACKGROUND_SPECIFIED != 0 {
                reader.read_exact(&mut px_buf[..bpp]).await?;
                bg = pixel_to_rgba(&px_buf[..bpp], pf, map);
            }
            if sub & FOREGROUND_SPECIFIED != 0 {
                reader.read_exact(&mut px_buf[..bpp]).await?;
                fg = pixel_to_rgba(&px_buf[..bpp], pf, map);
            }

            // Fill tile with background.
            fill(&mut out, w, tx, ty, tw, th, bg);

            if sub & ANY_SUBRECTS != 0 {
                let count = reader.read_u8().await? as usize;
                let coloured = sub & SUBRECTS_COLOURED != 0;
                for _ in 0..count {
                    let colour = if coloured {
                        reader.read_exact(&mut px_buf[..bpp]).await?;
                        pixel_to_rgba(&px_buf[..bpp], pf, map)
                    } else {
                        fg
                    };
                    let xy = reader.read_u8().await?;
                    let wh = reader.read_u8().await?;
                    let sx = (xy >> 4) as usize;
                    let sy = (xy & 0x0f) as usize;
                    let sw = (wh >> 4) as usize + 1;
                    let sh = (wh & 0x0f) as usize + 1;
                    if sx + sw > tw || sy + sh > th {
                        return Err(derr(
                            "hextile",
                            format!("subrect {sx},{sy} {sw}x{sh} outside {tw}x{th} tile"),
                        ));
                    }
                    fill(&mut out, w, tx + sx, ty + sy, sw, sh, colour);
                }
            }
            tx += tw;
        }
        ty += th;
    }

    Ok(RectPayload::Rgba(out))
}

fn fill(out: &mut [u8], stride: usize, x: usize, y: usize, w: usize, h: usize, colour: [u8; 4]) {
    for row in y..y + h {
        let start = (row * stride + x) * 4;
        for px in out[start..start + w * 4].chunks_exact_mut(4) {
            px.copy_from_slice(&colour);
        }
    }
}

fn blit(out: &mut [u8], stride: usize, x: usize, y: usize, w: usize, h: usize, rgba: &[u8]) {
    for row in 0..h {
        let src = row * w * 4;
        let dst = ((y + row) * stride + x) * 4;
        out[dst..dst + w * 4].copy_from_slice(&rgba[src..src + w * 4]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two 16x16 tiles side by side. Tile 1 specifies a red background; tile 2
    /// sends subencoding 0 (nothing specified) and must inherit the red
    /// background from tile 1.
    #[tokio::test]
    async fn background_persists_across_tiles() {
        let pf = PixelFormat::bgra8888();
        let mut wire: Vec<u8> = Vec::new();
        // Tile 1: BackgroundSpecified, bg = red (BGRX wire order).
        wire.push(BACKGROUND_SPECIFIED);
        wire.extend_from_slice(&[0, 0, 255, 0]);
        // Tile 2: nothing specified -> background persists.
        wire.push(0);
        let mut r: &[u8] = &wire;
        let payload = decode(&mut r, Rect::new(0, 0, 32, 16), &pf, None)
            .await
            .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                // A pixel in tile 1 and one in tile 2 are both red.
                let p1 = &px[(5 * 32 + 5) * 4..(5 * 32 + 5) * 4 + 4];
                let p2 = &px[(5 * 32 + 20) * 4..(5 * 32 + 20) * 4 + 4];
                assert_eq!(p1, &[255, 0, 0, 255]);
                assert_eq!(p2, &[255, 0, 0, 255]);
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subrects_with_foreground() {
        let pf = PixelFormat::bgra8888();
        let mut wire: Vec<u8> = Vec::new();
        // 8x8 rect, single tile: bg=black, fg=white, one 2x2 subrect at (1,1).
        wire.push(BACKGROUND_SPECIFIED | FOREGROUND_SPECIFIED | ANY_SUBRECTS);
        wire.extend_from_slice(&[0, 0, 0, 0]); // bg black
        wire.extend_from_slice(&[255, 255, 255, 0]); // fg white
        wire.push(1); // one subrect
        wire.push(0x11); // x=1, y=1
        wire.push(0x11); // w=2, h=2
        let mut r: &[u8] = &wire;
        let payload = decode(&mut r, Rect::new(0, 0, 8, 8), &pf, None)
            .await
            .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                let at = |x: usize, y: usize| &px[(y * 8 + x) * 4..(y * 8 + x) * 4 + 4];
                assert_eq!(at(0, 0), &[0, 0, 0, 255]);
                assert_eq!(at(1, 1), &[255, 255, 255, 255]);
                assert_eq!(at(2, 2), &[255, 255, 255, 255]);
                assert_eq!(at(3, 3), &[0, 0, 0, 255]);
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn out_of_tile_subrect_errors() {
        let pf = PixelFormat::bgra8888();
        let mut wire: Vec<u8> = Vec::new();
        // 4x4 rect (tile is 4x4): subrect claims 16x16 -> out of tile bounds.
        wire.push(ANY_SUBRECTS | SUBRECTS_COLOURED);
        wire.push(1);
        wire.extend_from_slice(&[0, 0, 0, 0]); // colour
        wire.push(0x00); // x=0,y=0
        wire.push(0xff); // w=16,h=16
        let mut r: &[u8] = &wire;
        assert!(decode(&mut r, Rect::new(0, 0, 4, 4), &pf, None)
            .await
            .is_err());
    }
}
