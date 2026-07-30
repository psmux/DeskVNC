//! RRE (2) and CoRRE (4): background pixel + list of solid subrectangles.
//!
//! RRE subrect geometry is u16 x4; CoRRE packs it into u8 x4 (rects are
//! limited to 255x255 by the server for CoRRE).

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{derr, read_exact_vec};
use crate::error::Result;
use crate::pixel::convert::pixel_to_rgba;
use crate::pixel::ColourMap;
use crate::types::{PixelFormat, Rect, RectPayload};

pub(crate) async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
    compact: bool, // true = CoRRE
) -> Result<RectPayload> {
    let enc: &'static str = if compact { "corre" } else { "rre" };
    let bpp = pf.bytes_per_pixel();
    let w = rect.width as usize;
    let h = rect.height as usize;

    let num_subrects = reader.read_u32().await? as usize;

    let mut bg_raw = [0u8; 4];
    reader.read_exact(&mut bg_raw[..bpp]).await?;
    let bg = pixel_to_rgba(&bg_raw[..bpp], pf, map);

    // Fill background.
    let mut out = vec![0u8; w * h * 4];
    for px in out.chunks_exact_mut(4) {
        px.copy_from_slice(&bg);
    }

    let geom = if compact { 4 } else { 8 };
    let per_subrect = bpp + geom;
    let total = num_subrects
        .checked_mul(per_subrect)
        .ok_or_else(|| derr(enc, "subrect count overflow"))?;
    let data = read_exact_vec(reader, total, enc).await?;

    for i in 0..num_subrects {
        let s = &data[i * per_subrect..(i + 1) * per_subrect];
        let colour = pixel_to_rgba(&s[..bpp], pf, map);
        let g = &s[bpp..];
        let (sx, sy, sw, sh) = if compact {
            (g[0] as usize, g[1] as usize, g[2] as usize, g[3] as usize)
        } else {
            (
                u16::from_be_bytes([g[0], g[1]]) as usize,
                u16::from_be_bytes([g[2], g[3]]) as usize,
                u16::from_be_bytes([g[4], g[5]]) as usize,
                u16::from_be_bytes([g[6], g[7]]) as usize,
            )
        };
        if sx + sw > w || sy + sh > h {
            return Err(derr(
                enc,
                format!("subrect {sx},{sy} {sw}x{sh} outside {w}x{h} rect"),
            ));
        }
        for y in sy..sy + sh {
            let row = (y * w + sx) * 4;
            for px in out[row..row + sw * 4].chunks_exact_mut(4) {
                px.copy_from_slice(&colour);
            }
        }
    }

    Ok(RectPayload::Rgba(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rre_background_plus_one_subrect() {
        let pf = PixelFormat::bgra8888();
        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&1u32.to_be_bytes()); // one subrect
        wire.extend_from_slice(&[0, 0, 255, 0]); // bg = red (BGRX)
        wire.extend_from_slice(&[255, 0, 0, 0]); // subrect colour = blue
        wire.extend_from_slice(&1u16.to_be_bytes()); // x
        wire.extend_from_slice(&0u16.to_be_bytes()); // y
        wire.extend_from_slice(&1u16.to_be_bytes()); // w
        wire.extend_from_slice(&2u16.to_be_bytes()); // h
        let mut r: &[u8] = &wire;
        let payload = decode(&mut r, Rect::new(0, 0, 2, 2), &pf, None, false)
            .await
            .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                assert_eq!(&px[0..4], &[255, 0, 0, 255]); // (0,0) bg red
                assert_eq!(&px[4..8], &[0, 0, 255, 255]); // (1,0) blue
                assert_eq!(&px[8..12], &[255, 0, 0, 255]); // (0,1) bg red
                assert_eq!(&px[12..16], &[0, 0, 255, 255]); // (1,1) blue
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rre_out_of_bounds_subrect_errors() {
        let pf = PixelFormat::bgra8888();
        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&1u32.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 0, 0]); // bg
        wire.extend_from_slice(&[0, 0, 0, 0]); // subrect colour
        wire.extend_from_slice(&5u16.to_be_bytes()); // x beyond 2x2 rect
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        let mut r: &[u8] = &wire;
        assert!(decode(&mut r, Rect::new(0, 0, 2, 2), &pf, None, false)
            .await
            .is_err());
    }
}
