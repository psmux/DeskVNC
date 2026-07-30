//! Raw (0): `width * height * bytes_per_pixel` uncompressed wire pixels.

use tokio::io::AsyncRead;

use super::read_exact_vec;
use crate::error::Result;
use crate::pixel::convert::convert_to_rgba_mapped;
use crate::pixel::ColourMap;
use crate::types::{PixelFormat, Rect, RectPayload};

pub(crate) async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
) -> Result<RectPayload> {
    let bpp = pf.bytes_per_pixel();
    let len = rect.area() * bpp;
    let data = read_exact_vec(reader, len, "raw").await?;
    Ok(RectPayload::Rgba(convert_to_rgba_mapped(
        &data,
        pf,
        rect.area(),
        map,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn raw_2x2_bgra() {
        let pf = PixelFormat::bgra8888();
        // Four pixels in BGRX order: blue, green, red, white.
        #[rustfmt::skip]
        let wire: Vec<u8> = vec![
            255, 0, 0, 0,      // blue
            0, 255, 0, 0,      // green
            0, 0, 255, 0,      // red
            255, 255, 255, 0,  // white
        ];
        let mut r: &[u8] = &wire;
        let payload = decode(&mut r, Rect::new(0, 0, 2, 2), &pf, None)
            .await
            .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                assert_eq!(&px[0..4], &[0, 0, 255, 255]); // blue
                assert_eq!(&px[4..8], &[0, 255, 0, 255]); // green
                assert_eq!(&px[8..12], &[255, 0, 0, 255]); // red
                assert_eq!(&px[12..16], &[255, 255, 255, 255]); // white
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn raw_truncated_input_errors() {
        let pf = PixelFormat::bgra8888();
        let wire = vec![0u8; 7]; // needs 16
        let mut r: &[u8] = &wire;
        assert!(decode(&mut r, Rect::new(0, 0, 2, 2), &pf, None)
            .await
            .is_err());
    }
}
