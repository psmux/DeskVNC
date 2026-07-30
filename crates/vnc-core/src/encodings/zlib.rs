//! zlib (6): a Raw rect compressed through ONE persistent zlib stream for the
//! whole connection (never a fresh decoder per rect).

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{derr, read_exact_vec, ZlibStream};
use crate::error::Result;
use crate::pixel::convert::convert_to_rgba_mapped;
use crate::pixel::ColourMap;
use crate::types::{PixelFormat, Rect, RectPayload};

pub(crate) async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
    stream: &mut ZlibStream,
) -> Result<RectPayload> {
    let compressed_len = reader.read_u32().await? as usize;
    let compressed = read_exact_vec(reader, compressed_len, "zlib").await?;

    let expected = rect.area() * pf.bytes_per_pixel();
    let data = stream.decompress(&compressed, expected, expected + 1024, "zlib")?;
    if data.len() < expected {
        return Err(derr(
            "zlib",
            format!("short inflate: got {} of {expected} bytes", data.len()),
        ));
    }
    Ok(RectPayload::Rgba(convert_to_rgba_mapped(
        &data[..expected],
        pf,
        rect.area(),
        map,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn deflate_sync(c: &mut Compress, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 64);
        c.compress_vec(data, &mut out, FlushCompress::Sync).unwrap();
        out
    }

    /// Two rects through the SAME persistent stream, the second only
    /// inflates correctly if stream state survived the first.
    #[tokio::test]
    async fn persistent_stream_across_rects() {
        let pf = PixelFormat::bgra8888();
        let mut compressor = Compress::new(Compression::default(), true);
        let mut stream = ZlibStream::new();

        for fill in [0x11u8, 0x22] {
            let raw = vec![fill; 2 * 2 * 4];
            let comp = deflate_sync(&mut compressor, &raw);
            let mut wire: Vec<u8> = Vec::new();
            wire.extend_from_slice(&(comp.len() as u32).to_be_bytes());
            wire.extend_from_slice(&comp);
            let mut r: &[u8] = &wire;
            let payload = decode(&mut r, Rect::new(0, 0, 2, 2), &pf, None, &mut stream)
                .await
                .unwrap();
            match payload {
                RectPayload::Rgba(px) => {
                    assert_eq!(px.len(), 16);
                    assert_eq!(&px[0..3], &[fill; 3]);
                }
                other => panic!("expected Rgba, got {other:?}"),
            }
        }
    }
}
