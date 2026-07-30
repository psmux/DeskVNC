//! CopyRect (1): source position only, the framebuffer does the copy.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::Result;
use crate::types::RectPayload;

pub(crate) async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<RectPayload> {
    let src_x = reader.read_u16().await?;
    let src_y = reader.read_u16().await?;
    Ok(RectPayload::CopyRect { src_x, src_y })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn copy_rect_parses_source() {
        let wire = [0x01u8, 0x02, 0x03, 0x04];
        let mut r: &[u8] = &wire;
        match decode(&mut r).await.unwrap() {
            RectPayload::CopyRect { src_x, src_y } => {
                assert_eq!(src_x, 0x0102);
                assert_eq!(src_y, 0x0304);
            }
            other => panic!("expected CopyRect, got {other:?}"),
        }
    }
}
