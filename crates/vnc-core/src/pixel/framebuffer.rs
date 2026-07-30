//! Client-side framebuffer: an RGBA8888 image the decoded rects are applied
//! to. All geometry is clipped defensively, a malformed rect can never write
//! out of bounds.

use crate::types::{DecodedRect, RectPayload};

pub struct Framebuffer {
    width: u16,
    height: u16,
    /// RGBA8888, row-major, `width * height * 4` bytes.
    data: Vec<u8>,
}

fn opaque_black(len_px: usize) -> Vec<u8> {
    // `[u8]::repeat` fills by doubling memcpy, which is far quicker than
    // touching every alpha byte individually on a 4K framebuffer.
    [0u8, 0, 0, 255].repeat(len_px)
}

impl Framebuffer {
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            data: opaque_black(width as usize * height as usize),
        }
    }

    /// Resize, preserving overlapping content (top-left anchored).
    pub fn resize(&mut self, width: u16, height: u16) {
        if width == self.width && height == self.height {
            return;
        }
        let mut new_data = opaque_black(width as usize * height as usize);
        let copy_w = self.width.min(width) as usize;
        let copy_h = self.height.min(height) as usize;
        for y in 0..copy_h {
            let src = (y * self.width as usize) * 4;
            let dst = (y * width as usize) * 4;
            new_data[dst..dst + copy_w * 4].copy_from_slice(&self.data[src..src + copy_w * 4]);
        }
        self.width = width;
        self.height = height;
        self.data = new_data;
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    /// RGBA8888, row-major, len = `width * height * 4`.
    pub fn as_rgba(&self) -> &[u8] {
        &self.data
    }

    /// Apply a decoded rectangle. Out-of-bounds regions are clipped.
    pub fn apply(&mut self, decoded: &DecodedRect) {
        let r = decoded.rect;
        match &decoded.payload {
            RectPayload::Rgba(pixels) => {
                self.blit_rgba(r.x, r.y, r.width, r.height, pixels);
            }
            RectPayload::Jpeg(bytes) => match crate::encodings::decode_jpeg_to_rgba(bytes) {
                Ok((jw, jh, pixels)) => {
                    // The JPEG should match the rect; crop bottom/right if not.
                    let w = (r.width as u32).min(jw);
                    let h = (r.height as u32).min(jh);
                    if jw == w && w == r.width as u32 {
                        self.blit_rgba(r.x, r.y, w as u16, h as u16, &pixels);
                    } else {
                        // Row stride differs, copy row by row.
                        for y in 0..h {
                            let src = (y as usize * jw as usize) * 4;
                            let row = &pixels[src..src + w as usize * 4];
                            self.blit_rgba(r.x, r.y.saturating_add(y as u16), w as u16, 1, row);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to decode JPEG rect for framebuffer: {e}");
                }
            },
            RectPayload::CopyRect { src_x, src_y } => {
                self.copy_rect(*src_x, *src_y, r.x, r.y, r.width, r.height);
            }
            RectPayload::H264 { .. } => {
                // H.264 is decoded in the webview (WebCodecs); the native
                // framebuffer keeps its previous contents for these rects.
            }
        }
    }

    /// Copy a `width x height` RGBA block (tightly packed) to (x, y), clipped.
    fn blit_rgba(&mut self, x: u16, y: u16, width: u16, height: u16, pixels: &[u8]) {
        let fb_w = self.width as usize;
        let fb_h = self.height as usize;
        let x = x as usize;
        let y = y as usize;
        if x >= fb_w || y >= fb_h {
            return;
        }
        let src_stride = width as usize * 4;
        let copy_w = (width as usize).min(fb_w - x);
        let copy_h = (height as usize).min(fb_h - y);
        for row in 0..copy_h {
            let src = row * src_stride;
            if src + copy_w * 4 > pixels.len() {
                break; // short payload, never read OOB
            }
            let dst = ((y + row) * fb_w + x) * 4;
            self.data[dst..dst + copy_w * 4].copy_from_slice(&pixels[src..src + copy_w * 4]);
        }
    }

    /// CopyRect, overlap-safe and allocation-free.
    ///
    /// `copy_within` is a `memmove`, so any overlap *within* a row pair is
    /// already handled; visiting rows away from the destination (downwards
    /// when moving up, upwards when moving down) keeps rows that are still
    /// needed as sources from being overwritten first. This halves the memory
    /// traffic of the old snapshot-then-write approach.
    fn copy_rect(
        &mut self,
        src_x: u16,
        src_y: u16,
        dst_x: u16,
        dst_y: u16,
        width: u16,
        height: u16,
    ) {
        let fb_w = self.width as usize;
        let fb_h = self.height as usize;
        let (sx, sy) = (src_x as usize, src_y as usize);
        let (dx, dy) = (dst_x as usize, dst_y as usize);
        if sx >= fb_w || sy >= fb_h || dx >= fb_w || dy >= fb_h {
            return;
        }
        let w = (width as usize).min(fb_w - sx).min(fb_w - dx);
        let h = (height as usize).min(fb_h - sy).min(fb_h - dy);
        if w == 0 || h == 0 {
            return;
        }
        let row_bytes = w * 4;
        let mut copy_row = |row: usize| {
            let src = ((sy + row) * fb_w + sx) * 4;
            let dst = ((dy + row) * fb_w + dx) * 4;
            self.data.copy_within(src..src + row_bytes, dst);
        };
        if dy > sy {
            for row in (0..h).rev() {
                copy_row(row);
            }
        } else {
            for row in 0..h {
                copy_row(row);
            }
        }
    }

    /// Downscaled RGBA snapshot for host thumbnails (PRD/03 §3).
    pub fn thumbnail_rgba(&self, max_width: u32) -> (u32, u32, Vec<u8>) {
        super::thumbnail::downscale_rgba(
            &self.data,
            self.width as u32,
            self.height as u32,
            max_width,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Rect;

    fn red_rect(x: u16, y: u16, w: u16, h: u16) -> DecodedRect {
        let mut px = vec![0u8; w as usize * h as usize * 4];
        for p in px.chunks_exact_mut(4) {
            p[0] = 255;
            p[3] = 255;
        }
        DecodedRect {
            rect: Rect::new(x, y, w, h),
            payload: RectPayload::Rgba(px),
        }
    }

    #[test]
    fn apply_and_read_back() {
        let mut fb = Framebuffer::new(4, 4);
        fb.apply(&red_rect(1, 1, 2, 2));
        let px = |x: usize, y: usize| &fb.as_rgba()[(y * 4 + x) * 4..(y * 4 + x) * 4 + 4];
        assert_eq!(px(1, 1), &[255, 0, 0, 255]);
        assert_eq!(px(2, 2), &[255, 0, 0, 255]);
        assert_eq!(px(0, 0), &[0, 0, 0, 255]);
        assert_eq!(px(3, 3), &[0, 0, 0, 255]);
    }

    #[test]
    fn apply_clips_out_of_bounds() {
        let mut fb = Framebuffer::new(4, 4);
        // Rect extends past the framebuffer on both axes, must not panic.
        fb.apply(&red_rect(3, 3, 5, 5));
        assert_eq!(&fb.as_rgba()[(3 * 4 + 3) * 4..], &[255, 0, 0, 255]);
    }

    #[test]
    fn copy_rect_overlapping() {
        let mut fb = Framebuffer::new(4, 1);
        // Pixels 0..4 = [A B C D]; copy [0..3] to x=1 (overlap): -> [A A B C]
        for (i, p) in fb.data.chunks_exact_mut(4).enumerate() {
            p[0] = i as u8 + 1;
        }
        fb.apply(&DecodedRect {
            rect: Rect::new(1, 0, 3, 1),
            payload: RectPayload::CopyRect { src_x: 0, src_y: 0 },
        });
        let reds: Vec<u8> = fb.as_rgba().chunks_exact(4).map(|p| p[0]).collect();
        assert_eq!(reds, vec![1, 1, 2, 3]);
    }

    /// Vertical scroll in both directions with overlapping source and
    /// destination, the case the row-ordering in `copy_rect` exists for.
    #[test]
    fn copy_rect_overlapping_rows_both_directions() {
        // Each row is tagged with its index in the red channel.
        let build = || {
            let mut fb = Framebuffer::new(2, 6);
            for (i, p) in fb.data.chunks_exact_mut(4).enumerate() {
                p[0] = (i / 2) as u8 + 1;
            }
            fb
        };
        let rows =
            |fb: &Framebuffer| -> Vec<u8> { fb.as_rgba().chunks_exact(8).map(|r| r[0]).collect() };

        // Scroll down: rows 0..5 land at y=1 -> [1,1,2,3,4,5].
        let mut fb = build();
        fb.apply(&DecodedRect {
            rect: Rect::new(0, 1, 2, 5),
            payload: RectPayload::CopyRect { src_x: 0, src_y: 0 },
        });
        assert_eq!(rows(&fb), vec![1, 1, 2, 3, 4, 5]);

        // Scroll up: rows 1..6 land at y=0 -> [2,3,4,5,6,6].
        let mut fb = build();
        fb.apply(&DecodedRect {
            rect: Rect::new(0, 0, 2, 5),
            payload: RectPayload::CopyRect { src_x: 0, src_y: 1 },
        });
        assert_eq!(rows(&fb), vec![2, 3, 4, 5, 6, 6]);
    }

    #[test]
    fn resize_preserves_overlap() {
        let mut fb = Framebuffer::new(2, 2);
        fb.apply(&red_rect(0, 0, 1, 1));
        fb.resize(3, 3);
        assert_eq!(fb.width(), 3);
        assert_eq!(&fb.as_rgba()[0..4], &[255, 0, 0, 255]);
        assert_eq!(fb.as_rgba().len(), 3 * 3 * 4);
    }
}
