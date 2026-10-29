//! A framebuffer the bench paints decoded rectangles into, the way the
//! viewer's canvas does, so the stage can be read back out of it.
use anyhow::{Context, Result};
use remote_core::{DecodedRect, RectPayload};
use std::collections::HashMap;

pub struct Framebuffer {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
    #[cfg(feature = "h264")]
    decoders: HashMap<u32, openh264::decoder::Decoder>,
    #[cfg(not(feature = "h264"))]
    decoders: HashMap<u32, ()>,
    /// On a Mac, VideoToolbox, as the viewer's webview decodes there.
    /// OpenH264 stops on the High profile pictures with two reference
    /// frames that Apple's software encoder makes.
    #[cfg(target_os = "macos")]
    vt: HashMap<u32, boundary_platform::video::VtDecoder>,
    /// Rectangles seen by kind, for the report.
    pub kinds: HashMap<&'static str, u64>,
}

impl Framebuffer {
    pub fn new() -> Self {
        Framebuffer {
            width: 0,
            height: 0,
            rgba: Vec::new(),
            decoders: HashMap::new(),
            #[cfg(target_os = "macos")]
            vt: HashMap::new(),
            kinds: HashMap::new(),
        }
    }

    pub fn resize(&mut self, width: u32, height: u32) {
        if (width, height) != (self.width, self.height) {
            self.width = width;
            self.height = height;
            self.rgba = vec![0; (width * height * 4) as usize];
        }
    }

    pub fn view(&self) -> bench_stage::View<'_> {
        bench_stage::View {
            rgba: &self.rgba,
            width: self.width,
            height: self.height,
        }
    }

    fn blit(&mut self, x: u32, y: u32, w: u32, h: u32, src: &[u8], src_stride: u32) {
        let w = w.min(self.width.saturating_sub(x));
        let h = h.min(self.height.saturating_sub(y));
        for row in 0..h {
            let from = ((row * src_stride) * 4) as usize;
            let to = (((y + row) * self.width + x) * 4) as usize;
            let n = (w * 4) as usize;
            if from + n <= src.len() {
                self.rgba[to..to + n].copy_from_slice(&src[from..from + n]);
            }
        }
    }

    pub fn apply(&mut self, decoded: &DecodedRect) -> Result<()> {
        let r = decoded.rect;
        let (x, y, w, h) = (r.x as u32, r.y as u32, r.width as u32, r.height as u32);
        if self.width == 0 {
            // A driver that never sent a size: grow to fit.
            self.resize(x + w, y + h);
        }
        match &decoded.payload {
            RectPayload::Rgba(pixels) => {
                *self.kinds.entry("rgba").or_default() += 1;
                self.blit(x, y, w, h, pixels, w);
            }
            RectPayload::Jpeg(bytes) => {
                *self.kinds.entry("jpeg").or_default() += 1;
                let image = image::load_from_memory_with_format(bytes, image::ImageFormat::Jpeg)
                    .context("jpeg rect")?
                    .into_rgba8();
                let iw = image.width();
                self.blit(x, y, w.min(iw), h.min(image.height()), image.as_raw(), iw);
            }
            RectPayload::CopyRect { src_x, src_y } => {
                *self.kinds.entry("copyrect").or_default() += 1;
                let mut copy = Vec::with_capacity((w * h * 4) as usize);
                for row in 0..h {
                    let sy = (*src_y as u32 + row).min(self.height.saturating_sub(1));
                    let from = ((sy * self.width + *src_x as u32) * 4) as usize;
                    let n = ((w.min(self.width.saturating_sub(*src_x as u32))) * 4) as usize;
                    copy.extend_from_slice(&self.rgba[from..from + n]);
                    copy.resize(((row + 1) * w * 4) as usize, 0);
                }
                self.blit(x, y, w, h, &copy, w);
            }
            RectPayload::H264 {
                data,
                flags,
                context_id,
                reset,
                ..
            } => {
                *self.kinds.entry("h264").or_default() += 1;
                self.h264(x, y, w, h, data, *flags, *context_id, *reset)?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "h264")]
    #[allow(clippy::too_many_arguments)]
    fn h264(
        &mut self,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        data: &[u8],
        flags: u32,
        context: u32,
        reset: bool,
    ) -> Result<()> {
        use openh264::decoder::Decoder;
        use openh264::formats::YUVSource;
        if flags & 2 != 0 {
            self.decoders.clear();
            #[cfg(target_os = "macos")]
            self.vt.clear();
        }
        if reset || flags & 1 != 0 {
            self.decoders.remove(&context);
            #[cfg(target_os = "macos")]
            self.vt.remove(&context);
        }
        if data.is_empty() {
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        if let Some(decoder) = match self.vt.entry(context) {
            std::collections::hash_map::Entry::Occupied(e) => Some(e.into_mut()),
            std::collections::hash_map::Entry::Vacant(e) => {
                boundary_platform::video::VtDecoder::new()
                    .ok()
                    .map(|d| e.insert(d))
            }
        } {
            if let Some(planes) = decoder.decode(data)? {
                let rgba = bt709(&planes, w, h);
                self.blit(x, y, w, h, &rgba, w);
            }
            return Ok(());
        }
        let decoder = match self.decoders.entry(context) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => e.insert(Decoder::new()?),
        };
        let Some(yuv) = decoder.decode(data)? else {
            return Ok(());
        };
        let (dw, dh) = yuv.dimensions();
        let mut rgba = vec![0u8; dw * dh * 4];
        yuv.write_rgba8(&mut rgba);
        self.blit(x, y, w.min(dw as u32), h.min(dh as u32), &rgba, dw as u32);
        Ok(())
    }

    #[cfg(not(feature = "h264"))]
    #[allow(clippy::too_many_arguments)]
    fn h264(
        &mut self,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        _: u32,
        _: u32,
        _: bool,
    ) -> Result<()> {
        anyhow::bail!("H.264 rectangle arrived but this bench was built without the h264 feature")
    }
}

/// Decoded planes to RGBA, BT.709 limited range, as VideoToolbox on the
/// host tags its pictures.
#[cfg(target_os = "macos")]
fn bt709(planes: &boundary_platform::video::Planes, w: u32, h: u32) -> Vec<u8> {
    let mut out = vec![0u8; (w * h * 4) as usize];
    for y in 0..h as usize {
        for x in 0..w as usize {
            let luma = planes
                .luma
                .get(y * planes.stride + x)
                .copied()
                .unwrap_or(16) as f32;
            let c = (y / 2) * planes.chroma_stride + x / 2;
            let u = planes.u.get(c).copied().unwrap_or(128) as f32 - 128.0;
            let v = planes.v.get(c).copied().unwrap_or(128) as f32 - 128.0;
            let l = (luma - 16.0) * 1.164;
            let i = (y * w as usize + x) * 4;
            out[i] = (l + 1.793 * v).clamp(0.0, 255.0) as u8;
            out[i + 1] = (l - 0.213 * u - 0.533 * v).clamp(0.0, 255.0) as u8;
            out[i + 2] = (l + 2.112 * u).clamp(0.0, 255.0) as u8;
            out[i + 3] = 255;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::Rect;

    #[test]
    fn rects_land_where_they_say() {
        let mut fb = Framebuffer::new();
        fb.resize(8, 4);
        fb.apply(&DecodedRect {
            rect: Rect::new(2, 1, 2, 2),
            payload: RectPayload::Rgba(vec![9; 16]),
        })
        .unwrap();
        fb.apply(&DecodedRect {
            rect: Rect::new(5, 1, 2, 2),
            payload: RectPayload::CopyRect { src_x: 2, src_y: 1 },
        })
        .unwrap();
        let at = |x: u32, y: u32| fb.rgba[((y * 8 + x) * 4) as usize];
        assert_eq!((at(2, 1), at(3, 2), at(5, 1), at(6, 2)), (9, 9, 9, 9));
        assert_eq!((at(1, 1), at(4, 1), at(2, 3)), (0, 0, 0));
    }
}
