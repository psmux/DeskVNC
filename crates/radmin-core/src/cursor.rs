use super::desktop::{field, fields, word};
use anyhow::{ensure, Result};
use remote_core::CursorShape;
use std::collections::HashMap;

#[derive(Default)]
pub struct CursorCache {
    shapes: HashMap<u32, CursorShape>,
    bytes: usize,
}
fn hidden() -> CursorShape {
    CursorShape {
        width: 0,
        height: 0,
        hotspot_x: 0,
        hotspot_y: 0,
        pixels: Vec::new(),
    }
}
impl CursorCache {
    pub fn decode(&mut self, data: &[u8]) -> Result<CursorShape> {
        ensure!(
            !data.is_empty() && data.len() <= 8 * 1024 * 1024,
            "Invalid Radmin cursor size"
        );
        let entries = fields(data, false)?;
        ensure!(
            entries
                .iter()
                .all(|(t, _)| matches!(t, 0x10000000 | 0x20000000)),
            "Unsupported Radmin cursor fields"
        );
        let id = if let Some(data) = field(&entries, 0x10000000) {
            ensure!(data.len() == 4, "Invalid Radmin cursor ID");
            word(data, 0)?
        } else {
            0
        };
        let Some(data) = field(&entries, 0x20000000) else {
            return Ok(self.shapes.get(&id).cloned().unwrap_or_else(hidden));
        };
        let frames = fields(data, true)?;
        ensure!(!frames.is_empty(), "Empty Radmin cursor definition");
        let mut first = None;
        let mut count = 0;
        for (tag, frame) in frames {
            ensure!(tag == 0x10000000, "Invalid Radmin cursor frame tag");
            let (shape, pixels) = decode_frame(frame)?;
            count += pixels;
            ensure!(
                count <= 1024 * 1024,
                "Radmin cursor animation exceeds pixel budget"
            );
            if first.is_none() {
                first = Some(shape);
            }
        }
        let shape = first.expect("nonempty frames");
        let size =
            self.bytes - self.shapes.get(&id).map_or(0, |s| s.pixels.len()) + shape.pixels.len();
        ensure!(
            size <= 32 * 1024 * 1024 && (self.shapes.contains_key(&id) || self.shapes.len() < 256),
            "Radmin cursor cache limit exceeded"
        );
        self.bytes = size;
        self.shapes.insert(id, shape.clone());
        Ok(shape)
    }
}
fn decode_frame(data: &[u8]) -> Result<(CursorShape, usize)> {
    let entries = fields(data, false)?;
    ensure!(entries.len() == 2, "Invalid Radmin cursor frame fields");
    let header =
        field(&entries, 0x10000000).ok_or_else(|| anyhow::anyhow!("Missing cursor header"))?;
    let data =
        field(&entries, 0x20000000).ok_or_else(|| anyhow::anyhow!("Missing cursor bitmap"))?;
    ensure!(header.len() == 24, "Invalid Radmin cursor header");
    let (kind, hx, hy, w, h) = (
        word(header, 0)?,
        word(header, 4)? as usize,
        word(header, 8)? as usize,
        word(header, 12)? as usize,
        word(header, 16)? as usize,
    );
    ensure!(
        (1..=3).contains(&kind)
            && w > 0
            && h > 0
            && w <= 4096
            && h <= 4096
            && w * h <= 1024 * 1024
            && hx < w
            && hy < h,
        "Unsupported Radmin cursor geometry or kind"
    );
    let mask_stride = w.div_ceil(32) * 4;
    let mask_size = mask_stride * h;
    let stride = (w * 3 + 3) & !3;
    let expected = match kind {
        1 => mask_size * 2,
        2 => mask_size + stride * h,
        _ => w * h * 4,
    };
    ensure!(
        data.len() == expected,
        "Radmin cursor bitmap extent mismatch"
    );
    let mut pixels = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        for x in 0..w {
            if kind == 3 {
                let i = (y * w + x) * 4;
                pixels.extend_from_slice(&[data[i + 2], data[i + 1], data[i], data[i + 3]]);
            } else {
                let mask = data[y * mask_stride + x / 8] & (0x80 >> (x % 8)) != 0;
                let color = if kind == 1 {
                    [if data[mask_size + y * mask_stride + x / 8] & (0x80 >> (x % 8)) != 0 {
                        255
                    } else {
                        0
                    }; 3]
                } else {
                    let i = mask_size + y * stride + x * 3;
                    [data[i + 2], data[i + 1], data[i]]
                };
                // Destination-XOR cannot be represented by the shared RGBA
                // cursor layer. Keep the local pointer, never disconnect.
                if mask && color != [0; 3] {
                    return Ok((hidden(), w * h));
                }
                pixels.extend_from_slice(&[
                    color[0],
                    color[1],
                    color[2],
                    if mask { 0 } else { 255 },
                ]);
            }
        }
    }
    Ok((
        CursorShape {
            width: w as u16,
            height: h as u16,
            hotspot_x: hx as u16,
            hotspot_y: hy as u16,
            pixels,
        },
        w * h,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop::tlv;
    #[test]
    fn alpha_shape_and_cache_reference() {
        let mut frame = tlv(
            0x10000000,
            &[3u32, 0, 0, 1, 1, 0]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect::<Vec<_>>(),
        );
        frame.extend(tlv(0x20000000, &[3, 2, 1, 128]));
        let mut shape = tlv(0x10000000, &7u32.to_be_bytes());
        shape.extend(tlv(0x20000000, &tlv(0x10000000, &frame)));
        let mut cache = CursorCache::default();
        assert_eq!(cache.decode(&shape).unwrap().pixels, [1, 2, 3, 128]);
        assert_eq!(
            cache
                .decode(&tlv(0x10000000, &7u32.to_be_bytes()))
                .unwrap()
                .pixels,
            [1, 2, 3, 128]
        );
        assert!(cache.decode(&shape[..shape.len() - 1]).is_err());
    }
}
