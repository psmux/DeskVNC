//! Persistent raw-DEFLATE and bounded 24-bit framebuffer updates.
use anyhow::{ensure, Result};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use remote_core::{DecodedRect, Rect, RectPayload, SessionEvent};

pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;
pub const MAX_PIXELS: usize = 16 * 1024 * 1024;
pub fn word(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("Truncated Radmin integer"))?;
    Ok(u32::from_be_bytes(bytes.try_into()?))
}
pub fn tlv(tag: u32, data: &[u8]) -> Vec<u8> {
    let mut out = (tag | data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(data);
    out
}
pub fn fields(mut data: &[u8], repeated: bool) -> Result<Vec<(u32, &[u8])>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let header = word(data, 0)?;
        let (tag, len) = (header & 0xf8000000, (header & 0x07ffffff) as usize);
        ensure!(
            tag != 0 && len != 0 && len <= data.len() - 4,
            "Invalid Radmin desktop TLV"
        );
        ensure!(
            repeated || !out.iter().any(|(t, _)| *t == tag),
            "Duplicate Radmin desktop TLV"
        );
        out.push((tag, &data[4..4 + len]));
        ensure!(out.len() <= 256, "Too many Radmin TLVs");
        data = &data[4 + len..];
    }
    Ok(out)
}
pub fn field<'a>(fields: &[(u32, &'a [u8])], tag: u32) -> Option<&'a [u8]> {
    fields.iter().find(|(t, _)| *t == tag).map(|(_, d)| *d)
}

pub struct Deflate {
    send: Compress,
    receive: Decompress,
}
impl Default for Deflate {
    fn default() -> Self {
        Self {
            send: Compress::new(Compression::fast(), false),
            receive: Decompress::new(false),
        }
    }
}
impl Deflate {
    pub fn encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            !data.is_empty() && data.len() <= super::channel::MAX_RECORD - 1024,
            "Radmin outgoing desktop message is too large"
        );
        let mut out = vec![0; data.len() + data.len() / 1000 + 128];
        let (input, output) = (self.send.total_in(), self.send.total_out());
        self.send
            .compress(data, &mut out[4..], FlushCompress::Sync)?;
        let written = (self.send.total_out() - output) as usize;
        ensure!(
            self.send.total_in() - input == data.len() as u64 && written < out.len() - 4,
            "Radmin compression did not finish"
        );
        out[..4].copy_from_slice(&(data.len() as u32).to_be_bytes());
        out.truncate(4 + written);
        Ok(out)
    }
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let len = word(data, 0)? as usize;
        ensure!(
            data.len() > 4 && (1..=MAX_MESSAGE).contains(&len),
            "Invalid Radmin decompressed length"
        );
        let mut out = vec![0; len + 1];
        let (input, output) = (self.receive.total_in(), self.receive.total_out());
        let status = self
            .receive
            .decompress(&data[4..], &mut out, FlushDecompress::Sync)?;
        ensure!(
            status != Status::StreamEnd
                && self.receive.total_in() - input == (data.len() - 4) as u64
                && self.receive.total_out() - output == len as u64,
            "Invalid Radmin DEFLATE stream or extent"
        );
        out.truncate(len);
        Ok(out)
    }
}

#[derive(Default)]
pub struct Desktop {
    size: (u16, u16),
    format: bool,
    pixels: Vec<u8>, // top-down, packed RGBA; converted only for damaged spans
}
impl Desktop {
    pub fn size(&self) -> (u16, u16) {
        self.size
    }
    pub fn has_frame(&self) -> bool {
        !self.pixels.is_empty()
    }
    pub fn refresh(&self) -> Option<SessionEvent> {
        if !self.has_frame() {
            return None;
        }
        let rect = Rect {
            x: 0,
            y: 0,
            width: self.size.0,
            height: self.size.1,
        };
        Some(SessionEvent::FramebufferUpdate {
            damage: rect,
            rects: vec![DecodedRect {
                rect,
                payload: RectPayload::Rgba(self.pixels.clone()),
            }],
        })
    }
    pub fn decode(&mut self, entries: &[(u32, &[u8])]) -> Result<Vec<SessionEvent>> {
        ensure!(
            entries.iter().all(|(t, _)| matches!(
                t,
                0x10000000
                    | 0x20000000
                    | 0x30000000
                    | 0x40000000
                    | 0x50000000
                    | 0x60000000
                    | 0x70000000
                    | 0x80000000
                    | 0x90000000
                    | 0xa0000000
            )),
            "Unsupported Radmin desktop fields"
        );
        let mut size = self.size;
        let mut format = self.format;
        if let Some(data) = field(entries, 0x10000000) {
            ensure!(
                data.len() == 16
                    && [
                        word(data, 0)?,
                        word(data, 4)?,
                        word(data, 8)?,
                        word(data, 12)?
                    ] == [24, 0xff0000, 0xff00, 0xff],
                "Unsupported Radmin pixel format"
            );
            format = true;
        }
        if let Some(data) = field(entries, 0x30000000) {
            ensure!(data.len() == 8, "Invalid Radmin desktop geometry");
            let (w, h) = (word(data, 0)? as usize, word(data, 4)? as usize);
            ensure!(
                w > 0 && h > 0 && w <= 32768 && h <= 32768 && w * h <= MAX_PIXELS,
                "Radmin desktop exceeds geometry limit"
            );
            size = (w as u16, h as u16);
        }
        if let Some(data) = field(entries, 0x20000000) {
            ensure!(
                data.len() == 4 && word(data, 0)? & !3 == 0,
                "Unsupported Radmin desktop flags"
            );
        }
        let full = field(entries, 0x40000000);
        let region = field(entries, 0x50000000);
        let replacement = field(entries, 0x60000000);
        ensure!(
            region.is_some() == replacement.is_some(),
            "Incomplete Radmin delta"
        );
        ensure!(full.is_none() || region.is_none(), "Ambiguous Radmin image");
        let resized = size != self.size;
        let (w, h) = (size.0 as usize, size.1 as usize);
        let mut events = Vec::new();
        if full.is_some() || region.is_some() {
            ensure!(
                format && w > 0 && h > 0,
                "Image before Radmin pixel format or geometry"
            );
        }
        if let Some(data) = full {
            let stride = (w * 3 + 3) & !3;
            ensure!(
                data.len() == stride * h,
                "Unsupported Radmin full image extent"
            );
            let mut pixels = vec![0; w * h * 4];
            for (y, row) in data.chunks_exact(stride).enumerate() {
                for (x, bgr) in row[..w * 3].chunks_exact(3).enumerate() {
                    pixels[(y * w + x) * 4..(y * w + x + 1) * 4]
                        .copy_from_slice(&[bgr[2], bgr[1], bgr[0], 255]);
                }
            }
            self.pixels = pixels;
        } else if let (Some(region), Some(data)) = (region, replacement) {
            ensure!(
                !resized && self.pixels.len() == w * h * 4,
                "Radmin delta has no matching base frame"
            );
            let spans = spans(region, w, h)?;
            let expected: usize = spans.iter().map(|(_, l, r)| (r - l) * 3).sum();
            ensure!(data.len() == expected, "Radmin delta pixel length mismatch");
            // Validate completely before mutation. Emit row strips, not an
            // entire framebuffer copy for a small cursor-sized dirty region.
            let mut offset = 0;
            let mut rects = Vec::new();
            let mut damage: Option<Rect> = None;
            for (y, left, right) in spans {
                let len = (right - left) * 3;
                let mut rgba = Vec::with_capacity((right - left) * 4);
                for bgr in data[offset..offset + len].chunks_exact(3) {
                    rgba.extend_from_slice(&[bgr[2], bgr[1], bgr[0], 255]);
                }
                offset += len;
                self.pixels[(y * w + left) * 4..(y * w + right) * 4].copy_from_slice(&rgba);
                let rect = Rect {
                    x: left as u16,
                    y: y as u16,
                    width: (right - left) as u16,
                    height: 1,
                };
                damage = Some(match damage {
                    None => rect,
                    Some(d) => {
                        let x = d.x.min(rect.x);
                        let y = d.y.min(rect.y);
                        Rect {
                            x,
                            y,
                            width: (d.x + d.width).max(rect.x + rect.width) - x,
                            height: (d.y + d.height).max(rect.y + rect.height) - y,
                        }
                    }
                });
                rects.push(DecodedRect {
                    rect,
                    payload: RectPayload::Rgba(rgba),
                });
            }
            if let Some(damage) = damage {
                events.push(SessionEvent::FramebufferUpdate { rects, damage });
            }
        } else if resized {
            self.pixels.clear();
        }
        self.size = size;
        self.format = format;
        if resized {
            events.insert(
                0,
                SessionEvent::DesktopResize {
                    width: size.0,
                    height: size.1,
                },
            );
        }
        if full.is_some() {
            events.push(self.refresh().expect("full image exists"));
        }
        Ok(events)
    }
}

fn spans(data: &[u8], width: usize, height: usize) -> Result<Vec<(usize, usize, usize)>> {
    let (mut pos, mut y, mut previous, mut open) = (0, 0, 0, false);
    let mut out = Vec::new();
    while pos < data.len() {
        if data[pos] & 0x80 != 0 {
            ensure!(!open, "Radmin row skip inside unfinished row");
            y += (data[pos] & 0x7f) as usize + 1;
            ensure!(y <= height, "Radmin row skip exceeds desktop");
            pos += 1;
        } else {
            ensure!(data.len() - pos >= 4, "Truncated Radmin span");
            let left = u16::from_be_bytes(data[pos..pos + 2].try_into()?) as usize;
            let encoded = u16::from_be_bytes(data[pos + 2..pos + 4].try_into()?);
            let right = (encoded & 0x7fff) as usize;
            ensure!(
                y < height && previous <= left && left < right && right <= width,
                "Invalid Radmin dirty span"
            );
            // Bound metadata overhead as well as pixel allocations.
            ensure!(out.len() < 262144, "Too many Radmin dirty spans");
            out.push((y, left, right));
            previous = right;
            open = encoded & 0x8000 == 0;
            pos += 4;
            if !open {
                y += 1;
                previous = 0;
            }
        }
    }
    ensure!(!open && y == height, "Incomplete Radmin dirty region");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deflate_is_persistent_and_rejects_false_lengths() {
        let (mut tx, mut rx) = (Deflate::default(), Deflate::default());
        for _ in 0..3 {
            let data = vec![42; 10000];
            assert_eq!(rx.decode(&tx.encode(&data).unwrap()).unwrap(), data);
        }
        let mut bad = tx.encode(b"hello").unwrap();
        bad[..4].copy_from_slice(&2u32.to_be_bytes());
        assert!(rx.decode(&bad).is_err());
    }
    #[test]
    fn frame_and_delta_damage_have_exact_colours_and_are_atomic() {
        let mut desktop = Desktop::default();
        let format: Vec<u8> = [24u32, 0xff0000, 0xff00, 0xff]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect();
        let size = [0, 0, 0, 2, 0, 0, 0, 2];
        let image = [0, 0, 255, 0, 255, 0, 0, 0, 255, 0, 0, 255, 255, 255, 0, 0];
        desktop
            .decode(&[
                (0x10000000, &format),
                (0x30000000, &size),
                (0x40000000, &image),
            ])
            .unwrap();
        assert_eq!(&desktop.pixels[..8], &[255, 0, 0, 255, 0, 255, 0, 255]);
        let before = desktop.pixels.clone();
        let region = [0, 1, 0x80, 2, 0x80];
        assert!(desktop
            .decode(&[(0x50000000, &region), (0x60000000, &[1, 2])])
            .is_err());
        assert_eq!(desktop.pixels, before);
        let events = desktop
            .decode(&[(0x50000000, &region), (0x60000000, &[3, 2, 1])])
            .unwrap();
        let SessionEvent::FramebufferUpdate { damage, .. } = events[0] else {
            panic!()
        };
        assert_eq!(
            damage,
            Rect {
                x: 1,
                y: 0,
                width: 1,
                height: 1
            }
        );
        assert_eq!(&desktop.pixels[4..8], &[1, 2, 3, 255]);
    }
    #[test]
    fn hostile_regions_and_tlvs_fail() {
        assert!(fields(&[0x40, 0, 0, 8, 1], false).is_err());
        assert!(spans(&[0, 0, 0, 1, 0x80], 2, 2).is_err());
        assert!(spans(&[0x82], 2, 2).is_err());
    }
}
