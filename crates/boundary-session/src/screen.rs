//! Screens as changed rectangles, for helpers that take them.
//!
//! The host keeps the last screen it sent and compares each new capture with
//! it in tiles. Only the tiles that differ are encoded, as JPEG rectangles,
//! so a pointer moving or a letter typed costs a few kilobytes instead of a
//! whole screen. Updates go one after another on a single stream, which keeps
//! them in order: each one is drawn over the one before.
//!
//! An update is a length, then:
//!
//! ```text
//! seq u64 | width u16 | height u16 | count u16 | count × (x y w h u16, len u32, JPEG)
//! ```
use crate::{Frame, dimensions, wire};
use anyhow::{Result, ensure};
use image::{ImageDecoder, ImageEncoder};
use std::io::Cursor;

/// The first bytes of a stream of updates. A JPEG or PNG screen starts
/// differently, which is how a helper tells the two kinds of stream apart.
pub(crate) const MAGIC: &[u8; 4] = b"BDT1";
/// The first bytes of a stream of updates that may carry video
/// (`crate::video`). After it each message is a length, then a kind byte,
/// then an update as above or a picture of video. Sent only to a helper that
/// said it decodes video.
pub(crate) const MAGIC_VIDEO: &[u8; 4] = b"BDV1";
const TILE: u32 = 64;
const MAX_RECTS: usize = 4096;
/// Below this many changed pixels one thread encodes everything.
const PARALLEL_PIXELS: u64 = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// The host's side: what the helper has, and what to send it next.
#[derive(Default)]
pub(crate) struct Encoder {
    reference: Option<std::sync::Arc<Frame>>,
    /// The reference is the last capture this encoder was shown, so what
    /// the desktop said changed since then is all that can differ.
    current: bool,
}
impl Encoder {
    /// Forget what the helper has, so the next update is the whole screen,
    /// as after video drew over it.
    pub fn reset(&mut self) {
        self.reference = None;
    }
    /// A capture went to the helper some other way, as video, so the
    /// reference is no longer the last capture.
    pub fn passed(&mut self) {
        self.current = false;
    }
    /// The update that turns what the helper has into `frame`, or nothing
    /// when the two are the same.
    #[cfg(test)]
    pub fn update(&mut self, frame: std::sync::Arc<Frame>, seq: u64) -> Result<Option<Vec<u8>>> {
        self.update_at(frame, seq, crate::JPEG_QUALITY)
    }
    /// [`Encoder::update`] at a chosen JPEG quality.
    pub fn update_at(
        &mut self,
        frame: std::sync::Arc<Frame>,
        seq: u64,
        quality: u8,
    ) -> Result<Option<Vec<u8>>> {
        self.update_with(frame, seq, quality, None)
    }
    /// [`Encoder::update_at`], told what the desktop said changed since the
    /// last capture, so only those tiles are compared: a whole screen
    /// compared for a caret cost a millisecond or two of every keystroke.
    pub fn update_with(
        &mut self,
        frame: std::sync::Arc<Frame>,
        seq: u64,
        quality: u8,
        damage: Option<&[Rect]>,
    ) -> Result<Option<Vec<u8>>> {
        frame.validate()?;
        let damage = damage.filter(|_| self.current);
        self.current = true;
        let rects = match self
            .reference
            .as_ref()
            .filter(|r| r.width == frame.width && r.height == frame.height)
        {
            Some(reference) => match damage {
                Some(damage) => changed_within(reference, &frame, damage),
                None => changed(reference, &frame),
            },
            None => vec![Rect {
                x: 0,
                y: 0,
                width: frame.width,
                height: frame.height,
            }],
        };
        self.send(frame, rects, seq, quality)
    }
    /// After video drew over the screen: the tiles marked in `stale`, in rows
    /// of 64 pixel tiles, from `frame`, which the helper then counts as
    /// holding all of. The rest video already drew closely enough.
    pub fn refine(
        &mut self,
        frame: std::sync::Arc<Frame>,
        stale: &[bool],
        seq: u64,
        quality: u8,
    ) -> Result<Option<Vec<u8>>> {
        frame.validate()?;
        self.current = true;
        let cols = frame.width.div_ceil(TILE);
        let rects = joined(frame.width, frame.height, |tx, ty| {
            stale
                .get((ty * cols + tx) as usize)
                .copied()
                .unwrap_or(true)
        });
        if rects.is_empty() {
            self.reference = Some(frame);
            return Ok(None);
        }
        self.send(frame, rects, seq, quality)
    }
    fn send(
        &mut self,
        frame: std::sync::Arc<Frame>,
        rects: Vec<Rect>,
        seq: u64,
        quality: u8,
    ) -> Result<Option<Vec<u8>>> {
        if rects.is_empty() {
            return Ok(None);
        }
        let rects = split(&frame, rects);
        let encoded = encode_rects(&frame, &rects, quality)?;
        let mut out = Vec::with_capacity(16 + encoded.iter().map(|e| e.len() + 12).sum::<usize>());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&(frame.width as u16).to_be_bytes());
        out.extend_from_slice(&(frame.height as u16).to_be_bytes());
        out.extend_from_slice(&(rects.len() as u16).to_be_bytes());
        for (rect, jpeg) in rects.iter().zip(&encoded) {
            for v in [rect.x, rect.y, rect.width, rect.height] {
                out.extend_from_slice(&(v as u16).to_be_bytes());
            }
            out.extend_from_slice(&(jpeg.len() as u32).to_be_bytes());
            out.extend_from_slice(jpeg);
        }
        ensure!(out.len() <= wire::MAX_FRAME, "Encoded screen is too large");
        self.reference = Some(frame);
        Ok(Some(out))
    }
}

/// The tiles that differ, joined into rectangles: runs along a row of
/// tiles, then runs with the same columns stacked down the rows.
fn changed(old: &Frame, new: &Frame) -> Vec<Rect> {
    let (w, h) = (new.width, new.height);
    let stride = w as usize * 4;
    joined(w, h, |tx, ty| {
        let (y0, x0) = (ty * TILE, (tx * TILE) as usize * 4);
        let th = TILE.min(h - y0);
        let tw = TILE.min(w - tx * TILE) as usize * 4;
        (y0..y0 + th).any(|y| {
            let i = y as usize * stride + x0;
            old.rgba[i..i + tw] != new.rgba[i..i + tw]
        })
    })
}

/// [`changed`], looking only at the tiles `damage` touches.
fn changed_within(old: &Frame, new: &Frame, damage: &[Rect]) -> Vec<Rect> {
    let (w, h) = (new.width, new.height);
    let (cols, rows) = (w.div_ceil(TILE), h.div_ceil(TILE));
    let mut touched = vec![false; (cols * rows) as usize];
    for r in damage {
        if r.width == 0 || r.height == 0 || r.x >= w || r.y >= h {
            continue;
        }
        let (x1, y1) = ((r.x + r.width).min(w) - 1, (r.y + r.height).min(h) - 1);
        for ty in r.y / TILE..=y1 / TILE {
            for tx in r.x / TILE..=x1 / TILE {
                touched[(ty * cols + tx) as usize] = true;
            }
        }
    }
    let stride = w as usize * 4;
    joined(w, h, |tx, ty| {
        if !touched[(ty * cols + tx) as usize] {
            return false;
        }
        let (y0, x0) = (ty * TILE, (tx * TILE) as usize * 4);
        let th = TILE.min(h - y0);
        let tw = TILE.min(w - tx * TILE) as usize * 4;
        (y0..y0 + th).any(|y| {
            let i = y as usize * stride + x0;
            old.rgba[i..i + tw] != new.rgba[i..i + tw]
        })
    })
}

/// The tiles `dirty` picks, joined into rectangles as [`changed`] does.
fn joined(w: u32, h: u32, dirty: impl Fn(u32, u32) -> bool) -> Vec<Rect> {
    let cols = w.div_ceil(TILE);
    let mut rects: Vec<Rect> = Vec::new();
    // Rectangles that end on the row of tiles above, which this row may extend.
    let mut open: Vec<usize> = Vec::new();
    for ty in 0..h.div_ceil(TILE) {
        let y0 = ty * TILE;
        let th = TILE.min(h - y0);
        let dirty: Vec<bool> = (0..cols).map(|tx| dirty(tx, ty)).collect();
        let mut next_open = Vec::new();
        let mut tx = 0;
        while tx < cols {
            if !dirty[tx as usize] {
                tx += 1;
                continue;
            }
            let start = tx;
            while tx < cols && dirty[tx as usize] {
                tx += 1;
            }
            let x = start * TILE;
            let width = (tx * TILE).min(w) - x;
            match open
                .iter()
                .find(|&&i| rects[i].x == x && rects[i].width == width)
            {
                Some(&i) => {
                    rects[i].height += th;
                    next_open.push(i);
                }
                None => {
                    next_open.push(rects.len());
                    rects.push(Rect {
                        x,
                        y: y0,
                        width,
                        height: th,
                    });
                }
            }
        }
        open = next_open;
    }
    if rects.len() > MAX_RECTS {
        return vec![Rect {
            x: 0,
            y: 0,
            width: w,
            height: h,
        }];
    }
    rects
}

fn encode_rect(frame: &Frame, rect: &Rect, quality: u8) -> Result<Vec<u8>> {
    let stride = frame.width as usize * 4;
    let mut rgb = Vec::with_capacity((rect.width * rect.height * 3) as usize);
    for y in rect.y..rect.y + rect.height {
        let i = y as usize * stride + rect.x as usize * 4;
        let row = &frame.rgba[i..i + rect.width as usize * 4];
        rgb.extend(
            row.as_chunks::<4>()
                .0
                .iter()
                .flat_map(|p| [p[0], p[1], p[2]]),
        );
    }
    let mut bytes = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, quality).write_image(
        &rgb,
        rect.width,
        rect.height,
        image::ExtendedColorType::Rgb8,
    )?;
    Ok(bytes)
}

fn threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(8)
}

/// Cut large rectangles into bands when much of the screen changed, as when
/// a page scrolls, so that several cores can share the encoding: one core
/// takes about 40 ms for a whole screen on a 2020 iMac.
fn split(frame: &Frame, rects: Vec<Rect>) -> Vec<Rect> {
    let pixels: u64 = rects.iter().map(|r| r.width as u64 * r.height as u64).sum();
    if pixels < PARALLEL_PIXELS || threads() < 2 {
        return rects;
    }
    let band = (frame.height / threads() as u32).max(TILE);
    rects
        .into_iter()
        .flat_map(|r| {
            (0..r.height.div_ceil(band)).map(move |b| {
                let y = r.y + b * band;
                Rect {
                    y,
                    height: band.min(r.y + r.height - y),
                    ..r
                }
            })
        })
        .collect()
}

/// Encode each rectangle, in order, on as many cores as there are bands.
fn encode_rects(frame: &Frame, rects: &[Rect], quality: u8) -> Result<Vec<Vec<u8>>> {
    if rects.len() < 2 || threads() < 2 {
        return rects
            .iter()
            .map(|r| encode_rect(frame, r, quality))
            .collect();
    }
    let chunk = rects.len().div_ceil(threads());
    std::thread::scope(|s| {
        let handles: Vec<_> = rects
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || {
                    part.iter()
                        .map(|r| encode_rect(frame, r, quality))
                        .collect::<Result<Vec<_>>>()
                })
            })
            .collect();
        let mut out = Vec::with_capacity(rects.len());
        for handle in handles {
            out.extend(
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("Screen encoder failed"))??,
            );
        }
        Ok(out)
    })
}

/// The helper's side: the screen as it stands, updated in place.
#[derive(Default)]
pub(crate) struct Canvas {
    /// The screen as it stands, as last handed out.
    shown: Option<std::sync::Arc<Frame>>,
    /// The one before it, drawn into next when nobody holds it any more,
    /// and the rectangles it lacks.
    spare: Option<std::sync::Arc<Frame>>,
    behind: Vec<Rect>,
}
impl Canvas {
    /// Draw one update. Returns its sequence number, the screen after it and
    /// the rectangles it changed.
    ///
    /// The screen is drawn into the one before last, brought up to date by
    /// the rectangles it lacks, rather than into a copy of the last one: a
    /// copy of a 1920 by 1080 screen cost a few milliseconds of every
    /// keystroke and pointer move.
    pub fn apply(&mut self, bytes: &[u8]) -> Result<(u64, std::sync::Arc<Frame>, Vec<Rect>)> {
        let mut r = Reader(bytes);
        let seq = u64::from_be_bytes(r.take::<8>()?);
        let width = u16::from_be_bytes(r.take::<2>()?) as u32;
        let height = u16::from_be_bytes(r.take::<2>()?) as u32;
        dimensions(width, height)?;
        let count = u16::from_be_bytes(r.take::<2>()?) as usize;
        ensure!(count > 0 && count <= MAX_RECTS * 8, "Invalid screen update");
        let fits = |f: &Frame| f.width == width && f.height == height;
        let shown = self.shown.clone().filter(|s| fits(s));
        let spare = self
            .spare
            .take()
            .and_then(|a| std::sync::Arc::try_unwrap(a).ok())
            .filter(fits);
        let mut frame = match (spare, &shown) {
            (Some(mut spare), Some(shown)) => {
                let stride = width as usize * 4;
                for b in &self.behind {
                    for y in b.y..b.y + b.height {
                        let i = y as usize * stride + b.x as usize * 4;
                        let n = b.width as usize * 4;
                        spare.rgba[i..i + n].copy_from_slice(&shown.rgba[i..i + n]);
                    }
                }
                spare
            }
            (_, Some(shown)) => (**shown).clone(),
            (_, None) => Frame {
                width,
                height,
                rgba: vec![0; width as usize * height as usize * 4],
            },
        };
        let mut rects = Vec::with_capacity(count);
        for _ in 0..count {
            let [x, y, w, h] = [(); 4].map(|_| r.take::<2>().map(u16::from_be_bytes));
            let rect = Rect {
                x: x? as u32,
                y: y? as u32,
                width: w? as u32,
                height: h? as u32,
            };
            ensure!(
                rect.width > 0
                    && rect.height > 0
                    && rect.x + rect.width <= width
                    && rect.y + rect.height <= height,
                "Screen update outside the screen"
            );
            let len = u32::from_be_bytes(r.take::<4>()?) as usize;
            let jpeg = r.bytes(len)?;
            draw(&mut frame, &rect, jpeg)?;
            rects.push(rect);
        }
        ensure!(r.0.is_empty(), "Trailing bytes in screen update");
        let frame = std::sync::Arc::new(frame);
        self.spare = self.shown.replace(frame.clone());
        self.behind = rects.clone();
        Ok((seq, frame, rects))
    }
}

fn draw(frame: &mut Frame, rect: &Rect, jpeg: &[u8]) -> Result<()> {
    ensure!(jpeg.starts_with(&[0xff, 0xd8]), "Screen update is not JPEG");
    let mut decoder = image::codecs::jpeg::JpegDecoder::new(Cursor::new(jpeg))?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(wire::MAX_SIDE);
    limits.max_image_height = Some(wire::MAX_SIDE);
    limits.max_alloc = Some(64 * 1024 * 1024);
    decoder.set_limits(limits)?;
    ensure!(
        decoder.dimensions() == (rect.width, rect.height),
        "Screen update has the wrong size"
    );
    let rgb = image::DynamicImage::from_decoder(decoder)?.into_rgb8();
    let stride = frame.width as usize * 4;
    for (row, line) in rgb
        .as_raw()
        .chunks_exact(rect.width as usize * 3)
        .enumerate()
    {
        let i = (rect.y as usize + row) * stride + rect.x as usize * 4;
        for (dst, src) in frame.rgba[i..i + rect.width as usize * 4]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(line.as_chunks::<3>().0)
        {
            *dst = [src[0], src[1], src[2], 255];
        }
    }
    Ok(())
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into()?)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "Screen update is cut short");
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn screen(width: u32, height: u32, seed: u8) -> Frame {
        Frame {
            width,
            height,
            rgba: (0..width * height)
                .flat_map(|i| {
                    let v = ((i % width) as u8 / 4).wrapping_add(seed);
                    [v, v, v, 255]
                })
                .collect(),
        }
    }

    #[test]
    fn updates_carry_only_what_changed_and_draw_back_to_the_screen() {
        let mut encoder = Encoder::default();
        let mut canvas = Canvas::default();
        let first = Arc::new(screen(1000, 700, 0));
        let full = encoder.update(first.clone(), 1).unwrap().unwrap();
        let (seq, shown, rects) = canvas.apply(&full).unwrap();
        assert_eq!((seq, shown.width, shown.height), (1, 1000, 700));
        assert!(rects.iter().map(|r| r.width * r.height).sum::<u32>() == 1000 * 700);
        assert!(encoder.update(first.clone(), 2).unwrap().is_none());

        // A small square moves: two tiles change, not the screen.
        let mut moved = (*first).clone();
        for y in 130..150 {
            for x in 70..90 {
                let i = (y * 1000 + x) * 4;
                moved.rgba[i..i + 3].copy_from_slice(&[255, 0, 255]);
            }
        }
        let small = encoder.update(Arc::new(moved.clone()), 2).unwrap().unwrap();
        assert!(
            small.len() * 20 < full.len(),
            "{} vs {}",
            small.len(),
            full.len()
        );
        let (seq, shown, rects) = canvas.apply(&small).unwrap();
        assert_eq!(seq, 2);
        assert_eq!(
            rects,
            vec![Rect {
                x: 64,
                y: 128,
                width: 64,
                height: 64
            }]
        );
        let i = (140 * 1000 + 80) * 4;
        assert!(shown.rgba[i] > 200 && shown.rgba[i + 1] < 60);

        // Most of the screen changes: cut into bands, all drawn.
        let busy = Arc::new(screen(1000, 700, 90));
        let update = encoder.update(busy, 3).unwrap().unwrap();
        let (_, shown, _) = canvas.apply(&update).unwrap();
        let i = (600 * 1000 + 900) * 4;
        assert!((shown.rgba[i] as i32 - (900u32 as u8 / 4).wrapping_add(90) as i32).abs() < 12);
    }

    /// Drawing into the screen before last gives the same screens as
    /// drawing into a copy, whether or not somebody still holds the old one,
    /// and when told what changed the encoder sends the same.
    #[test]
    fn the_spare_screen_and_damage_give_the_same_pictures() {
        let mut encoder = Encoder::default();
        let mut hinted = Encoder::default();
        let (mut free, mut held) = (Canvas::default(), Canvas::default());
        let mut keep = Vec::new();
        let mut frame = screen(512, 256, 0);
        for step in 0..8u32 {
            let damage = if step > 0 {
                let (x0, y0) = ((step * 37) % 400, (step * 23) % 200);
                for y in y0..y0 + 30 {
                    for x in x0..x0 + 50 {
                        let i = ((y * 512 + x) * 4) as usize;
                        frame.rgba[i..i + 3].copy_from_slice(&[255, step as u8 * 30, 0]);
                    }
                }
                vec![Rect {
                    x: x0,
                    y: y0,
                    width: 50,
                    height: 30,
                }]
            } else {
                Vec::new()
            };
            let arc = Arc::new(frame.clone());
            let update = encoder
                .update(arc.clone(), step as u64 + 1)
                .unwrap()
                .unwrap();
            let with = hinted
                .update_with(
                    arc,
                    step as u64 + 1,
                    crate::JPEG_QUALITY,
                    (step > 0).then_some(&damage[..]),
                )
                .unwrap()
                .unwrap();
            assert_eq!(update, with);
            let (_, a, _) = free.apply(&update).unwrap();
            let (_, b, _) = held.apply(&update).unwrap();
            assert_eq!(a.rgba, b.rgba, "step {step}");
            keep.push(b);
        }
    }

    #[test]
    fn untrusted_updates_are_refused() {
        let mut canvas = Canvas::default();
        assert!(canvas.apply(b"short").is_err());
        let mut encoder = Encoder::default();
        let mut update = encoder
            .update(Arc::new(screen(128, 64, 0)), 1)
            .unwrap()
            .unwrap();
        // A rectangle that claims to reach past the screen.
        update[14..16].copy_from_slice(&200u16.to_be_bytes());
        assert!(canvas.apply(&update).is_err());
    }
}
