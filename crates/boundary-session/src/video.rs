//! Moving screens as H.264, for helpers that decode it.
//!
//! Changed tiles as JPEG are cheap for a pointer, a caret or a line of text,
//! but when most of the screen moves (a video, a window dragged, a page
//! scrolled) every tile changes every capture and a whole screen of JPEG goes
//! each time. That held a helper across an ocean to ten or twelve screens a
//! second. A video encoder sends only how the picture moved, so while much of
//! the screen changes the host sends H.264 instead, and when the screen comes
//! to rest it sends the whole screen once more as tiles, so text is sharp
//! again and the helper's own copy of the screen is whole.
//!
//! The encoder is the platform's (VideoToolbox, Media Foundation, or a
//! software one), which is why this crate only names what one does.
use crate::{Frame, screen, wire};
use anyhow::{Result, ensure};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// One encoded picture.
pub struct Encoded {
    /// Annex B: NAL units each after a start code, with the parameter sets
    /// before every keyframe so a decoder can start there.
    pub data: Vec<u8>,
    /// An IDR picture, which a decoder can start from.
    pub keyframe: bool,
}

/// A low latency H.264 encoder: no B frames, one picture in and one out, so
/// what comes out of [`VideoEncoder::encode`] is the picture just given.
pub trait VideoEncoder: Send {
    /// What does the encoding, for the log: "VideoToolbox", "OpenH264".
    fn name(&self) -> &str;
    /// Encode one screen, the same size as the encoder was made for.
    /// `keyframe` asks for an IDR picture.
    fn encode(&mut self, frame: &Frame, keyframe: bool) -> Result<Encoded>;
    /// The bits a second to aim for and the screens a second expected,
    /// which the sender changes as it measures the link.
    fn set_rate(&mut self, bits_per_second: u32, frames_per_second: u32);
    /// The last picture as the helper's decoder draws it,
    /// once every picture encoded so far has been decoded here too, so the
    /// host can tell which parts video already drew well. `None` when this
    /// encoder does not keep a decoded copy.
    fn shown(&mut self) -> Option<Shown> {
        None
    }
}

/// A decoded picture, as YUV 4:2:0 planes, and how to compare a screen with it.
pub struct Shown {
    pub luma: Vec<u8>,
    /// Bytes from one row of `luma` to the next.
    pub stride: usize,
    /// The colour planes, at half the width and half the height.
    pub u: Vec<u8>,
    pub v: Vec<u8>,
    pub chroma_stride: usize,
    /// The colours were encoded as BT.709, not BT.601.
    pub bt709: bool,
}

/// Makes an encoder for screens of a given width and height.
pub type VideoEncoders = Arc<dyn Fn(u32, u32) -> Result<Box<dyn VideoEncoder>> + Send + Sync>;

/// On the helper's side: one picture of H.264, in order, for a decoder.
#[derive(Clone, Debug)]
pub struct VideoUnit {
    pub width: u32,
    pub height: u32,
    /// Annex B.
    pub data: Vec<u8>,
    pub keyframe: bool,
    /// The first picture of a new encoder, whose decoder has to start over.
    pub fresh: bool,
}

/// What the helper's window should draw next, in the order it arrived.
#[derive(Clone, Debug)]
pub enum Update {
    /// The screen as it now stands, with the rectangles that changed since
    /// the last update read, or `None` when all of it may have.
    Screen {
        frame: Arc<Frame>,
        rects: Option<Vec<screen::Rect>>,
    },
    /// A picture of video covering the whole screen. The screen in
    /// [`Update::Screen`] does not follow it: it is the last one sent as
    /// rectangles, until the host sends rectangles again.
    Video(VideoUnit),
}

/// Kinds of message on a stream that starts with [`screen::MAGIC_VIDEO`].
pub(crate) const KIND_TILES: u8 = 0;
pub(crate) const KIND_VIDEO: u8 = 1;
const FLAG_KEYFRAME: u8 = 1;
const FLAG_FRESH: u8 = 2;

/// A picture of video as it goes on the wire, after its kind:
///
/// ```text
/// seq u64 | width u16 | height u16 | flags u8 (1 keyframe, 2 fresh) | Annex B
/// ```
pub(crate) fn encode_unit(
    seq: u64,
    width: u32,
    height: u32,
    unit: &Encoded,
    fresh: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + unit.data.len());
    out.push(KIND_VIDEO);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(width as u16).to_be_bytes());
    out.extend_from_slice(&(height as u16).to_be_bytes());
    out.push(if unit.keyframe { FLAG_KEYFRAME } else { 0 } | if fresh { FLAG_FRESH } else { 0 });
    out.extend_from_slice(&unit.data);
    out
}

/// The sequence number and picture in a message of [`KIND_VIDEO`], without
/// its kind byte.
pub(crate) fn decode_unit(bytes: &[u8]) -> Result<(u64, VideoUnit)> {
    ensure!(bytes.len() > 13, "Video update is cut short");
    let seq = u64::from_be_bytes(bytes[0..8].try_into()?);
    let width = u16::from_be_bytes(bytes[8..10].try_into()?) as u32;
    let height = u16::from_be_bytes(bytes[10..12].try_into()?) as u32;
    crate::dimensions(width, height)?;
    let flags = bytes[12];
    let data = bytes[13..].to_vec();
    ensure!(
        data.starts_with(&[0, 0, 1]) || data.starts_with(&[0, 0, 0, 1]),
        "Video update is not Annex B"
    );
    Ok((
        seq,
        VideoUnit {
            width,
            height,
            data,
            keyframe: flags & FLAG_KEYFRAME != 0,
            fresh: flags & FLAG_FRESH != 0,
        },
    ))
}

/// Above this share of the screen changing from one capture to the next,
/// the capture counts as motion. A paragraph typed or a menu opened is a few
/// percent; a scrolled page or a dragged window is most of it.
pub(crate) const MOTION_SHARE: f32 = 0.25;
/// Captures of motion in a row before video starts, so that one large
/// change, such as a window opening, goes as sharp tiles.
pub(crate) const MOTION_RUN: u32 = 2;
/// Below this share a capture counts as quiet: a pointer or a caret.
pub(crate) const QUIET_SHARE: f32 = 0.02;
/// How long the screen has to stay quiet before video stops and the screen
/// is sent sharp again. It is most of the time from the last moving picture
/// to the sharp one, since only the tiles video drew wrong go then.
pub(crate) const SETTLE: Duration = Duration::from_millis(60);
/// Motion again this soon after the screen settled was a pause, not a stop,
/// as between the turns of a scroll wheel: video picks up at once, and waits
/// longer before it settles again.
pub(crate) const RESUME: Duration = Duration::from_millis(500);
pub(crate) const SETTLE_AGAIN: Duration = Duration::from_millis(200);

/// When to send video and when tiles.
#[derive(Default)]
pub(crate) struct Policy {
    run: u32,
    video: bool,
    /// When the last capture that was not quiet came, while on video.
    busy: Option<Instant>,
    /// When the screen last settled.
    settled: Option<Instant>,
    /// How long to wait for this run of video to settle.
    wait: Duration,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Choice {
    Tiles,
    /// Video, starting with a keyframe when `start`.
    Video {
        start: bool,
    },
}
impl Policy {
    /// What to send for a capture of which `share` changed.
    pub fn capture(&mut self, share: f32, now: Instant) -> Choice {
        if share >= MOTION_SHARE {
            self.run += 1;
        } else {
            self.run = 0;
        }
        if share >= QUIET_SHARE {
            self.busy = Some(now);
        }
        if self.video {
            return Choice::Video { start: false };
        }
        let resumed = self
            .settled
            .is_some_and(|at| now.saturating_duration_since(at) < RESUME);
        if self.run >= MOTION_RUN || (resumed && share >= MOTION_SHARE) {
            self.video = true;
            self.busy = Some(now);
            self.wait = if resumed { SETTLE_AGAIN } else { SETTLE };
            return Choice::Video { start: true };
        }
        Choice::Tiles
    }
    /// When the screen will have settled, while on video.
    pub fn settles_at(&self) -> Option<Instant> {
        let wait = self.wait.max(SETTLE);
        self.video.then(|| self.busy.map(|b| b + wait)).flatten()
    }
    /// Video has stopped, as the helper asked for the whole screen: the next
    /// capture goes as tiles.
    pub fn stop(&mut self) {
        self.video = false;
        self.run = 0;
        self.busy = None;
        self.settled = None;
    }
    /// The screen settled at `now`.
    pub fn settle(&mut self, now: Instant) {
        self.stop();
        self.settled = Some(now);
    }
    pub fn on_video(&self) -> bool {
        self.video
    }
}

/// The share of 64 pixel tiles that differ between two screens of one size.
pub(crate) fn changed_share(old: &Frame, new: &Frame) -> f32 {
    const TILE: usize = 64;
    let (w, h) = (new.width as usize, new.height as usize);
    if old.width != new.width || old.height != new.height {
        return 1.0;
    }
    let stride = w * 4;
    let (cols, rows) = (w.div_ceil(TILE), h.div_ceil(TILE));
    let mut dirty = 0usize;
    for ty in 0..rows {
        let y0 = ty * TILE;
        let y1 = (y0 + TILE).min(h);
        for tx in 0..cols {
            let x0 = tx * TILE * 4;
            let x1 = ((tx + 1) * TILE).min(w) * 4;
            if (y0..y1).any(|y| {
                old.rgba[y * stride + x0..y * stride + x1]
                    != new.rgba[y * stride + x0..y * stride + x1]
            }) {
                dirty += 1;
            }
        }
    }
    dirty as f32 / (cols * rows) as f32
}

/// A tile whose brightness is off by more than this at any pixel, as the
/// edges of blurred text are, is sent again sharp once the screen settles.
/// JPEG at the settled quality is off by about this much itself, so what is
/// left alone looks as good as what is sent.
pub(crate) const STALE_PEAK: u32 = 24;
/// Or off by more than this on average. On a desktop picture that scrolled,
/// this is what picks most tiles: a fifth to four fifths of the screen, where
/// sending all of it was the rule before.
pub(crate) const STALE_MEAN: u32 = 2;

/// Which 64 pixel tiles, in rows, the helper's video picture shows visibly
/// differently from `frame`. Tiles video drew well enough, such as plain
/// backgrounds, need not be sent again when the screen settles.
pub(crate) fn stale_tiles(frame: &Frame, shown: &Shown) -> Vec<bool> {
    const TILE: usize = 64;
    let (w, h) = (frame.width as usize, frame.height as usize);
    let (cols, rows) = (w.div_ceil(TILE), h.div_ceil(TILE));
    // Limited range YUV to RGB, in 256ths: red from V, green from U and V,
    // blue from U, after 298 Y.
    let (rv, gu, gv, bu) = if shown.bt709 {
        (459, 55, 136, 541)
    } else {
        (409, 100, 208, 516)
    };
    let mut stale = vec![false; cols * rows];
    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
    if shown.stride < w
        || shown.luma.len() < shown.stride * h
        || shown.chroma_stride < cw
        || shown.u.len() < shown.chroma_stride * ch
        || shown.v.len() < shown.chroma_stride * ch
    {
        stale.fill(true);
        return stale;
    }
    for ty in 0..rows {
        for tx in 0..cols {
            let (x0, y0) = (tx * TILE, ty * TILE);
            let (x1, y1) = ((x0 + TILE).min(w), (y0 + TILE).min(h));
            let (mut peak, mut sum) = (0u32, 0u32);
            for y in y0..y1 {
                let rgba = &frame.rgba[(y * w + x0) * 4..(y * w + x1) * 4];
                let luma = &shown.luma[y * shown.stride..];
                let (u, v) = (
                    &shown.u[y / 2 * shown.chroma_stride..],
                    &shown.v[y / 2 * shown.chroma_stride..],
                );
                for (x, p) in (x0..x1).zip(rgba.as_chunks::<4>().0) {
                    let c = 298 * (luma[x] as i32 - 16);
                    let (d, e) = (u[x / 2] as i32 - 128, v[x / 2] as i32 - 128);
                    let shown = [
                        (c + rv * e + 128) >> 8,
                        (c - gu * d - gv * e + 128) >> 8,
                        (c + bu * d + 128) >> 8,
                    ];
                    for (s, t) in shown.into_iter().zip(&p[..3]) {
                        let diff = s.clamp(0, 255).abs_diff(*t as i32);
                        peak = peak.max(diff);
                        sum += diff;
                    }
                }
            }
            let area = ((x1 - x0) * (y1 - y0) * 3) as u32;
            stale[ty * cols + tx] = peak > STALE_PEAK || sum > STALE_MEAN * area;
        }
    }
    stale
}

/// [`changed_share`] from the rectangles a desktop said changed, without
/// looking at a pixel: the share of 64 pixel tiles they touch.
pub(crate) fn damage_share(rects: &[screen::Rect], width: u32, height: u32) -> f32 {
    const TILE: u32 = 64;
    let (cols, rows) = (width.div_ceil(TILE), height.div_ceil(TILE));
    let mut touched = vec![false; (cols * rows) as usize];
    for r in rects {
        if r.width == 0 || r.height == 0 || r.x >= width || r.y >= height {
            continue;
        }
        let (x1, y1) = (
            (r.x + r.width).min(width) - 1,
            (r.y + r.height).min(height) - 1,
        );
        for ty in r.y / TILE..=y1 / TILE {
            for tx in r.x / TILE..=x1 / TILE {
                touched[(ty * cols + tx) as usize] = true;
            }
        }
    }
    touched.iter().filter(|t| **t).count() as f32 / touched.len() as f32
}

/// Bits a second to aim the encoder at, from what the link carries.
///
/// The congestion window over the round trip is what the link delivers a
/// second right now. Video takes about half of that, so the tiles of the
/// settle refresh and the input still find room, and the queue at the
/// bottleneck stays short: a frame that waits there is lag the helper feels.
pub(crate) fn bitrate(cwnd: u64, rtt: Duration) -> u32 {
    const MIN: u64 = 300_000;
    const MAX: u64 = 16_000_000;
    let rtt = rtt.max(Duration::from_millis(5)).as_secs_f64();
    ((cwnd as f64 * 8.0 / rtt * 0.5) as u64).clamp(MIN, MAX) as u32
}

/// Screens a second to aim for at a bit rate: fewer on a slow link, so each
/// one keeps enough bits to be readable.
pub(crate) fn frame_rate(bits_per_second: u32) -> u32 {
    (bits_per_second / 40_000).clamp(10, 60)
}

/// Read a whole message off a stream of updates, which carries
/// [`wire::MAX_FRAME`] at most.
pub(crate) fn bounded(length: usize) -> Result<usize> {
    ensure!(
        length > 0 && length <= wire::MAX_FRAME,
        "Invalid screen update length"
    );
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_starts_on_sustained_motion_and_settles_after_quiet() {
        let mut policy = Policy::default();
        let t = Instant::now();
        let ms = |n| t + Duration::from_millis(n);
        // A pointer and a caret stay on tiles.
        assert_eq!(policy.capture(0.01, ms(0)), Choice::Tiles);
        // One big change, a window opening, stays on tiles.
        assert_eq!(policy.capture(0.9, ms(16)), Choice::Tiles);
        assert_eq!(policy.capture(0.0, ms(32)), Choice::Tiles);
        // Scrolling: two captures of motion in a row start video.
        assert_eq!(policy.capture(0.6, ms(48)), Choice::Tiles);
        assert_eq!(policy.capture(0.6, ms(64)), Choice::Video { start: true });
        assert_eq!(policy.capture(0.6, ms(80)), Choice::Video { start: false });
        assert_eq!(policy.settles_at(), Some(ms(80) + SETTLE));
        // The pointer moving after the scroll stops does not hold video.
        assert_eq!(policy.capture(0.01, ms(96)), Choice::Video { start: false });
        assert_eq!(policy.settles_at(), Some(ms(80) + SETTLE));
        policy.settle(ms(180));
        assert_eq!(policy.settles_at(), None);
        assert_eq!(policy.capture(0.01, ms(300)), Choice::Tiles);
        // Motion again soon after: a pause in a scroll. Video at once, and a
        // longer wait before settling again.
        assert_eq!(policy.capture(0.6, ms(400)), Choice::Video { start: true });
        assert_eq!(policy.settles_at(), Some(ms(400) + SETTLE_AGAIN));
        policy.settle(ms(700));
        // Long after, motion starts as new: two captures in a row.
        assert_eq!(policy.capture(0.6, ms(2000)), Choice::Tiles);
        assert_eq!(policy.capture(0.6, ms(2016)), Choice::Video { start: true });
        assert_eq!(policy.settles_at(), Some(ms(2016) + SETTLE));
    }

    #[test]
    fn units_go_through_the_wire_and_bad_ones_are_refused() {
        let unit = Encoded {
            data: vec![0, 0, 0, 1, 0x67, 1, 2, 3],
            keyframe: true,
        };
        let bytes = encode_unit(7, 1920, 1200, &unit, true);
        assert_eq!(bytes[0], KIND_VIDEO);
        let (seq, back) = decode_unit(&bytes[1..]).unwrap();
        assert_eq!((seq, back.width, back.height), (7, 1920, 1200));
        assert!(back.keyframe && back.fresh);
        assert_eq!(back.data, unit.data);
        assert!(decode_unit(&bytes[1..10]).is_err());
        let mut huge = bytes.clone();
        huge[9..11].copy_from_slice(&60000u16.to_be_bytes());
        assert!(decode_unit(&huge[1..]).is_err());
        let mut junk = bytes;
        junk[14] = 9;
        assert!(decode_unit(&junk[1..]).is_err());
    }

    #[test]
    fn rate_follows_the_link() {
        // Across an ocean: 300 ms and a 400 KB window.
        let slow = bitrate(400_000, Duration::from_millis(300));
        assert!((4_000_000..6_000_000).contains(&slow), "{slow}");
        assert!(frame_rate(slow) >= 30);
        // A cellular uplink gets less, and fewer screens.
        let cell = bitrate(30_000, Duration::from_millis(200));
        assert!(cell < 1_000_000 && frame_rate(cell) < 30);
        // A LAN is capped.
        assert_eq!(bitrate(10_000_000, Duration::from_millis(1)), 16_000_000);
    }

    #[test]
    fn only_tiles_video_drew_visibly_wrong_are_stale() {
        // Video drew a plain grey screen; the screen has text in one tile.
        let (w, h) = (256usize, 128usize);
        let grey = 128u32;
        for bt709 in [false, true] {
            let (kr, kg, kb) = if bt709 { (47, 157, 16) } else { (66, 129, 25) };
            let y = (((kr + kg + kb) * grey + 128) >> 8) + 16;
            let shown = Shown {
                luma: vec![y as u8; w * h],
                stride: w,
                u: vec![128; w / 2 * h / 2],
                v: vec![128; w / 2 * h / 2],
                chroma_stride: w / 2,
                bt709,
            };
            let mut frame = Frame {
                width: w as u32,
                height: h as u32,
                rgba: [grey as u8, grey as u8, grey as u8, 255].repeat(w * h),
            };
            assert!(stale_tiles(&frame, &shown).iter().all(|s| !s));
            for x in 70..80 {
                let i = (100 * w + x) * 4;
                frame.rgba[i..i + 3].copy_from_slice(&[0, 0, 0]);
            }
            let stale = stale_tiles(&frame, &shown);
            assert_eq!(stale.iter().filter(|s| **s).count(), 1);
            assert!(stale[4 + 1], "the tile at (1, 1) of 4 by 2");
        }
    }

    #[test]
    fn share_counts_tiles() {
        let a = Frame {
            width: 256,
            height: 128,
            rgba: vec![0; 256 * 128 * 4],
        };
        let mut b = a.clone();
        assert_eq!(changed_share(&a, &b), 0.0);
        b.rgba[0] = 1;
        assert_eq!(changed_share(&a, &b), 1.0 / 8.0);
        // The same, from what a desktop said changed.
        let rect = |x, y, width, height| screen::Rect {
            x,
            y,
            width,
            height,
        };
        assert_eq!(damage_share(&[rect(0, 0, 1, 1)], 256, 128), 1.0 / 8.0);
        assert_eq!(damage_share(&[rect(60, 0, 10, 70)], 256, 128), 4.0 / 8.0);
        assert_eq!(
            damage_share(&[rect(0, 0, 256, 128), rect(0, 0, 9, 9)], 256, 128),
            1.0
        );
        assert_eq!(damage_share(&[rect(300, 0, 5, 5)], 256, 128), 0.0);
    }
}
