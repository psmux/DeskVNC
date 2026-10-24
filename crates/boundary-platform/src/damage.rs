//! Changed rectangles as a capture backend reports them, made fit for the
//! screen that is sent. Kept apart from any one backend so it is tested on
//! every platform.
// Only Desktop Duplication reports changes so far.
#![cfg_attr(not(windows), allow(dead_code))]
use boundary_session::Rect;

/// More rectangles than this are sent as the one box around them all. Desktop
/// Duplication can report hundreds of tiny ones for a page of text, and each
/// costs a copy from the GPU and a JPEG header, while the box around them is
/// usually not much larger than their sum.
const MAX_RECTS: usize = 64;

/// Clip rectangles to a `width` by `height` screen, drop empty ones, and fold
/// them into one when there are too many to be worth keeping apart.
pub(crate) fn tidy(rects: impl IntoIterator<Item = Rect>, width: u32, height: u32) -> Vec<Rect> {
    let mut out: Vec<Rect> = rects
        .into_iter()
        .filter_map(|r| {
            let x = r.x.min(width);
            let y = r.y.min(height);
            let right = r.x.saturating_add(r.width).min(width);
            let bottom = r.y.saturating_add(r.height).min(height);
            (right > x && bottom > y).then_some(Rect {
                x,
                y,
                width: right - x,
                height: bottom - y,
            })
        })
        .collect();
    if out.len() > MAX_RECTS {
        out = vec![bounds(&out)];
    }
    out
}

/// The box around all of `rects`, which must not be empty.
fn bounds(rects: &[Rect]) -> Rect {
    let x = rects.iter().map(|r| r.x).min().unwrap_or(0);
    let y = rects.iter().map(|r| r.y).min().unwrap_or(0);
    let right = rects.iter().map(|r| r.x + r.width).max().unwrap_or(0);
    let bottom = rects.iter().map(|r| r.y + r.height).max().unwrap_or(0);
    Rect {
        x,
        y,
        width: right - x,
        height: bottom - y,
    }
}

/// A rectangle of a `from` sized screen, in the pixels of the same screen
/// shrunk to `to`. It is widened by a pixel each way, since a shrunk pixel
/// blends its neighbours and one just outside a change can change too.
pub(crate) fn scale(rect: Rect, from: (u32, u32), to: (u32, u32)) -> Rect {
    let sx = to.0 as f64 / from.0.max(1) as f64;
    let sy = to.1 as f64 / from.1.max(1) as f64;
    let x = ((rect.x as f64 * sx).floor() as u32).saturating_sub(1);
    let y = ((rect.y as f64 * sy).floor() as u32).saturating_sub(1);
    let right = (((rect.x + rect.width) as f64 * sx).ceil() as u32 + 1).min(to.0);
    let bottom = (((rect.y + rect.height) as f64 * sy).ceil() as u32 + 1).min(to.1);
    Rect {
        x,
        y,
        width: right.saturating_sub(x),
        height: bottom.saturating_sub(y),
    }
}

/// One row of BGRA pixels as RGBA, opaque. Done a word at a time, which the
/// compiler turns into vector shuffles.
pub(crate) fn bgra_to_rgba(src: &[u8], dst: &mut [u8]) {
    for (s, d) in src
        .as_chunks::<4>()
        .0
        .iter()
        .zip(dst.as_chunks_mut::<4>().0.iter_mut())
    {
        let p = u32::from_le_bytes(*s);
        let q = ((p >> 16) & 0xff) | (p & 0xff00) | ((p & 0xff) << 16) | 0xff00_0000;
        *d = q.to_le_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: u32, y: u32, width: u32, height: u32) -> Rect {
        Rect {
            x,
            y,
            width,
            height,
        }
    }

    #[test]
    fn tidy_clips_and_drops_empty() {
        let out = tidy(
            [
                rect(10, 10, 100, 100),
                rect(90, 90, 50, 50),
                rect(200, 0, 5, 5),
            ],
            100,
            100,
        );
        assert_eq!(out, vec![rect(10, 10, 90, 90), rect(90, 90, 10, 10)]);
    }

    #[test]
    fn tidy_folds_many_into_one() {
        let many = (0..100).map(|i| rect(i * 2, i, 1, 1));
        assert_eq!(tidy(many, 1000, 1000), vec![rect(0, 0, 199, 100)]);
    }

    #[test]
    fn scale_widens_and_clamps() {
        // A 4K screen shown at 1920 by 1080: half size.
        let r = scale(rect(100, 100, 10, 10), (3840, 2160), (1920, 1080));
        assert_eq!(r, rect(49, 49, 7, 7));
        let edge = scale(rect(3830, 2150, 10, 10), (3840, 2160), (1920, 1080));
        assert_eq!(edge.x + edge.width, 1920);
        assert_eq!(edge.y + edge.height, 1080);
        let corner = scale(rect(0, 0, 1, 1), (3840, 2160), (1920, 1080));
        assert_eq!((corner.x, corner.y), (0, 0));
    }

    #[test]
    fn bgra_becomes_opaque_rgba() {
        let src = [1, 2, 3, 0, 10, 20, 30, 40];
        let mut dst = [0; 8];
        bgra_to_rgba(&src, &mut dst);
        assert_eq!(dst, [3, 2, 1, 255, 30, 20, 10, 255]);
    }
}
