//! The exact way back from a pixel in the image we sent to a pixel on the
//! remote screen.
//!
//! `00 R43` (WA-13) and `15 §6`. **The inverse transform is
//! `fb_x = rx + floor((mx + 0.5) / s)`**, where `(rx, ry)` is the crop origin
//! in framebuffer coordinates, `(mx, my)` is what the model read off the image
//! it was sent, and `s` is the scale we applied.
//!
//! The `+ 0.5` is the term everybody drops, including two of the reference
//! implementations the ruling was written against. Without it the transform
//! lands on the top left corner of the source box rather than its centre,
//! which is a half source pixel bias at every scale and about 2 px on a
//! 5760 wide triple head. A 2 px bias is invisible in a test on a 400x300
//! image and it is the difference between hitting a scrollbar and hitting the
//! window beside it.
//!
//! It is a function here rather than a comment in a wire format document
//! because a comment cannot be tested and this one has to be. `00 R43` also
//! records why it degenerates cleanly: at `s = 1.0` the expression is
//! `rx + floor(mx + 0.5)`, which for an integer `mx` is `rx + mx` with no
//! rounding at all, and that identity is asserted rather than assumed.
//!
//! The other half of `00 R43` is a rule this module cannot enforce and the
//! caller must: **never send an image the provider will resize** (WA-11),
//! because then the scale factor is one we did not choose and cannot invert.
//! [`crate::encode::DEFAULT_LONG_EDGE`] exists to keep that from happening.

use limb_core::intent::Point;
use remote_core::geometry::Rect;
use serde::Serialize;

/// An image that was made from part of a framebuffer, and the way back.
///
/// Carried with every encoded image rather than beside it, because a scale
/// factor that can be separated from its image is a scale factor that will be
/// separated from its image, and a coordinate transformed with the wrong
/// scale produces a click that lands somewhere plausible.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ImageSpace {
    /// The framebuffer rectangle this image was made from. `03 §4.4`'s
    /// `rect`, and its `x` and `y` are the `rx` and `ry` of the transform.
    pub region: Rect,
    /// Image width in pixels, after any downscale.
    pub width: u32,
    /// Image height in pixels, after any downscale.
    pub height: u32,
    /// Output pixels per source pixel. Exactly 1.0 for a region read, which is
    /// why `03 §4.4` says a region is the rung to read a dialog from.
    ///
    /// `f64` and not `f32`. The transform divides by this and then floors, so
    /// a value that is a rounding away from 1.0 turns the exact case into an
    /// off by one at the right hand edge.
    pub scale: f64,
}

impl ImageSpace {
    /// An image that is the region itself, pixel for pixel.
    pub fn unscaled(region: Rect) -> Self {
        ImageSpace {
            region,
            width: region.width as u32,
            height: region.height as u32,
            scale: 1.0,
        }
    }

    /// Is this the case with no arithmetic to argue about?
    pub fn is_unscaled(&self) -> bool {
        self.scale == 1.0
    }

    /// A coordinate the model read off this image, in framebuffer pixels.
    ///
    /// `00 R43`'s expression, written once.
    ///
    /// Out of range is REFUSED and never clamped, which is the rule
    /// `RefusalCode::OutOfBounds` already sets for a coordinate outside the
    /// framebuffer: a clamped coordinate lands on whatever is at the edge,
    /// which is a different action performed silently.
    pub fn to_framebuffer(&self, mx: u32, my: u32) -> Result<Point, OutOfImage> {
        if mx >= self.width || my >= self.height {
            return Err(OutOfImage {
                x: mx,
                y: my,
                width: self.width,
                height: self.height,
            });
        }
        Ok(Point::new(
            self.region.x + source_offset(mx, self.scale),
            self.region.y + source_offset(my, self.scale),
        ))
    }

    /// A framebuffer coordinate as a pixel of this image.
    ///
    /// The forward direction, which exists for two reasons: it draws a mark on
    /// the image at a place the plane already knows about, such as the
    /// pointer, and it makes the round trip an assertion rather than an
    /// argument.
    ///
    /// It is the algebraic inverse of [`ImageSpace::to_framebuffer`],
    /// `mx = round((sx + 0.5) * s - 0.5)`, and it is deliberately NOT the
    /// source box `remote_pixel::downscale_rgba` averaged over. Those two
    /// disagree by one pixel at ratios near 1.0, because the box boundaries
    /// are integer divisions of the output index and the ruling's inverse is a
    /// division of the output pixel's centre. `00 R43` fixes the inverse, so
    /// the inverse is what a coordinate goes through, and the filter's window
    /// is an implementation detail of how the colour got there.
    pub fn to_image(&self, p: Point) -> Result<(u32, u32), OutsideRegion> {
        let inside = p.x >= self.region.x
            && p.y >= self.region.y
            && u32::from(p.x) < u32::from(self.region.x) + u32::from(self.region.width)
            && u32::from(p.y) < u32::from(self.region.y) + u32::from(self.region.height);
        if !inside {
            return Err(OutsideRegion {
                point: p,
                region: self.region,
            });
        }
        let map = |v: u16, origin: u16, limit: u32| {
            let scaled = ((f64::from(v - origin) + 0.5) * self.scale - 0.5).round();
            (scaled.max(0.0) as u32).min(limit.saturating_sub(1))
        };
        Ok((
            map(p.x, self.region.x, self.width),
            map(p.y, self.region.y, self.height),
        ))
    }
}

/// `floor((m + 0.5) / s)`, the whole ruling in one line.
///
/// `f64` throughout. For every `m` a `u16` framebuffer can hold, `m + 0.5` is
/// exact in `f64` and so is the division by 1.0, so the `s = 1.0` case
/// degenerates to `m` by arithmetic rather than by a special case. A branch on
/// `s == 1.0` would pass the same test and prove nothing about the general
/// path, which is the path that actually carries a coordinate back from a
/// downscaled frame.
fn source_offset(m: u32, s: f64) -> u16 {
    let offset = ((f64::from(m) + 0.5) / s).floor();
    // A crop is a `Rect`, so the offset cannot leave `u16` unless the caller
    // built an `ImageSpace` whose scale disagrees with its own dimensions.
    // Saturating rather than wrapping: an absurd coordinate at the edge of the
    // screen is recoverable, and a wrapped one is a click at the origin.
    if offset < 0.0 {
        0
    } else if offset > f64::from(u16::MAX) {
        u16::MAX
    } else {
        offset as u16
    }
}

/// The model named a pixel this image does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("({x}, {y}) is outside the {width}x{height} image it was read from: nothing was clamped, read the image again and name a pixel inside it")]
pub struct OutOfImage {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// A framebuffer coordinate that this image does not show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("({}, {}) is outside the region this image covers, which is {}x{} at ({}, {})", point.x, point.y, region.width, region.height, region.x, region.y)]
pub struct OutsideRegion {
    pub point: Point,
    pub region: Rect,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_scale_one_it_is_addition_and_nothing_else() {
        let space = ImageSpace::unscaled(Rect::new(600, 340, 400, 200));
        for mx in 0..400u32 {
            let p = space.to_framebuffer(mx, 0).unwrap();
            assert_eq!(p.x, 600 + mx as u16, "off by one at mx = {mx}");
        }
    }

    #[test]
    fn the_half_pixel_is_actually_there() {
        // A half scale image: output pixel 3 covers source pixels 6 and 7, and
        // the ruling picks the one at the centre of that box, which is 7.
        // Dropping the `+ 0.5` would answer 6 at every pixel and nobody would
        // notice until a triple head desktop was off by two.
        let space = ImageSpace {
            region: Rect::new(0, 0, 800, 600),
            width: 400,
            height: 300,
            scale: 0.5,
        };
        assert_eq!(space.to_framebuffer(3, 0).unwrap().x, 7);
        assert_eq!(space.to_framebuffer(0, 0).unwrap().x, 1);
    }

    #[test]
    fn out_of_range_is_refused_rather_than_clamped() {
        let space = ImageSpace::unscaled(Rect::new(0, 0, 10, 10));
        assert!(space.to_framebuffer(10, 0).is_err());
    }
}
