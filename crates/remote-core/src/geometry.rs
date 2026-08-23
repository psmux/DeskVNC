//! Geometry.
//!
//! Moved out of `vnc-core/src/types.rs` unchanged (PRDRDP/02 §2.1).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl Rect {
    pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
    pub fn area(&self) -> usize {
        self.width as usize * self.height as usize
    }
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
    /// Smallest rectangle covering both.
    pub fn union(&self, other: &Rect) -> Rect {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        let x0 = self.x.min(other.x);
        let y0 = self.y.min(other.y);
        let x1 = (self.x + self.width).max(other.x + other.width);
        let y1 = (self.y + self.height).max(other.y + other.height);
        Rect::new(x0, y0, x1 - x0, y1 - y0)
    }
    /// Overlapping region of both, or an empty rect when they are disjoint.
    pub fn intersect(&self, other: &Rect) -> Rect {
        let x0 = self.x.max(other.x);
        let y0 = self.y.max(other.y);
        let x1 = (self.x + self.width).min(other.x + other.width);
        let y1 = (self.y + self.height).min(other.y + other.height);
        if x1 <= x0 || y1 <= y0 {
            return Rect::new(0, 0, 0, 0);
        }
        Rect::new(x0, y0, x1 - x0, y1 - y0)
    }
}
