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

/// How many times a session's geometry has changed under an agent.
///
/// `PRDAgentPlug/00 R10`. Two authors found the defect from opposite
/// directions, which is what promoted it from a hypothesis to a finding. A
/// `DesktopResize` arrives and a pointer packet already in flight from
/// `send_input` lands against the NEW framebuffer. A person's next move
/// corrects it within 50 ms because a person is watching. An agent's does not,
/// because the agent is not looking at the screen, it is waiting for a result,
/// and the click it just made landed somewhere it did not choose.
///
/// Starts at [`GeometryGeneration::FIRST`] on the first `Connected` and
/// increments, never resets, for the life of the session (`02 §4.5`). It is
/// not stable across anything: it exists to be compared, and an agent that has
/// lost it reacquires it by observing.
///
/// It lives here rather than beside the counter that mints it because
/// [`AgentIntent::fence`](crate::intent::AgentIntent::fence) carries one and
/// this crate cannot reach into `limb-core` for it (`00 R47a`). The counter
/// itself, `limb_core::fence::GeometryFence`, and the one place the comparison
/// is written, its `admit`, both stayed where they were: they are the plane's
/// live state, not vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GeometryGeneration(u32);

impl GeometryGeneration {
    /// What the counter reads when a session first reaches `Connected`.
    ///
    /// One rather than zero so that a defaulted, never initialised zero in
    /// somebody else's struct can never be mistaken for a live generation.
    pub const FIRST: GeometryGeneration = GeometryGeneration(1);

    /// The raw value, for a wire encoding or a log line.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The next generation. Called only by the fence that owns the counter.
    ///
    /// Saturating rather than wrapping. A session that has resized four
    /// billion times is not a real situation, and a wrap would silently start
    /// admitting stale fences again, which is worse than a counter that sticks
    /// at the top and refuses everything computed before it.
    pub const fn next(self) -> GeometryGeneration {
        GeometryGeneration(self.0.saturating_add(1))
    }
}

impl std::fmt::Display for GeometryGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
