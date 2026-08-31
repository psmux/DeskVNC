//! What changed, per reader, as a rectangle LIST.
//!
//! `00 R39b`, `14 §2.2` and `03 §4.2`. This is the cheapest rung of the
//! perception ladder and the best idea in `03`: the run loop already unions
//! damage across every rect of an update and ships it in the event, so
//! publishing it is free change detection with no mirror, no encode and no
//! capability to see content. "Wait until the screen stops changing" and "wait
//! until this region changes" are both built from it.
//!
//! **Nothing in this module sizes work from the union, and that is the whole
//! point.** `Rect::union` (`crates/remote-core/src/geometry.rs:31`) is a
//! bounding box, so a clock ticking in one corner and a dialog opening in the
//! other union to the entire screen. An agent that sized its work from the
//! `damage` field would re-read a whole 4K frame to find two moved pixels.
//! The union is correct for the renderer it was built for, which is why it is
//! in the event, and wrong for perception. `16 §4` caught this and `00 R39b`
//! rules on it: every perception consumer operates on the rect list.
//!
//! The union appears exactly once below, in [`DamageLog::record`], because
//! `Observation::Damage` carries it and limb-core's own doc comment already
//! labels it a union bounding box with the rect count beside it for exactly
//! this reason.
//!
//! **Deltas are per reader.** Two agents watching one session, or one agent
//! and the plane's own quiescence detector, must not consume each other's
//! changes. A single shared cursor would make the second reader see an empty
//! delta and conclude the screen had settled, which is the same class of
//! confidently wrong answer as a stale mirror.

use limb_core::observation::{Observation, Timestamp};
use remote_core::events::DecodedRect;
use remote_core::geometry::Rect;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::VecDeque;

/// How many rectangles the log keeps before the oldest are dropped.
///
/// A busy 1080p desktop is about 30 updates per second at 40 rects each, so
/// this is roughly three and a half seconds of the worst case. A reader that
/// falls further behind than that is told exactly how much it missed rather
/// than being handed a short list that looks complete (`00 R24`).
pub const DEFAULT_CAPACITY: usize = 4096;

/// `03 §4.5`'s margin around a change, so the change has context.
///
/// Sixty four pixels is a guess and `03 §8` carries it as spike S3-4, to be
/// settled by a task success measurement rather than by taste.
pub const DEFAULT_MARGIN: u16 = 64;

/// Above this fraction of the screen, one crop stops being cheaper than the
/// frame and the rung says so instead of silently becoming the most expensive
/// call in the system (`03 §4.5`, acceptance criterion A10).
pub const DEFAULT_CROP_COVERAGE_LIMIT: f32 = 0.25;

/// Who is reading. Minted by the plane, opaque here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReaderId(pub u64);

/// What one reader has missed since it last looked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DamageDelta {
    /// Every changed rectangle, in the order the server sent them. THE list.
    pub rects: Vec<Rect>,
    /// How many rectangles fell off the back of the log before this reader
    /// asked. Never silent, per `00 R24`: a reader that is told nothing was
    /// dropped and has actually missed half a screen will decide the screen is
    /// quiet.
    pub dropped: u64,
    /// How many coalesced updates the rectangles came from. The difference
    /// between one update of 200 rects and 200 updates of one rect is the
    /// difference between a repaint and an animation.
    pub updates: u64,
    /// The exclusive sequence number this delta reaches.
    ///
    /// It exists so a caller can plan a read from a delta and only mark the
    /// reader caught up once the read has actually succeeded. A read that
    /// refuses, because the region is priming or stale, must not eat the
    /// changes it refused to show: the agent would then be told nothing had
    /// changed on its next call, which is a stale answer arriving by a
    /// different route.
    pub through: u64,
}

impl DamageDelta {
    pub fn is_empty(&self) -> bool {
        self.rects.is_empty()
    }

    /// The bounding box of everything in this delta.
    ///
    /// Provided once, named so it cannot be reached for by accident, and used
    /// by nothing in this crate except the `Observation::Damage` that limb-core
    /// already defines as a union. If you are about to size a read from this,
    /// read `00 R39b` first.
    pub fn bounding_box(&self) -> Rect {
        self.rects
            .iter()
            .fold(Rect::new(0, 0, 0, 0), |acc, r| acc.union(r))
    }
}

/// The per session damage history, with one cursor per reader.
#[derive(Debug)]
pub struct DamageLog {
    entries: VecDeque<(u64, Rect)>,
    /// Sequence number of the next rectangle to be recorded.
    next_seq: u64,
    /// Sequence number of the oldest rectangle still held.
    first_seq: u64,
    /// Update boundaries, so a delta can say how many updates it spans without
    /// storing an update id on every rectangle.
    update_starts: VecDeque<u64>,
    readers: HashMap<ReaderId, u64>,
    capacity: usize,
}

impl Default for DamageLog {
    fn default() -> Self {
        DamageLog::new(DEFAULT_CAPACITY)
    }
}

impl DamageLog {
    pub fn new(capacity: usize) -> Self {
        DamageLog {
            entries: VecDeque::new(),
            next_seq: 0,
            first_seq: 0,
            update_starts: VecDeque::new(),
            readers: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Take one coalesced `SessionEvent::FramebufferUpdate`.
    ///
    /// Returns the unsolicited `Observation::Damage` a subscriber gets, which
    /// is `03 §4.2`'s rung 1 and costs nothing to produce because the run loop
    /// computed the geometry already. `rects` and `coverage` travel beside the
    /// union in that observation because "damage covers ninety percent of the
    /// screen" means something completely different at 2 rects than at 200.
    ///
    /// This is the ONLY producer that needs no mirror, and `03 §9 A5` makes
    /// that an acceptance criterion: a client holding only the weaker
    /// capability gets damage and gets nothing allocated on its behalf.
    pub fn record(
        &mut self,
        rects: &[DecodedRect],
        framebuffer: Rect,
        at: Timestamp,
    ) -> Observation {
        let mut union = Rect::new(0, 0, 0, 0);
        let mut count = 0u32;
        self.update_starts.push_back(self.next_seq);
        for decoded in rects {
            if decoded.rect.is_empty() {
                continue;
            }
            union = union.union(&decoded.rect);
            count = count.saturating_add(1);
            self.entries.push_back((self.next_seq, decoded.rect));
            self.next_seq += 1;
            if self.entries.len() > self.capacity {
                self.entries.pop_front();
                self.first_seq += 1;
            }
        }
        while self
            .update_starts
            .front()
            .is_some_and(|s| *s < self.first_seq)
        {
            self.update_starts.pop_front();
        }
        let screen = framebuffer.area();
        let coverage = if screen == 0 {
            0.0
        } else {
            union.area() as f32 / screen as f32
        };
        Observation::Damage {
            rect: union,
            rects: count,
            coverage,
            at,
        }
    }

    /// Register a reader from now on.
    ///
    /// A new reader starts at the head and not at the beginning, because
    /// history it never asked for is not a change it has missed. Calling this
    /// twice does not rewind an existing reader.
    pub fn subscribe(&mut self, reader: ReaderId) {
        self.readers.entry(reader).or_insert(self.next_seq);
    }

    pub fn forget(&mut self, reader: ReaderId) {
        self.readers.remove(&reader);
    }

    /// What this reader has missed, without consuming it.
    pub fn peek(&self, reader: ReaderId) -> DamageDelta {
        let cursor = self.readers.get(&reader).copied().unwrap_or(self.next_seq);
        self.delta_from(cursor)
    }

    /// What this reader has missed, and mark it caught up.
    ///
    /// Only this reader's cursor moves. That is the property two readers
    /// depend on and the one a single shared cursor would break.
    pub fn take(&mut self, reader: ReaderId) -> DamageDelta {
        let delta = self.peek(reader);
        self.advance(reader, delta.through);
        delta
    }

    /// Mark this reader caught up as far as a delta it has actually used.
    ///
    /// Moving backwards is ignored rather than honoured, because a reader that
    /// rewound would receive changes twice and conclude the screen was busier
    /// than it is.
    pub fn advance(&mut self, reader: ReaderId, through: u64) {
        let cursor = self.readers.entry(reader).or_insert(0);
        *cursor = (*cursor).max(through.min(self.next_seq));
    }

    fn delta_from(&self, cursor: u64) -> DamageDelta {
        let dropped = self.first_seq.saturating_sub(cursor);
        let from = cursor.max(self.first_seq);
        let rects: Vec<Rect> = self
            .entries
            .iter()
            .filter(|(seq, _)| *seq >= from)
            .map(|(_, r)| *r)
            .collect();
        let counted = self.update_starts.iter().filter(|s| **s >= from).count() as u64;
        // An update that began before the cursor can still have contributed
        // rectangles after it, so a delta holding rectangles spans at least one
        // update however the boundaries fell.
        let updates = if counted == 0 && !rects.is_empty() {
            1
        } else {
            counted
        };
        DamageDelta {
            rects,
            dropped,
            updates,
            through: self.next_seq,
        }
    }

    /// How many rectangles are held, for a stats line.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What rung 4 decided to look at.
///
/// `03 §4.5`: "something changed, show me what changed" is the call an agent
/// should make most often, and the surface should make it the shortest thing
/// to type.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "plan", rename_all = "kebab-case")]
pub enum ChangePlan {
    /// Nothing has changed since this reader last looked. An answer, not an
    /// error.
    Nothing,
    /// Read this rectangle at full resolution.
    Crop {
        /// What to read. `03 §4.5` reports this beside the damage because they
        /// answer different questions: the damage is what the server said
        /// changed, the crop is what the agent is going to look at.
        rect: Rect,
        /// The damage rectangles this crop covers.
        damage: Vec<Rect>,
        margin: u16,
        /// Changed rectangles this crop does NOT cover, because covering them
        /// would have cost more than the whole screen. Reported rather than
        /// dropped: an agent told it has seen everything, when two thirds of
        /// the changes were in the other corner, will stop looking.
        remaining: usize,
    },
    /// One crop cannot answer this cheaply, so say so and let the caller fall
    /// back to a downscaled frame.
    Degraded {
        reason: DegradeReason,
        coverage: f32,
    },
}

/// Why rung 4 could not stay on rung 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DegradeReason {
    /// The changed area is most of the screen, which is what a full screen
    /// repaint, a video or a scrolling terminal looks like. `03 §9 A10`
    /// requires this to be said out loud rather than answered with a full
    /// resolution crop of the whole desktop.
    DamageUnionTooLarge,
}

/// Choose the rectangle rung 4 should read.
///
/// The algorithm is the shortest one that cannot fall into the union trap:
/// seed the crop with the LARGEST changed rectangle expanded by the margin,
/// then absorb the other changed rectangles in size order for as long as the
/// result stays under the coverage limit. Two small changes in opposite
/// corners therefore produce a crop around one of them and a `remaining` count
/// of one, never a full screen read.
///
/// It is deliberately not a clustering algorithm. A real one would group by
/// proximity and return several crops, which is a better answer and a bigger
/// thing to get wrong; `03 §8` has no spike for it and this crate should not
/// invent one.
pub fn plan_change_crop(
    rects: &[Rect],
    framebuffer: Rect,
    margin: u16,
    coverage_limit: f32,
) -> ChangePlan {
    let screen = framebuffer.area();
    let mut live: Vec<Rect> = rects
        .iter()
        .map(|r| r.intersect(&framebuffer))
        .filter(|r| !r.is_empty())
        .collect();
    if live.is_empty() || screen == 0 {
        return ChangePlan::Nothing;
    }
    live.sort_by_key(|r| std::cmp::Reverse(r.area()));

    let limit = (screen as f32 * coverage_limit) as usize;
    let seed = expand(live[0], margin, framebuffer);
    if seed.area() > limit {
        return ChangePlan::Degraded {
            reason: DegradeReason::DamageUnionTooLarge,
            coverage: seed.area() as f32 / screen as f32,
        };
    }

    let mut crop = seed;
    let mut covered = vec![live[0]];
    let mut remaining = 0usize;
    for r in &live[1..] {
        let grown = crop.union(&expand(*r, margin, framebuffer));
        if grown.area() <= limit {
            crop = grown;
            covered.push(*r);
        } else {
            remaining += 1;
        }
    }
    ChangePlan::Crop {
        rect: crop,
        damage: covered,
        margin,
        remaining,
    }
}

/// Grow a rectangle by `margin` on every side, clamped to the framebuffer.
fn expand(r: Rect, margin: u16, fb: Rect) -> Rect {
    // In `u32` because a rect that ends at 65535 plus a margin is the one case
    // that would wrap, and a wrapped crop is a read of the opposite corner.
    let far = |start: u16, len: u16, limit_start: u16, limit_len: u16| -> (u16, u16) {
        let lo = start.saturating_sub(margin).max(limit_start);
        let hi = (u32::from(start) + u32::from(len) + u32::from(margin))
            .min(u32::from(limit_start) + u32::from(limit_len)) as u16;
        (lo, hi.saturating_sub(lo))
    };
    let (x, width) = far(r.x, r.width, fb.x, fb.width);
    let (y, height) = far(r.y, r.height, fb.y, fb.height);
    Rect::new(x, y, width, height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::events::RectPayload;

    fn rgba_rect(x: u16, y: u16, w: u16, h: u16) -> DecodedRect {
        DecodedRect {
            rect: Rect::new(x, y, w, h),
            payload: RectPayload::Rgba(vec![0; w as usize * h as usize * 4]),
        }
    }

    #[test]
    fn the_observation_carries_the_count_beside_the_union() {
        let mut log = DamageLog::default();
        let obs = log.record(
            &[rgba_rect(0, 0, 8, 8), rgba_rect(1912, 1072, 8, 8)],
            Rect::new(0, 0, 1920, 1080),
            Timestamp(1),
        );
        match obs {
            Observation::Damage { rect, rects, .. } => {
                assert_eq!(rects, 2);
                // The union really is the whole screen, which is why nothing
                // else in this module uses it.
                assert_eq!(rect, Rect::new(0, 0, 1920, 1080));
            }
            other => panic!("expected damage, got {other:?}"),
        }
    }

    #[test]
    fn a_reader_that_fell_behind_is_told_how_much_it_missed() {
        let mut log = DamageLog::new(2);
        log.subscribe(ReaderId(1));
        for i in 0..5 {
            log.record(
                &[rgba_rect(i, 0, 4, 4)],
                Rect::new(0, 0, 64, 64),
                Timestamp(i as u64),
            );
        }
        let delta = log.take(ReaderId(1));
        assert_eq!(delta.rects.len(), 2);
        assert_eq!(delta.dropped, 3);
    }

    #[test]
    fn a_new_reader_starts_at_the_head() {
        let mut log = DamageLog::default();
        log.record(
            &[rgba_rect(0, 0, 4, 4)],
            Rect::new(0, 0, 64, 64),
            Timestamp(1),
        );
        log.subscribe(ReaderId(7));
        assert!(log.take(ReaderId(7)).is_empty());
    }
}
