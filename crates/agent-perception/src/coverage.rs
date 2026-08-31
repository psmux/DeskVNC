//! Which pixels of the mirror are real, which have never been written, and
//! which are stale because H.264 went past.
//!
//! **This module is the H.264 hazard made impossible to fall into, and it is
//! the reason to prefer this crate over a bare `Framebuffer`.**
//!
//! `00 R6` and `03 §3`. `Framebuffer::apply`'s H.264 arm is a documented no-op
//! (`crates/vnc-core/src/pixel/framebuffer.rs:90`, "the native framebuffer
//! keeps its previous contents for these rects"), and the client advertises
//! H.264 to every server except Apple Screen Sharing
//! (`crates/vnc-core/src/proto/handshake.rs:176`), with Medium, Auto and Low
//! all setting `allow_h264: true`. A mirror built on that arm holds **stale
//! pixels in exactly the region that is moving**, with no error anywhere. An
//! agent reading it sees a video that never started or a window that never
//! opened, and acts confidently on it. `03 §3.1` calls that worse than having
//! no screenshot, and it is right: a missing answer is retried and a wrong one
//! is believed.
//!
//! So the mirror carries a coverage grid beside its pixels and every read is
//! checked against it. `03 §3.5` states the rule this implements: **a mirror
//! never lies about coverage.** The grid is 16x16 tiles, which is the tile
//! size `crates/vnc-core/examples/fb_probe.rs:363` already compares frames at,
//! so a coverage report and a pixel diff are talking about the same squares.
//! At 4K that is 32,400 bytes beside 33 MB of pixels.
//!
//! Three states and the transitions between them are deliberately asymmetric:
//!
//! * a compositable rect marks a tile [`TileState::Written`] only when it
//!   covers the tile ENTIRELY, because half a fresh tile is not a fresh tile;
//! * an H.264 rect marks every tile it TOUCHES [`TileState::Stale`], because
//!   one stale pixel in a tile makes the tile a lie;
//! * a `CopyRect` whose source is not wholly written makes its destination
//!   stale, because scrolling a stale region drags the staleness with it and
//!   that is the case a per rect check misses.
//!
//! Conservative in both directions, and the direction it errs in is over
//! reporting unknown, which costs an agent a second call. The other direction
//! costs it a misclick nobody can reproduce.

use crate::error::TooManyStaleRegions;
use remote_core::geometry::Rect;
use serde::Serialize;

/// Tile edge, in framebuffer pixels.
///
/// Sixteen, matching `fb_probe.rs:363`'s comparison tiles rather than picking
/// a second number, so "the mirror says this region is stale" and "the pixel
/// diff says these tiles differ" name the same squares.
pub const TILE: u16 = 16;

/// How many stale regions a read will describe before it refuses instead.
///
/// A checkerboard of poisoned tiles merges into thousands of rectangles, and a
/// response carrying thousands of rectangles is not an answer, it is a way of
/// saying "the whole thing is suspect" that a model will skim past. Past this
/// count the read is refused, which is the other half of the option `00 R6`
/// gives: refuse, or annotate. It never degrades into a bounding box, because
/// a bounding box is the union trap `00 R39b` rules out.
pub const MAX_STALE_REGIONS: usize = 256;

/// What one tile of the mirror is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TileState {
    /// Allocated and never painted. Opaque black that means nothing.
    ///
    /// `03 §9 A3`: a mirror attached to a session that has been connected for
    /// ten minutes starts here, and a read one second later must not return
    /// the black.
    NeverWritten,
    /// Composited from a rect this crate can actually composite.
    Written,
    /// Something the mirror cannot composite passed over it, so whatever is
    /// there is left over from before. `00 R6`.
    Stale,
}

/// Why a region of a returned frame is not to be trusted.
///
/// Two reasons and they are not the same claim, which is the same distinction
/// `Availability` draws between `absent` and `unknown`. `NeverWritten`
/// resolves as soon as the server paints there and an agent may simply ask
/// again. `H264` will not resolve while the session keeps negotiating H.264,
/// and the repair is `00 R6`'s: turn it off, re-send SetEncodings, `Refresh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaleReason {
    /// Nothing has painted here since the mirror was allocated or resized.
    NeverWritten,
    /// An H.264 rectangle passed over it and the mirror cannot decode one.
    H264,
}

impl StaleReason {
    /// The identifier an agent matches on, beside the sentence it reads. The
    /// same shape as [`limb_core::observation::RefusalCode::as_str`], for the
    /// reason `06 §5.5` gives: a model that has to parse prose to find out
    /// what happened will parse it wrong on the day the prose is edited.
    pub const fn as_str(self) -> &'static str {
        match self {
            StaleReason::NeverWritten => "NEVER_WRITTEN",
            StaleReason::H264 => "H264",
        }
    }
}

/// One rectangle of a returned frame that is not what the remote screen shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StaleRegion {
    /// In framebuffer coordinates, tile aligned, so it is never smaller than
    /// the truth.
    pub rect: Rect,
    pub why: StaleReason,
}

/// Whether a returned frame is the whole truth about the region it covers.
///
/// `03 §4.3` puts this on every response and `03 §9 A8` makes a response
/// without it a bug rather than a compact form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "coverage", rename_all = "kebab-case")]
pub enum FrameCoverage {
    /// Every pixel in the region was composited from something the mirror
    /// understands.
    Complete,
    /// Some of it was not, and here is exactly which parts and why.
    Partial { stale_regions: Vec<StaleRegion> },
}

impl FrameCoverage {
    pub fn is_complete(&self) -> bool {
        matches!(self, FrameCoverage::Complete)
    }
}

/// How much of one region the mirror can vouch for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegionState {
    pub tiles: u32,
    pub never_written: u32,
    pub stale: u32,
}

impl RegionState {
    pub fn is_complete(&self) -> bool {
        self.never_written == 0 && self.stale == 0
    }
}

/// The per tile record beside the mirror's pixels.
#[derive(Debug, Clone)]
pub struct Coverage {
    width: u16,
    height: u16,
    cols: u16,
    tiles: Vec<TileState>,
}

/// Tiles spanned by `[start, start + len)` as a half open tile index range.
fn touched(start: u16, len: u16, limit: u16) -> (u16, u16) {
    if len == 0 || start >= limit {
        return (0, 0);
    }
    let end = start.saturating_add(len).min(limit);
    (start / TILE, end.div_ceil(TILE))
}

impl Coverage {
    pub fn new(width: u16, height: u16) -> Self {
        let cols = width.div_ceil(TILE);
        let rows = height.div_ceil(TILE);
        Coverage {
            width,
            height,
            cols,
            tiles: vec![TileState::NeverWritten; cols as usize * rows as usize],
        }
    }

    /// Forget everything, because the geometry moved.
    ///
    /// A resize does not carry coverage across even though
    /// `Framebuffer::resize` carries the overlapping pixels across. The pixels
    /// are worth keeping so the picture does not flash; the CLAIM that they
    /// are current is not, because a desktop that resized is repainting and
    /// the agent's coordinates are void anyway (`00 R10`). Keeping a tile
    /// marked written across a resize would be the same class of lie as
    /// serving an H.264 region.
    pub fn reset(&mut self, width: u16, height: u16) {
        *self = Coverage::new(width, height);
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    fn tile_bounds(&self, col: u16, row: u16) -> Rect {
        let x = col * TILE;
        let y = row * TILE;
        // The last column and row are short where the framebuffer is not a
        // multiple of the tile size, and a rect that reaches the framebuffer
        // edge does cover them completely.
        let w = (self.width - x).min(TILE);
        let h = (self.height - y).min(TILE);
        Rect::new(x, y, w, h)
    }

    fn idx(&self, col: u16, row: u16) -> usize {
        row as usize * self.cols as usize + col as usize
    }

    /// Mark every tile this rect covers ENTIRELY as composited.
    ///
    /// Partly covered tiles keep whatever they had: their uncovered part still
    /// holds whatever it held, so the tile is no better than it was, and the
    /// fresh half does not redeem the stale one.
    pub fn mark_written(&mut self, rect: Rect) {
        self.mark(rect, TileState::Written);
    }

    /// Mark every tile this rect TOUCHES as stale, however little of it.
    pub fn mark_stale(&mut self, rect: Rect) {
        self.mark(rect, TileState::Stale);
    }

    fn mark(&mut self, rect: Rect, state: TileState) {
        let (c0, c1) = touched(rect.x, rect.width, self.width);
        let (r0, r1) = touched(rect.y, rect.height, self.height);
        for row in r0..r1 {
            for col in c0..c1 {
                if state == TileState::Written {
                    let tile = self.tile_bounds(col, row);
                    if rect.intersect(&tile) != tile {
                        continue;
                    }
                }
                let i = self.idx(col, row);
                self.tiles[i] = state;
            }
        }
    }

    /// A `CopyRect` moved content from `src` to `dst`.
    ///
    /// The staleness travels with the pixels. A terminal scrolling a region
    /// that H.264 last painted would otherwise hand back tiles marked fresh
    /// that hold pixels the mirror never decoded, and the scroll is the exact
    /// case where a per rect check looks clean: the rect that arrived was a
    /// `CopyRect`, which this crate composites perfectly, and its source was
    /// the lie.
    pub fn mark_copied(&mut self, src: Rect, dst: Rect) {
        if self.region_state(src).is_complete() {
            self.mark_written(dst);
        } else {
            self.mark_stale(dst);
        }
    }

    /// Has anything ever painted every tile?
    ///
    /// `03 §2.7` item 3 says to reuse `REFRESH_ANSWER_COVERAGE` (0.9,
    /// `run_loop.rs:141`) as the priming threshold rather than inventing a
    /// second one. This crate needs no threshold at all, which is better than
    /// reusing one: a read is answerable when the tiles it actually touches
    /// are written, so a region read can succeed on a mirror that is only
    /// nine tenths primed, and a full frame read on the same mirror is
    /// correctly refused. A single global fraction cannot say both.
    pub fn is_primed(&self) -> bool {
        !self.tiles.contains(&TileState::NeverWritten)
    }

    /// How much of one region the mirror can vouch for.
    pub fn region_state(&self, region: Rect) -> RegionState {
        let (c0, c1) = touched(region.x, region.width, self.width);
        let (r0, r1) = touched(region.y, region.height, self.height);
        let mut out = RegionState::default();
        for row in r0..r1 {
            for col in c0..c1 {
                out.tiles += 1;
                match self.tiles[self.idx(col, row)] {
                    TileState::NeverWritten => out.never_written += 1,
                    TileState::Stale => out.stale += 1,
                    TileState::Written => {}
                }
            }
        }
        out
    }

    /// The untrustworthy parts of one region, as a rectangle LIST.
    ///
    /// A list and never a bounding box. `00 R39b` rules the union out for
    /// perception and the reason applies with double force here: two stale
    /// tiles in opposite corners would union to the whole screen and an agent
    /// would throw away a frame that is ninety nine percent good.
    ///
    /// Runs of tiles are merged along a row and then merged with the row above
    /// where the extents and the reason match, which turns a stale video
    /// window into one rectangle rather than a few hundred.
    pub fn stale_regions(&self, region: Rect) -> Result<Vec<StaleRegion>, TooManyStaleRegions> {
        let (c0, c1) = touched(region.x, region.width, self.width);
        let (r0, r1) = touched(region.y, region.height, self.height);
        let mut out: Vec<StaleRegion> = Vec::new();
        for row in r0..r1 {
            let mut col = c0;
            while col < c1 {
                let why = match self.tiles[self.idx(col, row)] {
                    TileState::Written => {
                        col += 1;
                        continue;
                    }
                    TileState::NeverWritten => StaleReason::NeverWritten,
                    TileState::Stale => StaleReason::H264,
                };
                let start = col;
                while col < c1 && self.tiles[self.idx(col, row)] == self.tiles[self.idx(start, row)]
                {
                    col += 1;
                }
                let first = self.tile_bounds(start, row);
                let last = self.tile_bounds(col - 1, row);
                let rect = Rect::new(
                    first.x,
                    first.y,
                    last.x + last.width - first.x,
                    first.height,
                );
                // Merge upwards where the run above has the same extent and
                // the same reason, so a rectangular stale area is one rect.
                match out.last_mut() {
                    Some(prev)
                        if prev.why == why
                            && prev.rect.x == rect.x
                            && prev.rect.width == rect.width
                            && prev.rect.y + prev.rect.height == rect.y =>
                    {
                        prev.rect.height += rect.height;
                    }
                    _ => {
                        if out.len() == MAX_STALE_REGIONS {
                            return Err(TooManyStaleRegions {
                                limit: MAX_STALE_REGIONS,
                            });
                        }
                        out.push(StaleRegion { rect, why });
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_partly_covered_tile_is_not_written() {
        let mut c = Coverage::new(64, 64);
        c.mark_written(Rect::new(0, 0, 8, 8));
        assert_eq!(c.region_state(Rect::new(0, 0, 16, 16)).never_written, 1);
        c.mark_written(Rect::new(0, 0, 16, 16));
        assert!(c.region_state(Rect::new(0, 0, 16, 16)).is_complete());
    }

    #[test]
    fn the_short_last_tile_is_covered_by_a_rect_reaching_the_edge() {
        // 40 wide is two full tiles and one eight pixel stub.
        let mut c = Coverage::new(40, 16);
        c.mark_written(Rect::new(0, 0, 40, 16));
        assert!(c.is_primed());
    }

    #[test]
    fn stale_runs_merge_into_one_rectangle() {
        let mut c = Coverage::new(64, 64);
        c.mark_written(Rect::new(0, 0, 64, 64));
        c.mark_stale(Rect::new(16, 16, 32, 32));
        let stale = c.stale_regions(Rect::new(0, 0, 64, 64)).unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].rect, Rect::new(16, 16, 32, 32));
        assert_eq!(stale[0].why, StaleReason::H264);
    }

    #[test]
    fn a_copy_from_a_stale_source_stales_the_destination() {
        let mut c = Coverage::new(64, 64);
        c.mark_written(Rect::new(0, 0, 64, 64));
        c.mark_stale(Rect::new(0, 0, 16, 16));
        c.mark_copied(Rect::new(0, 0, 16, 16), Rect::new(32, 32, 16, 16));
        assert_eq!(c.region_state(Rect::new(32, 32, 16, 16)).stale, 1);
    }
}
