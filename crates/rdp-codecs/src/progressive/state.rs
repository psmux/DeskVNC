//! The per tile coefficient store, which is what makes progressive
//! progressive (MS-RDPEGFX 3.3.7, PRDRDP/04 §4.9.4).
//!
//! ## Lifetime
//!
//! One [`ProgressiveState`] per surface with an active progressive context.
//! It is allocated once, reused for every frame, and reset on `ResetGraphics`,
//! on a surface resize and on reconnect. Nothing in it is allocated per frame
//! and nothing in it is allocated per tile until that tile has actually
//! received a first pass, which is what makes a session that refines one
//! corner of a 4K desktop pay for one corner.
//!
//! ## What a tile holds, and what PRDRDP/04 §4.9.4 asks for that it does not
//!
//! §4.9.4 sketches three things per tile: the coefficients, the quality stage
//! per component, and a `BitSet4096` per component recording which
//! coefficients are already non zero, for a total of 25.5 KiB. The bitsets
//! are not here and it is deliberate, not an omission.
//!
//! The upgrade pass needs a three way answer per coefficient: still zero,
//! positive, or negative. A one bit set cannot carry it, so §4.9.4's
//! `BitSet4096` would need a companion sign bit anyway. But the stored
//! coefficient already **is** that answer. [`super::bands::dequantize`] is a
//! left shift, so it maps zero to zero and preserves sign, and
//! [`super::srl::upgrade_component`] only ever adds magnitude in the
//! direction a coefficient already points. So a coefficient is zero in the
//! store exactly when it is still insignificant, and its sign is its sign.
//! Deriving it costs a comparison that the loop is already doing and saves
//! 1.5 KiB per tile, which is 3 MiB on a 4K surface.
//!
//! What is here that §4.9.4 does not list is the per band bit position, three
//! sets of ten nibbles. An upgrade pass says which bit position it brings and
//! the difference against the one the tile holds is how many bits it carries,
//! so the tile has to remember it. It cannot be recomputed: the quantization
//! tables live in the region block and the next frame's are different ones.
//!
//! ```text
//! 3 * 4096 * 2 bytes of coefficients        24576
//! 3 * 10 bytes of bit positions                30
//! layout and bookkeeping                       ~8
//! ```
//!
//! So 24 KiB per live tile rather than 25.5, and the surface totals become
//! 12.0 MiB at 1080p, 21.6 MiB at 1440p and 47.8 MiB at 4K.

use crate::remotefx::quant::COEFS;
use crate::DecodeError;

use super::bands::Layout;

/// Components in a tile.
pub const COMPONENTS: usize = 3;

/// Coefficients a tile stores, across all three components.
pub const TILE_COEFS: usize = COMPONENTS * COEFS;

/// Bytes one live tile costs.
pub const TILE_BYTES: usize = TILE_COEFS * core::mem::size_of::<i16>();

/// The default ceiling on one surface's tile store.
///
/// PRDRDP/04 §4.9.4 sets `PROGRESSIVE_MAX_BYTES` at 128 MiB across all
/// contexts and drops the least recently used context past it. That eviction
/// is a `rdp-core` decision because only `rdp-core` sees more than one
/// surface; what belongs here is the per surface ceiling, and 128 MiB is high
/// enough that no single legal surface reaches it (a 4K surface is 47.8 MiB)
/// and low enough that a server claiming a 65535 by 65535 surface is refused
/// rather than allocating 262 GiB.
pub const DEFAULT_MAX_BYTES: usize = 128 << 20;

/// One tile's retained coefficients and the bit position they sit at.
pub struct TileState {
    /// Three components of 4096, boxed rather than inline so building one
    /// never puts 24 KiB on the stack.
    coef: Box<[i16]>,
    /// The per band bit position each component currently holds, in the
    /// nibble order of `RFX_COMPONENT_CODEC_QUANT`.
    bit_pos: [[u8; 10]; COMPONENTS],
    /// Which wavelet produced these coefficients. A context that changes the
    /// `RFX_DWT_REDUCE_EXTRAPOLATE` flag mid session changes the subband
    /// layout underneath the store, so a tile coded under the other layout is
    /// not refinable and says so.
    layout: Layout,
}

impl TileState {
    fn new(layout: Layout) -> Self {
        Self {
            coef: vec![0i16; TILE_COEFS].into_boxed_slice(),
            bit_pos: [[0u8; 10]; COMPONENTS],
            layout,
        }
    }

    /// The three component coefficient buffers.
    pub fn parts(&mut self) -> (&mut [i16], &mut [i16], &mut [i16]) {
        let (y, rest) = self.coef.split_at_mut(COEFS);
        let (cb, cr) = rest.split_at_mut(COEFS);
        (y, cb, cr)
    }

    /// One component's coefficients.
    pub fn component(&mut self, c: usize) -> &mut [i16] {
        &mut self.coef[c * COEFS..(c + 1) * COEFS]
    }

    /// The bit position component `c` currently holds.
    pub fn bit_pos(&self, c: usize) -> &[u8; 10] {
        &self.bit_pos[c]
    }

    /// Record the bit position component `c` now holds.
    pub fn set_bit_pos(&mut self, c: usize, pos: [u8; 10]) {
        self.bit_pos[c] = pos;
    }

    /// The layout these coefficients were coded under.
    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// Start this tile again under `layout`, forgetting every coefficient.
    /// This is what a `WBT_TILE_SIMPLE` or a `WBT_TILE_FIRST` without
    /// `RFX_TILE_DIFFERENCE` does.
    pub fn restart(&mut self, layout: Layout) {
        self.coef.fill(0);
        self.bit_pos = [[0u8; 10]; COMPONENTS];
        self.layout = layout;
    }
}

/// Every tile of one surface, plus the context state the stream negotiated.
///
/// This is the type a caller pools. It is the codec's whole memory budget and
/// [`ProgressiveState::bytes`] is what PRDRDP/04 §11.3's accounting reads.
pub struct ProgressiveState {
    cols: u16,
    rows: u16,
    tiles: Vec<Option<TileState>>,
    live: usize,
    budget: usize,
    layout: Layout,
    seen_sync: bool,
}

impl Default for ProgressiveState {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressiveState {
    /// An empty store at the default budget. Allocates nothing until a tile
    /// arrives.
    pub fn new() -> Self {
        Self::with_budget(DEFAULT_MAX_BYTES)
    }

    /// An empty store at a chosen ceiling, for a caller enforcing
    /// PRDRDP/04 §4.9.4's cross context total itself.
    pub fn with_budget(budget: usize) -> Self {
        Self {
            cols: 0,
            rows: 0,
            tiles: Vec::new(),
            live: 0,
            budget,
            // MS-RDPEGFX 2.2.4.2.1.4 makes the flag a property of
            // `RFX_PROGRESSIVE_CONTEXT`, and a stream that sends tiles before
            // a context block has not selected the extrapolated wavelet. The
            // plain one is therefore the default, which is also the reading
            // that makes an unadorned progressive tile a RemoteFX tile.
            layout: Layout::Plain,
            seen_sync: false,
        }
    }

    /// Give every byte back. The tiles reappear at low quality on the next
    /// frame, which is why an eviction is safe in the way an EGFX cache
    /// eviction is safe.
    pub fn reset(&mut self) {
        self.cols = 0;
        self.rows = 0;
        self.tiles = Vec::new();
        self.live = 0;
        self.layout = Layout::Plain;
        self.seen_sync = false;
    }

    /// Bytes currently held, for PRDRDP/04 §11.3's accounting.
    pub fn bytes(&self) -> usize {
        self.live * TILE_BYTES + self.tiles.capacity() * core::mem::size_of::<Option<TileState>>()
    }

    /// Live tiles, which is what the memory is.
    pub fn live_tiles(&self) -> usize {
        self.live
    }

    /// The wavelet the last `WBT_CONTEXT` selected.
    pub fn layout(&self) -> Layout {
        self.layout
    }

    pub(super) fn set_layout(&mut self, layout: Layout) {
        self.layout = layout;
    }

    pub(super) fn set_seen_sync(&mut self) {
        self.seen_sync = true;
    }

    /// Whether a `WBT_SYNC` has been seen on this surface.
    pub fn seen_sync(&self) -> bool {
        self.seen_sync
    }

    /// Size the grid for a destination, dropping every tile if the geometry
    /// moved.
    ///
    /// A resize is a repaint in EGFX, so losing the store there costs one
    /// low quality frame and nothing else. Keeping it would be worse: tile
    /// `(3, 0)` of a 256 wide surface is not tile `(3, 0)` of a 1024 wide one
    /// in any sense the encoder shares.
    pub(super) fn fit(&mut self, width: u16, height: u16) {
        let cols = (usize::from(width).div_ceil(64)) as u16;
        let rows = (usize::from(height).div_ceil(64)) as u16;
        if cols == self.cols && rows == self.rows {
            return;
        }
        self.cols = cols;
        self.rows = rows;
        self.live = 0;
        self.tiles = Vec::new();
        self.tiles
            .resize_with(usize::from(cols) * usize::from(rows), || None);
    }

    fn index(&self, x_idx: usize, y_idx: usize) -> Option<usize> {
        if x_idx >= usize::from(self.cols) || y_idx >= usize::from(self.rows) {
            return None;
        }
        Some(y_idx * usize::from(self.cols) + x_idx)
    }

    /// The tile at `(x_idx, y_idx)`, allocating it if this is its first pass.
    ///
    /// A tile index outside the grid is a [`DecodeError::Range`] rather than
    /// an allocation: the indices are two remote controlled `u16` fields and
    /// a tile that lands outside the destination is already clipped away
    /// before this is reached, so reaching here with a wild index means the
    /// caller's clip and this grid disagree.
    pub(super) fn entry(
        &mut self,
        x_idx: usize,
        y_idx: usize,
        layout: Layout,
    ) -> Result<&mut TileState, DecodeError> {
        let at = self.index(x_idx, y_idx).ok_or(DecodeError::Range {
            what: "RFX_PROGRESSIVE_TILE index",
            got: (x_idx.max(y_idx)) as u32,
        })?;
        if self.tiles[at].is_none() {
            if (self.live + 1) * TILE_BYTES > self.budget {
                return Err(DecodeError::Budget("progressive tile store"));
            }
            self.tiles[at] = Some(TileState::new(layout));
            self.live += 1;
        }
        Ok(self.tiles[at].as_mut().expect("just filled"))
    }

    /// The tile at `(x_idx, y_idx)` if it has already had a first pass.
    ///
    /// An upgrade pass that names a tile nothing was ever sent for is exactly
    /// the input a fuzzer finds, and it is a [`DecodeError::StateLost`]:
    /// `rdp-core` reads that variant as "repaint needed" rather than "fail the
    /// session", which is the right answer for a client that joined a stream
    /// midway or lost a frame.
    pub(super) fn existing(
        &mut self,
        x_idx: usize,
        y_idx: usize,
    ) -> Result<&mut TileState, DecodeError> {
        let at = self.index(x_idx, y_idx).ok_or(DecodeError::Range {
            what: "RFX_PROGRESSIVE_TILE index",
            got: (x_idx.max(y_idx)) as u32,
        })?;
        self.tiles[at].as_mut().ok_or(DecodeError::StateLost(
            "progressive upgrade before first pass",
        ))
    }
}

impl core::fmt::Debug for ProgressiveState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProgressiveState")
            .field("cols", &self.cols)
            .field("rows", &self.rows)
            .field("live", &self.live)
            .field("bytes", &self.bytes())
            .field("layout", &self.layout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arithmetic of the module comment, as a test, so a change to what a
    /// tile holds has to restate what a surface costs.
    #[test]
    fn a_tile_costs_twenty_four_kibibytes() {
        assert_eq!(TILE_BYTES, 24 * 1024);
        // 1080p is 30 by 17 tiles, 4K is 60 by 34.
        assert_eq!(30 * 17 * TILE_BYTES, 12_533_760);
        assert_eq!(60 * 34 * TILE_BYTES, 50_135_040);
    }

    #[test]
    fn a_store_allocates_only_the_tiles_that_arrived() {
        let mut s = ProgressiveState::new();
        assert_eq!(s.bytes(), 0);
        s.fit(1920, 1080);
        assert_eq!(s.live_tiles(), 0);
        s.entry(0, 0, Layout::Plain).unwrap();
        s.entry(29, 16, Layout::Plain).unwrap();
        assert_eq!(s.live_tiles(), 2);
        assert!(s.bytes() >= 2 * TILE_BYTES);
        // The same tile again is the same allocation.
        s.entry(0, 0, Layout::Plain).unwrap();
        assert_eq!(s.live_tiles(), 2);
        s.reset();
        assert_eq!(s.bytes(), 0);
    }

    #[test]
    fn a_resize_drops_the_store() {
        let mut s = ProgressiveState::new();
        s.fit(256, 256);
        s.entry(1, 1, Layout::Plain).unwrap();
        assert_eq!(s.live_tiles(), 1);
        s.fit(1024, 256);
        assert_eq!(s.live_tiles(), 0);
        assert!(s.existing(1, 1).is_err());
    }

    #[test]
    fn a_tile_index_outside_the_grid_is_a_range_error() {
        let mut s = ProgressiveState::new();
        s.fit(64, 64);
        assert_eq!(
            s.entry(1, 0, Layout::Plain).err(),
            Some(DecodeError::Range {
                what: "RFX_PROGRESSIVE_TILE index",
                got: 1
            })
        );
    }

    /// An upgrade for a tile that never had a first pass is the fuzzer's
    /// favourite input and it names the state rather than indexing.
    #[test]
    fn an_upgrade_without_a_first_pass_is_state_lost() {
        let mut s = ProgressiveState::new();
        s.fit(128, 64);
        assert_eq!(
            s.existing(1, 0).err(),
            Some(DecodeError::StateLost(
                "progressive upgrade before first pass"
            ))
        );
    }

    #[test]
    fn the_budget_refuses_rather_than_allocating() {
        let mut s = ProgressiveState::with_budget(TILE_BYTES);
        s.fit(256, 64);
        s.entry(0, 0, Layout::Plain).unwrap();
        assert_eq!(
            s.entry(1, 0, Layout::Plain).err(),
            Some(DecodeError::Budget("progressive tile store"))
        );
        assert_eq!(s.live_tiles(), 1);
    }

    /// Restarting a tile forgets its coefficients and its bit positions, which
    /// is what makes a `WBT_TILE_SIMPLE` after a series of upgrades the same
    /// picture as one sent on its own.
    #[test]
    fn restart_forgets_everything_about_a_tile() {
        let mut t = TileState::new(Layout::Plain);
        t.component(0)[7] = 99;
        t.set_bit_pos(0, [6; 10]);
        t.restart(Layout::Extrapolate);
        assert_eq!(t.component(0)[7], 0);
        assert_eq!(t.bit_pos(0), &[0u8; 10]);
        assert_eq!(t.layout(), Layout::Extrapolate);
    }
}
