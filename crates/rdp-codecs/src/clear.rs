//! ClearCodec (MS-RDPEGFX 2.2.4.1 for the bitstream, 3.3.8.1.3 for the decode
//! rules).
//!
//! `RDPGFX_CODECID_CLEARCODEC` (0x0008). Lossless and non wavelet, built for
//! the mixed content RemoteFX handles badly: window chrome, text, flat fills
//! with a photograph in the middle. One bitmap decomposes into three layers
//! composited in a fixed order, with a glyph cache in front of the whole
//! thing.
//!
//! ## Compositing order
//!
//! Residual first, because it fills the whole bitmap. Then bands, which
//! overwrite. Then the subcodec rectangles, which overwrite again
//! (MS-RDPEGFX 3.3.8.1.3). A layer that is absent contributes nothing and
//! does not clear what came before, which is why a zero `residualByteCount`
//! is ordinary rather than an error.
//!
//! ## Three caches, and why a miss is not fatal
//!
//! Every cache in this codec is exact: the server tracks what it believes we
//! hold and sends an index rather than the pixels. If we ever miss a bitmap,
//! every later hit reads the wrong entry. So [`ClearDecoder`] keeps an
//! expected sequence number and a mismatch is
//! [`DecodeError::StateLost`], which `rdp-core` handles by clearing all
//! ClearCodec state, logging once, and carrying on. Carrying on is right
//! rather than failing the session, because the server repaints the affected
//! region on its next full frame and a stale glyph shows for at most one
//! frame (PRDRDP/04 §4.8.1).
//!
//! A v1 stream starts its sequence at zero on the first bitmap of a channel
//! and a v2 stream may start anywhere, because the sequence survives a
//! `RESET_GRAPHICS`. So any value is accepted as the first sequence number on
//! a channel and the increment is enforced only from the second bitmap
//! onward. That is one line and it is the difference between working against
//! Windows Server 2012 R2 and not.
//!
//! ## Two fields this lane could not pin, stated plainly
//!
//! PRDRDP/04 §4.8 names exactly two fields that have to be read out of the
//! specification rather than assumed, and MS-RDPEGFX §4's ClearCodec example
//! was not available to this lane. Both are implemented from reasoning that
//! is written out at the point of use, both are isolated in one function so a
//! vector corrects them in one place, and neither can overrun a buffer
//! whichever way it turns out:
//!
//! * The VBar header split, in [`vbar_header`]. PRDRDP/04 §4.8.3's own table
//!   contradicts its own cache sizes, and the cache sizes win. See that
//!   function.
//! * The RLEX segment byte, in [`rlex_code`]. See that function.

use remote_pixel::{put, DstView, OutFormat};

use crate::nscodec::{self, NscScratch};
use crate::{DecodeError, Reader};

// Stream header flags (MS-RDPEGFX 2.2.4.1).
const FLAG_GLYPH_INDEX: u8 = 0x01;
const FLAG_GLYPH_HIT: u8 = 0x02;
const FLAG_CACHE_RESET: u8 = 0x04;

/// Glyph cache entries (PRDRDP/04 §4.8.1).
const GLYPH_ENTRIES: usize = 4000;
/// A bitmap is eligible for the glyph cache only at or under this many pixels.
const GLYPH_MAX_PIXELS: usize = 1024;
/// Bytes per glyph slot: [`GLYPH_MAX_PIXELS`] as B, G, R triples.
///
/// Three bytes per pixel rather than the four PRDRDP/04 §4.8.1 budgets,
/// because a cached glyph has to be independent of the destination channel
/// order: the same decoder instance can be asked for RGBA one call and BGRA
/// the next. Storing the wire's own B, G, R makes the entry mean one thing,
/// and it takes the worst case from 16 MB to 12 MB.
const GLYPH_STRIDE: usize = GLYPH_MAX_PIXELS * 3;

/// VBar cache entries (MS-RDPEGFX 2.2.4.1.2.2).
const VBAR_ENTRIES: usize = 32768;
/// ShortVBar cache entries.
const SHORT_VBAR_ENTRIES: usize = 16384;
/// The largest short VBar, bounded by the six bit pixel count field.
const SHORT_VBAR_MAX: usize = 63;
/// Bytes per short VBar slot.
const SHORT_VBAR_STRIDE: usize = SHORT_VBAR_MAX * 3;
/// The VBar arena, 32 MB (PRDRDP/04 §4.8.3).
const VBAR_ARENA: usize = 32 * 1024 * 1024;
/// The tallest VBar that is worth caching.
const VBAR_MAX_PIXELS: usize = 4096;

/// Subcodec ids (MS-RDPEGFX 2.2.4.1.3).
const SUBCODEC_RAW: u8 = 0;
const SUBCODEC_NSCODEC: u8 = 1;
const SUBCODEC_RLEX: u8 = 2;

/// The largest palette an RLEX rectangle may carry
/// (MS-RDPEGFX 2.2.4.1.3.1.2).
const RLEX_MAX_PALETTE: usize = 127;

/// What a VBar header selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VBar {
    /// Index into the VBar cache.
    CacheHit(usize),
    /// Index into the ShortVBar cache; the count of leading background rows
    /// follows as one byte.
    ShortHit(usize),
    /// `count` explicit pixels follow, preceded by `y_on` rows of background.
    ShortMiss { y_on: usize, count: usize },
}

/// Split a `vBarHeader` (MS-RDPEGFX 2.2.4.1.2.2).
///
/// **This split is not transcribed from the specification.** MS-RDPEGFX §4's
/// ClearCodec example was not available to this lane, so it is derived, and
/// the derivation is here so a reviewer can check it rather than trust it.
///
/// PRDRDP/04 §4.8.3's table says the top two bits select the form, with 00
/// meaning `VBAR_CACHE_HIT` over a 14 bit index. That cannot be right,
/// because the same section sets the VBar cache at **32768 entries**, and 14
/// bits addresses 16384 of them. The cache sizes are stated twice in that
/// section, with a memory budget computed from them, so they are the half to
/// keep. That forces:
///
/// * `VBAR_CACHE_HIT` is one selector bit set, leaving **15** bits of index,
///   which addresses exactly 32768 entries.
/// * `SHORT_VBAR_CACHE_HIT` is `01`, leaving **14** bits of index, which
///   addresses exactly 16384 entries, the ShortVBar cache size.
/// * `SHORT_VBAR_CACHE_MISS` is `00`, and the remaining 14 bits carry the two
///   fields. §4.8.3 states independently that the pixel count is bounded by a
///   **six bit** field, so it is six bits and the other is eight, and the
///   eight bit one is the count of leading background rows because a band can
///   be taller than 63.
///
/// Every one of those follows from a number §4.8.3 states for another reason,
/// which is why this is written out rather than guessed. If MS-RDPEGFX §4
/// disagrees, this function is the only thing that changes.
fn vbar_header(h: u16) -> VBar {
    if h & 0x8000 != 0 {
        VBar::CacheHit(usize::from(h & 0x7FFF))
    } else if h & 0x4000 != 0 {
        VBar::ShortHit(usize::from(h & 0x3FFF))
    } else {
        VBar::ShortMiss {
            y_on: usize::from(h & 0x00FF),
            count: usize::from((h >> 8) & 0x3F),
        }
    }
}

/// Split an RLEX segment's first byte into a palette stop index and a suite
/// depth (MS-RDPEGFX 2.2.4.1.3.1.2).
///
/// **Not transcribed from the specification either**, and less well pinned
/// than [`vbar_header`]. What is known: `paletteCount` is at most 127, so the
/// stop index needs seven bits, which rules out the obvious four and four
/// split PRDRDP/04 §4.8.4 also rules out. Seven bits of index leaves one bit
/// of suite depth in a single byte, so that is what this implements.
///
/// A suite depth of one paints a single ramp pixel at `palette[stop - 1]`
/// after the run, which is a plausible thing for a codec aimed at
/// antialiased text edges to code and an implausibly small one for a field
/// the specification bothered to name. So this is the reading most likely to
/// be corrected by the MS-RDPEGFX §4 vector, and it is reported as such.
/// Whichever way it turns out, the caller range checks both halves against
/// `paletteCount` before using either, so a wrong split is a wrong picture
/// and never a wrong memory access.
fn rlex_code(b: u8) -> (usize, usize) {
    (usize::from(b & 0x7F), usize::from(b >> 7))
}

/// The escalating run length of MS-RDPEGFX 2.2.4.1.1 and 2.2.4.1.3.1.2.
///
/// One byte, then two more when the first is `0xFF`, then four more when
/// those are `0xFFFF`. The effective length is the largest factor present,
/// not the sum, which is the reading that makes the three forms a widening
/// rather than an addition.
fn run_length(r: &mut Reader<'_>) -> Result<usize, DecodeError> {
    let f1 = r.u8()?;
    if f1 != 0xFF {
        return Ok(usize::from(f1));
    }
    let f2 = r.u16_le()?;
    if f2 != 0xFFFF {
        return Ok(usize::from(f2));
    }
    Ok(r.u32_le()? as usize)
}

/// The glyph cache: whole small bitmaps, indexed by the server
/// (MS-RDPEGFX 2.2.4.1).
struct GlyphCache {
    arena: Vec<u8>,
    /// Width and height per slot; a zero width means the slot is empty.
    dims: Vec<(u16, u16)>,
}

impl GlyphCache {
    fn new() -> Self {
        Self {
            arena: Vec::new(),
            dims: vec![(0, 0); GLYPH_ENTRIES],
        }
    }

    fn reset(&mut self) {
        self.arena = Vec::new();
        self.dims.iter_mut().for_each(|d| *d = (0, 0));
    }

    fn bytes(&self) -> usize {
        self.arena.capacity() + self.dims.capacity() * 4
    }

    fn get(&self, index: usize, w: u16, h: u16) -> Option<&[u8]> {
        let (gw, gh) = *self.dims.get(index)?;
        if gw != w || gh != h || gw == 0 {
            return None;
        }
        let n = usize::from(gw) * usize::from(gh) * 3;
        self.arena
            .get(index * GLYPH_STRIDE..index * GLYPH_STRIDE + n)
    }

    /// Reserve a slot and hand back its pixel bytes to be filled.
    fn slot(&mut self, index: usize, w: u16, h: u16) -> Option<&mut [u8]> {
        if index >= GLYPH_ENTRIES {
            return None;
        }
        let n = usize::from(w) * usize::from(h);
        if n == 0 || n > GLYPH_MAX_PIXELS {
            return None;
        }
        let end = (index + 1) * GLYPH_STRIDE;
        if self.arena.len() < end {
            self.arena.resize(end, 0);
        }
        self.dims[index] = (w, h);
        Some(&mut self.arena[index * GLYPH_STRIDE..index * GLYPH_STRIDE + n * 3])
    }
}

/// One VBar cache entry: where its pixels were written, in the arena's global
/// byte count, and how many bytes they are.
#[derive(Clone, Copy, Default)]
struct VBarEntry {
    at: u64,
    len: u32,
}

/// The VBar cache: variable length columns over a fixed arena
/// (PRDRDP/04 §4.8.3).
///
/// The protocol's own structure is circular over 32768 **entries**, and the
/// arena is circular over 32 MB of **bytes**. Those are two different rings,
/// and the interesting question is what happens when the byte ring laps an
/// entry that the entry ring still considers live.
///
/// It is answered exactly and without an eviction list. Every entry records
/// the arena's total bytes written at the moment it was stored, so an entry
/// is still intact precisely when fewer than `arena - len` bytes have been
/// written since. That is one subtraction on lookup and it costs no
/// bookkeeping on insert. In practice it never fires: 32768 entries of a
/// typical column are a few megabytes, so the entry ring laps long before the
/// byte ring does, and the check is there for the case where it does not.
struct VBarCache {
    arena: Vec<u8>,
    written: u64,
    entries: Vec<VBarEntry>,
    cursor: usize,
}

impl VBarCache {
    fn new() -> Self {
        Self {
            arena: Vec::new(),
            written: 0,
            entries: vec![VBarEntry::default(); VBAR_ENTRIES],
            cursor: 0,
        }
    }

    fn reset(&mut self) {
        self.arena = Vec::new();
        self.written = 0;
        self.entries
            .iter_mut()
            .for_each(|e| *e = VBarEntry::default());
        self.cursor = 0;
    }

    fn bytes(&self) -> usize {
        self.arena.capacity() + self.entries.capacity() * core::mem::size_of::<VBarEntry>()
    }

    fn get(&self, index: usize) -> Option<&[u8]> {
        let e = self.entries.get(index)?;
        let len = e.len as usize;
        if len == 0 {
            return None;
        }
        // Overwritten if the arena has lapped past it.
        if self.written - e.at > (VBAR_ARENA - len) as u64 {
            return None;
        }
        let pos = (e.at % VBAR_ARENA as u64) as usize;
        self.arena.get(pos..pos + len)
    }

    /// Store one column's B, G, R bytes at the next cursor position.
    ///
    /// A column too tall to be worth caching is dropped rather than stored,
    /// and the entry cursor still advances, because the server advanced its
    /// own. Getting that wrong desynchronises every later index.
    fn insert(&mut self, px: &[u8]) {
        let slot = self.cursor;
        self.cursor = (self.cursor + 1) % VBAR_ENTRIES;
        let n = px.len();
        if n == 0 || n > VBAR_MAX_PIXELS * 3 {
            self.entries[slot] = VBarEntry::default();
            return;
        }
        let mut pos = (self.written % VBAR_ARENA as u64) as usize;
        if pos + n > VBAR_ARENA {
            // Pad to the wrap so the arithmetic in `get` stays exact.
            self.written += (VBAR_ARENA - pos) as u64;
            pos = 0;
        }
        if self.arena.len() < pos + n {
            self.arena.resize(pos + n, 0);
        }
        self.arena[pos..pos + n].copy_from_slice(px);
        self.entries[slot] = VBarEntry {
            at: self.written,
            len: n as u32,
        };
        self.written += n as u64;
    }
}

/// The ShortVBar cache: at most 63 pixels each, so a flat arena with a fixed
/// stride and no eviction logic at all (PRDRDP/04 §4.8.3).
struct ShortVBarCache {
    arena: Vec<u8>,
    counts: Vec<u8>,
    cursor: usize,
}

impl ShortVBarCache {
    fn new() -> Self {
        Self {
            arena: Vec::new(),
            counts: vec![0; SHORT_VBAR_ENTRIES],
            cursor: 0,
        }
    }

    fn reset(&mut self) {
        self.arena = Vec::new();
        self.counts.iter_mut().for_each(|c| *c = 0);
        self.cursor = 0;
    }

    fn bytes(&self) -> usize {
        self.arena.capacity() + self.counts.capacity()
    }

    fn get(&self, index: usize) -> Option<&[u8]> {
        let n = usize::from(*self.counts.get(index)?);
        if n == 0 {
            return None;
        }
        self.arena
            .get(index * SHORT_VBAR_STRIDE..index * SHORT_VBAR_STRIDE + n * 3)
    }

    fn insert(&mut self, px: &[u8]) {
        let slot = self.cursor;
        self.cursor = (self.cursor + 1) % SHORT_VBAR_ENTRIES;
        let n = px.len() / 3;
        if n == 0 || n > SHORT_VBAR_MAX {
            self.counts[slot] = 0;
            return;
        }
        let end = (slot + 1) * SHORT_VBAR_STRIDE;
        if self.arena.len() < end {
            self.arena.resize(end, 0);
        }
        self.arena[slot * SHORT_VBAR_STRIDE..slot * SHORT_VBAR_STRIDE + n * 3].copy_from_slice(px);
        self.counts[slot] = n as u8;
    }
}

/// The ClearCodec decoder and its persistent state.
///
/// One instance per EGFX channel, held by the caller and reset on
/// `ResetGraphics` and on reconnect (PRDRDP/04 §3.9). A decoder recreated per
/// PDU would silently lose every glyph cache hit, and the picture would be
/// wrong rather than merely slow.
pub struct ClearDecoder {
    glyphs: GlyphCache,
    vbar: VBarCache,
    short_vbar: ShortVBarCache,
    nsc: NscScratch,
    /// Working column, reused across bands.
    column: Vec<u8>,
    expect_seq: Option<u8>,
}

impl Default for ClearDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClearDecoder {
    /// A decoder with empty caches. Nothing is allocated until a stream needs
    /// it, so an idle session holds only the index tables.
    pub fn new() -> Self {
        Self {
            glyphs: GlyphCache::new(),
            vbar: VBarCache::new(),
            short_vbar: ShortVBarCache::new(),
            nsc: NscScratch::new(),
            column: Vec::new(),
            expect_seq: None,
        }
    }

    /// Drop every cache and forget the sequence number
    /// (PRDRDP/04 §4.1 rule three).
    pub fn reset(&mut self) {
        self.glyphs.reset();
        self.vbar.reset();
        self.short_vbar.reset();
        self.nsc.reset();
        self.column = Vec::new();
        self.expect_seq = None;
    }

    /// Bytes held by the three caches, for the RSS accounting in
    /// PRDRDP/04 §11.3.
    pub fn bytes(&self) -> usize {
        self.glyphs.bytes()
            + self.vbar.bytes()
            + self.short_vbar.bytes()
            + self.nsc.bytes()
            + self.column.capacity()
    }

    /// Decode one `CLEARCODEC_BITMAP_STREAM` into the caller's destination
    /// (MS-RDPEGFX 2.2.4.1, 3.3.8.1.3).
    ///
    /// The geometry and the row order live in `dst`. ClearCodec is always top
    /// down; it is an EGFX codec and there is no legacy path into it.
    ///
    /// [`DecodeError::StateLost`] means the caches are out of step with the
    /// server and the caller should clear this decoder and ask for a repaint.
    /// Every other error is a malformed stream.
    pub fn decode(&mut self, src: &[u8], dst: &mut DstView<'_>) -> Result<(), DecodeError> {
        match dst.format() {
            OutFormat::Rgba => self.decode_inner::<false>(src, dst),
            OutFormat::Bgra => self.decode_inner::<true>(src, dst),
        }
    }

    fn decode_inner<const BGRA: bool>(
        &mut self,
        src: &[u8],
        dst: &mut DstView<'_>,
    ) -> Result<(), DecodeError> {
        let mut r = Reader::new(src, "clearcodec bitmap");
        let flags = r.u8()?;
        let seq = r.u8()?;
        let glyph_index = if flags & FLAG_GLYPH_INDEX != 0 {
            Some(usize::from(r.u16_le()?))
        } else {
            None
        };

        if flags & FLAG_CACHE_RESET != 0 {
            self.glyphs.reset();
            self.vbar.reset();
            self.short_vbar.reset();
        }

        // Any value is accepted as the first sequence number on a channel;
        // the increment is enforced from the second bitmap onward.
        let expected = self.expect_seq.replace(seq.wrapping_add(1));
        if let Some(want) = expected {
            if want != seq {
                self.glyphs.reset();
                self.vbar.reset();
                self.short_vbar.reset();
                return Err(DecodeError::StateLost("clearcodec sequence number"));
            }
        }

        let (w, h) = (dst.width(), dst.height());
        if flags & FLAG_GLYPH_HIT != 0 {
            let Some(index) = glyph_index else {
                return Err(DecodeError::Range {
                    what: "CLEARCODEC_FLAG_GLYPH_HIT without GLYPH_INDEX",
                    got: u32::from(flags),
                });
            };
            let Some(px) = self.glyphs.get(index, w, h) else {
                return Err(DecodeError::StateLost("clearcodec glyph cache miss"));
            };
            for y in 0..usize::from(h) {
                let row = &px[y * usize::from(w) * 3..][..usize::from(w) * 3];
                for (bgr, o) in row.chunks_exact(3).zip(dst.row(y).chunks_exact_mut(4)) {
                    put::<BGRA>(o, bgr[2], bgr[1], bgr[0], 0xFF);
                }
            }
            return Ok(());
        }

        if usize::from(w) * usize::from(h) == 0 {
            return Ok(());
        }

        let residual_bytes = r.u32_le()? as usize;
        let bands_bytes = r.u32_le()? as usize;
        let subcodec_bytes = r.u32_le()? as usize;
        let residual = r.take(residual_bytes)?;
        let bands = r.take(bands_bytes)?;
        let subcodec = r.take(subcodec_bytes)?;

        if !residual.is_empty() {
            self.residual::<BGRA>(residual, dst)?;
        }
        if !bands.is_empty() {
            self.bands::<BGRA>(bands, dst)?;
        }
        if !subcodec.is_empty() {
            self.subcodec::<BGRA>(subcodec, dst)?;
        }

        // Cache the finished bitmap when the server asked for it. The pixels
        // are read back out of the destination rather than kept in a second
        // buffer, which keeps the decode at one write per pixel.
        if let Some(index) = glyph_index {
            let (gw, gh) = (w, h);
            if let Some(slot) = self.glyphs.slot(index, gw, gh) {
                for y in 0..usize::from(gh) {
                    let out = &mut slot[y * usize::from(gw) * 3..][..usize::from(gw) * 3];
                    let row = dst.row(y);
                    for (o, px) in out.chunks_exact_mut(3).zip(row.chunks_exact(4)) {
                        // Store the wire's own B, G, R whatever the
                        // destination order is.
                        let (r, g, b) = if BGRA {
                            (px[2], px[1], px[0])
                        } else {
                            (px[0], px[1], px[2])
                        };
                        o[0] = b;
                        o[1] = g;
                        o[2] = r;
                    }
                }
            }
        }
        Ok(())
    }

    /// The residual layer: run length encoded raw pixels filling the whole
    /// bitmap in raster order (MS-RDPEGFX 2.2.4.1.1).
    fn residual<const BGRA: bool>(
        &mut self,
        src: &[u8],
        dst: &mut DstView<'_>,
    ) -> Result<(), DecodeError> {
        let w = usize::from(dst.width());
        let h = usize::from(dst.height());
        let total = w * h;
        let mut r = Reader::new(src, "clearcodec residual");
        let mut at = 0usize;
        while at < total {
            let b = r.u8()?;
            let g = r.u8()?;
            let red = r.u8()?;
            let run = run_length(&mut r)?;
            // A zero length run would leave `at` where it was, and the loop
            // would consume four bytes per iteration forever on a long
            // enough payload. Refusing it is cheaper than reasoning about it.
            if run == 0 {
                return Err(DecodeError::Range {
                    what: "clearcodec residual run length",
                    got: 0,
                });
            }
            if run > total - at {
                return Err(DecodeError::Range {
                    what: "clearcodec residual overruns the bitmap",
                    got: run as u32,
                });
            }
            let mut left = run;
            while left > 0 {
                let y = at / w;
                let x = at % w;
                let n = left.min(w - x);
                let row = dst.row(y);
                for o in row[x * 4..(x + n) * 4].chunks_exact_mut(4) {
                    put::<BGRA>(o, red, g, b, 0xFF);
                }
                at += n;
                left -= n;
            }
        }
        Ok(())
    }

    /// The bands layer: vertical bars, literal or from one of the two caches
    /// (MS-RDPEGFX 2.2.4.1.2).
    fn bands<const BGRA: bool>(
        &mut self,
        src: &[u8],
        dst: &mut DstView<'_>,
    ) -> Result<(), DecodeError> {
        let w = usize::from(dst.width());
        let h = usize::from(dst.height());
        let mut r = Reader::new(src, "clearcodec bands");
        while !r.is_empty() {
            let x_start = usize::from(r.u16_le()?);
            let x_end = usize::from(r.u16_le()?);
            let y_start = usize::from(r.u16_le()?);
            let y_end = usize::from(r.u16_le()?);
            let bkg = [r.u8()?, r.u8()?, r.u8()?]; // blue, green, red

            if x_end < x_start || y_end < y_start || x_end >= w || y_end >= h {
                return Err(DecodeError::Range {
                    what: "clearcodec band outside the bitmap",
                    got: x_end.max(y_end) as u32,
                });
            }
            let height = y_end - y_start + 1;
            self.column.resize(height * 3, 0);

            for x in x_start..=x_end {
                let header = r.u16_le()?;
                match vbar_header(header) {
                    VBar::CacheHit(index) => {
                        let Some(px) = self.vbar.get(index) else {
                            return Err(DecodeError::StateLost("clearcodec vbar cache miss"));
                        };
                        let n = (px.len() / 3).min(height);
                        self.column[..n * 3].copy_from_slice(&px[..n * 3]);
                        // A cached column shorter than the band is padded
                        // with the band background, which is what the
                        // background colour is for.
                        for p in self.column[n * 3..height * 3].chunks_exact_mut(3) {
                            p.copy_from_slice(&bkg);
                        }
                    }
                    VBar::ShortHit(index) => {
                        let y_on = usize::from(r.u8()?);
                        let Some(px) = self.short_vbar.get(index) else {
                            return Err(DecodeError::StateLost("clearcodec short vbar cache miss"));
                        };
                        build_column(&mut self.column, height, y_on, px, &bkg);
                        // Two disjoint fields of `self`, so this needs no
                        // temporary. The obvious `to_vec()` here would be one
                        // allocation per column of every band, which is the
                        // per call allocation PRDRDP/04 §4.1 rule two exists
                        // to prevent.
                        self.vbar.insert(&self.column[..height * 3]);
                    }
                    VBar::ShortMiss { y_on, count } => {
                        let px = r.take(count * 3)?;
                        self.short_vbar.insert(px);
                        build_column(&mut self.column, height, y_on, px, &bkg);
                        self.vbar.insert(&self.column[..height * 3]);
                    }
                }
                for (y, p) in self.column[..height * 3].chunks_exact(3).enumerate() {
                    let row = dst.row(y_start + y);
                    put::<BGRA>(&mut row[x * 4..x * 4 + 4], p[2], p[1], p[0], 0xFF);
                }
            }
        }
        Ok(())
    }

    /// The subcodec layer: independently coded rectangles
    /// (MS-RDPEGFX 2.2.4.1.3).
    fn subcodec<const BGRA: bool>(
        &mut self,
        src: &[u8],
        dst: &mut DstView<'_>,
    ) -> Result<(), DecodeError> {
        let w = usize::from(dst.width());
        let h = usize::from(dst.height());
        let mut r = Reader::new(src, "clearcodec subcodec");
        while !r.is_empty() {
            let x = usize::from(r.u16_le()?);
            let y = usize::from(r.u16_le()?);
            let rw = usize::from(r.u16_le()?);
            let rh = usize::from(r.u16_le()?);
            let n = r.u32_le()? as usize;
            let id = r.u8()?;
            let data = r.take(n)?;

            if x + rw > w || y + rh > h {
                return Err(DecodeError::Range {
                    what: "clearcodec subcodec rectangle outside the bitmap",
                    got: (x + rw).max(y + rh) as u32,
                });
            }
            if rw == 0 || rh == 0 {
                continue;
            }

            match id {
                SUBCODEC_RAW => {
                    let mut d = Reader::new(data, "clearcodec raw subcodec");
                    for row in 0..rh {
                        let px = d.take(rw * 3)?;
                        let out = dst.row(y + row);
                        for (p, o) in px
                            .chunks_exact(3)
                            .zip(out[x * 4..(x + rw) * 4].chunks_exact_mut(4))
                        {
                            put::<BGRA>(o, p[2], p[1], p[0], 0xFF);
                        }
                    }
                }
                SUBCODEC_NSCODEC => {
                    // The one caller NSCodec has (PRDRDP/04 §4.7). It writes
                    // through the row emitter rather than its own entry
                    // point, so the rectangle lands at its offset with no
                    // intermediate buffer.
                    let g = nscodec::decode_planes(data, rw as u16, rh as u16, &mut self.nsc)?;
                    for row in 0..rh {
                        let out = dst.row(y + row);
                        nscodec::emit_row::<BGRA>(
                            &mut self.nsc,
                            &g,
                            row,
                            &mut out[x * 4..(x + rw) * 4],
                        );
                    }
                }
                SUBCODEC_RLEX => self.rlex::<BGRA>(data, x, y, rw, rh, dst)?,
                other => {
                    return Err(DecodeError::Range {
                        what: "clearcodec subcodecId",
                        got: u32::from(other),
                    })
                }
            }
        }
        Ok(())
    }

    /// RLEX, a palette plus runs and short ramps
    /// (MS-RDPEGFX 2.2.4.1.3.1.2).
    ///
    /// A segment paints `runLength` pixels of `palette[stopIndex]` and then a
    /// suite of `suiteDepth` pixels walking the palette from
    /// `stopIndex - suiteDepth` upward. The suite is what makes RLEX good at
    /// antialiased text edges, where the pixels step through a short ramp of
    /// related colours. See [`rlex_code`] for what is and is not known about
    /// the packing of those two fields.
    #[allow(clippy::too_many_arguments)]
    fn rlex<const BGRA: bool>(
        &mut self,
        src: &[u8],
        x0: usize,
        y0: usize,
        rw: usize,
        rh: usize,
        dst: &mut DstView<'_>,
    ) -> Result<(), DecodeError> {
        let mut r = Reader::new(src, "clearcodec rlex");
        let count = usize::from(r.u8()?);
        if count == 0 || count > RLEX_MAX_PALETTE {
            return Err(DecodeError::Range {
                what: "clearcodec RLEX paletteCount",
                got: count as u32,
            });
        }
        let palette = r.take(count * 3)?;

        let total = rw * rh;
        let mut at = 0usize;
        while at < total {
            let (stop, depth) = rlex_code(r.u8()?);
            let run = run_length(&mut r)?;
            if stop >= count || depth > stop {
                return Err(DecodeError::Range {
                    what: "clearcodec RLEX stop index",
                    got: stop as u32,
                });
            }
            if run + depth == 0 {
                return Err(DecodeError::Range {
                    what: "clearcodec RLEX segment length",
                    got: 0,
                });
            }
            if run + depth > total - at {
                return Err(DecodeError::Range {
                    what: "clearcodec RLEX overruns the rectangle",
                    got: (run + depth) as u32,
                });
            }
            let entry = |i: usize| {
                let p = &palette[i * 3..i * 3 + 3];
                (p[2], p[1], p[0])
            };
            let (rr, gg, bb) = entry(stop);
            for i in 0..run {
                let p = at + i;
                let out = dst.row(y0 + p / rw);
                put::<BGRA>(&mut out[(x0 + p % rw) * 4..][..4], rr, gg, bb, 0xFF);
            }
            at += run;
            for i in 0..depth {
                let (rr, gg, bb) = entry(stop - depth + i);
                let out = dst.row(y0 + at / rw);
                put::<BGRA>(&mut out[(x0 + at % rw) * 4..][..4], rr, gg, bb, 0xFF);
                at += 1;
            }
        }
        Ok(())
    }
}

/// Build one band column: `y_on` rows of background, then the explicit
/// pixels, then background to the bottom of the band.
///
/// That shape is why the short form is short: window chrome is mostly
/// background with a few pixels of border (PRDRDP/04 §4.8.3).
fn build_column(column: &mut [u8], height: usize, y_on: usize, px: &[u8], bkg: &[u8; 3]) {
    let count = px.len() / 3;
    let start = y_on.min(height);
    let end = (start + count).min(height);
    for p in column[..start * 3].chunks_exact_mut(3) {
        p.copy_from_slice(bkg);
    }
    if end > start {
        column[start * 3..end * 3].copy_from_slice(&px[..(end - start) * 3]);
    }
    for p in column[end * 3..height * 3].chunks_exact_mut(3) {
        p.copy_from_slice(bkg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::clear as enc;
    use crate::uncompressed::dst_len;
    use remote_pixel::RowOrder;

    fn view<'a>(buf: &'a mut [u8], w: u16, h: u16) -> DstView<'a> {
        DstView::packed(buf, w, h, OutFormat::Rgba, RowOrder::TopDown).unwrap()
    }

    /// The derivation in [`vbar_header`]'s doc comment, encoded so a change
    /// to it fails a test rather than only a picture.
    #[test]
    fn the_vbar_header_split_matches_the_cache_sizes() {
        assert_eq!(vbar_header(0x8000), VBar::CacheHit(0));
        assert_eq!(vbar_header(0xFFFF), VBar::CacheHit(32767));
        assert_eq!(vbar_header(0x4000), VBar::ShortHit(0));
        assert_eq!(vbar_header(0x7FFF), VBar::ShortHit(16383));
        assert_eq!(vbar_header(0x0000), VBar::ShortMiss { y_on: 0, count: 0 });
        assert_eq!(
            vbar_header(0x3FFF),
            VBar::ShortMiss {
                y_on: 255,
                count: 63
            }
        );
        // The index of a cache hit must address the whole cache and no more.
        assert!(matches!(vbar_header(0xFFFF), VBar::CacheHit(i) if i < VBAR_ENTRIES));
        assert!(matches!(vbar_header(0x7FFF), VBar::ShortHit(i) if i < SHORT_VBAR_ENTRIES));
        // And the pixel count must never exceed the short cache's stride.
        assert!(matches!(
            vbar_header(0x3FFF),
            VBar::ShortMiss { count, .. } if count <= SHORT_VBAR_MAX
        ));
    }

    #[test]
    fn the_rlex_code_splits_seven_and_one() {
        assert_eq!(rlex_code(0x00), (0, 0));
        assert_eq!(rlex_code(0x7F), (127, 0));
        assert_eq!(rlex_code(0x80), (0, 1));
        assert_eq!(rlex_code(0xFF), (127, 1));
    }

    /// The escalating run length is a widening rather than a sum: the largest
    /// factor present is the length, so 0xFF followed by 0x0102 is 258 and
    /// not 258 plus 255.
    #[test]
    fn the_run_length_escape_widens_rather_than_adds() {
        let mut r = Reader::new(&[0x05], "t");
        assert_eq!(run_length(&mut r).unwrap(), 5);
        let mut r = Reader::new(&[0xFF, 0x02, 0x01], "t");
        assert_eq!(run_length(&mut r).unwrap(), 0x0102);
        let mut r = Reader::new(&[0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04], "t");
        assert_eq!(run_length(&mut r).unwrap(), 0x0403_0201);
        let mut r = Reader::new(&[0xFF], "t");
        assert!(run_length(&mut r).is_err());
    }

    #[test]
    fn the_residual_layer_fills_the_bitmap_in_raster_order() {
        let (w, h) = (5u16, 3u16);
        let px: Vec<[u8; 3]> = (0..15u8).map(|i| [i, i + 100, 200 - i]).collect();
        let src = enc::residual_only(&px, w, h);
        let mut buf = vec![0u8; dst_len(w, h)];
        {
            let mut v = view(&mut buf, w, h);
            ClearDecoder::new().decode(&src, &mut v).unwrap();
        }
        for (i, out) in buf.chunks_exact(4).enumerate() {
            assert_eq!(&out[..3], &px[i][..], "pixel {i}");
            assert_eq!(out[3], 0xFF);
        }
    }

    /// Runs cross scanlines, which is the case a decoder that writes row by
    /// row without carrying the remainder gets wrong.
    #[test]
    fn a_residual_run_crosses_scanlines() {
        let (w, h) = (7u16, 4u16);
        let px: Vec<[u8; 3]> = (0..28).map(|_| [9u8, 8, 7]).collect();
        let src = enc::residual_only(&px, w, h);
        let mut buf = vec![0u8; dst_len(w, h)];
        {
            let mut v = view(&mut buf, w, h);
            ClearDecoder::new().decode(&src, &mut v).unwrap();
        }
        assert!(buf.chunks_exact(4).all(|p| p[..3] == [9, 8, 7]));
    }

    #[test]
    fn a_residual_run_that_overruns_is_refused() {
        let (w, h) = (4u16, 2u16);
        let mut src = vec![0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // glyphFlags, seqNumber, then the three byte counts.
        src[0] = 0;
        let mut payload = vec![1u8, 2, 3]; // B, G, R
        payload.push(0xFF);
        payload.extend_from_slice(&0xFFFFu16.to_le_bytes());
        payload.extend_from_slice(&1_000_000u32.to_le_bytes());
        let mut stream = vec![0u8, 0];
        stream.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&payload);
        let mut buf = vec![0u8; dst_len(w, h)];
        let mut v = view(&mut buf, w, h);
        assert!(matches!(
            ClearDecoder::new().decode(&stream, &mut v),
            Err(DecodeError::Range { .. })
        ));
    }

    /// One band of literal short VBars, which is the miss path, followed by a
    /// second bitmap that hits both caches. That pair is the whole point of
    /// the bands layer and it only works if the two cursors advance in step
    /// with the server's.
    #[test]
    fn short_vbars_are_cached_and_then_hit() {
        let (w, h) = (4u16, 6u16);
        let bkg = [10u8, 20, 30];
        // Two pixels of border at row 2 of every column.
        let cols: Vec<(usize, Vec<[u8; 3]>)> = (0..4)
            .map(|_| (2usize, vec![[200u8, 100, 50], [201, 101, 51]]))
            .collect();
        let first = enc::band_short_miss(w, h, &bkg, &cols);
        let mut dec = ClearDecoder::new();
        let mut buf = vec![0u8; dst_len(w, h)];
        {
            let mut v = view(&mut buf, w, h);
            dec.decode(&first, &mut v).unwrap();
        }
        let px = |x: usize, y: usize| &buf[(y * usize::from(w) + x) * 4..][..3];
        assert_eq!(px(0, 0), &[30, 20, 10]); // background, R G B from B G R
        assert_eq!(px(0, 2), &[50, 100, 200]);
        assert_eq!(px(3, 3), &[51, 101, 201]);
        assert_eq!(px(3, 5), &[30, 20, 10]);

        // The four columns went into the ShortVBar cache at 0 to 3 and into
        // the VBar cache at 0 to 3. A second bitmap that hits them must
        // reproduce the same picture.
        let second = enc::band_vbar_hits(w, h, &bkg, &[0, 1, 2, 3], 1);
        let mut buf2 = vec![0u8; dst_len(w, h)];
        {
            let mut v = view(&mut buf2, w, h);
            dec.decode(&second, &mut v).unwrap();
        }
        assert_eq!(buf, buf2);
    }

    #[test]
    fn a_vbar_cache_miss_is_state_lost_rather_than_a_failure() {
        let (w, h) = (2u16, 2u16);
        let src = enc::band_vbar_hits(w, h, &[0, 0, 0], &[9999, 9999], 0);
        let mut buf = vec![0u8; dst_len(w, h)];
        let mut v = view(&mut buf, w, h);
        assert_eq!(
            ClearDecoder::new().decode(&src, &mut v),
            Err(DecodeError::StateLost("clearcodec vbar cache miss"))
        );
    }

    /// The sequence number. Any first value is accepted; a gap after that is
    /// `StateLost` and clears the caches so the next bitmap starts clean.
    #[test]
    fn a_sequence_gap_is_state_lost_and_clears_the_caches() {
        let (w, h) = (2u16, 2u16);
        let px = vec![[1u8, 2, 3]; 4];
        let mut dec = ClearDecoder::new();
        let mut buf = vec![0u8; dst_len(w, h)];

        // A stream that starts at 200 rather than at zero is accepted.
        let a = enc::with_seq(&enc::residual_only(&px, w, h), 200);
        {
            let mut v = view(&mut buf, w, h);
            assert!(dec.decode(&a, &mut v).is_ok());
        }
        let b = enc::with_seq(&enc::residual_only(&px, w, h), 201);
        {
            let mut v = view(&mut buf, w, h);
            assert!(dec.decode(&b, &mut v).is_ok());
        }
        let c = enc::with_seq(&enc::residual_only(&px, w, h), 210);
        {
            let mut v = view(&mut buf, w, h);
            assert_eq!(
                dec.decode(&c, &mut v),
                Err(DecodeError::StateLost("clearcodec sequence number"))
            );
        }
        // And the decoder recovers: the next bitmap in sequence works.
        let d = enc::with_seq(&enc::residual_only(&px, w, h), 211);
        let mut v = view(&mut buf, w, h);
        assert!(dec.decode(&d, &mut v).is_ok());
    }

    /// The glyph cache: decode with `GLYPH_INDEX`, then hit it. A hit whose
    /// dimensions do not match the destination is `StateLost` rather than a
    /// wrongly scaled picture.
    #[test]
    fn a_glyph_is_stored_and_then_hit() {
        let (w, h) = (8u16, 4u16);
        let px: Vec<[u8; 3]> = (0..32u8).map(|i| [i * 3, i * 5, i * 7]).collect();
        let store = enc::with_glyph(&enc::residual_only(&px, w, h), 17, false);
        let mut dec = ClearDecoder::new();
        let mut a = vec![0u8; dst_len(w, h)];
        {
            let mut v = view(&mut a, w, h);
            dec.decode(&store, &mut v).unwrap();
        }
        let hit = enc::glyph_hit(17, 1);
        let mut b = vec![0u8; dst_len(w, h)];
        {
            let mut v = view(&mut b, w, h);
            dec.decode(&hit, &mut v).unwrap();
        }
        assert_eq!(a, b);

        // The same glyph asked for at another size is a miss.
        let hit = enc::glyph_hit(17, 2);
        let mut c = vec![0u8; dst_len(4, 4)];
        let mut v = view(&mut c, 4, 4);
        assert_eq!(
            dec.decode(&hit, &mut v),
            Err(DecodeError::StateLost("clearcodec glyph cache miss"))
        );
    }

    /// A bitmap too large for the glyph cache is decoded and simply not
    /// stored, so a later hit misses rather than reading a truncated entry.
    #[test]
    fn an_oversized_bitmap_is_not_cached() {
        let (w, h) = (64u16, 32u16); // 2048 pixels, over the 1024 limit
        let px = vec![[7u8, 7, 7]; 2048];
        let store = enc::with_glyph(&enc::residual_only(&px, w, h), 3, false);
        let mut dec = ClearDecoder::new();
        let mut buf = vec![0u8; dst_len(w, h)];
        {
            let mut v = view(&mut buf, w, h);
            dec.decode(&store, &mut v).unwrap();
        }
        let hit = enc::glyph_hit(3, 1);
        let mut v = view(&mut buf, w, h);
        assert!(matches!(
            dec.decode(&hit, &mut v),
            Err(DecodeError::StateLost(_))
        ));
    }

    #[test]
    fn cache_reset_clears_every_cache() {
        let (w, h) = (8u16, 4u16);
        let px = vec![[1u8, 2, 3]; 32];
        let mut dec = ClearDecoder::new();
        let mut buf = vec![0u8; dst_len(w, h)];
        {
            let mut v = view(&mut buf, w, h);
            dec.decode(
                &enc::with_glyph(&enc::residual_only(&px, w, h), 5, false),
                &mut v,
            )
            .unwrap();
        }
        let mut reset = enc::with_glyph(&enc::residual_only(&px, w, h), 6, false);
        reset[0] |= FLAG_CACHE_RESET;
        reset[1] = 1;
        {
            let mut v = view(&mut buf, w, h);
            dec.decode(&reset, &mut v).unwrap();
        }
        let mut v = view(&mut buf, w, h);
        assert!(matches!(
            dec.decode(&enc::glyph_hit(5, 2), &mut v),
            Err(DecodeError::StateLost(_))
        ));
    }

    /// The subcodec layer, all three ids, each over a sub rectangle of a
    /// bitmap the residual layer already filled. That composition order is
    /// MS-RDPEGFX 3.3.8.1.3's and it is what the assertions check: the
    /// rectangle changed and nothing around it did.
    #[test]
    fn every_subcodec_writes_only_its_own_rectangle() {
        let (w, h) = (16u16, 12u16);
        let base = vec![[0u8, 0, 0]; 192];
        let rect: Vec<[u8; 3]> = (0..24u8).map(|i| [i * 9, 255 - i * 9, 128]).collect();
        for id in [SUBCODEC_RAW, SUBCODEC_NSCODEC, SUBCODEC_RLEX] {
            let src = enc::residual_plus_subcodec(&base, w, h, 4, 3, 6, 4, id, &rect);
            let mut buf = vec![0u8; dst_len(w, h)];
            {
                let mut v = view(&mut buf, w, h);
                ClearDecoder::new().decode(&src, &mut v).unwrap();
            }
            let px = |x: usize, y: usize| &buf[(y * 16 + x) * 4..][..3];
            assert_eq!(px(0, 0), &[0, 0, 0], "id {id} leaked left");
            assert_eq!(px(15, 11), &[0, 0, 0], "id {id} leaked right");
            for row in 0..4usize {
                for col in 0..6usize {
                    let want = rect[row * 6 + col];
                    let got = px(4 + col, 3 + row);
                    for c in 0..3 {
                        assert!(
                            (i32::from(got[c]) - i32::from(want[c])).abs() <= 3,
                            "id {id} at ({col}, {row}): got {got:?} want {want:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn an_unknown_subcodec_id_is_refused() {
        let (w, h) = (8u16, 8u16);
        let base = vec![[0u8; 3]; 64];
        let rect = vec![[1u8, 2, 3]; 4];
        let src = enc::residual_plus_subcodec(&base, w, h, 0, 0, 2, 2, 9, &rect);
        let mut buf = vec![0u8; dst_len(w, h)];
        let mut v = view(&mut buf, w, h);
        assert_eq!(
            ClearDecoder::new().decode(&src, &mut v),
            Err(DecodeError::Range {
                what: "clearcodec subcodecId",
                got: 9
            })
        );
    }

    #[test]
    fn a_subcodec_rectangle_outside_the_bitmap_is_refused() {
        let (w, h) = (8u16, 8u16);
        let base = vec![[0u8; 3]; 64];
        let rect = vec![[1u8, 2, 3]; 4];
        let src = enc::residual_plus_subcodec(&base, w, h, 7, 7, 2, 2, SUBCODEC_RAW, &rect);
        let mut buf = vec![0u8; dst_len(w, h)];
        let mut v = view(&mut buf, w, h);
        assert!(matches!(
            ClearDecoder::new().decode(&src, &mut v),
            Err(DecodeError::Range { .. })
        ));
    }

    /// The truncation sweep, over a stream that uses all three layers.
    #[test]
    fn every_prefix_is_handled() {
        let (w, h) = (12u16, 8u16);
        let base: Vec<[u8; 3]> = (0..96).map(|i| [i as u8, 0, 0]).collect();
        let rect = vec![[9u8, 9, 9]; 12];
        let src = enc::residual_plus_subcodec(&base, w, h, 2, 2, 4, 3, SUBCODEC_RLEX, &rect);
        let mut buf = vec![0u8; dst_len(w, h)];
        for n in 0..src.len() {
            let mut dec = ClearDecoder::new();
            let mut v = view(&mut buf, w, h);
            let _ = dec.decode(&src[..n], &mut v);
        }
    }

    /// The adversarial sweep over the leading byte, which is `glyphFlags` and
    /// therefore selects between four completely different parses.
    #[test]
    fn every_leading_flag_byte_terminates() {
        let (w, h) = (8u16, 4u16);
        let px = vec![[3u8, 4, 5]; 32];
        let base = enc::residual_only(&px, w, h);
        let mut buf = vec![0u8; dst_len(w, h)];
        for lead in 0u16..=255 {
            let mut src = base.clone();
            src[0] = lead as u8;
            let mut dec = ClearDecoder::new();
            let mut v = view(&mut buf, w, h);
            let _ = dec.decode(&src, &mut v);
        }
    }

    #[test]
    fn the_caches_report_and_release_their_memory() {
        let (w, h) = (8u16, 4u16);
        let px = vec![[1u8, 2, 3]; 32];
        let mut dec = ClearDecoder::new();
        let empty = dec.bytes();
        let mut buf = vec![0u8; dst_len(w, h)];
        {
            let mut v = view(&mut buf, w, h);
            dec.decode(
                &enc::with_glyph(&enc::residual_only(&px, w, h), 1, false),
                &mut v,
            )
            .unwrap();
        }
        assert!(dec.bytes() > empty);
        dec.reset();
        assert!(dec.bytes() <= empty);
    }

    /// The VBar arena's lap check, exercised directly because reaching 32 MB
    /// of columns through the decoder would be a slow test. An entry stays
    /// valid until the arena has written past it and then reports a miss
    /// rather than handing back another column's bytes.
    #[test]
    fn a_lapped_vbar_entry_reports_a_miss() {
        let mut c = VBarCache::new();
        c.insert(&[1u8, 2, 3]);
        assert_eq!(c.get(0), Some(&[1u8, 2, 3][..]));
        // Write the whole arena past it.
        let block = vec![7u8; VBAR_MAX_PIXELS * 3];
        let laps = VBAR_ARENA / block.len() + 2;
        for _ in 0..laps {
            c.insert(&block);
        }
        assert_eq!(c.get(0), None);
        c.reset();
        assert_eq!(c.get(0), None);
    }
}
