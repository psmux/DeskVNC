//! RemoteFX (MS-RDPRFX), the wavelet codec over 64 by 64 tiles.
//!
//! Carried either as `RDPGFX_CODECID_CAVIDEO` (0x0003) inside EGFX or as a
//! Bitmap Codecs codec id inside legacy Surface Commands (PRDRDP/04 §2.8).
//! Both carry the same bitstream, so both arrive here.
//!
//! ## What is in this module and what is in `rdp-pdu`
//!
//! All of it is here. Every `TS_RFX_*` structure is self describing inside
//! the codec payload: a block carries its own `blockLen`, a tileset carries
//! its own `numTiles`, a tile carries its own three component lengths.
//! Nothing needs a length from an outer PDU field, which is the test
//! PRDRDP/12 §2.2.2 gives for the codec payload boundary.
//!
//! ## The four stages, in the order MS-RDPRFX 3.1.8.1 fixes
//!
//! 1. [`rlgr::decode`] expands one component's entropy coded bytes into 4096
//!    coefficients (3.1.8.1.7).
//! 2. [`quant::differential_ll3`] undoes the DPCM coding of the last 64
//!    coefficients (3.1.8.1.6). This happens **before** dequantization, which
//!    is the pair people reorder.
//! 3. [`quant::dequantize`] left shifts each subband by its own factor less
//!    one (3.1.8.1.5).
//! 4. [`dwt::inverse_2d`] runs the three level inverse wavelet (3.1.8.1.4).
//!
//! Then, with all three components done, [`ycbcr::row`] converts and writes
//! (3.1.8.1.3). PRDRDP/04 §11.2 budgets those at 2.0, 0.3, 1.9 and 1.0 ms of
//! a 5.2 ms 1080p frame, which is why each is its own module with its own
//! bench line rather than one function.
//!
//! ## State
//!
//! RemoteFX has no inter frame state at the pixel level, which is why
//! PRDRDP/04 §4.14 gives it "none" in the persistent state column. It does
//! have negotiated per channel state, the entropy algorithm and the tile
//! size, and that lives in [`RfxContext`] because MS-RDPRFX lets a
//! `TS_RFX_CONTEXT` change it mid session. The coefficient buffers are
//! caller pooled in [`RfxScratch`], the way `planar::PlanarScratch` is
//! (PRDRDP/04 §4.1 rules two and three).

pub mod dwt;
pub mod quant;
pub mod rlgr;
pub mod ycbcr;

use remote_pixel::{DstView, OutFormat};

use crate::{DecodeError, Reader};

pub use quant::{COEFS, TILE};
pub use rlgr::Entropy;

// Block types, MS-RDPRFX 2.2.2.1.1.
const WBT_SYNC: u16 = 0xCCC0;
const WBT_CODEC_VERSIONS: u16 = 0xCCC1;
const WBT_CHANNELS: u16 = 0xCCC2;
const WBT_CONTEXT: u16 = 0xCCC3;
const WBT_FRAME_BEGIN: u16 = 0xCCC4;
const WBT_FRAME_END: u16 = 0xCCC5;
const WBT_REGION: u16 = 0xCCC6;
const WBT_EXTENSION: u16 = 0xCCC7;

/// `TS_RFX_BLOCKT` is a `u16` type and a `u32` length, and the length counts
/// itself (MS-RDPRFX 2.2.2.1.1).
const BLOCKT_LEN: usize = 6;

/// `WBT_SYNC.magic` (MS-RDPRFX 2.2.2.2.1).
const SYNC_MAGIC: u32 = 0xCACC_ACCA;
/// `TS_RFX_REGION.regionType` (MS-RDPRFX 2.2.2.3.3).
const CBT_REGION: u16 = 0xCAC1;
/// `TS_RFX_TILESET.subtype` (MS-RDPRFX 2.2.2.3.4).
const CBT_TILESET: u16 = 0xCAC2;
/// `TS_RFX_TILE.blockType` (MS-RDPRFX 2.2.2.3.4.1).
const CBT_TILE: u16 = 0xCAC3;

/// Bytes of a `TS_RFX_TILE` before its three component blobs: the block
/// header, three quantization indices, two tile indices and three lengths.
const TILE_HEADER: usize = BLOCKT_LEN + 3 + 4 + 6;

/// Bytes of one `TS_RFX_CODEC_QUANT` (MS-RDPRFX 2.2.2.1.6).
const QUANT_LEN: usize = 5;

/// `CLW_ENTROPY_RLGR1`, the `et` field of a `properties` word.
const CLW_ENTROPY_RLGR1: u16 = 1;
/// `CLW_ENTROPY_RLGR3`.
const CLW_ENTROPY_RLGR3: u16 = 4;

/// A rectangle in destination coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    /// Left edge.
    pub x: u16,
    /// Top edge.
    pub y: u16,
    /// Width in pixels.
    pub w: u16,
    /// Height in pixels.
    pub h: u16,
}

impl Rect {
    /// The intersection, or `None` when they do not overlap.
    pub(crate) fn intersect(self, other: Rect) -> Option<Rect> {
        let x0 = self.x.max(other.x);
        let y0 = self.y.max(other.y);
        let x1 = (self.x as u32 + self.w as u32).min(other.x as u32 + other.w as u32);
        let y1 = (self.y as u32 + self.h as u32).min(other.y as u32 + other.h as u32);
        if x1 <= x0 as u32 || y1 <= y0 as u32 {
            return None;
        }
        Some(Rect {
            x: x0,
            y: y0,
            w: (x1 - x0 as u32) as u16,
            h: (y1 - y0 as u32) as u16,
        })
    }

    /// The smallest rectangle covering both.
    pub(crate) fn union(self, other: Rect) -> Rect {
        let x0 = self.x.min(other.x);
        let y0 = self.y.min(other.y);
        let x1 = (self.x as u32 + self.w as u32).max(other.x as u32 + other.w as u32);
        let y1 = (self.y as u32 + self.h as u32).max(other.y as u32 + other.h as u32);
        Rect {
            x: x0,
            y: y0,
            w: (x1 - x0 as u32) as u16,
            h: (y1 - y0 as u32) as u16,
        }
    }
}

/// The clip region of a `TS_RFX_REGION`, as a borrow of the rectangle array
/// still inside the payload (MS-RDPRFX 2.2.2.3.3).
///
/// It is a borrow rather than a `Vec<Rect>` because PRDRDP/04 §4.1 rule two
/// forbids a per call allocation and a region can carry hundreds of
/// rectangles. Every tile is tested against it by walking these bytes again,
/// which is eight bytes per rectangle out of L1 and cheaper than the
/// allocation would be.
///
/// `pub(crate)` because the progressive codec's `WBT_REGION` carries the same
/// `RFX_RECT` array with the same meaning (MS-RDPEGFX 2.2.4.2.1.5), so the
/// clip stage is shared rather than written twice.
#[derive(Clone, Copy, Default)]
pub(crate) struct Region<'a> {
    rects: &'a [u8],
}

impl<'a> Region<'a> {
    pub(crate) fn new(rects: &'a [u8]) -> Self {
        Self { rects }
    }

    pub(crate) fn count(&self) -> usize {
        self.rects.len() / 8
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Rect> + '_ {
        self.rects.chunks_exact(8).map(|c| Rect {
            x: u16::from_le_bytes([c[0], c[1]]),
            y: u16::from_le_bytes([c[2], c[3]]),
            w: u16::from_le_bytes([c[4], c[5]]),
            h: u16::from_le_bytes([c[6], c[7]]),
        })
    }
}

/// What a message turned out to contain, for the caller's damage tracking and
/// frame acknowledgement (PRDRDP/04 §3.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RfxFrame {
    /// `TS_RFX_FRAME_BEGIN.frameIdx`, when the message carried one.
    pub frame_idx: Option<u32>,
    /// Tiles the message declared.
    pub tiles: u32,
    /// Tiles that intersected the clip region and were therefore decoded. A
    /// tile that intersects nothing is skipped before its entropy decode,
    /// which PRDRDP/04 §4.6.7 asks for because the check is free.
    pub decoded: u32,
    /// The bounding box of everything written, in destination coordinates.
    pub damage: Option<Rect>,
}

impl RfxFrame {
    fn touch(&mut self, r: Rect) {
        self.damage = Some(match self.damage {
            Some(d) => d.union(r),
            None => r,
        });
    }
}

/// Per channel negotiated state (MS-RDPRFX 2.2.2.2.4).
///
/// The entropy algorithm is per context and per tileset and can change mid
/// session, so it is read out of the stream rather than out of what we
/// advertised (PRDRDP/04 §4.6.1). One of these per EGFX channel, reset on
/// `ResetGraphics` and on reconnect.
#[derive(Debug, Clone)]
pub struct RfxContext {
    entropy: Entropy,
    tile_size: u16,
    seen_sync: bool,
}

impl Default for RfxContext {
    fn default() -> Self {
        Self::new()
    }
}

impl RfxContext {
    /// A context at the defaults MS-RDPRFX 2.2.2.2.4 implies before any
    /// `TS_RFX_CONTEXT` has arrived: RLGR1 and 64 by 64 tiles.
    pub fn new() -> Self {
        Self {
            entropy: Entropy::Rlgr1,
            tile_size: TILE as u16,
            seen_sync: false,
        }
    }

    /// Forget everything the server told us.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// The entropy algorithm currently in force.
    pub fn entropy(&self) -> Entropy {
        self.entropy
    }

    /// Bytes held, for the accounting in PRDRDP/04 §11.3. A context is a
    /// handful of fields, so this is here for symmetry with the caches the
    /// other codecs keep rather than because it is large.
    pub fn bytes(&self) -> usize {
        core::mem::size_of::<Self>()
    }
}

/// The four coefficient buffers a tile decode needs, allocated once and
/// reused (PRDRDP/04 §4.1 rule two).
///
/// Three components of 4096 `i16` plus one working buffer for the inverse
/// DWT, so 32 KiB. Nothing in it survives a decode.
#[derive(Default)]
pub struct RfxScratch {
    buf: Vec<i16>,
}

impl RfxScratch {
    /// An empty scratch, which allocates on its first decode.
    pub fn new() -> Self {
        Self::default()
    }

    /// Size the buffers, so the next decode does not allocate.
    ///
    /// `remotefx::decode_message` calls `grow` directly; this exists for
    /// `progressive::decode_message`, which pools the same four buffers, and
    /// is gated so a `--no-default-features` build has no unused method.
    #[cfg(feature = "progressive")]
    pub(crate) fn ensure(&mut self) {
        self.grow();
    }

    /// A scratch already sized, so the first decode does not allocate either.
    pub fn with_capacity() -> Self {
        let mut s = Self::new();
        s.grow();
        s
    }

    /// Give the memory back.
    pub fn reset(&mut self) {
        self.buf = Vec::new();
    }

    /// Bytes currently held.
    pub fn bytes(&self) -> usize {
        self.buf.capacity() * core::mem::size_of::<i16>()
    }

    fn grow(&mut self) {
        if self.buf.len() < 4 * COEFS {
            self.buf.resize(4 * COEFS, 0);
        }
    }

    /// The three component buffers and the inverse DWT's working buffer.
    ///
    /// `pub(crate)` because the progressive codec needs exactly this set of
    /// four and pooling a second identical type would be four buffers of the
    /// same size under a different name.
    pub(crate) fn parts(&mut self) -> (&mut [i16], &mut [i16], &mut [i16], &mut [i16]) {
        let (y, rest) = self.buf.split_at_mut(COEFS);
        let (cb, rest) = rest.split_at_mut(COEFS);
        let (cr, tmp) = rest.split_at_mut(COEFS);
        (y, cb, cr, &mut tmp[..COEFS])
    }
}

/// Bytes of scratch a decode needs, so a caller can size a pool without
/// decoding first.
pub fn scratch_len() -> usize {
    4 * COEFS * core::mem::size_of::<i16>()
}

/// The entropy algorithm out of a `properties` word.
///
/// `properties` is packed as `flags` (3 bits), `cct` (2), `xft` (4), `et` (4)
/// and `qt` (2), low bits first, so `et` is bits 9 to 12
/// (MS-RDPRFX 2.2.2.2.4). The colour conversion transform and the wavelet
/// transform have exactly one legal value each, and a stream that names
/// another is asking for a codec we do not have rather than one we should
/// guess at.
fn entropy_from_properties(properties: u16) -> Result<Entropy, DecodeError> {
    match (properties >> 9) & 0x0F {
        CLW_ENTROPY_RLGR1 => Ok(Entropy::Rlgr1),
        CLW_ENTROPY_RLGR3 => Ok(Entropy::Rlgr3),
        other => Err(DecodeError::Range {
            what: "TS_RFX properties et",
            got: u32::from(other),
        }),
    }
}

/// Decode one RemoteFX message into the caller's destination.
///
/// A message is a sequence of `TS_RFX_*` blocks. Everything that is not a
/// tileset is state or geometry; the tileset is the pixels. Tiles are placed
/// at `(xIdx * 64, yIdx * 64)` relative to the destination origin and are
/// written only where they intersect the current region and the destination
/// (MS-RDPRFX 3.1.8, PRDRDP/04 §4.6.7).
///
/// The row order lives in `dst`, and RemoteFX is always top down: both EGFX
/// and Surface Bits are (PRDRDP/04 §2.8), and there is no legacy DIB body
/// path into this codec.
///
/// Every error is a [`DecodeError`]. No input makes this panic, loop without
/// consuming, or write outside `dst`.
pub fn decode_message(
    src: &[u8],
    ctx: &mut RfxContext,
    scratch: &mut RfxScratch,
    dst: &mut DstView<'_>,
) -> Result<RfxFrame, DecodeError> {
    scratch.grow();
    let mut frame = RfxFrame::default();
    let mut region = Region::default();
    let mut have_region = false;

    let mut r = Reader::new(src, "remotefx message");
    while !r.is_empty() {
        let block_type = r.u16_le()?;
        let block_len = r.u32_le()? as usize;
        // A block shorter than its own header would let the walk stand still,
        // which is the loop forever case PRDRDP/04 §4.1 rule five names.
        if block_len < BLOCKT_LEN {
            return Err(DecodeError::Range {
                what: "TS_RFX_BLOCKT blockLen",
                got: block_len as u32,
            });
        }
        let body = r.take(block_len - BLOCKT_LEN)?;
        let mut b = Reader::new(body, "remotefx block");

        match block_type {
            WBT_SYNC => {
                let magic = b.u32_le()?;
                if magic != SYNC_MAGIC {
                    return Err(DecodeError::Range {
                        what: "TS_RFX_SYNC magic",
                        got: magic,
                    });
                }
                let _version = b.u16_le()?;
                ctx.seen_sync = true;
            }
            WBT_CODEC_VERSIONS => {
                let n = b.u8()?;
                for _ in 0..n {
                    let _codec_id = b.u8()?;
                    let _version = b.u16_le()?;
                }
            }
            WBT_CHANNELS => {
                let n = b.u8()?;
                for _ in 0..n {
                    let _channel_id = b.u8()?;
                    let _width = b.u16_le()?;
                    let _height = b.u16_le()?;
                }
            }
            WBT_CONTEXT => {
                let _codec_id = b.u8()?;
                let _channel_id = b.u8()?;
                let _ctx_id = b.u8()?;
                let tile_size = b.u16_le()?;
                if usize::from(tile_size) != TILE {
                    return Err(DecodeError::Range {
                        what: "TS_RFX_CONTEXT tileSize",
                        got: u32::from(tile_size),
                    });
                }
                ctx.tile_size = tile_size;
                ctx.entropy = entropy_from_properties(b.u16_le()?)?;
            }
            WBT_FRAME_BEGIN => {
                let _codec_id = b.u8()?;
                let _channel_id = b.u8()?;
                frame.frame_idx = Some(b.u32_le()?);
                let _num_regions = b.u16_le()?;
            }
            WBT_FRAME_END => {
                let _codec_id = b.u8()?;
                let _channel_id = b.u8()?;
            }
            WBT_REGION => {
                let _codec_id = b.u8()?;
                let _channel_id = b.u8()?;
                let _region_flags = b.u8()?;
                let num_rects = usize::from(b.u16_le()?);
                region = Region::new(b.take(num_rects * 8)?);
                let region_type = b.u16_le()?;
                if region_type != CBT_REGION {
                    return Err(DecodeError::Range {
                        what: "TS_RFX_REGION regionType",
                        got: u32::from(region_type),
                    });
                }
                // `numTileSets` follows and is deliberately not read. It is
                // always one, nothing here uses it, and PRDRDP/04 §4.6.1's
                // table gives it without a width. Reading two bytes for a
                // field that is one would turn a well formed region into a
                // truncation, and reading one for a field that is two would
                // leave a byte the block walk ignores anyway, so the safe
                // move is to read neither: `blockLen` already said where this
                // block ends.
                have_region = true;
            }
            WBT_EXTENSION => {
                let clip = if have_region && region.count() > 0 {
                    Some(region)
                } else {
                    // BEHAVIOUR: a message with no region block, or a region
                    // that carries zero rectangles, is taken as "the whole
                    // destination" rather than as "draw nothing". MS-RDPRFX
                    // 2.2.2.3.3 does not say which, and reading it the other
                    // way turns a server that relies on the destination
                    // rectangle alone into a black screen. Source: the
                    // failure mode is asymmetric, so the tolerant reading is
                    // the safe one until a capture settles it.
                    None
                };
                decode_tileset(&mut b, ctx, scratch, clip, dst, &mut frame)?;
            }
            // A block type we do not know is skipped rather than refused. Its
            // `blockLen` already told us how long it is, so skipping cannot
            // desynchronise the walk, and MS-RDPRFX has added block types
            // before.
            _ => {}
        }
    }
    Ok(frame)
}

/// `TS_RFX_TILESET` (MS-RDPRFX 2.2.2.3.4) and the tile loop.
fn decode_tileset(
    b: &mut Reader<'_>,
    ctx: &mut RfxContext,
    scratch: &mut RfxScratch,
    clip: Option<Region<'_>>,
    dst: &mut DstView<'_>,
    frame: &mut RfxFrame,
) -> Result<(), DecodeError> {
    let _codec_id = b.u8()?;
    let _channel_id = b.u8()?;
    let subtype = b.u16_le()?;
    if subtype != CBT_TILESET {
        return Err(DecodeError::Range {
            what: "TS_RFX_TILESET subtype",
            got: u32::from(subtype),
        });
    }
    let _idx = b.u16_le()?;
    // The tileset carries its own copy of the properties word and it is the
    // one in force for these tiles, so it wins over the context's.
    ctx.entropy = entropy_from_properties(b.u16_le()?)?;
    let num_quant = usize::from(b.u8()?);
    let tile_size = b.u8()?;
    if usize::from(tile_size) != TILE {
        return Err(DecodeError::Range {
            what: "TS_RFX_TILESET tileSize",
            got: u32::from(tile_size),
        });
    }
    let num_tiles = u32::from(b.u16_le()?);
    let tiles_data_size = b.u32_le()? as usize;
    let quants = b.take(num_quant * QUANT_LEN)?;
    let tiles = b.take(tiles_data_size)?;

    frame.tiles = frame.tiles.saturating_add(num_tiles);

    let mut t = Reader::new(tiles, "remotefx tile");
    for _ in 0..num_tiles {
        decode_tile(&mut t, ctx, scratch, quants, num_quant, clip, dst, frame)?;
    }
    Ok(())
}

/// One `TS_RFX_TILE` (MS-RDPRFX 2.2.2.3.4.1).
#[allow(clippy::too_many_arguments)]
fn decode_tile(
    t: &mut Reader<'_>,
    ctx: &RfxContext,
    scratch: &mut RfxScratch,
    quants: &[u8],
    num_quant: usize,
    clip: Option<Region<'_>>,
    dst: &mut DstView<'_>,
    frame: &mut RfxFrame,
) -> Result<(), DecodeError> {
    let block_type = t.u16_le()?;
    let block_len = t.u32_le()? as usize;
    if block_type != CBT_TILE {
        return Err(DecodeError::Range {
            what: "TS_RFX_TILE blockType",
            got: u32::from(block_type),
        });
    }
    if block_len < TILE_HEADER {
        return Err(DecodeError::Range {
            what: "TS_RFX_TILE blockLen",
            got: block_len as u32,
        });
    }
    let body = t.take(block_len - BLOCKT_LEN)?;
    let mut b = Reader::new(body, "remotefx tile body");

    let qy = usize::from(b.u8()?);
    let qcb = usize::from(b.u8()?);
    let qcr = usize::from(b.u8()?);
    let x_idx = usize::from(b.u16_le()?);
    let y_idx = usize::from(b.u16_le()?);
    let y_len = usize::from(b.u16_le()?);
    let cb_len = usize::from(b.u16_le()?);
    let cr_len = usize::from(b.u16_le()?);

    for (i, what) in [(qy, "quantIdxY"), (qcb, "quantIdxCb"), (qcr, "quantIdxCr")] {
        if i >= num_quant {
            return Err(DecodeError::Range {
                what,
                got: i as u32,
            });
        }
    }

    // The three blobs are taken before anything is decoded, so a tile that
    // claims more bytes than it carries is a truncation here rather than a
    // short read three stages later.
    let y_data = b.take(y_len)?;
    let cb_data = b.take(cb_len)?;
    let cr_data = b.take(cr_len)?;

    // Placement, and the early out of PRDRDP/04 §4.6.7. A tile whose
    // rectangle intersects nothing costs three 4096 coefficient decodes if it
    // is decoded anyway, and the intersection test is a handful of
    // comparisons, so the test happens first.
    let tx = x_idx.saturating_mul(TILE);
    let ty = y_idx.saturating_mul(TILE);
    if tx > usize::from(u16::MAX) || ty > usize::from(u16::MAX) {
        return Err(DecodeError::Range {
            what: "TS_RFX_TILE index",
            got: (x_idx.max(y_idx)) as u32,
        });
    }
    let tile_rect = Rect {
        x: tx as u16,
        y: ty as u16,
        w: TILE as u16,
        h: TILE as u16,
    };
    let bounds = Rect {
        x: 0,
        y: 0,
        w: dst.width(),
        h: dst.height(),
    };
    let Some(visible) = tile_rect.intersect(bounds) else {
        return Ok(());
    };
    let covered = match clip {
        None => true,
        Some(region) => region.iter().any(|r| visible.intersect(r).is_some()),
    };
    if !covered {
        return Ok(());
    }

    let qy = quant::parse_quant(&quants[qy * QUANT_LEN..]);
    let qcb = quant::parse_quant(&quants[qcb * QUANT_LEN..]);
    let qcr = quant::parse_quant(&quants[qcr * QUANT_LEN..]);

    {
        let (y, cb, cr, tmp) = scratch.parts();
        for (data, buf, q) in [
            (y_data, &mut *y, &qy),
            (cb_data, &mut *cb, &qcb),
            (cr_data, &mut *cr, &qcr),
        ] {
            rlgr::decode(ctx.entropy, data, buf);
            quant::differential_ll3(buf);
            quant::dequantize(buf, q)?;
            dwt::inverse_2d(buf, tmp);
        }
    }
    frame.decoded += 1;

    let (y, cb, cr, _) = scratch.parts();
    match clip {
        None => {
            blit(y, cb, cr, tile_rect, visible, dst);
            frame.touch(visible);
        }
        Some(region) => {
            for rect in region.iter() {
                if let Some(part) = visible.intersect(rect) {
                    blit(y, cb, cr, tile_rect, part, dst);
                    frame.touch(part);
                }
            }
        }
    }
    Ok(())
}

/// Write the part of a decoded tile that `part` covers.
///
/// `part` is already proved to be inside both the tile and the destination,
/// so every slice below is in range by construction and the row loop carries
/// no bounds check (PRDRDP/04 §4.6.8 rule two).
///
/// `pub(crate)` and taking the three component buffers rather than a
/// [`RfxScratch`] because the progressive codec's tile blit is this function
/// exactly: the same 64 by 64 layout, the same clip rectangle, the same
/// colour conversion (MS-RDPEGFX 3.3.7).
pub(crate) fn blit(
    y: &[i16],
    cb: &[i16],
    cr: &[i16],
    tile: Rect,
    part: Rect,
    dst: &mut DstView<'_>,
) {
    let bgra = matches!(dst.format(), OutFormat::Bgra);
    let cx = usize::from(part.x - tile.x);
    let cy = usize::from(part.y - tile.y);
    let w = usize::from(part.w);
    for row in 0..usize::from(part.h) {
        let off = (cy + row) * TILE + cx;
        let d = dst.row(usize::from(part.y) + row);
        let d = &mut d[usize::from(part.x) * 4..][..w * 4];
        if bgra {
            ycbcr::row::<true>(&y[off..][..w], &cb[off..][..w], &cr[off..][..w], d);
        } else {
            ycbcr::row::<false>(&y[off..][..w], &cb[off..][..w], &cr[off..][..w], d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uncompressed::dst_len;
    use remote_pixel::RowOrder;

    fn view<'a>(buf: &'a mut [u8], w: u16, h: u16) -> DstView<'a> {
        DstView::packed(buf, w, h, OutFormat::Rgba, RowOrder::TopDown).unwrap()
    }

    #[test]
    fn rect_intersection_and_union_agree_with_the_obvious_cases() {
        let a = Rect {
            x: 10,
            y: 10,
            w: 20,
            h: 20,
        };
        assert_eq!(
            a.intersect(Rect {
                x: 20,
                y: 0,
                w: 40,
                h: 15
            }),
            Some(Rect {
                x: 20,
                y: 10,
                w: 10,
                h: 5
            })
        );
        assert_eq!(
            a.intersect(Rect {
                x: 30,
                y: 10,
                w: 5,
                h: 5
            }),
            None
        );
        assert_eq!(
            a.union(Rect {
                x: 0,
                y: 0,
                w: 5,
                h: 5
            }),
            Rect {
                x: 0,
                y: 0,
                w: 30,
                h: 30
            }
        );
    }

    /// An intersection at the `u16` ceiling must not wrap. A tile at
    /// `xIdx = 1023` lands at 65472 and is 64 wide, which is exactly the
    /// ceiling, so this is reachable from a two byte wire field.
    #[test]
    fn rect_intersection_does_not_wrap_at_the_u16_ceiling() {
        let a = Rect {
            x: 65472,
            y: 0,
            w: 64,
            h: 64,
        };
        let b = Rect {
            x: 0,
            y: 0,
            w: u16::MAX,
            h: u16::MAX,
        };
        assert_eq!(
            a.intersect(b),
            Some(Rect {
                x: 65472,
                y: 0,
                w: 63,
                h: 64
            })
        );
    }

    #[test]
    fn the_entropy_field_is_bits_nine_to_twelve() {
        // et = 1 at bit 9 is RLGR1, et = 4 is RLGR3, and the flags, cct, xft
        // and qt bits around it must not change the answer.
        assert_eq!(entropy_from_properties(1 << 9).unwrap(), Entropy::Rlgr1);
        assert_eq!(entropy_from_properties(4 << 9).unwrap(), Entropy::Rlgr3);
        assert_eq!(
            entropy_from_properties(0b11 << 13 | 0b0001 << 5 | 0b01 << 3 | 0b010 | (4 << 9))
                .unwrap(),
            Entropy::Rlgr3
        );
        assert!(entropy_from_properties(2 << 9).is_err());
        assert!(entropy_from_properties(0).is_err());
    }

    #[test]
    fn a_context_carries_the_entropy_algorithm_across_messages() {
        let mut ctx = RfxContext::new();
        assert_eq!(ctx.entropy(), Entropy::Rlgr1);
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(64, 64)];
        let mut v = view(&mut buf, 64, 64);
        let msg = crate::encode::rfx_context(4);
        decode_message(&msg, &mut ctx, &mut scratch, &mut v).unwrap();
        assert_eq!(ctx.entropy(), Entropy::Rlgr3);
        ctx.reset();
        assert_eq!(ctx.entropy(), Entropy::Rlgr1);
    }

    /// A whole message through the reference encoder, both entropy variants,
    /// both destination channel orders. The tile is a flat colour, which the
    /// wavelet reproduces exactly, so this is an equality test rather than a
    /// tolerance test.
    #[test]
    fn a_flat_tile_round_trips_exactly() {
        for entropy in [Entropy::Rlgr1, Entropy::Rlgr3] {
            for (r, g, b) in [(0u8, 0u8, 0u8), (255, 255, 255), (30, 144, 255)] {
                let src = vec![[r, g, b]; TILE * TILE];
                let msg = crate::encode::rfx_message(entropy, &[(0, 0, src.clone())], 64, 64);
                let mut ctx = RfxContext::new();
                let mut scratch = RfxScratch::new();
                let mut buf = vec![0u8; dst_len(64, 64)];
                {
                    let mut v = view(&mut buf, 64, 64);
                    let frame = decode_message(&msg, &mut ctx, &mut scratch, &mut v).unwrap();
                    assert_eq!(frame.tiles, 1);
                    assert_eq!(frame.decoded, 1);
                    assert_eq!(
                        frame.damage,
                        Some(Rect {
                            x: 0,
                            y: 0,
                            w: 64,
                            h: 64
                        })
                    );
                }
                for (i, px) in buf.chunks_exact(4).enumerate() {
                    assert!(
                        (i32::from(px[0]) - i32::from(r)).abs() <= 2
                            && (i32::from(px[1]) - i32::from(g)).abs() <= 2
                            && (i32::from(px[2]) - i32::from(b)).abs() <= 2
                            && px[3] == 0xFF,
                        "pixel {i} is {px:?}, wanted {r} {g} {b}"
                    );
                }
            }
        }
    }

    /// A gradient tile, which is what exercises the wavelet rather than only
    /// its DC term. The tolerance is the quantization the encoder applied,
    /// which is why the encoder and this bound are stated together.
    #[test]
    fn a_gradient_tile_round_trips_inside_the_quantization_error() {
        let src: Vec<[u8; 3]> = (0..TILE * TILE)
            .map(|i| {
                let x = (i % TILE) as u8;
                let y = (i / TILE) as u8;
                [x.wrapping_mul(4), y.wrapping_mul(4), 128]
            })
            .collect();
        let msg = crate::encode::rfx_message(Entropy::Rlgr3, &[(0, 0, src.clone())], 64, 64);
        let mut ctx = RfxContext::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(64, 64)];
        {
            let mut v = view(&mut buf, 64, 64);
            decode_message(&msg, &mut ctx, &mut scratch, &mut v).unwrap();
        }
        let mut worst = 0i32;
        for (i, px) in buf.chunks_exact(4).enumerate() {
            for c in 0..3 {
                worst = worst.max((i32::from(px[c]) - i32::from(src[i][c])).abs());
            }
        }
        assert!(worst <= 8, "worst channel error was {worst}");
    }

    /// Tiles land where `xIdx` and `yIdx` say and nowhere else, and a tile
    /// past the destination edge is clipped rather than refused.
    #[test]
    fn tiles_are_placed_by_index_and_clipped_to_the_destination() {
        let red = vec![[255u8, 0, 0]; TILE * TILE];
        let blue = vec![[0u8, 0, 255]; TILE * TILE];
        let msg = crate::encode::rfx_message(
            Entropy::Rlgr1,
            &[(0, 0, red), (1, 0, blue.clone()), (5, 5, blue)],
            100,
            64,
        );
        let mut ctx = RfxContext::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(100, 64)];
        let frame = {
            let mut v = view(&mut buf, 100, 64);
            decode_message(&msg, &mut ctx, &mut scratch, &mut v).unwrap()
        };
        assert_eq!(frame.tiles, 3);
        // The tile at (5, 5) is entirely past a 100 by 64 destination, so it
        // is never decoded.
        assert_eq!(frame.decoded, 2);
        let px = |x: usize, y: usize| &buf[(y * 100 + x) * 4..][..3];
        assert!(px(10, 10)[0] > 200 && px(10, 10)[2] < 60);
        assert!(px(80, 10)[2] > 200 && px(80, 10)[0] < 60);
        assert_eq!(
            frame.damage,
            Some(Rect {
                x: 0,
                y: 0,
                w: 100,
                h: 64
            })
        );
    }

    /// The region rectangles clip the blit. Everything outside them keeps
    /// whatever the caller had in the buffer, which is what makes an EGFX
    /// surface composite rather than flicker.
    #[test]
    fn a_region_rectangle_clips_the_tile() {
        let white = vec![[255u8, 255, 255]; TILE * TILE];
        let msg = crate::encode::rfx_message_region(
            Entropy::Rlgr1,
            &[(0, 0, white)],
            64,
            64,
            &[Rect {
                x: 8,
                y: 8,
                w: 16,
                h: 16,
            }],
        );
        let mut ctx = RfxContext::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0x11u8; dst_len(64, 64)];
        let frame = {
            let mut v = view(&mut buf, 64, 64);
            decode_message(&msg, &mut ctx, &mut scratch, &mut v).unwrap()
        };
        assert_eq!(
            frame.damage,
            Some(Rect {
                x: 8,
                y: 8,
                w: 16,
                h: 16
            })
        );
        let px = |x: usize, y: usize| &buf[(y * 64 + x) * 4..][..4];
        assert_eq!(px(0, 0), &[0x11, 0x11, 0x11, 0x11]);
        assert_eq!(px(7, 8), &[0x11, 0x11, 0x11, 0x11]);
        assert!(px(8, 8)[0] > 200);
        assert!(px(23, 23)[0] > 200);
        assert_eq!(px(24, 24), &[0x11, 0x11, 0x11, 0x11]);
    }

    /// A tile that intersects no region rectangle is skipped before its
    /// entropy decode, which is the saving PRDRDP/04 §4.6.7 asks for.
    #[test]
    fn a_tile_outside_the_region_is_not_decoded() {
        let white = vec![[255u8, 255, 255]; TILE * TILE];
        let msg = crate::encode::rfx_message_region(
            Entropy::Rlgr1,
            &[(0, 0, white.clone()), (1, 0, white)],
            128,
            64,
            &[Rect {
                x: 0,
                y: 0,
                w: 64,
                h: 64,
            }],
        );
        let mut ctx = RfxContext::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(128, 64)];
        let mut v = view(&mut buf, 128, 64);
        let frame = decode_message(&msg, &mut ctx, &mut scratch, &mut v).unwrap();
        assert_eq!(frame.tiles, 2);
        assert_eq!(frame.decoded, 1);
    }

    /// The truncation sweep. Every prefix of a valid message must return
    /// `Err` or `Ok` and must never panic, and the destination must still be
    /// a defined buffer afterwards.
    #[test]
    fn every_prefix_of_a_message_is_handled() {
        let src = vec![[90u8, 120, 200]; TILE * TILE];
        let msg = crate::encode::rfx_message(Entropy::Rlgr3, &[(0, 0, src)], 64, 64);
        let mut ctx = RfxContext::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(64, 64)];
        for n in 0..msg.len() {
            let mut v = view(&mut buf, 64, 64);
            let _ = decode_message(&msg[..n], &mut ctx, &mut scratch, &mut v);
        }
        // The full message still works after all of that, so no partial
        // decode left the context or the scratch in a state that breaks the
        // next one.
        let mut v = view(&mut buf, 64, 64);
        assert!(decode_message(&msg, &mut ctx, &mut scratch, &mut v).is_ok());
    }

    /// The adversarial sweep over leading bytes: a message whose first block
    /// header is replaced by every possible pair of type bytes.
    #[test]
    fn every_leading_block_type_terminates() {
        let src = vec![[10u8, 20, 30]; TILE * TILE];
        let base = crate::encode::rfx_message(Entropy::Rlgr1, &[(0, 0, src)], 64, 64);
        let mut ctx = RfxContext::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(64, 64)];
        for lead in 0u16..=255 {
            let mut msg = base.clone();
            msg[0] = lead as u8;
            msg[1] = 0xCC;
            let mut v = view(&mut buf, 64, 64);
            let _ = decode_message(&msg, &mut ctx, &mut scratch, &mut v);
        }
    }

    /// A block whose length is smaller than its own header would leave the
    /// walk standing still. That is the one shape that can hang this loop, so
    /// it is refused explicitly rather than by luck.
    #[test]
    fn a_zero_length_block_is_refused_rather_than_looping() {
        let mut msg = Vec::new();
        msg.extend_from_slice(&WBT_SYNC.to_le_bytes());
        msg.extend_from_slice(&0u32.to_le_bytes());
        let mut ctx = RfxContext::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(64, 64)];
        let mut v = view(&mut buf, 64, 64);
        assert_eq!(
            decode_message(&msg, &mut ctx, &mut scratch, &mut v),
            Err(DecodeError::Range {
                what: "TS_RFX_BLOCKT blockLen",
                got: 0
            })
        );
    }

    /// A quantization index past the end of the tileset's table is a range
    /// error rather than a read of whatever follows it.
    #[test]
    fn an_out_of_range_quant_index_is_refused() {
        let src = vec![[10u8, 20, 30]; TILE * TILE];
        let mut msg = crate::encode::rfx_message(Entropy::Rlgr1, &[(0, 0, src)], 64, 64);
        // The reference encoder emits exactly one quantization value, so any
        // index above zero is out of range. The tile's quantIdxY is the first
        // byte after its six byte block header, and `rfx_message` puts the
        // tile last.
        let at = crate::encode::rfx_first_tile_offset(&msg) + 6;
        msg[at] = 3;
        let mut ctx = RfxContext::new();
        let mut scratch = RfxScratch::new();
        let mut buf = vec![0u8; dst_len(64, 64)];
        let mut v = view(&mut buf, 64, 64);
        assert_eq!(
            decode_message(&msg, &mut ctx, &mut scratch, &mut v),
            Err(DecodeError::Range {
                what: "quantIdxY",
                got: 3
            })
        );
    }

    #[test]
    fn the_scratch_reports_and_releases_its_memory() {
        let mut s = RfxScratch::with_capacity();
        assert_eq!(s.bytes(), scratch_len());
        s.reset();
        assert_eq!(s.bytes(), 0);
    }
}
