//! Progressive RemoteFX (MS-RDPEGFX 2.2.4.2, decode rules 3.3.7).
//!
//! `RDPGFX_CODECID_CAPROGRESSIVE` (0x0009). A second, larger RemoteFX decoder
//! with its own persistent tile store: the first pass carries a coarse tile
//! and later passes refine it in place, so a tile's coefficients survive
//! between frames and the store is the codec's whole memory budget
//! ([`state`], PRDRDP/04 §4.9.4).
//!
//! ## Why this is compiled by default
//!
//! It used to be behind an off by default cargo feature, on the argument that
//! a phase 1 binary does not need it and the fuzzer would have to cover it
//! anyway. `docs/RDP_SPEC_NOTES.md` §1.6 overtook that argument. Progressive
//! is available from EGFX capability version 8, which is what we advertise,
//! and nothing declines it: `RDPGFX_CAPS_FLAG_AVC_DISABLED` exists only from
//! version 10 and there is no progressive equivalent at any version. So a
//! server may legitimately send this codec id and, without a decoder, the
//! session stops with a named refusal. A feature that is off cannot save a
//! session. The `progressive` feature still exists, so
//! `--no-default-features` gives back a binary without it, but it is on.
//!
//! ## What is shared with `remotefx` and what is not
//!
//! Shared, as calls rather than copies: the RLGR1 entropy decode
//! ([`crate::remotefx::rlgr::decode`]) and its bit reader, the run mode
//! adaptation constants, `RFX_COMPONENT_CODEC_QUANT` parsing
//! ([`crate::remotefx::quant::parse_quant`]), the LL3 differential decode and
//! the inverse quantization in the plain layout, the **whole** inverse
//! wavelet in the plain layout ([`crate::remotefx::dwt::inverse_2d`]), the
//! clip region and rectangle arithmetic, the tile blit, the colour transform
//! ([`crate::remotefx::ycbcr`]) and the scratch buffers
//! ([`crate::remotefx::RfxScratch`], which is the same four buffers).
//!
//! Not shared, because they are genuinely different:
//!
//! * The block set. Progressive reuses the `0xCCCx` numbers with **different
//!   meanings**: `0xCCC1` is `WBT_FRAME_BEGIN` here and `WBT_CODEC_VERSIONS`
//!   in MS-RDPRFX, `0xCCC4` is `WBT_REGION` here and `WBT_FRAME_BEGIN` there.
//!   Reading the two documents side by side is a trap and it is why this
//!   walk is a separate function rather than a mode flag on the RemoteFX one.
//! * The subband layout, when `RFX_DWT_REDUCE_EXTRAPOLATE` is set. Ten bands
//!   of different sizes, from a wavelet whose halves are 33 and 31 rather
//!   than 32 and 32 ([`bands`], [`dwt`]).
//! * The SRL layer, which has no RemoteFX counterpart at all ([`srl`]).
//! * The per tile state and the diff across passes ([`state`]).
//! * RLGR3. Progressive is RLGR1 only, so the `properties` word and the
//!   entropy selection of `TS_RFX_CONTEXT` have no equivalent here.
//!
//! ## Section numbering
//!
//! The stub this replaced cited MS-RDPEGFX 3.3.7 for the decode rules and
//! PRDRDP/04 §4.9 cites 3.3.8.2 for the same procedure. Both numbers appear
//! in the tree and neither could be checked against the document, so this
//! module says 3.3.7 throughout and the disagreement is recorded rather than
//! silently resolved.

pub mod bands;
pub mod dwt;
pub mod srl;
pub mod state;

use remote_pixel::DstView;

use crate::remotefx::quant::{parse_quant, COEFS};
use crate::remotefx::{blit, rlgr, Entropy, Rect, Region, RfxScratch, TILE};
use crate::{DecodeError, Reader};

pub use bands::Layout;
pub use state::{ProgressiveState, DEFAULT_MAX_BYTES, TILE_BYTES};

// Block types, MS-RDPEGFX 2.2.4.2.1. These are the same sixteen bit values
// MS-RDPRFX 2.2.2.1.1 uses and four of them mean something else there.
const WBT_SYNC: u16 = 0xCCC0;
const WBT_FRAME_BEGIN: u16 = 0xCCC1;
const WBT_FRAME_END: u16 = 0xCCC2;
const WBT_CONTEXT: u16 = 0xCCC3;
const WBT_REGION: u16 = 0xCCC4;
const WBT_TILE_SIMPLE: u16 = 0xCCC5;
const WBT_TILE_FIRST: u16 = 0xCCC6;
const WBT_TILE_UPGRADE: u16 = 0xCCC7;

/// A block is a `u16` type and a `u32` length, and the length counts itself
/// (MS-RDPEGFX 2.2.4.2.1).
const BLOCK_HEADER: usize = 6;

/// `RFX_PROGRESSIVE_SYNC.magic` (MS-RDPEGFX 2.2.4.2.1.1). The same value
/// MS-RDPRFX 2.2.2.2.1 uses.
const SYNC_MAGIC: u32 = 0xCACC_ACCA;

/// `RFX_PROGRESSIVE_CONTEXT.flags`, bit zero: use the extrapolated wavelet
/// and therefore the second subband layout (MS-RDPEGFX 2.2.4.2.1.4).
const RFX_DWT_REDUCE_EXTRAPOLATE: u8 = 0x01;

/// `RFX_PROGRESSIVE_TILE_SIMPLE.flags` and `..._FIRST.flags`, bit zero: the
/// coefficients in this block are a difference against what the tile already
/// holds rather than a replacement (MS-RDPEGFX 2.2.4.2.1.6.1).
const RFX_TILE_DIFFERENCE: u8 = 0x01;

/// Bytes of one `RFX_COMPONENT_CODEC_QUANT` (MS-RDPEGFX 2.2.4.2.1.5.1),
/// which is byte for byte a `TS_RFX_CODEC_QUANT`.
const QUANT_LEN: usize = 5;

/// Bytes of one `RFX_PROGRESSIVE_CODEC_QUANT` (MS-RDPEGFX 2.2.4.2.1.5.2): a
/// quality label and three `RFX_COMPONENT_CODEC_QUANT`.
const PROG_QUANT_LEN: usize = 1 + 3 * QUANT_LEN;

/// Bytes of an `RFX_PROGRESSIVE_TILE_SIMPLE` before its four blobs.
const SIMPLE_HEADER: usize = 3 + 4 + 1 + 8;
/// Bytes of an `RFX_PROGRESSIVE_TILE_FIRST` before its four blobs: a simple
/// tile plus the `quality` index.
const FIRST_HEADER: usize = SIMPLE_HEADER + 1;
/// Bytes of an `RFX_PROGRESSIVE_TILE_UPGRADE` before its six blobs.
const UPGRADE_HEADER: usize = 3 + 4 + 1 + 12;

/// What a message turned out to contain, for the caller's damage tracking and
/// frame acknowledgement (PRDRDP/04 §3.6).
///
/// The same shape as [`crate::remotefx::RfxFrame`] with one field added: a
/// progressive frame is worth reporting per pass kind, because a session that
/// only ever receives first passes is a session whose upgrades are being
/// dropped somewhere and it looks like a soft picture rather than an error.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgressiveFrame {
    /// `RFX_PROGRESSIVE_FRAME_BEGIN.frameIndex`, when the message carried one.
    pub frame_idx: Option<u32>,
    /// Tiles the message declared, across every region.
    pub tiles: u32,
    /// Tiles that were decoded into the store.
    pub decoded: u32,
    /// Of those, the ones that were `WBT_TILE_UPGRADE`.
    pub upgrades: u32,
    /// The bounding box of everything written, in destination coordinates.
    pub damage: Option<Rect>,
}

impl ProgressiveFrame {
    fn touch(&mut self, r: Rect) {
        self.damage = Some(match self.damage {
            Some(d) => d.union(r),
            None => r,
        });
    }
}

/// Bytes of scratch a decode needs, so a caller can size a pool without
/// decoding first. The same four buffers RemoteFX uses.
pub fn scratch_len() -> usize {
    crate::remotefx::scratch_len()
}

/// Decode one progressive RemoteFX message into the caller's destination.
///
/// `state` is the per surface tile store and it must be the same one across
/// frames: that is the whole point of the codec, and a caller that builds a
/// fresh one per PDU gets a picture that never sharpens rather than an error.
/// `scratch` is pooled the way every other decoder in this crate pools its
/// working buffers and holds nothing between calls.
///
/// Tiles are placed at `(xIdx * 64, yIdx * 64)` relative to the destination
/// origin and are written only where they intersect the region's rectangles
/// and the destination (MS-RDPEGFX 3.3.7).
///
/// Every error is a [`DecodeError`]. No input makes this panic, loop without
/// consuming, or write outside `dst`.
pub fn decode_message(
    src: &[u8],
    state: &mut ProgressiveState,
    scratch: &mut RfxScratch,
    dst: &mut DstView<'_>,
) -> Result<ProgressiveFrame, DecodeError> {
    scratch.ensure();
    state.fit(dst.width(), dst.height());
    let mut frame = ProgressiveFrame::default();

    let mut r = Reader::new(src, "progressive message");
    while !r.is_empty() {
        let block_type = r.u16_le()?;
        let block_len = r.u32_le()? as usize;
        // A block shorter than its own header would let the walk stand still,
        // which is the loop forever case PRDRDP/04 §4.1 rule five names.
        if block_len < BLOCK_HEADER {
            return Err(DecodeError::Range {
                what: "RFX_PROGRESSIVE_BLOCK blockLen",
                got: block_len as u32,
            });
        }
        let body = r.take(block_len - BLOCK_HEADER)?;
        let mut b = Reader::new(body, "progressive block");

        match block_type {
            WBT_SYNC => {
                let magic = b.u32_le()?;
                if magic != SYNC_MAGIC {
                    return Err(DecodeError::Range {
                        what: "RFX_PROGRESSIVE_SYNC magic",
                        got: magic,
                    });
                }
                let _version = b.u16_le()?;
                state.set_seen_sync();
            }
            WBT_FRAME_BEGIN => {
                frame.frame_idx = Some(b.u32_le()?);
                let _region_count = b.u16_le()?;
            }
            WBT_FRAME_END => {}
            WBT_CONTEXT => {
                let _ctx_id = b.u8()?;
                let tile_size = b.u16_le()?;
                if usize::from(tile_size) != TILE {
                    return Err(DecodeError::Range {
                        what: "RFX_PROGRESSIVE_CONTEXT tileSize",
                        got: u32::from(tile_size),
                    });
                }
                let flags = b.u8()?;
                let layout = if flags & RFX_DWT_REDUCE_EXTRAPOLATE != 0 {
                    Layout::Extrapolate
                } else {
                    Layout::Plain
                };
                state.set_layout(layout);
            }
            WBT_REGION => decode_region(&mut b, state, scratch, dst, &mut frame)?,
            // A block type we do not know is skipped rather than refused. Its
            // `blockLen` already told us how long it is, so skipping cannot
            // desynchronise the walk. Tile blocks are not reachable here:
            // MS-RDPEGFX 2.2.4.2.1.5 puts them inside a region's
            // `tilesDataSize`, never at the top level.
            _ => {}
        }
    }
    Ok(frame)
}

/// `RFX_PROGRESSIVE_REGION` (MS-RDPEGFX 2.2.4.2.1.5) and the tile loop.
fn decode_region(
    b: &mut Reader<'_>,
    state: &mut ProgressiveState,
    scratch: &mut RfxScratch,
    dst: &mut DstView<'_>,
    frame: &mut ProgressiveFrame,
) -> Result<(), DecodeError> {
    let tile_size = b.u8()?;
    if usize::from(tile_size) != TILE {
        return Err(DecodeError::Range {
            what: "RFX_PROGRESSIVE_REGION tileSize",
            got: u32::from(tile_size),
        });
    }
    let num_rects = usize::from(b.u16_le()?);
    let num_quant = usize::from(b.u8()?);
    let num_prog_quant = usize::from(b.u8()?);
    // `flags` here is not the wavelet selector. That one is on
    // `RFX_PROGRESSIVE_CONTEXT` (MS-RDPEGFX 2.2.4.2.1.4) and taking it from
    // the region instead would change the subband layout halfway through a
    // frame, which nothing in the store could survive.
    let _flags = b.u8()?;
    let num_tiles = u32::from(b.u16_le()?);
    let tiles_data_size = b.u32_le()? as usize;

    // Everything is taken before anything is decoded, so a region that claims
    // more than it carries is a truncation here rather than a short read
    // three stages later.
    let rects = b.take(num_rects * 8)?;
    let quants = b.take(num_quant * QUANT_LEN)?;
    let prog_quants = b.take(num_prog_quant * PROG_QUANT_LEN)?;
    let tiles = b.take(tiles_data_size)?;

    frame.tiles = frame.tiles.saturating_add(num_tiles);

    // BEHAVIOUR: a region with zero rectangles is taken as "the whole
    // destination" rather than as "draw nothing", which is the reading
    // `remotefx::decode_message` already takes and for the same reason: the
    // failure modes are asymmetric, and a black screen is worse than an
    // over generous repaint.
    let region = Region::new(rects);
    let clip = if region.count() > 0 {
        Some(region)
    } else {
        None
    };

    let mut t = Reader::new(tiles, "progressive tile");
    for _ in 0..num_tiles {
        if t.is_empty() {
            // `numTiles` outran `tilesDataSize`. Stopping is the tolerant
            // reading and it is safe: everything already decoded is correct
            // and the store is consistent.
            break;
        }
        decode_tile(
            &mut t,
            &Tables {
                quants,
                num_quant,
                prog_quants,
                num_prog_quant,
            },
            state,
            scratch,
            clip,
            dst,
            frame,
        )?;
    }
    Ok(())
}

/// The two quantization tables a region carries, as borrows into the payload.
struct Tables<'a> {
    quants: &'a [u8],
    num_quant: usize,
    prog_quants: &'a [u8],
    num_prog_quant: usize,
}

impl Tables<'_> {
    /// One `RFX_COMPONENT_CODEC_QUANT` by index.
    fn quant(&self, idx: usize, what: &'static str) -> Result<[u8; 10], DecodeError> {
        if idx >= self.num_quant {
            return Err(DecodeError::Range {
                what,
                got: idx as u32,
            });
        }
        Ok(parse_quant(&self.quants[idx * QUANT_LEN..]))
    }

    /// The three progressive quantization values a `quality` index selects.
    ///
    /// `RFX_PROGRESSIVE_CODEC_QUANT` is sixteen bytes: a `quality` label and
    /// then the Y, Cb and Cr values in that order. The label is not read; the
    /// tile's own `quality` field is the index, and a table whose label
    /// disagrees with its position would be a server contradicting itself.
    fn prog(&self, idx: usize) -> Result<[[u8; 10]; 3], DecodeError> {
        if idx >= self.num_prog_quant {
            return Err(DecodeError::Range {
                what: "RFX_PROGRESSIVE_TILE quality",
                got: idx as u32,
            });
        }
        let base = idx * PROG_QUANT_LEN + 1;
        Ok([
            parse_quant(&self.prog_quants[base..]),
            parse_quant(&self.prog_quants[base + QUANT_LEN..]),
            parse_quant(&self.prog_quants[base + 2 * QUANT_LEN..]),
        ])
    }
}

/// Where a tile goes and how much of it is visible.
struct Placement {
    x_idx: usize,
    y_idx: usize,
    tile: Rect,
    visible: Rect,
}

/// One tile block of any of the three kinds (MS-RDPEGFX 2.2.4.2.1.6).
#[allow(clippy::too_many_arguments)]
fn decode_tile(
    t: &mut Reader<'_>,
    tables: &Tables<'_>,
    state: &mut ProgressiveState,
    scratch: &mut RfxScratch,
    clip: Option<Region<'_>>,
    dst: &mut DstView<'_>,
    frame: &mut ProgressiveFrame,
) -> Result<(), DecodeError> {
    let block_type = t.u16_le()?;
    let block_len = t.u32_le()? as usize;
    let header = match block_type {
        WBT_TILE_SIMPLE => SIMPLE_HEADER,
        WBT_TILE_FIRST => FIRST_HEADER,
        WBT_TILE_UPGRADE => UPGRADE_HEADER,
        other => {
            return Err(DecodeError::Range {
                what: "RFX_PROGRESSIVE_TILE blockType",
                got: u32::from(other),
            })
        }
    };
    if block_len < BLOCK_HEADER + header {
        return Err(DecodeError::Range {
            what: "RFX_PROGRESSIVE_TILE blockLen",
            got: block_len as u32,
        });
    }
    let body = t.take(block_len - BLOCK_HEADER)?;
    let mut b = Reader::new(body, "progressive tile body");

    let qy = usize::from(b.u8()?);
    let qcb = usize::from(b.u8()?);
    let qcr = usize::from(b.u8()?);
    let x_idx = usize::from(b.u16_le()?);
    let y_idx = usize::from(b.u16_le()?);

    let quant = [
        tables.quant(qy, "quantIdxY")?,
        tables.quant(qcb, "quantIdxCb")?,
        tables.quant(qcr, "quantIdxCr")?,
    ];

    let Some(place) = place(x_idx, y_idx, dst)? else {
        // Entirely outside the destination. It can never be drawn and the
        // store has no slot for it, so it is skipped before its entropy
        // decode: the saving PRDRDP/04 §4.6.7 asks for, and the only case
        // where progressive can take it.
        return Ok(());
    };

    // Whether the scratch already holds exactly what the store now holds, so
    // [`draw`] can run the wavelet where the coefficients already are. It is
    // true for the common pass and false for the two that accumulate.
    let in_scratch = match block_type {
        WBT_TILE_UPGRADE => {
            let quality = usize::from(b.u8()?);
            let prog = tables.prog(quality)?;
            let mut lens = [0usize; 6];
            for slot in lens.iter_mut() {
                *slot = usize::from(b.u16_le()?);
            }
            let mut blobs: [(&[u8], &[u8]); 3] = [(&[], &[]); 3];
            for (c, slot) in blobs.iter_mut().enumerate() {
                let srl_data = b.take(lens[c * 2])?;
                let raw_data = b.take(lens[c * 2 + 1])?;
                *slot = (srl_data, raw_data);
            }

            let layout = state.layout();
            let tile = state.existing(place.x_idx, place.y_idx)?;
            if tile.layout() != layout {
                // The context changed wavelet under a tile that is mid
                // refinement. Its coefficients mean nothing in the new
                // layout, so the caller is told to repaint rather than shown
                // a tile assembled from two band tables.
                return Err(DecodeError::StateLost(
                    "progressive wavelet changed mid tile",
                ));
            }
            for c in 0..3 {
                let new = bands::bit_positions(&quant[c], &prog[c]);
                if new.contains(&0) {
                    return Err(DecodeError::Range {
                        what: "RFX_PROGRESSIVE bit position",
                        got: 0,
                    });
                }
                let old = *tile.bit_pos(c);
                srl::upgrade_component(
                    tile.component(c),
                    layout,
                    &old,
                    &new,
                    blobs[c].0,
                    blobs[c].1,
                );
                tile.set_bit_pos(c, new);
            }
            frame.upgrades += 1;
            false
        }
        _ => {
            let flags = b.u8()?;
            let prog = if block_type == WBT_TILE_FIRST {
                let quality = usize::from(b.u8()?);
                tables.prog(quality)?
            } else {
                // A `WBT_TILE_SIMPLE` carries the whole tile in one pass, so
                // there is no progressive quantization on top of the
                // component one. That is what makes it byte for byte the same
                // picture a RemoteFX tile of the same content produces, and
                // it is the property the multi pass test converges on.
                [[0u8; 10]; 3]
            };
            let mut lens = [0usize; 4];
            for slot in lens.iter_mut() {
                *slot = usize::from(b.u16_le()?);
            }
            let mut blobs: [&[u8]; 3] = [&[]; 3];
            for (c, slot) in blobs.iter_mut().enumerate() {
                *slot = b.take(lens[c])?;
            }
            // `tailData`. MS-RDPEGFX 2.2.4.2.1.6.1 gives it a length and this
            // decoder does not read it: nothing in the three component
            // pipeline consumes it and no reading of it could be checked. It
            // is taken so a tile that declares one is a truncation rather
            // than a silently short block.
            let _tail = b.take(lens[3])?;

            let difference = flags & RFX_TILE_DIFFERENCE != 0;
            let layout = state.layout();

            let (y, cb, cr, _) = scratch.parts();
            let comps: [&mut [i16]; 3] = [y, cb, cr];
            let mut pos = [[0u8; 10]; 3];
            for (c, buf) in comps.into_iter().enumerate() {
                pos[c] = bands::bit_positions(&quant[c], &prog[c]);
                // Progressive is RLGR1 only (MS-RDPEGFX 3.3.7). There is no
                // `properties` word here and no way for a stream to ask for
                // RLGR3, which is one fewer thing than RemoteFX carries.
                rlgr::decode(Entropy::Rlgr1, blobs[c], buf);
                bands::differential_ll3(buf, layout);
                bands::dequantize(buf, layout, &pos[c])?;
            }

            let tile = state.entry(place.x_idx, place.y_idx, layout)?;
            if difference {
                if tile.layout() != layout {
                    // The wavelet moved under a tile that is asking to be
                    // added to, so the difference is added to zeros instead.
                    tile.restart(layout);
                }
            } else {
                // A replacing pass writes every coefficient in the loop
                // below, so `restart`'s zero fill would be 24 KiB stored and
                // then stored over. `adopt` takes the layout and the bit
                // position reset and skips the fill.
                tile.adopt(layout);
            }
            // `RFX_TILE_DIFFERENCE` on a tile that has never been sent is not
            // an error the way an upgrade on one is. A freshly allocated tile
            // is all zeros, so adding to it and replacing it are the same
            // operation, and refusing would drop a frame over a distinction
            // with no consequence.
            let (ty, tcb, tcr) = tile.parts();
            let (sy, scb, scr, _) = scratch.parts();
            for (store, fresh) in [(ty, &*sy), (tcb, &*scb), (tcr, &*scr)] {
                if difference {
                    // `RFX_TILE_DIFFERENCE`: the coefficients are a delta
                    // against what the tile holds. It is applied after
                    // dequantization, in the units the store keeps, because
                    // the previous pass may have used a different
                    // quantization and adding raw entropy decoded values
                    // across two tables would mean nothing.
                    for (s, &f) in store.iter_mut().zip(fresh.iter()) {
                        *s = s.saturating_add(f);
                    }
                } else {
                    store.copy_from_slice(fresh);
                }
            }
            for (c, p) in pos.into_iter().enumerate() {
                tile.set_bit_pos(c, p);
            }
            !difference
        }
    };

    frame.decoded += 1;
    draw(state, scratch, &place, in_scratch, clip, dst, frame);
    Ok(())
}

/// Where a tile index lands, or `None` when it lands nowhere visible.
fn place(x_idx: usize, y_idx: usize, dst: &DstView<'_>) -> Result<Option<Placement>, DecodeError> {
    let tx = x_idx.saturating_mul(TILE);
    let ty = y_idx.saturating_mul(TILE);
    if tx > usize::from(u16::MAX) || ty > usize::from(u16::MAX) {
        return Err(DecodeError::Range {
            what: "RFX_PROGRESSIVE_TILE index",
            got: (x_idx.max(y_idx)) as u32,
        });
    }
    let tile = Rect {
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
    Ok(tile.intersect(bounds).map(|visible| Placement {
        x_idx,
        y_idx,
        tile,
        visible,
    }))
}

/// Run the inverse wavelet over a copy of the tile's stored coefficients and
/// write the pixels.
///
/// The copy is not avoidable and it is the cost PRDRDP/04 §4.9's 250 MPix/s
/// target is lower than RemoteFX's 400 for: the store has to keep the
/// coefficients as they were before the transform, because the next upgrade
/// pass refines those and not the pixels.
///
/// **Clipping differs from RemoteFX here, deliberately.** A tile that lands
/// inside the destination but outside every region rectangle is still decoded
/// into the store, and only its blit is skipped. RemoteFX skips such a tile
/// entirely (PRDRDP/04 §4.6.7) and can, because it has no memory. Skipping it
/// here would leave the store one pass behind, and the next upgrade would
/// apply the wrong number of bits to coefficients that were never written.
#[allow(clippy::too_many_arguments)]
fn draw(
    state: &mut ProgressiveState,
    scratch: &mut RfxScratch,
    place: &Placement,
    in_scratch: bool,
    clip: Option<Region<'_>>,
    dst: &mut DstView<'_>,
    frame: &mut ProgressiveFrame,
) {
    let layout = state.layout();
    if in_scratch {
        // The pass that replaced the tile left the same coefficients in the
        // scratch on its way past, so the copy back is skipped and the
        // wavelet runs where they already are.
        //
        // This measured far larger than a 24 KiB copy has any right to: 35
        // percent off a whole `WBT_TILE_SIMPLE` frame at 1080p and 20 percent
        // off a first pass, against no change at all on the upgrade path,
        // which still has to copy. The reason is that the store is 12 MiB at
        // 1080p, so a tile read back out of it is a cold stream from memory
        // rather than a copy inside a cache, and skipping it takes both the
        // read and its write allocate off the frame. PRDRDP/04 §4.9.5 is
        // right that the tile state write is what makes progressive slower
        // than RemoteFX; what it does not say is that the read back costs
        // more than the write.
        let (sy, scb, scr, tmp) = scratch.parts();
        for work in [sy, scb, scr] {
            match layout {
                Layout::Plain => crate::remotefx::dwt::inverse_2d(work, tmp),
                Layout::Extrapolate => dwt::inverse_2d(work, tmp),
            }
        }
    } else {
        let Ok(tile) = state.existing(place.x_idx, place.y_idx) else {
            return;
        };
        let (ty, tcb, tcr) = tile.parts();
        let (sy, scb, scr, tmp) = scratch.parts();
        for (store, work) in [(&*ty, sy), (&*tcb, scb), (&*tcr, scr)] {
            work[..COEFS].copy_from_slice(&store[..COEFS]);
            match layout {
                Layout::Plain => crate::remotefx::dwt::inverse_2d(work, tmp),
                Layout::Extrapolate => dwt::inverse_2d(work, tmp),
            }
        }
    }

    let (y, cb, cr, _) = scratch.parts();
    match clip {
        None => {
            blit(y, cb, cr, place.tile, place.visible, dst);
            frame.touch(place.visible);
        }
        Some(region) => {
            for rect in region.iter() {
                if let Some(part) = place.visible.intersect(rect) {
                    blit(y, cb, cr, place.tile, part, dst);
                    frame.touch(part);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
