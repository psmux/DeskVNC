//! The legacy graphics path: bitmap updates and pointer updates into
//! [`remote_core`] events (PRDRDP/04 §2 and §6).
//!
//! `rdp-pdu` parses down to the first byte of a codec's bitstream and stops,
//! `rdp-codecs` decodes what is inside it, and this file is the join: it picks
//! the decoder from `bitsPerPixel` and the compression flag, sizes the
//! destination, and turns the result into a [`DecodedRect`].
//!
//! # The invariant this file exists to keep
//!
//! **A whole framebuffer never crosses a channel as one value** (AGENT_BRIEF
//! invariant 3.2). Every update leaves here as a list of dirty rectangles,
//! each carrying only its own pixels, and there is no framebuffer in this
//! crate at all: the renderer owns it and blits rectangles into it. That is
//! the same contract the RFB path keeps, which is why the shell and the
//! webview need no RDP specific code to draw an RDP session.
//!
//! # Row order, which is the detail everything else depends on
//!
//! A legacy `bitmapDataStream` is a Windows DIB body: rows are stored bottom
//! to top and each row is padded (PRDRDP/04 §2.3). The flip happens on the way
//! **out**, in [`DstView::row`], and never on the way in, because both the
//! interleaved RLE and planar decoders predict from the previously decoded
//! scanline and a decoder writing its rows in reverse would predict from the
//! wrong neighbour and produce a picture that looks almost right.

use rdp_codecs::{planar, rle, uncompressed, DstView, OutFormat, Palette, PixelFormat, RowOrder};
use rdp_pdu::update::{
    and_mask_len, and_mask_row_len, xor_mask_len, xor_mask_row_len, BitmapData, BitmapUpdate,
    ColorPointer, PaletteUpdate, PointerUpdate, COLOR_POINTER_BPP,
};
use remote_core::{CursorShape, DecodedRect, Rect, RectPayload, SessionEvent};

use crate::error::{RdpError, Result};

/// Bytes per pixel in everything this module emits.
const DST_BPP: usize = 4;

/// How many finished cursors the pointer cache holds
/// (MS-RDPBCGR 2.2.9.1.1.4.6, PRDRDP/04 §6.5).
///
/// The Pointer capability set advertises 32 colour and 32 new pointer slots,
/// so 64 covers both without a second table. A cache index outside it is
/// ignored with a warning rather than treated as a protocol error: a stale
/// cursor beats a dropped session.
pub const POINTER_CACHE: usize = 64;

/// The decoding half of one connection.
///
/// Holds the three things a legacy session has to carry between updates: the
/// session palette, the codec scratch buffers, and the pointer cache. All
/// three are reset by a Deactivate All, because the server is entitled to
/// rebuild the share underneath them.
pub struct Graphics {
    /// The desktop size, which every rectangle is checked against before a
    /// decode runs.
    desktop: (u16, u16),
    /// The session palette, which applies to 8 bpp bitmaps and 8 bpp pointers
    /// and to nothing else (PRDRDP/04 §2.7).
    palette: Palette,
    /// Wire format scratch for the interleaved RLE decoder, which writes wire
    /// pixels in wire row order and hands them to the converter.
    rle_scratch: Vec<u8>,
    /// The planar decoder's plane buffers, pooled rather than allocated per
    /// rectangle.
    planar_scratch: planar::PlanarScratch,
    /// Finished cursors by cache index. Stores the `CursorShape` rather than
    /// the wire form, so a cache hit is a clone of a small `Vec` and nothing
    /// is decoded twice.
    pointers: Vec<Option<CursorShape>>,
}

impl std::fmt::Debug for Graphics {
    /// The shapes and the counts. Not the pixels: a `Debug` that prints a
    /// framebuffer is a log line nobody can read and a screenshot in a bug
    /// report nobody meant to attach (PRDRDP/12 §6.5).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Graphics")
            .field("desktop", &self.desktop)
            .field("rle_scratch", &self.rle_scratch.len())
            .field("cached_pointers", &self.pointers.iter().flatten().count())
            .finish_non_exhaustive()
    }
}

impl Graphics {
    /// A fresh decoder for a desktop of this size.
    #[must_use]
    pub fn new(desktop: (u16, u16)) -> Self {
        Self {
            desktop,
            palette: Palette::default(),
            rle_scratch: Vec::new(),
            planar_scratch: planar::PlanarScratch::default(),
            pointers: vec![None; POINTER_CACHE],
        }
    }

    /// The desktop size every rectangle is clipped against.
    #[must_use]
    pub const fn desktop(&self) -> (u16, u16) {
        self.desktop
    }

    /// Adopt a new desktop size after a Deactivate All and a fresh capability
    /// exchange (MS-RDPBCGR 2.2.3.1).
    ///
    /// The palette and the pointer cache go with it: the share is being
    /// rebuilt and nothing that was true of the old one is guaranteed of the
    /// new one.
    pub fn reset(&mut self, desktop: (u16, u16)) {
        self.desktop = desktop;
        self.palette = Palette::default();
        for slot in &mut self.pointers {
            *slot = None;
        }
    }

    /// Replace the session palette from a `TS_UPDATE_PALETTE`
    /// (MS-RDPBCGR 2.2.9.1.1.3.1.1, PRDRDP/04 §2.7).
    pub fn set_palette(&mut self, update: &PaletteUpdate) {
        for (index, entry) in update.entries.iter().enumerate() {
            let Ok(index) = u8::try_from(index) else {
                break;
            };
            self.palette.set(index, entry.red, entry.green, entry.blue);
        }
    }

    /// Decode one bitmap update into dirty rectangles and their union
    /// (MS-RDPBCGR 2.2.9.1.1.3.1.2).
    ///
    /// Each `TS_BITMAP_DATA` produces exactly one [`DecodedRect`]. A rectangle
    /// outside the desktop is dropped with a trace rather than decoded, which
    /// is what the RFB path already does at
    /// `crates/vnc-core/src/session/run_loop.rs:947`: a server that addresses
    /// a rectangle we do not have is confused about the session, and the
    /// picture is better off missing that region than having a decoder write
    /// past the size the renderer allocated.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] when a codec refuses the bitstream, which names
    /// the codec and the geometry and never the bytes.
    pub fn bitmap_update(&mut self, update: &BitmapUpdate<'_>) -> Result<(Vec<DecodedRect>, Rect)> {
        let mut rects = Vec::with_capacity(update.rectangles.len());
        let mut damage = Rect::new(0, 0, 0, 0);
        for data in &update.rectangles {
            let Some(decoded) = self.bitmap_rect(data)? else {
                continue;
            };
            damage = damage.union(&decoded.rect);
            rects.push(decoded);
        }
        Ok((rects, damage))
    }

    /// One `TS_BITMAP_DATA`, or `None` when it does not belong on this
    /// desktop.
    fn bitmap_rect(&mut self, data: &BitmapData<'_>) -> Result<Option<DecodedRect>> {
        // `rdp-pdu` has already refused a destination larger than the encoded
        // bitmap and an inverted rectangle, so both unwraps below are a
        // restatement of what it proved rather than a new assumption
        // (`crates/rdp-pdu/src/update/mod.rs:409`).
        let (Some(dest_w), Some(dest_h)) = (data.dest.width(), data.dest.height()) else {
            return Ok(None);
        };
        let (Ok(dest_w), Ok(dest_h)) = (u16::try_from(dest_w), u16::try_from(dest_h)) else {
            return Ok(None);
        };
        let rect = Rect::new(data.dest.left, data.dest.top, dest_w, dest_h);
        if rect.is_empty() {
            return Ok(None);
        }

        let (desktop_w, desktop_h) = self.desktop;
        if u32::from(rect.x) + u32::from(rect.width) > u32::from(desktop_w)
            || u32::from(rect.y) + u32::from(rect.height) > u32::from(desktop_h)
        {
            tracing::debug!(
                x = rect.x,
                y = rect.y,
                w = rect.width,
                h = rect.height,
                desktop_w,
                desktop_h,
                "dropping a bitmap rectangle outside the desktop"
            );
            return Ok(None);
        }

        let mut pixels = vec![0u8; usize::from(data.width) * usize::from(data.height) * DST_BPP];
        self.decode_into(data, &mut pixels)?;

        // The encoded bitmap may be wider than its destination, in which case
        // it is clipped and not scaled (PRDRDP/04 §2.2). The clip is from the
        // top left, which is what every other client does and what makes the
        // common Windows case, a width rounded up to a multiple of four, come
        // out right.
        let payload = if (data.width, data.height) == (dest_w, dest_h) {
            pixels
        } else {
            crop_top_left(&pixels, data.width, dest_w, dest_h)
        };
        Ok(Some(DecodedRect {
            rect,
            payload: RectPayload::Rgba(payload),
        }))
    }

    /// Run the codec `bitsPerPixel` and the compression flag select, into a
    /// packed RGBA destination of the encoded bitmap's own size.
    fn decode_into(&mut self, data: &BitmapData<'_>, pixels: &mut [u8]) -> Result<()> {
        let (w, h) = (data.width, data.height);
        let bpp = u8::try_from(data.bits_per_pixel).unwrap_or(0);
        let mut dst = DstView::packed(pixels, w, h, OutFormat::Rgba, RowOrder::BottomUp)
            .map_err(|e| codec_error("destination", data, &e.into()))?;

        if !data.is_compressed() {
            return uncompressed::decode_legacy(bpp, data.data.as_slice(), &self.palette, &mut dst)
                .map_err(|e| codec_error("uncompressed", data, &e));
        }

        // The two compressed codecs are told apart by `bitsPerPixel` and not
        // by sniffing the first byte: Windows sends planar for 32 bpp and
        // interleaved RLE for 8, 15, 16 and 24, and the first byte of a planar
        // `FormatHeader` is a legal interleaved RLE order code (PRDRDP/04
        // §2.5). Guessing wrong produces a plausible picture that is wrong,
        // which is worse than refusing.
        match bpp {
            32 => planar::decode(
                data.data.as_slice(),
                // A legacy `TS_BITMAP_DATA`'s alpha byte is meaningless, so
                // the interleave writes a constant 255 rather than an alpha
                // the renderer would honour (PRDRDP/04 §2.5).
                false,
                &mut self.planar_scratch,
                &mut dst,
            )
            .map_err(|e| codec_error("planar", data, &e)),
            8 | 15 | 16 | 24 => {
                let need = rle::scratch_len(bpp, w, h)
                    .map_err(|e| codec_error("interleaved rle", data, &e))?;
                if self.rle_scratch.len() < need {
                    self.rle_scratch.resize(need, 0);
                }
                let scratch = &mut self.rle_scratch[..need];
                rle::decode_bpp(bpp, data.data.as_slice(), scratch, w, h)
                    .map_err(|e| codec_error("interleaved rle", data, &e))?;
                // The scratch holds wire pixels in wire row order, tightly
                // packed, so the conversion is the second and last pass and
                // the bottom up flip happens inside it.
                let fmt = PixelFormat::from_legacy_bpp(bpp)
                    .map_err(|e| codec_error("interleaved rle", data, &e.into()))?;
                uncompressed::decode(fmt, scratch, fmt.row_bytes(w), &self.palette, &mut dst)
                    .map_err(|e| codec_error("interleaved rle", data, &e))
            }
            other => Err(RdpError::Protocol(format!(
                "a compressed bitmap at {other} bits per pixel is not a codec this client \
                 advertised (MS-RDPBCGR 2.2.9.1.1.3.1.2.2)"
            ))),
        }
    }

    /// Turn one pointer update into the event it means (PRDRDP/04 §6).
    ///
    /// `None` means there is nothing for the UI to do about it.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] when a cursor's masks do not match the geometry
    /// that describes them.
    pub fn pointer(&mut self, update: &PointerUpdate<'_>) -> Result<Option<SessionEvent>> {
        use rdp_pdu::update::system_pointer;

        match update {
            PointerUpdate::System(system_pointer::NULL) => {
                // A zero by zero cursor is the contract's "hide the client
                // rendered sprite" (`FRAME_FORMAT.md`).
                Ok(Some(SessionEvent::CursorUpdate(CursorShape {
                    width: 0,
                    height: 0,
                    hotspot_x: 0,
                    hotspot_y: 0,
                    pixels: Vec::new(),
                })))
            }
            PointerUpdate::System(_) => {
                // `SYSPTR_DEFAULT` means "show the platform's own arrow", and
                // `SessionEvent` has no way to say that: a zero by zero shape
                // hides the sprite instead, which is the opposite. PRDRDP/04
                // §6.1 answers it with a built in arrow bitmap compiled into
                // this crate; that bitmap is not written, so the last shape
                // stays and the gap is named rather than papered over.
                tracing::debug!("SYSPTR_DEFAULT has no built in arrow yet; keeping the last shape");
                Ok(None)
            }
            PointerUpdate::Position(point) => Ok(Some(SessionEvent::CursorPosition {
                x: point.x,
                y: point.y,
            })),
            PointerUpdate::Cached(index) => match self.cached(*index) {
                Some(shape) => Ok(Some(SessionEvent::CursorUpdate(shape))),
                None => {
                    // A stale cursor beats a dropped session (PRDRDP/04 §6.5).
                    tracing::warn!(index, "a cached pointer index we never populated");
                    Ok(None)
                }
            },
            PointerUpdate::Color(pointer) => Ok(Some(self.store(pointer, COLOR_POINTER_BPP)?)),
            PointerUpdate::New { xor_bpp, pointer } | PointerUpdate::Large { xor_bpp, pointer } => {
                Ok(Some(self.store(pointer, *xor_bpp)?))
            }
        }
    }

    /// The cursor at a cache index, if we ever decoded one there.
    fn cached(&self, index: u16) -> Option<CursorShape> {
        self.pointers.get(usize::from(index))?.clone()
    }

    /// Decode a cursor, remember it under its cache index, and hand back the
    /// event.
    fn store(&mut self, pointer: &ColorPointer<'_>, xor_bpp: u16) -> Result<SessionEvent> {
        let shape = cursor_shape(pointer, xor_bpp, &self.palette)?;
        if let Some(slot) = self.pointers.get_mut(usize::from(pointer.cache_index)) {
            *slot = Some(shape.clone());
        } else {
            tracing::debug!(
                index = pointer.cache_index,
                "a cursor cache index past the cache we advertised"
            );
        }
        Ok(SessionEvent::CursorUpdate(shape))
    }
}

/// The one rectangle a `DecodedRect` list covers, for the renderer's present.
///
/// Free rather than a method so the run loop can fold several updates into one
/// `FramebufferUpdate` without this module knowing.
#[must_use]
pub fn union(rects: &[DecodedRect]) -> Rect {
    rects
        .iter()
        .fold(Rect::new(0, 0, 0, 0), |acc, r| acc.union(&r.rect))
}

/// Copy the top left `dest_w` by `dest_h` pixels out of a packed RGBA image
/// `src_w` pixels wide.
fn crop_top_left(pixels: &[u8], src_w: u16, dest_w: u16, dest_h: u16) -> Vec<u8> {
    let src_stride = usize::from(src_w) * DST_BPP;
    let dst_stride = usize::from(dest_w) * DST_BPP;
    let mut out = Vec::with_capacity(dst_stride * usize::from(dest_h));
    for y in 0..usize::from(dest_h) {
        let at = y * src_stride;
        match pixels.get(at..at + dst_stride) {
            Some(row) => out.extend_from_slice(row),
            // Cannot happen: the destination was proved no larger than the
            // encoded bitmap before the decode ran. A short row here is a
            // black band rather than a panic, because this runs on remote
            // input.
            None => out.resize(dst_stride * (y + 1), 0),
        }
    }
    out
}

/// One codec refusal, named and without a byte of the bitstream in it
/// (PRDRDP/12 §6.4).
fn codec_error(codec: &str, data: &BitmapData<'_>, e: &rdp_codecs::DecodeError) -> RdpError {
    RdpError::Protocol(format!(
        "the {codec} decoder refused a {}x{} bitmap at {} bits per pixel: {e}",
        data.width, data.height, data.bits_per_pixel
    ))
}

/// Turn a `TS_COLORPOINTERATTRIBUTE` and its two masks into RGBA
/// (MS-RDPBCGR 2.2.9.1.1.4.4, PRDRDP/04 §6.7).
///
/// The XOR mask is an ordinary bitmap at 1, 8, 16, 24 or 32 bits per pixel,
/// bottom up with rows padded to two bytes, so it goes through the same
/// converter every other bitmap uses. The AND mask is then applied as alpha,
/// with classic Windows cursor semantics:
///
/// | AND bit | XOR pixel | Result |
/// |---|---|---|
/// | 0 | any | opaque, the XOR colour |
/// | 1 | black | transparent |
/// | 1 | white | inverted screen |
/// | 1 | anything else | undefined by Windows; transparent |
///
/// The inverted case cannot be expressed by a sprite composited with
/// `SRC_ALPHA, ONE_MINUS_SRC_ALPHA`, and adding an invert blend would mean a
/// second shader program for a handful of legacy cursors. PRDRDP/04 §6.7 rules
/// that those pixels become an opaque two by two black and white check, which
/// is visible against anything and unambiguous to a user, and that is what
/// this does.
///
/// **At 32 bits per pixel the AND mask is ignored entirely** and the alpha
/// byte is used directly. Servers send both, and honouring the AND mask on a
/// 32 bpp cursor punches holes in antialiased edges; that is the single most
/// common cursor rendering bug in RDP clients.
///
/// # Errors
///
/// [`RdpError::Protocol`] when a mask is shorter than its geometry says, or
/// when the bit depth is not one a cursor may use.
pub fn cursor_shape(
    pointer: &ColorPointer<'_>,
    xor_bpp: u16,
    palette: &Palette,
) -> Result<CursorShape> {
    let (w, h) = (pointer.width, pointer.height);
    if w == 0 || h == 0 {
        return Ok(CursorShape {
            width: 0,
            height: 0,
            hotspot_x: 0,
            hotspot_y: 0,
            pixels: Vec::new(),
        });
    }

    let xor = pointer.xor_mask.as_slice();
    let and = pointer.and_mask.as_slice();
    if xor.len() < xor_mask_len(w, h, xor_bpp) {
        return Err(RdpError::Protocol(format!(
            "a {w}x{h} cursor at {xor_bpp} bits per pixel needs {} bytes of xorMaskData and \
             carried {} (MS-RDPBCGR 2.2.9.1.1.4.4)",
            xor_mask_len(w, h, xor_bpp),
            xor.len()
        )));
    }

    // A 32 bpp cursor carries a real alpha channel, so it is converted as
    // `BgrA32` rather than as `BgrX32`, which would force every pixel opaque.
    let fmt = if xor_bpp == 32 {
        PixelFormat::BgrA32
    } else {
        PixelFormat::from_legacy_bpp(u8::try_from(xor_bpp).unwrap_or(0)).map_err(|e| {
            RdpError::Protocol(format!(
                "a cursor at {xor_bpp} bits per pixel is not a bitmap layout: {e}"
            ))
        })?
    };

    let mut pixels = vec![0u8; usize::from(w) * usize::from(h) * DST_BPP];
    {
        let mut dst = DstView::packed(&mut pixels, w, h, OutFormat::Rgba, RowOrder::BottomUp)
            .map_err(|e| RdpError::Protocol(format!("a cursor destination is wrong: {e}")))?;
        uncompressed::decode(fmt, xor, xor_mask_row_len(w, xor_bpp), palette, &mut dst).map_err(
            |e| {
                RdpError::Protocol(format!(
                    "a {w}x{h} cursor's xorMaskData did not decode: {e}"
                ))
            },
        )?;
    }

    if xor_bpp != 32 {
        if and.len() < and_mask_len(w, h) {
            return Err(RdpError::Protocol(format!(
                "a {w}x{h} cursor needs {} bytes of andMaskData and carried {} \
                 (MS-RDPBCGR 2.2.9.1.1.4.4)",
                and_mask_len(w, h),
                and.len()
            )));
        }
        apply_and_mask(&mut pixels, and, w, h);
    }

    Ok(CursorShape {
        width: w,
        height: h,
        hotspot_x: pointer.hot_spot.x,
        hotspot_y: pointer.hot_spot.y,
        pixels,
    })
}

/// The alpha half of PRDRDP/04 §6.7's table, over an RGBA image that is
/// already top down.
fn apply_and_mask(pixels: &mut [u8], and: &[u8], w: u16, h: u16) {
    let and_stride = and_mask_row_len(w);
    for y in 0..usize::from(h) {
        // The AND mask is bottom up like the colour mask, and the destination
        // was already flipped, so row `y` of the image is row `h - 1 - y` of
        // the mask.
        let src_row = usize::from(h) - 1 - y;
        for x in 0..usize::from(w) {
            let Some(byte) = and.get(src_row * and_stride + x / 8) else {
                continue;
            };
            if (byte >> (7 - (x % 8))) & 1 == 0 {
                continue;
            }
            let at = (y * usize::from(w) + x) * DST_BPP;
            let Some(px) = pixels.get_mut(at..at + DST_BPP) else {
                continue;
            };
            let white = px[0] == 0xff && px[1] == 0xff && px[2] == 0xff;
            if white {
                // "XOR the screen", which the compositor cannot express. An
                // opaque two by two check is visible against anything, which
                // is what a cursor has to be (PRDRDP/04 §6.7).
                let dark = (x + y) % 2 == 0;
                let v = if dark { 0x00 } else { 0xff };
                px.copy_from_slice(&[v, v, v, 0xff]);
            } else {
                // Black is transparent, and so is anything else, which Windows
                // leaves undefined.
                px.copy_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
}

/// One coalesced framebuffer update, ready to emit.
///
/// A convenience for the run loop rather than a type with behaviour: the
/// renderer presents once per event, so several bitmap updates read out of one
/// fast path PDU become one of these (PRDRDP/04 §10.4).
#[must_use]
pub fn framebuffer_update(rects: Vec<DecodedRect>) -> SessionEvent {
    let damage = union(&rects);
    SessionEvent::FramebufferUpdate { rects, damage }
}

/// The pixels of a decoded rectangle, for a caller that wants to assert on
/// them. Nothing in the session path uses this; the tests do.
#[must_use]
pub fn rgba(rect: &DecodedRect) -> Option<&[u8]> {
    match &rect.payload {
        RectPayload::Rgba(pixels) => Some(pixels),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::io::Payload;
    use rdp_pdu::update::{Point16, RectInclusive};

    fn bitmap(
        dest: RectInclusive,
        w: u16,
        h: u16,
        bpp: u16,
        data: &'static [u8],
    ) -> BitmapData<'static> {
        BitmapData {
            dest,
            width: w,
            height: h,
            bits_per_pixel: bpp,
            flags: 0,
            compression_header: None,
            data: Payload::new(data),
        }
    }

    /// The whole of PRDRDP/04 §2.3 in one assertion: an uncompressed bitmap is
    /// a DIB body, so its first row is the bottom row of the picture. A
    /// symmetric fixture would pass whichever way round it went, so this one
    /// is deliberately asymmetric.
    #[test]
    fn an_uncompressed_bitmap_arrives_the_right_way_up() {
        // Two rows of two pixels at 24 bpp, stride padded to four bytes.
        // Wire row 0 is the BOTTOM row of the image.
        static WIRE: &[u8] = &[
            // bottom row: blue, blue (B G R)
            0xff, 0x00, 0x00, 0x00, //
            0xff, 0x00, 0x00, 0x00, //
            // top row: red, red
            0x00, 0x00, 0xff, 0x00, //
            0x00, 0x00, 0xff, 0x00, //
        ];
        let mut g = Graphics::new((64, 64));
        let update = BitmapUpdate {
            rectangles: vec![bitmap(
                RectInclusive {
                    left: 4,
                    top: 8,
                    right: 5,
                    bottom: 9,
                },
                2,
                2,
                24,
                WIRE,
            )],
        };
        let (rects, damage) = g.bitmap_update(&update).expect("decodes");
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].rect, Rect::new(4, 8, 2, 2));
        assert_eq!(damage, Rect::new(4, 8, 2, 2));
        let pixels = rgba(&rects[0]).expect("rgba");
        assert_eq!(pixels.len(), 2 * 2 * 4);
        assert_eq!(
            &pixels[0..4],
            &[0xff, 0x00, 0x00, 0xff],
            "the top row is red"
        );
        assert_eq!(
            &pixels[8..12],
            &[0x00, 0x00, 0xff, 0xff],
            "the bottom row is blue"
        );
    }

    /// A rectangle the desktop does not have is dropped rather than decoded.
    /// A server that addresses one is confused about the session, and the
    /// alternative is a decoder writing past what the renderer allocated.
    #[test]
    fn a_rectangle_outside_the_desktop_is_dropped() {
        static WIRE: &[u8] = &[0; 64];
        let mut g = Graphics::new((16, 16));
        let update = BitmapUpdate {
            rectangles: vec![bitmap(
                RectInclusive {
                    left: 14,
                    top: 0,
                    right: 17,
                    bottom: 3,
                },
                4,
                4,
                32,
                WIRE,
            )],
        };
        let (rects, damage) = g.bitmap_update(&update).expect("no decode runs");
        assert!(rects.is_empty());
        assert!(damage.is_empty());
    }

    /// The interleaved RLE vector `rdp-codecs` carries for its own decoder,
    /// driven through the framing this file puts around it, so the scratch,
    /// the stride and the palette are all exercised together.
    #[test]
    fn a_compressed_eight_bit_bitmap_goes_through_the_rle_decoder() {
        static WIRE: &[u8] = &[0x83, 0x11, 0x22, 0x33, 0x61, 0x44, 0x04, 0x24];
        let mut g = Graphics::new((64, 64));
        let mut data = bitmap(
            RectInclusive {
                left: 0,
                top: 0,
                right: 3,
                bottom: 2,
            },
            4,
            3,
            8,
            WIRE,
        );
        data.flags = rdp_pdu::update::bitmap_flags::COMPRESSION;
        let (rects, _) = g
            .bitmap_update(&BitmapUpdate {
                rectangles: vec![data],
            })
            .expect("decodes");
        let pixels = rgba(&rects[0]).expect("rgba");
        assert_eq!(pixels.len(), 4 * 3 * 4);
        // The default palette is a grayscale ramp, so index 0x11 is grey 0x11.
        // Wire row 2 is the top row of the picture: 0xEE 0xDD 0xCC 0xBB.
        assert_eq!(&pixels[0..4], &[0xee, 0xee, 0xee, 0xff]);
    }

    /// A compressed bitmap at a depth no codec covers is refused by name,
    /// never guessed at: the two compressed codecs are told apart by
    /// `bitsPerPixel` and a wrong guess makes a plausible picture that is
    /// wrong (PRDRDP/04 §2.5).
    #[test]
    fn a_compressed_bitmap_at_an_impossible_depth_is_refused() {
        static WIRE: &[u8] = &[0; 32];
        let mut g = Graphics::new((64, 64));
        let mut data = bitmap(
            RectInclusive {
                left: 0,
                top: 0,
                right: 1,
                bottom: 1,
            },
            2,
            2,
            4,
            WIRE,
        );
        data.flags = rdp_pdu::update::bitmap_flags::COMPRESSION;
        let err = g
            .bitmap_update(&BitmapUpdate {
                rectangles: vec![data],
            })
            .expect_err("no codec at 4 bpp");
        assert!(err.to_string().contains("4 bits per pixel"), "{err}");
    }

    fn cursor(w: u16, h: u16, xor: &'static [u8], and: &'static [u8]) -> ColorPointer<'static> {
        ColorPointer {
            cache_index: 3,
            hot_spot: Point16 { x: 1, y: 2 },
            width: w,
            height: h,
            xor_mask: Payload::new(xor),
            and_mask: Payload::new(and),
        }
    }

    /// The cursor table of PRDRDP/04 §6.7, one row per assertion. This is
    /// where cursor bugs live, so every row of the table is a byte level
    /// check rather than a shape check.
    #[test]
    fn the_and_mask_decides_transparency_and_the_invert_case_becomes_a_check() {
        // 2 by 2 at 24 bpp. Rows are padded to two bytes, so a row of two
        // 24 bpp pixels is six bytes and needs no padding.
        // Wire row 0 is the bottom row.
        static XOR: &[u8] = &[
            // bottom row: white, black
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, //
            // top row: red, white
            0x00, 0x00, 0xff, 0xff, 0xff, 0xff, //
        ];
        // 1 bpp, rows padded to two bytes. Bottom row first.
        // bottom row bits: 1 0  -> 0b1000_0000
        // top row bits:    0 1  -> 0b0100_0000
        static AND: &[u8] = &[0b1000_0000, 0x00, 0b0100_0000, 0x00];

        let shape = cursor_shape(&cursor(2, 2, XOR, AND), 24, &Palette::default())
            .expect("a well formed cursor");
        assert_eq!((shape.width, shape.height), (2, 2));
        assert_eq!((shape.hotspot_x, shape.hotspot_y), (1, 2));

        // Top row: red with AND 0 is opaque; white with AND 1 is the invert
        // check, which is opaque black or white by position.
        assert_eq!(&shape.pixels[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(shape.pixels[7], 0xff, "an inverted pixel stays opaque");
        assert!(
            shape.pixels[4] == 0x00 || shape.pixels[4] == 0xff,
            "an inverted pixel is black or white, not the xor colour"
        );

        // Bottom row: white with AND 1 is the invert check; black with AND 0
        // is opaque black.
        assert_eq!(shape.pixels[11], 0xff, "an inverted pixel stays opaque");
        assert_eq!(&shape.pixels[12..16], &[0x00, 0x00, 0x00, 0xff]);
    }

    /// The single most common cursor bug in RDP clients: honouring the AND
    /// mask on a 32 bpp cursor punches holes in antialiased edges. At 32 bpp
    /// the alpha byte wins and the AND mask is not read at all.
    #[test]
    fn a_thirty_two_bit_cursor_uses_its_alpha_and_ignores_the_and_mask() {
        // One pixel, BGRA, half transparent red.
        static XOR: &[u8] = &[0x00, 0x00, 0xff, 0x80];
        // An AND mask that would make it transparent if it were honoured.
        static AND: &[u8] = &[0b1000_0000, 0x00];
        let shape =
            cursor_shape(&cursor(1, 1, XOR, AND), 32, &Palette::default()).expect("decodes");
        assert_eq!(shape.pixels, vec![0xff, 0x00, 0x00, 0x80]);
    }

    /// A mask shorter than its geometry is refused by name rather than read
    /// past: these are bytes a remote peer chose.
    #[test]
    fn a_short_mask_is_refused_rather_than_read_past() {
        static SHORT: &[u8] = &[0x00];
        let err = cursor_shape(&cursor(16, 16, SHORT, SHORT), 24, &Palette::default())
            .expect_err("far too short");
        assert!(err.to_string().contains("xorMaskData"), "{err}");
    }

    /// A cursor is decoded once and cached, so a `TS_CACHEDPOINTERATTRIBUTE`
    /// costs a clone. An index we never populated is a warning and not a
    /// dropped session.
    #[test]
    fn a_cached_pointer_index_is_remembered_and_a_missing_one_is_survivable() {
        static XOR: &[u8] = &[0x00, 0x00, 0xff, 0xff];
        static AND: &[u8] = &[0x00, 0x00];
        let mut g = Graphics::new((64, 64));

        let event = g
            .pointer(&PointerUpdate::Color(cursor(1, 1, XOR, AND)))
            .expect("decodes")
            .expect("an event");
        assert!(matches!(event, SessionEvent::CursorUpdate(_)));

        let hit = g
            .pointer(&PointerUpdate::Cached(3))
            .expect("a cache hit")
            .expect("an event");
        match hit {
            SessionEvent::CursorUpdate(shape) => assert_eq!((shape.width, shape.height), (1, 1)),
            other => panic!("expected a cursor, got {other:?}"),
        }

        assert!(
            g.pointer(&PointerUpdate::Cached(POINTER_CACHE as u16 + 5))
                .expect("survivable")
                .is_none(),
            "an index we never populated is a warning, not a failure"
        );
    }

    /// `SYSPTR_NULL` hides the sprite, and hiding it is a zero by zero shape
    /// rather than an absent event.
    #[test]
    fn a_null_system_pointer_hides_the_cursor() {
        let mut g = Graphics::new((64, 64));
        let event = g
            .pointer(&PointerUpdate::System(
                rdp_pdu::update::system_pointer::NULL,
            ))
            .expect("no decode")
            .expect("an event");
        match event {
            SessionEvent::CursorUpdate(shape) => {
                assert_eq!((shape.width, shape.height), (0, 0));
                assert!(shape.pixels.is_empty());
            }
            other => panic!("expected a cursor update, got {other:?}"),
        }
    }

    /// A pointer position is a JSON event and never touches the frame path,
    /// which is the split the RFB path already has (PRDRDP/04 §6.6).
    #[test]
    fn a_pointer_position_is_its_own_event() {
        let mut g = Graphics::new((64, 64));
        let event = g
            .pointer(&PointerUpdate::Position(Point16 { x: 800, y: 600 }))
            .expect("no decode")
            .expect("an event");
        assert!(matches!(
            event,
            SessionEvent::CursorPosition { x: 800, y: 600 }
        ));
    }
}
