//! EGFX surfaces: the offscreen bitmaps every graphics command draws into
//! (MS-RDPEGFX 2.2.2.9, 3.3.5.6, PRDRDP/04 §3.3).
//!
//! # Why surfaces exist at all
//!
//! A legacy bitmap update names a rectangle on the screen. An EGFX command
//! names a rectangle on a *surface*, and a separate command says where, if
//! anywhere, that surface appears on the output. That indirection is what
//! makes `RDPGFX_SURFACE_TO_CACHE` and `RDPGFX_CACHE_TO_SURFACE` worth having:
//! a window border decoded once is pasted back a hundred times without a byte
//! crossing the wire. A client that threw the surface away after drawing it
//! would have to fail every one of those commands, which on a real Windows
//! desktop is most of the traffic.
//!
//! # The storage format, and a divergence from PRDRDP/04 §3.3
//!
//! §3.3 stores a surface BGRA8888, and `remote_pixel::OutFormat::Bgra`'s own
//! comment repeats it (`crates/remote-pixel/src/dst.rs:120`). These store
//! RGBA8888 instead. The reason is the emit path: what the renderer takes is
//! `remote_core::RectPayload::Rgba`
//! (`crates/remote-core/src/events.rs:28`), so a BGRA surface would need a per
//! pixel swizzle every time a rectangle left it. Nothing is gained in
//! exchange, because every decoder in `rdp-codecs` takes the destination
//! channel order as a parameter and costs the same either way
//! ([`remote_pixel::put`] resolves it at monomorphisation). Storing RGBA makes
//! the emit a row copy.
//!
//! # The one copy, and the one that follows it
//!
//! A decoder writes each pixel of a rectangle exactly once, straight into the
//! surface, through a [`DstView`] carrying the surface's stride: that is D9's
//! zero copy invariant, and [`Surface::view`] is the only way to get one.
//! Handing a rectangle to the shell is then one contiguous `extend_from_slice`
//! per row out of the surface into the event payload
//! ([`Surface::copy_out`]), which is the same transfer the legacy bitmap path
//! makes at `crates/rdp-core/src/session/graphics.rs:205`. It is not a second
//! decode and it is not a conversion; it is the handover, and it exists
//! because `RectPayload::Rgba` owns its bytes.

use rdp_codecs::progressive::ProgressiveState;
use rdp_codecs::{DstView, OutFormat, RowOrder};
use rdp_pdu::update::{Point16, RectExclusive};
use rdp_pdu::vc::egfx::{pixel_format, Color32};

use crate::error::{RdpError, Result};

/// Bytes per pixel in a surface, and in a decoded rect.
const BPP: usize = 4;

/// The most surface memory one session may hold.
///
/// A 3840 by 2160 surface is `3840 * 2160 * 4` bytes, 33,177,600, so this is
/// four of them and a little. A server needs one surface for the output and
/// usually one or two more for composition; a server asking for four 4K
/// surfaces at once is not one we are going to keep up with anyway.
pub const MAX_SURFACE_BYTES: usize = 144 * 1024 * 1024;

/// The most surfaces one session may hold at once.
///
/// MS-RDPEGFX puts no limit on `surfaceId`, which is a `u16`, so without one
/// a server can ask for 65,536 allocations.
pub const MAX_SURFACES: usize = 64;

/// One EGFX surface.
#[derive(Debug)]
pub struct Surface {
    /// `surfaceId` (MS-RDPEGFX 2.2.2.9).
    pub id: u16,
    /// `width`.
    pub width: u16,
    /// `height`.
    pub height: u16,
    /// True for `GFX_PIXEL_FORMAT_ARGB_8888`, where the alpha channel a codec
    /// produces is meaningful. False for `XRGB_8888`, where it is padding and
    /// every pixel is opaque.
    pub has_alpha: bool,
    /// Where the surface appears on the output, from
    /// `RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU` (MS-RDPEGFX 2.2.2.15). `None` for a
    /// surface that is composed into another and never shown, whose contents
    /// must not reach the renderer.
    pub origin: Option<(u32, u32)>,
    /// RGBA8888, packed, top down.
    pixels: Vec<u8>,
    /// The progressive codec's tile store for this surface.
    ///
    /// It lives on the surface because that is what MS-RDPEGFX 2.2.4.2 makes
    /// it: a first pass leaves a coarse tile behind and a later
    /// `WBT_TILE_UPGRADE` refines that same tile in place, so the store has
    /// to outlive the message and die with the surface it describes. A store
    /// pooled per channel instead would refine one surface's tiles with
    /// another's coefficients.
    ///
    /// It allocates nothing until a progressive tile arrives, so a session
    /// that never sees the codec pays a `Vec` header per surface
    /// (`rdp_codecs::progressive::ProgressiveState::new`).
    ///
    /// # What bounds it
    ///
    /// The per store ceiling is `rdp_codecs::progressive::DEFAULT_MAX_BYTES`
    /// (128 MiB, PRDRDP/04 §4.9.4), which no legal surface reaches: the grid
    /// is fixed by the surface's own geometry, so the store cannot exceed
    /// `ceil(w/64) * ceil(h/64) * 24 KiB`, which is 47.8 MiB at 4K. Across
    /// the session the bound is geometric too, at one and a half times
    /// [`MAX_SURFACE_BYTES`], because a tile costs 24 KiB of coefficients for
    /// 16 KiB of pixels. §4.9.4's cross context eviction is therefore not
    /// implemented: there is nothing it could evict that the surface budget
    /// has not already refused.
    progressive: ProgressiveState,
}

impl Surface {
    /// Bytes between the starts of two rows.
    #[must_use]
    pub fn stride(&self) -> usize {
        usize::from(self.width) * BPP
    }

    /// Bytes this surface occupies.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.pixels.len()
    }

    /// Bytes the progressive tile store is holding for this surface, which is
    /// zero until a progressive tile arrives (PRDRDP/04 §11.3).
    #[must_use]
    pub fn progressive_bytes(&self) -> usize {
        self.progressive.bytes()
    }

    /// Check a rectangle against the surface's own bounds and return it as
    /// `(left, top, width, height)`.
    ///
    /// Every command that names a rectangle goes through here before a pixel
    /// moves. `RectExclusive::width` already refuses inverted edges
    /// (`crates/rdp-pdu/src/update/mod.rs:208`); what is added is the bound
    /// against this surface, which `rdp-pdu` cannot check because it does not
    /// know the geometry.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] naming the rectangle and the surface.
    pub fn bounded(&self, rect: RectExclusive, what: &str) -> Result<(u16, u16, u16, u16)> {
        let (Some(w), Some(h)) = (rect.width(), rect.height()) else {
            return Err(RdpError::Protocol(format!(
                "{what} named a rectangle with inverted edges on surface {} \
                 (MS-RDPEGFX 2.2.2.1)",
                self.id
            )));
        };
        let right = u32::from(rect.left) + w;
        let bottom = u32::from(rect.top) + h;
        if right > u32::from(self.width) || bottom > u32::from(self.height) {
            return Err(RdpError::Protocol(format!(
                "{what} named {w}x{h} at ({}, {}) on surface {}, which is {}x{} \
                 (MS-RDPEGFX 2.2.2.1)",
                rect.left, rect.top, self.id, self.width, self.height
            )));
        }
        // Both fit in a `u16` because `right` and `bottom` do.
        Ok((rect.left, rect.top, w as u16, h as u16))
    }

    /// A destination a decoder writes one rectangle of this surface through.
    ///
    /// The stride is the surface's, so the decoder writes into the middle of a
    /// larger buffer with no intermediate rectangle sized allocation, which is
    /// what [`DstView::new`]'s stride parameter exists for
    /// (`crates/remote-pixel/src/dst.rs:139`).
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] when the rectangle is not inside the surface.
    pub fn view(&mut self, rect: RectExclusive, what: &str) -> Result<DstView<'_>> {
        let (left, top, w, h) = self.bounded(rect, what)?;
        if w == 0 || h == 0 {
            // A zero sized destination is legal on the wire and there is
            // nothing to write; `DstView` accepts it and every decoder's row
            // loop runs zero times.
            return DstView::new(&mut [], 0, 0, 0, OutFormat::Rgba, RowOrder::TopDown)
                .map_err(|e| dst_error(self.id, &e));
        }
        let stride = self.stride();
        let start = usize::from(top) * stride + usize::from(left) * BPP;
        let buf = self.pixels.get_mut(start..).unwrap_or(&mut []);
        // EGFX is always top down: there is no legacy DIB body path into a
        // surface (PRDRDP/04 §2.8).
        DstView::new(buf, stride, w, h, OutFormat::Rgba, RowOrder::TopDown)
            .map_err(|e| dst_error(self.id, &e))
    }

    /// The progressive tile store for this surface, beside a destination view
    /// of one rectangle of it.
    ///
    /// Two borrows of fields that do not overlap, which is the whole reason
    /// this is not [`Surface::view`] plus a second call: the view already
    /// borrows the surface, and the progressive decoder needs the store and
    /// the destination at the same time
    /// (`rdp_codecs::progressive::decode_message`).
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] when the rectangle is not inside the surface.
    pub fn progressive_view(
        &mut self,
        rect: RectExclusive,
        what: &str,
    ) -> Result<(&mut ProgressiveState, DstView<'_>)> {
        let (left, top, w, h) = self.bounded(rect, what)?;
        let (id, stride) = (self.id, self.stride());
        let Self {
            pixels,
            progressive,
            ..
        } = self;
        let dst = if w == 0 || h == 0 {
            // A zero sized destination is legal on the wire and there is
            // nothing to write; `DstView` accepts it and every decoder's row
            // loop runs zero times.
            DstView::new(&mut [], 0, 0, 0, OutFormat::Rgba, RowOrder::TopDown)
        } else {
            let start = usize::from(top) * stride + usize::from(left) * BPP;
            let buf = pixels.get_mut(start..).unwrap_or(&mut []);
            DstView::new(buf, stride, w, h, OutFormat::Rgba, RowOrder::TopDown)
        }
        .map_err(|e| dst_error(id, &e))?;
        Ok((progressive, dst))
    }

    /// Copy one rectangle out, appending `width * height * 4` bytes to `out`.
    ///
    /// `out` is reserved exactly once and then filled a row at a time, so the
    /// handover to the shell is one allocation and `height` contiguous
    /// copies.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] when the rectangle is not inside the surface.
    pub fn copy_out(&self, rect: RectExclusive, out: &mut Vec<u8>) -> Result<()> {
        let (left, top, w, h) = self.bounded(rect, "a frame emit")?;
        let stride = self.stride();
        let row_bytes = usize::from(w) * BPP;
        out.reserve_exact(row_bytes * usize::from(h));
        for y in 0..usize::from(h) {
            let start = (usize::from(top) + y) * stride + usize::from(left) * BPP;
            let row = self.pixels.get(start..start + row_bytes).ok_or_else(|| {
                RdpError::Protocol(format!("surface {} is shorter than its geometry", self.id))
            })?;
            out.extend_from_slice(row);
        }
        Ok(())
    }

    /// `RDPGFX_SOLIDFILL_PDU`: paint one rectangle a single colour
    /// (MS-RDPEGFX 2.2.2.4).
    ///
    /// The first row is written pixel by pixel and every row after it is a
    /// copy of the first, which is what turns a fill into one `memcpy` per
    /// row instead of a multiply and four stores per pixel.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] when the rectangle is not inside the surface.
    pub fn fill(&mut self, rect: RectExclusive, colour: Color32) -> Result<()> {
        let (left, top, w, h) = self.bounded(rect, "a solid fill")?;
        if w == 0 || h == 0 {
            return Ok(());
        }
        // `RDPGFX_COLOR32` is `{B, G, R, XA}` on the wire and the surface is
        // RGBA, so the three colour bytes are reordered here and nowhere else.
        // `XA` is alpha only on an ARGB surface (MS-RDPEGFX 2.2.2.4).
        let alpha = if self.has_alpha { colour.xa } else { 0xFF };
        let px = [colour.r, colour.g, colour.b, alpha];
        let stride = self.stride();
        let row_bytes = usize::from(w) * BPP;

        let first = usize::from(top) * stride + usize::from(left) * BPP;
        let Some(row) = self.pixels.get_mut(first..first + row_bytes) else {
            return Err(RdpError::Protocol(format!(
                "surface {} is shorter than its geometry",
                self.id
            )));
        };
        for chunk in row.chunks_exact_mut(BPP) {
            chunk.copy_from_slice(&px);
        }
        for y in 1..usize::from(h) {
            let start = (usize::from(top) + y) * stride + usize::from(left) * BPP;
            // Split so the source row and the destination row are two
            // disjoint borrows, which is what lets this be a copy rather than
            // a per pixel write.
            let (head, tail) = self.pixels.split_at_mut(start);
            let src = head
                .get(first..first + row_bytes)
                .ok_or_else(|| short(self.id))?;
            tail.get_mut(..row_bytes)
                .ok_or_else(|| short(self.id))?
                .copy_from_slice(src);
        }
        Ok(())
    }

    /// Copy a rectangle from one place in this surface to another
    /// (`RDPGFX_SURFACE_TO_SURFACE_PDU` with `surfaceIdSrc == surfaceIdDest`,
    /// MS-RDPEGFX 2.2.2.5).
    ///
    /// Overlapping copies are handled by choosing the row order: a copy that
    /// moves content downwards runs bottom to top, so a row is read before
    /// the copy overwrites it. That is the `memmove` rule applied one
    /// dimension up, and Windows does use overlapping copies (scrolling a
    /// window is one).
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] when either rectangle is not inside the
    /// surface.
    pub fn blit_within(&mut self, src: RectExclusive, dest: Point16) -> Result<RectExclusive> {
        let (sx, sy, w, h) = self.bounded(src, "a surface to surface copy")?;
        let dst_rect = translated(dest, w, h)?;
        let (dx, dy, _, _) = self.bounded(dst_rect, "a surface to surface copy destination")?;
        if w == 0 || h == 0 {
            return Ok(dst_rect);
        }
        let stride = self.stride();
        let row_bytes = usize::from(w) * BPP;
        let downwards = dy > sy;
        for i in 0..usize::from(h) {
            let y = if downwards { usize::from(h) - 1 - i } else { i };
            let from = (usize::from(sy) + y) * stride + usize::from(sx) * BPP;
            let to = (usize::from(dy) + y) * stride + usize::from(dx) * BPP;
            if from == to {
                continue;
            }
            // `copy_within` is `memmove` on the whole buffer, so the same row
            // overlapping itself horizontally is handled too.
            if from + row_bytes > self.pixels.len() || to + row_bytes > self.pixels.len() {
                return Err(short(self.id));
            }
            self.pixels.copy_within(from..from + row_bytes, to);
        }
        Ok(dst_rect)
    }

    /// Read a rectangle into a caller's buffer, replacing what is there.
    ///
    /// Used by `RDPGFX_SURFACE_TO_CACHE` and by the cross surface half of
    /// `RDPGFX_SURFACE_TO_SURFACE`.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] when the rectangle is not inside the surface.
    pub fn read_into(&self, rect: RectExclusive, out: &mut Vec<u8>) -> Result<(u16, u16)> {
        let (_, _, w, h) = self.bounded(rect, "a surface read")?;
        out.clear();
        self.copy_out(rect, out)?;
        Ok((w, h))
    }

    /// Write a packed RGBA rectangle into the surface.
    ///
    /// The source is `width * height * 4` bytes with no padding, which is what
    /// a cache slot and [`Surface::read_into`] both produce.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] when the destination is not inside the surface
    /// or the source is too short.
    pub fn write_packed(
        &mut self,
        dest: Point16,
        width: u16,
        height: u16,
        src: &[u8],
    ) -> Result<RectExclusive> {
        let rect = translated(dest, width, height)?;
        let (dx, dy, w, h) = self.bounded(rect, "a cache to surface paste")?;
        let row_bytes = usize::from(w) * BPP;
        if src.len() < row_bytes * usize::from(h) {
            return Err(RdpError::Protocol(format!(
                "a {w}x{h} paste onto surface {} had only {} source bytes \
                 (MS-RDPEGFX 2.2.2.7)",
                self.id,
                src.len()
            )));
        }
        let stride = self.stride();
        for y in 0..usize::from(h) {
            let to = (usize::from(dy) + y) * stride + usize::from(dx) * BPP;
            let from = y * row_bytes;
            let row = src
                .get(from..from + row_bytes)
                .ok_or_else(|| short(self.id))?;
            self.pixels
                .get_mut(to..to + row_bytes)
                .ok_or_else(|| short(self.id))?
                .copy_from_slice(row);
        }
        Ok(rect)
    }
}

/// Every surface this session holds.
///
/// A `Vec` rather than a map for the same reason [`crate::channels`] uses one:
/// a session has a handful of surfaces and a linear scan over a `u16` beats
/// hashing one.
#[derive(Debug, Default)]
pub struct SurfaceStore {
    surfaces: Vec<Surface>,
    bytes: usize,
}

impl SurfaceStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget every surface. Called on `RDPGFX_RESET_GRAPHICS` and when the
    /// channel closes.
    pub fn reset(&mut self) {
        self.surfaces.clear();
        self.bytes = 0;
    }

    /// Surfaces held, for a log line and for the tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.surfaces.len()
    }

    /// True when nothing is allocated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.surfaces.is_empty()
    }

    /// Bytes held across every surface.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Bytes the progressive tile stores are holding, across every surface.
    ///
    /// Counted rather than tracked, because it changes on every tile and the
    /// only reader is the trace line. It is not part of [`Self::bytes`]: that
    /// figure decides whether a `CREATE_SURFACE` is admitted against
    /// [`MAX_SURFACE_BYTES`], and an admission test that moved with decode
    /// history would refuse a surface for what a previous frame drew.
    #[must_use]
    pub fn progressive_bytes(&self) -> usize {
        self.surfaces.iter().map(Surface::progressive_bytes).sum()
    }

    /// `RDPGFX_CREATE_SURFACE_PDU` (MS-RDPEGFX 2.2.2.9).
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] for a duplicate id, an unknown pixel format, or
    /// a request that would take the session past [`MAX_SURFACE_BYTES`] or
    /// [`MAX_SURFACES`].
    pub fn create(&mut self, id: u16, width: u16, height: u16, format: u8) -> Result<()> {
        if self.surfaces.iter().any(|s| s.id == id) {
            return Err(RdpError::Protocol(format!(
                "the server created surface {id} twice (MS-RDPEGFX 2.2.2.9)"
            )));
        }
        let has_alpha = match format {
            pixel_format::ARGB_8888 => true,
            pixel_format::XRGB_8888 => false,
            other => {
                return Err(RdpError::Protocol(format!(
                    "surface {id} asked for pixel format 0x{other:02x}, which \
                     MS-RDPEGFX 2.2.2.9 does not define"
                )));
            }
        };
        if self.surfaces.len() >= MAX_SURFACES {
            return Err(RdpError::Protocol(format!(
                "the server asked for more than {MAX_SURFACES} surfaces at once"
            )));
        }
        let bytes = usize::from(width) * usize::from(height) * BPP;
        if self.bytes + bytes > MAX_SURFACE_BYTES {
            return Err(RdpError::Protocol(format!(
                "surface {id} at {width}x{height} would take this session past the \
                 {MAX_SURFACE_BYTES} byte surface budget"
            )));
        }
        self.surfaces.push(Surface {
            id,
            width,
            height,
            has_alpha,
            origin: None,
            // Zeroed, so a surface read before it is drawn is black rather
            // than whatever the allocator last held.
            pixels: vec![0; bytes],
            progressive: ProgressiveState::new(),
        });
        self.bytes += bytes;
        tracing::debug!(
            id,
            width,
            height,
            has_alpha,
            total = self.bytes,
            "created an egfx surface"
        );
        Ok(())
    }

    /// `RDPGFX_DELETE_SURFACE_PDU` (MS-RDPEGFX 2.2.2.10).
    ///
    /// Deleting a surface that is not there is not an error: MS-RDPEGFX
    /// 3.3.5.7 makes the client's own reset the only other thing that removes
    /// one, so the two can race.
    pub fn delete(&mut self, id: u16) {
        if let Some(at) = self.surfaces.iter().position(|s| s.id == id) {
            self.bytes = self.bytes.saturating_sub(self.surfaces[at].bytes());
            self.surfaces.remove(at);
        }
    }

    /// The surface with this id.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`], because a command naming a surface that was
    /// never created means the server and the client disagree about what
    /// exists, and drawing the rest of the frame onto the wrong thing is
    /// worse than stopping.
    pub fn get_mut(&mut self, id: u16, what: &str) -> Result<&mut Surface> {
        self.surfaces
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| unknown_surface(id, what))
    }

    /// The surface with this id, immutably.
    ///
    /// # Errors
    ///
    /// As [`SurfaceStore::get_mut`].
    pub fn get(&self, id: u16, what: &str) -> Result<&Surface> {
        self.surfaces
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| unknown_surface(id, what))
    }

    /// Two surfaces at once, for a cross surface copy.
    ///
    /// Returns `None` when the two ids name the same surface, which is the
    /// case [`Surface::blit_within`] handles instead.
    ///
    /// # Errors
    ///
    /// As [`SurfaceStore::get_mut`], for whichever is missing.
    pub fn pair(
        &mut self,
        src: u16,
        dest: u16,
        what: &str,
    ) -> Result<Option<(&Surface, &mut Surface)>> {
        if src == dest {
            return Ok(None);
        }
        let si = self
            .surfaces
            .iter()
            .position(|s| s.id == src)
            .ok_or_else(|| unknown_surface(src, what))?;
        let di = self
            .surfaces
            .iter()
            .position(|s| s.id == dest)
            .ok_or_else(|| unknown_surface(dest, what))?;
        // `split_at_mut` at the higher index is the only way to hold two
        // `&mut` into one `Vec` without `unsafe`, and this crate forbids it.
        let (low, high) = self.surfaces.split_at_mut(si.max(di));
        let (source, destination) = if si < di {
            (low.get(si), high.get_mut(0))
        } else {
            (high.first().map(|s| s as &Surface), low.get_mut(di))
        };
        match (source, destination) {
            (Some(s), Some(d)) => Ok(Some((s, d))),
            _ => Err(unknown_surface(src, what)),
        }
    }
}

/// The rectangle a `width` by `height` paste at `dest` covers.
fn translated(dest: Point16, width: u16, height: u16) -> Result<RectExclusive> {
    let (Some(right), Some(bottom)) = (dest.x.checked_add(width), dest.y.checked_add(height))
    else {
        return Err(RdpError::Protocol(format!(
            "a {width}x{height} paste at ({}, {}) runs past the coordinate space \
             (MS-RDPEGFX 2.2.2.7)",
            dest.x, dest.y
        )));
    };
    Ok(RectExclusive {
        left: dest.x,
        top: dest.y,
        right,
        bottom,
    })
}

fn short(id: u16) -> RdpError {
    RdpError::Protocol(format!("surface {id} is shorter than its geometry"))
}

fn unknown_surface(id: u16, what: &str) -> RdpError {
    RdpError::Protocol(format!(
        "{what} named surface {id}, which was never created (MS-RDPEGFX 2.2.2.9)"
    ))
}

fn dst_error(id: u16, e: &rdp_codecs::PixelError) -> RdpError {
    RdpError::Protocol(format!("surface {id} could not take a destination: {e}"))
}

/// A rectangle, for the assertions in the tests below.
#[cfg(test)]
fn rect_for_test(left: u16, top: u16, right: u16, bottom: u16) -> RectExclusive {
    RectExclusive {
        left,
        top,
        right,
        bottom,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(w: u16, h: u16) -> SurfaceStore {
        let mut store = SurfaceStore::new();
        store
            .create(1, w, h, pixel_format::XRGB_8888)
            .expect("creates");
        store
    }

    fn rect(left: u16, top: u16, right: u16, bottom: u16) -> RectExclusive {
        RectExclusive {
            left,
            top,
            right,
            bottom,
        }
    }

    fn red() -> Color32 {
        // `RDPGFX_COLOR32` is B, G, R, XA on the wire.
        Color32 {
            b: 0,
            g: 0,
            r: 0xFF,
            xa: 0x40,
        }
    }

    /// A surface is created once, counted against the budget, and freed when
    /// it is deleted.
    #[test]
    fn surfaces_are_created_counted_and_deleted() {
        let mut store = store_with(4, 4);
        assert_eq!(store.len(), 1);
        assert_eq!(store.bytes(), 4 * 4 * 4);

        let err = store
            .create(1, 4, 4, pixel_format::XRGB_8888)
            .expect_err("duplicate");
        assert!(err.to_string().contains("twice"), "{err}");

        let err = store.create(2, 4, 4, 0x77).expect_err("bad format");
        assert!(err.to_string().contains("0x77"), "{err}");

        store.delete(1);
        assert!(store.is_empty());
        assert_eq!(store.bytes(), 0);
        // Deleting again is a no op, not a panic.
        store.delete(1);
    }

    /// The budget is the whole reason a hostile `CreateSurface` is not an
    /// unbounded allocation.
    #[test]
    fn the_surface_budget_refuses_an_impossible_request() {
        let mut store = SurfaceStore::new();
        // 65535 * 65535 * 4 is 17,179,344,900 bytes, far past the budget.
        let err = store
            .create(1, u16::MAX, u16::MAX, pixel_format::XRGB_8888)
            .expect_err("budget");
        assert!(err.to_string().contains("budget"), "{err}");
        assert!(store.is_empty());
    }

    /// Every rectangle is checked against the surface before a pixel moves,
    /// because `rdp-pdu` cannot: it does not know the geometry.
    #[test]
    fn a_rectangle_outside_the_surface_is_refused() {
        let mut store = store_with(4, 4);
        let s = store.get_mut(1, "a test").expect("surface");
        assert!(s.bounded(rect(0, 0, 4, 4), "a test").is_ok());
        assert!(s.bounded(rect(0, 0, 5, 4), "a test").is_err());
        assert!(s.bounded(rect(3, 3, 5, 5), "a test").is_err());
        // Inverted edges, which `RectExclusive::width` refuses.
        assert!(s.bounded(rect(3, 0, 1, 4), "a test").is_err());
    }

    /// A fill writes the colour in RGBA order, forces alpha opaque on an
    /// XRGB surface, and copies out unchanged.
    #[test]
    fn a_solid_fill_reorders_the_colour_and_reads_back() {
        let mut store = store_with(2, 2);
        let s = store.get_mut(1, "a test").expect("surface");
        s.fill(rect(0, 0, 2, 2), red()).expect("fills");

        let mut out = Vec::new();
        s.copy_out(rect(0, 0, 2, 2), &mut out).expect("copies");
        assert_eq!(out.len(), 2 * 2 * 4);
        for px in out.chunks_exact(4) {
            // R, G, B, A. The wire's `XA` of 0x40 is ignored on an XRGB
            // surface, which is what MS-RDPEGFX 2.2.2.4 means by X.
            assert_eq!(px, [0xFF, 0x00, 0x00, 0xFF]);
        }

        // A sub rectangle comes back with the right stride applied.
        let mut out = Vec::new();
        s.copy_out(rect(1, 0, 2, 1), &mut out).expect("copies");
        assert_eq!(out.len(), 4);
    }

    /// An ARGB surface keeps the alpha byte the fill named.
    #[test]
    fn an_argb_surface_keeps_the_fill_alpha() {
        let mut store = SurfaceStore::new();
        store
            .create(9, 1, 1, pixel_format::ARGB_8888)
            .expect("creates");
        let s = store.get_mut(9, "a test").expect("surface");
        s.fill(rect(0, 0, 1, 1), red()).expect("fills");
        let mut out = Vec::new();
        s.copy_out(rect(0, 0, 1, 1), &mut out).expect("copies");
        assert_eq!(out, vec![0xFF, 0x00, 0x00, 0x40]);
    }

    /// A decoder writes through the view, and what it wrote is at the right
    /// place in the surface. This is the property the whole stride argument
    /// rests on: one write, into the middle of a larger buffer.
    #[test]
    fn a_view_writes_into_the_middle_of_the_surface() {
        let mut store = store_with(4, 4);
        let s = store.get_mut(1, "a test").expect("surface");
        {
            let mut view = s.view(rect(1, 1, 3, 3), "a test").expect("view");
            assert_eq!(view.width(), 2);
            assert_eq!(view.height(), 2);
            for y in 0..2 {
                view.row(y).copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            }
        }
        // Row 0 is untouched, row 1 has the two pixels at x = 1 and x = 2.
        let mut out = Vec::new();
        s.copy_out(rect(0, 0, 4, 1), &mut out).expect("copies");
        assert!(out.iter().all(|b| *b == 0), "row zero was written");

        let mut out = Vec::new();
        s.copy_out(rect(0, 1, 4, 2), &mut out).expect("copies");
        assert_eq!(&out[0..4], &[0, 0, 0, 0]);
        assert_eq!(&out[4..12], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&out[12..16], &[0, 0, 0, 0]);
    }

    /// Scrolling a window is an overlapping copy, and getting the row order
    /// wrong smears the first row down the whole rectangle.
    #[test]
    fn an_overlapping_copy_moves_content_rather_than_smearing_it() {
        let mut store = store_with(1, 4);
        let s = store.get_mut(1, "a test").expect("surface");
        for y in 0..4u8 {
            let mut view = s
                .view(rect(0, y.into(), 1, u16::from(y) + 1), "a test")
                .expect("view");
            view.row(0).copy_from_slice(&[y, y, y, 0xFF]);
        }

        // Move rows 0..3 down one, which overlaps.
        s.blit_within(rect(0, 0, 1, 3), Point16 { x: 0, y: 1 })
            .expect("blits");
        let mut out = Vec::new();
        s.copy_out(rect(0, 0, 1, 4), &mut out).expect("copies");
        let rows: Vec<u8> = out.chunks_exact(4).map(|c| c[0]).collect();
        assert_eq!(rows, vec![0, 0, 1, 2], "rows moved down by one");
    }

    /// A cache paste writes packed source rows at the destination, and a
    /// source that is too short is refused rather than read past.
    #[test]
    fn a_packed_paste_lands_where_it_was_told_and_checks_its_source() {
        let mut store = store_with(2, 2);
        let s = store.get_mut(1, "a test").expect("surface");
        let src = [9u8; 4];
        let rect = s
            .write_packed(Point16 { x: 1, y: 1 }, 1, 1, &src)
            .expect("pastes");
        assert_eq!(rect, super::rect_for_test(1, 1, 2, 2));

        let err = s
            .write_packed(Point16 { x: 0, y: 0 }, 2, 2, &src)
            .expect_err("short source");
        assert!(err.to_string().contains("source bytes"), "{err}");

        let err = s
            .write_packed(Point16 { x: 2, y: 2 }, 1, 1, &src)
            .expect_err("outside");
        assert!(err.to_string().contains("surface 1"), "{err}");
    }

    /// A cross surface copy needs two mutable views of one `Vec`, which is
    /// the case `pair` exists for, and a same id pair is refused so the
    /// caller uses the overlapping path instead.
    #[test]
    fn a_pair_hands_out_two_surfaces_and_refuses_one() {
        let mut store = store_with(2, 2);
        store
            .create(2, 2, 2, pixel_format::XRGB_8888)
            .expect("creates");

        assert!(store.pair(1, 1, "a test").expect("same").is_none());
        {
            let (src, dest) = store.pair(1, 2, "a test").expect("ok").expect("two");
            assert_eq!(src.id, 1);
            assert_eq!(dest.id, 2);
        }
        {
            let (src, dest) = store.pair(2, 1, "a test").expect("ok").expect("two");
            assert_eq!(src.id, 2);
            assert_eq!(dest.id, 1);
        }
        assert!(store.pair(1, 3, "a test").is_err());
        assert!(store.pair(3, 1, "a test").is_err());
    }
}
