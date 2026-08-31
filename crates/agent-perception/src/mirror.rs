//! The framebuffer mirror: the plane's own copy of the remote screen.
//!
//! `00 R5` and `03 §2`. A mirror is an RGBA8888 image owned by the agent
//! plane, one per session, fed by the same `SessionEvent::FramebufferUpdate`
//! stream the webview encoder is fed from, kept current by applying every rect
//! in order. It is the second consumer of an event that today has one, and it
//! exists because the running application keeps no server side framebuffer at
//! all: the only complete picture of any session lives in a WebGL texture
//! inside a webview process, so a session with no window showing it has no
//! picture anywhere (`03 §1.4`).
//!
//! ## Why this is not `vnc_core::pixel::Framebuffer`
//!
//! `crates/vnc-core/src/pixel/framebuffer.rs` already holds a complete,
//! tested `Framebuffer` with a clipped `apply`, an overlap safe `copy_rect`
//! and a `thumbnail_rgba`. Reusing it was the obvious move and it is refused
//! for three reasons, in order of weight.
//!
//! 1. **The H.264 arm.** `framebuffer.rs:90` is a documented no-op, and `00 R6`
//!    is that no-op promoted to the sharpest finding in the set. A mirror built
//!    on it holds stale pixels in exactly the region that is moving. Coverage
//!    has to be tracked at the moment a rect is applied, and `03 §8 OQ-5` asks
//!    whether `Framebuffer` grows a coverage notion or a wrapper owns one; a
//!    wrapper cannot see the H.264 arm being skipped, so it would have to
//!    re-inspect every rect and stay in step with `resize` by hand, which is
//!    the cost that ruling names.
//! 2. **The dependency.** `vnc-core` is the RFB protocol crate: decoders,
//!    tokio, a transport. `00 R5` says the mirror must not be visible from
//!    inside `vnc-core`, and `01 §3` says this crate is "pixels with no
//!    transport". Taking `vnc-core` to get one 170 line file would put the
//!    whole RFB stack behind a crate that is meant to be inert, and it would
//!    make a headless `deskd` link the protocol crate to take a screenshot of
//!    an RDP session.
//! 3. **The JPEG path.** `pixel/mod.rs` records why `Framebuffer` did not move
//!    to `remote-pixel` with everything else: it decodes JPEG through
//!    `crate::encodings`, and `remote-pixel` is meant to have no dependencies.
//!    We decode through `image`, which we need anyway for the encode side.
//!
//! What is reimplemented is small: a blit, a copy, a resize. It is written to
//! match `framebuffer.rs` deliberately, including the row ordering in
//! [`Mirror::copy_rect`], so that `03 §9 A2` can assert the two produce
//! identical pixels from identical input. **If one of them is fixed, fix the
//! other.** The two are compared tile by tile by `fb_probe.rs`'s method for
//! exactly this reason.

use crate::budget::{mirror_bytes, MirrorBudget};
use crate::coverage::Coverage;
use crate::damage::{plan_change_crop, ChangePlan, DamageLog, DEFAULT_CROP_COVERAGE_LIMIT};
use crate::encode::{
    crop_rgba, decode_jpeg_to_rgba, downscale_to_long_edge, encode_rgba, EncodedImage,
};
use crate::error::PerceptionError;
use crate::ladder::{
    FrameObservation, Read, ReadKind, ReadRequest, Rung, ScreenFacts, Space, StalePolicy,
};
use crate::signals::PerceptionSignals;
use crate::transform::ImageSpace;
use limb_core::fence::GeometryGeneration;
use limb_core::observation::Timestamp;
use remote_core::events::{DecodedRect, RectPayload};
use remote_core::geometry::Rect;

/// Whether this session's negotiated encodings can produce a mirror worth
/// reading, judged before a byte of memory is allocated.
///
/// `00 R6`, and this is the predicate the plane needs to negotiate H.264 away
/// **up front**. The two arguments are the two the existing code already reads
/// together: `encodings_for` puts `OPEN_H264` in the SetEncodings list when
/// `settings.allow_h264 && caps.supports_h264`
/// (`crates/vnc-core/src/quality/mod.rs:373`), and `supports_h264` is
/// `!version.is_apple_screen_sharing`, meaning it is true for nearly every
/// server (`crates/vnc-core/src/proto/handshake.rs:176`). Medium, Auto and Low
/// all set `allow_h264: true`, so **the default preset on a capable server
/// gets H.264 and a naive mirror silently rots.**
///
/// The sequence when this answers [`MirrorSafety::H264Advertised`] is fixed by
/// `03 §3.4` and the order matters: set `allow_h264 = false`, send
/// SetEncodings, send `Refresh`, and treat the mirror as priming until the
/// answer arrives. Turning H.264 off without the refresh leaves every region a
/// live decoder context owned holding whatever the mirror last put there,
/// which is black.
pub fn mirror_safety(allow_h264: bool, server_supports_h264: bool) -> MirrorSafety {
    if allow_h264 && server_supports_h264 {
        MirrorSafety::H264Advertised
    } else {
        MirrorSafety::Safe
    }
}

/// The answer [`mirror_safety`] gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorSafety {
    /// Nothing in the negotiated set can reach the mirror as an H.264 rect.
    Safe,
    /// H.264 is on the wire, so the mirror WILL go stale in the moving region
    /// and every read of that region will refuse. Renegotiate before
    /// attaching.
    H264Advertised,
}

impl MirrorSafety {
    pub fn is_safe(self) -> bool {
        matches!(self, MirrorSafety::Safe)
    }
}

/// The plane's copy of one session's screen.
#[derive(Debug)]
pub struct Mirror {
    width: u16,
    height: u16,
    /// RGBA8888, row major, `width * height * 4` bytes. The only allocation.
    data: Vec<u8>,
    coverage: Coverage,
    generation: GeometryGeneration,
    last_read: Timestamp,
    screens: ScreenFacts,
    signals: PerceptionSignals,
}

fn opaque_black(pixels: usize) -> Vec<u8> {
    // `[u8]::repeat` fills by doubling memcpy, which is far quicker than
    // touching every alpha byte individually on a 4K framebuffer. Taken from
    // `framebuffer.rs:14` along with the reason.
    [0u8, 0, 0, 255].repeat(pixels)
}

impl Mirror {
    /// Allocate. Callers go through [`MirrorSlot::attach`], which applies the
    /// budget first.
    fn new(width: u16, height: u16, generation: GeometryGeneration, at: Timestamp) -> Self {
        Mirror {
            width,
            height,
            data: opaque_black(width as usize * height as usize),
            coverage: Coverage::new(width, height),
            generation,
            last_read: at,
            screens: ScreenFacts::unknown(),
            signals: PerceptionSignals::new(),
        }
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    /// What this mirror costs, for `session.stats` (`03 §9 A6`: an operator
    /// can answer "why is this process holding 380 MB" without a profiler).
    pub fn bytes(&self) -> u64 {
        mirror_bytes(self.width, self.height)
    }

    pub fn generation(&self) -> GeometryGeneration {
        self.generation
    }

    /// Has every tile been painted at least once?
    ///
    /// `03 §9 A3`. A mirror attached to a session that has been connected for
    /// ten minutes starts as opaque black, and only a `Refresh` fills it.
    pub fn is_primed(&self) -> bool {
        self.coverage.is_primed()
    }

    /// The signals the pixel path is the authority on (`00 R34`, `00 R39a`).
    pub fn signals(&self) -> &PerceptionSignals {
        &self.signals
    }

    pub fn screens(&self) -> &ScreenFacts {
        &self.screens
    }

    /// RGBA8888. For a test or a diff, never for a caller assembling its own
    /// answer: everything that leaves this crate goes through [`Mirror::read`]
    /// so it cannot leave without its coverage.
    pub fn as_rgba(&self) -> &[u8] {
        &self.data
    }

    /// The monitor layout changed. Called with the generation the plane's
    /// fence bumped to (`00 R10`).
    pub fn layout_changed(&mut self, screens: ScreenFacts, generation: GeometryGeneration) {
        self.screens = screens;
        self.generation = generation;
    }

    /// The remote desktop changed resolution.
    ///
    /// Pixels that overlap are kept, top left anchored, exactly as
    /// `Framebuffer::resize` does, so the picture does not flash. Their
    /// COVERAGE is not kept, so nothing is served as current until the server
    /// paints it again: see [`Coverage::reset`].
    pub fn resize(&mut self, width: u16, height: u16, generation: GeometryGeneration) {
        self.generation = generation;
        if width == self.width && height == self.height {
            return;
        }
        let mut fresh = opaque_black(width as usize * height as usize);
        let copy_w = self.width.min(width) as usize;
        let copy_h = self.height.min(height) as usize;
        for y in 0..copy_h {
            let src = y * self.width as usize * 4;
            let dst = y * width as usize * 4;
            fresh[dst..dst + copy_w * 4].copy_from_slice(&self.data[src..src + copy_w * 4]);
        }
        self.width = width;
        self.height = height;
        self.data = fresh;
        self.coverage.reset(width, height);
    }

    /// Apply one coalesced `SessionEvent::FramebufferUpdate`.
    ///
    /// Rect by rect and in order, which is the only order that composites
    /// correctly: a `CopyRect` reads pixels an earlier rect in the same update
    /// wrote.
    pub fn apply(&mut self, rects: &[DecodedRect]) {
        self.signals.observe(rects);
        for decoded in rects {
            self.apply_one(decoded);
        }
    }

    fn apply_one(&mut self, decoded: &DecodedRect) {
        let r = decoded.rect;
        if r.is_empty() {
            return;
        }
        match &decoded.payload {
            RectPayload::Rgba(pixels) => {
                let needed = r.width as usize * r.height as usize * 4;
                if pixels.len() < needed {
                    // A short payload cannot be composited and the pixels
                    // under it are whatever was there before. `blit_rgba`
                    // stops at the last complete row rather than reading out
                    // of bounds, and the rows it did not write are exactly the
                    // silent staleness `00 R6` is about, arriving from a
                    // different direction.
                    tracing::warn!(
                        rect = ?r,
                        got = pixels.len(),
                        needed,
                        "short RGBA rect, marking the region stale rather than mirroring it"
                    );
                    self.blit_rgba(r, pixels);
                    self.coverage.mark_stale(r);
                    return;
                }
                self.blit_rgba(r, pixels);
                self.coverage.mark_written(r);
            }
            RectPayload::Jpeg(bytes) => match decode_jpeg_to_rgba(bytes) {
                Ok((jw, jh, pixels)) => {
                    let w = u32::from(r.width).min(jw);
                    let h = u32::from(r.height).min(jh);
                    if jw == w && w == u32::from(r.width) {
                        self.blit_rgba(Rect::new(r.x, r.y, w as u16, h as u16), &pixels);
                    } else {
                        // The JPEG is a different width from the rect, so the
                        // row stride differs and it goes row by row.
                        for y in 0..h {
                            let src = (y as usize * jw as usize) * 4;
                            let row = &pixels[src..src + w as usize * 4];
                            self.blit_rgba(
                                Rect::new(r.x, r.y.saturating_add(y as u16), w as u16, 1),
                                row,
                            );
                        }
                    }
                    self.coverage
                        .mark_written(Rect::new(r.x, r.y, w as u16, h as u16));
                }
                Err(e) => {
                    // `Framebuffer::apply` logs and moves on here
                    // (`framebuffer.rs:83`), which is right for a renderer a
                    // person is watching, because the next repaint fixes it
                    // and the person sees the glitch. An agent is not
                    // watching, so the region is marked stale as well.
                    tracing::warn!(rect = ?r, error = %e, "undecodable JPEG rect, marking the region stale");
                    self.coverage.mark_stale(r);
                }
            },
            RectPayload::CopyRect { src_x, src_y } => {
                let src = Rect::new(*src_x, *src_y, r.width, r.height);
                self.copy_rect(src, r);
                self.coverage.mark_copied(src, r);
            }
            RectPayload::H264 { data, .. } => {
                // `00 R6`, and this arm is the whole reason this crate exists.
                //
                // `framebuffer.rs:90` leaves this empty with a comment saying
                // the webview decodes it, which is true and which leaves the
                // native image holding its previous contents for these rects
                // forever, with no error anywhere. Here the pixels are left
                // alone too, because there is no decoder, and the region is
                // marked stale so no read can hand it back as current.
                //
                // A zero length payload is a pure control message (apply the
                // flags, decode nothing), so it changes no pixels and poisons
                // nothing.
                if !data.is_empty() {
                    self.coverage.mark_stale(r);
                }
            }
        }
    }

    /// Copy a tightly packed RGBA block to `rect`, clipped.
    ///
    /// The clipping is defensive in the same way `framebuffer.rs:98` is: a
    /// malformed rect can never write out of bounds, and a short payload stops
    /// the loop rather than reading past the end of the slice.
    fn blit_rgba(&mut self, rect: Rect, pixels: &[u8]) {
        let fb_w = self.width as usize;
        let fb_h = self.height as usize;
        let (x, y) = (rect.x as usize, rect.y as usize);
        if x >= fb_w || y >= fb_h {
            return;
        }
        let src_stride = rect.width as usize * 4;
        let copy_w = (rect.width as usize).min(fb_w - x);
        let copy_h = (rect.height as usize).min(fb_h - y);
        for row in 0..copy_h {
            let src = row * src_stride;
            if src + copy_w * 4 > pixels.len() {
                break;
            }
            let dst = ((y + row) * fb_w + x) * 4;
            self.data[dst..dst + copy_w * 4].copy_from_slice(&pixels[src..src + copy_w * 4]);
        }
    }

    /// CopyRect, overlap safe and allocation free.
    ///
    /// `copy_within` is a `memmove`, so overlap within a row pair is already
    /// handled. Visiting rows away from the destination (upwards when moving
    /// down, downwards when moving up) keeps rows that are still needed as
    /// sources from being overwritten first. This is `framebuffer.rs:126`
    /// including the row ordering, and the ordering is the part that is easy
    /// to get wrong and invisible until a list scrolls.
    fn copy_rect(&mut self, src: Rect, dst: Rect) {
        let fb_w = self.width as usize;
        let fb_h = self.height as usize;
        let (sx, sy) = (src.x as usize, src.y as usize);
        let (dx, dy) = (dst.x as usize, dst.y as usize);
        if sx >= fb_w || sy >= fb_h || dx >= fb_w || dy >= fb_h {
            return;
        }
        let w = (dst.width as usize).min(fb_w - sx).min(fb_w - dx);
        let h = (dst.height as usize).min(fb_h - sy).min(fb_h - dy);
        if w == 0 || h == 0 {
            return;
        }
        let row_bytes = w * 4;
        let mut copy_row = |row: usize| {
            let s = ((sy + row) * fb_w + sx) * 4;
            let d = ((dy + row) * fb_w + dx) * 4;
            self.data.copy_within(s..s + row_bytes, d);
        };
        if dy > sy {
            for row in (0..h).rev() {
                copy_row(row);
            }
        } else {
            for row in 0..h {
                copy_row(row);
            }
        }
    }

    /// The whole framebuffer as a rectangle.
    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }

    /// Answer one read.
    ///
    /// The order of the checks is the order of the rulings, and it is chosen so
    /// that the cheapest refusal happens first: the fence (`00 R10`) before the
    /// geometry, the geometry before the coverage (`00 R6`), and the coverage
    /// before a single pixel is copied or encoded.
    pub fn read(
        &mut self,
        request: &ReadRequest,
        damage: &mut DamageLog,
        now: Timestamp,
    ) -> Result<Read, PerceptionError> {
        if let Some(fenced_at) = request.fence {
            if fenced_at != self.generation {
                return Err(limb_core::fence::GeometryRejected::Stale {
                    fenced_at,
                    current: self.generation,
                }
                .into());
            }
        }

        let bounds = self.bounds();
        let mut damage_rects: Vec<Rect> = Vec::new();
        let mut remaining = 0usize;
        let mut degraded = None;
        let mut consume = None;
        let (region, long_edge, rung) = match &request.kind {
            ReadKind::Frame { long_edge } => (bounds, Some(*long_edge), Rung::Frame),
            ReadKind::Region { rect } => {
                let clipped = rect.intersect(&bounds);
                if clipped.is_empty() || clipped != *rect {
                    return Err(PerceptionError::OutOfBounds {
                        region: *rect,
                        width: self.width,
                        height: self.height,
                    });
                }
                (clipped, None, Rung::Region)
            }
            ReadKind::Change { reader, margin } => {
                // Peeked and not taken. The reader is marked caught up at the
                // bottom of this function, once there is actually an answer,
                // so a refusal does not eat the changes it refused to show.
                let delta = damage.peek(*reader);
                consume = Some((*reader, delta.through));
                match plan_change_crop(&delta.rects, bounds, *margin, DEFAULT_CROP_COVERAGE_LIMIT) {
                    ChangePlan::Nothing => {
                        damage.advance(*reader, delta.through);
                        return Ok(Read::Unchanged {
                            generation: self.generation,
                            at: now,
                        });
                    }
                    ChangePlan::Crop {
                        rect,
                        damage: covered,
                        remaining: left,
                        ..
                    } => {
                        damage_rects = covered;
                        remaining = left;
                        (rect, None, Rung::Change)
                    }
                    ChangePlan::Degraded { reason, .. } => {
                        // `03 §9 A10`: say so, and fall back to the downscaled
                        // frame rather than quietly returning a full
                        // resolution crop of the whole desktop.
                        damage_rects = delta.rects;
                        degraded = Some(reason);
                        (bounds, Some(crate::encode::DEFAULT_LONG_EDGE), Rung::Frame)
                    }
                }
            }
        };

        let coverage = self.coverage_of(region, request.stale)?;

        let cropped = crop_rgba(&self.data, self.width, self.height, region);
        let (width, height, pixels, scale) = match long_edge {
            Some(edge) => downscale_to_long_edge(
                &cropped,
                u32::from(region.width),
                u32::from(region.height),
                edge,
            ),
            None => (
                u32::from(region.width),
                u32::from(region.height),
                cropped,
                1.0,
            ),
        };
        let bytes = encode_rgba(&pixels, width, height, request.encode)?;

        self.last_read = now;
        if let Some((reader, through)) = consume {
            damage.advance(reader, through);
        }

        Ok(Read::Frame(Box::new(FrameObservation {
            rung,
            space: Space {
                width: self.width,
                height: self.height,
            },
            image: EncodedImage {
                format: request.encode.format,
                space: ImageSpace {
                    region,
                    width,
                    height,
                    scale,
                },
                encoded_bytes: bytes.len(),
                bytes,
            },
            coverage,
            geometry_generation: self.generation,
            captured_at: now,
            screens: self.screens.screens.clone(),
            primary_known: self.screens.primary_known,
            damage: damage_rects,
            remaining_changes: remaining,
            degraded,
        })))
    }

    /// Refuse or annotate, per `00 R6` and the caller's policy.
    fn coverage_of(
        &self,
        region: Rect,
        policy: StalePolicy,
    ) -> Result<crate::coverage::FrameCoverage, PerceptionError> {
        let state = self.coverage.region_state(region);
        if state.is_complete() {
            return Ok(crate::coverage::FrameCoverage::Complete);
        }
        let stale_regions = self.coverage.stale_regions(region)?;
        match policy {
            StalePolicy::Annotate => Ok(crate::coverage::FrameCoverage::Partial { stale_regions }),
            // Two refusals rather than one, because the repairs differ. A
            // priming mirror resolves on its own once the server paints; a
            // poisoned one resolves only when the session stops advertising
            // H.264, which is the plane's job and not the agent's.
            StalePolicy::Refuse if state.stale == 0 => Err(PerceptionError::Priming {
                region,
                tiles: state.tiles,
                never_written: state.never_written,
            }),
            StalePolicy::Refuse => Err(PerceptionError::Stale {
                region,
                stale_regions,
            }),
        }
    }
}

/// One session's mirror, if it has one, with the lifecycle `00 R5` requires.
///
/// The capability half of that ruling is not here. `perceive.frame` on the
/// token decides whether a mirror may EVER exist for a session, and that is a
/// grant question the plane answers before it calls [`MirrorSlot::attach`].
/// This type is the other half: whether one does right now. Neither alone is
/// sufficient, which is what `03 §2.7` means by "B and C together, and they
/// are not really alternatives": a capability with no lifecycle underneath it
/// still holds 380 MB for twelve idle 4K sessions nobody has asked a question
/// about in an hour.
#[derive(Debug)]
pub struct MirrorSlot {
    budget: MirrorBudget,
    mirror: Option<Mirror>,
}

impl MirrorSlot {
    pub fn new(budget: MirrorBudget) -> Self {
        MirrorSlot {
            budget,
            mirror: None,
        }
    }

    pub fn budget(&self) -> MirrorBudget {
        self.budget
    }

    pub fn is_attached(&self) -> bool {
        self.mirror.is_some()
    }

    /// Bytes this session's mirror holds, or zero. For `session.stats`.
    pub fn bytes(&self) -> u64 {
        self.mirror.as_ref().map_or(0, Mirror::bytes)
    }

    pub fn get(&self) -> Option<&Mirror> {
        self.mirror.as_ref()
    }

    pub fn get_mut(&mut self) -> Option<&mut Mirror> {
        self.mirror.as_mut()
    }

    /// Allocate, on the first frame request (`00 R5`).
    ///
    /// `total_bytes_in_use` is what every OTHER mirror in the process holds.
    /// The plane sums it, because the plane is the only thing that knows how
    /// many sessions there are.
    ///
    /// A mirror attached to a session that has been connected for ten minutes
    /// starts as opaque black and stays that way until damage arrives, so the
    /// caller's next act is `ClientCommand::Refresh`
    /// (`crates/remote-core/src/commands.rs:35`), which forces a full non
    /// incremental update. Until it lands, every read refuses with
    /// [`PerceptionError::Priming`] rather than returning the black
    /// (`03 §9 A3`).
    pub fn attach(
        &mut self,
        width: u16,
        height: u16,
        generation: GeometryGeneration,
        total_bytes_in_use: u64,
        now: Timestamp,
    ) -> Result<&mut Mirror, PerceptionError> {
        if self.mirror.is_none() {
            self.budget.admit(width, height, total_bytes_in_use)?;
            tracing::debug!(
                width,
                height,
                bytes = mirror_bytes(width, height),
                "attaching a framebuffer mirror"
            );
            self.mirror = Some(Mirror::new(width, height, generation, now));
        }
        Ok(self.mirror.as_mut().expect("just allocated"))
    }

    /// Free it, whatever its state.
    pub fn detach(&mut self) -> u64 {
        match self.mirror.take() {
            Some(m) => m.bytes(),
            None => 0,
        }
    }

    /// Free it if nothing has read it for the idle timeout (`00 R5`).
    ///
    /// Returns the bytes freed. Called on a timer by the plane; this crate
    /// starts no clock of its own, which is the discipline `limb-core` and
    /// `agent-lease` already follow so that the rules are testable without a
    /// runtime.
    pub fn reap(&mut self, now: Timestamp) -> u64 {
        let idle = match &self.mirror {
            Some(m) => now.0.saturating_sub(m.last_read.0) >= self.budget.idle_timeout_ms,
            None => false,
        };
        if idle {
            let bytes = self.detach();
            tracing::debug!(bytes, "freeing an idle framebuffer mirror");
            return bytes;
        }
        0
    }

    /// Feed the mirror, if there is one. A session with no mirror pays
    /// nothing, which is `03 §9 A5`.
    pub fn apply(&mut self, rects: &[DecodedRect]) {
        if let Some(m) = &mut self.mirror {
            m.apply(rects);
        }
    }

    /// The desktop resized. The mirror is dropped rather than kept when the
    /// new geometry is over budget: a session that resizes from 1080p to
    /// something enormous must not go on serving reads from the old picture,
    /// and `00 R5` says refuse rather than degrade.
    pub fn resize(
        &mut self,
        width: u16,
        height: u16,
        generation: GeometryGeneration,
        total_bytes_in_use: u64,
    ) -> Result<(), PerceptionError> {
        let Some(m) = &mut self.mirror else {
            return Ok(());
        };
        let others = total_bytes_in_use.saturating_sub(m.bytes());
        match self.budget.admit(width, height, others) {
            Ok(_) => {
                m.resize(width, height, generation);
                Ok(())
            }
            Err(refused) => {
                self.detach();
                Err(refused.into())
            }
        }
    }

    /// Answer one read, or say there is no mirror to answer from.
    pub fn read(
        &mut self,
        request: &ReadRequest,
        damage: &mut DamageLog,
        now: Timestamp,
    ) -> Result<Read, PerceptionError> {
        match &mut self.mirror {
            Some(m) => m.read(request, damage, now),
            None => Err(PerceptionError::NoMirror),
        }
    }
}

impl Default for MirrorSlot {
    fn default() -> Self {
        MirrorSlot::new(MirrorBudget::default())
    }
}
