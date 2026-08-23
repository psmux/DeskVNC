//! The graphics pipeline, `Microsoft::Windows::RDS::Graphics` (MS-RDPEGFX,
//! PRDRDP/04 §3).
//!
//! # The shape of one message
//!
//! A drdynvc message on this channel is an `RDP_SEGMENTED_DATA` envelope
//! holding RDP 8.0 bulk compressed bytes, and those bytes are a concatenation
//! of `RDPGFX_HEADER` commands (MS-RDPEGFX 2.2.1.5). So one message is:
//! decompress once, then walk commands until the buffer is empty. A frame is
//! `RDPGFX_START_FRAME_PDU`, some drawing, `RDPGFX_END_FRAME_PDU`, and the
//! acknowledgement we send back.
//!
//! # ZGFX, and the reason this file is careful about parse failures
//!
//! `docs/RDP_SPEC_NOTES.md` §1.1 records that the ZGFX token table in
//! `rdp_codecs::zgfx` is a reconstruction rather than a transcription: the
//! eleven match rows prove themselves arithmetically and the literal rows do
//! not. If one literal row is wrong, decompression produces a wrong byte
//! every few thousand, and a wrong byte inside an EGFX message is usually a
//! `cmdId` or a `pduLength` that does not parse.
//!
//! That note also says the reconstruction "must not go live before the vector
//! is run". This is the commit that puts it live, so the mitigation is the
//! other half of what the note asks for: a message that decompresses and then
//! fails to parse is reported as
//! [`RdpError::Protocol`] naming ZGFX and the specification note, rather than
//! as a generic PDU error. The failure mode is loud and it points at the right
//! file. See [`Egfx::commands`] and the test that pins the message.
//!
//! # Per frame allocations
//!
//! Three things are allocated once and reused for the life of the channel:
//! the 2.5 MB ZGFX history (`rdp_codecs::zgfx::HISTORY`), the decompression
//! output buffer [`Egfx::message`], and every codec scratch in
//! [`decode::Decoders`]. A `WIRE_TO_SURFACE_1` hands the decoder a slice of
//! the decompression buffer and a [`DstView`](rdp_codecs::DstView) over the
//! destination surface, so there is no per rectangle intermediate buffer
//! anywhere on the path (D9).
//!
//! What is allocated per frame is the handover: one `Vec<u8>` per rectangle
//! that reaches the shell, because `remote_core::RectPayload::Rgba` owns its
//! bytes, and the `Vec<DecodedRect>` that carries them. That is the same cost
//! the legacy bitmap path pays at
//! `crates/rdp-core/src/session/graphics.rs:205`.

pub mod cache;
pub mod decode;
pub mod surface;

use rdp_codecs::zgfx::Rdp8Decompressor;
use rdp_pdu::update::RectExclusive;
use rdp_pdu::vc::egfx::{caps_version, Capset, EgfxPdu};
use rdp_pdu::{Encode, Writer};
use remote_core::{DecodedRect, Rect, RectPayload, SessionEvent};

use crate::channels::dvc::ReplyBuf;
use crate::channels::ChannelCtx;
use crate::error::{RdpError, Result};

use cache::BitmapCache;
use decode::Decoders;
use surface::SurfaceStore;

/// The capability sets we advertise (MS-RDPEGFX 2.2.2.18, PRDRDP/04 §3.2).
///
/// Version 8 and version 8.1, and nothing above them. The reason is the codec
/// set: from version 10 the server may use H.264, which this build cannot
/// decode because `rdp_codecs::avc420` is a metablock parser and there is no
/// decoder behind it, and advertising a version 10 set with
/// `RDPGFX_CAPS_FLAG_AVC_DISABLED` would be advertising a version whose other
/// semantics we have never tested against a server. Every RDP 8.0 server
/// confirms version 8 and every RDP 8.1 server confirms 8.1, so the coverage
/// lost is nil.
///
/// The flags are zero on both. `RDPGFX_CAPS_FLAG_THINCLIENT` and
/// `RDPGFX_CAPS_FLAG_SMALL_CACHE` both shrink the cache the server may use
/// (MS-RDPEGFX 2.2.3.1), and we would rather have the 100 MB.
///
/// What this does not buy us is protection from RemoteFX Progressive, which
/// is available from version 8 and which this build cannot decode. There is
/// no capability bit that declines it, so the refusal is at the codec id and
/// it is loud: see [`CODEC_CAPROGRESSIVE`].
const ADVERTISED: [u32; 2] = [caps_version::V8, caps_version::V8_1];

/// `RDPGFX_CODECID_CAPROGRESSIVE` (MS-RDPEGFX 2.2.2.1).
///
/// Not in `rdp_pdu::vc::egfx::codec_id`, which lists the eight ids it needs.
/// It is named here so the refusal can say "progressive" rather than
/// "0x0009", because it is the one unsupported codec a Windows server is
/// likely to actually send.
pub const CODEC_CAPROGRESSIVE: u16 = 0x0009;

/// The graphics channel.
///
/// Boxed by its owner: the ZGFX history alone is 2.5 MB, and an enum whose
/// largest variant is that size would make every entry in the dynamic channel
/// table that size (`crate::channels::dvc::DynKind`).
pub struct Egfx {
    /// The RDP 8.0 decompressor and its history. One per channel, reset only
    /// when the channel itself is torn down: the server does not reset its
    /// own copy on `ResetGraphics` (PRDRDP/04 §4.12.3).
    zgfx: Rdp8Decompressor,
    /// The decompression output, allocated once and reused every message.
    message: Vec<u8>,
    surfaces: SurfaceStore,
    cache: BitmapCache,
    decoders: Decoders,
    /// A rectangle read out of one surface on its way into another or into
    /// the cache, reused.
    scratch: Vec<u8>,
    /// The capability set version the server confirmed, `None` until it does.
    confirmed: Option<u32>,
    /// `frameId` of the frame in progress (MS-RDPEGFX 2.2.2.11).
    open_frame: Option<u32>,
    /// `totalFramesDecoded`, which MS-RDPEGFX 2.2.2.13 defines as a running
    /// count over the life of the channel.
    frames_decoded: u32,
    /// Rectangles drawn since the last flush, waiting for the frame to end.
    pending: Vec<DecodedRect>,
}

/// Hand written for the same reason [`decode::Decoders`]'s is: the ZGFX
/// history is 2.5 MB and a derived `Debug` would put all of it in a log line.
/// What is printed instead is the state a reader of a trace actually wants.
impl std::fmt::Debug for Egfx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Egfx")
            .field("confirmed", &self.confirmed)
            .field("surfaces", &self.surfaces.len())
            .field("surface_bytes", &self.surfaces.bytes())
            .field("cache_entries", &self.cache.len())
            .field("cache_bytes", &self.cache.bytes())
            .field("open_frame", &self.open_frame)
            .field("frames_decoded", &self.frames_decoded)
            .finish()
    }
}

impl Default for Egfx {
    fn default() -> Self {
        Self::new()
    }
}

impl Egfx {
    /// Allocate the channel: the history window, the buffers and every codec
    /// scratch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            zgfx: Rdp8Decompressor::new(),
            message: Vec::new(),
            surfaces: SurfaceStore::new(),
            cache: BitmapCache::new(),
            decoders: Decoders::new(),
            scratch: Vec::new(),
            confirmed: None,
            open_frame: None,
            frames_decoded: 0,
            pending: Vec::new(),
        }
    }

    /// The capability set the server confirmed, for a log line and the tests.
    #[must_use]
    pub const fn confirmed(&self) -> Option<u32> {
        self.confirmed
    }

    /// Frames acknowledged so far.
    #[must_use]
    pub const fn frames_decoded(&self) -> u32 {
        self.frames_decoded
    }

    /// The channel is open: say what we can decode (MS-RDPEGFX 3.3.5.1).
    ///
    /// # Errors
    ///
    /// [`RdpError::Pdu`] if the advertisement will not encode, which cannot
    /// happen for a fixed two element list and is checked rather than
    /// asserted.
    pub fn opened(&mut self, replies: &mut ReplyBuf) -> Result<()> {
        // `Capset` borrows its body, and every set here carries the same
        // four bytes, so one static is all the borrow needs.
        let capsets = ADVERTISED
            .iter()
            .map(|version| Capset::new(*version, &CAPS_FLAGS_NONE))
            .collect();
        replies.emit(|buf| encode(&EgfxPdu::CapsAdvertise { capsets }, buf))
    }

    /// One complete drdynvc message on this channel.
    ///
    /// # Errors
    ///
    /// [`RdpError::Protocol`] for anything the graphics state machine cannot
    /// act on, always naming the command and, where it matters, the surface
    /// and the geometry.
    pub fn message(
        &mut self,
        message: &[u8],
        ctx: ChannelCtx,
        events: &mut Vec<SessionEvent>,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        // The whole `RDP_SEGMENTED_DATA` envelope goes to the decompressor,
        // descriptor byte and all. It walks the segments itself, and it has
        // to: an uncompressed segment still feeds the history window that the
        // next compressed one matches against (MS-RDPBCGR 3.1.8.4.2), which
        // `docs/RDP_SPEC_NOTES.md` §2.1 records as the reading PRDRDP/13 §6.4
        // got wrong. Parsing the envelope up here as well would be the same
        // walk twice.
        //
        // The buffer is taken out of `self` for the call so the borrow of the
        // decompressed bytes is disjoint from the `&mut self` the command
        // walk needs. It goes back before this function returns, on the error
        // path too, so its capacity survives.
        let mut buf = std::mem::take(&mut self.message);
        let decompressed = self.zgfx.decompress(message, &mut buf).map_err(|e| {
            RdpError::Protocol(format!(
                "the graphics channel could not decompress a {} byte message: {e} \
                 (MS-RDPEGFX 2.2.5.1)",
                message.len()
            ))
        });
        let result = match decompressed {
            Ok(()) => self.commands(&buf, ctx, events, replies),
            Err(e) => Err(e),
        };
        self.message = buf;
        result
    }

    /// Walk the commands one decompressed message holds
    /// (MS-RDPEGFX 2.2.1.5).
    ///
    /// A parse failure here is the ZGFX reconstruction's failure mode, so it
    /// is reported as one. See the module comment and
    /// `docs/RDP_SPEC_NOTES.md` §1.1.
    fn commands(
        &mut self,
        message: &[u8],
        ctx: ChannelCtx,
        events: &mut Vec<SessionEvent>,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        for item in EgfxPdu::iter(message) {
            let pdu = item.map_err(|e| zgfx_suspect(message.len(), &e))?;
            self.command(pdu, ctx, events, replies)?;
        }
        // A server is not obliged to wrap every command in a frame, and a
        // command outside one still drew something. Flushing at the end of
        // the message keeps that visible rather than holding it until the
        // next `END_FRAME` that may never come.
        self.flush(events);
        Ok(())
    }

    /// One `RDPGFX_HEADER` command.
    #[allow(clippy::too_many_lines)]
    fn command(
        &mut self,
        pdu: EgfxPdu<'_>,
        ctx: ChannelCtx,
        events: &mut Vec<SessionEvent>,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        match pdu {
            EgfxPdu::CapsConfirm { capset } => {
                if !ADVERTISED.contains(&capset.version) {
                    return Err(RdpError::Protocol(format!(
                        "the server confirmed graphics capability set 0x{:08x}, which this \
                         client did not advertise (MS-RDPEGFX 2.2.2.19)",
                        capset.version
                    )));
                }
                tracing::info!(
                    version = capset.version,
                    "the graphics capabilities were confirmed"
                );
                self.confirmed = Some(capset.version);
                // MS-RDPEGFX 3.3.5.4 puts the cache offer after the confirm.
                // Ours is empty, because nothing in this build saves a cache
                // between sessions (PRDRDP/04 §3.7); the server answers with
                // an equally empty reply and both sides start from nothing.
                replies.emit(|buf| {
                    encode(
                        &EgfxPdu::CacheImportOffer {
                            entries: Vec::new(),
                        },
                        buf,
                    )
                })
            }
            EgfxPdu::CreateSurface {
                surface_id,
                width,
                height,
                pixel_format,
            } => self
                .surfaces
                .create(surface_id, width, height, pixel_format),
            EgfxPdu::DeleteSurface { surface_id } => {
                self.surfaces.delete(surface_id);
                Ok(())
            }
            EgfxPdu::MapSurfaceToOutput {
                surface_id,
                output_origin_x,
                output_origin_y,
                ..
            } => self.map(surface_id, output_origin_x, output_origin_y),
            EgfxPdu::MapSurfaceToScaledOutput {
                surface_id,
                output_origin_x,
                output_origin_y,
                target_width,
                target_height,
                ..
            } => {
                let surface = self.surfaces.get(surface_id, "a scaled output mapping")?;
                // Nothing in this client scales a surface, and stretching it
                // here would put the scaling in the wrong place: the renderer
                // already scales the framebuffer to the window. A mapping
                // whose target is the surface's own size is the identity and
                // is accepted as an ordinary mapping.
                if target_width != u32::from(surface.width)
                    || target_height != u32::from(surface.height)
                {
                    return Err(RdpError::Protocol(format!(
                        "the server asked for surface {surface_id} to be scaled from {}x{} to \
                         {target_width}x{target_height}, which this client does not do \
                         (MS-RDPEGFX 2.2.2.22)",
                        surface.width, surface.height
                    )));
                }
                self.map(surface_id, output_origin_x, output_origin_y)
            }
            EgfxPdu::WireToSurface1 {
                surface_id,
                codec_id,
                pixel_format,
                dest_rect,
                bitmap_data,
            } => {
                if codec_id == CODEC_CAPROGRESSIVE {
                    return Err(RdpError::Protocol(
                        "the server sent a RemoteFX Progressive rectangle; this build has no \
                         progressive decoder (MS-RDPEGFX 2.2.2.1, PRDRDP/04 §4.9, the \
                         `progressive` feature of rdp-codecs)"
                            .to_owned(),
                    ));
                }
                let Self {
                    surfaces, decoders, ..
                } = self;
                let surface = surfaces.get_mut(surface_id, "a wire to surface command")?;
                let has_alpha = surface.has_alpha;
                let mut dst = surface.view(dest_rect, "a wire to surface command")?;
                decode::wire_to_surface(
                    codec_id,
                    pixel_format,
                    has_alpha,
                    bitmap_data.as_slice(),
                    decoders,
                    &mut dst,
                )?;
                self.damaged(surface_id, dest_rect)
            }
            // `WIRE_TO_SURFACE_2` carries a persistent codec context, which
            // only the progressive codec uses (MS-RDPEGFX 2.2.2.2). We never
            // advertise it, so this is a server drawing with something it was
            // not offered.
            EgfxPdu::WireToSurface2 { codec_id, .. } => Err(RdpError::Protocol(format!(
                "the server sent a wire to surface 2 command in codec 0x{codec_id:04x}, which \
                 needs a persistent codec context this client never created \
                 (MS-RDPEGFX 2.2.2.2)"
            ))),
            // We never created a context, so there is none to delete. Saying
            // so once is better than treating a tidy up as an error.
            EgfxPdu::DeleteEncodingContext { surface_id, .. } => {
                tracing::trace!(
                    surface_id,
                    "a delete encoding context with no context to delete"
                );
                Ok(())
            }
            EgfxPdu::SolidFill {
                surface_id,
                fill_pixel,
                fill_rects,
            } => {
                for rect in &fill_rects {
                    self.surfaces
                        .get_mut(surface_id, "a solid fill")?
                        .fill(*rect, fill_pixel)?;
                    self.damaged(surface_id, *rect)?;
                }
                Ok(())
            }
            EgfxPdu::SurfaceToSurface {
                surface_id_src,
                surface_id_dest,
                rect_src,
                dest_pts,
            } => self.surface_to_surface(surface_id_src, surface_id_dest, rect_src, &dest_pts),
            EgfxPdu::SurfaceToCache {
                surface_id,
                cache_slot,
                rect_src,
                ..
            } => {
                let Self {
                    surfaces,
                    cache,
                    scratch,
                    ..
                } = self;
                let surface = surfaces.get(surface_id, "a surface to cache command")?;
                let (w, h) = surface.read_into(rect_src, scratch)?;
                // The buffer the slot gave back becomes the next read's
                // buffer, so a cache in a steady state allocates nothing.
                let recycled = cache.put(cache_slot, w, h, std::mem::take(scratch))?;
                *scratch = recycled;
                Ok(())
            }
            EgfxPdu::CacheToSurface {
                cache_slot,
                surface_id,
                dest_pts,
            } => {
                let Self {
                    surfaces, cache, ..
                } = self;
                let entry = cache.get(cache_slot)?;
                let surface = surfaces.get_mut(surface_id, "a cache to surface command")?;
                let mut painted = Vec::with_capacity(dest_pts.len());
                for point in &dest_pts {
                    painted.push(surface.write_packed(
                        *point,
                        entry.width,
                        entry.height,
                        &entry.pixels,
                    )?);
                }
                for rect in painted {
                    self.damaged(surface_id, rect)?;
                }
                Ok(())
            }
            EgfxPdu::EvictCacheEntry { cache_slot } => {
                self.cache.evict(cache_slot);
                Ok(())
            }
            EgfxPdu::CacheImportReply { cache_slots } => {
                // We offered nothing, so the only correct reply is an empty
                // one. A server that hands back slots is describing a cache
                // we do not have and every one of them would miss.
                if !cache_slots.is_empty() {
                    return Err(RdpError::Protocol(format!(
                        "the server imported {} cache slots against an offer of none \
                         (MS-RDPEGFX 2.2.2.17)",
                        cache_slots.len()
                    )));
                }
                Ok(())
            }
            EgfxPdu::StartFrame { frame_id, .. } => {
                // A frame that starts while another is open means the end of
                // the first was lost, which after ZGFX means a byte was.
                if let Some(open) = self.open_frame {
                    tracing::debug!(open, frame_id, "a frame started before the last one ended");
                    self.flush(events);
                }
                self.open_frame = Some(frame_id);
                Ok(())
            }
            EgfxPdu::EndFrame { frame_id } => {
                self.flush(events);
                self.open_frame = None;
                self.frames_decoded = self.frames_decoded.wrapping_add(1);
                self.frame_acknowledge(frame_id, ctx, replies)
            }
            EgfxPdu::ResetGraphics { width, height, .. } => {
                self.reset_graphics(width, height, events)
            }
            // RemoteApp mappings. This client draws a whole desktop and has
            // no window ids to map onto, so a server that sends one is
            // running a session we did not ask for; ignoring it leaves the
            // surface mapped wherever it already was.
            EgfxPdu::MapSurfaceToWindow { surface_id, .. }
            | EgfxPdu::MapSurfaceToScaledWindow { surface_id, .. } => {
                tracing::debug!(surface_id, "ignoring a remoteapp window mapping");
                Ok(())
            }
            // Client to server commands. A server echoing one back is
            // confused about which end it is.
            EgfxPdu::CapsAdvertise { .. }
            | EgfxPdu::CacheImportOffer { .. }
            | EgfxPdu::FrameAcknowledge { .. }
            | EgfxPdu::QoeFrameAcknowledge { .. } => {
                tracing::trace!("a client to server egfx command arrived from the server");
                Ok(())
            }
            // `pduLength` said how long it was, so skipping it cannot
            // desynchronise the channel, which is the condition PRDRDP/13 §2.7
            // sets for tolerating an unknown enumerant.
            EgfxPdu::Unknown { cmd_id, body, .. } => {
                tracing::debug!(
                    cmd_id,
                    len = body.len(),
                    "an egfx command this build ignores"
                );
                Ok(())
            }
        }
    }

    /// `RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU` (MS-RDPEGFX 2.2.2.15).
    fn map(&mut self, surface_id: u16, x: u32, y: u32) -> Result<()> {
        // The framebuffer the shell holds is addressed in `u16`
        // (`remote_core::Rect`), so an origin past 65,535 has nowhere to be
        // drawn and would silently wrap.
        if x > u32::from(u16::MAX) || y > u32::from(u16::MAX) {
            return Err(RdpError::Protocol(format!(
                "surface {surface_id} was mapped to output ({x}, {y}), outside the \
                 framebuffer coordinate space (MS-RDPEGFX 2.2.2.15)"
            )));
        }
        let surface = self.surfaces.get_mut(surface_id, "an output mapping")?;
        surface.origin = Some((x, y));
        tracing::debug!(surface_id, x, y, "mapped a surface to the output");
        Ok(())
    }

    /// `RDPGFX_SURFACE_TO_SURFACE_PDU` (MS-RDPEGFX 2.2.2.5).
    fn surface_to_surface(
        &mut self,
        src: u16,
        dest: u16,
        rect_src: RectExclusive,
        dest_pts: &[rdp_pdu::update::Point16],
    ) -> Result<()> {
        let mut painted = Vec::with_capacity(dest_pts.len());
        match self
            .surfaces
            .pair(src, dest, "a surface to surface command")?
        {
            // The same surface: an overlapping copy, which is what scrolling
            // a window is, so the row order matters.
            None => {
                let surface = self
                    .surfaces
                    .get_mut(dest, "a surface to surface command")?;
                for point in dest_pts {
                    painted.push(surface.blit_within(rect_src, *point)?);
                }
            }
            Some((source, destination)) => {
                let (w, h) = (
                    source.bounded(rect_src, "a surface to surface source")?.2,
                    source.bounded(rect_src, "a surface to surface source")?.3,
                );
                let mut scratch = std::mem::take(&mut self.scratch);
                let read = source.read_into(rect_src, &mut scratch);
                let write = read.and_then(|_| {
                    for point in dest_pts {
                        painted.push(destination.write_packed(*point, w, h, &scratch)?);
                    }
                    Ok(())
                });
                self.scratch = scratch;
                write?;
            }
        }
        for rect in painted {
            self.damaged(dest, rect)?;
        }
        Ok(())
    }

    /// `RDPGFX_RESET_GRAPHICS_PDU` (MS-RDPEGFX 2.2.2.14).
    ///
    /// Everything the server drew belongs to the old geometry, so the
    /// surfaces, the cache and every codec's cross call state go. The ZGFX
    /// history does **not**: the server does not reset its own, and dropping
    /// ours would decode the next compressed segment against nothing
    /// (PRDRDP/04 §4.12.3).
    fn reset_graphics(
        &mut self,
        width: u32,
        height: u32,
        events: &mut Vec<SessionEvent>,
    ) -> Result<()> {
        let (Ok(w), Ok(h)) = (u16::try_from(width), u16::try_from(height)) else {
            return Err(RdpError::Protocol(format!(
                "the server reset the graphics to {width}x{height}, outside the \
                 framebuffer coordinate space (MS-RDPEGFX 2.2.2.14)"
            )));
        };
        tracing::info!(
            width = w,
            height = h,
            "the server reset the graphics pipeline"
        );
        self.pending.clear();
        self.open_frame = None;
        self.surfaces.reset();
        self.cache.reset();
        self.decoders.reset();
        events.push(SessionEvent::DesktopResize {
            width: w,
            height: h,
        });
        Ok(())
    }

    /// `RDPGFX_FRAME_ACKNOWLEDGE_PDU` (MS-RDPEGFX 2.2.2.13, PRDRDP/04 §3.6).
    ///
    /// # What `queueDepth` is here
    ///
    /// The field is "the number of frames queued at the client waiting to be
    /// displayed". This client has no display queue of its own: a decoded
    /// frame is pushed into the bounded event channel and the shell drains it
    /// at the rate the renderer presents. So the number of frames waiting is
    /// the number of events the shell has not taken, which is what
    /// [`ChannelCtx::event_backlog`] carries and what the run loop reads off
    /// the channel before it dispatches.
    ///
    /// Zero is the specification's `QUEUE_DEPTH_UNAVAILABLE`, so an empty
    /// queue and an unknown queue are the same value on the wire. That is
    /// harmless: a server treats both as "no back pressure", which is exactly
    /// what an empty queue means.
    ///
    /// # What this deliberately does not do
    ///
    /// It never sends `SUSPEND_FRAME_ACKNOWLEDGEMENT`. PRDRDP/04 §3.6 forbids
    /// it, and the reason is worth repeating: a client that stops bounding
    /// its own demand starves every other session on the server.
    ///
    /// The acknowledgement is queued **after** the frame's events have been
    /// pushed, and the run loop emits into a bounded channel that blocks when
    /// the shell is behind. So a slow renderer slows the acknowledgements,
    /// which slows the server. That is the whole flow control loop, and it is
    /// why the ordering of these two lines is not cosmetic.
    fn frame_acknowledge(
        &mut self,
        frame_id: u32,
        ctx: ChannelCtx,
        replies: &mut ReplyBuf,
    ) -> Result<()> {
        let total = self.frames_decoded;
        replies.emit(|buf| {
            encode(
                &EgfxPdu::FrameAcknowledge {
                    queue_depth: ctx.event_backlog,
                    frame_id,
                    total_frames_decoded: total,
                },
                buf,
            )
        })
    }

    /// Record that a rectangle of a surface changed.
    ///
    /// A surface with no output mapping is composed into another one and is
    /// never shown, so its damage produces nothing: emitting it would draw
    /// an offscreen scratch surface over the desktop.
    fn damaged(&mut self, surface_id: u16, rect: RectExclusive) -> Result<()> {
        let Self {
            surfaces, pending, ..
        } = self;
        let surface = surfaces.get(surface_id, "a frame emit")?;
        let Some((ox, oy)) = surface.origin else {
            return Ok(());
        };
        let (left, top, w, h) = surface.bounded(rect, "a frame emit")?;
        if w == 0 || h == 0 {
            return Ok(());
        }
        let (Ok(x), Ok(y)) = (
            u16::try_from(ox + u32::from(left)),
            u16::try_from(oy + u32::from(top)),
        ) else {
            return Err(RdpError::Protocol(format!(
                "surface {surface_id} drew at ({}, {}) from an origin of ({ox}, {oy}), \
                 outside the framebuffer coordinate space",
                left, top
            )));
        };
        let mut pixels = Vec::new();
        surface.copy_out(rect, &mut pixels)?;
        pending.push(DecodedRect {
            rect: Rect::new(x, y, w, h),
            payload: RectPayload::Rgba(pixels),
        });
        Ok(())
    }

    /// Turn everything drawn since the last flush into one framebuffer
    /// update.
    ///
    /// One event per frame and not one per rectangle: the renderer presents
    /// once per event (PRDRDP/04 §10.4), which is the same rule the legacy
    /// path follows in `crate::session::run_loop::flush`.
    fn flush(&mut self, events: &mut Vec<SessionEvent>) {
        if self.pending.is_empty() {
            return;
        }
        events.push(crate::session::graphics::framebuffer_update(
            std::mem::take(&mut self.pending),
        ));
    }
}

/// The `capsData` word every advertised version carries.
///
/// Versions 8 and 8.1 carry a single `u32` of `RDPGFX_CAPS_FLAG_*`, little
/// endian like every other RDP integer (MS-RDPEGFX 2.2.3.1). Zero is what we
/// want: the only two flags defined for those versions are
/// `RDPGFX_CAPS_FLAG_THINCLIENT` and `RDPGFX_CAPS_FLAG_SMALL_CACHE`, and both
/// shrink the cache the server is allowed to use.
const CAPS_FLAGS_NONE: [u8; 4] = 0u32.to_le_bytes();

/// Encode one client to server EGFX command into a pooled buffer.
fn encode(pdu: &EgfxPdu<'_>, buf: &mut Vec<u8>) -> Result<()> {
    pdu.encode_checked(&mut Writer::new(buf))?;
    Ok(())
}

/// A message that decompressed and then would not parse.
///
/// This is the ZGFX reconstruction's failure mode and the error says so, in
/// as many words, with the file to look in. `docs/RDP_SPEC_NOTES.md` §1.1 asks
/// for exactly this before the table goes live.
fn zgfx_suspect(len: usize, e: &rdp_pdu::PduError) -> RdpError {
    RdpError::Protocol(format!(
        "the graphics channel decompressed {len} bytes that do not parse as EGFX commands: \
         {e}. If this is intermittent rather than every frame, the ZGFX literal token table \
         (crates/rdp-codecs/src/zgfx.rs, docs/RDP_SPEC_NOTES.md section 1.1) is the first \
         thing to check: it is a reconstruction, and one wrong literal row produces a wrong \
         byte every few thousand (MS-RDPEGFX 2.2.1.5)"
    ))
}

#[cfg(test)]
mod tests;
