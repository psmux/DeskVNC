//! `drdynvc`, the dynamic virtual channel multiplexer (MS-RDPEDYC,
//! PRDRDP/05 §5.2).
//!
//! One static channel carries an arbitrary number of dynamic ones. The server
//! opens each by name, the client answers with a creation status, and after
//! that both sides exchange fragments tagged with the dynamic channel id.
//! This file is the multiplexer and nothing else: it owns the version
//! handshake, the open channel table and the per channel reassembly, and it
//! hands a complete message to whichever handler owns that channel.
//!
//! # What we open, and what we refuse
//!
//! Two names are answered with `STATUS_SUCCESS`, and three with the `audio`
//! feature on: [`EGFX_CHANNEL_NAME`], `Microsoft::Windows::RDS::DisplayControl`
//! and `AUDIO_PLAYBACK_DVC`. Every other name is refused with
//! `STATUS_NOT_FOUND`, which MS-RDPEDYC 3.2.5.2 defines as the answer for a
//! channel the client does not implement. Refusing by name is what stops a
//! server opening `rdpdr` or `rdpsnd` and then waiting forever for traffic
//! that will never come; silence would look like a hung client.
//!
//! # Compression
//!
//! `DYNVC_DATA_COMPRESSED` and `DYNVC_DATA_FIRST_COMPRESSED` carry RDP 8.0
//! bulk compressed payloads. PRDRDP/05 §5.2 says RDP 6.1 and is wrong;
//! `docs/RDP_SPEC_NOTES.md` §2.1 records the correction. We do not accept
//! either form, and the reason is a budget rather than a gap: the RDP 8.0
//! decompressor carries a 2.5 MB history window
//! (`rdp_codecs::zgfx::HISTORY`), the graphics channel already owns one, and
//! a second independent history for a form no server uses unless the client
//! asks for it is 2.5 MB spent on nothing. It is refused with a typed error
//! naming the phase rather than with a `todo!()`.

use rdp_pdu::codes::CompressionType;
use rdp_pdu::vc::dvc::{creation_status, dvc_version, DvcPdu, DvcReassembler};
use rdp_pdu::vc::segment::Segmented;
use rdp_pdu::vc::static_vc::CHANNEL_CHUNK_LENGTH;
use rdp_pdu::{Decode, Encode, Payload, Reader, Writer};

use crate::channels::display::{DisplayControl, DISPLAY_CHANNEL_NAME};
use crate::channels::egfx::Egfx;
#[cfg(feature = "audio")]
use crate::channels::rdpsnd::{Rdpsnd, AUDIO_CHANNEL_NAME};
use crate::channels::{encode_channel_pdu, ChannelCtx, Outbox};
use crate::error::{RdpError, Result};

/// The graphics channel's name (MS-RDPEGFX 2.1).
pub const EGFX_CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Graphics";

/// The largest payload we put in one `DYNVC_DATA`.
///
/// A dynamic channel PDU rides inside a static channel chunk, so keeping it
/// under [`CHANNEL_CHUNK_LENGTH`] minus the worst case headers means one
/// dynamic fragment is always one static chunk. The nine bytes are the
/// drdynvc header (1) plus a four byte channel id plus a four byte `Length`,
/// which is the largest a `DYNVC_DATA_FIRST` can be (MS-RDPEDYC 2.2.3.1).
///
/// Nothing this client sends is anywhere near it: the largest is a
/// `RDPGFX_CAPS_ADVERTISE_PDU` at a few dozen bytes. The fragmentation
/// exists so that a later channel with a real payload does not find out the
/// hard way.
const MAX_DVC_FRAGMENT: usize = CHANNEL_CHUNK_LENGTH - 9;

/// The reassembly cap for the graphics channel (PRDRDP/05 §5.2).
///
/// Thirty two mebibytes, which is what `rdp_pdu::vc::dvc::DvcReassembler`'s
/// own documentation argues for: an uncompressed `WIRE_TO_SURFACE_1` covering
/// a 4K surface is `3840 * 2160 * 4` bytes, a little under 32 MiB on its own,
/// so the 4 MiB default would refuse a legal PDU as a cap violation.
const EGFX_REASSEMBLY_CAP: usize = 32 * 1024 * 1024;

/// The reassembly cap for the display control channel.
///
/// Sixty four kibibytes. The only message the server sends is a twenty byte
/// capability PDU (MS-RDPEDISP 2.2.2.1), and the largest a client sends is
/// sixteen monitors at forty bytes. The cap is three orders of magnitude
/// above both, which is the point: a server that claims a megabyte on this
/// channel is not sending a display control PDU.
const DISPLAY_REASSEMBLY_CAP: usize = 64 * 1024;

/// The reassembly cap for the audio playback channel (MS-RDPEA).
///
/// One mebibyte, which matches the largest block
/// `crate::channels::rdpsnd::Rdpsnd` will assemble. Two seconds of stereo
/// 48 kHz sixteen bit PCM is 384,000 bytes, so this is five times the largest
/// legitimate message.
#[cfg(feature = "audio")]
const AUDIO_REASSEMBLY_CAP: usize = 1024 * 1024;

/// The highest drdynvc version we answer with.
///
/// Version 3 adds soft sync, which moves channels onto a UDP tunnel. We never
/// negotiate multitransport, so there is no tunnel to move anything to, and
/// the Soft-Sync Request is answered with a response listing zero tunnels
/// (PRDRDP/05 §5.2). Answering version 3 and then declining every sync is
/// what MS-RDPEDYC 3.2.5.5 describes; answering version 1 to dodge the
/// exchange would also decline priority classes we may want later.
const MAX_DVC_VERSION: u16 = dvc_version::V3;

/// Buffers for replies a dynamic channel handler produced, pooled across
/// frames.
///
/// Every EGFX frame produces exactly one reply, the frame acknowledgement,
/// and allocating a fresh `Vec` for its twenty bytes sixty times a second is
/// the kind of per frame allocation PRDRDP/04 §4.1 rule two exists to
/// prevent. Handlers encode into a buffer this type lends them, the
/// multiplexer wraps each one and puts it on the wire, and the buffers come
/// straight back.
#[derive(Debug, Default)]
pub struct ReplyBuf {
    ready: Vec<Vec<u8>>,
    spare: Vec<Vec<u8>>,
}

impl ReplyBuf {
    /// Encode one reply into a pooled buffer.
    ///
    /// A buffer that the closure failed on goes back to the pool rather than
    /// onto the ready list, so a refused encode leaves nothing half written
    /// for the multiplexer to send.
    ///
    /// # Errors
    ///
    /// Whatever `f` reported.
    pub fn emit<F>(&mut self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> Result<()>,
    {
        let mut buf = self.spare.pop().unwrap_or_default();
        buf.clear();
        match f(&mut buf) {
            Ok(()) => {
                self.ready.push(buf);
                Ok(())
            }
            Err(e) => {
                self.spare.push(buf);
                Err(e)
            }
        }
    }

    /// True when a handler produced nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ready.is_empty()
    }

    /// What a handler has produced and the multiplexer has not yet wrapped.
    ///
    /// For the tests that drive a dynamic channel handler directly, which is
    /// most of them: the alternative is asserting through three layers of
    /// framing to see one twenty byte acknowledgement.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn queued(&self) -> &[Vec<u8>] {
        &self.ready
    }

    /// Drop what is queued, so one test can make several assertions.
    #[cfg(test)]
    pub(crate) fn take(&mut self) {
        for mut buf in self.ready.drain(..) {
            buf.clear();
            self.spare.push(buf);
        }
    }
}

/// One open dynamic channel.
#[derive(Debug)]
struct DynChannel {
    id: u32,
    kind: DynKind,
    /// Fragment reassembly, per channel rather than per multiplexer: nothing
    /// in MS-RDPEDYC 3.1.5.1 stops a server interleaving one channel's
    /// `DYNVC_DATA` between another's `DYNVC_DATA_FIRST` and its last
    /// fragment, and a shared buffer would splice the two together.
    reassembler: DvcReassembler,
}

/// The handler behind one dynamic channel.
///
/// One variant per dynamic channel this build speaks. An enum rather than a
/// `Box<dyn>` for the reason [`crate::channels::Handler`] gives: the set is
/// closed at compile time and a wildcard arm would be a bug.
#[derive(Debug)]
enum DynKind {
    Egfx(Box<Egfx>),
    /// `Microsoft::Windows::RDS::DisplayControl` (MS-RDPEDISP).
    Display(DisplayControl),
    /// `AUDIO_PLAYBACK_DVC` (MS-RDPEA), behind the `audio` feature.
    ///
    /// Boxed for the reason the graphics channel is: this variant carries the
    /// wave assembly buffer and the negotiated format list, and an enum whose
    /// largest variant is a megabyte would make every entry in the channel
    /// table that size.
    #[cfg(feature = "audio")]
    Audio(Box<Rdpsnd>),
}

impl DynKind {
    /// Whether this channel's messages ride inside an `RDP_SEGMENTED_DATA`
    /// envelope.
    ///
    /// The graphics channel's do (MS-RDPEGFX 2.2.5.1) and nothing else's
    /// does: the segmentation layer is defined by MS-RDPEGFX and is not part
    /// of MS-RDPEDYC, so a display control PDU wrapped in one would be read
    /// by the server as a malformed header.
    const fn segmented(&self) -> bool {
        matches!(self, DynKind::Egfx(_))
    }
}

/// The dynamic channel multiplexer.
#[derive(Debug, Default)]
pub struct DvcMux {
    /// The version the capability exchange settled on, `None` until it
    /// happens. A Create Request before the exchange is a server getting the
    /// order wrong (MS-RDPEDYC 1.3.1) and is refused.
    version: Option<u16>,
    open: Vec<DynChannel>,
    replies: ReplyBuf,
    /// The `RDP_SEGMENTED_DATA` envelope, reused across frames.
    wire: Vec<u8>,
    /// The drdynvc PDU, reused across frames.
    dvc: Vec<u8>,
    /// The static channel chunk, reused across frames.
    chunk: Vec<u8>,
    /// A size asked for before the display control channel existed.
    ///
    /// The server opens that channel some way into the session, and a resize
    /// arriving first used to be logged and dropped. That is fine for a window
    /// the user is dragging, which will ask again, and wrong for the size a
    /// session was configured with, which is asked for exactly once.
    deferred_resize: Option<(u32, u32, u32)>,
}

impl DvcMux {
    /// A multiplexer with no channels open.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget every open channel and every partial message.
    ///
    /// A held resize deliberately survives: it was asked for and never
    /// delivered, and the channels are about to be reopened.
    ///
    /// A deactivation tears the share down and the server reopens its
    /// channels on the new one (PRDRDP/05 §5.1 rule 6).
    pub fn reset(&mut self) {
        self.open.clear();
        self.version = None;
    }

    /// Send a size the display control debounce held back
    /// (MS-RDPEDISP 2.2.2.2, PRDRDP/05 §5.4).
    ///
    /// # Errors
    ///
    /// Whatever the encoder reported.
    pub fn flush_pending_resize(
        &mut self,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let Some(index) = self
            .open
            .iter()
            .position(|c| matches!(c.kind, DynKind::Display(_)))
        else {
            return Ok(());
        };
        let Self { open, replies, .. } = self;
        let channel = &mut open[index];
        let channel_id = channel.id;
        let DynKind::Display(display) = &mut channel.kind else {
            unreachable!("the index came from a matches! on this variant");
        };
        display.flush_pending(replies)?;
        if replies.is_empty() {
            return Ok(());
        }
        self.flush(channel_id, false, static_id, ctx, out)
    }

    /// The window changed size: ask the server to resize the desktop
    /// (MS-RDPEDISP 2.2.2.2).
    ///
    /// A no op when the server never opened the display control channel,
    /// which is what a host with dynamic resolution turned off leaves us
    /// with. The request is not remembered here: the session settings hold
    /// it, and it is re-applied on the next connection
    /// (`crate::session::settings::RdpSessionSettings::requested_size`).
    ///
    /// # Errors
    ///
    /// Whatever the encoder reported.
    pub fn resize(
        &mut self,
        width: u32,
        height: u32,
        scale_percent: u32,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let Some(index) = self
            .open
            .iter()
            .position(|c| matches!(c.kind, DynKind::Display(_)))
        else {
            tracing::debug!("a resize before the display control channel, holding it");
            self.deferred_resize = Some((width, height, scale_percent));
            return Ok(());
        };
        let Self { open, replies, .. } = self;
        let channel = &mut open[index];
        let channel_id = channel.id;
        let DynKind::Display(display) = &mut channel.kind else {
            unreachable!("the index came from a matches! on this variant");
        };
        display.resize(width, height, scale_percent, replies)?;
        self.flush(channel_id, false, static_id, ctx, out)
    }

    /// One complete drdynvc message.
    ///
    /// # Errors
    ///
    /// [`RdpError::Pdu`] when the PDU did not parse, and
    /// [`RdpError::Protocol`] for a message that parsed and then said
    /// something the state machine cannot act on.
    pub fn message(
        &mut self,
        message: &[u8],
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let pdu = DvcPdu::decode(&mut Reader::new(message))?;
        match pdu {
            DvcPdu::Capabilities { version, .. } => self.capabilities(version, static_id, ctx, out),
            DvcPdu::CreateRequest {
                channel_id,
                channel_name,
            } => self.create(channel_id, &channel_name, static_id, ctx, out),
            DvcPdu::DataFirst {
                channel_id,
                total_length,
                data,
                compressed,
            } => self.data(
                channel_id,
                Some(total_length),
                data,
                compressed,
                static_id,
                ctx,
                out,
            ),
            DvcPdu::Data {
                channel_id,
                data,
                compressed,
            } => self.data(channel_id, None, data, compressed, static_id, ctx, out),
            DvcPdu::Close { channel_id } => {
                let before = self.open.len();
                self.open.retain(|c| c.id != channel_id);
                tracing::debug!(
                    channel_id,
                    closed = before != self.open.len(),
                    "the server closed a dynamic channel"
                );
                Ok(())
            }
            DvcPdu::SoftSyncRequest {
                number_of_tunnels, ..
            } => {
                // We never negotiated multitransport, so there is no tunnel
                // to move a channel onto and the honest answer is "I moved
                // none" (MS-RDPEDYC 3.2.5.5, PRDRDP/05 §5.2).
                tracing::debug!(number_of_tunnels, "declining a soft sync request");
                self.write_dvc(
                    &DvcPdu::SoftSyncResponse {
                        number_of_tunnels: 0,
                        tunnels_to_switch: Payload::new(&[]),
                    },
                    static_id,
                    ctx,
                    out,
                )
            }
            // Client to server PDUs. A server that echoes one back is
            // confused about which end it is, and answering would be worse
            // than ignoring it.
            DvcPdu::CreateResponse { .. } | DvcPdu::SoftSyncResponse { .. } => {
                tracing::trace!("a client to server drdynvc pdu arrived from the server");
                Ok(())
            }
        }
    }

    /// The version handshake (MS-RDPEDYC 2.2.1.1, 2.2.1.2).
    fn capabilities(
        &mut self,
        version: u16,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        // MS-RDPEDYC 3.2.5.1.2: the client answers with a version it
        // supports, which may not exceed the one it was offered.
        let agreed = version.min(MAX_DVC_VERSION);
        tracing::info!(offered = version, agreed, "drdynvc version negotiated");
        self.version = Some(agreed);
        self.write_dvc(&DvcPdu::capabilities_response(agreed), static_id, ctx, out)
    }

    /// A Create Request (MS-RDPEDYC 2.2.2.1).
    fn create(
        &mut self,
        channel_id: u32,
        name: &str,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        if self.version.is_none() {
            return Err(RdpError::Protocol(
                "the server opened a dynamic channel before the drdynvc capability exchange \
                 (MS-RDPEDYC 1.3.1)"
                    .to_owned(),
            ));
        }
        // A second Create Request for a live id is the server having lost
        // track of the session, and silently replacing the channel would lose
        // whatever the old one was mid frame on.
        if self.open.iter().any(|c| c.id == channel_id) {
            return Err(RdpError::Protocol(format!(
                "the server opened dynamic channel {channel_id} twice (MS-RDPEDYC 2.2.2.1)"
            )));
        }

        #[cfg(feature = "audio")]
        if name == AUDIO_CHANNEL_NAME {
            tracing::info!(channel_id, "opening the audio playback channel");
            self.write_dvc(
                &DvcPdu::CreateResponse {
                    channel_id,
                    creation_status: creation_status::SUCCESS,
                },
                static_id,
                ctx,
                out,
            )?;
            // MS-RDPEA 1.3.2: the server speaks first, with its format list,
            // so there is nothing to flush here.
            self.open.push(DynChannel {
                id: channel_id,
                kind: DynKind::Audio(Box::new(Rdpsnd::new())),
                reassembler: DvcReassembler::with_cap(AUDIO_REASSEMBLY_CAP),
            });
            return Ok(());
        }

        if name == DISPLAY_CHANNEL_NAME {
            tracing::info!(channel_id, "opening the display control channel");
            self.write_dvc(
                &DvcPdu::CreateResponse {
                    channel_id,
                    creation_status: creation_status::SUCCESS,
                },
                static_id,
                ctx,
                out,
            )?;
            // MS-RDPEDISP 1.3.1: the client says nothing until the server's
            // capability PDU arrives, so there is nothing to flush here.
            self.open.push(DynChannel {
                id: channel_id,
                kind: DynKind::Display(DisplayControl::new()),
                reassembler: DvcReassembler::with_cap(DISPLAY_REASSEMBLY_CAP),
            });
            // Anything asked for while there was nowhere to send it. The
            // channel holds it again until the capability PDU arrives, so this
            // is a hand off rather than a send.
            if let Some((width, height, scale)) = self.deferred_resize.take() {
                self.resize(width, height, scale, static_id, ctx, out)?;
            }
            return Ok(());
        }

        if name != EGFX_CHANNEL_NAME {
            tracing::debug!(
                channel_id,
                name,
                "refusing a dynamic channel we do not speak"
            );
            return self.write_dvc(
                &DvcPdu::CreateResponse {
                    channel_id,
                    creation_status: creation_status::NOT_FOUND,
                },
                static_id,
                ctx,
                out,
            );
        }

        tracing::info!(channel_id, "opening the graphics channel");
        // Boxed because `Egfx` carries the ZGFX history window and every
        // codec's scratch, which is megabytes: an enum whose largest variant
        // is that big would make every `DynChannel` in the table that size.
        let mut egfx = Box::new(Egfx::new());
        // The response goes first. MS-RDPEGFX 3.3.5.1 has the client
        // advertise its capabilities on a channel that is already open, and a
        // server that sees graphics traffic before the creation status has to
        // decide what the status was going to be.
        self.write_dvc(
            &DvcPdu::CreateResponse {
                channel_id,
                creation_status: creation_status::SUCCESS,
            },
            static_id,
            ctx,
            out,
        )?;
        egfx.opened(&mut self.replies)?;
        self.open.push(DynChannel {
            id: channel_id,
            kind: DynKind::Egfx(egfx),
            reassembler: DvcReassembler::with_cap(EGFX_REASSEMBLY_CAP),
        });
        self.flush(channel_id, true, static_id, ctx, out)
    }

    /// A Data or Data First fragment (MS-RDPEDYC 2.2.3.1, 2.2.3.2).
    #[allow(clippy::too_many_arguments)]
    fn data(
        &mut self,
        channel_id: u32,
        total_length: Option<u32>,
        data: Payload<'_>,
        compressed: bool,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        if compressed {
            return Err(RdpError::Protocol(format!(
                "the server sent RDP 8.0 compressed data on dynamic channel {channel_id}, \
                 which this client never asked for (MS-RDPEDYC 2.2.3.3, PRDRDP/05 §5.2)"
            )));
        }
        let Some(index) = self.open.iter().position(|c| c.id == channel_id) else {
            // A channel we refused, or one closed while a fragment was in
            // flight. Both are the server's timing rather than an error, and
            // a length prefixed fragment can be skipped without desyncing.
            tracing::trace!(channel_id, "data on a dynamic channel we did not open");
            return Ok(());
        };

        // Disjoint borrows again: the reassembler returns a view of its own
        // buffer, or of `data` when the whole message arrived in one
        // fragment, and `kind` and `replies` are separate fields. Nothing
        // between the socket and the codec copies these bytes.
        let Self { open, replies, .. } = self;
        let Some(channel) = open.get_mut(index) else {
            unreachable!("index came from position()");
        };
        let DynChannel {
            reassembler, kind, ..
        } = channel;
        // MS-RDPEDYC 2.2.3.2: a message that fits in one PDU is sent as a bare
        // `DYNVC_DATA` with no `DYNVC_DATA_FIRST` in front of it, and on this
        // channel that is nearly every message. `DvcReassembler` models only
        // the fragmented sequence and says so
        // (`crates/rdp-pdu/src/vc/dvc.rs:688`: "`total_length` is `Some` for a
        // Data First and `None` for a Data"), so telling a continuation from a
        // whole message is the caller's decision, which is where PRDRDP/13 §2.7
        // puts policy. Feeding an unfragmented `DYNVC_DATA` to the reassembler
        // is refused as a fragment with no first, which is the right answer to
        // the question it was asked and the wrong answer to this one.
        //
        // The whole message case borrows the receive buffer and copies
        // nothing, which is the layer of D9 that matters most here: it is the
        // path every EGFX frame under 1600 bytes takes.
        let complete = match total_length {
            Some(_) => reassembler.push(total_length, data.as_slice())?,
            None if !reassembler.in_progress() => Some(data.as_slice()),
            None => reassembler.push(None, data.as_slice())?,
        };
        let Some(message) = complete else {
            return Ok(());
        };
        let segmented = kind.segmented();
        match kind {
            DynKind::Egfx(egfx) => egfx.message(message, ctx, &mut out.events, replies)?,
            DynKind::Display(display) => display.message(message, replies)?,
            #[cfg(feature = "audio")]
            DynKind::Audio(audio) => audio.message(message, &mut out.events, replies)?,
        }
        self.flush(channel_id, segmented, static_id, ctx, out)
    }

    /// Wrap and queue everything the handler produced.
    ///
    /// An EGFX reply gets its own `RDP_SEGMENTED_DATA` envelope
    /// (MS-RDPEGFX 2.2.5.1); every other channel's rides in `DYNVC_DATA` on
    /// its own, because the segmentation layer is MS-RDPEGFX's and not
    /// MS-RDPEDYC's. Either way it gets its own drdynvc fragmentation and
    /// every buffer goes straight back to the pool.
    fn flush(
        &mut self,
        channel_id: u32,
        segmented: bool,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        if self.replies.is_empty() {
            return Ok(());
        }
        let mut ready = std::mem::take(&mut self.replies.ready);
        let result = (|| -> Result<()> {
            for payload in &ready {
                self.wire.clear();
                if segmented {
                    // A client to server EGFX message is never compressed:
                    // the flags byte carries `PACKET_COMPR_TYPE_RDP8` with
                    // `PACKET_COMPRESSED` clear, which is the literal form
                    // (MS-RDPEGFX 2.2.5.1, MS-RDPBCGR 3.1.8.4.2).
                    Segmented::Literal {
                        flags: CompressionType::Rdp8.to_u8(),
                        data: Payload::new(payload),
                    }
                    .encode_checked(&mut Writer::new(&mut self.wire))?;
                } else {
                    self.wire.extend_from_slice(payload);
                }
                self.fragment(channel_id, static_id, ctx, out)?;
            }
            Ok(())
        })();
        for mut buf in ready.drain(..) {
            buf.clear();
            self.replies.spare.push(buf);
        }
        self.replies.ready = ready;
        result
    }

    /// Split `self.wire` into `DYNVC_DATA` fragments and queue each one.
    fn fragment(
        &mut self,
        channel_id: u32,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let total = self.wire.len();
        let mut offset = 0;
        while offset < total || offset == 0 {
            let end = (offset + MAX_DVC_FRAGMENT).min(total);
            let slice = self.wire.get(offset..end).unwrap_or(&[]);
            let pdu = if offset == 0 && end == total {
                DvcPdu::Data {
                    channel_id,
                    data: Payload::new(slice),
                    compressed: false,
                }
            } else if offset == 0 {
                DvcPdu::DataFirst {
                    channel_id,
                    total_length: total as u32,
                    data: Payload::new(slice),
                    compressed: false,
                }
            } else {
                DvcPdu::Data {
                    channel_id,
                    data: Payload::new(slice),
                    compressed: false,
                }
            };
            self.dvc.clear();
            pdu.encode_checked(&mut Writer::new(&mut self.dvc))?;
            encode_channel_pdu(
                ctx.user_channel_id,
                static_id,
                &self.dvc,
                &mut self.chunk,
                &mut out.frames,
            )?;
            if end == total {
                break;
            }
            offset = end;
        }
        Ok(())
    }

    /// Encode one drdynvc control PDU and queue it as a static channel PDU.
    fn write_dvc(
        &mut self,
        pdu: &DvcPdu<'_>,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        self.dvc.clear();
        pdu.encode_checked(&mut Writer::new(&mut self.dvc))?;
        encode_channel_pdu(
            ctx.user_channel_id,
            static_id,
            &self.dvc,
            &mut self.chunk,
            &mut out.frames,
        )
    }
}

/// The bytes of one static channel PDU, for a test that wants to see what the
/// multiplexer put on the wire without unwrapping three layers by hand.
#[cfg(test)]
pub(crate) fn unwrap_channel_frame(frame: &bytes::Bytes) -> Vec<u8> {
    use rdp_pdu::mcs::DomainMcsPdu;
    use rdp_pdu::vc::static_vc::ChannelPduHeader;
    use rdp_pdu::x224;

    let mut r = Reader::new(frame);
    let mut body = x224::read_data_tpdu(&mut r).expect("x224");
    let DomainMcsPdu::SendDataRequest { payload, .. } =
        DomainMcsPdu::decode(&mut body).expect("mcs")
    else {
        panic!("not a send data request");
    };
    let mut r = Reader::new(payload.as_slice());
    let _ = ChannelPduHeader::decode(&mut r).expect("channel header");
    r.rest().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::vc::egfx::{caps_version, Capset};
    use rdp_pdu::vc::static_vc::{channel_flags, ChannelPduHeader};

    /// The static channel this multiplexer is reached on in these tests.
    const STATIC_ID: u16 = 1004;

    fn ctx() -> ChannelCtx {
        ChannelCtx {
            user_channel_id: 1007,
            desktop: (800, 600),
            event_backlog: 0,
        }
    }

    /// One static channel PDU wrapping one drdynvc PDU, as a server sends it.
    fn from_server(pdu: &DvcPdu<'_>) -> Vec<u8> {
        let mut body = Vec::new();
        pdu.encode_checked(&mut Writer::new(&mut body))
            .expect("encodes");
        body
    }

    /// The drdynvc PDUs the multiplexer queued, unwrapped from their frames.
    fn sent(out: &Outbox) -> Vec<DvcPdu<'static>> {
        out.frames
            .iter()
            .map(|frame| {
                let body = unwrap_channel_frame(frame);
                // The decoded PDU borrows `body`, so it is rebuilt as an owned
                // value the caller can match on after this closure returns.
                // Only the variants these tests assert on are reconstructed.
                match DvcPdu::decode(&mut Reader::new(&body)).expect("a reply parses") {
                    DvcPdu::Capabilities {
                        version,
                        priority_charges,
                    } => DvcPdu::Capabilities {
                        version,
                        priority_charges,
                    },
                    DvcPdu::CreateRequest {
                        channel_id,
                        channel_name,
                    } => DvcPdu::CreateRequest {
                        channel_id,
                        channel_name,
                    },
                    DvcPdu::Close { channel_id } => DvcPdu::Close { channel_id },
                    other => DvcPdu::Close {
                        // A stand in the assertions never match, so a reply of
                        // the wrong shape fails loudly rather than silently.
                        channel_id: 0xDEAD_0000 | u32::from(other.cmd()),
                    },
                }
            })
            .collect()
    }

    /// The `CreationStatus` of a client `DYNVC_CREATE`, which
    /// [`DvcPdu::decode`] cannot give us: the two directions share a `Cmd` and
    /// only the direction tells them apart, so the decoder is written for the
    /// one this client receives (`crates/rdp-pdu/src/vc/dvc.rs:407`).
    fn creation_statuses(out: &Outbox) -> Vec<(u32, i32)> {
        out.frames
            .iter()
            .filter_map(|frame| {
                let body = unwrap_channel_frame(frame);
                let mut r = Reader::new(&body);
                let header = rdp_pdu::vc::dvc::DvcHeader::from_u8(r.u8("header").ok()?);
                if header.cmd != rdp_pdu::vc::dvc::cmd::CREATE {
                    return None;
                }
                let id =
                    rdp_pdu::vc::dvc::read_channel_id(&mut r, header.cb_id, "ChannelId").ok()?;
                let status = r.u32("CreationStatus").ok()?;
                r.is_empty().then_some((id, status as i32))
            })
            .collect()
    }

    /// The EGFX payloads the multiplexer wrapped, with their envelope and
    /// drdynvc header stripped.
    fn egfx_payloads(out: &Outbox) -> Vec<Vec<u8>> {
        out.frames
            .iter()
            .filter_map(|frame| {
                let body = unwrap_channel_frame(frame);
                match DvcPdu::decode(&mut Reader::new(&body)).ok()? {
                    DvcPdu::Data { data, .. } => {
                        // Descriptor `SINGLE` then the RDP 8.0 flags byte.
                        let bytes = data.as_slice();
                        assert_eq!(bytes.first(), Some(&0xE0), "descriptor SINGLE");
                        assert_eq!(bytes.get(1), Some(&0x04), "RDP8, not compressed");
                        Some(bytes[2..].to_vec())
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// A multiplexer with the version settled and the graphics channel open,
    /// with everything that produced already drained.
    fn opened() -> (DvcMux, u32) {
        let mut mux = DvcMux::new();
        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::Capabilities {
                version: dvc_version::V3,
                priority_charges: Some([0, 0, 0, 0]),
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("capabilities");
        mux.message(
            &from_server(&DvcPdu::CreateRequest {
                channel_id: 7,
                channel_name: EGFX_CHANNEL_NAME.to_owned(),
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("create");
        (mux, 7)
    }

    /// One EGFX message inside an uncompressed `RDP_SEGMENTED_DATA` envelope.
    fn egfx_message(pdu: &rdp_pdu::vc::egfx::EgfxPdu<'_>) -> Vec<u8> {
        let mut out = vec![0xE0, 0x04];
        pdu.encode_checked(&mut Writer::new(&mut out))
            .expect("encodes");
        out
    }

    /// MS-RDPEDYC 3.2.5.1.2: the client answers a version it supports, which
    /// may not exceed the one it was offered.
    #[test]
    fn the_version_answer_never_exceeds_what_was_offered() {
        for (offered, expected) in [(1u16, 1u16), (2, 2), (3, 3), (9, MAX_DVC_VERSION)] {
            let mut mux = DvcMux::new();
            let mut out = Outbox::new();
            mux.message(
                &from_server(&DvcPdu::Capabilities {
                    version: offered,
                    priority_charges: None,
                }),
                STATIC_ID,
                ctx(),
                &mut out,
            )
            .expect("capabilities");
            match sent(&out).first() {
                Some(DvcPdu::Capabilities { version, .. }) => assert_eq!(*version, expected),
                other => panic!("{offered}: expected a capabilities response, got {other:?}"),
            }
        }
    }

    /// A channel we do not speak is refused by name with `STATUS_NOT_FOUND`,
    /// the graphics one is accepted and immediately advertises what it can
    /// decode, and the display control one is accepted and says nothing until
    /// the server's capabilities arrive (MS-RDPEDYC 3.2.5.2,
    /// MS-RDPEGFX 3.3.5.1, MS-RDPEDISP 1.3.1).
    ///
    /// `rdpsnd` stands in for the refused channel here. It used to be the
    /// display control channel, which this build now speaks.
    #[test]
    fn only_the_graphics_channel_is_opened_and_the_rest_are_refused_by_name() {
        let mut mux = DvcMux::new();
        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::Capabilities {
                version: dvc_version::V3,
                priority_charges: None,
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("capabilities");

        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::CreateRequest {
                channel_id: 4,
                channel_name: "rdpdr".to_owned(),
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("refused");
        assert_eq!(
            creation_statuses(&out),
            vec![(4, creation_status::NOT_FOUND)]
        );
        assert!(egfx_payloads(&out).is_empty(), "nothing was opened");

        // The display control channel is accepted, and MS-RDPEDISP 1.3.1
        // says nothing goes out on it until the server has sent its
        // capabilities, so the creation status is the only frame.
        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::CreateRequest {
                channel_id: 6,
                channel_name: DISPLAY_CHANNEL_NAME.to_owned(),
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("accepted");
        assert_eq!(creation_statuses(&out), vec![(6, creation_status::SUCCESS)]);
        assert_eq!(out.frames.len(), 1, "the status and nothing else");

        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::CreateRequest {
                channel_id: 5,
                channel_name: EGFX_CHANNEL_NAME.to_owned(),
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("accepted");
        assert_eq!(creation_statuses(&out), vec![(5, creation_status::SUCCESS)]);
        // The creation status goes out before the graphics traffic: a server
        // that saw the advertisement first would still be deciding what the
        // status was going to be (MS-RDPEGFX 3.3.5.1).
        assert_eq!(out.frames.len(), 2, "the status, then the advertisement");
        assert_eq!(egfx_payloads(&out).len(), 1);
    }

    /// A size asked for before the display control channel exists is held,
    /// not dropped.
    ///
    /// The server opens that channel some way into the session. A resize
    /// arriving first used to be logged and thrown away, which is harmless for
    /// a window being dragged, because another will follow, and wrong for the
    /// size a session was configured with, which is asked for exactly once. A
    /// desktop too tall for the connection request depends entirely on this.
    #[test]
    fn a_resize_before_the_display_channel_is_held_until_it_opens() {
        let mut mux = DvcMux::new();
        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::Capabilities {
                version: dvc_version::V3,
                priority_charges: None,
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("capabilities");

        let mut out = Outbox::new();
        mux.resize(3840, 2160, 100, STATIC_ID, ctx(), &mut out)
            .expect("held");
        assert!(out.frames.is_empty(), "nowhere to send it yet");

        // Opening the channel hands it on. MS-RDPEDISP 1.3.1 still holds it
        // back until the capability PDU, so what is asserted is that the
        // request survived, not that it went out.
        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::CreateRequest {
                channel_id: 6,
                channel_name: DISPLAY_CHANNEL_NAME.to_owned(),
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("accepted");
        assert_eq!(creation_statuses(&out), vec![(6, creation_status::SUCCESS)]);

        assert_eq!(
            mux.deferred_resize, None,
            "the held size was handed to the channel, not still waiting"
        );

        // And a later resize now has somewhere to go, so nothing is held.
        let mut again = Outbox::new();
        mux.resize(1920, 1080, 100, STATIC_ID, ctx(), &mut again)
            .expect("a later resize has a channel now");
        assert_eq!(mux.deferred_resize, None);
    }

    /// The regression the socket test caught.
    ///
    /// MS-RDPEDYC 2.2.3.2: a message that fits in one PDU is a bare
    /// `DYNVC_DATA` with no `DYNVC_DATA_FIRST` in front of it, and on the
    /// graphics channel that is nearly every message. Handing one to
    /// `DvcReassembler` as if it were a continuation is refused as a fragment
    /// with no first, which killed every EGFX session at the capability
    /// confirm. Both shapes have to work, and the reply proves the message
    /// reached the handler intact.
    #[test]
    fn a_whole_message_arrives_as_one_data_pdu_and_a_split_one_is_reassembled() {
        let confirm = egfx_message(&rdp_pdu::vc::egfx::EgfxPdu::CapsConfirm {
            capset: Capset::new(caps_version::V8_1, &[0, 0, 0, 0]),
        });

        // One `DYNVC_DATA` carrying the whole message.
        let (mut mux, channel_id) = opened();
        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::Data {
                channel_id,
                data: Payload::new(&confirm),
                compressed: false,
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("a whole message in one data pdu");
        let whole = egfx_payloads(&out);
        assert_eq!(whole.len(), 1, "the confirm was answered");

        // The same message split across a `DATA_FIRST` and a `DATA`.
        let (mut mux, channel_id) = opened();
        let (head, tail) = confirm.split_at(4);
        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::DataFirst {
                channel_id,
                total_length: confirm.len() as u32,
                data: Payload::new(head),
                compressed: false,
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("the first fragment");
        assert!(
            out.frames.is_empty(),
            "an incomplete message answers nothing"
        );
        mux.message(
            &from_server(&DvcPdu::Data {
                channel_id,
                data: Payload::new(tail),
                compressed: false,
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("the last fragment");
        assert_eq!(
            egfx_payloads(&out),
            whole,
            "a split message produces the same answer as a whole one"
        );
    }

    /// A dynamic channel opened before the version handshake is a server
    /// getting the order wrong (MS-RDPEDYC 1.3.1), and opening one id twice
    /// is a server that has lost track of the session.
    #[test]
    fn the_open_sequence_is_enforced() {
        let mut mux = DvcMux::new();
        let mut out = Outbox::new();
        let err = mux
            .message(
                &from_server(&DvcPdu::CreateRequest {
                    channel_id: 1,
                    channel_name: EGFX_CHANNEL_NAME.to_owned(),
                }),
                STATIC_ID,
                ctx(),
                &mut out,
            )
            .expect_err("before the capability exchange");
        assert!(err.to_string().contains("capability exchange"), "{err}");

        let (mut mux, channel_id) = opened();
        let err = mux
            .message(
                &from_server(&DvcPdu::CreateRequest {
                    channel_id,
                    channel_name: EGFX_CHANNEL_NAME.to_owned(),
                }),
                STATIC_ID,
                ctx(),
                &mut Outbox::new(),
            )
            .expect_err("twice");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    /// RDP 8.0 compressed dynamic channel data is refused by name rather than
    /// with a `todo!()`, and the message says whose decision it was. The
    /// compressed forms are never used unless the client asks for them, and
    /// this one does not: a second 2.5 MB history window for a form no server
    /// volunteers is a budget spent on nothing.
    #[test]
    fn compressed_dynamic_channel_data_is_refused_by_name() {
        let (mut mux, channel_id) = opened();
        for pdu in [
            DvcPdu::Data {
                channel_id,
                data: Payload::new(&[1, 2, 3]),
                compressed: true,
            },
            DvcPdu::DataFirst {
                channel_id,
                total_length: 16,
                data: Payload::new(&[1, 2, 3]),
                compressed: true,
            },
        ] {
            let err = mux
                .message(&from_server(&pdu), STATIC_ID, ctx(), &mut Outbox::new())
                .expect_err("compressed");
            assert!(err.to_string().contains("compressed"), "{err}");
            assert!(err.to_string().contains("never asked for"), "{err}");
        }
    }

    /// We never negotiate multitransport, so there is no tunnel to move a
    /// channel onto and the honest answer is a response listing none
    /// (MS-RDPEDYC 3.2.5.5).
    #[test]
    fn a_soft_sync_request_is_declined_with_zero_tunnels() {
        let (mut mux, _) = opened();
        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::SoftSyncRequest {
                length: 12,
                flags: 0,
                number_of_tunnels: 1,
                channel_lists: Payload::new(&[]),
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("declined");
        let body = unwrap_channel_frame(&out.frames[0]);
        match DvcPdu::decode(&mut Reader::new(&body)).expect("parses") {
            DvcPdu::SoftSyncResponse {
                number_of_tunnels, ..
            } => assert_eq!(number_of_tunnels, 0),
            other => panic!("expected a soft sync response, got {:?}", other.cmd()),
        }
    }

    /// Data for a channel we refused, or one closed while a fragment was in
    /// flight, is the server's timing rather than an error. The PDU is length
    /// prefixed, so skipping it cannot desynchronise the channel.
    #[test]
    fn data_for_a_channel_we_never_opened_is_ignored() {
        let (mut mux, channel_id) = opened();
        let mut out = Outbox::new();
        mux.message(
            &from_server(&DvcPdu::Data {
                channel_id: channel_id + 1,
                data: Payload::new(&[0xE0, 0x04]),
                compressed: false,
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("ignored");
        assert!(out.is_empty());

        // And after a close, the same is true of the channel that was open.
        mux.message(
            &from_server(&DvcPdu::Close { channel_id }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("closed");
        mux.message(
            &from_server(&DvcPdu::Data {
                channel_id,
                data: Payload::new(&[0xE0, 0x04]),
                compressed: false,
            }),
            STATIC_ID,
            ctx(),
            &mut out,
        )
        .expect("ignored");
        assert!(out.is_empty());
    }

    /// A reply longer than one static chunk is split at the drdynvc layer as
    /// well, so one dynamic fragment is always one static chunk. Nothing this
    /// client sends is near the limit; the arithmetic is pinned so the next
    /// channel with a real payload does not find out the hard way.
    #[test]
    fn a_long_reply_is_fragmented_at_both_layers() {
        let (mut mux, channel_id) = opened();
        let mut out = Outbox::new();
        // Three fragments' worth.
        mux.wire = vec![0x5a; MAX_DVC_FRAGMENT * 2 + 11];
        mux.fragment(channel_id, STATIC_ID, ctx(), &mut out)
            .expect("fragments");
        assert_eq!(out.frames.len(), 3);

        let mut total = 0;
        for (i, frame) in out.frames.iter().enumerate() {
            let body = unwrap_channel_frame(frame);
            match DvcPdu::decode(&mut Reader::new(&body)).expect("parses") {
                DvcPdu::DataFirst {
                    total_length, data, ..
                } => {
                    assert_eq!(i, 0, "only the first fragment declares the total");
                    assert_eq!(total_length as usize, MAX_DVC_FRAGMENT * 2 + 11);
                    total += data.len();
                }
                DvcPdu::Data { data, .. } => {
                    assert_ne!(i, 0);
                    total += data.len();
                }
                other => panic!("expected a data pdu, got {:?}", other.cmd()),
            }
            // One dynamic fragment is one static chunk, which is the whole
            // point of `MAX_DVC_FRAGMENT`.
            assert!(
                unwrap_channel_frame(frame).len() <= CHANNEL_CHUNK_LENGTH,
                "fragment {i} would need a second static chunk"
            );
        }
        assert_eq!(total, MAX_DVC_FRAGMENT * 2 + 11);

        // Every frame is a single chunk carrying both flags.
        for frame in &out.frames {
            let mut r = Reader::new(frame);
            let mut body = rdp_pdu::x224::read_data_tpdu(&mut r).expect("x224");
            let rdp_pdu::mcs::DomainMcsPdu::SendDataRequest { payload, .. } =
                rdp_pdu::mcs::DomainMcsPdu::decode(&mut body).expect("mcs")
            else {
                panic!("not a send data request");
            };
            let header = ChannelPduHeader::decode(&mut Reader::new(payload.as_slice()))
                .expect("channel header");
            assert_ne!(header.flags & channel_flags::FIRST, 0);
            assert_ne!(header.flags & channel_flags::LAST, 0);
        }
    }
}
