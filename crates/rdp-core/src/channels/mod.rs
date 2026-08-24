//! Virtual channels: the static layer, the registry, and what a handler may
//! produce (MS-RDPBCGR 2.2.6.1, PRDRDP/05 §5.1, PRDRDP/12 §3.11).
//!
//! # Where this sits
//!
//! [`crate::session::run_loop`] owns the socket and the dispatch. It knows
//! two things about this module and nothing else: a Send Data Indication that
//! is not on the I/O channel goes to [`StaticChannels::deliver`], and a
//! clipboard command goes to [`StaticChannels::clipboard_text`]. Adding a
//! channel is a variant of [`Handler`] and a line in
//! [`StaticChannels::new`]; the run loop does not change.
//!
//! # The four layers, and which one is here
//!
//! `rdp_pdu::vc` draws them (`crates/rdp-pdu/src/vc/mod.rs:12`):
//!
//! ```text
//! MCS Send Data Indication on a channel id      <- the run loop unwraps this
//!   -> CHANNEL_PDU_HEADER, 1600 byte chunks     <- this file
//!     -> drdynvc, DATA_FIRST and DATA           <- channels::dvc
//!       -> RDP_SEGMENTED_DATA, RDP 8.0 bulk     <- channels::egfx
//!         -> RDPGFX_HEADER commands             <- channels::egfx
//! ```
//!
//! Every one of those parsers is in `rdp-pdu` and every reassembler is
//! `rdp-pdu`'s. This crate owns the I/O, the state that spans PDUs, and the
//! policy decisions `rdp-pdu` deliberately refuses to make (PRDRDP/13 §2.7).
//!
//! # Zero copy, layer by layer
//!
//! A chunk that carries `CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST`, which is
//! every clipboard message under 1600 bytes and most EGFX ones, is returned
//! by [`ChannelReassembler::push`] as a borrow of the receive buffer with no
//! copy at all (`crates/rdp-pdu/src/vc/static_vc.rs:388`). The borrow is
//! carried down through drdynvc and into the codecs, so the first byte that
//! is written anywhere is a decoded pixel (D9).

pub mod cliprdr;
pub mod display;
pub mod dvc;
pub mod egfx;
#[cfg(feature = "audio")]
pub mod rdpsnd;

use bytes::Bytes;
use rdp_pdu::vc::static_vc::{
    chunk_channel_pdu, ChannelPduHeader, ChannelReassembler, CHANNEL_CHUNK_LENGTH,
};
use rdp_pdu::{Decode, Encode, Reader, Writer};
use remote_core::SessionEvent;

use crate::connection::activate::send_data_request;
use crate::connection::ChannelMap;
use crate::error::Result;
use crate::options::{CHANNEL_CLIPRDR, CHANNEL_DRDYNVC};

/// What a channel handler produces: events for the shell and frames for the
/// writer task, in the order it produced them.
///
/// Handlers never write and never emit. They push here and the run loop
/// carries it out, which is the same rule
/// [`crate::session::signal::SessionSignal`] states for the I/O channel:
/// parsing stays synchronous and testable against a byte slice with no socket
/// and no runtime.
#[derive(Debug, Default)]
pub struct Outbox {
    /// Events for the shell, in order.
    pub events: Vec<SessionEvent>,
    /// Whole encoded PDUs for the writer task, in order.
    pub frames: Vec<Bytes>,
}

impl Outbox {
    /// An empty outbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True when the handler had nothing to say.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.frames.is_empty()
    }
}

/// What a handler needs in order to answer, and nothing it does not.
///
/// Passed by value on every delivery rather than stored, because two of the
/// three change during a session: the desktop resizes on a reactivation and
/// the backlog changes every PDU. Copying three words is cheaper than a
/// handler holding a stale one.
#[derive(Debug, Clone, Copy)]
pub struct ChannelCtx {
    /// The MCS user channel, the `initiator` of every Send Data Request
    /// (MS-RDPBCGR 2.2.1.13.2.1).
    pub user_channel_id: u16,
    /// The desktop the capability exchange settled on, which is where an
    /// EGFX surface mapped to the output has to fit.
    pub desktop: (u16, u16),
    /// Events the shell has not drained yet.
    ///
    /// This is the only observable back pressure a client has, and MS-RDPEGFX
    /// 2.2.2.13's `queueDepth` is the field it belongs in. See
    /// [`egfx::Egfx::frame_acknowledge`].
    pub event_backlog: u32,
}

/// One static virtual channel: its id, its reassembler and its handler.
#[derive(Debug)]
struct Entry {
    id: u16,
    name: &'static str,
    reassembler: ChannelReassembler,
    handler: Handler,
}

/// The handler for one static virtual channel.
///
/// An enum and not a `Box<dyn ChannelHandler>`, which is the shape a registry
/// usually takes. Two reasons, and the first is the one that decides it:
/// every EGFX frame in the session goes through this dispatch, and a vtable
/// call that cannot be inlined sits between the socket and the codec. The
/// second is that the set of channels a build supports is closed and known at
/// compile time, so a wildcard arm is a bug rather than an extension point,
/// and an enum makes adding a channel break the matches that have to change.
#[derive(Debug)]
enum Handler {
    /// `drdynvc`, the dynamic channel multiplexer (MS-RDPEDYC).
    Dvc(dvc::DvcMux),
    /// `cliprdr`, the clipboard (MS-RDPECLIP).
    Cliprdr(cliprdr::Cliprdr),
}

/// Every static virtual channel this session joined.
///
/// A `Vec` and not a map: a session has two or three virtual channels and a
/// linear scan over three `u16` is faster than hashing one, which is the same
/// call [`ChannelMap::by_name`] makes
/// (`crates/rdp-core/src/connection/mcs.rs:63`).
#[derive(Debug)]
pub struct StaticChannels {
    entries: Vec<Entry>,
}

impl StaticChannels {
    /// Build the registry from the channels the MCS phase actually joined.
    ///
    /// A channel we asked for and the server refused has already been struck
    /// off `map.statics` (`crates/rdp-core/src/connection/mcs.rs:406`), so a
    /// channel with no entry here is one that does not exist, and data
    /// arriving on it is caught by [`ChannelMap::knows`] before it reaches
    /// this module.
    #[must_use]
    pub fn new(map: &ChannelMap) -> Self {
        let mut entries = Vec::with_capacity(map.statics.len());
        for (name, id) in &map.statics {
            // PRDRDP/05 §5.1 gives each channel its own reassembly cap, on
            // the reasoning that a clipboard paste is legitimately megabytes
            // and a dynamic channel message is not.
            let (cap, handler) = match *name {
                CHANNEL_DRDYNVC => (DRDYNVC_REASSEMBLY_CAP, Handler::Dvc(dvc::DvcMux::new())),
                CHANNEL_CLIPRDR => (
                    CLIPRDR_REASSEMBLY_CAP,
                    Handler::Cliprdr(cliprdr::Cliprdr::new()),
                ),
                other => {
                    // Unreachable through `ResolvedOptions`, which builds the
                    // list from the two constants above. A log line rather
                    // than a panic, because the cost of being wrong is one
                    // dead channel and not a dead session.
                    tracing::warn!(channel = other, "joined a channel with no handler");
                    continue;
                }
            };
            entries.push(Entry {
                id: *id,
                name,
                reassembler: ChannelReassembler::with_cap(cap),
                handler,
            });
        }
        Self { entries }
    }

    /// True when `id` is a static virtual channel with a handler.
    #[must_use]
    pub fn handles(&self, id: u16) -> bool {
        self.entries.iter().any(|e| e.id == id)
    }

    /// The name of the channel with this id, for a log line.
    #[must_use]
    pub fn name_of(&self, id: u16) -> Option<&'static str> {
        self.entries.iter().find(|e| e.id == id).map(|e| e.name)
    }

    /// Drop every partial reassembly on every channel.
    ///
    /// Called when the share is deactivated. A fragment that belongs to the
    /// old share must not be glued onto the first chunk of the new one
    /// (PRDRDP/05 §5.1 rule 6), which is the same reason the fast path
    /// reassembler is reset at that point
    /// (`crate::session::run_loop`, the `DeactivateAll` arm).
    pub fn reset(&mut self) {
        for entry in &mut self.entries {
            entry.reassembler.reset();
            match &mut entry.handler {
                Handler::Dvc(mux) => mux.reset(),
                Handler::Cliprdr(clip) => clip.reset(),
            }
        }
    }

    /// One MCS Send Data Indication on a static virtual channel.
    ///
    /// `payload` is a `CHANNEL_PDU_HEADER` and one chunk of a channel PDU
    /// (MS-RDPBCGR 2.2.6.1). It borrows the receive buffer and stays borrowed
    /// all the way down.
    ///
    /// # Errors
    ///
    /// [`RdpError::Pdu`] for a malformed header or a reassembly that broke
    /// its own rules, and whatever the handler reported. A channel id with no
    /// handler is not an error here: the caller has already established the
    /// session joined it, and a channel we joined but do not speak is
    /// ignored with a reason.
    pub fn deliver(
        &mut self,
        channel_id: u16,
        payload: &[u8],
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let Some(entry) = self.entries.iter_mut().find(|e| e.id == channel_id) else {
            tracing::trace!(channel_id, "a joined channel with no handler in this build");
            return Ok(());
        };

        let mut r = Reader::new(payload);
        let header = ChannelPduHeader::decode(&mut r)?;
        let chunk = r.rest();

        // Two disjoint field borrows. The reassembler hands out a view of its
        // own buffer, or of `chunk` itself when the whole PDU arrived in one
        // piece, and the handler is a separate field, so a complete message
        // is dispatched without copying the reassembled bytes first. This is
        // the same shape the fast path takes in
        // `crate::session::run_loop::dispatch_fastpath`.
        let Entry {
            reassembler,
            handler,
            id,
            ..
        } = entry;
        let Some(message) = reassembler.push(header, chunk)? else {
            return Ok(());
        };
        match handler {
            Handler::Dvc(mux) => mux.message(message, *id, ctx, out),
            Handler::Cliprdr(clip) => clip.message(message, *id, ctx, out),
        }
    }

    /// The shell put text on the local clipboard: offer it to the server.
    ///
    /// A no op with no `cliprdr` channel, which is what a server that refused
    /// the join leaves us with.
    ///
    /// # Errors
    ///
    /// Whatever the encoder reported.
    pub fn clipboard_text(&mut self, text: &str, ctx: ChannelCtx, out: &mut Outbox) -> Result<()> {
        for entry in &mut self.entries {
            if let Handler::Cliprdr(clip) = &mut entry.handler {
                return clip.offer_text(text, entry.id, ctx, out);
            }
        }
        tracing::debug!("clipboard text with no cliprdr channel to put it on");
        Ok(())
    }

    /// The window changed size: ask the server to resize the desktop
    /// (MS-RDPEDISP 2.2.2.2, PRDRDP/05 §5.4).
    ///
    /// A no op with no `drdynvc` channel, or with no display control channel
    /// open on it, which is what a server with dynamic resolution turned off
    /// leaves us with.
    ///
    /// # Errors
    ///
    /// Whatever the encoder reported.
    pub fn resize(
        &mut self,
        width: u32,
        height: u32,
        scale_percent: u32,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        for entry in &mut self.entries {
            if let Handler::Dvc(mux) = &mut entry.handler {
                return mux.resize(width, height, scale_percent, entry.id, ctx, out);
            }
        }
        tracing::debug!("a resize with no drdynvc channel to carry it");
        Ok(())
    }

    /// Send a resize the display control debounce held back.
    ///
    /// Called once a second from the run loop's stats tick.
    ///
    /// # Errors
    ///
    /// Whatever the encoder reported.
    pub fn flush_pending_resize(&mut self, ctx: ChannelCtx, out: &mut Outbox) -> Result<()> {
        for entry in &mut self.entries {
            if let Handler::Dvc(mux) = &mut entry.handler {
                return mux.flush_pending_resize(entry.id, ctx, out);
            }
        }
        Ok(())
    }

    /// The shell asked for the server's clipboard contents.
    ///
    /// # Errors
    ///
    /// Whatever the encoder reported.
    pub fn clipboard_request(&mut self, ctx: ChannelCtx, out: &mut Outbox) -> Result<()> {
        for entry in &mut self.entries {
            if let Handler::Cliprdr(clip) = &mut entry.handler {
                return clip.request_text(entry.id, ctx, out);
            }
        }
        Ok(())
    }
}

/// The reassembly cap for `drdynvc` (PRDRDP/05 §5.1).
///
/// Four mebibytes. A dynamic channel message is a graphics frame or a display
/// control PDU, and neither is larger; the EGFX message inside it may
/// decompress to more, and that budget is `rdp_codecs::zgfx`'s.
const DRDYNVC_REASSEMBLY_CAP: usize = 4 * 1024 * 1024;

/// The reassembly cap for `cliprdr` (PRDRDP/05 §5.1).
///
/// Sixteen mebibytes, because a pasted document legitimately is one and a
/// user whose paste silently truncates has no way to find out why.
const CLIPRDR_REASSEMBLY_CAP: usize = 16 * 1024 * 1024;

/// Wrap one channel PDU in `CHANNEL_PDU_HEADER` chunks, each inside its own
/// Send Data Request (MS-RDPBCGR 2.2.6.1).
///
/// The chunk size is [`CHANNEL_CHUNK_LENGTH`], 1600 bytes, which is the value
/// every server accepts. A server may advertise a larger `VCChunkSize` and we
/// do not use it: the win is a handful of MCS headers on a clipboard paste,
/// and the cost of getting it wrong is a channel that desynchronises on the
/// one server whose advertised size we misread.
///
/// # Errors
///
/// [`RdpError::Pdu`] when a chunk will not encode, which means the payload is
/// longer than the length field can carry.
pub fn encode_channel_pdu(
    user_channel_id: u16,
    channel_id: u16,
    payload: &[u8],
    scratch: &mut Vec<u8>,
    out: &mut Vec<Bytes>,
) -> Result<()> {
    // `scratch` is the caller's, and it is the same buffer for every chunk of
    // every PDU on the channel: `send_data_request` copies it into the frame
    // it returns, so it is free to be reused as soon as that call returns.
    // The one allocation left per frame is the frame itself, which is the
    // value handed to the writer task.
    scratch.reserve(ChannelPduHeader::LEN + CHANNEL_CHUNK_LENGTH);
    for chunk in chunk_channel_pdu(payload, CHANNEL_CHUNK_LENGTH) {
        scratch.clear();
        chunk.encode_checked(&mut Writer::new(scratch))?;
        out.push(send_data_request(user_channel_id, channel_id, scratch)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RdpError;

    fn map() -> ChannelMap {
        ChannelMap {
            io_channel_id: 1003,
            user_channel_id: 1007,
            message_channel_id: Some(1005),
            statics: vec![(CHANNEL_DRDYNVC, 1004), (CHANNEL_CLIPRDR, 1006)],
        }
    }

    fn ctx() -> ChannelCtx {
        ChannelCtx {
            user_channel_id: 1007,
            desktop: (800, 600),
            event_backlog: 0,
        }
    }

    /// The registry is built from what was joined, not from what was asked
    /// for, so a channel the server refused has no handler and cannot be
    /// delivered to.
    #[test]
    fn the_registry_holds_one_entry_per_joined_channel() {
        let channels = StaticChannels::new(&map());
        assert!(channels.handles(1004));
        assert!(channels.handles(1006));
        assert!(!channels.handles(1003), "the I/O channel is not a vc");
        assert_eq!(channels.name_of(1004), Some(CHANNEL_DRDYNVC));
        assert_eq!(channels.name_of(1006), Some(CHANNEL_CLIPRDR));
        assert_eq!(channels.name_of(9999), None);

        let mut refused = map();
        refused.statics.retain(|(n, _)| *n != CHANNEL_CLIPRDR);
        let channels = StaticChannels::new(&refused);
        assert!(!channels.handles(1006));
    }

    /// Data on a channel the session joined but this build has no handler for
    /// is ignored rather than failed. The case that matters is a future
    /// build's channel list reaching an older registry through a shared
    /// profile.
    #[test]
    fn a_channel_with_no_handler_is_ignored_rather_than_failed() {
        let mut channels = StaticChannels::new(&map());
        let mut out = Outbox::new();
        channels
            .deliver(4242, &[0; 8], ctx(), &mut out)
            .expect("ignored");
        assert!(out.is_empty());
    }

    /// A chunk whose header does not parse is an error and not a silent drop:
    /// the reassembler's state depends on every header in the sequence, so a
    /// header we could not read means the next one cannot be trusted either.
    #[test]
    fn a_truncated_channel_header_is_an_error() {
        let mut channels = StaticChannels::new(&map());
        let mut out = Outbox::new();
        let err = channels
            .deliver(1006, &[0, 0, 0], ctx(), &mut out)
            .expect_err("truncated");
        assert!(matches!(err, RdpError::Pdu { .. }), "{err}");
    }

    /// The outbound side: one payload becomes as many Send Data Requests as
    /// it has 1600 byte chunks, and every one of them is a whole TPKT frame
    /// the writer task can put on the wire unchanged.
    #[test]
    fn a_long_channel_pdu_is_chunked_into_send_data_requests() {
        let payload = vec![0x5a_u8; CHANNEL_CHUNK_LENGTH * 2 + 7];
        let mut frames = Vec::new();
        let mut scratch = Vec::new();
        encode_channel_pdu(1007, 1006, &payload, &mut scratch, &mut frames).expect("encodes");
        assert_eq!(frames.len(), 3, "two full chunks and a remainder");

        // Every frame is a TPKT unit whose length field is its own length
        // (MS-RDPBCGR 2.2.1.1: version 3, reserved 0, then a big endian u16).
        for frame in &frames {
            assert_eq!(frame[0], 3, "TPKT version");
            let declared = u16::from_be_bytes([frame[2], frame[3]]) as usize;
            assert_eq!(declared, frame.len(), "TPKT length");
        }

        // A payload that fits in one chunk is one frame carrying both flags.
        let mut frames = Vec::new();
        encode_channel_pdu(1007, 1006, b"hello", &mut scratch, &mut frames).expect("encodes");
        assert_eq!(frames.len(), 1);
    }

    /// A deactivation drops every partial reassembly. Without this, the first
    /// chunk of the new share is appended to the tail of the old one and the
    /// channel is desynchronised for the rest of the session.
    #[test]
    fn a_reset_drops_partial_reassemblies_on_every_channel() {
        use rdp_pdu::vc::static_vc::channel_flags;

        let mut channels = StaticChannels::new(&map());
        let mut out = Outbox::new();

        // A FIRST chunk that declares more than it carries: the reassembler
        // is now in progress and waiting for the rest.
        let mut first = Vec::new();
        ChannelPduHeader {
            length: 64,
            flags: channel_flags::FIRST,
        }
        .encode(&mut Writer::new(&mut first))
        .expect("encodes");
        first.extend_from_slice(&[0x11; 16]);
        channels
            .deliver(1006, &first, ctx(), &mut out)
            .expect("buffered");

        channels.reset();

        // A chunk with no FIRST after the reset is refused, which proves the
        // reassembler forgot the message rather than continuing it.
        let mut cont = Vec::new();
        ChannelPduHeader {
            length: 64,
            flags: channel_flags::LAST,
        }
        .encode(&mut Writer::new(&mut cont))
        .expect("encodes");
        cont.extend_from_slice(&[0x22; 48]);
        assert!(channels.deliver(1006, &cont, ctx(), &mut out).is_err());
    }
}
