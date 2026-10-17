//! `cliprdr`, the clipboard (MS-RDPECLIP, PRDRDP/05 §4).
//!
//! # A bridge, not a second clipboard
//!
//! Everything about *what* a clipboard is in this application is already
//! decided: the shell puts text on the OS clipboard
//! (`src-tauri/src/commands/session.rs:932`), a session announces the peer's
//! formats with `remote_core::SessionEvent::ClipboardNotify` and delivers text
//! with `SessionEvent::ClipboardText`, and the shell offers ours with
//! `ClientCommand::ClipboardText`. The session pulls the peer's text itself
//! when it is announced, as the RFB session does; an explicit
//! `ClientCommand::ClipboardRequest` is honoured too, and is what an agent's
//! clipboard read sends. This file speaks MS-RDPECLIP on one side of
//! that contract and nothing more. Text only, which is what the RFB side
//! supports today (`crates/vnc-core/src/clipboard/mod.rs:220` encodes text and
//! nothing else on the outbound path).
//!
//! # What was reused from `vnc-core`, and what was not
//!
//! `crates/vnc-core/src/clipboard/mod.rs` holds the pieces this file would
//! otherwise invent: the format bits, the 10 MiB inbound cap, and the two line
//! ending conversions. Its state machine is not reusable here and its wire
//! format certainly is not: `handle_server_cut_text` parses an RFB
//! ServerCutText body with a signed `i32` length whose sign selects the legacy
//! and extended forms, and `encode_client_cut_text` produces zlib framed RFB
//! bytes. None of that has an MS-RDPECLIP counterpart.
//!
//! What is genuinely shared is [`FORMAT_TEXT`], [`MAX_INBOUND_TEXT`],
//! `lf_to_crlf` and `crlf_to_lf`, and they are restated here rather than
//! imported, because importing them means `rdp-core` depending on `vnc-core`,
//! which would put `des`, `rsa`, `aes`, `flate2` and a JPEG decoder into the
//! dependency graph of an RDP session for the sake of thirteen lines. The
//! values match `vnc-core`'s exactly and the constants below say so, so the
//! two do not drift; the right home for them is a `remote_core::clipboard`
//! module, which is a change to a crate this lane does not own.
//!
//! # Line endings
//!
//! Windows puts CRLF on the clipboard and every other platform puts LF, so
//! text is converted in both directions. `vnc-core` makes the same conversion
//! for the same reason (`crates/vnc-core/src/clipboard/mod.rs:92`), which is
//! what stops a paste from an RDP session and a paste from a VNC session
//! behaving differently in the same window.

use std::collections::VecDeque;

use rdp_pdu::{PduError, Reader, Writer};
use remote_core::SessionEvent;

use crate::channels::{encode_channel_pdu_with, ChannelCtx, Outbox};
use crate::error::{RdpError, Result};

/// `msgType` (MS-RDPECLIP 2.2.1).
pub mod msg_type {
    /// `CB_MONITOR_READY`: the server's clipboard is up (2.2.2.1).
    pub const MONITOR_READY: u16 = 0x0001;
    /// `CB_FORMAT_LIST` (2.2.3.1).
    pub const FORMAT_LIST: u16 = 0x0002;
    /// `CB_FORMAT_LIST_RESPONSE` (2.2.3.2).
    pub const FORMAT_LIST_RESPONSE: u16 = 0x0003;
    /// `CB_FORMAT_DATA_REQUEST` (2.2.5.1).
    pub const FORMAT_DATA_REQUEST: u16 = 0x0004;
    /// `CB_FORMAT_DATA_RESPONSE` (2.2.5.2).
    pub const FORMAT_DATA_RESPONSE: u16 = 0x0005;
    /// `CB_TEMP_DIRECTORY` (2.2.2.3).
    pub const TEMP_DIRECTORY: u16 = 0x0006;
    /// `CB_CLIP_CAPS` (2.2.2.1).
    pub const CLIP_CAPS: u16 = 0x0007;
    /// `CB_LOCK_CLIPDATA` (2.2.4.1).
    pub const LOCK_CLIPDATA: u16 = 0x000A;
    /// `CB_UNLOCK_CLIPDATA` (2.2.4.2).
    pub const UNLOCK_CLIPDATA: u16 = 0x000B;
}

/// `msgFlags` (MS-RDPECLIP 2.2.1).
pub mod msg_flags {
    /// `CB_RESPONSE_OK`.
    pub const RESPONSE_OK: u16 = 0x0001;
    /// `CB_RESPONSE_FAIL`.
    pub const RESPONSE_FAIL: u16 = 0x0002;
    /// `CB_ASCII_NAMES`: the short format names in the list are ASCII rather
    /// than Unicode. Both are 32 bytes wide and we never read a format name,
    /// so it changes nothing here. In particular it does not choose between
    /// the short and the long list form: only the capability exchange does
    /// that (MS-RDPECLIP 2.2.3.1).
    pub const ASCII_NAMES: u16 = 0x0004;
}

/// Windows standard clipboard format ids (MS-RDPECLIP 1.3.1.2).
pub mod format_id {
    /// `CF_TEXT`: ANSI text in the server's code page.
    pub const TEXT: u32 = 1;
    /// `CF_OEMTEXT`.
    pub const OEM_TEXT: u32 = 7;
    /// `CF_UNICODETEXT`: UTF-16LE, NUL terminated. The only one we ask for.
    pub const UNICODE_TEXT: u32 = 13;
}

/// `CLIPRDR_GENERAL_CAPABILITY.version` (MS-RDPECLIP 2.2.2.1.1.1).
const CB_CAPS_VERSION_2: u32 = 0x0000_0002;

/// `CB_CAPSTYPE_GENERAL` (MS-RDPECLIP 2.2.2.1.1).
const CB_CAPSTYPE_GENERAL: u16 = 0x0001;

/// The length `CLIPRDR_GENERAL_CAPABILITY` declares for itself: the two byte
/// type, the two byte length, the four byte version and the four byte flags
/// (MS-RDPECLIP 2.2.2.1.1.1).
const GENERAL_CAPABILITY_LEN: u16 = 12;

/// `CB_USE_LONG_FORMAT_NAMES` (MS-RDPECLIP 2.2.2.1.1.1).
///
/// The only flag we set. Long format names make a format list a sequence of
/// `{u32 id, NUL terminated UTF-16LE name}` instead of fixed 36 byte records,
/// which is both easier to parse and what every server since Windows 7 uses.
/// The file transfer flags are deliberately absent: this build moves text.
const CB_USE_LONG_FORMAT_NAMES: u32 = 0x0000_0002;

/// The eight byte `CLIPRDR_HEADER` (MS-RDPECLIP 2.2.1).
const HEADER_LEN: usize = 8;

/// Format bit: plain text.
///
/// The same value as `vnc_core::clipboard::FORMAT_TEXT`
/// (`crates/vnc-core/src/clipboard/mod.rs:25`), because it is the same bit in
/// the same `SessionEvent::ClipboardNotify` the same shell renders. See the
/// module comment for why it is restated rather than imported.
pub const FORMAT_TEXT: u32 = 1 << 0;

/// Inbound text hard cap.
///
/// Ten mebibytes, the same figure as
/// `vnc_core::clipboard::MAX_INBOUND_TEXT`
/// (`crates/vnc-core/src/clipboard/mod.rs:50`), so a paste that is refused on
/// one protocol is refused on the other.
pub const MAX_INBOUND_TEXT: usize = 10 * 1024 * 1024;

/// The clipboard channel.
#[derive(Debug, Default)]
pub struct Cliprdr {
    /// True once `CB_MONITOR_READY` has arrived. Nothing may be sent before
    /// it (MS-RDPECLIP 1.3.2.1).
    ready: bool,
    /// True when both ends agreed long format names.
    ///
    /// We always ask for them, so this is the server's answer and nothing
    /// else: false until its `CB_CLIP_CAPS` says otherwise, because a server
    /// that sends no capabilities is a version 1 server with no flags set
    /// (MS-RDPECLIP 3.1.5.2.1). The server sends its capabilities before the
    /// Monitor Ready, so the answer is already here when our first list goes
    /// out.
    long_names: bool,
    /// The text the shell last put on the local clipboard, held until the
    /// server asks for it.
    ///
    /// MS-RDPECLIP is an offer and request protocol: announcing a format does
    /// not send it, and the server asks only when something on its side
    /// pastes. Holding the string is what lets the answer be immediate.
    local: Option<String>,
    /// The text format the server's last format list offered, if any:
    /// `CF_UNICODETEXT` when it was in the list, otherwise `CF_TEXT` or
    /// `CF_OEMTEXT`. A client may only ask for a format the server offered
    /// (MS-RDPECLIP 3.1.5.2.5).
    server_text: Option<u32>,
    /// The formats we asked for and have not had an answer to, oldest first.
    ///
    /// A `CB_FORMAT_DATA_RESPONSE` does not say which format it carries
    /// (MS-RDPECLIP 2.2.5.2), and the responses come back in the order the
    /// requests went out, so this is how a `CF_TEXT` answer is told from a
    /// `CF_UNICODETEXT` one.
    requested: VecDeque<u32>,
    /// The message under construction, reused.
    scratch: Vec<u8>,
    /// The static channel chunk, reused.
    chunk: Vec<u8>,
}

impl Cliprdr {
    /// A channel that has not seen `CB_MONITOR_READY` yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True once the server has said its clipboard is ready.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.ready
    }

    /// One complete `cliprdr` channel PDU.
    ///
    /// # Errors
    ///
    /// [`RdpError::Pdu`] for a header that did not parse and
    /// [`RdpError::Protocol`] for a body that contradicts its own header.
    pub fn message(
        &mut self,
        message: &[u8],
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let mut r = Reader::new(message);
        let msg_type = r.u16("CLIPRDR_HEADER msgType")?;
        let msg_flags = r.u16("CLIPRDR_HEADER msgFlags")?;
        let data_len = r.u32("CLIPRDR_HEADER dataLen")? as usize;
        // `dataLen` is what the sender says is behind the header. A body
        // shorter than it means the channel reassembly and this header
        // disagree, and reading the shorter one as if it were whole is how a
        // truncated paste becomes a wrong paste.
        let body = r.rest();
        if body.len() < data_len {
            return Err(RdpError::Protocol(format!(
                "a cliprdr message declared {data_len} bytes and carried {} \
                 (MS-RDPECLIP 2.2.1)",
                body.len()
            )));
        }
        let body = body.get(..data_len).unwrap_or(body);
        tracing::trace!(msg_type, msg_flags, data_len, "a cliprdr message");

        match msg_type {
            msg_type::MONITOR_READY => self.monitor_ready(static_id, ctx, out),
            msg_type::CLIP_CAPS => {
                self.capabilities(body);
                Ok(())
            }
            msg_type::FORMAT_LIST => self.format_list(body, msg_flags, static_id, ctx, out),
            msg_type::FORMAT_DATA_REQUEST => self.format_data_request(body, static_id, ctx, out),
            msg_type::FORMAT_DATA_RESPONSE => {
                self.format_data_response(body, msg_flags, out);
                Ok(())
            }
            msg_type::FORMAT_LIST_RESPONSE => {
                if msg_flags & msg_flags::RESPONSE_FAIL != 0 {
                    // The server could not take our offer. Not fatal: the
                    // user's next copy raises a new one.
                    tracing::debug!("the server refused a clipboard format list");
                }
                Ok(())
            }
            // Locking pins a clipboard data id so a delayed file transfer can
            // still find it (MS-RDPECLIP 2.2.4.1). We transfer no files, so
            // there is nothing to pin and nothing to answer.
            msg_type::LOCK_CLIPDATA | msg_type::UNLOCK_CLIPDATA | msg_type::TEMP_DIRECTORY => {
                Ok(())
            }
            other => {
                tracing::trace!(msg_type = other, "a cliprdr message this build ignores");
                Ok(())
            }
        }
    }

    /// `CB_MONITOR_READY` (MS-RDPECLIP 2.2.2.2): the exchange may start.
    ///
    /// The client answers with its capabilities and then with a format list,
    /// in that order (MS-RDPECLIP 1.3.2.1). The first list announces whatever
    /// the shell has already handed us, which is usually nothing; announcing
    /// an empty list is how a client says "my clipboard is empty" and is what
    /// stops the server offering its own contents into a void.
    ///
    /// A second Monitor Ready on the same channel is answered the same way.
    /// Nothing in MS-RDPECLIP forbids a server restarting its clipboard, and
    /// answering twice costs two short PDUs.
    fn monitor_ready(&mut self, static_id: u16, ctx: ChannelCtx, out: &mut Outbox) -> Result<()> {
        self.ready = true;
        tracing::debug!("the server's clipboard is ready");
        self.send_capabilities(static_id, ctx, out)?;
        self.send_format_list(static_id, ctx, out)
    }

    /// `CB_CLIP_CAPS` from the server (MS-RDPECLIP 2.2.2.1).
    ///
    /// One field is read: whether the server agreed long format names. Every
    /// other flag in the general capability set is about file transfer, which
    /// this build does not do. A malformed capability set is not an error:
    /// the defaults are the conservative ones, so the worst case is short
    /// format names, which are also parsed here.
    ///
    /// Sending our own capabilities never changes this. It used to: the
    /// Monitor Ready handler set long names on as it sent ours, which threw
    /// away a server's "no" that had arrived just before it, and every list
    /// we sent such a server after that was in a form it does not parse.
    fn capabilities(&mut self, body: &[u8]) {
        let mut r = Reader::new(body);
        let Ok(count) = r.u16("CLIPRDR_CAPS cCapabilitiesSets") else {
            return;
        };
        if r.skip(2, "CLIPRDR_CAPS pad1").is_err() {
            return;
        }
        for _ in 0..count {
            let (Ok(kind), Ok(len)) = (
                r.u16("CLIPRDR_CAPS_SET capabilitySetType"),
                r.u16("CLIPRDR_CAPS_SET lengthCapability"),
            ) else {
                return;
            };
            // The declared length includes the four bytes just read.
            let Some(rest) = usize::from(len).checked_sub(4) else {
                return;
            };
            let Ok(set) = r.slice(rest, "CLIPRDR_CAPS_SET") else {
                return;
            };
            if kind != CB_CAPSTYPE_GENERAL {
                continue;
            }
            let mut s = Reader::new(set);
            let (Ok(_version), Ok(flags)) = (
                s.u32("CLIPRDR_GENERAL_CAPABILITY version"),
                s.u32("CLIPRDR_GENERAL_CAPABILITY generalFlags"),
            ) else {
                return;
            };
            self.long_names = flags & CB_USE_LONG_FORMAT_NAMES != 0;
            tracing::debug!(
                long_names = self.long_names,
                "the server's clipboard capabilities"
            );
        }
    }

    /// `CB_FORMAT_LIST` from the server (MS-RDPECLIP 2.2.3.1).
    ///
    /// The response is mandatory and is what unblocks the server's own
    /// clipboard thread (MS-RDPECLIP 3.1.5.2.4); a client that does not send
    /// one hangs copy and paste on the server for every application.
    fn format_list(
        &mut self,
        body: &[u8],
        flags: u16,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        // The capability exchange alone decides the list form.
        // `CB_ASCII_NAMES` only says how a short name is encoded, and both
        // encodings are 32 bytes wide (MS-RDPECLIP 2.2.3.1), so it is logged
        // and not acted on.
        let ids = format_ids(body, self.long_names);
        self.server_text = best_text_format(&ids);
        tracing::debug!(
            formats = ids.len(),
            text = ?self.server_text,
            ascii_names = flags & msg_flags::ASCII_NAMES != 0,
            "the server offered clipboard formats"
        );

        self.send_header(
            msg_type::FORMAT_LIST_RESPONSE,
            msg_flags::RESPONSE_OK,
            &[],
            static_id,
            ctx,
            out,
        )?;

        if let Some(format) = self.server_text {
            out.events.push(SessionEvent::ClipboardNotify {
                formats: FORMAT_TEXT,
            });
            // Pulled now rather than left for the shell to ask for. The shell
            // never asks: it treats a notify as information and waits for the
            // `ClipboardText` that follows, because that is what the RFB
            // session does (`crates/vnc-core/src/session/run_loop.rs`, the
            // `ACTION_NOTIFY` arm, pulls on every notify). Leaving the pull to
            // the shell meant nothing copied on a Windows desktop ever
            // reached this side (issue #9). Whether the clipboard is shared
            // at all is decided before the channel is requested, by the
            // host's clipboard setting.
            self.send_request(format, static_id, ctx, out)?;
        }
        Ok(())
    }

    /// `CB_FORMAT_DATA_REQUEST` from the server (MS-RDPECLIP 2.2.5.1): it
    /// wants what we announced.
    fn format_data_request(
        &mut self,
        body: &[u8],
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let requested = Reader::new(body).u32("CLIPRDR_FORMAT_DATA_REQUEST requestedFormatId")?;
        let text = match (&self.local, requested == format_id::UNICODE_TEXT) {
            (Some(text), true) => text,
            _ => {
                // MS-RDPECLIP 3.1.5.2.6: a client with nothing to give
                // answers with `CB_RESPONSE_FAIL`, which is a normal outcome
                // and not an error, and never with silence.
                tracing::debug!(requested, "refusing a clipboard request we cannot answer");
                return self.send_header(
                    msg_type::FORMAT_DATA_RESPONSE,
                    msg_flags::RESPONSE_FAIL,
                    &[],
                    static_id,
                    ctx,
                    out,
                );
            }
        };
        // `CF_UNICODETEXT` is UTF-16LE with a NUL terminator
        // (MS-RDPECLIP 2.2.5.2). `CF_TEXT` is the server's ANSI code page,
        // which we have no way to know, so we only ever answer the Unicode
        // one and refuse the rest above. That costs nothing: we announce only
        // `CF_UNICODETEXT`, and Windows synthesises the other two from it on
        // its own side. Answering a `CF_TEXT` request with UTF-16, as this
        // once did, pasted a NUL after the first character.
        let mut data = Vec::with_capacity(text.len() * 2 + 2);
        for unit in lf_to_crlf(text).encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
        self.send_header(
            msg_type::FORMAT_DATA_RESPONSE,
            msg_flags::RESPONSE_OK,
            &data,
            static_id,
            ctx,
            out,
        )
    }

    /// `CB_FORMAT_DATA_RESPONSE` from the server (MS-RDPECLIP 2.2.5.2): the
    /// text we asked for.
    fn format_data_response(&mut self, body: &[u8], flags: u16, out: &mut Outbox) {
        // An answer nobody is waiting for is read as the Unicode form, which
        // is the only one a well behaved server would volunteer.
        let format = self
            .requested
            .pop_front()
            .unwrap_or(format_id::UNICODE_TEXT);
        if flags & msg_flags::RESPONSE_OK == 0 {
            tracing::debug!("the server could not produce the clipboard format we asked for");
            return;
        }
        if body.len() > MAX_INBOUND_TEXT {
            // Refused rather than truncated: half a paste is worse than none,
            // and the same cap refuses the same paste on the RFB side.
            tracing::warn!(
                bytes = body.len(),
                "refusing a clipboard payload past the inbound cap"
            );
            return;
        }
        let text = if format == format_id::UNICODE_TEXT {
            let units: Vec<u16> = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|u| *u != 0)
                .collect();
            // Lossy rather than refused: a server sending an unpaired
            // surrogate is sending something no clipboard should hold, and
            // losing one character beats losing the paste.
            String::from_utf16_lossy(&units)
        } else {
            // `CF_TEXT` or `CF_OEMTEXT`, asked for only because the server
            // offered no Unicode form. The code page is the server's and is
            // not on the wire, so each byte is taken as Latin-1: exact for
            // ASCII, which is what a server offering only these formats
            // usually holds, and one wrong character rather than a lost paste
            // for anything else.
            body.iter()
                .take_while(|b| **b != 0)
                .map(|b| char::from(*b))
                .collect()
        };
        let text = crlf_to_lf(&text);
        tracing::debug!(
            chars = text.chars().count(),
            "clipboard text from the server"
        );
        out.events.push(SessionEvent::ClipboardText(text));
    }

    /// The shell put text on the local clipboard: announce it.
    ///
    /// The text is held rather than sent. MS-RDPECLIP is offer and request:
    /// the server pulls it when something on its side pastes, which is what
    /// keeps a copy of a large document off the wire until somebody wants it.
    ///
    /// # Errors
    ///
    /// Whatever the encoder reported.
    pub fn offer_text(
        &mut self,
        text: &str,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        self.local = Some(text.to_owned());
        if !self.ready {
            // Nothing may go out before `CB_MONITOR_READY` (MS-RDPECLIP
            // 1.3.2.1). The text is kept, and the format list that follows
            // the monitor ready will announce it.
            return Ok(());
        }
        self.send_format_list(static_id, ctx, out)
    }

    /// The shell asked for the server's clipboard.
    ///
    /// # Errors
    ///
    /// Whatever the encoder reported.
    pub fn request_text(
        &mut self,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let Some(format) = self.server_text.filter(|_| self.ready) else {
            tracing::debug!(
                ready = self.ready,
                text = ?self.server_text,
                "a clipboard request with nothing to ask for"
            );
            return Ok(());
        };
        self.send_request(format, static_id, ctx, out)
    }

    /// `CB_FORMAT_DATA_REQUEST` (MS-RDPECLIP 2.2.5.1) for one format, noted
    /// so its answer is decoded as that format.
    fn send_request(
        &mut self,
        format: u32,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        self.requested.push_back(format);
        self.send_header(
            msg_type::FORMAT_DATA_REQUEST,
            0,
            &format.to_le_bytes(),
            static_id,
            ctx,
            out,
        )
    }

    /// `CB_CLIP_CAPS` (MS-RDPECLIP 2.2.2.1).
    fn send_capabilities(
        &mut self,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let mut body = Vec::with_capacity(4 + usize::from(GENERAL_CAPABILITY_LEN));
        {
            let mut w = Writer::new(&mut body);
            w.u16(1); // cCapabilitiesSets
            w.u16(0); // pad1
            w.u16(CB_CAPSTYPE_GENERAL);
            w.u16(GENERAL_CAPABILITY_LEN);
            w.u32(CB_CAPS_VERSION_2);
            w.u32(CB_USE_LONG_FORMAT_NAMES);
        }
        // `long_names` is left alone: it is the server's answer, and the
        // server has usually given it already (see the field).
        self.send_header(msg_type::CLIP_CAPS, 0, &body, static_id, ctx, out)
    }

    /// `CB_FORMAT_LIST` (MS-RDPECLIP 2.2.3.1), in the long name form.
    ///
    /// One format when we hold text and none when we do not, in whichever
    /// form the capability exchange settled: long names when the server
    /// agreed them, the 36 byte short form when it did not or sent no
    /// capabilities at all.
    fn send_format_list(
        &mut self,
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let mut body = Vec::new();
        if self.local.is_some() {
            let mut w = Writer::new(&mut body);
            w.u32(format_id::UNICODE_TEXT);
            if self.long_names {
                // An empty NUL terminated UTF-16LE name: a standard format
                // has no name (MS-RDPECLIP 2.2.3.1.2).
                w.u16(0);
            } else {
                // The short form pads the name to 32 bytes
                // (MS-RDPECLIP 2.2.3.1.1).
                w.bytes(&[0u8; 32]);
            }
        }
        self.send_header(msg_type::FORMAT_LIST, 0, &body, static_id, ctx, out)
    }

    /// Frame one message and queue it.
    fn send_header(
        &mut self,
        msg_type: u16,
        flags: u16,
        body: &[u8],
        static_id: u16,
        ctx: ChannelCtx,
        out: &mut Outbox,
    ) -> Result<()> {
        let len = u32::try_from(body.len()).map_err(|_| {
            RdpError::from(PduError::Encode {
                context: "CLIPRDR_HEADER",
                reason: "body longer than dataLen can hold",
            })
        })?;
        self.scratch.clear();
        self.scratch.reserve(HEADER_LEN + body.len());
        {
            let mut w = Writer::new(&mut self.scratch);
            w.u16(msg_type);
            w.u16(flags);
            w.u32(len);
            w.bytes(body);
        }
        // Windows reads `cliprdr` with the channel header shown, the way its
        // own client sends it, and ignored this channel entirely without
        // the flag (see `encode_channel_pdu_with`).
        encode_channel_pdu_with(
            ctx.user_channel_id,
            static_id,
            &self.scratch,
            rdp_pdu::vc::static_vc::channel_flags::SHOW_PROTOCOL,
            &mut self.chunk,
            &mut out.frames,
        )?;
        tracing::trace!(msg_type, len, static_id, "sent a cliprdr message");
        Ok(())
    }
}

/// The format ids one `CLIPRDR_FORMAT_LIST` body announces
/// (MS-RDPECLIP 2.2.3.1.1, 2.2.3.1.2).
///
/// Names are skipped rather than decoded. We ask for one standard format and
/// standard formats have no name; a registered format's name would only
/// matter to a client that could do something with the payload behind it.
///
/// A body that runs out mid record ends the list rather than failing it: the
/// format list is advisory, and a truncated one that still named text is
/// worth acting on.
fn format_ids(body: &[u8], long_names: bool) -> Vec<u32> {
    let mut ids = Vec::new();
    let mut r = Reader::new(body);
    while r.remaining() >= 4 {
        let Ok(id) = r.u32("CLIPRDR_FORMAT_LIST formatId") else {
            break;
        };
        ids.push(id);
        if long_names {
            // A NUL terminated UTF-16LE name: two zero bytes on an even
            // boundary end it.
            loop {
                match r.u16("CLIPRDR_LONG_FORMAT_NAME") {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => return ids,
                }
            }
        } else if r.skip(32, "CLIPRDR_SHORT_FORMAT_NAME").is_err() {
            return ids;
        }
    }
    ids
}

/// The text format to ask for out of a server's format list, if it offered
/// one.
///
/// `CF_UNICODETEXT` whenever it is there, which on Windows is always, because
/// the OS synthesises it from either of the other two (MS-RDPECLIP 1.3.1.2).
/// A server that is not Windows may offer only `CF_TEXT` or `CF_OEMTEXT`, and
/// asking it for a format it never offered gets a refusal at best
/// (MS-RDPECLIP 3.1.5.2.5), so the one it did offer is asked for instead.
fn best_text_format(ids: &[u32]) -> Option<u32> {
    [
        format_id::UNICODE_TEXT,
        format_id::TEXT,
        format_id::OEM_TEXT,
    ]
    .into_iter()
    .find(|wanted| ids.contains(wanted))
}

/// Normalise to CRLF for the wire.
///
/// The same function as `vnc_core::clipboard::lf_to_crlf`
/// (`crates/vnc-core/src/clipboard/mod.rs:92`), including its handling of an
/// existing CRLF pair, which must not become CRCRLF.
fn lf_to_crlf(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    let mut prev_cr = false;
    for c in s.chars() {
        if c == '\n' && !prev_cr {
            out.push('\r');
        }
        prev_cr = c == '\r';
        out.push(c);
    }
    out
}

/// Normalise CRLF pairs to LF on the way in.
///
/// The same function as `vnc_core::clipboard::crlf_to_lf`
/// (`crates/vnc-core/src/clipboard/mod.rs:106`).
fn crlf_to_lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::dvc::unwrap_channel_frame;

    fn ctx() -> ChannelCtx {
        ChannelCtx {
            user_channel_id: 1007,
            desktop: (800, 600),
            event_backlog: 0,
        }
    }

    /// One `CLIPRDR_HEADER` and its body, as a server would send it.
    fn from_server(msg_type: u16, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u16(msg_type);
        w.u16(flags);
        w.u32(body.len() as u32);
        w.bytes(body);
        out
    }

    /// The `msgType` and body of every frame the channel queued.
    fn sent(out: &Outbox) -> Vec<(u16, u16, Vec<u8>)> {
        out.frames
            .iter()
            .map(|f| {
                let pdu = unwrap_channel_frame(f);
                let mut r = Reader::new(&pdu);
                let t = r.u16("msgType").expect("msgType");
                let f = r.u16("msgFlags").expect("msgFlags");
                let len = r.u32("dataLen").expect("dataLen") as usize;
                (t, f, r.rest().get(..len).unwrap_or(&[]).to_vec())
            })
            .collect()
    }

    fn caps_from_server(long_names: bool) -> Vec<u8> {
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u16(1);
        w.u16(0);
        w.u16(CB_CAPSTYPE_GENERAL);
        w.u16(GENERAL_CAPABILITY_LEN);
        w.u32(CB_CAPS_VERSION_2);
        w.u32(if long_names {
            CB_USE_LONG_FORMAT_NAMES
        } else {
            0
        });
        from_server(msg_type::CLIP_CAPS, 0, &body)
    }

    /// A long format name list offering `CF_UNICODETEXT`.
    fn text_format_list() -> Vec<u8> {
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u32(format_id::UNICODE_TEXT);
        w.u16(0);
        from_server(msg_type::FORMAT_LIST, 0, &body)
    }

    fn utf16(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// Nothing goes out before `CB_MONITOR_READY`, and the two messages that
    /// follow it go out in the order MS-RDPECLIP 1.3.2.1 sets.
    /// Every chunk we send carries `CHANNEL_FLAG_SHOW_PROTOCOL`. Without it
    /// a Windows server ignored the whole channel: no format list response,
    /// no data request, nothing copied in either direction (issue #9).
    #[test]
    fn every_chunk_we_send_shows_the_channel_header() {
        use rdp_pdu::mcs::DomainMcsPdu;
        use rdp_pdu::vc::static_vc::{channel_flags, ChannelPduHeader};
        use rdp_pdu::Decode;

        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");
        // Long enough to need several chunks.
        clip.offer_text(&"x".repeat(5000), 1006, ctx(), &mut out)
            .expect("offer");
        clip.message(
            &from_server(
                msg_type::FORMAT_DATA_REQUEST,
                0,
                &format_id::UNICODE_TEXT.to_le_bytes(),
            ),
            1006,
            ctx(),
            &mut out,
        )
        .expect("request");
        assert!(out.frames.len() > 3, "the paste spans several chunks");
        for frame in &out.frames {
            let mut r = Reader::new(frame);
            let mut body = rdp_pdu::x224::read_data_tpdu(&mut r).expect("x224");
            let DomainMcsPdu::SendDataRequest { payload, .. } =
                DomainMcsPdu::decode(&mut body).expect("mcs")
            else {
                panic!("not a send data request");
            };
            let header = ChannelPduHeader::decode(&mut Reader::new(payload.as_slice()))
                .expect("channel header");
            assert_ne!(
                header.flags & channel_flags::SHOW_PROTOCOL,
                0,
                "{:#x}",
                header.flags
            );
        }
    }

    #[test]
    fn the_exchange_starts_at_monitor_ready_and_not_before() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        assert!(!clip.ready());

        clip.offer_text("held", 1006, ctx(), &mut out)
            .expect("held");
        assert!(
            out.frames.is_empty(),
            "nothing goes out before monitor ready"
        );

        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");
        assert!(clip.ready());

        let sent = sent(&out);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].0, msg_type::CLIP_CAPS);
        assert_eq!(sent[1].0, msg_type::FORMAT_LIST);
        // The text held before the channel was ready is in the first list.
        assert_eq!(
            u32::from_le_bytes([sent[1].2[0], sent[1].2[1], sent[1].2[2], sent[1].2[3]]),
            format_id::UNICODE_TEXT
        );
    }

    /// The round trip the shell sees: the server offers text, we notify and
    /// pull it, the server answers, we emit the text with its line endings
    /// converted. A request from the shell on top of that is still honoured,
    /// which is what an agent's clipboard read sends.
    #[test]
    fn text_from_the_server_reaches_the_shell() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");
        clip.message(&caps_from_server(true), 1006, ctx(), &mut out)
            .expect("caps");

        let mut out = Outbox::new();
        clip.message(&text_format_list(), 1006, ctx(), &mut out)
            .expect("list");
        // The mandatory response, the pull, and a notify for the shell.
        assert_eq!(sent(&out)[0].0, msg_type::FORMAT_LIST_RESPONSE);
        assert_eq!(sent(&out)[0].1, msg_flags::RESPONSE_OK);
        assert_eq!(sent(&out)[1].0, msg_type::FORMAT_DATA_REQUEST);
        assert!(matches!(
            out.events.first(),
            Some(SessionEvent::ClipboardNotify {
                formats: FORMAT_TEXT
            })
        ));

        let mut out = Outbox::new();
        clip.request_text(1006, ctx(), &mut out).expect("request");
        let sent = sent(&out);
        assert_eq!(sent[0].0, msg_type::FORMAT_DATA_REQUEST);
        assert_eq!(
            u32::from_le_bytes([sent[0].2[0], sent[0].2[1], sent[0].2[2], sent[0].2[3]]),
            format_id::UNICODE_TEXT
        );

        let mut out = Outbox::new();
        clip.message(
            &from_server(
                msg_type::FORMAT_DATA_RESPONSE,
                msg_flags::RESPONSE_OK,
                &utf16("one\r\ntwo"),
            ),
            1006,
            ctx(),
            &mut out,
        )
        .expect("data");
        match out.events.first() {
            Some(SessionEvent::ClipboardText(text)) => assert_eq!(text, "one\ntwo"),
            other => panic!("expected clipboard text, got {other:?}"),
        }
    }

    /// The other direction: our text is announced, the server asks, and what
    /// goes back is UTF-16LE with CRLF line endings and a NUL terminator.
    #[test]
    fn text_from_the_shell_reaches_the_server() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");

        let mut out = Outbox::new();
        clip.offer_text("a\nb", 1006, ctx(), &mut out)
            .expect("offer");
        assert_eq!(sent(&out)[0].0, msg_type::FORMAT_LIST);

        let mut out = Outbox::new();
        clip.message(
            &from_server(
                msg_type::FORMAT_DATA_REQUEST,
                0,
                &format_id::UNICODE_TEXT.to_le_bytes(),
            ),
            1006,
            ctx(),
            &mut out,
        )
        .expect("request");
        let sent = sent(&out);
        assert_eq!(sent[0].0, msg_type::FORMAT_DATA_RESPONSE);
        assert_eq!(sent[0].1, msg_flags::RESPONSE_OK);
        // "a\r\nb\0" as UTF-16LE.
        assert_eq!(sent[0].2, utf16("a\r\nb"));
    }

    /// A request we cannot answer gets `CB_RESPONSE_FAIL` and never silence:
    /// a server waiting on a response that never comes hangs its own
    /// clipboard for every application on the desktop.
    #[test]
    fn a_request_we_cannot_answer_is_refused_rather_than_dropped() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");

        // Nothing held at all.
        let mut out = Outbox::new();
        clip.message(
            &from_server(
                msg_type::FORMAT_DATA_REQUEST,
                0,
                &format_id::UNICODE_TEXT.to_le_bytes(),
            ),
            1006,
            ctx(),
            &mut out,
        )
        .expect("request");
        assert_eq!(sent(&out)[0].1, msg_flags::RESPONSE_FAIL);

        // Held text, but a format we do not produce.
        clip.local = Some("x".into());
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::FORMAT_DATA_REQUEST, 0, &2u32.to_le_bytes()),
            1006,
            ctx(),
            &mut out,
        )
        .expect("request");
        assert_eq!(sent(&out)[0].1, msg_flags::RESPONSE_FAIL);
    }

    /// A header that declares more than it carries is refused rather than
    /// read short, because a truncated paste that looks whole is a wrong
    /// paste.
    #[test]
    fn a_body_shorter_than_its_declared_length_is_refused() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        let mut pdu = from_server(
            msg_type::FORMAT_DATA_RESPONSE,
            msg_flags::RESPONSE_OK,
            &[1, 2, 3, 4],
        );
        pdu.truncate(HEADER_LEN + 2);
        let err = clip
            .message(&pdu, 1006, ctx(), &mut out)
            .expect_err("short");
        assert!(err.to_string().contains("declared 4 bytes"), "{err}");
    }

    /// Both format list forms are walked, and a truncated one ends rather
    /// than failing.
    #[test]
    fn format_ids_are_read_from_both_list_forms() {
        // Long: id, empty name; id, a two character name.
        let mut long = Vec::new();
        let mut w = Writer::new(&mut long);
        w.u32(13);
        w.u16(0);
        w.u32(0xC0DE);
        w.u16(u16::from(b'H'));
        w.u16(u16::from(b'i'));
        w.u16(0);
        assert_eq!(format_ids(&long, true), vec![13, 0xC0DE]);

        // Short: 4 + 32 bytes per record.
        let mut short = Vec::new();
        short.extend_from_slice(&1u32.to_le_bytes());
        short.extend_from_slice(&[0u8; 32]);
        short.extend_from_slice(&13u32.to_le_bytes());
        short.extend_from_slice(&[0u8; 32]);
        assert_eq!(format_ids(&short, false), vec![1, 13]);

        // Truncated mid name: the ids read so far still count.
        assert_eq!(format_ids(&short[..10], false), vec![1]);
        assert!(format_ids(&[], true).is_empty());
    }

    /// A paste past the cap is refused whole rather than truncated, and the
    /// cap is the RFB path's so the two agree.
    #[test]
    fn an_oversized_paste_is_refused_rather_than_truncated() {
        assert_eq!(MAX_INBOUND_TEXT, 10 * 1024 * 1024);
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        let body = vec![0x41u8; MAX_INBOUND_TEXT + 2];
        clip.message(
            &from_server(
                msg_type::FORMAT_DATA_RESPONSE,
                msg_flags::RESPONSE_OK,
                &body,
            ),
            1006,
            ctx(),
            &mut out,
        )
        .expect("survives");
        assert!(out.events.is_empty(), "nothing was emitted");
    }

    /// The Monitor Ready handler used to set long format names on as it sent
    /// our capabilities, which threw away the server's answer: Windows sends
    /// its `CB_CLIP_CAPS` before the Monitor Ready (MS-RDPECLIP 1.3.2.1), so
    /// a server that said no was then sent long form lists it reads as
    /// garbage. The list now goes out in the form the server agreed.
    #[test]
    fn a_server_that_refuses_long_names_gets_short_format_lists() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.offer_text("held", 1006, ctx(), &mut out)
            .expect("held");
        clip.message(&caps_from_server(false), 1006, ctx(), &mut out)
            .expect("caps");
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");

        let sent = sent(&out);
        assert_eq!(sent[0].0, msg_type::CLIP_CAPS);
        assert_eq!(sent[1].0, msg_type::FORMAT_LIST);
        // One 36 byte short record: the id and a 32 byte name.
        assert_eq!(sent[1].2.len(), 36, "{:?}", sent[1].2);
        assert_eq!(format_ids(&sent[1].2, false), vec![format_id::UNICODE_TEXT]);
    }

    /// A server that sends no capabilities at all is a version 1 server with
    /// no flags (MS-RDPECLIP 3.1.5.2.1), so it gets the short form too. One
    /// that agrees long names gets the long form, whichever order its
    /// capabilities and the shell's offer arrive in.
    #[test]
    fn the_list_form_follows_the_server_capabilities() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");
        let mut out = Outbox::new();
        clip.offer_text("x", 1006, ctx(), &mut out).expect("offer");
        assert_eq!(sent(&out)[0].2.len(), 36, "no capabilities, short form");

        clip.message(&caps_from_server(true), 1006, ctx(), &mut out)
            .expect("caps");
        let mut out = Outbox::new();
        clip.offer_text("y", 1006, ctx(), &mut out).expect("offer");
        // The id and an empty NUL terminated UTF-16LE name.
        assert_eq!(sent(&out)[0].2, [13, 0, 0, 0, 0, 0]);
    }

    /// Text copied on the server reaches the shell with no request from the
    /// shell, which never sends one (issue #9). The pull names the format the
    /// server offered.
    #[test]
    fn the_server_text_is_pulled_without_the_shell_asking() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.message(&caps_from_server(true), 1006, ctx(), &mut out)
            .expect("caps");
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");

        // A Windows Server list: registered formats with names, and the three
        // text formats with none.
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u32(0xC004);
        for unit in "Rich Text Format".encode_utf16() {
            w.u16(unit);
        }
        w.u16(0);
        for id in [
            format_id::UNICODE_TEXT,
            16,
            format_id::TEXT,
            format_id::OEM_TEXT,
        ] {
            w.u32(id);
            w.u16(0);
        }
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::FORMAT_LIST, 0, &body),
            1006,
            ctx(),
            &mut out,
        )
        .expect("list");
        let sent = sent(&out);
        assert_eq!(sent[0].0, msg_type::FORMAT_LIST_RESPONSE);
        assert_eq!(sent[1].0, msg_type::FORMAT_DATA_REQUEST);
        assert_eq!(sent[1].2, format_id::UNICODE_TEXT.to_le_bytes());

        let mut out = Outbox::new();
        clip.message(
            &from_server(
                msg_type::FORMAT_DATA_RESPONSE,
                msg_flags::RESPONSE_OK,
                &utf16("copied on the server"),
            ),
            1006,
            ctx(),
            &mut out,
        )
        .expect("data");
        assert!(matches!(
            out.events.as_slice(),
            [SessionEvent::ClipboardText(t)] if t == "copied on the server"
        ));
    }

    /// A short name list (long names not agreed) that offers only `CF_TEXT`,
    /// with `CB_ASCII_NAMES` set: the request names `CF_TEXT`, because asking
    /// for a format the server never offered is refused, and the answer is
    /// read as bytes rather than as UTF-16.
    #[test]
    fn a_server_offering_only_cf_text_is_asked_for_cf_text() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.message(&caps_from_server(false), 1006, ctx(), &mut out)
            .expect("caps");
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");

        let mut body = Vec::new();
        body.extend_from_slice(&format_id::TEXT.to_le_bytes());
        body.extend_from_slice(&[0u8; 32]);
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::FORMAT_LIST, msg_flags::ASCII_NAMES, &body),
            1006,
            ctx(),
            &mut out,
        )
        .expect("list");
        let requests: Vec<_> = sent(&out)
            .into_iter()
            .filter(|m| m.0 == msg_type::FORMAT_DATA_REQUEST)
            .collect();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].2, format_id::TEXT.to_le_bytes());

        let mut out = Outbox::new();
        clip.message(
            &from_server(
                msg_type::FORMAT_DATA_RESPONSE,
                msg_flags::RESPONSE_OK,
                b"one\r\ntwo\0",
            ),
            1006,
            ctx(),
            &mut out,
        )
        .expect("data");
        assert!(matches!(
            out.events.as_slice(),
            [SessionEvent::ClipboardText(t)] if t == "one\ntwo"
        ));
    }

    /// `CB_ASCII_NAMES` does not switch a long name list to the short form.
    /// Only the capability exchange decides that (MS-RDPECLIP 2.2.3.1), and
    /// reading a long list as short records skips straight past the text
    /// format.
    #[test]
    fn the_ascii_names_flag_does_not_change_the_list_form() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.message(&caps_from_server(true), 1006, ctx(), &mut out)
            .expect("caps");
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");
        // A named format first, so a short form reading lands its 32 byte
        // skip in the middle of the name and never sees the text format.
        let mut body = Vec::new();
        let mut w = Writer::new(&mut body);
        w.u32(0xC0DE);
        for unit in "HTML Format".encode_utf16() {
            w.u16(unit);
        }
        w.u16(0);
        w.u32(format_id::UNICODE_TEXT);
        w.u16(0);
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::FORMAT_LIST, msg_flags::ASCII_NAMES, &body),
            1006,
            ctx(),
            &mut out,
        )
        .expect("list");
        assert!(matches!(
            out.events.as_slice(),
            [SessionEvent::ClipboardNotify { .. }]
        ));
    }

    /// We announce only `CF_UNICODETEXT`, so a `CF_TEXT` request is refused
    /// rather than answered with UTF-16, which the server would paste as one
    /// character followed by a NUL.
    #[test]
    fn a_cf_text_request_is_refused_rather_than_answered_in_utf16() {
        let mut clip = Cliprdr::new();
        let mut out = Outbox::new();
        clip.message(
            &from_server(msg_type::MONITOR_READY, 0, &[]),
            1006,
            ctx(),
            &mut out,
        )
        .expect("ready");
        clip.offer_text("abc", 1006, ctx(), &mut out)
            .expect("offer");
        let mut out = Outbox::new();
        clip.message(
            &from_server(
                msg_type::FORMAT_DATA_REQUEST,
                0,
                &format_id::TEXT.to_le_bytes(),
            ),
            1006,
            ctx(),
            &mut out,
        )
        .expect("request");
        assert_eq!(sent(&out)[0].0, msg_type::FORMAT_DATA_RESPONSE);
        assert_eq!(sent(&out)[0].1, msg_flags::RESPONSE_FAIL);
    }

    /// The line ending conversions, including the pair that must not double.
    #[test]
    fn line_endings_convert_both_ways_without_doubling() {
        assert_eq!(lf_to_crlf("a\nb"), "a\r\nb");
        assert_eq!(lf_to_crlf("a\r\nb"), "a\r\nb");
        assert_eq!(crlf_to_lf("a\r\nb"), "a\nb");
        assert_eq!(crlf_to_lf(&lf_to_crlf("a\nb\nc")), "a\nb\nc");
    }
}
