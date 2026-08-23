//! `cliprdr`, the clipboard (MS-RDPECLIP, PRDRDP/05 §4).
//!
//! # A bridge, not a second clipboard
//!
//! Everything about *what* a clipboard is in this application is already
//! decided: the shell puts text on the OS clipboard
//! (`src-tauri/src/commands/session.rs:932`), a session announces the peer's
//! formats with `remote_core::SessionEvent::ClipboardNotify` and delivers text
//! with `SessionEvent::ClipboardText`, and the shell asks for it with
//! `ClientCommand::ClipboardRequest` and offers ours with
//! `ClientCommand::ClipboardText`. This file speaks MS-RDPECLIP on one side of
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

use rdp_pdu::{PduError, Reader, Writer};
use remote_core::SessionEvent;

use crate::channels::{encode_channel_pdu, ChannelCtx, Outbox};
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
    /// than Unicode. We never read a format name, so it changes nothing here.
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
    long_names: bool,
    /// The text the shell last put on the local clipboard, held until the
    /// server asks for it.
    ///
    /// MS-RDPECLIP is an offer and request protocol: announcing a format does
    /// not send it, and the server asks only when something on its side
    /// pastes. Holding the string is what lets the answer be immediate.
    local: Option<String>,
    /// True when the server's last format list offered text we can ask for.
    server_has_text: bool,
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

    /// Forget the negotiation. The share is being torn down and the server
    /// restarts the clipboard sequence on the new one.
    pub fn reset(&mut self) {
        self.ready = false;
        self.long_names = false;
        self.server_has_text = false;
        // `local` survives: it is what the *user* has on their clipboard, and
        // a reactivation is not a reason to forget it.
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
        // The sender's own `CB_ASCII_NAMES` decides the record width for this
        // message, whatever the capability exchange settled, because
        // MS-RDPECLIP 2.2.3.1.1 makes it a per message flag.
        let long = self.long_names && flags & msg_flags::ASCII_NAMES == 0;
        let ids = format_ids(body, long);
        self.server_has_text = ids.iter().any(|id| is_text(*id));
        tracing::debug!(
            formats = ids.len(),
            text = self.server_has_text,
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

        if self.server_has_text {
            // The shell decides whether to pull it: a notify is cheap and a
            // transfer is not, and pulling every remote copy into the local
            // clipboard unasked is what makes a remote session steal a user's
            // clipboard (PRDRDP/05 §4.3).
            out.events.push(SessionEvent::ClipboardNotify {
                formats: FORMAT_TEXT,
            });
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
        let text = match (&self.local, is_text(requested)) {
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
        // one and refuse the rest above.
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
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|u| *u != 0)
            .collect();
        // Lossy rather than refused: a server sending an unpaired surrogate is
        // sending something no clipboard should hold, and losing one character
        // beats losing the paste.
        let text = crlf_to_lf(&String::from_utf16_lossy(&units));
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
        if !self.ready || !self.server_has_text {
            tracing::debug!(
                ready = self.ready,
                text = self.server_has_text,
                "a clipboard request with nothing to ask for"
            );
            return Ok(());
        }
        self.send_header(
            msg_type::FORMAT_DATA_REQUEST,
            0,
            &format_id::UNICODE_TEXT.to_le_bytes(),
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
        // We asked for long names; the server agrees or it does not, and its
        // own capability set says which. Assuming ours until then is what
        // MS-RDPECLIP 3.1.5.2.1 describes.
        self.long_names = true;
        self.send_header(msg_type::CLIP_CAPS, 0, &body, static_id, ctx, out)
    }

    /// `CB_FORMAT_LIST` (MS-RDPECLIP 2.2.3.1), in the long name form.
    ///
    /// One format when we hold text and none when we do not. The short name
    /// form is never produced: we always ask for long names, and a server
    /// that refuses them still parses a list we send in the form its own
    /// capability set advertised, which is the form we agreed to.
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
        encode_channel_pdu(
            ctx.user_channel_id,
            static_id,
            &self.scratch,
            &mut self.chunk,
            &mut out.frames,
        )
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

/// True for a format id whose payload is text we can present.
///
/// Only `CF_UNICODETEXT` is asked for. `CF_TEXT` and `CF_OEMTEXT` are in the
/// list because a server that offers only those is still offering text, and
/// the notify the shell sees should say so; the request that follows names
/// the Unicode form, which every Windows server synthesises from the others
/// (MS-RDPECLIP 1.3.1.2).
const fn is_text(id: u32) -> bool {
    matches!(
        id,
        format_id::TEXT | format_id::OEM_TEXT | format_id::UNICODE_TEXT
    )
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

    /// The round trip the shell sees: the server offers text, we notify, the
    /// shell asks, the server answers, we emit the text with its line endings
    /// converted.
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
        // The mandatory response, and a notify for the shell.
        assert_eq!(sent(&out)[0].0, msg_type::FORMAT_LIST_RESPONSE);
        assert_eq!(sent(&out)[0].1, msg_flags::RESPONSE_OK);
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

    /// The line ending conversions, including the pair that must not double.
    #[test]
    fn line_endings_convert_both_ways_without_doubling() {
        assert_eq!(lf_to_crlf("a\nb"), "a\r\nb");
        assert_eq!(lf_to_crlf("a\r\nb"), "a\r\nb");
        assert_eq!(crlf_to_lf("a\r\nb"), "a\nb");
        assert_eq!(crlf_to_lf(&lf_to_crlf("a\nb\nc")), "a\nb\nc");
    }
}
