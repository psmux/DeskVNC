//! Clipboard protocol layer: legacy Latin-1 cut text plus the Extended
//! Clipboard pseudo-encoding (`0xc0a1e5ce`) notify/request/provide flow
//! (PRD/07 §1).
//!
//! Framing convention: every `encode_*` function here returns the message
//! BODY, everything after the ClientCutText (6) / ServerCutText (3) message
//! type byte, i.e. `3 pad bytes + i32 length + payload`. Correspondingly,
//! [`handle_server_cut_text`] expects the payload after the type byte.
//!
//! The length field is a SIGNED i32: positive = legacy Latin-1 text,
//! negative = an extended-clipboard message of `abs(length)` bytes.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;

// ---------------------------------------------------------------------------
// Flag constants (extended clipboard, PRD/07 §1.2)
// ---------------------------------------------------------------------------

/// Format bit: plain text (UTF-8, CRLF line endings, NUL-terminated).
pub const FORMAT_TEXT: u32 = 1 << 0;
/// Format bit: RTF.
pub const FORMAT_RTF: u32 = 1 << 1;
/// Format bit: HTML (Microsoft clipboard fragment format).
pub const FORMAT_HTML: u32 = 1 << 2;
/// Format bit: DIB (BMPv5 without file header).
pub const FORMAT_DIB: u32 = 1 << 3;
/// Format bit: files (reserved/undefined).
pub const FORMAT_FILES: u32 = 1 << 4;
/// All defined format bits.
pub const FORMAT_MASK: u32 = 0x1f;

/// Action bit: capabilities announcement.
pub const ACTION_CAPS: u32 = 1 << 24;
/// Action bit: request data in the flagged formats.
pub const ACTION_REQUEST: u32 = 1 << 25;
/// Action bit: ask the peer to re-send its latest notify.
pub const ACTION_PEEK: u32 = 1 << 26;
/// Action bit: announce that data is available in the flagged formats.
pub const ACTION_NOTIFY: u32 = 1 << 27;
/// Action bit: deliver data (zlib-compressed payload).
pub const ACTION_PROVIDE: u32 = 1 << 28;

/// Inbound text hard cap (10 MiB, TigerVNC-compatible). Oversized payloads
/// are ignored rather than allocated.
pub const MAX_INBOUND_TEXT: usize = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Per-session clipboard negotiation state.
#[derive(Debug, Default)]
pub struct ClipboardState {
    extended: bool,
    last_send_lossy: AtomicBool,
}

impl ClipboardState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark whether the peer negotiated the Extended Clipboard
    /// pseudo-encoding (set when its caps message arrives).
    pub fn set_extended_supported(&mut self, yes: bool) {
        self.extended = yes;
    }

    pub fn extended_supported(&self) -> bool {
        self.extended
    }

    /// True when the most recent legacy send had to alter characters
    /// (transliteration or `?` replacement). The UI uses this to warn once
    /// per session (PRD/07 §1.1).
    pub fn last_send_was_lossy(&self) -> bool {
        self.last_send_lossy.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Line-ending helpers
// ---------------------------------------------------------------------------

/// Normalise to CRLF line endings for the wire (extended clipboard spec).
/// Existing CRLF pairs are preserved, lone LFs become CRLF.
pub fn lf_to_crlf(s: &str) -> String {
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

/// Normalise CRLF pairs to LF on receive.
pub fn crlf_to_lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

// ---------------------------------------------------------------------------
// Inbound: ServerCutText
// ---------------------------------------------------------------------------

/// Parse a ServerCutText payload (everything after the message type byte:
/// `3 pad + i32 length + body`). Handles both legacy Latin-1 and Extended
/// Clipboard messages. Returns `Some(text)` when plain text became available
/// (line endings normalised to LF). Malformed or oversized input returns
/// `None`; nothing panics and nothing oversized is allocated.
pub fn handle_server_cut_text(state: &mut ClipboardState, data: &[u8]) -> Option<String> {
    if data.len() < 7 {
        return None;
    }
    let len = i32::from_be_bytes([data[3], data[4], data[5], data[6]]);
    let body = &data[7..];

    if len >= 0 {
        // Legacy: Latin-1 text with LF line endings.
        let n = len as usize;
        if n > MAX_INBOUND_TEXT || n > body.len() {
            return None;
        }
        let mut bytes = &body[..n];
        // Some servers include a trailing NUL; strip it.
        while bytes.last() == Some(&0) {
            bytes = &bytes[..bytes.len() - 1];
        }
        let text: String = bytes.iter().map(|&b| b as char).collect();
        return Some(crlf_to_lf(&text));
    }

    // Extended message of abs(length) bytes.
    let n = len.unsigned_abs() as usize;
    if n < 4 || n > body.len() {
        return None;
    }
    let ext = &body[..n];
    let flags = u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]);
    let rest = &ext[4..];

    if flags & ACTION_CAPS != 0 {
        // The server speaks Extended Clipboard; remember it. Real servers
        // ignore advertised sizes, so we do not parse them beyond validity.
        state.set_extended_supported(true);
        return None;
    }
    if flags & ACTION_PROVIDE != 0 {
        state.set_extended_supported(true);
        return decode_provide_text(flags, rest);
    }
    // notify / request / peek carry no text for us to surface here; the
    // session layer inspects those messages itself (ClipboardNotify event).
    None
}

/// Decode the zlib-compressed `provide` payload and extract the text format,
/// if present. Per the spec, each advertised format appears in ascending bit
/// order as `u32 size + data`; text is bit 0, so it is always first.
fn decode_provide_text(flags: u32, compressed: &[u8]) -> Option<String> {
    if flags & FORMAT_TEXT == 0 {
        return None;
    }
    let mut dec = ZlibDecoder::new(compressed);
    let mut szb = [0u8; 4];
    dec.read_exact(&mut szb).ok()?;
    let size = u32::from_be_bytes(szb) as usize;
    if size > MAX_INBOUND_TEXT {
        return None;
    }
    let mut buf = vec![0u8; size];
    dec.read_exact(&mut buf).ok()?;
    // UTF-8, CRLF line endings, NUL-terminated.
    while buf.last() == Some(&0) {
        buf.pop();
    }
    let text = String::from_utf8_lossy(&buf);
    Some(crlf_to_lf(&text))
}

// ---------------------------------------------------------------------------
// Outbound framing helpers
// ---------------------------------------------------------------------------

/// `3 pad + positive i32 length + payload` (legacy framing).
fn frame_legacy(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + payload.len());
    v.extend_from_slice(&[0, 0, 0]);
    v.extend_from_slice(&(payload.len() as i32).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// `3 pad + negative i32 length + u32 flags + payload` (extended framing).
fn frame_extended(flags: u32, payload: &[u8]) -> Vec<u8> {
    let total = 4 + payload.len();
    let mut v = Vec::with_capacity(7 + total);
    v.extend_from_slice(&[0, 0, 0]);
    v.extend_from_slice(&(-(total as i64) as i32).to_be_bytes());
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

// ---------------------------------------------------------------------------
// Outbound: ClientCutText
// ---------------------------------------------------------------------------

/// Build a ClientCutText message BODY for outgoing text: an extended
/// `provide` when the peer negotiated Extended Clipboard, otherwise legacy
/// Latin-1 (with transliteration; see [`ClipboardState::last_send_was_lossy`]).
pub fn encode_client_cut_text(state: &ClipboardState, text: &str) -> Vec<u8> {
    if state.extended_supported() {
        state.last_send_lossy.store(false, Ordering::Relaxed);
        return encode_provide_text(text);
    }
    // Legacy path: Latin-1, LF line endings.
    let normalized = crlf_to_lf(text);
    let (latin1, lossy) = to_latin1(&normalized);
    state.last_send_lossy.store(lossy, Ordering::Relaxed);
    frame_legacy(&latin1)
}

/// Build an extended-clipboard `notify` announcing which formats are
/// available locally (no payload; data flows only when the peer requests it).
pub fn encode_notify(_state: &ClipboardState, formats: u32) -> Vec<u8> {
    frame_extended(ACTION_NOTIFY | (formats & FORMAT_MASK), &[])
}

/// Build an extended-clipboard `request` for the given formats.
pub fn encode_request(formats: u32) -> Vec<u8> {
    frame_extended(ACTION_REQUEST | (formats & FORMAT_MASK), &[])
}

/// Build an extended-clipboard `provide` carrying text. The payload is a
/// zlib stream of `u32 size + data` per format in flag order; text data is
/// UTF-8 with CRLF line endings and a trailing NUL.
pub fn encode_provide_text(text: &str) -> Vec<u8> {
    let mut data = lf_to_crlf(&crlf_to_lf(text)).into_bytes();
    data.push(0);

    let mut raw = Vec::with_capacity(4 + data.len());
    raw.extend_from_slice(&(data.len() as u32).to_be_bytes());
    raw.extend_from_slice(&data);

    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    // Writing to a Vec cannot fail.
    let _ = enc.write_all(&raw);
    let compressed = enc.finish().unwrap_or_default();

    frame_extended(ACTION_PROVIDE | FORMAT_TEXT, &compressed)
}

/// Our capabilities announcement: text + rtf + html accepted, with every
/// max-unsolicited-size set to 0, "notify me, don't push data", the
/// recommended flow in PRD/07 §1.3. Caps layout: `u32 flags` then one
/// `u32 size` per advertised format bit in ascending bit order.
pub fn encode_caps() -> Vec<u8> {
    let flags = ACTION_CAPS
        | ACTION_REQUEST
        | ACTION_PEEK
        | ACTION_NOTIFY
        | ACTION_PROVIDE
        | FORMAT_TEXT
        | FORMAT_RTF
        | FORMAT_HTML;
    // Three advertised formats -> three zero sizes.
    let sizes = [0u8; 12];
    frame_extended(flags, &sizes)
}

// ---------------------------------------------------------------------------
// Latin-1 transliteration (legacy path)
// ---------------------------------------------------------------------------

/// Convert to Latin-1, transliterating common typographic characters to
/// ASCII and replacing anything unrepresentable with `?`. Returns the bytes
/// and whether any character was altered.
fn to_latin1(s: &str) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(s.len());
    let mut lossy = false;
    for c in s.chars() {
        let cp = c as u32;
        if cp <= 0xff {
            out.push(cp as u8);
            continue;
        }
        lossy = true;
        match c {
            '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{2032}' => out.push(b'\''),
            '\u{201c}' | '\u{201d}' | '\u{201e}' | '\u{2033}' => out.push(b'"'),
            '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2212}' => {
                out.push(b'-')
            }
            '\u{2026}' => out.extend_from_slice(b"..."),
            '\u{2022}' => out.push(b'*'),
            '\u{2039}' => out.push(b'<'),
            '\u{203a}' => out.push(b'>'),
            _ => out.push(b'?'),
        }
    }
    (out, lossy)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_server_msg(text: &[u8]) -> Vec<u8> {
        let mut v = vec![0, 0, 0];
        v.extend_from_slice(&(text.len() as i32).to_be_bytes());
        v.extend_from_slice(text);
        v
    }

    #[test]
    fn legacy_latin1_roundtrip() {
        let mut state = ClipboardState::new();
        let msg = legacy_server_msg(b"caf\xe9\n");
        assert_eq!(
            handle_server_cut_text(&mut state, &msg).as_deref(),
            Some("café\n")
        );
        assert!(!state.extended_supported());
    }

    #[test]
    fn negative_length_is_detected_as_extended() {
        let mut state = ClipboardState::new();
        // A caps message: flags + 3 sizes, length = -(4 + 12).
        let caps = encode_caps();
        let len = i32::from_be_bytes([caps[3], caps[4], caps[5], caps[6]]);
        assert_eq!(len, -16, "extended messages carry a negative length");
        assert_eq!(handle_server_cut_text(&mut state, &caps), None);
        assert!(state.extended_supported(), "caps flips extended support on");
    }

    #[test]
    fn caps_encoding_layout() {
        let caps = encode_caps();
        // 3 pad + 4 length + 4 flags + 12 sizes.
        assert_eq!(caps.len(), 23);
        assert_eq!(&caps[0..3], &[0, 0, 0]);
        let flags = u32::from_be_bytes([caps[7], caps[8], caps[9], caps[10]]);
        assert_ne!(flags & ACTION_CAPS, 0);
        assert_ne!(flags & ACTION_NOTIFY, 0);
        assert_ne!(flags & ACTION_REQUEST, 0);
        assert_ne!(flags & ACTION_PROVIDE, 0);
        assert_eq!(flags & FORMAT_MASK, FORMAT_TEXT | FORMAT_RTF | FORMAT_HTML);
        // All advertised sizes are zero (notify/request/provide flow).
        assert!(caps[11..23].iter().all(|&b| b == 0));
    }

    #[test]
    fn provide_roundtrip_utf8() {
        let mut state = ClipboardState::new();
        let msg = encode_provide_text("héllo 😀\nsecond line");
        let got = handle_server_cut_text(&mut state, &msg);
        assert_eq!(got.as_deref(), Some("héllo 😀\nsecond line"));
        assert!(state.extended_supported());
    }

    #[test]
    fn crlf_normalisation() {
        assert_eq!(lf_to_crlf("a\nb"), "a\r\nb");
        assert_eq!(lf_to_crlf("a\r\nb"), "a\r\nb", "no double conversion");
        assert_eq!(crlf_to_lf("a\r\nb\r\n"), "a\nb\n");
        // Wire text in a provide is CRLF; delivery is LF.
        let mut state = ClipboardState::new();
        let msg = encode_provide_text("one\ntwo\r\nthree");
        assert_eq!(
            handle_server_cut_text(&mut state, &msg).as_deref(),
            Some("one\ntwo\nthree")
        );
    }

    #[test]
    fn notify_and_request_layout() {
        let state = ClipboardState::new();
        let n = encode_notify(&state, FORMAT_TEXT | FORMAT_HTML);
        let len = i32::from_be_bytes([n[3], n[4], n[5], n[6]]);
        assert_eq!(len, -4, "notify has flags only, no payload");
        let flags = u32::from_be_bytes([n[7], n[8], n[9], n[10]]);
        assert_eq!(flags, ACTION_NOTIFY | FORMAT_TEXT | FORMAT_HTML);

        let r = encode_request(FORMAT_TEXT);
        let flags = u32::from_be_bytes([r[7], r[8], r[9], r[10]]);
        assert_eq!(flags, ACTION_REQUEST | FORMAT_TEXT);
        // Action bits never leak into the format filter.
        let r = encode_request(FORMAT_TEXT | ACTION_PROVIDE);
        let flags = u32::from_be_bytes([r[7], r[8], r[9], r[10]]);
        assert_eq!(flags, ACTION_REQUEST | FORMAT_TEXT);
    }

    #[test]
    fn client_cut_text_legacy_translates_and_flags_lossy() {
        let state = ClipboardState::new();
        let body = encode_client_cut_text(&state, "“smart” — dash 😀");
        let len = i32::from_be_bytes([body[3], body[4], body[5], body[6]]) as usize;
        let text: String = body[7..7 + len].iter().map(|&b| b as char).collect();
        assert_eq!(text, "\"smart\" - dash ?");
        assert!(state.last_send_was_lossy());

        let body = encode_client_cut_text(&state, "plain ascii");
        let len = i32::from_be_bytes([body[3], body[4], body[5], body[6]]) as usize;
        assert_eq!(&body[7..7 + len], b"plain ascii");
        assert!(!state.last_send_was_lossy());
    }

    #[test]
    fn client_cut_text_extended_uses_provide() {
        let mut state = ClipboardState::new();
        state.set_extended_supported(true);
        let body = encode_client_cut_text(&state, "émoji 😀");
        let len = i32::from_be_bytes([body[3], body[4], body[5], body[6]]);
        assert!(len < 0, "extended send uses negative length");
        // Round-trips losslessly through our own parser.
        let mut rx = ClipboardState::new();
        assert_eq!(
            handle_server_cut_text(&mut rx, &body).as_deref(),
            Some("émoji 😀")
        );
        assert!(!state.last_send_was_lossy());
    }

    #[test]
    fn malformed_and_oversized_input_is_ignored() {
        let mut state = ClipboardState::new();
        assert_eq!(handle_server_cut_text(&mut state, &[]), None);
        assert_eq!(handle_server_cut_text(&mut state, &[0, 0, 0]), None);
        // Length longer than the actual body.
        let mut v = vec![0, 0, 0];
        v.extend_from_slice(&100i32.to_be_bytes());
        v.extend_from_slice(b"short");
        assert_eq!(handle_server_cut_text(&mut state, &v), None);
        // Claimed 100 MiB of legacy text -> ignored without allocating.
        let mut v = vec![0, 0, 0];
        v.extend_from_slice(&(100 * 1024 * 1024i32).to_be_bytes());
        assert_eq!(handle_server_cut_text(&mut state, &v), None);
        // Extended message with a length exceeding the body.
        let mut v = vec![0, 0, 0];
        v.extend_from_slice(&(-1000i32).to_be_bytes());
        v.extend_from_slice(&(ACTION_PROVIDE | FORMAT_TEXT).to_be_bytes());
        assert_eq!(handle_server_cut_text(&mut state, &v), None);
        // Provide whose decompressed size claims > 10 MiB -> ignored.
        let mut raw = Vec::new();
        raw.extend_from_slice(&(64 * 1024 * 1024u32).to_be_bytes());
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw).unwrap();
        let compressed = enc.finish().unwrap();
        let msg = frame_extended(ACTION_PROVIDE | FORMAT_TEXT, &compressed);
        assert_eq!(handle_server_cut_text(&mut state, &msg), None);
        // Truncated zlib stream.
        let msg = frame_extended(ACTION_PROVIDE | FORMAT_TEXT, &[0x78, 0x9c, 0x01]);
        assert_eq!(handle_server_cut_text(&mut state, &msg), None);
    }

    #[test]
    fn legacy_trailing_nul_is_stripped() {
        let mut state = ClipboardState::new();
        let msg = legacy_server_msg(b"hello\0");
        assert_eq!(
            handle_server_cut_text(&mut state, &msg).as_deref(),
            Some("hello")
        );
    }
}
