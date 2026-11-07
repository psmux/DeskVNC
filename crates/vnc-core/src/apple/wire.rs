//! Apple's own RFB messages: what the client sends to set up and drive an
//! encrypted Screen Sharing session, and what the server sends back.

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Result, VncError};
use crate::proto::messages::{map_eof, read_exact_vec};
use crate::types::{CursorShape, Rect};

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

/// Client message types.
pub mod client_msg {
    pub const SET_MODE: u8 = 0x0a;
    pub const AUTO_FRAMEBUFFER_UPDATE: u8 = 0x09;
    pub const SET_ENCRYPTION: u8 = 0x12;
    pub const AUTO_PASTEBOARD: u8 = 0x15;
    pub const SET_DISPLAY_CONFIGURATION: u8 = 0x1d;
    pub const VIEWER_INFO: u8 = 0x21;
    pub const CLIPBOARD_FETCH: u8 = 0x0b;
    pub const CLIPBOARD_SEND: u8 = 0x1f;
}

/// Server message types.
pub mod server_msg {
    pub const MISC_STATUS: u8 = 0x14;
    pub const CLIPBOARD_SEND: u8 = 0x1f;
}

/// Rectangle encodings Apple uses for out of band data.
pub mod encoding {
    pub const MEDIA_ANNOUNCE: i32 = 0x3f2;
    pub const REKEY: i32 = 0x44f;
    pub const CURSOR: i32 = 0x450;
    pub const DISPLAY_LAYOUT: i32 = 0x451;
    pub const VENDOR_KEYSYMS: i32 = 0x453;
    pub const KEYBOARD_INPUT_SOURCE: i32 = 0x455;
    pub const DEVICE_INFO: i32 = 0x456;

    /// The ones listed in SetEncodings. The media announcement is left out:
    /// it belongs to High Performance mode, which this client does not
    /// speak, and it is still read and skipped if a Mac sends it anyway.
    pub const ADVERTISED: [i32; 6] = [
        REKEY,
        CURSOR,
        DISPLAY_LAYOUT,
        VENDOR_KEYSYMS,
        KEYBOARD_INPUT_SOURCE,
        DEVICE_INFO,
    ];
}

/// The ClientInit byte the native viewer sends (shared, plus two Apple bits).
pub const CLIENT_INIT_SHARED: u8 = 0xC1;
/// The same without the shared bit.
pub const CLIENT_INIT_EXCLUSIVE: u8 = 0xC0;

/// MiscStatus commands.
pub mod misc {
    pub const CLIPBOARD_CHANGED: u16 = 2;
    pub const SESSION_CHANGED: u16 = 11;
    pub const HEARTBEAT: u16 = 12;
}

/// Cap on any length-prefixed Apple metadata rectangle.
const MAX_META: usize = 64 * 1024;
/// Cap on the clipboard, compressed and inflated.
const MAX_CLIPBOARD: usize = 32 * 1024 * 1024;
/// Cursor shapes kept for later SELECT messages.
const MAX_CACHED_CURSORS: usize = 64;
/// Cursors are small; refuse anything absurd before inflating.
const MAX_CURSOR_AREA: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Client to server
// ---------------------------------------------------------------------------

/// The capability bits the native viewer sets in ViewerInfo. The server is
/// known to test only bit 20 (observe only mode supported).
pub const VIEWER_CAPABILITY_BITS: [usize; 10] = [0, 2, 3, 20, 21, 30, 31, 32, 35, 81];

/// The 32 byte capability bitmap, most significant bit of byte 0 first.
pub fn capability_bitmap(bits: &[usize]) -> [u8; 32] {
    let mut map = [0u8; 32];
    for &b in bits {
        if b < 256 {
            map[b / 8] |= 0x80 >> (b % 8);
        }
    }
    map
}

/// ViewerInfo (0x21): `u8 0x21, u8 0, u16 body_len`, then a fixed 62 byte
/// body: `u16 1`, seven u32 values, and the 32 byte capability bitmap.
///
/// The layout and values are the ones Apple's own client sends to a macOS 26
/// Mac, read through a relay: the seven words were 2, 6, 1, 0 and then 26,
/// 7, 1 (the client's macOS version). The Mac reads the body at that fixed
/// size whatever \`body_len\` says, so a shorter ViewerInfo makes it take the
/// next message as part of this one, and it then never sends the session
/// key. With this one the Mac also announces clipboard changes.
pub fn viewer_info() -> Vec<u8> {
    let mut body = Vec::with_capacity(62);
    body.extend_from_slice(&1u16.to_be_bytes());
    for word in VIEWER_INFO_WORDS {
        body.extend_from_slice(&word.to_be_bytes());
    }
    body.extend_from_slice(&capability_bitmap(&VIEWER_CAPABILITY_BITS));
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(client_msg::VIEWER_INFO);
    out.push(0);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// The seven words of the native ViewerInfo, as observed.
pub const VIEWER_INFO_WORDS: [u32; 7] = [2, 6, 1, 0, 26, 7, 1];

/// ClipboardFetch (0x0b) asking for the Mac's clipboard with its data, which
/// the Mac answers with a ClipboardSend. Apple's client sends this with all
/// fields zero when it needs the text itself (with a 1 and a random tag it
/// gets only the list of types).
pub fn clipboard_fetch() -> [u8; 8] {
    [client_msg::CLIPBOARD_FETCH, 0, 0, 0, 0, 0, 0, 0]
}

/// ClipboardSend (0x1f) from the viewer carrying plain text, in the Mac's own
/// layout: `u8 0x1f, u8 0, u8 0, u8 0, u32 0, u32 uncompressed, u32
/// compressed`, then a zlib stream (sync flushed) of one item, the UTF-8
/// text with the aliases the Mac itself attaches. A Mac given this puts the
/// text on its pasteboard as UTF-8, UTF-16 and classic text alike, where a
/// standard ClientCutText reaches only the classic text flavour.
pub fn clipboard_send_text(text: &str) -> Vec<u8> {
    use std::io::Write;
    fn blob(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    let aliases: [(&[u8], &[u8]); 3] = [
        (b"com.apple.ostype", b"utf8"),
        (b"com.apple.nspboard-type", b"NSStringPboardType"),
        (b"public.mime-type", b"text/plain;charset=utf-8"),
    ];
    let mut raw = 1u32.to_be_bytes().to_vec();
    blob(&mut raw, b"public.utf8-plain-text");
    raw.extend_from_slice(&0u32.to_be_bytes());
    raw.extend_from_slice(&(aliases.len() as u32).to_be_bytes());
    for (k, v) in aliases {
        blob(&mut raw, k);
        blob(&mut raw, v);
    }
    blob(&mut raw, text.as_bytes());
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&raw).expect("writing to a Vec");
    z.flush().expect("writing to a Vec");
    let compressed = z.get_ref().clone();
    let mut out = vec![client_msg::CLIPBOARD_SEND, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    out.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    out.extend_from_slice(&compressed);
    out
}

/// Inflate a zlib stream that may end on a sync flush with no final block,
/// which is how the Mac sends its clipboard; a reader that waits for the end
/// of the stream fails on it. `expected` is the size the message declares.
pub fn inflate_flushed(data: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut d = flate2::Decompress::new(true);
    let mut out = Vec::with_capacity(expected);
    while out.len() < expected {
        let consumed = d.total_in() as usize;
        let produced = out.len();
        let status = d
            .decompress_vec(&data[consumed..], &mut out, flate2::FlushDecompress::Sync)
            .map_err(|e| VncError::Protocol(format!("clipboard did not inflate: {e}")))?;
        if status == flate2::Status::StreamEnd
            || (d.total_in() as usize == consumed && out.len() == produced)
        {
            break;
        }
    }
    Ok(out)
}

/// SetEncryption command 1, which makes the server send its first rekey.
/// The native bytes, the trailing word included.
pub fn set_encryption_start() -> [u8; 12] {
    [0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1]
}

/// SetEncryption command 2, sent last before the record layer starts.
pub fn set_encryption_finish() -> [u8; 8] {
    [0x12, 0, 0, 2, 0, 1, 0, 0]
}

/// SetMode (0x0a): 0 observe, 1 control.
pub fn set_mode(control: bool) -> [u8; 4] {
    [client_msg::SET_MODE, 0, 0, control as u8]
}

/// AutoFrameBufferUpdate (0x09) for the whole of every display.
pub fn auto_framebuffer_update(rect: Rect) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = client_msg::AUTO_FRAMEBUFFER_UPDATE;
    out[2..4].copy_from_slice(&1u16.to_be_bytes());
    out[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    out[8..10].copy_from_slice(&rect.x.to_be_bytes());
    out[10..12].copy_from_slice(&rect.y.to_be_bytes());
    out[12..14].copy_from_slice(&rect.width.to_be_bytes());
    out[14..16].copy_from_slice(&rect.height.to_be_bytes());
    out
}

/// AutoPasteboard (0x15): start (true) or stop clipboard syncing.
pub fn auto_pasteboard(start: bool) -> [u8; 8] {
    [
        client_msg::AUTO_PASTEBOARD,
        0,
        0,
        if start { 1 } else { 2 },
        0,
        0,
        0,
        0,
    ]
}

/// Millimetres per pixel the native viewer reports for a 1920x1080 display.
const MM_PER_PX: f32 = 369.45 / 1920.0;

/// Size of one display descriptor before its mode table.
pub const DESCRIPTOR_FIXED: usize = 156;
/// Size of one mode table entry.
pub const MODE_LEN: usize = 28;

/// SetDisplayConfiguration (0x1d) for one fixed size display with one mode.
///
/// This is the plain form: no dynamic resolution flag, display type 0, both
/// mode indices 0. `rotation` is the word at descriptor offset 150, which is
/// either a rotation (0) or a value the native viewer sets to 7; which one is
/// unconfirmed, and 0 is what this module sends.
pub fn set_display_configuration(width: u16, height: u16, rotation: u32) -> Vec<u8> {
    let modes = 1usize;
    let descriptor = DESCRIPTOR_FIXED + MODE_LEN * modes;
    let total = 12 + descriptor;
    let mut out = Vec::with_capacity(total);
    out.push(client_msg::SET_DISPLAY_CONFIGURATION);
    out.push(0);
    out.extend_from_slice(&((total - 4) as u16).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // version
    out.extend_from_slice(&1u16.to_be_bytes()); // display count
    out.extend_from_slice(&0u32.to_be_bytes()); // flags

    let d = out.len();
    out.extend_from_slice(&(descriptor as u16).to_be_bytes());
    out.resize(d + 122, 0); // 120 opaque name bytes, zero
    out.extend_from_slice(&0u32.to_be_bytes()); // display flags
    out.extend_from_slice(&0u32.to_be_bytes()); // display type
    out.extend_from_slice(&(width as f32 * MM_PER_PX).to_be_bytes());
    out.extend_from_slice(&(height as f32 * MM_PER_PX).to_be_bytes());
    out.extend_from_slice(&(width as u32).to_be_bytes()); // max width
    out.extend_from_slice(&(height as u32).to_be_bytes()); // max height
    out.extend_from_slice(&0u16.to_be_bytes()); // current mode
    out.extend_from_slice(&0u16.to_be_bytes()); // preferred mode
    out.extend_from_slice(&rotation.to_be_bytes());
    out.extend_from_slice(&(modes as u16).to_be_bytes());
    debug_assert_eq!(out.len() - d, DESCRIPTOR_FIXED);

    // The one mode: render size = logical size, 60 Hz, no HDR.
    out.extend_from_slice(&(width as u32).to_be_bytes());
    out.extend_from_slice(&(height as u32).to_be_bytes());
    out.extend_from_slice(&(width as u32).to_be_bytes());
    out.extend_from_slice(&(height as u32).to_be_bytes());
    out.extend_from_slice(&60.0f64.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    debug_assert_eq!(out.len(), total);
    out
}

// ---------------------------------------------------------------------------
// Server to client: rectangles
// ---------------------------------------------------------------------------

/// One display in an AppleDisplayLayout message.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LayoutDisplay {
    pub id: u32,
    /// Bounds in the global desktop, as sent.
    pub global: Rect,
    /// The scaled (logical) bounds, as sent.
    pub scaled: Rect,
    pub flags: u32,
}

impl LayoutDisplay {
    pub fn is_main(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// AppleDisplayLayout (0x451), parsed defensively.
#[derive(Debug, Clone, PartialEq)]
pub struct DisplayLayout {
    pub version: u16,
    pub displays: Vec<LayoutDisplay>,
    /// The four u16 values before the display records, if present: by one
    /// reading scaled width and height, then backing width and height.
    pub leading: Option<[u16; 4]>,
}

impl DisplayLayout {
    /// The display whose geometry the framebuffer follows: the main one, or
    /// the first.
    pub fn main(&self) -> Option<&LayoutDisplay> {
        self.displays
            .iter()
            .find(|d| d.is_main())
            .or(self.displays.first())
    }

    /// `(backing, logical)` sizes. Rectangles arrive in backing pixels and
    /// pointer positions are given in logical ones, and of the two sizes the
    /// message carries the larger is the backing one (a HiDPI Mac doubles it).
    pub fn sizes(&self) -> Option<((u16, u16), (u16, u16))> {
        let d = self.main()?;
        let a = (d.global.width, d.global.height);
        let b = (d.scaled.width, d.scaled.height);
        let area = |s: (u16, u16)| s.0 as u32 * s.1 as u32;
        let (backing, logical) = if area(a) >= area(b) { (a, b) } else { (b, a) };
        if area(backing) == 0 {
            return None;
        }
        let logical = if area(logical) == 0 { backing } else { logical };
        Some((backing, logical))
    }
}

/// Parse the body of a 0x451 rectangle (after its u16 length).
///
/// The layout as known is a 20 byte header and 56 bytes per display. The
/// header's exact contents are disputed, so it is not relied on: the number
/// of displays comes from the length, and the records are read from the end
/// of the header.
pub fn parse_display_layout(body: &[u8]) -> Result<DisplayLayout> {
    const HEADER: usize = 18;
    const RECORD: usize = 56;
    // With the u16 length counted the header is 20 bytes; without it, 18.
    if body.len() < HEADER {
        return Err(VncError::Protocol(format!(
            "display layout of {} bytes is too short",
            body.len()
        )));
    }
    let count = (body.len() - HEADER) / RECORD;
    let start = body.len() - count * RECORD;
    let version = u16::from_be_bytes([body[0], body[1]]);
    let leading = (start >= 18).then(|| {
        let g = &body[start - 8..start];
        [
            u16::from_be_bytes([g[0], g[1]]),
            u16::from_be_bytes([g[2], g[3]]),
            u16::from_be_bytes([g[4], g[5]]),
            u16::from_be_bytes([g[6], g[7]]),
        ]
    });
    let u16_at = |r: &[u8], o: usize| u16::from_be_bytes([r[o], r[o + 1]]);
    let u32_at = |r: &[u8], o: usize| u32::from_be_bytes(r[o..o + 4].try_into().expect("four"));
    let displays = body[start..]
        .as_chunks::<RECORD>()
        .0
        .iter()
        .map(|r| LayoutDisplay {
            id: u32_at(r, 16),
            global: Rect::new(u16_at(r, 20), u16_at(r, 22), u16_at(r, 24), u16_at(r, 26)),
            scaled: Rect::new(u16_at(r, 28), u16_at(r, 30), u16_at(r, 32), u16_at(r, 34)),
            flags: u32_at(r, 36),
        })
        .collect();
    Ok(DisplayLayout {
        version,
        displays,
        leading,
    })
}

/// KeyboardInputSource (0x455).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSource {
    /// The Mac is in secure input mode (a password field has focus).
    pub secure: bool,
    /// The keyboard layout identifier, such as `com.apple.keylayout.ABC`.
    pub id: String,
}

/// Parse the body of a 0x455 rectangle (after its u16 length):
/// `u16 1, u32 flags, u16 len, id`.
pub fn parse_input_source(body: &[u8]) -> Result<InputSource> {
    if body.len() < 8 {
        return Err(VncError::Protocol("keyboard input source too short".into()));
    }
    let flags = u32::from_be_bytes(body[2..6].try_into().expect("four"));
    let len = u16::from_be_bytes([body[6], body[7]]) as usize;
    let id = body
        .get(8..8 + len)
        .ok_or_else(|| VncError::Protocol("keyboard input source id is truncated".into()))?;
    Ok(InputSource {
        secure: flags & 1 != 0,
        id: String::from_utf8_lossy(id).into_owned(),
    })
}

/// Read a rectangle body that starts with a u16 length counting the bytes
/// after it.
pub async fn read_u16_prefixed<R: AsyncRead + Unpin>(r: &mut R, what: &str) -> Result<Vec<u8>> {
    let len = r.read_u16().await.map_err(map_eof)? as usize;
    if len > MAX_META {
        return Err(VncError::Protocol(format!("{what} of {len} bytes")));
    }
    read_exact_vec(r, len).await
}

/// Read a DeviceInfo (0x456) rectangle by its structure: `u16 size, u16 2,
/// u32 flags, u32 colour, u16 len1, u16 len2, u16 len3`, three strings, then
/// a u32. The size word and the structure are described inconsistently (the
/// size seems not to count the final word), so the structure decides how
/// much is read and a size that claims more is honoured by skipping the
/// rest. Returns the model string.
pub async fn read_device_info<R: AsyncRead + Unpin>(r: &mut R) -> Result<String> {
    let size = r.read_u16().await.map_err(map_eof)? as usize;
    let mut head = [0u8; 16];
    r.read_exact(&mut head).await.map_err(map_eof)?;
    let l1 = u16::from_be_bytes([head[10], head[11]]) as usize;
    let l2 = u16::from_be_bytes([head[12], head[13]]) as usize;
    let l3 = u16::from_be_bytes([head[14], head[15]]) as usize;
    let strings = l1 + l2 + l3;
    if strings > MAX_META {
        return Err(VncError::Protocol("device info strings too long".into()));
    }
    let block = read_exact_vec(r, strings).await?;
    let mut tail = [0u8; 4];
    r.read_exact(&mut tail).await.map_err(map_eof)?;
    let structural = 16 + strings + 4;
    if size > structural {
        read_exact_vec(r, size - structural).await?;
    }
    let model = block[..l1]
        .split(|b| *b == 0)
        .next()
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .unwrap_or_default();
    Ok(model)
}

/// Apple cursor shapes, kept by the id the server assigns so a later SELECT
/// can switch back to one without resending it.
#[derive(Default)]
pub struct CursorCache {
    shapes: HashMap<u32, CursorShape>,
    order: Vec<u32>,
    stream: Option<flate2::Decompress>,
}

impl std::fmt::Debug for CursorCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CursorCache")
            .field("shapes", &self.shapes.len())
            .finish_non_exhaustive()
    }
}

/// Whether `data` opens with a zlib header (CMF/FLG with a valid check).
fn starts_zlib_stream(data: &[u8]) -> bool {
    data.len() >= 2
        && data[0] & 0x0f == 8
        && (u16::from(data[0]) << 8 | u16::from(data[1])) % 31 == 0
}

impl CursorCache {
    /// Inflate one STORE payload into exactly `want` bytes.
    ///
    /// Whether the server keeps one deflate stream across cursors or starts a
    /// new one each time is not known, so both are handled: a payload that
    /// opens with a zlib header starts a fresh stream, and one that does not
    /// continues the previous stream.
    fn inflate(&mut self, data: &[u8], want: usize) -> Result<Vec<u8>> {
        if self.stream.is_none() || starts_zlib_stream(data) {
            self.stream = Some(flate2::Decompress::new(true));
        }
        let z = self.stream.as_mut().expect("just set");
        let mut out = Vec::with_capacity(want);
        let mut input = data;
        while out.len() < want {
            let before_in = z.total_in();
            let before_out = out.len();
            z.decompress_vec(input, &mut out, flate2::FlushDecompress::Sync)
                .map_err(|e| VncError::Protocol(format!("Apple cursor did not inflate: {e}")))?;
            let used = (z.total_in() - before_in) as usize;
            input = &input[used..];
            if out.len() == before_out && used == 0 {
                break;
            }
            if out.len() == out.capacity() && out.len() < want {
                out.reserve(want - out.len());
            }
        }
        if out.len() < want {
            return Err(VncError::Protocol(format!(
                "Apple cursor inflated to {} bytes, expected {want}",
                out.len()
            )));
        }
        out.truncate(want);
        Ok(out)
    }

    /// Read a 0x450 rectangle: `u32 cache_id, u32 compressed_len, data`.
    /// Returns the shape to show, or `None` for a SELECT of an id we never
    /// received.
    pub async fn read<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        rect: Rect,
    ) -> Result<Option<CursorShape>> {
        let id = r.read_u32().await.map_err(map_eof)?;
        let len = r.read_u32().await.map_err(map_eof)? as usize;
        if len == 0 {
            return Ok(self.shapes.get(&id).cloned());
        }
        if len > MAX_META * 16 {
            return Err(VncError::Protocol(format!("Apple cursor of {len} bytes")));
        }
        let data = read_exact_vec(r, len).await?;
        let shape = self.store(id, rect, &data)?;
        Ok(Some(shape))
    }

    /// Decode and remember one STORE: BGRA pixels then a separate alpha plane.
    pub fn store(&mut self, id: u32, rect: Rect, data: &[u8]) -> Result<CursorShape> {
        let w = rect.width as usize;
        let h = rect.height as usize;
        if w * h > MAX_CURSOR_AREA {
            return Err(VncError::Protocol(format!(
                "Apple cursor {w}x{h} is too big"
            )));
        }
        let px = w * h;
        let raw = self.inflate(data, px * 5)?;
        let (bgra, alpha) = raw.split_at(px * 4);
        let mut pixels = vec![0u8; px * 4];
        for i in 0..px {
            pixels[i * 4] = bgra[i * 4 + 2];
            pixels[i * 4 + 1] = bgra[i * 4 + 1];
            pixels[i * 4 + 2] = bgra[i * 4];
            pixels[i * 4 + 3] = alpha[i];
        }
        let shape = CursorShape {
            width: rect.width,
            height: rect.height,
            hotspot_x: if rect.width == 0 {
                0
            } else {
                rect.x.min(rect.width - 1)
            },
            hotspot_y: if rect.height == 0 {
                0
            } else {
                rect.y.min(rect.height - 1)
            },
            pixels,
        };
        if !self.shapes.contains_key(&id) {
            self.order.push(id);
            if self.order.len() > MAX_CACHED_CURSORS {
                let old = self.order.remove(0);
                self.shapes.remove(&old);
            }
        }
        self.shapes.insert(id, shape.clone());
        Ok(shape)
    }
}

// ---------------------------------------------------------------------------
// Server to client: messages
// ---------------------------------------------------------------------------

/// Read a MiscStatus (0x14) after its type byte: `u8 0, u16 len, u16
/// version, u16 cmd`. Returns the command.
pub async fn read_misc_status<R: AsyncRead + Unpin>(r: &mut R) -> Result<u16> {
    let _pad = r.read_u8().await.map_err(map_eof)?;
    let len = r.read_u16().await.map_err(map_eof)? as usize;
    if len > MAX_META {
        return Err(VncError::Protocol(format!("MiscStatus of {len} bytes")));
    }
    let body = read_exact_vec(r, len).await?;
    Ok(if body.len() >= 4 {
        u16::from_be_bytes([body[2], body[3]])
    } else {
        0
    })
}

/// Read a ClipboardSend (0x1f) after its type byte and return its plain
/// text, if it carries any. A promise (third byte 1) lists the types the Mac
/// has without their data and is skipped; the data comes in answer to
/// [`clipboard_fetch`].
pub async fn read_clipboard<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<String>> {
    let mut head = [0u8; 15];
    r.read_exact(&mut head).await.map_err(map_eof)?;
    let uncompressed = u32::from_be_bytes(head[7..11].try_into().expect("four")) as usize;
    let compressed = u32::from_be_bytes(head[11..15].try_into().expect("four")) as usize;
    if compressed > MAX_CLIPBOARD || uncompressed > MAX_CLIPBOARD {
        return Err(VncError::Protocol(format!(
            "clipboard of {uncompressed} bytes ({compressed} compressed)"
        )));
    }
    let data = read_exact_vec(r, compressed).await?;
    if uncompressed == 0 || head[1] == 1 {
        return Ok(None);
    }
    let inflated = inflate_flushed(&data, uncompressed)?;
    Ok(clipboard_text(&inflated))
}

/// One flavour in a clipboard item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardItem {
    pub kind: String,
    pub data: Vec<u8>,
}

/// Parse an inflated clipboard: `u32 count`, then per item `u32 len, type,
/// u32 0, u32 alias_count, (u32 len, name, u32 len, value) * alias_count,
/// u32 data_len, data`.
pub fn parse_clipboard(buf: &[u8]) -> Result<Vec<ClipboardItem>> {
    let mut pos = 0usize;
    let u32_ = |pos: &mut usize| -> Result<usize> {
        let b = buf
            .get(*pos..*pos + 4)
            .ok_or_else(|| VncError::Protocol("clipboard is truncated".into()))?;
        *pos += 4;
        Ok(u32::from_be_bytes(b.try_into().expect("four")) as usize)
    };
    let take = |pos: &mut usize, n: usize| -> Result<Vec<u8>> {
        let b = buf
            .get(*pos..pos.checked_add(n).unwrap_or(usize::MAX))
            .ok_or_else(|| VncError::Protocol("clipboard is truncated".into()))?;
        *pos += n;
        Ok(b.to_vec())
    };
    let count = u32_(&mut pos)?;
    let mut items = Vec::new();
    for _ in 0..count.min(1024) {
        let tl = u32_(&mut pos)?;
        let kind = String::from_utf8_lossy(&take(&mut pos, tl)?).into_owned();
        let _zero = u32_(&mut pos)?;
        let aliases = u32_(&mut pos)?;
        for _ in 0..aliases.min(1024) {
            let n = u32_(&mut pos)?;
            take(&mut pos, n)?;
            let v = u32_(&mut pos)?;
            take(&mut pos, v)?;
        }
        let dl = u32_(&mut pos)?;
        let data = take(&mut pos, dl)?;
        items.push(ClipboardItem { kind, data });
    }
    Ok(items)
}

/// The best plain text flavour of a clipboard, if it has one.
pub fn clipboard_text(inflated: &[u8]) -> Option<String> {
    let items = match parse_clipboard(inflated) {
        Ok(i) => i,
        Err(e) => {
            tracing::debug!(error = %e, "Apple clipboard did not parse");
            return None;
        }
    };
    if let Some(i) = items.iter().find(|i| i.kind == "public.utf8-plain-text") {
        return Some(String::from_utf8_lossy(&i.data).into_owned());
    }
    if let Some(i) = items.iter().find(|i| i.kind == "public.utf16-plain-text") {
        let units: Vec<u16> = i
            .data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        return Some(String::from_utf16_lossy(&units));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    #[test]
    fn capability_bitmap_is_msb_first() {
        let m = capability_bitmap(&VIEWER_CAPABILITY_BITS);
        // Bits 0, 2, 3 -> 1011_0000.
        assert_eq!(m[0], 0b1011_0000);
        // Bits 20, 21 -> byte 2, 0x08 | 0x04, as Apple's client sends.
        assert_eq!(m[2], 0x0c);
        // Bits 30, 31 -> byte 3, low two bits.
        assert_eq!(m[3], 0x03);
        // Bits 32, 35 -> byte 4, 0x80 | 0x10.
        assert_eq!(m[4], 0x90);
        // Bit 81 -> byte 10, 0x40.
        assert_eq!(m[10], 0x40);
    }

    #[test]
    fn viewer_info_header_counts_the_body() {
        let v = viewer_info();
        assert_eq!(&v[..2], &[0x21, 0]);
        assert_eq!(u16::from_be_bytes([v[2], v[3]]) as usize, v.len() - 4);
        assert_eq!(&v[4..6], &[0, 1]);
    }

    #[test]
    fn set_encryption_bytes_are_the_native_ones() {
        assert_eq!(
            set_encryption_start(),
            [0x12, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(
            set_encryption_finish(),
            [0x12, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00]
        );
        assert_eq!(set_mode(true), [0x0a, 0, 0, 1]);
    }

    #[test]
    fn auto_update_layout() {
        let m = auto_framebuffer_update(Rect::new(0, 0, 1920, 1080));
        assert_eq!(
            m,
            [9, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0x07, 0x80, 0x04, 0x38]
        );
        assert_eq!(auto_pasteboard(true), [0x15, 0, 0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn display_configuration_offsets() {
        let m = set_display_configuration(1920, 1080, 0);
        assert_eq!(m.len(), 12 + 156 + 28);
        assert_eq!(m[0], 0x1d);
        assert_eq!(u16::from_be_bytes([m[2], m[3]]) as usize, m.len() - 4);
        assert_eq!(&m[4..8], &[0, 1, 0, 1]);
        let d = &m[12..];
        assert_eq!(u16::from_be_bytes([d[0], d[1]]) as usize, 156 + 28);
        assert_eq!(d[121], 0, "name NUL");
        assert_eq!(&d[138..142], &1920u32.to_be_bytes());
        assert_eq!(&d[142..146], &1080u32.to_be_bytes());
        assert_eq!(&d[154..156], &1u16.to_be_bytes());
        let mode = &d[156..];
        assert_eq!(&mode[..4], &1920u32.to_be_bytes());
        assert_eq!(&mode[16..24], &[0x40, 0x4E, 0, 0, 0, 0, 0, 0]);
        let mm = f32::from_be_bytes(d[130..134].try_into().unwrap());
        assert!((mm - 369.45).abs() < 0.01);
    }

    fn layout_body(scaled: (u16, u16), global: (u16, u16)) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&5u16.to_be_bytes());
        b.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        b.extend_from_slice(&0x0200_0000u32.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        for v in [scaled.0, scaled.1, global.0, global.1] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        assert_eq!(b.len(), 20);
        let mut r = vec![0u8; 56];
        r[..8].copy_from_slice(&1.0f64.to_be_bytes());
        r[8..16].copy_from_slice(&1.0f64.to_be_bytes());
        r[16..20].copy_from_slice(&7u32.to_be_bytes());
        r[24..26].copy_from_slice(&global.0.to_be_bytes());
        r[26..28].copy_from_slice(&global.1.to_be_bytes());
        r[32..34].copy_from_slice(&scaled.0.to_be_bytes());
        r[34..36].copy_from_slice(&scaled.1.to_be_bytes());
        r[36..40].copy_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&r);
        b
    }

    #[test]
    fn layout_picks_backing_and_logical_sizes() {
        let l = parse_display_layout(&layout_body((1920, 1080), (3840, 2160))).unwrap();
        assert_eq!(l.displays.len(), 1);
        assert_eq!(l.displays[0].id, 7);
        assert_eq!(l.sizes(), Some(((3840, 2160), (1920, 1080))));
        // Swapped fields give the same answer: the larger is the backing.
        let l = parse_display_layout(&layout_body((3840, 2160), (1920, 1080))).unwrap();
        assert_eq!(l.sizes(), Some(((3840, 2160), (1920, 1080))));
        assert!(parse_display_layout(&[0; 10]).is_err());
    }

    #[test]
    fn input_source_parses() {
        let id = b"com.apple.keylayout.ABC";
        let mut b = vec![0, 1, 0, 0, 0, 1];
        b.extend_from_slice(&(id.len() as u16).to_be_bytes());
        b.extend_from_slice(id);
        let s = parse_input_source(&b).unwrap();
        assert!(s.secure);
        assert_eq!(s.id, "com.apple.keylayout.ABC");
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn cursor_store_and_select() {
        let mut c = CursorCache::default();
        // 2x1 cursor: BGRA pixels then the alpha plane.
        let raw = [10, 20, 30, 0, 40, 50, 60, 0, 255, 128];
        let shape = c.store(1000, Rect::new(1, 0, 2, 1), &zlib(&raw)).unwrap();
        assert_eq!(shape.pixels, vec![30, 20, 10, 255, 60, 50, 40, 128]);
        assert_eq!((shape.hotspot_x, shape.hotspot_y), (1, 0));
        // A second STORE in its own zlib stream works too.
        let shape2 = c
            .store(1001, Rect::new(0, 0, 1, 1), &zlib(&[1, 2, 3, 4, 9]))
            .unwrap();
        assert_eq!(shape2.pixels, vec![3, 2, 1, 9]);
        assert_eq!(c.shapes.get(&1000).unwrap().pixels, shape.pixels);
    }

    #[tokio::test]
    async fn misc_status_and_clipboard_messages() {
        let mut m: &[u8] = &[0, 0, 4, 0, 1, 0, 12];
        assert_eq!(read_misc_status(&mut m).await.unwrap(), misc::HEARTBEAT);

        let text = "hello from the Mac";
        let kind = b"public.utf8-plain-text";
        let mut inner = Vec::new();
        inner.extend_from_slice(&1u32.to_be_bytes());
        inner.extend_from_slice(&(kind.len() as u32).to_be_bytes());
        inner.extend_from_slice(kind);
        inner.extend_from_slice(&0u32.to_be_bytes());
        inner.extend_from_slice(&1u32.to_be_bytes());
        for s in [b"alias".as_slice(), b"value".as_slice()] {
            inner.extend_from_slice(&(s.len() as u32).to_be_bytes());
            inner.extend_from_slice(s);
        }
        inner.extend_from_slice(&(text.len() as u32).to_be_bytes());
        inner.extend_from_slice(text.as_bytes());
        let z = zlib(&inner);
        let mut msg = vec![0u8, 0, 0, 0, 0, 0, 0];
        msg.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        msg.extend_from_slice(&(z.len() as u32).to_be_bytes());
        msg.extend_from_slice(&z);
        let mut r: &[u8] = &msg;
        assert_eq!(read_clipboard(&mut r).await.unwrap().as_deref(), Some(text));
        assert!(r.is_empty());

        // An empty clipboard is no items, not an error.
        let empty = [0u8; 15];
        let mut r: &[u8] = &empty;
        assert_eq!(read_clipboard(&mut r).await.unwrap(), None);
    }

    #[tokio::test]
    async fn device_info_reads_by_structure() {
        let mut b = Vec::new();
        let strings = b"Mac14,3\0silver\0blue\0";
        b.extend_from_slice(&((16 + strings.len()) as u16).to_be_bytes());
        b.extend_from_slice(&2u16.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        for l in [8u16, 7, 5] {
            b.extend_from_slice(&l.to_be_bytes());
        }
        b.extend_from_slice(strings);
        b.extend_from_slice(&(-1i32).to_be_bytes());
        b.push(0xEE); // the next message
        let mut r: &[u8] = &b;
        assert_eq!(read_device_info(&mut r).await.unwrap(), "Mac14,3");
        assert_eq!(r, &[0xEE]);
    }
}
