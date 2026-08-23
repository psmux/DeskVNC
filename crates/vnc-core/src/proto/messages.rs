//! RFB message encoding (client→server) and decoding (server→client).
//!
//! All multi-byte values are big-endian on the wire (RFC 6143 §7).
//! Every server-originated length is bounds-checked: a malicious server must
//! never be able to make us allocate unbounded memory or panic.

use crate::error::{Result, VncError};
use crate::types::{PixelFormat, Rect};
use tokio::io::{AsyncRead, AsyncReadExt};

// ---------------------------------------------------------------------------
// Message type numbers
// ---------------------------------------------------------------------------

pub mod client_msg {
    pub const SET_PIXEL_FORMAT: u8 = 0;
    pub const SET_ENCODINGS: u8 = 2;
    pub const FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;
    pub const KEY_EVENT: u8 = 4;
    pub const POINTER_EVENT: u8 = 5;
    pub const CLIENT_CUT_TEXT: u8 = 6;
    pub const ENABLE_CONTINUOUS_UPDATES: u8 = 150;
    pub const CLIENT_FENCE: u8 = 248;
    pub const SET_DESKTOP_SIZE: u8 = 251;
    pub const QEMU: u8 = 255;
    pub const QEMU_SUB_EXTENDED_KEY_EVENT: u8 = 0;
}

pub mod server_msg {
    pub const FRAMEBUFFER_UPDATE: u8 = 0;
    pub const SET_COLOUR_MAP_ENTRIES: u8 = 1;
    pub const BELL: u8 = 2;
    pub const SERVER_CUT_TEXT: u8 = 3;
    pub const END_OF_CONTINUOUS_UPDATES: u8 = 150;
    /// ServerFence and ClientFence share message type 248 (TigerVNC
    /// `msgTypeServerFence`); 249 is OLIVE Call Control. This was 249, so a
    /// real ServerFence fell through to "unknown server message type" and
    /// tore the session down, which the mock server never caught because it
    /// only ever emits types 0, 2 and 3.
    pub const SERVER_FENCE: u8 = 248;
}

/// Fence flag bits (rfbproto Fence extension).
pub mod fence_flags {
    pub const BLOCK_BEFORE: u32 = 1;
    pub const BLOCK_AFTER: u32 = 1 << 1;
    pub const SYNC_NEXT: u32 = 1 << 2;
    pub const REQUEST: u32 = 1 << 31;
    /// Flags we understand and may echo in a response.
    pub const KNOWN_RESPONSE_MASK: u32 = BLOCK_BEFORE | BLOCK_AFTER | SYNC_NEXT;
    /// Maximum fence payload length per spec.
    pub const MAX_PAYLOAD: usize = 64;
}

/// Extended Clipboard (0xc0a1e5ce) action bits, used in the ClientCutText /
/// ServerCutText flags word when the length is negative.
pub mod ext_clipboard {
    pub const ACTION_CAPS: u32 = 1 << 24;
    pub const ACTION_REQUEST: u32 = 1 << 25;
    pub const ACTION_PEEK: u32 = 1 << 26;
    pub const ACTION_NOTIFY: u32 = 1 << 27;
    pub const ACTION_PROVIDE: u32 = 1 << 28;
    pub const FORMAT_MASK: u32 = 0x0000_ffff;
}

/// Hard caps applied to server-supplied lengths (threat model: hostile server).
const MAX_CUT_TEXT: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// One screen in an ExtendedDesktopSize / SetDesktopSize SCREEN list
// ---------------------------------------------------------------------------

/// The protocol neutral screen type carries this list now, so `SessionEvent`
/// can live in `remote-core` without naming an RFB wire type
/// (PRDRDP/02 §2.2.2). The alias keeps the RFB spelling where RFB code reads
/// better for it; the wire format below is unchanged.
pub type Screen = crate::types::ScreenInfo;

/// The 16 byte SCREEN entry of an ExtendedDesktopSize / SetDesktopSize list.
///
/// A free function rather than an inherent method, because the type is no
/// longer defined in this crate. `primary` is not on the wire: RFB has no
/// field for it.
pub fn encode_screen_into(s: &Screen, out: &mut Vec<u8>) {
    out.extend_from_slice(&s.id.to_be_bytes());
    out.extend_from_slice(&s.x.to_be_bytes());
    out.extend_from_slice(&s.y.to_be_bytes());
    out.extend_from_slice(&s.width.to_be_bytes());
    out.extend_from_slice(&s.height.to_be_bytes());
    out.extend_from_slice(&s.flags.to_be_bytes());
}

// ---------------------------------------------------------------------------
// PixelFormat wire form (16 bytes)
// ---------------------------------------------------------------------------

pub fn encode_pixel_format(pf: &PixelFormat) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = pf.bits_per_pixel;
    b[1] = pf.depth;
    b[2] = pf.big_endian as u8;
    b[3] = pf.true_colour as u8;
    b[4..6].copy_from_slice(&pf.red_max.to_be_bytes());
    b[6..8].copy_from_slice(&pf.green_max.to_be_bytes());
    b[8..10].copy_from_slice(&pf.blue_max.to_be_bytes());
    b[10] = pf.red_shift;
    b[11] = pf.green_shift;
    b[12] = pf.blue_shift;
    // b[13..16] padding
    b
}

pub fn parse_pixel_format(b: &[u8; 16]) -> Result<PixelFormat> {
    let pf = PixelFormat {
        bits_per_pixel: b[0],
        depth: b[1],
        big_endian: b[2] != 0,
        true_colour: b[3] != 0,
        red_max: u16::from_be_bytes([b[4], b[5]]),
        green_max: u16::from_be_bytes([b[6], b[7]]),
        blue_max: u16::from_be_bytes([b[8], b[9]]),
        red_shift: b[10],
        green_shift: b[11],
        blue_shift: b[12],
    };
    if !matches!(pf.bits_per_pixel, 8 | 16 | 32) {
        return Err(VncError::Protocol(format!(
            "invalid bits-per-pixel {} in pixel format",
            pf.bits_per_pixel
        )));
    }
    if pf.depth == 0 || pf.depth > pf.bits_per_pixel {
        return Err(VncError::Protocol(format!(
            "invalid depth {} for bpp {}",
            pf.depth, pf.bits_per_pixel
        )));
    }
    Ok(pf)
}

// ---------------------------------------------------------------------------
// Client → server encoders
// ---------------------------------------------------------------------------

pub fn set_pixel_format(pf: &PixelFormat) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0] = client_msg::SET_PIXEL_FORMAT;
    // 3 bytes padding
    b[4..20].copy_from_slice(&encode_pixel_format(pf));
    b
}

pub fn set_encodings(encodings: &[i32]) -> Vec<u8> {
    let n = encodings.len().min(u16::MAX as usize);
    let mut out = Vec::with_capacity(4 + n * 4);
    out.push(client_msg::SET_ENCODINGS);
    out.push(0); // padding
    out.extend_from_slice(&(n as u16).to_be_bytes());
    for &e in &encodings[..n] {
        out.extend_from_slice(&e.to_be_bytes());
    }
    out
}

pub fn framebuffer_update_request(incremental: bool, rect: Rect) -> [u8; 10] {
    let mut b = [0u8; 10];
    b[0] = client_msg::FRAMEBUFFER_UPDATE_REQUEST;
    b[1] = incremental as u8;
    b[2..4].copy_from_slice(&rect.x.to_be_bytes());
    b[4..6].copy_from_slice(&rect.y.to_be_bytes());
    b[6..8].copy_from_slice(&rect.width.to_be_bytes());
    b[8..10].copy_from_slice(&rect.height.to_be_bytes());
    b
}

pub fn key_event(keysym: u32, down: bool) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = client_msg::KEY_EVENT;
    b[1] = down as u8;
    // 2 bytes padding
    b[4..8].copy_from_slice(&keysym.to_be_bytes());
    b
}

pub fn pointer_event(x: u16, y: u16, button_mask: u8) -> [u8; 6] {
    let mut b = [0u8; 6];
    b[0] = client_msg::POINTER_EVENT;
    b[1] = button_mask;
    b[2..4].copy_from_slice(&x.to_be_bytes());
    b[4..6].copy_from_slice(&y.to_be_bytes());
    b
}

/// Legacy ClientCutText carrying raw (Latin-1) bytes.
pub fn client_cut_text(data: &[u8]) -> Vec<u8> {
    let n = data.len().min(MAX_CUT_TEXT);
    let mut out = Vec::with_capacity(8 + n);
    out.push(client_msg::CLIENT_CUT_TEXT);
    out.extend_from_slice(&[0, 0, 0]); // padding
    out.extend_from_slice(&(n as u32).to_be_bytes());
    out.extend_from_slice(&data[..n]);
    out
}

/// Extended Clipboard "request" message: ClientCutText with negative length
/// and a single flags word (action = request, plus the wanted format bits).
pub fn extended_clipboard_request(formats: u32) -> Vec<u8> {
    let flags = ext_clipboard::ACTION_REQUEST | (formats & ext_clipboard::FORMAT_MASK);
    let mut out = Vec::with_capacity(12);
    out.push(client_msg::CLIENT_CUT_TEXT);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&(-4i32).to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out
}

pub fn enable_continuous_updates(enable: bool, rect: Rect) -> [u8; 10] {
    let mut b = [0u8; 10];
    b[0] = client_msg::ENABLE_CONTINUOUS_UPDATES;
    b[1] = enable as u8;
    b[2..4].copy_from_slice(&rect.x.to_be_bytes());
    b[4..6].copy_from_slice(&rect.y.to_be_bytes());
    b[6..8].copy_from_slice(&rect.width.to_be_bytes());
    b[8..10].copy_from_slice(&rect.height.to_be_bytes());
    b
}

/// ClientFence. The payload is truncated to the spec maximum of 64 bytes.
pub fn client_fence(flags: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len().min(fence_flags::MAX_PAYLOAD);
    let mut out = Vec::with_capacity(9 + n);
    out.push(client_msg::CLIENT_FENCE);
    out.extend_from_slice(&[0, 0, 0]); // padding
    out.extend_from_slice(&flags.to_be_bytes());
    out.push(n as u8);
    out.extend_from_slice(&payload[..n]);
    out
}

pub fn set_desktop_size(width: u16, height: u16, screens: &[Screen]) -> Vec<u8> {
    let n = screens.len().min(u8::MAX as usize);
    let mut out = Vec::with_capacity(8 + n * 16);
    out.push(client_msg::SET_DESKTOP_SIZE);
    out.push(0); // padding
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.push(n as u8);
    out.push(0); // padding
    for s in &screens[..n] {
        encode_screen_into(s, &mut out);
    }
    out
}

pub fn qemu_extended_key_event(keysym: u32, keycode: u32, down: bool) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = client_msg::QEMU;
    b[1] = client_msg::QEMU_SUB_EXTENDED_KEY_EVENT;
    b[2..4].copy_from_slice(&(down as u16).to_be_bytes());
    b[4..8].copy_from_slice(&keysym.to_be_bytes());
    b[8..12].copy_from_slice(&keycode.to_be_bytes());
    b
}

// ---------------------------------------------------------------------------
// Server → client readers
// ---------------------------------------------------------------------------

/// Read exactly `len` bytes, mapping EOF to `ConnectionClosed`.
pub async fn read_exact_vec<R>(reader: &mut R, len: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await.map_err(map_eof)?;
    Ok(buf)
}

pub(crate) fn map_eof(e: std::io::Error) -> VncError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        VncError::ConnectionClosed
    } else {
        VncError::Io(e)
    }
}

/// After the type byte of a FramebufferUpdate: padding + number-of-rectangles.
pub async fn read_framebuffer_update_header<R>(reader: &mut R) -> Result<u16>
where
    R: AsyncRead + Unpin,
{
    let _pad = reader.read_u8().await.map_err(map_eof)?;
    let count = reader.read_u16().await.map_err(map_eof)?;
    Ok(count)
}

/// One rectangle header: x, y, width, height, encoding.
pub async fn read_rect_header<R>(reader: &mut R) -> Result<(Rect, i32)>
where
    R: AsyncRead + Unpin,
{
    let x = reader.read_u16().await.map_err(map_eof)?;
    let y = reader.read_u16().await.map_err(map_eof)?;
    let width = reader.read_u16().await.map_err(map_eof)?;
    let height = reader.read_u16().await.map_err(map_eof)?;
    let encoding = reader.read_i32().await.map_err(map_eof)?;
    Ok((Rect::new(x, y, width, height), encoding))
}

/// SetColourMapEntries: (first_colour, entries as \[r, g, b\]).
pub async fn read_set_colour_map_entries<R>(reader: &mut R) -> Result<(u16, Vec<[u16; 3]>)>
where
    R: AsyncRead + Unpin,
{
    let _pad = reader.read_u8().await.map_err(map_eof)?;
    let first = reader.read_u16().await.map_err(map_eof)?;
    let n = reader.read_u16().await.map_err(map_eof)? as usize;
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let r = reader.read_u16().await.map_err(map_eof)?;
        let g = reader.read_u16().await.map_err(map_eof)?;
        let b = reader.read_u16().await.map_err(map_eof)?;
        entries.push([r, g, b]);
    }
    Ok((first, entries))
}

/// A ServerCutText payload: legacy (non-negative length, Latin-1 bytes) or the
/// Extended Clipboard form (negative length; payload begins with a flags word).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutTextPayload {
    Legacy(Vec<u8>),
    Extended(Vec<u8>),
}

pub async fn read_server_cut_text<R>(reader: &mut R) -> Result<CutTextPayload>
where
    R: AsyncRead + Unpin,
{
    let mut pad = [0u8; 3];
    reader.read_exact(&mut pad).await.map_err(map_eof)?;
    let len = reader.read_i32().await.map_err(map_eof)?;
    let abs = len.unsigned_abs() as usize;
    if abs > MAX_CUT_TEXT {
        return Err(VncError::Protocol(format!(
            "server cut text length {abs} exceeds limit"
        )));
    }
    let data = read_exact_vec(reader, abs).await?;
    if len < 0 {
        if data.len() < 4 {
            return Err(VncError::Protocol(
                "extended clipboard message shorter than flags word".into(),
            ));
        }
        Ok(CutTextPayload::Extended(data))
    } else {
        Ok(CutTextPayload::Legacy(data))
    }
}

/// ServerFence: (flags, payload). Payload length is capped at 64 by the spec;
/// anything larger is a protocol violation.
pub async fn read_server_fence<R>(reader: &mut R) -> Result<(u32, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut pad = [0u8; 3];
    reader.read_exact(&mut pad).await.map_err(map_eof)?;
    let flags = reader.read_u32().await.map_err(map_eof)?;
    let len = reader.read_u8().await.map_err(map_eof)? as usize;
    if len > fence_flags::MAX_PAYLOAD {
        return Err(VncError::Protocol(format!(
            "fence payload length {len} exceeds 64"
        )));
    }
    let payload = read_exact_vec(reader, len).await?;
    Ok((flags, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixel_format_round_trip() {
        for pf in [
            PixelFormat::bgra8888(),
            PixelFormat::palette8(),
            PixelFormat::rgb222(),
        ] {
            let wire = encode_pixel_format(&pf);
            let back = parse_pixel_format(&wire).unwrap();
            assert_eq!(pf, back);
        }
    }

    #[test]
    fn pixel_format_rejects_bad_bpp_and_depth() {
        let mut wire = encode_pixel_format(&PixelFormat::bgra8888());
        wire[0] = 24; // bpp 24 invalid
        assert!(parse_pixel_format(&wire).is_err());
        let mut wire = encode_pixel_format(&PixelFormat::bgra8888());
        wire[1] = 0; // depth 0 invalid
        assert!(parse_pixel_format(&wire).is_err());
    }

    #[test]
    fn set_pixel_format_layout() {
        let b = set_pixel_format(&PixelFormat::bgra8888());
        assert_eq!(b[0], 0);
        assert_eq!(&b[1..4], &[0, 0, 0]);
        assert_eq!(b[4], 32); // bpp
        assert_eq!(b[5], 24); // depth
    }

    #[test]
    fn set_encodings_layout() {
        let b = set_encodings(&[7, -239, 16]);
        assert_eq!(b[0], 2);
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 3);
        assert_eq!(i32::from_be_bytes([b[4], b[5], b[6], b[7]]), 7);
        assert_eq!(i32::from_be_bytes([b[8], b[9], b[10], b[11]]), -239);
        assert_eq!(b.len(), 4 + 12);
    }

    #[test]
    fn fbur_layout() {
        let b = framebuffer_update_request(true, Rect::new(1, 2, 300, 400));
        assert_eq!(b, [3, 1, 0, 1, 0, 2, 1, 44, 1, 144]);
    }

    #[test]
    fn key_and_pointer_layout() {
        assert_eq!(key_event(0xffeb, true), [4, 1, 0, 0, 0, 0, 0xff, 0xeb]);
        assert_eq!(pointer_event(0x0102, 0x0304, 0b101), [5, 0b101, 1, 2, 3, 4]);
    }

    #[test]
    fn qemu_key_layout() {
        let b = qemu_extended_key_event(0x61, 0x1e, true);
        assert_eq!(b[0], 255);
        assert_eq!(b[1], 0);
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 1);
        assert_eq!(u32::from_be_bytes([b[4], b[5], b[6], b[7]]), 0x61);
        assert_eq!(u32::from_be_bytes([b[8], b[9], b[10], b[11]]), 0x1e);
    }

    #[test]
    fn fence_truncates_payload_to_64() {
        let big = vec![0xaa; 100];
        let b = client_fence(fence_flags::REQUEST, &big);
        assert_eq!(b[8], 64);
        assert_eq!(b.len(), 9 + 64);
    }

    #[test]
    fn set_desktop_size_layout() {
        let s = Screen {
            id: 7,
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
            flags: 3,
            primary: false,
        };
        let b = set_desktop_size(1920, 1080, &[s]);
        assert_eq!(b[0], 251);
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 1920);
        assert_eq!(u16::from_be_bytes([b[4], b[5]]), 1080);
        assert_eq!(b[6], 1); // one screen
        assert_eq!(u32::from_be_bytes([b[8], b[9], b[10], b[11]]), 7);
        assert_eq!(b.len(), 8 + 16);
    }

    #[test]
    fn extended_clipboard_request_layout() {
        let b = extended_clipboard_request(0x1);
        assert_eq!(b[0], 6);
        assert_eq!(i32::from_be_bytes([b[4], b[5], b[6], b[7]]), -4);
        let flags = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        assert_eq!(flags, ext_clipboard::ACTION_REQUEST | 1);
    }

    #[tokio::test]
    async fn rect_header_round_trip() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(&6u16.to_be_bytes());
        wire.extend_from_slice(&7u16.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());
        wire.extend_from_slice(&(-239i32).to_be_bytes());
        let mut cur = std::io::Cursor::new(wire);
        let (rect, enc) = read_rect_header(&mut cur).await.unwrap();
        assert_eq!(rect, Rect::new(5, 6, 7, 8));
        assert_eq!(enc, -239);
    }

    #[tokio::test]
    async fn server_cut_text_legacy_and_extended() {
        // legacy
        let mut wire = vec![0, 0, 0];
        wire.extend_from_slice(&5i32.to_be_bytes());
        wire.extend_from_slice(b"hello");
        let mut cur = std::io::Cursor::new(wire);
        assert_eq!(
            read_server_cut_text(&mut cur).await.unwrap(),
            CutTextPayload::Legacy(b"hello".to_vec())
        );
        // extended (negative length)
        let mut wire = vec![0, 0, 0];
        wire.extend_from_slice(&(-4i32).to_be_bytes());
        wire.extend_from_slice(&0x0800_0001u32.to_be_bytes());
        let mut cur = std::io::Cursor::new(wire);
        match read_server_cut_text(&mut cur).await.unwrap() {
            CutTextPayload::Extended(d) => assert_eq!(d.len(), 4),
            other => panic!("expected extended, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_fence_rejects_oversized_payload() {
        let mut wire = vec![0, 0, 0];
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.push(65);
        let mut cur = std::io::Cursor::new(wire);
        assert!(read_server_fence(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn server_fence_round_trip() {
        let mut wire = vec![0, 0, 0];
        wire.extend_from_slice(&(fence_flags::REQUEST | fence_flags::SYNC_NEXT).to_be_bytes());
        wire.push(3);
        wire.extend_from_slice(&[1, 2, 3]);
        let mut cur = std::io::Cursor::new(wire);
        let (flags, payload) = read_server_fence(&mut cur).await.unwrap();
        assert_eq!(flags, fence_flags::REQUEST | fence_flags::SYNC_NEXT);
        assert_eq!(payload, vec![1, 2, 3]);
    }
}
