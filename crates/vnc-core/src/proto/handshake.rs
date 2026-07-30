//! ClientInit / ServerInit exchange (RFC 6143 §7.3) and capability bootstrap.

use crate::error::{Result, VncError};
use crate::proto::messages::{map_eof, parse_pixel_format, read_exact_vec};
use crate::proto::version::NegotiatedVersion;
use crate::types::{PixelFormat, SecurityType, ServerCapabilities};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Sanity cap on the server-supplied desktop name length.
const MAX_NAME_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub pixel_format: PixelFormat,
    pub name: String,
}

/// Send the one-byte ClientInit (shared flag).
pub async fn write_client_init<W>(writer: &mut W, shared: bool) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[shared as u8]).await?;
    writer.flush().await?;
    Ok(())
}

/// Read and validate ServerInit.
pub async fn read_server_init<R>(reader: &mut R) -> Result<ServerInit>
where
    R: AsyncRead + Unpin,
{
    let width = reader.read_u16().await.map_err(map_eof)?;
    let height = reader.read_u16().await.map_err(map_eof)?;
    let mut pf_bytes = [0u8; 16];
    reader.read_exact(&mut pf_bytes).await.map_err(map_eof)?;
    let pixel_format = parse_pixel_format(&pf_bytes)?;
    let name_len = reader.read_u32().await.map_err(map_eof)? as usize;
    if name_len > MAX_NAME_LEN {
        return Err(VncError::Protocol(format!(
            "desktop name length {name_len} exceeds limit"
        )));
    }
    let name_bytes = read_exact_vec(reader, name_len).await?;
    let name = String::from_utf8_lossy(&name_bytes).into_owned();
    if width == 0 || height == 0 {
        return Err(VncError::Protocol(format!(
            "server reported empty framebuffer {width}x{height}"
        )));
    }
    Ok(ServerInit {
        width,
        height,
        pixel_format,
        name,
    })
}

/// One entry of a Tight capability list: `S32 code`, 4-byte vendor,
/// 8-byte signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TightCapability {
    pub code: i32,
    pub vendor: [u8; 4],
    pub signature: [u8; 8],
}

/// What the Tight security type appends after ServerInit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TightServerCapabilities {
    pub server_messages: Vec<TightCapability>,
    pub client_messages: Vec<TightCapability>,
    pub encodings: Vec<TightCapability>,
}

/// Cap on advertised capabilities, so a hostile server cannot make us read
/// (and allocate for) an unbounded list.
const MAX_TIGHT_CAPS: usize = 1024;

/// Read the **extended ServerInit** that follows the standard one when the
/// Tight security type (16) was negotiated.
///
/// ```text
/// U16 number-of-server-messages
/// U16 number-of-client-messages
/// U16 number-of-encodings
/// U16 padding
/// then (server + client + encodings) x 16-byte capability records
/// ```
///
/// **This is not optional.** Skipping it leaves `8 + 16N` unread bytes in the
/// stream, so the very next message header is parsed from the middle of the
/// capability list and every subsequent read is garbage, which surfaces as an
/// absurd rectangle ("rect 64512x512 exceeds framebuffer"). Servers offering
/// security types `[2, 16]` (TightVNC/TigerVNC family) hit this whenever the
/// client prefers Tight over VncAuth.
pub async fn read_tight_server_capabilities<R>(reader: &mut R) -> Result<TightServerCapabilities>
where
    R: AsyncRead + Unpin,
{
    let n_server = reader.read_u16().await.map_err(map_eof)? as usize;
    let n_client = reader.read_u16().await.map_err(map_eof)? as usize;
    let n_encodings = reader.read_u16().await.map_err(map_eof)? as usize;
    let _padding = reader.read_u16().await.map_err(map_eof)?;

    let total = n_server + n_client + n_encodings;
    if total > MAX_TIGHT_CAPS {
        return Err(VncError::Protocol(format!(
            "server advertised {total} Tight capabilities, exceeding the {MAX_TIGHT_CAPS} limit"
        )));
    }

    async fn read_list<R>(reader: &mut R, count: usize) -> Result<Vec<TightCapability>>
    where
        R: AsyncRead + Unpin,
    {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf).await.map_err(map_eof)?;
            out.push(TightCapability {
                code: i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
                vendor: [buf[4], buf[5], buf[6], buf[7]],
                signature: [
                    buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                ],
            });
        }
        Ok(out)
    }

    let caps = TightServerCapabilities {
        server_messages: read_list(reader, n_server).await?,
        client_messages: read_list(reader, n_client).await?,
        encodings: read_list(reader, n_encodings).await?,
    };
    tracing::debug!(
        server_messages = caps.server_messages.len(),
        client_messages = caps.client_messages.len(),
        encodings = caps.encodings.len(),
        "read Tight extended ServerInit capabilities"
    );
    Ok(caps)
}

/// Build the initial capability set for a fresh connection. Extension support
/// flags start false and are switched on as the server proves each one
/// (EndOfContinuousUpdates, ServerFence, pseudo-encoding acks, ...).
pub fn build_capabilities(
    version: &NegotiatedVersion,
    init: &ServerInit,
    security: SecurityType,
) -> ServerCapabilities {
    ServerCapabilities {
        protocol_version: version.version.as_str().to_string(),
        desktop_name: init.name.clone(),
        width: init.width,
        height: init.height,
        pixel_format: Some(init.pixel_format),
        security_type: Some(security),
        supports_continuous_updates: false,
        supports_fence: false,
        supports_extended_desktop_size: false,
        supports_extended_clipboard: false,
        supports_qemu_ext_key: false,
        supports_extended_mouse_buttons: false,
        // There is no handshake-time discovery for Open H.264, so we advertise
        // it by default (a server that cannot encode it simply never picks it)
        // and the webview decodes via VideoDecoder. The one server we *know*
        // cannot: macOS Screen Sharing offers third parties only
        // Raw/CopyRect/zlib/Hextile/ZRLE (PRD/02 §6), so do not waste a slot in
        // its encoding list.
        supports_h264: !version.is_apple_screen_sharing,
        is_apple_screen_sharing: version.is_apple_screen_sharing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::messages::encode_pixel_format;
    use crate::proto::version::parse_server_banner;

    fn server_init_wire(width: u16, height: u16, name: &str) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&width.to_be_bytes());
        wire.extend_from_slice(&height.to_be_bytes());
        wire.extend_from_slice(&encode_pixel_format(&PixelFormat::bgra8888()));
        wire.extend_from_slice(&(name.len() as u32).to_be_bytes());
        wire.extend_from_slice(name.as_bytes());
        wire
    }

    #[tokio::test]
    async fn server_init_round_trip() {
        let wire = server_init_wire(2560, 1440, "Living Room Mac");
        let mut cur = std::io::Cursor::new(wire);
        let si = read_server_init(&mut cur).await.unwrap();
        assert_eq!(si.width, 2560);
        assert_eq!(si.height, 1440);
        assert_eq!(si.name, "Living Room Mac");
        assert_eq!(si.pixel_format, PixelFormat::bgra8888());
    }

    #[tokio::test]
    async fn server_init_rejects_huge_name() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&800u16.to_be_bytes());
        wire.extend_from_slice(&600u16.to_be_bytes());
        wire.extend_from_slice(&encode_pixel_format(&PixelFormat::bgra8888()));
        wire.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cur = std::io::Cursor::new(wire);
        assert!(read_server_init(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn server_init_rejects_empty_framebuffer() {
        let wire = server_init_wire(0, 600, "x");
        let mut cur = std::io::Cursor::new(wire);
        assert!(read_server_init(&mut cur).await.is_err());
    }

    #[test]
    fn capabilities_flag_apple() {
        let mut banner = [0u8; 12];
        banner.copy_from_slice(b"RFB 003.889\n");
        let neg = parse_server_banner(&banner).unwrap();
        let si = ServerInit {
            width: 2880,
            height: 1800,
            pixel_format: PixelFormat::bgra8888(),
            name: "mac".into(),
        };
        let caps = build_capabilities(&neg, &si, SecurityType::AppleDh);
        assert!(caps.is_apple_screen_sharing);
        assert_eq!(caps.protocol_version, "3.8");
        assert!(!caps.supports_continuous_updates);
        assert!(
            !caps.supports_h264,
            "macOS Screen Sharing has no H.264 encoder for third parties"
        );
    }

    #[test]
    fn capabilities_advertise_h264_for_non_apple_servers() {
        let mut banner = [0u8; 12];
        banner.copy_from_slice(b"RFB 003.008\n");
        let neg = parse_server_banner(&banner).unwrap();
        let si = ServerInit {
            width: 1920,
            height: 1080,
            pixel_format: PixelFormat::bgra8888(),
            name: "tiger".into(),
        };
        let caps = build_capabilities(&neg, &si, SecurityType::VncAuth);
        assert!(caps.supports_h264);
    }

    /// Build a Tight extended-ServerInit blob, then whatever bytes the server
    /// would send next.
    fn tight_caps_blob(n_server: u16, n_client: u16, n_enc: u16, trailer: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&n_server.to_be_bytes());
        v.extend_from_slice(&n_client.to_be_bytes());
        v.extend_from_slice(&n_enc.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // padding
        for i in 0..(n_server + n_client + n_enc) {
            v.extend_from_slice(&(i as i32).to_be_bytes()); // code
            v.extend_from_slice(b"TGHT"); // vendor
            v.extend_from_slice(b"CAPNAME_"); // 8-byte signature
        }
        v.extend_from_slice(trailer);
        v
    }

    #[tokio::test]
    async fn reads_tight_extended_server_init_and_stops_exactly_at_the_end() {
        // The trailer is what a real server sends next, a FramebufferUpdate
        // header. If we consume one byte too few or too many, this is where the
        // desync shows up.
        let trailer = [0u8, 0, 0, 1];
        let blob = tight_caps_blob(3, 2, 5, &trailer);
        let mut r = std::io::Cursor::new(blob);

        let caps = read_tight_server_capabilities(&mut r).await.unwrap();
        assert_eq!(caps.server_messages.len(), 3);
        assert_eq!(caps.client_messages.len(), 2);
        assert_eq!(caps.encodings.len(), 5);
        assert_eq!(caps.encodings[0].vendor, *b"TGHT");

        // The stream must now be positioned exactly on the trailer.
        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut r, &mut rest)
            .await
            .unwrap();
        assert_eq!(
            rest, trailer,
            "stream desynchronised, this is the 'rect 64512x512 exceeds framebuffer' bug"
        );
    }

    #[tokio::test]
    async fn empty_tight_capability_lists_consume_only_the_header() {
        let trailer = [0xABu8; 4];
        let blob = tight_caps_blob(0, 0, 0, &trailer);
        let mut r = std::io::Cursor::new(blob);
        let caps = read_tight_server_capabilities(&mut r).await.unwrap();
        assert!(caps.encodings.is_empty());
        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut r, &mut rest)
            .await
            .unwrap();
        assert_eq!(rest, trailer);
    }

    #[tokio::test]
    async fn absurd_tight_capability_count_is_rejected_before_allocating() {
        let mut v = Vec::new();
        v.extend_from_slice(&u16::MAX.to_be_bytes());
        v.extend_from_slice(&u16::MAX.to_be_bytes());
        v.extend_from_slice(&u16::MAX.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        let mut r = std::io::Cursor::new(v);
        assert!(matches!(
            read_tight_server_capabilities(&mut r).await,
            Err(VncError::Protocol(_))
        ));
    }
}
