//! The RD Gateway HTTP transport PDUs (MS-TSGU 2.2.10).
//!
//! An RD Gateway tunnels one RDP connection inside HTTPS. After the HTTP
//! side is set up (an `RDG_OUT_DATA` and `RDG_IN_DATA` pair, or one WebSocket
//! upgrade) both directions carry the packets in this module, each behind the
//! eight byte `HTTP_PACKET_HEADER` of MS-TSGU 2.2.10.9. The client sends a
//! handshake, creates a tunnel, authorizes it, creates one channel to the
//! RDP server, and from then on the RDP bytes travel in `HTTP_DATA_PACKET`s.
//!
//! The legacy RPC over HTTP transport (MS-TSGU 2.2.9) is not here and not
//! planned: every gateway since Windows Server 2008 R2 SP1 speaks this one,
//! and current ones prefer the WebSocket variant of it.
//!
//! Byte layouts were checked against MS-TSGU and against FreeRDP's
//! `libfreerdp/core/gateway/rdg.c`, which interoperates with Windows
//! gateways. Everything is little endian.

use crate::io::{PduError, PduResult, Reader, Writer};

/// `HTTP_PACKET_HEADER`: type, reserved, length (MS-TSGU 2.2.10.9).
pub const HEADER_LEN: usize = 8;

/// The largest packet this client accepts from a gateway.
///
/// A data packet carries at most a `u16` of payload, so anything that claims
/// more than that plus its headers is either a control packet with a
/// surprising body or garbage. Control packets are a few hundred bytes; a
/// consent message is the longest thing a gateway sends and fits easily.
pub const MAX_PACKET_LEN: usize = 0x1_0000 + HEADER_LEN + 2;

/// `PKT_TYPE_*` (MS-TSGU 2.2.5.3.3).
#[allow(missing_docs)]
pub mod packet_type {
    pub const HANDSHAKE_REQUEST: u16 = 0x1;
    pub const HANDSHAKE_RESPONSE: u16 = 0x2;
    pub const EXTENDED_AUTH_MSG: u16 = 0x3;
    pub const TUNNEL_CREATE: u16 = 0x4;
    pub const TUNNEL_RESPONSE: u16 = 0x5;
    pub const TUNNEL_AUTH: u16 = 0x6;
    pub const TUNNEL_AUTH_RESPONSE: u16 = 0x7;
    pub const CHANNEL_CREATE: u16 = 0x8;
    pub const CHANNEL_RESPONSE: u16 = 0x9;
    pub const DATA: u16 = 0xA;
    pub const SERVICE_MESSAGE: u16 = 0xB;
    pub const REAUTH_MESSAGE: u16 = 0xC;
    pub const KEEPALIVE: u16 = 0xD;
    pub const CLOSE_CHANNEL: u16 = 0x10;
    pub const CLOSE_CHANNEL_RESPONSE: u16 = 0x11;
}

/// `HTTP_EXTENDED_AUTH` (MS-TSGU 2.2.5.3.2): how the client proves who it is
/// beyond the HTTP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtendedAuth {
    /// The HTTP layer's own authentication (NTLM or Negotiate) is all there is.
    None = 0x0,
    /// Smart card.
    SmartCard = 0x1,
    /// Pluggable authentication: a cookie in the tunnel create packet.
    Paa = 0x2,
    /// NTLM inside `PKT_TYPE_EXTENDED_AUTH_MSG`, after a WebSocket upgrade.
    SspiNtlm = 0x4,
}

/// `HTTP_CAPABILITY_TYPE` flags (MS-TSGU 2.2.5.3.1).
#[allow(missing_docs)]
pub mod caps {
    pub const QUAR_SOH: u32 = 0x1;
    pub const IDLE_TIMEOUT: u32 = 0x2;
    pub const MESSAGING_CONSENT_SIGN: u32 = 0x4;
    pub const MESSAGING_SERVICE_MSG: u32 = 0x8;
    pub const REAUTH: u32 = 0x10;
    pub const UDP_TRANSPORT: u32 = 0x20;
}

/// What this client advertises in `HTTP_TUNNEL_PACKET.capsFlags`.
///
/// No `QUAR_SOH`: a statement of health is a Network Access Protection
/// artefact, NAP was removed in Windows Server 2016, and a client that
/// advertises it can be sent a nonce it has nothing to answer with. No consent
/// signing either: a gateway that requires the user to accept a message
/// before connecting will refuse this client with a capability mismatch
/// rather than have the client accept on the user's behalf.
pub const CLIENT_CAPS: u32 = caps::IDLE_TIMEOUT | caps::MESSAGING_SERVICE_MSG;

/// Protocol number of the only resource type there is, RDP
/// (`HTTP_CHANNEL_PACKET.protocol`, MS-TSGU 2.2.10.2).
pub const PROTOCOL_RDP: u16 = 3;

/// The header every packet starts with (MS-TSGU 2.2.10.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// `packetType`, one of [`packet_type`].
    pub packet_type: u16,
    /// `packetLength`, header included.
    pub length: u32,
}

impl Header {
    /// Read the eight header bytes.
    ///
    /// # Errors
    ///
    /// Truncation, a length shorter than the header itself, and a length over
    /// [`MAX_PACKET_LEN`].
    pub fn decode(bytes: &[u8]) -> PduResult<Self> {
        let mut r = Reader::new(bytes);
        let packet_type = r.u16("HTTP_PACKET_HEADER")?;
        let _reserved = r.u16("HTTP_PACKET_HEADER")?;
        let at = r.offset();
        let length = r.u32("HTTP_PACKET_HEADER")?;
        if (length as usize) < HEADER_LEN {
            return Err(PduError::InvalidField {
                context: "HTTP_PACKET_HEADER",
                field: "packetLength",
                value: u64::from(length),
                offset: at,
            });
        }
        if length as usize > MAX_PACKET_LEN {
            return Err(PduError::CapExceeded {
                context: "HTTP_PACKET_HEADER",
                declared: length as usize,
                cap: MAX_PACKET_LEN,
                limit_name: "tsgu::MAX_PACKET_LEN",
                offset: at,
            });
        }
        Ok(Self {
            packet_type,
            length,
        })
    }
}

/// Write a packet: the header, then whatever `body` writes, with the length
/// filled in afterwards.
fn packet(packet_type: u16, body: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    {
        let mut w = Writer::new(&mut out);
        w.u16(packet_type);
        w.u16(0);
        w.u32(0);
        body(&mut w);
    }
    let len = u32::try_from(out.len()).unwrap_or(u32::MAX).to_le_bytes();
    if let Some(field) = out.get_mut(4..8) {
        field.copy_from_slice(&len);
    }
    out
}

/// An `HTTP_UNICODE_STRING`: a `u16` byte count, then UTF-16LE with its NUL
/// (MS-TSGU 2.2.10.20).
fn unicode_string(w: &mut Writer<'_>, s: &str, context: &'static str) -> PduResult<()> {
    let units = s.encode_utf16().count() + 1;
    let bytes = u16::try_from(units * 2).map_err(|_| PduError::Encode {
        context,
        reason: "string longer than a u16 byte count",
    })?;
    w.u16(bytes);
    w.utf16(s);
    Ok(())
}

fn read_unicode_string(r: &mut Reader<'_>, context: &'static str) -> PduResult<String> {
    let len = usize::from(r.u16(context)?);
    r.utf16_len(len, context)
}

fn read_blob<'a>(r: &mut Reader<'a>, context: &'static str) -> PduResult<&'a [u8]> {
    let len = usize::from(r.u16(context)?);
    r.slice(len, context)
}

/// `HTTP_HANDSHAKE_REQUEST_PACKET` (MS-TSGU 2.2.10.10): version 1.0, client
/// version 0, and the extended authentication the client will use.
#[must_use]
pub fn handshake_request(ext_auth: ExtendedAuth) -> Vec<u8> {
    packet(packet_type::HANDSHAKE_REQUEST, |w| {
        w.u8(1);
        w.u8(0);
        w.u16(0);
        w.u16(ext_auth as u16);
    })
}

/// `HTTP_HANDSHAKE_RESPONSE_PACKET` (MS-TSGU 2.2.10.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// `errorCode`, an HRESULT.
    pub error_code: u32,
    /// `verMajor`.
    pub version_major: u8,
    /// `verMinor`.
    pub version_minor: u8,
    /// `serverVersion`.
    pub server_version: u16,
    /// `extendedAuth`, what the gateway accepted.
    pub extended_auth: u16,
}

/// `HTTP_TUNNEL_PACKET` (MS-TSGU 2.2.10.18), with the PAA cookie when there
/// is one.
///
/// The cookie goes as UTF-16LE with its terminator, the form mstsc sends and
/// the form FreeRDP copied from it, inside the `HTTP_BYTE_BLOB` the
/// specification names.
///
/// # Errors
///
/// A cookie too long for a `u16` byte count.
pub fn tunnel_create(paa_cookie: Option<&str>) -> PduResult<Vec<u8>> {
    let mut result = Ok(());
    let out = packet(packet_type::TUNNEL_CREATE, |w| {
        w.u32(CLIENT_CAPS);
        w.u16(u16::from(paa_cookie.is_some()));
        w.u16(0);
        if let Some(cookie) = paa_cookie {
            result = unicode_string(w, cookie, "HTTP_TUNNEL_PACKET");
        }
    });
    result.map(|()| out)
}

/// `HTTP_TUNNEL_RESPONSE` (MS-TSGU 2.2.10.20).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TunnelResponse {
    /// `serverVersion`.
    pub server_version: u16,
    /// `statusCode`, an HRESULT.
    pub status_code: u32,
    /// `tunnelId`, when present.
    pub tunnel_id: Option<u32>,
    /// The gateway's `capsFlags`, when present.
    pub caps: Option<u32>,
    /// A consent message the gateway wants accepted, when present.
    pub consent_message: Option<String>,
}

/// `HTTP_TUNNEL_AUTH_PACKET` (MS-TSGU 2.2.10.14): the client's machine name.
///
/// # Errors
///
/// A name too long for a `u16` byte count.
pub fn tunnel_auth(client_name: &str) -> PduResult<Vec<u8>> {
    let mut result = Ok(());
    let out = packet(packet_type::TUNNEL_AUTH, |w| {
        w.u16(0);
        result = unicode_string(w, client_name, "HTTP_TUNNEL_AUTH_PACKET");
    });
    result.map(|()| out)
}

/// `HTTP_TUNNEL_AUTH_RESPONSE` (MS-TSGU 2.2.10.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TunnelAuthResponse {
    /// `errorCode`, an HRESULT.
    pub error_code: u32,
    /// The device redirection flags the gateway imposes, when present.
    pub redir_flags: Option<u32>,
    /// The idle timeout in minutes, when present.
    pub idle_timeout: Option<u32>,
}

/// `HTTP_CHANNEL_PACKET` (MS-TSGU 2.2.10.2): one resource, no alternatives,
/// the RDP port, protocol 3.
///
/// # Errors
///
/// A server name too long for a `u16` byte count.
pub fn channel_create(server: &str, port: u16) -> PduResult<Vec<u8>> {
    let mut result = Ok(());
    let out = packet(packet_type::CHANNEL_CREATE, |w| {
        w.u8(1);
        w.u8(0);
        w.u16(port);
        w.u16(PROTOCOL_RDP);
        result = unicode_string(w, server, "HTTP_CHANNEL_PACKET");
    });
    result.map(|()| out)
}

/// `HTTP_CHANNEL_RESPONSE` (MS-TSGU 2.2.10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelResponse {
    /// `errorCode`, an HRESULT.
    pub error_code: u32,
    /// `channelId`, when present.
    pub channel_id: Option<u32>,
}

/// The fixed part of an `HTTP_DATA_PACKET` in front of its payload: the
/// header and `cbDataLen` (MS-TSGU 2.2.10.6).
pub const DATA_PREFIX_LEN: usize = HEADER_LEN + 2;

/// The most RDP bytes one data packet carries.
pub const MAX_DATA_LEN: usize = u16::MAX as usize;

/// `HTTP_DATA_PACKET` (MS-TSGU 2.2.10.6). The caller splits anything longer
/// than [`MAX_DATA_LEN`].
///
/// # Errors
///
/// A payload over [`MAX_DATA_LEN`].
pub fn data(payload: &[u8]) -> PduResult<Vec<u8>> {
    let len = u16::try_from(payload.len()).map_err(|_| PduError::Encode {
        context: "HTTP_DATA_PACKET",
        reason: "payload longer than cbDataLen can count",
    })?;
    let mut out = Vec::with_capacity(DATA_PREFIX_LEN + payload.len());
    {
        let mut w = Writer::new(&mut out);
        w.u16(packet_type::DATA);
        w.u16(0);
        w.u32((DATA_PREFIX_LEN + payload.len()) as u32);
        w.u16(len);
        w.bytes(payload);
    }
    Ok(out)
}

/// `HTTP_KEEPALIVE_PACKET`: the header alone (MS-TSGU 2.2.10.8).
#[must_use]
pub fn keepalive() -> Vec<u8> {
    packet(packet_type::KEEPALIVE, |_| {})
}

/// `HTTP_CLOSE_PACKET` with type `PKT_TYPE_CLOSE_CHANNEL`, which the client
/// sends to end the session (MS-TSGU 2.2.10.3).
#[must_use]
pub fn close_channel(status: u32) -> Vec<u8> {
    packet(packet_type::CLOSE_CHANNEL, |w| w.u32(status))
}

/// The answer to a gateway's `PKT_TYPE_CLOSE_CHANNEL` (MS-TSGU 2.2.10.3).
#[must_use]
pub fn close_channel_response(status: u32) -> Vec<u8> {
    packet(packet_type::CLOSE_CHANNEL_RESPONSE, |w| w.u32(status))
}

/// `PKT_TYPE_EXTENDED_AUTH_MSG` (MS-TSGU 2.2.10.7): an SSPI token after a
/// WebSocket upgrade, with `errorCode` zero as the client always sends it.
///
/// # Errors
///
/// A token too long for a `u16` byte count.
pub fn extended_auth(token: &[u8]) -> PduResult<Vec<u8>> {
    let len = u16::try_from(token.len()).map_err(|_| PduError::Encode {
        context: "HTTP_EXTENDED_AUTH_PACKET",
        reason: "token longer than cbExtendedAuthBlob can count",
    })?;
    Ok(packet(packet_type::EXTENDED_AUTH_MSG, |w| {
        w.u32(0);
        w.u16(len);
        w.bytes(token);
    }))
}

/// One packet from the gateway, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerPacket<'a> {
    /// `PKT_TYPE_HANDSHAKE_RESPONSE`.
    Handshake(HandshakeResponse),
    /// `PKT_TYPE_EXTENDED_AUTH_MSG`: an HRESULT and an SSPI token.
    ExtendedAuth {
        /// `errorCode`.
        error_code: u32,
        /// The token, possibly empty.
        token: &'a [u8],
    },
    /// `PKT_TYPE_TUNNEL_RESPONSE`.
    Tunnel(TunnelResponse),
    /// `PKT_TYPE_TUNNEL_AUTH_RESPONSE`.
    TunnelAuth(TunnelAuthResponse),
    /// `PKT_TYPE_CHANNEL_RESPONSE`.
    Channel(ChannelResponse),
    /// `PKT_TYPE_DATA`: RDP bytes.
    Data(&'a [u8]),
    /// `PKT_TYPE_KEEPALIVE`.
    Keepalive,
    /// `PKT_TYPE_CLOSE_CHANNEL`, with the gateway's status.
    CloseChannel(u32),
    /// `PKT_TYPE_CLOSE_CHANNEL_RESPONSE`.
    CloseChannelResponse(u32),
    /// `PKT_TYPE_SERVICE_MESSAGE`: an administrator's message.
    ServiceMessage(String),
    /// `PKT_TYPE_REAUTH_MESSAGE`, which this client does not take part in.
    Reauth,
    /// A type this client does not know. Its length is in the header, so it
    /// is skipped rather than desynchronising the stream.
    Unknown(u16),
}

impl<'a> ServerPacket<'a> {
    /// Decode one whole packet, header included.
    ///
    /// # Errors
    ///
    /// Truncation, a length field that disagrees with the bytes, and any
    /// field the specification fixes holding something else.
    pub fn decode(bytes: &'a [u8]) -> PduResult<Self> {
        let header = Header::decode(bytes)?;
        let total = header.length as usize;
        if bytes.len() != total {
            return Err(PduError::LengthMismatch {
                context: "HTTP_PACKET_HEADER",
                declared: total,
                actual: bytes.len(),
                offset: 4,
            });
        }
        let body = bytes.get(HEADER_LEN..).unwrap_or_default();
        let mut r = Reader::sub(body, HEADER_LEN);
        let packet = match header.packet_type {
            packet_type::HANDSHAKE_RESPONSE => {
                const C: &str = "HTTP_HANDSHAKE_RESPONSE_PACKET";
                Self::Handshake(HandshakeResponse {
                    error_code: r.u32(C)?,
                    version_major: r.u8(C)?,
                    version_minor: r.u8(C)?,
                    server_version: r.u16(C)?,
                    extended_auth: r.u16(C)?,
                })
            }
            packet_type::EXTENDED_AUTH_MSG => {
                const C: &str = "HTTP_EXTENDED_AUTH_PACKET";
                let error_code = r.u32(C)?;
                let token = read_blob(&mut r, C)?;
                Self::ExtendedAuth { error_code, token }
            }
            packet_type::TUNNEL_RESPONSE => Self::Tunnel(decode_tunnel_response(&mut r)?),
            packet_type::TUNNEL_AUTH_RESPONSE => {
                const C: &str = "HTTP_TUNNEL_AUTH_RESPONSE";
                let error_code = r.u32(C)?;
                let fields = r.u16(C)?;
                let _reserved = r.u16(C)?;
                let mut out = TunnelAuthResponse {
                    error_code,
                    ..TunnelAuthResponse::default()
                };
                if fields & 0x1 != 0 {
                    out.redir_flags = Some(r.u32(C)?);
                }
                if fields & 0x2 != 0 {
                    out.idle_timeout = Some(r.u32(C)?);
                }
                if fields & 0x4 != 0 {
                    let _soh_response = read_blob(&mut r, C)?;
                }
                Self::TunnelAuth(out)
            }
            packet_type::CHANNEL_RESPONSE => {
                const C: &str = "HTTP_CHANNEL_RESPONSE";
                let error_code = r.u32(C)?;
                let fields = r.u16(C)?;
                let _reserved = r.u16(C)?;
                let mut out = ChannelResponse {
                    error_code,
                    channel_id: None,
                };
                // A failed response may stop after the fixed part even with
                // bits set, so the optional fields are only read on success.
                if error_code == 0 {
                    if fields & 0x1 != 0 {
                        out.channel_id = Some(r.u32(C)?);
                    }
                    if fields & 0x4 != 0 {
                        let _udp_port = r.u16(C)?;
                    }
                    if fields & 0x2 != 0 {
                        let _authn_cookie = read_blob(&mut r, C)?;
                    }
                }
                Self::Channel(out)
            }
            packet_type::DATA => {
                const C: &str = "HTTP_DATA_PACKET";
                let len = usize::from(r.u16(C)?);
                let at = r.offset();
                let data = r.slice(len, C)?;
                if !r.is_empty() {
                    return Err(PduError::LengthMismatch {
                        context: C,
                        declared: len,
                        actual: len + r.remaining(),
                        offset: at,
                    });
                }
                Self::Data(data)
            }
            packet_type::KEEPALIVE => Self::Keepalive,
            packet_type::CLOSE_CHANNEL => Self::CloseChannel(r.u32("HTTP_CLOSE_PACKET")?),
            packet_type::CLOSE_CHANNEL_RESPONSE => {
                Self::CloseChannelResponse(r.u32("HTTP_CLOSE_PACKET")?)
            }
            packet_type::SERVICE_MESSAGE => {
                Self::ServiceMessage(read_unicode_string(&mut r, "HTTP_SERVICE_MESSAGE")?)
            }
            packet_type::REAUTH_MESSAGE => Self::Reauth,
            other => Self::Unknown(other),
        };
        Ok(packet)
    }
}

fn decode_tunnel_response(r: &mut Reader<'_>) -> PduResult<TunnelResponse> {
    const C: &str = "HTTP_TUNNEL_RESPONSE";
    let server_version = r.u16(C)?;
    let status_code = r.u32(C)?;
    let fields = r.u16(C)?;
    let _reserved = r.u16(C)?;
    let mut out = TunnelResponse {
        server_version,
        status_code,
        ..TunnelResponse::default()
    };
    if status_code != 0 {
        return Ok(out);
    }
    if fields & 0x1 != 0 {
        out.tunnel_id = Some(r.u32(C)?);
    }
    if fields & 0x2 != 0 {
        out.caps = Some(r.u32(C)?);
    }
    if fields & 0x4 != 0 {
        // The statement of health request: a nonce and the server's
        // certificate. Never asked for, because `QUAR_SOH` is not advertised,
        // and skipped if it comes anyway.
        r.skip(20, C)?;
        let _server_cert = read_unicode_string(r, C)?;
    }
    if fields & 0x10 != 0 {
        out.consent_message = Some(read_unicode_string(r, C)?);
    }
    Ok(out)
}

/// The name of a gateway HRESULT, for a message a person reads.
///
/// The values are MS-TSGU 2.2.6's. Some arrive as full HRESULTs and some as
/// their low sixteen bits, which is how the gateway sends them.
#[must_use]
pub fn error_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x8007_59D8 | 0x0000_59D8 => "E_PROXY_INTERNALERROR",
        0x8007_59DA => "E_PROXY_RAP_ACCESSDENIED",
        0x8007_59DB => "E_PROXY_NAP_ACCESSDENIED",
        0x8007_59DD | 0x0000_59DD => "E_PROXY_TS_CONNECTFAILED",
        0x8007_59DF => "E_PROXY_ALREADYDISCONNECTED",
        0x8007_59E9 => "E_PROXY_CAPABILITYMISMATCH",
        0x8007_59ED => "E_PROXY_QUARANTINE_ACCESSDENIED",
        0x8007_59EE => "E_PROXY_NOCERTAVAILABLE",
        0x8007_59F7 => "E_PROXY_COOKIE_BADPACKET",
        0x8007_59F8 => "E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED",
        0x8007_59F9 => "E_PROXY_UNSUPPORTED_AUTHENTICATION_METHOD",
        0x0000_59E6 => "E_PROXY_MAXCONNECTIONSREACHED",
        0x0000_59E8 => "E_PROXY_NOTSUPPORTED",
        0x0000_59F6 => "E_PROXY_SESSIONTIMEOUT",
        0x0000_04D4 => "E_PROXY_CONNECTIONABORTED",
        0x8007_0005 => "E_ACCESSDENIED",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    /// The bytes `rdg_send_handshake` in FreeRDP writes: type 1, length 14,
    /// version 1.0, client version 0, then the extended auth.
    #[test]
    fn the_handshake_request_is_fourteen_bytes() {
        assert_eq!(
            handshake_request(ExtendedAuth::None),
            h("0100 0000 0e000000 01 00 0000 0000")
        );
        assert_eq!(
            handshake_request(ExtendedAuth::Paa),
            h("0100 0000 0e000000 01 00 0000 0200")
        );
    }

    #[test]
    fn a_handshake_response_decodes() {
        let bytes = h("0200 0000 12000000 00000000 01 00 0300 0000");
        assert_eq!(
            ServerPacket::decode(&bytes).unwrap(),
            ServerPacket::Handshake(HandshakeResponse {
                error_code: 0,
                version_major: 1,
                version_minor: 0,
                server_version: 3,
                extended_auth: 0,
            })
        );
    }

    #[test]
    fn the_tunnel_create_carries_our_caps_and_no_cookie() {
        assert_eq!(
            tunnel_create(None).unwrap(),
            h("0400 0000 10000000 0a000000 0000 0000")
        );
    }

    #[test]
    fn the_tunnel_create_carries_a_paa_cookie_as_utf16_with_its_nul() {
        // "ab": 3 units with the terminator, 6 bytes.
        assert_eq!(
            tunnel_create(Some("ab")).unwrap(),
            h("0400 0000 18000000 0a000000 0100 0000 0600 6100 6200 0000")
        );
    }

    #[test]
    fn a_tunnel_response_with_an_id_and_caps_decodes() {
        let bytes = h("0500 0000 1a000000 0500 00000000 0300 0000 07000000 3f000000");
        assert_eq!(
            ServerPacket::decode(&bytes).unwrap(),
            ServerPacket::Tunnel(TunnelResponse {
                server_version: 5,
                status_code: 0,
                tunnel_id: Some(7),
                caps: Some(0x3f),
                consent_message: None,
            })
        );
    }

    #[test]
    fn a_tunnel_response_with_a_consent_message_and_a_soh_request_decodes() {
        let mut body = h("0500 00000000 1400 0000");
        body.extend(std::iter::repeat_n(0xAA, 20)); // nonce
        body.extend(h("0400 7a00 0000")); // serverCert "z"
        body.extend(h("0600 6f00 6b00 0000")); // consent "ok"
        let mut bytes = h("0500 0000");
        bytes.extend(((body.len() + 8) as u32).to_le_bytes());
        bytes.extend(body);
        match ServerPacket::decode(&bytes).unwrap() {
            ServerPacket::Tunnel(t) => assert_eq!(t.consent_message.as_deref(), Some("ok")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_refused_tunnel_keeps_its_status() {
        let bytes = h("0500 0000 12000000 0500 f9590780 0000 0000");
        match ServerPacket::decode(&bytes).unwrap() {
            ServerPacket::Tunnel(t) => {
                assert_eq!(t.status_code, 0x8007_59F9);
                assert_eq!(
                    error_name(t.status_code),
                    Some("E_PROXY_UNSUPPORTED_AUTHENTICATION_METHOD")
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_tunnel_auth_carries_the_client_name() {
        // "PC": 6 bytes with the terminator, 8 + 2 + 2 + 6 = 18.
        assert_eq!(
            tunnel_auth("PC").unwrap(),
            h("0600 0000 12000000 0000 0600 5000 4300 0000")
        );
    }

    #[test]
    fn a_tunnel_auth_response_with_every_field_decodes() {
        let bytes = h("0700 0000 1c000000 00000000 0700 0000 01000000 1e000000 0200 abcd");
        assert_eq!(
            ServerPacket::decode(&bytes).unwrap(),
            ServerPacket::TunnelAuth(TunnelAuthResponse {
                error_code: 0,
                redir_flags: Some(1),
                idle_timeout: Some(30),
            })
        );
    }

    #[test]
    fn the_channel_create_names_one_rdp_resource() {
        // "h" on 3389: 1 resource, 0 alternatives, port 0x0d3d, protocol 3.
        assert_eq!(
            channel_create("h", 3389).unwrap(),
            h("0800 0000 14000000 01 00 3d0d 0300 0400 6800 0000")
        );
    }

    #[test]
    fn a_channel_response_decodes_with_and_without_an_id() {
        let ok = h("0900 0000 14000000 00000000 0100 0000 2a000000");
        assert_eq!(
            ServerPacket::decode(&ok).unwrap(),
            ServerPacket::Channel(ChannelResponse {
                error_code: 0,
                channel_id: Some(42),
            })
        );
        let refused = h("0900 0000 10000000 dd590780 0100 0000");
        assert_eq!(
            ServerPacket::decode(&refused).unwrap(),
            ServerPacket::Channel(ChannelResponse {
                error_code: 0x8007_59DD,
                channel_id: None,
            })
        );
    }

    #[test]
    fn data_round_trips_and_a_short_one_is_refused() {
        let packet = data(b"\x03\x00\x00\x0b").unwrap();
        assert_eq!(packet, h("0a00 0000 0e000000 0400 0300000b"));
        assert_eq!(
            ServerPacket::decode(&packet).unwrap(),
            ServerPacket::Data(b"\x03\x00\x00\x0b")
        );
        // cbDataLen says five, four follow.
        let lying = h("0a00 0000 0e000000 0500 0300000b");
        assert!(ServerPacket::decode(&lying).is_err());
        assert!(data(&vec![0; MAX_DATA_LEN + 1]).is_err());
    }

    #[test]
    fn keepalive_and_close_are_what_freerdp_sends() {
        assert_eq!(keepalive(), h("0d00 0000 08000000"));
        assert_eq!(close_channel_response(0), h("1100 0000 0c000000 00000000"));
        assert_eq!(close_channel(0), h("1000 0000 0c000000 00000000"));
        assert_eq!(
            ServerPacket::decode(&h("1000 0000 0c000000 dd590000")).unwrap(),
            ServerPacket::CloseChannel(0x59DD)
        );
        assert_eq!(
            ServerPacket::decode(&keepalive()).unwrap(),
            ServerPacket::Keepalive
        );
    }

    #[test]
    fn an_extended_auth_message_round_trips() {
        let packet = extended_auth(b"NTLM").unwrap();
        assert_eq!(packet, h("0300 0000 12000000 00000000 0400 4e544c4d"));
        assert_eq!(
            ServerPacket::decode(&packet).unwrap(),
            ServerPacket::ExtendedAuth {
                error_code: 0,
                token: b"NTLM"
            }
        );
    }

    #[test]
    fn a_service_message_decodes() {
        let bytes = h("0b00 0000 0e000000 0400 6800 0000");
        assert_eq!(
            ServerPacket::decode(&bytes).unwrap(),
            ServerPacket::ServiceMessage("h".into())
        );
    }

    #[test]
    fn the_header_refuses_lengths_it_cannot_honour() {
        assert!(Header::decode(&h("0a00 0000 07000000")).is_err());
        assert!(Header::decode(&h("0a00 0000 ffffffff")).is_err());
        assert!(Header::decode(&h("0a00 0000")).is_err());
        // A length that disagrees with the bytes handed in.
        assert!(ServerPacket::decode(&h("0d00 0000 09000000")).is_err());
    }

    #[test]
    fn an_unknown_type_is_named_rather_than_refused() {
        assert_eq!(
            ServerPacket::decode(&h("4200 0000 0a000000 0000")).unwrap(),
            ServerPacket::Unknown(0x42)
        );
    }
}
