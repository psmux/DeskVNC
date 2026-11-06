//! WebSocket framing for the RD Gateway's upgraded channel (RFC 6455).
//!
//! After a `101 Switching Protocols` on `RDG_OUT_DATA` the gateway and the
//! client exchange MS-TSGU packets inside binary frames on that one
//! connection. A frame boundary means nothing to MS-TSGU: a packet can span
//! frames and one frame can hold several packets, so the decoder below hands
//! back payload bytes and the packet layer reassembles.
//!
//! Client frames are masked, as RFC 6455 5.3 requires, with a fresh key from
//! the operating system's generator per frame. Server frames are not.

use base64::Engine as _;
use rand::Rng as _;
use sha1::{Digest as _, Sha1};

use crate::error::{RdpError, Result};

/// The GUID RFC 6455 4.2.2 appends to the key before hashing.
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The largest frame payload accepted from the gateway. Its frames carry at
/// most one MS-TSGU packet's worth; this is room for several.
pub const MAX_FRAME: usize = 1 << 20;

/// Frame opcodes (RFC 6455 5.2).
#[allow(missing_docs)]
pub mod opcode {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// A fresh `Sec-WebSocket-Key`: sixteen random bytes in base64.
#[must_use]
pub fn new_key() -> String {
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    base64::engine::general_purpose::STANDARD.encode(nonce)
}

/// The `Sec-WebSocket-Accept` a server must answer `key` with.
#[must_use]
pub fn accept_for(key: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(key.as_bytes());
    sha.update(ACCEPT_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(sha.finalize())
}

/// One client frame, FIN set, masked with `mask`.
#[must_use]
pub fn encode_with_mask(op: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | op);
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= usize::from(u16::MAX) {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
    out
}

/// One client frame with a fresh random mask.
#[must_use]
pub fn encode(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut mask = [0u8; 4];
    rand::rng().fill_bytes(&mut mask);
    encode_with_mask(op, payload, mask)
}

/// What one decoded frame was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Payload of a data frame (binary, text or continuation).
    Data(Vec<u8>),
    /// A ping, whose payload goes back in a pong.
    Ping(Vec<u8>),
    /// A pong, ignored.
    Pong,
    /// The gateway closed the WebSocket.
    Close,
}

/// Take one whole frame off the front of `buf`, or `None` when it has not
/// all arrived.
///
/// # Errors
///
/// [`RdpError::Protocol`] for a masked server frame, a reserved bit, an
/// unknown opcode, or a payload over [`MAX_FRAME`].
pub fn decode(buf: &mut Vec<u8>) -> Result<Option<Frame>> {
    let (Some(&b0), Some(&b1)) = (buf.first(), buf.get(1)) else {
        return Ok(None);
    };
    if b0 & 0x70 != 0 {
        return Err(bad("a reserved bit is set"));
    }
    if b1 & 0x80 != 0 {
        return Err(bad("the gateway masked its frame"));
    }
    let op = b0 & 0x0F;
    let (len, header) = match b1 & 0x7F {
        126 => match buf.get(2..4) {
            Some(b) => (usize::from(u16::from_be_bytes([b[0], b[1]])), 4),
            None => return Ok(None),
        },
        127 => match buf.get(2..10) {
            Some(b) => {
                let mut be = [0u8; 8];
                be.copy_from_slice(b);
                (
                    usize::try_from(u64::from_be_bytes(be)).unwrap_or(usize::MAX),
                    10,
                )
            }
            None => return Ok(None),
        },
        n => (usize::from(n), 2),
    };
    if len > MAX_FRAME {
        return Err(bad("a frame is larger than the gateway ever needs"));
    }
    if buf.len() < header + len {
        return Ok(None);
    }
    let payload: Vec<u8> = buf.drain(..header + len).skip(header).collect();
    Ok(Some(match op {
        opcode::CONTINUATION | opcode::TEXT | opcode::BINARY => Frame::Data(payload),
        opcode::PING => Frame::Ping(payload),
        opcode::PONG => Frame::Pong,
        opcode::CLOSE => Frame::Close,
        _ => return Err(bad("an unknown opcode")),
    }))
}

fn bad(what: &str) -> RdpError {
    RdpError::Protocol(format!(
        "the RD Gateway's WebSocket stream is malformed: {what}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6455 1.3's worked example.
    #[test]
    fn the_accept_value_is_the_one_in_the_rfc() {
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(new_key().len(), 24);
        assert_ne!(new_key(), new_key());
    }

    /// RFC 6455 5.7: "a single-frame masked text message" containing "Hello".
    #[test]
    fn a_masked_frame_matches_the_rfc_example() {
        assert_eq!(
            encode_with_mask(opcode::TEXT, b"Hello", [0x37, 0xfa, 0x21, 0x3d]),
            [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]
        );
    }

    #[test]
    fn the_long_length_forms_are_used_at_their_thresholds() {
        let f = encode_with_mask(opcode::BINARY, &[0; 126], [0; 4]);
        assert_eq!(&f[..4], [0x82, 0xFE, 0x00, 0x7E]);
        let f = encode_with_mask(opcode::BINARY, &[0; 65536], [0; 4]);
        assert_eq!(&f[..10], [0x82, 0xFF, 0, 0, 0, 0, 0, 1, 0, 0]);
    }

    /// RFC 6455 5.7: "a single-frame unmasked text message" and the unmasked
    /// ping, back to back, arriving a byte at a time.
    #[test]
    fn server_frames_decode_however_they_arrive() {
        let wire = [
            0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
        ];
        let mut buf = Vec::new();
        let mut frames = Vec::new();
        for b in wire {
            buf.push(b);
            while let Some(f) = decode(&mut buf).unwrap() {
                frames.push(f);
            }
        }
        assert_eq!(
            frames,
            vec![
                Frame::Data(b"Hello".to_vec()),
                Frame::Ping(b"Hello".to_vec())
            ]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn a_sixteen_bit_length_decodes_and_a_close_is_reported() {
        let mut buf = vec![0x82, 0x7E, 0x01, 0x00];
        buf.extend([9u8; 256]);
        buf.extend([0x88, 0x00]);
        assert_eq!(decode(&mut buf).unwrap(), Some(Frame::Data(vec![9; 256])));
        assert_eq!(decode(&mut buf).unwrap(), Some(Frame::Close));
    }

    #[test]
    fn frames_a_client_must_not_accept_are_refused() {
        assert!(decode(&mut vec![0x82, 0x81, 0, 0, 0, 0, 0]).is_err());
        assert!(decode(&mut vec![0xC2, 0x00]).is_err());
        assert!(decode(&mut vec![0x83, 0x00]).is_err());
        assert!(decode(&mut vec![0x82, 0x7F, 0, 0, 0, 0, 0xFF, 0, 0, 0]).is_err());
    }
}
