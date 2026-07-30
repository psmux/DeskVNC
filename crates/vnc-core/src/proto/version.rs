//! RFB protocol version handshake (RFC 6143 §7.1.1, PRD/02 §1).
//!
//! The server speaks first with a 12-byte banner `RFB xxx.yyy\n`. We parse it,
//! classify quirky real-world servers (macOS Screen Sharing `003.889`, UltraVNC
//! minor-version abuse, RealVNC `004.001`), and reply with the version we will
//! actually speak.

use crate::error::{Result, VncError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The RFB protocol versions we implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtocolVersion {
    V3_3,
    V3_7,
    V3_8,
}

impl ProtocolVersion {
    pub const fn major(self) -> u16 {
        3
    }

    pub const fn minor(self) -> u16 {
        match self {
            ProtocolVersion::V3_3 => 3,
            ProtocolVersion::V3_7 => 7,
            ProtocolVersion::V3_8 => 8,
        }
    }

    /// The 12-byte wire banner for this version.
    pub const fn banner(self) -> [u8; 12] {
        match self {
            ProtocolVersion::V3_3 => *b"RFB 003.003\n",
            ProtocolVersion::V3_7 => *b"RFB 003.007\n",
            ProtocolVersion::V3_8 => *b"RFB 003.008\n",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ProtocolVersion::V3_3 => "3.3",
            ProtocolVersion::V3_7 => "3.7",
            ProtocolVersion::V3_8 => "3.8",
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of parsing the server's version banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedVersion {
    /// The version we will speak with this server.
    pub version: ProtocolVersion,
    /// True when the banner was `RFB 003.889` (macOS Screen Sharing / ARD).
    pub is_apple_screen_sharing: bool,
    /// The raw major/minor the server announced (e.g. (3, 889)).
    pub server_major: u16,
    pub server_minor: u16,
}

impl NegotiatedVersion {
    /// The banner the client must send back.
    pub fn client_reply(&self) -> [u8; 12] {
        // Apple 003.889 expects `RFB 003.008` back (PRD/02 §1).
        self.version.banner()
    }
}

fn parse_u16_field(digits: &[u8]) -> Option<u16> {
    let mut v: u16 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u16)?;
    }
    Some(v)
}

/// Parse the server's 12-byte `RFB xxx.yyy\n` banner.
///
/// Classification rules (PRD/02 §1):
/// - `003.889` → macOS Screen Sharing; speak 3.8 and set the quirk flag.
/// - major 3, minor >= 8 (incl. unknown minors) → 3.8.
/// - major 3, minor 7 → 3.7.
/// - major 3, minor 3..=6 → 3.3 (UltraVNC abuses 3.4/3.6; treat as 3.3).
/// - major > 3 (RealVNC `004.001`) → downgrade to 3.8.
/// - anything else → `UnsupportedVersion`.
pub fn parse_server_banner(banner: &[u8; 12]) -> Result<NegotiatedVersion> {
    let bad =
        || VncError::UnsupportedVersion(String::from_utf8_lossy(banner).trim_end().to_string());

    if &banner[0..4] != b"RFB " || banner[7] != b'.' || banner[11] != b'\n' {
        return Err(bad());
    }
    let major = parse_u16_field(&banner[4..7]).ok_or_else(bad)?;
    let minor = parse_u16_field(&banner[8..11]).ok_or_else(bad)?;

    let (version, apple) = match (major, minor) {
        (3, 889) => (ProtocolVersion::V3_8, true),
        (3, m) if m >= 8 => (ProtocolVersion::V3_8, false),
        (3, 7) => (ProtocolVersion::V3_7, false),
        (3, m) if m >= 3 => (ProtocolVersion::V3_3, false),
        (m, _) if m > 3 => (ProtocolVersion::V3_8, false),
        _ => return Err(bad()),
    };

    Ok(NegotiatedVersion {
        version,
        is_apple_screen_sharing: apple,
        server_major: major,
        server_minor: minor,
    })
}

/// Perform the version handshake: read the server banner, reply with ours.
pub async fn negotiate<S>(stream: &mut S) -> Result<NegotiatedVersion>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut banner = [0u8; 12];
    stream.read_exact(&mut banner).await.map_err(map_eof)?;
    let negotiated = parse_server_banner(&banner)?;
    stream.write_all(&negotiated.client_reply()).await?;
    stream.flush().await?;
    Ok(negotiated)
}

fn map_eof(e: std::io::Error) -> VncError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        VncError::ConnectionClosed
    } else {
        VncError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<NegotiatedVersion> {
        let mut b = [0u8; 12];
        b.copy_from_slice(s.as_bytes());
        parse_server_banner(&b)
    }

    #[test]
    fn parses_standard_versions() {
        assert_eq!(
            parse("RFB 003.003\n").unwrap().version,
            ProtocolVersion::V3_3
        );
        assert_eq!(
            parse("RFB 003.007\n").unwrap().version,
            ProtocolVersion::V3_7
        );
        assert_eq!(
            parse("RFB 003.008\n").unwrap().version,
            ProtocolVersion::V3_8
        );
        assert!(!parse("RFB 003.008\n").unwrap().is_apple_screen_sharing);
    }

    #[test]
    fn apple_screen_sharing_889() {
        let neg = parse("RFB 003.889\n").unwrap();
        assert_eq!(neg.version, ProtocolVersion::V3_8);
        assert!(neg.is_apple_screen_sharing);
        assert_eq!(neg.server_minor, 889);
        assert_eq!(&neg.client_reply(), b"RFB 003.008\n");
    }

    #[test]
    fn ultravnc_minors_treated_as_3_3() {
        assert_eq!(
            parse("RFB 003.004\n").unwrap().version,
            ProtocolVersion::V3_3
        );
        assert_eq!(
            parse("RFB 003.006\n").unwrap().version,
            ProtocolVersion::V3_3
        );
    }

    #[test]
    fn unknown_high_minors_treated_as_3_8() {
        assert_eq!(
            parse("RFB 003.014\n").unwrap().version,
            ProtocolVersion::V3_8
        );
        assert_eq!(
            parse("RFB 003.024\n").unwrap().version,
            ProtocolVersion::V3_8
        );
    }

    #[test]
    fn realvnc_4_downgrades_to_3_8() {
        let neg = parse("RFB 004.001\n").unwrap();
        assert_eq!(neg.version, ProtocolVersion::V3_8);
        assert_eq!(&neg.client_reply(), b"RFB 003.008\n");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("HTTP/1.1 200").is_err());
        assert!(parse("RFB 00a.008\n").is_err());
        assert!(parse("RFB 003.008 ").is_err());
        assert!(parse("RFB 002.000\n").is_err());
        assert!(parse("RFB 003.002\n").is_err());
    }

    #[tokio::test]
    async fn negotiate_over_stream() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut server, b"RFB 003.889\n")
            .await
            .unwrap();
        let neg = negotiate(&mut client).await.unwrap();
        assert!(neg.is_apple_screen_sharing);
        let mut reply = [0u8; 12];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut reply)
            .await
            .unwrap();
        assert_eq!(&reply, b"RFB 003.008\n");
    }
}
