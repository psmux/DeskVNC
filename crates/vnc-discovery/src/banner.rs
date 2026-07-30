//! RFB banner parsing and fingerprint labelling.
//!
//! On TCP connect an RFB server speaks first: exactly 12 ASCII bytes of the
//! form `RFB xxx.yyy\n` (e.g. `RFB 003.008\n`). This module parses that banner
//! defensively (no panics on hostile input) and derives a human label.

/// A parsed RFB protocol banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Banner {
    /// Major protocol version (the `xxx` field).
    pub major: u16,
    /// Minor protocol version (the `yyy` field).
    pub minor: u16,
    /// The raw banner string, verbatim, without the trailing newline.
    pub raw: String,
}

/// Parse a 12-byte RFB banner.
///
/// Returns `None` for anything that is not a well-formed `RFB xxx.yyy\n`
/// banner. Bounds are checked; malformed or truncated input never panics.
pub fn parse_banner(buf: &[u8]) -> Option<Banner> {
    // Must be exactly 12 bytes: "RFB " (4) + "xxx" (3) + "." (1) + "yyy" (3) + "\n" (1)
    if buf.len() != 12 {
        return None;
    }
    if &buf[0..4] != b"RFB " {
        return None;
    }
    if buf[7] != b'.' {
        return None;
    }
    if buf[11] != b'\n' {
        return None;
    }
    let major = parse_u16_ascii(&buf[4..7])?;
    let minor = parse_u16_ascii(&buf[8..11])?;
    // Raw string, minus trailing newline. All bytes 0..11 are ASCII by now.
    let raw = std::str::from_utf8(&buf[0..11]).ok()?.to_string();
    Some(Banner { major, minor, raw })
}

/// Parse an exactly-3-byte ASCII decimal field into a u16.
fn parse_u16_ascii(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 3 {
        return None;
    }
    let mut val: u16 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val * 10 + u16::from(b - b'0');
    }
    Some(val)
}

/// Derive a human-friendly server label from the protocol version.
///
/// Recognises the fingerprints called out in PRD/04 §5:
/// - `003.889` → macOS Screen Sharing / ARD
/// - `004.001` → RealVNC proprietary path
/// - `003.008` → modern default (TigerVNC/RealVNC/UltraVNC/…)
/// - `003.003` / `003.007` → legacy
pub fn server_label(major: u16, minor: u16) -> String {
    match (major, minor) {
        (3, 889) => "macOS Screen Sharing".to_string(),
        (4, 1) => "RealVNC (RFB 4.1)".to_string(),
        (3, 8) => "VNC server (RFB 3.8)".to_string(),
        (3, 3) => "Legacy VNC server (RFB 3.3)".to_string(),
        (3, 7) => "Legacy VNC server (RFB 3.7)".to_string(),
        _ => format!("VNC server (RFB {major}.{minor})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modern_default() {
        let b = parse_banner(b"RFB 003.008\n").expect("valid banner");
        assert_eq!(b.major, 3);
        assert_eq!(b.minor, 8);
        assert_eq!(b.raw, "RFB 003.008");
        assert_eq!(server_label(b.major, b.minor), "VNC server (RFB 3.8)");
    }

    #[test]
    fn parses_macos_screen_sharing() {
        let b = parse_banner(b"RFB 003.889\n").expect("valid banner");
        assert_eq!((b.major, b.minor), (3, 889));
        assert_eq!(server_label(b.major, b.minor), "macOS Screen Sharing");
    }

    #[test]
    fn parses_realvnc() {
        let b = parse_banner(b"RFB 004.001\n").expect("valid banner");
        assert_eq!((b.major, b.minor), (4, 1));
        assert_eq!(server_label(b.major, b.minor), "RealVNC (RFB 4.1)");
    }

    #[test]
    fn parses_legacy_variants() {
        let b3 = parse_banner(b"RFB 003.003\n").expect("valid");
        assert_eq!(
            server_label(b3.major, b3.minor),
            "Legacy VNC server (RFB 3.3)"
        );
        let b7 = parse_banner(b"RFB 003.007\n").expect("valid");
        assert_eq!(
            server_label(b7.major, b7.minor),
            "Legacy VNC server (RFB 3.7)"
        );
    }

    #[test]
    fn rejects_malformed() {
        // Wrong magic
        assert!(parse_banner(b"HTTP/1.1 200\n").is_none());
        // Missing newline
        assert!(parse_banner(b"RFB 003.008 ").is_none());
        // Non-digit version
        assert!(parse_banner(b"RFB 00X.008\n").is_none());
        // Missing dot separator
        assert!(parse_banner(b"RFB 003x008\n").is_none());
        // Too short
        assert!(parse_banner(b"RFB 003.0\n").is_none());
        // Too long
        assert!(parse_banner(b"RFB 003.0088\n").is_none());
        // Empty
        assert!(parse_banner(b"").is_none());
        // Unknown but well-formed version still parses and gets a generic label
        let b = parse_banner(b"RFB 005.000\n").expect("well formed");
        assert_eq!(server_label(b.major, b.minor), "VNC server (RFB 5.0)");
    }
}
