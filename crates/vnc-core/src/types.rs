//! Shared contract types for the VNC core.
//!
//! This module is the integration contract between every other module and the
//! Tauri shell. Treat changes here as API changes.
//!
//! Everything that is not RFB now lives in `remote-core` and is re-exported
//! here at its old path, so no call site outside this crate moved
//! (PRDRDP/02 §2). What is left is the RFB half: the wire pixel format, the
//! encoding numbers, the security type numbers, and the capabilities read out
//! of a ServerInit.

pub use remote_core::*;

use serde::{Deserialize, Serialize};

/// The RFB wire pixel format (RFB §7.4).
///
/// Defined in `remote-pixel` because every conversion routine takes one and
/// that crate has no dependencies, so it cannot reach back here
/// (PRDRDP/02 §13 commit 1b). Re-exported at its old path.
pub use remote_pixel::PixelFormat;

// ---------------------------------------------------------------------------
// Encodings (PRD/02 §2, §3)
// ---------------------------------------------------------------------------

pub mod encoding {
    pub const RAW: i32 = 0;
    pub const COPY_RECT: i32 = 1;
    pub const RRE: i32 = 2;
    pub const CORRE: i32 = 4;
    pub const HEXTILE: i32 = 5;
    pub const ZLIB: i32 = 6;
    pub const TIGHT: i32 = 7;
    pub const ZLIBHEX: i32 = 8;
    pub const TRLE: i32 = 15;
    pub const ZRLE: i32 = 16;
    pub const ZYWRLE: i32 = 17;
    pub const JPEG: i32 = 21;
    pub const OPEN_H264: i32 = 50;
    pub const TIGHT_PNG: i32 = -260;

    // pseudo-encodings
    pub const PSEUDO_CURSOR: i32 = -239;
    pub const PSEUDO_X_CURSOR: i32 = -240;
    pub const PSEUDO_CURSOR_WITH_ALPHA: i32 = -314;
    pub const PSEUDO_DESKTOP_SIZE: i32 = -223;
    pub const PSEUDO_EXTENDED_DESKTOP_SIZE: i32 = -308;
    pub const PSEUDO_DESKTOP_NAME: i32 = -307;
    pub const PSEUDO_LAST_RECT: i32 = -224;
    pub const PSEUDO_FENCE: i32 = -312;
    pub const PSEUDO_CONTINUOUS_UPDATES: i32 = -313;
    pub const PSEUDO_EXTENDED_MOUSE_BUTTONS: i32 = -316;
    pub const PSEUDO_TIGHT_WITHOUT_ZLIB: i32 = -317;
    pub const PSEUDO_QEMU_POINTER_MOTION: i32 = -257;
    pub const PSEUDO_QEMU_EXT_KEY_EVENT: i32 = -258;
    pub const PSEUDO_QEMU_LED_STATE: i32 = -261;
    pub const PSEUDO_EXTENDED_CLIPBOARD: i32 = 0xc0a1_e5ce_u32 as i32;
    pub const PSEUDO_VMWARE_CURSOR: i32 = 0x574d_5664_u32 as i32;

    /// JPEG quality level pseudo-encodings, ASCENDING: -32 is level 0 (worst)
    /// and -23 is level 9 (best), per `rfbEncodingQualityLevel0..9`.
    ///
    /// These were inverted, which is not a cosmetic slip: asking for the BEST
    /// quality transmitted the encoding that means the WORST, so the "High"
    /// preset produced the most heavily compressed picture the server could
    /// make, and the "Low" preset produced a good one. Every judgement built
    /// on top, the Auto ladder included, was therefore backwards too.
    pub const fn jpeg_quality(level: u8) -> i32 {
        -32 + (level as i32)
    }
    /// Compression level pseudo-encodings, ASCENDING: -256 is level 0 and
    /// -247 is level 9, per `rfbEncodingCompressLevel0..9`. Inverted for the
    /// same reason as [`jpeg_quality`], so "less compression effort" asked the
    /// server for more.
    pub const fn compression_level(level: u8) -> i32 {
        -256 + (level as i32)
    }
}

// ---------------------------------------------------------------------------
// Security types (PRD/10 §1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityType {
    None,
    VncAuth,
    Tight,
    VeNCrypt,
    Ra2,
    Ra2ne,
    Ra2_256,
    Ra2ne256,
    AppleDh,
    MsLogonII,
    Unknown(u8),
}

impl SecurityType {
    pub fn from_wire(v: u8) -> Self {
        match v {
            1 => Self::None,
            2 => Self::VncAuth,
            5 => Self::Ra2,
            6 => Self::Ra2ne,
            16 => Self::Tight,
            19 => Self::VeNCrypt,
            30 => Self::AppleDh,
            113 => Self::MsLogonII,
            129 => Self::Ra2_256,
            130 => Self::Ra2ne256,
            other => Self::Unknown(other),
        }
    }

    pub fn to_wire(self) -> u8 {
        match self {
            Self::None => 1,
            Self::VncAuth => 2,
            Self::Ra2 => 5,
            Self::Ra2ne => 6,
            Self::Tight => 16,
            Self::VeNCrypt => 19,
            Self::AppleDh => 30,
            Self::MsLogonII => 113,
            Self::Ra2_256 => 129,
            Self::Ra2ne256 => 130,
            Self::Unknown(v) => v,
        }
    }

    /// Preference rank, higher = stronger. Drives automatic selection
    /// (PRD/10 §2). VeNCrypt is ranked by its negotiated subtype elsewhere.
    pub fn strength(self) -> u8 {
        match self {
            Self::VeNCrypt => 90,
            Self::Ra2_256 | Self::Ra2ne256 => 80,
            Self::Ra2 | Self::Ra2ne => 70,
            Self::AppleDh => 40,
            Self::MsLogonII => 30,
            Self::VncAuth => 20,
            // Ranked BELOW VncAuth deliberately. Tight (16) is a wrapper whose
            // inner auth, for the types we implement, resolves to VncAuth
            // anyway, so when a server offers both `[2, 16]` (the TightVNC /
            // TigerVNC family default) picking Tight buys no extra security and
            // adds the tunnel + capability negotiation and the extended
            // ServerInit as failure surface. We still implement Tight in full
            // for servers that offer *only* it.
            Self::Tight => 18,
            Self::None => 0,
            Self::Unknown(_) => 0,
        }
    }

    /// Whether the *session* (not just auth) is encrypted.
    pub fn encrypts_session(self) -> bool {
        matches!(self, Self::VeNCrypt | Self::Ra2 | Self::Ra2_256)
    }

    /// Legacy DES auth truncates the password to 8 characters (PRD/10 §3.4).
    pub fn truncates_password(self) -> bool {
        matches!(self, Self::VncAuth | Self::MsLogonII)
    }

    /// Parse a stored `security_pref` spelling into a pinned type.
    ///
    /// These are the host editor's "Security type" values (see
    /// `ui/src/components/HostDialog.tsx` and the `security_pref` column).
    /// `None` means Auto: negotiate the strongest type the server offers.
    ///
    /// This lived in the shell (`src-tauri/src/commands/session.rs:55`) until
    /// `VncOptions::security_pref` became a string, which is what the column
    /// always held (PRDRDP/02 §5.3).
    pub fn parse_pref(pref: Option<&str>) -> Option<Self> {
        match pref?.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "vncauth" => Some(Self::VncAuth),
            "tight" => Some(Self::Tight),
            "vencrypt" | "vencrypt-x509" => Some(Self::VeNCrypt),
            "ra2" => Some(Self::Ra2),
            // Not a spelling the host editor writes; the RA2 variants past
            // the first were only reachable by building the enum by hand,
            // which `crates/vnc-core/examples/live_quality.rs:55` did.
            "ra2-256" => Some(Self::Ra2_256),
            "apple-dh" => Some(Self::AppleDh),
            "ms-logon" | "mslogon" => Some(Self::MsLogonII),
            // "auto", and anything a newer build wrote that this one
            // predates: negotiate rather than guess at what was meant.
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Quality presets (PRD/09)
// ---------------------------------------------------------------------------

/// Concrete protocol knobs a preset resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualitySettings {
    pub jpeg_quality: u8, // 0..=9
    pub compression: u8,  // 0..=9
    pub pixel_format: ColorDepth,
    pub allow_jpeg: bool,
    pub allow_h264: bool,
    /// Client-side shader conversion when the server can't reduce colour.
    pub grayscale_levels: Option<u8>, // None | Some(256|16|8|4|2|1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ColorDepth {
    Full, // 24-bit true colour
    Palette256,
    Rgb222, // 64 colours
    Rgb111, // 8 colours
    Grayscale,
}

// ---------------------------------------------------------------------------
// Server capabilities discovered during handshake
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ServerCapabilities {
    pub protocol_version: String,
    pub desktop_name: String,
    pub width: u16,
    pub height: u16,
    pub pixel_format: Option<PixelFormat>,
    pub security_type: Option<SecurityType>,
    pub supports_continuous_updates: bool,
    pub supports_fence: bool,
    pub supports_extended_desktop_size: bool,
    pub supports_extended_clipboard: bool,
    pub supports_qemu_ext_key: bool,
    pub supports_extended_mouse_buttons: bool,
    pub supports_h264: bool,
    /// True when the banner was `RFB 003.889` (macOS Screen Sharing).
    pub is_apple_screen_sharing: bool,
}

impl ServerCapabilities {
    /// Remote resize is only offered when the server proved support by sending
    /// an ExtendedDesktopSize rectangle (PRD/05 §4).
    pub fn supports_remote_resize(&self) -> bool {
        self.supports_extended_desktop_size
    }
}

#[cfg(test)]
mod pseudo_encoding_level_tests {
    use super::encoding::{compression_level, jpeg_quality};

    /// REGRESSION, and the most expensive bug in this file's history: these
    /// two ladders were inverted, so "High quality" transmitted the encoding
    /// meaning "worst quality" and the picture got worse the better you asked
    /// for. Pinned against the literal `rfbproto.h` constants rather than a
    /// formula, because a formula is exactly what was wrong.
    #[test]
    fn quality_and_compression_levels_match_the_wire_constants() {
        // rfbEncodingQualityLevel0..9
        assert_eq!(jpeg_quality(0), -32, "level 0 is the WORST quality");
        assert_eq!(jpeg_quality(9), -23, "level 9 is the BEST quality");
        // rfbEncodingCompressLevel0..9
        assert_eq!(compression_level(0), -256);
        assert_eq!(compression_level(9), -247);

        // Both ladders ascend with the level; a descending one is the bug.
        for n in 0..9u8 {
            assert!(jpeg_quality(n) < jpeg_quality(n + 1));
            assert!(compression_level(n) < compression_level(n + 1));
        }
        // And they must never collide with each other's range.
        for n in 0..=9u8 {
            assert!((-32..=-23).contains(&jpeg_quality(n)));
            assert!((-256..=-247).contains(&compression_level(n)));
        }
    }
}
