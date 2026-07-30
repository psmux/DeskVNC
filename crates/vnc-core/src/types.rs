//! Shared contract types for the VNC core.
//!
//! This module is the integration contract between every other module and the
//! Tauri shell. Treat changes here as API changes.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl Rect {
    pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
    pub fn area(&self) -> usize {
        self.width as usize * self.height as usize
    }
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
    /// Smallest rectangle covering both.
    pub fn union(&self, other: &Rect) -> Rect {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        let x0 = self.x.min(other.x);
        let y0 = self.y.min(other.y);
        let x1 = (self.x + self.width).max(other.x + other.width);
        let y1 = (self.y + self.height).max(other.y + other.height);
        Rect::new(x0, y0, x1 - x0, y1 - y0)
    }
}

// ---------------------------------------------------------------------------
// Pixel format (RFB §7.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    /// 32bpp true colour, little endian, BGRA byte order in memory, our
    /// canonical local format (matches what the WebGL renderer expects after
    /// conversion to RGBA).
    pub const fn bgra8888() -> Self {
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }

    /// 8-bit palette (256 colours), used by the Low quality preset.
    pub const fn palette8() -> Self {
        Self {
            bits_per_pixel: 8,
            depth: 8,
            big_endian: false,
            true_colour: false,
            red_max: 0,
            green_max: 0,
            blue_max: 0,
            red_shift: 0,
            green_shift: 0,
            blue_shift: 0,
        }
    }

    /// rgb222-64 colours.
    pub const fn rgb222() -> Self {
        Self {
            bits_per_pixel: 8,
            depth: 6,
            big_endian: false,
            true_colour: true,
            red_max: 3,
            green_max: 3,
            blue_max: 3,
            red_shift: 4,
            green_shift: 2,
            blue_shift: 0,
        }
    }

    pub fn bytes_per_pixel(&self) -> usize {
        (self.bits_per_pixel as usize) / 8
    }

    /// True when Tight/ZRLE may use the compact 3-byte CPIXEL/TPIXEL form.
    pub fn is_compact_3byte(&self) -> bool {
        self.bits_per_pixel == 32
            && self.depth == 24
            && self.red_max == 255
            && self.green_max == 255
            && self.blue_max == 255
    }
}

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

    /// JPEG quality level pseudo-encodings: -23 (q0) .. -32 (q9).
    pub const fn jpeg_quality(level: u8) -> i32 {
        -23 - (level as i32)
    }
    /// Compression level pseudo-encodings: -247 (c0) .. -256 (c9).
    pub const fn compression_level(level: u8) -> i32 {
        -247 - (level as i32)
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
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Credentials {
    pub fn password(pw: impl Into<String>) -> Self {
        Self {
            username: None,
            password: Some(pw.into()),
        }
    }
    pub fn user_pass(user: impl Into<String>, pw: impl Into<String>) -> Self {
        Self {
            username: Some(user.into()),
            password: Some(pw.into()),
        }
    }
}

// Never leak secrets into logs.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username.as_deref().map(|_| "***"))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Quality presets (PRD/09)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum QualityPreset {
    #[default]
    Auto,
    High,
    Medium,
    Low,
    BlackAndWhite,
}

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

impl QualityPreset {
    pub fn settings(self) -> QualitySettings {
        match self {
            // Auto starts at Medium and adapts (see quality::AutoTuner).
            QualityPreset::Auto | QualityPreset::Medium => QualitySettings {
                jpeg_quality: 6,
                compression: 3,
                pixel_format: ColorDepth::Full,
                allow_jpeg: true,
                allow_h264: true,
                grayscale_levels: None,
            },
            QualityPreset::High => QualitySettings {
                jpeg_quality: 9,
                compression: 1,
                pixel_format: ColorDepth::Full,
                allow_jpeg: true,
                allow_h264: false,
                grayscale_levels: None,
            },
            QualityPreset::Low => QualitySettings {
                jpeg_quality: 2,
                compression: 7,
                pixel_format: ColorDepth::Palette256,
                allow_jpeg: true,
                allow_h264: true,
                grayscale_levels: None,
            },
            QualityPreset::BlackAndWhite => QualitySettings {
                jpeg_quality: 0,
                compression: 9,
                pixel_format: ColorDepth::Grayscale,
                allow_jpeg: false, // palette/RLE compresses grayscale far better
                allow_h264: false,
                grayscale_levels: Some(2),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Trust-on-first-use pins
// ---------------------------------------------------------------------------

/// Which server key a trust-on-first-use pin describes.
///
/// Two handshakes authenticate a server identity, and they authenticate
/// *different keys*:
///
/// * [`PinScheme::Tls`], VeNCrypt's TLS upgrade, SHA-256 over the X.509
///   certificate's SubjectPublicKeyInfo.
/// * [`PinScheme::Ra2`], RealVNC RSA-AES, SHA-256 over the server's RSA
///   public key in canonical DER SPKI form.
///
/// A server can offer both (wayvnc does). Their fingerprints are unrelated, so
/// pins must be stored and compared per scheme: matching a TLS pin against an
/// RA2 key would report a changed identity for a server that changed nothing, /// the worst kind of false alarm, because it teaches the user to click through
/// the real one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PinScheme {
    /// TLS / VeNCrypt X.509 certificate SPKI.
    Tls,
    /// RealVNC RSA-AES (RA2 / RA2ne / RA2_256 / RA2ne_256) server RSA key.
    Ra2,
}

impl PinScheme {
    /// Every scheme, for callers that must handle all of them (loading pins
    /// before a security type is negotiated, forgetting an endpoint).
    pub const ALL: [PinScheme; 2] = [PinScheme::Tls, PinScheme::Ra2];

    /// The wire/database spelling. Matches the serde representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            PinScheme::Tls => "tls",
            PinScheme::Ra2 => "ra2",
        }
    }

    /// Parses a stored spelling. `None` for anything unrecognised, a pin row
    /// written by a newer build is ignored, never guessed at.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tls" => Some(PinScheme::Tls),
            "ra2" => Some(PinScheme::Ra2),
            _ => None,
        }
    }
}

impl std::fmt::Display for PinScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The pins available for one endpoint, one per [`PinScheme`].
///
/// At connect time the security type has not been negotiated yet, so whichever
/// handshake runs must be able to find its own pin. Carrying only one would
/// mean either prompting for a key already trusted or, worse, comparing a pin
/// against a key it does not describe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertPins {
    /// SHA-256 SPKI of the pinned X.509 certificate (hex).
    pub tls: Option<String>,
    /// SHA-256 SPKI of the pinned RA2 server RSA key (hex).
    pub ra2: Option<String>,
}

impl CertPins {
    /// The pin a given handshake should verify against, and only that one.
    pub fn for_scheme(&self, scheme: PinScheme) -> Option<&str> {
        match scheme {
            PinScheme::Tls => self.tls.as_deref(),
            PinScheme::Ra2 => self.ra2.as_deref(),
        }
    }

    pub fn set(&mut self, scheme: PinScheme, pin: Option<String>) {
        match scheme {
            PinScheme::Tls => self.tls = pin,
            PinScheme::Ra2 => self.ra2 = pin,
        }
    }

    /// Convenience for a single known pin (tests, probes).
    pub fn one(scheme: PinScheme, pin: impl Into<String>) -> Self {
        let mut pins = Self::default();
        pins.set(scheme, Some(pin.into()));
        pins
    }

    pub fn is_empty(&self) -> bool {
        self.tls.is_none() && self.ra2.is_none()
    }
}

// ---------------------------------------------------------------------------
// Connection options
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub credentials: Credentials,
    /// None = automatic strongest-first selection.
    pub security_pref: Option<SecurityType>,
    pub quality: QualityPreset,
    pub view_only: bool,
    /// Sharpen lossily-painted regions once motion stops (PRD/09 §3.2).
    pub lossless_refresh: bool,
    pub shared: bool,
    /// Allow security types that leave the session in cleartext.
    pub allow_insecure: bool,
    /// Pinned SHA-256 SPKI fingerprints for TOFU (hex), one per scheme.
    pub cert_pins: CertPins,
    pub connect_timeout: std::time::Duration,
    /// Auto-reconnect policy (PRD/05 §6).
    pub reconnect: ReconnectPolicy,
}

impl ConnectOptions {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            credentials: Credentials::default(),
            security_pref: None,
            quality: QualityPreset::Auto,
            view_only: false,
            lossless_refresh: true,
            shared: true,
            allow_insecure: false,
            cert_pins: CertPins::default(),
            connect_timeout: std::time::Duration::from_secs(15),
            reconnect: ReconnectPolicy::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Reconnect policy (PRD/05 §6.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReconnectPolicy {
    pub enabled: bool,
    /// None = retry forever while the session window is open.
    pub max_attempts: Option<u32>,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub multiplier: f64,
    /// Jitter fraction (0.0..=1.0) applied to each delay.
    pub jitter: f64,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        // 250ms -> 500 -> 1s -> 2s -> 4s -> 8s -> capped 15s, ±20% jitter.
        Self {
            enabled: true,
            max_attempts: None,
            initial_delay_ms: 250,
            max_delay_ms: 15_000,
            multiplier: 2.0,
            jitter: 0.2,
        }
    }
}

impl ReconnectPolicy {
    /// Delay before attempt `attempt` (1-based), with jitter applied.
    pub fn delay_for(&self, attempt: u32, rand_unit: f64) -> std::time::Duration {
        let base =
            (self.initial_delay_ms as f64) * self.multiplier.powi(attempt.saturating_sub(1) as i32);
        let capped = base.min(self.max_delay_ms as f64);
        let jitter_span = capped * self.jitter;
        // rand_unit in [0,1) -> symmetric jitter around `capped`
        let jittered = capped - jitter_span + (2.0 * jitter_span * rand_unit);
        std::time::Duration::from_millis(jittered.max(0.0) as u64)
    }
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum SessionState {
    Idle,
    Resolving,
    Connecting,
    Authenticating {
        method: String,
    },
    Negotiating,
    Connected,
    /// Auto-reconnect in progress (PRD/05 §6.3).
    Reconnecting {
        attempt: u32,
        next_retry_ms: u64,
        reason: String,
    },
    Disconnected {
        reason: String,
        can_retry: bool,
    },
}

// ---------------------------------------------------------------------------
// Events emitted by a session to the shell/UI
// ---------------------------------------------------------------------------

/// A decoded rectangle ready for the renderer.
#[derive(Debug, Clone)]
pub struct DecodedRect {
    pub rect: Rect,
    pub payload: RectPayload,
}

#[derive(Debug, Clone)]
pub enum RectPayload {
    /// Tightly packed RGBA8888, `rect.width * rect.height * 4` bytes.
    Rgba(Vec<u8>),
    /// Compressed image the webview can decode via `createImageBitmap`.
    Jpeg(Vec<u8>),
    /// Copy from elsewhere in the framebuffer.
    CopyRect { src_x: u16, src_y: u16 },
    /// H.264 Annex-B data for the webview's `VideoDecoder` (PRD/02 §2.3).
    ///
    /// `data` may be empty, a zero-length payload is a pure control message
    /// (apply `flags`, decode nothing).
    H264 {
        data: Vec<u8>,
        /// Server flags, verbatim: bit0 `ResetContext`, bit1 `ResetAllContexts`.
        flags: u32,
        /// Decoder context this rectangle belongs to (`0..64`). Contexts are
        /// keyed by rect geometry and LRU-evicted, so a slot can be recycled, /// always with `reset` set.
        context_id: u32,
        /// The context is new/reset/still waiting for its first IDR: the
        /// frontend must rebuild the decoder for `context_id` before decoding.
        reset: bool,
        /// `data` contains an IDR access unit, so it can start a decoder.
        keyframe: bool,
    },
}

#[derive(Debug, Clone)]
pub struct CursorShape {
    pub width: u16,
    pub height: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    /// RGBA8888.
    pub pixels: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    StateChanged(SessionState),
    /// A coalesced framebuffer update. The renderer presents once per event.
    FramebufferUpdate {
        rects: Vec<DecodedRect>,
        damage: Rect,
    },
    DesktopResize {
        width: u16,
        height: u16,
    },
    DesktopName(String),
    CursorUpdate(CursorShape),
    CursorPosition {
        x: u16,
        y: u16,
    },
    ClipboardText(String),
    /// Extended clipboard notify: peer has data available in these formats.
    ClipboardNotify {
        formats: u32,
    },
    Bell,
    /// Server key awaiting trust-on-first-use approval.
    ///
    /// `scheme` says which key the fingerprint belongs to. The answer must
    /// carry it back unchanged ([`ClientCommand::TrustCertificate`]) so the pin
    /// is stored against the key the user actually looked at.
    CertificatePrompt {
        fingerprint: String,
        subject: String,
        is_change: bool,
        scheme: PinScheme,
    },
    /// The handshake needs credentials from the user. The session is PAUSED
    /// mid-authentication until `ProvideCredentials` or `CancelCredentials`
    /// arrives, it must not fail the connection instead of asking.
    CredentialsRequired(CredentialRequest),
    Stats(SessionStats),
    Error(String),
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SessionStats {
    pub rtt_ms: f32,
    pub throughput_bps: f64,
    /// TX bits/sec over the last stats tick, the upload mirror of
    /// `throughput_bps`.
    pub throughput_up_bps: f64,
    pub fps: f32,
    pub decode_ms: f32,
    pub bytes_received: u64,
    /// Cumulative bytes written to the transport (plaintext side, same layer
    /// as `bytes_received`).
    pub bytes_sent: u64,
    pub rects_decoded: u64,
    pub current_encoding: i32,
    pub jpeg_quality: u8,
}

// ---------------------------------------------------------------------------
// Commands sent into a session
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ClientCommand {
    Pointer {
        x: u16,
        y: u16,
        button_mask: u16,
    },
    Key {
        keysym: u32,
        keycode: Option<u32>,
        down: bool,
    },
    /// Release every key we believe is pressed (blur / disconnect safety).
    ReleaseAllKeys,
    ClipboardText(String),
    ClipboardRequest {
        formats: u32,
    },
    SetQuality(QualityPreset),
    RequestResize {
        width: u16,
        height: u16,
    },
    /// Force a full non-incremental update.
    Refresh,
    SetViewOnly(bool),
    /// User accepted a server key at the TOFU prompt. `scheme` is echoed back
    /// from the prompt that raised it, never inferred here.
    TrustCertificate {
        fingerprint: String,
        permanent: bool,
        scheme: PinScheme,
    },
    /// User answered a [`SessionEvent::CredentialsRequired`] prompt.
    ///
    /// `save` is the "remember these credentials" checkbox. The core never
    /// touches the keychain, the shell persists them only after the session
    /// actually reaches `Connected`, so a rejected password is never stored.
    ProvideCredentials {
        username: Option<String>,
        password: String,
        save: bool,
    },
    /// User dismissed the credentials prompt, abandon the connection attempt.
    CancelCredentials,
    /// Reset backoff and retry immediately (network came back / user clicked).
    ReconnectNow,
    Disconnect,
}

/// What a security type needs from the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    /// Classic VNC Authentication, VeNCrypt `*Vnc` subtypes, RA2 subtype 2.
    PasswordOnly,
    /// VeNCrypt `*Plain`, Apple DH (30), MSLogonII (113), RA2 subtype 1.
    UsernameAndPassword,
}

/// A pending interactive credential request raised from inside the security
/// handshake (PRD/10 §3.4).
///
/// The session emits [`SessionEvent::CredentialsRequired`] carrying this, then
/// waits for [`ClientCommand::ProvideCredentials`] or
/// [`ClientCommand::CancelCredentials`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    /// Human-readable method name, e.g. "VNC Authentication",
    /// "VeNCrypt (X509Plain)", "Apple Remote Desktop".
    pub method: String,
    pub kind: CredentialKind,
    /// 1-based. Greater than 1 means a previous attempt was rejected.
    pub attempt: u32,
    /// Why the previous attempt failed, when there was one.
    pub error: Option<String>,
    /// True for DES-based methods, which silently truncate to 8 characters.
    /// The UI must warn (PRD/10 §3.4).
    pub truncates_password: bool,
    /// Prefill for the username field (saved profile value, or the OS user).
    pub username_hint: Option<String>,
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
mod pin_tests {
    use super::*;

    /// The wire spelling is a stored value: the DB, the IPC payload and the
    /// serde representation must all agree, or a pin written by one layer is
    /// invisible to another.
    #[test]
    fn scheme_spelling_is_stable() {
        for scheme in PinScheme::ALL {
            let json = serde_json::to_string(&scheme).unwrap();
            assert_eq!(json, format!("\"{}\"", scheme.as_str()));
            assert_eq!(PinScheme::parse(scheme.as_str()), Some(scheme));
            assert_eq!(
                serde_json::from_str::<PinScheme>(&json).unwrap(),
                scheme,
                "round trip"
            );
        }
        assert_eq!(PinScheme::parse("TLS"), Some(PinScheme::Tls));
        assert_eq!(PinScheme::parse(" ra2 "), Some(PinScheme::Ra2));
    }

    /// Anything unrecognised is ignored, never mapped onto a known scheme, /// a pin applied to the wrong key is worse than no pin at all.
    #[test]
    fn an_unknown_scheme_does_not_degrade_into_a_known_one() {
        for junk in ["", "ssh", "ra", "tls2", "quantum-kem"] {
            assert_eq!(PinScheme::parse(junk), None, "{junk:?}");
        }
    }

    /// The core of the fix: one endpoint, two unrelated keys. Each handshake
    /// sees only the pin for the key it is actually verifying.
    #[test]
    fn a_pin_is_only_visible_to_its_own_scheme() {
        let mut pins = CertPins::default();
        assert!(pins.is_empty());
        assert_eq!(pins.for_scheme(PinScheme::Tls), None);

        pins.set(PinScheme::Tls, Some("aa".repeat(32)));
        assert_eq!(pins.for_scheme(PinScheme::Tls).unwrap(), "aa".repeat(32));
        assert_eq!(
            pins.for_scheme(PinScheme::Ra2),
            None,
            "a TLS pin must not be offered to the RA2 handshake"
        );

        pins.set(PinScheme::Ra2, Some("bb".repeat(32)));
        assert_eq!(pins.for_scheme(PinScheme::Tls).unwrap(), "aa".repeat(32));
        assert_eq!(pins.for_scheme(PinScheme::Ra2).unwrap(), "bb".repeat(32));

        pins.set(PinScheme::Tls, None);
        assert_eq!(pins.for_scheme(PinScheme::Tls), None);
        assert_eq!(
            pins.for_scheme(PinScheme::Ra2).unwrap(),
            "bb".repeat(32),
            "forgetting one scheme must not disturb the other"
        );
    }

    #[test]
    fn connect_options_start_with_no_pins() {
        assert!(ConnectOptions::new("h", 5900).cert_pins.is_empty());
        let one = CertPins::one(PinScheme::Ra2, "cc");
        assert_eq!(one.for_scheme(PinScheme::Ra2), Some("cc"));
        assert_eq!(one.for_scheme(PinScheme::Tls), None);
    }
}
