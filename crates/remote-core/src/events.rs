//! Events a session emits to the shell.
//!
//! Moved out of `vnc-core/src/types.rs` (PRDRDP/02 §2.1). One type is new:
//! `ScreenInfo` replaces `vnc_core::proto::messages::Screen` in the
//! `ScreenLayout` payload, because `SessionEvent` cannot move while it names
//! an RFB wire type (PRDRDP/02 §2.2.2).
//!
//! `SessionEvent` deliberately does not derive `Serialize`. The shell hand
//! writes the JSON in `event_json` (`src-tauri/src/commands/session.rs:85`)
//! with an exhaustive match, so a new variant is a compile error where
//! someone has to decide what the UI sees.

use crate::credentials::CredentialRequest;
use crate::geometry::Rect;
use crate::pins::PinScheme;
use crate::state::SessionState;
use crate::stats::SessionStats;

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
        /// Server flags, verbatim. RFB's Open H.264 encoding gives bit0 as
        /// `ResetContext` and bit1 as `ResetAllContexts`; a protocol that
        /// numbers them differently maps onto the same two meanings.
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

/// One monitor of a multi head remote desktop, in framebuffer coordinates.
///
/// Replaces `vnc_core::proto::messages::Screen` in the `ScreenLayout` payload.
/// `vnc_core::proto::messages` keeps `Screen` as an alias of this type and
/// encodes it with a free function, so the RFB SetDesktopSize wire format is
/// unchanged (PRDRDP/02 §2.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenInfo {
    pub id: u32,
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    /// Protocol defined. RFB assigns no meaning to it yet (RFB
    /// ExtendedDesktopSize); the shell already drops it before it reaches the
    /// webview (`src-tauri/src/commands/session.rs:96`).
    pub flags: u32,
    /// True for the monitor the remote desktop treats as primary. RFB never
    /// says, so the VNC path leaves this false for every screen. RDP does say:
    /// TS_MONITOR_PRIMARY (0x1) in TS_UD_CS_MONITOR, MS-RDPBCGR 2.2.1.3.6.
    pub primary: bool,
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
    /// The server's monitor layout, from an ExtendedDesktopSize rectangle.
    /// Emitted whenever the advertised screen list changes, so the UI can
    /// offer per-monitor views of a multi-head desktop. Servers without
    /// ExtendedDesktopSize never produce one; the UI treats the whole
    /// framebuffer as a single display.
    ScreenLayout {
        screens: Vec<ScreenInfo>,
    },
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
    /// Decoded audio for playback. Protocol neutral by shape: an RDP driver
    /// fills it from MS-RDPEA, and a future VNC audio extension could too.
    ///
    /// Nothing produces one yet. The variant exists in phase 0 so the shell's
    /// `event_json` match already has a place to decide from (PRDRDP/02 §9.2).
    Audio(AudioPacket),
    /// Protocol specific news the UI may want to show.
    Protocol(ProtocolEvent),
}

/// A block of decoded PCM, ready for playback.
///
/// Decoding whatever the server sent happens inside the protocol crate, so
/// the shell and the webview only ever see PCM. That is the rule the bitmap
/// path already follows.
#[derive(Debug, Clone)]
pub struct AudioPacket {
    /// Interleaved PCM, native endian, `channels` samples per frame.
    pub pcm: Vec<i16>,
    pub sample_rate: u32,
    pub channels: u8,
    /// Server timestamp for lip sync, milliseconds, protocol relative.
    pub timestamp_ms: u32,
}

/// Protocol specific news. One arm per protocol; the payload types are
/// defined here, in terms of plain Rust primitives, so no protocol crate's
/// types reach the shell (PRDRDP/02 §9.4).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProtocolEvent {
    Rdp(RdpEvent),
    Ssh(SshEvent),
}

/// News from a remote shell.
///
/// The byte-carrying variants use [`bytes::Bytes`] rather than `Vec<u8>`
/// deliberately. PTY output arrives as many small reads, and this event
/// travels channel to channel to the webview encoder; `Bytes` is refcounted,
/// so each hop is a pointer bump rather than a memcpy of the payload. On a
/// fast-scrolling build log that is the difference between a terminal that
/// keeps up and one that falls behind its own output.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SshEvent {
    /// Bytes from the remote PTY, in order. Already coalesced by the session,
    /// so one of these is a batch rather than a single read.
    Output(bytes::Bytes),

    /// Bytes the *client* must write to its own terminal to undo whatever
    /// private modes a dead session left switched on.
    ///
    /// Deliberately not [`SshEvent::Output`]. This is the app's own
    /// correction, not something the server said, so a UI that logs or
    /// replays output must be able to tell them apart. Without it, a session
    /// cut while tmux had mouse reporting on leaves the terminal spraying
    /// escape sequences at the prompt on every mouse move, which is the most
    /// common complaint about running ssh in a window.
    ResetTerminal(bytes::Bytes),

    /// The shell is up. `multiplexer` is `None` for a plain login shell,
    /// either by choice or because the host had none. `resumed` is true only
    /// when the attach found a session that was **already running**, which is
    /// the case where the user's work survived a drop, and it must never be
    /// guessed.
    Attached {
        multiplexer: Option<crate::options::MultiplexerKind>,
        resumed: bool,
    },

    /// A line for the UI's status area, never for the terminal itself.
    Notice(String),
}

/// News from an RDP session. Nothing produces one before phase 1.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RdpEvent {
    /// The server told us who is logged on. MS-RDPBCGR 2.2.10.1 Server Save
    /// Session Info PDU, TS_LOGON_INFO (2.2.10.1.1.1) or
    /// TS_LOGON_INFO_VERSION_2 (2.2.10.1.1.2).
    ///
    /// Both strings are SERVER SUPPLIED. Render as text, never as HTML.
    LogonInfo {
        domain: String,
        username: String,
        /// Terminal Services session id on the server.
        session_id: u32,
    },

    /// The logon failed or needs attention. MS-RDPBCGR 2.2.10.1.1.5
    /// TS_LOGON_ERRORS_INFO. Both numbers are the raw wire values; the driver
    /// supplies `message` as the human sentence it derived from them, so the
    /// UI never has to own a code table.
    LogonError {
        notification_type: u32,
        notification_data: u32,
        message: String,
    },

    /// The session hit a server side error and is about to end. MS-RDPBCGR
    /// 2.2.5.1.1 Set Error Info PDU, the ERRINFO_* space.
    ///
    /// `symbol` is the specification's constant name
    /// ("ERRINFO_LOGOFF_BY_USER") when the driver recognises the code, and an
    /// empty string when it does not. `code` is always the raw value, so an
    /// unrecognised code is still reportable in a bug.
    ErrorInfo {
        code: u32,
        symbol: String,
        message: String,
    },

    /// The server asked us to reconnect somewhere else. MS-RDPBCGR 2.2.13.1
    /// Server Redirection Packet.
    ///
    /// Informational only: the driver performs the redirect itself and the
    /// session continues, so the UI shows this as a note, not as an action.
    /// The routing token and the redirection password are NEVER in here.
    Redirected { target: String, session_id: u32 },

    /// A fresh auto reconnect cookie arrived and was held in memory for the
    /// next attempt. MS-RDPBCGR 2.2.4.2 ARC_SC_PRIVATE_PACKET carries it;
    /// 2.2.4.3 ARC_CS_PRIVATE_PACKET is what goes back on the next attempt.
    ///
    /// Deliberately carries no payload. The cookie is a bearer secret; the
    /// UI's only legitimate interest is "a fast reconnect is now possible".
    AutoReconnectArmed,

    /// The server issued a licensing warning we chose to continue past.
    /// MS-RDPBCGR 2.2.1.13.1 Server License Error PDU.
    LicenseWarning { message: String },
}
