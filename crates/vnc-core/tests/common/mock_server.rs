//! A configurable in-process RFB 3.x server for end-to-end tests.
//!
//! It speaks the real wire protocol over a real TCP socket bound to
//! `127.0.0.1:0`, so the client under test exercises `vnc-transport`,
//! `proto::version`, `security`, `encodings` and `session` exactly as it would
//! against TigerVNC or macOS Screen Sharing.
//!
//! Everything the client sends is recorded (see [`Recorded`]) so tests can make
//! byte-level assertions, and the server can be told to misbehave in the
//! specific ways the reconnect supervisor has to survive (abrupt close, silent
//! hang, refusing the first N connections).

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flate2::{Compress, Compression, FlushCompress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

use vnc_core::proto::messages::encode_pixel_format;
use vnc_core::types::{PixelFormat, Rect};

// ---------------------------------------------------------------------------
// Version banners
// ---------------------------------------------------------------------------

pub const RFB_33: [u8; 12] = *b"RFB 003.003\n";
pub const RFB_37: [u8; 12] = *b"RFB 003.007\n";
pub const RFB_38: [u8; 12] = *b"RFB 003.008\n";
/// macOS Screen Sharing / ARD.
pub const RFB_APPLE: [u8; 12] = *b"RFB 003.889\n";

pub const SEC_NONE: u8 = 1;
pub const SEC_VNC_AUTH: u8 = 2;
/// VeNCrypt (19). The mock only offers the `Plain` subtype (256), no TLS, /// which is enough to exercise a username+password credential prompt.
pub const SEC_VENCRYPT: u8 = 19;
const VENCRYPT_PLAIN: u32 = 256;

/// The effective RFB minor version a banner maps to, using the same rules the
/// client applies (`003.889` is Apple's 3.8).
fn effective_minor(banner: &[u8; 12]) -> u16 {
    let digits = &banner[8..11];
    let mut minor: u16 = 0;
    for &b in digits {
        minor = minor * 10 + (b - b'0') as u16;
    }
    match minor {
        889 => 8,
        m if m >= 8 => 8,
        7 => 7,
        _ => 3,
    }
}

// ---------------------------------------------------------------------------
// Pixels
// ---------------------------------------------------------------------------

/// A colour as the test author thinks of it: `[r, g, b]`.
pub type Rgb = [u8; 3];

/// One wire pixel in the client's negotiated format (bgra8888, little endian).
fn bgrx(c: Rgb) -> [u8; 4] {
    [c[2], c[1], c[0], 0]
}

/// A ZRLE/TRLE compact CPIXEL for bgra8888: the three colour bytes in wire
/// order, i.e. B, G, R.
fn cpixel(c: Rgb) -> [u8; 3] {
    [c[2], c[1], c[0]]
}

/// A Tight compact TPIXEL: literally R, G, B.
fn tpixel(c: Rgb) -> [u8; 3] {
    c
}

/// The RGBA8888 the decoder must produce for `c`.
pub fn expect_rgba(c: Rgb) -> [u8; 4] {
    [c[0], c[1], c[2], 255]
}

// ---------------------------------------------------------------------------
// Synthetic H.264 Annex-B data (PRD/02 §2.3)
// ---------------------------------------------------------------------------

/// `flags` bit 0, reset this rectangle's decoder context.
pub const H264_RESET_CONTEXT: u32 = 1 << 0;
/// `flags` bit 1, reset every decoder context on the connection.
pub const H264_RESET_ALL_CONTEXTS: u32 = 1 << 1;

/// One Annex-B NAL unit: start code, `header` byte, then `body`.
///
/// The header packs `forbidden_zero_bit(1) | nal_ref_idc(2) | nal_unit_type(5)`,
/// so `0x65` is a reference IDR slice (type 5) and `0x41` a non-IDR slice.
fn nal(start4: bool, header: u8, body: &[u8]) -> Vec<u8> {
    let mut v = if start4 {
        vec![0u8, 0, 0, 1]
    } else {
        vec![0u8, 0, 1]
    };
    v.push(header);
    v.extend_from_slice(body);
    v
}

/// A synthetic IDR access unit: SPS + PPS + IDR slice.
///
/// The bytes are not decodable video, they exist so the *framing* and
/// keyframe detection can be asserted byte-exactly without pulling in an
/// encoder. `tag` differentiates otherwise identical frames.
pub fn annexb_idr(tag: u8) -> Vec<u8> {
    let mut v = nal(true, 0x67, &[0x42, 0x00, 0x1e, tag]); // SPS (type 7)
    v.extend(nal(false, 0x68, &[0xce, 0x3c, 0x80])); // PPS (type 8)
    v.extend(nal(true, 0x65, &[0x88, 0x84, 0x00, tag])); // IDR slice (type 5)
    v
}

/// A synthetic non-IDR (delta) frame, a decoder cannot start on this.
pub fn annexb_delta(tag: u8) -> Vec<u8> {
    nal(false, 0x41, &[0x9a, 0x00, tag])
}

// ---------------------------------------------------------------------------
// Rectangle specifications
// ---------------------------------------------------------------------------

/// One rectangle the mock should put inside a FramebufferUpdate. Each variant
/// produces genuinely wire-correct data for the encoding it names.
#[derive(Debug, Clone)]
pub enum RectSpec {
    /// Raw (0), solid colour.
    Raw { rect: Rect, colour: Rgb },
    /// Raw (0) with an explicit pixel per position (row-major).
    RawPixels { rect: Rect, pixels: Vec<Rgb> },
    /// CopyRect (1).
    CopyRect { rect: Rect, src_x: u16, src_y: u16 },
    /// Hextile (5). `subrects` (x, y, w, h in tile coordinates) are only
    /// allowed when the rect fits in a single 16x16 tile; otherwise every tile
    /// is a plain background fill and the background is specified once so the
    /// "colours persist across tiles" rule is exercised.
    Hextile {
        rect: Rect,
        bg: Rgb,
        fg: Option<Rgb>,
        subrects: Vec<(u8, u8, u8, u8)>,
    },
    /// zlib (6): a Raw rect through the connection's persistent zlib stream.
    Zlib { rect: Rect, colour: Rgb },
    /// Tight (7) Fill: one TPIXEL for the whole rect.
    TightFill { rect: Rect, colour: Rgb },
    /// Tight (7) basic compression, palette filter, two colours, 1-bit packed.
    /// `rows[y]` holds the packed bits for row `y`, MSB first.
    TightPalette {
        rect: Rect,
        colour0: Rgb,
        colour1: Rgb,
        rows: Vec<Vec<u8>>,
    },
    /// Tight (7) basic compression, copy filter, through zlib stream 0.
    TightCompressed { rect: Rect, pixels: Vec<Rgb> },
    /// ZRLE (16): a solid tile per 64x64 tile.
    ZrleSolid { rect: Rect, colour: Rgb },
    /// ZRLE (16) packed-palette tile (2 colours, 1-bit indices). The rect must
    /// fit in a single 64x64 tile.
    ZrlePalette {
        rect: Rect,
        colour0: Rgb,
        colour1: Rgb,
        rows: Vec<Vec<u8>>,
    },
    /// Open H.264 (50): `U32 length + U32 flags + Annex-B data`.
    ///
    /// `data` goes on the wire verbatim, so tests can send a synthetic NAL
    /// sequence (see [`annexb_idr`] / [`annexb_delta`]) or nothing at all, an
    /// empty payload is the protocol's control message.
    H264 {
        rect: Rect,
        flags: u32,
        data: Vec<u8>,
    },
    /// ExtendedDesktopSize (-308).
    ExtendedDesktopSize {
        width: u16,
        height: u16,
        reason: u16,
        status: u16,
    },
    /// DesktopName (-307).
    DesktopName(String),
    /// RichCursor (-239), fully opaque, solid colour.
    RichCursor {
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
        colour: Rgb,
    },
    /// Fence capability ack (-312).
    FenceCapable,
    /// ContinuousUpdates capability ack (-313).
    ContinuousUpdatesCapable,
    /// QEMU Extended Key Event capability ack (-258).
    QemuExtKeyCapable,
    /// LastRect (-224).
    LastRect,
}

// ---------------------------------------------------------------------------
// Per-connection encoder state (persistent zlib streams, like a real server)
// ---------------------------------------------------------------------------

struct Encoders {
    zlib: Compress,
    zrle: Compress,
    tight: [Compress; 4],
}

impl Encoders {
    fn new() -> Self {
        let mk = || Compress::new(Compression::default(), true);
        Self {
            zlib: mk(),
            zrle: mk(),
            tight: [mk(), mk(), mk(), mk()],
        }
    }
}

fn deflate_sync(c: &mut Compress, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2 + 8192);
    let before = c.total_in();
    c.compress_vec(data, &mut out, FlushCompress::Sync)
        .expect("deflate must succeed");
    assert_eq!(
        (c.total_in() - before) as usize,
        data.len(),
        "compressor did not consume all input"
    );
    out
}

/// Tight's 1-3 byte compact length.
fn push_compact_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x4000 {
        out.push((n & 0x7f) as u8 | 0x80);
        out.push(((n >> 7) & 0x7f) as u8);
    } else {
        out.push((n & 0x7f) as u8 | 0x80);
        out.push(((n >> 7) & 0x7f) as u8 | 0x80);
        out.push(((n >> 14) & 0xff) as u8);
    }
}

fn rect_header(out: &mut Vec<u8>, x: u16, y: u16, w: u16, h: u16, enc: i32) {
    out.extend_from_slice(&x.to_be_bytes());
    out.extend_from_slice(&y.to_be_bytes());
    out.extend_from_slice(&w.to_be_bytes());
    out.extend_from_slice(&h.to_be_bytes());
    out.extend_from_slice(&enc.to_be_bytes());
}

/// Encode a complete FramebufferUpdate message (type byte included).
fn encode_update(enc: &mut Encoders, specs: &[RectSpec]) -> Vec<u8> {
    let mut out = vec![0u8, 0u8];
    // A trailing LastRect means the real server does not know the count up
    // front and uses the 0xffff sentinel.
    let count = if matches!(specs.last(), Some(RectSpec::LastRect)) {
        0xffffu16
    } else {
        specs.len() as u16
    };
    out.extend_from_slice(&count.to_be_bytes());
    for s in specs {
        encode_rect(enc, s, &mut out);
    }
    out
}

fn encode_rect(enc: &mut Encoders, spec: &RectSpec, out: &mut Vec<u8>) {
    match spec {
        RectSpec::Raw { rect, colour } => {
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 0);
            let px = bgrx(*colour);
            for _ in 0..rect.area() {
                out.extend_from_slice(&px);
            }
        }
        RectSpec::RawPixels { rect, pixels } => {
            assert_eq!(pixels.len(), rect.area(), "RawPixels pixel count");
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 0);
            for p in pixels {
                out.extend_from_slice(&bgrx(*p));
            }
        }
        RectSpec::CopyRect { rect, src_x, src_y } => {
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 1);
            out.extend_from_slice(&src_x.to_be_bytes());
            out.extend_from_slice(&src_y.to_be_bytes());
        }
        RectSpec::Hextile {
            rect,
            bg,
            fg,
            subrects,
        } => {
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 5);
            const BACKGROUND_SPECIFIED: u8 = 2;
            const FOREGROUND_SPECIFIED: u8 = 4;
            const ANY_SUBRECTS: u8 = 8;
            if !subrects.is_empty() {
                assert!(
                    rect.width <= 16 && rect.height <= 16,
                    "hextile subrects only supported for a single tile"
                );
                let fg = fg.expect("subrects need a foreground colour");
                out.push(BACKGROUND_SPECIFIED | FOREGROUND_SPECIFIED | ANY_SUBRECTS);
                out.extend_from_slice(&bgrx(*bg));
                out.extend_from_slice(&bgrx(fg));
                out.push(subrects.len() as u8);
                for (x, y, w, h) in subrects {
                    out.push((x << 4) | (y & 0x0f));
                    out.push(((w - 1) << 4) | ((h - 1) & 0x0f));
                }
            } else {
                let mut first = true;
                let mut ty = 0u16;
                while ty < rect.height {
                    let mut tx = 0u16;
                    while tx < rect.width {
                        if first {
                            out.push(BACKGROUND_SPECIFIED);
                            out.extend_from_slice(&bgrx(*bg));
                            first = false;
                        } else {
                            // Nothing specified: the background must persist.
                            out.push(0);
                        }
                        tx += 16;
                    }
                    ty += 16;
                }
            }
        }
        RectSpec::Zlib { rect, colour } => {
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 6);
            let px = bgrx(*colour);
            let mut raw = Vec::with_capacity(rect.area() * 4);
            for _ in 0..rect.area() {
                raw.extend_from_slice(&px);
            }
            let comp = deflate_sync(&mut enc.zlib, &raw);
            out.extend_from_slice(&(comp.len() as u32).to_be_bytes());
            out.extend_from_slice(&comp);
        }
        RectSpec::TightFill { rect, colour } => {
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 7);
            out.push(0x80); // Fill
            out.extend_from_slice(&tpixel(*colour));
        }
        RectSpec::TightPalette {
            rect,
            colour0,
            colour1,
            rows,
        } => {
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 7);
            let row_bytes = (rect.width as usize).div_ceil(8);
            assert_eq!(rows.len(), rect.height as usize, "one packed row per line");
            let mut data = Vec::with_capacity(row_bytes * rows.len());
            for r in rows {
                assert_eq!(r.len(), row_bytes, "packed row width");
                data.extend_from_slice(r);
            }
            out.push(0x40); // basic, stream 0, filter byte follows
            out.push(1); // FILTER_PALETTE
            out.push(1); // numColours - 1 == 1 -> two colours
            out.extend_from_slice(&tpixel(*colour0));
            out.extend_from_slice(&tpixel(*colour1));
            push_tight_body(&mut enc.tight[0], out, &data);
        }
        RectSpec::TightCompressed { rect, pixels } => {
            assert_eq!(pixels.len(), rect.area(), "TightCompressed pixel count");
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 7);
            let mut data = Vec::with_capacity(pixels.len() * 3);
            for p in pixels {
                data.extend_from_slice(&tpixel(*p));
            }
            out.push(0x00); // basic, stream 0, copy filter
            push_tight_body(&mut enc.tight[0], out, &data);
        }
        RectSpec::ZrleSolid { rect, colour } => {
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 16);
            let mut tiles = Vec::new();
            let mut ty = 0u16;
            while ty < rect.height {
                let mut tx = 0u16;
                while tx < rect.width {
                    tiles.push(1u8); // solid
                    tiles.extend_from_slice(&cpixel(*colour));
                    tx += 64;
                }
                ty += 64;
            }
            let comp = deflate_sync(&mut enc.zrle, &tiles);
            out.extend_from_slice(&(comp.len() as u32).to_be_bytes());
            out.extend_from_slice(&comp);
        }
        RectSpec::ZrlePalette {
            rect,
            colour0,
            colour1,
            rows,
        } => {
            assert!(
                rect.width <= 64 && rect.height <= 64,
                "ZrlePalette only supports a single tile"
            );
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 16);
            let row_bytes = (rect.width as usize).div_ceil(8);
            let mut tile = vec![2u8]; // packed palette, 2 colours -> 1 bit
            tile.extend_from_slice(&cpixel(*colour0));
            tile.extend_from_slice(&cpixel(*colour1));
            assert_eq!(rows.len(), rect.height as usize);
            for r in rows {
                assert_eq!(r.len(), row_bytes);
                tile.extend_from_slice(r);
            }
            let comp = deflate_sync(&mut enc.zrle, &tile);
            out.extend_from_slice(&(comp.len() as u32).to_be_bytes());
            out.extend_from_slice(&comp);
        }
        RectSpec::H264 { rect, flags, data } => {
            rect_header(out, rect.x, rect.y, rect.width, rect.height, 50);
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(&flags.to_be_bytes());
            out.extend_from_slice(data);
        }
        RectSpec::ExtendedDesktopSize {
            width,
            height,
            reason,
            status,
        } => {
            rect_header(out, *reason, *status, *width, *height, -308);
            out.push(1); // one screen
            out.extend_from_slice(&[0, 0, 0]); // padding
            out.extend_from_slice(&0u32.to_be_bytes()); // screen id
            out.extend_from_slice(&0u16.to_be_bytes()); // x
            out.extend_from_slice(&0u16.to_be_bytes()); // y
            out.extend_from_slice(&width.to_be_bytes());
            out.extend_from_slice(&height.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes()); // flags
        }
        RectSpec::DesktopName(name) => {
            rect_header(out, 0, 0, 0, 0, -307);
            out.extend_from_slice(&(name.len() as u32).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        RectSpec::RichCursor {
            width,
            height,
            hotspot_x,
            hotspot_y,
            colour,
        } => {
            rect_header(out, *hotspot_x, *hotspot_y, *width, *height, -239);
            let px = bgrx(*colour);
            for _ in 0..(*width as usize * *height as usize) {
                out.extend_from_slice(&px);
            }
            let mask_row = (*width as usize).div_ceil(8);
            out.extend(std::iter::repeat_n(0xffu8, mask_row * *height as usize));
        }
        RectSpec::FenceCapable => rect_header(out, 0, 0, 0, 0, -312),
        RectSpec::ContinuousUpdatesCapable => rect_header(out, 0, 0, 0, 0, -313),
        RectSpec::QemuExtKeyCapable => rect_header(out, 0, 0, 0, 0, -258),
        RectSpec::LastRect => rect_header(out, 0, 0, 0, 0, -224),
    }
}

/// Tight bodies below 12 bytes go on the wire raw with no length prefix;
/// anything larger is deflated through the given persistent stream and
/// prefixed with a compact length.
fn push_tight_body(stream: &mut Compress, out: &mut Vec<u8>, data: &[u8]) {
    if data.len() < 12 {
        out.extend_from_slice(data);
    } else {
        let comp = deflate_sync(stream, data);
        push_compact_len(out, comp.len());
        out.extend_from_slice(&comp);
    }
}

// ---------------------------------------------------------------------------
// Recorded client traffic
// ---------------------------------------------------------------------------

/// A parsed client→server message. `raw` fields keep the exact bytes so tests
/// can assert byte-for-byte wire correctness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMessage {
    SetPixelFormat {
        raw: Vec<u8>,
    },
    SetEncodings {
        encodings: Vec<i32>,
    },
    FramebufferUpdateRequest {
        incremental: bool,
        rect: Rect,
    },
    KeyEvent {
        down: bool,
        keysym: u32,
        raw: Vec<u8>,
    },
    PointerEvent {
        button_mask: u8,
        x: u16,
        y: u16,
        raw: Vec<u8>,
    },
    ClientCutText {
        raw: Vec<u8>,
    },
    EnableContinuousUpdates {
        enable: bool,
    },
    ClientFence {
        flags: u32,
        payload: Vec<u8>,
    },
    SetDesktopSize {
        width: u16,
        height: u16,
    },
    QemuKeyEvent {
        down: bool,
        keysym: u32,
        keycode: u32,
    },
}

#[derive(Debug, Default)]
pub struct Recorded {
    /// One entry per accepted TCP connection, in order.
    pub connections: Vec<Instant>,
    /// The 12-byte version banner the client replied with, per connection.
    pub version_replies: Vec<[u8; 12]>,
    /// Security type the client selected (RFB 3.7+ only).
    pub selected_security: Vec<u8>,
    /// Raw 16-byte VncAuth responses.
    pub auth_responses: Vec<Vec<u8>>,
    /// `(username, password)` pairs received via VeNCrypt Plain.
    pub plain_credentials: Vec<(String, String)>,
    /// The ClientInit shared flag, per connection.
    pub shared_flags: Vec<bool>,
    /// Every post-ServerInit message, in arrival order.
    pub messages: Vec<ClientMessage>,
    /// Number of FramebufferUpdates written back.
    pub updates_sent: usize,
}

#[derive(Debug, Clone)]
enum ServerAction {
    Raw(Vec<u8>),
    Disconnect,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MockConfig {
    pub banner: [u8; 12],
    pub security_types: Vec<u8>,
    /// Password the VncAuth challenge/response (or VeNCrypt Plain) is
    /// validated against.
    pub password: Option<String>,
    /// Username VeNCrypt Plain is validated against.
    pub username: Option<String>,
    pub challenge: [u8; 16],
    /// Reject authentication whatever the client sends.
    pub force_auth_failure: bool,
    pub auth_failure_reason: String,
    pub width: u16,
    pub height: u16,
    pub desktop_name: String,
    pub server_pixel_format: PixelFormat,
    /// One entry per FramebufferUpdateRequest, consumed in order. When the
    /// queue is exhausted the server simply stays quiet.
    pub updates: Vec<Vec<RectSpec>>,
    /// Close the TCP connection after writing this many updates.
    pub drop_after_n_updates: Option<usize>,
    /// How many connections may exhibit `drop_after_n_updates`.
    pub max_drops: usize,
    /// Stop answering (without closing) after this many updates.
    pub hang_after_n_updates: Option<usize>,
    /// Accept and immediately close the first N connections.
    pub refuse_first_n_connections: usize,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            banner: RFB_38,
            security_types: vec![SEC_NONE],
            password: None,
            username: None,
            challenge: [0x5a; 16],
            force_auth_failure: false,
            auth_failure_reason: "Authentication failed".into(),
            width: 640,
            height: 480,
            desktop_name: "Mock Desktop".into(),
            server_pixel_format: PixelFormat::bgra8888(),
            updates: Vec::new(),
            drop_after_n_updates: None,
            max_drops: usize::MAX,
            hang_after_n_updates: None,
            refuse_first_n_connections: 0,
        }
    }
}

impl MockConfig {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn banner(mut self, b: [u8; 12]) -> Self {
        self.banner = b;
        self
    }
    pub fn security(mut self, types: &[u8]) -> Self {
        self.security_types = types.to_vec();
        self
    }
    pub fn password(mut self, pw: &str) -> Self {
        self.password = Some(pw.into());
        self
    }
    pub fn username(mut self, user: &str) -> Self {
        self.username = Some(user.into());
        self
    }
    pub fn size(mut self, w: u16, h: u16) -> Self {
        self.width = w;
        self.height = h;
        self
    }
    pub fn name(mut self, n: &str) -> Self {
        self.desktop_name = n.into();
        self
    }
    pub fn update(mut self, rects: Vec<RectSpec>) -> Self {
        self.updates.push(rects);
        self
    }
    pub fn drop_after_n_updates(mut self, n: usize) -> Self {
        self.drop_after_n_updates = Some(n);
        self
    }
    pub fn max_drops(mut self, n: usize) -> Self {
        self.max_drops = n;
        self
    }
    pub fn hang_after_n_updates(mut self, n: usize) -> Self {
        self.hang_after_n_updates = Some(n);
        self
    }
    pub fn refuse_first_n_connections(mut self, n: usize) -> Self {
        self.refuse_first_n_connections = n;
        self
    }
}

// ---------------------------------------------------------------------------
// The server handle
// ---------------------------------------------------------------------------

pub struct MockServer {
    addr: SocketAddr,
    rec: Arc<Mutex<Recorded>>,
    actions: broadcast::Sender<ServerAction>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl MockServer {
    /// Bind on an ephemeral loopback port and start accepting.
    pub async fn start(cfg: MockConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().expect("local_addr");
        let rec = Arc::new(Mutex::new(Recorded::default()));
        let (actions, _) = broadcast::channel(64);

        let rec2 = rec.clone();
        let actions2 = actions.clone();
        let accept_task = tokio::spawn(async move {
            let drops_left = Arc::new(AtomicUsize::new(cfg.max_drops));
            let mut index = 0usize;
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                rec2.lock().unwrap().connections.push(Instant::now());
                if index < cfg.refuse_first_n_connections {
                    index += 1;
                    drop(stream); // accept-then-close: forces a retry
                    continue;
                }
                index += 1;
                let cfg = cfg.clone();
                let rec = rec2.clone();
                let rx = actions2.subscribe();
                let drops_left = drops_left.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, cfg, rec, rx, drops_left).await;
                });
            }
        });

        Self {
            addr,
            rec,
            actions,
            accept_task,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn connection_count(&self) -> usize {
        self.rec.lock().unwrap().connections.len()
    }

    pub fn connection_times(&self) -> Vec<Instant> {
        self.rec.lock().unwrap().connections.clone()
    }

    pub fn messages(&self) -> Vec<ClientMessage> {
        self.rec.lock().unwrap().messages.clone()
    }

    pub fn version_replies(&self) -> Vec<[u8; 12]> {
        self.rec.lock().unwrap().version_replies.clone()
    }

    pub fn selected_security(&self) -> Vec<u8> {
        self.rec.lock().unwrap().selected_security.clone()
    }

    pub fn plain_credentials(&self) -> Vec<(String, String)> {
        self.rec.lock().unwrap().plain_credentials.clone()
    }

    pub fn shared_flags(&self) -> Vec<bool> {
        self.rec.lock().unwrap().shared_flags.clone()
    }

    pub fn updates_sent(&self) -> usize {
        self.rec.lock().unwrap().updates_sent
    }

    pub fn key_events(&self) -> Vec<(u32, bool)> {
        self.messages()
            .into_iter()
            .filter_map(|m| match m {
                ClientMessage::KeyEvent { keysym, down, .. } => Some((keysym, down)),
                _ => None,
            })
            .collect()
    }

    pub fn pointer_events(&self) -> Vec<(u16, u16, u8)> {
        self.messages()
            .into_iter()
            .filter_map(|m| match m {
                ClientMessage::PointerEvent {
                    x, y, button_mask, ..
                } => Some((x, y, button_mask)),
                _ => None,
            })
            .collect()
    }

    /// Every SetEncodings list the client sent, in order.
    pub fn encoding_lists(&self) -> Vec<Vec<i32>> {
        self.messages()
            .into_iter()
            .filter_map(|m| match m {
                ClientMessage::SetEncodings { encodings } => Some(encodings),
                _ => None,
            })
            .collect()
    }

    /// Every SetPixelFormat message, as raw 20-byte messages.
    pub fn pixel_formats(&self) -> Vec<Vec<u8>> {
        self.messages()
            .into_iter()
            .filter_map(|m| match m {
                ClientMessage::SetPixelFormat { raw } => Some(raw),
                _ => None,
            })
            .collect()
    }

    /// Every ClientCutText body (everything after the type byte).
    pub fn cut_text_bodies(&self) -> Vec<Vec<u8>> {
        self.messages()
            .into_iter()
            .filter_map(|m| match m {
                ClientMessage::ClientCutText { raw } => Some(raw),
                _ => None,
            })
            .collect()
    }

    /// Inject arbitrary bytes into every live connection.
    pub fn send_raw(&self, bytes: Vec<u8>) {
        let _ = self.actions.send(ServerAction::Raw(bytes));
    }

    /// Send a legacy ServerCutText carrying `text`.
    pub fn send_server_cut_text(&self, text: &str) {
        let body = text.as_bytes();
        let mut msg = vec![3u8, 0, 0, 0];
        msg.extend_from_slice(&(body.len() as i32).to_be_bytes());
        msg.extend_from_slice(body);
        self.send_raw(msg);
    }

    /// Send a ServerCutText whose body is already framed (`3 pad + i32 len +
    /// payload`), e.g. one built by `vnc_core::clipboard::encode_provide_text`.
    pub fn send_cut_text_body(&self, body: Vec<u8>) {
        let mut msg = vec![3u8];
        msg.extend_from_slice(&body);
        self.send_raw(msg);
    }

    /// Send a Bell message.
    pub fn send_bell(&self) {
        self.send_raw(vec![2u8]);
    }

    /// Drop every live connection from the server side, mid-session.
    pub fn disconnect_now(&self) {
        let _ = self.actions.send(ServerAction::Disconnect);
    }

    /// Poll until `pred` holds or `within` elapses. Returns whether it held.
    pub async fn wait_until<F: Fn(&Recorded) -> bool>(&self, within: Duration, pred: F) -> bool {
        let deadline = Instant::now() + within;
        loop {
            if pred(&self.rec.lock().unwrap()) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    pub async fn wait_for_connections(&self, n: usize, within: Duration) -> bool {
        self.wait_until(within, |r| r.connections.len() >= n).await
    }

    pub async fn wait_for_messages(&self, n: usize, within: Duration) -> bool {
        self.wait_until(within, |r| r.messages.len() >= n).await
    }
}

// ---------------------------------------------------------------------------
// One connection
// ---------------------------------------------------------------------------

async fn serve(
    mut stream: TcpStream,
    cfg: MockConfig,
    rec: Arc<Mutex<Recorded>>,
    mut actions: broadcast::Receiver<ServerAction>,
    drops_left: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    let minor = effective_minor(&cfg.banner);

    // --- version handshake ------------------------------------------------
    stream.write_all(&cfg.banner).await?;
    stream.flush().await?;
    let mut reply = [0u8; 12];
    stream.read_exact(&mut reply).await?;
    rec.lock().unwrap().version_replies.push(reply);

    // --- security offer ---------------------------------------------------
    let chosen = if minor >= 7 {
        stream.write_all(&[cfg.security_types.len() as u8]).await?;
        stream.write_all(&cfg.security_types).await?;
        stream.flush().await?;
        let mut sel = [0u8; 1];
        stream.read_exact(&mut sel).await?;
        rec.lock().unwrap().selected_security.push(sel[0]);
        sel[0]
    } else {
        let ty = *cfg.security_types.first().unwrap_or(&SEC_NONE);
        stream.write_all(&(ty as u32).to_be_bytes()).await?;
        stream.flush().await?;
        ty
    };

    // --- authentication ---------------------------------------------------
    let mut auth_ok = !cfg.force_auth_failure;
    match chosen {
        SEC_NONE => {}
        SEC_VNC_AUTH => {
            stream.write_all(&cfg.challenge).await?;
            stream.flush().await?;
            let mut response = [0u8; 16];
            stream.read_exact(&mut response).await?;
            rec.lock().unwrap().auth_responses.push(response.to_vec());
            if let Some(pw) = &cfg.password {
                let expected =
                    vnc_core::security::vnc_auth::respond_to_challenge(pw, &cfg.challenge);
                if expected != response {
                    auth_ok = false;
                }
            }
        }
        SEC_VENCRYPT => {
            // Version 0.2, then a single subtype: Plain (cleartext
            // username+password, no TLS, rustls cannot do anonymous DH and
            // the mock has no certificate).
            stream.write_all(&[0, 2]).await?;
            stream.flush().await?;
            let mut client_version = [0u8; 2];
            stream.read_exact(&mut client_version).await?;
            stream.write_all(&[0]).await?; // ack
            stream.write_all(&[1]).await?; // one subtype
            stream.write_all(&VENCRYPT_PLAIN.to_be_bytes()).await?;
            stream.flush().await?;

            let mut chosen_subtype = [0u8; 4];
            stream.read_exact(&mut chosen_subtype).await?;
            assert_eq!(
                u32::from_be_bytes(chosen_subtype),
                VENCRYPT_PLAIN,
                "mock only offers VeNCrypt Plain"
            );

            // `u32 user_len, u32 pass_len, user, pass`.
            let mut lens = [0u8; 8];
            stream.read_exact(&mut lens).await?;
            let ulen = u32::from_be_bytes(lens[..4].try_into().unwrap()) as usize;
            let plen = u32::from_be_bytes(lens[4..].try_into().unwrap()) as usize;
            assert!(
                ulen <= 4096 && plen <= 4096,
                "implausible credential lengths"
            );
            let mut buf = vec![0u8; ulen + plen];
            stream.read_exact(&mut buf).await?;
            let user = String::from_utf8_lossy(&buf[..ulen]).into_owned();
            let pass = String::from_utf8_lossy(&buf[ulen..]).into_owned();
            rec.lock()
                .unwrap()
                .plain_credentials
                .push((user.clone(), pass.clone()));

            if cfg.username.as_deref().is_some_and(|u| u != user) {
                auth_ok = false;
            }
            if cfg.password.as_deref().is_some_and(|p| p != pass) {
                auth_ok = false;
            }
        }
        other => {
            // Nothing else is implemented; the client should never get here.
            panic!("mock server asked for unimplemented security type {other}");
        }
    }

    // SecurityResult: RFB 3.8 always sends one; before that only non-None does.
    let send_result = minor >= 8 || chosen != SEC_NONE;
    if send_result {
        if auth_ok {
            stream.write_all(&0u32.to_be_bytes()).await?;
        } else {
            stream.write_all(&1u32.to_be_bytes()).await?;
            if minor >= 8 {
                let reason = cfg.auth_failure_reason.as_bytes();
                stream
                    .write_all(&(reason.len() as u32).to_be_bytes())
                    .await?;
                stream.write_all(reason).await?;
            }
            stream.flush().await?;
            return Ok(());
        }
        stream.flush().await?;
    }

    // --- ClientInit / ServerInit -----------------------------------------
    let mut shared = [0u8; 1];
    stream.read_exact(&mut shared).await?;
    rec.lock().unwrap().shared_flags.push(shared[0] != 0);

    let mut init = Vec::new();
    init.extend_from_slice(&cfg.width.to_be_bytes());
    init.extend_from_slice(&cfg.height.to_be_bytes());
    init.extend_from_slice(&encode_pixel_format(&cfg.server_pixel_format));
    init.extend_from_slice(&(cfg.desktop_name.len() as u32).to_be_bytes());
    init.extend_from_slice(cfg.desktop_name.as_bytes());
    stream.write_all(&init).await?;
    stream.flush().await?;

    // --- message pump -----------------------------------------------------
    let (mut read_half, mut write_half) = stream.into_split();
    let (msg_tx, mut msg_rx) = mpsc::channel::<ClientMessage>(256);
    let reader = tokio::spawn(async move {
        // Ends on EOF, a framing error, or the pump going away.
        while let Ok(Some(m)) = read_client_message(&mut read_half).await {
            if msg_tx.send(m).await.is_err() {
                break;
            }
        }
    });

    let mut enc = Encoders::new();
    let mut update_idx = 0usize;
    let mut updates_sent = 0usize;
    let mut hung = false;

    loop {
        tokio::select! {
            msg = msg_rx.recv() => {
                let Some(msg) = msg else { break };
                let is_fbur = matches!(msg, ClientMessage::FramebufferUpdateRequest { .. });
                rec.lock().unwrap().messages.push(msg);
                if !is_fbur || hung {
                    continue;
                }
                let Some(specs) = cfg.updates.get(update_idx) else { continue };
                update_idx += 1;
                let bytes = encode_update(&mut enc, specs);
                if write_half.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = write_half.flush().await;
                updates_sent += 1;
                rec.lock().unwrap().updates_sent += 1;
                if cfg.drop_after_n_updates == Some(updates_sent)
                    && drops_left
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                            (v > 0).then_some(v - 1)
                        })
                        .is_ok()
                {
                    break;
                }
                if cfg.hang_after_n_updates == Some(updates_sent) {
                    hung = true;
                }
            }
            action = actions.recv() => match action {
                Ok(ServerAction::Raw(bytes)) => {
                    if write_half.write_all(&bytes).await.is_err() {
                        break;
                    }
                    let _ = write_half.flush().await;
                }
                Ok(ServerAction::Disconnect) => break,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }

    reader.abort();
    let _ = write_half.shutdown().await;
    Ok(())
}

/// Read and parse exactly one client→server message.
async fn read_client_message<R: AsyncReadExt + Unpin>(
    r: &mut R,
) -> std::io::Result<Option<ClientMessage>> {
    let ty = r.read_u8().await?;
    let msg = match ty {
        0 => {
            let mut rest = [0u8; 19];
            r.read_exact(&mut rest).await?;
            let mut raw = vec![0u8];
            raw.extend_from_slice(&rest);
            ClientMessage::SetPixelFormat { raw }
        }
        2 => {
            let _pad = r.read_u8().await?;
            let n = r.read_u16().await? as usize;
            let mut encodings = Vec::with_capacity(n);
            for _ in 0..n {
                encodings.push(r.read_i32().await?);
            }
            ClientMessage::SetEncodings { encodings }
        }
        3 => {
            let incremental = r.read_u8().await? != 0;
            let x = r.read_u16().await?;
            let y = r.read_u16().await?;
            let w = r.read_u16().await?;
            let h = r.read_u16().await?;
            ClientMessage::FramebufferUpdateRequest {
                incremental,
                rect: Rect::new(x, y, w, h),
            }
        }
        4 => {
            let mut rest = [0u8; 7];
            r.read_exact(&mut rest).await?;
            let down = rest[0] != 0;
            let keysym = u32::from_be_bytes([rest[3], rest[4], rest[5], rest[6]]);
            let mut raw = vec![4u8];
            raw.extend_from_slice(&rest);
            ClientMessage::KeyEvent { down, keysym, raw }
        }
        5 => {
            let mut rest = [0u8; 5];
            r.read_exact(&mut rest).await?;
            let mut raw = vec![5u8];
            raw.extend_from_slice(&rest);
            ClientMessage::PointerEvent {
                button_mask: rest[0],
                x: u16::from_be_bytes([rest[1], rest[2]]),
                y: u16::from_be_bytes([rest[3], rest[4]]),
                raw,
            }
        }
        6 => {
            let mut head = [0u8; 7];
            r.read_exact(&mut head).await?;
            let len = i32::from_be_bytes([head[3], head[4], head[5], head[6]]);
            let n = len.unsigned_abs() as usize;
            if n > 16 * 1024 * 1024 {
                return Err(std::io::Error::other("absurd cut text length"));
            }
            let mut body = vec![0u8; n];
            r.read_exact(&mut body).await?;
            let mut raw = head.to_vec();
            raw.extend_from_slice(&body);
            ClientMessage::ClientCutText { raw }
        }
        150 => {
            let mut rest = [0u8; 9];
            r.read_exact(&mut rest).await?;
            ClientMessage::EnableContinuousUpdates {
                enable: rest[0] != 0,
            }
        }
        248 => {
            let mut pad = [0u8; 3];
            r.read_exact(&mut pad).await?;
            let flags = r.read_u32().await?;
            let len = r.read_u8().await? as usize;
            let mut payload = vec![0u8; len];
            r.read_exact(&mut payload).await?;
            ClientMessage::ClientFence { flags, payload }
        }
        251 => {
            let _pad = r.read_u8().await?;
            let width = r.read_u16().await?;
            let height = r.read_u16().await?;
            let n = r.read_u8().await? as usize;
            let _pad2 = r.read_u8().await?;
            let mut screens = vec![0u8; n * 16];
            r.read_exact(&mut screens).await?;
            ClientMessage::SetDesktopSize { width, height }
        }
        255 => {
            let sub = r.read_u8().await?;
            if sub != 0 {
                return Err(std::io::Error::other("unknown QEMU submessage"));
            }
            let down = r.read_u16().await? != 0;
            let keysym = r.read_u32().await?;
            let keycode = r.read_u32().await?;
            ClientMessage::QemuKeyEvent {
                down,
                keysym,
                keycode,
            }
        }
        other => {
            return Err(std::io::Error::other(format!(
                "mock server got unknown client message type {other}"
            )))
        }
    };
    Ok(Some(msg))
}
