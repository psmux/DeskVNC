//! Pixel-level correctness probe against a live server.
//!
//! The quality/stall diagnostics (`live_quality`) can only see numbers; this
//! sees what the user sees. It composes the decoded rect stream into an
//! in-memory framebuffer, exactly as the webview renderer is asked to, then
//! answers the question "is what we accumulated over a long session still the
//! truth?" by connecting a SECOND session and taking its first full update as
//! ground truth: the first frame of a fresh session is a single
//! non-incremental paint with no history to corrupt.
//!
//! Output: `A-mid.png` (long session, mid-load), `A.png` (long session,
//! settled), `B.png` (fresh session, truth), `diff.png` (red where A and B
//! disagree), plus per-tile statistics. If A matches B, everything up to and
//! including vnc-core decoding is correct and a display bug must live in the
//! webview renderer; if A is corrupt, the decode path is at fault. That
//! attribution is the entire point of the exercise.
//!
//! ```sh
//! DVV_HOST=... DVV_USER=... DVV_PASS=... DVV_OUT=/tmp \
//!   cargo run -p vnc-core --example fb_probe
//! ```

use std::io::Write as _;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use vnc_core::encodings::tight::decode_jpeg_to_rgba;
use vnc_core::types::{
    ConnectOptions, Credentials, QualityPreset, RectPayload, SessionEvent, SessionState,
};
use vnc_core::Session;

// ---------------------------------------------------------------------------
// Framebuffer composition (the reference implementation of FRAME_FORMAT.md)
// ---------------------------------------------------------------------------

struct Fb {
    w: usize,
    h: usize,
    px: Vec<u8>, // RGBA
    /// Last decode path that wrote each pixel (0 none, 1 rgba/tight-basic,
    /// 2 jpeg, 3 copyrect): when a tile is wrong, this names the suspect.
    writer: Vec<u8>,
    jpeg_fail: u64,
    h264_rects: u64,
    rects: u64,
    rgba_rects: u64,
    jpeg_rects: u64,
    copy_rects: u64,
}

impl Fb {
    fn new() -> Self {
        Self {
            w: 0,
            h: 0,
            px: Vec::new(),
            writer: Vec::new(),
            jpeg_fail: 0,
            h264_rects: 0,
            rects: 0,
            rgba_rects: 0,
            jpeg_rects: 0,
            copy_rects: 0,
        }
    }

    fn resize(&mut self, w: usize, h: usize) {
        self.w = w;
        self.h = h;
        self.px = vec![0u8; w * h * 4];
        self.writer = vec![0u8; w * h];
    }

    /// Blit `data` (tight RGBA rows) at (x, y), clipped to the framebuffer.
    fn blit(&mut self, x: usize, y: usize, w: usize, h: usize, data: &[u8], tag: u8) {
        if self.w == 0 || data.len() < w * h * 4 {
            return;
        }
        for row in 0..h {
            let dy = y + row;
            if dy >= self.h {
                break;
            }
            let cols = w.min(self.w.saturating_sub(x));
            if cols == 0 {
                break;
            }
            let src = row * w * 4;
            let dst = (dy * self.w + x) * 4;
            self.px[dst..dst + cols * 4].copy_from_slice(&data[src..src + cols * 4]);
            self.writer[dy * self.w + x..dy * self.w + x + cols].fill(tag);
        }
    }

    /// Overlap-safe self-copy, the reference CopyRect.
    fn copy_rect(&mut self, sx: usize, sy: usize, dx: usize, dy: usize, w: usize, h: usize) {
        if self.w == 0 {
            return;
        }
        let mut tmp = vec![0u8; w * h * 4];
        for row in 0..h {
            let y = sy + row;
            if y >= self.h {
                break;
            }
            let cols = w.min(self.w.saturating_sub(sx));
            let src = (y * self.w + sx) * 4;
            tmp[row * w * 4..row * w * 4 + cols * 4].copy_from_slice(&self.px[src..src + cols * 4]);
        }
        self.blit(dx, dy, w, h, &tmp, 3);
    }

    fn apply(&mut self, rects: &[vnc_core::types::DecodedRect]) {
        for r in rects {
            self.rects += 1;
            let (x, y) = (r.rect.x as usize, r.rect.y as usize);
            let (w, h) = (r.rect.width as usize, r.rect.height as usize);
            match &r.payload {
                RectPayload::Rgba(data) => {
                    self.rgba_rects += 1;
                    self.blit(x, y, w, h, data, 1)
                }
                RectPayload::Jpeg(bytes) => {
                    self.jpeg_rects += 1;
                    let decoded = decode_jpeg_to_rgba(bytes);
                    match decoded {
                        Ok((jw, jh, data)) => {
                            // The webview trusts the bitmap's own dimensions; do
                            // the same so a mismatch shows up as a visible defect
                            // rather than being silently corrected here.
                            self.blit(x, y, jw as usize, jh as usize, &data, 2);
                            if (jw as usize, jh as usize) != (w, h) {
                                eprintln!("JPEG dims {jw}x{jh} != rect {w}x{h} at ({x},{y})");
                            }
                        }
                        Err(e) => {
                            self.jpeg_fail += 1;
                            eprintln!("JPEG decode failed at ({x},{y}) {w}x{h}: {e}");
                        }
                    }
                }
                RectPayload::CopyRect { src_x, src_y } => {
                    self.copy_rects += 1;
                    self.copy_rect(*src_x as usize, *src_y as usize, x, y, w, h)
                }
                other => {
                    // H.264 and anything future: we cannot compose it here, so
                    // count it; a non-zero count invalidates the comparison.
                    let _ = other;
                    self.h264_rects += 1;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal PNG writer (no new dependencies; flate2 is already a vnc-core dep)
// ---------------------------------------------------------------------------

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (n, slot) in table.iter_mut().enumerate() {
        let mut c = n as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c = table[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffff_ffff
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    let mut tagged = Vec::with_capacity(4 + body.len());
    tagged.extend_from_slice(kind);
    tagged.extend_from_slice(body);
    out.extend_from_slice(&tagged);
    out.extend_from_slice(&crc32(&tagged).to_be_bytes());
}

fn write_png(path: &str, w: usize, h: usize, rgba: &[u8]) {
    let mut raw = Vec::with_capacity(h * (1 + w * 4));
    for row in 0..h {
        raw.push(0); // filter: none
        raw.extend_from_slice(&rgba[row * w * 4..(row + 1) * w * 4]);
    }
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    let _ = enc.write_all(&raw);
    let idat = enc.finish().unwrap_or_default();

    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(w as u32).to_be_bytes());
    ihdr.extend_from_slice(&(h as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA
    png_chunk(&mut png, b"IHDR", &ihdr);
    png_chunk(&mut png, b"IDAT", &idat);
    png_chunk(&mut png, b"IEND", &[]);
    if let Err(e) = std::fs::write(path, png) {
        eprintln!("could not write {path}: {e}");
    } else {
        println!("wrote {path}");
    }
}

// ---------------------------------------------------------------------------
// Session driving
// ---------------------------------------------------------------------------

fn options() -> ConnectOptions {
    let host = std::env::var("DVV_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let mut o = ConnectOptions::new(host, 5900);
    // Auto is what the app's profile uses; a FIXED preset never sends a
    // mid-session SetEncodings, which is the discriminating experiment for
    // state that desyncs on a quality switch.
    o.quality = match std::env::var("DVV_QUALITY").as_deref() {
        Ok("high") => QualityPreset::High,
        Ok("medium") => QualityPreset::Medium,
        Ok("low") => QualityPreset::Low,
        _ => QualityPreset::Auto,
    };
    o.allow_insecure = true;
    o.credentials = Credentials {
        username: std::env::var("DVV_USER").ok(),
        password: std::env::var("DVV_PASS").ok(),
    };
    o.reconnect.enabled = false;
    // DVV_ALR=0 disables auto lossless refresh: with the tuner still active,
    // this splits "the tuner's SetEncodings corrupts" from "ALR's
    // SetEncodings-toggle-around-a-request corrupts".
    o.lossless_refresh = std::env::var("DVV_ALR").as_deref() != Ok("0");
    o
}

/// Pump one session into `fb` until `deadline`, optionally snapshotting at
/// `mid` (both measured from this call).
async fn pump(
    label: &str,
    fb: &mut Fb,
    rx: &mut mpsc::Receiver<SessionEvent>,
    deadline: Duration,
    mid: Option<(Duration, &str)>,
) {
    let started = Instant::now();
    let mut mid = mid;
    while started.elapsed() < deadline {
        let left = deadline.saturating_sub(started.elapsed());
        let Ok(Some(event)) =
            tokio::time::timeout(left.min(Duration::from_secs(2)), rx.recv()).await
        else {
            // Timeout tick: check the mid snapshot even while idle.
            if let Some((at, path)) = mid {
                if started.elapsed() >= at && fb.w > 0 {
                    write_png(path, fb.w, fb.h, &fb.px);
                    mid = None;
                }
            }
            continue;
        };
        match event {
            SessionEvent::DesktopResize { width, height } => {
                fb.resize(width as usize, height as usize)
            }
            SessionEvent::FramebufferUpdate { rects, .. } => {
                // DVV_SLOW=1 emulates the real app's consumer: decode + WebGL
                // upload + compositing take tens of milliseconds per update,
                // which backpressures the socket. wayvnc mistracks damage
                // exactly under that backpressure, so a probe that consumes
                // instantly can never reproduce what the app shows.
                if std::env::var("DVV_SLOW").as_deref() == Ok("1") {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                fb.apply(&rects)
            }
            SessionEvent::StateChanged(SessionState::Connected) => {
                println!("[{label}] connected");
            }
            SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                println!("[{label}] disconnected: {reason}");
                return;
            }
            SessionEvent::Error(e) => println!("[{label}] error: {e}"),
            _ => {}
        }
        if let Some((at, path)) = mid {
            if started.elapsed() >= at && fb.w > 0 {
                write_png(path, fb.w, fb.h, &fb.px);
                mid = None;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let out = std::env::var("DVV_OUT").unwrap_or_else(|_| ".".into());
    let secs_a: u64 = std::env::var("DVV_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(45);

    // Phase A: the long-lived session that accumulates through the animations.
    println!("phase A: long session, {secs_a}s (drive load on the server now)");
    let (tx, mut rx) = mpsc::channel::<SessionEvent>(256);
    let handle_a = Session::spawn("fb-probe-a".into(), options(), tx);
    let mut a = Fb::new();
    pump(
        "A",
        &mut a,
        &mut rx,
        Duration::from_secs(secs_a),
        Some((Duration::from_secs(secs_a / 2), &format!("{out}/A-mid.png"))),
    )
    .await;
    write_png(&format!("{out}/A.png"), a.w, a.h, &a.px);
    println!(
        "[A] rects={} (rgba={} jpeg={} copy={}) jpeg_failures={} h264_rects={}",
        a.rects, a.rgba_rects, a.jpeg_rects, a.copy_rects, a.jpeg_fail, a.h264_rects
    );

    // Phase B: fresh session; its first full paint is the truth. Session A is
    // kept alive so the server does not reconfigure anything between the two.
    println!("phase B: fresh session for ground truth");
    let (tx, mut rx_b) = mpsc::channel::<SessionEvent>(256);
    let handle_b = Session::spawn("fb-probe-b".into(), options(), tx);
    let mut b = Fb::new();
    pump("B", &mut b, &mut rx_b, Duration::from_secs(6), None).await;
    write_png(&format!("{out}/B.png"), b.w, b.h, &b.px);

    handle_a.shutdown();
    handle_b.shutdown();

    // Diff. The screen is live (a clock ticks somewhere), so per-tile stats
    // with a tolerance beat a naive byte compare.
    if a.w != b.w || a.h != b.h || a.w == 0 {
        println!("size mismatch: A {}x{} vs B {}x{}", a.w, a.h, b.w, b.h);
        return;
    }
    if a.h264_rects > 0 {
        println!("H.264 rects present: comparison not meaningful");
        return;
    }

    const TILE: usize = 16;
    let (tw, th) = (a.w.div_ceil(TILE), a.h.div_ceil(TILE));
    let mut bad_tiles = 0usize;
    let mut worst: Vec<(u64, usize, usize)> = Vec::new();
    let mut diff = b.px.clone();
    // Who last wrote the pixels that turned out wrong.
    let mut writer_hist = [0u64; 4];
    for ty in 0..th {
        for tx_ in 0..tw {
            let mut acc = 0u64;
            let mut n = 0u64;
            for y in (ty * TILE)..((ty + 1) * TILE).min(a.h) {
                for x in (tx_ * TILE)..((tx_ + 1) * TILE).min(a.w) {
                    let i = (y * a.w + x) * 4;
                    for c in 0..3 {
                        acc += (a.px[i + c] as i32 - b.px[i + c] as i32).unsigned_abs() as u64;
                    }
                    n += 3;
                }
            }
            let mean = acc / n.max(1);
            if mean > 12 {
                bad_tiles += 1;
                worst.push((mean, tx_ * TILE, ty * TILE));
                for y in (ty * TILE)..((ty + 1) * TILE).min(a.h) {
                    for x in (tx_ * TILE)..((tx_ + 1) * TILE).min(a.w) {
                        let i = (y * a.w + x) * 4;
                        diff[i] = 255;
                        diff[i + 1] = 0;
                        diff[i + 2] = 0;
                        writer_hist[a.writer[y * a.w + x].min(3) as usize] += 1;
                    }
                }
            }
        }
    }
    write_png(&format!("{out}/diff.png"), a.w, a.h, &diff);
    worst.sort_unstable_by_key(|&(mean, _, _)| std::cmp::Reverse(mean));
    println!(
        "\n{} of {} tiles differ (mean-abs > 12). Worst:",
        bad_tiles,
        tw * th
    );
    for (mean, x, y) in worst.iter().take(12) {
        println!("  tile at ({x:>4},{y:>4}) mean-abs {mean}");
    }
    println!(
        "corrupt pixels by last writer: never-written={} tight-basic/rgba={} jpeg={} copyrect={}",
        writer_hist[0], writer_hist[1], writer_hist[2], writer_hist[3]
    );
    if bad_tiles == 0 {
        println!("A == B: vnc-core's decode is faithful; any visible corruption is renderer-side.");
    }
}
