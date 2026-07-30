//! Criterion benchmarks for the VNC pixel hot path.
//!
//! Everything here measures the *decode + apply* half of the pipeline described
//! in PRD/01 §3 against the budgets in PRD/13 §3.6. Wire data is synthesised
//! once, outside the timed loop, from a desktop-like test image; the timed
//! region contains only the decoder (or the pixel routine) itself.
//!
//! Throughput is reported with `Throughput::Elements(pixels)` so criterion
//! prints `Melem/s` == **MPixels/s**, comparable across resolutions.

use std::future::Future;
use std::task::{Context, Poll};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use flate2::{Compress, Compression, FlushCompress};

use vnc_core::encodings::{decode_rect, DecoderState};
use vnc_core::pixel::{convert_to_rgba, convert_to_rgba_mapped, downscale_rgba, ColourMap};
use vnc_core::types::{encoding, DecodedRect, PixelFormat, Rect, RectPayload};

// ---------------------------------------------------------------------------
// Minimal executor: the decoders are async but every reader here is an
// in-memory slice, so every future completes on the first poll. This keeps
// runtime overhead out of the measurement.
// ---------------------------------------------------------------------------

fn run<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => unreachable!("in-memory reader never pends"),
    }
}

// ---------------------------------------------------------------------------
// Test content
// ---------------------------------------------------------------------------

const SIZES: [(usize, usize, &str); 2] = [(1920, 1080, "1080p"), (3840, 2160, "4k")];

fn pf() -> PixelFormat {
    PixelFormat::bgra8888()
}

/// Desktop-like BGRX image: flat "window" panes, a vertical gradient
/// background and text-ish high-frequency detail. This mix is what decides
/// whether a real encoder picks solid/palette/RLE/raw tiles.
fn synth_desktop(w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let o = (y * w + x) * 4;
            let pane = (x / 320 + y / 240) % 3;
            let (r, g, b) = match pane {
                0 => {
                    // Light document window with text-like runs.
                    if (y % 18) < 9 && ((x * 7 + y * 13) % 23) < 6 {
                        (24, 24, 28)
                    } else {
                        (246, 246, 248)
                    }
                }
                1 => (32, 34, 40), // dark terminal pane
                _ => {
                    // Desktop wallpaper gradient.
                    (
                        (30 + y * 100 / h) as u8,
                        (40 + y * 80 / h) as u8,
                        (90 + x * 60 / w) as u8,
                    )
                }
            };
            out[o] = b;
            out[o + 1] = g;
            out[o + 2] = r;
            out[o + 3] = 0;
        }
    }
    out
}

/// A flatter variant: large solid regions with long horizontal runs. This is
/// the content for which a server actually selects RLE/solid subencodings.
fn synth_flat(w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let o = (y * w + x) * 4;
            let band = (x / 64 + y / 64) % 4;
            let (r, g, b) = match band {
                0 => (240, 240, 240),
                1 => (28, 30, 36),
                2 => (70, 110, 190),
                _ => (200, 90, 60),
            };
            out[o] = b;
            out[o + 1] = g;
            out[o + 2] = r;
            out[o + 3] = 0;
        }
    }
    out
}

#[inline]
fn px_at(img: &[u8], w: usize, x: usize, y: usize) -> (u8, u8, u8) {
    let o = (y * w + x) * 4;
    (img[o + 2], img[o + 1], img[o]) // (R, G, B)
}

// ---------------------------------------------------------------------------
// Wire-format builders
// ---------------------------------------------------------------------------

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2 + 1024);
    let mut c = Compress::new(Compression::default(), true);
    c.compress_vec(data, &mut out, FlushCompress::Sync).unwrap();
    assert_eq!(c.total_in() as usize, data.len(), "compressor stalled");
    out
}

/// Tight's 1-3 byte compact length.
fn compact_len(mut n: usize) -> Vec<u8> {
    let mut v = vec![(n & 0x7f) as u8];
    n >>= 7;
    if n > 0 {
        v[0] |= 0x80;
        v.push((n & 0x7f) as u8);
        n >>= 7;
        if n > 0 {
            v[1] |= 0x80;
            v.push((n & 0xff) as u8);
        }
    }
    v
}

// --- Raw / CopyRect / zlib -------------------------------------------------

fn raw_wire(img: &[u8]) -> Vec<u8> {
    img.to_vec()
}

fn copy_rect_wire() -> Vec<u8> {
    vec![0, 0, 0, 0] // src_x = 0, src_y = 0
}

fn zlib_wire(img: &[u8]) -> Vec<u8> {
    let comp = deflate(img);
    let mut wire = (comp.len() as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(&comp);
    wire
}

// --- Hextile ---------------------------------------------------------------

const HEX_RAW: u8 = 1;
const HEX_BG: u8 = 2;
const HEX_ANY_SUBRECTS: u8 = 8;
const HEX_SUBRECTS_COLOURED: u8 = 16;

/// A real-ish Hextile encoder: solid tiles become background-only, tiles that
/// fit in <=255 coloured runs become subrect tiles, everything else is raw.
fn hextile_wire(img: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut wire = Vec::with_capacity(w * h);
    let mut ty = 0;
    while ty < h {
        let th = (h - ty).min(16);
        let mut tx = 0;
        while tx < w {
            let tw = (w - tx).min(16);
            // Collect the tile and its colour histogram.
            let mut counts: Vec<((u8, u8, u8), usize)> = Vec::new();
            for y in 0..th {
                for x in 0..tw {
                    let c = px_at(img, w, tx + x, ty + y);
                    match counts.iter_mut().find(|(k, _)| *k == c) {
                        Some((_, n)) => *n += 1,
                        None => counts.push((c, 1)),
                    }
                }
            }
            counts.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
            let bg = counts[0].0;

            if counts.len() == 1 {
                wire.push(HEX_BG);
                wire.extend_from_slice(&[bg.2, bg.1, bg.0, 0]);
                tx += tw;
                continue;
            }

            // Try run-length subrects over the non-background pixels.
            let mut subs: Vec<(u8, u8, u8, u8, u8)> = Vec::new(); // x,y,w,h,colour-idx placeholder
            let mut colours: Vec<(u8, u8, u8)> = Vec::new();
            let mut ok = true;
            'rows: for y in 0..th {
                let mut x = 0;
                while x < tw {
                    let c = px_at(img, w, tx + x, ty + y);
                    if c == bg {
                        x += 1;
                        continue;
                    }
                    let start = x;
                    while x < tw && px_at(img, w, tx + x, ty + y) == c {
                        x += 1;
                    }
                    if subs.len() == 255 {
                        ok = false;
                        break 'rows;
                    }
                    colours.push(c);
                    subs.push((start as u8, y as u8, (x - start) as u8, 1, 0));
                }
            }

            if ok {
                wire.push(HEX_BG | HEX_ANY_SUBRECTS | HEX_SUBRECTS_COLOURED);
                wire.extend_from_slice(&[bg.2, bg.1, bg.0, 0]);
                wire.push(subs.len() as u8);
                for (i, &(sx, sy, sw, sh, _)) in subs.iter().enumerate() {
                    let c = colours[i];
                    wire.extend_from_slice(&[c.2, c.1, c.0, 0]);
                    wire.push((sx << 4) | sy);
                    wire.push(((sw - 1) << 4) | (sh - 1));
                }
            } else {
                wire.push(HEX_RAW);
                for y in 0..th {
                    let o = ((ty + y) * w + tx) * 4;
                    wire.extend_from_slice(&img[o..o + tw * 4]);
                }
            }
            tx += tw;
        }
        ty += th;
    }
    wire
}

// --- Tight -----------------------------------------------------------------

/// Fill: a single TPIXEL covering the rect.
fn tight_fill_wire() -> Vec<u8> {
    vec![0x80, 70, 110, 190] // ctrl = Fill, TPIXEL = R,G,B
}

/// Basic + Copy filter, zlib stream 0 (reset each rect so the blob is
/// self-contained), compact TPIXELs.
fn tight_copy_wire(img: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut tp = Vec::with_capacity(w * h * 3);
    for y in 0..h {
        for x in 0..w {
            let (r, g, b) = px_at(img, w, x, y);
            tp.extend_from_slice(&[r, g, b]);
        }
    }
    let comp = deflate(&tp);
    let mut wire = vec![0x01]; // cc=0 -> basic/stream0/no filter; bit0 resets stream 0
    wire.extend_from_slice(&compact_len(comp.len()));
    wire.extend_from_slice(&comp);
    wire
}

/// Basic + Palette filter with a 256-colour palette (8-bit indices).
fn tight_palette_wire(img: &[u8], w: usize, h: usize) -> Vec<u8> {
    // Fixed 6x6x7-ish cube so every pixel maps deterministically.
    let mut palette = Vec::with_capacity(256);
    for i in 0..256u32 {
        palette.push((
            ((i >> 5) * 36) as u8,
            (((i >> 2) & 0x7) * 36) as u8,
            ((i & 0x3) * 85) as u8,
        ));
    }
    let mut idx = Vec::with_capacity(w * h);
    for y in 0..h {
        for x in 0..w {
            let (r, g, b) = px_at(img, w, x, y);
            idx.push((((r as u32 / 36) << 5) | ((g as u32 / 36) << 2) | (b as u32 / 85)) as u8);
        }
    }
    let comp = deflate(&idx);
    let mut wire = vec![0x41]; // cc=4 -> basic/stream0/filter byte; bit0 resets stream 0
    wire.push(1); // FILTER_PALETTE
    wire.push(255); // 256 colours
    for (r, g, b) in &palette {
        wire.extend_from_slice(&[*r, *g, *b]);
    }
    wire.extend_from_slice(&compact_len(comp.len()));
    wire.extend_from_slice(&comp);
    wire
}

/// Forward gradient prediction: the residual bytes `undo_gradient` consumes.
fn tight_gradient_data(img: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut data = vec![0u8; w * h * 3];
    let mut prev = vec![[0i32; 3]; w];
    let mut cur = vec![[0i32; 3]; w];
    for y in 0..h {
        let mut left = [0i32; 3];
        for x in 0..w {
            let (r, g, b) = px_at(img, w, x, y);
            let val = [r as i32, g as i32, b as i32];
            let upleft = if x > 0 { prev[x - 1] } else { [0; 3] };
            let o = (y * w + x) * 3;
            for c in 0..3 {
                let pred = (left[c] + prev[x][c] - upleft[c]).clamp(0, 255);
                data[o + c] = (val[c] - pred).rem_euclid(256) as u8;
                cur[x][c] = val[c];
            }
            left = cur[x];
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    data
}

/// Basic + Gradient filter.
fn tight_gradient_wire(img: &[u8], w: usize, h: usize) -> Vec<u8> {
    let comp = deflate(&tight_gradient_data(img, w, h));
    let mut wire = vec![0x41];
    wire.push(2); // FILTER_GRADIENT
    wire.extend_from_slice(&compact_len(comp.len()));
    wire.extend_from_slice(&comp);
    wire
}

// --- ZRLE ------------------------------------------------------------------

fn zrle_frame(tile_stream: &[u8]) -> Vec<u8> {
    let comp = deflate(tile_stream);
    let mut wire = (comp.len() as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(&comp);
    wire
}

/// Every 64x64 tile as subencoding 1 (solid), colour = the tile's dominant
/// pixel. The cheapest ZRLE shape a server can send.
fn zrle_solid_stream(img: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut ts = Vec::new();
    let mut ty = 0;
    while ty < h {
        let mut tx = 0;
        while tx < w {
            let (r, g, b) = px_at(img, w, tx, ty);
            ts.extend_from_slice(&[1, b, g, r]); // CPIXEL bytes are B,G,R
            tx += 64;
        }
        ty += 64;
    }
    ts
}

/// Packed-palette tiles: 4 colours -> 2-bit indices, rows byte-padded.
fn zrle_packed_palette_stream(img: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut ts = Vec::new();
    let mut ty = 0;
    while ty < h {
        let th = (h - ty).min(64);
        let mut tx = 0;
        while tx < w {
            let tw = (w - tx).min(64);
            // Four most common colours in the tile (padded if fewer).
            let mut counts: Vec<((u8, u8, u8), usize)> = Vec::new();
            for y in 0..th {
                for x in 0..tw {
                    let c = px_at(img, w, tx + x, ty + y);
                    match counts.iter_mut().find(|(k, _)| *k == c) {
                        Some((_, n)) => *n += 1,
                        None => counts.push((c, 1)),
                    }
                }
            }
            counts.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
            let mut pal: Vec<(u8, u8, u8)> = counts.iter().take(4).map(|&(c, _)| c).collect();
            while pal.len() < 4 {
                pal.push((0, 0, 0));
            }
            ts.push(4); // subencoding = palette size
            for &(r, g, b) in &pal {
                ts.extend_from_slice(&[b, g, r]);
            }
            let row_bytes = (tw * 2).div_ceil(8);
            for y in 0..th {
                let mut row = vec![0u8; row_bytes];
                for x in 0..tw {
                    let c = px_at(img, w, tx + x, ty + y);
                    // Nearest of the four by simple sum-of-abs distance.
                    let idx = pal
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, p)| {
                            (p.0 as i32 - c.0 as i32).abs()
                                + (p.1 as i32 - c.1 as i32).abs()
                                + (p.2 as i32 - c.2 as i32).abs()
                        })
                        .map(|(i, _)| i)
                        .unwrap() as u8;
                    let bit_off = x * 2;
                    row[bit_off / 8] |= idx << (8 - 2 - (bit_off % 8));
                }
                ts.extend_from_slice(&row);
            }
            tx += tw;
        }
        ty += th;
    }
    ts
}

/// Plain RLE tiles (subencoding 128) built from real horizontal runs.
fn zrle_rle_stream(img: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut ts = Vec::new();
    let mut ty = 0;
    while ty < h {
        let th = (h - ty).min(64);
        let mut tx = 0;
        while tx < w {
            let tw = (w - tx).min(64);
            ts.push(128);
            // Runs are over the tile in row-major order.
            let mut i = 0;
            let n = tw * th;
            while i < n {
                let c = px_at(img, w, tx + i % tw, ty + i / tw);
                let mut len = 1;
                while i + len < n && px_at(img, w, tx + (i + len) % tw, ty + (i + len) / tw) == c {
                    len += 1;
                }
                ts.extend_from_slice(&[c.2, c.1, c.0]);
                let mut rem = len - 1;
                while rem >= 255 {
                    ts.push(255);
                    rem -= 255;
                }
                ts.push(rem as u8);
                i += len;
            }
            tx += tw;
        }
        ty += th;
    }
    ts
}

/// Palette-RLE tiles (subencoding 130+): the shape real servers send most.
fn zrle_palette_rle_stream(img: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut ts = Vec::new();
    let mut ty = 0;
    while ty < h {
        let th = (h - ty).min(64);
        let mut tx = 0;
        while tx < w {
            let tw = (w - tx).min(64);
            let mut pal: Vec<(u8, u8, u8)> = Vec::new();
            for y in 0..th {
                for x in 0..tw {
                    let c = px_at(img, w, tx + x, ty + y);
                    if !pal.contains(&c) && pal.len() < 127 {
                        pal.push(c);
                    }
                }
            }
            if pal.len() < 2 {
                // Palette size 1 has no encoding (129 is reserved), a real
                // server sends the solid subencoding for these tiles.
                let (r, g, b) = pal[0];
                ts.extend_from_slice(&[1, b, g, r]);
                tx += tw;
                continue;
            }
            ts.push(128 + pal.len() as u8);
            for &(r, g, b) in &pal {
                ts.extend_from_slice(&[b, g, r]);
            }
            let n = tw * th;
            let mut i = 0;
            while i < n {
                let c = px_at(img, w, tx + i % tw, ty + i / tw);
                let idx = pal.iter().position(|p| *p == c).unwrap_or(0) as u8;
                let mut len = 1;
                while i + len < n && px_at(img, w, tx + (i + len) % tw, ty + (i + len) / tw) == c {
                    len += 1;
                }
                if len == 1 {
                    ts.push(idx);
                } else {
                    ts.push(idx | 0x80);
                    let mut rem = len - 1;
                    while rem >= 255 {
                        ts.push(255);
                        rem -= 255;
                    }
                    ts.push(rem as u8);
                }
                i += len;
            }
            tx += tw;
        }
        ty += th;
    }
    ts
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn decode_once(state: &mut DecoderState, wire: &[u8], rect: Rect, enc: i32) {
    let mut r: &[u8] = wire;
    let out = run(decode_rect(state, &mut r, rect, enc)).expect("decode failed");
    std::hint::black_box(out);
}

fn bench_decoders(c: &mut Criterion) {
    for (w, h, label) in SIZES {
        let rect = Rect::new(0, 0, w as u16, h as u16);
        let img = synth_desktop(w, h);
        let flat = synth_flat(w, h);

        let cases: Vec<(&str, i32, Vec<u8>)> = vec![
            ("raw", encoding::RAW, raw_wire(&img)),
            ("copy_rect", encoding::COPY_RECT, copy_rect_wire()),
            ("hextile", encoding::HEXTILE, hextile_wire(&img, w, h)),
            ("zlib", encoding::ZLIB, zlib_wire(&img)),
            ("tight_fill", encoding::TIGHT, tight_fill_wire()),
            (
                "tight_palette",
                encoding::TIGHT,
                tight_palette_wire(&img, w, h),
            ),
            (
                "tight_gradient",
                encoding::TIGHT,
                tight_gradient_wire(&img, w, h),
            ),
            ("tight_copy", encoding::TIGHT, tight_copy_wire(&img, w, h)),
            (
                "zrle_solid",
                encoding::ZRLE,
                zrle_frame(&zrle_solid_stream(&flat, w, h)),
            ),
            (
                "zrle_packed_palette",
                encoding::ZRLE,
                zrle_frame(&zrle_packed_palette_stream(&img, w, h)),
            ),
            (
                "zrle_rle",
                encoding::ZRLE,
                zrle_frame(&zrle_rle_stream(&flat, w, h)),
            ),
            (
                "zrle_palette_rle",
                encoding::ZRLE,
                zrle_frame(&zrle_palette_rle_stream(&flat, w, h)),
            ),
        ];

        let mut g = c.benchmark_group("decode");
        g.throughput(Throughput::Elements((w * h) as u64));
        g.sample_size(if w > 2000 { 20 } else { 30 });
        g.measurement_time(std::time::Duration::from_secs(4));
        g.warm_up_time(std::time::Duration::from_secs(1));

        for (name, enc, wire) in &cases {
            g.bench_with_input(BenchmarkId::new(*name, label), wire, |b, wire| {
                b.iter_batched_ref(
                    || DecoderState::new(pf()),
                    |st| decode_once(st, wire, rect, *enc),
                    BatchSize::SmallInput,
                );
            });
        }
        g.finish();
    }
}

fn bench_convert(c: &mut Criterion) {
    // A non-canonical true-colour layout: 32bpp big-endian with 10-bit
    // channels, nothing about it hits a fast path.
    let exotic = PixelFormat {
        bits_per_pixel: 32,
        depth: 30,
        big_endian: true,
        true_colour: true,
        red_max: 1023,
        green_max: 1023,
        blue_max: 1023,
        red_shift: 20,
        green_shift: 10,
        blue_shift: 0,
    };
    let rgb565 = PixelFormat {
        bits_per_pixel: 16,
        depth: 16,
        big_endian: false,
        true_colour: true,
        red_max: 31,
        green_max: 63,
        blue_max: 31,
        red_shift: 11,
        green_shift: 5,
        blue_shift: 0,
    };
    let map = ColourMap::new();

    for (w, h, label) in SIZES {
        let n = w * h;
        let mut g = c.benchmark_group("convert");
        g.throughput(Throughput::Elements(n as u64));
        g.sample_size(30);
        g.measurement_time(std::time::Duration::from_secs(4));
        g.warm_up_time(std::time::Duration::from_secs(1));

        let src32 = synth_desktop(w, h);
        let src16: Vec<u8> = (0..n * 2).map(|i| (i * 37) as u8).collect();
        let src8: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();

        g.bench_with_input(BenchmarkId::new("bgra8888_fast", label), &src32, |b, s| {
            b.iter(|| std::hint::black_box(convert_to_rgba(s, &pf(), n)))
        });
        g.bench_with_input(BenchmarkId::new("rgb565_16bpp", label), &src16, |b, s| {
            b.iter(|| std::hint::black_box(convert_to_rgba(s, &rgb565, n)))
        });
        g.bench_with_input(BenchmarkId::new("palette_8bpp", label), &src8, |b, s| {
            b.iter(|| {
                std::hint::black_box(convert_to_rgba_mapped(
                    s,
                    &PixelFormat::palette8(),
                    n,
                    Some(&map),
                ))
            })
        });
        g.bench_with_input(
            BenchmarkId::new("generic_shift_max", label),
            &src32,
            |b, s| b.iter(|| std::hint::black_box(convert_to_rgba(s, &exotic, n))),
        );
        g.finish();
    }
}

fn bench_framebuffer(c: &mut Criterion) {
    for (w, h, label) in SIZES {
        let mut g = c.benchmark_group("framebuffer");
        g.throughput(Throughput::Elements((w * h) as u64));
        g.sample_size(30);
        g.measurement_time(std::time::Duration::from_secs(4));
        g.warm_up_time(std::time::Duration::from_secs(1));

        let full = DecodedRect {
            rect: Rect::new(0, 0, w as u16, h as u16),
            payload: RectPayload::Rgba(synth_desktop(w, h)),
        };
        // Overlapping CopyRect: scroll the whole desktop up-left by 8 px.
        let scroll = DecodedRect {
            rect: Rect::new(0, 0, (w - 8) as u16, (h - 8) as u16),
            payload: RectPayload::CopyRect { src_x: 8, src_y: 8 },
        };

        g.bench_with_input(BenchmarkId::new("apply_rgba_full", label), &full, |b, d| {
            b.iter_batched_ref(
                || vnc_core::pixel::Framebuffer::new(w as u16, h as u16),
                |fb| fb.apply(d),
                BatchSize::LargeInput,
            );
        });
        g.bench_with_input(
            BenchmarkId::new("apply_copyrect_overlap", label),
            &scroll,
            |b, d| {
                b.iter_batched_ref(
                    || vnc_core::pixel::Framebuffer::new(w as u16, h as u16),
                    |fb| fb.apply(d),
                    // A 4K framebuffer is 33 MB; batching several would put the
                    // measurement under memory pressure rather than CPU load.
                    BatchSize::PerIteration,
                );
            },
        );
        g.finish();
    }
}

fn bench_thumbnail(c: &mut Criterion) {
    let (w, h) = (1920usize, 1080usize);
    let src = synth_desktop(w, h);
    let mut g = c.benchmark_group("thumbnail");
    g.throughput(Throughput::Elements((w * h) as u64));
    g.sample_size(30);
    g.measurement_time(std::time::Duration::from_secs(4));
    g.bench_function("1080p_to_480", |b| {
        b.iter(|| std::hint::black_box(downscale_rgba(&src, w as u32, h as u32, 480)))
    });
    g.finish();
}

fn bench_damage_union(c: &mut Criterion) {
    // A pathological update: many small scattered rects coalesced into one
    // damage region, exactly as run_loop does per FramebufferUpdate.
    const N: usize = 4096;
    let rects: Vec<Rect> = (0..N)
        .map(|i| {
            let x = ((i * 7919) % 1900) as u16;
            let y = ((i * 6271) % 1060) as u16;
            Rect::new(x, y, 16, 16)
        })
        .collect();

    let mut g = c.benchmark_group("damage");
    g.throughput(Throughput::Elements(N as u64));
    g.bench_function("union_4096_rects", |b| {
        b.iter(|| {
            let mut d = Rect::new(0, 0, 0, 0);
            for r in &rects {
                d = d.union(r);
            }
            std::hint::black_box(d)
        })
    });
    g.finish();
}

// ---------------------------------------------------------------------------
// Before/after: the pre-optimisation implementations, verbatim, so the
// speed-up of each change is measured in the same process on the same machine
// rather than compared across two runs.
// ---------------------------------------------------------------------------

// The point of this module is to be a *verbatim* copy of the code as it was
// before the optimisation pass, so lints that would ask us to modernise it are
// deliberately silenced here.
#[allow(clippy::manual_checked_ops, clippy::too_many_arguments)]
mod legacy {
    use vnc_core::types::PixelFormat;

    fn raw_pixel_value(bytes: &[u8], big_endian: bool) -> u32 {
        let mut v: u32 = 0;
        if big_endian {
            for &b in bytes {
                v = (v << 8) | b as u32;
            }
        } else {
            for &b in bytes.iter().rev() {
                v = (v << 8) | b as u32;
            }
        }
        v
    }

    fn scale_channel(c: u32, max: u16) -> u8 {
        if max == 0 {
            0
        } else {
            ((c * 255 + (max as u32) / 2) / max as u32) as u8
        }
    }

    fn value_to_rgba(v: u32, pf: &PixelFormat) -> [u8; 4] {
        if pf.true_colour {
            [
                scale_channel((v >> pf.red_shift) & pf.red_max as u32, pf.red_max),
                scale_channel((v >> pf.green_shift) & pf.green_max as u32, pf.green_max),
                scale_channel((v >> pf.blue_shift) & pf.blue_max as u32, pf.blue_max),
                255,
            ]
        } else {
            let idx = (v & 0xff) as u8;
            [idx, idx, idx, 255]
        }
    }

    /// The original `convert_to_rgba_mapped`: one canonical-BGRA fast path and
    /// an otherwise fully scalar per-pixel loop.
    pub fn convert_to_rgba(src: &[u8], pf: &PixelFormat, count: usize) -> Vec<u8> {
        let bpp = pf.bytes_per_pixel();
        let mut out = vec![0u8; count * 4];
        if bpp == 0 || bpp > 4 {
            return out;
        }
        let n = count.min(src.len() / bpp);
        if pf.true_colour
            && pf.bits_per_pixel == 32
            && !pf.big_endian
            && pf.red_max == 255
            && pf.green_max == 255
            && pf.blue_max == 255
            && pf.red_shift == 16
            && pf.green_shift == 8
            && pf.blue_shift == 0
        {
            for i in 0..n {
                let s = &src[i * 4..i * 4 + 4];
                let d = &mut out[i * 4..i * 4 + 4];
                d[0] = s[2];
                d[1] = s[1];
                d[2] = s[0];
                d[3] = 255;
            }
            for i in n..count {
                out[i * 4 + 3] = 255;
            }
            return out;
        }
        for i in 0..n {
            let px = value_to_rgba(
                raw_pixel_value(&src[i * bpp..(i + 1) * bpp], pf.big_endian),
                pf,
            );
            out[i * 4..i * 4 + 4].copy_from_slice(&px);
        }
        for i in n..count {
            out[i * 4 + 3] = 255;
        }
        out
    }

    /// The original `undo_gradient`, which scaled every channel of every pixel
    /// through a runtime division even when the channels were already 8-bit.
    pub fn undo_gradient(data: &[u8], pf: &PixelFormat, w: usize, h: usize, tpx: usize) -> Vec<u8> {
        let compact = tpx == 3;
        let maxes: [i32; 3] = if compact {
            [255, 255, 255]
        } else {
            [pf.red_max as i32, pf.green_max as i32, pf.blue_max as i32]
        };
        let shifts = [pf.red_shift, pf.green_shift, pf.blue_shift];
        let mut out = vec![0u8; w * h * 4];
        let mut prev: Vec<[i32; 3]> = vec![[0; 3]; w];
        let mut cur: Vec<[i32; 3]> = vec![[0; 3]; w];
        for y in 0..h {
            let mut left = [0i32; 3];
            for x in 0..w {
                let p = &data[(y * w + x) * tpx..(y * w + x) * tpx + tpx];
                let raw: [i32; 3] = if compact {
                    [p[0] as i32, p[1] as i32, p[2] as i32]
                } else {
                    let v = raw_pixel_value(p, pf.big_endian);
                    [
                        ((v >> shifts[0]) & maxes[0] as u32) as i32,
                        ((v >> shifts[1]) & maxes[1] as u32) as i32,
                        ((v >> shifts[2]) & maxes[2] as u32) as i32,
                    ]
                };
                let upleft = if x > 0 { prev[x - 1] } else { [0; 3] };
                let o = (y * w + x) * 4;
                for c in 0..3 {
                    let pred = (left[c] + prev[x][c] - upleft[c]).clamp(0, maxes[c]);
                    let v = (raw[c] + pred).rem_euclid(maxes[c] + 1);
                    cur[x][c] = v;
                    out[o + c] = scale_channel(v as u32, maxes[c] as u16);
                }
                out[o + 3] = 255;
                left = cur[x];
            }
            std::mem::swap(&mut prev, &mut cur);
        }
        out
    }

    /// The current compact-TPIXEL gradient kernel, mirroring
    /// `tight::undo_gradient_compact`, so the filter can be compared against
    /// its predecessor kernel-to-kernel (the decoder itself is private).
    pub fn undo_gradient_compact(data: &[u8], w: usize, h: usize) -> Vec<u8> {
        let mut out = vec![0u8; w * h * 4];
        let mut prev: Vec<[u8; 3]> = vec![[0; 3]; w];
        for (src_row, out_row) in data
            .chunks_exact(w * 3)
            .zip(out.chunks_exact_mut(w * 4))
            .take(h)
        {
            let mut left = [0u8; 3];
            let mut upleft = [0u8; 3];
            for ((s, d), up) in src_row
                .chunks_exact(3)
                .zip(out_row.chunks_exact_mut(4))
                .zip(prev.iter_mut())
            {
                let u = *up;
                let mut px = [0u8; 3];
                for c in 0..3 {
                    let pred =
                        (left[c] as i32 + u[c] as i32 - upleft[c] as i32).clamp(0, 255) as u8;
                    px[c] = s[c].wrapping_add(pred);
                }
                d[..3].copy_from_slice(&px);
                d[3] = 255;
                *up = px;
                upleft = u;
                left = px;
            }
        }
        out
    }

    /// The original CopyRect: snapshot the source region into a fresh heap
    /// buffer, then write it back.
    pub fn copy_rect_via_temp(
        data: &mut [u8],
        fb_w: usize,
        sx: usize,
        sy: usize,
        dx: usize,
        dy: usize,
        w: usize,
        h: usize,
    ) {
        let mut tmp = vec![0u8; w * h * 4];
        for row in 0..h {
            let src = ((sy + row) * fb_w + sx) * 4;
            tmp[row * w * 4..(row + 1) * w * 4].copy_from_slice(&data[src..src + w * 4]);
        }
        for row in 0..h {
            let dst = ((dy + row) * fb_w + dx) * 4;
            data[dst..dst + w * 4].copy_from_slice(&tmp[row * w * 4..(row + 1) * w * 4]);
        }
    }

    /// The current CopyRect strategy, mirroring `Framebuffer::copy_rect`.
    pub fn copy_rect_in_place(
        data: &mut [u8],
        fb_w: usize,
        sx: usize,
        sy: usize,
        dx: usize,
        dy: usize,
        w: usize,
        h: usize,
    ) {
        let row_bytes = w * 4;
        let copy_row = |row: usize, data: &mut [u8]| {
            let src = ((sy + row) * fb_w + sx) * 4;
            let dst = ((dy + row) * fb_w + dx) * 4;
            data.copy_within(src..src + row_bytes, dst);
        };
        if dy > sy {
            for row in (0..h).rev() {
                copy_row(row, data);
            }
        } else {
            for row in 0..h {
                copy_row(row, data);
            }
        }
    }
}

fn bench_before_after(c: &mut Criterion) {
    let (w, h) = (1920usize, 1080usize);
    let n = w * h;
    let img = synth_desktop(w, h);
    let rgb565 = PixelFormat {
        bits_per_pixel: 16,
        depth: 16,
        big_endian: false,
        true_colour: true,
        red_max: 31,
        green_max: 63,
        blue_max: 31,
        red_shift: 11,
        green_shift: 5,
        blue_shift: 0,
    };
    let exotic = PixelFormat {
        bits_per_pixel: 32,
        depth: 30,
        big_endian: true,
        true_colour: true,
        red_max: 1023,
        green_max: 1023,
        blue_max: 1023,
        red_shift: 20,
        green_shift: 10,
        blue_shift: 0,
    };
    let src16: Vec<u8> = (0..n * 2).map(|i| (i * 37) as u8).collect();
    let src8: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
    // The gradient-filtered residual bytes the filter kernel consumes.
    let grad = tight_gradient_data(&img, w, h);

    let mut g = c.benchmark_group("before_after");
    g.throughput(Throughput::Elements(n as u64));
    g.sample_size(30);
    g.measurement_time(std::time::Duration::from_secs(4));
    g.warm_up_time(std::time::Duration::from_secs(1));

    macro_rules! pair {
        ($name:literal, $legacy:expr, $current:expr) => {
            g.bench_function(concat!($name, "/legacy"), |b| {
                b.iter(|| std::hint::black_box($legacy))
            });
            g.bench_function(concat!($name, "/current"), |b| {
                b.iter(|| std::hint::black_box($current))
            });
        };
    }

    pair!(
        "convert_bgra8888",
        legacy::convert_to_rgba(&img, &pf(), n),
        convert_to_rgba(&img, &pf(), n)
    );
    pair!(
        "convert_rgb565",
        legacy::convert_to_rgba(&src16, &rgb565, n),
        convert_to_rgba(&src16, &rgb565, n)
    );
    pair!(
        "convert_palette8",
        legacy::convert_to_rgba(&src8, &PixelFormat::palette8(), n),
        convert_to_rgba(&src8, &PixelFormat::palette8(), n)
    );
    pair!(
        "convert_generic_10bit",
        legacy::convert_to_rgba(&img, &exotic, n),
        convert_to_rgba(&img, &exotic, n)
    );
    pair!(
        "tight_gradient_filter",
        legacy::undo_gradient(&grad, &pf(), w, h, 3),
        legacy::undo_gradient_compact(&grad, w, h)
    );

    // Sanity: the two kernels must agree, or the comparison is meaningless.
    assert_eq!(
        legacy::undo_gradient(&grad, &pf(), w, h, 3),
        legacy::undo_gradient_compact(&grad, w, h),
        "gradient kernels disagree"
    );

    // CopyRect: scroll the whole desktop by 8 px, source and destination
    // overlapping, on a real 1080p RGBA buffer.
    let scratch = vec![0u8; n * 4];
    g.bench_function("copy_rect_overlap/legacy", |b| {
        b.iter_batched_ref(
            || scratch.clone(),
            |d| legacy::copy_rect_via_temp(d, w, 8, 8, 0, 0, w - 8, h - 8),
            BatchSize::PerIteration,
        )
    });
    g.bench_function("copy_rect_overlap/current", |b| {
        b.iter_batched_ref(
            || scratch.clone(),
            |d| legacy::copy_rect_in_place(d, w, 8, 8, 0, 0, w - 8, h - 8),
            BatchSize::PerIteration,
        )
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_decoders,
    bench_convert,
    bench_framebuffer,
    bench_thumbnail,
    bench_damage_union,
    bench_before_after
);
criterion_main!(benches);
