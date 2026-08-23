//! Criterion benchmarks for the RDP bitmap decoders.
//!
//! Structure copied from `crates/vnc-core/benches/decode.rs`: wire data is
//! synthesised once, outside the timed loop, from a desktop-like test image,
//! and the timed region contains only the decoder. Throughput is reported with
//! `Throughput::Elements(pixels)` so criterion prints `Melem/s`, which reads as
//! MPixels/s and is comparable across resolutions and against
//! `docs/PERFORMANCE.md`.
//!
//! The groups are the ones PRDRDP/04 §11.4 names, restricted to the phase 1a
//! decoders: `rdp_decode` for a whole codec through its real public entry
//! point, `rdp_stage` for the split in §11.2 so a miss can be attributed,
//! `rdp_convert` for the pixel conversion, and `before_after` for each
//! optimised routine against a copy of its pre optimisation self in the same
//! process.
//!
//! One deliberate difference from the VNC benches. There the output `Vec`
//! allocation sits inside the timed region because that is what the VNC path
//! really does. Here every destination is caller owned and pooled by design
//! (PRDRDP/04 §4.1 rule two), so the buffers are allocated once outside the
//! loop and reused, which is what `rdp-core` will do.
//!
//! Honest caveats, carried forward from `docs/PERFORMANCE.md` §1.2: runs on a
//! loaded machine swing two to three times, so report the minimum of the lower
//! confidence bound across three repetitions, and run with the shipped target
//! features rather than `-C target-cpu=native`, because a number produced with
//! AVX2 is not a number we can ship.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use rdp_codecs::mppc::{MppcDecompressor, Variant, PACKET_AT_FRONT, PACKET_COMPRESSED};
use rdp_codecs::remotefx::{dwt, quant, rlgr, ycbcr, Entropy, RfxContext, RfxScratch, TILE};
use rdp_codecs::{
    avc420, clear, encode, mppc, nscodec, planar, remotefx, rle, uncompressed, zgfx, DstView,
    OutFormat, Palette, PixelFormat, RowOrder,
};

const SIZES: [(usize, usize, &str); 2] = [(1920, 1080, "1080p"), (3840, 2160, "4k")];

// ---------------------------------------------------------------------------
// Test content
// ---------------------------------------------------------------------------

/// One channel of a desktop-like image: flat window panes, a wallpaper
/// gradient and text-like high frequency detail. This mix is what decides
/// whether an encoder picks a run, a literal or a copy from the row above, and
/// noise would make every RLE number artificially bad.
fn synth_plane(w: usize, h: usize, seed: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            let pane = (x / 320 + y / 240) % 3;
            out[y * w + x] = match pane {
                0 => {
                    // Light document window with text-like runs.
                    if (y % 18) < 9 && ((x * 7 + y * 13) % 23) < 6 {
                        (24 + seed) as u8
                    } else {
                        (246 - seed) as u8
                    }
                }
                1 => (32 + seed * 2) as u8, // dark terminal pane
                _ => (60 + y * 100 / h + seed) as u8, // wallpaper gradient
            };
        }
    }
    out
}

fn planes(w: usize, h: usize) -> [Vec<u8>; 4] {
    [
        synth_plane(w, h, 0),
        synth_plane(w, h, 7),
        synth_plane(w, h, 14),
        synth_plane(w, h, 21),
    ]
}

/// Interleave channel planes into a tightly packed wire image of
/// `bytes_per_pixel` bytes per pixel.
fn interleave(src: &[Vec<u8>], w: usize, h: usize, bytes_per_pixel: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h * bytes_per_pixel];
    for i in 0..w * h {
        for c in 0..bytes_per_pixel {
            out[i * bytes_per_pixel + c] = src[c][i];
        }
    }
    out
}

/// A legacy DIB body: the same pixels with each row padded to four bytes. The
/// content is not flipped here; the flip is the decoder's job and it is a
/// destination index (PRDRDP/04 §2.3).
fn dib(packed: &[u8], w: usize, h: usize, bits_per_pixel: u8) -> Vec<u8> {
    let stride = uncompressed::dib_stride(w as u16, bits_per_pixel);
    let row = w * usize::from(bits_per_pixel) / 8;
    let mut out = vec![0u8; stride * h];
    for y in 0..h {
        out[y * stride..y * stride + row].copy_from_slice(&packed[y * row..y * row + row]);
    }
    out
}

// ---------------------------------------------------------------------------
// rdp_decode: each codec through its real public entry point
// ---------------------------------------------------------------------------

fn bench_decode(c: &mut Criterion) {
    let pal = Palette::default();
    for (w, h, label) in SIZES {
        let ch = planes(w, h);
        let n = (w * h) as u64;
        let mut g = c.benchmark_group("rdp_decode");
        g.throughput(Throughput::Elements(n));

        // Uncompressed 32 bpp, bottom up, with the four byte row padding.
        let packed32 = interleave(&ch, w, h, 4);
        let dib32 = dib(&packed32, w, h, 32);
        let mut out = vec![0u8; uncompressed::dst_len(w as u16, h as u16)];
        g.bench_function(BenchmarkId::new("uncompressed_bottom_up", label), |b| {
            b.iter(|| {
                let mut v = DstView::packed(
                    &mut out,
                    w as u16,
                    h as u16,
                    OutFormat::Rgba,
                    RowOrder::BottomUp,
                )
                .unwrap();
                uncompressed::decode_legacy(32, &dib32, &pal, &mut v).unwrap()
            })
        });

        // Interleaved RLE, whole codec: the order decode into the wire format
        // scratch plus the conversion into RGBA, which is what §11.1's number
        // covers.
        for (bits, fmt, id) in [
            (16u8, PixelFormat::Rgb565, "rle_16bpp"),
            (24, PixelFormat::Bgr24, "rle_24bpp"),
        ] {
            let bytes = usize::from(bits) / 8;
            let packed = interleave(&ch, w, h, bytes);
            let wire = encode::interleaved(bits, &packed, w, h);
            let mut scratch = vec![0u8; rle::scratch_len(bits, w as u16, h as u16).unwrap()];
            g.bench_function(BenchmarkId::new(id, label), |b| {
                b.iter(|| {
                    rle::decode_bpp(bits, &wire, &mut scratch, w as u16, h as u16).unwrap();
                    let mut v = DstView::packed(
                        &mut out,
                        w as u16,
                        h as u16,
                        OutFormat::Rgba,
                        RowOrder::BottomUp,
                    )
                    .unwrap();
                    uncompressed::decode(fmt, &scratch, w * bytes, &pal, &mut v).unwrap()
                })
            });
        }

        // Planar, with and without an alpha plane.
        let three = [&ch[0][..], &ch[1][..], &ch[2][..]];
        let four = [&ch[3][..], &ch[0][..], &ch[1][..], &ch[2][..]];
        let mut scratch = planar::PlanarScratch::with_capacity(w as u16, h as u16);
        for (src, want_alpha, id) in [
            (encode::planar(&three, w, h, true), false, "planar"),
            (encode::planar(&four, w, h, true), true, "planar_alpha"),
        ] {
            g.bench_function(BenchmarkId::new(id, label), |b| {
                b.iter(|| {
                    let mut v = DstView::packed(
                        &mut out,
                        w as u16,
                        h as u16,
                        OutFormat::Rgba,
                        RowOrder::BottomUp,
                    )
                    .unwrap();
                    planar::decode(&src, want_alpha, &mut scratch, &mut v).unwrap()
                })
            });
        }
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// rdp_stage: the split of PRDRDP/04 §11.2, so a miss names its own stage
// ---------------------------------------------------------------------------

fn bench_stage(c: &mut Criterion) {
    let pal = Palette::default();
    for (w, h, label) in SIZES {
        let ch = planes(w, h);
        let n = (w * h) as u64;
        let mut g = c.benchmark_group("rdp_stage");
        g.throughput(Throughput::Elements(n));

        // Stage one of interleaved RLE: order decode into the wire scratch.
        let packed16 = interleave(&ch, w, h, 2);
        let wire16 = encode::interleaved(16, &packed16, w, h);
        let mut scratch = vec![0u8; packed16.len()];
        g.bench_function(BenchmarkId::new("interleaved", label), |b| {
            b.iter(|| rle::decode_bpp(16, &wire16, &mut scratch, w as u16, h as u16).unwrap())
        });

        // Stage two: the conversion into RGBA, which is also PRDRDP/04 §4.2's
        // `convert_image` and which every legacy codec ends with.
        let mut out = vec![0u8; uncompressed::dst_len(w as u16, h as u16)];
        g.bench_function(BenchmarkId::new("rle_convert", label), |b| {
            b.iter(|| {
                let mut v = DstView::packed(
                    &mut out,
                    w as u16,
                    h as u16,
                    OutFormat::Rgba,
                    RowOrder::BottomUp,
                )
                .unwrap();
                uncompressed::decode(PixelFormat::Rgb565, &scratch, w * 2, &pal, &mut v).unwrap()
            })
        });

        // Planar stage one, the run length pass over one plane, and stage two,
        // the delta pass. Four planes per bitmap, so the whole codec budget is
        // four of each.
        let one = encode::planar(&[&ch[0][..], &ch[0][..], &ch[0][..]], w, h, true);
        // Skip the format header and take the first plane's segments.
        let plane_stream = one[1..].to_vec();
        let mut plane = vec![0u8; w * h];
        g.bench_function(BenchmarkId::new("planar_rle", label), |b| {
            b.iter(|| planar::stages::plane_rle(&plane_stream, &mut plane, w, h).unwrap())
        });
        g.bench_function(BenchmarkId::new("planar_delta", label), |b| {
            b.iter(|| planar::stages::plane_delta(&mut plane, w, h))
        });
        g.finish();
    }
}

// ---------------------------------------------------------------------------
// rdp_convert: the pixel conversion, per wire format
// ---------------------------------------------------------------------------

fn bench_convert(c: &mut Criterion) {
    let pal = Palette::default();
    let (w, h) = (1920usize, 1080usize);
    let ch = planes(w, h);
    let mut out = vec![0u8; uncompressed::dst_len(w as u16, h as u16)];
    let mut g = c.benchmark_group("rdp_convert");
    g.throughput(Throughput::Elements((w * h) as u64));

    for (fmt, id) in [
        (PixelFormat::BgrX32, "bgrx32"),
        (PixelFormat::BgrA32, "bgra32"),
        (PixelFormat::Bgr24, "bgr24"),
        (PixelFormat::Rgb565, "rgb565"),
        (PixelFormat::Rgb555, "rgb555"),
        (PixelFormat::Palette8, "palette8"),
        (PixelFormat::Mono1, "mono1"),
    ] {
        let bytes = fmt.row_bytes(w as u16);
        let src = interleave(&ch, w, h, 4)[..bytes * h].to_vec();
        g.bench_function(id, |b| {
            b.iter(|| {
                let mut v = DstView::packed(
                    &mut out,
                    w as u16,
                    h as u16,
                    OutFormat::Rgba,
                    RowOrder::TopDown,
                )
                .unwrap();
                uncompressed::decode(fmt, &src, bytes, &pal, &mut v).unwrap()
            })
        });
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// before_after: each optimisation against a copy of its pre optimisation self
// ---------------------------------------------------------------------------

/// The implementation PRDRDP/04 §2.3 rejects: flip the wire image into a top
/// down scratch and then convert it. Kept verbatim so the cost of the second
/// full copy is a measured number rather than an assertion.
fn flip_then_convert(
    src: &[u8],
    src_stride: usize,
    w: usize,
    h: usize,
    scratch: &mut [u8],
    pal: &Palette,
    dst: &mut [u8],
) {
    // Fixed at the 32 bpp layout, which is the one the pair compares.
    let fmt = PixelFormat::BgrX32;
    let row = fmt.row_bytes(w as u16);
    for y in 0..h {
        let from = (h - 1 - y) * src_stride;
        scratch[y * row..y * row + row].copy_from_slice(&src[from..from + row]);
    }
    let mut v =
        DstView::packed(dst, w as u16, h as u16, OutFormat::Rgba, RowOrder::TopDown).unwrap();
    uncompressed::decode(fmt, scratch, row, pal, &mut v).unwrap();
}

/// The plane interleave written the way rule two of PRDRDP/04 §4.6.8 says not
/// to: a computed index into each plane inside the loop, so every iteration
/// carries four bounds checks and LLVM has a panic path to preserve.
fn interleave_indexed(r: &[u8], g: &[u8], b: &[u8], w: usize, h: usize, dst: &mut [u8]) {
    for y in 0..h {
        for x in 0..w {
            let i = y * w + x;
            dst[i * 4] = r[i];
            dst[i * 4 + 1] = g[i];
            dst[i * 4 + 2] = b[i];
            dst[i * 4 + 3] = 0xFF;
        }
    }
}

/// The same interleave with the bounds proved once per row and the bodies
/// zipped, which is what `planar::interleave` does.
fn interleave_zipped(r: &[u8], g: &[u8], b: &[u8], w: usize, h: usize, dst: &mut [u8]) {
    for y in 0..h {
        let (rr, gg, bb) = (&r[y * w..][..w], &g[y * w..][..w], &b[y * w..][..w]);
        let row = &mut dst[y * w * 4..][..w * 4];
        for (((&r, &g), &b), o) in rr.iter().zip(gg).zip(bb).zip(row.chunks_exact_mut(4)) {
            o[0] = r;
            o[1] = g;
            o[2] = b;
            o[3] = 0xFF;
        }
    }
}

fn bench_before_after(c: &mut Criterion) {
    let pal = Palette::default();
    let (w, h) = (1920usize, 1080usize);
    let ch = planes(w, h);
    let packed = interleave(&ch, w, h, 4);
    let src = dib(&packed, w, h, 32);
    let stride = uncompressed::dib_stride(w as u16, 32);
    let mut scratch = vec![0u8; w * 4 * h];
    let mut out = vec![0u8; uncompressed::dst_len(w as u16, h as u16)];

    let mut g = c.benchmark_group("before_after");
    g.throughput(Throughput::Elements((w * h) as u64));

    g.bench_function("bottom_up_convert/legacy_scratch", |b| {
        b.iter(|| flip_then_convert(&src, stride, w, h, &mut scratch, &pal, &mut out))
    });
    g.bench_function("bottom_up_convert/current", |b| {
        b.iter(|| {
            let mut v = DstView::packed(
                &mut out,
                w as u16,
                h as u16,
                OutFormat::Rgba,
                RowOrder::BottomUp,
            )
            .unwrap();
            uncompressed::decode(PixelFormat::BgrX32, &src, stride, &pal, &mut v).unwrap()
        })
    });

    g.bench_function("planar_interleave/indexed", |b| {
        b.iter(|| interleave_indexed(&ch[0], &ch[1], &ch[2], w, h, &mut out))
    });
    g.bench_function("planar_interleave/zipped", |b| {
        b.iter(|| interleave_zipped(&ch[0], &ch[1], &ch[2], w, h, &mut out))
    });

    // Sanity: the two kernels must agree, or the comparison is meaningless.
    let mut a = vec![0u8; out.len()];
    let mut z = vec![0u8; out.len()];
    interleave_indexed(&ch[0], &ch[1], &ch[2], w, h, &mut a);
    interleave_zipped(&ch[0], &ch[1], &ch[2], w, h, &mut z);
    assert_eq!(a, z, "interleave kernels disagree");
    g.finish();
}

// ---------------------------------------------------------------------------
// Phase 2 fixtures: RemoteFX, NSCodec, ClearCodec and ZGFX
// ---------------------------------------------------------------------------

/// The synthetic desktop as B, G, R triples, which is what every phase 2
/// codec takes.
fn rgb_image(w: usize, h: usize) -> Vec<[u8; 3]> {
    let ch = planes(w, h);
    (0..w * h).map(|i| [ch[0][i], ch[1][i], ch[2][i]]).collect()
}

/// Photographic content: smooth gradients with a little grain.
///
/// This is the fixture RemoteFX is measured on, and the choice is a
/// decision rather than a convenience. A server picks RemoteFX for the
/// photographic parts of the screen and planar for the text
/// (PRDRDP/04 §4.5), so measuring the wavelet codec on the text-like image
/// the legacy benches use would measure content it is never sent. The
/// difference is not small: the same tile through the same encoder is three
/// kilobytes of entropy coded coefficients as text and a few hundred bytes
/// as a gradient, so the fixture decides the number more than the code does.
/// `remotefx_text` below carries the pessimistic case so both are on record.
fn photo_image(w: usize, h: usize) -> Vec<[u8; 3]> {
    let mut out = vec![[0u8; 3]; w * h];
    for y in 0..h {
        for x in 0..w {
            // Two overlapping gradients plus a low amplitude grain, which is
            // what a photograph or a blurred desktop wallpaper looks like to
            // a wavelet.
            let grain = (((x * 31 + y * 17) % 11) as i32) - 5;
            let r = (40 + x * 180 / w) as i32 + grain;
            let g = (20 + y * 200 / h) as i32 + grain;
            let b = (200 - (x + y) * 120 / (w + h)) as i32 + grain;
            out[y * w + x] = [
                r.clamp(0, 255) as u8,
                g.clamp(0, 255) as u8,
                b.clamp(0, 255) as u8,
            ];
        }
    }
    out
}

/// Cut one 64 by 64 tile out of the image, replicating the edges when the
/// tile hangs off the right or the bottom, which is what a server does.
fn tile_at(img: &[[u8; 3]], w: usize, h: usize, tx: usize, ty: usize) -> Vec<[u8; 3]> {
    let mut out = vec![[0u8; 3]; TILE * TILE];
    for y in 0..TILE {
        for x in 0..TILE {
            let sx = (tx * TILE + x).min(w - 1);
            let sy = (ty * TILE + y).min(h - 1);
            out[y * TILE + x] = img[sy * w + sx];
        }
    }
    out
}

/// A whole frame of RemoteFX tiles, which is 510 of them at 1080p.
fn rfx_frame(mode: Entropy, w: usize, h: usize, photo: bool) -> Vec<u8> {
    let img = if photo {
        photo_image(w, h)
    } else {
        rgb_image(w, h)
    };
    let mut tiles = Vec::new();
    for ty in 0..h.div_ceil(TILE) {
        for tx in 0..w.div_ceil(TILE) {
            tiles.push((tx as u16, ty as u16, tile_at(&img, w, h, tx, ty)));
        }
    }
    // The typical table rather than the fine one the correctness tests use.
    // A uniform table leaves most level 1 coefficients non zero, which is not
    // what a server sends and which measures the fixture rather than the
    // codec (`encode::RFX_QUANT_TYPICAL`).
    encode::rfx_message_quant(mode, &tiles, w as u16, h as u16, &encode::RFX_QUANT_TYPICAL)
}

/// One component's quantized coefficients and its RLGR bitstream, which is
/// what the entropy stage bench measures on its own.
///
/// It is the **luma** component, and that is not a shortcut. The three
/// components of a tile do not cost the same and are not close: the chroma of
/// this fixture is nearly free, because the grain is added equally to all
/// three channels and MS-RDPRFX 3.1.8.1.3's Cb and Cr rows sum to zero, so it
/// cancels there and passes through the luma row untouched. Real content
/// behaves the same way for the same reason, which is why a codec puts its
/// bits in the luma. So this number is the expensive third of a tile and the
/// whole codec bench above is what the §11.1 target is actually about.
/// The tile the stage benches use, cut out of a full 1080p image rather than
/// synthesised at 64 by 64.
///
/// Synthesising the fixture at tile size looks equivalent and is not: a
/// gradient that spans its whole range across 64 pixels is forty times
/// steeper than the same gradient across 1920, so it lands far more energy in
/// the level 1 bands and the entropy stage measures three times slower. The
/// stage numbers have to add up to the whole codec number or neither is worth
/// reading, so both are cut from the same image.
fn rfx_component(mode: Entropy, photo: bool) -> (Vec<u8>, Vec<i16>) {
    let (fw, fh) = (1920usize, 1080usize);
    let full = if photo {
        photo_image(fw, fh)
    } else {
        rgb_image(fw, fh)
    };
    // A tile from the middle, so it is representative rather than an edge.
    let img = tile_at(&full, fw, fh, 15, 8);
    let mut tile = vec![0i16; 4096];
    for (i, p) in img.iter().enumerate() {
        // The luma of MS-RDPRFX 3.1.8.1.3, at the five fractional bit scale
        // the wavelet stage works in.
        let y = 0.299 * f64::from(p[0]) + 0.587 * f64::from(p[1]) + 0.114 * f64::from(p[2]);
        tile[i] = (y * 32.0 - 4096.0).round() as i16;
    }
    let mut coef = vec![0i16; 4096];
    dwt::forward::forward_2d(&tile, &mut coef);
    for (off, n, qi) in quant::BANDS {
        let shift = u32::from(encode::RFX_QUANT_TYPICAL[qi] - 1);
        for v in coef[off..off + n].iter_mut() {
            *v >>= shift;
        }
    }
    (encode::rlgr(mode, &coef), coef)
}

fn bench_phase2_decode(c: &mut Criterion) {
    let (w, h) = (1920usize, 1080usize);
    let n = (w * h) as u64;
    let img = rgb_image(w, h);
    let mut out = vec![0u8; uncompressed::dst_len(w as u16, h as u16)];

    let mut g = c.benchmark_group("rdp_decode");
    g.throughput(Throughput::Elements(n));

    // RemoteFX, whole codec through its real entry point, both entropy
    // variants. PRDRDP/04 §11.1 asks for 400 MPix/s, which is 5.2 ms.
    for (mode, photo, id) in [
        (Entropy::Rlgr1, true, "remotefx_rlgr1"),
        (Entropy::Rlgr3, true, "remotefx_rlgr3"),
        (Entropy::Rlgr3, false, "remotefx_text"),
    ] {
        let msg = rfx_frame(mode, w, h, photo);
        let mut ctx = RfxContext::new();
        let mut scratch = RfxScratch::with_capacity();
        g.bench_function(BenchmarkId::new(id, "1080p"), |b| {
            b.iter(|| {
                let mut v = DstView::packed(
                    &mut out,
                    w as u16,
                    h as u16,
                    OutFormat::Bgra,
                    RowOrder::TopDown,
                )
                .unwrap();
                remotefx::decode_message(&msg, &mut ctx, &mut scratch, &mut v).unwrap()
            })
        });
    }

    // NSCodec, both with and without chroma subsampling. §11.1 asks for
    // 400 MPix/s.
    for (css, id) in [(false, "nscodec"), (true, "nscodec_subsampled")] {
        let src = encode::nscodec(&img, w, h, 1, css, true);
        let mut scratch = nscodec::NscScratch::with_capacity(w as u16, h as u16);
        g.bench_function(BenchmarkId::new(id, "1080p"), |b| {
            b.iter(|| {
                let mut v = DstView::packed(
                    &mut out,
                    w as u16,
                    h as u16,
                    OutFormat::Bgra,
                    RowOrder::TopDown,
                )
                .unwrap();
                nscodec::decode(&src, &mut scratch, &mut v).unwrap()
            })
        });
    }

    // ClearCodec through the residual layer, which is the layer that has to
    // cover a whole bitmap. §11.1 asks for 300 MPix/s.
    let src = encode::clear::residual_only(&img, w as u16, h as u16);
    let mut dec = clear::ClearDecoder::new();
    g.bench_function(BenchmarkId::new("clearcodec_residual", "1080p"), |b| {
        b.iter(|| {
            let mut v = DstView::packed(
                &mut out,
                w as u16,
                h as u16,
                OutFormat::Bgra,
                RowOrder::TopDown,
            )
            .unwrap();
            // A fresh sequence every iteration, because the decoder enforces
            // the increment and the bench must not be measuring an error
            // path.
            dec.reset();
            dec.decode(&src, &mut v).unwrap()
        })
    });
    g.finish();
}

fn bench_phase2_stage(c: &mut Criterion) {
    let mut g = c.benchmark_group("rdp_stage");

    // The four RemoteFX stages of PRDRDP/04 §11.2, each reported in
    // coefficients per second so the table's Mcoef/s numbers read directly.
    // A 1080p frame is 1530 components of 4096, so the budget per component
    // is the table's millisecond figure divided by 1530.
    g.throughput(Throughput::Elements(4096));
    for (mode, photo, id) in [
        (Entropy::Rlgr1, true, "rfx_rlgr1"),
        (Entropy::Rlgr3, true, "rfx_rlgr3"),
        (Entropy::Rlgr1, false, "rfx_rlgr1_text"),
        (Entropy::Rlgr3, false, "rfx_rlgr3_text"),
    ] {
        let (bits, _) = rfx_component(mode, photo);
        let mut dst = vec![0i16; 4096];
        g.bench_function(BenchmarkId::new(id, "tile"), |b| {
            b.iter(|| rlgr::decode(mode, &bits, &mut dst))
        });
    }

    let (_, coef) = rfx_component(Entropy::Rlgr3, true);
    let q = [6u8; 10];
    let mut buf = coef.clone();
    g.bench_function(BenchmarkId::new("rfx_quant", "tile"), |b| {
        b.iter(|| {
            quant::differential_ll3(&mut buf);
            quant::dequantize(&mut buf, &q).unwrap()
        })
    });

    let mut buf = coef.clone();
    let mut tmp = vec![0i16; 4096];
    g.bench_function(BenchmarkId::new("rfx_dwt", "tile"), |b| {
        b.iter(|| dwt::inverse_2d(&mut buf, &mut tmp))
    });

    let (y, cb, cr) = (coef.clone(), coef.clone(), coef.clone());
    let mut px = vec![0u8; 4096 * 4];
    g.bench_function(BenchmarkId::new("rfx_ycbcr", "tile"), |b| {
        b.iter(|| {
            for row in 0..TILE {
                ycbcr::row::<true>(
                    &y[row * TILE..][..TILE],
                    &cb[row * TILE..][..TILE],
                    &cr[row * TILE..][..TILE],
                    &mut px[row * TILE * 4..][..TILE * 4],
                );
            }
        })
    });

    // NSCodec and ClearCodec, split the way §11.2's second table splits them.
    let (w, h) = (1920usize, 1080usize);
    let img = rgb_image(w, h);
    let mut out = vec![0u8; uncompressed::dst_len(w as u16, h as u16)];
    g.throughput(Throughput::Elements((w * h) as u64));

    let src = encode::nscodec(&img, w, h, 1, false, true);
    let raw = encode::nscodec(&img, w, h, 1, false, false);
    let mut scratch = nscodec::NscScratch::with_capacity(w as u16, h as u16);
    for (data, id) in [(&src, "nsc_plane_rle"), (&raw, "nsc_plane_raw")] {
        g.bench_function(BenchmarkId::new(id, "1080p"), |b| {
            b.iter(|| {
                let mut v = DstView::packed(
                    &mut out,
                    w as u16,
                    h as u16,
                    OutFormat::Bgra,
                    RowOrder::TopDown,
                )
                .unwrap();
                nscodec::decode(data, &mut scratch, &mut v).unwrap()
            })
        });
    }

    // ClearCodec bands: one band covering the whole bitmap, every column a
    // short VBar cache miss, which is the worst case for that layer because
    // every column is inserted into both caches.
    let cols: Vec<(usize, Vec<[u8; 3]>)> = (0..w)
        .map(|x| {
            (
                x % 200,
                (0..63u8).map(|i| [i, i.wrapping_add(60), 200]).collect(),
            )
        })
        .collect();
    let bands = encode::clear::band_short_miss(w as u16, h as u16, &[8, 16, 24], &cols);
    let mut dec = clear::ClearDecoder::new();
    g.bench_function(BenchmarkId::new("clear_bands", "1080p"), |b| {
        b.iter(|| {
            let mut v = DstView::packed(
                &mut out,
                w as u16,
                h as u16,
                OutFormat::Bgra,
                RowOrder::TopDown,
            )
            .unwrap();
            dec.reset();
            dec.decode(&bands, &mut v).unwrap()
        })
    });

    // ClearCodec subcodec: a flat residual layer, which costs one run, plus
    // one subcodec rectangle covering the whole bitmap. So the number is the
    // subcodec layer with a rounding error of a residual run on top.
    let flat = vec![[0u8, 0, 0]; w * h];
    for (id, sub) in [("clear_subcodec_raw", 0u8), ("clear_subcodec_rlex", 2)] {
        let rect: Vec<[u8; 3]> = if sub == 2 {
            // RLEX carries at most 127 palette entries, so the rectangle it
            // is measured on is quantized to that many colours. A real
            // encoder picks RLEX for exactly that kind of content.
            img.iter()
                .map(|p| [p[0] & 0xE0, p[1] & 0xE0, p[2] & 0xC0])
                .collect()
        } else {
            img.clone()
        };
        let src = encode::clear::residual_plus_subcodec(
            &flat, w as u16, h as u16, 0, 0, w as u16, h as u16, sub, &rect,
        );
        g.bench_function(BenchmarkId::new(id, "1080p"), |b| {
            b.iter(|| {
                let mut v = DstView::packed(
                    &mut out,
                    w as u16,
                    h as u16,
                    OutFormat::Bgra,
                    RowOrder::TopDown,
                )
                .unwrap();
                dec.reset();
                dec.decode(&src, &mut v).unwrap()
            })
        });
    }
    g.finish();

    // ZGFX is measured in output bytes rather than pixels, because it wraps
    // every EGFX codec rather than producing pixels of its own
    // (PRDRDP/04 §11.2). The target is 400 MB/s of output.
    let mut g = c.benchmark_group("rdp_stage");
    let payload: Vec<u8> = {
        // EGFX traffic is PDU headers and codec payloads, so a mix of highly
        // repetitive structure and incompressible bitstream is the honest
        // fixture. Random noise alone would measure only the literal path.
        let mut v = Vec::with_capacity(1 << 20);
        while v.len() < (1 << 20) {
            v.extend_from_slice(&[0x0E, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]);
            v.extend_from_slice(&img[v.len() % img.len()][..]);
            v.extend_from_slice(&[0u8; 24]);
        }
        v.truncate(1 << 20);
        v
    };
    let compressed = encode::zgfx::single_compressed(&payload);
    g.throughput(Throughput::Bytes(payload.len() as u64));
    let mut zd = zgfx::Rdp8Decompressor::new();
    let mut zout = Vec::with_capacity(payload.len());
    g.bench_function(BenchmarkId::new("zgfx", "1MiB"), |b| {
        b.iter(|| zd.decompress(&compressed, &mut zout).unwrap())
    });
    let uncompressed_seg = encode::zgfx::single_uncompressed(&payload);
    g.bench_function(BenchmarkId::new("zgfx_uncompressed", "1MiB"), |b| {
        b.iter(|| zd.decompress(&uncompressed_seg, &mut zout).unwrap())
    });
    g.finish();
}

// ---------------------------------------------------------------------------
// AVC420 and MPPC
// ---------------------------------------------------------------------------

/// A synthetic H.264 Annex B access unit of roughly `bytes` bytes.
///
/// Entropy coded video is close to uniform over the byte values, except that
/// emulation prevention keeps `00 00 0x` out of the payload, so the fixture
/// carries isolated zeros and no pair of them. That distribution is what
/// decides how often the word at a time start code scan has to fall back to a
/// byte scan, so getting it wrong would flatter the number.
fn access_unit(bytes: usize, idr: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes + 32);
    v.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x64, 0x00, 0x1F]); // SPS
    v.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xEB, 0xE3, 0xCB]); // PPS
    v.extend_from_slice(&[0, 0, 0, 1, if idr { 0x65 } else { 0x41 }]);
    let mut x = 0x1234_5678u32;
    let mut last_zero = false;
    while v.len() < bytes {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let b = (x >> 24) as u8;
        // Never two zeros in a row, which is what emulation prevention
        // guarantees a real encoder produces.
        let b = if b == 0 && last_zero { 0x03 } else { b };
        last_zero = b == 0;
        v.push(b);
    }
    v
}

/// A metablock naming `count` region rectangles, followed by `unit`.
fn avc420_stream(count: usize, unit: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + count * 10 + unit.len());
    v.extend_from_slice(&(count as u32).to_le_bytes());
    for i in 0..count {
        let x = ((i % 120) * 16) as u16;
        let y = ((i / 120) * 16) as u16;
        v.extend_from_slice(&x.to_le_bytes());
        v.extend_from_slice(&y.to_le_bytes());
        v.extend_from_slice(&(x + 16).to_le_bytes());
        v.extend_from_slice(&(y + 16).to_le_bytes());
    }
    for _ in 0..count {
        v.extend_from_slice(&[0x96, 100]);
    }
    v.extend_from_slice(unit);
    v
}

/// AVC420 and MPPC, the last two phase 2 modules.
///
/// AVC420 is reported two ways because it has two costs with different shapes.
/// The metablock parse is per region rectangle and is nothing; the IDR scan is
/// per byte of access unit and is the only part that can miss the 50
/// microsecond per frame budget of PRDRDP/04 §11.1. `avc420_frame` is the
/// whole Rust side of one frame together, which is the number that budget is
/// actually about.
///
/// MPPC is reported in output bytes per second, like ZGFX, because it produces
/// bytes rather than pixels. One packet is at most one history buffer, so the
/// RDP 4.0 fixture is 8 KiB and the RDP 5.0 one is 64 KiB, which is also the
/// largest packet either can legally produce.
fn bench_phase2_bulk(c: &mut Criterion) {
    let mut g = c.benchmark_group("rdp_stage");

    // The delta frame is the case that matters, because an access unit with no
    // IDR in it is scanned all the way to the end. Reported per byte.
    let delta = access_unit(48 * 1024, false);
    g.throughput(Throughput::Bytes(delta.len() as u64));
    g.bench_function(BenchmarkId::new("avc420_delta_scan", "1080p"), |b| {
        b.iter(|| avc420::contains_idr(&delta))
    });

    // The IDR case is reported per frame and not per byte, because the scan
    // stops at the IDR: a real access unit carries SPS, PPS and then the IDR
    // slice at the front, so the answer is known after twenty odd bytes of a
    // quarter megabyte frame and a bytes per second figure for it would be
    // both enormous and meaningless.
    let idr = access_unit(256 * 1024, true);
    g.throughput(Throughput::Elements(1));
    g.bench_function(BenchmarkId::new("avc420_idr_scan", "1080p"), |b| {
        b.iter(|| avc420::contains_idr(&idr))
    });

    // The metablock parse on its own, per region rectangle. 135 regions is one
    // per macroblock row of a 4K frame, which is more than a real server sends.
    let unit = access_unit(48 * 1024, false);
    for count in [8usize, 135] {
        let src = avc420_stream(count, &unit);
        g.throughput(Throughput::Elements(count as u64));
        g.bench_function(BenchmarkId::new("avc420_metablock", count), |b| {
            b.iter(|| {
                let s = avc420::parse(&src).unwrap();
                s.bounds()
            })
        });
    }

    // Everything the Rust side does for one AVC420 frame: parse the metablock,
    // union the regions into a damage rectangle, and scan the access unit for
    // an IDR. Reported per frame rather than per byte, against the 50
    // microsecond budget.
    let src = avc420_stream(135, &unit);
    g.throughput(Throughput::Elements(1));
    g.bench_function(BenchmarkId::new("avc420_frame", "1080p_delta"), |b| {
        b.iter(|| {
            let s = avc420::parse(&src).unwrap();
            let d = s.bounds();
            (d, avc420::contains_idr(s.bitstream))
        })
    });

    // MPPC. The legacy path's traffic is uncompressed bitmaps and channel
    // data, so the fixture is structure and pixels rather than noise: noise
    // would measure only the literal path, which is the fast one.
    for (v, id) in [(Variant::Rdp4, "mppc_8k"), (Variant::Rdp5, "mppc_64k")] {
        let size = v.history_size();
        let mut payload = Vec::with_capacity(size);
        let mut i = 0u32;
        while payload.len() < size {
            payload.extend_from_slice(b"\x00\x00\xff\xff clipboard/text; charset=utf-8; item=");
            payload.extend_from_slice(format!("{i:06}\n").as_bytes());
            payload.extend_from_slice(&[0x20, 0x20, 0x20, 0x20, 0xC3, 0xA9, 0x00, 0x00]);
            i += 1;
        }
        payload.truncate(size);
        let body = encode::mppc::compressed(v, &payload);
        let flags = PACKET_COMPRESSED | PACKET_AT_FRONT | v.compression_type();
        let mut d = MppcDecompressor::new(v);
        g.throughput(Throughput::Bytes(payload.len() as u64));
        g.bench_function(BenchmarkId::new(id, payload.len()), |b| {
            b.iter(|| d.decompress(flags, &body).unwrap().len())
        });
    }

    // The pathological case for the copy loop: one long run, which is the
    // shape that forces the byte at a time overlapping copy for its whole
    // length and is what a repainted flat background compresses to.
    let payload = vec![0x1Fu8; mppc::HISTORY_64K];
    let body = encode::mppc::compressed(Variant::Rdp5, &payload);
    let flags = PACKET_COMPRESSED | PACKET_AT_FRONT | Variant::Rdp5.compression_type();
    let mut d = MppcDecompressor::new(Variant::Rdp5);
    g.throughput(Throughput::Bytes(payload.len() as u64));
    g.bench_function(BenchmarkId::new("mppc_64k_run", payload.len()), |b| {
        b.iter(|| d.decompress(flags, &body).unwrap().len())
    });

    g.finish();

    // The start code scan, against the byte at a time form it replaced.
    //
    // `vnc_core::encodings::h264::contains_idr` walks one byte and three
    // comparisons at a time. That is the "before". The "after" skips eight
    // bytes whenever the word holds no zero byte, which on entropy coded video
    // is almost every word. Both are in this process on the same fixture, so
    // the ratio is a measurement and not an argument (PRDRDP/04 §11.4).
    let mut g = c.benchmark_group("before_after");
    let delta = access_unit(48 * 1024, false);
    g.throughput(Throughput::Bytes(delta.len() as u64));
    g.bench_function("annexb_idr_scan/byte_at_a_time", |b| {
        b.iter(|| contains_idr_byte_at_a_time(&delta))
    });
    g.bench_function("annexb_idr_scan/current", |b| {
        b.iter(|| avc420::contains_idr(&delta))
    });
    g.finish();
}

/// The pre optimisation start code scan, kept here and nowhere else so the
/// number above is a comparison rather than a claim.
///
/// This is `vnc_core::encodings::h264::nal_types` reduced to the question
/// `contains_idr` asks: one byte and three comparisons per position.
fn contains_idr_byte_at_a_time(data: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 3 <= data.len() {
        let three = data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1;
        let four = i + 4 <= data.len()
            && data[i] == 0
            && data[i + 1] == 0
            && data[i + 2] == 0
            && data[i + 3] == 1;
        if four {
            i += 4;
        } else if three {
            i += 3;
        } else {
            i += 1;
            continue;
        }
        if i < data.len() {
            let header = data[i];
            i += 1;
            if header & 0x80 == 0 && header & 0x1F == 5 {
                return true;
            }
        }
    }
    false
}

criterion_group!(
    benches,
    bench_decode,
    bench_stage,
    bench_convert,
    bench_before_after,
    bench_phase2_decode,
    bench_phase2_stage,
    bench_phase2_bulk
);
criterion_main!(benches);
