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

use rdp_codecs::{
    encode, planar, rle, uncompressed, DstView, OutFormat, Palette, PixelFormat, RowOrder,
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

criterion_group!(
    benches,
    bench_decode,
    bench_stage,
    bench_convert,
    bench_before_after
);
criterion_main!(benches);
