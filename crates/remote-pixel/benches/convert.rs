//! Criterion benchmarks for pixel format conversion.
//!
//! The `convert/*` group moved here unchanged with the crate
//! (PRDRDP/02 §13 commit 1b). It is the regression gate on the extraction: the
//! canonical 32 bpp little endian BGRA number must not move across the commit
//! (`docs/PERFORMANCE.md` §3.2).
//!
//! Throughput is reported with `Throughput::Elements(pixels)` so criterion
//! prints `Melem/s` == **MPixels/s**, comparable across resolutions.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use remote_pixel::{convert_to_rgba, convert_to_rgba_mapped, ColourMap, PixelFormat};

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

criterion_group!(benches, bench_convert);
criterion_main!(benches);
