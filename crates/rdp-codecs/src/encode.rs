//! Minimal reference encoders, for bench fixtures and round trip tests
//! (PRDRDP/04 §11.4).
//!
//! These are not products. Each emits one legal form of each construct it
//! uses, none of them is efficient, and their only job is to produce
//! bitstreams our decoders must read. They are gated behind the `encode`
//! feature so they never reach a shipped binary, and the hand assembled spec
//! vectors in each decoder's test module are what stops "our encoder and our
//! decoder agree" from being the only evidence we have.
//!
//! Two deliberate gaps, so nobody reads a bench number as covering more than
//! it does. [`interleaved`] emits background runs, colour runs and colour
//! images and never emits a foreground run, an FGBG image or a dithered run;
//! those are covered by the unit tests instead. [`planar`] never emits colour
//! loss or chroma subsampling.

/// Bytes per pixel for an interleaved RLE colour depth.
fn wire_bpp(bits_per_pixel: u8) -> usize {
    match bits_per_pixel {
        8 => 1,
        15 | 16 => 2,
        24 => 3,
        other => panic!("interleaved RLE has no {other} bpp form"),
    }
}

/// Encode a tightly packed wire format image as interleaved RLE
/// (MS-RDPBCGR 2.2.9.1.1.3.1.2.4).
///
/// Greedy and linear: at each pixel it takes the longest run that matches the
/// scanline above, then the longest run of one colour, and otherwise
/// accumulates literals. Runs are allowed to span rows, which is what a real
/// encoder does and what PRDRDP/04 §4.4.4 requires the decoder to accept.
///
/// The one subtlety it has to respect is the insert_fg rule of
/// MS-RDPBCGR 3.1.9: two background runs in a row are not the same as one
/// longer run, because the decoder replaces the second run's first pixel with
/// the foreground. A greedy scan produces two in a row only when the first hit
/// the 65535 length ceiling, so the encoder simply declines to start a
/// background run immediately after one.
///
/// # Panics
///
/// On a colour depth interleaved RLE is not defined for, or on a `src` too
/// short for the geometry. This is test scaffolding and is never fed remote
/// bytes.
pub fn interleaved(bits_per_pixel: u8, src: &[u8], w: usize, h: usize) -> Vec<u8> {
    let bpp = wire_bpp(bits_per_pixel);
    let total = w * h;
    assert!(src.len() >= total * bpp, "source too short for {w}x{h}");
    let px = |i: usize| &src[i * bpp..(i + 1) * bpp];

    let mut out = Vec::with_capacity(total * bpp / 4 + 64);
    let mut lits: Vec<usize> = Vec::new();
    let mut p = 0usize;
    let mut last_was_bg = false;

    while p < total {
        if p >= w && !last_was_bg {
            let mut n = 0usize;
            while p + n < total && n < 0xFFFF && px(p + n) == px(p + n - w) {
                n += 1;
            }
            if n >= 4 {
                flush_literals(&mut out, &mut lits, src, bpp);
                emit_len(&mut out, 0x00, 0xF0, n);
                p += n;
                last_was_bg = true;
                continue;
            }
        }
        last_was_bg = false;

        let mut n = 1usize;
        while p + n < total && n < 0xFFFF && px(p + n) == px(p) {
            n += 1;
        }
        if n >= 3 {
            flush_literals(&mut out, &mut lits, src, bpp);
            emit_len(&mut out, 0x60, 0xF3, n);
            out.extend_from_slice(px(p));
            p += n;
            continue;
        }

        lits.push(p);
        if lits.len() == 0xFFFF {
            flush_literals(&mut out, &mut lits, src, bpp);
        }
        p += 1;
    }
    flush_literals(&mut out, &mut lits, src, bpp);
    out
}

/// Emit an order header with its run length, in the regular form when it fits
/// in five bits and in the mega mega form otherwise.
fn emit_len(out: &mut Vec<u8>, regular: u8, mega: u8, n: usize) {
    if (1..=31).contains(&n) {
        out.push(regular | n as u8);
    } else {
        out.push(mega);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    }
}

fn flush_literals(out: &mut Vec<u8>, lits: &mut Vec<usize>, src: &[u8], bpp: usize) {
    if lits.is_empty() {
        return;
    }
    emit_len(out, 0x80, 0xF4, lits.len());
    for &i in lits.iter() {
        out.extend_from_slice(&src[i * bpp..(i + 1) * bpp]);
    }
    lits.clear();
}

/// Encode planes as an `RDP6_BITMAP_STREAM` (MS-RDPEGDI 2.2.2.5.1).
///
/// `planes` is three plane buffers of `w * h` bytes in red, green, blue order,
/// or four with alpha first. With `rle` set the planes are delta encoded
/// against the scanline above and then run length encoded per scanline; with
/// it clear they are written raw.
///
/// # Panics
///
/// On a plane count other than three or four, or on a plane of the wrong size.
pub fn planar(planes: &[&[u8]], w: usize, h: usize, rle: bool) -> Vec<u8> {
    assert!(
        planes.len() == 3 || planes.len() == 4,
        "planar takes three or four planes"
    );
    for p in planes {
        assert_eq!(p.len(), w * h, "plane must be w by h");
    }
    let mut hdr = 0u8;
    if planes.len() == 3 {
        hdr |= 0x20; // NA, no alpha plane
    }
    if rle {
        hdr |= 0x10;
    }
    let mut out = vec![hdr];
    for p in planes {
        if rle {
            let deltas = delta_encode(p, w, h);
            for y in 0..h {
                rle_scanline(&mut out, &deltas[y * w..][..w]);
            }
        } else {
            out.extend_from_slice(p);
        }
    }
    out
}

/// The inverse of `planar::undo_delta`: scanline zero is raw and every other
/// scanline is sign and magnitude against the one above, with the sign in
/// bit 0 and `u8` wrapping arithmetic.
fn delta_encode(plane: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h];
    out[..w].copy_from_slice(&plane[..w]);
    for y in 1..h {
        for x in 0..w {
            let cur = plane[y * w + x];
            let above = plane[(y - 1) * w + x];
            let up = cur.wrapping_sub(above);
            out[y * w + x] = if up <= 127 {
                up << 1
            } else {
                ((above.wrapping_sub(cur) - 1) << 1) | 1
            };
        }
    }
    out
}

/// One scanline of RDP 6.0 RLE segments (MS-RDPEGDI 2.2.2.5.1.1).
fn rle_scanline(out: &mut Vec<u8>, row: &[u8]) {
    let mut pending: Vec<u8> = Vec::new();
    let mut x = 0usize;
    while x < row.len() {
        let b = row[x];
        let mut n = 1usize;
        while x + n < row.len() && row[x + n] == b {
            n += 1;
        }
        if n >= 4 {
            pending.push(b);
            flush_raw(out, &mut pending);
            emit_plane_run(out, &mut pending, b, n - 1);
            x += n;
        } else {
            pending.extend_from_slice(&row[x..x + n]);
            if pending.len() >= 15 {
                flush_raw(out, &mut pending);
            }
            x += n;
        }
    }
    flush_raw(out, &mut pending);
}

fn flush_raw(out: &mut Vec<u8>, pending: &mut Vec<u8>) {
    for chunk in pending.chunks(15) {
        out.push((chunk.len() as u8) << 4);
        out.extend_from_slice(chunk);
    }
    pending.clear();
}

/// A run of `n` copies of the last byte written. Lengths of one and two have
/// no run encoding, because those two low nibble values are the escapes that
/// mean 16 plus and 32 plus, so they go back into the literal buffer.
fn emit_plane_run(out: &mut Vec<u8>, pending: &mut Vec<u8>, byte: u8, mut n: usize) {
    while n > 0 {
        if n <= 2 {
            pending.resize(pending.len() + n, byte);
            flush_raw(out, pending);
            n = 0;
        } else if n <= 15 {
            out.push(n as u8);
            n = 0;
        } else if n <= 31 {
            out.push(((n - 16) as u8) << 4 | 1);
            n = 0;
        } else if n <= 47 {
            out.push(((n - 32) as u8) << 4 | 2);
            n = 0;
        } else {
            out.push(0xF2); // cRawBytes 15, escape 2, so a run of 47
            n -= 47;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dst::{DstView, OutFormat, RowOrder};
    use crate::uncompressed::dst_len;
    use crate::{planar as planar_dec, rle};

    /// Desktop-like content: flat panes, a gradient and text-like detail. The
    /// same mix as `crates/vnc-core/benches/decode.rs:47`, because a codec is
    /// only as fast, and only as well exercised, as its content lets it be.
    pub(crate) fn synth_plane(w: usize, h: usize, seed: u8) -> Vec<u8> {
        let mut out = vec![0u8; w * h];
        for y in 0..h {
            for x in 0..w {
                let pane = (x / 37 + y / 23) % 3;
                out[y * w + x] = match pane {
                    0 => {
                        if (y % 18) < 9 && ((x * 7 + y * 13) % 23) < 6 {
                            24
                        } else {
                            246
                        }
                    }
                    1 => 32u8.wrapping_add(seed),
                    _ => (90 + (x * 60 / w.max(1))) as u8,
                };
            }
        }
        out
    }

    fn wire_image(bits_per_pixel: u8, w: usize, h: usize) -> Vec<u8> {
        let bpp = wire_bpp(bits_per_pixel);
        let planes: Vec<Vec<u8>> = (0..bpp).map(|i| synth_plane(w, h, i as u8 * 40)).collect();
        let mut out = vec![0u8; w * h * bpp];
        for i in 0..w * h {
            for (c, plane) in planes.iter().enumerate() {
                out[i * bpp + c] = plane[i];
            }
        }
        out
    }

    #[test]
    fn interleaved_round_trips_at_every_colour_depth() {
        for bits in [8u8, 15, 16, 24] {
            let (w, h) = (61usize, 37usize);
            let wire = wire_image(bits, w, h);
            let encoded = interleaved(bits, &wire, w, h);
            let mut got = vec![0u8; wire.len()];
            rle::decode_bpp(bits, &encoded, &mut got, w as u16, h as u16).unwrap();
            assert_eq!(got, wire, "{bits} bpp round trip");
            assert!(
                encoded.len() < wire.len(),
                "{bits} bpp should compress this content"
            );
        }
    }

    #[test]
    fn planar_round_trips_raw_and_rle() {
        let (w, h) = (61usize, 37usize);
        let r = synth_plane(w, h, 0);
        let g = synth_plane(w, h, 40);
        let b = synth_plane(w, h, 80);
        let a = synth_plane(w, h, 120);

        for rle_on in [false, true] {
            for planes in [
                vec![&r[..], &g[..], &b[..]],
                vec![&a[..], &r[..], &g[..], &b[..]],
            ] {
                let has_alpha = planes.len() == 4;
                let encoded = planar(&planes, w, h, rle_on);
                let mut out = vec![0u8; dst_len(w as u16, h as u16)];
                {
                    let mut v = DstView::packed(
                        &mut out,
                        w as u16,
                        h as u16,
                        OutFormat::Rgba,
                        RowOrder::TopDown,
                    )
                    .unwrap();
                    planar_dec::decode(
                        &encoded,
                        true,
                        &mut planar_dec::PlanarScratch::new(),
                        &mut v,
                    )
                    .unwrap();
                }
                for i in 0..w * h {
                    let want = [r[i], g[i], b[i], if has_alpha { a[i] } else { 0xFF }];
                    assert_eq!(&out[i * 4..i * 4 + 4], &want, "pixel {i}, rle {rle_on}");
                }
            }
        }
    }

    #[test]
    fn planar_rle_actually_compresses() {
        let (w, h) = (256usize, 128usize);
        let p = synth_plane(w, h, 0);
        let raw = planar(&[&p, &p, &p], w, h, false);
        let packed = planar(&[&p, &p, &p], w, h, true);
        assert!(
            packed.len() * 2 < raw.len(),
            "rle {} vs raw {}",
            packed.len(),
            raw.len()
        );
    }
}
