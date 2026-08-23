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

// ---------------------------------------------------------------------------
// RemoteFX (MS-RDPRFX)
// ---------------------------------------------------------------------------

/// A most significant bit first writer, the exact inverse of the reader in
/// [`crate::remotefx::rlgr`].
///
/// Shared with that module's tests so a hand assembled bit string vector and
/// an encoder produced bitstream go through one writer rather than two that
/// can drift.
pub(crate) struct BitWriter {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl BitWriter {
    pub(crate) fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }

    /// The low `k` bits of `v`, most significant first.
    pub(crate) fn put(&mut self, v: u32, k: u32) {
        for i in (0..k).rev() {
            self.acc = (self.acc << 1) | ((v >> i) & 1);
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }

    /// A bit string, ignoring spaces and underscores.
    ///
    /// # Panics
    ///
    /// On any character that is not a bit or a separator. This is test
    /// scaffolding and is never fed remote bytes.
    #[cfg(test)]
    pub(crate) fn bits(&mut self, s: &str) {
        for c in s.chars() {
            match c {
                '0' => self.put(0, 1),
                '1' => self.put(1, 1),
                ' ' | '_' => {}
                other => panic!("not a bit: {other}"),
            }
        }
    }

    /// Bits of zero padding [`BitWriter::finish`] will add.
    pub(crate) fn padding(&self) -> u8 {
        ((8 - self.n) % 8) as u8
    }

    /// Pad with zeros to the next byte boundary, which the ZGFX unencoded run
    /// escape needs before its literal bytes.
    pub(crate) fn align(&mut self) {
        if self.n > 0 {
            let k = 8 - self.n;
            self.put(0, k);
        }
    }

    /// Whole bytes, straight through.
    ///
    /// # Panics
    ///
    /// If the writer is not on a byte boundary, which would silently produce
    /// a bitstream nothing can read.
    pub(crate) fn raw(&mut self, bytes: &[u8]) {
        assert_eq!(self.n, 0, "raw bytes need a byte aligned writer");
        self.out.extend_from_slice(bytes);
    }

    /// Flush, padding the last byte with zeros. Zero padding is what makes
    /// the decoder's lenient tail work, so it is what the wire carries.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc << (8 - self.n)) as u8);
        }
        self.out
    }
}

// The adaptation constants of MS-RDPRFX 3.1.8.1.7.1, mirrored from the
// decoder because an encoder that adapts differently produces a stream that
// only it can read.
const KPMAX: i32 = 80;
const LSGR: u32 = 3;
const UP_GR: i32 = 4;
const DN_GR: i32 = 6;
const UQ_GR: i32 = 3;
const DQ_GR: i32 = 3;

struct Rlgr {
    kp: i32,
    k: u32,
    krp: i32,
    kr: u32,
}

impl Rlgr {
    fn new() -> Self {
        Self {
            kp: 1 << LSGR,
            k: 1,
            krp: 1 << LSGR,
            kr: 1,
        }
    }

    fn gr(&mut self, w: &mut BitWriter, mag: u32) {
        let vk = mag >> self.kr;
        for _ in 0..vk {
            w.put(1, 1);
        }
        w.put(0, 1);
        if self.kr > 0 {
            w.put(mag & ((1 << self.kr) - 1), self.kr);
        }
        if vk == 0 {
            self.krp = (self.krp - 2).max(0);
            self.kr = (self.krp >> LSGR) as u32;
        } else if vk > 1 {
            self.krp = (self.krp + vk as i32).min(KPMAX);
            self.kr = (self.krp >> LSGR) as u32;
        }
    }
}

/// `v` as the two magnitude sign value MS-RDPRFX 3.1.8.1.7 codes.
fn two_mag_sign(v: i16) -> u32 {
    if v >= 0 {
        (v as u32) << 1
    } else {
        (((-(v as i32)) as u32) << 1) - 1
    }
}

/// RLGR encode one component's coefficients.
///
/// Trailing zeros are simply not written: the decoder's zero padding produces
/// them, which is the property `remotefx::rlgr`'s module comment relies on
/// and which this encoder therefore exercises on every tile.
pub fn rlgr(mode: crate::remotefx::Entropy, data: &[i16]) -> Vec<u8> {
    use crate::remotefx::Entropy;
    let mut w = BitWriter::new();
    let mut s = Rlgr::new();
    let n = data.len();
    let mut i = 0usize;

    while i < n {
        if s.k > 0 {
            let mut run = 0usize;
            while i + run < n && data[i + run] == 0 {
                run += 1;
            }
            if i + run >= n {
                break; // the tail is zeros; let the padding carry it
            }
            let mut left = run;
            loop {
                let block = 1usize << s.k;
                if left >= block {
                    w.put(0, 1);
                    left -= block;
                    s.kp = (s.kp + UP_GR).min(KPMAX);
                    s.k = (s.kp >> LSGR) as u32;
                } else {
                    w.put(1, 1);
                    w.put(left as u32, s.k);
                    break;
                }
            }
            let v = data[i + run];
            w.put(u32::from(v < 0), 1);
            let mag = (i32::from(v).abs() - 1) as u32;
            s.gr(&mut w, mag);
            s.kp = (s.kp - DN_GR).max(0);
            s.k = (s.kp >> LSGR) as u32;
            i += run + 1;
        } else {
            match mode {
                Entropy::Rlgr1 => {
                    let v = data[i];
                    let m = two_mag_sign(v);
                    s.gr(&mut w, m);
                    if v == 0 {
                        s.kp = (s.kp + UQ_GR).min(KPMAX);
                    } else {
                        s.kp = (s.kp - DQ_GR).max(0);
                    }
                    s.k = (s.kp >> LSGR) as u32;
                    i += 1;
                }
                Entropy::Rlgr3 => {
                    let v1 = two_mag_sign(data[i]);
                    let v2 = if i + 1 < n {
                        two_mag_sign(data[i + 1])
                    } else {
                        0
                    };
                    let mag = v1 + v2;
                    s.gr(&mut w, mag);
                    let nidx = if mag == 0 {
                        0
                    } else {
                        u32::BITS - mag.leading_zeros()
                    };
                    w.put(v1, nidx);
                    if v1 == 0 && v2 == 0 {
                        s.kp = (s.kp + 2 * UQ_GR).min(KPMAX);
                    } else {
                        s.kp = (s.kp - 2 * DQ_GR).max(0);
                    }
                    s.k = (s.kp >> LSGR) as u32;
                    i += 2;
                }
            }
        }
    }
    w.finish()
}

/// The quantization table the correctness tests use: six for every band.
///
/// Six, so the decoder's "factor less one" shift is five, which is exactly
/// the five fractional bits the colour stage removes. A single factor keeps
/// the round trip error uniform across bands, which makes a failure easy to
/// attribute to a band rather than to the choice of table.
pub const RFX_QUANT_FINE: [u8; 10] = [6; 10];

/// A quantization table shaped the way a real server's is: coarser as the
/// bands get finer.
///
/// The nibble order is LL3, LH3, HL3, HH3, LH2, HL2, HH2, LH1, HL1, HH1
/// (MS-RDPRFX 2.2.2.1.6), so this quantizes the three level 1 bands two to
/// three bits harder than the LL band. That matters for the benches and not
/// for correctness: a uniform table leaves most of a tile's level 1
/// coefficients non zero, which makes the entropy stage's zero runs
/// disappear and understates its throughput by several times. Reporting a
/// RemoteFX number measured with a table no server sends would be reporting
/// the fixture rather than the codec.
pub const RFX_QUANT_TYPICAL: [u8; 10] = [6, 6, 6, 6, 7, 7, 8, 8, 8, 9];

/// RGB to the fixed point YCbCr the wavelet stage expects
/// (MS-RDPRFX 3.1.8.1.3 read backwards).
fn rgb_to_ycbcr(px: [u8; 3]) -> (i16, i16, i16) {
    let r = f64::from(px[0]);
    let g = f64::from(px[1]);
    let b = f64::from(px[2]);
    let y = 0.299 * r + 0.587 * g + 0.114 * b;
    let cb = -0.168736 * r - 0.331264 * g + 0.5 * b;
    let cr = 0.5 * r - 0.418688 * g - 0.081312 * b;
    let s = 32.0;
    (
        (y * s - 4096.0).round() as i16,
        (cb * s).round() as i16,
        (cr * s).round() as i16,
    )
}

/// One tile's three entropy coded components.
fn rfx_tile_components(
    mode: crate::remotefx::Entropy,
    px: &[[u8; 3]],
    quant: &[u8; 10],
) -> [Vec<u8>; 3] {
    use crate::remotefx::quant::{BANDS, COEFS, LL3};
    assert_eq!(px.len(), COEFS);
    let mut planes = [[0i16; COEFS], [0i16; COEFS], [0i16; COEFS]];
    for (i, &p) in px.iter().enumerate() {
        let (y, cb, cr) = rgb_to_ycbcr(p);
        planes[0][i] = y;
        planes[1][i] = cb;
        planes[2][i] = cr;
    }

    let mut out = [Vec::new(), Vec::new(), Vec::new()];
    let mut coef = vec![0i16; COEFS];
    for (c, plane) in planes.iter().enumerate() {
        crate::remotefx::dwt::forward::forward_2d(plane, &mut coef);
        // Quantize band by band: the inverse of `quant::dequantize`, rounding
        // to nearest rather than truncating. A real encoder rounds too, and
        // it halves the round trip error, which is what lets the tests state
        // a tolerance tight enough to catch a decoder bug rather than one
        // loose enough to hide one.
        for (off, n, qi) in BANDS {
            let shift = u32::from(quant[qi] - 1);
            let half = 1i32 << (shift - 1);
            for v in coef[off..off + n].iter_mut() {
                *v = ((i32::from(*v) + half) >> shift) as i16;
            }
        }
        // Differential encode LL3: the inverse of `quant::differential_ll3`,
        // and it runs backwards so each difference uses the original
        // predecessor rather than the one already rewritten.
        for i in (LL3 + 1..COEFS).rev() {
            coef[i] = coef[i].wrapping_sub(coef[i - 1]);
        }
        out[c] = rlgr(mode, &coef);
    }
    out
}

fn blockt(out: &mut Vec<u8>, block_type: u16, body: &[u8]) {
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&((body.len() + 6) as u32).to_le_bytes());
    out.extend_from_slice(body);
}

/// A `WBT_CONTEXT` block on its own, for the tests that check the entropy
/// algorithm survives from one message to the next.
pub fn rfx_context(et: u16) -> Vec<u8> {
    let mut body = vec![1u8, 0xFF, 0]; // codecId, channelId, ctxId
    body.extend_from_slice(&0x0040u16.to_le_bytes());
    body.extend_from_slice(&(et << 9 | 1 << 5 | 1 << 3 | 1 << 13).to_le_bytes());
    let mut out = Vec::new();
    blockt(&mut out, 0xCCC3, &body);
    out
}

/// A whole RemoteFX message with no region block, so every tile is clipped
/// only against the destination.
pub fn rfx_message(
    mode: crate::remotefx::Entropy,
    tiles: &[(u16, u16, Vec<[u8; 3]>)],
    w: u16,
    h: u16,
) -> Vec<u8> {
    rfx_build(mode, tiles, w, h, None, &RFX_QUANT_FINE)
}

/// The same with a chosen quantization table, which is what the benches use.
pub fn rfx_message_quant(
    mode: crate::remotefx::Entropy,
    tiles: &[(u16, u16, Vec<[u8; 3]>)],
    w: u16,
    h: u16,
    quant: &[u8; 10],
) -> Vec<u8> {
    rfx_build(mode, tiles, w, h, None, quant)
}

/// The same with an explicit `TS_RFX_REGION`.
pub fn rfx_message_region(
    mode: crate::remotefx::Entropy,
    tiles: &[(u16, u16, Vec<[u8; 3]>)],
    w: u16,
    h: u16,
    rects: &[crate::remotefx::Rect],
) -> Vec<u8> {
    rfx_build(mode, tiles, w, h, Some(rects), &RFX_QUANT_FINE)
}

fn rfx_build(
    mode: crate::remotefx::Entropy,
    tiles: &[(u16, u16, Vec<[u8; 3]>)],
    w: u16,
    h: u16,
    rects: Option<&[crate::remotefx::Rect]>,
    quant: &[u8; 10],
) -> Vec<u8> {
    use crate::remotefx::Entropy;
    let et: u16 = match mode {
        Entropy::Rlgr1 => 1,
        Entropy::Rlgr3 => 4,
    };
    let mut out = Vec::new();

    let mut sync = Vec::new();
    sync.extend_from_slice(&0xCACC_ACCAu32.to_le_bytes());
    sync.extend_from_slice(&0x0100u16.to_le_bytes());
    blockt(&mut out, 0xCCC0, &sync);

    blockt(&mut out, 0xCCC1, &[1u8, 1, 0x00, 0x01]);

    let mut chan = vec![1u8, 0];
    chan.extend_from_slice(&w.to_le_bytes());
    chan.extend_from_slice(&h.to_le_bytes());
    blockt(&mut out, 0xCCC2, &chan);

    out.extend_from_slice(&rfx_context(et));

    let mut fb = vec![1u8, 0xFF];
    fb.extend_from_slice(&7u32.to_le_bytes());
    fb.extend_from_slice(&1u16.to_le_bytes());
    blockt(&mut out, 0xCCC4, &fb);

    if let Some(rects) = rects {
        let mut body = vec![1u8, 0xFF, 1];
        body.extend_from_slice(&(rects.len() as u16).to_le_bytes());
        for r in rects {
            body.extend_from_slice(&r.x.to_le_bytes());
            body.extend_from_slice(&r.y.to_le_bytes());
            body.extend_from_slice(&r.w.to_le_bytes());
            body.extend_from_slice(&r.h.to_le_bytes());
        }
        body.extend_from_slice(&0xCAC1u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        blockt(&mut out, 0xCCC6, &body);
    }

    // The tileset. One quantization value, used by all three components of
    // every tile, so `numQuant` is one and every `quantIdx` is zero.
    let mut tiles_data = Vec::new();
    for (x_idx, y_idx, px) in tiles {
        let [y, cb, cr] = rfx_tile_components(mode, px, quant);
        let mut body = vec![0u8, 0, 0];
        body.extend_from_slice(&x_idx.to_le_bytes());
        body.extend_from_slice(&y_idx.to_le_bytes());
        body.extend_from_slice(&(y.len() as u16).to_le_bytes());
        body.extend_from_slice(&(cb.len() as u16).to_le_bytes());
        body.extend_from_slice(&(cr.len() as u16).to_le_bytes());
        body.extend_from_slice(&y);
        body.extend_from_slice(&cb);
        body.extend_from_slice(&cr);
        blockt(&mut tiles_data, 0xCAC3, &body);
    }

    let mut ts = vec![1u8, 0xFF];
    ts.extend_from_slice(&0xCAC2u16.to_le_bytes());
    ts.extend_from_slice(&0u16.to_le_bytes());
    ts.extend_from_slice(&(et << 9 | 1 << 5 | 1 << 3 | 1 << 13).to_le_bytes());
    ts.push(1); // numQuant
    ts.push(0x40); // tileSize
    ts.extend_from_slice(&(tiles.len() as u16).to_le_bytes());
    ts.extend_from_slice(&(tiles_data.len() as u32).to_le_bytes());
    // Ten nibbles of the quantization table, low nibble first
    // (MS-RDPRFX 2.2.2.1.6).
    for pair in quant.chunks_exact(2) {
        ts.push(pair[0] | (pair[1] << 4));
    }
    ts.extend_from_slice(&tiles_data);
    blockt(&mut out, 0xCCC7, &ts);

    blockt(&mut out, 0xCCC5, &[1u8, 0xFF]);
    out
}

/// Where the first `TS_RFX_TILE` block starts inside a message this module
/// built, for the tests that corrupt one field of it.
///
/// # Panics
///
/// If the message carries no tileset, which would mean this module and the
/// test using it disagree about what it emits.
pub fn rfx_first_tile_offset(msg: &[u8]) -> usize {
    let mut at = 0usize;
    while at + 6 <= msg.len() {
        let ty = u16::from_le_bytes([msg[at], msg[at + 1]]);
        let len = u32::from_le_bytes([msg[at + 2], msg[at + 3], msg[at + 4], msg[at + 5]]) as usize;
        if ty == 0xCCC7 {
            // codecId, channelId, subtype, idx, properties, numQuant,
            // tileSize, numTiles, tilesDataSize, then numQuant * 5 bytes.
            let num_quant = usize::from(msg[at + 6 + 8]);
            return at + 6 + 16 + num_quant * 5;
        }
        at += len.max(6);
    }
    panic!("no tileset in this message");
}

// ---------------------------------------------------------------------------
// NSCodec (MS-RDPNSC)
// ---------------------------------------------------------------------------

/// RGB to the YCoCg triple `nscodec` stores, chosen so the decoder's lifting
/// form reconstructs blue and the luma exactly and loses only the bits the
/// colour loss level throws away.
///
/// It is written as the algebraic inverse of `planar::ycocg_to_rgb` rather
/// than as the textbook forward transform, because the textbook forward
/// followed by that particular inverse drifts: the decoder reconstructs from
/// the *quantized* chroma, so the encoder has to choose the luma from the
/// quantized chroma as well or the round trip error grows with the colour
/// loss level instead of staying bounded by it.
fn rgb_to_ycocg(px: [u8; 3], cll: u8) -> (u8, u8, u8) {
    let r = i32::from(px[0]);
    let g = i32::from(px[1]);
    let b = i32::from(px[2]);
    let shift = u32::from(cll);

    let co_full = r - b;
    let co_q = (co_full >> shift).clamp(-128, 127);
    let co = co_q << shift;

    let t = b + (co >> 1);
    let cg_full = g - t;
    let cg_q = (cg_full >> shift).clamp(-128, 127);
    let cg = cg_q << shift;

    let y = (t + (cg >> 1)).clamp(0, 255);
    (y as u8, co_q as u8, cg_q as u8)
}

/// The plane run length encoding of MS-RDPNSC 3.1.8.
///
/// The last four bytes are emitted raw and no run is allowed to reach into
/// them, and the byte immediately before them is always a literal. Both rules
/// are the decoder's, mirrored here so a round trip exercises them.
fn nsc_rle(plane: &[u8]) -> Vec<u8> {
    let n = plane.len();
    if n <= 4 {
        return plane.to_vec();
    }
    let mut out = Vec::new();
    let mut at = 0usize;
    while n - at > 4 {
        if n - at == 5 {
            out.push(plane[at]);
            at += 1;
            continue;
        }
        let v = plane[at];
        let mut run = 1usize;
        while at + run < n - 4 && plane[at + run] == v {
            run += 1;
        }
        if run >= 2 {
            out.push(v);
            out.push(v);
            if run - 2 < 0xFF {
                out.push((run - 2) as u8);
            } else {
                out.push(0xFF);
                out.extend_from_slice(&(run as u32).to_le_bytes());
            }
            at += run;
        } else {
            out.push(v);
            at += 1;
        }
    }
    out.extend_from_slice(&plane[n - 4..]);
    // A run length encoded plane whose length happens to equal the plane's
    // own size would be read back as a raw plane, because that equality is
    // the only signal MS-RDPNSC 3.1.8 gives. Falling back to raw keeps the
    // byte count honest and the pixels right.
    if out.len() == n {
        return plane.to_vec();
    }
    out
}

/// An `NSCODEC_BITMAP_STREAM` with no alpha plane (MS-RDPNSC 2.2).
pub fn nscodec(px: &[[u8; 3]], w: usize, h: usize, cll: u8, css: bool, rle: bool) -> Vec<u8> {
    nsc_build(px, None, w, h, cll, css, rle)
}

/// The same with an alpha plane.
pub fn nscodec_alpha(
    px: &[[u8; 3]],
    alpha: &[u8],
    w: usize,
    h: usize,
    cll: u8,
    css: bool,
    rle: bool,
) -> Vec<u8> {
    nsc_build(px, Some(alpha), w, h, cll, css, rle)
}

fn nsc_build(
    px: &[[u8; 3]],
    alpha: Option<&[u8]>,
    w: usize,
    h: usize,
    cll: u8,
    css: bool,
    rle: bool,
) -> Vec<u8> {
    assert_eq!(px.len(), w * h);
    assert!((1..=7).contains(&cll));

    let (luma_w, chroma_w, chroma_h) = if css {
        let lw = w.next_multiple_of(8);
        (lw, lw / 2, h.div_ceil(2))
    } else {
        (w, w, h)
    };

    let mut y = vec![0u8; luma_w * h];
    let mut co = vec![0u8; chroma_w * chroma_h];
    let mut cg = vec![0u8; chroma_w * chroma_h];
    for row in 0..h {
        for col in 0..luma_w {
            let src = px[row * w + col.min(w - 1)];
            y[row * luma_w + col] = rgb_to_ycocg(src, cll).0;
        }
    }
    for cy in 0..chroma_h {
        for cx in 0..chroma_w {
            let (sx, sy) = if css {
                ((2 * cx).min(w - 1), (2 * cy).min(h - 1))
            } else {
                (cx.min(w - 1), cy.min(h - 1))
            };
            let (_, c1, c2) = rgb_to_ycocg(px[sy * w + sx], cll);
            co[cy * chroma_w + cx] = c1;
            cg[cy * chroma_w + cx] = c2;
        }
    }

    let mut out = Vec::new();
    let planes: Vec<Vec<u8>> = [Some(&y), Some(&co), Some(&cg)]
        .into_iter()
        .flatten()
        .map(|p| if rle { nsc_rle(p) } else { p.clone() })
        .chain(alpha.map(|a| {
            let a = a.to_vec();
            if rle {
                nsc_rle(&a)
            } else {
                a
            }
        }))
        .collect();

    for i in 0..4 {
        let n = planes.get(i).map(|p| p.len()).unwrap_or(0);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.push(cll);
    out.push(u8::from(css));
    out.extend_from_slice(&0u16.to_le_bytes());
    for p in &planes {
        out.extend_from_slice(p);
    }
    out
}

// ---------------------------------------------------------------------------
// ClearCodec (MS-RDPEGFX 2.2.4.1)
// ---------------------------------------------------------------------------

/// Reference ClearCodec streams, one construct at a time.
///
/// Each function builds a whole `CLEARCODEC_BITMAP_STREAM` rather than a
/// layer, because the three layers share a header and the caches only mean
/// anything across whole bitmaps.
pub mod clear {
    /// The escalating run length of MS-RDPEGFX 2.2.4.1.1, written so the
    /// short form never emits the `0xFF` that means "read more".
    fn run_length(out: &mut Vec<u8>, n: usize) {
        if n < 0xFF {
            out.push(n as u8);
        } else if n < 0xFFFF {
            out.push(0xFF);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        } else {
            out.push(0xFF);
            out.extend_from_slice(&0xFFFFu16.to_le_bytes());
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }

    /// The residual layer for a whole bitmap: runs of identical pixels in
    /// raster order.
    fn residual_layer(px: &[[u8; 3]]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < px.len() {
            let v = px[at];
            let mut run = 1usize;
            while at + run < px.len() && px[at + run] == v {
                run += 1;
            }
            out.extend_from_slice(&[v[2], v[1], v[0]]); // B, G, R
            run_length(&mut out, run);
            at += run;
        }
        out
    }

    fn stream(residual: &[u8], bands: &[u8], subcodec: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8, 0]; // glyphFlags, seqNumber
        out.extend_from_slice(&(residual.len() as u32).to_le_bytes());
        out.extend_from_slice(&(bands.len() as u32).to_le_bytes());
        out.extend_from_slice(&(subcodec.len() as u32).to_le_bytes());
        out.extend_from_slice(residual);
        out.extend_from_slice(bands);
        out.extend_from_slice(subcodec);
        out
    }

    /// A bitmap that is nothing but its residual layer.
    ///
    /// # Panics
    ///
    /// On a pixel count that does not match the geometry.
    pub fn residual_only(px: &[[u8; 3]], w: u16, h: u16) -> Vec<u8> {
        assert_eq!(px.len(), usize::from(w) * usize::from(h));
        stream(&residual_layer(px), &[], &[])
    }

    /// Set the sequence number of a stream this module built.
    pub fn with_seq(src: &[u8], seq: u8) -> Vec<u8> {
        let mut out = src.to_vec();
        out[1] = seq;
        out
    }

    /// Add `CLEARCODEC_FLAG_GLYPH_INDEX`, and optionally `GLYPH_HIT`, to a
    /// stream this module built.
    pub fn with_glyph(src: &[u8], index: u16, hit: bool) -> Vec<u8> {
        let mut out = src[..2].to_vec();
        out[0] |= 0x01 | if hit { 0x02 } else { 0 };
        out.extend_from_slice(&index.to_le_bytes());
        out.extend_from_slice(&src[2..]);
        out
    }

    /// A glyph hit, which carries no payload at all.
    pub fn glyph_hit(index: u16, seq: u8) -> Vec<u8> {
        let mut out = vec![0x03u8, seq];
        out.extend_from_slice(&index.to_le_bytes());
        out
    }

    /// One band covering the whole bitmap, every column a
    /// `SHORT_VBAR_CACHE_MISS` with its own explicit pixels.
    ///
    /// # Panics
    ///
    /// On a column list that does not match the width, or a column with more
    /// than 63 explicit pixels, which the six bit count field cannot express.
    pub fn band_short_miss(
        w: u16,
        h: u16,
        bkg: &[u8; 3],
        cols: &[(usize, Vec<[u8; 3]>)],
    ) -> Vec<u8> {
        assert_eq!(cols.len(), usize::from(w));
        let mut bands = Vec::new();
        bands.extend_from_slice(&0u16.to_le_bytes());
        bands.extend_from_slice(&(w - 1).to_le_bytes());
        bands.extend_from_slice(&0u16.to_le_bytes());
        bands.extend_from_slice(&(h - 1).to_le_bytes());
        bands.extend_from_slice(bkg);
        for (y_on, px) in cols {
            assert!(px.len() <= 63 && *y_on <= 255);
            let header = ((px.len() as u16) << 8) | (*y_on as u16);
            bands.extend_from_slice(&header.to_le_bytes());
            for p in px {
                bands.extend_from_slice(&[p[0], p[1], p[2]]);
            }
        }
        with_seq(&stream(&[], &bands, &[]), 0)
    }

    /// One band covering the whole bitmap, every column a `VBAR_CACHE_HIT`.
    ///
    /// # Panics
    ///
    /// On an index list that does not match the width.
    pub fn band_vbar_hits(w: u16, h: u16, bkg: &[u8; 3], indices: &[u16], seq: u8) -> Vec<u8> {
        assert_eq!(indices.len(), usize::from(w));
        let mut bands = Vec::new();
        bands.extend_from_slice(&0u16.to_le_bytes());
        bands.extend_from_slice(&(w - 1).to_le_bytes());
        bands.extend_from_slice(&0u16.to_le_bytes());
        bands.extend_from_slice(&(h - 1).to_le_bytes());
        bands.extend_from_slice(bkg);
        for &i in indices {
            bands.extend_from_slice(&(0x8000u16 | i).to_le_bytes());
        }
        with_seq(&stream(&[], &bands, &[]), seq)
    }

    /// RLEX with one segment per pixel: a palette of the distinct colours and
    /// a run of one, with no suite. The suite path is the half of RLEX this
    /// lane could not pin (see `clear::rlex_code`), so the encoder does not
    /// emit it and no test here claims to cover it.
    ///
    /// # Panics
    ///
    /// On a rectangle with more than 127 distinct colours, which RLEX cannot
    /// express.
    fn rlex(px: &[[u8; 3]]) -> Vec<u8> {
        let mut palette: Vec<[u8; 3]> = Vec::new();
        for p in px {
            if !palette.contains(p) {
                palette.push(*p);
            }
        }
        assert!(
            palette.len() <= 127,
            "too many colours for one RLEX palette"
        );
        let mut out = vec![palette.len() as u8];
        for p in &palette {
            out.extend_from_slice(&[p[2], p[1], p[0]]);
        }
        let mut at = 0usize;
        while at < px.len() {
            let v = px[at];
            let mut run = 1usize;
            while at + run < px.len() && px[at + run] == v {
                run += 1;
            }
            let stop = palette.iter().position(|c| *c == v).unwrap();
            out.push(stop as u8); // suite depth zero in the high bit
            run_length(&mut out, run);
            at += run;
        }
        out
    }

    /// A residual layer over the whole bitmap plus one subcodec rectangle.
    ///
    /// # Panics
    ///
    /// On pixel counts that do not match the geometries.
    #[allow(clippy::too_many_arguments)]
    pub fn residual_plus_subcodec(
        base: &[[u8; 3]],
        w: u16,
        h: u16,
        x: u16,
        y: u16,
        rw: u16,
        rh: u16,
        id: u8,
        rect: &[[u8; 3]],
    ) -> Vec<u8> {
        assert_eq!(base.len(), usize::from(w) * usize::from(h));
        assert_eq!(rect.len(), usize::from(rw) * usize::from(rh));
        let data = match id {
            0 => {
                let mut v = Vec::new();
                for p in rect {
                    v.extend_from_slice(&[p[2], p[1], p[0]]);
                }
                v
            }
            1 => super::nscodec(rect, usize::from(rw), usize::from(rh), 1, false, true),
            2 => rlex(rect),
            _ => {
                let mut v = Vec::new();
                for p in rect {
                    v.extend_from_slice(&[p[2], p[1], p[0]]);
                }
                v
            }
        };
        let mut sub = Vec::new();
        sub.extend_from_slice(&x.to_le_bytes());
        sub.extend_from_slice(&y.to_le_bytes());
        sub.extend_from_slice(&rw.to_le_bytes());
        sub.extend_from_slice(&rh.to_le_bytes());
        sub.extend_from_slice(&(data.len() as u32).to_le_bytes());
        sub.push(id);
        sub.extend_from_slice(&data);
        stream(&residual_layer(base), &[], &sub)
    }
}

// ---------------------------------------------------------------------------
// ZGFX, RDP 8.0 bulk compression (MS-RDPEGFX 2.2.5.1, MS-RDPBCGR 3.1.8.4.2)
// ---------------------------------------------------------------------------

/// Reference `RDP_SEGMENTED_DATA` streams.
///
/// The compressor is greedy and looks back at most 31 bytes, so it only ever
/// emits the first match token. That is enough to exercise the literal path,
/// the match path, the overlapping copy and the unencoded run escape, which
/// are the four things the decompressor can get wrong on its own.
///
/// It shares [`crate::zgfx::TOKENS`] with the decompressor rather than
/// carrying a second copy. A round trip through the shared table proves the
/// two agree and proves nothing about whether the table is the one
/// MS-RDPBCGR 3.1.8.4.2.2.1 publishes; `zgfx`'s module comment says so at
/// more length.
pub mod zgfx {
    use super::BitWriter;
    use crate::zgfx::TOKENS;

    /// The compressed segment flags byte: `PACKET_COMPRESSED` plus
    /// `PACKET_COMPR_TYPE_RDP8`.
    const COMPRESSED: u8 = 0x24;
    /// The same without `PACKET_COMPRESSED`.
    const UNCOMPRESSED: u8 = 0x04;

    /// The shortest literal token for one byte value.
    fn put_literal(w: &mut BitWriter, b: u8) {
        for t in TOKENS.iter() {
            if !t.is_match && t.value_bits == 0 && t.value_base == u32::from(b) {
                w.put(u32::from(t.code), u32::from(t.len));
                return;
            }
        }
        let t = TOKENS[0];
        w.put(u32::from(t.code), u32::from(t.len));
        w.put(u32::from(b), 8);
    }

    /// The first match token, whose distance base is zero and whose value is
    /// five bits, so it covers distances 1 to 31 and the distance zero
    /// escape.
    fn put_match_token(w: &mut BitWriter, distance: u32) {
        let t = TOKENS[1];
        w.put(u32::from(t.code), u32::from(t.len));
        w.put(distance, u32::from(t.value_bits));
    }

    /// The match length code: three is one zero bit, and everything else is a
    /// one, a unary width, and the value.
    fn put_length(w: &mut BitWriter, len: usize) {
        if len == 3 {
            w.put(0, 1);
            return;
        }
        let mut extra = 2u32;
        while (1usize << (extra + 1)) <= len {
            extra += 1;
        }
        w.put(1, 1);
        for _ in 0..extra - 2 {
            w.put(1, 1);
        }
        w.put(0, 1);
        w.put((len - (1usize << extra)) as u32, extra);
    }

    fn segment(flags: u8, body: Vec<u8>, pad: u8) -> Vec<u8> {
        let mut seg = vec![flags];
        seg.extend_from_slice(&body);
        if flags & 0x20 != 0 {
            seg.push(pad);
        }
        seg
    }

    fn single(seg: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0xE0u8];
        out.extend_from_slice(&seg);
        out
    }

    /// One uncompressed segment, which still seeds the history.
    pub fn single_uncompressed(data: &[u8]) -> Vec<u8> {
        single(segment(UNCOMPRESSED, data.to_vec(), 0))
    }

    /// One compressed segment, greedy over literals and short matches.
    pub fn single_compressed(data: &[u8]) -> Vec<u8> {
        let mut w = BitWriter::new();
        let mut i = 0usize;
        while i < data.len() {
            let mut best = (0usize, 0usize); // (length, distance)
            let max_d = i.min(31);
            for d in 1..=max_d {
                let mut n = 0usize;
                while i + n < data.len() && n < 255 && data[i + n] == data[i - d + (n % d)] {
                    n += 1;
                }
                if n >= 3 && n > best.0 {
                    best = (n, d);
                }
            }
            if best.0 >= 3 {
                put_match_token(&mut w, best.1 as u32);
                put_length(&mut w, best.0);
                i += best.0;
            } else {
                put_literal(&mut w, data[i]);
                i += 1;
            }
        }
        let pad = w.padding();
        single(segment(COMPRESSED, w.finish(), pad))
    }

    /// One compressed segment holding exactly one match, for the tests that
    /// reach back into a history the previous message left behind.
    ///
    /// # Panics
    ///
    /// On a distance the first match token cannot express.
    pub fn single_compressed_match(distance: u32, length: usize) -> Vec<u8> {
        assert!((1..32).contains(&distance));
        let mut w = BitWriter::new();
        put_match_token(&mut w, distance);
        put_length(&mut w, length);
        let pad = w.padding();
        single(segment(COMPRESSED, w.finish(), pad))
    }

    /// One compressed segment that is nothing but the distance zero escape:
    /// fifteen bits of count, a byte align, then the literal bytes.
    ///
    /// # Panics
    ///
    /// On a run longer than the fifteen bit count can express.
    pub fn single_unencoded_run(data: &[u8]) -> Vec<u8> {
        assert!(data.len() < (1 << 15));
        let mut w = BitWriter::new();
        put_match_token(&mut w, 0);
        w.put(data.len() as u32, 15);
        w.align();
        w.raw(data);
        let pad = w.padding();
        single(segment(COMPRESSED, w.finish(), pad))
    }

    /// A multipart message of uncompressed segments.
    pub fn multipart(parts: &[&[u8]]) -> Vec<u8> {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut out = vec![0xE1u8];
        out.extend_from_slice(&(parts.len() as u16).to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        for p in parts {
            let seg = segment(UNCOMPRESSED, p.to_vec(), 0);
            out.extend_from_slice(&(seg.len() as u32).to_le_bytes());
            out.extend_from_slice(&seg);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uncompressed::dst_len;
    use crate::{planar as planar_dec, rle};
    use remote_pixel::{DstView, OutFormat, RowOrder};

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
