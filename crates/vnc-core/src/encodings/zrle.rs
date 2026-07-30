//! ZRLE (16) and TRLE (15): 64x64 tiles of palette/RLE data.
//!
//! ZRLE wraps the tile stream in ONE persistent zlib stream for the whole
//! connection; TRLE sends the identical tile stream uncompressed. CPIXEL is
//! 3 bytes when the pixel format is compact (bpp32/depth24).
//!
//! Tile subencodings: 0 raw, 1 solid, 2-16 packed palette (1/2/4-bit
//! indices), 128 plain RLE, 130-255 palette RLE (palette size = subenc-128).

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{derr, read_exact_into, read_exact_vec, ZlibStream};
use crate::error::Result;
use crate::pixel::convert::{cpixel_to_rgba, pixel_to_rgba};
use crate::pixel::ColourMap;
use crate::types::{PixelFormat, Rect, RectPayload};

pub(crate) async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
    zlib: Option<&mut ZlibStream>, // Some = ZRLE, None = TRLE
) -> Result<RectPayload> {
    match zlib {
        Some(stream) => {
            let enc = "zrle";
            let clen = reader.read_u32().await? as usize;
            let compressed = read_exact_vec(reader, clen, enc).await?;
            // Worst case is roughly raw tiles: area * cpixel_size + 1 byte
            // per tile of subencoding overhead.
            let hint = rect.area() * cpixel_size(pf);
            let cap = hint + rect.area() / 1024 + 4096;
            let data = stream.decompress(&compressed, hint, cap, enc)?;
            let mut cursor: &[u8] = &data;
            decode_tiles(&mut cursor, rect, pf, map, enc).await
        }
        None => decode_tiles(reader, rect, pf, map, "trle").await,
    }
}

async fn decode_tiles<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
    enc: &'static str,
) -> Result<RectPayload> {
    let w = rect.width as usize;
    let h = rect.height as usize;
    let mut out = vec![0u8; w * h * 4];

    // Scratch reused by every tile: the decoded tile, its palette and its raw
    // wire payload. A 1080p ZRLE rect is ~510 tiles, so this removes ~1500
    // allocate/free pairs per frame.
    let mut scratch = TileScratch::default();

    let mut ty = 0usize;
    while ty < h {
        let th = (h - ty).min(64);
        let mut tx = 0usize;
        while tx < w {
            let tw = (w - tx).min(64);
            decode_tile(reader, pf, map, tw, th, enc, &mut scratch).await?;
            let tile = &scratch.tile[..tw * th * 4];
            for row in 0..th {
                let src = row * tw * 4;
                let dst = ((ty + row) * w + tx) * 4;
                out[dst..dst + tw * 4].copy_from_slice(&tile[src..src + tw * 4]);
            }
            tx += tw;
        }
        ty += th;
    }
    Ok(RectPayload::Rgba(out))
}

/// Per-rect scratch buffers, grown once and then reused for every tile.
#[derive(Default)]
struct TileScratch {
    tile: Vec<u8>,
    palette: Vec<[u8; 4]>,
    wire: Vec<u8>,
}

impl TileScratch {
    /// Make `tile` at least `len` bytes long. It only ever grows, and every
    /// subencoding writes each of the `len` bytes before the tile is read, so
    /// no re-zeroing is needed between tiles.
    fn tile_mut(&mut self, len: usize) -> &mut [u8] {
        if self.tile.len() < len {
            self.tile.resize(len, 0);
        }
        &mut self.tile[..len]
    }
}

async fn decode_tile<R: AsyncRead + Unpin>(
    reader: &mut R,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
    tw: usize,
    th: usize,
    enc: &'static str,
    scratch: &mut TileScratch,
) -> Result<()> {
    let n = tw * th;
    let sub = reader.read_u8().await?;

    match sub {
        // Raw: tw*th CPIXELs.
        0 => {
            let cps = cpixel_size(pf);
            read_exact_into(reader, &mut scratch.wire, n * cps, enc).await?;
            let compact = pf.is_compact_3byte();
            let tile = {
                let len = n * 4;
                if scratch.tile.len() < len {
                    scratch.tile.resize(len, 0);
                }
                &mut scratch.tile[..len]
            };
            // Hoist the CPIXEL-form test out of the pixel loop.
            if compact {
                for (c, d) in scratch.wire.chunks_exact(3).zip(tile.chunks_exact_mut(4)) {
                    d.copy_from_slice(&cpixel_to_rgba(&[c[0], c[1], c[2]], pf));
                }
            } else {
                for (c, d) in scratch.wire.chunks_exact(cps).zip(tile.chunks_exact_mut(4)) {
                    d.copy_from_slice(&pixel_to_rgba(c, pf, map));
                }
            }
        }
        // Solid: one CPIXEL fills the tile.
        1 => {
            let colour = read_cpixel(reader, pf, map).await?;
            for px in scratch.tile_mut(n * 4).chunks_exact_mut(4) {
                px.copy_from_slice(&colour);
            }
        }
        // Packed palette: 1/2/4-bit indices, rows padded to byte boundary.
        2..=16 => {
            let size = sub as usize;
            read_palette(reader, pf, map, size, enc, scratch).await?;
            let bits: usize = match size {
                2 => 1,
                3..=4 => 2,
                _ => 4,
            };
            let row_bytes = (tw * bits).div_ceil(8);
            read_exact_into(reader, &mut scratch.wire, row_bytes * th, enc).await?;
            let mask = (1u8 << bits) - 1;
            // A fixed 16-entry table: the index is provably in range after the
            // explicit size check, so the compiler drops the bounds check.
            let mut pal = [[0u8; 4]; 16];
            pal[..size].copy_from_slice(&scratch.palette);
            let tile = {
                let len = n * 4;
                if scratch.tile.len() < len {
                    scratch.tile.resize(len, 0);
                }
                &mut scratch.tile[..len]
            };
            for (row, out_row) in scratch
                .wire
                .chunks_exact(row_bytes)
                .zip(tile.chunks_exact_mut(tw * 4))
            {
                for (x, d) in out_row.chunks_exact_mut(4).enumerate() {
                    let bit_off = x * bits;
                    let byte = row[bit_off / 8];
                    let shift = 8 - bits - (bit_off % 8);
                    let idx = ((byte >> shift) & mask) as usize;
                    if idx >= size {
                        return Err(derr(
                            enc,
                            format!("packed palette index {idx} out of range"),
                        ));
                    }
                    d.copy_from_slice(&pal[idx & 0x0f]);
                }
            }
        }
        17..=127 => return Err(derr(enc, format!("unused subencoding {sub}"))),
        // Plain RLE: runs of (CPIXEL, 255-terminated length).
        128 => {
            let mut filled = 0usize;
            while filled < n {
                let colour = read_cpixel(reader, pf, map).await?;
                let len = read_run_length(reader).await?;
                if filled + len > n {
                    return Err(derr(enc, "RLE run overflows tile"));
                }
                let tile = scratch.tile_mut(n * 4);
                for px in tile[filled * 4..(filled + len) * 4].chunks_exact_mut(4) {
                    px.copy_from_slice(&colour);
                }
                filled += len;
            }
        }
        129 => return Err(derr(enc, "unused subencoding 129")),
        // Palette RLE: palette size = sub - 128; index high bit = run follows.
        130..=255 => {
            let size = (sub - 128) as usize;
            read_palette(reader, pf, map, size, enc, scratch).await?;
            let mut filled = 0usize;
            while filled < n {
                let b = reader.read_u8().await?;
                let idx = (b & 0x7f) as usize;
                let len = if b & 0x80 != 0 {
                    read_run_length(reader).await?
                } else {
                    1
                };
                let colour = *scratch
                    .palette
                    .get(idx)
                    .ok_or_else(|| derr(enc, format!("palette RLE index {idx} out of range")))?;
                if filled + len > n {
                    return Err(derr(enc, "palette RLE run overflows tile"));
                }
                let tile = scratch.tile_mut(n * 4);
                for px in tile[filled * 4..(filled + len) * 4].chunks_exact_mut(4) {
                    px.copy_from_slice(&colour);
                }
                filled += len;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CPIXEL + helpers
// ---------------------------------------------------------------------------

#[inline]
pub(crate) fn cpixel_size(pf: &PixelFormat) -> usize {
    if pf.is_compact_3byte() {
        3
    } else {
        pf.bytes_per_pixel()
    }
}

#[inline]
fn read_cpixel_slice(bytes: &[u8], pf: &PixelFormat, map: Option<&ColourMap>) -> [u8; 4] {
    if pf.is_compact_3byte() {
        cpixel_to_rgba(&[bytes[0], bytes[1], bytes[2]], pf)
    } else {
        pixel_to_rgba(bytes, pf, map)
    }
}

async fn read_cpixel<R: AsyncRead + Unpin>(
    reader: &mut R,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
) -> Result<[u8; 4]> {
    let cps = cpixel_size(pf);
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf[..cps]).await?;
    Ok(read_cpixel_slice(&buf[..cps], pf, map))
}

/// Read `size` CPIXELs into `scratch.palette` (reusing its allocation).
async fn read_palette<R: AsyncRead + Unpin>(
    reader: &mut R,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
    size: usize,
    enc: &'static str,
    scratch: &mut TileScratch,
) -> Result<()> {
    let cps = cpixel_size(pf);
    read_exact_into(reader, &mut scratch.wire, size * cps, enc).await?;
    let (palette, wire) = (&mut scratch.palette, &scratch.wire);
    palette.clear();
    palette.extend(
        wire.chunks_exact(cps)
            .map(|c| read_cpixel_slice(c, pf, map)),
    );
    Ok(())
}

/// RLE run length: sum of bytes + 1, each 255 byte adds 255 and continues.
async fn read_run_length<R: AsyncRead + Unpin>(reader: &mut R) -> Result<usize> {
    let mut len = 1usize;
    loop {
        let b = reader.read_u8().await?;
        len += b as usize;
        if b != 255 {
            return Ok(len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn pf() -> PixelFormat {
        PixelFormat::bgra8888()
    }

    fn zlib_wrap(tile_stream: &[u8]) -> Vec<u8> {
        let mut comp = Vec::with_capacity(tile_stream.len() + 1024);
        let mut c = Compress::new(Compression::default(), true);
        c.compress_vec(tile_stream, &mut comp, FlushCompress::Sync)
            .unwrap();
        assert_eq!(
            c.total_in() as usize,
            tile_stream.len(),
            "compressor consumed all input"
        );
        let mut wire = Vec::new();
        wire.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        wire.extend_from_slice(&comp);
        wire
    }

    #[tokio::test]
    async fn zrle_solid_tile() {
        // 10x10 rect -> one tile; subencoding 1 (solid) + compact CPIXEL.
        // bgra8888 is little endian with colour in the low 3 bytes:
        // bytes are B, G, R (blue_shift 0, green 8, red 16).
        let tile_stream = [1u8, 40, 30, 20]; // B=40 G=30 R=20
        let wire = zlib_wrap(&tile_stream);
        let mut r: &[u8] = &wire;
        let mut stream = ZlibStream::new();
        let payload = decode(
            &mut r,
            Rect::new(0, 0, 10, 10),
            &pf(),
            None,
            Some(&mut stream),
        )
        .await
        .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                assert_eq!(px.len(), 400);
                for p in px.chunks_exact(4) {
                    assert_eq!(p, &[20, 30, 40, 255]);
                }
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn zrle_packed_palette_two_colours() {
        // 4x2 tile, palette size 2 -> 1-bit indices, 1 byte per row.
        let mut ts: Vec<u8> = vec![2];
        ts.extend_from_slice(&[0, 0, 255]); // colour 0: B=0 G=0 R=255 -> red
        ts.extend_from_slice(&[255, 0, 0]); // colour 1: blue
        ts.push(0b0101_0000); // row 0: r b r b
        ts.push(0b1010_0000); // row 1: b r b r
        let wire = zlib_wrap(&ts);
        let mut r: &[u8] = &wire;
        let mut stream = ZlibStream::new();
        let payload = decode(
            &mut r,
            Rect::new(0, 0, 4, 2),
            &pf(),
            None,
            Some(&mut stream),
        )
        .await
        .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                let at = |x: usize, y: usize| &px[(y * 4 + x) * 4..(y * 4 + x) * 4 + 4];
                assert_eq!(at(0, 0), &[255, 0, 0, 255]);
                assert_eq!(at(1, 0), &[0, 0, 255, 255]);
                assert_eq!(at(0, 1), &[0, 0, 255, 255]);
                assert_eq!(at(3, 1), &[255, 0, 0, 255]);
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn zrle_plain_rle() {
        // 4x1 tile: run of 3 red + run of 1 blue.
        let mut ts: Vec<u8> = vec![128];
        ts.extend_from_slice(&[0, 0, 255]); // red
        ts.push(2); // run length 3 (2 + 1)
        ts.extend_from_slice(&[255, 0, 0]); // blue
        ts.push(0); // run length 1
        let wire = zlib_wrap(&ts);
        let mut r: &[u8] = &wire;
        let mut stream = ZlibStream::new();
        let payload = decode(
            &mut r,
            Rect::new(0, 0, 4, 1),
            &pf(),
            None,
            Some(&mut stream),
        )
        .await
        .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                assert_eq!(&px[0..4], &[255, 0, 0, 255]);
                assert_eq!(&px[8..12], &[255, 0, 0, 255]);
                assert_eq!(&px[12..16], &[0, 0, 255, 255]);
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn zrle_rle_overrun_errors() {
        // 2x1 tile, run claims 300 pixels.
        let mut ts: Vec<u8> = vec![128];
        ts.extend_from_slice(&[0, 0, 0]);
        ts.extend_from_slice(&[255, 44]); // 1 + 255 + 44 = 300
        let wire = zlib_wrap(&ts);
        let mut r: &[u8] = &wire;
        let mut stream = ZlibStream::new();
        assert!(decode(
            &mut r,
            Rect::new(0, 0, 2, 1),
            &pf(),
            None,
            Some(&mut stream)
        )
        .await
        .is_err());
    }

    /// A rect spanning six tiles of three different sizes, cycling through
    /// every subencoding. Guards the scratch buffers that are now reused
    /// across tiles: a stale byte anywhere would show up as a wrong pixel.
    #[tokio::test]
    async fn multi_tile_mixed_subencodings() {
        let (w, h) = (130usize, 70usize);
        let mut expect = vec![0u8; w * h * 4];
        let set = |img: &mut Vec<u8>, x: usize, y: usize, c: [u8; 3]| {
            let o = (y * w + x) * 4;
            img[o..o + 4].copy_from_slice(&[c[0], c[1], c[2], 255]);
        };

        let mut ts: Vec<u8> = Vec::new();
        let mut tile_no = 0usize;
        let mut ty = 0usize;
        while ty < h {
            let th = (h - ty).min(64);
            let mut tx = 0usize;
            while tx < w {
                let tw = (w - tx).min(64);
                match tile_no % 4 {
                    // Raw CPIXELs.
                    0 => {
                        ts.push(0);
                        for y in 0..th {
                            for x in 0..tw {
                                let c = [(tx + x) as u8, (ty + y) as u8, (tile_no * 40) as u8];
                                ts.extend_from_slice(&[c[2], c[1], c[0]]);
                                set(&mut expect, tx + x, ty + y, c);
                            }
                        }
                    }
                    // Solid.
                    1 => {
                        let c = [11u8, 22, 33];
                        ts.extend_from_slice(&[1, c[2], c[1], c[0]]);
                        for y in 0..th {
                            for x in 0..tw {
                                set(&mut expect, tx + x, ty + y, c);
                            }
                        }
                    }
                    // Packed palette: 4 colours -> 2-bit indices.
                    2 => {
                        let pal = [[200u8, 0, 0], [0, 200, 0], [0, 0, 200], [200, 200, 0]];
                        ts.push(4);
                        for c in pal {
                            ts.extend_from_slice(&[c[2], c[1], c[0]]);
                        }
                        let row_bytes = (tw * 2).div_ceil(8);
                        for y in 0..th {
                            let mut row = vec![0u8; row_bytes];
                            for x in 0..tw {
                                let idx = ((x + y) % 4) as u8;
                                row[x * 2 / 8] |= idx << (8 - 2 - ((x * 2) % 8));
                                set(&mut expect, tx + x, ty + y, pal[idx as usize]);
                            }
                            ts.extend_from_slice(&row);
                        }
                    }
                    // Palette RLE with runs of varying length.
                    _ => {
                        let pal = [[7u8, 8, 9], [250, 251, 252]];
                        ts.push(128 + 2);
                        for c in pal {
                            ts.extend_from_slice(&[c[2], c[1], c[0]]);
                        }
                        let n = tw * th;
                        let (mut i, mut k) = (0usize, 0usize);
                        while i < n {
                            let len = ((k * 7) % 13 + 1).min(n - i);
                            let idx = (k % 2) as u8;
                            if len == 1 {
                                ts.push(idx);
                            } else {
                                ts.push(idx | 0x80);
                                ts.push((len - 1) as u8);
                            }
                            for j in i..i + len {
                                set(&mut expect, tx + j % tw, ty + j / tw, pal[idx as usize]);
                            }
                            i += len;
                            k += 1;
                        }
                    }
                }
                tile_no += 1;
                tx += tw;
            }
            ty += th;
        }

        let wire = zlib_wrap(&ts);
        let mut r: &[u8] = &wire;
        let mut stream = ZlibStream::new();
        let payload = decode(
            &mut r,
            Rect::new(0, 0, w as u16, h as u16),
            &pf(),
            None,
            Some(&mut stream),
        )
        .await
        .unwrap();
        match payload {
            RectPayload::Rgba(px) => assert_eq!(px, expect),
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn trle_solid_tile_uncompressed() {
        // TRLE: same tile stream, no zlib framing.
        let wire = [1u8, 40, 30, 20];
        let mut r: &[u8] = &wire;
        let payload = decode(&mut r, Rect::new(0, 0, 3, 3), &pf(), None, None)
            .await
            .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                for p in px.chunks_exact(4) {
                    assert_eq!(p, &[20, 30, 40, 255]);
                }
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }
}
