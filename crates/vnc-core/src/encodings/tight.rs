//! Tight (7), the workhorse encoding (PRD/02 §2.1).
//!
//! Compression control byte:
//! - bits 0-3: reset Tight zlib streams 0-3 (before anything else)
//! - bit 7 == 0: BasicCompression, bits 4-5 = stream id, bit 6 = a filter-id
//!   byte follows (else filter 0 / Copy)
//! - `1000` (0x08 << 4): Fill, a single TPIXEL
//! - `1001`: JPEG, compact length + JFIF data
//! - `1010`/`1110`: Basic without zlib (pseudo-encoding -317)
//!
//! TPIXEL is 3 bytes (R, G, B) when the pixel format is compact
//! (32bpp/depth24/8-bit channels). Payloads shorter than 12 bytes are sent
//! uncompressed with no length prefix. The FOUR zlib streams are persistent
//! for the whole connection; reset only via the control bits.

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{derr, read_exact_vec, ZlibStream, MAX_WIRE_LEN};
use crate::error::Result;
use crate::pixel::convert::{pixel_to_rgba, raw_pixel_value, scale_channel};
use crate::pixel::convert_to_rgba_mapped;
use crate::pixel::ColourMap;
use crate::types::{PixelFormat, Rect, RectPayload};

const FILTER_COPY: u8 = 0;
const FILTER_PALETTE: u8 = 1;
const FILTER_GRADIENT: u8 = 2;

/// Payloads below this size are sent uncompressed (no zlib, no length).
const MIN_BYTES_TO_COMPRESS: usize = 12;

pub(crate) async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
    streams: &mut [ZlibStream; 4],
) -> Result<RectPayload> {
    let ctrl = reader.read_u8().await?;

    // Stream resets apply regardless of compression type.
    for (i, s) in streams.iter_mut().enumerate() {
        if ctrl & (1 << i) != 0 {
            s.reset();
        }
    }

    let cc = ctrl >> 4;
    match cc {
        // BasicCompression (bit 7 clear).
        0x00..=0x07 => {
            let stream_id = (cc & 0x3) as usize;
            let has_filter = cc & 0x4 != 0;
            decode_basic(
                reader,
                rect,
                pf,
                map,
                Some(&mut streams[stream_id]),
                has_filter,
            )
            .await
        }
        // Fill: one TPIXEL covering the whole rect.
        0x08 => {
            let colour = read_tpixel(reader, pf, map).await?;
            let mut out = vec![0u8; rect.area() * 4];
            for px in out.chunks_exact_mut(4) {
                px.copy_from_slice(&colour);
            }
            Ok(RectPayload::Rgba(out))
        }
        // JPEG: compact length + JFIF stream, GPU-decoded in the webview.
        0x09 => {
            let len = read_compact_len(reader).await?;
            let data = read_exact_vec(reader, len, "tight").await?;
            Ok(RectPayload::Jpeg(data))
        }
        // Basic without zlib (pseudo-encoding -317): 1010 = no filter byte,
        // 1110 = filter byte follows.
        0x0A => decode_basic(reader, rect, pf, map, None, false).await,
        0x0E => decode_basic(reader, rect, pf, map, None, true).await,
        other => Err(derr(
            "tight",
            format!("invalid compression control {other:#x}"),
        )),
    }
}

/// BasicCompression body. `stream: None` = the no-zlib variant (data is
/// always unframed and uncompressed).
async fn decode_basic<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
    stream: Option<&mut ZlibStream>,
    has_filter: bool,
) -> Result<RectPayload> {
    let w = rect.width as usize;
    let h = rect.height as usize;
    let tpx = tpixel_size(pf);

    let filter = if has_filter {
        reader.read_u8().await?
    } else {
        FILTER_COPY
    };

    // Palette (if any) is read *before* the compressed data and is never
    // itself compressed.
    let mut palette: Vec<[u8; 4]> = Vec::new();
    let row_bytes = match filter {
        FILTER_COPY => w * tpx,
        FILTER_PALETTE => {
            let num_colours = reader.read_u8().await? as usize + 1;
            let raw = read_exact_vec(reader, num_colours * tpx, "tight").await?;
            palette = raw
                .chunks_exact(tpx)
                .map(|c| tpixel_to_rgba(c, pf, map))
                .collect();
            if num_colours == 2 {
                w.div_ceil(8)
            } else {
                w
            }
        }
        FILTER_GRADIENT => {
            if !pf.true_colour {
                return Err(derr("tight", "gradient filter requires true colour"));
            }
            w * tpx
        }
        other => return Err(derr("tight", format!("unknown filter id {other}"))),
    };

    let total = row_bytes * h;
    let data = match stream {
        Some(s) if total >= MIN_BYTES_TO_COMPRESS => {
            let clen = read_compact_len(reader).await?;
            let compressed = read_exact_vec(reader, clen, "tight").await?;
            let out = s.decompress(&compressed, total, total + 1024, "tight")?;
            if out.len() < total {
                return Err(derr(
                    "tight",
                    format!("short inflate: got {} of {total} bytes", out.len()),
                ));
            }
            out
        }
        // < 12 bytes, or the no-zlib variant: raw bytes, no length prefix.
        _ => read_exact_vec(reader, total, "tight").await?,
    };
    let data = &data[..total];

    let rgba = match filter {
        FILTER_COPY if pf.is_compact_3byte() => {
            // Compact TPIXELs are literally R, G, B, a straight widening
            // copy, with the format test hoisted out of the pixel loop.
            let mut out = vec![0u8; w * h * 4];
            for (s, d) in data.chunks_exact(3).zip(out.chunks_exact_mut(4)) {
                d[0] = s[0];
                d[1] = s[1];
                d[2] = s[2];
                d[3] = 255;
            }
            out
        }
        // Non-compact TPIXEL == an ordinary wire pixel, so this is exactly
        // what the (already specialised) bulk converter does.
        FILTER_COPY => convert_to_rgba_mapped(data, pf, w * h, map),
        FILTER_PALETTE => unpack_palette(data, &palette, w, h, row_bytes)?,
        FILTER_GRADIENT => undo_gradient(data, pf, w, h, tpx),
        _ => unreachable!(),
    };

    Ok(RectPayload::Rgba(rgba))
}

fn unpack_palette(
    data: &[u8],
    palette: &[[u8; 4]],
    w: usize,
    h: usize,
    row_bytes: usize,
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; w * h * 4];
    if palette.len() == 2 {
        // 1-bit packed, MSB first, rows padded to a byte boundary.
        for y in 0..h {
            let row = &data[y * row_bytes..(y + 1) * row_bytes];
            for x in 0..w {
                let bit = (row[x / 8] >> (7 - (x % 8))) & 1;
                let o = (y * w + x) * 4;
                out[o..o + 4].copy_from_slice(&palette[bit as usize]);
            }
        }
    } else {
        for y in 0..h {
            let row = &data[y * row_bytes..(y + 1) * row_bytes];
            for (x, &byte) in row.iter().take(w).enumerate() {
                let idx = byte as usize;
                let colour = palette
                    .get(idx)
                    .ok_or_else(|| derr("tight", format!("palette index {idx} out of range")))?;
                let o = (y * w + x) * 4;
                out[o..o + 4].copy_from_slice(colour);
            }
        }
    }
    Ok(out)
}

/// Undo the gradient prediction filter: each channel value is transmitted as
/// the difference (mod max+1) from the prediction `clamp(left + up - upleft)`.
fn undo_gradient(data: &[u8], pf: &PixelFormat, w: usize, h: usize, tpx: usize) -> Vec<u8> {
    if w == 0 || h == 0 {
        return Vec::new();
    }
    if tpx == 3 {
        undo_gradient_compact(data, w, h)
    } else {
        undo_gradient_generic(data, pf, w, h, tpx)
    }
}

/// Compact TPIXEL gradient, by far the common case (32bpp/depth24 servers).
///
/// With 8-bit channels every per-pixel division disappears: `max + 1 == 256`
/// makes `rem_euclid` a wrapping `u8` add, and `scale_channel(v, 255) == v`
/// makes the output scaling the identity. The previous row is carried in a
/// single reused buffer so the whole thing is three zipped `chunks_exact`
/// walks with no bounds checks.
fn undo_gradient_compact(data: &[u8], w: usize, h: usize) -> Vec<u8> {
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
                let pred = (left[c] as i32 + u[c] as i32 - upleft[c] as i32).clamp(0, 255) as u8;
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

/// Gradient over an arbitrary true-colour layout (non-compact TPIXEL).
fn undo_gradient_generic(data: &[u8], pf: &PixelFormat, w: usize, h: usize, tpx: usize) -> Vec<u8> {
    let maxes: [i32; 3] = [pf.red_max as i32, pf.green_max as i32, pf.blue_max as i32];
    let shifts = [pf.red_shift, pf.green_shift, pf.blue_shift];

    let mut out = vec![0u8; w * h * 4];
    let mut prev: Vec<[i32; 3]> = vec![[0; 3]; w];
    let mut cur: Vec<[i32; 3]> = vec![[0; 3]; w];

    for y in 0..h {
        let mut left = [0i32; 3];
        for x in 0..w {
            let p = &data[(y * w + x) * tpx..(y * w + x) * tpx + tpx];
            let v = raw_pixel_value(p, pf.big_endian);
            let raw: [i32; 3] = [
                ((v >> shifts[0]) & maxes[0] as u32) as i32,
                ((v >> shifts[1]) & maxes[1] as u32) as i32,
                ((v >> shifts[2]) & maxes[2] as u32) as i32,
            ];
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

// ---------------------------------------------------------------------------
// TPIXEL + compact length
// ---------------------------------------------------------------------------

#[inline]
pub(crate) fn tpixel_size(pf: &PixelFormat) -> usize {
    if pf.is_compact_3byte() {
        3
    } else {
        pf.bytes_per_pixel()
    }
}

/// Convert one TPIXEL. In the compact form the bytes are literally R, G, B
/// (TigerVNC/noVNC behaviour); otherwise it is a normal wire pixel.
#[inline]
fn tpixel_to_rgba(bytes: &[u8], pf: &PixelFormat, map: Option<&ColourMap>) -> [u8; 4] {
    if pf.is_compact_3byte() {
        [bytes[0], bytes[1], bytes[2], 255]
    } else {
        pixel_to_rgba(bytes, pf, map)
    }
}

async fn read_tpixel<R: AsyncRead + Unpin>(
    reader: &mut R,
    pf: &PixelFormat,
    map: Option<&ColourMap>,
) -> Result<[u8; 4]> {
    let n = tpixel_size(pf);
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf[..n]).await?;
    Ok(tpixel_to_rgba(&buf[..n], pf, map))
}

/// Tight compact length: 1-3 bytes, 7 bits each, high bit = continue
/// (the third byte contributes all 8 bits).
pub(crate) async fn read_compact_len<R: AsyncRead + Unpin>(reader: &mut R) -> Result<usize> {
    let b0 = reader.read_u8().await?;
    let mut len = (b0 & 0x7f) as usize;
    if b0 & 0x80 != 0 {
        let b1 = reader.read_u8().await?;
        len |= ((b1 & 0x7f) as usize) << 7;
        if b1 & 0x80 != 0 {
            let b2 = reader.read_u8().await?;
            len |= (b2 as usize) << 14;
        }
    }
    if len > MAX_WIRE_LEN {
        return Err(derr("tight", format!("compact length {len} exceeds cap")));
    }
    Ok(len)
}

// ---------------------------------------------------------------------------
// JPEG helper (thumbnails / native framebuffer fills)
// ---------------------------------------------------------------------------

/// Decode a JPEG rect payload to `(width, height, RGBA8888)`.
///
/// The hot path hands [`RectPayload::Jpeg`] to the webview for GPU decode;
/// this software path exists for the native framebuffer (thumbnails).
pub fn decode_jpeg_to_rgba(data: &[u8]) -> Result<(u32, u32, Vec<u8>)> {
    use zune_jpeg::zune_core::bytestream::ZCursor;
    use zune_jpeg::zune_core::colorspace::ColorSpace;
    use zune_jpeg::zune_core::options::DecoderOptions;
    use zune_jpeg::JpegDecoder;

    let options = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGBA);
    // zune-jpeg 0.5 reads through `ZByteReaderTrait` rather than a bare slice,
    // so the input is wrapped in a cursor. Still zero-copy over `data`.
    let mut decoder = JpegDecoder::new_with_options(ZCursor::new(data), options);
    let pixels = decoder
        .decode()
        .map_err(|e| derr("tight-jpeg", format!("jpeg decode failed: {e:?}")))?;
    let info = decoder
        .info()
        .ok_or_else(|| derr("tight-jpeg", "jpeg missing image info"))?;
    let (w, h) = (info.width as u32, info.height as u32);
    let n = w as usize * h as usize;
    if n == 0 {
        return Ok((0, 0, Vec::new()));
    }

    // Normalise whatever component count came back to RGBA.
    let comps = pixels.len() / n;
    let rgba = match comps {
        4 => pixels,
        3 => {
            let mut out = vec![255u8; n * 4];
            for i in 0..n {
                out[i * 4..i * 4 + 3].copy_from_slice(&pixels[i * 3..i * 3 + 3]);
            }
            out
        }
        1 => {
            let mut out = vec![255u8; n * 4];
            for i in 0..n {
                let l = pixels[i];
                out[i * 4] = l;
                out[i * 4 + 1] = l;
                out[i * 4 + 2] = l;
            }
            out
        }
        c => {
            return Err(derr(
                "tight-jpeg",
                format!("unexpected component count {c}"),
            ))
        }
    };
    Ok((w, h, rgba))
}

#[cfg(test)]
mod tests {

    /// A real JPEG, decoded end to end. This path had no coverage, which
    /// matters because it parses server-supplied bytes and because the reader
    /// API changed in zune-jpeg 0.5. The fixture is 8x8, left half pure red
    /// and right half pure blue, so a channel-order or stride regression is
    /// visible rather than subtle.
    const JPEG_8X8_RED_BLUE: &[u8] = &[
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x02, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x08, 0x00, 0x08, 0x03,
        0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x02,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x04,
        0x03, 0x02, 0x02, 0x02, 0x02, 0x05, 0x04, 0x04, 0x03, 0x04, 0x06, 0x05, 0x06, 0x06, 0x06,
        0x05, 0x06, 0x06, 0x06, 0x07, 0x09, 0x08, 0x06, 0x07, 0x09, 0x07, 0x06, 0x06, 0x08, 0x0b,
        0x08, 0x09, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x06, 0x08, 0x0b, 0x0c, 0x0b, 0x0a, 0x0c, 0x09,
        0x0a, 0x0a, 0x0a, 0xff, 0xdb, 0x00, 0x43, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x05,
        0x03, 0x03, 0x05, 0x0a, 0x07, 0x06, 0x07, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
        0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
        0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
        0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0xff, 0xc4, 0x00,
        0x1f, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0xff, 0xc4, 0x00, 0xb5, 0x10, 0x00, 0x02, 0x01, 0x03, 0x03, 0x02, 0x04, 0x03, 0x05, 0x05,
        0x04, 0x04, 0x00, 0x00, 0x01, 0x7d, 0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21,
        0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08,
        0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56,
        0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75,
        0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92, 0x93,
        0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
        0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6,
        0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
        0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xff, 0xc4, 0x00, 0x1f, 0x01, 0x00, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xc4, 0x00, 0xb5, 0x11, 0x00, 0x02, 0x01, 0x02,
        0x04, 0x04, 0x03, 0x04, 0x07, 0x05, 0x04, 0x04, 0x00, 0x01, 0x02, 0x77, 0x00, 0x01, 0x02,
        0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71, 0x13, 0x22,
        0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0, 0x15,
        0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
        0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66,
        0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84,
        0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
        0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4,
        0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea,
        0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xff, 0xda, 0x00, 0x0c, 0x03, 0x01,
        0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3f, 0x00, 0xfc, 0xd1, 0xfd, 0xaa, 0xbf, 0xe6, 0x03,
        0xff, 0x00, 0x6f, 0x5f, 0xfb, 0x46, 0xbf, 0xaa, 0x3f, 0x66, 0x5f, 0xfc, 0xd5, 0x7f, 0xf7,
        0x23, 0xff, 0x00, 0xbb, 0x87, 0xf6, 0xa7, 0xed, 0x0c, 0xff, 0x00, 0x9a, 0x67, 0xfe, 0xe7,
        0x7f, 0xf7, 0x50, 0xff, 0xd9,
    ];

    #[test]
    fn decode_jpeg_to_rgba_returns_rgba_pixels() {
        let (w, h, rgba) = decode_jpeg_to_rgba(JPEG_8X8_RED_BLUE).expect("decode");
        assert_eq!((w, h), (8, 8));
        assert_eq!(rgba.len(), 8 * 8 * 4, "expected tightly packed RGBA");

        let px = |x: usize, y: usize| {
            let i = (y * 8 + x) * 4;
            (rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3])
        };

        // JPEG is lossy, so assert dominance rather than exact values.
        for y in [0usize, 7] {
            let (r, g, b, a) = px(1, y);
            assert!(
                r > 150 && g < 90 && b < 90,
                "left half should be red, got {:?}",
                (r, g, b)
            );
            assert_eq!(a, 255, "alpha must be opaque");

            let (r, g, b, a) = px(6, y);
            assert!(
                b > 150 && r < 90 && g < 90,
                "right half should be blue, got {:?}",
                (r, g, b)
            );
            assert_eq!(a, 255, "alpha must be opaque");
        }
    }

    #[test]
    fn decode_jpeg_rejects_garbage_without_panicking() {
        assert!(decode_jpeg_to_rgba(&[]).is_err());
        assert!(decode_jpeg_to_rgba(b"not a jpeg at all").is_err());
        // Valid header, truncated body: the common hostile shape.
        assert!(decode_jpeg_to_rgba(&JPEG_8X8_RED_BLUE[..20]).is_err());
    }
    use super::*;

    fn pf() -> PixelFormat {
        PixelFormat::bgra8888()
    }

    fn streams() -> [ZlibStream; 4] {
        [
            ZlibStream::new(),
            ZlibStream::new(),
            ZlibStream::new(),
            ZlibStream::new(),
        ]
    }

    #[tokio::test]
    async fn fill_rect() {
        // Control 0x80 = Fill; compact TPIXEL = [R, G, B].
        let wire = [0x80u8, 10, 20, 30];
        let mut r: &[u8] = &wire;
        let mut s = streams();
        let payload = decode(&mut r, Rect::new(0, 0, 3, 2), &pf(), None, &mut s)
            .await
            .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                assert_eq!(px.len(), 3 * 2 * 4);
                for p in px.chunks_exact(4) {
                    assert_eq!(p, &[10, 20, 30, 255]);
                }
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn palette_two_colours_bit_packed() {
        // Basic compression, stream 0, filter byte follows: ctrl = 0x40.
        // Palette filter, 2 colours -> 1-bit packed rows; 2x2 rect ->
        // 1 byte/row * 2 rows = 2 bytes < 12 -> uncompressed.
        let mut wire: Vec<u8> = vec![0x40, FILTER_PALETTE, 1];
        wire.extend_from_slice(&[255, 0, 0]); // colour 0 = red (TPIXEL: R,G,B)
        wire.extend_from_slice(&[0, 0, 255]); // colour 1 = blue
        wire.push(0b0100_0000); // row 0: pixels [c0, c1]
        wire.push(0b1000_0000); // row 1: pixels [c1, c0]
        let mut r: &[u8] = &wire;
        let mut s = streams();
        let payload = decode(&mut r, Rect::new(0, 0, 2, 2), &pf(), None, &mut s)
            .await
            .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                assert_eq!(&px[0..4], &[255, 0, 0, 255]);
                assert_eq!(&px[4..8], &[0, 0, 255, 255]);
                assert_eq!(&px[8..12], &[0, 0, 255, 255]);
                assert_eq!(&px[12..16], &[255, 0, 0, 255]);
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn palette_index_out_of_range_errors() {
        // 3-colour palette -> 8-bit indices; 4x4 rect = 16 bytes >= 12 so it
        // would be compressed; use the no-zlib variant (0xE0) to keep the
        // test wire simple.
        let mut wire: Vec<u8> = vec![0xE0, FILTER_PALETTE, 2];
        wire.extend_from_slice(&[0, 0, 0, 1, 1, 1, 2, 2, 2]); // 3 colours
        wire.extend_from_slice(&[9; 16]); // index 9 out of range
        let mut r: &[u8] = &wire;
        let mut s = streams();
        assert!(decode(&mut r, Rect::new(0, 0, 4, 4), &pf(), None, &mut s)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn copy_filter_compressed_roundtrip() {
        use flate2::{Compress, Compression, FlushCompress};
        // 4x1 rect, compact TPIXELs -> 12 bytes -> compressed path.
        let raw: Vec<u8> = vec![
            1, 2, 3, //
            4, 5, 6, //
            7, 8, 9, //
            10, 11, 12,
        ];
        let mut comp = Vec::with_capacity(raw.len() + 1024);
        Compress::new(Compression::default(), true)
            .compress_vec(&raw, &mut comp, FlushCompress::Sync)
            .unwrap();
        // ctrl 0x00: basic, stream 0, no filter byte (= Copy filter).
        let mut wire: Vec<u8> = vec![0x00];
        wire.push(comp.len() as u8); // compact length (fits in 7 bits)
        wire.extend_from_slice(&comp);
        let mut r: &[u8] = &wire;
        let mut s = streams();
        let payload = decode(&mut r, Rect::new(0, 0, 4, 1), &pf(), None, &mut s)
            .await
            .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                assert_eq!(&px[0..4], &[1, 2, 3, 255]);
                assert_eq!(&px[12..16], &[10, 11, 12, 255]);
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    /// Forward-filter a real image, decode it back and require an exact match.
    /// This is the guard on the specialised compact gradient path.
    #[tokio::test]
    async fn gradient_filter_round_trips() {
        let (w, h) = (9usize, 5usize);
        let pixels: Vec<[u8; 3]> = (0..w * h)
            .map(|i| {
                [
                    (i * 17 % 251) as u8,
                    (i * 29 % 253) as u8,
                    (i * 43 % 247) as u8,
                ]
            })
            .collect();

        // Encode: residual = value - clamp(left + up - upleft), mod 256.
        let mut data = vec![0u8; w * h * 3];
        let mut prev = vec![[0i32; 3]; w];
        let mut cur = vec![[0i32; 3]; w];
        for y in 0..h {
            let mut left = [0i32; 3];
            for x in 0..w {
                let v = pixels[y * w + x];
                let upleft = if x > 0 { prev[x - 1] } else { [0; 3] };
                for c in 0..3 {
                    let pred = (left[c] + prev[x][c] - upleft[c]).clamp(0, 255);
                    data[(y * w + x) * 3 + c] = (v[c] as i32 - pred).rem_euclid(256) as u8;
                    cur[x][c] = v[c] as i32;
                }
                left = cur[x];
            }
            std::mem::swap(&mut prev, &mut cur);
        }

        // ctrl 0xE0 = basic, no zlib, filter byte follows.
        let mut wire: Vec<u8> = vec![0xE0, FILTER_GRADIENT];
        wire.extend_from_slice(&data);
        let mut r: &[u8] = &wire;
        let mut s = streams();
        let payload = decode(
            &mut r,
            Rect::new(0, 0, w as u16, h as u16),
            &pf(),
            None,
            &mut s,
        )
        .await
        .unwrap();
        match payload {
            RectPayload::Rgba(px) => {
                for (i, want) in pixels.iter().enumerate() {
                    assert_eq!(
                        &px[i * 4..i * 4 + 4],
                        &[want[0], want[1], want[2], 255],
                        "pixel {i}"
                    );
                }
            }
            other => panic!("expected Rgba, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn jpeg_rect_passthrough() {
        // ctrl 0x90 = JPEG; compact length 5; opaque payload bytes.
        let wire = [0x90u8, 5, 1, 2, 3, 4, 5];
        let mut r: &[u8] = &wire;
        let mut s = streams();
        let payload = decode(&mut r, Rect::new(0, 0, 8, 8), &pf(), None, &mut s)
            .await
            .unwrap();
        match payload {
            RectPayload::Jpeg(data) => assert_eq!(data, vec![1, 2, 3, 4, 5]),
            other => panic!("expected Jpeg, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn compact_len_multibyte() {
        // 0x83 0x01 -> 3 | (1 << 7) = 131
        let mut r: &[u8] = &[0x83, 0x01];
        assert_eq!(read_compact_len(&mut r).await.unwrap(), 131);
        // 0x80 0x80 0x01 -> 1 << 14 = 16384
        let mut r: &[u8] = &[0x80, 0x80, 0x01];
        assert_eq!(read_compact_len(&mut r).await.unwrap(), 16384);
    }
}
