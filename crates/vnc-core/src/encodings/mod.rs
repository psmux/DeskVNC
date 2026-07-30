//! Rectangle decoders for every supported RFB encoding.
//!
//! Entry point: [`decode_rect`], driven by [`DecoderState`] which owns all
//! per-connection decoder state, most importantly the **persistent zlib
//! streams** (four for Tight, one for ZRLE, one for the zlib encoding) that
//! must live for the whole connection (PRD/02 §9).

pub mod copy_rect;
pub mod h264;
pub mod hextile;
pub mod raw;
pub mod rre;
pub mod tight;
pub mod zlib;
pub mod zrle;

pub use tight::decode_jpeg_to_rgba;

use flate2::{Decompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Result, VncError};
use crate::pixel::ColourMap;
use crate::types::{encoding, DecodedRect, PixelFormat, Rect};

/// Reject any rect claiming more pixels than this before allocating anything.
pub(crate) const MAX_RECT_AREA: usize = 64 * 1024 * 1024;
/// Cap on any single length-prefixed payload read from the wire.
pub(crate) const MAX_WIRE_LEN: usize = 64 * 1024 * 1024;
/// Absolute cap on a single rect's decompressed size.
pub(crate) const MAX_INFLATED_LEN: usize = 256 * 1024 * 1024;

const READ_CHUNK: usize = 64 * 1024;

/// Shorthand for a decode error.
pub(crate) fn derr(encoding: &'static str, message: impl Into<String>) -> VncError {
    VncError::Decode {
        encoding,
        message: message.into(),
    }
}

// ---------------------------------------------------------------------------
// Wire read helpers
// ---------------------------------------------------------------------------

/// Read exactly `len` bytes, in chunks, so a hostile length can never force a
/// huge up-front allocation before any data has actually arrived.
pub(crate) async fn read_exact_vec<R: AsyncRead + Unpin>(
    reader: &mut R,
    len: usize,
    enc: &'static str,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    read_exact_into(reader, &mut buf, len, enc).await?;
    Ok(buf)
}

/// As [`read_exact_vec`] but into a caller-owned buffer, so hot loops that
/// read one payload per tile can reuse a single allocation.
pub(crate) async fn read_exact_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    len: usize,
    enc: &'static str,
) -> Result<()> {
    if len > MAX_WIRE_LEN {
        return Err(derr(
            enc,
            format!("payload length {len} exceeds cap {MAX_WIRE_LEN}"),
        ));
    }
    buf.clear();
    buf.reserve(len.min(READ_CHUNK));
    let mut remaining = len;
    while remaining > 0 {
        let take = remaining.min(READ_CHUNK);
        let start = buf.len();
        buf.resize(start + take, 0);
        reader.read_exact(&mut buf[start..]).await?;
        remaining -= take;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Persistent zlib stream
// ---------------------------------------------------------------------------

/// A persistent zlib decompression stream (state survives across rects; reset
/// only when the protocol says so).
pub(crate) struct ZlibStream {
    d: Decompress,
}

impl ZlibStream {
    pub(crate) fn new() -> Self {
        Self {
            d: Decompress::new(true),
        }
    }

    pub(crate) fn reset(&mut self) {
        self.d.reset(true);
    }

    /// Decompress `input` completely, using `FlushDecompress::Sync` so all
    /// output for this rect is flushed even though the stream stays open.
    ///
    /// `size_hint` pre-sizes the output; `cap` bounds it (server-derived
    /// expectations, additionally clamped by [`MAX_INFLATED_LEN`]).
    pub(crate) fn decompress(
        &mut self,
        input: &[u8],
        size_hint: usize,
        cap: usize,
        enc: &'static str,
    ) -> Result<Vec<u8>> {
        let cap = cap.min(MAX_INFLATED_LEN);
        let mut out: Vec<u8> = Vec::with_capacity(size_hint.min(cap).min(4 * 1024 * 1024));
        let mut consumed = 0usize;
        loop {
            if out.len() == out.capacity() {
                let grow = (out.capacity() / 2).clamp(4096, 1024 * 1024);
                out.reserve(grow);
            }
            let before_in = self.d.total_in();
            let before_out = self.d.total_out();
            let status = self
                .d
                .decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync)
                .map_err(|e| derr(enc, format!("zlib inflate failed: {e}")))?;
            let in_delta = (self.d.total_in() - before_in) as usize;
            let out_delta = (self.d.total_out() - before_out) as usize;
            consumed += in_delta;
            if out.len() > cap {
                return Err(derr(enc, format!("decompressed data exceeds cap {cap}")));
            }
            match status {
                Status::StreamEnd => break,
                Status::Ok | Status::BufError => {
                    // Input fully consumed and output not space-limited:
                    // everything available has been flushed.
                    if consumed >= input.len() && out.len() < out.capacity() {
                        break;
                    }
                    // No progress at all -> bail out rather than spin.
                    if in_delta == 0 && out_delta == 0 && consumed >= input.len() {
                        break;
                    }
                    if in_delta == 0 && out_delta == 0 && matches!(status, Status::BufError) {
                        return Err(derr(enc, "zlib made no progress (corrupt stream?)"));
                    }
                }
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Decoder state
// ---------------------------------------------------------------------------

/// Per-connection decoder state. Create once per connection; `reset()` on
/// reconnect (zlib streams and colour map are connection-scoped).
pub struct DecoderState {
    pf: PixelFormat,
    /// Tight zlib streams 0-3, persistent, reset only via control-byte bits.
    tight_streams: [ZlibStream; 4],
    /// The single persistent ZRLE stream.
    zrle_stream: ZlibStream,
    /// The single persistent stream for the plain zlib (6) encoding.
    zlib_stream: ZlibStream,
    /// Colour map for non-true-colour pixel formats (SetColourMapEntries).
    colour_map: Option<ColourMap>,
    /// H.264 decoder contexts, keyed by rect geometry (PRD/02 §2.3).
    h264: h264::H264Contexts,
}

impl DecoderState {
    pub fn new(pf: PixelFormat) -> Self {
        Self {
            pf,
            tight_streams: [
                ZlibStream::new(),
                ZlibStream::new(),
                ZlibStream::new(),
                ZlibStream::new(),
            ],
            zrle_stream: ZlibStream::new(),
            zlib_stream: ZlibStream::new(),
            colour_map: None,
            h264: h264::H264Contexts::new(),
        }
    }

    /// Mid-session SetPixelFormat. Deliberately does NOT touch the zlib
    /// streams, they are connection-scoped, not format-scoped.
    pub fn set_pixel_format(&mut self, pf: PixelFormat) {
        self.pf = pf;
    }

    pub fn pixel_format(&self) -> PixelFormat {
        self.pf
    }

    /// Full reset for a reconnect: fresh zlib streams, colour map cleared, and
    /// every H.264 decoder context forgotten (the webview rebuilds them).
    pub fn reset(&mut self) {
        for s in &mut self.tight_streams {
            s.reset();
        }
        self.zrle_stream.reset();
        self.zlib_stream.reset();
        self.colour_map = None;
        self.h264.clear();
    }

    /// Live H.264 decoder contexts (diagnostics/tests).
    pub fn h264_context_count(&self) -> usize {
        self.h264.live()
    }

    /// Install colour map entries from a SetColourMapEntries message
    /// (`[r, g, b]` per entry). Channel values are 16-bit on the wire; we
    /// keep the high byte.
    pub fn set_colour_map(&mut self, first_colour: u16, entries: &[[u16; 3]]) {
        let map = self.colour_map.get_or_insert_with(ColourMap::new);
        let rgb: Vec<[u8; 3]> = entries
            .iter()
            .map(|e| [(e[0] >> 8) as u8, (e[1] >> 8) as u8, (e[2] >> 8) as u8])
            .collect();
        map.set_entries(first_colour as usize, &rgb);
    }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Decode one rectangle from `reader`, which is positioned at the rect
/// payload (x/y/w/h/encoding already consumed by the caller).
///
/// Returns `Ok(None)` for pseudo-encodings the caller should handle instead
/// (the reader is left positioned at the pseudo-rect payload).
pub async fn decode_rect<R: AsyncRead + Unpin + Send>(
    state: &mut DecoderState,
    reader: &mut R,
    rect: Rect,
    encoding: i32,
) -> Result<Option<DecodedRect>> {
    // Pseudo-encodings are negative, except VMware's (0x574d5664) which is a
    // positive registered number, proto/ owns all of them.
    if encoding < 0 || encoding == encoding::PSEUDO_VMWARE_CURSOR {
        return Ok(None);
    }

    if rect.area() > MAX_RECT_AREA {
        return Err(derr(
            "dispatch",
            format!("rect {}x{} exceeds max area", rect.width, rect.height),
        ));
    }

    // Pixel-carrying encodings need a sane pixel format.
    let pf_ok = matches!(state.pf.bits_per_pixel, 8 | 16 | 24 | 32);

    let payload = match encoding {
        encoding::RAW => {
            check_pf(pf_ok, "raw")?;
            raw::decode(reader, rect, &state.pf, state.colour_map.as_ref()).await?
        }
        encoding::COPY_RECT => copy_rect::decode(reader).await?,
        encoding::RRE => {
            check_pf(pf_ok, "rre")?;
            rre::decode(reader, rect, &state.pf, state.colour_map.as_ref(), false).await?
        }
        encoding::CORRE => {
            check_pf(pf_ok, "corre")?;
            rre::decode(reader, rect, &state.pf, state.colour_map.as_ref(), true).await?
        }
        encoding::HEXTILE => {
            check_pf(pf_ok, "hextile")?;
            hextile::decode(reader, rect, &state.pf, state.colour_map.as_ref()).await?
        }
        encoding::ZLIB => {
            check_pf(pf_ok, "zlib")?;
            zlib::decode(
                reader,
                rect,
                &state.pf,
                state.colour_map.as_ref(),
                &mut state.zlib_stream,
            )
            .await?
        }
        encoding::TIGHT => {
            check_pf(pf_ok, "tight")?;
            tight::decode(
                reader,
                rect,
                &state.pf,
                state.colour_map.as_ref(),
                &mut state.tight_streams,
            )
            .await?
        }
        encoding::TRLE => {
            check_pf(pf_ok, "trle")?;
            zrle::decode(reader, rect, &state.pf, state.colour_map.as_ref(), None).await?
        }
        encoding::ZRLE => {
            check_pf(pf_ok, "zrle")?;
            zrle::decode(
                reader,
                rect,
                &state.pf,
                state.colour_map.as_ref(),
                Some(&mut state.zrle_stream),
            )
            .await?
        }
        encoding::OPEN_H264 => h264::decode(reader, rect, &mut state.h264).await?,
        other => return Err(VncError::UnsupportedEncoding(other)),
    };

    Ok(Some(DecodedRect { rect, payload }))
}

fn check_pf(ok: bool, enc: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(derr(
            enc,
            "unsupported bits-per-pixel in negotiated pixel format",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RectPayload;

    fn pf() -> PixelFormat {
        PixelFormat::bgra8888()
    }

    #[tokio::test]
    async fn pseudo_encodings_return_none() {
        let mut state = DecoderState::new(pf());
        let mut data: &[u8] = &[];
        let rect = Rect::new(0, 0, 0, 0);
        for enc in [
            encoding::PSEUDO_CURSOR,
            encoding::PSEUDO_DESKTOP_SIZE,
            encoding::PSEUDO_LAST_RECT,
            encoding::PSEUDO_VMWARE_CURSOR,
            encoding::PSEUDO_EXTENDED_CLIPBOARD,
            encoding::TIGHT_PNG,
        ] {
            let out = decode_rect(&mut state, &mut data, rect, enc).await.unwrap();
            assert!(out.is_none(), "encoding {enc} should be Ok(None)");
        }
    }

    #[tokio::test]
    async fn unknown_positive_encoding_is_unsupported() {
        let mut state = DecoderState::new(pf());
        let mut data: &[u8] = &[];
        let err = decode_rect(&mut state, &mut data, Rect::new(0, 0, 1, 1), 12345)
            .await
            .unwrap_err();
        assert!(matches!(err, VncError::UnsupportedEncoding(12345)));
    }

    #[tokio::test]
    async fn oversized_rect_is_rejected() {
        let mut state = DecoderState::new(pf());
        let mut data: &[u8] = &[];
        let err = decode_rect(
            &mut state,
            &mut data,
            Rect::new(0, 0, 65535, 65535),
            encoding::RAW,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VncError::Decode { .. }));
    }

    #[tokio::test]
    async fn h264_rect_carries_context_metadata() {
        let mut state = DecoderState::new(pf());
        // SPS + IDR slice, so this frame may start a decoder.
        let frame: Vec<u8> = vec![0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x65, 0x88];
        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        wire.extend_from_slice(&3u32.to_be_bytes()); // flags: reset both
        wire.extend_from_slice(&frame);
        let mut r: &[u8] = &wire;
        let out = decode_rect(
            &mut state,
            &mut r,
            Rect::new(0, 0, 8, 8),
            encoding::OPEN_H264,
        )
        .await
        .unwrap()
        .unwrap();
        match out.payload {
            RectPayload::H264 {
                data,
                flags,
                context_id,
                reset,
                keyframe,
            } => {
                assert_eq!(data, frame);
                assert_eq!(flags, 3);
                assert_eq!(context_id, 0);
                assert!(reset);
                assert!(keyframe);
            }
            other => panic!("expected H264 payload, got {other:?}"),
        }
        assert_eq!(state.h264_context_count(), 1);
        state.reset();
        assert_eq!(state.h264_context_count(), 0);
    }
}
