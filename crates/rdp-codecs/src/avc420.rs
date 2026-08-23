//! AVC420: the `RFX_AVC420_METABLOCK`, the Annex B boundary, and nothing else
//! (MS-RDPEGFX 2.2.4.4, 2.2.4.4.1, 2.2.4.5; decode rules 3.3.8.3).
//!
//! # Nothing here decodes H.264, and that is the design
//!
//! `RDPGFX_CODECID_AVC420` (0x000B) carries `RFX_AVC420_BITMAP_STREAM`, which
//! is a metablock followed by one H.264 Annex B access unit. The access unit
//! is not decoded in Rust. It is handed to the webview, which already decodes
//! H.264 through WebCodecs on a hardware backed `VideoDecoder`, over the rect
//! format that `src-tauri/FRAME_FORMAT.md` has carried since the VNC side
//! shipped Open H.264:
//!
//! ```text
//! format 3   [u32 flags][u32 context_id][u32 ctx_flags][Annex B data]
//! ```
//!
//! So the whole Rust side of AVC420 is: read four fields, produce two borrowed
//! slices, and scan the access unit once for an IDR so the renderer knows
//! whether it may start a decoder on it. The budget in PRDRDP/04 §11.1 is
//! under 50 microseconds per frame for all of that, and PRDRDP/04 §4.14 counts
//! AVC as the only codec in the set with a single copy, which is true only
//! because [`Avc420Stream::bitstream`] borrows the receive buffer instead of
//! owning a `Vec`.
//!
//! Writing an H.264 decoder here instead would be wrong three times over: it
//! is forbidden by `AGENT_BRIEF` D3 and D4, it would move a GPU workload onto
//! the CPU, and it would be the largest single piece of code in the tree.
//!
//! # How the pieces reach format 3
//!
//! `rdp-core` builds one `RectPayload::H264` per `WIRE_TO_SURFACE_1`
//! (PRDRDP/04 §5.2), and every field of it comes from here or from the
//! enclosing PDU:
//!
//! | Format 3 field | Source |
//! |---|---|
//! | Annex B data | [`Avc420Stream::bitstream`], verbatim, never copied here |
//! | `flags` | Always zero. RDP has no `ResetContext` bits (PRDRDP/04 §5.2) |
//! | `context_id` | One slot per `surfaceId`, `rdp-core`'s table (§5.2.1) |
//! | `ctx_flags` bit 1 | [`contains_idr`] over that same slice |
//! | `ctx_flags` bit 0 | `rdp-core`'s slot state, sticky until an IDR arrives |
//! | rect `x,y,w,h` | The `destRect` of the PDU, translated to screen space |
//! | frame `damage` | [`Avc420Stream::bounds`], translated the same way |
//!
//! Region rectangles are damage, not rectangles to emit. H.264 inter
//! prediction makes the whole decoded picture valid; the regions say which
//! parts moved. Emitting one format 3 rect per region would feed the same
//! access unit to the decoder once per region (PRDRDP/04 §5.2.3).
//!
//! # Where `rdp-pdu` stops and this module starts
//!
//! PRDRDP/12 §2.2.2 draws the codec payload boundary with one test: a
//! structure whose length comes from an outer PDU field belongs to `rdp-pdu`,
//! and a structure that is self describing inside the payload belongs here.
//! `numRegionRects` is inside `bitmapData`, not an outer field, so by that
//! test the metablock is on this side of the line and `rdp-pdu` should hand on
//! `bitmapData` whole.
//!
//! `rdp-pdu` also parses it today, in `vc::egfx::Avc420Metablock`, and says in
//! its own module comment that it is "the one exception the specification
//! forces". Two crates parsing the same four fields is one too many, and this
//! is the copy that belongs to the boundary. The difference is not only which
//! side of a line it sits on: that one allocates two `Vec`s per frame, and
//! this one allocates nothing at all, which is what a 60 frames per second
//! path needs and what PRDRDP/04 §4.1 rule two requires. Reported to the
//! owner; `rdp-codecs` cannot depend on `rdp-pdu` and so cannot remove it.
//!
//! # Section numbering, unresolved
//!
//! The design set numbers these structures two different ways. PRDRDP/04 §4.10
//! and §5.2 call `RFX_AVC420_BITMAP_STREAM` §2.2.4.4 and the metablock inside
//! it §2.2.4.4.1, which leaves `RDPGFX_H264_QUANT_QUALITY` unnumbered.
//! `rdp-pdu` and the stub this module replaced call the metablock §2.2.4.4,
//! the quant quality §2.2.4.4.1 and the bitmap stream §2.2.4.5. The two cannot
//! both be right. The citations here follow `rdp-pdu`, so the RDP tree at
//! least disagrees with the PRD in one direction rather than with itself, and
//! only MS-RDPEGFX settles it. The field layouts below are identical under
//! both readings, so nothing in the code depends on the answer.

use crate::{DecodeError, Reader};

/// `RDPGFX_RECT16` is eight bytes (MS-RDPEGFX 2.2.1.2).
pub const RECT16_LEN: usize = 8;

/// `RDPGFX_H264_QUANT_QUALITY` is two bytes (MS-RDPEGFX 2.2.4.4.1).
pub const QUANT_QUALITY_LEN: usize = 2;

/// One region costs a rectangle plus a quant quality pair.
const REGION_LEN: usize = RECT16_LEN + QUANT_QUALITY_LEN;

/// The cap on `numRegionRects`.
///
/// The field is a `u32` off the network and the specification states no
/// bound, so the number is ours. Nothing here reserves on it, because
/// [`parse`] slices the two arrays out of the payload rather than building
/// them, so the real bound is the arithmetic: `numRegionRects` region
/// rectangles need ten bytes each and a short payload is refused before a
/// single rectangle is read. This cap exists so a count of four billion is
/// rejected by name rather than by subtraction.
///
/// It is 4096 to agree with `rdp_pdu::io::limits::MAX_AVC420_REGION_RECTS`,
/// because two layers that disagree about what is legal produce a PDU that
/// one accepts and the other refuses. PRDRDP/04 §4.10 says 1024 under the
/// name `MAX_AVC_REGIONS`; that is a third value and is reported. One region
/// rectangle per macroblock row of a 4K frame is 135, so all three are
/// generous.
pub const MAX_REGION_RECTS: usize = 4096;

/// NAL unit type 5, a coded slice of an IDR picture. The only access unit a
/// decoder is allowed to start on (ITU-T H.264 table 7-1).
const NAL_IDR_SLICE: u8 = 5;

/// `RDPGFX_RECT16` (MS-RDPEGFX 2.2.1.2).
///
/// Right and bottom are **exclusive**, which is the surface command
/// convention and not the legacy bitmap update one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect16 {
    /// `left`.
    pub left: u16,
    /// `top`.
    pub top: u16,
    /// `right`, exclusive.
    pub right: u16,
    /// `bottom`, exclusive.
    pub bottom: u16,
}

impl Rect16 {
    /// Width, saturating at zero for an inverted rectangle. A server may send
    /// one and it is damage rather than a drawing target, so it is clamped
    /// rather than refused.
    #[must_use]
    pub const fn width(&self) -> u16 {
        self.right.saturating_sub(self.left)
    }

    /// Height, saturating at zero for an inverted rectangle.
    #[must_use]
    pub const fn height(&self) -> u16 {
        self.bottom.saturating_sub(self.top)
    }

    /// True when the rectangle covers no pixels.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.right <= self.left || self.bottom <= self.top
    }

    /// The four little endian `u16` of one wire rectangle.
    #[inline]
    fn from_wire(b: &[u8]) -> Self {
        // `b` is one chunk of a `chunks_exact(RECT16_LEN)`, so its length is
        // eight and the compiler knows it: the eight indexes below compile to
        // two loads with no bounds check (PRDRDP/04 §4.6.8 rule one).
        Self {
            left: u16::from_le_bytes([b[0], b[1]]),
            top: u16::from_le_bytes([b[2], b[3]]),
            right: u16::from_le_bytes([b[4], b[5]]),
            bottom: u16::from_le_bytes([b[6], b[7]]),
        }
    }
}

/// `RDPGFX_H264_QUANT_QUALITY` (MS-RDPEGFX 2.2.4.4.1).
///
/// Two bytes: a packed `qpVal` and a `qualityVal` of 0 to 100. Nothing in the
/// decode path reads these; PRDRDP/04 §9.5 records them as the measure of how
/// hard the server is compressing, which is what drives the quality tuner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuantQuality {
    /// `qpVal`, the whole byte: `qp` in bits 0 to 5, `r` in bit 6, `p` in
    /// bit 7.
    pub qp_val: u8,
    /// `qualityVal`, 0 to 100.
    pub quality_val: u8,
}

impl QuantQuality {
    /// The quantization parameter, bits 0 to 5 of `qpVal`. Lower is better
    /// quality.
    #[must_use]
    pub const fn qp(&self) -> u8 {
        self.qp_val & 0x3F
    }

    /// `r`, bit 6 of `qpVal`. Reserved.
    #[must_use]
    pub const fn r(&self) -> bool {
        self.qp_val & 0x40 != 0
    }

    /// `p`, bit 7 of `qpVal`, the progressive indicator.
    #[must_use]
    pub const fn p(&self) -> bool {
        self.qp_val & 0x80 != 0
    }
}

/// One region rectangle and the quality it was coded at.
///
/// The metablock stores the two as parallel arrays; this is the pairing, and
/// it is what [`Avc420Stream::regions`] yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Region {
    /// The rectangle, in surface coordinates.
    pub rect: Rect16,
    /// Its `RDPGFX_H264_QUANT_QUALITY`.
    pub quality: QuantQuality,
}

/// A parsed `RFX_AVC420_BITMAP_STREAM` (MS-RDPEGFX 2.2.4.5).
///
/// Every field is a borrow into the caller's buffer. Nothing is allocated,
/// nothing is copied, and the type is `Copy`, so handing it around costs
/// nothing either. The two arrays stay in wire form and are decoded by
/// [`Avc420Stream::regions`] on demand, because a caller that only wants the
/// damage rectangle should not pay for a `Vec` of a thousand rectangles it
/// will not look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Avc420Stream<'a> {
    /// `regionRects`, still packed: `numRegionRects * 8` bytes.
    rects: &'a [u8],
    /// `quantQualityVals`, still packed: `numRegionRects * 2` bytes.
    quants: &'a [u8],
    /// The H.264 Annex B access unit, borrowed from the caller's buffer and
    /// never touched.
    ///
    /// This is the slice that goes into the format 3 payload verbatim. It may
    /// be empty: a metablock with no bitstream is a control message, the same
    /// case `FRAME_FORMAT.md` already documents for the VNC path.
    pub bitstream: &'a [u8],
}

impl<'a> Avc420Stream<'a> {
    /// `numRegionRects`.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rects.len() / RECT16_LEN
    }

    /// True when the metablock names no regions at all, which is legal and
    /// means the whole `destRect` changed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rects.is_empty()
    }

    /// The region rectangles paired with their quality values, in wire order.
    ///
    /// Decoding happens here rather than in [`parse`], so a caller pays for
    /// exactly the regions it reads.
    pub fn regions(&self) -> impl ExactSizeIterator<Item = Region> + 'a {
        self.rects
            .chunks_exact(RECT16_LEN)
            .zip(self.quants.chunks_exact(QUANT_QUALITY_LEN))
            .map(|(r, q)| Region {
                rect: Rect16::from_wire(r),
                quality: QuantQuality {
                    qp_val: q[0],
                    quality_val: q[1],
                },
            })
    }

    /// The union bounding box of the region rectangles, or `None` when there
    /// are none.
    ///
    /// This is the frame `damage` of PRDRDP/04 §5.2.3, before translation
    /// into screen space. Empty and inverted rectangles are skipped, so a
    /// server that pads its array with zeroed entries does not drag the box
    /// to the origin.
    ///
    /// Not a hot loop and not written as one: it runs once per frame over at
    /// most [`MAX_REGION_RECTS`] rectangles, which is 32 KiB in the worst
    /// case and a few hundred bytes in practice. The scan that had to be fast
    /// is [`contains_idr`], which walks the whole access unit.
    #[must_use]
    pub fn bounds(&self) -> Option<Rect16> {
        let mut acc: Option<Rect16> = None;
        for c in self.rects.chunks_exact(RECT16_LEN) {
            let r = Rect16::from_wire(c);
            if r.is_empty() {
                continue;
            }
            acc = Some(match acc {
                None => r,
                Some(a) => Rect16 {
                    left: a.left.min(r.left),
                    top: a.top.min(r.top),
                    right: a.right.max(r.right),
                    bottom: a.bottom.max(r.bottom),
                },
            });
        }
        acc
    }
}

/// Parse one `RFX_AVC420_BITMAP_STREAM` (MS-RDPEGFX 2.2.4.5, 2.2.4.4).
///
/// `src` is the `bitmapData` of a `WIRE_TO_SURFACE_1` whose `codecId` is
/// `RDPGFX_CODECID_AVC420`, after ZGFX decompression. The layout is:
///
/// ```text
/// numRegionRects          u32
/// regionRects             numRegionRects * RDPGFX_RECT16
/// quantQualityVals        numRegionRects * RDPGFX_H264_QUANT_QUALITY
/// avc420EncodedBitstream  the rest, an H.264 Annex B access unit
/// ```
///
/// Everything after the two arrays is the bitstream, however long it is,
/// including nothing at all. There is no length field for it: the enclosing
/// `bitmapDataLength` is what bounds it, and that is `rdp-pdu`'s field.
///
/// # Errors
///
/// [`DecodeError::Range`] when `numRegionRects` is past
/// [`MAX_REGION_RECTS`], and [`DecodeError::Truncated`] when the payload is
/// too short for the count it declares.
pub fn parse(src: &[u8]) -> Result<Avc420Stream<'_>, DecodeError> {
    let mut r = Reader::new(src, "avc420 metablock");
    let count = r.u32_le()? as usize;
    if count > MAX_REGION_RECTS {
        return Err(DecodeError::Range {
            what: "numRegionRects",
            got: count as u32,
        });
    }
    // `count` is at most 4096 here, so neither multiplication can overflow on
    // a 32 bit target either.
    let rects = r.take(count * RECT16_LEN)?;
    let quants = r.take(count * QUANT_QUALITY_LEN)?;
    let rest = r.remaining();
    Ok(Avc420Stream {
        rects,
        quants,
        bitstream: r.take(rest)?,
    })
}

/// Bytes of payload a metablock naming `count` regions occupies, before the
/// bitstream.
///
/// This is the offset [`Avc420Stream::bitstream`] begins at, which is the
/// invariant the fuzz target checks and the one that proves the Annex B bytes
/// are still the caller's. Exposed so there is one definition of it rather
/// than one per caller.
#[must_use]
pub const fn metablock_len(count: usize) -> usize {
    4 + count * REGION_LEN
}

// ---------------------------------------------------------------------------
// Annex B inspection
// ---------------------------------------------------------------------------

/// True when the access unit contains an IDR slice, which is the only kind of
/// frame a `VideoDecoder` may be started on.
///
/// This is `ctx_flags` bit 1 of rect format 3, and it is the same tolerant
/// scan as `vnc_core::encodings::h264::contains_idr`: it accepts three and
/// four byte start codes, ignores any NAL whose forbidden zero bit is set, and
/// parses nothing else. The bytes come from an untrusted server and a wrong
/// answer costs a dropped frame, not a wrong pixel, so tolerance is the right
/// trade.
///
/// The duplication with `vnc-core` is deliberate and is what PRDRDP/04 §4.10
/// specifies, because this crate may not depend on `vnc-core`. Twenty five
/// lines in two places is the cost; the alternative is a shared crate, and
/// `remote-core` is the obvious home if the owner wants one.
#[must_use]
pub fn contains_idr(annex_b: &[u8]) -> bool {
    nal_types(annex_b).any(|t| t == NAL_IDR_SLICE)
}

/// The NAL unit types of an Annex B byte stream, in order.
fn nal_types(data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let mut i = 0usize;
    core::iter::from_fn(move || {
        while let Some(p) = find_start_code(data, i) {
            i = p + 3;
            match data.get(i) {
                None => return None,
                Some(&header) => {
                    i += 1;
                    // forbidden_zero_bit must be zero in a real NAL header.
                    if header & 0x80 == 0 {
                        return Some(header & 0x1F);
                    }
                }
            }
        }
        None
    })
}

/// Does this eight byte word hold a zero byte?
///
/// The standard word trick: subtracting one from every byte borrows into the
/// high bit exactly when that byte was zero, and `!w` keeps the answer from
/// firing on 0x80. Endianness does not matter, because the question is about
/// the set of bytes and not about their order.
#[inline]
const fn has_zero_byte(w: u64) -> bool {
    w.wrapping_sub(0x0101_0101_0101_0101) & !w & 0x8080_8080_8080_8080 != 0
}

/// Index of the next `00 00 01` prefix at or after `from`.
///
/// Eight bytes at a time. Every Annex B start code prefix begins with a zero
/// byte, so a word with no zero byte in it cannot contain the start of one and
/// the whole word is skipped. An H.264 slice is entropy coded and emulation
/// prevention keeps `00 00` out of the payload, so the fast path takes almost
/// every word and the scan runs at close to memory speed instead of at one
/// byte and three comparisons per iteration.
///
/// The eight bytes are copied into an array through `get`, so there is no
/// index that can panic and no unaligned read to justify (PRDRDP/04 §4.6.8
/// rule one: prove the length once, then let the compiler drop the check).
fn find_start_code(data: &[u8], from: usize) -> Option<usize> {
    let n = data.len();
    if n < 3 {
        return None;
    }
    // The last index a three byte prefix can begin at.
    let last = n - 3;
    let mut i = from;
    while i <= last {
        if let Some(chunk) = data.get(i..i + 8) {
            let mut w = [0u8; 8];
            w.copy_from_slice(chunk);
            if !has_zero_byte(u64::from_ne_bytes(w)) {
                // None of these eight bytes is zero, so no prefix begins at
                // any of them.
                i += 8;
                continue;
            }
        }
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a metablock. Hand written rather than generated, because the
    /// point of the vectors below is the byte layout.
    fn metablock(regions: &[(Rect16, QuantQuality)], bitstream: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(regions.len() as u32).to_le_bytes());
        for (r, _) in regions {
            v.extend_from_slice(&r.left.to_le_bytes());
            v.extend_from_slice(&r.top.to_le_bytes());
            v.extend_from_slice(&r.right.to_le_bytes());
            v.extend_from_slice(&r.bottom.to_le_bytes());
        }
        for (_, q) in regions {
            v.push(q.qp_val);
            v.push(q.quality_val);
        }
        v.extend_from_slice(bitstream);
        v
    }

    fn nal(start4: bool, header: u8, body: &[u8]) -> Vec<u8> {
        let mut v = if start4 {
            vec![0, 0, 0, 1]
        } else {
            vec![0, 0, 1]
        };
        v.push(header);
        v.extend_from_slice(body);
        v
    }

    fn idr_access_unit() -> Vec<u8> {
        let mut v = nal(true, 0x67, &[0x42, 0x00, 0x1E]); // SPS
        v.extend(nal(false, 0x68, &[0xCE, 0x3C, 0x80])); // PPS
        v.extend(nal(true, 0x65, &[0x88, 0x84, 0x00])); // IDR slice
        v
    }

    fn delta_access_unit() -> Vec<u8> {
        nal(false, 0x41, &[0x9A, 0x00])
    }

    /// A hand assembled metablock, byte by byte, with the arithmetic written
    /// out.
    ///
    /// **This is not a transcription of a published example.** MS-RDPEGFX has
    /// no section 4 vector for `RFX_AVC420_BITMAP_STREAM` that this lane could
    /// obtain, and `docs/RDP_SPEC_NOTES.md` §1.6 records that every hand
    /// computed vector in this tree says so. The bytes below are assembled
    /// from the field table of MS-RDPEGFX 2.2.4.4 and 2.2.4.4.1 directly:
    ///
    /// ```text
    /// 02 00 00 00                numRegionRects = 2, little endian u32
    /// 00 00 00 00 40 00 20 00    rect 0: left 0, top 0, right 0x40, bottom 0x20
    /// 40 00 00 00 80 00 20 00    rect 1: left 0x40, top 0, right 0x80, bottom 0x20
    /// 96 64                      quant 0: qpVal 0x96, qualityVal 100
    /// 1E 5A                      quant 1: qpVal 0x1E, qualityVal 90
    /// ```
    ///
    /// `qpVal` 0x96 is `1001_0110`: `qp` is the low six bits, `0b010110` = 22;
    /// `r` is bit 6, clear; `p` is bit 7, set. `qpVal` 0x1E is `0001_1110`:
    /// `qp` = 30, `r` clear, `p` clear.
    #[test]
    fn a_hand_assembled_metablock_parses_field_by_field() {
        let bytes = [
            0x02, 0x00, 0x00, 0x00, // numRegionRects
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x20, 0x00, // rect 0
            0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x20, 0x00, // rect 1
            0x96, 0x64, // quant 0
            0x1E, 0x5A, // quant 1
            0x00, 0x00, 0x00, 0x01, 0x65, 0x88, // Annex B, an IDR slice
        ];
        let s = parse(&bytes).unwrap();
        assert_eq!(s.len(), 2);
        assert!(!s.is_empty());

        let r: Vec<Region> = s.regions().collect();
        assert_eq!(
            r[0].rect,
            Rect16 {
                left: 0,
                top: 0,
                right: 0x40,
                bottom: 0x20
            }
        );
        assert_eq!(
            r[1].rect,
            Rect16 {
                left: 0x40,
                top: 0,
                right: 0x80,
                bottom: 0x20
            }
        );
        assert_eq!(r[0].quality.qp(), 22);
        assert!(r[0].quality.p());
        assert!(!r[0].quality.r());
        assert_eq!(r[0].quality.quality_val, 100);
        assert_eq!(r[1].quality.qp(), 30);
        assert!(!r[1].quality.p());
        assert_eq!(r[1].quality.quality_val, 90);

        // The metablock is 4 + 2 * 10 = 24 bytes, so the bitstream starts at
        // byte 24 and is the six bytes that remain.
        assert_eq!(metablock_len(2), 24);
        assert_eq!(s.bitstream, &bytes[24..]);
        assert!(contains_idr(s.bitstream));
    }

    /// The property the whole design rests on: the bitstream is the caller's
    /// bytes, not a copy of them.
    #[test]
    fn the_bitstream_is_a_borrow_of_the_caller_s_buffer() {
        let annex_b = idr_access_unit();
        let src = metablock(&[(Rect16::default(), QuantQuality::default())], &annex_b);
        let s = parse(&src).unwrap();
        assert_eq!(s.bitstream, &annex_b[..]);
        // Same allocation, at the offset the metablock ends at.
        let base = src.as_ptr() as usize;
        assert_eq!(s.bitstream.as_ptr() as usize - base, metablock_len(1));
    }

    #[test]
    fn a_metablock_with_no_regions_and_no_bitstream_is_legal() {
        let s = parse(&[0, 0, 0, 0]).unwrap();
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        assert_eq!(s.bounds(), None);
        assert!(s.bitstream.is_empty());
        assert_eq!(s.regions().count(), 0);
        // An empty access unit is a control message, not a frame.
        assert!(!contains_idr(s.bitstream));
    }

    /// The damage rectangle of PRDRDP/04 §5.2.3.
    #[test]
    fn bounds_unions_the_regions_and_skips_the_empty_ones() {
        let q = QuantQuality::default();
        let src = metablock(
            &[
                (
                    Rect16 {
                        left: 100,
                        top: 50,
                        right: 200,
                        bottom: 80,
                    },
                    q,
                ),
                // Empty: right equals left. A padded array must not drag the
                // box back to the origin.
                (
                    Rect16 {
                        left: 0,
                        top: 0,
                        right: 0,
                        bottom: 0,
                    },
                    q,
                ),
                (
                    Rect16 {
                        left: 16,
                        top: 64,
                        right: 32,
                        bottom: 96,
                    },
                    q,
                ),
                // Inverted: bottom above top. Skipped for the same reason.
                (
                    Rect16 {
                        left: 900,
                        top: 900,
                        right: 910,
                        bottom: 800,
                    },
                    q,
                ),
            ],
            &[],
        );
        let s = parse(&src).unwrap();
        assert_eq!(
            s.bounds(),
            Some(Rect16 {
                left: 16,
                top: 50,
                right: 200,
                bottom: 96
            })
        );
    }

    #[test]
    fn rect_dimensions_saturate_rather_than_wrapping() {
        let r = Rect16 {
            left: 40,
            top: 40,
            right: 10,
            bottom: 10,
        };
        assert_eq!(r.width(), 0);
        assert_eq!(r.height(), 0);
        assert!(r.is_empty());
        let r = Rect16 {
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1080,
        };
        assert_eq!(r.width(), 1920);
        assert_eq!(r.height(), 1080);
        assert!(!r.is_empty());
    }

    #[test]
    fn a_region_count_past_the_cap_is_refused_by_name() {
        let bytes = (MAX_REGION_RECTS as u32 + 1).to_le_bytes();
        assert_eq!(
            parse(&bytes),
            Err(DecodeError::Range {
                what: "numRegionRects",
                got: MAX_REGION_RECTS as u32 + 1
            })
        );
        // And the extreme: a `u32` that would overflow a `usize * 8` on a 32
        // bit target if the cap were not checked first.
        assert!(parse(&u32::MAX.to_le_bytes()).is_err());
    }

    #[test]
    fn a_count_the_payload_cannot_cover_is_truncation() {
        // Two regions declared, one rectangle's worth of bytes present.
        let mut src = 2u32.to_le_bytes().to_vec();
        src.extend_from_slice(&[0u8; RECT16_LEN]);
        assert_eq!(
            parse(&src),
            Err(DecodeError::Truncated {
                what: "avc420 metablock"
            })
        );
        // Rectangles complete, quant array short by one byte.
        let mut src = 2u32.to_le_bytes().to_vec();
        src.extend_from_slice(&[0u8; 2 * RECT16_LEN + 3]);
        assert!(parse(&src).is_err());
    }

    /// The truncation sweep. Every prefix of a valid stream parses or errors,
    /// and never panics.
    #[test]
    fn every_prefix_is_handled() {
        let q = QuantQuality {
            qp_val: 0x96,
            quality_val: 100,
        };
        let regions: Vec<(Rect16, QuantQuality)> = (0..7)
            .map(|i| {
                (
                    Rect16 {
                        left: i * 16,
                        top: 0,
                        right: i * 16 + 16,
                        bottom: 16,
                    },
                    q,
                )
            })
            .collect();
        let src = metablock(&regions, &idr_access_unit());
        for n in 0..=src.len() {
            if let Ok(s) = parse(&src[..n]) {
                // Whatever it accepted must be self consistent.
                assert_eq!(s.regions().count(), s.len());
                let _ = s.bounds();
                let _ = contains_idr(s.bitstream);
            }
        }
        // And the whole thing still parses afterwards.
        let s = parse(&src).unwrap();
        assert_eq!(s.len(), 7);
    }

    /// The adversarial leading byte sweep. `numRegionRects` is the first
    /// field and the only one that can force work, so every value of its low
    /// byte is driven against a fixed tail.
    #[test]
    fn every_leading_byte_terminates() {
        let tail: Vec<u8> = (0..200u8).map(|i| i.wrapping_mul(31)).collect();
        for lead in 0u16..=255 {
            for hi in [0x00u8, 0x01, 0x10, 0xFF] {
                let mut src = vec![lead as u8, hi, hi, hi];
                src.extend_from_slice(&tail);
                if let Ok(s) = parse(&src) {
                    assert_eq!(s.regions().count(), s.len());
                    let _ = s.bounds();
                    let _ = contains_idr(s.bitstream);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Annex B
    // -----------------------------------------------------------------------

    #[test]
    fn idr_detection_matches_the_vnc_path() {
        assert!(contains_idr(&idr_access_unit()));
        assert!(!contains_idr(&delta_access_unit()));
        assert!(!contains_idr(&[]));
        assert!(!contains_idr(&[0, 0, 1]));
        assert!(!contains_idr(&[0, 0, 0, 1]));
        // A NAL header with the forbidden zero bit set is not a NAL header.
        assert!(!contains_idr(&nal(true, 0x85, &[0x00])));
        // Both start code lengths, and an IDR that is not the first NAL.
        assert!(contains_idr(&nal(true, 0x65, &[])));
        assert!(contains_idr(&nal(false, 0x65, &[])));
    }

    /// The eight byte skip must not step over a start code that straddles a
    /// word boundary, so the same access unit is scanned at every alignment.
    #[test]
    fn the_word_at_a_time_scan_finds_start_codes_at_every_offset() {
        let unit = idr_access_unit();
        for pad in 0..32usize {
            // Padding bytes are non zero so they cannot themselves make a
            // start code.
            let mut v: Vec<u8> = (0..pad).map(|i| (i as u8) | 0x40).collect();
            v.extend_from_slice(&unit);
            assert!(contains_idr(&v), "missed an IDR at offset {pad}");
            let mut v: Vec<u8> = (0..pad).map(|i| (i as u8) | 0x40).collect();
            v.extend_from_slice(&delta_access_unit());
            assert!(!contains_idr(&v), "invented an IDR at offset {pad}");
        }
    }

    /// A zero byte in the payload is common and must not confuse the scan,
    /// and a long run of zeros must not either.
    #[test]
    fn zero_bytes_in_the_payload_do_not_invent_start_codes() {
        assert!(!contains_idr(&[0u8; 64]));
        let mut v = vec![0u8; 40];
        v.extend_from_slice(&nal(true, 0x65, &[0, 0, 0, 0, 0]));
        v.extend_from_slice(&[0u8; 40]);
        assert!(contains_idr(&v));
        // 00 00 02 is not a prefix, and 00 00 03 is the emulation prevention
        // escape rather than a start code.
        assert!(!contains_idr(&[0, 0, 2, 0x65, 0, 0, 3, 0x65]));
    }

    /// A start code with nothing after it, and a truncated one at the very
    /// end of the buffer. Both must terminate rather than index past the end.
    #[test]
    fn a_truncated_start_code_at_the_end_terminates() {
        for n in 0..8usize {
            let mut v = vec![0x41u8; 4];
            v.extend_from_slice(&vec![0u8; n]);
            let _ = contains_idr(&v);
            let mut v = nal(true, 0x65, &[]);
            v.truncate(v.len().saturating_sub(n.min(v.len())));
            let _ = contains_idr(&v);
        }
    }

    /// The scan must terminate on arbitrary bytes, including the ones that
    /// look most like start codes.
    #[test]
    fn arbitrary_bytes_terminate() {
        for seed in 0u32..64 {
            let v: Vec<u8> = (0..1024u32)
                .map(|i| ((i.wrapping_mul(seed).wrapping_add(i / 3)) % 4) as u8)
                .collect();
            let _ = contains_idr(&v);
        }
    }

    /// The invariants `fuzz/fuzz_targets/fuzz_avc420.rs` asserts, driven by a
    /// deterministic generator so they are checked on every `cargo test` and
    /// not only when someone runs the fuzzer.
    ///
    /// The generator is biased towards small counts and towards bytes that
    /// look like start codes, because uniform noise almost never produces
    /// either and would exercise the truncation path and nothing else.
    #[test]
    fn the_fuzz_invariants_hold_over_a_generated_corpus() {
        let mut x = 0x9E37_79B9u32;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        let mut src = Vec::with_capacity(512);
        for _ in 0..20_000 {
            src.clear();
            let count = next() % 6;
            src.extend_from_slice(&count.to_le_bytes());
            let tail = 8 + next() % 200;
            for _ in 0..tail {
                src.push(match next() % 5 {
                    0 => 0,
                    1 => 1,
                    2 => 0x65,
                    _ => (next() >> 16) as u8,
                });
            }
            let Ok(s) = parse(&src) else { continue };

            assert_eq!(s.regions().count(), s.len());
            let base = src.as_ptr() as usize;
            assert_eq!(
                s.bitstream.as_ptr() as usize - base,
                metablock_len(s.len()),
                "the bitstream must start where the metablock ends"
            );
            assert_eq!(metablock_len(s.len()) + s.bitstream.len(), src.len());

            match s.bounds() {
                Some(b) => {
                    assert!(!b.is_empty());
                    for r in s.regions().filter(|r| !r.rect.is_empty()) {
                        assert!(r.rect.left >= b.left && r.rect.top >= b.top);
                        assert!(r.rect.right <= b.right && r.rect.bottom <= b.bottom);
                    }
                }
                None => assert!(s.regions().all(|r| r.rect.is_empty())),
            }
            let _ = contains_idr(s.bitstream);
        }
    }

    #[test]
    fn nal_types_reports_every_unit_in_order() {
        let mut v = nal(true, 0x67, &[1, 2, 3]);
        v.extend(nal(false, 0x68, &[4, 5]));
        v.extend(nal(true, 0x65, &[6]));
        v.extend(nal(false, 0x41, &[7]));
        let types: Vec<u8> = nal_types(&v).collect();
        assert_eq!(types, vec![7, 8, 5, 1]);
    }
}
