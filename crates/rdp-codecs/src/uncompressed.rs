//! Uncompressed bitmaps, and the row conversion every other legacy codec ends
//! with (PRDRDP/04 §2.3 and §4.3).
//!
//! Two flavours, and both are trivial, which is why they go first: they are
//! the correctness reference the other decoders are tested against.
//!
//! * **Legacy.** The `bitmapDataStream` of a `TS_BITMAP_DATA`
//!   (MS-RDPBCGR 2.2.9.1.1.3.1.2.2) with `BITMAP_COMPRESSION` clear is a
//!   Windows DIB body: rows are stored **bottom to top** and each row is
//!   padded to a four byte boundary. Both traps are in [`dib_stride`] and
//!   [`RowOrder::BottomUp`](remote_pixel::RowOrder::BottomUp), and neither
//!   costs a copy.
//! * **EGFX.** `RDPGFX_CODECID_UNCOMPRESSED` (0x0000) is raw 32 bpp XRGB or
//!   ARGB, top down, tightly packed with no row padding. Same function with
//!   `src_stride = width * 4` and
//!   [`RowOrder::TopDown`](remote_pixel::RowOrder::TopDown).
//!
//! ## No scratch buffer
//!
//! The naive implementation copies the bitmap into a top down tightly packed
//! scratch and then runs a converter over it. That is a second full copy of
//! every rect, which breaks the D9 zero copy invariant. Instead the converter
//! writes the destination rows in reverse, which is one index expression in
//! [`DstView::row`], and the padding bytes at the end of each source row are
//! never read because the row slice is cut to its real length first.
//! `benches/decode.rs` measures the pair so PRDRDP/04 §2.3's claim is a number
//! rather than an assertion.
//!
//! ## This is also `convert_image`
//!
//! PRDRDP/04 §4.2 gives the conversion primitive the signature
//! `convert_image(fmt, src, src_stride, order, w, h, pal, dst)`. That is
//! [`decode`] with the destination arguments folded into [`DstView`], and it
//! is what the interleaved RLE path calls on its wire format scratch (§4.4).
//! `remote-pixel` has landed (PRDRDP/00 R37), so the body is now a delegation
//! to [`remote_pixel::convert_image`] and the signature did not change.

use remote_pixel::{convert_image, DstView, Format as PixelFormat, Palette, DST_BPP};

use crate::DecodeError;

/// The stride of a legacy DIB scanline, in bytes.
///
/// PRDRDP/04 §2.3 writes it as `((w * bpp / 8) + 3) & !3`, which truncates at
/// 1 bpp for a width that is not a multiple of eight. The bit count is rounded
/// up to whole bytes first and then to the four byte boundary, which agrees
/// with §2.3 at every depth above one and is right at one as well.
pub fn dib_stride(width: u16, bits_per_pixel: u8) -> usize {
    let bytes = (usize::from(width) * usize::from(bits_per_pixel)).div_ceil(8);
    (bytes + 3) & !3
}

/// The smallest `src` a call with this geometry can accept.
///
/// The last row's trailing padding is not required to be present. Windows
/// always sends it, and accepting a stream without it costs nothing and
/// removes one reason to reject a rect from a server we have not met.
pub fn min_src_len(fmt: PixelFormat, src_stride: usize, width: u16, height: u16) -> usize {
    fmt.min_src_len(src_stride, width, height)
}

/// Convert an uncompressed image into the caller's destination.
///
/// `src_stride` is the byte distance between the starts of two consecutive
/// wire scanlines: [`dib_stride`] for a legacy bitmap, `width * 4` for EGFX.
/// The row order lives in `dst` because the flip is a property of the
/// destination mapping, not of the source data (PRDRDP/04 §4.2).
///
/// Errors with [`DecodeError::Truncated`] if `src` is shorter than
/// [`min_src_len`]. It cannot panic on any input.
pub fn decode(
    fmt: PixelFormat,
    src: &[u8],
    src_stride: usize,
    palette: &Palette,
    dst: &mut DstView<'_>,
) -> Result<(), DecodeError> {
    Ok(convert_image(fmt, src, src_stride, palette, dst)?)
}

/// The legacy shorthand: a DIB body at `bits_per_pixel`, bottom up, with the
/// four byte row padding computed for you.
pub fn decode_legacy(
    bits_per_pixel: u8,
    src: &[u8],
    palette: &Palette,
    dst: &mut DstView<'_>,
) -> Result<(), DecodeError> {
    let fmt = PixelFormat::from_legacy_bpp(bits_per_pixel)?;
    decode(
        fmt,
        src,
        dib_stride(dst.width(), bits_per_pixel),
        palette,
        dst,
    )
}

/// Bytes a tightly packed wire image of this geometry occupies. The
/// interleaved RLE scratch is sized with this.
pub fn packed_len(fmt: PixelFormat, width: u16, height: u16) -> usize {
    fmt.row_bytes(width) * usize::from(height)
}

/// The destination size a decoded rect of this geometry needs.
pub fn dst_len(width: u16, height: u16) -> usize {
    usize::from(width) * usize::from(height) * DST_BPP
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_pixel::{OutFormat, RowOrder};

    #[test]
    fn dib_stride_matches_the_worked_examples() {
        // 4 byte alignment at every depth PRDRDP/04 §2.3 lists.
        assert_eq!(dib_stride(1, 32), 4);
        assert_eq!(dib_stride(3, 24), 12); // 9 bytes rounds to 12
        assert_eq!(dib_stride(3, 16), 8); // 6 bytes rounds to 8
        assert_eq!(dib_stride(5, 8), 8); // 5 bytes rounds to 8
        assert_eq!(dib_stride(9, 1), 4); // 9 bits is 2 bytes, rounds to 4
        assert_eq!(dib_stride(0, 32), 0);
    }

    /// A 3x2 24 bpp DIB. Row bytes are 9 and the stride is 12, so each row
    /// carries three padding bytes that must never be read. The wire rows are
    /// bottom up, so wire row 0 is image row 1.
    ///
    /// Wire, with the padding set to a value that would be visible if read:
    ///   row 0 (image row 1): B G R per pixel = (10,11,12) (20,21,22) (30,31,32) FF FF FF
    ///   row 1 (image row 0): (40,41,42) (50,51,52) (60,61,62) FF FF FF
    #[test]
    fn bottom_up_24bpp_places_the_rows_the_right_way_up() {
        let mut src = Vec::new();
        src.extend_from_slice(&[10, 11, 12, 20, 21, 22, 30, 31, 32, 0xFF, 0xFF, 0xFF]);
        src.extend_from_slice(&[40, 41, 42, 50, 51, 52, 60, 61, 62, 0xFF, 0xFF, 0xFF]);

        let mut out = vec![0u8; dst_len(3, 2)];
        let mut v = DstView::packed(&mut out, 3, 2, OutFormat::Rgba, RowOrder::BottomUp).unwrap();
        decode_legacy(24, &src, &Palette::default(), &mut v).unwrap();

        // Image row 0 is the second wire row, and B G R becomes R G B A.
        assert_eq!(
            &out[0..12],
            &[42, 41, 40, 0xFF, 52, 51, 50, 0xFF, 62, 61, 60, 0xFF]
        );
        assert_eq!(
            &out[12..24],
            &[12, 11, 10, 0xFF, 22, 21, 20, 0xFF, 32, 31, 30, 0xFF]
        );
    }

    #[test]
    fn top_down_is_the_same_data_the_other_way_up() {
        let src = [
            10u8, 11, 12, 20, 21, 22, 30, 31, 32, 0, 0, 0, 40, 41, 42, 50, 51, 52, 60, 61, 62, 0,
            0, 0,
        ];
        let mut out = vec![0u8; dst_len(3, 2)];
        let mut v = DstView::packed(&mut out, 3, 2, OutFormat::Rgba, RowOrder::TopDown).unwrap();
        decode(PixelFormat::Bgr24, &src, 12, &Palette::default(), &mut v).unwrap();
        assert_eq!(&out[0..4], &[12, 11, 10, 0xFF]);
        assert_eq!(&out[12..16], &[42, 41, 40, 0xFF]);
    }

    #[test]
    fn every_depth_round_trips_a_known_pixel() {
        let pal = {
            let mut p = Palette::default();
            p.set(7, 0x11, 0x22, 0x33);
            p
        };
        // (format, one wire pixel, expected RGBA)
        let cases: [(PixelFormat, &[u8], [u8; 4]); 6] = [
            (
                PixelFormat::BgrX32,
                &[0x30, 0x20, 0x10, 0x00],
                [0x10, 0x20, 0x30, 0xFF],
            ),
            (
                PixelFormat::BgrA32,
                &[0x30, 0x20, 0x10, 0x80],
                [0x10, 0x20, 0x30, 0x80],
            ),
            (
                PixelFormat::Bgr24,
                &[0x30, 0x20, 0x10],
                [0x10, 0x20, 0x30, 0xFF],
            ),
            // 0x1126 is 5-6-5 as r = 0b00010, g = 0b001001, b = 0b00110,
            // each expanded to eight bits by replication.
            (PixelFormat::Rgb565, &[0x26, 0x11], [0x10, 0x24, 0x31, 0xFF]),
            // 0x0826 is 5-5-5 as r = 0b00010, g = 0b00001, b = 0b00110.
            (PixelFormat::Rgb555, &[0x26, 0x08], [0x10, 0x08, 0x31, 0xFF]),
            (PixelFormat::Palette8, &[7], [0x11, 0x22, 0x33, 0xFF]),
        ];
        for (fmt, wire, want) in cases {
            let mut out = vec![0u8; 4];
            let mut v =
                DstView::packed(&mut out, 1, 1, OutFormat::Rgba, RowOrder::TopDown).unwrap();
            decode(fmt, wire, wire.len(), &pal, &mut v).unwrap();
            assert_eq!(out, want, "{fmt:?}");
        }
    }

    #[test]
    fn truncation_returns_err_and_never_panics() {
        let valid = vec![0x77u8; dib_stride(7, 16) * 5];
        let mut out = vec![0u8; dst_len(7, 5)];
        for k in 0..valid.len() {
            let mut v =
                DstView::packed(&mut out, 7, 5, OutFormat::Rgba, RowOrder::BottomUp).unwrap();
            let r = decode_legacy(16, &valid[..k], &Palette::default(), &mut v);
            // Only the last row's padding may be missing, and this fixture
            // has two padding bytes on its last row.
            if k < valid.len() - 2 {
                assert!(r.is_err(), "prefix {k} should not decode");
            }
        }
        let mut v = DstView::packed(&mut out, 7, 5, OutFormat::Rgba, RowOrder::BottomUp).unwrap();
        assert!(decode_legacy(16, &valid, &Palette::default(), &mut v).is_ok());
    }

    #[test]
    fn unsupported_depth_is_a_range_error() {
        let mut out = vec![0u8; 4];
        let mut v = DstView::packed(&mut out, 1, 1, OutFormat::Rgba, RowOrder::TopDown).unwrap();
        assert!(matches!(
            decode_legacy(7, &[0; 64], &Palette::default(), &mut v),
            Err(DecodeError::Range { .. })
        ));
    }

    #[test]
    fn zero_height_is_a_no_op_rather_than_an_underflow() {
        let mut out: [u8; 0] = [];
        let mut v = DstView::packed(&mut out, 4, 0, OutFormat::Rgba, RowOrder::BottomUp).unwrap();
        assert!(decode_legacy(32, &[], &Palette::default(), &mut v).is_ok());
    }
}
