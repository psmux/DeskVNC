//! The destination a converter or a decoder writes through (PRDRDP/04 §4.2).
//!
//! Moved here from `crates/rdp-codecs/src/dst.rs`, which was the interim home
//! while this crate was still the verbatim RFB move (PRDRDP/00 R37). The
//! module comment there recorded the swap as pending and named the shape it
//! would take; this is that shape, unchanged.
//!
//! ## Why a converter takes a `DstView` rather than nine loose arguments
//!
//! PRDRDP/04 §4.2 puts three things on every destination write: a caller owned
//! buffer, a stride, and a row order. §2.3 adds the rule that makes the row
//! order load bearing: legacy `TS_BITMAP_DATA` is a DIB body and its rows are
//! stored bottom to top, while Surface Bits (§2.8) and every EGFX codec are
//! top down. Getting that backwards inverts the picture in a way that is
//! obvious on screen and invisible to a unit test with a symmetric pattern.
//!
//! Bundling them buys three things. The buffer length is proved once in
//! [`DstView::new`] instead of once per row, so the row loops index a subslice
//! that cannot be short (PRDRDP/04 §4.6.8 rule two). The flip lives in exactly
//! one expression, [`DstView::row`], which keeps §4.2's rule that no decoder
//! reverses its own rows: both interleaved RLE and planar predict from the
//! previously decoded scanline, and a decoder that wrote its rows in reverse
//! to save the flip would predict from the wrong neighbour and produce a
//! picture that looks almost right. And it keeps the argument list of a decode
//! call at four or five, which matters because every one of them is a `usize`
//! and a transposed pair compiles.
//!
//! ## The two parameters PRDRDP/04 §4.2 left out
//!
//! §4.2's published signature has a `src_stride` and a `RowOrder` and neither
//! a destination channel order nor a destination stride. Both are needed and
//! both are here.
//!
//! * [`OutFormat`], because an EGFX surface is stored BGRA (PRDRDP/04 §3.3)
//!   while a framebuffer rect is RGBA (§10.3). Without it the conversion
//!   would have to be followed by a red and blue swap pass over the whole
//!   rect, which is the second copy §4.2's single copy rule forbids.
//! * The destination stride argument of [`DstView::new`], because a rect
//!   decoded straight into a larger framebuffer has a destination pitch that
//!   is not `width * 4`. Without it that case needs a packed scratch and a
//!   row by row copy out, which is the same second copy again.

use core::fmt;

/// Bytes per destination pixel. The destination is always 32 bits per pixel:
/// `RectPayload::Rgba` for a framebuffer rect (PRDRDP/04 §10.3), BGRA for an
/// EGFX surface (§3.3).
pub const DST_BPP: usize = 4;

/// What can go wrong converting wire pixels into a caller owned destination
/// (PRDRDP/04 §4.2).
///
/// Three variants because `rdp-codecs` maps them one for one onto the
/// `DecodeError` variants it already published, so moving the conversion here
/// changed no error a caller can observe. This crate has no dependencies at
/// all (PRDRDP/00 R37), so the `Display` and `Error` impls are written out
/// rather than derived with `thiserror`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelError {
    /// The source ended in the middle of the image.
    Truncated {
        /// What was being read.
        what: &'static str,
    },
    /// A field parsed cleanly and then said something impossible: a colour
    /// depth that is not defined, a stride narrower than one scanline.
    Range {
        /// The field that was out of range.
        what: &'static str,
        /// The value it carried.
        got: u32,
    },
    /// The caller's destination cannot hold the image.
    Dst {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
}

impl fmt::Display for PixelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PixelError::Truncated { what } => write!(f, "input truncated in {what}"),
            PixelError::Range { what, got } => write!(f, "{what}: value {got} out of range"),
            PixelError::Dst { need, have } => {
                write!(f, "output buffer too small: need {need}, have {have}")
            }
        }
    }
}

impl std::error::Error for PixelError {}

/// Source row order relative to the destination, which is always top down
/// (PRDRDP/04 §4.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowOrder {
    /// Row zero of the bitstream is the top row. EGFX and Surface Bits
    /// (PRDRDP/04 §2.8).
    TopDown,
    /// Row zero of the bitstream is the bottom row. The legacy DIB body
    /// (PRDRDP/04 §2.3).
    BottomUp,
}

/// Destination channel order (PRDRDP/04 §4.2, and see the module comment for
/// why this parameter exists at all).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutFormat {
    /// `RectPayload::Rgba`, what the framing layer and the WebGL renderer take
    /// (PRDRDP/04 §10.3).
    Rgba,
    /// An EGFX surface, stored BGRA8888 (PRDRDP/04 §3.3).
    Bgra,
}

/// The caller owned destination, with its stride, its geometry and the row
/// order to apply on the way out (PRDRDP/04 §4.2).
///
/// The buffer is validated once at construction. Every row handed out by
/// [`DstView::row`] is exactly `width * 4` bytes and is proved to be inside
/// the buffer, so the per pixel loops that consume it carry no bounds check.
pub struct DstView<'a> {
    buf: &'a mut [u8],
    stride: usize,
    width: u16,
    height: u16,
    format: OutFormat,
    order: RowOrder,
}

impl<'a> DstView<'a> {
    /// Wrap a destination.
    ///
    /// `stride` is in bytes and lets a decoder write a rectangle into a larger
    /// framebuffer without a second copy, which is the D9 zero copy invariant
    /// applied to the output side (PRDRDP/04 §4.2): the decode into the
    /// destination is the only copy per bitmap rect.
    pub fn new(
        buf: &'a mut [u8],
        stride: usize,
        width: u16,
        height: u16,
        format: OutFormat,
        order: RowOrder,
    ) -> Result<Self, PixelError> {
        let row = usize::from(width) * DST_BPP;
        if stride < row {
            return Err(PixelError::Dst {
                need: row,
                have: stride,
            });
        }
        // The last row does not need its trailing padding to be present.
        let need = match usize::from(height).checked_sub(1) {
            None => 0,
            Some(n) => n * stride + row,
        };
        if buf.len() < need {
            return Err(PixelError::Dst {
                need,
                have: buf.len(),
            });
        }
        Ok(Self {
            buf,
            stride,
            width,
            height,
            format,
            order,
        })
    }

    /// A tightly packed destination, the common case for a decoded rect that
    /// becomes a `RectPayload::Rgba` of its own (PRDRDP/04 §10.3).
    pub fn packed(
        buf: &'a mut [u8],
        width: u16,
        height: u16,
        format: OutFormat,
        order: RowOrder,
    ) -> Result<Self, PixelError> {
        Self::new(
            buf,
            usize::from(width) * DST_BPP,
            width,
            height,
            format,
            order,
        )
    }

    /// Width in pixels.
    #[inline]
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Height in pixels.
    #[inline]
    pub fn height(&self) -> u16 {
        self.height
    }

    /// Destination channel order.
    #[inline]
    pub fn format(&self) -> OutFormat {
        self.format
    }

    /// Row `y` counted from the top of the *image*, exactly `width * 4` bytes.
    ///
    /// This is the only place [`RowOrder::BottomUp`] has any effect
    /// (PRDRDP/04 §4.2). The whole implementation of the flip is the one index
    /// expression below, and it costs nothing because it is per row.
    ///
    /// `#[inline]` because the caller is in another crate now: `rdp-codecs`
    /// planar interleave calls this once per scanline and the call must fold
    /// into the row loop the way it did when both lived in one crate.
    ///
    /// # Panics
    ///
    /// Never on remote input: `y` comes from a decoder's own row loop, which
    /// is bounded by [`DstView::height`], and the slice was proved to exist in
    /// [`DstView::new`]. A `y` at or past [`DstView::height`] panics, and the
    /// debug assertion is there to name it as a caller bug.
    #[inline]
    pub fn row(&mut self, y: usize) -> &mut [u8] {
        debug_assert!(y < usize::from(self.height), "row {y} past the destination");
        let phys = match self.order {
            RowOrder::TopDown => y,
            RowOrder::BottomUp => usize::from(self.height) - 1 - y,
        };
        let off = phys * self.stride;
        &mut self.buf[off..off + usize::from(self.width) * DST_BPP]
    }
}

/// Store one pixel into a four byte destination chunk (PRDRDP/04 §4.2).
///
/// `BGRA` is a const generic rather than a runtime flag so the branch is
/// resolved at monomorphisation and the row loops stay branch free
/// (PRDRDP/04 §4.6.8 rule one). The indices are constants, and the chunk came
/// from `chunks_exact_mut(4)`, so there is no bounds check here either.
#[inline(always)]
pub fn put<const BGRA: bool>(d: &mut [u8], r: u8, g: u8, b: u8, a: u8) {
    if BGRA {
        d[0] = b;
        d[1] = g;
        d[2] = r;
    } else {
        d[0] = r;
        d[1] = g;
        d[2] = b;
    }
    d[3] = a;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bottom_up_flip_is_the_only_difference_between_the_two_orders() {
        // An asymmetric pattern, because a symmetric one cannot tell the two
        // apart. PRDRDP/04 §2.3 makes exactly this point about fixtures.
        let mut top = vec![0u8; 2 * 3 * DST_BPP];
        let mut bottom = vec![0u8; 2 * 3 * DST_BPP];
        {
            let mut t =
                DstView::packed(&mut top, 2, 3, OutFormat::Rgba, RowOrder::TopDown).unwrap();
            let mut b =
                DstView::packed(&mut bottom, 2, 3, OutFormat::Rgba, RowOrder::BottomUp).unwrap();
            for y in 0..3usize {
                t.row(y).fill(y as u8);
                b.row(y).fill(y as u8);
            }
        }
        assert_eq!(top[0], 0);
        assert_eq!(top[2 * DST_BPP * 2], 2);
        assert_eq!(bottom[0], 2, "bottom up must place image row 0 last");
        assert_eq!(bottom[2 * DST_BPP * 2], 0);
    }

    #[test]
    fn stride_wider_than_the_row_leaves_the_padding_alone() {
        let mut buf = vec![0xAAu8; 3 * 16];
        {
            let mut v =
                DstView::new(&mut buf, 16, 2, 3, OutFormat::Rgba, RowOrder::TopDown).unwrap();
            for y in 0..3usize {
                v.row(y).fill(0x11);
            }
        }
        for y in 0..3 {
            assert_eq!(&buf[y * 16..y * 16 + 8], &[0x11; 8]);
            assert_eq!(&buf[y * 16 + 8..y * 16 + 16], &[0xAA; 8]);
        }
    }

    #[test]
    fn short_destination_is_an_error_not_a_panic() {
        let mut buf = vec![0u8; 4];
        assert!(matches!(
            DstView::packed(&mut buf, 4, 4, OutFormat::Rgba, RowOrder::TopDown),
            Err(PixelError::Dst { .. })
        ));
        assert!(matches!(
            DstView::new(&mut buf, 3, 4, 1, OutFormat::Rgba, RowOrder::TopDown),
            Err(PixelError::Dst { .. })
        ));
    }

    /// The `Display` text is the text `rdp-codecs` published through
    /// `thiserror`, because that crate maps these variants one for one onto
    /// its own and a caller that logged the message keeps reading the same
    /// message (PRDRDP/04 §4.1).
    #[test]
    fn the_error_messages_match_the_ones_rdp_codecs_published() {
        assert_eq!(
            PixelError::Truncated { what: "bitmap" }.to_string(),
            "input truncated in bitmap"
        );
        assert_eq!(
            PixelError::Range {
                what: "bitsPerPixel",
                got: 7
            }
            .to_string(),
            "bitsPerPixel: value 7 out of range"
        );
        assert_eq!(
            PixelError::Dst { need: 8, have: 4 }.to_string(),
            "output buffer too small: need 8, have 4"
        );
    }
}
