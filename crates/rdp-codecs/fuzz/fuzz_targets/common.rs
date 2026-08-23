//! The destination harness every `rdp-codecs` target shares
//! (AGENT_BRIEF D11, PRDRDP/09 §2.6).
//!
//! ## What the targets assert, and why it is not just "it did not crash"
//!
//! A fuzz target that feeds only valid input proves nothing, and a target that
//! feeds raw bytes and checks nothing proves only that the process stayed up.
//! Both properties PRDRDP/04 §4.1 rule five states are checked here on every
//! execution:
//!
//! 1. **No input panics.** libFuzzer catches that one for us, but only if the
//!    harness actually reaches the decoder, which is why the geometry is drawn
//!    from the input rather than fixed. A fixed 64 by 64 destination never
//!    exercises the odd width paths, the chroma subsample rounding, or the
//!    zero height early return.
//! 2. **No input writes outside the destination.** Safe Rust gives half of
//!    this for free: a decoder handed a `&mut [u8]` cannot reach past it. The
//!    half it does not give is the rectangle *inside* that slice. A
//!    destination with a stride wider than its row has padding bytes at the
//!    end of every scanline that belong to the caller's framebuffer, and
//!    nothing in the type system stops a decoder from walking into them.
//!    [`Canvas`] therefore always allocates a wider stride than it needs,
//!    fills the whole allocation with [`FILL`], and [`Canvas::check`] proves
//!    every padding byte and both guard bands still hold it.
//!
//! `check` is called after every decode, including the ones that returned
//! `Err`, because a decoder that writes half a rect and then reports failure
//! has still corrupted the caller's framebuffer.

// Each target uses the part of this harness its decoder needs, so any one of
// them leaves some of it unused.
#![allow(dead_code)]

use arbitrary::{Arbitrary, Result, Unstructured};
use rdp_codecs::{DstView, OutFormat, Palette, RowOrder};

/// Bytes of untouched fill on each side of the destination.
pub const GUARD: usize = 64;

/// The poison the whole allocation starts as. Any of it that survives inside
/// the rectangle is fine; any of it that is gone from outside the rectangle is
/// a bug.
pub const FILL: u8 = 0xA5;

/// The longest destination edge a single execution will allocate. At 256 the
/// worst case destination is 256 KiB, which keeps executions per second high
/// enough for the 60 second smoke run of PRDRDP/09 §7.2 to be worth anything,
/// and it is wide enough to exercise every loop shape in the crate.
pub const MAX_DIM: u16 = 256;

/// A destination with guard bands, drawn from the fuzzer's input.
pub struct Canvas {
    buf: Vec<u8>,
    stride: usize,
    width: u16,
    height: u16,
    format: OutFormat,
    order: RowOrder,
}

impl Canvas {
    /// Draw a geometry, a destination channel order and a row order.
    ///
    /// The stride is always at least the row and usually more, because the
    /// padding it creates is what makes [`Canvas::check`] able to fail.
    pub fn draw(u: &mut Unstructured<'_>) -> Result<Self> {
        let width = u16::from(u8::arbitrary(u)?) % MAX_DIM + 1;
        let height = u16::from(u8::arbitrary(u)?) % MAX_DIM + 1;
        // Zero to fifteen extra pixels of destination pitch, so the common
        // case (a rect that is its own buffer) and the framebuffer case (a
        // rect written into something wider) both occur.
        let pad = usize::from(u8::arbitrary(u)? & 0x0F);
        let format = if bool::arbitrary(u)? {
            OutFormat::Bgra
        } else {
            OutFormat::Rgba
        };
        let order = if bool::arbitrary(u)? {
            RowOrder::BottomUp
        } else {
            RowOrder::TopDown
        };

        let stride = (usize::from(width) + pad) * 4;
        let area = stride * usize::from(height);
        Ok(Self {
            buf: vec![FILL; GUARD + area + GUARD],
            stride,
            width,
            height,
            format,
            order,
        })
    }

    /// Width in pixels.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Height in pixels.
    pub fn height(&self) -> u16 {
        self.height
    }

    fn area(&self) -> usize {
        self.stride * usize::from(self.height)
    }

    /// The destination the decoder under test writes through.
    ///
    /// # Panics
    ///
    /// Only if this file computed a geometry that does not fit the buffer it
    /// just allocated for it, which is a bug in the harness and should stop
    /// the run rather than be reported as a finding.
    pub fn view(&mut self) -> DstView<'_> {
        let end = GUARD + self.area();
        DstView::new(
            &mut self.buf[GUARD..end],
            self.stride,
            self.width,
            self.height,
            self.format,
            self.order,
        )
        .expect("the harness sized this buffer itself")
    }

    /// Prove nothing outside the rectangle moved.
    pub fn check(&self) {
        assert!(
            self.buf[..GUARD].iter().all(|&b| b == FILL),
            "a decoder wrote before the destination"
        );
        let end = GUARD + self.area();
        assert!(
            self.buf[end..].iter().all(|&b| b == FILL),
            "a decoder wrote past the destination"
        );
        let row = usize::from(self.width) * 4;
        for y in 0..usize::from(self.height) {
            let o = GUARD + y * self.stride;
            assert!(
                self.buf[o + row..o + self.stride]
                    .iter()
                    .all(|&b| b == FILL),
                "a decoder wrote into row {y}'s stride padding, which belongs \
                 to the caller's framebuffer"
            );
        }
    }
}

/// A session palette with attacker chosen entries (PRDRDP/04 §2.7).
///
/// Loaded through the real `TS_UPDATE_PALETTE` entry point, including short
/// and over long bodies, because that is remote input too.
pub fn palette(u: &mut Unstructured<'_>) -> Result<Palette> {
    let n = usize::from(u8::arbitrary(u)?);
    let mut p = Palette::default();
    let bytes = u.bytes(n.min(u.len()))?;
    p.load_rgb_triplets(bytes);
    Ok(p)
}
