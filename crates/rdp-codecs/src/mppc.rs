//! MPPC bulk decompression for the legacy RDP path
//! (MS-RDPBCGR 3.1.8.4.1 for RDP 4.0, 3.1.8.4.2 for RDP 5.0; the framing and
//! the flags are 2.2.1.11.1.1 and 3.1.8.2.1).
//!
//! A literal and copy scheme over a history buffer, negotiated in the Client
//! Info PDU with `INFO_COMPRESSION` (0x00000080) and a type in the
//! `CompressionTypeMask` bits (0x00001E00). The same shape as [`crate::zgfx`]
//! and a completely different bitstream: different tokens, a linear history
//! instead of a ring, and a flags byte that steers the history rather than
//! decorating it.
//!
//! | Type | Value | Scheme | Here |
//! |---|---|---|---|
//! | `PACKET_COMPR_TYPE_8K` | 0 | MPPC, 8 KB history | [`Variant::Rdp4`] |
//! | `PACKET_COMPR_TYPE_64K` | 1 | MPPC, 64 KB history | [`Variant::Rdp5`] |
//! | `PACKET_COMPR_TYPE_RDP6` | 2 | RDP 6.0 | not implemented, below |
//! | `PACKET_COMPR_TYPE_RDP61` | 3 | RDP 6.1 | not implemented, below |
//! | `PACKET_COMPR_TYPE_RDP8` | 4 | RDP 8.0 | [`crate::zgfx`] |
//!
//! Phase 1 never sets `INFO_COMPRESSION`, so nothing reaches this decoder
//! until a phase 2 client asks for it (PRDRDP/00 R43, PRDRDP/04 §4.13). That
//! is what makes "we implement the two we can verify and refuse the two we
//! cannot" a safe position rather than a gap: a server must not compress with
//! a type the client did not request, and the client chooses what to request.
//!
//! # RDP 6.0 and RDP 6.1 are refused, deliberately
//!
//! They are not MPPC. RDP 6.0 (MS-RDPEGDI 3.1.8.1) is an LZ77 stage followed
//! by a static Huffman stage, and RDP 6.1 (MS-RDPEGDI 3.1.8.2) adds a match
//! history in front of it and then feeds RDP 6.0. The Huffman tables of
//! MS-RDPEGDI 3.1.8.1.2 are several thousand transcribed entries and that
//! document was not available to this lane.
//!
//! `docs/RDP_SPEC_NOTES.md` §1.1 already records what happens when a table is
//! reconstructed rather than transcribed: the ZGFX literal rows have no
//! internal structure to check them against, and a single wrong row corrupts
//! one byte in a few thousand, which surfaces days later as an occasional
//! malformed PDU. A Huffman table with thousands of rows and no chain to prove
//! it would be that failure with three more zeroes on it. So
//! [`Variant::from_compression_type`] refuses types 2 and 3 by name, and the
//! client simply does not advertise them.
//!
//! # The history buffer
//!
//! One buffer per direction, 8 KiB or 64 KiB, allocated once by
//! [`MppcDecompressor::new`] and never reallocated. It is **linear**, not a
//! ring: `HistoryOffset` only moves forward, and the compressor is the one
//! that resets it, by setting `PACKET_AT_FRONT` on the packet whose output it
//! wants placed at the start. Three flags steer it (MS-RDPBCGR 3.1.8.2.1):
//!
//! * `PACKET_FLUSHED` (0x80): zero the buffer and set the offset to zero.
//! * `PACKET_AT_FRONT` (0x40): set the offset to zero without clearing.
//! * `PACKET_COMPRESSED` (0x20): the body is a token stream rather than bytes.
//!
//! The decompressed output **is** the history: [`MppcDecompressor::decompress`]
//! returns a borrow of the region it just wrote, so a decompressed packet
//! costs no copy at all.
//!
//! A packet that would run the offset past the end of the buffer is refused.
//! The compressor is required to send `PACKET_AT_FRONT` before that can
//! happen, so a stream that does it is malformed, and silently wrapping would
//! desynchronise our history from the server's for every packet afterwards
//! rather than failing the one that is wrong.
//!
//! # The one reading that a capture has to settle
//!
//! **An uncompressed packet is passed through and does not enter the
//! history.** That is the opposite of the RDP 8.0 rule, where an uncompressed
//! segment does seed the history, which `PRDRDP/13 §6.4` had to be corrected
//! about, so it is worth being explicit that the correction does not carry
//! across. See [`MppcDecompressor::decompress`] for the argument and the
//! failure mode. It is recorded for `docs/RDP_SPEC_NOTES.md`.

use crate::DecodeError;

/// `PACKET_COMPRESSED`: the body is a token stream (MS-RDPBCGR 2.2.1.11.1.1).
pub const PACKET_COMPRESSED: u8 = 0x20;
/// `PACKET_AT_FRONT`: place this packet's output at the start of the history.
pub const PACKET_AT_FRONT: u8 = 0x40;
/// `PACKET_FLUSHED`: the history was reinitialized; do the same.
pub const PACKET_FLUSHED: u8 = 0x80;
/// The low nibble of the flags byte holds the compression type.
pub const COMPRESSION_TYPE_MASK: u8 = 0x0F;

/// `PACKET_COMPR_TYPE_*` (MS-RDPBCGR 2.2.1.11.1.1).
pub mod compression_type {
    /// `PACKET_COMPR_TYPE_8K`: MPPC with an 8 KiB history, RDP 4.0.
    pub const RDP4: u8 = 0;
    /// `PACKET_COMPR_TYPE_64K`: MPPC with a 64 KiB history, RDP 5.0.
    pub const RDP5: u8 = 1;
    /// `PACKET_COMPR_TYPE_RDP6`. Not implemented; see the module comment.
    pub const RDP6: u8 = 2;
    /// `PACKET_COMPR_TYPE_RDP61`. Not implemented; see the module comment.
    pub const RDP61: u8 = 3;
    /// `PACKET_COMPR_TYPE_RDP8`, which is [`crate::zgfx`] and is EGFX only.
    pub const RDP8: u8 = 4;
}

/// History size for RDP 4.0, 8 KiB (MS-RDPBCGR 3.1.8.4.1).
pub const HISTORY_8K: usize = 8 * 1024;
/// History size for RDP 5.0, 64 KiB (MS-RDPBCGR 3.1.8.4.2).
pub const HISTORY_64K: usize = 64 * 1024;

/// Which MPPC the peer negotiated.
///
/// The two differ in three places and nowhere else: the history size, the
/// split points of the copy offset prefix code, and how far the length of
/// match code is allowed to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// RDP 4.0: 8 KiB of history, lengths to 511.
    Rdp4,
    /// RDP 5.0: 64 KiB of history, lengths to 65535.
    Rdp5,
}

impl Variant {
    /// The `PACKET_COMPR_TYPE_*` value this variant answers to.
    #[must_use]
    pub const fn compression_type(self) -> u8 {
        match self {
            Variant::Rdp4 => compression_type::RDP4,
            Variant::Rdp5 => compression_type::RDP5,
        }
    }

    /// Bytes of history this variant keeps.
    #[must_use]
    pub const fn history_size(self) -> usize {
        match self {
            Variant::Rdp4 => HISTORY_8K,
            Variant::Rdp5 => HISTORY_64K,
        }
    }

    /// The largest number of leading one bits a length of match code may
    /// carry, which is what bounds the unary loop.
    ///
    /// RDP 4.0 stops at `11111110` plus eight value bits, a length of 256 to
    /// 511. RDP 5.0 continues to `111111111111110` plus fifteen, a length of
    /// 32768 to 65535, which is exactly its history size.
    const fn max_length_prefix(self) -> u32 {
        match self {
            Variant::Rdp4 => 7,
            Variant::Rdp5 => 14,
        }
    }

    /// The variant for a `PACKET_COMPR_TYPE_*` value.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Range`] for RDP 6.0 and RDP 6.1, which are not
    /// implemented and are never advertised (see the module comment), for RDP
    /// 8.0, which belongs to [`crate::zgfx`] and never arrives on this path,
    /// and for any value the field is not defined for.
    pub fn from_compression_type(ty: u8) -> Result<Self, DecodeError> {
        match ty {
            compression_type::RDP4 => Ok(Variant::Rdp4),
            compression_type::RDP5 => Ok(Variant::Rdp5),
            _ => Err(DecodeError::Range {
                what: "PACKET_COMPR_TYPE",
                got: u32::from(ty),
            }),
        }
    }
}

/// A most significant bit first reader over a packet body.
///
/// Simpler than the ZGFX one: an MPPC packet has no trailing padding count,
/// so the budget is just the body in bits and the trailing zero bits of the
/// last byte are padding by construction. The shortest token is eight bits, a
/// literal, so the decode loop runs while at least eight bits remain and
/// anything shorter than that is the padding.
struct Bits<'a> {
    src: &'a [u8],
    next: usize,
    acc: u64,
    n: u32,
    left: usize,
}

impl<'a> Bits<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            next: 0,
            acc: 0,
            n: 0,
            left: src.len() * 8,
        }
    }

    #[inline]
    fn left(&self) -> usize {
        self.left
    }

    #[inline]
    fn refill(&mut self) {
        while self.n <= 32 {
            let b = match self.src.get(self.next) {
                Some(&b) => {
                    self.next += 1;
                    b
                }
                None => 0,
            };
            self.acc = (self.acc << 8) | u64::from(b);
            self.n += 8;
        }
    }

    /// `k` bits, `k <= 32`.
    #[inline]
    fn bits(&mut self, k: u32) -> Result<u32, DecodeError> {
        if k == 0 {
            return Ok(0);
        }
        if self.left < k as usize {
            return Err(DecodeError::Truncated {
                what: "mppc bitstream",
            });
        }
        self.refill();
        let v = (self.acc >> (self.n - k)) & ((1u64 << k) - 1);
        self.n -= k;
        self.left -= k as usize;
        Ok(v as u32)
    }

    #[inline]
    fn bit(&mut self) -> Result<u32, DecodeError> {
        self.bits(1)
    }
}

/// The MPPC decompressor and its history buffer.
///
/// One per direction per connection. Allocated once; [`Self::decompress`]
/// allocates nothing (PRDRDP/04 §4.1 rule two) and returns a borrow of the
/// history, so a decompressed packet is not copied anywhere.
#[derive(Debug)]
pub struct MppcDecompressor {
    variant: Variant,
    history: Box<[u8]>,
    offset: usize,
}

impl MppcDecompressor {
    /// A decompressor with an empty history. The 8 KiB or 64 KiB is allocated
    /// here and never reallocated.
    #[must_use]
    pub fn new(variant: Variant) -> Self {
        Self {
            variant,
            history: vec![0u8; variant.history_size()].into_boxed_slice(),
            offset: 0,
        }
    }

    /// Which MPPC this is.
    #[must_use]
    pub const fn variant(&self) -> Variant {
        self.variant
    }

    /// Forget the history, as `PACKET_FLUSHED` does. Correct on reconnect and
    /// nowhere else, because the server does not reset its own copy.
    pub fn reset(&mut self) {
        self.history.fill(0);
        self.offset = 0;
    }

    /// Bytes held, for the accounting in PRDRDP/04 §11.3.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.history.len()
    }

    /// How far into the history the next packet will be written. Exposed for
    /// the tests that prove `PACKET_AT_FRONT` and `PACKET_FLUSHED` do what
    /// they say.
    #[must_use]
    pub const fn history_offset(&self) -> usize {
        self.offset
    }

    /// Decompress one packet body.
    ///
    /// `flags` is the whole `compressedType` byte of the share data header
    /// (MS-RDPBCGR 2.2.8.1.1.1.2): the compression type in the low nibble and
    /// `PACKET_COMPRESSED`, `PACKET_AT_FRONT` and `PACKET_FLUSHED` above it.
    /// The returned slice borrows the history buffer, or `src` itself when the
    /// packet was not compressed, so the caller must consume it before the
    /// next packet.
    ///
    /// The order of the three flags is the order MS-RDPBCGR 3.1.8.2.1 gives
    /// and it matters: a packet may carry both `PACKET_FLUSHED` and
    /// `PACKET_AT_FRONT`, and flushing after moving the offset would throw
    /// away the packet we are about to write.
    ///
    /// # An uncompressed packet does not enter the history
    ///
    /// This is the reading that a capture has to settle, and it is the
    /// opposite of the RDP 8.0 rule, where an uncompressed segment does seed
    /// the history (`PRDRDP/13 §6.4`, corrected). The argument for it here:
    /// the compressor and the decompressor must hold identical histories or
    /// every later copy reads the wrong bytes, and an MPPC compressor sends a
    /// packet uncompressed only when compression made it larger, which is a
    /// decision it takes after the fact and which does not retroactively feed
    /// its dictionary.
    ///
    /// If this reading is wrong the failure is quiet and nasty: everything
    /// works until the first uncompressed packet, and then every copy in every
    /// packet afterwards reads bytes that are not there. It cannot corrupt
    /// memory, only pixels and channel data. One capture containing an
    /// uncompressed packet followed by a compressed one settles it.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Range`] when the type nibble is not this decompressor's,
    /// when a copy reaches back past the start of the history, or when a
    /// packet would run the history offset past the end of the buffer.
    /// [`DecodeError::Truncated`] when the token stream ends inside a token.
    pub fn decompress<'a>(&'a mut self, flags: u8, src: &'a [u8]) -> Result<&'a [u8], DecodeError> {
        let ty = flags & COMPRESSION_TYPE_MASK;
        if ty != self.variant.compression_type() {
            return Err(DecodeError::Range {
                what: "mppc compression type",
                got: u32::from(ty),
            });
        }
        if flags & PACKET_FLUSHED != 0 {
            self.history.fill(0);
            self.offset = 0;
        }
        if flags & PACKET_AT_FRONT != 0 {
            self.offset = 0;
        }
        if flags & PACKET_COMPRESSED == 0 {
            return Ok(src);
        }

        let start = self.offset;
        match self.tokens(src) {
            Ok(()) => Ok(&self.history[start..self.offset]),
            Err(e) => {
                // A packet that failed half way has written bytes the server
                // does not believe are there, so the history is no longer
                // shared and every later copy would be wrong. Rewinding is
                // the honest recovery: the caller is going to fail the
                // session, and if it does not, the next `PACKET_AT_FRONT`
                // or `PACKET_FLUSHED` resynchronises from a known state
                // rather than from a partial write.
                self.offset = start;
                Err(e)
            }
        }
    }

    /// The token loop (MS-RDPBCGR 3.1.8.4.1).
    ///
    /// Every token is at least eight bits: a literal is one prefix bit and
    /// seven value bits, and the shortest copy is a four bit offset prefix,
    /// six offset bits and a one bit length. So "at least eight bits left" is
    /// exactly the condition that separates a token from the zero padding of
    /// the last byte, and it is also what makes the loop terminate: every
    /// iteration consumes at least eight bits of a budget that only shrinks.
    fn tokens(&mut self, src: &[u8]) -> Result<(), DecodeError> {
        let mut bits = Bits::new(src);
        while bits.left() >= 8 {
            if bits.bit()? == 0 {
                // `0` then seven bits: a literal below 0x80. Note that this
                // encodes such a byte as itself, which is why an ASCII run
                // costs exactly one byte per character.
                let b = bits.bits(7)? as u8;
                self.push(b)?;
                continue;
            }
            if bits.bit()? == 0 {
                // `10` then seven bits: a literal from 0x80 up.
                let b = 0x80 | bits.bits(7)? as u8;
                self.push(b)?;
                continue;
            }
            // `11`: a copy.
            let offset = self.copy_offset(&mut bits)? as usize;
            let length = length_of_match(&mut bits, self.variant)? as usize;
            self.copy(offset, length)?;
        }
        Ok(())
    }

    /// The copy offset prefix code, which is the only token that differs
    /// between the variants (MS-RDPBCGR 3.1.8.4.1 and 3.1.8.4.2).
    ///
    /// Both leading bits are already consumed. The ranges are contiguous and
    /// each base is the previous base plus the previous row's span, which is
    /// what [`the_copy_offset_ranges_are_contiguous`] checks:
    ///
    /// ```text
    /// RDP 4.0   1111  + 6 bits   0 to 63
    ///           1110  + 8 bits   64 to 319
    ///           110   + 13 bits  320 to 8511
    ///
    /// RDP 5.0   11111 + 6 bits   0 to 63
    ///           11110 + 8 bits   64 to 319
    ///           1110  + 11 bits  320 to 2367
    ///           110   + 16 bits  2368 to 67903
    /// ```
    ///
    /// Both top rows reach past their own history, which is not a hole in the
    /// code: the offset is checked against how much history has actually been
    /// written, in [`Self::copy`], which is a tighter bound than the buffer
    /// size and the only one that is correct.
    #[inline]
    fn copy_offset(&self, bits: &mut Bits<'_>) -> Result<u32, DecodeError> {
        match self.variant {
            Variant::Rdp4 => {
                if bits.bit()? == 0 {
                    return Ok(bits.bits(13)? + 320);
                }
                if bits.bit()? == 1 {
                    Ok(bits.bits(6)?)
                } else {
                    Ok(bits.bits(8)? + 64)
                }
            }
            Variant::Rdp5 => {
                if bits.bit()? == 0 {
                    return Ok(bits.bits(16)? + 2368);
                }
                if bits.bit()? == 0 {
                    return Ok(bits.bits(11)? + 320);
                }
                if bits.bit()? == 1 {
                    Ok(bits.bits(6)?)
                } else {
                    Ok(bits.bits(8)? + 64)
                }
            }
        }
    }

    /// One literal byte into the history.
    #[inline]
    fn push(&mut self, b: u8) -> Result<(), DecodeError> {
        match self.history.get_mut(self.offset) {
            Some(slot) => {
                *slot = b;
                self.offset += 1;
                Ok(())
            }
            None => Err(DecodeError::Range {
                what: "mppc history offset",
                got: self.offset as u32,
            }),
        }
    }

    /// A copy out of the history, `length` bytes from `offset` back.
    #[inline]
    fn copy(&mut self, offset: usize, length: usize) -> Result<(), DecodeError> {
        // Offset zero would read the byte being written and is not produced
        // by any compressor; it is a hole in the code space, not a run.
        if offset == 0 || offset > self.offset {
            return Err(DecodeError::Range {
                what: "mppc copy offset",
                got: offset as u32,
            });
        }
        let end = self.offset + length;
        if end > self.history.len() {
            return Err(DecodeError::Range {
                what: "mppc history offset",
                got: end as u32,
            });
        }
        let mut from = self.offset - offset;
        if length <= offset {
            // The source range ends at or before the destination starts, so
            // the copy reads nothing it is producing and the whole block moves
            // at once. Both bounds were proved above, so this is one memmove
            // with no per byte check (PRDRDP/04 §4.6.8 rule one). Most copies
            // in real traffic land here: an overlapping copy only happens when
            // the server is coding a run.
            self.history.copy_within(from..from + length, self.offset);
            self.offset = end;
            return Ok(());
        }
        // `offset < length`: the copy overlaps the bytes it is producing,
        // which is how a run of one value or of a short repeating pattern is
        // coded. This one has to be byte at a time, because a `copy_within`
        // would move the pre-copy bytes rather than the ones the run is
        // building. Same rule as the ZGFX ring and not negotiable.
        while self.offset < end {
            self.history[self.offset] = self.history[from];
            from += 1;
            self.offset += 1;
        }
        Ok(())
    }
}

/// The length of match prefix code (MS-RDPBCGR 3.1.8.4.1).
///
/// A zero bit means three. Otherwise the number of leading one bits `k` says
/// how many value bits follow, `k + 1` of them, added to `1 << (k + 1)`. So
/// the ranges are 3, then 4 to 7, 8 to 15, 16 to 31 and so on, with no gaps
/// and no overlap, the same structure as the ZGFX match length and a different
/// starting point.
///
/// `k` is bounded by the variant, which is what stops a stream of one bits
/// from running the unary prefix off the end of the shift.
#[inline]
fn length_of_match(bits: &mut Bits<'_>, variant: Variant) -> Result<u32, DecodeError> {
    if bits.bit()? == 0 {
        return Ok(3);
    }
    let mut k = 1u32;
    while bits.bit()? == 1 {
        k += 1;
        if k > variant.max_length_prefix() {
            return Err(DecodeError::Range {
                what: "mppc length of match",
                got: k,
            });
        }
    }
    Ok(bits.bits(k + 1)? + (1u32 << (k + 1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::mppc as enc;

    fn flags(v: Variant, compressed: bool) -> u8 {
        v.compression_type() | if compressed { PACKET_COMPRESSED } else { 0 }
    }

    /// The copy offset code must tile its range with no gap and no overlap,
    /// which is the only structural check the offset table carries. A
    /// mistyped base shows up here rather than as a wrong byte in a clipboard
    /// transfer.
    #[test]
    fn the_copy_offset_ranges_are_contiguous() {
        // (value bits, base) in code order, from the shortest offset up.
        let rdp4 = [(6u32, 0u32), (8, 64), (13, 320)];
        let rdp5 = [(6u32, 0u32), (8, 64), (11, 320), (16, 2368)];
        for rows in [&rdp4[..], &rdp5[..]] {
            assert_eq!(rows[0].1, 0, "the first row must start at zero");
            for w in rows.windows(2) {
                assert_eq!(
                    w[1].1,
                    w[0].1 + (1u32 << w[0].0),
                    "base {} does not follow {} with {} bits",
                    w[1].1,
                    w[0].1,
                    w[0].0
                );
            }
        }
        // And the top row of each reaches past its own history, so the real
        // bound is what has been written, not the buffer size.
        assert!(320 + (1u32 << 13) > HISTORY_8K as u32);
        assert!(2368 + (1u32 << 16) > HISTORY_64K as u32);
    }

    /// The same check for the length of match code, whose bases are powers of
    /// two by construction. RDP 4.0's top length is 511 and RDP 5.0's is
    /// 65535, which is exactly its history.
    #[test]
    fn the_length_of_match_ranges_are_contiguous() {
        let mut top = 3u32;
        for k in 1..=14u32 {
            let base = 1u32 << (k + 1);
            assert_eq!(base, top + 1, "length {base} does not follow {top}");
            top = base + (1u32 << (k + 1)) - 1;
            if k == Variant::Rdp4.max_length_prefix() {
                assert_eq!(top, 511);
            }
        }
        assert_eq!(top, 65535);
        assert_eq!(top as usize, HISTORY_64K - 1);
    }

    /// A hand assembled RDP 4.0 packet, bit by bit, with the arithmetic
    /// written out.
    ///
    /// **This is not a transcription of a published example.** No MS-RDPBCGR
    /// section 4 vector for MPPC was available to this lane, and
    /// `docs/RDP_SPEC_NOTES.md` §1.6 records that every hand computed vector
    /// in this tree says so. The bits below come from the token table of
    /// MS-RDPBCGR 3.1.8.4.1 directly.
    ///
    /// Input `"abcabc"`. The encoder emits three literals and then a copy of
    /// three bytes from three back:
    ///
    /// ```text
    /// 'a' 0x61   0 1100001            a literal below 0x80 encodes as itself
    /// 'b' 0x62   0 1100010
    /// 'c' 0x63   0 1100011
    /// copy       1111 000011 0        offset 3 in six bits, length 3
    /// ```
    ///
    /// That is 24 + 4 + 6 + 1 = 35 bits. Laid out most significant bit first
    /// and padded to 40 with zeros:
    ///
    /// ```text
    /// 01100001 01100010 01100011 11110000 110 00000
    ///   0x61     0x62     0x63     0xF0     0xC0
    /// ```
    #[test]
    fn a_hand_assembled_rdp4_packet_decodes_to_abcabc() {
        let body = [0x61u8, 0x62, 0x63, 0xF0, 0xC0];
        let mut d = MppcDecompressor::new(Variant::Rdp4);
        let out = d.decompress(flags(Variant::Rdp4, true), &body).unwrap();
        assert_eq!(out, b"abcabc");
    }

    /// The same input under RDP 5.0, which spends one more bit on the offset.
    ///
    /// **Hand assembled, not a transcription**, exactly as above.
    ///
    /// ```text
    /// 'a' 'b' 'c'   as before, 24 bits
    /// copy          11111 000011 0     offset 3 in six bits, length 3
    /// ```
    ///
    /// 24 + 5 + 6 + 1 = 36 bits, padded to 40:
    ///
    /// ```text
    /// 01100001 01100010 01100011 11111000 0110 0000
    ///   0x61     0x62     0x63     0xF8     0x60
    /// ```
    #[test]
    fn a_hand_assembled_rdp5_packet_decodes_to_abcabc() {
        let body = [0x61u8, 0x62, 0x63, 0xF8, 0x60];
        let mut d = MppcDecompressor::new(Variant::Rdp5);
        let out = d.decompress(flags(Variant::Rdp5, true), &body).unwrap();
        assert_eq!(out, b"abcabc");
    }

    /// A byte at or above 0x80 takes the two bit prefix.
    ///
    /// **Hand assembled.** Input `[0xE9]`: `0xE9` is `1110_1001`, so the low
    /// seven bits are `110_1001` and the token is `10` then those seven bits.
    ///
    /// ```text
    /// 10 1101001   ->   10110100 1 0000000
    ///                     0xB4     0x80
    /// ```
    #[test]
    fn a_hand_assembled_high_literal_decodes() {
        let body = [0xB4u8, 0x80];
        let mut d = MppcDecompressor::new(Variant::Rdp5);
        let out = d.decompress(flags(Variant::Rdp5, true), &body).unwrap();
        assert_eq!(out, &[0xE9]);
    }

    #[test]
    fn both_variants_round_trip_a_realistic_body() {
        // Repetitive like a channel payload, with runs and with high bytes.
        let mut data = Vec::new();
        for i in 0..600u32 {
            data.extend_from_slice(b"GET /session/");
            data.extend_from_slice(format!("{i:04}").as_bytes());
            data.extend_from_slice(&[0xC3, 0xA9, 0x00, 0x00, 0xFF]);
        }
        for v in [Variant::Rdp4, Variant::Rdp5] {
            // RDP 4.0 has 8 KiB of history, so it gets the first 8000 bytes.
            let src = &data[..data.len().min(v.history_size() - 192)];
            let body = enc::compressed(v, src);
            assert!(
                body.len() < src.len(),
                "{v:?} encoder produced no compression at all"
            );
            let mut d = MppcDecompressor::new(v);
            let out = d.decompress(flags(v, true), &body).unwrap();
            assert_eq!(out, src, "{v:?} round trip");
        }
    }

    /// A copy whose offset is smaller than its length reads bytes it is still
    /// producing. That is how a run is coded and it is why the copy is byte
    /// at a time.
    #[test]
    fn an_overlapping_copy_produces_a_run() {
        for v in [Variant::Rdp4, Variant::Rdp5] {
            let data = vec![0x5Au8; 300];
            let body = enc::compressed(v, &data);
            let mut d = MppcDecompressor::new(v);
            assert_eq!(d.decompress(flags(v, true), &body).unwrap(), &data[..]);

            // And a repeating pattern, where the offset is three and the
            // length is far more.
            let data: Vec<u8> = b"xyz".iter().cycle().take(400).copied().collect();
            let body = enc::compressed(v, &data);
            let mut d = MppcDecompressor::new(v);
            assert_eq!(d.decompress(flags(v, true), &body).unwrap(), &data[..]);
        }
    }

    /// The whole point of the history: a copy in a later packet reaches back
    /// into an earlier one.
    #[test]
    fn the_history_survives_from_one_packet_to_the_next() {
        let mut d = MppcDecompressor::new(Variant::Rdp5);
        let first = enc::compressed(Variant::Rdp5, b"the quick brown fox");
        assert_eq!(
            d.decompress(flags(Variant::Rdp5, true), &first).unwrap(),
            b"the quick brown fox"
        );
        assert_eq!(d.history_offset(), 19);
        // "brown" starts at index 10 of a nineteen byte history, so it is
        // nine bytes back from the write position.
        let second = enc::copy_only(Variant::Rdp5, 9, 5);
        assert_eq!(
            d.decompress(flags(Variant::Rdp5, true), &second).unwrap(),
            b"brown"
        );
        assert_eq!(d.history_offset(), 24);
    }

    #[test]
    fn packet_at_front_moves_the_offset_without_clearing() {
        let mut d = MppcDecompressor::new(Variant::Rdp5);
        let first = enc::compressed(Variant::Rdp5, b"0123456789");
        d.decompress(flags(Variant::Rdp5, true), &first).unwrap();
        assert_eq!(d.history_offset(), 10);

        let second = enc::compressed(Variant::Rdp5, b"AB");
        let out = d
            .decompress(flags(Variant::Rdp5, true) | PACKET_AT_FRONT, &second)
            .unwrap();
        assert_eq!(out, b"AB");
        assert_eq!(d.history_offset(), 2);
    }

    #[test]
    fn packet_flushed_zeroes_the_history() {
        let mut d = MppcDecompressor::new(Variant::Rdp5);
        let first = enc::compressed(Variant::Rdp5, b"0123456789");
        d.decompress(flags(Variant::Rdp5, true), &first).unwrap();

        let second = enc::compressed(Variant::Rdp5, b"ABC");
        d.decompress(flags(Variant::Rdp5, true) | PACKET_FLUSHED, &second)
            .unwrap();
        assert_eq!(d.history_offset(), 3);
        // The history restarted, so a copy three back reaches the bytes this
        // packet wrote rather than anything the flushed packet left.
        let third = enc::copy_only(Variant::Rdp5, 3, 3);
        assert_eq!(
            d.decompress(flags(Variant::Rdp5, true), &third).unwrap(),
            b"ABC"
        );
        // And a copy that reaches further back than the restart is refused
        // rather than reading the zeros the flush wrote.
        let fourth = enc::copy_only(Variant::Rdp5, 9, 3);
        assert!(d.decompress(flags(Variant::Rdp5, true), &fourth).is_err());
    }

    /// The reading recorded in the module comment, pinned so a change to it
    /// is a deliberate change and not a drift.
    #[test]
    fn an_uncompressed_packet_is_passed_through_and_does_not_seed_the_history() {
        let mut d = MppcDecompressor::new(Variant::Rdp5);
        let out = d
            .decompress(flags(Variant::Rdp5, false), b"plain bytes")
            .unwrap();
        assert_eq!(out, b"plain bytes");
        assert_eq!(d.history_offset(), 0, "the history did not move");
    }

    #[test]
    fn the_wrong_compression_type_is_refused() {
        let mut d = MppcDecompressor::new(Variant::Rdp5);
        assert_eq!(
            d.decompress(PACKET_COMPRESSED | compression_type::RDP4, &[0x61]),
            Err(DecodeError::Range {
                what: "mppc compression type",
                got: 0
            })
        );
    }

    #[test]
    fn rdp6_and_rdp61_are_refused_by_name() {
        for ty in [
            compression_type::RDP6,
            compression_type::RDP61,
            compression_type::RDP8,
            5,
            15,
        ] {
            assert_eq!(
                Variant::from_compression_type(ty),
                Err(DecodeError::Range {
                    what: "PACKET_COMPR_TYPE",
                    got: u32::from(ty)
                })
            );
        }
        assert_eq!(
            Variant::from_compression_type(compression_type::RDP4),
            Ok(Variant::Rdp4)
        );
        assert_eq!(
            Variant::from_compression_type(compression_type::RDP5),
            Ok(Variant::Rdp5)
        );
    }

    /// A copy that reaches back further than anything has been written is a
    /// read of the buffer's initial zeros in every other implementation. Here
    /// it is an error, because the only reason it can happen is that our
    /// history and the server's have already diverged.
    #[test]
    fn a_copy_past_the_start_of_the_history_is_refused() {
        let mut d = MppcDecompressor::new(Variant::Rdp5);
        let body = enc::copy_only(Variant::Rdp5, 5, 3);
        assert_eq!(
            d.decompress(flags(Variant::Rdp5, true), &body),
            Err(DecodeError::Range {
                what: "mppc copy offset",
                got: 5
            })
        );
        // And offset zero, which is a hole in the code space.
        let body = enc::copy_only(Variant::Rdp5, 0, 3);
        assert_eq!(
            d.decompress(flags(Variant::Rdp5, true), &body),
            Err(DecodeError::Range {
                what: "mppc copy offset",
                got: 0
            })
        );
    }

    /// A packet that would run past the end of the history is refused rather
    /// than wrapping, and the failure leaves the offset where it was.
    #[test]
    fn a_packet_past_the_end_of_the_history_is_refused() {
        let mut d = MppcDecompressor::new(Variant::Rdp4);
        // Fill almost the whole 8 KiB.
        let data = vec![0x41u8; HISTORY_8K - 4];
        let body = enc::compressed(Variant::Rdp4, &data);
        assert_eq!(
            d.decompress(flags(Variant::Rdp4, true), &body)
                .unwrap()
                .len(),
            HISTORY_8K - 4
        );
        assert_eq!(d.history_offset(), HISTORY_8K - 4);

        // Eight more bytes do not fit.
        let more = enc::compressed(Variant::Rdp4, b"12345678");
        let before = d.history_offset();
        assert!(d.decompress(flags(Variant::Rdp4, true), &more).is_err());
        assert_eq!(
            d.history_offset(),
            before,
            "a failed packet must not leave a partial write behind"
        );
        // And the connection recovers on the next PACKET_AT_FRONT, which is
        // what the server sends when its own history fills.
        let out = d
            .decompress(flags(Variant::Rdp4, true) | PACKET_AT_FRONT, &more)
            .unwrap();
        assert_eq!(out, b"12345678");
    }

    /// The truncation sweep. Every prefix of a valid packet decodes or
    /// errors, never panics, and never leaves the decompressor unable to
    /// handle the next packet.
    #[test]
    fn every_prefix_is_handled() {
        for v in [Variant::Rdp4, Variant::Rdp5] {
            let data: Vec<u8> = (0..900u32).map(|i| (i * 7 % 251) as u8).collect();
            let body = enc::compressed(v, &data);
            let mut d = MppcDecompressor::new(v);
            for n in 0..body.len() {
                let _ = d.decompress(flags(v, true), &body[..n]);
            }
            d.reset();
            assert_eq!(d.decompress(flags(v, true), &body).unwrap(), &data[..]);
        }
    }

    /// The adversarial sweep. Arbitrary bodies must terminate: the bit budget
    /// only shrinks, every iteration takes at least eight bits of it, and
    /// every write is bounded by the history.
    #[test]
    fn arbitrary_bodies_terminate() {
        for v in [Variant::Rdp4, Variant::Rdp5] {
            let mut d = MppcDecompressor::new(v);
            for lead in 0u16..=255 {
                for tail in [
                    &[0xFFu8; 12][..],
                    &[0x00; 12][..],
                    &[0xAA; 12][..],
                    &[
                        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFF, 0xFF, 0xFF, 0xFF,
                    ][..],
                ] {
                    let mut body = vec![lead as u8];
                    body.extend_from_slice(tail);
                    let _ = d.decompress(flags(v, true), &body);
                    let _ = d.decompress(flags(v, true) | PACKET_AT_FRONT, &body);
                }
            }
        }
    }

    /// A body of nothing but one bits drives the length of match unary escape
    /// as far as it goes, which is the one loop whose bound is not the bit
    /// budget alone.
    #[test]
    fn a_pathological_length_of_match_is_refused_rather_than_overflowing() {
        for v in [Variant::Rdp4, Variant::Rdp5] {
            let mut d = MppcDecompressor::new(v);
            // A literal to give the copy something to reach, then all ones.
            let mut body = vec![0x41u8];
            body.extend_from_slice(&[0xFF; 64]);
            let _ = d.decompress(flags(v, true), &body);
        }
    }

    /// A single packet whose output is the whole history, which is the
    /// largest legal one, and it must not be off by one at either end.
    #[test]
    fn a_packet_that_exactly_fills_the_history_is_accepted() {
        let mut d = MppcDecompressor::new(Variant::Rdp4);
        let data = vec![0x37u8; HISTORY_8K];
        let body = enc::compressed(Variant::Rdp4, &data);
        let out = d.decompress(flags(Variant::Rdp4, true), &body).unwrap();
        assert_eq!(out.len(), HISTORY_8K);
        assert_eq!(d.history_offset(), HISTORY_8K);
        // One more byte does not fit, and the offset does not move.
        let more = enc::compressed(Variant::Rdp4, b"z");
        assert!(d.decompress(flags(Variant::Rdp4, true), &more).is_err());
        assert_eq!(d.history_offset(), HISTORY_8K);
    }

    #[test]
    fn the_history_reports_its_size_and_its_variant() {
        let d = MppcDecompressor::new(Variant::Rdp4);
        assert_eq!(d.bytes(), HISTORY_8K);
        assert_eq!(d.variant(), Variant::Rdp4);
        let d = MppcDecompressor::new(Variant::Rdp5);
        assert_eq!(d.bytes(), HISTORY_64K);
        assert_eq!(d.variant(), Variant::Rdp5);
    }

    /// The invariants `fuzz/fuzz_targets/fuzz_mppc.rs` asserts, driven by a
    /// deterministic generator so they are checked on every `cargo test` and
    /// not only when someone runs the fuzzer.
    ///
    /// Every flag combination runs against a history that earlier packets
    /// seeded, because the flags are the part that cannot be checked one
    /// packet at a time: `PACKET_AT_FRONT` on a decompressor that has never
    /// written anything proves nothing.
    #[test]
    fn the_fuzz_invariants_hold_over_a_generated_corpus() {
        let mut x = 0x1234_ABCDu32;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for v in [Variant::Rdp4, Variant::Rdp5] {
            let mut d = MppcDecompressor::new(v);
            let size = d.bytes();
            let mut body = Vec::with_capacity(256);
            for _ in 0..8_000 {
                body.clear();
                let n = 1 + next() % 120;
                for _ in 0..n {
                    // Biased towards all ones and all zeros, which are the
                    // longest unary prefixes and the longest literal runs.
                    body.push(match next() % 4 {
                        0 => 0xFF,
                        1 => 0x00,
                        _ => (next() >> 19) as u8,
                    });
                }
                let flags = ((next() as u8) & !COMPRESSION_TYPE_MASK) | v.compression_type();
                let before = d.history_offset();
                match d.decompress(flags, &body) {
                    Ok(out) => assert!(out.len() <= size, "output larger than the history"),
                    Err(_) => {
                        if flags & (PACKET_AT_FRONT | PACKET_FLUSHED) == 0 {
                            assert_eq!(
                                d.history_offset(),
                                before,
                                "a failed packet left a partial write behind"
                            );
                        }
                    }
                }
                assert!(d.history_offset() <= size, "the offset left the buffer");
            }
        }
    }

    /// An empty body is a legal packet that decodes to nothing.
    #[test]
    fn an_empty_body_produces_nothing() {
        let mut d = MppcDecompressor::new(Variant::Rdp5);
        assert_eq!(
            d.decompress(flags(Variant::Rdp5, true), &[]).unwrap(),
            b"" as &[u8]
        );
        assert_eq!(d.history_offset(), 0);
    }
}
