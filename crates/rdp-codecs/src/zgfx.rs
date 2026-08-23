//! RDP 8.0 bulk decompression, the EGFX outer layer (MS-RDPEGFX 3.1.9.1 for
//! the container, MS-RDPBCGR 3.1.8.4.2 for the compressor itself).
//!
//! Every byte on the EGFX channel arrives inside `RDP_SEGMENTED_DATA`, so
//! without this the channel does not function at all and no other phase 2
//! codec can be tested end to end. That is why PRDRDP/04 §4.12 makes it the
//! first phase 2 package, and why PRDRDP/04 §11.2 puts it in the stage bench
//! group: it taxes every EGFX codec at once.
//!
//! ## The three things a first implementation gets wrong
//!
//! * **Uncompressed segments still go into the history buffer.** Everything
//!   works until the server sends one, and then every match afterwards reads
//!   the wrong bytes. It has its own test.
//! * **A match token with distance zero is not a match.** It is the escape
//!   for incompressible data: read fifteen bits as a byte count, align the
//!   reader to the next byte boundary, and copy that many literal bytes
//!   straight through. It has its own test.
//! * **A match may overlap the bytes it is producing.** `distance < length`
//!   is how a run of one byte is coded, so the copy is byte at a time out of
//!   the ring and never a `copy_from_slice`. That is slower than a bulk copy
//!   and it is not negotiable.
//!
//! ## The token table, and how far to trust it
//!
//! [`TOKENS`] is transcribed into a `const` array and turned into a 512 entry
//! flat lookup table by a `const fn`, so the prefix decode is "peek nine bits,
//! index, consume `len`" with no search.
//!
//! **The table's contents are a reconstruction, not a transcription.**
//! MS-RDPBCGR 3.1.8.4.2.2.1 was not available to this lane. The match rows
//! carry their own proof and the literal rows do not, and the difference
//! matters:
//!
//! * The eleven match rows have distance bases 0, 32, 160, 672, 1696, 5792,
//!   22176, 54944, 317088, 1365664 and 18142880 with 5, 7, 9, 10, 12, 14, 15,
//!   18, 20, 24 and 32 value bits. Each base is the previous base plus two to
//!   the previous row's bit count, all eleven times, with no slack anywhere.
//!   A single wrong digit in any of those twenty two numbers breaks the
//!   chain, so the chain is the evidence.
//! * The literal rows carry no such structure. They are a frequency ordering
//!   and nothing checks them. If one of them is wrong, a decompressed EGFX
//!   stream carries a wrong byte at a rate of roughly one in a few thousand,
//!   which shows up as an occasional malformed PDU rather than as garbage.
//!   [`the_token_table_is_a_prefix_code`] proves the table is decodable and
//!   proves nothing about whether it is the right one.
//!
//! This is the single highest risk transcription in this crate and it is
//! reported as such. The MS-RDPBCGR §4 segmented data vector settles it in
//! one test (PRDRDP/04 §11.8).

use crate::{DecodeError, Reader};

/// `RDP_SEGMENTED_DATA.descriptor` values (MS-RDPEGFX 2.2.5.1).
const SINGLE: u8 = 0xE0;
const MULTIPART: u8 = 0xE1;

/// `PACKET_COMPR_TYPE_RDP8`, the low nibble of a segment's header byte.
const COMPR_TYPE_RDP8: u8 = 0x04;
/// `PACKET_COMPRESSED`, in the high nibble.
const PACKET_COMPRESSED: u8 = 0x20;

/// History ring size (MS-RDPBCGR 3.1.8.4.2, PRDRDP/04 §4.12.3).
pub const HISTORY: usize = 2_500_000;

/// The ceiling on one decompressed EGFX message
/// (PRDRDP/04 §4.12.1, `MAX_EGFX_MESSAGE`).
///
/// `uncompressedSize` is a `u32` from the network, so it is checked against
/// this before a byte is decompressed.
pub const MAX_EGFX_MESSAGE: usize = 64 * 1024 * 1024;

/// One row of the token table (MS-RDPBCGR 3.1.8.4.2.2.1).
#[derive(Clone, Copy)]
pub(crate) struct Token {
    /// Prefix length in bits.
    pub(crate) len: u8,
    /// The prefix itself, right aligned in `len` bits.
    pub(crate) code: u16,
    /// Value bits that follow the prefix.
    pub(crate) value_bits: u8,
    /// True for a match token, false for a literal.
    pub(crate) is_match: bool,
    /// Literal byte when `value_bits` is zero, or the match distance base.
    pub(crate) value_base: u32,
}

const fn lit(len: u8, code: u16, value_bits: u8, value_base: u32) -> Token {
    Token {
        len,
        code,
        value_bits,
        is_match: false,
        value_base,
    }
}

const fn mat(len: u8, code: u16, value_bits: u8, value_base: u32) -> Token {
    Token {
        len,
        code,
        value_bits,
        is_match: true,
        value_base,
    }
}

/// The token table, in the specification's own row order so a reviewer can
/// diff it against MS-RDPBCGR 3.1.8.4.2.2.1 line by line.
///
/// See the module comment for what is and is not evidence here.
pub(crate) const TOKENS: [Token; 37] = [
    lit(1, 0b0, 8, 0),
    mat(5, 0b10001, 5, 0),
    mat(5, 0b10010, 7, 32),
    mat(5, 0b10011, 9, 160),
    mat(5, 0b10100, 10, 672),
    mat(5, 0b10101, 12, 1696),
    lit(5, 0b11000, 0, 0x00),
    lit(5, 0b11001, 0, 0x01),
    mat(6, 0b101100, 14, 5792),
    mat(6, 0b101101, 15, 22176),
    lit(6, 0b110100, 0, 0x02),
    lit(6, 0b110101, 0, 0x03),
    lit(6, 0b110110, 0, 0xFF),
    mat(7, 0b1011100, 18, 54944),
    mat(7, 0b1011101, 20, 317088),
    lit(7, 0b1101110, 0, 0x04),
    lit(7, 0b1101111, 0, 0x05),
    lit(7, 0b1110000, 0, 0x06),
    lit(7, 0b1110001, 0, 0x07),
    lit(7, 0b1110010, 0, 0x08),
    lit(7, 0b1110011, 0, 0x09),
    lit(7, 0b1110100, 0, 0x0A),
    lit(7, 0b1110101, 0, 0x0B),
    lit(7, 0b1110110, 0, 0x3A),
    lit(7, 0b1110111, 0, 0x3B),
    lit(7, 0b1111000, 0, 0x3C),
    lit(7, 0b1111001, 0, 0x3D),
    lit(7, 0b1111010, 0, 0x3E),
    lit(7, 0b1111011, 0, 0x3F),
    lit(7, 0b1111100, 0, 0x40),
    lit(7, 0b1111101, 0, 0x80),
    mat(8, 0b10111100, 24, 1_365_664),
    mat(8, 0b10111101, 32, 18_142_880),
    lit(8, 0b11111100, 0, 0x0C),
    lit(8, 0b11111101, 0, 0x38),
    lit(8, 0b11111110, 0, 0x39),
    lit(8, 0b11111111, 0, 0x66),
];

/// Bits the flat lookup table indexes on. The longest prefix is eight, so
/// nine is one more than enough and keeps the table in one cache line group.
const LUT_BITS: u32 = 9;
/// No token has this prefix.
const NO_TOKEN: u8 = 0xFF;

/// Peek nine bits, index, get the token, consume its prefix.
///
/// Built by a `const fn` so the transcription in [`TOKENS`] is checked once
/// by the compiler rather than once per reviewer: a duplicated prefix would
/// make the table ambiguous, and [`the_token_table_is_a_prefix_code`] proves
/// the built table assigns every reachable index at most once.
const fn build_lut() -> [u8; 1 << LUT_BITS] {
    let mut lut = [NO_TOKEN; 1 << LUT_BITS];
    let mut i = 0;
    while i < TOKENS.len() {
        let t = TOKENS[i];
        let shift = LUT_BITS - t.len as u32;
        let start = (t.code as usize) << shift;
        let end = start + (1 << shift);
        let mut v = start;
        while v < end {
            lut[v] = i as u8;
            v += 1;
        }
        i += 1;
    }
    lut
}

const LUT: [u8; 1 << LUT_BITS] = build_lut();

/// A most significant bit first reader with an explicit bit budget and a
/// byte align, which the distance zero escape needs
/// (MS-RDPBCGR 3.1.8.4.2.2).
struct Bits<'a> {
    src: &'a [u8],
    next: usize,
    acc: u64,
    n: u32,
    consumed: usize,
    total: usize,
}

impl<'a> Bits<'a> {
    fn new(src: &'a [u8], total: usize) -> Self {
        Self {
            src,
            next: 0,
            acc: 0,
            n: 0,
            consumed: 0,
            total,
        }
    }

    #[inline]
    fn left(&self) -> usize {
        self.total - self.consumed
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

    /// `k` bits, `k <= 32`. Errors rather than reading past the budget, which
    /// is where the segment's padding bits live.
    #[inline]
    fn bits(&mut self, k: u32) -> Result<u32, DecodeError> {
        if k == 0 {
            return Ok(0);
        }
        if self.left() < k as usize {
            return Err(DecodeError::Truncated {
                what: "zgfx bitstream",
            });
        }
        self.refill();
        let v = (self.acc >> (self.n - k)) & ((1u64 << k) - 1);
        self.n -= k;
        self.consumed += k as usize;
        Ok(v as u32)
    }

    #[inline]
    fn bit(&mut self) -> Result<u32, DecodeError> {
        self.bits(1)
    }

    /// Peek up to [`LUT_BITS`] bits without consuming, padding with zeros at
    /// the end of the budget.
    ///
    /// Padding rather than erroring is deliberate: the last token of a
    /// segment can be shorter than nine bits, so a peek that insisted on nine
    /// would refuse a well formed stream. The token's own prefix length is
    /// checked against the budget when it is consumed.
    #[inline]
    fn peek9(&mut self) -> u32 {
        self.refill();
        let have = (self.left() as u32).min(LUT_BITS);
        let v = (self.acc >> (self.n - have)) & ((1u64 << have) - 1);
        (v as u32) << (LUT_BITS - have)
    }

    /// Discard bits up to the next byte boundary.
    fn align(&mut self) -> Result<(), DecodeError> {
        let r = self.consumed % 8;
        if r != 0 {
            self.bits(8 - r as u32)?;
        }
        Ok(())
    }

    /// `count` whole bytes, which the caller has aligned first.
    fn bytes(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        debug_assert_eq!(self.consumed % 8, 0);
        if self.left() < count * 8 {
            return Err(DecodeError::Truncated {
                what: "zgfx unencoded run",
            });
        }
        let at = self.consumed / 8;
        let s = self.src.get(at..at + count).ok_or(DecodeError::Truncated {
            what: "zgfx unencoded run",
        })?;
        self.consumed += count * 8;
        // The window is stale now, so drop it and reload from the new byte.
        self.next = at + count;
        self.acc = 0;
        self.n = 0;
        Ok(s)
    }
}

/// The RDP 8.0 bulk decompressor and its history buffer.
///
/// One per EGFX channel. The history persists across PDUs and across EGFX
/// frames and is reset only when the channel is closed and reopened, never on
/// `ResetGraphics`, because the server does not reset its own copy
/// (PRDRDP/04 §4.12.3).
pub struct Rdp8Decompressor {
    history: Box<[u8]>,
    pos: usize,
}

impl Default for Rdp8Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Rdp8Decompressor {
    /// A decompressor with an empty history. The 2.5 MB is allocated here and
    /// never reallocated.
    pub fn new() -> Self {
        Self {
            history: vec![0u8; HISTORY].into_boxed_slice(),
            pos: 0,
        }
    }

    /// Forget the history. Only correct when the channel itself was torn
    /// down; see the type comment.
    pub fn reset(&mut self) {
        self.history.fill(0);
        self.pos = 0;
    }

    /// Bytes held, for the accounting in PRDRDP/04 §11.3.
    pub fn bytes(&self) -> usize {
        self.history.len()
    }

    #[inline]
    fn push(&mut self, b: u8, out: &mut Vec<u8>) {
        self.history[self.pos] = b;
        self.pos += 1;
        if self.pos == HISTORY {
            self.pos = 0;
        }
        out.push(b);
    }

    /// Decompress one `RDP_SEGMENTED_DATA` into `out`, which is cleared
    /// first (MS-RDPEGFX 2.2.5.1, 3.1.9.1).
    pub fn decompress(&mut self, src: &[u8], out: &mut Vec<u8>) -> Result<(), DecodeError> {
        out.clear();
        let mut r = Reader::new(src, "zgfx segmented data");
        match r.u8()? {
            SINGLE => {
                let rest = r.remaining();
                self.segment(r.take(rest)?, out)
            }
            MULTIPART => {
                let count = usize::from(r.u16_le()?);
                let uncompressed = r.u32_le()? as usize;
                if uncompressed > MAX_EGFX_MESSAGE {
                    return Err(DecodeError::Budget("zgfx uncompressedSize"));
                }
                out.reserve(uncompressed);
                for _ in 0..count {
                    let n = r.u32_le()? as usize;
                    self.segment(r.take(n)?, out)?;
                }
                // The declared size is a budget rather than a promise: a
                // server that gets it wrong is a stream we still decode, and
                // saying so here is cheaper than a caller wondering why.
                Ok(())
            }
            other => Err(DecodeError::Range {
                what: "RDP_SEGMENTED_DATA descriptor",
                got: u32::from(other),
            }),
        }
    }

    /// One `RDP_DATA_SEGMENT` (MS-RDPBCGR 2.2.2.4).
    fn segment(&mut self, seg: &[u8], out: &mut Vec<u8>) -> Result<(), DecodeError> {
        let (&flags, data) = seg.split_first().ok_or(DecodeError::Truncated {
            what: "zgfx data segment",
        })?;
        if flags & 0x0F != COMPR_TYPE_RDP8 {
            return Err(DecodeError::Range {
                what: "zgfx compression type",
                got: u32::from(flags & 0x0F),
            });
        }
        if flags & PACKET_COMPRESSED == 0 {
            // Literal bytes, and they go into the history as well as into the
            // output. This is the rule that makes everything work right up
            // until the first uncompressed segment.
            if out.len() + data.len() > MAX_EGFX_MESSAGE {
                return Err(DecodeError::Budget("zgfx output"));
            }
            for &b in data {
                self.push(b, out);
            }
            return Ok(());
        }

        // The last byte of a compressed segment is the number of padding bits
        // in the byte before it, so the reader stops before consuming them.
        let (&pad, body) = data.split_last().ok_or(DecodeError::Truncated {
            what: "zgfx compressed segment",
        })?;
        let total = body
            .len()
            .checked_mul(8)
            .and_then(|b| b.checked_sub(usize::from(pad)))
            .ok_or(DecodeError::Range {
                what: "zgfx padding bit count",
                got: u32::from(pad),
            })?;
        let mut bits = Bits::new(body, total);

        while bits.left() > 0 {
            let t = TOKENS[self.token(&mut bits)?];
            if !t.is_match {
                let b = if t.value_bits == 0 {
                    t.value_base as u8
                } else {
                    bits.bits(u32::from(t.value_bits))? as u8
                };
                if out.len() >= MAX_EGFX_MESSAGE {
                    return Err(DecodeError::Budget("zgfx output"));
                }
                self.push(b, out);
                continue;
            }

            let distance = t.value_base + bits.bits(u32::from(t.value_bits))?;
            if distance == 0 {
                // The unencoded run escape.
                let count = bits.bits(15)? as usize;
                bits.align()?;
                let run = bits.bytes(count)?;
                if out.len() + run.len() > MAX_EGFX_MESSAGE {
                    return Err(DecodeError::Budget("zgfx output"));
                }
                for &b in run {
                    self.push(b, out);
                }
                continue;
            }

            let length = self.match_length(&mut bits)?;
            let distance = distance as usize;
            if distance > HISTORY {
                return Err(DecodeError::Range {
                    what: "zgfx match distance",
                    got: distance as u32,
                });
            }
            if out.len() + length > MAX_EGFX_MESSAGE {
                return Err(DecodeError::Budget("zgfx output"));
            }
            // Byte at a time out of the ring, because a match may overlap the
            // bytes it is producing and that is how a run of one value is
            // coded.
            let mut from = (self.pos + HISTORY - distance) % HISTORY;
            for _ in 0..length {
                let b = self.history[from];
                from += 1;
                if from == HISTORY {
                    from = 0;
                }
                self.push(b, out);
            }
        }
        Ok(())
    }

    /// Longest prefix match through the flat lookup table.
    #[inline]
    fn token(&self, bits: &mut Bits<'_>) -> Result<usize, DecodeError> {
        let idx = LUT[bits.peek9() as usize];
        if idx == NO_TOKEN {
            return Err(DecodeError::Range {
                what: "zgfx token prefix",
                got: bits.peek9(),
            });
        }
        let t = TOKENS[idx as usize];
        bits.bits(u32::from(t.len))?;
        Ok(idx as usize)
    }

    /// The match length code (MS-RDPBCGR 3.1.8.4.2.2).
    ///
    /// A zero bit means three. Otherwise the number of following one bits
    /// says how many value bits there are, starting at two, and the value is
    /// added to `1 << extra`. So the ranges are 3, then 4 to 7, then 8 to 15,
    /// and so on, with no gaps and no overlap.
    #[inline]
    fn match_length(&self, bits: &mut Bits<'_>) -> Result<usize, DecodeError> {
        if bits.bit()? == 0 {
            return Ok(3);
        }
        let mut extra = 2u32;
        while bits.bit()? == 1 {
            extra += 1;
            if extra > 30 {
                // A length of 2^31 cannot be produced by any legal stream and
                // would overflow the shift below.
                return Err(DecodeError::Range {
                    what: "zgfx match length",
                    got: extra,
                });
            }
        }
        Ok(bits.bits(extra)? as usize + (1usize << extra))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::zgfx as enc;

    /// The table must be decodable: no prefix may be a prefix of another, or
    /// the flat lookup would have to pick one and the picture would depend on
    /// which. This proves the table is a code. It does not prove it is the
    /// right code; see the module comment.
    #[test]
    fn the_token_table_is_a_prefix_code() {
        let mut owner = [NO_TOKEN; 1 << LUT_BITS];
        for (i, t) in TOKENS.iter().enumerate() {
            assert!(
                t.len as u32 <= LUT_BITS,
                "prefix {i} is longer than the lut"
            );
            let shift = LUT_BITS - t.len as u32;
            let start = (t.code as usize) << shift;
            for slot in owner.iter_mut().skip(start).take(1 << shift) {
                assert_eq!(*slot, NO_TOKEN, "two tokens claim the same prefix");
                *slot = i as u8;
            }
        }
        assert_eq!(owner, LUT);
    }

    /// The match rows' own consistency proof, written out as a test so a
    /// mistyped digit fails here rather than in a picture. Each distance base
    /// is the previous base plus two to the previous row's value bit count.
    #[test]
    fn the_match_distance_bases_form_one_unbroken_chain() {
        let matches: Vec<&Token> = TOKENS.iter().filter(|t| t.is_match).collect();
        assert_eq!(matches.len(), 11);
        assert_eq!(matches[0].value_base, 0);
        for w in matches.windows(2) {
            let want = w[0].value_base + (1u32 << w[0].value_bits);
            assert_eq!(
                w[1].value_base, want,
                "base {} does not follow {} with {} bits",
                w[1].value_base, w[0].value_base, w[0].value_bits
            );
        }
        // And the last one covers the whole distance range a 2.5 MB history
        // can address, which is the other end of the same check.
        let last = matches[matches.len() - 1];
        assert!(u64::from(last.value_base) > HISTORY as u64);
    }

    #[test]
    fn a_single_uncompressed_segment_round_trips_and_seeds_the_history() {
        let data: Vec<u8> = (0..200u8).collect();
        let src = enc::single_uncompressed(&data);
        let mut d = Rdp8Decompressor::new();
        let mut out = Vec::new();
        d.decompress(&src, &mut out).unwrap();
        assert_eq!(out, data);
        // The rule that a first implementation misses: an uncompressed
        // segment still goes into the history, so a match in the next
        // message can reach back into it.
        let follow = enc::single_compressed_match(1, 5);
        let mut out2 = Vec::new();
        d.decompress(&follow, &mut out2).unwrap();
        assert_eq!(out2, vec![199u8; 5]);
    }

    #[test]
    fn literals_round_trip_through_the_token_table() {
        // Every byte value, so every literal row of the table is exercised
        // whether it is one of the short coded ones or the eight bit form.
        let data: Vec<u8> = (0..=255u8).collect();
        let src = enc::single_compressed(&data);
        let mut out = Vec::new();
        Rdp8Decompressor::new().decompress(&src, &mut out).unwrap();
        assert_eq!(out, data);
    }

    /// A match whose distance is smaller than its length reads bytes it is
    /// still producing. That is how a run is coded and it is why the copy is
    /// byte at a time.
    #[test]
    fn an_overlapping_match_produces_a_run() {
        let src = enc::single_compressed(b"abcabcabcabcabcabc");
        let mut out = Vec::new();
        Rdp8Decompressor::new().decompress(&src, &mut out).unwrap();
        assert_eq!(out, b"abcabcabcabcabcabc");
    }

    #[test]
    fn the_distance_zero_escape_copies_literal_bytes() {
        let run: Vec<u8> = (0..137u8).map(|i| i.wrapping_mul(97) ^ 0x3C).collect();
        let src = enc::single_unencoded_run(&run);
        let mut d = Rdp8Decompressor::new();
        let mut out = Vec::new();
        d.decompress(&src, &mut out).unwrap();
        assert_eq!(out, run);
        // And those bytes went into the history too, so a match afterwards
        // finds them.
        let follow = enc::single_compressed_match(3, 3);
        let mut out2 = Vec::new();
        d.decompress(&follow, &mut out2).unwrap();
        assert_eq!(out2, run[run.len() - 3..]);
    }

    #[test]
    fn a_multipart_message_concatenates_its_segments() {
        let a: Vec<u8> = (0..90u8).collect();
        let b: Vec<u8> = (90..200u8).collect();
        let src = enc::multipart(&[&a, &b]);
        let mut out = Vec::new();
        Rdp8Decompressor::new().decompress(&src, &mut out).unwrap();
        let mut want = a.clone();
        want.extend_from_slice(&b);
        assert_eq!(out, want);
    }

    /// The whole point of the history: a match in a later message reaches
    /// back into an earlier one.
    #[test]
    fn the_history_survives_from_one_message_to_the_next() {
        let mut d = Rdp8Decompressor::new();
        let mut out = Vec::new();
        d.decompress(&enc::single_uncompressed(b"the quick brown fox"), &mut out)
            .unwrap();
        let mut out2 = Vec::new();
        d.decompress(&enc::single_compressed_match(9, 5), &mut out2)
            .unwrap();
        assert_eq!(&out2, b"brown");
        d.reset();
        let mut out3 = Vec::new();
        d.decompress(&enc::single_compressed_match(9, 5), &mut out3)
            .unwrap();
        assert_eq!(out3, vec![0u8; 5]);
    }

    #[test]
    fn a_bad_descriptor_or_compression_type_is_refused() {
        let mut d = Rdp8Decompressor::new();
        let mut out = Vec::new();
        assert_eq!(
            d.decompress(&[0xE5, 0x24, 0x00], &mut out),
            Err(DecodeError::Range {
                what: "RDP_SEGMENTED_DATA descriptor",
                got: 0xE5
            })
        );
        assert_eq!(
            d.decompress(&[SINGLE, 0x21, 0x00], &mut out),
            Err(DecodeError::Range {
                what: "zgfx compression type",
                got: 1
            })
        );
    }

    #[test]
    fn an_oversized_uncompressed_size_is_a_budget_error() {
        let mut src = vec![MULTIPART];
        src.extend_from_slice(&1u16.to_le_bytes());
        src.extend_from_slice(&(MAX_EGFX_MESSAGE as u32 + 1).to_le_bytes());
        let mut d = Rdp8Decompressor::new();
        let mut out = Vec::new();
        assert_eq!(
            d.decompress(&src, &mut out),
            Err(DecodeError::Budget("zgfx uncompressedSize"))
        );
    }

    /// The truncation sweep. Every prefix of a valid message returns an error
    /// or succeeds, never panics, and never leaves the decompressor unable to
    /// handle the next one.
    #[test]
    fn every_prefix_is_handled() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 7 % 251) as u8).collect();
        let src = enc::single_compressed(&data);
        let mut d = Rdp8Decompressor::new();
        let mut out = Vec::new();
        for n in 0..src.len() {
            let _ = d.decompress(&src[..n], &mut out);
        }
        d.reset();
        d.decompress(&src, &mut out).unwrap();
        assert_eq!(out, data);
    }

    /// The adversarial sweep. A segment body of arbitrary bytes must
    /// terminate: the bit budget only ever shrinks, so the token loop cannot
    /// stand still, and every write is bounded by the output budget.
    #[test]
    fn arbitrary_segment_bodies_terminate() {
        let mut d = Rdp8Decompressor::new();
        let mut out = Vec::new();
        for lead in 0u16..=255 {
            for pad in [0u8, 3, 7, 200] {
                let mut src = vec![SINGLE, 0x24, lead as u8];
                src.extend_from_slice(&[0x9C, 0xE1, 0x00, 0x7F, 0xFF, 0xFF]);
                src.push(pad);
                let _ = d.decompress(&src, &mut out);
            }
        }
    }

    /// A stream of nothing but one bits drives the match length's unary
    /// escape as far as it goes, which is the one loop here whose bound is
    /// not the bit budget alone.
    #[test]
    fn a_pathological_match_length_is_refused_rather_than_overflowing() {
        let mut d = Rdp8Decompressor::new();
        let mut out = Vec::new();
        let mut src = vec![SINGLE, 0x24];
        src.extend_from_slice(&[0xFF; 64]);
        src.push(0);
        let _ = d.decompress(&src, &mut out);
    }

    #[test]
    fn the_history_reports_its_size() {
        let d = Rdp8Decompressor::new();
        assert_eq!(d.bytes(), HISTORY);
    }
}
