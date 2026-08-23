//! [`Reader`], the bounds checked cursor every decoder in this crate uses
//! (PRDRDP/13 §2.4).

use super::error::{PduError, PduResult};

/// A cursor over borrowed bytes that cannot read past the end.
///
/// Cheap to copy (two words plus a base offset), so a decoder hands a sub
/// reader to a nested structure by value. Every fallible method takes a
/// `context` string naming the structure being parsed and returns a
/// [`PduResult`]. There is no `Index` implementation and no method that
/// panics: D11 says a decoder returns a `Result` on every read and never an
/// index, and `#![deny(clippy::indexing_slicing)]` on the crate root makes
/// that mechanical rather than a matter of reviewer attention.
///
/// This is the only type in the crate that touches endianness. Integers are
/// assembled with `u16::from_le_bytes` and friends on a slice whose length
/// was already checked, which is why there is no `byteorder` dependency
/// (PRDRDP/12 §2.2.1).
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Offset of `buf[0]` within the caller's original buffer, so errors
    /// report absolute offsets even inside a nested sub reader.
    base: usize,
}

impl<'a> Reader<'a> {
    /// A reader over a whole buffer, whose first byte is offset zero.
    ///
    /// The session creates one of these per PDU, so the offsets in an error
    /// line up with a hex dump of that PDU.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            base: 0,
        }
    }

    /// A reader over `buf` whose first byte sits at absolute offset `base`.
    ///
    /// Used by [`Reader::take`] and by any caller that has already sliced a
    /// buffer by hand and wants the errors to keep the outer numbering.
    #[must_use]
    pub const fn sub(buf: &'a [u8], base: usize) -> Self {
        Self { buf, pos: 0, base }
    }

    /// Bytes left in this reader.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The absolute offset of the next byte, which is what every error
    /// reports.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.base + self.pos
    }

    /// True when nothing is left.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The next `n` bytes as a borrowed view, advancing past them.
    ///
    /// Every other read goes through this function, so the bound is checked
    /// in one place. The `checked_add` is not decoration: a 32 bit length
    /// field read from a hostile server can be `0xFFFF_FFFF`, and on a 32 bit
    /// target `pos + n` wraps and a plain `end > len` test passes.
    pub fn slice(&mut self, n: usize, context: &'static str) -> PduResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(PduError::Truncated {
            context,
            offset: self.offset(),
            needed: n,
            available: self.remaining(),
        })?;
        if end > self.buf.len() {
            return Err(PduError::Truncated {
                context,
                offset: self.offset(),
                needed: n,
                available: self.remaining(),
            });
        }
        // The only indexing in the crate, three lines after the bound was
        // checked, and the point of the function.
        #[allow(clippy::indexing_slicing)]
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// The next `N` bytes copied into a fixed size array.
    ///
    /// `N` instantiates at about eight distinct values across the crate, which
    /// is the whole of its const generic surface (PRDRDP/13 §10.3).
    pub fn array<const N: usize>(&mut self, context: &'static str) -> PduResult<[u8; N]> {
        let s = self.slice(N, context)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    /// A bounded sub reader over the next `n` bytes.
    ///
    /// The outer reader advances past the whole body, so a nested decoder
    /// that reads too little cannot desync the outer stream, and the sub
    /// reader's buffer ends at the body, so a nested decoder that reads too
    /// much cannot reach the next structure. That is the property
    /// `crates/vnc-core/src/encodings/mod.rs` protects by discipline in its
    /// `unknown_negative_encoding_is_unsupported` test, obtained here by
    /// construction (PRDRDP/13 §2.5).
    pub fn take(&mut self, n: usize, context: &'static str) -> PduResult<Reader<'a>> {
        let base = self.offset();
        let body = self.slice(n, context)?;
        Ok(Reader::sub(body, base))
    }

    /// Everything left, consuming it. Cannot fail; the empty case is a zero
    /// length slice.
    pub fn rest(&mut self) -> &'a [u8] {
        let n = self.remaining();
        // `n` is exactly what is left, so this cannot fail.
        self.slice(n, "rest").unwrap_or(&[])
    }

    /// The next byte without advancing.
    pub fn peek_u8(&self, context: &'static str) -> PduResult<u8> {
        let mut probe = *self;
        probe.u8(context)
    }

    /// One byte.
    pub fn u8(&mut self, context: &'static str) -> PduResult<u8> {
        Ok(u8::from_le_bytes(self.array::<1>(context)?))
    }

    /// One signed byte.
    pub fn i8(&mut self, context: &'static str) -> PduResult<i8> {
        Ok(i8::from_le_bytes(self.array::<1>(context)?))
    }

    /// A little endian `u16`, which is nearly every length in RDP.
    pub fn u16(&mut self, context: &'static str) -> PduResult<u16> {
        Ok(u16::from_le_bytes(self.array::<2>(context)?))
    }

    /// A little endian `i16`, for the signed coordinates of an order or a
    /// pointer hotspot.
    pub fn i16(&mut self, context: &'static str) -> PduResult<i16> {
        Ok(i16::from_le_bytes(self.array::<2>(context)?))
    }

    /// A little endian `u32`.
    pub fn u32(&mut self, context: &'static str) -> PduResult<u32> {
        Ok(u32::from_le_bytes(self.array::<4>(context)?))
    }

    /// A little endian `i32`, for the time zone biases of
    /// `TS_TIME_ZONE_INFORMATION` (MS-RDPBCGR 2.2.1.11.1.1.1), which the
    /// specification documents as unsigned and which are signed. PRDRDP/11
    /// §5.3 carries that erratum.
    pub fn i32(&mut self, context: &'static str) -> PduResult<i32> {
        Ok(i32::from_le_bytes(self.array::<4>(context)?))
    }

    /// A little endian `u64`.
    pub fn u64(&mut self, context: &'static str) -> PduResult<u64> {
        Ok(u64::from_le_bytes(self.array::<8>(context)?))
    }

    /// A big endian `u16`. The exceptions to RDP's little endian rule are the
    /// TPKT length (MS-RDPBCGR 2.2.1.1), the X.224 fields (X.224 §13) and the
    /// fast path length (2.2.9.1.2), and each call site says which it is.
    pub fn be_u16(&mut self, context: &'static str) -> PduResult<u16> {
        Ok(u16::from_be_bytes(self.array::<2>(context)?))
    }

    /// A big endian `u32`, for the ASN.1 long form lengths of §3.
    pub fn be_u32(&mut self, context: &'static str) -> PduResult<u32> {
        Ok(u32::from_be_bytes(self.array::<4>(context)?))
    }

    /// Discard `n` bytes.
    pub fn skip(&mut self, n: usize, context: &'static str) -> PduResult<()> {
        self.slice(n, context)?;
        Ok(())
    }

    /// Discard bytes until the position is a multiple of `n`.
    ///
    /// The origin is the start of this reader's own buffer, not the outer
    /// frame, because aligned PER counts from the start of the PER encoding
    /// (X.691 §10.1) and the caller hands a PER decoder a sub reader created
    /// by [`Reader::take`] that begins exactly there.
    pub fn align(&mut self, n: usize, context: &'static str) -> PduResult<()> {
        if n == 0 {
            return Ok(());
        }
        let pad = (n - (self.pos % n)) % n;
        self.skip(pad, context)
    }

    /// Reject anything left over.
    ///
    /// This is the "exact" half of the trailing byte rule (PRDRDP/13 §2.5).
    /// A fixed structure with a leftover byte means we mis-parsed it, so it is
    /// an error. Extensible structures such as `TS_UD_CS_CORE` do the
    /// opposite and never call this, because the specification says a client
    /// must tolerate a longer block from a newer server.
    pub fn expect_empty(&self, context: &'static str) -> PduResult<()> {
        if self.is_empty() {
            return Ok(());
        }
        Err(PduError::LengthMismatch {
            context,
            declared: self.pos,
            actual: self.buf.len(),
            offset: self.offset(),
        })
    }

    /// Reject a declared length that is larger than a cap from
    /// [`limits`](crate::io::limits), naming the constant that rejected it.
    pub fn ensure_cap(
        &self,
        declared: usize,
        cap: usize,
        limit_name: &'static str,
        context: &'static str,
    ) -> PduResult<()> {
        if declared > cap {
            return Err(PduError::CapExceeded {
                context,
                declared,
                cap,
                limit_name,
                offset: self.offset(),
            });
        }
        Ok(())
    }

    /// A fixed width UTF-16LE field, decoded up to the first NUL unit.
    ///
    /// The field is always `bytes` long on the wire whatever the string's
    /// length, which is how `TS_UD_CS_CORE.clientName` (MS-RDPBCGR 2.2.1.3.2,
    /// 32 bytes) and the redirection strings are laid out.
    ///
    /// Decoding is lossy: an unpaired surrogate becomes U+FFFD rather than an
    /// error, and control characters are dropped. A server can put anything in
    /// these fields and they end up in a prompt, which is the same treatment
    /// `crates/vnc-transport/src/tls.rs:377` gives a certificate's subject CN.
    pub fn utf16_fixed(&mut self, bytes: usize, context: &'static str) -> PduResult<String> {
        let at = self.offset();
        let raw = self.slice(bytes, context)?;
        decode_utf16_lossy(raw, true, context, at)
    }

    /// A UTF-16LE field whose byte length was read from an earlier field.
    ///
    /// A single trailing NUL unit is dropped if it is there. The length
    /// fields of `TS_INFO_PACKET` (MS-RDPBCGR 2.2.1.11.1.1) exclude the
    /// mandatory terminator while the field on the wire includes it, so the
    /// caller adds two and this drops it again.
    pub fn utf16_len(&mut self, bytes: usize, context: &'static str) -> PduResult<String> {
        let at = self.offset();
        let raw = self.slice(bytes, context)?;
        decode_utf16_lossy(raw, false, context, at)
    }

    /// A fixed width ANSI field, decoded up to the first NUL byte.
    ///
    /// `CHANNEL_DEF.name` (MS-RDPBCGR 2.2.1.3.4.1) is eight of these bytes
    /// holding at most seven characters and a terminator. Lossy and control
    /// stripped for the same reason as [`Reader::utf16_fixed`].
    pub fn ansi_fixed(&mut self, bytes: usize, context: &'static str) -> PduResult<String> {
        let raw = self.slice(bytes, context)?;
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        let text = raw.get(..end).unwrap_or(&[]);
        Ok(String::from_utf8_lossy(text)
            .chars()
            .filter(|c| !c.is_control())
            .collect())
    }
}

/// Decode UTF-16LE, stopping at the first NUL unit when `nul_terminated`, and
/// dropping one trailing NUL unit otherwise.
fn decode_utf16_lossy(
    raw: &[u8],
    nul_terminated: bool,
    context: &'static str,
    offset: usize,
) -> PduResult<String> {
    if raw.len() % 2 != 0 {
        return Err(PduError::InvalidField {
            context,
            field: "UTF-16 field length",
            value: raw.len() as u64,
            offset,
        });
    }
    let units = raw.chunks_exact(2).map(|c| match c {
        [lo, hi] => u16::from_le_bytes([*lo, *hi]),
        // `chunks_exact(2)` yields nothing else; the arm keeps the match
        // total without an `unwrap`.
        _ => 0,
    });
    let mut out = String::with_capacity(raw.len() / 2);
    let mut collected: Vec<u16> = Vec::with_capacity(raw.len() / 2);
    for u in units {
        if u == 0 && nul_terminated {
            break;
        }
        collected.push(u);
    }
    if !nul_terminated {
        while collected.last() == Some(&0) {
            collected.pop();
        }
    }
    for c in char::decode_utf16(collected).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)) {
        if !c.is_control() {
            out.push(c);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    #[test]
    fn integers_are_little_endian_except_where_they_are_not() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(r.u16("t").unwrap(), 0x0201);
        assert_eq!(r.be_u16("t").unwrap(), 0x0304);
        assert_eq!(r.u8("t").unwrap(), 0x05);
        assert_eq!(r.i8("t").unwrap(), 0x06);
        assert!(r.is_empty());
    }

    #[test]
    fn signed_reads_sign_extend() {
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(r.i16("t").unwrap(), -1);
        assert_eq!(r.i32("t").unwrap(), -1);
    }

    #[test]
    fn a_short_read_reports_the_offset_and_what_it_wanted() {
        let mut r = Reader::new(&[0x00, 0x01, 0x02]);
        r.skip(2, "t").unwrap();
        let err = r.u32("TS_UD_CS_CORE").unwrap_err();
        assert_eq!(
            err,
            PduError::Truncated {
                context: "TS_UD_CS_CORE",
                offset: 2,
                needed: 4,
                available: 1,
            }
        );
    }

    /// The wrap that a plain `pos + n > len` test misses on a 32 bit target.
    #[test]
    fn a_huge_length_does_not_wrap_the_bound_check() {
        let mut r = Reader::new(&[0u8; 8]);
        r.skip(4, "t").unwrap();
        assert!(r.slice(usize::MAX, "hostile").is_err());
        assert!(r.slice(usize::MAX - 3, "hostile").is_err());
        // The failed reads did not move the cursor.
        assert_eq!(r.remaining(), 4);
    }

    #[test]
    fn a_sub_reader_keeps_the_outer_offsets_and_cannot_over_read() {
        let buf: Vec<u8> = (0u8..16).collect();
        let mut outer = Reader::new(&buf);
        outer.skip(4, "t").unwrap();
        let mut body = outer.take(4, "body").unwrap();
        assert_eq!(body.offset(), 4);
        assert_eq!(body.remaining(), 4);
        assert_eq!(body.u32("t").unwrap(), 0x0706_0504);
        // The nested decoder cannot reach the next structure.
        assert!(body.u8("t").is_err());
        // The outer reader advanced past the whole body however wrong the
        // nested decoder's own arithmetic was.
        assert_eq!(outer.offset(), 8);
    }

    #[test]
    fn take_reports_truncation_rather_than_clamping() {
        let mut r = Reader::new(&[0u8; 4]);
        let err = r.take(8, "TS_UD_HEADER").unwrap_err();
        assert!(matches!(err, PduError::Truncated { needed: 8, .. }));
    }

    #[test]
    fn expect_empty_is_the_exact_half_of_the_tail_rule() {
        let mut r = Reader::new(&[0x01, 0x02]);
        r.u8("t").unwrap();
        assert!(r.expect_empty("LICENSE_PREAMBLE").is_err());
        r.u8("t").unwrap();
        assert!(r.expect_empty("LICENSE_PREAMBLE").is_ok());
    }

    #[test]
    fn align_counts_from_the_start_of_this_readers_buffer() {
        let buf = [0u8; 8];
        let mut r = Reader::sub(&buf, 3);
        r.u8("t").unwrap();
        r.align(4, "PER padding").unwrap();
        assert_eq!(r.remaining(), 4);
        // Absolute offset 7, position 4: the padding followed the reader's own
        // origin and not the frame's.
        assert_eq!(r.offset(), 7);
        r.align(4, "PER padding").unwrap();
        assert_eq!(r.remaining(), 4);
    }

    #[test]
    fn peek_does_not_advance() {
        let r = Reader::new(&[0xaa, 0xbb]);
        assert_eq!(r.peek_u8("t").unwrap(), 0xaa);
        assert_eq!(r.remaining(), 2);
        assert!(Reader::new(&[]).peek_u8("t").is_err());
    }

    #[test]
    fn rest_consumes_everything_and_never_fails() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.rest(), &[1, 2, 3]);
        assert_eq!(r.rest(), &[] as &[u8]);
    }

    #[test]
    fn ensure_cap_names_the_constant() {
        let r = Reader::new(&[]);
        let err = r
            .ensure_cap(100, 31, "MAX_CHANNELS", "TS_UD_CS_NET")
            .unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_CHANNELS",
                ..
            }
        ));
        assert!(r.ensure_cap(31, 31, "MAX_CHANNELS", "TS_UD_CS_NET").is_ok());
    }

    #[test]
    fn utf16_fixed_stops_at_the_nul_and_consumes_the_whole_field() {
        // "hi" then a terminator then trailing padding, 32 bytes as
        // TS_UD_CS_CORE.clientName is laid out.
        let mut raw = vec![b'h', 0, b'i', 0, 0, 0];
        raw.resize(32, 0);
        let mut r = Reader::new(&raw);
        assert_eq!(r.utf16_fixed(32, "clientName").unwrap(), "hi");
        assert!(r.is_empty());
    }

    #[test]
    fn utf16_len_drops_the_terminator_the_length_field_excluded() {
        let raw = [b'a', 0, b'b', 0, 0, 0];
        let mut r = Reader::new(&raw);
        assert_eq!(r.utf16_len(6, "UserName").unwrap(), "ab");
    }

    #[test]
    fn an_odd_utf16_length_is_an_invalid_field_not_a_panic() {
        let raw = [b'a', 0, b'b'];
        let mut r = Reader::new(&raw);
        assert!(matches!(
            r.utf16_len(3, "UserName").unwrap_err(),
            PduError::InvalidField { .. }
        ));
    }

    #[test]
    fn an_unpaired_surrogate_becomes_the_replacement_character() {
        // 0xD800 with no low surrogate following it.
        let raw = [0x00, 0xd8, b'x', 0x00];
        let mut r = Reader::new(&raw);
        assert_eq!(r.utf16_len(4, "clientName").unwrap(), "\u{fffd}x");
    }

    #[test]
    fn ansi_fixed_reads_a_channel_name() {
        let raw = *b"cliprdr\0";
        let mut r = Reader::new(&raw);
        assert_eq!(r.ansi_fixed(8, "CHANNEL_DEF.name").unwrap(), "cliprdr");
        assert!(r.is_empty());
    }

    /// Truncating at every offset must return an error and never panic, which
    /// is the reader's own half of PRDRDP/13 §9.3.
    #[test]
    fn every_read_on_every_prefix_errors_without_panicking() {
        let buf: Vec<u8> = (0u8..12).collect();
        for cut in 0..buf.len() {
            let prefix = &buf[..cut];
            let mut r = Reader::new(prefix);
            let _ = r.u64("t");
            let mut r = Reader::new(prefix);
            let _ = r.utf16_fixed(12, "t");
            let mut r = Reader::new(prefix);
            let _ = r.take(12, "t");
            let mut r = Reader::new(prefix);
            let _ = r.array::<8>("t");
        }
    }
}
