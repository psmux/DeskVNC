//! A bounds checked cursor over a codec payload (PRDRDP/04 §4.1 rule one).
//!
//! PRDRDP/04 §4.1 places this type in `rdp-pdu` and has `rdp-codecs`
//! re-export it. That contradicts the manifest in PRDRDP/12 §2.2.2, which
//! forbids the dependency outright, so the reader lives here and `rdp-pdu`
//! keeps its own. The duplication is thirty lines and the alternative is a
//! dependency edge the codec payload boundary exists to prevent. Reported to
//! the owner.

use crate::DecodeError;

/// A forward only cursor whose every method returns `Result`.
///
/// The `what` label is fixed at construction and names the bitstream in the
/// error, so a truncation reads as "input truncated in interleaved rle"
/// rather than as an unattributed index panic.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    /// Wrap a payload. `what` names the bitstream for error messages.
    pub fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, pos: 0, what }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// True once the payload is fully consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(DecodeError::Truncated { what: self.what })?;
        self.pos += 1;
        Ok(b)
    }

    /// Two bytes, little endian. Every length field in the RDP codec set is
    /// little endian (MS-RDPBCGR 2.2.9.1.1.3.1.2.4, MS-RDPEGDI 2.2.2.5.1).
    pub fn u16_le(&mut self) -> Result<u16, DecodeError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Four bytes, little endian.
    pub fn u32_le(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// `n` bytes as a borrow into the payload. This is the zero copy read
    /// (D9): a colour image order hands the returned slice straight to
    /// `copy_from_slice` and never builds an intermediate `Vec`.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DecodeError::Truncated { what: self.what })?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated { what: self.what })?;
        self.pos = end;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_in_order_and_then_reports_truncation() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05], "test");
        assert_eq!(r.u8().unwrap(), 0x01);
        assert_eq!(r.u16_le().unwrap(), 0x0302);
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.take(2).unwrap(), &[0x04, 0x05]);
        assert!(r.is_empty());
        assert_eq!(r.u8(), Err(DecodeError::Truncated { what: "test" }));
    }

    #[test]
    fn oversized_take_errors_rather_than_overflowing() {
        let mut r = Reader::new(&[0x01], "test");
        assert!(r.take(usize::MAX).is_err());
        assert!(r.take(2).is_err());
        // A failed read must not consume.
        assert_eq!(r.remaining(), 1);
    }
}
