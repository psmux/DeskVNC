//! [`Writer`], the append side of the wire layer (PRDRDP/13 §2.6).

use super::error::{PduError, PduResult};

/// Appends to a caller owned buffer.
///
/// Encoding cannot fail on capacity, only on a value that is not
/// representable, which is [`PduError::Encode`]. The buffer belongs to the
/// caller so the session can encode a whole TPKT into one allocation and hand
/// it to the socket.
///
/// Like [`Reader`](crate::Reader), this is the only place the crate touches
/// endianness: integers go out through `to_le_bytes` and its big endian twin.
#[derive(Debug)]
pub struct Writer<'a> {
    out: &'a mut Vec<u8>,
    /// Index in `out` where this PDU started, so a back patched length prefix
    /// is relative and nesting works.
    start: usize,
}

impl<'a> Writer<'a> {
    /// A writer that appends to `out`, treating the current end as offset
    /// zero of the structure being written.
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        let start = out.len();
        Self { out, start }
    }

    /// Bytes written since this writer was created.
    #[must_use]
    pub fn len(&self) -> usize {
        self.out.len().saturating_sub(self.start)
    }

    /// True when nothing has been written yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append raw bytes.
    pub fn bytes(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    /// Append `n` zero bytes, which is how every reserved and padding field
    /// in RDP is written.
    pub fn zeros(&mut self, n: usize) {
        self.out.resize(self.out.len() + n, 0);
    }

    /// One byte.
    pub fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    /// One signed byte.
    pub fn i8(&mut self, v: i8) {
        self.bytes(&v.to_le_bytes());
    }

    /// A little endian `u16`.
    pub fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }

    /// A little endian `i16`.
    pub fn i16(&mut self, v: i16) {
        self.bytes(&v.to_le_bytes());
    }

    /// A little endian `u32`.
    pub fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }

    /// A little endian `i32`.
    pub fn i32(&mut self, v: i32) {
        self.bytes(&v.to_le_bytes());
    }

    /// A little endian `u64`.
    pub fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }

    /// A big endian `u16`: the TPKT length (MS-RDPBCGR 2.2.1.1), the X.224
    /// fields (X.224 §13) and the fast path length (2.2.9.1.2).
    pub fn be_u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }

    /// A big endian `u32`, for the ASN.1 long form lengths of §3.
    pub fn be_u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }

    /// Pad with zeros until the position is a multiple of `n`, counting from
    /// where this writer started for the reason
    /// [`Reader::align`](crate::Reader::align) gives.
    pub fn align(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let pad = (n - (self.len() % n)) % n;
        self.zeros(pad);
    }

    /// A fixed width UTF-16LE field of exactly `bytes` bytes, NUL terminated
    /// and zero padded.
    ///
    /// Fails with [`PduError::Encode`] when the string plus its terminator
    /// does not fit, rather than truncating: a silently cut host name is an
    /// interop bug that looks like a server problem.
    pub fn utf16_fixed(&mut self, s: &str, bytes: usize, context: &'static str) -> PduResult<()> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let needed = units.len() * 2 + 2;
        if needed > bytes {
            return Err(PduError::Encode {
                context,
                reason: "string does not fit its fixed width field",
            });
        }
        for u in units {
            self.u16(u);
        }
        self.zeros(bytes - (needed - 2));
        Ok(())
    }

    /// A UTF-16LE string with no padding, NUL terminated. Returns the number
    /// of bytes written, which is what the matching `cb*` length field
    /// counts, minus the terminator (MS-RDPBCGR 2.2.1.11.1.1).
    pub fn utf16(&mut self, s: &str) -> usize {
        let before = self.out.len();
        for u in s.encode_utf16() {
            self.u16(u);
        }
        let written = self.out.len() - before;
        self.u16(0);
        written
    }

    /// A fixed width ANSI field, NUL terminated and zero padded, for
    /// `CHANNEL_DEF.name` (MS-RDPBCGR 2.2.1.3.4.1).
    ///
    /// Non ASCII is rejected rather than transliterated. Every channel name
    /// the protocol defines is ASCII, and a name we cannot represent exactly
    /// would be a channel the server never joins.
    pub fn ansi_fixed(&mut self, s: &str, bytes: usize, context: &'static str) -> PduResult<()> {
        if !s.is_ascii() {
            return Err(PduError::Encode {
                context,
                reason: "ANSI field is not ASCII",
            });
        }
        if s.len() + 1 > bytes {
            return Err(PduError::Encode {
                context,
                reason: "string does not fit its fixed width field",
            });
        }
        self.bytes(s.as_bytes());
        self.zeros(bytes - s.len());
        Ok(())
    }

    /// Reserve two bytes for a little endian length, run `f`, then write the
    /// byte count `f` produced back into the reservation.
    ///
    /// `include_self` exists because RDP is inconsistent about it and the
    /// choice has to be visible at every call site. The TPKT length
    /// (2.2.1.1) counts the four header bytes, `TS_UD_HEADER.length`
    /// (2.2.1.3.1) counts its own four, `RDPGFX_HEADER.pduLength`
    /// (MS-RDPEGFX 2.2.1.5) counts its own eight, and
    /// `CHANNEL_PDU_HEADER.length` (2.2.6.1.1) counts the reassembled payload
    /// and not the header. Getting one wrong produces a PDU that a Windows
    /// server accepts from some code paths and drops from others.
    pub fn with_len_u16<F>(
        &mut self,
        include_self: bool,
        context: &'static str,
        f: F,
    ) -> PduResult<()>
    where
        F: FnOnce(&mut Writer<'_>) -> PduResult<()>,
    {
        let (at, body) = self.reserved_body(2, f)?;
        let total = if include_self { body + 2 } else { body };
        let v = u16::try_from(total).map_err(|_| PduError::Encode {
            context,
            reason: "body longer than its u16 length prefix",
        })?;
        self.patch(at, &v.to_le_bytes(), context)
    }

    /// [`Writer::with_len_u16`] with a big endian prefix, which is the TPKT
    /// and X.224 case (MS-RDPBCGR 2.2.1.1).
    pub fn with_len_be_u16<F>(
        &mut self,
        include_self: bool,
        context: &'static str,
        f: F,
    ) -> PduResult<()>
    where
        F: FnOnce(&mut Writer<'_>) -> PduResult<()>,
    {
        let (at, body) = self.reserved_body(2, f)?;
        let total = if include_self { body + 2 } else { body };
        let v = u16::try_from(total).map_err(|_| PduError::Encode {
            context,
            reason: "body longer than its u16 length prefix",
        })?;
        self.patch(at, &v.to_be_bytes(), context)
    }

    /// [`Writer::with_len_u16`] with a four byte little endian prefix:
    /// `CHANNEL_PDU_HEADER.length` (2.2.6.1.1) and `RDPGFX_HEADER.pduLength`
    /// (MS-RDPEGFX 2.2.1.5).
    pub fn with_len_u32<F>(
        &mut self,
        include_self: bool,
        context: &'static str,
        f: F,
    ) -> PduResult<()>
    where
        F: FnOnce(&mut Writer<'_>) -> PduResult<()>,
    {
        let (at, body) = self.reserved_body(4, f)?;
        let total = if include_self { body + 4 } else { body };
        let v = u32::try_from(total).map_err(|_| PduError::Encode {
            context,
            reason: "body longer than its u32 length prefix",
        })?;
        self.patch(at, &v.to_le_bytes(), context)
    }

    /// Reserve `n` bytes, run `f` over a nested writer whose origin is the
    /// first body byte, and report where the reservation is and how long the
    /// body came out.
    fn reserved_body<F>(&mut self, n: usize, f: F) -> PduResult<(usize, usize)>
    where
        F: FnOnce(&mut Writer<'_>) -> PduResult<()>,
    {
        let at = self.out.len();
        self.zeros(n);
        let body_start = self.out.len();
        {
            let mut inner = Writer {
                out: &mut *self.out,
                start: body_start,
            };
            f(&mut inner)?;
        }
        Ok((at, self.out.len() - body_start))
    }

    /// Write `value` over the reservation made at `at`.
    fn patch(&mut self, at: usize, value: &[u8], context: &'static str) -> PduResult<()> {
        let end = at + value.len();
        let Some(dst) = self.out.get_mut(at..end) else {
            // Unreachable: the reservation was made by this writer and
            // nothing shortens the buffer. Reported rather than asserted
            // because a panic in an encoder is still a panic in the session
            // process.
            return Err(PduError::Encode {
                context,
                reason: "length reservation disappeared",
            });
        };
        dst.copy_from_slice(value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    #[test]
    fn integers_go_out_in_the_endianness_the_call_site_asked_for() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.u16(0x0201);
        w.be_u16(0x0304);
        w.u32(0x0807_0605);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn with_len_counts_itself_only_when_asked() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            w.with_len_u16(true, "TS_UD_HEADER", |w| {
                w.u16(0xbeef);
                Ok(())
            })
            .unwrap();
        }
        // Two body bytes plus the two byte prefix.
        assert_eq!(buf, [0x04, 0x00, 0xef, 0xbe]);

        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            w.with_len_u16(false, "CHANNEL_PDU_HEADER", |w| {
                w.u16(0xbeef);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(buf, [0x02, 0x00, 0xef, 0xbe]);
    }

    #[test]
    fn nested_length_prefixes_back_patch_independently() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            w.with_len_be_u16(true, "TPKT", |w| {
                w.with_len_u16(true, "inner", |w| {
                    w.u8(0xaa);
                    Ok(())
                })
            })
            .unwrap();
        }
        // Outer: 2 prefix + 3 inner = 5, big endian. Inner: 2 prefix + 1.
        assert_eq!(buf, [0x00, 0x05, 0x03, 0x00, 0xaa]);
    }

    #[test]
    fn an_oversized_body_is_an_encode_error_and_not_a_wrapped_length() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        let err = w
            .with_len_u16(false, "TS_UD_HEADER", |w| {
                w.zeros(0x1_0000);
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(err, PduError::Encode { .. }));
    }

    #[test]
    fn a_writer_appends_rather_than_owning_the_buffer() {
        let mut buf = vec![0xff];
        {
            let mut w = Writer::new(&mut buf);
            assert!(w.is_empty());
            w.u8(0x01);
            assert_eq!(w.len(), 1);
        }
        assert_eq!(buf, [0xff, 0x01]);
    }

    #[test]
    fn align_counts_from_this_writers_origin() {
        let mut buf = vec![0xff; 3];
        {
            let mut w = Writer::new(&mut buf);
            w.u8(0x01);
            w.align(4);
            assert_eq!(w.len(), 4);
        }
        assert_eq!(buf, [0xff, 0xff, 0xff, 0x01, 0, 0, 0]);
    }

    #[test]
    fn utf16_fixed_pads_to_the_field_width() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.utf16_fixed("hi", 12, "clientName").unwrap();
        assert_eq!(buf, [b'h', 0, b'i', 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn utf16_fixed_refuses_to_truncate() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        assert!(w.utf16_fixed("abcdef", 12, "clientName").is_err());
        // Nothing was written before the check.
        assert!(buf.is_empty());
    }

    #[test]
    fn utf16_reports_the_length_the_cb_field_counts() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        assert_eq!(w.utf16("ab"), 4);
        assert_eq!(buf, [b'a', 0, b'b', 0, 0, 0]);
    }

    #[test]
    fn ansi_fixed_writes_a_channel_name_and_rejects_non_ascii() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            w.ansi_fixed("cliprdr", 8, "CHANNEL_DEF.name").unwrap();
            assert!(w.ansi_fixed("caf\u{e9}", 8, "CHANNEL_DEF.name").is_err());
            assert!(w.ansi_fixed("toolongname", 8, "CHANNEL_DEF.name").is_err());
        }
        assert_eq!(&buf, b"cliprdr\0");
    }
}
