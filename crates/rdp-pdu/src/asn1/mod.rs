//! The three ASN.1 subsets RDP needs, and nothing else.
//!
//! Nobody writes a general ASN.1 parser here and nobody writes a schema
//! compiler. The rule is the one `crates/vnc-transport/src/tls.rs:246`
//! already states for its own DER walk: "A full ASN.1 parser is not a
//! dependency this crate needs, and everything here is bounds-checked against
//! a hostile server." Hand write the walk for the exact grammar the protocol
//! uses, bounds check every step, and test it against bytes from the
//! specification.
//!
//! The scope, stated so it can be reviewed as a whole (PRDRDP/13 §3.1):
//!
//! | Rules | Used for | Specification |
//! |---|---|---|
//! | [`ber`], definite length | MCS Connect Initial and Connect Response | T.125 §7 and §11.1 to §11.4, MS-RDPBCGR 2.2.1.3.1 and 2.2.1.4.1 |
//! | [`per`], ALIGNED variant | GCC Conference Create Request and Response, and the MCS domain PDUs | T.124 §8.7, T.125 §7, X.691 |
//! | [`der`] | TSRequest, TSCredentials, X.509 certificates | MS-CSSP 2.2.1, X.690 |
//!
//! Anything outside that table is a design bug rather than a gap to fill. If
//! a future feature needs more ASN.1, RD Gateway's RPC being the likely one,
//! it gets its own review and not an incremental widening of these modules.

pub mod ber;
pub mod der;
pub mod per;

use crate::io::{PduError, PduResult, Reader, Writer};

/// Identifier octets for the universal types this crate meets (X.690 §8.1.2,
/// low tag number form, so the whole identifier is one octet).
///
/// The constructed bit (0x20) is already set on `SEQUENCE` and `SET` because
/// they are always constructed, which is how they appear on the wire.
pub mod tag {
    /// X.690 §8.2.
    pub const BOOLEAN: u8 = 0x01;
    /// X.690 §8.3.
    pub const INTEGER: u8 = 0x02;
    /// X.690 §8.6.
    pub const BIT_STRING: u8 = 0x03;
    /// X.690 §8.7.
    pub const OCTET_STRING: u8 = 0x04;
    /// X.690 §8.8.
    pub const NULL: u8 = 0x05;
    /// X.690 §8.19.
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    /// X.690 §8.4.
    pub const ENUMERATED: u8 = 0x0a;
    /// Universal 16, constructed (X.690 §8.9).
    pub const SEQUENCE: u8 = 0x30;
    /// Universal 17, constructed (X.690 §8.12).
    pub const SET: u8 = 0x31;
}

/// The identifier octet of a context specific constructed tag `[n]`
/// (X.690 §8.1.2.2: class bits 10, constructed bit set).
///
/// `TSRequest` is six of these, `[0]` through `[5]` (MS-CSSP 2.2.1), and a
/// TBSCertificate's EXPLICIT version tag is `[0]` (RFC 5280 §4.1).
#[must_use]
pub const fn context(n: u8) -> u8 {
    0xa0 | (n & 0x1f)
}

/// The largest definite length this crate will read.
///
/// X.690 §8.1.3.5 allows up to 126 length octets. Four is every length that
/// fits a `u32`, and a structure larger than that is a hostile server rather
/// than a certificate.
const MAX_LEN_OCTETS: usize = 4;

/// Read a definite length in either the short or the long form
/// (X.690 §8.1.3.3 and §8.1.3.5).
///
/// The indefinite form (§8.1.3.6, a `0x80` length octet with an end of
/// contents marker) is rejected. It is legal in BER and T.125 §11.1 permits
/// it, and no MCS server in existence sends it; accepting it would mean
/// carrying an end of contents scan through every nested structure for a case
/// that never arrives.
pub fn read_definite_len(r: &mut Reader<'_>, context: &'static str) -> PduResult<usize> {
    let at = r.offset();
    let first = r.u8(context)?;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > MAX_LEN_OCTETS {
        return Err(PduError::InvalidField {
            context,
            field: "ASN.1 length octets",
            value: first as u64,
            offset: at,
        });
    }
    let mut len: usize = 0;
    for b in r.slice(n, context)? {
        len = (len << 8) | (*b as usize);
    }
    Ok(len)
}

/// Write a definite length in the shortest form (X.690 §8.1.3, and §10.1 for
/// why DER has no choice about it).
///
/// BER permits a longer encoding of the same length and this crate never
/// emits one, so a BER structure we write is also valid DER.
pub fn write_definite_len(w: &mut Writer<'_>, len: usize) {
    if len < 0x80 {
        w.u8(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = bytes.get(first..).unwrap_or(&[]);
    w.u8(0x80 | (significant.len() as u8));
    w.bytes(significant);
}

/// The number of bytes [`write_definite_len`] will write for `len`, so an
/// `Encode::size` implementation can be exact.
#[must_use]
pub const fn definite_len_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len <= 0xff {
        2
    } else if len <= 0xffff {
        3
    } else if len <= 0x00ff_ffff {
        4
    } else {
        5
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    #[test]
    fn context_tags_are_the_ones_ms_cssp_names() {
        // TSRequest's version [0] and clientNonce [5] (MS-CSSP 2.2.1).
        assert_eq!(context(0), 0xa0);
        assert_eq!(context(5), 0xa5);
    }

    #[test]
    fn short_and_long_form_lengths_round_trip() {
        for len in [0usize, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x1_0000] {
            let mut buf = Vec::new();
            write_definite_len(&mut Writer::new(&mut buf), len);
            assert_eq!(buf.len(), definite_len_size(len), "len {len}");
            assert_eq!(read_definite_len(&mut Reader::new(&buf), "t").unwrap(), len);
        }
    }

    /// X.690 §8.1.3.3: a length below 128 is one octet, never a long form.
    #[test]
    fn the_shortest_form_is_used() {
        let mut buf = Vec::new();
        write_definite_len(&mut Writer::new(&mut buf), 0x7f);
        assert_eq!(buf, [0x7f]);
        let mut buf = Vec::new();
        write_definite_len(&mut Writer::new(&mut buf), 0x80);
        assert_eq!(buf, [0x81, 0x80]);
        let mut buf = Vec::new();
        write_definite_len(&mut Writer::new(&mut buf), 0x1_0000);
        assert_eq!(buf, [0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn the_indefinite_form_is_rejected() {
        let err = read_definite_len(&mut Reader::new(&[0x80]), "Connect-Initial").unwrap_err();
        assert!(matches!(err, PduError::InvalidField { .. }));
    }

    #[test]
    fn more_than_four_length_octets_is_rejected() {
        let err = read_definite_len(&mut Reader::new(&[0x85, 1, 1, 1, 1, 1]), "t").unwrap_err();
        assert!(matches!(err, PduError::InvalidField { .. }));
    }

    #[test]
    fn a_length_with_missing_octets_is_truncated_not_a_panic() {
        assert!(read_definite_len(&mut Reader::new(&[0x82, 0x01]), "t").is_err());
        assert!(read_definite_len(&mut Reader::new(&[]), "t").is_err());
    }
}
