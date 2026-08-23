//! BER with definite lengths, the subset MCS uses (PRDRDP/13 §3.2).
//!
//! MCS Connect Initial and Connect Response are BER encoded: T.125 §7 gives
//! the ASN.1 and §11 the encoding requirements, and MS-RDPBCGR 2.2.1.3.1 and
//! 2.2.1.4.1 wrap them. Six tag types, two length forms and one nesting level
//! below `SEQUENCE` is the whole of it.
//!
//! Why this is not the DER walker in [`super::der`]: MCS mixes the two
//! identifier forms in one structure. `Connect-Initial ::= [APPLICATION 101]
//! IMPLICIT SEQUENCE` needs the high tag number form of X.690 §8.1.2.4 and
//! encodes as `7F 65`, while `DomainParameters ::= [APPLICATION 30]` fits the
//! low tag number form and encodes as the single octet `7E`. The DER walker
//! rejects every high tag number form on purpose
//! (`crates/vnc-transport/src/tls.rs:264`, "Multi-byte tags are not used
//! anywhere on our path"), so MCS gets its own reader rather than a widened
//! shared one.

use super::{read_definite_len, tag, write_definite_len};
use crate::io::{PduError, PduResult, Reader, Writer};

/// An identifier, in the only two forms MCS uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerTag {
    /// Low tag number form: the whole identifier is one octet, tag number in
    /// the low five bits (X.690 §8.1.2.2).
    Low(u8),
    /// High tag number form, application class and constructed: the two
    /// octets `7F n` with `n < 0x80` (X.690 §8.1.2.4). Three octet and longer
    /// forms are rejected, because MCS has none.
    HighApplication(u8),
}

impl BerTag {
    /// `BOOLEAN` (X.690 §8.2).
    pub const BOOLEAN: Self = Self::Low(tag::BOOLEAN);
    /// `INTEGER` (X.690 §8.3).
    pub const INTEGER: Self = Self::Low(tag::INTEGER);
    /// `OCTET STRING` (X.690 §8.7).
    pub const OCTET_STRING: Self = Self::Low(tag::OCTET_STRING);
    /// `ENUMERATED` (X.690 §8.4).
    pub const ENUMERATED: Self = Self::Low(tag::ENUMERATED);
    /// `SEQUENCE` (X.690 §8.9).
    pub const SEQUENCE: Self = Self::Low(tag::SEQUENCE);
    /// `Connect-Initial ::= [APPLICATION 101] IMPLICIT SEQUENCE`, the two
    /// octets `7F 65` (T.125 §7).
    pub const CONNECT_INITIAL: Self = Self::HighApplication(101);
    /// `Connect-Response ::= [APPLICATION 102] IMPLICIT SEQUENCE`, `7F 66`
    /// (T.125 §7).
    pub const CONNECT_RESPONSE: Self = Self::HighApplication(102);
    /// `DomainParameters ::= [APPLICATION 30] IMPLICIT SEQUENCE`, the single
    /// octet `7E` because 30 fits in five bits (T.125 §7).
    pub const DOMAIN_PARAMETERS: Self = Self::Low(0x7e);

    /// The identifier octets, for an error message and for
    /// [`write_tag_len`].
    fn octets(self) -> [u8; 2] {
        match self {
            Self::Low(t) => [t, 0],
            Self::HighApplication(n) => [0x7f, n],
        }
    }

    /// How many octets the identifier occupies.
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            Self::Low(_) => 1,
            Self::HighApplication(_) => 2,
        }
    }
}

/// A parsed element: the tag, the content, and the full element including its
/// header.
///
/// `full` is what a caller hashes or forwards verbatim; `content` is what it
/// parses. Same three fields as the DER walker's `Tlv`
/// (`crates/vnc-transport/src/tls.rs:251`), which is deliberate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerTlv<'a> {
    /// The identifier.
    pub tag: BerTag,
    /// The content octets.
    pub content: &'a [u8],
    /// The identifier, length and content octets together.
    pub full: &'a [u8],
}

/// Read one element, advancing past it.
pub fn read_tlv<'a>(r: &mut Reader<'a>, context: &'static str) -> PduResult<BerTlv<'a>> {
    // A copy of the cursor at the identifier, so `full` can be re-sliced once
    // the length is known. `Reader` is `Copy` for exactly this.
    let start = *r;
    let at = r.offset();
    let first = r.u8(context)?;
    let parsed = if first & 0x1f == 0x1f {
        if first != 0x7f {
            return Err(PduError::Unsupported {
                context,
                kind: "ASN.1 high tag number class",
                value: first as u64,
                offset: at,
            });
        }
        let n = r.u8(context)?;
        if n & 0x80 != 0 {
            return Err(PduError::Unsupported {
                context,
                kind: "ASN.1 tag number wider than one octet",
                value: n as u64,
                offset: at,
            });
        }
        BerTag::HighApplication(n)
    } else {
        BerTag::Low(first)
    };
    let len = read_definite_len(r, context)?;
    let content = r.slice(len, context)?;
    let consumed = r.offset() - at;
    let full = {
        let mut from_start = start;
        from_start.slice(consumed, context)?
    };
    Ok(BerTlv {
        tag: parsed,
        content,
        full,
    })
}

/// Read one element, check its tag, and return a bounded sub reader over its
/// content.
///
/// The sub reader is the same `take` pattern as PRDRDP/13 §2.5, so a nested
/// `DomainParameters` cannot read past its own `SEQUENCE` however wrong its
/// own arithmetic is.
pub fn expect<'a>(
    r: &mut Reader<'a>,
    expected: BerTag,
    context: &'static str,
) -> PduResult<Reader<'a>> {
    let at = r.offset();
    let tlv = read_tlv(r, context)?;
    if tlv.tag != expected {
        let want = expected.octets();
        let found = tlv.tag.octets();
        return Err(PduError::Asn1Tag {
            context,
            expected: want.first().copied().unwrap_or(0),
            found: found.first().copied().unwrap_or(0),
            offset: at,
        });
    }
    let content_start = r.offset() - tlv.content.len();
    Ok(Reader::sub(tlv.content, content_start))
}

/// Read an `INTEGER` as a `u32`.
///
/// Every integer MCS carries is small and unsigned: `maxChannelIds`,
/// `maxMCSPDUsize`, `protocolVersion`, `calledConnectId` (T.125 §7). A
/// negative value or one wider than `u32` is a malformed PDU rather than a
/// value we could act on, so both are [`PduError::InvalidField`].
pub fn read_u32(r: &mut Reader<'_>, context: &'static str) -> PduResult<u32> {
    read_integer_content(r, BerTag::INTEGER, context)
}

/// Read an `ENUMERATED` as a `u32`. `Result ::= ENUMERATED` in the Connect
/// Response is the one that matters (T.125 §7).
pub fn read_enumerated(r: &mut Reader<'_>, context: &'static str) -> PduResult<u32> {
    read_integer_content(r, BerTag::ENUMERATED, context)
}

/// Read a `BOOLEAN`. Any nonzero content octet is true, per X.690 §8.2.2 as
/// BER states it. DER's "0xFF only" rule (X.690 §11.1) does not apply here.
pub fn read_bool(r: &mut Reader<'_>, context: &'static str) -> PduResult<bool> {
    let at = r.offset();
    let mut content = expect(r, BerTag::BOOLEAN, context)?;
    if content.remaining() != 1 {
        return Err(PduError::InvalidField {
            context,
            field: "BOOLEAN length",
            value: content.remaining() as u64,
            offset: at,
        });
    }
    Ok(content.u8(context)? != 0)
}

/// Read an `OCTET STRING` as a borrowed view. Zero copy: this is how the GCC
/// user data reaches [`super::per`] without a copy.
pub fn read_octet_string<'a>(r: &mut Reader<'a>, context: &'static str) -> PduResult<&'a [u8]> {
    let mut content = expect(r, BerTag::OCTET_STRING, context)?;
    Ok(content.rest())
}

fn read_integer_content(
    r: &mut Reader<'_>,
    expected: BerTag,
    context: &'static str,
) -> PduResult<u32> {
    let at = r.offset();
    let mut content = expect(r, expected, context)?;
    let raw = content.rest();
    // X.690 §8.3.1: at least one content octet, and the value is two's
    // complement, so a leading bit set means negative.
    let (first, rest) = raw.split_first().ok_or(PduError::InvalidField {
        context,
        field: "INTEGER length",
        value: 0,
        offset: at,
    })?;
    let (significant, negative) = if *first == 0 {
        (rest, false)
    } else {
        (raw, *first & 0x80 != 0)
    };
    if negative || significant.len() > 4 {
        return Err(PduError::InvalidField {
            context,
            field: "INTEGER value",
            value: raw.len() as u64,
            offset: at,
        });
    }
    let mut v: u32 = 0;
    for b in significant {
        v = (v << 8) | u32::from(*b);
    }
    Ok(v)
}

/// Write an identifier and a definite length in the shortest form.
pub fn write_tag_len(w: &mut Writer<'_>, tag: BerTag, len: usize) {
    match tag {
        BerTag::Low(t) => w.u8(t),
        BerTag::HighApplication(n) => {
            w.u8(0x7f);
            w.u8(n);
        }
    }
    write_definite_len(w, len);
}

/// Write an `INTEGER` with the given tag, in the minimum number of octets and
/// with a leading zero when the top bit would otherwise make it negative.
///
/// That leading zero is not pedantry. A Connect Initial with `maxMCSPDUsize =
/// 0xFFFF` encoded as `02 02 FF FF` is the integer -1, and servers reject it;
/// `02 03 00 FF FF` is what every working client sends (T.125 §7 with X.690
/// §8.3.2).
pub fn write_u32(w: &mut Writer<'_>, tag: BerTag, value: u32) {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    let mut significant = bytes.get(first..).unwrap_or(&[0]);
    if significant.is_empty() {
        significant = &[0];
    }
    let needs_pad = significant.first().is_some_and(|b| *b & 0x80 != 0);
    write_tag_len(w, tag, significant.len() + usize::from(needs_pad));
    if needs_pad {
        w.u8(0);
    }
    w.bytes(significant);
}

/// Write a `BOOLEAN`. `0xFF` for true, which is what T.125 encoders emit and
/// what DER would require anyway (X.690 §11.1).
pub fn write_bool(w: &mut Writer<'_>, value: bool) {
    write_tag_len(w, BerTag::BOOLEAN, 1);
    w.u8(if value { 0xff } else { 0x00 });
}

/// Write an `OCTET STRING`.
pub fn write_octet_string(w: &mut Writer<'_>, content: &[u8]) {
    write_tag_len(w, BerTag::OCTET_STRING, content.len());
    w.bytes(content);
}

/// Write a constructed element whose length is not known until its body has
/// been written.
///
/// The body goes into a scratch buffer, gets measured, and is then copied in
/// behind its header. BER length octets are variable width, so there is no
/// reservation to back patch the way [`Writer::with_len_u16`] does. The
/// structures this is used for are built once per connection and are at most
/// three levels deep, so the copy is not a path worth optimising (PRDRDP/13
/// §3.4 makes the same call for DER).
pub fn write_nested<F>(w: &mut Writer<'_>, tag: BerTag, f: F) -> PduResult<()>
where
    F: FnOnce(&mut Writer<'_>) -> PduResult<()>,
{
    let mut scratch = Vec::new();
    {
        let mut inner = Writer::new(&mut scratch);
        f(&mut inner)?;
    }
    write_tag_len(w, tag, scratch.len());
    w.bytes(&scratch);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// The `DomainParameters` of a real Connect Initial (T.125 §7): maxChannelIds
    /// 34, maxUserIds 2, maxTokenIds 0, numPriorities 1, minThroughput 0,
    /// maxHeight 1, maxMCSPDUsize 65535, protocolVersion 2. This is the target
    /// parameter set every mstsc sends (MS-RDPBCGR 2.2.1.3.1).
    const DOMAIN_PARAMETERS: &[u8] = &[
        0x7e, 0x1a, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02,
        0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff, 0xff, 0x02, 0x01, 0x02,
    ];

    #[test]
    fn reads_the_target_domain_parameters() {
        let mut r = Reader::new(DOMAIN_PARAMETERS);
        let mut body = expect(&mut r, BerTag::DOMAIN_PARAMETERS, "DomainParameters").unwrap();
        assert!(r.is_empty());
        let values: Vec<u32> = (0..8)
            .map(|_| read_u32(&mut body, "DomainParameters").unwrap())
            .collect();
        assert_eq!(values, [34, 2, 0, 1, 0, 1, 65535, 2]);
        assert!(body.is_empty());
    }

    /// `maxMCSPDUsize` is the field that proves the leading zero rule: the
    /// specification's own value needs three content octets.
    #[test]
    fn integers_round_trip_with_the_leading_zero_rule() {
        for (value, expected) in [
            (0u32, vec![0x02, 0x01, 0x00]),
            (2, vec![0x02, 0x01, 0x02]),
            (0x7f, vec![0x02, 0x01, 0x7f]),
            (0x80, vec![0x02, 0x02, 0x00, 0x80]),
            (0xffff, vec![0x02, 0x03, 0x00, 0xff, 0xff]),
            (0x0100, vec![0x02, 0x02, 0x01, 0x00]),
            (0xffff_ffff, vec![0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff]),
        ] {
            let mut buf = Vec::new();
            write_u32(&mut Writer::new(&mut buf), BerTag::INTEGER, value);
            assert_eq!(buf, expected, "value {value:#x}");
            assert_eq!(read_u32(&mut Reader::new(&buf), "t").unwrap(), value);
        }
    }

    #[test]
    fn the_two_octet_application_tag_round_trips() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            write_nested(&mut w, BerTag::CONNECT_INITIAL, |w| {
                write_u32(w, BerTag::INTEGER, 1);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(buf, [0x7f, 0x65, 0x03, 0x02, 0x01, 0x01]);
        let mut r = Reader::new(&buf);
        let mut body = expect(&mut r, BerTag::CONNECT_INITIAL, "Connect-Initial").unwrap();
        assert_eq!(read_u32(&mut body, "t").unwrap(), 1);
    }

    #[test]
    fn full_covers_the_header_and_the_content() {
        let mut r = Reader::new(DOMAIN_PARAMETERS);
        let tlv = read_tlv(&mut r, "DomainParameters").unwrap();
        assert_eq!(tlv.full, DOMAIN_PARAMETERS);
        assert_eq!(tlv.content.len(), DOMAIN_PARAMETERS.len() - 2);
        assert_eq!(tlv.tag, BerTag::DOMAIN_PARAMETERS);
    }

    #[test]
    fn a_wrong_tag_is_an_asn1_tag_error_naming_the_offset() {
        let mut r = Reader::new(&[0x30, 0x00]);
        let err = expect(&mut r, BerTag::CONNECT_INITIAL, "Connect-Initial").unwrap_err();
        assert!(matches!(
            err,
            PduError::Asn1Tag {
                found: 0x30,
                offset: 0,
                ..
            }
        ));
    }

    /// A three octet identifier is not something MCS ever sends, and guessing
    /// at one would be a parser for a grammar we have not reviewed.
    #[test]
    fn tags_wider_than_two_octets_are_unsupported() {
        let mut r = Reader::new(&[0x7f, 0x81, 0x01, 0x00]);
        assert!(matches!(
            read_tlv(&mut r, "t").unwrap_err(),
            PduError::Unsupported { .. }
        ));
        // A universal class high tag number form is equally out of scope.
        let mut r = Reader::new(&[0x1f, 0x01, 0x00]);
        assert!(matches!(
            read_tlv(&mut r, "t").unwrap_err(),
            PduError::Unsupported { .. }
        ));
    }

    #[test]
    fn a_negative_or_oversized_integer_is_rejected() {
        // -1 as a two's complement INTEGER.
        assert!(read_u32(&mut Reader::new(&[0x02, 0x01, 0xff]), "t").is_err());
        // Five significant octets does not fit a u32.
        assert!(read_u32(&mut Reader::new(&[0x02, 0x05, 0x01, 0, 0, 0, 0]), "t").is_err());
        // Zero content octets is malformed (X.690 §8.3.1).
        assert!(read_u32(&mut Reader::new(&[0x02, 0x00]), "t").is_err());
    }

    #[test]
    fn booleans_and_octet_strings_round_trip() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            write_bool(&mut w, true);
            write_octet_string(&mut w, b"Duca");
        }
        let mut r = Reader::new(&buf);
        assert!(read_bool(&mut r, "t").unwrap());
        assert_eq!(read_octet_string(&mut r, "t").unwrap(), b"Duca");
        assert!(r.is_empty());
        // BER, not DER: any nonzero octet is true (X.690 §8.2.2).
        assert!(read_bool(&mut Reader::new(&[0x01, 0x01, 0x01]), "t").unwrap());
        assert!(!read_bool(&mut Reader::new(&[0x01, 0x01, 0x00]), "t").unwrap());
    }

    #[test]
    fn a_nested_element_cannot_read_past_its_own_sequence() {
        // A SEQUENCE holding one INTEGER, followed by a byte that belongs to
        // the next structure.
        let buf = [0x30, 0x03, 0x02, 0x01, 0x07, 0xff];
        let mut r = Reader::new(&buf);
        let mut body = expect(&mut r, BerTag::SEQUENCE, "SEQUENCE").unwrap();
        assert_eq!(read_u32(&mut body, "t").unwrap(), 7);
        assert!(body.is_empty());
        assert!(read_u32(&mut body, "t").is_err());
        assert_eq!(r.remaining(), 1);
    }

    /// PRDRDP/13 §9.3 for this module: every prefix of a valid element must
    /// error rather than panic, and must not decode short.
    #[test]
    fn every_prefix_of_the_domain_parameters_errors() {
        for cut in 0..DOMAIN_PARAMETERS.len() {
            let mut r = Reader::new(&DOMAIN_PARAMETERS[..cut]);
            assert!(
                expect(&mut r, BerTag::DOMAIN_PARAMETERS, "DomainParameters").is_err(),
                "prefix of {cut} bytes decoded"
            );
        }
    }
}
