//! Aligned PER, the subset GCC and the MCS domain PDUs use (PRDRDP/13 §3.3).
//!
//! T.124 §8.7 says GCC PDUs use the ALIGNED variant of PER (X.691), and the
//! `DomainMCSPDU` CHOICE of T.125 §7 is encoded the same way. Every
//! production below is constrained, none of the types we touch has reached an
//! extension marker, and so every one of them lands on an octet boundary.
//! That is what makes a hand written encoder possible at all: the general
//! aligned PER rules are bit oriented, and none of the bit oriented cases
//! occur here.
//!
//! The boundary is drawn deliberately and stated in PRDRDP/13 §3.3: the GCC
//! decoder checks the fixed prefix bytes it knows, reads the determinants it
//! must, and rejects a structurally different but legal PER encoding of the
//! same PDU. No such server exists, and the alternative is a general PER
//! decoder driven by an ASN.1 schema, which D3 rules out and which would be
//! larger than the rest of this crate. If it ever does bite, the fix is a
//! targeted widening of one function with a captured trace attached to the
//! commit.

use crate::io::{PduError, PduResult, Reader, Writer};

/// The largest length determinant this crate reads or writes.
///
/// X.691 §10.9.3.6 gives the one octet form below 128 and the two octet form
/// below 16384. Above that the value is fragmented into 16K blocks
/// (§10.9.3.8), which GCC never reaches: the whole user data of a Connect
/// Initial is capped at [`MAX_GCC_USER_DATA`](crate::io::limits::MAX_GCC_USER_DATA),
/// which is 8192.
pub const MAX_LENGTH_DETERMINANT: usize = 16383;

/// Read a length determinant (X.691 §10.9.3.6 and §10.9.3.7).
///
/// The fragmented form is rejected rather than assembled: accepting it would
/// mean a reassembly buffer in a module that is meant to have no state, for a
/// case no GCC PDU can reach.
pub fn read_length_determinant(r: &mut Reader<'_>, context: &'static str) -> PduResult<usize> {
    let at = r.offset();
    let first = r.u8(context)?;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    if first & 0x40 != 0 {
        return Err(PduError::Unsupported {
            context,
            kind: "PER fragmented length determinant",
            value: first as u64,
            offset: at,
        });
    }
    let second = r.u8(context)?;
    Ok((usize::from(first & 0x3f) << 8) | usize::from(second))
}

/// Write a length determinant in the form X.691 §10.9.3.6 requires for the
/// value, which is the shortest of the two.
pub fn write_length_determinant(
    w: &mut Writer<'_>,
    len: usize,
    context: &'static str,
) -> PduResult<()> {
    if len < 0x80 {
        w.u8(len as u8);
        return Ok(());
    }
    if len > MAX_LENGTH_DETERMINANT {
        return Err(PduError::Encode {
            context,
            reason: "length determinant needs the fragmented form",
        });
    }
    w.u8(0x80 | ((len >> 8) as u8));
    w.u8((len & 0xff) as u8);
    Ok(())
}

/// The number of octets [`write_length_determinant`] writes for `len`.
#[must_use]
pub const fn length_determinant_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else {
        2
    }
}

/// Read the index of a CHOICE alternative (X.691 §23).
///
/// One octet, which holds for every choice this crate meets: none has an
/// extension marker and none has more than 255 alternatives, so the index is
/// a constrained whole number that occupies a whole octet.
/// `ConnectData.t124Identifier`, `ConnectGCCPDU` and `DomainMCSPDU` are the
/// three (T.124 §8.7, T.125 §7).
pub fn read_choice_index(r: &mut Reader<'_>, count: u8, context: &'static str) -> PduResult<u8> {
    let at = r.offset();
    let index = r.u8(context)?;
    if index >= count {
        return Err(PduError::InvalidField {
            context,
            field: "CHOICE index",
            value: index as u64,
            offset: at,
        });
    }
    Ok(index)
}

/// Write a CHOICE index, checking it against the alternative count so a
/// caller cannot emit an index the grammar has no alternative for.
pub fn write_choice_index(
    w: &mut Writer<'_>,
    index: u8,
    count: u8,
    context: &'static str,
) -> PduResult<()> {
    if index >= count {
        return Err(PduError::Encode {
            context,
            reason: "CHOICE index is past the last alternative",
        });
    }
    w.u8(index);
    Ok(())
}

/// Read the optional field bitmap that precedes a SEQUENCE with OPTIONAL
/// members (X.691 §18.2).
///
/// One octet covers up to eight optional members, which is every SEQUENCE
/// here. `ConferenceCreateRequest` has one, `userData`, and its bitmap is
/// `0x08` because the bits are left aligned within the octet.
pub fn read_selection(r: &mut Reader<'_>, context: &'static str) -> PduResult<u8> {
    r.u8(context)
}

/// Write the optional field bitmap.
pub fn write_selection(w: &mut Writer<'_>, bitmap: u8) {
    w.u8(bitmap);
}

/// Read a constrained whole number (X.691 §13).
///
/// The width follows the range: one octet when `upper - lower` is below 256,
/// two big endian octets when it is below 65536. Wider ranges are not
/// something the MCS user ids and channel ids this is used for can produce
/// (T.125 §7), so they are rejected rather than guessed at.
pub fn read_constrained_int(
    r: &mut Reader<'_>,
    lower: u32,
    upper: u32,
    context: &'static str,
) -> PduResult<u32> {
    let at = r.offset();
    let range = upper.checked_sub(lower).ok_or(PduError::InvalidField {
        context,
        field: "constrained integer range",
        value: u64::from(lower),
        offset: at,
    })?;
    let raw = if range < 256 {
        u32::from(r.u8(context)?)
    } else if range < 65536 {
        u32::from(r.be_u16(context)?)
    } else {
        return Err(PduError::Unsupported {
            context,
            kind: "PER constrained integer range",
            value: u64::from(range),
            offset: at,
        });
    };
    if raw > range {
        return Err(PduError::InvalidField {
            context,
            field: "constrained integer",
            value: u64::from(raw),
            offset: at,
        });
    }
    Ok(lower + raw)
}

/// Write a constrained whole number, in the width [`read_constrained_int`]
/// will read it back at.
pub fn write_constrained_int(
    w: &mut Writer<'_>,
    value: u32,
    lower: u32,
    upper: u32,
    context: &'static str,
) -> PduResult<()> {
    if value < lower || value > upper {
        return Err(PduError::Encode {
            context,
            reason: "value is outside the constraint",
        });
    }
    let range = upper - lower;
    let offset = value - lower;
    if range < 256 {
        w.u8(offset as u8);
    } else if range < 65536 {
        w.be_u16(offset as u16);
    } else {
        return Err(PduError::Encode {
            context,
            reason: "constrained integer range wider than two octets",
        });
    }
    Ok(())
}

/// Read an OBJECT IDENTIFIER's content octets (X.691 §24): a length
/// determinant then the packed encoding, which is the same packing X.690
/// §8.19 uses.
///
/// The content is returned unparsed. The only OID on this path is
/// `t124Identifier`, which is compared against a five byte constant rather
/// than decoded into arcs.
pub fn read_object_identifier<'a>(
    r: &mut Reader<'a>,
    context: &'static str,
) -> PduResult<&'a [u8]> {
    let len = read_length_determinant(r, context)?;
    r.slice(len, context)
}

/// Write an OBJECT IDENTIFIER from its content octets.
pub fn write_object_identifier(
    w: &mut Writer<'_>,
    content: &[u8],
    context: &'static str,
) -> PduResult<()> {
    write_length_determinant(w, content.len(), context)?;
    w.bytes(content);
    Ok(())
}

/// `{ 0 0 20 124 0 1 }`, itu-t recommendation t.124 version 1, as its five
/// content octets. This is `ConnectData.t124Identifier` and it is the first
/// thing in every GCC PDU in both directions (T.124 §8.7).
pub const T124_IDENTIFIER: &[u8] = &[0x00, 0x14, 0x7c, 0x00, 0x01];

/// Read a NumericString of `SIZE(min_len..255)` (X.691 §30 and §27).
///
/// The digits are four bits each, shifted down by `0x30`, and the string is
/// padded to an octet boundary. `ConferenceName` is the only one, and every
/// client sends the single digit `"1"` (T.124 §8.7, MS-RDPBCGR 2.2.1.3).
pub fn read_numeric_string(
    r: &mut Reader<'_>,
    min_len: usize,
    context: &'static str,
) -> PduResult<String> {
    let at = r.offset();
    let extra = r.u8(context)? as usize;
    let len = min_len + extra;
    let packed = r.slice(len.div_ceil(2), context)?;
    let mut out = String::with_capacity(len);
    for i in 0..len {
        let byte = packed.get(i / 2).copied().unwrap_or(0);
        let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
        if nibble > 9 {
            return Err(PduError::InvalidField {
                context,
                field: "NumericString digit",
                value: u64::from(nibble),
                offset: at,
            });
        }
        out.push((b'0' + nibble) as char);
    }
    // No alignment call follows: four bit digits padded to a whole number of
    // octets already end on the boundary X.691 §30.2 requires.
    Ok(out)
}

/// Write a NumericString of `SIZE(min_len..255)`.
pub fn write_numeric_string(
    w: &mut Writer<'_>,
    s: &str,
    min_len: usize,
    context: &'static str,
) -> PduResult<()> {
    let digits: Vec<u8> = s.bytes().collect();
    if digits.len() < min_len || digits.len() > min_len + 255 {
        return Err(PduError::Encode {
            context,
            reason: "NumericString length is outside the constraint",
        });
    }
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(PduError::Encode {
            context,
            reason: "NumericString holds a character that is not a digit",
        });
    }
    w.u8((digits.len() - min_len) as u8);
    for pair in digits.chunks(2) {
        let hi = pair.first().copied().unwrap_or(b'0') - 0x30;
        let lo = pair.get(1).map_or(0, |d| d - 0x30);
        w.u8((hi << 4) | lo);
    }
    Ok(())
}

/// Read an unconstrained whole number (X.691 §13.2.4): a length determinant,
/// then that many octets of two's complement.
///
/// `ErectDomainRequest.subHeight` and `.subInterval` are
/// `INTEGER (0..MAX)` (T.125 §7), which is the only unconstrained integer on
/// this path. A negative value or one wider than four octets is a malformed
/// PDU rather than a value we could act on, the same rule
/// [`super::ber::read_u32`] applies for the same reason.
pub fn read_unconstrained_int(r: &mut Reader<'_>, context: &'static str) -> PduResult<u32> {
    let at = r.offset();
    let len = read_length_determinant(r, context)?;
    let raw = r.slice(len, context)?;
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

/// Write an unconstrained whole number in the minimum number of octets, with
/// a leading zero when the top bit would otherwise make it negative.
pub fn write_unconstrained_int(
    w: &mut Writer<'_>,
    value: u32,
    context: &'static str,
) -> PduResult<()> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    let mut significant = bytes.get(first..).unwrap_or(&[0]);
    if significant.is_empty() {
        significant = &[0];
    }
    let pad = significant.first().is_some_and(|b| *b & 0x80 != 0);
    write_length_determinant(w, significant.len() + usize::from(pad), context)?;
    if pad {
        w.u8(0);
    }
    w.bytes(significant);
    Ok(())
}

/// The number of octets [`write_unconstrained_int`] writes for `value`,
/// determinant included.
#[must_use]
pub const fn unconstrained_int_size(value: u32) -> usize {
    // One determinant octet plus the content, which never reaches the two
    // octet determinant form.
    1 + if value < 0x80 {
        1
    } else if value < 0x8000 {
        2
    } else if value < 0x0080_0000 {
        3
    } else if value < 0x8000_0000 {
        4
    } else {
        5
    }
}

/// Read an OCTET STRING constrained to `min..=max` octets (X.691 §16).
///
/// A fixed length string, `min == max`, carries no determinant: the four
/// octet `h221NonStandard` key is the case that matters, and it is why the
/// `"Duca"` and `"McDn"` keys appear in a GCC PDU with nothing in front of
/// them. Anything else takes a determinant first.
///
/// Fixed strings of one or two octets are bit packed rather than aligned in
/// PER, and none occur on this path, so `min == max <= 2` is rejected rather
/// than encoded wrongly.
pub fn read_octet_string<'a>(
    r: &mut Reader<'a>,
    min: usize,
    max: usize,
    context: &'static str,
) -> PduResult<&'a [u8]> {
    let at = r.offset();
    if min == max {
        if min <= 2 {
            return Err(PduError::Unsupported {
                context,
                kind: "PER bit packed fixed OCTET STRING",
                value: min as u64,
                offset: at,
            });
        }
        return r.slice(min, context);
    }
    let len = read_length_determinant(r, context)?;
    if len < min || len > max {
        return Err(PduError::InvalidField {
            context,
            field: "OCTET STRING length",
            value: len as u64,
            offset: at,
        });
    }
    r.slice(len, context)
}

/// Write an OCTET STRING constrained to `min..=max` octets.
pub fn write_octet_string(
    w: &mut Writer<'_>,
    content: &[u8],
    min: usize,
    max: usize,
    context: &'static str,
) -> PduResult<()> {
    if content.len() < min || content.len() > max {
        return Err(PduError::Encode {
            context,
            reason: "OCTET STRING length is outside the constraint",
        });
    }
    if min == max {
        if min <= 2 {
            return Err(PduError::Encode {
                context,
                reason: "a fixed OCTET STRING of one or two octets is bit packed",
            });
        }
        w.bytes(content);
        return Ok(());
    }
    write_length_determinant(w, content.len(), context)?;
    w.bytes(content);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// The Conference Create Request prefix, field by field, from the walk in
    /// PRDRDP/13 §3.3 (MS-RDPBCGR 4.1.3 shows the same bytes in context).
    /// `284` is the user data length of that capture and `298` is the
    /// connectPDU length, which is the user data plus the fourteen byte GCC
    /// wrapper.
    #[test]
    fn the_conference_create_request_prefix_encodes_byte_for_byte() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            // ConnectData ::= SEQUENCE { key Key, connectPDU OCTET STRING }
            // Key ::= CHOICE { object OBJECT IDENTIFIER, h221NonStandard ... }
            write_choice_index(&mut w, 0, 2, "Key").unwrap();
            write_object_identifier(&mut w, T124_IDENTIFIER, "t124Identifier").unwrap();
            write_length_determinant(&mut w, 298, "connectPDU").unwrap();
            // ConnectGCCPDU ::= CHOICE, alternative 0 is
            // conferenceCreateRequest (T.124 §8.7).
            write_choice_index(&mut w, 0, 21, "ConnectGCCPDU").unwrap();
            // The optional field bitmap: userData is present.
            write_selection(&mut w, 0x08);
            write_numeric_string(&mut w, "1", 1, "conferenceName").unwrap();
        }
        assert_eq!(
            buf,
            [0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x81, 0x2a, 0x00, 0x08, 0x00, 0x10]
        );

        // ... the SET OF and the choice preamble are GCC's business, and the
        // H.221 key is this module's again.
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            write_octet_string(&mut w, b"Duca", 4, 4, "h221NonStandard").unwrap();
            write_length_determinant(&mut w, 284, "userData.value").unwrap();
        }
        assert_eq!(buf, [0x44, 0x75, 0x63, 0x61, 0x81, 0x1c]);
    }

    #[test]
    fn the_t124_identifier_reads_back() {
        let buf = [0x05, 0x00, 0x14, 0x7c, 0x00, 0x01];
        let mut r = Reader::new(&buf);
        assert_eq!(
            read_object_identifier(&mut r, "t124Identifier").unwrap(),
            T124_IDENTIFIER
        );
    }

    /// The 127/128 and 16383/16384 boundaries, which PRDRDP/13 §9.5 names as
    /// the encoding most likely to be written wrong.
    #[test]
    fn length_determinants_round_trip_across_both_boundaries() {
        for len in [0usize, 1, 127, 128, 129, 255, 256, 16382, 16383] {
            let mut buf = Vec::new();
            write_length_determinant(&mut Writer::new(&mut buf), len, "t").unwrap();
            assert_eq!(buf.len(), length_determinant_size(len), "len {len}");
            assert_eq!(
                read_length_determinant(&mut Reader::new(&buf), "t").unwrap(),
                len,
                "len {len}"
            );
        }
        assert_eq!(
            {
                let mut buf = Vec::new();
                write_length_determinant(&mut Writer::new(&mut buf), 127, "t").unwrap();
                buf
            },
            [0x7f]
        );
        assert_eq!(
            {
                let mut buf = Vec::new();
                write_length_determinant(&mut Writer::new(&mut buf), 128, "t").unwrap();
                buf
            },
            [0x80, 0x80]
        );
    }

    #[test]
    fn the_fragmented_length_form_is_refused_in_both_directions() {
        let err = read_length_determinant(&mut Reader::new(&[0xc1]), "userData").unwrap_err();
        assert!(matches!(err, PduError::Unsupported { .. }));
        let mut buf = Vec::new();
        assert!(write_length_determinant(&mut Writer::new(&mut buf), 16384, "userData").is_err());
    }

    #[test]
    fn a_choice_index_past_the_last_alternative_is_rejected() {
        let mut r = Reader::new(&[0x05]);
        assert!(read_choice_index(&mut r, 2, "Key").is_err());
        let mut buf = Vec::new();
        assert!(write_choice_index(&mut Writer::new(&mut buf), 5, 2, "Key").is_err());
    }

    /// MCS user ids are `INTEGER (1001..65535)` and channel ids
    /// `INTEGER (0..65535)` (T.125 §7), which is the two octet width; the one
    /// octet width shows up in the smaller domain PDU fields.
    #[test]
    fn constrained_integers_round_trip_at_both_widths() {
        for (value, lower, upper, expected) in [
            (1002u32, 1001u32, 65535u32, vec![0x00, 0x01]),
            (1001, 1001, 65535, vec![0x00, 0x00]),
            (65535, 1001, 65535, vec![0xfc, 0x16]),
            (3, 0, 255, vec![0x03]),
        ] {
            let mut buf = Vec::new();
            write_constrained_int(&mut Writer::new(&mut buf), value, lower, upper, "t").unwrap();
            assert_eq!(buf, expected, "value {value}");
            assert_eq!(
                read_constrained_int(&mut Reader::new(&buf), lower, upper, "t").unwrap(),
                value
            );
        }
    }

    #[test]
    fn a_constrained_integer_outside_its_range_is_rejected_in_both_directions() {
        // Range 0..=3 is one octet wide, so 0x09 is readable and out of range.
        let err = read_constrained_int(&mut Reader::new(&[0x09]), 0, 3, "t").unwrap_err();
        assert!(matches!(err, PduError::InvalidField { .. }));
        let mut buf = Vec::new();
        assert!(write_constrained_int(&mut Writer::new(&mut buf), 9, 0, 3, "t").is_err());
    }

    #[test]
    fn numeric_strings_round_trip() {
        for (s, min, expected) in [
            ("1", 1usize, vec![0x00, 0x10]),
            ("12", 1, vec![0x01, 0x12]),
            ("123", 1, vec![0x02, 0x12, 0x30]),
        ] {
            let mut buf = Vec::new();
            write_numeric_string(&mut Writer::new(&mut buf), s, min, "conferenceName").unwrap();
            assert_eq!(buf, expected, "string {s}");
            assert_eq!(
                read_numeric_string(&mut Reader::new(&buf), min, "conferenceName").unwrap(),
                s
            );
        }
    }

    #[test]
    fn a_non_digit_is_rejected_in_both_directions() {
        let mut buf = Vec::new();
        assert!(write_numeric_string(&mut Writer::new(&mut buf), "1a", 1, "t").is_err());
        // Nibble 0x0f is not a digit.
        assert!(read_numeric_string(&mut Reader::new(&[0x00, 0xf0]), 1, "t").is_err());
    }

    /// T.125 §7's `ErectDomainRequest` sends `subHeight = 0` and
    /// `subInterval = 0`, which is `01 00` twice (MS-RDPBCGR 2.2.1.5).
    #[test]
    fn unconstrained_integers_round_trip_with_the_leading_zero_rule() {
        for value in [0u32, 1, 0x7f, 0x80, 0xff, 0x1234, 0x8000_0000, u32::MAX] {
            let mut buf = Vec::new();
            write_unconstrained_int(&mut Writer::new(&mut buf), value, "t").unwrap();
            assert_eq!(buf.len(), unconstrained_int_size(value), "value {value}");
            assert_eq!(
                read_unconstrained_int(&mut Reader::new(&buf), "t").unwrap(),
                value
            );
        }
        let mut buf = Vec::new();
        write_unconstrained_int(&mut Writer::new(&mut buf), 0, "subHeight").unwrap();
        assert_eq!(buf, [0x01, 0x00]);
        let mut buf = Vec::new();
        write_unconstrained_int(&mut Writer::new(&mut buf), 0x80, "t").unwrap();
        assert_eq!(buf, [0x02, 0x00, 0x80]);
    }

    #[test]
    fn a_negative_or_oversized_unconstrained_integer_is_rejected() {
        // Five content octets.
        assert!(read_unconstrained_int(&mut Reader::new(&[0x05, 1, 2, 3, 4, 5]), "t").is_err());
        // A leading bit set, which is a negative INTEGER.
        assert!(read_unconstrained_int(&mut Reader::new(&[0x01, 0xff]), "t").is_err());
        // No content octets at all.
        assert!(read_unconstrained_int(&mut Reader::new(&[0x00]), "t").is_err());
    }

    #[test]
    fn a_fixed_octet_string_carries_no_determinant() {
        let buf = *b"McDn";
        let mut r = Reader::new(&buf);
        assert_eq!(
            read_octet_string(&mut r, 4, 4, "h221NonStandard").unwrap(),
            b"McDn"
        );
        assert!(r.is_empty());
    }

    #[test]
    fn a_bounded_octet_string_carries_one() {
        let mut buf = Vec::new();
        write_octet_string(&mut Writer::new(&mut buf), b"abc", 0, 1024, "userData").unwrap();
        assert_eq!(buf, [0x03, b'a', b'b', b'c']);
        let mut r = Reader::new(&buf);
        assert_eq!(
            read_octet_string(&mut r, 0, 1024, "userData").unwrap(),
            b"abc"
        );
    }

    #[test]
    fn an_octet_string_longer_than_its_constraint_is_rejected() {
        let buf = [0x05, 1, 2, 3, 4, 5];
        let mut r = Reader::new(&buf);
        assert!(read_octet_string(&mut r, 0, 4, "userData").is_err());
        let mut out = Vec::new();
        assert!(write_octet_string(&mut Writer::new(&mut out), &[0u8; 5], 0, 4, "t").is_err());
    }

    /// PRDRDP/13 §9.3 for this module.
    #[test]
    fn every_prefix_of_the_ccr_prefix_errors_without_panicking() {
        let full = [
            0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x81, 0x2a, 0x00, 0x08, 0x00, 0x10,
        ];
        for cut in 0..full.len() {
            let mut r = Reader::new(&full[..cut]);
            let decoded = (|| -> PduResult<()> {
                read_choice_index(&mut r, 2, "Key")?;
                read_object_identifier(&mut r, "t124Identifier")?;
                read_length_determinant(&mut r, "connectPDU")?;
                read_choice_index(&mut r, 21, "ConnectGCCPDU")?;
                read_selection(&mut r, "selection")?;
                read_numeric_string(&mut r, 1, "conferenceName")?;
                Ok(())
            })();
            assert!(decoded.is_err(), "prefix of {cut} bytes decoded");
        }
    }
}
