//! DER, the subset CredSSP and X.509 need (PRDRDP/13 §3.4).
//!
//! This is the walker that `crates/vnc-transport/src/tls.rs` lines 246 to 400
//! has been using for the trust on first use certificate path, moved here so
//! there is one X.690 implementation in the workspace rather than two that
//! drift (PRDRDP/13 §3.5, PRDRDP/00 R45). `extract_spki` and
//! `subject_common_name` keep their signatures exactly, so the call sites in
//! `tls.rs` change by a `use` line and nothing else. The module comment there
//! is the precedent this file extends: "A full ASN.1 parser is not a
//! dependency this crate needs, and everything here is bounds-checked against
//! a hostile server."
//!
//! What `rdp-auth` adds to it: the context specific tags `[0]` through `[5]`
//! of `TSRequest` (MS-CSSP 2.2.1), signed INTEGER reading because `errorCode`
//! carries an NTSTATUS that is negative as an ASN.1 integer, the writing side
//! for `TSRequest`, `TSCredentials` and `TSPasswordCreds` (MS-CSSP 2.2.1.2
//! and 2.2.1.2.1), and `subject_public_key`, because MS-CSSP 3.1.5 hashes the
//! server's public key and the CredSSP versions differ over whether that is
//! the SPKI or the key inside it.
//!
//! The reading side keeps its `Option` return rather than gaining a
//! [`PduResult`](crate::PduResult): `vnc-transport`'s existing callers use
//! `Option` and changing them is churn with no benefit. The `TSRequest` layer
//! above converts `None` into a
//! [`PduError::Asn1Tag`](crate::PduError::Asn1Tag) with a context string.

use super::tag;

/// A parsed element: the tag, the content, and the full element including its
/// header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The identifier octet.
    pub tag: u8,
    /// The content octets.
    pub content: &'a [u8],
    /// The identifier, length and content octets together, which is what a
    /// fingerprint is computed over.
    pub full: &'a [u8],
}

/// Read one TLV from the front of `buf`, returning it and the remainder.
///
/// Multi byte tags (X.690 §8.1.2.4) are rejected: nothing on this path uses
/// one, and MCS, which does, has its own reader in [`super::ber`].
#[must_use]
pub fn read_tlv(buf: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *buf.first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *buf.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (first as usize, 2usize)
    } else {
        let n = (first & 0x7f) as usize;
        // Indefinite length is illegal in DER (X.690 §10.1); more than four
        // length octets means an element larger than 4 GiB. Reject both.
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in buf.get(2..2 + n)? {
            len = (len << 8) | (*b as usize);
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    Some((
        Tlv {
            tag,
            content: buf.get(header..end)?,
            full: buf.get(..end)?,
        },
        buf.get(end..)?,
    ))
}

/// Read one TLV and require its tag, returning its content and the
/// remainder.
#[must_use]
pub fn expect_tag(buf: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (tlv, rest) = read_tlv(buf)?;
    if tlv.tag != tag {
        return None;
    }
    Some((tlv.content, rest))
}

/// Read an `INTEGER` as a `u32`, rejecting a negative or oversized value.
///
/// `TSRequest.version` (MS-CSSP 2.2.1) is the field this reads.
#[must_use]
pub fn read_int_u32(buf: &[u8]) -> Option<(u32, &[u8])> {
    let (value, rest) = read_int_i64(buf)?;
    Some((u32::try_from(value).ok()?, rest))
}

/// Read an `INTEGER` as an `i64`, sign extended per X.690 §8.3.
///
/// Signed because `TSRequest.errorCode` carries an NTSTATUS, and
/// `0xC0000022` (STATUS_ACCESS_DENIED) is a negative ASN.1 integer.
#[must_use]
pub fn read_int_i64(buf: &[u8]) -> Option<(i64, &[u8])> {
    let (content, rest) = expect_tag(buf, tag::INTEGER)?;
    let (first, _) = content.split_first()?;
    if content.len() > 8 {
        return None;
    }
    let mut value: i64 = if *first & 0x80 != 0 { -1 } else { 0 };
    for b in content {
        value = (value << 8) | i64::from(*b);
    }
    Some((value, rest))
}

/// Read a `BIT STRING`'s bits, dropping the leading unused bit count
/// (X.690 §8.6.2).
///
/// Returns `None` when any bits are declared unused: every BIT STRING on this
/// path is a whole number of octets, and a partial one would mean we are
/// looking at a structure we did not expect.
#[must_use]
pub fn read_bit_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let (content, rest) = expect_tag(buf, tag::BIT_STRING)?;
    let (unused, bits) = content.split_first()?;
    if *unused != 0 {
        return None;
    }
    Some((bits, rest))
}

/// Write a definite length in the shortest form, which DER requires
/// (X.690 §10.1).
fn write_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = bytes.get(first..).unwrap_or(&[]);
    out.push(0x80 | (significant.len() as u8));
    out.extend_from_slice(significant);
}

/// Write one element with the given tag and content.
pub fn write_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    write_len(out, content.len());
    out.extend_from_slice(content);
}

/// Write an `INTEGER` with the given tag, in the minimum number of octets of
/// two's complement (X.690 §8.3.2).
///
/// The tag is a parameter because CredSSP's integers are wrapped in a context
/// specific tag: `version [0] INTEGER` is `A0 03 02 01 06`, an INTEGER inside
/// a `[0]`, so the caller writes the wrapper with [`write_nested`] and this
/// with [`tag::INTEGER`](super::tag::INTEGER).
pub fn write_int(out: &mut Vec<u8>, tag: u8, value: i64) {
    let bytes = value.to_be_bytes();
    // Drop leading octets that the sign bit of the next one already implies.
    let mut start = 0usize;
    while start + 1 < bytes.len() {
        let cur = bytes.get(start).copied().unwrap_or(0);
        let next = bytes.get(start + 1).copied().unwrap_or(0);
        let redundant = (cur == 0x00 && next & 0x80 == 0) || (cur == 0xff && next & 0x80 != 0);
        if !redundant {
            break;
        }
        start += 1;
    }
    write_tlv(out, tag, bytes.get(start..).unwrap_or(&[0]));
}

/// Write a constructed element whose length is not known until its body has
/// been written.
///
/// The body goes into a scratch buffer, is measured, and is then copied in
/// behind its header, because DER lengths are the shortest form and so cannot
/// be reserved and back patched. That is one copy per nesting level on a
/// structure at most four levels deep, built a handful of times per
/// connection, which is not a path worth optimising.
pub fn write_nested<F>(out: &mut Vec<u8>, tag: u8, f: F)
where
    F: FnOnce(&mut Vec<u8>),
{
    let mut scratch = Vec::new();
    f(&mut scratch);
    write_tlv(out, tag, &scratch);
}

/// `[0]` constructed, the EXPLICIT version tag in a TBSCertificate
/// (RFC 5280 §4.1).
const CONTEXT_0: u8 = 0xa0;
/// OID 2.5.4.3 (id-at-commonName), RFC 5280 §4.1.2.4.
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/// Walk `Certificate -> TBSCertificate -> subjectPublicKeyInfo` and return
/// that element's complete DER encoding, header included, which is what a
/// "SPKI fingerprint" is computed over.
#[must_use]
pub fn extract_spki(cert: &[u8]) -> Option<&[u8]> {
    let (spki, _) = spki_element(cert)?;
    Some(spki)
}

/// The `subjectPublicKey` BIT STRING's contents, without the SPKI wrapper and
/// without the unused bit count.
///
/// MS-CSSP 3.1.5 hashes the server's public key into `pubKeyAuth`, and the
/// CredSSP versions differ over whether the hash covers the whole
/// SubjectPublicKeyInfo or only the key inside it, so both have to be
/// reachable.
#[must_use]
pub fn subject_public_key(cert: &[u8]) -> Option<&[u8]> {
    let (_, content) = spki_element(cert)?;
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
    //                                     subjectPublicKey BIT STRING }
    let (_alg, rest) = read_tlv(content)?;
    let (bits, _) = read_bit_string(rest)?;
    Some(bits)
}

/// The OID of `Certificate.signatureAlgorithm`, as its DER content octets.
///
/// ```text
/// Certificate         ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
/// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
/// ```
///
/// RFC 5280 §4.1. Three TLV reads over the walker this module already owns,
/// so it adds no second X.690 implementation (PRDRDP/00 R45).
///
/// This is the hash choice input of RFC 5929 §4.1 and nothing else. Reading
/// the wrong element produces a channel binding that a Windows host with
/// Extended Protection set to "Require" rejects, and the failure reads to the
/// user as a wrong password (PRDRDP/03 §4.3). It is named
/// `signature_algorithm_oid` rather than `certificate_signature_algorithm`
/// because everything in this module takes a certificate, so the prefix would
/// carry nothing (PRDRDP/00 R62).
#[must_use]
pub fn signature_algorithm_oid(cert: &[u8]) -> Option<&[u8]> {
    let (certificate, _) = expect_tag(cert, tag::SEQUENCE)?;
    let (_tbs, rest) = read_tlv(certificate)?;
    let (algorithm_identifier, _) = expect_tag(rest, tag::SEQUENCE)?;
    let (oid, _) = expect_tag(algorithm_identifier, tag::OBJECT_IDENTIFIER)?;
    Some(oid)
}

/// The subject `CN=` value, for display in the trust prompt. Untrusted text:
/// the caller must render it as plain text, never as markup.
#[must_use]
pub fn subject_common_name(cert: &[u8]) -> Option<String> {
    let tbs = tbs_certificate(cert)?;
    let mut rest = tbs;
    let (first, after_first) = read_tlv(rest)?;
    if first.tag == CONTEXT_0 {
        rest = after_first;
    }
    let (_serial, rest2) = read_tlv(rest)?;
    let (_sigalg, rest3) = read_tlv(rest2)?;
    let (_issuer, rest4) = read_tlv(rest3)?;
    let (_validity, rest5) = read_tlv(rest4)?;
    let (subject, _) = read_tlv(rest5)?;
    if subject.tag != tag::SEQUENCE {
        return None;
    }

    // Name ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTVA)
    let mut rdns = subject.content;
    while let Some((rdn, next)) = read_tlv(rdns) {
        rdns = next;
        if rdn.tag != tag::SET {
            continue;
        }
        let mut attrs = rdn.content;
        while let Some((attr, next_attr)) = read_tlv(attrs) {
            attrs = next_attr;
            if attr.tag != tag::SEQUENCE {
                continue;
            }
            let (oid, after_oid) = read_tlv(attr.content)?;
            if oid.tag != tag::OBJECT_IDENTIFIER || oid.content != OID_CN {
                continue;
            }
            let (value, _) = read_tlv(after_oid)?;
            // Cap the length, a server may claim anything.
            let text: String = String::from_utf8_lossy(value.content)
                .chars()
                .filter(|c| !c.is_control())
                .take(128)
                .collect();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

/// The subjectPublicKeyInfo element: its full encoding and its content.
fn spki_element(cert: &[u8]) -> Option<(&[u8], &[u8])> {
    let tbs = tbs_certificate(cert)?;
    let mut rest = tbs;
    // Optional [0] version.
    let (first, after_first) = read_tlv(rest)?;
    if first.tag == CONTEXT_0 {
        rest = after_first;
    }
    // serialNumber
    let (serial, rest2) = read_tlv(rest)?;
    if serial.tag != tag::INTEGER {
        return None;
    }
    // signature, issuer, validity, subject, four SEQUENCEs, then SPKI.
    let mut rest = rest2;
    for _ in 0..4 {
        let (tlv, next) = read_tlv(rest)?;
        if tlv.tag != tag::SEQUENCE {
            return None;
        }
        rest = next;
    }
    let (spki, _) = read_tlv(rest)?;
    if spki.tag != tag::SEQUENCE {
        return None;
    }
    Some((spki.full, spki.content))
}

fn tbs_certificate(cert: &[u8]) -> Option<&[u8]> {
    let (outer, _) = read_tlv(cert)?;
    if outer.tag != tag::SEQUENCE {
        return None;
    }
    let (tbs, _) = read_tlv(outer.content)?;
    if tbs.tag != tag::SEQUENCE {
        return None;
    }
    Some(tbs.content)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use crate::asn1::context;

    #[test]
    fn rejects_truncated_input() {
        assert!(extract_spki(&[]).is_none());
        assert!(extract_spki(&[0x30]).is_none());
        assert!(extract_spki(&[0x30, 0x82, 0xff, 0xff]).is_none());
        assert!(subject_common_name(&[0x30, 0x03, 0x30, 0x01]).is_none());
    }

    #[test]
    fn rejects_non_certificate() {
        // A well-formed SEQUENCE that is not a certificate.
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        assert!(extract_spki(&der).is_none());
    }

    #[test]
    fn long_form_lengths_are_bounds_checked() {
        // Claims 0x0102 content bytes but supplies none.
        let der = [0x30, 0x82, 0x01, 0x02];
        assert!(extract_spki(&der).is_none());
    }

    /// A real self-signed certificate (`CN=vnc.example.test`, P-256), carried
    /// over from `crates/vnc-transport/src/tls.rs` with the move (PRDRDP/13
    /// §3.5).
    const TEST_CERT_HEX: &str = "3082021b308201c0020900fed9f6f5144ee51d300a06082a8648ce3d040302301b31\
19301706035504030c10766e632e6578616d706c652e74657374301e170d3236303732383139333830395a170d32363037323931\
39333830395a301b3119301706035504030c10766e632e6578616d706c652e746573743082014b3082010306072a8648ce3d0201\
3081f7020101302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff\
305b0420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd557698\
86bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247\
f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb64068\
37bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101034200040b2ec0b3fed6\
08022b545e768b3ab0ffc340ff9fb4f606b0c6c9e98a8a2f1919bb93370b6d21abd621dc5122cf599bff084ff2d8b16df21bf62a\
96fcbd59975a300a06082a8648ce3d0403020349003046022100ba92e99e98c2144752897231a266796f434ccab0137f03df2af2\
69c74c7f545402210084092ec5d5ddc0caad180befc2aa4e62cbef693c063287947a776840d6c92b88";

    fn test_cert() -> Vec<u8> {
        hex::decode(TEST_CERT_HEX.replace(['\n', ' '], "")).unwrap()
    }

    /// The digest of these bytes is what `openssl x509 -pubkey | openssl pkey
    /// -pubin -outform der | sha256` produces, which is the value users
    /// compare against elsewhere. `vnc-transport` asserted the digest; this
    /// crate has no hash dependency and no business having one (PRDRDP/00
    /// R54), so it asserts the bytes the digest is taken over instead.
    #[test]
    fn extracts_the_spki_element_whole() {
        let der = test_cert();
        let spki = extract_spki(&der).expect("SPKI should be found");
        assert_eq!(spki.len(), 335);
        assert_eq!(hex::encode(&spki[..16]), "3082014b3082010306072a8648ce3d02");
        // The element is a view into the certificate, not a copy of it.
        let start = spki.as_ptr() as usize - der.as_ptr() as usize;
        assert_eq!(&der[start..start + spki.len()], spki);
    }

    /// The uncompressed P-256 point, 0x04 then two 32 byte coordinates
    /// (RFC 5480 §2.2). This is the buffer MS-CSSP 3.1.5's later pubKeyAuth
    /// versions hash.
    #[test]
    fn extracts_the_subject_public_key() {
        let der = test_cert();
        let key = subject_public_key(&der).expect("public key should be found");
        assert_eq!(key.len(), 65);
        assert_eq!(key.first(), Some(&0x04));
        assert_eq!(
            hex::encode(key),
            "040b2ec0b3fed608022b545e768b3ab0ffc340ff9fb4f606b0c6c9e98a8a2f1919\
bb93370b6d21abd621dc5122cf599bff084ff2d8b16df21bf62a96fcbd59975a"
        );
    }

    #[test]
    fn reads_the_subject_common_name() {
        let der = test_cert();
        assert_eq!(
            subject_common_name(&der).as_deref(),
            Some("vnc.example.test")
        );
    }

    /// The fixture is signed `ecdsa-with-SHA256`, OID 1.2.840.10045.4.3.2.
    /// Its DER content octets are the arithmetic of X.690 §8.19: the first
    /// two arcs collapse to `40 * 1 + 2 = 42 = 0x2a`, then 840 is
    /// `0x86 0x48` (`0x06 << 7 | 0x48 = 840`), then 10045 is
    /// `0xce 0x3d` (`0x4e << 7 | 0x3d = 10045`), then 4, 3 and 2 one byte
    /// each. That is `2a 86 48 ce 3d 04 03 02`, eight bytes.
    #[test]
    fn reads_the_signature_algorithm_oid_and_not_the_subject_key() {
        let der = test_cert();
        assert_eq!(
            signature_algorithm_oid(&der),
            Some(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02][..])
        );
        // The two values a certificate yields are different things and must
        // not collapse into one another by a later refactor: the pin is
        // taken over the whole SPKI element and the CredSSP binding input is
        // the inner subjectPublicKey contents (PRDRDP/03 §4.3).
        let spki = extract_spki(&der).unwrap();
        let key = subject_public_key(&der).unwrap();
        assert_ne!(spki, key);
        assert!(spki.len() > key.len());
        assert_ne!(signature_algorithm_oid(&der), Some(key));
    }

    /// Truncation and rubbish are `None`, never a panic and never a partial
    /// OID: this walks bytes a remote peer chose.
    #[test]
    fn a_malformed_certificate_yields_no_signature_algorithm_oid() {
        let der = test_cert();
        for cut in 0..der.len() {
            let _ = signature_algorithm_oid(&der[..cut]);
        }
        assert_eq!(signature_algorithm_oid(&[]), None);
        assert_eq!(signature_algorithm_oid(&[0x30, 0x00]), None);
        assert_eq!(signature_algorithm_oid(&[0x02, 0x01, 0x00]), None);
    }

    /// Truncating a real certificate anywhere must fail cleanly, never panic.
    #[test]
    fn truncated_real_certificate_never_panics() {
        let der = test_cert();
        for n in 0..der.len() {
            let _ = extract_spki(&der[..n]);
            let _ = subject_common_name(&der[..n]);
            let _ = subject_public_key(&der[..n]);
        }
    }

    /// `TSRequest ::= SEQUENCE { version [0] INTEGER, negoTokens [1] ...`
    /// (MS-CSSP 2.2.1). Version 6 with one nego token is the shape `rdp-auth`
    /// writes first, and this is the encoding a Windows server expects.
    #[test]
    fn writes_the_shape_of_a_ts_request() {
        let mut out = Vec::new();
        write_nested(&mut out, tag::SEQUENCE, |seq| {
            write_nested(seq, context(0), |v| write_int(v, tag::INTEGER, 6));
            write_nested(seq, context(1), |nego| {
                write_nested(nego, tag::SEQUENCE, |list| {
                    write_nested(list, tag::SEQUENCE, |item| {
                        write_nested(item, context(0), |t| {
                            write_tlv(t, tag::OCTET_STRING, b"NTLMSSP\0");
                        });
                    });
                });
            });
        });
        assert_eq!(
            hex::encode(&out),
            "3017a003020106a110300e300ca00a04084e544c4d53535000"
        );

        // Walk it back: version 6, then the [1] wrapper.
        let (body, rest) = expect_tag(&out, tag::SEQUENCE).unwrap();
        assert!(rest.is_empty());
        let (v, after_version) = expect_tag(body, context(0)).unwrap();
        assert_eq!(read_int_u32(v).unwrap().0, 6);
        let (nego, _) = expect_tag(after_version, context(1)).unwrap();
        assert!(!nego.is_empty());
    }

    /// X.690 §8.3.2: the minimum number of octets, and the sign bit decides
    /// whether a leading `00` or `FF` is redundant. `errorCode` is the field
    /// that needs the negative side (MS-CSSP 2.2.1).
    #[test]
    fn integers_round_trip_at_the_sign_boundaries() {
        for (value, expected) in [
            (0i64, "020100"),
            (1, "020101"),
            (127, "02017f"),
            (128, "02020080"),
            (255, "020200ff"),
            (-1, "0201ff"),
            (-128, "020180"),
            (-129, "0202ff7f"),
            (0xc000_0022u32 as i64, "020500c0000022"),
        ] {
            let mut out = Vec::new();
            write_int(&mut out, tag::INTEGER, value);
            assert_eq!(hex::encode(&out), expected, "value {value}");
            assert_eq!(read_int_i64(&out).unwrap().0, value);
        }
    }

    #[test]
    fn an_ntstatus_reads_back_negative_when_it_is_written_negative() {
        // STATUS_LOGON_FAILURE as the negative integer a server sends.
        let mut out = Vec::new();
        write_int(&mut out, tag::INTEGER, -1_073_741_715);
        let (value, rest) = read_int_i64(&out).unwrap();
        assert_eq!(value, -1_073_741_715);
        assert!(rest.is_empty());
        // It does not fit a u32, so the unsigned reader refuses it rather
        // than wrapping.
        assert!(read_int_u32(&out).is_none());
    }

    #[test]
    fn lengths_use_the_shortest_form() {
        let mut out = Vec::new();
        write_tlv(&mut out, tag::OCTET_STRING, &[0u8; 0x7f]);
        assert_eq!(out.get(..2), Some(&[0x04, 0x7f][..]));
        let mut out = Vec::new();
        write_tlv(&mut out, tag::OCTET_STRING, &[0u8; 0x80]);
        assert_eq!(out.get(..3), Some(&[0x04, 0x81, 0x80][..]));
        let mut out = Vec::new();
        write_tlv(&mut out, tag::OCTET_STRING, &[0u8; 0x1234]);
        assert_eq!(out.get(..4), Some(&[0x04, 0x82, 0x12, 0x34][..]));
    }

    #[test]
    fn a_multi_byte_tag_is_refused() {
        // 0x7f is where MCS's Connect-Initial lives; DER on this path has no
        // such tag and guessing at one would be a parser for a grammar
        // nobody reviewed.
        assert!(read_tlv(&[0x7f, 0x65, 0x00]).is_none());
    }

    #[test]
    fn every_prefix_of_a_written_ts_request_fails_cleanly() {
        let mut out = Vec::new();
        write_nested(&mut out, tag::SEQUENCE, |seq| {
            write_nested(seq, context(0), |v| write_int(v, tag::INTEGER, 6));
        });
        for cut in 0..out.len() {
            let prefix = out.get(..cut).unwrap();
            if let Some((body, _)) = expect_tag(prefix, tag::SEQUENCE) {
                let _ = expect_tag(body, context(0));
            }
        }
    }
}
