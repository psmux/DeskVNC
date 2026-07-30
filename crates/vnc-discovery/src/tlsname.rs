//! Reading a machine's name out of the TLS certificate it serves on RDP.
//!
//! This is the last-resort rung of the resolution ladder, and it exists
//! because of a real and growing gap: current Windows ships with LLMNR
//! disabled and NetBIOS-over-TCP/IP firewalled off the Public profile, and a
//! consumer router registers no DNS. Such a host answers *no* name service at
//! all, every rung in [`crate::resolve`] above this one comes back empty, //! yet it will happily complete a TLS handshake on 3389 and hand over a
//! self-signed certificate whose subject `CN` is the machine name
//! (`CN=DESKTOP-H21K47C`). Windows generates that certificate itself; the name
//! in it is the computer name.
//!
//! **Nothing here authenticates.** We send a TLS `ClientHello`, read the
//! server's `Certificate` message, and drop the socket. No `ClientKeyExchange`,
//! no `Finished`, no CredSSP/NLA, no credential material of any kind ever
//! leaves this process, the handshake is abandoned less than one round trip
//! in. It is the same bargain as the RFB deep probe in [`crate::probe`], which
//! completes a version handshake and closes before authenticating.
//!
//! Deliberately *not* done: the RDP X.224 negotiation that would normally
//! precede TLS. A server configured for NLA answers that negotiation with
//! `RDP_NEG_FAILURE`/`SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER` and gives us
//! nothing, and the only way past it is CredSSP, which *is* authentication.
//! Speaking TLS directly avoids the RDP state machine entirely and works
//! against exactly the hosts we could not otherwise name.
//!
//! The `ClientHello` offers TLS 1.2 and no higher on purpose: from TLS 1.3 the
//! certificate is encrypted and unreadable to a handshake we never finish.
//!
//! Everything parsed here is attacker-controlled, so the record, handshake and
//! DER walkers are all bounds-checked, depth-capped and length-capped.

/// Port we read a certificate from. RDP is the only service probed: on Windows
/// its certificate is self-signed and named after the machine, which is not
/// true of a general HTTPS port.
pub const RDP_PORT: u16 = 3389;

/// Stop reading after this much of the server's flight. ServerHello plus a
/// certificate chain is ~1-4 KiB; this is the ceiling on hostile buffering.
pub const MAX_TLS_READ: usize = 16 * 1024;

/// `handshake` TLS record type.
const RECORD_HANDSHAKE: u8 = 22;
/// `Certificate` handshake message type.
const HANDSHAKE_CERTIFICATE: u8 = 11;
/// Largest legal TLS record payload (RFC 5246 §6.2.1 allows 2^14 plus
/// compression/MAC expansion).
const MAX_RECORD_LEN: usize = 16_384 + 2_048;
/// Longest certificate we will look at.
const MAX_CERT_LEN: usize = 16 * 1024;
/// Cap on RDNs walked in a subject, and attributes within one RDN.
const MAX_RDNS: usize = 32;
/// X.520 `ub-common-name`.
const MAX_CN_LEN: usize = 64;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_OID: u8 = 0x06;
/// Explicit `[0]`, the optional `version` field of a `TBSCertificate`.
const TAG_CONTEXT_0: u8 = 0xA0;
/// OID 2.5.4.3, `id-at-commonName`.
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// Build a minimal TLS 1.2 `ClientHello`.
///
/// `random` is the 32-byte client random; taking it as a parameter keeps this
/// a pure function, so a test can assert the bytes exactly. No SNI is sent, /// we are asking the host what it is called, so by definition we do not know a
/// name to put in it.
pub fn client_hello(random: [u8; 32]) -> Vec<u8> {
    // Cipher suites: enough modern and legacy ECDHE/RSA options that any
    // Windows schannel will pick one. We never complete the handshake, so the
    // choice only has to be acceptable, not good.
    const SUITES: &[u16] = &[
        0xc02f, 0xc030, 0xc027, 0xc028, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ];
    const GROUPS: &[u16] = &[0x0017, 0x0018, 0x0019];
    const SIG_ALGS: &[u16] = &[0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0201];

    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&[0x03, 0x03]); // client_version: TLS 1.2
    body.extend_from_slice(&random);
    body.push(0); // session_id: empty
    body.extend_from_slice(&((SUITES.len() * 2) as u16).to_be_bytes());
    for suite in SUITES {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]); // compression_methods: null

    let mut ext = Vec::with_capacity(48);
    push_u16_list_extension(&mut ext, 10, GROUPS); // supported_groups
    ext.extend_from_slice(&11u16.to_be_bytes()); // ec_point_formats
    ext.extend_from_slice(&2u16.to_be_bytes());
    ext.extend_from_slice(&[0x01, 0x00]); // length 1, uncompressed
    push_u16_list_extension(&mut ext, 13, SIG_ALGS); // signature_algorithms

    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01); // client_hello
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // u24
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]); // record version: TLS 1.0, as is customary
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Append an extension whose body is a `u16`-length-prefixed list of `u16`s.
fn push_u16_list_extension(out: &mut Vec<u8>, ext_type: u16, values: &[u16]) {
    let body_len = values.len() * 2;
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&((body_len + 2) as u16).to_be_bytes());
    out.extend_from_slice(&(body_len as u16).to_be_bytes());
    for v in values {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Read a 24-bit big-endian length at `at`.
fn u24(buf: &[u8], at: usize) -> Option<usize> {
    let b = buf.get(at..at + 3)?;
    Some((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
}

/// Extract the server's end-entity certificate from a partial TLS server
/// flight.
///
/// Handshake messages may be split across records, so the handshake stream is
/// reassembled first. Returns `None` while the certificate has not arrived
/// yet, which is what lets a caller feed this growing buffer after every read.
pub fn first_certificate(stream: &[u8]) -> Option<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut at = 0usize;
    while at + 5 <= stream.len() {
        let ctype = stream[at];
        let len = usize::from(u16::from_be_bytes([stream[at + 3], stream[at + 4]]));
        if len > MAX_RECORD_LEN {
            return None; // not a TLS server, or hostile
        }
        let end = at.checked_add(5)?.checked_add(len)?;
        if end > stream.len() {
            break; // record still in flight; parse what we have
        }
        if ctype == RECORD_HANDSHAKE {
            handshake.extend_from_slice(&stream[at + 5..end]);
            if handshake.len() > MAX_TLS_READ {
                return None;
            }
        }
        at = end;
    }

    let mut i = 0usize;
    while i + 4 <= handshake.len() {
        let mtype = handshake[i];
        let mlen = u24(&handshake, i + 1)?;
        let end = i.checked_add(4)?.checked_add(mlen)?;
        if end > handshake.len() {
            break; // message incomplete
        }
        if mtype == HANDSHAKE_CERTIFICATE {
            let body = &handshake[i + 4..end];
            // Certificate ::= { u24 list_length, then u24 length + DER, … }
            let _list_len = u24(body, 0)?;
            let cert_len = u24(body, 3)?;
            if cert_len == 0 || cert_len > MAX_CERT_LEN {
                return None;
            }
            let cert = body.get(6..6usize.checked_add(cert_len)?)?;
            return Some(cert.to_vec());
        }
        i = end;
    }
    None
}

/// Split the next DER TLV off `buf`, returning `(tag, value, remainder)`.
///
/// Rejects multi-byte tags, indefinite lengths and long-form lengths over four
/// bytes, none of which occur in a certificate, and all of which are ways to
/// make a naive parser loop or over-read.
fn next_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *buf.first()?;
    if tag & 0x1F == 0x1F {
        return None; // multi-byte tag number
    }
    let first = *buf.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (usize::from(first), 2usize)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None; // indefinite length, or absurdly long
        }
        let bytes = buf.get(2..2 + n)?;
        let mut v = 0usize;
        for &b in bytes {
            v = (v << 8) | usize::from(b);
        }
        (v, 2 + n)
    };
    let end = header.checked_add(len)?;
    let value = buf.get(header..end)?;
    Some((tag, value, &buf[end..]))
}

/// The subject `commonName` of a DER certificate.
///
/// Walks the real structure rather than searching for the OID bytes: the CN
/// OID also appears in the *issuer*, and a byte-search can match inside a
/// public key or signature, which would let a host choose what name we
/// display.
pub fn subject_common_name(cert: &[u8]) -> Option<String> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (tag, cert_body, _) = next_tlv(cert)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    let (tag, tbs, _) = next_tlv(cert_body)?;
    if tag != TAG_SEQUENCE {
        return None;
    }

    // TBSCertificate ::= SEQUENCE {
    //   [0] version OPTIONAL, serialNumber, signature, issuer, validity,
    //   subject, subjectPublicKeyInfo, … }
    let mut rest = tbs;
    let (tag, _, after) = next_tlv(rest)?;
    if tag == TAG_CONTEXT_0 {
        rest = after; // explicit version present
    }
    for _ in 0..4 {
        // serialNumber, signature, issuer, validity
        let (_, _, after) = next_tlv(rest)?;
        rest = after;
    }
    let (tag, subject, _) = next_tlv(rest)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    common_name_in(subject)
}

/// Find the `commonName` attribute inside an X.501 `Name`.
fn common_name_in(name: &[u8]) -> Option<String> {
    let mut rest = name;
    for _ in 0..MAX_RDNS {
        if rest.is_empty() {
            break;
        }
        let (tag, rdn, after) = next_tlv(rest)?;
        rest = after;
        if tag != TAG_SET {
            continue;
        }
        let mut attrs = rdn;
        for _ in 0..MAX_RDNS {
            if attrs.is_empty() {
                break;
            }
            let (tag, atv, after) = next_tlv(attrs)?;
            attrs = after;
            if tag != TAG_SEQUENCE {
                continue;
            }
            let (otag, oid, after_oid) = next_tlv(atv)?;
            if otag != TAG_OID || oid != OID_COMMON_NAME {
                continue;
            }
            let (_, value, _) = next_tlv(after_oid)?;
            return decode_string(value);
        }
    }
    None
}

/// Accept a directory string only if it is short, non-empty printable ASCII.
///
/// `BMPString`/`UniversalString` CNs are UTF-16/32 and fail this, which is
/// correct: a Windows machine certificate uses `PrintableString`, and anything
/// else here is not a name we should be rendering.
fn decode_string(value: &[u8]) -> Option<String> {
    if value.is_empty() || value.len() > MAX_CN_LEN {
        return None;
    }
    if !value.iter().all(|&b| (0x21..0x7F).contains(&b)) {
        return None;
    }
    Some(String::from_utf8_lossy(value).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The genuine self-signed RDP certificate served by the Windows host at
    /// 192.168.77.133, the machine that answers no name service at all and
    /// which this rung exists to name.
    const RDP_CERT_HEX: &str = concat!(
        "308202e2308201caa00302010202102cc65f988a12bcb9454d73d4cdab52c9300d06092a864886f70d01010b0500301a",
        "311830160603550403130f4445534b544f502d4832314b343743301e170d3236303632393231303735335a170d323631",
        "3232393231303735335a301a311830160603550403130f4445534b544f502d4832314b34374330820122300d06092a86",
        "4886f70d01010105000382010f003082010a0282010100d11a996ae44ec1e46aae74a975bc9a398d1ba757445e745cd4",
        "5239024df65cde69b96898078a00430048bfd53a22c37ef641af1c2abab65bf1990ed66c51476640a12b259d3f418c6f",
        "9120553e0760c20aef79a37e5bf8e6a294e1bf5eec8458a6bf51e742bbbdea580cba14249a6b8b41d71a2a439dcc7cf1",
        "63a42a53dc8917f2d36280e2a59eafb444fe19e491a4df5ec42817a08a5fe8e6b2c7f02cd2946bb2603349b9bf686e7a",
        "1202f372671ddbd4ff6d4951f7ddbf642fda2e63e282a6ab5cf764e2822c53c75491023d9b3b1bf733d65ce8cac09c6c",
        "02defb8e77619807fbbfa39bb4a3fc3fd80001023daa21a3034fa874ee3b94fa049726eb34cd710203010001a3243022",
        "30130603551d25040c300a06082b06010505070301300b0603551d0f040403020430300d06092a864886f70d01010b05",
        "0003820101001851e007404f17c23d537fc3e69c7b3f9e9efeb782a96fd3dc463eff0e01934fd86507fb640c585de26b",
        "b079affdb5175d610ddd5a99806abbd547c4cb054f6edf7e919eaa380f5611ea62a85521f246d587f56bd55c1d7f2331",
        "1a569e007e98096ec2468cc17e3a7d7e3c3a957b999607b5bb84c64df282647b0150aec2608366c222f164042a62eba9",
        "2ea77b21308c39079f057628f474f2fd455a8f8a4d2f1f22967c91bfb6d188fc0a64f9fb70d57bbc6e96a53a1ad76523",
        "5bab4e468c8e70fa891151d66cc6af42af4954ca70b9a93f03cd58bce86825eb7c5d3df9c4609ed7f40147595084068c",
        "515a5065a6d32e1d3738a700ac9896e5c70f40ae3c8a",
    );

    fn cert() -> Vec<u8> {
        hex::decode(RDP_CERT_HEX).expect("fixture must be valid hex")
    }

    /// Wrap a payload in a TLS handshake record, as the wire would.
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut r = vec![RECORD_HANDSHAKE, 0x03, 0x03];
        r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        r.extend_from_slice(payload);
        r
    }

    /// A `Certificate` handshake message carrying one certificate.
    fn certificate_message(der: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        let list_len = der.len() + 3;
        body.extend_from_slice(&(list_len as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(der);

        let mut msg = vec![HANDSHAKE_CERTIFICATE];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn the_real_windows_certificate_yields_the_machine_name() {
        assert_eq!(
            subject_common_name(&cert()).as_deref(),
            Some("DESKTOP-H21K47C")
        );
    }

    #[test]
    fn the_certificate_is_found_across_a_record_boundary() {
        // Windows splits its flight; the Certificate message routinely spans
        // records, which is the case a naive per-record parser misses.
        let msg = certificate_message(&cert());
        let (a, b) = msg.split_at(200);
        let mut stream = record(&[0x02, 0, 0, 0]); // a (bogus) ServerHello first
        stream.extend_from_slice(&record(a));
        stream.extend_from_slice(&record(b));

        let found = first_certificate(&stream).expect("certificate must be reassembled");
        assert_eq!(found, cert());
        assert_eq!(
            subject_common_name(&found).as_deref(),
            Some("DESKTOP-H21K47C")
        );
    }

    #[test]
    fn a_partial_flight_yields_nothing_rather_than_guessing() {
        let stream = record(&certificate_message(&cert()));
        for take in 0..stream.len() {
            if let Some(der) = first_certificate(&stream[..take]) {
                // The only way to succeed early is to genuinely have it all.
                assert_eq!(der, cert());
                assert!(take >= stream.len() - 1);
            }
        }
    }

    #[test]
    fn truncating_the_certificate_never_panics() {
        let full = cert();
        for take in 0..full.len() {
            let _ = subject_common_name(&full[..take]);
        }
    }

    #[test]
    fn a_hostile_length_is_refused() {
        let mut stream = record(&certificate_message(&cert()));
        // Claim a 60 KiB record.
        stream[3] = 0xff;
        stream[4] = 0xff;
        assert!(first_certificate(&stream).is_none());

        // Claim a certificate longer than the message that contains it.
        let mut msg = certificate_message(&cert());
        msg[7] = 0xff;
        msg[8] = 0xff;
        assert!(first_certificate(&record(&msg)).is_none());
    }

    #[test]
    fn an_indefinite_der_length_is_refused() {
        // 0x80 = indefinite length: legal BER, illegal DER, and a classic way
        // to make a parser run off the end.
        assert!(next_tlv(&[0x30, 0x80, 0x00, 0x00]).is_none());
        // Long-form length with an absurd byte count.
        assert!(next_tlv(&[0x30, 0x88, 1, 1, 1, 1, 1, 1, 1, 1]).is_none());
        // Length that overruns the buffer.
        assert!(next_tlv(&[0x30, 0x10, 0x00]).is_none());
    }

    #[test]
    fn the_issuer_common_name_is_not_mistaken_for_the_subject() {
        // Same shape as a real certificate but with different issuer/subject
        // CNs, so a parser that byte-searches for the OID picks the wrong one.
        let cn = |name: &str| {
            let mut atv = vec![TAG_OID, 3];
            atv.extend_from_slice(OID_COMMON_NAME);
            atv.push(0x13);
            atv.push(name.len() as u8);
            atv.extend_from_slice(name.as_bytes());
            let seq = wrap(TAG_SEQUENCE, &atv);
            let set = wrap(TAG_SET, &seq);
            wrap(TAG_SEQUENCE, &set)
        };
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&wrap(TAG_CONTEXT_0, &[0x02, 0x01, 0x02])); // version
        tbs.extend_from_slice(&[0x02, 0x01, 0x01]); // serial
        tbs.extend_from_slice(&wrap(TAG_SEQUENCE, &[])); // sig alg
        tbs.extend_from_slice(&cn("ISSUER-CA")); // issuer
        tbs.extend_from_slice(&wrap(TAG_SEQUENCE, &[])); // validity
        tbs.extend_from_slice(&cn("THE-REAL-HOST")); // subject
        let der = wrap(TAG_SEQUENCE, &wrap(TAG_SEQUENCE, &tbs));

        assert_eq!(
            subject_common_name(&der).as_deref(),
            Some("THE-REAL-HOST"),
            "the subject CN must win over the issuer CN"
        );
    }

    /// Wrap `body` in a DER TLV with a short-form length.
    fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
        assert!(body.len() < 128, "test helper only does short-form lengths");
        let mut out = vec![tag, body.len() as u8];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_name_of_escape_codes_is_dropped() {
        assert_eq!(decode_string(b"\x1b[2JOWNED"), None);
        assert_eq!(decode_string(b""), None);
        assert_eq!(decode_string(&[b'x'; 65]), None);
        assert_eq!(decode_string(b"OK-HOST").as_deref(), Some("OK-HOST"));
    }

    #[test]
    fn the_client_hello_is_well_formed_tls_12() {
        let hello = client_hello([0x11; 32]);
        assert_eq!(hello[0], RECORD_HANDSHAKE);
        assert_eq!(&hello[1..3], &[0x03, 0x01], "record version TLS 1.0");
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5, "record length must be exact");

        assert_eq!(hello[5], 0x01, "client_hello");
        let hs_len = u24(&hello, 6).unwrap();
        assert_eq!(hs_len, hello.len() - 9, "handshake length must be exact");

        assert_eq!(&hello[9..11], &[0x03, 0x03], "client_version TLS 1.2");
        assert_eq!(&hello[11..43], &[0x11; 32], "client random is carried");
        assert!(
            !hello.windows(2).any(|w| w == [0x00, 0x2b]),
            "no supported_versions extension: TLS 1.3 would encrypt the cert"
        );
    }

    #[test]
    fn a_non_tls_server_produces_no_name() {
        // An RFB banner, an SSH banner, and plain rubbish.
        assert!(first_certificate(b"RFB 003.008\n").is_none());
        assert!(first_certificate(b"SSH-2.0-OpenSSH_for_Windows_9.5\r\n").is_none());
        assert!(first_certificate(&[0xff; 64]).is_none());
        assert!(first_certificate(&[]).is_none());
    }
}
