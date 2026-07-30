//! Minimal DNS wire-format encoder/decoder.
//!
//! Three of the four hostname-resolution paths in [`crate::resolve`] speak
//! DNS-shaped messages on different transports: mDNS (multicast 5353), LLMNR
//! (multicast 5355) and NetBIOS name service (unicast 137). They share this
//! module rather than a DNS library, the subset we need is a query builder
//! and an answer walker, and a resolver crate would drag in a full recursive
//! stack we have no use for (PRD/04 §6).
//!
//! **Everything here parses attacker-controlled bytes.** Any host on the LAN
//! can answer these queries, and the reply is rendered in the UI. So every
//! read is bounds-checked, compression pointers may only point strictly
//! backwards and are capped, names are capped at the protocol maximum, and the
//! question/answer counts are capped well below what the 16-bit fields allow.

use std::net::Ipv4Addr;

/// `PTR` resource-record type.
pub const TYPE_PTR: u16 = 12;
/// NetBIOS `NBSTAT` (node status) query type.
pub const TYPE_NBSTAT: u16 = 0x0021;
/// `IN` class.
pub const CLASS_IN: u16 = 1;

/// Largest datagram we will read. Real answers here are 50-250 bytes; this is
/// simply the ceiling on how much a hostile host can make us buffer.
pub const MAX_MESSAGE: usize = 4096;

/// Fixed DNS header size.
const HEADER_LEN: usize = 12;
/// Maximum length of a decoded name (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 255;
/// Maximum compression-pointer indirections before we call it a loop.
const MAX_JUMPS: usize = 16;
/// Maximum labels in one name.
const MAX_LABELS: usize = 64;
/// Maximum questions we will walk past in a response.
const MAX_QUESTIONS: usize = 8;
/// Maximum answer records we will walk.
const MAX_ANSWERS: usize = 32;
/// `QR` bit in the header flags: set on a response.
const FLAG_RESPONSE: u16 = 0x8000;

/// One answer record located inside a response buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// Record type (e.g. [`TYPE_PTR`]).
    pub rtype: u16,
    /// Offset of the RDATA within the message.
    pub rdata_at: usize,
    /// Length of the RDATA, already verified to lie inside the message.
    pub rdata_len: usize,
}

impl Answer {
    /// The RDATA bytes of this answer.
    pub fn rdata<'a>(&self, msg: &'a [u8]) -> &'a [u8] {
        &msg[self.rdata_at..self.rdata_at + self.rdata_len]
    }
}

/// Encode a domain name as a length-prefixed label sequence.
///
/// Returns `None` for a name that cannot be represented on the wire (an empty
/// or over-long label, or a name past [`MAX_NAME_LEN`]).
pub fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    (out.len() <= MAX_NAME_LEN).then_some(out)
}

/// Encoded `<d>.<c>.<b>.<a>.in-addr.arpa` question name for a reverse lookup.
pub fn reverse_ptr_qname(ip: Ipv4Addr) -> Vec<u8> {
    let [a, b, c, d] = ip.octets();
    // Every component is short and non-empty, so encoding cannot fail.
    encode_name(&format!("{d}.{c}.{b}.{a}.in-addr.arpa")).unwrap_or_else(|| vec![0])
}

/// Build a standard query: one question, no other sections.
pub fn build_query(id: u16, qname: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(HEADER_LEN + qname.len() + 4);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // flags: standard query
    msg.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    msg.extend_from_slice(&0u16.to_be_bytes()); // ancount
    msg.extend_from_slice(&0u16.to_be_bytes()); // nscount
    msg.extend_from_slice(&0u16.to_be_bytes()); // arcount
    msg.extend_from_slice(qname);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&qclass.to_be_bytes());
    msg
}

/// Read a big-endian `u16` at `pos`, bounds-checked.
fn u16_at(msg: &[u8], pos: usize) -> Option<u16> {
    let hi = *msg.get(pos)?;
    let lo = *msg.get(pos + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Decode the name starting at `pos`.
///
/// Returns the dotted name and the offset just past the name **in the outer
/// stream** (a compression pointer is two bytes wide however far it jumps).
/// `None` on any malformed input: a truncated label, a forward or self
/// pointer, too many jumps, or a name over [`MAX_NAME_LEN`].
pub fn read_name(msg: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut total = 0usize;
    let mut at = pos;
    let mut jumps = 0usize;
    // Offset to report back to the caller: fixed at the first pointer.
    let mut end: Option<usize> = None;

    loop {
        let len = *msg.get(at)?;
        match len & 0xC0 {
            0 => {
                if len == 0 {
                    let after = at + 1;
                    break Some((join_labels(&labels), end.unwrap_or(after)));
                }
                let start = at + 1;
                let stop = start + usize::from(len);
                let label = msg.get(start..stop)?;
                total += usize::from(len) + 1;
                if total > MAX_NAME_LEN || labels.len() >= MAX_LABELS {
                    break None;
                }
                labels.push(label);
                at = stop;
            }
            0xC0 => {
                // Compression pointer. Must point strictly backwards, so a
                // chain always terminates; the jump cap is belt and braces.
                let target = usize::from(u16_at(msg, at)? & 0x3FFF);
                if target >= at {
                    break None;
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    break None;
                }
                end.get_or_insert(at + 2);
                at = target;
            }
            // 0x40/0x80 are reserved label types (EDNS extended labels); we do
            // not speak them and will not guess.
            _ => break None,
        }
    }
}

/// Join decoded labels into a dotted name, replacing anything that is not
/// printable ASCII so a hostile answer cannot smuggle control characters into
/// the UI.
fn join_labels(labels: &[&[u8]]) -> String {
    let mut out = String::new();
    for (i, label) in labels.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        for &b in *label {
            out.push(if (0x20..0x7F).contains(&b) {
                b as char
            } else {
                '?'
            });
        }
    }
    out
}

/// Skip the name at `pos` without allocating it.
fn skip_name(msg: &[u8], pos: usize) -> Option<usize> {
    let mut at = pos;
    let mut steps = 0usize;
    loop {
        let len = *msg.get(at)?;
        match len & 0xC0 {
            0 if len == 0 => return Some(at + 1),
            0 => {
                at = at + 1 + usize::from(len);
                steps += 1;
                if steps > MAX_LABELS {
                    return None;
                }
            }
            0xC0 => {
                // A pointer always ends the name.
                u16_at(msg, at)?;
                return Some(at + 2);
            }
            _ => return None,
        }
    }
}

/// Walk a response and return its answer records.
///
/// `None` unless the message is a well-formed response to *our* query: header
/// present, matching transaction id, `QR` set, and every section walkable
/// within the buffer.
pub fn parse_answers(msg: &[u8], id: u16) -> Option<Vec<Answer>> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    if u16_at(msg, 0)? != id {
        return None;
    }
    let flags = u16_at(msg, 2)?;
    if flags & FLAG_RESPONSE == 0 {
        return None;
    }
    let qdcount = usize::from(u16_at(msg, 4)?);
    let ancount = usize::from(u16_at(msg, 6)?);
    if qdcount > MAX_QUESTIONS {
        return None;
    }

    let mut at = HEADER_LEN;
    for _ in 0..qdcount {
        at = skip_name(msg, at)?;
        // QTYPE + QCLASS
        at = at.checked_add(4)?;
        if at > msg.len() {
            return None;
        }
    }

    let mut answers = Vec::new();
    for _ in 0..ancount.min(MAX_ANSWERS) {
        at = skip_name(msg, at)?;
        let rtype = u16_at(msg, at)?;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        let rdata_len = usize::from(u16_at(msg, at + 8)?);
        let rdata_at = at.checked_add(10)?;
        let end = rdata_at.checked_add(rdata_len)?;
        if end > msg.len() {
            return None;
        }
        answers.push(Answer {
            rtype,
            rdata_at,
            rdata_len,
        });
        at = end;
    }
    Some(answers)
}

/// The name in the first `PTR` answer of a response to query `id`.
pub fn first_ptr_answer(msg: &[u8], id: u16) -> Option<String> {
    let answers = parse_answers(msg, id)?;
    answers
        .iter()
        .filter(|a| a.rtype == TYPE_PTR)
        .find_map(|a| read_name(msg, a.rdata_at).map(|(name, _)| name))
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Capture of a Mac answering an mDNS reverse-PTR query for 192.168.77.135
    /// on multicast 5353. The answer name is a compression pointer (`c0 0c`)
    /// back into the question, which is exactly the case a hand-rolled decoder
    /// gets wrong.
    ///
    /// The host label was rewritten to `Example-MacBook-Air`, the same 19-byte
    /// length as the captured name, so every length and RDLENGTH field is
    /// unchanged and the packet stays byte-exact.
    const MDNS_PTR_RESPONSE: &[u8] = &[
        0x4d, 0x4e, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x31, 0x33,
        0x35, 0x02, 0x37, 0x37, 0x03, 0x31, 0x36, 0x38, 0x03, 0x31, 0x39, 0x32, 0x07, 0x69, 0x6e,
        0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x1b, 0x13, 0x45, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2d, 0x4d, 0x61, 0x63, 0x42, 0x6f, 0x6f, 0x6b, 0x2d, 0x41,
        0x69, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
    ];

    /// Real capture: a Windows box answering an LLMNR reverse-PTR query for
    /// 192.168.77.126 on multicast 5355. No compression: the answer repeats
    /// the question name in full.
    const LLMNR_PTR_RESPONSE: &[u8] = &[
        0x4d, 0x4e, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x31, 0x32,
        0x36, 0x02, 0x37, 0x37, 0x03, 0x31, 0x36, 0x38, 0x03, 0x31, 0x39, 0x32, 0x07, 0x69, 0x6e,
        0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01,
        0x03, 0x31, 0x32, 0x36, 0x02, 0x37, 0x37, 0x03, 0x31, 0x36, 0x38, 0x03, 0x31, 0x39, 0x32,
        0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x11, 0x0f, 0x44, 0x45, 0x53, 0x4b, 0x54,
        0x4f, 0x50, 0x2d, 0x36, 0x34, 0x36, 0x55, 0x33, 0x4f, 0x4b, 0x00,
    ];

    #[test]
    fn reverse_qname_is_byte_exact() {
        let q = reverse_ptr_qname(Ipv4Addr::new(192, 168, 77, 135));
        assert_eq!(
            q,
            vec![
                3, b'1', b'3', b'5', 2, b'7', b'7', 3, b'1', b'6', b'8', 3, b'1', b'9', b'2', 7,
                b'i', b'n', b'-', b'a', b'd', b'd', b'r', 4, b'a', b'r', b'p', b'a', 0,
            ]
        );
    }

    #[test]
    fn query_matches_the_captured_bytes() {
        // The exact 45-byte query that produced MDNS_PTR_RESPONSE.
        let q = build_query(
            0x4d4e,
            &reverse_ptr_qname(Ipv4Addr::new(192, 168, 77, 135)),
            TYPE_PTR,
            CLASS_IN,
        );
        assert_eq!(q.len(), 45);
        assert_eq!(&q[..12], &[0x4d, 0x4e, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x0c, 0x00, 0x01]);
        assert_eq!(&q[12..q.len() - 4], &MDNS_PTR_RESPONSE[12..41]);
    }

    #[test]
    fn decodes_a_compressed_mdns_answer() {
        assert_eq!(
            first_ptr_answer(MDNS_PTR_RESPONSE, 0x4d4e).as_deref(),
            Some("Example-MacBook-Air.local")
        );
    }

    #[test]
    fn decodes_an_uncompressed_llmnr_answer() {
        assert_eq!(
            first_ptr_answer(LLMNR_PTR_RESPONSE, 0x4d4e).as_deref(),
            Some("DESKTOP-646U3OK")
        );
    }

    #[test]
    fn a_mismatched_transaction_id_is_rejected() {
        assert!(first_ptr_answer(MDNS_PTR_RESPONSE, 0x0001).is_none());
    }

    #[test]
    fn a_query_masquerading_as_an_answer_is_rejected() {
        let mut msg = MDNS_PTR_RESPONSE.to_vec();
        msg[2] = 0x00; // clear QR
        msg[3] = 0x00;
        assert!(first_ptr_answer(&msg, 0x4d4e).is_none());
    }

    #[test]
    fn truncation_at_every_length_is_survivable() {
        for take in 0..MDNS_PTR_RESPONSE.len() {
            let _ = first_ptr_answer(&MDNS_PTR_RESPONSE[..take], 0x4d4e);
        }
        // A response whose last label is cut off yields nothing, not a panic.
        let cut = &MDNS_PTR_RESPONSE[..MDNS_PTR_RESPONSE.len() - 3];
        assert!(first_ptr_answer(cut, 0x4d4e).is_none());
    }

    #[test]
    fn a_self_referential_pointer_terminates() {
        // Header claiming one answer; the answer name points at itself.
        let mut msg = vec![
            0x00, 0x01, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        msg.extend_from_slice(&[0xc0, 0x0c]); // pointer to offset 12 == itself
        msg.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0, 0, 0, 10, 0x00, 0x02, 0xc0, 0x0c]);
        assert!(first_ptr_answer(&msg, 0x0001).is_none());
    }

    #[test]
    fn a_forward_pointer_is_rejected() {
        let mut msg = vec![
            0x00, 0x01, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        msg.extend_from_slice(&[0x00]); // empty answer name
        msg.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0, 0, 0, 10, 0x00, 0x02]);
        msg.extend_from_slice(&[0xc0, 0x40]); // rdata: pointer past the end
        assert!(first_ptr_answer(&msg, 0x0001).is_none());
    }

    #[test]
    fn an_rdlength_past_the_end_is_rejected() {
        let mut msg = MDNS_PTR_RESPONSE.to_vec();
        // rdlength lives 2 bytes before the rdata; inflate it hugely.
        let rd_len_at = 45 + 2 + 8;
        msg[rd_len_at] = 0xff;
        msg[rd_len_at + 1] = 0xff;
        assert!(parse_answers(&msg, 0x4d4e).is_none());
    }

    #[test]
    fn an_answer_count_far_beyond_the_data_is_rejected() {
        let mut msg = MDNS_PTR_RESPONSE.to_vec();
        msg[6] = 0xff;
        msg[7] = 0xff;
        assert!(parse_answers(&msg, 0x4d4e).is_none());
    }

    #[test]
    fn control_characters_in_a_name_are_neutralised() {
        let mut msg = vec![
            0x00, 0x07, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0c, 0x00, 0x01, 0, 0, 0, 10, 0x00, 0x06,
        ];
        msg.extend_from_slice(&[0x04, b'a', 0x1b, b'[', b'2', 0x00]);
        assert_eq!(first_ptr_answer(&msg, 0x0007).as_deref(), Some("a?[2"));
    }

    #[test]
    fn encode_name_rejects_the_unencodable() {
        assert!(encode_name("a..b").is_none());
        assert!(encode_name(&"x".repeat(64)).is_none());
        assert!(encode_name(&vec!["abcdefgh"; 40].join(".")).is_none());
        assert_eq!(encode_name("a.b"), Some(vec![1, b'a', 1, b'b', 0]));
    }
}
