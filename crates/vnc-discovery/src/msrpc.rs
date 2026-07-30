//! Reading a Windows machine name out of the MSRPC endpoint mapper (TCP 135).
//!
//! The endpoint mapper is how RPC clients find out which port or named pipe a
//! given interface lives on, and enumerating it (`ept_lookup`) is **anonymous
//! by design**, no credential is offered and none is asked for; the `bind` and
//! `request` PDUs built here both carry `auth_length = 0` and no authentication
//! verifier of any kind. This is the same unauthenticated query `rpcdump` makes.
//!
//! Why it earns a place in the ladder: many of the endpoints it returns are
//! *named pipes*, and an `ncacn_np` tower spells its pipe out in full, //! `\\SUPERFLOW\PIPE\lsass`. That leading `\\NAME` is the machine's NetBIOS
//! computer name, which is exactly what [`crate::netbios`] would have told us
//! had the host not firewalled UDP 137. On a current Windows box with NetBIOS
//! blocked, LLMNR off, no local DNS and no mDNS, this and the RDP certificate
//! ([`crate::tlsname`]) are the only things left that will say what the machine
//! is called.
//!
//! **This is a targeted string extraction, not an NDR decoder.** Properly
//! decoding `ept_lookup`'s reply means implementing NDR conformant-varying
//! arrays of protocol towers, a large, security-sensitive surface to maintain
//! for one string. Instead the reply is treated as opaque bytes and scanned for
//! a `\\NAME\0` that satisfies NetBIOS computer-name rules. That is sound here
//! because the extracted name is **only ever displayed**, never used to make a
//! connection or trust decision, and because every other rung of the ladder is
//! equally a case of a host telling us what it would like to be called. The
//! validation below is what stops it telling us something else.

/// MSRPC endpoint mapper port.
pub const EPM_PORT: u16 = 135;

/// Stop reading the reply after this much.
///
/// The name sits in the named-pipe towers, which in practice land 15-20 KiB
/// into a ~40-60 KiB reply, so this must be generous to be useful, but it is
/// still a hard cap on what a hostile host can make us buffer. On a LAN the
/// whole reply arrives in well under 50 ms.
pub const MAX_EPM_READ: usize = 96 * 1024;

/// `bind` PDU type.
const PTYPE_BIND: u8 = 11;
/// `bind_ack` PDU type.
const PTYPE_BIND_ACK: u8 = 12;
/// `request` PDU type.
const PTYPE_REQUEST: u8 = 0;
/// `fault` PDU type, the server refusing us.
const PTYPE_FAULT: u8 = 3;
/// `PFC_FIRST_FRAG | PFC_LAST_FRAG`.
const PFC_SINGLE_FRAG: u8 = 0x03;
/// Data representation: little-endian, ASCII, IEEE float.
const DREP: [u8; 4] = [0x10, 0x00, 0x00, 0x00];
/// Fixed DCE/RPC header length.
const HEADER_LEN: usize = 16;

/// `ept` interface `e1af8308-5d1f-11c9-91a4-08002b14a0fa` v3.0, little-endian.
const EPM_UUID: [u8; 16] = [
    0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
];
/// NDR transfer syntax `8a885d04-1ceb-11c9-9fe8-08002b104860` v2, little-endian.
const NDR_UUID: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

/// `ept_lookup` operation number.
const OPNUM_EPT_LOOKUP: u16 = 2;
/// `RPC_C_EP_ALL_ELTS`, enumerate everything, filtered by nothing.
const INQUIRY_ALL: u32 = 0;
/// Entries requested per call. One call is plenty; we never page.
const MAX_ENTRIES: u32 = 500;

/// A NetBIOS computer name is at most 15 characters.
const MAX_NAME_LEN: usize = 15;

/// Build the fixed 16-byte DCE/RPC common header.
fn header(ptype: u8, frag_length: u16, call_id: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.push(5); // rpc_vers
    h.push(0); // rpc_vers_minor
    h.push(ptype);
    h.push(PFC_SINGLE_FRAG);
    h.extend_from_slice(&DREP);
    h.extend_from_slice(&frag_length.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // auth_length: none, ever
    h.extend_from_slice(&call_id.to_le_bytes());
    h
}

/// Build the `bind` PDU binding the `ept` interface with NDR transfer syntax.
pub fn bind_pdu() -> Vec<u8> {
    let mut body = Vec::with_capacity(56);
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
    body.push(1); // n_context_elem
    body.push(0); // reserved
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved2

    body.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    body.push(1); // n_transfer_syn
    body.push(0); // reserved
    body.extend_from_slice(&EPM_UUID);
    body.extend_from_slice(&3u16.to_le_bytes()); // interface major
    body.extend_from_slice(&0u16.to_le_bytes()); // interface minor
    body.extend_from_slice(&NDR_UUID);
    body.extend_from_slice(&2u32.to_le_bytes()); // NDR version

    let mut pdu = header(PTYPE_BIND, (HEADER_LEN + body.len()) as u16, 1);
    pdu.extend_from_slice(&body);
    pdu
}

/// Build the `ept_lookup` request PDU.
pub fn ept_lookup_pdu() -> Vec<u8> {
    let mut stub = Vec::with_capacity(40);
    stub.extend_from_slice(&INQUIRY_ALL.to_le_bytes());
    stub.extend_from_slice(&0u32.to_le_bytes()); // object: NULL pointer
    stub.extend_from_slice(&0u32.to_le_bytes()); // Ifid: NULL pointer
    stub.extend_from_slice(&0u32.to_le_bytes()); // vers_option
    stub.extend_from_slice(&[0u8; 20]); // entry_handle: nil
    stub.extend_from_slice(&MAX_ENTRIES.to_le_bytes());

    let frag_length = (HEADER_LEN + 8 + stub.len()) as u16;
    let mut pdu = header(PTYPE_REQUEST, frag_length, 2);
    pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    pdu.extend_from_slice(&OPNUM_EPT_LOOKUP.to_le_bytes());
    pdu.extend_from_slice(&stub);
    pdu
}

/// True if `buf` starts with a DCE/RPC PDU of the given type.
fn is_pdu(buf: &[u8], ptype: u8) -> bool {
    buf.len() >= HEADER_LEN && buf[0] == 5 && buf[2] == ptype
}

/// True if the server accepted our bind.
pub fn is_bind_ack(buf: &[u8]) -> bool {
    is_pdu(buf, PTYPE_BIND_ACK)
}

/// True if the server refused the call outright.
pub fn is_fault(buf: &[u8]) -> bool {
    is_pdu(buf, PTYPE_FAULT)
}

/// True for a byte that may appear in a Windows computer name.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Find the server's NetBIOS computer name in an `ept_lookup` reply.
///
/// Scans for the `\\NAME` prefix of an `ncacn_np` tower and returns the first
/// one that is a legal computer name: 1-15 bytes of alphanumerics, `-` or `_`,
/// starting with an alphanumeric, NUL-terminated within the buffer.
pub fn find_server_name(buf: &[u8]) -> Option<String> {
    let mut at = 0usize;
    while at + 2 < buf.len() {
        if buf[at] != b'\\' || buf[at + 1] != b'\\' {
            at += 1;
            continue;
        }
        let start = at + 2;
        // The name must begin with an alphanumeric: this rejects `\\\` and
        // other punctuation runs that are not a host name.
        if !buf.get(start).is_some_and(|b| b.is_ascii_alphanumeric()) {
            at += 1;
            continue;
        }
        let mut end = start;
        while end < buf.len() && end - start < MAX_NAME_LEN && is_name_byte(buf[end]) {
            end += 1;
        }
        // Must be NUL-terminated: a name running straight into other data is
        // not a name, it is us reading into the middle of a structure.
        if buf.get(end) == Some(&0) && end > start {
            return Some(String::from_utf8_lossy(&buf[start..end]).into_owned());
        }
        at += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact 72-byte `bind` PDU verified against real Windows hosts.
    const BIND_HEX: &str = concat!(
        "05000b03100000004800000001000000d016d0160000000001000000000001000883afe11f5dc91191a408002b14a0fa",
        "03000000045d888aeb1cc9119fe808002b1048600200000",
        "0",
    );

    /// The exact 64-byte `ept_lookup` request PDU.
    const REQUEST_HEX: &str = concat!(
        "0500000310000000400000000200000028000000000002000000000000000000000000000000000000000000000000",
        "00000000000000000000000000f4010000",
    );

    #[test]
    fn the_bind_pdu_is_byte_exact() {
        assert_eq!(bind_pdu(), hex::decode(BIND_HEX).unwrap());
        assert_eq!(bind_pdu().len(), 72);
    }

    #[test]
    fn the_request_pdu_is_byte_exact() {
        assert_eq!(ept_lookup_pdu(), hex::decode(REQUEST_HEX).unwrap());
        assert_eq!(ept_lookup_pdu().len(), 64);
    }

    #[test]
    fn no_pdu_ever_carries_an_authentication_verifier() {
        // auth_length lives at offset 10..12 and must be zero in both PDUs, // a non-zero value would mean we had attached NTLMSSP/Kerberos, i.e.
        // an authentication attempt.
        for pdu in [bind_pdu(), ept_lookup_pdu()] {
            assert_eq!(
                u16::from_le_bytes([pdu[10], pdu[11]]),
                0,
                "auth_length must be zero: discovery never authenticates"
            );
            // frag_length must describe the buffer exactly.
            assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
        }
    }

    #[test]
    fn pdu_types_are_recognised() {
        assert!(is_bind_ack(&{
            let mut b = bind_pdu();
            b[2] = PTYPE_BIND_ACK;
            b
        }));
        assert!(!is_bind_ack(&bind_pdu()));
        assert!(!is_bind_ack(&[5, 0, 12]), "a stub header is not a bind_ack");
        assert!(is_fault(&{
            let mut b = bind_pdu();
            b[2] = PTYPE_FAULT;
            b
        }));
    }

    /// A slice of a genuine `ept_lookup` reply: the tail of a tower, an
    /// `ncacn_np` binding naming the host, and the pipe that follows it.
    fn real_tower_fragment(name: &str) -> Vec<u8> {
        let mut v = vec![0x13, 0x00, 0x0d];
        v.extend_from_slice(format!("\\\\{name}").as_bytes());
        v.push(0);
        v.extend_from_slice(b"\x01\x00\x1f\x00\x0f");
        v.extend_from_slice(b"\\PIPE\\lsass");
        v.push(0);
        v
    }

    #[test]
    fn the_machine_name_is_read_out_of_a_named_pipe_tower() {
        let mut reply = vec![0u8; 512];
        reply.extend_from_slice(&real_tower_fragment("SUPERFLOW"));
        reply.extend_from_slice(&[0u8; 64]);
        assert_eq!(find_server_name(&reply).as_deref(), Some("SUPERFLOW"));
    }

    #[test]
    fn a_hyphenated_name_survives_intact() {
        let reply = real_tower_fragment("DESKTOP-646U3OK");
        assert_eq!(find_server_name(&reply).as_deref(), Some("DESKTOP-646U3OK"));
    }

    #[test]
    fn a_pipe_path_is_not_mistaken_for_a_machine_name() {
        // `\PIPE\lsass` has a single backslash and must never match.
        let mut reply = b"\\PIPE\\lsass\x00\\pipe\\eventlog\x00".to_vec();
        assert_eq!(find_server_name(&reply), None);
        // Even preceded by other data.
        reply.splice(0..0, [0u8; 32]);
        assert_eq!(find_server_name(&reply), None);
    }

    #[test]
    fn an_unterminated_name_is_refused() {
        // Runs to the end of the buffer with no NUL: we are reading into the
        // middle of a structure, not at a string.
        assert_eq!(find_server_name(b"\\\\SUPERFLOW"), None);
        // Terminated by something that is not a NUL.
        assert_eq!(find_server_name(b"\\\\SUPERFLOW\xff\xff"), None);
    }

    #[test]
    fn an_over_long_name_is_refused() {
        // 16 characters: longer than any NetBIOS computer name.
        let mut v = b"\\\\".to_vec();
        v.extend_from_slice(&[b'A'; 16]);
        v.push(0);
        assert_eq!(find_server_name(&v), None);
    }

    #[test]
    fn escape_codes_and_punctuation_never_produce_a_name() {
        assert_eq!(find_server_name(b"\\\\\x1b[2J\x00"), None);
        assert_eq!(
            find_server_name(b"\\\\-LEADING\x00"),
            None,
            "must start alnum"
        );
        assert_eq!(find_server_name(b"\\\\\x00"), None, "empty");
        assert_eq!(find_server_name(b"\\\\..\\..\\etc\x00"), None);
        assert_eq!(find_server_name(b""), None);
        assert_eq!(find_server_name(b"\\"), None);
    }

    #[test]
    fn scanning_never_panics_on_arbitrary_bytes() {
        let junk: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let _ = find_server_name(&junk);
        for take in 0..300 {
            let _ = find_server_name(&junk[..take]);
        }
        let slashes = vec![b'\\'; 1024];
        assert_eq!(find_server_name(&slashes), None);
    }
}
