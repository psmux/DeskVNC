//! The X.224 negotiation half of the 3389 probe: I/O and mapping, no bytes.
//!
//! **Nothing here authenticates.** The probe writes one X.224 Connection
//! Request, reads the Connection Confirm, optionally reads the certificate the
//! server offers next, and drops the socket. It never sends an MCS Connect
//! Initial, so no client name, no capability set and no credential ever leaves
//! this process. That is the same bargain as the RFB deep probe in
//! [`crate::probe`] and the certificate read in [`crate::tlsname`], and it is
//! held by the dependency graph as well as by this comment: this crate may
//! depend on `rdp-pdu` and on nothing else in the RDP set, so the code that
//! knows how to send a credential is not linked in (PRDRDP/00 R44).
//!
//! # Where the bytes come from
//!
//! The nineteen byte request and the parser for the answer are `rdp-pdu`'s,
//! the same ones the real client uses (MS-RDPBCGR 2.2.1.1 and 2.2.1.2). This
//! module is the socket and the mapping and nothing else. Two reasons, and the
//! second is the one that matters:
//!
//! * The probe's whole output is a claim about what a client could negotiate
//!   with this host. A second copy of the request bytes here would drift from
//!   the connect path's the first time a flag was added, silently, and a
//!   capability chip that lies is worse than no chip.
//! * Everything after `connect` is attacker controlled. One parser for that
//!   input means one fuzzed parser; two means one fuzzed parser and one
//!   unfuzzed one, and the unfuzzed one would be the one pointed at every
//!   address on the subnet during a sweep.
//!
//! What stays here is what belongs to the socket rather than to the bytes: the
//! read cap, the timeouts, and the mapping onto [`RdpCaps`].

use std::net::SocketAddr;
use std::time::Duration;

use rdp_pdu::io::{Decode, Encode, Reader, Writer};
use rdp_pdu::x224::{
    neg_rsp_flags, security_protocol, X224ConnectionConfirm, X224ConnectionRequest, X224Negotiation,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::tlsname;
use crate::types::{RdpCaps, RdpServerKind};

/// What the bulk sweep advertises: TLS and NLA.
///
/// `PROTOCOL_RDP` (standard RC4 security) and `PROTOCOL_RDSTLS` are
/// deliberately absent. This client supports neither, so advertising either
/// would invite a server to select something we would then have to refuse.
pub const SWEEP_PROTOCOLS: u32 = security_protocol::SSL | security_protocol::HYBRID;

/// What the second, on-demand probe advertises, to learn whether NLA is
/// *required*. A server configured for "Allow connections only from computers
/// running Remote Desktop with Network Level Authentication" answers this with
/// `RDP_NEG_FAILURE` and `HYBRID_REQUIRED_BY_SERVER`.
pub const SSL_ONLY_PROTOCOLS: u32 = security_protocol::SSL;

/// The most we will read while looking for a Connection Confirm.
///
/// A Connection Confirm is at most 4 + 7 + 8 = 19 bytes, and a server that
/// sends more is either not an RDP server or is trying something. The cap is
/// the probe's rather than the parser's: the connect path reads far larger
/// PDUs through the same decoder and must not inherit a 512 byte ceiling.
pub const MAX_NEGO_READ: usize = 512;

/// Read timeout for the confirm, matching `probe::BANNER_READ_TIMEOUT`.
const NEGO_READ_TIMEOUT: Duration = Duration::from_millis(200);

/// Budget for the certificate read that shares this connection. Separate from
/// the negotiation timeout because a TLS flight is several records and arrives
/// after the server has done real work, where a Connection Confirm is one
/// small write it had already prepared.
const CERT_READ_TIMEOUT: Duration = Duration::from_millis(800);

/// The X.224 Connection Request the probe writes, built by `rdp-pdu`.
///
/// No cookie and no correlation info, and both are omissions the encoder has
/// to be asked for rather than getting by accident. `mstsc` prefixes the
/// negotiation with `Cookie: mstshash=<username>\r\n`; that string is a
/// username, it reaches the server's event log and any load balancer in front
/// of it, and a discovery sweep has no username to send. Sending an invented
/// one would be worse than sending none. The 36 byte correlation info block
/// exists to tie a connection to a server side trace, and a probe has nothing
/// to correlate.
pub fn connection_request(requested_protocols: u32) -> Vec<u8> {
    let request = X224ConnectionRequest::new(requested_protocols);
    let mut bytes = Vec::with_capacity(request.size());
    let mut writer = Writer::new(&mut bytes);
    // The encoder's only failure modes are a cookie too long and a PDU too
    // large for the TPKT length field, and this request has no cookie and is
    // nineteen bytes. An empty request would be a bug rather than a network
    // condition, so it is not dressed up as one: the caller gets no bytes and
    // writes nothing.
    if request.encode_checked(&mut writer).is_err() {
        debug_assert!(false, "the fixed 19 byte connection request must encode");
        return Vec::new();
    }
    bytes
}

/// Decode a Connection Confirm from the bytes read so far.
///
/// `Ok(None)` means "not yet a whole PDU, read more". `Err(())` means the
/// bytes are not a Connection Confirm and never will be, so the caller stops
/// rather than reading up to the cap on a server that is not answering.
///
/// The decision of how many bytes make a frame is `rdp-pdu`'s TPKT length
/// peek, which validates the length before anything is sized from it.
#[allow(clippy::result_unit_err)]
pub fn decode_confirm(bytes: &[u8]) -> Result<Option<X224ConnectionConfirm>, ()> {
    let total = match rdp_pdu::x224::peek_tpkt_length(bytes) {
        Ok(Some(total)) => total,
        // Fewer than four bytes so far: the length is not knowable yet.
        Ok(None) => return Ok(None),
        // A wrong TPKT version, or a length below the header. Neither becomes
        // valid by reading more.
        Err(_) => return Err(()),
    };
    if total > MAX_NEGO_READ {
        return Err(());
    }
    if bytes.len() < total {
        return Ok(None);
    }
    let frame = bytes.get(..total).ok_or(())?;
    let mut reader = Reader::new(frame);
    X224ConnectionConfirm::decode(&mut reader)
        .map(Some)
        .map_err(|_| ())
}

/// Map a decoded Connection Confirm onto what the interface shows.
///
/// A pure function, so the whole of what the probe claims about a host can be
/// tested without a socket. It claims exactly what MS-RDPBCGR 2.2.1.2.1 says
/// and no more: `nla_required` stays `None` here whatever the confirm said,
/// because a single probe advertising both protocols cannot answer it.
pub fn caps_from_confirm(confirm: &X224ConnectionConfirm) -> RdpCaps {
    let mut caps = RdpCaps::default();
    match confirm.nego {
        Some(X224Negotiation::Response(rsp)) => {
            caps.selected_protocol = Some(rsp.selected_protocol);
            caps.tls = rsp.selected_protocol & security_protocol::SSL != 0;
            caps.nla = rsp.selected_protocol & security_protocol::HYBRID != 0;
            caps.extended_client_data =
                rsp.flags & neg_rsp_flags::EXTENDED_CLIENT_DATA_SUPPORTED != 0;
            caps.gfx = rsp.flags & neg_rsp_flags::DYNVC_GFX_PROTOCOL_SUPPORTED != 0;
            caps.restricted_admin = rsp.flags & neg_rsp_flags::RESTRICTED_ADMIN_MODE_SUPPORTED != 0;
            caps.redirected_auth =
                rsp.flags & neg_rsp_flags::REDIRECTED_AUTHENTICATION_MODE_SUPPORTED != 0;
        }
        Some(X224Negotiation::Failure(failure)) => {
            caps.failure_code = Some(failure.failure_code);
        }
        // No rdpNegData at all: the server does not understand Enhanced RDP
        // Security and is offering standard RDP security.
        None => caps.standard_only = true,
    }
    caps
}

/// Fold the second, SSL-only probe's answer into the first probe's result.
///
/// `HYBRID_REQUIRED_BY_SERVER` is the answer that proves NLA is enforced. Any
/// other outcome means TLS alone was acceptable, so NLA is available and not
/// required. A probe that never got an answer leaves the field `None`, which
/// is why this takes an `Option`.
pub fn apply_ssl_only_answer(caps: &mut RdpCaps, ssl_only: Option<&RdpCaps>) {
    let Some(ssl_only) = ssl_only else {
        return;
    };
    caps.nla_required =
        Some(ssl_only.failure_code == Some(rdp_pdu::x224::neg_failure::HYBRID_REQUIRED_BY_SERVER));
}

/// Probe one address.
///
/// Writes the request, reads the confirm, and, when the server selected TLS or
/// NLA, continues on the *same connection* to read the certificate subject. A
/// Connection Confirm selecting `PROTOCOL_SSL` or `PROTOCOL_HYBRID` means TLS
/// is exactly what the server expects next, so the `ClientHello` goes out on
/// the socket that is already open rather than on a second one to the same
/// port (PRDRDP/08 §4.6). The handshake is abandoned before key exchange, the
/// same way [`crate::tlsname`] abandons its own.
///
/// `None` when nothing that looks like an RDP server answered. That covers the
/// common case on a subnet with no RDP hosts, where the connect is refused in
/// about a millisecond and this returns before the read timeout is reached.
pub async fn probe(
    addr: SocketAddr,
    connect_timeout: Duration,
    requested_protocols: u32,
    read_certificate: bool,
) -> Option<RdpCaps> {
    let request = connection_request(requested_protocols);
    if request.is_empty() {
        return None;
    }

    let mut stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        _ => return None,
    };
    timeout(NEGO_READ_TIMEOUT, stream.write_all(&request))
        .await
        .ok()?
        .ok()?;

    let confirm = read_confirm(&mut stream).await?;
    let mut caps = caps_from_confirm(&confirm);

    if read_certificate && (caps.tls || caps.nla) {
        caps.cert_cn = read_certificate_cn(&mut stream).await;
    }
    caps.server_kind = classify(caps.cert_cn.as_deref());
    // Socket drops here. No MCS Connect Initial, no ClientKeyExchange, no
    // Finished, no CredSSP.
    Some(caps)
}

/// Read until a whole Connection Confirm has arrived, or until the cap.
async fn read_confirm(stream: &mut TcpStream) -> Option<X224ConnectionConfirm> {
    // Nineteen bytes is the whole answer, so this buffer never grows and
    // nothing is ever sized from a length the server sent.
    let mut buf = Vec::with_capacity(64);
    let mut chunk = [0u8; 64];
    loop {
        match decode_confirm(&buf) {
            Ok(Some(confirm)) => return Some(confirm),
            Ok(None) => {}
            Err(()) => return None,
        }
        if buf.len() >= MAX_NEGO_READ {
            return None;
        }
        let read = timeout(NEGO_READ_TIMEOUT, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            return None; // the server hung up
        }
        buf.extend_from_slice(chunk.get(..read)?);
    }
}

/// Read the subject `CN` of the certificate the server offers next.
///
/// Reuses [`crate::tlsname`] verbatim: the same `ClientHello`, the same
/// bounded record walk, the same DER walker, and the same rule that only short
/// printable ASCII is accepted. Nothing new parses a certificate here.
async fn read_certificate_cn(stream: &mut TcpStream) -> Option<String> {
    let hello = tlsname::client_hello(rand::random());
    timeout(CERT_READ_TIMEOUT, stream.write_all(&hello))
        .await
        .ok()?
        .ok()?;

    let mut flight = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        let read = timeout(CERT_READ_TIMEOUT, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            return None;
        }
        flight.extend_from_slice(chunk.get(..read)?);
        if let Some(der) = tlsname::first_certificate(&flight) {
            return tlsname::subject_common_name(&der);
        }
        if flight.len() >= tlsname::MAX_TLS_READ {
            return None;
        }
    }
}

/// What the certificate subject suggests is listening.
///
/// A hint for an icon and a label, and the only claim it makes is the one
/// [`crate::resolve::looks_like_a_windows_computer_name`] can support. A
/// hostile server can put any string in its `CN`, which is why nothing here
/// reaches a trust decision.
fn classify(cert_cn: Option<&str>) -> RdpServerKind {
    match cert_cn {
        None => RdpServerKind::Unknown,
        Some(cn) if crate::resolve::looks_like_a_windows_computer_name(cn) => {
            RdpServerKind::Windows
        }
        Some(_) => RdpServerKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::x224::{NegotiationFailure, NegotiationResponse};

    /// The exact nineteen bytes of MS-RDPBCGR 2.2.1.1 with an RDP_NEG_REQ for
    /// `PROTOCOL_SSL | PROTOCOL_HYBRID`, no cookie and no correlation info.
    ///
    /// `rdp-pdu` owns the encoder and asserts the same bytes; this asserts
    /// that the probe *asks* for that shape, which is the other half. It is
    /// also the test that catches a little endian slip in `requestedProtocols`
    /// against the big endian TPKT length.
    #[test]
    fn the_request_is_the_nineteen_bytes_we_promise() {
        let bytes = connection_request(SWEEP_PROTOCOLS);
        assert_eq!(
            bytes,
            vec![
                0x03, 0x00, // TPKT version 3, reserved
                0x00, 0x13, // TPKT length 19, big endian
                0x0e, // X.224 length indicator, 14
                0xe0, // CR CDT
                0x00, 0x00, // DST-REF
                0x00, 0x00, // SRC-REF
                0x00, // classOptions
                0x01, // TYPE_RDP_NEG_REQ
                0x00, // flags: no correlation info, no restricted admin
                0x08, 0x00, // length 8, little endian
                0x03, 0x00, 0x00, 0x00, // PROTOCOL_SSL | PROTOCOL_HYBRID
            ]
        );
        // No cookie: the request carries no `mstshash` and no username.
        assert!(!bytes.windows(8).any(|w| w == b"mstshash"));
    }

    #[test]
    fn the_ssl_only_request_asks_for_ssl_alone() {
        let bytes = connection_request(SSL_ONLY_PROTOCOLS);
        assert_eq!(bytes.len(), 19);
        assert_eq!(&bytes[15..19], &[0x01, 0x00, 0x00, 0x00]);
    }

    fn confirm_bytes(nego: Option<X224Negotiation>) -> Vec<u8> {
        let confirm = X224ConnectionConfirm {
            dst_ref: 0,
            src_ref: 0x1234,
            class_options: 0,
            nego,
        };
        let mut bytes = Vec::new();
        confirm.encode(&mut Writer::new(&mut bytes)).unwrap();
        bytes
    }

    #[test]
    fn a_negotiation_response_maps_onto_caps() {
        let bytes = confirm_bytes(Some(X224Negotiation::Response(NegotiationResponse {
            flags: neg_rsp_flags::EXTENDED_CLIENT_DATA_SUPPORTED
                | neg_rsp_flags::DYNVC_GFX_PROTOCOL_SUPPORTED,
            selected_protocol: security_protocol::HYBRID,
        })));
        let confirm = decode_confirm(&bytes).unwrap().unwrap();
        let caps = caps_from_confirm(&confirm);

        assert!(caps.nla);
        assert!(!caps.tls, "HYBRID alone is not SSL");
        assert!(caps.gfx, "the graphics pipeline flag is what says EGFX");
        assert!(caps.extended_client_data);
        assert!(!caps.restricted_admin);
        assert_eq!(caps.selected_protocol, Some(security_protocol::HYBRID));
        assert_eq!(
            caps.nla_required, None,
            "one probe cannot know whether NLA is required"
        );
        assert!(!caps.standard_only);
        assert_eq!(caps.failure_code, None);
    }

    /// A protocol bit we do not implement is information, not an error: it
    /// means the server offers something we do not, and treating it as an
    /// error would hide the host.
    #[test]
    fn an_unknown_selected_protocol_bit_is_kept_not_rejected() {
        let bytes = confirm_bytes(Some(X224Negotiation::Response(NegotiationResponse {
            flags: 0xff,
            selected_protocol: 0x8000_0001,
        })));
        let caps = caps_from_confirm(&decode_confirm(&bytes).unwrap().unwrap());
        assert!(caps.tls);
        assert_eq!(caps.selected_protocol, Some(0x8000_0001));
    }

    #[test]
    fn a_negotiation_failure_maps_onto_a_code() {
        let bytes = confirm_bytes(Some(X224Negotiation::Failure(NegotiationFailure {
            failure_code: rdp_pdu::x224::neg_failure::HYBRID_REQUIRED_BY_SERVER,
        })));
        let caps = caps_from_confirm(&decode_confirm(&bytes).unwrap().unwrap());
        assert_eq!(caps.failure_code, Some(5));
        assert!(!caps.tls && !caps.nla && !caps.standard_only);
    }

    /// A confirm with no `rdpNegData` is a real case rather than a malformed
    /// one: it means standard RDP security, which we cannot speak. The host is
    /// listed and marked, not hidden.
    #[test]
    fn a_confirm_without_neg_data_means_standard_security() {
        let caps = caps_from_confirm(&decode_confirm(&confirm_bytes(None)).unwrap().unwrap());
        assert!(caps.standard_only);
        assert!(!caps.tls && !caps.nla);
        assert_eq!(caps.selected_protocol, None);
    }

    #[test]
    fn the_ssl_only_answer_decides_whether_nla_is_required() {
        let mut caps = RdpCaps {
            nla: true,
            ..RdpCaps::default()
        };
        apply_ssl_only_answer(&mut caps, None);
        assert_eq!(caps.nla_required, None, "not asked is not a `false`");

        let refused = RdpCaps {
            failure_code: Some(rdp_pdu::x224::neg_failure::HYBRID_REQUIRED_BY_SERVER),
            ..RdpCaps::default()
        };
        apply_ssl_only_answer(&mut caps, Some(&refused));
        assert_eq!(caps.nla_required, Some(true));

        let accepted = RdpCaps {
            tls: true,
            selected_protocol: Some(security_protocol::SSL),
            ..RdpCaps::default()
        };
        apply_ssl_only_answer(&mut caps, Some(&accepted));
        assert_eq!(caps.nla_required, Some(false));
    }

    /// Truncation at every offset, and the shapes a hostile server would try.
    /// None of them may panic, and none may make the reader ask for more than
    /// the cap.
    #[test]
    fn hostile_answers_are_rejected_and_never_panic() {
        let full = confirm_bytes(Some(X224Negotiation::Response(NegotiationResponse {
            flags: 0,
            selected_protocol: security_protocol::HYBRID,
        })));
        for cut in 0..full.len() {
            // A truncation is "not yet", not an error, until the frame length
            // is known and exceeded.
            assert!(
                matches!(decode_confirm(&full[..cut]), Ok(None) | Err(())),
                "a {cut} byte prefix must not decode as a whole confirm"
            );
        }
        assert!(decode_confirm(&full).unwrap().is_some());

        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x03],
            // Wrong TPKT version.
            vec![0x04, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0, 0, 0],
            // TPKT length 0.
            vec![0x03, 0x00, 0x00, 0x00, 0x0e, 0xd0, 0, 0, 0, 0, 0],
            // TPKT length 3, below the header itself.
            vec![0x03, 0x00, 0x00, 0x03, 0x0e],
            // TPKT length 65535: must be refused rather than reserved for.
            vec![0x03, 0x00, 0xff, 0xff, 0x0e, 0xd0, 0, 0, 0, 0, 0],
            // An X.224 code that is not Connection Confirm.
            vec![0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0, 0, 0, 0, 0],
            // rdpNegData type 0x00 and 0xff.
            vec![
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 0x00, 0x00, 0x08, 0x00,
                0x02, 0x00, 0x00, 0x00,
            ],
            vec![
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 0xff, 0x00, 0x08, 0x00,
                0x02, 0x00, 0x00, 0x00,
            ],
            // rdpNegData length 0x0000 and 0xffff.
            vec![
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 0x02, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x00, 0x00,
            ],
            vec![
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 0x02, 0x00, 0xff, 0xff,
                0x02, 0x00, 0x00, 0x00,
            ],
            // An X.224 length indicator that runs past the frame.
            vec![0x03, 0x00, 0x00, 0x0b, 0x7f, 0xd0, 0, 0, 0, 0, 0],
        ];
        for case in cases {
            if let Ok(Some(confirm)) = decode_confirm(&case) {
                panic!("{case:02x?} must not decode, got {confirm:?}");
            }
        }
    }

    /// Every prefix of every hostile case, which is where a parser that
    /// indexes rather than reads falls over.
    #[test]
    fn every_prefix_of_every_shape_is_safe() {
        let mut corpus: Vec<Vec<u8>> = vec![
            confirm_bytes(None),
            confirm_bytes(Some(X224Negotiation::Failure(NegotiationFailure {
                failure_code: 0xdead_beef,
            }))),
        ];
        corpus.push((0u8..=255).collect());
        corpus.push(vec![0xff; MAX_NEGO_READ + 64]);
        for case in corpus {
            for cut in 0..=case.len() {
                let _ = decode_confirm(&case[..cut]);
            }
        }
    }

    #[test]
    fn a_frame_larger_than_the_cap_is_refused_before_it_is_read() {
        let mut oversize = vec![0x03, 0x00];
        oversize.extend_from_slice(&((MAX_NEGO_READ + 1) as u16).to_be_bytes());
        oversize.extend_from_slice(&[0x0e, 0xd0, 0, 0, 0, 0, 0]);
        assert!(decode_confirm(&oversize).is_err());
    }

    #[test]
    fn the_server_kind_is_a_hint_from_the_certificate_only() {
        assert_eq!(classify(None), RdpServerKind::Unknown);
        assert_eq!(classify(Some("DESKTOP-H21K47C")), RdpServerKind::Windows);
        assert_eq!(classify(Some("www.xrdp.org")), RdpServerKind::Other);
    }
}
