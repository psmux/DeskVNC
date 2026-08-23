//! Phase 1 of the connection sequence: X.224 negotiation and the security
//! protocol choice (MS-RDPBCGR 2.2.1.1 and 2.2.1.2, PRDRDP/03 §2.1).
//!
//! We send an X.224 Connection Request carrying `RDP_NEG_REQ` with
//! `PROTOCOL_SSL | PROTOCOL_HYBRID` and read the Connection Confirm. The
//! server answers with `RDP_NEG_RSP` naming one protocol, with
//! `RDP_NEG_FAILURE` naming a code, or with nothing at all.

use rdp_pdu::io::{Decode, Encode, Writer};
use rdp_pdu::x224::{
    self, neg_failure, security_protocol, X224ConnectionConfirm, X224ConnectionRequest, X224Cookie,
    X224Negotiation,
};
use rdp_pdu::Reader;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{ConnectStage, RdpError, Result};
use crate::options::ResolvedOptions;
use crate::transport::framer::{Expect, Framer};
use crate::transport::{with_timeout, X224_TIMEOUT};

/// The protocol the server selected.
///
/// A three variant enum rather than the raw `u32`, because the rest of the
/// sequence branches on exactly this and a bare number invites a comparison
/// against the wrong constant. `PROTOCOL_RDP` is not a variant: standard RDP
/// security is RC4 and this client never negotiates it (D6), so it is refused
/// at the point of decoding rather than carried forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProtocol {
    /// `PROTOCOL_SSL`: TLS, and the server's own logon screen collects the
    /// credentials.
    Ssl,
    /// `PROTOCOL_HYBRID`: TLS then CredSSP (MS-CSSP).
    Hybrid,
    /// `PROTOCOL_HYBRID_EX`: `Hybrid` plus the four byte Early User
    /// Authorization Result (MS-RDPBCGR 2.2.10.2).
    HybridEx,
}

impl SecurityProtocol {
    /// The `selectedProtocol` value this variant corresponds to.
    #[must_use]
    pub const fn wire(self) -> u32 {
        match self {
            SecurityProtocol::Ssl => security_protocol::SSL,
            SecurityProtocol::Hybrid => security_protocol::HYBRID,
            SecurityProtocol::HybridEx => security_protocol::HYBRID_EX,
        }
    }

    /// True when CredSSP runs after the TLS handshake.
    #[must_use]
    pub const fn wants_credssp(self) -> bool {
        matches!(self, SecurityProtocol::Hybrid | SecurityProtocol::HybridEx)
    }

    /// The `method` string that reaches
    /// [`remote_core::SessionState::Authenticating`] (PRDRDP/00 R12).
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            SecurityProtocol::Ssl => "tls",
            // Phase 1 and 2 are NTLMv2 only (D6). When the `kerberos` feature
            // lands this becomes a decision the mechanism makes, not one this
            // enum can answer.
            SecurityProtocol::Hybrid | SecurityProtocol::HybridEx => "nla-ntlm",
        }
    }
}

/// What we advertise in `RDP_NEG_REQ.requestedProtocols`.
///
/// `PROTOCOL_SSL | PROTOCOL_HYBRID`, and deliberately not
/// `PROTOCOL_HYBRID_EX`: the extended variant adds a four byte Early User
/// Authorization Result after the CredSSP exchange, and a client that reads
/// four bytes after a plain `HYBRID` desynchronises the stream. We will ask
/// for it when we want the early authorisation answer (PRDRDP/03 §2.3), not
/// before.
///
/// `PROTOCOL_RDP` is zero, so it is always implicitly in the set on the wire.
/// A server that selects it is refused (D6): standard RDP security is RC4
/// with a server chosen key, and no amount of profile setting makes that
/// acceptable.
pub const REQUESTED_PROTOCOLS: u32 = security_protocol::SSL | security_protocol::HYBRID;

/// Send the Connection Request and read the Connection Confirm.
///
/// # Errors
///
/// [`RdpError::NegotiationFailed`] when the server answered with
/// `RDP_NEG_FAILURE`, [`RdpError::NegotiationInconsistent`] when it selected
/// something we did not offer or something we refuse, and
/// [`RdpError::Timeout`] against [`ConnectStage::AwaitConnectionConfirm`].
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    framer: &mut Framer<S>,
    opts: &ResolvedOptions,
    username: Option<&str>,
) -> Result<SecurityProtocol> {
    let mut request = X224ConnectionRequest::new(REQUESTED_PROTOCOLS);
    if opts.send_mstshash_cookie {
        // PRDRDP/00 R29 defaults this off: the identifier travels in
        // cleartext ahead of the TLS upgrade and lands in server and load
        // balancer logs. It exists because a broker needs it to route.
        // `MAX_MSTSHASH_LEN` is nine characters and the encoder refuses a
        // longer one rather than truncating, so the truncation happens here
        // where it can be reasoned about.
        if let Some(user) = username.filter(|u| !u.is_empty()) {
            let short: String = user.chars().take(x224::MAX_MSTSHASH_LEN).collect();
            if short.is_ascii() {
                request.cookie = Some(X224Cookie::MstsHash(short));
            } else {
                tracing::debug!("mstshash cookie omitted: the user name is not ASCII");
            }
        }
    }

    let mut buf = Vec::with_capacity(request.size());
    request.encode_checked(&mut Writer::new(&mut buf))?;
    tracing::debug!(stage = %ConnectStage::SendConnectionRequest, "sending the x.224 connection request");
    framer.write_pdu(&buf).await?;

    let frame = with_timeout(
        ConnectStage::AwaitConnectionConfirm,
        X224_TIMEOUT,
        framer.read_expect(Expect::Tpkt),
    )
    .await?;
    let confirm = X224ConnectionConfirm::decode(&mut Reader::new(&frame))?;
    select_protocol(&confirm)
}

/// Turn a Connection Confirm into the protocol we will use, or into the error
/// that explains why we cannot.
///
/// Separate from [`negotiate`] and taking no stream, so every branch is a
/// unit test over a decoded structure rather than a socket.
///
/// # Errors
///
/// As [`negotiate`].
pub fn select_protocol(confirm: &X224ConnectionConfirm) -> Result<SecurityProtocol> {
    match confirm.nego {
        Some(X224Negotiation::Response(rsp)) => match rsp.selected_protocol {
            security_protocol::HYBRID_EX => Ok(SecurityProtocol::HybridEx),
            security_protocol::HYBRID => Ok(SecurityProtocol::Hybrid),
            security_protocol::SSL => Ok(SecurityProtocol::Ssl),
            // Includes `PROTOCOL_RDP` (0), which is standard RDP security
            // with RC4 (D6), and `RDSTLS` and `RDSAAD`, which we did not
            // offer. MS-RDPBCGR 2.2.1.2.1 lets a server select only from what
            // the request asked for, so anything else is the server being
            // wrong about the session and not something to carry on through.
            other => {
                tracing::warn!(
                    selected = format!("{other:#010x}"),
                    "unusable selectedProtocol"
                );
                Err(RdpError::NegotiationInconsistent)
            }
        },
        Some(X224Negotiation::Failure(fail)) => Err(RdpError::NegotiationFailed {
            code: fail.failure_code,
            reason: failure_reason(fail.failure_code).to_owned(),
        }),
        // No negotiation structure at all means the server does not
        // understand negotiation and has selected standard RDP security
        // (MS-RDPBCGR 2.2.1.2, and `X224ConnectionConfirm::nego` records that
        // this is a real case rather than a theoretical one). D6 refuses it.
        None => {
            tracing::warn!("the server answered without a negotiation structure");
            Err(RdpError::NegotiationInconsistent)
        }
    }
}

/// The sentence for an `RDP_NEG_FAILURE.failureCode` (MS-RDPBCGR 2.2.1.2.2,
/// PRDRDP/03 §9.2).
///
/// Every code the specification defines, so a user gets a sentence rather
/// than a number. An unknown code still reports its value through
/// [`RdpError::NegotiationFailed::code`], which is most of what a bug report
/// needs.
fn failure_reason(code: u32) -> &'static str {
    match code {
        neg_failure::SSL_REQUIRED_BY_SERVER => {
            "the server requires TLS and the client did not offer it"
        }
        neg_failure::SSL_NOT_ALLOWED_BY_SERVER => {
            "the server is configured for standard RDP security only, which this client refuses"
        }
        neg_failure::SSL_CERT_NOT_ON_SERVER => {
            "the server has no certificate installed for Remote Desktop"
        }
        neg_failure::INCONSISTENT_FLAGS => "the server rejected the negotiation flags we sent",
        neg_failure::HYBRID_REQUIRED_BY_SERVER => {
            "the server requires network level authentication"
        }
        neg_failure::SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER => {
            "the server requires network level authentication with user authorisation"
        }
        _ => "the server refused the connection without giving a reason we recognise",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::x224::{NegotiationFailure, NegotiationResponse};

    fn confirm(nego: Option<X224Negotiation>) -> X224ConnectionConfirm {
        X224ConnectionConfirm {
            dst_ref: 0,
            src_ref: 0x1234,
            class_options: 0,
            nego,
        }
    }

    fn response(selected: u32) -> X224ConnectionConfirm {
        confirm(Some(X224Negotiation::Response(NegotiationResponse {
            flags: 0,
            selected_protocol: selected,
        })))
    }

    #[test]
    fn the_three_protocols_we_can_use_are_accepted() {
        assert_eq!(
            select_protocol(&response(security_protocol::SSL)).unwrap(),
            SecurityProtocol::Ssl
        );
        assert_eq!(
            select_protocol(&response(security_protocol::HYBRID)).unwrap(),
            SecurityProtocol::Hybrid
        );
        assert_eq!(
            select_protocol(&response(security_protocol::HYBRID_EX)).unwrap(),
            SecurityProtocol::HybridEx
        );
    }

    /// Standard RDP security is RC4 with a server chosen key and D6 refuses
    /// it. `PROTOCOL_RDP` is zero, so this is also the "the server ignored
    /// what we asked for and sent an empty selection" case.
    #[test]
    fn standard_rdp_security_is_refused() {
        assert!(matches!(
            select_protocol(&response(security_protocol::RDP)),
            Err(RdpError::NegotiationInconsistent)
        ));
    }

    /// A server may select only from what the request asked for
    /// (MS-RDPBCGR 2.2.1.2.1), and we asked for neither of these.
    #[test]
    fn a_protocol_we_never_offered_is_refused() {
        for p in [security_protocol::RDSTLS, security_protocol::RDSAAD] {
            assert!(matches!(
                select_protocol(&response(p)),
                Err(RdpError::NegotiationInconsistent)
            ));
        }
    }

    /// A Connection Confirm with no negotiation structure means the server
    /// does not understand negotiation and has chosen standard RDP security.
    #[test]
    fn a_confirm_without_a_negotiation_structure_is_refused() {
        assert!(matches!(
            select_protocol(&confirm(None)),
            Err(RdpError::NegotiationInconsistent)
        ));
    }

    /// Every failure code the specification defines gets a sentence, and the
    /// raw value survives for the bug report.
    #[test]
    fn every_negotiation_failure_code_produces_a_sentence() {
        for code in 1..=6u32 {
            let c = confirm(Some(X224Negotiation::Failure(NegotiationFailure {
                failure_code: code,
            })));
            match select_protocol(&c) {
                Err(RdpError::NegotiationFailed { code: got, reason }) => {
                    assert_eq!(got, code);
                    assert!(!reason.is_empty());
                    assert!(
                        !reason.contains("we recognise"),
                        "code {code} fell through to the default sentence"
                    );
                }
                other => panic!("expected a negotiation failure, got {other:?}"),
            }
        }
    }

    /// An unrecognised code still reports its value, which is what a report
    /// against a server we have never seen needs.
    #[test]
    fn an_unknown_failure_code_keeps_its_value() {
        let c = confirm(Some(X224Negotiation::Failure(NegotiationFailure {
            failure_code: 0xdead,
        })));
        match select_protocol(&c) {
            Err(RdpError::NegotiationFailed { code, .. }) => assert_eq!(code, 0xdead),
            other => panic!("expected a negotiation failure, got {other:?}"),
        }
    }

    /// A negotiation failure needs the user to change something (turn NLA
    /// off, install a certificate on the server), so it is never retried on a
    /// backoff ladder.
    #[test]
    fn a_negotiation_failure_stops_and_asks_the_user() {
        let e = RdpError::NegotiationFailed {
            code: neg_failure::HYBRID_REQUIRED_BY_SERVER,
            reason: failure_reason(neg_failure::HYBRID_REQUIRED_BY_SERVER).to_owned(),
        };
        assert!(!e.is_transient());
        assert!(e.needs_user_action());
    }

    #[test]
    fn we_advertise_tls_and_credssp_and_nothing_else() {
        assert_eq!(
            REQUESTED_PROTOCOLS,
            security_protocol::SSL | security_protocol::HYBRID
        );
        assert_eq!(REQUESTED_PROTOCOLS & security_protocol::HYBRID_EX, 0);
        assert!(SecurityProtocol::Hybrid.wants_credssp());
        assert!(SecurityProtocol::HybridEx.wants_credssp());
        assert!(!SecurityProtocol::Ssl.wants_credssp());
        assert_eq!(SecurityProtocol::Ssl.method(), "tls");
        assert_eq!(SecurityProtocol::Hybrid.method(), "nla-ntlm");
    }
}
