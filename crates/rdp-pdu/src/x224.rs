//! TPKT framing and the X.224 TPDUs of connection initiation
//! (PRDRDP/13 §4.1).
//!
//! Three structures and one constant header live here: the TPKT header of
//! RFC 1006 §6, the X.224 Connection Request and Connection Confirm of
//! MS-RDPBCGR 2.2.1.1 and 2.2.1.2 with their negotiation blocks, and the
//! three byte Data TPDU header that prefixes every slow path PDU after the
//! confirm (X.224 §13.7).
//!
//! Everything in this module is big endian. RDP is little endian nearly
//! everywhere else, and the TPKT length and the X.224 reference fields are
//! two of the three exceptions (PRDRDP/13 §1.4), so every read and write
//! below says `be_` and means it.
//!
//! The Connection Request and Connection Confirm encoders emit the TPKT
//! header as well, because those two PDUs are never carried inside anything
//! else. Everything after them is a Data TPDU wrapping a body this module
//! knows nothing about, which is [`write_data_tpdu_with`] and
//! [`read_data_tpdu`].

use crate::io::limits::MAX_TPKT_LEN;
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// TPKT version 3, the only version RFC 1006 §6 defines and the only one RDP
/// uses (MS-RDPBCGR 2.2.1.1).
pub const TPKT_VERSION: u8 = 3;

/// Version, reserved and a big endian length: four bytes (RFC 1006 §6).
pub const TPKT_HEADER_LEN: usize = 4;

/// The X.224 Data TPDU header that prefixes every slow path PDU after the
/// Connection Confirm: `LI` = 2, `TPDU code` = `DT` with the EOT bit set
/// (X.224 §13.7, MS-RDPBCGR 2.2.1.1).
pub const X224_DATA_HEADER: [u8; 3] = [0x02, 0xf0, 0x80];

/// Connection Request, CR TPDU with a class 0 credit field (X.224 §13.3).
const TPDU_CR: u8 = 0xe0;

/// Connection Confirm, CC TPDU (X.224 §13.4).
const TPDU_CC: u8 = 0xd0;

/// The fixed part of a CR or CC TPDU after `LI`: the code, `dstRef`,
/// `srcRef` and `classOptions`.
const TPDU_FIXED_LEN: usize = 6;

/// `TYPE_RDP_NEG_REQ` (MS-RDPBCGR 2.2.1.1.1).
pub const TYPE_RDP_NEG_REQ: u8 = 0x01;

/// `TYPE_RDP_NEG_RSP` (MS-RDPBCGR 2.2.1.2.1).
pub const TYPE_RDP_NEG_RSP: u8 = 0x02;

/// `TYPE_RDP_NEG_FAILURE` (MS-RDPBCGR 2.2.1.2.2).
pub const TYPE_RDP_NEG_FAILURE: u8 = 0x03;

/// `TYPE_RDP_CORRELATION_INFO` (MS-RDPBCGR 2.2.1.1.2).
pub const TYPE_RDP_CORRELATION_INFO: u8 = 0x06;

/// Every negotiation block except the correlation info is eight bytes: type,
/// flags, a `u16 le` length of 8, and one `u32 le` payload.
const NEG_BLOCK_LEN: usize = 8;

/// `RDP_NEG_CORRELATION_INFO` is 36 bytes: the same four byte header, a
/// sixteen byte id and sixteen reserved bytes (MS-RDPBCGR 2.2.1.1.2).
const CORRELATION_BLOCK_LEN: usize = 36;

/// The longest `mstshash` identifier this crate will send.
///
/// The identifier is the user name and mstsc sends at most nine characters
/// of it. Longer values have been observed to make load balancers truncate
/// the field, so the encoder refuses rather than producing a request that
/// works against a direct server and fails behind a broker (PRDRDP/13 §4.1).
pub const MAX_MSTSHASH_LEN: usize = 9;

/// `RDP_NEG_REQ.requestedProtocols` and `RDP_NEG_RSP.selectedProtocol`
/// (MS-RDPBCGR 2.2.1.1.1).
pub mod security_protocol {
    /// Standard RDP Security. PRDRDP/03 §13.1 refuses it.
    pub const RDP: u32 = 0x0000_0000;
    /// TLS only, with a graphical logon.
    pub const SSL: u32 = 0x0000_0001;
    /// CredSSP over TLS, which is what everyone calls NLA.
    pub const HYBRID: u32 = 0x0000_0002;
    /// Out of scope (PRDRDP/03 §13.2).
    pub const RDSTLS: u32 = 0x0000_0004;
    /// CredSSP plus the Early User Authorization Result PDU.
    pub const HYBRID_EX: u32 = 0x0000_0008;
    /// Entra ID authentication. Out of scope.
    pub const RDSAAD: u32 = 0x0000_0010;
}

/// `RDP_NEG_REQ.flags` (MS-RDPBCGR 2.2.1.1.1).
pub mod neg_req_flags {
    /// `RESTRICTED_ADMIN_MODE_REQUIRED`.
    pub const RESTRICTED_ADMIN_MODE_REQUIRED: u8 = 0x01;
    /// `REDIRECTED_AUTHENTICATION_MODE_REQUIRED`.
    pub const REDIRECTED_AUTHENTICATION_MODE_REQUIRED: u8 = 0x02;
    /// `CORRELATION_INFO_PRESENT`. The encoder sets it from the presence of
    /// the correlation block rather than from the caller's flag word.
    pub const CORRELATION_INFO_PRESENT: u8 = 0x08;
}

/// `RDP_NEG_RSP.flags` (MS-RDPBCGR 2.2.1.2.1).
pub mod neg_rsp_flags {
    /// Without this the server never reads the monitor and multitransport
    /// blocks of the Connect Initial.
    pub const EXTENDED_CLIENT_DATA_SUPPORTED: u8 = 0x01;
    /// Without this there is no EGFX.
    pub const DYNVC_GFX_PROTOCOL_SUPPORTED: u8 = 0x02;
    /// `NEGRSP_FLAG_RESERVED`.
    pub const NEGRSP_FLAG_RESERVED: u8 = 0x04;
    /// `RESTRICTED_ADMIN_MODE_SUPPORTED`.
    pub const RESTRICTED_ADMIN_MODE_SUPPORTED: u8 = 0x08;
    /// `REDIRECTED_AUTHENTICATION_MODE_SUPPORTED`.
    pub const REDIRECTED_AUTHENTICATION_MODE_SUPPORTED: u8 = 0x10;
}

/// `RDP_NEG_FAILURE.failureCode` (MS-RDPBCGR 2.2.1.2.2).
///
/// These live here rather than in `codes/nego.rs` because they are the only
/// codes this module needs and duplicating them later would give the same
/// number two homes. When `codes/nego.rs` lands (PRDRDP/13 §8) it re-exports
/// these rather than restating them.
pub mod neg_failure {
    /// The server does not support TLS.
    pub const SSL_REQUIRED_BY_SERVER: u32 = 0x0000_0001;
    /// The server requires standard RDP security.
    pub const SSL_NOT_ALLOWED_BY_SERVER: u32 = 0x0000_0002;
    /// The server has no valid authentication certificate.
    pub const SSL_CERT_NOT_ON_SERVER: u32 = 0x0000_0003;
    /// The request flags were inconsistent.
    pub const INCONSISTENT_FLAGS: u32 = 0x0000_0004;
    /// The server requires CredSSP.
    pub const HYBRID_REQUIRED_BY_SERVER: u32 = 0x0000_0005;
    /// CredSSP succeeded but the certificate was not trusted.
    pub const SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER: u32 = 0x0000_0006;
}

/// Read a TPKT header and return the length it declares, including the four
/// header bytes (RFC 1006 §6, MS-RDPBCGR 2.2.1.1).
fn read_tpkt_length(r: &mut Reader<'_>) -> PduResult<usize> {
    const CONTEXT: &str = "TPKT";
    let at = r.offset();
    let version = r.u8(CONTEXT)?;
    if version != TPKT_VERSION {
        return Err(PduError::InvalidField {
            context: CONTEXT,
            field: "version",
            value: u64::from(version),
            offset: at,
        });
    }
    // `reserved`, which RFC 1006 §6 fixes at zero and which we do not check:
    // no server sets it and rejecting one that did would buy nothing.
    r.skip(1, CONTEXT)?;
    let at_len = r.offset();
    let length = usize::from(r.be_u16(CONTEXT)?);
    r.ensure_cap(length, MAX_TPKT_LEN, "MAX_TPKT_LEN", CONTEXT)?;
    if length < TPKT_HEADER_LEN {
        return Err(PduError::InvalidField {
            context: CONTEXT,
            field: "length",
            value: length as u64,
            offset: at_len,
        });
    }
    Ok(length)
}

/// The total length of the TPKT whose header starts `bytes`, or `None` when
/// fewer than four bytes have arrived.
///
/// This is the framer's entry point: read four bytes, ask how many more, read
/// them, hand the whole frame to a decoder.
pub fn peek_tpkt_length(bytes: &[u8]) -> PduResult<Option<usize>> {
    if bytes.len() < TPKT_HEADER_LEN {
        return Ok(None);
    }
    let mut r = Reader::new(bytes);
    Ok(Some(read_tpkt_length(&mut r)?))
}

/// Read a TPKT header and return a bounded sub reader over its payload.
pub fn read_tpkt<'a>(r: &mut Reader<'a>) -> PduResult<Reader<'a>> {
    let length = read_tpkt_length(r)?;
    r.take(length - TPKT_HEADER_LEN, "TPKT")
}

/// Write a TPKT header for a payload of exactly `body_len` bytes, then the
/// payload itself.
fn write_tpkt_with<F>(w: &mut Writer<'_>, body_len: usize, f: F) -> PduResult<()>
where
    F: FnOnce(&mut Writer<'_>) -> PduResult<()>,
{
    let total = body_len + TPKT_HEADER_LEN;
    let length = u16::try_from(total).map_err(|_| PduError::Encode {
        context: "TPKT",
        reason: "PDU longer than the TPKT length field",
    })?;
    w.u8(TPKT_VERSION);
    w.u8(0);
    w.be_u16(length);
    f(w)
}

/// Write a TPKT header and an X.224 Data TPDU header around a body of exactly
/// `body_len` bytes, which `f` appends.
///
/// `body_len` is what the body's own `Encode::size()` reports, so nothing is
/// copied: the MCS PDU is written straight into the caller's send buffer
/// behind a header whose length was already known.
pub fn write_data_tpdu_with<F>(w: &mut Writer<'_>, body_len: usize, f: F) -> PduResult<()>
where
    F: FnOnce(&mut Writer<'_>) -> PduResult<()>,
{
    write_tpkt_with(w, X224_DATA_HEADER.len() + body_len, |w| {
        w.bytes(&X224_DATA_HEADER);
        f(w)
    })
}

/// [`write_data_tpdu_with`] for a body that is already a slice.
pub fn write_data_tpdu(w: &mut Writer<'_>, body: &[u8]) -> PduResult<()> {
    write_data_tpdu_with(w, body.len(), |w| {
        w.bytes(body);
        Ok(())
    })
}

/// Strip the TPKT header and the X.224 Data TPDU header, returning a bounded
/// sub reader over the body.
///
/// The three header bytes are constant, so they are compared rather than
/// parsed: a class 0 Data TPDU has no other legal shape on this path
/// (X.224 §13.7).
pub fn read_data_tpdu<'a>(r: &mut Reader<'a>) -> PduResult<Reader<'a>> {
    const CONTEXT: &str = "X224_DATA";
    let mut body = read_tpkt(r)?;
    let at = body.offset();
    let header = body.array::<3>(CONTEXT)?;
    if header != X224_DATA_HEADER {
        let mut value = 0u64;
        for b in header {
            value = (value << 8) | u64::from(b);
        }
        return Err(PduError::InvalidField {
            context: CONTEXT,
            field: "X.224 Data TPDU header",
            value,
            offset: at,
        });
    }
    Ok(body)
}

/// The routing token or the cookie of a Connection Request
/// (MS-RDPBCGR 2.2.1.1). A request carries at most one of the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X224Cookie {
    /// `Cookie: msts=<token>\r\n`. A load balancer supplies the token out of
    /// band and we echo it, so the bytes stay opaque here.
    RoutingToken(Vec<u8>),
    /// `Cookie: mstshash=<identifier>\r\n`, where the identifier is the user
    /// name. Decision log R29 defaults this off, because the identifier
    /// travels in cleartext ahead of the TLS upgrade.
    MstsHash(String),
}

impl X224Cookie {
    /// The structure's name in the specification.
    const NAME: &'static str = "X224_COOKIE";

    const ROUTING_PREFIX: &'static [u8] = b"Cookie: msts=";
    const HASH_PREFIX: &'static [u8] = b"Cookie: mstshash=";

    /// The encoded length, terminator included.
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            Self::RoutingToken(t) => Self::ROUTING_PREFIX.len() + t.len() + 2,
            Self::MstsHash(s) => Self::HASH_PREFIX.len() + s.len() + 2,
        }
    }

    /// Reject anything that would not survive the round trip or that a load
    /// balancer would mangle, before a single byte is written.
    fn check(&self) -> PduResult<()> {
        match self {
            Self::RoutingToken(t) => {
                if t.windows(2).any(|w| matches!(w, [0x0d, 0x0a])) {
                    return Err(PduError::Encode {
                        context: Self::NAME,
                        reason: "routing token contains its own terminator",
                    });
                }
                Ok(())
            }
            Self::MstsHash(s) => {
                if !s.is_ascii() {
                    return Err(PduError::Encode {
                        context: Self::NAME,
                        reason: "mstshash identifier is not ASCII",
                    });
                }
                if s.len() > MAX_MSTSHASH_LEN {
                    return Err(PduError::Encode {
                        context: Self::NAME,
                        reason: "mstshash identifier is longer than nine characters",
                    });
                }
                Ok(())
            }
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        match self {
            Self::RoutingToken(t) => {
                w.bytes(Self::ROUTING_PREFIX);
                w.bytes(t);
            }
            Self::MstsHash(s) => {
                w.bytes(Self::HASH_PREFIX);
                w.bytes(s.as_bytes());
            }
        }
        w.bytes(b"\r\n");
        Ok(())
    }

    /// Read a cookie if one is there, leaving the reader untouched if not.
    ///
    /// The field is optional and is followed by structures whose first byte
    /// is a small type code, so "does it start with `Cookie: `" is the whole
    /// test the specification gives.
    fn decode(r: &mut Reader<'_>) -> PduResult<Option<Self>> {
        let mut probe = *r;
        let rest = probe.rest();
        let routing = rest.starts_with(Self::ROUTING_PREFIX);
        let hash = rest.starts_with(Self::HASH_PREFIX);
        if !routing && !hash {
            return Ok(None);
        }
        let prefix = if hash {
            Self::HASH_PREFIX
        } else {
            Self::ROUTING_PREFIX
        };
        let at = r.offset();
        let Some(crlf) = rest.windows(2).position(|w| matches!(w, [0x0d, 0x0a])) else {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "cookie terminator",
                value: rest.len() as u64,
                offset: at,
            });
        };
        // Everything up to and including the CRLF belongs to the field.
        let field = r.slice(crlf + 2, Self::NAME)?;
        let value = field
            .get(prefix.len()..crlf)
            .ok_or(PduError::InvalidField {
                context: Self::NAME,
                field: "cookie value",
                value: crlf as u64,
                offset: at,
            })?;
        if hash {
            Ok(Some(Self::MstsHash(
                String::from_utf8_lossy(value).into_owned(),
            )))
        } else {
            Ok(Some(Self::RoutingToken(value.to_vec())))
        }
    }
}

/// `RDP_NEG_REQ` (MS-RDPBCGR 2.2.1.1.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NegotiationRequest {
    /// [`neg_req_flags`]. `CORRELATION_INFO_PRESENT` is set by the encoder
    /// from the presence of the correlation block, so a caller never sets it
    /// here.
    pub flags: u8,
    /// A bit field of [`security_protocol`] values.
    pub requested_protocols: u32,
}

/// `RDP_NEG_RSP` (MS-RDPBCGR 2.2.1.2.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NegotiationResponse {
    /// [`neg_rsp_flags`].
    pub flags: u8,
    /// Exactly one [`security_protocol`] value.
    pub selected_protocol: u32,
}

/// `RDP_NEG_FAILURE` (MS-RDPBCGR 2.2.1.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiationFailure {
    /// One of [`neg_failure`]. Kept as a `u32` because an unknown code still
    /// has to reach the error message.
    pub failure_code: u32,
}

/// `RDP_NEG_CORRELATION_INFO` (MS-RDPBCGR 2.2.1.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorrelationInfo {
    /// Sixteen bytes whose first must be neither `0x00` nor `0xF4`, and none
    /// of which may be `0x0D`. The encoder enforces all three.
    pub correlation_id: [u8; 16],
}

impl CorrelationInfo {
    /// The structure's name in the specification.
    const NAME: &'static str = "RDP_NEG_CORRELATION_INFO";

    fn check(&self) -> PduResult<()> {
        let first = self.correlation_id.first().copied().unwrap_or(0);
        if first == 0x00 || first == 0xf4 {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "correlationId starts with 0x00 or 0xF4",
            });
        }
        if self.correlation_id.contains(&0x0d) {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "correlationId contains 0x0D",
            });
        }
        Ok(())
    }
}

/// Read the four byte header every negotiation block shares, check the
/// declared length against the block's fixed size, and return the type code
/// and the flags.
///
/// The length field is `0x0008` for `RDP_NEG_REQ`, `RDP_NEG_RSP` and
/// `RDP_NEG_FAILURE` and `0x0024` for `RDP_NEG_CORRELATION_INFO`, and the
/// specification gives no other value, so any other value is rejected rather
/// than trusted to skip by (MS-RDPBCGR 2.2.1.1.1).
fn read_neg_header(
    r: &mut Reader<'_>,
    expected_len: u16,
    context: &'static str,
) -> PduResult<(u8, u8)> {
    let kind = r.u8(context)?;
    let flags = r.u8(context)?;
    let at_len = r.offset();
    let length = r.u16(context)?;
    if length != expected_len {
        return Err(PduError::InvalidField {
            context,
            field: "length",
            value: u64::from(length),
            offset: at_len,
        });
    }
    Ok((kind, flags))
}

/// The X.224 Connection Request PDU (MS-RDPBCGR 2.2.1.1), TPKT header
/// included. Client to server, phase 1.
///
/// `dstRef`, `srcRef` and `classOptions` are all zero in a Connection Request
/// and are not fields here: the encoder writes zeros and the decoder skips
/// them, which is what every client and every server does with them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct X224ConnectionRequest {
    /// The routing token or the `mstshash` cookie, if either is sent.
    pub cookie: Option<X224Cookie>,
    /// The negotiation request. Absent means "standard RDP security only",
    /// which this client never sends and the mock server exercises.
    pub nego: Option<NegotiationRequest>,
    /// The correlation info block, phase 3.
    pub correlation: Option<CorrelationInfo>,
}

impl X224ConnectionRequest {
    /// The structure's name in the specification. An inherent constant so
    /// `Self::NAME` is unambiguous in a type that implements both traits.
    pub const NAME: &'static str = "X224_CONNECTION_REQUEST";

    /// A request for `requested_protocols` with no cookie and no correlation
    /// info, which is what PRDRDP/03 §2.1 sends.
    #[must_use]
    pub fn new(requested_protocols: u32) -> Self {
        Self {
            cookie: None,
            nego: Some(NegotiationRequest {
                flags: 0,
                requested_protocols,
            }),
            correlation: None,
        }
    }

    /// The variable part's length: cookie, negotiation request and
    /// correlation info.
    fn variable_len(&self) -> usize {
        self.cookie.as_ref().map_or(0, X224Cookie::size)
            + self.nego.map_or(0, |_| NEG_BLOCK_LEN)
            + self.correlation.map_or(0, |_| CORRELATION_BLOCK_LEN)
    }
}

impl Encode for X224ConnectionRequest {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        TPKT_HEADER_LEN + 1 + TPDU_FIXED_LEN + self.variable_len()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if let Some(cookie) = &self.cookie {
            cookie.check()?;
        }
        if let Some(correlation) = &self.correlation {
            correlation.check()?;
        }
        let li = TPDU_FIXED_LEN + self.variable_len();
        let li = u8::try_from(li).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "X.224 header longer than its one byte length indicator",
        })?;
        write_tpkt_with(w, 1 + usize::from(li), |w| {
            w.u8(li);
            w.u8(TPDU_CR);
            // dstRef, srcRef, classOptions, all zero in a CR (X.224 §13.3).
            w.be_u16(0);
            w.be_u16(0);
            w.u8(0);
            if let Some(cookie) = &self.cookie {
                cookie.encode(w)?;
            }
            if let Some(nego) = self.nego {
                let mut flags = nego.flags;
                if self.correlation.is_some() {
                    flags |= neg_req_flags::CORRELATION_INFO_PRESENT;
                }
                w.u8(TYPE_RDP_NEG_REQ);
                w.u8(flags);
                w.u16(NEG_BLOCK_LEN as u16);
                w.u32(nego.requested_protocols);
            }
            if let Some(correlation) = &self.correlation {
                w.u8(TYPE_RDP_CORRELATION_INFO);
                w.u8(0);
                w.u16(CORRELATION_BLOCK_LEN as u16);
                w.bytes(&correlation.correlation_id);
                w.zeros(16);
            }
            Ok(())
        })
    }
}

impl Decode<'_> for X224ConnectionRequest {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut frame = read_tpkt(r)?;
        let li = usize::from(frame.u8(Self::NAME)?);
        let mut tpdu = frame.take(li, Self::NAME)?;
        frame.expect_empty(Self::NAME)?;
        let at = tpdu.offset();
        let code = tpdu.u8(Self::NAME)?;
        if code != TPDU_CR {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "x224Type",
                value: u64::from(code),
                offset: at,
            });
        }
        // dstRef, srcRef and classOptions.
        tpdu.skip(5, Self::NAME)?;

        let cookie = X224Cookie::decode(&mut tpdu)?;
        let mut nego = None;
        let mut correlation = None;
        if !tpdu.is_empty() {
            let at = tpdu.offset();
            let (kind, flags) = read_neg_header(&mut tpdu, NEG_BLOCK_LEN as u16, Self::NAME)?;
            if kind != TYPE_RDP_NEG_REQ {
                return Err(PduError::Unsupported {
                    context: Self::NAME,
                    kind: "negotiation block type",
                    value: u64::from(kind),
                    offset: at,
                });
            }
            nego = Some(NegotiationRequest {
                // CORRELATION_INFO_PRESENT is dropped here and recomputed by
                // the encoder from the block's presence, so the flag word and
                // the block cannot contradict each other.
                flags: flags & !neg_req_flags::CORRELATION_INFO_PRESENT,
                requested_protocols: tpdu.u32(Self::NAME)?,
            });
        }
        if !tpdu.is_empty() {
            let at = tpdu.offset();
            let (kind, _) = read_neg_header(&mut tpdu, CORRELATION_BLOCK_LEN as u16, Self::NAME)?;
            if kind != TYPE_RDP_CORRELATION_INFO {
                return Err(PduError::Unsupported {
                    context: Self::NAME,
                    kind: "negotiation block type",
                    value: u64::from(kind),
                    offset: at,
                });
            }
            correlation = Some(CorrelationInfo {
                correlation_id: tpdu.array::<16>(Self::NAME)?,
            });
            tpdu.skip(16, Self::NAME)?;
        }
        tpdu.expect_empty(Self::NAME)?;
        Ok(Self {
            cookie,
            nego,
            correlation,
        })
    }
}

/// The negotiation structure a Connection Confirm carries (MS-RDPBCGR
/// 2.2.1.2.1 and 2.2.1.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X224Negotiation {
    /// The server selected a protocol.
    Response(NegotiationResponse),
    /// The server refused, with a code PRDRDP/03 §9.2 maps to a message.
    Failure(NegotiationFailure),
}

/// The X.224 Connection Confirm PDU (MS-RDPBCGR 2.2.1.2), TPKT header
/// included. Server to client, phase 1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct X224ConnectionConfirm {
    /// `dstRef`, echoed. Zero from every server seen, kept so a golden vector
    /// round trips.
    pub dst_ref: u16,
    /// `srcRef`, the server's own reference. Non zero in MS-RDPBCGR 4.1.2.
    pub src_ref: u16,
    /// `classOptions`, zero for class 0.
    pub class_options: u8,
    /// The negotiation response, the negotiation failure, or nothing at all.
    ///
    /// Nothing at all means the server does not understand negotiation and
    /// has selected standard RDP security. That is a real case rather than a
    /// theoretical one (PRDRDP/03 §2.1), so it decodes rather than erroring
    /// and PRDRDP/03 turns it into a message.
    pub nego: Option<X224Negotiation>,
}

impl X224ConnectionConfirm {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "X224_CONNECTION_CONFIRM";

    /// The protocol the server selected, or `None` when it failed or sent no
    /// negotiation structure at all.
    #[must_use]
    pub fn selected_protocol(&self) -> Option<u32> {
        match self.nego {
            Some(X224Negotiation::Response(r)) => Some(r.selected_protocol),
            _ => None,
        }
    }
}

impl Encode for X224ConnectionConfirm {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        TPKT_HEADER_LEN + 1 + TPDU_FIXED_LEN + self.nego.map_or(0, |_| NEG_BLOCK_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        let li = TPDU_FIXED_LEN + self.nego.map_or(0, |_| NEG_BLOCK_LEN);
        let li = u8::try_from(li).map_err(|_| PduError::Encode {
            context: Self::NAME,
            reason: "X.224 header longer than its one byte length indicator",
        })?;
        write_tpkt_with(w, 1 + usize::from(li), |w| {
            w.u8(li);
            w.u8(TPDU_CC);
            w.be_u16(self.dst_ref);
            w.be_u16(self.src_ref);
            w.u8(self.class_options);
            match self.nego {
                None => {}
                Some(X224Negotiation::Response(rsp)) => {
                    w.u8(TYPE_RDP_NEG_RSP);
                    w.u8(rsp.flags);
                    w.u16(NEG_BLOCK_LEN as u16);
                    w.u32(rsp.selected_protocol);
                }
                Some(X224Negotiation::Failure(fail)) => {
                    w.u8(TYPE_RDP_NEG_FAILURE);
                    w.u8(0);
                    w.u16(NEG_BLOCK_LEN as u16);
                    w.u32(fail.failure_code);
                }
            }
            Ok(())
        })
    }
}

impl Decode<'_> for X224ConnectionConfirm {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let mut frame = read_tpkt(r)?;
        let li = usize::from(frame.u8(Self::NAME)?);
        let mut tpdu = frame.take(li, Self::NAME)?;
        frame.expect_empty(Self::NAME)?;
        let at = tpdu.offset();
        let code = tpdu.u8(Self::NAME)?;
        if code != TPDU_CC {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "x224Type",
                value: u64::from(code),
                offset: at,
            });
        }
        let dst_ref = tpdu.be_u16(Self::NAME)?;
        let src_ref = tpdu.be_u16(Self::NAME)?;
        let class_options = tpdu.u8(Self::NAME)?;
        let nego = if tpdu.is_empty() {
            None
        } else {
            let at = tpdu.offset();
            let (kind, flags) = read_neg_header(&mut tpdu, NEG_BLOCK_LEN as u16, Self::NAME)?;
            let value = tpdu.u32(Self::NAME)?;
            match kind {
                TYPE_RDP_NEG_RSP => Some(X224Negotiation::Response(NegotiationResponse {
                    flags,
                    selected_protocol: value,
                })),
                TYPE_RDP_NEG_FAILURE => Some(X224Negotiation::Failure(NegotiationFailure {
                    failure_code: value,
                })),
                _ => {
                    return Err(PduError::Unsupported {
                        context: Self::NAME,
                        kind: "negotiation block type",
                        value: u64::from(kind),
                        offset: at,
                    });
                }
            }
        };
        tpdu.expect_empty(Self::NAME)?;
        Ok(Self {
            dst_ref,
            src_ref,
            class_options,
            nego,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// The Client X.224 Connection Request of MS-RDPBCGR 4.1.1.
    ///
    /// The capture that section annotates is a Standard RDP Security session,
    /// which is why `requestedProtocols` is `PROTOCOL_RDP` (0) and why the
    /// Connection Confirm below carries no `RDP_NEG_RSP` at all. The user
    /// name in the cookie is Microsoft's own test value and is kept, per
    /// PRDRDP/13 §9.2.
    ///
    /// Transcribed from the annotated example rather than from a capture, and
    /// so due one re-check against the published revision in hand when this
    /// moves to a file under `tests/vectors/` with its revision date, which is
    /// what PRDRDP/13 §9.2 Q6 requires of every golden. The lengths are
    /// self consistent (44 = 4 + 1 + 6 + 25 + 8, `LI` = 39) and the fields
    /// are MS-RDPBCGR 2.2.1.1's, so a transcription error would have to be in
    /// a value rather than in the layout.
    const CONNECTION_REQUEST_4_1_1: &[u8] = &[
        0x03, 0x00, 0x00, 0x2c, // TPKT: version 3, reserved, length 44
        0x27, // X.224 LI = 39
        0xe0, // CR CDT
        0x00, 0x00, // dstRef
        0x00, 0x00, // srcRef
        0x00, // classOptions
        // "Cookie: mstshash=eltons\r\n"
        0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73,
        0x68, 0x3d, 0x65, 0x6c, 0x74, 0x6f, 0x6e, 0x73, 0x0d, 0x0a,
        // RDP_NEG_REQ: type 1, flags 0, length 8, requestedProtocols 0
        0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// The Server X.224 Connection Confirm of MS-RDPBCGR 4.1.2: eleven bytes
    /// with an empty variable part, which is a server saying it selected
    /// Standard RDP Security.
    const CONNECTION_CONFIRM_4_1_2: &[u8] = &[
        0x03, 0x00, 0x00, 0x0b, // TPKT length 11
        0x06, // LI = 6
        0xd0, // CC CDT
        0x00, 0x00, // dstRef
        0x12, 0x34, // srcRef
        0x00, // classOptions
    ];

    fn encode(value: &impl Encode) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_checked(&mut Writer::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), value.size(), "size() disagrees with encode()");
        buf
    }

    #[test]
    fn the_connection_request_of_4_1_1_decodes_and_re_encodes_byte_for_byte() {
        let pdu =
            X224ConnectionRequest::decode(&mut Reader::new(CONNECTION_REQUEST_4_1_1)).unwrap();
        assert_eq!(pdu.cookie, Some(X224Cookie::MstsHash("eltons".to_owned())));
        assert_eq!(
            pdu.nego,
            Some(NegotiationRequest {
                flags: 0,
                requested_protocols: security_protocol::RDP,
            })
        );
        assert_eq!(pdu.correlation, None);
        assert_eq!(encode(&pdu), CONNECTION_REQUEST_4_1_1);
    }

    #[test]
    fn the_connection_confirm_of_4_1_2_has_no_negotiation_structure() {
        let pdu =
            X224ConnectionConfirm::decode(&mut Reader::new(CONNECTION_CONFIRM_4_1_2)).unwrap();
        assert_eq!(pdu.src_ref, 0x1234);
        assert_eq!(pdu.nego, None);
        assert_eq!(pdu.selected_protocol(), None);
        assert_eq!(encode(&pdu), CONNECTION_CONFIRM_4_1_2);
    }

    /// The request PRDRDP/03 §2.1 sends: no cookie, TLS and CredSSP offered.
    #[test]
    fn the_request_this_client_sends_is_nineteen_bytes() {
        let pdu = X224ConnectionRequest::new(security_protocol::SSL | security_protocol::HYBRID);
        assert_eq!(
            encode(&pdu),
            [
                0x03, 0x00, 0x00, 0x13, // TPKT length 19
                0x0e, // LI = 14
                0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // CR and the three zero fields
                0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            X224ConnectionRequest::decode(&mut Reader::new(&encode(&pdu))).unwrap(),
            pdu
        );
    }

    #[test]
    fn a_negotiation_response_and_a_failure_both_round_trip() {
        for nego in [
            X224Negotiation::Response(NegotiationResponse {
                flags: neg_rsp_flags::EXTENDED_CLIENT_DATA_SUPPORTED
                    | neg_rsp_flags::DYNVC_GFX_PROTOCOL_SUPPORTED,
                selected_protocol: security_protocol::HYBRID,
            }),
            X224Negotiation::Failure(NegotiationFailure {
                failure_code: neg_failure::HYBRID_REQUIRED_BY_SERVER,
            }),
        ] {
            let pdu = X224ConnectionConfirm {
                dst_ref: 0,
                src_ref: 0x1234,
                class_options: 0,
                nego: Some(nego),
            };
            let bytes = encode(&pdu);
            assert_eq!(bytes.len(), 19);
            assert_eq!(
                X224ConnectionConfirm::decode(&mut Reader::new(&bytes)).unwrap(),
                pdu
            );
        }
    }

    #[test]
    fn a_routing_token_round_trips_as_opaque_bytes() {
        let pdu = X224ConnectionRequest {
            cookie: Some(X224Cookie::RoutingToken(b"3640205228.15629.0000".to_vec())),
            nego: Some(NegotiationRequest {
                flags: 0,
                requested_protocols: security_protocol::HYBRID,
            }),
            correlation: None,
        };
        let bytes = encode(&pdu);
        assert!(bytes.windows(13).any(|w| w == b"Cookie: msts="));
        assert_eq!(
            X224ConnectionRequest::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );
    }

    /// The two cookie forms are mutually exclusive and the decoder tells them
    /// apart by their prefix, so `mstshash=` must not be read as a routing
    /// token whose value starts with `hash=`.
    #[test]
    fn the_two_cookie_prefixes_do_not_collide() {
        let hash = X224ConnectionRequest {
            cookie: Some(X224Cookie::MstsHash("abc".to_owned())),
            nego: None,
            correlation: None,
        };
        let decoded = X224ConnectionRequest::decode(&mut Reader::new(&encode(&hash))).unwrap();
        assert_eq!(decoded.cookie, Some(X224Cookie::MstsHash("abc".to_owned())));
    }

    #[test]
    fn an_over_long_or_non_ascii_mstshash_is_refused_before_anything_is_written() {
        for bad in ["muchtoolongidentifier", "caf\u{e9}"] {
            let pdu = X224ConnectionRequest {
                cookie: Some(X224Cookie::MstsHash(bad.to_owned())),
                nego: None,
                correlation: None,
            };
            let mut buf = Vec::new();
            let err = pdu.encode(&mut Writer::new(&mut buf)).unwrap_err();
            assert!(matches!(err, PduError::Encode { .. }));
            assert!(buf.is_empty(), "bytes were written before the check");
        }
    }

    #[test]
    fn correlation_info_round_trips_and_rejects_the_forbidden_ids() {
        let pdu = X224ConnectionRequest {
            cookie: None,
            nego: Some(NegotiationRequest {
                flags: 0,
                requested_protocols: security_protocol::HYBRID,
            }),
            correlation: Some(CorrelationInfo {
                correlation_id: [0x11; 16],
            }),
        };
        let bytes = encode(&pdu);
        // The encoder sets CORRELATION_INFO_PRESENT from the block itself.
        assert_eq!(bytes[12], neg_req_flags::CORRELATION_INFO_PRESENT);
        assert_eq!(
            X224ConnectionRequest::decode(&mut Reader::new(&bytes)).unwrap(),
            pdu
        );

        for bad in [[0x00u8; 16], [0xf4; 16], {
            let mut id = [0x11u8; 16];
            id[7] = 0x0d;
            id
        }] {
            let pdu = X224ConnectionRequest {
                cookie: None,
                nego: None,
                correlation: Some(CorrelationInfo {
                    correlation_id: bad,
                }),
            };
            let mut buf = Vec::new();
            assert!(pdu.encode(&mut Writer::new(&mut buf)).is_err());
        }
    }

    #[test]
    fn the_data_tpdu_header_is_written_and_checked() {
        let mut buf = Vec::new();
        write_data_tpdu(&mut Writer::new(&mut buf), &[0xaa, 0xbb]).unwrap();
        assert_eq!(buf, [0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0xaa, 0xbb]);

        let mut r = Reader::new(&buf);
        let mut body = read_data_tpdu(&mut r).unwrap();
        assert_eq!(body.rest(), &[0xaa, 0xbb]);

        // A Connection Confirm is not a Data TPDU.
        assert!(read_data_tpdu(&mut Reader::new(CONNECTION_CONFIRM_4_1_2)).is_err());
    }

    #[test]
    fn tpkt_rejects_a_bad_version_and_a_length_below_its_own_header() {
        assert!(peek_tpkt_length(&[0x04, 0x00, 0x00, 0x0b]).is_err());
        assert!(peek_tpkt_length(&[0x03, 0x00, 0x00, 0x03]).is_err());
        assert_eq!(peek_tpkt_length(&[0x03, 0x00, 0x00]).unwrap(), None);
        assert_eq!(
            peek_tpkt_length(CONNECTION_CONFIRM_4_1_2).unwrap(),
            Some(11)
        );
    }

    /// A short `LI` leaves bytes inside the TPKT frame that belong to no
    /// field, which is PRDRDP/13 §2.5's exact case and an error.
    #[test]
    fn a_trailing_byte_inside_the_frame_is_a_length_mismatch() {
        let mut bytes = CONNECTION_CONFIRM_4_1_2.to_vec();
        bytes.push(0xff);
        bytes[3] = 0x0c;
        let err = X224ConnectionConfirm::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(err, PduError::LengthMismatch { .. }));
    }

    #[test]
    fn every_prefix_of_every_vector_errors_without_panicking() {
        for cut in 0..CONNECTION_REQUEST_4_1_1.len() {
            assert!(
                X224ConnectionRequest::decode(&mut Reader::new(&CONNECTION_REQUEST_4_1_1[..cut]))
                    .is_err(),
                "connection request truncated to {cut} bytes decoded"
            );
        }
        for cut in 0..CONNECTION_CONFIRM_4_1_2.len() {
            assert!(
                X224ConnectionConfirm::decode(&mut Reader::new(&CONNECTION_CONFIRM_4_1_2[..cut]))
                    .is_err(),
                "connection confirm truncated to {cut} bytes decoded"
            );
        }
    }

    /// A cookie with no terminator must not run off the end of the variable
    /// part, and a negotiation block with a length other than eight must not
    /// be trusted.
    #[test]
    fn a_malformed_variable_part_is_rejected() {
        // "Cookie: msts=" and then nothing.
        let mut bytes = vec![0x03, 0x00, 0x00, 0x18, 0x13, 0xe0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(b"Cookie: msts=");
        assert_eq!(bytes.len(), 24);
        assert!(X224ConnectionRequest::decode(&mut Reader::new(&bytes)).is_err());

        // RDP_NEG_RSP with a declared length of 12.
        let bytes = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x0c,
            0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        assert!(X224ConnectionConfirm::decode(&mut Reader::new(&bytes)).is_err());
    }
}
