//! The security header variants, and the table that says when each one is
//! there at all (MS-RDPBCGR 2.2.8.1.1.2, PRDRDP/13 §5.2).
//!
//! This is the classic interop trap in RDP and it is worth the whole rule.
//! Whether a slow path PDU carries a security header depends on the
//! negotiated security *and* on which PDU it is. A decoder that
//! unconditionally reads four bytes eats the front of the Share Control
//! header of every graphics PDU and the session dies about two seconds in
//! with an unintelligible error. A decoder that never reads it mis-parses the
//! Client Info PDU on the first exchange.
//!
//! The crate makes the choice impossible to get wrong by never guessing. The
//! session names the PDU class it is about to read, [`IoPduContext`] answers
//! with [`Some`] or [`None`], and the table driven test at the bottom of this
//! file runs every combination.
//!
//! # Under an external security protocol
//!
//! TLS or CredSSP is the only mode this client supports (PRDRDP/03 §13.1).
//! The server then sends `ENCRYPTION_METHOD_NONE` and `ENCRYPTION_LEVEL_NONE`
//! in `TS_UD_SC_SEC1` (MS-RDPBCGR 2.2.1.4.3, 5.3.2), and exactly six classes
//! of PDU still carry a basic header, each recognised by a flag:
//!
//! | PDU class | Header | Flag |
//! |---|---|---|
//! | Client Info (2.2.1.11) | basic | `SEC_INFO_PKT` |
//! | Licensing (2.2.1.12) | basic | `SEC_LICENSE_PKT` |
//! | Auto-detect (2.2.14) | basic | `SEC_AUTODETECT_REQ` or `SEC_AUTODETECT_RSP` |
//! | Heartbeat (2.2.16) | basic | `SEC_HEARTBEAT` |
//! | Enhanced Server Redirection (2.2.13.3) | basic | `SEC_REDIRECTION_PKT` |
//! | Multitransport (2.2.15) | basic | `SEC_TRANSPORT_REQ` or `SEC_TRANSPORT_RSP` |
//!
//! Everything else on the slow path has no header at all, and no fast path
//! PDU ever has one: the fast path header carries its own flags
//! (MS-RDPBCGR 2.2.9.1.2).

use crate::gcc::server::{ENCRYPTION_LEVEL_NONE, ENCRYPTION_METHOD_NONE};
use crate::io::{Decode, Encode, PduError, PduResult, Reader, Writer};

/// The basic security header: `flags` and `flagsHi` (MS-RDPBCGR
/// 2.2.8.1.1.2.1).
pub const BASIC_SECURITY_HEADER_LEN: usize = 4;

/// The basic header plus an eight byte `dataSignature` (MS-RDPBCGR
/// 2.2.8.1.1.2.2).
pub const NON_FIPS_SECURITY_HEADER_LEN: usize = BASIC_SECURITY_HEADER_LEN + 8;

/// The basic header plus `length`, `version`, `padlen` and `dataSignature`
/// (MS-RDPBCGR 2.2.8.1.1.2.3).
pub const FIPS_SECURITY_HEADER_LEN: usize = BASIC_SECURITY_HEADER_LEN + 12;

/// `TSFIPS_VERSION1`, the only value `TS_SECURITY_HEADER2.version` takes
/// (MS-RDPBCGR 2.2.8.1.1.2.3).
pub const TSFIPS_VERSION1: u8 = 0x01;

/// The `length` field of a FIPS header, which is fixed at sixteen
/// (MS-RDPBCGR 2.2.8.1.1.2.3).
pub const FIPS_HEADER_LENGTH_FIELD: u16 = 0x0010;

/// `TS_SECURITY_HEADER.flags` (MS-RDPBCGR 2.2.8.1.1.2.1).
///
/// Several of these are how the header's presence is recognised, which is why
/// the whole table is here rather than only the flags we send.
pub mod security_flags {
    /// `SEC_EXCHANGE_PKT`, the Client Security Exchange PDU we never send.
    pub const EXCHANGE_PKT: u16 = 0x0001;
    /// `SEC_TRANSPORT_REQ`, Server Initiate Multitransport Request.
    pub const TRANSPORT_REQ: u16 = 0x0002;
    /// `SEC_TRANSPORT_RSP`, Client Initiate Multitransport Response.
    pub const TRANSPORT_RSP: u16 = 0x0004;
    /// `SEC_ENCRYPT`. Never set on anything we send and never accepted on
    /// anything we receive: it means the server believes standard RDP
    /// security is in force, and the session cannot continue.
    pub const ENCRYPT: u16 = 0x0008;
    /// `SEC_RESET_SEQNO`.
    pub const RESET_SEQNO: u16 = 0x0010;
    /// `SEC_IGNORE_SEQNO`.
    pub const IGNORE_SEQNO: u16 = 0x0020;
    /// `SEC_INFO_PKT`, the Client Info PDU.
    pub const INFO_PKT: u16 = 0x0040;
    /// `SEC_LICENSE_PKT`, every licensing PDU.
    pub const LICENSE_PKT: u16 = 0x0080;
    /// `SEC_LICENSE_ENCRYPT_CS`, client to server licensing encryption.
    pub const LICENSE_ENCRYPT_CS: u16 = 0x0200;
    /// `SEC_LICENSE_ENCRYPT_SC`, which MS-RDPBCGR 2.2.8.1.1.2.1 gives the
    /// same value as [`LICENSE_ENCRYPT_CS`]; the direction of the PDU is what
    /// tells the two apart.
    pub const LICENSE_ENCRYPT_SC: u16 = 0x0200;
    /// `SEC_REDIRECTION_PKT`, the Enhanced Server Redirection PDU.
    pub const REDIRECTION_PKT: u16 = 0x0400;
    /// `SEC_SECURE_CHECKSUM`.
    pub const SECURE_CHECKSUM: u16 = 0x0800;
    /// `SEC_AUTODETECT_REQ`, a network characteristics detection request.
    pub const AUTODETECT_REQ: u16 = 0x1000;
    /// `SEC_AUTODETECT_RSP`, our answer to one.
    pub const AUTODETECT_RSP: u16 = 0x2000;
    /// `SEC_HEARTBEAT`.
    pub const HEARTBEAT: u16 = 0x4000;
    /// `SEC_FLAGCHKSUM`.
    pub const FLAGCHKSUM: u16 = 0x8000;
}

/// `TS_UD_SC_SEC1.encryptionLevel` (MS-RDPBCGR 2.2.1.4.3).
///
/// [`ENCRYPTION_LEVEL_NONE`] is the only value that appears under an external
/// security protocol and the only one this client accepts; the rest are here
/// so [`IoPduContext`] can state the whole rule and the table driven test can
/// exercise it.
pub mod encryption_level {
    /// `ENCRYPTION_LEVEL_LOW`.
    pub const LOW: u32 = 0x0000_0001;
    /// `ENCRYPTION_LEVEL_CLIENT_COMPATIBLE`.
    pub const CLIENT_COMPATIBLE: u32 = 0x0000_0002;
    /// `ENCRYPTION_LEVEL_HIGH`.
    pub const HIGH: u32 = 0x0000_0003;
    /// `ENCRYPTION_LEVEL_FIPS`.
    pub const FIPS: u32 = 0x0000_0004;
}

/// `TS_UD_SC_SEC1.encryptionMethod` (MS-RDPBCGR 2.2.1.4.3).
pub mod encryption_method {
    /// `ENCRYPTION_METHOD_40BIT`.
    pub const BIT40: u32 = 0x0000_0001;
    /// `ENCRYPTION_METHOD_128BIT`.
    pub const BIT128: u32 = 0x0000_0002;
    /// `ENCRYPTION_METHOD_56BIT`.
    pub const BIT56: u32 = 0x0000_0008;
    /// `ENCRYPTION_METHOD_FIPS`, the one that selects the FIPS header.
    pub const FIPS: u32 = 0x0000_0010;
}

/// Which of the three headers of MS-RDPBCGR 2.2.8.1.1.2 a PDU carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityHeaderKind {
    /// Four bytes: `flags` and `flagsHi` (2.2.8.1.1.2.1).
    Basic,
    /// The basic header plus `dataSignature` (2.2.8.1.1.2.2).
    NonFips,
    /// The basic header plus `length`, `version`, `padlen` and
    /// `dataSignature` (2.2.8.1.1.2.3).
    Fips,
}

impl SecurityHeaderKind {
    /// The encoded size of a header of this kind.
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            Self::Basic => BASIC_SECURITY_HEADER_LEN,
            Self::NonFips => NON_FIPS_SECURITY_HEADER_LEN,
            Self::Fips => FIPS_SECURITY_HEADER_LEN,
        }
    }
}

/// The class of slow path PDU the session is about to read or write.
///
/// The six named classes are the ones that carry a security header under an
/// external security protocol; [`SlowPathClass::Other`] is everything else,
/// which is every Share Control PDU and therefore nearly all the traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlowPathClass {
    /// The Client Info PDU (MS-RDPBCGR 2.2.1.11).
    ClientInfo,
    /// Any licensing PDU (MS-RDPBCGR 2.2.1.12).
    Licensing,
    /// A network characteristics detection request, server to client
    /// (MS-RDPBCGR 2.2.14.1).
    AutoDetectRequest,
    /// Our answer to one (MS-RDPBCGR 2.2.14.2).
    AutoDetectResponse,
    /// The heartbeat PDU (MS-RDPBCGR 2.2.16.1).
    Heartbeat,
    /// The Enhanced Security Server Redirection PDU (MS-RDPBCGR 2.2.13.3).
    EnhancedRedirection,
    /// Server Initiate Multitransport Request (MS-RDPBCGR 2.2.15.1).
    MultitransportRequest,
    /// Client Initiate Multitransport Response (MS-RDPBCGR 2.2.15.2).
    MultitransportResponse,
    /// Every other slow path PDU: Demand Active, Confirm Active, every Share
    /// Data PDU, Deactivate All, the standard Server Redirection PDU.
    Other,
}

impl SlowPathClass {
    /// The flag that marks this class in the basic header's `flags`, or zero
    /// for [`SlowPathClass::Other`], which has no header to carry one.
    #[must_use]
    pub const fn security_flag(self) -> u16 {
        match self {
            Self::ClientInfo => security_flags::INFO_PKT,
            Self::Licensing => security_flags::LICENSE_PKT,
            Self::AutoDetectRequest => security_flags::AUTODETECT_REQ,
            Self::AutoDetectResponse => security_flags::AUTODETECT_RSP,
            Self::Heartbeat => security_flags::HEARTBEAT,
            Self::EnhancedRedirection => security_flags::REDIRECTION_PKT,
            Self::MultitransportRequest => security_flags::TRANSPORT_REQ,
            Self::MultitransportResponse => security_flags::TRANSPORT_RSP,
            Self::Other => 0,
        }
    }

    /// Whether this class carries a header when no RDP standard security is
    /// in force, which is the whole of PRDRDP/13 §5.2's table.
    #[must_use]
    pub const fn carries_header_without_encryption(self) -> bool {
        !matches!(self, Self::Other)
    }
}

/// What the session knows about the negotiated security, which is all the
/// security header rule depends on (PRDRDP/13 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoPduContext {
    /// `TS_UD_SC_SEC1.encryptionMethod` as the server sent it.
    pub encryption_method: u32,
    /// `TS_UD_SC_SEC1.encryptionLevel` as the server sent it.
    pub encryption_level: u32,
}

impl Default for IoPduContext {
    fn default() -> Self {
        Self::external_security()
    }
}

impl IoPduContext {
    /// The context under TLS or CredSSP, which is the only one this client
    /// ever runs in: both fields are `NONE` (MS-RDPBCGR 5.3.2).
    #[must_use]
    pub const fn external_security() -> Self {
        Self {
            encryption_method: ENCRYPTION_METHOD_NONE,
            encryption_level: ENCRYPTION_LEVEL_NONE,
        }
    }

    /// True when the server negotiated no RDP standard security, which is
    /// what an external security protocol produces.
    #[must_use]
    pub const fn is_external_security(&self) -> bool {
        self.encryption_method == ENCRYPTION_METHOD_NONE
            && self.encryption_level == ENCRYPTION_LEVEL_NONE
    }

    /// Which header `class` carries in this context, or [`None`] when it
    /// carries none.
    ///
    /// Under an external security protocol only the six classes of
    /// [`SlowPathClass::carries_header_without_encryption`] have one, and it
    /// is basic. Under standard RDP security every slow path PDU has one, and
    /// it is the FIPS variant when the method is `ENCRYPTION_METHOD_FIPS`.
    /// The client refuses to negotiate standard security at all (PRDRDP/03
    /// §13.1), so the second half of this rule exists to make the table
    /// complete and testable rather than because we run in it.
    #[must_use]
    pub const fn header_kind(&self, class: SlowPathClass) -> Option<SecurityHeaderKind> {
        if self.is_external_security() {
            if class.carries_header_without_encryption() {
                return Some(SecurityHeaderKind::Basic);
            }
            return None;
        }
        if self.encryption_method == encryption_method::FIPS {
            return Some(SecurityHeaderKind::Fips);
        }
        Some(SecurityHeaderKind::NonFips)
    }
}

/// `TS_SECURITY_HEADER` (MS-RDPBCGR 2.2.8.1.1.2.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BasicSecurityHeader {
    /// `flags`, from [`security_flags`].
    pub flags: u16,
    /// `flagsHi`, reserved and zero.
    pub flags_hi: u16,
}

impl BasicSecurityHeader {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SECURITY_HEADER";

    /// A header carrying exactly `flags`.
    #[must_use]
    pub const fn new(flags: u16) -> Self {
        Self { flags, flags_hi: 0 }
    }

    /// True when `flag` is set.
    #[must_use]
    pub const fn has(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }
}

impl Encode for BasicSecurityHeader {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        BASIC_SECURITY_HEADER_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        if self.has(security_flags::ENCRYPT) {
            return Err(PduError::Encode {
                context: Self::NAME,
                reason: "SEC_ENCRYPT on an outgoing PDU; this client never encrypts at this layer",
            });
        }
        w.u16(self.flags);
        w.u16(self.flags_hi);
        Ok(())
    }
}

impl Decode<'_> for BasicSecurityHeader {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'_>) -> PduResult<Self> {
        let at = r.offset();
        let flags = r.u16(Self::NAME)?;
        let flags_hi = r.u16(Self::NAME)?;
        if flags & security_flags::ENCRYPT != 0 {
            // Naming the flag produces a much better error than the garbled
            // body a caller would otherwise get (PRDRDP/13 §5.2).
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "flags (SEC_ENCRYPT)",
                value: u64::from(flags),
                offset: at,
            });
        }
        Ok(Self { flags, flags_hi })
    }
}

/// One of the three headers of MS-RDPBCGR 2.2.8.1.1.2.
///
/// Only [`SecurityHeader::Basic`] is ever produced under an external security
/// protocol. The other two decode so that a server which believes standard
/// security is in force produces a clear error rather than a mis-parse, and
/// so §11's row for 2.2.8.1.1.2 is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityHeader {
    /// `TS_SECURITY_HEADER` (2.2.8.1.1.2.1).
    Basic(BasicSecurityHeader),
    /// `TS_SECURITY_HEADER1` (2.2.8.1.1.2.2).
    NonFips {
        /// The basic header it starts with.
        basic: BasicSecurityHeader,
        /// `dataSignature`, the eight byte MAC we never verify.
        data_signature: [u8; 8],
    },
    /// `TS_SECURITY_HEADER2` (2.2.8.1.1.2.3).
    Fips {
        /// The basic header it starts with.
        basic: BasicSecurityHeader,
        /// `length`, fixed at [`FIPS_HEADER_LENGTH_FIELD`].
        length: u16,
        /// `version`, [`TSFIPS_VERSION1`].
        version: u8,
        /// `padlen`, the block cipher padding on the body.
        pad_len: u8,
        /// `dataSignature`.
        data_signature: [u8; 8],
    },
}

impl SecurityHeader {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SECURITY_HEADER";

    /// The basic header every variant starts with.
    #[must_use]
    pub const fn basic(&self) -> BasicSecurityHeader {
        match self {
            Self::Basic(basic) | Self::NonFips { basic, .. } | Self::Fips { basic, .. } => *basic,
        }
    }

    /// Which variant this is.
    #[must_use]
    pub const fn kind(&self) -> SecurityHeaderKind {
        match self {
            Self::Basic(_) => SecurityHeaderKind::Basic,
            Self::NonFips { .. } => SecurityHeaderKind::NonFips,
            Self::Fips { .. } => SecurityHeaderKind::Fips,
        }
    }

    /// Read a header of the kind the context says is there.
    ///
    /// This is the only way to read one: there is deliberately no
    /// [`Decode`] implementation that guesses, because guessing is the bug
    /// PRDRDP/13 §5.2 is written to prevent.
    pub fn read(r: &mut Reader<'_>, kind: SecurityHeaderKind) -> PduResult<Self> {
        let basic = BasicSecurityHeader::decode(r)?;
        match kind {
            SecurityHeaderKind::Basic => Ok(Self::Basic(basic)),
            SecurityHeaderKind::NonFips => Ok(Self::NonFips {
                basic,
                data_signature: r.array::<8>(Self::NAME)?,
            }),
            SecurityHeaderKind::Fips => Ok(Self::Fips {
                basic,
                length: r.u16(Self::NAME)?,
                version: r.u8(Self::NAME)?,
                pad_len: r.u8(Self::NAME)?,
                data_signature: r.array::<8>(Self::NAME)?,
            }),
        }
    }
}

impl Encode for SecurityHeader {
    const NAME: &'static str = Self::NAME;

    fn size(&self) -> usize {
        self.kind().size()
    }

    fn encode(&self, w: &mut Writer<'_>) -> PduResult<()> {
        match self {
            Self::Basic(basic) => basic.encode(w),
            Self::NonFips {
                basic,
                data_signature,
            } => {
                basic.encode(w)?;
                w.bytes(data_signature);
                Ok(())
            }
            Self::Fips {
                basic,
                length,
                version,
                pad_len,
                data_signature,
            } => {
                basic.encode(w)?;
                w.u16(*length);
                w.u8(*version);
                w.u8(*pad_len);
                w.bytes(data_signature);
                Ok(())
            }
        }
    }
}

/// Read the security header a PDU of `class` carries in `context`, if any.
///
/// Returns [`None`] when the class carries none, having read nothing. The
/// flag check is the other half of the rule: a Client Info PDU without
/// `SEC_INFO_PKT` is not a Client Info PDU, and saying so here is much
/// clearer than the truncation the body decoder would otherwise report.
pub fn read_expected_header(
    r: &mut Reader<'_>,
    context: IoPduContext,
    class: SlowPathClass,
) -> PduResult<Option<SecurityHeader>> {
    let Some(kind) = context.header_kind(class) else {
        return Ok(None);
    };
    let at = r.offset();
    let header = SecurityHeader::read(r, kind)?;
    let expected = class.security_flag();
    if expected != 0 && !header.basic().has(expected) {
        return Err(PduError::InvalidField {
            context: SecurityHeader::NAME,
            field: "flags",
            value: u64::from(header.basic().flags),
            offset: at,
        });
    }
    Ok(Some(header))
}

/// Write the basic security header a PDU of `class` needs, if it needs one.
///
/// `extra` is ored into `flags` for the cases that carry more than the class
/// flag; nothing in phase 1 does, and the parameter exists so the licensing
/// encryption flags have somewhere to go when phase 3 needs them.
pub fn write_expected_header(
    w: &mut Writer<'_>,
    context: IoPduContext,
    class: SlowPathClass,
    extra: u16,
) -> PduResult<()> {
    if context.header_kind(class).is_none() {
        return Ok(());
    }
    BasicSecurityHeader::new(class.security_flag() | extra).encode(w)
}

/// The Client Security Exchange PDU (MS-RDPBCGR 2.2.1.10), decoded only.
///
/// # Why it is in this file
///
/// It is a security layer PDU and nothing else: a basic security header whose
/// only distinguishing feature is `SEC_EXCHANGE_PKT`, then
/// `TS_SECURITY_PACKET` (2.2.1.10.1), which is one length and one blob. It
/// carries no share header, so `share.rs` has no claim on it; it is not part
/// of the connection sequence this client runs, so `client_info.rs` has none
/// either. What it does belong beside is [`security_flags::EXCHANGE_PKT`],
/// the flag that identifies it, and the table in this file's module comment
/// that says which classes carry a header at all.
///
/// # Why there is no encoder
///
/// The client sends this PDU only under standard RDP security, where it
/// carries a 32 byte client random encrypted under the server's proprietary
/// certificate with RSA (MS-RDPBCGR 5.3.4). This client requires an external
/// security protocol (PRDRDP/03 §13.1) and this crate does no cryptography
/// (PRDRDP/00 R54), so there is nothing to put in the blob and an encoder
/// would be an encoder for a PDU we cannot legitimately fill. Decoding is
/// still worth having: it lets the mock server of PRDRDP/09 §3 recognise the
/// PDU by name when a test drives the standard security path, and it makes
/// §11's row for 2.2.1.10 complete rather than absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientSecurityExchange<'a> {
    /// The basic header, kept because `flags` may carry more than
    /// `SEC_EXCHANGE_PKT`.
    pub header: BasicSecurityHeader,
    /// `encryptedClientRandom`, `length` bytes of which the last eight are
    /// padding (2.2.1.10.1). Borrowed: nothing here is interpreted, so
    /// nothing is copied.
    pub encrypted_client_random: crate::io::Payload<'a>,
}

impl<'a> ClientSecurityExchange<'a> {
    /// The structure's name in the specification.
    pub const NAME: &'static str = "TS_SECURITY_PACKET";

    /// The eight bytes of padding `length` counts and the blob ends with
    /// (MS-RDPBCGR 2.2.1.10.1).
    pub const PADDING_LEN: usize = 8;
}

impl<'a> Decode<'a> for ClientSecurityExchange<'a> {
    const NAME: &'static str = Self::NAME;

    fn decode(r: &mut Reader<'a>) -> PduResult<Self> {
        let at = r.offset();
        let header = BasicSecurityHeader::decode(r)?;
        if !header.has(security_flags::EXCHANGE_PKT) {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "flags (SEC_EXCHANGE_PKT)",
                value: u64::from(header.flags),
                offset: at,
            });
        }
        let at = r.offset();
        let length = r.u32(Self::NAME)?;
        // No cap: the blob is never allocated, only borrowed, so a lie in
        // `length` costs a `Truncated` error and not a `Vec`. The one bound
        // worth stating is the specification's own, that `length` counts the
        // eight padding bytes and so cannot be smaller than them.
        let length = usize::try_from(length).map_err(|_| PduError::InvalidField {
            context: Self::NAME,
            field: "length",
            value: u64::from(length),
            offset: at,
        })?;
        if length < Self::PADDING_LEN {
            return Err(PduError::InvalidField {
                context: Self::NAME,
                field: "length",
                value: length as u64,
                offset: at,
            });
        }
        let encrypted_client_random = crate::io::Payload::new(r.slice(length, Self::NAME)?);
        Ok(Self {
            header,
            encrypted_client_random,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    const CLASSES: &[SlowPathClass] = &[
        SlowPathClass::ClientInfo,
        SlowPathClass::Licensing,
        SlowPathClass::AutoDetectRequest,
        SlowPathClass::AutoDetectResponse,
        SlowPathClass::Heartbeat,
        SlowPathClass::EnhancedRedirection,
        SlowPathClass::MultitransportRequest,
        SlowPathClass::MultitransportResponse,
        SlowPathClass::Other,
    ];

    /// PRDRDP/13 §5.2's table, stated as a test: every combination of
    /// encryption level and PDU class against the expected presence.
    #[test]
    fn the_presence_table_holds_for_every_combination() {
        let external = IoPduContext::external_security();
        for class in CLASSES {
            let expected = match class {
                SlowPathClass::Other => None,
                _ => Some(SecurityHeaderKind::Basic),
            };
            assert_eq!(external.header_kind(*class), expected, "{class:?}");
        }

        // Standard security, which we never negotiate: every slow path PDU
        // carries a header, and the FIPS method selects the FIPS variant.
        let fips = IoPduContext {
            encryption_method: encryption_method::FIPS,
            encryption_level: encryption_level::FIPS,
        };
        let standard = IoPduContext {
            encryption_method: encryption_method::BIT128,
            encryption_level: encryption_level::CLIENT_COMPATIBLE,
        };
        for class in CLASSES {
            assert_eq!(
                fips.header_kind(*class),
                Some(SecurityHeaderKind::Fips),
                "{class:?}"
            );
            assert_eq!(
                standard.header_kind(*class),
                Some(SecurityHeaderKind::NonFips),
                "{class:?}"
            );
        }
    }

    /// The failure this module exists to prevent: a Demand Active must not
    /// lose four bytes to a header that is not there.
    #[test]
    fn a_share_control_pdu_reads_no_security_header() {
        let bytes = [0x1a, 0x00, 0x11, 0x00, 0xea, 0x03];
        let mut r = Reader::new(&bytes);
        let header = read_expected_header(
            &mut r,
            IoPduContext::external_security(),
            SlowPathClass::Other,
        )
        .unwrap();
        assert!(header.is_none());
        assert_eq!(
            r.remaining(),
            bytes.len(),
            "the header reader consumed bytes"
        );
    }

    #[test]
    fn the_basic_header_round_trips_and_carries_its_class_flag() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            write_expected_header(
                &mut w,
                IoPduContext::external_security(),
                SlowPathClass::ClientInfo,
                0,
            )
            .unwrap();
        }
        assert_eq!(buf, [0x40, 0x00, 0x00, 0x00]);

        let header = read_expected_header(
            &mut Reader::new(&buf),
            IoPduContext::external_security(),
            SlowPathClass::ClientInfo,
        )
        .unwrap()
        .unwrap();
        assert_eq!(header.kind(), SecurityHeaderKind::Basic);
        assert!(header.basic().has(security_flags::INFO_PKT));
    }

    #[test]
    fn a_licensing_header_is_recognised_by_its_flag() {
        let bytes = [0x80, 0x00, 0x00, 0x00];
        let header = read_expected_header(
            &mut Reader::new(&bytes),
            IoPduContext::external_security(),
            SlowPathClass::Licensing,
        )
        .unwrap()
        .unwrap();
        assert!(header.basic().has(security_flags::LICENSE_PKT));
    }

    /// A header without the flag its class requires is a mis-parse waiting to
    /// happen, and saying so here is clearer than the truncation the body
    /// decoder would report.
    #[test]
    fn a_missing_class_flag_is_an_invalid_field() {
        let bytes = [0x00, 0x00, 0x00, 0x00];
        let err = read_expected_header(
            &mut Reader::new(&bytes),
            IoPduContext::external_security(),
            SlowPathClass::ClientInfo,
        )
        .unwrap_err();
        assert!(matches!(err, PduError::InvalidField { field: "flags", .. }));
    }

    /// `SEC_ENCRYPT` in either direction is the end of the session, and it is
    /// worth an error that names the flag.
    #[test]
    fn sec_encrypt_is_refused_in_both_directions() {
        let bytes = [0x48, 0x00, 0x00, 0x00];
        let err = BasicSecurityHeader::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            PduError::InvalidField {
                field: "flags (SEC_ENCRYPT)",
                ..
            }
        ));

        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        let err = BasicSecurityHeader::new(security_flags::ENCRYPT)
            .encode(&mut w)
            .unwrap_err();
        assert!(matches!(err, PduError::Encode { .. }));
    }

    #[test]
    fn the_three_variants_round_trip_at_their_stated_sizes() {
        let basic = BasicSecurityHeader::new(security_flags::INFO_PKT);
        let cases = [
            SecurityHeader::Basic(basic),
            SecurityHeader::NonFips {
                basic,
                data_signature: [1, 2, 3, 4, 5, 6, 7, 8],
            },
            SecurityHeader::Fips {
                basic,
                length: FIPS_HEADER_LENGTH_FIELD,
                version: TSFIPS_VERSION1,
                pad_len: 6,
                data_signature: [9, 10, 11, 12, 13, 14, 15, 16],
            },
        ];
        for case in cases {
            let mut buf = Vec::new();
            case.encode_checked(&mut Writer::new(&mut buf)).unwrap();
            assert_eq!(buf.len(), case.size());
            assert_eq!(buf.len(), case.kind().size());
            assert_eq!(
                SecurityHeader::read(&mut Reader::new(&buf), case.kind()).unwrap(),
                case
            );
        }
    }

    /// A hand computed Client Security Exchange (MS-RDPBCGR 2.2.1.10.1).
    ///
    /// `SEC_EXCHANGE_PKT` is 0x0001, so `flags` is `01 00` and `flagsHi` is
    /// `00 00`. `length` is the blob plus its eight padding bytes: eight
    /// bytes of "random" here plus eight of padding is sixteen, so `length`
    /// is `10 00 00 00`. Four header bytes plus four length bytes plus
    /// sixteen of blob is twenty four bytes in all.
    fn client_security_exchange_bytes() -> Vec<u8> {
        let mut bytes = vec![0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&[0xaa; 8]);
        bytes.extend_from_slice(&[0x00; 8]);
        assert_eq!(bytes.len(), 4 + 4 + 16);
        bytes
    }

    #[test]
    fn a_client_security_exchange_decodes_its_blob_without_copying_it() {
        let bytes = client_security_exchange_bytes();
        let pdu = ClientSecurityExchange::decode(&mut Reader::new(&bytes)).unwrap();
        assert!(pdu.header.has(security_flags::EXCHANGE_PKT));
        assert_eq!(pdu.encrypted_client_random.len(), 16);
        assert_eq!(
            pdu.encrypted_client_random.as_slice(),
            &bytes[8..],
            "the blob is the tail of the buffer"
        );
        // Borrowed, so the view points inside the buffer it was decoded from.
        let offset =
            pdu.encrypted_client_random.as_slice().as_ptr() as usize - bytes.as_ptr() as usize;
        assert_eq!(offset, 8);
    }

    #[test]
    fn a_security_exchange_without_its_flag_is_refused() {
        let mut bytes = client_security_exchange_bytes();
        bytes[0] = 0x40;
        assert!(matches!(
            ClientSecurityExchange::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField {
                field: "flags (SEC_EXCHANGE_PKT)",
                ..
            }
        ));
    }

    /// `length` counts the eight padding bytes, so a smaller value is a
    /// structure we are not looking at (MS-RDPBCGR 2.2.1.10.1).
    #[test]
    fn a_security_exchange_shorter_than_its_padding_is_refused() {
        let mut bytes = client_security_exchange_bytes();
        bytes[4] = 0x07;
        assert!(matches!(
            ClientSecurityExchange::decode(&mut Reader::new(&bytes)).unwrap_err(),
            PduError::InvalidField {
                field: "length",
                ..
            }
        ));
    }

    #[test]
    fn every_prefix_of_a_security_exchange_errors_rather_than_panicking() {
        let bytes = client_security_exchange_bytes();
        for cut in 0..bytes.len() {
            assert!(
                ClientSecurityExchange::decode(&mut Reader::new(&bytes[..cut])).is_err(),
                "a {cut} byte prefix decoded"
            );
        }
        // A `length` a hostile server made enormous is a truncation and never
        // an allocation.
        let mut huge = client_security_exchange_bytes();
        huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            ClientSecurityExchange::decode(&mut Reader::new(&huge)).unwrap_err(),
            PduError::Truncated { .. }
        ));
    }

    #[test]
    fn every_prefix_of_every_header_errors_rather_than_panicking() {
        let full = [
            0x40, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x06, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        for kind in [
            SecurityHeaderKind::Basic,
            SecurityHeaderKind::NonFips,
            SecurityHeaderKind::Fips,
        ] {
            for cut in 0..kind.size() {
                assert!(
                    SecurityHeader::read(&mut Reader::new(&full[..cut]), kind).is_err(),
                    "{kind:?} decoded from {cut} bytes"
                );
            }
        }
    }
}
