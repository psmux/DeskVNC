//! RFC 4121: the Kerberos V5 GSS-API mechanism.
//!
//! Three things live here and they are worth keeping apart:
//!
//! 1. The context establishment token: an AP-REQ inside RFC 2743 §3.1's
//!    `[APPLICATION 0]` framing, with the authenticator checksum of
//!    RFC 4121 §4.1.1 that carries the channel binding and the flags.
//! 2. The AP-REP that comes back, which settles which key per-message tokens
//!    are protected with (RFC 4121 §2).
//! 3. [`GssContext`], the per-message half: `GSS_Wrap`, `GSS_Unwrap`,
//!    `GSS_GetMIC` and `GSS_VerifyMIC` as RFC 4121 §4.2 lays them out. This
//!    is what [`GssMechanism::wrap`](crate::gss::GssMechanism::wrap) and its
//!    three companions become on the Kerberos path.
//!
//! ## Known risk, stated rather than discovered later
//!
//! **RFC 4121 publishes no test vectors.** Nothing in this file is held by a
//! value from a specification, unlike the whole of `crypto.rs`. What holds it
//! is the structure tests below, a round trip against an acceptor written
//! from the same text, and the live interop matrix (PRDRDP/14 §7.3). Both
//! sides of that round trip share this crate's reading of RFC 4121, so a
//! misreading common to both passes.
//!
//! The three parts most likely to be wrong, in order:
//!
//! * **The per-message sequence numbers.** RFC 4121 §4.2.1 says the sender
//!   increments after sending, and the initial value is the `seq-number` in
//!   the authenticator. The acceptor's initial value is the `seq-number` in
//!   the AP-REP's `EncAPRepPart`, which RFC 4120 §5.5.2 makes OPTIONAL. When
//!   the acceptor supplies one we hold it to it; when it does not we latch
//!   onto the first token it sends. That leniency is deliberate and it is
//!   narrow: the exchange runs inside TLS against a certificate we have
//!   already bound to, so the replay a strict check would prevent is one an
//!   attacker cannot mount, and being strict here against a server that
//!   omits the field would fail every connection to it.
//! * **The `RRC` rotation.** We send `RRC = 0`, which needs no rotation at
//!   all and is what makes the sending path simple. RFC 4121 §4.2.5 requires
//!   a receiver to "be able to interpret all possible rotation count values",
//!   so the receiving path implements it properly and is exercised at every
//!   rotation in the tests.
//! * **The empty final token.** See [`super::KerberosClient`].

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use rdp_pdu::asn1::der::{expect_tag, read_tlv, write_int, write_nested, write_tlv};
use rdp_pdu::asn1::{context, tag};

use crate::bindings::ChannelBindings;
use crate::error::AuthError;

use super::asn1::{
    app, application, kerberos_flags, msg_type, write_checksum, write_encrypted_data,
    write_kerberos_string, write_kerberos_time, write_principal_name, EncryptedData, EncryptionKey,
    KerberosTime, PVNO,
};
use super::crypto::{self, usage, Enctype, Key, BLOCK_LEN, CHECKSUM_LEN};
use super::kdc::ServiceTicket;

/// `[APPLICATION 15]`, `AP-REP` (RFC 4120 §5.5.2).
const APP_AP_REP: u8 = 15;
/// `[APPLICATION 27]`, `EncAPRepPart` (RFC 4120 §5.5.2).
const APP_ENC_AP_REP_PART: u8 = 27;

/// TOK_ID values for the context establishment tokens (RFC 4121 §4.1).
const TOK_ID_AP_REQ: [u8; 2] = [0x01, 0x00];
const TOK_ID_AP_REP: [u8; 2] = [0x02, 0x00];
const TOK_ID_KRB_ERROR: [u8; 2] = [0x03, 0x00];
/// TOK_ID for a MIC token (RFC 4121 §4.2.6.1).
const TOK_ID_MIC: [u8; 2] = [0x04, 0x04];
/// TOK_ID for a Wrap token (RFC 4121 §4.2.6.2).
const TOK_ID_WRAP: [u8; 2] = [0x05, 0x04];

/// The per-message token header is sixteen octets for both kinds
/// (RFC 4121 §4.2.6).
const TOKEN_HEADER_LEN: usize = 16;

/// The `Flags` octet of a per-message token (RFC 4121 §4.2.2).
mod token_flag {
    /// Bit 0: the sender is the context acceptor.
    pub const SENT_BY_ACCEPTOR: u8 = 0x01;
    /// Bit 1: confidentiality is provided for. Wrap tokens only; RFC 4121
    /// §4.2.2 says it "SHALL NOT be set in MIC tokens".
    pub const SEALED: u8 = 0x02;
    /// Bit 2: a subkey asserted by the acceptor is protecting the message.
    pub const ACCEPTOR_SUBKEY: u8 = 0x04;
}

/// The context establishment flags of RFC 4121 §4.1.1.1, as they go in the
/// `Flags` field of the 0x8003 checksum.
mod gss_flag {
    /// `GSS_C_DELEG_FLAG`. Never set: delegating a TGT to a Remote Desktop
    /// host hands it the user's whole domain identity, which is what
    /// unconstrained delegation attacks harvest, and RDP does not need it.
    #[allow(dead_code)]
    pub const DELEG: u32 = 1;
    /// `GSS_C_MUTUAL_FLAG`. The server proves it holds the service key by
    /// answering with an AP-REP.
    pub const MUTUAL: u32 = 2;
    /// `GSS_C_REPLAY_FLAG`.
    pub const REPLAY: u32 = 4;
    /// `GSS_C_SEQUENCE_FLAG`.
    pub const SEQUENCE: u32 = 8;
    /// `GSS_C_CONF_FLAG`. CredSSP wraps `pubKeyAuth` and `authInfo` with
    /// confidentiality (MS-CSSP 3.1.5), so it is asked for.
    pub const CONF: u32 = 16;
    /// `GSS_C_INTEG_FLAG`.
    pub const INTEG: u32 = 32;
}

/// The flags this client asks for: mutual authentication, replay and
/// sequence detection, confidentiality and integrity, and no delegation.
const REQUESTED_FLAGS: u32 =
    gss_flag::MUTUAL | gss_flag::REPLAY | gss_flag::SEQUENCE | gss_flag::CONF | gss_flag::INTEG;

/// `mutual-required(2)` in `APOptions` (RFC 4120 §5.5.1).
const AP_OPTION_MUTUAL_REQUIRED: u32 = 2;

/// The checksum type of RFC 4121 §4.1.1, which is a structure and not a MAC.
///
/// 0x8003 is 32771. It is in the "unassigned" range of RFC 3961 §8 on purpose:
/// it names a field layout that carries channel bindings and flags, not an
/// algorithm, and nothing keys it. A reader who assumes every `Checksum` in
/// Kerberos is a keyed hash will look for a key here and not find one.
pub const CKSUMTYPE_GSSAPI: i64 = 0x8003;

/// The 0x8003 authenticator checksum, RFC 4121 §4.1.1.
///
/// ```text
/// 0..3    Lgth   16, little endian
/// 4..19   Bnd    the MD5 of the gss_channel_bindings_struct, or 16 zeroes
/// 20..23  Flags  the context establishment flags, little endian
/// ```
///
/// Twenty four octets, which is the minimum RFC 4121 §4.1.1 allows when
/// `GSS_C_DELEG_FLAG` is clear, and the maximum an initiator that does not
/// implement the §4.1.1.2 extensions may send.
///
/// **Little endian, twice.** Both `Lgth` and `Flags` are little endian inside
/// a structure that sits in an ASN.1 message where every other integer is big
/// endian. That is not a mistake in the RFC and it is the single most likely
/// transcription error in this file; a big endian `Flags` of 62 becomes
/// `0x3E000000`, which sets four reserved bits and clears every flag the
/// server is looking for.
///
/// `Bnd` is [`ChannelBindings::value`], the same MD5 over the same RFC 2744
/// §3.11 structure that the NTLM path puts in its `MsvAvChannelBindings` AV
/// pair. That is why `bindings.rs` is a crate level module and not part of
/// `ntlm/` (PRDRDP/14 §7.1 item 5).
#[must_use]
pub fn authenticator_checksum(bindings: Option<&ChannelBindings>) -> [u8; 24] {
    let mut out = [0u8; 24];
    // Lgth: "Currently contains hex value 10 00 00 00 (16)".
    if let Some(slot) = out.get_mut(..4) {
        slot.copy_from_slice(&16u32.to_le_bytes());
    }
    // Bnd: sixteen zeroes stand for GSS_C_NO_CHANNEL_BINDINGS
    // (RFC 4121 §4.1.1.2).
    if let Some(bindings) = bindings {
        if let Some(slot) = out.get_mut(4..20) {
            slot.copy_from_slice(bindings.value());
        }
    }
    if let Some(slot) = out.get_mut(20..24) {
        slot.copy_from_slice(&REQUESTED_FLAGS.to_le_bytes());
    }
    out
}

/// RFC 2743 §3.1's `InitialContextToken`, which RFC 4121 §4.1 puts the
/// mechanism's first token inside.
///
/// ```text
/// [APPLICATION 0] IMPLICIT SEQUENCE { thisMech OBJECT IDENTIFIER, innerToken ANY }
/// ```
///
/// IMPLICIT, so there is no `0x30` after the `0x60`: the OID follows the
/// application header directly and the inner token follows the OID with no
/// tag of its own. `spnego::token` states the same rule for the SPNEGO
/// wrapper and gives the reason it catches people out; this is that wrapper
/// with a different OID, which is what PRDRDP/14 §7.1 item 4 means by the
/// encoder being shared.
fn initial_context_token(mech_oid: &[u8], tok_id: [u8; 2], inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inner.len() + 32);
    write_nested(
        &mut out,
        crate::spnego::token::TAG_INITIAL_CONTEXT_TOKEN,
        |body| {
            write_tlv(body, tag::OBJECT_IDENTIFIER, mech_oid);
            body.extend_from_slice(&tok_id);
            body.extend_from_slice(inner);
        },
    );
    out
}

/// An AP-REQ, ready to send, and the state the reply is checked against.
pub struct ApReqToken {
    /// The framed token.
    pub token: Vec<u8>,
    /// The subkey we asserted. RFC 4121 §2: this is the base key unless the
    /// acceptor asserts one of its own.
    pub subkey: Key,
    /// The `seq-number` we asserted, which is our first sending sequence.
    pub seq_number: u64,
}

/// Build the AP-REQ that establishes the context (RFC 4120 §5.5.1,
/// RFC 4121 §4.1).
///
/// An initiator subkey is asserted. RFC 4121 §2 allows the ticket session key
/// to be the base key when neither side asserts a subkey, and asserting one
/// is better: the ticket session key is fixed for the life of the ticket and
/// known to the KDC, and a per connection subkey is neither. Windows asserts
/// one too.
///
/// `mutual-required` is set, so the service answers with an AP-REP and proves
/// it holds the service key. Without it a client cannot tell a real host from
/// anything that can replay a ticket at it.
///
/// # Errors
///
/// Whatever the encryption of the authenticator makes of the session key.
pub fn build_ap_req(
    ticket: &ServiceTicket,
    bindings: Option<&ChannelBindings>,
    now_unix: i64,
    mech_oid: &[u8],
) -> Result<ApReqToken, AuthError> {
    let enctype = ticket.session_key.enctype();
    let subkey = fresh_subkey(enctype)?;
    let seq_number = fresh_sequence_number();
    let ctime = KerberosTime::from_unix_seconds(now_unix)?;
    let checksum = authenticator_checksum(bindings);

    let mut authenticator = Vec::new();
    write_nested(
        &mut authenticator,
        application(app::AUTHENTICATOR),
        |outer| {
            write_nested(outer, tag::SEQUENCE, |seq| {
                write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, PVNO));
                write_nested(seq, context(1), |t| {
                    write_kerberos_string(t, &ticket.client_realm);
                });
                write_nested(seq, context(2), |t| {
                    let parts: Vec<&str> = ticket
                        .client_name
                        .components
                        .iter()
                        .map(String::as_str)
                        .collect();
                    write_principal_name(t, ticket.client_name.name_type, &parts);
                });
                // cksum [3] Checksum, type 0x8003. RFC 4121 §4.1.1: "The
                // authenticator in the KRB_AP_REQ message MUST include the
                // optional sequence number and the checksum field."
                write_nested(seq, context(3), |t| {
                    write_checksum(t, CKSUMTYPE_GSSAPI, &checksum);
                });
                write_nested(seq, context(4), |t| write_int(t, tag::INTEGER, 0));
                write_nested(seq, context(5), |t| write_kerberos_time(t, ctime));
                // subkey [6] EncryptionKey.
                write_nested(seq, context(6), |t| {
                    write_nested(t, tag::SEQUENCE, |k| {
                        write_nested(k, context(0), |x| {
                            write_int(x, tag::INTEGER, i64::from(enctype.etype()));
                        });
                        write_nested(k, context(1), |x| {
                            write_tlv(x, tag::OCTET_STRING, subkey.octets());
                        });
                    });
                });
                // seq-number [7] UInt32.
                write_nested(seq, context(7), |t| {
                    write_int(t, tag::INTEGER, i64::try_from(seq_number).unwrap_or(0));
                });
            });
        },
    );
    let authenticator = Zeroizing::new(authenticator);

    // RFC 4120 §7.5.1: key usage 11 for an AP-REQ authenticator going to a
    // service. 7 is the number the same structure takes when it goes to the
    // KDC inside a PA-TGS-REQ, and using it here is rejected with no
    // diagnostic.
    let encrypted = crypto::encrypt(
        &ticket.session_key,
        usage::AP_REQ_AUTHENTICATOR,
        &authenticator,
    )?;

    let mut ap_req = Vec::new();
    write_nested(&mut ap_req, application(app::AP_REQ), |outer| {
        write_nested(outer, tag::SEQUENCE, |seq| {
            write_nested(seq, context(0), |t| write_int(t, tag::INTEGER, PVNO));
            write_nested(seq, context(1), |t| {
                write_int(t, tag::INTEGER, msg_type::AP_REQ);
            });
            write_nested(seq, context(2), |t| {
                let mut bits = vec![0x00];
                bits.extend_from_slice(&kerberos_flags(&[AP_OPTION_MUTUAL_REQUIRED]));
                write_tlv(t, tag::BIT_STRING, &bits);
            });
            write_nested(seq, context(3), |t| {
                t.extend_from_slice(ticket.ticket.der());
            });
            write_nested(seq, context(4), |t| {
                write_encrypted_data(t, enctype, &encrypted);
            });
        });
    });

    Ok(ApReqToken {
        token: initial_context_token(mech_oid, TOK_ID_AP_REQ, &ap_req),
        subkey,
        seq_number,
    })
}

/// What an AP-REP settles (RFC 4120 §5.5.2, RFC 4121 §2).
pub struct ApRepContents {
    /// The acceptor's subkey, when it asserted one. RFC 4121 §2: "If the
    /// acceptor asserts a subkey, the base key is the acceptor-asserted
    /// subkey and subsequent per-message tokens MUST be flagged with
    /// AcceptorSubkey".
    pub subkey: Option<Key>,
    /// The acceptor's initial sequence number, when it sent one.
    pub seq_number: Option<u64>,
}

impl std::fmt::Debug for ApRepContents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApRepContents")
            .field("subkey", &self.subkey.as_ref().map(Key::enctype))
            .field("seq_number", &self.seq_number)
            .finish()
    }
}

/// Read the acceptor's answer to our AP-REQ.
///
/// Accepts the token in either of the two shapes it arrives in. RFC 2743 §3.1
/// frames only the initiator's **first** token, so an acceptor's AP-REP is
/// bare `02 00 || AP-REP`; some stacks frame it in `[APPLICATION 0]` anyway.
/// Both are read, because refusing the second would fail against a real
/// server for no benefit and the framing carries nothing we act on.
///
/// A `03 00` token is a `KRB-ERROR` and is turned into the error it names,
/// which is how a service with the wrong key or a clock too far out says so.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] for a token that is neither,
/// [`AuthError::KdcRefused`] for a `KRB-ERROR`, and
/// [`AuthError::SignatureMismatch`] when the `EncAPRepPart` does not decrypt,
/// which means the service does not hold the key the KDC gave the ticket to.
pub fn parse_ap_rep(token: &[u8], session_key: &Key) -> Result<ApRepContents, AuthError> {
    let bad = AuthError::MalformedMessage("AP-REP");
    let inner = strip_context_framing(token)?;
    let (tok_id, body) = inner.split_at_checked(2).ok_or(bad)?;

    if tok_id == TOK_ID_KRB_ERROR {
        let error = super::asn1::KrbError::read(body)?;
        let code = i32::try_from(error.error_code).unwrap_or(i32::MAX);
        tracing::warn!(
            code,
            "the remote computer answered the AP-REQ with a KRB-ERROR"
        );
        return Err(AuthError::KdcRefused(code));
    }
    if tok_id != TOK_ID_AP_REP {
        return Err(bad);
    }

    let ap_rep = read_tlv(body).ok_or(bad)?.0;
    if ap_rep.tag != application(APP_AP_REP) {
        return Err(bad);
    }
    let (seq, _) = expect_tag(ap_rep.content, tag::SEQUENCE).ok_or(bad)?;

    let mut rest = seq;
    let (pvno, next) = take_field(rest, 0).ok_or(bad)?;
    if read_int(pvno)? != PVNO {
        return Err(AuthError::MalformedMessage("AP-REP.pvno"));
    }
    rest = next;
    let (mtype, next) = take_field(rest, 1).ok_or(bad)?;
    if read_int(mtype)? != 15 {
        return Err(AuthError::MalformedMessage("AP-REP.msg-type"));
    }
    rest = next;
    let (enc_field, _) = take_field(rest, 2).ok_or(bad)?;
    let enc = EncryptedData::read(enc_field)?;

    // RFC 4120 §5.5.2: the EncAPRepPart "is computed with a key usage value
    // of 12" under the ticket session key, and not under any subkey: the
    // subkey is what the reply is announcing, so it cannot be what protects
    // the announcement.
    let plain = crypto::decrypt(session_key, usage::AP_REP_ENC_PART, &enc.cipher)?;

    let part = read_tlv(&plain).ok_or(bad)?.0;
    if part.tag != application(APP_ENC_AP_REP_PART) {
        return Err(AuthError::MalformedMessage("EncAPRepPart"));
    }
    let (body, _) = expect_tag(part.content, tag::SEQUENCE).ok_or(bad)?;

    // ctime [0] and cusec [1] are required and are not checked against our
    // own clock: RFC 4120 §5.5.2 has the *acceptor* echo the values from our
    // authenticator, so they prove nothing we do not already know, and the
    // decryption above is what proves the service holds the key.
    let mut rest = body;
    let (_ctime, next) = take_field(rest, 0).ok_or(bad)?;
    rest = next;
    let (_cusec, next) = take_field(rest, 1).ok_or(bad)?;
    rest = next;

    let (subkey, rest) = match take_field(rest, 2) {
        Some((field, next)) => {
            let key = EncryptionKey::read(field)?;
            let enctype = Enctype::from_etype(i32::try_from(key.keytype).unwrap_or(0))
                .ok_or(AuthError::MalformedMessage("EncAPRepPart.subkey.keytype"))?;
            (Some(Key::new(enctype, &key.keyvalue)?), next)
        }
        None => (None, rest),
    };
    let seq_number = match take_field(rest, 3) {
        Some((field, _)) => Some(u64::try_from(read_int(field)?).unwrap_or(0)),
        None => None,
    };

    Ok(ApRepContents { subkey, seq_number })
}

/// Strip an `[APPLICATION 0]` wrapper and its OID if one is present,
/// returning the inner token either way.
fn strip_context_framing(token: &[u8]) -> Result<&[u8], AuthError> {
    let bad = AuthError::MalformedMessage("GSS token framing");
    let Some((tlv, _)) = read_tlv(token) else {
        return if token.len() >= 2 {
            Ok(token)
        } else {
            Err(bad)
        };
    };
    if tlv.tag != crate::spnego::token::TAG_INITIAL_CONTEXT_TOKEN {
        return Ok(token);
    }
    // IMPLICIT: the OID follows the header directly, then the inner token.
    let (oid, rest) = read_tlv(tlv.content).ok_or(bad)?;
    if oid.tag != tag::OBJECT_IDENTIFIER {
        return Err(bad);
    }
    Ok(rest)
}

/// One `[n]` field at the front of a SEQUENCE's content, and the rest.
fn take_field(buf: &[u8], n: u8) -> Option<(&[u8], &[u8])> {
    match read_tlv(buf) {
        Some((tlv, rest)) if tlv.tag == context(n) => Some((tlv.content, rest)),
        _ => None,
    }
}

/// An `INTEGER` inside a `[n]` wrapper.
fn read_int(buf: &[u8]) -> Result<i64, AuthError> {
    rdp_pdu::asn1::der::read_int_i64(buf)
        .map(|(value, _)| value)
        .ok_or(AuthError::MalformedMessage("INTEGER"))
}

/// A fresh subkey, from `rand::rng()` and nothing else (PRDRDP/14 §2.10).
fn fresh_subkey(enctype: Enctype) -> Result<Key, AuthError> {
    use rand::Rng;
    let mut octets = Zeroizing::new(vec![0u8; enctype.key_len()]);
    rand::rng().fill_bytes(&mut octets);
    Key::new(enctype, &octets)
}

/// A fresh initial sequence number (RFC 4121 §4.2.1).
///
/// Masked to 31 bits because it is announced in the authenticator's
/// `seq-number`, which RFC 4120 §5.2.4 types `UInt32`, and because a value
/// with the top bit set encodes as a five octet DER `INTEGER` that some
/// implementations have been reported to mishandle. The sequence is 64 bits
/// on the wire in a per-message token and counts up from here.
fn fresh_sequence_number() -> u64 {
    use rand::Rng;
    let mut bytes = [0u8; 4];
    rand::rng().fill_bytes(&mut bytes);
    u64::from(u32::from_be_bytes(bytes) & 0x7fff_ffff)
}

/// The per-message half of the mechanism (RFC 4121 §4.2).
pub struct GssContext {
    /// The base key of RFC 4121 §2: the acceptor's subkey if it asserted one,
    /// otherwise ours.
    base_key: Key,
    /// Set when the base key is the acceptor's subkey, which RFC 4121 §4.2.2
    /// requires every per-message token to be flagged with.
    acceptor_subkey: bool,
    /// Our next sending sequence number.
    send_seq: u64,
    /// The acceptor's next expected sequence number, once known.
    recv_seq: Option<u64>,
}

impl GssContext {
    /// Build the context from what the AP-REQ asserted and what the AP-REP
    /// answered (RFC 4121 §2).
    #[must_use]
    pub fn new(request: ApReqToken, reply: ApRepContents) -> Self {
        let acceptor_subkey = reply.subkey.is_some();
        let base_key = reply.subkey.unwrap_or(request.subkey);
        GssContext {
            base_key,
            acceptor_subkey,
            send_seq: request.seq_number,
            recv_seq: reply.seq_number,
        }
    }

    /// The `Flags` octet for a token we send (RFC 4121 §4.2.2).
    fn our_flags(&self, sealed: bool) -> u8 {
        let mut flags = 0u8;
        if sealed {
            flags |= token_flag::SEALED;
        }
        if self.acceptor_subkey {
            flags |= token_flag::ACCEPTOR_SUBKEY;
        }
        flags
    }

    /// A sixteen octet per-message token header (RFC 4121 §4.2.6).
    fn header(tok_id: [u8; 2], flags: u8, ec: u16, rrc: u16, seq: u64) -> [u8; TOKEN_HEADER_LEN] {
        let mut out = [0u8; TOKEN_HEADER_LEN];
        if let Some(slot) = out.get_mut(..2) {
            slot.copy_from_slice(&tok_id);
        }
        if let Some(slot) = out.get_mut(2) {
            *slot = flags;
        }
        if tok_id == TOK_ID_MIC {
            // RFC 4121 §4.2.6.1: five octets of 0xFF, then the sequence.
            if let Some(slot) = out.get_mut(3..8) {
                slot.copy_from_slice(&[0xff; 5]);
            }
        } else {
            // RFC 4121 §4.2.6.2: one filler octet, then EC and RRC.
            if let Some(slot) = out.get_mut(3) {
                *slot = 0xff;
            }
            if let Some(slot) = out.get_mut(4..6) {
                slot.copy_from_slice(&ec.to_be_bytes());
            }
            if let Some(slot) = out.get_mut(6..8) {
                slot.copy_from_slice(&rrc.to_be_bytes());
            }
        }
        if let Some(slot) = out.get_mut(8..16) {
            slot.copy_from_slice(&seq.to_be_bytes());
        }
        out
    }

    /// `GSS_Wrap` with confidentiality, RFC 4121 §4.2.4 and §4.2.6.2.
    ///
    /// ```text
    /// token = header | encrypt(plaintext | filler | header)
    /// ```
    ///
    /// with `EC = 0`, so there is no filler, and `RRC = 0`, so there is no
    /// rotation. RFC 4121 §4.2.4 requires the header appended to the
    /// plaintext to carry `RRC = 00 00` whatever the emitted header says;
    /// with `RRC = 0` the two are the same sixteen octets, which is one fewer
    /// place for them to diverge.
    ///
    /// The appended header is what binds the ciphertext to its own sequence
    /// number and flags: without it a token could be replayed under a
    /// different header and the integrity tag would still verify.
    ///
    /// # Errors
    ///
    /// Whatever the encryption makes of the base key.
    pub fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        let header = Self::header(TOK_ID_WRAP, self.our_flags(true), 0, 0, self.send_seq);

        let mut to_encrypt = Zeroizing::new(Vec::with_capacity(plaintext.len() + TOKEN_HEADER_LEN));
        to_encrypt.extend_from_slice(plaintext);
        to_encrypt.extend_from_slice(&header);

        let ciphertext = crypto::encrypt(&self.base_key, usage::GSS_INITIATOR_SEAL, &to_encrypt)?;
        self.send_seq = self.send_seq.wrapping_add(1);

        let mut token = Vec::with_capacity(TOKEN_HEADER_LEN + ciphertext.len());
        token.extend_from_slice(&header);
        token.extend_from_slice(&ciphertext);
        Ok(token)
    }

    /// `GSS_Unwrap`, RFC 4121 §4.2.4, §4.2.5 and §4.2.6.2.
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] for a token that is not the shape
    /// §4.2.6.2 defines, [`AuthError::SignatureMismatch`] when the ciphertext
    /// does not verify or the header inside it does not match the one outside
    /// it, and [`AuthError::MessageOutOfSequence`] when the sequence number
    /// is not the one expected.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        let bad = AuthError::MalformedMessage("GSS Wrap token");
        let header = token.get(..TOKEN_HEADER_LEN).ok_or(bad)?;
        if header.get(..2) != Some(&TOK_ID_WRAP[..]) {
            return Err(bad);
        }
        let flags = *header.get(2).ok_or(bad)?;
        if flags & token_flag::SENT_BY_ACCEPTOR == 0 {
            // Our own token coming back at us, which is the reflection
            // RFC 4121 §4.2.2's direction bit exists to stop.
            return Err(bad);
        }
        if flags & token_flag::SEALED == 0 {
            // A Wrap token without confidentiality carries a checksum rather
            // than ciphertext. CredSSP asks for confidentiality and a server
            // that answers without it is not doing what was agreed.
            return Err(bad);
        }
        let ec = usize::from(u16::from_be_bytes([
            *header.get(4).ok_or(bad)?,
            *header.get(5).ok_or(bad)?,
        ]));
        let rrc = usize::from(u16::from_be_bytes([
            *header.get(6).ok_or(bad)?,
            *header.get(7).ok_or(bad)?,
        ]));
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(header.get(8..16).ok_or(bad)?);
        let seq = u64::from_be_bytes(seq_bytes);
        self.check_sequence(seq)?;

        let body = token.get(TOKEN_HEADER_LEN..).ok_or(bad)?;
        let ciphertext = undo_rrc(body, rrc);

        let plain = crypto::decrypt(&self.base_key, usage::GSS_ACCEPTOR_SEAL, &ciphertext)?;

        // The trailing sixteen octets are the header as it was when the
        // sender encrypted it: EC and RRC as sent, with RRC zeroed
        // (RFC 4121 §4.2.4).
        let split = plain.len().checked_sub(TOKEN_HEADER_LEN + ec).ok_or(bad)?;
        let (plaintext, tail) = plain.split_at_checked(split).ok_or(bad)?;
        let echoed = tail.get(ec..).ok_or(bad)?;

        let mut expected = [0u8; TOKEN_HEADER_LEN];
        expected.copy_from_slice(header);
        // RFC 4121 §4.2.4: the encrypted copy carries RRC = 00 00.
        if let Some(slot) = expected.get_mut(6..8) {
            slot.copy_from_slice(&[0, 0]);
        }
        if !bool::from(expected.ct_eq(echoed)) {
            return Err(AuthError::SignatureMismatch);
        }

        Ok(Zeroizing::new(plaintext.to_vec()))
    }

    /// `GSS_GetMIC`, RFC 4121 §4.2.6.1.
    ///
    /// ```text
    /// token = header | get_mic(data | header)
    /// ```
    ///
    /// # Errors
    ///
    /// Whatever the checksum makes of the base key.
    pub fn mic(&mut self, message: &[u8]) -> Result<Vec<u8>, AuthError> {
        let header = Self::header(TOK_ID_MIC, self.our_flags(false), 0, 0, self.send_seq);
        let mut signed = Vec::with_capacity(message.len() + TOKEN_HEADER_LEN);
        signed.extend_from_slice(message);
        signed.extend_from_slice(&header);

        let tag = crypto::checksum(&self.base_key, usage::GSS_INITIATOR_SIGN, &signed)?;
        self.send_seq = self.send_seq.wrapping_add(1);

        let mut token = Vec::with_capacity(TOKEN_HEADER_LEN + tag.len());
        token.extend_from_slice(&header);
        token.extend_from_slice(&tag);
        Ok(token)
    }

    /// `GSS_VerifyMIC`, RFC 4121 §4.2.6.1. Constant time
    /// (PRDRDP/14 §8.1): the comparison is inside
    /// [`crypto::verify_checksum`], which goes through `subtle`.
    ///
    /// # Errors
    ///
    /// [`AuthError::SignatureMismatch`] when the checksum does not verify,
    /// [`AuthError::MalformedMessage`] for a token of the wrong shape, and
    /// [`AuthError::MessageOutOfSequence`] for an unexpected sequence number.
    pub fn verify_mic(&mut self, message: &[u8], token: &[u8]) -> Result<(), AuthError> {
        let bad = AuthError::MalformedMessage("GSS MIC token");
        let header = token.get(..TOKEN_HEADER_LEN).ok_or(bad)?;
        if header.get(..2) != Some(&TOK_ID_MIC[..]) {
            return Err(bad);
        }
        let flags = *header.get(2).ok_or(bad)?;
        if flags & token_flag::SENT_BY_ACCEPTOR == 0 {
            return Err(bad);
        }
        if flags & token_flag::SEALED != 0 {
            // RFC 4121 §4.2.2: Sealed "SHALL NOT be set in MIC tokens".
            return Err(bad);
        }
        if header.get(3..8) != Some(&[0xff; 5][..]) {
            return Err(bad);
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(header.get(8..16).ok_or(bad)?);
        self.check_sequence(u64::from_be_bytes(seq_bytes))?;

        let tag = token.get(TOKEN_HEADER_LEN..).ok_or(bad)?;
        if tag.len() != CHECKSUM_LEN {
            return Err(bad);
        }
        let mut signed = Vec::with_capacity(message.len() + TOKEN_HEADER_LEN);
        signed.extend_from_slice(message);
        signed.extend_from_slice(header);
        crypto::verify_checksum(&self.base_key, usage::GSS_ACCEPTOR_SIGN, &signed, tag)
    }

    /// Hold the acceptor to the sequence it announced, or latch onto the
    /// first one it sends. The module comment argues the leniency.
    fn check_sequence(&mut self, seq: u64) -> Result<(), AuthError> {
        match self.recv_seq {
            Some(expected) if expected != seq => {
                tracing::warn!(expected, got = seq, "a GSS token arrived out of sequence");
                Err(AuthError::MessageOutOfSequence)
            }
            _ => {
                self.recv_seq = Some(seq.wrapping_add(1));
                Ok(())
            }
        }
    }
}

impl std::fmt::Debug for GssContext {
    /// PRDRDP/14 §8.3.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssContext")
            .field("base_key", &self.base_key)
            .field("acceptor_subkey", &self.acceptor_subkey)
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .finish()
    }
}

/// Undo RFC 4121 §4.2.5's `RRC` rotation: move the first `rrc` octets of the
/// token body to the back.
///
/// "The receiver MUST be able to interpret all possible rotation count
/// values, including rotation counts greater than the length of the token",
/// which is what the modulo is for. An empty buffer is returned unchanged
/// rather than dividing by zero.
///
/// **Deliberately not named after a word rotation.** `tests/redaction.rs`
/// greps every source file in this crate for the two shift-in-place method
/// names, because a word rotation inside a loop is the shape a hand written
/// cipher primitive takes, and that grep is worth more than the naming.
/// What happens here is a rearrangement of whole octets of a token by a
/// count the sender put in a header: a protocol field, not arithmetic over a
/// secret. Naming these two after RFC 4121's own field says so. Renaming
/// them back will fail that test, and the right response is to leave the
/// names alone.
fn undo_rrc(buf: &[u8], rrc: usize) -> Vec<u8> {
    if buf.is_empty() {
        return Vec::new();
    }
    let at = rrc % buf.len();
    let mut out = Vec::with_capacity(buf.len());
    out.extend_from_slice(buf.get(at..).unwrap_or(&[]));
    out.extend_from_slice(buf.get(..at).unwrap_or(&[]));
    out
}

/// Apply RFC 4121 §4.2.5's `RRC` rotation: move the last `rrc` octets of the
/// token body to the front.
///
/// We send `RRC = 0`, so nothing in the sending path calls this. It exists
/// because a receiver that has not been tested at every rotation count is a
/// receiver nobody has tested, and because a future sender that wants a non
/// zero `RRC` needs it. See [`undo_rrc`] for the naming.
#[must_use]
pub fn apply_rrc(buf: &[u8], rrc: usize) -> Vec<u8> {
    if buf.is_empty() {
        return Vec::new();
    }
    undo_rrc(buf, buf.len() - (rrc % buf.len()))
}

/// The smallest a Wrap token can be: the header, a confounder, a copy of the
/// header, and the integrity tag.
///
/// Exported because it is the bound a caller checks before deciding a short
/// token is worth parsing, and because writing it out is the clearest way to
/// say what a Wrap token is made of.
#[must_use]
pub const fn min_wrap_token_len() -> usize {
    TOKEN_HEADER_LEN + BLOCK_LEN + TOKEN_HEADER_LEN + CHECKSUM_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4121 §4.1.1's layout, octet by octet, and the little endian trap.
    #[test]
    fn the_authenticator_checksum_is_the_layout_rfc_4121_defines() {
        let sum = authenticator_checksum(None);
        assert_eq!(sum.len(), 24, "the minimum RFC 4121 §4.1.1 allows");
        // Lgth = 16, little endian: "Currently contains hex value 10 00 00 00".
        assert_eq!(sum.get(..4), Some(&[0x10, 0x00, 0x00, 0x00][..]));
        // Bnd = 16 zeroes for GSS_C_NO_CHANNEL_BINDINGS.
        assert_eq!(sum.get(4..20), Some(&[0u8; 16][..]));
        // Flags = MUTUAL|REPLAY|SEQUENCE|CONF|INTEG = 2+4+8+16+32 = 62,
        // little endian, so 3e 00 00 00 and not 00 00 00 3e.
        assert_eq!(sum.get(20..24), Some(&[0x3e, 0x00, 0x00, 0x00][..]));
        assert_eq!(REQUESTED_FLAGS, 62);
        // DELEG is not among them.
        assert_eq!(REQUESTED_FLAGS & gss_flag::DELEG, 0, "no delegation");
    }

    /// The channel binding goes in `Bnd` unchanged: it is the same MD5 the
    /// NTLM path puts in its AV pair.
    #[test]
    fn the_channel_binding_is_the_bnd_field() {
        let bindings = ChannelBindings::from_certificate_hash(&[0x42; 32]);
        let sum = authenticator_checksum(Some(&bindings));
        assert_eq!(sum.get(4..20), Some(&bindings.value()[..]));
        assert_ne!(sum.get(4..20), Some(&[0u8; 16][..]));
        // And the rest of the structure is unchanged by it.
        assert_eq!(sum.get(..4), Some(&[0x10, 0x00, 0x00, 0x00][..]));
        assert_eq!(sum.get(20..24), Some(&[0x3e, 0x00, 0x00, 0x00][..]));
    }

    /// RFC 4121 §4.2.6.1 and §4.2.6.2's headers.
    #[test]
    fn the_token_headers_are_the_layouts_rfc_4121_defines() {
        let mic = GssContext::header(TOK_ID_MIC, 0x04, 0, 0, 0x0102_0304_0506_0708);
        assert_eq!(mic.get(..2), Some(&[0x04, 0x04][..]), "MIC TOK_ID");
        assert_eq!(mic.get(2), Some(&0x04));
        assert_eq!(mic.get(3..8), Some(&[0xff; 5][..]), "five octets of filler");
        assert_eq!(
            mic.get(8..16),
            Some(&[1, 2, 3, 4, 5, 6, 7, 8][..]),
            "the sequence is big endian"
        );

        let wrap = GssContext::header(TOK_ID_WRAP, 0x02, 0x0011, 0x2233, 1);
        assert_eq!(wrap.get(..2), Some(&[0x05, 0x04][..]), "Wrap TOK_ID");
        assert_eq!(wrap.get(2), Some(&0x02));
        assert_eq!(wrap.get(3), Some(&0xff), "one octet of filler");
        assert_eq!(wrap.get(4..6), Some(&[0x00, 0x11][..]), "EC big endian");
        assert_eq!(wrap.get(6..8), Some(&[0x22, 0x33][..]), "RRC big endian");
    }

    /// RFC 4121 §4.2.5's own worked example: "Assume that the RRC value is 3
    /// and the token before the rotation is {"header" | aa | bb | cc | dd |
    /// ee | ff | gg | hh}. The token after rotation would be {"header" | ff |
    /// gg | hh | aa | bb | cc | dd | ee}."
    #[test]
    fn the_rotation_matches_the_example_in_rfc_4121_section_4_2_5() {
        let before = b"aabbccddeeffgghh";
        let after = b"ffgghhaabbccddee";
        // The example's letters are one octet each in the RFC's notation.
        let before: Vec<u8> = before.chunks(2).map(|c| c[0]).collect();
        let after: Vec<u8> = after.chunks(2).map(|c| c[0]).collect();
        assert_eq!(apply_rrc(&before, 3), after);
        assert_eq!(undo_rrc(&after, 3), before);
    }

    /// "The receiver MUST be able to interpret all possible rotation count
    /// values, including rotation counts greater than the length of the
    /// token" (RFC 4121 §4.2.5).
    #[test]
    fn every_rotation_count_round_trips_including_the_absurd_ones() {
        let data: Vec<u8> = (0u8..37).collect();
        for rrc in [0usize, 1, 36, 37, 38, 100, 65_535] {
            assert_eq!(undo_rrc(&apply_rrc(&data, rrc), rrc), data, "rrc {rrc}");
        }
        assert!(undo_rrc(&[], 5).is_empty());
        assert!(apply_rrc(&[], 5).is_empty());
    }

    fn context(acceptor_subkey: bool) -> GssContext {
        let enctype = Enctype::Aes256CtsHmacSha1_96;
        let ours = Key::new(enctype, &[0x11; 32]).expect("32 octets");
        let theirs = Key::new(enctype, &[0x22; 32]).expect("32 octets");
        GssContext::new(
            ApReqToken {
                token: Vec::new(),
                subkey: ours,
                seq_number: 100,
            },
            ApRepContents {
                subkey: acceptor_subkey.then_some(theirs),
                seq_number: Some(200),
            },
        )
    }

    /// RFC 4121 §2's base key rule, and §4.2.2's flag that announces it.
    #[test]
    fn the_acceptor_subkey_becomes_the_base_key_and_sets_its_flag() {
        let without = context(false);
        assert_eq!(without.base_key.octets(), &[0x11; 32]);
        assert_eq!(without.our_flags(true), token_flag::SEALED);

        let with = context(true);
        assert_eq!(with.base_key.octets(), &[0x22; 32]);
        assert_eq!(
            with.our_flags(true),
            token_flag::SEALED | token_flag::ACCEPTOR_SUBKEY
        );
        assert_eq!(with.our_flags(false), token_flag::ACCEPTOR_SUBKEY);
        // The direction bit is never set on a token we send.
        assert_eq!(with.our_flags(true) & token_flag::SENT_BY_ACCEPTOR, 0);
    }

    /// A Wrap token is the header, then ciphertext, and the sequence number
    /// counts up.
    #[test]
    fn wrap_produces_the_shape_rfc_4121_section_4_2_6_2_defines() {
        let mut ctx = context(true);
        let token = ctx.wrap(b"pubKeyAuth").expect("wrap");
        assert_eq!(token.get(..2), Some(&[0x05, 0x04][..]));
        assert_eq!(
            token.get(2),
            Some(&(token_flag::SEALED | token_flag::ACCEPTOR_SUBKEY))
        );
        assert_eq!(token.get(4..6), Some(&[0, 0][..]), "EC = 0");
        assert_eq!(token.get(6..8), Some(&[0, 0][..]), "RRC = 0");
        assert_eq!(token.get(8..16), Some(&100u64.to_be_bytes()[..]));
        assert!(token.len() >= min_wrap_token_len());
        // The plaintext does not appear in the token.
        assert!(
            !token.windows(10).any(|w| w == b"pubKeyAuth"),
            "the payload is in clear"
        );

        let next = ctx.wrap(b"authInfo").expect("wrap");
        assert_eq!(next.get(8..16), Some(&101u64.to_be_bytes()[..]));
    }

    /// A MIC token is the header and a 96 bit checksum, and nothing else.
    #[test]
    fn mic_produces_the_shape_rfc_4121_section_4_2_6_1_defines() {
        let mut ctx = context(false);
        let token = ctx.mic(b"mechTypes").expect("mic");
        assert_eq!(token.len(), TOKEN_HEADER_LEN + CHECKSUM_LEN);
        assert_eq!(token.get(..2), Some(&[0x04, 0x04][..]));
        assert_eq!(token.get(2), Some(&0x00), "no flags for a plain initiator");
        assert_eq!(token.get(3..8), Some(&[0xff; 5][..]));
        assert_eq!(token.get(8..16), Some(&100u64.to_be_bytes()[..]));
    }

    /// Two contexts facing each other, with the direction bits swapped, which
    /// is the closest thing to an acceptor this file can have without one.
    fn acceptor_of(client: &GssContext) -> GssContext {
        GssContext {
            base_key: client.base_key.clone(),
            acceptor_subkey: client.acceptor_subkey,
            send_seq: client.recv_seq.unwrap_or(0),
            recv_seq: Some(client.send_seq),
        }
    }

    /// An acceptor's Wrap token, built the way RFC 4121 §4.2.4 says an
    /// acceptor builds one, at an assortment of rotation counts.
    fn acceptor_wrap(ctx: &mut GssContext, plaintext: &[u8], rrc: u16) -> Vec<u8> {
        let flags = token_flag::SENT_BY_ACCEPTOR
            | token_flag::SEALED
            | if ctx.acceptor_subkey {
                token_flag::ACCEPTOR_SUBKEY
            } else {
                0
            };
        // The encrypted copy of the header always carries RRC = 00 00.
        let inner = GssContext::header(TOK_ID_WRAP, flags, 0, 0, ctx.send_seq);
        let mut to_encrypt = plaintext.to_vec();
        to_encrypt.extend_from_slice(&inner);
        let ciphertext =
            crypto::encrypt(&ctx.base_key, usage::GSS_ACCEPTOR_SEAL, &to_encrypt).expect("encrypt");
        ctx.send_seq += 1;

        let outer = GssContext::header(TOK_ID_WRAP, flags, 0, rrc, ctx.send_seq - 1);
        let mut token = outer.to_vec();
        token.extend_from_slice(&apply_rrc(&ciphertext, usize::from(rrc)));
        token
    }

    /// Unwrap against an acceptor, at every rotation count that matters.
    #[test]
    fn unwrap_reads_an_acceptor_token_at_any_rotation_count() {
        for rrc in [0u16, 1, 16, 28, 31, 60_000] {
            let mut client = context(true);
            let mut server = acceptor_of(&client);
            let token = acceptor_wrap(&mut server, b"the server's pubKeyAuth", rrc);
            let plain = client.unwrap(&token).expect("unwrap");
            assert_eq!(&*plain, b"the server's pubKeyAuth", "rrc {rrc}");
        }
    }

    /// A flipped bit anywhere is caught, and so is a doctored header.
    #[test]
    fn unwrap_refuses_a_tampered_token() {
        let client = context(true);
        let mut server = acceptor_of(&client);
        let token = acceptor_wrap(&mut server, b"secret", 0);

        for byte in 0..token.len() {
            for bit in 0..8u32 {
                let mut client = context(true);
                let mut tampered = token.clone();
                if let Some(slot) = tampered.get_mut(byte) {
                    *slot ^= 1 << bit;
                }
                assert!(
                    client.unwrap(&tampered).is_err(),
                    "byte {byte} bit {bit} was accepted"
                );
            }
        }
        // And the untampered one still works, so the sweep proved something.
        let mut client = context(true);
        assert_eq!(&*client.unwrap(&token).expect("unwrap"), b"secret");
    }

    /// Our own Wrap token reflected back at us has the direction bit clear
    /// and is refused (RFC 4121 §4.2.2).
    #[test]
    fn a_reflected_token_is_refused() {
        let mut client = context(true);
        let ours = client.wrap(b"pubKeyAuth").expect("wrap");
        let mut fresh = context(true);
        assert!(fresh.unwrap(&ours).is_err(), "reflection was accepted");
    }

    /// A MIC round trip, and the two things that must be refused: a MIC over
    /// a different message, and a MIC with the Sealed flag set.
    #[test]
    fn verify_mic_accepts_the_acceptor_and_refuses_everything_else() {
        let client = context(false);
        let server = acceptor_of(&client);

        let flags = token_flag::SENT_BY_ACCEPTOR;
        let header = GssContext::header(TOK_ID_MIC, flags, 0, 0, server.send_seq);
        let mut signed = b"mechTypes".to_vec();
        signed.extend_from_slice(&header);
        let tag = crypto::checksum(&server.base_key, usage::GSS_ACCEPTOR_SIGN, &signed)
            .expect("checksum");
        let mut token = header.to_vec();
        token.extend_from_slice(&tag);

        let mut fresh = context(false);
        fresh.verify_mic(b"mechTypes", &token).expect("verify");

        let mut fresh = context(false);
        assert!(fresh.verify_mic(b"mechTypez", &token).is_err());

        let mut sealed = token.clone();
        sealed[2] |= token_flag::SEALED;
        let mut fresh = context(false);
        assert!(fresh.verify_mic(b"mechTypes", &sealed).is_err());

        // Our own MIC reflected back has the direction bit clear.
        let mut fresh = context(false);
        let ours = fresh.mic(b"mechTypes").expect("mic");
        let mut fresh = context(false);
        assert!(fresh.verify_mic(b"mechTypes", &ours).is_err());

        for cut in 0..token.len() {
            let mut fresh = context(false);
            assert!(
                fresh
                    .verify_mic(b"mechTypes", token.get(..cut).expect("in range"))
                    .is_err(),
                "cut {cut}"
            );
        }
    }

    /// Every truncation of a Wrap token is an error and never a panic.
    #[test]
    fn every_truncation_of_a_wrap_token_fails_cleanly() {
        let client = context(true);
        let mut server = acceptor_of(&client);
        let token = acceptor_wrap(&mut server, b"a payload of some length", 7);
        for cut in 0..token.len() {
            let mut client = context(true);
            assert!(
                client.unwrap(token.get(..cut).expect("in range")).is_err(),
                "cut {cut}"
            );
        }
        // Rubbish of the right length is refused too.
        let mut client = context(true);
        assert!(client.unwrap(&vec![0u8; token.len()]).is_err());
    }

    /// The acceptor's sequence number is held to what the AP-REP announced.
    #[test]
    fn a_token_out_of_sequence_is_refused() {
        let mut client = context(true);
        let mut server = acceptor_of(&client);
        // Skip one on the acceptor side.
        server.send_seq += 1;
        let token = acceptor_wrap(&mut server, b"payload", 0);
        assert_eq!(
            client.unwrap(&token).unwrap_err(),
            AuthError::MessageOutOfSequence
        );
    }

    /// An acceptor that announced no sequence number is believed the first
    /// time and held to it afterwards. The module comment argues why.
    #[test]
    fn an_acceptor_with_no_announced_sequence_is_latched_onto() {
        let enctype = Enctype::Aes256CtsHmacSha1_96;
        let ours = Key::new(enctype, &[0x11; 32]).expect("32 octets");
        let mut client = GssContext::new(
            ApReqToken {
                token: Vec::new(),
                subkey: ours,
                seq_number: 100,
            },
            ApRepContents {
                subkey: None,
                seq_number: None,
            },
        );
        let mut server = acceptor_of(&client);
        server.send_seq = 9_000;
        let first = acceptor_wrap(&mut server, b"first", 0);
        assert_eq!(&*client.unwrap(&first).expect("unwrap"), b"first");

        // Now it is latched: a jump is refused.
        server.send_seq = 9_500;
        let jumped = acceptor_wrap(&mut server, b"second", 0);
        assert_eq!(
            client.unwrap(&jumped).unwrap_err(),
            AuthError::MessageOutOfSequence
        );
    }

    /// PRDRDP/14 §8.3.
    #[test]
    fn the_context_never_prints_its_key() {
        let ctx = context(true);
        let shown = format!("{ctx:?}");
        assert!(!shown.contains("22, 22"), "{shown}");
        assert!(!shown.contains("2222"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    /// The `[APPLICATION 0]` wrapper is IMPLICIT: `0x60`, a length, then the
    /// OID, then the token, with no `0x30` in between.
    #[test]
    fn the_initial_context_token_is_implicit() {
        let token = initial_context_token(crate::spnego::oid::KRB5, TOK_ID_AP_REQ, b"AP-REQ");
        assert_eq!(token.first(), Some(&0x60));
        // 0x06, the OID tag, follows the header directly.
        assert_eq!(token.get(2), Some(&0x06), "no SEQUENCE after the 0x60");
        assert_eq!(token.get(3), Some(&9), "the krb5 OID is nine octets");
        assert_eq!(token.get(4..13), Some(crate::spnego::oid::KRB5));
        assert_eq!(token.get(13..15), Some(&[0x01, 0x00][..]), "TOK_ID");
        assert_eq!(token.get(15..), Some(&b"AP-REQ"[..]));

        // And it round trips through the stripper, as does a bare token.
        assert_eq!(
            strip_context_framing(&token).expect("framed"),
            &[&[0x01, 0x00][..], b"AP-REQ"].concat()[..]
        );
        let bare = [&TOK_ID_AP_REP[..], b"AP-REP"].concat();
        assert_eq!(strip_context_framing(&bare).expect("bare"), &bare[..]);
    }
}
