//! The three NTLM messages, MS-NLMP 2.2.1.1, 2.2.1.2 and 2.2.1.3.
//!
//! All little endian, all with an 8 byte signature `"NTLMSSP\0"` and a 4 byte
//! message type. Payload fields are described by a triple
//! `{ Len u16, MaxLen u16, BufferOffset u32 }`; `Len` is authoritative and
//! `MaxLen` may differ.
//!
//! Every read out of a peer's buffer goes through [`slice_at`], which returns
//! `Result` and never indexes (D11). A hostile server will exercise every one
//! of those bounds checks, and `tests/nlmp_vectors.rs` truncates a valid
//! CHALLENGE at every length to prove none of them panics.

use crate::error::AuthError;

use super::flags;
use super::version::Version;

/// `"NTLMSSP\0"`, MS-NLMP 2.2.1.
pub const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// `NtLmNegotiate`, MS-NLMP 2.2.1.1.
pub const MESSAGE_TYPE_NEGOTIATE: u32 = 0x0000_0001;
/// `NtLmChallenge`, MS-NLMP 2.2.1.2.
pub const MESSAGE_TYPE_CHALLENGE: u32 = 0x0000_0002;
/// `NtLmAuthenticate`, MS-NLMP 2.2.1.3.
pub const MESSAGE_TYPE_AUTHENTICATE: u32 = 0x0000_0003;

/// The fixed size of a NEGOTIATE_MESSAGE with a `Version` and no payload.
pub const NEGOTIATE_LEN: usize = 40;
/// Where the MIC field starts in an AUTHENTICATE_MESSAGE that carries one.
pub const AUTHENTICATE_MIC_OFFSET: usize = 72;
/// The MIC is sixteen bytes.
pub const MIC_LEN: usize = 16;

/// A `Len`/`MaxLen`/`BufferOffset` triple.
fn put_field(out: &mut Vec<u8>, len: usize, offset: usize) {
    let len = u16::try_from(len).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&u32::try_from(offset).unwrap_or(u32::MAX).to_le_bytes());
}

/// A bounds checked slice out of a peer's message.
fn slice_at(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], AuthError> {
    offset
        .checked_add(len)
        .and_then(|end| bytes.get(offset..end))
        .ok_or(AuthError::MalformedMessage("payload runs past the message"))
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, AuthError> {
    let b = slice_at(bytes, at, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, AuthError> {
    let b = slice_at(bytes, at, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a `{ Len, MaxLen, BufferOffset }` triple and return the bytes it
/// describes. `Len` wins over `MaxLen`.
fn read_field(bytes: &[u8], field_at: usize) -> Result<&[u8], AuthError> {
    let len = usize::from(u16_at(bytes, field_at)?);
    let offset = u32_at(bytes, field_at + 4)? as usize;
    slice_at(bytes, offset, len)
}

/// Check the signature and message type that open every NTLM message.
fn check_header(bytes: &[u8], expected_type: u32) -> Result<(), AuthError> {
    let sig = slice_at(bytes, 0, 8)?;
    if sig != SIGNATURE {
        return Err(AuthError::MalformedMessage("NTLM signature"));
    }
    if u32_at(bytes, 8)? != expected_type {
        return Err(AuthError::MalformedMessage("NTLM message type"));
    }
    Ok(())
}

/// NEGOTIATE_MESSAGE, MS-NLMP 2.2.1.1.
///
/// ```text
/// offset size field
///   0     8    Signature = "NTLMSSP\0"
///   8     4    MessageType = 0x00000001
///  12     4    NegotiateFlags
///  16     8    DomainNameFields      { Len u16, MaxLen u16, BufferOffset u32 }
///  24     8    WorkstationFields     { Len u16, MaxLen u16, BufferOffset u32 }
///  32     8    Version               (present because we set NEGOTIATE_VERSION)
///  40    ..    Payload
/// ```
///
/// `DomainNameFields` and `WorkstationFields` go out as zero lengths with
/// `BufferOffset = 40` and no payload. MS-NLMP 3.1.5.1.1 makes both meaningful
/// only when `NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED` or
/// `NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED` is set, and those flags force
/// the OEM codepage encoding we do not want. The workstation name we do send
/// goes in the AUTHENTICATE message in Unicode.
///
/// So the message is forty bytes, fixed, every time. That constancy matters
/// more than it looks: this message is one of the three inputs to the MIC, so
/// it has to be kept byte for byte, and a forty byte constant plus a flags
/// word is easy to keep.
#[must_use]
pub fn encode_negotiate(negotiate_flags: u32, version: Version) -> Vec<u8> {
    let mut out = Vec::with_capacity(NEGOTIATE_LEN);
    out.extend_from_slice(SIGNATURE);
    out.extend_from_slice(&MESSAGE_TYPE_NEGOTIATE.to_le_bytes());
    out.extend_from_slice(&negotiate_flags.to_le_bytes());
    put_field(&mut out, 0, NEGOTIATE_LEN);
    put_field(&mut out, 0, NEGOTIATE_LEN);
    out.extend_from_slice(&version.encode());
    debug_assert_eq!(out.len(), NEGOTIATE_LEN);
    out
}

/// A parsed NEGOTIATE_MESSAGE. Only the mock server side needs this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateMessage {
    /// `NegotiateFlags`.
    pub flags: u32,
    /// `Version`, present when `NTLMSSP_NEGOTIATE_VERSION` is set.
    pub version: Option<Version>,
}

/// Parse a NEGOTIATE_MESSAGE, MS-NLMP 2.2.1.1.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] on a bad signature, a wrong message type,
/// or a message too short for the fields it claims.
pub fn decode_negotiate(bytes: &[u8]) -> Result<NegotiateMessage, AuthError> {
    check_header(bytes, MESSAGE_TYPE_NEGOTIATE)?;
    let flags = u32_at(bytes, 12)?;
    let version = if flags & flags::NEGOTIATE_VERSION != 0 {
        let v = slice_at(bytes, 32, 8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(v);
        Some(Version::decode(buf))
    } else {
        None
    };
    Ok(NegotiateMessage { flags, version })
}

/// A parsed CHALLENGE_MESSAGE, MS-NLMP 2.2.1.2.
///
/// ```text
/// offset size field
///   0     8    Signature
///   8     4    MessageType = 0x00000002
///  12     8    TargetNameFields { Len u16, MaxLen u16, BufferOffset u32 }
///  20     4    NegotiateFlags
///  24     8    ServerChallenge
///  32     8    Reserved (must be ignored)
///  40     8    TargetInfoFields { Len u16, MaxLen u16, BufferOffset u32 }
///  48     8    Version    (present iff NTLMSSP_NEGOTIATE_VERSION is set)
///  56    ..    Payload
/// ```
///
/// The flags here are the server's, not ours. `NTLMSSP_NEGOTIATE_KEY_EXCH`,
/// `_128`, `_56` and `_SEAL` are read back from this message and drive the key
/// derivations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeMessage {
    /// `TargetName`, raw UTF-16LE bytes, copied through unchanged.
    pub target_name: Vec<u8>,
    /// `NegotiateFlags` as the server set them.
    pub flags: u32,
    /// `ServerChallenge`.
    pub server_challenge: [u8; 8],
    /// `TargetInfo`, raw AV pair bytes including the terminator.
    pub target_info: Vec<u8>,
    /// `Version`, present when the flag is set.
    pub version: Option<Version>,
    /// The message exactly as it arrived. Retained because it is one of the
    /// three inputs to the MIC (MS-NLMP 3.1.5.1.2) and a re-encoding is not
    /// guaranteed to be the same bytes.
    pub raw: Vec<u8>,
}

/// Parse a CHALLENGE_MESSAGE, MS-NLMP 2.2.1.2.
///
/// The parsing rules are all bounds checks a hostile server will exercise:
///
/// * At least 48 bytes, and at least 56 when the version flag is set. Reading
///   the `Version` field with the flag clear reads into the payload.
/// * Every `BufferOffset` plus `Len` must be inside the message.
/// * `Len` and `MaxLen` may differ; `Len` wins.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] for any of the above.
pub fn decode_challenge(bytes: &[u8]) -> Result<ChallengeMessage, AuthError> {
    check_header(bytes, MESSAGE_TYPE_CHALLENGE)?;
    if bytes.len() < 48 {
        return Err(AuthError::MalformedMessage(
            "CHALLENGE is shorter than 48 bytes",
        ));
    }
    let target_name = read_field(bytes, 12)?.to_vec();
    let flags = u32_at(bytes, 20)?;
    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(slice_at(bytes, 24, 8)?);
    // Bytes 32 to 39 are Reserved and MS-NLMP 2.2.1.2 says to ignore them.
    let target_info = read_field(bytes, 40)?.to_vec();
    let version = if flags & flags::NEGOTIATE_VERSION != 0 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(slice_at(bytes, 48, 8)?);
        Some(Version::decode(buf))
    } else {
        None
    };
    Ok(ChallengeMessage {
        target_name,
        flags,
        server_challenge,
        target_info,
        version,
        raw: bytes.to_vec(),
    })
}

/// Encode a CHALLENGE_MESSAGE.
///
/// The client never sends one. This exists so the round trip of MS-NLMP
/// 4.2.4.3's CHALLENGE can be asserted byte for byte, and so the mock server
/// side of PRDRDP/14 §9.3 has an encoder that is the same code the client
/// parses.
///
/// The payload order is `TargetName` then `TargetInfo`, which is what the
/// 4.2.4.3 example uses.
#[must_use]
pub fn encode_challenge(msg: &ChallengeMessage) -> Vec<u8> {
    let header_len = if msg.version.is_some() { 56 } else { 48 };
    let target_name_at = header_len;
    let target_info_at = target_name_at + msg.target_name.len();

    let mut out = Vec::with_capacity(target_info_at + msg.target_info.len());
    out.extend_from_slice(SIGNATURE);
    out.extend_from_slice(&MESSAGE_TYPE_CHALLENGE.to_le_bytes());
    put_field(&mut out, msg.target_name.len(), target_name_at);
    out.extend_from_slice(&msg.flags.to_le_bytes());
    out.extend_from_slice(&msg.server_challenge);
    out.extend_from_slice(&[0u8; 8]); // Reserved
    put_field(&mut out, msg.target_info.len(), target_info_at);
    if let Some(v) = msg.version {
        out.extend_from_slice(&v.encode());
    }
    debug_assert_eq!(out.len(), header_len);
    out.extend_from_slice(&msg.target_name);
    out.extend_from_slice(&msg.target_info);
    out
}

/// Everything that goes into an AUTHENTICATE_MESSAGE, MS-NLMP 2.2.1.3.
///
/// Every field is bytes rather than a `str`, because the encoding decision
/// (UTF-16LE, no BOM) belongs to the caller that also fed those strings to
/// `NTOWFv2`. Encoding them twice, in two places, is how they end up different.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticateFields<'a> {
    /// `LmChallengeResponse`. Twenty four zero bytes for us.
    pub lm_challenge_response: &'a [u8],
    /// `NtChallengeResponse`, that is `NTProofStr || temp`.
    pub nt_challenge_response: &'a [u8],
    /// `DomainName`, UTF-16LE.
    pub domain_name: &'a [u8],
    /// `UserName`, UTF-16LE.
    pub user_name: &'a [u8],
    /// `Workstation`, UTF-16LE.
    pub workstation: &'a [u8],
    /// `EncryptedRandomSessionKey`. Empty when `NTLMSSP_NEGOTIATE_KEY_EXCH`
    /// was not negotiated.
    pub encrypted_random_session_key: &'a [u8],
    /// The negotiated flags, which decide how the server derives its keys.
    pub negotiate_flags: u32,
    /// The `Version` we report.
    pub version: Version,
    /// Whether to reserve the sixteen byte MIC field at offset 72.
    ///
    /// MS-NLMP 4.2.4.3's AUTHENTICATE_MESSAGE has a `Version` present and no
    /// MIC: its `DomainNameFields.BufferOffset` is 0x48, that is 72, so the
    /// payload begins where the MIC would be. Version presence therefore does
    /// not imply MIC presence, whatever a reading of 2.2.1.3 suggests, and the
    /// vector is the authority. The production path always sets this true; the
    /// vector test sets it false.
    pub with_mic: bool,
}

/// Encode an AUTHENTICATE_MESSAGE, MS-NLMP 2.2.1.3.
///
/// ```text
/// offset size field
///   0     8    Signature
///   8     4    MessageType = 0x00000003
///  12     8    LmChallengeResponseFields
///  20     8    NtChallengeResponseFields
///  28     8    DomainNameFields
///  36     8    UserNameFields
///  44     8    WorkstationFields
///  52     8    EncryptedRandomSessionKeyFields
///  60     4    NegotiateFlags
///  64     8    Version
///  72    16    MIC          (only when `with_mic`)
///  ..    ..    Payload
/// ```
///
/// The payload order emitted is `DomainName`, `UserName`, `Workstation`,
/// `LmChallengeResponse`, `NtChallengeResponse`, `EncryptedRandomSessionKey`.
/// The order is not specified and any order with correct offsets is legal.
/// This one is the order MS-NLMP 4.2.4.3's worked example uses, which is what
/// lets the encoder be asserted against the specification byte for byte.
/// PRDRDP/14 §5.5 proposes the other order (responses first); it is a free
/// choice and the vector settles it.
///
/// Returns the message and, when `with_mic`, the offset of the sixteen zero
/// bytes the MIC goes into. Encoding is a two pass job because of the MIC:
/// pass one writes the message with the MIC field zeroed, the MIC is computed
/// over that, pass two overwrites the field. [`patch_mic`] does pass two and
/// asserts the bytes it is about to overwrite are still zero, so a refactor
/// that reorders the passes fails loudly.
#[must_use]
pub fn encode_authenticate(f: &AuthenticateFields<'_>) -> (Vec<u8>, Option<usize>) {
    let header_len = if f.with_mic {
        AUTHENTICATE_MIC_OFFSET + MIC_LEN
    } else {
        AUTHENTICATE_MIC_OFFSET
    };

    let domain_at = header_len;
    let user_at = domain_at + f.domain_name.len();
    let workstation_at = user_at + f.user_name.len();
    let lm_at = workstation_at + f.workstation.len();
    let nt_at = lm_at + f.lm_challenge_response.len();
    let key_at = nt_at + f.nt_challenge_response.len();
    let total = key_at + f.encrypted_random_session_key.len();

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(SIGNATURE);
    out.extend_from_slice(&MESSAGE_TYPE_AUTHENTICATE.to_le_bytes());
    put_field(&mut out, f.lm_challenge_response.len(), lm_at);
    put_field(&mut out, f.nt_challenge_response.len(), nt_at);
    put_field(&mut out, f.domain_name.len(), domain_at);
    put_field(&mut out, f.user_name.len(), user_at);
    put_field(&mut out, f.workstation.len(), workstation_at);
    put_field(&mut out, f.encrypted_random_session_key.len(), key_at);
    out.extend_from_slice(&f.negotiate_flags.to_le_bytes());
    out.extend_from_slice(&f.version.encode());
    if f.with_mic {
        out.extend_from_slice(&[0u8; MIC_LEN]);
    }
    debug_assert_eq!(out.len(), header_len);
    out.extend_from_slice(f.domain_name);
    out.extend_from_slice(f.user_name);
    out.extend_from_slice(f.workstation);
    out.extend_from_slice(f.lm_challenge_response);
    out.extend_from_slice(f.nt_challenge_response);
    out.extend_from_slice(f.encrypted_random_session_key);
    debug_assert_eq!(out.len(), total);

    let mic_offset = f.with_mic.then_some(AUTHENTICATE_MIC_OFFSET);
    (out, mic_offset)
}

/// Pass two of the AUTHENTICATE encoding: write the MIC over the sixteen zero
/// bytes at `offset` (MS-NLMP 3.1.5.1.2).
///
/// # Panics
///
/// In a debug build, when the bytes being overwritten are not still zero. That
/// would mean the MIC was computed over a message that already had one, which
/// is a different value from the one the server computes.
pub fn patch_mic(message: &mut [u8], offset: usize, mic: &[u8; MIC_LEN]) {
    debug_assert!(
        message
            .get(offset..offset + MIC_LEN)
            .is_some_and(|f| f.iter().all(|b| *b == 0)),
        "the MIC field was not zero when the MIC was computed"
    );
    if let Some(field) = message.get_mut(offset..offset + MIC_LEN) {
        field.copy_from_slice(mic);
    }
}

/// A parsed AUTHENTICATE_MESSAGE. Only the mock server side needs this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateMessage {
    /// `LmChallengeResponse`.
    pub lm_challenge_response: Vec<u8>,
    /// `NtChallengeResponse`.
    pub nt_challenge_response: Vec<u8>,
    /// `DomainName`, UTF-16LE.
    pub domain_name: Vec<u8>,
    /// `UserName`, UTF-16LE.
    pub user_name: Vec<u8>,
    /// `Workstation`, UTF-16LE.
    pub workstation: Vec<u8>,
    /// `EncryptedRandomSessionKey`.
    pub encrypted_random_session_key: Vec<u8>,
    /// `NegotiateFlags`.
    pub negotiate_flags: u32,
    /// `Version`.
    pub version: Option<Version>,
    /// The MIC, when the message carries one.
    pub mic: Option<[u8; MIC_LEN]>,
}

/// Parse an AUTHENTICATE_MESSAGE, MS-NLMP 2.2.1.3.
///
/// MIC presence is inferred the only way it can be: if the earliest payload
/// offset leaves room for sixteen bytes after the `Version` field, those
/// sixteen bytes are the MIC.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] on a bad signature, a wrong message type,
/// or any field that runs past the end.
pub fn decode_authenticate(bytes: &[u8]) -> Result<AuthenticateMessage, AuthError> {
    check_header(bytes, MESSAGE_TYPE_AUTHENTICATE)?;
    if bytes.len() < 64 {
        return Err(AuthError::MalformedMessage(
            "AUTHENTICATE is shorter than 64 bytes",
        ));
    }
    let lm_challenge_response = read_field(bytes, 12)?.to_vec();
    let nt_challenge_response = read_field(bytes, 20)?.to_vec();
    let domain_name = read_field(bytes, 28)?.to_vec();
    let user_name = read_field(bytes, 36)?.to_vec();
    let workstation = read_field(bytes, 44)?.to_vec();
    let encrypted_random_session_key = read_field(bytes, 52)?.to_vec();
    let negotiate_flags = u32_at(bytes, 60)?;

    let version = if negotiate_flags & flags::NEGOTIATE_VERSION != 0 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(slice_at(bytes, 64, 8)?);
        Some(Version::decode(buf))
    } else {
        None
    };

    let first_payload = [12usize, 20, 28, 36, 44, 52]
        .into_iter()
        .filter_map(|at| {
            let len = usize::from(u16_at(bytes, at).ok()?);
            let off = u32_at(bytes, at + 4).ok()? as usize;
            (len > 0).then_some(off)
        })
        .min()
        .unwrap_or(AUTHENTICATE_MIC_OFFSET);
    let mic = if first_payload >= AUTHENTICATE_MIC_OFFSET + MIC_LEN {
        let mut buf = [0u8; MIC_LEN];
        buf.copy_from_slice(slice_at(bytes, AUTHENTICATE_MIC_OFFSET, MIC_LEN)?);
        Some(buf)
    } else {
        None
    };

    Ok(AuthenticateMessage {
        lm_challenge_response,
        nt_challenge_response,
        domain_name,
        user_name,
        workstation,
        encrypted_random_session_key,
        negotiate_flags,
        version,
        mic,
    })
}
