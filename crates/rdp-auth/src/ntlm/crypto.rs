//! Every NTLMv2 key derivation, as a pure function with a spec vector next to
//! it.
//!
//! MS-NLMP 3.3.2 for the one way functions and the response, 3.4.5.1 for
//! `KXKEY`, 3.4.5.2 for `SIGNKEY`, 3.4.5.3 for `SEALKEY`, 3.1.5.1.2 for the
//! exported session key and the MIC.
//!
//! ## Nothing here computes anything
//!
//! MD4 is `md4::Md4`, MD5 is `md5::Md5`, HMAC-MD5 is `hmac::Hmac<Md5>`, RC4 is
//! `rc4::Rc4`, and the random bytes are `rand::rng()`. What this file owns is
//! which buffers go in, in which order (AGENT_BRIEF V3-A, PRDRDP/14 §2.10).
//!
//! `crypto.rs` and `seal.rs` are deliberately split. Everything here is a pure
//! function; everything in `seal.rs` owns mutable RC4 state and a sequence
//! number. Mixing the two is how the RC4 handle ends up reset per message by
//! an innocent looking refactor.

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest, Md5};
use rand::Rng;
use rc4::{consts::U16, KeyInit, Rc4, StreamCipher};
use zeroize::Zeroizing;

use super::flags;

/// HMAC-MD5, `hmac` 0.12 over `md-5` 0.10 (PRDRDP/14 §2.10's register row).
type HmacMd5 = Hmac<Md5>;

/// Which direction a key is for. MS-NLMP 3.4.5.2 and 3.4.5.3 derive a
/// different key for each, and swapping them produces a client that signs with
/// the key the server verifies with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Keys the client uses to send.
    ClientToServer,
    /// Keys the client uses to receive.
    ServerToClient,
}

// The four magic strings of MS-NLMP 3.4.5.2 and 3.4.5.3, all NUL terminated,
// all of which have to be exact. They differ from each other by one word in
// the middle, and a transposition produces a failure that looks like a wrong
// password (PRDRDP/14 §9.2, the transcription rule).
const CLIENT_SIGN: &[u8] = b"session key to client-to-server signing key magic constant\0";
const SERVER_SIGN: &[u8] = b"session key to server-to-client signing key magic constant\0";
const CLIENT_SEAL: &[u8] = b"session key to client-to-server sealing key magic constant\0";
const SERVER_SEAL: &[u8] = b"session key to server-to-client sealing key magic constant\0";

/// The trailing `Z(4)` of `temp`, MS-NLMP 3.3.2.
///
/// The structure diagram in 2.2.2.7 does not show it and the concatenation in
/// 3.3.2 does: `temp` ends with four zero bytes after the `MsvAvEOL` pair, so
/// the last eight bytes of `temp` are all zero. Omitting them changes
/// `NTProofStr` and produces a wrong password error against a correct
/// password.
pub const NTLMV2_TEMP_TRAILER_LEN: usize = 4;

/// UTF-16LE with no byte order mark and no terminator, which is what MS-NLMP
/// means by `UNICODE()`.
#[must_use]
pub fn unicode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// `NTOWFv2(Passwd, User, UserDom)`, MS-NLMP 3.3.2.
///
/// ```text
/// NTOWFv2 = HMAC_MD5( MD4( UNICODE(Passwd) ),
///                     UNICODE( Uppercase(User) || UserDom ) )
/// ```
///
/// Four details, each of which has produced a shipped bug somewhere:
///
/// * `UNICODE` is UTF-16LE with no BOM and no terminator.
/// * `Uppercase` applies to the user name only. The domain is used exactly as
///   supplied. Uppercasing the domain works against most servers by luck,
///   because most domains are supplied uppercase already, and fails against
///   the ones that are not.
/// * The concatenation is of the encoded strings, so it is
///   `utf16le(upper(user)) || utf16le(domain)`. For ASCII that is the same as
///   encoding the concatenation; for non ASCII it is not, if the uppercase
///   mapping changes length. Encode, then concatenate.
/// * For a local account `UserDom` is the empty string, not the computer name.
///   Windows computes the same value for a local account with an empty domain.
///
/// Known limitation: `Uppercase` in the specification is the Windows locale
/// invariant uppercase. This uses Rust's `str::to_uppercase`, the Unicode full
/// uppercase mapping. For ASCII user names, which is every user name in
/// practice, the two agree. A Turkish dotless i in a user name would diverge.
/// Recorded rather than solved, because solving it means carrying a case
/// mapping table.
///
/// The MD4 of the password is the NT hash and it is password equivalent:
/// anything holding it can authenticate. It never leaves this function
/// unzeroized.
#[must_use]
pub fn ntowf_v2(password: &str, user: &str, domain: &str) -> Zeroizing<[u8; 16]> {
    let password_utf16 = Zeroizing::new(unicode(password));
    let nt_hash: Zeroizing<[u8; 16]> = Zeroizing::new(Md4::digest(&*password_utf16).into());

    let mut identity = unicode(&user.to_uppercase());
    identity.extend_from_slice(&unicode(domain));

    let mut mac = <HmacMd5 as Mac>::new_from_slice(&*nt_hash).expect("HMAC accepts any key length");
    mac.update(&identity);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// `LMOWFv2` is `NTOWFv2`, MS-NLMP 3.3.2.
///
/// Kept as its own name, with its own 4.2.4.1.1 vector, because the mock
/// server side computes it to check the alternative response, and because
/// deleting a function the specification defines makes the next reader wonder
/// whether it was forgotten.
#[must_use]
pub fn lmowf_v2(password: &str, user: &str, domain: &str) -> Zeroizing<[u8; 16]> {
    ntowf_v2(password, user, domain)
}

/// `temp`, MS-NLMP 3.3.2 and the `NTLMv2_CLIENT_CHALLENGE` of 2.2.2.7.
///
/// ```text
/// temp = RespType || HiRespType || Z(6) || Time || ClientChallenge || Z(4)
///        || ServerName || Z(4)
/// ```
///
/// `ServerName` is the AV pair list, terminator included. `Time` is the value
/// from the server's `MsvAvTimestamp`, not our own clock: MS-NLMP 3.1.5.1.2
/// uses the server timestamp when one is present, which removes clock skew
/// from the equation. Since we refuse a CHALLENGE without a timestamp
/// (PRDRDP/14 §8.5), the "our own clock" branch does not exist here and
/// neither does a FILETIME conversion.
#[must_use]
pub fn temp(time: &[u8; 8], client_challenge: &[u8; 8], av_pairs: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::with_capacity(28 + av_pairs.len() + NTLMV2_TEMP_TRAILER_LEN);
    out.push(0x01); // RespType
    out.push(0x01); // HiRespType
    out.extend_from_slice(&[0u8; 6]); // Reserved1, Reserved2
    out.extend_from_slice(time);
    out.extend_from_slice(client_challenge);
    out.extend_from_slice(&[0u8; 4]); // Reserved3
    out.extend_from_slice(av_pairs);
    out.extend_from_slice(&[0u8; NTLMV2_TEMP_TRAILER_LEN]);
    Zeroizing::new(out)
}

/// `NTProofStr = HMAC_MD5( ResponseKeyNT, ServerChallenge || temp )`,
/// MS-NLMP 3.3.2.
#[must_use]
pub fn nt_proof_str(
    response_key_nt: &[u8; 16],
    server_challenge: &[u8; 8],
    temp: &[u8],
) -> Zeroizing<[u8; 16]> {
    let mut mac =
        <HmacMd5 as Mac>::new_from_slice(response_key_nt).expect("HMAC accepts any key length");
    mac.update(server_challenge);
    mac.update(temp);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// `NtChallengeResponse = NTProofStr || temp`, MS-NLMP 3.3.2.
#[must_use]
pub fn nt_challenge_response(nt_proof_str: &[u8; 16], temp: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::with_capacity(16 + temp.len());
    out.extend_from_slice(nt_proof_str);
    out.extend_from_slice(temp);
    Zeroizing::new(out)
}

/// `LmChallengeResponseV2`, MS-NLMP 3.3.2.
///
/// ```text
/// LmChallengeResponseV2 = HMAC_MD5( ResponseKeyLM,
///                                   ServerChallenge || ClientChallenge )
///                         || ClientChallenge
/// ```
///
/// We do not send this. MS-NLMP 3.1.5.1.2 says that when the CHALLENGE's
/// TargetInfo has an `MsvAvTimestamp`, the client SHOULD NOT send the
/// `LmChallengeResponse` and SHOULD send `Z(24)` instead, and we make the
/// timestamp mandatory. The reason the rule exists is worth stating: this
/// value is keyed with the same `NTOWFv2` but covers only the two challenges,
/// not the timestamp or the AV pairs, so it is an offline crackable value that
/// adds nothing when `NtChallengeResponse` is present.
///
/// Kept for the mock server side and for the 4.2.4.2.1 vector.
#[must_use]
pub fn lm_challenge_response_v2(
    response_key_lm: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
) -> Zeroizing<[u8; 24]> {
    let mut mac =
        <HmacMd5 as Mac>::new_from_slice(response_key_lm).expect("HMAC accepts any key length");
    mac.update(server_challenge);
    mac.update(client_challenge);
    let checksum = mac.finalize().into_bytes();
    let mut out = [0u8; 24];
    out[..16].copy_from_slice(&checksum);
    out[16..].copy_from_slice(client_challenge);
    Zeroizing::new(out)
}

/// `SessionBaseKey = HMAC_MD5( ResponseKeyNT, NTProofStr )`, MS-NLMP 3.3.2.
#[must_use]
pub fn session_base_key(
    response_key_nt: &[u8; 16],
    nt_proof_str: &[u8; 16],
) -> Zeroizing<[u8; 16]> {
    let mut mac =
        <HmacMd5 as Mac>::new_from_slice(response_key_nt).expect("HMAC accepts any key length");
    mac.update(nt_proof_str);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// `KXKEY`, MS-NLMP 3.4.5.1. For NTLMv2 the key exchange key is the session
/// base key, and that is the whole of it.
///
/// The 3.4.5.1 pseudocode has branches for `NTLMSSP_NEGOTIATE_LM_KEY`, for non
/// extended session security, and for `NTLMSSP_REQUEST_NON_NT_SESSION_KEY`.
/// None of them is reachable: we never set the first or the third, and we
/// refuse a CHALLENGE with extended session security cleared
/// (PRDRDP/14 §8.5). Naming the flags that would have selected them is more
/// useful than carrying dead code.
#[must_use]
pub fn key_exchange_key(session_base_key: &[u8; 16]) -> Zeroizing<[u8; 16]> {
    Zeroizing::new(*session_base_key)
}

/// `RC4K(K, D)`, MS-NLMP 6: initialise an RC4 handle with K, encrypt D,
/// discard the handle.
///
/// This is a different operation from the persistent sealing handles of
/// `seal.rs` and it has a different name for exactly that reason. The handle
/// created here encrypts sixteen bytes and dies on the next line.
#[must_use]
pub fn rc4k(key: &[u8; 16], data: &[u8; 16]) -> [u8; 16] {
    let mut buf = *data;
    let mut handle = Rc4::<U16>::new(key.into());
    handle.apply_keystream(&mut buf);
    buf
}

/// `SIGNKEY`, MS-NLMP 3.4.5.2, with extended session security negotiated.
///
/// ```text
/// SignKey(client) = MD5( ExportedSessionKey || CLIENT_SIGN )
/// SignKey(server) = MD5( ExportedSessionKey || SERVER_SIGN )
/// ```
///
/// Without extended session security `SIGNKEY` returns NULL and there is no
/// signing at all, which is one more reason we refuse to negotiate without it.
#[must_use]
pub fn sign_key(exported_session_key: &[u8; 16], direction: Direction) -> Zeroizing<[u8; 16]> {
    let magic = match direction {
        Direction::ClientToServer => CLIENT_SIGN,
        Direction::ServerToClient => SERVER_SIGN,
    };
    let mut hash = Md5::new();
    hash.update(exported_session_key);
    hash.update(magic);
    Zeroizing::new(hash.finalize().into())
}

/// `SEALKEY`, MS-NLMP 3.4.5.3, with extended session security negotiated.
///
/// ```text
/// if NTLMSSP_NEGOTIATE_128: k = ExportedSessionKey            (16 bytes)
/// elif NTLMSSP_NEGOTIATE_56: k = ExportedSessionKey[0..8]     (8 bytes)
/// else:                      k = ExportedSessionKey[0..5]     (5 bytes)
///
/// SealKey(client) = MD5( k || CLIENT_SEAL )
/// SealKey(server) = MD5( k || SERVER_SEAL )
/// ```
///
/// `negotiated_flags` are the server's from the CHALLENGE, not the ones we
/// asked for. We ask for 128 and 56 both; a server supporting 128 leaves both
/// set and 128 wins; a server supporting only 56 clears 128 and the 8 byte
/// truncation applies. The 5 byte case is 40 bit and is reachable only against
/// a server that cleared both. We accept it, because the sealing key strength
/// protects nothing TLS is not already protecting and refusing would break an
/// antique server for no gain. It is logged at `warn`.
///
/// The truncation applies to the input of the hash and never to the key that
/// reaches RC4: MD5 outputs 16 bytes whatever went in, so the handle is
/// `Rc4<U16>` in every case.
#[must_use]
pub fn seal_key(
    exported_session_key: &[u8; 16],
    negotiated_flags: u32,
    direction: Direction,
) -> Zeroizing<[u8; 16]> {
    let magic = match direction {
        Direction::ClientToServer => CLIENT_SEAL,
        Direction::ServerToClient => SERVER_SEAL,
    };
    let take = if negotiated_flags & flags::NEGOTIATE_128 != 0 {
        16
    } else if negotiated_flags & flags::NEGOTIATE_56 != 0 {
        8
    } else {
        tracing::warn!("the server negotiated a 40 bit NTLM sealing key");
        5
    };
    let mut hash = Md5::new();
    hash.update(&exported_session_key[..take]);
    hash.update(magic);
    Zeroizing::new(hash.finalize().into())
}

/// The MIC, MS-NLMP 3.1.5.1.2.
///
/// ```text
/// MIC = HMAC_MD5( ExportedSessionKey,
///                 NEGOTIATE_MESSAGE || CHALLENGE_MESSAGE || AUTHENTICATE_MESSAGE )
/// ```
///
/// All three are the exact bytes that went on the wire or arrived from it, not
/// re-encodings, and the AUTHENTICATE message has its MIC field set to sixteen
/// zero bytes.
///
/// The MIC is what makes the NTLM exchange tamper evident. Without it an
/// interceptor can strip flags out of the NEGOTIATE message or rewrite the
/// CHALLENGE's AV pairs, and neither is covered by `NTProofStr`, which covers
/// the AV pairs but says nothing about the NEGOTIATE message or the flags.
#[must_use]
pub fn mic(
    exported_session_key: &[u8; 16],
    negotiate: &[u8],
    challenge: &[u8],
    authenticate_with_zero_mic: &[u8],
) -> [u8; 16] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(exported_session_key)
        .expect("HMAC accepts any key length");
    mac.update(negotiate);
    mac.update(challenge);
    mac.update(authenticate_with_zero_mic);
    mac.finalize().into_bytes().into()
}

/// `MAC`'s checksum, MS-NLMP 3.4.4.1 with extended session security:
/// `HMAC_MD5(SigningKey, LE32(SeqNum) || Message)[0..8]`.
///
/// The checksum is computed over the plaintext, never over the ciphertext.
#[must_use]
pub fn mac_checksum(signing_key: &[u8; 16], seq_num: u32, message: &[u8]) -> [u8; 8] {
    let mut mac =
        <HmacMd5 as Mac>::new_from_slice(signing_key).expect("HMAC accepts any key length");
    mac.update(&seq_num.to_le_bytes());
    mac.update(message);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    out
}

/// Eight fresh bytes for `ChallengeFromClient` (MS-NLMP 2.2.2.7).
///
/// `rand::rng()` is a `ThreadRng`: ChaCha with 12 rounds, seeded from the
/// system source, reseeded every 64 kB, and it implements `CryptoRng`. It is
/// the generator `crates/vnc-core/src/security/ra2.rs:465` already uses for
/// the RealVNC client random, so the workspace has one generator rather than a
/// second opinion. `SmallRng`, `StdRng::seed_from_u64`, a `rand_chacha` seeded
/// from a constant and anything derived from a clock are all forbidden here
/// (PRDRDP/14 §2.10).
#[must_use]
pub fn client_challenge() -> [u8; 8] {
    let mut out = [0u8; 8];
    rand::rng().fill_bytes(&mut out);
    out
}

/// Sixteen fresh bytes for the `ExportedSessionKey` (MS-NLMP 3.1.5.1.2).
///
/// This is what makes the session keys independent of the password hash.
/// Without `NTLMSSP_NEGOTIATE_KEY_EXCH`, every session with the same password,
/// the same challenges and the same AV pairs derives the same sealing key.
#[must_use]
pub fn exported_session_key() -> Zeroizing<[u8; 16]> {
    let mut out = Zeroizing::new([0u8; 16]);
    rand::rng().fill_bytes(&mut *out);
    out
}
