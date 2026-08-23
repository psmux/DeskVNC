//! MS-NLMP section 4.2, transcribed.
//!
//! Section 4.2 is a complete worked example and it is the reason the NTLM
//! module can be written with confidence. Every constant below was copied from
//! the section named in the comment above it, not typed from memory, which is
//! the transcription rule of PRDRDP/14 §9.2. If a vector does not match, the
//! code is wrong and the test does not move.
//!
//! These are the tests that matter most, because they test the composition
//! rather than the primitives: a vetted MD4 and a vetted HMAC called in the
//! wrong order fail `NTOWFv2`'s vector immediately (PRDRDP/14 §8.8).
//!
//! ## What is proved here and what is not
//!
//! 4.2.4's CHALLENGE carries no `MsvAvTimestamp`, so its inputs cannot be
//! driven through `NtlmClient` at all: our policy refuses that CHALLENGE
//! (PRDRDP/14 §8.5). The split is deliberate. The pure functions are proved
//! against the specification here; the state machine is proved against the
//! mock server side of PRDRDP/14 §9.3 and against real servers.
//!
//! Sections **4.2.2** (NTLM v1) and **4.2.3** (NTLM v1 with client challenge)
//! are not transcribed. Their test would be a negative one, and the negative
//! is already asserted where it belongs, in `ntlm::tests`: a CHALLENGE that
//! would select NTLMv1 is refused rather than answered, and there is no code
//! path in the crate that can produce an NTLMv1 response.

use rdp_auth::ntlm::crypto::{self, Direction};
use rdp_auth::ntlm::seal::NtlmSession;
use rdp_auth::ntlm::version::Version;
use rdp_auth::ntlm::{av_pair, flags, messages};

// ---------------------------------------------------------------------------
// 4.2.1 Common Values
// ---------------------------------------------------------------------------

/// 4.2.1: `User`.
const USER: &str = "User";
/// 4.2.1: `Domain`.
const DOMAIN: &str = "Domain";
/// 4.2.1: `Password`.
const PASSWORD: &str = "Password";
/// 4.2.1: `Workstation`, which appears in 4.2.4.3's AUTHENTICATE_MESSAGE at
/// offset 0x5c as `43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00`.
const WORKSTATION: &str = "COMPUTER";
/// 4.2.1: `Server Name`, which appears in 4.2.4.3's CHALLENGE_MESSAGE at
/// offset 0x38 as `53 00 65 00 72 00 76 00 65 00 72 00`.
const SERVER_NAME: &str = "Server";
/// 4.2.1: `RandomSessionKey`, sixteen bytes of 0x55.
const RANDOM_SESSION_KEY: [u8; 16] = [0x55; 16];
/// 4.2.1: `Time`, eight zero bytes.
const TIME: [u8; 8] = [0x00; 8];
/// 4.2.1: `ClientChallenge`, eight bytes of 0xaa.
const CLIENT_CHALLENGE: [u8; 8] = [0xaa; 8];
/// 4.2.1: `ServerChallenge`, `01 23 45 67 89 ab cd ef`.
const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

/// The `TargetInfo` of 4.2.4.3's CHALLENGE_MESSAGE, bytes 0x44 to 0x67:
/// `MsvAvNbDomainName = "Domain"`, `MsvAvNbComputerName = "Server"`,
/// `MsvAvEOL`.
const TARGET_INFO: &[u8] = &[
    0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
    0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

// ---------------------------------------------------------------------------
// 4.2.4.1 Calculations
// ---------------------------------------------------------------------------

/// 4.2.4.1.1: `NTOWFv2("Password", "User", "Domain")`.
/// `0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f`
const NTOWF_V2: [u8; 16] = [
    0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f,
];

/// 4.2.4.1.2: the Session Base Key.
/// `8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3`
const SESSION_BASE_KEY: [u8; 16] = [
    0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9, 0x5c, 0xa3,
];

/// 4.2.4.1.3: `temp`. The published dump on Microsoft Learn is rendered with
/// its first line clipped, so these are the same bytes as they appear inside
/// 4.2.4.3's AUTHENTICATE_MESSAGE, offsets 0x94 to 0xd7, that is the
/// `NtChallengeResponse` with its leading sixteen byte `NTProofStr` removed.
const TEMP: &[u8] = &[
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0x00,
    0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00,
    0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

// ---------------------------------------------------------------------------
// 4.2.4.2 Results
// ---------------------------------------------------------------------------

/// 4.2.4.2.1: the LMv2 Response, twenty four bytes. Also visible in
/// 4.2.4.3's AUTHENTICATE_MESSAGE at offset 0x6c.
const LMV2_RESPONSE: [u8; 24] = [
    0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
];

/// 4.2.4.2.2: the first sixteen bytes of the NTLMv2 Response, that is
/// `NTProofStr`. Visible in 4.2.4.3's AUTHENTICATE_MESSAGE at offset 0x84.
const NT_PROOF_STR: [u8; 16] = [
    0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef, 0x6a, 0x1c,
];

/// 4.2.4.2.3: the Encrypted Session Key, `RC4(RandomSessionKey)` under the
/// `KeyExchangeKey`.
/// `c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e`
const ENCRYPTED_SESSION_KEY: [u8; 16] = [
    0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90, 0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9, 0xd0, 0x3e,
];

// ---------------------------------------------------------------------------
// 4.2.4.3 Messages
// ---------------------------------------------------------------------------

/// 4.2.4.3: the CHALLENGE_MESSAGE, 104 bytes.
const CHALLENGE_MESSAGE: &[u8] = &[
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
    0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x8a, 0xe2, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x24, 0x00, 0x44, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
    0x65, 0x00, 0x72, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
    0x69, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
    0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// 4.2.4.3: the AUTHENTICATE_MESSAGE, 232 bytes.
///
/// Note two things a reader should check against the dump. Its
/// `NegotiateFlags` at offset 60 are `35 82 88 e2`, that is `0xE2888235`, and
/// its `DomainNameFields.BufferOffset` at offset 32 is `48 00 00 00`, that is
/// 72. So the payload begins at 72 and there is no MIC field, even though the
/// `Version` at offset 64 is present and non zero.
const AUTHENTICATE_MESSAGE: &[u8] = &[
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
    0x6c, 0x00, 0x00, 0x00, 0x54, 0x00, 0x54, 0x00, 0x84, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
    0x48, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x54, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
    0x5c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0xd8, 0x00, 0x00, 0x00, 0x35, 0x82, 0x88, 0xe2,
    0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
    0x69, 0x00, 0x6e, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x43, 0x00, 0x4f, 0x00,
    0x4d, 0x00, 0x50, 0x00, 0x55, 0x00, 0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x86, 0xc3, 0x50, 0x97,
    0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b,
    0xeb, 0xef, 0x6a, 0x1c, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
    0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90,
    0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9, 0xd0, 0x3e,
];

// ---------------------------------------------------------------------------
// 4.2.4.4 GSS_WrapEx Examples
// ---------------------------------------------------------------------------

/// 4.2.4.4: the plaintext, `"Plaintext"` in UTF-16LE.
const WRAP_PLAINTEXT: &[u8] = &[
    0x50, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x65, 0x00, 0x78, 0x00,
    0x74, 0x00,
];

/// 4.2.4.4: `SEALKEY(RandomSessionKey, "client-to-server")`.
/// `59 f6 00 97 3c c4 96 0a 25 48 0a 7c 19 6e 4c 58`
const CLIENT_SEALING_KEY: [u8; 16] = [
    0x59, 0xf6, 0x00, 0x97, 0x3c, 0xc4, 0x96, 0x0a, 0x25, 0x48, 0x0a, 0x7c, 0x19, 0x6e, 0x4c, 0x58,
];

/// 4.2.4.4: `SIGNKEY(RandomSessionKey, "client-to-server")`.
/// `47 88 dc 86 1b 47 82 f3 5d 43 fd 98 fe 1a 2d 39`
const CLIENT_SIGNING_KEY: [u8; 16] = [
    0x47, 0x88, 0xdc, 0x86, 0x1b, 0x47, 0x82, 0xf3, 0x5d, 0x43, 0xfd, 0x98, 0xfe, 0x1a, 0x2d, 0x39,
];

/// 4.2.4.4: the sealed data.
/// `54 e5 01 65 bf 19 36 dc 99 60 20 c1 81 1b 0f 06 fb 5f`
const WRAP_SEALED: &[u8] = &[
    0x54, 0xe5, 0x01, 0x65, 0xbf, 0x19, 0x36, 0xdc, 0x99, 0x60, 0x20, 0xc1, 0x81, 0x1b, 0x0f, 0x06,
    0xfb, 0x5f,
];

/// 4.2.4.4: `HMAC_MD5(SigningKey, ConcatenationOf(SeqNum, Message))[0..7]`,
/// before the RC4 pass. `70 35 28 51 f2 56 43 09`
const WRAP_CHECKSUM_PLAIN: [u8; 8] = [0x70, 0x35, 0x28, 0x51, 0xf2, 0x56, 0x43, 0x09];

/// 4.2.4.4: the signature.
/// `01 00 00 00 7f b3 8e c5 c5 5d 49 76 00 00 00 00`
const WRAP_SIGNATURE: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x7f, 0xb3, 0x8e, 0xc5, 0xc5, 0x5d, 0x49, 0x76, 0x00, 0x00, 0x00, 0x00,
];

// ---------------------------------------------------------------------------
// The assertions
// ---------------------------------------------------------------------------

/// 4.2.4.1.1. Proves the MD4, the UTF-16LE encoding, the user uppercasing and
/// the un-uppercased domain, all in one value.
#[test]
fn ntowf_v2_matches_4_2_4_1_1() {
    assert_eq!(*crypto::ntowf_v2(PASSWORD, USER, DOMAIN), NTOWF_V2);
    // LMOWFv2 is NTOWFv2 (MS-NLMP 3.3.2), which is what makes one vector
    // enough for both.
    assert_eq!(*crypto::lmowf_v2(PASSWORD, USER, DOMAIN), NTOWF_V2);
}

/// The un-uppercased domain is a real distinction, not a restatement.
#[test]
fn only_the_user_name_is_uppercased() {
    // "user" uppercases to "User"'s value; "domain" does not.
    assert_eq!(*crypto::ntowf_v2(PASSWORD, "user", DOMAIN), NTOWF_V2);
    assert_ne!(*crypto::ntowf_v2(PASSWORD, USER, "domain"), NTOWF_V2);
}

/// 4.2.4.1.3. Proves the RespType bytes, the reserved fields, the AV pair
/// serialisation and the trailing `Z(4)`.
#[test]
fn temp_matches_4_2_4_1_3() {
    let temp = crypto::temp(&TIME, &CLIENT_CHALLENGE, TARGET_INFO);
    assert_eq!(&*temp, TEMP);
}

/// The trailing `Z(4)` of MS-NLMP 3.3.2, asserted on its own because omitting
/// it produces a wrong password error against a correct password.
#[test]
fn temp_ends_in_eight_zero_bytes() {
    let temp = crypto::temp(&TIME, &CLIENT_CHALLENGE, TARGET_INFO);
    let tail = &temp[temp.len() - 8..];
    assert_eq!(tail, &[0u8; 8], "the MsvAvEOL pair plus the trailing Z(4)");
    assert_eq!(temp.len(), 28 + TARGET_INFO.len() + 4);
}

/// 4.2.4.2.2, the `NTProofStr` half of the NTLMv2 Response.
#[test]
fn nt_proof_str_matches_4_2_4_2_2() {
    let key = crypto::ntowf_v2(PASSWORD, USER, DOMAIN);
    let temp = crypto::temp(&TIME, &CLIENT_CHALLENGE, TARGET_INFO);
    let proof = crypto::nt_proof_str(&key, &SERVER_CHALLENGE, &temp);
    assert_eq!(*proof, NT_PROOF_STR);
}

/// 4.2.4.2.2, the whole `NtChallengeResponse`, which is what goes on the wire.
#[test]
fn the_ntlmv2_response_matches_the_authenticate_message() {
    let key = crypto::ntowf_v2(PASSWORD, USER, DOMAIN);
    let temp = crypto::temp(&TIME, &CLIENT_CHALLENGE, TARGET_INFO);
    let proof = crypto::nt_proof_str(&key, &SERVER_CHALLENGE, &temp);
    let response = crypto::nt_challenge_response(&proof, &temp);
    // Offsets 0x84 to 0xd7 of 4.2.4.3's AUTHENTICATE_MESSAGE.
    assert_eq!(&*response, &AUTHENTICATE_MESSAGE[0x84..0x84 + 0x54]);
    assert_eq!(response.len(), 84);
}

/// 4.2.4.1.2.
#[test]
fn session_base_key_matches_4_2_4_1_2() {
    let key = crypto::ntowf_v2(PASSWORD, USER, DOMAIN);
    let sbk = crypto::session_base_key(&key, &NT_PROOF_STR);
    assert_eq!(*sbk, SESSION_BASE_KEY);
    // MS-NLMP 3.4.5.1: for NTLMv2 the key exchange key is the session base key.
    assert_eq!(*crypto::key_exchange_key(&sbk), SESSION_BASE_KEY);
}

/// 4.2.4.2.1. We never send this value, and the mock server side recomputes it.
#[test]
fn lmv2_response_matches_4_2_4_2_1() {
    let key = crypto::lmowf_v2(PASSWORD, USER, DOMAIN);
    let lm = crypto::lm_challenge_response_v2(&key, &SERVER_CHALLENGE, &CLIENT_CHALLENGE);
    assert_eq!(*lm, LMV2_RESPONSE);
    // And 4.2.4.3's AUTHENTICATE_MESSAGE carries it at offset 0x6c.
    assert_eq!(&*lm, &AUTHENTICATE_MESSAGE[0x6c..0x6c + 24]);
}

/// 4.2.4.2.3. Proves `RC4K` and the `KXKEY` identity for NTLMv2 together.
#[test]
fn encrypted_session_key_matches_4_2_4_2_3() {
    let kxkey = crypto::key_exchange_key(&SESSION_BASE_KEY);
    assert_eq!(
        crypto::rc4k(&kxkey, &RANDOM_SESSION_KEY),
        ENCRYPTED_SESSION_KEY
    );
    // And 4.2.4.3's AUTHENTICATE_MESSAGE carries it at offset 0xd8.
    assert_eq!(
        &ENCRYPTED_SESSION_KEY,
        &AUTHENTICATE_MESSAGE[0xd8..0xd8 + 16]
    );
}

/// 4.2.4.3's CHALLENGE_MESSAGE, decoded and re-encoded to the same bytes.
#[test]
fn the_challenge_message_of_4_2_4_3_round_trips() {
    let msg = messages::decode_challenge(CHALLENGE_MESSAGE).unwrap();
    assert_eq!(msg.flags, 0xE28A_8233);
    assert_eq!(msg.server_challenge, SERVER_CHALLENGE);
    assert_eq!(msg.target_name, crypto::unicode(SERVER_NAME));
    assert_eq!(msg.target_info, TARGET_INFO);
    assert_eq!(
        msg.version,
        Some(Version {
            major: 6,
            minor: 0,
            build: 6000,
            revision: 0x0f
        })
    );
    assert_eq!(messages::encode_challenge(&msg), CHALLENGE_MESSAGE);

    // The AV pair list inside it round trips too.
    let pairs = av_pair::AvPairs::decode(&msg.target_info).unwrap();
    assert_eq!(pairs.encode(), TARGET_INFO);
    assert_eq!(
        pairs.get(av_pair::MSV_AV_NB_DOMAIN_NAME).unwrap(),
        crypto::unicode(DOMAIN)
    );
    assert_eq!(
        pairs.get(av_pair::MSV_AV_NB_COMPUTER_NAME).unwrap(),
        crypto::unicode(SERVER_NAME)
    );
    // No MsvAvTimestamp, which is why this example cannot be driven through
    // `NtlmClient` (PRDRDP/14 §8.5).
    assert!(pairs.get(av_pair::MSV_AV_TIMESTAMP).is_none());
}

/// 4.2.4.3's AUTHENTICATE_MESSAGE, encoded from its parts, byte for byte.
///
/// This is the field offset and payload order test: get any `BufferOffset`
/// wrong by one and the whole tail moves.
#[test]
fn the_authenticate_message_of_4_2_4_3_encodes_byte_for_byte() {
    let key = crypto::ntowf_v2(PASSWORD, USER, DOMAIN);
    let temp = crypto::temp(&TIME, &CLIENT_CHALLENGE, TARGET_INFO);
    let proof = crypto::nt_proof_str(&key, &SERVER_CHALLENGE, &temp);
    let nt = crypto::nt_challenge_response(&proof, &temp);
    let lm = crypto::lm_challenge_response_v2(&key, &SERVER_CHALLENGE, &CLIENT_CHALLENGE);
    let kxkey = crypto::key_exchange_key(&SESSION_BASE_KEY);
    let encrypted = crypto::rc4k(&kxkey, &RANDOM_SESSION_KEY);

    let fields = messages::AuthenticateFields {
        lm_challenge_response: &*lm,
        nt_challenge_response: &nt,
        domain_name: &crypto::unicode(DOMAIN),
        user_name: &crypto::unicode(USER),
        workstation: &crypto::unicode(WORKSTATION),
        encrypted_random_session_key: &encrypted,
        // The flags the example carries at offset 60, which are exactly the OR
        // of the twelve flags PRDRDP/14 §5.2's table names.
        negotiate_flags: 0xE288_8235,
        version: Version {
            major: 5,
            minor: 1,
            build: 2600,
            revision: 0x0f,
        },
        // The example predates the MIC: its payload begins at offset 72.
        with_mic: false,
    };
    let (encoded, mic_offset) = messages::encode_authenticate(&fields);
    assert_eq!(mic_offset, None);
    assert_eq!(encoded, AUTHENTICATE_MESSAGE);
}

/// Our own flag word is the one the specification's example uses.
#[test]
fn the_client_flag_word_equals_the_examples() {
    assert_eq!(flags::CLIENT_NEGOTIATE_FLAGS, 0xE288_8235);
    assert_eq!(
        &flags::CLIENT_NEGOTIATE_FLAGS.to_le_bytes(),
        &AUTHENTICATE_MESSAGE[60..64]
    );
}

/// 4.2.4.3's AUTHENTICATE_MESSAGE decodes to the parts it was built from.
#[test]
fn the_authenticate_message_of_4_2_4_3_decodes() {
    let msg = messages::decode_authenticate(AUTHENTICATE_MESSAGE).unwrap();
    assert_eq!(msg.lm_challenge_response, LMV2_RESPONSE);
    assert_eq!(msg.nt_challenge_response.len(), 84);
    assert_eq!(&msg.nt_challenge_response[..16], &NT_PROOF_STR);
    assert_eq!(msg.domain_name, crypto::unicode(DOMAIN));
    assert_eq!(msg.user_name, crypto::unicode(USER));
    assert_eq!(msg.workstation, crypto::unicode(WORKSTATION));
    assert_eq!(msg.encrypted_random_session_key, ENCRYPTED_SESSION_KEY);
    assert_eq!(msg.negotiate_flags, 0xE288_8235);
    assert_eq!(msg.mic, None, "the 4.2.4.3 example carries no MIC");
}

/// 4.2.4.4's `SIGNKEY` and `SEALKEY`, both directions of the client's half.
#[test]
fn the_sign_and_seal_keys_match_4_2_4_4() {
    let f = flags::CLIENT_NEGOTIATE_FLAGS;
    assert_eq!(
        *crypto::sign_key(&RANDOM_SESSION_KEY, Direction::ClientToServer),
        CLIENT_SIGNING_KEY
    );
    assert_eq!(
        *crypto::seal_key(&RANDOM_SESSION_KEY, f, Direction::ClientToServer),
        CLIENT_SEALING_KEY
    );
    // The server's keys are different values. A transposed magic string would
    // make these two equal to the two above.
    assert_ne!(
        *crypto::sign_key(&RANDOM_SESSION_KEY, Direction::ServerToClient),
        CLIENT_SIGNING_KEY
    );
    assert_ne!(
        *crypto::seal_key(&RANDOM_SESSION_KEY, f, Direction::ServerToClient),
        CLIENT_SEALING_KEY
    );
}

/// MS-NLMP 3.4.5.3's truncation cases, which are reachable against an old
/// server that clears 128 or both.
#[test]
fn the_seal_key_truncates_its_input_and_never_its_output() {
    let f56 = flags::NEGOTIATE_56;
    let f40 = 0u32;
    let k128 = crypto::seal_key(
        &RANDOM_SESSION_KEY,
        flags::NEGOTIATE_128,
        Direction::ClientToServer,
    );
    let k56 = crypto::seal_key(&RANDOM_SESSION_KEY, f56, Direction::ClientToServer);
    let k40 = crypto::seal_key(&RANDOM_SESSION_KEY, f40, Direction::ClientToServer);
    // MD5 output is sixteen bytes whatever went in, so the RC4 handle is
    // Rc4<U16> in every case (PRDRDP/14 §2.10).
    assert_eq!((k128.len(), k56.len(), k40.len()), (16, 16, 16));
    assert_ne!(*k128, *k56);
    assert_ne!(*k56, *k40);
}

/// 4.2.4.4's checksum before the RC4 pass. Proves that the MAC covers the
/// plaintext and that the sequence number is prepended little endian.
#[test]
fn the_mac_checksum_matches_4_2_4_4_before_the_rc4_pass() {
    assert_eq!(
        crypto::mac_checksum(&CLIENT_SIGNING_KEY, 0, WRAP_PLAINTEXT),
        WRAP_CHECKSUM_PLAIN
    );
}

/// 4.2.4.4's `GSS_WrapEx`, whole.
///
/// This is the vector that fixes the keystream consumption order byte for
/// byte: the message is encrypted first and the checksum takes the next eight
/// bytes of the same handle. Doing the checksum first shifts the entire
/// keystream and both halves of the output change.
#[test]
fn gss_wrap_ex_matches_4_2_4_4() {
    let mut session = NtlmSession::new(&RANDOM_SESSION_KEY, flags::CLIENT_NEGOTIATE_FLAGS);
    let token = session.wrap(WRAP_PLAINTEXT);
    assert_eq!(&token[..16], WRAP_SIGNATURE, "signature");
    assert_eq!(&token[16..], WRAP_SEALED, "sealed data");
    assert_eq!(session.send_seq(), 1);
}

/// Every prefix of a valid CHALLENGE_MESSAGE returns an error, never a panic.
///
/// This is `truncated_real_certificate_never_panics` from
/// `crates/vnc-transport/src/tls.rs:465` applied to a different structure, and
/// it is the single highest value test in the file: the CHALLENGE is the one
/// message a hostile server hands us directly.
#[test]
fn every_prefix_of_the_challenge_message_errors_rather_than_panicking() {
    for n in 0..CHALLENGE_MESSAGE.len() {
        let r = messages::decode_challenge(&CHALLENGE_MESSAGE[..n]);
        assert!(r.is_err(), "prefix of {n} bytes parsed as a whole message");
    }
    assert!(messages::decode_challenge(CHALLENGE_MESSAGE).is_ok());
}

/// The same for the AUTHENTICATE_MESSAGE, which the mock server side parses.
#[test]
fn every_prefix_of_the_authenticate_message_errors_rather_than_panicking() {
    for n in 0..AUTHENTICATE_MESSAGE.len() {
        let r = messages::decode_authenticate(&AUTHENTICATE_MESSAGE[..n]);
        assert!(r.is_err(), "prefix of {n} bytes parsed as a whole message");
    }
    assert!(messages::decode_authenticate(AUTHENTICATE_MESSAGE).is_ok());
}

/// Flipping any single bit of a valid CHALLENGE must not panic. 832 bits, 832
/// iterations, well under a second.
#[test]
fn no_single_bit_flip_in_a_challenge_panics() {
    for byte in 0..CHALLENGE_MESSAGE.len() {
        for bit in 0..8 {
            let mut m = CHALLENGE_MESSAGE.to_vec();
            m[byte] ^= 1 << bit;
            // Either outcome is fine. Panicking is not.
            let _ = messages::decode_challenge(&m);
        }
    }
}

/// Length field abuse: a `TargetInfoFields` that claims more than the message
/// holds, and a `BufferOffset` pointing backwards into the header.
#[test]
fn abusive_length_fields_are_refused() {
    let mut m = CHALLENGE_MESSAGE.to_vec();
    // TargetInfoFields.Len at offset 40, claim 0xffff.
    m[40] = 0xff;
    m[41] = 0xff;
    assert!(messages::decode_challenge(&m).is_err());

    let mut m = CHALLENGE_MESSAGE.to_vec();
    // TargetInfoFields.BufferOffset at offset 44, point past the end.
    m[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(messages::decode_challenge(&m).is_err());

    // A backwards offset into the header is legal in the sense that it parses
    // (the bytes are there); what must not happen is a panic or a read outside
    // the message.
    let mut m = CHALLENGE_MESSAGE.to_vec();
    m[44..48].copy_from_slice(&0u32.to_le_bytes());
    let _ = messages::decode_challenge(&m);

    // A wrong signature and a wrong message type are both refused.
    let mut m = CHALLENGE_MESSAGE.to_vec();
    m[0] = b'X';
    assert!(messages::decode_challenge(&m).is_err());
    let mut m = CHALLENGE_MESSAGE.to_vec();
    m[8] = 0x03;
    assert!(messages::decode_challenge(&m).is_err());
}
