//! `pubKeyAuth`: the two constructions of MS-CSSP 3.1.5, and the check that
//! the whole mechanism rests on.
//!
//! CredSSP's job is to stop the client handing its password to a machine that
//! is relaying the TLS connection somewhere else. It does that by making the
//! server prove it holds the private key of the certificate the client saw,
//! before the password is sent. Message 3 carries a value derived from the
//! server's public key, encrypted under the mechanism's session key; message
//! 4 carries the server's answer, which it can only compute if it decrypted
//! ours. If that answer does not verify, the exchange stops and no password
//! is sent (PRDRDP/14 §3.5, §3.7, §3.8).
//!
//! Two constructions, chosen by the effective version, which is frozen from
//! the server's first reply (PRDRDP/14 §3.4):
//!
//! ```text
//! versions 2, 3, 4        client: E( SubjectPublicKey )
//!                         server: E( SubjectPublicKey with byte 0 plus one )
//!
//! versions 5, 6           clientNonce = 32 random bytes
//!                         client: E( SHA256(CLIENT_MAGIC || nonce || key) )
//!                         server: E( SHA256(SERVER_MAGIC || nonce || key) )
//! ```
//!
//! ## Two errata land on eleven bytes of this file
//!
//! **The magic strings are ASCII with their NUL, not UTF-16.** MS-CSSP
//! erratum 2018-04-09 corrected 3.1.5 from
//! `SHA256(UNICODE(ClientServerHashMagic), Nonce, SubjectPublicKey)` to
//! `SHA256(ClientServerHashMagic, Nonce, SubjectPublicKey)`
//! (PRDRDP/11 §5.3 item 3). The current text also says, after both pseudocode
//! blocks: "The hash MUST include the null terminator (\0) of the string."
//! Both mistakes fail silently and both look exactly like a wrong password.
//! The `const` assertions below are why: a Rust byte string literal writes the
//! NUL as `\0` and it is invisible in a diff. A reviewer cannot see it; the
//! compiler can.
//!
//! **The input order is magic, nonce, key.** MS-CSSP 3.1.5 contradicts itself
//! and still does (PRDRDP/11 §5.3 item 10). The prose says "a SHA256 hash of
//! the ASN.1 encoded SubjectPublicKey concatenated with the bytes of the
//! well-known string ... and the generated nonce", which reads key, magic,
//! nonce. The pseudocode two lines below says
//! `SHA256(ClientServerHashMagic, Nonce, SubjectPublicKey)`. The pseudocode is
//! what Windows does. Follow the prose and NLA fails against every Windows
//! host.
//!
//! ## What the value bound actually is
//!
//! The `subjectPublicKey` BIT STRING contents of the server certificate's
//! SubjectPublicKeyInfo, with the unused bits octet already stripped
//! (MS-CSSP 3.1.5: "the ASN.1-encoded SubjectPublicKey sub-field of
//! SubjectPublicKeyInfo"). Not the SPKI element, not the SPKI contents, not
//! the certificate. The extraction is
//! [`rdp_pdu::asn1::der::subject_public_key`] and it happens in the session,
//! not here; this module is handed the bytes. For a 2048 bit RSA certificate
//! they start `30 82 01 0A 02 82 01 01 00`. If they start
//! `30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01` the caller passed the
//! SPKI and the exchange will reach message 4 and die opaquely
//! (PRDRDP/14 §3.6).
//!
//! ## Known risk
//!
//! The version 5 and 6 construction has no published test vector, because the
//! nonce makes it non-deterministic (PRDRDP/11 §2.10). What is proved here is
//! the concatenation order, the NUL terminators, the direction reversal and
//! the refusal, all against values this module computes and against a server
//! side written from the same specification. The first real proof is a
//! Windows host.

use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::AuthError;

use super::ts_request::NONCE_LEN;

/// MS-CSSP 3.1.5 step 3, "Version 5 or 6". Thirty seven characters and the
/// NUL terminator the specification requires.
pub const CLIENT_SERVER_HASH_MAGIC: &[u8] = b"CredSSP Client-To-Server Binding Hash\0";
/// MS-CSSP 3.1.5 step 4, "Version 5 and 6". Same length.
pub const SERVER_CLIENT_HASH_MAGIC: &[u8] = b"CredSSP Server-To-Client Binding Hash\0";
const _: () = assert!(CLIENT_SERVER_HASH_MAGIC.len() == 38);
const _: () = assert!(SERVER_CLIENT_HASH_MAGIC.len() == 38);
const _: () = assert!(CLIENT_SERVER_HASH_MAGIC[37] == 0);
const _: () = assert!(SERVER_CLIENT_HASH_MAGIC[37] == 0);

/// The lowest version that uses the nonce and the SHA-256 hashes
/// (MS-CSSP 2.2.1: "This value is only used in version 5 or higher").
pub const FIRST_HASHED_VERSION: u32 = 5;

/// The binding construction for one effective version, with its nonce.
///
/// One type rather than a version number and an `Option<nonce>` passed
/// separately, because those two can disagree and this cannot: a value built
/// for version 4 has no nonce and a value built for version 6 always has one.
#[derive(Clone)]
pub struct PublicKeyBinding {
    version: u32,
    /// `None` below version 5. Not zeroized: it is sent in the clear in the
    /// TSRequest and treating it as a secret would be cargo cult
    /// (PRDRDP/14 §8.2).
    nonce: Option<[u8; NONCE_LEN]>,
}

impl PublicKeyBinding {
    /// Choose the construction for `version` and, at version 5 or higher,
    /// draw the nonce.
    ///
    /// The nonce comes from `rand::rng()`, the one generator in the
    /// workspace, exactly as the NTLM client challenge does
    /// (PRDRDP/14 §2.10). A counter or a short value here is a downgrade to a
    /// replayable binding.
    ///
    /// Call order matters and is fixed by PRDRDP/14 §3.5: the mechanism
    /// produces its final token first, then this is built, then the hash is
    /// computed from it. Building it after the hash produces a binding over a
    /// nonce that was never sent.
    #[must_use]
    pub fn new(version: u32) -> Self {
        let nonce = if version >= FIRST_HASHED_VERSION {
            let mut nonce = [0u8; NONCE_LEN];
            rand::rng().fill_bytes(&mut nonce);
            Some(nonce)
        } else {
            None
        };
        PublicKeyBinding { version, nonce }
    }

    /// The same, with the nonce supplied. For the tests and for a server side
    /// recomputing what a client sent.
    #[must_use]
    pub fn with_nonce(version: u32, nonce: [u8; NONCE_LEN]) -> Self {
        PublicKeyBinding {
            version,
            nonce: if version >= FIRST_HASHED_VERSION {
                Some(nonce)
            } else {
                None
            },
        }
    }

    /// The effective CredSSP version this binding was built for.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The bytes that go in `TSRequest.clientNonce`, or `None` below version
    /// 5.
    ///
    /// MS-CSSP is explicit that `clientNonce` appears only in the message
    /// carrying `pubKeyAuth`. It is not repeated in message 5 and a server
    /// that sends one back is refused.
    #[must_use]
    pub fn nonce(&self) -> Option<&[u8; NONCE_LEN]> {
        self.nonce.as_ref()
    }

    /// What the client encrypts into `pubKeyAuth` in message 3
    /// (MS-CSSP 3.1.5 step 3).
    #[must_use]
    pub fn client_value(&self, public_key: &[u8]) -> Vec<u8> {
        match &self.nonce {
            Some(nonce) => hash(CLIENT_SERVER_HASH_MAGIC, nonce, public_key),
            None => public_key.to_vec(),
        }
    }

    /// What the server must send back in message 4 (MS-CSSP 3.1.5 step 4).
    ///
    /// The direction reverses. At version 5 and above that is a different
    /// magic string over the same nonce and key; below it, the same public
    /// key with one added to its first byte. Both exist so that the client's
    /// own `pubKeyAuth` cannot be replayed back at it, which MS-CSSP 3.1.5
    /// says in as many words: "The addition of 1 to the first byte of the
    /// public key is performed so that the client-generated pubKeyAuth
    /// message cannot be replayed back to the client by an attacker."
    #[must_use]
    pub fn expected_server_value(&self, public_key: &[u8]) -> Vec<u8> {
        match &self.nonce {
            Some(nonce) => hash(SERVER_CLIENT_HASH_MAGIC, nonce, public_key),
            None => {
                let mut want = public_key.to_vec();
                if let Some(first) = want.first_mut() {
                    // Wrapping, not `+= 1`. The first byte of a DER
                    // RSAPublicKey is 0x30 and of an EC point is 0x04, so an
                    // overflow cannot happen for a real certificate, and a
                    // hostile input must not be able to panic a debug build.
                    *first = first.wrapping_add(1);
                }
                want
            }
        }
    }

    /// Verify the server's `pubKeyAuth` plaintext, MS-CSSP 3.1.5 step 5.
    ///
    /// This is the check the whole mechanism exists for. A server that cannot
    /// produce this value did not decrypt ours, which means it does not hold
    /// the session key, which means it is not the machine whose certificate
    /// we pinned. The password is not sent when this fails.
    ///
    /// # Errors
    ///
    /// [`AuthError::PublicKeyMismatch`] on any difference, including a length
    /// difference. The variant carries no offset and no payload: an offset
    /// that exists only for a log line is a forgery oracle's other half
    /// (PRDRDP/00 R63, PRDRDP/14 §8.1).
    pub fn verify_server_value(&self, public_key: &[u8], got: &[u8]) -> Result<(), AuthError> {
        let mut want = self.expected_server_value(public_key);
        // Constant time even though both values are public here. It costs
        // nothing and it means nobody has to reason about whether it is
        // public (PRDRDP/14 §8.1).
        let same = want.ct_eq(got);
        want.zeroize();
        if same.unwrap_u8() != 1 {
            tracing::warn!(
                version = self.version,
                got = got.len(),
                want = public_key.len(),
                "the server's pubKeyAuth did not match the value we computed"
            );
            return Err(AuthError::PublicKeyMismatch);
        }
        Ok(())
    }
}

impl std::fmt::Debug for PublicKeyBinding {
    /// The nonce is not a secret and there is still no reason for it to reach
    /// a log (PRDRDP/14 §8.4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeyBinding")
            .field("version", &self.version)
            .field("nonce", &self.nonce.map(|_| "32 bytes"))
            .finish()
    }
}

/// `SHA256(magic, nonce, key)`, in that order, MS-CSSP 3.1.5.
///
/// The order is the pseudocode's and not the prose's; see the module comment.
/// The arithmetic is `sha2`'s (AGENT_BRIEF V3-A, PRDRDP/14 §2.10).
fn hash(magic: &[u8], nonce: &[u8; NONCE_LEN], public_key: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(magic);
    digest.update(nonce);
    digest.update(public_key);
    digest.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `subjectPublicKey` of a 2048 bit RSA certificate starts like this
    /// (PRDRDP/14 §3.6). Only the shape matters for these tests.
    const KEY: &[u8] = &[
        0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc3, 0x2f, 0x11,
    ];
    const NONCE: [u8; NONCE_LEN] = [0x5a; NONCE_LEN];

    #[test]
    fn the_magic_strings_carry_their_nul_and_are_not_transposed() {
        assert_eq!(CLIENT_SERVER_HASH_MAGIC.len(), 38);
        assert_eq!(SERVER_CLIENT_HASH_MAGIC.len(), 38);
        assert_eq!(
            &CLIENT_SERVER_HASH_MAGIC[..37],
            b"CredSSP Client-To-Server Binding Hash"
        );
        assert_eq!(
            &SERVER_CLIENT_HASH_MAGIC[..37],
            b"CredSSP Server-To-Client Binding Hash"
        );
        // They differ in exactly the two words that name the direction, which
        // is the transposition PRDRDP/14 §8.8 lists as looking exactly like a
        // wrong password.
        assert_ne!(CLIENT_SERVER_HASH_MAGIC, SERVER_CLIENT_HASH_MAGIC);
    }

    #[test]
    fn version_six_hashes_magic_then_nonce_then_key() {
        // Derived independently here, from the pseudocode of MS-CSSP 3.1.5,
        // and then compared with what the type produces.
        let mut want = Sha256::new();
        want.update(b"CredSSP Client-To-Server Binding Hash\0");
        want.update(NONCE);
        want.update(KEY);
        let want = want.finalize().to_vec();

        let binding = PublicKeyBinding::with_nonce(6, NONCE);
        assert_eq!(binding.client_value(KEY), want);
        assert_eq!(binding.client_value(KEY).len(), 32);

        // The order the prose asks for, which is the one that fails against
        // every Windows host (PRDRDP/11 §5.3 item 10).
        let mut prose = Sha256::new();
        prose.update(KEY);
        prose.update(b"CredSSP Client-To-Server Binding Hash\0");
        prose.update(NONCE);
        assert_ne!(binding.client_value(KEY), prose.finalize().to_vec());
    }

    #[test]
    fn the_server_direction_uses_the_other_magic_string() {
        let binding = PublicKeyBinding::with_nonce(6, NONCE);
        let mut want = Sha256::new();
        want.update(b"CredSSP Server-To-Client Binding Hash\0");
        want.update(NONCE);
        want.update(KEY);
        assert_eq!(binding.expected_server_value(KEY), want.finalize().to_vec());
        // And it is not the value we sent, which is the replay the reversal
        // exists to stop.
        assert_ne!(
            binding.expected_server_value(KEY),
            binding.client_value(KEY)
        );
    }

    #[test]
    fn versions_two_to_four_send_the_key_and_expect_it_incremented() {
        for version in [2u32, 3, 4] {
            let binding = PublicKeyBinding::new(version);
            assert!(binding.nonce().is_none(), "version {version} drew a nonce");
            assert_eq!(binding.client_value(KEY), KEY);
            let want = binding.expected_server_value(KEY);
            assert_eq!(want[0], 0x31, "0x30 plus one");
            assert_eq!(&want[1..], &KEY[1..], "only the first byte changes");
        }
    }

    #[test]
    fn the_increment_wraps_and_an_empty_key_does_not_panic() {
        let binding = PublicKeyBinding::new(2);
        assert_eq!(
            binding.expected_server_value(&[0xff, 0x01]),
            vec![0x00, 0x01]
        );
        assert!(binding.expected_server_value(&[]).is_empty());
    }

    #[test]
    fn a_pubkeyauth_that_does_not_match_is_refused() {
        // The entire point of the mechanism. Every one of these is a value a
        // relay or a confused server can produce, and none of them may pass.
        for version in [2u32, 3, 4, 5, 6] {
            let binding = PublicKeyBinding::with_nonce(version, NONCE);
            let good = binding.expected_server_value(KEY);
            assert!(binding.verify_server_value(KEY, &good).is_ok());

            // Our own value echoed back, which is the replay.
            assert_eq!(
                binding
                    .verify_server_value(KEY, &binding.client_value(KEY))
                    .unwrap_err(),
                AuthError::PublicKeyMismatch
            );
            // One bit flipped, in every position.
            for i in 0..good.len() {
                let mut bad = good.clone();
                bad[i] ^= 0x01;
                assert_eq!(
                    binding.verify_server_value(KEY, &bad).unwrap_err(),
                    AuthError::PublicKeyMismatch,
                    "version {version} accepted a flip at byte {i}"
                );
            }
            // Truncated, extended, and empty.
            assert_eq!(
                binding
                    .verify_server_value(KEY, &good[..good.len() - 1])
                    .unwrap_err(),
                AuthError::PublicKeyMismatch
            );
            let mut longer = good.clone();
            longer.push(0);
            assert_eq!(
                binding.verify_server_value(KEY, &longer).unwrap_err(),
                AuthError::PublicKeyMismatch
            );
            assert_eq!(
                binding.verify_server_value(KEY, &[]).unwrap_err(),
                AuthError::PublicKeyMismatch
            );
            // The right construction over a different certificate.
            assert_eq!(
                binding
                    .verify_server_value(b"another server's public key", &good)
                    .unwrap_err(),
                AuthError::PublicKeyMismatch
            );
        }
    }

    #[test]
    fn a_version_six_binding_is_not_a_version_four_one() {
        // A server that advertised 6, watched us pick the hash, and then
        // answered as if at version 2 gets nothing: the values do not agree
        // in either direction (PRDRDP/14 §8.7).
        let six = PublicKeyBinding::with_nonce(6, NONCE);
        let four = PublicKeyBinding::new(4);
        assert_eq!(
            six.verify_server_value(KEY, &four.expected_server_value(KEY))
                .unwrap_err(),
            AuthError::PublicKeyMismatch
        );
        assert_eq!(
            four.verify_server_value(KEY, &six.expected_server_value(KEY))
                .unwrap_err(),
            AuthError::PublicKeyMismatch
        );
    }

    #[test]
    fn two_bindings_never_share_a_nonce() {
        let a = PublicKeyBinding::new(6);
        let b = PublicKeyBinding::new(6);
        assert_ne!(a.nonce(), b.nonce());
        assert_ne!(a.client_value(KEY), b.client_value(KEY));
    }

    #[test]
    fn the_debug_rendering_shows_no_nonce_bytes() {
        let binding = PublicKeyBinding::with_nonce(6, NONCE);
        let rendered = format!("{binding:?}");
        assert!(!rendered.contains("5a"), "{rendered}");
        assert!(rendered.contains("32 bytes"), "{rendered}");
    }
}
