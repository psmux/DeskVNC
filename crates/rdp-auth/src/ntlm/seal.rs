//! The sealing handles, the sequence numbers, and `GSS_WrapEx`.
//!
//! MS-NLMP 3.4.3 defines `SEAL`, 3.4.4 defines `MAC`, 3.4.6 defines
//! `GSS_WrapEx`, and 2.2.2.9.1 defines the signature. This module owns the
//! only mutable cryptographic state in the crate.
//!
//! ```text
//! SEAL(Handle, SigningKey, SeqNum, Message):
//!     Sealed    = RC4(Handle, Message)              # 1. encrypt the plaintext
//!     Signature = MAC(Handle, SigningKey, SeqNum, Message)
//!     return Signature || Sealed
//!
//! MAC(Handle, SigningKey, SeqNum, Message):         # extended session security
//!     Checksum = HMAC_MD5(SigningKey, LE32(SeqNum) || Message)[0..8]
//!     if NTLMSSP_NEGOTIATE_KEY_EXCH:
//!         Checksum = RC4(Handle, Checksum)          # 2. same handle, after (1)
//!     return LE32(1) || Checksum || LE32(SeqNum)
//! ```
//!
//! Three rules hide in those six lines:
//!
//! * The checksum is computed over the plaintext, not the ciphertext. "Encrypt
//!   then sign" describes the order of operations on the RC4 handle, not what
//!   the MAC covers.
//! * The message is encrypted first, then the checksum, through the same
//!   handle. The keystream is consumed by the message and the checksum takes
//!   the next eight bytes. Doing the checksum first shifts the entire
//!   keystream and everything after it fails.
//! * The sequence number is prepended to the message for the HMAC and also
//!   appears in the signature, little endian in both places, and it increments
//!   after the operation.
//!
//! ## The RC4 state persists across messages
//!
//! MS-NLMP 3.4.3 and 3.4.4.2 create each handle once, at
//! `SIGNKEY`/`SEALKEY` initialisation in 3.1.5.1, and use it for every
//! subsequent message; the keystream continues where the last message left it.
//! Re-keying per message is the single most common NTLM sealing bug, and it
//! produces a first message that decrypts correctly and a second that does
//! not, which is exactly the shape of CredSSP failing at message 5 after
//! message 3 worked. The type prevents it: each `Rc4` is held by value and
//! there is no method that rebuilds one.
//!
//! ## Known risk
//!
//! This module has been exercised against MS-NLMP 4.2.4.4's `GSS_WrapEx`
//! vectors, which fix the keystream consumption order byte for byte for the
//! first message in one direction. The second and later messages, and the
//! unwrap direction, are proved only against ourselves until the mock server
//! side of PRDRDP/14 §9.3 exists and until a live server has been seen. If
//! CredSSP reaches message 4 and then fails, this file and the sequence
//! numbers are where to look.

use rc4::{consts::U16, KeyInit, Rc4, StreamCipher};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::AuthError;

use super::crypto::{mac_checksum, seal_key, sign_key, Direction};
use super::flags;

/// `MESSAGE_SIGNATURE` with extended session security, MS-NLMP 2.2.2.9.1.
///
/// ```text
/// offset size field
///   0     4    Version = 0x00000001
///   4     8    Checksum
///  12     4    SeqNum
/// ```
pub const SIGNATURE_LEN: usize = 16;
/// The `Version` field of a `MESSAGE_SIGNATURE`, MS-NLMP 2.2.2.9.1.
pub const SIGNATURE_VERSION: u32 = 0x0000_0001;

/// The established NTLM security context: four keys, two RC4 handles, two
/// sequence numbers.
pub struct NtlmSession {
    client_signing: Zeroizing<[u8; 16]>,
    server_signing: Zeroizing<[u8; 16]>,
    /// Persistent RC4 keystream, client to server. Never re-created
    /// (MS-NLMP 3.4.4.2).
    client_sealing: Rc4<U16>,
    /// Persistent RC4 keystream, server to client. Never re-created
    /// (MS-NLMP 3.4.4.2).
    server_sealing: Rc4<U16>,
    send_seq: u32,
    recv_seq: u32,
    /// Whether the checksum is RC4 encrypted, MS-NLMP 3.4.4.1.
    key_exch: bool,
}

impl NtlmSession {
    /// Derive all four keys and create both handles, MS-NLMP 3.1.5.1.
    ///
    /// `negotiated_flags` are the ones in the AUTHENTICATE message, which is
    /// the value the server uses for its own derivation. They must be the same
    /// value, or the two sides derive different sealing keys and nothing says
    /// why.
    #[must_use]
    pub fn new(exported_session_key: &[u8; 16], negotiated_flags: u32) -> Self {
        let client_seal = seal_key(
            exported_session_key,
            negotiated_flags,
            Direction::ClientToServer,
        );
        let server_seal = seal_key(
            exported_session_key,
            negotiated_flags,
            Direction::ServerToClient,
        );
        NtlmSession {
            client_signing: sign_key(exported_session_key, Direction::ClientToServer),
            server_signing: sign_key(exported_session_key, Direction::ServerToClient),
            client_sealing: Rc4::<U16>::new((&*client_seal).into()),
            server_sealing: Rc4::<U16>::new((&*server_seal).into()),
            send_seq: 0,
            recv_seq: 0,
            key_exch: negotiated_flags & flags::NEGOTIATE_KEY_EXCH != 0,
        }
    }

    /// The next sequence number we will send with. Diagnostics and tests.
    #[must_use]
    pub fn send_seq(&self) -> u32 {
        self.send_seq
    }

    /// The next sequence number we expect to receive.
    #[must_use]
    pub fn recv_seq(&self) -> u32 {
        self.recv_seq
    }

    /// `GSS_WrapEx` with confidentiality, MS-NLMP 3.4.6.
    ///
    /// The output layout is `signature || sealed`, sixteen bytes then the
    /// ciphertext, and that whole thing is what goes in a `pubKeyAuth` or
    /// `authInfo` OCTET STRING.
    pub fn wrap(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // 1. Encrypt the plaintext. This consumes `plaintext.len()` bytes of
        //    keystream, and the checksum below takes the next eight.
        let mut sealed = plaintext.to_vec();
        self.client_sealing.apply_keystream(&mut sealed);

        // 2. The checksum covers the PLAINTEXT, not `sealed`.
        let mut checksum = mac_checksum(&self.client_signing, self.send_seq, plaintext);
        if self.key_exch {
            self.client_sealing.apply_keystream(&mut checksum);
        }

        let mut out = Vec::with_capacity(SIGNATURE_LEN + sealed.len());
        out.extend_from_slice(&SIGNATURE_VERSION.to_le_bytes());
        out.extend_from_slice(&checksum);
        out.extend_from_slice(&self.send_seq.to_le_bytes());
        out.extend_from_slice(&sealed);
        self.send_seq = self.send_seq.wrapping_add(1);
        out
    }

    /// `GSS_UnwrapEx`, the mirror of [`wrap`](Self::wrap).
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] when the token is shorter than a
    /// signature or the version field is not 1,
    /// [`AuthError::MessageOutOfSequence`] when the signature's sequence
    /// number is not the one we expect, and [`AuthError::SignatureMismatch`]
    /// when the checksum does not verify.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        if token.len() < SIGNATURE_LEN {
            return Err(AuthError::MalformedMessage("NTLM signature is truncated"));
        }
        let (signature, sealed) = token.split_at(SIGNATURE_LEN);

        let version = u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
        if version != SIGNATURE_VERSION {
            return Err(AuthError::MalformedMessage("NTLM signature version"));
        }
        let seq = u32::from_le_bytes([signature[12], signature[13], signature[14], signature[15]]);
        if seq != self.recv_seq {
            return Err(AuthError::MessageOutOfSequence);
        }

        // Same order as the sender used: the message consumes its keystream
        // first, the checksum takes the next eight bytes.
        let mut plaintext = Zeroizing::new(sealed.to_vec());
        self.server_sealing.apply_keystream(&mut plaintext);

        let mut received = [0u8; 8];
        received.copy_from_slice(&signature[4..12]);
        if self.key_exch {
            self.server_sealing.apply_keystream(&mut received);
        }

        let expected = mac_checksum(&self.server_signing, self.recv_seq, &plaintext);
        // `Mac::verify_slice` is not usable here: the tag was RC4 encrypted
        // after truncation and has to be decrypted before comparison, so this
        // one site compares with `subtle` instead (PRDRDP/14 §8.1).
        let ok = expected.ct_eq(&received);
        received.zeroize();
        if ok.unwrap_u8() != 1 {
            return Err(AuthError::SignatureMismatch);
        }

        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(plaintext)
    }

    /// `GSS_GetMIC`: a signature over a message that is not sealed,
    /// MS-NLMP 3.4.4. Used for SPNEGO's `mechListMIC`.
    ///
    /// The handle still advances, because the checksum is encrypted through
    /// it. A `mic` call between two `wrap` calls therefore shifts the
    /// keystream, which is correct and is why this takes `&mut self`.
    pub fn mic(&mut self, message: &[u8]) -> Vec<u8> {
        let mut checksum = mac_checksum(&self.client_signing, self.send_seq, message);
        if self.key_exch {
            self.client_sealing.apply_keystream(&mut checksum);
        }
        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        out.extend_from_slice(&SIGNATURE_VERSION.to_le_bytes());
        out.extend_from_slice(&checksum);
        out.extend_from_slice(&self.send_seq.to_le_bytes());
        self.send_seq = self.send_seq.wrapping_add(1);
        out
    }

    /// `GSS_VerifyMIC`, constant time.
    ///
    /// # Errors
    ///
    /// As [`unwrap`](Self::unwrap), minus the decryption.
    pub fn verify_mic(&mut self, message: &[u8], signature: &[u8]) -> Result<(), AuthError> {
        let signature = signature
            .get(..SIGNATURE_LEN)
            .ok_or(AuthError::MalformedMessage("NTLM signature is truncated"))?;
        let version = u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
        if version != SIGNATURE_VERSION {
            return Err(AuthError::MalformedMessage("NTLM signature version"));
        }
        let seq = u32::from_le_bytes([signature[12], signature[13], signature[14], signature[15]]);
        if seq != self.recv_seq {
            return Err(AuthError::MessageOutOfSequence);
        }

        let mut received = [0u8; 8];
        received.copy_from_slice(&signature[4..12]);
        if self.key_exch {
            self.server_sealing.apply_keystream(&mut received);
        }
        let expected = mac_checksum(&self.server_signing, self.recv_seq, message);
        let ok = expected.ct_eq(&received);
        received.zeroize();
        if ok.unwrap_u8() != 1 {
            return Err(AuthError::SignatureMismatch);
        }
        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(())
    }
}

impl std::fmt::Debug for NtlmSession {
    /// Prints the sequence numbers, which are diagnostics, and nothing else.
    /// The four keys and both keystream states stay out of every rendering
    /// (PRDRDP/14 §8.3).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtlmSession")
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .field("keys", &"***")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two sessions with the same key, one used as each side, so a wrap on one
    /// unwraps on the other. The keys are directional, so the "server" side
    /// has to swap them, which is what `mirror` does.
    fn pair() -> (NtlmSession, NtlmSession) {
        let key = [0x55u8; 16];
        let f = flags::CLIENT_NEGOTIATE_FLAGS;
        let client = NtlmSession::new(&key, f);
        let mut server = NtlmSession::new(&key, f);
        std::mem::swap(&mut server.client_signing, &mut server.server_signing);
        std::mem::swap(&mut server.client_sealing, &mut server.server_sealing);
        (client, server)
    }

    #[test]
    fn a_wrap_round_trips_through_the_other_side() {
        let (mut client, mut server) = pair();
        let token = client.wrap(b"a public key blob");
        let plain = server.unwrap(&token).unwrap();
        assert_eq!(&*plain, b"a public key blob");
    }

    #[test]
    fn the_rc4_handle_persists_so_two_wraps_of_one_plaintext_differ() {
        // The check for the single most common NTLM sealing bug: re-keying the
        // handle per message (MS-NLMP 3.4.4.2).
        let (mut client, _) = pair();
        let first = client.wrap(b"same plaintext");
        let second = client.wrap(b"same plaintext");
        assert_ne!(first, second, "the RC4 handle was re-created per message");
    }

    #[test]
    fn the_sequence_numbers_are_zero_then_one() {
        // CredSSP sends pubKeyAuth at seq 0 and authInfo at seq 1, so a
        // mistake here is invisible at message 3 and fatal at message 5.
        let (mut client, mut server) = pair();
        assert_eq!(client.send_seq(), 0);
        let first = client.wrap(b"pubKeyAuth");
        assert_eq!(&first[12..16], &0u32.to_le_bytes());
        let second = client.wrap(b"authInfo");
        assert_eq!(&second[12..16], &1u32.to_le_bytes());
        assert_eq!(client.send_seq(), 2);

        server.unwrap(&first).unwrap();
        assert_eq!(server.recv_seq(), 1);
        server.unwrap(&second).unwrap();
    }

    #[test]
    fn out_of_order_messages_are_rejected() {
        let (mut client, mut server) = pair();
        let first = client.wrap(b"one");
        let second = client.wrap(b"two");
        assert_eq!(
            server.unwrap(&second).unwrap_err(),
            AuthError::MessageOutOfSequence
        );
        // And the first still verifies afterwards, because a rejected message
        // must not have advanced anything.
        assert_eq!(&*server.unwrap(&first).unwrap(), b"one");
    }

    #[test]
    fn tampering_is_detected() {
        let (mut client, mut server) = pair();
        let mut token = client.wrap(b"a public key blob");
        let last = token.len() - 1;
        token[last] ^= 0x01;
        assert_eq!(
            server.unwrap(&token).unwrap_err(),
            AuthError::SignatureMismatch
        );
    }

    #[test]
    fn a_truncated_token_is_an_error_not_a_panic() {
        let (mut client, mut server) = pair();
        let token = client.wrap(b"a public key blob");
        for n in 0..token.len() {
            assert!(server.unwrap(&token[..n]).is_err(), "prefix of {n} bytes");
        }
    }

    #[test]
    fn a_wrong_signature_version_is_refused() {
        let (mut client, mut server) = pair();
        let mut token = client.wrap(b"hello");
        token[0] = 2;
        assert!(matches!(
            server.unwrap(&token),
            Err(AuthError::MalformedMessage(_))
        ));
    }

    #[test]
    fn debug_prints_no_key_material() {
        let session = NtlmSession::new(&[0xABu8; 16], flags::CLIENT_NEGOTIATE_FLAGS);
        let rendered = format!("{session:?}");
        assert!(!rendered.to_lowercase().contains("ab"), "{rendered}");
        assert!(rendered.contains("***"), "{rendered}");
    }
}
