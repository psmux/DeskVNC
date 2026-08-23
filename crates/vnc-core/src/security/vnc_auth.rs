//! Security type 2, classic VNC authentication (DES challenge/response).
//!
//! The server sends a 16-byte challenge. The client builds a DES key from the
//! password (truncated to 8 bytes, zero-padded), encrypts both halves of the
//! challenge **independently** in ECB mode, and returns the 16 bytes.
//!
//! ## The bit-reversal trap
//!
//! AT&T's original implementation fed the password bytes to a DES
//! implementation that consumed key bits LSB-first. Every VNC server since has
//! reproduced that, so **each key byte's bit order must be reversed** before it
//! is handed to a conventional DES implementation. Get it wrong and the
//! handshake completes but authentication simply fails, with no diagnostic, //! which is why this has its own unit tests.
//!
//! Corroborating public constant: the fixed key TightVNC/UltraVNC/TigerVNC use
//! to obfuscate stored passwords is `e84ad660c4721ae0`, which is exactly the
//! byte-reversed form of the ASCII-ish bytes `17 52 6b 06 23 4e 58 07`.

use cipher::{BlockEncrypt, KeyInit};
use des::Des;
use zeroize::Zeroize;

use vnc_transport::BoxedStream;

use super::prompt::CredentialSource;
use super::{read_bytes, write_all, AuthOutcome};
use crate::error::Result;
use crate::types::{ConnectOptions, CredentialKind};

/// Legacy DES auth uses at most 8 password bytes.
pub const MAX_PASSWORD_BYTES: usize = 8;

/// What the credential dialog calls this method.
pub const METHOD: &str = "VNC Authentication";
const CHALLENGE_LEN: usize = 16;

/// Reverse the bit order within a byte (`0b0000_0001` -> `0b1000_0000`).
#[inline]
pub fn mirror_byte(b: u8) -> u8 {
    b.reverse_bits()
}

/// Build the 8-byte DES key a VNC server expects from a password.
///
/// Truncates to 8 bytes, zero-pads, and mirrors every byte. The password is
/// treated as raw bytes (its UTF-8 encoding), matching every server we target.
pub fn des_key_from_password(password: &str) -> [u8; 8] {
    let bytes = password.as_bytes();
    let mut key = [0u8; 8];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = mirror_byte(bytes.get(i).copied().unwrap_or(0));
    }
    key
}

/// Encrypt one 8-byte block with DES-ECB under an already-mirrored key.
fn des_ecb_block(key: &[u8; 8], block: &mut [u8; 8]) {
    let cipher = Des::new_from_slice(key).expect("DES key is exactly 8 bytes");
    cipher.encrypt_block(block.as_mut_slice().into());
}

/// The full VNC-auth response: both halves of the challenge, encrypted
/// independently under the same key.
pub fn respond_to_challenge(
    password: &str,
    challenge: &[u8; CHALLENGE_LEN],
) -> [u8; CHALLENGE_LEN] {
    let mut key = des_key_from_password(password);
    let mut response = *challenge;
    for chunk in response.chunks_exact_mut(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        des_ecb_block(&key, &mut block);
        chunk.copy_from_slice(&block);
    }
    key.zeroize();
    response
}

pub(crate) async fn handshake(
    stream: BoxedStream,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<AuthOutcome> {
    handshake_named(stream, opts, creds, METHOD).await
}

/// As [`handshake`], but with the method name the dialog should show.
///
/// Tight (16) and VeNCrypt's `*Vnc` subtypes run this exact exchange nested
/// inside their own negotiation, and the user is better served by
/// "TightVNC (VNC Authentication)" than by a bare "VNC Authentication" that
/// does not match the security type they picked.
pub(crate) async fn handshake_named(
    mut stream: BoxedStream,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
    method: &str,
) -> Result<AuthOutcome> {
    // DES truncates to 8 characters, silently, the dialog must say so.
    let supplied = creds
        .obtain(method, CredentialKind::PasswordOnly, true, opts)
        .await?;
    let mut password = supplied.password.unwrap_or_default();
    if password.len() > MAX_PASSWORD_BYTES {
        tracing::warn!(
            "server uses legacy VNC authentication, only the first {MAX_PASSWORD_BYTES} \
             characters of the password are used"
        );
    }

    let challenge = read_challenge(&mut stream).await?;
    let response = respond_to_challenge(&password, &challenge);
    password.zeroize();
    write_all(&mut stream, &response).await?;

    Ok(AuthOutcome::auto(stream))
}

/// Read the 16-byte challenge. Split out so VeNCrypt's `*Vnc` subtypes and
/// Tight's auth code 2 can reuse the whole exchange via [`handshake`].
async fn read_challenge(stream: &mut BoxedStream) -> Result<[u8; CHALLENGE_LEN]> {
    let bytes = read_bytes(stream, CHALLENGE_LEN, "VNC auth challenge").await?;
    let mut challenge = [0u8; CHALLENGE_LEN];
    challenge.copy_from_slice(&bytes);
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrors_single_bits() {
        assert_eq!(mirror_byte(0b0000_0001), 0b1000_0000);
        assert_eq!(mirror_byte(0b1000_0000), 0b0000_0001);
        assert_eq!(mirror_byte(0x00), 0x00);
        assert_eq!(mirror_byte(0xff), 0xff);
        assert_eq!(mirror_byte(0b1010_0000), 0b0000_0101);
    }

    /// The publicly documented VNC "fixed key" used by vncpasswd to obfuscate
    /// stored passwords is the mirrored form of these bytes. If our mirroring
    /// matches, it matches every VNC server's.
    #[test]
    fn matches_the_published_fixed_key() {
        let plain = [0x17u8, 0x52, 0x6b, 0x06, 0x23, 0x4e, 0x58, 0x07];
        let mirrored: Vec<u8> = plain.iter().copied().map(mirror_byte).collect();
        assert_eq!(
            mirrored,
            vec![0xe8, 0x4a, 0xd6, 0x60, 0xc4, 0x72, 0x1a, 0xe0]
        );
    }

    #[test]
    fn builds_keys_with_truncation_and_padding() {
        // "password" -> mirrored bytes.
        assert_eq!(
            des_key_from_password("password"),
            [0x0e, 0x86, 0xce, 0xce, 0xee, 0xf6, 0x4e, 0x26]
        );
        // Short passwords are zero padded; zero mirrors to zero.
        assert_eq!(des_key_from_password("ab")[2..], [0u8; 6]);
        // Anything past 8 bytes is ignored.
        assert_eq!(
            des_key_from_password("password"),
            des_key_from_password("passwordEXTRA")
        );
    }

    /// Known-good vector, cross-checked against `openssl enc -des-ecb`:
    ///
    /// ```text
    /// password  = "password"
    /// DES key   = 0E86CECEEEF64E26   (mirrored "password")
    /// challenge = 00112233445566778899aabbccddeeff
    /// response  = b7b9c87777661a7a2299733209bfdfce
    /// ```
    #[test]
    fn known_good_challenge_response() {
        let challenge: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0xb7, 0xb9, 0xc8, 0x77, 0x77, 0x66, 0x1a, 0x7a, 0x22, 0x99, 0x73, 0x32, 0x09, 0xbf,
            0xdf, 0xce,
        ];
        assert_eq!(respond_to_challenge("password", &challenge), expected);
    }

    /// Each 8-byte half is encrypted independently, a repeated half must
    /// produce a repeated response half (that is what "ECB" costs us).
    #[test]
    fn halves_are_encrypted_independently() {
        let challenge = [0xa5u8; 16];
        let r = respond_to_challenge("secret", &challenge);
        assert_eq!(r[..8], r[8..]);
    }

    #[test]
    fn wrong_bit_order_would_differ() {
        // Guard against someone "simplifying" the mirroring away.
        let challenge = [0u8; 16];
        let correct = respond_to_challenge("password", &challenge);
        let mut naive_key = [0u8; 8];
        naive_key.copy_from_slice(b"password");
        let mut block = [0u8; 8];
        des_ecb_block(&naive_key, &mut block);
        assert_ne!(&correct[..8], &block[..]);
    }

    #[tokio::test]
    async fn handshake_reads_challenge_and_writes_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(64);
        let challenge = [0x42u8; 16];
        server.write_all(&challenge).await.unwrap();

        let mut o = ConnectOptions::vnc("h", 5900);
        o.credentials = crate::types::Credentials::password("hunter2");
        let s: BoxedStream = Box::pin(client);
        let out = handshake(s, &o, &CredentialSource::none()).await.unwrap();
        drop(out);

        let mut got = [0u8; 16];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, respond_to_challenge("hunter2", &challenge));
    }

    #[tokio::test]
    async fn missing_password_asks_for_one() {
        let (client, _server) = tokio::io::duplex(64);
        let o = ConnectOptions::vnc("h", 5900);
        let s: BoxedStream = Box::pin(client);
        assert!(matches!(
            handshake(s, &o, &CredentialSource::none()).await,
            Err(crate::error::VncError::CredentialsRequired(_))
        ));
    }
}
