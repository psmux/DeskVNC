//! Security type 30, Apple's Diffie-Hellman authentication.
//!
//! Used by macOS Screen Sharing and Apple Remote Desktop. Wire format:
//!
//! ```text
//! S->C  u16 generator
//! S->C  u16 key_length            (bytes, typically 64 => 512-bit DH)
//! S->C  prime[key_length]
//! S->C  server_public[key_length]
//! C->S  credentials[128]          AES-128-ECB( MD5(shared secret) )
//! C->S  client_public[key_length]
//! ```
//!
//! The credentials blob is two 64-byte fields, username then password, each
//! NUL-terminated and padded to length with **random** bytes (padding with
//! zeroes would leak the credential lengths to a passive observer).
//!
//! ## Security note
//!
//! 512-bit Diffie-Hellman is cryptographically dead: it is within reach of
//! precomputation attacks, and the *session* that follows is entirely
//! unencrypted regardless. This protects the password from casual capture and
//! nothing more. PRD/10 §5 is explicit that SSH tunnelling is the only way to
//! get a genuinely encrypted session to a Mac; the UI should offer it whenever
//! the banner is `RFB 003.889`.

use aes::Aes128;
use cipher::{block_padding::NoPadding, BlockEncryptMut, KeyInit};
use md5::{Digest, Md5};
use num_bigint_dig::BigUint;
use rand::Rng;
use zeroize::Zeroize;

use vnc_transport::BoxedStream;

use super::prompt::CredentialSource;
use super::{read_bytes, read_u16, write_all, AuthOutcome};
use crate::error::{Result, VncError};
use crate::types::{ConnectOptions, CredentialKind};

type Aes128EcbEnc = ecb::Encryptor<Aes128>;

/// One credential field: NUL-terminated, random-padded.
const FIELD_LEN: usize = 64;
/// Username field + password field.
const CREDENTIALS_LEN: usize = FIELD_LEN * 2;

/// Smallest DH modulus we will talk to. Apple uses 64 (512-bit).
const MIN_KEY_BYTES: usize = 32;
/// 8192-bit, anything larger is a denial-of-service attempt, not a server.
const MAX_KEY_BYTES: usize = 1024;

/// What the credential dialog calls this method.
pub const METHOD: &str = "Apple Remote Desktop";

pub(crate) async fn handshake(
    mut stream: BoxedStream,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<AuthOutcome> {
    // Apple's server behaves erratically with an empty user name, so we insist
    // on having one rather than sending a blank field. `obtain` guarantees a
    // non-empty user name for `UsernameAndPassword` (falling back to the OS
    // account name as the dialog's prefill).
    let supplied = creds
        .obtain(METHOD, CredentialKind::UsernameAndPassword, false, opts)
        .await?;
    let username = supplied.username.unwrap_or_default();
    let password = supplied.password.unwrap_or_default();
    if username.is_empty() {
        return Err(VncError::CredentialsRequired(
            "macOS Screen Sharing requires the name of a user account on that Mac".into(),
        ));
    }

    let generator = read_u16(&mut stream).await? as u64;
    let key_length = read_u16(&mut stream).await? as usize;

    if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key_length) {
        return Err(VncError::Protocol(format!(
            "Apple DH key length {key_length} is out of range ({MIN_KEY_BYTES}..={MAX_KEY_BYTES})"
        )));
    }
    if generator < 2 {
        return Err(VncError::Protocol(format!(
            "Apple DH generator {generator} is invalid"
        )));
    }

    let prime = read_bytes(&mut stream, key_length, "Apple DH prime").await?;
    let server_public = read_bytes(&mut stream, key_length, "Apple DH server public value").await?;

    let prime = BigUint::from_bytes_be(&prime);
    let server_public = BigUint::from_bytes_be(&server_public);
    if prime < BigUint::from(3u32) {
        return Err(VncError::Protocol("Apple DH modulus is degenerate".into()));
    }
    // A server public value of 0/1 (or p-1) forces a predictable shared secret.
    if server_public < BigUint::from(2u32) || server_public >= prime {
        return Err(VncError::Protocol(
            "Apple DH server public value is out of range".into(),
        ));
    }

    let (client_public, mut shared) = dh_exchange(generator, &prime, &server_public, key_length);

    // AES key = MD5 of the shared secret, left-padded to the modulus size.
    let mut aes_key = [0u8; 16];
    aes_key.copy_from_slice(&Md5::digest(&shared));
    shared.zeroize();

    let mut blob = credentials_blob(&username, &password);
    let mut ciphertext = [0u8; CREDENTIALS_LEN];
    Aes128EcbEnc::new(&aes_key.into())
        .encrypt_padded_b2b_mut::<NoPadding>(&blob, &mut ciphertext)
        .map_err(|_| VncError::Other("Apple DH: credential block was not block-aligned".into()))?;
    blob.zeroize();
    aes_key.zeroize();

    let mut message = Vec::with_capacity(CREDENTIALS_LEN + key_length);
    message.extend_from_slice(&ciphertext);
    message.extend_from_slice(&client_public);
    write_all(&mut stream, &message).await?;

    Ok(AuthOutcome::auto(stream))
}

/// Generate the client key pair and derive the shared secret.
///
/// Returns `(client_public, shared_secret)`, both left-padded to `key_length`.
fn dh_exchange(
    generator: u64,
    prime: &BigUint,
    server_public: &BigUint,
    key_length: usize,
) -> (Vec<u8>, Vec<u8>) {
    let g = BigUint::from(generator);

    // A private exponent the size of the modulus. `modpow` reduces it anyway.
    let mut private_bytes = vec![0u8; key_length];
    rand::rng().fill_bytes(&mut private_bytes);
    // Clear the top bit so the exponent is comfortably below the modulus and
    // never accidentally zero.
    private_bytes[0] &= 0x7f;
    private_bytes[key_length - 1] |= 0x01;
    let private = BigUint::from_bytes_be(&private_bytes);
    private_bytes.zeroize();

    let client_public = g.modpow(&private, prime);
    let shared = server_public.modpow(&private, prime);

    (
        left_pad(&client_public.to_bytes_be(), key_length),
        left_pad(&shared.to_bytes_be(), key_length),
    )
}

/// Big-endian values must occupy the full field width; `to_bytes_be` drops
/// leading zeroes, which happens roughly once in 256 exchanges and would
/// otherwise produce an intermittent, unreproducible auth failure.
fn left_pad(bytes: &[u8], width: usize) -> Vec<u8> {
    if bytes.len() >= width {
        return bytes[bytes.len() - width..].to_vec();
    }
    let mut out = vec![0u8; width];
    out[width - bytes.len()..].copy_from_slice(bytes);
    out
}

/// Build the 128-byte credentials block: two NUL-terminated, random-padded
/// 64-byte UTF-8 fields.
fn credentials_blob(username: &str, password: &str) -> [u8; CREDENTIALS_LEN] {
    let mut blob = [0u8; CREDENTIALS_LEN];
    rand::rng().fill_bytes(&mut blob);
    write_field(&mut blob[..FIELD_LEN], username);
    write_field(&mut blob[FIELD_LEN..], password);
    blob
}

/// Copy `value` into a random-filled field, truncating on a UTF-8 boundary so
/// there is always room for the terminating NUL.
fn write_field(field: &mut [u8], value: &str) {
    let mut end = value.len().min(field.len() - 1);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    field[..end].copy_from_slice(&value.as_bytes()[..end]);
    field[end] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_the_field_width() {
        assert_eq!(left_pad(&[1, 2], 4), vec![0, 0, 1, 2]);
        assert_eq!(left_pad(&[1, 2, 3, 4], 4), vec![1, 2, 3, 4]);
        // Over-long input keeps the least significant bytes.
        assert_eq!(left_pad(&[9, 1, 2, 3, 4], 4), vec![1, 2, 3, 4]);
    }

    #[test]
    fn credentials_blob_is_nul_terminated_and_random_padded() {
        let a = credentials_blob("alice", "hunter2");
        assert_eq!(&a[..5], b"alice");
        assert_eq!(a[5], 0);
        assert_eq!(&a[64..71], b"hunter2");
        assert_eq!(a[71], 0);

        // Padding differs between invocations, it is random, not zeroes.
        let b = credentials_blob("alice", "hunter2");
        assert_ne!(a[6..64], b[6..64]);
        assert_eq!(a.len(), 128);
    }

    #[test]
    fn over_long_credentials_are_truncated_safely() {
        let long = "é".repeat(100); // 200 bytes, multi-byte chars
        let blob = credentials_blob(&long, &long);
        // Terminator present within the field, and the prefix is valid UTF-8.
        let nul = blob[..FIELD_LEN].iter().position(|b| *b == 0).unwrap();
        assert!(nul < FIELD_LEN);
        assert!(std::str::from_utf8(&blob[..nul]).is_ok());
    }

    #[test]
    fn empty_credentials_still_produce_a_terminator() {
        let blob = credentials_blob("", "");
        assert_eq!(blob[0], 0);
        assert_eq!(blob[64], 0);
    }

    /// Both sides must arrive at the same secret, and it must fill the field.
    #[test]
    fn dh_round_trips_against_a_simulated_server() {
        // A small but real safe prime (RFC 5114-style toy value) keeps the test
        // fast while exercising the padding and modpow paths.
        let prime = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
              020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
              4FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap();
        let key_length = 128;
        let g = 2u64;

        // Simulated server key pair.
        let server_private = BigUint::from(0x1234_5678_9abc_def0u64);
        let server_public = BigUint::from(g).modpow(&server_private, &prime);

        let (client_public, shared) = dh_exchange(g, &prime, &server_public, key_length);
        assert_eq!(client_public.len(), key_length);
        assert_eq!(shared.len(), key_length);

        let server_view = BigUint::from_bytes_be(&client_public).modpow(&server_private, &prime);
        assert_eq!(left_pad(&server_view.to_bytes_be(), key_length), shared);
    }

    #[tokio::test]
    async fn rejects_absurd_key_length() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(&[0, 2]).await.unwrap(); // generator 2
        server.write_all(&[0xff, 0xff]).await.unwrap(); // 65535-byte key
        let mut o = ConnectOptions::vnc("mac", 5900);
        o.credentials = crate::types::Credentials::user_pass("alice", "pw");
        let s: BoxedStream = Box::pin(client);
        assert!(matches!(
            handshake(s, &o, &CredentialSource::none()).await,
            Err(VncError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn demands_a_username() {
        let (client, _server) = tokio::io::duplex(64);
        let mut o = ConnectOptions::vnc("mac", 5900);
        o.credentials = crate::types::Credentials::password("pw");
        let s: BoxedStream = Box::pin(client);
        assert!(matches!(
            handshake(s, &o, &CredentialSource::none()).await,
            Err(VncError::CredentialsRequired(_))
        ));
    }
}
