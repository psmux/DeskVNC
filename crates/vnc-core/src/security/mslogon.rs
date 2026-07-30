//! Security type 113, UltraVNC MSLogonII.
//!
//! A 64-bit Diffie-Hellman exchange whose shared secret is used as both the DES
//! key and the CBC initialisation vector for the credential fields:
//!
//! ```text
//! S->C  generator[8]              (big-endian u64)
//! S->C  modulus[8]
//! S->C  server_public[8]
//! C->S  client_public[8]
//! C->S  username[256]             DES-CBC, NUL-terminated, random-padded
//! C->S  password[64]              same
//! ```
//!
//! The DES key uses the same per-byte bit reversal as classic VNC auth (see
//! [`super::vnc_auth`]) because UltraVNC reuses VNC's modified `d3des`
//! implementation. The IV is the shared secret in its *unmirrored* form, //! `d3des` mirrors inside `deskey`, while the CBC XOR uses the raw bytes.
//!
//! ## Security note
//!
//! A 64-bit DH modulus is breakable by brute force on a laptop; MSLogonII is
//! supported for compatibility with existing UltraVNC deployments, not because
//! it is sound. The session that follows is unencrypted.

use cipher::{BlockEncrypt, KeyInit};
use des::Des;
use num_bigint_dig::BigUint;
use rand::Rng;
use zeroize::Zeroize;

use vnc_transport::BoxedStream;

use super::prompt::CredentialSource;
use super::{read_bytes, write_all, AuthOutcome};
use crate::error::{Result, VncError};
use crate::types::{ConnectOptions, CredentialKind};

const DH_BYTES: usize = 8;
const USER_FIELD: usize = 256;
const PASS_FIELD: usize = 64;

/// What the credential dialog calls this method.
pub const METHOD: &str = "UltraVNC MS-Logon";

pub(crate) async fn handshake(
    mut stream: BoxedStream,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<AuthOutcome> {
    // MS-Logon authenticates a Windows account, and DES truncates the password
    // to 8 characters just as classic VNC auth does.
    let supplied = creds
        .obtain(METHOD, CredentialKind::UsernameAndPassword, true, opts)
        .await?;
    let username = supplied.username.unwrap_or_default();
    let password = supplied.password.unwrap_or_default();

    let generator = read_bytes(&mut stream, DH_BYTES, "MSLogon generator").await?;
    let modulus = read_bytes(&mut stream, DH_BYTES, "MSLogon modulus").await?;
    let server_public = read_bytes(&mut stream, DH_BYTES, "MSLogon server public value").await?;

    let generator = BigUint::from_bytes_be(&generator);
    let modulus = BigUint::from_bytes_be(&modulus);
    let server_public = BigUint::from_bytes_be(&server_public);

    if modulus < BigUint::from(3u32) || generator < BigUint::from(2u32) {
        return Err(VncError::Protocol(
            "MSLogon server sent a degenerate Diffie-Hellman group".into(),
        ));
    }
    if server_public < BigUint::from(2u32) || server_public >= modulus {
        return Err(VncError::Protocol(
            "MSLogon server public value is out of range".into(),
        ));
    }

    // Client key pair.
    let mut private_bytes = [0u8; DH_BYTES];
    rand::rng().fill_bytes(&mut private_bytes);
    let private = BigUint::from_bytes_be(&private_bytes) % (&modulus - BigUint::from(1u32));
    private_bytes.zeroize();

    let client_public = generator.modpow(&private, &modulus);
    let mut secret = fixed_be(&server_public.modpow(&private, &modulus));

    write_all(&mut stream, &fixed_be(&client_public)).await?;

    let mut user_field = encrypt_field::<USER_FIELD>(&username, &secret);
    let mut pass_field = encrypt_field::<PASS_FIELD>(&password, &secret);
    secret.zeroize();

    let mut out = Vec::with_capacity(USER_FIELD + PASS_FIELD);
    out.extend_from_slice(&user_field);
    out.extend_from_slice(&pass_field);
    user_field.zeroize();
    pass_field.zeroize();

    let r = write_all(&mut stream, &out).await;
    out.zeroize();
    r?;

    Ok(AuthOutcome::auto(stream))
}

/// A `BigUint` as exactly 8 big-endian bytes.
fn fixed_be(v: &BigUint) -> [u8; DH_BYTES] {
    let bytes = v.to_bytes_be();
    let mut out = [0u8; DH_BYTES];
    if bytes.len() >= DH_BYTES {
        out.copy_from_slice(&bytes[bytes.len() - DH_BYTES..]);
    } else {
        out[DH_BYTES - bytes.len()..].copy_from_slice(&bytes);
    }
    out
}

/// Build one NUL-terminated, random-padded field and DES-CBC encrypt it.
fn encrypt_field<const N: usize>(value: &str, secret: &[u8; DH_BYTES]) -> [u8; N] {
    let mut field = [0u8; N];
    rand::rng().fill_bytes(&mut field);

    let mut end = value.len().min(N - 1);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    field[..end].copy_from_slice(&value.as_bytes()[..end]);
    field[end] = 0;

    des_cbc_encrypt(&mut field, secret);
    field
}

/// DES-CBC with the VNC bit-mirrored key and the raw secret as the IV.
///
/// `cbc` is not a dependency of this crate and the loop is four lines, so the
/// mode is written out rather than pulled in.
fn des_cbc_encrypt(buf: &mut [u8], secret: &[u8; DH_BYTES]) {
    debug_assert_eq!(buf.len() % 8, 0);

    let mut key = [0u8; 8];
    for (dst, src) in key.iter_mut().zip(secret.iter()) {
        *dst = super::vnc_auth::mirror_byte(*src);
    }
    let cipher = Des::new_from_slice(&key).expect("DES key is exactly 8 bytes");
    key.zeroize();

    let mut prev = *secret;
    for chunk in buf.chunks_exact_mut(8) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        cipher.encrypt_block(block.as_mut_slice().into());
        chunk.copy_from_slice(&block);
        prev = block;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_conversion() {
        assert_eq!(fixed_be(&BigUint::from(1u32)), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(fixed_be(&BigUint::from(u64::MAX)), [0xff; 8]);
    }

    #[test]
    fn fields_are_nul_terminated_before_encryption() {
        // Encrypt with an all-zero secret and decrypt by hand to check framing.
        let secret = [0u8; 8];
        let ct = encrypt_field::<64>("bob", &secret);
        let pt = des_cbc_decrypt(&ct, &secret);
        assert_eq!(&pt[..3], b"bob");
        assert_eq!(pt[3], 0);
    }

    #[test]
    fn cbc_chains_blocks() {
        // Identical plaintext blocks must not produce identical ciphertext.
        let secret = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut buf = [0xAAu8; 16];
        des_cbc_encrypt(&mut buf, &secret);
        assert_ne!(buf[..8], buf[8..]);
    }

    #[test]
    fn cbc_round_trips() {
        let secret = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let plain: Vec<u8> = (0u8..64).collect();
        let mut buf = plain.clone();
        des_cbc_encrypt(&mut buf, &secret);
        assert_ne!(buf, plain);
        assert_eq!(des_cbc_decrypt(&buf, &secret), plain);
    }

    #[test]
    fn dh_agrees_with_a_simulated_server() {
        let modulus = BigUint::from(0xFFFF_FFFF_FFFF_FFC5u64); // largest 64-bit prime
        let generator = BigUint::from(5u32);
        let server_private = BigUint::from(0x0BAD_C0FF_EE0D_DF00_u64);
        let server_public = generator.modpow(&server_private, &modulus);

        let client_private = BigUint::from(0x1234_5678_9ABCu64);
        let client_public = generator.modpow(&client_private, &modulus);

        let a = server_public.modpow(&client_private, &modulus);
        let b = client_public.modpow(&server_private, &modulus);
        assert_eq!(fixed_be(&a), fixed_be(&b));
    }

    #[tokio::test]
    async fn rejects_a_degenerate_group() {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(&[0u8; 8]).await.unwrap(); // generator 0
        server.write_all(&[0u8; 8]).await.unwrap(); // modulus 0
        server.write_all(&[0u8; 8]).await.unwrap();
        let mut o = ConnectOptions::new("h", 5900);
        o.credentials = crate::types::Credentials::user_pass("u", "p");
        let s: BoxedStream = Box::pin(client);
        assert!(matches!(
            handshake(s, &o, &CredentialSource::none()).await,
            Err(VncError::Protocol(_))
        ));
    }

    // Test-only inverse of `des_cbc_encrypt`.
    fn des_cbc_decrypt(buf: &[u8], secret: &[u8; 8]) -> Vec<u8> {
        use cipher::BlockDecrypt;
        let mut key = [0u8; 8];
        for (dst, src) in key.iter_mut().zip(secret.iter()) {
            *dst = super::super::vnc_auth::mirror_byte(*src);
        }
        let cipher = Des::new_from_slice(&key).unwrap();
        let mut prev = *secret;
        let mut out = Vec::with_capacity(buf.len());
        for chunk in buf.chunks_exact(8) {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            let saved = block;
            cipher.decrypt_block(block.as_mut_slice().into());
            for (b, p) in block.iter_mut().zip(prev.iter()) {
                *b ^= *p;
            }
            out.extend_from_slice(&block);
            prev = saved;
        }
        out
    }
}
