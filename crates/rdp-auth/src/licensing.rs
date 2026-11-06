//! The cryptography of the client licensing exchange (MS-RDPELE 5.1).
//!
//! An RD Session Host with a licence server will not let a client through
//! without a client access licence, and the exchange that obtains one is
//! encrypted end to end: the client picks a premaster secret, encrypts it
//! under the licence server's RSA key, and both sides derive an RC4 key and a
//! MAC salt from it and the two randoms. Everything after the client's first
//! message (the platform challenge, the hardware id, the licence itself) is
//! RC4 under that key with an MD5 and SHA-1 MAC.
//!
//! This module owns the order of the calls and nothing else, under the same
//! rule as the rest of the crate (PRDRDP/00 R54): RC4 is `rc4`, the hashes
//! are `md-5` and `sha1`, the modular exponentiation is `num-bigint-dig`, the
//! randoms are `rand::rng()`. The message layouts are `rdp-pdu`'s, and which
//! message to send is `rdp-core`'s.
//!
//! # Why the RSA here is "raw"
//!
//! MS-RDPELE 5.1.1.1 encrypts the premaster secret the way MS-RDPBCGR 5.3.4.1
//! encrypts the client random: the little endian integer raised to the public
//! exponent modulo the modulus, with no padding scheme at all, written back
//! little endian and followed by eight zero bytes. That is not PKCS #1 and no
//! RSA library offers it as an encryption mode, so the one operation is a
//! `BigUint::modpow`, which is the library doing the arithmetic.
//!
//! # What these keys protect
//!
//! Little. The exchange runs inside TLS or CredSSP on every connection this
//! client makes, and its keys exist so that a licence server can tell a
//! client that knows the premaster secret from one that does not. The
//! premaster secret is still zeroized on drop, as every secret in this crate
//! is, because a rule with exceptions is a rule nobody can audit.

use md5::{Digest, Md5};
use num_bigint_dig::BigUint;
use rand::Rng;
use rc4::{consts::U16, KeyInit, Rc4, StreamCipher};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// `PremasterSecret` (MS-RDPELE 5.1.1).
pub const PREMASTER_SECRET_LEN: usize = 48;

/// `ClientRandom` and `ServerRandom` (MS-RDPELE 5.1.1).
pub const RANDOM_LEN: usize = 32;

/// Every `MACData` in MS-RDPELE.
pub const MAC_LEN: usize = 16;

/// The eight zero bytes MS-RDPELE 2.2.2.3 appends to the encrypted
/// premaster secret, which the server requires and does not explain.
pub const RSA_PADDING_LEN: usize = 8;

/// `pad1` and `pad2` of MS-RDPELE 5.1.5, the same constants as MS-RDPBCGR
/// 5.3.6.1.
const PAD1: [u8; 40] = [0x36; 40];
const PAD2: [u8; 48] = [0x5c; 48];

/// What can go wrong in the licensing cryptography.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LicensingError {
    /// The server's public key cannot encrypt anything: a zero or empty
    /// modulus, a modulus no larger than the secret, or an empty exponent.
    #[error("the licence server's public key is not usable")]
    UnusableKey,
    /// A `MACData` from the server did not match what its plaintext hashes
    /// to, so either the keys disagree or the message was altered.
    #[error("a licensing message failed its integrity check")]
    MacMismatch,
}

/// The client's half of the secrets: `ClientRandom` and `PremasterSecret`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientSecrets {
    client_random: [u8; RANDOM_LEN],
    premaster_secret: [u8; PREMASTER_SECRET_LEN],
}

impl ClientSecrets {
    /// Fresh ones from `rand::rng()`, which is the only place a secret in
    /// this crate comes from (PRDRDP/14 §2.10).
    #[must_use]
    pub fn generate() -> Self {
        let mut out = Self {
            client_random: [0; RANDOM_LEN],
            premaster_secret: [0; PREMASTER_SECRET_LEN],
        };
        let mut rng = rand::rng();
        rng.fill_bytes(&mut out.client_random);
        rng.fill_bytes(&mut out.premaster_secret);
        out
    }

    /// Fixed values, for the specification's examples and for tests.
    #[must_use]
    pub const fn from_parts(
        client_random: [u8; RANDOM_LEN],
        premaster_secret: [u8; PREMASTER_SECRET_LEN],
    ) -> Self {
        Self {
            client_random,
            premaster_secret,
        }
    }

    /// `ClientRandom`, which travels in the clear.
    #[must_use]
    pub const fn client_random(&self) -> &[u8; RANDOM_LEN] {
        &self.client_random
    }

    /// `EncryptedPreMasterSecret`: the premaster secret under the server's
    /// key, little endian, padded with [`RSA_PADDING_LEN`] zero bytes.
    ///
    /// # Errors
    ///
    /// [`LicensingError::UnusableKey`] for a key that cannot hold the secret.
    pub fn encrypted_premaster_secret(
        &self,
        key: &LicensingPublicKey,
    ) -> Result<Vec<u8>, LicensingError> {
        key.encrypt(&self.premaster_secret)
    }

    /// The keys both sides derive (MS-RDPELE 5.1.2).
    #[must_use]
    pub fn derive_keys(&self, server_random: &[u8; RANDOM_LEN]) -> LicensingKeys {
        LicensingKeys::derive(&self.premaster_secret, &self.client_random, server_random)
    }
}

impl std::fmt::Debug for ClientSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSecrets").finish_non_exhaustive()
    }
}

/// The licence server's RSA public key, both halves little endian as
/// MS-RDPBCGR 2.2.1.4.3.1.1.1 stores them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicensingPublicKey {
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl LicensingPublicKey {
    /// A key from its little endian modulus and exponent. Trailing zero
    /// bytes of the modulus (the proprietary certificate pads it by eight)
    /// do not count towards its length.
    ///
    /// # Errors
    ///
    /// [`LicensingError::UnusableKey`] for an empty or zero modulus or
    /// exponent, or a modulus too short to hold a premaster secret.
    pub fn from_le(modulus: &[u8], exponent: &[u8]) -> Result<Self, LicensingError> {
        let trim = |b: &[u8]| {
            let end = b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
            b[..end].to_vec()
        };
        let modulus = trim(modulus);
        let exponent = trim(exponent);
        if modulus.len() <= PREMASTER_SECRET_LEN || exponent.is_empty() {
            return Err(LicensingError::UnusableKey);
        }
        Ok(Self { modulus, exponent })
    }

    /// The same, from the big endian integers of an X.509 `RSAPublicKey`
    /// (RFC 8017 A.1.1), which is what a Windows licence server's
    /// certificate chain carries.
    ///
    /// # Errors
    ///
    /// As [`Self::from_le`].
    pub fn from_be(modulus: &[u8], exponent: &[u8]) -> Result<Self, LicensingError> {
        let rev = |b: &[u8]| b.iter().rev().copied().collect::<Vec<u8>>();
        Self::from_le(&rev(modulus), &rev(exponent))
    }

    /// The modulus length in bytes, which is also the RSA output length.
    #[must_use]
    pub fn modulus_len(&self) -> usize {
        self.modulus.len()
    }

    /// Raw RSA, little endian in and out, then the padding.
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, LicensingError> {
        let n = BigUint::from_bytes_le(&self.modulus);
        let e = BigUint::from_bytes_le(&self.exponent);
        let m = BigUint::from_bytes_le(input);
        if m >= n {
            return Err(LicensingError::UnusableKey);
        }
        let c = m.modpow(&e, &n).to_bytes_le();
        let mut out = vec![0u8; self.modulus.len() + RSA_PADDING_LEN];
        out[..c.len()].copy_from_slice(&c);
        Ok(out)
    }
}

/// `MAC-salt-key` and `LicensingEncryptionKey` (MS-RDPELE 5.1.2).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LicensingKeys {
    mac_salt_key: [u8; 16],
    encryption_key: [u8; 16],
}

impl std::fmt::Debug for LicensingKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicensingKeys").finish_non_exhaustive()
    }
}

/// `SaltedHash(S, I) = MD5(S + SHA-1(I + S + A + B))`, where MS-RDPELE 5.1.2
/// takes `A, B` as `ClientRandom, ServerRandom` for the master secret and the
/// other way round for the session key blob.
fn salted_hash(salt: &[u8], input: &[u8], a: &[u8], b: &[u8]) -> [u8; 16] {
    let inner = Sha1::new()
        .chain_update(input)
        .chain_update(salt)
        .chain_update(a)
        .chain_update(b)
        .finalize();
    Md5::new()
        .chain_update(salt)
        .chain_update(inner)
        .finalize()
        .into()
}

/// `X('A') + X('BB') + X('CCC')`, the 48 byte construction both secrets use.
fn triple(salt: &[u8], a: &[u8], b: &[u8]) -> Zeroizing<[u8; 48]> {
    let mut out = Zeroizing::new([0u8; 48]);
    for (i, label) in [&b"A"[..], b"BB", b"CCC"].into_iter().enumerate() {
        out[i * 16..(i + 1) * 16].copy_from_slice(&salted_hash(salt, label, a, b));
    }
    out
}

impl LicensingKeys {
    /// MS-RDPELE 5.1.2, in the order it is written.
    #[must_use]
    pub fn derive(
        premaster_secret: &[u8; PREMASTER_SECRET_LEN],
        client_random: &[u8; RANDOM_LEN],
        server_random: &[u8; RANDOM_LEN],
    ) -> Self {
        let master_secret = triple(premaster_secret, client_random, server_random);
        let session_key_blob = triple(&master_secret[..], server_random, client_random);
        let mut mac_salt_key = [0u8; 16];
        mac_salt_key.copy_from_slice(&session_key_blob[..16]);
        let encryption_key: [u8; 16] = Md5::new()
            .chain_update(&session_key_blob[16..32])
            .chain_update(client_random)
            .chain_update(server_random)
            .finalize()
            .into();
        Self {
            mac_salt_key,
            encryption_key,
        }
    }

    /// RC4 under `LicensingEncryptionKey`, from a fresh key schedule every
    /// call: each encrypted blob of the exchange starts its own keystream
    /// (MS-RDPELE 5.1.3, 5.1.4). The same call decrypts.
    #[must_use]
    pub fn rc4(&self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        Rc4::<U16>::new((&self.encryption_key).into()).apply_keystream(&mut out);
        out
    }

    /// `MACData = MD5(MAC-salt-key + pad2 + SHA-1(MAC-salt-key + pad1 +
    /// length + data))` (MS-RDPELE 5.1.5).
    #[must_use]
    pub fn mac(&self, data: &[u8]) -> [u8; MAC_LEN] {
        // `data` is a licensing blob, which `wBlobLen` bounds at 65535.
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let inner = Sha1::new()
            .chain_update(self.mac_salt_key)
            .chain_update(PAD1)
            .chain_update(len.to_le_bytes())
            .chain_update(data)
            .finalize();
        Md5::new()
            .chain_update(self.mac_salt_key)
            .chain_update(PAD2)
            .chain_update(inner)
            .finalize()
            .into()
    }

    /// Decrypt a server blob and check its MAC, in constant time.
    ///
    /// # Errors
    ///
    /// [`LicensingError::MacMismatch`] when the MAC is not the plaintext's.
    pub fn decrypt_verified(
        &self,
        ciphertext: &[u8],
        mac: &[u8; MAC_LEN],
    ) -> Result<Zeroizing<Vec<u8>>, LicensingError> {
        let plain = Zeroizing::new(self.rc4(ciphertext));
        if bool::from(self.mac(&plain).ct_eq(mac)) {
            Ok(plain)
        } else {
            Err(LicensingError::MacMismatch)
        }
    }
}

/// Sixteen random bytes for the `Data1` to `Data4` of a `CLIENT_HARDWARE_ID`
/// (MS-RDPELE 2.2.2.3.1), generated once and stored by the caller: a licence
/// is bound to the hardware id it was issued against, so a new one every
/// connection would need a new licence every connection.
#[must_use]
pub fn random_hardware_id() -> [u8; 16] {
    let mut out = [0u8; 16];
    rand::rng().fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use num_bigint_dig::ModInverse;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        let v = hex::decode(s).unwrap();
        v.try_into().unwrap()
    }

    /// `ServerRandom` of MS-RDPELE 4.1, `ClientRandom` and the decrypted
    /// premaster secret of 4.2 (revision 18.0).
    fn spec_inputs() -> ([u8; 48], [u8; 32], [u8; 32]) {
        (
            h(
                "cf7adbcbfb0e1523871c8481ba9d4e15bbd256bdd8f7f316cc353be1934278dd\
               929ae47ae299d473b1aa6f55943bc9bc",
            ),
            h("dc73a0c869256b18af0b947aa9a520af8bbc0dcca395b7b9eb815dbe0a109cd8"),
            h("84efae20b1d59e36491ae82e0a9989ac49a6474f339b5ab99503a6c6c23c3f61"),
        )
    }

    /// The keys MS-RDPELE 5.1.2 gives for the 4.1 and 4.2 inputs. The
    /// specification prints the formulas and not the results, so these were
    /// computed from the formulas by a separate script written from the
    /// specification text alone (Python `hashlib`), not by this code. The
    /// real check is a Windows licence server accepting the exchange.
    #[test]
    fn key_derivation_matches_the_specification_formulas() {
        let (pm, cr, sr) = spec_inputs();
        let keys = LicensingKeys::derive(&pm, &cr, &sr);
        assert_eq!(
            hex::encode(keys.mac_salt_key),
            "74cca2098e38f01d3eddf0b495c56968"
        );
        assert_eq!(
            hex::encode(keys.encryption_key),
            "6e1891432db6e14ce25985fba5c6f36d"
        );
    }

    /// The order of the randoms matters, and a swap is the mistake that would
    /// still produce sixteen plausible bytes.
    #[test]
    fn swapping_the_randoms_changes_both_keys() {
        let (pm, cr, sr) = spec_inputs();
        let a = LicensingKeys::derive(&pm, &cr, &sr);
        let b = LicensingKeys::derive(&pm, &sr, &cr);
        assert_ne!(a.mac_salt_key, b.mac_salt_key);
        assert_ne!(a.encryption_key, b.encryption_key);
    }

    /// RC4 restarts its keystream on every call, so encrypting twice gives
    /// the same bytes and the call is its own inverse. MS-RDPELE 4.5 shows
    /// the restart on the wire: the response data and the hardware id both
    /// start with a zero byte and both encrypt it to `0xfa`.
    #[test]
    fn rc4_restarts_per_blob_and_is_its_own_inverse() {
        let (pm, cr, sr) = spec_inputs();
        let keys = LicensingKeys::derive(&pm, &cr, &sr);
        let plain = b"T\0E\0S\0T\0\0\0";
        let once = keys.rc4(plain);
        assert_eq!(keys.rc4(plain), once);
        assert_eq!(keys.rc4(&once), plain);
        assert_ne!(&once[..], &plain[..]);
    }

    #[test]
    fn a_tampered_blob_fails_its_mac() {
        let (pm, cr, sr) = spec_inputs();
        let keys = LicensingKeys::derive(&pm, &cr, &sr);
        let plain = b"a licence";
        let mac = keys.mac(plain);
        let mut sealed = keys.rc4(plain);
        assert_eq!(&keys.decrypt_verified(&sealed, &mac).unwrap()[..], plain);
        sealed[0] ^= 1;
        assert_eq!(
            keys.decrypt_verified(&sealed, &mac),
            Err(LicensingError::MacMismatch)
        );
    }

    /// The MAC covers the length as well as the bytes: the same content
    /// with a different length prefix must not collide.
    #[test]
    fn the_mac_depends_on_the_data_and_the_salt() {
        let (pm, cr, sr) = spec_inputs();
        let keys = LicensingKeys::derive(&pm, &cr, &sr);
        assert_ne!(keys.mac(b"abc"), keys.mac(b"abd"));
        assert_ne!(keys.mac(b""), keys.mac(b"\0"));
        let other = LicensingKeys::derive(&pm, &sr, &cr);
        assert_ne!(keys.mac(b"abc"), other.mac(b"abc"));
    }

    /// A 512 bit key whose private exponent the test knows: encrypting little
    /// endian and decrypting with the private exponent gives the secret back,
    /// and the output is the modulus length plus eight zero bytes.
    #[test]
    fn raw_rsa_round_trips_little_endian_and_pads_by_eight() {
        // p and q are the two 256 bit primes 2^256 - 189 and 2^256 - 357.
        let one = BigUint::from(1u32);
        let p = (BigUint::from(1u32) << 256) - BigUint::from(189u32);
        let q = (BigUint::from(1u32) << 256) - BigUint::from(357u32);
        let n = &p * &q;
        let e = BigUint::from(65537u32);
        let phi = (&p - &one) * (&q - &one);
        let d = e.clone().mod_inverse(&phi).unwrap().to_biguint().unwrap();

        let key = LicensingPublicKey::from_le(&n.to_bytes_le(), &e.to_bytes_le()).unwrap();
        assert_eq!(key.modulus_len(), 64);
        let (pm, cr, _) = spec_inputs();
        let secrets = ClientSecrets::from_parts(cr, pm);
        let sealed = secrets.encrypted_premaster_secret(&key).unwrap();
        assert_eq!(sealed.len(), 64 + RSA_PADDING_LEN);
        assert_eq!(&sealed[64..], &[0u8; RSA_PADDING_LEN]);
        let back = BigUint::from_bytes_le(&sealed[..64]).modpow(&d, &n);
        let mut back = back.to_bytes_le();
        back.resize(PREMASTER_SECRET_LEN, 0);
        assert_eq!(back, pm);
    }

    /// The big endian constructor is the little endian one reversed, and a
    /// leading zero (DER's sign byte) does not count towards the length.
    #[test]
    fn a_der_modulus_with_its_sign_byte_has_the_right_length() {
        let mut be = vec![0x00];
        be.extend(std::iter::repeat_n(0xc1, 256));
        let key = LicensingPublicKey::from_be(&be, &[0x01, 0x00, 0x01]).unwrap();
        assert_eq!(key.modulus_len(), 256);
        assert_eq!(key.exponent, vec![0x01, 0x00, 0x01]);
    }

    #[test]
    fn a_key_too_small_for_the_secret_is_refused() {
        assert_eq!(
            LicensingPublicKey::from_le(&[0xff; 48], &[3]),
            Err(LicensingError::UnusableKey)
        );
        assert_eq!(
            LicensingPublicKey::from_le(&[0xff; 64], &[0, 0]),
            Err(LicensingError::UnusableKey)
        );
    }

    #[test]
    fn debug_output_hides_the_secrets() {
        let (pm, cr, sr) = spec_inputs();
        let secrets = ClientSecrets::from_parts(cr, pm);
        let keys = secrets.derive_keys(&sr);
        assert!(!format!("{secrets:?}").contains("cf"));
        assert_eq!(format!("{keys:?}"), "LicensingKeys { .. }");
    }
}
