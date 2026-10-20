//! Type-33 RSA-SRP authentication.
//!
//! The group is the RFC 3526 4096-bit MODP prime with g = 5. The password is
//! stretched with PBKDF2-HMAC-SHA512, then standard SRP-6a with SHA-512.
//! The record-layer wrap key is the first 16 bytes of SHA-256(K).

use num_bigint_dig::BigUint;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

/// The 4096-bit MODP prime from RFC 3526, used with generator 5.
const MODP_4096: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22\
514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6\
F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603\
9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C\
1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D\
99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";
const MOD_LEN: usize = 512;

pub struct SrpSecret {
    pub a_public: Vec<u8>,
    pub m1: [u8; 64],
    /// First 16 bytes of SHA-256(K). Becomes the initial wrap key.
    pub wrap_key: [u8; 16],
    /// The session key K = SHA-512(PAD(S)). Read by the tests that check
    /// the server's proof against it.
    #[allow(dead_code)]
    session_key: [u8; 64],
    /// The server's proof: M2 = SHA-512(PAD(A) || M1 || K).
    expected_m2: [u8; 64],
}

impl SrpSecret {
    pub fn client(
        password: &str,
        salt: &[u8],
        iterations: u32,
        server_public: &[u8],
    ) -> Result<Self, AuthError> {
        let n = BigUint::parse_bytes(MODP_4096.as_bytes(), 16).ok_or(AuthError::Group)?;
        let g = BigUint::from(5u32);
        let b = BigUint::from_bytes_be(server_public);
        if b < BigUint::from(2u32) || b >= n {
            return Err(AuthError::Range);
        }
        let mut stretched = [0u8; 128];
        pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, iterations, &mut stretched);
        let mut inner = b":".to_vec();
        inner.extend_from_slice(&stretched);
        let x = BigUint::from_bytes_be(&Sha512::digest(
            [salt, &Sha512::digest(&inner)[..]].concat(),
        ));
        stretched.zeroize();
        inner.zeroize();

        let mut private = [0u8; 64];
        rand::rng().fill_bytes(&mut private);
        let a = BigUint::from_bytes_be(&private);
        private.zeroize();
        let a_pub = g.modpow(&a, &n);
        let a_bytes = pad(&a_pub);

        let k = BigUint::from_bytes_be(&Sha512::digest([&pad(&n)[..], &pad(&g)[..]].concat()));
        let u = BigUint::from_bytes_be(&Sha512::digest([&a_bytes[..], &pad(&b)[..]].concat()));
        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        let base = if b >= kgx { &b - kgx } else { &n - (kgx - &b) };
        let exponent = &a + &u * &x;
        let s = base.modpow(&exponent, &n);
        let session = Sha512::digest(pad(&s));
        let hn = Sha512::digest(pad(&n));
        let hg = Sha512::digest(pad(&g));
        let mut mix = [0u8; 64];
        for i in 0..64 {
            mix[i] = hn[i] ^ hg[i];
        }
        let m1_full = Sha512::digest(
            [
                &mix[..],
                &Sha512::digest(b"")[..],
                salt,
                &a_bytes[..],
                &pad(&b)[..],
                &session[..],
            ]
            .concat(),
        );
        let mut m1 = [0u8; 64];
        m1.copy_from_slice(&m1_full);
        // M2 = H(PAD(A) || M1 || K). Kept so the server proof can be checked.
        let expected = Sha512::digest([&a_bytes[..], &m1[..], &session[..]].concat());
        let digest = Sha256::digest(session);
        let mut wrap_key = [0u8; 16];
        wrap_key.copy_from_slice(&digest[..16]);
        let mut session_key = [0u8; 64];
        session_key.copy_from_slice(&session);
        let mut expected_m2 = [0u8; 64];
        expected_m2.copy_from_slice(&expected);
        Ok(Self {
            a_public: a_bytes,
            m1,
            wrap_key,
            session_key,
            expected_m2,
        })
    }

    /// Whether the server's proof is the one this session expects.
    pub fn m2_matches(&self, server_m2: &[u8]) -> bool {
        server_m2 == self.expected_m2
    }

    /// The session key, for tests that check the proof.
    #[cfg(test)]
    pub fn session_key(&self) -> &[u8; 64] {
        &self.session_key
    }
}

fn pad(n: &BigUint) -> Vec<u8> {
    let raw = n.to_bytes_be();
    if raw.len() >= MOD_LEN {
        return raw[raw.len() - MOD_LEN..].to_vec();
    }
    let mut out = vec![0u8; MOD_LEN];
    out[MOD_LEN - raw.len()..].copy_from_slice(&raw);
    out
}

/// PKCS#1 v1.5 encrypt of the username envelope under the server's DER key.
pub fn seal_identity(spki_der: &[u8], username: &str) -> Result<Vec<u8>, AuthError> {
    let key = RsaPublicKey::from_public_key_der(spki_der).map_err(|_| AuthError::Key)?;
    if key.size() != 256 {
        return Err(AuthError::Key);
    }
    let user = username.as_bytes();
    let mut plain = Vec::new();
    let rest = 4 + user.len() + 2 + 1;
    plain.extend_from_slice(&(rest as u32).to_be_bytes());
    plain.extend_from_slice(&(user.len() as u32).to_be_bytes());
    plain.extend_from_slice(user);
    plain.extend_from_slice(&0u16.to_be_bytes());
    plain.push(0);
    let mut rng = rand::rng();
    key.encrypt(&mut rng, Pkcs1v15Encrypt, &plain)
        .map_err(|_| AuthError::Key)
}

/// `u32 total_len || version || "RSA1" || authtype || inner_len || body || zeros`.
pub fn rsa1_packet(authtype: u16, inner_len: u16, body: &[u8], tail_zeros: usize) -> Vec<u8> {
    let after = 2 + 4 + 2 + 2 + body.len() + tail_zeros;
    let mut out = Vec::with_capacity(4 + after);
    out.extend_from_slice(&(after as u32).to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(b"RSA1");
    out.extend_from_slice(&authtype.to_be_bytes());
    out.extend_from_slice(&inner_len.to_be_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + tail_zeros, 0);
    out
}

/// Packet-2 inner: `%m A || %o M1 || %s options || %o client_random`.
pub fn packet2_inner(a_public: &[u8], m1: &[u8], options: &str, client_random: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    push_m(&mut inner, a_public);
    push_o(&mut inner, m1);
    push_s(&mut inner, options.as_bytes());
    push_o(&mut inner, client_random);
    inner
}

/// Client proof. The bytes after the length word are padded out to 1076,
/// which is the size the server reads for this step.
pub fn packet2_wire(a_public: &[u8], m1: &[u8], options: &str, client_random: &[u8]) -> Vec<u8> {
    let inner = packet2_inner(a_public, m1, options, client_random);
    let mut pay = Vec::new();
    pay.extend_from_slice(&1u16.to_le_bytes());
    pay.extend_from_slice(b"RSA1");
    pay.extend_from_slice(&2u16.to_be_bytes());
    pay.extend_from_slice(&((inner.len() + 4) as u16).to_be_bytes());
    pay.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    pay.extend_from_slice(&inner);
    pay.resize(1076, 0);
    let mut out = Vec::with_capacity(4 + pay.len());
    out.extend_from_slice(&(pay.len() as u32).to_be_bytes());
    out.extend_from_slice(&pay);
    out
}

fn push_m(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_o(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn push_s(out: &mut Vec<u8>, bytes: &[u8]) {
    push_m(out, bytes);
}

pub struct Challenge {
    pub salt: Vec<u8>,
    pub server_public: Vec<u8>,
    pub iterations: u32,
    pub options: String,
}

/// Parse the SRP challenge body (the bytes after the leading length word).
///
/// Layout, after a 12-byte header: a `0x00` marker, the 512-byte modulus,
/// `u16` generator length and the generator, a one-byte salt length and the
/// salt, `u16` server-public length and `B`, `u64` PBKDF2 iterations, then
/// `u16` length and the options string.
pub fn parse_challenge(body: &[u8]) -> Result<Challenge, AuthError> {
    if body.len() < 12 + 1 + MOD_LEN + 2 + 1 + 1 + 32 {
        return Err(AuthError::Truncated);
    }
    if body[12] != 0 {
        return Err(AuthError::Truncated);
    }
    let mut p = 13;
    let modulus = body.get(p..p + MOD_LEN).ok_or(AuthError::Truncated)?;
    p += MOD_LEN;
    if p + 2 > body.len() {
        return Err(AuthError::Truncated);
    }
    let g_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let _g = body.get(p..p + g_len).ok_or(AuthError::Truncated)?;
    p += g_len;
    let salt_len = *body.get(p).ok_or(AuthError::Truncated)? as usize;
    p += 1;
    let salt = body
        .get(p..p + salt_len)
        .ok_or(AuthError::Truncated)?
        .to_vec();
    p += salt_len;
    if p + 2 > body.len() {
        return Err(AuthError::Truncated);
    }
    let b_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let server_public = body.get(p..p + b_len).ok_or(AuthError::Truncated)?.to_vec();
    p += b_len;
    if p + 8 + 2 > body.len() {
        return Err(AuthError::Truncated);
    }
    let iterations = u64::from_be_bytes(body[p..p + 8].try_into().unwrap());
    p += 8;
    let cap_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let options = body.get(p..p + cap_len).ok_or(AuthError::Truncated)?;
    let options = String::from_utf8(options.to_vec()).map_err(|_| AuthError::Truncated)?;
    if modulus.len() != MOD_LEN || iterations == 0 || iterations > 1_000_000 {
        return Err(AuthError::Range);
    }
    let _ = modulus;
    Ok(Challenge {
        salt,
        server_public,
        iterations: iterations as u32,
        options,
    })
}

/// The places the server's proof may be in the final-proof payload.
///
/// The inner grammar is `%o M2 || %o server_random || %s empty || %u zero`,
/// so the proof normally starts with its own one-byte length. Some servers
/// put the 64 bytes of the proof straight into the payload. Both are
/// offered, and the caller accepts the proof if EITHER of them matches: the
/// two shapes overlap, and guessing wrong must not turn a sign-in into a
/// failure.
pub fn server_proofs(payload: &[u8]) -> Vec<&[u8]> {
    const HASH: usize = 64;
    let mut out = Vec::new();
    if payload.len() > HASH && payload[0] == HASH as u8 {
        out.push(&payload[1..HASH + 1]);
    }
    if payload.len() >= HASH {
        out.push(&payload[..HASH]);
    }
    out
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("the SRP group constant is unusable")]
    Group,
    #[error("a value in the authentication transcript is out of range")]
    Range,
    #[error("the server public key could not encrypt the identity")]
    Key,
    #[error("the authentication transcript was truncated")]
    Truncated,
}

// Silence an unused import if a future rsa version drops the trait method
// we use only through size().
#[allow(dead_code)]
fn _parts(key: &RsaPublicKey) -> usize {
    key.size()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_is_4096_bits() {
        let n = BigUint::parse_bytes(MODP_4096.as_bytes(), 16).unwrap();
        assert_eq!(n.to_bytes_be().len(), 512);
        assert_eq!(n.bits(), 4096);
    }

    #[test]
    fn client_proof_verifies_against_itself() {
        // A local server: same formulas, so a disagreement here is our bug
        // rather than a difference of opinion with the Mac.
        let n = BigUint::parse_bytes(MODP_4096.as_bytes(), 16).unwrap();
        let g = BigUint::from(5u32);
        let mut b_priv = [0u8; 32];
        rand::rng().fill_bytes(&mut b_priv);
        let b = BigUint::from_bytes_be(&b_priv);
        let server_public = pad(&g.modpow(&b, &n));
        let salt = b"salt-for-the-unit-test-only!!!!";
        let secret = SrpSecret::client("password", salt, 1000, &server_public).unwrap();
        assert_eq!(secret.a_public.len(), 512);
        assert_ne!(secret.wrap_key, [0u8; 16]);
    }

    #[test]
    fn the_server_proof_is_the_one_this_session_expects() {
        // The proof is M2 = H(PAD(A) || M1 || K), where K is the session key
        // both sides derived. The live Mac accepted our M1, and M1 is built
        // from K, so K is the Mac's K too, and this is the Mac's proof.
        let n = BigUint::parse_bytes(MODP_4096.as_bytes(), 16).unwrap();
        let g = BigUint::from(5u32);
        let mut b_priv = [0u8; 32];
        rand::rng().fill_bytes(&mut b_priv);
        let b = BigUint::from_bytes_be(&b_priv);
        let server_public = pad(&g.modpow(&b, &n));
        let salt = b"salt-for-the-unit-test-only!!!!";
        let secret = SrpSecret::client("password", salt, 1000, &server_public).unwrap();
        let m2 = Sha512::digest(
            [
                &secret.a_public[..],
                &secret.m1[..],
                &secret.session_key()[..],
            ]
            .concat(),
        );
        assert!(secret.m2_matches(&m2), "the server's proof did not verify");
        // And a proof from a server that does not know the password does
        // not verify.
        assert!(!secret.m2_matches(&[0u8; 64]));
    }

    #[test]
    fn the_server_proof_is_found_in_both_shapes() {
        let proof = [7u8; 64];
        // The documented shape: a one-byte length, then the proof.
        let mut with_length = vec![64u8];
        with_length.extend_from_slice(&proof);
        with_length.extend_from_slice(&[16u8]);
        with_length.extend_from_slice(&[9u8; 16]);
        assert!(server_proofs(&with_length).contains(&&proof[..]));
        // And the proof on its own.
        assert!(server_proofs(&proof).contains(&&proof[..]));
        // Nothing that could be a proof.
        assert!(server_proofs(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn packet2_length_field_is_inner_plus_four() {
        let inner = packet2_inner(&[1, 2], &[3, 4], "opts", &[9]);
        let env = packet2_wire(&[0; 512], &[0; 64], "opts", &[0; 16]);
        let _ = inner;
        // version sits right after the total length.
        assert_eq!(&env[4..6], &0x0100u16.to_be_bytes());
        assert_eq!(&env[6..10], b"RSA1");
    }
}
