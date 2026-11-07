//! Security types 33 and 36: macOS Screen Sharing's SRP logins.
//!
//! Both run SRP-6a over the 4096-bit group of RFC 5054 appendix A (generator
//! 5) with SHA-512, and the password is first stretched with
//! PBKDF2-HMAC-SHA512 using a salt and an iteration count the server keeps
//! per account. The two types differ only in how the first two client
//! messages travel:
//!
//! * Type 33 wraps them in an `RSA1` envelope. The first one, which names
//!   the account, is RSA encrypted to the Mac's 2048-bit host key, so the
//!   user name never crosses the wire in clear. The host key is fetched with
//!   an `RSA1` request of its own and pinned trust on first use.
//! * Type 36 sends the same records in clear and has no host key.
//!
//! ```text
//! type 33                                 type 36
//! C->S RSA1(authtype 0)  key request      -
//! S->C u32 len, u32le 0x100, u16 n, SPKI, u8 0
//! C->S RSA1(authtype 2) RSA(identity)     C->S identity
//! S->C frame(challenge)                   S->C frame(challenge)
//! C->S RSA1(authtype 2) proof             C->S proof
//! S->C frame(server proof)                S->C frame(server proof)
//! S->C u32 SecurityResult                 S->C u32 SecurityResult
//! ```
//!
//! After a successful login the first 16 bytes of `SHA-256(K)` are the key
//! that unwraps the server's first session rekey (see [`crate::apple`]).
//!
//! ## What is still unconfirmed
//!
//! The parts of this exchange that have not been checked against a real Mac
//! yet are named in the doc comment of each function that implements them,
//! and each has a test in `tests/apple_screen_sharing.rs` that pins the
//! assumption so a live run that disagrees points straight at it. The live
//! run is `tests/apple_live.rs`.

use num_bigint_dig::BigUint;
use rand::Rng;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use vnc_transport::{format_fingerprint, normalize_fingerprint, BoxedStream, TrustDecision};

use super::prompt::CredentialSource;
use super::{read_bytes_max, read_u32, read_u8, write_all, AuthOutcome, ServerIdentity};
use crate::error::{Result, VncError};
use crate::types::{ConnectOptions, CredentialKind, PinScheme};

/// Shown in the credential dialog. The same name the type 30 path uses, so a
/// Mac asks for its account the same way whichever login it negotiates.
pub const METHOD: &str = super::apple_dh::METHOD;

/// RFC 5054 appendix A, 4096-bit group (the same prime as RFC 3526 group 16).
pub const GROUP_4096_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33\
A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2\
08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8\
DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

/// The generator that goes with [`GROUP_4096_HEX`].
pub const GROUP_4096_G: u32 = 5;

/// Width of every padded group element on the wire.
pub const GROUP_BYTES: usize = 512;

/// PBKDF2 output length the server's verifier was made from.
pub const DERIVED_KEY_LEN: usize = 128;

/// Bytes of RSA ciphertext the identity packet carries for a 2048-bit key.
const RSA_BLOCK: usize = 256;

/// Zero bytes after the ciphertext in the identity packet, and the number of
/// trailing bytes after the proof, which mirrors it.
const RSA1_TRAILER: usize = 384;

/// The `RSA1` envelope's version word.
const RSA1_VERSION: u16 = 0x0100;

/// `RSA1` authtype for the host key request.
const AUTHTYPE_KEY_REQUEST: u16 = 0;
/// `RSA1` authtype for the two SRP packets.
const AUTHTYPE_SRP: u16 = 2;

/// Length of the random the client appends to its proof.
const CLIENT_RANDOM_LEN: usize = 16;

/// Above this a server is asking us to burn CPU, not log in. macOS uses tens
/// of thousands; ten million is several seconds of SHA-512.
const MAX_ITERATIONS: u64 = 10_000_000;

/// No legitimate SRP message from the server is anywhere near this.
const MAX_FRAME: usize = 16 * 1024;

/// Longest user name that still fits a PKCS#1 v1.5 block of a 2048-bit key
/// next to the seven bytes of framing the identity record adds.
const MAX_USER_LEN: usize = RSA_BLOCK - 11 - 11;

// ---------------------------------------------------------------------------
// SRP-6a
// ---------------------------------------------------------------------------

/// An SRP group: the prime, the generator and the width elements are padded to.
#[derive(Clone)]
pub struct SrpGroup {
    pub n: BigUint,
    pub g: BigUint,
    pub len: usize,
}

impl SrpGroup {
    pub fn from_hex(n_hex: &str, g: u32) -> Self {
        let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).expect("group prime is valid hex");
        let len = n.to_bytes_be().len();
        Self {
            n,
            g: BigUint::from(g),
            len,
        }
    }

    /// The group macOS uses for both SRP types.
    pub fn apple() -> Self {
        Self::from_hex(GROUP_4096_HEX, GROUP_4096_G)
    }

    /// Left pad a value to the group width.
    pub fn pad(&self, v: &BigUint) -> Vec<u8> {
        left_pad(&v.to_bytes_be(), self.len)
    }
}

pub fn left_pad(bytes: &[u8], width: usize) -> Vec<u8> {
    if bytes.len() >= width {
        return bytes[bytes.len() - width..].to_vec();
    }
    let mut out = vec![0u8; width];
    out[width - bytes.len()..].copy_from_slice(bytes);
    out
}

fn hash<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = D::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// `k = H(PAD(N) || PAD(g))`.
pub fn srp_k<D: Digest>(group: &SrpGroup) -> BigUint {
    BigUint::from_bytes_be(&hash::<D>(&[&group.pad(&group.n), &group.pad(&group.g)]))
}

/// `x = H(salt || H(identity || ":" || password))`.
///
/// macOS leaves the identity empty and passes the PBKDF2 output as the
/// password. That form is an assumption a live login has to confirm: a wrong
/// `x` shows up as the server rejecting a correct password.
pub fn srp_x<D: Digest>(salt: &[u8], identity: &[u8], password: &[u8]) -> BigUint {
    let inner = hash::<D>(&[identity, b":", password]);
    BigUint::from_bytes_be(&hash::<D>(&[salt, &inner]))
}

/// `u = H(PAD(A) || PAD(B))`.
pub fn srp_u<D: Digest>(group: &SrpGroup, a_pub: &BigUint, b_pub: &BigUint) -> BigUint {
    BigUint::from_bytes_be(&hash::<D>(&[&group.pad(a_pub), &group.pad(b_pub)]))
}

/// The client's premaster secret, `S = (B - k * g^x) ^ (a + u * x) mod N`.
pub fn srp_client_premaster(
    group: &SrpGroup,
    k: &BigUint,
    x: &BigUint,
    a: &BigUint,
    u: &BigUint,
    b_pub: &BigUint,
) -> BigUint {
    let n = &group.n;
    let kgx = (k * group.g.modpow(x, n)) % n;
    // B - kg^x, kept non-negative by adding N first.
    let base = ((b_pub % n) + n - kgx) % n;
    let exp = a + u * x;
    base.modpow(&exp, n)
}

/// `K = H(PAD(S))`.
///
/// Whether the server hashes `S` padded or as its minimal bytes is one of the
/// open points; the two only differ when `S` has a leading zero byte, about
/// once in 256 logins, which is what a live test with many logins would see.
pub fn srp_session_key<D: Digest>(group: &SrpGroup, s: &BigUint) -> Vec<u8> {
    hash::<D>(&[&group.pad(s)])
}

/// `M1 = H((H(N) xor H(g)) || H(I) || salt || A || B || K)`, with `A` and `B`
/// as they travel on the wire (padded to the group width) and `g` hashed as
/// its minimal bytes.
pub fn srp_client_proof<D: Digest>(
    group: &SrpGroup,
    identity: &[u8],
    salt: &[u8],
    a_pub: &BigUint,
    b_pub: &BigUint,
    key: &[u8],
) -> Vec<u8> {
    let hn = hash::<D>(&[&group.n.to_bytes_be()]);
    let hg = hash::<D>(&[&group.g.to_bytes_be()]);
    let xor: Vec<u8> = hn.iter().zip(&hg).map(|(a, b)| a ^ b).collect();
    let hi = hash::<D>(&[identity]);
    hash::<D>(&[&xor, &hi, salt, &group.pad(a_pub), &group.pad(b_pub), key])
}

/// `M2 = H(PAD(A) || M1 || K)`.
pub fn srp_server_proof<D: Digest>(
    group: &SrpGroup,
    a_pub: &BigUint,
    m1: &[u8],
    key: &[u8],
) -> Vec<u8> {
    hash::<D>(&[&group.pad(a_pub), m1, key])
}

/// `PBKDF2-HMAC-SHA512(password, salt, iterations, 128 bytes)`.
pub fn derive_password(password: &[u8], salt: &[u8], iterations: u32) -> [u8; DERIVED_KEY_LEN] {
    let mut out = [0u8; DERIVED_KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut out);
    out
}

/// The 16-byte key that unwraps the first rekey after an SRP login.
pub fn initial_wrap_key(session_key: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(session_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Everything the client derives from one challenge.
pub struct ClientProof {
    /// `A`, padded to the group width.
    pub a_pub: Vec<u8>,
    pub m1: Vec<u8>,
    /// What the server's `M2` must equal.
    pub expected_m2: Vec<u8>,
    /// `K`.
    pub session_key: Vec<u8>,
}

impl Drop for ClientProof {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

/// Run the client half of SRP-6a for one challenge, with the private value
/// `a` supplied (tests use fixed values, the handshake a random one).
pub fn client_proof(
    group: &SrpGroup,
    challenge: &Challenge,
    derived_password: &[u8],
    a: &BigUint,
) -> Result<ClientProof> {
    let n = &group.n;
    let b_pub = BigUint::from_bytes_be(&challenge.b_pub);
    // A server value of 0 mod N would make the premaster secret predictable.
    if (&b_pub % n) == BigUint::from(0u32) {
        return Err(VncError::Protocol(
            "the Mac sent an SRP public value of zero".into(),
        ));
    }
    let a_pub = group.g.modpow(a, n);
    let k = srp_k::<Sha512>(group);
    let u = srp_u::<Sha512>(group, &a_pub, &b_pub);
    if u == BigUint::from(0u32) {
        return Err(VncError::Protocol("SRP scrambling value is zero".into()));
    }
    let x = srp_x::<Sha512>(&challenge.salt, b"", derived_password);
    let s = srp_client_premaster(group, &k, &x, a, &u, &b_pub);
    let session_key = srp_session_key::<Sha512>(group, &s);
    let m1 = srp_client_proof::<Sha512>(group, b"", &challenge.salt, &a_pub, &b_pub, &session_key);
    let expected_m2 = srp_server_proof::<Sha512>(group, &a_pub, &m1, &session_key);
    Ok(ClientProof {
        a_pub: group.pad(&a_pub),
        m1,
        expected_m2,
        session_key,
    })
}

// ---------------------------------------------------------------------------
// Wire records
// ---------------------------------------------------------------------------

/// The parsed SRP challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub control: u8,
    pub n: Vec<u8>,
    pub g: Vec<u8>,
    pub salt: Vec<u8>,
    pub b_pub: Vec<u8>,
    pub iterations: u64,
    /// Echoed back verbatim in the proof.
    pub options: Vec<u8>,
}

/// The parsed server proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerProof {
    pub m2: Vec<u8>,
    pub server_random: Vec<u8>,
}

/// A bounds-checked reader over one message body.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, pos: 0, what }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() - self.pos < n {
            return Err(VncError::Protocol(format!(
                "{} is truncated: wanted {n} more bytes at offset {}, have {}",
                self.what,
                self.pos,
                self.buf.len() - self.pos
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().expect("eight bytes")))
    }
    fn lv8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn lv16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

fn push_lv8(out: &mut Vec<u8>, v: &[u8]) -> Result<()> {
    let n = u8::try_from(v.len())
        .map_err(|_| VncError::Other(format!("SRP field of {} bytes is too long", v.len())))?;
    out.push(n);
    out.extend_from_slice(v);
    Ok(())
}

fn push_lv16(out: &mut Vec<u8>, v: &[u8]) -> Result<()> {
    let n = u16::try_from(v.len())
        .map_err(|_| VncError::Other(format!("SRP field of {} bytes is too long", v.len())))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(v);
    Ok(())
}

pub fn parse_challenge(payload: &[u8]) -> Result<Challenge> {
    let mut c = Cursor::new(payload, "SRP challenge");
    let control = c.u8()?;
    let n = c.lv16()?.to_vec();
    let g = c.lv16()?.to_vec();
    let salt = c.lv8()?.to_vec();
    let b_pub = c.lv16()?.to_vec();
    let iterations = c.u64()?;
    let options = c.lv16()?.to_vec();
    Ok(Challenge {
        control,
        n,
        g,
        salt,
        b_pub,
        iterations,
        options,
    })
}

pub fn parse_server_proof(payload: &[u8]) -> Result<ServerProof> {
    let mut c = Cursor::new(payload, "SRP server proof");
    let m2 = c.lv8()?.to_vec();
    // The random, an empty string and a zero word follow. Only M2 matters to
    // us, so a server that ends early after the random is not refused.
    let server_random = c.lv8().map(|r| r.to_vec()).unwrap_or_default();
    Ok(ServerProof { m2, server_random })
}

/// Check the group in a challenge is the one we expect. A server choosing its
/// own prime could choose a weak one, so anything else is refused.
pub fn check_group(group: &SrpGroup, challenge: &Challenge) -> Result<()> {
    let n = BigUint::from_bytes_be(&challenge.n);
    let g = BigUint::from_bytes_be(&challenge.g);
    if n != group.n || g != group.g {
        return Err(VncError::Protocol(format!(
            "the Mac offered an unexpected SRP group ({} byte prime, generator {:?}); \
             only the RFC 5054 4096-bit group is accepted",
            challenge.n.len(),
            challenge.g
        )));
    }
    if challenge.b_pub.len() > group.len {
        return Err(VncError::Protocol(
            "SRP public value is wider than the group".into(),
        ));
    }
    Ok(())
}

/// The identity record: `u32 rest_len, u32 user_len, user, u16 0, u8 0`.
pub fn identity_record(username: &str) -> Result<Vec<u8>> {
    let user = username.as_bytes();
    if user.len() > MAX_USER_LEN {
        return Err(VncError::CredentialsRequired(format!(
            "the user name is too long for macOS Screen Sharing ({MAX_USER_LEN} bytes max)"
        )));
    }
    let rest_len = 4 + user.len() + 3;
    let mut out = Vec::with_capacity(4 + rest_len);
    out.extend_from_slice(&(rest_len as u32).to_be_bytes());
    out.extend_from_slice(&(user.len() as u32).to_be_bytes());
    out.extend_from_slice(user);
    out.extend_from_slice(&[0, 0, 0]);
    Ok(out)
}

/// An `RSA1` envelope: `u32 total_len, u16 0x0100, "RSA1", u16 authtype,
/// u16 field, body`, where `total_len` counts everything after itself.
pub fn rsa1_envelope(authtype: u16, field: u16, body: &[u8]) -> Vec<u8> {
    let total = 2 + 4 + 2 + 2 + body.len();
    let mut out = Vec::with_capacity(4 + total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(&RSA1_VERSION.to_be_bytes());
    out.extend_from_slice(b"RSA1");
    out.extend_from_slice(&authtype.to_be_bytes());
    out.extend_from_slice(&field.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// The host key request.
///
/// UNCONFIRMED: no description of its body exists. This sends the envelope
/// with an empty body, right after the security type byte. If a Mac rejects
/// it, the native client's behaviour (it skips the request and uses a cached
/// key) is the next thing to capture.
pub fn key_request() -> Vec<u8> {
    rsa1_envelope(AUTHTYPE_KEY_REQUEST, 0, &[])
}

/// Type 33 packet 1: the RSA ciphertext of the identity record plus 384 zero
/// bytes, with `field` = 256.
pub fn identity_packet_33(ciphertext: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(ciphertext.len() + RSA1_TRAILER);
    body.extend_from_slice(ciphertext);
    body.resize(ciphertext.len() + RSA1_TRAILER, 0);
    rsa1_envelope(AUTHTYPE_SRP, ciphertext.len() as u16, &body)
}

/// `LV16(A) || LV8(M1) || LV16(options) || LV8(client_random)`.
pub fn proof_inner(
    a_pub: &[u8],
    m1: &[u8],
    options: &[u8],
    client_random: &[u8],
) -> Result<Vec<u8>> {
    let mut inner = Vec::with_capacity(2 + a_pub.len() + 1 + m1.len() + 2 + options.len() + 17);
    push_lv16(&mut inner, a_pub)?;
    push_lv8(&mut inner, m1)?;
    push_lv16(&mut inner, options)?;
    push_lv8(&mut inner, client_random)?;
    Ok(inner)
}

/// Type 33 packet 2: `RSA1(authtype 2, field = inner_len + 4)` carrying
/// `u16 0, u16 inner_len, inner` and then 384 trailing bytes.
///
/// UNCONFIRMED: whether the trailing bytes are needed. A capture shows 384
/// non-zero bytes there; random bytes are sent to match it.
pub fn proof_packet_33(inner: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + inner.len() + RSA1_TRAILER);
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    body.extend_from_slice(inner);
    let start = body.len();
    body.resize(start + RSA1_TRAILER, 0);
    rand::rng().fill_bytes(&mut body[start..]);
    rsa1_envelope(AUTHTYPE_SRP, (inner.len() + 4) as u16, &body)
}

/// How type 36 frames the client proof.
///
/// UNCONFIRMED: nothing describes it. [`ProofFraming36::Bare`] is the
/// default: the type 33 proof body without the envelope, behind a u32 length
/// like the identity record. [`ProofFraming36::Rsa1`] sends exactly the type
/// 33 packet 2. The live test tries both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofFraming36 {
    Bare,
    Rsa1,
}

/// Type 36 proof in the given framing.
pub fn proof_packet_36(inner: &[u8], framing: ProofFraming36) -> Vec<u8> {
    match framing {
        ProofFraming36::Rsa1 => proof_packet_33(inner),
        ProofFraming36::Bare => {
            let rest = 4 + inner.len();
            let mut out = Vec::with_capacity(4 + rest);
            out.extend_from_slice(&(rest as u32).to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
            out.extend_from_slice(inner);
            out
        }
    }
}

/// One server SRP message: `u32 total_len, u8 step, u32 x, u32 payload_len,
/// payload`, where `x` is `payload_len + 4`.
///
/// What `total_len` counts is not certain, so it is not trusted to delimit
/// the message: the payload is read by its own length, and any surplus
/// `total_len` claims beyond the header and payload is read and dropped.
///
/// A server that refuses the login can answer with an ordinary failing
/// SecurityResult where a frame was expected. No frame is shorter than its
/// own 9 byte header, so a first word below 9 is read as that result, with
/// the RFB 3.8 reason string after it, and reported as rejected
/// credentials. How a Mac reports a wrong password here is unconfirmed.
pub async fn read_server_frame(stream: &mut BoxedStream, what: &str) -> Result<(u8, Vec<u8>)> {
    let total = read_u32(stream).await? as usize;
    if total < 9 {
        let mut reason = "the Mac rejected the user name or password".to_string();
        if let Ok(len) = read_u32(stream).await {
            if let Ok(bytes) = read_bytes_max(stream, len as usize, 8192, "failure reason").await {
                let text: String = String::from_utf8_lossy(&bytes)
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(512)
                    .collect();
                if !text.trim().is_empty() {
                    reason = text;
                }
            }
        }
        tracing::info!(what, status = total, "the Mac refused the SRP login");
        return Err(VncError::AuthFailed(reason));
    }
    let step = read_u8(stream).await?;
    let x = read_u32(stream).await? as usize;
    let payload_len = read_u32(stream).await? as usize;
    if x != payload_len + 4 {
        tracing::debug!(
            what,
            x,
            payload_len,
            "SRP frame length words disagree; trusting the payload length"
        );
    }
    let payload = read_bytes_max(stream, payload_len, MAX_FRAME, what).await?;
    let used = 1 + 4 + 4 + payload_len;
    if total > used {
        let surplus = total - used;
        tracing::debug!(what, surplus, "SRP frame has trailing bytes");
        read_bytes_max(stream, surplus, MAX_FRAME, what).await?;
    }
    Ok((step, payload))
}

/// Parse the host key reply's body (everything after its u32 length).
pub fn parse_key_reply(body: &[u8]) -> Result<RsaPublicKey> {
    let mut c = Cursor::new(body, "RSA host key reply");
    let tag = c.take(4)?;
    if tag != [0, 1, 0, 0] {
        tracing::debug!(?tag, "unexpected RSA host key reply tag");
    }
    let der = c.lv16()?;
    let key = RsaPublicKey::from_public_key_der(der)
        .map_err(|e| VncError::Protocol(format!("the Mac's RSA host key did not parse: {e}")))?;
    let bits = key.n().bits();
    if !(2048..=8192).contains(&bits) {
        return Err(VncError::Protocol(format!(
            "the Mac's RSA host key is {bits} bits; 2048 or more is required"
        )));
    }
    Ok(key)
}

/// SHA-256 over the host key's DER SubjectPublicKeyInfo.
pub fn host_key_fingerprint(key: &RsaPublicKey) -> Result<String> {
    let spki = key
        .to_public_key_der()
        .map_err(|e| VncError::Protocol(format!("RSA host key could not be encoded: {e}")))?;
    Ok(format_fingerprint(&Sha256::digest(spki.as_bytes())))
}

fn evaluate_trust(key: &RsaPublicKey, pin: Option<&str>) -> Result<TrustDecision> {
    let fingerprint = host_key_fingerprint(key)?;
    let actual = normalize_fingerprint(&fingerprint);
    let subject = format!("macOS Screen Sharing host key ({}-bit RSA)", key.n().bits());
    Ok(
        match pin.map(normalize_fingerprint).filter(|p| !p.is_empty()) {
            Some(expected) if expected == actual => TrustDecision::PinnedMatch,
            Some(expected) => TrustDecision::Changed {
                expected,
                actual: fingerprint,
            },
            None => TrustDecision::Unknown {
                fingerprint,
                subject,
                certificate: None,
            },
        },
    )
}

// ---------------------------------------------------------------------------
// Handshakes
// ---------------------------------------------------------------------------

async fn read_key_reply(stream: &mut BoxedStream) -> Result<RsaPublicKey> {
    let len = read_u32(stream).await? as usize;
    let body = read_bytes_max(stream, len, MAX_FRAME, "RSA host key reply").await?;
    parse_key_reply(&body)
}

async fn obtain_credentials(
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<(String, String)> {
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
    Ok((username, password))
}

/// Read the challenge, derive the proof and return it with the challenge.
async fn answer_challenge(
    stream: &mut BoxedStream,
    password: &str,
) -> Result<(Challenge, ClientProof, Vec<u8>)> {
    let (_step, payload) = read_server_frame(stream, "SRP challenge").await?;
    let challenge = parse_challenge(&payload)?;
    let group = SrpGroup::apple();
    check_group(&group, &challenge)?;
    if challenge.iterations == 0 || challenge.iterations > MAX_ITERATIONS {
        return Err(VncError::Protocol(format!(
            "the Mac asked for {} PBKDF2 iterations",
            challenge.iterations
        )));
    }

    // PBKDF2 at tens of thousands of rounds and three 4096-bit modpows are
    // tens of milliseconds of pure CPU; keep them off the reactor.
    let mut pw = password.as_bytes().to_vec();
    let ch = challenge.clone();
    let proof = tokio::task::spawn_blocking(move || {
        let mut derived = derive_password(&pw, &ch.salt, ch.iterations as u32);
        pw.zeroize();
        let mut a_bytes = [0u8; 64];
        rand::rng().fill_bytes(&mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);
        a_bytes.zeroize();
        let out = client_proof(&group, &ch, &derived, &a);
        derived.zeroize();
        out
    })
    .await
    .map_err(|e| VncError::Other(format!("SRP task failed: {e}")))??;

    let mut client_random = [0u8; CLIENT_RANDOM_LEN];
    rand::rng().fill_bytes(&mut client_random);
    let inner = proof_inner(&proof.a_pub, &proof.m1, &challenge.options, &client_random)?;
    Ok((challenge, proof, inner))
}

/// Read the server proof and check `M2`.
async fn check_server_proof(stream: &mut BoxedStream, proof: &ClientProof) -> Result<()> {
    let (_step, payload) = read_server_frame(stream, "SRP server proof").await?;
    let server = parse_server_proof(&payload)?;
    if server.m2 != proof.expected_m2 {
        // Either the server does not know the verifier (wrong password on its
        // side gives no M2 at all, so this is unusual) or our M2 formula is
        // off. Refuse: an unverified server is not one to send input to.
        return Err(VncError::AuthFailed(
            "the Mac's SRP proof did not verify".into(),
        ));
    }
    Ok(())
}

/// Type 33 after the type byte.
pub(crate) async fn handshake_33(
    mut stream: BoxedStream,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<AuthOutcome> {
    write_all(&mut stream, &key_request()).await?;
    let host_key = read_key_reply(&mut stream).await?;

    let trust = evaluate_trust(&host_key, opts.cert_pins.for_scheme(PinScheme::AppleRsa))?;
    if let TrustDecision::Changed { expected, actual } = &trust {
        return Err(VncError::CertificateMismatch {
            expected: expected.clone(),
            actual: actual.clone(),
        });
    }

    let (username, password) = obtain_credentials(opts, creds).await?;
    let mut identity = identity_record(&username)?;
    let ciphertext = host_key
        .encrypt(&mut rand::rng(), Pkcs1v15Encrypt, &identity)
        .map_err(|e| VncError::Other(format!("could not encrypt the identity record: {e}")));
    identity.zeroize();
    let ciphertext = ciphertext?;
    write_all(&mut stream, &identity_packet_33(&ciphertext)).await?;

    let (_challenge, proof, inner) = answer_challenge(&mut stream, &password).await?;
    write_all(&mut stream, &proof_packet_33(&inner)).await?;
    check_server_proof(&mut stream, &proof).await?;

    let mut outcome = AuthOutcome::auto(stream);
    outcome.apple_wrap_key = Some(initial_wrap_key(&proof.session_key));
    // The server proved it holds the verifier, which a key substituted in the
    // path cannot do, so the fingerprint is now worth offering to pin.
    outcome.trust = Some(ServerIdentity {
        scheme: PinScheme::AppleRsa,
        decision: trust,
    });
    Ok(outcome)
}

/// Type 36 after the type byte.
pub(crate) async fn handshake_36(
    stream: BoxedStream,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<AuthOutcome> {
    handshake_36_with(stream, opts, creds, ProofFraming36::Bare).await
}

async fn handshake_36_with(
    mut stream: BoxedStream,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
    framing: ProofFraming36,
) -> Result<AuthOutcome> {
    let (username, password) = obtain_credentials(opts, creds).await?;
    let mut identity = identity_record(&username)?;
    let sent = write_all(&mut stream, &identity).await;
    identity.zeroize();
    sent?;

    let (_challenge, proof, inner) = answer_challenge(&mut stream, &password).await?;
    write_all(&mut stream, &proof_packet_36(&inner, framing)).await?;
    check_server_proof(&mut stream, &proof).await?;

    let mut outcome = AuthOutcome::auto(stream);
    outcome.apple_wrap_key = Some(initial_wrap_key(&proof.session_key));
    Ok(outcome)
}

/// Run a type 36 login with an explicit proof framing, from the point the
/// server's security offer has been read: writes the type byte, runs the
/// exchange and reads the SecurityResult. The live test uses it to try both
/// framings; the session always uses [`ProofFraming36::Bare`].
#[doc(hidden)]
pub async fn login_36_with_framing(
    mut stream: BoxedStream,
    opts: &ConnectOptions,
    framing: ProofFraming36,
) -> Result<(BoxedStream, [u8; 16])> {
    write_all(&mut stream, &[36]).await?;
    let outcome = handshake_36_with(stream, opts, &CredentialSource::none(), framing).await?;
    let mut stream = outcome.stream;
    super::read_security_result(&mut stream, super::ProtocolVersionInfo::new(3, 8)).await?;
    let key = outcome
        .apple_wrap_key
        .ok_or_else(|| VncError::Other("type 36 produced no session key".into()))?;
    Ok((stream, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Sha1;

    fn h(s: &str) -> BigUint {
        BigUint::parse_bytes(s.as_bytes(), 16).unwrap()
    }

    // RFC 5054 appendix A, 1024-bit group, and appendix B test vectors.
    const N1024: &str = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576\
D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6\
CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A\
FD5138FE8376435B9FC61D2FC0EB06E3";
    const SALT: &str = "BEB25379D1A8581EB5A727673A2441EE";
    const K: &str = "7556AA045AEF2CDD07ABAF0F665C3E818913186F";
    const X: &str = "94B7555AABE9127CC58CCF4993DB6CF84D16C124";
    const A_PRIV: &str = "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393";
    const B_PRIV: &str = "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20";
    const A_PUB: &str = "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E890\
3211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED8251\
71E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA\
B349EF5D76988A3672FAC47B0769447B";
    const B_PUB: &str = "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964\
DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885\
D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE\
EB4012B7D7665238A8E3FB004B117B58";
    const U: &str = "CE38B9593487DA98554ED47D70A7AE5F462EF019";
    const PREMASTER: &str = "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E3\
59B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A\
0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D\
C346D7E474B29EDE8A469FFECA686E5A";

    /// The generic SRP functions reproduce RFC 5054 appendix B exactly when
    /// run with its hash (SHA-1), group (1024-bit, g = 2) and identity.
    #[test]
    fn srp_functions_match_rfc5054_appendix_b() {
        let group = SrpGroup::from_hex(N1024, 2);
        let salt = hex::decode(SALT).unwrap();
        assert_eq!(srp_k::<Sha1>(&group), h(K));
        let x = srp_x::<Sha1>(&salt, b"alice", b"password123");
        assert_eq!(x, h(X));
        let a = h(A_PRIV);
        let a_pub = group.g.modpow(&a, &group.n);
        assert_eq!(a_pub, h(A_PUB));
        let b_pub = h(B_PUB);
        let u = srp_u::<Sha1>(&group, &a_pub, &b_pub);
        assert_eq!(u, h(U));
        let s = srp_client_premaster(&group, &h(K), &x, &a, &u, &b_pub);
        assert_eq!(s, h(PREMASTER));
        // And the server side of the RFC gets there too, through its own
        // formula, so B in the vectors is consistent with b.
        let v = group.g.modpow(&x, &group.n);
        let b = h(B_PRIV);
        let b_check = (h(K) * &v + group.g.modpow(&b, &group.n)) % &group.n;
        assert_eq!(b_check, b_pub);
    }

    /// The 4096-bit prime is the RFC 3526 group 16 prime: 512 bytes, both
    /// ends all ones, and it parses to the same width the wire uses.
    #[test]
    fn apple_group_is_the_4096_bit_prime() {
        let g = SrpGroup::apple();
        assert_eq!(g.len, GROUP_BYTES);
        let bytes = g.n.to_bytes_be();
        assert!(bytes[..8].iter().all(|b| *b == 0xff));
        assert!(bytes[bytes.len() - 8..].iter().all(|b| *b == 0xff));
        assert_eq!(g.g, BigUint::from(5u32));
    }

    /// PBKDF2-HMAC-SHA512 against values computed with an independent
    /// implementation (OpenSSL via Python's hashlib), including the 128-byte
    /// output length macOS uses.
    #[test]
    fn pbkdf2_sha512_known_answers() {
        let mut one = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<Sha512>(b"password", b"salt", 1, &mut one);
        assert_eq!(
            hex::encode(one),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252\
c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
        );
        let long = derive_password(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
        );
        assert_eq!(
            hex::encode(long),
            "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71\
115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8\
04f75bdd41494fa324cab24bcc680fb3b96a30cf5d21fac3c2875913919f3399\
b1d9ce7eb54c95ba49118596cf7465719bbe02c4ecab1b1541298c321d13c6f6"
        );
    }

    /// PBKDF2-HMAC-SHA1 against RFC 6070, so the crate wiring is checked
    /// against a published vector as well.
    #[test]
    fn pbkdf2_sha1_rfc6070() {
        let mut out = [0u8; 20];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"password", b"salt", 4096, &mut out);
        assert_eq!(hex::encode(out), "4b007901b765489abead49d926f721d065a429c1");
    }

    #[test]
    fn identity_record_layout() {
        let r = identity_record("bob").unwrap();
        assert_eq!(r, [0, 0, 0, 10, 0, 0, 0, 3, b'b', b'o', b'b', 0, 0, 0]);
        assert!(identity_record(&"x".repeat(MAX_USER_LEN + 1)).is_err());
    }

    #[test]
    fn rsa1_packet_sizes_match_the_captured_lengths() {
        let p1 = identity_packet_33(&[0xAA; 256]);
        assert_eq!(&p1[..4], &650u32.to_be_bytes());
        assert_eq!(&p1[4..14], &[1, 0, b'R', b'S', b'A', b'1', 0, 2, 1, 0]);
        assert_eq!(p1.len(), 654);
        assert!(p1[14 + 256..].iter().all(|b| *b == 0));

        let inner = proof_inner(&[1; 512], &[2; 64], &[b'o'; 80], &[3; 16]).unwrap();
        assert_eq!(inner.len(), 678);
        let p2 = proof_packet_33(&inner);
        assert_eq!(&p2[..4], &1076u32.to_be_bytes());
        assert_eq!(&p2[12..14], &682u16.to_be_bytes());
        assert_eq!(&p2[14..18], &[0, 0, 0x02, 0xA6]);
        assert_eq!(&p2[18..18 + 678], &inner[..]);
        assert_eq!(p2.len(), 4 + 1076);
    }

    #[test]
    fn key_request_is_an_empty_rsa1_envelope() {
        assert_eq!(
            key_request(),
            [0, 0, 0, 10, 1, 0, b'R', b'S', b'A', b'1', 0, 0, 0, 0]
        );
    }

    #[test]
    fn challenge_parse_rejects_truncation() {
        let mut p = vec![0u8];
        p.extend_from_slice(&[0x02, 0x00]); // N says 512 bytes
        p.extend_from_slice(&[0xff; 10]);
        assert!(matches!(parse_challenge(&p), Err(VncError::Protocol(_))));
    }

    #[test]
    fn a_foreign_group_is_refused() {
        let group = SrpGroup::apple();
        let ch = Challenge {
            control: 0,
            n: hex::decode(N1024).unwrap(),
            g: vec![2],
            salt: vec![0; 32],
            b_pub: vec![1; 128],
            iterations: 1000,
            options: vec![],
        };
        assert!(check_group(&group, &ch).is_err());
    }

    #[test]
    fn wrap_key_is_the_first_half_of_sha256() {
        let k = [7u8; 64];
        let full = Sha256::digest(k);
        assert_eq!(initial_wrap_key(&k), full[..16]);
    }
}
