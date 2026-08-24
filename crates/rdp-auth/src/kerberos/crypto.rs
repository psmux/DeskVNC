//! RFC 3961's simplified profile, with RFC 3962's two AES encryption types.
//!
//! `aes128-cts-hmac-sha1-96` (etype 17) and `aes256-cts-hmac-sha1-96`
//! (etype 18), RFC 3962 §7. Everything a Kerberos exchange needs from
//! cryptography is here: the string-to-key function of RFC 3962 §4, the key
//! derivation of RFC 3961 §5.1, the encryption and decryption functions of
//! RFC 3961 §5.3, and the checksum of RFC 3961 §5.4.
//!
//! ## Nothing here computes anything
//!
//! AES is `aes::Aes128` and `aes::Aes256`. CBC is `cbc::Encryptor` and
//! `cbc::Decryptor`. Ciphertext stealing is `cts::CbcCs3Enc` and
//! `cts::CbcCs3Dec`. PBKDF2 is `pbkdf2::pbkdf2_hmac`. HMAC-SHA1 is
//! `hmac::Hmac<sha1::Sha1>`. The confounder is `rand::rng()`. What this file
//! owns is which buffer goes into which call, in which order, and with which
//! key usage number (AGENT_BRIEF V3-A, PRDRDP/14 §2.10).
//!
//! The one function here that is arithmetic rather than a library call is
//! [`n_fold`], and PRDRDP/00 R57 ruled on it in terms: it takes no key, it is
//! a fixed rearrangement of bits over a public constant, and RFC 3961
//! appendix A publishes vectors that prove it completely. Every vector in
//! that appendix is asserted in `tests/vectors_kerberos.rs`.
//!
//! ## The single block case, and why it is not `cts`
//!
//! RFC 3962 §5: "Ciphertext stealing, as defined in [RC5], assumes that more
//! than one block of plain text is available. If exactly one block is to be
//! encrypted, that block is simply encrypted with AES (also known as ECB
//! mode)." `cts` 0.6.0 does not implement that case. `CbcCs3Enc` swaps the
//! last two ciphertext blocks only when the tail is empty **and** there is
//! more than one block (`cts-0.6.0/src/cbc_cs3_enc.rs`, the condition
//! `if tail.is_empty() && blocks.len() > 1`); a single block input takes the
//! other branch and is encrypted a second time.
//!
//! **Read the next paragraph before deleting the branch in
//! [`encrypt_raw`].** `CbcCs3Dec` is the exact inverse of `CbcCs3Enc`,
//! including the part that is wrong: it decrypts a single block twice as
//! well. So `cts` round trips against itself perfectly, and every test anyone
//! can write inside this process passes, while the octets that go out on the
//! wire are not the octets RFC 3962 §5 defines. The defect is invisible to
//! encrypt-then-decrypt testing and visible only against a second
//! implementation, which in production means a domain controller answering
//! `KRB_AP_ERR_BAD_INTEGRITY` with nothing that points at a cipher mode. This
//! project already carries one bug of exactly that class, the RemoteFX
//! wavelet, and the lesson from it is the same: a self consistent codec is
//! not a correct one, and the only thing that catches this shape of error is
//! a vector from the specification. `tests/vectors_kerberos.rs` holds one,
//! and it asserts both that our answer is right and that `cts`'s answer
//! differs, so the branch cannot be simplified away without a test failing
//! and saying why.
//!
//! Every RFC 3961 §5.1 key derivation reaches that case, because `DR`
//! encrypts exactly one n-folded block. So [`encrypt_raw`] and
//! [`decrypt_raw`] dispatch on length: one block goes to `cbc`, more than one
//! goes to `cts`. Both arms are library calls and the branch condition is a
//! length comparison, which is the composition AGENT_BRIEF V3-A leaves with
//! us (PRDRDP/11 §3.9.2, PRDRDP/14 §7.5, `RustCrypto/block-modes` issue 77).
//! PRDRDP/11 §3.9.2 left three options open and recommended this one; it is
//! taken, and the escalation it records is answered rather than pending.
//!
//! An input shorter than one block would be padded under RFC 3962 §5, with
//! unspecified padding bits. No Kerberos message reaches it: RFC 3961 §5.3's
//! encryption function prepends a full block of confounder to every
//! plaintext, so the shortest thing ever encrypted is sixteen bytes plus
//! whatever it is confounding. The case is refused rather than padded, so a
//! future caller that finds it gets an error and not a value that depends on
//! padding a protocol may not rely on.

use aes::{Aes128, Aes256};
use cipher::generic_array::GenericArray;
use cipher::{BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit};
use cipher::{KeyIvInit, KeySizeUser};
use cts::{CbcCs3Dec, CbcCs3Enc, Decrypt, Encrypt};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::AuthError;

/// HMAC-SHA1, `hmac` 0.12 over `sha1` 0.10 (PRDRDP/14 §2.10's register row).
type HmacSha1 = Hmac<Sha1>;

/// The AES block size, and therefore RFC 3961 §5.1's `c`.
pub const BLOCK_LEN: usize = 16;

/// RFC 3962 §6: the HMAC output size `h` is 12 octets, 96 bits.
pub const CHECKSUM_LEN: usize = 12;

/// RFC 3961 §5.3: the confounder is a random string of length `c`.
pub const CONFOUNDER_LEN: usize = BLOCK_LEN;

/// RFC 3962 §4: the iteration count when `PA-ETYPE-INFO2` does not supply
/// string-to-key parameters. The four octets `00 00 10 00`, decimal 4096.
pub const DEFAULT_ITERATIONS: u32 = 4096;

/// RFC 3962 §4's advice on a spoofed iteration count: a KDC that names four
/// billion iterations is spending our CPU, not proving anything. The RFC says
/// a limit SHOULD be no less than 50,000; this is well above that and still
/// finishes in well under a second.
pub const MAX_ITERATIONS: u32 = 5_000_000;

/// RFC 3962 §4: the `DK` constant applied to the PBKDF2 output.
const STRING_TO_KEY_CONSTANT: &[u8] = b"kerberos";

/// RFC 3961 §5.3's key derivation suffixes. The well known constant is the
/// key usage number as four big endian octets followed by one of these.
///
/// They differ from each other in one byte and a transposition produces a
/// key that is wrong with no diagnostic beyond a decryption failure, which is
/// why each carries its own name rather than being written at the call site.
const KEY_USAGE_CHECKSUM: u8 = 0x99;
const KEY_USAGE_ENCRYPTION: u8 = 0xaa;
const KEY_USAGE_INTEGRITY: u8 = 0x55;

/// The key usage numbers of RFC 4120 §7.5.1 and RFC 4121 §2.
///
/// Getting one of these wrong produces a decryption failure with no
/// diagnostic, so each carries the line of the specification that assigns it
/// (PRDRDP/14 §7.1 item 7).
pub mod usage {
    /// Key usage 1: AS-REQ `PA-ENC-TIMESTAMP` padata timestamp, encrypted with the
    /// client key (RFC 4120 §7.5.1, §5.2.7.2).
    pub const AS_REQ_PA_ENC_TIMESTAMP: u32 = 1;
    /// Key usage 3: AS-REP encrypted part, encrypted with the client key
    /// (RFC 4120 §7.5.1, §5.4.2).
    pub const AS_REP_ENC_PART: u32 = 3;
    /// Key usage 6: TGS-REQ `PA-TGS-REQ` padata AP-REQ Authenticator checksum, keyed
    /// with the TGS session key (RFC 4120 §7.5.1, §5.5.1).
    pub const TGS_REQ_AUTHENTICATOR_CKSUM: u32 = 6;
    /// Key usage 7: TGS-REQ `PA-TGS-REQ` padata AP-REQ Authenticator, encrypted with
    /// the TGS session key (RFC 4120 §7.5.1, §5.5.1).
    pub const TGS_REQ_AUTHENTICATOR: u32 = 7;
    /// Key usage 8: TGS-REP encrypted part, encrypted with the TGS session key
    /// (RFC 4120 §7.5.1, §5.4.2).
    pub const TGS_REP_ENC_PART: u32 = 8;
    /// Key usage 9: TGS-REP encrypted part, encrypted with the TGS authenticator
    /// subkey (RFC 4120 §7.5.1, §5.4.2). We never send a subkey in the
    /// TGS-REQ authenticator, so a KDC that answers under this usage has
    /// invented a subkey; the reply decode tries 8 first and 9 second.
    pub const TGS_REP_ENC_PART_SUBKEY: u32 = 9;
    /// Key usage 10: AP-REQ Authenticator checksum, keyed with the application session
    /// key (RFC 4120 §7.5.1, §5.5.1). This is the usage the 0x8003 checksum
    /// of RFC 4121 §4.1.1 would take if it were keyed, and it is not: 0x8003
    /// is a plaintext structure, not a MAC.
    pub const AP_REQ_AUTHENTICATOR_CKSUM: u32 = 10;
    /// Key usage 11: AP-REQ Authenticator, encrypted with the application session key
    /// (RFC 4120 §7.5.1, §5.5.1).
    pub const AP_REQ_AUTHENTICATOR: u32 = 11;
    /// Key usage 12: AP-REP encrypted part, encrypted with the application session
    /// key (RFC 4120 §7.5.1, §5.5.2). The session key from the ticket and
    /// never a subkey: the subkey is what the AP-REP announces, so it cannot
    /// be what protects the announcement.
    pub const AP_REP_ENC_PART: u32 = 12;
    /// Key usage 22: `KG-USAGE-ACCEPTOR-SEAL`, RFC 4121 §2.
    pub const GSS_ACCEPTOR_SEAL: u32 = 22;
    /// Key usage 23: `KG-USAGE-ACCEPTOR-SIGN`, RFC 4121 §2.
    pub const GSS_ACCEPTOR_SIGN: u32 = 23;
    /// Key usage 24: `KG-USAGE-INITIATOR-SEAL`, RFC 4121 §2.
    pub const GSS_INITIATOR_SEAL: u32 = 24;
    /// Key usage 25: `KG-USAGE-INITIATOR-SIGN`, RFC 4121 §2.
    pub const GSS_INITIATOR_SIGN: u32 = 25;
}

/// One of RFC 3962's two encryption types.
///
/// RFC 3961's other enctypes are declined: `des3-cbc-sha1` and
/// `arcfour-hmac` are what modern Kerberos policy is removing, and offering
/// `arcfour-hmac` would put an NT hash back on the Kerberos path
/// (PRDRDP/14 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Enctype {
    /// `aes256-cts-hmac-sha1-96`, etype 18 (RFC 3962 §7). Preferred.
    Aes256CtsHmacSha1_96,
    /// `aes128-cts-hmac-sha1-96`, etype 17 (RFC 3962 §7).
    Aes128CtsHmacSha1_96,
}

impl Enctype {
    /// The `etype` value that goes on the wire (RFC 3962 §7).
    #[must_use]
    pub const fn etype(self) -> i32 {
        match self {
            Enctype::Aes256CtsHmacSha1_96 => 18,
            Enctype::Aes128CtsHmacSha1_96 => 17,
        }
    }

    /// The protocol key length in octets, which is also RFC 3961 §5.1's `k`,
    /// the key generation seed length: RFC 3962 §6 sets the two equal.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Enctype::Aes256CtsHmacSha1_96 => 32,
            Enctype::Aes128CtsHmacSha1_96 => 16,
        }
    }

    /// The checksum type paired with this enctype (RFC 3962 §7):
    /// `hmac-sha1-96-aes128` is 15 and `hmac-sha1-96-aes256` is 16.
    #[must_use]
    pub const fn checksum_type(self) -> i32 {
        match self {
            Enctype::Aes256CtsHmacSha1_96 => 16,
            Enctype::Aes128CtsHmacSha1_96 => 15,
        }
    }

    /// The enctype an `etype` value names, or `None` for one we do not offer.
    #[must_use]
    pub const fn from_etype(etype: i32) -> Option<Self> {
        match etype {
            18 => Some(Enctype::Aes256CtsHmacSha1_96),
            17 => Some(Enctype::Aes128CtsHmacSha1_96),
            _ => None,
        }
    }

    /// The two we offer, most preferred first. The order is the order they
    /// go in `KDC-REQ-BODY.etype` (RFC 4120 §5.4.1).
    #[must_use]
    pub const fn offered() -> [Enctype; 2] {
        [Enctype::Aes256CtsHmacSha1_96, Enctype::Aes128CtsHmacSha1_96]
    }
}

/// A protocol key: the enctype it belongs to and its octets.
///
/// The octets are `Zeroizing`, so a key is overwritten wherever it drops
/// (PRDRDP/14 §8.2). `Debug` prints the enctype and the length and never the
/// bytes (§8.3).
#[derive(Clone)]
pub struct Key {
    enctype: Enctype,
    octets: Zeroizing<Vec<u8>>,
}

impl Key {
    /// A key from octets the caller already has, usually a session key out of
    /// an `EncryptionKey` in a KDC reply (RFC 4120 §5.2.9).
    ///
    /// # Errors
    ///
    /// [`AuthError::MalformedMessage`] when the length is not the one the
    /// enctype defines. A KDC that sends a 16 byte key for etype 18 is either
    /// confused or probing.
    pub fn new(enctype: Enctype, octets: &[u8]) -> Result<Self, AuthError> {
        if octets.len() != enctype.key_len() {
            return Err(AuthError::MalformedMessage("EncryptionKey.keyvalue length"));
        }
        Ok(Key {
            enctype,
            octets: Zeroizing::new(octets.to_vec()),
        })
    }

    /// Which enctype this key is for.
    #[must_use]
    pub const fn enctype(&self) -> Enctype {
        self.enctype
    }

    /// The key octets. Secret.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        &self.octets
    }
}

impl std::fmt::Debug for Key {
    /// PRDRDP/14 §8.3: no secret appears in any `Debug`, asserted by
    /// `tests/redaction.rs`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("enctype", &self.enctype)
            .field(
                "octets",
                &format_args!("{} bytes, redacted", self.octets.len()),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// n-fold, RFC 3961 §5.1
// ---------------------------------------------------------------------------

/// `n-fold`, RFC 3961 §5.1.
///
/// The specification, quoted because every sentence of it is load bearing:
/// "To n-fold a number X, replicate the input value to a length that is the
/// least common multiple of n and the length of X. Before each repetition,
/// the input is rotated to the right by 13 bit positions. The successive
/// n-bit chunks are added together using 1's-complement addition (that is,
/// with end-around carry) to yield a n-bit result."
///
/// Three readings of that text decide the answer and all three are held by
/// the appendix A vectors:
///
/// * The first repetition is unrotated, and repetition `r` is rotated right
///   by `13 * r` bits. RFC 3961 appendix A says of the `"kerberos"` values
///   "the initial octets exactly match the input string when the output
///   length is a multiple of the input length", which is only true if the
///   first repetition is the input itself.
/// * Octet strings are big endian, most significant byte first, which is what
///   makes "rotate right" mean "towards the end of the string".
/// * The chunks are `n` bits each, taken from the replicated string, not from
///   each repetition. When the input is longer than the output a repetition
///   spans several chunks, and when it is shorter several repetitions share
///   one.
///
/// `out_len` is in octets. RFC 3961 §5.1 always calls it with the cipher
/// block size, so the only call in this crate passes 16, but the appendix A
/// vectors exercise 7, 8, 21, 24 and 32 and the function takes any of them.
///
/// # Panics
///
/// Never, for a non empty `input` and a non zero `out_len`. Both are
/// compile time constants at every call site in this crate.
#[must_use]
pub fn n_fold(input: &[u8], out_len: usize) -> Vec<u8> {
    if input.is_empty() || out_len == 0 {
        return vec![0u8; out_len];
    }
    let repetitions = lcm(input.len(), out_len) / input.len();

    let mut sum = vec![0u8; out_len];
    let mut replicated = Vec::with_capacity(repetitions * input.len());
    for r in 0..repetitions {
        replicated.extend_from_slice(&rotated_right(input, 13 * r));
    }
    for chunk in replicated.chunks_exact(out_len) {
        ones_complement_add(&mut sum, chunk);
    }
    sum
}

/// The octet string `input` rotated right by `bits` bit positions, treated as
/// one big endian number (RFC 3961 §5.1).
///
/// Written as a bit index permutation rather than as a word rotation. The
/// input is a byte string of an arbitrary length, not a machine word, so
/// there is no word to rotate; and `tests/redaction.rs` greps this crate for
/// `rotate_left` and `rotate_right`, because a word rotation inside a loop is
/// the shape a hand written cipher primitive takes and that grep is worth
/// more than the two lines it costs here.
fn rotated_right(input: &[u8], bits: usize) -> Vec<u8> {
    let total_bits = input.len() * 8;
    let shift = bits % total_bits;
    let mut out = vec![0u8; input.len()];
    for target in 0..total_bits {
        // Rotating right moves bit 0 (the most significant) towards the end,
        // so the bit landing at `target` came from `target - shift`.
        let source = (target + total_bits - shift) % total_bits;
        let byte = input.get(source / 8).copied().unwrap_or(0);
        let bit = (byte >> (7 - (source % 8))) & 1;
        if let Some(slot) = out.get_mut(target / 8) {
            *slot |= bit << (7 - (target % 8));
        }
    }
    out
}

/// One's complement addition of two equal length big endian octet strings,
/// with end around carry (RFC 3961 §5.1). `acc` is replaced by the sum.
fn ones_complement_add(acc: &mut [u8], addend: &[u8]) {
    let mut carry = 0u16;
    for i in (0..acc.len()).rev() {
        let a = u16::from(acc.get(i).copied().unwrap_or(0));
        let b = u16::from(addend.get(i).copied().unwrap_or(0));
        let sum = a + b + carry;
        if let Some(slot) = acc.get_mut(i) {
            *slot = (sum & 0xff) as u8;
        }
        carry = sum >> 8;
    }
    // End around: the carry out of the most significant octet is added back
    // in at the least significant one, and may itself carry.
    while carry != 0 {
        let mut c = carry;
        for i in (0..acc.len()).rev() {
            let sum = u16::from(acc.get(i).copied().unwrap_or(0)) + c;
            if let Some(slot) = acc.get_mut(i) {
                *slot = (sum & 0xff) as u8;
            }
            c = sum >> 8;
            if c == 0 {
                break;
            }
        }
        carry = c;
    }
}

/// The least common multiple, for the replication length of [`n_fold`].
const fn lcm(a: usize, b: usize) -> usize {
    a / gcd(a, b) * b
}

/// Euclid's algorithm.
const fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

// ---------------------------------------------------------------------------
// The raw cipher, RFC 3962 §5
// ---------------------------------------------------------------------------

/// RFC 3961 §5.1's `E`: AES in CBC mode with ciphertext stealing, over
/// `buf` in place, with the initial cipher state `iv`.
///
/// This is the raw cipher and not the encryption function of RFC 3961 §5.3.
/// It adds no confounder and no integrity tag, and it is called directly only
/// by [`derive_key`]. Everything else goes through [`encrypt`].
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] for a buffer shorter than one block, which
/// no Kerberos message produces; see the module comment.
pub fn encrypt_raw(key: &Key, iv: &[u8; BLOCK_LEN], buf: &mut [u8]) -> Result<(), AuthError> {
    match key.enctype {
        Enctype::Aes128CtsHmacSha1_96 => encrypt_raw_with::<Aes128>(key.octets(), iv, buf),
        Enctype::Aes256CtsHmacSha1_96 => encrypt_raw_with::<Aes256>(key.octets(), iv, buf),
    }
}

/// The inverse of [`encrypt_raw`], RFC 3962 §5.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] for a buffer shorter than one block.
pub fn decrypt_raw(key: &Key, iv: &[u8; BLOCK_LEN], buf: &mut [u8]) -> Result<(), AuthError> {
    match key.enctype {
        Enctype::Aes128CtsHmacSha1_96 => decrypt_raw_with::<Aes128>(key.octets(), iv, buf),
        Enctype::Aes256CtsHmacSha1_96 => decrypt_raw_with::<Aes256>(key.octets(), iv, buf),
    }
}

/// The length dispatch of the module comment: exactly one block is plain CBC,
/// more than one is CBC with ciphertext stealing, less than one is refused.
///
/// The `cts` crate would answer the one block case, and its answer is wrong
/// (`RustCrypto/block-modes` issue 77, PRDRDP/11 §3.9.2). Both arms below are
/// a call into a library and neither computes anything.
fn encrypt_raw_with<C>(key: &[u8], iv: &[u8; BLOCK_LEN], buf: &mut [u8]) -> Result<(), AuthError>
where
    C: BlockCipher + BlockEncrypt + KeyInit + KeySizeUser,
{
    match buf.len() {
        n if n < BLOCK_LEN => Err(AuthError::MalformedMessage(
            "cipher input shorter than a block",
        )),
        BLOCK_LEN => {
            // RFC 3962 §5: "If exactly one block is to be encrypted, that
            // block is simply encrypted with AES". With the CBC chaining that
            // RFC 3961 §5.3 puts around it, that is one CBC block.
            let mut cipher = cbc::Encryptor::<C>::new_from_slices(key, iv)
                .map_err(|_| AuthError::MalformedMessage("AES key length"))?;
            cipher.encrypt_block_mut(GenericArray::from_mut_slice(buf));
            Ok(())
        }
        _ => CbcCs3Enc::<C>::new_from_slices(key, iv)
            .map_err(|_| AuthError::MalformedMessage("AES key length"))?
            .encrypt(buf)
            .map_err(|_| AuthError::MalformedMessage("AES-CTS input length")),
    }
}

/// The decryption half of [`encrypt_raw_with`], with the same dispatch. The
/// two must agree on where the boundary is or a message encrypted here does
/// not decrypt here, which is the failure the round trip tests catch.
fn decrypt_raw_with<C>(key: &[u8], iv: &[u8; BLOCK_LEN], buf: &mut [u8]) -> Result<(), AuthError>
where
    C: BlockCipher + BlockDecrypt + BlockEncrypt + KeyInit + KeySizeUser,
{
    match buf.len() {
        n if n < BLOCK_LEN => Err(AuthError::MalformedMessage(
            "cipher input shorter than a block",
        )),
        BLOCK_LEN => {
            let mut cipher = cbc::Decryptor::<C>::new_from_slices(key, iv)
                .map_err(|_| AuthError::MalformedMessage("AES key length"))?;
            cipher.decrypt_block_mut(GenericArray::from_mut_slice(buf));
            Ok(())
        }
        _ => CbcCs3Dec::<C>::new_from_slices(key, iv)
            .map_err(|_| AuthError::MalformedMessage("AES key length"))?
            .decrypt(buf)
            .map_err(|_| AuthError::MalformedMessage("AES-CTS input length")),
    }
}

// ---------------------------------------------------------------------------
// DR and DK, RFC 3961 §5.1
// ---------------------------------------------------------------------------

/// `DK(base, constant)`, RFC 3961 §5.1.
///
/// ```text
/// DK(Key, Constant)  = random-to-key(DR(Key, Constant))
/// DR(Key, Constant)  = k-truncate(K1 | K2 | K3 | ...)
///   K1 = E(Key, n-fold(Constant), initial-cipher-state)
///   K2 = E(Key, K1, initial-cipher-state)
/// ```
///
/// RFC 3962 §4 makes `random-to-key` the identity for both AES enctypes, so
/// `DK` is `DR` truncated to the key length.
///
/// Three details that each produce a silently wrong key:
///
/// * The initial cipher state is all bits zero and it is reset for every
///   `Ki`, rather than being chained from the previous one. RFC 3961 §5.1
///   writes `initial-cipher-state` in each line of the construction.
/// * `E` here is the whole RFC 3962 §5 cipher, and its input is always
///   exactly one block, which is the case the module comment is about.
/// * For etype 18 the loop runs twice, because one block of output is 16
///   bytes and the seed length is 32. For etype 17 it runs once.
///
/// # Errors
///
/// Whatever [`encrypt_raw`] makes of the block, which for a well formed key
/// is nothing.
pub fn derive_key(base: &Key, constant: &[u8]) -> Result<Key, AuthError> {
    let seed_len = base.enctype.key_len();
    let zero_iv = [0u8; BLOCK_LEN];

    let mut block = n_fold(constant, BLOCK_LEN);
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(seed_len + BLOCK_LEN));
    while out.len() < seed_len {
        encrypt_raw(base, &zero_iv, &mut block)?;
        out.extend_from_slice(&block);
    }
    out.truncate(seed_len);
    Key::new(base.enctype, &out)
}

/// The well known constant of RFC 3961 §5.3: the key usage number as four
/// octets in big endian order, then one suffix octet.
fn usage_constant(usage: u32, suffix: u8) -> [u8; 5] {
    let u = usage.to_be_bytes();
    [u[0], u[1], u[2], u[3], suffix]
}

/// `Kc = DK(base-key, usage | 0x99)`, RFC 3961 §5.3. The checksum key.
///
/// # Errors
///
/// Whatever [`derive_key`] makes of the base key.
pub fn checksum_key(base: &Key, usage: u32) -> Result<Key, AuthError> {
    derive_key(base, &usage_constant(usage, KEY_USAGE_CHECKSUM))
}

/// `Ke = DK(base-key, usage | 0xAA)`, RFC 3961 §5.3. The encryption key.
///
/// # Errors
///
/// Whatever [`derive_key`] makes of the base key.
pub fn encryption_key(base: &Key, usage: u32) -> Result<Key, AuthError> {
    derive_key(base, &usage_constant(usage, KEY_USAGE_ENCRYPTION))
}

/// `Ki = DK(base-key, usage | 0x55)`, RFC 3961 §5.3. The integrity key.
///
/// # Errors
///
/// Whatever [`derive_key`] makes of the base key.
pub fn integrity_key(base: &Key, usage: u32) -> Result<Key, AuthError> {
    derive_key(base, &usage_constant(usage, KEY_USAGE_INTEGRITY))
}

// ---------------------------------------------------------------------------
// string-to-key, RFC 3962 §4
// ---------------------------------------------------------------------------

/// `string-to-key(passphrase, salt, params)`, RFC 3962 §4.
///
/// ```text
/// tkey = random2key(PBKDF2(passphrase, salt, iter_count, keylength))
/// key  = DK(tkey, "kerberos")
/// ```
///
/// The passphrase is UTF-8, not UTF-16: RFC 3961 §4 leaves the encoding to
/// the profile and every Kerberos implementation including Active Directory
/// uses UTF-8 here. This is the one place a Windows authentication path does
/// **not** encode a password as UTF-16LE, and taking NTLM's `unicode()` by
/// habit produces a key that is wrong for every non empty password.
///
/// The salt comes from `PA-ETYPE-INFO2` and is never computed here. Active
/// Directory's default is `REALM || principal` with no separator, and a
/// principal with an explicit salt differs; asking the KDC makes the question
/// moot, which is the reason for the two round AS exchange (PRDRDP/14 §7.2).
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] when the iteration count is zero or above
/// [`MAX_ITERATIONS`]. RFC 3962 §4 says the minimum expressible count is 1
/// and recommends an upper bound against a spoofed reply.
pub fn string_to_key(
    enctype: Enctype,
    passphrase: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Key, AuthError> {
    let tkey = string_to_key_intermediate(enctype, passphrase, salt, iterations)?;
    let tkey = Key::new(enctype, &tkey)?;
    derive_key(&tkey, STRING_TO_KEY_CONSTANT)
}

/// The `tkey` of RFC 3962 §4: the PBKDF2 output before the `DK` step.
///
/// It is public because RFC 3962 appendix B publishes both halves of every
/// string-to-key vector, the "128-bit PBKDF2 output" and the "128-bit AES
/// key", and `tests/vectors_kerberos.rs` asserts both. A vector suite that
/// checks only the final value cannot tell a wrong iteration count from a
/// wrong `DK` constant, and those are different bugs with different fixes
/// (PRDRDP/14 §9.2).
///
/// Secret: this is the user's password stretched, and it is one `DK` away
/// from the long term key.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] when the iteration count is zero or above
/// [`MAX_ITERATIONS`].
pub fn string_to_key_intermediate(
    enctype: Enctype,
    passphrase: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(AuthError::MalformedMessage("string-to-key iteration count"));
    }
    let mut tkey: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; enctype.key_len()]);
    pbkdf2::pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), salt, iterations, &mut tkey);
    Ok(tkey)
}

// ---------------------------------------------------------------------------
// The encryption and checksum functions, RFC 3961 §5.3 and §5.4
// ---------------------------------------------------------------------------

/// RFC 3961 §5.3's encryption function, at the given key usage.
///
/// ```text
/// conf       = Random string of length c
/// C1         = E(Ke, conf | plaintext, initial-cipher-state)
/// H1         = HMAC(Ki, conf | plaintext)
/// ciphertext = C1 | H1[1..h]
/// ```
///
/// There is no `pad`: RFC 3962 §6 sets the message block size `m` to one
/// octet, so the shortest string that brings the confounder and the plaintext
/// to a multiple of `m` is empty. A padding step here would change every
/// ciphertext length by up to fifteen bytes and would be accepted by nothing.
///
/// # Errors
///
/// Whatever [`derive_key`] and [`encrypt_raw`] make of the key.
pub fn encrypt(base: &Key, usage: u32, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
    let ke = encryption_key(base, usage)?;
    let ki = integrity_key(base, usage)?;

    let mut confounded: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(CONFOUNDER_LEN + plaintext.len()));
    confounded.extend_from_slice(&confounder());
    confounded.extend_from_slice(plaintext);

    let tag = truncated_hmac(&ki, &confounded);

    let mut ciphertext = confounded.to_vec();
    encrypt_raw(&ke, &[0u8; BLOCK_LEN], &mut ciphertext)?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

/// RFC 3961 §5.3's decryption function, at the given key usage.
///
/// The tag is verified before the plaintext is returned, and the comparison
/// goes through `subtle::ConstantTimeEq` (PRDRDP/14 §8.1). The confounder is
/// stripped from the front of the result.
///
/// The return is `Zeroizing`: the plaintext of a KDC reply is a session key.
///
/// # Errors
///
/// [`AuthError::MalformedMessage`] for a ciphertext too short to hold a
/// confounder and a tag, and [`AuthError::SignatureMismatch`] when the tag
/// does not verify, which is what a wrong password looks like on the AS-REP
/// path.
pub fn decrypt(base: &Key, usage: u32, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    if ciphertext.len() < CONFOUNDER_LEN + CHECKSUM_LEN {
        return Err(AuthError::MalformedMessage("EncryptedData.cipher length"));
    }
    let split = ciphertext.len() - CHECKSUM_LEN;
    let (body, tag) = ciphertext.split_at(split);

    let ke = encryption_key(base, usage)?;
    let ki = integrity_key(base, usage)?;

    let mut plain: Zeroizing<Vec<u8>> = Zeroizing::new(body.to_vec());
    decrypt_raw(&ke, &[0u8; BLOCK_LEN], &mut plain)?;

    let want = truncated_hmac(&ki, &plain);
    if bool::from(want.ct_eq(tag)) {
        Ok(Zeroizing::new(
            plain.get(CONFOUNDER_LEN..).unwrap_or(&[]).to_vec(),
        ))
    } else {
        Err(AuthError::SignatureMismatch)
    }
}

/// RFC 3961 §5.4's `get_mic`: `HMAC(Kc, message)[1..h]`, with `Kc` derived at
/// the given key usage and `h` the 12 octets of RFC 3962 §6.
///
/// # Errors
///
/// Whatever [`checksum_key`] makes of the base key.
pub fn checksum(base: &Key, usage: u32, message: &[u8]) -> Result<Vec<u8>, AuthError> {
    let kc = checksum_key(base, usage)?;
    Ok(truncated_hmac(&kc, message).to_vec())
}

/// RFC 3961 §5.4's `verify_mic`: get_mic and compare, in constant time.
///
/// # Errors
///
/// [`AuthError::SignatureMismatch`] when the checksum does not verify.
pub fn verify_checksum(
    base: &Key,
    usage: u32,
    message: &[u8],
    tag: &[u8],
) -> Result<(), AuthError> {
    let want = checksum(base, usage, message)?;
    if bool::from(want.as_slice().ct_eq(tag)) {
        Ok(())
    } else {
        Err(AuthError::SignatureMismatch)
    }
}

/// `HMAC-SHA1(key, message)` truncated to the leftmost 96 bits (RFC 3962 §6).
///
/// The truncation is a slice of a vetted HMAC's output, not a hand written
/// truncation of a hand written hash. `hmac` takes any key length, so the
/// `expect` is unreachable.
fn truncated_hmac(key: &Key, message: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut mac =
        <HmacSha1 as Mac>::new_from_slice(key.octets()).expect("HMAC accepts any key length");
    mac.update(message);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; CHECKSUM_LEN];
    for (slot, byte) in out.iter_mut().zip(full.iter()) {
        *slot = *byte;
    }
    out
}

/// RFC 3961 §5.3's confounder: a random string of length `c`, from
/// `rand::rng()` and from nothing else (PRDRDP/14 §2.10).
fn confounder() -> [u8; CONFOUNDER_LEN] {
    let mut out = [0u8; CONFOUNDER_LEN];
    rand::rng().fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3961 appendix A.1, the `"kerberos"` values. The whole appendix is
    /// in `tests/vectors_kerberos.rs`; these two are here because a broken
    /// `n_fold` should fail the unit run and not wait for the integration
    /// one.
    #[test]
    fn n_fold_matches_rfc_3961_appendix_a_1() {
        assert_eq!(n_fold(b"kerberos", 8), hex_bytes("6b657262 65726f73"));
        assert_eq!(
            n_fold(b"kerberos", 16),
            hex_bytes("6b657262 65726f73 7b9b5b2b 93132b93")
        );
    }

    /// RFC 3962 §7's two enctypes and their two checksum types, and the
    /// round trip through `from_etype`.
    #[test]
    fn the_enctypes_are_the_ones_rfc_3962_assigns() {
        assert_eq!(Enctype::Aes128CtsHmacSha1_96.etype(), 17);
        assert_eq!(Enctype::Aes256CtsHmacSha1_96.etype(), 18);
        assert_eq!(Enctype::Aes128CtsHmacSha1_96.key_len(), 16);
        assert_eq!(Enctype::Aes256CtsHmacSha1_96.key_len(), 32);
        assert_eq!(Enctype::Aes128CtsHmacSha1_96.checksum_type(), 15);
        assert_eq!(Enctype::Aes256CtsHmacSha1_96.checksum_type(), 16);
        for e in Enctype::offered() {
            assert_eq!(Enctype::from_etype(e.etype()), Some(e));
        }
        assert_eq!(Enctype::from_etype(23), None);
        assert_eq!(Enctype::from_etype(16), None);
    }

    /// RFC 3961 §5.3's three suffixes, which differ from each other in one
    /// byte and are the easiest thing in the profile to transpose.
    #[test]
    fn the_usage_constant_is_four_big_endian_octets_and_a_suffix() {
        assert_eq!(usage_constant(1, KEY_USAGE_ENCRYPTION), [0, 0, 0, 1, 0xaa]);
        assert_eq!(usage_constant(2, KEY_USAGE_CHECKSUM), [0, 0, 0, 2, 0x99]);
        assert_eq!(usage_constant(3, KEY_USAGE_INTEGRITY), [0, 0, 0, 3, 0x55]);
        assert_eq!(
            usage_constant(0x0102_0304, KEY_USAGE_ENCRYPTION),
            [1, 2, 3, 4, 0xaa]
        );
    }

    /// A key of the wrong length for its enctype is refused rather than
    /// padded or truncated.
    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(Key::new(Enctype::Aes256CtsHmacSha1_96, &[0u8; 16]).is_err());
        assert!(Key::new(Enctype::Aes128CtsHmacSha1_96, &[0u8; 32]).is_err());
        assert!(Key::new(Enctype::Aes128CtsHmacSha1_96, &[0u8; 16]).is_ok());
        assert!(Key::new(Enctype::Aes256CtsHmacSha1_96, &[0u8; 32]).is_ok());
    }

    /// PRDRDP/14 §8.3.
    #[test]
    fn a_key_never_prints_its_octets() {
        let key = Key::new(Enctype::Aes256CtsHmacSha1_96, &[0xab; 32]).expect("32 bytes");
        let shown = format!("{key:?}");
        assert!(!shown.contains("ab"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    /// Round trips at every length that reaches a different branch of the
    /// dispatch: exactly one block, one block plus a byte, exactly two, and a
    /// ragged tail.
    #[test]
    fn the_raw_cipher_round_trips_at_every_length_branch() {
        for enctype in Enctype::offered() {
            let key = Key::new(enctype, &vec![0x11u8; enctype.key_len()]).expect("key");
            for len in [16usize, 17, 32, 33, 47, 48, 64] {
                let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let mut buf = plain.clone();
                encrypt_raw(&key, &[0u8; BLOCK_LEN], &mut buf).expect("encrypt");
                assert_eq!(buf.len(), len, "AES-CTS never changes the length");
                assert_ne!(buf, plain, "len {len}");
                decrypt_raw(&key, &[0u8; BLOCK_LEN], &mut buf).expect("decrypt");
                assert_eq!(buf, plain, "len {len} enctype {enctype:?}");
            }
            let mut short = [0u8; 15];
            assert!(encrypt_raw(&key, &[0u8; BLOCK_LEN], &mut short).is_err());
            assert!(decrypt_raw(&key, &[0u8; BLOCK_LEN], &mut short).is_err());
        }
    }

    /// RFC 3961 §5.3 end to end, including that a flipped bit anywhere in the
    /// ciphertext is caught by the tag rather than returned as plaintext.
    #[test]
    fn encrypt_and_decrypt_round_trip_and_reject_tampering() {
        for enctype in Enctype::offered() {
            let key = Key::new(enctype, &vec![0x22u8; enctype.key_len()]).expect("key");
            let message = b"PA-ENC-TS-ENC would go here";
            let ct = encrypt(&key, usage::AS_REQ_PA_ENC_TIMESTAMP, message).expect("encrypt");
            assert_eq!(ct.len(), CONFOUNDER_LEN + message.len() + CHECKSUM_LEN);
            let pt = decrypt(&key, usage::AS_REQ_PA_ENC_TIMESTAMP, &ct).expect("decrypt");
            assert_eq!(&*pt, message);

            // A different key usage is a different key, so the tag fails.
            assert_eq!(
                decrypt(&key, usage::AS_REP_ENC_PART, &ct).unwrap_err(),
                AuthError::SignatureMismatch
            );

            for bit in 0..8 {
                for byte in 0..ct.len() {
                    let mut tampered = ct.clone();
                    if let Some(slot) = tampered.get_mut(byte) {
                        *slot ^= 1 << bit;
                    }
                    assert_eq!(
                        decrypt(&key, usage::AS_REQ_PA_ENC_TIMESTAMP, &tampered).unwrap_err(),
                        AuthError::SignatureMismatch,
                        "byte {byte} bit {bit}"
                    );
                }
            }
        }
    }

    /// Every prefix of a ciphertext fails cleanly. A KDC reply is bytes a
    /// remote peer chose.
    #[test]
    fn every_truncation_of_a_ciphertext_is_an_error_and_not_a_panic() {
        let enctype = Enctype::Aes256CtsHmacSha1_96;
        let key = Key::new(enctype, &vec![0x33u8; enctype.key_len()]).expect("key");
        let ct = encrypt(&key, usage::AS_REP_ENC_PART, b"reply").expect("encrypt");
        for cut in 0..ct.len() {
            let prefix = ct.get(..cut).expect("in range");
            assert!(
                decrypt(&key, usage::AS_REP_ENC_PART, prefix).is_err(),
                "cut {cut}"
            );
        }
    }

    /// RFC 3961 §5.4, and the constant time comparison of §8.1.
    #[test]
    fn a_checksum_verifies_only_against_its_own_message_and_usage() {
        let enctype = Enctype::Aes128CtsHmacSha1_96;
        let key = Key::new(enctype, &vec![0x44u8; enctype.key_len()]).expect("key");
        let tag = checksum(&key, usage::TGS_REQ_AUTHENTICATOR_CKSUM, b"body").expect("checksum");
        assert_eq!(tag.len(), CHECKSUM_LEN);
        verify_checksum(&key, usage::TGS_REQ_AUTHENTICATOR_CKSUM, b"body", &tag).expect("verify");
        assert!(verify_checksum(&key, usage::TGS_REQ_AUTHENTICATOR_CKSUM, b"bodz", &tag).is_err());
        assert!(verify_checksum(&key, usage::AP_REQ_AUTHENTICATOR_CKSUM, b"body", &tag).is_err());
        assert!(verify_checksum(&key, usage::TGS_REQ_AUTHENTICATOR_CKSUM, b"body", &[]).is_err());
    }

    /// RFC 3962 §4's bounds on the iteration count.
    #[test]
    fn a_spoofed_iteration_count_is_refused() {
        let e = Enctype::Aes128CtsHmacSha1_96;
        assert!(string_to_key(e, "password", b"salt", 0).is_err());
        assert!(string_to_key(e, "password", b"salt", MAX_ITERATIONS + 1).is_err());
        assert!(string_to_key(e, "password", b"salt", u32::MAX).is_err());
        assert!(string_to_key(e, "password", b"salt", 1).is_ok());
    }

    /// A hex string with spaces, the way the RFCs print them.
    fn hex_bytes(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len() / 2)
            .map(|i| {
                u8::from_str_radix(clean.get(i * 2..i * 2 + 2).expect("pairs"), 16)
                    .expect("hex digits")
            })
            .collect()
    }
}
