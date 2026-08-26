//! PuTTY private keys (`.ppk`), versions 2 and 3.
//!
//! `russh::keys::load_secret_key` reads the OpenSSH family: the modern
//! `BEGIN OPENSSH PRIVATE KEY` container, and the older PEM/PKCS#1 and
//! PKCS#8 files `ssh-keygen -m PEM` and `-m PKCS8` still emit. It does not
//! read PuTTY's format, and PuTTY is what a large number of Windows users
//! have: `puttygen` writes `.ppk`, WinSCP and FileZilla store `.ppk`, and
//! "convert it with puttygen first" is a poor answer when the file is right
//! there.
//!
//! # Format
//!
//! A `.ppk` is a small line-oriented text file. Both versions carry the same
//! fields; version 3 replaced the homebrew key derivation with Argon2 and
//! widened the MAC.
//!
//! ```text
//! PuTTY-User-Key-File-3: ssh-ed25519      <- version and algorithm
//! Encryption: aes256-cbc                  <- or "none"
//! Comment: some text
//! Public-Lines: 2
//! <base64>
//! Key-Derivation: Argon2id                <- v3, encrypted only
//! Argon2-Memory: 8192
//! Argon2-Passes: 21
//! Argon2-Parallelism: 1
//! Argon2-Salt: <hex>
//! Private-Lines: 1
//! <base64>
//! Private-MAC: <hex>
//! ```
//!
//! The public and private blobs are SSH wire format (4-byte big-endian
//! length prefixes), but PuTTY's field order is its own and does not match
//! what OpenSSH puts in a private key. [`openssh_keypair_blob`] is where
//! that is reconciled, per algorithm.
//!
//! # Why this is hand-rolled
//!
//! No crate in the tree reads PPK, and the format is small enough that
//! pulling in an unaudited one to parse key material would be the larger
//! risk. Everything the crypto needs (`aes`, `cbc`, `hmac`, `sha1`, `sha2`,
//! `argon2`) is already in the dependency graph via russh, so this adds no
//! new third-party code to the build, only workspace crates that were
//! already being compiled.
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use russh::keys::ssh_encoding::Decode;
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::PrivateKey;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use zeroize::Zeroize;

/// Every `.ppk` begins with this, whatever the version.
const MAGIC: &str = "PuTTY-User-Key-File-";

/// PuTTY's own bound. A key file larger than this is not a key file, and the
/// line parser should not be handed an arbitrary amount of memory.
const MAX_FILE_BYTES: usize = 1 << 20;

/// Fixed string PPK v2 mixes into the passphrase to derive its MAC key.
const V2_MAC_SALT: &[u8] = b"putty-private-key-file-mac-key";

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug, thiserror::Error)]
pub enum PpkError {
    #[error("not a PuTTY key file")]
    NotPpk,
    #[error("PuTTY key file version {0} is not supported (only 2 and 3 are)")]
    Version(String),
    #[error("malformed PuTTY key file: {0}")]
    Malformed(String),
    #[error("unsupported {what} in PuTTY key file: {value}")]
    Unsupported { what: &'static str, value: String },
    /// The MAC did not verify. On an encrypted key this is almost always a
    /// wrong passphrase rather than a damaged file, which is why the two are
    /// separate variants: only this one is worth re-prompting for.
    #[error("wrong passphrase for PuTTY key file")]
    WrongPassphrase,
    #[error("PuTTY key file is corrupt (its MAC does not match its contents)")]
    BadMac,
    #[error("PuTTY key file needs a passphrase")]
    PassphraseRequired,
    #[error("unsupported key algorithm in PuTTY key file: {0}")]
    Algorithm(String),
    /// Called out separately from [`PpkError::Algorithm`] because the file is
    /// perfectly valid and the user is owed the reason.
    #[error("DSA (ssh-dss) keys are not supported: the algorithm is obsolete and OpenSSH dropped it; generate an Ed25519 or RSA key instead")]
    Dsa,
    #[error("could not build a key from the PuTTY key file: {0}")]
    KeyBuild(String),
}

/// Does this look like a `.ppk`?
///
/// Content-sniffed rather than decided by file extension: a key is a key
/// whatever it has been renamed to, and the caller has already read the
/// bytes to load it anyway.
#[must_use]
pub fn is_ppk(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC.as_bytes())
}

/// Parse a `.ppk` into a key russh can authenticate with.
///
/// `passphrase` is ignored for an unencrypted key, so a caller holding a
/// stored secret does not have to know in advance whether it is needed.
pub fn load(bytes: &[u8], passphrase: Option<&str>) -> Result<PrivateKey, PpkError> {
    if !is_ppk(bytes) {
        return Err(PpkError::NotPpk);
    }
    if bytes.len() > MAX_FILE_BYTES {
        return Err(PpkError::Malformed("file is implausibly large".into()));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PpkError::Malformed("file is not valid UTF-8".into()))?;

    let file = PpkFile::parse(text)?;
    let encrypted = match file.encryption.as_str() {
        "none" => false,
        "aes256-cbc" => true,
        other => {
            return Err(PpkError::Unsupported {
                what: "encryption",
                value: other.to_string(),
            })
        }
    };

    // An empty passphrase and no passphrase are the same thing to PuTTY, and
    // treating them alike keeps a stored-but-blank secret from being an error.
    let passphrase = passphrase.filter(|p| !p.is_empty());
    if encrypted && passphrase.is_none() {
        return Err(PpkError::PassphraseRequired);
    }

    // An unencrypted key derives from the EMPTY passphrase, never from
    // whatever the caller happened to pass. PuTTY ignores the passphrase for
    // such a file, and mixing it in would change the v2 MAC key and reject a
    // perfectly good key with a corruption error.
    let effective = if encrypted {
        passphrase.unwrap_or("")
    } else {
        ""
    };
    let mut derived = file.derive(effective, encrypted)?;
    let mut private = file.private.clone();
    if encrypted {
        decrypt_cbc(&mut private, &derived.cipher_key, &derived.iv)?;
    }

    verify_mac(
        &file,
        &private,
        &derived.mac_key,
        encrypted,
        passphrase.is_some(),
    )?;
    derived.zeroize();

    let result = build_key(&file, &private);
    private.zeroize();
    result
}

// ------------------------------------------------------------------ parsing

/// The fields of a `.ppk`, with the base64 bodies already decoded.
struct PpkFile {
    version: u8,
    algorithm: String,
    encryption: String,
    comment: String,
    public: Vec<u8>,
    /// Still ciphertext when the key is encrypted.
    private: Vec<u8>,
    mac: Vec<u8>,
    argon2: Option<Argon2Params>,
}

struct Argon2Params {
    variant: argon2::Algorithm,
    memory_kib: u32,
    passes: u32,
    parallelism: u32,
    salt: Vec<u8>,
}

impl PpkFile {
    fn parse(text: &str) -> Result<Self, PpkError> {
        // `lines()` handles CRLF, which matters: these files usually come off
        // a Windows machine, and a stray `\r` left on the end of a hex MAC
        // would fail to decode for a reason nobody could guess from the
        // error.
        let mut lines = text.lines().peekable();

        let first = lines.next().ok_or(PpkError::NotPpk)?;
        let (key, algorithm) = split_field(first)?;
        let version_str = key.strip_prefix(MAGIC).ok_or(PpkError::NotPpk)?.to_string();
        let version = match version_str.as_str() {
            "2" => 2u8,
            "3" => 3u8,
            other => return Err(PpkError::Version(other.to_string())),
        };

        let mut encryption = None;
        let mut comment = String::new();
        let mut public = None;
        let mut private = None;
        let mut mac = None;
        let mut kdf: Option<String> = None;
        let mut memory = None;
        let mut passes = None;
        let mut parallelism = None;
        let mut salt = None;

        while let Some(line) = lines.next() {
            if line.trim().is_empty() {
                continue;
            }
            let (key, value) = split_field(line)?;
            match key {
                "Encryption" => encryption = Some(value.to_string()),
                "Comment" => comment = value.to_string(),
                "Public-Lines" => public = Some(read_base64(&mut lines, value)?),
                "Private-Lines" => private = Some(read_base64(&mut lines, value)?),
                "Private-MAC" => {
                    mac = Some(hex::decode(value).map_err(|_| {
                        PpkError::Malformed("Private-MAC is not hexadecimal".into())
                    })?)
                }
                "Key-Derivation" => kdf = Some(value.to_string()),
                "Argon2-Memory" => memory = Some(parse_u32(value, "Argon2-Memory")?),
                "Argon2-Passes" => passes = Some(parse_u32(value, "Argon2-Passes")?),
                "Argon2-Parallelism" => parallelism = Some(parse_u32(value, "Argon2-Parallelism")?),
                "Argon2-Salt" => {
                    salt = Some(hex::decode(value).map_err(|_| {
                        PpkError::Malformed("Argon2-Salt is not hexadecimal".into())
                    })?)
                }
                // Unknown headers are skipped rather than rejected: PuTTY has
                // added fields before (the whole Argon2 block is one such
                // addition) and a reader that refuses anything it has not
                // seen ages badly.
                _ => {}
            }
        }

        let encryption =
            encryption.ok_or_else(|| PpkError::Malformed("no Encryption field".into()))?;
        let argon2 = match kdf.as_deref() {
            None => None,
            Some(name) => {
                let variant = match name {
                    "Argon2id" => argon2::Algorithm::Argon2id,
                    "Argon2i" => argon2::Algorithm::Argon2i,
                    "Argon2d" => argon2::Algorithm::Argon2d,
                    other => {
                        return Err(PpkError::Unsupported {
                            what: "key derivation",
                            value: other.to_string(),
                        })
                    }
                };
                Some(Argon2Params {
                    variant,
                    memory_kib: memory
                        .ok_or_else(|| PpkError::Malformed("no Argon2-Memory field".into()))?,
                    passes: passes
                        .ok_or_else(|| PpkError::Malformed("no Argon2-Passes field".into()))?,
                    parallelism: parallelism
                        .ok_or_else(|| PpkError::Malformed("no Argon2-Parallelism field".into()))?,
                    salt: salt.ok_or_else(|| PpkError::Malformed("no Argon2-Salt field".into()))?,
                })
            }
        };

        Ok(Self {
            version,
            algorithm: algorithm.to_string(),
            encryption,
            comment,
            public: public.ok_or_else(|| PpkError::Malformed("no Public-Lines block".into()))?,
            private: private.ok_or_else(|| PpkError::Malformed("no Private-Lines block".into()))?,
            mac: mac.ok_or_else(|| PpkError::Malformed("no Private-MAC field".into()))?,
            argon2,
        })
    }

    /// Key material for this file: the AES key and IV that decrypt the
    /// private blob, and the key its MAC is taken with.
    fn derive(&self, passphrase: &str, encrypted: bool) -> Result<Derived, PpkError> {
        match self.version {
            2 => Ok(derive_v2(passphrase, encrypted)),
            _ => derive_v3(self, passphrase, encrypted),
        }
    }
}

/// `Key: value`, with the single space after the colon that PuTTY writes.
fn split_field(line: &str) -> Result<(&str, &str), PpkError> {
    let (key, value) = line
        .split_once(':')
        .ok_or_else(|| PpkError::Malformed(format!("line is not a field: {line:?}")))?;
    Ok((key.trim(), value.trim()))
}

fn parse_u32(value: &str, field: &str) -> Result<u32, PpkError> {
    value
        .parse()
        .map_err(|_| PpkError::Malformed(format!("{field} is not a number")))
}

/// Take `count` lines and base64-decode them as one body.
fn read_base64<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
    count: &str,
) -> Result<Vec<u8>, PpkError> {
    let count: usize = count
        .parse()
        .map_err(|_| PpkError::Malformed("line count is not a number".into()))?;
    // A line count is a length prefix from an untrusted file, so it is a
    // budget rather than an instruction: cap it before allocating.
    if count > MAX_FILE_BYTES / 8 {
        return Err(PpkError::Malformed("implausible line count".into()));
    }
    let mut body = String::new();
    for _ in 0..count {
        let line = lines
            .next()
            .ok_or_else(|| PpkError::Malformed("file ends inside a base64 block".into()))?;
        body.push_str(line.trim());
    }
    base64::engine::general_purpose::STANDARD
        .decode(&body)
        .map_err(|_| PpkError::Malformed("base64 block does not decode".into()))
}

// --------------------------------------------------------- key derivation

/// AES key, IV and MAC key for one file.
struct Derived {
    cipher_key: Vec<u8>,
    iv: Vec<u8>,
    mac_key: Vec<u8>,
}

impl Zeroize for Derived {
    fn zeroize(&mut self) {
        self.cipher_key.zeroize();
        self.iv.zeroize();
        self.mac_key.zeroize();
    }
}

/// PPK v2: SHA-1 used as a homebrew KDF, predating PuTTY adopting a real one.
///
/// The cipher key is `SHA1(u32be(0) || pass) || SHA1(u32be(1) || pass)`
/// truncated to 32 bytes, the IV is all zeroes, and the MAC key is
/// `SHA1("putty-private-key-file-mac-key" || pass)`.
fn derive_v2(passphrase: &str, encrypted: bool) -> Derived {
    let cipher_key = if encrypted {
        let mut key = Vec::with_capacity(40);
        for counter in 0u32..2 {
            let mut h = Sha1::new();
            h.update(counter.to_be_bytes());
            h.update(passphrase.as_bytes());
            key.extend_from_slice(&h.finalize());
        }
        key.truncate(32);
        key
    } else {
        Vec::new()
    };

    // Unlike v3, the v2 MAC key is derived the same way whether or not the
    // key is encrypted; for an unencrypted key the passphrase is simply
    // empty, which is what PuTTY hashes.
    let mut h = Sha1::new();
    h.update(V2_MAC_SALT);
    h.update(passphrase.as_bytes());
    let mac_key = h.finalize().to_vec();

    Derived {
        cipher_key,
        iv: vec![0u8; 16],
        mac_key,
    }
}

/// PPK v3: one Argon2 call produces all three pieces at once, 80 bytes split
/// 32 (cipher key) / 16 (IV) / 32 (MAC key).
///
/// An unencrypted v3 file has no Argon2 block at all and its MAC is taken
/// with an empty key, which is why this returns early rather than inventing
/// parameters.
fn derive_v3(file: &PpkFile, passphrase: &str, encrypted: bool) -> Result<Derived, PpkError> {
    if !encrypted {
        return Ok(Derived {
            cipher_key: Vec::new(),
            iv: Vec::new(),
            mac_key: Vec::new(),
        });
    }
    let params = file
        .argon2
        .as_ref()
        .ok_or_else(|| PpkError::Malformed("encrypted v3 key has no Argon2 parameters".into()))?;

    let argon_params = argon2::Params::new(
        params.memory_kib,
        params.passes,
        params.parallelism,
        Some(80),
    )
    .map_err(|e| PpkError::Malformed(format!("bad Argon2 parameters: {e}")))?;
    let argon = argon2::Argon2::new(params.variant, argon2::Version::V0x13, argon_params);

    let mut out = vec![0u8; 80];
    argon
        .hash_password_into(passphrase.as_bytes(), &params.salt, &mut out)
        .map_err(|e| PpkError::Malformed(format!("Argon2 failed: {e}")))?;

    let derived = Derived {
        cipher_key: out[0..32].to_vec(),
        iv: out[32..48].to_vec(),
        mac_key: out[48..80].to_vec(),
    };
    out.zeroize();
    Ok(derived)
}

// ------------------------------------------------------- decrypt and verify

/// AES-256-CBC with no padding: PuTTY pads the plaintext to the block size
/// itself before encrypting, so the decrypted length is the stored length
/// and there is no padding byte to strip.
fn decrypt_cbc(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), PpkError> {
    if data.len() % 16 != 0 {
        return Err(PpkError::Malformed(
            "encrypted private blob is not a whole number of blocks".into(),
        ));
    }
    let cipher = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|_| PpkError::Malformed("bad AES key or IV length".into()))?;
    // `decrypt_padded_mut` would insist on a padding scheme; PuTTY's blob has
    // none, so the blocks are walked directly.
    use aes::cipher::block_padding::NoPadding;
    cipher
        .decrypt_padded_mut::<NoPadding>(data)
        .map_err(|_| PpkError::Malformed("private blob failed to decrypt".into()))?;
    Ok(())
}

/// The MAC covers the algorithm, the encryption name, the comment, and both
/// blobs, each as a length-prefixed SSH string, with the private blob in its
/// PLAINTEXT form. Verifying it after decrypting is therefore also the
/// passphrase check: a wrong passphrase produces garbage plaintext whose MAC
/// cannot match.
fn verify_mac(
    file: &PpkFile,
    private_plain: &[u8],
    mac_key: &[u8],
    encrypted: bool,
    had_passphrase: bool,
) -> Result<(), PpkError> {
    let mut data = Vec::new();
    put_string(&mut data, file.algorithm.as_bytes());
    put_string(&mut data, file.encryption.as_bytes());
    put_string(&mut data, file.comment.as_bytes());
    put_string(&mut data, &file.public);
    put_string(&mut data, private_plain);

    let ok = if file.version == 2 {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(mac_key)
            .map_err(|_| PpkError::Malformed("bad MAC key length".into()))?;
        mac.update(&data);
        mac.verify_slice(&file.mac).is_ok()
    } else {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key)
            .map_err(|_| PpkError::Malformed("bad MAC key length".into()))?;
        mac.update(&data);
        mac.verify_slice(&file.mac).is_ok()
    };
    data.zeroize();

    if ok {
        Ok(())
    } else if encrypted && had_passphrase {
        Err(PpkError::WrongPassphrase)
    } else {
        Err(PpkError::BadMac)
    }
}

// ------------------------------------------------------------ key assembly

/// Build the key by handing ssh-key the byte layout it already parses, rather
/// than by calling a different component constructor per algorithm.
fn build_key(file: &PpkFile, private_plain: &[u8]) -> Result<PrivateKey, PpkError> {
    let blob = openssh_keypair_blob(&file.algorithm, &file.public, private_plain)?;
    let mut reader = blob.as_slice();
    let keypair = KeypairData::decode(&mut reader)
        .map_err(|e| PpkError::KeyBuild(format!("{}: {e}", file.algorithm)))?;
    let mut key = PrivateKey::new(keypair, file.comment.clone())
        .map_err(|e| PpkError::KeyBuild(e.to_string()))?;
    // PuTTY comments are free text and can be empty; ssh-key is happy either
    // way, but an empty comment reads better than a literal "".
    if file.comment.is_empty() {
        key.set_comment("");
    }
    Ok(key)
}

/// Rewrite PuTTY's public + private blobs as the keypair blob OpenSSH stores,
/// which is what `KeypairData::decode` reads.
///
/// PuTTY's public blob is already `string(algorithm) || <public fields>`, and
/// for two of the four algorithm families the private fields follow in
/// exactly the order OpenSSH wants, so the answer is a plain concatenation.
/// RSA and Ed25519 are the two that do not line up:
///
/// * RSA. PuTTY writes public `e, n` then private `d, p, q, iqmp`; OpenSSH
///   writes `n, e, d, iqmp, p, q`. Same six numbers, three differences in
///   order. Both define `iqmp` as the inverse of `q` modulo `p`, so the value
///   itself carries across untouched.
/// * Ed25519. PuTTY stores the 32-byte scalar alone; OpenSSH stores 64 bytes,
///   the scalar followed by a copy of the public key.
fn openssh_keypair_blob(
    algorithm: &str,
    public: &[u8],
    private: &[u8],
) -> Result<Vec<u8>, PpkError> {
    // The public blob repeats the algorithm name; check it rather than trust
    // the header, so a file claiming one algorithm and carrying another is
    // rejected instead of being decoded as whatever the body says.
    let mut cursor = public;
    let named = get_string(&mut cursor)?;
    if named != algorithm.as_bytes() {
        return Err(PpkError::Malformed(
            "the algorithm in the public blob does not match the header".into(),
        ));
    }
    let public_fields = cursor;

    let mut out = Vec::new();
    match algorithm {
        // string(pub) || string(priv 32) becomes string(pub) || string(priv || pub)
        "ssh-ed25519" => {
            let mut p = public_fields;
            let pubkey = get_string(&mut p)?;
            let mut s = private;
            let scalar = get_string(&mut s)?;
            if scalar.len() != 32 || pubkey.len() != 32 {
                return Err(PpkError::Malformed("bad Ed25519 component length".into()));
            }
            put_string(&mut out, algorithm.as_bytes());
            put_string(&mut out, pubkey);
            let mut expanded = Vec::with_capacity(64);
            expanded.extend_from_slice(scalar);
            expanded.extend_from_slice(pubkey);
            put_string(&mut out, &expanded);
            expanded.zeroize();
        }
        // e, n, d, p, q, iqmp  becomes  n, e, d, iqmp, p, q
        "ssh-rsa" => {
            let mut p = public_fields;
            let e = get_string(&mut p)?;
            let n = get_string(&mut p)?;
            let mut s = private;
            let d = get_string(&mut s)?;
            let prime1 = get_string(&mut s)?;
            let prime2 = get_string(&mut s)?;
            let iqmp = get_string(&mut s)?;
            put_string(&mut out, algorithm.as_bytes());
            for field in [n, e, d, iqmp, prime1, prime2] {
                put_string(&mut out, field);
            }
        }
        // Refused deliberately, and early. PuTTY still writes DSA keys and
        // the blob would decode fine (p, q, g, y then x is already OpenSSH's
        // order), but russh is built without its `dsa` feature, so nothing in
        // this workspace can produce a DSA signature. Accepting the key here
        // would only move the failure to the handshake, where it surfaces as
        // an authentication rejection with no hint that the algorithm was the
        // problem. OpenSSH itself disabled ssh-dss by default in 7.0 and
        // removed it in 9.8, so this is a dead end worth naming rather than a
        // gap worth filling.
        "ssh-dss" => return Err(PpkError::Dsa),
        // string(curve) || string(point) then mpint(d), also already in order.
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            out.extend_from_slice(public);
            out.extend_from_slice(private);
        }
        other => return Err(PpkError::Algorithm(other.to_string())),
    }
    Ok(out)
}

// ------------------------------------------------------------ wire helpers

/// Length-prefixed SSH string. Also how an `mpint` is framed, which is why
/// the numeric fields above are moved around as opaque byte slices: their
/// encoding never has to be understood, only their order.
fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn get_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], PpkError> {
    if input.len() < 4 {
        return Err(PpkError::Malformed(
            "blob ends inside a length prefix".into(),
        ));
    }
    let (len_bytes, rest) = input.split_at(4);
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if rest.len() < len {
        return Err(PpkError::Malformed("blob ends inside a field".into()));
    }
    let (value, rest) = rest.split_at(len);
    *input = rest;
    Ok(value)
}
