//! Security types 5/6/129/130, RealVNC's RSA-AES (RA2 family).
//!
//! Used by RealVNC Server, including the Raspberry Pi OS default. Both sides
//! exchange raw RSA public keys, each RSA-encrypts a 16-byte random for the
//! other, and the two randoms are hashed into a pair of directional AES-EAX
//! session keys.
//!
//! ```text
//! S->C  u32 server_key_bits, modulus[k], exponent[k]      (k = ceil(bits/8))
//! C->S  u32 client_key_bits, modulus[c], exponent[c]      (c = 256, 2048-bit)
//! C->S  RSA_pkcs1v15(server_key, client_random[16])       -> k bytes
//! S->C  RSA_pkcs1v15(client_key, server_random[16])       -> c bytes
//!       --- everything below is AES-EAX framed ---
//! S->C  server_hash                                       H(server_pub || client_pub)
//! C->S  client_hash                                       H(client_pub || server_pub)
//! S->C  u8 subtype                                        1 = user+pass, 2 = pass only
//! C->S  u8 user_len, user, u8 pass_len, pass
//! ```
//!
//! Session keys: `client_key = H(server_random || client_random)`,
//! `server_key = H(client_random || server_random)`, the first 16 bytes with
//! SHA-1 (types 5/6), the full 32 bytes with SHA-256 (types 129/130).
//!
//! Framing: `{u16 length, ciphertext, 16-byte MAC}` under AES-EAX, with a
//! 16-byte little-endian message counter as the nonce and the two length bytes
//! as the associated data. Each direction has its own key and counter.
//!
//! `RA2ne`/`RA2ne_256` ("no encryption") use the identical handshake but drop
//! back to a cleartext stream once authentication is done; `RA2`/`RA2_256` keep
//! every subsequent byte inside the framing, which is what [`Ra2Stream`]
//! implements.
//!
//! ## Server identity (PRD/10 §1.1)
//!
//! RA2 has no PKI: the server just hands over a raw RSA public key. Encryption
//! without identity is worthless, anyone in the path can substitute their own
//! key and relay, so the key is pinned trust-on-first-use exactly like a TLS
//! certificate, via [`evaluate_trust`]. See that function for which bytes are
//! hashed and why.
//!
//! ## Known risk
//!
//! This handshake could not be exercised against a real RealVNC server here.
//! The key derivation, framing and EAX construction are unit-tested against
//! themselves (and the framing is symmetric, so a client/server round trip is
//! meaningful), but the *message ordering*, specifically that the server hash
//! arrives before the client hash is sent, is taken from noVNC's `ra2.js` and
//! has not been validated on the wire. If a live server stalls at the hash
//! exchange, that is the line to flip.
//!
//! `rsa` 0.9 carries RUSTSEC-2023-0071 (Marvin timing attack). We perform one
//! private-key decryption per connection with no attacker-controlled retry, so
//! the practical risk is low; tracked in the security review.

use std::pin::Pin;
use std::task::{Context, Poll};

use aes::{Aes128, Aes256};
use eax::aead::generic_array::GenericArray;
use eax::aead::{AeadInPlace, KeyInit};
use eax::Eax;
use rand::Rng;
use rsa::pkcs8::EncodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{BoxedUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroize;

use vnc_transport::{
    format_fingerprint, normalize_fingerprint, BoxedStream, Stream, TrustDecision,
};

use super::prompt::CredentialSource;
use super::{read_bytes_max, read_u32, AuthOutcome, ServerIdentity};
use crate::error::{Result, VncError};
use crate::types::{ConnectOptions, CredentialKind, PinScheme, SecurityType};

/// Our RSA key size. RealVNC accepts anything from 1024 bits up.
const CLIENT_KEY_BITS: usize = 2048;
const CLIENT_KEY_BYTES: usize = CLIENT_KEY_BITS / 8;

const RANDOM_LEN: usize = 16;
const MAC_LEN: usize = 16;
/// Largest plaintext we put in one frame. The length field is a u16, but
/// RealVNC's own implementation chunks at 8 KiB.
const MAX_FRAME_PLAINTEXT: usize = 8192;

const MIN_SERVER_KEY_BITS: u32 = 1024;
const MAX_SERVER_KEY_BITS: u32 = 8192;

/// What the credential dialog calls this family of methods.
pub const METHOD: &str = "RealVNC RSA-AES";

/// What the server's credential subtype byte asks the user for.
///
/// Subtype 1 wants a user name and a password; subtype 2 wants a password only.
/// Neither truncates. The server only tells us *during* the handshake, which is
/// why RA2 raises its prompt this late.
pub fn credential_kind_for_subtype(subtype: u8) -> Option<CredentialKind> {
    match subtype {
        1 => Some(CredentialKind::UsernameAndPassword),
        2 => Some(CredentialKind::PasswordOnly),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Variant
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Variant {
    /// SHA-256 (and 32-byte keys) instead of SHA-1 (16-byte keys).
    sha256: bool,
    /// Keep encrypting after authentication (`RA2`), or drop to cleartext (`RA2ne`).
    encrypt_session: bool,
}

impl Variant {
    fn of(t: SecurityType) -> Option<Self> {
        Some(match t {
            SecurityType::Ra2 => Variant {
                sha256: false,
                encrypt_session: true,
            },
            SecurityType::Ra2ne => Variant {
                sha256: false,
                encrypt_session: false,
            },
            SecurityType::Ra2_256 => Variant {
                sha256: true,
                encrypt_session: true,
            },
            SecurityType::Ra2ne256 => Variant {
                sha256: true,
                encrypt_session: false,
            },
            _ => return None,
        })
    }

    fn key_len(&self) -> usize {
        if self.sha256 {
            32
        } else {
            16
        }
    }

    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        if self.sha256 {
            let mut h = Sha256::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        } else {
            let mut h = Sha1::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
    }
}

// ---------------------------------------------------------------------------
// AES-EAX framing
// ---------------------------------------------------------------------------

enum Aead {
    A128(Box<Eax<Aes128>>),
    A256(Box<Eax<Aes256>>),
}

/// One direction of the encrypted channel: a key plus a message counter.
pub(crate) struct Ra2Cipher {
    aead: Aead,
    counter: u128,
}

impl Ra2Cipher {
    fn new(key: &[u8]) -> Result<Self> {
        let aead = match key.len() {
            16 => Aead::A128(Box::new(Eax::<Aes128>::new(GenericArray::from_slice(key)))),
            32 => Aead::A256(Box::new(Eax::<Aes256>::new(GenericArray::from_slice(key)))),
            n => {
                return Err(VncError::Other(format!(
                    "invalid RA2 session key length {n}"
                )))
            }
        };
        Ok(Self { aead, counter: 0 })
    }

    /// 16-byte little-endian message counter.
    fn next_nonce(&mut self) -> [u8; 16] {
        let nonce = self.counter.to_le_bytes();
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    /// Encrypt one message into a complete `{u16 len, ciphertext, mac}` frame.
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > u16::MAX as usize {
            return Err(VncError::Other("RA2 frame is too large".into()));
        }
        let header = (plaintext.len() as u16).to_be_bytes();
        let nonce = self.next_nonce();
        let mut body = plaintext.to_vec();
        let tag = match &self.aead {
            Aead::A128(c) => {
                c.encrypt_in_place_detached(GenericArray::from_slice(&nonce), &header, &mut body)
            }
            Aead::A256(c) => {
                c.encrypt_in_place_detached(GenericArray::from_slice(&nonce), &header, &mut body)
            }
        }
        .map_err(|_| VncError::Other("RA2 encryption failed".into()))?;

        let mut frame = Vec::with_capacity(2 + body.len() + MAC_LEN);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&tag);
        body.zeroize();
        Ok(frame)
    }

    /// Decrypt a frame body (`ciphertext || mac`) given its length header.
    fn open(&mut self, header: [u8; 2], body: &[u8]) -> Result<Vec<u8>> {
        if body.len() < MAC_LEN {
            return Err(VncError::Protocol("truncated RA2 frame".into()));
        }
        let (ciphertext, tag) = body.split_at(body.len() - MAC_LEN);
        let nonce = self.next_nonce();
        let mut out = ciphertext.to_vec();
        let ok = match &self.aead {
            Aead::A128(c) => c.decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &header,
                &mut out,
                GenericArray::from_slice(tag),
            ),
            Aead::A256(c) => c.decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &header,
                &mut out,
                GenericArray::from_slice(tag),
            ),
        };
        if ok.is_err() {
            // A bad MAC means tampering or desynchronisation; either way the
            // channel is unusable.
            return Err(VncError::Protocol(
                "RA2 message authentication failed, the connection may be under attack".into(),
            ));
        }
        Ok(out)
    }
}

/// Send one encrypted frame over a not-yet-wrapped stream.
async fn send_frame(
    stream: &mut BoxedStream,
    cipher: &mut Ra2Cipher,
    plaintext: &[u8],
) -> Result<()> {
    let frame = cipher.seal(plaintext)?;
    super::write_all(stream, &frame).await
}

/// Receive one encrypted frame from a not-yet-wrapped stream.
async fn recv_frame(stream: &mut BoxedStream, cipher: &mut Ra2Cipher) -> Result<Vec<u8>> {
    let header_bytes = read_bytes_max(stream, 2, 2, "RA2 frame header").await?;
    let header = [header_bytes[0], header_bytes[1]];
    let len = u16::from_be_bytes(header) as usize;
    let body = read_bytes_max(
        stream,
        len + MAC_LEN,
        u16::MAX as usize + MAC_LEN,
        "RA2 frame body",
    )
    .await?;
    cipher.open(header, &body)
}

// ---------------------------------------------------------------------------
// Server identity (TOFU pinning)
// ---------------------------------------------------------------------------

/// SHA-256 of the server's RSA public key, in the *same* canonical form the TLS
/// path fingerprints: the DER `SubjectPublicKeyInfo`.
///
/// ## Why not hash the wire blob
///
/// The obvious candidate is `server_public_blob` (`bits || modulus ||
/// exponent`), the bytes the ServerHash covers. It is not safe to fingerprint
/// directly, because that encoding is **not canonical**. `bits` is the server's
/// own claim, and the modulus and exponent fields are `ceil(bits/8)` bytes
/// regardless of their real magnitude. One RSA key therefore has many valid
/// blobs: a 2048-bit modulus can be sent as `bits = 2048` with 256 bytes, or as
/// `bits = 2056` with 257 bytes and a leading zero, and so on. A server that
/// wanted to dodge a stored pin, or to make one key look like several, would
/// only have to re-pad. The exponent field is worse: 65537 is sent
/// left-padded with 250-odd zero bytes.
///
/// So we hash the parsed key instead. `BigUint` discards leading zeros, and DER
/// `INTEGER` is minimal-length by definition, so every encoding of one key
/// collapses to one fingerprint.
///
/// ## Why this is still the authenticated key
///
/// `key` is not a re-parse of some other message: it is the very
/// `RsaPublicKey` this handshake goes on to use, and it is derived from the
/// same bytes that end up in `server_public_blob`. Those bytes are authenticated
/// twice over, later in the handshake:
///
/// 1. `client_random` is RSA-encrypted *to this key*, and both session keys are
///    derived from it. A server that does not hold the matching private key
///    cannot produce a frame we can decrypt at all.
/// 2. The ServerHash frame is `H(server_blob || client_blob)`, sent under those
///    session keys. It binds the exact modulus/exponent bytes we fingerprinted
///    to the key that proved possession in (1).
///
/// Canonicalisation does not weaken that: it is a deterministic function of
/// `(n, e)`, so equal blobs give equal fingerprints, and the fingerprint cannot
/// be made to describe a key other than the one actually in use.
fn key_fingerprint(key: &RsaPublicKey) -> Result<String> {
    let spki = key
        .to_public_key_der()
        .map_err(|e| VncError::Protocol(format!("RA2 server key could not be encoded: {e}")))?;
    Ok(format_fingerprint(&Sha256::digest(spki.as_bytes())))
}

/// Compare the server's RSA key against the stored pin (PRD/10 §1.1, §4.3).
///
/// Mirrors the TLS verifier in `vnc-transport::tls`, minus the CA step, there
/// is no chain to validate here, so first contact always prompts.
///
/// `TrustDecision::Changed` is returned rather than raised; the caller turns it
/// into `VncError::CertificateMismatch`, which `needs_user_action()` marks as
/// terminal so the reconnect loop never retries into a suspected interceptor.
fn evaluate_trust(key: &RsaPublicKey, bits: u32, pin: Option<&str>) -> Result<TrustDecision> {
    let fingerprint = key_fingerprint(key)?;
    let actual = normalize_fingerprint(&fingerprint);

    // There is no X.509 subject to show, inventing a hostname here would be a
    // lie, since nothing in RA2 binds the key to a name. Say exactly what the
    // user is being asked to trust; the dialog already names the host it is
    // connecting to.
    let subject = format!("RealVNC RSA key ({bits}-bit)");

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
            },
        },
    )
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

pub(crate) async fn handshake(
    mut stream: BoxedStream,
    security_type: SecurityType,
    opts: &ConnectOptions,
    creds: &CredentialSource<'_>,
) -> Result<AuthOutcome> {
    let variant = Variant::of(security_type)
        .ok_or_else(|| VncError::UnsupportedSecurityType(security_type.to_wire()))?;

    // --- 1. server public key ---------------------------------------------
    let server_bits = read_u32(&mut stream).await?;
    if !(MIN_SERVER_KEY_BITS..=MAX_SERVER_KEY_BITS).contains(&server_bits) {
        return Err(VncError::Protocol(format!(
            "RA2 server key length {server_bits} bits is out of range"
        )));
    }
    let server_bytes = server_bits.div_ceil(8) as usize;
    let server_n = read_bytes_max(&mut stream, server_bytes, 1024, "RA2 server modulus").await?;
    let server_e = read_bytes_max(&mut stream, server_bytes, 1024, "RA2 server exponent").await?;

    let server_key = RsaPublicKey::new(
        BoxedUint::from_be_slice_vartime(&server_n),
        BoxedUint::from_be_slice_vartime(&server_e),
    )
    .map_err(|e| VncError::Protocol(format!("RA2 server sent an unusable RSA key: {e}")))?;

    // The public key blob exactly as it appeared on the wire, this is what the
    // hashes are computed over.
    let mut server_public_blob = Vec::with_capacity(4 + server_bytes * 2);
    server_public_blob.extend_from_slice(&server_bits.to_be_bytes());
    server_public_blob.extend_from_slice(&server_n);
    server_public_blob.extend_from_slice(&server_e);

    // --- 1a. server identity ----------------------------------------------
    // Before anything is encrypted *to* this key, and long before credentials
    // go anywhere near it, decide whether we recognise it.
    // Only the RA2 pin is consulted. This endpoint may also have a TLS pin
    // from a VeNCrypt connection; that fingerprint describes an X.509
    // certificate, not this RSA key, and comparing the two would report a
    // changed identity for a server that changed nothing.
    let trust = evaluate_trust(
        &server_key,
        server_bits,
        opts.cert_pins.for_scheme(PinScheme::Ra2),
    )?;
    match &trust {
        TrustDecision::PinnedMatch => tracing::info!("RA2 server key matches stored pin"),
        TrustDecision::Unknown { fingerprint, .. } => {
            // First contact. `authenticate_with_trust` carries this out to the
            // session layer, which raises the TOFU prompt.
            tracing::warn!(%fingerprint, "RA2 server key is not yet trusted (TOFU prompt required)");
        }
        TrustDecision::Changed { expected, actual } => {
            // HARD STOP. Never retried, never auto-accepted: the key changed,
            // which is what an interception looks like.
            return Err(VncError::CertificateMismatch {
                expected: expected.clone(),
                actual: actual.clone(),
            });
        }
        // No CA path exists for a bare RSA key.
        TrustDecision::VerifiedByCa => unreachable!("RA2 has no certificate authority"),
    }

    // --- 2. our public key -------------------------------------------------
    // RSA keygen is hundreds of milliseconds of pure CPU; keep it off the
    // reactor thread.
    let client_key =
        tokio::task::spawn_blocking(|| RsaPrivateKey::new(&mut rand::rng(), CLIENT_KEY_BITS))
            .await
            .map_err(|e| VncError::Other(format!("RSA key generation task failed: {e}")))?
            .map_err(|e| VncError::Other(format!("could not generate an RSA key: {e}")))?;
    let client_public = client_key.to_public_key();

    let client_n = left_pad(
        &client_public.n().as_ref().to_be_bytes_trimmed_vartime(),
        CLIENT_KEY_BYTES,
    );
    let client_e = left_pad(
        &client_public.e().to_be_bytes_trimmed_vartime(),
        CLIENT_KEY_BYTES,
    );

    let mut client_public_blob = Vec::with_capacity(4 + CLIENT_KEY_BYTES * 2);
    client_public_blob.extend_from_slice(&(CLIENT_KEY_BITS as u32).to_be_bytes());
    client_public_blob.extend_from_slice(&client_n);
    client_public_blob.extend_from_slice(&client_e);
    super::write_all(&mut stream, &client_public_blob).await?;

    // --- 3. exchange randoms ----------------------------------------------
    let mut client_random = [0u8; RANDOM_LEN];
    rand::rng().fill_bytes(&mut client_random);

    let encrypted = server_key
        .encrypt(&mut rand::rng(), Pkcs1v15Encrypt, &client_random)
        .map_err(|e| VncError::Other(format!("RA2: could not encrypt the client random: {e}")))?;
    super::write_all(&mut stream, &encrypted).await?;

    let server_encrypted = read_bytes_max(
        &mut stream,
        CLIENT_KEY_BYTES,
        CLIENT_KEY_BYTES,
        "RA2 server random",
    )
    .await?;
    let mut server_random = client_key
        .decrypt(Pkcs1v15Encrypt, &server_encrypted)
        .map_err(|_| {
            VncError::AuthFailed(
                "the server's authentication payload could not be decrypted".into(),
            )
        })?;
    if server_random.len() != RANDOM_LEN {
        server_random.zeroize();
        return Err(VncError::Protocol(
            "RA2 server random has the wrong length".into(),
        ));
    }

    // --- 4. session keys ---------------------------------------------------
    let key_len = variant.key_len();
    let mut client_session_key = variant.hash(&[&server_random, &client_random]);
    let mut server_session_key = variant.hash(&[&client_random, &server_random]);
    client_session_key.truncate(key_len);
    server_session_key.truncate(key_len);

    let mut send_cipher = Ra2Cipher::new(&client_session_key)?;
    let mut recv_cipher = Ra2Cipher::new(&server_session_key)?;
    client_session_key.zeroize();
    server_session_key.zeroize();
    client_random.zeroize();
    server_random.zeroize();

    // --- 5. mutual key confirmation ---------------------------------------
    let expected_server_hash = variant.hash(&[&server_public_blob, &client_public_blob]);
    let client_hash = variant.hash(&[&client_public_blob, &server_public_blob]);

    let received = recv_frame(&mut stream, &mut recv_cipher).await?;
    if received != expected_server_hash {
        return Err(VncError::AuthFailed(
            "the server failed to prove ownership of its key (RA2 hash mismatch)".into(),
        ));
    }
    send_frame(&mut stream, &mut send_cipher, &client_hash).await?;

    // --- 6. credentials ----------------------------------------------------
    let subtype = recv_frame(&mut stream, &mut recv_cipher).await?;
    let subtype = *subtype
        .first()
        .ok_or_else(|| VncError::Protocol("RA2 server sent an empty subtype".into()))?;

    // The subtype is only known now, so this is where we can ask the user for
    // exactly what the server wants, not before.
    let kind = credential_kind_for_subtype(subtype)
        .ok_or_else(|| VncError::Protocol(format!("unknown RA2 credential subtype {subtype}")))?;
    let supplied = creds.obtain(METHOD, kind, false, opts).await?;
    let password = supplied.password.unwrap_or_default();
    let username = match kind {
        CredentialKind::UsernameAndPassword => {
            let u = supplied.username.unwrap_or_default();
            if u.is_empty() {
                return Err(VncError::CredentialsRequired(
                    "this server requires a user name and password".into(),
                ));
            }
            u
        }
        // Subtype 2 authenticates the password alone; the field stays empty.
        CredentialKind::PasswordOnly => String::new(),
    };

    let mut credentials = encode_credentials(&username, &password)?;
    let sent = send_frame(&mut stream, &mut send_cipher, &credentials).await;
    credentials.zeroize();
    sent?;

    // --- 7. hand back the right stream ------------------------------------
    let mut outcome = if variant.encrypt_session {
        // Everything from the SecurityResult onwards stays inside the framing.
        let wrapped = Ra2Stream::new(stream, recv_cipher, send_cipher);
        AuthOutcome::auto(Box::pin(wrapped))
    } else {
        // "ne" = no encryption: the channel reverts to cleartext now.
        AuthOutcome::auto(stream)
    };
    // Reaching here means the key confirmation in step 5 succeeded, so the
    // fingerprint now describes a key the server proved it holds. That is what
    // the session layer may offer the user to pin.
    outcome.trust = Some(ServerIdentity {
        scheme: PinScheme::Ra2,
        decision: trust,
    });
    Ok(outcome)
}

/// `u8 user_len, user, u8 pass_len, pass`, both UTF-8.
fn encode_credentials(username: &str, password: &str) -> Result<Vec<u8>> {
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(VncError::Other(
            "the user name or password is too long for RealVNC authentication (255 bytes max)"
                .into(),
        ));
    }
    let mut out = Vec::with_capacity(2 + username.len() + password.len());
    out.push(username.len() as u8);
    out.extend_from_slice(username.as_bytes());
    out.push(password.len() as u8);
    out.extend_from_slice(password.as_bytes());
    Ok(out)
}

fn left_pad(bytes: &[u8], width: usize) -> Vec<u8> {
    if bytes.len() >= width {
        return bytes[bytes.len() - width..].to_vec();
    }
    let mut out = vec![0u8; width];
    out[width - bytes.len()..].copy_from_slice(bytes);
    out
}

// ---------------------------------------------------------------------------
// The encrypted stream
// ---------------------------------------------------------------------------

/// Wraps a stream in RA2's AES-EAX framing so the rest of the RFB session is
/// encrypted transparently.
pub struct Ra2Stream {
    inner: BoxedStream,
    recv: Ra2Cipher,
    send: Ra2Cipher,

    /// Raw bytes of the frame currently being read.
    in_raw: Vec<u8>,
    /// How many raw bytes the current frame needs (2 while reading the header).
    want: usize,
    /// Decrypted bytes not yet handed to the caller.
    plain: Vec<u8>,
    plain_pos: usize,

    /// Encrypted bytes not yet written to the inner stream.
    out: Vec<u8>,
    out_pos: usize,
}

impl Ra2Stream {
    fn new(inner: BoxedStream, recv: Ra2Cipher, send: Ra2Cipher) -> Self {
        Self {
            inner,
            recv,
            send,
            in_raw: Vec::with_capacity(2 + MAX_FRAME_PLAINTEXT + MAC_LEN),
            want: 2,
            plain: Vec::new(),
            plain_pos: 0,
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// Push buffered ciphertext at the inner stream. `Ok(true)` when drained.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        while self.out_pos < self.out.len() {
            match self
                .inner
                .as_mut()
                .poll_write(cx, &self.out[self.out_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "RA2 stream closed while writing",
                    )))
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(true))
    }
}

impl AsyncRead for Ra2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1. Serve anything already decrypted.
            if this.plain_pos < this.plain.len() {
                let n = buf.remaining().min(this.plain.len() - this.plain_pos);
                buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                if this.plain_pos == this.plain.len() {
                    this.plain.clear();
                    this.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 2. Complete the current frame.
            if this.in_raw.len() < this.want {
                let mut scratch = [0u8; 4096];
                let need = this.want - this.in_raw.len();
                let mut read_buf = ReadBuf::new(&mut scratch[..need.min(4096)]);
                match this.inner.as_mut().poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let filled = read_buf.filled();
                        if filled.is_empty() {
                            // Clean EOF only on a frame boundary.
                            return if this.in_raw.is_empty() && this.want == 2 {
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "RA2 stream ended mid-frame",
                                )))
                            };
                        }
                        this.in_raw.extend_from_slice(filled);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }

            // 3. Header complete -> learn the body length.
            if this.want == 2 {
                let len = u16::from_be_bytes([this.in_raw[0], this.in_raw[1]]) as usize;
                this.want = 2 + len + MAC_LEN;
                continue;
            }

            // 4. Whole frame present -> decrypt.
            let header = [this.in_raw[0], this.in_raw[1]];
            let body = this.in_raw[2..this.want].to_vec();
            this.in_raw.clear();
            this.want = 2;
            match this.recv.open(header, &body) {
                Ok(plain) => {
                    if plain.is_empty() {
                        // A zero-length frame carries nothing; keep reading.
                        continue;
                    }
                    this.plain = plain;
                    this.plain_pos = 0;
                }
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                }
            }
        }
    }
}

impl AsyncWrite for Ra2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Never accept new data while a previous frame is still going out, // otherwise a `Pending` here would force the caller to re-offer bytes
        // we had already encrypted.
        match this.poll_drain(cx) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(MAX_FRAME_PLAINTEXT);
        let frame = this
            .send
            .seal(&buf[..take])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        this.out = frame;
        this.out_pos = 0;

        // Opportunistic flush; whatever is left goes out on the next call.
        let _ = this.poll_drain(cx);
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(_)) => this.inner.as_mut().poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(_)) => this.inner.as_mut().poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// `Ra2Stream` is a `Stream` by the blanket impl; assert it so a future change
// to the bounds fails here rather than at every call site.
const _: fn() = || {
    fn assert_stream<T: Stream + 'static>() {}
    assert_stream::<Ra2Stream>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CertPins;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn variant_mapping() {
        assert_eq!(Variant::of(SecurityType::Ra2).unwrap().key_len(), 16);
        assert_eq!(Variant::of(SecurityType::Ra2_256).unwrap().key_len(), 32);
        assert!(Variant::of(SecurityType::Ra2).unwrap().encrypt_session);
        assert!(!Variant::of(SecurityType::Ra2ne).unwrap().encrypt_session);
        assert!(!Variant::of(SecurityType::Ra2ne256).unwrap().encrypt_session);
        assert!(Variant::of(SecurityType::VncAuth).is_none());
    }

    #[test]
    fn session_keys_are_directional() {
        let v = Variant::of(SecurityType::Ra2).unwrap();
        let server_random = [1u8; 16];
        let client_random = [2u8; 16];
        let mut a = v.hash(&[&server_random, &client_random]);
        let mut b = v.hash(&[&client_random, &server_random]);
        a.truncate(16);
        b.truncate(16);
        assert_ne!(a, b, "the two directions must not share a key");
        assert_eq!(a.len(), 16);

        let v256 = Variant::of(SecurityType::Ra2_256).unwrap();
        assert_eq!(v256.hash(&[&server_random, &client_random]).len(), 32);
    }

    #[test]
    fn frames_round_trip() {
        let key = [7u8; 16];
        let mut sender = Ra2Cipher::new(&key).unwrap();
        let mut receiver = Ra2Cipher::new(&key).unwrap();

        for i in 0..4u8 {
            let msg = vec![i; 40 + i as usize];
            let frame = sender.seal(&msg).unwrap();
            assert_eq!(
                u16::from_be_bytes([frame[0], frame[1]]) as usize,
                msg.len(),
                "header carries the plaintext length"
            );
            assert_eq!(frame.len(), 2 + msg.len() + MAC_LEN);
            let header = [frame[0], frame[1]];
            let out = receiver.open(header, &frame[2..]).unwrap();
            assert_eq!(out, msg);
        }
    }

    #[test]
    fn nonce_counter_advances_so_repeats_differ() {
        let key = [3u8; 32];
        let mut c = Ra2Cipher::new(&key).unwrap();
        let a = c.seal(b"same").unwrap();
        let b = c.seal(b"same").unwrap();
        assert_ne!(a, b, "the message counter must feed the nonce");
    }

    #[test]
    fn tampering_is_detected() {
        let key = [5u8; 16];
        let mut sender = Ra2Cipher::new(&key).unwrap();
        let mut receiver = Ra2Cipher::new(&key).unwrap();
        let mut frame = sender.seal(b"hello there").unwrap();
        frame[4] ^= 0x01;
        let header = [frame[0], frame[1]];
        assert!(receiver.open(header, &frame[2..]).is_err());
    }

    #[test]
    fn out_of_order_frames_are_rejected() {
        let key = [9u8; 16];
        let mut sender = Ra2Cipher::new(&key).unwrap();
        let mut receiver = Ra2Cipher::new(&key).unwrap();
        let first = sender.seal(b"one").unwrap();
        let second = sender.seal(b"two").unwrap();
        // Deliver the second frame first: the counters no longer line up.
        assert!(receiver.open([second[0], second[1]], &second[2..]).is_err());
        let _ = first;
    }

    #[test]
    fn rejects_bad_key_lengths() {
        assert!(Ra2Cipher::new(&[0u8; 24]).is_err());
    }

    #[test]
    fn credentials_encoding() {
        assert_eq!(
            encode_credentials("ab", "cde").unwrap(),
            vec![2, b'a', b'b', 3, b'c', b'd', b'e']
        );
        assert_eq!(encode_credentials("", "x").unwrap(), vec![0, 1, b'x']);
        assert!(encode_credentials(&"a".repeat(256), "x").is_err());
    }

    #[test]
    fn pads_public_key_components() {
        assert_eq!(left_pad(&[1, 0, 1], 5), vec![0, 0, 1, 0, 1]);
        assert_eq!(left_pad(&[1, 2, 3], 3), vec![1, 2, 3]);
    }

    /// Drive `Ra2Stream` against a peer using the mirror-image cipher pair, /// this is exactly the arrangement a real server has.
    #[tokio::test]
    async fn wrapped_stream_round_trips_through_a_peer() {
        let client_key = [0xA1u8; 16];
        let server_key = [0xB2u8; 32];

        let (a, b) = tokio::io::duplex(64 * 1024);

        // The "server" side: decode what the client sends, encode replies.
        let mut server_in = Ra2Cipher::new(&client_key).unwrap();
        let mut server_out = Ra2Cipher::new(&server_key).unwrap();

        let mut client = Ra2Stream::new(
            Box::pin(a),
            Ra2Cipher::new(&server_key).unwrap(), // recv
            Ra2Cipher::new(&client_key).unwrap(), // send
        );

        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        let server = tokio::spawn(async move {
            let mut b = b;
            // Read one frame from the client.
            let mut header = [0u8; 2];
            b.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes(header) as usize;
            let mut body = vec![0u8; len + MAC_LEN];
            b.read_exact(&mut body).await.unwrap();
            let got = server_in.open(header, &body).unwrap();

            // Reply with a SecurityResult-shaped message.
            let frame = server_out.seal(&0u32.to_be_bytes()).unwrap();
            b.write_all(&frame).await.unwrap();
            b.flush().await.unwrap();
            got
        });

        client
            .write_all(&payload[..MAX_FRAME_PLAINTEXT.min(payload.len())])
            .await
            .unwrap();
        client.flush().await.unwrap();

        let got = server.await.unwrap();
        assert_eq!(got, expected);

        let mut result = [0u8; 4];
        client.read_exact(&mut result).await.unwrap();
        assert_eq!(u32::from_be_bytes(result), 0);
    }

    /// Writes larger than one frame must be split, not truncated or merged.
    #[tokio::test]
    async fn long_writes_are_chunked_into_frames() {
        let key = [0x11u8; 16];
        let (a, mut b) = tokio::io::duplex(256 * 1024);
        let mut peer = Ra2Cipher::new(&key).unwrap();
        let mut client = Ra2Stream::new(
            Box::pin(a),
            Ra2Cipher::new(&key).unwrap(),
            Ra2Cipher::new(&key).unwrap(),
        );

        let payload = vec![0x5Au8; MAX_FRAME_PLAINTEXT + 100];
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            client
        });

        let mut assembled = Vec::new();
        while assembled.len() < expected.len() {
            let mut header = [0u8; 2];
            b.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes(header) as usize;
            assert!(len <= MAX_FRAME_PLAINTEXT);
            let mut body = vec![0u8; len + MAC_LEN];
            b.read_exact(&mut body).await.unwrap();
            assembled.extend_from_slice(&peer.open(header, &body).unwrap());
        }
        assert_eq!(assembled, expected);
        let _ = writer.await.unwrap();
    }

    /// A full handshake against a simulated RealVNC server built from the same
    /// specification. This exercises key generation, the public-key blobs, the
    /// RSA exchange, key derivation, the hash confirmation and the credential
    /// frame end to end. It cannot validate our reading of the *message order*
    /// against a real server (both sides here share our assumption), but it
    /// does catch every self-inconsistency.
    #[tokio::test]
    async fn full_handshake_against_a_simulated_server() {
        // One key for the whole test: it stands in for a single server that the
        // client meets repeatedly, which is what pinning is about.
        let server_key = tokio::task::spawn_blocking(|| RsaPrivateKey::new(&mut rand::rng(), 2048))
            .await
            .unwrap()
            .unwrap();
        let expected_fingerprint = key_fingerprint(&server_key.to_public_key()).unwrap();

        for (i, security_type) in [
            SecurityType::Ra2,
            SecurityType::Ra2_256,
            SecurityType::Ra2ne,
        ]
        .into_iter()
        .enumerate()
        {
            // First contact has nothing stored; afterwards the shell would have
            // saved the fingerprint the prompt showed.
            let stored_pin = (i > 0).then(|| expected_fingerprint.clone());

            let variant = Variant::of(security_type).unwrap();
            let (client_side, mut server_side) = tokio::io::duplex(128 * 1024);

            let server_key = server_key.clone();
            let server = tokio::spawn(async move {
                let server_pub = server_key.to_public_key();
                let server_n =
                    left_pad(&server_pub.n().as_ref().to_be_bytes_trimmed_vartime(), 256);
                let server_e = left_pad(&server_pub.e().to_be_bytes_trimmed_vartime(), 256);

                let mut server_blob = Vec::new();
                server_blob.extend_from_slice(&2048u32.to_be_bytes());
                server_blob.extend_from_slice(&server_n);
                server_blob.extend_from_slice(&server_e);
                server_side.write_all(&server_blob).await.unwrap();

                // Client public key.
                let mut client_blob = vec![0u8; 4 + 512];
                server_side.read_exact(&mut client_blob).await.unwrap();
                let client_pub = RsaPublicKey::new(
                    BoxedUint::from_be_slice_vartime(&client_blob[4..260]),
                    BoxedUint::from_be_slice_vartime(&client_blob[260..516]),
                )
                .unwrap();

                // Randoms.
                let mut encrypted = vec![0u8; 256];
                server_side.read_exact(&mut encrypted).await.unwrap();
                let client_random = server_key.decrypt(Pkcs1v15Encrypt, &encrypted).unwrap();

                let server_random = [0x5Au8; RANDOM_LEN];
                let out = client_pub
                    .encrypt(&mut rand::rng(), Pkcs1v15Encrypt, &server_random)
                    .unwrap();
                server_side.write_all(&out).await.unwrap();

                // Session keys, mirrored: the client's send key is ours to read.
                let key_len = variant.key_len();
                let mut recv_key = variant.hash(&[&server_random, &client_random]);
                let mut send_key = variant.hash(&[&client_random, &server_random]);
                recv_key.truncate(key_len);
                send_key.truncate(key_len);
                let mut recv = Ra2Cipher::new(&recv_key).unwrap();
                let mut send = Ra2Cipher::new(&send_key).unwrap();

                // Hash confirmation.
                let server_hash = variant.hash(&[&server_blob, &client_blob]);
                let expected_client_hash = variant.hash(&[&client_blob, &server_blob]);
                server_side
                    .write_all(&send.seal(&server_hash).unwrap())
                    .await
                    .unwrap();

                let got_client_hash = read_one_frame(&mut server_side, &mut recv).await;
                assert_eq!(got_client_hash, expected_client_hash);

                // Credentials.
                server_side
                    .write_all(&send.seal(&[1u8]).unwrap())
                    .await
                    .unwrap();
                let credentials = read_one_frame(&mut server_side, &mut recv).await;

                // SecurityResult, encrypted for RA2, cleartext for RA2ne.
                if variant.encrypt_session {
                    server_side
                        .write_all(&send.seal(&0u32.to_be_bytes()).unwrap())
                        .await
                        .unwrap();
                } else {
                    server_side.write_all(&0u32.to_be_bytes()).await.unwrap();
                }
                server_side.flush().await.unwrap();
                credentials
            });

            let mut o = ConnectOptions::new("h", 5900);
            o.credentials = crate::types::Credentials::user_pass("alice", "hunter2");
            o.cert_pins.ra2 = stored_pin.clone();
            // A TLS pin for the same endpoint must be ignored here: it
            // describes an X.509 certificate, not this RSA key.
            o.cert_pins.tls = Some("ff".repeat(32));
            let s: BoxedStream = Box::pin(client_side);
            let outcome = handshake(s, security_type, &o, &CredentialSource::none())
                .await
                .unwrap();

            // The identity check must not disturb the handshake, and must
            // report what the session layer needs to prompt with, including
            // which key was judged.
            let identity = outcome
                .trust
                .as_ref()
                .unwrap_or_else(|| panic!("RA2 must report an identity for {security_type:?}"));
            assert_eq!(identity.scheme, PinScheme::Ra2, "{security_type:?}");
            match (&identity.decision, &stored_pin) {
                (TrustDecision::Unknown { fingerprint, .. }, None) => {
                    assert_eq!(*fingerprint, expected_fingerprint, "{security_type:?}");
                }
                (TrustDecision::PinnedMatch, Some(_)) => {}
                other => panic!("unexpected trust decision for {security_type:?}: {other:?}"),
            }

            let credentials = server.await.unwrap();
            assert_eq!(
                credentials,
                encode_credentials("alice", "hunter2").unwrap(),
                "{security_type:?}"
            );

            // The SecurityResult must be readable through whatever stream we
            // were handed, framed for RA2, raw for RA2ne.
            let mut stream = outcome.stream;
            let mut result = [0u8; 4];
            stream.read_exact(&mut result).await.unwrap();
            assert_eq!(u32::from_be_bytes(result), 0, "{security_type:?}");
        }
    }

    async fn read_one_frame<S: tokio::io::AsyncRead + Unpin>(
        s: &mut S,
        cipher: &mut Ra2Cipher,
    ) -> Vec<u8> {
        let mut header = [0u8; 2];
        s.read_exact(&mut header).await.unwrap();
        let len = u16::from_be_bytes(header) as usize;
        let mut body = vec![0u8; len + MAC_LEN];
        s.read_exact(&mut body).await.unwrap();
        cipher.open(header, &body).unwrap()
    }

    // -----------------------------------------------------------------------
    // Server identity pinning
    // -----------------------------------------------------------------------

    /// A syntactically valid RSA public key. `n` must be odd and larger than
    /// `e`; nothing here needs it to be a real product of primes.
    fn test_key(seed: u8) -> RsaPublicKey {
        let mut n = vec![seed | 0x80; 256];
        n[255] |= 1;
        RsaPublicKey::new(
            BoxedUint::from_be_slice_vartime(&n),
            BoxedUint::from(65537u32),
        )
        .unwrap()
    }

    #[test]
    fn same_key_twice_is_a_pinned_match() {
        let key = test_key(0x31);
        let first = evaluate_trust(&key, 2048, None).unwrap();
        let TrustDecision::Unknown { fingerprint, .. } = first else {
            panic!("first contact must be Unknown, got {first:?}");
        };

        // What the shell would store and hand back on the next connect.
        let second = evaluate_trust(&key, 2048, Some(&fingerprint)).unwrap();
        assert_eq!(second, TrustDecision::PinnedMatch);

        // The stored form may have been normalised on its way through SQLite.
        let bare = normalize_fingerprint(&fingerprint);
        assert_eq!(
            evaluate_trust(&key, 2048, Some(&bare)).unwrap(),
            TrustDecision::PinnedMatch
        );
        assert_eq!(
            evaluate_trust(&key, 2048, Some(&bare.to_lowercase())).unwrap(),
            TrustDecision::PinnedMatch
        );
    }

    #[test]
    fn a_different_key_against_a_stored_pin_is_a_hard_stop() {
        let pinned = key_fingerprint(&test_key(0x31)).unwrap();
        let decision = evaluate_trust(&test_key(0x57), 2048, Some(&pinned)).unwrap();
        let TrustDecision::Changed { expected, actual } = decision else {
            panic!("a substituted key must be Changed, got {decision:?}");
        };
        assert_eq!(expected, normalize_fingerprint(&pinned));
        assert_ne!(normalize_fingerprint(&actual), expected);
    }

    #[test]
    fn no_pin_yields_a_stable_fingerprint() {
        let key = test_key(0x22);
        let a = evaluate_trust(&key, 2048, None).unwrap();
        let b = evaluate_trust(&key, 2048, None).unwrap();
        assert_eq!(a, b, "the fingerprint must not vary between calls");
        let TrustDecision::Unknown {
            fingerprint,
            subject,
        } = a
        else {
            panic!("expected Unknown");
        };
        // 32 bytes rendered as `XX:` pairs, exactly like the TLS prompt.
        assert_eq!(fingerprint.len(), 32 * 3 - 1);
        assert_eq!(
            fingerprint,
            format_fingerprint(&Sha256::digest(
                test_key(0x22).to_public_key_der().unwrap().as_bytes(),
            ))
        );
        assert_eq!(subject, "RealVNC RSA key (2048-bit)");
        // An empty stored pin is "no pin", not "a pin that never matches".
        assert!(matches!(
            evaluate_trust(&key, 2048, Some("")).unwrap(),
            TrustDecision::Unknown { .. }
        ));
    }

    /// The wire encoding is not canonical: `bits` is the server's own claim and
    /// the components are `ceil(bits/8)` bytes whatever their magnitude. One key
    /// must not get two fingerprints by re-padding, or a pin could be dodged.
    #[test]
    fn padding_does_not_change_the_fingerprint() {
        let n = {
            let mut v = vec![0x9Fu8; 256];
            v[255] |= 1;
            v
        };
        let e = 65537u32;

        // As sent by an honest 2048-bit server.
        let tight =
            RsaPublicKey::new(BoxedUint::from_be_slice_vartime(&n), BoxedUint::from(e)).unwrap();

        // The same key claiming 2056 bits, with a leading zero byte on the
        // modulus, and an exponent padded out to full width, which is what
        // RealVNC actually puts on the wire.
        let mut padded_n = vec![0u8];
        padded_n.extend_from_slice(&n);
        let padded_e = left_pad(&e.to_be_bytes(), 257);
        let loose = RsaPublicKey::new(
            BoxedUint::from_be_slice_vartime(&padded_n),
            BoxedUint::from_be_slice_vartime(&padded_e),
        )
        .unwrap();

        assert_eq!(
            key_fingerprint(&tight).unwrap(),
            key_fingerprint(&loose).unwrap(),
            "re-padding one key must not produce a second fingerprint"
        );
        // ...and the declared bit count, which only feeds the display string,
        // must not feed the fingerprint either.
        let a = evaluate_trust(&tight, 2048, None).unwrap();
        let b = evaluate_trust(&loose, 2056, None).unwrap();
        match (a, b) {
            (
                TrustDecision::Unknown {
                    fingerprint: fa, ..
                },
                TrustDecision::Unknown {
                    fingerprint: fb, ..
                },
            ) => assert_eq!(fa, fb),
            other => panic!("expected two Unknowns, got {other:?}"),
        }
    }

    /// End to end: a stored pin for a *different* key must abort the handshake
    /// before any credential or random reaches the server, and must be terminal.
    #[tokio::test]
    async fn handshake_aborts_on_a_changed_server_key() {
        let (client, mut server) = tokio::io::duplex(4096);

        // The key an interceptor presents.
        let key = test_key(0xC3);
        let n = left_pad(&key.n().as_ref().to_be_bytes_trimmed_vartime(), 256);
        let e = left_pad(&key.e().to_be_bytes_trimmed_vartime(), 256);
        let mut blob = Vec::new();
        blob.extend_from_slice(&2048u32.to_be_bytes());
        blob.extend_from_slice(&n);
        blob.extend_from_slice(&e);
        server.write_all(&blob).await.unwrap();

        let mut o = ConnectOptions::new("h", 5900);
        o.credentials = crate::types::Credentials::password("pw");
        // The pin we saved on a previous, honest connection.
        o.cert_pins = CertPins::one(PinScheme::Ra2, key_fingerprint(&test_key(0x31)).unwrap());

        let s: BoxedStream = Box::pin(client);
        let err = match handshake(s, SecurityType::Ra2, &o, &CredentialSource::none()).await {
            Err(e) => e,
            Ok(_) => panic!("a changed server key must abort the handshake"),
        };
        assert!(
            matches!(err, VncError::CertificateMismatch { .. }),
            "got {err:?}"
        );
        assert!(
            err.needs_user_action(),
            "a mismatch must never be auto-retried"
        );

        // Nothing was sent back: the client did not reveal its public key, its
        // random, or anything derived from a credential.
        drop(o);
        let mut leaked = Vec::new();
        server.shutdown().await.ok();
        server.read_to_end(&mut leaked).await.unwrap();
        assert!(
            leaked.is_empty(),
            "{} bytes sent to an unknown key",
            leaked.len()
        );
    }

    #[tokio::test]
    async fn rejects_an_absurd_server_key_length() {
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(&99_999u32.to_be_bytes()).await.unwrap();
        let mut o = ConnectOptions::new("h", 5900);
        o.credentials = crate::types::Credentials::password("pw");
        let s: BoxedStream = Box::pin(client);
        assert!(matches!(
            handshake(s, SecurityType::Ra2, &o, &CredentialSource::none()).await,
            Err(VncError::Protocol(_))
        ));
    }
}
