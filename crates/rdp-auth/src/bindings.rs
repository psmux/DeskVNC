//! RFC 5929 `tls-server-end-point` channel bindings, and the AV pair that
//! carries them.
//!
//! PRDRDP/14 §3.12 owns this. Three things happen here and they are worth
//! keeping apart:
//!
//! 1. Which hash RFC 5929 §4 selects, from the certificate's signature
//!    algorithm OID. That is [`hash_for_signature_algorithm`], a pure table.
//! 2. How RFC 2744 §3.11's `gss_channel_bindings_struct` is packed around the
//!    resulting digest. That is [`gss_channel_bindings_struct`].
//! 3. The MD5 of that structure, which is the value of the
//!    `MsvAvChannelBindings` AV pair (MS-NLMP 2.2.2.1, `AvId = 0x000A`). That
//!    is [`ChannelBindings`].
//!
//! The certificate itself is not opened here. The session reads the
//! `signatureAlgorithm` OID with the DER walker in `rdp-pdu` and hands both
//! the OID and the leaf DER in, which is R47's list. This crate never sees a
//! `rustls-pki-types` type.
//!
//! ## Why the substitution branch matters
//!
//! RFC 5929 §4 substitutes SHA-256 whenever the certificate's own signature
//! hash is MD5, SHA-1, or absent. Getting that wrong is silent: the client
//! would hash with SHA-1, the server with SHA-256, `NTProofStr` would not
//! match, and the user would be told their password is wrong. Under
//! PRDRDP/00 R55 a Windows 7 SP1 or Server 2008 R2 host is a supported target
//! on the legacy TLS backend, and those hosts mint `sha1WithRSAEncryption`
//! listener certificates, so this branch runs against real hosts rather than
//! sitting in the table for completeness.
//!
//! The client must never infer the hash from the host version. A Server 2022
//! host behind an enterprise CA that still signs with SHA-1 presents a SHA-1
//! certificate, and a Server 2008 R2 host behind a modern CA presents a
//! SHA-256 one. Read the OID, look it up.
//!
//! ## Known risk
//!
//! An unrecognised signature algorithm falls back to SHA-256 with a warning,
//! which is a deviation from RFC 5929 (it says the binding is undefined).
//! Refusing to authenticate against an algorithm we do not recognise is a
//! worse outcome than sending a binding a permissive server ignores, and a
//! server enforcing Extended Protection rejects a wrong binding cleanly. The
//! warning names the OID so the table can be extended.

use md5::{Digest, Md5};
use sha2::{Sha256, Sha384, Sha512};

/// The RFC 5929 §4 prefix, 21 bytes, no NUL terminator.
const APPLICATION_DATA_PREFIX: &[u8] = b"tls-server-end-point:";

/// Which hash RFC 5929 §4 selects for a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndPointHash {
    /// SHA-256, either the certificate's own hash or the RFC 5929
    /// substitution for MD5, SHA-1 and anything unrecognised.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl EndPointHash {
    /// The digest length in bytes, which decides the size of the packed
    /// structure.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            EndPointHash::Sha256 => 32,
            EndPointHash::Sha384 => 48,
            EndPointHash::Sha512 => 64,
        }
    }
}

// The `signatureAlgorithm` OIDs, as DER OBJECT IDENTIFIER *contents* with no
// tag and no length, which is what the walker in `rdp-pdu` returns. Every
// value is transcribed from the registry entry named in the comment, not
// typed from memory (PRDRDP/14 §9.2, the transcription rule).
/// 1.2.840.113549.1.1.4, md5WithRSAEncryption (PKCS #1).
const OID_MD5_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04];
/// 1.2.840.113549.1.1.5, sha1WithRSAEncryption (PKCS #1).
const OID_SHA1_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
/// 1.2.840.113549.1.1.10, RSASSA-PSS (PKCS #1).
const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
/// 1.2.840.113549.1.1.11, sha256WithRSAEncryption (PKCS #1).
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
/// 1.2.840.113549.1.1.12, sha384WithRSAEncryption (PKCS #1).
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
/// 1.2.840.113549.1.1.13, sha512WithRSAEncryption (PKCS #1).
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
/// 1.2.840.10045.4.1, ecdsa-with-SHA1 (ANSI X9.62).
const OID_ECDSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
/// 1.2.840.10045.4.3.2, ecdsa-with-SHA256 (ANSI X9.62).
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// 1.2.840.10045.4.3.3, ecdsa-with-SHA384 (ANSI X9.62).
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// 1.2.840.10045.4.3.4, ecdsa-with-SHA512 (ANSI X9.62).
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];

/// RFC 5929 §4: the hash the `tls-server-end-point` binding uses, from the
/// certificate's `signatureAlgorithm` OID contents.
///
/// "The hash of the certificate ... using the hash algorithm associated with
/// the certificate's signature algorithm ... if the certificate's signature
/// algorithm uses no hash, or uses MD5 or SHA-1, then SHA-256 is used
/// instead."
#[must_use]
pub fn hash_for_signature_algorithm(oid: &[u8]) -> EndPointHash {
    match oid {
        // The substitution cases. MD5 and SHA-1 are named by RFC 5929; PSS
        // carries its hash in parameters we do not parse, so it takes the
        // same default Windows uses.
        OID_MD5_RSA | OID_SHA1_RSA | OID_ECDSA_SHA1 | OID_RSASSA_PSS => EndPointHash::Sha256,
        OID_SHA256_RSA | OID_ECDSA_SHA256 => EndPointHash::Sha256,
        OID_SHA384_RSA | OID_ECDSA_SHA384 => EndPointHash::Sha384,
        OID_SHA512_RSA | OID_ECDSA_SHA512 => EndPointHash::Sha512,
        other => {
            tracing::warn!(
                oid = %hex_oid(other),
                "unrecognised certificate signature algorithm; using SHA-256 for the channel binding"
            );
            EndPointHash::Sha256
        }
    }
}

/// The certificate digest RFC 5929 §4 asks for.
///
/// Every branch is a call into `sha2`; nothing here computes a hash
/// (AGENT_BRIEF V3-A, PRDRDP/14 §2.10).
#[must_use]
pub fn certificate_digest(cert_der: &[u8], signature_algorithm_oid: &[u8]) -> Vec<u8> {
    match hash_for_signature_algorithm(signature_algorithm_oid) {
        EndPointHash::Sha256 => Sha256::digest(cert_der).to_vec(),
        EndPointHash::Sha384 => Sha384::digest(cert_der).to_vec(),
        EndPointHash::Sha512 => Sha512::digest(cert_der).to_vec(),
    }
}

/// RFC 2744 §3.11's `gss_channel_bindings_struct`, laid out as GSS-API
/// implementations serialise it, all lengths little endian.
///
/// ```text
/// initiator_addrtype        u32 = 0        (GSS_C_NO_ADDRESS)
/// initiator_address.length  u32 = 0
/// acceptor_addrtype         u32 = 0
/// acceptor_address.length   u32 = 0
/// application_data.length   u32 = 21 + hash_len
/// application_data          "tls-server-end-point:" || hash
/// ```
///
/// With SHA-256 the whole structure is 20 + 21 + 32 = 73 bytes. A 20 byte
/// SHA-1 digest would make it 61, which is why the length is worth asserting
/// in a test before the digest is.
#[must_use]
pub fn gss_channel_bindings_struct(certificate_hash: &[u8]) -> Vec<u8> {
    let app_len = APPLICATION_DATA_PREFIX.len() + certificate_hash.len();
    let mut out = Vec::with_capacity(20 + app_len);
    // initiator_addrtype, initiator_address.length, acceptor_addrtype,
    // acceptor_address.length: four zero u32s, GSS_C_NO_ADDRESS throughout.
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&u32::try_from(app_len).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(APPLICATION_DATA_PREFIX);
    out.extend_from_slice(certificate_hash);
    out
}

/// The value of the `MsvAvChannelBindings` AV pair: an MD5 of the packed
/// `gss_channel_bindings_struct` (MS-NLMP 2.2.2.1, `AvId = 0x000A`).
///
/// MD5 here is a wire format, not a security choice, exactly as MD4 is in
/// `NTOWFv2`.
///
/// The AV pair goes in the `AvPairs` field of the NTLMv2 client challenge, so
/// it is covered by `NTProofStr`, which is keyed with a value derived from the
/// password. An interceptor cannot rewrite it. It is covered by the MIC too,
/// which is the other half of the reason the MIC exists.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChannelBindings {
    md5: [u8; 16],
}

impl ChannelBindings {
    /// From a certificate hash the session has already computed.
    ///
    /// This is the production entry point: the TLS layer owns the
    /// certificate, this crate owns the structure.
    #[must_use]
    pub fn from_certificate_hash(certificate_hash: &[u8]) -> Self {
        let packed = gss_channel_bindings_struct(certificate_hash);
        ChannelBindings {
            md5: Md5::digest(&packed).into(),
        }
    }

    /// From the leaf certificate DER and its `signatureAlgorithm` OID, doing
    /// the RFC 5929 hash selection here.
    ///
    /// Convenient for tests and for a caller that would otherwise have to
    /// depend on `sha2` only to pick a digest.
    #[must_use]
    pub fn from_certificate(cert_der: &[u8], signature_algorithm_oid: &[u8]) -> Self {
        let hash = certificate_digest(cert_der, signature_algorithm_oid);
        Self::from_certificate_hash(&hash)
    }

    /// The 16 bytes that go in the AV pair.
    #[must_use]
    pub fn value(&self) -> &[u8; 16] {
        &self.md5
    }
}

impl std::fmt::Debug for ChannelBindings {
    /// The binding is not a secret, but it is derived from the connection and
    /// there is no reason for it to reach a log, so it prints as a shape.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelBindings(16 bytes)")
    }
}

/// Dotted form of a DER OID's contents, for the one `warn!` above.
fn hex_oid(oid: &[u8]) -> String {
    oid.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_5929_substitutes_sha256_for_md5_and_sha1() {
        // One assertion per row of PRDRDP/14 §3.12's table.
        assert_eq!(
            hash_for_signature_algorithm(OID_MD5_RSA),
            EndPointHash::Sha256
        );
        assert_eq!(
            hash_for_signature_algorithm(OID_SHA1_RSA),
            EndPointHash::Sha256
        );
        assert_eq!(
            hash_for_signature_algorithm(OID_ECDSA_SHA1),
            EndPointHash::Sha256
        );
        assert_eq!(
            hash_for_signature_algorithm(OID_RSASSA_PSS),
            EndPointHash::Sha256
        );
        assert_eq!(
            hash_for_signature_algorithm(OID_SHA256_RSA),
            EndPointHash::Sha256
        );
        assert_eq!(
            hash_for_signature_algorithm(OID_SHA384_RSA),
            EndPointHash::Sha384
        );
        assert_eq!(
            hash_for_signature_algorithm(OID_SHA512_RSA),
            EndPointHash::Sha512
        );
        assert_eq!(
            hash_for_signature_algorithm(OID_ECDSA_SHA256),
            EndPointHash::Sha256
        );
        assert_eq!(
            hash_for_signature_algorithm(OID_ECDSA_SHA384),
            EndPointHash::Sha384
        );
        assert_eq!(
            hash_for_signature_algorithm(OID_ECDSA_SHA512),
            EndPointHash::Sha512
        );
        // Anything else, including an empty OID, falls back to SHA-256.
        assert_eq!(hash_for_signature_algorithm(&[]), EndPointHash::Sha256);
        assert_eq!(
            hash_for_signature_algorithm(&[0x2a, 0x03, 0x04]),
            EndPointHash::Sha256
        );
    }

    #[test]
    fn the_packed_structure_is_73_bytes_for_sha256() {
        // 20 bytes of zero address fields and lengths, 21 bytes of prefix, 32
        // bytes of digest. A SHA-1 digest would make it 61, so this length
        // catches the wrong hash before any digest comparison does.
        let packed = gss_channel_bindings_struct(&[0u8; 32]);
        assert_eq!(packed.len(), 73);
        assert_eq!(&packed[..16], &[0u8; 16]);
        assert_eq!(&packed[16..20], &53u32.to_le_bytes());
        assert_eq!(&packed[20..41], b"tls-server-end-point:");
        assert_eq!(&packed[41..], &[0u8; 32]);

        assert_eq!(gss_channel_bindings_struct(&[0u8; 48]).len(), 89);
        assert_eq!(gss_channel_bindings_struct(&[0u8; 64]).len(), 105);
    }

    #[test]
    fn a_sha1_signed_certificate_is_hashed_with_sha256() {
        // The branch a Server 2008 R2 listener exercises on every connection.
        let cert = b"not a real certificate, but the OID decides the hash";
        let by_oid = certificate_digest(cert, OID_SHA1_RSA);
        assert_eq!(by_oid.len(), 32, "SHA-1 would be 20 bytes");
        assert_eq!(by_oid, Sha256::digest(cert).to_vec());

        // And the binding built from it is the binding built from the hash.
        assert_eq!(
            ChannelBindings::from_certificate(cert, OID_SHA1_RSA),
            ChannelBindings::from_certificate_hash(&by_oid)
        );
    }

    #[test]
    fn the_binding_is_the_md5_of_the_packed_structure() {
        let hash = [0xabu8; 32];
        let expected: [u8; 16] = Md5::digest(gss_channel_bindings_struct(&hash)).into();
        assert_eq!(
            ChannelBindings::from_certificate_hash(&hash).value(),
            &expected
        );
    }
}
