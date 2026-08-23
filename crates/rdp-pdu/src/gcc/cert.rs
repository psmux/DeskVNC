//! The server certificate of `TS_UD_SC_SEC1` (PRDRDP/13 §4.5, MS-RDPBCGR
//! 2.2.1.4.3.1).
//!
//! **This parser verifies nothing, derives nothing and holds no key
//! material.** Standard RDP Security is out of scope (PRDRDP/03 §13.1, D6),
//! so there is no RC4 session key to derive and the certificate is never used
//! to encrypt anything. There is in particular no signature check of the
//! proprietary certificate against Microsoft's hard coded terminal services
//! public key, because a signature check on a certificate we will never use
//! is theatre, and because PRDRDP/00 R54 puts every cryptographic operation
//! in a library rather than in this crate.
//!
//! Why parse it at all. Three reasons, all of them about failing well rather
//! than failing weirdly:
//!
//! 1. The whole block gets consumed, so a length mismatch is reported as a
//!    length mismatch instead of corrupting the block that follows.
//! 2. PRDRDP/03 can say "this server offers only standard RDP security (128
//!    bit RC4), which this client does not implement" and include the key
//!    size, which is the message a user of an old xrdp or a Windows Server
//!    2003 box needs.
//! 3. The mock server can exercise the path.
//!
//! It is a fuzz target (PRDRDP/13 §9.4) despite being a path we never use in
//! anger, because it is reachable by a hostile server before any
//! authentication has happened.

use crate::io::limits::MAX_GCC_USER_DATA;
use crate::io::{PduError, PduResult, Reader};

/// The structure's name in the specification, and the `context` of every
/// error this module raises.
const NAME: &str = "SERVER_CERTIFICATE";

/// `CERT_CHAIN_VERSION_1`: a Server Proprietary Certificate
/// (MS-RDPBCGR 2.2.1.4.3.1.1).
pub const CERT_CHAIN_VERSION_1: u32 = 0x0000_0001;

/// `CERT_CHAIN_VERSION_2`: an X.509 certificate chain
/// (MS-RDPBCGR 2.2.1.4.3.1.2).
pub const CERT_CHAIN_VERSION_2: u32 = 0x0000_0002;

/// The mask that separates the version from the `t` flag in `dwVersion`.
pub const CERT_CHAIN_VERSION_MASK: u32 = 0x7fff_ffff;

/// `BB_RSA_KEY_BLOB`.
pub const BB_RSA_KEY_BLOB: u16 = 0x0006;

/// `BB_RSA_SIGNATURE_BLOB`.
pub const BB_RSA_SIGNATURE_BLOB: u16 = 0x0008;

/// The `RSA1` magic of an `RSA_PUBLIC_KEY` (MS-RDPBCGR 2.2.1.4.3.1.1.1),
/// little endian, so the bytes on the wire read `52 53 41 31`.
pub const RSA_MAGIC: u32 = 0x3141_5352;

/// `RSA_PUBLIC_KEY` (MS-RDPBCGR 2.2.1.4.3.1.1.1), parsed as far as its
/// declared lengths so a truncation is caught.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPublicKey<'a> {
    /// `magic`, [`RSA_MAGIC`].
    pub magic: u32,
    /// `keylen`, the length of `modulus` including its eight padding bytes.
    pub keylen: u32,
    /// `bitlen`, the key size in bits, which is what the error message needs.
    pub bitlen: u32,
    /// `datalen`.
    pub datalen: u32,
    /// `pubExp`, the public exponent.
    pub pub_exp: u32,
    /// `modulus`, borrowed and never used.
    pub modulus: &'a [u8],
}

/// `PROPRIETARY_CERTIFICATE` (MS-RDPBCGR 2.2.1.4.3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProprietaryCertificate<'a> {
    /// `dwSigAlgId`, 1.
    pub dw_sig_alg_id: u32,
    /// `dwKeyAlgId`, 1.
    pub dw_key_alg_id: u32,
    /// `wPublicKeyBlobType`, [`BB_RSA_KEY_BLOB`].
    pub public_key_blob_type: u16,
    /// The `RSA_PUBLIC_KEY` inside `PublicKeyBlob`.
    pub public_key: RsaPublicKey<'a>,
    /// `wSignatureBlobType`, [`BB_RSA_SIGNATURE_BLOB`].
    pub signature_blob_type: u16,
    /// `SignatureBlob`, borrowed and never checked.
    pub signature: &'a [u8],
}

/// The X.509 chain variant (MS-RDPBCGR 2.2.1.4.3.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509CertificateChain<'a> {
    /// `CertBlobArray`, each `abCert` as a borrowed slice. The leaf is the
    /// last entry, per 2.2.1.4.3.1.2.
    pub certificates: Vec<&'a [u8]>,
}

/// What `TS_UD_SC_SEC1.serverCertificate` held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerCertificate<'a> {
    /// `CERT_CHAIN_VERSION_1`.
    Proprietary(ProprietaryCertificate<'a>),
    /// `CERT_CHAIN_VERSION_2`.
    X509Chain(X509CertificateChain<'a>),
}

impl ServerCertificate<'_> {
    /// The RSA key size in bits, for the error message PRDRDP/03 shows when
    /// it refuses a standard security server. `None` for an X.509 chain,
    /// whose key size lives inside a certificate this crate does not walk.
    #[must_use]
    pub fn key_size_bits(&self) -> Option<u32> {
        match self {
            Self::Proprietary(c) => Some(c.public_key.bitlen),
            Self::X509Chain(_) => None,
        }
    }
}

/// Parse `TS_UD_SC_SEC1.serverCertificate`.
///
/// The `t` flag in bit 31 of `dwVersion` is stripped before the version is
/// matched, per MS-RDPBCGR 2.2.1.4.3.1.
pub fn parse_server_certificate(bytes: &[u8]) -> PduResult<ServerCertificate<'_>> {
    let mut r = Reader::new(bytes);
    let at = r.offset();
    let dw_version = r.u32(NAME)?;
    match dw_version & CERT_CHAIN_VERSION_MASK {
        CERT_CHAIN_VERSION_1 => Ok(ServerCertificate::Proprietary(read_proprietary(&mut r)?)),
        CERT_CHAIN_VERSION_2 => Ok(ServerCertificate::X509Chain(read_x509_chain(&mut r)?)),
        other => Err(PduError::Unsupported {
            context: NAME,
            kind: "dwVersion",
            value: u64::from(other),
            offset: at,
        }),
    }
}

fn read_proprietary<'a>(r: &mut Reader<'a>) -> PduResult<ProprietaryCertificate<'a>> {
    let dw_sig_alg_id = r.u32(NAME)?;
    let dw_key_alg_id = r.u32(NAME)?;
    let public_key_blob_type = r.u16(NAME)?;
    let key_blob_len = usize::from(r.u16(NAME)?);
    let mut key_blob = r.take(key_blob_len, NAME)?;
    let public_key = read_rsa_public_key(&mut key_blob)?;
    let signature_blob_type = r.u16(NAME)?;
    let signature_blob_len = usize::from(r.u16(NAME)?);
    let signature = r.slice(signature_blob_len, NAME)?;
    Ok(ProprietaryCertificate {
        dw_sig_alg_id,
        dw_key_alg_id,
        public_key_blob_type,
        public_key,
        signature_blob_type,
        signature,
    })
}

fn read_rsa_public_key<'a>(r: &mut Reader<'a>) -> PduResult<RsaPublicKey<'a>> {
    let at = r.offset();
    let magic = r.u32(NAME)?;
    if magic != RSA_MAGIC {
        return Err(PduError::InvalidField {
            context: NAME,
            field: "RSA_PUBLIC_KEY.magic",
            value: u64::from(magic),
            offset: at,
        });
    }
    let keylen = r.u32(NAME)?;
    let bitlen = r.u32(NAME)?;
    let datalen = r.u32(NAME)?;
    let pub_exp = r.u32(NAME)?;
    // `keylen` is attacker controlled, so it is bounded before it becomes a
    // slice length. The sub reader would bound it anyway; the explicit check
    // is what names the cap in the log line.
    let keylen_usize = keylen as usize;
    r.ensure_cap(keylen_usize, MAX_GCC_USER_DATA, "MAX_GCC_USER_DATA", NAME)?;
    let modulus = r.slice(keylen_usize, NAME)?;
    Ok(RsaPublicKey {
        magic,
        keylen,
        bitlen,
        datalen,
        pub_exp,
        modulus,
    })
}

fn read_x509_chain<'a>(r: &mut Reader<'a>) -> PduResult<X509CertificateChain<'a>> {
    let num_cert_blobs = r.u32(NAME)?;
    // No `with_capacity`: `NumCertBlobs` is a remote `u32` and reserving
    // against it is the allocation this crate exists to avoid (D11). The loop
    // ends on the first read past the end of the block.
    let mut certificates = Vec::new();
    for _ in 0..num_cert_blobs {
        let len = r.u32(NAME)? as usize;
        r.ensure_cap(len, MAX_GCC_USER_DATA, "MAX_GCC_USER_DATA", NAME)?;
        certificates.push(r.slice(len, NAME)?);
    }
    Ok(X509CertificateChain { certificates })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;

    /// A proprietary certificate with a 512 bit key, which is what a Windows
    /// Server 2003 era host offers.
    fn proprietary_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&CERT_CHAIN_VERSION_1.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // dwSigAlgId
        out.extend_from_slice(&1u32.to_le_bytes()); // dwKeyAlgId
        out.extend_from_slice(&BB_RSA_KEY_BLOB.to_le_bytes());
        // 20 bytes of RSA_PUBLIC_KEY header plus a 72 byte modulus.
        out.extend_from_slice(&(20u16 + 72).to_le_bytes());
        out.extend_from_slice(&RSA_MAGIC.to_le_bytes());
        out.extend_from_slice(&72u32.to_le_bytes()); // keylen
        out.extend_from_slice(&512u32.to_le_bytes()); // bitlen
        out.extend_from_slice(&64u32.to_le_bytes()); // datalen
        out.extend_from_slice(&65537u32.to_le_bytes()); // pubExp
        out.extend_from_slice(&[0xab; 72]);
        out.extend_from_slice(&BB_RSA_SIGNATURE_BLOB.to_le_bytes());
        out.extend_from_slice(&72u16.to_le_bytes());
        out.extend_from_slice(&[0xcd; 72]);
        out
    }

    #[test]
    fn a_proprietary_certificate_parses_as_far_as_its_lengths() {
        let bytes = proprietary_bytes();
        let cert = parse_server_certificate(&bytes).unwrap();
        let ServerCertificate::Proprietary(p) = &cert else {
            panic!("expected the proprietary variant");
        };
        assert_eq!(p.dw_sig_alg_id, 1);
        assert_eq!(p.public_key_blob_type, BB_RSA_KEY_BLOB);
        assert_eq!(p.public_key.bitlen, 512);
        assert_eq!(p.public_key.pub_exp, 65537);
        assert_eq!(p.public_key.modulus.len(), 72);
        assert_eq!(p.signature.len(), 72);
        assert_eq!(cert.key_size_bits(), Some(512));
        // Zero copy: the modulus points into the block rather than at a copy.
        assert!(std::ptr::eq(
            p.public_key.modulus.as_ptr(),
            bytes[36..].as_ptr()
        ));
    }

    /// The `t` flag in bit 31 is stripped before the version is matched.
    #[test]
    fn the_t_flag_does_not_change_the_version() {
        let mut bytes = proprietary_bytes();
        bytes[3] |= 0x80;
        assert!(matches!(
            parse_server_certificate(&bytes).unwrap(),
            ServerCertificate::Proprietary(_)
        ));
    }

    #[test]
    fn an_x509_chain_exposes_each_certificate_as_a_slice() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CERT_CHAIN_VERSION_2.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[0x05, 0x06, 0x07]);
        let cert = parse_server_certificate(&bytes).unwrap();
        let ServerCertificate::X509Chain(chain) = &cert else {
            panic!("expected the chain variant");
        };
        assert_eq!(chain.certificates.len(), 2);
        assert_eq!(chain.certificates[1], &[0x05, 0x06, 0x07]);
        assert_eq!(cert.key_size_bits(), None);
    }

    #[test]
    fn an_unknown_version_is_unsupported_rather_than_guessed_at() {
        let bytes = [0x07, 0x00, 0x00, 0x00];
        assert!(matches!(
            parse_server_certificate(&bytes).unwrap_err(),
            PduError::Unsupported { .. }
        ));
    }

    #[test]
    fn a_wrong_rsa_magic_is_rejected() {
        let mut bytes = proprietary_bytes();
        bytes[16] = 0x00;
        assert!(matches!(
            parse_server_certificate(&bytes).unwrap_err(),
            PduError::InvalidField { .. }
        ));
    }

    /// A `NumCertBlobs` of four billion must not reserve four billion slots,
    /// and a `cbCert` of two gigabytes must not become a slice length.
    #[test]
    fn hostile_lengths_are_refused_rather_than_allocated() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CERT_CHAIN_VERSION_2.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        assert!(parse_server_certificate(&bytes).is_err());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CERT_CHAIN_VERSION_2.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0x7fff_ffffu32.to_le_bytes());
        let err = parse_server_certificate(&bytes).unwrap_err();
        assert!(matches!(
            err,
            PduError::CapExceeded {
                limit_name: "MAX_GCC_USER_DATA",
                ..
            }
        ));

        // The same for the proprietary variant's `keylen`.
        let mut bytes = proprietary_bytes();
        bytes[20..24].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        assert!(parse_server_certificate(&bytes).is_err());
    }

    #[test]
    fn every_prefix_of_every_certificate_errors_without_panicking() {
        let proprietary = proprietary_bytes();
        for cut in 0..proprietary.len() {
            assert!(
                parse_server_certificate(&proprietary[..cut]).is_err(),
                "proprietary certificate truncated to {cut} bytes parsed"
            );
        }
    }
}
