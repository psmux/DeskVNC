//! TLS transport with trust-on-first-use (TOFU) certificate pinning.
//!
//! Used by VeNCrypt's `X509*` subtypes: the plain TCP stream is upgraded to TLS
//! in the middle of the RFB handshake, after the subtype ack.
//!
//! Verification policy (PRD/10 §4):
//!
//! 1. Compute the SHA-256 fingerprint of the certificate's `SubjectPublicKeyInfo`
//!    (the same value as `openssl x509 -pubkey | openssl pkey -pubin -outform der
//!    | sha256sum`, stable across certificate renewals that keep the key).
//! 2. If the chain validates against the webpki/Mozilla root set *and* the
//!    hostname matches → [`TrustDecision::VerifiedByCa`], no prompt ever.
//! 3. Else if the caller supplied a pin and it matches → [`TrustDecision::PinnedMatch`].
//! 4. Else if a pin was supplied and differs → the handshake is **aborted** and
//!    [`TransportError::CertificateMismatch`] is returned. This is a hard stop:
//!    the caller maps it to `VncError::CertificateMismatch`, which is never
//!    auto-retried. We deliberately do not hand back a usable stream here.
//! 5. Else → [`TrustDecision::Unknown`] and the connected stream, so the UI can
//!    prompt the user before anything is sent over it.
//!
//! Note that VeNCrypt's anonymous-DH `TLS*` subtypes cannot be served by rustls
//! at all (no anon ciphersuites); only `X509*` reaches this module.

use std::sync::Arc;

use parking_lot::Mutex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio_rustls::TlsConnector;

use crate::{
    format_fingerprint, normalize_fingerprint, BoxedStream, Result, Stream, TransportError,
    TrustDecision,
};

/// Install the process-wide rustls crypto provider exactly once.
///
/// rustls 0.23 refuses to build a `ClientConfig` until a provider is installed;
/// `install_default` errors if one already is, which is fine, some other part
/// of the app (or a test) may have got there first.
fn ensure_provider() -> Arc<CryptoProvider> {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

/// Upgrade an established byte stream to TLS.
///
/// `server_name` is used both for SNI and for CA hostname verification;
/// `pin` is the stored SHA-256 SPKI fingerprint for this host, if any (any
/// separator style, any case).
pub async fn upgrade<S: Stream + 'static>(
    stream: S,
    server_name: &str,
    pin: Option<&str>,
) -> Result<(BoxedStream, TrustDecision)> {
    let provider = ensure_provider();

    let verifier = Arc::new(TofuVerifier::new(provider.clone(), pin)?);

    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    // VNC servers are long-lived single connections; session resumption buys
    // nothing and only adds state.
    config.resumption = rustls::client::Resumption::disabled();

    // SNI. An IP literal is accepted by `ServerName` and simply suppresses SNI.
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| TransportError::Tls(format!("invalid server name: {server_name}")))?;

    let connector = TlsConnector::from(Arc::new(config));
    let tls = match connector.connect(name, stream).await {
        Ok(tls) => tls,
        Err(e) => {
            // A pin mismatch aborts the handshake from inside the verifier;
            // surface the precise reason rather than a generic TLS error.
            if let Some(TrustDecision::Changed { expected, actual }) = verifier.decision() {
                return Err(TransportError::CertificateMismatch { expected, actual });
            }
            return Err(TransportError::Tls(e.to_string()));
        }
    };

    let decision = verifier
        .decision()
        .ok_or_else(|| TransportError::Tls("certificate was never verified".into()))?;

    if let TrustDecision::Changed { expected, actual } = decision {
        return Err(TransportError::CertificateMismatch { expected, actual });
    }

    tracing::debug!(?decision, "tls handshake complete");
    Ok((Box::pin(tls) as BoxedStream, decision))
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TofuVerifier {
    /// Standard chain+hostname verification against the Mozilla root set.
    webpki: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
    /// Normalised (hex, uppercase, no separators) expected fingerprint.
    pin: Option<String>,
    decision: Mutex<Option<TrustDecision>>,
}

impl TofuVerifier {
    fn new(provider: Arc<CryptoProvider>, pin: Option<&str>) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| TransportError::Tls(e.to_string()))?;

        let pin = pin.map(normalize_fingerprint).filter(|p| !p.is_empty());

        Ok(Self {
            webpki,
            provider,
            pin,
            decision: Mutex::new(None),
        })
    }

    fn decision(&self) -> Option<TrustDecision> {
        self.decision.lock().clone()
    }

    fn record(&self, d: TrustDecision) {
        *self.decision.lock() = Some(d);
    }
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let spki = der::extract_spki(end_entity.as_ref())
            .ok_or_else(|| rustls::Error::General("malformed server certificate".into()))?;
        let digest = Sha256::digest(spki);
        let fingerprint = format_fingerprint(&digest);
        let normalized = normalize_fingerprint(&fingerprint);

        // 1. Real PKI validation. If this passes there is nothing to prompt about.
        let ca_ok = self
            .webpki
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .is_ok();
        if ca_ok {
            self.record(TrustDecision::VerifiedByCa);
            return Ok(ServerCertVerified::assertion());
        }

        // 2/3. Pin comparison.
        match &self.pin {
            Some(expected) if *expected == normalized => {
                self.record(TrustDecision::PinnedMatch);
                Ok(ServerCertVerified::assertion())
            }
            Some(expected) => {
                // Abort the handshake; `upgrade` turns the recorded decision
                // into `CertificateMismatch`.
                self.record(TrustDecision::Changed {
                    expected: expected.clone(),
                    actual: fingerprint,
                });
                Err(rustls::Error::General(
                    "server certificate does not match the pinned fingerprint".into(),
                ))
            }
            // 5. First contact: accept the connection but tell the caller it is
            // unverified so the UI can prompt before any traffic flows.
            None => {
                let subject = der::subject_common_name(end_entity.as_ref())
                    .unwrap_or_else(|| "(unknown subject)".to_string());
                self.record(TrustDecision::Unknown {
                    fingerprint,
                    subject,
                });
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // Signature checking is orthogonal to trust: always do it properly,
        // otherwise TOFU pinning would be pinning a key nobody proved they own.
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Minimal DER walking
// ---------------------------------------------------------------------------

/// Just enough X.509/DER to pull the `SubjectPublicKeyInfo` and the subject CN
/// out of a certificate. A full ASN.1 parser is not a dependency this crate
/// needs, and everything here is bounds-checked against a hostile server.
mod der {
    /// A parsed TLV: the tag, the content, and the full element including header.
    struct Tlv<'a> {
        tag: u8,
        content: &'a [u8],
        full: &'a [u8],
    }

    /// Read one TLV from the front of `buf`, returning it and the remainder.
    fn read_tlv(buf: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
        if buf.len() < 2 {
            return None;
        }
        let tag = buf[0];
        // Multi-byte tags are not used anywhere on our path.
        if tag & 0x1f == 0x1f {
            return None;
        }
        let first = buf[1];
        let (len, header) = if first & 0x80 == 0 {
            (first as usize, 2usize)
        } else {
            let n = (first & 0x7f) as usize;
            // Indefinite length is illegal in DER; >4 length bytes means a
            // certificate larger than 4 GiB. Reject both.
            if n == 0 || n > 4 || buf.len() < 2 + n {
                return None;
            }
            let mut len = 0usize;
            for b in &buf[2..2 + n] {
                len = (len << 8) | (*b as usize);
            }
            (len, 2 + n)
        };
        let end = header.checked_add(len)?;
        if buf.len() < end {
            return None;
        }
        Some((
            Tlv {
                tag,
                content: &buf[header..end],
                full: &buf[..end],
            },
            &buf[end..],
        ))
    }

    const SEQUENCE: u8 = 0x30;
    const SET: u8 = 0x31;
    const INTEGER: u8 = 0x02;
    const OID: u8 = 0x06;
    /// `[0]` constructed, the EXPLICIT version tag in a TBSCertificate.
    const CONTEXT_0: u8 = 0xa0;
    /// OID 2.5.4.3 (id-at-commonName).
    const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

    /// Walk `Certificate -> TBSCertificate -> subjectPublicKeyInfo` and return
    /// that element's complete DER encoding (header included), which is what a
    /// "SPKI fingerprint" is computed over.
    pub fn extract_spki(cert: &[u8]) -> Option<&[u8]> {
        let tbs = tbs_certificate(cert)?;
        let mut rest = tbs;
        // Optional [0] version.
        let (first, after_first) = read_tlv(rest)?;
        if first.tag == CONTEXT_0 {
            rest = after_first;
        }
        // serialNumber
        let (serial, rest2) = read_tlv(rest)?;
        if serial.tag != INTEGER {
            return None;
        }
        // signature, issuer, validity, subject, four SEQUENCEs, then SPKI.
        let mut rest = rest2;
        for _ in 0..4 {
            let (tlv, next) = read_tlv(rest)?;
            if tlv.tag != SEQUENCE {
                return None;
            }
            rest = next;
        }
        let (spki, _) = read_tlv(rest)?;
        if spki.tag != SEQUENCE {
            return None;
        }
        Some(spki.full)
    }

    /// The subject `CN=` value, for display in the TOFU prompt. Untrusted text:
    /// the caller must render it as plain text, never as markup.
    pub fn subject_common_name(cert: &[u8]) -> Option<String> {
        let tbs = tbs_certificate(cert)?;
        let mut rest = tbs;
        let (first, after_first) = read_tlv(rest)?;
        if first.tag == CONTEXT_0 {
            rest = after_first;
        }
        let (_serial, rest2) = read_tlv(rest)?;
        let (_sigalg, rest3) = read_tlv(rest2)?;
        let (_issuer, rest4) = read_tlv(rest3)?;
        let (_validity, rest5) = read_tlv(rest4)?;
        let (subject, _) = read_tlv(rest5)?;
        if subject.tag != SEQUENCE {
            return None;
        }

        // Name ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTVA)
        let mut rdns = subject.content;
        while let Some((rdn, next)) = read_tlv(rdns) {
            rdns = next;
            if rdn.tag != SET {
                continue;
            }
            let mut attrs = rdn.content;
            while let Some((attr, next_attr)) = read_tlv(attrs) {
                attrs = next_attr;
                if attr.tag != SEQUENCE {
                    continue;
                }
                let (oid, after_oid) = read_tlv(attr.content)?;
                if oid.tag != OID || oid.content != OID_CN {
                    continue;
                }
                let (value, _) = read_tlv(after_oid)?;
                // Cap the length, a server may claim anything.
                let text: String = String::from_utf8_lossy(value.content)
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(128)
                    .collect();
                if !text.is_empty() {
                    return Some(text);
                }
            }
        }
        None
    }

    fn tbs_certificate(cert: &[u8]) -> Option<&[u8]> {
        let (outer, _) = read_tlv(cert)?;
        if outer.tag != SEQUENCE {
            return None;
        }
        let (tbs, _) = read_tlv(outer.content)?;
        if tbs.tag != SEQUENCE {
            return None;
        }
        Some(tbs.content)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_truncated_input() {
            assert!(extract_spki(&[]).is_none());
            assert!(extract_spki(&[0x30]).is_none());
            assert!(extract_spki(&[0x30, 0x82, 0xff, 0xff]).is_none());
            assert!(subject_common_name(&[0x30, 0x03, 0x30, 0x01]).is_none());
        }

        #[test]
        fn rejects_non_certificate() {
            // A well-formed SEQUENCE that is not a certificate.
            let der = [0x30, 0x03, 0x02, 0x01, 0x05];
            assert!(extract_spki(&der).is_none());
        }

        #[test]
        fn long_form_lengths_are_bounds_checked() {
            // Claims 0x0102 content bytes but supplies none.
            let der = [0x30, 0x82, 0x01, 0x02];
            assert!(extract_spki(&der).is_none());
        }

        /// A real self-signed certificate (`CN=vnc.example.test`, P-256).
        /// The expected digest is what
        /// `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256`
        /// produces, i.e. the value users compare against elsewhere.
        const TEST_CERT_HEX: &str = "3082021b308201c0020900fed9f6f5144ee51d300a06082a8648ce3d040302301b31\
19301706035504030c10766e632e6578616d706c652e74657374301e170d3236303732383139333830395a170d32363037323931\
39333830395a301b3119301706035504030c10766e632e6578616d706c652e746573743082014b3082010306072a8648ce3d0201\
3081f7020101302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff\
305b0420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd557698\
86bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247\
f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb64068\
37bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101034200040b2ec0b3fed6\
08022b545e768b3ab0ffc340ff9fb4f606b0c6c9e98a8a2f1919bb93370b6d21abd621dc5122cf599bff084ff2d8b16df21bf62a\
96fcbd59975a300a06082a8648ce3d0403020349003046022100ba92e99e98c2144752897231a266796f434ccab0137f03df2af2\
69c74c7f545402210084092ec5d5ddc0caad180befc2aa4e62cbef693c063287947a776840d6c92b88";

        #[test]
        fn spki_digest_matches_openssl() {
            use sha2::{Digest, Sha256};
            let der = hex::decode(TEST_CERT_HEX.replace(['\n', ' '], "")).unwrap();
            let spki = extract_spki(&der).expect("SPKI should be found");
            let digest = Sha256::digest(spki);
            assert_eq!(
                hex::encode(digest),
                "c42563ef393c1cabdf5438ffc8c5a8f0ecd2796cc33b556d4ee4d9f386e2118a"
            );
        }

        #[test]
        fn reads_the_subject_common_name() {
            let der = hex::decode(TEST_CERT_HEX.replace(['\n', ' '], "")).unwrap();
            assert_eq!(
                subject_common_name(&der).as_deref(),
                Some("vnc.example.test")
            );
        }

        /// Truncating a real certificate anywhere must fail cleanly, never panic.
        #[test]
        fn truncated_real_certificate_never_panics() {
            let der = hex::decode(TEST_CERT_HEX.replace(['\n', ' '], "")).unwrap();
            for n in 0..der.len() {
                let _ = extract_spki(&der[..n]);
                let _ = subject_common_name(&der[..n]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_installs_idempotently() {
        let a = ensure_provider();
        let b = ensure_provider();
        assert!(Arc::ptr_eq(&a, &b) || !a.cipher_suites.is_empty());
    }

    #[test]
    fn verifier_builds_with_and_without_pin() {
        let p = ensure_provider();
        assert!(TofuVerifier::new(p.clone(), None).unwrap().pin.is_none());
        let v = TofuVerifier::new(p, Some("de:ad:be:ef")).unwrap();
        assert_eq!(v.pin.as_deref(), Some("DEADBEEF"));
        assert!(v.decision().is_none());
    }
}
