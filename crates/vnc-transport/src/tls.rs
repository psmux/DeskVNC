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
//!
//! # Two entry points, one handshake
//!
//! [`upgrade_with_identity`] is the real one. It returns a [`TlsUpgrade`],
//! which PRDRDP/00 R47 and R62 fix at four owned values: the stream, the trust
//! decision, the leaf certificate DER, and that certificate's
//! `signatureAlgorithm` OID. RDP needs all four, because CredSSP binds to the
//! server's public key (MS-CSSP 3.1.5) and the RFC 5929 section 4.1
//! `tls-server-end-point` channel binding picks its hash from the signature
//! algorithm. Neither derived value is computed here: a TLS module that
//! computes a CredSSP binding is a TLS module that has to know what CredSSP
//! is, and `rdp-core` derives both from these two pieces of evidence.
//!
//! [`upgrade`] keeps its old three argument signature and its old return type,
//! so every VeNCrypt call site is unchanged.

use std::sync::Arc;

use parking_lot::Mutex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio_rustls::TlsConnector;

// The DER walker this module used to carry itself. It moved to `rdp-pdu` so
// there is one X.690 implementation in the workspace rather than two that
// drift: CredSSP needs the same walk for `TSRequest` and for the server
// public key it hashes (PRDRDP/13 §3.5, PRDRDP/00 R45). `extract_spki` and
// `subject_common_name` kept their signatures exactly, so the call sites below
// are unchanged and this line is the whole of the import side of the move.
use rdp_pdu::asn1::der;

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

/// Which TLS implementation performs the handshake (PRDRDP/03 §4.7.2).
///
/// Chosen by the caller from the host profile and never from anything the peer
/// said. Automatic fallback from one to the other would be a downgrade an
/// attacker triggers by sending one alert, so there is none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsBackend {
    /// rustls, TLS 1.2 and 1.3. The only value when `legacy-tls` is off.
    #[default]
    Modern,
    /// Vendored OpenSSL, TLS 1.0 through 1.2. Requires the `legacy-tls`
    /// feature; without it this variant does not exist, so a build that cannot
    /// speak TLS 1.0 also cannot be asked to.
    #[cfg(feature = "legacy-tls")]
    Legacy,
}

/// Everything a caller can learn about the peer from one TLS handshake
/// (PRDRDP/00 R47, spelled by R62).
///
/// Owned values only. This struct names no `rustls-pki-types` type and no
/// `openssl` type, so a consumer does not acquire either dependency to read
/// it, and the concrete `tokio_rustls::client::TlsStream` never escapes the
/// function that built it. That is also what lets one authentication path
/// serve both backends: everything derived from the certificate is derived in
/// the consumer, from bytes that carry no trace of which library produced
/// them.
pub struct TlsUpgrade {
    /// The upgraded stream.
    pub stream: BoxedStream,
    /// What the trust on first use policy decided.
    pub decision: TrustDecision,
    /// The end entity certificate, DER, exactly as the peer sent it.
    ///
    /// Not an `Option`: no anonymous cipher suite is permitted on either
    /// backend, so a handshake that reaches this struct has a certificate, and
    /// an `Option` would put a dead arm at every call site.
    pub server_certificate: Vec<u8>,
    /// The OID of that certificate's `signatureAlgorithm`, as its DER content
    /// octets.
    ///
    /// The RFC 5929 section 4.1 hash choice input and nothing else. Empty when
    /// the certificate does not parse far enough to name one, which the
    /// consumer treats as "use SHA-256", the same answer RFC 5929 gives for an
    /// unrecognised algorithm.
    pub signature_algorithm_oid: Vec<u8>,
}

/// A hand written `Debug`, because `BoxedStream` is a trait object over a
/// trait that does not require `Debug`, and because a certificate identifies a
/// host: its length is diagnostic, its bytes are not.
impl std::fmt::Debug for TlsUpgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsUpgrade")
            .field("decision", &self.decision)
            .field("server_certificate", &self.server_certificate.len())
            .field("signature_algorithm_oid", &self.signature_algorithm_oid)
            .finish_non_exhaustive()
    }
}

/// The OID of `Certificate.signatureAlgorithm`, as its DER content octets.
///
/// ```text
/// Certificate         ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
/// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
/// ```
///
/// RFC 5280 §4.1. Three TLV reads over the walker `rdp-pdu` already owns
/// (PRDRDP/00 R45), so this adds no second X.690 implementation.
///
/// Upgrade an established byte stream to TLS.
///
/// `server_name` is used both for SNI and for CA hostname verification;
/// `pin` is the stored SHA-256 SPKI fingerprint for this host, if any (any
/// separator style, any case).
///
/// The VeNCrypt entry point, kept at its old signature so no RFB call site
/// changed when RDP needed more (PRDRDP/03 §4.3). It hard codes
/// [`TlsBackend::Modern`], so the VNC path cannot acquire a legacy handshake
/// by accident.
pub async fn upgrade<S: Stream + 'static>(
    stream: S,
    server_name: &str,
    pin: Option<&str>,
) -> Result<(BoxedStream, TrustDecision)> {
    let up = upgrade_with_identity(stream, server_name, pin, TlsBackend::Modern).await?;
    Ok((up.stream, up.decision))
}

/// Upgrade an established byte stream to TLS and hand back the server identity
/// material with it (PRDRDP/03 §4.3).
///
/// The same handshake and the same trust policy as [`upgrade`]; the difference
/// is only what comes back.
///
/// # Errors
///
/// [`TransportError::CertificateMismatch`] when a pin was supplied and the
/// peer presented a different key, which aborts the handshake from inside the
/// verifier and never yields a usable stream, and [`TransportError::Tls`] for
/// anything else the handshake reports.
pub async fn upgrade_with_identity<S: Stream + 'static>(
    stream: S,
    server_name: &str,
    pin: Option<&str>,
    backend: TlsBackend,
) -> Result<TlsUpgrade> {
    match backend {
        TlsBackend::Modern => upgrade_rustls(stream, server_name, pin).await,
        #[cfg(feature = "legacy-tls")]
        TlsBackend::Legacy => {
            crate::tls_legacy::upgrade_with_identity(stream, server_name, pin).await
        }
    }
}

async fn upgrade_rustls<S: Stream + 'static>(
    stream: S,
    server_name: &str,
    pin: Option<&str>,
) -> Result<TlsUpgrade> {
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

    // The verifier kept the leaf next to the decision it recorded, so both
    // describe the same handshake. A handshake that produced a decision
    // produced a certificate, which is why R62 makes the field non optional
    // and why this is an error rather than an empty vector.
    let server_certificate = verifier
        .certificate()
        .ok_or_else(|| TransportError::Tls("the server sent no certificate".into()))?;
    // R62 puts this in `rdp_pdu::asn1::der`, and it is there now, so the copy
    // that lived here while that crate was being written is gone.
    let signature_algorithm_oid = der::signature_algorithm_oid(&server_certificate)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();

    tracing::debug!(?decision, "tls handshake complete");
    Ok(TlsUpgrade {
        stream: Box::pin(tls) as BoxedStream,
        decision,
        server_certificate,
        signature_algorithm_oid,
    })
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
    /// The leaf certificate DER, filled beside the decision so the two cannot
    /// describe different handshakes (PRDRDP/03 §4.7.6).
    certificate: Mutex<Option<Vec<u8>>>,
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
            certificate: Mutex::new(None),
        })
    }

    fn decision(&self) -> Option<TrustDecision> {
        self.decision.lock().clone()
    }

    fn certificate(&self) -> Option<Vec<u8>> {
        self.certificate.lock().clone()
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
        // Copied out here rather than after the handshake, because this is the
        // only place the concrete rustls type exists and because RFC 5929 wants
        // the certificate "as it appears, octet for octet, in the server's
        // Certificate message" rather than a re-encode (PRDRDP/03 §4.7.6).
        *self.certificate.lock() = Some(end_entity.as_ref().to_vec());
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

    /// A real self-signed certificate (`CN=vnc.example.test`, P-256).
    ///
    /// The walker itself is tested in `rdp-pdu`, which the move took it to
    /// (PRDRDP/13 §3.5). This vector stays here as well because the assertion
    /// that matters to this crate is the one `rdp-pdu` cannot make: the
    /// SHA-256 of the SPKI, which is the fingerprint step 1 of the module
    /// comment above defines and the string a user compares against
    /// `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256sum`.
    /// `rdp-pdu` has no hash dependency and should not gain one for a test
    /// (AGENT_BRIEF D12: the leaf crates build and test in under a second and
    /// fuzz without a runtime, which is a property of a small tree), so it
    /// asserts the SPKI bytes and this asserts their digest.
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
        let der_bytes = hex::decode(TEST_CERT_HEX.replace(['\n', ' '], "")).unwrap();
        let spki = der::extract_spki(&der_bytes).expect("SPKI should be found");
        let digest = Sha256::digest(spki);
        assert_eq!(
            hex::encode(digest),
            "c42563ef393c1cabdf5438ffc8c5a8f0ecd2796cc33b556d4ee4d9f386e2118a"
        );
    }

    /// RFC 5929 §4.1 picks the channel binding hash from this OID, so reading
    /// the wrong element produces a binding a Windows host with Extended
    /// Protection set to "Require" rejects, and the failure reads to the user
    /// as a wrong password (PRDRDP/03 §4.3).
    ///
    /// The fixture is signed `ecdsa-with-SHA256`, OID 1.2.840.10045.4.3.2,
    /// whose DER content octets are `2a 86 48 ce 3d 04 03 02`.
    #[test]
    fn reads_the_signature_algorithm_oid_and_not_the_subject_key() {
        let der_bytes = hex::decode(TEST_CERT_HEX.replace(['\n', ' '], "")).unwrap();
        assert_eq!(
            der::signature_algorithm_oid(&der_bytes),
            Some(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02][..])
        );
        // The two values a certificate yields are different things and must
        // not be allowed to collapse into one another by a later refactor: the
        // pin is SHA-256 over the whole SPKI element, and the CredSSP binding
        // input is the inner subjectPublicKey contents (PRDRDP/03 §4.3).
        let spki = der::extract_spki(&der_bytes).unwrap();
        let key = der::subject_public_key(&der_bytes).unwrap();
        assert_ne!(spki, key);
        assert!(spki.len() > key.len());
    }

    /// Truncation and rubbish are `None`, never a panic and never a partial
    /// OID: this walks bytes a remote peer chose.
    #[test]
    fn a_malformed_certificate_yields_no_oid() {
        let der_bytes = hex::decode(TEST_CERT_HEX.replace(['\n', ' '], "")).unwrap();
        for cut in 0..64 {
            let _ = der::signature_algorithm_oid(&der_bytes[..cut]);
        }
        assert_eq!(der::signature_algorithm_oid(&[]), None);
        assert_eq!(der::signature_algorithm_oid(&[0x30, 0x00]), None);
        assert_eq!(der::signature_algorithm_oid(&[0x02, 0x01, 0x00]), None);
    }

    /// The subject CN is what the TOFU prompt shows, so this crate keeps a
    /// test that the re-exported walker still reads it (PRDRDP/13 §3.5).
    #[test]
    fn reads_the_subject_common_name() {
        let der_bytes = hex::decode(TEST_CERT_HEX.replace(['\n', ' '], "")).unwrap();
        assert_eq!(
            der::subject_common_name(&der_bytes).as_deref(),
            Some("vnc.example.test")
        );
    }
}
