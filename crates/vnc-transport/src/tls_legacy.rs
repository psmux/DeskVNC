//! Legacy TLS backend: OpenSSL, vendored via `openssl-src`, with TLS 1.0
//! and 1.1 enabled. Reaches hosts rustls will never speak to: rustls
//! implements TLS 1.2 and 1.3 only, by upstream design (rustls issue #26,
//! and the crate's own FAQ states earlier versions are out of scope), and
//! that is a fact about rustls, not a configuration this crate could flip.
//!
//! Only compiled when the `legacy-tls` cargo feature is set (not in
//! `default`). PRDRDP/10 package P0.6, phase 1b: this file holds the real
//! handshake, and `rdp-core`'s `upgrade_tls` selects it from the per-host
//! `legacy_tls` setting (PRDRDP/03 sec 4.7.2). The selection is made before
//! the socket is touched and never from anything the peer said.
//!
//! # The seam (PRDRDP/03 sec 4.7.1)
//!
//! Both backends produce the same [`crate::TrustDecision`] values from the
//! same certificate bytes, computed by the same code: this backend hands
//! the leaf, the chain, the server name and the stored pin to
//! [`crate::tls::decide_certificate`], the function `TofuVerifier` runs on
//! the rustls side, so a host reached on either backend has one pin and one
//! answer to "does this chain to a CA". Nothing about trust is decided
//! here.
//!
//! # What crosses the seam
//!
//! A [`TlsUpgrade`] and nothing else — the same four owned values the
//! modern backend builds (PRDRDP/00 R47): the upgraded stream, the trust
//! decision, the leaf certificate DER as the peer sent it, and that
//! certificate's `signatureAlgorithm` OID. `rdp-core` derives the CredSSP
//! public key and the RFC 5929 channel binding from those, so no `openssl`
//! type escapes this file and nothing in it has to know what CredSSP is.
//!
//! The pin is checked after the handshake completes rather than from inside
//! a verifier callback, because a callback would mean hand written `unsafe`
//! glue into OpenSSL's C ABI, which the workspace rule forbids outright.
//! The check still happens before a single byte of the stream is handed
//! back: on a mismatch this function returns
//! [`TransportError::CertificateMismatch`] and drops the stream, so no
//! application data ever flows on a connection whose pin failed. The only
//! visible difference to a passive observer is that the TLS handshake
//! itself completed first.
//!
//! # The configuration this backend runs, researched per V3-B
//!
//! Recorded against the vendored OpenSSL this crate pins (`openssl-src`
//! `=300.5.5`, OpenSSL 3.5.5, the LTS branch), so the answers below are
//! checked rather than reasoned from memory of an older OpenSSL.
//! PRDRDP/03 sec 4.7.3 and PRDRDP/11 sec 3.10.5 carry the full citations;
//! this is the summary a reviewer of this file needs without following
//! them.
//!
//! 1. **Minimum and maximum protocol version.**
//!    `set_min_proto_version(TLS1)` and `set_max_proto_version(TLS1_2)`.
//!    The maximum is 1.2, not 1.3: a host that can negotiate 1.3 belongs
//!    on the default rustls backend, and capping it here makes a
//!    misconfigured profile fail loudly in testing instead of silently
//!    behaving like the default backend.
//! 2. **Security level 0, set with `set_security_level(0)`.** Not the
//!    `@SECLEVEL=0` cipher-string suffix, which is equivalent but easy to
//!    lose in a later edit of the cipher list. OpenSSL 3.1 and later ban
//!    TLS 1.0 and 1.1 outright at security level 1, and the compiled-in
//!    default level is 2 from OpenSSL 3.2 onward, so leaving the level
//!    unset does not almost work, it refuses the handshake with "no
//!    protocols available". Level 0 is also required for the certificate,
//!    independent of the protocol version: a Server 2008 R2 listener
//!    certificate is `sha1WithRSAEncryption`, and level 1 already rejects
//!    SHA-1 signatures.
//! 3. **The cipher list, set with `set_cipher_list`: [`CIPHER_LIST`],**
//!    which is `DEFAULT`. The original plan named four suites —
//!    `ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA`,
//!    "every one of those is in the default enabled list of Windows 7 SP1
//!    and Server 2008 R2 Schannel". Interop probing against the real RDP
//!    listener this fork was written for (Windows Server 2012) found the
//!    server resetting the connection, before a single byte came back, on
//!    every ClientHello that carried a short cipher list — that four-suite
//!    list included — while the full OpenSSL default list negotiated
//!    `ECDHE-RSA-AES256-SHA384` on every attempt, each success sandwiched
//!    between failing probes of the narrow lists. So the narrow list is
//!    dropped in favour of the broadest one the vendored build enables.
//!    `DEFAULT` is a superset of the four, so every host the plan's list
//!    reached is still reached; the wire evidence is recorded here because
//!    a reviewer should know the deviation was measured, not guessed.
//! 4. **RC4 and 3DES are absent, and neither the `weak-crypto`
//!    `openssl-src` feature nor the OpenSSL legacy provider is enabled.**
//!    In this build they are absent from `DEFAULT` outright — checked with
//!    `openssl ciphers DEFAULT`, which lists no RC4, 3DES, DES, IDEA or
//!    SEED suite at all — so the exclusion holds without spending cipher
//!    list width on it. `DEFAULT` does contain the PSK and SRP suites;
//!    they are inert here, because completing one needs a pre-shared key
//!    configured on both ends and neither end has one, so a listener that
//!    selected one would fail the handshake rather than downgrade it.
//!
//!    `openssl-src` never disables TLS 1.0 or 1.1 at build time on any
//!    platform (there is no `no-tls1` / `no-tls1_1` flag to begin with),
//!    so nothing at the dependency level is needed to reach them. If an
//!    actual interop test ever finds a host that offers only RC4 or 3DES,
//!    that is a second, explicit escalation (`enable-md2`/`enable-rc5`
//!    come bundled with `weak-crypto` and cannot be taken separately, and
//!    enabling the legacy provider needs a process-lifetime guard that
//!    must never be dropped), not a quiet flag flip.
//!
//! # The rejected alternative
//!
//! Writing TLS 1.0 and 1.1 ourselves was considered and is rejected under
//! the workspace rule that every cryptographic operation calls a third
//! party library (no cipher, no record layer, no version negotiation is
//! written here). TLS 1.0's weak points are exactly the class of bug a
//! hand written implementation produces: a non-constant-time CBC padding
//! check is a padding oracle, MAC-then-encrypt is what produced the Lucky
//! 13 attack in a library that had already been reviewed for a decade, and
//! version negotiation and renegotiation logic have a long history of
//! subtle downgrade bugs. Taking OpenSSL trades that class of bug for an
//! advisory stream we have to track; that trade is the right one.

use std::pin::Pin;

use openssl::ssl::{
    SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode, SslVersion,
};
use rdp_pdu::asn1::der;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_openssl::SslStream;

use crate::tls::{
    ca_verifier, decide_certificate, ensure_provider, MalformedCertificate, TlsUpgrade,
};
use crate::{BoxedStream, Result, Stream, TransportError, TrustDecision};

/// The cipher list this backend puts on the wire.
///
/// `DEFAULT` as the vendored OpenSSL enables it — the broadest list in the
/// build, and the one with a checked answer against a real Server 2012 RDP
/// listener (the four-suite list from the original plan was reset by that
/// server on every probe; see the module comment, item 3). Security level
/// 0 is set on the context rather than appended as `@SECLEVEL=0`, so this
/// string is exactly what `openssl s_client -cipher DEFAULT` sends.
const CIPHER_LIST: &str = "DEFAULT";

/// The context this backend dials with: the configuration the module
/// comment documents, in one place a test can read it back.
fn client_context() -> Result<SslConnectorBuilder> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| TransportError::Tls(e.to_string()))?;

    // 1. TLS 1.0 through 1.2, capped at 1.2 on purpose.
    builder
        .set_min_proto_version(Some(SslVersion::TLS1))
        .map_err(|e| TransportError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| TransportError::Tls(e.to_string()))?;

    // 2. Level 0: without it OpenSSL 3.x refuses the versions and the
    // SHA-1 listener certificates this backend exists for.
    builder.set_security_level(0);

    // 3. The wire-proven list.
    builder
        .set_cipher_list(CIPHER_LIST)
        .map_err(|e| TransportError::Tls(e.to_string()))?;

    // Verification is `decide_certificate`'s job, not OpenSSL's: one root
    // set and one trust ladder across both backends. An OpenSSL chain
    // check alongside it would be a second, divergent opinion about the
    // same certificate. Handshake signatures are unaffected — OpenSSL
    // verifies those unconditionally, and they are not a trust decision.
    builder.set_verify(SslVerifyMode::NONE);

    Ok(builder)
}

/// Surface an OpenSSL failure the way the rustls path reads: OpenSSL's
/// `Display` already prints the underlying I/O error for a reset or an
/// EOF, so the log line says "connection reset by peer" rather than an
/// error stack hex code. Generic because the handshake returns two error
/// types — `ErrorStack` from setup, `ssl::Error` from the handshake.
fn tls_error<E: std::fmt::Display>(e: E) -> TransportError {
    TransportError::Tls(e.to_string())
}

/// Upgrade an established byte stream to TLS over OpenSSL, and hand back
/// the server identity material with it.
///
/// The parameters and the return type match
/// [`crate::tls::upgrade_with_identity`] exactly, which is the seam
/// PRDRDP/03 §4.7.1 fixes: both backends produce one [`TlsUpgrade`] and
/// nothing else crosses, so the pin, the CredSSP public key and the RFC
/// 5929 channel binding are computed once in `rdp-core` from values that
/// carry no trace of which library produced them.
///
/// # Errors
///
/// [`TransportError::CertificateMismatch`] when a pin was supplied and the
/// peer presented a different key — the handshake is dropped, never
/// returned — [`TransportError::Tls`] for anything the handshake reports.
pub async fn upgrade_with_identity<S: Stream + 'static>(
    stream: S,
    server_name: &str,
    pin: Option<&str>,
) -> Result<TlsUpgrade> {
    let connector = client_context()?.build();

    let mut config = connector.configure().map_err(tls_error)?;
    // Hostname checking is not this layer's: `decide_certificate` runs
    // webpki's chain-and-name verification with the same root set the
    // rustls path uses, so one backend cannot accept a name the other
    // rejects. SNI is unaffected — `into_ssl` still sends it for a
    // non-IP `server_name`, exactly as rustls does.
    config.set_verify_hostname(false);
    let ssl = config.into_ssl(server_name).map_err(tls_error)?;

    let mut tls = SslStream::new(ssl, stream).map_err(tls_error)?;
    Pin::new(&mut tls).connect().await.map_err(tls_error)?;

    // The handshake is over; the trust ladder runs here on the same bytes
    // the rustls path hands its verifier.
    let leaf = tls
        .ssl()
        .peer_certificate()
        .ok_or_else(|| TransportError::Tls("the server sent no certificate".into()))?;
    let leaf_der = CertificateDer::from(leaf.to_der().map_err(tls_error)?);

    // `peer_cert_chain` is the chain as the peer sent it, leaf first; drop
    // the leaf so `decide_certificate` sees only the issuers, the same
    // shape rustls passes a verifier.
    let intermediates: Vec<CertificateDer<'static>> = tls
        .ssl()
        .peer_cert_chain()
        .map(|chain| {
            chain
                .iter()
                .filter_map(|x| x.to_der().ok())
                .filter(|der| der.as_slice() != &*leaf_der)
                .map(CertificateDer::from)
                .collect()
        })
        .unwrap_or_default();

    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| TransportError::Tls(format!("invalid server name: {server_name}")))?;
    let ca = ca_verifier(ensure_provider())?;
    let decision =
        decide_certificate(&ca, &leaf_der, &intermediates, &name, UnixTime::now(), pin).map_err(
            |MalformedCertificate| TransportError::Tls("malformed server certificate".into()),
        )?;
    let decision = match decision {
        // A pin was supplied and differs: abort here, before the stream
        // is handed to anyone, exactly as the rustls verifier does.
        TrustDecision::Changed { expected, actual } => {
            return Err(TransportError::CertificateMismatch { expected, actual });
        }
        other => other,
    };

    let signature_algorithm_oid = der::signature_algorithm_oid(&leaf_der)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();

    tracing::debug!(?decision, "tls handshake complete (legacy backend)");
    Ok(TlsUpgrade {
        stream: Box::pin(tls) as BoxedStream,
        decision,
        server_certificate: leaf_der.to_vec(),
        signature_algorithm_oid,
    })
}

/// [`upgrade_with_identity`] for a caller that wants only the stream and the
/// decision, matching [`crate::tls::upgrade`]'s shape.
pub async fn upgrade<S: Stream + 'static>(
    stream: S,
    server_name: &str,
    pin: Option<&str>,
) -> Result<(BoxedStream, TrustDecision)> {
    let up = upgrade_with_identity(stream, server_name, pin).await?;
    Ok((up.stream, up.decision))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::ssl::{Ssl, SslAcceptor, SslOptions};
    use openssl::x509::{X509, X509NameBuilder};
    use sha2::{Digest, Sha256};
    use tokio::net::{TcpListener, TcpStream};

    use crate::format_fingerprint;

    /// The handshake budget for a loopback test; a handshake that takes
    /// this long has hung, and a hung `cargo test` helps nobody.
    const BUDGET: Duration = Duration::from_secs(10);

    /// A self-signed RSA-2048 certificate, `CN=deskvnc-loopback.test`.
    ///
    /// Generated rather than checked in: the assertion that matters here
    /// is that the bytes OpenSSL produced as a server come back out of the
    /// client's identity extraction unchanged, and a fixture would only
    /// prove that about itself.
    fn self_signed() -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa key")).expect("pkey");
        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", "deskvnc-loopback.test")
            .expect("cn");
        let name = name.build();

        let mut builder = X509::builder().expect("x509");
        builder.set_version(2).expect("v3");
        builder
            .set_serial_number(&BigNum::from_u32(1).expect("bn").to_asn1_integer().expect("sn"))
            .expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("not before"))
            .expect("not before");
        builder
            .set_not_after(&Asn1Time::days_from_now(30).expect("not after"))
            .expect("not after");
        builder.set_pubkey(&key).expect("pubkey");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        (builder.build(), key)
    }

    /// A test server on the same configuration the client runs, pinned to
    /// the version window the calling test wants to prove.
    fn acceptor(cert: &X509, key: &PKey<Private>, min: SslVersion, max: SslVersion) -> SslAcceptor {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("acceptor");
        // The Mozilla preset disables TLS 1.3 by option; the window is
        // stated explicitly below, so clear theirs and keep the test
        // about the versions it claims.
        builder.clear_options(SslOptions::NO_TLSV1_3);
        builder.set_security_level(0);
        builder.set_cipher_list(CIPHER_LIST).expect("ciphers");
        builder.set_min_proto_version(Some(min)).expect("min");
        builder.set_max_proto_version(Some(max)).expect("max");
        builder.set_certificate(cert).expect("cert");
        builder.set_private_key(key).expect("key");
        builder.build()
    }

    /// Accept exactly one TLS connection and report the version the
    /// handshake settled on — or the error, for the tests that expect the
    /// server side to refuse too.
    fn spawn_server(
        acceptor: SslAcceptor,
        listener: TcpListener,
    ) -> tokio::task::JoinHandle<std::result::Result<String, String>> {
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept tcp");
            let ssl = Ssl::new(acceptor.context()).expect("ssl");
            let mut tls = SslStream::new(ssl, stream).expect("wrap");
            match Pin::new(&mut tls).accept().await {
                Ok(()) => Ok(tls.ssl().version_str().to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
    }

    async fn bound() -> (TcpListener, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        (listener, addr)
    }

    /// The documented configuration, read back from the context itself:
    /// the version getters are on the builder that was configured, and the
    /// level only exists on a built context, so a later edit that loosens
    /// the window or the level fails here first.
    #[test]
    fn the_config_is_the_documented_one() {
        let mut ctx = client_context().expect("context");
        assert_eq!(ctx.min_proto_version(), Some(SslVersion::TLS1));
        assert_eq!(ctx.max_proto_version(), Some(SslVersion::TLS1_2));
        let connector = ctx.build();
        assert_eq!(connector.context().security_level(), 0);
    }

    #[tokio::test]
    async fn negotiates_tls12_and_reports_the_certificate_it_saw() {
        let (cert, key) = self_signed();
        let (listener, addr) = bound().await;
        let server = spawn_server(
            acceptor(&cert, &key, SslVersion::TLS1_2, SslVersion::TLS1_2),
            listener,
        );

        let stream = TcpStream::connect(addr).await.expect("connect");
        let up = tokio::time::timeout(
            BUDGET,
            upgrade_with_identity(stream, "127.0.0.1", None),
        )
        .await
        .expect("the handshake hung")
        .expect("the handshake failed");

        // The identity material is the server's bytes, octet for octet.
        let der = cert.to_der().expect("der");
        assert_eq!(up.server_certificate, der);
        // `sha256WithRSAEncryption`, 1.2.840.113549.1.1.11, as DER
        // content octets: the element RFC 5929 §4.1 reads, not the key's.
        assert_eq!(
            up.signature_algorithm_oid,
            [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
        );

        // Self-signed and unrecognised: first contact, TOFU prompt
        // material, with the fingerprint the user compares against
        // `openssl x509 -pubkey | ... | sha256sum`.
        match &up.decision {
            TrustDecision::Unknown {
                fingerprint,
                subject,
                ..
            } => {
                let expected =
                    format_fingerprint(&Sha256::digest(der::extract_spki(&der).expect("spki")));
                assert_eq!(*fingerprint, expected);
                assert_eq!(subject, "deskvnc-loopback.test");
            }
            other => panic!("expected TrustDecision::Unknown, got {other:?}"),
        }

        assert_eq!(server.await.expect("join").expect("server"), "TLSv1.2");
    }

    #[tokio::test]
    async fn a_matching_pin_is_a_pinned_match() {
        let (cert, key) = self_signed();
        let (listener, addr) = bound().await;
        let server = spawn_server(
            acceptor(&cert, &key, SslVersion::TLS1_2, SslVersion::TLS1_2),
            listener,
        );

        let der = cert.to_der().expect("der");
        let pin = format_fingerprint(&Sha256::digest(der::extract_spki(&der).expect("spki")));

        let stream = TcpStream::connect(addr).await.expect("connect");
        let up = tokio::time::timeout(
            BUDGET,
            upgrade_with_identity(stream, "127.0.0.1", Some(&pin)),
        )
        .await
        .expect("the handshake hung")
        .expect("the handshake failed");
        assert!(matches!(up.decision, TrustDecision::PinnedMatch));

        assert_eq!(server.await.expect("join").expect("server"), "TLSv1.2");
    }

    #[tokio::test]
    async fn a_stale_pin_aborts_before_the_stream_escapes() {
        let (cert, key) = self_signed();
        let (listener, addr) = bound().await;
        let server = spawn_server(
            acceptor(&cert, &key, SslVersion::TLS1_2, SslVersion::TLS1_2),
            listener,
        );

        let stream = TcpStream::connect(addr).await.expect("connect");
        let err = tokio::time::timeout(
            BUDGET,
            upgrade_with_identity(stream, "127.0.0.1", Some("DEADBEEF")),
        )
        .await
        .expect("the handshake hung")
        .expect_err("a wrong pin must not yield a stream");

        match err {
            TransportError::CertificateMismatch { expected, actual } => {
                assert_eq!(expected, "DEADBEEF");
                let der = cert.to_der().expect("der");
                let want =
                    format_fingerprint(&Sha256::digest(der::extract_spki(&der).expect("spki")));
                assert_eq!(actual, want);
            }
            other => panic!("expected CertificateMismatch, got {other:?}"),
        }

        server.await.expect("join").expect("server");
    }

    /// The point of this backend: a host whose listener speaks only TLS
    /// 1.0 — rustls refuses such a host by design, this one connects.
    #[tokio::test]
    async fn reaches_a_server_that_offers_only_tls10() {
        let (cert, key) = self_signed();
        let (listener, addr) = bound().await;
        let server =
            spawn_server(acceptor(&cert, &key, SslVersion::TLS1, SslVersion::TLS1), listener);

        let stream = TcpStream::connect(addr).await.expect("connect");
        let up = tokio::time::timeout(
            BUDGET,
            upgrade_with_identity(stream, "127.0.0.1", None),
        )
        .await
        .expect("the handshake hung")
        .expect("TLS 1.0 must be reachable");
        assert!(matches!(up.decision, TrustDecision::Unknown { .. }));
        assert_eq!(server.await.expect("join").expect("server"), "TLSv1");
    }

    /// The cap from module comment item 1, proven from both sides: a
    /// 1.3-only listener is refused rather than reached on a version the
    /// profile did not ask for.
    #[tokio::test]
    async fn refuses_a_server_that_offers_only_tls13() {
        let (cert, key) = self_signed();
        let (listener, addr) = bound().await;
        let server = spawn_server(
            acceptor(&cert, &key, SslVersion::TLS1_3, SslVersion::TLS1_3),
            listener,
        );

        let stream = TcpStream::connect(addr).await.expect("connect");
        let err = tokio::time::timeout(
            BUDGET,
            upgrade_with_identity(stream, "127.0.0.1", None),
        )
        .await
        .expect("the handshake hung")
        .expect_err("a TLS 1.3-only server must not be reached");
        assert!(matches!(err, TransportError::Tls(_)), "got {err:?}");

        assert!(
            server.await.expect("join").is_err(),
            "the server should refuse the version window too"
        );
    }
}
