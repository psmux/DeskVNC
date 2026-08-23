//! Legacy TLS backend: OpenSSL, vendored via `openssl-src`, built with TLS
//! 1.0 and 1.1 enabled. Reaches hosts rustls will never speak to: rustls
//! implements TLS 1.2 and 1.3 only, by upstream design (rustls issue #26,
//! and the crate's own FAQ states earlier versions are out of scope), and
//! that is a fact about rustls, not a configuration this crate could flip.
//!
//! Only compiled when the `legacy-tls` cargo feature is set (not in
//! `default`). PRDRDP/10 package P0.6, phase 0: this file adds the
//! dependency, the build configuration and a STUB upgrade path only. No
//! TLS 1.0 or 1.1 connection is made here. The real handshake, its per-host
//! `legacy_tls` setting and its wiring into `rdp-core`'s `TlsBackend`
//! selection (PRDRDP/03 sec 4.7.2) land in phase 1b.
//!
//! # The seam (PRDRDP/03 sec 4.7.1)
//!
//! Both backends must produce the same [`crate::TrustDecision`] values from
//! the same certificate bytes, computed by the same code, so a host reached
//! on either backend has one pin. That shared decision function does not
//! exist as a standalone entry point yet (`tls.rs`'s `TofuVerifier` still
//! owns it inline); factoring it out is phase 1b work, tracked here rather
//! than duplicated ahead of time.
//!
//! # The configuration this backend will run, researched now per V3-B
//!
//! Recorded here, against the vendored OpenSSL this crate now pins
//! (`openssl-src` `=300.5.5`, OpenSSL 3.5.5, the LTS branch), so the
//! phase 1b implementation has a checked answer rather than one reasoned
//! from memory of an older OpenSSL. PRDRDP/03 sec 4.7.3 and PRDRDP/11
//! sec 3.10.5 carry the full citations; this is the summary a reviewer of
//! this file needs without following them.
//!
//! 1. **Minimum and maximum protocol version.**
//!    `SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION)` and
//!    `SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)`. The maximum is
//!    1.2, not 1.3: a host that can negotiate 1.3 belongs on the default
//!    rustls backend, and capping it here makes a misconfigured profile
//!    fail loudly in testing instead of silently behaving like the default
//!    backend.
//! 2. **Security level 0, set with `SSL_CTX_set_security_level(ctx, 0)`.**
//!    Not the `@SECLEVEL=0` cipher-string suffix, which is equivalent but
//!    easy to lose in a later edit of the cipher list. OpenSSL 3.1 and
//!    later ban TLS 1.0 and 1.1 outright at security level 1, and the
//!    compiled-in default level is 2 from OpenSSL 3.2 onward, so leaving
//!    the level unset does not almost work, it refuses the handshake with
//!    "no protocols available". Level 0 is also required for the
//!    certificate, independent of the protocol version: a Server 2008 R2
//!    listener certificate is `sha1WithRSAEncryption`, and level 1 already
//!    rejects SHA-1 signatures.
//! 3. **An explicit cipher list, set with `SSL_CTX_set_cipher_list`:**
//!    `ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA`.
//!    Every one of those is in the default enabled list of Windows 7 SP1
//!    and Server 2008 R2 Schannel, so a default host connects without
//!    needing anything weaker.
//! 4. **RC4 and 3DES are deliberately absent, and neither the
//!    `weak-crypto` `openssl-src` feature nor the OpenSSL legacy provider
//!    is enabled.** `openssl-src` never disables TLS 1.0 or 1.1 at build
//!    time on any platform (there is no `no-tls1` / `no-tls1_1` flag to
//!    begin with), so nothing at the dependency level is needed to reach
//!    them; RC4 and 3DES are a separate, deliberate build-time exclusion
//!    covered below.
//!
//!    Yes, the RC4 suites Server 2008 R2 can offer do need the OpenSSL
//!    legacy provider loaded at runtime (RC4 moved out of the default
//!    provider in OpenSSL 3.x) on top of an `enable-weak-ssl-ciphers`
//!    build, and we take neither: AES-CBC-SHA suites are in the default
//!    enabled set on every Server 2008 R2 / Windows 7 install this project
//!    targets, so RC4 buys nothing a real host needs. If an actual
//!    interop test ever finds a host that offers only RC4 or 3DES, that is
//!    a second, explicit escalation (`enable-md2`/`enable-rc5` come bundled
//!    with `weak-crypto` and cannot be taken separately, and enabling the
//!    legacy provider needs a process-lifetime guard that must never be
//!    dropped), not a quiet flag flip.
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

use crate::{BoxedStream, Result, Stream, TransportError, TrustDecision};

/// Upgrade an established byte stream to TLS 1.0/1.1 through OpenSSL.
///
/// STUB (PRDRDP/10 P0.6): always returns
/// [`TransportError::Tls`] naming the `legacy-tls` feature. No OpenSSL
/// context is built, no socket byte is touched, and the `server_name` and
/// `pin` parameters exist only to match the shape [`crate::tls::upgrade`]
/// will keep in phase 1b, so callers do not have to change again when the
/// real handshake lands.
pub async fn upgrade<S: Stream + 'static>(
    _stream: S,
    _server_name: &str,
    _pin: Option<&str>,
) -> Result<(BoxedStream, TrustDecision)> {
    Err(TransportError::Tls(
        "legacy TLS (feature `legacy-tls`) is not implemented yet; \
         the dependency and build are wired up, the handshake is phase 1b"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    #[tokio::test]
    async fn stub_upgrade_always_errors() {
        let (a, _b): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
        // `Result<(BoxedStream, TrustDecision), _>` has no `Debug` on the `Ok`
        // side (`dyn Stream` is not `Debug`), so match rather than
        // `unwrap_err()`.
        match upgrade(a, "example.test", None).await {
            Err(TransportError::Tls(msg)) => assert!(msg.contains("legacy-tls")),
            Err(other) => panic!("expected TransportError::Tls, got {other:?}"),
            Ok(_) => panic!("stub upgrade must always error"),
        }
    }
}
