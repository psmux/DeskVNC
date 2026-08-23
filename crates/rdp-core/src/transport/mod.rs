//! Opening the byte stream, framing it, and writing to it
//! (PRDRDP/12 §3.8).
//!
//! Three files: [`framer`] decides where a PDU ends, [`writer`] owns the
//! write half in its own task, and this one opens the stream and upgrades it
//! to TLS.

pub mod framer;
pub mod writer;

use std::time::Duration;

use remote_core::{CertPins, ConnectOptions, SessionEvent, SessionState};
use tokio::sync::mpsc;
use vnc_transport::{BoxedStream, TrustDecision};

use crate::error::{ConnectStage, RdpError, Result};

/// What a completed TLS upgrade hands back (PRDRDP/00 R47).
///
/// PRDRDP/12 §3.8 puts this type in `vnc-transport`, because both TLS
/// backends have to produce the same value and the shared module is the only
/// place that can guarantee it, and has `rdp-core` re-export the name and add
/// nothing. **It is declared here instead, and that is a gap rather than a
/// design choice.** `vnc_transport::tls::upgrade` returns
/// `(BoxedStream, TrustDecision)` and nothing else
/// (`crates/vnc-transport/src/tls.rs:59`), so the two certificate fields
/// below are `None` on every path today and CredSSP cannot run. PRDRDP/03
/// §4.3 owns the additive change to `vnc-transport`
/// (`upgrade_with_identity`), and [`crate::connection::nla`] is the one place
/// that reads the fields.
///
/// Every field is owned, which is the whole of R47: this crate depends on
/// neither `rustls-pki-types` nor `openssl`, so a second backend cannot leak
/// its types up here.
pub struct TlsUpgrade {
    /// The upgraded stream.
    pub stream: BoxedStream,
    /// What the trust on first use verifier decided.
    pub trust: TrustDecision,
    /// The leaf certificate, DER encoded.
    ///
    /// Two things need it and both need the same bytes: the SHA-256 of its
    /// `SubjectPublicKeyInfo` is the pin, and the `subjectPublicKey` inside
    /// it is what CredSSP's `pubKeyAuth` binds to (MS-CSSP 3.1.5). Extracting
    /// it once, at the moment of the upgrade, is why PRDRDP/03 §4 asks
    /// `vnc-transport` for an upgrade variant that returns it.
    pub server_certificate: Option<Vec<u8>>,
    /// The certificate's `signatureAlgorithm` OID, DER content octets only.
    ///
    /// RFC 5929 §4.1 picks the `tls-server-end-point` hash from it, so the
    /// channel binding cannot be computed without it.
    pub signature_algorithm_oid: Option<Vec<u8>>,
}

/// A hand written `Debug`, because `BoxedStream` is a trait object over a
/// trait that does not require `Debug`, and because a certificate is a value
/// that identifies a host: its length is diagnostic, its bytes are not
/// (PRDRDP/12 §6.4, §6.5).
impl std::fmt::Debug for TlsUpgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsUpgrade")
            .field("trust", &self.trust)
            .field(
                "server_certificate",
                &self.server_certificate.as_ref().map(Vec::len),
            )
            .field(
                "signature_algorithm_oid",
                &self.signature_algorithm_oid.as_ref().map(Vec::len),
            )
            .finish_non_exhaustive()
    }
}

/// Open the stream this attempt runs over, within `connect_timeout`.
///
/// An injected connector when the options carry one (the SSH tunnel from
/// `vnc-files`), plain TCP otherwise. This is the same decision `vnc-core`
/// makes at `crates/vnc-core/src/session/connection.rs:97`, including the
/// reason a connector resolves the endpoint itself: `localhost` names the
/// *tunnelled* machine's loopback, so resolving it here would be wrong as
/// well as useless. That property matters more for RDP than for VNC, because
/// an SSH tunnel to a jump host and then RDP to a Windows box is a common
/// shape.
///
/// # Errors
///
/// Whatever the dial reports, classified: [`RdpError::ConnectionRefused`],
/// [`RdpError::Timeout`] and [`RdpError::ResolveFailed`] are separate
/// variants because the reconnect supervisor treats them the same way but a
/// user does not.
pub async fn open_stream(
    options: &ConnectOptions,
    events: &mpsc::Sender<SessionEvent>,
) -> Result<BoxedStream> {
    let host = options.host.clone();
    let port = options.port;

    if let Some(connector) = &options.connector {
        remote_core::emit_state(events, SessionState::Connecting).await?;
        tracing::info!(transport = %connector.0.describe(), "opening the injected transport");
        return Ok(connector
            .0
            .connect(&host, port, options.connect_timeout)
            .await?);
    }

    remote_core::emit_state(events, SessionState::Resolving).await?;
    // Resolution and connection both go through vnc-transport so we inherit
    // TCP_NODELAY, the tuned keepalive schedule, IPv4 first ordering, and the
    // refused versus timeout classification the supervisor depends on.
    let addrs = vnc_transport::tcp::resolve(&host, port, options.connect_timeout).await?;
    if addrs.is_empty() {
        return Err(RdpError::ResolveFailed(host));
    }

    remote_core::emit_state(events, SessionState::Connecting).await?;
    let tcp = vnc_transport::tcp::connect(&host, port, options.connect_timeout).await?;
    Ok(Box::pin(tcp))
}

/// Upgrade to TLS with trust on first use (MS-RDPBCGR 5.4.5.1).
///
/// The pin is looked up under [`remote_core::PinScheme::Tls`]. PRDRDP/12 §3.8
/// asks for a new `PinScheme::RdpTls` variant so an RDP pin and a VeNCrypt
/// pin for the same host cannot be confused; it does not exist yet
/// (`crates/remote-core/src/pins.rs:35` still has a two entry `ALL`), so this
/// uses the TLS scheme and the report names the gap.
///
/// `legacy_tls` is permission, never a request. With it false and the server
/// offering nothing above TLS 1.1 the attempt fails rather than downgrading
/// (AGENT_BRIEF V3-B). The second backend is behind `vnc-transport`'s
/// `legacy-tls` feature and this crate would forward the flag to it; nothing
/// forwards it today, so the argument is recorded and refused rather than
/// silently ignored.
///
/// # Errors
///
/// [`RdpError::CertificateMismatch`] when the pinned key changed, which is a
/// hard stop and never auto retried, and [`RdpError::Tls`] for anything else
/// the handshake reports.
pub async fn upgrade_tls(
    stream: BoxedStream,
    server_name: &str,
    pins: &CertPins,
    legacy_tls: bool,
) -> Result<TlsUpgrade> {
    if legacy_tls {
        // Silently ignoring the setting would mean a user who turned it on to
        // reach a Server 2008 R2 host sees the same failure with no clue that
        // the switch did nothing.
        return Err(RdpError::Tls(format!(
            "{server_name}: the TLS 1.0 and 1.1 backend is not wired up in this build \
             (AGENT_BRIEF V3-B, PRDRDP/12 §3.16)"
        )));
    }

    let pin = pins.for_scheme(remote_core::PinScheme::Tls);
    let (stream, trust) = vnc_transport::tls::upgrade(stream, server_name, pin).await?;

    Ok(TlsUpgrade {
        stream,
        trust,
        // See this type's documentation: `vnc_transport::tls::upgrade` does
        // not hand back the leaf certificate, so these stay empty and CredSSP
        // reports a named gap rather than computing a binding from nothing.
        server_certificate: None,
        signature_algorithm_oid: None,
    })
}

/// Wrap `fut` in `limit`, reporting a timeout against `stage` so the message
/// names the phase that was waiting.
///
/// The per stage budgets are PRDRDP/03 §3.3's. They are deliberately longer
/// than [`ConnectOptions::connect_timeout`], which keeps its "how long the
/// dial may take" meaning: a cold domain logon spends twenty to thirty
/// seconds inside capability exchange with nothing wrong.
///
/// # Errors
///
/// [`RdpError::Timeout`] naming `stage`, or whatever `fut` returned.
pub async fn with_timeout<T>(
    stage: ConnectStage,
    limit: Duration,
    fut: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err(RdpError::Timeout { stage }),
    }
}

/// X.224 and the TLS handshake (PRDRDP/03 §3.3).
pub const X224_TIMEOUT: Duration = Duration::from_secs(15);
/// The MCS connect and channel connection phases (PRDRDP/03 §3.3).
pub const MCS_TIMEOUT: Duration = Duration::from_secs(30);
