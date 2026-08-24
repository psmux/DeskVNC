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
use vnc_transport::BoxedStream;

use crate::error::{ConnectStage, RdpError, Result};

/// What a completed TLS upgrade hands back (PRDRDP/00 R47, spelled by R62).
///
/// Declared in `vnc-transport`, because both TLS backends have to produce the
/// same value and the shared module is the only place that can guarantee it
/// (PRDRDP/03 §4.7.1, PRDRDP/12 §3.8). This crate re-exports the name and adds
/// nothing: every field is owned, which is the whole of R47, so a second
/// backend cannot leak `rustls-pki-types` or `openssl` types up here.
///
/// [`crate::connection::nla`] is the one place that reads the two certificate
/// fields.
pub use vnc_transport::TlsUpgrade;

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
/// The pin is looked up under [`remote_core::PinScheme::RdpTls`], never under
/// [`remote_core::PinScheme::Tls`]. One host can serve VNC over VeNCrypt and
/// RDP on 3389 with two unrelated certificates, and sharing one pin row would
/// mean a certificate approved for one protocol silently vouching for the
/// other (PRDRDP/02 §2.1, PRDRDP/12 §3.8).
///
/// `legacy_tls` is permission, never a request. With it false and the server
/// offering nothing above TLS 1.1 the attempt fails rather than downgrading
/// (AGENT_BRIEF V3-B). The selection is made here, before the socket is
/// touched, and nothing the server says is an input to it (PRDRDP/03 §4.7.2).
/// This crate does not enable `vnc-transport`'s `legacy-tls` feature, so
/// `TlsBackend::Legacy` does not exist in this build and the flag is refused
/// with a message rather than silently ignored.
///
/// # Errors
///
/// [`RdpError::CertificateMismatch`] when the pinned key changed, which is a
/// hard stop and never auto retried,
/// [`RdpError::LegacyTlsUnavailable`] when the host profile asks for a
/// backend this build does not have, and [`RdpError::Tls`] for anything else
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
        return Err(RdpError::LegacyTlsUnavailable(server_name.to_owned()));
    }

    let pin = pins.for_scheme(remote_core::PinScheme::RdpTls);
    Ok(vnc_transport::tls::upgrade_with_identity(
        stream,
        server_name,
        pin,
        vnc_transport::TlsBackend::Modern,
    )
    .await?)
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
