//! Plain TCP transport.
//!
//! Latency, not throughput, is what a remote-desktop session is judged on, so
//! `TCP_NODELAY` is always set: a 40 ms Nagle delay on a mouse-move packet is
//! immediately visible to the user.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};

use crate::{Result, TransportError};

/// Keepalive tuning (PRD/05 §6.4): 15 s idle, 5 s interval, 3 probes, a dead
/// peer is noticed in ~30 s instead of the OS default (often 2 h on
/// Linux/macOS), which is what makes auto-reconnect feel immediate after a
/// cable pull or a Wi-Fi drop where no RST is ever delivered.
///
/// Applied via `socket2`. The probe *count* is not settable on every platform,
/// so that part stays best-effort; idle and interval are the ones that matter.
/// Application-level liveness is additionally covered by the session's RFB
/// fence probes.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub const KEEPALIVE_PROBES: u32 = 3;

/// Apply the keepalive schedule above to an already-connected stream.
///
/// Uses a borrowed socket so ownership of the tokio `TcpStream` is untouched.
fn apply_keepalive(stream: &TcpStream) {
    use socket2::{SockRef, TcpKeepalive};

    // `mut` is only used by the `with_retries` branch below, which is compiled
    // out on the targets that do not support it. Without this, clippy's
    // `unused_mut` fires there and CI runs with `-D warnings`.
    #[cfg_attr(any(target_os = "windows", target_os = "openbsd"), allow(unused_mut))]
    let mut ka = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);

    // `with_retries` is unavailable on some targets (notably Windows and
    // older BSDs); idle+interval already give us fast dead-peer detection.
    #[cfg(not(any(target_os = "windows", target_os = "openbsd")))]
    {
        ka = ka.with_retries(KEEPALIVE_PROBES);
    }

    let sock = SockRef::from(stream);
    if let Err(e) = sock.set_tcp_keepalive(&ka) {
        tracing::debug!(error = %e, "could not tune tcp keepalive; using OS defaults");
    }
}

/// Resolve `host` and connect, trying every returned address in order.
///
/// `timeout` bounds resolution *and* each individual connect attempt.
/// Errors distinguish refusal (server not listening, usually permanent until
/// the user fixes the port) from timeout (host asleep/filtered, retryable).
pub async fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addrs = resolve(host, port, timeout).await?;
    if addrs.is_empty() {
        return Err(TransportError::Resolve(host.to_string()));
    }

    let mut last_err: Option<TransportError> = None;
    for addr in addrs {
        match connect_addr(addr, timeout).await {
            Ok(stream) => {
                configure(&stream);
                tracing::debug!(%addr, "tcp connected");
                return Ok(stream);
            }
            Err(e) => {
                tracing::debug!(%addr, error = %e, "tcp connect attempt failed");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| TransportError::Resolve(host.to_string())))
}

/// Resolve a host:port to socket addresses, preferring IPv4 first (VNC servers
/// on consumer networks are far more often reachable over v4, and a dead v6
/// route otherwise burns the whole connect timeout).
pub async fn resolve(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let target = format!("{host}:{port}");
    let lookup = tokio::time::timeout(timeout, tokio::net::lookup_host(target));
    let iter = match lookup.await {
        Err(_) => return Err(TransportError::Timeout),
        Ok(Err(e)) => {
            tracing::debug!(%host, error = %e, "dns resolution failed");
            return Err(TransportError::Resolve(host.to_string()));
        }
        Ok(Ok(iter)) => iter,
    };

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in iter {
        if addr.is_ipv4() {
            v4.push(addr)
        } else {
            v6.push(addr)
        }
    }
    v4.extend(v6);
    Ok(v4)
}

async fn connect_addr(addr: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }?;

    // Best effort, see the note on KEEPALIVE_IDLE above.
    if let Err(e) = socket.set_keepalive(true) {
        tracing::debug!(error = %e, "could not enable tcp keepalive");
    }

    match tokio::time::timeout(timeout, socket.connect(addr)).await {
        Err(_) => Err(TransportError::Timeout),
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(map_connect_error(e, addr)),
    }
}

fn map_connect_error(e: std::io::Error, addr: SocketAddr) -> TransportError {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => TransportError::Refused(addr.to_string()),
        TimedOut => TransportError::Timeout,
        // "no route to host" / "network unreachable" behave like a timeout for
        // the reconnect policy (transient), so leave them as I/O errors.
        _ => TransportError::Io(e),
    }
}

/// Apply the per-connection socket options a VNC session wants.
fn configure(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!(error = %e, "could not set TCP_NODELAY");
    }
    apply_keepalive(stream);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refused_is_distinct_from_timeout() {
        // Bind and immediately drop the listener so the port is (almost
        // certainly) closed but routable, loopback refuses instantly.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let err = connect("127.0.0.1", addr.port(), Duration::from_secs(2))
            .await
            .unwrap_err();

        // Windows does not reliably answer a closed loopback port with
        // WSAECONNREFUSED: the SYN is dropped and the attempt runs into our
        // deadline instead, so Timeout is a legitimate outcome there. The
        // mapping itself is still asserted, just with the wider set. Every
        // other platform must produce a prompt refusal, which is what the
        // reconnect policy keys off to decide "permanent until the user fixes
        // the port" versus "retry".
        #[cfg(windows)]
        assert!(
            matches!(err, TransportError::Refused(_) | TransportError::Timeout),
            "expected refusal or timeout, got {err:?}"
        );
        #[cfg(not(windows))]
        assert!(
            matches!(err, TransportError::Refused(_)),
            "expected refusal, got {err:?}"
        );
    }

    #[tokio::test]
    async fn connects_and_sets_nodelay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = connect("127.0.0.1", addr.port(), Duration::from_secs(2))
            .await
            .unwrap();
        assert!(stream.nodelay().unwrap());
    }
}
