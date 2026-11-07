//! Connect-time fingerprinting and the on-demand deep probe, for both
//! protocols.
//!
//! The RFB pair is [`fingerprint`] and [`deep_probe`]; the RDP pair is
//! [`rdp_fingerprint`] and [`rdp_deep_probe`], and they are the same shape for
//! the same reason. The bulk sweep learns what a host is with the smallest
//! exchange that answers the question, and the on-demand probe spends a second
//! connection on the one host the user asked about.
//!
//! Neither RDP function parses a byte itself: the request and the parser are
//! `rdp-pdu`'s and the mapping is [`crate::rdpnego`]'s.

use crate::banner::{parse_banner, Banner};
use crate::error::{Error, Result};
use crate::rdpnego;
use crate::types::RdpCaps;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Timeout for reading the 12-byte banner once connected.
const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(200);
/// Timeout for reads during a deep probe.
const PROBE_READ_TIMEOUT: Duration = Duration::from_millis(800);
/// Longest refusal reason a deep probe reads. The length on the wire is a
/// u32, and a probe has no reason to allocate whatever a server claims.
const MAX_REASON: usize = 8192;

/// Connect to `addr`, read the RFB banner, and return it if valid.
///
/// This is the bulk-sweep fingerprint: it connects, reads exactly 12 bytes with
/// a short timeout, and **never** sends anything back, no auth, no version
/// reply, so it generates minimal server logging. The socket is dropped on
/// return.
pub async fn fingerprint(addr: SocketAddr, connect_timeout: Duration) -> Option<Banner> {
    let mut stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let mut buf = [0u8; 12];
    match timeout(BANNER_READ_TIMEOUT, stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => parse_banner(&buf),
        _ => None,
    }
    // stream dropped here, no bytes ever written back.
}

/// Deep probe: complete the RFB version handshake and read the server's
/// security-type list, then close the socket **without authenticating**.
///
/// Per PRD/04 §5 this is on-demand only. It writes back the negotiated version
/// (the same version the server offered, which is always a valid client reply)
/// and reads the security types, then drops the connection before any
/// challenge/response, so it never trips fail2ban/UseBlacklist on the server.
///
/// A server that refuses the connection instead of offering types gives
/// [`Error::Refused`] with the reason it sent, so the caller can show why
/// rather than an empty list that reads as "offers nothing".
pub async fn deep_probe(addr: SocketAddr) -> Result<Vec<u8>> {
    let connect_to = Duration::from_millis(1500);
    let mut stream = timeout(connect_to, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Probe {
            addr,
            reason: "connect timed out".into(),
        })??;

    // Read the server banner.
    let mut banner = [0u8; 12];
    timeout(PROBE_READ_TIMEOUT, stream.read_exact(&mut banner))
        .await
        .map_err(|_| Error::Probe {
            addr,
            reason: "banner read timed out".into(),
        })?
        .map_err(|e| Error::Probe {
            addr,
            reason: format!("banner read failed: {e}"),
        })?;

    let parsed = parse_banner(&banner).ok_or_else(|| Error::Probe {
        addr,
        reason: "not an RFB server".into(),
    })?;

    // Reply with the server's own version string (a valid client choice).
    timeout(PROBE_READ_TIMEOUT, stream.write_all(&banner))
        .await
        .map_err(|_| Error::Probe {
            addr,
            reason: "version write timed out".into(),
        })?
        .map_err(|e| Error::Probe {
            addr,
            reason: format!("version write failed: {e}"),
        })?;

    // RFB 3.3: server sends a single 4-byte (u32) security type.
    // RFB 3.7+: server sends u8 count, then `count` type bytes.
    // In both a 0 is a refusal, followed by a u32 length and a reason string
    // (RFC 6143 7.1.2, and 3.3's ConnFailed has the same shape).
    let is_legacy_33 = parsed.major == 3 && parsed.minor < 7;
    let types = if is_legacy_33 {
        let mut b = [0u8; 4];
        read_exact_to(&mut stream, &mut b, addr).await?;
        let sec = u32::from_be_bytes(b);
        if sec == 0 {
            return Err(refusal(&mut stream, addr).await);
        }
        let sec = u8::try_from(sec).map_err(|_| Error::Probe {
            addr,
            reason: format!("RFB 3.3 security type {sec} is out of range"),
        })?;
        vec![sec]
    } else {
        let mut count_buf = [0u8; 1];
        read_exact_to(&mut stream, &mut count_buf, addr).await?;
        let count = count_buf[0] as usize;
        if count == 0 {
            return Err(refusal(&mut stream, addr).await);
        } else {
            // Guard against absurd counts (max is 255 anyway, so this is safe).
            let mut list = vec![0u8; count];
            read_exact_to(&mut stream, &mut list, addr).await?;
            list
        }
    };

    // Close immediately, never authenticate.
    let _ = stream.shutdown().await;
    Ok(types)
}

/// Connect to `addr`, negotiate X.224, and return what the server said.
///
/// This is the bulk sweep's RDP probe, and it is the counterpart of
/// [`fingerprint`]: one write, one read, then the socket is dropped. It
/// advertises TLS and NLA, never standard RDP security, and it sends no
/// cookie, so nothing that could identify a user reaches the server's event
/// log (MS-RDPBCGR 2.2.1.1).
///
/// When the server selects TLS or NLA the probe reads the certificate subject
/// on the *same* connection, which is the name the resolution ladder's last
/// rung would otherwise open a second connection to 3389 to read.
///
/// `None` for anything that is not an RDP server. On a subnet with no RDP
/// hosts that is a refused connect, which costs a rate limiter slot and about
/// a millisecond, and no VNC result ever waits on it.
pub async fn rdp_fingerprint(addr: SocketAddr, connect_timeout: Duration) -> Option<RdpCaps> {
    rdpnego::probe(addr, connect_timeout, rdpnego::SWEEP_PROTOCOLS, true).await
}

/// Deep probe an RDP host: everything [`rdp_fingerprint`] learns, plus whether
/// NLA is *required*.
///
/// The second answer needs a second connection advertising `PROTOCOL_SSL`
/// alone, because a server that permits both selects the stronger one and so
/// never reveals whether it would have refused TLS by itself. That doubles the
/// connections to one host, which is why it is on demand: the user asked about
/// this host, and that is the right place to spend them.
///
/// Still never authenticates. The second exchange is the same nineteen bytes
/// with one flag changed.
pub async fn rdp_deep_probe(addr: SocketAddr) -> Result<RdpCaps> {
    let connect_to = Duration::from_millis(1500);
    let mut caps = rdpnego::probe(addr, connect_to, rdpnego::SWEEP_PROTOCOLS, true)
        .await
        .ok_or_else(|| Error::Probe {
            addr,
            reason: "not an RDP server, or it refused the negotiation".into(),
        })?;
    // The certificate is already in hand from the first exchange, so the
    // second one asks only the question it exists to answer.
    let ssl_only = rdpnego::probe(addr, connect_to, rdpnego::SSL_ONLY_PROTOCOLS, false).await;
    rdpnego::apply_ssl_only_answer(&mut caps, ssl_only.as_ref());
    Ok(caps)
}

/// Read exactly `buf.len()` bytes with the probe timeout, mapping errors.
/// Read the reason that follows a refusal and turn it into [`Error::Refused`].
///
/// The refusal is the answer that matters, so a reason that fails to arrive
/// still yields `Refused`, with a note saying the server sent none, rather
/// than hiding the refusal behind a read error.
async fn refusal(stream: &mut TcpStream, addr: SocketAddr) -> Error {
    let mut len = [0u8; 4];
    let reason = match read_exact_to(stream, &mut len, addr).await {
        Ok(()) => {
            let len = (u32::from_be_bytes(len) as usize).min(MAX_REASON);
            let mut text = vec![0u8; len];
            match read_exact_to(stream, &mut text, addr).await {
                Ok(()) => String::from_utf8_lossy(&text).trim().to_string(),
                Err(_) => String::new(),
            }
        }
        Err(_) => String::new(),
    };
    let _ = stream.shutdown().await;
    Error::Refused {
        addr,
        reason: if reason.is_empty() {
            "the server gave no reason".into()
        } else {
            reason
        },
    }
}

async fn read_exact_to(stream: &mut TcpStream, buf: &mut [u8], addr: SocketAddr) -> Result<()> {
    timeout(PROBE_READ_TIMEOUT, stream.read_exact(buf))
        .await
        .map_err(|_| Error::Probe {
            addr,
            reason: "security-type read timed out".into(),
        })?
        .map_err(|e| Error::Probe {
            addr,
            reason: format!("security-type read failed: {e}"),
        })?;
    Ok(())
}
