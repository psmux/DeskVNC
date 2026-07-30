//! Connect-time RFB fingerprinting and the on-demand deep probe.

use crate::banner::{parse_banner, Banner};
use crate::error::{Error, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Timeout for reading the 12-byte banner once connected.
const BANNER_READ_TIMEOUT: Duration = Duration::from_millis(200);
/// Timeout for reads during a deep probe.
const PROBE_READ_TIMEOUT: Duration = Duration::from_millis(800);

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
    // RFB 3.7+: server sends u8 count, then `count` type bytes (0 => failure,
    // followed by a reason string we ignore).
    let is_legacy_33 = parsed.major == 3 && parsed.minor < 7;
    let types = if is_legacy_33 {
        let mut b = [0u8; 4];
        read_exact_to(&mut stream, &mut b, addr).await?;
        let sec = u32::from_be_bytes(b);
        // 0 means the connection failed; otherwise it's the single chosen type.
        if sec == 0 || sec > u32::from(u8::MAX) {
            Vec::new()
        } else {
            vec![sec as u8]
        }
    } else {
        let mut count_buf = [0u8; 1];
        read_exact_to(&mut stream, &mut count_buf, addr).await?;
        let count = count_buf[0] as usize;
        if count == 0 {
            Vec::new()
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

/// Read exactly `buf.len()` bytes with the probe timeout, mapping errors.
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
