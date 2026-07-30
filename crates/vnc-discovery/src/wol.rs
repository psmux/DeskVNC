//! Wake-on-LAN magic packets and wake-then-connect polling.

use crate::error::{Error, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Instant};

/// WoL destination ports (9 = discard, 7 = echo; both are used in the wild).
const WOL_PORTS: [u16; 2] = [9, 7];
/// Poll interval for [`wake_and_wait`].
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Per-attempt TCP connect timeout while polling.
const POLL_CONNECT_TIMEOUT: Duration = Duration::from_millis(800);

/// Parse a MAC address from the common textual forms:
/// `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`, or bare `AABBCCDDEEFF`.
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let cleaned: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect();
    if cleaned.len() != 12 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::InvalidMac(s.to_string()));
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        let hi =
            hex_val(cleaned.as_bytes()[i * 2]).ok_or_else(|| Error::InvalidMac(s.to_string()))?;
        let lo = hex_val(cleaned.as_bytes()[i * 2 + 1])
            .ok_or_else(|| Error::InvalidMac(s.to_string()))?;
        *byte = (hi << 4) | lo;
    }
    Ok(mac)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Build the 102-byte magic packet: 6×`0xFF` followed by the MAC repeated 16×.
pub fn magic_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut pkt = [0u8; 102];
    for b in pkt.iter_mut().take(6) {
        *b = 0xFF;
    }
    for rep in 0..16 {
        let start = 6 + rep * 6;
        pkt[start..start + 6].copy_from_slice(&mac);
    }
    pkt
}

/// Send a Wake-on-LAN magic packet.
///
/// Sends to the limited broadcast `255.255.255.255`, the subnet-directed
/// `broadcast` (if given), and the unicast `last_known_ip` (if given), on both
/// UDP port 9 and 7. Individual send failures are tolerated; the call only
/// errors if the socket cannot be created or the MAC is invalid.
pub async fn wake_on_lan(
    mac: &str,
    broadcast: Option<Ipv4Addr>,
    last_known_ip: Option<Ipv4Addr>,
) -> Result<()> {
    let mac = parse_mac(mac)?;
    let packet = magic_packet(mac);

    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.set_broadcast(true)?;

    let mut targets: Vec<Ipv4Addr> = vec![Ipv4Addr::BROADCAST];
    if let Some(b) = broadcast {
        targets.push(b);
    }
    if let Some(ip) = last_known_ip {
        targets.push(ip);
    }

    let mut sent_any = false;
    for ip in targets {
        for &port in &WOL_PORTS {
            let dst = SocketAddrV4::new(ip, port);
            match socket.send_to(&packet, dst).await {
                Ok(_) => sent_any = true,
                Err(e) => tracing::debug!(%ip, port, error = %e, "WoL send failed"),
            }
        }
    }

    if sent_any {
        Ok(())
    } else {
        Err(Error::Io(std::io::Error::other(
            "no magic packet could be sent",
        )))
    }
}

/// Wake `target`'s host, then poll TCP until it answers or `timeout` elapses.
///
/// Derives a `/24` subnet-directed broadcast and unicast last-known IP from the
/// target when it is IPv4. Returns `true` if the port came up in time.
pub async fn wake_and_wait(mac: &str, target: SocketAddr, timeout_total: Duration) -> Result<bool> {
    let (broadcast, last_ip) = match target.ip() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            (Some(Ipv4Addr::new(o[0], o[1], o[2], 255)), Some(v4))
        }
        std::net::IpAddr::V6(_) => (None, None),
    };

    wake_on_lan(mac, broadcast, last_ip).await?;

    let deadline = Instant::now() + timeout_total;
    loop {
        if let Ok(Ok(_stream)) = timeout(POLL_CONNECT_TIMEOUT, TcpStream::connect(target)).await {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        // Re-send periodically in case the first packet was missed.
        let _ = wake_on_lan(mac, broadcast, last_ip).await;
        tokio::time::sleep(POLL_INTERVAL).await;
        if Instant::now() >= deadline {
            return Ok(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mac_colon() {
        assert_eq!(
            parse_mac("AA:BB:CC:DD:EE:FF").unwrap(),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
    }

    #[test]
    fn parses_mac_dash_and_bare_and_lower() {
        assert_eq!(
            parse_mac("aa-bb-cc-dd-ee-ff").unwrap(),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
        assert_eq!(
            parse_mac("001122334455").unwrap(),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
    }

    #[test]
    fn rejects_bad_mac() {
        assert!(parse_mac("AA:BB:CC:DD:EE").is_err()); // too short
        assert!(parse_mac("GG:BB:CC:DD:EE:FF").is_err()); // non-hex
        assert!(parse_mac("").is_err());
        assert!(parse_mac("AA:BB:CC:DD:EE:FF:00").is_err()); // too long
    }

    #[test]
    fn magic_packet_layout() {
        let mac = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let pkt = magic_packet(mac);
        assert_eq!(pkt.len(), 102);
        // First 6 bytes are 0xFF.
        assert_eq!(&pkt[0..6], &[0xFF; 6]);
        // Then the MAC repeated exactly 16 times.
        for rep in 0..16 {
            let start = 6 + rep * 6;
            assert_eq!(&pkt[start..start + 6], &mac, "repetition {rep}");
        }
        // Total structure: 6 + 16*6 = 102.
        assert_eq!(6 + 16 * 6, 102);
    }
}
