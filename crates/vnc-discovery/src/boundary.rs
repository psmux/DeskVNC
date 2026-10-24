//! Finding Boundary computers: the machines DeskVNC Support (or DeskVNC's
//! own Get help panel) has opened to unattended helpers.
//!
//! Such a machine binds UDP 5940 for QUIC and answers TCP on the same port
//! with one line, `BOUNDARY1 <machine id>\n`, then closes. That line is the
//! whole fingerprint. The probe reads it and writes nothing, the same promise
//! the RFB probe makes, and the machine ID it learns is public: it is what
//! the machine publishes to the address directory anyway. Being let in is
//! still decided on the machine, by pairing or by its unattended password.
//!
//! A machine whose 5940 was taken listens on a random port, and one behind a
//! firewall that drops TCP never answers the probe at all. Both are found by
//! the DNS-SD advertisement instead ([`SERVICE_TYPE`], browsed in
//! `crate::mdns`), which carries the same ID, the real port and a name.
//!
//! The constants here are the other half of
//! `crates/boundary-session/src/nearby.rs` and `direct.rs`. This crate does
//! not link boundary-session (it would pull QUIC and a TLS stack into
//! discovery), so the two are kept in step by hand and by the live test in
//! `crates/boundary-session/tests/nearby.rs`.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// The port an unattended Boundary machine listens on, UDP for sessions and
/// TCP for its ID.
pub const BOUNDARY_PORT: u16 = 5940;

/// The DNS-SD service type an unattended Boundary machine advertises.
///
/// `_udp` because the session itself is QUIC. The label is short on purpose:
/// RFC 6335 caps a service name at fifteen characters and mdns-sd enforces
/// it, so `_deskvnc-boundary` would be refused by both ends.
pub const SERVICE_TYPE: &str = "_boundary._udp.local.";

/// The row label for a Boundary computer, from either source. One spelling,
/// so a scan hit and an mDNS sighting of the same machine never disagree
/// about what it is and the registry folds them into one row.
pub const LABEL: &str = "Boundary computer";

const GREETING: &[u8] = b"BOUNDARY1 ";
/// A machine ID is an Ed25519 public key, 32 bytes written as hex.
const ID_LEN: usize = 64;
/// The greeting, the ID and the newline: nothing longer is a Boundary answer.
const LINE_MAX: usize = GREETING.len() + ID_LEN + 1;
/// The machine writes its line the moment it accepts, so this is the same
/// budget the RFB banner gets.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

/// The machine ID in a TCP answer, lowercased, or `None` for anything that is
/// not exactly `BOUNDARY1 <64 hex>` with an optional trailing newline.
pub fn parse_greeting(line: &[u8]) -> Option<String> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let id = line.strip_prefix(GREETING)?;
    machine_id(std::str::from_utf8(id).ok()?)
}

/// `text` as a machine ID, lowercased, if it is one. Shared by the TCP probe
/// and the mDNS TXT record so both accept exactly the same thing.
pub fn machine_id(text: &str) -> Option<String> {
    (text.len() == ID_LEN && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| text.to_ascii_lowercase())
}

/// Connect to `addr` and read the one line a Boundary machine answers with.
///
/// Never writes. Reads at most [`LINE_MAX`] bytes, stopping at the newline,
/// and drops the socket. `None` for anything that does not answer, answers
/// slowly, or answers with something else (a VNC banner on a moved port, an
/// HTTP server).
pub async fn fingerprint(addr: SocketAddr, connect_timeout: Duration) -> Option<String> {
    let mut stream = timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let mut line = Vec::with_capacity(LINE_MAX);
    let read = async {
        let mut chunk = [0u8; LINE_MAX];
        while line.len() < LINE_MAX && !line.contains(&b'\n') {
            let want = LINE_MAX - line.len();
            let n = stream.read(&mut chunk[..want]).await.ok()?;
            if n == 0 {
                break;
            }
            line.extend_from_slice(&chunk[..n]);
        }
        Some(())
    };
    timeout(READ_TIMEOUT, read).await.ok()??;
    parse_greeting(&line)
}

/// A display name from a TXT record: trimmed, printable, and short enough
/// for a tile. The value is whatever the other machine chose to send, so it
/// is cleaned rather than trusted.
pub fn clean_name(name: &str) -> Option<String> {
    let name = name.trim();
    (!name.is_empty() && name.len() <= 80 && !name.chars().any(char::is_control))
        .then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "3ae432ab7fd87dbd85b26c69e3d00be3f1ad47688df3e79e650ea9c8f0440723";

    #[test]
    fn the_greeting_gives_the_id() {
        let line = format!("BOUNDARY1 {ID}\n");
        assert_eq!(parse_greeting(line.as_bytes()).as_deref(), Some(ID));
        // Without the newline (a short read that stopped at the cap) and
        // with a carriage return from some future writer, still the ID.
        assert_eq!(
            parse_greeting(&line.as_bytes()[..line.len() - 1]).as_deref(),
            Some(ID)
        );
        let crlf = format!("BOUNDARY1 {ID}\r\n");
        assert_eq!(parse_greeting(crlf.as_bytes()).as_deref(), Some(ID));
        // Upper case hex is the same key, and is stored one way.
        let upper = format!("BOUNDARY1 {}\n", ID.to_ascii_uppercase());
        assert_eq!(parse_greeting(upper.as_bytes()).as_deref(), Some(ID));
    }

    #[test]
    fn anything_else_is_not_a_boundary_computer() {
        for bad in [
            b"RFB 003.008\n".to_vec(),
            b"HTTP/1.1 400 Bad Request\r\n".to_vec(),
            b"BOUNDARY1 \n".to_vec(),
            format!("BOUNDARY1 {}\n", &ID[1..]).into_bytes(),
            format!("BOUNDARY1 {ID}0\n").into_bytes(),
            format!("BOUNDARY2 {ID}\n").into_bytes(),
            format!("BOUNDARY1 {}zz\n", &ID[2..]).into_bytes(),
            format!("boundary1 {ID}\n").into_bytes(),
            Vec::new(),
        ] {
            assert!(
                parse_greeting(&bad).is_none(),
                "{:?} parsed",
                String::from_utf8_lossy(&bad)
            );
        }
    }

    #[test]
    fn a_txt_name_is_cleaned() {
        assert_eq!(clean_name("  Studio iMac ").as_deref(), Some("Studio iMac"));
        assert_eq!(clean_name(""), None);
        assert_eq!(clean_name("a\u{7}b"), None);
        assert_eq!(clean_name(&"x".repeat(81)), None);
    }

    /// End to end against a socket that answers the way `direct::answer`
    /// does, and against one that answers like a VNC server on that port.
    #[tokio::test]
    async fn the_probe_reads_the_line_and_writes_nothing() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(format!("BOUNDARY1 {ID}\n").as_bytes())
                .await
                .unwrap();
            // Whatever the probe sends lands here. It must be nothing.
            let mut rest = Vec::new();
            let _ = timeout(Duration::from_millis(500), sock.read_to_end(&mut rest)).await;
            rest
        });
        let id = fingerprint(addr, Duration::from_millis(500)).await;
        assert_eq!(id.as_deref(), Some(ID));
        assert!(
            server.await.unwrap().is_empty(),
            "the probe wrote to the machine"
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = sock.write_all(b"RFB 003.008\n").await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        assert_eq!(fingerprint(addr, Duration::from_millis(500)).await, None);
    }
}
