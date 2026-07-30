//! Capability probe (PRD/08 §2.1).
//!
//! On session start the shell asks "is SSH even reachable here?" and enables
//! or disables the Files button accordingly. This must be **quiet**: a closed
//! port is the normal case for a Windows box without OpenSSH Server, not an
//! error worth a toast.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Longest we will wait for the server's identification string once the TCP
/// handshake is done. An open port with no banner still counts as reachable.
const BANNER_WAIT: Duration = Duration::from_millis(600);

/// Is an SSH server reachable at `host:port` within `timeout`?
///
/// Returns `true` when the port accepts a connection; when the peer also
/// sends an `SSH-` identification string we know it is really SSH. Never
/// returns an error, an unreachable host is an answer, not a failure.
pub async fn probe_ssh(host: &str, port: u16, timeout: Duration) -> bool {
    let deadline = timeout.max(Duration::from_millis(200));
    let connect = TcpStream::connect((host, port));
    let mut stream = match tokio::time::timeout(deadline, connect).await {
        Ok(Ok(stream)) => stream,
        // Refused, unreachable, DNS failure, or slower than the deadline.
        Ok(Err(_)) | Err(_) => return false,
    };

    // Best effort: SSH servers greet first, so a short read confirms the
    // protocol without sending anything ourselves.
    let mut buf = [0u8; 4];
    match tokio::time::timeout(BANNER_WAIT, stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => &buf == b"SSH-",
        // Nothing said in time: the port is open, treat it as usable and let
        // the real connect produce a precise error if it is not.
        Err(_) => true,
        // Peer hung up immediately (fail2ban, tcpwrappers, wrong service).
        Ok(Err(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn a_closed_port_is_simply_unavailable() {
        // Bind then drop, so the port is almost certainly free.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(!probe_ssh("127.0.0.1", port, Duration::from_millis(500)).await);
    }

    #[tokio::test]
    async fn an_ssh_banner_is_recognised() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
                let _ = socket.flush().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        assert!(probe_ssh("127.0.0.1", port, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn some_other_service_on_the_port_is_not_ssh() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"HTTP/1.1 400 Bad Request\r\n").await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        assert!(!probe_ssh("127.0.0.1", port, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn an_unresolvable_host_is_not_an_error() {
        assert!(!probe_ssh("no-such-host.invalid", 22, Duration::from_millis(800)).await);
    }
}
