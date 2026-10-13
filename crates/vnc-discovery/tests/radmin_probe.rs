//! Radmin discovery is a bounded pre-authentication greeting, not a port guess.
//! Every socket here is a synthetic loopback endpoint; no LAN scan is performed.
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vnc_discovery::{Discovery, DiscoveryEvent, ProtocolKind, ScanOptions, Subnet};

const GREETING: [u8; 14] = [1, 0, 0, 0, 5, 0, 0, 2, 0x27, 0x27, 2, 0, 0, 0];
const ACK: [u8; 14] = [1, 0, 0, 0, 5, 0, 0, 0, 0x27, 0x27, 0, 0, 0, 0];

async fn fake_radmin(reply: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 14];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, GREETING);
        // Fragment the response to ensure discovery reads the whole greeting.
        for chunk in reply.chunks(2) {
            stream.write_all(chunk).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut remaining))
            .await
            .unwrap()
            .unwrap();
        assert!(
            remaining.is_empty(),
            "Discovery must never start authentication"
        );
    });
    (addr, task)
}

fn options(port: u16) -> ScanOptions {
    ScanOptions {
        subnets: vec![Subnet::new(Ipv4Addr::LOCALHOST, 32)],
        ports: vec![1],
        probe_rdp: false,
        rdp_ports: vec![],
        probe_radmin: true,
        radmin_ports: vec![port],
        include_local: true,
        resolve_names: false,
        probe_other_services: false,
        connect_timeout: Duration::from_millis(100),
        max_rate_per_sec: 1000,
        ..ScanOptions::default()
    }
}

#[tokio::test]
async fn recognizes_fragmented_greeting_and_sends_no_credentials() {
    let (addr, server) = fake_radmin(ACK.to_vec()).await;
    assert!(Discovery::radmin_fingerprint(addr, Duration::from_millis(100)).await);
    server.await.unwrap();
}

#[tokio::test]
async fn rejects_wrong_protocol_and_truncated_replies() {
    for reply in [b"RFB 003.008\n".to_vec(), vec![0; 14], ACK[..8].to_vec()] {
        let (addr, server) = fake_radmin(reply).await;
        assert!(!Discovery::radmin_fingerprint(addr, Duration::from_millis(100)).await);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn a_silent_open_port_is_not_a_radmin_server() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
    });
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        Discovery::radmin_fingerprint(addr, Duration::from_millis(100)),
    )
    .await
    .unwrap();
    assert!(!result);
    server.abort();
}

#[tokio::test]
async fn scan_finds_radmin_without_a_vnc_or_rdp_responder() {
    let (addr, server) = fake_radmin(ACK.to_vec()).await;
    let (tx, mut rx) = mpsc::channel(16);
    let count = Discovery::new()
        .scan_subnet(options(addr.port()), tx, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(count, 1);
    let mut found = Vec::new();
    let mut complete = false;
    while let Some(event) = rx.recv().await {
        match event {
            DiscoveryEvent::Found(host) => found.push(host),
            DiscoveryEvent::ScanComplete { found } => {
                assert_eq!(found, 1);
                complete = true;
            }
            _ => {}
        }
    }
    assert!(complete);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].protocol, ProtocolKind::Radmin);
    assert_eq!(found[0].port, addr.port());
    assert_eq!(found[0].server_label, "Radmin server");
    assert!(found[0].rfb_version.is_none() && found[0].rdp.is_none());
    assert!(found[0].security_types.is_empty());
    server.await.unwrap();
}

#[tokio::test]
async fn disabling_radmin_opens_no_radmin_socket() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut opts = options(listener.local_addr().unwrap().port());
    opts.probe_radmin = false;
    let (tx, _rx) = mpsc::channel(16);
    assert_eq!(
        Discovery::new()
            .scan_subnet(opts, tx, CancellationToken::new())
            .await
            .unwrap(),
        0
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cancelling_an_inflight_radmin_probe_closes_its_socket() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let opts = options(listener.local_addr().unwrap().port());
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let (tx, _rx) = mpsc::channel(16);
    let scan = tokio::spawn(async move { Discovery::new().scan_subnet(opts, tx, token).await });
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut greeting = [0; 14];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, GREETING);
    cancel.cancel();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), scan)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        0
    );
    let mut buf = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
