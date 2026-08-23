//! The 3389 probe, end to end against fake servers on loopback.
//!
//! Hermetic: every server here is a `TcpListener` this test spawned. Nothing
//! reaches the network, and nothing needs a Windows machine.
//!
//! The fixtures are hand written bytes rather than something our own encoder
//! produced. A fixture built by the code under test cannot catch the code
//! under test being wrong, and the whole value of these is that they say what
//! a real server puts on the wire (MS-RDPBCGR 2.2.1.2).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use vnc_discovery::{
    Discovery, DiscoveryEvent, RdpServerKind, ScanOptions, Subnet, RESOLVE_BUDGET,
};

/// A Server X.224 Connection Confirm carrying an RDP_NEG_RSP.
///
/// ```text
/// 03 00 00 13     TPKT version 3, length 19 big endian
/// 0e d0 00 00     X.224 length indicator 14, CC CDT, DST-REF
/// 12 34 00        SRC-REF, classOptions
/// 02 <flags>      TYPE_RDP_NEG_RSP, flags
/// 08 00           length 8, little endian
/// <protocol LE>   selectedProtocol
/// ```
fn neg_rsp(flags: u8, selected_protocol: u32) -> Vec<u8> {
    let mut bytes = vec![
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, flags, 0x08, 0x00,
    ];
    bytes.extend_from_slice(&selected_protocol.to_le_bytes());
    bytes
}

/// The same, carrying an RDP_NEG_FAILURE instead.
fn neg_failure(code: u32) -> Vec<u8> {
    let mut bytes = vec![
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x03, 0x00, 0x08, 0x00,
    ];
    bytes.extend_from_slice(&code.to_le_bytes());
    bytes
}

/// A Connection Confirm with no `rdpNegData`: eleven bytes, and a real case.
fn no_neg_data() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
    ]
}

/// Every byte a client sent us, per connection.
type Received = Arc<Mutex<Vec<Vec<u8>>>>;

/// A fake server that answers each connection with `reply` and records what it
/// was sent. Returns its port and the recording.
async fn fake_server(reply: Vec<u8>, connections: usize) -> (u16, Received) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received: Received = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    tokio::spawn(async move {
        for _ in 0..connections {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let reply = reply.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut chunk = [0u8; 1024];
                // One read is enough: the probe writes its whole request in
                // one call and then waits for us.
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(300), sock.read(&mut chunk)).await
                {
                    got.extend_from_slice(&chunk[..n]);
                }
                let _ = sock.write_all(&reply).await;
                let _ = sock.flush().await;
                // Stay open long enough for the probe to decide it has
                // everything, then read whatever else it sends, which must be
                // nothing but a TLS ClientHello at most.
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(300), sock.read(&mut chunk)).await
                {
                    got.extend_from_slice(&chunk[..n]);
                }
                sink.lock().unwrap().push(got);
            });
        }
    });
    (port, received)
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn scan_options(port: u16) -> ScanOptions {
    ScanOptions {
        subnets: vec![Subnet::new(Ipv4Addr::LOCALHOST, 32)],
        // Port 0 is never listening, so the RFB half of phase 1 finds nothing
        // and only the RDP half can produce a row.
        ports: vec![1],
        concurrency: 16,
        connect_timeout: Duration::from_millis(500),
        max_rate_per_sec: 1000,
        allow_large: true,
        include_local: true,
        resolve_names: false,
        resolve_budget: RESOLVE_BUDGET,
        probe_other_services: false,
        probe_rdp: true,
        rdp_ports: vec![port],
    }
}

async fn run_scan(opts: ScanOptions) -> Vec<vnc_discovery::DiscoveredHost> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let disc = Discovery::new();
    let handle =
        tokio::spawn(async move { disc.scan_subnet(opts, tx, CancellationToken::new()).await });
    let mut found = Vec::new();
    while let Some(event) = rx.recv().await {
        if let DiscoveryEvent::Found(host) = event {
            found.push(host);
        }
    }
    handle.await.unwrap().unwrap();
    found
}

#[tokio::test]
async fn a_negotiating_server_is_found_with_its_capabilities() {
    // PROTOCOL_HYBRID selected, with the graphics pipeline flag set: what a
    // current Windows host answers.
    let (port, _received) = fake_server(neg_rsp(0x03, 0x0000_0002), 4).await;
    let caps = Discovery::rdp_fingerprint(loopback(port), Duration::from_millis(500))
        .await
        .expect("the probe must recognise an RDP server");

    assert!(caps.nla, "PROTOCOL_HYBRID means NLA is available");
    assert!(caps.gfx, "the DYNVC_GFX flag says EGFX is available");
    assert!(caps.extended_client_data);
    assert_eq!(
        caps.nla_required, None,
        "the sweep never claims to know whether NLA is required"
    );
    assert!(!caps.standard_only);
    assert_eq!(caps.failure_code, None);
    assert_eq!(
        caps.server_kind,
        RdpServerKind::Unknown,
        "no certificate was read from this server, so nothing is claimed"
    );
}

#[tokio::test]
async fn a_refusing_server_reports_its_failure_code() {
    let (port, _received) = fake_server(neg_failure(5), 2).await;
    let caps = Discovery::rdp_fingerprint(loopback(port), Duration::from_millis(500))
        .await
        .unwrap();
    assert_eq!(caps.failure_code, Some(5));
    assert!(!caps.tls && !caps.nla);
}

/// A server that offers no `rdpNegData` speaks only standard RDP security,
/// which this client does not support. It is listed and marked rather than
/// hidden: "there is an RDP server here that this client cannot talk to" is
/// more useful to a user than silence.
#[tokio::test]
async fn a_server_without_negotiation_is_listed_as_unsupported() {
    let (port, _received) = fake_server(no_neg_data(), 2).await;
    let caps = Discovery::rdp_fingerprint(loopback(port), Duration::from_millis(500))
        .await
        .unwrap();
    assert!(caps.standard_only);

    let found = run_scan(scan_options(port)).await;
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].server_label,
        "Remote Desktop (unsupported security)"
    );
}

/// The probe writes the nineteen byte Connection Request and nothing else.
///
/// This is the test that would catch a future refactor reaching for a
/// credential, and it is why the dependency check in
/// `crates/rdp-pdu/tests/workspace_rules.rs` exists as well: one proves the
/// bytes, the other proves the code that could produce other bytes is not
/// linked in.
#[tokio::test]
async fn the_probe_writes_exactly_one_pdu_and_no_credential() {
    // A negotiation failure, so the probe does not go on to read a
    // certificate and the recording is the whole conversation.
    let (port, received) = fake_server(neg_failure(1), 2).await;
    Discovery::rdp_fingerprint(loopback(port), Duration::from_millis(500))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let sent = received.lock().unwrap();
    assert_eq!(sent.len(), 1, "one connection, one exchange");
    assert_eq!(
        sent[0],
        vec![
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x03, 0x00, 0x00, 0x00,
        ],
        "the request is the nineteen bytes of MS-RDPBCGR 2.2.1.1 and nothing more"
    );
    // No cookie, so no username reaches the server's log or a load balancer.
    assert!(!sent[0].windows(8).any(|w| w == b"mstshash"));
}

/// A server that selected TLS gets a `ClientHello` on the *same* connection,
/// which is the certificate rung's connection rather than a second one.
#[tokio::test]
async fn the_certificate_read_shares_the_probe_connection() {
    let (port, received) = fake_server(neg_rsp(0x00, 0x0000_0001), 2).await;
    Discovery::rdp_fingerprint(loopback(port), Duration::from_millis(500))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let sent = received.lock().unwrap();
    assert_eq!(sent.len(), 1, "one connection, not two");
    let bytes = &sent[0];
    assert_eq!(&bytes[..19], &neg_req()[..], "the negotiation came first");
    assert_eq!(
        bytes[19], 22,
        "and then a TLS handshake record on the same socket"
    );
    assert_eq!(bytes[24], 0x01, "a ClientHello");
}

fn neg_req() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
        0x03, 0x00, 0x00, 0x00,
    ]
}

/// A server that says nothing, and a server that says rubbish, must both be
/// "not an RDP server" rather than a hang or a panic.
#[tokio::test]
async fn a_silent_or_hostile_server_is_not_an_rdp_server() {
    let (silent, _r1) = fake_server(Vec::new(), 2).await;
    assert!(
        Discovery::rdp_fingerprint(loopback(silent), Duration::from_millis(500))
            .await
            .is_none()
    );

    // A TPKT that claims 65535 bytes: the probe must refuse it rather than
    // read up to that length.
    let (liar, _r2) = fake_server(vec![0x03, 0x00, 0xff, 0xff, 0x0e, 0xd0], 2).await;
    assert!(
        Discovery::rdp_fingerprint(loopback(liar), Duration::from_millis(500))
            .await
            .is_none()
    );

    // An RFB banner on 3389, which is a real thing to find on a mis-configured
    // host and must not be read as a Connection Confirm.
    let (rfb, _r3) = fake_server(b"RFB 003.008\n".to_vec(), 2).await;
    assert!(
        Discovery::rdp_fingerprint(loopback(rfb), Duration::from_millis(500))
            .await
            .is_none()
    );
}

/// The truncation case, with the server dribbling one byte and then hanging
/// up. The probe must give up rather than wait for a PDU that is not coming.
#[tokio::test]
async fn a_truncated_confirm_never_hangs() {
    for cut in 1..19usize {
        let (port, _received) = fake_server(neg_rsp(0x03, 2)[..cut].to_vec(), 2).await;
        let started = std::time::Instant::now();
        let caps = Discovery::rdp_fingerprint(loopback(port), Duration::from_millis(500)).await;
        assert!(caps.is_none(), "a {cut} byte answer is not a confirm");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a {cut} byte answer must not hold the probe open"
        );
    }
}

#[tokio::test]
async fn scan_finds_a_fake_rdp_server() {
    let (port, _received) = fake_server(neg_rsp(0x03, 0x0000_0002), 4).await;
    let found = run_scan(scan_options(port)).await;

    assert_eq!(found.len(), 1, "exactly one server should be found");
    let host = &found[0];
    assert_eq!(host.port, port);
    assert_eq!(host.protocol, vnc_discovery::ProtocolKind::Rdp);
    assert_eq!(host.server_label, "Remote Desktop (TLS, NLA)");
    assert!(host.rdp.as_ref().unwrap().nla);
    assert!(
        host.rfb_version.is_none(),
        "an RDP row carries no RFB banner"
    );
    assert!(
        host.security_types.is_empty(),
        "securityTypes stays an RFB-only field"
    );
}

/// One machine running both services is two rows with two ids, which is what
/// lets a user connect to either. They are kept apart by the port, and the
/// protocol guard in `banner_conflict` is the insurance for that.
#[tokio::test]
async fn scan_finds_both_services_on_one_fake_machine() {
    let rfb = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let rfb_port = rfb.local_addr().unwrap().port();
    tokio::spawn(async move {
        for _ in 0..4 {
            if let Ok((mut sock, _)) = rfb.accept().await {
                let _ = sock.write_all(b"RFB 003.008\n").await;
                let _ = sock.flush().await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    });
    let (rdp_port, _received) = fake_server(neg_rsp(0x03, 0x0000_0002), 4).await;

    let mut opts = scan_options(rdp_port);
    opts.ports = vec![rfb_port];
    let mut found = run_scan(opts).await;
    found.sort_by_key(|h| h.port);

    assert_eq!(found.len(), 2, "two services, two rows: {found:?}");
    let ports: Vec<u16> = found.iter().map(|h| h.port).collect();
    assert!(ports.contains(&rfb_port) && ports.contains(&rdp_port));
    let protocols: Vec<_> = found.iter().map(|h| h.protocol).collect();
    assert!(protocols.contains(&vnc_discovery::ProtocolKind::Vnc));
    assert!(protocols.contains(&vnc_discovery::ProtocolKind::Rdp));
}

/// With the switch off, nothing is written to 3389 at all. The politeness
/// argument for the switch is only worth making if the switch actually stops
/// the connection.
#[tokio::test]
async fn probe_rdp_off_opens_no_connection_to_3389() {
    let (port, received) = fake_server(neg_rsp(0x03, 0x0000_0002), 4).await;
    let mut opts = scan_options(port);
    opts.probe_rdp = false;

    let found = run_scan(opts).await;
    assert!(found.is_empty());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        received.lock().unwrap().is_empty(),
        "the RDP port must not be touched when the switch is off"
    );
}

/// The politeness cap is on connections per second in total, across both
/// services, which is what makes it a cap at all. Measured rather than
/// assumed: with the rate set low, a scan that opens two connections per
/// address takes at least as long as those connections' slots.
#[tokio::test]
async fn both_services_share_one_rate_limit() {
    let (port, _received) = fake_server(neg_rsp(0x03, 2), 8).await;
    let mut opts = scan_options(port);
    // Four addresses would be better, and loopback is one address, so the two
    // probes for it are the whole sample. At 20 per second each slot is 50 ms,
    // so two slots cannot be spent in less than one gap.
    opts.max_rate_per_sec = 20;

    let started = std::time::Instant::now();
    run_scan(opts).await;
    assert!(
        started.elapsed() >= Duration::from_millis(50),
        "the RDP probe must take a rate limiter slot of its own"
    );
}
