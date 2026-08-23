//! LAN discovery for DeskVNCViewer.
//!
//! Combines mDNS/DNS-SD browsing with a polite active subnet scan and RFB
//! banner fingerprinting to surface every reachable VNC server, plus
//! Wake-on-LAN support. See `PRD/04-discovery.md` for the full specification.
//!
//! The bulk sweep is deliberately stealthy: it reads the 12-byte RFB banner and
//! never writes anything back. Only the on-demand [`Discovery::deep_probe`]
//! completes the version handshake to read the security-type list, and it
//! closes before authenticating.
//!
//! RDP servers are found the same way, by an X.224 negotiation on 3389 that
//! writes nineteen bytes and reads the answer (PRDRDP/08 §4). **Nothing here
//! authenticates, for either protocol.** The RDP probe never sends an MCS
//! Connect Initial, so no client name, no capability set and no credential
//! ever leaves this process, and the promise is held by the dependency graph
//! as well as by this comment: this crate depends on `rdp-pdu` for the wire
//! format and on none of the crates that know how to authenticate
//! (PRDRDP/00 R44).

#![forbid(unsafe_code)]

mod banner;
mod dnsmsg;
mod error;
pub mod filter;
mod mdns;
mod msrpc;
mod netbios;
mod probe;
mod rdpnego;
mod registry;
pub mod resolve;
mod scan;
mod subnet;
mod tlsname;
mod types;
mod wol;

pub use banner::{parse_banner, server_label, Banner};
pub use error::{Error, Result};
pub use filter::{
    address_rank, classify, is_listable, pick_best_address, rank_addresses, AddressVerdict,
    LocalNetwork,
};
pub use rdpnego::{caps_from_confirm, MAX_NEGO_READ};
pub use registry::HostRegistry;
pub use resolve::{
    looks_like_a_windows_computer_name, resolve_host, NameSource, Resolved, RESOLVE_BUDGET,
};
pub use subnet::{local_subnets, HostIter, Subnet, MIN_SCAN_PREFIX};
pub use types::{
    DiscoveredHost, DiscoveryEvent, DiscoverySource, RdpCaps, RdpServerKind, ScanOptions,
};
pub use wol::{magic_packet, parse_mac, wake_and_wait, wake_on_lan};

/// Which protocol a discovered row's port speaks, re-exported so a caller
/// naming [`DiscoveredHost::protocol`] needs no second dependency line.
pub use remote_core::ProtocolKind;

use std::net::SocketAddr;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

/// Entry point for discovery operations.
///
/// Construct with [`Discovery::new`], then drive mDNS browsing and subnet
/// scanning; both stream [`DiscoveryEvent`]s over a caller-supplied channel and
/// stop when the [`CancellationToken`] fires.
pub struct Discovery;

impl Discovery {
    /// Create a new discovery handle.
    pub fn new() -> Self {
        Discovery
    }

    /// Continuous mDNS browse. Events stream out until `cancel` is cancelled.
    pub fn browse_mdns(&self, tx: Sender<DiscoveryEvent>, cancel: CancellationToken) {
        mdns::browse_mdns(tx, cancel);
    }

    /// One-shot polite subnet scan. Returns the number of hosts found.
    pub async fn scan_subnet(
        &self,
        opts: ScanOptions,
        tx: Sender<DiscoveryEvent>,
        cancel: CancellationToken,
    ) -> Result<u32> {
        scan::scan_subnet(opts, tx, cancel).await
    }

    /// Deep probe: complete the version handshake, read the security-type list,
    /// then close **without** authenticating.
    pub async fn deep_probe(addr: SocketAddr) -> Result<Vec<u8>> {
        probe::deep_probe(addr).await
    }

    /// Deep probe an RDP host: what the sweep learned, plus whether NLA is
    /// required. Two X.224 exchanges, no credential, no MCS.
    pub async fn rdp_deep_probe(addr: SocketAddr) -> Result<RdpCaps> {
        probe::rdp_deep_probe(addr).await
    }

    /// One X.224 negotiation with `addr`, the bulk sweep's RDP probe.
    pub async fn rdp_fingerprint(
        addr: SocketAddr,
        connect_timeout: std::time::Duration,
    ) -> Option<RdpCaps> {
        probe::rdp_fingerprint(addr, connect_timeout).await
    }
}

impl Default for Discovery {
    fn default() -> Self {
        Discovery::new()
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// Spawn a fake RFB server on localhost that emits a banner then holds the
    /// connection briefly. Returns the bound port.
    async fn spawn_fake_server(banner: &'static [u8]) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Accept a few connections so both phase-1 scan and any retry work.
            for _ in 0..8 {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let _ = sock.write_all(banner).await;
                    let _ = sock.flush().await;
                    // Hold briefly so the client can read.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn scan_finds_fake_rfb_server() {
        let port = spawn_fake_server(b"RFB 003.008\n").await;

        let opts = ScanOptions {
            subnets: vec![Subnet::new(Ipv4Addr::LOCALHOST, 32)],
            ports: vec![port],
            concurrency: 16,
            connect_timeout: std::time::Duration::from_millis(500),
            max_rate_per_sec: 1000,
            allow_large: true,
            // The fake server lives on loopback, which the default scan now
            // (correctly) refuses to probe, see `scan_skips_this_machine`.
            include_local: true,
            // Loopback has no name to look up; asking would only add the
            // resolution budget to a hermetic test.
            resolve_names: false,
            resolve_budget: RESOLVE_BUDGET,
            probe_other_services: false,
            // This test is about the RFB probe. `scan_finds_a_fake_rdp_server`
            // in tests/rdp_probe.rs is the other half.
            probe_rdp: false,
            rdp_ports: Vec::new(),
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let cancel = CancellationToken::new();
        let disc = Discovery::new();

        let handle = tokio::spawn(async move { disc.scan_subnet(opts, tx, cancel).await });

        let mut found_host = None;
        while let Some(ev) = rx.recv().await {
            if let DiscoveryEvent::Found(h) = ev {
                found_host = Some(h);
            }
        }
        let count = handle.await.unwrap().unwrap();

        assert_eq!(count, 1, "exactly one server should be found");
        let h = found_host.expect("a Found event");
        assert_eq!(h.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(h.port, port);
        assert_eq!(h.rfb_version.as_deref(), Some("RFB 003.008"));
        assert_eq!(h.server_label, "VNC server (RFB 3.8)");
        assert_eq!(h.source, DiscoverySource::Scan);
    }

    /// The same fake server, with the default options: a real VNC server *is*
    /// listening, and the scan must still refuse to list it, because it is us.
    #[tokio::test]
    async fn scan_skips_this_machine() {
        let port = spawn_fake_server(b"RFB 003.008\n").await;

        let opts = ScanOptions {
            subnets: vec![Subnet::new(Ipv4Addr::LOCALHOST, 32)],
            ports: vec![port],
            concurrency: 16,
            connect_timeout: std::time::Duration::from_millis(500),
            max_rate_per_sec: 1000,
            allow_large: true,
            ..Default::default()
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let disc = Discovery::new();
        let handle =
            tokio::spawn(async move { disc.scan_subnet(opts, tx, CancellationToken::new()).await });

        let mut found = Vec::new();
        while let Some(ev) = rx.recv().await {
            if let DiscoveryEvent::Found(h) = ev {
                found.push(h);
            }
        }
        assert_eq!(handle.await.unwrap().unwrap(), 0);
        assert!(found.is_empty(), "loopback must never be listed: {found:?}");
    }

    #[tokio::test]
    async fn deep_probe_reads_security_types() {
        // Fake RFB 3.8 server: banner, then expects version reply, then sends
        // security-type list: count=2, [1, 18].
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::AsyncReadExt;
                let _ = sock.write_all(b"RFB 003.008\n").await;
                let mut reply = [0u8; 12];
                let _ = sock.read_exact(&mut reply).await;
                let _ = sock.write_all(&[2u8, 1u8, 18u8]).await;
                let _ = sock.flush().await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let types = Discovery::deep_probe(addr).await.unwrap();
        assert_eq!(types, vec![1u8, 18u8]);
    }

    #[tokio::test]
    async fn scan_refuses_large_subnet() {
        let opts = ScanOptions {
            subnets: vec![Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 16)],
            ..Default::default()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let cancel = CancellationToken::new();
        let disc = Discovery::new();
        let res = disc.scan_subnet(opts, tx, cancel).await;
        assert!(matches!(res, Err(Error::SubnetTooLarge { .. })));
    }
}
