//! Public data types surfaced by discovery.

use crate::resolve::NameSource;
use crate::subnet::Subnet;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// How a host was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DiscoverySource {
    /// Found via mDNS/DNS-SD browse.
    Mdns,
    /// Found via active subnet scan.
    Scan,
    /// Entered manually by the user.
    Manual,
}

/// A VNC server found on the network.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredHost {
    /// Server address: the single best address for this machine.
    ///
    /// mDNS routinely resolves one service instance to several addresses: IPv4,
    /// global IPv6, one link-local per interface, sometimes loopback. Discovery
    /// picks the most connectable one, see
    /// [`crate::filter::rank_addresses`], so a machine occupies one row.
    pub address: IpAddr,
    /// Server port.
    pub port: u16,
    /// Other usable addresses the same machine answered on, best-first.
    ///
    /// Never contains [`DiscoveredHost::address`], and never contains a
    /// loopback/link-local/own-interface address. Kept so a future connect can
    /// fall back without a second discovery pass; the Nearby list shows only
    /// `address`.
    pub alternate_addresses: Vec<IpAddr>,
    /// Best human name we could resolve (mDNS instance, PTR, NetBIOS, or None).
    pub hostname: Option<String>,
    /// Which rung of [`crate::resolve`] produced [`DiscoveredHost::hostname`].
    ///
    /// Provenance, not decoration: three of the rungs (`netbios`, `msrpc-epm`,
    /// `rdp-cert`) are services only Windows runs, so a name that came from one
    /// of them *proves* the host is Windows where a banner substring only
    /// guesses. Always travels with `hostname`, whichever name wins a merge
    /// brings its source with it, so the two can never disagree.
    ///
    /// `None` for a name that did not come from the ladder: an mDNS instance
    /// name from the `_rfb._tcp` browse is a DNS-SD advertisement rather than a
    /// reverse-PTR answer, and calling it [`NameSource::MdnsPtr`] would claim
    /// evidence we do not have.
    pub name_source: Option<NameSource>,
    /// Raw banner, e.g. "RFB 003.008".
    pub rfb_version: Option<String>,
    /// Derived label, e.g. "macOS Screen Sharing" / "VNC server (RFB 3.8)".
    pub server_label: String,
    /// Security types the server offered (only filled by a deep probe).
    pub security_types: Vec<u8>,
    /// How this host was discovered.
    pub source: DiscoverySource,
    /// MAC address, if known (from ARP/NBT/etc.); useful for Wake-on-LAN.
    pub mac: Option<String>,
    /// Other MACs belonging to the same machine, in the order they were learned.
    ///
    /// A dual-homed host (wired *and* wireless on the same LAN) has one MAC per
    /// interface, and when the two rows it produced are collapsed into one
    /// (see [`crate::HostRegistry`]) both are kept: Wake-on-LAN has to be sent
    /// to the adapter that is actually up, and we cannot know which that is.
    /// Never contains [`DiscoveredHost::mac`], and never contains a duplicate.
    pub alternate_macs: Vec<String>,
    /// When this host was first observed.
    pub first_seen: SystemTime,
    /// When this host was most recently observed.
    pub last_seen: SystemTime,
}

impl DiscoveredHost {
    /// Construct a freshly-seen host with `first_seen == last_seen == now`.
    pub fn new(address: IpAddr, port: u16, source: DiscoverySource, server_label: String) -> Self {
        let now = SystemTime::now();
        DiscoveredHost {
            address,
            port,
            alternate_addresses: Vec::new(),
            hostname: None,
            name_source: None,
            rfb_version: None,
            server_label,
            security_types: Vec::new(),
            source,
            mac: None,
            alternate_macs: Vec::new(),
            first_seen: now,
            last_seen: now,
        }
    }

    /// Every MAC known for this machine, primary first.
    pub fn macs(&self) -> impl Iterator<Item = &str> {
        self.mac
            .iter()
            .chain(self.alternate_macs.iter())
            .map(String::as_str)
    }

    /// Every address known for this machine, primary first.
    pub fn addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        std::iter::once(self.address).chain(self.alternate_addresses.iter().copied())
    }
}

/// Streamed discovery events.
#[derive(Debug, Clone, serde::Serialize)]
pub enum DiscoveryEvent {
    /// A newly discovered host.
    Found(DiscoveredHost),
    /// An existing host whose details changed.
    Updated(DiscoveredHost),
    /// A host that is no longer present (mDNS removal / TTL expiry).
    Lost {
        /// Address of the lost host.
        address: IpAddr,
        /// Port of the lost host.
        port: u16,
    },
    /// Progress of an in-flight subnet scan.
    ScanProgress {
        /// Hosts probed so far.
        scanned: u32,
        /// Total hosts to probe.
        total: u32,
    },
    /// A subnet scan finished.
    ScanComplete {
        /// Number of VNC servers found.
        found: u32,
    },
    /// A non-fatal error worth surfacing.
    Error(String),
}

/// Options controlling a subnet scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Subnets to scan. If empty, [`crate::local_subnets`] is used.
    pub subnets: Vec<Subnet>,
    /// Ports to probe. The first port is scanned across all hosts in phase one;
    /// the rest are probed only on hosts that answered.
    pub ports: Vec<u16>,
    /// Maximum number of concurrent connection attempts.
    pub concurrency: usize,
    /// Per-connection connect timeout.
    pub connect_timeout: Duration,
    /// Maximum new connections opened per second (politeness cap).
    pub max_rate_per_sec: u32,
    /// Allow scanning subnets shorter than `/22` (dangerous; off by default).
    pub allow_large: bool,
    /// Probe this machine's own addresses (loopback and every address on a
    /// local interface) as well as everyone else's.
    ///
    /// Off by default: "Nearby" is about *other* machines, and a user's own
    /// desktop showing up in the list is pure noise. Tests that deliberately
    /// scan `127.0.0.1/32` turn it on.
    pub include_local: bool,
    /// Resolve a human name (and, via NetBIOS, a MAC) for every address that
    /// answers, see [`crate::resolve`] and PRD/04 §6.
    ///
    /// On by default: without it a Windows or Linux server found by the scan
    /// is a bare IP address forever, because only mDNS-advertising machines
    /// (in practice, Macs) ever supply a name. Resolution runs beside the scan
    /// and never delays a result: hosts are emitted as `Found` immediately and
    /// the name follows as `Updated`.
    pub resolve_names: bool,
    /// Wall-clock budget for resolving one address across the whole ladder.
    pub resolve_budget: Duration,
    /// Also read names disclosed by non-name services (MSRPC endpoint mapper
    /// on 135, RDP certificate on 3389).
    ///
    /// These are what put a name to a hardened Windows box that has NetBIOS,
    /// LLMNR and mDNS switched off, but they open connections to ports
    /// unrelated to VNC, which an IDS may read as reconnaissance. On by
    /// default because an unnamed row is close to useless to a human; the
    /// operator can turn it off.
    pub probe_other_services: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            subnets: Vec::new(),
            ports: (5900..=5906).collect(),
            concurrency: 200,
            connect_timeout: Duration::from_millis(500),
            max_rate_per_sec: 500,
            allow_large: false,
            include_local: false,
            resolve_names: true,
            resolve_budget: crate::resolve::RESOLVE_BUDGET,
            probe_other_services: true,
        }
    }
}
