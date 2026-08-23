//! Public data types surfaced by discovery.

use remote_core::ProtocolKind;

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

    /// Which protocol this row's port speaks.
    ///
    /// One row is one service, so this is not "what the machine runs", it is
    /// "what answers here". A machine running both VNC and RDP produces two
    /// rows, joined in the interface rather than in the registry.
    pub protocol: ProtocolKind,

    /// What the X.224 probe learned. Always `None` for a VNC row.
    pub rdp: Option<RdpCaps>,
}

/// What one X.224 negotiation told us about an RDP server.
///
/// Every field is what the Connection Confirm said, and nothing is inferred
/// beyond it. In particular there is no "TLS version" here and there cannot
/// be: the probe never completes a handshake, so the only honest way to learn
/// that a server tops out at TLS 1.1 is to fail a connection to it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RdpCaps {
    /// `PROTOCOL_SSL` was selected: the server speaks TLS on this port.
    pub tls: bool,
    /// `PROTOCOL_HYBRID` was selected: NLA (CredSSP) is available.
    pub nla: bool,
    /// Whether NLA is *required*, which one probe cannot answer.
    ///
    /// A server that permits both TLS and NLA selects the stronger one, so
    /// selecting HYBRID proves availability and says nothing about whether
    /// TLS alone would have been refused. Learning that needs a second probe
    /// advertising `PROTOCOL_SSL` alone, which is what the on-demand deep
    /// probe sends. `None` means "not asked", and an unprobed host must read
    /// that way rather than as an optimistic `false`.
    pub nla_required: Option<bool>,
    /// `DYNVC_GFX_PROTOCOL_SUPPORTED`: the server can do EGFX, so the H.264
    /// path is available for this host. Known before a connection is made,
    /// which is what makes it worth a chip in the interface.
    pub gfx: bool,
    /// `EXTENDED_CLIENT_DATA_SUPPORTED`.
    pub extended_client_data: bool,
    /// `RESTRICTED_ADMIN_MODE_SUPPORTED`.
    pub restricted_admin: bool,
    /// `REDIRECTED_AUTHENTICATION_MODE_SUPPORTED`.
    pub redirected_auth: bool,
    /// The server offered no `rdpNegData` at all, so it speaks only standard
    /// RDP security, which this client does not support. Such a host is
    /// listed and marked rather than hidden: "there is an RDP server here
    /// that this client cannot talk to" is more useful than silence.
    pub standard_only: bool,
    /// The `RDP_NEG_FAILURE` code, when the negotiation was refused outright.
    /// Carried as the raw value; a code we do not recognise is information,
    /// not an error.
    pub failure_code: Option<u32>,
    /// `selectedProtocol` verbatim, including bits we do not implement. A
    /// protocol bit we do not recognise means "this server offers something we
    /// do not implement", which is worth knowing and is not worth guessing at.
    pub selected_protocol: Option<u32>,
    /// Subject `CN` of the TLS certificate the server presented, read on the
    /// same connection and never trusted for anything but display (§4.7).
    pub cert_cn: Option<String>,
    /// A hint at what is listening, for an icon and a label. Never changes
    /// what we connect to, what we send, or what we trust.
    pub server_kind: RdpServerKind,
}

/// What kind of RDP server answered. A hint, never a fact.
///
/// Derived from the certificate subject only. The Connection Confirm flags
/// would be the other signal, and this crate does not use them for this:
/// current Windows sets `EXTENDED_CLIENT_DATA_SUPPORTED` and
/// `DYNVC_GFX_PROTOCOL_SUPPORTED`, xrdp's flag set differs by version, and no
/// specific xrdp release has been verified here, so a classifier written
/// against a guess would be worse than none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RdpServerKind {
    /// The certificate subject is a Windows computer name.
    Windows,
    /// Known to be xrdp. Nothing sets this yet: the packaged xrdp certificate
    /// subject (`O=xrdp, CN=www.xrdp.org` on Debian and Ubuntu) is remembered
    /// rather than observed, and the interop matrix has not confirmed it.
    /// Claiming a distribution from an unverified string is exactly the guess
    /// [`RdpServerKind::Other`] exists to avoid.
    Xrdp,
    /// An RDP server whose certificate subject is not a Windows machine name.
    Other,
    /// Nothing was learned: no certificate, or none read.
    #[default]
    Unknown,
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
            // Every existing construction site keeps its meaning without being
            // edited: a row built by the RFB probe or by mDNS is a VNC row.
            protocol: ProtocolKind::Vnc,
            rdp: None,
        }
    }

    /// Whether this row's evidence proves the host runs Windows.
    ///
    /// [`NameSource::implies_windows`] answers the question the enum alone can
    /// answer. This one answers the whole question, because the certificate
    /// rung's answer depends on the *value* it produced and not only on which
    /// rung replied: a `CN` proves Windows when it looks like a Windows
    /// computer name, and xrdp's packaged certificate does not.
    pub fn implies_windows(&self) -> bool {
        if self.name_source.is_some_and(NameSource::implies_windows) {
            return true;
        }
        let from_certificate = self.name_source == Some(NameSource::RdpCertificate);
        let cn = self
            .rdp
            .as_ref()
            .and_then(|caps| caps.cert_cn.as_deref())
            .or_else(|| {
                from_certificate
                    .then_some(self.hostname.as_deref())
                    .flatten()
            });
        cn.is_some_and(crate::resolve::looks_like_a_windows_computer_name)
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
    /// Probe for RDP servers as well as VNC ones.
    ///
    /// On by default: a scan the user explicitly consented to should find what
    /// is there, and RDP hosts are found by the subnet scan and by nothing
    /// else (there is no DNS-SD service type for RDP, and we do not invent
    /// one). An operator running this on a monitored network can turn it off.
    ///
    /// The cost, stated rather than implied: phase 1 opens one connection to
    /// 3389 per address on top of the one to 5900, and each takes the same
    /// semaphore permit and the same rate limiter slot as every RFB one, so
    /// the politeness cap stays a cap on the total rather than becoming one
    /// per service. On a /24 at the default 500 per second that is about one
    /// second of pacing instead of half a second. What it does not do is add
    /// any latency to a VNC result: both probes for an address run
    /// concurrently, a VNC row is emitted the moment its banner is read, and
    /// nothing waits on the RDP side.
    ///
    /// It also *removes* a connection per RDP host. The name resolution
    /// ladder's last rung reads the certificate on 3389, and when this probe
    /// has already read it on its own socket the rung is not dialled again.
    pub probe_rdp: bool,

    /// Ports probed for RDP. 3389 is the IANA registration
    /// (`ms-wbt-server`); the list exists for the handful of installs that
    /// move it. There is no phase 2 equivalent because there is no convention
    /// of running RDP on a range.
    pub rdp_ports: Vec<u16>,

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
            probe_rdp: true,
            rdp_ports: vec![crate::tlsname::RDP_PORT],
        }
    }
}
