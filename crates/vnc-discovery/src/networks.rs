//! The networks this computer can scan, for the picker beside "Scan network".
//!
//! The default scan only covers the subnets of the interfaces
//! [`crate::local_subnets`] deems safe, which leaves out every network that is
//! reachable through a VPN, a Cloudflare WARP tunnel or a route through a
//! gateway. This module lists those as well, each with a plain name, a kind,
//! the CIDR ranges it covers and how many addresses that is, so a person can
//! pick one and scan just that.
//!
//! Interfaces alone are not enough. A WARP or Tailscale interface carries a
//! single `/32` address, which says nothing about what sits behind it; the
//! ranges it reaches are the routes the client installed through it. So the
//! listing is built from two tables: the interfaces with their addresses, and
//! the IPv4 routing table. Each OS gives those up differently:
//!
//! * Linux: `ip -4 -o route show table all` (WARP puts its routes in a table
//!   of its own, which `/proc/net/route` never shows), falling back to
//!   `/proc/net/route` where `ip` is missing.
//! * macOS: `netstat -rn -f inet`.
//! * Windows: `route print -4`.
//!
//! The parsers and the listing itself are pure functions of those tables, so
//! every platform's input is unit tested on every platform. Only
//! [`list_networks`] touches the system.
//!
//! [`judge_range`] holds the limits a scan of a picked or typed range must
//! pass, and the shell applies it again before scanning, so the UI is not the
//! only thing standing between a typo and a scan of somebody's `/8`.

use crate::subnet::{Subnet, MIN_SCAN_PREFIX};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// The largest range a picked or typed scan may cover, as a prefix: `/16`,
/// 65,534 hosts. Anything shorter is refused outright, confirmed or not.
pub const LARGEST_SCAN_PREFIX: u8 = 16;

/// What kind of network a listed range is. The declaration order is the order
/// the picker shows them in, so virtual bridges come last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkKind {
    /// Wi-Fi or Ethernet: the network this computer sits on.
    Lan,
    /// OpenVPN, WireGuard, Tailscale, ZeroTier, a macOS `utun` and the like.
    Vpn,
    /// Cloudflare WARP (or Cloudflare One) tunnel.
    Warp,
    /// A private range reached through a gateway on one of the above.
    Routed,
    /// Docker, Hyper-V, VirtualBox, VMware and other virtual bridges.
    Virtual,
}

/// Whether a range may be scanned as it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RangeVerdict {
    /// `/22` or smaller and private: scan it.
    Scan,
    /// Larger than `/22` but no larger than `/16`: scan only after the person
    /// confirms the address count.
    Confirm,
    /// Larger than `/16`: refused.
    TooLarge,
    /// Not inside a private range (RFC 1918 or the RFC 6598 shared space that
    /// Tailscale and WARP use): refused.
    Public,
}

/// Judge one range against the scan limits.
pub fn judge_range(subnet: &Subnet) -> RangeVerdict {
    if !is_private(subnet) {
        RangeVerdict::Public
    } else if subnet.prefix < LARGEST_SCAN_PREFIX {
        RangeVerdict::TooLarge
    } else if subnet.prefix < MIN_SCAN_PREFIX {
        RangeVerdict::Confirm
    } else {
        RangeVerdict::Scan
    }
}

/// The strictest verdict over several ranges, with the address count summed.
pub fn judge_ranges(subnets: &[Subnet]) -> (RangeVerdict, u64) {
    let mut verdict = RangeVerdict::Scan;
    let mut addresses = 0u64;
    for s in subnets {
        addresses += s.host_count();
        verdict = match (verdict, judge_range(s)) {
            (RangeVerdict::Public, _) | (_, RangeVerdict::Public) => RangeVerdict::Public,
            (RangeVerdict::TooLarge, _) | (_, RangeVerdict::TooLarge) => RangeVerdict::TooLarge,
            (RangeVerdict::Confirm, _) | (_, RangeVerdict::Confirm) => RangeVerdict::Confirm,
            _ => RangeVerdict::Scan,
        };
    }
    // Several ranges that are each small enough can still add up to a large
    // scan; the confirmation is about the count, so it follows the count.
    if verdict == RangeVerdict::Scan
        && addresses > Subnet::new(Ipv4Addr::UNSPECIFIED, MIN_SCAN_PREFIX).host_count()
    {
        verdict = RangeVerdict::Confirm;
    }
    (verdict, addresses)
}

/// The private blocks a scan may target.
const PRIVATE_BLOCKS: [(Ipv4Addr, u8); 4] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    // RFC 6598 shared address space: Tailscale and WARP hand out addresses
    // here, and nothing public lives in it.
    (Ipv4Addr::new(100, 64, 0, 0), 10),
];

/// True when the whole of `subnet` lies inside one private block.
pub fn is_private(subnet: &Subnet) -> bool {
    PRIVATE_BLOCKS.iter().any(|&(net, prefix)| {
        subnet.prefix >= prefix && Subnet::new(net, prefix).contains(subnet.network)
    })
}

/// Parse a range typed by a person: `a.b.c.d/nn`, or a bare `a.b.c.d` for
/// that one address. Host bits are cleared, so `192.168.1.77/24` means
/// `192.168.1.0/24`.
pub fn parse_cidr(text: &str) -> Result<Subnet, String> {
    let text = text.trim();
    let (addr, prefix) = match text.split_once('/') {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (text, None),
    };
    let addr: Ipv4Addr = addr.parse().map_err(|_| {
        format!("{text:?} is not an IPv4 address or range, for example 192.168.1.0/24")
    })?;
    let prefix: u8 = match prefix {
        None => 32,
        Some(p) => match p.parse::<u8>() {
            Ok(n) if n <= 32 && !p.starts_with('+') => n,
            _ => {
                return Err(format!(
                    "{text:?} has no valid prefix after the slash (0 to 32)"
                ))
            }
        },
    };
    Ok(Subnet::new(addr, prefix))
}

/// The text form of a subnet, `a.b.c.d/nn`.
pub fn cidr(subnet: &Subnet) -> String {
    format!("{}/{}", subnet.network, subnet.prefix)
}

/// One network the picker offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanNetwork {
    /// Stable across listings while the network stays the same: the
    /// interface and the first range.
    pub id: String,
    /// What a person reads: "Ethernet (enp6s0)", "Cloudflare WARP".
    pub name: String,
    /// What kind of network this is.
    pub kind: NetworkKind,
    /// The interface it is reached through, as the OS names it.
    pub interface: String,
    /// The range as shown: one CIDR, or the enclosing `/24` with "part" when
    /// the routes cover pieces of it.
    pub range: String,
    /// The CIDRs a scan of this network covers, for `scan_network`.
    pub cidrs: Vec<String>,
    /// Host addresses the scan would probe.
    pub addresses: u64,
    /// Whether it can be scanned as is, needs a confirmation, or is too large.
    pub verdict: RangeVerdict,
}

// ------------------------------------------------------------------ tables

/// The physical medium of an interface, as far as the OS says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Medium {
    /// Wired Ethernet.
    Ethernet,
    /// Wi-Fi.
    Wireless,
    /// A tunnel the OS knows is one.
    Tunnel,
    /// Point to point (PPP, often a VPN).
    Ppp,
    /// Loopback.
    Loopback,
    /// Anything else, or unknown.
    Other,
}

/// What the listing needs to know about one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceFacts {
    /// The OS name: `enp6s0`, `en0`, `utun3`, or a GUID on Windows.
    pub name: String,
    /// A friendly name where the OS keeps one ("Wi-Fi", "Ethernet 2").
    pub label: Option<String>,
    /// The adapter description where the OS keeps one (Windows).
    pub description: Option<String>,
    /// The medium.
    pub medium: Medium,
    /// Up and running.
    pub up: bool,
    /// A Linux bridge device.
    pub bridge: bool,
    /// IPv4 addresses with their prefix lengths.
    pub ipv4: Vec<(Ipv4Addr, u8)>,
}

/// One IPv4 route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteFacts {
    /// The destination range.
    pub dest: Subnet,
    /// The interface name the route goes out of, matching
    /// [`InterfaceFacts::name`].
    pub interface: String,
    /// The next hop, `None` for an on-link route.
    pub gateway: Option<Ipv4Addr>,
}

// ---------------------------------------------------------- classification

/// The kind of an interface and the name a person sees for it.
fn describe(iface: &InterfaceFacts, has_default_route: bool) -> (NetworkKind, String) {
    let name = iface.name.as_str();
    let lname = name.to_ascii_lowercase();
    let desc = iface
        .description
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let label = iface.label.as_deref().unwrap_or("");
    let llabel = label.to_ascii_lowercase();
    let any =
        |needle: &str| lname.contains(needle) || desc.contains(needle) || llabel.contains(needle);
    // On Windows the OS name is a GUID nobody can read; the friendly name is
    // what the person knows the adapter by.
    let shown = if label.is_empty() || label == name {
        name.to_string()
    } else {
        label.to_string()
    };
    // "Wi-Fi", not "Wi-Fi (Wi-Fi)"; "OpenVPN TAP-Windows6", not "OpenVPN
    // (OpenVPN TAP-Windows6)". An OS name such as docker0 keeps the kind in
    // front, because docker0 alone means nothing to most people.
    let with = |what: &str| -> String {
        let friendly = !label.is_empty() && label != name;
        if shown.eq_ignore_ascii_case(what)
            || (friendly && llabel.contains(&what.to_ascii_lowercase()))
        {
            shown.clone()
        } else {
            format!("{what} ({shown})")
        }
    };

    if any("cloudflarewarp") || any("cloudflare warp") || any("cloudflare one") {
        return (NetworkKind::Warp, "Cloudflare WARP".to_string());
    }
    if any("tailscale") {
        return (NetworkKind::Vpn, with("Tailscale"));
    }
    if any("zerotier") || lname.starts_with("zt") {
        return (NetworkKind::Vpn, with("ZeroTier"));
    }
    if any("wireguard") || lname.starts_with("wg") {
        return (NetworkKind::Vpn, with("WireGuard"));
    }
    if any("openvpn") || any("tap-windows") || lname.starts_with("tun") || lname.starts_with("tap")
    {
        return (NetworkKind::Vpn, with("OpenVPN"));
    }

    // Virtual bridges before the generic VPN test, so a Hyper-V switch whose
    // description mentions nothing else is not taken for a tunnel.
    if lname == "docker0" || lname.starts_with("br-") || any("docker") {
        return (NetworkKind::Virtual, with("Docker"));
    }
    if any("hyper-v") || llabel.starts_with("vethernet") {
        return (NetworkKind::Virtual, with("Hyper-V"));
    }
    if any("virtualbox") || lname.starts_with("vboxnet") {
        return (NetworkKind::Virtual, with("VirtualBox"));
    }
    if any("vmware") || lname.starts_with("vmnet") {
        return (NetworkKind::Virtual, with("VMware"));
    }
    if lname.starts_with("virbr") {
        return (NetworkKind::Virtual, with("Virtual machines"));
    }
    if [
        "lxcbr", "lxdbr", "incusbr", "podman", "cni", "flannel", "cali", "kube", "veth",
    ]
    .iter()
    .any(|p| lname.starts_with(p))
    {
        return (NetworkKind::Virtual, with("Containers"));
    }
    // macOS names the bridge that Internet Sharing and its virtual machines
    // use bridge100 and up.
    if lname.starts_with("bridge") {
        return (NetworkKind::Virtual, with("Virtual bridge"));
    }

    if lname.starts_with("utun")
        || lname.starts_with("ipsec")
        || lname.starts_with("ppp")
        || matches!(iface.medium, Medium::Tunnel | Medium::Ppp)
        || any("vpn")
    {
        return (NetworkKind::Vpn, with("VPN"));
    }
    // A bridge that carries no default route is a host-only network for
    // virtual machines or containers. One that does is the LAN itself, as on
    // a server whose Ethernet was enslaved to br0 for its guests.
    if iface.bridge && !has_default_route {
        return (NetworkKind::Virtual, with("Virtual bridge"));
    }
    match iface.medium {
        Medium::Wireless => (NetworkKind::Lan, with("Wi-Fi")),
        Medium::Ethernet => (NetworkKind::Lan, with("Ethernet")),
        _ => (NetworkKind::Lan, with("Local network")),
    }
}

// ----------------------------------------------------------------- listing

/// A candidate range before grouping.
#[derive(Debug, Clone)]
struct Piece {
    subnet: Subnet,
    interface: String,
    /// Through a gateway rather than on-link.
    via_gateway: bool,
}

/// Build the picker's list from an interface table and a route table.
///
/// The rules, in order:
///
/// * Interfaces that are down, loopback, or link-local only contribute
///   nothing. A `/32` address (WARP, Tailscale) contributes no range of its
///   own; its routes do.
/// * Routes count when they are private, go out of an interface that is up,
///   and are not the default route, a multicast or loopback route, or a host
///   route to one of this computer's own addresses.
/// * A range already covered by a larger one on the same interface is
///   dropped; adjacent halves are joined, so WARP's eight split tunnel pieces
///   of one `/24` read as few ranges, and what is still in pieces inside one
///   `/24` is shown as that `/24`, "part".
/// * Ranges larger than `/16` stay on the list marked too large, because
///   seeing that a VPN routes a `/8` is useful even when it cannot be scanned
///   whole; a smaller range of it can be typed by hand.
pub fn build_networks(interfaces: &[InterfaceFacts], routes: &[RouteFacts]) -> Vec<ScanNetwork> {
    let own: Vec<Ipv4Addr> = interfaces
        .iter()
        .flat_map(|i| i.ipv4.iter().map(|(a, _)| *a))
        .collect();
    let usable = |name: &str| -> Option<&InterfaceFacts> {
        interfaces
            .iter()
            .find(|i| i.name == name && i.up && i.medium != Medium::Loopback)
    };
    let default_ifaces: Vec<&str> = routes
        .iter()
        .filter(|r| r.dest.prefix == 0)
        .map(|r| r.interface.as_str())
        .collect();

    let mut pieces: Vec<Piece> = Vec::new();
    let mut push = |p: Piece| {
        if !pieces.iter().any(|q| q.subnet == p.subnet) {
            pieces.push(p);
        }
    };

    // Connected subnets first, so a route that repeats one (Linux lists both)
    // keeps the on-link reading.
    for iface in interfaces {
        if !iface.up || iface.medium == Medium::Loopback {
            continue;
        }
        for &(addr, prefix) in &iface.ipv4 {
            if prefix >= 32 || addr.is_loopback() || addr.is_link_local() || addr.is_unspecified() {
                continue;
            }
            push(Piece {
                subnet: Subnet::new(addr, prefix),
                interface: iface.name.clone(),
                via_gateway: false,
            });
        }
    }
    for r in routes {
        let d = r.dest;
        if d.prefix == 0
            || d.network.is_loopback()
            || d.network.is_link_local()
            || d.network.is_multicast()
            || d.network.is_broadcast()
            || !is_private(&d)
            || usable(&r.interface).is_none()
        {
            continue;
        }
        if d.prefix == 32 && own.contains(&d.network) {
            continue;
        }
        // The broadcast address of a connected subnet (Windows lists it).
        if d.prefix == 32
            && interfaces.iter().any(|i| {
                i.ipv4
                    .iter()
                    .any(|&(a, p)| p < 31 && Subnet::new(a, p).broadcast() == d.network)
            })
        {
            continue;
        }
        push(Piece {
            subnet: d,
            interface: r.interface.clone(),
            via_gateway: r.gateway.is_some_and(|g| !g.is_unspecified()),
        });
    }

    // Group by interface and by whether the range is routed through a gateway,
    // which changes how it is named.
    let mut groups: BTreeMap<(String, bool), Vec<Subnet>> = BTreeMap::new();
    for p in pieces {
        groups
            .entry((p.interface, p.via_gateway))
            .or_default()
            .push(p.subnet);
    }

    let mut out: Vec<ScanNetwork> = Vec::new();
    for ((iface_name, via_gateway), subnets) in groups {
        let Some(iface) = usable(&iface_name) else {
            continue;
        };
        let (base_kind, base_name) = describe(iface, default_ifaces.contains(&iface_name.as_str()));
        let (kind, name) = if via_gateway && base_kind == NetworkKind::Lan {
            (NetworkKind::Routed, format!("Routed via {base_name}"))
        } else {
            (base_kind, base_name)
        };
        for (range, members) in shape(subnets) {
            let (verdict, addresses) = judge_ranges(&members);
            let cidrs: Vec<String> = members.iter().map(cidr).collect();
            out.push(ScanNetwork {
                id: format!("{iface_name}|{}", cidrs[0]),
                name: name.clone(),
                kind,
                interface: iface_name.clone(),
                range,
                cidrs,
                addresses,
                verdict,
            });
        }
    }
    out.sort_by(|a, b| (a.kind, &a.name, first_addr(a)).cmp(&(b.kind, &b.name, first_addr(b))));
    out
}

fn first_addr(n: &ScanNetwork) -> u32 {
    n.cidrs
        .first()
        .and_then(|c| parse_cidr(c).ok())
        .map(|s| u32::from(s.network))
        .unwrap_or(0)
}

/// Tidy one interface's ranges into what the picker shows: drop covered
/// ranges, join adjacent halves, and gather what is left in pieces inside one
/// `/24` under that `/24`. Returns the shown range text with its members.
fn shape(mut subnets: Vec<Subnet>) -> Vec<(String, Vec<Subnet>)> {
    // Drop anything inside a larger range of the same interface.
    let all = subnets.clone();
    subnets.retain(|s| {
        !all.iter()
            .any(|o| o != s && o.prefix < s.prefix && o.contains(s.network))
    });
    // Join sibling halves until nothing joins.
    loop {
        subnets.sort_by_key(|s| (u32::from(s.network), s.prefix));
        let mut joined = false;
        let mut i = 0;
        while i + 1 < subnets.len() {
            let (a, b) = (subnets[i], subnets[i + 1]);
            if a.prefix == b.prefix && a.prefix > 0 {
                let parent = Subnet::new(a.network, a.prefix - 1);
                if parent.network == a.network && parent.contains(b.network) {
                    subnets[i] = parent;
                    subnets.remove(i + 1);
                    joined = true;
                    continue;
                }
            }
            i += 1;
        }
        if !joined {
            break;
        }
    }
    // Gather the pieces smaller than a /24 under their /24.
    let mut out: Vec<(String, Vec<Subnet>)> = Vec::new();
    let mut parts: BTreeMap<u32, Vec<Subnet>> = BTreeMap::new();
    for s in subnets {
        if s.prefix > 24 {
            parts
                .entry(u32::from(Subnet::new(s.network, 24).network))
                .or_default()
                .push(s);
        } else {
            out.push((cidr(&s), vec![s]));
        }
    }
    for (base, members) in parts {
        if members.len() == 1 {
            out.push((cidr(&members[0]), members));
        } else {
            let whole = Subnet::new(Ipv4Addr::from(base), 24);
            out.push((format!("{}, part", cidr(&whole)), members));
        }
    }
    out
}

// ----------------------------------------------------------------- parsers

/// Parse `ip -4 -o route show table all` (Linux).
pub fn parse_ip_route(text: &str) -> Vec<RouteFacts> {
    const SKIP_TYPES: [&str; 9] = [
        "local",
        "broadcast",
        "unreachable",
        "blackhole",
        "prohibit",
        "throw",
        "multicast",
        "anycast",
        "nat",
    ];
    let mut out = Vec::new();
    for line in text.lines() {
        let mut words: Vec<&str> = line.split_whitespace().collect();
        if words.first() == Some(&"unicast") {
            words.remove(0);
        }
        let Some(&first) = words.first() else {
            continue;
        };
        if SKIP_TYPES.contains(&first) {
            continue;
        }
        let dest = if first == "default" {
            Subnet::new(Ipv4Addr::UNSPECIFIED, 0)
        } else {
            match parse_cidr(first) {
                Ok(s) => s,
                Err(_) => continue,
            }
        };
        let after = |key: &str| words.windows(2).find(|w| w[0] == key).map(|w| w[1]);
        let Some(dev) = after("dev") else { continue };
        let gateway = after("via").and_then(|g| g.parse().ok());
        out.push(RouteFacts {
            dest,
            interface: dev.to_string(),
            gateway,
        });
    }
    out
}

/// Parse `/proc/net/route` (Linux, main table only), the fallback when `ip`
/// is not installed.
pub fn parse_proc_net_route(text: &str) -> Vec<RouteFacts> {
    // The kernel prints each address as the hex of a u32 in host byte order.
    let hex = |s: &str| {
        u32::from_str_radix(s, 16)
            .ok()
            .map(|v| Ipv4Addr::from(v.to_ne_bytes()))
    };
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (Some(dest), Some(gw), Some(mask)) = (hex(f[1]), hex(f[2]), hex(f[7])) else {
            continue;
        };
        let prefix = u32::from(mask).count_ones() as u8;
        out.push(RouteFacts {
            dest: Subnet::new(dest, prefix),
            interface: f[0].to_string(),
            gateway: (!gw.is_unspecified()).then_some(gw),
        });
    }
    out
}

/// Parse `netstat -rn -f inet` (macOS).
///
/// Destinations come abbreviated: `default`, `10.8/16`, `192.168.1` (a /24),
/// `127` (a /8), or a full address for a host route. ARP entries and cloned
/// host routes (flags `L` or `W`) are skipped: they are neighbours, not
/// networks.
pub fn parse_netstat_routes(text: &str) -> Vec<RouteFacts> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let (dest, gateway, flags, netif) = (f[0], f[1], f[2], f[3]);
        if flags.contains('L') || flags.contains('W') {
            continue;
        }
        let dest = if dest == "default" {
            Subnet::new(Ipv4Addr::UNSPECIFIED, 0)
        } else {
            let (addr, prefix) = match dest.split_once('/') {
                Some((a, p)) => (a, p.parse::<u8>().ok()),
                None => (dest, None),
            };
            let octets: Vec<&str> = addr.split('.').collect();
            if octets.is_empty() || octets.len() > 4 {
                continue;
            }
            let mut bytes = [0u8; 4];
            let mut ok = true;
            for (i, o) in octets.iter().enumerate() {
                match o.parse::<u8>() {
                    Ok(v) => bytes[i] = v,
                    Err(_) => ok = false,
                }
            }
            if !ok {
                continue;
            }
            let prefix = prefix.unwrap_or(8 * octets.len() as u8);
            if prefix > 32 {
                continue;
            }
            Subnet::new(Ipv4Addr::from(bytes), prefix)
        };
        out.push(RouteFacts {
            dest,
            interface: netif.to_string(),
            gateway: gateway.parse().ok(),
        });
    }
    out
}

/// Parse `route print -4` (Windows).
///
/// Only the active routes are read: rows of a destination, a netmask, a
/// gateway (an address, or "On-link" in whatever language the system speaks,
/// which can be two words), the interface's own address, and a metric. The
/// persistent routes section has no interface column, so its four word rows
/// are skipped. `interface_of` maps the interface address to the interface
/// name the interface table uses.
pub fn parse_route_print(
    text: &str,
    interface_of: impl Fn(Ipv4Addr) -> Option<String>,
) -> Vec<RouteFacts> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let (Ok(dest), Ok(mask)) = (f[0].parse::<Ipv4Addr>(), f[1].parse::<Ipv4Addr>()) else {
            continue;
        };
        let n = f.len();
        if f[n - 1].parse::<u32>().is_err() {
            continue;
        }
        let Ok(iface_addr) = f[n - 2].parse::<Ipv4Addr>() else {
            continue;
        };
        let mask = u32::from(mask);
        // A netmask is a run of ones; anything else is not a row of the table.
        if mask.leading_ones() + mask.trailing_zeros() != 32 {
            continue;
        }
        let Some(interface) = interface_of(iface_addr) else {
            continue;
        };
        let gateway = if n == 5 { f[2].parse().ok() } else { None };
        out.push(RouteFacts {
            dest: Subnet::new(dest, mask.leading_ones() as u8),
            interface,
            gateway,
        });
    }
    out
}

// ------------------------------------------------------------ the system

/// List the networks this computer can scan, from its own interface and route
/// tables. Blocking: it runs the OS's route tool once.
pub fn list_networks() -> Vec<ScanNetwork> {
    let interfaces = read_interfaces();
    let routes = read_routes(&interfaces);
    build_networks(&interfaces, &routes)
}

fn read_interfaces() -> Vec<InterfaceFacts> {
    netdev::get_interfaces()
        .into_iter()
        .map(|i| {
            use netdev::interface::state::OperState;
            let medium = if i.is_loopback() {
                Medium::Loopback
            } else {
                match i.if_type {
                    netdev::interface::types::InterfaceType::Ethernet
                    | netdev::interface::types::InterfaceType::GigabitEthernet
                    | netdev::interface::types::InterfaceType::FastEthernetT
                    | netdev::interface::types::InterfaceType::FastEthernetFx => Medium::Ethernet,
                    netdev::interface::types::InterfaceType::Wireless80211 => Medium::Wireless,
                    netdev::interface::types::InterfaceType::Tunnel => Medium::Tunnel,
                    netdev::interface::types::InterfaceType::Ppp => Medium::Ppp,
                    netdev::interface::types::InterfaceType::Loopback => Medium::Loopback,
                    _ => Medium::Other,
                }
            };
            let down = matches!(
                i.oper_state,
                OperState::Down | OperState::LowerLayerDown | OperState::NotPresent
            );
            InterfaceFacts {
                bridge: is_bridge(&i.name),
                up: i.is_up() && !down,
                ipv4: i.ipv4.iter().map(|n| (n.addr(), n.prefix_len())).collect(),
                label: i.friendly_name.clone(),
                description: i.description.clone(),
                medium,
                name: i.name,
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn is_bridge(name: &str) -> bool {
    !name.contains('/')
        && std::path::Path::new("/sys/class/net")
            .join(name)
            .join("bridge")
            .exists()
}

#[cfg(not(target_os = "linux"))]
fn is_bridge(_name: &str) -> bool {
    false
}

/// Run a system tool by absolute path and return its stdout, or None.
fn run(path: &str, args: &[&str]) -> Option<String> {
    let mut cmd = std::process::Command::new(path);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: no console flashes up over the viewer.
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn read_routes(_interfaces: &[InterfaceFacts]) -> Vec<RouteFacts> {
    for ip in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if let Some(text) = run(ip, &["-4", "-o", "route", "show", "table", "all"]) {
            return parse_ip_route(&text);
        }
    }
    std::fs::read_to_string("/proc/net/route")
        .map(|t| parse_proc_net_route(&t))
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn read_routes(_interfaces: &[InterfaceFacts]) -> Vec<RouteFacts> {
    run("/usr/sbin/netstat", &["-rn", "-f", "inet"])
        .map(|t| parse_netstat_routes(&t))
        .unwrap_or_default()
}

#[cfg(windows)]
fn read_routes(interfaces: &[InterfaceFacts]) -> Vec<RouteFacts> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let route = format!(r"{root}\System32\route.exe");
    run(&route, &["print", "-4"])
        .map(|t| {
            parse_route_print(&t, |addr| {
                interfaces
                    .iter()
                    .find(|i| i.ipv4.iter().any(|(a, _)| *a == addr))
                    .map(|i| i.name.clone())
            })
        })
        .unwrap_or_default()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn read_routes(_interfaces: &[InterfaceFacts]) -> Vec<RouteFacts> {
    Vec::new()
}

#[cfg(test)]
mod tests;
