//! Address hygiene: which addresses are worth showing a human, and which one
//! of several addresses best identifies a machine.
//!
//! "Nearby" answers one question: *which other machines can I connect to?* An
//! address that fails that question is noise, and noise is what this module
//! removes. Everything here is a pure function of an address plus a snapshot of
//! this host's own networking ([`LocalNetwork`]), no I/O, no async, so the
//! policy can be unit-tested exhaustively instead of being inferred from a live
//! network.
//!
//! # The rules
//!
//! An address is **rejected** when it is any of:
//!
//! * **unspecified**, `0.0.0.0` / `::`. A wildcard, never a destination.
//! * **loopback**, `127.0.0.0/8` / `::1`. That is *this* machine; the user
//!   does not need Nearby to find their own desktop.
//! * **multicast**, `224.0.0.0/4` / `ff00::/8`, plus the IPv4 broadcast
//!   `255.255.255.255`. Group addresses, not hosts.
//! * **link-local**, `169.254.0.0/16` (IPv4 APIPA) and `fe80::/10` (IPv6).
//!   IPv4 APIPA means "DHCP failed"; IPv6 link-local is unusable without a
//!   zone/scope id, which neither our socket layer nor the stored host profile
//!   carries. Both would produce a row that cannot be connected to.
//! * **one of this host's own interface addresses**, the same machine, wearing
//!   a different hat. Enumerated from `netdev` at snapshot time.
//!
//! # IPv6 policy
//!
//! IPv6 is **not** blanket-banned. A machine that only publishes a global
//! (`2000::/3`) or unique-local (`fc00::/7`) IPv6 address is genuinely
//! reachable, and refusing it would make that machine undiscoverable. What we
//! ban is the *unusable* forms above, link-local, loopback, multicast,
//! unspecified, which is where essentially all of the real-world IPv6 noise
//! comes from (`fe80::1`, `::1`).
//!
//! The second half of the policy is ranking, not banning: when one machine
//! advertises both IPv4 and IPv6, [`rank_addresses`] prefers IPv4 on one of our
//! own interfaces' subnets, so the machine shows up **once**, under the address
//! most likely to work, and the IPv6 forms are kept only as alternates. IPv6 is
//! therefore chosen exactly when it is the only usable thing on offer.
//!
//! IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) addresses
//! are normalised to their IPv4 form first, so they can never sneak past the
//! IPv4 rules or appear as a second row for a machine already listed by IPv4.

use crate::subnet::Subnet;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why an address was kept out of the Nearby list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressVerdict {
    /// Usable: show it.
    Listable,
    /// `0.0.0.0` / `::`.
    Unspecified,
    /// `127.0.0.0/8` / `::1`.
    Loopback,
    /// `224.0.0.0/4`, `ff00::/8`, or the IPv4 broadcast address.
    Multicast,
    /// `169.254.0.0/16` or `fe80::/10`.
    LinkLocal,
    /// An address configured on one of this machine's own interfaces.
    OwnInterface,
}

impl AddressVerdict {
    /// True only for [`AddressVerdict::Listable`].
    pub fn is_listable(self) -> bool {
        matches!(self, AddressVerdict::Listable)
    }

    /// Short reason string, for logs.
    pub fn reason(self) -> &'static str {
        match self {
            AddressVerdict::Listable => "listable",
            AddressVerdict::Unspecified => "unspecified address",
            AddressVerdict::Loopback => "loopback",
            AddressVerdict::Multicast => "multicast/broadcast",
            AddressVerdict::LinkLocal => "link-local",
            AddressVerdict::OwnInterface => "this machine's own interface",
        }
    }
}

/// A snapshot of this host's own networking: every address configured on a
/// local interface, plus the IPv4 subnets those interfaces sit on.
///
/// Taken once at the start of a browse/scan rather than per address, so a run
/// sees a consistent view and does not hammer `netdev`.
#[derive(Debug, Clone, Default)]
pub struct LocalNetwork {
    own: HashSet<IpAddr>,
    v4_subnets: Vec<Subnet>,
}

impl LocalNetwork {
    /// Enumerate this machine's interfaces via `netdev`.
    ///
    /// *Every* interface contributes to the "own address" set, loopback and
    /// VPN/tunnel devices included, because the point is to recognise
    /// ourselves under any address. Only up, non-loopback interfaces contribute
    /// to the on-link IPv4 subnet list used for ranking.
    pub fn detect() -> Self {
        let mut own: HashSet<IpAddr> = HashSet::new();
        let mut v4_subnets: Vec<Subnet> = Vec::new();

        for iface in netdev::get_interfaces() {
            let on_link = iface.is_up() && !iface.is_loopback();
            for net in &iface.ipv4 {
                let addr = net.addr();
                own.insert(IpAddr::V4(addr));
                if on_link && !addr.is_loopback() && !addr.is_link_local() && !addr.is_unspecified()
                {
                    let subnet = Subnet::new(net.network(), net.prefix_len());
                    if !v4_subnets.contains(&subnet) {
                        v4_subnets.push(subnet);
                    }
                }
            }
            for net in &iface.ipv6 {
                own.insert(IpAddr::V6(net.addr()));
            }
        }

        // Belt and braces: loopback is always us, whether or not netdev
        // reported the loopback interface.
        own.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        own.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));

        LocalNetwork { own, v4_subnets }
    }

    /// Build a snapshot from explicit parts. For tests and callers that already
    /// know the answer; never touches the system.
    pub fn from_parts(
        own: impl IntoIterator<Item = IpAddr>,
        v4_subnets: impl IntoIterator<Item = Subnet>,
    ) -> Self {
        LocalNetwork {
            own: own.into_iter().map(normalize).collect(),
            v4_subnets: v4_subnets.into_iter().collect(),
        }
    }

    /// A snapshot that claims no addresses and no subnets. Only the universal
    /// rules (loopback, link-local, multicast, unspecified) then apply.
    pub fn empty() -> Self {
        LocalNetwork::default()
    }

    /// True if `addr` is configured on one of this machine's interfaces.
    pub fn is_own(&self, addr: IpAddr) -> bool {
        self.own.contains(&normalize(addr))
    }

    /// True if `addr` sits on the same IPv4 subnet as one of our interfaces.
    pub fn is_on_link(&self, addr: IpAddr) -> bool {
        match normalize(addr) {
            IpAddr::V4(v4) => self.v4_subnets.iter().any(|s| s.contains(v4)),
            IpAddr::V6(_) => false,
        }
    }

    /// The IPv4 subnets our interfaces sit on.
    pub fn v4_subnets(&self) -> &[Subnet] {
        &self.v4_subnets
    }
}

/// Fold IPv4-mapped/compatible IPv6 addresses down to plain IPv4.
///
/// `::ffff:192.168.1.5` and `192.168.1.5` are the same host on the same wire;
/// treating them as one address is what stops a machine being listed twice.
pub fn normalize(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped().or_else(|| ipv4_compatible(v6)) {
            Some(v4) => IpAddr::V4(v4),
            None => addr,
        },
    }
}

/// The deprecated `::a.b.c.d` form (excluding `::` and `::1`).
fn ipv4_compatible(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    if s[0..6] != [0, 0, 0, 0, 0, 0] {
        return None;
    }
    let v4 = Ipv4Addr::new(
        (s[6] >> 8) as u8,
        (s[6] & 0xff) as u8,
        (s[7] >> 8) as u8,
        (s[7] & 0xff) as u8,
    );
    // `::` and `::1` are the unspecified/loopback addresses, not v4-compatible.
    if u32::from(v4) <= 1 {
        None
    } else {
        Some(v4)
    }
}

/// True if `v6` is in `fe80::/10`.
fn is_v6_link_local(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// True if `v6` is in `fc00::/7` (unique local).
fn is_v6_unique_local(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// True if `v6` is in `2000::/3` (global unicast).
fn is_v6_global_unicast(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xe000) == 0x2000
}

/// Decide whether `addr` belongs in the Nearby list, and if not, why.
///
/// Structural rules are checked before the own-interface rule so the reason
/// reported is the most specific one (`127.0.0.1` reads as `Loopback`, not
/// `OwnInterface`, even though it is both).
pub fn classify(addr: IpAddr, local: &LocalNetwork) -> AddressVerdict {
    match normalize(addr) {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return AddressVerdict::Unspecified;
            }
            if v4.is_loopback() {
                return AddressVerdict::Loopback;
            }
            if v4.is_multicast() || v4.is_broadcast() {
                return AddressVerdict::Multicast;
            }
            if v4.is_link_local() {
                return AddressVerdict::LinkLocal;
            }
            if local.is_own(IpAddr::V4(v4)) {
                return AddressVerdict::OwnInterface;
            }
            AddressVerdict::Listable
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return AddressVerdict::Unspecified;
            }
            if v6.is_loopback() {
                return AddressVerdict::Loopback;
            }
            if v6.is_multicast() {
                return AddressVerdict::Multicast;
            }
            if is_v6_link_local(v6) {
                return AddressVerdict::LinkLocal;
            }
            if local.is_own(IpAddr::V6(v6)) {
                return AddressVerdict::OwnInterface;
            }
            AddressVerdict::Listable
        }
    }
}

/// Convenience predicate over [`classify`].
pub fn is_listable(addr: IpAddr, local: &LocalNetwork) -> bool {
    classify(addr, local).is_listable()
}

/// Preference for an address as *the* address of a machine, lower is better.
///
/// 0. IPv4 on one of our own interfaces' subnets, same wire, certain to route.
/// 1. Other private IPv4 (RFC 1918 / RFC 6598), a LAN we reach via a router.
/// 2. Any other IPv4.
/// 3. Global IPv6 (`2000::/3`).
/// 4. Unique-local IPv6 (`fc00::/7`).
/// 5. Anything else that survived [`classify`].
///
/// IPv4 outranks IPv6 deliberately: it is what a VNC server on a home/office
/// LAN is actually reached on, it makes a shorter and more recognisable id, and
/// it keeps the id stable across IPv6 privacy-address rotation.
pub fn address_rank(addr: IpAddr, local: &LocalNetwork) -> u8 {
    match normalize(addr) {
        IpAddr::V4(v4) => {
            if local.is_on_link(IpAddr::V4(v4)) {
                0
            } else if is_private_v4(v4) {
                1
            } else {
                2
            }
        }
        IpAddr::V6(v6) => {
            if is_v6_global_unicast(v6) {
                3
            } else if is_v6_unique_local(v6) {
                4
            } else {
                5
            }
        }
    }
}

/// RFC 1918 private space plus RFC 6598 carrier-grade NAT (`100.64.0.0/10`),
/// which is what most VPN/mesh overlays hand out.
fn is_private_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private() || (o[0] == 100 && (64..128).contains(&o[1]))
}

/// Filter `addrs` down to the listable ones and order them best-first.
///
/// Duplicates (including the same host written as IPv4 and as an IPv4-mapped
/// IPv6) collapse to one entry. Ties break on the address itself so the result
/// is stable across runs, the id derived from it must not flap.
pub fn rank_addresses<I>(addrs: I, local: &LocalNetwork) -> Vec<IpAddr>
where
    I: IntoIterator<Item = IpAddr>,
{
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut out: Vec<IpAddr> = Vec::new();
    for addr in addrs {
        let addr = normalize(addr);
        if !is_listable(addr, local) {
            continue;
        }
        if seen.insert(addr) {
            out.push(addr);
        }
    }
    out.sort_by_key(|a| (address_rank(*a, local), *a));
    out
}

/// The single best address for a machine that advertised several, or `None`
/// when none of them are usable.
pub fn pick_best_address<I>(addrs: I, local: &LocalNetwork) -> Option<IpAddr>
where
    I: IntoIterator<Item = IpAddr>,
{
    rank_addresses(addrs, local).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address must parse")
    }

    /// A machine on 192.168.77.135/24 with a global IPv6 and a link-local one.
    fn this_mac() -> LocalNetwork {
        LocalNetwork::from_parts(
            [
                ip("127.0.0.1"),
                ip("::1"),
                ip("192.168.77.135"),
                ip("fe80::14e0:7472:a527:8ab"),
                ip("2001:db8:77::135"),
            ],
            [Subnet::new(Ipv4Addr::new(192, 168, 77, 0), 24)],
        )
    }

    #[test]
    fn loopback_is_rejected() {
        let local = this_mac();
        assert_eq!(classify(ip("127.0.0.1"), &local), AddressVerdict::Loopback);
        assert_eq!(classify(ip("127.1.2.3"), &local), AddressVerdict::Loopback);
        assert_eq!(classify(ip("::1"), &local), AddressVerdict::Loopback);
        // …and even with no idea what our own addresses are.
        let blind = LocalNetwork::empty();
        assert!(!is_listable(ip("127.0.0.1"), &blind));
        assert!(!is_listable(ip("::1"), &blind));
    }

    #[test]
    fn own_interface_addresses_are_rejected() {
        let local = this_mac();
        assert_eq!(
            classify(ip("192.168.77.135"), &local),
            AddressVerdict::OwnInterface
        );
        assert_eq!(
            classify(ip("2001:db8:77::135"), &local),
            AddressVerdict::OwnInterface
        );
        // The neighbours on the same wire are fine.
        assert!(is_listable(ip("192.168.77.126"), &local));
        assert!(is_listable(ip("192.168.77.133"), &local));
        assert!(is_listable(ip("192.168.77.150"), &local));
    }

    #[test]
    fn own_address_written_as_ipv4_mapped_is_still_us() {
        let local = this_mac();
        assert_eq!(
            classify(ip("::ffff:192.168.77.135"), &local),
            AddressVerdict::OwnInterface
        );
    }

    #[test]
    fn link_local_v4_and_v6_are_rejected() {
        let local = this_mac();
        assert_eq!(
            classify(ip("169.254.13.7"), &local),
            AddressVerdict::LinkLocal
        );
        assert_eq!(classify(ip("fe80::1"), &local), AddressVerdict::LinkLocal);
        // Someone else's link-local is just as unusable as our own.
        assert_eq!(
            classify(ip("fe80::dead:beef"), &local),
            AddressVerdict::LinkLocal
        );
        // febf:: is the last address in fe80::/10.
        assert_eq!(classify(ip("febf::1"), &local), AddressVerdict::LinkLocal);
        // fec0:: is outside fe80::/10 (site-local, deprecated but not banned).
        assert!(is_listable(ip("fec0::1"), &local));
    }

    #[test]
    fn multicast_and_unspecified_are_rejected() {
        let local = this_mac();
        assert_eq!(classify(ip("0.0.0.0"), &local), AddressVerdict::Unspecified);
        assert_eq!(classify(ip("::"), &local), AddressVerdict::Unspecified);
        assert_eq!(
            classify(ip("224.0.0.251"), &local),
            AddressVerdict::Multicast
        );
        assert_eq!(
            classify(ip("239.255.255.250"), &local),
            AddressVerdict::Multicast
        );
        assert_eq!(
            classify(ip("255.255.255.255"), &local),
            AddressVerdict::Multicast
        );
        assert_eq!(classify(ip("ff02::fb"), &local), AddressVerdict::Multicast);
    }

    #[test]
    fn global_ipv6_is_accepted() {
        let local = this_mac();
        // A neighbour's global IPv6 is a real, connectable address.
        assert_eq!(
            classify(ip("2001:db8:77::126"), &local),
            AddressVerdict::Listable
        );
        assert_eq!(classify(ip("2600::abcd"), &local), AddressVerdict::Listable);
        // Unique-local too, that is a normal LAN prefix.
        assert_eq!(
            classify(ip("fd00:1234::5"), &local),
            AddressVerdict::Listable
        );
    }

    #[test]
    fn ranking_prefers_on_link_ipv4_then_private_then_ipv6() {
        let local = this_mac();
        assert_eq!(address_rank(ip("192.168.77.126"), &local), 0);
        assert_eq!(address_rank(ip("10.0.0.9"), &local), 1);
        assert_eq!(address_rank(ip("100.100.0.9"), &local), 1);
        assert_eq!(address_rank(ip("93.184.216.34"), &local), 2);
        assert_eq!(address_rank(ip("2001:db8::9"), &local), 3);
        assert_eq!(address_rank(ip("fd00::9"), &local), 4);
    }

    #[test]
    fn multi_address_instance_collapses_to_one_on_link_ipv4() {
        let local = this_mac();
        // What a real mDNS resolution of one neighbouring Mac looks like.
        let advertised = [
            ip("fe80::1"),
            ip("::1"),
            ip("127.0.0.1"),
            ip("2001:db8:77::126"),
            ip("192.168.77.126"),
            ip("fe80::14e0:7472:a527:8ab"),
        ];
        let ranked = rank_addresses(advertised, &local);
        assert_eq!(
            ranked,
            vec![ip("192.168.77.126"), ip("2001:db8:77::126")],
            "only the two usable addresses survive, IPv4 first"
        );
        assert_eq!(
            pick_best_address(advertised, &local),
            Some(ip("192.168.77.126"))
        );
    }

    #[test]
    fn ipv6_only_machine_still_gets_listed() {
        let local = this_mac();
        let advertised = [ip("fe80::1"), ip("2001:db8:99::7")];
        assert_eq!(
            pick_best_address(advertised, &local),
            Some(ip("2001:db8:99::7")),
            "IPv6 is banned only in its unusable forms, never wholesale"
        );
    }

    #[test]
    fn instance_with_nothing_usable_yields_nothing() {
        let local = this_mac();
        let advertised = [ip("127.0.0.1"), ip("::1"), ip("fe80::1"), ip("0.0.0.0")];
        assert_eq!(pick_best_address(advertised, &local), None);
        assert!(rank_addresses(advertised, &local).is_empty());
    }

    #[test]
    fn ipv4_and_its_mapped_form_are_one_address() {
        let local = this_mac();
        let ranked = rank_addresses([ip("192.168.77.126"), ip("::ffff:192.168.77.126")], &local);
        assert_eq!(ranked, vec![ip("192.168.77.126")]);
    }

    #[test]
    fn ranking_is_stable_for_equal_ranks() {
        let local = this_mac();
        let a = rank_addresses([ip("192.168.77.150"), ip("192.168.77.126")], &local);
        let b = rank_addresses([ip("192.168.77.126"), ip("192.168.77.150")], &local);
        assert_eq!(a, b);
        assert_eq!(a, vec![ip("192.168.77.126"), ip("192.168.77.150")]);
    }

    #[test]
    fn detect_snapshot_recognises_this_machine() {
        // Whatever this machine's addresses are, loopback must be ours and the
        // enumeration must not panic.
        let local = LocalNetwork::detect();
        assert!(local.is_own(ip("127.0.0.1")));
        assert!(local.is_own(ip("::1")));
        for subnet in local.v4_subnets() {
            assert!(subnet.prefix <= 32);
        }
    }
}
