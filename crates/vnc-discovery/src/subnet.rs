//! IPv4 subnet representation, host iteration, and local-interface enumeration.

use crate::error::{Error, Result};
use std::net::Ipv4Addr;

/// Minimum prefix length we will scan without an explicit opt-in.
///
/// `/22` is 1024 addresses (1022 usable hosts). Anything larger (a shorter
/// prefix) is refused by default, see PRD/04 §4.1.
pub const MIN_SCAN_PREFIX: u8 = 22;

/// Interface name prefixes treated as VPN/tunnel interfaces and skipped by
/// default.
const VPN_PREFIXES: &[&str] = &["utun", "tun", "tap", "wg", "tailscale", "zt"];

/// A simple IPv4 CIDR subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Subnet {
    /// Network base address (host bits cleared).
    pub network: Ipv4Addr,
    /// CIDR prefix length (0..=32).
    pub prefix: u8,
}

impl Subnet {
    /// Construct a subnet, normalising the address to the network base.
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        let mask = prefix_to_mask(prefix);
        let net = u32::from(addr) & mask;
        Subnet {
            network: Ipv4Addr::from(net),
            prefix,
        }
    }

    /// Number of addresses in the block (including network & broadcast).
    pub fn address_count(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix))
    }

    /// Number of usable host addresses (excludes network & broadcast for
    /// prefixes shorter than /31).
    pub fn host_count(&self) -> u64 {
        match self.prefix {
            31 => 2,
            32 => 1,
            _ => self.address_count().saturating_sub(2),
        }
    }

    /// True if `addr` falls inside this block.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = prefix_to_mask(self.prefix);
        (u32::from(addr) & mask) == u32::from(self.network)
    }

    /// The broadcast address of the block.
    pub fn broadcast(&self) -> Ipv4Addr {
        let mask = prefix_to_mask(self.prefix);
        Ipv4Addr::from(u32::from(self.network) | !mask)
    }

    /// Reject this subnet if its prefix is shorter than [`MIN_SCAN_PREFIX`],
    /// unless `allow_large` is set.
    pub fn guard_scannable(&self, allow_large: bool) -> Result<()> {
        if !allow_large && self.prefix < MIN_SCAN_PREFIX {
            return Err(Error::SubnetTooLarge {
                network: self.network,
                prefix: self.prefix,
                min: MIN_SCAN_PREFIX,
                hosts: self.host_count(),
            });
        }
        Ok(())
    }

    /// Iterate the usable host addresses in this block.
    ///
    /// For prefixes `/30` and shorter this excludes the network and broadcast
    /// addresses. For `/31` and `/32` all addresses are yielded.
    pub fn hosts(&self) -> HostIter {
        let count = self.address_count();
        let base = u32::from(self.network);
        let (start_off, len) = match self.prefix {
            32 => (0u64, 1u64),
            31 => (0, 2),
            _ => (1, count.saturating_sub(2)),
        };
        HostIter {
            base,
            next: start_off,
            remaining: len,
        }
    }
}

/// Iterator over the host addresses of a [`Subnet`].
pub struct HostIter {
    base: u32,
    next: u64,
    remaining: u64,
}

impl Iterator for HostIter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Ipv4Addr> {
        if self.remaining == 0 {
            return None;
        }
        // next is bounded by the block size (<= 2^32), fits after add to base.
        let addr = self.base.wrapping_add(self.next as u32);
        self.next += 1;
        self.remaining -= 1;
        Some(Ipv4Addr::from(addr))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let r = self.remaining as usize;
        (r, Some(r))
    }
}

/// Convert a prefix length into a big-endian host-order mask.
fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    }
}

/// Returns true if the interface name looks like a VPN/tunnel device.
fn is_vpn_name(name: &str) -> bool {
    let lname = name.to_ascii_lowercase();
    VPN_PREFIXES.iter().any(|p| lname.starts_with(p))
}

/// Enumerate scannable local IPv4 subnets.
///
/// Keeps interfaces that are up, non-loopback, and carry an IPv4 address with a
/// netmask giving a prefix `>= /22`. VPN/tunnel interfaces are excluded unless
/// `include_vpn` is set. Subnets shorter than `/22` are skipped with a warning
/// rather than returned.
pub fn local_subnets(include_vpn: bool) -> Vec<Subnet> {
    let mut out: Vec<Subnet> = Vec::new();
    for iface in netdev::get_interfaces() {
        if !iface.is_up() || iface.is_loopback() {
            continue;
        }
        if !include_vpn && is_vpn_name(&iface.name) {
            tracing::debug!(iface = %iface.name, "skipping VPN/tunnel interface");
            continue;
        }
        for net in &iface.ipv4 {
            let prefix = net.prefix_len();
            let addr = net.addr();
            if addr.is_loopback() || addr.is_link_local() || addr.is_unspecified() {
                continue;
            }
            let subnet = Subnet::new(net.network(), prefix);
            if prefix < MIN_SCAN_PREFIX {
                tracing::warn!(
                    iface = %iface.name,
                    subnet = %format!("{}/{}", subnet.network, prefix),
                    "skipping subnet: prefix shorter than /{MIN_SCAN_PREFIX} is too large to scan"
                );
                continue;
            }
            if !out.contains(&subnet) {
                out.push(subnet);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_24_host_iteration() {
        let s = Subnet::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let hosts: Vec<_> = s.hosts().collect();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(s.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(s.host_count(), 254);
    }

    #[test]
    fn normalises_network_base() {
        let s = Subnet::new(Ipv4Addr::new(192, 168, 1, 77), 24);
        assert_eq!(s.network, Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn slash_30_and_31_and_32() {
        let s30 = Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 30);
        assert_eq!(s30.hosts().count(), 2);
        let s31 = Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 31);
        assert_eq!(s31.hosts().count(), 2);
        let s32 = Subnet::new(Ipv4Addr::new(10, 0, 0, 5), 32);
        let hosts: Vec<_> = s32.hosts().collect();
        assert_eq!(hosts, vec![Ipv4Addr::new(10, 0, 0, 5)]);
    }

    #[test]
    fn guard_rejects_large_prefix() {
        let s16 = Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 16);
        assert!(s16.guard_scannable(false).is_err());
        // Explicit opt-in allows it.
        assert!(s16.guard_scannable(true).is_ok());
        // /22 is exactly the boundary and is allowed.
        let s22 = Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 22);
        assert!(s22.guard_scannable(false).is_ok());
        assert_eq!(s22.hosts().count(), 1022);
        // /21 is refused.
        let s21 = Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 21);
        assert!(s21.guard_scannable(false).is_err());
    }

    #[test]
    fn contains_respects_the_prefix() {
        let s = Subnet::new(Ipv4Addr::new(192, 168, 77, 0), 24);
        assert!(s.contains(Ipv4Addr::new(192, 168, 77, 1)));
        assert!(s.contains(Ipv4Addr::new(192, 168, 77, 255)));
        assert!(!s.contains(Ipv4Addr::new(192, 168, 78, 1)));
        let s32 = Subnet::new(Ipv4Addr::new(10, 1, 2, 3), 32);
        assert!(s32.contains(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!s32.contains(Ipv4Addr::new(10, 1, 2, 4)));
        let s0 = Subnet::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        assert!(s0.contains(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn vpn_name_detection() {
        assert!(is_vpn_name("utun3"));
        assert!(is_vpn_name("tailscale0"));
        assert!(is_vpn_name("wg0"));
        assert!(is_vpn_name("zt0abcdef"));
        assert!(!is_vpn_name("en0"));
        assert!(!is_vpn_name("eth0"));
    }
}
