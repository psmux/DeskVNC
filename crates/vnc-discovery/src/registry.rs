//! One row per machine: cross-source de-duplication of discovered hosts.
//!
//! mDNS and the subnet scan are independent streams that routinely see the same
//! server. mDNS knows the friendly name (`"Studio iMac"`); the scan knows the
//! real banner (`"macOS Screen Sharing"`, `RFB 003.889`). Left alone they
//! produce two rows that say different things about one machine.
//!
//! [`HostRegistry`] is the join point. Every [`DiscoveryEvent`] from every
//! source goes through [`HostRegistry::observe_event`], which
//!
//! * drops anything whose address fails [`crate::filter`] (loopback, this
//!   machine, link-local, multicast, unspecified),
//! * emits `Found` the first time a machine is seen,
//! * merges later sightings into the existing row and emits `Updated` **only**
//!   when something a human would notice actually changed,
//! * collapses two rows that turn out to be one machine, emitting `Lost` for
//!   the row that is absorbed, and
//! * emits nothing at all for a pure re-sighting.
//!
//! It is a plain synchronous state machine, no I/O, no async, no clock beyond
//! the timestamps already on the events, so the whole de-duplication policy is
//! unit-testable.
//!
//! # What counts as "the same machine"
//!
//! Rows are joined on evidence, strongest first. Only the first two rungs are
//! proof; the third is a well-founded guess, and it is guarded.
//!
//! 1. **Same address and port.** Identity, by definition.
//! 2. **A shared MAC on the same port.** Hardware identity: one adapter is one
//!    machine. This holds even when the two rows disagree about the name, and
//!    it is the rung that survives a DHCP lease moving a host to a new address
//!    before its old row has expired.
//! 3. **The same non-empty name on the same port**, with no contradicting
//!    banner. This is the rung that fixes the dual-homed machine, one box
//!    cabled *and* on Wi-Fi answers on two addresses with two MACs, so rung 2
//!    cannot see it, and only the name it reports on both says they are one.
//!
//! Two things this deliberately does **not** do:
//!
//! * **Different MACs are not counter-evidence.** They are the *expected*
//!   result for a dual-homed host (this LAN: `192.168.77.92` is
//!   `a0:d3:c1:0f:81:e4`, `192.168.77.129` is `d0:37:45:af:7a:61`, one
//!   machine). So a shared MAC merges, and disjoint MACs simply say nothing.
//! * **A missing name is never a join.** Two rows that are both unnamed are
//!   two rows; `None == None` is not evidence of anything.
//!
//! Rung 3 has a real failure mode: Windows derives `DESKTOP-XXXXXXX` from the
//! install, and two machines imaged from the same source can genuinely share a
//! name. Nothing on the wire distinguishes that from one dual-homed host, //! same name, different MACs, same subnet, so this is a judgement call, made
//! as follows.
//!
//! * We merge, because the dual-homed case is overwhelmingly the common one
//!   (one machine with two NICs is ordinary; a duplicate `ComputerName` on one
//!   LAN breaks Windows' own name resolution and gets noticed and fixed).
//! * We refuse the merge when the two rows carry **contradicting banners**, a
//!   different `RFB` version or a different non-placeholder server label on the
//!   same port. One machine's server cannot answer two different banners on
//!   one port, so that is proof of two machines and it overrides the name.
//! * The merge is **lossless**: the survivor keeps every address and every MAC
//!   both rows knew, so a wrong merge still leaves a connectable row and a
//!   Wake-on-LAN target, and the user never silently loses the ability to reach
//!   a machine.

use crate::filter::{self, LocalNetwork};
use crate::types::{DiscoveredHost, DiscoveryEvent, DiscoverySource};
use std::collections::HashMap;
use std::net::IpAddr;

/// Identity of a row in the Nearby list: the address we settled on, plus port.
/// Matches the `"<address>:<port>"` id the shell derives, so `Lost` can be
/// resolved back to the same row.
type Key = (IpAddr, u16);

/// De-duplicating view over everything discovery finds.
#[derive(Debug)]
pub struct HostRegistry {
    local: LocalNetwork,
    by_key: HashMap<Key, DiscoveredHost>,
    /// A machine's name is a second, address-independent identity for it. Maps
    /// `(lowercased name, port)` onto the row that owns it.
    by_name: HashMap<(String, u16), Key>,
    /// …and its MAC is a third, stronger one. Maps `(canonical MAC, port)` onto
    /// the row that owns it; a row with several MACs appears once per MAC.
    by_mac: HashMap<(String, u16), Key>,
}

impl HostRegistry {
    /// Build a registry against a snapshot of this machine's networking.
    pub fn new(local: LocalNetwork) -> Self {
        HostRegistry {
            local,
            by_key: HashMap::new(),
            by_name: HashMap::new(),
            by_mac: HashMap::new(),
        }
    }

    /// Refresh the local-networking snapshot (after a link change, or at the
    /// start of a browse/scan) without discarding what has been found.
    pub fn set_local(&mut self, local: LocalNetwork) {
        self.local = local;
    }

    /// Forget every host seen so far.
    pub fn clear(&mut self) {
        self.by_key.clear();
        self.by_name.clear();
        self.by_mac.clear();
    }

    /// Hosts currently listed, in no particular order.
    pub fn hosts(&self) -> impl Iterator<Item = &DiscoveredHost> {
        self.by_key.values()
    }

    /// Number of rows the Nearby list would show.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// True when nothing has been discovered.
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Feed one event through de-duplication.
    ///
    /// Returns the events that should actually reach the UI, usually one, and
    /// **empty** when the event was noise (unusable address, this machine, or a
    /// re-sighting that told us nothing new). Non-host events (progress,
    /// completion, errors) pass through untouched.
    ///
    /// One sighting can produce more than one event: a name arriving late can
    /// reveal that two rows are one machine, which is a `Lost` for the row
    /// being absorbed *and* an `Updated` for the survivor. Callers must forward
    /// them in order.
    pub fn observe_event(&mut self, event: DiscoveryEvent) -> Vec<DiscoveryEvent> {
        match event {
            DiscoveryEvent::Found(host) | DiscoveryEvent::Updated(host) => self.observe(host),
            DiscoveryEvent::Lost { address, port } => self.forget(address, port),
            other => vec![other],
        }
    }

    /// Record a sighting. See [`HostRegistry::observe_event`] for the contract.
    ///
    /// The emitted order is every `Lost` first, then the survivor's `Updated`,
    /// so the absorbed row leaves the list before the row that inherited its
    /// addresses is redrawn, the user never sees one machine twice, even for
    /// a frame.
    pub fn observe(&mut self, mut host: DiscoveredHost) -> Vec<DiscoveryEvent> {
        // Collapse the advertised addresses to the one we will show, dropping
        // everything unusable. This also re-checks a scan-sourced host, so no
        // source can bypass the filter.
        let ranked = filter::rank_addresses(host.addresses(), &self.local);
        let Some((&best, alternates)) = ranked.split_first() else {
            tracing::debug!(
                address = %host.address,
                reason = filter::classify(host.address, &self.local).reason(),
                "discovery: hiding host with no usable address"
            );
            return Vec::new();
        };
        host.address = best;
        host.alternate_addresses = alternates.to_vec();

        let key = (host.address, host.port);

        // Which row is this a sighting of? Address+port is identity; failing
        // that, hardware; failing that, the name.
        let owner = if self.by_key.contains_key(&key) {
            Some(key)
        } else {
            self.owner_by_mac(&host)
                .or_else(|| self.owner_by_name(&host))
        };

        let Some(owner) = owner else {
            self.index(key, &host);
            self.by_key.insert(key, host.clone());
            return vec![DiscoveryEvent::Found(host)];
        };

        // A known machine, possibly under a new address: fold the sighting in
        // and keep the row (and therefore its id) exactly where it was.
        let local = &self.local;
        let row = self.by_key.get_mut(&owner).expect("owner is a live row");
        let mut changed = merge_into(row, &host);
        tidy_alternates(row, local);
        let row = row.clone();
        self.index(owner, &row);

        // The merge may have taught this row a name or a MAC that another row
        // already answers to, a name resolved after both rows were emitted is
        // exactly how a dual-homed machine shows up twice. Collapse them.
        let mut events = Vec::new();
        let mut survivor = owner;
        while let Some(twin) = self.twin_of(survivor) {
            let (keep, absorbed) = self.pick_survivor(survivor, twin);
            events.push(self.absorb(keep, absorbed));
            survivor = keep;
            changed = true;
        }

        if changed {
            events.push(DiscoveryEvent::Updated(self.by_key[&survivor].clone()));
        }
        events
    }

    /// Drop a row. Returns the `Lost` event to forward, or nothing if we were
    /// never showing that host.
    pub fn forget(&mut self, address: IpAddr, port: u16) -> Vec<DiscoveryEvent> {
        let key = (filter::normalize(address), port);
        if self.by_key.remove(&key).is_none() {
            return Vec::new();
        }
        // Release every identity the row was holding, so the machine can come
        // back cleanly on its next sighting.
        self.by_name.retain(|_, owner| *owner != key);
        self.by_mac.retain(|_, owner| *owner != key);
        vec![DiscoveryEvent::Lost {
            address: key.0,
            port,
        }]
    }

    /// Rung 2: the live row that already answers to one of `host`'s MACs.
    ///
    /// A shared MAC on one port is a dual-homed machine and the two rows are
    /// one machine, with one exception: a row for another protocol is another
    /// service, never the same one. Today the port keeps those apart on its
    /// own, so this can only fire if the keying ever changes, which is exactly
    /// when it needs to.
    fn owner_by_mac(&self, host: &DiscoveredHost) -> Option<Key> {
        host.macs()
            .filter_map(canonical_mac)
            .find_map(|mac| self.by_mac.get(&(mac, host.port)).copied())
            .filter(|key| {
                self.by_key
                    .get(key)
                    .is_some_and(|row| row.protocol == host.protocol)
            })
    }

    /// Rung 3: the live row that already answers to `host`'s name, unless its
    /// banner says the two cannot be the same server.
    fn owner_by_name(&self, host: &DiscoveredHost) -> Option<Key> {
        let owner = *self.by_name.get(&name_key(host)?)?;
        let row = self.by_key.get(&owner)?;
        (!banner_conflict(row, host)).then_some(owner)
    }

    /// Another live row that is the same machine as `key`, if there is one.
    fn twin_of(&self, key: Key) -> Option<Key> {
        let row = self.by_key.get(&key)?;
        // Same rule as `owner_by_mac`: one MAC on one port is one machine,
        // and two protocols are still two services.
        let by_mac = row
            .macs()
            .filter_map(canonical_mac)
            .filter_map(|mac| self.by_mac.get(&(mac, row.port)).copied())
            .find(|other| {
                *other != key
                    && self
                        .by_key
                        .get(other)
                        .is_some_and(|twin| twin.protocol == row.protocol)
            });
        if by_mac.is_some() {
            return by_mac;
        }
        let other = *self.by_name.get(&name_key(row)?)?;
        if other == key {
            return None;
        }
        let twin = self.by_key.get(&other)?;
        (!banner_conflict(row, twin)).then_some(other)
    }

    /// Of two rows for one machine, which address stays on the list.
    ///
    /// The best-ranked address wins ([`filter::address_rank`], an on-link IPv4
    /// beats a routed one beats IPv6), and ties break on the address itself so
    /// the outcome does not depend on which sighting happened to arrive first.
    fn pick_survivor(&self, a: Key, b: Key) -> (Key, Key) {
        let rank = |key: Key| (filter::address_rank(key.0, &self.local), key.0);
        if rank(a) <= rank(b) {
            (a, b)
        } else {
            (b, a)
        }
    }

    /// Fold the row at `absorbed` into the row at `keep` and delete it,
    /// returning the `Lost` that removes it from the UI.
    ///
    /// Everything the absorbed row knew survives: its address becomes an
    /// alternate, its MAC joins the survivor's, and any name/banner/security
    /// detail the survivor lacked is taken over.
    fn absorb(&mut self, keep: Key, absorbed: Key) -> DiscoveryEvent {
        let gone = self.by_key.remove(&absorbed).expect("twin is a live row");
        let local = &self.local;
        if let Some(row) = self.by_key.get_mut(&keep) {
            merge_into(row, &gone);
            tidy_alternates(row, local);
        }
        // Every index entry that pointed at the row just deleted now points at
        // the survivor, which owns everything that row knew.
        for owner in self.by_name.values_mut().chain(self.by_mac.values_mut()) {
            if *owner == absorbed {
                *owner = keep;
            }
        }
        let row = self.by_key[&keep].clone();
        self.index(keep, &row);
        tracing::debug!(
            keep = %keep.0,
            absorbed = %absorbed.0,
            port = keep.1,
            name = row.hostname.as_deref().unwrap_or("?"),
            macs = row.macs().collect::<Vec<_>>().join(","),
            "discovery: one machine on two addresses, collapsing to one row"
        );
        DiscoveryEvent::Lost {
            address: absorbed.0,
            port: absorbed.1,
        }
    }

    /// Point every identity this row publishes at `key`, without stealing one
    /// another row already owns, a claim is resolved by [`Self::twin_of`],
    /// not by overwriting the index.
    fn index(&mut self, key: Key, host: &DiscoveredHost) {
        if let Some(nk) = name_key(host) {
            self.by_name.entry(nk).or_insert(key);
        }
        for mac in host.macs().filter_map(canonical_mac) {
            self.by_mac.entry((mac, host.port)).or_insert(key);
        }
    }
}

/// Address-independent identity for a machine, when it published a name.
///
/// The port is part of the key on purpose: `:5900` and `:5901` on one box are
/// two screens and therefore two rows, so the same name on a different port
/// must never join them.
fn name_key(host: &DiscoveredHost) -> Option<(String, u16)> {
    let name = host.hostname.as_ref()?.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_lowercase(), host.port))
}

/// Canonical form of a MAC for comparison: its twelve hex digits, lowercased.
///
/// `None` for anything that is not six octets, and for the all-zero address, /// an all-zero unit id means "no MAC", and joining two rows on it would be a
/// spectacular false positive.
fn canonical_mac(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 12 || hex.bytes().all(|b| b == b'0') {
        return None;
    }
    Some(hex)
}

/// Record a MAC the row did not already have. Returns true if it was new.
///
/// Both MACs of a dual-homed machine are kept: Wake-on-LAN has to reach the
/// adapter that is actually powered, and discovery cannot know which that is.
fn add_mac(host: &mut DiscoveredHost, mac: &str) -> bool {
    let Some(canon) = canonical_mac(mac) else {
        return false;
    };
    if host.macs().filter_map(canonical_mac).any(|m| m == canon) {
        return false;
    }
    if host.mac.is_none() {
        host.mac = Some(mac.to_string());
    } else {
        host.alternate_macs.push(mac.to_string());
    }
    true
}

/// True when two rows advertise fingerprints one server cannot both have.
///
/// The guard on name-based merging: two machines imaged from the same Windows
/// install genuinely share a `DESKTOP-XXXXXXX` name, but they cannot also
/// answer one port with two different banners. A placeholder label is not a
/// fingerprint (mDNS never sees the banner), so it never conflicts.
fn banner_conflict(a: &DiscoveredHost, b: &DiscoveredHost) -> bool {
    // Two different protocols are two different services, whatever else
    // matches. Today the port already keeps them apart, because `Key` and
    // `name_key` both carry it, so this can only fire if the keying ever
    // changes. That is exactly when it needs to fire.
    if a.protocol != b.protocol {
        return true;
    }
    if let (Some(x), Some(y)) = (&a.rfb_version, &b.rfb_version) {
        if x != y {
            return true;
        }
    }
    !is_placeholder_label(&a.server_label)
        && !is_placeholder_label(&b.server_label)
        && a.server_label != b.server_label
}

/// Re-order a row's alternates best-first, which a merge can disturb.
fn tidy_alternates(host: &mut DiscoveredHost, local: &LocalNetwork) {
    host.alternate_addresses
        .sort_by_key(|a| (filter::address_rank(*a, local), *a));
}

/// True if `label` is a placeholder rather than a real fingerprint. mDNS cannot
/// see the banner, so it can only ever say "there is a VNC server here".
fn is_placeholder_label(label: &str) -> bool {
    label.is_empty() || label == "VNC server (mDNS)"
}

/// Fold a new sighting into an existing row. Returns true if anything a human
/// would notice changed (`last_seen` alone does not count, otherwise a steady
/// mDNS re-announce would flood the UI with `Updated`).
///
/// Field-by-field the better value wins:
/// * **hostname**, an mDNS instance name beats nothing; we never replace a
///   name we already have with `None`, which is what makes the mDNS name
///   survive a later scan hit on the same address. `name_source` always travels
///   with the name it describes.
/// * **source**, `Mdns` is sticky for the same reason: it is the source that
///   carries the friendly name.
/// * **server_label / rfb_version**, the scan's banner fingerprint
///   ("macOS Screen Sharing") beats mDNS's placeholder.
/// * **security_types**, filled in once known, never cleared.
/// * **mac / alternate_addresses**, union. Nothing that could be a route to
///   the machine, or a way to wake it, is ever dropped.
fn merge_into(existing: &mut DiscoveredHost, incoming: &DiscoveredHost) -> bool {
    let mut changed = false;

    if existing.hostname.is_none() {
        if let Some(name) = &incoming.hostname {
            existing.hostname = Some(name.clone());
            existing.name_source = incoming.name_source;
            changed = true;
        }
    } else if existing.name_source.is_none()
        && incoming.name_source.is_some()
        && existing.hostname == incoming.hostname
    {
        // Same name, now with provenance. Worth taking: the rung that answered
        // is what proves the OS, so the row's icon changes.
        existing.name_source = incoming.name_source;
        changed = true;
    }

    if incoming.source == DiscoverySource::Mdns && existing.source != DiscoverySource::Mdns {
        existing.source = DiscoverySource::Mdns;
        changed = true;
    }

    if let Some(version) = &incoming.rfb_version {
        if existing.rfb_version.as_ref() != Some(version) {
            existing.rfb_version = Some(version.clone());
            changed = true;
        }
    }

    if !is_placeholder_label(&incoming.server_label)
        && (is_placeholder_label(&existing.server_label)
            || existing.server_label != incoming.server_label)
    {
        existing.server_label = incoming.server_label.clone();
        changed = true;
    }

    if !incoming.security_types.is_empty() && existing.security_types != incoming.security_types {
        existing.security_types = incoming.security_types.clone();
        changed = true;
    }

    for mac in incoming.macs() {
        changed |= add_mac(existing, mac);
    }

    for addr in incoming.addresses() {
        if addr != existing.address && !existing.alternate_addresses.contains(&addr) {
            existing.alternate_addresses.push(addr);
            changed = true;
        }
    }

    existing.first_seen = existing.first_seen.min(incoming.first_seen);
    existing.last_seen = existing.last_seen.max(incoming.last_seen);

    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::NameSource;
    use crate::subnet::Subnet;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address must parse")
    }

    /// This machine: 192.168.77.135 on 192.168.77.0/24.
    fn local() -> LocalNetwork {
        LocalNetwork::from_parts(
            [
                ip("127.0.0.1"),
                ip("::1"),
                ip("192.168.77.135"),
                ip("fe80::14e0:7472:a527:8ab"),
            ],
            [Subnet::new(Ipv4Addr::new(192, 168, 77, 0), 24)],
        )
    }

    fn registry() -> HostRegistry {
        HostRegistry::new(local())
    }

    fn mdns(addr: &str, name: &str) -> DiscoveredHost {
        let mut h = DiscoveredHost::new(
            ip(addr),
            5900,
            DiscoverySource::Mdns,
            "VNC server (mDNS)".to_string(),
        );
        h.hostname = Some(name.to_string());
        h
    }

    fn scanned(addr: &str) -> DiscoveredHost {
        let mut h = DiscoveredHost::new(
            ip(addr),
            5900,
            DiscoverySource::Scan,
            "macOS Screen Sharing".to_string(),
        );
        h.rfb_version = Some("RFB 003.889".to_string());
        h
    }

    /// What the scan emits for one of this LAN's Windows boxes: a banner and
    /// nothing else, because the name has not been resolved yet.
    fn windows_scan(addr: &str) -> DiscoveredHost {
        let mut h = DiscoveredHost::new(
            ip(addr),
            5900,
            DiscoverySource::Scan,
            "VNC server (RFB 3.8)".to_string(),
        );
        h.rfb_version = Some("RFB 003.008".to_string());
        h
    }

    /// The same host once the NetBIOS rung has answered for that adapter.
    fn named_by_netbios(addr: &str, name: &str, mac: &str) -> DiscoveredHost {
        let mut h = windows_scan(addr);
        h.hostname = Some(name.to_string());
        h.name_source = Some(NameSource::NetBios);
        h.mac = Some(mac.to_string());
        h
    }

    /// What the 3389 probe emits for the same machine.
    fn rdp_scan(addr: &str) -> DiscoveredHost {
        let mut h = DiscoveredHost::new(
            ip(addr),
            3389,
            DiscoverySource::Scan,
            "Remote Desktop (TLS, NLA)".to_string(),
        );
        h.protocol = remote_core::ProtocolKind::Rdp;
        h.rdp = Some(crate::types::RdpCaps {
            tls: true,
            nla: true,
            ..Default::default()
        });
        h
    }

    fn found(evs: Vec<DiscoveryEvent>) -> DiscoveredHost {
        match evs.as_slice() {
            [DiscoveryEvent::Found(h)] => h.clone(),
            other => panic!("expected one Found, got {other:?}"),
        }
    }

    fn updated(evs: Vec<DiscoveryEvent>) -> DiscoveredHost {
        match evs.as_slice() {
            [DiscoveryEvent::Updated(h)] => h.clone(),
            other => panic!("expected one Updated, got {other:?}"),
        }
    }

    /// A collapse: the absorbed row's `Lost`, then the survivor's `Updated`.
    fn collapsed(evs: Vec<DiscoveryEvent>) -> (Key, DiscoveredHost) {
        match evs.as_slice() {
            [DiscoveryEvent::Lost { address, port }, DiscoveryEvent::Updated(h)] => {
                ((*address, *port), h.clone())
            }
            other => panic!("expected Lost then Updated, got {other:?}"),
        }
    }

    #[test]
    fn this_machine_never_reaches_the_list() {
        let mut reg = registry();
        assert!(reg.observe(mdns("127.0.0.1", "My MacBook")).is_empty());
        assert!(reg.observe(mdns("::1", "My MacBook")).is_empty());
        assert!(reg.observe(mdns("fe80::1", "My MacBook")).is_empty());
        assert!(reg
            .observe(mdns("fe80::14e0:7472:a527:8ab", "My MacBook"))
            .is_empty());
        assert!(reg.observe(mdns("192.168.77.135", "My MacBook")).is_empty());
        assert!(reg.observe(scanned("127.0.0.1")).is_empty());
        assert!(reg.is_empty(), "the Nearby list must be empty");
    }

    #[test]
    fn a_multi_address_mdns_instance_becomes_one_row() {
        let mut reg = registry();
        // One neighbour, exactly as mDNS resolves it in the wild.
        let mut host = mdns("fe80::abc", "Studio iMac");
        host.alternate_addresses = vec![
            ip("::1"),
            ip("127.0.0.1"),
            ip("2001:db8:77::126"),
            ip("192.168.77.126"),
            ip("169.254.9.9"),
        ];
        let h = found(reg.observe(host));

        assert_eq!(reg.len(), 1, "one machine, one row");
        assert_eq!(
            h.address,
            ip("192.168.77.126"),
            "the on-link IPv4 is the address we show"
        );
        assert_eq!(
            h.alternate_addresses,
            vec![ip("2001:db8:77::126")],
            "only usable addresses survive as alternates"
        );
    }

    #[test]
    fn separate_events_for_one_instance_also_collapse() {
        // mdns.rs collapses per resolution, but a re-resolution can arrive
        // under a different address; the name must keep it in one row.
        let mut reg = registry();
        found(reg.observe(mdns("192.168.77.126", "Studio iMac")));
        let h = updated(reg.observe(mdns("2001:db8:77::126", "Studio iMac")));
        assert_eq!(reg.len(), 1, "still one row");
        assert_eq!(h.address, ip("192.168.77.126"), "the id must not move");
        assert_eq!(h.alternate_addresses, vec![ip("2001:db8:77::126")]);
    }

    #[test]
    fn mdns_then_scan_is_one_row_keeping_the_mdns_name() {
        let mut reg = registry();
        let first = found(reg.observe(mdns("192.168.77.126", "Studio iMac")));
        assert_eq!(first.hostname.as_deref(), Some("Studio iMac"));

        let merged = updated(reg.observe(scanned("192.168.77.126")));
        assert_eq!(reg.len(), 1, "the scan must not add a second row");
        assert_eq!(
            merged.hostname.as_deref(),
            Some("Studio iMac"),
            "the friendly mDNS name wins over the bare IP"
        );
        assert_eq!(merged.source, DiscoverySource::Mdns);
        assert_eq!(
            merged.server_label, "macOS Screen Sharing",
            "but the scan's real fingerprint beats the mDNS placeholder"
        );
        assert_eq!(merged.rfb_version.as_deref(), Some("RFB 003.889"));
    }

    #[test]
    fn scan_then_mdns_is_one_row_and_gains_the_name() {
        let mut reg = registry();
        let first = found(reg.observe(scanned("192.168.77.133")));
        assert!(first.hostname.is_none());
        assert_eq!(first.source, DiscoverySource::Scan);

        let merged = updated(reg.observe(mdns("192.168.77.133", "Ops Box")));
        assert_eq!(reg.len(), 1);
        assert_eq!(merged.hostname.as_deref(), Some("Ops Box"));
        assert_eq!(
            merged.source,
            DiscoverySource::Mdns,
            "the named source wins so the UI shows the friendly name"
        );
        assert_eq!(merged.server_label, "macOS Screen Sharing");
    }

    #[test]
    fn an_unchanged_re_sighting_emits_nothing() {
        let mut reg = registry();
        assert!(!reg.observe(mdns("192.168.77.150", "Lab Mac")).is_empty());
        assert!(
            reg.observe(mdns("192.168.77.150", "Lab Mac")).is_empty(),
            "a repeat announcement must not churn the UI"
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn different_machines_stay_separate() {
        let mut reg = registry();
        assert!(!reg
            .observe(mdns("192.168.77.126", "Studio iMac"))
            .is_empty());
        assert!(!reg.observe(mdns("192.168.77.133", "Ops Box")).is_empty());
        assert!(!reg.observe(scanned("192.168.77.150")).is_empty());
        assert_eq!(reg.len(), 3);
    }

    #[test]
    fn the_same_name_on_a_different_port_is_a_different_row() {
        let mut reg = registry();
        assert!(!reg
            .observe(mdns("192.168.77.126", "Studio iMac"))
            .is_empty());
        let mut other = mdns("192.168.77.126", "Studio iMac");
        other.port = 5901;
        assert!(
            !reg.observe(other).is_empty(),
            ":5900 and :5901 are separate screens"
        );
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn lost_removes_the_row_and_only_for_a_known_host() {
        let mut reg = registry();
        reg.observe(mdns("192.168.77.126", "Studio iMac"));
        assert!(reg.forget(ip("192.168.77.99"), 5900).is_empty());
        assert!(matches!(
            reg.forget(ip("192.168.77.126"), 5900).as_slice(),
            [DiscoveryEvent::Lost { .. }]
        ));
        assert!(reg.is_empty());
        // The name index was released too, so it can come back cleanly.
        assert!(matches!(
            reg.observe(mdns("192.168.77.126", "Studio iMac"))
                .as_slice(),
            [DiscoveryEvent::Found(_)]
        ));
    }

    #[test]
    fn non_host_events_pass_straight_through() {
        let mut reg = registry();
        assert!(matches!(
            reg.observe_event(DiscoveryEvent::ScanProgress {
                scanned: 3,
                total: 254
            })
            .as_slice(),
            [DiscoveryEvent::ScanProgress { .. }]
        ));
        assert!(matches!(
            reg.observe_event(DiscoveryEvent::ScanComplete { found: 2 })
                .as_slice(),
            [DiscoveryEvent::ScanComplete { found: 2 }]
        ));
        assert!(matches!(
            reg.observe_event(DiscoveryEvent::Error("nope".into()))
                .as_slice(),
            [DiscoveryEvent::Error(_)]
        ));
    }

    #[test]
    fn an_ipv4_mapped_duplicate_does_not_add_a_row() {
        let mut reg = registry();
        assert!(!reg.observe(scanned("192.168.77.126")).is_empty());
        let mapped = scanned("::ffff:192.168.77.126");
        assert!(
            reg.observe(mapped).is_empty(),
            "same host, same everything, written differently"
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn an_ipv6_only_neighbour_is_still_listed() {
        let mut reg = registry();
        let mut host = mdns("fe80::5", "v6 Only Box");
        host.alternate_addresses = vec![ip("2001:db8:99::7")];
        let h = found(reg.observe(host));
        assert_eq!(h.address, ip("2001:db8:99::7"));
        assert_eq!(reg.len(), 1);
    }

    // -----------------------------------------------------------------------
    // The dual-homed machine: one box, wired and wireless, named late.
    // -----------------------------------------------------------------------

    /// The reported bug, with this LAN's real numbers: `192.168.77.92` and
    /// `192.168.77.129` are one Windows box on two adapters. Both answer the
    /// scan unnamed, nothing at that point says they are one machine, and
    /// the NetBIOS rung then names both `DESKTOP-TFBL07A`, each with its own
    /// adapter MAC. That late name is what collapses the two rows.
    #[test]
    fn a_late_name_collapses_the_dual_homed_machine_into_one_row() {
        let mut reg = registry();
        assert!(found(reg.observe(windows_scan("192.168.77.92")))
            .hostname
            .is_none());
        assert!(found(reg.observe(windows_scan("192.168.77.129")))
            .hostname
            .is_none());
        assert_eq!(reg.len(), 2, "unnamed, they are two rows, correctly so");

        // The first name is only an update: nothing yet contradicts two rows.
        let first = updated(reg.observe(named_by_netbios(
            "192.168.77.92",
            "DESKTOP-TFBL07A",
            "a0:d3:c1:0f:81:e4",
        )));
        assert_eq!(first.address, ip("192.168.77.92"));
        assert_eq!(reg.len(), 2);

        // The second name is the evidence. One row must go.
        let (lost, survivor) = collapsed(reg.observe(named_by_netbios(
            "192.168.77.129",
            "DESKTOP-TFBL07A",
            "d0:37:45:af:7a:61",
        )));

        assert_eq!(reg.len(), 1, "one machine, one row");
        assert_eq!(lost, (ip("192.168.77.129"), 5900), "the absorbed row's id");
        assert_eq!(
            survivor.address,
            ip("192.168.77.92"),
            "the best-ranked address stays"
        );
        assert_eq!(
            survivor.alternate_addresses,
            vec![ip("192.168.77.129")],
            "the other address is kept as a route to the same machine"
        );
        assert_eq!(
            survivor.macs().collect::<Vec<_>>(),
            vec!["a0:d3:c1:0f:81:e4", "d0:37:45:af:7a:61"],
            "both adapters are kept: Wake-on-LAN may need either"
        );
        assert_eq!(survivor.hostname.as_deref(), Some("DESKTOP-TFBL07A"));
        assert_eq!(survivor.name_source, Some(NameSource::NetBios));
    }

    /// Whichever adapter is named first, the row the user is looking at keeps
    /// its id: the survivor is chosen by address rank, not by arrival order,
    /// so the UI never sees the tile deleted and re-added.
    #[test]
    fn the_surviving_id_does_not_depend_on_arrival_order() {
        for (first, second) in [
            ("192.168.77.92", "192.168.77.129"),
            ("192.168.77.129", "192.168.77.92"),
        ] {
            let mut reg = registry();
            reg.observe(windows_scan(first));
            reg.observe(windows_scan(second));
            reg.observe(named_by_netbios(
                first,
                "DESKTOP-TFBL07A",
                "a0:d3:c1:0f:81:e4",
            ));
            let (lost, survivor) = collapsed(reg.observe(named_by_netbios(
                second,
                "DESKTOP-TFBL07A",
                "d0:37:45:af:7a:61",
            )));
            assert_eq!(survivor.address, ip("192.168.77.92"), "named {first} first");
            assert_eq!(lost.0, ip("192.168.77.129"));
            assert_eq!(reg.len(), 1);
        }
    }

    /// …and "ranks best" means [`filter::address_rank`], not "lowest": an
    /// on-link address beats a routed one even when it sorts higher.
    #[test]
    fn the_best_ranked_address_survives_not_the_lowest() {
        let mut reg = registry();
        reg.observe(windows_scan("10.1.1.5")); // routed private: rank 1
        reg.observe(windows_scan("192.168.77.92")); // on our wire: rank 0
        reg.observe(named_by_netbios(
            "10.1.1.5",
            "DESKTOP-TFBL07A",
            "a0:d3:c1:0f:81:e4",
        ));
        let (lost, survivor) = collapsed(reg.observe(named_by_netbios(
            "192.168.77.92",
            "DESKTOP-TFBL07A",
            "d0:37:45:af:7a:61",
        )));
        assert_eq!(survivor.address, ip("192.168.77.92"));
        assert_eq!(lost.0, ip("10.1.1.5"));
        assert_eq!(survivor.alternate_addresses, vec![ip("10.1.1.5")]);
    }

    /// A name is only evidence when there *is* one. Two anonymous rows are two
    /// machines as far as anyone can tell.
    #[test]
    fn a_missing_name_is_never_a_merge() {
        let mut reg = registry();
        reg.observe(windows_scan("192.168.77.92"));
        reg.observe(windows_scan("192.168.77.129"));
        assert_eq!(reg.len(), 2);

        // A blank or whitespace-only name is not a name either.
        let mut blank = windows_scan("192.168.77.92");
        blank.hostname = Some("   ".to_string());
        reg.observe(blank);
        let mut empty = windows_scan("192.168.77.129");
        empty.hostname = Some(String::new());
        reg.observe(empty);
        assert_eq!(reg.len(), 2, "two anonymous hosts are not one machine");
    }

    /// The port stays part of every identity, including the late-name one:
    /// `:5900` and `:5901` are two screens even on one adapter.
    #[test]
    fn a_late_name_never_joins_two_ports() {
        let mut reg = registry();
        reg.observe(windows_scan("192.168.77.92"));
        let mut second_screen = windows_scan("192.168.77.92");
        second_screen.port = 5901;
        reg.observe(second_screen);
        assert_eq!(reg.len(), 2);

        // Same machine, same name, and even the same MAC on both rows.
        reg.observe(named_by_netbios(
            "192.168.77.92",
            "DESKTOP-TFBL07A",
            "a0:d3:c1:0f:81:e4",
        ));
        let mut other_port =
            named_by_netbios("192.168.77.92", "DESKTOP-TFBL07A", "a0:d3:c1:0f:81:e4");
        other_port.port = 5901;
        let events = reg.observe(other_port);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, DiscoveryEvent::Lost { .. })),
            "nothing may be absorbed across ports: {events:?}"
        );
        assert_eq!(reg.len(), 2, ":5900 and :5901 stay separate screens");
    }

    /// A MAC is hardware identity and outranks the name: one adapter is one
    /// machine, so a host that moved address (DHCP) before its old row expired
    /// must not be listed twice, even though neither row has a name.
    #[test]
    fn a_shared_mac_collapses_rows_without_any_name() {
        let mut reg = registry();
        let mut old = windows_scan("192.168.77.92");
        old.mac = Some("A0-D3-C1-0F-81-E4".to_string()); // a different spelling
        reg.observe(old);
        let mut moved = windows_scan("192.168.77.129");
        moved.mac = Some("a0:d3:c1:0f:81:e4".to_string());
        reg.observe(moved);

        assert_eq!(reg.len(), 1, "one adapter cannot be two machines");
        let row = reg.hosts().next().expect("the surviving row");
        assert_eq!(row.address, ip("192.168.77.92"));
        assert_eq!(row.alternate_addresses, vec![ip("192.168.77.129")]);
        assert_eq!(
            row.macs().count(),
            1,
            "the same MAC written two ways is one MAC"
        );
    }

    /// The same thing once both rows have already been emitted: the collapse
    /// has to produce a `Lost`, exactly as the name-driven one does.
    #[test]
    fn a_late_mac_collapses_two_emitted_rows() {
        let mut reg = registry();
        reg.observe(windows_scan("192.168.77.92"));
        reg.observe(windows_scan("192.168.77.129"));
        let mut a = windows_scan("192.168.77.92");
        a.mac = Some("a0:d3:c1:0f:81:e4".to_string());
        reg.observe(a);
        let mut b = windows_scan("192.168.77.129");
        b.mac = Some("a0:d3:c1:0f:81:e4".to_string());
        let (lost, survivor) = collapsed(reg.observe(b));
        assert_eq!(lost, (ip("192.168.77.129"), 5900));
        assert_eq!(survivor.address, ip("192.168.77.92"));
        assert_eq!(reg.len(), 1);
    }

    /// The guard on name-based merging: two machines really can share a
    /// `DESKTOP-XXXXXXX` name, and when their banners disagree that is proof
    /// they are two machines, one server cannot answer one port two ways.
    #[test]
    fn one_name_on_two_banners_is_two_machines() {
        let mut reg = registry();
        let mut windows = windows_scan("192.168.77.92"); // RFB 003.008
        windows.hostname = Some("DESKTOP-TFBL07A".to_string());
        reg.observe(windows);

        let mut mac_mini = scanned("192.168.77.129"); // RFB 003.889, macOS
        mac_mini.hostname = Some("DESKTOP-TFBL07A".to_string());
        reg.observe(mac_mini);

        assert_eq!(
            reg.len(),
            2,
            "a name is a guess; contradicting banners are proof"
        );
    }

    /// An all-zero MAC means "no MAC" and must never join anything.
    #[test]
    fn an_all_zero_mac_is_not_an_identity() {
        assert_eq!(canonical_mac("00:00:00:00:00:00"), None);
        assert_eq!(canonical_mac(""), None);
        assert_eq!(canonical_mac("a0:d3:c1:0f:81"), None, "five octets");
        assert_eq!(
            canonical_mac("A0-D3-C1-0F-81-E4"),
            canonical_mac("a0:d3:c1:0f:81:e4"),
            "separators and case are not part of a MAC"
        );

        let mut reg = registry();
        let mut a = windows_scan("192.168.77.92");
        a.mac = Some("00:00:00:00:00:00".to_string());
        reg.observe(a);
        let mut b = windows_scan("192.168.77.129");
        b.mac = Some("00-00-00-00-00-00".to_string());
        reg.observe(b);
        assert_eq!(reg.len(), 2, "nothing is identified by an absent MAC");
    }

    // -----------------------------------------------------------------------
    // Name provenance
    // -----------------------------------------------------------------------

    /// `name_source` describes the name the row is actually showing. A losing
    /// name must not leave its provenance behind, that would tell the UI the
    /// machine is Windows on the strength of a name it discarded.
    #[test]
    fn the_name_source_describes_the_name_that_won() {
        let mut reg = registry();
        found(reg.observe(mdns("192.168.77.126", "Studio iMac")));

        let mut resolved = scanned("192.168.77.126");
        resolved.hostname = Some("studio-imac".to_string());
        resolved.name_source = Some(NameSource::NetBios);
        let row = updated(reg.observe(resolved));

        assert_eq!(row.hostname.as_deref(), Some("Studio iMac"));
        assert_eq!(
            row.name_source, None,
            "the mDNS name won, and it has no ladder provenance"
        );
    }

    /// …but a rung that independently confirms the *same* name does upgrade it.
    #[test]
    fn a_confirming_rung_supplies_the_missing_provenance() {
        let mut reg = registry();
        found(reg.observe(mdns("192.168.77.92", "DESKTOP-TFBL07A")));
        let row = updated(reg.observe(named_by_netbios(
            "192.168.77.92",
            "DESKTOP-TFBL07A",
            "a0:d3:c1:0f:81:e4",
        )));
        assert_eq!(row.name_source, Some(NameSource::NetBios));
    }

    /// One machine running both services is two rows with two ids. The port is
    /// already part of every key the registry uses, so this falls out of the
    /// existing rules rather than needing new ones, and that is worth pinning.
    #[test]
    fn a_machine_answering_on_5900_and_3389_is_two_rows() {
        let mut reg = registry();
        reg.observe(windows_scan("192.168.77.20"));
        reg.observe(rdp_scan("192.168.77.20"));

        let rows: Vec<_> = reg.hosts().cloned().collect();
        assert_eq!(rows.len(), 2, "two services, two rows: {rows:?}");
        let mut ports: Vec<u16> = rows.iter().map(|h| h.port).collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![3389, 5900]);

        // And a name learned for the address reaches both rows, because the
        // scan's resolution bookkeeping keys on the address rather than the
        // port.
        let mut named_vnc = windows_scan("192.168.77.20");
        named_vnc.hostname = Some("DESKTOP-H21K47C".into());
        named_vnc.name_source = Some(NameSource::NetBios);
        reg.observe(named_vnc);
        let mut named_rdp = rdp_scan("192.168.77.20");
        named_rdp.hostname = Some("DESKTOP-H21K47C".into());
        named_rdp.name_source = Some(NameSource::NetBios);
        reg.observe(named_rdp);

        let rows: Vec<_> = reg.hosts().cloned().collect();
        assert_eq!(rows.len(), 2, "naming them must not merge them: {rows:?}");
        assert!(rows
            .iter()
            .all(|h| h.hostname.as_deref() == Some("DESKTOP-H21K47C")));
    }

    /// Forced into the state the port normally prevents: one name, one MAC and
    /// one port shared by a VNC row and an RDP row. They must still not merge.
    /// This is the insurance for a future change to the keying, and it is the
    /// only line RDP adds to the de-duplication.
    #[test]
    fn a_vnc_row_and_an_rdp_row_never_merge() {
        let mut reg = registry();
        let mut vnc = windows_scan("192.168.77.21");
        vnc.hostname = Some("DESKTOP-H21K47C".into());
        vnc.mac = Some("aa:bb:cc:dd:ee:ff".into());

        let mut rdp = rdp_scan("192.168.77.22");
        rdp.port = 5900;
        rdp.hostname = Some("DESKTOP-H21K47C".into());
        rdp.mac = Some("aa:bb:cc:dd:ee:ff".into());

        reg.observe(vnc);
        reg.observe(rdp);
        let rows: Vec<_> = reg.hosts().cloned().collect();
        assert_eq!(
            rows.len(),
            2,
            "two protocols are two services whatever else matches: {rows:?}"
        );
    }

    /// An xrdp certificate names a host and proves nothing about its OS, where
    /// a Windows computer name does both. Before the scan probed 3389 on every
    /// address, nothing brought a Linux host on that port into the list and
    /// the distinction did not arise; now it does, and a Linux box with a
    /// Windows icon is a small thing that is hard to trace.
    #[test]
    fn an_xrdp_certificate_cn_does_not_prove_windows() {
        let windows_cn = |cn: &str| {
            let mut h = rdp_scan("192.168.77.23");
            h.hostname = Some(cn.to_string());
            h.name_source = Some(NameSource::RdpCertificate);
            h.rdp.as_mut().unwrap().cert_cn = Some(cn.to_string());
            h.implies_windows()
        };

        assert!(windows_cn("DESKTOP-H21K47C"), "a real Windows machine name");
        assert!(windows_cn("PC-1"));
        assert!(
            windows_cn("A123456789012345".get(..15).unwrap()),
            "15 passes"
        );
        assert!(!windows_cn("www.xrdp.org"), "xrdp's packaged certificate");
        assert!(!windows_cn("A1234567890123456"), "16 fails");
        assert!(!windows_cn("host_name"), "an underscore fails");
        assert!(!windows_cn(""), "an empty CN fails");

        // A name from a rung that is itself Windows-only still proves it.
        let mut netbios = windows_scan("192.168.77.24");
        netbios.hostname = Some("anything".into());
        netbios.name_source = Some(NameSource::NetBios);
        assert!(netbios.implies_windows());
    }
}
