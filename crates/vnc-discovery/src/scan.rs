//! Polite two-phase subnet scan engine.

use crate::banner::server_label;
use crate::error::Result;
use crate::filter::{self, LocalNetwork};
use crate::probe::{fingerprint, rdp_fingerprint};
use crate::resolve::{self, Resolved};
use crate::types::{DiscoveredHost, DiscoveryEvent, DiscoverySource, ScanOptions};
use remote_core::ProtocolKind;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Minimum spacing between progress events (~10/sec).
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// In-flight hostname resolution for the addresses a scan turned up.
///
/// The scan itself never waits for a name (PRD/04 §6): a host is emitted as
/// `Found` the instant its banner is read, a resolution task starts alongside,
/// and the name lands later as `Updated`. This bookkeeping exists because one
/// machine can answer on several ports, resolving `192.168.1.20` once must
/// update the `:5900` **and** `:5901` rows, and a port found *after* the name
/// arrived should carry it immediately rather than waiting for a second round.
#[derive(Debug)]
struct NameResolution {
    /// Whether to resolve at all.
    enabled: bool,
    /// Per-address wall-clock budget for the whole ladder.
    budget: Duration,
    /// Also read names from non-name services (MSRPC, RDP certificate).
    probe_other_services: bool,
    /// Every row already emitted, keyed by address.
    rows: HashMap<Ipv4Addr, Vec<DiscoveredHost>>,
    /// Addresses whose ladder has finished, with whatever it learned.
    done: HashMap<Ipv4Addr, Resolved>,
}

/// One answering service: the row to emit, and what the probe learned that the
/// resolver would otherwise have to open its own connection for.
struct Hit {
    host: DiscoveredHost,
    /// Subject `CN` from the certificate the RDP probe read on the connection
    /// it already had open (PRDRDP/08 §4.6). `None` for a VNC row and for an
    /// RDP host that offered no certificate.
    cert_name: Option<String>,
}

/// Fold a resolution into a row. Returns true if it changed anything.
///
/// A name we already have always wins, in practice that is the mDNS instance
/// name, which is friendlier than any reverse lookup ("Studio iMac" versus
/// "studio-imac"). The same rule holds in [`crate::registry`], so the two
/// cannot disagree.
///
/// The winning rung travels with the name it produced: `name_source` is only
/// set when this resolution is also what supplied `hostname`, so it can never
/// claim provenance for a name that came from somewhere else.
fn apply_resolution(host: &mut DiscoveredHost, resolved: &Resolved) -> bool {
    let mut changed = false;
    if host.hostname.is_none() {
        if let Some(name) = &resolved.hostname {
            host.hostname = Some(name.clone());
            host.name_source = resolved.source;
            changed = true;
        }
    }
    if host.mac.is_none() {
        if let Some(mac) = &resolved.mac {
            host.mac = Some(mac.clone());
            changed = true;
        }
    }
    changed
}

impl NameResolution {
    fn new(opts: &ScanOptions) -> Self {
        NameResolution {
            enabled: opts.resolve_names,
            budget: opts.resolve_budget,
            probe_other_services: opts.probe_other_services,
            rows: HashMap::new(),
            done: HashMap::new(),
        }
    }

    /// Register a freshly-found host, starting its resolution if this is the
    /// first time we have seen the address. Applies an already-known name in
    /// place, so the `Found` event carries it and no `Updated` is needed.
    fn track(
        &mut self,
        host: &mut DiscoveredHost,
        cert_name: Option<String>,
        tasks: &mut JoinSet<(Ipv4Addr, Resolved)>,
    ) {
        let IpAddr::V4(ip) = host.address else {
            return;
        };
        if !self.enabled {
            return;
        }
        if let Some(resolved) = self.done.get(&ip) {
            apply_resolution(host, resolved);
        }
        let first_sighting = !self.rows.contains_key(&ip);
        self.rows.entry(ip).or_default().push(host.clone());
        if first_sighting && !self.done.contains_key(&ip) {
            let budget = self.budget;
            let deep = self.probe_other_services;
            tasks.spawn(async move {
                (
                    ip,
                    resolve::resolve_host_sharing(ip, budget, deep, cert_name).await,
                )
            });
        }
    }

    /// Record a finished ladder. Returns the rows that gained something and so
    /// need an `Updated` event.
    fn complete(&mut self, ip: Ipv4Addr, resolved: Resolved) -> Vec<DiscoveredHost> {
        let mut updates = Vec::new();
        if let Some(rows) = self.rows.get_mut(&ip) {
            for row in rows.iter_mut() {
                if apply_resolution(row, &resolved) {
                    updates.push(row.clone());
                }
            }
        }
        self.done.insert(ip, resolved);
        updates
    }
}

/// A human label for an RDP row, built the way `server_label` builds one for
/// RFB: from what the server actually said, never from a guess.
fn rdp_label(caps: &crate::types::RdpCaps) -> String {
    if caps.standard_only {
        return "Remote Desktop (unsupported security)".to_string();
    }
    if caps.failure_code.is_some() {
        return "Remote Desktop (negotiation refused)".to_string();
    }
    match (caps.tls, caps.nla) {
        (_, true) => "Remote Desktop (TLS, NLA)".to_string(),
        (true, false) => "Remote Desktop (TLS)".to_string(),
        (false, false) => "Remote Desktop".to_string(),
    }
}

/// Paces the start of new connections to at most `max_per_sec`.
///
/// A simple time-based token bucket: each caller reserves the next slot,
/// spacing reservations by `1/rate` seconds, and sleeps until its slot.
struct RateLimiter {
    min_gap: Duration,
    next: tokio::sync::Mutex<Instant>,
}

impl RateLimiter {
    fn new(max_per_sec: u32) -> Arc<Self> {
        let rate = max_per_sec.max(1);
        Arc::new(RateLimiter {
            min_gap: Duration::from_secs_f64(1.0 / f64::from(rate)),
            next: tokio::sync::Mutex::new(Instant::now()),
        })
    }

    async fn acquire(&self) {
        let scheduled = {
            let mut guard = self.next.lock().await;
            let now = Instant::now();
            let slot = (*guard).max(now);
            *guard = slot + self.min_gap;
            slot
        };
        tokio::time::sleep_until(scheduled).await;
    }
}

/// Run a polite two-phase subnet scan, emitting events on `tx`.
///
/// Returns the number of hosts discovered. Honours `cancel` promptly.
pub async fn scan_subnet(
    mut opts: ScanOptions,
    tx: Sender<DiscoveryEvent>,
    cancel: CancellationToken,
) -> Result<u32> {
    if opts.subnets.is_empty() {
        opts.subnets = crate::subnet::local_subnets(false);
    }
    if opts.ports.is_empty() {
        opts.ports = (5900..=5906).collect();
    }

    // Validate every subnet up-front, refuse over-large scans.
    for s in &opts.subnets {
        s.guard_scannable(opts.allow_large)?;
    }

    // Gather all phase-1 host addresses.
    let mut hosts: Vec<Ipv4Addr> = Vec::new();
    for s in &opts.subnets {
        hosts.extend(s.hosts());
    }

    // Drop addresses nobody would want in a "Nearby" list, this machine's own
    // interfaces, loopback, APIPA, multicast. Doing it here rather than at
    // display time also means we never open a socket to ourselves, so the
    // politeness budget (rate limit, concurrency) is spent on real neighbours.
    if !opts.include_local {
        let local = LocalNetwork::detect();
        let before = hosts.len();
        hosts.retain(|ip| filter::is_listable(IpAddr::V4(*ip), &local));
        let skipped = before - hosts.len();
        if skipped > 0 {
            tracing::debug!(skipped, "scan: skipping own/unusable addresses");
        }
    }

    // Progress counts addresses, not connections, which is what a user reads
    // it as. Phase 1 issues more than one task per address when RDP probing is
    // on, so `scanned` can exceed `total`; the events are clamped below rather
    // than the total being inflated into a number that means nothing.
    let total = hosts.len() as u32;
    let base_port = *opts.ports.first().unwrap_or(&5900);
    let extra_ports: Vec<u16> = opts
        .ports
        .iter()
        .copied()
        .filter(|&p| p != base_port)
        .collect();

    let semaphore = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let limiter = RateLimiter::new(opts.max_rate_per_sec);
    let connect_timeout = opts.connect_timeout;

    let scanned = Arc::new(AtomicU32::new(0));
    let found = Arc::new(AtomicU32::new(0));

    // ---- Phase 1: probe base_port, and 3389, across all hosts. ----
    //
    // One task per address per service rather than one per address. Both take
    // the same semaphore permit and the same rate limiter slot before
    // connecting, so the politeness cap stays a cap on connections per second
    // in total rather than becoming one per service, which is the property
    // PRDRDP/08 §4.5 asks to be measured. They run concurrently, so an RDP
    // probe never delays a VNC row: a row is emitted the moment its own
    // answer arrives.
    let rdp_ports: Vec<u16> = if opts.probe_rdp {
        opts.rdp_ports.clone()
    } else {
        Vec::new()
    };
    let mut set: JoinSet<Option<Hit>> = JoinSet::new();
    for ip in hosts {
        if cancel.is_cancelled() {
            break;
        }
        {
            let sem = semaphore.clone();
            let lim = limiter.clone();
            let cancel = cancel.clone();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                if cancel.is_cancelled() {
                    return None;
                }
                lim.acquire().await;
                if cancel.is_cancelled() {
                    return None;
                }
                let addr = SocketAddr::new(IpAddr::V4(ip), base_port);
                let banner = fingerprint(addr, connect_timeout).await?;
                let mut host = DiscoveredHost::new(
                    IpAddr::V4(ip),
                    base_port,
                    DiscoverySource::Scan,
                    server_label(banner.major, banner.minor),
                );
                host.rfb_version = Some(banner.raw);
                Some(Hit {
                    host,
                    cert_name: None,
                })
            });
        }
        for &port in &rdp_ports {
            let sem = semaphore.clone();
            let lim = limiter.clone();
            let cancel = cancel.clone();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                if cancel.is_cancelled() {
                    return None;
                }
                lim.acquire().await;
                if cancel.is_cancelled() {
                    return None;
                }
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                let caps = rdp_fingerprint(addr, connect_timeout).await?;
                let cert_name = caps.cert_cn.clone();
                let mut host = DiscoveredHost::new(
                    IpAddr::V4(ip),
                    port,
                    DiscoverySource::Scan,
                    rdp_label(&caps),
                );
                host.protocol = ProtocolKind::Rdp;
                // The probe read the certificate on the connection it already
                // had open, so this row is named without the ladder running at
                // all. It matters most when name resolution is off entirely,
                // where the row would otherwise be a bare address forever.
                host.hostname = cert_name
                    .as_deref()
                    .and_then(|cn| resolve::sanitize_hostname(cn, ip));
                if host.hostname.is_some() {
                    host.name_source = Some(resolve::NameSource::RdpCertificate);
                }
                host.rdp = Some(caps);
                Some(Hit { host, cert_name })
            });
        }
    }

    // Hostname resolution runs alongside the scan, never in front of it.
    let mut names = NameResolution::new(&opts);
    let mut resolvers: JoinSet<(Ipv4Addr, Resolved)> = JoinSet::new();

    let mut responders: Vec<Ipv4Addr> = Vec::new();
    let mut last_progress = Instant::now();
    let _ = tx
        .send(DiscoveryEvent::ScanProgress { scanned: 0, total })
        .await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                set.abort_all();
                resolvers.abort_all();
                break;
            }
            joined = resolvers.join_next(), if !resolvers.is_empty() => {
                if let Some(Ok((ip, resolved))) = joined {
                    for host in names.complete(ip, resolved) {
                        let _ = tx.send(DiscoveryEvent::Updated(host)).await;
                    }
                }
            }
            res = set.join_next() => {
                let Some(joined) = res else { break };
                scanned.fetch_add(1, Ordering::Relaxed);
                if let Ok(Some(Hit { mut host, cert_name })) = joined {
                    // An address that answers on 3389 counts as a responder,
                    // so a Windows box found by RDP gets its 5901 to 5906
                    // probed as well. It is the same machine and it might run
                    // both.
                    if let IpAddr::V4(v4) = host.address {
                        if !responders.contains(&v4) {
                            responders.push(v4);
                        }
                    }
                    names.track(&mut host, cert_name, &mut resolvers);
                    found.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(DiscoveryEvent::Found(host)).await;
                }
                if last_progress.elapsed() >= PROGRESS_INTERVAL {
                    last_progress = Instant::now();
                    let _ = tx
                        .send(DiscoveryEvent::ScanProgress {
                            scanned: scanned.load(Ordering::Relaxed).min(total),
                            total,
                        })
                        .await;
                }
            }
        }
    }

    // ---- Phase 2: probe the remaining ports, only on responders. ----
    if !cancel.is_cancelled() && !extra_ports.is_empty() && !responders.is_empty() {
        let mut set2: JoinSet<Option<DiscoveredHost>> = JoinSet::new();
        for ip in &responders {
            for &port in &extra_ports {
                let ip = *ip;
                let sem = semaphore.clone();
                let lim = limiter.clone();
                let cancel = cancel.clone();
                set2.spawn(async move {
                    let _permit = sem.acquire_owned().await.ok()?;
                    if cancel.is_cancelled() {
                        return None;
                    }
                    lim.acquire().await;
                    let addr = SocketAddr::new(IpAddr::V4(ip), port);
                    let banner = fingerprint(addr, connect_timeout).await?;
                    let mut host = DiscoveredHost::new(
                        IpAddr::V4(ip),
                        port,
                        DiscoverySource::Scan,
                        server_label(banner.major, banner.minor),
                    );
                    host.rfb_version = Some(banner.raw);
                    Some(host)
                });
            }
        }
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    set2.abort_all();
                    resolvers.abort_all();
                    break;
                }
                joined = resolvers.join_next(), if !resolvers.is_empty() => {
                    if let Some(Ok((ip, resolved))) = joined {
                        for host in names.complete(ip, resolved) {
                            let _ = tx.send(DiscoveryEvent::Updated(host)).await;
                        }
                    }
                }
                res = set2.join_next() => {
                    let Some(joined) = res else { break };
                    if let Ok(Some(mut host)) = joined {
                        names.track(&mut host, None, &mut resolvers);
                        found.fetch_add(1, Ordering::Relaxed);
                        let _ = tx.send(DiscoveryEvent::Found(host)).await;
                    }
                }
            }
        }
    }

    // Let the outstanding ladders finish before declaring the scan complete.
    // Each is deadlined by `resolve_budget`, so this adds at most that much to
    // a scan that has otherwise finished, and it means a caller that drains
    // events until the channel closes sees every name the run could produce.
    while !cancel.is_cancelled() && !resolvers.is_empty() {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                resolvers.abort_all();
                break;
            }
            joined = resolvers.join_next() => {
                let Some(joined) = joined else { break };
                if let Ok((ip, resolved)) = joined {
                    for host in names.complete(ip, resolved) {
                        let _ = tx.send(DiscoveryEvent::Updated(host)).await;
                    }
                }
            }
        }
    }

    let total_found = found.load(Ordering::Relaxed);
    let _ = tx
        .send(DiscoveryEvent::ScanComplete { found: total_found })
        .await;
    Ok(total_found)
}
