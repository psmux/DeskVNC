//! Polite two-phase subnet scan engine.

use crate::banner::server_label;
use crate::boundary;
use crate::error::Result;
use crate::filter::{self, LocalNetwork};
use crate::probe::{fingerprint, rdp_fingerprint};
use crate::resolve::{self, Resolved};
use crate::types::{DiscoveredHost, DiscoveryEvent, DiscoverySource, ScanOptions};
use remote_core::ProtocolKind;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
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

/// Which kind of server one connection looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Service {
    /// RFB banner, on the base port in phase 1 and the other ports in phase 2.
    Vnc,
    /// X.224 negotiation on 3389 (or whatever `rdp_ports` says).
    Rdp,
    /// The machine ID line a Boundary computer sends on 5940.
    Boundary,
}

/// One connection the scan will make: an address, a port, and what to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Probe {
    ip: Ipv4Addr,
    port: u16,
    service: Service,
}

/// Every probe of a phase, address by address, made only as the pool asks for
/// them: a /16 never exists as a list of 196,602 probes.
struct Probes {
    hosts: std::vec::IntoIter<Ipv4Addr>,
    services: Vec<(u16, Service)>,
    current: Option<Ipv4Addr>,
    next_service: usize,
}

impl Probes {
    fn new(hosts: Vec<Ipv4Addr>, services: Vec<(u16, Service)>) -> Self {
        Probes {
            hosts: hosts.into_iter(),
            services,
            current: None,
            next_service: 0,
        }
    }
}

impl Iterator for Probes {
    type Item = Probe;

    fn next(&mut self) -> Option<Probe> {
        if self.services.is_empty() {
            return None;
        }
        if self.current.is_none() || self.next_service == self.services.len() {
            self.current = Some(self.hosts.next()?);
            self.next_service = 0;
        }
        let (port, service) = self.services[self.next_service];
        self.next_service += 1;
        Some(Probe {
            ip: self.current?,
            port,
            service,
        })
    }
}

/// Make one real connection and turn whatever answered into a row.
async fn probe(p: Probe, connect_timeout: Duration) -> Option<Hit> {
    let addr = SocketAddr::new(IpAddr::V4(p.ip), p.port);
    match p.service {
        Service::Vnc => {
            let banner = fingerprint(addr, connect_timeout).await?;
            let mut host = DiscoveredHost::new(
                IpAddr::V4(p.ip),
                p.port,
                DiscoverySource::Scan,
                server_label(banner.major, banner.minor),
            );
            host.rfb_version = Some(banner.raw);
            Some(Hit {
                host,
                cert_name: None,
            })
        }
        Service::Rdp => {
            let caps = rdp_fingerprint(addr, connect_timeout).await?;
            let cert_name = caps.cert_cn.clone();
            let mut host = DiscoveredHost::new(
                IpAddr::V4(p.ip),
                p.port,
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
                .and_then(|cn| resolve::sanitize_hostname(cn, p.ip));
            if host.hostname.is_some() {
                host.name_source = Some(resolve::NameSource::RdpCertificate);
            }
            host.rdp = Some(caps);
            Some(Hit { host, cert_name })
        }
        Service::Boundary => {
            let id = boundary::fingerprint(addr, connect_timeout).await?;
            let mut host = DiscoveredHost::new(
                IpAddr::V4(p.ip),
                p.port,
                DiscoverySource::Scan,
                boundary::LABEL.to_string(),
            );
            host.protocol = ProtocolKind::Boundary;
            host.boundary_id = Some(id);
            Some(Hit {
                host,
                cert_name: None,
            })
        }
    }
}

/// Runs a scan's probes through at most `limit` tasks at a time.
///
/// The probes come from an iterator and a task is started only when one of
/// the `limit` slots is free, so a /16 holds the same couple of hundred tasks
/// a /24 does. Starting one task per probe up front and letting a semaphore
/// hold them back kept every waiting task's future alive at once: about
/// 200,000 of them for a /16 with RDP and Boundary probing on, which is what
/// took the app from about 180 MB to about 450 MB.
///
/// `limit` is `ScanOptions::concurrency`, the number of connections a scan
/// may have open at once. Each task holds its slot from before it waits for
/// a rate limiter slot until its connection is done, which is exactly how
/// long it used to hold a semaphore permit, so the scan is as polite and as
/// fast as before.
struct ProbePool<I, F> {
    probes: I,
    tasks: JoinSet<(Probe, Option<Hit>)>,
    /// What each running task is probing, so a task that panics can still be
    /// counted against its address.
    running: HashMap<tokio::task::Id, Probe>,
    limit: usize,
    prober: F,
    limiter: Arc<RateLimiter>,
    cancel: CancellationToken,
}

impl<I, F, Fut> ProbePool<I, F>
where
    I: Iterator<Item = Probe>,
    F: Fn(Probe) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Option<Hit>> + Send + 'static,
{
    fn new(
        probes: I,
        limit: usize,
        prober: F,
        limiter: Arc<RateLimiter>,
        cancel: CancellationToken,
    ) -> Self {
        ProbePool {
            probes,
            tasks: JoinSet::new(),
            running: HashMap::new(),
            limit: limit.max(1),
            prober,
            limiter,
            cancel,
        }
    }

    /// Start probes until every slot is busy or there are none left.
    fn fill(&mut self) {
        while self.tasks.len() < self.limit && !self.cancel.is_cancelled() {
            let Some(p) = self.probes.next() else { break };
            let prober = self.prober.clone();
            let lim = self.limiter.clone();
            let cancel = self.cancel.clone();
            let handle = self.tasks.spawn(async move {
                if cancel.is_cancelled() {
                    return (p, None);
                }
                lim.acquire().await;
                if cancel.is_cancelled() {
                    return (p, None);
                }
                (p, prober(p).await)
            });
            self.running.insert(handle.id(), p);
        }
    }

    /// The next finished probe, refilling the freed slot first. `None` once
    /// every probe has run. Cancel safe: the refill is synchronous and
    /// `JoinSet::join_next_with_id` loses nothing when dropped.
    ///
    /// A probe whose task panicked comes back as a miss for that probe, so
    /// its address is still counted as scanned.
    async fn next(&mut self) -> Option<(Probe, Option<Hit>)> {
        self.fill();
        match self.tasks.join_next_with_id().await? {
            Ok((id, done)) => {
                self.running.remove(&id);
                Some(done)
            }
            Err(e) => {
                tracing::debug!("scan: probe task failed: {e}");
                let probe = self.running.remove(&e.id())?;
                Some((probe, None))
            }
        }
    }

    fn abort(&mut self) {
        self.tasks.abort_all();
        self.running.clear();
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

    let connect_timeout = opts.connect_timeout;
    Ok(scan_hosts(hosts, &opts, tx, cancel, move |p| probe(p, connect_timeout)).await)
}

/// The scan proper, over addresses already chosen, with the connection itself
/// supplied by `prober` so the tests can count what the scan holds in memory
/// without opening a socket.
async fn scan_hosts<F, Fut>(
    hosts: Vec<Ipv4Addr>,
    opts: &ScanOptions,
    tx: Sender<DiscoveryEvent>,
    cancel: CancellationToken,
    prober: F,
) -> u32
where
    F: Fn(Probe) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Option<Hit>> + Send + 'static,
{
    // Progress counts addresses, not connections, which is what a user reads
    // it as: an address counts once every probe phase 1 makes to it is done.
    let total = hosts.len() as u32;
    let base_port = *opts.ports.first().unwrap_or(&5900);
    let extra_ports: Vec<u16> = opts
        .ports
        .iter()
        .copied()
        .filter(|&p| p != base_port)
        .collect();

    let limiter = RateLimiter::new(opts.max_rate_per_sec);
    let mut found: u32 = 0;

    // ---- Phase 1: probe base_port, 3389 and 5940, across all hosts. ----
    //
    // One probe per address per service rather than one per address. Every
    // probe takes the same pool slot and the same rate limiter slot before
    // connecting, so the politeness cap stays a cap on connections per second
    // in total rather than becoming one per service, which is the property
    // PRDRDP/08 §4.5 asks to be measured. They run concurrently, so an RDP
    // probe never delays a VNC row: a row is emitted the moment its own
    // answer arrives.
    let mut services: Vec<(u16, Service)> = vec![(base_port, Service::Vnc)];
    if opts.probe_rdp {
        services.extend(opts.rdp_ports.iter().map(|&p| (p, Service::Rdp)));
    }
    if opts.probe_boundary {
        services.extend(opts.boundary_ports.iter().map(|&p| (p, Service::Boundary)));
    }
    let per_address = services.len();
    let phase1 = Probes::new(hosts, services);
    let mut pool = ProbePool::new(
        phase1,
        opts.concurrency,
        prober.clone(),
        limiter.clone(),
        cancel.clone(),
    );

    // Hostname resolution runs alongside the scan, never in front of it.
    let mut names = NameResolution::new(opts);
    let mut resolvers: JoinSet<(Ipv4Addr, Resolved)> = JoinSet::new();

    let mut responders: Vec<Ipv4Addr> = Vec::new();
    // Probes finished per address, for the addresses still in flight. Probes
    // start in address order, so this never holds more than about
    // `concurrency` entries.
    let mut finished: HashMap<Ipv4Addr, usize> = HashMap::new();
    let mut scanned: u32 = 0;
    let mut last_progress = Instant::now();
    let _ = tx
        .send(DiscoveryEvent::ScanProgress { scanned: 0, total })
        .await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                pool.abort();
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
            res = pool.next() => {
                let Some((probe, hit)) = res else {
                    // Every address is done: say so, whatever the throttle
                    // last let through, so a bar never stops short of full.
                    let _ = tx
                        .send(DiscoveryEvent::ScanProgress { scanned, total })
                        .await;
                    break;
                };
                let count = finished.entry(probe.ip).or_insert(0);
                *count += 1;
                if *count == per_address {
                    finished.remove(&probe.ip);
                    scanned += 1;
                }
                if let Some(Hit { mut host, cert_name }) = hit {
                    // An address that answers on 3389 or 5940 counts as a
                    // responder, so a Windows box found by RDP gets its 5901
                    // to 5906 probed as well. It is the same machine and it
                    // might run both.
                    if let IpAddr::V4(v4) = host.address {
                        if !responders.contains(&v4) {
                            responders.push(v4);
                        }
                    }
                    names.track(&mut host, cert_name, &mut resolvers);
                    found += 1;
                    let _ = tx.send(DiscoveryEvent::Found(host)).await;
                }
                if last_progress.elapsed() >= PROGRESS_INTERVAL {
                    last_progress = Instant::now();
                    let _ = tx
                        .send(DiscoveryEvent::ScanProgress { scanned, total })
                        .await;
                }
            }
        }
    }

    // ---- Phase 2: probe the remaining ports, only on responders. ----
    if !cancel.is_cancelled() && !extra_ports.is_empty() && !responders.is_empty() {
        let services = extra_ports.iter().map(|&p| (p, Service::Vnc)).collect();
        let phase2 = Probes::new(responders, services);
        let mut pool = ProbePool::new(phase2, opts.concurrency, prober, limiter, cancel.clone());
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    pool.abort();
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
                res = pool.next() => {
                    let Some((_, hit)) = res else { break };
                    if let Some(Hit { mut host, .. }) = hit {
                        names.track(&mut host, None, &mut resolvers);
                        found += 1;
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

    let _ = tx.send(DiscoveryEvent::ScanComplete { found }).await;
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subnet::Subnet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// What the fake prober saw over a whole scan.
    #[derive(Default)]
    struct Seen {
        calls: AtomicUsize,
        in_flight: AtomicUsize,
        peak_in_flight: AtomicUsize,
        peak_alive_tasks: AtomicUsize,
        after_cancel: AtomicUsize,
    }

    fn opts(concurrency: usize) -> ScanOptions {
        ScanOptions {
            concurrency,
            max_rate_per_sec: u32::MAX,
            resolve_names: false,
            allow_large: true,
            ..ScanOptions::default()
        }
    }

    /// A prober that opens nothing. It records how many tasks the runtime is
    /// holding and how many probes overlap, takes a millisecond of (paused)
    /// time, and answers on every port for the addresses in `answer`.
    fn fake(
        seen: Arc<Seen>,
        answer: Vec<Ipv4Addr>,
        cancel: CancellationToken,
        cancel_after: usize,
    ) -> impl Fn(Probe) -> std::pin::Pin<Box<dyn Future<Output = Option<Hit>> + Send>>
           + Clone
           + Send
           + 'static {
        let answer = Arc::new(answer);
        move |p: Probe| {
            let seen = seen.clone();
            let answer = answer.clone();
            let cancel = cancel.clone();
            Box::pin(async move {
                if cancel.is_cancelled() {
                    seen.after_cancel.fetch_add(1, Ordering::SeqCst);
                }
                let n = seen.calls.fetch_add(1, Ordering::SeqCst) + 1;
                if n == cancel_after {
                    cancel.cancel();
                }
                let alive = tokio::runtime::Handle::current()
                    .metrics()
                    .num_alive_tasks();
                seen.peak_alive_tasks.fetch_max(alive, Ordering::SeqCst);
                let now = seen.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                seen.peak_in_flight.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1)).await;
                seen.in_flight.fetch_sub(1, Ordering::SeqCst);
                if !answer.contains(&p.ip) {
                    return None;
                }
                let mut host = DiscoveredHost::new(
                    IpAddr::V4(p.ip),
                    p.port,
                    DiscoverySource::Scan,
                    "fake".to_string(),
                );
                host.protocol = match p.service {
                    Service::Vnc => ProtocolKind::Vnc,
                    Service::Rdp => ProtocolKind::Rdp,
                    Service::Boundary => ProtocolKind::Boundary,
                };
                Some(Hit {
                    host,
                    cert_name: None,
                })
            })
        }
    }

    fn drain(
        mut rx: tokio::sync::mpsc::Receiver<DiscoveryEvent>,
    ) -> tokio::task::JoinHandle<Vec<DiscoveryEvent>> {
        tokio::spawn(async move {
            let mut events = Vec::new();
            while let Some(e) = rx.recv().await {
                events.push(e);
            }
            events
        })
    }

    fn slash16() -> Vec<Ipv4Addr> {
        Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 16)
            .hosts()
            .collect()
    }

    /// A /16 with VNC, RDP and Boundary probing on is 196,602 probes. The scan
    /// must hold no more tasks than its concurrency allows connections, keep
    /// every one of those slots busy (or it would be slower), probe each
    /// address and port exactly once, and report progress in addresses that
    /// ends at the total.
    #[tokio::test(start_paused = true)]
    async fn a_slash_16_holds_only_as_many_tasks_as_it_has_connections() {
        let hosts = slash16();
        let total = hosts.len();
        assert_eq!(total, 65_534);
        let answer = vec![Ipv4Addr::new(10, 0, 0, 7), Ipv4Addr::new(10, 0, 200, 9)];
        let seen = Arc::new(Seen::default());
        let cancel = CancellationToken::new();
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let events = drain(rx);
        let o = opts(200);
        let found = scan_hosts(
            hosts,
            &o,
            tx,
            cancel.clone(),
            fake(seen.clone(), answer, cancel, 0),
        )
        .await;
        let events = events.await.unwrap();

        let peak_alive = seen.peak_alive_tasks.load(Ordering::SeqCst);
        // The pool's tasks, the event drain, and nothing else.
        assert!(
            peak_alive <= o.concurrency + 2,
            "peak tasks alive {peak_alive} for a concurrency of {}",
            o.concurrency
        );
        assert_eq!(seen.peak_in_flight.load(Ordering::SeqCst), o.concurrency);

        // Phase 1: three probes per address. Phase 2: 5901 to 5906 on the two
        // that answered.
        assert_eq!(seen.calls.load(Ordering::SeqCst), total * 3 + 2 * 6);
        // Each responder answers on 5900, 3389, 5940 and then 5901 to 5906.
        assert_eq!(found, 2 * (3 + 6));
        let found_events = events
            .iter()
            .filter(|e| matches!(e, DiscoveryEvent::Found(_)))
            .count();
        assert_eq!(found_events, found as usize);

        let progress: Vec<(u32, u32)> = events
            .iter()
            .filter_map(|e| match e {
                DiscoveryEvent::ScanProgress { scanned, total } => Some((*scanned, *total)),
                _ => None,
            })
            .collect();
        assert!(progress.iter().all(|&(_, t)| t as usize == total));
        assert!(progress.windows(2).all(|w| w[0].0 <= w[1].0));
        assert_eq!(progress.first().unwrap().0, 0);
        assert_eq!(progress.last().unwrap().0 as usize, total);
        assert!(matches!(
            events.last(),
            Some(DiscoveryEvent::ScanComplete { found: f }) if *f == found
        ));
    }

    /// Cancelling stops the scan where it is: no probe starts after the token
    /// fires, the scan returns, and it still says it is complete.
    #[tokio::test(start_paused = true)]
    async fn cancelling_a_large_scan_starts_no_more_probes() {
        let seen = Arc::new(Seen::default());
        let cancel = CancellationToken::new();
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let events = drain(rx);
        let o = opts(200);
        scan_hosts(
            slash16(),
            &o,
            tx,
            cancel.clone(),
            fake(seen.clone(), Vec::new(), cancel.clone(), 10_000),
        )
        .await;
        let events = events.await.unwrap();

        assert!(cancel.is_cancelled());
        assert_eq!(seen.after_cancel.load(Ordering::SeqCst), 0);
        assert_eq!(seen.calls.load(Ordering::SeqCst), 10_000);
        assert!(seen.peak_alive_tasks.load(Ordering::SeqCst) <= o.concurrency + 2);
        let last_progress = events.iter().rev().find_map(|e| match e {
            DiscoveryEvent::ScanProgress { scanned, .. } => Some(*scanned),
            _ => None,
        });
        assert!(last_progress.unwrap() < 10_000 / 3 + 1);
        assert!(matches!(
            events.last(),
            Some(DiscoveryEvent::ScanComplete { found: 0 })
        ));
    }

    /// A probe that panics is counted as a miss, so progress still reaches the
    /// total and the scan finishes.
    #[tokio::test]
    async fn a_panicking_probe_still_counts_toward_progress() {
        let hosts: Vec<Ipv4Addr> = Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 24)
            .hosts()
            .collect();
        let total = hosts.len() as u32;
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let events = drain(rx);
        let calls = Arc::new(Mutex::new(0usize));
        let c = calls.clone();
        let prober = move |p: Probe| {
            let c = c.clone();
            async move {
                *c.lock().unwrap() += 1;
                if p.ip == Ipv4Addr::new(10, 0, 0, 42) && p.service == Service::Rdp {
                    panic!("probe blew up");
                }
                None
            }
        };
        scan_hosts(hosts, &opts(16), tx, CancellationToken::new(), prober).await;
        let events = events.await.unwrap();
        assert_eq!(*calls.lock().unwrap(), total as usize * 3);
        let last = events.iter().rev().find_map(|e| match e {
            DiscoveryEvent::ScanProgress { scanned, .. } => Some(*scanned),
            _ => None,
        });
        assert_eq!(last, Some(total));
    }
}
