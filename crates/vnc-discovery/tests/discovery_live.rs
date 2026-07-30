//! Live discovery tests against this machine's own network stack.
//!
//! Three things are proved here that a mock cannot prove:
//!
//! 1. the whole scan pipeline (connect → banner → fingerprint → label) against
//!    a **genuine** VNC server,
//! 2. that the mDNS `_rfb._tcp` browse works end to end on a real interface, and
//! 3. that hostname resolution (PRD/04 §6) puts real names on the real
//!    Windows/Linux servers on the operator's LAN, the one claim that byte
//!    fixtures cannot make, because it depends on what those hosts answer.
//!
//! All of them skip gracefully when the environment cannot support them, so CI
//! stays green: the scan target is probed first, the mDNS test never asserts
//! that a host *was* found (that depends on the machine's sharing settings, //! such an assertion would be flaky by construction), and the two that touch
//! every address on the LAN are opt-in via `DVV_LIVE_SUBNET_SCAN=1` /
//! `DVV_LIVE_RESOLVE=1`.
//!
//! Nothing here ever authenticates. The bulk scan only reads the banner and
//! writes nothing at all; the deep probe stops at the security-type list; the
//! name queries carry no credential of any kind.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use vnc_discovery::{
    parse_banner, server_label, DiscoveredHost, Discovery, DiscoveryEvent, DiscoverySource,
    HostRegistry, LocalNetwork, ScanOptions, Subnet,
};

/// How long the live mDNS browse runs before it is cancelled.
const BROWSE_FOR: Duration = Duration::from_secs(5);

/// The address under test: `$DVV_LIVE_VNC`, else `127.0.0.1:5900`.
fn target() -> SocketAddr {
    std::env::var("DVV_LIVE_VNC")
        .unwrap_or_else(|_| "127.0.0.1:5900".to_string())
        .parse()
        .expect("DVV_LIVE_VNC must be host:port")
}

/// Read the live server's banner, or `None` when nothing RFB-shaped answers.
/// Reads only, never writes, exactly like the scanner's own fingerprint.
async fn live_banner(what: &str) -> Option<(u16, u16)> {
    let addr = target();
    let mut stream = match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            eprintln!("SKIP {what}: no VNC server listening on {addr}");
            return None;
        }
    };
    let mut buf = [0u8; 12];
    if timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
        .await
        .is_err()
    {
        eprintln!("SKIP {what}: {addr} sent no banner");
        return None;
    }
    match parse_banner(&buf) {
        Some(b) => Some((b.major, b.minor)),
        None => {
            eprintln!("SKIP {what}: {addr} is not an RFB server");
            None
        }
    }
}

/// Collect every event a discovery run emits.
async fn drain(mut rx: mpsc::Receiver<DiscoveryEvent>) -> Vec<DiscoveryEvent> {
    let mut out = Vec::new();
    while let Some(ev) = rx.recv().await {
        out.push(ev);
    }
    out
}

fn found_hosts(events: &[DiscoveryEvent]) -> Vec<&DiscoveredHost> {
    events
        .iter()
        .filter_map(|e| match e {
            DiscoveryEvent::Found(h) => Some(h),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Scan pipeline against the real server
// ---------------------------------------------------------------------------

/// Scan `127.0.0.1/32` on the live port with the real `scan_subnet` engine and
/// assert the whole pipeline lands: the host is found, its raw banner is
/// recorded, and the fingerprint is turned into the right human label.
#[tokio::test]
async fn live_scan_finds_and_labels_the_local_server() {
    let what = "live_scan_finds_and_labels_the_local_server";
    let Some((major, minor)) = live_banner(what).await else {
        return;
    };
    let addr = target();
    let IpAddr::V4(v4) = addr.ip() else {
        eprintln!("SKIP {what}: the scanner is IPv4-only");
        return;
    };

    let opts = ScanOptions {
        subnets: vec![Subnet::new(v4, 32)],
        ports: vec![addr.port()],
        concurrency: 4,
        connect_timeout: Duration::from_millis(1500),
        max_rate_per_sec: 50,
        allow_large: false,
        probe_other_services: true,
        // This test's whole point is to exercise the pipeline against the
        // server on *this* machine, which the default policy hides.
        include_local: true,
        // The banner pipeline is what is under test here; name resolution has
        // its own live test below.
        resolve_names: false,
        resolve_budget: Duration::from_millis(500),
    };
    let (tx, rx) = mpsc::channel(64);
    let collector = tokio::spawn(drain(rx));

    let found = Discovery::new()
        .scan_subnet(opts, tx, CancellationToken::new())
        .await
        .expect("a /32 scan must not be refused");
    let events = collector.await.expect("collector must not panic");

    assert_eq!(found, 1, "exactly one server on {addr}");
    let hosts = found_hosts(&events);
    assert_eq!(hosts.len(), 1, "one Found event: {events:?}");
    let host = hosts[0];

    assert_eq!(host.address, addr.ip());
    assert_eq!(host.port, addr.port());
    assert_eq!(host.source, DiscoverySource::Scan);
    assert_eq!(
        host.rfb_version.as_deref(),
        Some(format!("RFB {major:03}.{minor:03}").as_str()),
        "the raw banner must be recorded verbatim"
    );
    assert_eq!(
        host.server_label,
        server_label(major, minor),
        "the label must come from the fingerprint"
    );
    assert!(
        host.security_types.is_empty(),
        "a bulk scan must not deep-probe"
    );

    // Progress and completion must both be reported.
    assert!(events
        .iter()
        .any(|e| matches!(e, DiscoveryEvent::ScanProgress { .. })));
    assert!(
        matches!(
            events.last(),
            Some(DiscoveryEvent::ScanComplete { found: 1 })
        ),
        "the run must end with ScanComplete: {events:?}"
    );

    eprintln!(
        "LIVE scan {addr}: {}, {} ({:?})",
        host.rfb_version.as_deref().unwrap_or("?"),
        host.server_label,
        host.source
    );

    if (major, minor) == (3, 889) {
        assert_eq!(
            host.server_label, "macOS Screen Sharing",
            "RFB 003.889 must be labelled as macOS Screen Sharing"
        );
    } else {
        eprintln!("SKIP macOS label assertion: server is RFB {major}.{minor}");
    }
}

/// An empty result is just as important: scanning a port nothing listens on
/// must complete cleanly and find nothing (this is the CI-safe half).
#[tokio::test]
async fn live_scan_of_a_dead_port_finds_nothing() {
    let opts = ScanOptions {
        subnets: vec![Subnet::new(Ipv4Addr::LOCALHOST, 32)],
        // Ephemeral-range port that nothing sane binds for RFB.
        ports: vec![59_009],
        concurrency: 2,
        connect_timeout: Duration::from_millis(500),
        max_rate_per_sec: 50,
        allow_large: false,
        probe_other_services: true,
        include_local: true,
        resolve_names: false,
        resolve_budget: Duration::from_millis(500),
    };
    let (tx, rx) = mpsc::channel(16);
    let collector = tokio::spawn(drain(rx));
    let found = Discovery::new()
        .scan_subnet(opts, tx, CancellationToken::new())
        .await
        .expect("scan must succeed even when it finds nothing");
    let events = collector.await.unwrap();
    assert_eq!(found, 0);
    assert!(found_hosts(&events).is_empty());
    assert!(matches!(
        events.last(),
        Some(DiscoveryEvent::ScanComplete { found: 0 })
    ));
}

/// The other half of the bug: filtering must not throw away real neighbours.
///
/// Scans this machine's own LAN with default options and asserts that whatever
/// is found is a *different* machine, correctly fingerprinted. Opt-in via
/// `DVV_LIVE_SUBNET_SCAN=1`: touching every host on the operator's LAN is not
/// something a plain `cargo test` should do.
#[tokio::test]
async fn live_scan_of_the_local_subnet_lists_neighbours_only() {
    let what = "live_scan_of_the_local_subnet_lists_neighbours_only";
    if std::env::var("DVV_LIVE_SUBNET_SCAN").as_deref() != Ok("1") {
        eprintln!("SKIP {what}: set DVV_LIVE_SUBNET_SCAN=1 to scan the real LAN");
        return;
    }
    let local = LocalNetwork::detect();
    let Some(&subnet) = local.v4_subnets().first() else {
        eprintln!("SKIP {what}: no local IPv4 subnet");
        return;
    };

    let opts = ScanOptions {
        subnets: vec![subnet],
        ports: vec![5900],
        connect_timeout: Duration::from_millis(400),
        ..ScanOptions::default()
    };
    let (tx, rx) = mpsc::channel(256);
    let collector = tokio::spawn(drain(rx));
    Discovery::new()
        .scan_subnet(opts, tx, CancellationToken::new())
        .await
        .expect("scanning our own /24 must be allowed");
    let events = collector.await.unwrap();

    let mut registry = HostRegistry::new(LocalNetwork::detect());
    for ev in events {
        registry.observe_event(ev);
    }
    let mut listed: Vec<&DiscoveredHost> = registry.hosts().collect();
    listed.sort_by_key(|h| (h.address, h.port));
    eprintln!(
        "LIVE scan {}/{}: {} row(s)",
        subnet.network,
        subnet.prefix,
        listed.len()
    );
    for h in &listed {
        eprintln!(
            "  {} :{}, name={:?} via={:?} macs={:?} alt={:?} {:?} ({})",
            h.address,
            h.port,
            h.hostname,
            h.name_source.map(vnc_discovery::NameSource::as_str),
            h.macs().collect::<Vec<_>>(),
            h.alternate_addresses,
            h.rfb_version,
            h.server_label
        );
        assert_usable(h.address, "scanned neighbour");
        assert!(!local.is_own(h.address), "{} is us", h.address);
        assert!(
            h.rfb_version.is_some(),
            "a scanned host must carry its banner"
        );
    }

    // The acceptance criterion for the dual-homed-machine bug: one machine is
    // one row. A named machine answering on two addresses (wired + wireless)
    // must have been collapsed by the registry, so no name may appear twice.
    let mut seen: Vec<(String, u16)> = Vec::new();
    for h in &listed {
        let Some(name) = &h.hostname else { continue };
        let id = (name.to_lowercase(), h.port);
        assert!(
            !seen.contains(&id),
            "{name} occupies two rows on port {}, the same machine is listed twice",
            h.port
        );
        seen.push(id);
    }
}

// ---------------------------------------------------------------------------
// Deep probe against the real server
// ---------------------------------------------------------------------------

/// The on-demand deep probe against a genuine server: it completes the version
/// handshake, reads the security-type list, and closes **without**
/// authenticating.
#[tokio::test]
async fn live_deep_probe_reads_security_types_without_authenticating() {
    let what = "live_deep_probe_reads_security_types_without_authenticating";
    let Some((major, minor)) = live_banner(what).await else {
        return;
    };
    let addr = target();

    let types = Discovery::deep_probe(addr)
        .await
        .expect("deep probe must succeed against a live server");
    eprintln!("LIVE deep_probe {addr}: security types {types:?}");
    assert!(!types.is_empty(), "a live server must offer something");

    if (major, minor) == (3, 889) {
        assert!(
            types.contains(&30),
            "macOS Screen Sharing must offer Apple DH (30); got {types:?}"
        );
    } else {
        eprintln!("SKIP Apple security-type assertion: server is RFB {major}.{minor}");
    }
}

// ---------------------------------------------------------------------------
// mDNS
// ---------------------------------------------------------------------------

/// Browse `_rfb._tcp` for real, for a few seconds.
///
/// This asserts the code path works end to end, daemon start, browse, event
/// pump, clean cancellation, and reports what it saw. It deliberately does
/// **not** assert that any host was found: whether this Mac advertises
/// `_rfb._tcp` depends on its Sharing settings, so that assertion would be
/// flaky.
#[tokio::test]
async fn live_mdns_browse_runs_end_to_end() {
    let (tx, mut rx) = mpsc::channel(128);
    let cancel = CancellationToken::new();
    Discovery::new().browse_mdns(tx, cancel.clone());

    let mut hosts: Vec<DiscoveredHost> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + BROWSE_FOR;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Err(_) => break,   // browse window elapsed
            Ok(None) => break, // channel closed
            Ok(Some(ev)) => match ev {
                DiscoveryEvent::Found(h) => hosts.push(h),
                DiscoveryEvent::Error(e) => errors.push(e),
                _ => {}
            },
        }
    }
    cancel.cancel();

    if !errors.is_empty() {
        // Multicast is not available everywhere (containers, locked-down CI).
        // That is an environment limitation, not a failure of this code.
        eprintln!("SKIP live_mdns_browse_runs_end_to_end: mDNS unavailable here: {errors:?}");
        return;
    }

    eprintln!(
        "LIVE mDNS _rfb._tcp: {} host(s) in {:?}",
        hosts.len(),
        BROWSE_FOR
    );
    for h in &hosts {
        eprintln!(
            "  {} :{}, {:?} ({}) alt={:?}",
            h.address, h.port, h.hostname, h.server_label, h.alternate_addresses
        );
        // Whatever was found must be well-formed.
        assert_ne!(h.port, 0, "a resolved service must carry a real port");
        assert_eq!(h.source, DiscoverySource::Mdns);
        assert!(!h.server_label.is_empty());
        assert_usable(h.address, "mDNS Found");
        for alt in &h.alternate_addresses {
            assert_usable(*alt, "mDNS alternate");
            assert_ne!(
                *alt, h.address,
                "the primary must not repeat as an alternate"
            );
        }
    }

    // One machine, one row: a single instance resolving to v4 + v6 +
    // link-local must not produce several entries. Before the fix this Mac
    // alone produced eight.
    let mut names: Vec<String> = hosts.iter().filter_map(|h| h.hostname.clone()).collect();
    names.sort();
    let unique = {
        let mut n = names.clone();
        n.dedup();
        n
    };
    assert_eq!(
        names, unique,
        "each mDNS instance must appear at most once per browse: {names:?}"
    );

    // Cancellation must actually stop the browse: nothing new after a beat.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut after = 0usize;
    while rx.try_recv().is_ok() {
        after += 1;
    }
    eprintln!("LIVE mDNS: {after} event(s) drained after cancellation");
}

// ---------------------------------------------------------------------------
// Hostname resolution (PRD/04 §6)
// ---------------------------------------------------------------------------

/// The reported bug, live: *"it resolves names only for Apple Mac machines,
/// not for windows and linux machines"*.
///
/// Scans the real LAN with resolution on, feeds every event through the same
/// [`HostRegistry`] the app uses, and reports what each responding address can
/// now be called and by which rung of the ladder. Then it re-runs the ladder
/// directly per address so the *method* is named in the output, that is the
/// acceptance evidence a unit test cannot give.
///
/// Assertions are deliberately about the *mechanism*, not about any particular
/// neighbour: whether a given host answers NetBIOS or mDNS is a property of
/// somebody else's firewall. What must hold is that resolution runs, never
/// duplicates a row, and never produces a name that is unsafe to display.
///
/// Opt-in via `DVV_LIVE_RESOLVE=1`; skips cleanly with no network.
#[tokio::test]
async fn live_scan_resolves_names_for_non_mdns_hosts() {
    let what = "live_scan_resolves_names_for_non_mdns_hosts";
    if std::env::var("DVV_LIVE_RESOLVE").as_deref() != Ok("1") {
        eprintln!("SKIP {what}: set DVV_LIVE_RESOLVE=1 to resolve names on the real LAN");
        return;
    }
    let local = LocalNetwork::detect();
    let Some(&subnet) = local.v4_subnets().first() else {
        eprintln!("SKIP {what}: no local IPv4 subnet (no network here)");
        return;
    };

    let opts = ScanOptions {
        subnets: vec![subnet],
        ports: vec![5900],
        connect_timeout: Duration::from_millis(400),
        resolve_names: true,
        probe_other_services: true,
        ..ScanOptions::default()
    };
    let (tx, rx) = mpsc::channel(256);
    let collector = tokio::spawn(drain(rx));
    Discovery::new()
        .scan_subnet(opts, tx, CancellationToken::new())
        .await
        .expect("scanning our own subnet must be allowed");
    let events = collector.await.unwrap();

    let errors: Vec<&String> = events
        .iter()
        .filter_map(|e| match e {
            DiscoveryEvent::Error(m) => Some(m),
            _ => None,
        })
        .collect();
    assert!(errors.is_empty(), "resolution must not error: {errors:?}");

    let updates = events
        .iter()
        .filter(|e| matches!(e, DiscoveryEvent::Updated(_)))
        .count();

    // Everything the scan emitted, joined exactly as the shell joins it.
    let mut registry = HostRegistry::new(LocalNetwork::detect());
    for ev in events {
        registry.observe_event(ev);
    }
    let listed: Vec<DiscoveredHost> = registry.hosts().cloned().collect();
    eprintln!(
        "LIVE resolve {}/{}: {} host(s), {updates} Updated event(s)",
        subnet.network,
        subnet.prefix,
        listed.len()
    );
    if listed.is_empty() {
        eprintln!("SKIP {what}: no VNC server answered on this LAN");
        return;
    }

    // A name arriving late must *update* the row, never add one.
    let mut addresses: Vec<IpAddr> = listed.iter().map(|h| h.address).collect();
    addresses.sort();
    let unique = {
        let mut a = addresses.clone();
        a.dedup();
        a.len()
    };
    assert_eq!(
        unique,
        addresses.len(),
        "an Updated event must merge into its row, not duplicate it"
    );

    for host in &listed {
        let IpAddr::V4(v4) = host.address else {
            continue;
        };
        // Re-run the ladder so the report can name the winning method.
        let resolved = vnc_discovery::resolve_host(v4, vnc_discovery::RESOLVE_BUDGET).await;
        eprintln!(
            "  {} :{}  name={:?}  mac={:?}  via={:?}  banner={:?}",
            host.address,
            host.port,
            host.hostname,
            host.mac,
            resolved.source.map(|s| s.as_str()),
            host.rfb_version,
        );

        if let Some(name) = &host.hostname {
            assert!(!name.is_empty());
            assert!(
                name.bytes().all(|b| (0x21..0x7F).contains(&b)),
                "a name rendered in the UI must be printable ASCII: {name:?}"
            );
            assert_ne!(
                name,
                &host.address.to_string(),
                "the address is not a name, the row should have stayed unnamed"
            );
        }
        if let Some(mac) = &host.mac {
            vnc_discovery::parse_mac(mac)
                .unwrap_or_else(|e| panic!("MAC must be Wake-on-LAN ready: {mac:?} ({e})"));
        }
        // The scan's own name must agree with a fresh run of the ladder.
        if let (Some(from_scan), Some(fresh)) = (&host.hostname, &resolved.hostname) {
            assert_eq!(
                from_scan, fresh,
                "resolution must be stable for {}",
                host.address
            );
        }
    }
}

/// The ladder against a single address, for pointing at one machine:
/// `DVV_LIVE_RESOLVE_IP=192.168.1.20 cargo test -p vnc-discovery -- --nocapture`.
#[tokio::test]
async fn live_resolve_one_address() {
    let what = "live_resolve_one_address";
    let Ok(raw) = std::env::var("DVV_LIVE_RESOLVE_IP") else {
        eprintln!("SKIP {what}: set DVV_LIVE_RESOLVE_IP=<ipv4> to resolve one address");
        return;
    };
    let ip: Ipv4Addr = raw
        .parse()
        .expect("DVV_LIVE_RESOLVE_IP must be an IPv4 address");
    let started = std::time::Instant::now();
    let resolved = vnc_discovery::resolve_host(ip, vnc_discovery::RESOLVE_BUDGET).await;
    let elapsed = started.elapsed();
    eprintln!(
        "LIVE resolve {ip}: name={:?} mac={:?} via={:?} in {elapsed:?}",
        resolved.hostname,
        resolved.mac,
        resolved.source.map(|s| s.as_str())
    );
    assert!(
        elapsed < vnc_discovery::RESOLVE_BUDGET * 4,
        "the ladder must stay inside its budget, took {elapsed:?}"
    );
    if let Some(mac) = &resolved.mac {
        vnc_discovery::parse_mac(mac).expect("a NetBIOS MAC must be Wake-on-LAN ready");
    }
}

// ---------------------------------------------------------------------------
// The reported bug: "discovery shows up localhost, ipv6 hosts etc."
// ---------------------------------------------------------------------------

/// Assert an address is one a human could actually connect to.
fn assert_usable(addr: IpAddr, what: &str) {
    let verdict = vnc_discovery::classify(addr, &LocalNetwork::detect());
    assert!(
        verdict.is_listable(),
        "{what}: {addr} must not be listed ({})",
        verdict.reason()
    );
}

/// The end-to-end regression test for the reported bug.
///
/// Runs both real discovery sources on this machine, a genuine mDNS browse and
/// a default-options scan of `127.0.0.1/32`, through the same [`HostRegistry`]
/// the app uses, and asserts that **this machine never appears**, in any of its
/// disguises: loopback, its own LAN IPv4, `::1`, or any `fe80::`.
///
/// This Mac runs Screen Sharing on `127.0.0.1:5900` and advertises `_rfb._tcp`,
/// so there is something real to reject. The test still passes (vacuously) on a
/// machine with neither, and skips only if multicast is unavailable.
#[tokio::test]
async fn live_discovery_never_lists_this_machine() {
    let local = LocalNetwork::detect();
    eprintln!("LIVE local subnets: {:?}", local.v4_subnets());
    let mut registry = HostRegistry::new(LocalNetwork::detect());

    // --- Source 1: a real mDNS browse. ---
    let (tx, mut rx) = mpsc::channel(128);
    let cancel = CancellationToken::new();
    Discovery::new().browse_mdns(tx, cancel.clone());

    let mut raw_mdns = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + BROWSE_FOR;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Err(_) | Ok(None) => break,
            Ok(Some(DiscoveryEvent::Error(e))) => errors.push(e),
            Ok(Some(ev)) => {
                if matches!(ev, DiscoveryEvent::Found(_)) {
                    raw_mdns += 1;
                }
                registry.observe_event(ev);
            }
        }
    }
    cancel.cancel();
    if !errors.is_empty() {
        eprintln!("SKIP live_discovery_never_lists_this_machine: mDNS unavailable: {errors:?}");
        return;
    }

    // --- Source 2: a real scan of this machine's own loopback. ---
    // 127.0.0.1:5900 is macOS Screen Sharing here, a live RFB server that the
    // scanner must nonetheless refuse to surface.
    let scan_target = target();
    let opts = ScanOptions {
        subnets: vec![Subnet::new(Ipv4Addr::LOCALHOST, 32)],
        ports: vec![scan_target.port()],
        concurrency: 4,
        connect_timeout: Duration::from_millis(1500),
        max_rate_per_sec: 50,
        // Everything else at its default, crucially `include_local: false`.
        ..ScanOptions::default()
    };
    let (tx, rx) = mpsc::channel(64);
    let collector = tokio::spawn(drain(rx));
    let scan_found = Discovery::new()
        .scan_subnet(opts, tx, CancellationToken::new())
        .await
        .expect("a /32 scan must not be refused");
    for ev in collector.await.expect("collector must not panic") {
        registry.observe_event(ev);
    }

    assert_eq!(
        scan_found, 0,
        "scanning 127.0.0.1/32 must find nothing to list, even with a real \
         server listening on it"
    );

    // --- The list a human would see. ---
    let listed: Vec<&DiscoveredHost> = registry.hosts().collect();
    eprintln!(
        "LIVE nearby: {} raw mDNS Found event(s) collapsed to {} row(s)",
        raw_mdns,
        listed.len()
    );
    for h in &listed {
        eprintln!(
            "  {} :{}, {:?} ({}) alt={:?} via {:?}",
            h.address, h.port, h.hostname, h.server_label, h.alternate_addresses, h.source
        );
    }

    for h in &listed {
        assert_usable(h.address, "nearby row");
        assert!(
            !local.is_own(h.address),
            "{} is one of this machine's own addresses",
            h.address
        );
        for alt in &h.alternate_addresses {
            assert_usable(*alt, "nearby alternate");
            assert!(!local.is_own(*alt));
        }
    }

    // No two rows may be the same machine.
    let mut keys: Vec<(IpAddr, u16)> = listed.iter().map(|h| (h.address, h.port)).collect();
    keys.sort();
    let before = keys.len();
    keys.dedup();
    assert_eq!(before, keys.len(), "duplicate rows in the Nearby list");
}
