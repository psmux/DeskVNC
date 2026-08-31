//! Discovery commands: mDNS browse, polite subnet scan, deep probe, WoL.
//!
//! Events are normalized here into the shell's own `discovery://event`
//! contract (internally tagged, kebab-case `type`), see
//! `src-tauri/IPC_CONTRACT.md`. `vnc_discovery::DiscoveryEvent` is an
//! externally-tagged Rust enum (`{"Found":{…}}`) whose `DiscoveredHost` has no
//! stable identity and uses `SystemTime`/`IpAddr` field types; the webview
//! never sees that shape. A finished scan additionally emits
//! `discovery://scan-complete` with an optional error string. Discovered
//! hostnames/labels are server-derived and untrusted, the UI renders them as
//! text only.
//!
//! Both discovery sources funnel through one [`vnc_discovery::HostRegistry`]
//! (see [`registry`]) before anything is emitted. mDNS and the subnet scan run
//! as independent streams and routinely see the same server; the registry is
//! where they are joined into one row per machine, and where this machine's own
//! addresses are dropped.
//!
//! That join is also what makes hostname resolution safe to stream. Only mDNS
//! carries a friendly name, so a scanned Windows/Linux server is emitted as a
//! bare address and gains its name (and, from NetBIOS, its MAC) a fraction of a
//! second later, see `vnc_discovery::resolve`. Those arrive as `Updated`
//! events on the same address/port, so the registry merges them into the
//! existing row rather than adding a second one, and an mDNS name already on
//! the row still wins.
//!
//! A late name can also reveal that two rows already on screen are one
//! dual-homed machine, in which case one incoming event becomes two outgoing
//! ones, a `lost` for the absorbed tile, then an `updated` for the survivor.
//! The name's provenance (`vnc_discovery::NameSource`) is forwarded as
//! `nameSource` and is what lets [`os_hint`] tell Windows from Linux with
//! evidence instead of by sniffing the banner text.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Instant;

use parking_lot::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
use vnc_discovery::{
    DiscoveredHost, Discovery, DiscoveryEvent, DiscoverySource, HostRegistry, LocalNetwork,
    ScanOptions, Subnet,
};

use crate::state::AppState;

/// The single de-duplication point for every discovery stream.
///
/// It is process-global rather than part of `AppState` on purpose: the mDNS
/// browse and each subnet scan are started by different commands with their own
/// channels, and they must all be de-duplicated against *each other*, a server
/// that mDNS already named must not reappear as a bare IP when a scan finds it.
fn registry() -> &'static Mutex<HostRegistry> {
    static REGISTRY: OnceLock<Mutex<HostRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HostRegistry::new(LocalNetwork::detect())))
}

/// Re-read this machine's interfaces before a discovery run so a Wi-Fi/VPN
/// change since startup does not make us list ourselves.
fn refresh_local_network() {
    let local = LocalNetwork::detect();
    registry().lock().set_local(local);
}

/// Stable identity for a discovered host: `"<address>:<port>"`. `Lost` only
/// carries an address/port pair, so the id must be derivable from those alone.
fn discovered_id(address: &std::net::IpAddr, port: u16) -> String {
    format!("{address}:{port}")
}

/// OS classification for a discovered host, drives an icon + a text label.
///
/// Two tiers, and the difference matters. **Proof first**: `netbios`,
/// `msrpc-epm` and `rdp-cert` are Windows-only services, so a name that came
/// from one of them settles the question no matter what the VNC server calls
/// itself, which is the whole point, because a Windows box running TigerVNC
/// advertises a banner that reads Linux. See
/// [`vnc_discovery::NameSource::implies_windows`].
///
/// **Then guessing**: the substring sniff over the banner and hostname, which
/// is all we have for everything else. Note what is *not* proof: `mdns-ptr`
/// says nothing about macOS, because Avahi answers it on every Linux desktop
/// (this LAN's `raspberrypi` is named exactly that way), and `llmnr` is
/// implemented by `systemd-resolved` too.
fn os_hint(host: &DiscoveredHost) -> &'static str {
    if host.name_source.is_some_and(|s| s.implies_windows()) {
        return "windows";
    }

    let mut hay = host.server_label.to_ascii_lowercase();
    if let Some(name) = &host.hostname {
        hay.push(' ');
        hay.push_str(&name.to_ascii_lowercase());
    }
    if hay.contains("macos") || hay.contains("apple") || hay.contains("screen sharing") {
        "macos"
    } else if hay.contains("qemu") || hay.contains("proxmox") || hay.contains("libvirt") {
        "qemu"
    } else if hay.contains("windows") || hay.contains("tightvnc") || hay.contains("ultravnc") {
        "windows"
    } else if hay.contains("tigervnc") || hay.contains("vino") || hay.contains("x11") {
        "linux"
    } else {
        "unknown"
    }
}

/// Friendly name for an RFB security type number (RFC 6143 §7.2 + vendor
/// extensions), used for the "Apple auth" / "VncAuth" hint on a tile.
fn security_type_label(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "None",
        2 => "VncAuth",
        5 => "RA2",
        6 => "RA2ne",
        16 => "Tight",
        18 => "TLS",
        19 => "VeNCrypt",
        30 => "Apple auth",
        _ => return None,
    })
}

/// Coarse transport-security classification from the offered security types.
/// Only a deep probe fills `security_types`, so an un-probed host is
/// `"unknown"` rather than being optimistically labelled.
fn security_level(types: &[u8]) -> &'static str {
    if types.is_empty() {
        "unknown"
    } else if types.iter().any(|t| matches!(t, 18 | 19)) {
        // TLS/VeNCrypt: encrypted, but the certificate is not pinned yet.
        "unverified"
    } else if types.iter().any(|t| matches!(t, 5 | 6 | 30)) {
        // Challenge/response with a real key exchange, no channel encryption.
        "unverified"
    } else {
        "unencrypted"
    }
}

/// Map a `vnc_discovery::DiscoveredHost` onto the webview's `DiscoveredHost`.
fn host_json(host: &DiscoveredHost) -> serde_json::Value {
    let security_hint = host
        .security_types
        .iter()
        .copied()
        .find_map(security_type_label)
        .map(str::to_string)
        .or_else(|| host.rfb_version.clone());
    serde_json::json!({
        "id": discovered_id(&host.address, host.port),
        "name": host.hostname.clone().unwrap_or_else(|| host.address.to_string()),
        "address": host.address.to_string(),
        "port": host.port,
        "osHint": os_hint(host),
        "serverHint": host.server_label,
        "securityHint": security_hint,
        "security": security_level(&host.security_types),
        "securityTypes": host.security_types,
        "source": match host.source {
            DiscoverySource::Mdns => "mdns",
            DiscoverySource::Scan => "scan",
            DiscoverySource::Manual => "manual",
        },
        "mac": host.mac,
        // A dual-homed machine is one row with one MAC per adapter, and
        // Wake-on-LAN may need either, `mac` is the primary, this is the rest.
        "alternateMacs": host.alternate_macs,
        // Which rung of the resolution ladder produced `name` (or null when the
        // name came from the mDNS browse rather than the ladder). Provenance,
        // not decoration: `netbios` / `msrpc-epm` / `rdp-cert` are Windows-only
        // services and are what `osHint` trusts over the banner text.
        "nameSource": host.name_source.map(vnc_discovery::NameSource::as_str),
        // Which protocol answers on THIS row's port. One row is one service,
        // so a machine running both produces two rows and the interface joins
        // them, not the registry.
        "protocol": host.protocol,
        // What the X.224 negotiation learned, `null` for a VNC row and for an
        // RDP row that has not been deep probed. `nlaRequired` inside it is
        // itself nullable, because one negotiation cannot answer it: a server
        // that permits both TLS and NLA selects the stronger, which proves
        // NLA is available and says nothing about whether TLS alone would
        // have been refused.
        "rdp": host.rdp,
        // The shell does not join against the host library on the hot path;
        // the UI already de-dupes discovered entries against its own list.
        "savedHostId": serde_json::Value::Null,
    })
}

/// Normalize one discovery event into the `discovery://event` JSON contract.
fn event_json(event: &DiscoveryEvent) -> serde_json::Value {
    use serde_json::json;
    match event {
        DiscoveryEvent::Found(h) => json!({ "type": "found", "host": host_json(h) }),
        DiscoveryEvent::Updated(h) => json!({ "type": "updated", "host": host_json(h) }),
        DiscoveryEvent::Lost { address, port } => {
            json!({ "type": "lost", "id": discovered_id(address, *port) })
        }
        DiscoveryEvent::ScanProgress { scanned, total } => {
            json!({ "type": "scan-progress", "done": scanned, "total": total })
        }
        DiscoveryEvent::ScanComplete { found } => {
            json!({ "type": "scan-complete", "found": found })
        }
        DiscoveryEvent::Error(message) => json!({ "type": "error", "message": message }),
    }
}

/// Pump one discovery stream to the webview, de-duplicated.
///
/// Every event passes through the shared registry first: hosts that are this
/// machine, or that carry no usable address, are dropped; a machine already
/// listed is merged into its existing row and only re-emitted (as `updated`)
/// when something visible actually changed.
///
/// One incoming event can become several outgoing ones, a name that arrives
/// after both of a dual-homed machine's addresses have been listed collapses
/// the two rows, which is a `lost` for the absorbed row *and* an `updated` for
/// the survivor. They are emitted in the order the registry returned them.
fn forward_events(app: AppHandle, mut rx: tokio::sync::mpsc::Receiver<DiscoveryEvent>) {
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            // The lock is held only for the map lookup/merge, no awaits inside.
            let events = registry().lock().observe_event(event);
            for event in events {
                let _ = app.emit("discovery://event", event_json(&event));
            }
        }
    });
}

/// Does a window with this label still exist?
///
/// Injected into [`crate::state::DiscoveryState`] rather than looked up there,
/// the same way `state::find_live_session` takes it, so the subscription rules
/// stay testable without a running Tauri app. Takes the handle by value
/// (`AppHandle` is a cheap clone) so the closure borrows nothing and can sit
/// alongside a later move of the handle.
fn window_exists(app: AppHandle) -> impl Fn(&str) -> bool {
    move |label: &str| app.get_webview_window(label).is_some()
}

/// Start the passive mDNS browse (`_rfb._tcp` / `_ard._tcp`).
///
/// Idempotent per window, which is the part that used to be wrong: the browse
/// is one process-wide stream, but each Library window starts and stops it
/// independently, so it is reference counted by window label (B2, see
/// [`crate::state::DiscoveryState::subscribe_browse`]). `window` is injected by
/// Tauri from the invoke context, it is not an argument the webview passes, so
/// `invoke("start_discovery")` is unchanged.
#[tauri::command]
pub async fn start_discovery(
    app: AppHandle,
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let exists = window_exists(app.clone());
    let Some(cancel) = state.discovery.subscribe_browse(window.label(), &exists) else {
        return Ok(()); // already browsing, this window joined the running one
    };

    refresh_local_network();
    let (tx, rx) = tokio::sync::mpsc::channel::<DiscoveryEvent>(64);
    Discovery::new().browse_mdns(tx, cancel);
    forward_events(app, rx);
    Ok(())
}

/// Stop the mDNS browse for this window. The stream itself stops when the last
/// window watching it has gone.
#[tauri::command]
pub async fn stop_discovery(
    app: AppHandle,
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let exists = window_exists(app);
    let stopped = state.discovery.unsubscribe_browse(window.label(), &exists);
    // Forget what we found so the next browse re-emits `found` for everything
    // rather than silently suppressing it as a duplicate. The UI de-dupes
    // discovered entries by id, so a repeat `found` is harmless; a missing one
    // would leave the list empty.
    //
    // Only once nothing is left reading the registry, though. This used to fire
    // whenever any window closed, which threw away the de-duplication state a
    // second Library window was still displaying against (and cancelled that
    // window's browse outright, which is B2).
    if stopped && !state.discovery.scan_is_running() {
        registry().lock().clear();
    }
    Ok(())
}

/// Parse `"a.b.c.d/nn"` into a [`Subnet`].
fn parse_subnet(s: &str) -> Result<Subnet, String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| format!("invalid subnet (expected CIDR): {s}"))?;
    let addr: Ipv4Addr = addr
        .trim()
        .parse()
        .map_err(|_| format!("invalid subnet address: {s}"))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .map_err(|_| format!("invalid subnet prefix: {s}"))?;
    if prefix > 32 {
        return Err(format!("invalid subnet prefix: {s}"));
    }
    Ok(Subnet::new(addr, prefix))
}

/// Kick off an active subnet scan (PRD/04 §4). `subnets` is a list of CIDR
/// strings; `None`/empty means "the interfaces vnc-discovery deems safe".
/// The scan runs in the background; results stream via `discovery://event`
/// and completion via `discovery://scan-complete`. Never started implicitly, /// only from an explicit user action in the UI (PRD/04 consent gate). The
/// /22-size guard (`allow_large: false`) stays enforced in vnc-discovery.
///
/// # One scan at a time, and the second caller is told which one (B2)
///
/// A second `scan_network` is refused, by an error that names the scan already
/// in flight. It is never allowed to take the first scan's place: the first
/// caller has a scan on screen and no channel on which it could be told the
/// scan was taken away, so results would just stop arriving and it would read
/// as a quiet network. Two Library windows reach that today, and an agent plane
/// that can start scans reaches it far more often.
///
/// Refusing was chosen over giving each caller its own independently cancelled
/// scan because **the politeness budget is per call**:
/// `vnc_discovery::scan::scan_subnet` builds its concurrency semaphore and its
/// rate limiter inside the call (`crates/vnc-discovery/src/scan.rs`), so two
/// scans at once is twice the connections per second aimed at a network the
/// user does not necessarily own, and that cap is the whole of PRD/04 §4's
/// consent argument. Per-caller scans would need one shared budget underneath
/// them first, which is a change to vnc-discovery, not to the shell.
///
/// There is a second reason and it would be enough on its own: `scan-progress`
/// and `discovery://scan-complete` are app-wide events carrying no scan id (see
/// `IPC_CONTRACT.md`), so a window could not tell its own scan's progress from
/// another window's without a payload change and matching frontend work.
///
/// The command surface is therefore unchanged. What changed is that the refusal
/// now names the running scan (see `state::RunningScan::already_running_error`)
/// so a caller can choose between waiting for it and going to stop it, which is
/// what makes this loud rather than merely different.
#[tauri::command]
pub async fn scan_network(
    app: AppHandle,
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    subnets: Option<Vec<String>>,
) -> Result<(), String> {
    let requested = subnets.unwrap_or_default();
    let parsed: Vec<Subnet> = requested
        .iter()
        .map(|s| parse_subnet(s))
        .collect::<Result<_, _>>()?;

    // Parse first, claim second: a caller who asked for a malformed CIDR must
    // get the parse error, not a complaint about somebody else's scan.
    let (scan_id, cancel) =
        state
            .discovery
            .begin_scan(window.label(), &requested, Instant::now())?;

    refresh_local_network();
    let (tx, rx) = tokio::sync::mpsc::channel::<DiscoveryEvent>(256);
    forward_events(app.clone(), rx);

    // Reading a name off MSRPC/RDP is what puts a name to a hardened Windows
    // box, but it opens connections to ports unrelated to VNC. Operator's call.
    let probe_other_services = state
        .store
        .get_setting("probe_other_services")
        .ok()
        .flatten()
        .map(|v| v != "false")
        .unwrap_or(true);

    // One extra connection per address, to 3389. Read the same way as the
    // setting above and on by default for the same reason: without it an RDP
    // only machine is invisible to the scan. It takes the same politeness
    // permit as every RFB probe, so the cap stays a cap on the total.
    let probe_rdp = state
        .store
        .get_setting("probe_rdp")
        .ok()
        .flatten()
        .map(|v| v != "false")
        .unwrap_or(true);

    let options = ScanOptions {
        probe_other_services,
        probe_rdp,
        subnets: parsed,
        ..ScanOptions::default()
    };
    let discovery_state = state.discovery.clone();
    tauri::async_runtime::spawn(async move {
        let result = Discovery::new().scan_subnet(options, tx, cancel).await;
        // By id, so a scan that finishes late cannot release a claim that is no
        // longer its own, see `DiscoveryState::finish_scan`.
        discovery_state.finish_scan(scan_id);
        let error = result.err().map(|e| e.to_string());
        if let Some(e) = &error {
            tracing::warn!("subnet scan failed: {e}");
        }
        let _ = app.emit("discovery://scan-complete", error);
    });
    Ok(())
}

/// Second-phase probe of a single host, dispatched on what speaks there.
///
/// For VNC: complete the RFB version handshake and read the offered
/// security-type list, closing before authenticating (PRD/04 §5). Returns
/// `{ "protocol": "vnc", "securityTypes": [u8...] }`.
///
/// For RDP: a second X.224 negotiation advertising `PROTOCOL_SSL` alone,
/// which is the only way to learn whether NLA is *required* rather than
/// merely available. Returns `{ "protocol": "rdp", "rdp": { … } }` with
/// `nlaRequired` filled in.
///
/// `protocol` is passed by the caller, never inferred from the port. A port
/// number says nothing about what is behind it, and sending an RFB handshake
/// at something else is exactly the mistake the connect path refuses to make.
/// Absent means VNC, which is what every existing caller meant.
#[tauri::command]
pub async fn deep_probe(
    address: String,
    port: u16,
    protocol: Option<vnc_discovery::ProtocolKind>,
) -> Result<serde_json::Value, String> {
    // Resolve hostnames; prefer the first result.
    let addr: SocketAddr = tokio::net::lookup_host((address.as_str(), port))
        .await
        .map_err(|e| format!("could not resolve {address}: {e}"))?
        .next()
        .ok_or_else(|| format!("could not resolve {address}"))?;
    match protocol.unwrap_or_default() {
        vnc_discovery::ProtocolKind::Rdp => {
            let caps = Discovery::rdp_deep_probe(addr)
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::json!({ "protocol": "rdp", "rdp": caps }))
        }
        _ => {
            let security_types = Discovery::deep_probe(addr)
                .await
                .map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "protocol": "vnc",
                "securityTypes": security_types,
            }))
        }
    }
}

/// CIDR strings of local subnets eligible for scanning, so the UI can show
/// the consent gate ("Scan 192.168.1.0/24?"). VPN/tunnel interfaces are
/// excluded.
#[tauri::command]
pub async fn local_subnets() -> Result<Vec<String>, String> {
    // Interface enumeration is synchronous (netdev).
    let subnets = tokio::task::spawn_blocking(|| vnc_discovery::local_subnets(false))
        .await
        .map_err(|e| e.to_string())?;
    Ok(subnets
        .into_iter()
        .map(|s| format!("{}/{}", s.network, s.prefix))
        .collect())
}

/// Send Wake-on-LAN magic packets to a saved host (PRD/04 §8): broadcast on
/// the stored/derived broadcast address plus unicast to the last known IP.
#[tauri::command]
pub async fn wake_host(state: State<'_, AppState>, profile_id: String) -> Result<(), String> {
    let store = state.store.clone();
    let pid = profile_id.clone();
    let profile = super::blocking(move || store.get_host(&pid))
        .await?
        .ok_or_else(|| format!("unknown host profile: {profile_id}"))?;

    let mac = profile.wol_mac.ok_or_else(|| {
        "no MAC address stored for this host, connect to it once so the MAC can be captured"
            .to_string()
    })?;
    let broadcast: Option<Ipv4Addr> = profile
        .wol_broadcast
        .as_deref()
        .and_then(|b| b.parse().ok());
    let last_known_ip: Option<Ipv4Addr> = profile.address.parse().ok();
    vnc_discovery::wake_on_lan(&mac, broadcast, last_known_ip)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use vnc_discovery::NameSource;

    /// The single event a sighting was expected to produce.
    fn only(events: Vec<DiscoveryEvent>) -> DiscoveryEvent {
        match <[DiscoveryEvent; 1]>::try_from(events) {
            Ok([event]) => event,
            Err(other) => panic!("expected exactly one event, got {other:?}"),
        }
    }

    fn host(label: &str, security_types: Vec<u8>) -> DiscoveredHost {
        let mut h = DiscoveredHost::new(
            "192.168.1.5".parse::<IpAddr>().unwrap(),
            5900,
            DiscoverySource::Mdns,
            label.to_string(),
        );
        h.security_types = security_types;
        h
    }

    #[test]
    fn found_event_matches_the_ui_contract() {
        let payload = event_json(&DiscoveryEvent::Found(host(
            "macOS Screen Sharing",
            vec![30],
        )));
        assert_eq!(payload["type"], "found");
        let h = &payload["host"];
        assert_eq!(h["id"], "192.168.1.5:5900");
        assert_eq!(h["address"], "192.168.1.5");
        assert_eq!(h["port"], 5900);
        // no hostname -> name falls back to the address
        assert_eq!(h["name"], "192.168.1.5");
        assert_eq!(h["osHint"], "macos");
        assert_eq!(h["source"], "mdns");
        assert_eq!(h["securityHint"], "Apple auth");
        assert_eq!(h["security"], "unverified");
        assert!(h["savedHostId"].is_null());
    }

    #[test]
    fn lost_id_matches_the_found_id() {
        let h = host("VNC", vec![]);
        let found = event_json(&DiscoveryEvent::Found(h.clone()));
        let lost = event_json(&DiscoveryEvent::Lost {
            address: h.address,
            port: h.port,
        });
        assert_eq!(lost["type"], "lost");
        assert_eq!(lost["id"], found["host"]["id"]);
    }

    #[test]
    fn scan_events_are_renamed_for_the_ui() {
        let progress = event_json(&DiscoveryEvent::ScanProgress {
            scanned: 7,
            total: 254,
        });
        assert_eq!(progress["type"], "scan-progress");
        assert_eq!(
            progress["done"], 7,
            "Rust's `scanned` is `done` on the wire"
        );
        assert_eq!(progress["total"], 254);

        let complete = event_json(&DiscoveryEvent::ScanComplete { found: 3 });
        assert_eq!(complete["type"], "scan-complete");
        assert_eq!(complete["found"], 3);
    }

    #[test]
    fn unprobed_host_is_unknown_not_optimistically_secure() {
        assert_eq!(security_level(&[]), "unknown");
        assert_eq!(security_level(&[1]), "unencrypted");
        assert_eq!(security_level(&[2]), "unencrypted");
        assert_eq!(security_level(&[19]), "unverified");
    }

    /// The shell's end of the fix: two sources reporting the same server must
    /// produce one id, and that row must keep the friendly mDNS name.
    #[test]
    fn mdns_and_scan_hits_on_one_server_produce_one_row() {
        let mut reg = HostRegistry::new(LocalNetwork::empty());

        let mut from_mdns = DiscoveredHost::new(
            "192.168.77.126".parse().unwrap(),
            5900,
            DiscoverySource::Mdns,
            "VNC server (mDNS)".to_string(),
        );
        from_mdns.hostname = Some("Studio iMac".to_string());
        let mut from_scan = DiscoveredHost::new(
            "192.168.77.126".parse().unwrap(),
            5900,
            DiscoverySource::Scan,
            "macOS Screen Sharing".to_string(),
        );
        from_scan.rfb_version = Some("RFB 003.889".to_string());

        let first = only(reg.observe_event(DiscoveryEvent::Found(from_mdns)));
        let second = only(reg.observe_event(DiscoveryEvent::Found(from_scan)));

        let a = event_json(&first);
        let b = event_json(&second);
        assert_eq!(a["type"], "found");
        assert_eq!(b["type"], "updated", "not a second `found`");
        assert_eq!(a["host"]["id"], b["host"]["id"], "one id, one tile");
        assert_eq!(b["host"]["name"], "Studio iMac");
        assert_eq!(b["host"]["source"], "mdns");
        assert_eq!(b["host"]["serverHint"], "macOS Screen Sharing");
        assert_eq!(reg.len(), 1);
    }

    /// The reported bug at the IPC layer: a Windows box found by the scan is
    /// emitted as a bare address, and the NetBIOS name that arrives ~0.5 s
    /// later must land on **the same tile**, same id, no second `found`, and
    /// bring its MAC with it for Wake-on-LAN.
    #[test]
    fn a_late_resolved_name_updates_the_row_it_belongs_to() {
        let mut reg = HostRegistry::new(LocalNetwork::empty());
        let addr = "192.168.77.126".parse::<IpAddr>().unwrap();

        let mut scanned = DiscoveredHost::new(
            addr,
            5900,
            DiscoverySource::Scan,
            "VNC server (RFB 3.8)".to_string(),
        );
        scanned.rfb_version = Some("RFB 003.008".to_string());

        let first = event_json(&only(
            reg.observe_event(DiscoveryEvent::Found(scanned.clone())),
        ));
        assert_eq!(first["type"], "found");
        assert_eq!(
            first["host"]["name"], "192.168.77.126",
            "before resolution the row can only show its address"
        );
        assert!(first["host"]["mac"].is_null());

        // What vnc_discovery emits once the NetBIOS rung answers.
        let mut resolved = scanned;
        resolved.hostname = Some("DESKTOP-646U3OK".to_string());
        resolved.mac = Some("9c:53:22:6a:36:7c".to_string());
        let second = event_json(&only(reg.observe_event(DiscoveryEvent::Updated(resolved))));

        assert_eq!(second["type"], "updated", "not a second `found`");
        assert_eq!(
            second["host"]["id"], first["host"]["id"],
            "one id, one tile"
        );
        assert_eq!(second["host"]["name"], "DESKTOP-646U3OK");
        assert_eq!(second["host"]["mac"], "9c:53:22:6a:36:7c");
        assert_eq!(reg.len(), 1, "resolution must never add a row");
    }

    /// …and the mDNS name still wins, because it is the friendly one: a Mac
    /// named "Studio iMac" must not be relabelled "studio-imac" by a reverse
    /// lookup that happens to answer too.
    #[test]
    fn a_resolved_name_never_displaces_the_mdns_name() {
        let mut reg = HostRegistry::new(LocalNetwork::empty());
        let addr = "192.168.77.126".parse::<IpAddr>().unwrap();

        let mut from_mdns = DiscoveredHost::new(
            addr,
            5900,
            DiscoverySource::Mdns,
            "VNC server (mDNS)".to_string(),
        );
        from_mdns.hostname = Some("Studio iMac".to_string());
        only(reg.observe_event(DiscoveryEvent::Found(from_mdns)));

        let mut resolved = DiscoveredHost::new(
            addr,
            5900,
            DiscoverySource::Scan,
            "macOS Screen Sharing".to_string(),
        );
        resolved.hostname = Some("studio-imac".to_string());
        resolved.mac = Some("9c:53:22:6a:36:7c".to_string());
        let ev = only(reg.observe_event(DiscoveryEvent::Updated(resolved)));
        let host = &event_json(&ev)["host"];
        assert_eq!(host["name"], "Studio iMac", "the friendly name survives");
        assert_eq!(host["mac"], "9c:53:22:6a:36:7c", "but the MAC is kept");
        assert_eq!(reg.len(), 1);
    }

    /// Nothing that is this machine may reach the webview.
    #[test]
    fn this_machine_is_never_emitted() {
        let mut reg = HostRegistry::new(LocalNetwork::from_parts(
            ["192.168.77.135".parse::<IpAddr>().unwrap()],
            [],
        ));
        for addr in ["127.0.0.1", "::1", "fe80::1", "192.168.77.135", "0.0.0.0"] {
            let h = DiscoveredHost::new(
                addr.parse().unwrap(),
                5900,
                DiscoverySource::Mdns,
                "VNC server (mDNS)".to_string(),
            );
            assert!(
                reg.observe_event(DiscoveryEvent::Found(h)).is_empty(),
                "{addr} must not be emitted"
            );
        }
        assert!(reg.is_empty());
    }

    #[test]
    fn os_hint_falls_back_to_unknown() {
        assert_eq!(os_hint(&host("QEMU built-in VNC", vec![])), "qemu");
        assert_eq!(os_hint(&host("TightVNC", vec![])), "windows");
        assert_eq!(os_hint(&host("something else", vec![])), "unknown");
    }

    /// The three Windows-only rungs are proof, and proof beats the banner: a
    /// Windows box running TigerVNC advertises a label that reads Linux, and
    /// used to be mislabelled because of it.
    #[test]
    fn a_windows_only_name_service_settles_the_os() {
        for source in [NameSource::NetBios, NameSource::MsrpcEndpoint] {
            let mut h = host("TigerVNC", vec![]);
            h.hostname = Some("DESKTOP-TFBL07A".to_string());
            h.name_source = Some(source);
            assert_eq!(
                os_hint(&h),
                "windows",
                "{} can only be answered by Windows",
                source.as_str()
            );
            assert_eq!(host_json(&h)["nameSource"], source.as_str());
        }
    }

    /// …and the rungs that are *not* proof must not pretend to be. Avahi
    /// answers reverse mDNS on Linux, this LAN's `raspberrypi` is named
    /// exactly that way, so `mdns-ptr` may never imply macOS.
    ///
    /// `rdp-cert` is in this list and it used to be in the one above. Answering
    /// on 3389 with a TLS certificate is not proof of Windows: xrdp serves
    /// exactly that on Linux, and so do several thin client appliances. The
    /// certificate's CN is a good name and it is not evidence of an OS, so this
    /// rung under-claims rather than labelling every xrdp box Windows.
    #[test]
    fn a_shared_name_service_proves_nothing_about_the_os() {
        for source in [
            NameSource::MdnsPtr,
            NameSource::Llmnr,
            NameSource::ReverseDns,
            NameSource::RdpCertificate,
        ] {
            let mut h = host("VNC server (RFB 3.8)", vec![]);
            h.hostname = Some("raspberrypi".to_string());
            h.name_source = Some(source);
            assert_eq!(
                os_hint(&h),
                "unknown",
                "{} is not evidence of any OS",
                source.as_str()
            );
        }

        // The substring fallback is untouched by all of this.
        let mut tiger = host("TigerVNC", vec![]);
        tiger.name_source = Some(NameSource::MdnsPtr);
        assert_eq!(os_hint(&tiger), "linux");
    }

    /// A name resolved off the ladder is provenance the UI can see; a name that
    /// came from the mDNS browse is not, and must not claim to be.
    #[test]
    fn name_source_is_null_when_the_name_did_not_come_from_the_ladder() {
        let mut h = host("VNC server (mDNS)", vec![]);
        h.hostname = Some("Studio iMac".to_string());
        assert!(host_json(&h)["nameSource"].is_null());
    }

    /// The dual-homed machine at the IPC layer: `192.168.77.92` and
    /// `192.168.77.129` are one Windows box. Both are emitted as bare
    /// addresses, then NetBIOS names both, and the shell must forward a
    /// `lost` for the absorbed tile and an `updated` for the survivor, which
    /// keeps the id it already had and both adapters' MACs.
    #[test]
    fn a_late_name_collapses_two_tiles_into_one() {
        let mut reg = HostRegistry::new(LocalNetwork::empty());
        let scanned = |addr: &str| {
            let mut h = DiscoveredHost::new(
                addr.parse().unwrap(),
                5900,
                DiscoverySource::Scan,
                "VNC server (RFB 3.8)".to_string(),
            );
            h.rfb_version = Some("RFB 003.008".to_string());
            h
        };
        let named = |addr: &str, mac: &str| {
            let mut h = scanned(addr);
            h.hostname = Some("DESKTOP-TFBL07A".to_string());
            h.name_source = Some(NameSource::NetBios);
            h.mac = Some(mac.to_string());
            h
        };

        let wired = event_json(&only(
            reg.observe_event(DiscoveryEvent::Found(scanned("192.168.77.92"))),
        ));
        let wireless = event_json(&only(
            reg.observe_event(DiscoveryEvent::Found(scanned("192.168.77.129"))),
        ));
        assert_eq!(wired["host"]["id"], "192.168.77.92:5900");
        assert_eq!(wireless["host"]["id"], "192.168.77.129:5900");

        only(reg.observe_event(DiscoveryEvent::Updated(named(
            "192.168.77.92",
            "a0:d3:c1:0f:81:e4",
        ))));
        let events: Vec<serde_json::Value> = reg
            .observe_event(DiscoveryEvent::Updated(named(
                "192.168.77.129",
                "d0:37:45:af:7a:61",
            )))
            .iter()
            .map(event_json)
            .collect();

        assert_eq!(events.len(), 2, "one row goes, one row changes: {events:?}");
        assert_eq!(events[0]["type"], "lost");
        assert_eq!(
            events[0]["id"], wireless["host"]["id"],
            "the absorbed tile is removed by the id the UI holds"
        );
        assert_eq!(events[1]["type"], "updated");
        let host = &events[1]["host"];
        assert_eq!(
            host["id"], wired["host"]["id"],
            "the surviving tile keeps its id, no delete-and-re-add flicker"
        );
        assert_eq!(host["name"], "DESKTOP-TFBL07A");
        assert_eq!(host["osHint"], "windows");
        assert_eq!(host["nameSource"], "netbios");
        assert_eq!(host["mac"], "a0:d3:c1:0f:81:e4");
        assert_eq!(
            host["alternateMacs"],
            serde_json::json!(["d0:37:45:af:7a:61"]),
            "Wake-on-LAN may need either adapter"
        );
        assert_eq!(reg.len(), 1, "one machine, one tile");
    }
}
