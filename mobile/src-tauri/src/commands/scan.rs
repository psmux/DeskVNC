//! `scan_start` and `scan_stop`: the radar.
//!
//! Two sources at once, both from `vnc-discovery`, the desktop's own:
//! an mDNS browse (`_rfb._tcp` and the record a Boundary computer
//! advertises) and a polite TCP sweep of the phone's own subnet on 5900 and
//! 5901 for VNC, 3389 for Remote Desktop and 5940 for Boundary.
//!
//! `identify` asks the same questions of one typed address, for the quick
//! connect field.

use std::time::Duration;

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vnc_discovery::{
    DiscoveredHost, Discovery, DiscoveryEvent, Identified, OsHint, ProtocolKind, ScanOptions,
};

use crate::state::AppState;
use crate::store::{HostOs, Protocol};

/// `FoundComputer` in `contract.ts`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoundComputer {
    pub address: String,
    pub port: u16,
    pub protocol: Protocol,
    pub name: Option<String>,
    pub os: HostOs,
}

/// `ScanEvent` in `contract.ts`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ScanEvent {
    Found { item: FoundComputer },
    Progress { done: u32, total: u32 },
    Complete,
}

/// The VNC ports swept. The first is tried on every address, the rest only
/// on addresses that answered something.
const VNC_PORTS: [u16; 2] = [5900, 5901];

/// Start a scan, replacing one already running. Returns at once; results
/// arrive on `on_event`, ending with `complete` when the sweep is done. The
/// mDNS browse keeps adding computers after that until `scan_stop`.
#[tauri::command]
pub async fn scan_start(
    state: State<'_, AppState>,
    on_event: Channel<ScanEvent>,
) -> Result<(), String> {
    let cancel = CancellationToken::new();
    if let Some(old) = state.scan.lock().replace(cancel.clone()) {
        old.cancel();
    }
    // Android drops multicast to save power unless an app holds this lock,
    // and mDNS is multicast.
    #[cfg(target_os = "android")]
    crate::android::multicast_lock(true);

    let (tx, mut rx) = mpsc::channel::<DiscoveryEvent>(256);
    let discovery = Discovery::new();
    discovery.browse_mdns(tx.clone(), cancel.clone());
    let opts = ScanOptions {
        ports: VNC_PORTS.to_vec(),
        // A phone on battery: fewer sockets at once than the desktop's 200.
        concurrency: 64,
        max_rate_per_sec: 300,
        ..ScanOptions::default()
    };
    let sweep_cancel = cancel.clone();
    let sweep_tx = tx.clone();
    tokio::spawn(async move {
        if let Err(error) = discovery
            .scan_subnet(opts, sweep_tx.clone(), sweep_cancel)
            .await
        {
            tracing::warn!(%error, "subnet scan did not run");
            // The UI still needs to hear that the sweep is over.
            let _ = sweep_tx
                .send(DiscoveryEvent::ScanComplete { found: 0 })
                .await;
        }
    });
    drop(tx);

    tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => break,
                event = rx.recv() => event,
            };
            let Some(event) = event else { break };
            let out = match event {
                // A host found again with a better name is sent again: the UI
                // keys rows by address and port.
                DiscoveryEvent::Found(host) | DiscoveryEvent::Updated(host) => match found(&host) {
                    Some(item) => ScanEvent::Found { item },
                    None => continue,
                },
                DiscoveryEvent::ScanProgress { scanned, total } => ScanEvent::Progress {
                    done: scanned,
                    total,
                },
                DiscoveryEvent::ScanComplete { .. } => ScanEvent::Complete,
                DiscoveryEvent::Error(message) => {
                    tracing::warn!(%message, "discovery");
                    continue;
                }
                _ => continue,
            };
            if on_event.send(out).is_err() {
                // The page that asked has gone.
                cancel.cancel();
                break;
            }
        }
        #[cfg(target_os = "android")]
        crate::android::multicast_lock(false);
    });
    Ok(())
}

#[tauri::command]
pub async fn scan_stop(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(cancel) = state.scan.lock().take() {
        cancel.cancel();
    }
    Ok(())
}

/// How long each probe of `identify` waits for a connect. A computer on the
/// same Wi-Fi answers in a few milliseconds; this is for one that is waking.
const IDENTIFY_TIMEOUT: Duration = Duration::from_millis(1500);

/// What answers at a typed address: every service found, as rows shaped like
/// the scan's, Remote Desktop first. Empty when nothing answered or the name
/// does not resolve. `port` limits the probes to that one port.
#[tauri::command]
pub async fn identify(address: String, port: Option<u16>) -> Result<Vec<FoundComputer>, String> {
    let address = address.trim();
    if address.is_empty() || address.len() > 255 {
        return Err("Type a name or address".into());
    }
    let port = port.filter(|p| *p != 0);
    let found = vnc_discovery::identify(address, port, IDENTIFY_TIMEOUT).await;
    Ok(found.iter().filter_map(identified).collect())
}

/// One `identify` row as the phone shows it. `None` for a protocol the phone
/// does not speak.
pub fn identified(row: &Identified) -> Option<FoundComputer> {
    let protocol = match row.protocol {
        ProtocolKind::Vnc => Protocol::Vnc,
        ProtocolKind::Rdp => Protocol::Rdp,
        ProtocolKind::Boundary => Protocol::Boundary,
        _ => return None,
    };
    // A Boundary computer is dialled by its machine ID and address, so the
    // key is pinned, the way a scan row is saved (`discoveredEndpoint`).
    let address = match (&row.boundary_id, protocol) {
        (Some(id), Protocol::Boundary) => format!("{id}@{}", row.address),
        _ => row.address.to_string(),
    };
    Some(FoundComputer {
        address,
        port: row.port,
        protocol,
        name: row.name.clone().filter(|n| !n.trim().is_empty()),
        os: host_os(row.os),
    })
}

fn host_os(os: OsHint) -> HostOs {
    match os {
        OsHint::Windows => HostOs::Windows,
        OsHint::Mac => HostOs::Mac,
        OsHint::Linux => HostOs::Linux,
        OsHint::Raspberry => HostOs::Raspberry,
        OsHint::Unknown => HostOs::Unknown,
    }
}

/// One discovered row as the phone shows it. `None` for a protocol the
/// phone does not speak.
pub fn found(host: &DiscoveredHost) -> Option<FoundComputer> {
    let protocol = match host.protocol {
        ProtocolKind::Vnc => Protocol::Vnc,
        ProtocolKind::Rdp => Protocol::Rdp,
        ProtocolKind::Boundary => Protocol::Boundary,
        _ => return None,
    };
    Some(FoundComputer {
        address: host.address.to_string(),
        port: host.port,
        protocol,
        name: host.hostname.clone().filter(|n| !n.trim().is_empty()),
        os: os_hint(host),
    })
}

/// A guess at the operating system, for the card's artwork. The rule is
/// `vnc_discovery::os_hint`, shared with `identify` so a computer found by
/// the radar and one typed in get the same picture.
pub fn os_hint(host: &DiscoveredHost) -> HostOs {
    host_os(vnc_discovery::os_hint(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(protocol: ProtocolKind, label: &str, name: Option<&str>) -> DiscoveredHost {
        let now = std::time::SystemTime::now();
        DiscoveredHost {
            address: "192.0.2.7".parse().unwrap(),
            port: protocol.default_port(),
            alternate_addresses: vec![],
            hostname: name.map(str::to_string),
            name_source: None,
            rfb_version: None,
            server_label: label.into(),
            security_types: vec![],
            source: vnc_discovery::DiscoverySource::Scan,
            mac: None,
            alternate_macs: vec![],
            first_seen: now,
            last_seen: now,
            protocol,
            rdp: None,
            boundary_id: None,
        }
    }

    #[test]
    fn rows_map_to_the_contract() {
        let f = found(&host(
            ProtocolKind::Vnc,
            "macOS Screen Sharing",
            Some("studio"),
        ))
        .unwrap();
        assert_eq!(f.os, HostOs::Mac);
        assert_eq!(f.name.as_deref(), Some("studio"));
        let json = serde_json::to_value(ScanEvent::Found { item: f }).unwrap();
        assert_eq!(json["type"], "found");
        assert_eq!(json["item"]["protocol"], "vnc");
        assert_eq!(json["item"]["address"], "192.0.2.7");
        assert_eq!(
            serde_json::to_value(ScanEvent::Progress {
                done: 3,
                total: 254
            })
            .unwrap(),
            serde_json::json!({ "type": "progress", "done": 3, "total": 254 })
        );
        assert_eq!(
            serde_json::to_value(ScanEvent::Complete).unwrap(),
            serde_json::json!({ "type": "complete" })
        );
    }

    #[test]
    fn os_guesses() {
        assert_eq!(os_hint(&host(ProtocolKind::Rdp, "", None)), HostOs::Windows);
        assert_eq!(
            os_hint(&host(ProtocolKind::Vnc, "RFB 3.8", Some("raspberrypi"))),
            HostOs::Raspberry
        );
        assert_eq!(
            os_hint(&host(ProtocolKind::Vnc, "TigerVNC", None)),
            HostOs::Linux
        );
        assert_eq!(os_hint(&host(ProtocolKind::Vnc, "", None)), HostOs::Unknown);
        assert!(found(&host(ProtocolKind::Ssh, "", None)).is_none());
    }

    #[test]
    fn an_identified_boundary_computer_keeps_its_id() {
        let row = Identified {
            address: "192.0.2.7".parse().unwrap(),
            port: 5940,
            protocol: ProtocolKind::Boundary,
            name: Some("studio".into()),
            name_source: None,
            server_label: String::new(),
            os: OsHint::Mac,
            rdp: None,
            boundary_id: Some("ab".repeat(32)),
        };
        let f = identified(&row).unwrap();
        assert_eq!(f.address, format!("{}@192.0.2.7", "ab".repeat(32)));
        assert_eq!(f.protocol, Protocol::Boundary);
        assert_eq!(f.os, HostOs::Mac);
        let vnc = identified(&Identified {
            protocol: ProtocolKind::Vnc,
            port: 5900,
            boundary_id: None,
            ..row
        })
        .unwrap();
        assert_eq!(vnc.address, "192.0.2.7");
    }
}
