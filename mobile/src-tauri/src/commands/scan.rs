//! `scan_start` and `scan_stop`: the radar.
//!
//! Two sources at once, both from `vnc-discovery`, the desktop's own:
//! an mDNS browse (`_rfb._tcp` and the record a Boundary computer
//! advertises) and a polite TCP sweep of the phone's own subnet on 5900 and
//! 5901 for VNC, 3389 for Remote Desktop and 5940 for Boundary.

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vnc_discovery::{DiscoveredHost, Discovery, DiscoveryEvent, ProtocolKind, ScanOptions};

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

/// A guess at the operating system, for the card's artwork.
///
/// The desktop's `os_hint` in `src-tauri/src/commands/discovery.rs` is a
/// private function of a Tauri command module, so its rule is restated here
/// rather than shared: a name from a Windows only service settles it, then a
/// sniff over the banner and host name. Two phone specific additions: an RDP
/// row is Windows, and a Raspberry Pi gets its own artwork.
pub fn os_hint(host: &DiscoveredHost) -> HostOs {
    if host.name_source.is_some_and(|s| s.implies_windows()) {
        return HostOs::Windows;
    }
    let mut hay = host.server_label.to_ascii_lowercase();
    if let Some(name) = &host.hostname {
        hay.push(' ');
        hay.push_str(&name.to_ascii_lowercase());
    }
    if hay.contains("raspberry") || hay.contains("wayvnc") {
        HostOs::Raspberry
    } else if hay.contains("macos") || hay.contains("apple") || hay.contains("screen sharing") {
        HostOs::Mac
    } else if host.protocol == ProtocolKind::Rdp
        || hay.contains("windows")
        || hay.contains("tightvnc")
        || hay.contains("ultravnc")
    {
        HostOs::Windows
    } else if hay.contains("tigervnc") || hay.contains("vino") || hay.contains("x11") {
        HostOs::Linux
    } else {
        HostOs::Unknown
    }
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
}
