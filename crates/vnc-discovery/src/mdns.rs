//! Continuous mDNS / DNS-SD browsing.

use crate::filter::{self, LocalNetwork};
use crate::types::{DiscoveredHost, DiscoveryEvent, DiscoverySource};
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

/// The canonical VNC/RFB DNS-SD service type.
const RFB_TYPE: &str = "_rfb._tcp.local.";
/// Defensive extra service types, logged only (see PRD/04 §3).
const AUX_TYPES: &[&str] = &["_ard._tcp.local.", "_workstation._tcp.local."];

/// Poll interval for bridging the mdns-sd flume channel into tokio.
const RECV_TICK: Duration = Duration::from_millis(200);

/// Start a continuous mDNS browse. Events stream on `tx` until `cancel` fires.
pub fn browse_mdns(tx: Sender<DiscoveryEvent>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let daemon = match ServiceDaemon::new() {
            Ok(d) => d,
            Err(e) => {
                let _ = tx
                    .send(DiscoveryEvent::Error(format!("mDNS daemon failed: {e}")))
                    .await;
                return;
            }
        };

        let mut handles = Vec::new();

        // Snapshot this machine's own addressing once, up front: it decides
        // which advertised addresses are usable and which are just us.
        let local = Arc::new(LocalNetwork::detect());

        // Primary: _rfb._tcp emits real Found/Lost events.
        match daemon.browse(RFB_TYPE) {
            Ok(rx) => {
                let tx = tx.clone();
                let cancel = cancel.clone();
                let local = local.clone();
                handles.push(tokio::task::spawn_blocking(move || {
                    pump(rx, tx, cancel, Some(local));
                }));
            }
            Err(e) => {
                let _ = tx
                    .send(DiscoveryEvent::Error(format!(
                        "browse {RFB_TYPE} failed: {e}"
                    )))
                    .await;
            }
        }

        // Auxiliary types: log only, do not emit Found.
        for ty in AUX_TYPES {
            match daemon.browse(ty) {
                Ok(rx) => {
                    let tx = tx.clone();
                    let cancel = cancel.clone();
                    handles.push(tokio::task::spawn_blocking(move || {
                        pump(rx, tx, cancel, None);
                    }));
                }
                Err(e) => tracing::debug!(service = ty, error = %e, "aux mDNS browse failed"),
            }
        }

        // Keep the daemon alive until cancellation, then shut it down.
        cancel.cancelled().await;
        let _ = daemon.shutdown();
        for h in handles {
            let _ = h.await;
        }
    });
}

/// Blocking loop that bridges one flume receiver into the tokio channel.
///
/// `local` is `Some` for the browse that emits hosts and `None` for the
/// log-only auxiliary browses.
fn pump(
    rx: mdns_sd::Receiver<ServiceEvent>,
    tx: Sender<DiscoveryEvent>,
    cancel: CancellationToken,
    local: Option<Arc<LocalNetwork>>,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        match rx.recv_timeout(RECV_TICK) {
            Ok(event) => handle_event(event, &tx, local.as_deref()),
            Err(_) => {
                // Timeout (normal) or disconnected. Stop only on disconnect.
                if rx.is_disconnected() {
                    return;
                }
            }
        }
    }
}

/// Translate one mdns-sd event into discovery events.
fn handle_event(event: ServiceEvent, tx: &Sender<DiscoveryEvent>, local: Option<&LocalNetwork>) {
    match event {
        ServiceEvent::ServiceResolved(info) => {
            let Some(local) = local else {
                tracing::debug!(
                    service = %info.ty_domain,
                    instance = info.get_fullname(),
                    "aux mDNS resolved (log only)"
                );
                return;
            };
            if let Some(host) = host_from_info(&info, local) {
                let _ = tx.blocking_send(DiscoveryEvent::Found(host));
            }
        }
        ServiceEvent::ServiceRemoved(_ty, fullname) => {
            if local.is_none() {
                return;
            }
            // We do not have addresses at removal time; report the instance so
            // the shell can dedupe. Address is unspecified as a sentinel.
            tracing::debug!(instance = %fullname, "mDNS service removed");
            // Best-effort: emit Lost with an unspecified address is not useful,
            // so we skip emitting here, resolution-keyed removal is handled by
            // the shell via TTL. (Kept for completeness / future use.)
        }
        other => {
            tracing::trace!(?other, "mDNS event");
        }
    }
}

/// Build **one** [`DiscoveredHost`] for a resolved service instance.
///
/// A single instance normally resolves to a fistful of addresses, IPv4, global
/// IPv6, one `fe80::` per interface, sometimes loopback. Emitting one host per
/// address is what made a single Mac fill the whole Nearby list on its own. We
/// instead pick the best usable address (see [`crate::filter`]) and keep the
/// rest as alternates, so one machine is one row. `None` means the instance
/// advertised nothing we could connect to, typically because it *is* this
/// machine.
fn host_from_info(info: &ResolvedService, local: &LocalNetwork) -> Option<DiscoveredHost> {
    let port = info.port;
    // mdns-sd 0.20 reports addresses as `ScopedIp` (carrying the interface
    // scope for link-local v6) rather than bare `IpAddr`.
    let addrs = filter::rank_addresses(info.addresses.iter().map(|a| a.to_ip_addr()), local);
    let Some((best, alternates)) = addrs.split_first() else {
        tracing::debug!(
            instance = %info.fullname,
            "mDNS instance has no usable address (own machine / link-local only)"
        );
        return None;
    };
    let mut host = DiscoveredHost::new(
        *best,
        port,
        DiscoverySource::Mdns,
        "VNC server (mDNS)".to_string(),
    );
    host.hostname = instance_name(info);
    host.alternate_addresses = alternates.to_vec();
    Some(host)
}

/// Extract the human instance name from the fullname by stripping the service
/// type suffix, e.g. `"iMac._rfb._tcp.local."` → `"iMac"`.
fn instance_name(info: &ResolvedService) -> Option<String> {
    let fullname = info.fullname.as_str();
    let suffix = format!(".{}", info.ty_domain);
    let name = fullname.strip_suffix(&suffix).unwrap_or(fullname).trim();
    if name.is_empty() {
        // Fall back to the resolved hostname (e.g. "imac.local.").
        let h = info.host.trim_end_matches('.');
        if h.is_empty() {
            None
        } else {
            Some(h.to_string())
        }
    } else {
        Some(name.to_string())
    }
}
