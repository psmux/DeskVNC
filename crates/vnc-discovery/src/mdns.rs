//! Continuous mDNS / DNS-SD browsing.

use crate::boundary;
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

/// What one browse is for: which service type it emits rows for, or none.
#[derive(Clone)]
enum Browse {
    /// `_rfb._tcp`: a VNC row per instance.
    Vnc(Arc<LocalNetwork>),
    /// [`boundary::SERVICE_TYPE`]: a Boundary row per instance.
    Boundary(Arc<LocalNetwork>),
    /// The auxiliary types: logged, never listed.
    LogOnly,
}

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

        // Primary: _rfb._tcp, and the record an unattended Boundary machine
        // publishes, emit real Found events.
        for (ty, browse) in [
            (RFB_TYPE, Browse::Vnc(local.clone())),
            (boundary::SERVICE_TYPE, Browse::Boundary(local.clone())),
        ] {
            match daemon.browse(ty) {
                Ok(rx) => {
                    let tx = tx.clone();
                    let cancel = cancel.clone();
                    handles.push(tokio::task::spawn_blocking(move || {
                        pump(rx, tx, cancel, browse);
                    }));
                }
                Err(e) => {
                    let _ = tx
                        .send(DiscoveryEvent::Error(format!("browse {ty} failed: {e}")))
                        .await;
                }
            }
        }

        // Auxiliary types: log only, do not emit Found.
        for ty in AUX_TYPES {
            match daemon.browse(ty) {
                Ok(rx) => {
                    let tx = tx.clone();
                    let cancel = cancel.clone();
                    handles.push(tokio::task::spawn_blocking(move || {
                        pump(rx, tx, cancel, Browse::LogOnly);
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
fn pump(
    rx: mdns_sd::Receiver<ServiceEvent>,
    tx: Sender<DiscoveryEvent>,
    cancel: CancellationToken,
    browse: Browse,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        match rx.recv_timeout(RECV_TICK) {
            Ok(event) => handle_event(event, &tx, &browse),
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
fn handle_event(event: ServiceEvent, tx: &Sender<DiscoveryEvent>, browse: &Browse) {
    match event {
        ServiceEvent::ServiceResolved(info) => {
            let host = match browse {
                Browse::Vnc(local) => host_from_info(&info, local),
                Browse::Boundary(local) => boundary_from_info(&info, local),
                Browse::LogOnly => {
                    tracing::debug!(
                        service = %info.ty_domain,
                        instance = info.get_fullname(),
                        "aux mDNS resolved (log only)"
                    );
                    return;
                }
            };
            if let Some(host) = host {
                let _ = tx.blocking_send(DiscoveryEvent::Found(host));
            }
        }
        ServiceEvent::ServiceRemoved(_ty, fullname) => {
            if matches!(browse, Browse::LogOnly) {
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

/// Build one Boundary row from the record an unattended machine publishes.
///
/// The TXT record carries `id` (the machine ID, which a connection pins) and
/// `name` (what the machine calls itself). A record without a well formed ID
/// is dropped: the service type is short enough that something else could
/// one day use it, and a row that cannot be dialled by key is no use. The
/// port is the machine's real one, which is the point of the record: a
/// machine that could not have 5940 is still found, and still dialled.
fn boundary_from_info(info: &ResolvedService, local: &LocalNetwork) -> Option<DiscoveredHost> {
    let id = info
        .get_property_val_str("id")
        .and_then(boundary::machine_id)?;
    let addrs = filter::rank_addresses(info.addresses.iter().map(|a| a.to_ip_addr()), local);
    let Some((best, alternates)) = addrs.split_first() else {
        tracing::debug!(
            instance = %info.fullname,
            "Boundary record has no usable address (own machine / link-local only)"
        );
        return None;
    };
    let mut host = DiscoveredHost::new(
        *best,
        info.port,
        DiscoverySource::Mdns,
        boundary::LABEL.to_string(),
    );
    host.protocol = remote_core::ProtocolKind::Boundary;
    host.boundary_id = Some(id);
    host.hostname = info
        .get_property_val_str("name")
        .and_then(boundary::clean_name)
        .or_else(|| instance_name(info));
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
