//! Telling machines on the same network that this one takes unattended
//! helpers, so DeskVNC's Scan network lists it without anyone typing an ID.
//!
//! The TCP answer in [`crate::direct`] already lets a scan find a machine on
//! port 5940. This covers the two cases it cannot: a machine that had to take
//! a random port because 5940 was in use, and one whose firewall lets the
//! QUIC port in but drops the TCP probe. The record is DNS-SD over multicast,
//! so it stays on the local link, and it is published only while the
//! unattended listener runs, which is only while the person has unattended
//! access turned on. It says what the TCP answer already says to anyone who
//! asks (the machine ID, which is public) plus the port and the computer's
//! name. Being let in is still decided here, by pairing or the unattended
//! password.
//!
//! `crates/vnc-discovery/src/boundary.rs` is the reading half. The two do
//! not share a crate, so the service type and the TXT keys are written in
//! both and checked against each other by `tests/nearby.rs`.

use iroh::EndpointId;
use mdns_sd::{ServiceDaemon, ServiceInfo};

/// The DNS-SD service type. Fifteen characters is the most RFC 6335 allows
/// for the name, which is why it is not `_deskvnc-boundary`.
pub const SERVICE_TYPE: &str = "_boundary._udp.local.";

/// A published record. Dropping it withdraws the record (the daemon sends a
/// goodbye before it shuts down), so it lives exactly as long as the
/// listener that holds it.
pub(crate) struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        // Commands run in order on the daemon's thread, so the goodbye for
        // the unregister goes out before the shutdown stops it.
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Publish this machine as `id` on `port`, called `name`. `None` when the
/// record could not be published, which costs only the scan's convenience:
/// the machine is still reachable by ID and, on 5940, by address.
pub(crate) fn advertise(id: EndpointId, port: u16, name: &str) -> Option<Advertisement> {
    let id = id.to_string();
    // The instance and host labels are the ID's first characters rather than
    // the computer's name: they must be unique on the link, and a host label
    // that matched the computer's own (`Studio-iMac.local`) would fight the
    // operating system's responder for it. The name travels in the TXT
    // record, where only a reader that looks for it shows it.
    let label = format!("boundary-{}", &id[..16]);
    let host = format!("{label}.local.");
    let properties = [("v", "1"), ("id", id.as_str()), ("name", name)];
    let info = ServiceInfo::new(SERVICE_TYPE, &label, &host, "", port, &properties[..])
        .ok()?
        .enable_addr_auto();
    let fullname = info.get_fullname().to_string();
    let daemon = ServiceDaemon::new().ok()?;
    if daemon.register(info).is_err() {
        let _ = daemon.shutdown();
        return None;
    }
    Some(Advertisement { daemon, fullname })
}

/// What to call this computer: what a helper sees when saving it, and what
/// the scan shows beside its address.
pub fn computer_name() -> String {
    let name = if cfg!(target_os = "macos") {
        std::process::Command::new("scutil")
            .args(["--get", "ComputerName"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else if cfg!(windows) {
        std::env::var("COMPUTERNAME").ok()
    } else {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
    };
    name.filter(|n| !n.is_empty() && n.len() <= 80)
        .unwrap_or_else(|| "This computer".into())
}
