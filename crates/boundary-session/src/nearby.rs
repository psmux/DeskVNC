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
//! both and checked against each other by the test below.

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// The reading half agrees on the type, and what this side publishes is
    /// what it accepts. Real multicast on this machine's interfaces: the
    /// record is browsed back with a second daemon, as a scan on another
    /// computer would.
    #[test]
    fn the_record_is_published_and_read_back() {
        assert_eq!(SERVICE_TYPE, vnc_discovery::boundary::SERVICE_TYPE);
        let id = iroh::SecretKey::generate().public();
        let Some(advert) = advertise(id, 61234, "Front Desk") else {
            eprintln!("SKIP: no multicast interface to publish on");
            return;
        };
        let browser = ServiceDaemon::new().unwrap();
        let events = browser.browse(SERVICE_TYPE).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut found = None;
        while found.is_none() && Instant::now() < deadline {
            if let Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) =
                events.recv_timeout(Duration::from_millis(200))
                && info.get_fullname() == advert.fullname
            {
                found = Some(info);
            }
        }
        let _ = browser.shutdown();
        let info = found.expect("the record was not seen within ten seconds");
        assert_eq!(info.get_port(), 61234);
        let txt_id = info.get_property_val_str("id").unwrap();
        assert_eq!(
            vnc_discovery::boundary::machine_id(txt_id),
            Some(id.to_string())
        );
        assert_eq!(
            info.get_property_val_str("name")
                .and_then(vnc_discovery::boundary::clean_name)
                .as_deref(),
            Some("Front Desk")
        );
        assert!(!info.get_addresses().is_empty());
    }
}
