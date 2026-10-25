//! Run the Scan network pipeline from the command line and print what it
//! finds, for checking discovery against real machines.
//!
//! ```sh
//! # The local subnets, and the mDNS browse, for ten seconds
//! cargo run -p vnc-discovery --example scan
//! # One address or range, also listing this machine (which the app hides)
//! cargo run -p vnc-discovery --example scan -- 10.42.0.9/32 --include-local
//! ```
//!
//! Every event is printed as it arrives, before the de-duplication the app
//! applies, so a sighting of this machine is visible here even though the
//! Nearby list would drop it. Each line says which source saw it.

use std::time::Duration;
use tokio_util::sync::CancellationToken;
use vnc_discovery::{Discovery, DiscoveryEvent, ProtocolKind, ScanOptions, Subnet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let include_local = args.iter().any(|a| a == "--include-local");
    let subnets: Vec<Subnet> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(|a| {
            let (ip, prefix) = a.split_once('/').unwrap_or((a, "32"));
            Subnet::new(
                ip.parse().expect("an IPv4 address"),
                prefix.parse().expect("a prefix"),
            )
        })
        .collect();

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let cancel = CancellationToken::new();
    Discovery::new().browse_mdns(tx.clone(), cancel.clone());
    // The browse's own-machine filter drops this machine's records; print
    // them anyway when asked, straight off the wire.
    if include_local {
        raw_boundary_browse(cancel.clone());
    }
    let opts = ScanOptions {
        subnets,
        include_local,
        probe_boundary: !args.iter().any(|a| a == "--no-boundary"),
        ..Default::default()
    };
    let scan_cancel = cancel.clone();
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let found = Discovery::new().scan_subnet(opts, tx, scan_cancel).await;
        println!("scan done in {:?}: {found:?}", started.elapsed());
    });
    let stop = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            event = rx.recv() => match event {
                Some(DiscoveryEvent::Found(h)) | Some(DiscoveryEvent::Updated(h)) => {
                    let what = match h.protocol {
                        ProtocolKind::Boundary => format!("boundary id={}", h.boundary_id.as_deref().unwrap_or("?")),
                        other => other.as_str().to_string(),
                    };
                    println!(
                        "{:?} {}:{} {} name={:?} label={:?}",
                        h.source, h.address, h.port, what, h.hostname, h.server_label
                    );
                }
                Some(DiscoveryEvent::Error(e)) => println!("error: {e}"),
                Some(_) => {}
                None => break,
            }
        }
    }
    cancel.cancel();
    Ok(())
}

fn raw_boundary_browse(cancel: CancellationToken) {
    std::thread::spawn(move || {
        let daemon = mdns_sd::ServiceDaemon::new().expect("mDNS daemon");
        let events = daemon
            .browse(vnc_discovery::boundary::SERVICE_TYPE)
            .expect("browse");
        while !cancel.is_cancelled() {
            if let Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) =
                events.recv_timeout(Duration::from_millis(200))
            {
                println!(
                    "mdns-raw {} port={} id={:?} name={:?} addrs={:?}",
                    info.get_fullname(),
                    info.get_port(),
                    info.get_property_val_str("id"),
                    info.get_property_val_str("name"),
                    info.get_addresses()
                );
            }
        }
        let _ = daemon.shutdown();
    });
}
