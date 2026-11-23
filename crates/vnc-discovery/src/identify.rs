//! What answers at one address: the quick connect probe.
//!
//! The phone's address field takes `studio`, `10.0.0.5` or `box:5902` with no
//! protocol picker, so something has to work out what is listening there.
//! [`identify`] asks the same questions the subnet scan asks, of one address
//! only, all at once: the RFB banner on 5900 and 5901, the X.224 negotiation
//! on 3389 and the Boundary greeting on 5940, next to the name ladder of
//! [`crate::resolve`]. Every probe is one this crate already has. Nothing here
//! speaks a protocol of its own, and nothing authenticates.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use remote_core::ProtocolKind;

use crate::banner::server_label;
use crate::boundary;
use crate::probe;
use crate::resolve::{self, NameSource, Resolved};
use crate::scan::rdp_label;
use crate::types::{DiscoveredHost, DiscoverySource, RdpCaps};

/// The ports tried when the address carries none, with what each is asked.
pub const DEFAULT_PROBES: [(u16, Service); 4] = [
    (5900, Service::Vnc),
    (5901, Service::Vnc),
    (3389, Service::Rdp),
    (boundary::BOUNDARY_PORT, Service::Boundary),
];

/// Which existing probe a port gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// The 12 byte RFB banner read. Writes nothing.
    Vnc,
    /// The 19 byte X.224 negotiation, which also reads the certificate name.
    Rdp,
    /// The one line a Boundary computer sends. Writes nothing.
    Boundary,
}

/// A guess at the operating system, for a picture on a card. Never used to
/// decide what to connect to or what to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OsHint {
    Windows,
    Mac,
    Linux,
    Raspberry,
    #[default]
    Unknown,
}

/// One service that answered at the address.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identified {
    /// The address that was probed, after any name lookup.
    pub address: IpAddr,
    pub port: u16,
    pub protocol: ProtocolKind,
    /// The best name known for the machine, the same for every service.
    pub name: Option<String>,
    /// Which rung of the ladder gave [`Identified::name`].
    pub name_source: Option<NameSource>,
    /// What the service said it is, e.g. "macOS Screen Sharing".
    pub server_label: String,
    /// The machine's operating system, the same for every service.
    pub os: OsHint,
    /// What the RDP negotiation learned, for an RDP row.
    pub rdp: Option<RdpCaps>,
    /// The machine ID a Boundary computer sent.
    pub boundary_id: Option<String>,
}

/// The probe plan: every default port, or only the port that was given.
///
/// A given port could be any of the three, so it gets the two read only
/// probes first and the RDP negotiation only when neither answered: an RFB
/// server should not be sent 19 bytes it will log as a bad version.
pub fn plan(port: Option<u16>) -> Vec<Vec<(u16, Service)>> {
    match port {
        None => vec![DEFAULT_PROBES.to_vec()],
        Some(p) => vec![
            vec![(p, Service::Vnc), (p, Service::Boundary)],
            vec![(p, Service::Rdp)],
        ],
    }
}

/// Find what answers at `host`, which may be a name or an address.
///
/// The probes and the name lookups run at the same time. Each connect is held
/// to `timeout`, and so is the wait for a VNC banner or a Boundary line once
/// it connects: the subnet scan gives that read 200 ms, which x11vnc misses
/// on its own loopback. The names keep the ladder's own budget. A server that
/// answers takes as long as it takes to greet; on a LAN that is usually about
/// half a second. A name that does not resolve, or an address where
/// nothing answers, gives an empty list. The list is in a fixed order:
/// Remote Desktop, then VNC by port, then Boundary.
pub async fn identify(host: &str, port: Option<u16>, timeout: Duration) -> Vec<Identified> {
    let Some(ip) = lookup(host, timeout).await else {
        return Vec::new();
    };
    let probes = async {
        let mut rows = Vec::new();
        for wave in plan(port) {
            let found =
                futures::future::join_all(wave.into_iter().map(|(p, s)| run(ip, p, s, timeout)))
                    .await;
            rows.extend(found.into_iter().flatten());
            if !rows.is_empty() {
                break;
            }
        }
        rows
    };
    let names = async {
        match ip {
            // The ladder's own rule and budget: only the name services, no
            // extra ports. The certificate name comes from the RDP probe.
            IpAddr::V4(v4) => {
                resolve::resolve_host_with(v4, timeout.min(resolve::RESOLVE_BUDGET), false).await
            }
            IpAddr::V6(_) => Resolved::default(),
        }
    };
    let (mut rows, resolved) = tokio::join!(probes, names);
    let cert = rows
        .iter()
        .find_map(|h| h.rdp.as_ref().and_then(|c| c.cert_cn.clone()));
    let (name, source) = best_name(&resolved, cert.as_deref(), ip);
    for row in &mut rows {
        if name.is_some() {
            row.hostname = name.clone();
            row.name_source = source;
        }
    }
    let os = machine_os(rows.iter().map(os_hint));
    let mut out: Vec<Identified> = rows
        .into_iter()
        .map(|h| Identified {
            address: h.address,
            port: h.port,
            protocol: h.protocol,
            name: h.hostname,
            name_source: h.name_source,
            server_label: h.server_label,
            os,
            rdp: h.rdp,
            boundary_id: h.boundary_id,
        })
        .collect();
    sort(&mut out);
    out
}

/// The address to probe: a literal as it is, a name through the system
/// resolver, IPv4 preferred since that is what a LAN computer listens on.
async fn lookup(host: &str, timeout: Duration) -> Option<IpAddr> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    let found = tokio::time::timeout(timeout, tokio::net::lookup_host((host, 0)))
        .await
        .ok()?
        .ok()?;
    let all: Vec<IpAddr> = found.map(|a| a.ip()).collect();
    all.iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| all.first())
        .copied()
}

/// One probe, turned into a row the way the subnet scan builds one.
async fn run(ip: IpAddr, port: u16, service: Service, timeout: Duration) -> Option<DiscoveredHost> {
    let addr = SocketAddr::new(ip, port);
    match service {
        Service::Vnc => {
            let banner = probe::fingerprint_within(addr, timeout, timeout).await?;
            let mut host = DiscoveredHost::new(
                ip,
                port,
                DiscoverySource::Manual,
                server_label(banner.major, banner.minor),
            );
            host.rfb_version = Some(banner.raw);
            Some(host)
        }
        Service::Rdp => {
            let caps = probe::rdp_fingerprint(addr, timeout).await?;
            let mut host = DiscoveredHost::new(ip, port, DiscoverySource::Manual, rdp_label(&caps));
            host.protocol = ProtocolKind::Rdp;
            host.rdp = Some(caps);
            Some(host)
        }
        Service::Boundary => {
            let id = boundary::fingerprint_within(addr, timeout, timeout).await?;
            let mut host = DiscoveredHost::new(
                ip,
                port,
                DiscoverySource::Manual,
                boundary::LABEL.to_string(),
            );
            host.protocol = ProtocolKind::Boundary;
            host.boundary_id = Some(id);
            Some(host)
        }
    }
}

/// The ladder's answer first, in its own order (mDNS, reverse DNS, NetBIOS,
/// LLMNR), then the RDP certificate's subject, which is the ladder's last
/// rung and was read by the probe on the connection it already had.
pub fn best_name(
    resolved: &Resolved,
    cert_cn: Option<&str>,
    ip: IpAddr,
) -> (Option<String>, Option<NameSource>) {
    if let Some(name) = &resolved.hostname {
        return (Some(name.clone()), resolved.source);
    }
    let cert = match ip {
        IpAddr::V4(v4) => cert_cn.and_then(|cn| resolve::sanitize_hostname(cn, v4)),
        IpAddr::V6(_) => cert_cn
            .map(str::trim)
            .filter(|cn| !cn.is_empty() && cn.parse::<IpAddr>().is_err())
            .map(str::to_string),
    };
    match cert {
        Some(cn) => (Some(cn), Some(NameSource::RdpCertificate)),
        None => (None, None),
    }
}

/// A guess at the operating system from one row's evidence.
///
/// A name from a Windows only service settles it, then a certificate name
/// shaped like a Windows computer name, then a sniff over the banner label
/// and the host name. An RDP row with nothing else to go on reads as
/// Windows, since that is what nearly every RDP server is.
pub fn os_hint(host: &DiscoveredHost) -> OsHint {
    if host.implies_windows() {
        return OsHint::Windows;
    }
    let mut hay = host.server_label.to_ascii_lowercase();
    if let Some(name) = &host.hostname {
        hay.push(' ');
        hay.push_str(&name.to_ascii_lowercase());
    }
    if hay.contains("raspberry") || hay.contains("wayvnc") {
        OsHint::Raspberry
    } else if hay.contains("macos") || hay.contains("apple") || hay.contains("screen sharing") {
        OsHint::Mac
    } else if host.protocol == ProtocolKind::Rdp
        || hay.contains("windows")
        || hay.contains("tightvnc")
        || hay.contains("ultravnc")
    {
        OsHint::Windows
    } else if hay.contains("tigervnc") || hay.contains("vino") || hay.contains("x11") {
        OsHint::Linux
    } else {
        OsHint::Unknown
    }
}

/// One answer for the whole machine from what each service suggested.
///
/// A Mac banner and a Pi name are specific, so they win; Windows next, since
/// an RDP server is the next best evidence; Linux, a guess from a VNC
/// server's name, last.
pub fn machine_os(hints: impl IntoIterator<Item = OsHint>) -> OsHint {
    let rank = |os: OsHint| match os {
        OsHint::Mac => 0,
        OsHint::Raspberry => 1,
        OsHint::Windows => 2,
        OsHint::Linux => 3,
        OsHint::Unknown => 4,
    };
    hints
        .into_iter()
        .min_by_key(|os| rank(*os))
        .unwrap_or(OsHint::Unknown)
}

/// Remote Desktop, then VNC, then Boundary, each by port.
pub fn sort(rows: &mut [Identified]) {
    let rank = |p: ProtocolKind| match p {
        ProtocolKind::Rdp => 0,
        ProtocolKind::Vnc => 1,
        ProtocolKind::Boundary => 2,
        _ => 3,
    };
    rows.sort_by_key(|r| (rank(r.protocol), r.port));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    fn row(protocol: ProtocolKind, port: u16, label: &str) -> DiscoveredHost {
        let mut h = DiscoveredHost::new(IP, port, DiscoverySource::Manual, label.into());
        h.protocol = protocol;
        h
    }

    #[test]
    fn no_port_means_every_default_port_in_one_wave() {
        let waves = plan(None);
        assert_eq!(waves.len(), 1);
        let ports: Vec<u16> = waves[0].iter().map(|(p, _)| *p).collect();
        assert_eq!(ports, vec![5900, 5901, 3389, 5940]);
        assert_eq!(waves[0][2].1, Service::Rdp);
        assert_eq!(waves[0][3].1, Service::Boundary);
    }

    #[test]
    fn a_given_port_is_read_first_and_negotiated_only_after() {
        let waves = plan(Some(5902));
        assert_eq!(
            waves,
            vec![
                vec![(5902, Service::Vnc), (5902, Service::Boundary)],
                vec![(5902, Service::Rdp)],
            ]
        );
    }

    #[test]
    fn the_ladder_name_wins_over_the_certificate() {
        let resolved = Resolved {
            hostname: Some("studio".into()),
            source: Some(NameSource::NetBios),
            mac: None,
        };
        assert_eq!(
            best_name(&resolved, Some("STUDIO-PC"), IP),
            (Some("studio".into()), Some(NameSource::NetBios))
        );
    }

    #[test]
    fn the_certificate_names_a_machine_the_ladder_could_not() {
        assert_eq!(
            best_name(&Resolved::default(), Some("STUDIO-PC"), IP),
            (Some("STUDIO-PC".into()), Some(NameSource::RdpCertificate))
        );
        // A certificate that only repeats the address is no name.
        assert_eq!(
            best_name(&Resolved::default(), Some("192.0.2.7"), IP),
            (None, None)
        );
        assert_eq!(best_name(&Resolved::default(), None, IP), (None, None));
    }

    #[test]
    fn each_row_suggests_an_os() {
        assert_eq!(
            os_hint(&row(ProtocolKind::Rdp, 3389, "Remote Desktop")),
            OsHint::Windows
        );
        assert_eq!(
            os_hint(&row(ProtocolKind::Vnc, 5900, "macOS Screen Sharing")),
            OsHint::Mac
        );
        assert_eq!(
            os_hint(&row(ProtocolKind::Vnc, 5900, "VNC server (RFB 3.8)")),
            OsHint::Unknown
        );
        assert_eq!(
            os_hint(&row(ProtocolKind::Boundary, 5940, boundary::LABEL)),
            OsHint::Unknown
        );
        let mut pi = row(ProtocolKind::Vnc, 5900, "VNC server (RFB 3.8)");
        pi.hostname = Some("raspberrypi".into());
        assert_eq!(os_hint(&pi), OsHint::Raspberry);
        let mut nb = row(ProtocolKind::Vnc, 5900, "VNC server (RFB 3.8)");
        nb.hostname = Some("DESK".into());
        nb.name_source = Some(NameSource::NetBios);
        assert_eq!(os_hint(&nb), OsHint::Windows);
    }

    #[test]
    fn the_machine_takes_the_most_specific_hint() {
        // A Mac with Screen Sharing and Boundary.
        assert_eq!(machine_os([OsHint::Mac, OsHint::Unknown]), OsHint::Mac);
        // A Windows PC with Remote Desktop and a VNC server that says nothing.
        assert_eq!(
            machine_os([OsHint::Unknown, OsHint::Windows]),
            OsHint::Windows
        );
        assert_eq!(
            machine_os([OsHint::Linux, OsHint::Windows]),
            OsHint::Windows
        );
        assert_eq!(machine_os([]), OsHint::Unknown);
    }

    #[test]
    fn rows_come_back_rdp_then_vnc_then_boundary() {
        let id = |protocol, port| Identified {
            address: IP,
            port,
            protocol,
            name: None,
            name_source: None,
            server_label: String::new(),
            os: OsHint::Unknown,
            rdp: None,
            boundary_id: None,
        };
        let mut rows = vec![
            id(ProtocolKind::Boundary, 5940),
            id(ProtocolKind::Vnc, 5901),
            id(ProtocolKind::Rdp, 3389),
            id(ProtocolKind::Vnc, 5900),
        ];
        sort(&mut rows);
        let order: Vec<u16> = rows.iter().map(|r| r.port).collect();
        assert_eq!(order, vec![3389, 5900, 5901, 5940]);
    }

    #[test]
    fn the_wire_shape_is_camel_case() {
        let json = serde_json::to_value(Identified {
            address: IP,
            port: 5940,
            protocol: ProtocolKind::Boundary,
            name: Some("studio".into()),
            name_source: Some(NameSource::MdnsPtr),
            server_label: boundary::LABEL.into(),
            os: OsHint::Mac,
            rdp: None,
            boundary_id: Some("ab".into()),
        })
        .unwrap();
        assert_eq!(json["os"], "mac");
        assert_eq!(json["serverLabel"], boundary::LABEL);
        assert_eq!(json["boundaryId"], "ab");
        assert_eq!(json["nameSource"], "mdns-ptr");
    }

    /// A server that writes `line` to every connection and holds it open.
    async fn speaker(line: &'static [u8]) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = sock.write_all(line).await;
                    let mut sink = [0u8; 64];
                    let _ = tokio::time::timeout(Duration::from_millis(500), sock.read(&mut sink))
                        .await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn a_vnc_server_on_a_given_port_is_found() {
        let port = speaker(b"RFB 003.889\n").await;
        let rows = identify("127.0.0.1", Some(port), Duration::from_millis(400)).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].protocol, ProtocolKind::Vnc);
        assert_eq!(rows[0].port, port);
        assert_eq!(rows[0].os, OsHint::Mac);
        assert_eq!(rows[0].server_label, "macOS Screen Sharing");
    }

    /// A server that waits `delay` after the accept before it writes `line`.
    /// x11vnc does this: on an idle desktop it took 400 to 530 ms to send
    /// its banner, even over loopback.
    async fn slow_speaker(line: &'static [u8], delay: Duration) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sock.write_all(line).await;
                    let mut sink = [0u8; 64];
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), sock.read(&mut sink)).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn a_vnc_server_slow_to_greet_is_still_found() {
        // `10.0.2.2:5901` in quick connect came back "Nothing answered" from
        // an x11vnc server that a `vnc://` link reached fine: the banner
        // arrived after the probe had stopped listening for it.
        let port = slow_speaker(b"RFB 003.008\n", Duration::from_millis(550)).await;
        let rows = identify("127.0.0.1", Some(port), Duration::from_millis(1500)).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].protocol, ProtocolKind::Vnc);
        assert_eq!(rows[0].port, port);
    }

    #[tokio::test]
    async fn a_boundary_computer_slow_to_greet_is_still_found() {
        const LINE: &[u8] =
            b"BOUNDARY1 3ae432ab7fd87dbd85b26c69e3d00be3f1ad47688df3e79e650ea9c8f0440723\n";
        let port = slow_speaker(LINE, Duration::from_millis(550)).await;
        let rows = identify("127.0.0.1", Some(port), Duration::from_millis(1500)).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].protocol, ProtocolKind::Boundary);
    }

    #[tokio::test]
    async fn a_boundary_computer_on_a_given_port_is_found() {
        const LINE: &[u8] =
            b"BOUNDARY1 3ae432ab7fd87dbd85b26c69e3d00be3f1ad47688df3e79e650ea9c8f0440723\n";
        let port = speaker(LINE).await;
        let rows = identify("127.0.0.1", Some(port), Duration::from_millis(400)).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].protocol, ProtocolKind::Boundary);
        assert_eq!(rows[0].boundary_id.as_deref().map(str::len), Some(64));
    }

    #[tokio::test]
    async fn nothing_listening_gives_nothing() {
        // Bind and drop, so the port is very likely closed.
        let port = {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            l.local_addr().unwrap().port()
        };
        let rows = identify("127.0.0.1", Some(port), Duration::from_millis(300)).await;
        assert!(rows.is_empty(), "{rows:?}");
        assert!(identify("", None, Duration::from_millis(100))
            .await
            .is_empty());
    }
}
