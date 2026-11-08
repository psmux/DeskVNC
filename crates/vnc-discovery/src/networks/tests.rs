//! The listing is a pure function of an interface table and a route table, so
//! each OS's tables are written out here as that OS prints them.

use super::*;

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn net(s: &str) -> Subnet {
    parse_cidr(s).unwrap()
}

fn iface(name: &str, medium: Medium, addrs: &[&str]) -> InterfaceFacts {
    InterfaceFacts {
        name: name.to_string(),
        label: None,
        description: None,
        medium,
        up: true,
        bridge: false,
        ipv4: addrs
            .iter()
            .map(|a| {
                let s = parse_cidr(a).unwrap();
                let addr = a.split('/').next().unwrap().parse().unwrap();
                (addr, s.prefix)
            })
            .collect(),
    }
}

fn find<'a>(list: &'a [ScanNetwork], name: &str) -> Vec<&'a ScanNetwork> {
    list.iter().filter(|n| n.name == name).collect()
}

fn ranges(list: &[ScanNetwork]) -> Vec<(String, String)> {
    list.iter()
        .map(|n| (n.name.clone(), n.range.clone()))
        .collect()
}

// ------------------------------------------------------------------ Linux

/// A Linux workstation with Ethernet, Docker, a bridge that is down, and
/// Cloudflare WARP, whose routes live in a table of their own.
const LINUX_IP_ROUTE: &str = "\
default via 10.0.0.1 dev enp6s0 proto dhcp src 10.0.0.10 metric 100
10.0.0.0/24 dev enp6s0 proto kernel scope link src 10.0.0.10 metric 100
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1
172.18.0.0/16 dev mlbr0 proto kernel scope link src 172.18.0.1 linkdown
100.70.20.0/24 dev CloudflareWARP table 65743 proto static scope link
10.61.1.0/24 dev CloudflareWARP table 65743 proto static scope link
10.61.2.0/24 dev CloudflareWARP table 65743 proto static scope link
10.62.0.0/16 dev CloudflareWARP table 65743 proto static scope link
198.51.100.4 dev CloudflareWARP table 65743 proto static scope link
203.0.113.0/24 dev CloudflareWARP table 65743 proto static scope link
192.168.50.0/25 dev CloudflareWARP table 65743 proto static scope link
192.168.50.128/27 dev CloudflareWARP table 65743 proto static scope link
192.168.50.160/28 dev CloudflareWARP table 65743 proto static scope link
192.168.50.176 dev CloudflareWARP table 65743 proto static scope link
192.168.50.178/31 dev CloudflareWARP table 65743 proto static scope link
192.168.50.180/30 dev CloudflareWARP table 65743 proto static scope link
192.168.50.184/29 dev CloudflareWARP table 65743 proto static scope link
192.168.50.192/26 dev CloudflareWARP table 65743 proto static scope link
10.0.0.0/8 dev CloudflareWARP table 65743 proto static scope link
local 10.0.0.10 dev enp6s0 table local proto kernel scope host src 10.0.0.10
broadcast 10.0.0.255 dev enp6s0 table local proto kernel scope link src 10.0.0.10
local 100.70.20.7 dev CloudflareWARP table local proto kernel scope host src 100.70.20.7
local 127.0.0.0/8 dev lo table local proto kernel scope host src 127.0.0.1
";

fn linux_interfaces() -> Vec<InterfaceFacts> {
    let mut mlbr = iface("mlbr0", Medium::Ethernet, &["172.18.0.1/16"]);
    mlbr.bridge = true;
    mlbr.up = false;
    let mut docker = iface("docker0", Medium::Ethernet, &["172.17.0.1/16"]);
    docker.bridge = true;
    vec![
        iface("lo", Medium::Loopback, &["127.0.0.1/8"]),
        iface("enp6s0", Medium::Ethernet, &["10.0.0.10/24"]),
        docker,
        mlbr,
        iface("CloudflareWARP", Medium::Other, &["100.70.20.7/32"]),
    ]
}

#[test]
fn ip_route_parser_reads_every_table_and_skips_local_and_broadcast() {
    let routes = parse_ip_route(LINUX_IP_ROUTE);
    assert_eq!(routes[0].dest, net("0.0.0.0/0"));
    assert_eq!(routes[0].gateway, Some(ip("10.0.0.1")));
    assert_eq!(routes[0].interface, "enp6s0");
    let warp: Vec<_> = routes
        .iter()
        .filter(|r| r.interface == "CloudflareWARP")
        .collect();
    // 15 routes in table 65743; the `local` row for WARP's own address is not one.
    assert_eq!(warp.len(), 15);
    assert!(warp.iter().any(|r| r.dest == net("192.168.50.176/32")));
    assert!(!routes.iter().any(|r| r.interface == "lo"));
}

#[test]
fn linux_listing_with_warp_docker_and_ethernet() {
    let list = build_networks(&linux_interfaces(), &parse_ip_route(LINUX_IP_ROUTE));
    let shown = ranges(&list);
    assert_eq!(
        shown,
        vec![
            ("Ethernet (enp6s0)".to_string(), "10.0.0.0/24".to_string()),
            ("Cloudflare WARP".to_string(), "10.0.0.0/8".to_string()),
            ("Cloudflare WARP".to_string(), "100.70.20.0/24".to_string()),
            (
                "Cloudflare WARP".to_string(),
                "192.168.50.0/24, part".to_string()
            ),
            ("Docker (docker0)".to_string(), "172.17.0.0/16".to_string()),
        ],
        "{list:#?}"
    );
}

#[test]
fn warp_routes_are_the_reachable_ranges_and_public_ones_are_left_out() {
    let mut interfaces = linux_interfaces();
    let routes: Vec<RouteFacts> = parse_ip_route(LINUX_IP_ROUTE)
        .into_iter()
        // Without the covering /8 the /16 and the /24s show on their own.
        .filter(|r| r.dest != net("10.0.0.0/8"))
        .collect();
    interfaces.retain(|i| i.name != "docker0");
    let list = build_networks(&interfaces, &routes);
    let warp = find(&list, "Cloudflare WARP");
    let shown: Vec<&str> = warp.iter().map(|n| n.range.as_str()).collect();
    // 10.61.1.0/24 and 10.61.2.0/24 are not halves of one /23, so they stay two.
    assert_eq!(
        shown,
        vec![
            "10.61.1.0/24",
            "10.61.2.0/24",
            "10.62.0.0/16",
            "100.70.20.0/24",
            "192.168.50.0/24, part"
        ]
    );
    for n in &warp {
        assert_eq!(n.kind, NetworkKind::Warp);
        assert!(!n
            .cidrs
            .iter()
            .any(|c| c.starts_with("198.51.100.") || c.starts_with("203.0.113.")));
    }
    // The split tunnel pieces join where they can: /25 + /27 + /28 + the
    // rest, around the one excluded address 192.168.50.177.
    let part = warp.iter().find(|n| n.range.ends_with("part")).unwrap();
    assert_eq!(
        part.cidrs,
        vec![
            "192.168.50.0/25",
            "192.168.50.128/27",
            "192.168.50.160/28",
            "192.168.50.176/32",
            "192.168.50.178/31",
            "192.168.50.180/30",
            "192.168.50.184/29",
            "192.168.50.192/26",
        ]
    );
    assert_eq!(part.verdict, RangeVerdict::Scan);
    let wide = warp.iter().find(|n| n.range == "10.62.0.0/16").unwrap();
    assert_eq!(wide.verdict, RangeVerdict::Confirm);
    assert_eq!(wide.addresses, 65_534);
}

#[test]
fn a_range_larger_than_a_slash_16_is_listed_but_marked_too_large() {
    let list = build_networks(&linux_interfaces(), &parse_ip_route(LINUX_IP_ROUTE));
    let eight = list.iter().find(|n| n.range == "10.0.0.0/8").unwrap();
    assert_eq!(eight.verdict, RangeVerdict::TooLarge);
    // and everything WARP routes inside it folds into it.
    assert!(!list.iter().any(|n| n.range == "10.62.0.0/16"));
}

#[test]
fn docker_bridge_is_virtual_and_last_and_a_down_bridge_is_not_listed() {
    let list = build_networks(&linux_interfaces(), &parse_ip_route(LINUX_IP_ROUTE));
    let last = list.last().unwrap();
    assert_eq!(last.kind, NetworkKind::Virtual);
    assert_eq!(last.name, "Docker (docker0)");
    assert_eq!(last.verdict, RangeVerdict::Confirm);
    assert!(!list.iter().any(|n| n.interface == "mlbr0"));
}

#[test]
fn openvpn_tun_with_a_pushed_route() {
    let interfaces = vec![
        iface("eth0", Medium::Ethernet, &["10.0.0.10/24"]),
        iface("tun0", Medium::Tunnel, &["10.8.0.6/24"]),
    ];
    let routes = parse_ip_route(
        "default via 10.0.0.1 dev eth0\n\
         10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.10\n\
         10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.6\n\
         172.20.30.0/24 via 10.8.0.1 dev tun0\n",
    );
    let list = build_networks(&interfaces, &routes);
    assert_eq!(
        ranges(&list),
        vec![
            ("Ethernet (eth0)".to_string(), "10.0.0.0/24".to_string()),
            ("OpenVPN (tun0)".to_string(), "10.8.0.0/24".to_string()),
            ("OpenVPN (tun0)".to_string(), "172.20.30.0/24".to_string()),
        ]
    );
    assert!(list[1..].iter().all(|n| n.kind == NetworkKind::Vpn));
}

#[test]
fn a_private_range_behind_a_lan_gateway_is_routed() {
    let interfaces = vec![iface("eth0", Medium::Ethernet, &["10.0.0.10/24"])];
    let routes = parse_ip_route(
        "default via 10.0.0.1 dev eth0\n\
         10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.10\n\
         10.50.0.0/22 via 10.0.0.254 dev eth0\n\
         198.51.100.0/24 via 10.0.0.254 dev eth0\n",
    );
    let list = build_networks(&interfaces, &routes);
    assert_eq!(list.len(), 2, "{list:#?}");
    assert_eq!(list[1].kind, NetworkKind::Routed);
    assert_eq!(list[1].name, "Routed via Ethernet (eth0)");
    assert_eq!(list[1].range, "10.50.0.0/22");
    assert_eq!(list[1].addresses, 1022);
}

#[test]
fn a_bridge_carrying_the_default_route_is_the_lan() {
    let mut br = iface("br0", Medium::Ethernet, &["10.0.0.10/24"]);
    br.bridge = true;
    let routes = parse_ip_route("default via 10.0.0.1 dev br0\n10.0.0.0/24 dev br0 scope link\n");
    let list = build_networks(&[br], &routes);
    assert_eq!(list[0].kind, NetworkKind::Lan);
}

#[test]
fn proc_net_route_fallback() {
    let text =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
    if cfg!(target_endian = "little") {
        let routes = parse_proc_net_route(text);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].dest.prefix, 0);
        assert_eq!(routes[0].gateway, Some(ip("10.0.0.1")));
        assert_eq!(routes[1].dest, net("10.0.0.0/24"));
        assert_eq!(routes[1].gateway, None);
    }
}

// ------------------------------------------------------------------ macOS

const MACOS_NETSTAT: &str = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.0.0.1           UGScg                 en0
default            link#22            UCSIg               utun4
10.0.0/24          link#14            UCS                   en0      !
10.0.0.1/32        link#14            UCS                   en0      !
10.0.0.1           0:11:22:33:44:55   UHLWIir               en0   1186
10.0.0.10/32       link#14            UCS                   en0      !
10.0.0.255         ff:ff:ff:ff:ff:ff  UHLWbI                en0      !
10.8/16            10.8.0.1           UGSc                utun4
10.8.0.1           10.8.0.6           UH                  utun4
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
169.254            link#14            UCS                   en0      !
192.168.64         link#25            UC             bridge100      !
224.0.0/4          link#14            UmCS                  en0      !
255.255.255.255/32 link#14            UCS                   en0      !
";

#[test]
fn netstat_parser_reads_abbreviated_destinations() {
    let routes = parse_netstat_routes(MACOS_NETSTAT);
    let dests: Vec<String> = routes
        .iter()
        .map(|r| format!("{} {}", cidr(&r.dest), r.interface))
        .collect();
    assert!(dests.contains(&"10.0.0.0/24 en0".to_string()));
    assert!(dests.contains(&"10.8.0.0/16 utun4".to_string()));
    assert!(dests.contains(&"127.0.0.0/8 lo0".to_string()));
    assert!(dests.contains(&"192.168.64.0/24 bridge100".to_string()));
    // ARP entries are neighbours, not networks.
    assert!(!routes.iter().any(|r| r.dest == net("10.0.0.255/32")));
}

#[test]
fn macos_listing_with_wifi_a_utun_vpn_and_a_vm_bridge() {
    let mut wifi = iface("en0", Medium::Wireless, &["10.0.0.10/24"]);
    wifi.label = Some("Wi-Fi".to_string());
    let interfaces = vec![
        iface("lo0", Medium::Loopback, &["127.0.0.1/8"]),
        wifi,
        iface("utun4", Medium::Other, &["10.8.0.6/32"]),
        iface("bridge100", Medium::Ethernet, &["192.168.64.1/24"]),
    ];
    let list = build_networks(&interfaces, &parse_netstat_routes(MACOS_NETSTAT));
    assert_eq!(
        ranges(&list),
        vec![
            ("Wi-Fi".to_string(), "10.0.0.0/24".to_string()),
            ("VPN (utun4)".to_string(), "10.8.0.0/16".to_string()),
            (
                "Virtual bridge (bridge100)".to_string(),
                "192.168.64.0/24".to_string()
            ),
        ],
        "{list:#?}"
    );
    assert_eq!(list[1].kind, NetworkKind::Vpn);
    assert_eq!(list[1].verdict, RangeVerdict::Confirm);
    assert_eq!(list[2].kind, NetworkKind::Virtual);
}

// ---------------------------------------------------------------- Windows

/// `route print -4` from a Windows machine with Ethernet, WARP (whose
/// adapter has a /32 address), an OpenVPN TAP adapter and Hyper-V, printed in
/// German so "On-link" is two words.
const WINDOWS_ROUTE_PRINT: &str = "\
===========================================================================
Schnittstellenliste
 12...00 11 22 33 44 55 ......Intel(R) Ethernet Connection
 30...........................Cloudflare WARP Interface Tunnel
===========================================================================

IPv4-Routentabelle
===========================================================================
Aktive Routen:
     Netzwerkziel    Netzwerkmaske          Gateway    Schnittstelle Metrik
          0.0.0.0          0.0.0.0         10.0.0.1        10.0.0.10     25
         10.0.0.0    255.255.255.0   Auf Verbindung        10.0.0.10    281
        10.0.0.10  255.255.255.255   Auf Verbindung        10.0.0.10    281
       10.0.0.255  255.255.255.255   Auf Verbindung        10.0.0.10    281
         10.8.0.0    255.255.255.0   Auf Verbindung         10.8.0.6    257
       10.30.40.0    255.255.255.0         10.8.0.1         10.8.0.6    257
        10.62.0.0      255.255.0.0   Auf Verbindung       172.16.0.2      5
     198.51.100.1  255.255.255.255   Auf Verbindung       172.16.0.2      5
        127.0.0.0        255.0.0.0   Auf Verbindung        127.0.0.1    331
       172.16.0.2  255.255.255.255   Auf Verbindung       172.16.0.2    261
      172.29.80.0    255.255.240.0   Auf Verbindung      172.29.80.1   5256
        224.0.0.0        240.0.0.0   Auf Verbindung        10.0.0.10    281
  255.255.255.255  255.255.255.255   Auf Verbindung        10.0.0.10    281
===========================================================================
Ständige Routen:
  Netzwerkadresse          Netzmaske  Gatewayadresse  Metrik
       10.99.0.0    255.255.0.0         10.0.0.254       1
===========================================================================
";

fn windows_interfaces() -> Vec<InterfaceFacts> {
    let mut eth = iface(
        "{11111111-2222-3333-4444-555555555555}",
        Medium::Ethernet,
        &["10.0.0.10/24"],
    );
    eth.label = Some("Ethernet".to_string());
    eth.description = Some("Intel(R) Ethernet Connection".to_string());
    let mut warp = iface(
        "{22222222-2222-3333-4444-555555555555}",
        Medium::Other,
        &["172.16.0.2/32"],
    );
    warp.label = Some("CloudflareWARP".to_string());
    warp.description = Some("Cloudflare WARP Interface Tunnel".to_string());
    let mut tap = iface(
        "{33333333-2222-3333-4444-555555555555}",
        Medium::Ethernet,
        &["10.8.0.6/24"],
    );
    tap.label = Some("OpenVPN TAP-Windows6".to_string());
    tap.description = Some("TAP-Windows Adapter V9".to_string());
    let mut hv = iface(
        "{44444444-2222-3333-4444-555555555555}",
        Medium::Ethernet,
        &["172.29.80.1/20"],
    );
    hv.label = Some("vEthernet (WSL)".to_string());
    hv.description = Some("Hyper-V Virtual Ethernet Adapter".to_string());
    let lo = iface(
        "{55555555-2222-3333-4444-555555555555}",
        Medium::Loopback,
        &["127.0.0.1/8"],
    );
    vec![eth, warp, tap, hv, lo]
}

fn windows_routes() -> Vec<RouteFacts> {
    let interfaces = windows_interfaces();
    parse_route_print(WINDOWS_ROUTE_PRINT, |addr| {
        interfaces
            .iter()
            .find(|i| i.ipv4.iter().any(|(a, _)| *a == addr))
            .map(|i| i.name.clone())
    })
}

#[test]
fn route_print_parser_handles_two_word_on_link_and_skips_persistent_rows() {
    let routes = windows_routes();
    let default = routes.iter().find(|r| r.dest.prefix == 0).unwrap();
    assert_eq!(default.gateway, Some(ip("10.0.0.1")));
    let on_link = routes
        .iter()
        .find(|r| r.dest == net("10.8.0.0/24"))
        .unwrap();
    assert_eq!(on_link.gateway, None);
    let via = routes
        .iter()
        .find(|r| r.dest == net("10.30.40.0/24"))
        .unwrap();
    assert_eq!(via.gateway, Some(ip("10.8.0.1")));
    // The persistent route has no interface column and is not read.
    assert!(!routes.iter().any(|r| r.dest == net("10.99.0.0/16")));
    assert_eq!(routes.len(), 13);
}

#[test]
fn windows_listing_names_adapters_by_friendly_name() {
    let list = build_networks(&windows_interfaces(), &windows_routes());
    assert_eq!(
        ranges(&list),
        vec![
            ("Ethernet".to_string(), "10.0.0.0/24".to_string()),
            (
                "OpenVPN TAP-Windows6".to_string(),
                "10.8.0.0/24".to_string()
            ),
            (
                "OpenVPN TAP-Windows6".to_string(),
                "10.30.40.0/24".to_string()
            ),
            ("Cloudflare WARP".to_string(), "10.62.0.0/16".to_string()),
            (
                "Hyper-V (vEthernet (WSL))".to_string(),
                "172.29.80.0/20".to_string()
            ),
        ],
        "{list:#?}"
    );
    // The broadcast and own address host routes are not networks.
    assert!(!list.iter().any(|n| n.range.ends_with("/32")));
}

// ------------------------------------------------------------ CIDR limits

#[test]
fn parse_cidr_accepts_ranges_and_bare_addresses() {
    assert_eq!(parse_cidr("192.168.1.0/24").unwrap(), net("192.168.1.0/24"));
    assert_eq!(parse_cidr("  10.1.2.3/16 ").unwrap(), net("10.1.0.0/16"));
    assert_eq!(parse_cidr("10.1.2.3").unwrap().prefix, 32);
    for bad in [
        "",
        "10.1.2",
        "10.1.2.3/",
        "10.1.2.3/33",
        "10.1.2.3/+8",
        "10.1.2.3/x",
        "hello",
        "300.1.1.1/24",
    ] {
        assert!(parse_cidr(bad).is_err(), "{bad:?} parsed");
    }
}

#[test]
fn limits_scan_confirm_and_refuse() {
    assert_eq!(judge_range(&net("192.168.1.0/24")), RangeVerdict::Scan);
    assert_eq!(judge_range(&net("10.0.0.0/22")), RangeVerdict::Scan);
    assert_eq!(judge_range(&net("10.0.0.5/32")), RangeVerdict::Scan);
    assert_eq!(judge_range(&net("10.0.0.0/21")), RangeVerdict::Confirm);
    assert_eq!(judge_range(&net("172.16.0.0/16")), RangeVerdict::Confirm);
    assert_eq!(judge_range(&net("10.0.0.0/15")), RangeVerdict::TooLarge);
    assert_eq!(judge_range(&net("10.0.0.0/8")), RangeVerdict::TooLarge);
    assert_eq!(judge_range(&net("100.64.5.0/24")), RangeVerdict::Scan);
}

#[test]
fn public_and_straddling_ranges_are_refused() {
    for public in [
        "8.8.8.0/24",
        "198.51.100.0/24",
        "172.32.0.0/24",
        "192.169.0.0/24",
        "0.0.0.0/0",
        "169.254.0.0/16",
        "127.0.0.0/24",
        "224.0.0.0/24",
    ] {
        assert_eq!(judge_range(&net(public)), RangeVerdict::Public, "{public}");
    }
    // 172.0.0.0/11 holds part of 172.16.0.0/12 and a lot of public space.
    assert_eq!(judge_range(&net("172.0.0.0/11")), RangeVerdict::Public);
    // Public outranks too large, so the message is about the right thing.
    assert_eq!(judge_range(&net("8.0.0.0/8")), RangeVerdict::Public);
}

#[test]
fn several_small_ranges_that_add_up_need_confirming() {
    let small: Vec<Subnet> = (0..5)
        .map(|i| Subnet::new(Ipv4Addr::new(10, 0, i, 0), 24))
        .collect();
    assert_eq!(judge_ranges(&small[..4]), (RangeVerdict::Scan, 1016));
    assert_eq!(judge_ranges(&small), (RangeVerdict::Confirm, 1270));
    let mixed = [net("10.0.0.0/24"), net("8.8.8.0/24")];
    assert_eq!(judge_ranges(&mixed).0, RangeVerdict::Public);
}
