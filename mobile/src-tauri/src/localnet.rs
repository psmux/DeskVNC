//! Android 17's local network permission.
//!
//! An app that targets SDK 37 cannot reach the local network on Android 17
//! until it holds `ACCESS_LOCAL_NETWORK`, which Settings shows as Nearby
//! devices. Without it a TCP connect to a computer on the same Wi-Fi is
//! dropped and just times out, so the session sat on "Finding the computer"
//! (issue #56).
//!
//! `session_connect` checks before it dials. When the permission is not held
//! and the computer is plainly on this network, it fails at once with
//! [`REFUSED`], and the UI asks for the permission or explains how to allow
//! it. The prompt itself and the settings page live in `LocalNetworkPlugin.kt`
//! next to `MainActivity`; this module registers that plugin and talks to it.
//! On iOS and the desktop check build every answer is "granted".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::plugin::TauriPlugin;
use tauri::Runtime;

/// What `session_connect` returns when Android would drop the connection. The
/// UI recognises the error by the words "the local network" (see
/// `mobile/ui/src/session/status.ts`), so keep them in.
pub const REFUSED: &str = "Android is not letting DeskVNC reach the local network, so it cannot get to this computer. Allow Nearby devices for DeskVNC.";

/// The permission as the UI sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LocalNetwork {
    Granted,
    Denied,
}

#[derive(Deserialize)]
struct StateReply {
    state: LocalNetwork,
}

/// Registers the Kotlin plugin on Android. Elsewhere it is an empty plugin.
pub fn plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new("localnet")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            {
                use tauri::Manager;
                let handle =
                    _api.register_android_plugin("com.psmux.deskvnc.mobile", "LocalNetworkPlugin")?;
                _app.manage(Handle(handle));
            }
            Ok(())
        })
        .build()
}

#[cfg(target_os = "android")]
struct Handle<R: Runtime>(tauri::plugin::PluginHandle<R>);

/// Runs one plugin command. A plugin that is missing or fails reads as
/// granted, so a fault here never blocks a connect: the worst case is the
/// old behaviour, a connect that times out.
async fn call<R: Runtime>(_app: &tauri::AppHandle<R>, _command: &str) -> LocalNetwork {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let Some(handle) = _app.try_state::<Handle<R>>() else {
            return LocalNetwork::Granted;
        };
        match handle
            .0
            .run_mobile_plugin_async::<StateReply>(_command, ())
            .await
        {
            Ok(reply) => return reply.state,
            Err(error) => {
                tracing::warn!(%error, command = _command, "local network plugin");
                return LocalNetwork::Granted;
            }
        }
    }
    #[allow(unreachable_code)]
    LocalNetwork::Granted
}

/// Whether the permission is held now.
pub async fn state<R: Runtime>(app: &tauri::AppHandle<R>) -> LocalNetwork {
    call(app, "state").await
}

/// Ask with the system prompt, where Android still shows one, and say what
/// the person chose.
pub async fn ask<R: Runtime>(app: &tauri::AppHandle<R>) -> LocalNetwork {
    call(app, "ask").await
}

/// Open this app's page in Android settings.
pub async fn open_settings<R: Runtime>(_app: &tauri::AppHandle<R>) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        if let Some(handle) = _app.try_state::<Handle<R>>() {
            return handle
                .0
                .run_mobile_plugin_async::<serde_json::Value>("openSettings", ())
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
        }
    }
    Ok(())
}

/// Fails with [`REFUSED`] when the permission is missing and `host` is on
/// this network. Anything else goes ahead and dials.
pub async fn check<R: Runtime>(app: &tauri::AppHandle<R>, host: &str, port: u16) -> Result<(), String> {
    if !cfg!(target_os = "android") {
        return Ok(());
    }
    if state(app).await == LocalNetwork::Granted {
        return Ok(());
    }
    let subnets: Vec<(Ipv4Addr, u8)> = vnc_discovery::local_subnets(false)
        .into_iter()
        .map(|s| (s.network, s.prefix))
        .collect();
    if on_this_network(host, port, &subnets).await {
        Err(REFUSED.into())
    } else {
        Ok(())
    }
}

/// True when `host` is surely a computer on the local network: a `.local`
/// name, a link local address, or a private address inside one of the
/// phone's own (non VPN) subnets. A name is looked up first; the DNS server
/// itself is exempt from the permission, so that works without it.
///
/// It leans towards false. A private address that is not on one of these
/// subnets may sit behind a VPN, which the permission does not cover, so it
/// is left to dial; if Android drops it after all, the timeout's own message
/// names the permission.
pub async fn on_this_network(host: &str, port: u16, subnets: &[(Ipv4Addr, u8)]) -> bool {
    let host = bare_host(host);
    if host.is_empty() {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_lan_ip(ip, subnets);
    }
    if is_local_name(host) {
        return true;
    }
    let lookup = tokio::net::lookup_host((host, port));
    match tokio::time::timeout(Duration::from_secs(3), lookup).await {
        Ok(Ok(addrs)) => addrs.into_iter().any(|a| is_lan_ip(a.ip(), subnets)),
        _ => false,
    }
}

/// The host without IPv6 brackets or a zone (`[fe80::1%wlan0]`).
fn bare_host(host: &str) -> &str {
    let host = host.trim();
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    host.split('%').next().unwrap_or(host)
}

/// Multicast DNS names, which only ever resolve on this network.
pub fn is_local_name(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h.ends_with(".local") || h == "local"
}

/// See [`on_this_network`]. Loopback is never the local network.
pub fn is_lan_ip(ip: IpAddr, subnets: &[(Ipv4Addr, u8)]) -> bool {
    match ip {
        IpAddr::V4(v4) => lan_v4(v4, subnets),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => lan_v4(v4, subnets),
            None => lan_v6(v6),
        },
    }
}

fn lan_v4(ip: Ipv4Addr, subnets: &[(Ipv4Addr, u8)]) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() {
        return false;
    }
    if ip.is_link_local() {
        return true;
    }
    ip.is_private() && subnets.iter().any(|&(net, prefix)| in_subnet(ip, net, prefix))
}

fn lan_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    // fe80::/10 link local. Unique local fc00::/7 can be routed through a
    // VPN like a private IPv4 range, and the phone's IPv6 prefixes are not
    // listed here, so it is left to dial.
    first & 0xffc0 == 0xfe80
}

fn in_subnet(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    u32::from(ip) & mask == u32::from(net) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &[(Ipv4Addr, u8)] = &[(Ipv4Addr::new(192, 168, 1, 0), 24)];

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_private_address_on_the_phones_subnet_is_local() {
        assert!(is_lan_ip(ip("192.168.1.20"), HOME));
        assert!(is_lan_ip(ip("::ffff:192.168.1.20"), HOME));
    }

    #[test]
    fn a_private_address_elsewhere_may_be_a_vpn_and_is_left_to_dial() {
        assert!(!is_lan_ip(ip("10.0.0.5"), HOME));
        assert!(!is_lan_ip(ip("192.168.2.20"), HOME));
        assert!(!is_lan_ip(ip("fd12:3456::1"), HOME));
    }

    #[test]
    fn link_local_is_always_local() {
        assert!(is_lan_ip(ip("169.254.10.1"), &[]));
        assert!(is_lan_ip(ip("fe80::1"), &[]));
    }

    #[test]
    fn public_and_loopback_addresses_are_not_local() {
        assert!(!is_lan_ip(ip("203.0.113.7"), HOME));
        assert!(!is_lan_ip(ip("2001:db8::1"), HOME));
        assert!(!is_lan_ip(ip("127.0.0.1"), HOME));
        assert!(!is_lan_ip(ip("::1"), HOME));
        // A public address is not local even inside a subnet listed by mistake.
        assert!(!is_lan_ip(ip("203.0.113.7"), &[(Ipv4Addr::new(203, 0, 113, 0), 24)]));
    }

    #[test]
    fn mdns_names_are_local() {
        assert!(is_local_name("studio-mac.local"));
        assert!(is_local_name("Studio-Mac.LOCAL."));
        assert!(!is_local_name("example.com"));
        assert!(!is_local_name("localhost"));
    }

    #[tokio::test]
    async fn names_and_literals_are_judged_without_dialing() {
        assert!(on_this_network("192.168.1.20", 5900, HOME).await);
        assert!(on_this_network(" [fe80::1%wlan0] ", 5900, HOME).await);
        assert!(on_this_network("studio-mac.local", 5900, HOME).await);
        assert!(!on_this_network("203.0.113.7", 5900, HOME).await);
        assert!(!on_this_network("", 5900, HOME).await);
        // A name that resolves to loopback is not the local network.
        assert!(!on_this_network("localhost", 5900, HOME).await);
    }

    #[test]
    fn the_ui_knows_the_refusal_by_the_same_sentence() {
        let contract = include_str!("../../ui/src/api/contract.ts");
        assert!(contract.contains(&format!("\"{REFUSED}\"")));
    }

    #[test]
    fn subnet_masks() {
        assert!(in_subnet(Ipv4Addr::new(10, 0, 2, 2), Ipv4Addr::new(10, 0, 2, 0), 24));
        assert!(!in_subnet(Ipv4Addr::new(10, 0, 3, 2), Ipv4Addr::new(10, 0, 2, 0), 24));
        assert!(in_subnet(Ipv4Addr::new(172, 16, 9, 9), Ipv4Addr::new(172, 16, 0, 0), 20));
    }
}
