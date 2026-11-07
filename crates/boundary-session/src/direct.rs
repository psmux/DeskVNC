//! Reaching an unattended machine by its address, the way VNC and RDP are
//! reached, as well as by its ID.
//!
//! A machine listening for unattended helpers binds a fixed UDP port,
//! [`PORT`], for its QUIC endpoint, so a helper that can route to it (a LAN,
//! a VPN, a forwarded port) can dial it straight. A QUIC connection still
//! has to name the key it expects, so the machine also answers on the same
//! port over TCP with one line carrying its ID. The ID is public: it is what
//! the machine publishes to the address directory anyway. Being let in is
//! still decided by pairing or the unattended password, never by knowing
//! the address. A helper that wants the key pinned types `id@address`, and
//! then the TCP answer is never asked for.
//!
//! Accepted forms: `id`, `id@host`, `id@host:port`, `host`, `host:port`,
//! `[v6]:port`, each optionally after `boundary://`.

use anyhow::{Context, Result, anyhow, bail, ensure};
use iroh::{EndpointAddr, EndpointId};
use std::{net::SocketAddr, str::FromStr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

/// The port an unattended machine listens on, UDP for sessions and TCP for
/// its ID. A machine where it is taken falls back to a random port, which
/// still works by ID.
pub const PORT: u16 = 5940;
const GREETING: &str = "BOUNDARY1 ";
const ASK_TIMEOUT: Duration = Duration::from_secs(5);

/// Where a helper asked to go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// By ID alone, found through the address directory.
    Id(EndpointId),
    /// At an address, with the ID if the helper gave it.
    At {
        id: Option<EndpointId>,
        host: String,
        port: u16,
    },
}

impl Target {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let text = text
            .strip_prefix("boundary://")
            .unwrap_or(text)
            .trim_end_matches('/');
        ensure!(!text.is_empty(), "Enter a machine ID or an address");
        ensure!(
            text.len() <= 400 && !text.chars().any(|c| c.is_control() || c.is_whitespace()),
            "That is not a machine ID or an address"
        );
        if let Ok(id) = EndpointId::from_str(text) {
            return Ok(Self::Id(id));
        }
        // A long run of hex is a machine ID with a character missing or
        // extra, not a host name anybody has.
        ensure!(
            text.len() < 40 || !text.chars().all(|c| c.is_ascii_hexdigit()),
            "A machine ID has 64 characters, and this has {}",
            text.len()
        );
        let (id, rest) = match text.rsplit_once('@') {
            Some((id, rest)) => (
                Some(
                    EndpointId::from_str(id)
                        .map_err(|_| anyhow!("Before the @ goes the machine ID, 64 characters"))?,
                ),
                rest,
            ),
            None => (None, text),
        };
        let (host, port) = split_port(rest)?;
        ensure!(!host.is_empty(), "Enter an address");
        ensure!(
            host.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_' | '%')),
            "That is not an address"
        );
        Ok(Self::At {
            id,
            host: host.to_string(),
            port,
        })
    }
}

fn split_port(text: &str) -> Result<(&str, u16)> {
    if let Some(rest) = text.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .context("An IPv6 address needs its closing ]")?;
        return match after.strip_prefix(':') {
            Some(port) => Ok((host, parse_port(port)?)),
            None if after.is_empty() => Ok((host, PORT)),
            None => bail!("That is not an address"),
        };
    }
    // More than one colon and no brackets is a bare IPv6 address.
    match text.split_once(':') {
        Some((host, port)) if !port.contains(':') => Ok((host, parse_port(port)?)),
        _ => Ok((text, PORT)),
    }
}
fn parse_port(text: &str) -> Result<u16> {
    text.parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow!("Port must be between 1 and 65535"))
}

/// Turn a target into the address QUIC dials: the ID, plus the address's
/// IPs on its port when it has one. Asks the machine for its ID if the
/// helper did not give it.
pub(crate) async fn resolve(target: Target) -> Result<EndpointAddr> {
    let (id, host, port) = match target {
        Target::Id(id) => return Ok(EndpointAddr::new(id)),
        Target::At { id, host, port } => (id, host, port),
    };
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(ASK_TIMEOUT, tokio::net::lookup_host((host.as_str(), port)))
            .await
            .map_err(|_| anyhow!("Looking up {host} took too long"))?
            .with_context(|| format!("Cannot find {host}"))?
            .collect();
    ensure!(!addrs.is_empty(), "{host} has no address");
    let id = match id {
        Some(id) => id,
        None => ask(&host, &addrs).await?,
    };
    Ok(addrs
        .into_iter()
        .fold(EndpointAddr::new(id), EndpointAddr::with_ip_addr))
}

async fn ask(host: &str, addrs: &[SocketAddr]) -> Result<EndpointId> {
    let mut last = None;
    for addr in addrs {
        match tokio::time::timeout(ASK_TIMEOUT, ask_one(*addr)).await {
            Ok(Ok(id)) => return Ok(id),
            Ok(Err(error)) => last = Some(error),
            Err(_) => last = Some(anyhow!("no answer")),
        }
    }
    let why = last.map(|e| format!("{e:#}")).unwrap_or_default();
    bail!(
        "{host} did not say which computer it is ({why}). Check that unattended access is on there and that port {} is open, or connect with its machine ID",
        addrs[0].port()
    )
}
async fn ask_one(addr: SocketAddr) -> Result<EndpointId> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let mut line = Vec::with_capacity(GREETING.len() + 66);
    let mut byte = [0u8; 1];
    while line.len() < GREETING.len() + 66 {
        if stream.read(&mut byte).await? == 0 || byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    let line = String::from_utf8(line).map_err(|_| anyhow!("not a DeskVNC computer"))?;
    let id = line
        .trim()
        .strip_prefix(GREETING)
        .ok_or_else(|| anyhow!("not a DeskVNC computer"))?;
    EndpointId::from_str(id.trim()).map_err(|_| anyhow!("not a DeskVNC computer"))
}

/// Answer "which computer are you" on TCP at each of these UDP sockets'
/// addresses, until `stop`. A socket whose TCP twin cannot be bound is
/// skipped; the machine is still reachable by ID.
pub(crate) fn answer(sockets: Vec<SocketAddr>, id: EndpointId, stop: CancellationToken) -> usize {
    let line = format!("{GREETING}{id}\n");
    let mut bound = 0;
    for addr in sockets {
        let listener = match std::net::TcpListener::bind(addr).and_then(|l| {
            l.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(l)
        }) {
            Ok(listener) => listener,
            Err(_) => continue,
        };
        bound += 1;
        let line = line.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    biased;
                    _ = stop.cancelled() => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((mut stream, _)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let line = line.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(ASK_TIMEOUT, async {
                        stream.write_all(line.as_bytes()).await?;
                        stream.shutdown().await
                    })
                    .await;
                });
            }
        });
    }
    bound
}

/// The addresses a person would type for this computer: the ones on the
/// direct port, LAN and VPN first, without loopback or link local noise.
pub fn typed_addresses(address: &EndpointAddr) -> Vec<String> {
    let mut found: Vec<std::net::SocketAddr> = address
        .ip_addrs()
        .filter(|a| a.port() == PORT)
        .filter(|a| !a.ip().is_loopback() && !a.ip().is_unspecified())
        .filter(|a| match a.ip() {
            std::net::IpAddr::V4(ip) => !ip.is_link_local(),
            std::net::IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) != 0xfe80,
        })
        .copied()
        .collect();
    found.sort_by_key(|a| (!a.is_ipv4(), !is_private(a.ip()), a.ip()));
    found.dedup();
    found.iter().map(|a| a.ip().to_string()).collect()
}
fn is_private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.octets()[0] == 100,
        std::net::IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "3ae432ab7fd87dbd85b26c69e3d00be3f1ad47688df3e79e650ea9c8f0440723";

    fn at(id: bool, host: &str, port: u16) -> Target {
        Target::At {
            id: id.then(|| EndpointId::from_str(ID).unwrap()),
            host: host.into(),
            port,
        }
    }

    #[test]
    fn every_form_parses() {
        assert!(matches!(Target::parse(ID).unwrap(), Target::Id(_)));
        assert_eq!(
            Target::parse("10.42.0.2").unwrap(),
            at(false, "10.42.0.2", PORT)
        );
        assert_eq!(
            Target::parse("box.lan:6000").unwrap(),
            at(false, "box.lan", 6000)
        );
        assert_eq!(
            Target::parse(&format!("{ID}@10.0.0.5")).unwrap(),
            at(true, "10.0.0.5", PORT)
        );
        assert_eq!(
            Target::parse(&format!("boundary://{ID}@10.0.0.5:7000/")).unwrap(),
            at(true, "10.0.0.5", 7000)
        );
        assert_eq!(
            Target::parse("[fd00::2]:6001").unwrap(),
            at(false, "fd00::2", 6001)
        );
        assert_eq!(
            Target::parse("fd00::2").unwrap(),
            at(false, "fd00::2", PORT)
        );
    }

    #[test]
    fn nonsense_is_refused() {
        for bad in [
            "",
            "a b",
            "x@10.0.0.1",
            "10.0.0.1:0",
            "10.0.0.1:99999",
            "[fd00::2",
            "a/b",
            &ID[1..],
        ] {
            assert!(Target::parse(bad).is_err(), "{bad} parsed");
        }
    }

    #[test]
    fn the_addresses_shown_are_the_ones_a_person_types() {
        let id = EndpointId::from_str(ID).unwrap();
        let addr = [
            "127.0.0.1:5940",
            "203.0.113.9:5940",
            "192.168.50.173:5940",
            "169.254.3.4:5940",
            "10.8.0.4:6000",
            "[fe80::1]:5940",
            "[2606:4700::4]:5940",
        ]
        .into_iter()
        .map(|a| a.parse().unwrap())
        .fold(EndpointAddr::new(id), EndpointAddr::with_ip_addr);
        assert_eq!(
            typed_addresses(&addr),
            ["192.168.50.173", "203.0.113.9", "2606:4700::4"]
        );
    }

    #[tokio::test]
    async fn the_id_is_asked_for_and_given() {
        let id = EndpointId::from_str(ID).unwrap();
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let stop = CancellationToken::new();
        assert_eq!(answer(vec![addr], id, stop.clone()), 1);
        let resolved = resolve(Target::parse(&addr.to_string()).unwrap())
            .await
            .unwrap();
        assert_eq!(resolved.id, id);
        assert_eq!(resolved.ip_addrs().copied().collect::<Vec<_>>(), vec![addr]);
        stop.cancel();
    }
}
