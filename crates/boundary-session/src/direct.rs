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
//!
//! A helper given an address dials only that address. Its endpoint has no
//! relay, no address directory and no port mapping, so nothing but the
//! computer at the address hears from it, the way a VNC or RDP client works.
//! [`plan`] decides when the ID route through the directory and relays is
//! tried after that, and when it is not tried at all.

use anyhow::{Context, Result, anyhow, bail, ensure};
use iroh::{EndpointAddr, EndpointId};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
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

/// One way of reaching a computer, tried in the order [`plan`] gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Dial the address with no relay and no directory. `short` when the
    /// ID route follows, so a computer that is not there costs only
    /// [`DIRECT_TRY`] before it is tried.
    Direct { short: bool },
    /// Find the computer by its ID through the address directory, with
    /// relays to fall back on.
    Directory(EndpointId),
}

/// How long a direct try may take when the ID route follows it. On a LAN
/// or a VPN the handshake takes milliseconds; a computer that is elsewhere
/// never answers, so this is all it costs.
pub(crate) const DIRECT_TRY: Duration = Duration::from_secs(4);

/// Said when relays are off and the helper gave only an ID.
pub const NO_DIRECT_ADDRESS: &str = "Never use relays is on, and there is no direct address for this computer yet. Connect to it once by its address, or turn off Never use relays";

/// How to reach `target`. `relay` is false when the helper turned relays
/// off, and then the directory is never used either.
///
/// * An address alone is dialled directly, and that is all. Without an ID
///   there is nothing to look up anyway.
/// * An ID with an address (typed as `id@address`, saved by the phone, or
///   remembered from a direct session) is dialled directly first, then by
///   ID if that fails.
/// * An ID alone goes through the directory, or is refused with relays off.
pub(crate) fn plan(target: &Target, relay: bool) -> Result<Vec<Step>> {
    Ok(match (target, relay) {
        (Target::Id(_), false) => bail!(NO_DIRECT_ADDRESS),
        (Target::Id(id), true) => vec![Step::Directory(*id)],
        (Target::At { id: Some(id), .. }, true) => {
            vec![Step::Direct { short: true }, Step::Directory(*id)]
        }
        (Target::At { .. }, _) => vec![Step::Direct { short: false }],
    })
}

/// Whether a direct address is worth trying first next time. One on the
/// fixed port, or on a private or VPN network, is where the computer itself
/// listens. A public address on another port is a NAT's mapping for that
/// one session and would only cost [`DIRECT_TRY`] next time.
pub fn worth_remembering(addr: SocketAddr) -> bool {
    let ip = addr.ip();
    let link_local = match ip {
        std::net::IpAddr::V4(ip) => ip.is_link_local(),
        std::net::IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    };
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !link_local
        && addr.port() != 0
        && (addr.port() == PORT || is_private(ip))
}

/// What the helper typed, with the address this computer last answered on
/// directly put in front of a bare ID, so that address is tried first.
/// Anything else is returned as it is.
pub fn prefer_direct(text: &str, known: Option<SocketAddr>) -> String {
    match (Target::parse(text), known) {
        (Ok(Target::Id(id)), Some(addr)) => format!("{id}@{addr}"),
        _ => text.to_string(),
    }
}

/// The address each computer last answered on directly, by machine ID, in
/// a small file of its own.
#[derive(Debug, Default)]
pub struct Book {
    path: Option<PathBuf>,
    addrs: BTreeMap<String, SocketAddr>,
}
/// Enough for every computer anybody helps; the file stays a few KB.
const BOOK_MAX: usize = 500;
impl Book {
    /// The book in `path`. A missing or unreadable file is an empty book.
    pub fn open(path: &Path) -> Self {
        let addrs = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<BTreeMap<String, SocketAddr>>(&bytes).ok())
            .unwrap_or_default();
        Self {
            path: Some(path.to_path_buf()),
            addrs,
        }
    }
    /// Where `machine` last answered directly.
    pub fn get(&self, machine: &str) -> Option<SocketAddr> {
        let id = EndpointId::from_str(&machine.trim().to_ascii_lowercase()).ok()?;
        self.addrs.get(&id.to_string()).copied()
    }
    /// Note that `machine` answered directly at `addr`. True when that is
    /// news and was written down.
    pub fn remember(&mut self, machine: EndpointId, addr: SocketAddr) -> bool {
        if !worth_remembering(addr) {
            return false;
        }
        let key = machine.to_string();
        if self.addrs.get(&key) == Some(&addr) {
            return false;
        }
        if !self.addrs.contains_key(&key) && self.addrs.len() >= BOOK_MAX {
            let first = self.addrs.keys().next().cloned();
            if let Some(first) = first {
                self.addrs.remove(&first);
            }
        }
        self.addrs.insert(key, addr);
        if let Some(path) = &self.path {
            let _ = save(path, &self.addrs);
        }
        true
    }
}
fn save(path: &Path, addrs: &BTreeMap<String, SocketAddr>) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(addrs)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
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
            "10.0.0.4:6000",
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

    fn id() -> EndpointId {
        EndpointId::from_str(ID).unwrap()
    }

    #[test]
    fn an_address_is_dialled_directly_and_nothing_else() {
        for relay in [true, false] {
            for text in ["10.0.0.5", "box.lan:6000", "[fd00::2]:6001"] {
                assert_eq!(
                    plan(&Target::parse(text).unwrap(), relay).unwrap(),
                    [Step::Direct { short: false }],
                    "{text} relay {relay}"
                );
            }
        }
    }

    #[test]
    fn an_id_with_an_address_goes_direct_first() {
        let target = Target::parse(&format!("{ID}@10.0.0.5")).unwrap();
        assert_eq!(
            plan(&target, true).unwrap(),
            [Step::Direct { short: true }, Step::Directory(id())]
        );
        // With relays off the address is all there is, so it gets the
        // whole wait.
        assert_eq!(
            plan(&target, false).unwrap(),
            [Step::Direct { short: false }]
        );
    }

    #[test]
    fn an_id_alone_uses_the_directory_unless_relays_are_off() {
        let target = Target::parse(ID).unwrap();
        assert_eq!(plan(&target, true).unwrap(), [Step::Directory(id())]);
        let refused = plan(&target, false).unwrap_err().to_string();
        assert_eq!(refused, NO_DIRECT_ADDRESS);
    }

    #[test]
    fn a_known_address_goes_in_front_of_a_bare_id() {
        let lan: SocketAddr = "192.168.1.20:5940".parse().unwrap();
        let v6: SocketAddr = "[fd00::7]:5940".parse().unwrap();
        let typed = prefer_direct(ID, Some(lan));
        assert_eq!(typed, format!("{ID}@192.168.1.20:5940"));
        assert_eq!(
            Target::parse(&typed).unwrap(),
            Target::At {
                id: Some(id()),
                host: "192.168.1.20".into(),
                port: PORT
            }
        );
        assert_eq!(
            Target::parse(&prefer_direct(ID, Some(v6))).unwrap(),
            Target::At {
                id: Some(id()),
                host: "fd00::7".into(),
                port: PORT
            }
        );
        assert_eq!(prefer_direct(ID, None), ID);
        // An address the helper typed is never replaced.
        assert_eq!(prefer_direct("10.0.0.9:6000", Some(lan)), "10.0.0.9:6000");
        let typed = format!("{ID}@10.0.0.9");
        assert_eq!(prefer_direct(&typed, Some(lan)), typed);
    }

    #[test]
    fn only_addresses_the_computer_listens_on_are_remembered() {
        for good in [
            "192.168.1.20:5940",
            "10.0.0.4:61234",
            "100.64.1.2:5940",
            "[fd00::2]:7000",
            "203.0.113.9:5940",
        ] {
            assert!(worth_remembering(good.parse().unwrap()), "{good}");
        }
        for bad in [
            "203.0.113.9:41641",
            "127.0.0.1:5940",
            "169.254.3.4:5940",
            "[fe80::1]:5940",
            "0.0.0.0:5940",
            "[2606:4700::4]:40000",
        ] {
            assert!(!worth_remembering(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn the_book_keeps_the_last_direct_address() {
        let dir = std::env::temp_dir().join(format!("boundary-book-{}", std::process::id()));
        let path = dir.join("direct.json");
        let _ = std::fs::remove_dir_all(&dir);
        let mut book = Book::open(&path);
        assert_eq!(book.get(ID), None);
        let first: SocketAddr = "192.168.1.20:5940".parse().unwrap();
        let moved: SocketAddr = "192.168.1.31:5940".parse().unwrap();
        assert!(book.remember(id(), first));
        assert!(!book.remember(id(), first), "the same address is not news");
        assert!(!book.remember(id(), "203.0.113.9:41641".parse().unwrap()));
        assert_eq!(Book::open(&path).get(ID), Some(first));
        assert!(book.remember(id(), moved));
        assert_eq!(Book::open(&path).get(&ID.to_uppercase()), Some(moved));
        assert_eq!(book.get("not an id"), None);
        std::fs::write(&path, b"{ broken").unwrap();
        assert_eq!(Book::open(&path).get(ID), None);
        let _ = std::fs::remove_dir_all(&dir);
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
