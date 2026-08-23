//! Hostname (and MAC) resolution for scanned IP addresses, PRD/04 §6.
//!
//! mDNS hands us a friendly instance name for free, which is why Macs have
//! always been readable in the Nearby list and everything else was a bare IP.
//! The subnet scan knows only an address, so this module asks the network what
//! that address is called, over six protocols at once:
//!
//! | # | Method | Reaches |
//! |---|---|---|
//! | 1 | mDNS reverse `PTR` (multicast 5353) | macOS, any Linux running Avahi |
//! | 2 | Unicast reverse DNS `PTR` | managed networks where DHCP registers names |
//! | 3 | NetBIOS node status (UDP 137) | **Windows on a home LAN**, and its MAC |
//! | 4 | LLMNR reverse `PTR` (multicast 5355) | Windows where NBT-NS is off |
//! | 5 | MSRPC endpoint mapper (TCP 135) | Windows that answers no name service at all |
//! | 6 | RDP TLS certificate `CN` (TCP 3389) | ditto, where RPC is closed but RDP is not |
//!
//! Rungs 5 and 6 are the odd ones out and are deliberately last: they are not
//! name services, they read the machine name off a service that happens to
//! carry it. They earn their place because current Windows ships with LLMNR
//! off and NetBIOS firewalled on the Public profile, and a consumer router
//! registers no DNS, so a hardened Windows host answers rungs 1-4 with
//! silence and would otherwise stay a bare IP forever. Neither authenticates:
//! see [`crate::msrpc`] (an anonymous `ept_lookup`, no auth verifier) and
//! [`crate::tlsname`] (a TLS handshake abandoned before key exchange). Both are
//! the same bargain as the RFB deep probe in [`crate::probe`].
//!
//! They run **concurrently** under one deadline ([`RESOLVE_BUDGET`], ~500 ms):
//! the scan never waits on any of them. A host is emitted the moment its RFB
//! banner is read; the name arrives afterwards as an `Updated` event, and if
//! no rung answers within the budget the host simply keeps showing its address.
//!
//! When more than one rung answers, the earlier one wins. The ladder is
//! ordered by how good the answer is rather than by who replied first, so a
//! slow `hostname.local` still beats a fast NetBIOS name, the extra wait costs
//! the scan nothing, because it is already off the critical path.
//!
//! Every probe is a plain name query. None of them carries a credential or
//! looks like an authentication attempt.

use crate::dnsmsg;
use crate::msrpc;
use crate::netbios;
use crate::tlsname;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout_at, Instant};

/// Total wall-clock budget for resolving one address (PRD/04 §6).
pub const RESOLVE_BUDGET: Duration = Duration::from_millis(500);

/// Resend an unanswered UDP query once after this long, a single dropped
/// datagram should not cost a host its name.
const RETRY_AFTER: Duration = Duration::from_millis(180);

/// Longest hostname we will surface, after which the answer is suspect.
const MAX_HOSTNAME_LEN: usize = 128;

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const LLMNR_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
const LLMNR_PORT: u16 = 5355;

/// Which rung of the ladder produced a name. Ordered best-first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NameSource {
    /// mDNS reverse `PTR` over multicast 5353.
    MdnsPtr,
    /// Unicast reverse DNS `PTR` via the system resolver.
    ReverseDns,
    /// NetBIOS node status over UDP 137.
    NetBios,
    /// LLMNR reverse `PTR` over multicast 5355.
    Llmnr,
    /// NetBIOS computer name read from the MSRPC endpoint mapper (TCP 135).
    MsrpcEndpoint,
    /// Subject `CN` of the TLS certificate served on RDP (TCP 3389).
    RdpCertificate,
}

impl NameSource {
    /// Short tag, for logs and for the shell's `nameSource` JSON field.
    pub fn as_str(self) -> &'static str {
        match self {
            NameSource::MdnsPtr => "mdns-ptr",
            NameSource::ReverseDns => "reverse-dns",
            NameSource::NetBios => "netbios",
            NameSource::Llmnr => "llmnr",
            NameSource::MsrpcEndpoint => "msrpc-epm",
            NameSource::RdpCertificate => "rdp-cert",
        }
    }

    /// True when answering this rung at all identifies the host as Windows.
    ///
    /// This is evidence, not a guess. Both are Windows-only *services*, so
    /// the OS is settled by the fact that the answer arrived, independently of
    /// what the VNC server on top of it calls itself, which is what makes a
    /// Windows box running TigerVNC classifiable at all:
    ///
    /// * `netbios`, NetBIOS node status (UDP 137). Samba can serve it on
    ///   Linux, but only when `nmbd` is deliberately installed and running,
    ///   and a Samba host is a file server pretending to be Windows on purpose.
    /// * `msrpc-epm`, the MSRPC endpoint mapper on TCP 135. Nothing else
    ///   ships it; the reply we parse is a `\\MACHINE` named-pipe binding.
    ///
    /// Deliberately **not** included:
    ///
    /// * `rdp-cert`, the self-signed RDP certificate on TCP 3389. It used to
    ///   be here, and it was safe only for as long as nothing brought Linux
    ///   hosts on 3389 into the list. Now that the scan probes 3389 on every
    ///   address, an xrdp box answers this rung, and answering it is no longer
    ///   evidence of anything: xrdp serves a certificate too. What still
    ///   proves Windows is the *shape* of the name in it, which depends on the
    ///   value rather than on which rung replied, so it is
    ///   [`DiscoveredHost::implies_windows`] that answers it and
    ///   [`looks_like_a_windows_computer_name`] that decides. A `CN` that
    ///   fails those tests still supplies a name; what it no longer supplies
    ///   is the claim that the host runs Windows.
    /// * `mdns-ptr`, Avahi answers reverse mDNS on every Linux desktop and on
    ///   Raspberry Pi OS, so it is no evidence of macOS (this LAN's
    ///   `raspberrypi` resolves exactly this way).
    /// * `llmnr`, implemented by `systemd-resolved` on Linux too.
    /// * `reverse-dns`, says something about the DHCP server, not the host.
    pub fn implies_windows(self) -> bool {
        matches!(self, NameSource::NetBios | NameSource::MsrpcEndpoint)
    }
}

/// True when a certificate `CN` looks like a Windows computer name.
///
/// Windows generates its RDP certificate with `CN` = the NetBIOS computer
/// name: at most 15 characters, no dots, letters, digits and hyphens only.
/// xrdp's packaged certificate carries a domain-shaped `CN` instead, which
/// fails every one of those tests.
///
/// This is a display decision and never a trust one. A hostile server can put
/// any string in its `CN`, which is why nothing reachable from here decides
/// what to connect to or what to send.
pub fn looks_like_a_windows_computer_name(cn: &str) -> bool {
    !cn.is_empty()
        && cn.len() <= 15
        && !cn.contains('.')
        && cn.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Serialized as its [`NameSource::as_str`] tag, so the wire form has one
/// definition rather than a `serde` rename that can drift from the log tag.
impl serde::Serialize for NameSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// What the ladder learned about one address.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Best hostname found, if any.
    pub hostname: Option<String>,
    /// Which method produced [`Resolved::hostname`].
    pub source: Option<NameSource>,
    /// Adapter MAC, if NetBIOS reported one (feeds Wake-on-LAN, PRD/04 §8).
    pub mac: Option<String>,
}

impl Resolved {
    /// True when nothing was learned.
    pub fn is_empty(&self) -> bool {
        self.hostname.is_none() && self.mac.is_none()
    }
}

/// Resolve `ip` over the whole ladder, in parallel, within `budget`.
///
/// Never fails: an unreachable host, a blocked port or a hostile answer all
/// come back as an empty [`Resolved`].
pub async fn resolve_host(ip: Ipv4Addr, budget: Duration) -> Resolved {
    resolve_host_with(ip, budget, true).await
}

/// As [`resolve_host`], but `probe_other_services` selects how far to go.
///
/// The first four rungs are *name services*, asking "what is this host
/// called?" is the only thing they do. The last two (MSRPC endpoint mapper on
/// 135, RDP certificate on 3389) instead read a name that some other service
/// discloses in passing. They are unauthenticated and read-only, but they mean
/// a VNC client opens connections to ports that have nothing to do with VNC,
/// which an IDS may reasonably read as reconnaissance. That is a decision for
/// the operator, not for us, hence the switch (PRD/04 §4.3 politeness).
pub async fn resolve_host_with(
    ip: Ipv4Addr,
    budget: Duration,
    probe_other_services: bool,
) -> Resolved {
    resolve_host_sharing(ip, budget, probe_other_services, None).await
}

/// As [`resolve_host_with`], with the certificate rung's answer supplied.
///
/// The 3389 probe already opened a connection to this address and, when the
/// server selected TLS, already read the subject `CN` off it. Handing that in
/// is what stops the ladder dialling 3389 a second time during one scan: the
/// probe result reaches the resolver as an input rather than the resolver
/// opening its own socket (PRDRDP/08 §4.6).
///
/// `rdp_cert_name` is `None` when the probe found nothing, which is also the
/// case where the raw path is still worth trying: `tlsname` speaks TLS on 3389
/// without the X.224 negotiation and demonstrably works against at least one
/// real Windows host, so a host that is nameable today does not become
/// unnameable. Try the negotiated path first, fall back to the raw one.
pub async fn resolve_host_sharing(
    ip: Ipv4Addr,
    budget: Duration,
    probe_other_services: bool,
    rdp_cert_name: Option<String>,
) -> Resolved {
    let deadline = Instant::now() + budget;

    let mdns = mdns_reverse_ptr(ip, deadline);
    let rdns = unicast_reverse_ptr(ip, budget);
    let nbns = netbios_node_status(ip, deadline);
    let llmnr = llmnr_reverse_ptr(ip, deadline);
    let epm = async {
        if probe_other_services {
            msrpc_endpoint_name(ip, deadline).await
        } else {
            None
        }
    };
    let shared_name = rdp_cert_name.and_then(|cn| sanitize_hostname(&cn, ip));
    let rdp = async {
        match shared_name {
            // The probe read it on the connection it already had open, so
            // this rung costs nothing at all.
            Some(name) => Some(name),
            None if probe_other_services => rdp_certificate_name(ip, deadline).await,
            None => None,
        }
    };

    // Six concurrent probes on one task. `join` keeps the whole ladder on the
    // caller's task rather than spawning six, and each arm is independently
    // deadlined, so the join cannot outlive the budget.
    let (mdns, rdns, nbns, llmnr, epm, rdp) = tokio::join!(mdns, rdns, nbns, llmnr, epm, rdp);

    let mut out = Resolved {
        mac: nbns.as_ref().and_then(|s| s.mac.clone()),
        ..Resolved::default()
    };
    let ladder = [
        (NameSource::MdnsPtr, mdns),
        (NameSource::ReverseDns, rdns),
        (NameSource::NetBios, nbns.and_then(|s| s.name)),
        (NameSource::Llmnr, llmnr),
        (NameSource::MsrpcEndpoint, epm),
        (NameSource::RdpCertificate, rdp),
    ];
    for (source, name) in ladder {
        if let Some(name) = name {
            out.hostname = Some(name);
            out.source = Some(source);
            break;
        }
    }

    if let (Some(name), Some(source)) = (&out.hostname, out.source) {
        tracing::debug!(%ip, name, method = source.as_str(), "resolved hostname");
    }
    out
}

/// Tidy a name from the wire into something worth showing a user.
///
/// Drops the trailing root dot and the `.local` mDNS suffix (so a scan-derived
/// name reads like the mDNS instance name next to it), rejects anything that is
/// not printable ASCII, over-long, or merely the address written back at us.
pub(crate) fn sanitize_hostname(raw: &str, ip: Ipv4Addr) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').trim();
    let name = name.strip_suffix(".local").unwrap_or(name);
    if name.is_empty() || name.len() > MAX_HOSTNAME_LEN {
        return None;
    }
    if !name
        .bytes()
        .all(|b| (0x21..0x7F).contains(&b) && b != b'/' && b != b'\\')
    {
        return None;
    }
    // A resolver that has nothing to say often echoes the address back.
    if name.parse::<IpAddr>().is_ok() || name == ip.to_string() {
        return None;
    }
    Some(name.to_string())
}

/// Send one UDP query and wait for a reply **from the host we asked**, until
/// `deadline`. Resends once if nothing has arrived by [`RETRY_AFTER`].
///
/// The source-address check matters: these are multicast queries, so any
/// machine on the LAN can hear them and answer. Only the address whose name we
/// asked for is allowed to name it.
async fn udp_query(
    target: Ipv4Addr,
    dest: SocketAddrV4,
    query: &[u8],
    multicast_ttl: Option<u32>,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    if let Some(ttl) = multicast_ttl {
        // Best-effort: a platform that refuses the option still sends with the
        // default TTL, which is fine for an on-link responder.
        let _ = socket.set_multicast_ttl_v4(ttl);
    }
    socket.send_to(query, dest).await.ok()?;

    let retry_at = Instant::now() + RETRY_AFTER;
    let mut resent = false;
    let mut buf = vec![0u8; dnsmsg::MAX_MESSAGE];
    loop {
        let until = if resent {
            deadline
        } else {
            deadline.min(retry_at)
        };
        match timeout_at(until, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, SocketAddr::V4(src)))) => {
                if n > 0 && *src.ip() == target {
                    return Some(buf[..n].to_vec());
                }
                // Someone else's answer, or an empty datagram: keep listening.
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return None,
            Err(_) => {
                if resent || Instant::now() >= deadline {
                    return None;
                }
                resent = true;
                socket.send_to(query, dest).await.ok()?;
            }
        }
    }
}

/// A transaction id that an off-path answer cannot guess.
///
/// Every parser in [`crate::dnsmsg`] refuses a reply whose id does not match,
/// so this is the first line of defence against a LAN host answering a query
/// it was not asked. Zero is avoided because it is the conventional id for
/// *multicast* mDNS queries and would therefore match stray traffic.
fn transaction_id() -> u16 {
    match rand::random::<u16>() {
        0 => 1,
        id => id,
    }
}

/// Rung 1, mDNS reverse `PTR` on multicast 5353.
///
/// Sent from an ephemeral port, so responders treat it as a legacy unicast
/// query (RFC 6762 §6.7) and reply straight back to us instead of flooding the
/// group. Covers macOS and any Linux box running Avahi.
async fn mdns_reverse_ptr(ip: Ipv4Addr, deadline: Instant) -> Option<String> {
    let id = transaction_id();
    let query = dnsmsg::build_query(
        id,
        &dnsmsg::reverse_ptr_qname(ip),
        dnsmsg::TYPE_PTR,
        dnsmsg::CLASS_IN,
    );
    let reply = udp_query(
        ip,
        SocketAddrV4::new(MDNS_GROUP, MDNS_PORT),
        &query,
        Some(255), // RFC 6762 §11
        deadline,
    )
    .await?;
    sanitize_hostname(&dnsmsg::first_ptr_answer(&reply, id)?, ip)
}

/// Rung 4, LLMNR reverse `PTR` on multicast 5355.
///
/// Windows resolves mDNS → LLMNR → NBT-NS in that order, so LLMNR is the rung
/// that still works on a Windows host with NetBIOS-over-TCP/IP disabled.
async fn llmnr_reverse_ptr(ip: Ipv4Addr, deadline: Instant) -> Option<String> {
    let id = transaction_id();
    let query = dnsmsg::build_query(
        id,
        &dnsmsg::reverse_ptr_qname(ip),
        dnsmsg::TYPE_PTR,
        dnsmsg::CLASS_IN,
    );
    let reply = udp_query(
        ip,
        SocketAddrV4::new(LLMNR_GROUP, LLMNR_PORT),
        &query,
        Some(1), // RFC 4795 §2.1: link-local scope
        deadline,
    )
    .await?;
    sanitize_hostname(&dnsmsg::first_ptr_answer(&reply, id)?, ip)
}

/// Rung 3, NetBIOS node status on UDP 137.
///
/// Same-subnet only (the reply is unicast but the service is not routed in
/// practice). Returns the Windows machine name *and* the adapter MAC.
async fn netbios_node_status(ip: Ipv4Addr, deadline: Instant) -> Option<netbios::NodeStatus> {
    let id = transaction_id();
    let query = netbios::build_nbstat_query(id);
    let reply = udp_query(
        ip,
        SocketAddrV4::new(ip, netbios::NBNS_PORT),
        &query,
        None,
        deadline,
    )
    .await?;
    let mut status = netbios::parse_nbstat_response(&reply, id)?;
    let cleaned = status
        .name
        .as_deref()
        .and_then(|n| sanitize_hostname(n, ip));
    status.name = cleaned;
    (!status.is_empty()).then_some(status)
}

/// Rung 5, the NetBIOS computer name from the MSRPC endpoint mapper.
///
/// Binds the `ept` interface anonymously and enumerates it; the named-pipe
/// bindings in the reply are prefixed with `\\MACHINENAME`. No credential is
/// offered at any point, both PDUs carry `auth_length = 0`. See
/// [`crate::msrpc`].
async fn msrpc_endpoint_name(ip: Ipv4Addr, deadline: Instant) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = SocketAddrV4::new(ip, msrpc::EPM_PORT);
    let mut stream = timeout_at(deadline, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    timeout_at(deadline, stream.write_all(&msrpc::bind_pdu()))
        .await
        .ok()?
        .ok()?;

    let mut chunk = vec![0u8; 8192];
    let read = timeout_at(deadline, stream.read(&mut chunk))
        .await
        .ok()?
        .ok()?;
    if !msrpc::is_bind_ack(&chunk[..read]) {
        return None; // not an endpoint mapper, or it refused the bind
    }

    timeout_at(deadline, stream.write_all(&msrpc::ept_lookup_pdu()))
        .await
        .ok()?
        .ok()?;

    let mut reply = Vec::with_capacity(64 * 1024);
    loop {
        let read = timeout_at(deadline, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            break;
        }
        if reply.is_empty() && msrpc::is_fault(&chunk[..read]) {
            return None; // the server declined to answer
        }
        reply.extend_from_slice(&chunk[..read]);
        if let Some(name) = msrpc::find_server_name(&reply) {
            return sanitize_hostname(&name, ip);
        }
        if reply.len() >= msrpc::MAX_EPM_READ {
            break;
        }
    }
    None
}

/// Rung 6, the subject `CN` of the TLS certificate served on RDP.
///
/// The last resort, for a Windows host that answers no name service at all.
/// Sends a TLS `ClientHello`, reads the server's `Certificate` message, and
/// drops the socket, the handshake is abandoned before any key exchange, so
/// nothing resembling a credential is ever sent. See [`crate::tlsname`].
async fn rdp_certificate_name(ip: Ipv4Addr, deadline: Instant) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = SocketAddrV4::new(ip, tlsname::RDP_PORT);
    let mut stream = timeout_at(deadline, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let hello = tlsname::client_hello(rand::random());
    timeout_at(deadline, stream.write_all(&hello))
        .await
        .ok()?
        .ok()?;

    let mut flight = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        let read = timeout_at(deadline, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            return None; // server hung up
        }
        flight.extend_from_slice(&chunk[..read]);
        if let Some(der) = tlsname::first_certificate(&flight) {
            // Socket drops here: no ClientKeyExchange, no Finished, no NLA.
            return sanitize_hostname(&tlsname::subject_common_name(&der)?, ip);
        }
        if flight.len() >= tlsname::MAX_TLS_READ {
            return None;
        }
    }
}

/// Rung 2, unicast reverse DNS `PTR` through the system resolver.
///
/// `getnameinfo` is blocking and can sit on a slow upstream server for
/// seconds, so it runs on the blocking pool and we simply stop waiting at the
/// budget; the stray thread finishes on its own. Only ever consulted for
/// addresses on a local subnet, so a scan cannot turn into a stream of PTR
/// lookups for arbitrary hosts.
async fn unicast_reverse_ptr(ip: Ipv4Addr, budget: Duration) -> Option<String> {
    let handle = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    let name = match tokio::time::timeout(budget, handle).await {
        Ok(Ok(Some(name))) => name,
        _ => return None,
    };
    // `lookup_addr` falls back to the numeric form when there is no PTR
    // record; `sanitize_hostname` rejects that.
    sanitize_hostname(&name, ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 77, 126)
    }

    #[test]
    fn mdns_names_lose_their_local_suffix_and_root_dot() {
        assert_eq!(
            sanitize_hostname("Example-MacBook-Air.local.", ip()).as_deref(),
            Some("Example-MacBook-Air")
        );
        assert_eq!(
            sanitize_hostname("ops-box.local", ip()).as_deref(),
            Some("ops-box")
        );
    }

    #[test]
    fn an_fqdn_from_unicast_dns_is_kept_whole() {
        assert_eq!(
            sanitize_hostname("ws-14.corp.example.com.", ip()).as_deref(),
            Some("ws-14.corp.example.com")
        );
    }

    #[test]
    fn a_resolver_echoing_the_address_is_not_a_name() {
        assert_eq!(sanitize_hostname("192.168.77.126", ip()), None);
        assert_eq!(sanitize_hostname("::1", ip()), None);
    }

    #[test]
    fn hostile_names_are_rejected() {
        assert_eq!(sanitize_hostname("", ip()), None);
        assert_eq!(sanitize_hostname("   ", ip()), None);
        assert_eq!(sanitize_hostname(".", ip()), None);
        assert_eq!(sanitize_hostname("bad name", ip()), None, "no spaces");
        assert_eq!(sanitize_hostname("a\u{1b}[2Jb", ip()), None, "no escapes");
        assert_eq!(sanitize_hostname("../../etc/passwd", ip()), None);
        assert_eq!(sanitize_hostname("a\\b", ip()), None);
        assert_eq!(sanitize_hostname(&"x".repeat(129), ip()), None);
        assert_eq!(
            sanitize_hostname(&"x".repeat(128), ip()).as_deref(),
            Some("x".repeat(128).as_str()),
            "the cap is inclusive"
        );
    }

    #[test]
    fn transaction_ids_are_never_zero_and_vary() {
        let ids: Vec<u16> = (0..16).map(|_| transaction_id()).collect();
        assert!(ids.iter().all(|&i| i != 0));
        assert!(
            ids.iter().any(|&i| i != ids[0]),
            "a constant id would let any host spoof an answer"
        );
    }

    /// Nothing on 198.51.100.0/24 (TEST-NET-2) can answer, so the whole ladder
    /// must come back empty inside the budget rather than hanging.
    #[tokio::test]
    async fn an_unreachable_address_resolves_to_nothing_within_the_budget() {
        let started = std::time::Instant::now();
        let out = resolve_host(Ipv4Addr::new(198, 51, 100, 77), Duration::from_millis(300)).await;
        assert!(out.is_empty(), "no host, no name: {out:?}");
        assert!(
            started.elapsed() < Duration::from_millis(2500),
            "resolution must be bounded, took {:?}",
            started.elapsed()
        );
    }
}
