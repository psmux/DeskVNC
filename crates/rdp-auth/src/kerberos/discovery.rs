//! KDC discovery: the question, not the answer.
//!
//! RFC 4120 §7.2.3 locates a realm's domain controllers with DNS SRV records.
//! A DNS lookup is I/O and this crate does none (D12, PRDRDP/12 §2.1), so the
//! lookup is a question the state machine asks its caller, the same way
//! `CredSspClient` asks for a token rather than reading a socket.
//!
//! There is no trait here and no `KdcTransport`. PRDRDP/14 §7.1 item 9
//! sketched one, and a trait object would put a `dyn` in the middle of a
//! crate whose whole shape is "bytes in, bytes out", for a call that happens
//! once per connection and whose result is a list of host names. So this
//! module is two pure functions and two plain structs: [`srv_queries`] says
//! what to look up, [`KdcEndpoint`] says what an answer looks like, and
//! [`order_endpoints`] applies RFC 2782's priority and weight rules to a set
//! of answers. `rdp-core` does the resolving and the connecting between the
//! two.
//!
//! ## What `rdp-core` has to satisfy
//!
//! ```text
//! for query in discovery::srv_queries(realm) {
//!     // Resolve `query.name` as an SRV record. Failure is not fatal:
//!     // a realm may publish _tcp and not the _msdcs form, or the other
//!     // way round.
//!     for record in resolver.srv_lookup(&query.name).await? {
//!         endpoints.push(KdcEndpoint {
//!             host: record.target().to_string(),
//!             port: record.port(),
//!             priority: record.priority(),
//!             weight: record.weight(),
//!         });
//!     }
//! }
//! if endpoints.is_empty() {
//!     // RFC 4120 §7.2.3's fallback, and the one every client implements:
//!     // the realm name itself on port 88.
//!     endpoints.push(KdcEndpoint::fallback(realm));
//! }
//! for endpoint in discovery::order_endpoints(endpoints) {
//!     // TCP connect, then drive KdcClient::step over the socket.
//! }
//! ```
//!
//! Four things `rdp-core` owns and this module deliberately does not:
//!
//! * **The resolver.** `hickory-resolver` is the usual answer and the
//!   platform resolver through `getaddrinfo` cannot do SRV, so a real DNS
//!   client is needed. It is a dependency of `rdp-core`, never of this crate.
//! * **Connecting, and failing over.** Try the endpoints in the order
//!   [`order_endpoints`] returns and move to the next on a connection
//!   failure. A KDC that answers with a `KRB-ERROR` has answered: that is not
//!   a reason to try another one, because every KDC in a realm gives the same
//!   answer.
//! * **The timeout.** RFC 4120 §7.2.2 sets none. Windows uses ten seconds per
//!   KDC.
//! * **`RdpOptions::kdc_proxy_url` (R29).** When it is set, discovery does
//!   not happen at all: the whole exchange goes through the KDC Proxy
//!   Protocol (MS-KKDCP) to that URL. That is `rdp-core`'s decision to make
//!   before it calls anything here, and the bytes
//!   [`KdcClient`](super::kdc::KdcClient) produces are the same either way,
//!   because MS-KKDCP carries the RFC 4120 §7.2.2 framed message verbatim
//!   inside its own wrapper.
//!
//! ## Windows and the `_msdcs` form
//!
//! Active Directory publishes the RFC 4120 names and also
//! `_kerberos._tcp.dc._msdcs.<domain>`, which resolves only to domain
//! controllers rather than to anything that answers on port 88, and
//! `_kerberos._tcp.<site>._sites.dc._msdcs.<domain>` for site awareness.
//! [`srv_queries`] returns the `_msdcs` form first because on a Windows
//! domain it is the more precise answer, and the plain RFC 4120 form after it
//! because on an MIT realm it is the only one. The site aware form is not
//! returned: finding the site name means reading it from the machine's own
//! domain membership, which this client does not have and a non domain joined
//! client does not have at all.

/// One DNS SRV name to look up, and what it means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvQuery {
    /// The fully qualified name to resolve as an SRV record.
    pub name: String,
    /// What publishes this name, for the log line when it does not resolve.
    pub source: SrvSource,
}

/// Which specification a query name comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrvSource {
    /// `_kerberos._tcp.dc._msdcs.<domain>`, Active Directory's own form.
    /// More precise than the RFC form on a Windows domain and absent
    /// everywhere else.
    ActiveDirectory,
    /// `_kerberos._tcp.<REALM>`, RFC 4120 §7.2.3.2. Every Kerberos realm
    /// publishes it, including Active Directory.
    Rfc4120,
}

/// The IANA assigned port for Kerberos (RFC 4120 §7.2.3.2).
///
/// "It is strongly recommended that KDCs be configured to listen on that
/// port", and an SRV record may name another, which is why
/// [`KdcEndpoint::port`] exists rather than this being assumed everywhere.
pub const KERBEROS_PORT: u16 = 88;

/// The SRV names to look up for a realm, most precise first.
///
/// TCP only. RFC 4120 §7.2.3.2 says "both 'udp' and 'tcp' records MUST be
/// specified for all KDC deployments", so a realm that publishes anything
/// publishes the TCP form, and `_udp` would only find KDCs we have no
/// transport for (PRDRDP/14 §7.1 item 10 declines the UDP path).
///
/// `_kerberos-master._tcp` is not returned either. RFC 4120 §7.2.3 does not
/// define it; it is an MIT convention for the KDC that accepts password
/// changes, and an ordinary AS exchange works against any KDC in the realm.
///
/// The realm goes into the name as it was given. RFC 4120 §7.2.3.1 is
/// explicit that realm names are case sensitive while DNS queries are not, so
/// the case here changes nothing about which record is found; it is passed
/// through rather than normalised so a log line shows the realm the caller
/// actually has.
///
/// A trailing dot is stripped: `EXAMPLE.COM.` and `EXAMPLE.COM` are the same
/// realm, and a name with two dots in the middle resolves to nothing.
#[must_use]
pub fn srv_queries(realm: &str) -> Vec<SrvQuery> {
    let realm = realm.trim_end_matches('.');
    if realm.is_empty() {
        return Vec::new();
    }
    vec![
        SrvQuery {
            name: format!("_kerberos._tcp.dc._msdcs.{realm}"),
            source: SrvSource::ActiveDirectory,
        },
        SrvQuery {
            name: format!("_kerberos._tcp.{realm}"),
            source: SrvSource::Rfc4120,
        },
    ]
}

/// One place a KDC might be, from an SRV answer or from the fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcEndpoint {
    /// The SRV target, a host name. Not resolved here.
    pub host: String,
    /// The SRV port, usually [`KERBEROS_PORT`].
    pub port: u16,
    /// RFC 2782's priority. Lower is tried first.
    pub priority: u16,
    /// RFC 2782's weight, for choosing among equal priorities.
    pub weight: u16,
}

impl KdcEndpoint {
    /// The fallback every Kerberos client implements: the realm name itself,
    /// on the assigned port.
    ///
    /// RFC 4120 §7.2.3 describes SRV discovery and does not say what to do
    /// when a realm publishes nothing. In practice a realm whose name is also
    /// a resolvable host name is common in small deployments and in test
    /// labs, and trying it costs one connection attempt. It is last, after
    /// every SRV answer.
    #[must_use]
    pub fn fallback(realm: &str) -> Self {
        KdcEndpoint {
            host: realm.trim_end_matches('.').to_owned(),
            port: KERBEROS_PORT,
            // Worse than any real SRV answer, so a caller that appends this
            // to a list of answers and sorts gets it last without having to
            // remember to.
            priority: u16::MAX,
            weight: 0,
        }
    }
}

/// Put endpoints in the order to try them: RFC 2782's priority, then weight.
///
/// RFC 2782 orders by ascending priority, and within one priority it picks
/// randomly with a probability proportional to weight. The weighted random
/// selection is not done here and the reason is not laziness: it needs a
/// random number, and a crate whose test suite asserts that every random byte
/// comes from `rand::rng()` for key material should not also be spending that
/// generator on load balancing. Descending weight inside a priority is a
/// deterministic order that respects the operator's intent, and the
/// difference between it and RFC 2782's is which of two equally good domain
/// controllers gets the connection.
///
/// Ties beyond that keep the order they arrived in, which for a caller that
/// queried the `_msdcs` name first means Active Directory's answer is tried
/// before the RFC 4120 one.
#[must_use]
pub fn order_endpoints(mut endpoints: Vec<KdcEndpoint>) -> Vec<KdcEndpoint> {
    // A KDC published under both names is one KDC.
    endpoints.dedup_by(|a, b| a.host.eq_ignore_ascii_case(&b.host) && a.port == b.port);
    endpoints.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| b.weight.cmp(&a.weight))
    });
    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4120 §7.2.3.2's own example realm, and Active Directory's form
    /// beside it.
    #[test]
    fn the_query_names_are_the_ones_the_specifications_define() {
        let queries = srv_queries("EXAMPLE.COM");
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].name, "_kerberos._tcp.dc._msdcs.EXAMPLE.COM");
        assert_eq!(queries[0].source, SrvSource::ActiveDirectory);
        // RFC 4120 §7.2.3.3's sample record is
        // `_kerberos._tcp.EXAMPLE.COM. IN SRV 0 0 88 kdc1.example.com.`
        assert_eq!(queries[1].name, "_kerberos._tcp.EXAMPLE.COM");
        assert_eq!(queries[1].source, SrvSource::Rfc4120);
    }

    /// A trailing dot is a valid way to write a realm and produces a name
    /// with two dots in the middle if it is not stripped.
    #[test]
    fn a_trailing_dot_does_not_become_a_double_dot() {
        let queries = srv_queries("EXAMPLE.COM.");
        assert_eq!(queries[1].name, "_kerberos._tcp.EXAMPLE.COM");
        assert!(!queries[0].name.contains(".."), "{}", queries[0].name);
        assert!(srv_queries("").is_empty());
        assert!(srv_queries(".").is_empty());
    }

    /// RFC 4120 §7.2.3.1: the case is passed through, because DNS does not
    /// care and the realm does.
    #[test]
    fn the_realm_case_is_passed_through_unchanged() {
        assert_eq!(
            srv_queries("MyRealm.Example.Com")[1].name,
            "_kerberos._tcp.MyRealm.Example.Com"
        );
    }

    /// RFC 2782: ascending priority, and within a priority the heavier first.
    #[test]
    fn endpoints_are_ordered_by_priority_then_weight() {
        let e = |host: &str, priority, weight| KdcEndpoint {
            host: host.to_owned(),
            port: KERBEROS_PORT,
            priority,
            weight,
        };
        let ordered = order_endpoints(vec![
            e("slow.example.com", 1, 0),
            e("light.example.com", 0, 10),
            e("heavy.example.com", 0, 90),
        ]);
        let names: Vec<&str> = ordered.iter().map(|x| x.host.as_str()).collect();
        assert_eq!(
            names,
            ["heavy.example.com", "light.example.com", "slow.example.com"]
        );
    }

    /// The fallback sorts last however it is inserted, which is what lets a
    /// caller append it without thinking about order.
    #[test]
    fn the_fallback_is_always_tried_last() {
        let real = KdcEndpoint {
            host: "kdc1.example.com".to_owned(),
            port: KERBEROS_PORT,
            priority: u16::MAX - 1,
            weight: 0,
        };
        let fallback = KdcEndpoint::fallback("EXAMPLE.COM.");
        assert_eq!(fallback.host, "EXAMPLE.COM");
        assert_eq!(fallback.port, 88);
        let ordered = order_endpoints(vec![fallback.clone(), real.clone()]);
        assert_eq!(ordered, [real, fallback]);
    }

    /// A KDC published under both the `_msdcs` and the RFC 4120 name is one
    /// KDC, and connecting to it twice on failure wastes a timeout.
    #[test]
    fn a_kdc_published_twice_is_tried_once() {
        let e = |host: &str| KdcEndpoint {
            host: host.to_owned(),
            port: KERBEROS_PORT,
            priority: 0,
            weight: 0,
        };
        let ordered = order_endpoints(vec![e("kdc1.example.com"), e("KDC1.example.com")]);
        assert_eq!(ordered.len(), 1);
    }
}
