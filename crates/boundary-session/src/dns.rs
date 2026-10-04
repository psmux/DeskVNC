//! Name lookups through the operating system first.
//!
//! iroh resolves names with its own DNS client, which sends UDP queries to
//! every nameserver it finds in the adapter settings. On a Windows PC with a
//! VPN and a disconnected Wi-Fi adapter that still lists a router as its
//! nameserver, every one of those queries timed out, so a helper could not
//! look up the address directory and could not reach a machine by its ID,
//! while the browser and `nslookup` on the same PC worked. The operating
//! system's own resolver is what everything else on the computer uses, and it
//! knows which adapters are live and what the VPN wants, so it is asked first.
//! iroh's client remains the fallback, and answers TXT lookups, which the
//! system API cannot make.

use iroh::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_secs(5);
type Boxed<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// A resolver for an endpoint: the system's, then iroh's.
pub(crate) fn resolver() -> DnsResolver {
    DnsResolver::custom(SystemFirst {
        fallback: DnsResolver::new(),
    })
}

#[derive(Debug, Clone)]
struct SystemFirst {
    fallback: DnsResolver,
}

/// The system's answer, or nothing; never an error, so the fallback runs.
async fn system(host: &str) -> Vec<IpAddr> {
    match tokio::time::timeout(TIMEOUT, tokio::net::lookup_host((host, 0))).await {
        Ok(Ok(found)) => found.map(|address| address.ip()).collect(),
        _ => Vec::new(),
    }
}

impl Resolver for SystemFirst {
    fn lookup_ipv4(&self, host: String) -> Boxed<Result<BoxIter<Ipv4Addr>, DnsError>> {
        let fallback = self.fallback.clone();
        Box::pin(async move {
            let mut found: Vec<Ipv4Addr> = system(&host)
                .await
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                })
                .collect();
            if found.is_empty() {
                found = fallback
                    .lookup_ipv4(host, TIMEOUT)
                    .await?
                    .filter_map(|ip| match ip {
                        IpAddr::V4(v4) => Some(v4),
                        IpAddr::V6(_) => None,
                    })
                    .collect();
            }
            Ok(Box::new(found.into_iter()) as BoxIter<Ipv4Addr>)
        })
    }
    fn lookup_ipv6(&self, host: String) -> Boxed<Result<BoxIter<Ipv6Addr>, DnsError>> {
        let fallback = self.fallback.clone();
        Box::pin(async move {
            let mut found: Vec<Ipv6Addr> = system(&host)
                .await
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(v6),
                    IpAddr::V4(_) => None,
                })
                .collect();
            if found.is_empty() {
                found = fallback
                    .lookup_ipv6(host, TIMEOUT)
                    .await?
                    .filter_map(|ip| match ip {
                        IpAddr::V6(v6) => Some(v6),
                        IpAddr::V4(_) => None,
                    })
                    .collect();
            }
            Ok(Box::new(found.into_iter()) as BoxIter<Ipv6Addr>)
        })
    }
    fn lookup_txt(&self, host: String) -> Boxed<Result<BoxIter<TxtRecordData>, DnsError>> {
        let fallback = self.fallback.clone();
        Box::pin(async move {
            let found: Vec<TxtRecordData> = fallback.lookup_txt(host, TIMEOUT).await?.collect();
            Ok(Box::new(found.into_iter()) as BoxIter<TxtRecordData>)
        })
    }
    fn clear_cache(&self) {
        self.fallback.clear_cache();
    }
    fn reset(&self) -> Box<dyn Resolver> {
        // The system resolver keeps no state of ours; the fallback re-reads
        // its configuration on its own reset.
        self.fallback.reset();
        Box::new(self.clone())
    }
}
