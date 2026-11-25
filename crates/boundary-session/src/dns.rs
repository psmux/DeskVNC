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
//!
//! The system API blocks a thread until it has an answer, and cannot be
//! cancelled. During a DNS outage on a Mac each lookup held its thread for
//! about a minute, while iroh asked again every few hundred milliseconds
//! (its lookups are staggered, seven tries a name, and each network report
//! asks for every relay) and gave up on each after three seconds. The
//! threads that were given up on went on waiting, each holding a socket, so
//! the host at the sign in screen grew past 250 threads and ran out of open
//! files. So each name has at most one system lookup running, whoever asks;
//! everyone asking for it shares that one, and its answer is kept a while.

use iroh::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    pin::Pin,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

const TIMEOUT: Duration = Duration::from_secs(5);
/// How long the addresses the system found for a name are used again.
const KEEP_FOUND: Duration = Duration::from_secs(30);
/// How long a name the system found nothing for is not asked about again.
const KEEP_MISSING: Duration = Duration::from_secs(10);
/// The most names with a system lookup running at once. Past this a name
/// goes straight to iroh's client, which holds no thread.
const MOST_RUNNING: usize = 16;
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
    lookup(host, TIMEOUT).await
}

/// The addresses the operating system has for `host`, waiting at most
/// `wait`, with no more than one lookup running for it however often this
/// is called. Empty when it found none or took too long.
pub(crate) async fn lookup(host: &str, wait: Duration) -> Vec<IpAddr> {
    SYSTEM.get(host, wait).await
}

static SYSTEM: LazyLock<Names> = LazyLock::new(|| Names::new(system_lookup));

/// The operating system's resolver. Blocks.
fn system_lookup(host: &str) -> Vec<IpAddr> {
    (host, 0)
        .to_socket_addrs()
        .map(|found| found.map(|address| address.ip()).collect())
        .unwrap_or_default()
}

/// What is known about one name.
enum Slot {
    /// A lookup is running on its own thread, since `since`.
    Running {
        since: Instant,
        answer: watch::Receiver<Option<Arc<Vec<IpAddr>>>>,
    },
    /// The last lookup ended at `at`. Empty means it found nothing.
    Done {
        at: Instant,
        found: Arc<Vec<IpAddr>>,
    },
}

/// Blocking lookups, at most one running for each name.
#[derive(Clone)]
pub(crate) struct Names {
    lookup: fn(&str) -> Vec<IpAddr>,
    slots: Arc<Mutex<HashMap<String, Slot>>>,
}

impl Names {
    pub(crate) fn new(lookup: fn(&str) -> Vec<IpAddr>) -> Self {
        Self {
            lookup,
            slots: Arc::default(),
        }
    }

    /// The addresses for `host`, waiting at most `wait`. Joins a lookup
    /// already running for it rather than starting another, and a caller
    /// that stops waiting leaves that lookup to finish for the next one. A
    /// lookup that has already run longer than `wait` is not waited on.
    pub(crate) async fn get(&self, host: &str, wait: Duration) -> Vec<IpAddr> {
        let mut answer = {
            let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            match slots.get(host) {
                Some(Slot::Done { at, found }) => {
                    let keep = if found.is_empty() {
                        KEEP_MISSING
                    } else {
                        KEEP_FOUND
                    };
                    if at.elapsed() < keep {
                        return found.to_vec();
                    }
                    self.start(&mut slots, host)
                }
                Some(Slot::Running { since, answer }) => {
                    if since.elapsed() >= wait {
                        return Vec::new();
                    }
                    Some(answer.clone())
                }
                None => self.start(&mut slots, host),
            }
        };
        let Some(answer_rx) = answer.as_mut() else {
            return Vec::new();
        };
        match tokio::time::timeout(wait, answer_rx.wait_for(Option::is_some)).await {
            Ok(Ok(found)) => found.as_deref().map(|f| f.to_vec()).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Drop the answers kept, after the network changed. A lookup still
    /// running stays, so asking again joins it rather than adding a thread.
    fn forget(&self) {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, slot| matches!(slot, Slot::Running { .. }));
    }

    /// Start a lookup for `host` on a thread of its own, unless too many
    /// are running already.
    fn start(
        &self,
        slots: &mut HashMap<String, Slot>,
        host: &str,
    ) -> Option<watch::Receiver<Option<Arc<Vec<IpAddr>>>>> {
        // Answers past their time are of no use to anyone.
        slots.retain(|_, slot| match slot {
            Slot::Running { .. } => true,
            Slot::Done { at, .. } => at.elapsed() < KEEP_FOUND,
        });
        let running = slots
            .values()
            .filter(|slot| matches!(slot, Slot::Running { .. }))
            .count();
        if running >= MOST_RUNNING {
            return None;
        }
        let (tx, rx) = watch::channel(None);
        let lookup = self.lookup;
        let shared = self.slots.clone();
        let name = host.to_string();
        let started = std::thread::Builder::new()
            .name("dns lookup".into())
            .spawn(move || {
                let found = Arc::new(lookup(&name));
                shared.lock().unwrap_or_else(|e| e.into_inner()).insert(
                    name,
                    Slot::Done {
                        at: Instant::now(),
                        found: found.clone(),
                    },
                );
                let _ = tx.send(Some(found));
            });
        if started.is_err() {
            return None;
        }
        slots.insert(
            host.to_string(),
            Slot::Running {
                since: Instant::now(),
                answer: rx.clone(),
            },
        );
        Some(rx)
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
        SYSTEM.forget();
        self.fallback.clear_cache();
    }
    fn reset(&self) -> Box<dyn Resolver> {
        // The answers kept from the system go, and the fallback re-reads its
        // configuration on its own reset.
        SYSTEM.forget();
        self.fallback.reset();
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Condvar,
        atomic::{AtomicUsize, Ordering},
    };

    /// A resolver that does not answer until `open` is called, like one
    /// whose packets are dropped.
    struct Gate {
        open: Mutex<bool>,
        changed: Condvar,
        started: AtomicUsize,
        running: AtomicUsize,
    }
    impl Gate {
        const fn new() -> Self {
            Self {
                open: Mutex::new(false),
                changed: Condvar::new(),
                started: AtomicUsize::new(0),
                running: AtomicUsize::new(0),
            }
        }
        fn hang(&self) -> Vec<IpAddr> {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.running.fetch_add(1, Ordering::SeqCst);
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.changed.wait(open).unwrap();
            }
            self.running.fetch_sub(1, Ordering::SeqCst);
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]
        }
        fn open(&self) {
            *self.open.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    static OUTAGE: Gate = Gate::new();
    fn outage(_: &str) -> Vec<IpAddr> {
        OUTAGE.hang()
    }

    /// iroh asks for the same relay name over and over, each try its own
    /// task, and gives up on each within seconds. During an outage that must
    /// not add a thread each time, and once DNS answers the name is found.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_hanging_name_holds_one_thread_however_often_it_is_asked() {
        let names = Names::new(outage);
        for _ in 0..20 {
            let mut tries = tokio::task::JoinSet::new();
            for _ in 0..50 {
                let names = names.clone();
                tries.spawn(async move {
                    names
                        .get("relay.example.com", Duration::from_millis(20))
                        .await
                });
            }
            for found in tries.join_all().await {
                assert!(found.is_empty());
            }
        }
        assert_eq!(OUTAGE.started.load(Ordering::SeqCst), 1);
        assert_eq!(OUTAGE.running.load(Ordering::SeqCst), 1);
        OUTAGE.open();
        let mut found = Vec::new();
        for _ in 0..100 {
            found = names.get("relay.example.com", Duration::from_secs(1)).await;
            if !found.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(found, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]);
        // Kept, so asking again starts nothing.
        names.get("relay.example.com", Duration::from_secs(1)).await;
        assert_eq!(OUTAGE.started.load(Ordering::SeqCst), 1);
    }

    static MANY: Gate = Gate::new();
    fn many(_: &str) -> Vec<IpAddr> {
        MANY.hang()
    }

    /// Many names hanging at once still hold only so many threads.
    #[tokio::test]
    async fn names_hanging_at_once_are_capped() {
        let names = Names::new(many);
        for round in 0..3 {
            for n in 0..100 {
                let host = format!("host{n}.example.com");
                assert!(names.get(&host, Duration::from_millis(1)).await.is_empty());
            }
            assert_eq!(MANY.started.load(Ordering::SeqCst), MOST_RUNNING, "{round}");
        }
        MANY.open();
    }

    static MISSING: AtomicUsize = AtomicUsize::new(0);
    fn missing(_: &str) -> Vec<IpAddr> {
        MISSING.fetch_add(1, Ordering::SeqCst);
        Vec::new()
    }

    /// A name that has no address is not asked about again straight away,
    /// until the network changes.
    #[tokio::test]
    async fn a_missing_name_is_remembered_for_a_while() {
        let names = Names::new(missing);
        for _ in 0..10 {
            assert!(
                names
                    .get("gone.example.com", Duration::from_secs(1))
                    .await
                    .is_empty()
            );
        }
        assert_eq!(MISSING.load(Ordering::SeqCst), 1);
        names.forget();
        names.get("gone.example.com", Duration::from_secs(1)).await;
        assert_eq!(MISSING.load(Ordering::SeqCst), 2);
    }
}
