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
//!
//! iroh's own client holds no thread, but each try opens sockets until it
//! times out, and with every try of every name going to it during an outage
//! the same host held more than 600 open files at moments. So the fallback
//! is shared the same way, and a name it could not find is not asked about
//! again for a few seconds.

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
/// How long a name nothing was found for is not asked about again.
const KEEP_MISSING: Duration = Duration::from_secs(10);
/// The most names with a lookup running at once, in each kind. Past this a
/// name the system is asked about goes straight to iroh's client, and one
/// iroh's client is asked about fails at once.
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

/// What iroh's client said, shared by everyone who asked: the records, or
/// why there are none.
type Answer<T> = Result<Arc<Vec<T>>, Arc<str>>;
static FALLBACK_V4: LazyLock<Flights<Answer<Ipv4Addr>>> = LazyLock::new(Flights::default);
static FALLBACK_V6: LazyLock<Flights<Answer<Ipv6Addr>>> = LazyLock::new(Flights::default);
static FALLBACK_TXT: LazyLock<Flights<Answer<TxtRecordData>>> = LazyLock::new(Flights::default);

/// The operating system's resolver. Blocks.
fn system_lookup(host: &str) -> Vec<IpAddr> {
    (host, 0)
        .to_socket_addrs()
        .map(|found| found.map(|address| address.ip()).collect())
        .unwrap_or_default()
}

/// What is known about one name.
enum Slot<V> {
    /// A lookup is running, since `since`.
    Running {
        since: Instant,
        answer: watch::Receiver<Option<V>>,
    },
    /// The last lookup ended at `at`, and its answer stands for `keep`.
    Done {
        at: Instant,
        keep: Duration,
        value: V,
    },
}

/// Lookups of one kind, at most one running for each name.
pub(crate) struct Flights<V> {
    slots: Arc<Mutex<HashMap<String, Slot<V>>>>,
}
impl<V> Clone for Flights<V> {
    fn clone(&self) -> Self {
        Self {
            slots: self.slots.clone(),
        }
    }
}
impl<V> Default for Flights<V> {
    fn default() -> Self {
        Self {
            slots: Arc::default(),
        }
    }
}

/// Handed to a lookup that was started, for its answer.
pub(crate) struct Finish<V> {
    slots: Arc<Mutex<HashMap<String, Slot<V>>>>,
    key: String,
    keep: fn(&V) -> Duration,
    tx: watch::Sender<Option<V>>,
}
impl<V: Clone> Finish<V> {
    fn send(self, value: V) {
        let keep = (self.keep)(&value);
        {
            let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            if keep.is_zero() {
                slots.remove(&self.key);
            } else {
                slots.insert(
                    self.key,
                    Slot::Done {
                        at: Instant::now(),
                        keep,
                        value: value.clone(),
                    },
                );
            }
        }
        let _ = self.tx.send(Some(value));
    }
}

/// What a caller found in the slots.
enum Seen<V> {
    Kept(V),
    Join(Instant, watch::Receiver<Option<V>>),
    Start,
}

impl<V: Clone + Send + Sync + 'static> Flights<V> {
    /// The answer for `key`, waiting at most `wait`. Joins a lookup already
    /// running for it rather than starting another, and a caller that stops
    /// waiting leaves that lookup to finish for the next one. A lookup that
    /// has already run longer than `wait` is not waited on. Otherwise
    /// `start` is called to begin one, which hands its answer to the
    /// [`Finish`] it is given; it says false when it could not begin. `keep`
    /// says how long an answer stands; zero keeps none.
    pub(crate) async fn get(
        &self,
        key: &str,
        wait: Duration,
        keep: fn(&V) -> Duration,
        start: impl FnOnce(Finish<V>) -> bool,
    ) -> Option<V> {
        let mut answer = {
            let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            let seen = match slots.get(key) {
                Some(Slot::Done { at, keep, value }) if at.elapsed() < *keep => {
                    Seen::Kept(value.clone())
                }
                // A lookup whose task went away, with the runtime it ran on,
                // answers nobody and is started again.
                Some(Slot::Running { since, answer }) if answer.has_changed().is_ok() => {
                    Seen::Join(*since, answer.clone())
                }
                _ => Seen::Start,
            };
            match seen {
                Seen::Kept(value) => return Some(value),
                Seen::Join(since, answer) => {
                    if since.elapsed() >= wait {
                        return None;
                    }
                    answer
                }
                Seen::Start => {
                    // Answers past their time are of no use to anyone.
                    slots.retain(|_, slot| match slot {
                        Slot::Running { answer, .. } => answer.has_changed().is_ok(),
                        Slot::Done { at, keep, .. } => at.elapsed() < *keep,
                    });
                    let running = slots
                        .values()
                        .filter(|slot| matches!(slot, Slot::Running { .. }))
                        .count();
                    if running >= MOST_RUNNING {
                        return None;
                    }
                    let (tx, rx) = watch::channel(None);
                    let finish = Finish {
                        slots: self.slots.clone(),
                        key: key.to_string(),
                        keep,
                        tx,
                    };
                    // The lookup cannot record its answer before this
                    // returns: it needs the lock held here.
                    if !start(finish) {
                        return None;
                    }
                    slots.insert(
                        key.to_string(),
                        Slot::Running {
                            since: Instant::now(),
                            answer: rx.clone(),
                        },
                    );
                    rx
                }
            }
        };
        match tokio::time::timeout(wait, answer.wait_for(Option::is_some)).await {
            Ok(Ok(value)) => value.clone(),
            _ => None,
        }
    }

    /// Drop the answers kept, after the network changed. A lookup still
    /// running stays, so asking again joins it rather than adding another.
    fn forget(&self) {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, slot| matches!(slot, Slot::Running { .. }));
    }
}

/// Blocking system lookups, each on a thread of its own, at most one running
/// for each name.
#[derive(Clone)]
pub(crate) struct Names {
    lookup: fn(&str) -> Vec<IpAddr>,
    flights: Flights<Arc<Vec<IpAddr>>>,
}

impl Names {
    pub(crate) fn new(lookup: fn(&str) -> Vec<IpAddr>) -> Self {
        Self {
            lookup,
            flights: Flights::default(),
        }
    }

    /// The addresses for `host`, or none if the system found none, did not
    /// answer within `wait`, or is still on an earlier try that has taken
    /// longer than that.
    pub(crate) async fn get(&self, host: &str, wait: Duration) -> Vec<IpAddr> {
        let lookup = self.lookup;
        let name = host.to_string();
        let start = move |finish: Finish<Arc<Vec<IpAddr>>>| {
            std::thread::Builder::new()
                .name("dns lookup".into())
                .spawn(move || finish.send(Arc::new(lookup(&name))))
                .is_ok()
        };
        self.flights
            .get(host, wait, keep_found, start)
            .await
            .map(|found| found.to_vec())
            .unwrap_or_default()
    }

    fn forget(&self) {
        self.flights.forget();
    }
}

fn keep_found(found: &Arc<Vec<IpAddr>>) -> Duration {
    if found.is_empty() {
        KEEP_MISSING
    } else {
        KEEP_FOUND
    }
}

/// iroh's client keeps what it found itself, for as long as the records
/// say, so only a failure is kept here.
fn keep_answer<T>(answer: &Answer<T>) -> Duration {
    match answer {
        Ok(_) => Duration::ZERO,
        Err(_) => KEEP_MISSING,
    }
}

/// Ask iroh's client through `flights`, so one query runs for `host`
/// however many callers want it.
async fn shared<T: Clone + Send + Sync + 'static>(
    flights: &Flights<Answer<T>>,
    host: &str,
    wait: Duration,
    run: impl Future<Output = Answer<T>> + Send + 'static,
) -> Result<Vec<T>, DnsError> {
    let start = move |finish: Finish<Answer<T>>| {
        tokio::spawn(async move { finish.send(run.await) });
        true
    };
    match flights.get(host, wait, keep_answer::<T>, start).await {
        Some(Ok(found)) => Ok(found.to_vec()),
        Some(Err(why)) => Err(failed(&why)),
        None => Err(failed("No answer in time")),
    }
}

fn failed(why: &str) -> DnsError {
    DnsError::from(n0_error::AnyError::from_string(why.to_string()))
}

fn why(error: DnsError) -> Arc<str> {
    error.to_string().into()
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
                let name = host.clone();
                let run = async move {
                    let found = fallback.lookup_ipv4(name, TIMEOUT).await.map_err(why)?;
                    Ok(Arc::new(
                        found
                            .filter_map(|ip| match ip {
                                IpAddr::V4(v4) => Some(v4),
                                IpAddr::V6(_) => None,
                            })
                            .collect(),
                    ))
                };
                found = shared(&FALLBACK_V4, &host, TIMEOUT, run).await?;
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
                let name = host.clone();
                let run = async move {
                    let found = fallback.lookup_ipv6(name, TIMEOUT).await.map_err(why)?;
                    Ok(Arc::new(
                        found
                            .filter_map(|ip| match ip {
                                IpAddr::V6(v6) => Some(v6),
                                IpAddr::V4(_) => None,
                            })
                            .collect(),
                    ))
                };
                found = shared(&FALLBACK_V6, &host, TIMEOUT, run).await?;
            }
            Ok(Box::new(found.into_iter()) as BoxIter<Ipv6Addr>)
        })
    }
    fn lookup_txt(&self, host: String) -> Boxed<Result<BoxIter<TxtRecordData>, DnsError>> {
        let fallback = self.fallback.clone();
        Box::pin(async move {
            let name = host.clone();
            let run = async move {
                let found = fallback.lookup_txt(name, TIMEOUT).await.map_err(why)?;
                Ok(Arc::new(found.collect()))
            };
            let found = shared(&FALLBACK_TXT, &host, TIMEOUT, run).await?;
            Ok(Box::new(found.into_iter()) as BoxIter<TxtRecordData>)
        })
    }
    fn clear_cache(&self) {
        forget_all();
        self.fallback.clear_cache();
    }
    fn reset(&self) -> Box<dyn Resolver> {
        // The answers kept here go, and the fallback re-reads its
        // configuration on its own reset.
        forget_all();
        self.fallback.reset();
        Box::new(self.clone())
    }
}

fn forget_all() {
    SYSTEM.forget();
    FALLBACK_V4.forget();
    FALLBACK_V6.forget();
    FALLBACK_TXT.forget();
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

    static ASKED: AtomicUsize = AtomicUsize::new(0);

    /// iroh's client is shared the same way: one query for a name however
    /// many callers want it, and a name it failed on is not asked about
    /// again straight away.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_fallback_runs_one_query_a_name_and_keeps_a_failure() {
        let flights: Flights<Answer<IpAddr>> = Flights::default();
        let answer = Arc::new(tokio::sync::Notify::new());
        for _ in 0..20 {
            let mut tries = tokio::task::JoinSet::new();
            for _ in 0..50 {
                let flights = flights.clone();
                let answer = answer.clone();
                tries.spawn(async move {
                    let run = async move {
                        ASKED.fetch_add(1, Ordering::SeqCst);
                        answer.notified().await;
                        Err(Arc::<str>::from("timed out"))
                    };
                    shared(
                        &flights,
                        "relay.example.com",
                        Duration::from_millis(20),
                        run,
                    )
                    .await
                });
            }
            for found in tries.join_all().await {
                assert!(found.is_err());
            }
        }
        assert_eq!(ASKED.load(Ordering::SeqCst), 1);
        answer.notify_waiters();
        tokio::time::sleep(Duration::from_millis(50)).await;
        for _ in 0..10 {
            let run = async {
                ASKED.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::new(Vec::new()))
            };
            let found = shared(&flights, "relay.example.com", Duration::from_secs(1), run).await;
            assert!(found.is_err());
        }
        assert_eq!(ASKED.load(Ordering::SeqCst), 1);
        flights.forget();
        let run = async {
            ASKED.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))]))
        };
        let found = shared(&flights, "relay.example.com", Duration::from_secs(1), run).await;
        assert_eq!(
            found.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))]
        );
        assert_eq!(ASKED.load(Ordering::SeqCst), 2);
    }
}
