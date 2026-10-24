//! Where a host's screens spend their time, printed every two seconds to
//! standard error when `BOUNDARY_STATS` is set, for measuring.
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

fn on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("BOUNDARY_STATS").is_some())
}

#[derive(Default)]
struct Counter {
    count: AtomicU64,
    micros: AtomicU64,
}
impl Counter {
    fn add(&self, took: Duration) {
        self.count.fetch_add(1, Relaxed);
        self.micros.fetch_add(took.as_micros() as u64, Relaxed);
    }
    fn take(&self) -> (u64, f64) {
        let n = self.count.swap(0, Relaxed);
        let us = self.micros.swap(0, Relaxed);
        (
            n,
            if n > 0 {
                us as f64 / n as f64 / 1000.0
            } else {
                0.0
            },
        )
    }
}

static CAPTURES: Counter = Counter {
    count: AtomicU64::new(0),
    micros: AtomicU64::new(0),
};
static CHANGED: Counter = Counter {
    count: AtomicU64::new(0),
    micros: AtomicU64::new(0),
};
static ENCODED: Counter = Counter {
    count: AtomicU64::new(0),
    micros: AtomicU64::new(0),
};
static WINDOW: Counter = Counter {
    count: AtomicU64::new(0),
    micros: AtomicU64::new(0),
};
static SENT: Counter = Counter {
    count: AtomicU64::new(0),
    micros: AtomicU64::new(0),
};
static SINCE: OnceLock<std::sync::Mutex<Instant>> = OnceLock::new();

pub(crate) fn captured(took: Duration, changed: bool) {
    if !on() {
        return;
    }
    CAPTURES.add(took);
    if changed {
        CHANGED.add(took);
    }
    report();
}
pub(crate) fn encoded(took: Duration) {
    if on() {
        ENCODED.add(took);
    }
}
pub(crate) fn waited(took: Duration) {
    if on() {
        WINDOW.add(took);
    }
}
pub(crate) fn sent(took: Duration) {
    if on() {
        SENT.add(took);
    }
}
fn report() {
    let since = SINCE.get_or_init(|| std::sync::Mutex::new(Instant::now()));
    let mut since = since.lock().unwrap_or_else(|e| e.into_inner());
    let secs = since.elapsed().as_secs_f64();
    if secs < 2.0 {
        return;
    }
    *since = Instant::now();
    let (c, cms) = CAPTURES.take();
    let (ch, chms) = CHANGED.take();
    let (e, ems) = ENCODED.take();
    let (w, wms) = WINDOW.take();
    let (s, sms) = SENT.take();
    eprintln!(
        "STATS captures {:.1}/s {:.1} ms | changed {:.1}/s {:.1} ms | encoded {:.1}/s {:.1} ms | window waits {:.1}/s {:.1} ms | writes {:.1}/s {:.1} ms",
        c as f64 / secs,
        cms,
        ch as f64 / secs,
        chms,
        e as f64 / secs,
        ems,
        w as f64 / secs,
        wms,
        s as f64 / secs,
        sms
    );
}
