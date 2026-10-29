//! How much a host may have on its way to a helper, and how fast video may
//! go, from what the helper's acknowledgements say about the link.
//!
//! The congestion window was the limit before. On a link that queues deeply,
//! a VPN tunnel or a home router, the window keeps growing until packets are
//! lost, and by then seconds of screens wait in the queue: Chennai to an
//! iMac in the US over Cloudflare WARP showed a 300 ms link with 2.4 s of
//! lag at p90 while video moved. So the pacer times every update from its
//! write to the helper saying it was shown. The quickest of those over the
//! last few seconds is the link without a queue; the bytes the helper took
//! over the time they took is what the link carries. About two round trips
//! and a half of that may be on the way, and video aims under it, lower as soon as the
//! round trip grows past the quickest one and higher again, slowly, while it
//! does not. A link that changes speed is followed within a round trip.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long the quickest round trip is remembered. A route that changed for
/// good is picked up after this.
const MIN_RTT_WINDOW: Duration = Duration::from_secs(10);
/// How long the best delivery rate is remembered. Short, so a link that got
/// slower is believed within a couple of seconds.
const RATE_WINDOW: Duration = Duration::from_secs(2);
/// Round trips of data allowed on the way: one fills the link, the half
/// covers a helper's decoding and acknowledgements that bunch up.
const IN_FLIGHT_GAIN: f64 = 1.5;
/// Round trips allowed on the way while nothing queues, to find out
/// whether the link carries more.
const PROBE_GAIN: f64 = 2.5;
/// A sender that has not waited for room for this long has stopped filling
/// the link.
const FULL_FOR: Duration = Duration::from_secs(1);
/// Video bit rate never goes below or above these.
pub(crate) const MIN_BITRATE: f64 = 300_000.0;
pub(crate) const MAX_BITRATE: f64 = 16_000_000.0;

struct Sent {
    seq: u64,
    bytes: u64,
    at: Instant,
    /// Bytes the helper had taken when this one was written.
    delivered: u64,
    delivered_at: Instant,
}

pub(crate) struct Pace {
    sent: VecDeque<Sent>,
    /// Bytes the helper has said it took, in all.
    delivered: u64,
    delivered_at: Instant,
    /// Round trips seen, quickest kept: (when, round trip).
    rtts: VecDeque<(Instant, Duration)>,
    /// Delivery rates seen, best kept: (when, bits a second).
    rates: VecDeque<(Instant, f64)>,
    /// The latest delivery rates, smoothed.
    recent: Option<f64>,
    /// The latest round trips with the time to put their bytes on the wire
    /// taken off, smoothed: what the queue adds is this less the quickest.
    smoothed: Option<Duration>,
    /// What video aims at, in bits a second, once the link has been seen.
    target: Option<f64>,
    /// When the target last moved, so it moves once a round trip at most.
    moved: Instant,
    /// What the congestion window said video could have, the start before
    /// the pacer has seen enough.
    fallback: f64,
    /// Since when, and until when, the sender has had to wait for room.
    /// Only a couple of round trips into that does what arrives say what
    /// the link can carry; while a pointer moves, and just after, it says
    /// only how little was sent.
    full: Option<(Instant, Instant)>,
}

impl Pace {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            sent: VecDeque::new(),
            delivered: 0,
            delivered_at: now,
            rtts: VecDeque::new(),
            rates: VecDeque::new(),
            recent: None,
            smoothed: None,
            target: None,
            moved: now,
            fallback: MAX_BITRATE,
            full: None,
        }
    }

    pub(crate) fn on_send(&mut self, seq: u64, bytes: u64, now: Instant) {
        self.sent.push_back(Sent {
            seq,
            bytes,
            at: now,
            delivered: self.delivered,
            delivered_at: self.delivered_at,
        });
    }

    /// The helper has shown everything up to `acked`.
    pub(crate) fn on_ack(&mut self, acked: u64, now: Instant) {
        while self.sent.front().is_some_and(|s| s.seq <= acked) {
            let s = self.sent.pop_front().expect("checked above");
            self.delivered += s.bytes;
            self.delivered_at = now;
            let rtt = now.saturating_duration_since(s.at);
            // As BBR does: what arrived since this one left, over the longer
            // of the time it took to send and the time it took to arrive.
            let span = now
                .saturating_duration_since(s.delivered_at)
                .max(rtt)
                .max(Duration::from_millis(1));
            let rate = (self.delivered - s.delivered) as f64 * 8.0 / span.as_secs_f64();
            push_best(&mut self.rates, now, rate, RATE_WINDOW, |new, old| {
                new >= old
            });
            self.recent = Some(self.recent.map_or(rate, |old| (old * 3.0 + rate) / 4.0));
            push_best(&mut self.rtts, now, rtt, MIN_RTT_WINDOW, |new, old| {
                new <= old
            });
            // A big update spends time going onto the wire, which is not
            // queueing; take it off before judging the queue.
            let wire = self.rate().map_or(Duration::ZERO, |r| {
                Duration::from_secs_f64(s.bytes as f64 * 8.0 / r)
            });
            let seen = rtt.saturating_sub(wire);
            self.smoothed = Some(match self.smoothed {
                Some(old) => (old * 7 + seen) / 8,
                None => seen,
            });
        }
        self.steer(now);
    }

    /// The sender is waiting for room.
    pub(crate) fn on_full(&mut self, now: Instant) {
        self.full = Some(match self.full {
            Some((since, last)) if now.saturating_duration_since(last) < FULL_FOR => (since, now),
            _ => (now, now),
        });
    }

    /// Updates waiting to be shown.
    pub(crate) fn count(&self) -> usize {
        self.sent.len()
    }

    /// Bytes waiting to be shown.
    pub(crate) fn bytes(&self) -> u64 {
        self.sent.iter().map(|s| s.bytes).sum()
    }

    /// The quickest round trip lately.
    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        self.rtts.front().map(|(_, rtt)| *rtt)
    }

    /// What the link has carried lately, in bits a second.
    pub(crate) fn rate(&self) -> Option<f64> {
        self.rates.front().map(|(_, rate)| *rate)
    }

    /// Bytes that may be on their way, never more than the congestion
    /// window allows. With no queue, two and a half round trips of what the
    /// link has carried, so a host that was sending little, a pointer and
    /// then a scroll, finds the link's speed in a few round trips: at one and
    /// a half that took ten seconds on the i5. With a little queue, one and a
    /// half. Once it has queued, one round trip of what arrives now, so a
    /// link that just got slower is not handed seconds of screens at the old
    /// rate.
    pub(crate) fn limit(&self, window: u64, floor: u64) -> u64 {
        match (self.rate(), self.min_rtt(), self.queue()) {
            (Some(best), Some(rtt), queue) => {
                let queue = queue.unwrap_or_default();
                let (rate, gain) = match self.recent {
                    Some(recent) if queue > allowed(rtt) => (recent.min(best), 1.0),
                    _ if queue > allowed(rtt) / 2 => (best, IN_FLIGHT_GAIN),
                    _ => (best, PROBE_GAIN),
                };
                let bdp = rate / 8.0 * rtt.as_secs_f64() * gain;
                (bdp as u64).clamp(floor, window.max(floor))
            }
            _ => window,
        }
    }

    /// The bit rate video should aim at, or `fallback` before the link has
    /// been seen.
    pub(crate) fn bitrate(&mut self, fallback: u32) -> u32 {
        self.fallback = fallback as f64;
        match self.target {
            Some(t) => t.min(fallback.max(MIN_BITRATE as u32) as f64) as u32,
            None => fallback,
        }
    }

    /// How long the queue makes each screen wait now.
    pub(crate) fn queue(&self) -> Option<Duration> {
        Some(self.smoothed?.saturating_sub(self.min_rtt()?))
    }

    fn steer(&mut self, now: Instant) {
        let (Some(rate), Some(rtt), Some(queue)) = (self.rate(), self.min_rtt(), self.queue())
        else {
            return;
        };
        let target = *self
            .target
            .get_or_insert(self.fallback.clamp(MIN_BITRATE, MAX_BITRATE));
        if now.saturating_duration_since(self.moved) < rtt.max(Duration::from_millis(50)) {
            return;
        }
        // What arrives is a ceiling only once the sender has kept the link
        // full for a couple of round trips.
        let full = self.full.is_some_and(|(since, last)| {
            now.saturating_duration_since(last) < FULL_FOR
                && now.saturating_duration_since(since) > rtt * 2
        });
        let ceiling = if full { rate } else { f64::INFINITY };
        // A little queue is normal; past it, back off by how bad it is.
        let allowed = allowed(rtt);
        let next = if queue > allowed * 3 {
            target * 0.6
        } else if queue > allowed {
            target * 0.85
        } else if queue > allowed / 2 {
            // A queue starting: hold, and come down to what arrives.
            target.min(ceiling * 1.05)
        } else {
            // Room: climb, though not far past what the link has shown.
            (target * 1.12).min(ceiling * 1.25)
        };
        self.target = Some(next.clamp(MIN_BITRATE, MAX_BITRATE));
        self.moved = now;
    }
}

/// The queue a link may have before video backs off.
fn allowed(rtt: Duration) -> Duration {
    (rtt / 4).max(Duration::from_millis(40))
}

/// Keep `value` in a windowed best-of, oldest first, where `better` says the
/// new value beats an old one. The front is the best in the window.
fn push_best<T: Copy>(
    list: &mut VecDeque<(Instant, T)>,
    now: Instant,
    value: T,
    window: Duration,
    better: impl Fn(T, T) -> bool,
) {
    while list.back().is_some_and(|(_, old)| better(value, *old)) {
        list.pop_back();
    }
    list.push_back((now, value));
    while list
        .front()
        .is_some_and(|(at, _)| now.saturating_duration_since(*at) > window)
    {
        list.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link with a queue in front of it, sent a picture every 16 ms at
    /// the pacer's bit rate whenever the pacer allows.
    struct Link {
        pace: Pace,
        now: Instant,
        seq: u64,
        /// When the link has finished with what is queued.
        free: Instant,
        arrivals: VecDeque<(Instant, u64)>,
        bits: f64,
        base: Duration,
        /// Sending pictures; when not, a small update a second, as a pointer.
        busy: bool,
    }
    impl Link {
        fn new() -> Self {
            let now = Instant::now();
            Self {
                pace: Pace::new(now),
                now,
                seq: 0,
                free: now,
                arrivals: VecDeque::new(),
                bits: 1e6,
                busy: true,
                base: Duration::ZERO,
            }
        }
        fn run(&mut self, bits: f64, base: Duration, secs: u64) {
            self.bits = bits;
            self.base = base;
            self.run_for(Duration::from_secs(secs));
        }
        fn run_for(&mut self, time: Duration) {
            let (bits, base) = (self.bits, self.base);
            let end = self.now + time;
            while self.now < end {
                while self.arrivals.front().is_some_and(|(at, _)| *at <= self.now) {
                    let (_, seq) = self.arrivals.pop_front().unwrap();
                    self.pace.on_ack(seq, self.now);
                }
                let room = self.pace.count() == 0
                    || self.pace.bytes() < self.pace.limit(4_000_000, 128 * 1024);
                if !room {
                    self.pace.on_full(self.now);
                }
                // Idle, a pointer's update a second.
                let due = self.busy || self.seq.is_multiple_of(60);
                if room && due {
                    let bytes = if self.busy {
                        (self.pace.bitrate(6_000_000) as f64 / 8.0 / 60.0) as u64
                    } else {
                        3000
                    };
                    self.seq += 1;
                    self.pace.on_send(self.seq, bytes, self.now);
                    self.free = self.free.max(self.now)
                        + Duration::from_secs_f64(bytes as f64 * 8.0 / bits);
                    self.arrivals.push_back((self.free + base, self.seq));
                } else if !self.busy {
                    self.seq += 1;
                    self.pace.on_send(self.seq, 0, self.now);
                    self.arrivals.push_back((self.now + base, self.seq));
                }
                self.now += Duration::from_millis(16);
            }
        }
        /// How long a picture sent now would wait in the queue.
        fn waiting(&self) -> Duration {
            self.free.saturating_duration_since(self.now)
        }
    }

    #[test]
    fn a_slow_link_gets_a_short_queue() {
        let mut link = Link::new();
        // 4 Mbit/s with a 300 ms round trip, as a phone tether to the US.
        link.run(4e6, Duration::from_millis(300), 10);
        let (mut worst, mut sent) = (Duration::ZERO, 0);
        for _ in 0..100 {
            let before = link.pace.delivered;
            link.run(4e6, Duration::from_millis(300), 0);
            link.run_for(Duration::from_millis(100));
            worst = worst.max(link.waiting());
            sent += link.pace.delivered - before;
        }
        assert!(
            worst < Duration::from_millis(250),
            "queue reached {worst:?}"
        );
        // Most of the link is used: 10 s at 4 Mbit/s is 5 MB.
        assert!(sent > 3_500_000, "{sent} bytes in 10 s");
        let rtt = link.pace.min_rtt().unwrap();
        assert!(rtt >= Duration::from_millis(300) && rtt < Duration::from_millis(400));
    }

    #[test]
    fn a_link_that_slows_down_is_followed() {
        let mut link = Link::new();
        link.run(8e6, Duration::from_millis(300), 15);
        let before = link.pace.bitrate(6_000_000);
        link.run(1.5e6, Duration::from_millis(300), 10);
        let after = link.pace.bitrate(6_000_000);
        assert!(after < before, "{after} after {before}");
        assert!(after <= 1_650_000, "rate {after} on a 1.5 Mbit/s link");
        assert!(
            link.waiting() < Duration::from_millis(400),
            "queue {:?}",
            link.waiting()
        );
    }

    #[test]
    fn a_link_that_speeds_up_is_climbed() {
        let mut link = Link::new();
        link.run(1.5e6, Duration::from_millis(100), 10);
        let before = link.pace.bitrate(6_000_000);
        link.run(20e6, Duration::from_millis(100), 15);
        let after = link.pace.bitrate(6_000_000);
        assert!(after > before * 2, "{after} after {before}");
    }

    #[test]
    fn a_quiet_spell_does_not_hold_video_down() {
        let mut link = Link::new();
        link.run(8e6, Duration::from_millis(300), 5);
        // A pointer moving for ten seconds sends next to nothing.
        link.busy = false;
        link.run(8e6, Duration::from_millis(300), 10);
        link.busy = true;
        link.run(8e6, Duration::from_millis(300), 2);
        let rate = link.pace.bitrate(6_000_000);
        assert!(rate >= 3_000_000, "video at {rate} two seconds into motion");
    }

    #[test]
    fn before_any_acknowledgement_the_window_rules() {
        let mut pace = Pace::new(Instant::now());
        assert_eq!(pace.limit(500_000, 128 * 1024), 500_000);
        assert_eq!(pace.bitrate(2_000_000), 2_000_000);
    }
}
