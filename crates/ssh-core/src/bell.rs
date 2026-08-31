//! How often the terminal bell is allowed to ring.
//!
//! Detecting the bell is [`crate::modes::ModeTracker`]'s job (it is the only
//! thing in this crate that can tell an audible BEL from the BEL that
//! terminates an OSC string). What is left is the volume problem: a BEL is one
//! byte, so a remote can produce them faster than any UI can react to them.
//! `cat` of a binary file, a build printing a warning bell per error, or a
//! `find` over a filesystem with odd filenames all deliver thousands of them
//! inside a single 16 KB read. One event each would be thousands of channel
//! sends, thousands of IPC messages, and thousands of overlapping sound plays
//! for what the user experiences as a single burst of noise.

use std::time::{Duration, Instant};

/// The shortest gap between two bell events.
///
/// 250 ms is a sound length, not an arbitrary throttle. The system alert
/// sounds a UI plays for a bell run roughly a quarter of a second, so two
/// bells closer together than that are already one noise to the listener
/// however many events reach the UI. It also caps the cost at four events a
/// second no matter how fast the remote writes, which is what makes a binary
/// file dumped to the terminal harmless.
///
/// Not longer, because past this the limiter starts eating bells the user
/// meant to hear: pressing Tab twice at an ambiguous completion is two
/// deliberate bells and those presses can be half a second apart.
const QUIET_PERIOD: Duration = Duration::from_millis(250);

/// Leading-edge rate limiter for the terminal bell.
///
/// Leading edge, so the first bell of a burst rings at once: a bell that
/// arrives late is a bell attached to the wrong moment, and a lone bell (the
/// common case, a long build finishing) must be instant. Everything inside
/// the quiet period after it is dropped rather than queued, because a bell
/// that has been waiting 250 ms is telling the user about something that has
/// already scrolled past.
#[derive(Debug, Clone, Default)]
pub struct BellLimiter {
    /// When the last bell we let through rang, or `None` if none has.
    last: Option<Instant>,
}

impl BellLimiter {
    /// A limiter that will let the very next bell through.
    pub fn new() -> Self {
        Self { last: None }
    }

    /// A bell arrived at `now`: true when the caller should emit an event for
    /// it, false when it falls inside the quiet period after the last one.
    ///
    /// `now` is a parameter rather than an `Instant::now()` inside so a test
    /// can drive a flood through a whole second of wall clock without
    /// sleeping for it.
    #[must_use]
    pub fn ring(&mut self, now: Instant) -> bool {
        match self.last {
            Some(last) if now.duration_since(last) < QUIET_PERIOD => false,
            _ => {
                self.last = Some(now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_bell_rings_immediately() {
        let mut limiter = BellLimiter::new();
        assert!(limiter.ring(Instant::now()));
    }

    #[test]
    fn a_second_bell_inside_the_quiet_period_is_dropped() {
        let mut limiter = BellLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.ring(t0));
        assert!(!limiter.ring(t0 + Duration::from_millis(1)));
        assert!(!limiter.ring(t0 + QUIET_PERIOD - Duration::from_millis(1)));
    }

    /// The limiter exists to thin a burst, not to mute the bell: a build that
    /// finishes a minute after the last one still has to be heard.
    #[test]
    fn a_bell_after_the_quiet_period_rings_again() {
        let mut limiter = BellLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.ring(t0));
        assert!(limiter.ring(t0 + QUIET_PERIOD));
    }

    /// Dropped bells must not push the next allowed one further out, or a
    /// stream arriving faster than the quiet period would silence the bell
    /// for as long as it lasted.
    #[test]
    fn a_dropped_bell_does_not_extend_the_quiet_period() {
        let mut limiter = BellLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.ring(t0));
        for ms in 1..250 {
            assert!(!limiter.ring(t0 + Duration::from_millis(ms)));
        }
        assert!(limiter.ring(t0 + Duration::from_millis(250)));
    }
}
