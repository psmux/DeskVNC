//! Time as an argument, never as an ambient fact.
//!
//! Nothing in this crate calls `Instant::now()`. Every rule that depends on
//! the clock (hard expiry, idle revocation, the disconnect grace, the queue
//! time to live, the preemption deadline) takes the instant from its caller,
//! so the whole of §5.4 can be tested by handing the same state two different
//! numbers. The alternative is a test that sleeps, and a test that sleeps is
//! a test that goes red on a loaded CI box for reasons that have nothing to
//! do with arbitration.
//!
//! ## Why a millisecond newtype and not `std::time::Instant`
//!
//! `Instant` is opaque by design: it can only be obtained from the real
//! clock, so a test cannot say "pretend it is now two minutes later" without
//! anchoring itself to wall time and then adding to it, and it cannot express
//! an instant before the process started at all. It is also not
//! serialisable, and `10 §3` wants every lease change to reach a trace with
//! the time it happened on it. A `u64` of milliseconds is constructible,
//! orderable, printable and serialisable, and milliseconds are the unit
//! `08 §5.4` already states every default in.
//!
//! The origin is deliberately unspecified. This crate never compares an
//! instant to anything but another instant from the same caller, so the only
//! thing the caller owes is monotonicity within one limb.

/// A count of milliseconds. Every duration in `08 §5.4` is quoted in these,
/// so they are the unit rather than something to convert into.
pub type Millis = u64;

/// A point on the caller's clock, in milliseconds from an origin the caller
/// picks.
///
/// Arithmetic saturates. A caller that hands in a `now` older than the one it
/// handed in last (which happens the moment two threads read a clock and the
/// later read arrives first) gets an elapsed time of zero rather than a panic
/// in debug and a wrapped enormous number in release. Zero is the safe
/// answer: it never expires a lease early, and expiring a lease early is the
/// failure that takes a machine away from somebody who is still using it.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct LeaseInstant(u64);

impl LeaseInstant {
    /// The zero point. Useful in tests, and as the "never" that a freshly
    /// built lease starts from.
    pub const ORIGIN: LeaseInstant = LeaseInstant(0);

    /// Build an instant from a millisecond count on the caller's clock.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        LeaseInstant(ms)
    }

    /// The raw millisecond count, for a trace or a UI.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// This instant moved forward by `d`. Saturates at the top of the range.
    #[must_use]
    pub const fn plus(self, d: Millis) -> Self {
        LeaseInstant(self.0.saturating_add(d))
    }

    /// How long has passed since `earlier`, or zero if `earlier` is in fact
    /// later (see the type's note on a clock that goes backwards).
    #[must_use]
    pub const fn since(self, earlier: Self) -> Millis {
        self.0.saturating_sub(earlier.0)
    }

    /// Has this instant reached `deadline`?
    ///
    /// Deliberately inclusive. A timer quoted as "60000 ms" fires at exactly
    /// 60000, because the alternative is a rule that can only be tested by
    /// adding one millisecond to every expectation, which is the kind of
    /// off by one that survives review.
    #[must_use]
    pub const fn reached(self, deadline: Self) -> bool {
        self.0 >= deadline.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_never_goes_negative() {
        let later = LeaseInstant::from_millis(100);
        let earlier = LeaseInstant::from_millis(400);
        assert_eq!(later.since(earlier), 0);
    }

    #[test]
    fn deadlines_are_inclusive() {
        let deadline = LeaseInstant::from_millis(60_000);
        assert!(!LeaseInstant::from_millis(59_999).reached(deadline));
        assert!(LeaseInstant::from_millis(60_000).reached(deadline));
    }

    #[test]
    fn addition_saturates_rather_than_wrapping() {
        let late = LeaseInstant::from_millis(u64::MAX - 1);
        assert_eq!(late.plus(1_000).as_millis(), u64::MAX);
    }
}
