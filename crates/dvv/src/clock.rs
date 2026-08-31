//! The one place this binary reads a clock.
//!
//! `limb-core`, `agent-lease` and `agent-perception` all take time as an
//! argument and read no clock at all, and `agent-plane`'s crate root says why
//! that leaves the runtime holding it: `agent_lease::LeaseInstant` takes its
//! origin from the caller and `limb_core::observation::Timestamp` is unix
//! milliseconds, so a caller that uses unix milliseconds as the lease origin
//! gets two types that agree.
//!
//! This crate is that caller, so both come from the same reading here and a
//! trace can join a lease change to an observation on the number
//! (`10 §3` wants exactly that).

use agent_lease::LeaseInstant;
use limb_core::observation::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

/// Unix milliseconds.
///
/// A clock before the epoch reads as zero rather than panicking. It is not a
/// real situation, and a panic in the path that stamps every observation would
/// take the whole attachment down for a machine whose date is wrong.
pub fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Now, for arbitration.
pub fn lease_now() -> LeaseInstant {
    LeaseInstant::from_millis(unix_millis())
}

/// Now, for an observation.
pub fn stamp() -> Timestamp {
    Timestamp(unix_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_clocks_are_the_same_number() {
        // Not an equality assertion between two calls, which would be flaky by
        // construction. What matters is that both are unix milliseconds on the
        // same scale, so a lease change and an observation taken in the same
        // millisecond join.
        let lease = lease_now().as_millis();
        let observed = stamp().0;
        assert!(
            observed >= lease,
            "the clock went backwards between two reads"
        );
        assert!(observed - lease < 1_000);
    }
}
