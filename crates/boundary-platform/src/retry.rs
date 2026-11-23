//! Something made on first use that may not be makeable yet.

use boundary_session::InputUnavailable;
use std::time::{Duration, Instant};

/// How long a failed attempt stands before the next one.
pub(crate) const RETRY_AFTER: Duration = Duration::from_secs(2);

/// The input injector, made when the first event needs it. A Mac at its lock
/// screen or sign in screen cannot make one. While that lasts, each event gets
/// the last failure straight back, and a new attempt is made at most every
/// [`RETRY_AFTER`]: often enough that control comes back on its own soon
/// after someone unlocks the Mac, rarely enough that a stream of pointer
/// moves does not ask macOS sixty times a second.
pub(crate) struct Retry<T> {
    made: Option<T>,
    failed: Option<(Instant, InputUnavailable)>,
}
impl<T> Default for Retry<T> {
    fn default() -> Self {
        Self {
            made: None,
            failed: None,
        }
    }
}
impl<T> Retry<T> {
    /// What was made, making it with `make` if it is not made yet and the
    /// last failure is older than [`RETRY_AFTER`] at `now`.
    pub(crate) fn get(
        &mut self,
        now: Instant,
        make: impl FnOnce() -> Result<T, InputUnavailable>,
    ) -> Result<&mut T, InputUnavailable> {
        let made = match self.made.take() {
            Some(made) => made,
            None => {
                if let Some((at, why)) = &self.failed
                    && now.saturating_duration_since(*at) < RETRY_AFTER
                {
                    return Err(why.clone());
                }
                match make() {
                    Ok(made) => {
                        self.failed = None;
                        made
                    }
                    Err(why) => {
                        self.failed = Some((now, why.clone()));
                        return Err(why);
                    }
                }
            }
        };
        Ok(self.made.insert(made))
    }
    /// What was made, if it has been, without trying to make it.
    pub(crate) fn made(&mut self) -> Option<&mut T> {
        self.made.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boundary_session::InputTrouble;

    fn locked() -> InputUnavailable {
        InputUnavailable {
            trouble: InputTrouble::LockScreen,
            reason: "no connection could be established: (failed creating event source)".into(),
        }
    }

    #[test]
    fn a_failure_stands_until_it_is_old_enough_to_try_again() {
        let start = Instant::now();
        let mut retry = Retry::<u32>::default();
        let mut attempts = 0;
        let mut attempt = |works: bool| {
            attempts += 1;
            if works { Ok(7) } else { Err(locked()) }
        };
        assert_eq!(retry.get(start, || attempt(false)), Err(locked()));
        // Every event in the next two seconds gets the same answer, and
        // nothing is asked of the system for it.
        for ms in [1, 500, 1999] {
            let at = start + Duration::from_millis(ms);
            assert_eq!(
                retry.get(at, || panic!("tried again after {ms} ms")),
                Err(locked())
            );
        }
        // Two seconds on it is tried again, still locked, and that failure
        // stands for two more.
        let second = start + RETRY_AFTER;
        assert_eq!(retry.get(second, || attempt(false)), Err(locked()));
        assert_eq!(
            retry.get(second + Duration::from_millis(1500), || panic!(
                "tried again too soon"
            )),
            Err(locked())
        );
        // Unlocked: the next attempt makes it, and it is kept from then on.
        let third = second + RETRY_AFTER;
        assert_eq!(retry.get(third, || attempt(true)).copied(), Ok(7));
        assert_eq!(retry.get(third, || panic!("made twice")).copied(), Ok(7));
        assert_eq!(retry.made().copied(), Some(7));
        assert_eq!(attempts, 3);
    }

    #[test]
    fn nothing_is_made_before_it_is_needed() {
        let mut retry = Retry::<u32>::default();
        assert!(retry.made().is_none());
        assert_eq!(retry.get(Instant::now(), || Ok(1)).copied(), Ok(1));
    }
}
