//! Ownership state machine around a [`KeyboardCapture`] backend.
//!
//! Capture is global (one hook per process) but is requested *per session
//! window*. This tracks which session currently owns the grab so that:
//!
//! - a second session asking for capture takes it over cleanly rather than
//!   stacking two hooks,
//! - `stop` from a session that does **not** own capture cannot release
//!   somebody else's grab,
//! - [`release`](CaptureController::release), the blur / disconnect / window
//!   close / app exit / panic-recovery path, and the `Ctrl+Alt+Shift+Esc`
//!   escape hatch, always releases, from anywhere, idempotently.

use crate::{CaptureStatus, KeyboardCapture, Result};

/// Which session (if any) currently holds the keyboard.
pub struct CaptureController {
    backend: Box<dyn KeyboardCapture>,
    owner: Option<String>,
}

impl CaptureController {
    pub fn new(backend: Box<dyn KeyboardCapture>) -> Self {
        Self {
            backend,
            owner: None,
        }
    }

    /// Session id currently holding capture.
    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    /// Backend status, or `Inactive` when nothing owns capture.
    ///
    /// The owner check matters: a backend can report `Active` for a moment
    /// after a release request, and the UI indicator must never claim the
    /// keyboard is grabbed when we believe it is not.
    pub fn status(&self) -> CaptureStatus {
        if self.owner.is_none() {
            return CaptureStatus::Inactive;
        }
        self.backend.status()
    }

    /// Grab the keyboard for `session_id`.
    ///
    /// Idempotent for the same session. A different session takes ownership
    /// over (the previous owner's window has necessarily lost focus). If the
    /// backend refuses, ownership is *not* recorded, so nothing can later think
    /// it needs releasing.
    pub fn start(&mut self, session_id: &str) -> Result<CaptureStatus> {
        if self.owner.as_deref() == Some(session_id) {
            return Ok(self.status());
        }
        match self.backend.start() {
            Ok(()) => {
                self.owner = Some(session_id.to_string());
                Ok(self.backend.status())
            }
            Err(e) => {
                // Leave no half-owned state behind.
                self.backend.stop();
                self.owner = None;
                Err(e)
            }
        }
    }

    /// Release the keyboard **if** `session_id` owns it. A stop from a session
    /// that does not own capture is a no-op, not an error.
    pub fn stop(&mut self, session_id: &str) -> CaptureStatus {
        if self.owner.as_deref() == Some(session_id) {
            return self.release();
        }
        self.status()
    }

    /// Force-release, whoever owns it. Idempotent and infallible.
    ///
    /// This is the safety path: window blur, session disconnect, window close,
    /// app exit, and the `Ctrl+Alt+Shift+Esc` global shortcut all land here.
    pub fn release(&mut self) -> CaptureStatus {
        self.owner = None;
        self.backend.stop();
        CaptureStatus::Inactive
    }
}

impl Drop for CaptureController {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Default)]
    struct Counters {
        starts: AtomicUsize,
        stops: AtomicUsize,
    }

    struct MockBackend {
        counters: Arc<Counters>,
        running: bool,
        fail_with: Option<&'static str>,
    }

    impl MockBackend {
        fn new(counters: Arc<Counters>) -> Self {
            Self {
                counters,
                running: false,
                fail_with: None,
            }
        }
        fn failing(counters: Arc<Counters>) -> Self {
            Self {
                counters,
                running: false,
                fail_with: Some("no permission"),
            }
        }
    }

    impl KeyboardCapture for MockBackend {
        fn start(&mut self) -> Result<()> {
            self.counters.starts.fetch_add(1, Ordering::SeqCst);
            if self.fail_with.is_some() {
                return Err(Error::PermissionRequired);
            }
            self.running = true;
            Ok(())
        }
        fn stop(&mut self) {
            self.counters.stops.fetch_add(1, Ordering::SeqCst);
            self.running = false;
        }
        fn status(&self) -> CaptureStatus {
            if self.running {
                CaptureStatus::Active
            } else {
                CaptureStatus::Inactive
            }
        }
    }

    fn controller() -> (CaptureController, Arc<Counters>) {
        let counters = Arc::new(Counters::default());
        let backend = Box::new(MockBackend::new(counters.clone()));
        (CaptureController::new(backend), counters)
    }

    #[test]
    fn starts_inactive_and_unowned() {
        let (c, counters) = controller();
        assert_eq!(c.status(), CaptureStatus::Inactive);
        assert_eq!(c.owner(), None);
        assert_eq!(counters.starts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn start_grabs_and_records_the_owner() {
        let (mut c, counters) = controller();
        assert_eq!(c.start("s1").unwrap(), CaptureStatus::Active);
        assert_eq!(c.owner(), Some("s1"));
        assert_eq!(counters.starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn start_is_idempotent_for_the_same_session() {
        let (mut c, counters) = controller();
        c.start("s1").unwrap();
        c.start("s1").unwrap();
        c.start("s1").unwrap();
        assert_eq!(counters.starts.load(Ordering::SeqCst), 1);
        assert_eq!(c.owner(), Some("s1"));
    }

    #[test]
    fn another_session_takes_ownership_over() {
        let (mut c, counters) = controller();
        c.start("s1").unwrap();
        c.start("s2").unwrap();
        assert_eq!(c.owner(), Some("s2"));
        assert_eq!(counters.starts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn stop_from_a_non_owner_does_not_release() {
        let (mut c, counters) = controller();
        c.start("s1").unwrap();
        assert_eq!(c.stop("s2"), CaptureStatus::Active);
        assert_eq!(c.owner(), Some("s1"));
        assert_eq!(counters.stops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn stop_from_the_owner_releases() {
        let (mut c, counters) = controller();
        c.start("s1").unwrap();
        assert_eq!(c.stop("s1"), CaptureStatus::Inactive);
        assert_eq!(c.owner(), None);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stop_is_idempotent() {
        let (mut c, counters) = controller();
        c.start("s1").unwrap();
        c.stop("s1");
        c.stop("s1");
        c.stop("s1");
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
        assert_eq!(c.status(), CaptureStatus::Inactive);
    }

    #[test]
    fn release_always_releases_even_when_unowned() {
        let (mut c, counters) = controller();
        assert_eq!(c.release(), CaptureStatus::Inactive);
        c.start("s1").unwrap();
        assert_eq!(c.release(), CaptureStatus::Inactive);
        assert_eq!(c.release(), CaptureStatus::Inactive);
        assert_eq!(c.owner(), None);
        // Every release reaches the backend, this is the escape hatch, so it
        // must never be optimized into a no-op.
        assert_eq!(counters.stops.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn a_failed_start_leaves_nothing_owned_and_stops_the_backend() {
        let counters = Arc::new(Counters::default());
        let mut c = CaptureController::new(Box::new(MockBackend::failing(counters.clone())));
        let err = c.start("s1").unwrap_err();
        assert!(matches!(err, Error::PermissionRequired));
        assert_eq!(c.owner(), None);
        assert_eq!(c.status(), CaptureStatus::Inactive);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_failed_start_can_be_retried_after_the_permission_is_granted() {
        let counters = Arc::new(Counters::default());
        let mut c = CaptureController::new(Box::new(MockBackend::failing(counters.clone())));
        assert!(c.start("s1").is_err());
        // The owner was never recorded, so the retry is a real start, not the
        // idempotent no-op path.
        assert!(c.start("s1").is_err());
        assert_eq!(counters.starts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn status_is_inactive_once_released_even_if_the_backend_lags() {
        struct StickyBackend;
        impl KeyboardCapture for StickyBackend {
            fn start(&mut self) -> Result<()> {
                Ok(())
            }
            fn stop(&mut self) {}
            fn status(&self) -> CaptureStatus {
                CaptureStatus::Active // never reports going away
            }
        }
        let mut c = CaptureController::new(Box::new(StickyBackend));
        c.start("s1").unwrap();
        assert_eq!(c.status(), CaptureStatus::Active);
        c.release();
        assert_eq!(
            c.status(),
            CaptureStatus::Inactive,
            "the indicator must not claim the keyboard is grabbed after release"
        );
    }

    #[test]
    fn dropping_the_controller_releases() {
        let counters = Arc::new(Counters::default());
        {
            let mut c = CaptureController::new(Box::new(MockBackend::new(counters.clone())));
            c.start("s1").unwrap();
        }
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
    }
}
