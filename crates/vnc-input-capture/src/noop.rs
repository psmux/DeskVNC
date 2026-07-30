//! Fallback backend: compiles everywhere, never grabs anything.
//!
//! Used so the crate builds on any target and the app degrades gracefully
//! instead of failing to start. Also the honest answer on Wayland, where no
//! global grab exists at all (PRD/06 §3 Tier 2).

use crate::{CaptureStatus, KeyboardCapture, Result};

/// A capture backend that does nothing and says so.
pub struct NoopCapture {
    /// `None` -> plain `Inactive`; `Some` -> `Unsupported` with this reason.
    reason: Option<&'static str>,
}

impl NoopCapture {
    /// A backend that reports `Unsupported { reason }`, for platforms where
    /// capture cannot work and the UI must explain why.
    pub fn new(reason: &'static str) -> Self {
        Self {
            reason: Some(reason),
        }
    }

    /// A backend that reports plain `Inactive`.
    pub fn inactive() -> Self {
        Self { reason: None }
    }
}

impl KeyboardCapture for NoopCapture {
    fn start(&mut self) -> Result<()> {
        // Deliberately `Ok`: an unsupported platform is not a failure the user
        // needs an error dialog for. `status()` tells the truth, and the caller
        // is documented to check it.
        Ok(())
    }

    fn stop(&mut self) {}

    fn status(&self) -> CaptureStatus {
        match self.reason {
            Some(reason) => CaptureStatus::Unsupported { reason },
            None => CaptureStatus::Inactive,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_backend_never_becomes_active() {
        let mut c = NoopCapture::inactive();
        assert_eq!(c.status(), CaptureStatus::Inactive);
        c.start().unwrap();
        assert_eq!(c.status(), CaptureStatus::Inactive);
        c.stop();
        assert_eq!(c.status(), CaptureStatus::Inactive);
    }

    #[test]
    fn unsupported_backend_keeps_reporting_its_reason() {
        let mut c = NoopCapture::new("Wayland does not allow global keyboard grabs");
        c.start().unwrap();
        assert_eq!(
            c.status(),
            CaptureStatus::Unsupported {
                reason: "Wayland does not allow global keyboard grabs"
            }
        );
    }
}
