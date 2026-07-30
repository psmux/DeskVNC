//! Linux keyboard capture (PRD/06 §3 Tier 2).
//!
//! # X11
//!
//! `XGrabKeyboard` on the focused window takes the whole keyboard away from the
//! window manager, which is what makes Alt+Tab and the compositor's shortcuts
//! reach the remote instead. The grab is requested with `owner_events = true`,
//! so key events are still delivered normally to *our* windows, the webview
//! keeps receiving them through the existing Tier 1 path, and this backend
//! forwards nothing on the channel. That is deliberate: on X11 the grab alone
//! is the whole feature, and routing keys through a second path would deliver
//! everything twice.
//!
//! # Wayland
//!
//! **There are no global keyboard grabs on Wayland.** The protocol has no
//! equivalent of `XGrabKeyboard`; the nearest thing,
//! `zwp_keyboard_shortcuts_inhibit_manager_v1`, is a compositor-optional
//! extension that must be driven from the toolkit that owns the surface, and it
//! is not reachable from here. Every Wayland remote-desktop client shares this
//! limitation.
//!
//! So Wayland reports [`CaptureStatus::Unsupported`] with an explanation the UI
//! can show, rather than pretending to work. Under XWayland the client would
//! *appear* to be on X11 while the compositor still ate the shortcuts, so
//! `WAYLAND_DISPLAY` is checked first and wins.

use crossbeam_channel::Sender;

use crate::{CapturedKey, KeyboardCapture, NoopCapture, Result};

pub const WAYLAND_REASON: &str = "Wayland does not allow global keyboard grabs";

/// Are we on a Wayland session? Checked before anything X11, because an
/// XWayland client can talk X11 while the compositor still owns the shortcuts.
pub fn is_wayland() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
}

/// Build the Linux backend: an X11 grab where possible, an honest
/// "unsupported" everywhere else.
///
/// The channel is unused on this platform, see the module docs: the X11 grab
/// leaves normal event delivery intact, so keys reach the remote through the
/// webview's existing path rather than being forwarded here.
pub fn create(_tx: Sender<CapturedKey>) -> Result<Box<dyn KeyboardCapture>> {
    if is_wayland() {
        return Ok(Box::new(NoopCapture::new(WAYLAND_REASON)));
    }
    #[cfg(feature = "x11")]
    {
        Ok(Box::new(x11::X11Capture::new()))
    }
    #[cfg(not(feature = "x11"))]
    {
        Ok(Box::new(NoopCapture::new(
            "this build was compiled without X11 support, so system shortcuts cannot be captured",
        )))
    }
}

#[cfg(feature = "x11")]
mod x11 {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{ConnectionExt, GrabMode, GrabStatus};
    use x11rb::rust_connection::RustConnection;

    use crate::{CaptureStatus, Error, KeyboardCapture, Result};

    /// An active `XGrabKeyboard` on the focused window.
    ///
    /// The connection is owned here so that dropping the backend closes it,
    /// which the X server treats as an implicit ungrab, the keyboard cannot
    /// stay grabbed past the life of this object even if `stop` never runs.
    pub struct X11Capture {
        conn: Option<RustConnection>,
        grabbed: bool,
        error: Option<String>,
    }

    impl X11Capture {
        pub fn new() -> Self {
            Self {
                conn: None,
                grabbed: false,
                error: None,
            }
        }

        fn connect(&mut self) -> Result<&RustConnection> {
            if self.conn.is_none() {
                let (conn, _screen) = x11rb::connect(None)
                    .map_err(|e| Error::Backend(format!("cannot connect to the X server: {e}")))?;
                self.conn = Some(conn);
            }
            Ok(self.conn.as_ref().expect("just connected"))
        }
    }

    impl KeyboardCapture for X11Capture {
        fn start(&mut self) -> Result<()> {
            if self.grabbed {
                return Ok(()); // idempotent
            }
            self.error = None;
            let conn = self.connect()?;

            // Grab on whatever window currently has input focus, that is our
            // session window when the user toggles pass-through, and it saves
            // plumbing a native window handle down from Tauri.
            let focus = conn
                .get_input_focus()
                .map_err(|e| Error::Backend(format!("GetInputFocus failed: {e}")))?
                .reply()
                .map_err(|e| Error::Backend(format!("GetInputFocus failed: {e}")))?
                .focus;

            // `owner_events = true` keeps normal delivery to our own windows,
            // so the webview still sees the keys; the grab's only job is to
            // take them away from the window manager.
            let reply = conn
                .grab_keyboard(
                    true,
                    focus,
                    x11rb::CURRENT_TIME,
                    GrabMode::ASYNC,
                    GrabMode::ASYNC,
                )
                .map_err(|e| Error::Backend(format!("XGrabKeyboard failed: {e}")))?
                .reply()
                .map_err(|e| Error::Backend(format!("XGrabKeyboard failed: {e}")))?;

            if reply.status != GrabStatus::SUCCESS {
                let reason = format!(
                    "the X server refused the keyboard grab ({:?})",
                    reply.status
                );
                self.error = Some(reason.clone());
                return Err(Error::Backend(reason));
            }
            let _ = conn.flush();
            self.grabbed = true;
            tracing::info!("X11 keyboard grab active");
            Ok(())
        }

        fn stop(&mut self) {
            if !self.grabbed {
                return;
            }
            self.grabbed = false;
            if let Some(conn) = self.conn.as_ref() {
                // Best effort by design: if the server or connection is already
                // gone the grab died with it, and there is nothing left to
                // release. Never panic on the release path.
                let _ = conn.ungrab_keyboard(x11rb::CURRENT_TIME);
                let _ = conn.flush();
            }
            tracing::info!("X11 keyboard grab released");
        }

        fn status(&self) -> CaptureStatus {
            if self.grabbed {
                CaptureStatus::Active
            } else {
                CaptureStatus::Inactive
            }
        }
    }

    impl Drop for X11Capture {
        fn drop(&mut self) {
            self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wayland_detection_reads_the_environment() {
        // Not asserted against the live environment (CI may be either), just
        // that the check is consistent with the variable it documents.
        let expected = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
        assert_eq!(is_wayland(), expected);
    }

    #[test]
    fn wayland_backend_is_honest_about_being_unsupported() {
        let mut backend = NoopCapture::new(WAYLAND_REASON);
        backend.start().unwrap();
        assert_eq!(
            backend.status(),
            crate::CaptureStatus::Unsupported {
                reason: WAYLAND_REASON
            }
        );
    }
}
