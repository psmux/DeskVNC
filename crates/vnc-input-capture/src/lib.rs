//! Native OS-level keyboard capture for shortcut pass-through
//! (PRD/06 §3 **Tier 2**).
//!
//! Webviews cannot see OS-reserved combos, Cmd+Tab, Cmd+Space, the Windows
//! key, Alt+Tab, because the window server or shell consumes them first. This
//! crate installs the per-platform native hook that intercepts them so they can
//! be routed to the remote machine instead.
//!
//! ```no_run
//! let (tx, rx) = crossbeam_channel::unbounded();
//! let mut capture = vnc_input_capture::create(tx).expect("backend");
//! capture.start().expect("start");
//! // `Ok` does not mean active, a permission may still be missing:
//! match capture.status() {
//!     vnc_input_capture::CaptureStatus::Active => { /* forward rx to the session */ }
//!     other => println!("not capturing: {other:?}"),
//! }
//! capture.stop();
//! ```
//!
//! # Safety model
//!
//! A stuck grab that swallows the user's keyboard is unforgivable, so every
//! backend is built around these invariants:
//!
//! 1. **Capture is opt-in.** [`create`] never installs anything; nothing is
//!    hooked until [`KeyboardCapture::start`] is called, and no OS permission is
//!    requested until [`request_permission`] is called explicitly.
//! 2. **`stop()` is unconditional and idempotent.** It tears the hook down even
//!    if `start` failed, and it also runs from `Drop`, so a panic anywhere up
//!    the stack releases the keyboard while unwinding.
//! 3. **The capture thread cannot leak a live hook.** The tap/hook handle lives
//!    in a guard whose `Drop` disables it, and the thread body is wrapped in
//!    `catch_unwind`, so a panic *inside the callback* still releases.
//! 4. **The escape hatch is never swallowed.** `Ctrl+Alt+Shift+Esc` is excluded
//!    in [`should_intercept`] itself, independently of the app-level global
//!    shortcut that force-releases capture.
//! 5. **Only what is swallowed is forwarded**, so no key is delivered twice
//!    (see [`policy`](crate#modules) for why interception is selective).

mod controller;
mod keymap;
mod noop;
mod policy;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub use controller::CaptureController;
pub use keymap::{
    code_to_xt, evdev_to_xt, is_modifier, kvk_to_xt, windows_to_xt, x11_keycode_to_xt, xt,
    xt_to_code, xt_to_keysym, KEYS, MAC_KVK,
};
pub use noop::NoopCapture;
pub use policy::{should_intercept, HostOs, Modifiers};

use crossbeam_channel::Sender;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The OS permission needed for capture has not been granted. The caller
    /// should show the onboarding explanation and offer [`request_permission`].
    #[error("keyboard capture needs a permission that has not been granted")]
    PermissionRequired,
    /// This platform cannot support a global keyboard grab at all.
    #[error("keyboard capture is unavailable here: {0}")]
    Unsupported(&'static str),
    /// The platform API failed for some other reason.
    #[error("keyboard capture failed: {0}")]
    Backend(String),
}

/// What the capture backend is currently doing.
///
/// Serialized for the webview as an internally tagged, kebab-case object, /// `{"state":"active"}`, `{"state":"unsupported","reason":"…"}`, matching the
/// convention `vnc_core::SessionState` already uses on `session://event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum CaptureStatus {
    /// The hook is installed and OS shortcuts are being routed to the remote.
    Active,
    /// Nothing is hooked; the local machine keeps all its shortcuts.
    Inactive,
    /// Needs an OS permission the user must grant (macOS Accessibility).
    PermissionRequired,
    /// Platform cannot support global grabs (Wayland).
    Unsupported { reason: &'static str },
}

impl CaptureStatus {
    /// Is the keyboard actually grabbed right now?
    pub fn is_active(self) -> bool {
        matches!(self, CaptureStatus::Active)
    }
}

/// One intercepted key transition, ready to forward as an RFB key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct CapturedKey {
    /// Physical key as an XT set-1 scancode (matches vnc-core's scancode table).
    pub scancode: u32,
    /// Best-effort X11 keysym.
    pub keysym: u32,
    pub down: bool,
}

/// A platform keyboard-capture backend.
///
/// Implementors must make `stop` idempotent and safe to call from `Drop`, and
/// must leave the keyboard released once it returns.
pub trait KeyboardCapture: Send {
    /// Install the hook. Idempotent: starting an already-started capture is a
    /// no-op, not an error.
    fn start(&mut self) -> Result<()>;
    /// Remove the hook. Idempotent, infallible, and safe to call from `Drop`.
    fn stop(&mut self);
    /// The live status. Cheap enough to poll.
    fn status(&self) -> CaptureStatus;
}

/// Create the platform capture backend. Events are delivered on the channel.
///
/// Returning `Ok` does **not** mean capture is active, nothing is installed
/// until [`KeyboardCapture::start`], and even then the OS may refuse. Always
/// check [`KeyboardCapture::status`].
pub fn create(tx: Sender<CapturedKey>) -> Result<Box<dyn KeyboardCapture>> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacCapture::new(tx)))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsCapture::new(tx)))
    }
    #[cfg(target_os = "linux")]
    {
        linux::create(tx)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = tx;
        Ok(Box::new(NoopCapture::new(
            "keyboard capture is not implemented on this platform",
        )))
    }
}

/// Whether the OS permission needed for capture is currently granted.
///
/// Never prompts. On platforms with no permission gate (Windows, X11) this is
/// always `true`; on Wayland it is `false`, because no grant can help.
pub fn permission_granted() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::ax_trusted()
    }
    #[cfg(target_os = "linux")]
    {
        !linux::is_wayland()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        true
    }
}

/// Ask the OS to prompt for the capture permission (macOS only; no-op
/// elsewhere). Non-blocking.
///
/// PRD/06 §3: never call this at first launch, only when the user first turns
/// pass-through on, after explaining why. An unexplained Accessibility prompt
/// reads as spyware.
pub fn request_permission() {
    #[cfg(target_os = "macos")]
    {
        macos::request_accessibility();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_serializes_internally_tagged_kebab_case() {
        let json = |s: CaptureStatus| serde_json::to_string(&s).unwrap();
        assert_eq!(json(CaptureStatus::Active), r#"{"state":"active"}"#);
        assert_eq!(json(CaptureStatus::Inactive), r#"{"state":"inactive"}"#);
        assert_eq!(
            json(CaptureStatus::PermissionRequired),
            r#"{"state":"permission-required"}"#
        );
        assert_eq!(
            json(CaptureStatus::Unsupported { reason: "nope" }),
            r#"{"state":"unsupported","reason":"nope"}"#
        );
    }

    #[test]
    fn captured_key_serializes_flat() {
        let json = serde_json::to_string(&CapturedKey {
            scancode: 0x0f,
            keysym: 0xff09,
            down: true,
        })
        .unwrap();
        assert_eq!(json, r#"{"scancode":15,"keysym":65289,"down":true}"#);
    }

    #[test]
    fn only_active_counts_as_active() {
        assert!(CaptureStatus::Active.is_active());
        for s in [
            CaptureStatus::Inactive,
            CaptureStatus::PermissionRequired,
            CaptureStatus::Unsupported { reason: "x" },
        ] {
            assert!(!s.is_active());
        }
    }

    #[test]
    fn create_never_installs_anything() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let capture = create(tx).expect("backend should always be constructible");
        assert!(
            !capture.status().is_active(),
            "capture must be opt-in: create() must not grab the keyboard"
        );
    }
}
