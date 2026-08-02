//! macOS keyboard capture via `CGEventTap` (PRD/06 §3 Tier 2).
//!
//! # How it works
//!
//! A tap is installed at `kCGHIDEventTap` with `kCGHeadInsertEventTap`, ahead
//! of the WindowServer's own shortcut handling, so it sees Cmd+Tab and
//! Cmd+Space *before* they are turned into a Dock switch or Spotlight. The
//! callback returns `NULL` for the events it wants, that is what deletes them
//! from the local machine and lets us forward them to the remote instead.
//!
//! The tap runs on a **dedicated thread with its own `CFRunLoop`**. It must
//! never go on the main thread: Tauri's event loop lives there, and a tap whose
//! run loop is busy rendering gets disabled by the OS for being slow.
//!
//! # Permissions
//!
//! An *intercepting* tap needs **Accessibility** (`AXIsProcessTrusted`); the
//! listen-only variant would only need Input Monitoring, but listen-only cannot
//! swallow, which is the entire point. `permission_granted` uses the
//! non-prompting check; only [`request_accessibility`] prompts, and it is only
//! ever called when the user turns pass-through on (PRD/06 §3: an unexplained
//! Accessibility prompt at first launch reads as spyware).
//!
//! Note also PRD/12 §1.1: TCC grants are bound to code identity, so re-signing
//! silently invalidates the grant, hence the status is re-read live rather
//! than cached at startup.
//!
//! # Secure Input
//!
//! If any app has secure event input enabled (a focused password field), taps
//! receive nothing at all. `IsSecureEventInputEnabled` detects it so the UI can
//! say *why* pass-through went quiet instead of looking broken.

use std::ffi::c_void;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use core_foundation::base::TCFType;
use core_foundation::mach_port::{CFMachPort, CFMachPortRef};
use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use core_graphics::event::{CGEventFlags, EventField};
use core_graphics::sys::CGEventRef;
use crossbeam_channel::Sender;
use parking_lot::Mutex;

use crate::keymap;
use crate::policy::{should_intercept_key, HeldKeys, HostOs, Modifiers};
use crate::{CaptureStatus, CapturedKey, Error, KeyboardCapture, Result};

// ---------------------------------------------------------------------------
// FFI
// ---------------------------------------------------------------------------
//
// `core_graphics::event::CGEventTap` cannot be used here: its safe callback
// wrapper treats `None` as "pass the original event through", so there is no
// way to return NULL and swallow. Swallowing is the whole feature, so the tap
// is created through the raw C API instead.

type CGEventTapProxy = *const c_void;
type CGEventMask = u64;
type CGEventTapCallback =
    unsafe extern "C" fn(CGEventTapProxy, u32, CGEventRef, *mut c_void) -> CGEventRef;

const K_CG_HID_EVENT_TAP: u32 = 0;
const K_CG_HEAD_INSERT_EVENT_TAP: u32 = 0;
const K_CG_EVENT_TAP_OPTION_DEFAULT: u32 = 0;

const K_CG_EVENT_KEY_DOWN: u32 = 10;
const K_CG_EVENT_KEY_UP: u32 = 11;
const K_CG_EVENT_FLAGS_CHANGED: u32 = 12;
const K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT: u32 = 0xFFFF_FFFE;
const K_CG_EVENT_TAP_DISABLED_BY_USER_INPUT: u32 = 0xFFFF_FFFF;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGEventTapCreate(
        tap: u32,
        place: u32,
        options: u32,
        events_of_interest: CGEventMask,
        callback: CGEventTapCallback,
        user_info: *mut c_void,
    ) -> CFMachPortRef;
    fn CGEventTapEnable(tap: CFMachPortRef, enable: bool);
    fn CGEventGetIntegerValueField(event: CGEventRef, field: u32) -> i64;
    fn CGEventGetFlags(event: CGEventRef) -> u64;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFMachPortInvalidate(port: CFMachPortRef);
    fn CFRelease(cf: *const c_void);
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    /// Non-prompting Accessibility check.
    fn AXIsProcessTrusted() -> bool;
    /// Accessibility check that can prompt, per `kAXTrustedCheckOptionPrompt`.
    fn AXIsProcessTrustedWithOptions(options: *const c_void) -> bool;
    static kAXTrustedCheckOptionPrompt: core_foundation::string::CFStringRef;
}

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    /// True when *any* process has secure event input enabled, in which case
    /// event taps receive nothing.
    fn IsSecureEventInputEnabled() -> bool;
}

/// The tap only ever asks for keyboard events.
fn keyboard_event_mask() -> CGEventMask {
    (1 << K_CG_EVENT_KEY_DOWN) | (1 << K_CG_EVENT_KEY_UP) | (1 << K_CG_EVENT_FLAGS_CHANGED)
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// Is this process trusted for Accessibility? Never prompts.
pub fn ax_trusted() -> bool {
    // SAFETY: no arguments, no state; the symbol is a plain predicate.
    unsafe { AXIsProcessTrusted() }
}

/// Show the system Accessibility prompt. Non-blocking.
pub fn request_accessibility() {
    // The call itself returns promptly (the panel is drawn by the OS out of
    // process), but it is done on a scratch thread so a slow WindowServer can
    // never stall a Tauri command.
    std::thread::spawn(|| {
        use core_foundation::base::TCFType;
        use core_foundation::boolean::CFBoolean;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::string::CFString;

        // SAFETY: `kAXTrustedCheckOptionPrompt` is an immortal CFStringRef
        // constant exported by ApplicationServices; wrapping it under the *get*
        // rule borrows it without taking ownership.
        let key: CFString = unsafe { CFString::wrap_under_get_rule(kAXTrustedCheckOptionPrompt) };
        let options = CFDictionary::from_CFType_pairs(&[(key, CFBoolean::true_value())]);

        // SAFETY: `options` is a valid CFDictionaryRef and outlives the call.
        let granted = unsafe {
            AXIsProcessTrustedWithOptions(options.as_concrete_TypeRef() as *const c_void)
        };
        tracing::info!(granted, "requested macOS Accessibility permission");
    });
}

/// Does another process currently hold secure event input?
fn secure_input_enabled() -> bool {
    // SAFETY: no arguments, no state.
    unsafe { IsSecureEventInputEnabled() }
}

const SECURE_INPUT_REASON: &str =
    "Another app has secure keyboard entry turned on (a password field, or Terminal's \
     Secure Keyboard Entry). macOS delivers no key events to any capture while that is \
     active, dismiss it and try again.";

// ---------------------------------------------------------------------------
// Shared state between the API object and the tap thread
// ---------------------------------------------------------------------------

const STATUS_INACTIVE: u8 = 0;
const STATUS_ACTIVE: u8 = 1;
const STATUS_PERMISSION: u8 = 2;

struct Shared {
    tx: Sender<CapturedKey>,
    /// Cleared to ask the tap thread to stop swallowing immediately, before
    /// the run loop has had a chance to wind down.
    running: AtomicBool,
    status: AtomicU8,
    /// `CGEventFlags` from the most recent event, for the intercept policy.
    flags: AtomicUsize,
    /// The tap's `CFMachPortRef`, needed to re-enable after a timeout disable.
    /// `0` while no tap exists.
    tap_port: AtomicUsize,
    /// The tap thread's run loop, so `stop()` can wake it. `CFRunLoop` is
    /// documented thread-safe for `CFRunLoopStop`, and core-foundation marks it
    /// `Send`/`Sync` accordingly.
    runloop: Mutex<Option<CFRunLoop>>,
    /// Scancodes whose key-down was swallowed and forwarded, so the matching
    /// key-up is swallowed unconditionally regardless of modifier state (see
    /// `policy.rs`). Cleared on `stop()`.
    held: Mutex<HeldKeys>,
}

impl Shared {
    fn modifiers(&self) -> Modifiers {
        let flags = CGEventFlags::from_bits_truncate(self.flags.load(Ordering::Relaxed) as u64);
        Modifiers {
            shift: flags.contains(CGEventFlags::CGEventFlagShift),
            ctrl: flags.contains(CGEventFlags::CGEventFlagControl),
            alt: flags.contains(CGEventFlags::CGEventFlagAlternate),
            meta: flags.contains(CGEventFlags::CGEventFlagCommand),
        }
    }
}

// ---------------------------------------------------------------------------
// The tap callback
// ---------------------------------------------------------------------------

/// Event-tap callback.
///
/// # Safety / invariants
///
/// - `user_info` is a `*const Shared` that the tap thread keeps alive for
///   strictly longer than the tap itself (the tap is invalidated by
///   `TapGuard::drop` before the `Arc` is dropped).
/// - Returning the incoming `event` passes it through untouched; returning
///   `null` deletes it from the system event stream.
/// - This runs on the tap thread's run loop and must be fast, the OS disables
///   taps that take too long (handled below by re-enabling).
unsafe extern "C" fn tap_callback(
    _proxy: CGEventTapProxy,
    event_type: u32,
    event: CGEventRef,
    user_info: *mut c_void,
) -> CGEventRef {
    let shared = &*(user_info as *const Shared);

    match event_type {
        // The OS disables a tap that is too slow, or when the user asks it to.
        // Re-enable rather than silently dying: PRD/06 requires the capture
        // indicator to reflect reality.
        K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT | K_CG_EVENT_TAP_DISABLED_BY_USER_INPUT => {
            let port = shared.tap_port.load(Ordering::Relaxed) as CFMachPortRef;
            if !port.is_null() && shared.running.load(Ordering::Relaxed) {
                tracing::warn!("CGEventTap was disabled by the OS; re-enabling");
                CGEventTapEnable(port, true);
            }
            return event;
        }
        _ => {}
    }

    // Modifier state is tracked from every event (the flags field is present on
    // key events too, which keeps us correct even if a FlagsChanged was missed
    // while the tap was disabled).
    shared
        .flags
        .store(CGEventGetFlags(event) as usize, Ordering::Relaxed);

    // FlagsChanged is never swallowed: the webview needs to see Command go down
    // so it sends `Super_L` itself (see `policy.rs`).
    let down = match event_type {
        K_CG_EVENT_KEY_DOWN => true,
        K_CG_EVENT_KEY_UP => false,
        _ => return event,
    };

    if !shared.running.load(Ordering::Relaxed) {
        return event;
    }

    let kvk = CGEventGetIntegerValueField(event, EventField::KEYBOARD_EVENT_KEYCODE) as u16;
    let Some(scancode) = keymap::kvk_to_xt(kvk) else {
        // Unmapped physical key (Fn, media keys, F13+): leave it to the local
        // machine rather than eating a key we cannot express.
        return event;
    };

    let mods = shared.modifiers();
    let intercept = {
        let mut held = shared.held.lock();
        should_intercept_key(HostOs::MacOs, scancode, down, mods, &mut held)
    };
    if !intercept {
        return event;
    }

    let keysym = keymap::xt_to_keysym(scancode, mods.shift).unwrap_or(0);
    // `try_send` on an unbounded channel only fails if the receiver is gone; a
    // full/closed channel must never make the callback block or panic.
    let _ = shared.tx.try_send(CapturedKey {
        scancode,
        keysym,
        down,
    });

    // NULL deletes the event: this is what routes Cmd+Tab to the remote.
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Tap lifetime guard
// ---------------------------------------------------------------------------

/// Owns the tap's mach port and guarantees it is disabled and invalidated on
/// every exit path from the tap thread, including a panic.
struct TapGuard {
    port: CFMachPortRef,
    shared: Arc<Shared>,
}

impl Drop for TapGuard {
    fn drop(&mut self) {
        self.shared.tap_port.store(0, Ordering::Relaxed);
        self.shared.status.store(STATUS_INACTIVE, Ordering::Relaxed);
        // SAFETY: `port` was created by `CGEventTapCreate` (create rule) and is
        // released exactly once, here. Disabling before invalidating means no
        // further callback can run, so the `Arc<Shared>` the callback borrows
        // is unreferenced by the time this returns.
        unsafe {
            CGEventTapEnable(self.port, false);
            CFMachPortInvalidate(self.port);
            CFRelease(self.port as *const c_void);
        }
    }
}

// ---------------------------------------------------------------------------
// Public backend
// ---------------------------------------------------------------------------

pub struct MacCapture {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl MacCapture {
    pub fn new(tx: Sender<CapturedKey>) -> Self {
        Self {
            shared: Arc::new(Shared {
                tx,
                running: AtomicBool::new(false),
                status: AtomicU8::new(STATUS_INACTIVE),
                flags: AtomicUsize::new(0),
                tap_port: AtomicUsize::new(0),
                runloop: Mutex::new(None),
                held: Mutex::new(HeldKeys::new()),
            }),
            thread: None,
        }
    }
}

impl KeyboardCapture for MacCapture {
    fn start(&mut self) -> Result<()> {
        if self.thread.is_some() {
            return Ok(()); // idempotent
        }
        if !ax_trusted() {
            self.shared
                .status
                .store(STATUS_PERMISSION, Ordering::Relaxed);
            return Err(Error::PermissionRequired);
        }

        self.shared.running.store(true, Ordering::Relaxed);
        let shared = self.shared.clone();
        let handle = std::thread::Builder::new()
            .name("vnc-capture-tap".into())
            .spawn(move || {
                // A panic inside the run loop must still release the keyboard.
                // `TapGuard` does the releasing; `catch_unwind` keeps the panic
                // from tearing down the process before it can run and stops it
                // propagating across the FFI boundary.
                let result = std::panic::catch_unwind(AssertUnwindSafe(|| run_tap(&shared)));
                if result.is_err() {
                    tracing::error!("keyboard capture thread panicked; keyboard released");
                }
                shared.running.store(false, Ordering::Relaxed);
                shared.status.store(STATUS_INACTIVE, Ordering::Relaxed);
                *shared.runloop.lock() = None;
            })
            .map_err(|e| Error::Backend(format!("could not spawn the capture thread: {e}")))?;
        self.thread = Some(handle);

        // Wait briefly for the thread to publish its outcome so `start()` can
        // report a permission failure synchronously instead of leaving the UI
        // to discover it from a later poll.
        for _ in 0..100 {
            match self.shared.status.load(Ordering::Relaxed) {
                STATUS_ACTIVE => return Ok(()),
                STATUS_PERMISSION => {
                    self.stop();
                    return Err(Error::PermissionRequired);
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(2)),
            }
        }
        Ok(())
    }

    fn stop(&mut self) {
        // Stop swallowing *first*: even if the run loop takes a moment to wind
        // down, no further key is taken from the user.
        self.shared.running.store(false, Ordering::Relaxed);
        if let Some(runloop) = self.shared.runloop.lock().take() {
            runloop.stop();
        }
        if let Some(handle) = self.thread.take() {
            // Joining is deliberate: `stop()` must not return while a tap could
            // still be alive.
            let _ = handle.join();
        }
        self.shared.status.store(STATUS_INACTIVE, Ordering::Relaxed);
        // A key held from this session must never swallow a local key-up once
        // capture is stopped or force-released.
        self.shared.held.lock().clear();
    }

    fn status(&self) -> CaptureStatus {
        match self.shared.status.load(Ordering::Relaxed) {
            STATUS_ACTIVE if secure_input_enabled() => CaptureStatus::Unsupported {
                reason: SECURE_INPUT_REASON,
            },
            STATUS_ACTIVE => CaptureStatus::Active,
            STATUS_PERMISSION => CaptureStatus::PermissionRequired,
            _ => CaptureStatus::Inactive,
        }
    }
}

impl Drop for MacCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Tap-thread body: create the tap, pump its run loop until asked to stop.
///
/// Every early return leaves the keyboard untouched, and the `TapGuard`
/// declared after `shared` is dropped *before* it, so the callback's borrow can
/// never outlive the data.
fn run_tap(shared: &Arc<Shared>) {
    let user_info = Arc::as_ptr(shared) as *mut c_void;

    // SAFETY: `tap_callback` matches the C signature; `user_info` points at the
    // `Shared` that this function's caller keeps alive for the whole call, and
    // the tap is invalidated by `TapGuard` before this function returns.
    let port = unsafe {
        CGEventTapCreate(
            K_CG_HID_EVENT_TAP,
            K_CG_HEAD_INSERT_EVENT_TAP,
            K_CG_EVENT_TAP_OPTION_DEFAULT,
            keyboard_event_mask(),
            tap_callback,
            user_info,
        )
    };
    if port.is_null() {
        // The only realistic cause is a missing/revoked Accessibility grant, // including the documented post-re-signing silent disable (PRD/12 §1.1).
        tracing::warn!("CGEventTapCreate returned NULL, Accessibility not granted?");
        shared.status.store(STATUS_PERMISSION, Ordering::Relaxed);
        return;
    }

    let guard = TapGuard {
        port,
        shared: shared.clone(),
    };
    shared.tap_port.store(port as usize, Ordering::Relaxed);

    // SAFETY: `port` is a live CFMachPort created just above (create rule).
    let mach_port = unsafe { CFMachPort::wrap_under_get_rule(port) };
    let Ok(source) = mach_port.create_runloop_source(0) else {
        tracing::error!("could not create a run loop source for the event tap");
        drop(guard);
        return;
    };

    let runloop = CFRunLoop::get_current();
    // SAFETY: `kCFRunLoopCommonModes` is an immortal CF constant.
    unsafe { runloop.add_source(&source, kCFRunLoopCommonModes) };
    *shared.runloop.lock() = Some(runloop.clone());

    // SAFETY: `port` is live and owned by `guard`.
    unsafe { CGEventTapEnable(port, true) };
    shared.status.store(STATUS_ACTIVE, Ordering::Relaxed);
    if secure_input_enabled() {
        tracing::warn!("secure event input is enabled; the tap will not receive keys");
    }
    tracing::info!("macOS keyboard capture active");

    // Blocks until `stop()` calls `CFRunLoopStop`.
    CFRunLoop::run_current();

    runloop.remove_source(&source, unsafe { kCFRunLoopCommonModes });
    drop(guard);
    tracing::info!("macOS keyboard capture released");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_mask_covers_exactly_the_keyboard_events() {
        let mask = keyboard_event_mask();
        assert_ne!(mask & (1 << 10), 0, "KeyDown");
        assert_ne!(mask & (1 << 11), 0, "KeyUp");
        assert_ne!(mask & (1 << 12), 0, "FlagsChanged");
        assert_eq!(mask & (1 << 5), 0, "must not tap MouseMoved");
        assert_eq!(mask & (1 << 22), 0, "must not tap ScrollWheel");
    }

    #[test]
    fn flags_map_onto_modifiers() {
        let shared = Shared {
            tx: crossbeam_channel::unbounded().0,
            running: AtomicBool::new(false),
            status: AtomicU8::new(STATUS_INACTIVE),
            flags: AtomicUsize::new(
                (CGEventFlags::CGEventFlagCommand | CGEventFlags::CGEventFlagShift).bits() as usize,
            ),
            tap_port: AtomicUsize::new(0),
            runloop: Mutex::new(None),
            held: Mutex::new(HeldKeys::new()),
        };
        let mods = shared.modifiers();
        assert!(mods.meta && mods.shift);
        assert!(!mods.ctrl && !mods.alt);
    }

    /// Runtime check on the real machine: constructing a backend must not grab
    /// anything, and stopping something that never started must be safe.
    #[test]
    fn lifecycle_without_permission_is_harmless() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut capture = MacCapture::new(tx);
        assert_eq!(capture.status(), CaptureStatus::Inactive);
        // `start` may legitimately fail (no Accessibility grant in CI) or
        // succeed (granted dev machine); either way `stop` must return the
        // machine to Inactive.
        let _ = capture.start();
        capture.stop();
        assert_eq!(capture.status(), CaptureStatus::Inactive);
        capture.stop(); // idempotent
        assert_eq!(capture.status(), CaptureStatus::Inactive);
    }

    #[test]
    fn permission_check_does_not_panic_or_prompt() {
        // Purely a smoke test that the ApplicationServices symbols link.
        let _ = ax_trusted();
        let _ = secure_input_enabled();
    }
}
