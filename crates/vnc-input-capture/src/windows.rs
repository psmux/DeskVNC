//! Windows keyboard capture via a `WH_KEYBOARD_LL` low-level hook
//! (PRD/06 §3 Tier 2).
//!
//! # How it works
//!
//! `SetWindowsHookExW(WH_KEYBOARD_LL, …)` installs a system-wide keyboard hook.
//! Returning a non-zero value from the hook procedure suppresses the key, which
//! is how the Windows key, Alt+Tab and Alt+Esc get routed to the remote instead
//! of the local shell.
//!
//! The hook is installed on a **dedicated thread running its own `GetMessage`
//! pump**. This is not optional:
//!
//! - a low-level hook is only serviced while its owning thread pumps messages,
//!   and Tauri's main-thread loop is not a plain `GetMessage` loop;
//! - PRD/06 §3 records the known Tauri issue where an in-process hook installed
//!   on the main thread stops firing once the Tauri window takes focus.
//!
//! # What cannot be captured
//!
//! - **Ctrl+Alt+Del**, the Secure Attention Sequence is handled by winlogon in
//!   a separate desktop; no hook, driver-free, can see it. PRD/06 Tier 3's
//!   synthetic-send menu is the only way to deliver it to a remote host.
//! - **UIPI**: a non-elevated process cannot hook input destined for an
//!   elevated window, so pass-through silently stops over an elevated app.
//! - Win+L (workstation lock) and Ctrl+Shift+Esc are likewise handled below the
//!   hook by the OS.
//!
//! # Scancodes
//!
//! `KBDLLHOOKSTRUCT::scanCode` is already an XT set-1 code, so mapping is just
//! folding in `LLKHF_EXTENDED` as bit 7, see [`crate::windows_to_xt`].

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crossbeam_channel::Sender;
use parking_lot::Mutex;
use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, PostThreadMessageW, SetWindowsHookExW,
    TranslateMessage, UnhookWindowsHookEx, HHOOK, KBDLLHOOKSTRUCT, LLKHF_EXTENDED, MSG,
    WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_QUIT, WM_SYSKEYDOWN, WM_SYSKEYUP,
};

use crate::keymap;
use crate::policy::{should_intercept_key, HeldKeys, HostOs, Modifiers};
use crate::{CaptureStatus, CapturedKey, Error, KeyboardCapture, Result};

const STATUS_INACTIVE: u8 = 0;
const STATUS_ACTIVE: u8 = 1;

/// Virtual-key codes we need for modifier tracking.
mod vk {
    pub const SHIFT: u32 = 0x10;
    pub const CONTROL: u32 = 0x11;
    pub const MENU: u32 = 0x12; // Alt
    pub const LSHIFT: u32 = 0xa0;
    pub const RSHIFT: u32 = 0xa1;
    pub const LCONTROL: u32 = 0xa2;
    pub const RCONTROL: u32 = 0xa3;
    pub const LMENU: u32 = 0xa4;
    pub const RMENU: u32 = 0xa5;
    pub const LWIN: u32 = 0x5b;
    pub const RWIN: u32 = 0x5c;
}

mod modbit {
    pub const SHIFT: u32 = 1 << 0;
    pub const CTRL: u32 = 1 << 1;
    pub const ALT: u32 = 1 << 2;
    pub const META: u32 = 1 << 3;
}

/// Which modifier bit (if any) a virtual-key code represents.
fn modifier_bit(vk_code: u32) -> Option<u32> {
    Some(match vk_code {
        vk::SHIFT | vk::LSHIFT | vk::RSHIFT => modbit::SHIFT,
        vk::CONTROL | vk::LCONTROL | vk::RCONTROL => modbit::CTRL,
        vk::MENU | vk::LMENU | vk::RMENU => modbit::ALT,
        vk::LWIN | vk::RWIN => modbit::META,
        _ => return None,
    })
}

fn modifiers_from_bits(bits: u32) -> Modifiers {
    Modifiers {
        shift: bits & modbit::SHIFT != 0,
        ctrl: bits & modbit::CTRL != 0,
        alt: bits & modbit::ALT != 0,
        meta: bits & modbit::META != 0,
    }
}

// ---------------------------------------------------------------------------
// Hook context
// ---------------------------------------------------------------------------
//
// A `WH_KEYBOARD_LL` procedure is a bare `extern "system" fn` with no user
// data, so its state has to be reachable from a static. Everything the hook
// touches on the hot path is an atomic or a `try_lock`, because blocking inside
// the procedure stalls every keystroke on the machine and gets the hook evicted
// by the OS after `LowLevelHooksTimeout`.

struct HookCtx {
    tx: Sender<CapturedKey>,
    running: Arc<AtomicBool>,
    mods: Arc<AtomicU32>,
    /// Scancodes whose key-down was swallowed and forwarded, so the matching
    /// key-up is swallowed unconditionally regardless of modifier state (see
    /// `policy.rs`). Shared with `WindowsCapture` so `start`/`stop` can clear
    /// it the same way `mods` is reset.
    held: Arc<Mutex<HeldKeys>>,
}

static HOOK_CTX: Mutex<Option<HookCtx>> = Mutex::new(None);
/// The installed hook handle, as `usize`, so `Drop` can uninstall it.
static HOOK_HANDLE: Mutex<Option<isize>> = Mutex::new(None);

/// Low-level keyboard hook procedure.
///
/// # Invariants
///
/// - Runs on the capture thread (the thread that called `SetWindowsHookExW`),
///   once per key transition, system-wide.
/// - Returning `LRESULT(1)` suppresses the key; anything else must chain to
///   `CallNextHookEx` so other hooks still see it.
/// - `n_code < 0` (`HC_ACTION` not set) means "do not inspect, just chain".
/// - Must never block or panic: a panic across the FFI boundary is UB, so the
///   body is wrapped in `catch_unwind` and falls back to passing the key
///   through.
unsafe extern "system" fn keyboard_hook(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if n_code < 0 {
        return CallNextHookEx(None, n_code, w_param, l_param);
    }

    let suppress = std::panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: for `HC_ACTION`, `l_param` is a pointer to a KBDLLHOOKSTRUCT
        // owned by the OS and valid for the duration of this call.
        let info = &*(l_param.0 as *const KBDLLHOOKSTRUCT);
        handle_key(w_param.0 as u32, info)
    }))
    .unwrap_or(false);

    if suppress {
        return LRESULT(1);
    }
    CallNextHookEx(None, n_code, w_param, l_param)
}

/// Pure-ish decision half of the hook: update modifier state, decide whether to
/// suppress, and forward what we suppress. Returns `true` to suppress.
fn handle_key(message: u32, info: &KBDLLHOOKSTRUCT) -> bool {
    let down = matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN);
    if !down && !matches!(message, WM_KEYUP | WM_SYSKEYUP) {
        return false;
    }

    let vk_code = info.vkCode;
    let extended = info.flags.contains(LLKHF_EXTENDED);

    let Some(guard) = HOOK_CTX.try_lock() else {
        // Contended only while starting/stopping. Never block a keystroke.
        return false;
    };
    let Some(ctx) = guard.as_ref() else {
        return false;
    };

    // Track modifiers before deciding, so the modifier's own event sees itself
    // as held (Windows' Win key must be judged with meta already set).
    if let Some(bit) = modifier_bit(vk_code) {
        let previous = ctx.mods.load(Ordering::Relaxed);
        let updated = if down {
            previous | bit
        } else {
            previous & !bit
        };
        ctx.mods.store(updated, Ordering::Relaxed);
    }
    let mods = modifiers_from_bits(ctx.mods.load(Ordering::Relaxed));

    if !ctx.running.load(Ordering::Relaxed) {
        return false;
    }

    let Some(scancode) = keymap::windows_to_xt(vk_code, info.scanCode, extended) else {
        return false;
    };
    let mut held = ctx.held.lock();
    if !should_intercept_key(HostOs::Windows, scancode, down, mods, &mut held) {
        return false;
    }
    drop(held);

    let keysym = keymap::xt_to_keysym(scancode, mods.shift).unwrap_or(0);
    let _ = ctx.tx.try_send(CapturedKey {
        scancode,
        keysym,
        down,
    });
    true
}

/// Owns the installed hook and guarantees it is removed on every exit path from
/// the capture thread, including a panic.
struct HookGuard(HHOOK);

impl Drop for HookGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `SetWindowsHookExW` on this thread and is
        // unhooked exactly once, from the same thread, as the API requires.
        unsafe {
            let _ = UnhookWindowsHookEx(self.0);
        }
        *HOOK_HANDLE.lock() = None;
        *HOOK_CTX.lock() = None;
    }
}

// ---------------------------------------------------------------------------
// Public backend
// ---------------------------------------------------------------------------

pub struct WindowsCapture {
    tx: Sender<CapturedKey>,
    running: Arc<AtomicBool>,
    status: Arc<AtomicU8>,
    mods: Arc<AtomicU32>,
    /// Scancodes whose key-down was swallowed and forwarded; see `HookCtx`.
    held: Arc<Mutex<HeldKeys>>,
    /// Thread id of the message pump, for `PostThreadMessageW(WM_QUIT)`.
    thread_id: Arc<AtomicU32>,
    thread: Option<JoinHandle<()>>,
}

impl WindowsCapture {
    pub fn new(tx: Sender<CapturedKey>) -> Self {
        Self {
            tx,
            running: Arc::new(AtomicBool::new(false)),
            status: Arc::new(AtomicU8::new(STATUS_INACTIVE)),
            mods: Arc::new(AtomicU32::new(0)),
            held: Arc::new(Mutex::new(HeldKeys::new())),
            thread_id: Arc::new(AtomicU32::new(0)),
            thread: None,
        }
    }
}

impl KeyboardCapture for WindowsCapture {
    fn start(&mut self) -> Result<()> {
        if self.thread.is_some() {
            return Ok(()); // idempotent
        }
        self.running.store(true, Ordering::Relaxed);
        self.mods.store(0, Ordering::Relaxed);
        self.held.lock().clear();

        let ctx = HookCtx {
            tx: self.tx.clone(),
            running: self.running.clone(),
            mods: self.mods.clone(),
            held: self.held.clone(),
        };
        let status = self.status.clone();
        let thread_id = self.thread_id.clone();

        let handle = std::thread::Builder::new()
            .name("vnc-capture-hook".into())
            .spawn(move || {
                // A panic must still uninstall the hook; `HookGuard` does that
                // and `catch_unwind` keeps the unwind from crossing back into
                // the OS.
                let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    run_hook(ctx, &status, &thread_id)
                }));
                if result.is_err() {
                    tracing::error!("keyboard capture thread panicked; keyboard released");
                }
                status.store(STATUS_INACTIVE, Ordering::Relaxed);
                thread_id.store(0, Ordering::Relaxed);
            })
            .map_err(|e| Error::Backend(format!("could not spawn the capture thread: {e}")))?;
        self.thread = Some(handle);

        // Give the pump a moment to report success so `start()` can fail loudly
        // rather than leaving the UI to discover it later.
        for _ in 0..100 {
            if self.status.load(Ordering::Relaxed) == STATUS_ACTIVE {
                return Ok(());
            }
            if self.thread.as_ref().is_some_and(|t| t.is_finished()) {
                self.stop();
                return Err(Error::Backend(
                    "SetWindowsHookExW failed to install the keyboard hook".into(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        Ok(())
    }

    fn stop(&mut self) {
        // Stop suppressing first: even if the pump takes a moment to drain, no
        // further key is taken from the user.
        self.running.store(false, Ordering::Relaxed);
        let id = self.thread_id.swap(0, Ordering::Relaxed);
        if id != 0 {
            // SAFETY: posting WM_QUIT to a thread id is safe; a stale id simply
            // fails, which is why the result is ignored.
            unsafe {
                let _ = PostThreadMessageW(id, WM_QUIT, WPARAM(0), LPARAM(0));
            }
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        self.status.store(STATUS_INACTIVE, Ordering::Relaxed);
        self.mods.store(0, Ordering::Relaxed);
        // A key held from this session must never swallow a local key-up once
        // capture is stopped or force-released.
        self.held.lock().clear();
    }

    fn status(&self) -> CaptureStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_ACTIVE => CaptureStatus::Active,
            _ => CaptureStatus::Inactive,
        }
    }
}

impl Drop for WindowsCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Capture-thread body: install the hook, then pump messages until `WM_QUIT`.
fn run_hook(ctx: HookCtx, status: &AtomicU8, thread_id: &AtomicU32) {
    use windows::Win32::System::Threading::GetCurrentThreadId;

    *HOOK_CTX.lock() = Some(ctx);

    // SAFETY: `keyboard_hook` matches the `HOOKPROC` signature. A
    // `WH_KEYBOARD_LL` hook needs neither a module handle nor a DLL, it is
    // called back on this thread, so the module argument is NULL and the
    // thread id 0 (system-wide).
    let hook = match unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), None, 0) } {
        Ok(hook) => hook,
        Err(e) => {
            tracing::error!("SetWindowsHookExW failed: {e}");
            *HOOK_CTX.lock() = None;
            return;
        }
    };
    let guard = HookGuard(hook);
    *HOOK_HANDLE.lock() = Some(hook.0 as isize);

    // SAFETY: no arguments, no state.
    thread_id.store(unsafe { GetCurrentThreadId() }, Ordering::Relaxed);
    status.store(STATUS_ACTIVE, Ordering::Relaxed);
    tracing::info!("Windows keyboard capture active");

    // The hook is only serviced while this thread pumps messages.
    let mut msg = MSG::default();
    loop {
        // SAFETY: `msg` is a valid, writable MSG for the duration of the call.
        let got = unsafe { GetMessageW(&mut msg, None, 0, 0) };
        // 0 = WM_QUIT, -1 = error; both end the pump.
        if got.0 <= 0 {
            break;
        }
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    drop(guard);
    tracing::info!("Windows keyboard capture released");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modifier_bits_cover_both_sides() {
        assert_eq!(modifier_bit(vk::LWIN), Some(modbit::META));
        assert_eq!(modifier_bit(vk::RWIN), Some(modbit::META));
        assert_eq!(modifier_bit(vk::LMENU), Some(modbit::ALT));
        assert_eq!(modifier_bit(vk::RCONTROL), Some(modbit::CTRL));
        assert_eq!(modifier_bit(0x41), None); // 'A'
    }

    #[test]
    fn modifier_bits_round_trip() {
        let all = modbit::SHIFT | modbit::CTRL | modbit::ALT | modbit::META;
        let mods = modifiers_from_bits(all);
        assert!(mods.shift && mods.ctrl && mods.alt && mods.meta);
        let none = modifiers_from_bits(0);
        assert!(!none.shift && !none.ctrl && !none.alt && !none.meta);
    }

    #[test]
    fn lifecycle_is_idempotent() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let mut capture = WindowsCapture::new(tx);
        assert_eq!(capture.status(), CaptureStatus::Inactive);
        capture.stop(); // stopping something never started is safe
        assert_eq!(capture.status(), CaptureStatus::Inactive);
    }
}
