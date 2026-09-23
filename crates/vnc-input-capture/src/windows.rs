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
//!
//! Inside the application this is still not enough: while a DeskVNC window is
//! in front the hook is not called at all. The application therefore runs this
//! backend in a helper process, see `windows_helper`.
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
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crossbeam_channel::Sender;
use parking_lot::Mutex;
use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetAncestor, GetForegroundWindow, GetMessageW,
    PostThreadMessageW, SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, GA_ROOT, HHOOK,
    KBDLLHOOKSTRUCT, LLKHF_EXTENDED, MSG, WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_QUIT,
    WM_SYSKEYDOWN, WM_SYSKEYUP,
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
/// One bit per physical modifier key, left and right apart, so releasing one
/// Shift while the other is still held does not clear Shift.
fn modifier_bit(vk_code: u32) -> Option<u32> {
    Some(match vk_code {
        vk::SHIFT | vk::LSHIFT => modbit::SHIFT,
        vk::RSHIFT => modbit::SHIFT << 8,
        vk::CONTROL | vk::LCONTROL => modbit::CTRL,
        vk::RCONTROL => modbit::CTRL << 8,
        vk::MENU | vk::LMENU => modbit::ALT,
        vk::RMENU => modbit::ALT << 8,
        vk::LWIN => modbit::META,
        vk::RWIN => modbit::META << 8,
        _ => return None,
    })
}

fn modifiers_from_bits(bits: u32) -> Modifiers {
    let either = bits | (bits >> 8);
    Modifiers {
        shift: either & modbit::SHIFT != 0,
        ctrl: either & modbit::CTRL != 0,
        alt: either & modbit::ALT != 0,
        meta: either & modbit::META != 0,
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
    /// The native top level window whose keys we take, as a raw `HWND`, or 0
    /// for no restriction. A key-down is only swallowed while this window is
    /// the foreground window, so the grab can stay installed for as long as
    /// pass-through is on without ever taking a key typed somewhere else.
    target: Arc<AtomicIsize>,
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
        trace_key(vk_code, down, "ctx-locked");
        return false;
    };
    let Some(ctx) = guard.as_ref() else {
        trace_key(vk_code, down, "no-ctx");
        return false;
    };

    // Track modifiers before deciding, so the modifier's own event sees itself
    // as held (Windows' Win key must be judged with meta already set).
    //
    // A modifier only counts if it went down while the target window was in
    // front. Alt held in another application and still held when DeskVNC is
    // clicked never reached the remote through the webview, so treating the
    // Tab that follows as Alt+Tab would send the remote a bare Tab.
    //
    // `ctx.mods` packs two masks: the low half is which modifiers count
    // (pressed fresh while the target was in front), the high half is which
    // are physically down. An autorepeat is a down for a key already
    // physically down, and it never makes a modifier count, because the press
    // it repeats may have happened elsewhere. Any key arriving while another
    // window is in front drops every modifier's eligibility: the window blur
    // has released them on the remote, so a held Alt must be pressed again
    // before it turns Tab into a grabbed Alt+Tab.
    let foreground = target_is_foreground(ctx.target.load(Ordering::Relaxed));
    let packed = ctx.mods.load(Ordering::Relaxed);
    let (mut counts, mut physical) = (packed & 0xffff, packed >> 16);
    if !foreground {
        counts = 0;
    }
    if let Some(bit) = modifier_bit(vk_code) {
        if !down {
            counts &= !bit;
            physical &= !bit;
        } else {
            if physical & bit == 0 && foreground {
                counts |= bit;
            }
            physical |= bit;
        }
    }
    ctx.mods.store(counts | (physical << 16), Ordering::Relaxed);
    let mods = modifiers_from_bits(counts);

    if !ctx.running.load(Ordering::Relaxed) {
        trace_key(vk_code, down, "not-running");
        return false;
    }

    let Some(scancode) = keymap::windows_to_xt(vk_code, info.scanCode, extended) else {
        return false;
    };
    // Key-ups are judged by `held` alone below, so a key-down we swallowed has
    // its key-up swallowed too even if the foreground changed in between. An
    // autorepeat of such a key-down is ours as well: forwarded while the
    // target is in front, and consumed without forwarding once it is not.
    let mut held = ctx.held.lock();
    let repeat_of_ours = down && held.contains(scancode);
    if repeat_of_ours && !foreground {
        // Swallowed so no other window sees a repeat it never saw the press
        // for, but not forwarded: the window blur has already released the
        // key on the remote, and the key-up will still be consumed.
        trace_key(vk_code, down, "consume-repeat-not-foreground");
        return true;
    }
    if down && !repeat_of_ours && !foreground {
        trace_key(vk_code, down, "pass-not-foreground");
        return false;
    }
    if !repeat_of_ours
        && !should_intercept_key(HostOs::Windows, scancode, down, mods, &mut held)
    {
        trace_key(vk_code, down, "pass");
        return false;
    }
    drop(held);
    trace_key(vk_code, down, "swallow");

    let keysym = keymap::xt_to_keysym(scancode, mods.shift).unwrap_or(0);
    let _ = ctx.tx.try_send(CapturedKey {
        scancode,
        keysym,
        down,
    });
    true
}

/// Is `target` (a raw top level `HWND`, 0 for any window) the foreground
/// window? Compared by root, so a key typed while focus sits in a child of the
/// target (the WebView2 document) counts as the target's.
fn target_is_foreground(target: isize) -> bool {
    if target == 0 {
        return true;
    }
    // SAFETY: both calls take and return plain window handles and have no
    // preconditions; a null foreground window simply compares unequal.
    let root = unsafe { GetAncestor(GetForegroundWindow(), GA_ROOT) };
    root.0 as isize == target
}

/// `DVV_CAPTURE_TRACE=<file>` appends every decision the hook makes to that
/// file. Off by default: the hook runs on every keystroke system wide, and a
/// file rather than stderr because the hook runs on its own thread and a
/// shared console pipe interleaves badly with the application's own log.
fn trace_key(vk_code: u32, down: bool, what: &str) {
    use std::io::Write;
    static FILE: std::sync::OnceLock<Option<parking_lot::Mutex<std::fs::File>>> =
        std::sync::OnceLock::new();
    let Some(file) = FILE.get_or_init(|| {
        let path = std::env::var_os("DVV_CAPTURE_TRACE")?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
            .map(parking_lot::Mutex::new)
    }) else {
        return;
    };
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() % 100_000)
        .unwrap_or(0);
    let _ = writeln!(
        file.lock(),
        "{ms:05} vk=0x{vk_code:02x} {} {what}",
        if down { "down" } else { "up" }
    );
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
    target: Arc<AtomicIsize>,
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
            target: Arc::new(AtomicIsize::new(0)),
            thread_id: Arc::new(AtomicU32::new(0)),
            thread: None,
        }
    }
}

impl WindowsCapture {
    /// The shared target cell, so the helper process can retarget the grab
    /// from its command thread while the hook is running.
    pub fn target_handle(&self) -> Arc<AtomicIsize> {
        self.target.clone()
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
            target: self.target.clone(),
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

    fn set_target_window(&mut self, native: Option<isize>) {
        self.target.store(native.unwrap_or(0), Ordering::Relaxed);
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
        let reads_as = |vk| modifiers_from_bits(modifier_bit(vk).unwrap());
        assert!(reads_as(vk::LWIN).meta && reads_as(vk::RWIN).meta);
        assert!(reads_as(vk::LMENU).alt && reads_as(vk::RMENU).alt);
        assert!(reads_as(vk::LCONTROL).ctrl && reads_as(vk::RCONTROL).ctrl);
        assert!(reads_as(vk::LSHIFT).shift && reads_as(vk::RSHIFT).shift);
        assert_ne!(modifier_bit(vk::LSHIFT), modifier_bit(vk::RSHIFT));
        assert_eq!(modifier_bit(0x41), None); // 'A'
    }

    #[test]
    fn releasing_one_side_keeps_the_other_held() {
        let both = modifier_bit(vk::LSHIFT).unwrap() | modifier_bit(vk::RSHIFT).unwrap();
        let after_left_up = both & !modifier_bit(vk::LSHIFT).unwrap();
        assert!(modifiers_from_bits(after_left_up).shift);
        assert!(modifiers_from_bits(modifier_bit(vk::RMENU).unwrap()).alt);
    }

    #[test]
    fn no_target_means_any_foreground() {
        assert!(target_is_foreground(0));
    }

    #[test]
    fn a_window_that_is_not_in_front_is_not_the_target() {
        // No real window has this handle, so it is never the foreground.
        assert!(!target_is_foreground(0x7fff_fff0));
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
