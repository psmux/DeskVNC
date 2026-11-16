//! Windows before anyone signs in.
//!
//! The sign in screen belongs to no user, so nothing a user starts can show
//! it. A service, running as SYSTEM, watches the console and starts a copy of
//! the support app in the console session, also as SYSTEM, while nobody is
//! signed in there or the session is locked. That copy draws and types on
//! whichever desktop has the input, which at the sign in screen and the lock
//! screen is Winlogon rather than Default.

use anyhow::{Context, Result, bail};
use std::ffi::c_void;
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_ALL, HANDLE, NO_ERROR, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS, TokenPrimary,
    TokenSessionId,
};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTSFreeMemory, WTSGetActiveConsoleSessionId,
    WTSINFOEXW, WTSQuerySessionInformationW, WTSSessionInfoEx,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetUserObjectInformationW, HDESK, OpenInputDesktop, SetThreadDesktop, UOI_NAME,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess,
    GetCurrentProcessId, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess,
    WaitForSingleObject,
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// The session on the physical screen.
pub struct Console {
    pub session: u32,
    /// Somebody is signed in to it.
    pub signed_in: bool,
    /// It shows the lock screen, which like the sign in screen is on the
    /// secure desktop where a person's own programs cannot see.
    pub locked: bool,
}

/// The console session, or `None` while there is none, as during a switch.
pub fn console() -> Option<Console> {
    // SAFETY: no arguments.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        return None;
    }
    let mut buffer: *mut u16 = std::ptr::null_mut();
    let mut bytes = 0u32;
    // SAFETY: the out pointers are valid; the buffer is freed below.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            WTSSessionInfoEx,
            &mut buffer,
            &mut bytes,
        )
    };
    if ok == 0 {
        return None;
    }
    let buffer = std::ptr::NonNull::new(buffer)?;
    // SAFETY: on success WTSQuerySessionInformationW hands back a buffer of
    // `bytes` bytes that stays valid until WTSFreeMemory, called right after.
    let state = unsafe { session_state(buffer.cast::<u8>().as_ptr(), bytes as usize) };
    // SAFETY: the buffer came from WTSQuerySessionInformationW and is freed
    // once, here, after the last read above.
    unsafe { WTSFreeMemory(buffer.as_ptr().cast()) };
    let (signed_in, locked) = state?;
    Some(Console {
        session,
        signed_in,
        locked,
    })
}

/// Whether somebody is signed in and whether the session is locked, read from
/// the `WTSSessionInfoEx` answer at `buffer`, or `None` when the answer is too
/// short to hold a `WTSINFOEXW` or is not the level 1 form this reads.
///
/// The record is copied out with an unaligned read rather than referenced in
/// place, and its length is checked first, so a short or oddly aligned buffer
/// is refused instead of read past its end.
///
/// # Safety
///
/// `buffer` must be valid for reads of `bytes` bytes.
unsafe fn session_state(buffer: *const u8, bytes: usize) -> Option<(bool, bool)> {
    if bytes < std::mem::size_of::<WTSINFOEXW>() {
        return None;
    }
    // SAFETY: the caller vouches for `bytes` readable bytes, and there are at
    // least as many as a WTSINFOEXW, which is plain data valid for any bits.
    let info = unsafe { std::ptr::read_unaligned(buffer.cast::<WTSINFOEXW>()) };
    if info.Level != 1 {
        return None;
    }
    // SAFETY: Level 1 says the union holds WTSInfoExLevel1.
    let level = unsafe { info.Data.WTSInfoExLevel1 };
    let signed_in = level.UserName[0] != 0;
    // WTS_SESSIONSTATE_LOCK is 0; UNLOCK is 1 and UNKNOWN is -1.
    let locked = level.SessionFlags == 0;
    Some((signed_in, locked))
}

/// The session this process runs in.
pub fn own_session() -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: a valid out pointer.
    (unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } != 0).then_some(session)
}

/// A process started by [`spawn_in_session`].
pub struct Child(HANDLE);
// SAFETY: a process handle may be used from any thread.
unsafe impl Send for Child {}
impl Child {
    pub fn running(&self) -> bool {
        // SAFETY: the handle is open for as long as self.
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_TIMEOUT }
    }
    pub fn kill(&self) {
        // SAFETY: as above.
        unsafe {
            TerminateProcess(self.0, 0);
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        // SAFETY: closed once, here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Start `exe` with `args` in `session`, as SYSTEM, with `env` added to this
/// process's environment. Only a SYSTEM service may do this.
pub fn spawn_in_session(
    session: u32,
    exe: &Path,
    args: &str,
    env: &[(&str, &str)],
) -> Result<Child> {
    let mut token: HANDLE = std::ptr::null_mut();
    let mut primary: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out pointers; each handle is closed below.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token) == 0 {
            bail!(
                "Cannot read this service's token: {}",
                std::io::Error::last_os_error()
            );
        }
        let duplicated = DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        );
        CloseHandle(token);
        if duplicated == 0 {
            bail!(
                "Cannot copy this service's token: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            // SAFETY: closed once, here.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let primary = Token(primary);
    // SAFETY: a u32 session id, as TokenSessionId takes.
    let moved = unsafe {
        SetTokenInformation(
            primary.0,
            TokenSessionId,
            (&session as *const u32).cast(),
            4,
        )
    };
    if moved == 0 {
        bail!(
            "Cannot move to session {session}: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut block: Vec<u16> = Vec::new();
    for (key, value) in std::env::vars() {
        if env.iter().any(|(k, _)| k.eq_ignore_ascii_case(&key)) {
            continue;
        }
        block.extend(format!("{key}={value}").encode_utf16().chain(Some(0)));
    }
    for (key, value) in env {
        block.extend(format!("{key}={value}").encode_utf16().chain(Some(0)));
    }
    block.push(0);
    let mut line = wide(&format!("\"{}\" {args}", exe.display()));
    let mut desktop = wide("winsta0\\default");
    // SAFETY: a zeroed STARTUPINFOW with its size set is a valid one.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.lpDesktop = desktop.as_mut_ptr();
    // SAFETY: filled in by the call.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: every buffer outlives the call; the command line is mutable as
    // the call requires.
    let started = unsafe {
        CreateProcessAsUserW(
            primary.0,
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            block.as_ptr().cast::<c_void>(),
            std::ptr::null(),
            &startup,
            &mut info,
        )
    };
    if started == 0 {
        bail!(
            "Cannot start in session {session}: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: the thread handle is not needed.
    unsafe {
        CloseHandle(info.hThread);
    }
    Ok(Child(info.hProcess))
}

static FOLLOW: AtomicBool = AtomicBool::new(false);

/// Make capture and input go to whichever desktop has the input, so a copy
/// running at the sign in screen sees Winlogon, and the desktop after it.
pub fn follow_input_desktop() {
    FOLLOW.store(true, Ordering::Relaxed);
}

thread_local! {
    static ATTACHED: std::cell::RefCell<Option<(HDESK, String)>> = const { std::cell::RefCell::new(None) };
}

/// Attach the calling thread to the input desktop, if it moved. Called before
/// every capture and every input event; a no op unless asked for.
pub(crate) fn on_input_desktop() {
    if !FOLLOW.load(Ordering::Relaxed) {
        return;
    }
    // SAFETY: the handle is closed below unless it is kept for the thread.
    let desk = unsafe { OpenInputDesktop(0, 0, GENERIC_ALL) };
    if desk.is_null() {
        return;
    }
    let mut name = [0u16; 128];
    let mut needed = 0u32;
    // SAFETY: the buffer and its size match.
    unsafe {
        GetUserObjectInformationW(
            desk as HANDLE,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            (name.len() * 2) as u32,
            &mut needed,
        );
    }
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let name = String::from_utf16_lossy(&name[..end]);
    ATTACHED.with(|attached| {
        let mut attached = attached.borrow_mut();
        if attached
            .as_ref()
            .is_some_and(|(_, current)| *current == name)
        {
            // SAFETY: not kept.
            unsafe {
                CloseDesktop(desk);
            }
            return;
        }
        // SAFETY: a thread with no windows of its own may switch desktops.
        if unsafe { SetThreadDesktop(desk) } == 0 {
            unsafe {
                CloseDesktop(desk);
            }
            return;
        }
        if let Some((old, _)) = attached.replace((desk, name)) {
            // SAFETY: the thread no longer uses it.
            unsafe {
                CloseDesktop(old);
            }
        }
    });
}

/// The desktop the calling thread last attached to, for the host's log.
pub fn attached_desktop() -> Option<String> {
    ATTACHED.with(|attached| attached.borrow().as_ref().map(|(_, name)| name.clone()))
}

static STOP: AtomicBool = AtomicBool::new(false);
static BODY: OnceLock<fn(&'static AtomicBool)> = OnceLock::new();
static STATUS: OnceLock<usize> = OnceLock::new();

fn report(state: SERVICE_STATUS_CURRENT_STATE) {
    let Some(&handle) = STATUS.get() else { return };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: the handle came from RegisterServiceCtrlHandlerExW.
    unsafe {
        SetServiceStatus(handle as SERVICE_STATUS_HANDLE, &status);
    }
}

unsafe extern "system" fn control(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        STOP.store(true, Ordering::Relaxed);
    }
    NO_ERROR
}

unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let name = wide(SERVICE);
    // SAFETY: the name is NUL terminated; `control` lives forever.
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), std::ptr::null()) };
    if handle.is_null() {
        return;
    }
    let _ = STATUS.set(handle as usize);
    report(SERVICE_RUNNING);
    if let Some(body) = BODY.get() {
        body(&STOP);
    }
    report(SERVICE_STOPPED);
}

/// The service's name, for `sc.exe` and the service control manager.
pub const SERVICE: &str = "DeskVNCSupport";

/// Run as the service: `body` runs until it returns, and is told through its
/// flag when Windows asks the service to stop. Fails when this process was
/// not started by the service control manager.
pub fn run_service(body: fn(&'static AtomicBool)) -> Result<()> {
    let _ = BODY.set(body);
    let mut name = wide(SERVICE);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table ends with a null entry and outlives the call, which
    // returns when the service stops.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(std::io::Error::last_os_error()).context("Not started as a service");
    }
    Ok(())
}

/// This process runs in a remote desktop session, which has no display that
/// Desktop Duplication can show.
pub(crate) fn remote_session() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};
    // SAFETY: no pointers.
    unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(level: u32, user: &str, flags: i32) -> WTSINFOEXW {
        // SAFETY: WTSINFOEXW is plain data; all zero bits is a valid value.
        let mut info: WTSINFOEXW = unsafe { std::mem::zeroed() };
        info.Level = level;
        // SAFETY: writing the level 1 arm of a zeroed union.
        let one = unsafe { &mut info.Data.WTSInfoExLevel1 };
        for (dst, src) in one.UserName.iter_mut().zip(user.encode_utf16()) {
            *dst = src;
        }
        one.SessionFlags = flags;
        info
    }

    fn read(info: &WTSINFOEXW, bytes: usize) -> Option<(bool, bool)> {
        // SAFETY: `bytes` never exceeds the record's size in these tests.
        unsafe { session_state((info as *const WTSINFOEXW).cast(), bytes) }
    }

    #[test]
    fn reads_a_signed_in_locked_session() {
        let info = record(1, "alice", 0);
        assert_eq!(read(&info, size_of::<WTSINFOEXW>()), Some((true, true)));
    }

    #[test]
    fn reads_the_sign_in_screen() {
        let info = record(1, "", 1);
        assert_eq!(read(&info, size_of::<WTSINFOEXW>()), Some((false, false)));
    }

    #[test]
    fn refuses_a_short_answer() {
        let info = record(1, "alice", 0);
        assert_eq!(read(&info, size_of::<WTSINFOEXW>() - 1), None);
        assert_eq!(read(&info, 0), None);
    }

    #[test]
    fn refuses_a_level_it_does_not_know() {
        let info = record(2, "alice", 0);
        assert_eq!(read(&info, size_of::<WTSINFOEXW>()), None);
    }

    #[test]
    fn reads_from_an_unaligned_buffer() {
        let info = record(1, "bob", 0);
        let size = size_of::<WTSINFOEXW>();
        let mut bytes = vec![0u8; size + 1];
        // SAFETY: copying the record's bytes into a buffer one longer.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&info as *const WTSINFOEXW).cast::<u8>(),
                bytes.as_mut_ptr().add(1),
                size,
            );
        }
        // SAFETY: `size` bytes from offset 1 are inside the vector.
        let got = unsafe { session_state(bytes.as_ptr().add(1), size) };
        assert_eq!(got, Some((true, true)));
    }
}
