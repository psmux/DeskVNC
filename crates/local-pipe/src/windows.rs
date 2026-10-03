use std::io;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, ERROR_PIPE_BUSY, HANDLE, HANDLE_FLAG_INHERIT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// How long a client waits for a free instance before giving up.
///
/// A listener makes the next instance as soon as one is taken, so a busy pipe
/// is a gap of microseconds between two accepts. Two seconds is a listener
/// that has stopped accepting, which is worth an error rather than a hang.
const BUSY_WAIT: Duration = Duration::from_secs(2);

/// Create one listening instance of the pipe at `name`.
///
/// `first` asks Windows to refuse when any instance of that name already
/// exists, which is how a second copy of the application learns that the first
/// one owns the plane instead of quietly sharing its clients. Every instance
/// after the first passes `false`.
///
/// Must be called inside a tokio runtime: the instance is registered with the
/// reactor as it is made.
///
/// # Errors
///
/// The `io::Error` from building the descriptor or from creating the pipe.
/// `first` with an existing instance is `ERROR_ACCESS_DENIED`.
pub fn create(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let descriptor = OwnerOnly::new()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES whose descriptor
    // lives until `descriptor` drops at the end of this function, after the
    // pipe has been created and the descriptor copied into it by the kernel.
    unsafe { options.create_with_security_attributes_raw(name, (&raw mut attributes).cast()) }
}

/// Open the pipe at `name` as a client, waiting out a busy instance.
///
/// A plain blocking `File`, because the callers are synchronous: one request,
/// one reply, under a lock. `NotFound` means nobody is listening.
///
/// # Errors
///
/// The `io::Error` from opening the pipe.
pub fn connect(name: &str) -> io::Result<std::fs::File> {
    let deadline = Instant::now() + BUSY_WAIT;
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
        {
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

/// Is anything listening at `name`?
///
/// Read from the pipe directory rather than by opening the pipe. Opening it
/// would take a listening instance, and the listener would see a client that
/// connects and leaves, which in the plane's case is an attachment in its
/// audit trail that never happened.
pub fn exists(name: &str) -> bool {
    let Some(wanted) = name.rsplit('\\').next().filter(|n| !n.is_empty()) else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(r"\\.\pipe\") else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case(wanted)
    })
}

/// Stop this process's stdin, stdout and stderr from reaching its children.
///
/// Windows hands a child every inheritable handle its parent has, not only
/// the three it was given, and the handles a shell gives a command are
/// inheritable. So a background process started from a command whose output
/// is piped keeps that pipe open after the command exits, and whatever reads
/// the pipe waits for an end that never comes. An agent running `dvv open`
/// and reading its output is exactly that reader. Call this before starting
/// anything that should outlive the command.
pub fn keep_std_handles_private() {
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle returns a handle this process owns, or null or
        // INVALID_HANDLE_VALUE, on which SetHandleInformation fails harmlessly.
        unsafe {
            let handle = GetStdHandle(which);
            if !handle.is_null() {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

/// A security descriptor granting full access to this process's user, and to
/// nobody else. Protected, so nothing is inherited into it.
struct OwnerOnly(PSECURITY_DESCRIPTOR);

impl OwnerOnly {
    fn new() -> io::Result<OwnerOnly> {
        let sid = current_user_sid()?;
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `sddl` is NUL terminated and outlives the call, and
        // `descriptor` receives a LocalAlloc'd pointer freed in Drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1, // SDDL_REVISION_1
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnerOnly(descriptor))
    }
}

impl Drop for OwnerOnly {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

/// The string form of the SID this process runs as, such as `S-1-5-21-...`.
fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: plain out parameter; the handle is closed below on every path.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = token_user_sid(token);
    // SAFETY: `token` was opened above and is not used after this.
    unsafe { CloseHandle(token) };
    sid
}

fn token_user_sid(token: HANDLE) -> io::Result<String> {
    let mut len = 0u32;
    // SAFETY: a size query with a null buffer, which fails and sets `len`.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // u64 words so the TOKEN_USER read out of it is suitably aligned.
    let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buffer` holds at least `len` bytes.
    if unsafe { GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call above filled the buffer with a TOKEN_USER, and the SID
    // it points to lives inside the same buffer.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text = null_mut();
    // SAFETY: `sid` is valid for the life of `buffer`; `text` is LocalAlloc'd
    // by the call and freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `text` is a NUL terminated wide string.
    let out = unsafe {
        let mut end = 0;
        while *text.add(end) != 0 {
            end += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, end))
    };
    // SAFETY: allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(text.cast()) };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sid_is_a_user_sid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }

    #[tokio::test]
    async fn a_pipe_is_listed_while_it_exists_and_answers_its_owner() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let name = format!(r"\\.\pipe\local-pipe-test-{}", std::process::id());
        assert!(!exists(&name));
        let server = create(&name, true).unwrap();
        assert!(exists(&name));
        // A second first instance is the second application refused.
        assert!(create(&name, true).is_err());

        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut file = connect(&client_name).unwrap();
            file.write_all(b"ping").unwrap();
            let mut reply = [0u8; 4];
            file.read_exact(&mut reply).unwrap();
            reply
        });
        let mut server = server;
        server.connect().await.unwrap();
        let mut heard = [0u8; 4];
        server.read_exact(&mut heard).await.unwrap();
        assert_eq!(&heard, b"ping");
        server.write_all(b"pong").await.unwrap();
        assert_eq!(&client.join().unwrap(), b"pong");
        drop(server);
        // The kernel removes the name once the last handle is closed, which
        // the reactor does a moment after the drop rather than during it.
        let gone = Instant::now() + Duration::from_secs(2);
        while exists(&name) && Instant::now() < gone {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!exists(&name));
    }
}
