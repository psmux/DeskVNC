//! Windows shortcut capture from a helper process.
//!
//! # Why a second process
//!
//! A `WH_KEYBOARD_LL` hook installed inside the DeskVNC process is not called
//! while a DeskVNC window is the foreground window, which is exactly when it is
//! needed. Measured on Windows 11 with a trace at the first line of the hook
//! procedure: typing into a focused session produced no calls at all, Windows
//! performed Alt+Tab itself, and calls resumed the moment another application
//! came to the front. The same backend running in a separate process swallows
//! Alt+Tab and Win+Tab reliably while DeskVNC is in front, and while such a
//! process is hooked, even the in-process hook starts being called through its
//! `CallNextHookEx`. A dedicated hook thread with its own message pump, which
//! the in-process backend already had, did not avoid it, and neither did
//! passing the module handle. Whatever the mechanism, WebView2 hosting is the
//! likely party; the helper sidesteps it.
//!
//! So the application relaunches its own executable with
//! [`HELPER_FLAG`], and that process owns the hook. It is the same
//! [`WindowsCapture`](crate::windows::WindowsCapture), gated on the session
//! window being the foreground window, with the captured keys written to its
//! stdout one line each.
//!
//! # Protocol
//!
//! Helper stdout, one line per event:
//! - `ready` once the hook is installed,
//! - `k <scancode> <keysym> <1|0>` for each swallowed key transition.
//!
//! Helper stdin, one line per command:
//! - `t <hwnd>` to change the target window (0 for none).
//!
//! The helper exits when its stdin reaches end of file, which is also what
//! happens when the application dies, since the application holds the only
//! write end of that pipe. The hook is never allowed to touch the pipe: it
//! pushes onto an in-memory channel and a writer thread does the I/O, so a
//! slow reader can never stall a keystroke.

use std::io::{BufRead, BufReader, Write};
use std::os::windows::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;

use crate::{CaptureStatus, CapturedKey, Error, KeyboardCapture, Result};

/// The command line flag that turns the application's executable into the
/// capture helper. `main` must check for it before anything else starts.
pub const HELPER_FLAG: &str = "--dvv-keyboard-helper";

const STATUS_INACTIVE: u8 = 0;
const STATUS_ACTIVE: u8 = 1;

/// `CREATE_NO_WINDOW`: the helper must never show a console, which would also
/// take the foreground away from the session window.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How long `start` waits for the helper to report its hook installed.
const READY_TIMEOUT: Duration = Duration::from_secs(3);

/// Capture backend that runs the hook in a child process.
pub struct HelperCapture {
    tx: Sender<CapturedKey>,
    target: isize,
    status: Arc<AtomicU8>,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    reader: Option<JoinHandle<()>>,
}

impl HelperCapture {
    pub fn new(tx: Sender<CapturedKey>) -> Self {
        Self {
            tx,
            target: 0,
            status: Arc::new(AtomicU8::new(STATUS_INACTIVE)),
            child: None,
            stdin: None,
            reader: None,
        }
    }

    fn send_target(&mut self) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = writeln!(stdin, "t {}", self.target);
            let _ = stdin.flush();
        }
    }
}

impl KeyboardCapture for HelperCapture {
    fn start(&mut self) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            if matches!(child.try_wait(), Ok(None)) {
                return Ok(());
            }
            // The helper died on its own. Clear it away and start a fresh one,
            // or switching pass-through back on would silently do nothing.
            self.stop();
        }
        let exe = std::env::current_exe()
            .map_err(|e| Error::Backend(format!("cannot find the application executable: {e}")))?;
        let mut child = Command::new(exe)
            .arg(HELPER_FLAG)
            .arg(self.target.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| Error::Backend(format!("could not start the keyboard helper: {e}")))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let stdin = child.stdin.take().expect("stdin is piped");

        let (ready_tx, ready_rx) = crossbeam_channel::bounded::<()>(1);
        let tx = self.tx.clone();
        let status = self.status.clone();
        let reader = std::thread::Builder::new()
            .name("vnc-capture-helper-read".into())
            .spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    let mut parts = line.split_ascii_whitespace();
                    match parts.next() {
                        Some("ready") => {
                            status.store(STATUS_ACTIVE, Ordering::Relaxed);
                            let _ = ready_tx.try_send(());
                        }
                        Some("k") => {
                            let mut num = || parts.next().and_then(|p| p.parse::<u32>().ok());
                            if let (Some(scancode), Some(keysym), Some(down)) = (num(), num(), num())
                            {
                                let _ = tx.send(CapturedKey {
                                    scancode,
                                    keysym,
                                    down: down != 0,
                                });
                            }
                        }
                        _ => {}
                    }
                }
                // The helper is gone, whatever the reason: nothing is grabbed.
                status.store(STATUS_INACTIVE, Ordering::Relaxed);
            })
            .map_err(|e| Error::Backend(format!("could not start the helper reader: {e}")))?;

        self.child = Some(child);
        self.stdin = Some(stdin);
        self.reader = Some(reader);

        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if ready_rx.try_recv().is_ok() {
                return Ok(());
            }
            if self.status.load(Ordering::Relaxed) == STATUS_ACTIVE {
                return Ok(());
            }
            let exited = self
                .child
                .as_mut()
                .map(|c| matches!(c.try_wait(), Ok(Some(_))))
                .unwrap_or(true);
            if exited || Instant::now() >= deadline {
                self.stop();
                return Err(Error::Backend(
                    "the keyboard helper did not install its hook".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn stop(&mut self) {
        // Closing stdin is the helper's signal to unhook and exit.
        self.stdin = None;
        if let Some(mut child) = self.child.take() {
            let deadline = Instant::now() + Duration::from_millis(500);
            while Instant::now() < deadline {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.status.store(STATUS_INACTIVE, Ordering::Relaxed);
    }

    fn status(&self) -> CaptureStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_ACTIVE => CaptureStatus::Active,
            _ => CaptureStatus::Inactive,
        }
    }

    fn set_target_window(&mut self, native: Option<isize>) {
        self.target = native.unwrap_or(0);
        self.send_target();
    }
}

impl Drop for HelperCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Run as the capture helper if this process was started with
/// [`HELPER_FLAG`]. Returns the exit code to use, or `None` for a normal start.
///
/// Call it first thing in `main`, before any window, runtime or webview
/// exists: the helper must stay a plain process with no UI of its own.
pub fn run_helper_if_requested() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some(HELPER_FLAG) {
        return None;
    }
    let target: isize = args.next().and_then(|a| a.parse().ok()).unwrap_or(0);
    Some(run_helper(target))
}

fn run_helper(target: isize) -> i32 {
    let (tx, rx) = crossbeam_channel::unbounded::<CapturedKey>();
    let mut capture = crate::windows::WindowsCapture::new(tx);
    capture.set_target_window(Some(target));
    if capture.start().is_err() || !capture.status().is_active() {
        return 2;
    }
    let target_cell = capture.target_handle();

    // Commands from the application, and the end of the application.
    let (quit_tx, quit_rx) = crossbeam_channel::bounded::<()>(1);
    let _stdin_thread = std::thread::Builder::new()
        .name("vnc-capture-helper-stdin".into())
        .spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                let mut parts = line.split_ascii_whitespace();
                if parts.next() == Some("t") {
                    if let Some(hwnd) = parts.next().and_then(|p| p.parse::<isize>().ok()) {
                        target_cell.store(hwnd, Ordering::Relaxed);
                    }
                }
            }
            let _ = quit_tx.send(());
        });

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if writeln!(out, "ready").and_then(|_| out.flush()).is_err() {
        capture.stop();
        return 3;
    }
    loop {
        crossbeam_channel::select! {
            recv(rx) -> key => {
                let Ok(key) = key else { break };
                let line = writeln!(out, "k {} {} {}", key.scancode, key.keysym, u8::from(key.down))
                    .and_then(|_| out.flush());
                if line.is_err() {
                    break;
                }
            }
            recv(quit_rx) -> _ => break,
        }
    }
    // Unhook first, then hand over everything still queued: a key-up captured
    // just before the end must still reach the application, or the remote is
    // left holding the key down.
    capture.stop();
    for key in rx.try_iter() {
        let _ = writeln!(out, "k {} {} {}", key.scancode, key.keysym, u8::from(key.down));
    }
    let _ = out.flush();
    0
}
