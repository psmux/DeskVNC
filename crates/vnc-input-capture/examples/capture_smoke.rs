//! Manual smoke test for the real platform backend.
//!
//! Keyboard capture cannot be exercised in CI, it needs a window server, a
//! logged-in session, and (on macOS) an Accessibility grant tied to code
//! identity. This example is the substitute: run it, press the shortcuts, and
//! watch what gets intercepted.
//!
//! ```sh
//! cargo run -p vnc-input-capture --example capture_smoke
//! ```
//!
//! It grabs for 10 seconds and then releases. `Ctrl+Alt+Shift+Esc` is excluded
//! from interception by policy, so it always reaches the local machine, try it
//! and confirm nothing is swallowed.

use std::time::{Duration, Instant};

use vnc_input_capture::{create, permission_granted, xt_to_code, CaptureStatus};

fn main() {
    let (tx, rx) = crossbeam_channel::unbounded();
    let mut capture = match create(tx) {
        Ok(capture) => capture,
        Err(e) => {
            eprintln!("could not create a capture backend: {e}");
            return;
        }
    };

    println!("permission granted: {}", permission_granted());
    println!("status before start:  {:?}", capture.status());

    if let Err(e) = capture.start() {
        eprintln!("start failed: {e}");
        if matches!(capture.status(), CaptureStatus::PermissionRequired) {
            eprintln!(
                "grant Accessibility to this binary (System Settings > Privacy & Security > \
                 Accessibility) and run it again"
            );
        }
        return;
    }

    let status = capture.status();
    println!("status after start:   {status:?}");
    if !status.is_active() {
        capture.stop();
        return;
    }

    println!("\ncapturing for 10s, try Cmd+Tab, Cmd+Space, Alt+Tab, the Windows key…");
    println!("(Ctrl+Alt+Shift+Esc must NOT be intercepted)\n");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(key) => println!(
                "  {:<5} scancode {:#04x} ({}) keysym {:#06x}",
                if key.down { "down" } else { "up" },
                key.scancode,
                xt_to_code(key.scancode).unwrap_or("?"),
                key.keysym,
            ),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    capture.stop();
    println!("\nstatus after stop:    {:?}", capture.status());
}
