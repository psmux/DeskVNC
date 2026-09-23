//! Start the native keyboard capture on its own and print every key it
//! swallows, for checking pass-through without the application around it.
//!
//! ```sh
//! cargo run -p vnc-input-capture --example capture_probe -- 20
//! ```
//!
//! The argument is how many seconds to hold the grab (default 15).
//! Ctrl+Alt+Shift+Esc is never swallowed, and the grab ends by itself.

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    let cycles: u32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (tx, rx) = crossbeam_channel::unbounded();
    let mut capture = vnc_input_capture::create(tx).expect("backend");
    // Optionally arm and release a few times first, the way a window losing
    // and regaining focus does, so a grab that only works on its first
    // installation shows up here.
    for _ in 0..cycles {
        capture.start().expect("start");
        capture.stop();
    }
    capture.start().expect("start");
    println!("capture {:?} for {secs}s after {cycles} stop/start cycles", capture.status());
    let until = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < until {
        if let Ok(k) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
            println!(
                "swallowed {} scancode 0x{:02x} keysym 0x{:04x}",
                if k.down { "down" } else { "up  " },
                k.scancode,
                k.keysym
            );
        }
    }
    capture.stop();
    println!("released");
}
