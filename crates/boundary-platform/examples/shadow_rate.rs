//! Whether the host's own decoded copy of its video keeps up with the
//! encoder at 60 screens a second of 1920 by 1080: encode a moving screen
//! for five seconds, paced like the sender, then time how long the copy
//! takes to be ready.
//!
//! ```sh
//! shadow_rate [--software] [--secs 5]
//! ```
use boundary_session::Frame;
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let secs: u64 = args
        .iter()
        .position(|a| a == "--secs")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let make = if args.iter().any(|a| a == "--software") {
        boundary_platform::video::software()
    } else {
        boundary_platform::video::encoders()
    };
    let (w, h) = (1920u32, 1080u32);
    let mut encoder = make(w, h)?;
    encoder.set_rate(6_000_000, 60);
    // Text that scrolls a few rows a screen, the hard case for the copy.
    let base: Vec<u8> = (0..w * h)
        .flat_map(|i| {
            let (x, y) = (i % w, i / w);
            let ink = (y % 18) < 11 && ((x * 31 + y * 7) % 13) < 6 && (x % 400) < 320;
            if ink {
                [30, 30, 40, 255]
            } else {
                [240, 240, 235, 255]
            }
        })
        .collect();
    let interval = Duration::from_secs(1) / 60;
    let start = Instant::now();
    let (mut n, mut encoding, mut bytes, mut ready) = (0u32, Duration::ZERO, 0usize, 0u32);
    while start.elapsed() < Duration::from_secs(secs) {
        let at = start + interval * n;
        if let Some(wait) = at.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
        let shift = (n as usize * 4 * w as usize * 4) % base.len();
        let mut rgba = base[shift..].to_vec();
        rgba.extend_from_slice(&base[..shift]);
        let frame = Frame {
            width: w,
            height: h,
            rgba,
        };
        let t = Instant::now();
        let unit = encoder.encode(&frame, n == 0)?;
        encoding += t.elapsed();
        bytes += unit.data.len();
        n += 1;
        // Ask now and then, as a settle would, whether the copy is ready.
        if n % 30 == 0 && encoder.shown().is_some() {
            ready += 1;
        }
    }
    let screens = n as f64 / start.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut caught = None;
    while t.elapsed() < Duration::from_secs(5) {
        if encoder.shown().is_some() {
            caught = Some(t.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    println!(
        "{}: {n} screens at {screens:.1}/s, encode {:.1} ms each, {:.1} Mbit/s | copy ready at {ready} of {} asks while moving | ready {:?} after the last screen",
        encoder.name(),
        encoding.as_secs_f64() * 1000.0 / n as f64,
        bytes as f64 * 8.0 / start.elapsed().as_secs_f64() / 1e6,
        n / 30,
        caught,
    );
    Ok(())
}
