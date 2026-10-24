//! Time one screen capture, at full Retina pixels and at point size,
//! without asking for permission first, so it can run over SSH. Where macOS
//! refuses the windows it still returns the wallpaper, which costs the same.
use std::time::Instant;

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn main() {
    // What the app uses: a stream where one starts, pictures otherwise.
    let id = boundary_platform::displays().unwrap()[0].id;
    let t = Instant::now();
    let mut capturer = boundary_platform::Capturer::new(id).unwrap();
    println!(
        "capturer ready in {:?}, streaming {}",
        t.elapsed(),
        capturer.streaming()
    );
    let t = Instant::now();
    let (mut new, mut calls) = (0, 0);
    while t.elapsed().as_secs() < 3 {
        calls += 1;
        if let Some(f) = capturer.capture_changed().unwrap() {
            new += 1;
            if new == 1 {
                println!("first screen {}x{}", f.width, f.height);
            }
        }
    }
    println!("3 s: {calls} calls, {new} new screens");
    use objc2_core_graphics::{
        CGDataProvider, CGDisplayBounds, CGImage, CGMainDisplayID, CGWindowImageOption,
        CGWindowListCreateImage, CGWindowListOption,
    };
    let id = CGMainDisplayID();
    for (name, option) in [
        ("retina", CGWindowImageOption::Default),
        ("nominal", CGWindowImageOption::NominalResolution),
    ] {
        for _ in 0..4 {
            let t = Instant::now();
            let image = CGWindowListCreateImage(
                CGDisplayBounds(id),
                CGWindowListOption::OptionAll,
                0,
                option,
            );
            let data = CGDataProvider::data(CGImage::data_provider(image.as_deref()).as_deref())
                .map(|d| d.to_vec())
                .unwrap_or_default();
            println!(
                "{name} {}x{} {} MB capture {:?}",
                CGImage::width(image.as_deref()),
                CGImage::height(image.as_deref()),
                data.len() / 1_000_000,
                t.elapsed()
            );
        }
    }
}
/// On Linux: how the screen is captured, how long a capture of a changed
/// screen takes, how many new screens come in a few seconds, and how much
/// of each the system said had changed.
#[cfg(target_os = "linux")]
fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let displays = boundary_platform::displays().unwrap();
    for d in &displays {
        println!("display {} {}", d.id, d.name);
    }
    let t = Instant::now();
    let mut capturer = boundary_platform::Capturer::new(displays[0].id).unwrap();
    println!(
        "capturer ready in {:?}, backend {}",
        t.elapsed(),
        capturer.backend()
    );
    let t = Instant::now();
    let (mut calls, mut new, mut damaged, mut pixels) = (0u64, 0u64, 0u64, 0u64);
    let mut times = Vec::new();
    while t.elapsed().as_secs() < secs {
        calls += 1;
        let started = Instant::now();
        let frame = capturer.capture_changed().unwrap();
        let took = started.elapsed();
        if let Some(f) = frame {
            new += 1;
            times.push(took);
            if new == 1 {
                println!("first screen {}x{}", f.width, f.height);
            }
            if let Some(rects) = capturer.damage() {
                damaged += 1;
                pixels += rects
                    .iter()
                    .map(|r| r.width as u64 * r.height as u64)
                    .sum::<u64>();
            }
        } else {
            // What the session does between screens.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    times.sort();
    let at =
        |q: f64| times.get(((times.len() as f64 * q) as usize).min(times.len().saturating_sub(1)));
    println!(
        "{secs} s: {calls} calls, {new} new screens ({:.1}/s), {damaged} with damage averaging {} px",
        new as f64 / secs as f64,
        pixels.checked_div(damaged).unwrap_or(0)
    );
    println!(
        "capture of a new screen: median {:?}, p90 {:?}, max {:?}",
        at(0.5),
        at(0.9),
        times.last()
    );
}
#[cfg(windows)]
fn main() {}
