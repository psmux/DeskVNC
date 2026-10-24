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
#[cfg(not(target_os = "macos"))]
fn main() {}
