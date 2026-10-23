//! Time one screen capture, at full Retina pixels and at point size,
//! without asking for permission first, so it can run over SSH. Where macOS
//! refuses the windows it still returns the wallpaper, which costs the same.
use std::time::Instant;

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn main() {
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
