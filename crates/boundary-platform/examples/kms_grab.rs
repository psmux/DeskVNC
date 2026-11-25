//! Read the screen from the graphics card as the Linux service does at a
//! Wayland sign in screen, and save it, to check a machine by hand.
//! sudo target/debug/examples/kms_grab [out.png] [count]
//! With a count it reads that many pictures and prints how long they took.
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let out = args.next().unwrap_or_else(|| "kms.png".into());
    let count: u32 = args.next().and_then(|n| n.parse().ok()).unwrap_or(1);
    let start = std::time::Instant::now();
    let (frame, how) = boundary_platform::kms_frame(count.max(1))?;
    println!(
        "{}x{}, {how}, {:.1} ms a picture with the setup",
        frame.width,
        frame.height,
        start.elapsed().as_secs_f64() * 1000.0 / count.max(1) as f64
    );
    image::RgbaImage::from_raw(frame.width, frame.height, frame.rgba)
        .expect("a whole picture")
        .save(&out)?;
    println!("saved {out}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux only");
}
