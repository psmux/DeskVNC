//! Encode a few seconds of a moving screen with the encoder this Mac would
//! host with, and write each picture to a file, to feed a helper's decoder
//! offline.
//!
//! ```sh
//! dump_units <dir> [--frames 60]
//! ```
use boundary_session::Frame;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(args.get(1).expect("a directory"));
    let frames: u32 = args
        .iter()
        .position(|a| a == "--frames")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let (w, h) = (1920u32, 1080u32);
    let mut encoder = boundary_platform::video::encoders()(w, h)?;
    eprintln!("encoder {}", encoder.name());
    encoder.set_rate(3_000_000, 30);
    for n in 0..frames {
        let rgba = (0..w * h)
            .flat_map(|i| {
                let (x, y) = (i % w, i / w);
                let v = ((x + n * 8) ^ (y + n * 3)) as u8;
                [v, v / 2, 255 - v, 255]
            })
            .collect();
        let encoded = encoder.encode(
            &Frame {
                width: w,
                height: h,
                rgba,
            },
            n == 0,
        )?;
        std::fs::write(
            dir.join(format!(
                "{n:03}{}.h264",
                if encoded.keyframe { "k" } else { "" }
            )),
            &encoded.data,
        )?;
    }
    Ok(())
}
