//! Host card thumbnails: a JPEG about 480 pixels wide per saved computer.

use std::path::{Path, PathBuf};

use base64::Engine;

/// Width of a stored thumbnail. A host card is at most the width of a
/// tablet column, and 480 at 2x or 3x pixel density is sharp there.
pub const WIDTH: u32 = 480;
/// JPEG quality. A desktop screenshot at this size compresses to around
/// 20 to 40 KB, cheap to hand to the UI as a data URL.
const QUALITY: u8 = 78;
/// The largest framebuffer the UI may claim, the desktop's bound too.
const MAX_DIMENSION: u32 = 16_384;

/// Check the UI supplied size against the body it actually sent.
pub fn validate(width: u32, height: u32, len: usize) -> Result<(), String> {
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err("invalid thumbnail dimensions".into());
    }
    if len != width as usize * height as usize * 4 {
        return Err("thumbnail body length does not match width*height*4".into());
    }
    Ok(())
}

/// Scale RGBA pixels down to [`WIDTH`] (never up) and encode them as JPEG.
pub fn encode(rgba: Vec<u8>, width: u32, height: u32) -> Result<Vec<u8>, String> {
    validate(width, height, rgba.len())?;
    let image = image::RgbaImage::from_raw(width, height, rgba)
        .ok_or("thumbnail pixels do not match their size")?;
    let image = if width > WIDTH {
        let h = ((u64::from(height) * u64::from(WIDTH)) / u64::from(width)).max(1) as u32;
        image::imageops::resize(&image, WIDTH, h, image::imageops::FilterType::Triangle)
    } else {
        image
    };
    // JPEG has no alpha. A framebuffer's alpha is meaningless anyway.
    let rgb = image::DynamicImage::ImageRgba8(image).into_rgb8();
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, QUALITY)
        .encode_image(&rgb)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

pub fn path(dir: &Path, host_id: &str) -> PathBuf {
    dir.join(format!("{host_id}.jpg"))
}

/// Write a thumbnail through a temporary file, so a reader never sees half.
pub fn save(dir: &Path, host_id: &str, jpeg: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let target = path(dir, host_id);
    let tmp = target.with_extension("jpg.tmp");
    std::fs::write(&tmp, jpeg).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &target).map_err(|e| e.to_string())
}

/// The stored thumbnail as a `data:image/jpeg;base64,` URL, or `None`.
pub fn data_url(dir: &Path, host_id: &str) -> Result<Option<String>, String> {
    match std::fs::read(path(dir, host_id)) {
        Ok(bytes) => Ok(Some(format!(
            "data:image/jpeg;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub fn delete(dir: &Path, host_id: &str) {
    let _ = std::fs::remove_file(path(dir, host_id));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scales_down_to_480_and_keeps_the_aspect() {
        let (w, h) = (1920u32, 1080u32);
        let jpeg = encode(vec![200u8; (w * h * 4) as usize], w, h).unwrap();
        let img = image::load_from_memory(&jpeg).unwrap();
        assert_eq!((img.width(), img.height()), (480, 270));
    }

    #[test]
    fn never_scales_up() {
        let jpeg = encode(vec![0u8; 100 * 50 * 4], 100, 50).unwrap();
        let img = image::load_from_memory(&jpeg).unwrap();
        assert_eq!((img.width(), img.height()), (100, 50));
    }

    #[test]
    fn rejects_a_lying_size() {
        assert!(encode(vec![0u8; 10], 100, 50).is_err());
        assert!(validate(0, 10, 0).is_err());
        assert!(validate(20_000, 1, 80_000).is_err());
    }

    #[test]
    fn save_and_read_back_as_a_data_url() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(data_url(dir.path(), "h1").unwrap(), None);
        save(dir.path(), "h1", b"\xff\xd8jpeg").unwrap();
        let url = data_url(dir.path(), "h1").unwrap().unwrap();
        assert!(url.starts_with("data:image/jpeg;base64,"));
        delete(dir.path(), "h1");
        assert_eq!(data_url(dir.path(), "h1").unwrap(), None);
    }
}
