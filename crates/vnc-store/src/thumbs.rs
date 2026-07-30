//! Thumbnail cache: PNG files under `data_dir/thumbnails/<host_id>.png`,
//! downscaled with `fast_image_resize` and capped by an LRU (mtime) policy.

use std::path::PathBuf;

use fast_image_resize::images::{Image, ImageRef};
use fast_image_resize::{PixelType, Resizer};
use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder};

use crate::{now_ts, Error, Result, Store};

/// Thumbnails are downscaled to at most this width (aspect preserved).
const MAX_THUMB_WIDTH: u32 = 480;
/// LRU cap: at most this many thumbnail files ...
const MAX_THUMB_FILES: usize = 200;
/// ... and at most this many bytes in total.
const MAX_THUMB_BYTES: u64 = 50 * 1024 * 1024;

/// Encode a thumbnail key as a single, portable file name component.
///
/// The key is not always a UUID: a session started from the Nearby list has no
/// profile, so it is keyed by endpoint (`discovered:10.0.0.5:5900`, see
/// `discovered_key` in the shell). That string contains `:`, illegal in a
/// Windows file name, and an address is ultimately network-supplied, so a `/`
/// or `..` in it would otherwise write outside the cache directory.
///
/// Everything outside `[A-Za-z0-9._-]` becomes `%XX`, which is injective (so
/// two keys can never share a file) and leaves plain UUID keys, the only kind
/// written before this existed, byte-for-byte unchanged.
fn encode_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for (i, byte) in key.bytes().enumerate() {
        let plain = byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'_'
            // A leading dot would make ".." (parent directory) or a hidden file.
            || (byte == b'.' && i > 0);
        if plain {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

impl Store {
    /// Downscales a full-size RGBA framebuffer to a thumbnail (max width
    /// 480 px, aspect preserved), stores it as
    /// `data_dir/thumbnails/<host_id>.png`, updates `hosts.thumbnail_at`,
    /// and enforces the cache cap (LRU by file mtime).
    pub fn save_thumbnail(
        &self,
        host_id: &str,
        rgba: &[u8],
        width: u32,
        height: u32,
    ) -> Result<()> {
        if host_id.is_empty() {
            return Err(Error::InvalidData("empty thumbnail key".into()));
        }
        if width == 0 || height == 0 {
            return Err(Error::InvalidData("zero-sized framebuffer".into()));
        }
        let expected = width as usize * height as usize * 4;
        if rgba.len() < expected {
            return Err(Error::InvalidData(format!(
                "rgba buffer is {} bytes, need {expected} for {width}x{height}",
                rgba.len()
            )));
        }
        let rgba = &rgba[..expected];

        let mut dst_holder;
        let (png_pixels, out_w, out_h);
        if width > MAX_THUMB_WIDTH {
            let dst_w = MAX_THUMB_WIDTH;
            let dst_h =
                ((height as u64 * dst_w as u64 + width as u64 / 2) / width as u64).max(1) as u32;
            let src = ImageRef::new(width, height, rgba, PixelType::U8x4)
                .map_err(|e| Error::Image(format!("bad source buffer: {e}")))?;
            dst_holder = Image::new(dst_w, dst_h, PixelType::U8x4);
            let mut resizer = Resizer::new();
            resizer
                .resize(&src, &mut dst_holder, None)
                .map_err(|e| Error::Image(format!("resize failed: {e}")))?;
            png_pixels = dst_holder.buffer();
            out_w = dst_w;
            out_h = dst_h;
        } else {
            png_pixels = rgba;
            out_w = width;
            out_h = height;
        }

        let dir = self.data_dir().join("thumbnails");
        std::fs::create_dir_all(&dir)?;
        let path = self.thumbnail_path(host_id);
        let tmp = dir.join(format!("{}.png.tmp", encode_key(host_id)));
        {
            let file = std::fs::File::create(&tmp)?;
            let encoder = PngEncoder::new(std::io::BufWriter::new(file));
            encoder
                .write_image(png_pixels, out_w, out_h, ExtendedColorType::Rgba8)
                .map_err(|e| Error::Image(format!("png encode failed: {e}")))?;
        }
        std::fs::rename(&tmp, &path)?;

        // Flag the profile. A `discovered:` key matches no row, which is fine:
        // the PNG on disk is the source of truth for whether a tile has an
        // image, `thumbnail_at` only records *when* for saved hosts.
        {
            let conn = self.conn_lock();
            conn.execute(
                "UPDATE hosts SET thumbnail_at = ?1 WHERE id = ?2",
                rusqlite::params![now_ts(), host_id],
            )?;
        }

        // The file we just wrote is never a candidate for eviction, see
        // `evict_thumbnails`.
        self.evict_thumbnails(Some(&path));
        Ok(())
    }

    /// Path of the (possibly nonexistent) thumbnail file for a host.
    pub fn thumbnail_path(&self, host_id: &str) -> PathBuf {
        self.data_dir()
            .join("thumbnails")
            .join(format!("{}.png", encode_key(host_id)))
    }

    /// Returns the stored PNG bytes, or `None` when no thumbnail exists.
    pub fn load_thumbnail(&self, host_id: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.thumbnail_path(host_id)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes the thumbnail file (missing files are not an error) and clears
    /// `hosts.thumbnail_at`.
    pub fn delete_thumbnail(&self, host_id: &str) -> Result<()> {
        match std::fs::remove_file(self.thumbnail_path(host_id)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let conn = self.conn_lock();
        conn.execute(
            "UPDATE hosts SET thumbnail_at = NULL WHERE id = ?1",
            rusqlite::params![host_id],
        )?;
        Ok(())
    }

    /// Best-effort LRU eviction: oldest files (by mtime) are removed until
    /// the cache is within [`MAX_THUMB_FILES`] / [`MAX_THUMB_BYTES`].
    ///
    /// `keep` (the file the caller has just written) and the newest file on
    /// disk are never removed, whatever the caps say. Without that guarantee a
    /// single oversized entry, or a cache already at the byte cap, could delete
    /// the screenshot the user is at that moment waiting to see, the tile
    /// would go blank the instant it was captured, and stay blank across
    /// restarts. Staying one file over the cap is the cheaper failure.
    fn evict_thumbnails(&self, keep: Option<&std::path::Path>) {
        let dir = self.data_dir().join("thumbnails");
        let Ok(read) = std::fs::read_dir(&dir) else {
            return;
        };
        let mut files: Vec<(PathBuf, std::time::SystemTime, u64)> = Vec::new();
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "png") != Some(true) {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                files.push((path, mtime, meta.len()));
            }
        }
        let mut total: u64 = files.iter().map(|f| f.2).sum();
        let mut count = files.len();
        if count <= MAX_THUMB_FILES && total <= MAX_THUMB_BYTES {
            return;
        }
        files.sort_by_key(|f| f.1); // oldest first
                                    // Never the newest entry, and never the one just written: mtime
                                    // resolution is coarse enough (one second on some filesystems) that a
                                    // burst of captures can otherwise sort the fresh file first.
        let candidates = files.len().saturating_sub(1);
        for (path, _, size) in files.into_iter().take(candidates) {
            if count <= MAX_THUMB_FILES && total <= MAX_THUMB_BYTES {
                break;
            }
            if keep == Some(path.as_path()) {
                continue;
            }
            if std::fs::remove_file(&path).is_ok() {
                tracing::debug!(path = %path.display(), "evicted thumbnail (LRU cap)");
                count -= 1;
                total = total.saturating_sub(size);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
        (dir, store)
    }

    fn gradient_rgba(w: u32, h: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                buf.push((x % 256) as u8);
                buf.push((y % 256) as u8);
                buf.push(((x + y) % 256) as u8);
                buf.push(255);
            }
        }
        buf
    }

    #[test]
    fn thumbnail_save_load_delete() {
        let (_dir, store) = temp_store();
        let host = crate::HostProfile {
            friendly_name: "Thumb".into(),
            address: "10.0.0.9".into(),
            ..Default::default()
        };
        store.save_host(&host).unwrap();

        let rgba = gradient_rgba(960, 540);
        store.save_thumbnail(&host.id, &rgba, 960, 540).unwrap();

        let png = store
            .load_thumbnail(&host.id)
            .unwrap()
            .expect("thumbnail saved");
        let decoded = image::load_from_memory(&png).unwrap();
        assert_eq!(decoded.width(), 480, "downscaled to max width");
        assert_eq!(decoded.height(), 270, "aspect preserved");
        assert!(store
            .thumbnail_path(&host.id)
            .ends_with(format!("{}.png", host.id)));

        let refreshed = store.get_host(&host.id).unwrap().unwrap();
        assert!(refreshed.thumbnail_at.is_some(), "thumbnail_at flagged");

        store.delete_thumbnail(&host.id).unwrap();
        assert!(store.load_thumbnail(&host.id).unwrap().is_none());
        assert!(store
            .get_host(&host.id)
            .unwrap()
            .unwrap()
            .thumbnail_at
            .is_none());
        // Deleting again is fine.
        store.delete_thumbnail(&host.id).unwrap();
    }

    /// The framebuffer arrives top-down (row 0 is the top of the desktop) and
    /// must stay that way through the downscale + PNG encode. A flip here
    /// would put every library tile on its head.
    #[test]
    fn row_order_is_preserved_top_down() {
        let (_dir, store) = temp_store();
        let (w, h) = (960u32, 540u32);
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            // Top half red, bottom half blue.
            let (r, b) = if y < h / 2 { (255, 0) } else { (0, 255) };
            for _ in 0..w {
                rgba.extend_from_slice(&[r, 0, b, 255]);
            }
        }
        store.save_thumbnail("orient", &rgba, w, h).unwrap();
        let png = store.load_thumbnail("orient").unwrap().unwrap();
        let decoded = image::load_from_memory(&png).unwrap().to_rgba8();

        let top = decoded.get_pixel(decoded.width() / 2, 2);
        let bottom = decoded.get_pixel(decoded.width() / 2, decoded.height() - 3);
        assert!(top[0] > 200 && top[2] < 55, "top row stayed red: {top:?}");
        assert!(
            bottom[2] > 200 && bottom[0] < 55,
            "bottom row stayed blue: {bottom:?}"
        );
    }

    #[test]
    fn small_frames_are_not_upscaled() {
        let (_dir, store) = temp_store();
        let rgba = gradient_rgba(320, 200);
        store.save_thumbnail("small-host", &rgba, 320, 200).unwrap();
        let png = store.load_thumbnail("small-host").unwrap().unwrap();
        let decoded = image::load_from_memory(&png).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (320, 200));
    }

    #[test]
    fn bad_buffer_is_rejected() {
        let (_dir, store) = temp_store();
        assert!(matches!(
            store.save_thumbnail("x", &[0u8; 16], 100, 100),
            Err(Error::InvalidData(_))
        ));
        assert!(matches!(
            store.save_thumbnail("x", &[], 0, 10),
            Err(Error::InvalidData(_))
        ));
    }

    /// A session started from the Nearby list has no profile row, so its
    /// screenshot is filed under `discovered:<address>:<port>`. Nothing in the
    /// store may reject that: there is no `hosts` row to join against, and the
    /// key contains characters a naive `format!("{key}.png")` would turn into a
    /// path separator or an illegal Windows file name.
    #[test]
    fn discovered_key_round_trips_without_a_host_row() {
        let (_dir, store) = temp_store();
        let key = "discovered:192.168.77.150:5900";

        store
            .save_thumbnail(key, &gradient_rgba(960, 540), 960, 540)
            .unwrap();

        let png = store
            .load_thumbnail(key)
            .unwrap()
            .expect("a host-less key still stores a thumbnail");
        assert_eq!(image::load_from_memory(&png).unwrap().width(), 480);

        let path = store.thumbnail_path(key);
        assert!(path.exists());
        assert_eq!(path.parent().unwrap(), store.data_dir().join("thumbnails"));
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(!name.contains(':'), "portable file name: {name}");
        assert!(!name.contains(std::path::MAIN_SEPARATOR));
    }

    /// The whole point of the cache: quit the app, come back, still recognise
    /// the machine. A fresh `Store` over the same data dir must see the PNG,
    /// for a discovered key as much as for a saved profile.
    #[test]
    fn thumbnails_survive_reopening_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let host = crate::HostProfile {
            friendly_name: "Saved".into(),
            address: "10.0.0.4".into(),
            ..Default::default()
        };
        let discovered = "discovered:10.0.0.5:5901";

        {
            let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
            store.save_host(&host).unwrap();
            store
                .save_thumbnail(&host.id, &gradient_rgba(640, 400), 640, 400)
                .unwrap();
            store
                .save_thumbnail(discovered, &gradient_rgba(640, 400), 640, 400)
                .unwrap();
        }

        // Everything above is dropped, this is the next launch of the app.
        let store = Store::open(Some(dir.path().to_path_buf())).unwrap();
        assert!(
            store.load_thumbnail(&host.id).unwrap().is_some(),
            "saved host kept its thumbnail across a restart"
        );
        assert!(
            store.load_thumbnail(discovered).unwrap().is_some(),
            "discovered host kept its thumbnail across a restart"
        );
        // …and the flag the library reads back on startup moved with it.
        assert!(store
            .get_host(&host.id)
            .unwrap()
            .unwrap()
            .thumbnail_at
            .is_some());
    }

    /// Eviction runs on every save. If it could take the file it was just
    /// handed, a capture would vanish the moment it was made.
    #[test]
    fn eviction_never_takes_the_newest_thumbnail() {
        let (_dir, store) = temp_store();
        let rgba = gradient_rgba(64, 64);
        // Comfortably past MAX_THUMB_FILES.
        for i in 0..(MAX_THUMB_FILES + 25) {
            store
                .save_thumbnail(&format!("host-{i}"), &rgba, 64, 64)
                .unwrap();
        }
        let newest = format!("host-{}", MAX_THUMB_FILES + 24);
        assert!(
            store.load_thumbnail(&newest).unwrap().is_some(),
            "the thumbnail written last is still there"
        );
        let count = std::fs::read_dir(store.data_dir().join("thumbnails"))
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().map(|x| x == "png") == Some(true))
            .count();
        assert!(
            count <= MAX_THUMB_FILES + 1,
            "cache stayed bounded: {count}"
        );
        assert!(
            count >= MAX_THUMB_FILES - 1,
            "cache not over-evicted: {count}"
        );
    }

    /// An address is network-supplied, so the key can be hostile.
    #[test]
    fn a_traversing_key_cannot_escape_the_cache_directory() {
        let (_dir, store) = temp_store();
        let key = "discovered:../../evil:5900";
        store
            .save_thumbnail(key, &gradient_rgba(32, 32), 32, 32)
            .unwrap();
        let path = store.thumbnail_path(key);
        assert_eq!(path.parent().unwrap(), store.data_dir().join("thumbnails"));
        assert!(path.exists());
        assert!(store.load_thumbnail(key).unwrap().is_some());
    }

    #[test]
    fn key_encoding_is_injective_and_leaves_uuids_alone() {
        let uuid = "d01a066d-ec6c-46e7-8501-be134b527717";
        assert_eq!(encode_key(uuid), uuid, "existing files keep their names");
        assert_eq!(
            encode_key("discovered:10.0.0.5:5900"),
            "discovered%3A10.0.0.5%3A5900"
        );
        assert_ne!(encode_key("a:b"), encode_key("a%3Ab"));
        assert_eq!(encode_key(".."), "%2E.");
        assert!(!encode_key("../x").contains('/'));
    }

    #[test]
    fn an_empty_key_is_rejected() {
        let (_dir, store) = temp_store();
        assert!(matches!(
            store.save_thumbnail("", &gradient_rgba(8, 8), 8, 8),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn delete_host_removes_thumbnail() {
        let (_dir, store) = temp_store();
        let host = crate::HostProfile {
            friendly_name: "T".into(),
            address: "10.0.0.10".into(),
            ..Default::default()
        };
        store.save_host(&host).unwrap();
        store
            .save_thumbnail(&host.id, &gradient_rgba(64, 64), 64, 64)
            .unwrap();
        assert!(store.thumbnail_path(&host.id).exists());
        store.delete_host(&host.id).unwrap();
        assert!(!store.thumbnail_path(&host.id).exists());
    }
}
