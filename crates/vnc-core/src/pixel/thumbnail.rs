//! Pure-Rust RGBA downscaling for host tile thumbnails (PRD/03 §3).

/// Box-filter downscale of an RGBA8888 image to at most `max_width` wide,
/// preserving aspect ratio. Returns `(width, height, rgba)`.
///
/// If the source is already narrow enough it is returned unscaled.
pub fn downscale_rgba(src: &[u8], width: u32, height: u32, max_width: u32) -> (u32, u32, Vec<u8>) {
    let needed = (width as usize)
        .checked_mul(height as usize)
        .and_then(|p| p.checked_mul(4));
    let needed = match needed {
        Some(n) => n,
        None => return (0, 0, Vec::new()),
    };
    if width == 0 || height == 0 || max_width == 0 || src.len() < needed {
        return (0, 0, Vec::new());
    }
    if width <= max_width {
        return (width, height, src[..needed].to_vec());
    }

    let out_w = max_width;
    let out_h = (((height as u64) * (out_w as u64) + (width as u64) / 2) / width as u64).max(1);
    let out_h = out_h.min(u32::MAX as u64) as u32;

    let mut out = vec![0u8; out_w as usize * out_h as usize * 4];
    let src_w = width as usize;

    for oy in 0..out_h as usize {
        // Source row range [y0, y1) for this output row.
        let y0 = (oy as u64 * height as u64 / out_h as u64) as usize;
        let mut y1 = ((oy as u64 + 1) * height as u64 / out_h as u64) as usize;
        if y1 <= y0 {
            y1 = y0 + 1;
        }
        let y1 = y1.min(height as usize);
        for ox in 0..out_w as usize {
            let x0 = (ox as u64 * width as u64 / out_w as u64) as usize;
            let mut x1 = ((ox as u64 + 1) * width as u64 / out_w as u64) as usize;
            if x1 <= x0 {
                x1 = x0 + 1;
            }
            let x1 = x1.min(src_w);

            let mut acc = [0u64; 4];
            let mut count = 0u64;
            for y in y0..y1 {
                let row = y * src_w;
                for x in x0..x1 {
                    let p = (row + x) * 4;
                    acc[0] += src[p] as u64;
                    acc[1] += src[p + 1] as u64;
                    acc[2] += src[p + 2] as u64;
                    acc[3] += src[p + 3] as u64;
                    count += 1;
                }
            }
            let o = (oy * out_w as usize + ox) * 4;
            // Rounded mean of the source box; skipped entirely for empty boxes,
            // which leaves the destination pixel transparent-black.
            if let Some(n) = std::num::NonZeroU64::new(count) {
                let n = n.get();
                for c in 0..4 {
                    out[o + c] = ((acc[c] + n / 2) / n) as u8;
                }
            }
        }
    }
    (out_w, out_h, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_scale_when_narrow() {
        let src = vec![7u8; 4 * 4 * 4];
        let (w, h, data) = downscale_rgba(&src, 4, 4, 8);
        assert_eq!((w, h), (4, 4));
        assert_eq!(data, src);
    }

    #[test]
    fn halves_evenly() {
        // 4x2 image, left half red, right half blue -> 2x1 output
        let mut src = vec![0u8; 4 * 2 * 4];
        for y in 0..2 {
            for x in 0..4 {
                let p = (y * 4 + x) * 4;
                if x < 2 {
                    src[p] = 255;
                } else {
                    src[p + 2] = 255;
                }
                src[p + 3] = 255;
            }
        }
        let (w, h, data) = downscale_rgba(&src, 4, 2, 2);
        assert_eq!((w, h), (2, 1));
        assert_eq!(&data[0..4], &[255, 0, 0, 255]);
        assert_eq!(&data[4..8], &[0, 0, 255, 255]);
    }

    #[test]
    fn zero_input_is_safe() {
        assert_eq!(downscale_rgba(&[], 0, 0, 100), (0, 0, Vec::new()));
        assert_eq!(downscale_rgba(&[1, 2, 3], 100, 100, 10), (0, 0, Vec::new()));
    }
}
