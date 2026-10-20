//! Server-side quality for Apple Screen Sharing, the Apple Remote Desktop way:
//! the preset selects the resolution the Mac renders and streams. `ScaleFactor`
//! (0x08) was live-tested and does not resize the H.264 path, so a smaller
//! canvas is the one server-side lever that actually reduces bandwidth.
use remote_core::QualityPreset;

/// The canvas each preset asks the Mac for.
///
/// `native` is the Mac's own picture size in pixels and `points` is the size
/// of its desktop in points. On a retina panel the two differ: a 3600x2338
/// screen is 1800x1169 points, so the Mac draws two pixels for every point.
///
/// The presets are therefore measured in **pixels per point** rather than
/// in absolute pixels, because that is what the person sees. A preset of
/// one pixel per point is as sharp as a plain screen; a preset of one and a
/// half is between that and the Mac's own two; the native is the sharpest
/// there is. A preset that named an absolute size would put a retina
/// Mac's "balanced" below one pixel per point, which is blurrier than the
/// screen the person is used to, and would leave a large monitor at
/// sharpness it never had.
///
/// A preset never asks for more than the Mac's own sharpness, and never
/// for more pixels than the Mac has. The desktop keeps its size either way:
/// only the number of pixels that arrive changes.
pub fn resolution_for(preset: QualityPreset, native: (u16, u16), points: (u16, u16)) -> (u16, u16) {
    if native.0 == 0 || native.1 == 0 {
        return native;
    }
    if points.0 == 0 || points.1 == 0 {
        // The Mac has not said how big its screen is in points, so there is
        // nothing to scale. Asking for the native is the honest answer.
        return native;
    }
    // How many pixels the Mac draws for every point of its screen.
    let native_scale =
        (f64::from(native.0) / f64::from(points.0)).min(f64::from(native.1) / f64::from(points.1));
    let wanted = match preset {
        QualityPreset::Low | QualityPreset::BlackAndWhite => 1.0,
        QualityPreset::Medium => 1.5,
        QualityPreset::High | QualityPreset::Auto => native_scale,
    };
    let scale = wanted.min(native_scale);
    let width = ((f64::from(points.0) * scale).round() as u32).clamp(2, u32::from(native.0));
    let height = ((f64::from(points.1) * scale).round() as u32).clamp(2, u32::from(native.1));
    (even(width) as u16, even(height) as u16)
}

/// Round a dimension up to an even number.
///
/// H.264 4:2:0 samples chroma at half resolution in both directions, so an
/// odd width or height leaves a chroma sample that belongs to no pixel. The
/// encoder pads the picture to a whole macroblock, and the viewer then has
/// to crop it back to a size the chroma plane divides evenly. Asking for an
/// even size in the first place avoids the crop.
///
/// Up, not down: rounding down would take the picture below the sharpness
/// that was asked for, and at one pixel per point that is the difference
/// between a plain screen and a blurred one.
fn even(value: u32) -> u32 {
    (value + 1) & !1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A retina Mac: 3600x2338 pixels, 1800x1169 points.
    const RETINA: ((u16, u16), (u16, u16)) = ((3600, 2338), (1800, 1169));
    /// A plain Mac: 1920x1080 pixels, 1920x1080 points.
    const PLAIN: ((u16, u16), (u16, u16)) = ((1920, 1080), (1920, 1080));

    #[test]
    fn a_preset_is_measured_in_pixels_per_point() {
        let (native, points) = RETINA;
        // The Mac draws two pixels for every point.
        assert_eq!(resolution_for(QualityPreset::High, native, points), native);
        assert_eq!(resolution_for(QualityPreset::Auto, native, points), native);
        // Balanced is between a plain screen and the Mac's own.
        let medium = resolution_for(QualityPreset::Medium, native, points);
        assert_eq!(medium, (2700, 1754));
        assert!(medium.0 < native.0 && medium.1 < native.1);
        // Low is a plain screen: one pixel for every point, and never less.
        let low = resolution_for(QualityPreset::Low, native, points);
        assert_eq!(low, (1800, 1170));
        assert!(low.0 <= medium.0 && low.1 <= medium.1);
    }

    #[test]
    fn a_preset_is_never_blurrier_than_a_plain_screen() {
        // This is the case that made "balanced" useless: an absolute box
        // put a retina Mac below one pixel per point.
        let (native, points) = RETINA;
        for preset in [
            QualityPreset::Low,
            QualityPreset::Medium,
            QualityPreset::High,
        ] {
            let (w, h) = resolution_for(preset, native, points);
            assert!(
                f64::from(w) >= f64::from(points.0),
                "{preset:?} asked for {w} pixels across {} points",
                points.0
            );
            assert!(f64::from(h) >= f64::from(points.1));
        }
    }

    #[test]
    fn a_plain_screen_is_left_alone() {
        // One pixel for every point is all a plain screen has, so there is
        // nothing to take away and nothing to add.
        let (native, points) = PLAIN;
        for preset in [
            QualityPreset::Low,
            QualityPreset::Medium,
            QualityPreset::High,
            QualityPreset::Auto,
        ] {
            assert_eq!(resolution_for(preset, native, points), native, "{preset:?}");
        }
    }

    #[test]
    fn a_preset_never_asks_for_more_than_the_mac_has() {
        let (native, points) = RETINA;
        let medium = resolution_for(QualityPreset::Medium, native, points);
        assert!(medium.0 <= native.0 && medium.1 <= native.1);
        // A screen that is not the shape of the preset's ratio is scaled on
        // both axes alike, so the shape never changes.
        let tall = ((3000, 2000), (1500, 1000));
        let (w, h) = resolution_for(QualityPreset::Medium, tall.0, tall.1);
        assert_eq!(w, 2250);
        assert_eq!(h, 1500);
    }

    #[test]
    fn nothing_is_known_yet() {
        assert_eq!(resolution_for(QualityPreset::Low, (0, 0), (0, 0)), (0, 0));
        assert_eq!(
            resolution_for(QualityPreset::Medium, (1920, 1080), (0, 0)),
            (1920, 1080)
        );
    }
}
