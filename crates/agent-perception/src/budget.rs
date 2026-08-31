//! What a mirror is allowed to cost, and the refusal when it is not.
//!
//! `00 R5` and `03 §2.7`. The arithmetic is exact and it is the whole reason
//! this module exists: `width * height * 4` bytes, no second buffer and no
//! scratch, which is 3.69 MB at 1280x720, 8.29 MB at 1920x1080, 14.75 MB at
//! 2560x1440 and 33.18 MB at 3840x2160. Twelve mirrored 1080p sessions is
//! 95 MiB and comfortable. Twelve mirrored 4K sessions is 380 MiB, which on
//! its own exceeds the 250 MB budget
//! `crates/vnc-core/examples/idle_session.rs` sets for the entire core. The
//! factor between those two cases is about sixty, and that asymmetry is why
//! there is a budget at all rather than a comment saying it is fine.
//!
//! **A mirror over budget refuses. It never quietly gives back something
//! smaller.** That is `00 R5` in one sentence and the reason is the same one
//! `crate::thumbnail::validate_frame` already applies to an untrusted body: a
//! perception layer that hands back something other than what was asked for
//! produces agents that click in the wrong place, and nobody can reproduce it
//! because the response looked fine.

/// A mirror is RGBA8888 and there is no other layout. Named rather than
/// spelled `4` at four call sites, because the number appears in the memory
/// tables of `03 §2.2` and a reader should be able to find the two together.
pub const BYTES_PER_PIXEL: u64 = 4;

/// `03 §2.7`'s recommendation: 4K plus headroom.
///
/// 3840x2160 is 8,294,400 pixels, so this admits a 4K desktop and refuses the
/// next size up. It is a setting and not a law, and it is quoted in `00 R5`
/// where an owner decision is still recorded as pending.
pub const DEFAULT_MAX_MIRROR_PIXELS: u64 = 8_300_000;

/// `03 §2.7`'s recommendation for every mirror in the process together.
///
/// 96 MiB admits three 4K mirrors or eleven 1080p ones. The per session
/// ceiling alone would let twelve 4K sessions reach 380 MiB, which is the
/// case the total exists to catch.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 96 * 1024 * 1024;

/// How long a mirror survives with nothing reading it (`03 §2.7` item 2).
///
/// Sixty seconds, unmeasured, and `03 §8` carries it as spike S3-2. It is a
/// setting for that reason.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 60_000;

/// Bytes a mirror of this geometry occupies.
///
/// The one place the arithmetic is written. `03 §2.2` also costs the resize
/// path, which transiently holds the old image and the new one at once: a 4K
/// session resizing peaks at 63 MiB, and a caller sizing a total budget should
/// know that the peak is not this number.
pub const fn mirror_bytes(width: u16, height: u16) -> u64 {
    width as u64 * height as u64 * BYTES_PER_PIXEL
}

/// Pixels a mirror of this geometry holds.
pub const fn mirror_pixels(width: u16, height: u16) -> u64 {
    width as u64 * height as u64
}

/// The two ceilings and the idle timer, all three settings (`00 R5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorBudget {
    /// Per session, in pixels rather than bytes, because that is the number a
    /// person reads off a resolution.
    pub max_mirror_pixels: u64,
    /// Every mirror in the process together, in bytes.
    pub max_total_bytes: u64,
    /// How long a mirror survives with no reads.
    pub idle_timeout_ms: u64,
}

impl Default for MirrorBudget {
    fn default() -> Self {
        MirrorBudget {
            max_mirror_pixels: DEFAULT_MAX_MIRROR_PIXELS,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
        }
    }
}

impl MirrorBudget {
    /// May a mirror of this geometry be allocated, given what is already out?
    ///
    /// Returns the byte size on success, so a caller that admits and then
    /// allocates does not compute the size twice and cannot compute it
    /// differently the second time.
    ///
    /// `total_bytes_in_use` is passed in rather than held here because this
    /// crate owns no global state and starts no clock. The plane knows how
    /// many sessions it has; a counter in here would be a second opinion about
    /// that, which is the failure `GeometryFence` is not `Clone` to prevent,
    /// one level up.
    pub fn admit(
        &self,
        width: u16,
        height: u16,
        total_bytes_in_use: u64,
    ) -> Result<u64, BudgetRefused> {
        let pixels = mirror_pixels(width, height);
        if pixels > self.max_mirror_pixels {
            return Err(BudgetRefused::Pixels {
                width,
                height,
                pixels,
                budget: self.max_mirror_pixels,
            });
        }
        let bytes = mirror_bytes(width, height);
        let total = total_bytes_in_use.saturating_add(bytes);
        if total > self.max_total_bytes {
            return Err(BudgetRefused::TotalBytes {
                width,
                height,
                bytes,
                in_use: total_bytes_in_use,
                budget: self.max_total_bytes,
            });
        }
        Ok(bytes)
    }
}

/// A mirror was refused, and the sentence says which ceiling refused it.
///
/// Both variants name the budget and the ask. An agent that reads "refused"
/// with no number cannot decide whether to lower its request or to give up,
/// and `03 §2.7` item 4 requires both numbers to be visible in
/// `session.stats` for the same reason.
///
/// There is deliberately no variant meaning "allocated something smaller".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetRefused {
    #[error("a {width}x{height} mirror is {pixels} pixels and the per session budget is {budget}: nothing was allocated and no smaller image was substituted, ask for a region instead or raise the budget")]
    Pixels {
        width: u16,
        height: u16,
        pixels: u64,
        budget: u64,
    },
    #[error("a {width}x{height} mirror needs {bytes} bytes, {in_use} bytes of mirrors are already allocated and the total budget is {budget}: nothing was allocated and no smaller image was substituted, free a mirror or raise the budget")]
    TotalBytes {
        width: u16,
        height: u16,
        bytes: u64,
        in_use: u64,
        budget: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table in `03 §2.2`, which four documents quote.
    #[test]
    fn the_four_documented_resolutions() {
        assert_eq!(mirror_bytes(1280, 720), 3_686_400);
        assert_eq!(mirror_bytes(1920, 1080), 8_294_400);
        assert_eq!(mirror_bytes(2560, 1440), 14_745_600);
        assert_eq!(mirror_bytes(3840, 2160), 33_177_600);
    }

    #[test]
    fn four_k_fits_the_default_pixel_budget_and_the_next_size_up_does_not() {
        let budget = MirrorBudget::default();
        assert!(budget.admit(3840, 2160, 0).is_ok());
        assert!(matches!(
            budget.admit(4096, 2560, 0),
            Err(BudgetRefused::Pixels { .. })
        ));
    }
}
