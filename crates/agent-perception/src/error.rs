//! Every way a read can fail, as a type an agent can match on.
//!
//! The sentences are long on purpose. They are read by a model, and `06 §5.5`
//! sets the rule the whole set follows: the code is what an agent matches on
//! and the sentence beside it is what an agent acts on, so a sentence that
//! says only "refused" produces a retry loop. Each one below says what was
//! refused, why, and what would make it work.
//!
//! There is no variant meaning "here is something smaller than you asked for",
//! and there is no variant carrying a frame with unexplained pixels in it.
//! That is `00 R5` and `00 R6` in the shape of an enum.

use crate::budget::BudgetRefused;
use crate::coverage::StaleRegion;
use crate::encode::{DecodeFailed, EncodeFailed};
use limb_core::fence::GeometryRejected;
use remote_core::geometry::Rect;

/// A read did not happen, and this is why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PerceptionError {
    /// `00 R5`. Nothing was allocated and nothing smaller was substituted.
    #[error(transparent)]
    Budget(#[from] BudgetRefused),

    /// `00 R10`. The screen this coordinate space describes no longer exists.
    #[error(transparent)]
    Geometry(#[from] GeometryRejected),

    /// A frame was asked for on a session that has no mirror.
    ///
    /// Not an internal error. A mirror is allocated on the first frame request
    /// and freed after an idle timeout (`00 R5`), so this is the ordinary
    /// answer to a read that arrives after the timeout, and the repair is to
    /// attach again and prime.
    #[error("no mirror is attached to this session: a mirror is allocated on the first frame request and freed after an idle timeout, so attach one and let it prime before reading")]
    NoMirror,

    /// `03 §9 A3`. The mirror is allocated and the server has not painted the
    /// requested region yet, so it holds the opaque black it was allocated
    /// with. Refused rather than returned.
    #[error("{never_written} of the {tiles} tiles covering {region:?} have never been painted since this mirror was allocated: it is priming, send a full refresh and read again rather than trusting the black")]
    Priming {
        region: Rect,
        tiles: u32,
        never_written: u32,
    },

    /// `00 R6`. Something the mirror cannot composite passed over part of the
    /// requested region, so those pixels are left over from before.
    ///
    /// **This is the error the crate exists for.** The alternative, which is
    /// what a mirror built directly on `Framebuffer` does, is to return the
    /// frame with no error at all and stale pixels in exactly the region that
    /// is moving.
    #[error("{} of {region:?} is stale because the mirror cannot composite what passed over it (H.264 is decoded in the webview, never here): stop advertising H.264 on this session, re-send SetEncodings, send a refresh, or ask for the frame with the stale regions annotated instead", stale_regions.len())]
    Stale {
        region: Rect,
        stale_regions: Vec<StaleRegion>,
    },

    /// Too much of the region is untrustworthy to describe rectangle by
    /// rectangle.
    #[error(transparent)]
    TooManyStaleRegions(#[from] TooManyStaleRegions),

    /// A region outside the framebuffer. Refused, never clamped, for the same
    /// reason `RefusalCode::OutOfBounds` refuses a click rather than clamping
    /// it: a clamped region is a picture of somewhere else.
    #[error("{region:?} is outside the {width}x{height} framebuffer: nothing was clamped, read the current geometry and ask again")]
    OutOfBounds {
        region: Rect,
        width: u16,
        height: u16,
    },

    /// The image could not be encoded.
    #[error(transparent)]
    Encode(#[from] EncodeFailed),

    /// A JPEG rectangle could not be decoded. Surfaced rather than logged,
    /// because the region it covered is now stale.
    #[error(transparent)]
    Decode(#[from] DecodeFailed),
}

impl PerceptionError {
    /// The identifier an agent matches on, in capitals, the way
    /// [`limb_core::observation::RefusalCode::as_str`] does.
    pub fn as_str(&self) -> &'static str {
        match self {
            PerceptionError::Budget(_) => "BUDGET_REFUSED",
            PerceptionError::Geometry(GeometryRejected::Stale { .. }) => "GEOMETRY_CHANGED",
            PerceptionError::Geometry(GeometryRejected::Unfenced { .. }) => "UNFENCED",
            PerceptionError::NoMirror => "NO_MIRROR",
            PerceptionError::Priming { .. } => "PRIMING",
            PerceptionError::Stale { .. } => "STALE_REGION",
            PerceptionError::TooManyStaleRegions(_) => "STALE_REGION",
            PerceptionError::OutOfBounds { .. } => "OUT_OF_BOUNDS",
            PerceptionError::Encode(_) => "ENCODE_FAILED",
            PerceptionError::Decode(_) => "DECODE_FAILED",
        }
    }

    /// Will asking again, unchanged, ever produce a different answer?
    ///
    /// A model that cannot tell a wait from a dead end will do one of the two
    /// forever. `Priming` resolves on its own once the server paints;
    /// `Stale` resolves only after the session renegotiates, which is the
    /// plane's job and not the agent's.
    pub fn is_transient(&self) -> bool {
        matches!(self, PerceptionError::Priming { .. })
    }
}

/// The untrustworthy part of a frame is too scattered to list.
///
/// The refusal is deliberate and it is the second half of `00 R6`'s choice:
/// refuse, or annotate. Collapsing the list into its bounding box would be the
/// union trap `00 R39b` rules out, and truncating it would return a frame
/// whose annotation says less than the truth, which is the silent staleness
/// this crate exists to prevent wearing a different hat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("this region is stale in more than {limit} separate places, so it is refused rather than annotated: renegotiate the session's encodings and refresh, or read a smaller region")]
pub struct TooManyStaleRegions {
    pub limit: usize,
}
