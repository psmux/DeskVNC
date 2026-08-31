//! What the pixel path can honestly say about the negotiated signals.
//!
//! `00 R34`, `00 R42` and `14 §2`. Every signal a limb can offer is capability
//! negotiated, so no consumer may assume presence and a signal the far side
//! did not offer is reported ABSENT rather than defaulted. The envelope is
//! [`limb_core::availability`] and this module defines no second one: it fills
//! in the entries the perception path is the authority on and leaves the rest
//! to the plane, which is the authority on the handshake.
//!
//! Two of those entries are worth reading closely, because both of them are
//! places where a guess would be easy and wrong.
//!
//! **`content_hint` is absent on this build and it is not going to resolve.**
//! `00 R39a` corrects `14 §2.3`, which originally claimed an agent gets
//! text-like against image-like classification per rectangle for free. It does
//! not. `RectPayload` (`crates/remote-core/src/events.rs:29`) has four
//! variants, and Tight palette, Tight RLE, Hextile, ZRLE and raw all decode to
//! `Rgba` and arrive indistinguishable from one another. So the free
//! classification is three way at best and `Rgba` covers most rectangles,
//! which is the case the hint was supposed to resolve. The encoding number
//! exists where the decision is made (`run_loop.rs:967`) and carrying it onto
//! `DecodedRect` is a phase 2 delta against three documents. Until then the
//! answer is `unknown` for every `Rgba` rect and the plane never guesses.
//!
//! **`copy_rect` is `unknown` until one arrives, and never `absent`.** The two
//! words are different claims (`availability.rs`): absent means we asked and
//! the far side does not do it, permanently, so stop reaching for it. `CopyRect`
//! is an encoder optimisation a server may simply not have used yet, so
//! calling it absent would be a permanent claim made from a temporary silence.

use crate::coverage::StaleReason;
use limb_core::availability::{SignalReport, SignalState, WindowStructureAbsent};
use remote_core::events::{DecodedRect, RectPayload};
use serde::Serialize;

/// `00 R39a`'s sentence, written once so every response says the same thing.
pub const CONTENT_HINT_REASON: &str = "the per rect encoding number does not reach the remote-core seam on this build, so Tight palette, Tight RLE, Hextile, ZRLE and raw all arrive as Rgba and are indistinguishable (00 R39a)";

/// What the payload variant says about a rectangle's content.
///
/// Three values and one of them is `Unknown`, which is most rectangles. That
/// is the honest shape of this signal today and `00 R39a` says so in terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentHint {
    /// The encoder judged the region photographic. A hint and never a
    /// contract: some servers use one encoding for everything.
    Photographic,
    /// The encoder judged the region moving. The mirror cannot composite it
    /// (`00 R6`).
    Moving,
    /// The server said the content at another place is now here, which is an
    /// exact delta rather than a classification (`14 §2.1`).
    Moved,
    /// Anything at all. **Most rectangles land here and this crate does not
    /// guess which.**
    Unknown,
}

impl ContentHint {
    pub fn of(payload: &RectPayload) -> Self {
        match payload {
            RectPayload::Jpeg(_) => ContentHint::Photographic,
            RectPayload::H264 { .. } => ContentHint::Moving,
            RectPayload::CopyRect { .. } => ContentHint::Moved,
            // Not "text-like". `00 R39a`.
            RectPayload::Rgba(_) => ContentHint::Unknown,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ContentHint::Photographic => "photographic",
            ContentHint::Moving => "moving",
            ContentHint::Moved => "moved",
            ContentHint::Unknown => "unknown",
        }
    }
}

/// The signals the pixel path is the authority on, from what it has actually
/// seen rather than from what the handshake advertised.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PerceptionSignals {
    copy_rects: u64,
    h264_rects: u64,
}

impl PerceptionSignals {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count what arrived. Cheap enough to call on every update.
    pub fn observe(&mut self, rects: &[DecodedRect]) {
        for r in rects {
            match r.payload {
                RectPayload::CopyRect { .. } => self.copy_rects += 1,
                RectPayload::H264 { .. } => self.h264_rects += 1,
                _ => {}
            }
        }
    }

    pub fn copy_rects(&self) -> u64 {
        self.copy_rects
    }

    /// How many H.264 rectangles have reached the mirror.
    ///
    /// Any number above zero means `00 R6`'s negotiation did not happen or did
    /// not take, and the mirror has poisoned regions to prove it. It belongs
    /// in `session.stats` beside the mirror's byte size (`03 §9 A6`), because
    /// it is the number that explains a stale frame after the fact.
    pub fn h264_rects(&self) -> u64 {
        self.h264_rects
    }

    /// `14 §2.1`. Live once one has arrived, unknown until then, never absent.
    pub fn copy_rect(&self) -> SignalState {
        if self.copy_rects > 0 {
            SignalState::Live
        } else {
            SignalState::unknown(
                "no CopyRect rectangle has arrived yet; it is an encoder choice this server may still make",
            )
        }
    }

    /// `00 R39a`. Absent, on this build, for every session.
    pub fn content_hint(&self) -> SignalState {
        SignalState::absent(CONTENT_HINT_REASON)
    }

    /// `00 R42` (WA-4). Structurally absent and there is no value of the type
    /// that says otherwise.
    pub fn window_structure(&self) -> WindowStructureAbsent {
        WindowStructureAbsent
    }

    /// Write the two entries this crate owns into the plane's report.
    ///
    /// The plane owns the other nine, because they are answers about the
    /// handshake and this crate never sees one.
    pub fn fill(&self, report: &mut SignalReport) {
        report.copy_rect = self.copy_rect();
        report.content_hint = self.content_hint();
        report.window_structure = self.window_structure();
    }
}

/// The staleness a payload variant causes, or `None` when the mirror can
/// composite it.
///
/// The one place the mapping from "what arrived" to "what the mirror can
/// vouch for" is written, so a new `RectPayload` variant is a compile error
/// here rather than a silently mirrored one.
pub fn stale_reason_for(payload: &RectPayload) -> Option<StaleReason> {
    match payload {
        RectPayload::Rgba(_) | RectPayload::Jpeg(_) | RectPayload::CopyRect { .. } => None,
        RectPayload::H264 { .. } => Some(StaleReason::H264),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rgba_rect_is_unknown_and_the_crate_does_not_guess() {
        let hint = ContentHint::of(&RectPayload::Rgba(vec![0; 16]));
        assert_eq!(hint, ContentHint::Unknown);
    }

    #[test]
    fn copy_rect_starts_unknown_rather_than_absent() {
        let signals = PerceptionSignals::new();
        assert!(matches!(signals.copy_rect(), SignalState::Unknown { .. }));
    }
}
