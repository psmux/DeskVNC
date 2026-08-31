//! # agent-perception
//!
//! What an agent is allowed to see: a server side framebuffer mirror, damage
//! tracking, and the crop, downscale and encode path that turns pixels into an
//! observation (PRDAgentPlug/03).
//!
//! ## The problem this crate exists for
//!
//! **The running application does not keep a server side framebuffer.** The
//! run loop reads one FramebufferUpdate to completion, emits the decoded rects
//! in a single coalesced event, and drops them; the only complete picture of
//! any session lives in a WebGL texture inside a webview process, readable only
//! by JavaScript in that webview handing bytes back over `capture_thumbnail`
//! (`03 §1`). That design is right, and it is why a 4K session does not push
//! 33 MB per frame across IPC. It also means a session with no window showing
//! it has no picture anywhere, a session in a background tab has a stale one
//! because a hidden webview's `requestAnimationFrame` is throttled, and the
//! first thing an agent asks for is the one thing the architecture has nowhere
//! to get.
//!
//! So this crate is the second consumer of the same `SessionEvent` stream, and
//! `00 R22` puts it in the plane rather than behind the webview bridge: in
//! tabbed mode every session shares one bridge and it is not a fair queue, so
//! eight limbs' frames through it is a starvation bug with our name on it.
//!
//! ## Module map
//!
//! | Module        | Responsibility                                             |
//! |---------------|------------------------------------------------------------|
//! | [`budget`]    | What a mirror may cost, and the refusal (`00 R5`)          |
//! | [`coverage`]  | Which pixels are real, and the H.264 poison (`00 R6`)      |
//! | [`mirror`]    | The framebuffer copy and its lifecycle                     |
//! | [`damage`]    | Per reader change deltas, as a rect LIST (`00 R39b`)       |
//! | [`ladder`]    | The five rungs and the self describing response (`03 §4`)  |
//! | [`encode`]    | Downscale, PNG and JPEG, sized for a model (`03 §5`)       |
//! | [`transform`] | The inverse coordinate transform (`00 R43`)                |
//! | [`signals`]   | Availability, and the content hint we do not have          |
//! | [`error`]     | Every refusal, as a type an agent can match on             |
//!
//! Every public item is re-exported at the crate root, matching `remote-core`
//! and `limb-core`, whose call sites are flat for the same reason.
//!
//! ## The four rules a reader should know before changing anything here
//!
//! **A mirror never lies about coverage** (`00 R6`, `03 §3.5`).
//! `Framebuffer::apply`'s H.264 arm is a documented no-op and H.264 is
//! advertised by default to every server except Apple Screen Sharing, so a
//! naive mirror holds stale pixels in exactly the region that is moving, with
//! no error anywhere. Every rect that cannot be composited poisons its region
//! and every read of a poisoned region refuses or is annotated.
//! [`mirror_safety`] is the predicate that keeps it from happening at all.
//!
//! **A mirror refuses rather than degrades** (`00 R5`). Over the pixel budget
//! it is a typed error naming the budget, never a smaller image than the
//! caller asked for. The reason is the reason `capture_thumbnail` validates
//! its body: a perception layer that quietly gives you something other than
//! what you asked for produces agents that click in the wrong place and nobody
//! can reproduce it.
//!
//! **Perception uses the rect list, never the union** (`00 R39b`).
//! `Rect::union` is a bounding box, so two changes in opposite corners union
//! to the whole screen and an agent would re-read a 4K frame to find two moved
//! pixels.
//!
//! **A coordinate carries a half source pixel bias** (`00 R43`). The inverse
//! transform is `fb_x = rx + floor((mx + 0.5) / s)` and it is
//! [`ImageSpace::to_framebuffer`], with tests, rather than a comment.
//!
//! ## What this crate deliberately does not do
//!
//! It starts no clock, spawns no task, opens no socket and holds no global.
//! Every decision is a pure function of what it was handed, including the
//! time, which is why an idle timeout is testable without a runtime. That is
//! the discipline `limb-core` and `agent-lease` already follow.
//!
//! It reads no text out of pixels. `03 §6.5` rules OCR out of version 1, and
//! the reason is not that OCR is bad: where a machine is reachable over both
//! SSH and a desktop protocol, an agent should read through the terminal and
//! act through the desktop (`00 R9`). A terminal's bytes are already text,
//! with no recognition step and no ambiguity between `l` and `1` in a path.
//!
//! It infers no widget tree. `00 R36` rules that an inferred tree is always
//! labelled inferred, and `00 R42` rules the five fabricated window fields out
//! of the observation object entirely; [`limb_core::availability::WindowStructureAbsent`]
//! carries that negative and this crate never contradicts it.

// Nothing here touches a raw pointer and nothing here ever will, but every
// crate in this workspace that could carries the attribute and the consistency
// is worth more than the exception.
#![forbid(unsafe_code)]

pub mod budget;
pub mod coverage;
pub mod damage;
pub mod encode;
pub mod error;
pub mod ladder;
pub mod mirror;
pub mod signals;
pub mod transform;

pub use budget::{
    mirror_bytes, mirror_pixels, BudgetRefused, MirrorBudget, BYTES_PER_PIXEL,
    DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_MAX_MIRROR_PIXELS, DEFAULT_MAX_TOTAL_BYTES,
};
pub use coverage::{
    Coverage, FrameCoverage, RegionState, StaleReason, StaleRegion, MAX_STALE_REGIONS, TILE,
};
pub use damage::{
    plan_change_crop, ChangePlan, DamageDelta, DamageLog, DegradeReason, ReaderId,
    DEFAULT_CAPACITY, DEFAULT_CROP_COVERAGE_LIMIT, DEFAULT_MARGIN,
};
pub use encode::{
    crop_rgba, decode_jpeg_to_rgba, downscale_to_long_edge, encode_rgba, DecodeFailed,
    EncodeFailed, EncodeOptions, EncodedImage, ImageFormat, DEFAULT_JPEG_QUALITY,
    DEFAULT_LONG_EDGE, HIGH_RES_LONG_EDGE,
};
pub use error::{PerceptionError, TooManyStaleRegions};
pub use ladder::{
    FrameObservation, Read, ReadKind, ReadRequest, Rung, ScreenFacts, ScreenList, Space,
    StalePolicy,
};
pub use mirror::{mirror_safety, Mirror, MirrorSafety, MirrorSlot};
pub use signals::{stale_reason_for, ContentHint, PerceptionSignals, CONTENT_HINT_REASON};
pub use transform::{ImageSpace, OutOfImage, OutsideRegion};
