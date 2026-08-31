//! The observation path, and the ONE place `agent-perception` is named.
//!
//! Everything this crate knows about pixels goes through [`FrameSource`]. That
//! is deliberate and it is the only module boundary in the crate that exists
//! for a scheduling reason as well as a design one: `agent-perception` is
//! being written in parallel with this crate, and a dependency spread across
//! eight files is a dependency that cannot be adapted in one commit when its
//! API settles.
//!
//! ## The capability gate
//!
//! `00 R5` splits perception in two and the split is not a convenience.
//!
//! * A FRAME needs [`Capability::Capture`], which is `07 §3.4`'s
//!   `perceive.frame` under `02 §5`'s name (`00 R20` settles that `02 §5` is
//!   canonical and that `07`'s placeholders map one for one and need a rename
//!   only). A frame is content: whatever is on somebody's screen, leaving the
//!   process.
//! * DAMAGE needs only [`Capability::View`], which is `perceive.damage`, and
//!   it is a genuinely weaker thing to hold. Damage rectangles leak geometry
//!   and timing and no content at all: an agent watching them learns that
//!   something in the lower right is repainting at 1 Hz and learns nothing
//!   about what it says.
//!
//! **`perceive.damage` does not imply `perceive.frame`.** That is `00 R5` in
//! terms, and it is the same deny by default rule as everywhere else: no
//! hierarchy, no wildcard, no inheritance.
//!
//! ## What is not here
//!
//! No mirror. `00 R5` allocates one on first frame request, frees it after an
//! idle timeout with no reads, and refuses above a configurable pixel budget
//! rather than downscaling silently, and `00 R22` puts it in the plane rather
//! than in the webview because in tabbed mode all sessions share one bridge
//! and it is not a fair queue. That machinery is `agent-perception`'s, and
//! this file is the seam it arrives through.
//!
//! No `Rect::union`. `00 R39b` rules that every perception and fusion consumer
//! operates on the RECTS LIST and never on the damage union, because
//! `Rect::union` (`crates/remote-core/src/geometry.rs:31`) is a bounding box
//! and two changes in opposite corners union to the whole screen. Sizing a
//! read from the union would re-read a whole 4K frame to find two moved
//! pixels.
//!
//! That rule is a property of the PORT and not of the call sites, which is why
//! [`Crop`] exists and why [`FrameSource`] has [`FrameSource::changed`] beside
//! [`FrameSource::frame`]. A port that accepts one `Option<Rect>` leaves a
//! caller holding a rect list exactly one move, which is to union it, and then
//! the ruling depends on nobody making the obvious mistake. The list travels
//! instead, and the layer that owns the pixels chooses the crop, because
//! choosing needs the framebuffer, the margin and the coverage, and nothing
//! above that layer has any of the three.

use crate::error::Refusal;
use crate::grant::Grant;
use limb_core::capability::{Capability, CapabilitySet};
use limb_core::fence::GeometryGeneration;
use limb_core::identity::LimbId;
use limb_core::intent::{CaptureForm, IntentKind, ReadForm};
use limb_core::observation::{Observation, RefusalCode, Timestamp, Untrusted};
use limb_core::Rect;
use std::sync::{Arc, Mutex};

/// What the plane needs from a mirror, and nothing else.
///
/// Named as a port rather than as `agent_perception`'s own type on purpose.
/// Two reasons and both survive the crate landing.
///
/// The scheduling one: this crate is built against a crate being written
/// beside it, so the coupling is one impl in one file rather than a type
/// spread through the dispatcher.
///
/// The design one, which is the one that lasts: a limb with no framebuffer has
/// no mirror at all, and a trait with an `Option` in front of it says that in
/// the type system. A terminal limb answers a read from its own grid and never
/// touches this.
pub trait FrameSource: Send + Sync {
    /// The pixels of a region, encoded, at the generation they were read at.
    ///
    /// `region` of `None` means the whole framebuffer. `03 §5.2` argues for
    /// regions rather than full frames on cost grounds, and `00 R43` (WA-11)
    /// argues for them on CORRECTNESS grounds, which is the stronger case:
    /// never send an image the provider will resize, because then the scale
    /// factor is one we did not choose and cannot invert.
    ///
    /// # Errors
    ///
    /// [`PerceptionUnavailable`], which the caller turns into a refusal with
    /// the sentence in it. A mirror above the pixel budget refuses rather than
    /// downscaling silently (`00 R5`).
    /// `at` is unix milliseconds, supplied by the plane. Nothing below this
    /// line reads a clock, which is the discipline `limb-core`, `agent-lease`
    /// and `agent-perception` all follow for the same reason: an idle timeout
    /// is testable without a runtime.
    fn frame(
        &self,
        region: Option<Rect>,
        scale: Option<f32>,
        at: Timestamp,
    ) -> Result<Frame, PerceptionUnavailable>;

    /// The pixels of a crop chosen from a damage LIST, at the generation the
    /// list was observed at.
    ///
    /// `00 R39b`, and it is a second method rather than an argument on
    /// [`FrameSource::frame`] because that one takes an `Option<Rect>` and a
    /// rectangle is exactly the thing rung 4 must not be given. A caller
    /// holding a rect list and a port that accepts one rectangle has only one
    /// move, which is to union the list, and `Rect::union`
    /// (`crates/remote-core/src/geometry.rs:31`) is a bounding box: two
    /// changes in opposite corners union to the whole screen, so a capture in
    /// the `damage-crop` form re-reads an entire 4K desktop to find two moved
    /// pixels, which is the exact opposite of what that form is for.
    ///
    /// The whole [`Damage`] travels and not just its rectangles, because the
    /// generation on it is what makes the crop meaningful: a crop computed
    /// from changes observed at generation 7 and read at generation 8 is a
    /// picture of the wrong screen, and an implementation that can fence
    /// should fence on it (`00 R10`).
    ///
    /// # Errors
    ///
    /// [`PerceptionUnavailable`], as [`FrameSource::frame`], plus the stale
    /// generation for an implementation that fences.
    fn changed(
        &self,
        damage: &Damage,
        scale: Option<f32>,
        at: Timestamp,
    ) -> Result<Frame, PerceptionUnavailable> {
        // The default keeps every source honest without making every source
        // implement rung 4: choose the crop from the list here, then ask for
        // it as an ordinary region. A source that has a real rung 4, as
        // `MirrorSource` does, overrides this and gets the margin, the
        // coverage check and the remaining count with it.
        self.frame(crop_of_changes(&damage.rects), scale, at)
    }

    /// The damage rectangles since the last call, and the two numbers that
    /// make them readable.
    ///
    /// `None` when nothing has arrived. A caller must not read that as "the
    /// screen is still": a server whose damage tracking cannot be trusted
    /// sends nothing either, which is why `ClientCommand::SetAlwaysRefresh`
    /// exists (`crates/remote-core/src/commands.rs:36`).
    fn damage(&self) -> Option<Damage>;
}

/// How much of a crop is allowed to be pixels nobody asked for.
///
/// Four. The crop is admitted while its area stays within this multiple of the
/// area the changes actually touch, so absorbing a neighbour is cheap and
/// absorbing the opposite corner is not.
const CROP_WASTE_LIMIT: usize = 4;

/// Choose ONE rectangle to read, from a list and never from its union.
///
/// The rule is `agent_perception::plan_change_crop`'s, cut down to what this
/// layer can know: seed with the LARGEST changed rectangle, then absorb the
/// others in size order for as long as the result stays inside
/// [`CROP_WASTE_LIMIT`]. Two small changes in opposite corners therefore
/// produce a crop around one of them, never a full screen read.
///
/// It is deliberately NOT a copy of that function. This one has no
/// framebuffer, so it cannot take a fraction of the screen the way the real
/// planner does, and it has nowhere to report the changes it left behind,
/// because [`Frame`] carries no remaining count. Both of those are why a
/// source with a real rung 4 overrides [`FrameSource::changed`] instead of
/// leaning on this.
///
/// `None`, meaning the whole framebuffer, only when the list is empty or every
/// rectangle in it is degenerate. That is the one case where there is nothing
/// to crop around.
pub fn crop_of_changes(rects: &[Rect]) -> Option<Rect> {
    let mut live: Vec<Rect> = rects.iter().copied().filter(|r| !r.is_empty()).collect();
    if live.is_empty() {
        return None;
    }
    live.sort_by_key(|r| std::cmp::Reverse(r.area()));
    let touched: usize = live.iter().map(Rect::area).sum();
    let limit = touched.max(live[0].area()).saturating_mul(CROP_WASTE_LIMIT);
    let mut crop = live[0];
    for r in &live[1..] {
        let grown = crop.union(r);
        if grown.area() <= limit {
            crop = grown;
        }
    }
    Some(crop)
}

/// Which pixels a read is asking for.
///
/// It exists so that `00 R39b`'s rule survives the trip from the dispatcher to
/// the mirror. A read expressed as `Option<Rect>` has already lost the
/// difference between "this rectangle" and "whatever the changes were",
/// because the only way to turn a list into a rectangle is to union it, and
/// the union is the trap. So the choice travels as a choice and the list
/// travels with it.
#[derive(Debug, Clone, PartialEq)]
pub enum Crop {
    /// The whole framebuffer.
    Whole,
    /// One rectangle the caller named, at native resolution.
    Region(Rect),
    /// Whatever changed, as the LIST and the generation it was observed at.
    /// The crop is chosen from it by whoever has the pixels, which is the only
    /// layer that knows the framebuffer, the margin and the coverage.
    Changes(Damage),
}

/// A read that named a rectangle, or none, is the same read it always was.
///
/// Here so that a call site holding an `Option<Rect>` keeps working unchanged
/// and only the damage crop path has to say anything new.
impl From<Option<Rect>> for Crop {
    fn from(region: Option<Rect>) -> Crop {
        match region {
            Some(rect) => Crop::Region(rect),
            None => Crop::Whole,
        }
    }
}

/// Encoded pixels, with the generation they were read at.
#[derive(Debug, Clone)]
pub struct Frame {
    pub bytes: bytes::Bytes,
    /// The rectangle these pixels actually cover, which is not always the one
    /// that was asked for: a mirror that could not composite the whole region
    /// says so here rather than returning a smaller image that looks whole.
    pub covers: Rect,
    /// The geometry generation the pixels were read at.
    ///
    /// It travels with the payload because a payload outlives the geometry it
    /// was read against: a screenshot read at generation 7 and acted on at
    /// generation 8 is a misclick, and the only place that can be noticed is
    /// where the two numbers sit side by side.
    pub generation: GeometryGeneration,
    /// False when the mirror could only composite part of the region.
    pub complete: bool,
}

/// What changed, as a list and never as a union (`00 R39b`).
#[derive(Debug, Clone, PartialEq)]
pub struct Damage {
    /// The rectangles themselves, in arrival order.
    pub rects: Vec<Rect>,
    /// The bounding box, carried beside the list rather than instead of it.
    /// A handful of scattered rects can span the desktop, so `coverage` and
    /// the rect count are what make the box readable.
    pub bounds: Rect,
    pub coverage: f32,
    pub generation: GeometryGeneration,
}

/// A perception could not be produced, with the sentence saying why.
///
/// Refusing rather than degrading is `00 R5`, and `00 R6` is the sharper case:
/// `Framebuffer::apply`'s H.264 arm is a documented no-op
/// (`crates/vnc-core/src/pixel/framebuffer.rs:90`), so a naive mirror holds
/// stale pixels in exactly the region that is moving, with no error anywhere.
/// An agent looking at that sees a video player that never started. That is
/// worse than having no screenshot at all, because there is no signal to act
/// on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PerceptionUnavailable(pub String);

/// The observation half of one limb.
///
/// Holds the mirror if there is one, applies the capability gate, and returns
/// `limb-core` observations. A limb with no framebuffer holds `None` and
/// answers reads from its own grid, which is the shape `PerceptionSet` already
/// describes: a set rather than an enum, because an Android device over ADB
/// genuinely offers both a character stream and a bitmap (`02 §8.4`).
pub struct Observatory {
    limb: LimbId,
    frames: Option<Arc<dyn FrameSource>>,
}

impl Observatory {
    /// An observatory with no mirror. Every pixel read is refused with a
    /// sentence naming the limb.
    pub fn blind(limb: LimbId) -> Observatory {
        Observatory { limb, frames: None }
    }

    /// An observatory over a mirror.
    pub fn with_frames(limb: LimbId, frames: Arc<dyn FrameSource>) -> Observatory {
        Observatory {
            limb,
            frames: Some(frames),
        }
    }

    /// Is there a mirror behind this limb?
    pub fn has_frames(&self) -> bool {
        self.frames.is_some()
    }

    /// The damage since the last call, with no gate.
    ///
    /// Ungated because every caller of this is already inside a check: a wait
    /// costs `view` through [`limb_core::capability::capabilities_for`] and a
    /// damage crop costs `capture` through [`Observatory::observe_frame`]. A
    /// second gate here would be a second place the rule is written, and two
    /// places is how the two drift.
    pub fn damage_now(&self) -> Option<Damage> {
        self.frames.as_ref().and_then(|source| source.damage())
    }

    /// What this intent costs on the perception path.
    ///
    /// Two capabilities where a naive design has one, and the split is
    /// [`Capability::Capture`] for content against [`Capability::View`] for
    /// geometry and timing. Nothing here consults
    /// [`limb_core::capability::capabilities_for`] a second time: that
    /// function owns the intent to capability table and this method owns only
    /// the frame against damage distinction that `00 R5` adds on top of it.
    pub const fn perception_cost(form: PerceptionForm) -> Capability {
        match form {
            PerceptionForm::Frame => Capability::Capture,
            PerceptionForm::Damage => Capability::View,
        }
    }

    /// The damage rectangles, gated on the weaker capability.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] when the grant does not carry [`Capability::View`], or
    /// when nothing has arrived yet.
    pub fn observe_damage(&self, grant: &Grant) -> Result<Observation, Refusal> {
        self.gate(grant, PerceptionForm::Damage)?;
        let Some(source) = &self.frames else {
            return Err(Refusal::limb(
                RefusalCode::NotSupported,
                format!(
                    "{} produces no framebuffer, so it has no damage to report; read its grid instead",
                    self.limb
                ),
            ));
        };
        let Some(damage) = source.damage() else {
            return Err(Refusal::limb(
                RefusalCode::NotReady,
                "no damage has arrived on this limb yet, and an absence of damage is not evidence the screen is still: a server whose damage tracking cannot be trusted sends nothing either",
            ));
        };
        Ok(Observation::Damage {
            rect: damage.bounds,
            rects: damage.rects.len() as u32,
            coverage: damage.coverage,
            at: limb_core::observation::Timestamp(0),
        })
    }

    /// The pixels, gated on the stronger capability.
    ///
    /// `crop` is [`Crop`], and an `Option<Rect>` converts into one, so a caller
    /// that names a rectangle writes what it always wrote. The damage crop is
    /// the case that needs the richer type: it carries the rect LIST down to
    /// the layer that owns the pixels, rather than unioning it into a bounding
    /// box on the way (`00 R39b`).
    ///
    /// # Errors
    ///
    /// A [`Refusal`] when the grant does not carry [`Capability::Capture`],
    /// when the limb has no mirror, or when the mirror refused.
    pub fn observe_frame(
        &self,
        grant: &Grant,
        intent: limb_core::intent::IntentId,
        crop: impl Into<Crop>,
        scale: Option<f32>,
        at: Timestamp,
    ) -> Result<Observation, Refusal> {
        self.gate(grant, PerceptionForm::Frame)?;
        let Some(source) = &self.frames else {
            return Err(Refusal::limb(
                RefusalCode::NotSupported,
                format!(
                    "{} has no framebuffer mirror attached, so there are no pixels to read",
                    self.limb
                ),
            ));
        };
        let frame = match crop.into() {
            Crop::Whole => source.frame(None, scale, at),
            Crop::Region(rect) => source.frame(Some(rect), scale, at),
            // The list, and never `damage.bounds`. This is the whole of
            // `00 R39b` at the one call site where it can be got wrong.
            Crop::Changes(damage) => source.changed(&damage, scale, at),
        }
        .map_err(|e| Refusal::limb(RefusalCode::NotSupported, e.0))?;
        // Wrapped, because everything a remote screen says is data and never
        // instruction (`AGENT_BRIEF` D6). The generation travels inside the
        // wrapper rather than beside it for the reason `Untrusted::new`
        // documents: a payload outlives the geometry it was read against.
        Ok(Observation::Read {
            id: intent,
            payload: Untrusted::new(self.limb.clone(), frame.generation, frame.bytes),
        })
    }

    fn gate(&self, grant: &Grant, form: PerceptionForm) -> Result<(), Refusal> {
        let needed = Observatory::perception_cost(form);
        if grant.allows_all(CapabilitySet::of(&[needed])) {
            return Ok(());
        }
        Err(Refusal::limb(
            RefusalCode::MissingCapability,
            format!(
                "reading {} on {} needs {}, which this grant does not carry; {} does not imply {}, because damage rectangles leak geometry and timing and a frame leaks whatever is on somebody's screen",
                form.as_str(),
                self.limb,
                needed,
                Capability::View,
                Capability::Capture,
            ),
        ))
    }
}

/// Which half of the perception split a read is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerceptionForm {
    /// Pixels. `07 §3.4`'s `perceive.frame`, which `02 §5` spells `capture`.
    Frame,
    /// Rectangles and cadence. `perceive.damage`, which `02 §5` spells `view`.
    Damage,
}

impl PerceptionForm {
    /// Which half of the split an intent asks for.
    ///
    /// `read_screen` is the parameter dependent one and it is `PARAM_RULES[0]`
    /// in `limb-core`: the same intent costs `view` or `view` plus `capture`
    /// depending on an argument.
    pub const fn of(kind: &IntentKind) -> Option<PerceptionForm> {
        match kind {
            IntentKind::Capture { .. } => Some(PerceptionForm::Frame),
            IntentKind::ReadScreen { form, .. } => match form {
                ReadForm::Pixels => Some(PerceptionForm::Frame),
                ReadForm::Text | ReadForm::Cells => Some(PerceptionForm::Damage),
            },
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            PerceptionForm::Frame => "pixels",
            PerceptionForm::Damage => "damage",
        }
    }
}

/// Which pixels a capture asks for, resolved against what the intent said.
///
/// `CaptureForm::DamageCrop` is the cheapest useful answer and the one to use
/// after an action (`03 §4.5`), and it is where `00 R39b` bites. This function
/// returns a [`Crop`] and NOT a rectangle, and that is the whole fix: it used
/// to answer `damage.bounds`, which is `Rect::union`, which is a bounding box,
/// so two changes in opposite corners came back as the whole screen and the
/// cheapest rung on the ladder read an entire 4K desktop to find two moved
/// pixels. Nothing here chooses a rectangle any more. The list goes down to
/// the layer that owns the pixels and that layer chooses, because choosing
/// needs the framebuffer, the margin and the coverage, and this function has
/// none of the three.
///
/// A damage crop with no damage is [`Crop::Whole`]. There is nothing to crop
/// around, and answering with an empty rectangle would be a read of nothing
/// dressed up as a read of the screen.
pub fn capture_region(form: CaptureForm, asked: Option<Rect>, damage: Option<&Damage>) -> Crop {
    match form {
        CaptureForm::Full => Crop::Whole,
        CaptureForm::Region => Crop::from(asked),
        CaptureForm::DamageCrop => match damage {
            Some(damage) => Crop::Changes(damage.clone()),
            None => Crop::Whole,
        },
    }
}

/// The adapter, and the only place in this crate that names
/// `agent_perception`.
///
/// Everything above this line is the plane's own vocabulary. Everything below
/// is `agent-perception`'s. If that crate's API moves, exactly this much
/// changes.
///
/// The two locks are here because `agent-perception` is deliberately inert:
/// `MirrorSlot::read` and `DamageLog::take` both take `&mut self`, since a
/// read advances a per reader cursor and a mirror's idle clock, and the crate
/// holds no lock of its own so that its rules stay pure functions of what they
/// were handed. Owning the locks is the runtime's job, which is what this
/// crate is for.
pub struct MirrorSource {
    slot: Mutex<agent_perception::MirrorSlot>,
    damage: Mutex<agent_perception::DamageLog>,
    /// Rung 4 is per reader by construction: a defaulted reader id would let
    /// two agents consume each other's changes, which is why
    /// `agent_perception::ReadRequest::change` takes one rather than
    /// defaulting it.
    reader: agent_perception::ReaderId,
}

impl MirrorSource {
    /// Wrap a mirror and a damage log for one limb.
    ///
    /// The reader is subscribed here rather than at the first read, because a
    /// reader that subscribes late is told nothing was dropped when in fact
    /// everything before it was.
    pub fn new(
        slot: agent_perception::MirrorSlot,
        mut damage: agent_perception::DamageLog,
        reader: agent_perception::ReaderId,
    ) -> MirrorSource {
        damage.subscribe(reader);
        MirrorSource {
            slot: Mutex::new(slot),
            damage: Mutex::new(damage),
            reader,
        }
    }

    /// Feed decoded rectangles in, from the caller's `SessionEvent` pump.
    ///
    /// The plane is the SECOND consumer of that stream and the webview is the
    /// first (`00 R22`). It is a plumbing change in the shell and it must not
    /// be visible from inside `vnc-core` or `rdp-core` (`00 R5`).
    /// Returns the `Observation::Damage` the caller owes any grant holding the
    /// weaker capability. It is unsolicited and carries no intent id: an agent
    /// subscribes to it rather than asking for it.
    pub fn apply(
        &self,
        rects: &[remote_core::events::DecodedRect],
        framebuffer: Rect,
        at: Timestamp,
    ) -> Observation {
        crate::registry::lock(&self.slot).apply(rects);
        crate::registry::lock(&self.damage).record(rects, framebuffer, at)
    }
}

impl FrameSource for MirrorSource {
    fn frame(
        &self,
        region: Option<Rect>,
        scale: Option<f32>,
        at: Timestamp,
    ) -> Result<Frame, PerceptionUnavailable> {
        let mut slot = crate::registry::lock(&self.slot);
        let mut damage = crate::registry::lock(&self.damage);

        let request = match (region, scale) {
            // Rung 3 is a rectangle at native resolution, scale 1.0, with no
            // rounding to argue about. A caller asking for a scaled region is
            // refused rather than served one: `00 R43` (WA-11) says never send
            // an image the provider will resize, and a region we scaled
            // ourselves and a region a provider scaled are indistinguishable
            // once the factor is lost.
            (Some(_), Some(s)) if (s - 1.0).abs() > f32::EPSILON => {
                return Err(PerceptionUnavailable(format!(
                    "a region read is native resolution and this one asked for scale {s}; ask for the region at 1.0 and downscale nothing, or ask for the whole frame at a long edge"
                )))
            }
            (Some(rect), _) => agent_perception::ReadRequest::region(rect),
            (None, None) => agent_perception::ReadRequest::frame(),
            (None, Some(s)) => {
                let long_edge = match slot.get() {
                    Some(mirror) => {
                        let edge = mirror.width().max(mirror.height());
                        (f32::from(edge) * s).round().max(1.0) as u32
                    }
                    None => return Err(PerceptionUnavailable(
                        "no mirror is attached to this limb, so there is no size for a scale to be relative to".to_string(),
                    )),
                };
                agent_perception::ReadRequest {
                    kind: agent_perception::ReadKind::Frame { long_edge },
                    ..agent_perception::ReadRequest::frame()
                }
            }
        };

        let read = slot
            .read(&request, &mut damage, at)
            .map_err(|e| PerceptionUnavailable(e.to_string()))?;
        frame_of(read)
    }

    fn changed(
        &self,
        damage: &Damage,
        scale: Option<f32>,
        at: Timestamp,
    ) -> Result<Frame, PerceptionUnavailable> {
        // A damage crop is a region read, and a region read is native
        // resolution with no rounding to argue about. `00 R43` (WA-11) says
        // never send an image the provider will resize, and a crop we scaled
        // ourselves is indistinguishable from one a provider scaled once the
        // factor is lost. Refused with the same sentence
        // [`FrameSource::frame`] gives for the same mistake.
        if let Some(s) = scale.filter(|s| (s - 1.0).abs() > f32::EPSILON) {
            return Err(PerceptionUnavailable(format!(
                "a damage crop is native resolution and this one asked for scale {s}; ask for the crop at 1.0 and downscale nothing, or ask for the whole frame at a long edge"
            )));
        }
        let mut slot = crate::registry::lock(&self.slot);
        let mut log = crate::registry::lock(&self.damage);
        let Some(bounds) = slot.get().map(agent_perception::Mirror::bounds) else {
            return Err(PerceptionUnavailable(
                "no mirror is attached to this limb, so there is nothing for a damage crop to be a crop of".to_string(),
            ));
        };

        // The rectangles come in rather than being taken from the log again.
        // They have already been consumed: `Observatory::damage_now` runs
        // before this and `DamageLog::take` advances the reader's cursor, so a
        // second read here would find nothing and answer "unchanged" for a
        // screen that had just changed. The planner is the same one rung 4
        // uses, given the same margin and the same coverage limit, so a crop
        // chosen here and a crop chosen inside the mirror are the same crop.
        let plan = agent_perception::plan_change_crop(
            &damage.rects,
            bounds,
            agent_perception::DEFAULT_MARGIN,
            agent_perception::DEFAULT_CROP_COVERAGE_LIMIT,
        );
        let request = match plan {
            // Not an error. "Nothing changed" is the answer to "show me what
            // changed", and an agent that receives an error for it will retry
            // immediately rather than wait, which turns the cheapest rung into
            // a spin loop.
            agent_perception::ChangePlan::Nothing => {
                return Ok(Frame {
                    bytes: bytes::Bytes::new(),
                    covers: Rect::new(0, 0, 0, 0),
                    generation: damage.generation,
                    complete: true,
                })
            }
            agent_perception::ChangePlan::Crop { rect, .. } => {
                agent_perception::ReadRequest::region(rect)
            }
            // `03 §9 A10`. One crop cannot answer this cheaply, which is what
            // a full screen repaint, a video or a scrolling terminal looks
            // like, so it says so by falling back to the downscaled whole
            // frame rather than quietly returning a full resolution crop of
            // the whole desktop.
            agent_perception::ChangePlan::Degraded { .. } => agent_perception::ReadRequest::frame(),
        }
        // `00 R10`. The crop was computed from changes observed at this
        // generation, so the read is fenced on it: if the desktop resized in
        // between, the rectangle refers to a screen that no longer exists and
        // the honest answer is a refusal, not a picture of somewhere else.
        // The fence is only worth anything because `damage` below now reports
        // the mirror's real generation: a constant cannot disagree with
        // anything, so fencing on one would have admitted every read.
        .fenced_at(damage.generation);

        let read = slot
            .read(&request, &mut log, at)
            .map_err(|e| PerceptionUnavailable(e.to_string()))?;
        frame_of(read)
    }

    fn damage(&self) -> Option<Damage> {
        // The mirror is consulted, and it is the only thing here that knows.
        // `00 R10` says the generation rides every perception response, and a
        // constant is not a generation: a caller cannot detect a stale read
        // against a number that never moves, and the shell's own
        // `screen.damage` has always returned the mirror's real one, so the
        // two sources of the same fact disagreed.
        let generation = crate::registry::lock(&self.slot)
            .get()
            .map(agent_perception::Mirror::generation)?;
        let mut log = crate::registry::lock(&self.damage);
        let delta = log.take(self.reader);
        if delta.is_empty() {
            return None;
        }
        Some(Damage {
            bounds: delta.bounding_box(),
            // `00 R39b`. THE list, in the order the server sent them. The
            // bounding box above it is carried for the `Observation::Damage`
            // that `limb-core` already defines as a union, and for nothing
            // else: sizing a read from it would re-read a whole 4K frame to
            // find two moved pixels.
            coverage: coverage_of(&delta.rects),
            rects: delta.rects,
            generation,
        })
    }
}

/// One `agent_perception::Read` as this crate's [`Frame`].
///
/// Written once because two call sites produce one, and a second copy of this
/// match is a second place the "unchanged" case can be turned into an error by
/// somebody who did not read the comment on it.
fn frame_of(read: agent_perception::Read) -> Result<Frame, PerceptionUnavailable> {
    match read {
        agent_perception::Read::Frame(observation) => {
            // The whole observation travels, not just the pixels. `03 §9 A8`
            // requires `space`, `scale`, `screens`, `primary_known`, the
            // geometry generation and `coverage` on every response at every
            // rung, and a response missing one is a bug rather than a compact
            // form. The encoded image is `#[serde(skip)]` on the far side
            // because framing it is the attachment surface's job, so it rides
            // beside the description here.
            let described = serde_json::to_vec(&observation).map_err(|e| {
                PerceptionUnavailable(format!("the frame could not be described: {e}"))
            })?;
            let complete = observation.coverage.is_complete();
            Ok(Frame {
                bytes: bytes::Bytes::from(described),
                covers: Rect::new(0, 0, observation.space.width, observation.space.height),
                generation: observation.geometry_generation,
                complete,
            })
        }
        agent_perception::Read::Unchanged { generation, .. } => Ok(Frame {
            bytes: bytes::Bytes::new(),
            covers: Rect::new(0, 0, 0, 0),
            generation,
            complete: true,
        }),
    }
}

/// The share of the framebuffer these rectangles touch, as a fraction.
///
/// Computed by summing areas rather than by unioning, because two rects in
/// opposite corners union to the whole screen and would report a coverage of
/// one for four moved pixels. Overlapping rects are double counted and the
/// result is clamped, which overstates rather than understates: a reader
/// deciding whether a partial read is worth it should be told the pessimistic
/// number.
fn coverage_of(rects: &[Rect]) -> f32 {
    let touched: u64 = rects
        .iter()
        .map(|r| u64::from(r.width) * u64::from(r.height))
        .sum();
    if touched == 0 {
        return 0.0;
    }
    let bounds = rects
        .iter()
        .fold(Rect::new(0, 0, 0, 0), |acc, r| acc.union(r));
    let area = u64::from(bounds.width) * u64::from(bounds.height);
    if area == 0 {
        return 0.0;
    }
    (touched as f32 / area as f32).min(1.0)
}
