//! The perception ladder: what an agent may ask for, and what it gets back.
//!
//! `03 §4`, ordered by cost, cheapest first. An agent should reach for the
//! cheapest rung that answers its question and the surface should make the
//! cheap rungs obvious, so the ordering below is the ordering of the enum.
//!
//! | Rung | What | Needs a mirror | Cost |
//! |---|---|---|---|
//! | 0 | session state and stats | no | zero, already emitted once a second |
//! | 1 | the damage rect list | no | zero, already computed by the run loop |
//! | 2 | a downscaled full frame | yes | 2.9 ms to 24.9 ms plus the encode |
//! | 3 | a full resolution region | yes | proportional to the crop |
//! | 4 | a crop around what changed | yes | as rung 3 |
//!
//! **The default call is rung 4 at scale 1.0, not rung 2.** `03 §5.2` gives
//! the arithmetic: a 400x200 crop is 120 visual tokens against 2691 for an
//! unscaled 1080p frame, twenty two times cheaper and legible, because nothing
//! was downscaled. The full frame's job is orientation, once, at the start of
//! a task. The region's job is everything after that.
//!
//! Two things `03 §4` lists are not in this enum and the absences are
//! deliberate.
//!
//! Rungs 0 and 1 are here as [`Rung`] values with no request shape, because
//! this crate adds nothing to them: rung 0 is `SessionStats`, already
//! broadcast at 1 Hz, and rung 1 is [`crate::damage::DamageLog`], which needs
//! no mirror and is the reason `03 §9 A5` can assert that no framebuffer is
//! allocated for a client that only watches for change.
//!
//! Rung 5, a tile diff between two frames, is not built. It costs a SECOND
//! full framebuffer (another 8.3 MB at 1080p or 33 MB at 4K) plus 4.3 ms to
//! 24.8 ms per comparison, and its competitor is free: the damage list is what
//! the server already told us changed. `03 §4.6` says a diff is only worth its
//! cost when the server's damage tracking is not to be trusted, which is a
//! real condition with an existing escape hatch (`SetAlwaysRefresh`), and
//! version 1 should not pay for it by default.

use crate::coverage::FrameCoverage;
use crate::damage::{DegradeReason, ReaderId, DEFAULT_MARGIN};
use crate::encode::{EncodeOptions, EncodedImage, DEFAULT_LONG_EDGE};
use limb_core::availability::Availability;
use limb_core::fence::GeometryGeneration;
use limb_core::observation::Timestamp;
use remote_core::events::ScreenInfo;
use remote_core::geometry::Rect;
use serde::{Serialize, Serializer};

/// Where on the ladder an answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rung {
    /// Rung 0. Free and already broadcast.
    StateAndStats,
    /// Rung 1. Free and already computed.
    Damage,
    /// Rung 2. The orientation shot.
    Frame,
    /// Rung 3. The precise one, for reading a dialog or an error message.
    Region,
    /// Rung 4. The default after something changes.
    Change,
}

impl Rung {
    /// Does answering this cost a framebuffer mirror?
    ///
    /// The gate `03 §9 A5` asserts against: a client that only watches for
    /// change must have nothing allocated on its behalf.
    pub const fn needs_mirror(self) -> bool {
        match self {
            Rung::StateAndStats | Rung::Damage => false,
            Rung::Frame | Rung::Region | Rung::Change => true,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Rung::StateAndStats => "state-and-stats",
            Rung::Damage => "damage",
            Rung::Frame => "frame",
            Rung::Region => "region",
            Rung::Change => "change",
        }
    }
}

/// What to look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadKind {
    /// Rung 2. The whole framebuffer, downscaled so its long edge is at most
    /// `long_edge`.
    Frame { long_edge: u32 },
    /// Rung 3. A rectangle at native resolution, `scale: 1.0`, no rounding to
    /// argue about.
    Region { rect: Rect },
    /// Rung 4. A crop around what has changed since this reader last looked.
    Change { reader: ReaderId, margin: u16 },
}

/// What to do when part of what was asked for cannot be vouched for.
///
/// `00 R6` allows exactly two answers and this is the choice between them.
/// There is no third value meaning "return it anyway", which is what a mirror
/// built directly on `Framebuffer` does by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StalePolicy {
    /// Refuse the read. The default, because an agent that did not ask to be
    /// told about staleness is an agent that will not check.
    #[default]
    Refuse,
    /// Return the frame with the untrustworthy rectangles listed on it. For a
    /// caller that has decided what to do with a partial answer.
    Annotate,
}

/// One read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub kind: ReadKind,
    /// The geometry generation this request was computed against, or `None`
    /// for a read that is not answering an earlier observation.
    ///
    /// `00 R10`. A read fenced against a generation the limb has moved past is
    /// refused, because the caller is asking about a screen that no longer
    /// exists and would compare the answer with coordinates from the old one.
    /// A read with no fence is admitted: asking what is on the screen right
    /// now is not a claim about what was on it before.
    pub fence: Option<GeometryGeneration>,
    pub encode: EncodeOptions,
    pub stale: StalePolicy,
}

impl ReadRequest {
    /// **The default perception call**: a crop around the changed region at
    /// scale 1.0 (`03 §4.5`, `03 §5.2`).
    ///
    /// It is a named constructor rather than a `Default` impl because there is
    /// no default reader: rung 4 is per reader by construction and a defaulted
    /// reader id would let two agents consume each other's changes.
    pub fn change(reader: ReaderId) -> Self {
        ReadRequest {
            kind: ReadKind::Change {
                reader,
                margin: DEFAULT_MARGIN,
            },
            fence: None,
            encode: EncodeOptions::default(),
            stale: StalePolicy::Refuse,
        }
    }

    /// Rung 2, at the long edge a standard tier model would have resized us to
    /// anyway (`00 R43` WA-11).
    pub fn frame() -> Self {
        ReadRequest {
            kind: ReadKind::Frame {
                long_edge: DEFAULT_LONG_EDGE,
            },
            fence: None,
            encode: EncodeOptions::default(),
            stale: StalePolicy::Refuse,
        }
    }

    /// Rung 3.
    pub fn region(rect: Rect) -> Self {
        ReadRequest {
            kind: ReadKind::Region { rect },
            fence: None,
            encode: EncodeOptions::default(),
            stale: StalePolicy::Refuse,
        }
    }

    pub fn fenced_at(mut self, generation: GeometryGeneration) -> Self {
        self.fence = Some(generation);
        self
    }

    pub fn annotating_stale(mut self) -> Self {
        self.stale = StalePolicy::Annotate;
        self
    }

    pub fn rung(&self) -> Rung {
        match self.kind {
            ReadKind::Frame { .. } => Rung::Frame,
            ReadKind::Region { .. } => Rung::Region,
            ReadKind::Change { .. } => Rung::Change,
        }
    }
}

/// What a read produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Read {
    /// A picture, self describing per `03 §9 A8`.
    Frame(Box<FrameObservation>),
    /// Rung 4 with an empty damage list.
    ///
    /// **Not an error.** "Nothing changed" is the answer to "show me what
    /// changed", and an agent that receives an error for it will retry
    /// immediately rather than wait, which turns the cheapest rung into a spin
    /// loop. It carries the generation so the caller can still fence its next
    /// action against a read that returned no pixels.
    Unchanged {
        generation: GeometryGeneration,
        at: Timestamp,
    },
}

/// `ScreenInfo` with a serialiser.
///
/// `remote-core` deliberately derives none: `SessionEvent` is hand serialised
/// by the shell in `event_json` so a new variant is a compile error where
/// somebody has to decide what a consumer sees
/// (`crates/remote-core/src/events.rs:8`). This is that decision made once for
/// the perception path, and it drops `flags`, which RFB assigns no meaning to
/// yet and which the shell already drops before the webview sees it
/// (`src-tauri/src/commands/session.rs:96`). Passing a field through that
/// nobody can interpret invites somebody to interpret it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenList(pub Vec<ScreenInfo>);

impl Serialize for ScreenList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeSeq, SerializeStruct};
        struct One<'a>(&'a ScreenInfo);
        impl Serialize for One<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut s = serializer.serialize_struct("ScreenInfo", 6)?;
                s.serialize_field("id", &self.0.id)?;
                s.serialize_field("x", &self.0.x)?;
                s.serialize_field("y", &self.0.y)?;
                s.serialize_field("width", &self.0.width)?;
                s.serialize_field("height", &self.0.height)?;
                s.serialize_field("primary", &self.0.primary)?;
                s.end()
            }
        }
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for screen in &self.0 {
            seq.serialize_element(&One(screen))?;
        }
        seq.end()
    }
}

/// What the plane knows about the monitors and this crate does not.
///
/// `03 §7.3`. Every perception response carries the screen list, because a
/// 3 x 1080p desktop is a 5760x1080 framebuffer and a full frame downscaled to
/// a 1456 long edge gives each window title about 30 pixels of height, which
/// is unreadable. An agent that can see the layout knows to ask for one screen
/// instead.
///
/// `primary_known` is not decoration. RFB never says which monitor is primary
/// so the VNC path leaves `primary` false on every screen, while RDP does say
/// through `TS_MONITOR_PRIMARY`. An agent that reads three falses as "there is
/// no primary monitor" rather than "this protocol does not say" will make a
/// wrong decision, and this is the same discipline `RttSource` already applies
/// to a round trip time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenFacts {
    pub screens: Availability<ScreenList>,
    pub primary_known: bool,
}

impl ScreenFacts {
    /// Nothing has arrived yet. May resolve.
    pub fn unknown() -> Self {
        ScreenFacts {
            screens: Availability::unknown("no screen layout has arrived yet this session"),
            primary_known: false,
        }
    }

    /// The server does not do ExtendedDesktopSize, so the whole framebuffer is
    /// one display and there is no list to give. Permanent for this session,
    /// which is why it is `absent` and not `unknown`.
    pub fn absent() -> Self {
        ScreenFacts {
            screens: Availability::absent(
                "this server did not offer ExtendedDesktopSize, so the whole framebuffer is one display and no monitor list exists",
            ),
            primary_known: false,
        }
    }

    pub fn live(screens: Vec<ScreenInfo>, primary_known: bool) -> Self {
        ScreenFacts {
            screens: Availability::live(ScreenList(screens)),
            primary_known,
        }
    }
}

/// A picture, and everything needed to use a coordinate read off it.
///
/// `03 §9 A8`: `space`, `scale`, `screens`, `primary_known`, the geometry
/// generation and `coverage` are present on every response at every rung. A
/// response missing one is a bug and not a compact form. `scale` lives inside
/// `image.space` because a scale factor that can be separated from its image
/// will be (`00 R43`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FrameObservation {
    pub rung: Rung,
    /// The framebuffer this was read from, which is the coordinate space every
    /// actuation uses. There is exactly one per limb (`00 R10`).
    pub space: Space,
    pub image: EncodedImage,
    /// `00 R6`. Complete, or partial with every untrustworthy rectangle named.
    #[serde(flatten)]
    pub coverage: FrameCoverage,
    /// `00 R10`. What to fence the next action against.
    #[serde(serialize_with = "ser_generation")]
    pub geometry_generation: GeometryGeneration,
    #[serde(serialize_with = "ser_timestamp")]
    pub captured_at: Timestamp,
    pub screens: Availability<ScreenList>,
    pub primary_known: bool,
    /// The damage rectangles this crop was chosen around, on rung 4. A LIST,
    /// never a union (`00 R39b`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub damage: Vec<Rect>,
    /// Changed rectangles this answer does not cover.
    #[serde(skip_serializing_if = "is_zero")]
    pub remaining_changes: usize,
    /// Set when a rung could not stay on its rung. `03 §9 A10`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded: Option<DegradeReason>,
}

/// The framebuffer's size, which is the one coordinate space (`03 §7.2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Space {
    pub width: u16,
    pub height: u16,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn ser_generation<S: Serializer>(g: &GeometryGeneration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u32(g.get())
}

fn ser_timestamp<S: Serializer>(t: &Timestamp, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(t.0)
}
