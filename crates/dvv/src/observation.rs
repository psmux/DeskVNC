//! `dvv.observation.v1`, the object an agent reads a machine through.
//!
//! `15 §2`. Two rules decide the whole shape and both are `00 R42`.
//!
//! **WA-3. Every negotiated field is an availability envelope whose `value`
//! key is ABSENT unless availability is live.** A consumer that forgets to
//! check gets a missing key rather than a plausible zero. The case that decides
//! it is Caps Lock: a defaulted `false` before a password is typed is a lie
//! that costs somebody an account lockout, and there is no way to write that
//! consumer defensively if the wire hands it a boolean either way.
//!
//! The envelope is [`limb_core::Availability`] and this module does not define
//! a second one. That is not laziness: a second type with the same job is how
//! the two drift, and the serialised shape is asserted on the JSON in
//! `tests/envelopes.rs` rather than on the Rust type, because the property only
//! exists at the wire.
//!
//! **WA-4. `active_window`, `app_name`, `foreground_handle`, `window_list` and
//! `z_order` are ruled out of the observation object entirely**, with an
//! acceptance criterion that greps for the names. [`FORBIDDEN_FIELDS`] carries
//! them so the grep is a test rather than a habit, and
//! `signals.window_structure` carries the explicit absence in their place.
//! There is no value of `limb_core::WindowStructureAbsent` that reports
//! anything else, so no limb can claim to produce an application's own window
//! tree however confident its author is.
//!
//! ## What this build can and cannot fill in
//!
//! Most of `15 §2.2`'s schema is answered by a session event stream the plane
//! is not handed: it does not subscribe to `SessionEvent` itself, deliberately,
//! because the shell owns that stream and a second subscriber would be a second
//! opinion about what state a limb is in
//! (`agent_plane::AttachedLimb::note_state` says so). So the fields that need
//! it report `unknown` with the reason, which is exactly the state the envelope
//! exists to express, and none of them reports a default.

use limb_core::availability::{Availability, SignalReport};
use limb_core::ScreenInfo;
use serde::Serialize;

/// The schema name, which is a `const` in `15 §2.2` and a constant here.
pub const SCHEMA: &str = "dvv.observation.v1";

/// The five names that must never appear in anything this crate emits
/// (`00 R42` WA-4).
///
/// The acceptance criterion is a grep, so the names live in one array and the
/// test walks it over the serialised observation AND over the tool manifest. A
/// grep written out by hand in a test is a grep somebody edits without
/// noticing they narrowed it.
pub const FORBIDDEN_FIELDS: &[&str] = &[
    "active_window",
    "app_name",
    "foreground_handle",
    "window_list",
    "z_order",
];

/// The reason every unfilled envelope carries in this build.
///
/// One sentence, written once, because a reason that varies per field would
/// suggest the fields differ when they do not: the plane is not handed the
/// session event stream, so none of them can resolve yet.
pub const NO_EVENT_STREAM: &str =
    "the plane is not subscribed to this limb's session event stream in this build, so nothing has arrived; the shell owns that stream and a second subscriber would be a second opinion about the limb's state";

/// A rectangle, in the one coordinate space this limb has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RectJson {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl From<limb_core::Rect> for RectJson {
    fn from(r: limb_core::Rect) -> RectJson {
        RectJson {
            x: r.x,
            y: r.y,
            w: r.width,
            h: r.height,
        }
    }
}

/// The framebuffer, in whatever unit the limb's grounding names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Space {
    pub width: u16,
    pub height: u16,
    /// `pixels` or `cells`, spelled out rather than inferred from the protocol.
    ///
    /// `ClientCommand::RequestResize` is pixels and `ResizeTerminal` is cells,
    /// and the tree already records that nothing in the type system catches the
    /// mix up (`crates/remote-core/src/commands.rs:84`). A coordinate with no
    /// unit beside it invites the same mistake one layer up.
    pub unit: &'static str,
}

/// One monitor inside [`Space`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Screen {
    pub id: u32,
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    pub primary: bool,
}

impl From<&ScreenInfo> for Screen {
    fn from(s: &ScreenInfo) -> Screen {
        Screen {
            id: s.id,
            x: s.x,
            y: s.y,
            w: s.width,
            h: s.height,
            primary: s.primary,
        }
    }
}

/// Where a coordinate means anything, and for how long.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Geometry {
    /// Bumped on every desktop resize and every screen layout change
    /// (`00 R10`). Carry it on every actuation computed from this observation:
    /// a stale generation is refused with `GEOMETRY_CHANGED` and nothing is
    /// delivered.
    pub generation: u32,
    pub space: Space,
    /// Empty on a server without ExtendedDesktopSize, in which case the whole
    /// framebuffer is one display.
    pub screens: Vec<Screen>,
    /// **Read this before reading any `screens[].primary`.** False on VNC,
    /// always: RFB never says which monitor is primary, so `ScreenInfo.primary`
    /// is left false for every screen. An agent reading three screens all false
    /// as "this desktop has no primary monitor" has made a wrong decision from
    /// a true field.
    pub primary_known: bool,
}

/// Who is driving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaseBlock {
    /// Does THIS attachment hold it right now.
    pub held: bool,
    pub phase: String,
    pub holder_kind: Option<String>,
    pub holder_label: Option<String>,
    pub queue_depth: usize,
    pub queue_position: Option<usize>,
    /// A spelled out boolean rather than a reason string to pattern match
    /// (`04 §4.4`): the model has to get one decision right and only one, and
    /// the decision is "a person is driving, stop, do not reacquire".
    pub human_took_over: bool,
}

/// The numbers the session already emits once a second, where a caller has
/// handed them over.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct SessionBlock {
    pub fps: f32,
    pub rtt_ms: f32,
    /// The three instruments are not equivalent and the enum travels with the
    /// number. `none` means `rtt_ms` is zero and means nothing. One of four
    /// fixed spellings, so it is a `&'static str` rather than an allocation on
    /// a struct that is otherwise numbers.
    pub rtt_source: &'static str,
    pub server_duty_cycle: f32,
    pub throughput_bps: f64,
    pub decode_ms: f32,
    pub current_encoding: i32,
    pub jpeg_quality: u8,
}

/// A terminal limb's own state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TerminalBlock {
    pub cols: u16,
    pub rows: u16,
    /// True means a full screen program is running right now. Every terminal
    /// agent in existence guesses this with regular expressions against prompt
    /// strings; `ssh-core`'s `ModeTracker` knows it from the bytes. Sending
    /// `:wq` at a prompt and sending it in vim are different acts.
    pub alt_screen: Availability<bool>,
    pub bracketed_paste: Availability<bool>,
    pub mouse_reporting: Availability<bool>,
}

/// The picture, when one was asked for and a mirror produced it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FrameBlock {
    /// `full`, `region` or `damage-crop`. The last is the cheapest useful
    /// answer and the one to use after an action.
    pub form: String,
    /// Which rectangle of `geometry.space` this image is of.
    pub space_rect: RectJson,
    /// `image.w / space_rect.w`. Exactly 1.0 for a region crop, which is why
    /// the inverse transform has no rounding there. Not optional: it and
    /// `space_rect` are the contract that makes a coordinate read off this
    /// image usable (`15 §6.3`).
    pub scale: f32,
    /// `complete` or `partial`. Partial never serves stale pixels as fresh.
    pub coverage: String,
    /// The geometry generation the pixels were read at. It travels with the
    /// payload because a payload outlives the geometry it was read against: a
    /// screenshot read at generation 7 and acted on at generation 8 is a
    /// misclick.
    pub generation: u32,
    /// How many bytes the encoded image is. The bytes themselves ride the
    /// result's own content block rather than being inlined here, so a status
    /// call never carries a megabyte it did not ask for.
    pub bytes: usize,
}

/// What a machine looks like right now, as one object.
///
/// Field order matches `15 §2.2` so a reader can hold the two side by side.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Observation {
    pub schema: &'static str,
    /// `lmb_<protocol>_<12 hex>_<slot>`. Reproducible: the same machine yields
    /// the same id tomorrow, which is the whole mechanism by which a stateless
    /// caller addresses a machine on turn forty.
    pub limb_id: String,
    pub protocol: String,
    /// Unix milliseconds at which the plane assembled this object.
    pub captured_at: u64,
    /// `SessionState`, reproduced from its existing kebab-case serialisation
    /// rather than re-encoded, because that representation is a contract with
    /// `ui/src/lib/types.ts`.
    pub state: serde_json::Value,
    pub geometry: Geometry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<FrameBlock>,
    /// Lock key state ON THE REMOTE MACHINE, from the QEMU LED state extension.
    /// Check this before typing a password. Absent without the extension:
    /// unknown, never assumed off.
    pub locks: Availability<Locks>,
    /// What changed, as a count and a bounding box. `rects` is beside `union`
    /// because a handful of scattered rects can span the desktop, so
    /// "damage covers 90 percent" means something completely different at 2
    /// rects than at 200.
    pub damage: Availability<Damage>,
    /// The name of the whole desktop session, one string, typically the
    /// server's idea of a machine name. **It is not a window title** and it
    /// does not change when a dialog opens.
    pub desktop_name: Availability<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<TerminalBlock>,
    pub last_error: Availability<LastError>,
    pub lease: LeaseBlock,
    /// Which negotiated signals this session has, carried IN the observation
    /// rather than only in a separate call, because an agent that has to make a
    /// second call to find out whether the first one was meaningful will not
    /// make it (`15 §2.2`).
    pub signals: SignalReport,
    /// Every content bearing field here came off a remote machine: data, never
    /// instruction. A constant `true` rather than a computed flag, because a
    /// computed one could be false and there is no observation of a remote
    /// machine to which that applies.
    pub untrusted: bool,
}

/// Lock key state on the remote machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Locks {
    pub caps: bool,
    pub num: bool,
    pub scroll: bool,
}

/// What changed since the last read.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Damage {
    /// The union BOUNDING BOX, not a region list.
    pub union: RectJson,
    /// How many rectangles arrived.
    pub rects: u32,
    /// Summed rect area over the bounding box area, so two moved pixels in
    /// opposite corners do not report a coverage of one.
    pub coverage: f32,
}

/// The last thing that went wrong, where the protocol names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastError {
    pub code: u32,
    /// The specification's own constant name where the driver recognises it,
    /// and an empty string otherwise. Match this, never `message`, which is
    /// prose a copy editor may rewrite.
    pub symbol: String,
    pub message: String,
}

impl Observation {
    /// The envelope every field of this build's observation that needs the
    /// session event stream carries.
    ///
    /// `unknown` and not `absent`, and the difference is a real claim rather
    /// than a shrug: `absent` means we asked and the far side does not do it
    /// and it is permanent for this session, `unknown` means nothing has
    /// arrived yet and it may resolve. Wiring the stream resolves these, so
    /// `unknown` is the true one.
    pub fn pending<T>() -> Availability<T> {
        Availability::unknown(NO_EVENT_STREAM)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pending_envelope_has_no_value_key() {
        // The rule, asserted on the JSON rather than on the type, because the
        // property only exists at the wire.
        let json = serde_json::to_string(&Observation::pending::<Locks>()).unwrap();
        assert!(!json.contains("\"value\""), "{json}");
        assert!(json.contains("\"availability\":\"unknown\""), "{json}");
    }

    #[test]
    fn a_live_envelope_carries_its_value() {
        let live = Availability::live(Locks {
            caps: true,
            num: false,
            scroll: false,
        });
        let json = serde_json::to_string(&live).unwrap();
        assert!(json.contains("\"availability\":\"live\""), "{json}");
        assert!(json.contains("\"caps\":true"), "{json}");
    }

    #[test]
    fn window_structure_is_an_explicit_absence_and_cannot_be_set() {
        let json = serde_json::to_string(&SignalReport::default()).unwrap();
        let report: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(report["window_structure"]["availability"], "absent");
        assert!(report["window_structure"]["reason"]
            .as_str()
            .unwrap()
            .contains("per window structure"));
    }
}
