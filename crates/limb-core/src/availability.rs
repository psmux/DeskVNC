//! The availability envelope, and the report of what this session negotiated.
//!
//! `00 R34` and `00 R42` (WA-3). Every signal a limb can offer is capability
//! negotiated: the QEMU LED state extension may not be there, RFB Fence may
//! not be there, ExtendedDesktopSize may not be there, and RDP's `ERRINFO_`
//! space does not exist on VNC at all. So no consumer may assume presence, and
//! a signal the far side did not offer is reported ABSENT rather than
//! defaulted.
//!
//! The rule that decides the shape: **a field whose availability is not live
//! has no `value` key at all**, so a consumer that forgets to check gets a
//! missing key rather than a plausible zero. The concrete case that decides it
//! is Caps Lock. A defaulted `false` before a password is typed is a lie that
//! costs somebody an account lockout, and there is no way to write that
//! consumer defensively if the wire hands it a boolean either way.
//!
//! `absent` and `unknown` are different claims and an agent should treat them
//! differently. `absent` means we asked and the far side does not do it, and it
//! is permanent for this session. `unknown` means nothing has arrived yet, and
//! it may resolve. There is no fourth value and there is no implicit default.
//!
//! This is the same discipline as `00 R7` (the plane never invents an exit
//! code) and `00 R36` (an inferred tree is always labelled inferred), and
//! `stats.rs` reached it a year earlier with `RttSource`, whose doc comment
//! already says that a number whose provenance has been stripped is worse than
//! no number.

use serde::{Deserialize, Serialize};

/// A value that may not be there, with the reason it is not.
///
/// The serialised shape is the contract and it is asserted on the JSON rather
/// than on the Rust type, because the property only exists at the wire:
///
/// ```jsonc
/// { "availability": "live",    "value": <the thing> }
/// { "availability": "absent",  "reason": "server did not offer QEMU LED state" }
/// { "availability": "unknown", "reason": "nothing has arrived yet this session" }
/// ```
///
/// There is deliberately no `unwrap_or_default`, no `Deref` and no `From<T>`.
/// Every one of those would be a way to turn a missing signal back into a
/// plausible value, which is the failure the type exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "availability", rename_all = "kebab-case")]
pub enum Availability<T> {
    /// We have it, now.
    Live { value: T },
    /// We asked and the far side does not do it. Permanent for this session.
    Absent { reason: String },
    /// Nothing has arrived yet. May resolve.
    Unknown { reason: String },
}

impl<T> Availability<T> {
    /// We have it.
    pub fn live(value: T) -> Self {
        Availability::Live { value }
    }

    /// The far side does not offer it. The reason is shown to an agent
    /// verbatim, so it is a sentence naming the extension rather than a code.
    pub fn absent(reason: impl Into<String>) -> Self {
        Availability::Absent {
            reason: reason.into(),
        }
    }

    /// Nothing yet.
    pub fn unknown(reason: impl Into<String>) -> Self {
        Availability::Unknown {
            reason: reason.into(),
        }
    }

    /// The value, if it is live.
    ///
    /// An `Option` and not a default. A caller that wants to proceed without
    /// the signal has to write the branch, which is the point.
    pub fn value(&self) -> Option<&T> {
        match self {
            Availability::Live { value } => Some(value),
            _ => None,
        }
    }

    /// Is this live? Named for the wire word rather than `is_some`, so a
    /// reader of the call site is reading the same vocabulary as a reader of
    /// the JSON.
    pub fn is_live(&self) -> bool {
        matches!(self, Availability::Live { .. })
    }
}

/// Whether one negotiated signal is available on this session.
///
/// The same three states as [`Availability`] with no payload, because the
/// signals report answers "can this session tell me X" and not "what is X".
/// A separate type rather than `Availability<()>`, which would serialise a
/// `"value": null` and reintroduce the key the whole rule exists to remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "availability", rename_all = "kebab-case")]
pub enum SignalState {
    /// This session can answer questions that need this signal.
    Live,
    /// We asked and the far side does not offer it. Permanent for this
    /// session, so an agent should stop reaching for it rather than retry.
    Absent { reason: String },
    /// Nothing has arrived yet. May resolve, so an agent may look again.
    Unknown { reason: String },
}

impl SignalState {
    pub fn absent(reason: impl Into<String>) -> Self {
        SignalState::Absent {
            reason: reason.into(),
        }
    }

    pub fn unknown(reason: impl Into<String>) -> Self {
        SignalState::Unknown {
            reason: reason.into(),
        }
    }

    /// Can this session answer a question that needs this signal?
    pub fn is_live(&self) -> bool {
        matches!(self, SignalState::Live)
    }
}

/// The reason `window_structure` gives, which is the same reason every time
/// because the fact is a property of the protocols and not of a session.
pub const WINDOW_STRUCTURE_REASON: &str =
    "neither RFB nor RDP carries per window structure on this build; the routes that would are 14 §5 Tier C and are not version 1";

/// The `window_structure` entry, which is always absent and cannot be set.
///
/// `00 R42` (WA-4) rules the five fabricated window fields out of the
/// observation object entirely: the focused window, the application name, the
/// foreground handle, the window list and the stacking order. Its acceptance
/// criterion is a grep for those five identifiers, which is why they are
/// described here rather than spelled, and the grep is
/// `tests/availability.rs`. `signals.window_structure` carries an explicit
/// absence in their place.
///
/// A zero sized type rather than a settable [`SignalState`] field, so that the
/// absence is structural. There is no value of this type that reports
/// anything else, which means no limb can ever claim to produce an
/// application's own window tree, however confident its author is. That is
/// `00 R36`'s discipline applied to a field that would otherwise be
/// fabricated: a confidently wrong tree is worse than no tree, because it
/// makes an agent act decisively on a misreading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowStructureAbsent;

impl Serialize for WindowStructureAbsent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("SignalState", 2)?;
        s.serialize_field("availability", "absent")?;
        s.serialize_field("reason", WINDOW_STRUCTURE_REASON)?;
        s.end()
    }
}

/// Which of the negotiated signals this session actually has.
///
/// Carried IN the observation rather than only in a separate call, because an
/// agent that has to make a second call to find out whether the first one was
/// meaningful will not make it (`15 §2.2`).
///
/// [`SignalReport::default`] is every signal `unknown` and window structure
/// absent, which is the honest state of a session that has just connected and
/// negotiated nothing yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignalReport {
    /// Exact move deltas from `RectPayload::CopyRect`
    /// (`crates/remote-core/src/events.rs:33`). When a list scrolls, RFB says
    /// "the content at src is now at dst" rather than resending pixels, which
    /// is an exact delta with magnitude and direction and the cheapest
    /// structural hint in the protocol.
    pub copy_rect: SignalState,
    /// RFB Fence. Decides whether verified action is a barrier or a timeout
    /// (`00 R35`), which is the largest single reliability difference between
    /// two desktop limbs.
    pub fence: SignalState,
    /// The QEMU LED state extension, giving lock key state ON THE REMOTE
    /// MACHINE. Check this before typing a password.
    pub led_state: SignalState,
    /// Server sent cursor position. Not merely where we last put the pointer:
    /// the far side can move it and tell us
    /// (`crates/remote-core/src/events.rs:110`).
    pub cursor_position: SignalState,
    /// Cursor shape, held apart from the framebuffer, which is why no
    /// wrapper's screenshot can contain it.
    pub cursor_shape: SignalState,
    /// ExtendedDesktopSize. Absent means the whole framebuffer is one display.
    pub screen_layout: SignalState,
    /// The per rect encoding byte as a content type hint. A HINT, never a
    /// contract: some servers use one encoding for everything.
    pub content_hint: SignalState,
    /// RDP's `ERRINFO_` space. Absent on VNC entirely.
    pub errinfo: SignalState,
    /// Terminal limbs only. `ModeTracker::in_alt_screen()`
    /// (`crates/ssh-core/src/modes.rs:253`) knows from the bytes whether a
    /// full screen program is running, which every other terminal agent
    /// guesses with regular expressions against prompt strings.
    pub alt_screen: SignalState,
    /// Whether a resize request will do anything. The run loop gates it on
    /// `supports_extended_desktop_size` and otherwise logs a line and drops
    /// the request, which is right for a UI and wrong for an agent
    /// (`06 R6-7`).
    pub resize: SignalState,
    /// Always absent, on every protocol this build speaks. The entry exists so
    /// the negative is STATED rather than inferred from a missing field.
    pub window_structure: WindowStructureAbsent,
}

impl Default for SignalReport {
    fn default() -> Self {
        let nothing_yet = || SignalState::unknown("nothing has arrived yet this session");
        SignalReport {
            copy_rect: nothing_yet(),
            fence: nothing_yet(),
            led_state: nothing_yet(),
            cursor_position: nothing_yet(),
            cursor_shape: nothing_yet(),
            screen_layout: nothing_yet(),
            content_hint: nothing_yet(),
            errinfo: nothing_yet(),
            alt_screen: nothing_yet(),
            resize: nothing_yet(),
            window_structure: WindowStructureAbsent,
        }
    }
}
