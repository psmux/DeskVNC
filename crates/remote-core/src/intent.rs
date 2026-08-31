//! What an agent wants done.
//!
//! `PRDAgentPlug/00 R28` and `02 §2`. [`ClientCommand`] gains exactly one
//! variant, `Agent(AgentIntent)`, and the reason it is one variant rather than
//! eighteen flat ones is a property of the command side that the event side
//! does not have.
//!
//! `SessionEvent` has an exhaustive match discipline, enforced by
//! `event_json`'s hand written match, so a new event variant is a compile
//! error where somebody has to decide what happens to it. The command side has
//! no such property. `ssh-core`'s pump ends in `_ => continue` with the comment
//! "dropped rather than guessed at, and silently, because the shell sends some
//! of them to every session it owns" (`crates/ssh-core/src/driver.rs`). For a
//! UI that is correct: a quality preset sent to a terminal is noise.
//!
//! For an agent it is the worst failure this design can have. Eighteen flat
//! variants would mean every driver silently ignoring the ones it has not
//! implemented, the intent vanishing with no error, and the agent not retrying
//! but WAITING, because nothing told it anything happened. Wrapped, the drop
//! site is one arm in one place, and `limb_core::Limb::supports` lets the plane
//! refuse before anything is sent, so silence becomes a sentence.
//!
//! ## Why this vocabulary lives in `remote-core`
//!
//! `00 R47a` records the cycle. This material was written as `limb-core`, which
//! depends on `remote-core`; `ClientCommand::Agent(AgentIntent)` would have
//! made `remote-core` name a `limb-core` type, and the two crates cannot both
//! depend on each other. The way out is that this was never limb material.
//! `remote-core` already owns the two protocol neutral vocabularies, the
//! commands a session is told ([`crate::commands`]) and the events it tells
//! back ([`crate::events`]); the intents an agent issues are a third of exactly
//! the same kind. What sits ON TOP of them, the `Limb` trait, capabilities,
//! identity and availability, stayed in `limb-core`, which re-exports every
//! name here at its old path so no caller moved.
//!
//! [`ClientCommand`]: crate::commands::ClientCommand

use crate::geometry::{GeometryGeneration, Rect};
use crate::keys::NamedKey;
use crate::options::QualityPreset;
use bytes::Bytes;
use std::time::Duration;

/// Which party asked, defined by `agent-lease` because arbitration owns the
/// identity every audit line is keyed on (`08 §5`).
///
/// Naming it here adds no cycle: `agent-lease` depends on serde and thiserror
/// and on no crate in this workspace.
///
/// Re-exported rather than aliased. `limb_core::party::GrantId` is already the
/// alias `02 §2.2` asks for, and a second alias for the same type would be a
/// second name to keep in step for no gain; passing the original through means
/// both crates' globs land on ONE item, which is what makes them agree.
pub use agent_lease::PartyId;

/// A dense, monotonic per limb identifier.
///
/// `u64` rather than a uuid because it appears in every observation, every
/// audit line and every trace span, and a thirty six byte string in that
/// position is a real cost at eight limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntentId(pub u64);

impl std::fmt::Display for IntentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Mints [`IntentId`]s for one limb.
///
/// Monotonic so a log reads in order, and never reused, which is what lets
/// `02 §3.2` say that an observation carrying an id an agent does not
/// recognise is a bug in the plane rather than a race.
#[derive(Debug, Default)]
pub struct IntentSequence {
    next: u64,
}

impl IntentSequence {
    pub fn new() -> Self {
        IntentSequence { next: 0 }
    }

    /// The next id. Called `mint` rather than `next` because this is not an
    /// iterator and must never be mistaken for one: an id handed out is an id
    /// an observation will refer to, so pulling one speculatively and dropping
    /// it leaves a gap in a sequence a reader is entitled to read as dense.
    ///
    /// Saturating rather than wrapping. At one intent a microsecond a `u64`
    /// lasts half a million years, so the saturation is unreachable, and a
    /// wrap would reissue an id that an outstanding observation still refers
    /// to.
    pub fn mint(&mut self) -> IntentId {
        self.next = self.next.saturating_add(1);
        IntentId(self.next)
    }
}

/// One thing an agent wants done, with the identity that lets the answer be
/// matched to the question.
///
/// The identity is the largest single thing this vocabulary adds. Nothing in
/// `ClientCommand` today is correlated: the UI sends a pointer event and never
/// asks whether it landed, because a person watching the screen IS the
/// acknowledgement. An agent has no eyes, so every intent gets an id and every
/// id gets exactly one settlement (`02 §3.3`).
#[derive(Debug, Clone)]
pub struct AgentIntent {
    /// Minted by the plane, unique within one limb for the life of the
    /// process.
    pub id: IntentId,
    /// Which attachment asked, so an observation can be routed back to one
    /// agent and an audit line can name it.
    pub grant: PartyId,
    /// How long the agent is willing to wait, clamped by the plane against the
    /// grant's ceiling. `05 §4.1` requires it on `run` with no default and the
    /// reason generalises: an agent that has not said how long it will wait
    /// has not thought about the action.
    pub deadline: Option<Duration>,
    /// The geometry this action was computed against (`00 R10`).
    ///
    /// Required on any intent for which [`IntentKind::is_grounded`] is true,
    /// and refused when it is behind the limb's current generation. See
    /// `limb_core::fence::GeometryFence::admit`, which is the only place the
    /// comparison is written.
    pub fence: Option<GeometryGeneration>,
    pub kind: IntentKind,
}

/// The fieldless mirror of [`IntentKind`], for `limb_core::Limb::supports` and
/// for the capability table.
///
/// Kept in step with [`IntentKind::name`] by a test that walks both, because a
/// mirror that has drifted is worse than no mirror: it makes
/// `Limb::supports` answer a question about an intent that no longer exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum IntentName {
    Type,
    Press,
    Scancode,
    /// `00 R44` (WA-16) added this. `02 §2.4` listed seventeen intents and
    /// none was a standalone pointer move, yet three of four model families
    /// have one and `14 §3.3`'s cursor probe cannot be built without it.
    Move,
    Click,
    Drag,
    Scroll,
    Wait,
    ReadScreen,
    Capture,
    Exec,
    PtyRun,
    Declare,
    SendBytes,
    ClipboardGet,
    ClipboardSet,
    Tune,
    Cancel,
}

impl IntentName {
    /// Every intent name. Walked by the test that keeps this enum and
    /// [`IntentKind`] in step, and by any limb author who wants to be sure
    /// their `supports` match is total.
    pub const ALL: &'static [IntentName] = &[
        IntentName::Type,
        IntentName::Press,
        IntentName::Scancode,
        IntentName::Move,
        IntentName::Click,
        IntentName::Drag,
        IntentName::Scroll,
        IntentName::Wait,
        IntentName::ReadScreen,
        IntentName::Capture,
        IntentName::Exec,
        IntentName::PtyRun,
        IntentName::Declare,
        IntentName::SendBytes,
        IntentName::ClipboardGet,
        IntentName::ClipboardSet,
        IntentName::Tune,
        IntentName::Cancel,
    ];

    /// The name in a refusal, a trace span and an audit line.
    pub const fn as_str(self) -> &'static str {
        match self {
            IntentName::Type => "type",
            IntentName::Press => "press",
            IntentName::Scancode => "scancode",
            IntentName::Move => "move",
            IntentName::Click => "click",
            IntentName::Drag => "drag",
            IntentName::Scroll => "scroll",
            IntentName::Wait => "wait",
            IntentName::ReadScreen => "read_screen",
            IntentName::Capture => "capture",
            IntentName::Exec => "exec",
            IntentName::PtyRun => "pty_run",
            IntentName::Declare => "declare",
            IntentName::SendBytes => "send_bytes",
            IntentName::ClipboardGet => "clipboard_get",
            IntentName::ClipboardSet => "clipboard_set",
            IntentName::Tune => "tune",
            IntentName::Cancel => "cancel",
        }
    }
}

impl std::fmt::Display for IntentName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A point in this limb's one coordinate space.
///
/// Which space that is comes from `limb_core::Limb::grounding` and there is
/// exactly one per limb: a three monitor desktop is one framebuffer with three
/// rectangles marked out inside it, not three coordinate spaces
/// (`00 R10`, `03 §7.2`). `u16` because that is what
/// `ClientCommand::Pointer` carries, so nothing is lost or gained in the
/// lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Point {
    pub x: u16,
    pub y: u16,
}

impl Point {
    pub const fn new(x: u16, y: u16) -> Self {
        Point { x, y }
    }
}

/// Which pointer button.
///
/// Three, matching what `SessionInput` forwards: `e.button` 0, 1 and 2 become
/// RFB button bits 0, 1 and 2 (`ui/src/render/input.ts:521`). Anything else the
/// webview declines to forward, and an agent gets no more than a person does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Button {
    Left,
    Middle,
    Right,
}

impl Button {
    /// The RFB `PointerEvent` button mask bit for this button.
    pub const fn mask(self) -> u16 {
        match self {
            Button::Left => 1 << 0,
            Button::Middle => 1 << 1,
            Button::Right => 1 << 2,
        }
    }
}

/// Which way the wheel turned.
///
/// A direction and a click count rather than a pixel delta, and the reason is
/// the wire rather than taste: **there is no scroll magnitude on the wire.**
/// RFB encodes the wheel as button bits 3 to 6 with nowhere to put a number,
/// which is why `sendWheel` sends one press and release pair per click
/// (`ui/src/render/input.ts:772`), and the RDP side converts the same bit form
/// into `WHEEL_DELTA` rotation flags. A model asking to scroll by pixels is
/// refused rather than served an invented conversion (`15 §4.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScrollDirection {
    Up,
    Down,
    Left,
    Right,
}

impl ScrollDirection {
    /// The RFB button mask bit. The numbering is `ui/src/render/input.ts:830`
    /// to `:845` and it is the only place in the tree that assigns it, so it
    /// is quoted rather than rederived.
    pub const fn mask(self) -> u16 {
        match self {
            ScrollDirection::Up => 1 << 3,
            ScrollDirection::Down => 1 << 4,
            ScrollDirection::Left => 1 << 5,
            ScrollDirection::Right => 1 << 6,
        }
    }
}

/// What a `wait` is waiting for.
///
/// The values `04`'s `dvv_wait` already publishes. A timeout is an ordinary
/// settlement with what was observed, never an error, which is `04 §4.3`'s
/// rule and the right one: an agent that gets an error for a timeout will
/// treat a slow machine as a broken one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaitUntil {
    /// The session reaches `Connected`. The only useful call while a limb is
    /// still negotiating or waiting on a person for a credential.
    Connected,
    /// Nothing has changed for the quiet window.
    ///
    /// This is where the vocabulary is at its weakest and the weakness is
    /// structural rather than a threshold we can tune. The client does not
    /// observe the screen, it observes damage rectangles the SERVER chose to
    /// send, and `ClientCommand::SetAlwaysRefresh` exists precisely for
    /// servers whose damage tracking cannot be trusted
    /// (`crates/remote-core/src/commands.rs:36`). So this is least reliable on
    /// exactly the servers where an agent most needs it, and there is no
    /// signal that tells the agent which kind of server it is on. It is
    /// evidence, never confirmation, which is why
    /// `limb_core::observation::Verified` exists.
    ScreenStable,
    /// Something changed. The other half of a verified action.
    ScreenChanged,
    /// This string appears. UNTRUSTED as a needle is fine, it is ours; what
    /// comes back around it is not.
    Text(String),
    /// This string is gone. The condition a spinner or a progress dialog
    /// answers, and the one a screen stable wait answers badly.
    TextGone(String),
    /// The limb stopped doing anything at all, by whatever instrument
    /// `limb_core::Limb::quiescence` named.
    Idle,
    /// A running command finished.
    Exit,
}

impl WaitUntil {
    /// Does answering this condition require reading text?
    ///
    /// The question `PARAM_RULES[1]` asks, and the reason it is a method here
    /// rather than a match at the capability check is that the two must not
    /// drift: a new text bearing condition added without updating the
    /// capability rule would be a free pixel read for a grant holding only
    /// `view`.
    pub fn reads_text(&self) -> bool {
        matches!(self, WaitUntil::Text(_) | WaitUntil::TextGone(_))
    }
}

/// What form a screen read comes back in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadForm {
    /// Plain text. Free and exact on a limb with a character grid.
    Text,
    /// The character grid with its attributes.
    Cells,
    /// An image. Costs `capture` as well as `view`, which is `PARAM_RULES[0]`.
    Pixels,
}

/// Which rectangle of the framebuffer a capture is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureForm {
    Full,
    Region,
    /// The damage union, cropped. The cheapest useful answer and the one to
    /// use after an action (`03 §4.5`).
    DamageCrop,
}

/// What to run, carried verbatim from `05 §4.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    /// A string rather than an argv vector, with `05`'s reason: the transport
    /// hands it to a shell anyway, and pretending to be safer than the
    /// transport is worse than being honest about it.
    pub command: String,
    /// The declared working directory. A second SSH `exec` channel starts in
    /// the user's home directory with a fresh environment and inherits nothing
    /// the agent did five commands ago, so this is stated rather than assumed
    /// (`05 §3.3`).
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    /// Required, with no default. `05 §4.1` insists and the insistence is
    /// right: a command with no timeout on a machine an agent cannot see is a
    /// hang nobody notices.
    pub timeout: Duration,
    pub stdin: Option<Bytes>,
    /// Above this, output is truncated and the agent is TOLD how much went
    /// (`00 R24`). Never dropped silently.
    pub max_output_bytes: Option<u64>,
}

/// What a `tune` is changing.
///
/// Every field optional, and a `tune` with all three empty is a no-op the
/// plane refuses rather than sends, because an intent that changes nothing
/// still consumes a lease and a settlement.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Tuning {
    pub quality: Option<QualityPreset>,
    pub view_only: Option<bool>,
    /// A resize request. In PIXELS on a limb whose grounding is pixels and in
    /// CELLS on one whose grounding is cells, lowering to `RequestResize` or
    /// `ResizeTerminal` respectively. The unit split is already in the tree
    /// with its reason written down (`crates/remote-core/src/commands.rs:84`)
    /// and this intent inherits it rather than inventing a third unit.
    pub size: Option<(u16, u16)>,
}

/// The intents themselves.
///
/// Eighteen. Every one has a capability (`limb_core::capabilities_for`), a
/// lease requirement ([`IntentKind::needs_control_lease`]) and a `Support`
/// value on every limb kind that exists (`limb_core::Limb::supports`). No cell
/// is blank, which is `02 AC-3`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IntentKind {
    /// Type a string. Keysyms only, never a scancode, and
    /// `limb_core::keys::lower_type` is where that is enforced and argued.
    ///
    /// `wpm` throttles the run. It is not politeness: a remote machine that
    /// drops characters under a fast synthetic type does it silently, because
    /// neither an RFB KeyEvent nor an RDP fast path input event carries an
    /// acknowledgement (`06 §2.5`).
    Type { text: String, wpm: Option<u16> },
    /// Press a named key, or a chord of them.
    ///
    /// Resolved keys, not strings. A name outside [`crate::keys::NAMED_KEYS`]
    /// cannot be turned into a [`NamedKey`], so an unknown key is refused
    /// where the caller's string is parsed rather than three layers down
    /// where the refusal has lost its context.
    Press { keys: Vec<&'static NamedKey> },
    /// Put a raw XT scancode on the wire. Needs
    /// `limb_core::Capability::Scancode`, which is in no bundle.
    Scancode { code: u32, down: bool },
    /// Move the pointer without pressing anything.
    ///
    /// Added by `00 R44`. It is an ACTION and not an observation, and the
    /// distinction matters because the side effects are real: hover opens
    /// menus and fires handlers. It needs `control` and a lease for exactly
    /// that reason.
    Move { to: Point },
    /// Move, press, release, at a point.
    Click {
        at: Point,
        button: Button,
        /// One for a single click, two for a double. Above two is refused: no
        /// toolkit agrees on what a triple click means and the remote's double
        /// click interval is something we cannot query (`15 §4.1`).
        count: u8,
        /// Modifiers held for the duration, as named keys.
        modifiers: Vec<&'static NamedKey>,
    },
    /// Press at one point, travel, release at another. Atomic, and `15 §4.5`
    /// owns what happens when it is interrupted: a drag released at an
    /// arbitrary point is not a cancelled drag, it is a COMPLETED drag to the
    /// wrong place, and a file may have moved.
    Drag {
        from: Point,
        to: Point,
        button: Button,
    },
    /// Turn the wheel.
    Scroll {
        at: Point,
        direction: ScrollDirection,
        clicks: u8,
    },
    /// Wait for a condition. Never reaches a limb: the plane holds the mirror
    /// and the damage stream and evaluates it itself.
    Wait {
        until: WaitUntil,
        quiet: Option<Duration>,
        timeout: Option<Duration>,
    },
    /// Read the screen, the grid or the structure.
    ReadScreen {
        form: ReadForm,
        region: Option<Rect>,
    },
    /// Photograph it.
    Capture {
        form: CaptureForm,
        region: Option<Rect>,
        scale: Option<f32>,
    },
    /// Run a command on a channel of its own, with a real exit status.
    Exec { spec: CommandSpec },
    /// Run a command on the PTY the person is watching.
    PtyRun { spec: CommandSpec },
    /// State the working directory and environment subsequent commands should
    /// assume. `05 §4.1`'s declared state, which exists because a second SSH
    /// channel inherits nothing.
    Declare {
        cwd: Option<String>,
        env: Vec<(String, String)>,
    },
    /// Bytes straight into the PTY.
    SendBytes { bytes: Bytes },
    /// Read the remote clipboard.
    ClipboardGet,
    /// Write it.
    ClipboardSet { text: String },
    /// Change quality, view only, or size.
    Tune { tuning: Tuning },
    /// Withdraw an earlier intent.
    ///
    /// Needs no capability. Withdrawing your own request is not a privilege,
    /// and gating it would mean an agent that has lost a capability mid task
    /// cannot stop the work it already started.
    Cancel { target: IntentId },
}

impl IntentKind {
    /// The fieldless name of this intent.
    pub const fn name(&self) -> IntentName {
        match self {
            IntentKind::Type { .. } => IntentName::Type,
            IntentKind::Press { .. } => IntentName::Press,
            IntentKind::Scancode { .. } => IntentName::Scancode,
            IntentKind::Move { .. } => IntentName::Move,
            IntentKind::Click { .. } => IntentName::Click,
            IntentKind::Drag { .. } => IntentName::Drag,
            IntentKind::Scroll { .. } => IntentName::Scroll,
            IntentKind::Wait { .. } => IntentName::Wait,
            IntentKind::ReadScreen { .. } => IntentName::ReadScreen,
            IntentKind::Capture { .. } => IntentName::Capture,
            IntentKind::Exec { .. } => IntentName::Exec,
            IntentKind::PtyRun { .. } => IntentName::PtyRun,
            IntentKind::Declare { .. } => IntentName::Declare,
            IntentKind::SendBytes { .. } => IntentName::SendBytes,
            IntentKind::ClipboardGet => IntentName::ClipboardGet,
            IntentKind::ClipboardSet { .. } => IntentName::ClipboardSet,
            IntentKind::Tune { .. } => IntentName::Tune,
            IntentKind::Cancel { .. } => IntentName::Cancel,
        }
    }

    /// Does this intent aim at a coordinate, and therefore need a geometry
    /// fence?
    ///
    /// The four pointer intents, and nothing else. The line is drawn at
    /// actuation rather than at "carries a rectangle" on purpose: a
    /// `read_screen` whose region was computed against an old generation reads
    /// the wrong rectangle, which costs a wasted call and is repaired by
    /// looking again, while a `click` computed against an old generation
    /// presses a button the agent did not choose, and there is no repair for
    /// that. The plane intersects a stale region with the current framebuffer;
    /// it refuses a stale click (`00 R10`).
    pub const fn is_grounded(&self) -> bool {
        matches!(
            self,
            IntentKind::Move { .. }
                | IntentKind::Click { .. }
                | IntentKind::Drag { .. }
                | IntentKind::Scroll { .. }
        )
    }

    /// Must the asking grant hold the control lease?
    ///
    /// The `L` column of `02 §2.4`. Everything that drives, plus the two that
    /// execute, plus the bytes that reach a PTY. Reading never does, because
    /// a watcher and a driver can coexist and `08` is built on their being
    /// able to.
    pub const fn needs_control_lease(&self) -> bool {
        matches!(
            self,
            IntentKind::Type { .. }
                | IntentKind::Press { .. }
                | IntentKind::Scancode { .. }
                | IntentKind::Move { .. }
                | IntentKind::Click { .. }
                | IntentKind::Drag { .. }
                | IntentKind::Scroll { .. }
                | IntentKind::Exec { .. }
                | IntentKind::PtyRun { .. }
                | IntentKind::SendBytes { .. }
                | IntentKind::Tune { .. }
        )
    }
}

impl AgentIntent {
    /// Decline this intent, with a sentence saying why.
    ///
    /// The only way a driver may say no. `00 R28` forbids the other way, and
    /// the arm this replaces is a real one: `ssh-core`'s command pump ends in
    /// `_ => continue`, which drops whatever it does not recognise without a
    /// word. For a quality preset the shell fans out to every session that is
    /// right. For an intent it is the failure the whole design is built to
    /// avoid, because the agent is not watching a screen, it is waiting for an
    /// answer, and a drop makes it wait forever.
    ///
    /// Carried to the shell as
    /// [`SessionEvent::AgentRefused`](crate::events::SessionEvent::AgentRefused).
    pub fn refuse(&self, reason: impl Into<String>) -> IntentRefused {
        IntentRefused {
            id: self.id,
            name: self.kind.name(),
            reason: reason.into(),
        }
    }

    /// Answer this intent with what serving it produced.
    ///
    /// The other half of [`AgentIntent::refuse`], and `00 R51b` is the hole it
    /// closes: there was a way for a driver to say no and none at all to say
    /// yes, so serving an intent and settling one were different things and
    /// only the first was possible. A driver that did the work waited out the
    /// deadline and settled as a timeout, which reads to an agent exactly like
    /// a driver that never answered.
    ///
    /// Carried to the shell as
    /// [`SessionEvent::AgentServed`](crate::events::SessionEvent::AgentServed).
    pub fn serve(&self, answer: ServedAnswer) -> IntentServed {
        IntentServed {
            id: self.id,
            name: self.kind.name(),
            answer,
        }
    }
}

/// An intent reached a driver that will not serve it, and NOTHING went on the
/// wire.
///
/// A refusal, never an error. The distinction is `04 §4.3`'s and it is the
/// same one a timeout gets: an agent handed an error for something the limb
/// simply does not do will treat a working machine as a broken one. This says
/// "not here", which is a fact the agent can plan around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRefused {
    pub id: IntentId,
    /// The intent's name, carried rather than looked up. A reader of a log
    /// line or a trace span does not hold the plane's in flight table, and a
    /// refusal that only says "id 41" is a refusal nobody can act on.
    pub name: IntentName,
    /// For the agent, not for a person: it says what the limb cannot do, so
    /// the next intent can be a different one. Never rendered as HTML.
    pub reason: String,
}

impl std::fmt::Display for IntentRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "intent {} ({}) refused: {}",
            self.id, self.name, self.reason
        )
    }
}

/// Which tier produced a command's exit status.
///
/// The mirror of `limb_core::observation::ExitSource`, and it is a mirror
/// rather than the type itself because of the same cycle `00 R47a` records:
/// `limb-core` depends on `remote-core`, so a driver's answer travelling on
/// `SessionEvent` cannot name a `limb-core` type. The plane converts one into
/// the other in exactly one place (`agent_plane::dispatch`), so the two lists
/// are kept in step by a compile error rather than by memory.
///
/// The tiers are `05 §3`'s and they are not equivalent, which is why the value
/// travels with the number rather than being implied by it. Same rule
/// `RttSource` already sets for round trip time
/// (`crates/remote-core/src/stats.rs:9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitTier {
    /// A second SSH channel with `exec`. The far side's own `exit-status`
    /// (RFC 4254 §6.10), delivered by the SSH server. Nothing about `PS1`,
    /// locale or shell dialect can corrupt it, which is why `00 R7` made this
    /// tier the default.
    Exec,
    /// The shell's own OSC 133 prompt marking, where it is configured.
    Osc133,
    /// A sentinel echoed after the command on the interactive PTY.
    Sentinel,
    /// Our own helper on the far side.
    Helper,
}

/// Why a run came back with no exit code and no signal.
///
/// `00 R7` and `05 R5.10`: **nothing here invents an exit code.** There is no
/// default of 0 and no default of 1, and a signal is never coerced into
/// `128 + signum`. A tier that cannot answer says which of these three
/// happened, and the plane turns that into the settlement the agent reads
/// rather than into a number nobody measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unanswered {
    /// The command's own deadline passed while it was still running. What
    /// happens to the process afterwards is on [`CommandRun::stdout`]'s doc
    /// comment: the driver asks for it to stop and cannot promise it did.
    Deadline,
    /// The link went away mid run. The command may well have finished on the
    /// far side; we were not there to hear it.
    LinkLost,
    /// The tier that ran this cannot report a status at all. The command ran
    /// and ended, and how it ended is not knowable from here.
    Tier,
}

impl Unanswered {
    /// The sentence an agent reads beside the missing number.
    pub const fn as_str(self) -> &'static str {
        match self {
            Unanswered::Deadline => {
                "the deadline passed while the command was still running, so there is no exit status: the command was asked to stop and may still be running on the far side"
            }
            Unanswered::LinkLost => {
                "the link went away before the far side reported an exit status: the command may have finished anyway"
            }
            Unanswered::Tier => {
                "the tier that ran this command cannot report an exit status, so there is none rather than a guessed one"
            }
        }
    }
}

impl std::fmt::Display for Unanswered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a command ended, with the provenance rather than just the number.
///
/// The mirror of `limb_core::observation::ExitStatus`, minus one field and
/// plus one, and both differences are deliberate.
///
/// **No `confidence`.** How much a status is worth is a property of the TIER
/// and not of the run: an `exit-status` off the wire is exact whoever read it,
/// and a sentinel echoed at a prompt is reported whoever read it. Writing it
/// once at the conversion means a driver cannot get it wrong, and it is what
/// keeps `limb-core`'s rule that `Confidence::Inferred` never appears on an
/// exit status true by construction.
///
/// **A `unanswered`.** `limb-core`'s shape has nowhere for a driver to say why
/// there is no number, because by the time the plane has it the answer has
/// become the settlement's [`Unanswered`] outcome instead. This is where the
/// driver says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExit {
    /// `None` when a signal killed the process, and `None` when
    /// [`CommandExit::unanswered`] says the tier could not answer. Never a
    /// stand in for either.
    pub code: Option<i32>,
    /// RFC 4254 §6.10's `exit-signal`, verbatim and without the `SIG` prefix
    /// the wire omits. **Never coerced into `code`**: `128 + signum` is a
    /// shell's convention for reporting a signal through a byte wide exit
    /// status, and this answer is neither a byte nor a shell's.
    pub signal: Option<String>,
    pub source: ExitTier,
    /// Set only when there is no code and no signal.
    pub unanswered: Option<Unanswered>,
}

impl CommandExit {
    /// A real exit code from the far side.
    pub fn code(source: ExitTier, code: i32) -> Self {
        CommandExit {
            code: Some(code),
            signal: None,
            source,
            unanswered: None,
        }
    }

    /// Killed by a signal. The number is not converted, because there is no
    /// honest conversion (`00 R7`).
    ///
    /// RFC 4254 §6.10's `error_message` beside the signal is not carried. It is
    /// a human readable line the far side MAY send and OpenSSH sends empty, and
    /// `limb-core`'s exit status has nowhere to put it, so carrying it here
    /// would only mean dropping it one layer further on. A driver that receives
    /// one logs it.
    pub fn signal(source: ExitTier, signal: impl Into<String>) -> Self {
        CommandExit {
            code: None,
            signal: Some(signal.into()),
            source,
            unanswered: None,
        }
    }

    /// No answer, and why.
    pub fn unanswered(source: ExitTier, why: Unanswered) -> Self {
        CommandExit {
            code: None,
            signal: None,
            source,
            unanswered: Some(why),
        }
    }

    /// Did the far side actually say how this ended?
    pub fn answered(&self) -> bool {
        self.unanswered.is_none()
    }
}

/// How much output was dropped on one stream, and how much of it was lines.
///
/// Bytes and lines both, because they answer different questions: an agent
/// deciding whether to re-run with a narrower command wants the bytes, and one
/// deciding whether the tail it received is the tail it wanted needs to know
/// how many lines it did not see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dropped {
    pub bytes: u64,
    pub lines: u64,
}

impl Dropped {
    pub fn any(&self) -> bool {
        self.bytes > 0
    }
}

/// What a run's output cap cost it (`00 R24`).
///
/// Present on every answer, including the ones that dropped nothing, so that
/// "nothing was dropped" is a fact the agent was TOLD rather than a silence it
/// has to read as good news.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Truncation {
    /// The cap that was applied, per stream, in bytes. Reported whether or not
    /// it bit, because an agent that knows the cap can ask for a narrower
    /// command instead of the same one again.
    pub cap: u64,
    pub stdout: Dropped,
    pub stderr: Dropped,
}

impl Truncation {
    pub fn any(&self) -> bool {
        self.stdout.any() || self.stderr.any()
    }
}

/// One command that ran, with the five things `05 §4.1` requires of an answer:
/// stdout, stderr, an exit status, a duration and a truncation record.
///
/// `stdout` and `stderr` are separate because that is one of the five, and a
/// tier that cannot separate them is a tier that does not serve this intent.
/// Both are REMOTE CONTENT: data, never instruction (`AGENT_BRIEF` D6). They
/// travel bare here because nothing between the driver and the plane can act
/// on them; the plane wraps them in `limb_core::observation::Untrusted` at the
/// point where somebody could.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRun {
    pub status: CommandExit,
    pub stdout: Bytes,
    pub stderr: Bytes,
    /// How much never made it into the two fields above.
    pub dropped: Truncation,
    /// Wall clock, measured around the run by the driver that ran it.
    pub duration: Duration,
}

/// What a driver did about an intent it SERVED.
///
/// One variant, and a variant rather than a bare [`CommandRun`] because the
/// other natively served intents (`declare`, and a `pty_run` that is answered
/// rather than refused) will each want their own answer shape, and an enum is
/// where the reader is made to decide what a new one means.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServedAnswer {
    /// A command ran to a conclusion, whatever that conclusion was. A non zero
    /// exit is a served answer and not a failure to serve: the driver did
    /// exactly what it was asked, and the number is the news.
    Ran(CommandRun),
}

/// An intent reached a driver that SERVED it, and here is the answer.
///
/// The counterpart of [`IntentRefused`], and `00 R51b` is the gap it fills.
/// Before it there was a way for a driver to say no and no way at all to say
/// yes, so a driver that genuinely served an intent settled as
/// `Outcome::TimedOut` once the deadline passed, and the first driver to
/// implement a native intent looked exactly like a driver that had failed.
///
/// Carried to the shell as
/// [`SessionEvent::AgentServed`](crate::events::SessionEvent::AgentServed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentServed {
    pub id: IntentId,
    /// The intent's name, carried for [`IntentRefused::name`]'s reason: a log
    /// line or a trace span that only says "id 41" is one nobody can act on.
    pub name: IntentName,
    pub answer: ServedAnswer,
}

impl std::fmt::Display for IntentServed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the output. What a remote machine printed is data, and a log
        // line is a second delivery path into a model: an agent asked to read
        // the application's own log would find whatever was planted there.
        // Lengths and a status are not content.
        match &self.answer {
            ServedAnswer::Ran(run) => write!(
                f,
                "intent {} ({}) served: {} in {} ms, {} bytes out, {} bytes err{}",
                self.id,
                self.name,
                match (&run.status.code, &run.status.signal, run.status.unanswered) {
                    (Some(code), _, _) => format!("exit {code}"),
                    (_, Some(signal), _) => format!("killed by {signal}"),
                    (_, _, Some(why)) => format!("no exit status ({why})"),
                    _ => "no exit status".to_string(),
                },
                run.duration.as_millis(),
                run.stdout.len(),
                run.stderr.len(),
                if run.dropped.any() {
                    format!(
                        ", {} bytes dropped past the {} byte cap",
                        run.dropped.stdout.bytes + run.dropped.stderr.bytes,
                        run.dropped.cap
                    )
                } else {
                    String::new()
                },
            ),
        }
    }
}
