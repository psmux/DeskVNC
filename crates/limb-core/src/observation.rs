//! What a limb, or the plane, has to tell an agent.
//!
//! `00 R28` and `02 §3`. `SessionEvent` gains exactly one variant,
//! `Agent(Observation)`, and only observations a LIMB produces travel through
//! it. Everything the plane works out for itself (quiescence, a downscaled
//! frame off the mirror, a lease change, a degradation) is produced by the
//! plane directly and never enters `SessionEvent`, because `SessionEvent`
//! means "what the session said" and diluting that would make the tree's most
//! useful invariant vaguer. Both producers use the type below and both go
//! through the same hand written serialiser.
//!
//! `00 R28` also rules that these are NOT `ProtocolEvent::Ssh` variants. An
//! exit status, a truncation notice, a settled signal and an output chunk have
//! exactly the same shape on a Kubernetes exec stream and on an ADB shell, so
//! filing them under `Ssh` guarantees a second copy the first time a non SSH
//! limb needs them, which is the failure `remote-core` was extracted to
//! prevent. `ProtocolEvent` keeps what is genuinely one protocol's news:
//! `RdpEvent::LogonInfo`, `SshEvent::Attached`, and the multiplexer facts.
//!
//! Like `SessionEvent` and `ClientCommand`, nothing here derives `Serialize`.
//! The plane carries a hand written exhaustive match beside `event_json`, so a
//! new variant is a compile error where somebody has to decide what an agent
//! sees. [`Observation::variant_name`] is the same match written once, and the
//! test that walks one constructor per variant is what keeps a variant from
//! being added without a decision (`01 §5 I4`).

use crate::availability::SignalReport;
use crate::fence::{GeometryChange, GeometryGeneration, GeometryRejected};
use crate::identity::LimbId;
use crate::intent::{IntentId, Point};
use crate::limb::{Confidence, Degraded, QuiescenceSignal};
use crate::party::HolderKind;
use bytes::Bytes;
use remote_core::geometry::Rect;
use remote_core::stats::SessionStats;

/// Unix milliseconds, supplied by the plane.
///
/// Not read from the clock inside this crate. Every decision here is a pure
/// function of what it was handed, which is what makes the settlement rules
/// testable without a runtime, and it is the discipline `agent-lease` follows
/// for arbitration for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

/// A value that came off a remote machine.
///
/// `AGENT_BRIEF` D6: everything a remote screen or terminal says is data,
/// never instruction. This is the mechanism, in the type system.
///
/// There is no `Deref`, no `Display`, no `AsRef` and no `Serialize`. The only
/// way out is [`Untrusted::into_inner_untrusted`], whose name is the point: it
/// appears in a diff, it appears in a grep, and a reviewer who sees one can
/// ask what happens to the value next. A newtype that unwrapped implicitly
/// would be a comment with extra steps.
///
/// `Debug` prints the origin, the generation and the type, and NEVER the
/// content, because an untrusted payload in a log line is a second delivery
/// path into a model: an agent asked to read the application's own log finds
/// the injection there. [`Untrusted::preview`] exists for the case where a
/// human genuinely needs to see some of it, and it escapes control bytes.
///
/// Note what is not wrapped. `Damage`, `GeometryChanged` and `Degraded` are
/// our own arithmetic over our own event stream, and wrapping them would train
/// a reader to ignore the wrapper.
#[derive(Clone)]
pub struct Untrusted<T> {
    origin: LimbId,
    geometry_generation: GeometryGeneration,
    value: T,
}

impl<T> Untrusted<T> {
    /// Wrap something a remote machine produced.
    ///
    /// The generation travels with the payload because a payload outlives the
    /// geometry it was read against: a screenshot read at generation 7 and
    /// acted on at generation 8 is a misclick, and the only place that can be
    /// noticed is where the two numbers sit side by side.
    pub fn new(origin: LimbId, geometry_generation: GeometryGeneration, value: T) -> Self {
        Untrusted {
            origin,
            geometry_generation,
            value,
        }
    }

    /// Which limb said it.
    pub fn origin(&self) -> &LimbId {
        &self.origin
    }

    /// The geometry generation this payload was read at.
    pub fn geometry_generation(&self) -> GeometryGeneration {
        self.geometry_generation
    }

    /// Take the value out. The name is deliberately awkward.
    pub fn into_inner_untrusted(self) -> T {
        self.value
    }
}

impl<T: AsRef<[u8]>> Untrusted<T> {
    /// How much there is. Safe to log: a length is not content.
    pub fn bytes(&self) -> usize {
        self.value.as_ref().len()
    }

    /// At most `max` bytes, with everything outside printable ASCII escaped.
    ///
    /// For a human looking at a diagnostic, never for a model. The escaping is
    /// the load bearing part: a terminal that receives raw output from an
    /// untrusted machine can be driven with escape sequences, and a preview
    /// that passed them through would make the diagnostic itself an attack
    /// surface.
    pub fn preview(&self, max: usize) -> String {
        let slice = self.value.as_ref();
        let take = slice.len().min(max);
        let mut out = String::with_capacity(take);
        for &b in &slice[..take] {
            match b {
                b' '..=b'~' => out.push(b as char),
                _ => out.push_str(&format!("\\x{b:02x}")),
            }
        }
        if slice.len() > take {
            out.push_str(&format!("… ({} more bytes)", slice.len() - take));
        }
        out
    }
}

impl<T> std::fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Untrusted")
            .field("origin", &self.origin.as_str())
            .field("geometry_generation", &self.geometry_generation)
            .field("of", &std::any::type_name::<T>())
            .finish_non_exhaustive()
    }
}

/// Which stream a chunk came from.
///
/// A PTY merges stdout and stderr by construction, because both descriptors
/// point at the same terminal device, so [`Stream::Pty`] is its own value
/// rather than a lie about being stdout (`05 §3.2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
    Pty,
}

/// A block of command output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub bytes: Bytes,
    /// False when something was dropped. The amount is reported separately by
    /// [`Observation::Truncated`], because `00 R24` says the plane never drops
    /// output without saying how much it dropped, and a boolean alone does
    /// not say how much.
    pub complete: bool,
}

/// Where a command's exit status came from.
///
/// The four tiers of `05 §3`. They are not equivalent and the enum travels
/// with the number, which is the rule `RttSource` already sets for round trip
/// time (`crates/remote-core/src/stats.rs:9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitSource {
    /// A second SSH channel with `exec`. A real `exit-status` from the far
    /// side's operating system, delivered by the SSH server and not inferred.
    Exec,
    /// The shell's own OSC 133 prompt marking, where it is configured.
    Osc133,
    /// A sentinel echoed after the command on the interactive PTY.
    Sentinel,
    /// Our own helper on the far side.
    Helper,
}

/// How a command ended, with the provenance rather than just the number.
///
/// `05 R5.9`. A consumer that wants only trustworthy statuses filters on
/// [`Confidence::Exact`]; a consumer rendering to a human shows the source.
///
/// `05 R5.10`: **the plane never invents an exit code.** A timeout produces
/// `code: None` and `signal: None` with the tier that could not answer, and
/// the observation says how much output had arrived. There is no default of 0
/// and there is no default of 1. [`Confidence::Inferred`] never appears here:
/// a tier that cannot answer says it cannot answer, which is a `None` code,
/// not a guessed one with a hedge on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatus {
    /// `None` when the process was killed by a signal, or when the tier could
    /// not answer.
    pub code: Option<i32>,
    /// The signal name, never coerced into `code`.
    pub signal: Option<String>,
    pub source: ExitSource,
    pub confidence: Confidence,
}

/// What was seen while waiting, carried on a timeout so that the timeout is a
/// result rather than an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettleEvidence {
    /// Which instrument answered. A desktop's quiescence is inferred from
    /// damage rectangles the SERVER chose to send; a terminal's is the absence
    /// of bytes, which is exact about the wire and silent about whether the far
    /// side is thinking or wedged. Reporting both as "quiet" without saying
    /// which produced it is the mistake `RttSource` already refuses to make.
    pub signal: QuiescenceSignal,
    pub quiet_ms: u64,
    /// How many damage rectangles arrived. "Damage covers 90 percent" means
    /// something completely different at 2 rects than at 200.
    pub damage_rects: u32,
    /// How many bytes arrived, on a limb whose signal is output bytes.
    pub bytes: u64,
}

/// Whether an action's expected effect was observed.
///
/// `06 §5` calls this verified action and it is the thing this design should
/// push agents toward. A settle on its own is evidence and not confirmation;
/// acting and then asserting that a specific region changed composes a weak
/// signal with a strong expectation and gets a usable answer out of both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub outcome: VerifyOutcome,
    /// The region the caller said would change.
    pub region: Rect,
    pub confidence: Confidence,
}

/// `06 §5.5`'s outcomes, kept apart from "did it get delivered".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Changed,
    NoChange,
    /// Something changed and it was not the region the caller named. Worth its
    /// own value: it is the signature of a click that landed on the wrong
    /// control, which is a different repair from a click that did nothing.
    ChangedElsewhere,
    /// Too much was moving to tell. An honest answer and a common one on a
    /// desktop with a video playing or a progress bar running.
    BusyScreen,
}

/// How far an interrupted intent got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Progress {
    /// Nothing went.
    None,
    /// Code points actually put on the wire. The count a half typed string
    /// settles with, so an agent knows exactly what the far side received
    /// rather than having to read it back and guess.
    CodePoints(u32),
    /// A drag interrupted between the press and the release (`15 §4.5`).
    ///
    /// The fields exist because the model has to be told, in terms, that the
    /// drop happened somewhere it did not choose. A drag released at an
    /// arbitrary point is not a cancelled drag, it is a COMPLETED drag to the
    /// wrong place, and a file may have moved. There is no honest way to undo
    /// it and nothing above this should pretend there is.
    Drag {
        released_at: Point,
        points_delivered: u16,
        /// True when the plane synthesised the release rather than the drag
        /// reaching its own end. Spelled out rather than left to be inferred
        /// from the coordinates.
        release_synthesised: bool,
    },
    /// Commands or messages delivered, for the intents that are a run of them.
    Delivered(u32),
}

/// Why an intent was refused before anything went on the wire.
///
/// The code is what an agent matches on and the sentence beside it is what an
/// agent reads. `06 §5.5` puts the code first and in capitals for exactly that
/// reason: a model that has to parse prose to find out what happened will
/// parse it wrong on the day the prose is edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusalCode {
    /// This limb does not do this. The sentence comes from
    /// [`Support::Unsupported`](crate::limb::Support::Unsupported).
    NotSupported,
    /// The grant does not carry a capability this intent needs.
    MissingCapability,
    /// The control lease is held by somebody else, or by nobody.
    LeaseNotHeld,
    /// The session is not `Connected`. Carries the retry time where there is
    /// one, so an agent backs off rather than spinning.
    NotReady,
    /// The geometry moved under this action. [`GeometryRejected`].
    GeometryChanged,
    /// A coordinate intent arrived with no geometry generation.
    Unfenced,
    /// A coordinate outside the framebuffer. Rejected, never clamped: a
    /// clamped click lands on whatever is at the edge, which is a different
    /// action performed silently.
    OutOfBounds,
    /// A key name outside [`crate::keys::NAMED_KEYS`]. A numeric code is a
    /// different action and needs `scancode`.
    UnknownKey,
    /// The protocol will not give this agent that slot
    /// ([`crate::identity::SlotRefused`]).
    SlotRefused,
    /// Over one of [`LimbLimits`](crate::limb::LimbLimits)'s ceilings.
    RateLimited,
    /// Asked for something the wire cannot express, such as a scroll by
    /// pixels. Refused rather than served an invented conversion.
    NotExpressible,
}

impl RefusalCode {
    /// The identifier an agent matches on, in capitals, as `06 §5.5`
    /// specifies.
    pub const fn as_str(self) -> &'static str {
        match self {
            RefusalCode::NotSupported => "NOT_SUPPORTED",
            RefusalCode::MissingCapability => "MISSING_CAPABILITY",
            RefusalCode::LeaseNotHeld => "LEASE_NOT_HELD",
            RefusalCode::NotReady => "NOT_READY",
            RefusalCode::GeometryChanged => "GEOMETRY_CHANGED",
            RefusalCode::Unfenced => "UNFENCED",
            RefusalCode::OutOfBounds => "OUT_OF_BOUNDS",
            RefusalCode::UnknownKey => "UNKNOWN_KEY",
            RefusalCode::SlotRefused => "SLOT_REFUSED",
            RefusalCode::RateLimited => "RATE_LIMITED",
            RefusalCode::NotExpressible => "NOT_EXPRESSIBLE",
        }
    }
}

impl std::fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How an intent ended. One of these per `Accepted`, forever.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Delivered and, where the intent asked for verification, verified.
    ///
    /// `delivered` and `verified` are separate fields and neither is called
    /// success, which is `06 §5.4`'s rule. They answer different questions: we
    /// know what we put on the wire, and we do not know what the far side did
    /// with it, because neither an RFB KeyEvent nor an RDP fast path input
    /// event carries an acknowledgement.
    Done {
        delivered: bool,
        verified: Option<Verified>,
    },
    /// The deadline passed. An ORDINARY RESULT and not an error, carrying what
    /// was seen. An agent that gets an error for a timeout will treat a slow
    /// machine as a broken one.
    TimedOut { observed: SettleEvidence },
    /// A person, or a higher priority party, took the limb.
    Superseded { by: HolderKind, progress: Progress },
    /// The agent withdrew it.
    Cancelled,
    /// Refused before anything went on the wire.
    Refused { because: String, code: RefusalCode },
    /// The connection went away underneath it. The session may still be alive
    /// and reconnecting.
    ///
    /// Note what this does NOT claim. Bytes on a socket that is about to die
    /// may still have arrived, so an agent is told the intent may or may not
    /// have happened rather than being told it failed. `generation` is the one
    /// the intent was fenced against, which is now stale by definition.
    LinkLost { generation: GeometryGeneration },
}

impl From<GeometryRejected> for Outcome {
    /// A stale or missing fence becomes a refusal with the sentence the error
    /// already carries. The conversion lives here so that the plane cannot
    /// turn a fence rejection into anything softer on its way to the agent.
    fn from(rejected: GeometryRejected) -> Outcome {
        let code = match rejected {
            GeometryRejected::Stale { .. } => RefusalCode::GeometryChanged,
            GeometryRejected::Unfenced { .. } => RefusalCode::Unfenced,
        };
        Outcome::Refused {
            because: rejected.to_string(),
            code,
        }
    }
}

/// Where output was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncationPoint {
    Stdout,
    Stderr,
    Scrollback,
    Stream,
}

/// The stats a degradation was read off.
///
/// The whole tick rather than the one number, because the readings are only
/// interpretable together: high duty cycle with high throughput is a loaded
/// link, and high duty cycle with low throughput is a struggling server, and
/// `SessionStats::server_duty_cycle`'s own doc comment says it cannot tell
/// them apart alone (`crates/remote-core/src/stats.rs:44`).
#[derive(Debug, Clone, Copy)]
pub struct DegradeEvidence(pub SessionStats);

/// What a limb, or the plane, has to tell an agent.
///
/// Every variant carries the [`IntentId`] it answers, except the four that are
/// unsolicited, and those say so in their own doc comments. An agent that
/// receives an observation with an id it does not recognise has found a bug in
/// the plane, not a race: ids are minted by the plane and never reused.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Observation {
    /// The intent was accepted, the capability check passed, the lease was
    /// held, and something is on the wire. Not "it worked".
    Accepted { id: IntentId, at: Timestamp },

    /// The intent is over, exactly once, whatever happened.
    ///
    /// **Every `Accepted` is followed by exactly one `Settled`, and nothing
    /// else ends an intent.** Not a disconnect, not a lease loss, not a
    /// shutdown, not a limb close: each of those produces a `Settled` with the
    /// appropriate [`Outcome`] before anything else happens.
    ///
    /// This is a rule about the plane rather than about a limb, and it is
    /// stated here because it is the property an agent author will assume
    /// without checking. An intent that can end silently forces every agent to
    /// carry its own timeout for every call, which is the state of the art and
    /// it is miserable. The corollary is that a limb which cannot settle an
    /// intent must REFUSE it instead, which is what
    /// [`Support::Unsupported`](crate::limb::Support::Unsupported) is for and
    /// why [`Limb::supports`](crate::limb::Limb::supports) is a required
    /// method rather than a defaulted one.
    Settled {
        id: IntentId,
        outcome: Outcome,
        at: Timestamp,
    },

    /// The screen, the grid or the structure, as asked for.
    Read {
        id: IntentId,
        payload: Untrusted<Bytes>,
    },

    /// A command finished.
    Ran {
        id: IntentId,
        status: ExitStatus,
        stdout: Untrusted<Output>,
        stderr: Untrusted<Output>,
        duration_ms: u64,
    },

    /// Bytes from a limb that produces a stream rather than a result: a
    /// detached run, a PTY, a log follow. Many arrive per intent, so it is not
    /// a settlement.
    ///
    /// `dropped` is never allowed to be silent (`00 R24`).
    Chunk {
        id: IntentId,
        stream: Stream,
        bytes: Untrusted<Bytes>,
        dropped: u64,
    },

    /// The picture changed, with the damage union and the two numbers that
    /// make the union readable. Free: the run loop already computes it.
    ///
    /// Unsolicited, and carries no id: an agent subscribes to it rather than
    /// asking for it. `rect` is a union BOUNDING BOX and not a region list,
    /// and a handful of scattered rects can span the desktop, which is why
    /// `rects` is beside it.
    Damage {
        rect: Rect,
        rects: u32,
        coverage: f32,
        at: Timestamp,
    },

    /// The limb settled, by whatever instrument
    /// [`Limb::quiescence`](crate::limb::Limb::quiescence) named, with the
    /// confidence that instrument is worth.
    ///
    /// Named `Quiesced` rather than `02 §3.2`'s `Settled_`, which was a
    /// document artefact working around the collision with [`Observation::Settled`].
    /// They are genuinely different events: one ends an intent and one reports
    /// that a screen stopped moving, and an underscore is not enough to keep a
    /// reader from confusing them.
    Quiesced {
        id: IntentId,
        quiet_ms: u64,
        evidence: SettleEvidence,
        confidence: Confidence,
    },

    /// Anything an agent had cached about this limb's geometry is now void.
    ///
    /// Unsolicited. It must reach the agent BEFORE the state change out of
    /// `reconnecting`: an agent that sees `ready` and clicks before it sees
    /// this has clicked at a coordinate from the previous connection.
    GeometryChanged {
        geometry_generation: GeometryGeneration,
        why: GeometryChange,
    },

    /// Which negotiated signals this session has. Unsolicited, and emitted
    /// again whenever one resolves, because a signal that starts `unknown` and
    /// becomes `live` on the first `CopyRect` is a real change in what the
    /// agent can ask for (`00 R34`).
    Signals { report: SignalReport, at: Timestamp },

    /// The limb is usable but not well, or has stopped being so.
    ///
    /// Unsolicited. Deliberately not a new `SessionState` variant: that enum's
    /// serde representation is a contract with `ui/src/lib/types.ts`
    /// (`crates/remote-core/src/state.rs:5`) and adding a variant would change
    /// what every existing consumer sees. Degradation is an overlay the plane
    /// computes and tells an agent about, and a person is told nothing new
    /// because the UI already shows them the numbers.
    Degraded {
        now: Option<Degraded>,
        from: DegradeEvidence,
    },

    /// Output was dropped rather than the read failing. `05 §7` owns the
    /// policy; this is how an agent finds out, and it is never silent.
    Truncated {
        id: IntentId,
        dropped_bytes: u64,
        dropped_lines: u64,
        at: TruncationPoint,
    },
}

impl Observation {
    /// The variant's name, as one exhaustive match.
    ///
    /// This is the discipline of `02 §3.5` made available to the plane's
    /// serialiser and to the test that walks one constructor per variant. A
    /// variant added without a decision fails to compile here, and a variant
    /// added here without a constructor in the list fails the test.
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Observation::Accepted { .. } => "accepted",
            Observation::Settled { .. } => "settled",
            Observation::Read { .. } => "read",
            Observation::Ran { .. } => "ran",
            Observation::Chunk { .. } => "chunk",
            Observation::Damage { .. } => "damage",
            Observation::Quiesced { .. } => "quiesced",
            Observation::GeometryChanged { .. } => "geometry_changed",
            Observation::Signals { .. } => "signals",
            Observation::Degraded { .. } => "degraded",
            Observation::Truncated { .. } => "truncated",
        }
    }

    /// Which intent this answers, or `None` for the four unsolicited ones.
    pub const fn intent(&self) -> Option<IntentId> {
        match self {
            Observation::Accepted { id, .. }
            | Observation::Settled { id, .. }
            | Observation::Read { id, .. }
            | Observation::Ran { id, .. }
            | Observation::Chunk { id, .. }
            | Observation::Quiesced { id, .. }
            | Observation::Truncated { id, .. } => Some(*id),
            Observation::Damage { .. }
            | Observation::GeometryChanged { .. }
            | Observation::Signals { .. }
            | Observation::Degraded { .. } => None,
        }
    }
}
