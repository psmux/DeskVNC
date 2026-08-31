//! Refusals, and the one place a plane refusal is turned into an
//! [`Outcome`] an agent can read.
//!
//! Two types, and the split between them is the whole of `00 R7` and `00 R28`
//! in this crate.
//!
//! [`Refusal`] answers an INTENT. `ssh-core`'s command pump ends in
//! `_ => continue` (`crates/ssh-core/src/driver.rs:136`), which is right for a
//! UI, where a quality preset sent to a terminal is noise, and is the worst
//! failure this design can have for an agent: the intent vanishes with no
//! error and the agent does not retry, it WAITS. So every intent this crate is
//! handed produces a settlement, and an intent nothing can serve produces a
//! refusal with a sentence in it rather than silence.
//!
//! [`PlaneError`] answers a PLANE OPERATION: attaching a limb, detaching one,
//! asking for the lease. Those are not intents, nothing is waiting on a
//! settlement for them, and a `Result` is the ordinary Rust shape for a call
//! that can be told no.

use limb_core::identity::{LimbIdError, SlotRefused};
use limb_core::observation::{Outcome, RefusalCode};

/// Why an intent was refused before, or part way through, reaching the wire.
///
/// `02 §3.4`'s [`RefusalCode`] is the canonical set and it is
/// `#[non_exhaustive]`, so this crate cannot add to it. Five of the refusals
/// the runtime genuinely has to make are not in that set, which is a real gap
/// rather than a shortcoming of this file: `08 §4.6` names `intent_blocked`,
/// `intent_in_flight`, `limb_gone` and `observations_overrun` as wire level
/// errors, and `09 §2` names the host check, and `02 §3.4` predates all five.
///
/// So the precise name lives here and travels beside the settlement, while
/// [`RefusalReason::code`] maps it onto the nearest member of the canonical
/// set for a consumer that matches on `02`'s vocabulary. The mapping is
/// written once, here, with the reason for each choice, rather than at each
/// call site where it would drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// One of `02 §3.4`'s eleven, used verbatim.
    Limb(RefusalCode),
    /// The grant does not name the host this limb addresses (`00 R19`,
    /// `09 §2`).
    ///
    /// This is the control that does not depend on recognising an injection.
    /// An injection saying "connect to the domain controller and run this"
    /// dies here, before the model's decision reaches a socket.
    HostNotInGrant,
    /// This grant already has a batch dispatching on this limb (`08 §7.3`).
    ///
    /// Not implementation convenience: two concurrent batches to one limb have
    /// no defined interleaving, and an agent that believes it typed `hello`
    /// and then `world` would get either, or a mix, and could not tell which.
    IntentInFlight,
    /// The session channel stayed full for
    /// [`crate::config::PlaneConfig::intent_block_ms`] (`08 §4.6`).
    IntentBlocked,
    /// The limb reports this intent as [`limb_core::Support::Native`], which
    /// means the driver expects to receive it as `ClientCommand::Agent`, and
    /// that variant does not exist.
    ///
    /// `00 R28` rules that `ClientCommand::Agent(AgentIntent)` wraps the agent
    /// vocabulary. `crates/remote-core/src/commands.rs` has no such variant
    /// today, so there is no way to put an agent intent into a session, and
    /// the plane refuses rather than pretending. This is the same treatment
    /// `00 R47a` gives the `ProtocolDriver::limb` accessor: owed, named, and
    /// not designed away.
    NoNativeVariant,
    /// The session behind the limb ended.
    LimbGone,
}

impl RefusalReason {
    /// The identifier an agent matches on, in capitals, following `06 §5.5`:
    /// a model that has to parse prose to find out what happened will parse it
    /// wrong on the day the prose is edited.
    pub const fn as_str(self) -> &'static str {
        match self {
            RefusalReason::Limb(code) => code.as_str(),
            RefusalReason::HostNotInGrant => "HOST_NOT_IN_GRANT",
            RefusalReason::IntentInFlight => "INTENT_IN_FLIGHT",
            RefusalReason::IntentBlocked => "INTENT_BLOCKED",
            RefusalReason::NoNativeVariant => "NO_NATIVE_VARIANT",
            RefusalReason::LimbGone => "LIMB_GONE",
        }
    }

    /// The nearest member of `02 §3.4`'s canonical set.
    ///
    /// Each mapping is a judgement and each is written down:
    ///
    /// * a grant that does not name a host carries no authority over it, which
    ///   is what `MISSING_CAPABILITY` says;
    /// * both queue refusals are the agent being asked to slow down, which is
    ///   what `RATE_LIMITED` says, and both carry a sentence saying which;
    /// * a driver expecting a wire variant that does not exist cannot serve
    ///   the intent, which is `NOT_SUPPORTED`;
    /// * a session that ended is not ready and will not become ready, and
    ///   `NOT_READY` is the code an agent already backs off on.
    pub const fn code(self) -> RefusalCode {
        match self {
            RefusalReason::Limb(code) => code,
            RefusalReason::HostNotInGrant => RefusalCode::MissingCapability,
            RefusalReason::IntentInFlight | RefusalReason::IntentBlocked => {
                RefusalCode::RateLimited
            }
            RefusalReason::NoNativeVariant => RefusalCode::NotSupported,
            RefusalReason::LimbGone => RefusalCode::NotReady,
        }
    }
}

impl std::fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serialised as the code string and nothing else.
///
/// Hand written rather than derived for two reasons that both matter. The
/// first is mechanical: `02 §3.4`'s [`RefusalCode`] does not derive
/// `Serialize`, deliberately, because `limb-core` carries a hand written
/// exhaustive match beside `event_json` so a new variant is a compile error
/// where somebody has to decide what an agent sees.
///
/// The second is the contract. A derived enum would emit
/// `{"limb": "geometry_changed"}` for one half of this type and a bare string
/// for the other, so a consumer would have to know which half it was looking
/// at before it could read the code. `06 §5.5` wants the code first and in
/// capitals, and a model that has to parse a shape to find it will parse it
/// wrong on the day the shape is edited.
impl serde::Serialize for RefusalReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// A refusal with the sentence an agent reads beside the code it matches on.
///
/// Not an error type. It is an ANSWER, and it becomes
/// [`Outcome::Refused`] on the way to the agent. Making it a `std::error::Error`
/// would invite a `?` somewhere that turned an answer into a failure and lost
/// the settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: RefusalReason,
    /// Shown to the agent verbatim. A sentence, never a code: an agent told
    /// "no" learns nothing, an agent told "a PTY has no pointer, use type"
    /// stops asking.
    pub because: String,
}

impl Refusal {
    /// A refusal with one of `02 §3.4`'s codes.
    pub fn limb(code: RefusalCode, because: impl Into<String>) -> Refusal {
        Refusal {
            reason: RefusalReason::Limb(code),
            because: because.into(),
        }
    }

    /// A refusal with one of the plane's own reasons.
    pub fn plane(reason: RefusalReason, because: impl Into<String>) -> Refusal {
        Refusal {
            reason,
            because: because.into(),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.because)
    }
}

impl From<Refusal> for Outcome {
    fn from(refusal: Refusal) -> Outcome {
        Outcome::Refused {
            because: refusal.because,
            code: refusal.reason.code(),
        }
    }
}

/// A plane operation was refused.
///
/// Distinct from [`Refusal`] because nothing is waiting on a settlement for
/// these. An attach that fails has produced no limb and therefore no intent
/// and no observation stream, so there is nowhere for an `Outcome` to go.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlaneError {
    /// Admission control (`00 R21`). The honest claim is four concurrent
    /// driven limbs, and the refusal names the limit rather than degrading
    /// silently, because degrading silently presents as the user interface
    /// hanging and gets debugged somewhere else entirely.
    #[error(
        "this build drives {limit} limbs at once and {attached} are attached; detach one or raise max_driven_limbs, which is 4 because 08 §2's audit puts the single tokio runtime at the binding constraint and spike S2 has not measured otherwise"
    )]
    TooManyLimbs { limit: usize, attached: usize },

    /// `00 R19`. Resolved at issue time, no wildcard, no inheritance.
    #[error(
        "grant {grant} does not name host {host}; a grant names its hosts at issue time and there is no wildcard, so this limb cannot be attached"
    )]
    HostNotInGrant { grant: String, host: String },

    /// The grant does not carry the capability the operation costs.
    #[error("grant {grant} does not carry {}, which {operation} costs", .missing.join(", "))]
    MissingCapability {
        grant: String,
        operation: &'static str,
        missing: Vec<String>,
    },

    /// Nothing is attached under that id.
    #[error("no limb is attached as {id}")]
    NoSuchLimb { id: String },

    /// The derived id already names a different machine.
    ///
    /// Forty eight bits over the few hundred machines a person has is far past
    /// any birthday concern, and `LimbId::derive`'s own doc comment promises a
    /// collision is DETECTED rather than acted on. This is that promise kept:
    /// the plane holds the machine beside the id and compares before it
    /// attaches, so a collision is a refusal and never a wrong machine.
    #[error(
        "limb id {id} is already attached to a different machine; this is a 48 bit digest collision, so nothing was opened and nothing was reused"
    )]
    IdentityCollision { id: String },

    /// The protocol will not give this agent that slot (`00 R31`).
    #[error(transparent)]
    SlotRefused(#[from] SlotRefused),

    /// A caller sent something that is not a limb id.
    #[error(transparent)]
    BadLimbId(#[from] LimbIdError),

    /// Arbitration said no.
    #[error(transparent)]
    Lease(#[from] agent_lease::LeaseError),
}
