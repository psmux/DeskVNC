//! # agent-plane
//!
//! The runtime. `limb-core` is vocabulary with no runtime, `agent-lease` is
//! arbitration with no clock, `agent-perception` is pixels with no transport,
//! and everything that spawns, sends or blocks lives here (`01 §3`). That
//! split is the reason the other three can be reasoned about at all, and it
//! means this crate is the one place where a mistake reaches a remote machine.
//!
//! Still no tauri. The shell adapts to this crate rather than the other way
//! round, which is what keeps a headless binary possible (`03 §1`).
//!
//! ## What it does
//!
//! | Module            | Responsibility                                          |
//! |-------------------|---------------------------------------------------------|
//! | [`config`]        | The numbers, including the four of `00 R21`              |
//! | [`grant`]         | What an attachment may do, and to which hosts            |
//! | [`registry`]      | [`LimbRegistry`], and both halves of slot semantics      |
//! | [`lowering`]      | [`AgentIntent`] to `ClientCommand`, pure                 |
//! | [`backpressure`]  | Bounded queues, the drop policy, and [`Gaps`]            |
//! | [`dispatch`]      | The wire, the lease fence, and one settlement per intent |
//! | [`perception`]    | The observation path, and the seam to `agent-perception` |
//! | [`error`]         | Refusals, and the plane's own error type                 |
//!
//! [`AgentIntent`]: limb_core::intent::AgentIntent
//!
//! ## The five rules a reader should know before changing anything
//!
//! **`00 R7` and `00 R28`. An intent is always answered.** Never dropped,
//! never silently succeeded. `ssh-core`'s command pump ends in
//! `_ => continue`, which is correct for a UI and is the worst failure this
//! design can have for an agent, because the agent does not retry, it waits.
//! Every path through [`AttachedLimb::dispatch`] produces a [`Settlement`].
//!
//! **`00 R8`. Typing is keysyms and never a scancode.** A scancode types what
//! the remote LAYOUT says that key is, so `a` becomes `q` on an AZERTY remote
//! and nothing anywhere reports an error. There is one keysym table in this
//! workspace, it is `limb_core::keys`, and this crate calls it.
//!
//! **`00 R11` and `00 B8`. Every lease change owes the limb a release, and it
//! is buttons before keys.** A zero mask pointer event goes first, then every
//! key. `agent-lease` hands the obligation back as data and a grant sits in
//! `HandingOver` until [`AttachedLimb::honour`] confirms it, so a caller that
//! ignores it gets a limb nobody can drive rather than a stuck Ctrl.
//!
//! **`00 R10`. Every actuation is fenced by the geometry generation.** A stale
//! fence is a typed rejection and nothing is delivered. A person's misclick is
//! corrected within 50 ms because a person is watching; an agent's is not,
//! because the agent is waiting for a result.
//!
//! **`08 §4`. Nothing is dropped silently.** The input path stays non blocking
//! and bounded, the drop policy is explicit and per command kind, and every
//! settlement carries [`Gaps`] saying what went and what did not.
//!
//! ## The clock
//!
//! [`agent_lease::LeaseInstant`] takes its origin from the caller and
//! [`limb_core::observation::Timestamp`] is unix milliseconds. This crate
//! passes both through untouched and never reads a clock for either, so a
//! caller that uses unix milliseconds as the lease origin gets two types that
//! agree, and a caller that does not gets two that are each internally
//! consistent. It matters only if somebody joins a trace on them, which
//! `10 §3` will want to.

// Nothing here touches a raw pointer and nothing here ever will, but every
// crate in this workspace that could carries the attribute and the consistency
// is worth more than the exception.
#![forbid(unsafe_code)]

pub mod backpressure;
pub mod config;
pub mod dispatch;
pub mod error;
pub mod grant;
pub mod lowering;
pub mod perception;
pub mod registry;

pub use backpressure::{Gaps, SendPolicy};
pub use config::{PlaneConfig, MAX_DRIVEN_LIMBS};
pub use dispatch::Settlement;
pub use error::{PlaneError, Refusal, RefusalReason};
pub use grant::{Grant, GrantError};
pub use lowering::{
    coalesce_settings, lower, pixel_scroll_refusal, release_sequence, LowerContext, Lowered, Step,
    StepMark,
};
pub use perception::{
    Damage, Frame, FrameSource, Observatory, PerceptionForm, PerceptionUnavailable,
};
pub use registry::{Attach, AttachedLimb, LimbRegistry};

pub use agent_lease;
/// The contract this runtime serves, re-exported so a caller needs one
/// dependency line rather than three. The same courtesy `limb-core` already
/// does for `remote-core`.
pub use limb_core;
