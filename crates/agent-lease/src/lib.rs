//! # agent-lease
//!
//! Control arbitration for the agent plane: who is driving a limb right now,
//! and what happens when somebody else wants the wheel.
//!
//! Specified in `PRDAgentPlug/08 §5` and `§6`, and by rulings R11, R12 and
//! R13 of `PRDAgentPlug/00-decision-log.md`. The shape and the priority
//! numbers are copied from BrowserGlass's `packages/core/src/control` rather
//! than invented, which `08 §5.2` argues for at length and which is the whole
//! reason "the human takes the wheel" needs no application code anywhere
//! above this crate.
//!
//! ## Why this is its own crate
//!
//! It is deliberately not part of `limb-core`. Arbitration is the part of the
//! plane most likely to be wrong in a way nobody notices until a person
//! cannot take a machine back from an agent, and it is the part easiest to
//! test to death provided nothing else is in the way. So there is no runtime
//! here, no socket, no protocol, and no idea what a limb, a framebuffer or a
//! keysym is. The dependencies are `serde`, because a pane and a trace both
//! render this state, and `thiserror`.
//!
//! ## The clock is an argument
//!
//! Nothing calls `Instant::now()`. Every rule that depends on time takes a
//! [`LeaseInstant`] from its caller, and [`Lease::tick`] is the only place
//! elapsed time is applied at all. See the note on [`clock`] for why it is a
//! millisecond newtype rather than `std::time::Instant`, and the note on
//! [`lease`] for the "tick, then act" discipline that follows from it.
//!
//! ## R11, which is the output that matters
//!
//! Every call that can change who is allowed to dispatch returns a
//! [`LeaseTransition`], and every transition carries a [`ReleaseObligation`].
//! This crate sends nothing; it hands back the obligation as data and the
//! plane above it owes the limb a release of held input before the new
//! holder's first intent. That is the plane's duty rather than the departing
//! holder's because an agent that crashed mid chord cannot release anything,
//! and that is precisely when a stuck Ctrl matters.
//!
//! The rule is stated once so that reading a call site never requires
//! working it out again: **the obligation is
//! [`ReleaseObligation::Required`] on every transition where the set of
//! parties allowed to dispatch changes.** The three exceptions are the calls
//! that change nothing, the calls that only touch the queue, and
//! [`Lease::confirm_release`], which is the caller reporting the obligation
//! discharged.
//!
//! That rule emits a redundant release in a couple of places, most obviously
//! when a called off preemption hands the wheel back to the party that never
//! lost it. The redundancy is chosen. A release is a small write on a channel
//! the plane already holds; a missed one is a modifier held down on a remote
//! machine, discovered by a person whose next keystroke turned into a
//! shortcut. There is no version of this trade where the cheap side is
//! sending fewer of them.
//!
//! ## Module map
//!
//! | Module         | Responsibility                                        |
//! |----------------|-------------------------------------------------------|
//! | [`clock`]      | [`LeaseInstant`], the injected clock                  |
//! | [`party`]      | The priority ladder, identities, the holder, a waiter |
//! | [`policy`]     | [`LeaseMode`] and the timers from `08 §5.4`           |
//! | [`transition`] | [`LeaseTransition`] and the R11 obligation            |
//! | [`error`]      | Refusals, each naming what the caller can do          |
//! | [`lease`]      | [`Lease`], the arbitration itself                     |
//!
//! Every public item is re-exported at the crate root, matching
//! `remote-core`, so call sites stay flat.

// This crate parses no remote bytes and touches no buffer, but every crate in
// this workspace that could carries the attribute and the consistency is
// worth more than the exception.
#![forbid(unsafe_code)]

pub mod clock;
pub mod error;
pub mod lease;
pub mod party;
pub mod policy;
pub mod transition;

pub use clock::{LeaseInstant, Millis};
pub use error::LeaseError;
pub use lease::{AcquireRequest, Lease};
pub use party::{Holder, HolderKind, LeaseId, LimbId, Party, PartyId, Waiter};
pub use policy::{LeaseConfig, LeaseMode, LeasePolicy};
pub use transition::{
    Departure, DepartureCause, Fencing, LeaseOutcome, LeasePhase, LeaseTransition, LeaseView,
    ReleaseObligation,
};
