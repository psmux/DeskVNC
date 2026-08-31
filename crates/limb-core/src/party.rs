//! Who asked, and who took the wheel.
//!
//! Two names and nothing else. Both are defined by `agent-lease`, which owns
//! arbitration (`08 §5`), and both are re-exported here rather than redefined,
//! for the reason `SessionEntry` reads its protocol off the handle instead of
//! storing it a second time: "the two can never disagree"
//! (`src-tauri/src/state.rs:242`). A limb contract carrying its own idea of
//! what a grant is would be a second source of truth for the identity every
//! audit line is keyed on.
//!
//! This is the whole of the coupling between the two crates. If `agent-lease`
//! renames either name, exactly this file changes.

/// Which party asked. Minted by the plane at approval and stable across a
/// reconnect of the attachment (`02 §4.5`), which is what makes an observation
/// routable back to one agent after a drop.
///
/// `agent-lease` calls it `PartyId` because arbitration genuinely cannot tell
/// a grant from a window label and must not try: it holds "a grant id, or a
/// window label" and never learns which. On an intent the answer is always a
/// grant, since a window does not send intents, which is why `02 §2.2` calls
/// the field `grant` and spells the type [`GrantId`].
pub use agent_lease::PartyId;

/// What `02` calls the identity on an intent envelope, and `04 §5.3` spells
/// `att_…` on the wire.
///
/// An alias rather than a newtype. A newtype would have to be converted at
/// every boundary with `agent-lease`, and a conversion that exists only to
/// satisfy two names for one thing is a place for the two to drift.
pub type GrantId = PartyId;

/// Whether the party that took a limb was a person, an agent, or the shell
/// acting on a person's behalf.
///
/// It appears in this crate in exactly one place,
/// [`Outcome::Superseded`](crate::observation::Outcome::Superseded), and that
/// placement is the point: an agent that was preempted needs to know whether a
/// person took the wheel, because `15 §2.2` requires the model to get one
/// decision right and only one, and the decision is "a person is driving,
/// stop, do not reacquire".
pub use agent_lease::HolderKind;
