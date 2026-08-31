//! What an agent wants done.
//!
//! **This module moved.** Every type it used to define now lives in
//! [`remote_core::intent`] and is re-exported here, at its old path, so no
//! caller changed.
//!
//! `00 R47a` records why it had to. `ClientCommand::Agent(AgentIntent)` is
//! `00 R28`, and it could not be written while the intent vocabulary sat in
//! this crate: `limb-core` depends on `remote-core`, so `remote-core` naming
//! `AgentIntent` would be a cycle. Without the variant `agent-plane` answers
//! every natively served intent (`exec`, `pty_run`, `declare`) with
//! `NoNativeVariant`, which is `05`'s whole terminal command channel refused
//! at the door, and that is the modality agents work best in (`00 R9`).
//!
//! The way out was not a feature flag or a third crate. It was noticing that
//! this was never limb material. `remote-core` already owns the two protocol
//! neutral vocabularies, the commands a session is told and the events it
//! tells back; the intents an agent issues are a third of exactly the same
//! kind, and they belong beside them. What sits on TOP of them, the [`Limb`]
//! trait, [`capability`], [`identity`] and [`availability`], is what this
//! crate is for and none of it moved.
//!
//! The keysym versus scancode argument, and the lowering it defends, stayed in
//! [`crate::keys`]. Only [`NamedKey`] and its table went, because
//! [`IntentKind::Press`] holds `&'static NamedKey` and could not travel
//! without it.
//!
//! [`Limb`]: crate::limb::Limb
//! [`capability`]: crate::capability
//! [`identity`]: crate::identity
//! [`availability`]: crate::availability
//! [`NamedKey`]: crate::keys::NamedKey

pub use remote_core::intent::*;
