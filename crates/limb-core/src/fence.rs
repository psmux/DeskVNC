//! The geometry generation, and why a stale actuation is a typed rejection.
//!
//! `00 R10`. Two authors found this defect from opposite directions, which is
//! what promoted it from a hypothesis to a finding. A `DesktopResize` arrives
//! and a pointer packet already in flight from `send_input` lands against the
//! NEW framebuffer. A person's next move corrects it within 50 ms because a
//! person is watching. An agent's does not, because the agent is not looking
//! at the screen, it is waiting for a result, and the click it just made
//! landed somewhere it did not choose.
//!
//! So a counter is bumped on every `SessionEvent::DesktopResize` and every
//! `SessionEvent::ScreenLayout` (`crates/remote-core/src/events.rs:96` and
//! `:106`), it rides every perception response, and every actuation computed
//! from that response carries it back. An actuation whose fence is behind the
//! counter is REFUSED and nothing is delivered.
//!
//! The reason this is a real type rather than a `u32` on a struct is that a
//! bare integer invites the comparison to be written at each call site, and
//! the comparison is the whole mechanism. There is one place it can be
//! written, [`GeometryFence::admit`], and getting past it produces a
//! [`GeometryRejected`] that the plane turns into a settlement an agent can
//! read.

use crate::intent::AgentIntent;
use remote_core::events::ScreenInfo;

/// The counter itself, re-exported at its old path.
///
/// It moved to [`remote_core::geometry`] because
/// [`AgentIntent::fence`](crate::intent::AgentIntent::fence) carries one and
/// the intent vocabulary had to reach the command side to make
/// `ClientCommand::Agent` writable (`00 R28`, `00 R47a`). Only the value
/// moved. [`GeometryFence`], which mints it, and [`GeometryFence::admit`],
/// which is the ONE place the comparison is written, both stayed: they are
/// this crate's live state and its rule, not vocabulary, and splitting the
/// rule from the value is how the comparison ends up rewritten at a call site.
pub use remote_core::geometry::GeometryGeneration;

/// Why the geometry changed. Carried on the unsolicited
/// [`Observation::GeometryChanged`] so an agent knows whether to re-read the
/// screen or to re-read everything.
///
/// [`Observation::GeometryChanged`]: crate::observation::Observation::GeometryChanged
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeometryChange {
    /// The remote desktop changed resolution.
    DesktopResize { width: u16, height: u16 },
    /// The monitor layout changed. Carries the new list verbatim, because an
    /// agent that has to make a second call to find out what changed will
    /// act on the old layout first.
    ScreenLayout { screens: Vec<ScreenInfo> },
    /// The terminal changed size, in character cells. A separate variant from
    /// [`GeometryChange::DesktopResize`] for the reason
    /// `ClientCommand::ResizeTerminal` is a separate command: 80 columns is
    /// not 80 pixels and nothing in the type system would catch the mix up
    /// (`crates/remote-core/src/commands.rs:84`).
    TerminalResize { cols: u16, rows: u16 },
    /// The link came back. The size may be identical and the generation still
    /// increments, because an RDP reconnect may land in a different Windows
    /// session, a locked desktop looks nothing like the one the agent was
    /// working on, and a screensaver may have started (`02 §4.6`). A
    /// coordinate from before the drop is not usable and the agent has to be
    /// told in a way it cannot miss.
    Reconnected,
}

/// One limb's live counter, held by the plane.
///
/// Not `Clone` and not `Copy`. There is one of these per limb and a copy of it
/// would be a second opinion about which generation is current, which is the
/// bug the counter exists to prevent, one level up.
#[derive(Debug)]
pub struct GeometryFence {
    current: GeometryGeneration,
}

impl GeometryFence {
    /// A fence for a limb that has just reached `Connected` for the first
    /// time.
    pub fn new() -> Self {
        GeometryFence {
            current: GeometryGeneration::FIRST,
        }
    }

    /// What an observation assembled right now would carry.
    pub fn current(&self) -> GeometryGeneration {
        self.current
    }

    /// Bump, and return the new value along with what to tell the agent.
    ///
    /// Returns the change rather than swallowing it so that the caller cannot
    /// bump the counter without emitting the notice. `02 §6.2` requires the
    /// notice to reach the agent BEFORE the state change out of
    /// `reconnecting`: an agent that sees `ready` and clicks before it sees
    /// the geometry notice has clicked at a coordinate from the previous
    /// connection.
    pub fn changed(&mut self, why: GeometryChange) -> (GeometryGeneration, GeometryChange) {
        // Saturating rather than wrapping, and the saturation lives on the
        // type now. A limb that has resized four billion times is not a real
        // situation, and a wrap would silently start admitting stale fences
        // again, which is worse than a counter that sticks at the top and
        // refuses everything computed before it.
        self.current = self.current.next();
        (self.current, why)
    }

    /// Should this intent be allowed onto the wire?
    ///
    /// The one place the comparison is written. An intent that carries a
    /// coordinate must carry a fence, because its coordinate came from an
    /// observation and that observation carried one; an intent that carries no
    /// coordinate needs none, because there is nothing about it a resize
    /// invalidates. [`crate::intent::IntentKind::is_grounded`] draws that
    /// line and this method obeys it rather than repeating it.
    pub fn admit(&self, intent: &AgentIntent) -> Result<(), GeometryRejected> {
        match (intent.fence, intent.kind.is_grounded()) {
            (Some(fenced_at), _) if fenced_at != self.current => Err(GeometryRejected::Stale {
                fenced_at,
                current: self.current,
            }),
            (None, true) => Err(GeometryRejected::Unfenced {
                current: self.current,
            }),
            _ => Ok(()),
        }
    }
}

impl Default for GeometryFence {
    fn default() -> Self {
        Self::new()
    }
}

/// An actuation was computed against a geometry that is no longer the one on
/// the wire, and nothing was delivered.
///
/// Two variants and they mean different things to an agent. `Stale` says
/// "observe again and recompute", which is a retry. `Unfenced` says "your
/// caller dropped a field", which is a bug in the adapter and no amount of
/// retrying fixes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GeometryRejected {
    #[error("this action was computed against geometry generation {fenced_at} and the limb is now at {current}: observe again and recompute, nothing was delivered")]
    Stale {
        fenced_at: GeometryGeneration,
        current: GeometryGeneration,
    },
    #[error("this action carries a coordinate and no geometry generation: read the current generation ({current}) from an observation and send it back with the action")]
    Unfenced { current: GeometryGeneration },
}
