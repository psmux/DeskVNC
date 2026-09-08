//! The two generations, and why a stale actuation is a typed rejection.
//!
//! There are two counters in this file and they answer two different
//! questions. [`GeometryFence`] answers "is this coordinate still the place I
//! meant", and it moves on a resize. [`ContentFence`] answers "is this still
//! the window I read", and it moves when something large repaints. The second
//! was added because the first had no counterpart for text: the plane refused
//! a click computed against a screen that had gone and delivered a keystroke
//! into a window that had appeared thirty milliseconds earlier without a word.
//! [`ContentFence`] carries the incident that closed that gap.
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

/// How many times the CONTENT of a session's screen has changed materially
/// under an agent.
///
/// The geometry generation above answers "is this coordinate still the place I
/// meant". This one answers the question nobody was asking and should have
/// been: "is this still the window I read". They are separate counters because
/// they move on separate events. A desktop that never resizes has one geometry
/// generation for its whole life while a dozen windows open and close on top
/// of it, and every one of those is a screen an agent has not read.
///
/// **The incident.** An agent ran `Start-Process notepad` on a remote Windows
/// desktop and typed into it without looking first. Notepad had come up
/// holding the person's own file with all 2,378,798 characters selected, so
/// the next keystroke would have replaced the file. A human looked at a
/// screenshot before the typing step ran, which is the only reason it did not
/// happen. Nothing in the plane would have stopped it: `Type`, `Press` and
/// `Scancode` are not grounded
/// ([`IntentKind::is_grounded`](remote_core::intent::IntentKind::is_grounded)),
/// so no fence was ever consulted for them, and the plane was therefore strict
/// about where a click landed and indifferent to what a keystroke landed in.
///
/// Starts at [`ContentGeneration::FIRST`] and increments, never resets, for
/// the life of the mirror. Like the geometry generation it is stable across
/// nothing and exists only to be compared, and an agent that has lost it
/// reacquires it the only honest way, by looking at the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentGeneration(u32);

impl ContentGeneration {
    /// What the counter reads on a screen nothing has repainted wholesale yet.
    ///
    /// One rather than zero, for the reason
    /// [`GeometryGeneration::FIRST`](remote_core::geometry::GeometryGeneration::FIRST)
    /// is one: a defaulted, never initialised zero in somebody else's struct
    /// must not be mistakable for a live generation.
    pub const FIRST: ContentGeneration = ContentGeneration(1);

    /// The raw value, for a wire encoding or a log line.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The next generation. Called only by the fence that owns the counter.
    ///
    /// Saturating, for the reason the geometry counter saturates: a wrap would
    /// silently start admitting observations of a screen that is long gone.
    pub const fn next(self) -> ContentGeneration {
        ContentGeneration(self.0.saturating_add(1))
    }
}

impl std::fmt::Display for ContentGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The share of the framebuffer one update has to repaint before the screen
/// counts as a different screen.
///
/// This number is the whole feature, so here is the argument for it rather
/// than a shrug and a round figure. It is measured as covered area against
/// framebuffer area, per SERVER UPDATE, not accumulated over time.
///
/// What has to stay BELOW it, on a 1920x1080 desktop (2,073,600 px):
///
/// * The echo of the agent's own keystroke. One glyph cell is about 200 px,
///   0.01 percent. This is the one that matters most: a fence the agent's own
///   typing trips is a fence that refuses the second character of every word.
/// * A blinking caret, about 40 px. A ticking clock in a taskbar, about
///   1,200 px, 0.06 percent. A spinner, a progress bar, a hover highlight.
/// * A whole rewrapped line of text, 1900x20, 1.8 percent.
/// * A menu opening, roughly 200x300, 2.9 percent, and a small modal
///   ("Save changes?") at 400x200, 3.9 percent. Both are usually the direct
///   result of what the agent just did, and typing into them (a letter, an
///   arrow, Enter) is the ordinary next step.
///
/// What has to stay ABOVE it, on the same desktop:
///
/// * A file dialog, roughly 900x600, 26 percent.
/// * Notepad at its default size, roughly 35 percent. This is the incident.
/// * Any maximised application, any full screen installer, a UAC prompt (which
///   dims and repaints everything), a lock screen, a screensaver: 100 percent.
///
/// 0.15 sits in the middle of that gap with room on both sides. 0.10 would
/// start catching a large autocomplete popup on a 1366x768 laptop (10 percent
/// there is only 400x260), and a fence that refuses ordinary work is a fence
/// somebody routes around. 0.20 would start letting a dialog through on a
/// large desktop for no gain, because nothing real sits between 15 and 20.
///
/// **What it cannot catch, said plainly.** A 4K framebuffer that is NOT running
/// scaled UI makes every window a smaller share of the screen: an unscaled
/// Notepad on 3840x2160 is about 9.6 percent and would not trip this. In
/// practice a 4K desktop runs at 150 or 200 percent scaling, which puts the
/// same window back over the line, but a machine with scaling off is a machine
/// where this fence is weaker than it reads. It also does not catch a window
/// that paints itself in from the top in fifty small updates, because each one
/// is measured on its own. Both are arguments for looking, not for a cleverer
/// threshold: this is a floor under blind typing and never a proof that the
/// screen is what the agent remembers.
pub const MATERIAL_REPAINT: f32 = 0.15;

/// One limb's live content counter, held beside its framebuffer mirror.
///
/// Not `Clone` and not `Copy`, for the reason [`GeometryFence`] is neither: a
/// copy of it would be a second opinion about which generation is current,
/// which is the bug the counter exists to prevent.
#[derive(Debug)]
pub struct ContentFence {
    current: ContentGeneration,
}

impl ContentFence {
    /// A fence for a screen nothing has painted yet.
    pub fn new() -> Self {
        ContentFence {
            current: ContentGeneration::FIRST,
        }
    }

    /// What an observation assembled right now would carry.
    pub fn current(&self) -> ContentGeneration {
        self.current
    }

    /// Feed one server update in, as the area it covered against the area of
    /// the framebuffer.
    ///
    /// Returns the new generation when it moved and `None` when the update was
    /// too small to count, so a caller cannot bump the counter without
    /// deciding, which is the shape [`GeometryFence::changed`] has for the
    /// same reason.
    ///
    /// `covered` is a plain sum over the update's rectangles and is allowed to
    /// exceed the framebuffer when they overlap. That over counts, and it over
    /// counts in the safe direction: an overlapping repaint is a repaint, and
    /// the error can only make the fence trip earlier than the true coverage
    /// would, never later.
    pub fn painted(&mut self, covered: u64, area: u64) -> Option<ContentGeneration> {
        if area == 0 {
            // A framebuffer of no size. Nothing can be a material share of
            // nothing, and dividing would be worse than saying so.
            return None;
        }
        let share = covered as f64 / area as f64;
        if share < f64::from(MATERIAL_REPAINT) {
            return None;
        }
        self.current = self.current.next();
        Some(self.current)
    }

    /// May this attachment type into this screen?
    ///
    /// The one place the comparison is written, and the counterpart of
    /// [`GeometryFence::admit`]. `observed` is the content generation the
    /// asking attachment last read PIXELS at, and `None` means it has never
    /// read any.
    ///
    /// The `None` arm is not a courtesy case, it is the incident: an agent
    /// that has never looked at a machine is precisely the agent that does not
    /// know a text editor is open with everything selected. It is refused for
    /// the same reason a stale one is, and the sentence sends it to the same
    /// place.
    pub fn admit(&self, observed: Option<ContentGeneration>) -> Result<(), ContentRejected> {
        match observed {
            Some(seen) if seen == self.current => Ok(()),
            Some(seen) => Err(ContentRejected::Stale {
                observed: seen,
                current: self.current,
            }),
            None => Err(ContentRejected::Unobserved {
                current: self.current,
            }),
        }
    }
}

impl Default for ContentFence {
    fn default() -> Self {
        Self::new()
    }
}

/// Text was about to be typed into a screen the agent has not read, and
/// nothing was delivered.
///
/// Two variants, and like [`GeometryRejected`] they mean different things.
/// `Stale` says "something big appeared since you last looked, look again",
/// which is a retry after one cheap call. `Unobserved` says "you have never
/// looked at this machine at all", which is the same retry and a much worse
/// habit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContentRejected {
    #[error("the screen changed materially since this attachment last read it: it read content generation {observed} and the limb is now at {current}. Nothing was typed. Something large repainted, which is what a new window, a dialog or an application launching looks like, and the keystroke you were about to send would have gone into whatever is there now. Read the screen again, check what has focus and what is selected, then type")]
    Stale {
        observed: ContentGeneration,
        current: ContentGeneration,
    },
    #[error("this attachment has never read this screen (the limb is at content generation {current}) and text was about to be typed into it. Nothing was typed. Attach with perceive set to frames and read the screen first: typing into a machine you have not looked at is how an agent replaces the contents of a file somebody had open")]
    Unobserved { current: ContentGeneration },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Button, IntentId, IntentKind, Point};
    use crate::party::GrantId;

    /// 1920x1080, the desktop every number in [`MATERIAL_REPAINT`]'s argument
    /// is quoted against.
    const AREA: u64 = 1920 * 1080;

    fn px(width: u64, height: u64) -> u64 {
        width * height
    }

    /// The failure that would make this feature worthless: a fence the agent's
    /// own typing trips refuses the second character of every word, and gets
    /// switched off.
    #[test]
    fn nothing_an_agent_does_to_itself_moves_the_counter() {
        let mut fence = ContentFence::new();
        let start = fence.current();
        for (what, covered) in [
            ("one glyph cell", px(12, 20)),
            ("the caret blinking", px(2, 20)),
            ("a clock digit in the taskbar", px(60, 20)),
            ("a whole rewrapped line of text", px(1900, 20)),
            ("a menu opening", px(200, 300)),
            ("a save changes dialog", px(400, 200)),
        ] {
            assert_eq!(
                fence.painted(covered, AREA),
                None,
                "{what} is {covered} pixels of {AREA} and must not count as a new screen"
            );
        }
        assert_eq!(fence.current(), start);
    }

    /// The other edge. Everything here can take focus and eat the next
    /// keystroke, and the file dialog and the editor are the incident.
    #[test]
    fn anything_that_could_take_focus_moves_the_counter() {
        for (what, covered) in [
            ("a file dialog", px(900, 600)),
            ("an editor at its default size", px(1100, 700)),
            ("a maximised application", AREA),
        ] {
            let mut fence = ContentFence::new();
            let was = fence.current();
            assert_eq!(
                fence.painted(covered, AREA),
                Some(was.next()),
                "{what} is {covered} pixels of {AREA} and is exactly what this counter is for"
            );
        }
    }

    /// The boundary itself, from both sides, so the comparison cannot be
    /// quietly rewritten as the wrong one.
    ///
    /// A pixel under the threshold is not a new screen and a pixel over it is,
    /// and the fraction is a share of the framebuffer rather than an absolute
    /// count: the same 200,000 pixels are a window on a small desktop and a
    /// tooltip on a huge one.
    #[test]
    fn the_threshold_is_a_share_of_the_framebuffer_and_is_exact() {
        let boundary = (AREA as f64 * f64::from(MATERIAL_REPAINT)) as u64;

        let mut under = ContentFence::new();
        assert_eq!(under.painted(boundary - 1, AREA), None);

        let mut over = ContentFence::new();
        assert_eq!(over.painted(boundary + 1, AREA), Some(ContentGeneration(2)));

        // The same coverage against a framebuffer four times the size is a
        // quarter of the share and does not count.
        let mut bigger = ContentFence::new();
        assert_eq!(bigger.painted(boundary + 1, AREA * 4), None);

        // A framebuffer of no size divides by nothing rather than panicking or
        // counting every update as the whole screen.
        let mut nothing = ContentFence::new();
        assert_eq!(nothing.painted(1, 0), None);
    }

    /// Overlapping rectangles over count, and the over count is allowed: it
    /// can only make the fence trip earlier than the true coverage would.
    #[test]
    fn an_overlapping_repaint_may_count_more_than_the_screen_holds() {
        let mut fence = ContentFence::new();
        assert_eq!(fence.painted(AREA * 3, AREA), Some(ContentGeneration(2)));
    }

    /// The comparison, all three arms.
    #[test]
    fn text_is_admitted_only_against_the_generation_that_was_observed() {
        let mut fence = ContentFence::new();
        assert!(fence.admit(Some(ContentGeneration::FIRST)).is_ok());

        // Never looked. This is the incident: an agent that has not read a
        // machine is exactly the agent that does not know a text editor is open
        // with everything selected.
        assert_eq!(
            fence.admit(None),
            Err(ContentRejected::Unobserved {
                current: ContentGeneration::FIRST
            })
        );

        fence.painted(AREA, AREA).expect("a full repaint counts");
        assert_eq!(
            fence.admit(Some(ContentGeneration::FIRST)),
            Err(ContentRejected::Stale {
                observed: ContentGeneration::FIRST,
                current: ContentGeneration(2),
            })
        );
        assert!(fence.admit(Some(ContentGeneration(2))).is_ok());
    }

    /// Both numbers are in the sentence, the way [`GeometryRejected`] carries
    /// both of its own. A refusal an agent cannot check against what it thought
    /// it knew is a refusal it retries blind.
    #[test]
    fn the_refusal_names_both_generations_and_says_nothing_was_typed() {
        let stale = ContentRejected::Stale {
            observed: ContentGeneration(7),
            current: ContentGeneration(9),
        }
        .to_string();
        assert!(stale.contains('7') && stale.contains('9'), "{stale}");
        assert!(stale.contains("Nothing was typed"), "{stale}");

        let blind = ContentRejected::Unobserved {
            current: ContentGeneration(4),
        }
        .to_string();
        assert!(blind.contains('4'), "{blind}");
        assert!(blind.contains("Nothing was typed"), "{blind}");
    }

    /// The counter this one sits beside is untouched. A regression guard,
    /// because the content fence was added to this module and the geometry
    /// fence is what the plane has refused stale clicks with since `00 R10`.
    #[test]
    fn the_geometry_fence_still_behaves_exactly_as_it_did() {
        let intent = |fence_at: Option<GeometryGeneration>| AgentIntent {
            id: IntentId(1),
            grant: GrantId::from("att_7f3c"),
            deadline: None,
            fence: fence_at,
            kind: IntentKind::Click {
                at: Point::new(576, 340),
                button: Button::Left,
                count: 1,
                modifiers: Vec::new(),
            },
        };

        let mut fence = GeometryFence::new();
        let first = fence.current();
        assert!(fence.admit(&intent(Some(first))).is_ok());
        assert_eq!(
            fence.admit(&intent(None)),
            Err(GeometryRejected::Unfenced { current: first })
        );

        let (now, _) = fence.changed(GeometryChange::DesktopResize {
            width: 1920,
            height: 1080,
        });
        assert_eq!(
            fence.admit(&intent(Some(first))),
            Err(GeometryRejected::Stale {
                fenced_at: first,
                current: now
            })
        );

        // A keystroke still needs no geometry fence: nothing about it is
        // invalidated by a resize, and that absence is what the content fence
        // above exists to cover instead.
        let typed = AgentIntent {
            id: IntentId(2),
            grant: GrantId::from("att_7f3c"),
            deadline: None,
            fence: None,
            kind: IntentKind::Type {
                text: "hello".into(),
                wpm: None,
            },
        };
        assert!(fence.admit(&typed).is_ok());
    }
}
