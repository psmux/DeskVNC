//! The trait itself, and the static card a limb answers with.

use crate::capability::Capability;
use crate::identity::{Slot, SlotRefused};
use crate::intent::IntentName;
use remote_core::driver::ProtocolDriver;
use remote_core::stats::SessionStats;
use std::time::Duration;

/// What a limb is, in the words an agent reads.
///
/// Every string here is MODEL FACING PROSE, rendered into the MCP tool listing
/// and written for a reader who has never seen this product. `steer_away` in
/// particular is not documentation: it is the sentence a desktop limb uses to
/// tell an agent that a text question belongs on the terminal sibling, which
/// is `00 R9` reaching the only place an agent will ever see it. A rule an
/// agent never reads is not a rule.
///
/// Not `#[non_exhaustive]`, which `02 §1.3` marked it and which does not
/// survive contact with the compiler. A non exhaustive struct cannot be built
/// with a struct expression outside its own crate, and every limb author is
/// outside this crate: the attribute is for a struct this crate CONSTRUCTS and
/// a consumer READS, and this one runs the other way. Adding a field here is
/// therefore a breaking change for every limb, which is the honest cost of the
/// card being a fixed set of questions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimbDescription {
    /// One noun phrase. "A remote desktop over RFB", "A login shell on a PTY".
    pub what: &'static str,
    /// What a coordinate means here, in one sentence, or the empty string when
    /// [`Limb::grounding`] is [`Grounding::None`].
    pub coordinates: &'static str,
    /// What "wait for it to settle" means on this limb, in one sentence.
    ///
    /// A desktop and a terminal both answer "wait" and they mean different
    /// things by it, and an agent that does not know which will misread a
    /// timeout as a failure.
    pub settling: &'static str,
    /// Whether the plane should present this limb ahead of, or behind, a
    /// sibling limb addressing the same machine.
    pub preference: Preference,
    /// Why, in one sentence. Rendered beside `preference`, never alone.
    pub preference_reason: &'static str,
    /// The sentence that tells an agent when NOT to use this limb.
    ///
    /// A desktop limb sets it to a sentence naming the terminal sibling. A
    /// terminal limb sets it to `None`, because there is nothing cheaper to
    /// steer toward.
    pub steer_away: Option<&'static str>,
}

/// Whether this limb is the cheap way to answer a question about a machine or
/// the expensive one.
///
/// Ordering, never substitution. The plane annotates and orders, and an agent
/// that asks for the desktop gets the desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preference {
    /// Reach for this one first. A terminal limb says this because text is
    /// the one modality where an agent is not guessing (`00 R9`).
    Preferred,
    /// Reach for this when the preferred sibling cannot answer. A desktop limb
    /// says this, and it says it even on a machine with no sibling, which is
    /// why the plane suppresses the annotation when there is nothing to
    /// prefer instead (`02 §9 OQ-7`).
    Fallback,
}

/// How an intent is answered on this limb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// The limb handles it itself. The intent reaches the driver's command
    /// pump as `ClientCommand::Agent`.
    Native,
    /// The plane rewrites it into primitives before the limb sees anything.
    ///
    /// The driver needs no code at all for these, which is the single largest
    /// reason a limb author's checklist is short: `type` on a desktop limb
    /// becomes a run of `ClientCommand::Key`, and `ClientCommand::Key` has
    /// worked for a year.
    ///
    /// The lowering is the PLANE's job and never the limb's, and that is a
    /// correctness requirement rather than tidiness. A composite intent has to
    /// be interruptible in the middle: `type("hello, world")` on a desktop is
    /// twenty six key messages, and if a person takes the wheel after the
    /// seventh the plane must stop at a code point boundary, send
    /// `ClientCommand::ReleaseAllKeys`, and settle the intent as superseded
    /// with the count that went. If the driver expanded the string, the driver
    /// would have to know about leases, and the lease engine would have to
    /// reach into every protocol crate.
    Lowered,
    /// Answered from the mirror or from the plane's own bookkeeping with no
    /// wire traffic at all. Every wait and every read is one of these.
    Observed,
    /// Not available here.
    ///
    /// `because` is shown to the agent verbatim, so it is a sentence and not
    /// an error code. An agent told "no" learns nothing; an agent told "a PTY
    /// has no pointer, use type" stops asking.
    Unsupported { because: &'static str },
}

/// Which perception families a limb produces.
///
/// A set rather than an enum, and `02 §8.4` is the case that decided it: an
/// Android device over ADB genuinely offers both a character stream (`shell`)
/// and a bitmap (`screencap`). Had this been an enum, an ADB limb would have
/// had to declare itself a terminal that lies about screenshots or a desktop
/// that lies about text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PerceptionSet {
    /// A framebuffer. Costs a mirror, and the mirror is where the real price
    /// of a limb is: a damage accumulator, a downscale, an encoder and a
    /// quiescence detector (`03 §2`).
    pub frames: bool,
    /// A character grid with a scrollback.
    pub cells: bool,
    /// Named elements with roles and bounds, the way an accessibility tree or
    /// a DOM answers.
    ///
    /// Nothing in this tree produces one and nothing in this tree may claim
    /// to. `00 R36`: the application's own object model is never placed on an
    /// RFB or RDP wire, and an inferred tree is always labelled inferred.
    pub structure: bool,
}

/// The coordinate space actuation uses on this limb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grounding {
    /// Framebuffer pixels, which is what `ClientCommand::Pointer` carries.
    /// There is exactly one such space per limb: a three monitor desktop is
    /// one framebuffer with three rectangles marked out inside it.
    Pixels,
    /// Character cells, columns and rows, which is what
    /// `ClientCommand::ResizeTerminal` carries. The unit split between this
    /// and pixels is already in the tree with its reason written down
    /// (`crates/remote-core/src/commands.rs:84`), and it is the one piece of
    /// grounding this design got for free.
    Cells,
    /// Nothing addressable. A limb that can be typed at and not pointed at.
    None,
}

/// How much an answer is worth, carried beside the answer.
///
/// Shared with `05`'s exit status, which uses the first two spellings. One type
/// rather than two so an agent learns the word once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// The protocol said so, unambiguously.
    Exact,
    /// Something on the far side said so and we believed it.
    Reported,
    /// We worked it out from evidence that could be wrong.
    Inferred,
}

/// How this limb decides that something has stopped happening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuiescencePolicy {
    pub signal: QuiescenceSignal,
    /// How long nothing must happen before the plane calls it settled. `04`'s
    /// wait tool exposes this with a default of 750 ms.
    pub default_quiet: Duration,
    /// How much the answer is worth.
    ///
    /// The load bearing field, and it is why this is a policy rather than a
    /// boolean. Nothing in this tree can report [`Confidence::Exact`]
    /// quiescence on a framebuffer, and saying so is the point: a desktop's
    /// quiescence is inferred from damage rectangles the SERVER chose to send,
    /// and `ClientCommand::SetAlwaysRefresh` exists precisely because some
    /// servers' damage tracking cannot be trusted
    /// (`crates/remote-core/src/commands.rs:36`). So a screen stable answer is
    /// least reliable on exactly the servers where an agent most needs it.
    pub confidence: Confidence,
}

/// Which instrument answers "has it stopped".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiescenceSignal {
    /// The damage union stopped arriving. Inferred, always.
    Damage,
    /// No bytes from the far side. Exact about the wire, silent about intent.
    OutputBytes,
    /// A structural readiness signal the protocol actually carries.
    Reported,
    /// This limb cannot answer the question and says so rather than guessing.
    None,
}

/// Ceilings imposed by the far side rather than by the grant.
///
/// `08 §3` owns the per grant buckets; this is the other half, the part that
/// depends on what is on the far side rather than on who is asking. A PTY
/// takes a kilobyte a second happily. A VNC server with a slow encoder does
/// not want two hundred pointer events a second, and the client cannot tell it
/// is drowning, because the damage simply stops.
///
/// Not `#[non_exhaustive]`, for the same reason as [`LimbDescription`]: a limb
/// author has to be able to write this struct down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimbLimits {
    /// How many intents from one grant may be in flight on one limb at once.
    pub max_in_flight: u8,
    pub pointer_per_sec: u16,
    pub keys_per_sec: u16,
    pub bytes_per_sec: u32,
    /// How many concurrent sessions this protocol supports against one
    /// machine, which is what makes slot addressing honest (`00 R31`).
    ///
    /// `None` means unbounded, which is true of SSH and of nothing else here.
    /// VNC depends on `VncOptions::shared`
    /// (`crates/remote-core/src/options.rs:202`), and a server that refuses a
    /// second connection will refuse it, so the honest value is 1 unless the
    /// profile has `shared` set. RDP depends on server policy and a second
    /// connection may log the first one out, so RDP reports 1 and the plane
    /// refuses a second slot with a sentence naming the reason rather than
    /// trying it.
    pub max_slots: Option<u16>,
}

impl LimbLimits {
    /// May this slot be opened?
    ///
    /// The refusal is the useful part. Without it an agent asking for eight
    /// RDP limbs on one Windows box discovers the server's session policy by
    /// watching seven of them disconnect the eighth.
    pub fn admits_slot(&self, slot: Slot) -> Result<(), SlotRefused> {
        match self.max_slots {
            None => Ok(()),
            Some(max) if u32::from(slot.0) < u32::from(max) => Ok(()),
            Some(max) => Err(SlotRefused {
                slot,
                max_slots: max,
            }),
        }
    }
}

/// Why a limb is usable but not well.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Degraded {
    /// Connected and the picture is not arriving.
    Starved,
    /// The far side is working flat out and producing little. From
    /// `SessionStats::server_duty_cycle`, whose own doc comment already names
    /// this exact reading (`crates/remote-core/src/stats.rs:44`).
    ServerSaturated,
    /// Round trip beyond anything an interactive loop can use.
    LinkSlow,
}

/// A protocol that has agreed to be driven by something that is not a person.
///
/// # Why this is a supertrait of `ProtocolDriver`
///
/// Three shapes were available: `Limb` as a supertrait of `ProtocolDriver`, a
/// sibling trait looked up in a second registry, or new defaulted methods on
/// `ProtocolDriver` itself. `02 §1.1` rules for the supertrait and the real
/// code agrees, for two reasons.
///
/// The bound is there so that identity cannot disagree with itself. A `Limb`
/// carrying its own `kind()` beside `ProtocolDriver::kind()` would be two
/// sources of truth for which protocol a limb speaks, and the repository has
/// already taken the opposite decision in the same situation: `SessionEntry`
/// reads its protocol off the handle rather than storing it a second time,
/// with the comment "the two can never disagree"
/// (`src-tauri/src/state.rs:242`). One value implements both traits, `kind()`
/// is asked once, and a driver and its limb are the same object.
///
/// The sibling shape was rejected because it means a second registry.
/// `ProtocolRegistry` holds `Vec<Arc<dyn ProtocolDriver>>`, and a parallel
/// `LimbRegistry` would make "which protocols does this build speak" a
/// question with two answers.
///
/// # The half of `02 §1.1` this crate cannot implement
///
/// `02 §1.1` also rules that `ProtocolDriver` gains one method,
/// `fn limb(&self) -> Option<&dyn Limb>`, defaulted to `None`, so the shell
/// can ask an `Arc<dyn ProtocolDriver>` whether it has agent support without a
/// downcast through `Any`. That method has to live on `ProtocolDriver`, which
/// is in `remote-core`, and `remote-core` cannot name `Limb` without depending
/// on this crate, which would be a cycle.
///
/// So the accessor is owed and it is one line in `remote-core` plus one line
/// per driver, and until it lands the shell reaches a limb through whatever
/// registry the plane keeps rather than through the driver. Recorded here
/// rather than in a plan file, because the person who wonders why the accessor
/// is missing will be reading this trait.
///
/// # Shape
///
/// One value per protocol, the same value the registry already holds,
/// constructed once at startup. Every method answers a question about the
/// PROTOCOL, never about a running session: implementations are stateless and
/// everything per session lives in the task `spawn` starts. That is why
/// nothing below can report a framebuffer size or a lease holder; those live
/// on the runtime card the plane assembles from `describe()` plus the address,
/// the current `SessionState`, the last resize, the lease and the sibling
/// limbs.
///
/// Eight required methods, five of which return a constant, plus two defaulted
/// accessors that read [`Limb::limits`] and ask no new question. The count is
/// closed on purpose: a limb that needs the plane to know something protocol
/// specific rides `SessionEvent::Protocol`, the escape hatch that already
/// exists for RDP logon info and SSH attach news
/// (`crates/remote-core/src/events.rs:167`). If this trait ever grows a method
/// that only one protocol answers usefully, the extension point has stopped
/// being one.
pub trait Limb: ProtocolDriver {
    /// The static card: what this limb is, what a coordinate means on it, and
    /// when an agent should reach for something else instead.
    fn describe(&self) -> LimbDescription;

    /// Every capability this limb can EVER offer, whatever is on the grant.
    ///
    /// The intersection of this and the grant's set is what an attachment may
    /// actually do
    /// ([`CapabilitySet::intersect`](crate::capability::CapabilitySet::intersect)),
    /// so a limb that cannot execute commands simply omits
    /// [`Capability::Exec`] and a grant carrying it gets a refusal naming the
    /// limb rather than a silent no-op. This is the whole of "capabilities per
    /// limb": the plane needs no table keyed on `ProtocolKind`.
    fn capabilities(&self) -> &'static [Capability];

    /// How this limb answers one kind of intent, before anything is sent.
    ///
    /// Required rather than defaulted, and the reason is the settlement rule.
    /// Every accepted intent gets exactly one settlement, so a limb that
    /// cannot settle an intent must refuse it, and a default of "supported"
    /// would let a limb accept something it can never answer. A default of
    /// "unsupported" would be worse: a limb author who forgot this method
    /// would ship a limb that refuses everything and looks broken rather than
    /// unfinished.
    ///
    /// A refusal carries a sentence because that is what makes it useful. See
    /// [`Support::Unsupported`].
    fn supports(&self, intent: IntentName) -> Support;

    /// Which perception families this limb can produce.
    fn perception(&self) -> PerceptionSet;

    /// What a coordinate means here.
    fn grounding(&self) -> Grounding;

    /// How "it stopped changing" is computed for this limb, and how much the
    /// answer is worth.
    fn quiescence(&self) -> QuiescencePolicy;

    /// Ceilings this protocol cannot exceed regardless of what a grant asks
    /// for.
    fn limits(&self) -> LimbLimits;

    /// Is this limb usable right now, judged from the numbers the session
    /// already emits once a second?
    ///
    /// Deliberately NOT a new `SessionState` variant. That enum's serde
    /// representation is a contract with `ui/src/lib/types.ts`
    /// (`crates/remote-core/src/state.rs:5`), and adding a variant would
    /// change what every existing consumer sees. Degradation is an overlay,
    /// and a person is told nothing new because the UI already shows them the
    /// numbers.
    ///
    /// A limb with nothing to read answers `None`, which is more useful than a
    /// number derived from nothing: `SessionStats` measures a socket, and a
    /// limb with no round trip to measure and no server duty cycle to read has
    /// no honest answer.
    fn degraded(&self, stats: &SessionStats) -> Option<Degraded>;

    /// How many concurrent sessions this protocol supports against one
    /// machine.
    ///
    /// `00 R31` requires this to be a trait method rather than a constant,
    /// because slot affinity is protocol dependent. It reads
    /// [`Limb::limits`] rather than being answered separately, so that a limb
    /// cannot report one ceiling here and another there.
    fn max_slots(&self) -> Option<u16> {
        self.limits().max_slots
    }

    /// May this slot be opened against this protocol?
    fn admits_slot(&self, slot: Slot) -> Result<(), SlotRefused> {
        self.limits().admits_slot(slot)
    }
}
