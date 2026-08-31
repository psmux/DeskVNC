//! Putting an intent on the wire, and answering for it either way.
//!
//! ## The rule this module exists to keep
//!
//! **Every accepted intent gets exactly one settlement, and nothing else ends
//! an intent** (`02 §3.2`). Not a disconnect, not a lease loss, not a
//! shutdown, not a limb close: each of those produces a settlement with the
//! appropriate outcome before anything else happens. An intent that can end
//! silently forces every agent to carry its own timeout for every call, which
//! is the state of the art and it is miserable.
//!
//! The corollary is `00 R7` and `00 R28`: an intent this limb cannot serve is
//! ANSWERED with a refusal rather than dropped. `ssh-core`'s command pump ends
//! in `_ => continue` and that is correct for a UI, where a quality preset
//! sent to a terminal is noise. For an agent it is the worst failure this
//! design can have, because the agent does not retry, it waits.
//!
//! ## The order of the checks, and why it is that order
//!
//! 1. **The host** (`00 R19`). An injection saying "connect to the domain
//!    controller and run this" has to die before the model's decision reaches
//!    a socket, so this is first and it is cheap.
//! 2. **What the limb can do** (`02 §1.2`). A refusal carrying the limb's own
//!    sentence teaches the agent something; a capability refusal for an intent
//!    the limb never had does not.
//! 3. **The capability** (`00 R19`, `00 R20`). Deny by default, intersected
//!    with what the limb can ever offer.
//! 4. **Readiness** (`02 §6.1`). No intent is accepted while a limb is
//!    negotiating, and the refusal carries the retry time so an agent backs
//!    off rather than spinning.
//! 5. **The lease** (`08 §5`).
//! 6. **The geometry fence** (`00 R10`). Last of the refusals, because it is
//!    the only one that can be repaired by observing again, and an agent that
//!    is told to re-observe should not then discover it lacked the capability
//!    all along.
//!
//! Then, and only then, the lowering, and then the wire.
//!
//! ## The one intent the plane does not rewrite
//!
//! Three intents have no lowering, because nothing in `ClientCommand` can
//! carry them, and they go to the driver whole as `ClientCommand::Agent`
//! (`00 R28`, `05 §4.1`). A limb reports [`Support::Native`] for those and the
//! plane's job on them is plumbing rather than translation: every check above
//! still fires, and then one command goes.
//!
//! What is different is the answer. A lowered plan is finished when the last
//! command is on the wire, because nothing on an RFB or RDP wire acknowledges
//! anything. A native intent is not: the driver either serves it or refuses
//! it, and a refusal arrives later, on the session's EVENT stream, carrying
//! the intent id. [`ANSWERS`] is where that refusal meets the dispatcher
//! waiting for it, and the wait is bounded, because a plane that waits forever
//! for a driver that will never speak has reproduced the failure `00 R7` and
//! `00 R28` exist to remove one layer higher up.

use crate::backpressure::{Gaps, SendPolicy};
use crate::error::{Refusal, RefusalReason};
use crate::grant::Grant;
use crate::lowering::{coalesce_settings, lower, release_sequence, Lowered, Step, StepMark};
use crate::registry::{lock, AttachedLimb, LimbInner, RunningIntent};
use agent_lease::{
    AcquireRequest, HolderKind, LeaseError, LeaseId, LeaseInstant, LeasePhase, LeaseTransition,
    Party,
};
use limb_core::capability::capabilities_for;
use limb_core::fence::GeometryRejected;
use limb_core::intent::{
    AgentIntent, CommandExit, Dropped, ExitTier, IntentId, IntentKind, IntentRefused, IntentServed,
    Point, ServedAnswer, Unanswered, WaitUntil,
};
use limb_core::limb::{Confidence, Support};
use limb_core::observation::{
    ExitSource, ExitStatus, Observation, Outcome, Output, Progress, RefusalCode, SettleEvidence,
    Timestamp, TruncationPoint, Untrusted,
};
use limb_core::party::GrantId;
use limb_core::ClientCommand;
use remote_core::state::SessionState;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// A driver's exit status, as the plane's.
///
/// The one place the two shapes meet, and the reason there are two is the cycle
/// `00 R47a` records: `limb-core` depends on `remote-core`, so an answer
/// travelling on `SessionEvent` cannot name a `limb-core` type. Writing the
/// conversion once here means the two lists are kept in step by a compile error
/// rather than by memory.
///
/// The confidence is derived rather than carried, and that is deliberate. How
/// much a status is worth is a property of the TIER: an `exit-status` off the
/// wire is exact whoever read it (RFC 4254 §6.10), and a sentinel echoed at a
/// prompt is reported whoever read it. Deciding it here means a driver cannot
/// claim a confidence its tier does not have, which is what keeps
/// `limb-core`'s rule that [`Confidence::Inferred`] never appears on an exit
/// status true by construction rather than by convention.
fn exit_status(status: &CommandExit) -> ExitStatus {
    let source = match status.source {
        ExitTier::Exec => ExitSource::Exec,
        ExitTier::Osc133 => ExitSource::Osc133,
        ExitTier::Sentinel => ExitSource::Sentinel,
        ExitTier::Helper => ExitSource::Helper,
        // `ExitTier` is `#[non_exhaustive]`. A tier this build does not know
        // is read as the weakest one it does know rather than as an exact
        // answer, because the failure mode of guessing high is an agent
        // trusting a number it should have checked.
        _ => ExitSource::Sentinel,
    };
    ExitStatus {
        code: status.code,
        // Carried across untouched. `128 + signum` is not computed here and is
        // not computed anywhere: it is a shell's convention for squeezing a
        // signal through a byte wide status, and an agent handed 137 cannot
        // tell a killed process from one that chose to exit 137 (`00 R7`).
        signal: status.signal.clone(),
        source,
        confidence: match source {
            ExitSource::Exec => Confidence::Exact,
            ExitSource::Osc133 | ExitSource::Sentinel | ExitSource::Helper => Confidence::Reported,
        },
    }
}

/// How often the plane looks for room above the reservation.
///
/// A poll rather than `mpsc::Sender::reserve`, and the reservation is the
/// reason. `reserve` waits for ANY slot and hands that slot over, which is
/// exactly the slot the webview's `send_input` path was going to use, and
/// there is no "wait until free capacity exceeds N" on an mpsc sender. Five
/// milliseconds is well under the two second block ceiling and well over the
/// cost of a wake up.
const ROOM_POLL: Duration = Duration::from_millis(5);

/// How often a wait re-reads what it is waiting for.
///
/// The plane holds the damage stream and the state, so a wait is answered from
/// the plane's own bookkeeping and never reaches a limb (`02 §2.4`).
const WAIT_POLL: Duration = Duration::from_millis(50);

/// How long the plane waits for a driver's answer to a natively served intent
/// when the agent named no deadline of its own.
///
/// [`AgentIntent::deadline`] wins whenever it is there: it is the agent saying
/// how long it is willing to wait, and `05 §4.1` requires it on `run` with no
/// default precisely because an agent that has not said has not thought about
/// the action. This is the ceiling for one that did not say.
///
/// There is a ceiling at all because of `00 R7` and `00 R28`: an intent nobody
/// answers is the failure this path exists to remove, and a plane that blocks
/// forever on a driver that will never speak has rebuilt it inside itself.
///
/// Five seconds because the answer is a channel hop and the driver's own turn
/// round its command pump rather than a network round trip: `ssh-core` builds
/// its refusal in the same match arm that receives the command.
const NATIVE_ANSWER_WINDOW: Duration = Duration::from_secs(5);

/// One native intent that has been handed to a driver and is waiting to hear
/// back.
///
/// The limb is held as the attachment itself rather than as its name, and the
/// difference is not pedantry. A [`LimbId`] names a machine at a slot and is
/// reproducible on purpose, so that the same machine resolves to the same id on
/// this run and on next week's (`00 R31`), which makes it exactly the wrong key
/// here: two registries in one process can each attach that machine, and their
/// intents are different intents that would share a name. An `Arc` is one
/// attachment and nothing else. Holding it costs nothing extra either, because
/// [`RunningGuard`] already holds one for the same span.
///
/// [`LimbId`]: limb_core::identity::LimbId
struct PendingAnswer {
    limb: Arc<LimbInner>,
    id: IntentId,
    answer: oneshot::Sender<Answer>,
}

/// What a driver said about an intent it was handed.
///
/// Two arms, and until `00 R51b` there was one. `SessionEvent::AgentRefused`
/// let a driver say no and nothing let it say yes, so a driver that genuinely
/// served an intent had nothing to send, the plane heard nothing, and the
/// intent settled as [`Outcome::TimedOut`] when the deadline passed. The first
/// driver to implement a native intent therefore looked exactly like a driver
/// that had failed, and the harder it worked the longer it took to look like
/// it. This is the other half.
#[derive(Debug)]
enum Answer {
    Refused(IntentRefused),
    Served(IntentServed),
}

/// Where a driver's refusal waits for the dispatcher that asked.
///
/// `00 R28`. A natively served intent goes out as `ClientCommand::Agent` and
/// the driver answers with `SessionEvent::AgentRefused` on the SESSION's event
/// stream, which this crate does not read: the shell owns that stream, and a
/// second subscriber inside the plane would be a second opinion about what a
/// limb is doing. That is the same reason [`AttachedLimb::note_state`] exists
/// rather than a subscription. So the caller that has the stream reports the
/// refusal with [`AttachedLimb::note_refused`], and this is where the two meet.
///
/// A list rather than a map, and one list for the process rather than one per
/// limb, because it is the dispatcher's own bookkeeping and nothing else in the
/// crate reads it. It holds one entry per native intent in flight, and `00 R21`
/// caps the limbs at four with one dispatching batch per grant on each, so the
/// scan a refusal does is over a handful of entries and a tree keyed on a
/// synthetic name would cost more than it saved.
///
/// An entry lives only while one native intent is in flight, and [`AnswerGuard`]
/// takes it out however that dispatch ends, including a panic.
static ANSWERS: Mutex<Vec<PendingAnswer>> = Mutex::new(Vec::new());

/// Takes one intent's answer slot out of [`ANSWERS`] however its dispatch ends.
///
/// A guard for the reason [`RunningGuard`] is one: there are several ways out
/// of a native dispatch and one of them is a panic. An entry left behind would
/// hold a sender nobody will ever send on and an `Arc` on a limb that has been
/// detached.
struct AnswerGuard {
    limb: Arc<LimbInner>,
    id: IntentId,
}

impl Drop for AnswerGuard {
    fn drop(&mut self) {
        lock(&ANSWERS)
            .retain(|pending| pending.id != self.id || !Arc::ptr_eq(&pending.limb, &self.limb));
    }
}

/// What happened to one intent, with everything an agent needs to decide what
/// to do next.
///
/// Wider than [`Outcome`] on purpose, and the extra fields are the ones
/// `08 §4.6` insists on: the plane never drops anything without saying how
/// much it dropped, and a settlement that carried only an outcome would be
/// exactly the silent path the section was written to forbid.
#[derive(Debug, Clone)]
pub struct Settlement {
    pub id: IntentId,
    pub outcome: Outcome,
    /// How far the intent got. `Progress::CodePoints` for a half typed string,
    /// `Progress::Drag` for an interrupted gesture, and those two are the
    /// reason this is not a command count.
    pub progress: Progress,
    /// What this intent lost. See [`Gaps`].
    pub gaps: Gaps,
    /// The precise plane level code, where `02 §3.4`'s canonical set has no
    /// member for it. `None` when nothing was refused.
    pub reason: Option<RefusalReason>,
    /// Observations produced while answering, such as the pixels of a read.
    /// Empty for an actuation.
    pub payload: Vec<Observation>,
}

impl Settlement {
    fn refuse(id: IntentId, refusal: Refusal) -> Settlement {
        let reason = refusal.reason;
        Settlement {
            id,
            outcome: refusal.into(),
            progress: Progress::None,
            gaps: Gaps::default(),
            reason: Some(reason),
            payload: Vec::new(),
        }
    }

    /// The same refusal, carrying what the attempt lost on the way.
    ///
    /// A refusal usually loses nothing, because it fires before anything is
    /// sent. The two that do not are the queue ones: a command that never
    /// reached a full channel is a drop, and `08 §4.6` is blunt that the plane
    /// never drops anything without saying how much.
    fn refuse_with(id: IntentId, refusal: Refusal, gaps: Gaps) -> Settlement {
        Settlement {
            gaps,
            ..Settlement::refuse(id, refusal)
        }
    }

    /// Was this refused before, or part way through, reaching the wire?
    pub fn refused(&self) -> bool {
        self.reason.is_some()
    }

    /// The acceptance an agent sees before the settlement, or `None` for a
    /// refusal.
    ///
    /// `Accepted` means the capability check passed, the lease was held, and
    /// something is on the wire. It does not mean it worked, and nothing
    /// anywhere in this design claims that it does: neither an RFB KeyEvent
    /// nor an RDP fast path input event carries an acknowledgement.
    pub fn accepted(&self, at: Timestamp) -> Option<Observation> {
        if self.refused() {
            return None;
        }
        Some(Observation::Accepted { id: self.id, at })
    }

    /// The one settlement this intent gets.
    pub fn settled(&self, at: Timestamp) -> Observation {
        Observation::Settled {
            id: self.id,
            outcome: self.outcome.clone(),
            at,
        }
    }
}

/// Removes an intent from the limb's running table however the dispatch ends.
///
/// A guard rather than a call at the end of the function, because there are
/// eight ways out of a dispatch and one of them is a panic. An intent left in
/// the table would refuse every subsequent intent from that grant with
/// `INTENT_IN_FLIGHT`, forever, which is a limb nobody can drive.
struct RunningGuard {
    limb: Arc<LimbInner>,
    id: IntentId,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        lock(&self.limb.running).remove(&self.id);
    }
}

/// What became of one command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepResult {
    Sent,
    /// Stale motion, dropped on a full channel. The designed path.
    Shed,
    /// The channel stayed full past the block ceiling.
    Blocked,
    /// The session task is gone.
    Gone,
}

/// Running totals while a plan is walked.
#[derive(Debug, Default)]
struct Walk {
    delivered: u32,
    code_points: u32,
    /// True once a drag's press went and its release did not.
    drag_held: bool,
    drag_points: u16,
    drag_at: Option<Point>,
    release_synthesised: bool,
}

impl Walk {
    fn record(&mut self, step: &Step) {
        self.delivered = self.delivered.saturating_add(1);
        match step.mark {
            StepMark::Plain => {}
            StepMark::CodePoint => self.code_points = self.code_points.saturating_add(1),
            StepMark::DragPress => self.drag_held = true,
            StepMark::DragPoint(at) => {
                self.drag_points = self.drag_points.saturating_add(1);
                self.drag_at = Some(at);
            }
            StepMark::DragRelease => {
                self.drag_held = false;
                self.drag_at = None;
            }
        }
    }

    fn progress(&self, was_drag: bool) -> Progress {
        if was_drag {
            return Progress::Drag {
                released_at: self.drag_at.unwrap_or(Point::new(0, 0)),
                points_delivered: self.drag_points,
                release_synthesised: self.release_synthesised,
            };
        }
        if self.code_points > 0 {
            return Progress::CodePoints(self.code_points);
        }
        if self.delivered == 0 {
            return Progress::None;
        }
        Progress::Delivered(self.delivered)
    }
}

impl AttachedLimb {
    /// The next intent id for this limb.
    ///
    /// Monotonic and never reused, which is what lets `02 §3.2` say that an
    /// observation carrying an id an agent does not recognise is a bug in the
    /// plane rather than a race. Called `mint` for the reason
    /// `IntentSequence::mint` is: an id handed out is an id an observation will
    /// refer to, so pulling one speculatively and dropping it leaves a gap in
    /// a sequence a reader is entitled to read as dense.
    pub fn mint(&self) -> IntentId {
        lock(&self.inner.seq).mint()
    }

    /// Ask for control of this limb.
    ///
    /// The transition that comes back carries the release obligation, and
    /// [`AttachedLimb::honour`] is the only thing that discharges it. A caller
    /// that acquires and never honours gets a limb nobody can drive, which is
    /// `00 R46c`'s deliberate asymmetry: a lease that will not hand over is a
    /// bug somebody notices in a second, and a modifier held down on a remote
    /// machine is a bug somebody notices after typing a paragraph into a
    /// keyboard shortcut.
    ///
    /// # Errors
    ///
    /// [`LeaseError`], each naming what the caller can do next.
    pub fn acquire(
        &self,
        request: AcquireRequest,
        now: LeaseInstant,
    ) -> Result<LeaseTransition, LeaseError> {
        lock(&self.inner.lease).acquire(request, now)
    }

    /// Let go.
    pub fn release_lease(
        &self,
        party: &GrantId,
        lease_id: LeaseId,
        now: LeaseInstant,
    ) -> LeaseTransition {
        lock(&self.inner.lease).release(party, lease_id, now)
    }

    /// The panic chord, for this limb (`08 §6.3`, `00 R13`).
    ///
    /// A revocation, not a request. The holder is gone the moment this
    /// returns, the queue is emptied, and there is no grace window, because
    /// BrowserGlass's own demo measures 2,008 ms for a polite handover, which
    /// is two seconds of somebody pressing a button labelled stop while
    /// nothing happens.
    pub fn force_release(&self, now: LeaseInstant) -> LeaseTransition {
        lock(&self.inner.lease).force_release(now)
    }

    /// Apply elapsed time to the lease. The only call that does.
    ///
    /// A caller ticks first and acts second. A caller that forgets sees a
    /// stale holder keep the wheel, which is a visible bug rather than a
    /// silent stuck modifier, and that is why `agent-lease` refuses to sweep
    /// expiries inside `acquire`.
    pub fn tick(&self, now: LeaseInstant) -> LeaseTransition {
        lock(&self.inner.lease).tick(now)
    }

    /// Whether this party's intents dispatch right now.
    pub fn fencing(&self, party: &GrantId) -> agent_lease::Fencing {
        lock(&self.inner.lease).fence(party)
    }

    /// Discharge the release a lease change owes the limb (`00 R11`).
    ///
    /// **Buttons before keys.** A pointer event with an empty button mask goes
    /// first, then every key is released. `00 B8` is why the first half exists
    /// and it is not theoretical: `release_all_keys` in `vnc-core` drains a map
    /// keyed by `(keysym, Option<keycode>)`, so it is keys only, and the VNC
    /// pointer arm remembers no mask at all. A preemption between a drag's
    /// press and its release therefore leaves the left button held on the
    /// remote machine, and for a preempted agent nothing follows at all until
    /// the new holder moves the mouse, so the interval is unbounded. The
    /// person who took the wheel gets a machine that rubber band selects
    /// across the desktop and nothing in the audit trail explains why.
    ///
    /// Both commands carry [`SendPolicy::Jump`]: ahead of anything queued, and
    /// exempt from the rate buckets, because a limiter that runs before the
    /// handler never sees the event kind and silently defeats the asymmetry
    /// above it.
    ///
    /// Returns what went on the wire, in order, so a trace and a test can both
    /// assert the ordering rather than trusting it.
    pub async fn honour(
        &self,
        transition: &LeaseTransition,
        now: LeaseInstant,
    ) -> Vec<ClientCommand> {
        if !transition.must_release() {
            return Vec::new();
        }
        let at = lock(&self.inner.input).ctx.last_point;
        let steps = release_sequence(at);
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.inner.config.intent_block_ms);
        let mut sent = Vec::new();
        for step in &steps {
            let (result, _waited) = self.send_step(step, deadline).await;
            match result {
                StepResult::Sent => {
                    self.remember(step);
                    sent.push(step.command.clone());
                }
                other => {
                    // The one place this crate logs rather than returning.
                    // There is nobody to return to: a release is owed to the
                    // limb by the plane itself, not by an agent, so a failure
                    // here is an operational fact and not an intent outcome.
                    tracing::warn!(
                        limb = %self.inner.id,
                        result = ?other,
                        "the release owed by a lease change did not reach the limb; a modifier or a button may be held on the remote machine"
                    );
                }
            }
        }

        // Only `HandingOver` has an exit and this is it (`00 R46c`). The
        // transition that comes back carries `ReleaseObligation::NotRequired`
        // by construction, so dropping it owes the limb nothing; it is
        // dropped explicitly rather than by accident because `LeaseTransition`
        // is `#[must_use]` and should stay that way.
        if lock(&self.inner.lease).phase() == LeasePhase::HandingOver {
            let _confirmed = lock(&self.inner.lease).confirm_release(now);
        }
        sent
    }

    /// Acquire and discharge in one call, which is what a caller almost always
    /// wants.
    ///
    /// # Errors
    ///
    /// [`LeaseError`] from the acquire. Nothing after the acquire can fail:
    /// a release that does not reach the limb is logged, because there is no
    /// caller who could do anything about it.
    pub async fn take_control(
        &self,
        party: Party,
        now: LeaseInstant,
    ) -> Result<(LeaseTransition, Vec<ClientCommand>), LeaseError> {
        let transition = self.acquire(AcquireRequest::new(party), now)?;
        let sent = self.honour(&transition, now).await;
        Ok((transition, sent))
    }

    /// Withdraw a running intent.
    ///
    /// Returns whether anything was found. `02 §2.4` needs no capability for
    /// this: withdrawing your own request is not a privilege, and gating it
    /// would mean an agent that has lost a capability mid task cannot stop the
    /// work it already started.
    pub fn cancel_running(&self, target: IntentId) -> bool {
        match lock(&self.inner.running).get(&target) {
            Some(running) => {
                running.cancel.cancel();
                true
            }
            None => false,
        }
    }

    /// Dispatch one intent and answer for it.
    ///
    /// Never returns a `Result`. Every path through this function produces a
    /// [`Settlement`], which is `00 R7` and `02 §3.2` in the signature rather
    /// than in a comment somebody has to remember.
    pub async fn dispatch(
        &self,
        grant: &Grant,
        intent: AgentIntent,
        now: LeaseInstant,
    ) -> Settlement {
        let id = intent.id;

        // The envelope names a grant and the caller passed one. If they
        // disagree, the caller has routed an intent to the wrong attachment,
        // and answering under the wrong identity would put the wrong grant in
        // the audit line.
        if intent.grant != *grant.id() {
            return Settlement::refuse(
                id,
                Refusal::plane(
                    RefusalReason::HostNotInGrant,
                    format!(
                        "this intent's envelope names grant {} and it was submitted under grant {}; nothing was sent",
                        intent.grant,
                        grant.id()
                    ),
                ),
            );
        }

        // 1. The host. First, and before anything is looked up, because this
        //    is the control that does not depend on recognising an injection.
        if !grant.allows_host(&self.inner.host) {
            return Settlement::refuse(id, grant.host_refusal(&self.inner.host));
        }

        // 2. What the limb can do at all, in the limb's own words.
        let name = intent.kind.name();
        if let Support::Unsupported { because } = self.inner.driver.supports(name) {
            return Settlement::refuse(id, Refusal::limb(RefusalCode::NotSupported, because));
        }

        // 3. The capability, deny by default, intersected with what this limb
        //    can ever offer. The two shortfalls get different sentences
        //    because they have different repairs: a grant can be reissued and
        //    a limb cannot grow a capability.
        let needed = capabilities_for(&intent.kind, &self.inner.driver.perception());
        let offered = self.offered();
        let missing_from_grant = grant.missing(needed);
        if !missing_from_grant.is_empty() {
            return Settlement::refuse(
                id,
                Refusal::limb(
                    RefusalCode::MissingCapability,
                    format!(
                        "{name} needs {} and this grant does not carry {}; a grant's capabilities are fixed when a person approves it",
                        list(&needed.iter().collect::<Vec<_>>()),
                        list(&missing_from_grant),
                    ),
                ),
            );
        }
        let missing_from_limb = offered.missing(needed);
        if !missing_from_limb.is_empty() {
            return Settlement::refuse(
                id,
                Refusal::limb(
                    RefusalCode::NotSupported,
                    format!(
                        "{name} needs {}, and {} never offers {}; the grant carries it and this limb cannot use it",
                        list(&needed.iter().collect::<Vec<_>>()),
                        self.inner.id,
                        list(&missing_from_limb),
                    ),
                ),
            );
        }

        // 4. Readiness. A wait for `connected` is the one useful call while a
        //    limb is still negotiating or waiting on a person for a
        //    credential, so it is exempt (`02 §6.1`).
        let waiting_to_connect = matches!(
            &intent.kind,
            IntentKind::Wait {
                until: WaitUntil::Connected,
                ..
            }
        );
        if !waiting_to_connect {
            if let Some(refusal) = self.readiness() {
                return Settlement::refuse(id, refusal);
            }
        }

        // 5. The lease.
        let needs_lease = intent.kind.needs_control_lease();
        if needs_lease && !self.fencing(grant.id()).is_allowed() {
            return Settlement::refuse(id, self.lease_refusal());
        }

        // 6. The geometry fence. `00 R10`: an actuation computed against a
        //    geometry that is no longer the one on the wire is refused and
        //    nothing is delivered.
        {
            let input = lock(&self.inner.input);
            if let Err(rejected) = input.fence.admit(&intent) {
                let code = match rejected {
                    GeometryRejected::Stale { .. } => RefusalCode::GeometryChanged,
                    GeometryRejected::Unfenced { .. } => RefusalCode::Unfenced,
                };
                return Settlement::refuse(id, Refusal::limb(code, rejected.to_string()));
            }
        }

        let ctx = lock(&self.inner.input).ctx;
        let lowered = match lower(&intent, &ctx) {
            Ok(lowered) => lowered,
            Err(refusal) => return Settlement::refuse(id, refusal),
        };

        match lowered {
            Lowered::Observed => self.observe(grant, &intent, now).await,
            Lowered::Native(step) => {
                self.serve_natively(grant, &intent, step, needs_lease, now)
                    .await
            }
            Lowered::Commands(steps) => self.actuate(grant, &intent, steps, needs_lease, now).await,
        }
    }

    /// Take this grant's one in flight slot on this limb, or say why not.
    ///
    /// `08 §7.3`. One in flight batch per (grant, limb), because two concurrent
    /// batches to one limb have no defined interleaving and an agent that
    /// believes it typed `hello` and then `world` would get either, or a mix,
    /// and could not tell which.
    ///
    /// Returns the token a `cancel` reaches this intent through, and the guard
    /// that takes it back out of the table however the dispatch ends. Both
    /// halves are wanted by both kinds of dispatch: a lowered plan is walked
    /// and a native intent is waited on, and either can be withdrawn.
    ///
    /// # Errors
    ///
    /// The settlement to return, already refused. A `Result` rather than an
    /// `Option` so the one arm the caller writes is `return refused`, and a
    /// caller cannot start a dispatch by ignoring it.
    fn start_running(
        &self,
        grant: &Grant,
        id: IntentId,
    ) -> Result<(CancellationToken, RunningGuard), Settlement> {
        let token = CancellationToken::new();
        {
            let mut running = lock(&self.inner.running);
            if running.values().any(|r| r.grant == *grant.id()) {
                return Err(Settlement::refuse(
                    id,
                    Refusal::plane(
                        RefusalReason::IntentInFlight,
                        format!(
                            "grant {} already has an intent dispatching on {}; two batches on one limb have no defined interleaving, so this one was not started",
                            grant.id(),
                            self.inner.id
                        ),
                    ),
                ));
            }
            running.insert(
                id,
                RunningIntent {
                    grant: grant.id().clone(),
                    cancel: token.clone(),
                },
            );
        }
        Ok((
            token,
            RunningGuard {
                limb: self.inner.clone(),
                id,
            },
        ))
    }

    /// Walk a lowered plan onto the wire, re-checking the lease before every
    /// command.
    ///
    /// `08 §6.2` ruling C: an intent batch is not atomic and the plane never
    /// claims it is. An agent's `type("hello world")` is 22 key events, and if
    /// the lease goes away at character 6 then six characters were typed and
    /// the settlement says so. It does not return an error implying nothing
    /// happened, and it does not finish the word.
    async fn actuate(
        &self,
        grant: &Grant,
        intent: &AgentIntent,
        mut steps: Vec<Step>,
        needs_lease: bool,
        now: LeaseInstant,
    ) -> Settlement {
        let id = intent.id;
        let was_drag = matches!(intent.kind, IntentKind::Drag { .. });

        let (token, _guard) = match self.start_running(grant, id) {
            Ok(started) => started,
            Err(refused) => return refused,
        };

        let mut gaps = Gaps {
            settings_coalesced: coalesce_settings(&mut steps),
            ..Gaps::default()
        };

        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_millis(self.inner.config.intent_block_ms);
        let mut waited = Duration::ZERO;
        let mut walk = Walk::default();
        let mut stopped_at = steps.len();
        let mut superseded: Option<HolderKind> = None;
        let mut blocked = false;
        let mut gone = false;
        let mut cancelled = false;

        for (index, step) in steps.iter().enumerate() {
            if token.is_cancelled() {
                cancelled = true;
                stopped_at = index;
                break;
            }
            // Re-checked here rather than once at the top. This is the only
            // place a person taking the wheel mid gesture can be noticed, and
            // it is why the pauses in a plan are where they are.
            if needs_lease && !self.fencing(grant.id()).is_allowed() {
                superseded = Some(self.superseder(grant.id()));
                stopped_at = index;
                break;
            }
            let (result, spent) = self.send_step(step, deadline).await;
            waited += spent;
            match result {
                StepResult::Sent => {
                    walk.record(step);
                    self.remember(step);
                }
                StepResult::Shed => {
                    gaps.pointer_moves_shed = gaps.pointer_moves_shed.saturating_add(1);
                }
                StepResult::Blocked => {
                    blocked = true;
                    stopped_at = index;
                    break;
                }
                StepResult::Gone => {
                    gone = true;
                    stopped_at = index;
                    break;
                }
            }
            if !step.pause.is_zero() {
                tokio::select! {
                    () = tokio::time::sleep(step.pause) => {}
                    () = token.cancelled() => {
                        cancelled = true;
                        stopped_at = index + 1;
                        break;
                    }
                }
            }
        }

        // `15 §4.5` WA-6. A drag whose press went and whose release did not
        // leaves a button held on the remote machine, and on VNC nothing will
        // ever clear it until somebody moves the mouse. So the plane releases
        // it here, at the last point the button was known to be, and says in
        // the settlement that the drop landed somewhere the agent did not
        // choose. There is no honest way to undo it and nothing above this
        // pretends there is.
        if walk.drag_held {
            let at = walk
                .drag_at
                .unwrap_or(lock(&self.inner.input).ctx.last_point);
            let resting = lock(&self.inner.input).ctx.resting_mask;
            let release = Step {
                command: ClientCommand::Pointer {
                    x: at.x,
                    y: at.y,
                    button_mask: resting,
                },
                policy: SendPolicy::Jump,
                pause: Duration::ZERO,
                mark: StepMark::DragRelease,
            };
            let (result, spent) = self.send_step(&release, deadline).await;
            waited += spent;
            if result == StepResult::Sent {
                self.remember(&release);
            }
            walk.drag_at = Some(at);
            walk.release_synthesised = true;
        }

        // What never reached the session, for the two failures that are the
        // plane's own backpressure. A supersession or a cancellation leaves
        // steps unsent too, and those are reported by `Progress` instead:
        // they were not dropped, they were stopped, and telling an agent its
        // keystrokes were dropped when a person took the wheel would send it
        // looking for a network fault.
        if blocked || gone {
            let remaining = &steps[stopped_at..];
            gaps.commands_dropped = remaining.len() as u32;
            gaps.bytes_dropped = remaining.iter().map(Step::payload_bytes).sum();
        }
        gaps.blocked_ms = waited.as_millis().min(u128::from(u64::MAX)) as u64;
        lock(&self.inner.input).gaps.absorb(gaps);

        let progress = walk.progress(was_drag);
        let generation = lock(&self.inner.input).fence.current();
        let (outcome, reason) = if cancelled {
            (Outcome::Cancelled, None)
        } else if gone {
            // Note what this does NOT claim. Bytes on a socket that is about
            // to die may still have arrived, so the agent is told the intent
            // may or may not have happened rather than being told it failed.
            (
                Outcome::LinkLost { generation },
                Some(RefusalReason::LimbGone),
            )
        } else if let Some(by) = superseded {
            (Outcome::Superseded { by, progress }, None)
        } else if blocked && walk.delivered == 0 {
            let refusal = Refusal::plane(
                RefusalReason::IntentBlocked,
                format!(
                    "the session channel on {} stayed full for {} ms and nothing was sent: {}",
                    self.inner.id,
                    self.inner.config.intent_block_ms,
                    gaps.describe()
                ),
            );
            let reason = refusal.reason;
            (Outcome::from(refusal), Some(reason))
        } else if blocked {
            // Part of it went. `delivered: false` is the honest reading, since
            // the intent as asked was not delivered, and `progress` says
            // exactly how much was. `02 §3.4`'s `Outcome` has no partial
            // variant and this is the closest honest use of the ones it has.
            (
                Outcome::Done {
                    delivered: false,
                    verified: None,
                },
                Some(RefusalReason::IntentBlocked),
            )
        } else {
            // Delivered, which is what we put on the wire. Not "it worked":
            // neither an RFB KeyEvent nor an RDP fast path input event carries
            // an acknowledgement, so `verified` is a separate field and is
            // `None` until something asserts a region changed (`06 §5.4`).
            (
                Outcome::Done {
                    delivered: true,
                    verified: None,
                },
                None,
            )
        };

        // A dispatched intent resets the hard time to live and the idle
        // revocation. Only when something actually went: `08 §5.4` measures
        // idle revocation from the last DISPATCHED intent, and counting a
        // refusal would let a grant hold a machine by being refused.
        if needs_lease && walk.delivered > 0 {
            lock(&self.inner.lease).note_intent(grant.id(), now);
        }

        Settlement {
            id,
            outcome,
            progress,
            gaps,
            reason,
            payload: Vec::new(),
        }
    }

    /// Report a refusal the caller saw on this limb's event stream.
    ///
    /// `00 R28`. `SessionEvent::AgentRefused` is a driver saying it will not
    /// serve an intent it was handed, and it carries the [`IntentId`] the agent
    /// is blocked on precisely so that nothing downstream has to parse a
    /// sentence to find out which one. This is where that id is turned back
    /// into the settlement the agent is waiting for, with the driver's own
    /// words in it.
    ///
    /// The plane does not read the event stream itself, for the reason on
    /// [`AttachedLimb::note_state`]: the shell owns it and a second subscriber
    /// would be a second opinion. So the refusal is reported here the same way
    /// a lifecycle change is.
    ///
    /// Returns whether an intent was waiting for it. `false` means the refusal
    /// arrived after its intent had already settled, which is what happens when
    /// the answer took longer than the agent was willing to wait or the limb
    /// closed underneath it. It is returned rather than swallowed so a caller
    /// can log a refusal nobody was waiting for, because a refusal that
    /// disappears is the thing this whole path exists to prevent.
    pub fn note_refused(&self, refusal: IntentRefused) -> bool {
        self.note_answer(refusal.id, Answer::Refused(refusal))
    }

    /// Report an answer the caller saw on this limb's event stream.
    ///
    /// `00 R51b`. `SessionEvent::AgentServed` is a driver saying it DID serve
    /// an intent, with what serving it produced, and it reaches the waiting
    /// dispatch exactly as a refusal does: the plane does not read the event
    /// stream itself, so the caller that owns it reports both.
    ///
    /// Returns whether an intent was waiting, and a `false` here is worth more
    /// than a `false` from [`AttachedLimb::note_refused`]. An answer nobody was
    /// waiting for means real work was done on a remote machine and the agent
    /// that asked for it has already been told the intent timed out. Log it.
    pub fn note_served(&self, served: IntentServed) -> bool {
        self.note_answer(served.id, Answer::Served(served))
    }

    /// The lookup both of the above share. One list scan, one send.
    fn note_answer(&self, id: IntentId, answer: Answer) -> bool {
        let waiting = {
            let mut answers = lock(&ANSWERS);
            let at = answers
                .iter()
                .position(|p| p.id == id && Arc::ptr_eq(&p.limb, &self.inner));
            at.map(|at| answers.swap_remove(at))
        };
        match waiting {
            Some(pending) => pending.answer.send(answer).is_ok(),
            None => false,
        }
    }

    /// Take this intent's answer slot, and hold it until the guard is dropped.
    fn listen_for_answer(&self, id: IntentId) -> (AnswerGuard, oneshot::Receiver<Answer>) {
        let (answer, listening) = oneshot::channel();
        lock(&ANSWERS).push(PendingAnswer {
            limb: self.inner.clone(),
            id,
            answer,
        });
        (
            AnswerGuard {
                limb: self.inner.clone(),
                id,
            },
            listening,
        )
    }

    /// Hand one intent to the driver whole, and wait for the answer it owes.
    ///
    /// `00 R28`. There was nothing to rewrite this into, so the intent itself
    /// goes as `ClientCommand::Agent` and the driver serves it or refuses it.
    /// Every check in [`AttachedLimb::dispatch`] has already fired: the host,
    /// the capability, the readiness and the lease all gate this exactly as
    /// they gate a click, and `exec` is in no role bundle (`00 R19`, `00 R30`),
    /// so nothing here is a way around any of them.
    ///
    /// Then it waits, and the wait is the part worth reading. A lowered plan is
    /// done when the last command is on the wire, because nothing on an RFB or
    /// an RDP wire acknowledges anything and the plane has never claimed
    /// otherwise. A native intent has an answer channel, so settling the moment
    /// the command went would settle it before the driver had said whether it
    /// would serve it at all, and a refusal arriving after that would be a
    /// second settlement for one intent, which `02 §3.2` forbids outright.
    ///
    /// An unanswered intent settles as a timeout rather than as delivered, and
    /// that is deliberate. `SessionEvent` can carry a driver's refusal and
    /// nothing else about an intent, so silence is not evidence that the work
    /// happened; it is the absence of any evidence at all, and reporting it as
    /// `Done` would be the plane inventing the one thing it was not told. The
    /// other half of the answer channel is what `00 R28` still owes.
    async fn serve_natively(
        &self,
        grant: &Grant,
        intent: &AgentIntent,
        step: Step,
        needs_lease: bool,
        now: LeaseInstant,
    ) -> Settlement {
        let id = intent.id;
        let (token, _running) = match self.start_running(grant, id) {
            Ok(started) => started,
            Err(refused) => return refused,
        };

        // The answer slot is taken BEFORE the command goes out. A driver's
        // command pump can refuse in the same turn it receives the command,
        // which is what `ssh-core`'s `route` does, so the refusal can be on the
        // event stream before `send_step` has even returned. A refusal that
        // arrives before the plane is listening is a refusal that is dropped.
        let (_answer, listening) = self.listen_for_answer(id);

        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.inner.config.intent_block_ms);
        let (result, waited) = self.send_step(&step, deadline).await;
        let mut gaps = Gaps {
            blocked_ms: waited.as_millis().min(u128::from(u64::MAX)) as u64,
            ..Gaps::default()
        };
        match result {
            StepResult::Sent => {}
            StepResult::Gone => {
                gaps.commands_dropped = 1;
                gaps.bytes_dropped = step.payload_bytes();
                lock(&self.inner.input).gaps.absorb(gaps);
                let generation = lock(&self.inner.input).fence.current();
                // The same reading an interrupted plan gets: bytes on a socket
                // that is about to die may still have arrived, so the agent is
                // told the intent may or may not have happened rather than
                // being told it failed.
                return Settlement {
                    id,
                    outcome: Outcome::LinkLost { generation },
                    progress: Progress::None,
                    gaps,
                    reason: Some(RefusalReason::LimbGone),
                    payload: Vec::new(),
                };
            }
            // An awaited command is never shed: `send_step` sheds only a `Shed`
            // policy and the lowering gives this one `Await` for the reason
            // written there. The arm is spelled out beside the blocked one
            // rather than folded into a wildcard, so that changing that policy
            // is a decision somebody makes here as well.
            StepResult::Shed | StepResult::Blocked => {
                gaps.commands_dropped = 1;
                gaps.bytes_dropped = step.payload_bytes();
                lock(&self.inner.input).gaps.absorb(gaps);
                return Settlement::refuse_with(
                    id,
                    Refusal::plane(
                        RefusalReason::IntentBlocked,
                        format!(
                            "the session channel on {} stayed full for {} ms and the intent never reached the driver: {}",
                            self.inner.id,
                            self.inner.config.intent_block_ms,
                            gaps.describe()
                        ),
                    ),
                    gaps,
                );
            }
        }
        lock(&self.inner.input).gaps.absorb(gaps);

        // It went, so the hard time to live and the idle revocation restart, on
        // the same rule an actuation follows: only when something actually
        // reached the session, because counting a refusal would let a grant
        // hold a machine by being refused (`08 §5.4`).
        if needs_lease {
            lock(&self.inner.lease).note_intent(grant.id(), now);
        }

        let window = intent.deadline.unwrap_or(NATIVE_ANSWER_WINDOW);
        let answered = tokio::select! {
            answer = listening => answer.ok(),
            () = tokio::time::sleep(window) => None,
            // A withdrawal reaches a native intent the same way it reaches a
            // plan: the intent is over and the settlement says who ended it.
            // What the driver does with a command already on its queue is the
            // driver's, and nothing here pretends to recall it.
            () = token.cancelled() => {
                return Settlement {
                    id,
                    outcome: Outcome::Cancelled,
                    progress: Progress::Delivered(1),
                    gaps,
                    reason: None,
                    payload: Vec::new(),
                }
            }
        };

        match answered {
            // The driver's sentence, verbatim and not summarised, because it is
            // the only party that knows why. `NOT_SUPPORTED` rather than an
            // error: `04 §4.3`'s distinction is that an agent handed an error
            // for something a limb simply does not do will treat a working
            // machine as a broken one, and "not here" is a fact it can plan
            // around. Nothing went on the wire, which is what `IntentRefused`
            // promises, so no progress is claimed.
            Some(Answer::Refused(refusal)) => Settlement::refuse_with(
                id,
                Refusal::limb(RefusalCode::NotSupported, refusal.reason),
                gaps,
            ),
            // `00 R51b`. The driver did the work and said so, so the intent
            // settles on the driver's answer rather than on the clock. Before
            // this arm existed there was no way for it to say so, and the
            // settlement below is what it got: a timeout, after the full
            // deadline, for an intent that had been served in a hundredth of
            // it.
            Some(Answer::Served(served)) => self.settle_served(served, gaps),
            None => Settlement {
                id,
                outcome: Outcome::TimedOut {
                    observed: SettleEvidence {
                        // The limb's own instrument, carried so a reader knows
                        // which of the numbers below could have meant anything.
                        // None of them do here: a native intent is settled by
                        // the driver's answer, not by damage or by bytes, and
                        // the plane saw neither in the window. Zero with the
                        // signal beside it, rather than a number nothing
                        // measured.
                        signal: self.inner.driver.quiescence().signal,
                        quiet_ms: window.as_millis().min(u128::from(u64::MAX)) as u64,
                        damage_rects: 0,
                        bytes: 0,
                    },
                },
                progress: Progress::Delivered(1),
                gaps,
                reason: None,
                payload: Vec::new(),
            },
        }
    }

    /// Turn a driver's served answer into the settlement and the observations
    /// the agent reads.
    ///
    /// Three rules are kept here and each one has a requirement behind it.
    ///
    /// **The exit status is not invented** (`00 R7`, `05 R5.10`). A run whose
    /// status the driver could not answer settles as what actually happened to
    /// it, a timeout or a lost link, and the status keeps its `None` code all
    /// the way to the agent. There is no default of 0 and no default of 1.
    ///
    /// **The output is not dropped in silence** (`00 R24`). A truncated stream
    /// produces an [`Observation::Truncated`] beside the run saying how many
    /// bytes and how many lines went, and the run's own
    /// [`Output::complete`](limb_core::observation::Output::complete) is false.
    /// The partial output still travels, including on a timeout: what arrived
    /// before the deadline is still the agent's output.
    ///
    /// **The output is untrusted** (`AGENT_BRIEF` D6). It crosses from
    /// `remote-core`'s bare `Bytes` into `limb-core`'s `Untrusted` here,
    /// which is the first point at which anything could act on it, and it
    /// carries the geometry generation it was read at because a payload
    /// outlives the geometry it was read against.
    fn settle_served(&self, served: IntentServed, gaps: Gaps) -> Settlement {
        let id = served.id;
        match served.answer {
            ServedAnswer::Ran(run) => {
                let generation = lock(&self.inner.input).fence.current();
                let wrap = |bytes: bytes::Bytes, dropped: Dropped| {
                    Untrusted::new(
                        self.inner.id.clone(),
                        generation,
                        Output {
                            bytes,
                            complete: !dropped.any(),
                        },
                    )
                };

                let stdout_bytes = run.stdout.len() as u64;
                let stderr_bytes = run.stderr.len() as u64;
                let duration_ms = run.duration.as_millis().min(u128::from(u64::MAX)) as u64;

                let mut payload = vec![Observation::Ran {
                    id,
                    status: exit_status(&run.status),
                    stdout: wrap(run.stdout, run.dropped.stdout),
                    stderr: wrap(run.stderr, run.dropped.stderr),
                    duration_ms,
                }];
                for (dropped, at) in [
                    (run.dropped.stdout, TruncationPoint::Stdout),
                    (run.dropped.stderr, TruncationPoint::Stderr),
                ] {
                    if dropped.any() {
                        payload.push(Observation::Truncated {
                            id,
                            dropped_bytes: dropped.bytes,
                            dropped_lines: dropped.lines,
                            at,
                        });
                    }
                }

                let outcome = match run.status.unanswered {
                    // The far side said how it ended, whatever it said. A non
                    // zero exit is `Done`: the command ran, and the number is
                    // the answer rather than a failure of this plane to deliver
                    // it. `06 §5.4` is blunt that neither field here is called
                    // success, and this is why.
                    //
                    // `Unanswered::Tier` lands here too. The command ran and
                    // finished and the tier could not say how, which is a
                    // delivered intent with an honest `None` in it, not a
                    // timeout: nothing timed out.
                    None | Some(Unanswered::Tier) => Outcome::Done {
                        delivered: true,
                        verified: None,
                    },
                    // The deadline passed with the command still running. An
                    // ordinary result and not an error (`04 §4.3`), carrying
                    // what was seen: the bytes that did arrive, which is the
                    // one thing the agent can still act on.
                    Some(Unanswered::Deadline) => Outcome::TimedOut {
                        observed: SettleEvidence {
                            signal: self.inner.driver.quiescence().signal,
                            quiet_ms: duration_ms,
                            damage_rects: 0,
                            bytes: stdout_bytes + stderr_bytes,
                        },
                    },
                    // Note what this does NOT claim. The command may well have
                    // finished on the far side; we were not there to hear it,
                    // so the agent is told the intent may or may not have
                    // happened rather than being told it failed.
                    Some(Unanswered::LinkLost) => Outcome::LinkLost { generation },
                    // `Unanswered` is `#[non_exhaustive]`. A reason this build
                    // does not know is read as a timeout, which is the arm that
                    // claims least: it says the intent ended without an answer
                    // and hands over what was seen, which is true of every
                    // reason there could be one.
                    Some(_) => Outcome::TimedOut {
                        observed: SettleEvidence {
                            signal: self.inner.driver.quiescence().signal,
                            quiet_ms: duration_ms,
                            damage_rects: 0,
                            bytes: stdout_bytes + stderr_bytes,
                        },
                    },
                };

                Settlement {
                    id,
                    outcome,
                    progress: Progress::Delivered(1),
                    gaps,
                    reason: None,
                    payload,
                }
            }
            // `ServedAnswer` is `#[non_exhaustive]`, so an answer shape this
            // build does not know lands here rather than being matched by
            // accident. It is settled and not dropped, because `02 §3.2` has no
            // exception for "we did not recognise the answer": every accepted
            // intent gets exactly one settlement.
            //
            // Never printed, whatever it is. An answer carries what a remote
            // machine produced, and a log line is a second delivery path into a
            // model (`AGENT_BRIEF` D6).
            _ => Settlement::refuse_with(
                id,
                Refusal::limb(
                    RefusalCode::NotSupported,
                    format!(
                        "the driver answered {} with a kind of answer this build cannot read, so nothing could be reported about it",
                        served.name
                    ),
                ),
                gaps,
            ),
        }
    }

    /// Answer an intent from the plane's own bookkeeping, with no wire traffic
    /// at all.
    async fn observe(&self, grant: &Grant, intent: &AgentIntent, now: LeaseInstant) -> Settlement {
        let id = intent.id;
        // The crate reads no clock of its own. `LeaseInstant`'s origin is the
        // caller's and `Timestamp` is unix milliseconds, so a caller that uses
        // unix milliseconds for the lease origin gets two types that agree.
        // See the note on the clock at the crate root.
        let at = Timestamp(now.as_millis());
        match &intent.kind {
            IntentKind::Capture {
                region,
                scale,
                form,
            } => {
                // `00 R39b`: the crop comes from the RECTS list, never from
                // the damage union. `Rect::union` is a bounding box, so two
                // changes in opposite corners union to the whole screen, and
                // sizing a read from it would re-read a whole 4K frame to find
                // two moved pixels.
                let damage = self.inner.observatory.damage_now();
                let region = crate::perception::capture_region(*form, *region, damage.as_ref());
                match self
                    .inner
                    .observatory
                    .observe_frame(grant, id, region, *scale, at)
                {
                    Ok(observation) => Settlement {
                        id,
                        outcome: Outcome::Done {
                            delivered: true,
                            verified: None,
                        },
                        progress: Progress::Delivered(1),
                        gaps: Gaps::default(),
                        reason: None,
                        payload: vec![observation],
                    },
                    Err(refusal) => Settlement::refuse(id, refusal),
                }
            }
            IntentKind::ReadScreen { form, region } => match form {
                limb_core::intent::ReadForm::Pixels => {
                    match self
                        .inner
                        .observatory
                        .observe_frame(grant, id, *region, None, at)
                    {
                        Ok(observation) => Settlement {
                            id,
                            outcome: Outcome::Done {
                                delivered: true,
                                verified: None,
                            },
                            progress: Progress::Delivered(1),
                            gaps: Gaps::default(),
                            reason: None,
                            payload: vec![observation],
                        },
                        Err(refusal) => Settlement::refuse(id, refusal),
                    }
                }
                // A text or cells read is answered from the limb's own
                // character grid and its scrollback, and this crate is not
                // handed either: `agent-perception` owns pixels and `05 §7`
                // owns the terminal's output path. Refused with the sentence
                // that says so rather than answered with an empty string,
                // which would be the plane inventing a value.
                _ => Settlement::refuse(
                    id,
                    Refusal::limb(
                        RefusalCode::NotSupported,
                        "this build's plane reads pixels and damage and is not handed a character grid; a text or cells read is owed by the terminal limb's own output path",
                    ),
                ),
            },
            IntentKind::Wait {
                until,
                quiet,
                timeout,
            } => self.wait(id, until, *quiet, *timeout).await,
            IntentKind::Cancel { target } => {
                let found = self.cancel_running(*target);
                Settlement {
                    id,
                    outcome: Outcome::Done {
                        delivered: found,
                        verified: None,
                    },
                    progress: if found {
                        Progress::Delivered(1)
                    } else {
                        Progress::None
                    },
                    gaps: Gaps::default(),
                    reason: None,
                    payload: Vec::new(),
                }
            }
            other => Settlement::refuse(
                id,
                Refusal::limb(
                    RefusalCode::NotSupported,
                    format!(
                        "{} is answered from the plane's own bookkeeping and this build has no bookkeeping for it",
                        other.name()
                    ),
                ),
            ),
        }
    }

    /// Wait for a condition, from the damage stream and the reported state.
    ///
    /// A timeout is an ORDINARY SETTLEMENT with what was observed, never an
    /// error (`04 §4.3`). An agent that gets an error for a timeout will treat
    /// a slow machine as a broken one.
    async fn wait(
        &self,
        id: IntentId,
        until: &WaitUntil,
        quiet: Option<Duration>,
        timeout: Option<Duration>,
    ) -> Settlement {
        let policy = self.inner.driver.quiescence();
        let quiet = quiet.unwrap_or(policy.default_quiet);
        let timeout = timeout.unwrap_or(Duration::from_secs(30));
        let started = tokio::time::Instant::now();
        let mut last_change = started;
        let mut rects: u32 = 0;

        let met = loop {
            if started.elapsed() >= timeout {
                break false;
            }
            match until {
                WaitUntil::Connected => {
                    if matches!(self.state(), SessionState::Connected) {
                        break true;
                    }
                }
                WaitUntil::ScreenChanged => {
                    if let Some(damage) = self.inner.observatory.damage_now() {
                        rects = rects.saturating_add(damage.rects.len() as u32);
                        break true;
                    }
                }
                WaitUntil::ScreenStable | WaitUntil::Idle => {
                    if let Some(damage) = self.inner.observatory.damage_now() {
                        rects = rects.saturating_add(damage.rects.len() as u32);
                        last_change = tokio::time::Instant::now();
                    } else if last_change.elapsed() >= quiet {
                        break true;
                    }
                }
                // `00 R43` and `02 OQ-3`: text conditions are refused on a
                // limb with no character grid, with a sentence naming the
                // terminal sibling, because matching text on a desktop means
                // reading pixels and this build does no OCR (`03 §6.5`). An
                // exit condition belongs to the command channel `00 R7`
                // specifies and this crate is not handed it.
                //
                // `WaitUntil` is `#[non_exhaustive]`, so the wildcard covers a
                // condition added after this build. Refusing by default is
                // right: the settlement rule says an intent that cannot be
                // settled must be refused, and a wait this build cannot
                // evaluate would otherwise settle as a timeout, which is a
                // plausible answer to a question nobody asked.
                WaitUntil::Text(_) | WaitUntil::TextGone(_) | WaitUntil::Exit | _ => {
                    return Settlement::refuse(
                        id,
                        Refusal::limb(
                            RefusalCode::NotSupported,
                            "this limb has no character grid and this build does no OCR, so there is no honest way to answer a text or exit condition here; ask the terminal limb on the same machine",
                        ),
                    )
                }
            }
            tokio::time::sleep(WAIT_POLL).await;
        };

        let evidence = SettleEvidence {
            signal: policy.signal,
            quiet_ms: last_change.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            damage_rects: rects,
            // Bytes are the terminal limb's instrument and this build's plane
            // does not see them. Reported as zero with the signal beside it
            // rather than omitted, because `SettleEvidence` carries the signal
            // precisely so a reader knows which number means anything.
            bytes: 0,
        };
        if !met {
            return Settlement {
                id,
                outcome: Outcome::TimedOut { observed: evidence },
                progress: Progress::None,
                gaps: Gaps::default(),
                reason: None,
                payload: Vec::new(),
            };
        }
        Settlement {
            id,
            outcome: Outcome::Done {
                delivered: true,
                verified: None,
            },
            progress: Progress::Delivered(1),
            gaps: Gaps::default(),
            reason: None,
            payload: vec![Observation::Quiesced {
                id,
                quiet_ms: evidence.quiet_ms,
                evidence,
                // Whatever the limb said its quiescence is worth. Nothing in
                // this tree can report `Exact` quiescence on a framebuffer and
                // saying so is the point.
                confidence: policy.confidence,
            }],
        }
    }

    /// Put one command on the wire, applying its drop policy.
    ///
    /// Returns how long it spent waiting for room as well as what happened, so
    /// the settlement can report the wait honestly rather than reporting the
    /// whole call, which on a drag is mostly the settle windows the gesture
    /// asked for.
    async fn send_step(
        &self,
        step: &Step,
        deadline: tokio::time::Instant,
    ) -> (StepResult, Duration) {
        // Reaching through to `SessionHandle::commands` rather than calling
        // `SessionHandle::try_send`, and the reason is in the module comment on
        // `backpressure`: `try_send` maps `Full` and `Closed` onto one
        // `SessionGone`, and full means wait or shed while closed means the
        // limb is gone and every outstanding intent settles. The non blocking
        // discipline the comment on `try_send` asks for is preserved exactly;
        // what is not preserved is the flattening.
        let sender = &self.inner.handle.commands;
        let opened = tokio::time::Instant::now();

        if step.policy == SendPolicy::Jump {
            // Exempt from the reservation and from the buckets. A queued
            // repair is not a repair.
            let result = match sender.try_send(step.command.clone()) {
                Ok(()) => StepResult::Sent,
                Err(TrySendError::Closed(_)) => StepResult::Gone,
                Err(TrySendError::Full(command)) => {
                    match tokio::time::timeout_at(deadline, sender.send(command)).await {
                        Ok(Ok(())) => StepResult::Sent,
                        Ok(Err(_)) => StepResult::Gone,
                        Err(_) => StepResult::Blocked,
                    }
                }
            };
            return (result, opened.elapsed());
        }

        let reserved = self.inner.config.reserved_slots(sender.max_capacity());
        loop {
            if sender.capacity() > reserved {
                match sender.try_send(step.command.clone()) {
                    Ok(()) => return (StepResult::Sent, opened.elapsed()),
                    Err(TrySendError::Closed(_)) => return (StepResult::Gone, opened.elapsed()),
                    // Somebody else took the slot between the check and the
                    // send. Fall through to the wait rather than treating it
                    // as a drop.
                    Err(TrySendError::Full(_)) => {}
                }
            }
            if step.policy == SendPolicy::Shed {
                // Stale motion, corrected by the next one, and this is the
                // designed path rather than a failure (`08 §4.6`,
                // `intent_shed`). Counted, never silent.
                return (StepResult::Shed, opened.elapsed());
            }
            if sender.is_closed() {
                return (StepResult::Gone, opened.elapsed());
            }
            if tokio::time::Instant::now() >= deadline {
                return (StepResult::Blocked, opened.elapsed());
            }
            tokio::time::sleep(ROOM_POLL).await;
        }
    }

    /// Remember what the plane put on the wire.
    ///
    /// `15 §4.5` WA-5 in one method: the plane tracks the last pointer mask it
    /// sent per limb, because `vnc-core` tracks none and there is therefore no
    /// state anywhere else to release from.
    fn remember(&self, step: &Step) {
        if let ClientCommand::Pointer { x, y, button_mask } = step.command {
            let mut input = lock(&self.inner.input);
            input.ctx.last_point = Point::new(x, y);
            input.last_mask = button_mask;
        }
    }

    /// The refusal for an intent against a limb that is not `Connected`.
    fn readiness(&self) -> Option<Refusal> {
        match self.state() {
            SessionState::Connected => None,
            SessionState::Reconnecting {
                attempt,
                next_retry_ms,
                reason,
            } => Some(Refusal::limb(
                RefusalCode::NotReady,
                format!(
                    "{} is reconnecting (attempt {attempt}, {reason}); the next try is in {next_retry_ms} ms, so back off rather than spinning",
                    self.inner.id
                ),
            )),
            SessionState::Disconnected { reason, symbol, .. } => Some(Refusal::plane(
                RefusalReason::LimbGone,
                format!(
                    "{} is closed: {reason} ({})",
                    self.inner.id,
                    symbol.unwrap_or_else(|| "no symbol".to_string())
                ),
            )),
            other => Some(Refusal::limb(
                RefusalCode::NotReady,
                format!(
                    "{} is still coming up ({}); wait for connected, which is the only useful call until it is",
                    self.inner.id,
                    state_name(&other)
                ),
            )),
        }
    }

    /// The refusal for an intent from a party that does not hold the wheel.
    ///
    /// Carries the holder's kind and label, which is what an agent needs to
    /// decide between retrying and stopping: `15 §2.2` requires the model to
    /// get one decision right and only one, and the decision is "a person is
    /// driving, stop, do not reacquire".
    fn lease_refusal(&self) -> Refusal {
        let lease = lock(&self.inner.lease);
        let held_by = lease
            .holder()
            .map(|h| format!("{:?} \"{}\"", h.party.kind, h.party.label))
            .unwrap_or_else(|| "nobody".to_string());
        Refusal::limb(
            RefusalCode::LeaseNotHeld,
            format!(
                "the control lease on {} is held by {held_by} and the lease is in {:?}; nothing was sent",
                self.inner.id,
                lease.phase()
            ),
        )
    }

    /// Who took the wheel, for a supersession.
    ///
    /// The party a preemption is running FOR is not reachable from
    /// `agent-lease`'s public API: it lives in the lease's private `pending`
    /// field and neither `holder()` nor `queue()` shows it, so during
    /// `PreemptPending` the holder is still the preempted party and there is
    /// nothing to read. `agent-lease` owes a `pending_party()` accessor, and
    /// it is recorded here rather than worked around silently.
    ///
    /// Until it lands, `Human` is the reading rather than a guess: a
    /// preemption requires strictly higher priority than the holder, and every
    /// DEFAULT rung above an agent on `08 §5.2`'s ladder is person shaped. A
    /// deployment that raised one agent above another with
    /// `Party::with_priority` gets a settlement naming the wrong kind, which
    /// is exactly why the accessor is owed.
    fn superseder(&self, party: &GrantId) -> HolderKind {
        let lease = lock(&self.inner.lease);
        match lease.holder() {
            Some(holder) if &holder.party.id != party => holder.party.kind,
            _ => HolderKind::Human,
        }
    }
}

/// A comma separated list of capability names, for a refusal sentence.
fn list<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The lifecycle state's name, for a refusal an agent reads.
///
/// Written by hand rather than through serde because this is prose in a
/// sentence, not a wire value, and `SessionState`'s serde representation is a
/// contract with `ui/src/lib/types.ts` that this crate must not start
/// depending on for a different purpose.
fn state_name(state: &SessionState) -> &'static str {
    match state {
        SessionState::Idle => "idle",
        SessionState::Resolving => "resolving",
        SessionState::Connecting => "connecting",
        SessionState::Authenticating { .. } => {
            "authenticating, which means a person is being asked for a credential"
        }
        SessionState::Negotiating => "negotiating",
        SessionState::Connected => "connected",
        SessionState::Reconnecting { .. } => "reconnecting",
        SessionState::Disconnected { .. } => "disconnected",
    }
}
