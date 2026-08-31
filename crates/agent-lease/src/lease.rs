//! The lease itself: one per limb, and the only mutable thing in the crate.
//!
//! Every rule here comes from `08 §5.4` and `08 §6`, and every one of them is
//! a pure function of the state plus the instant the caller handed in. There
//! is no timer, no task and no channel: `tick` is the whole of time.
//!
//! ## The discipline: tick, then act
//!
//! [`Lease::tick`] is the only method that applies elapsed time. An expired
//! holder is *not* swept up inside [`Lease::acquire`], and that is deliberate
//! rather than an oversight. An expiry is a lease change, and R11 says every
//! lease change owes the limb a release of held input; if `acquire` expired a
//! holder on the way past, that obligation would have to be smuggled out
//! inside a transition whose whole job is to describe a grant, and the
//! caller would have exactly one `ReleaseAllKeys` to cover two events it
//! never heard about. So a caller ticks first and acts second, and a caller
//! that forgets sees a stale holder keep the wheel, which is a visible bug
//! rather than a silent stuck modifier.

use crate::clock::LeaseInstant;
use crate::error::LeaseError;
use crate::party::{Holder, HolderKind, LeaseId, LimbId, Party, PartyId, Waiter};
use crate::policy::{LeaseConfig, LeaseMode, LeasePolicy};
use crate::transition::{
    Departure, DepartureCause, Fencing, LeaseOutcome, LeasePhase, LeaseTransition, LeaseView,
    ReleaseObligation,
};

/// A request for control.
///
/// It carries no mode. That is `08 §5.3`, adopted from BrowserGlass whole:
/// arbitration has to be single valued for a contended resource, so the mode
/// belongs to the limb and the only thing a caller genuinely chooses is
/// whether to ask at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcquireRequest {
    /// Who is asking.
    pub party: Party,
    /// What for, passed through untouched to the pane and the trace.
    pub reason: Option<String>,
    /// Whether to wait if the lease cannot be had immediately. `08 §5.4`
    /// makes this default to true, because an agent that asked for a machine
    /// usually still wants it in a second and a caller that does not can say
    /// so.
    pub queue: bool,
}

impl AcquireRequest {
    /// A request that queues if it has to.
    #[must_use]
    pub fn new(party: Party) -> Self {
        AcquireRequest {
            party,
            reason: None,
            queue: true,
        }
    }

    /// Say what the control is for.
    #[must_use]
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Refuse rather than wait. For a caller that has something else to do
    /// with the time, and for a pane that would rather show "an agent is
    /// driving" than a spinner.
    #[must_use]
    pub fn no_queue(mut self) -> Self {
        self.queue = false;
        self
    }
}

/// The party a preemption is running for, and the instant it stops being
/// polite about it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    waiter: Waiter,
    deadline: LeaseInstant,
}

/// Who is driving one limb, and what happens when somebody else wants the
/// wheel.
///
/// One per limb, which is what lets a person drive limb 3 while an agent
/// drives limbs 1, 2 and 4 (`08 §5.1`).
#[derive(Clone, Debug)]
pub struct Lease {
    limb: LimbId,
    mode: LeaseMode,
    policy: LeasePolicy,
    phase: LeasePhase,
    holder: Option<Holder>,
    pending: Option<Pending>,
    queue: Vec<Waiter>,
    next_lease_id: u64,
    force_release_until: Option<LeaseInstant>,
}

impl Lease {
    /// Build a lease for a limb.
    ///
    /// Fails only on [`LeaseMode::Shared`], which this version does not
    /// build. See [`LeaseError::SharedModeUnavailable`] for why that is a
    /// refusal and not a warning.
    ///
    /// # Errors
    ///
    /// [`LeaseError::SharedModeUnavailable`] if the config asks for shared
    /// control.
    pub fn new(limb: impl Into<LimbId>, config: LeaseConfig) -> Result<Self, LeaseError> {
        if config.mode == LeaseMode::Shared {
            return Err(LeaseError::SharedModeUnavailable);
        }
        Ok(Lease {
            limb: limb.into(),
            mode: config.mode,
            policy: config.policy,
            phase: LeasePhase::Unheld,
            holder: None,
            pending: None,
            queue: Vec::new(),
            // Starts at one so a zero in a log is obviously a grant that never
            // happened rather than the first one.
            next_lease_id: 1,
            force_release_until: None,
        })
    }

    /// An exclusive lease on the defaults from `08 §5.4`. The shape every
    /// limb in this version gets, so it is worth not making callers unwrap a
    /// result that cannot fail.
    #[must_use]
    pub fn exclusive(limb: impl Into<LimbId>) -> Self {
        Lease {
            limb: limb.into(),
            mode: LeaseMode::Exclusive,
            policy: LeasePolicy::default(),
            phase: LeasePhase::Unheld,
            holder: None,
            pending: None,
            queue: Vec::new(),
            next_lease_id: 1,
            force_release_until: None,
        }
    }

    /// Which limb this lease arbitrates.
    #[must_use]
    pub fn limb(&self) -> &LimbId {
        &self.limb
    }

    /// Exclusive or shared.
    #[must_use]
    pub fn mode(&self) -> LeaseMode {
        self.mode
    }

    /// The timers in force.
    #[must_use]
    pub fn policy(&self) -> &LeasePolicy {
        &self.policy
    }

    /// Where the lease is.
    #[must_use]
    pub fn phase(&self) -> LeasePhase {
        self.phase
    }

    /// The current holder, with its id.
    ///
    /// For the plane, which owns the map from a party to a transport. What
    /// gets broadcast to the parties themselves is [`Lease::view_for`], which
    /// carries the holder's kind and label and never its id.
    #[must_use]
    pub fn holder(&self) -> Option<&Holder> {
        self.holder.as_ref()
    }

    /// How many parties are waiting.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }

    /// Everyone waiting, highest priority first and in the order they asked
    /// within a priority.
    #[must_use]
    pub fn queue(&self) -> &[Waiter] {
        &self.queue
    }

    /// Where this party stands in the queue, counted from zero.
    #[must_use]
    pub fn queue_position(&self, party: &PartyId) -> Option<usize> {
        self.queue.iter().position(|w| &w.party.id == party)
    }

    /// What this party is told about the lease (`08 §5.5`).
    #[must_use]
    pub fn view_for(&self, party: &PartyId) -> LeaseView {
        LeaseView {
            limb: self.limb.clone(),
            mode: self.mode,
            phase: self.phase,
            holder_kind: self.holder.as_ref().map(|h| h.party.kind),
            holder_label: self.holder.as_ref().map(|h| h.party.label.clone()),
            you_hold: self.holder.as_ref().is_some_and(|h| &h.party.id == party),
            queue_depth: self.queue.len(),
            queue_position: self.queue_position(party),
        }
    }

    /// May this party's intents be dispatched right now?
    ///
    /// The answer is never a flat no. A party that is not the dispatching
    /// holder still gets [`Fencing::ReleaseOnly`], because a release has to go
    /// through even on a dead or stale lease or a departing driver leaves a
    /// button or a modifier stuck (`08 §6.2` ruling B).
    ///
    /// Note what this returns the instant the phase leaves
    /// [`LeasePhase::Held`]: the holder loses [`Fencing::Allowed`] on the
    /// spot, without being asked and without acknowledging. That is `08 §6.1`
    /// step 5, and it is the property that makes the takeover safe. Nothing
    /// the preempted party does or fails to do can let another intent
    /// through.
    #[must_use]
    pub fn fence(&self, party: &PartyId) -> Fencing {
        let holds = self.holder.as_ref().is_some_and(|h| &h.party.id == party);
        if holds && self.phase == LeasePhase::Held {
            Fencing::Allowed
        } else {
            Fencing::ReleaseOnly
        }
    }

    /// Ask for control.
    ///
    /// The ladder decides, in this order (`08 §5.4`):
    ///
    /// 1. Unheld: granted.
    /// 2. Held by somebody lower: preemption starts, and the requester is
    ///    granted when it settles.
    /// 3. Held by somebody equal or higher: queued, or refused if the request
    ///    said not to queue.
    /// 4. Queue at its cap: refused.
    ///
    /// Two checks that `08 §5.4` lists first are deliberately *not* here. The
    /// capability check (does this grant carry `control`, `09 §3`) and the
    /// rate check (the `control` bucket for this grant and limb, `08 §3.1`)
    /// both belong above this crate: one needs to know what a grant is and
    /// the other needs a clock of its own. Arbitration is what is left when
    /// those are taken out, and it is the part worth testing on its own.
    ///
    /// # Errors
    ///
    /// Every variant of [`LeaseError`] except
    /// [`LeaseError::SharedModeUnavailable`], each naming what the caller can
    /// do next.
    pub fn acquire(
        &mut self,
        request: AcquireRequest,
        now: LeaseInstant,
    ) -> Result<LeaseTransition, LeaseError> {
        let from = self.phase;

        // The panic chord's backoff, checked before anything else. Without it
        // an agent in a loop re acquires before the person who hit it can
        // click anything (`08 §6.3`).
        if let Some(until) = self.force_release_until {
            if !now.reached(until) {
                return Err(LeaseError::ForceReleased {
                    retry_after_ms: until.since(now),
                });
            }
            self.force_release_until = None;
        }

        // The holder asking again is a renew, not a second grant. It keeps
        // its lease id: minting a new one would invalidate the id the party
        // is holding and turn its own cleanup path into a no op.
        if let Some(holder) = self.holder.as_mut() {
            if holder.party.id == request.party.id {
                holder.last_renew_at = now;
                let lease_id = holder.lease_id;
                return Ok(self.draft(
                    now,
                    from,
                    LeaseOutcome::Renewed { lease_id },
                    ReleaseObligation::NotRequired,
                ));
            }
        }

        // Asking twice while a preemption is already running for you tells
        // you where it stands rather than starting a second one.
        if let Some(pending) = &self.pending {
            if pending.waiter.party.id == request.party.id {
                let deadline = pending.deadline;
                let requester = pending.waiter.party.clone();
                return Ok(self.draft(
                    now,
                    from,
                    LeaseOutcome::PreemptionStarted {
                        deadline,
                        requester,
                    },
                    ReleaseObligation::NotRequired,
                ));
            }
        }

        // Asking twice while queued returns the position instead of taking a
        // second slot. An agent that retries on a timer would otherwise fill
        // the queue with itself and lock everyone else out at the cap.
        if let Some(position) = self.queue_position(&request.party.id) {
            return Ok(self.draft(
                now,
                from,
                LeaseOutcome::Queued { position },
                ReleaseObligation::NotRequired,
            ));
        }

        if self.phase == LeasePhase::Unheld {
            return Ok(self.grant(request.party, now, from));
        }
        self.contest(request, now, from)
    }

    /// Let go.
    ///
    /// Idempotent, and infallible on purpose. A release quoting a lease id
    /// that is no longer current is a no op that reports success, because a
    /// party trying to release something it no longer holds has already
    /// achieved what it wanted (`08 §5.4`). The path that does this in
    /// practice is a crashed agent's cleanup, and turning that into an error
    /// would mean the last thing a dying agent does is log a failure about
    /// something that is already fine.
    pub fn release(
        &mut self,
        party: &PartyId,
        lease_id: LeaseId,
        now: LeaseInstant,
    ) -> LeaseTransition {
        let from = self.phase;
        let is_current = self
            .holder
            .as_ref()
            .is_some_and(|h| &h.party.id == party && h.lease_id == lease_id);
        if !is_current {
            return self.draft(
                now,
                from,
                LeaseOutcome::Unchanged,
                ReleaseObligation::NotRequired,
            );
        }
        let departed = self.take_holder(now, DepartureCause::Released);
        self.settle(now, from, departed)
    }

    /// Give up waiting.
    ///
    /// The queue's half of [`Lease::release`], and a no op for a party that
    /// is not waiting. A party that withdrew must not be handed the wheel
    /// later: control granted to somebody who stopped asking is a machine
    /// nobody is watching.
    ///
    /// Withdrawing while a preemption is running for you calls the
    /// preemption off and the previous holder keeps the lease.
    pub fn cancel_wait(&mut self, party: &PartyId, now: LeaseInstant) -> LeaseTransition {
        let from = self.phase;

        if self
            .pending
            .as_ref()
            .is_some_and(|p| &p.waiter.party.id == party)
        {
            self.pending = None;
            let connected = self.holder.as_ref().is_some_and(|h| h.connected);
            self.phase = if connected {
                LeasePhase::Held
            } else {
                LeasePhase::HeldGrace
            };
            // The holder gets dispatch back, so the obligation applies. It is
            // redundant in the common case (the release already went out when
            // the phase became `PreemptPending`) and it is kept anyway: see
            // the crate note on why a redundant release is the cheap side of
            // this trade.
            return self.draft(
                now,
                from,
                LeaseOutcome::PreemptionAbandoned,
                ReleaseObligation::Required,
            );
        }

        match self.queue_position(party) {
            Some(position) => {
                self.queue.remove(position);
                self.draft(
                    now,
                    from,
                    LeaseOutcome::WaitCancelled,
                    ReleaseObligation::NotRequired,
                )
            }
            None => self.draft(
                now,
                from,
                LeaseOutcome::Unchanged,
                ReleaseObligation::NotRequired,
            ),
        }
    }

    /// The panic chord (`08 §6.3`, R13).
    ///
    /// A revocation, not a request: the holder is gone the moment this
    /// returns, the queue is emptied, and there is no grace window. R13 is
    /// blunt about why. BrowserGlass's own demo measures 2,008 ms for a
    /// polite handover, which is two seconds of somebody pressing a button
    /// labelled stop while nothing happens.
    ///
    /// The obligation is always [`ReleaseObligation::Required`], even when
    /// this crate believes nobody was holding anything. A stuck grab is
    /// exactly the case where the plane's belief about what is held is the
    /// thing that turned out to be wrong, and one redundant release is a
    /// price worth paying for a button whose entire job is to work.
    ///
    /// Every acquire on this limb is then refused for
    /// [`LeasePolicy::force_release_backoff_ms`].
    pub fn force_release(&mut self, now: LeaseInstant) -> LeaseTransition {
        let from = self.phase;
        let departed = self.take_holder(now, DepartureCause::ForceReleased);
        let mut dropped: Vec<Waiter> = self.pending.take().map(|p| p.waiter).into_iter().collect();
        dropped.append(&mut self.queue);
        self.phase = LeasePhase::Unheld;
        self.force_release_until = Some(now.plus(self.policy.force_release_backoff_ms));

        let mut transition =
            self.draft(now, from, LeaseOutcome::Unheld, ReleaseObligation::Required);
        transition.departed = departed;
        transition.expired_waiters = dropped;
        transition
    }

    /// Report that the release owed by R11 reached the limb.
    ///
    /// The new holder's intents are fenced until this is called, so a caller
    /// that ignores the obligation gets a limb nobody can drive rather than a
    /// stuck Ctrl. That asymmetry is chosen: a lease that will not hand over
    /// is a bug somebody notices in a second, and a modifier held down on a
    /// remote machine is a bug somebody notices after typing a paragraph into
    /// a keyboard shortcut.
    ///
    /// There is no timer on [`LeasePhase::HandingOver`] on purpose. How long
    /// a small write to a limb takes is a number this crate has no way to
    /// know and every way to get wrong on a slow link.
    pub fn confirm_release(&mut self, now: LeaseInstant) -> LeaseTransition {
        let from = self.phase;
        if from != LeasePhase::HandingOver {
            return self.draft(
                now,
                from,
                LeaseOutcome::Unchanged,
                ReleaseObligation::NotRequired,
            );
        }
        self.phase = LeasePhase::Held;
        let mut lease_id = LeaseId::from_u64(0);
        if let Some(holder) = self.holder.as_mut() {
            // The clocks start at the flip, not at the grant. The holder
            // could not dispatch anything before now, and revoking somebody
            // for being idle during a window where they were fenced would be
            // punishing them for the plane's own queue hop.
            holder.last_intent_at = now;
            holder.last_renew_at = now;
            lease_id = holder.lease_id;
        }
        self.draft(
            now,
            from,
            LeaseOutcome::HandoverComplete { lease_id },
            ReleaseObligation::NotRequired,
        )
    }

    /// The holder's transport went away, or came back.
    ///
    /// A holder whose transport dropped keeps the lease for
    /// [`LeasePolicy::disconnect_grace_ms`] so a reconnect does not lose the
    /// wheel (`08 §5.4`). It does not keep dispatch: the phase leaves
    /// [`LeasePhase::Held`], so [`Lease::fence`] stops saying yes at once,
    /// and the obligation applies in both directions. The cost is honest and
    /// worth writing down: a holder that reconnects gets its lease back and
    /// not its modifiers.
    pub fn set_connected(
        &mut self,
        party: &PartyId,
        connected: bool,
        now: LeaseInstant,
    ) -> LeaseTransition {
        let from = self.phase;
        let is_holder = self.holder.as_ref().is_some_and(|h| &h.party.id == party);
        let changed = self
            .holder
            .as_ref()
            .is_some_and(|h| h.connected != connected);
        if !is_holder || !changed {
            return self.draft(
                now,
                from,
                LeaseOutcome::Unchanged,
                ReleaseObligation::NotRequired,
            );
        }

        let grace_until = if connected {
            None
        } else {
            Some(now.plus(self.policy.disconnect_grace_ms))
        };
        if let Some(holder) = self.holder.as_mut() {
            holder.connected = connected;
            // Set even when the phase does not move (a transport that drops
            // during a preemption), so the deadline is already there if the
            // preemption is called off and the lease falls back to
            // `HeldGrace`.
            holder.grace_until = grace_until;
        }

        self.phase = match (self.phase, connected) {
            (LeasePhase::Held, false) => LeasePhase::HeldGrace,
            (LeasePhase::HeldGrace, true) => LeasePhase::Held,
            (phase, _) => phase,
        };

        self.draft(
            now,
            from,
            LeaseOutcome::Unchanged,
            ReleaseObligation::Required,
        )
    }

    /// The holder dispatched something. Resets both the hard time to live and
    /// the idle revocation.
    ///
    /// Returns nothing, and that is the rule rather than an inconsistency:
    /// this cannot change who is allowed to dispatch, so there is no lease
    /// change and nothing is owed to the limb. Only calls that can move the
    /// phase hand back a [`LeaseTransition`].
    pub fn note_intent(&mut self, party: &PartyId, now: LeaseInstant) {
        if let Some(holder) = self.holder.as_mut() {
            if &holder.party.id == party {
                holder.last_intent_at = now;
            }
        }
    }

    /// The holder said it is still there. Resets the hard time to live and
    /// deliberately not the idle revocation.
    ///
    /// That asymmetry is the whole reason there are two timers. A renew is
    /// evidence the party is alive; it is not evidence the party is doing
    /// anything, and a crashed agent whose socket is still open renews
    /// forever.
    pub fn renew(&mut self, party: &PartyId, now: LeaseInstant) {
        if let Some(holder) = self.holder.as_mut() {
            if &holder.party.id == party {
                holder.last_renew_at = now;
            }
        }
    }

    /// Apply elapsed time. The only method in the crate that does.
    ///
    /// In one pass, in this order:
    ///
    /// 1. waiters past [`LeasePolicy::queue_ttl_ms`] are dropped, before any
    ///    promotion can hand one of them the wheel;
    /// 2. a preemption past its deadline flips;
    /// 3. a disconnect grace that ran out revokes;
    /// 4. a holder past the hard time to live, or past the idle revocation,
    ///    is removed;
    /// 5. whoever is next gets it.
    ///
    /// One transition comes back because at most one holder can change in a
    /// single instant, and dropped waiters ride along in
    /// [`LeaseTransition::expired_waiters`] because the plane owes each of
    /// them a `queue_expired` message.
    pub fn tick(&mut self, now: LeaseInstant) -> LeaseTransition {
        let from = self.phase;

        if let Some(until) = self.force_release_until {
            if now.reached(until) {
                self.force_release_until = None;
            }
        }

        let ttl = self.policy.queue_ttl_ms;
        let mut expired = Vec::new();
        self.queue.retain(|w| {
            if now.since(w.queued_at) >= ttl {
                expired.push(w.clone());
                false
            } else {
                true
            }
        });

        let mut transition = self.tick_holder(now, from);
        transition.expired_waiters = expired;
        transition.queue_depth = self.queue.len();
        transition
    }

    // The contested half of `acquire`, split out only because the borrow of
    // the holder has to end before the queue can be touched.
    fn contest(
        &mut self,
        request: AcquireRequest,
        now: LeaseInstant,
        from: LeasePhase,
    ) -> Result<LeaseTransition, LeaseError> {
        let Some(holder) = self.holder.as_ref() else {
            // Unreachable: every phase but `Unheld` has a holder. Recovering
            // rather than panicking because a panic in an arbitration path
            // takes the plane down with it, and the recovery is the same
            // thing the invariant says should happen.
            return Ok(self.grant(request.party, now, from));
        };
        let holder_kind = holder.party.kind;
        let holder_label = holder.party.label.clone();
        let holder_priority = holder.party.priority;
        let holder_connected = holder.connected;
        let granted_at = holder.granted_at;

        let held = LeaseError::Held {
            holder_kind,
            holder_label,
        };

        // Equal priority queues rather than steals. Equal parties taking turns
        // by force would let two panes on the same machine trade the wheel on
        // every click, and neither would ever finish a drag.
        if request.party.priority <= holder_priority {
            return self.queue_or_refuse(request, now, from, held);
        }

        // Somebody has already been promised the wheel. Queue behind them
        // rather than starting a second preemption: two in flight against one
        // holder has no honest answer to "who gets it".
        if matches!(
            self.phase,
            LeasePhase::PreemptPending | LeasePhase::HandingOver
        ) {
            return self.queue_or_refuse(request, now, from, held);
        }

        // The floor, and the one pairing that lifts it (`08 §6.1` step 3).
        // Lifting it grants no new preemption right: the priority test above
        // still had to pass on its own.
        let floor_lifted = request.party.kind.is_person() && holder_kind == HolderKind::Agent;
        let held_for = now.since(granted_at);
        if !floor_lifted && held_for < self.policy.min_hold_ms {
            let refusal = LeaseError::MinHoldNotElapsed {
                retry_after_ms: self.policy.min_hold_ms - held_for,
            };
            return self.queue_or_refuse(request, now, from, refusal);
        }

        if !holder_connected {
            // Nothing is going to acknowledge. Waiting the full preemption
            // grace for an answer that cannot come is R13's two seconds of a
            // person pressing a button while nothing happens, so the lease
            // flips now.
            return Ok(self.take_over(request.party, now, from));
        }

        let deadline = now.plus(self.policy.agent_preempt_grace_ms);
        let requester = request.party.clone();
        self.pending = Some(Pending {
            waiter: Waiter {
                party: request.party,
                queued_at: now,
                reason: request.reason,
            },
            deadline,
        });
        // Dispatch stops here, before the holder has been told and whatever
        // it does about it (`08 §6.1` step 5), which is why the obligation
        // lands on this transition and not on the flip.
        self.phase = LeasePhase::PreemptPending;
        Ok(self.draft(
            now,
            from,
            LeaseOutcome::PreemptionStarted {
                deadline,
                requester,
            },
            ReleaseObligation::Required,
        ))
    }

    fn queue_or_refuse(
        &mut self,
        request: AcquireRequest,
        now: LeaseInstant,
        from: LeasePhase,
        refusal: LeaseError,
    ) -> Result<LeaseTransition, LeaseError> {
        if !request.queue {
            return Err(refusal);
        }
        if self.queue.len() >= self.policy.max_queue_depth {
            // Refuses rather than growing. A queue that grows past its bound
            // hands out control in an order nobody chose, long after every
            // waiter has moved on (`08 §4.2`).
            return Err(LeaseError::QueueFull {
                depth: self.queue.len(),
            });
        }
        // Priority descending, and first come first served inside a priority.
        let position = self
            .queue
            .iter()
            .position(|w| w.party.priority < request.party.priority)
            .unwrap_or(self.queue.len());
        self.queue.insert(
            position,
            Waiter {
                party: request.party,
                queued_at: now,
                reason: request.reason,
            },
        );
        Ok(self.draft(
            now,
            from,
            LeaseOutcome::Queued { position },
            ReleaseObligation::NotRequired,
        ))
    }

    fn tick_holder(&mut self, now: LeaseInstant, from: LeasePhase) -> LeaseTransition {
        let unchanged = |lease: &Self| {
            lease.draft(
                now,
                from,
                LeaseOutcome::Unchanged,
                ReleaseObligation::NotRequired,
            )
        };

        match self.phase {
            LeasePhase::PreemptPending => {
                let due = self
                    .pending
                    .as_ref()
                    .is_some_and(|p| now.reached(p.deadline));
                if !due {
                    return unchanged(self);
                }
                let departed = self.take_holder(now, DepartureCause::Preempted);
                self.settle(now, from, departed)
            }
            LeasePhase::HeldGrace => {
                let due = self
                    .holder
                    .as_ref()
                    .and_then(|h| h.grace_until)
                    .is_some_and(|deadline| now.reached(deadline));
                if !due {
                    return unchanged(self);
                }
                let departed = self.take_holder(now, DepartureCause::DisconnectGraceElapsed);
                self.settle(now, from, departed)
            }
            LeasePhase::Held => {
                let Some(holder) = self.holder.as_ref() else {
                    return unchanged(self);
                };
                let cause = if now.since(holder.last_activity()) >= self.policy.lease_ttl_ms {
                    DepartureCause::Expired
                } else if now.since(holder.last_intent_at) >= self.policy.idle_revoke_ms {
                    DepartureCause::IdleRevoked
                } else {
                    return unchanged(self);
                };
                let departed = self.take_holder(now, cause);
                self.settle(now, from, departed)
            }
            // Nothing waits on a clock here. `Unheld` with a non empty queue
            // cannot happen, because a party asking while unheld is granted
            // rather than queued.
            LeasePhase::Unheld | LeasePhase::HandingOver => unchanged(self),
        }
    }

    fn take_holder(&mut self, now: LeaseInstant, cause: DepartureCause) -> Option<Departure> {
        let holder = self.holder.take()?;
        Some(Departure {
            held_for_ms: now.since(holder.granted_at),
            party: holder.party,
            lease_id: holder.lease_id,
            cause,
        })
    }

    // Who gets it now that the holder is gone: the party a preemption was
    // running for, then the head of the queue, then nobody.
    fn settle(
        &mut self,
        now: LeaseInstant,
        from: LeasePhase,
        departed: Option<Departure>,
    ) -> LeaseTransition {
        let successor = self
            .pending
            .take()
            .map(|p| p.waiter.party)
            .or_else(|| (!self.queue.is_empty()).then(|| self.queue.remove(0).party));

        let mut transition = match successor {
            Some(party) => self.grant(party, now, from),
            None => {
                self.phase = LeasePhase::Unheld;
                self.draft(now, from, LeaseOutcome::Unheld, ReleaseObligation::Required)
            }
        };
        transition.departed = departed;
        transition
    }

    fn take_over(&mut self, party: Party, now: LeaseInstant, from: LeasePhase) -> LeaseTransition {
        let departed = self.take_holder(now, DepartureCause::Preempted);
        self.pending = None;
        let mut transition = self.grant(party, now, from);
        transition.departed = departed;
        transition
    }

    fn grant(&mut self, party: Party, now: LeaseInstant, from: LeasePhase) -> LeaseTransition {
        let lease_id = LeaseId::from_u64(self.next_lease_id);
        self.next_lease_id += 1;
        self.holder = Some(Holder {
            lease_id,
            party: party.clone(),
            granted_at: now,
            last_intent_at: now,
            last_renew_at: now,
            // A party that just asked for the lease has a transport to have
            // asked over.
            connected: true,
            grace_until: None,
        });
        // Not `Held`. R11 owes the limb a release before this party's first
        // intent, and the phase is how that obligation is enforced rather
        // than merely reported.
        self.phase = LeasePhase::HandingOver;
        self.draft(
            now,
            from,
            LeaseOutcome::Granted {
                lease_id,
                holder: party,
            },
            ReleaseObligation::Required,
        )
    }

    fn draft(
        &self,
        at: LeaseInstant,
        from: LeasePhase,
        outcome: LeaseOutcome,
        release: ReleaseObligation,
    ) -> LeaseTransition {
        LeaseTransition {
            limb: self.limb.clone(),
            at,
            from,
            to: self.phase,
            outcome,
            release,
            departed: None,
            expired_waiters: Vec::new(),
            queue_depth: self.queue.len(),
        }
    }
}
