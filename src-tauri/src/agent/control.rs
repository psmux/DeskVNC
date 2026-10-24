//! Who is driving each session: one lease per session, kept here, for every
//! agent and the person at the window.
//!
//! ## Why it moved here
//!
//! The lease used to live in each agent's own process. Each `dvv mcp` server
//! and each `dvv hold` had its own, holding only itself, so it always said
//! yes, and the viewer rendered whatever the process last reported. Four
//! things went wrong because of that, and they are the reason for this file:
//!
//! 1. An agent process reported itself holding the moment it attached and
//!    never reported letting go, so a pane showed an agent driving for as
//!    long as the process lived, which for an MCP server is the whole of the
//!    agent's session.
//! 2. A person's pointer going down anywhere in that pane, even the click
//!    that only moves keyboard focus and never reaches the remote machine,
//!    revoked the attachment for good. Nothing ever cleared it, every later
//!    command was refused with a sentence telling the agent to stop, and the
//!    agent did.
//! 3. A second agent attaching to the same session replaced the first one's
//!    row, so the first was refused as not attached instead of waiting its
//!    turn. Nothing contended for anything.
//! 4. A connection that ended left its row behind, still "driving".
//!
//! So the viewer keeps an [`agent_lease::Board`], one lease per session, and
//! every party asks it: each attachment as an agent, and the person at the
//! window as a person. The board is ticked on a timer ([`tick_leases`]), so a
//! lease nobody is using frees itself with nobody calling.
//!
//! ## What counts as use
//!
//! Input, and only input. For an agent that is a pointer event or a key press
//! reaching `limb.command`. For a person it is a key or a button reaching
//! `send_input`; a bare pointer move is not, so a mouse passing over a pane
//! takes nothing, and focusing a pane or looking at it takes nothing either.
//! A status call, an acquire from the holder, a screen read: none of them
//! moves anybody's idle clock.

use super::AgentPlane;
use agent_lease::{
    Answer, DepartureCause, HolderKind, LeaseInstant, LeaseOutcome, LeaseStatus, Party, PartyId,
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// The party id the person at the window arbitrates as. One person per
/// viewer: two windows on one session are the same person's two hands.
pub const PERSON: &str = "person";

/// How often the board is ticked.
///
/// Twice a second, so a timer fires within half a second of its deadline. The
/// tick is a lock and a comparison per session with a lease, a handful at
/// most, and it emits nothing unless something moved.
pub const TICK_INTERVAL: Duration = Duration::from_millis(500);

fn origin() -> Instant {
    static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

/// The lease clock: milliseconds since this process first asked. Monotonic,
/// which is the only thing `agent-lease` asks of a clock.
pub fn lease_now() -> LeaseInstant {
    LeaseInstant::from_millis(origin().elapsed().as_millis() as u64)
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// The person, as the board sees them.
pub fn person() -> Party {
    Party::new(PERSON, HolderKind::Human, "a person in DeskVNCViewer")
}

fn kind_name(kind: HolderKind) -> &'static str {
    match kind {
        HolderKind::Admin => "admin",
        HolderKind::Owner => "owner",
        HolderKind::Human => "human",
        HolderKind::Agent => "agent",
    }
}

fn phase_name(phase: agent_lease::LeasePhase) -> &'static str {
    use agent_lease::LeasePhase;
    match phase {
        LeasePhase::Unheld => "free",
        LeasePhase::Held => "held",
        LeasePhase::HeldGrace => "held-grace",
        LeasePhase::PreemptPending => "preempt-pending",
        LeasePhase::HandingOver => "handing-over",
    }
}

fn seconds(ms: u64) -> String {
    format!("{:.0} s", (ms as f64 / 1000.0).ceil())
}

/// A lease status as JSON, addressed to one attachment (or to nobody).
///
/// Every time is a duration from now, plus `heldSince` as unix milliseconds,
/// so neither side needs the other's clock.
pub fn status_json(
    status: &LeaseStatus,
    me: Option<&str>,
    policy: &agent_lease::LeasePolicy,
) -> Value {
    let me = me.map(PartyId::from);
    let mine = |id: &PartyId| me.as_ref() == Some(id);
    let holder = status.holder.as_ref().map(|h| {
        json!({
            "kind": kind_name(h.kind),
            "label": h.label,
            "attachmentId": (h.kind == HolderKind::Agent).then(|| h.id.to_string()),
            "you": mine(&h.id),
            "since": unix_ms().saturating_sub(h.held_for_ms),
            "heldForMs": h.held_for_ms,
            "idleForMs": h.idle_for_ms,
        })
    });
    let waiter = |w: &agent_lease::WaiterStatus| {
        json!({
            "kind": kind_name(w.kind),
            "label": w.label,
            "you": mine(&w.id),
            "waitingMs": w.waiting_ms,
        })
    };
    json!({
        "phase": phase_name(status.phase),
        "holder": holder,
        "queue": status.queue.iter().map(waiter).collect::<Vec<_>>(),
        "preempting": status.preempting.as_ref().map(waiter),
        "youHold": me.as_ref().is_some_and(|id| status.held_by(id)),
        "dispatching": me.as_ref().is_some_and(|id| status.dispatching(id)),
        "yourPosition": me.as_ref().and_then(|id| status.position_of(id)),
        "personHolds": status.person_holds(),
        "changesInMs": status.changes_in_ms,
        "refusedForMs": status.refused_for_ms,
        "timers": {
            "agentIdleMs": policy.idle_revoke_ms,
            "personIdleMs": policy.person_idle_ms,
            "contendedIdleMs": policy.contended_idle_ms,
        },
    })
}

/// The sentence an agent reads when it does not have the wheel: who has it,
/// how long they have been quiet, and exactly when it can have it.
pub fn not_yours(
    session_id: &str,
    status: &LeaseStatus,
    policy: &agent_lease::LeasePolicy,
) -> String {
    if let Some(left) = status.refused_for_ms {
        return format!(
            "a person pressed stop on {session_id}; agents may ask again in {}. Nothing was sent. Call dvv_control acquire, which waits for it",
            seconds(left)
        );
    }
    let changes = status
        .changes_in_ms
        .map(|ms| {
            format!(
                " It changes hands by itself in {} if nothing more comes from them.",
                seconds(ms)
            )
        })
        .unwrap_or_default();
    match (&status.holder, &status.preempting) {
        (_, Some(w)) if w.kind.is_person() => format!(
            "a person is taking over {session_id} in DeskVNCViewer. Nothing was sent. Agents get it back {} after the person's last input: call dvv_control acquire, which waits for it",
            seconds(policy.person_idle_ms)
        ),
        (Some(h), _) if h.kind.is_person() => format!(
            "a person is using {session_id} in DeskVNCViewer (last input {} ago). Nothing was sent. Agents get it back {} after their last input.{changes} Call dvv_control acquire, which waits for it",
            seconds(h.idle_for_ms),
            seconds(policy.person_idle_ms)
        ),
        (Some(h), _) => format!(
            "{} holds {session_id} (for {}, last input {} ago). Nothing was sent. Call dvv_control acquire: it queues you, and if that holder sends nothing for {} after you ask, the wheel passes to you.{changes}",
            h.label,
            seconds(h.held_for_ms),
            seconds(h.idle_for_ms),
            seconds(policy.contended_idle_ms)
        ),
        (None, _) => format!(
            "nobody holds {session_id} right now and this attachment is not the holder. Call dvv_control acquire"
        ),
    }
}

impl AgentPlane {
    fn agent_party(&self, session_id: &str, attachment_id: &str, label: Option<&str>) -> Party {
        let client = label
            .map(str::to_string)
            .filter(|l| !l.trim().is_empty())
            .or_else(|| self.client_of(session_id, attachment_id))
            .filter(|l| !l.trim().is_empty())
            .unwrap_or_else(|| "agent".to_string());
        Party::new(
            attachment_id,
            HolderKind::Agent,
            format!("{client} ({attachment_id})"),
        )
    }

    /// The timers in force.
    pub fn lease_policy(&self) -> agent_lease::LeasePolicy {
        *self.board.lock().policy()
    }

    /// Ask for the wheel on a session: granted, queued, or a preemption.
    pub fn lease_ask(&self, session_id: &str, attachment_id: &str, label: Option<&str>) -> Answer {
        let party = self.agent_party(session_id, attachment_id, label);
        let answer = self.board.lock().ask(session_id, party, lease_now());
        self.settle(session_id, &answer);
        answer
    }

    /// Let go of a session, and stop waiting for it.
    pub fn lease_release(&self, session_id: &str, attachment_id: &str) -> Answer {
        let answer =
            self.board
                .lock()
                .release(session_id, &PartyId::from(attachment_id), lease_now());
        self.settle(session_id, &answer);
        answer
    }

    /// Where a session's lease is now.
    pub fn lease_status(&self, session_id: &str) -> Answer {
        let answer = self.board.lock().status(session_id, lease_now());
        self.settle(session_id, &answer);
        answer
    }

    /// An agent's pointer event or key press is about to go to the session.
    /// The answer's `refusal` says whether it may.
    pub fn lease_input(&self, session_id: &str, attachment_id: &str) -> Answer {
        let party = self.agent_party(session_id, attachment_id, None);
        let answer = self.board.lock().input(session_id, party, lease_now());
        self.settle(session_id, &answer);
        answer
    }

    /// A person's key or button reached the session. Takes it from an agent,
    /// and keeps it while the input keeps coming. Any release of an agent's
    /// held keys goes onto the session's channel before this returns, which
    /// is before the person's own input does.
    pub fn person_input(&self, session_id: &str) -> Answer {
        let answer = self
            .board
            .lock()
            .person_input(session_id, person(), lease_now());
        self.settle(session_id, &answer);
        answer
    }

    /// A person pressed take the wheel, or stop. The same as their input, so
    /// it lasts as long as they keep using the machine and no longer.
    pub fn person_takes(&self, session_id: &str) -> Value {
        let answer = self.person_input(session_id);
        if answer.changed() {
            tracing::info!(session = %session_id, "a person took the wheel from an agent");
        }
        self.lease_event(session_id)
    }

    /// Apply elapsed time to every lease. Called on a timer.
    pub fn tick_leases(&self) {
        let moved = self.board.lock().tick_all(lease_now());
        for (session_id, answer) in moved {
            self.settle(&session_id, &answer);
        }
    }

    /// An attachment went away: let go of everything it held or waited for,
    /// and drop its rows.
    pub fn forget_attachment(&self, attachment_id: &str) {
        let sessions: Vec<String> = {
            let mut attachments = self.attachments.lock();
            let mut touched = Vec::new();
            for (session, rows) in attachments.iter_mut() {
                if rows.remove(attachment_id).is_some() {
                    touched.push(session.clone());
                }
            }
            attachments.retain(|_, rows| !rows.is_empty());
            touched
        };
        let moved = self
            .board
            .lock()
            .forget_party(&PartyId::from(attachment_id), lease_now());
        for (session_id, answer) in &moved {
            self.settle(session_id, answer);
        }
        if !sessions.is_empty() || !moved.is_empty() {
            tracing::info!(
                attachment = %attachment_id,
                "an agent connection ended, so whatever it held was let go"
            );
            self.announce();
        }
    }

    /// The attachment holding a session, when an agent holds it. Reads the
    /// board without ticking it, so it can be called with other locks held.
    pub(super) fn lease_holder_id(&self, session_id: &str) -> Option<String> {
        self.board
            .lock()
            .peek(session_id, lease_now())?
            .holder
            .filter(|h| h.kind == HolderKind::Agent)
            .map(|h| h.id.to_string())
    }

    /// A session's lease as JSON, addressed to one attachment, without
    /// ticking. A session nobody has asked about yet reads as free.
    pub fn lease_for(&self, session_id: &str, me: Option<&str>) -> Value {
        let board = self.board.lock();
        let policy = *board.policy();
        match board.peek(session_id, lease_now()) {
            Some(status) => status_json(&status, me, &policy),
            None => status_json(
                &agent_lease::Lease::exclusive(session_id).status(lease_now()),
                me,
                &policy,
            ),
        }
    }

    /// How many sessions an agent holds right now.
    pub(super) fn sessions_driven(&self) -> usize {
        let board = self.board.lock();
        let now = lease_now();
        let keys: Vec<String> = board.keys().map(str::to_string).collect();
        keys.iter()
            .filter_map(|key| board.peek(key, now))
            .filter(|status| {
                // An agent a person is taking the wheel from is fenced
                // already, so it is not driving even before the grace ends.
                !status.person_holds()
                    && status
                        .holder
                        .as_ref()
                        .is_some_and(|h| h.kind == HolderKind::Agent)
            })
            .count()
    }

    /// The event a pane renders for one session.
    pub fn lease_event(&self, session_id: &str) -> Value {
        let (status, policy) = {
            let board = self.board.lock();
            (board.peek(session_id, lease_now()), *board.policy())
        };
        // A person taking over is shown as the holder from the moment they
        // act, not when the agent's grace runs out: the agent is fenced
        // already, and a pane still saying "agent driving" under somebody's
        // hands would be wrong for those two seconds.
        let holder: Option<(HolderKind, String, Option<String>)> =
            status
                .as_ref()
                .and_then(|s| match (&s.preempting, &s.holder) {
                    (Some(w), _) if w.kind.is_person() => Some((w.kind, w.label.clone(), None)),
                    (_, Some(h)) => Some((
                        h.kind,
                        h.label.clone(),
                        (h.kind == HolderKind::Agent).then(|| h.id.to_string()),
                    )),
                    _ => None,
                });
        let holder_attachment = holder.as_ref().and_then(|h| h.2.clone());
        let (client, inflight, revoked, attached) = {
            let attachments = self.attachments.lock();
            let rows = attachments.get(session_id);
            let row = holder_attachment
                .as_deref()
                .and_then(|id| rows.and_then(|r| r.get(id)));
            (
                row.map(|r| r.client.clone()),
                row.map(|r| r.inflight.clone()).unwrap_or_default(),
                rows.is_some_and(|r| r.values().any(|row| row.revoked)),
                rows.map_or(0, |r| r.len()),
            )
        };
        let mut event = json!({
            "type": "lease",
            "sessionId": session_id,
            "attachmentId": holder_attachment,
            "client": client,
            "held": holder.is_some(),
            "phase": status.as_ref().map_or("free", |s| phase_name(s.phase)),
            "holderKind": holder.as_ref().map(|h| kind_name(h.0)),
            "holderLabel": holder.as_ref().map(|h| h.1.clone()),
            "humanTookOver": status.as_ref().is_some_and(LeaseStatus::person_holds),
            "revoked": revoked,
            "inflight": inflight,
            "attached": attached,
        });
        if let Some(status) = &status {
            event["lease"] = status_json(status, None, &policy);
        }
        event
    }

    /// Discharge what a board call owes the session, then tell the panes.
    ///
    /// The release goes when an agent was fenced or left and a person is not
    /// the one now holding: a person's own keys are theirs, and releasing them
    /// under their fingers is the bug the obligation exists to prevent, not
    /// to cause. Every lease call in this file goes through here.
    fn settle(&self, session_id: &str, answer: &Answer) {
        if !answer.changed() {
            return;
        }
        let person_now = answer
            .status
            .holder
            .as_ref()
            .is_some_and(|h| h.kind.is_person());
        let fenced_agent = answer.transitions.iter().any(|t| {
            matches!(&t.outcome, LeaseOutcome::PreemptionStarted { .. })
                || t.departed
                    .as_ref()
                    .is_some_and(|d| d.party.kind == HolderKind::Agent && !person_now)
        });
        for departed in answer
            .transitions
            .iter()
            .filter_map(|t| t.departed.as_ref())
        {
            let cause = match departed.cause {
                DepartureCause::Released => "let go",
                DepartureCause::Preempted => "a person took over",
                DepartureCause::Expired => "it expired",
                DepartureCause::IdleRevoked => "no input for the idle time",
                DepartureCause::DisconnectGraceElapsed => "its connection did not come back",
                DepartureCause::ForceReleased => "stop was pressed",
                DepartureCause::YieldedToWaiter => "somebody was waiting and it sent no input",
            };
            tracing::info!(
                session = %session_id,
                holder = %departed.party.label,
                held_for_ms = departed.held_for_ms,
                "the wheel left its holder: {cause}"
            );
        }
        let wiring = self
            .counts_wiring
            .lock()
            .as_ref()
            .map(|w| (w.sessions.clone(), w.emit.clone()));
        let Some((sessions, emit)) = wiring else {
            return;
        };
        if fenced_agent {
            let handle = sessions
                .lock()
                .get(session_id)
                .filter(|entry| entry.is_live())
                .map(|entry| entry.handle.clone());
            if let Some(handle) = handle {
                let _ = handle.try_send(vnc_core::ClientCommand::ReleaseAllKeys);
            }
        }
        emit(self.lease_event(session_id));
        self.announce();
    }
}

/// Tick the board until the plane is switched off.
pub async fn tick_leases(
    plane: std::sync::Arc<AgentPlane>,
    cancel: tokio_util::sync::CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(TICK_INTERVAL) => plane.tick_leases(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Attachment;
    use std::sync::Arc;

    fn row(id: &str, client: &str) -> Attachment {
        Attachment {
            attachment_id: id.into(),
            client: client.into(),
            revoked: false,
            inflight: Vec::new(),
            observed_content: None,
        }
    }

    #[test]
    fn two_attachments_on_one_session_contend_for_one_lease() {
        let plane = Arc::new(AgentPlane::default());
        plane.attach("s1", row("att_1", "claude-code"));
        plane.attach("s1", row("att_2", "codex"));
        assert!(plane.is_attached("s1", "att_1"));
        assert!(plane.is_attached("s1", "att_2"));

        assert!(plane.lease_input("s1", "att_1").refusal.is_none());
        let refused = plane.lease_input("s1", "att_2");
        assert!(refused.refusal.is_some());
        let sentence = not_yours("s1", &refused.status, &plane.lease_policy());
        assert!(sentence.contains("claude-code (att_1)"), "{sentence}");

        let queued = plane.lease_ask("s1", "att_2", Some("codex"));
        assert_eq!(queued.status.position_of(&PartyId::from("att_2")), Some(0));
        let event = plane.lease_event("s1");
        assert_eq!(event["holderKind"], "agent");
        assert_eq!(event["attachmentId"], "att_1");
        assert_eq!(event["lease"]["queue"][0]["label"], "codex (att_2)");
    }

    #[test]
    fn a_person_focusing_a_pane_takes_nothing_and_typing_takes_it() {
        let plane = Arc::new(AgentPlane::default());
        plane.attach("s1", row("att_1", "claude-code"));
        assert!(plane.lease_input("s1", "att_1").refusal.is_none());
        // Focus, a status read and a screen read are not input: nothing in
        // this module is called for them, and the lease is untouched.
        let _ = plane.lease_status("s1");
        assert_eq!(plane.lease_event("s1")["holderKind"], "agent");
        // A key is.
        let _ = plane.person_input("s1");
        assert_eq!(plane.lease_event("s1")["humanTookOver"], true);
        assert!(plane.lease_input("s1", "att_1").refusal.is_some());
    }

    #[test]
    fn a_connection_that_ends_lets_go() {
        let plane = Arc::new(AgentPlane::default());
        let guard = plane.client_connected("dvv");
        guard.bind("att_1");
        plane.attach("s1", row("att_1", "dvv"));
        assert!(plane.lease_input("s1", "att_1").refusal.is_none());
        assert_eq!(plane.sessions_driven(), 1);
        drop(guard);
        assert_eq!(plane.sessions_driven(), 0);
        assert!(!plane.is_attached("s1", "att_1"));
        assert_eq!(plane.lease_event("s1")["held"], false);
    }

    #[test]
    fn the_ticker_frees_a_lease_with_nobody_calling() {
        let policy = agent_lease::LeasePolicy {
            idle_revoke_ms: 40,
            ..agent_lease::LeasePolicy::default()
        };
        let plane = Arc::new(AgentPlane::with_lease_policy(policy));
        plane.attach("s1", row("att_1", "dvv"));
        assert!(plane.lease_input("s1", "att_1").refusal.is_none());
        std::thread::sleep(Duration::from_millis(60));
        // Only the timer runs; the agent never calls again.
        plane.tick_leases();
        assert_eq!(plane.lease_event("s1")["held"], false);
    }

    #[test]
    fn the_sentence_for_a_person_says_when_agents_get_it_back() {
        let plane = Arc::new(AgentPlane::default());
        let answer = plane.person_input("s1");
        let sentence = not_yours("s1", &answer.status, &plane.lease_policy());
        assert!(sentence.contains("a person is using s1"), "{sentence}");
        assert!(
            sentence.contains("20 s after their last input"),
            "{sentence}"
        );
        assert!(sentence.contains("acquire"), "{sentence}");
    }
}
