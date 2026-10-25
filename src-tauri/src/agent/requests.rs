//! Agents asking a person for a machine the person is using.
//!
//! When a person holds a session (they typed or clicked in it in the last 20
//! seconds) and an agent asks for it, the agent is in the board's queue and
//! the person is shown one panel listing every such agent on every machine.
//! This file is the shell half of that: the list as an event the panel
//! renders, the person's three answers (let it use this machine, not now,
//! mute), and the sentence an agent reads about the person's answer.
//!
//! There is one `requests` event for the whole application, never one per
//! request, and that is what keeps the panel single: the webview renders the
//! latest list it was sent and nothing else. It is sent when the list
//! changes, and at most once a second while it is not empty so the countdown
//! follows the person's own typing.

use super::control::{lease_now, PERSON};
use super::AgentPlane;
use agent_lease::{LeaseError, MuteUntil, PartyId};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// How long an agent refused by a mute still counts as waiting on the badge.
/// An agent told "muted" goes off and does other work, so this is "agents
/// that asked recently" rather than a queue.
const MUTED_ASK_WINDOW: Duration = Duration::from_secs(60);

/// How often the list is sent again while it has not changed, for the
/// countdown.
const REFRESH: Duration = Duration::from_secs(1);

pub(super) fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// `14:32 UTC` for a unix millisecond time. UTC because the agent reading it
/// may be on another machine in another time zone, and a bare 14:32 would be
/// wrong for one of the two.
pub fn utc_clock(unix_ms: u64) -> String {
    let minutes = unix_ms / 60_000;
    format!("{:02}:{:02} UTC", (minutes / 60) % 24, minutes % 60)
}

fn minutes(ms: u64) -> String {
    let m = ms.div_ceil(60_000);
    if m == 1 {
        "1 minute".to_string()
    } else {
        format!("{m} minutes")
    }
}

fn secs(ms: u64) -> String {
    format!("{} s", ms.div_ceil(1000))
}

/// What the person said about this agent's request, as one word an agent
/// matches on and one sentence it acts on, plus the time a mute ends.
pub struct Verdict {
    pub word: &'static str,
    pub why: Option<String>,
    pub muted_until: Option<u64>,
}

/// Read a board answer into the person's answer for `attachment_id`.
pub fn verdict(
    session_id: &str,
    attachment_id: &str,
    answer: &agent_lease::Answer,
    person_idle_ms: u64,
) -> Verdict {
    let me = PartyId::from(attachment_id);
    let status = &answer.status;
    match &answer.refusal {
        Some(LeaseError::Muted { retry_after_ms }) => {
            let until = unix_ms() + retry_after_ms;
            Verdict {
                word: "muted",
                why: Some(format!(
                    "the person using {session_id} has muted requests from agents until {} (another {}). The request was not shown to them. Do other work and ask again after that",
                    utc_clock(until),
                    minutes(*retry_after_ms)
                )),
                muted_until: Some(until),
            }
        }
        Some(LeaseError::NotNow { retry_after_ms }) => Verdict {
            word: "not-now",
            why: Some(format!(
                "the person using {session_id} said not now. Do other work. Asking again within {} gets the same answer without asking them again; the machine comes back to agents {} after their last input",
                secs(*retry_after_ms),
                secs(person_idle_ms)
            )),
            muted_until: None,
        },
        _ if status.dispatching(&me) => Verdict {
            word: "granted",
            why: None,
            muted_until: None,
        },
        _ if status.position_of(&me).is_some() && status.person_holds() => Verdict {
            word: "waiting-for-person",
            why: Some(format!(
                "waiting for the person using {session_id}: they have been shown the request and can let you use it now. If they say nothing it is yours {} after their last input{}",
                secs(person_idle_ms),
                status
                    .changes_in_ms
                    .map(|ms| format!(", which is in {} if they stop now", secs(ms)))
                    .unwrap_or_default()
            )),
            muted_until: None,
        },
        _ if status.position_of(&me).is_some() => Verdict {
            word: "queued",
            why: None,
            muted_until: None,
        },
        _ => Verdict {
            word: "not-held",
            why: None,
            muted_until: None,
        },
    }
}

impl AgentPlane {
    pub(super) fn note_muted_ask(&self, session_id: &str, attachment_id: &str) {
        let mut asks = self.muted_asks.lock();
        asks.retain(|_, at| at.elapsed() < MUTED_ASK_WINDOW);
        asks.insert(
            (session_id.to_string(), attachment_id.to_string()),
            Instant::now(),
        );
    }

    /// The list the panel renders, and the mute, as the `requests` event.
    pub fn requests_event(&self) -> Value {
        let now = lease_now();
        let (requests, muted, policy) = {
            let board = self.board.lock();
            (board.requests(now), board.muted(now), *board.policy())
        };
        let wall = unix_ms();
        let addresses: std::collections::HashMap<String, String> = self
            .counts_wiring
            .lock()
            .as_ref()
            .map(|w| {
                w.sessions
                    .lock()
                    .iter()
                    .map(|(id, entry)| (id.clone(), format!("{}:{}", entry.address, entry.port)))
                    .collect()
            })
            .unwrap_or_default();
        let rows: Vec<Value> = requests
            .iter()
            .map(|r| {
                json!({
                    "sessionId": r.key,
                    "attachmentId": r.party.to_string(),
                    "agent": r.label,
                    "reason": r.reason,
                    "address": addresses.get(&r.key),
                    "askedAt": wall.saturating_sub(r.waiting_ms),
                    "freesAt": r.frees_in_ms.map(|ms| wall + ms),
                })
            })
            .collect();
        let muted_waiting = {
            let mut asks = self.muted_asks.lock();
            asks.retain(|_, at| at.elapsed() < MUTED_ASK_WINDOW);
            asks.len()
        };
        let muted = muted.map(|m| match m {
            MuteUntil::At(until) => json!({
                "until": wall + until.since(now),
                "untilIdle": false,
                "waiting": muted_waiting,
            }),
            MuteUntil::PersonIdle => json!({
                "until": Value::Null,
                "untilIdle": true,
                "waiting": muted_waiting,
            }),
        });
        json!({
            "type": "requests",
            "requests": rows,
            "muted": muted,
            "personIdleMs": policy.person_idle_ms,
        })
    }

    /// Send the list if it changed, or, with `refresh`, if a second has gone
    /// by and it is not empty.
    pub(super) fn announce_requests(&self, refresh: bool) {
        let emit = self.counts_wiring.lock().as_ref().map(|w| w.emit.clone());
        let Some(emit) = emit else {
            return;
        };
        let event = self.requests_event();
        // What decides "changed": who waits where and why, and the mute. The
        // times move every call and are not a change.
        let shape = json!({
            "rows": event["requests"]
                .as_array()
                .map(|rows| rows
                    .iter()
                    .map(|r| json!([r["sessionId"], r["attachmentId"], r["reason"]]))
                    .collect::<Vec<_>>())
                .unwrap_or_default(),
            "muted": [event["muted"]["until"], event["muted"]["untilIdle"], event["muted"]["waiting"]],
        });
        let busy = event["requests"].as_array().is_some_and(|r| !r.is_empty());
        {
            let mut last = self.last_requests.lock();
            let due = match last.as_ref() {
                None => true,
                Some((before, at)) => {
                    *before != shape || (refresh && busy && at.elapsed() >= REFRESH)
                }
            };
            if !due {
                return;
            }
            *last = Some((shape, Instant::now()));
        }
        emit(event);
    }

    /// "Let it use this machine": the person yields one session to one
    /// waiting agent now.
    pub fn allow_request(&self, session_id: &str, attachment_id: &str) -> bool {
        let answer = self.board.lock().yield_to(
            session_id,
            &PartyId::from(attachment_id),
            &PartyId::from(PERSON),
            lease_now(),
        );
        let allowed = answer.refusal.is_none();
        if allowed {
            tracing::info!(session = %session_id, attachment = %attachment_id, "a person let an agent use the machine");
        }
        self.settle(session_id, &answer);
        self.announce_requests(false);
        allowed
    }

    /// "Let it use this machine" for every row: each machine goes to the
    /// agent that has waited longest for it.
    pub fn allow_all_requests(&self) -> usize {
        let requests = self.board.lock().requests(lease_now());
        let mut seen = std::collections::BTreeSet::new();
        let mut allowed = 0;
        for request in requests {
            if seen.insert(request.key.clone())
                && self.allow_request(&request.key, request.party.as_str())
            {
                allowed += 1;
            }
        }
        allowed
    }

    /// "Not now" to one request.
    pub fn decline_request(&self, session_id: &str, attachment_id: &str) {
        let answer =
            self.board
                .lock()
                .not_now(session_id, &PartyId::from(attachment_id), lease_now());
        self.settle(session_id, &answer);
        self.announce_requests(false);
    }

    /// "Not now" to every request.
    pub fn decline_all_requests(&self) {
        let moved = self.board.lock().not_now_all(lease_now());
        for (session_id, answer) in &moved {
            self.settle(session_id, answer);
        }
        self.announce_requests(false);
    }

    /// Mute requests for `minutes`, or until the person stops using every
    /// machine when `None`.
    pub fn mute_requests(&self, minutes: Option<u64>) {
        let now = lease_now();
        let until = match minutes {
            Some(m) => MuteUntil::At(now.plus(m.saturating_mul(60_000))),
            None => MuteUntil::PersonIdle,
        };
        let moved = self.board.lock().mute(until, now);
        self.muted_asks.lock().clear();
        for (session_id, answer) in &moved {
            self.settle(session_id, answer);
        }
        self.announce_requests(false);
    }

    /// Show requests again.
    pub fn unmute_requests(&self) {
        self.board.lock().unmute();
        self.muted_asks.lock().clear();
        self.announce_requests(false);
    }

    /// Where a session's lease is, with the person's standing answer to this
    /// attachment (a mute, or a "not now") folded in as the refusal it would
    /// get if it asked, so a status call reads the same as an acquire.
    pub fn lease_status_for(&self, session_id: &str, attachment_id: &str) -> agent_lease::Answer {
        let mut answer = self.lease_status(session_id);
        let now = lease_now();
        let board = self.board.lock();
        if answer.status.person_holds() && !answer.status.held_by(&PartyId::from(attachment_id)) {
            answer.refusal = board
                .mute_left(session_id, now)
                .map(|retry_after_ms| LeaseError::Muted { retry_after_ms })
                .or_else(|| {
                    board
                        .not_now_left(session_id, &PartyId::from(attachment_id), now)
                        .map(|retry_after_ms| LeaseError::NotNow { retry_after_ms })
                });
        }
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Attachment;
    use parking_lot::Mutex;
    use std::collections::HashMap;
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

    fn wired(plane: &AgentPlane) -> Arc<Mutex<Vec<Value>>> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        plane.wire_counts(
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(move |value| sink.lock().push(value)),
        );
        events
    }

    fn requests_events(events: &Arc<Mutex<Vec<Value>>>) -> Vec<Value> {
        events
            .lock()
            .iter()
            .filter(|e| e["type"] == "requests")
            .cloned()
            .collect()
    }

    #[test]
    fn utc_clock_reads_hours_and_minutes() {
        // 2026-10-25 14:52:10 UTC.
        assert_eq!(utc_clock(1_792_939_930_000), "14:52 UTC");
    }

    #[test]
    fn many_requests_are_one_event_with_every_row_and_it_empties() {
        let plane = Arc::new(AgentPlane::default());
        let events = wired(&plane);
        plane.attach("s1", row("att_1", "claude-code"));
        plane.attach("s2", row("att_2", "codex"));
        let _ = plane.person_input("s1");
        let _ = plane.person_input("s2");
        let a = plane.lease_ask(
            "s1",
            "att_1",
            Some("claude-code pid 7"),
            Some("run the tests".into()),
        );
        let _ = plane.lease_ask("s2", "att_2", Some("codex pid 9"), None);
        let v = verdict("s1", "att_1", &a, 20_000);
        assert_eq!(v.word, "waiting-for-person");

        let last = requests_events(&events).last().cloned().expect("an event");
        let rows = last["requests"].as_array().expect("rows");
        assert_eq!(rows.len(), 2, "{last}");
        assert_eq!(rows[0]["reason"], "run the tests");
        assert_eq!(rows[0]["agent"], "claude-code pid 7 (att_1)");
        assert!(rows[0]["freesAt"].is_u64());

        // Asking again changes nothing a person sees: no new event.
        let before = requests_events(&events).len();
        let _ = plane.lease_ask("s1", "att_1", Some("claude-code pid 7"), None);
        assert_eq!(requests_events(&events).len(), before);

        plane.decline_request("s2", "att_2");
        assert!(plane.allow_request("s1", "att_1"));
        let last = requests_events(&events).last().cloned().expect("an event");
        assert!(last["requests"].as_array().expect("rows").is_empty());
        assert_eq!(plane.lease_event("s1")["holderKind"], "agent");
    }

    #[test]
    fn not_now_and_mute_are_the_answers_agents_read() {
        let plane = Arc::new(AgentPlane::default());
        let _events = wired(&plane);
        plane.attach("s1", row("att_1", "claude-code"));
        let _ = plane.person_input("s1");
        let _ = plane.lease_ask("s1", "att_1", None, None);
        plane.decline_request("s1", "att_1");
        let again = plane.lease_ask("s1", "att_1", None, None);
        let v = verdict("s1", "att_1", &again, 20_000);
        assert_eq!(v.word, "not-now");
        assert!(v.why.unwrap_or_default().contains("said not now"));

        plane.attach("s1", row("att_2", "codex"));
        plane.mute_requests(Some(15));
        let muted = plane.lease_ask("s1", "att_2", None, None);
        let v = verdict("s1", "att_2", &muted, 20_000);
        assert_eq!(v.word, "muted");
        assert!(v.muted_until.is_some());
        assert!(v
            .why
            .unwrap_or_default()
            .contains("muted requests from agents until"));
        let event = plane.requests_event();
        assert_eq!(event["muted"]["waiting"], 1);
        assert!(event["requests"].as_array().expect("rows").is_empty());

        plane.unmute_requests();
        assert!(plane.requests_event()["muted"].is_null());
    }
}
