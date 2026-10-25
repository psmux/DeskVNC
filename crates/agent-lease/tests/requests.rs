//! An agent asking for a machine a person is using is a request to that
//! person: shown in one list, answered with "let it use this machine", "not
//! now" or a mute, and otherwise settled by the person going quiet.

use agent_lease::board::{MuteUntil, NOT_NOW_MS};
use agent_lease::{Board, HolderKind, LeaseError, LeaseInstant, Party, PartyId};

fn at(ms: u64) -> LeaseInstant {
    LeaseInstant::from_millis(ms)
}

fn agent(id: &str) -> Party {
    Party::new(id, HolderKind::Agent, format!("{id} pid 1"))
}

fn person() -> Party {
    Party::new("person", HolderKind::Human, "a person")
}

fn holder(board: &mut Board, key: &str, now: LeaseInstant) -> Option<String> {
    board
        .status(key, now)
        .status
        .holder
        .map(|h| h.id.to_string())
}

#[test]
fn every_waiting_agent_on_every_machine_is_one_list_with_its_reason() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let _ = board.person_input("s2", person(), at(0));
    let _ = board.ask("s1", agent("a"), Some("run the tests".into()), at(1_000));
    let _ = board.ask("s2", agent("b"), None, at(2_000));
    let _ = board.ask("s1", agent("c"), Some("check mail".into()), at(3_000));
    // A machine nobody is using is not a request to anybody.
    let _ = board.ask("s3", agent("d"), None, at(3_000));

    let requests = board.requests(at(4_000));
    let seen: Vec<(&str, &str)> = requests
        .iter()
        .map(|r| (r.key.as_str(), r.party.as_str()))
        .collect();
    assert_eq!(seen, vec![("s1", "a"), ("s2", "b"), ("s1", "c")]);
    assert_eq!(requests[0].reason.as_deref(), Some("run the tests"));
    assert_eq!(requests[0].waiting_ms, 3_000);
    // The countdown: the person's last input was at 0.
    assert_eq!(requests[0].frees_in_ms, Some(16_000));
}

#[test]
fn the_list_follows_agents_that_leave_and_the_person_going_quiet() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let _ = board.ask("s1", agent("a"), None, at(1_000));
    let _ = board.ask("s1", agent("b"), None, at(1_000));
    assert_eq!(board.requests(at(1_000)).len(), 2);
    let _ = board.release("s1", &PartyId::from("b"), at(2_000));
    assert_eq!(board.requests(at(2_000)).len(), 1);
    // Twenty seconds after the person's last input, the head of the queue has
    // the machine and nothing is asked of the person any more.
    for t in (3_000..=20_000).step_by(1_000) {
        let _ = board.ask("s1", agent("a"), None, at(t));
    }
    assert_eq!(holder(&mut board, "s1", at(20_000)).as_deref(), Some("a"));
    assert!(board.requests(at(20_000)).is_empty());
}

#[test]
fn let_it_use_this_machine_hands_it_to_that_agent_now() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let _ = board.ask("s1", agent("a"), None, at(1_000));
    let _ = board.ask("s1", agent("b"), None, at(1_500));
    // The person picks the second one, not the head of the queue.
    let answer = board.yield_to(
        "s1",
        &PartyId::from("b"),
        &PartyId::from("person"),
        at(2_000),
    );
    assert!(answer.refusal.is_none());
    assert!(answer.transitions.iter().any(|t| t.must_release()));
    assert_eq!(holder(&mut board, "s1", at(2_000)).as_deref(), Some("b"));
    assert!(answer.status.dispatching(&PartyId::from("b")));
    // The other agent still waits, now behind an agent.
    assert_eq!(answer.status.position_of(&PartyId::from("a")), Some(0));
    assert!(board.requests(at(2_000)).is_empty());
}

#[test]
fn letting_an_agent_that_is_not_waiting_use_it_changes_nothing() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let answer = board.yield_to(
        "s1",
        &PartyId::from("ghost"),
        &PartyId::from("person"),
        at(1_000),
    );
    assert!(answer.refusal.is_some());
    assert_eq!(
        holder(&mut board, "s1", at(1_000)).as_deref(),
        Some("person")
    );
}

#[test]
fn not_now_refuses_and_keeps_refusing_without_asking_the_person_again() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let _ = board.ask("s1", agent("a"), None, at(1_000));
    let declined = board.not_now("s1", &PartyId::from("a"), at(2_000));
    assert!(matches!(declined.refusal, Some(LeaseError::NotNow { .. })));
    assert!(board.requests(at(2_000)).is_empty());

    // The same agent asking again is told the same, and is not shown.
    let _ = board.person_input("s1", person(), at(10_000));
    let again = board.ask("s1", agent("a"), None, at(10_000));
    assert_eq!(
        again.refusal,
        Some(LeaseError::NotNow {
            retry_after_ms: NOT_NOW_MS - 8_000
        })
    );
    assert!(board.requests(at(10_000)).is_empty());
    // Another agent is still a new request.
    let _ = board.ask("s1", agent("b"), None, at(10_000));
    assert_eq!(board.requests(at(10_000)).len(), 1);

    // Once the window is over the same agent is shown again.
    for t in (20_000..=62_000).step_by(5_000) {
        let _ = board.person_input("s1", person(), at(t));
    }
    let _ = board.tick_all(at(62_001));
    let shown = board.ask("s1", agent("a"), None, at(62_001));
    assert!(shown.refusal.is_none(), "{:?}", shown.refusal);
}

#[test]
fn not_now_does_not_outlast_the_person_using_the_machine() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let _ = board.ask("s1", agent("a"), None, at(1_000));
    let _ = board.not_now("s1", &PartyId::from("a"), at(1_000));
    let _ = board.tick_all(at(20_000));
    let granted = board.ask("s1", agent("a"), None, at(20_001));
    assert!(granted.refusal.is_none());
    assert!(granted.status.dispatching(&PartyId::from("a")));
}

#[test]
fn not_now_to_everyone_clears_the_list() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let _ = board.person_input("s2", person(), at(0));
    let _ = board.ask("s1", agent("a"), None, at(1_000));
    let _ = board.ask("s2", agent("b"), None, at(1_000));
    assert_eq!(board.not_now_all(at(2_000)).len(), 2);
    assert!(board.requests(at(2_000)).is_empty());
}

#[test]
fn a_mute_until_a_time_hides_requests_and_answers_with_when_it_ends() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let _ = board.ask("s1", agent("a"), None, at(1_000));
    let dropped = board.mute(MuteUntil::At(at(301_000)), at(1_000));
    assert_eq!(dropped.len(), 1, "the waiting agent is taken out of line");
    assert!(board.requests(at(1_000)).is_empty());
    assert_eq!(board.muted(at(1_000)), Some(MuteUntil::At(at(301_000))));

    let muted = board.ask("s1", agent("a"), None, at(5_000));
    assert_eq!(
        muted.refusal,
        Some(LeaseError::Muted {
            retry_after_ms: 296_000
        })
    );
    assert!(board.requests(at(5_000)).is_empty());

    // A machine nobody is using is not affected by the mute at all.
    let free = board.ask("s9", agent("a"), None, at(5_000));
    assert!(free.refusal.is_none());

    // It ends on time.
    for t in (10_000..=301_000).step_by(10_000) {
        let _ = board.person_input("s1", person(), at(t));
    }
    let _ = board.tick_all(at(301_000));
    assert_eq!(board.muted(at(301_000)), None);
    let shown = board.ask("s1", agent("b"), None, at(301_000));
    assert!(shown.refusal.is_none());
    assert_eq!(board.requests(at(301_000)).len(), 1);
}

#[test]
fn a_mute_until_hands_off_ends_when_the_person_goes_idle() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let _ = board.mute(MuteUntil::PersonIdle, at(0));
    let muted = board.ask("s1", agent("a"), None, at(5_000));
    assert_eq!(
        muted.refusal,
        Some(LeaseError::Muted {
            retry_after_ms: 15_000
        })
    );
    let _ = board.person_input("s1", person(), at(10_000));
    assert!(board.muted(at(29_000)).is_some());
    let _ = board.tick_all(at(30_000));
    assert_eq!(board.muted(at(30_000)), None);
    let granted = board.ask("s1", agent("a"), None, at(30_001));
    assert!(granted.status.dispatching(&PartyId::from("a")));
}

#[test]
fn unmuting_shows_requests_again() {
    let mut board = Board::default();
    let _ = board.person_input("s1", person(), at(0));
    let _ = board.mute(MuteUntil::At(at(900_000)), at(0));
    board.unmute();
    assert_eq!(board.muted(at(1)), None);
    let _ = board.ask("s1", agent("a"), None, at(1));
    assert_eq!(board.requests(at(1)).len(), 1);
}
