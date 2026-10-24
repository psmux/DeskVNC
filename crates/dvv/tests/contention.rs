//! Several agent processes and a person on one machine, through the plane.
//!
//! Each [`Plane`] here stands for one agent process (an MCP server, a `dvv
//! hold`), and the [`Board`] they share stands for the leases DeskVNCViewer
//! keeps, one per session, which every connection asks. The timers are cut
//! to milliseconds so the tests run in well under a second each; the numbers
//! themselves are tested in `agent-lease`.

use agent_lease::{Board, HolderKind, LeasePolicy, Party};
use dvv::fake::FakeSource;
use dvv::plane::{OpenRequest, Plane, SessionSource};
use limb_core::intent::{Button, IntentKind, Point};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn board(policy: LeasePolicy) -> Arc<Mutex<Board>> {
    Arc::new(Mutex::new(Board::new(policy)))
}

fn agent(board: &Arc<Mutex<Board>>, attachment: &str) -> Arc<Plane> {
    let source = Arc::new(FakeSource::two_machines().sharing(board.clone(), attachment));
    Arc::new(Plane::local(source as Arc<dyn SessionSource>).expect("a local grant"))
}

fn open(plane: &Plane) -> dvv::plane::LimbCard {
    plane
        .open(&OpenRequest {
            host_id: Some("h_lab01".to_string()),
            perceive: true,
            ..OpenRequest::default()
        })
        .expect("the fake opens it")
}

fn limb(plane: &Plane, card: &dvv::plane::LimbCard) -> agent_plane::AttachedLimb {
    plane
        .resolve(&dvv::plane::Selector {
            limb_id: Some(card.limb_id.clone()),
            ..Default::default()
        })
        .expect("attached")
}

fn holder(board: &Arc<Mutex<Board>>, key: &str) -> Option<String> {
    board
        .lock()
        .unwrap()
        .peek(key, dvv::clock::lease_now())
        .and_then(|s| s.holder)
        .map(|h| h.id.to_string())
}

#[tokio::test]
async fn two_agents_contend_and_the_waiter_takes_over_when_the_holder_stops_acting() {
    let shared = board(LeasePolicy {
        contended_idle_ms: 300,
        min_hold_ms: 0,
        ..LeasePolicy::default()
    });
    let first = agent(&shared, "att_a");
    let second = agent(&shared, "att_b");
    let card = open(&first);
    let _ = open(&second);
    let (a, b) = (limb(&first, &card), limb(&second, &card));

    let held = first
        .acquire(&a, None, Some(Duration::ZERO))
        .await
        .expect("the free wheel");
    assert!(held.held);

    // Asking without waiting is refused, and says who has it.
    let refused = second
        .acquire(&b, None, Some(Duration::ZERO))
        .await
        .expect_err("the first agent has it");
    assert_eq!(refused.code, "LEASE_NOT_HELD");
    assert!(refused.message.contains("holds it"), "{}", refused.message);

    // Asking and waiting gets it once the first agent has sent nothing for
    // the contended idle time, with no call from the first agent at all.
    let started = Instant::now();
    let granted = second
        .acquire(&b, None, Some(Duration::from_secs(5)))
        .await
        .expect("handed over");
    let took = started.elapsed();
    assert!(granted.held);
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(2),
        "{took:?}"
    );
    assert_eq!(holder(&shared, &card.limb_id).as_deref(), Some("att_b"));

    // And the first one is told who has it now, and that it is an agent.
    let status = first.control_status(&a).await;
    assert!(!status.held);
    let told = status.control_yield.expect("a yield");
    assert!(!told.human_took_over);
    assert!(told.by_label.unwrap_or_default().contains("pid"));
}

#[tokio::test]
async fn an_action_waits_for_the_wheel_instead_of_failing() {
    let shared = board(LeasePolicy {
        contended_idle_ms: 200,
        min_hold_ms: 0,
        ..LeasePolicy::default()
    });
    let first = agent(&shared, "att_a");
    let second = agent(&shared, "att_b");
    let card = open(&first);
    let _ = open(&second);
    let (a, b) = (limb(&first, &card), limb(&second, &card));
    first
        .acquire(&a, None, Some(Duration::ZERO))
        .await
        .expect("the free wheel");
    let _ = second.observe(&b, None);

    // The second agent never calls acquire: its click asks and waits.
    let settled = second
        .submit(
            &b,
            IntentKind::Click {
                at: Point::new(5, 5),
                button: Button::Left,
                count: 1,
                modifiers: Vec::new(),
            },
            Some(b.generation().get()),
        )
        .await
        .expect("the click went once the wheel was free");
    assert_eq!(dvv::plane::outcome_word(&settled.outcome), "delivered");
    assert_eq!(holder(&shared, &card.limb_id).as_deref(), Some("att_b"));
}

#[tokio::test]
async fn a_forgotten_lease_frees_itself_with_no_call_from_anyone() {
    let shared = board(LeasePolicy {
        idle_revoke_ms: 200,
        ..LeasePolicy::default()
    });
    let forgetful = agent(&shared, "att_a");
    let card = open(&forgetful);
    let a = limb(&forgetful, &card);
    forgetful
        .acquire(&a, None, Some(Duration::ZERO))
        .await
        .expect("the free wheel");
    assert_eq!(holder(&shared, &card.limb_id).as_deref(), Some("att_a"));

    // The viewer's timer, and nothing else: the agent makes no call.
    let ticker = shared.clone();
    let timer = std::thread::spawn(move || {
        for _ in 0..8 {
            std::thread::sleep(Duration::from_millis(50));
            let _ = ticker.lock().unwrap().tick_all(dvv::clock::lease_now());
        }
    });
    timer.join().expect("the timer ran");
    assert_eq!(holder(&shared, &card.limb_id), None);

    // Another agent gets it at once.
    let other = agent(&shared, "att_b");
    let _ = open(&other);
    let b = limb(&other, &card);
    assert!(
        other
            .acquire(&b, None, Some(Duration::ZERO))
            .await
            .expect("free")
            .held
    );
}

#[tokio::test]
async fn a_person_takes_over_and_the_agent_gets_it_back_once_they_go_quiet() {
    let shared = board(LeasePolicy {
        person_idle_ms: 300,
        agent_preempt_grace_ms: 50,
        ..LeasePolicy::default()
    });
    let plane = agent(&shared, "att_a");
    let card = open(&plane);
    let a = limb(&plane, &card);
    plane
        .acquire(&a, None, Some(Duration::ZERO))
        .await
        .expect("the free wheel");

    // A person types on the session in DeskVNCViewer.
    let person = Party::new("person", HolderKind::Human, "a person in DeskVNCViewer");
    let _ = shared
        .lock()
        .unwrap()
        .person_input(&card.limb_id, person, dvv::clock::lease_now());

    let status = plane.control_status(&a).await;
    assert!(!status.held);
    let told = status.control_yield.expect("a yield");
    assert!(told.human_took_over);
    assert!(
        told.advice.contains("get it back") && !told.advice.contains("STOP"),
        "{}",
        told.advice
    );

    // The agent asks and waits, and gets the machine back once the person
    // has sent nothing for the person idle time.
    let started = Instant::now();
    let back = plane
        .acquire(&a, None, Some(Duration::from_secs(5)))
        .await
        .expect("handed back");
    assert!(back.held);
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(holder(&shared, &card.limb_id).as_deref(), Some("att_a"));
}

#[tokio::test]
async fn a_person_who_keeps_using_it_keeps_it_and_the_agent_is_told_why() {
    let shared = board(LeasePolicy {
        person_idle_ms: 10_000,
        ..LeasePolicy::default()
    });
    let plane = agent(&shared, "att_a");
    let card = open(&plane);
    let a = limb(&plane, &card);
    let person = Party::new("person", HolderKind::Human, "a person in DeskVNCViewer");
    let _ = shared
        .lock()
        .unwrap()
        .person_input(&card.limb_id, person, dvv::clock::lease_now());
    let refused = plane
        .acquire(&a, None, Some(Duration::from_millis(300)))
        .await
        .expect_err("the person still has it");
    assert_eq!(refused.code, "LEASE_NOT_HELD");
    assert!(refused.message.contains("waited"), "{}", refused.message);
    // A waiter that gave up is out of the queue.
    let status = shared
        .lock()
        .unwrap()
        .peek(&card.limb_id, dvv::clock::lease_now())
        .expect("a lease");
    assert!(status.queue.is_empty());
}
