//! Helpers that arrive at an attended invitation close together, over real
//! connections bound to this machine's loopback address: each one hears
//! something, nobody waits behind another's knock, and a prompt goes away
//! when its helper does.

use boundary_session::{
    Approval, Desktop, Event, Frame, HostOptions, Input, Invitation, Session,
    unattended::{self, Access, Asked, Notice},
};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::time::timeout;

struct Fake;
impl Desktop for Fake {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        Ok(Frame {
            width: 2,
            height: 2,
            rgba: vec![200; 16],
        })
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        Ok(())
    }
    fn release(&mut self) {}
}

/// iroh on Windows does not complete a loopback path, as the unattended
/// tests say, so there these run only when asked for.
fn skipped() -> bool {
    cfg!(windows) && std::env::var_os("BOUNDARY_LAN_TESTS").is_none()
}

/// Loopback only: nothing listens on the network, so no firewall asks.
fn loopback() -> HostOptions {
    HostOptions {
        relay: false,
        relay_url: None,
        bind_ip: Some("127.0.0.1".parse().unwrap()),
    }
}

async fn invitation(host: &mut Session) -> String {
    loop {
        if let Some(Event::Invitation(ticket)) = host.events.recv().await {
            return ticket;
        }
    }
}

/// The next prompt the host shows, with who it is for.
async fn prompt(host: &mut Session) -> (String, oneshot::Sender<Approval>) {
    loop {
        match host.events.recv().await {
            Some(Event::Approval { name, answer, .. }) => return (name, answer),
            Some(Event::Finished(result)) => panic!("the host stopped: {result:?}"),
            None => panic!("the host went quiet"),
            _ => {}
        }
    }
}

/// What a helper heard by the end: in, or turned away and why.
async fn outcome(helper: &mut Session) -> Result<(), String> {
    loop {
        match helper.events.recv().await {
            Some(Event::Connected { .. }) => return Ok(()),
            Some(Event::Finished(Err(error))) => return Err(format!("{error:#}")),
            Some(Event::Finished(Ok(()))) | None => return Err("ended without a word".into()),
            _ => {}
        }
    }
}

fn helper(ticket: &str, name: &str) -> Session {
    boundary_session::viewer(ticket.to_string(), name.into(), loopback())
}

/// A helper that arrives while the person is still deciding about another
/// one used to hear nothing at all: the host was waiting on the first
/// prompt and did not take the second knock until it was answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_helper_hears_while_the_first_waits_for_approval() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let mut host = boundary_session::host(loopback(), || Ok(Box::new(Fake)));
        let ticket = invitation(&mut host).await;
        let mut first = helper(&ticket, "First");
        let (name, answer) = prompt(&mut host).await;
        assert_eq!(name, "First");

        let mut second = helper(&ticket, "Second");
        let heard = timeout(Duration::from_secs(10), outcome(&mut second)).await;
        let heard = heard.expect("the second helper heard nothing for ten seconds");
        let refusal = heard.expect_err("the second helper was let in with nobody asked");
        assert!(
            refusal.contains("already asking"),
            "the second helper should hear why: {refusal}"
        );
        assert!(
            !answer.is_closed(),
            "the first prompt is still the person's to answer"
        );

        // The first helper is let in as it always was.
        let _ = answer.send(Approval::View);
        assert_eq!(outcome(&mut first).await, Ok(()));
        host.stop();
    })
    .await
    .expect("timed out");
}

/// A connection that never says hello held up every knock behind it for the
/// five seconds the host waited on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_knock_that_never_says_hello_does_not_hold_up_the_next() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let mut host = boundary_session::host(loopback(), || Ok(Box::new(Fake)));
        let ticket = invitation(&mut host).await;
        let address = Invitation::decode(&ticket).unwrap().address;
        let silent = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let quiet = silent
            .connect(address, b"boundary/support-experimental/1")
            .await
            .expect("the silent helper connects");
        // Let the host take it and start waiting for its hello.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let start = Instant::now();
        let mut second = helper(&ticket, "Second");
        let (name, answer) = timeout(Duration::from_secs(15), prompt(&mut host))
            .await
            .expect("no prompt for the second helper");
        assert_eq!(name, "Second");
        let waited = start.elapsed();
        assert!(
            waited < Duration::from_secs(3),
            "the second helper waited {waited:?} behind a knock that said nothing"
        );
        let _ = answer.send(Approval::Control);
        assert_eq!(outcome(&mut second).await, Ok(()));
        drop(quiet);
        silent.close().await;
        host.stop();
    })
    .await
    .expect("timed out");
}

/// A helper that leaves while the person is deciding takes its prompt with
/// it, and the next helper gets a prompt of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prompt_goes_away_with_its_helper_and_the_next_gets_its_own() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let mut host = boundary_session::host(loopback(), || Ok(Box::new(Fake)));
        let ticket = invitation(&mut host).await;
        let first = helper(&ticket, "First");
        let (_, mut answer) = prompt(&mut host).await;
        first.stop();
        drop(first);
        timeout(Duration::from_secs(5), answer.closed())
            .await
            .expect("the prompt stayed after its helper left");

        let mut second = helper(&ticket, "Second");
        let (name, answer) = timeout(Duration::from_secs(10), prompt(&mut host))
            .await
            .expect("no prompt for the next helper");
        assert_eq!(name, "Second");
        let _ = answer.send(Approval::View);
        assert_eq!(outcome(&mut second).await, Ok(()));
        host.stop();
    })
    .await
    .expect("timed out");
}

/// Nobody answering used to end with the helper reading "Session ended
/// (code 0)" after a minute: the host wrote its refusal and closed the
/// connection in the same breath, and the close won.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_nobody_answers_hears_why() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(120), async {
        let mut host = boundary_session::host(loopback(), || Ok(Box::new(Fake)));
        let ticket = invitation(&mut host).await;
        let mut first = helper(&ticket, "First");
        let (_, answer) = prompt(&mut host).await;
        let heard = outcome(&mut first).await;
        let refusal = heard.expect_err("let in with nobody asked");
        assert!(
            refusal.contains("Nobody answered"),
            "the helper should hear that nobody answered: {refusal}"
        );
        drop(answer);
        host.stop();
    })
    .await
    .expect("timed out");
}

/// A helper the person turns down hears that they did, every time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_the_person_declines_hears_so() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let mut host = boundary_session::host(loopback(), || Ok(Box::new(Fake)));
        let ticket = invitation(&mut host).await;
        for _ in 0..5 {
            let mut first = helper(&ticket, "First");
            let (_, answer) = prompt(&mut host).await;
            let _ = answer.send(Approval::Deny);
            let refusal = outcome(&mut first).await.expect_err("let in when declined");
            assert!(refusal.contains("declined"), "{refusal}");
        }
        host.stop();
    })
    .await
    .expect("timed out");
}

/// Once a helper is in, the invitation is spent. A helper who knocks with it
/// then used to wait with no answer until the session ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_who_knocks_during_a_session_hears_it_is_in_use() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let mut host = boundary_session::host(loopback(), || Ok(Box::new(Fake)));
        let ticket = invitation(&mut host).await;
        let mut first = helper(&ticket, "First");
        let (_, answer) = prompt(&mut host).await;
        let _ = answer.send(Approval::View);
        assert_eq!(outcome(&mut first).await, Ok(()));

        let mut late = helper(&ticket, "Late");
        let heard = timeout(Duration::from_secs(10), outcome(&mut late))
            .await
            .expect("the late helper heard nothing for ten seconds");
        let refusal = heard.expect_err("a second helper got into a spent invitation");
        assert!(refusal.contains("already in use"), "{refusal}");
        host.stop();
    })
    .await
    .expect("timed out");
}

/// On Wayland the desktop opens only once the person answers the desktop's
/// own sharing prompt. The window said "Your screen is being shared" while
/// that prompt was still open, because the host said the helper was in as
/// soon as the person approved them, before the desktop was open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_screen_is_not_called_shared_until_the_desktop_opens() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        // The desktop's sharing prompt, answered when the test says so.
        let (answered, prompt_open) = std::sync::mpsc::channel::<bool>();
        let mut host = boundary_session::host(loopback(), move || match prompt_open.recv() {
            Ok(true) => Ok(Box::new(Fake) as Box<dyn Desktop>),
            _ => anyhow::bail!("The screen was not shared because Cancel was chosen"),
        });
        let ticket = invitation(&mut host).await;
        let mut first = helper(&ticket, "Sam");
        let (_, answer) = prompt(&mut host).await;
        let _ = answer.send(Approval::Control);
        // The helper is let in at once, so it stops waiting.
        assert_eq!(outcome(&mut first).await, Ok(()));
        // The person is still looking at the desktop's prompt.
        let early = timeout(Duration::from_millis(1500), async {
            loop {
                match host.events.recv().await {
                    Some(Event::Connected { .. }) => return,
                    None => std::future::pending::<()>().await,
                    _ => {}
                }
            }
        })
        .await;
        assert!(
            early.is_err(),
            "connected while the sharing prompt was open"
        );
        // They choose Share.
        answered.send(true).unwrap();
        let control = loop {
            match host.events.recv().await {
                Some(Event::Connected { control, .. }) => break control,
                Some(Event::Finished(result)) => panic!("the host stopped: {result:?}"),
                None => panic!("the host went quiet"),
                _ => {}
            }
        };
        assert!(control);
        host.stop();
    })
    .await
    .expect("timed out");
}

/// Cancel in the desktop's prompt ends the session with the reason, and the
/// window never says the screen was shared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_in_the_sharing_prompt_never_says_shared() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let (answered, prompt_open) = std::sync::mpsc::channel::<bool>();
        let mut host = boundary_session::host(loopback(), move || match prompt_open.recv() {
            Ok(true) => Ok(Box::new(Fake) as Box<dyn Desktop>),
            _ => anyhow::bail!("The screen was not shared because Cancel was chosen"),
        });
        let ticket = invitation(&mut host).await;
        let _first = helper(&ticket, "Sam");
        let (_, answer) = prompt(&mut host).await;
        let _ = answer.send(Approval::Control);
        answered.send(false).unwrap();
        loop {
            match host.events.recv().await {
                Some(Event::Connected { .. }) => panic!("called shared after Cancel"),
                Some(Event::Finished(result)) => {
                    let error = format!("{:#}", result.expect_err("Cancel is not a clean end"));
                    assert!(error.contains("Cancel"), "{error}");
                    break;
                }
                None => panic!("the host went quiet"),
                _ => {}
            }
        }
    })
    .await
    .expect("timed out");
}

/// A desktop that shares the screen alone, as GNOME does when Allow Remote
/// Interaction is left off in its prompt: every event sent to it fails.
struct Watched;
impl Desktop for Watched {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        Fake.capture()
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        anyhow::bail!("Control was not allowed")
    }
    fn release(&mut self) {}
    fn controllable(&self) -> bool {
        false
    }
}

/// Approved for control on a desktop that takes no input, the helper was
/// told it had control and its first click ended the whole session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_on_a_screen_shared_alone_is_told_it_can_only_watch() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let mut host = boundary_session::host(loopback(), || Ok(Box::new(Watched)));
        let ticket = invitation(&mut host).await;
        let mut first = helper(&ticket, "Sam");
        let (_, answer) = prompt(&mut host).await;
        let _ = answer.send(Approval::Control);
        let control = loop {
            match host.events.recv().await {
                Some(Event::Connected { control, .. }) => break control,
                Some(Event::Finished(result)) => panic!("the host stopped: {result:?}"),
                None => panic!("the host went quiet"),
                _ => {}
            }
        };
        assert!(!control, "the person's window said control");
        // The helper hears it is a viewer.
        loop {
            match first.events.recv().await {
                Some(Event::Control(false)) => break,
                Some(Event::Finished(result)) => panic!("the helper stopped: {result:?}"),
                None => panic!("the helper went quiet"),
                _ => {}
            }
        }
        // Its input is refused, and the session goes on.
        first.input(Input::Move { x: 0.5, y: 0.5 }).unwrap();
        first
            .input(Input::Button {
                button: boundary_session::Button::Left,
                down: true,
            })
            .unwrap();
        first
            .input(Input::Button {
                button: boundary_session::Button::Left,
                down: false,
            })
            .unwrap();
        // Ticking control on the person's side cannot give what the desktop
        // did not: it goes back off, with the reason.
        host.set_control(true);
        let quiet = timeout(Duration::from_secs(2), async {
            loop {
                match host.events.recv().await {
                    Some(Event::Control(false)) => return "unticked",
                    Some(Event::Finished(_)) | None => return "ended",
                    _ => {}
                }
            }
        })
        .await;
        assert_eq!(quiet, Ok("unticked"));
        let helper_heard = timeout(Duration::from_secs(2), async {
            loop {
                match first.events.recv().await {
                    Some(Event::Control(true)) => return "control",
                    Some(Event::Finished(_)) | None => return "ended",
                    _ => {}
                }
            }
        })
        .await;
        assert!(helper_heard.is_err(), "the helper heard {helper_heard:?}");
        host.stop();
    })
    .await
    .expect("timed out");
}

// Unattended: the same, for a computer listening for paired helpers.

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "boundary-knocks-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Unattended {
    listener: unattended::Listener,
    address: iroh::EndpointAddr,
    paired: iroh::SecretKey,
    dir: PathBuf,
}
async fn listening(name: &str) -> Unattended {
    let dir = scratch(name);
    let machine = unattended::load_or_create_key(&dir.join("machine.key")).unwrap();
    let paired = unattended::load_or_create_key(&dir.join("paired.key")).unwrap();
    let access_path = dir.join("access.json");
    let mut access = Access::default();
    access.enabled = true;
    access
        .trust(&paired.public().to_string(), "Paired", true)
        .unwrap();
    access.save(&access_path).unwrap();
    let mut listener = unattended::listen(loopback(), machine, access_path, || Ok(Box::new(Fake)));
    let address = loop {
        match listener.notices.recv().await {
            Some(Notice::Ready { address, .. }) => break address,
            Some(Notice::Finished(result)) => panic!("listener ended: {result:?}"),
            _ => {}
        }
    };
    Unattended {
        listener,
        address,
        paired,
        dir,
    }
}
impl Unattended {
    fn visit(&self, name: &str, key: iroh::SecretKey) -> Session {
        unattended::connect_to(Ok(self.address.clone()), name.into(), None, key, loopback())
    }
    fn stranger(&self, name: &str) -> Session {
        self.visit(name, iroh::SecretKey::generate())
    }
    async fn asked(&mut self) -> (String, oneshot::Sender<Asked>) {
        loop {
            match self.listener.notices.recv().await {
                Some(Notice::Ask { name, answer, .. }) => return (name, answer),
                Some(Notice::Finished(result)) => panic!("listener ended: {result:?}"),
                None => panic!("the listener went quiet"),
                _ => {}
            }
        }
    }
    async fn connected(&mut self) -> (String, Session) {
        loop {
            match self.listener.notices.recv().await {
                Some(Notice::Connected { name, session, .. }) => return (name, session),
                Some(Notice::Refused { name, reason, .. }) => panic!("{name} refused: {reason}"),
                Some(Notice::Finished(result)) => panic!("listener ended: {result:?}"),
                None => panic!("the listener went quiet"),
                _ => {}
            }
        }
    }
}
impl Drop for Unattended {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// While the person was asked about a stranger, the computer took no other
/// knock, so even a paired helper waited up to a minute for an answer that
/// had nothing to do with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unattended_computer_lets_a_paired_helper_in_while_it_asks_about_another() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let mut host = listening("asking").await;
        let mut stranger = host.stranger("Stranger");
        let (name, answer) = host.asked().await;
        assert_eq!(name, "Stranger");

        let start = Instant::now();
        let mut paired = host.visit("Paired", host.paired.clone());
        let (name, _held) = timeout(Duration::from_secs(10), host.connected())
            .await
            .expect("the paired helper waited behind the question");
        assert_eq!(name, "Paired");
        assert_eq!(outcome(&mut paired).await, Ok(()));
        assert!(start.elapsed() < Duration::from_secs(5));

        // A second stranger is told plainly that the person is busy.
        let mut second = host.stranger("Second");
        let heard = timeout(Duration::from_secs(10), outcome(&mut second))
            .await
            .expect("the second stranger heard nothing for ten seconds");
        let refusal = heard.expect_err("let in with nobody asked");
        assert!(refusal.contains("already"), "{refusal}");
        assert!(!answer.is_closed(), "the first question still stands");

        let _ = answer.send(Asked {
            approval: Approval::View,
            tools: false,
            clipboard: false,
            pair: false,
        });
        assert_eq!(outcome(&mut stranger).await, Ok(()));
    })
    .await
    .expect("timed out");
}

/// A stranger who left while the person was being asked about them left the
/// question standing for a minute, with nobody behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unattended_question_goes_away_with_its_helper() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let mut host = listening("leaving").await;
        let stranger = host.stranger("Stranger");
        let (_, mut answer) = host.asked().await;
        stranger.stop();
        drop(stranger);
        timeout(Duration::from_secs(5), answer.closed())
            .await
            .expect("the question stayed after its helper left");

        let _next = host.stranger("Next");
        let (name, _answer) = timeout(Duration::from_secs(10), host.asked())
            .await
            .expect("no question about the next helper");
        assert_eq!(name, "Next");
    })
    .await
    .expect("timed out");
}

/// A connection that never knocks held up the paired helper behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unattended_knock_that_says_nothing_does_not_hold_up_the_next() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(60), async {
        let mut host = listening("silent").await;
        let silent = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let quiet = silent
            .connect(host.address.clone(), b"boundary/support-experimental/1")
            .await
            .expect("the silent helper connects");
        tokio::time::sleep(Duration::from_millis(300)).await;

        let start = Instant::now();
        let mut paired = host.visit("Paired", host.paired.clone());
        let (_, _held) = timeout(Duration::from_secs(15), host.connected())
            .await
            .expect("the paired helper never got in");
        let waited = start.elapsed();
        assert!(
            waited < Duration::from_secs(3),
            "the paired helper waited {waited:?} behind a knock that said nothing"
        );
        assert_eq!(outcome(&mut paired).await, Ok(()));
        drop(quiet);
        silent.close().await;
    })
    .await
    .expect("timed out");
}
