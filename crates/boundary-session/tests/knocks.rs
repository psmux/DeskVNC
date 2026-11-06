//! Helpers that arrive at an attended invitation close together, over real
//! connections bound to this machine's loopback address: each one hears
//! something, nobody waits behind another's knock, and a prompt goes away
//! when its helper does.

use boundary_session::{Approval, Desktop, Event, Frame, HostOptions, Input, Invitation, Session};
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

/// Until it is waiting to be approved, which means its hello is sent.
async fn waiting(helper: &mut Session) {
    loop {
        match helper.events.recv().await {
            Some(Event::Status(status)) if status.contains("approve") => return,
            Some(Event::Finished(result)) => panic!("the helper stopped: {result:?}"),
            None => panic!("the helper went quiet"),
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
