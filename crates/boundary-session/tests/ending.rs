//! How the computer being helped hears that the helper ended the session.
//!
//! A helper that ends a session on purpose closes the connection with code 0
//! and "Session ended". The computer used to race that close against the read
//! of the helper's next message, and when the read lost it reported "connection
//! lost: closed by peer: Session ended (code 0)" as an error, which DeskVNC
//! Support showed in red as if something had failed. Ended on purpose, the
//! session has ended normally, every time.

use boundary_session::{Abilities, Approval, Desktop, Event, Frame, HostOptions, Input, Session};
use std::time::Duration;
use tokio::time::timeout;

/// A still screen that takes input.
struct Still;
impl Desktop for Still {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        Ok(Frame {
            width: 2,
            height: 2,
            rgba: vec![90; 16],
        })
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        Ok(())
    }
    fn release(&mut self) {}
}

fn local() -> HostOptions {
    HostOptions {
        relay: false,
        relay_url: None,
        bind_ip: None,
    }
}

async fn invitation(host: &mut Session) -> String {
    loop {
        match host.events.recv().await {
            Some(Event::Invitation(ticket)) => return ticket,
            Some(Event::Finished(result)) => panic!("the host stopped: {result:?}"),
            None => panic!("the host went quiet"),
            _ => {}
        }
    }
}

/// Wait for `session` to say `Connected`.
async fn connected(session: &mut Session, mut approve: Option<Approval>) {
    loop {
        match session.events.recv().await {
            Some(Event::Approval { answer, .. }) => {
                let _ = answer.send(approve.take().expect("the host is asked once"));
            }
            Some(Event::Connected { .. }) => return,
            Some(Event::Finished(result)) => panic!("ended before connecting: {result:?}"),
            None => panic!("went quiet before connecting"),
            _ => {}
        }
    }
}

/// How the host's session finished.
async fn finished(host: &mut Session) -> anyhow::Result<()> {
    loop {
        match host.events.recv().await {
            Some(Event::Finished(result)) => return result,
            None => panic!("the host went quiet without finishing"),
            _ => {}
        }
    }
}

/// One session, let in with `approval` and ended by the helper.
async fn ended_by_the_helper(approval: Approval, clipboard: bool) -> anyhow::Result<()> {
    let mut host = boundary_session::host(local(), || Ok(Box::new(Still)));
    let ticket = invitation(&mut host).await;
    let mut helper = boundary_session::viewer_with(
        ticket,
        "Ending test".into(),
        local(),
        None,
        Abilities {
            tools: false,
            video: false,
            clipboard,
        },
    );
    connected(&mut host, Some(approval)).await;
    connected(&mut helper, None).await;
    // Let a few pings and screens pass, as in a real session.
    tokio::time::sleep(Duration::from_millis(300)).await;
    helper.stop();
    let result = timeout(Duration::from_secs(10), finished(&mut host))
        .await
        .expect("the host heard the end within 10 s");
    drop(helper);
    result
}

/// Repeated, because whether the read or the close won was down to timing:
/// on one machine about one session in four ended in red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_the_helper_ends_ends_normally_on_the_computer() {
    let mut failures = Vec::new();
    for round in 0..48 {
        let approval = if round % 2 == 0 {
            Approval::Control
        } else {
            Approval::View
        };
        if let Err(error) = ended_by_the_helper(approval, round % 3 != 0).await {
            failures.push(format!("round {round}: {error:#}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of 48 sessions the helper ended came back as errors on the computer:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
