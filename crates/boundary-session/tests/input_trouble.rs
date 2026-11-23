//! A desktop that cannot take input, such as a Mac at its lock screen, over
//! real connections on this machine. The session goes on and the screen is
//! still shared; a helper that reads notices is told why its input is not
//! landing and when it lands again, and a helper that does not is never sent
//! a notice, since it would end the session on a message it does not know.

use boundary_session::{
    Abilities, Approval, Button, Desktop, Event, Frame, HostNotice, HostOptions, Input,
    InputTrouble, InputUnavailable, Session,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::time::Duration;
use tokio::time::timeout;

/// A screen that changes on every look, so screens keep reaching the
/// helper, and whose input fails while `locked`, as a Mac's does at its lock
/// screen.
struct Locked {
    locked: Arc<AtomicBool>,
    /// Events that reached the desktop.
    landed: Arc<AtomicU32>,
    shade: u8,
}
impl Desktop for Locked {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        self.shade = self.shade.wrapping_add(1);
        Ok(Frame {
            width: 2,
            height: 2,
            rgba: vec![self.shade; 16],
        })
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(InputUnavailable {
                trouble: InputTrouble::LockScreen,
                reason: "no connection could be established: (failed creating event source)".into(),
            }
            .into());
        }
        self.landed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn release(&mut self) {}
}

struct Pair {
    host: Session,
    helper: Session,
    locked: Arc<AtomicBool>,
    landed: Arc<AtomicU32>,
}

async fn pair(notices: bool) -> Pair {
    let locked = Arc::new(AtomicBool::new(true));
    let landed = Arc::new(AtomicU32::new(0));
    let options = HostOptions {
        relay: false,
        relay_url: None,
        bind_ip: None,
    };
    let (l, n) = (locked.clone(), landed.clone());
    let mut host = boundary_session::host(options.clone(), move || {
        Ok(Box::new(Locked {
            locked: l,
            landed: n,
            shade: 0,
        }))
    });
    let ticket = loop {
        match host.events.recv().await {
            Some(Event::Invitation(ticket)) => break ticket,
            Some(Event::Finished(result)) => panic!("the host stopped: {result:?}"),
            None => panic!("the host went quiet"),
            _ => {}
        }
    };
    let mut helper = boundary_session::viewer_with(
        ticket,
        "Input test".into(),
        options,
        None,
        Abilities {
            notices,
            ..Abilities::default()
        },
    );
    loop {
        match host.events.recv().await {
            Some(Event::Approval { answer, .. }) => {
                let _ = answer.send(Approval::Control);
                break;
            }
            Some(Event::Finished(result)) => panic!("the host stopped: {result:?}"),
            None => panic!("the host went quiet"),
            _ => {}
        }
    }
    loop {
        match helper.events.recv().await {
            Some(Event::Connected { control, .. }) => {
                assert!(control, "the helper was let in without control");
                break;
            }
            Some(Event::Finished(result)) => panic!("the helper did not get in: {result:?}"),
            None => panic!("the helper went quiet"),
            _ => {}
        }
    }
    Pair {
        host,
        helper,
        locked,
        landed,
    }
}

/// A click, which a helper sends as two events.
fn click(helper: &Session) {
    for down in [true, false] {
        helper
            .input(Input::Button {
                button: Button::Left,
                down,
            })
            .expect("the helper's input was refused");
    }
}

/// Every notice the helper hears within `wait`. Panics if either side's
/// session ends meanwhile.
async fn notices(pair: &mut Pair, wait: Duration) -> Vec<HostNotice> {
    let end = tokio::time::Instant::now() + wait;
    let mut heard = Vec::new();
    loop {
        while let Ok(event) = pair.host.events.try_recv() {
            if let Event::Finished(result) = event {
                panic!("the host's session ended: {result:?}");
            }
        }
        match tokio::time::timeout_at(end, pair.helper.events.recv()).await {
            Err(_) => return heard,
            Ok(Some(Event::Notice(notice))) => heard.push(notice),
            Ok(Some(Event::Finished(result))) => {
                panic!("the helper's session ended: {result:?}")
            }
            Ok(None) => panic!("the helper went quiet"),
            Ok(Some(_)) => {}
        }
    }
}

/// The screen goes on reaching the helper.
async fn still_shared(helper: &mut Session) {
    helper.frames.borrow_and_update();
    timeout(Duration::from_secs(5), helper.frames.changed())
        .await
        .expect("no screen reached the helper after its input failed")
        .expect("the helper's screens stopped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_locked_computer_keeps_sharing_and_says_why_input_is_not_landing() {
    timeout(Duration::from_secs(60), async {
        let mut p = pair(true).await;
        // Several clicks while it is locked: one notice for the whole run.
        for _ in 0..3 {
            click(&p.helper);
        }
        let heard = notices(&mut p, Duration::from_millis(1500)).await;
        assert_eq!(
            heard,
            [HostNotice::InputUnavailable {
                trouble: InputTrouble::LockScreen,
                reason: "no connection could be established: (failed creating event source)".into(),
            }]
        );
        assert!(heard[0].text().unwrap().contains("lock screen"));
        assert_eq!(p.landed.load(Ordering::SeqCst), 0);
        still_shared(&mut p.helper).await;
        // Someone unlocks it: the next click lands, and the helper hears so.
        p.locked.store(false, Ordering::SeqCst);
        click(&p.helper);
        let heard = notices(&mut p, Duration::from_millis(1500)).await;
        assert_eq!(heard, [HostNotice::InputBack]);
        assert_eq!(heard[0].text(), None);
        assert_eq!(p.landed.load(Ordering::SeqCst), 2);
        // Locked again: told again.
        p.locked.store(true, Ordering::SeqCst);
        click(&p.helper);
        let heard = notices(&mut p, Duration::from_millis(1500)).await;
        assert!(
            matches!(heard[..], [HostNotice::InputUnavailable { .. }]),
            "{heard:?}"
        );
        p.host.stop();
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_that_reads_no_notices_is_never_sent_one() {
    timeout(Duration::from_secs(60), async {
        let mut p = pair(false).await;
        for _ in 0..3 {
            click(&p.helper);
        }
        // A notice would end this helper's session, as it ends an older
        // helper's, and `notices` panics on that.
        let heard = notices(&mut p, Duration::from_millis(2000)).await;
        assert!(heard.is_empty(), "{heard:?}");
        still_shared(&mut p.helper).await;
        p.locked.store(false, Ordering::SeqCst);
        click(&p.helper);
        assert!(
            notices(&mut p, Duration::from_millis(1000))
                .await
                .is_empty()
        );
        assert_eq!(p.landed.load(Ordering::SeqCst), 2);
        p.host.stop();
    })
    .await
    .expect("timed out");
}
