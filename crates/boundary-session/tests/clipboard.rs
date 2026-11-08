//! Clipboard text over a Boundary session, end to end over real connections
//! on this machine, with a fake desktop whose clipboard the test copies to
//! and reads. What the person copies goes to a helper only while they allow
//! it, the helper's text lands only while it has control, and peers that do
//! not speak clipboard are never sent a clipboard message.

use boundary_session::{
    Abilities, Approval, ClipboardRights, Desktop, Event, Frame, HostOptions, Input, Invitation,
    Key, MAX_CLIPBOARD, Session,
    unattended::{self, Access, Notice},
};
use iroh::endpoint::{RecvStream, SendStream, presets};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

const ALPN: &[u8] = b"boundary/support-experimental/1";

/// The person's clipboard on the fake desktop.
#[derive(Default)]
struct Board {
    text: String,
    /// Bumped by every copy, as Windows bumps its sequence number.
    seq: u64,
    /// The last `seq` the session was told about.
    seen: u64,
    /// How often the session looked.
    polls: u32,
}
type Shared = Arc<Mutex<Board>>;

/// A board with something copied before any session began.
fn board() -> Shared {
    Arc::new(Mutex::new(Board {
        text: "copied before the session".into(),
        seq: 1,
        ..Board::default()
    }))
}
/// The person copies `text`.
fn copy(board: &Shared, text: &str) {
    let mut board = board.lock().unwrap();
    board.text = text.into();
    board.seq += 1;
}
fn clipboard_of(board: &Shared) -> String {
    board.lock().unwrap().text.clone()
}

/// A still screen with a clipboard. It reports every change since it was
/// last asked, including on the first call, which is stricter than the
/// contract asks of a real backend: the session itself must hold back what
/// was there before.
struct Fake {
    board: Shared,
    clipboard: bool,
}
impl Desktop for Fake {
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
    fn has_clipboard(&self) -> bool {
        self.clipboard
    }
    fn clipboard_changed(&mut self) -> anyhow::Result<Option<String>> {
        let mut board = self.board.lock().unwrap();
        board.polls += 1;
        if board.seq == board.seen {
            return Ok(None);
        }
        board.seen = board.seq;
        Ok(Some(board.text.clone()))
    }
    fn set_clipboard(&mut self, text: &str) -> anyhow::Result<()> {
        copy(&self.board, text);
        Ok(())
    }
}

fn local() -> HostOptions {
    HostOptions {
        relay: false,
        relay_url: None,
        bind_ip: None,
    }
}
fn abilities(clipboard: bool) -> Abilities {
    Abilities {
        tools: false,
        video: false,
        clipboard,
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

/// Answer the next prompt with `approval`, letting the helper see what is
/// copied if `read`, and say whether the prompt offered the clipboard.
async fn approve(host: &mut Session, approval: Approval, read: bool) -> bool {
    loop {
        match host.events.recv().await {
            Some(Event::Approval {
                clipboard, answer, ..
            }) => {
                host.set_clipboard_read(read);
                let _ = answer.send(approval);
                return clipboard;
            }
            Some(Event::Finished(result)) => panic!("the host stopped: {result:?}"),
            None => panic!("the host went quiet"),
            _ => {}
        }
    }
}

/// What a helper hears from the host about the clipboard.
#[derive(Debug, PartialEq)]
enum Heard {
    Rights(ClipboardRights),
    Text(String),
    Control(bool),
}
/// The next clipboard or control event the helper hears, within `wait`.
async fn next(helper: &mut Session, wait: Duration) -> Option<Heard> {
    let end = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(end, helper.events.recv()).await {
            Err(_) => return None,
            Ok(Some(Event::ClipboardRights(rights))) => return Some(Heard::Rights(rights)),
            Ok(Some(Event::ClipboardText(text))) => return Some(Heard::Text(text)),
            Ok(Some(Event::Control(control))) => return Some(Heard::Control(control)),
            Ok(Some(Event::Finished(result))) => panic!("the helper's session ended: {result:?}"),
            Ok(None) => panic!("the helper went quiet"),
            Ok(Some(_)) => {}
        }
    }
}
/// Wait for the helper to be let in.
async fn connected(helper: &mut Session) {
    loop {
        match helper.events.recv().await {
            Some(Event::Connected { .. }) => return,
            Some(Event::Finished(result)) => panic!("the helper did not get in: {result:?}"),
            None => panic!("the helper went quiet"),
            _ => {}
        }
    }
}
/// The activity lines the host has shown so far.
fn activity(host: &mut Session) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(event) = host.events.try_recv() {
        match event {
            Event::Activity(line) => lines.push(line),
            Event::Finished(result) => panic!("the host's session ended: {result:?}"),
            _ => {}
        }
    }
    lines
}
/// Poll `check` until it holds or `wait` passes.
async fn eventually(wait: Duration, mut check: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + wait;
    while Instant::now() < end {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    check()
}

struct Pair {
    host: Session,
    helper: Session,
    board: Shared,
}
/// A host with a fake clipboard and a helper let in with `approval`.
async fn pair(clipboard: bool, approval: Approval, read: bool) -> (Pair, bool) {
    let board = board();
    let shared = board.clone();
    let mut host = boundary_session::host(local(), move || {
        Ok(Box::new(Fake {
            board: shared,
            clipboard: true,
        }))
    });
    let ticket = invitation(&mut host).await;
    let mut helper = boundary_session::viewer_with(
        ticket,
        "Clipboard test".into(),
        local(),
        None,
        abilities(clipboard),
    );
    let offered = approve(&mut host, approval, read).await;
    connected(&mut helper).await;
    (
        Pair {
            host,
            helper,
            board,
        },
        offered,
    )
}

const QUIET: Duration = Duration::from_millis(2000);
const SOON: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_without_clipboard_is_never_sent_any() {
    timeout(Duration::from_secs(60), async {
        let (mut p, offered) = pair(false, Approval::Control, true).await;
        assert!(
            !offered,
            "the prompt offered clipboard to a helper that cannot take it"
        );
        assert!(!p.host.clipboard_read_allowed(), "reading stayed on for it");
        copy(&p.board, "a password");
        // Any clipboard message would end this helper's session, as it ends
        // an older helper's, and `next` panics on that.
        assert_eq!(next(&mut p.helper, QUIET).await, None);
        assert_eq!(
            p.board.lock().unwrap().polls,
            0,
            "the clipboard was looked at"
        );
        assert!(p.helper.send_clipboard("hello".into()).is_err());
        assert_eq!(p.helper.clipboard_rights(), ClipboardRights::default());
        p.host.stop();
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_is_read_unless_the_person_allows_it() {
    timeout(Duration::from_secs(60), async {
        let (mut p, offered) = pair(true, Approval::Control, false).await;
        assert!(offered);
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: true,
                read: false
            }))
        );
        copy(&p.board, "a password");
        assert_eq!(next(&mut p.helper, QUIET).await, None);
        assert_eq!(
            p.board.lock().unwrap().polls,
            0,
            "the clipboard was looked at"
        );
        p.host.stop();
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_person_copies_reaches_the_helper_until_they_stop_it() {
    timeout(Duration::from_secs(60), async {
        let (mut p, _) = pair(true, Approval::View, true).await;
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: false,
                read: true
            }))
        );
        // What was copied before the session never goes, though the fake
        // reports it on the first look.
        assert!(eventually(SOON, || p.board.lock().unwrap().polls >= 2).await);
        assert_eq!(next(&mut p.helper, Duration::from_millis(700)).await, None);

        copy(&p.board, "first copy");
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Text("first copy".into()))
        );
        assert!(
            eventually(SOON, || activity(&mut p.host)
                .contains(&"They got 10 characters you copied".to_string()))
            .await
        );

        p.host.set_clipboard_read(false);
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: false,
                read: false
            }))
        );
        copy(&p.board, "second copy");
        assert_eq!(next(&mut p.helper, QUIET).await, None);

        // On again: what was copied while it was off stays here too.
        p.host.set_clipboard_read(true);
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: false,
                read: true
            }))
        );
        assert_eq!(next(&mut p.helper, QUIET).await, None);
        copy(&p.board, "third");
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Text("third".into()))
        );
        p.host.stop();
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_helper_writes_only_while_it_has_control_and_hears_no_echo() {
    timeout(Duration::from_secs(60), async {
        let (mut p, _) = pair(true, Approval::View, true).await;
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: false,
                read: true
            }))
        );
        let refused = p.helper.send_clipboard("too early".into()).unwrap_err();
        assert!(format!("{refused:#}").contains("control"), "{refused:#}");

        p.host.set_control(true);
        assert_eq!(next(&mut p.helper, SOON).await, Some(Heard::Control(true)));
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: true,
                read: true
            }))
        );
        // Too long: refused here, and the session goes on.
        let long = p
            .helper
            .send_clipboard("x".repeat(MAX_CLIPBOARD + 1))
            .unwrap_err();
        assert!(format!("{long:#}").contains("too large"), "{long:#}");

        p.helper.send_clipboard("from helper".into()).unwrap();
        assert!(eventually(SOON, || clipboard_of(&p.board) == "from helper").await);
        assert!(
            eventually(SOON, || activity(&mut p.host)
                .contains(&"They put 11 characters on your clipboard".to_string()))
            .await
        );
        // The host's own write is not sent back as if the person copied it.
        assert_eq!(next(&mut p.helper, QUIET).await, None);
        // And what the person copies afterwards still goes.
        copy(&p.board, "after");
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Text("after".into()))
        );

        // A megabyte exactly is allowed, and arrives whole.
        let big = "é".repeat(MAX_CLIPBOARD / 2);
        p.helper.send_clipboard(big.clone()).unwrap();
        assert!(eventually(Duration::from_secs(20), || clipboard_of(&p.board) == big).await);

        p.host.set_control(false);
        assert_eq!(next(&mut p.helper, SOON).await, Some(Heard::Control(false)));
        assert_eq!(
            next(&mut p.helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: false,
                read: true
            }))
        );
        assert!(p.helper.send_clipboard("too late".into()).is_err());
        p.host.stop();
    })
    .await
    .expect("timed out");
}

/// A desktop that opens only when the test says, as GNOME's desktop opens
/// only once the person answers its sharing prompt.
fn opening_late(board: Shared) -> (std::sync::mpsc::Sender<()>, Session) {
    let (open, opened) = std::sync::mpsc::channel::<()>();
    let host = boundary_session::host(local(), move || {
        let _ = opened.recv_timeout(Duration::from_secs(30));
        Ok(Box::new(Fake {
            board,
            clipboard: true,
        }))
    });
    (open, host)
}

/// Control given on the sharing screen while the desktop is still opening
/// reaches the helper once it opens, and with it the right to write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_given_while_the_desktop_opens_reaches_the_helper() {
    timeout(Duration::from_secs(60), async {
        let board = board();
        let (open, mut host) = opening_late(board.clone());
        let ticket = invitation(&mut host).await;
        let mut helper = boundary_session::viewer_with(
            ticket,
            "Clipboard test".into(),
            local(),
            None,
            abilities(true),
        );
        approve(&mut host, Approval::View, true).await;
        connected(&mut helper).await;
        assert_eq!(
            next(&mut helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: false,
                read: true
            }))
        );
        host.set_control(true);
        open.send(()).unwrap();
        assert_eq!(next(&mut helper, SOON).await, Some(Heard::Control(true)));
        assert_eq!(
            next(&mut helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: true,
                read: true
            }))
        );
        helper.send_clipboard("with control".into()).unwrap();
        assert!(eventually(SOON, || clipboard_of(&board) == "with control").await);
        host.stop();
    })
    .await
    .expect("timed out");
}

/// Control taken back while the desktop is still opening stays taken back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_taken_back_while_the_desktop_opens_stays_off() {
    timeout(Duration::from_secs(60), async {
        let board = board();
        let (open, mut host) = opening_late(board.clone());
        let ticket = invitation(&mut host).await;
        let mut helper = boundary_session::viewer_with(
            ticket,
            "Clipboard test".into(),
            local(),
            None,
            abilities(true),
        );
        approve(&mut host, Approval::Control, false).await;
        connected(&mut helper).await;
        assert_eq!(
            next(&mut helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: true,
                read: false
            }))
        );
        host.set_control(false);
        open.send(()).unwrap();
        assert_eq!(next(&mut helper, SOON).await, Some(Heard::Control(false)));
        assert_eq!(
            next(&mut helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: false,
                read: false
            }))
        );
        assert!(helper.send_clipboard("too late".into()).is_err());
        host.stop();
    })
    .await
    .expect("timed out");
}

/// A clipboard whose first look is slow, as one busy computer's can be.
/// That look waits until the test has copied, or two seconds.
struct SlowFirstLook {
    fake: Fake,
    copied: Option<std::sync::mpsc::Receiver<()>>,
}
impl Desktop for SlowFirstLook {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        self.fake.capture()
    }
    fn input(&mut self, input: Input) -> anyhow::Result<()> {
        self.fake.input(input)
    }
    fn release(&mut self) {}
    fn has_clipboard(&self) -> bool {
        true
    }
    fn clipboard_changed(&mut self) -> anyhow::Result<Option<String>> {
        if let Some(copied) = self.copied.take() {
            let _ = copied.recv_timeout(Duration::from_secs(2));
        }
        self.fake.clipboard_changed()
    }
    fn set_clipboard(&mut self, text: &str) -> anyhow::Result<()> {
        self.fake.set_clipboard(text)
    }
}

/// What the person copies once they are told their screen is shared goes
/// to the helper, however late the session takes its first look.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_made_as_sharing_starts_reaches_the_helper() {
    timeout(Duration::from_secs(60), async {
        let board = board();
        let shared = board.clone();
        let (copied, looked) = std::sync::mpsc::channel::<()>();
        let mut host = boundary_session::host(local(), move || {
            Ok(Box::new(SlowFirstLook {
                fake: Fake {
                    board: shared,
                    clipboard: true,
                },
                copied: Some(looked),
            }))
        });
        let ticket = invitation(&mut host).await;
        let mut helper = boundary_session::viewer_with(
            ticket,
            "Clipboard test".into(),
            local(),
            None,
            abilities(true),
        );
        approve(&mut host, Approval::View, true).await;
        loop {
            match host.events.recv().await {
                Some(Event::Connected { .. }) => break,
                Some(Event::Finished(result)) => panic!("the host stopped: {result:?}"),
                None => panic!("the host went quiet"),
                _ => {}
            }
        }
        copy(&board, "copied as it started");
        let _ = copied.send(());
        assert_eq!(
            next(&mut helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: false,
                read: true
            }))
        );
        assert_eq!(
            next(&mut helper, SOON).await,
            Some(Heard::Text("copied as it started".into()))
        );
        host.stop();
    })
    .await
    .expect("timed out");
}

/// A desktop without a clipboard: the helper is told it has neither right,
/// and the person's tick goes back off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_desktop_without_a_clipboard_grants_neither() {
    timeout(Duration::from_secs(60), async {
        let board = board();
        let shared = board.clone();
        let mut host = boundary_session::host(local(), move || {
            Ok(Box::new(Fake {
                board: shared,
                clipboard: false,
            }))
        });
        let ticket = invitation(&mut host).await;
        let mut helper = boundary_session::viewer_with(
            ticket,
            "Clipboard test".into(),
            local(),
            None,
            abilities(true),
        );
        approve(&mut host, Approval::Control, true).await;
        connected(&mut helper).await;
        // Promised with the grant, then taken back once the desktop opened.
        assert_eq!(
            next(&mut helper, SOON).await,
            Some(Heard::Rights(ClipboardRights {
                write: true,
                read: true
            }))
        );
        assert_eq!(
            next(&mut helper, SOON).await,
            Some(Heard::Rights(ClipboardRights::default()))
        );
        assert!(!host.clipboard_read_allowed());
        copy(&board, "a password");
        assert_eq!(next(&mut helper, QUIET).await, None);
        assert_eq!(board.lock().unwrap().polls, 0);
        assert!(helper.send_clipboard("hello".into()).is_err());
        host.stop();
    })
    .await
    .expect("timed out");
}

// A peer that speaks the wire by hand, to send what a well behaved one
// never would and to stand in for copies older than clipboard.

async fn put(send: &mut SendStream, value: &Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    send.write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .unwrap();
    send.write_all(&bytes).await.unwrap();
}
async fn take(recv: &mut RecvStream) -> Value {
    let mut length = [0; 4];
    recv.read_exact(&mut length).await.unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
    recv.read_exact(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
async fn raw_endpoint(alpn: bool) -> iroh::Endpoint {
    let mut builder =
        iroh::Endpoint::builder(presets::Minimal).relay_mode(iroh::RelayMode::Disabled);
    if alpn {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    builder.bind().await.unwrap()
}

/// What the host must refuse it refuses quietly: text without control, and
/// text over the limit with control. The session goes on and the next
/// allowed text lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_refuses_what_it_may_not_take_and_goes_on() {
    timeout(Duration::from_secs(60), async {
        let board = board();
        let shared = board.clone();
        let mut host = boundary_session::host(local(), move || {
            Ok(Box::new(Fake {
                board: shared,
                clipboard: true,
            }))
        });
        let ticket = invitation(&mut host).await;
        let invite = Invitation::decode(&ticket).unwrap();
        let endpoint = raw_endpoint(false).await;
        let connection = endpoint
            .connect(invite.address.clone(), ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        put(
            &mut send,
            &json!({"Hello": {
                "version": 1,
                "secret": invite.secret,
                "name": "Raw helper",
                "clipboard": true,
            }}),
        )
        .await;
        approve(&mut host, Approval::View, false).await;
        let granted = take(&mut recv).await;
        assert_eq!(
            granted,
            json!({"Granted": {"control": false, "clipboard": {"write": false, "read": false}}})
        );

        // Without control: refused, and nothing ends.
        put(&mut send, &json!({"Clipboard": "no control"})).await;
        put(&mut send, &json!("Ping")).await;
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(clipboard_of(&board), "copied before the session");

        host.set_control(true);
        assert_eq!(take(&mut recv).await, json!({"Control": true}));
        assert_eq!(
            take(&mut recv).await,
            json!({"ClipboardRights": {"write": true, "read": false}})
        );
        // Over the limit, with control: refused, and nothing ends.
        put(
            &mut send,
            &json!({"Clipboard": "y".repeat(MAX_CLIPBOARD + 1)}),
        )
        .await;
        put(&mut send, &json!("Ping")).await;
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(clipboard_of(&board), "copied before the session");

        put(&mut send, &json!({"Clipboard": "allowed"})).await;
        assert!(eventually(SOON, || clipboard_of(&board) == "allowed").await);
        put(&mut send, &json!("Ping")).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            connection.close_reason().is_none(),
            "the host ended the session"
        );
        let lines = activity(&mut host);
        assert!(
            lines
                .iter()
                .filter(|l| l.contains("on your clipboard"))
                .count()
                == 1,
            "{lines:?}"
        );
        host.stop();
        endpoint.close().await;
    })
    .await
    .expect("timed out");
}

/// A host from before clipboard grants without saying anything about it.
/// The helper then has no rights, refuses to send, and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_with_an_older_host_sends_no_clipboard() {
    timeout(Duration::from_secs(60), async {
        let endpoint = raw_endpoint(true).await;
        let mut secret = [0u8; 32];
        secret[0] = 7;
        let ticket = Invitation {
            version: 1,
            address: endpoint.addr(),
            secret,
            expires: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600,
        }
        .encode()
        .unwrap();
        let mut helper = boundary_session::viewer_with(
            ticket,
            "New helper".into(),
            local(),
            None,
            abilities(true),
        );
        let incoming = endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let hello = take(&mut recv).await;
        assert_eq!(hello["Hello"]["clipboard"], json!(true));
        // Exactly what 0.34.1 writes for a helper without tools.
        put(&mut send, &json!({"Granted": {"control": true}})).await;
        connected(&mut helper).await;
        assert!(helper.send_clipboard("hello".into()).is_err());
        assert_eq!(helper.clipboard_rights(), ClipboardRights::default());
        let end = Instant::now() + QUIET;
        while Instant::now() < end {
            let message = timeout(Duration::from_secs(3), take(&mut recv))
                .await
                .expect("the helper stopped sending");
            assert_eq!(message, json!("Ping"), "an older host was sent {message}");
        }
        // No clipboard event reached the window either.
        while let Ok(event) = helper.events.try_recv() {
            assert!(
                !matches!(event, Event::ClipboardRights(_) | Event::ClipboardText(_)),
                "the helper was told about a clipboard an older host does not have"
            );
        }
        helper.stop();
        endpoint.close().await;
    })
    .await
    .expect("timed out");
}

/// Every test of the unattended listener listens on the machine's own
/// addresses, which on Windows asks the firewall, so there they run only
/// when asked for, as in the unattended tests.
fn skipped() -> bool {
    cfg!(windows) && std::env::var_os("BOUNDARY_LAN_TESTS").is_none()
}

/// At the sign in screen nobody is there to see what was copied, and what is
/// copied there is most likely a password: a paired helper allowed to read
/// still reads nothing. Signed in, the same helper does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sign_in_screen_never_lets_a_helper_read() {
    if skipped() {
        return;
    }
    timeout(Duration::from_secs(90), async {
        let dir = std::env::temp_dir().join(format!(
            "boundary-clipboard-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let friend = unattended::load_or_create_key(&dir.join("friend.key")).unwrap();
        let access_path = dir.join("access.json");
        let mut access = Access::default();
        access.enabled = true;
        access
            .trust(&friend.public().to_string(), "Friend", true)
            .unwrap();
        assert!(!access.helpers[0].clipboard, "a new helper may read");
        assert!(access.allow_clipboard(&friend.public().to_string(), true));
        access.save(&access_path).unwrap();

        for login in [true, false] {
            let board = board();
            let shared = board.clone();
            let machine_key = unattended::load_or_create_key(&dir.join("machine.key")).unwrap();
            let factory = move || -> anyhow::Result<Box<dyn Desktop>> {
                Ok(Box::new(Fake {
                    board: shared.clone(),
                    clipboard: true,
                }))
            };
            let mut listener = if login {
                unattended::listen_at_login(local(), machine_key, access_path.clone(), factory)
            } else {
                unattended::listen(local(), machine_key, access_path.clone(), factory)
            };
            let address = loop {
                match listener.notices.recv().await {
                    Some(Notice::Ready { address, .. }) => break address,
                    Some(Notice::Finished(result)) => panic!("listener ended: {result:?}"),
                    _ => {}
                }
            };
            let mut helper = unattended::connect_to_with(
                Ok(address),
                "Friend".into(),
                None,
                friend.clone(),
                local(),
                abilities(true),
            );
            let held = loop {
                match listener.notices.recv().await {
                    Some(Notice::Connected { session, .. }) => break session,
                    Some(Notice::Ask { .. }) => panic!("a paired helper was asked"),
                    Some(Notice::Finished(result)) => panic!("listener ended: {result:?}"),
                    _ => {}
                }
            };
            assert_eq!(held.clipboard_read_allowed(), !login);
            connected(&mut helper).await;
            assert_eq!(
                next(&mut helper, SOON).await,
                Some(Heard::Rights(ClipboardRights {
                    write: true,
                    read: !login
                }))
            );
            if login {
                copy(&board, "typed at the sign in screen");
                assert_eq!(next(&mut helper, QUIET).await, None);
                assert_eq!(board.lock().unwrap().polls, 0);
            } else {
                assert!(eventually(SOON, || board.lock().unwrap().polls >= 2).await);
                copy(&board, "signed in");
                assert_eq!(
                    next(&mut helper, SOON).await,
                    Some(Heard::Text("signed in".into()))
                );
            }
            helper.stop();
            drop(held);
            listener.stop();
        }
        let _ = std::fs::remove_dir_all(dir);
    })
    .await
    .expect("timed out");
}

/// A busy computer, slow to come back for the next input, whose keys note
/// what was on the clipboard when each paste key went down.
struct Typist {
    board: Shared,
    keys: Arc<Mutex<Vec<String>>>,
}
impl Desktop for Typist {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        // Everything the helper sends meanwhile waits on the host, as it
        // does behind a slow link.
        std::thread::sleep(Duration::from_millis(40));
        Ok(Frame {
            width: 2,
            height: 2,
            rgba: vec![90; 16],
        })
    }
    fn input(&mut self, input: Input) -> anyhow::Result<()> {
        if let Input::Key {
            key: Key::Letter('v'),
            down: true,
        } = input
        {
            let text = clipboard_of(&self.board);
            self.keys.lock().unwrap().push(text);
        }
        Ok(())
    }
    fn release(&mut self) {}
    fn has_clipboard(&self) -> bool {
        true
    }
    fn set_clipboard(&mut self, text: &str) -> anyhow::Result<()> {
        copy(&self.board, text);
        Ok(())
    }
}

/// A helper pastes by putting its text on the clipboard and then pressing
/// the paste keys. Each paste must find its own text there, however the
/// messages pile up on the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_paste_keys_find_the_text_sent_before_them() {
    timeout(Duration::from_secs(90), async {
        let board = board();
        let keys = Arc::new(Mutex::new(Vec::new()));
        let (b, k) = (board.clone(), keys.clone());
        let mut host =
            boundary_session::host(local(), move || Ok(Box::new(Typist { board: b, keys: k })));
        let ticket = invitation(&mut host).await;
        let mut helper = boundary_session::viewer_with(
            ticket,
            "Clipboard test".into(),
            local(),
            None,
            abilities(true),
        );
        approve(&mut host, Approval::Control, false).await;
        connected(&mut helper).await;
        loop {
            if let Some(Heard::Rights(rights)) = next(&mut helper, SOON).await {
                if rights.write {
                    break;
                }
            } else {
                panic!("never allowed to write");
            }
        }
        // Let the host's busy loop settle into its pace first.
        tokio::time::sleep(Duration::from_millis(300)).await;
        const PASTES: usize = 40;
        for i in 0..PASTES {
            // The helper's own queue holds two texts; a full one says so.
            while let Err(error) = helper.send_clipboard(format!("paste {i}")) {
                assert!(format!("{error:#}").contains("Still sending"), "{error:#}");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            for down in [true, false] {
                helper
                    .input(Input::Key {
                        key: Key::Letter('v'),
                        down,
                    })
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
            let _ = activity(&mut host);
        }
        assert!(
            eventually(Duration::from_secs(30), || {
                let _ = activity(&mut host);
                keys.lock().unwrap().len() == PASTES
            })
            .await,
            "only {} pastes arrived",
            keys.lock().unwrap().len()
        );
        let expected: Vec<String> = (0..PASTES).map(|i| format!("paste {i}")).collect();
        assert_eq!(*keys.lock().unwrap(), expected);
        host.stop();
    })
    .await
    .expect("timed out");
}
