//! Clipboard text through the DeskVNC driver, over real connections on this
//! machine. The window's `ClientCommand::ClipboardText` reaches the host's
//! clipboard only while the host says it takes it, what the person copies
//! comes back as `SessionEvent::ClipboardText`, the rights reach the shell as
//! `ProtocolEvent::BoundaryClipboard`, and a host from before clipboard (no
//! clipboard in its grant) is never sent any and never gives any rights.

use boundary_driver::BoundaryDriver;
use boundary_session::{Approval, Desktop, Event, Frame, HostOptions, Input, Invitation};
use iroh::endpoint::{presets, RecvStream, SendStream};
use remote_core::{
    ClientCommand, ConnectOptions, ProtocolDriver, ProtocolEvent, SessionEvent, SessionState,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::{sync::mpsc, time::timeout};

const ALPN: &[u8] = b"boundary/support-experimental/1";
const SOON: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(1500);

/// The person's clipboard on the fake desktop: its text and a counter bumped
/// by every copy, with the counter the session last saw.
type Board = Arc<Mutex<(String, u64, u64)>>;

fn copy(board: &Board, text: &str) {
    let mut board = board.lock().unwrap();
    board.0 = text.into();
    board.1 += 1;
}
fn clipboard_of(board: &Board) -> String {
    board.lock().unwrap().0.clone()
}

struct Fake(Board);
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
        true
    }
    fn clipboard_changed(&mut self) -> anyhow::Result<Option<String>> {
        let mut board = self.0.lock().unwrap();
        if board.1 == board.2 {
            return Ok(None);
        }
        board.2 = board.1;
        Ok(Some(board.0.clone()))
    }
    fn set_clipboard(&mut self, text: &str) -> anyhow::Result<()> {
        copy(&self.0, text);
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

/// What the driver tells the window about the clipboard.
#[derive(Debug, PartialEq)]
enum Heard {
    Rights { write: bool, read: bool },
    Text(String),
}
async fn next(rx: &mut mpsc::Receiver<SessionEvent>, wait: Duration) -> Option<Heard> {
    let end = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(end, rx.recv()).await {
            Err(_) => return None,
            Ok(Some(SessionEvent::Protocol(ProtocolEvent::BoundaryClipboard { write, read }))) => {
                return Some(Heard::Rights { write, read });
            }
            Ok(Some(SessionEvent::ClipboardText(text))) => return Some(Heard::Text(text)),
            Ok(Some(SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }))) => {
                panic!("the session ended: {reason}")
            }
            Ok(None) => panic!("the driver went quiet"),
            Ok(Some(_)) => {}
        }
    }
}
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

/// Both ways through the driver: the window's text lands on the host only
/// while the helper has control, and what the person copies reaches the
/// window while they let the helper see it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clipboard_text_goes_both_ways_through_the_driver_as_the_host_allows() {
    timeout(Duration::from_secs(60), async {
        let board: Board = Arc::new(Mutex::new(("copied before the session".into(), 1, 0)));
        let shared = board.clone();
        let mut host = boundary_session::host(local(), move || Ok(Box::new(Fake(shared.clone()))));
        let ticket = loop {
            if let Some(Event::Invitation(ticket)) = host.events.recv().await {
                break ticket;
            }
        };
        let driver = BoundaryDriver::default();
        let id = driver.prepare(ticket, "DeskVNC helper".into()).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = driver
            .spawn("clipboard".into(), ConnectOptions::boundary(id), tx)
            .unwrap();
        loop {
            if let Some(Event::Approval {
                clipboard, answer, ..
            }) = host.events.recv().await
            {
                assert!(clipboard, "DeskVNC's hello must say it carries a clipboard");
                host.set_clipboard_read(true);
                answer.send(Approval::View).ok().unwrap();
                break;
            }
        }
        handle
            .send(ClientCommand::SetViewOnly(false))
            .await
            .unwrap();
        assert_eq!(
            next(&mut rx, SOON).await,
            Some(Heard::Rights {
                write: false,
                read: true
            })
        );

        // What was copied before the session never comes; a copy made once
        // the person is told the screen is shared does. A copy made before
        // that, while the desktop was still opening, was taken for what was
        // there before and the test waited for it in vain.
        loop {
            match host.events.recv().await {
                Some(Event::Connected { .. }) => break,
                Some(Event::Finished(result)) => panic!("the host stopped: {result:?}"),
                None => panic!("the host went quiet"),
                _ => {}
            }
        }
        copy(&board, "copied on the host");
        assert_eq!(
            next(&mut rx, SOON).await,
            Some(Heard::Text("copied on the host".into()))
        );

        // Without control the host does not take the window's text, and the
        // driver does not even send it.
        handle
            .send(ClientCommand::ClipboardText("too early".into()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(clipboard_of(&board), "copied on the host");

        host.set_control(true);
        assert_eq!(
            next(&mut rx, SOON).await,
            Some(Heard::Rights {
                write: true,
                read: true
            })
        );
        handle
            .send(ClientCommand::ClipboardText(
                "pasted from the helper".into(),
            ))
            .await
            .unwrap();
        assert!(eventually(SOON, || clipboard_of(&board) == "pasted from the helper").await);
        // The host's own write does not echo back to the window.
        assert_eq!(next(&mut rx, QUIET).await, None);

        // Control taken back: write goes, read stays.
        host.set_control(false);
        assert_eq!(
            next(&mut rx, SOON).await,
            Some(Heard::Rights {
                write: false,
                read: true
            })
        );
        handle
            .send(ClientCommand::ClipboardText("after control went".into()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(clipboard_of(&board), "pasted from the helper");

        // The person stops letting the helper see what they copy.
        host.set_clipboard_read(false);
        assert_eq!(
            next(&mut rx, SOON).await,
            Some(Heard::Rights {
                write: false,
                read: false
            })
        );
        copy(&board, "a password");
        assert_eq!(next(&mut rx, QUIET).await, None);

        handle.shutdown();
        host.stop();
    })
    .await
    .expect("timed out");
}

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

/// A 0.34.1 host grants without a word about the clipboard. The driver then
/// tells the shell no rights at all, so the limb offers neither direction,
/// and text from the window is never put on the wire, where an older host
/// would end the session on a message it does not know.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_older_host_leaves_the_clipboard_off_and_is_sent_none() {
    timeout(Duration::from_secs(60), async {
        let endpoint = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let mut secret = [0u8; 32];
        secret[0] = 9;
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
        let driver = BoundaryDriver::default();
        let id = driver.prepare(ticket, "DeskVNC helper".into()).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = driver
            .spawn("older-host".into(), ConnectOptions::boundary(id), tx)
            .unwrap();
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let hello = take(&mut recv).await;
        assert_eq!(hello["Hello"]["clipboard"], json!(true));
        // Exactly what 0.34.1 writes when it lets a helper in with control.
        put(&mut send, &json!({"Granted": {"control": true}})).await;
        let mut events = Vec::new();
        loop {
            match timeout(SOON, rx.recv()).await.expect("never let in") {
                Some(SessionEvent::Protocol(ProtocolEvent::Boundary { control, .. })) => {
                    assert!(control);
                    break;
                }
                Some(SessionEvent::StateChanged(SessionState::Disconnected { reason, .. })) => {
                    panic!("{reason}")
                }
                Some(event) => events.push(event),
                None => panic!("the driver went quiet"),
            }
        }
        handle
            .send(ClientCommand::SetViewOnly(false))
            .await
            .unwrap();
        handle
            .send(ClientCommand::ClipboardText("never sent".into()))
            .await
            .unwrap();
        // Everything the driver sends from here on, read whole on a task of
        // its own so no message is cut by a timeout.
        let (heard_tx, mut heard) = mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            loop {
                let message = take(&mut recv).await;
                if heard_tx.send(message).is_err() {
                    break;
                }
            }
        });
        tokio::time::sleep(QUIET).await;
        while let Ok(message) = heard.try_recv() {
            assert!(
                message.get("Clipboard").is_none(),
                "an older host was sent {message}"
            );
        }
        reader.abort();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        for event in &events {
            assert!(
                !matches!(
                    event,
                    SessionEvent::Protocol(ProtocolEvent::BoundaryClipboard { write: true, .. })
                        | SessionEvent::Protocol(ProtocolEvent::BoundaryClipboard {
                            read: true,
                            ..
                        })
                        | SessionEvent::ClipboardText(_)
                ),
                "the shell was told about a clipboard an older host does not have: {event:?}"
            );
        }
        assert!(connection.close_reason().is_none(), "the session ended");
        handle.shutdown();
        endpoint.close().await;
    })
    .await
    .expect("timed out");
}
