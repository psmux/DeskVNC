use boundary_driver::BoundaryDriver;
use boundary_session::{Approval, Desktop, Event, Frame, HostOptions, Input};
use remote_core::{
    ClientCommand, ConnectOptions, ProtocolDriver, ProtocolEvent, RectPayload, SessionEvent,
    SessionState,
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::mpsc, time::timeout};
struct Fake(Arc<AtomicUsize>);
impl Desktop for Fake {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        Ok(Frame {
            width: 2,
            height: 2,
            rgba: vec![128; 16],
        })
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn release(&mut self) {}
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deskvnc_driver_receives_boundary_frames_and_obeys_host_consent() {
    timeout(Duration::from_secs(20), async {
        let inputs = Arc::new(AtomicUsize::new(0));
        let count = inputs.clone();
        let mut host = boundary_session::host(HostOptions { relay: false, relay_url: None, bind_ip: None }, move || Ok(Box::new(Fake(count))));
        let ticket = loop { if let Some(Event::Invitation(ticket)) = host.events.recv().await { break ticket; } };
        let driver = BoundaryDriver::default();
        let id = driver.prepare(ticket, "DeskVNC helper".into()).unwrap();
        let (tx, mut rx) = mpsc::channel(32);
        let handle = driver.spawn("test-session".into(), ConnectOptions::boundary(id.clone()), tx).unwrap();
        loop { if let Some(Event::Approval { answer, .. }) = host.events.recv().await { answer.send(Approval::View).ok().unwrap(); break; } }
        let mut permission = false;
        loop {
            match rx.recv().await.unwrap() {
                SessionEvent::Protocol(ProtocolEvent::Boundary { control }) => { assert!(!control); permission = true; }
                SessionEvent::FramebufferUpdate { rects, .. } => {
                    assert!(permission);
                    assert!(matches!(&rects[0].payload, RectPayload::Rgba(pixels) if pixels == &vec![128; 16]));
                    break;
                }
                SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => panic!("{reason}"),
                _ => {},
            }
        }
        handle.send(ClientCommand::SetViewOnly(false)).await.unwrap();
        handle.send(ClientCommand::Pointer { x: 1, y: 1, button_mask: 1 }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(180)).await;
        assert_eq!(inputs.load(Ordering::SeqCst), 0);
        host.set_control(true);
        loop { if let Some(SessionEvent::Protocol(ProtocolEvent::Boundary { control: true })) = rx.recv().await { break; } }
        handle.send(ClientCommand::Pointer { x: 1, y: 1, button_mask: 1 }).await.unwrap();
        while inputs.load(Ordering::SeqCst) == 0 { tokio::time::sleep(Duration::from_millis(10)).await; }
        handle.shutdown();
        loop { if let Some(SessionEvent::StateChanged(SessionState::Disconnected { can_retry, .. })) = rx.recv().await { assert!(!can_retry); break; } }

        // A session token cannot reopen a consumed invitation or fall back to TCP.
        let (tx, mut rx) = mpsc::channel(8);
        let _handle = driver.spawn("retry".into(), ConnectOptions::boundary(id), tx).unwrap();
        assert!(matches!(rx.recv().await, Some(SessionEvent::StateChanged(SessionState::Disconnected { can_retry: false, .. }))));
        host.stop();
    }).await.expect("support driver test timed out");
}
