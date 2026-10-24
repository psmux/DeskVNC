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
                SessionEvent::Protocol(ProtocolEvent::Boundary { control, tools }) => { assert!(!control && !tools); permission = true; }
                SessionEvent::FramebufferUpdate { rects, .. } => {
                    assert!(permission);
                    // JPEG, which DeskVNC takes, is lossy, so the grey comes back near 128.
                    assert!(matches!(&rects[0].payload, RectPayload::Rgba(pixels) if pixels.len() == 16 && pixels.iter().all(|p| p.abs_diff(128) <= 4 || *p == 255)));
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
        loop { if let Some(SessionEvent::Protocol(ProtocolEvent::Boundary { control: true, .. })) = rx.recv().await { break; } }
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

/// A pairing offered during an attended session reaches the callback DeskVNC
/// uses to save the computer, and the host saw DeskVNC's lasting identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pairing_reaches_deskvnc_with_the_machine_id_and_its_lasting_identity() {
    timeout(Duration::from_secs(20), async {
        let identity = boundary_session::unattended::SecretKey::generate();
        let expected_peer = identity.public().to_string();
        let mut host = boundary_session::host(
            HostOptions {
                relay: false,
                relay_url: None,
                bind_ip: None,
            },
            || Ok(Box::new(Fake(Arc::new(AtomicUsize::new(0))))),
        );
        let ticket = loop {
            if let Some(Event::Invitation(ticket)) = host.events.recv().await {
                break ticket;
            }
        };
        let driver = BoundaryDriver::default();
        driver.set_identity(identity);
        let (paired_tx, mut paired_rx) = mpsc::channel::<(String, String)>(1);
        driver.on_paired(Arc::new(move |machine, name| {
            let _ = paired_tx.try_send((machine, name));
        }));
        let id = driver.prepare(ticket, "DeskVNC helper".into()).unwrap();
        let (tx, mut rx) = mpsc::channel(32);
        let handle = driver
            .spawn("pairing".into(), ConnectOptions::boundary(id), tx)
            .unwrap();
        let peer = loop {
            match host.events.recv().await {
                Some(Event::Approval { answer, .. }) => {
                    answer.send(Approval::Control).ok().unwrap();
                }
                Some(Event::Connected { peer, .. }) => break peer,
                _ => {}
            }
        };
        assert_eq!(
            peer, expected_peer,
            "the host must see DeskVNC's lasting key, or pairing could never match it again"
        );
        loop {
            if let Some(SessionEvent::StateChanged(SessionState::Connected)) = rx.recv().await {
                break;
            }
        }
        let machine = boundary_session::unattended::SecretKey::generate()
            .public()
            .to_string();
        host.offer_pairing(machine.clone(), "Office PC".into())
            .unwrap();
        let (got, name) = paired_rx.recv().await.unwrap();
        assert_eq!(
            (got.as_str(), name.as_str()),
            (machine.as_str(), "Office PC")
        );
        handle.shutdown();
        host.stop();
    })
    .await
    .expect("pairing test timed out");
}

/// A desktop whose square jumps to wherever the pointer last went.
struct Square(Arc<AtomicUsize>);
impl Desktop for Square {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let (width, height) = (640u32, 400u32);
        let at = self.0.load(Ordering::SeqCst) as u32;
        let mut rgba = vec![200u8; (width * height * 4) as usize];
        for y in 300..340 {
            for x in at..at + 40 {
                let i = ((y * width + x) * 4) as usize;
                rgba[i..i + 4].copy_from_slice(&[20, 20, 20, 255]);
            }
        }
        Ok(Frame {
            width,
            height,
            rgba,
        })
    }
    fn input(&mut self, input: Input) -> anyhow::Result<()> {
        if let Input::Move { x, .. } = input {
            self.0.store((x * 500.0) as usize, Ordering::SeqCst);
        }
        Ok(())
    }
    fn release(&mut self) {}
}

/// After the first screen, DeskVNC is handed only what changed, and drawing
/// those rectangles over the first screen gives the host's screen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deskvnc_is_handed_only_the_rectangles_that_changed() {
    timeout(Duration::from_secs(20), async {
        let at = Arc::new(AtomicUsize::new(10));
        let shared = at.clone();
        let mut host = boundary_session::host(
            HostOptions {
                relay: false,
                relay_url: None,
                bind_ip: None,
            },
            move || Ok(Box::new(Square(shared))),
        );
        let ticket = loop {
            if let Some(Event::Invitation(ticket)) = host.events.recv().await {
                break ticket;
            }
        };
        let driver = BoundaryDriver::default();
        let id = driver.prepare(ticket, "DeskVNC helper".into()).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = driver
            .spawn("tiles".into(), ConnectOptions::boundary(id), tx)
            .unwrap();
        loop {
            if let Some(Event::Approval { answer, .. }) = host.events.recv().await {
                answer.send(Approval::Control).ok().unwrap();
                break;
            }
        }
        let (width, height) = (640usize, 400usize);
        let mut screen = vec![0u8; width * height * 4];
        let mut updates = 0;
        loop {
            match rx.recv().await.unwrap() {
                SessionEvent::FramebufferUpdate { rects, .. } => {
                    updates += 1;
                    for r in &rects {
                        let RectPayload::Rgba(pixels) = &r.payload else {
                            panic!("not RGBA")
                        };
                        let (x, y, w) =
                            (r.rect.x as usize, r.rect.y as usize, r.rect.width as usize);
                        assert_eq!(pixels.len(), w * r.rect.height as usize * 4);
                        for (row, line) in pixels.chunks_exact(w * 4).enumerate() {
                            let i = ((y + row) * width + x) * 4;
                            screen[i..i + w * 4].copy_from_slice(line);
                        }
                    }
                    if updates == 1 {
                        handle
                            .send(ClientCommand::SetViewOnly(false))
                            .await
                            .unwrap();
                        // 400 of 639 across: the square moves to x = 312.
                        handle
                            .send(ClientCommand::Pointer {
                                x: 400,
                                y: 10,
                                button_mask: 0,
                            })
                            .await
                            .unwrap();
                        continue;
                    }
                    let area: usize = rects
                        .iter()
                        .map(|r| r.rect.width as usize * r.rect.height as usize)
                        .sum();
                    assert!(
                        area * 4 < width * height,
                        "a moved square sent {area} pixels"
                    );
                    let dark = |x: usize| screen[((320 * width) + x) * 4] < 80;
                    if dark(330) && !dark(25) {
                        break;
                    }
                }
                SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                    panic!("{reason}")
                }
                _ => {}
            }
        }
        handle.shutdown();
        host.stop();
    })
    .await
    .expect("tiles driver test timed out");
}
