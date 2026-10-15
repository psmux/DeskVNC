//! A paired computer opened by its machine ID takes DeskVNC's pointer and
//! keys, the same as an invitation session does. Uses the real network for
//! discovery, like DeskVNC itself.
use boundary_driver::BoundaryDriver;
use boundary_session::{
    unattended::{self, Access, Notice},
    Desktop, Frame, HostOptions, Input,
};
use remote_core::{
    ClientCommand, ConnectOptions, ProtocolDriver, ProtocolEvent, SessionEvent, SessionState,
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
            width: 4,
            height: 4,
            rgba: vec![9; 64],
        })
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn release(&mut self) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "uses the public relay and discovery"]
async fn a_paired_computer_takes_pointer_input() {
    timeout(Duration::from_secs(60), async {
        let dir = std::env::temp_dir().join(format!("boundary-input-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let machine_key = unattended::load_or_create_key(&dir.join("machine.key")).unwrap();
        let machine = unattended::machine_id(&machine_key);
        let helper = unattended::SecretKey::generate();
        let access_path = dir.join("access.json");
        let mut access = Access::default();
        access.enabled = true;
        access
            .trust(&helper.public().to_string(), "DeskVNC", true)
            .unwrap();
        access.save(&access_path).unwrap();
        let inputs = Arc::new(AtomicUsize::new(0));
        let count = inputs.clone();
        let mut listener = unattended::listen(
            HostOptions::default(),
            machine_key,
            access_path,
            move || Ok(Box::new(Fake(count.clone()))),
        );
        loop {
            if let Some(Notice::Ready { .. }) = listener.notices.recv().await {
                break;
            }
        }
        let driver = BoundaryDriver::default();
        driver.set_identity(helper);
        let (tx, mut rx) = mpsc::channel(64);
        let handle = driver
            .spawn("paired".into(), ConnectOptions::boundary(machine), tx)
            .unwrap();
        let _held = loop {
            if let Some(Notice::Connected { session, .. }) = listener.notices.recv().await {
                break session;
            }
        };
        let mut control = None;
        loop {
            match rx.recv().await.unwrap() {
                SessionEvent::Protocol(ProtocolEvent::Boundary { control: c, .. }) => {
                    control = Some(c)
                }
                SessionEvent::FramebufferUpdate { .. } => break,
                SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                    panic!("{reason}")
                }
                _ => {}
            }
        }
        assert_eq!(
            control,
            Some(true),
            "a helper paired with control is told so"
        );
        for x in 0..4 {
            handle
                .send(ClientCommand::Pointer {
                    x,
                    y: 1,
                    button_mask: 0,
                })
                .await
                .unwrap();
        }
        let started = std::time::Instant::now();
        while inputs.load(Ordering::SeqCst) == 0 && started.elapsed() < Duration::from_secs(10) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            inputs.load(Ordering::SeqCst) > 0,
            "the pointer never reached the computer"
        );
        handle.shutdown();
        listener.stop();
        let _ = std::fs::remove_dir_all(dir);
    })
    .await
    .expect("timed out");
}
