//! A Boundary screen that moves reaches DeskVNC's window as H.264 for its
//! WebCodecs decoder, and the whole screen comes back as pixels once it
//! stops, or when the window or an agent asks for it.

use boundary_driver::BoundaryDriver;
use boundary_session::{
    video::{Encoded, VideoEncoder, VideoEncoders},
    Approval, Desktop, Event, Frame, HostOptions, Input,
};
use remote_core::{
    ClientCommand, ConnectOptions, ProtocolDriver, Rect, RectPayload, SessionEvent, SessionState,
};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{sync::mpsc, time::timeout};

const W: u32 = 256;
const H: u32 = 128;

/// Stands in for a real encoder: the driver passes pictures on, it does
/// not decode them.
struct FakeH264 {
    count: u8,
}
impl VideoEncoder for FakeH264 {
    fn name(&self) -> &str {
        "fake"
    }
    fn encode(&mut self, _: &Frame, keyframe: bool) -> anyhow::Result<Encoded> {
        let keyframe = keyframe || self.count == 0;
        self.count = self.count.wrapping_add(1);
        Ok(Encoded {
            data: vec![0, 0, 0, 1, if keyframe { 0x65 } else { 0x41 }, self.count],
            keyframe,
        })
    }
    fn set_rate(&mut self, _: u32, _: u32) {}
}

struct Moving {
    moving: Arc<AtomicBool>,
    step: Arc<AtomicU32>,
}
impl Desktop for Moving {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let step = if self.moving.load(Ordering::SeqCst) {
            self.step.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            self.step.load(Ordering::SeqCst)
        };
        Ok(Frame {
            width: W,
            height: H,
            rgba: (0..W * H)
                .flat_map(|i| [((i + step * 5) % 251) as u8, 90, 40, 255])
                .collect(),
        })
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        Ok(())
    }
    fn release(&mut self) {}
    fn video(&self) -> Option<VideoEncoders> {
        Some(Arc::new(|_, _| {
            Ok(Box::new(FakeH264 { count: 0 }) as Box<dyn VideoEncoder>)
        }))
    }
}

/// The next picture of video, or the next update that draws the whole
/// screen as pixels, whichever `want` asks for.
async fn next(rx: &mut mpsc::Receiver<SessionEvent>, video: bool) -> RectPayload {
    let whole = Rect {
        x: 0,
        y: 0,
        width: W as u16,
        height: H as u16,
    };
    loop {
        match rx.recv().await.unwrap() {
            SessionEvent::FramebufferUpdate { rects, damage } => {
                let h264 = rects
                    .iter()
                    .find(|r| matches!(r.payload, RectPayload::H264 { .. }));
                if video {
                    if let Some(rect) = h264 {
                        assert_eq!(rect.rect, whole, "video covers the whole screen");
                        return rect.payload.clone();
                    }
                } else if h264.is_none() && damage == whole {
                    return rects[0].payload.clone();
                }
            }
            SessionEvent::StateChanged(SessionState::Disconnected { reason, .. }) => {
                panic!("{reason}")
            }
            _ => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_moving_screen_reaches_the_window_as_h264_and_comes_back_sharp() {
    timeout(Duration::from_secs(30), async {
        let moving = Arc::new(AtomicBool::new(false));
        let step = Arc::new(AtomicU32::new(0));
        let (m, s) = (moving.clone(), step.clone());
        let mut host = boundary_session::host(HostOptions { relay: false, relay_url: None, bind_ip: None }, move || {
            Ok(Box::new(Moving { moving: m, step: s }))
        });
        let ticket = loop {
            if let Some(Event::Invitation(ticket)) = host.events.recv().await {
                break ticket;
            }
        };
        let driver = BoundaryDriver::default();
        let id = driver.prepare(ticket, "DeskVNC helper".into()).unwrap();
        let (tx, mut rx) = mpsc::channel(256);
        let handle = driver.spawn("video".into(), ConnectOptions::boundary(id), tx).unwrap();
        loop {
            if let Some(Event::Approval { answer, .. }) = host.events.recv().await {
                answer.send(Approval::View).ok().unwrap();
                break;
            }
        }
        assert!(matches!(next(&mut rx, false).await, RectPayload::Rgba(_)), "the first screen is pixels");

        moving.store(true, Ordering::SeqCst);
        let RectPayload::H264 { context_id, reset, keyframe, data, .. } = next(&mut rx, true).await else { unreachable!() };
        assert!(reset && keyframe, "the window's decoder starts on a keyframe");
        assert_eq!((context_id, &data[..4]), (0, &[0, 0, 0, 1][..]));
        let RectPayload::H264 { reset, keyframe, .. } = next(&mut rx, true).await else { unreachable!() };
        assert!(!reset && !keyframe, "the next picture follows on");

        // While video plays, what the driver holds is older than the window,
        // so a refresh asks the computer for the screen instead.
        handle.send(ClientCommand::Refresh).await.unwrap();
        assert!(matches!(next(&mut rx, false).await, RectPayload::Rgba(p) if p.len() == (W * H * 4) as usize));

        // Video picks up again while it moves, then the screen stops, and
        // the whole of it comes back as pixels after the last picture.
        next(&mut rx, true).await;
        moving.store(false, Ordering::SeqCst);
        let mut last = None;
        while let Ok(Some(event)) = timeout(Duration::from_millis(800), rx.recv()).await {
            if let SessionEvent::FramebufferUpdate { rects, .. } = event {
                last = Some(rects[0].payload.clone());
            }
        }
        let Some(RectPayload::Rgba(pixels)) = last else { panic!("the screen did not come back as pixels") };
        assert_eq!(pixels.len(), (W * H * 4) as usize);
        let expect = ((step.load(Ordering::SeqCst) * 5) % 251) as u8;
        assert!(pixels[0].abs_diff(expect) < 12, "{} vs {expect}", pixels[0]);
        handle.send(ClientCommand::Disconnect).await.unwrap();
        host.stop();
    })
    .await
    .unwrap();
}
