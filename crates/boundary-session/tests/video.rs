//! Moving screens as H.264, end to end over real connections on this
//! machine: a helper that decodes video gets it while the screen moves and
//! the whole screen sharp once it stops, and helpers or hosts without video
//! keep getting tiles.

use boundary_session::{
    Abilities, Approval, Desktop, Event, Frame, HostOptions, Input, Session, Update,
    video::VideoEncoders,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::time::{Duration, Instant};
use tokio::time::timeout;

const W: u32 = 320;
const H: u32 = 240;

/// A screen that slides along while `moving` is set, like a page scrolling.
struct Moving {
    moving: Arc<AtomicBool>,
    step: Arc<AtomicU32>,
    encoders: Option<VideoEncoders>,
}
fn picture(step: u32) -> Frame {
    Frame {
        width: W,
        height: H,
        rgba: (0..W * H)
            .flat_map(|i| {
                let (x, y) = ((i % W + step * 8) % W, i / W);
                let v = if (y % 16) < 9 && (x * 7 + y) % 11 < 5 {
                    30
                } else {
                    220
                };
                [v, (x % 200) as u8, v / 2, 255]
            })
            .collect(),
    }
}
impl Desktop for Moving {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        if self.moving.load(Ordering::SeqCst) {
            self.step.fetch_add(1, Ordering::SeqCst);
        }
        Ok(picture(self.step.load(Ordering::SeqCst)))
    }
    fn input(&mut self, _: Input) -> anyhow::Result<()> {
        Ok(())
    }
    fn release(&mut self) {}
    fn video(&self) -> Option<VideoEncoders> {
        self.encoders.clone()
    }
}

fn local() -> HostOptions {
    HostOptions {
        relay: false,
        relay_url: None,
        bind_ip: None,
    }
}

struct Pair {
    host: Session,
    helper: Session,
    moving: Arc<AtomicBool>,
    step: Arc<AtomicU32>,
}
async fn connect(encoders: Option<VideoEncoders>, video: bool) -> Pair {
    let moving = Arc::new(AtomicBool::new(false));
    let step = Arc::new(AtomicU32::new(0));
    let (m, s) = (moving.clone(), step.clone());
    let mut host = boundary_session::host(local(), move || {
        Ok(Box::new(Moving {
            moving: m,
            step: s,
            encoders,
        }))
    });
    let ticket = loop {
        if let Some(Event::Invitation(t)) = host.events.recv().await {
            break t;
        }
    };
    let mut helper = boundary_session::viewer_with(
        ticket,
        "Video test".into(),
        local(),
        None,
        Abilities {
            tools: false,
            video,
        },
    );
    loop {
        if let Some(Event::Approval { answer, .. }) = host.events.recv().await {
            let _ = answer.send(Approval::View);
            break;
        }
    }
    loop {
        if let Some(Event::Connected { .. }) = helper.events.recv().await {
            break;
        }
    }
    Pair {
        host,
        helper,
        moving,
        step,
    }
}

/// Updates for `wait`, in order.
async fn gather(helper: &mut Session, wait: Duration) -> Vec<(Instant, Update)> {
    let end = Instant::now() + wait;
    let mut out = Vec::new();
    while let Ok(Ok(())) = tokio::time::timeout_at(end.into(), helper.frames.changed()).await {
        let now = Instant::now();
        out.extend(helper.updates().into_iter().map(|u| (now, u)));
    }
    out
}

/// Does this update draw the whole screen?
fn whole(update: &Update) -> bool {
    match update {
        Update::Screen { frame, rects } => rects.as_ref().is_none_or(|rects| {
            rects.iter().map(|r| r.width * r.height).sum::<u32>() == frame.width * frame.height
        }),
        Update::Video(_) => false,
    }
}

/// The mean difference of two screens, per channel.
fn difference(a: &Frame, b: &Frame) -> u64 {
    let diff: u64 = a
        .rgba
        .iter()
        .zip(&b.rgba)
        .map(|(x, y)| x.abs_diff(*y) as u64)
        .sum();
    diff / a.rgba.len() as u64
}

/// What the helper's window shows: video decoded, and tiles drawn over it,
/// in the order they came.
struct Window {
    canvas: Frame,
    decoder: Option<openh264::decoder::Decoder>,
}
impl Window {
    fn new() -> Self {
        Self {
            canvas: Frame {
                width: W,
                height: H,
                rgba: vec![0; (W * H * 4) as usize],
            },
            decoder: None,
        }
    }
    fn draw(&mut self, updates: &[(Instant, Update)]) {
        use openh264::formats::YUVSource;
        let stride = W as usize * 4;
        for (_, update) in updates {
            match update {
                Update::Screen { frame, rects } => match rects {
                    None => self.canvas.rgba.copy_from_slice(&frame.rgba),
                    Some(rects) => {
                        for r in rects {
                            for y in r.y..r.y + r.height {
                                let i = y as usize * stride + r.x as usize * 4;
                                let n = r.width as usize * 4;
                                self.canvas.rgba[i..i + n].copy_from_slice(&frame.rgba[i..i + n]);
                            }
                        }
                    }
                },
                Update::Video(unit) => {
                    if unit.fresh || self.decoder.is_none() {
                        self.decoder = Some(openh264::decoder::Decoder::new().unwrap());
                    }
                    let decoder = self.decoder.as_mut().unwrap();
                    let picture = decoder
                        .decode(&unit.data)
                        .unwrap()
                        .expect("no frame held back");
                    // Every picture decodes, in order, to the screen's size.
                    assert_eq!(picture.dimensions(), (W as usize, H as usize));
                    picture.write_rgba8(&mut self.canvas.rgba);
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn moving_screens_come_as_h264_and_settle_back_to_sharp_tiles() {
    timeout(Duration::from_secs(60), async {
        let mut pair = connect(Some(boundary_platform::video::software()), true).await;
        let mut window = Window::new();
        let first = gather(&mut pair.helper, Duration::from_millis(500)).await;
        assert!(
            first.iter().any(|(_, u)| whole(u)),
            "the first screen is tiles"
        );
        window.draw(&first);

        pair.moving.store(true, Ordering::SeqCst);
        let moving = gather(&mut pair.helper, Duration::from_millis(1500)).await;
        let units: Vec<_> = moving
            .iter()
            .filter_map(|(_, u)| match u {
                Update::Video(unit) => Some(unit),
                _ => None,
            })
            .collect();
        assert!(units.len() >= 10, "{} pictures of video", units.len());
        assert!(
            units[0].fresh && units[0].keyframe,
            "video starts with a keyframe"
        );
        assert!(units[1..].iter().all(|u| !u.fresh && !u.keyframe));
        window.draw(&moving);

        // The agent asks for the whole screen while it still moves.
        pair.helper.refresh();
        let asked = gather(&mut pair.helper, Duration::from_millis(1000)).await;
        assert!(
            asked.iter().any(|(_, u)| whole(u)),
            "a refresh sends the whole screen"
        );
        window.draw(&asked);

        // The screen stops.
        pair.moving.store(false, Ordering::SeqCst);
        let stopped = Instant::now();
        let after = gather(&mut pair.helper, Duration::from_millis(1500)).await;
        // Video stops soon. Tiles follow only where video drew visibly
        // wrong, which on a fast link may be nowhere.
        if let Some((at, _)) = after.iter().rfind(|(_, u)| matches!(u, Update::Video(_))) {
            assert!(
                *at - stopped < Duration::from_millis(800),
                "{:?}",
                *at - stopped
            );
        }
        window.draw(&after);
        // What the window shows in the end is the still screen, near it as
        // JPEG is, and far from the one a step earlier.
        let step = pair.step.load(Ordering::SeqCst);
        let (now, before) = (
            difference(&window.canvas, &picture(step)),
            difference(&window.canvas, &picture(step - 1)),
        );
        assert!(now < 9 && before > now * 2, "{now} {before}");

        // Moving again, video follows on from the picture the helper's
        // decoder already holds, with no keyframe, and still draws right.
        pair.moving.store(true, Ordering::SeqCst);
        let again = gather(&mut pair.helper, Duration::from_millis(800)).await;
        let first_again = again
            .iter()
            .find_map(|(_, u)| match u {
                Update::Video(unit) => Some(unit.clone()),
                _ => None,
            })
            .expect("video again");
        assert!(!first_again.keyframe && !first_again.fresh);
        window.draw(&again);
        pair.moving.store(false, Ordering::SeqCst);
        let after = gather(&mut pair.helper, Duration::from_millis(1000)).await;
        window.draw(&after);
        let step = pair.step.load(Ordering::SeqCst);
        let (now, before) = (
            difference(&window.canvas, &picture(step)),
            difference(&window.canvas, &picture(step - 1)),
        );
        assert!(now < 9 && before > now * 2, "{now} {before}");
        pair.helper.stop();
        pair.host.stop();
    })
    .await
    .unwrap();
}

/// What a helper from before video says and gets: no `video` in its first
/// message, and tiles only, however much the screen moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_that_does_not_decode_video_gets_only_tiles() {
    timeout(Duration::from_secs(60), async {
        let mut pair = connect(Some(boundary_platform::video::software()), false).await;
        pair.moving.store(true, Ordering::SeqCst);
        let updates = gather(&mut pair.helper, Duration::from_millis(1500)).await;
        assert!(updates.len() > 5);
        assert!(
            updates
                .iter()
                .all(|(_, u)| matches!(u, Update::Screen { .. }))
        );
        // Asking for the screen again is not sent to a host that never sent
        // video, so the session goes on.
        pair.helper.refresh();
        assert!(
            !gather(&mut pair.helper, Duration::from_millis(500))
                .await
                .is_empty()
        );
        pair.helper.stop();
        pair.host.stop();
    })
    .await
    .unwrap();
}

/// A host that cannot encode video sends a helper that decodes it tiles on
/// the newer stream, and answers its refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_without_an_encoder_sends_tiles_to_a_helper_that_decodes_video() {
    timeout(Duration::from_secs(60), async {
        let mut pair = connect(None, true).await;
        pair.moving.store(true, Ordering::SeqCst);
        let updates = gather(&mut pair.helper, Duration::from_millis(1000)).await;
        assert!(updates.len() > 5);
        assert!(
            updates
                .iter()
                .all(|(_, u)| matches!(u, Update::Screen { .. }))
        );
        pair.moving.store(false, Ordering::SeqCst);
        gather(&mut pair.helper, Duration::from_millis(300)).await;
        pair.helper.refresh();
        let asked = gather(&mut pair.helper, Duration::from_millis(1000)).await;
        assert!(
            asked.iter().any(|(_, u)| whole(u)),
            "a refresh sends the whole screen"
        );
        pair.helper.stop();
        pair.host.stop();
    })
    .await
    .unwrap();
}
