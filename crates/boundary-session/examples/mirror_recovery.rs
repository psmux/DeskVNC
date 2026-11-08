//! How long an agent's mirror stays stale after a Boundary screen moves,
//! headless: a host on this machine with its real video encoder (Media
//! Foundation on Windows) under a synthetic screen that scrolls, and a
//! helper that decodes what it is sent as DeskVNCViewer's mirror does, with
//! OpenH264, one decoder per stream, lost until the next keyframe once a
//! picture does not decode.
//!
//! ```sh
//! mirror_recovery [--refresh] [--drop N] [--moving-ms 4000]
//! ```
//!
//! `--refresh` asks the host for the whole screen whenever the mirror's
//! decoder loses its place, at most once a second, as the mirror does now.
//! `--drop N` treats the Nth picture as undecodable, to time recovery from
//! one bad picture whatever the encoder makes.
use boundary_session::{
    Abilities, Approval, Desktop, Event, Frame, HostOptions, Input, Session, Update,
    video::VideoEncoders,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::time::{Duration, Instant};

const W: u32 = 1920;
const H: u32 = 1200;

struct Moving {
    moving: Arc<AtomicBool>,
    step: Arc<AtomicU32>,
}
fn picture(step: u32) -> Frame {
    Frame {
        width: W,
        height: H,
        rgba: (0..W * H)
            .flat_map(|i| {
                let (x, y) = (i % W, (i / W + step * 6) % H);
                let v = if (y % 18) < 11 && (x * 31 + y * 7) % 13 < 6 {
                    40
                } else {
                    230
                };
                [v, v, (x % 256) as u8, 255]
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
        Some(boundary_platform::video::encoders())
    }
}

/// The mirror: which pixels are stale, and the decoder.
struct Mirror {
    stale: Vec<bool>,
    decoder: Option<openh264::decoder::Decoder>,
    broken: bool,
    pictures: u32,
    drop: Option<u32>,
    failed: u32,
    keyframes: u32,
}
impl Mirror {
    fn clean(&self) -> bool {
        !self.stale.iter().any(|s| *s)
    }
    fn cover(&mut self, x: u32, y: u32, w: u32, h: u32) {
        for row in y..(y + h).min(H) {
            let line = (row * W) as usize;
            self.stale[line + x as usize..line + (x + w).min(W) as usize].fill(false);
        }
    }
    /// True when this update left the decoder lost.
    fn apply(&mut self, update: &Update) -> bool {
        match update {
            Update::Screen { rects: None, .. } => self.cover(0, 0, W, H),
            Update::Screen {
                rects: Some(rects), ..
            } => {
                for r in rects {
                    self.cover(r.x, r.y, r.width, r.height);
                }
            }
            Update::Video(unit) => {
                self.pictures += 1;
                if unit.fresh {
                    self.decoder = None;
                }
                if unit.keyframe {
                    self.keyframes += 1;
                    self.broken = false;
                }
                let decoded = !self.broken
                    && self.drop != Some(self.pictures)
                    && self
                        .decoder
                        .get_or_insert_with(|| openh264::decoder::Decoder::new().unwrap())
                        .decode(&unit.data)
                        .is_ok_and(|p| p.is_some());
                if decoded {
                    self.cover(0, 0, W, H);
                } else {
                    if !self.broken {
                        self.failed += 1;
                    }
                    self.broken = true;
                    self.decoder = None;
                    self.stale.fill(true);
                }
            }
        }
        self.broken
    }
}

fn local() -> HostOptions {
    HostOptions {
        relay: false,
        relay_url: None,
        bind_ip: None,
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| args.iter().position(|a| a == name);
    let value = |name: &str| flag(name).and_then(|i| args.get(i + 1)?.parse::<u64>().ok());
    let refresh = flag("--refresh").is_some();
    let drop = value("--drop").map(|n| n as u32);
    let moving_for = Duration::from_millis(value("--moving-ms").unwrap_or(4000));

    let moving = Arc::new(AtomicBool::new(false));
    let step = Arc::new(AtomicU32::new(0));
    let (m, s) = (moving.clone(), step.clone());
    let mut host =
        boundary_session::host(local(), move || Ok(Box::new(Moving { moving: m, step: s })));
    let ticket = loop {
        if let Some(Event::Invitation(t)) = host.events.recv().await {
            break t;
        }
    };
    let mut helper: Session = boundary_session::viewer_with(
        ticket,
        "Mirror recovery".into(),
        local(),
        None,
        Abilities {
            tools: false,
            video: true,
            clipboard: false,
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
    eprintln!(
        "encoder {}",
        boundary_platform::video::encoders()(W, H)?.name()
    );
    let mut mirror = Mirror {
        stale: vec![true; (W * H) as usize],
        decoder: None,
        broken: false,
        pictures: 0,
        drop,
        failed: 0,
        keyframes: 0,
    };
    let mut asked: Option<Instant> = None;
    let mut asks = 0;
    let mut pump = |helper: &mut Session, mirror: &mut Mirror, asked: &mut Option<Instant>| {
        for update in helper.updates() {
            let lost = mirror.apply(&update);
            if lost && refresh && asked.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                helper.refresh();
                *asked = Some(Instant::now());
                asks += 1;
            }
            if !lost {
                *asked = None;
            }
        }
    };
    // Settle on the first screen.
    let end = Instant::now() + Duration::from_secs(2);
    while let Ok(Ok(())) = tokio::time::timeout_at(end.into(), helper.frames.changed()).await {
        pump(&mut helper, &mut mirror, &mut asked);
    }
    println!("first screen clean: {}", mirror.clean());

    moving.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let mut stale_moving = Duration::ZERO;
    let mut last = Instant::now();
    while started.elapsed() < moving_for {
        if let Ok(Ok(())) =
            tokio::time::timeout(Duration::from_millis(50), helper.frames.changed()).await
        {
            let was_clean = mirror.clean();
            pump(&mut helper, &mut mirror, &mut asked);
            if !was_clean {
                stale_moving += last.elapsed();
            }
            last = Instant::now();
        }
    }
    moving.store(false, Ordering::SeqCst);
    let stopped = Instant::now();
    let give_up = stopped + Duration::from_secs(30);
    let clean_after = loop {
        if mirror.clean() {
            break Some(stopped.elapsed());
        }
        if Instant::now() >= give_up {
            break None;
        }
        if let Ok(Ok(())) = tokio::time::timeout_at(give_up.into(), helper.frames.changed()).await {
            pump(&mut helper, &mut mirror, &mut asked);
        }
    };
    println!(
        "pictures {} ({} keyframes) lost {} times, refreshes asked {asks}, stale while moving {:.1} s of {:.1} s, clean after motion stopped: {}",
        mirror.pictures,
        mirror.keyframes,
        mirror.failed,
        stale_moving.as_secs_f64(),
        moving_for.as_secs_f64(),
        clean_after.map_or("not within 30 s".to_string(), |d| format!(
            "{} ms",
            d.as_millis()
        )),
    );
    helper.stop();
    host.stop();
    Ok(())
}
