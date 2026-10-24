//! How the client drives the stage: in this process for a loopback run, or
//! over a TCP link the stage window dials.
use anyhow::{Context, Result, bail};
use bench_stage::{Layout, Scene, StageState, clock_ms, render_rgba};
use boundary_session::{Desktop, Frame, Input, Key};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;

/// One report from the stage machine.
#[derive(Clone, Copy, Debug)]
pub struct HostSample {
    pub at: Instant,
    pub cpu: f32,
    pub fps: f32,
    pub active: bool,
}

/// A stage drawn in this process, behind a Boundary host, for a loopback
/// run that proves the harness without any window or any real input.
pub struct Offscreen {
    pub layout: Layout,
    pub state: StageState,
    start: Instant,
}

impl Offscreen {
    pub fn new(width: u32, height: u32) -> Arc<Mutex<Offscreen>> {
        Arc::new(Mutex::new(Offscreen {
            layout: Layout::fit(width, height),
            state: StageState::default(),
            start: Instant::now(),
        }))
    }
    /// The frame the stage is on: it runs at 60 a second whether or not
    /// anyone captures it, as a real screen does.
    fn frame(&self) -> u32 {
        (self.start.elapsed().as_secs_f64() * bench_stage::FPS as f64) as u32
    }
}

pub struct OffscreenDesktop(pub Arc<Mutex<Offscreen>>);

impl Desktop for OffscreenDesktop {
    fn capture(&mut self) -> Result<Frame> {
        let (layout, state, frame) = {
            let s = self.0.lock().unwrap();
            (s.layout, s.state, s.frame())
        };
        Ok(Frame {
            width: layout.width,
            height: layout.height,
            rgba: render_rgba(layout, &state, frame, clock_ms()),
        })
    }
    fn input(&mut self, input: Input) -> Result<()> {
        let mut s = self.0.lock().unwrap();
        let (w, h) = (s.layout.width as f32, s.layout.height as f32);
        match input {
            Input::Move { x, y } => s.state.pointer = Some((x * (w - 1.0), y * (h - 1.0))),
            Input::Key {
                key: Key::Letter(_),
                down: true,
            } => s.state.keys = s.state.keys.wrapping_add(1),
            _ => {}
        }
        Ok(())
    }
    fn release(&mut self) {}
}

/// The stage window on another process or machine, which dialled in.
pub struct Link {
    writer: tokio::sync::Mutex<OwnedWriteHalf>,
    pongs: tokio::sync::Mutex<mpsc::Receiver<(u64, u32)>>,
    pub samples: Arc<Mutex<Vec<HostSample>>>,
    pub size: (u32, u32),
}

impl Link {
    /// Wait for the stage to dial `port`.
    pub async fn accept(port: u16, wait: Duration) -> Result<Link> {
        let listener = TcpListener::bind(("0.0.0.0", port))
            .await
            .with_context(|| format!("listen for the stage on port {port}"))?;
        eprintln!("waiting for the stage to dial port {port}");
        let (stream, from) = tokio::time::timeout(wait, listener.accept())
            .await
            .context("the stage never dialled in")??;
        stream.set_nodelay(true)?;
        eprintln!("stage connected from {from}");
        let (read, writer) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let first = lines.next_line().await?.unwrap_or_default();
        let mut words = first.split_whitespace();
        let size = match (words.next(), words.next(), words.next()) {
            (Some("hello"), Some(w), Some(h)) => (w.parse()?, h.parse()?),
            _ => bail!("the stage said {first:?} instead of hello"),
        };
        let (pong_tx, pongs) = mpsc::channel(64);
        let samples = Arc::new(Mutex::new(Vec::new()));
        let kept = samples.clone();
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let words: Vec<&str> = line.split_whitespace().collect();
                match words.as_slice() {
                    ["pong", sent, stage, ..] => {
                        if let (Ok(sent), Ok(stage)) = (sent.parse(), stage.parse()) {
                            let _ = pong_tx.send((sent, stage)).await;
                        }
                    }
                    ["cpu", cpu, "fps", fps, rest @ ..] => {
                        let active = matches!(rest, ["active", "1", ..]);
                        if let (Ok(cpu), Ok(fps)) = (cpu.parse(), fps.parse()) {
                            kept.lock().unwrap().push(HostSample {
                                at: Instant::now(),
                                cpu,
                                fps,
                                active,
                            });
                        }
                    }
                    _ => {}
                }
            }
        });
        Ok(Link {
            writer: tokio::sync::Mutex::new(writer),
            pongs: tokio::sync::Mutex::new(pongs),
            samples,
            size,
        })
    }

    async fn send(&self, line: String) -> Result<()> {
        self.writer
            .lock()
            .await
            .write_all(format!("{line}\n").as_bytes())
            .await?;
        Ok(())
    }

    /// The stage clock minus ours, in milliseconds, from the ping with the
    /// shortest round trip, NTP style. Also returns that round trip.
    pub async fn sync(&self) -> Result<(i64, f64)> {
        let mut best: Option<(f64, i64)> = None;
        let mut pongs = self.pongs.lock().await;
        for n in 0..25u64 {
            let sent = Instant::now();
            let ours = clock_ms();
            self.send(format!("ping {n}")).await?;
            let Ok(Some((echo, stage))) = tokio::time::timeout(Duration::from_secs(2), pongs.recv()).await
            else {
                continue;
            };
            if echo != n {
                continue;
            }
            let rtt = sent.elapsed().as_secs_f64() * 1000.0;
            let mid = ours.wrapping_add((rtt / 2.0) as u32);
            let offset = stage.wrapping_sub(mid) as i32 as i64;
            if best.is_none_or(|(r, _)| rtt < r) {
                best = Some((rtt, offset));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (rtt, offset) = best.context("the stage answered no clock pings")?;
        Ok((offset, rtt))
    }

    pub async fn scene(&self, scene: Scene) -> Result<()> {
        self.send(format!("scene {}", scene.name())).await
    }

    pub async fn quit(&self) {
        let _ = self.send("quit".into()).await;
    }
}

pub enum Stage {
    Local(Arc<Mutex<Offscreen>>),
    Linked(Link),
}

impl Stage {
    pub async fn scene(&self, scene: Scene) -> Result<()> {
        match self {
            Stage::Local(o) => {
                let mut s = o.lock().unwrap();
                let frame = s.frame();
                s.state.set_scene(scene, frame);
                Ok(())
            }
            Stage::Linked(link) => link.scene(scene).await,
        }
    }
    /// Stage clock minus ours, and the round trip it was measured over.
    pub async fn sync(&self) -> Result<(i64, f64)> {
        match self {
            Stage::Local(_) => Ok((0, 0.0)),
            Stage::Linked(link) => link.sync().await,
        }
    }
    pub fn samples(&self, from: Instant, to: Instant) -> Vec<HostSample> {
        match self {
            Stage::Local(_) => Vec::new(),
            Stage::Linked(link) => link
                .samples
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.at >= from && s.at <= to)
                .copied()
                .collect(),
        }
    }
    /// Whether key presses will reach the stage. A window that does not have
    /// the keyboard focus would send them to whatever does.
    pub fn takes_keys(&self) -> bool {
        match self {
            Stage::Local(_) => true,
            Stage::Linked(link) => link
                .samples
                .lock()
                .unwrap()
                .last()
                .is_some_and(|s| s.active),
        }
    }
}
