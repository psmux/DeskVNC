//! Connect with a protocol driver, paint what arrives, and measure the
//! stage's scenes in it.
use crate::fb::Framebuffer;
use crate::stage::Stage;
use crate::{arg, flag};
use anyhow::{Context, Result, bail};
use bench_stage::{Code, Mapping, PATCH, Scene, clock_ms, detail, pointer_target};
use remote_core::{
    ClientCommand, ConnectOptions, ProtocolDriver, ProtocolKind, QualityPreset, RdpResolution,
    SessionEvent, SessionHandle, SessionState, SessionStats,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

pub struct Config {
    /// `None` for a local run, where another client owns the display.
    kind: Option<ProtocolKind>,
    /// The protocol, as the report names it.
    protocol: String,
    /// Which client did the talking.
    client: String,
    target: String,
    user: Option<String>,
    password: Option<String>,
    label: String,
    build: String,
    note: String,
    out: std::path::PathBuf,
    count: usize,
    secs: u64,
    scenes: Vec<String>,
    quality: QualityPreset,
    watch: Vec<String>,
    rdp_size: (u16, u16),
    /// Close the stage window when the run ends.
    quit_stage: bool,
}

impl Config {
    pub fn from_args(args: &[String], proto: &str, target: String) -> Result<Config> {
        let kind = match proto {
            "local" => None,
            other => Some(ProtocolKind::parse(other).context("unknown protocol")?),
        };
        let protocol = match kind {
            Some(k) => k.to_string(),
            None => arg(args, "--as").context("a local run needs --as rdp|vnc|boundary")?,
        };
        let client = match kind {
            Some(_) => "DeskVNC's own protocol code".into(),
            None => arg(args, "--client").context("a local run needs --client with its name")?,
        };
        let quality = match arg(args, "--quality").as_deref() {
            None | Some("auto") => QualityPreset::Auto,
            Some("high") => QualityPreset::High,
            Some("medium") => QualityPreset::Medium,
            Some("low") => QualityPreset::Low,
            Some(other) => bail!("unknown quality {other}"),
        };
        let rdp_size = arg(args, "--rdp-size")
            .and_then(|s| {
                let (w, h) = s.split_once('x')?;
                Some((w.parse().ok()?, h.parse().ok()?))
            })
            .unwrap_or((1920, 1080));
        Ok(Config {
            kind,
            protocol,
            client,
            target,
            user: arg(args, "--user"),
            password: arg(args, "--password"),
            label: arg(args, "--label").unwrap_or_else(|| format!("{proto}-{}", clock_ms())),
            build: arg(args, "--build")
                .or_else(|| std::env::var("BENCH_BUILD").ok())
                .unwrap_or_else(|| "unknown".into()),
            note: arg(args, "--note").unwrap_or_default(),
            out: arg(args, "--out")
                .unwrap_or_else(|| "docs/benchmarks/raw".into())
                .into(),
            count: arg(args, "--count")
                .and_then(|s| s.parse().ok())
                .unwrap_or(40),
            secs: arg(args, "--secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            scenes: arg(args, "--scenes")
                .unwrap_or_else(|| "pointer,typing,scroll,motion,still".into())
                .split(',')
                .map(str::to_owned)
                .collect(),
            quality,
            watch: arg(args, "--watch-procs")
                .map(|s| s.split(',').map(str::to_owned).collect())
                .unwrap_or_default(),
            rdp_size,
            quit_stage: flag(args, "--quit-stage"),
        })
    }
}

#[derive(Clone)]
struct Obs {
    at: Instant,
    /// Our wall clock when the update was painted, low 32 bits.
    ms: u32,
    code: Code,
}

#[derive(Clone, Copy)]
enum Probe {
    Marker(f32, f32),
    Typed(u16),
}

struct Shared {
    fb: Framebuffer,
    map: Option<Mapping>,
    log: Vec<Obs>,
    updates: Vec<Instant>,
    probe: Option<Probe>,
    hit: Option<Instant>,
    patches: Option<Vec<(Obs, Vec<u8>)>>,
    stats: Option<SessionStats>,
    encodings: BTreeMap<i32, u64>,
    connected: bool,
    errors: Vec<String>,
}

impl Shared {
    fn last_code(&self) -> Option<Code> {
        self.log.last().map(|o| o.code)
    }
}

fn split_target(target: &str, port: u16) -> (String, u16) {
    match target.rsplit_once(':') {
        Some((host, p)) if p.parse::<u16>().is_ok() => (host.to_owned(), p.parse().unwrap()),
        _ => (target.to_owned(), port),
    }
}

/// Paint every update and read the stage out of it.
async fn pump(
    mut events: mpsc::Receiver<SessionEvent>,
    handle: SessionHandle,
    shared: Arc<Mutex<Shared>>,
    notify: watch::Sender<u64>,
    user: Option<String>,
    password: Option<String>,
) {
    let mut n = 0u64;
    while let Some(event) = events.recv().await {
        match event {
            SessionEvent::StateChanged(state) => {
                eprintln!("state {state:?}");
                if matches!(state, SessionState::Connected) {
                    shared.lock().unwrap().connected = true;
                    notify.send_replace(n);
                }
            }
            SessionEvent::CertificatePrompt {
                fingerprint,
                scheme,
                ..
            } => {
                let _ = handle
                    .send(ClientCommand::TrustCertificate {
                        fingerprint,
                        permanent: false,
                        scheme,
                    })
                    .await;
            }
            SessionEvent::CredentialsRequired(_) => {
                let _ = handle
                    .send(ClientCommand::ProvideCredentials {
                        username: user.clone(),
                        password: password.clone().unwrap_or_default(),
                        save: false,
                    })
                    .await;
            }
            SessionEvent::DesktopResize { width, height } => {
                let mut s = shared.lock().unwrap();
                s.fb.resize(width as u32, height as u32);
                s.map = None;
            }
            SessionEvent::FramebufferUpdate { rects, .. } => {
                let mut s = shared.lock().unwrap();
                for rect in &rects {
                    if let Err(e) = s.fb.apply(rect)
                        && s.errors.len() < 20
                    {
                        s.errors.push(format!("{e:#}"));
                    }
                }
                let at = Instant::now();
                s.updates.push(at);
                // Look for the stage again whenever its code does not read:
                // the first updates can hold only part of the screen, and a
                // stage window can move.
                let mut code = s.map.and_then(|m| s.fb.view().code(&m));
                if code.is_none() {
                    let found = s.fb.view().locate();
                    if found != s.map
                        && let Some(map) = found
                    {
                        eprintln!(
                            "stage found at {map:?} in a {}x{} screen",
                            s.fb.width, s.fb.height
                        );
                    }
                    s.map = found;
                    code = found.and_then(|m| s.fb.view().code(&m));
                }
                if let Some(map) = s.map {
                    let view = s.fb.view();
                    let hit = match s.probe {
                        Some(Probe::Marker(x, y)) => view.marked(&map, x, y),
                        Some(Probe::Typed(k)) => {
                            code.is_some_and(|c| c.keys > k) && view.typed(&map, k)
                        }
                        None => false,
                    };
                    let patch = (s.patches.is_some()
                        && code.is_some_and(|c| c.scene == Scene::Still))
                    .then(|| view.patch(&map));
                    if hit && s.hit.is_none() {
                        s.hit = Some(at);
                    }
                    if let Some(code) = code {
                        let obs = Obs {
                            at,
                            ms: clock_ms(),
                            code,
                        };
                        if let (Some(patch), Some(patches)) = (patch, s.patches.as_mut()) {
                            patches.push((obs.clone(), patch));
                        }
                        s.log.push(obs);
                    }
                }
                drop(s);
                n += 1;
                notify.send_replace(n);
            }
            SessionEvent::Stats(stats) => {
                let mut s = shared.lock().unwrap();
                *s.encodings.entry(stats.current_encoding).or_default() += 1;
                s.stats = Some(stats);
            }
            SessionEvent::Error(e) => {
                eprintln!("session error: {e}");
                shared.lock().unwrap().errors.push(e);
            }
            _ => {}
        }
    }
    eprintln!("session ended");
}

/// Bytes this process has received, as the operating system counts them.
/// On Linux it is every interface in the network namespace, which in the
/// bench container is the protocol under test and nothing else.
fn os_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string("/proc/net/dev").ok()?;
        Some(
            text.lines()
                .skip(2)
                .filter_map(|l| l.split_once(':'))
                .filter_map(|(_, rest)| rest.split_whitespace().next()?.parse::<u64>().ok())
                .sum(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/nettop")
            .args(["-P", "-L", "1", "-x", "-J", "bytes_in"])
            .args(["-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .skip(1)
            .filter_map(|l| l.split(',').nth(1)?.trim().parse::<u64>().ok())
            .last()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

#[derive(Default, Clone, Copy)]
struct CpuSample {
    own: f32,
    watched: f32,
}

/// Sample this process's CPU and the watched server processes' once a second.
fn cpu_sampler(watch: Vec<String>) -> Arc<Mutex<Vec<(Instant, CpuSample)>>> {
    let samples = Arc::new(Mutex::new(Vec::new()));
    let kept = samples.clone();
    std::thread::spawn(move || {
        use sysinfo::{ProcessesToUpdate, System};
        let mut sys = System::new();
        let me = sysinfo::get_current_pid().ok();
        loop {
            sys.refresh_processes(ProcessesToUpdate::All, true);
            let mut sample = CpuSample::default();
            for (pid, p) in sys.processes() {
                if Some(*pid) == me {
                    sample.own = p.cpu_usage();
                } else {
                    let name = p.name().to_string_lossy();
                    if watch.iter().any(|w| name.contains(w.as_str())) {
                        sample.watched += p.cpu_usage();
                    }
                }
            }
            kept.lock().unwrap().push((Instant::now(), sample));
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    samples
}

#[derive(Serialize, Default, Clone)]
struct Spread {
    n: usize,
    p50: f64,
    p90: f64,
    p99: f64,
    max: f64,
    mean: f64,
}

fn spread(values: &[f64]) -> Spread {
    if values.is_empty() {
        return Spread::default();
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    let pick = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
    Spread {
        n: v.len(),
        p50: pick(0.5),
        p90: pick(0.9),
        p99: pick(0.99),
        max: *v.last().unwrap(),
        mean: v.iter().sum::<f64>() / v.len() as f64,
    }
}

#[derive(Serialize, Default)]
struct Window {
    secs: f64,
    /// Kilobits per second received, as the protocol driver counted it.
    driver_kbps: Option<f64>,
    /// Kilobits per second received, as the operating system counted it.
    os_kbps: Option<f64>,
    /// Total CPU busy on the stage machine, percent of all cores.
    host_cpu: Option<f64>,
    /// CPU of the watched server processes, percent of one core.
    server_cpu: Option<f64>,
    /// CPU of this measuring client, percent of one core.
    client_cpu: Option<f64>,
    /// Updates the driver delivered per second.
    updates_per_sec: f64,
}

#[derive(Serialize, Default)]
struct InputResult {
    lag_ms: Spread,
    missed: usize,
    samples: Vec<f64>,
    skipped: Option<String>,
    window: Window,
}

#[derive(Serialize, Default)]
struct StreamResult {
    /// Distinct stage frames seen per second.
    fps: f64,
    /// The rate the stage drew at over the same time, from the span of
    /// frame numbers seen, since the counter moves only when it draws.
    stage_fps: f64,
    /// The rate the stage itself reported over its link, as a cross check.
    stage_reported_fps: Option<f64>,
    distinct: usize,
    span: u64,
    dropped: u64,
    /// Stage draw to client paint, from the frame code's timestamp.
    latency_ms: Spread,
    latency_samples: Vec<f64>,
    window: Window,
}

#[derive(Serialize, Default)]
struct StillResult {
    /// From the first still frame being drawn to it arriving.
    first_ms: Option<f64>,
    /// From the first still frame being drawn to the last update that
    /// changed the detail patch, which is when the picture is final.
    sharp_ms: Option<f64>,
    /// Fine detail in the patch when it first arrived, and at the end. The
    /// stage draws about 200 at one to one scale.
    detail_first: Option<f64>,
    detail_final: Option<f64>,
    updates_after: usize,
}

#[derive(Serialize, Default)]
struct Report {
    label: String,
    build: String,
    note: String,
    protocol: String,
    client: String,
    /// What the run actually used: the RDP graphics codec, the VNC
    /// encoding, the kinds of rectangle that arrived.
    negotiated: Vec<String>,
    /// For a local run, the mean time one reading of the display took. Lag
    /// includes on average half of it plus one whole one.
    grab_ms: Option<f64>,
    target_kind: String,
    quality: String,
    started_unix_ms: u64,
    host: String,
    client_os: String,
    /// The measuring machine's load when the run started, and its cores. A
    /// run on a busy machine measures the machine, so `loaded` marks one
    /// whose load was above half a task per core.
    load_1m: f64,
    cpus: usize,
    loaded: bool,
    connect_secs: f64,
    first_stage_secs: f64,
    screen: (u32, u32),
    stage_size: (u32, u32),
    stage_in_screen: Option<(f32, f32, f32, f32)>,
    clock_offset_ms: i64,
    clock_rtt_ms: f64,
    rect_kinds: BTreeMap<String, u64>,
    driver_encodings: BTreeMap<i32, u64>,
    errors: Vec<String>,
    pointer: Option<InputResult>,
    typing: Option<InputResult>,
    scroll: Option<StreamResult>,
    motion: Option<StreamResult>,
    still: Option<StillResult>,
}

struct Bench {
    shared: Arc<Mutex<Shared>>,
    notify: watch::Receiver<u64>,
    handle: SessionHandle,
    stage: Stage,
    offset: i64,
    cpu: Arc<Mutex<Vec<(Instant, CpuSample)>>>,
}

impl Bench {
    async fn changed(&mut self, until: Instant) -> bool {
        matches!(
            tokio::time::timeout_at(until.into(), self.notify.changed()).await,
            Ok(Ok(()))
        )
    }

    /// Wait until the code says the stage shows `scene`.
    async fn showing(&mut self, scene: Scene, wait: Duration) -> Result<()> {
        let until = Instant::now() + wait;
        loop {
            if self
                .shared
                .lock()
                .unwrap()
                .last_code()
                .is_some_and(|c| c.scene == scene)
            {
                return Ok(());
            }
            if !self.changed(until).await {
                let shot = std::env::temp_dir().join(format!("bench-never-{}.png", scene.name()));
                {
                    let s = self.shared.lock().unwrap();
                    if let Some(image) =
                        image::RgbaImage::from_raw(s.fb.width, s.fb.height, s.fb.rgba.clone())
                    {
                        let _ = image.save(&shot);
                    }
                }
                bail!(
                    "the stage never showed {} (what the client had is in {})",
                    scene.name(),
                    shot.display()
                );
            }
        }
    }

    /// Send input and time it until the probe sees its effect.
    async fn input_lag(
        &mut self,
        probe: Probe,
        commands: Vec<ClientCommand>,
    ) -> Result<Option<f64>> {
        {
            let mut s = self.shared.lock().unwrap();
            s.probe = Some(probe);
            s.hit = None;
        }
        let sent = Instant::now();
        for c in commands {
            self.handle.send(c).await.ok().context("session gone")?;
        }
        let until = sent + Duration::from_secs(3);
        loop {
            if let Some(hit) = self.shared.lock().unwrap().hit {
                return Ok(Some(hit.duration_since(sent).as_secs_f64() * 1000.0));
            }
            if !self.changed(until).await {
                return Ok(None);
            }
        }
    }

    fn window(&self, from: Instant, to: Instant, bytes: (Option<u64>, Option<u64>)) -> Window {
        let secs = to.duration_since(from).as_secs_f64();
        let s = self.shared.lock().unwrap();
        let kbps = |a: Option<u64>, b: Option<u64>| match (a, b) {
            (Some(a), Some(b)) if b >= a => Some((b - a) as f64 * 8.0 / 1000.0 / secs),
            _ => None,
        };
        let host: Vec<f64> = self
            .stage
            .samples(from, to)
            .iter()
            .map(|s| s.cpu as f64)
            .collect();
        let cpu: Vec<CpuSample> = self
            .cpu
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, _)| *at > from && *at <= to)
            .map(|(_, c)| *c)
            .collect();
        let mean = |v: Vec<f64>| (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64);
        Window {
            secs,
            driver_kbps: kbps(bytes.0, s.stats.map(|st| st.bytes_received)),
            os_kbps: kbps(bytes.1, os_bytes()),
            host_cpu: mean(host),
            server_cpu: mean(cpu.iter().map(|c| c.watched as f64).collect()),
            client_cpu: mean(cpu.iter().map(|c| c.own as f64).collect()),
            updates_per_sec: s
                .updates
                .iter()
                .filter(|t| **t >= from && **t <= to)
                .count() as f64
                / secs,
        }
    }

    fn bytes(&self) -> (Option<u64>, Option<u64>) {
        (
            self.shared.lock().unwrap().stats.map(|s| s.bytes_received),
            os_bytes(),
        )
    }

    /// Our wall clock at `ms` turned into the stage's, minus a frame's stamp.
    fn age(&self, ms: u32, stamp: u32) -> f64 {
        ms.wrapping_add(self.offset as i32 as u32)
            .wrapping_sub(stamp) as i32 as f64
    }

    async fn pointer(&mut self, count: usize) -> Result<InputResult> {
        self.stage.scene(Scene::Idle).await?;
        self.showing(Scene::Idle, Duration::from_secs(5)).await?;
        let map = self.shared.lock().unwrap().map.context("stage lost")?;
        let from = Instant::now();
        let bytes = self.bytes();
        let mut samples = Vec::new();
        let mut missed = 0;
        // One move to start from a known place, not measured.
        for n in 0..=count {
            let (ux, uy) = pointer_target(n, map.height_units());
            let (x, y) = map.pixel(ux, uy);
            let lag = self
                .input_lag(
                    Probe::Marker(ux, uy),
                    vec![ClientCommand::Pointer {
                        x: x as u16,
                        y: y as u16,
                        button_mask: 0,
                    }],
                )
                .await?;
            if n > 0 {
                match lag {
                    Some(ms) => samples.push(ms),
                    None => missed += 1,
                }
            }
            // An uneven pause, so moves do not lock to the capture rhythm.
            tokio::time::sleep(Duration::from_millis(250 + (n as u64 * 53) % 120)).await;
        }
        let window = self.window(from, Instant::now(), bytes);
        Ok(InputResult {
            lag_ms: spread(&samples),
            missed,
            samples,
            skipped: None,
            window,
        })
    }

    async fn typing(&mut self, count: usize) -> Result<InputResult> {
        self.stage.scene(Scene::Typing).await?;
        self.showing(Scene::Typing, Duration::from_secs(5)).await?;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        if !self.stage.takes_keys() {
            return Ok(InputResult {
                skipped: Some(
                    "the stage window did not have the keyboard focus, so no keys were sent".into(),
                ),
                ..InputResult::default()
            });
        }
        let start = self
            .shared
            .lock()
            .unwrap()
            .last_code()
            .map_or(0, |c| c.keys);
        let from = Instant::now();
        let bytes = self.bytes();
        let mut samples = Vec::new();
        let mut missed = 0;
        for n in 0..count {
            let k = start.wrapping_add(n as u16);
            let key = |down| ClientCommand::Key {
                keysym: 0x61,
                // The XT scancode for A, as the viewer sends with every key.
                keycode: Some(0x1e),
                down,
            };
            match self
                .input_lag(Probe::Typed(k), vec![key(true), key(false)])
                .await?
            {
                Some(ms) => samples.push(ms),
                None => missed += 1,
            }
            tokio::time::sleep(Duration::from_millis(150 + (n as u64 * 37) % 90)).await;
        }
        let window = self.window(from, Instant::now(), bytes);
        Ok(InputResult {
            lag_ms: spread(&samples),
            missed,
            samples,
            skipped: None,
            window,
        })
    }

    async fn stream(&mut self, scene: Scene, secs: u64) -> Result<StreamResult> {
        self.stage.scene(scene).await?;
        self.showing(scene, Duration::from_secs(5)).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let from = Instant::now();
        let bytes = self.bytes();
        tokio::time::sleep(Duration::from_secs(secs)).await;
        let to = Instant::now();
        let window = self.window(from, to, bytes);
        let log: Vec<Obs> = self
            .shared
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|o| o.at >= from && o.at <= to && o.code.scene == scene)
            .cloned()
            .collect();
        let mut seen = BTreeSet::new();
        let mut latency = Vec::new();
        let mut last: Option<i64> = None;
        for o in &log {
            // Unwrap the 16 bit counter against the previous sighting.
            let id = match last {
                None => o.code.frame as i64,
                Some(prev) => prev + (o.code.frame.wrapping_sub(prev as u16) as i16) as i64,
            };
            last = Some(id);
            if seen.insert(id) {
                latency.push(self.age(o.ms, o.code.clock_ms));
            }
        }
        let span = match (seen.first(), seen.last()) {
            (Some(a), Some(b)) => (b - a + 1) as u64,
            _ => 0,
        };
        let secs = window.secs;
        let stage_fps: Vec<f64> = self
            .stage
            .samples(from, to)
            .iter()
            .map(|s| s.fps as f64)
            .collect();
        Ok(StreamResult {
            fps: seen.len() as f64 / secs,
            stage_fps: span as f64 / secs,
            stage_reported_fps: (!stage_fps.is_empty())
                .then(|| stage_fps.iter().sum::<f64>() / stage_fps.len() as f64),
            distinct: seen.len(),
            span,
            dropped: span.saturating_sub(seen.len() as u64),
            latency_ms: spread(&latency),
            latency_samples: latency,
            window,
        })
    }

    async fn still(&mut self) -> Result<StillResult> {
        self.stage.scene(Scene::Motion).await?;
        self.showing(Scene::Motion, Duration::from_secs(5)).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;
        self.shared.lock().unwrap().patches = Some(Vec::new());
        self.stage.scene(Scene::Still).await?;
        tokio::time::sleep(Duration::from_secs(6)).await;
        let (patches, map) = {
            let mut s = self.shared.lock().unwrap();
            (s.patches.take().unwrap_or_default(), s.map)
        };
        let map = map.context("stage lost")?;
        let width = {
            let (x0, _) = map.pixel(PATCH.0, PATCH.1);
            let (x1, _) = map.pixel(PATCH.0 + PATCH.2, PATCH.1);
            (x1 - x0) as usize
        };
        let Some((first, first_patch)) = patches.first() else {
            return Ok(StillResult::default());
        };
        let drawn = patches
            .iter()
            .map(|(o, _)| o.code.clock_ms)
            .min_by_key(|c| c.wrapping_sub(first.code.clock_ms) as i32)
            .unwrap();
        let mut last_change = first;
        for pair in patches.windows(2) {
            let (a, b) = (&pair[0].1, &pair[1].1);
            if a.len() == b.len() && !a.is_empty() {
                let diff: u64 = a
                    .iter()
                    .zip(b)
                    .map(|(x, y)| (*x as i32 - *y as i32).unsigned_abs() as u64)
                    .sum();
                if diff as f64 / a.len() as f64 > 0.5 {
                    last_change = &pair[1].0;
                }
            }
        }
        Ok(StillResult {
            first_ms: Some(self.age(first.ms, drawn)),
            sharp_ms: Some(self.age(last_change.ms, drawn)),
            detail_first: Some(detail(first_patch, width) as f64),
            detail_final: patches.last().map(|(_, p)| detail(p, width) as f64),
            updates_after: patches.len(),
        })
    }
}

fn connect(
    config: &Config,
    events: mpsc::Sender<SessionEvent>,
) -> Result<(SessionHandle, Option<boundary_driver::BoundaryDriver>)> {
    let id = format!("bench-{}", clock_ms());
    let Some(kind) = config.kind else {
        return Ok((crate::local::spawn(events), None));
    };
    let mut options = match kind {
        ProtocolKind::Vnc => {
            let (host, port) = split_target(&config.target, 5900);
            let mut o = ConnectOptions::vnc(host, port);
            o.vnc_mut().allow_insecure = true;
            o
        }
        ProtocolKind::Rdp => {
            let (host, port) = split_target(&config.target, 3389);
            let mut o = ConnectOptions::rdp(host, port);
            let rdp = o.rdp_mut();
            rdp.nla = remote_core::NlaPolicy::AllowFallback;
            rdp.audio = remote_core::AudioMode::Off;
            rdp.redirect_clipboard = false;
            // The graphics pipeline, which the viewer does not ask for yet.
            // Every codec set this client can decode is on by default.
            rdp.graphics_pipeline = true;
            rdp.resolution = RdpResolution::Fixed {
                width: config.rdp_size.0,
                height: config.rdp_size.1,
            };
            o
        }
        ProtocolKind::Boundary => ConnectOptions::boundary(String::new()),
        other => bail!("{other} is not a desktop protocol"),
    };
    options.credentials.username = config.user.clone();
    options.credentials.password = config.password.clone();
    options.quality = config.quality;
    options.connect_timeout = Duration::from_secs(20);
    Ok(match kind {
        ProtocolKind::Vnc => (vnc_core::Session::spawn(id, options, events), None),
        ProtocolKind::Rdp => (rdp_core::RdpSession::spawn(id, options, events), None),
        _ => {
            // A fresh helper identity: never the viewer's own key, which
            // would knock a running DeskVNC off the relay.
            let driver = boundary_driver::BoundaryDriver::default();
            let token = driver.prepare(config.target.clone(), "Bench".into())?;
            options.host = token.clone();
            let handle = driver
                .spawn(token, options, events)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            (handle, Some(driver))
        }
    })
}

pub async fn run(
    config: Config,
    stage: impl std::future::Future<Output = Result<Stage>>,
) -> Result<()> {
    let started = Instant::now();
    let (events_tx, events) = mpsc::channel(256);
    let (handle, _driver) = connect(&config, events_tx)?;
    let shared = Arc::new(Mutex::new(Shared {
        fb: Framebuffer::new(),
        map: None,
        log: Vec::new(),
        updates: Vec::new(),
        probe: None,
        hit: None,
        patches: None,
        stats: None,
        encodings: BTreeMap::new(),
        connected: false,
        errors: Vec::new(),
    }));
    let (notify_tx, notify) = watch::channel(0);
    tokio::spawn(pump(
        events,
        handle.clone(),
        shared.clone(),
        notify_tx,
        config.user.clone(),
        config.password.clone(),
    ));
    let cpu = cpu_sampler(config.watch.clone());
    let stage = stage.await?;
    let mut bench = Bench {
        shared: shared.clone(),
        notify,
        handle: handle.clone(),
        stage,
        offset: 0,
        cpu,
    };
    // Connected, then the stage found and its code read.
    let until = Instant::now() + Duration::from_secs(60);
    while !shared.lock().unwrap().connected {
        if !bench.changed(until).await {
            bail!("never connected: {:?}", shared.lock().unwrap().errors);
        }
    }
    let connect_secs = started.elapsed().as_secs_f64();
    eprintln!("connected in {connect_secs:.2}s");
    while shared.lock().unwrap().last_code().is_none() {
        if !bench.changed(until).await {
            let s = shared.lock().unwrap();
            // Keep what the client saw, to tell a stage that never drew from
            // one the reader could not make out.
            let shot = config.out.join(format!("{}-screen.png", config.label));
            let _ = std::fs::create_dir_all(&config.out);
            if let Some(image) =
                image::RgbaImage::from_raw(s.fb.width, s.fb.height, s.fb.rgba.clone())
            {
                let _ = image.save(&shot);
            }
            bail!(
                "never read the stage (screen {}x{}, stage at {:?}, {} updates)",
                s.fb.width,
                s.fb.height,
                s.map,
                s.updates.len()
            );
        }
    }
    let first_stage_secs = started.elapsed().as_secs_f64();
    let (offset, rtt) = bench.stage.sync().await?;
    bench.offset = offset;
    eprintln!("stage clock offset {offset} ms over a {rtt:.2} ms round trip");

    let load_1m = sysinfo::System::load_average().one;
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    if load_1m > 0.5 * cpus as f64 {
        eprintln!(
            "WARNING: load {load_1m:.1} on {cpus} cores is above half a task per core; this run is marked loaded and its timings measure a busy machine"
        );
    }
    let mut report = Report {
        label: config.label.clone(),
        build: config.build.clone(),
        note: config.note.clone(),
        protocol: config.protocol.clone(),
        client: config.client.clone(),
        target_kind: match &bench.stage {
            Stage::Local(_) => "offscreen stage in this process".into(),
            Stage::Linked(_) => "stage window on the host".into(),
        },
        quality: format!("{:?}", config.quality),
        started_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        host: sysinfo::System::host_name().unwrap_or_default(),
        load_1m,
        cpus,
        loaded: load_1m > 0.5 * cpus as f64,
        client_os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        connect_secs,
        first_stage_secs,
        clock_offset_ms: offset,
        clock_rtt_ms: rtt,
        stage_size: bench.stage.size(),
        ..Report::default()
    };
    for scene in config.scenes.clone() {
        eprintln!("scene {scene}");
        match scene.as_str() {
            "pointer" => report.pointer = Some(bench.pointer(config.count).await?),
            "typing" => report.typing = Some(bench.typing(config.count).await?),
            "scroll" => report.scroll = Some(bench.stream(Scene::Scroll, config.secs).await?),
            "motion" => report.motion = Some(bench.stream(Scene::Motion, config.secs).await?),
            "still" => report.still = Some(bench.still().await?),
            other => bail!("unknown scene {other}"),
        }
    }
    bench.stage.scene(Scene::Idle).await?;
    {
        let s = shared.lock().unwrap();
        report.screen = (s.fb.width, s.fb.height);
        report.stage_in_screen = s.map.map(|m| (m.x0, m.y0, m.width, m.height));
        report.rect_kinds =
            s.fb.kinds
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect();
        report.driver_encodings = s.encodings.clone();
        report.negotiated =
            crate::negotiated::describe(&config.protocol, &s.encodings, &report.rect_kinds);
        if config.kind.is_none() {
            report.grab_ms = s.stats.map(|st| st.decode_ms as f64);
        }
        report.errors = s.errors.clone();
    }
    let _ = handle.send(ClientCommand::Disconnect).await;
    handle.shutdown();
    if let Stage::Linked(link) = &bench.stage
        && config.quit_stage
    {
        link.quit().await;
    }
    write(&config, &report)?;
    summary(&report);
    Ok(())
}

fn write(config: &Config, report: &Report) -> Result<()> {
    std::fs::create_dir_all(&config.out)?;
    let base = config.out.join(&config.label);
    std::fs::write(
        base.with_extension("json"),
        serde_json::to_string_pretty(report)?,
    )?;
    let mut csv = String::from("label,build,protocol,scene,metric,value\n");
    let mut row = |scene: &str, metric: &str, value: f64| {
        csv.push_str(&format!(
            "{},{},{},{scene},{metric},{value:.3}\n",
            report.label, report.build, report.protocol
        ));
    };
    for (name, r) in [("pointer", &report.pointer), ("typing", &report.typing)] {
        if let Some(r) = r {
            for v in &r.samples {
                row(name, "lag_ms", *v);
            }
        }
    }
    for (name, r) in [("scroll", &report.scroll), ("motion", &report.motion)] {
        if let Some(r) = r {
            for v in &r.latency_samples {
                row(name, "frame_latency_ms", *v);
            }
        }
    }
    if let Some(s) = &report.still {
        if let Some(v) = s.first_ms {
            row("still", "first_ms", v);
        }
        if let Some(v) = s.sharp_ms {
            row("still", "sharp_ms", v);
        }
    }
    std::fs::write(base.with_extension("csv"), csv)?;
    eprintln!("wrote {}.json and .csv", base.display());
    Ok(())
}

fn summary(r: &Report) {
    let kb = |w: &Window| {
        w.os_kbps
            .or(w.driver_kbps)
            .map_or("n/a".into(), |k| format!("{:.0} kbit/s", k))
    };
    println!(
        "== {} ({}, build {}) screen {:?}, load {:.1} on {} cores{}",
        r.label,
        r.protocol,
        r.build,
        r.screen,
        r.load_1m,
        r.cpus,
        if r.loaded { ", LOADED" } else { "" }
    );
    for (name, i) in [("pointer", &r.pointer), ("typing", &r.typing)] {
        if let Some(i) = i {
            match &i.skipped {
                Some(why) => println!("{name:8} skipped: {why}"),
                None => println!(
                    "{name:8} lag p50 {:.1} p90 {:.1} p99 {:.1} ms, {} missed, {}",
                    i.lag_ms.p50,
                    i.lag_ms.p90,
                    i.lag_ms.p99,
                    i.missed,
                    kb(&i.window)
                ),
            }
        }
    }
    for (name, s) in [("scroll", &r.scroll), ("motion", &r.motion)] {
        if let Some(s) = s {
            println!(
                "{name:8} {:.1} of {:.1} fps, {} dropped of {}, latency p50 {:.1} p90 {:.1} p99 {:.1} ms, {}, host cpu {:?} server cpu {:?}",
                s.fps,
                s.stage_fps,
                s.dropped,
                s.span,
                s.latency_ms.p50,
                s.latency_ms.p90,
                s.latency_ms.p99,
                kb(&s.window),
                s.window.host_cpu.map(|c| c.round()),
                s.window.server_cpu.map(|c| c.round())
            );
        }
    }
    if let Some(s) = &r.still {
        println!(
            "still    first {:?} ms, sharp {:?} ms, detail {:?} to {:?}",
            s.first_ms.map(|v| v.round()),
            s.sharp_ms.map(|v| v.round()),
            s.detail_first.map(|v| v.round()),
            s.detail_final.map(|v| v.round())
        );
    }
}
