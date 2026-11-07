//! Measure how a Boundary session feels across a real network.
//!
//! The host draws a still desktop picture with a square at the last pointer
//! position. The helper moves the pointer and times how long until a screen
//! with the square in its new place arrives, which is what a person feels as
//! lag. With `busy` the host also repaints a large band every capture, the
//! way a scrolling page or a video does, to measure screens per second.
//!
//! ```sh
//! bench host [--image screen.png] [--bind 10.42.0.9]    # prints INVITATION
//! bench host --real                                      # the real screen under the square
//! bench host --software | --no-video                     # OpenH264 only, or tiles only
//! bench view <invitation> [--bind 10.42.0.8] [--secs 20] [--busy] [--video] [--tiles] [--settle 10]
//! bench encode [--image screen.png]                      # time capture side work
//! ```
use boundary_session::video::{VideoEncoder, VideoEncoders};
use boundary_session::{
    Abilities, Approval, Desktop, Event, Frame, HostOptions, Input, Key, Route, Update,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MARK: i64 = 28;
const W: u32 = 1920;
const H: u32 = 1200;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn options(args: &[String]) -> HostOptions {
    match arg(args, "--bind") {
        Some(ip) => HostOptions {
            relay: false,
            relay_url: None,
            bind_ip: Some(ip.parse().expect("bind address")),
        },
        None => HostOptions::default(),
    }
}

/// A desktop sized picture: the given image, or bands of text-like noise.
fn base(args: &[String]) -> Vec<u8> {
    if let Some(path) = arg(args, "--image") {
        let image = image::open(path).expect("image").resize_exact(
            W,
            H,
            image::imageops::FilterType::Triangle,
        );
        return image.into_rgba8().into_raw();
    }
    (0..W * H)
        .flat_map(|i| {
            let (x, y) = (i % W, i / W);
            let text = (y % 18) < 11 && ((x * 31 + y * 7) % 13) < 6 && (x % 400) < 320;
            let v = if text {
                40
            } else {
                235 - ((y / 200) as u8) * 6
            };
            [v, v, v.saturating_add(10), 255]
        })
        .collect()
}

struct State {
    x: f32,
    y: f32,
    busy: bool,
    video: bool,
    tick: u32,
}

struct Synthetic {
    base: Vec<u8>,
    /// Capture the real screen, as the app does, and draw over that.
    real: Option<boundary_platform::Capturer>,
    state: Arc<Mutex<State>>,
    encoders: Option<VideoEncoders>,
}
impl Desktop for Synthetic {
    fn capture(&mut self) -> anyhow::Result<Frame> {
        let (w, h, mut rgba) = match self.real.as_mut() {
            Some(real) => {
                let f = real.capture()?;
                (f.width, f.height, f.rgba)
            }
            None => (W, H, self.base.clone()),
        };
        let mut s = self.state.lock().unwrap();
        s.tick = s.tick.wrapping_add(1);
        if s.video {
            // The whole screen moves, as a video or a dragged window does:
            // the picture slides along by a few pixels every capture.
            let shift = (s.tick * 6) as usize % w as usize;
            let old = rgba.clone();
            let stride = w as usize * 4;
            for y in 0..h as usize {
                let row = &old[y * stride..(y + 1) * stride];
                let (a, b) = row.split_at(shift * 4);
                rgba[y * stride..y * stride + b.len()].copy_from_slice(b);
                rgba[y * stride + b.len()..(y + 1) * stride].copy_from_slice(a);
            }
        }
        if s.busy {
            // A third of the screen changes every capture.
            let shift = s.tick * 37;
            for y in 300..700u32.min(h) {
                for x in 0..w {
                    let i = ((y * w + x) * 4) as usize;
                    let v = (((x + shift) ^ y) % 251) as u8;
                    rgba[i..i + 3].copy_from_slice(&[v, v / 2, 255 - v]);
                }
            }
        }
        let cx = (s.x * (w - 1) as f32) as i64;
        let cy = (s.y * (h - 1) as f32) as i64;
        for y in (cy - MARK / 2).max(0)..(cy + MARK / 2).min(h as i64) {
            for x in (cx - MARK / 2).max(0)..(cx + MARK / 2).min(w as i64) {
                let i = ((y as u32 * w + x as u32) * 4) as usize;
                rgba[i..i + 3].copy_from_slice(&[255, 0, 255]);
            }
        }
        Ok(Frame {
            width: w,
            height: h,
            rgba,
        })
    }
    fn input(&mut self, input: Input) -> anyhow::Result<()> {
        let mut s = self.state.lock().unwrap();
        match input {
            Input::Move { x, y } => (s.x, s.y) = (x, y),
            Input::Key {
                key: Key::Letter('b'),
                down: true,
            } => s.busy = true,
            Input::Key {
                key: Key::Letter('v'),
                down: true,
            } => s.video = true,
            Input::Key {
                key: Key::Letter('q'),
                down: true,
            } => (s.busy, s.video) = (false, false),
            _ => {}
        }
        Ok(())
    }
    fn release(&mut self) {}
    fn video(&self) -> Option<VideoEncoders> {
        self.encoders.clone()
    }
}

/// Is the square drawn at this normalised point?
fn marked(frame: &Frame, x: f32, y: f32) -> bool {
    let px = (x * (frame.width - 1) as f32) as usize;
    let py = (y * (frame.height - 1) as f32) as usize;
    let i = (py * frame.width as usize + px) * 4;
    let p = &frame.rgba[i..i + 3];
    p[0] > 200 && p[1] < 70 && p[2] > 200
}

/// What the helper's window would show: screens of tiles, and video decoded
/// over them, in the order they came.
#[derive(Default)]
struct Screen {
    canvas: Option<Frame>,
    decoder: Option<openh264::decoder::Decoder>,
    /// Updates drawn, and how many of them were video.
    shown: u64,
    video: u64,
    /// When the whole screen last came as tiles after video.
    settled: Option<Instant>,
    after_video: bool,
    /// Time spent decoding video here, which the webview does in hardware.
    decoding: Duration,
    last: Option<Instant>,
    /// The longest wait between two updates.
    gap: Duration,
}
impl Screen {
    fn apply(&mut self, updates: Vec<Update>) -> anyhow::Result<()> {
        for update in updates {
            self.shown += 1;
            if let Some(last) = self.last.replace(Instant::now()) {
                self.gap = self.gap.max(last.elapsed());
            }
            match update {
                Update::Screen { frame, rects } => {
                    let canvas = match self.canvas.as_mut() {
                        Some(c) if c.width == frame.width && c.height == frame.height => c,
                        _ => self.canvas.insert((*frame).clone()),
                    };
                    match &rects {
                        None => canvas.rgba.copy_from_slice(&frame.rgba),
                        Some(rects) => {
                            let stride = frame.width as usize * 4;
                            for r in rects {
                                for y in r.y..r.y + r.height {
                                    let i = y as usize * stride + r.x as usize * 4;
                                    let n = r.width as usize * 4;
                                    canvas.rgba[i..i + n].copy_from_slice(&frame.rgba[i..i + n]);
                                }
                            }
                        }
                    }
                    let whole = rects.as_ref().is_none_or(|rects| {
                        rects
                            .iter()
                            .map(|r| r.width as u64 * r.height as u64)
                            .sum::<u64>()
                            == frame.width as u64 * frame.height as u64
                    });
                    if self.after_video && whole {
                        self.after_video = false;
                        self.settled = Some(Instant::now());
                    }
                }
                Update::Video(unit) => {
                    self.video += 1;
                    self.after_video = true;
                    if unit.fresh || self.decoder.is_none() {
                        self.decoder = Some(openh264::decoder::Decoder::new()?);
                    }
                    let decoder = self.decoder.as_mut().expect("made above");
                    // Keep the stream, to look at with ffprobe.
                    if let Some(path) = std::env::var_os("BENCH_DUMP") {
                        use std::io::Write;
                        std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)?
                            .write_all(&unit.data)?;
                    }
                    let t = Instant::now();
                    // A NAL unit at a time: OpenH264 refuses a picture of
                    // several slices handed over at once, which is what the
                    // hardware encoders on Intel Macs make.
                    let mut decoded = None;
                    for nal in openh264::nal_units(&unit.data) {
                        if let Some(picture) = decoder.decode(nal)? {
                            use openh264::formats::YUVSource;
                            let (dw, dh) = picture.dimensions();
                            let mut rgba = vec![0u8; dw * dh * 4];
                            picture.write_rgba8(&mut rgba);
                            decoded = Some((dw, dh, rgba));
                        }
                    }
                    let Some((dw, dh, rgba)) = decoded else {
                        anyhow::bail!("the decoder held a picture back");
                    };
                    let canvas = match self.canvas.as_mut() {
                        Some(c) if c.width == unit.width && c.height == unit.height => c,
                        _ => self.canvas.insert(Frame {
                            width: unit.width,
                            height: unit.height,
                            rgba: vec![0; unit.width as usize * unit.height as usize * 4],
                        }),
                    };
                    let (w, h) = (dw.min(unit.width as usize), dh.min(unit.height as usize));
                    for y in 0..h {
                        let to = y * unit.width as usize * 4;
                        let from = y * dw * 4;
                        canvas.rgba[to..to + w * 4].copy_from_slice(&rgba[from..from + w * 4]);
                    }
                    self.decoding += t.elapsed();
                }
            }
        }
        Ok(())
    }
    fn marked(&self, x: f32, y: f32) -> bool {
        self.canvas.as_ref().is_some_and(|c| marked(c, x, y))
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let started = Instant::now();
    match args.first().map(String::as_str) {
        Some("host") => {
            let base = base(&args);
            let real = args.iter().any(|a| a == "--real");
            let encoders: Option<VideoEncoders> = if args.iter().any(|a| a == "--no-video") {
                None
            } else {
                let inner = if args.iter().any(|a| a == "--software") {
                    boundary_platform::video::software()
                } else {
                    boundary_platform::video::encoders()
                };
                // Say which encoder each session got.
                Some(Arc::new(move |w, h| {
                    let encoder: Box<dyn VideoEncoder> = inner(w, h)?;
                    println!("video encoder {} {w}x{h}", encoder.name());
                    Ok(encoder)
                }))
            };
            let mut session = boundary_session::host(options(&args), move || {
                let real = if real {
                    let id = boundary_platform::displays()?
                        .first()
                        .map(|d| d.id)
                        .ok_or_else(|| anyhow::anyhow!("no display"))?;
                    Some(boundary_platform::Capturer::new(id)?)
                } else {
                    None
                };
                Ok(Box::new(Synthetic {
                    base,
                    real,
                    state: Arc::new(Mutex::new(State {
                        x: 0.5,
                        y: 0.5,
                        busy: false,
                        video: false,
                        tick: 0,
                    })),
                    encoders,
                }))
            });
            while let Some(event) = session.events.recv().await {
                match event {
                    Event::Invitation(t) => println!("INVITATION {t}"),
                    Event::Approval { answer, .. } => {
                        let _ = answer.send(Approval::Control);
                    }
                    Event::Connected { .. } => println!("{:?} connected", started.elapsed()),
                    Event::Finished(result) => {
                        println!("finished: {result:?}");
                        break;
                    }
                    _ => {}
                }
            }
        }
        Some("view") => {
            let secs: u64 = arg(&args, "--secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(20);
            let busy = args.iter().any(|a| a == "--busy");
            let video = args.iter().any(|a| a == "--video");
            // Without --tiles the helper says it decodes H.264, as DeskVNC does.
            let tiles_only = args.iter().any(|a| a == "--tiles");
            let mut session = boundary_session::viewer_with(
                args[1].clone(),
                "Bench".into(),
                options(&args),
                None,
                Abilities {
                    tools: false,
                    video: !tiles_only,
                    clipboard: false,
                },
            );
            loop {
                match session.events.recv().await {
                    Some(Event::Connected { .. }) => break,
                    Some(Event::Finished(r)) => anyhow::bail!("finished before connecting: {r:?}"),
                    None => anyhow::bail!("session ended"),
                    _ => {}
                }
            }
            let connected = started.elapsed();
            let mut screen = Screen::default();
            while screen.canvas.is_none() {
                session.frames.changed().await?;
                screen.apply(session.updates())?;
            }
            let first = started.elapsed();
            for (on, letter) in [(busy, 'b'), (video, 'v')] {
                if on {
                    session.input(Input::Key {
                        key: Key::Letter(letter),
                        down: true,
                    })?;
                }
            }
            let mut lags = Vec::new();
            let mut misses = 0u32;
            let points = [(0.2, 0.2), (0.8, 0.3), (0.3, 0.8), (0.7, 0.7), (0.5, 0.15)];
            let end = Instant::now() + Duration::from_secs(secs);
            let mut n = 0;
            let measured = Instant::now();
            let (shown_before, video_before, bytes_before) =
                (screen.shown, screen.video, session.received());
            while Instant::now() < end {
                let (x, y) = points[n % points.len()];
                n += 1;
                let sent = Instant::now();
                session.input(Input::Move { x, y })?;
                let seen = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        session.frames.changed().await?;
                        screen.apply(session.updates())?;
                        if screen.marked(x, y) {
                            return anyhow::Ok(());
                        }
                        if std::env::var_os("BENCH_DEBUG").is_some()
                            && sent.elapsed() > Duration::from_millis(400)
                            && let Some(c) = screen.canvas.as_ref()
                        {
                            let px = (x * (c.width - 1) as f32) as usize;
                            let py = (y * (c.height - 1) as f32) as usize;
                            let i = (py * c.width as usize + px) * 4;
                            eprintln!("slow move {n} at {px},{py}: {:?}", &c.rgba[i..i + 4]);
                            let _ = image::save_buffer("/private/tmp/claude-501/-Users-godwin-workspace-DeskVNC/1e3123ad-01eb-4793-b40b-e5a5170e601b/scratchpad/fv/slow.png", &c.rgba, c.width, c.height, image::ExtendedColorType::Rgba8);
                        }
                    }
                })
                .await;
                match seen {
                    Ok(r) => {
                        r?;
                        lags.push(sent.elapsed());
                        if std::env::var_os("BENCH_DEBUG").is_some() {
                            eprintln!(
                                "move {n} lag {:?} shown {} video {} gap {:?}",
                                sent.elapsed(),
                                screen.shown,
                                screen.video,
                                screen.gap
                            );
                            screen.gap = Duration::ZERO;
                        }
                    }
                    Err(_) => {
                        misses += 1;
                        if std::env::var_os("BENCH_DEBUG").is_some()
                            && let Some(c) = screen.canvas.as_ref()
                        {
                            let px = (x * (c.width - 1) as f32) as usize;
                            let py = (y * (c.height - 1) as f32) as usize;
                            let i = (py * c.width as usize + px) * 4;
                            eprintln!(
                                "missed move {n} at {px},{py}: {:?} shown {} video {}",
                                &c.rgba[i..i + 4],
                                screen.shown,
                                screen.video
                            );
                            let _ = image::save_buffer(
                                "/private/tmp/claude-501/-Users-godwin-workspace-DeskVNC/1e3123ad-01eb-4793-b40b-e5a5170e601b/scratchpad/fv/miss.png",
                                &c.rgba,
                                c.width,
                                c.height,
                                image::ExtendedColorType::Rgba8,
                            );
                        }
                    }
                }
                // Keep counting screens for a moment, as a person pausing would.
                let pause = Instant::now() + Duration::from_millis(300);
                while let Ok(Ok(())) =
                    tokio::time::timeout_at(pause.into(), session.frames.changed()).await
                {
                    screen.apply(session.updates())?;
                }
            }
            let elapsed = measured.elapsed().as_secs_f64();
            let shown = screen.shown - shown_before;
            let as_video = screen.video - video_before;
            let bits = (session.received() - bytes_before) as f64 * 8.0 / elapsed;
            // Stop the motion and time until the screen is sent sharp again:
            // a whole screen of tiles after the last picture of video.
            let mut sharp = None;
            if video || busy {
                screen.settled = None;
                let stopped = Instant::now();
                let before = session.received();
                session.input(Input::Key {
                    key: Key::Letter('q'),
                    down: true,
                })?;
                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        session.frames.changed().await?;
                        screen.apply(session.updates())?;
                        if let Some(at) = screen.settled {
                            sharp = Some((at.duration_since(stopped), session.received() - before));
                            return anyhow::Ok(());
                        }
                    }
                })
                .await;
            }
            let c = session.connectivity.borrow().clone();
            lags.sort();
            println!(
                "route {} rtt {:?} | connect {:.2}s first screen {:.2}s | lag p50 {:?} p90 {:?} max {:?} ({} moves, {} missed) | {:.1} screens/s ({} video) | {:.2} Mbit/s | sharp after stop {} | decode {:?} a picture",
                match c.route {
                    Some(Route::Direct) => "direct",
                    Some(Route::Relay) => "relay",
                    _ => "unknown",
                },
                c.rtt,
                connected.as_secs_f64(),
                first.as_secs_f64(),
                percentile(&lags, 0.5),
                percentile(&lags, 0.9),
                lags.last().copied().unwrap_or_default(),
                lags.len(),
                misses,
                shown as f64 / elapsed,
                as_video,
                bits / 1e6,
                sharp.map_or("n/a".into(), |(d, bytes)| format!(
                    "{d:?} ({} KB since)",
                    bytes / 1024
                )),
                screen.decoding / screen.video.max(1) as u32,
            );
            // Start and stop the motion again and again, and time each stop
            // until the last update that follows it: what is sent once the
            // screen is still is what makes it sharp.
            if let Some(cycles) = arg(&args, "--settle").and_then(|n| n.parse::<usize>().ok()) {
                let mut sharp = Vec::new();
                let mut first = Vec::new();
                let mut bytes = Vec::new();
                let mut seen = Vec::new();
                let mut settled = Vec::new();
                for _ in 0..cycles {
                    session.input(Input::Key {
                        key: Key::Letter('v'),
                        down: true,
                    })?;
                    let moving = Instant::now() + Duration::from_millis(1500);
                    while let Ok(Ok(())) =
                        tokio::time::timeout_at(moving.into(), session.frames.changed()).await
                    {
                        screen.apply(session.updates())?;
                    }
                    let video = screen.video;
                    session.input(Input::Key {
                        key: Key::Letter('q'),
                        down: true,
                    })?;
                    let stopped = Instant::now();
                    let before = session.received();
                    let (mut last, mut earliest, mut still) = (None, None, stopped);
                    let (mut at_still, mut at_sharp) = (session.received(), 0);
                    let quiet = stopped + Duration::from_millis(2500);
                    while let Ok(Ok(())) =
                        tokio::time::timeout_at(quiet.into(), session.frames.changed()).await
                    {
                        let updates = session.updates();
                        let tiles = updates.iter().any(|u| matches!(u, Update::Screen { .. }));
                        let videos = updates.iter().any(|u| matches!(u, Update::Video(_)));
                        screen.apply(updates)?;
                        if videos {
                            (last, earliest, still) = (None, None, Instant::now());
                            at_still = session.received();
                        } else if tiles {
                            last = Some(stopped.elapsed());
                            at_sharp = session.received();
                            earliest.get_or_insert(stopped.elapsed());
                        }
                    }
                    if screen.video > video
                        && let (Some(last), Some(earliest)) = (last, earliest)
                    {
                        sharp.push(last);
                        // From when the picture stopped moving here, which is
                        // what the person watching sees.
                        seen.push(stopped + last - still);
                        first.push(earliest);
                        bytes.push(session.received() - before);
                        settled.push(at_sharp.saturating_sub(at_still));
                    }
                }
                sharp.sort();
                seen.sort();
                first.sort();
                bytes.sort();
                settled.sort();
                println!(
                    "settle over {} stops: sharp after stop key p50 {:?} p90 {:?} | after last video picture p50 {:?} p90 {:?} | first tiles p50 {:?} | KB after stop p50 {} max {} | KB of sharp tiles p50 {} max {}",
                    sharp.len(),
                    percentile(&sharp, 0.5),
                    percentile(&sharp, 0.9),
                    percentile(&seen, 0.5),
                    percentile(&seen, 0.9),
                    percentile(&first, 0.5),
                    bytes.get(bytes.len() / 2).copied().unwrap_or(0) / 1024,
                    bytes.last().copied().unwrap_or(0) / 1024,
                    settled.get(settled.len() / 2).copied().unwrap_or(0) / 1024,
                    settled.last().copied().unwrap_or(0) / 1024,
                );
            }
            session.stop();
        }
        Some("encode") => {
            let base = base(&args);
            let frame = Frame {
                width: W,
                height: H,
                rgba: base,
            };
            let big = image::DynamicImage::ImageRgba8(
                image::RgbaImage::from_raw(W, H, frame.rgba.clone()).unwrap(),
            )
            .resize_exact(5120, 2880, image::imageops::FilterType::Nearest);
            let t = Instant::now();
            let _ = big.resize(1920, 1200, image::imageops::FilterType::Triangle);
            let resize = t.elapsed();
            let fast = {
                use fast_image_resize::{
                    FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer, images::Image,
                };
                let raw = big.to_rgba8().into_raw();
                let mut resizer = Resizer::new();
                let t = Instant::now();
                let src = Image::from_vec_u8(5120, 2880, raw, PixelType::U8x4)?;
                let mut dst = Image::new(1920, 1080, PixelType::U8x4);
                resizer.resize(
                    &src,
                    &mut dst,
                    &ResizeOptions::new()
                        .resize_alg(ResizeAlg::Convolution(FilterType::Bilinear))
                        .use_alpha(false),
                )?;
                t.elapsed()
            };
            let t = Instant::now();
            let jpeg = frame.encode_jpeg()?;
            let encode = t.elapsed();
            let t = Instant::now();
            let _ = Frame::decode(&jpeg)?;
            let decode = t.elapsed();
            println!(
                "5K to 1920 resize {resize:?} simd {fast:?} | jpeg encode {encode:?} {} KB | decode {decode:?}",
                jpeg.len() / 1024
            );
        }
        _ => eprintln!("usage: bench host | bench view <invitation> | bench encode"),
    }
    Ok(())
}
