//! The stage window. Run it on the computer being measured, then point a
//! remote desktop client at that computer and run `remote-bench` there.
//!
//! ```sh
//! bench-stage [--size 960x600] [--pos 40,80] [--borderless] [--secs 600]
//!             [--control 10.0.0.5:47800] [--scene idle] [--focused]
//! ```
//!
//! With `--control` the stage dials the measuring client, which then switches
//! scenes, syncs clocks and reads the computer's CPU over that link. Without
//! it, F1 to F5 switch scenes by hand. The window closes by itself after
//! `--secs`, so a forgotten stage never stays on someone's screen.
//!
//! `--focused` reports the window as having the keyboard focus whatever the
//! window system says. Use it only on a display with no window manager and
//! nothing else on it, such as the bench container, where X sends keys to the
//! window under the pointer and never tells the window it has the focus.
//!
//! The still scenes (idle, typing, still) draw only when something changes,
//! and every frame presents only the rectangles that changed, so an idle
//! stage is as quiet as an idle desktop.
use bench_stage::{Layout, Scene, StageState, clock_ms, damage, render};
use softbuffer::{Context, Surface};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalPosition, LogicalSize};
use winit::event::{ElementState, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::keyboard::{Key, NamedKey};
use winit::window::{Window, WindowId};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn pair(value: &str, sep: char) -> Option<(u32, u32)> {
    let (a, b) = value.split_once(sep)?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

struct Shared {
    state: StageState,
    frame: u32,
    /// Frames drawn in the last second, for the client to compare against.
    fps: f32,
    /// Whether the window has the keyboard focus.
    active: bool,
    quit: bool,
}

/// Dial the client and serve it until the link drops, then dial again.
fn control(addr: String, shared: Arc<Mutex<Shared>>, size: (u32, u32)) {
    std::thread::spawn(move || {
        loop {
            let Ok(stream) = TcpStream::connect(&addr) else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            let _ = stream.set_nodelay(true);
            let Ok(mut out) = stream.try_clone() else {
                continue;
            };
            let _ = writeln!(out, "hello {} {}", size.0, size.1);
            // CPU goes out once a second from its own thread, so a ping is
            // never queued behind a CPU sample.
            if let Ok(mut report) = stream.try_clone() {
                let shared = shared.clone();
                std::thread::spawn(move || {
                    let mut sys = sysinfo::System::new();
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                        sys.refresh_cpu_usage();
                        let (fps, active) = {
                            let s = shared.lock().unwrap();
                            (s.fps, s.active)
                        };
                        let line = format!(
                            "cpu {:.1} fps {:.1} active {}",
                            sys.global_cpu_usage(),
                            fps,
                            active as u8
                        );
                        if writeln!(report, "{line}").is_err() {
                            return;
                        }
                    }
                });
            }
            for line in BufReader::new(stream).lines() {
                let Ok(line) = line else { break };
                let mut words = line.split_whitespace();
                match (words.next(), words.next()) {
                    (Some("ping"), Some(t)) => {
                        let _ = writeln!(out, "pong {t} {}", clock_ms());
                    }
                    (Some("scene"), Some(name)) => {
                        if let Some(scene) = Scene::parse(name) {
                            let mut s = shared.lock().unwrap();
                            let frame = s.frame;
                            s.state.set_scene(scene, frame);
                        }
                    }
                    (Some("quit"), _) => {
                        shared.lock().unwrap().quit = true;
                        return;
                    }
                    _ => {}
                }
            }
            let _ = out.shutdown(std::net::Shutdown::Both);
        }
    });
}

struct Shown {
    window: Rc<Window>,
    surface: Surface<Rc<Window>, Rc<Window>>,
    size: (u32, u32),
    /// The last frame presented, to work out what changed.
    last: Vec<u32>,
    drawn: Option<StageState>,
}

struct App {
    args: Vec<String>,
    shared: Arc<Mutex<Shared>>,
    shown: Option<Shown>,
    started: Instant,
    next: Instant,
    counted: (Instant, u32),
    focused: bool,
    secs: u64,
    linked: bool,
}

impl App {
    fn draw(&mut self) {
        let Some(shown) = self.shown.as_mut() else {
            return;
        };
        let (w, h) = shown.size;
        let layout = Layout::fit(w, h);
        let (state, frame) = {
            let s = self.shared.lock().unwrap();
            (s.state, s.frame)
        };
        let moving = matches!(state.scene, Scene::Scroll | Scene::Motion);
        let changed = shown.drawn.is_none_or(|d| {
            (d.scene, d.scene_start, d.pointer, d.keys)
                != (state.scene, state.scene_start, state.pointer, state.keys)
        });
        if !moving && !changed {
            return;
        }
        let mut cur = vec![0u32; (w * h) as usize];
        render(&mut cur, w, layout, &state, frame, clock_ms());
        let rects = if shown.last.len() == cur.len() {
            damage(&shown.last, &cur, w, h)
        } else {
            vec![(0, 0, w, h)]
        };
        shown.drawn = Some(state);
        if rects.is_empty() {
            return;
        }
        let Ok(mut buffer) = shown.surface.buffer_mut() else {
            return;
        };
        buffer.copy_from_slice(&cur);
        let rects: Vec<softbuffer::Rect> = rects
            .into_iter()
            .filter_map(|(x, y, rw, rh)| {
                Some(softbuffer::Rect {
                    x,
                    y,
                    width: NonZeroU32::new(rw)?,
                    height: NonZeroU32::new(rh)?,
                })
            })
            .collect();
        let _ = buffer.present_with_damage(&rects);
        shown.last = cur;
        let mut s = self.shared.lock().unwrap();
        s.frame = s.frame.wrapping_add(1);
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.shown.is_some() {
            return;
        }
        let (ww, wh) = arg(&self.args, "--size")
            .and_then(|s| pair(&s, 'x'))
            .unwrap_or((960, 600));
        let mut attributes = Window::default_attributes()
            .with_title("DeskVNC bench stage")
            .with_inner_size(LogicalSize::new(ww, wh))
            .with_resizable(false)
            .with_decorations(!self.args.iter().any(|a| a == "--borderless"));
        if let Some((x, y)) = arg(&self.args, "--pos").and_then(|s| pair(&s, ',')) {
            attributes = attributes.with_position(LogicalPosition::new(x, y));
        }
        let window = Rc::new(
            event_loop
                .create_window(attributes)
                .expect("open the stage window"),
        );
        let context = Context::new(window.clone()).expect("softbuffer context");
        let mut surface = Surface::new(&context, window.clone()).expect("softbuffer surface");
        let size = window.inner_size();
        let (w, h) = (size.width.max(1), size.height.max(1));
        surface
            .resize(NonZeroU32::new(w).unwrap(), NonZeroU32::new(h).unwrap())
            .expect("size the surface");
        if self.linked {
            let layout = Layout::fit(w, h);
            control(
                arg(&self.args, "--control").unwrap_or_default(),
                self.shared.clone(),
                (layout.width, layout.height),
            );
        }
        self.shown = Some(Shown {
            window,
            surface,
            size: (w, h),
            last: Vec::new(),
            drawn: None,
        });
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::CursorMoved { position, .. } => {
                self.shared.lock().unwrap().state.pointer =
                    Some((position.x as f32, position.y as f32));
            }
            WindowEvent::Focused(focused) => {
                self.shared.lock().unwrap().active = focused || self.focused;
            }
            WindowEvent::KeyboardInput { event, .. }
                if event.state == ElementState::Pressed && !event.repeat =>
            {
                let mut s = self.shared.lock().unwrap();
                let frame = s.frame;
                let scene = match event.logical_key {
                    Key::Named(NamedKey::F1) => Some(Scene::Idle),
                    Key::Named(NamedKey::F2) => Some(Scene::Typing),
                    Key::Named(NamedKey::F3) => Some(Scene::Scroll),
                    Key::Named(NamedKey::F4) => Some(Scene::Motion),
                    Key::Named(NamedKey::F5) => Some(Scene::Still),
                    _ => None,
                };
                match scene {
                    Some(scene) => s.state.set_scene(scene, frame),
                    None => s.state.keys = s.state.keys.wrapping_add(1),
                }
            }
            WindowEvent::RedrawRequested => self.draw(),
            _ => {}
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if self.started.elapsed() > Duration::from_secs(self.secs)
            || self.shared.lock().unwrap().quit
        {
            event_loop.exit();
            return;
        }
        let now = Instant::now();
        if now >= self.next {
            if let Some(shown) = &self.shown {
                shown.window.request_redraw();
            }
            let period = Duration::from_secs_f64(1.0 / bench_stage::FPS as f64);
            self.next += period;
            // Running late: start the schedule again rather than racing to
            // catch up with frames nobody saw.
            if self.next < now {
                self.next = now + period;
            }
            if self.counted.0.elapsed() >= Duration::from_secs(1) {
                let mut s = self.shared.lock().unwrap();
                s.fps = s.frame.wrapping_sub(self.counted.1) as f32
                    / self.counted.0.elapsed().as_secs_f32();
                self.counted = (Instant::now(), s.frame);
            }
        }
        event_loop.set_control_flow(ControlFlow::WaitUntil(self.next));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let secs: u64 = arg(&args, "--secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(600);
    let focused = args.iter().any(|a| a == "--focused");
    let mut state = StageState::default();
    if let Some(scene) = arg(&args, "--scene").and_then(|s| Scene::parse(&s)) {
        state.set_scene(scene, 0);
    }
    let shared = Arc::new(Mutex::new(Shared {
        state,
        frame: 0,
        fps: 0.0,
        active: focused,
        quit: false,
    }));
    let event_loop = EventLoop::new().expect("event loop");
    let mut app = App {
        linked: arg(&args, "--control").is_some(),
        args,
        shared,
        shown: None,
        started: Instant::now(),
        next: Instant::now(),
        counted: (Instant::now(), 0),
        focused,
        secs,
    };
    event_loop.run_app(&mut app).expect("run the stage");
}
