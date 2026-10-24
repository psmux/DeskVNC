//! The stage window. Run it on the computer being measured, then point a
//! remote desktop client at that computer and run `remote-bench` there.
//!
//! ```sh
//! bench-stage [--size 960x600] [--pos 40,80] [--borderless] [--secs 600]
//!             [--control 10.0.0.5:47800] [--scene idle]
//! ```
//!
//! With `--control` the stage dials the measuring client, which then switches
//! scenes, syncs clocks and reads the computer's CPU over that link. Without
//! it, F1 to F5 switch scenes by hand. The window closes by itself after
//! `--secs`, so a forgotten stage never stays on someone's screen.
use bench_stage::{Layout, Scene, StageState, clock_ms, render};
use minifb::{Key, KeyRepeat, MouseMode, Window, WindowOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
        let mut sys = sysinfo::System::new();
        loop {
            let Ok(stream) = TcpStream::connect(&addr) else {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            let _ = stream.set_nodelay(true);
            let mut out = stream.try_clone().expect("socket clone");
            let _ = writeln!(out, "hello {} {}", size.0, size.1);
            // CPU goes out once a second from its own thread, so a ping is
            // never queued behind a CPU sample.
            let reporter = {
                let mut out = stream.try_clone().expect("socket clone");
                let shared = shared.clone();
                std::thread::spawn(move || {
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
                        if writeln!(out, "{line}").is_err() {
                            return sys;
                        }
                    }
                })
            };
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
            sys = reporter.join().unwrap_or_else(|_| sysinfo::System::new());
        }
    });
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (ww, wh) = arg(&args, "--size")
        .and_then(|s| pair(&s, 'x'))
        .unwrap_or((960, 600));
    let secs: u64 = arg(&args, "--secs").and_then(|s| s.parse().ok()).unwrap_or(600);
    let layout = Layout::fit(ww, wh);
    let mut window = Window::new(
        "DeskVNC bench stage",
        ww as usize,
        wh as usize,
        WindowOptions {
            borderless: args.iter().any(|a| a == "--borderless"),
            ..WindowOptions::default()
        },
    )
    .expect("open the stage window");
    if let Some((x, y)) = arg(&args, "--pos").and_then(|s| pair(&s, ',')) {
        window.set_position(x as isize, y as isize);
    }
    // The stage paces itself; minifb's own limiter would sleep on top.
    window.set_target_fps(0);
    let shared = Arc::new(Mutex::new(Shared {
        state: StageState::default(),
        frame: 0,
        fps: 0.0,
        active: false,
        quit: false,
    }));
    if let Some(scene) = arg(&args, "--scene").and_then(|s| Scene::parse(&s)) {
        shared.lock().unwrap().state.set_scene(scene, 0);
    }
    if let Some(addr) = arg(&args, "--control") {
        control(addr, shared.clone(), (layout.width, layout.height));
    }
    let mut buf = vec![0u32; (ww * wh) as usize];
    let start = Instant::now();
    let period = Duration::from_secs_f64(1.0 / bench_stage::FPS as f64);
    let mut next = Instant::now();
    let mut counted = (Instant::now(), 0u32);
    let mut frame = 0u32;
    while window.is_open() && start.elapsed() < Duration::from_secs(secs) {
        let pointer = window.get_mouse_pos(MouseMode::Discard);
        let keys = window.get_keys_pressed(KeyRepeat::No);
        let state = {
            let mut s = shared.lock().unwrap();
            if s.quit {
                break;
            }
            s.frame = frame;
            s.active = window.is_active();
            s.state.pointer = pointer;
            for key in keys {
                let scene = match key {
                    Key::F1 => Some(Scene::Idle),
                    Key::F2 => Some(Scene::Typing),
                    Key::F3 => Some(Scene::Scroll),
                    Key::F4 => Some(Scene::Motion),
                    Key::F5 => Some(Scene::Still),
                    _ => None,
                };
                match scene {
                    Some(scene) => s.state.set_scene(scene, frame),
                    None => s.state.keys = s.state.keys.wrapping_add(1),
                }
            }
            if counted.0.elapsed() >= Duration::from_secs(1) {
                s.fps = (frame - counted.1) as f32 / counted.0.elapsed().as_secs_f32();
                counted = (Instant::now(), frame);
            }
            s.state
        };
        render(&mut buf, ww, layout, &state, frame, clock_ms());
        if window
            .update_with_buffer(&buf, ww as usize, wh as usize)
            .is_err()
        {
            break;
        }
        frame = frame.wrapping_add(1);
        next += period;
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else {
            // Running late: start the schedule again rather than racing to
            // catch up with frames nobody saw.
            next = now;
        }
    }
}
