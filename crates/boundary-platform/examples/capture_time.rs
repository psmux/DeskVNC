//! Time screen capture the way the host does it, against the old way.
//!
//! cargo run --release -p boundary-platform --example capture_time [seconds] [--motion] [--input]
//!
//! For each way it calls capture_changed in a loop, as the host's capture
//! worker does, and reports how long a call that brought a new screen took,
//! how many new screens came each second, how much of each screen was said to
//! have changed, and the CPU this process used. "stream" is ScreenCaptureKit
//! on a Mac and Desktop Duplication on Windows; "poll" is a whole picture per
//! call, as before. `--motion` on Windows opens a small window that redraws
//! every 15 ms for the length of the run, so there is something to capture;
//! without it the numbers are for whatever the screen does by itself.
//! `--input` also times pointer moves through the same path the host uses.
//!
//! It asks for no permission first, so it can run over SSH. A Mac that
//! refuses the windows still returns the wallpaper, which costs the same.
//! Windows over SSH runs outside the signed in session, where neither way
//! sees the desktop: run it in that session, for example from a scheduled
//! task with /IT.
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let seconds: u64 = args.iter().find_map(|a| a.parse().ok()).unwrap_or(5);
    let motion = args.iter().any(|a| a == "--motion");
    let input = args.iter().any(|a| a == "--input");
    let displays = boundary_platform::displays()?;
    for d in &displays {
        println!("display {} {}", d.id, d.name);
    }
    let id = displays.first().map(|d| d.id).unwrap_or_default();
    let _motion = motion.then(Motion::start);
    if motion {
        // Let the window appear before timing starts.
        std::thread::sleep(Duration::from_millis(1500));
    }
    for stream in [true, false] {
        let t = Instant::now();
        let capturer = if stream {
            boundary_platform::Capturer::new(id)?
        } else {
            boundary_platform::Capturer::polling(id)?
        };
        println!(
            "{}: ready in {:?}",
            if stream { "stream" } else { "poll" },
            t.elapsed()
        );
        run(capturer, Duration::from_secs(seconds), stream)?;
    }
    if input {
        time_input(id)?;
    }
    #[cfg(target_os = "macos")]
    mac_pictures();
    Ok(())
}

fn run(
    mut capturer: boundary_platform::Capturer,
    length: Duration,
    stream: bool,
) -> anyhow::Result<()> {
    let name = if stream { "stream" } else { "poll" };
    let (mut calls, mut frames) = (0u64, 0u64);
    let mut times = Vec::new();
    let mut changed_share = 0f64;
    let mut size = (0, 0);
    let cpu = cpu_time();
    let t = Instant::now();
    while t.elapsed() < length {
        calls += 1;
        let call = Instant::now();
        let frame = capturer.capture_changed()?;
        let took = call.elapsed();
        if let Some(frame) = frame {
            frames += 1;
            times.push(took);
            size = (frame.width, frame.height);
            let area = (frame.width as f64 * frame.height as f64).max(1.0);
            changed_share += match capturer.capture_damage() {
                Some(rects) => {
                    rects
                        .iter()
                        .map(|r| r.width as f64 * r.height as f64)
                        .sum::<f64>()
                        / area
                }
                None => 1.0,
            };
        }
        // The host captures at most every 16 ms while the screen is busy.
        if let Some(rest) = Duration::from_millis(16).checked_sub(call.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    let wall = t.elapsed();
    let cpu = cpu_time().zip(cpu).map(|(after, before)| after - before);
    times.sort();
    let pick = |q: f64| {
        times
            .get(((times.len() as f64 - 1.0) * q).round() as usize)
            .copied()
            .unwrap_or_default()
    };
    let mean = times.iter().sum::<Duration>() / (times.len().max(1) as u32);
    println!(
        "{name}: {}x{}, streaming {}, {calls} calls, {frames} new screens, {:.1} screens/s",
        size.0,
        size.1,
        capturer.streaming(),
        frames as f64 / wall.as_secs_f64()
    );
    println!(
        "{name}: capture mean {:.2} ms, median {:.2} ms, p95 {:.2} ms, max {:.2} ms",
        ms(mean),
        ms(pick(0.5)),
        ms(pick(0.95)),
        ms(pick(1.0))
    );
    println!(
        "{name}: changed {:.1}% of each new screen on average, CPU {}",
        100.0 * changed_share / frames.max(1) as f64,
        match cpu {
            Some(cpu) => format!(
                "{:.0} ms over {:.1} s ({:.1}% of one core)",
                ms(cpu),
                wall.as_secs_f64(),
                100.0 * cpu.as_secs_f64() / wall.as_secs_f64()
            ),
            None => "not measured here".into(),
        }
    );
    if let Some(trouble) = capturer.trouble() {
        println!("{name}: {trouble}");
    }
    Ok(())
}

/// Pointer moves through the host's own path, back and forth over a small
/// square in the middle of the screen, then the pointer put back.
fn time_input(id: u32) -> anyhow::Result<()> {
    use boundary_session::Input;
    let mut desktop = boundary_platform::open(id)?;
    let mut times = Vec::new();
    for i in 0..400 {
        let x = 0.45 + 0.1 * ((i % 20) as f32 / 20.0);
        let t = Instant::now();
        desktop.input(Input::Move { x, y: 0.5 })?;
        times.push(t.elapsed());
    }
    times.sort();
    println!(
        "input: 400 moves, median {:.3} ms, p95 {:.3} ms, max {:.3} ms",
        ms(times[200]),
        ms(times[380]),
        ms(times[399])
    );
    Ok(())
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// CPU time this process has used, user and system together.
#[cfg(unix)]
fn cpu_time() -> Option<Duration> {
    // SAFETY: getrusage fills the struct it is given.
    let usage = unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        (libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0).then_some(usage)
    }?;
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    Some(tv(usage.ru_utime) + tv(usage.ru_stime))
}
#[cfg(windows)]
fn cpu_time() -> Option<Duration> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let mut t = [FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }; 4];
    let [created, exited, kernel, user] = &mut t;
    // SAFETY: four valid out pointers.
    let ok = unsafe { GetProcessTimes(GetCurrentProcess(), created, exited, kernel, user) };
    let hundreds = |f: &FILETIME| (f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64;
    (ok != 0).then(|| Duration::from_nanos((hundreds(&t[2]) + hundreds(&t[3])) * 100))
}
#[cfg(not(any(unix, windows)))]
fn cpu_time() -> Option<Duration> {
    None
}

/// A window that redraws every 15 ms, for as long as this lives.
struct Motion(Option<std::process::Child>);
impl Motion {
    fn start() -> Self {
        #[cfg(windows)]
        {
            const SCRIPT: &str = r#"
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object Windows.Forms.Form
$f.Text = 'capture_time motion'; $f.Width = 900; $f.Height = 600
$f.StartPosition = 'CenterScreen'; $f.TopMost = $true
$l = New-Object Windows.Forms.Label
$l.Font = New-Object Drawing.Font('Consolas', 48); $l.AutoSize = $true
$f.Controls.Add($l)
$p = New-Object Windows.Forms.Panel; $p.Width = 120; $p.Height = 120
$f.Controls.Add($p)
$n = 0
$t = New-Object Windows.Forms.Timer; $t.Interval = 15
$t.Add_Tick({
  $script:n++
  $l.Text = "frame $script:n"
  $p.Left = 20 + ($script:n * 7) % 720; $p.Top = 120 + ($script:n * 3) % 300
  $p.BackColor = [Drawing.Color]::FromArgb(255, ($script:n * 5) % 256, ($script:n * 11) % 256, ($script:n * 17) % 256)
})
$t.Start()
[Windows.Forms.Application]::Run($f)
"#;
            Self(
                std::process::Command::new("powershell")
                    .args(["-NoProfile", "-Command", SCRIPT])
                    .spawn()
                    .ok(),
            )
        }
        #[cfg(not(windows))]
        {
            println!("--motion only draws on Windows; move something on screen instead");
            Self(None)
        }
    }
}
impl Drop for Motion {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// One picture from the window server at full Retina pixels and at point
/// size, which is what decided capturing at point size on a Mac.
#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn mac_pictures() {
    use objc2_core_graphics::{
        CGDataProvider, CGDisplayBounds, CGImage, CGMainDisplayID, CGWindowImageOption,
        CGWindowListCreateImage, CGWindowListOption,
    };
    let id = CGMainDisplayID();
    for (name, option) in [
        ("retina", CGWindowImageOption::Default),
        ("nominal", CGWindowImageOption::NominalResolution),
    ] {
        for _ in 0..4 {
            let t = Instant::now();
            let image = CGWindowListCreateImage(
                CGDisplayBounds(id),
                CGWindowListOption::OptionAll,
                0,
                option,
            );
            let data = CGDataProvider::data(CGImage::data_provider(image.as_deref()).as_deref())
                .map(|d| d.to_vec())
                .unwrap_or_default();
            println!(
                "{name} {}x{} {} MB capture {:?}",
                CGImage::width(image.as_deref()),
                CGImage::height(image.as_deref()),
                data.len() / 1_000_000,
                t.elapsed()
            );
        }
    }
}
