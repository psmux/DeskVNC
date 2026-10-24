use anyhow::{Context, Result, ensure};
use boundary_session::{Button, Desktop, Frame, Input, Key, Rect};
use enigo::{Axis, Coordinate, Direction, Enigo, Keyboard, Mouse, Settings};
#[cfg(not(target_os = "linux"))]
use xcap::Monitor;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod sck;
#[cfg(windows)]
pub mod system;

/// Attach this thread to the desktop with the input, where that matters.
fn on_input_desktop() {
    #[cfg(windows)]
    system::on_input_desktop();
}

#[derive(Clone)]
pub struct Display {
    pub id: u32,
    pub name: String,
}
/// Make this process see physical pixels on a scaled Windows display.
///
/// Windows gives a process that has not declared DPI awareness a scaled down
/// screen and rescales its coordinates. Capture then reports physical pixels
/// while a pointer move is read as scaled ones, so on a 200% display a click at
/// a quarter of the way across landed half way across. The support app's window
/// declared awareness by accident of its toolkit; a background host does not
/// have one, so it is declared here, once, for whatever process uses this
/// crate. Declaring it again, or after a toolkit did, is refused by Windows and
/// harmless.
fn dpi_aware() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::HiDpi::{
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
        };
        static ONCE: std::sync::Once = std::sync::Once::new();
        // SAFETY: a process wide setting with no pointers passed.
        ONCE.call_once(|| unsafe {
            SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        });
    }
}

pub fn displays() -> Result<Vec<Display>> {
    #[cfg(target_os = "linux")]
    return Ok(linux::displays()?
        .into_iter()
        .map(|(id, name)| Display { id, name })
        .collect());
    #[cfg(not(target_os = "linux"))]
    dpi_aware();
    #[cfg(not(target_os = "linux"))]
    Monitor::all()?
        .into_iter()
        .map(|m| {
            Ok(Display {
                id: m.id()?,
                name: format!("{} ({} × {})", m.name()?, m.width()?, m.height()?),
            })
        })
        .collect()
}
/// The primary display, for a computer nobody is at, chosen when a helper
/// arrives rather than when listening starts. A Mac whose screen has gone to
/// sleep lists no display at all, so a copy started then used to give up on
/// unattended access for good; this wakes the screen and asks again.
pub fn open_primary() -> Result<Box<dyn Desktop>> {
    open(primary_display()?)
}
fn primary_display() -> Result<u32> {
    let first = || displays().ok().and_then(|all| all.first().map(|d| d.id));
    if let Some(id) = first() {
        return Ok(id);
    }
    wake_screen();
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Some(id) = first() {
            return Ok(id);
        }
    }
    anyhow::bail!("No display found to share. The screen may be switched off")
}
/// Wake a sleeping screen the way a key press would.
fn wake_screen() {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("/usr/bin/caffeinate")
        .args(["-u", "-t", "5"])
        .spawn();
}
pub fn open(id: u32) -> Result<Box<dyn Desktop>> {
    dpi_aware();
    ensure!(
        screen_permission(),
        "Allow this app in System Settings > Privacy & Security > Screen & System Audio Recording, then reopen the app"
    );
    let awake = Awake::hold();
    let screen = Capturer::new(id)?;
    Ok(Box::new(NativeDesktop {
        #[cfg(target_os = "linux")]
        remote: screen.linux.remote(),
        screen,
        enigo: None,
        buttons: Vec::new(),
        keys: Vec::new(),
        _awake: awake,
    }))
}
/// The screen at its size in points, not Retina pixels.
///
/// A 5K iMac has four times as many pixels as points. Asking for all of them
/// took 110 ms on a 2020 i5 and 58 ms on an i9, then the copy and the shrink
/// to 1920 wide came on top; at point size the window server scales on the
/// GPU and the same capture takes 35 ms and 17 ms. The screen goes out at no
/// more than 1920 wide either way, so nothing a helper can see is lost.
#[cfg(target_os = "macos")]
fn capture_pixels(monitor: &Monitor) -> Result<(u32, u32, Vec<u8>)> {
    #[allow(deprecated)]
    use objc2_core_graphics::CGWindowListCreateImage;
    use objc2_core_graphics::{
        CGDataProvider, CGDisplayBounds, CGImage, CGWindowImageOption, CGWindowListOption,
    };
    const FAILED: &str = "Screen capture failed. Check Screen Recording permission";
    // Deprecated for ScreenCaptureKit, but still what works on every macOS
    // this app supports, and the call xcap itself makes.
    #[allow(deprecated)]
    let image = CGWindowListCreateImage(
        CGDisplayBounds(monitor.id()?),
        CGWindowListOption::OptionAll,
        0,
        CGWindowImageOption::NominalResolution,
    )
    .context(FAILED)?;
    let (width, height) = (CGImage::width(Some(&image)), CGImage::height(Some(&image)));
    let stride = CGImage::bytes_per_row(Some(&image));
    ensure!(
        width > 0
            && height > 0
            && CGImage::bits_per_pixel(Some(&image)) == 32
            && stride >= width * 4,
        FAILED
    );
    let data = CGDataProvider::data(CGImage::data_provider(Some(&image)).as_deref())
        .context(FAILED)?
        .to_vec();
    ensure!(data.len() >= stride * height, FAILED);
    // Drop the padding at the end of each row and turn BGRA into RGBA in
    // one pass.
    let mut rgba = Vec::with_capacity(width * height * 4);
    for row in data.chunks_exact(stride).take(height) {
        rgba.extend(
            row[..width * 4]
                .as_chunks::<4>()
                .0
                .iter()
                .flat_map(|p| [p[2], p[1], p[0], 255]),
        );
    }
    Ok((width as u32, height as u32, rgba))
}
#[cfg(windows)]
fn capture_pixels(monitor: &Monitor) -> Result<(u32, u32, Vec<u8>)> {
    let pixels = monitor
        .capture_image()
        .context("Screen capture failed. Check Screen Recording permission")?;
    let (width, height) = pixels.dimensions();
    Ok((width, height, pixels.into_raw()))
}

/// Screens larger than this are shrunk to fit before they are sent.
const MAX_WIDTH: u32 = 1920;
const MAX_HEIGHT: u32 = 1200;

/// One display's screen, captured and shrunk to the size it is sent at.
///
/// Opening one does not check for permission, which is [`open`]'s job: on a
/// Mac without it the picture is the wallpaper alone, at the same cost, which
/// is what makes this usable for timing a machine over SSH.
pub struct Capturer {
    #[cfg(not(target_os = "linux"))]
    monitor: Monitor,
    /// X11 through shared memory, or a Wayland portal stream.
    #[cfg(target_os = "linux")]
    linux: linux::Screen,
    resizer: fast_image_resize::Resizer,
    /// A ScreenCaptureKit stream, where one could be started.
    #[cfg(target_os = "macos")]
    stream: Option<sck::Stream>,
    /// The last screen, for a caller that wants one whether or not it changed.
    last: Option<Frame>,
    /// What changed in `last`, where the system said.
    damage: Option<Vec<Rect>>,
}
impl Capturer {
    pub fn new(id: u32) -> Result<Self> {
        dpi_aware();
        #[cfg(not(target_os = "linux"))]
        let monitor = Monitor::all()?
            .into_iter()
            .find(|m| m.id().ok() == Some(id))
            .context("The selected display is no longer connected")?;
        Ok(Self {
            #[cfg(target_os = "macos")]
            stream: sck::Stream::open(monitor.id()?, (MAX_WIDTH, MAX_HEIGHT)).ok(),
            #[cfg(not(target_os = "linux"))]
            monitor,
            #[cfg(target_os = "linux")]
            linux: linux::Screen::open(id)?,
            resizer: fast_image_resize::Resizer::new(),
            last: None,
            damage: None,
        })
    }
    /// Whether screens come from a stream that says when they change.
    pub fn streaming(&self) -> bool {
        #[cfg(target_os = "macos")]
        return self.stream.is_some();
        #[cfg(target_os = "linux")]
        return true;
        #[cfg(windows)]
        false
    }
    /// How screens are captured, for logs and measurements.
    pub fn backend(&self) -> &'static str {
        #[cfg(target_os = "linux")]
        return self.linux.backend();
        #[cfg(not(target_os = "linux"))]
        if self.streaming() {
            "stream"
        } else {
            "pictures"
        }
    }
    /// The screen, changed or not.
    pub fn capture(&mut self) -> Result<Frame> {
        match self.capture_changed()? {
            Some(frame) => Ok(frame),
            None => self.last.clone().context("No screen yet"),
        }
    }
    /// What changed in the screen `capture_changed` last returned, in its
    /// pixels, where the system said. `None` when it did not, or when the
    /// whole screen may have changed.
    pub fn damage(&self) -> Option<&[Rect]> {
        self.damage.as_deref()
    }
    /// The screen if it changed since the last call.
    pub fn capture_changed(&mut self) -> Result<Option<Frame>> {
        self.damage = None;
        #[cfg(target_os = "macos")]
        if let Some(stream) = &self.stream {
            match stream.next() {
                Ok(None) if self.last.is_some() => return Ok(None),
                Ok(Some(frame)) => {
                    self.last = Some(frame.clone());
                    return Ok(Some(frame));
                }
                // Stopped, as when the display went away: ask for pictures
                // instead, which says what is wrong if that fails too.
                Ok(None) | Err(_) => self.stream = None,
            }
        }
        #[cfg(target_os = "linux")]
        {
            let Some(raw) = self.linux.next()? else {
                return Ok(None);
            };
            let (frame, scale) = self.fit(raw.width, raw.height, raw.rgba)?;
            self.damage = raw.damage.map(|rects| {
                rects
                    .iter()
                    .map(|r| scaled(*r, scale, frame.width, frame.height))
                    .collect()
            });
            self.last = Some(frame.clone());
            Ok(Some(frame))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let (width, height, rgba) = capture_pixels(&self.monitor)?;
            let frame = self.fit(width, height, rgba)?.0;
            self.last = Some(frame.clone());
            Ok(Some(frame))
        }
    }
    /// The screen at no more than the size it is sent at, and how much it
    /// was shrunk.
    fn fit(&mut self, width: u32, height: u32, rgba: Vec<u8>) -> Result<(Frame, f64)> {
        if width <= MAX_WIDTH && height <= MAX_HEIGHT {
            return Ok((
                Frame {
                    width,
                    height,
                    rgba,
                },
                1.0,
            ));
        }
        // A 5K iMac screen shrunk with the image crate took 140 ms of a
        // 2020 i5, which by itself held Boundary to about six screens a
        // second. The same filter with SIMD takes a few milliseconds.
        let scale = (MAX_WIDTH as f64 / width as f64).min(MAX_HEIGHT as f64 / height as f64);
        let (w, h) = (
            ((width as f64 * scale).round() as u32).max(1),
            ((height as f64 * scale).round() as u32).max(1),
        );
        use fast_image_resize::{FilterType, PixelType, ResizeAlg, ResizeOptions, images::Image};
        let src = Image::from_vec_u8(width, height, rgba, PixelType::U8x4)?;
        let mut dst = Image::new(w, h, PixelType::U8x4);
        self.resizer.resize(
            &src,
            &mut dst,
            &ResizeOptions::new()
                .resize_alg(ResizeAlg::Convolution(FilterType::Bilinear))
                .use_alpha(false),
        )?;
        Ok((
            Frame {
                width: w,
                height: h,
                rgba: dst.into_vec(),
            },
            scale,
        ))
    }
}

/// A changed area of a screen, in the pixels of the same screen shrunk by
/// `scale`: rounded outward, and a pixel wider each way, since the filter
/// blends each pixel with its neighbours.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn scaled(r: Rect, scale: f64, width: u32, height: u32) -> Rect {
    if scale >= 1.0 {
        return r;
    }
    let x0 = ((r.x as f64 * scale).floor() as u32).saturating_sub(1);
    let y0 = ((r.y as f64 * scale).floor() as u32).saturating_sub(1);
    let x1 = (((r.x + r.width) as f64 * scale).ceil() as u32 + 1).min(width);
    let y1 = (((r.y + r.height) as f64 * scale).ceil() as u32 + 1).min(height);
    Rect {
        x: x0,
        y: y0,
        width: x1.saturating_sub(x0),
        height: y1.saturating_sub(y0),
    }
}

struct NativeDesktop {
    screen: Capturer,
    enigo: Option<Enigo>,
    buttons: Vec<Button>,
    keys: Vec<Key>,
    /// Input through the Wayland RemoteDesktop portal, granted with the
    /// screen.
    #[cfg(target_os = "linux")]
    remote: Option<std::sync::Arc<linux::portal::Remote>>,
    _awake: Awake,
}

/// Keeps the screen on while a helper is connected. A Mac nobody is at shows
/// its lock screen, which switches the display off thirty seconds after
/// anything wakes it, and a sleeping display captures as black: the helper
/// watched a black screen until their own input woke it. `caffeinate` holds
/// the assertion, is tied to this process so a crash cannot leave it behind,
/// and is stopped when the session lets go of the desktop.
struct Awake(Option<std::process::Child>);
impl Awake {
    fn hold() -> Self {
        #[cfg(target_os = "macos")]
        {
            let pid = std::process::id().to_string();
            Self(
                std::process::Command::new("/usr/bin/caffeinate")
                    .args(["-d", "-u", "-w", &pid])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .ok(),
            )
        }
        #[cfg(not(target_os = "macos"))]
        Self(None)
    }
}
impl Drop for Awake {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl NativeDesktop {
    fn injector(&mut self) -> Result<&mut Enigo> {
        ensure!(
            input_permission(),
            "Allow this app in System Settings > Privacy & Security > Accessibility to use control"
        );
        if self.enigo.is_none() {
            self.enigo = Some(Enigo::new(&input_settings())?);
        }
        self.enigo.as_mut().context("Input is unavailable")
    }
    /// Where a pointer at `x`, `y` across the shared screen goes, in the
    /// coordinates the injector takes.
    fn pointer_at(&mut self, x: f32, y: f32) -> Result<(i32, i32)> {
        let at = |origin: i32, size: u32, f: f32| {
            origin + (f * size.saturating_sub(1) as f32).round() as i32
        };
        #[cfg(target_os = "linux")]
        {
            if let Some(area) = self.screen.linux.area() {
                return Ok((at(area.x, area.width, x), at(area.y, area.height, y)));
            }
            // A wlroots desktop: the virtual pointer spans its main output.
            let (w, h) = self.injector()?.main_display()?;
            Ok((at(0, w.max(0) as u32, x), at(0, h.max(0) as u32, y)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // xcap reports macOS display bounds in points, matching CGEvent coordinates.
            let m = &self.screen.monitor;
            Ok((at(m.x()?, m.width()?, x), at(m.y()?, m.height()?, y)))
        }
    }
    /// Input through the Wayland RemoteDesktop portal, where this session
    /// has one.
    #[cfg(target_os = "linux")]
    fn portal(&mut self, input: &Input) -> Option<Result<()>> {
        let remote = self.remote.clone()?;
        Some(match input {
            Input::Move { x, y } => remote.move_to(*x, *y),
            Input::Button { button, down } => remote.button(*button, *down),
            Input::Key { key, down } => remote.keysym(linux_keysym(*key), *down),
            Input::Text(text) => remote.text(text),
            Input::Scroll { lines } => remote.scroll(*lines),
            Input::Release => Ok(()),
        })
    }
}
/// How the injector is set up. On Linux each session gets one kind of
/// input: enigo sends every event down every connection it made, so on a
/// Wayland desktop it would also type into Xwayland's own idea of focus.
fn input_settings() -> Settings {
    #[allow(unused_mut)]
    let mut settings = Settings {
        open_prompt_to_get_permissions: false,
        ..Settings::default()
    };
    #[cfg(target_os = "linux")]
    {
        // A name that cannot connect turns that kind off.
        const NOWHERE: &str = "deskvnc-input-off";
        match linux::kind() {
            linux::Kind::X11 => settings.wayland_display = Some(NOWHERE.into()),
            linux::Kind::Wayland => settings.x11_display = Some(NOWHERE.into()),
        }
        // enigo delays each X11 click by this many milliseconds on the
        // server, by default 12. Keys it maps for a character still get the
        // pause they need.
        settings.linux_delay = 0;
    }
    settings
}
#[cfg(target_os = "linux")]
fn linux_keysym(key: Key) -> u32 {
    match key {
        Key::Enter => 0xff0d,
        Key::Tab => 0xff09,
        Key::Escape => 0xff1b,
        Key::Backspace => 0xff08,
        Key::Delete => 0xffff,
        Key::Left => 0xff51,
        Key::Up => 0xff52,
        Key::Right => 0xff53,
        Key::Down => 0xff54,
        Key::Home => 0xff50,
        Key::End => 0xff57,
        Key::PageUp => 0xff55,
        Key::PageDown => 0xff56,
        Key::Shift => 0xffe1,
        Key::Control => 0xffe3,
        Key::Alt => 0xffe9,
        Key::Meta => 0xffeb,
        Key::Space => 0x20,
        Key::Letter(c) => linux::keysym(c),
    }
}
impl Desktop for NativeDesktop {
    fn capture(&mut self) -> Result<Frame> {
        on_input_desktop();
        self.screen.capture()
    }
    fn capture_changed(&mut self) -> Result<Option<Frame>> {
        on_input_desktop();
        self.screen.capture_changed()
    }
    fn damage(&self) -> Option<Vec<Rect>> {
        self.screen.damage().map(<[Rect]>::to_vec)
    }
    fn input(&mut self, input: Input) -> Result<()> {
        input.validate()?;
        on_input_desktop();
        match &input {
            Input::Button { button, down } => {
                self.buttons.retain(|b| b != button);
                if *down {
                    self.buttons.push(*button);
                }
            }
            Input::Key { key, down } => {
                self.keys.retain(|k| k != key);
                if *down {
                    self.keys.push(*key);
                }
            }
            _ => {}
        }
        #[cfg(target_os = "linux")]
        if let Some(done) = self.portal(&input) {
            return done;
        }
        match input {
            Input::Move { x, y } => {
                let (px, py) = self.pointer_at(x, y)?;
                self.injector()?.move_mouse(px, py, Coordinate::Abs)?;
            }
            Input::Button { button, down } => {
                self.injector()?
                    .button(native_button(button), direction(down))?;
            }
            Input::Key { key, down } => {
                self.injector()?.key(native_key(key), direction(down))?;
            }
            Input::Text(text) => self.injector()?.text(&text)?,
            Input::Scroll { lines } => self.injector()?.scroll(lines, Axis::Vertical)?,
            Input::Release => self.release(),
        }
        Ok(())
    }
    fn release(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(remote) = self.remote.clone() {
            for button in self.buttons.drain(..) {
                let _ = remote.button(button, false);
            }
            for key in self.keys.drain(..).rev() {
                let _ = remote.keysym(linux_keysym(key), false);
            }
            return;
        }
        if let Some(enigo) = self.enigo.as_mut() {
            for button in self.buttons.drain(..) {
                let _ = enigo.button(native_button(button), Direction::Release);
            }
            for key in self.keys.drain(..).rev() {
                let _ = enigo.key(native_key(key), Direction::Release);
            }
        }
    }
}
impl Drop for NativeDesktop {
    fn drop(&mut self) {
        self.release();
    }
}
fn direction(down: bool) -> Direction {
    if down {
        Direction::Press
    } else {
        Direction::Release
    }
}
fn native_button(button: Button) -> enigo::Button {
    match button {
        Button::Left => enigo::Button::Left,
        Button::Middle => enigo::Button::Middle,
        Button::Right => enigo::Button::Right,
    }
}
fn native_key(key: Key) -> enigo::Key {
    use enigo::Key as E;
    match key {
        Key::Enter => E::Return,
        Key::Tab => E::Tab,
        Key::Escape => E::Escape,
        Key::Backspace => E::Backspace,
        Key::Delete => E::Delete,
        Key::Left => E::LeftArrow,
        Key::Right => E::RightArrow,
        Key::Up => E::UpArrow,
        Key::Down => E::DownArrow,
        Key::Home => E::Home,
        Key::End => E::End,
        Key::PageUp => E::PageUp,
        Key::PageDown => E::PageDown,
        Key::Shift => E::Shift,
        Key::Control => E::Control,
        Key::Alt => E::Alt,
        Key::Meta => E::Meta,
        Key::Space => E::Space,
        Key::Letter(c) => E::Unicode(c),
    }
}
#[cfg(target_os = "macos")]
mod permissions {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGPreflightScreenCaptureAccess() -> bool;
        fn CGRequestScreenCaptureAccess() -> bool;
    }
    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn AXIsProcessTrusted() -> bool;
    }
    pub fn screen() -> bool {
        // These OS queries have no pointer arguments or caller preconditions.
        unsafe { CGPreflightScreenCaptureAccess() }
    }
    pub fn request() {
        unsafe {
            CGRequestScreenCaptureAccess();
        }
    }
    pub fn input() -> bool {
        unsafe { AXIsProcessTrusted() }
    }
}
pub fn screen_permission() -> bool {
    #[cfg(target_os = "macos")]
    {
        permissions::screen()
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}
pub fn input_permission() -> bool {
    #[cfg(target_os = "macos")]
    {
        permissions::input()
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}
pub fn request_screen_permission() {
    #[cfg(target_os = "macos")]
    permissions::request();
}
pub fn open_input_settings() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
            .spawn()?;
    }
    Ok(())
}
