use anyhow::{Context, Result, ensure};
use boundary_session::{Button, Desktop, Frame, Input, Key};
use enigo::{Axis, Coordinate, Direction, Enigo, Keyboard, Mouse, Settings};
use xcap::Monitor;

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
    dpi_aware();
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
pub fn open(id: u32) -> Result<Box<dyn Desktop>> {
    dpi_aware();
    ensure!(
        screen_permission(),
        "Allow this app in System Settings > Privacy & Security > Screen & System Audio Recording, then reopen the app"
    );
    Ok(Box::new(NativeDesktop {
        screen: Capturer::new(id)?,
        enigo: None,
        buttons: Vec::new(),
        keys: Vec::new(),
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
#[cfg(not(target_os = "macos"))]
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
    monitor: Monitor,
    resizer: fast_image_resize::Resizer,
    /// A ScreenCaptureKit stream, where one could be started.
    #[cfg(target_os = "macos")]
    stream: Option<sck::Stream>,
    /// The last screen, for a caller that wants one whether or not it changed.
    last: Option<Frame>,
}
impl Capturer {
    pub fn new(id: u32) -> Result<Self> {
        dpi_aware();
        let monitor = Monitor::all()?
            .into_iter()
            .find(|m| m.id().ok() == Some(id))
            .context("The selected display is no longer connected")?;
        Ok(Self {
            #[cfg(target_os = "macos")]
            stream: sck::Stream::open(monitor.id()?, (MAX_WIDTH, MAX_HEIGHT)).ok(),
            monitor,
            resizer: fast_image_resize::Resizer::new(),
            last: None,
        })
    }
    /// Whether screens come from a ScreenCaptureKit stream.
    pub fn streaming(&self) -> bool {
        #[cfg(target_os = "macos")]
        return self.stream.is_some();
        #[cfg(not(target_os = "macos"))]
        false
    }
    /// The screen, changed or not.
    pub fn capture(&mut self) -> Result<Frame> {
        match self.capture_changed()? {
            Some(frame) => Ok(frame),
            None => self.last.clone().context("No screen yet"),
        }
    }
    /// The screen if it changed since the last call.
    pub fn capture_changed(&mut self) -> Result<Option<Frame>> {
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
        let frame = self.grab()?;
        self.last = Some(frame.clone());
        Ok(Some(frame))
    }
    fn grab(&mut self) -> Result<Frame> {
        let (width, height, rgba) = capture_pixels(&self.monitor)?;
        if width <= MAX_WIDTH && height <= MAX_HEIGHT {
            return Ok(Frame {
                width,
                height,
                rgba,
            });
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
        Ok(Frame {
            width: w,
            height: h,
            rgba: dst.into_vec(),
        })
    }
}

struct NativeDesktop {
    screen: Capturer,
    enigo: Option<Enigo>,
    buttons: Vec<Button>,
    keys: Vec<Key>,
}
impl NativeDesktop {
    fn injector(&mut self) -> Result<&mut Enigo> {
        ensure!(
            input_permission(),
            "Allow this app in System Settings > Privacy & Security > Accessibility to use control"
        );
        if self.enigo.is_none() {
            self.enigo = Some(Enigo::new(&Settings {
                open_prompt_to_get_permissions: false,
                ..Settings::default()
            })?);
        }
        self.enigo.as_mut().context("Input is unavailable")
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
    fn input(&mut self, input: Input) -> Result<()> {
        input.validate()?;
        on_input_desktop();
        match input {
            Input::Move { x, y } => {
                // xcap reports macOS display bounds in points, matching CGEvent coordinates.
                let px = self.screen.monitor.x()?
                    + (x * self.screen.monitor.width()?.saturating_sub(1) as f32).round() as i32;
                let py = self.screen.monitor.y()?
                    + (y * self.screen.monitor.height()?.saturating_sub(1) as f32).round() as i32;
                self.injector()?.move_mouse(px, py, Coordinate::Abs)?;
            }
            Input::Button { button, down } => {
                self.injector()?
                    .button(native_button(button), direction(down))?;
                self.buttons.retain(|b| *b != button);
                if down {
                    self.buttons.push(button);
                }
            }
            Input::Key { key, down } => {
                self.injector()?.key(native_key(key), direction(down))?;
                self.keys.retain(|k| *k != key);
                if down {
                    self.keys.push(key);
                }
            }
            Input::Text(text) => self.injector()?.text(&text)?,
            Input::Scroll { lines } => self.injector()?.scroll(lines, Axis::Vertical)?,
            Input::Release => self.release(),
        }
        Ok(())
    }
    fn release(&mut self) {
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
