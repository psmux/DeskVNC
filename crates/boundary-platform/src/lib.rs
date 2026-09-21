use anyhow::{Context, Result, ensure};
use boundary_session::{Button, Desktop, Frame, Input, Key};
use enigo::{Axis, Coordinate, Direction, Enigo, Keyboard, Mouse, Settings};
use xcap::Monitor;

#[derive(Clone)]
pub struct Display {
    pub id: u32,
    pub name: String,
}
pub fn displays() -> Result<Vec<Display>> {
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
    ensure!(
        screen_permission(),
        "Allow Boundary in System Settings > Privacy & Security > Screen & System Audio Recording, then reopen the app"
    );
    let monitor = Monitor::all()?
        .into_iter()
        .find(|m| m.id().ok() == Some(id))
        .context("The selected display is no longer connected")?;
    Ok(Box::new(NativeDesktop {
        monitor,
        enigo: None,
        buttons: Vec::new(),
        keys: Vec::new(),
    }))
}
struct NativeDesktop {
    monitor: Monitor,
    enigo: Option<Enigo>,
    buttons: Vec<Button>,
    keys: Vec<Key>,
}
impl NativeDesktop {
    fn injector(&mut self) -> Result<&mut Enigo> {
        ensure!(
            input_permission(),
            "Allow Boundary in System Settings > Privacy & Security > Accessibility to use control"
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
        let pixels = self
            .monitor
            .capture_image()
            .context("Screen capture failed. Check Screen Recording permission")?;
        let image = image::DynamicImage::ImageRgba8(pixels);
        let image = if image.width() > 1920 || image.height() > 1200 {
            image.resize(1920, 1200, image::imageops::FilterType::Triangle)
        } else {
            image
        };
        let image = image.into_rgba8();
        Ok(Frame {
            width: image.width(),
            height: image.height(),
            rgba: image.into_raw(),
        })
    }
    fn input(&mut self, input: Input) -> Result<()> {
        input.validate()?;
        match input {
            Input::Move { x, y } => {
                // xcap reports macOS display bounds in points, matching CGEvent coordinates.
                let px = self.monitor.x()?
                    + (x * self.monitor.width()?.saturating_sub(1) as f32).round() as i32;
                let py = self.monitor.y()?
                    + (y * self.monitor.height()?.saturating_sub(1) as f32).round() as i32;
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
