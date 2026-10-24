//! Wayland screens and input through xdg-desktop-portal.
//!
//! Wayland lets no program read the screen or move the pointer by itself. The
//! portal asks the person once, then hands over a PipeWire stream that sends a
//! screen each time the compositor draws one, and, where the desktop has the
//! RemoteDesktop portal (GNOME, KDE), takes pointer and key events for the
//! same session. The portal returns a restore token with each grant; keeping
//! it lets an unattended computer share again without anyone at it, where the
//! desktop allows that (GNOME and KDE do; wlroots chooses by its own config).
use super::{Raw, keysym};
use anyhow::{Context, Result, anyhow, bail, ensure};
use ashpd::desktop::remote_desktop::{
    Axis, DeviceType, KeyState, RemoteDesktop, SelectDevicesOptions, StartOptions,
};
use ashpd::desktop::screencast::{
    CursorMode, OpenPipeWireRemoteOptions, Screencast, SelectSourcesOptions, SourceType,
    StartCastOptions, Stream as PortalStream,
};
use ashpd::desktop::{PersistMode, Session};
use ashpd::enumflags2::BitFlags;
use boundary_session::Button;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// How long the person has to answer the sharing prompt.
const ANSWER: Duration = Duration::from_secs(120);
/// How long a capture waits for a new screen before saying nothing changed.
const WAIT: Duration = Duration::from_millis(8);

fn block_on<T>(future: impl Future<Output = Result<T, ashpd::Error>>) -> Result<T> {
    async_io::block_on(future).map_err(|e| anyhow!("{e}"))
}
async fn within<T>(
    limit: Duration,
    future: impl Future<Output = Result<T, ashpd::Error>>,
) -> Result<T, ashpd::Error> {
    futures_lite::future::or(future, async {
        async_io::Timer::after(limit).await;
        Err(ashpd::Error::Portal(ashpd::PortalError::Failed(
            "Nobody answered the sharing prompt".into(),
        )))
    })
    .await
}

/// Where the portal's restore token is kept between runs.
fn token_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("deskvnc").join("portal-restore-token"))
}
fn load_token() -> Option<String> {
    let token = std::fs::read_to_string(token_path()?).ok()?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}
fn save_token(token: Option<&str>) {
    let (Some(path), Some(token)) = (token_path(), token) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Only this user may read it: it lets a program share this screen.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
    {
        let _ = file.write_all(token.as_bytes());
    }
}

/// Input to the shared screen through the RemoteDesktop portal.
pub(crate) struct Remote {
    portal: RemoteDesktop,
    session: Session<RemoteDesktop>,
    node: u32,
    /// The stream's size in the compositor's logical pixels, which is what
    /// absolute pointer positions are measured in.
    size: Mutex<Option<(f64, f64)>>,
}
impl Remote {
    pub fn move_to(&self, x: f32, y: f32) -> Result<()> {
        let (w, h) = self
            .size
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .context("The shared screen has no size yet")?;
        let (px, py) = (x as f64 * (w - 1.0).max(0.0), y as f64 * (h - 1.0).max(0.0));
        block_on(self.portal.notify_pointer_motion_absolute(
            &self.session,
            self.node,
            px,
            py,
            Default::default(),
        ))
    }
    pub fn button(&self, button: Button, down: bool) -> Result<()> {
        // Linux evdev codes, BTN_LEFT and on.
        let code = match button {
            Button::Left => 0x110,
            Button::Right => 0x111,
            Button::Middle => 0x112,
        };
        block_on(self.portal.notify_pointer_button(
            &self.session,
            code,
            state(down),
            Default::default(),
        ))
    }
    pub fn keysym(&self, keysym: u32, down: bool) -> Result<()> {
        block_on(self.portal.notify_keyboard_keysym(
            &self.session,
            keysym as i32,
            state(down),
            Default::default(),
        ))
    }
    /// Each character as a key press and release. A character the keyboard
    /// layout has no key for is dropped by GNOME and KDE, which only map
    /// keysyms onto keys they already have.
    pub fn text(&self, text: &str) -> Result<()> {
        for c in text.chars() {
            let sym = keysym(c);
            self.keysym(sym, true)?;
            self.keysym(sym, false)?;
        }
        Ok(())
    }
    pub fn scroll(&self, lines: i32) -> Result<()> {
        block_on(self.portal.notify_pointer_axis_discrete(
            &self.session,
            Axis::Vertical,
            lines,
            Default::default(),
        ))
    }
}
fn state(down: bool) -> KeyState {
    if down {
        KeyState::Pressed
    } else {
        KeyState::Released
    }
}

enum Held {
    Remote(Arc<Remote>),
    Cast(#[allow(dead_code)] Screencast, Session<Screencast>),
}

pub(crate) struct Screen {
    held: Held,
    video: Video,
}
impl Screen {
    /// Ask the portal for the screen, and for input where it offers that.
    pub fn open() -> Result<Self> {
        let token = load_token();
        let (held, fd, stream) = match block_on(remote(token.as_deref())) {
            Ok(found) => found,
            // No RemoteDesktop portal, as on wlroots: the screen alone.
            Err(e) if e.to_string().contains("RemoteDesktop unavailable") => {
                block_on(cast(token.as_deref()))?
            }
            Err(e) => return Err(e),
        };
        let size = stream
            .size()
            .map(|(w, h)| (w as f64, h as f64))
            .filter(|(w, h)| *w > 0.0 && *h > 0.0);
        let video = Video::start(fd, stream.pipe_wire_node_id())?;
        if let Held::Remote(remote) = &held {
            let mut known = remote.size.lock().unwrap_or_else(|e| e.into_inner());
            *known = size.or_else(|| video.size().map(|(w, h)| (w as f64, h as f64)));
        }
        Ok(Self { held, video })
    }
    pub fn remote(&self) -> Option<Arc<Remote>> {
        match &self.held {
            Held::Remote(r) => Some(r.clone()),
            Held::Cast(..) => None,
        }
    }
    pub fn next(&mut self) -> Result<Option<Raw>> {
        let raw = self.video.next()?;
        if let (Some(raw), Held::Remote(remote)) = (&raw, &self.held) {
            let mut size = remote.size.lock().unwrap_or_else(|e| e.into_inner());
            size.get_or_insert((raw.width as f64, raw.height as f64));
        }
        Ok(raw)
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        self.video.stop();
        let _ = match &self.held {
            Held::Remote(r) => async_io::block_on(r.session.close()),
            Held::Cast(_, session) => async_io::block_on(session.close()),
        };
    }
}

async fn cursor(cast: &Screencast) -> CursorMode {
    // DeskVNC draws its own pointer, which moves with no lag at all.
    match cast.available_cursor_modes().await {
        Ok(modes) if modes.contains(CursorMode::Hidden) => CursorMode::Hidden,
        _ => CursorMode::Embedded,
    }
}
fn sources() -> BitFlags<SourceType> {
    BitFlags::from_flag(SourceType::Monitor)
}

/// One RemoteDesktop session with the screen cast on it.
async fn remote(token: Option<&str>) -> Result<(Held, OwnedFd, PortalStream), ashpd::Error> {
    let unavailable = || {
        ashpd::Error::Portal(ashpd::PortalError::NotFound(
            "RemoteDesktop unavailable".into(),
        ))
    };
    let portal = RemoteDesktop::new().await.map_err(|_| unavailable())?;
    let devices = portal
        .available_device_types()
        .await
        .map_err(|_| unavailable())?;
    if !devices.contains(DeviceType::Pointer) || !devices.contains(DeviceType::Keyboard) {
        return Err(unavailable());
    }
    let cast = Screencast::new().await?;
    let session = portal.create_session(Default::default()).await?;
    portal
        .select_devices(
            &session,
            SelectDevicesOptions::default()
                .set_devices(DeviceType::Pointer | DeviceType::Keyboard)
                .set_persist_mode(PersistMode::ExplicitlyRevoked)
                .set_restore_token(token),
        )
        .await?
        .response()?;
    cast.select_sources(
        &session,
        SelectSourcesOptions::default()
            .set_cursor_mode(cursor(&cast).await)
            .set_sources(sources())
            .set_multiple(false),
    )
    .await?
    .response()?;
    let started = within(
        ANSWER,
        portal.start(&session, None, StartOptions::default()),
    )
    .await?
    .response()?;
    save_token(started.restore_token());
    let stream = started.streams().first().cloned().ok_or_else(|| {
        ashpd::Error::Portal(ashpd::PortalError::Failed("No screen was shared".into()))
    })?;
    let fd = cast
        .open_pipe_wire_remote(&session, OpenPipeWireRemoteOptions::default())
        .await?;
    let remote = Remote {
        portal,
        session,
        node: stream.pipe_wire_node_id(),
        size: Mutex::new(None),
    };
    Ok((Held::Remote(Arc::new(remote)), fd, stream))
}

/// A screen cast session alone.
async fn cast(token: Option<&str>) -> Result<(Held, OwnedFd, PortalStream), ashpd::Error> {
    let cast = Screencast::new().await?;
    let session = cast.create_session(Default::default()).await?;
    cast.select_sources(
        &session,
        SelectSourcesOptions::default()
            .set_cursor_mode(cursor(&cast).await)
            .set_sources(sources())
            .set_multiple(false)
            .set_persist_mode(PersistMode::ExplicitlyRevoked)
            .set_restore_token(token),
    )
    .await?
    .response()?;
    let started = within(
        ANSWER,
        cast.start(&session, None, StartCastOptions::default()),
    )
    .await?
    .response()?;
    save_token(started.restore_token());
    let stream = started.streams().first().cloned().ok_or_else(|| {
        ashpd::Error::Portal(ashpd::PortalError::Failed("No screen was shared".into()))
    })?;
    let fd = cast
        .open_pipe_wire_remote(&session, OpenPipeWireRemoteOptions::default())
        .await?;
    Ok((Held::Cast(cast, session), fd, stream))
}

#[derive(Default)]
struct Shared {
    latest: Mutex<Latest>,
    ready: Condvar,
}
#[derive(Default)]
struct Latest {
    frame: Option<Raw>,
    size: Option<(u32, u32)>,
    stopped: Option<String>,
}

/// The PipeWire stream, on a thread of its own.
struct Video {
    shared: Arc<Shared>,
    quit: Option<pipewire::channel::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Video {
    fn start(fd: OwnedFd, node: u32) -> Result<Self> {
        let shared = Arc::new(Shared::default());
        let (quit, quit_rx) = pipewire::channel::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("pipewire".into())
                .spawn(move || {
                    let result = run(fd, node, shared.clone(), quit_rx, &ready_tx);
                    let mut latest = shared.latest.lock().unwrap_or_else(|e| e.into_inner());
                    latest.stopped = Some(match result {
                        Ok(()) => "Screen sharing stopped".into(),
                        Err(e) => format!("{e:#}"),
                    });
                    shared.ready.notify_all();
                    let _ = ready_tx.send(());
                })?
        };
        let video = Self {
            shared,
            quit: Some(quit),
            thread: Some(thread),
        };
        // The stream is connected once the loop runs; the first screen follows.
        let _ = ready_rx.recv_timeout(Duration::from_secs(5));
        let latest = video
            .shared
            .latest
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (latest, _) = video
            .shared
            .ready
            .wait_timeout_while(latest, Duration::from_secs(3), |l| {
                l.frame.is_none() && l.stopped.is_none()
            })
            .unwrap_or_else(|e| e.into_inner());
        if let Some(why) = &latest.stopped {
            bail!("{why}");
        }
        ensure!(latest.frame.is_some(), "The shared screen sent no picture");
        drop(latest);
        Ok(video)
    }
    fn size(&self) -> Option<(u32, u32)> {
        self.shared
            .latest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .size
    }
    fn next(&self) -> Result<Option<Raw>> {
        let latest = self.shared.latest.lock().unwrap_or_else(|e| e.into_inner());
        let (mut latest, _) = self
            .shared
            .ready
            .wait_timeout_while(latest, WAIT, |l| l.frame.is_none() && l.stopped.is_none())
            .unwrap_or_else(|e| e.into_inner());
        if let Some(frame) = latest.frame.take() {
            return Ok(Some(frame));
        }
        if let Some(why) = &latest.stopped {
            bail!("{why}");
        }
        Ok(None)
    }
    fn stop(&mut self) {
        if let Some(quit) = self.quit.take() {
            let _ = quit.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Drop for Video {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(
    fd: OwnedFd,
    node: u32,
    shared: Arc<Shared>,
    quit: pipewire::channel::Receiver<()>,
    ready: &std::sync::mpsc::Sender<()>,
) -> Result<()> {
    use pipewire::spa;
    use pipewire::spa::param::ParamType;
    use pipewire::spa::param::format::{FormatProperties, MediaSubtype, MediaType};
    use pipewire::spa::param::video::{VideoFormat, VideoInfoRaw};
    use pipewire::spa::pod::{self, Pod, serialize::PodSerializer};
    use pipewire::spa::utils::{Direction, Fraction, Rectangle, SpaTypes};
    use pipewire::stream::{StreamFlags, StreamRc};

    pipewire::init();
    let main_loop = pipewire::main_loop::MainLoopRc::new(None)?;
    let context = pipewire::context::ContextRc::new(&main_loop, None)?;
    let core = context.connect_fd_rc(fd, None)?;
    let stream = StreamRc::new(
        core.clone(),
        "deskvnc-support",
        pipewire::properties::properties! {
            *pipewire::keys::MEDIA_TYPE => "Video",
            *pipewire::keys::MEDIA_CATEGORY => "Capture",
            *pipewire::keys::MEDIA_ROLE => "Screen",
        },
    )?;
    let on_frame = shared.clone();
    let on_state = shared.clone();
    let _listener = stream
        .add_local_listener_with_user_data(VideoInfoRaw::new())
        .state_changed(move |_, _, _, new| {
            if let pipewire::stream::StreamState::Error(e) = new {
                let mut latest = on_state.latest.lock().unwrap_or_else(|e| e.into_inner());
                latest.stopped = Some(format!("Screen sharing failed: {e}"));
                on_state.ready.notify_all();
            }
        })
        .param_changed(|_, info, id, param| {
            let Some(param) = param else { return };
            if id != ParamType::Format.as_raw() {
                return;
            }
            if let Ok((MediaType::Video, MediaSubtype::Raw)) =
                spa::param::format_utils::parse_format(param)
            {
                let _ = info.parse(param);
            }
        })
        .process(move |stream, info| {
            // Take the newest buffer and hand older ones straight back.
            let mut newest = None;
            while let Some(buffer) = stream.dequeue_buffer() {
                newest = Some(buffer);
            }
            let Some(mut buffer) = newest else { return };
            let size = info.size();
            let (width, height) = (size.width, size.height);
            let format = info.format();
            let Some(data) = buffer.datas_mut().first_mut() else {
                return;
            };
            let chunk = data.chunk();
            let (offset, chunk_size) = (chunk.offset() as usize, chunk.size() as usize);
            let stride = match chunk.stride() {
                s if s > 0 => s as usize,
                _ => width as usize * 4,
            };
            // An empty chunk only says the cursor moved, or nothing at all.
            if chunk_size == 0 || width == 0 || height == 0 {
                return;
            }
            let Some(bytes) = data.data() else {
                let mut latest = on_frame.latest.lock().unwrap_or_else(|e| e.into_inner());
                latest.stopped =
                    Some("The screen came as GPU buffers, which DeskVNC cannot read yet".into());
                on_frame.ready.notify_all();
                return;
            };
            let row = width as usize * 4;
            if stride < row || bytes.len() < offset + stride * (height as usize - 1) + row {
                return;
            }
            let mut rgba = vec![0u8; row * height as usize];
            for (y, dst) in rgba.chunks_exact_mut(row).enumerate() {
                let src = &bytes[offset + y * stride..offset + y * stride + row];
                match format {
                    VideoFormat::BGRx | VideoFormat::BGRA => super::bgrx_to_rgba(src, dst),
                    VideoFormat::RGBx | VideoFormat::RGBA => {
                        dst.copy_from_slice(src);
                        dst.as_chunks_mut::<4>()
                            .0
                            .iter_mut()
                            .for_each(|p| p[3] = 255);
                    }
                    _ => return,
                }
            }
            let mut latest = on_frame.latest.lock().unwrap_or_else(|e| e.into_inner());
            latest.size = Some((width, height));
            latest.frame = Some(Raw {
                width,
                height,
                rgba,
                damage: None,
            });
            on_frame.ready.notify_all();
        })
        .register()?;

    let format = pod::object!(
        SpaTypes::ObjectParamFormat,
        ParamType::EnumFormat,
        pod::property!(FormatProperties::MediaType, Id, MediaType::Video),
        pod::property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        pod::property!(
            FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            VideoFormat::BGRx,
            VideoFormat::BGRx,
            VideoFormat::BGRA,
            VideoFormat::RGBx,
            VideoFormat::RGBA
        ),
        pod::property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            Rectangle {
                width: 1920,
                height: 1080
            },
            Rectangle {
                width: 1,
                height: 1
            },
            Rectangle {
                width: 8192,
                height: 8192
            }
        ),
        pod::property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            Fraction { num: 60, denom: 1 },
            Fraction { num: 0, denom: 1 },
            Fraction { num: 360, denom: 1 }
        ),
    );
    let bytes = PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pod::Value::Object(format),
    )
    .map_err(|e| anyhow!("{e:?}"))?
    .0
    .into_inner();
    let mut params = [Pod::from_bytes(&bytes).context("Bad stream format")?];
    stream.connect(
        Direction::Input,
        Some(node),
        StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;
    let _quit = quit.attach(main_loop.loop_(), {
        let main_loop = main_loop.clone();
        move |()| main_loop.quit()
    });
    let _ = ready.send(());
    main_loop.run();
    let _ = stream.disconnect();
    Ok(())
}
