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
use ashpd::desktop::inhibit::{InhibitFlags, InhibitOptions, InhibitProxy};
use ashpd::desktop::remote_desktop::{
    Axis, DeviceType, KeyState, RemoteDesktop, SelectDevicesOptions, StartOptions,
};
use ashpd::desktop::screencast::{
    CursorMode, OpenPipeWireRemoteOptions, Screencast, SelectSourcesOptions, SourceType,
    StartCastOptions, Stream as PortalStream,
};
use ashpd::desktop::{PersistMode, Request, Session};
use ashpd::enumflags2::BitFlags;
use boundary_session::Button;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long the person has to answer the sharing prompt.
const ANSWER: Duration = Duration::from_secs(120);
/// How long a capture waits for a new screen before saying nothing changed.
const WAIT: Duration = Duration::from_millis(8);
/// How long after the portal starts a session its input is taken.
const SETTLE: Duration = Duration::from_secs(1);
/// How long the first key's keyboard takes to be ready.
const PRIME: Duration = Duration::from_millis(300);
/// The left Shift keysym.
const SHIFT: i32 = 0xffe1;

fn block_on<T>(future: impl Future<Output = Result<T, ashpd::Error>>) -> Result<T> {
    async_io::block_on(future).map_err(portal_error)
}
/// The person chose Cancel in the desktop's sharing prompt.
#[derive(Debug)]
pub(crate) struct Declined;
impl std::fmt::Display for Declined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The sharing prompt was cancelled")
    }
}
impl std::error::Error for Declined {}
/// A portal error, with a cancelled prompt kept apart from a portal that
/// failed, so the two are not explained the same way.
pub(crate) fn portal_error(e: ashpd::Error) -> anyhow::Error {
    match e {
        ashpd::Error::Response(ashpd::desktop::ResponseError::Cancelled) => Declined.into(),
        e => anyhow!("{e}"),
    }
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

/// Whether the screen is locked or blanked. GNOME refuses to start a remote
/// desktop or screen cast session then ("Session creation inhibited"), and
/// the portal passes that on as a bare failure with no reason, so this is
/// asked after the portal fails. GNOME's own screensaver reports a blank
/// screen as well as a locked one; logind's hint covers other desktops,
/// which set it on lock.
pub(crate) fn screen_asleep() -> bool {
    async_io::block_on(async {
        let Ok(session) = ashpd::zbus::Connection::session().await else {
            return false;
        };
        let gnome = session
            .call_method(
                Some("org.gnome.ScreenSaver"),
                "/org/gnome/ScreenSaver",
                Some("org.gnome.ScreenSaver"),
                "GetActive",
                &(),
            )
            .await
            .ok()
            .and_then(|reply| reply.body().deserialize::<bool>().ok());
        if gnome == Some(true) {
            return true;
        }
        let Ok(system) = ashpd::zbus::Connection::system().await else {
            return false;
        };
        system
            .call_method(
                Some("org.freedesktop.login1"),
                "/org/freedesktop/login1/session/auto",
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.login1.Session", "LockedHint"),
            )
            .await
            .ok()
            .and_then(|reply| {
                let value: ashpd::zvariant::OwnedValue = reply.body().deserialize().ok()?;
                bool::try_from(value).ok()
            })
            .unwrap_or(false)
    })
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
    /// What the person allowed. GNOME's prompt shares the screen alone
    /// unless "Allow Remote Interaction" is switched on.
    granted: BitFlags<DeviceType>,
    /// When the compositor takes events. GNOME dropped everything sent in
    /// about the first second after the session started.
    ready: Instant,
    /// Whether a key has been sent yet. See [`Remote::keysym`].
    typed: std::sync::atomic::AtomicBool,
}
impl Remote {
    /// Wait until the session takes events, or say why it never will.
    fn settle(&self, device: DeviceType) -> Result<()> {
        ensure!(
            self.granted.contains(device),
            "Control was not allowed. Share again and switch on Allow Remote Interaction in the sharing prompt"
        );
        if let Some(wait) = self.ready.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
        Ok(())
    }
    pub fn move_to(&self, x: f32, y: f32) -> Result<()> {
        self.settle(DeviceType::Pointer)?;
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
        self.settle(DeviceType::Pointer)?;
        block_on(self.portal.notify_pointer_button(
            &self.session,
            code,
            state(down),
            Default::default(),
        ))
    }
    pub fn keysym(&self, keysym: u32, down: bool) -> Result<()> {
        self.settle(DeviceType::Keyboard)?;
        // GNOME makes its virtual keyboard on the first key and drops the
        // keys that come in the next moment, which lost the first three to
        // ten characters typed. A Shift tap first takes that loss.
        if !self.typed.swap(true, std::sync::atomic::Ordering::Relaxed) {
            for down in [true, false] {
                block_on(self.portal.notify_keyboard_keysym(
                    &self.session,
                    SHIFT,
                    state(down),
                    Default::default(),
                ))?;
            }
            std::thread::sleep(PRIME);
        }
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
        self.settle(DeviceType::Pointer)?;
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
    /// Holds the screen awake while it is shared; see [`keep_awake`].
    _awake: Awake,
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
        let video = match Video::start(fd, stream.pipe_wire_node_id()) {
            Ok(video) => video,
            Err(e) => {
                // Dropping the session does not end it, and GNOME kept its
                // sharing indicator on until Support quit.
                close(&held);
                return Err(e);
            }
        };
        if let Held::Remote(remote) = &held {
            let mut known = remote.size.lock().unwrap_or_else(|e| e.into_inner());
            *known = size.or_else(|| video.size().map(|(w, h)| (w as f64, h as f64)));
        }
        Ok(Self {
            held,
            video,
            _awake: keep_awake(),
        })
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
        close(&self.held);
    }
}

/// What the inhibit asks the desktop to hold off: going idle, which blanks
/// the screen and on GNOME takes the shared screen away from the helper.
fn awake_flags() -> BitFlags<InhibitFlags> {
    BitFlags::from_flag(InhibitFlags::Idle)
}
/// gnome-session's flag for the same thing.
const GNOME_IDLE: u32 = 8;
const REASON: &str = "A helper is connected to this screen";

/// The app ID inhibits are held under. The portal works out the caller's ID
/// from its systemd scope, which an app started from a terminal, a file
/// manager or a service does not have, and then passes an empty one on.
/// gnome-session refuses that ("Application ID not specified") while the
/// portal still reports success, so the screen blanked anyway.
static APP_ID: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
/// Name the app for the desktop, once, before any screen is shared.
pub fn set_app_id(id: &'static str) {
    let _ = APP_ID.set(id);
}
fn app_id() -> &'static str {
    APP_ID.get().copied().unwrap_or("deskvnc")
}

/// The screen kept awake, until dropped.
struct Awake {
    portal: Option<Request<()>>,
    gnome: Option<(ashpd::zbus::Connection, u32)>,
}
impl Drop for Awake {
    fn drop(&mut self) {
        async_io::block_on(async {
            if let Some(request) = self.portal.take() {
                let _ = request.close().await;
            }
            if let Some((bus, cookie)) = self.gnome.take() {
                let _ = bus
                    .call_method(
                        Some("org.gnome.SessionManager"),
                        "/org/gnome/SessionManager",
                        Some("org.gnome.SessionManager"),
                        "Uninhibit",
                        &cookie,
                    )
                    .await;
            }
        });
    }
}

/// Ask the desktop not to go idle while a helper is connected. Input from a
/// helper with control counts as activity, but a helper who only watches
/// sends none, so a view only session ended once the person at the computer
/// stopped touching it and the screen blanked. Through the portal, and on
/// GNOME also with gnome-session directly under this app's ID, since the
/// portal's own request does nothing there when it cannot name the app.
fn keep_awake() -> Awake {
    async_io::block_on(async {
        let portal = async {
            InhibitProxy::new()
                .await?
                .inhibit(
                    None,
                    awake_flags(),
                    InhibitOptions::default().set_reason(REASON),
                )
                .await
        }
        .await
        .ok();
        // gnome-session lets the inhibit go when this connection closes, so
        // it is a connection of its own, held for as long as the inhibit.
        let gnome = async {
            let bus = ashpd::zbus::Connection::session().await.ok()?;
            let reply = bus
                .call_method(
                    Some("org.gnome.SessionManager"),
                    "/org/gnome/SessionManager",
                    Some("org.gnome.SessionManager"),
                    "Inhibit",
                    &(app_id(), 0u32, REASON, GNOME_IDLE),
                )
                .await
                .ok()?;
            let cookie: u32 = reply.body().deserialize().ok()?;
            Some((bus, cookie))
        }
        .await;
        Awake { portal, gnome }
    })
}
/// Ends the portal session, which takes GNOME's sharing indicator away.
fn close(held: &Held) {
    let _ = match held {
        Held::Remote(r) => async_io::block_on(r.session.close()),
        Held::Cast(_, session) => async_io::block_on(session.close()),
    };
}

/// Something the PipeWire stream was told that may mean the screen is gone.
#[derive(Debug)]
enum Seen<'a> {
    /// The stream moved to this state.
    State(&'a pipewire::stream::StreamState),
    /// The object with this id left the PipeWire graph.
    Removed(u32),
}
/// Why the shared screen is gone, or `None` while it may still send
/// pictures. GNOME removes the compositor's node, and leaves this stream
/// paused with nothing linked to it, when the screen locks, when the portal
/// session is closed and when the display changes mode. Waiting on it then
/// left the helper looking at the last picture for as long as the session
/// lasted.
fn gone(node: u32, seen: Seen) -> Option<String> {
    use pipewire::stream::StreamState;
    match seen {
        Seen::Removed(id) if id == node => Some(
            "The shared screen went away: the desktop locked, turned the screen off or changed the display. Share it again to go on".into(),
        ),
        Seen::Removed(_) => None,
        Seen::State(StreamState::Error(e)) => Some(format!("Screen sharing failed: {e}")),
        Seen::State(StreamState::Unconnected) => Some("Screen sharing stopped".into()),
        Seen::State(_) => None,
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
        granted: started.devices(),
        ready: Instant::now() + SETTLE,
        typed: Default::default(),
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

/// Records the first reason the screen stopped and wakes whoever waits for
/// a picture, so the session ends with that reason.
fn stop(shared: &Shared, why: Option<String>) {
    let Some(why) = why else { return };
    let mut latest = shared.latest.lock().unwrap_or_else(|e| e.into_inner());
    latest.stopped.get_or_insert(why);
    shared.ready.notify_all();
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
    let on_remove = shared.clone();
    let registry = core.get_registry_rc()?;
    let _registry = registry
        .add_listener_local()
        .global_remove(move |id| stop(&on_remove, gone(node, Seen::Removed(id))))
        .register();
    let _listener = stream
        .add_local_listener_with_user_data(VideoInfoRaw::new())
        .state_changed(move |_, _, _, new| stop(&on_state, gone(node, Seen::State(&new))))
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

#[cfg(test)]
mod tests {
    use super::*;
    use pipewire::stream::StreamState;

    #[test]
    fn a_shared_screen_holds_off_idle_and_nothing_else() {
        // Idle blanking took the screen away from a helper who only watched.
        // Suspend and logout stay the person's own business.
        assert_eq!(awake_flags(), BitFlags::from_flag(InhibitFlags::Idle));
        assert_eq!(GNOME_IDLE, InhibitFlags::Idle as u32);
    }

    #[test]
    fn the_inhibit_always_names_an_app() {
        // gnome-session refuses an inhibit with an empty app ID.
        assert!(!app_id().is_empty());
        set_app_id("deskvnc-support");
        assert_eq!(app_id(), "deskvnc-support");
    }

    #[test]
    fn the_screen_is_gone_when_the_compositor_node_leaves() {
        // What GNOME 46 did on lock and on a mode change: node 54 left the
        // graph and this stream was only paused.
        assert!(gone(54, Seen::Removed(54)).is_some());
        assert!(gone(54, Seen::State(&StreamState::Paused)).is_none());
        let shared = Shared::default();
        stop(&shared, gone(54, Seen::Removed(54)));
        let why = shared.latest.lock().unwrap().stopped.clone().unwrap();
        assert!(why.contains("went away"), "{why}");
    }

    #[test]
    fn other_objects_leaving_and_renegotiating_keep_the_screen() {
        assert!(gone(54, Seen::Removed(60)).is_none());
        assert!(gone(54, Seen::State(&StreamState::Connecting)).is_none());
        assert!(gone(54, Seen::State(&StreamState::Streaming)).is_none());
    }

    #[test]
    fn a_failed_or_unconnected_stream_stops_with_its_reason() {
        let failed = gone(54, Seen::State(&StreamState::Error("no memory".into())));
        assert_eq!(failed.as_deref(), Some("Screen sharing failed: no memory"));
        assert!(gone(54, Seen::State(&StreamState::Unconnected)).is_some());
    }

    #[test]
    fn the_first_reason_is_kept() {
        let shared = Shared::default();
        stop(&shared, gone(54, Seen::Removed(54)));
        stop(&shared, gone(54, Seen::State(&StreamState::Unconnected)));
        stop(&shared, None);
        let why = shared.latest.lock().unwrap().stopped.clone().unwrap();
        assert!(why.contains("went away"), "{why}");
    }
}
