//! Wayland screens and input through xdg-desktop-portal.
//!
//! Wayland lets no program read the screen or move the pointer by itself. The
//! portal asks the person once, then hands over a PipeWire stream that sends a
//! screen each time the compositor draws one, and, where the desktop has the
//! RemoteDesktop portal (GNOME, KDE), takes pointer and key events for the
//! same session. The portal returns a restore token with each grant; keeping
//! it lets an unattended computer share again without anyone at it, where the
//! desktop allows that (GNOME and KDE do; wlroots chooses by its own config).
//!
//! The same session carries the person's clipboard where the portal has its
//! Clipboard interface (version 1 on GNOME 50). GNOME then shows "Allow
//! Clipboard Access" in its prompt, on by default, and says in its Start
//! answer whether the person left it on.
use super::{Raw, keysym};
use anyhow::{Context, Result, anyhow, bail, ensure};
use ashpd::desktop::clipboard::{Clipboard, SetSelectionOptions};
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
/// Drop the saved grant, so the next session asks the person again.
fn forget_token() {
    if let Some(path) = token_path() {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(asked_path(&path));
    }
}
/// Beside the token: present when the grant it restores was given in a
/// prompt that asked for the clipboard. Support 0.34 saved tokens without
/// asking, so a token with no such file is from then.
fn asked_path(token: &std::path::Path) -> PathBuf {
    token.with_extension("clipboard")
}
/// Note that the grant just saved came from a prompt that asked for the
/// clipboard, or that it did not.
fn note_asked(asked: bool) {
    let Some(path) = token_path().map(|t| asked_path(&t)) else {
        return;
    };
    if asked {
        let _ = std::fs::write(path, b"asked\n");
    } else {
        let _ = std::fs::remove_file(path);
    }
}
fn grant_asked_clipboard() -> bool {
    token_path().is_some_and(|t| asked_path(&t).exists())
}

/// Why the screen shared now has no clipboard, when sharing again with the
/// prompt would give it one. Set each time a RemoteDesktop session starts.
static LEFT_OUT: Mutex<Option<&'static str>> = Mutex::new(None);
const OLD_GRANT: &str = "This computer's sharing permission is from an older version and does not include the clipboard. Share again and leave Allow Clipboard Access on to use it.";
const LEFT_OFF: &str = "This computer's sharing permission was given with Allow Clipboard Access off, so it does not include the clipboard. Share again and leave it on to use it.";
/// What to tell the person about a session's clipboard. Only a remembered
/// grant can be the reason: a prompt answered just now is what the person
/// chose. `asked` is whether this desktop's portal has a clipboard to ask
/// for, and `asked_before` whether the remembered grant's prompt asked for it.
fn left_out(
    restored: bool,
    asked: bool,
    enabled: bool,
    asked_before: bool,
) -> Option<&'static str> {
    if !restored || !asked || enabled {
        None
    } else if asked_before {
        Some(LEFT_OFF)
    } else {
        Some(OLD_GRANT)
    }
}
fn set_left_out(note: Option<&'static str>) {
    *LEFT_OUT.lock().unwrap_or_else(|e| e.into_inner()) = note;
}
/// See [`left_out`]: the line for the screen shared now, if any.
pub(crate) fn clipboard_left_out() -> Option<&'static str> {
    *LEFT_OUT.lock().unwrap_or_else(|e| e.into_inner())
}
/// Forget the remembered grant, so the next share shows the desktop's prompt.
pub(crate) fn forget_grant() {
    forget_token();
    set_left_out(None);
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
    /// The person's clipboard, when the portal has it and the person left
    /// Allow Clipboard Access on.
    clipboard: Option<Clip>,
}
impl Remote {
    /// Whether this session reads and writes the person's clipboard.
    pub fn has_clipboard(&self) -> bool {
        self.clipboard.is_some()
    }
    /// Text the person copied since the last call. The first call only
    /// notes what is there, so nothing copied before the session is sent.
    pub fn clipboard_changed(&self) -> Result<Option<String>> {
        let clip = self.clipboard()?;
        let changes = clip.state().changes;
        let mut watch = clip.watch.lock().unwrap_or_else(|e| e.into_inner());
        match watch.look(changes) {
            Look::Nothing => Ok(None),
            Look::First => {
                // What the person copied before is only remembered.
                watch.last = self.read_clipboard(clip).unwrap_or(None);
                Ok(None)
            }
            Look::Read => Ok(watch.report(self.read_clipboard(clip)?)),
        }
    }
    /// Put text on the person's clipboard. This session stays its owner and
    /// hands the text over each time something pastes it, until the person
    /// copies something else; GNOME keeps a copy after the session ends.
    pub fn set_clipboard(&self, text: &str) -> Result<()> {
        let clip = self.clipboard()?;
        clip.state().serving = Some(text.to_owned());
        clip.watch.lock().unwrap_or_else(|e| e.into_inner()).last = Some(text.to_owned());
        block_on(clip.portal.set_selection(
            &self.session,
            SetSelectionOptions::default().set_mime_types(TEXT_TYPES),
        ))
    }
    fn clipboard(&self) -> Result<&Clip> {
        self.clipboard.as_ref().context(
            "This computer's clipboard is not available to helpers: the desktop did not allow clipboard access when the screen was shared",
        )
    }
    /// The clipboard's text, or `None` when it holds no text.
    fn read_clipboard(&self, clip: &Clip) -> Result<Option<String>> {
        let offered = {
            let state = clip.state();
            if let Some(text) = &state.serving {
                return Ok(Some(text.clone()));
            }
            state.offered.clone()
        };
        let Some(mime) = text_type(offered.as_deref()) else {
            return Ok(None);
        };
        let fd = block_on(clip.portal.selection_read(&self.session, mime))?;
        let bytes = async_io::block_on(within_read(fd.into()))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }
}

/// The text types this session offers when it sets the clipboard: the
/// Wayland one first, then the X11 names Xwayland programs ask for.
const TEXT_TYPES: &[&str] = &[
    "text/plain;charset=utf-8",
    "text/plain",
    "UTF8_STRING",
    "STRING",
    "TEXT",
];
/// How much of the clipboard is read at most: one byte past the largest text
/// a session carries, so a larger one is seen as too large and refused there.
const READ_LIMIT: u64 = boundary_session::MAX_CLIPBOARD as u64 + 1;
/// How long a program that owns the clipboard has to hand its text over.
const READ_WAIT: Duration = Duration::from_secs(3);

/// Which of the offered types to read text as. `None` offered means no
/// owner change was seen yet, so the usual Wayland type is tried.
fn text_type(offered: Option<&[String]>) -> Option<&'static str> {
    let Some(offered) = offered else {
        return Some(TEXT_TYPES[0]);
    };
    TEXT_TYPES
        .iter()
        .copied()
        .find(|t| offered.iter().any(|o| o == t))
}

/// Read what the clipboard's owner writes into the pipe, up to
/// [`READ_LIMIT`], giving up when it stalls.
async fn within_read(fd: OwnedFd) -> Result<Vec<u8>> {
    use futures_lite::AsyncReadExt;
    let file = async_io::Async::new(std::fs::File::from(fd))?;
    let mut bytes = Vec::new();
    let read = async { file.take(READ_LIMIT).read_to_end(&mut bytes).await };
    futures_lite::future::or(async { read.await.map(|_| true) }, async {
        async_io::Timer::after(READ_WAIT).await;
        Ok::<_, std::io::Error>(false)
    })
    .await?
    .then_some(())
    .context("The program that owns the clipboard did not hand its text over")?;
    Ok(bytes)
}

/// The clipboard side of a portal session: what the portal said about the
/// clipboard's owner, kept by a thread that also hands over this session's
/// text when something pastes it.
pub(crate) struct Clip {
    portal: Clipboard,
    shared: Arc<Mutex<ClipState>>,
    watch: Mutex<Watch>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Clip {
    fn state(&self) -> std::sync::MutexGuard<'_, ClipState> {
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }
}
impl Drop for Clip {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Debug, Default)]
struct ClipState {
    /// How many times something other than this session took the clipboard.
    changes: u64,
    /// The types the clipboard offers, or `None` before the portal said.
    offered: Option<Vec<String>>,
    /// The text this session owns the clipboard with, if it does.
    serving: Option<String>,
}
impl ClipState {
    /// GNOME's SelectionOwnerChanged. It comes once right after Start, for
    /// whatever was copied before, and again each time anything copies; an
    /// empty one says nobody owns the clipboard. GNOME also takes over the
    /// text itself when the program that copied it quits, which is a new
    /// owner with the same text.
    fn owner_changed(&mut self, mime_types: &[String], ours: bool) {
        self.offered = Some(mime_types.to_vec());
        if !ours {
            self.serving = None;
            self.changes += 1;
        }
    }
}

/// What the session last looked at on the clipboard.
#[derive(Debug, Default)]
struct Watch {
    /// The owner changes seen at the last look, `None` before the first.
    seen: Option<u64>,
    /// The text last seen or set, so the same text is not sent twice.
    last: Option<String>,
}
#[derive(Debug, PartialEq, Eq)]
enum Look {
    First,
    Nothing,
    Read,
}
impl Watch {
    fn look(&mut self, changes: u64) -> Look {
        match self.seen.replace(changes) {
            None => Look::First,
            Some(seen) if seen == changes => Look::Nothing,
            Some(_) => Look::Read,
        }
    }
    /// The text to send for what was read, or `None` when it is no text or
    /// the same as before.
    fn report(&mut self, now: Option<String>) -> Option<String> {
        if now == self.last {
            return None;
        }
        self.last = now.clone();
        now
    }
}

/// The session's object path, which the portal's clipboard signals name.
fn session_path<T: ashpd::desktop::SessionPortal>(session: &Session<T>) -> Option<String> {
    use ashpd::zvariant::{LE, OwnedObjectPath, serialized::Context, to_bytes};
    let bytes = to_bytes(Context::new_dbus(LE, 0), session).ok()?;
    let (path, _): (OwnedObjectPath, _) = bytes.deserialize().ok()?;
    Some(path.as_str().to_owned())
}

/// Ask for the clipboard on a session that has not started, and listen to
/// it, so the owner change GNOME sends right after Start is not missed.
/// `None` where the portal has no Clipboard interface or refuses it; the
/// session then goes on without one.
async fn ask_clipboard(session: &Session<RemoteDesktop>) -> Option<ClipStart> {
    let portal = Clipboard::new().await.ok()?;
    portal.request(session, Default::default()).await.ok()?;
    let path = session_path(session)?;
    let shared = Arc::new(Mutex::new(ClipState::default()));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (listening, heard) = std::sync::mpsc::channel();
    let thread = {
        let (shared, stop) = (shared.clone(), stop.clone());
        std::thread::Builder::new()
            .name("portal-clipboard".into())
            .spawn(move || async_io::block_on(serve_clipboard(path, shared, stop, listening)))
            .ok()?
    };
    // The thread says once its signals are subscribed.
    if heard.recv_timeout(Duration::from_secs(5)) != Ok(true) {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    Some(ClipStart {
        portal,
        shared,
        stop,
        thread,
    })
}
/// A clipboard asked for, before the portal said whether it was allowed.
struct ClipStart {
    portal: Clipboard,
    shared: Arc<Mutex<ClipState>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}
impl ClipStart {
    /// The clipboard, when the person allowed it.
    fn started(self, allowed: bool) -> Option<Clip> {
        let clip = Clip {
            portal: self.portal,
            shared: self.shared,
            watch: Mutex::new(Watch::default()),
            stop: self.stop,
            thread: Some(self.thread),
        };
        // Dropped when refused, which stops its thread.
        allowed.then_some(clip)
    }
}

/// Follow the clipboard's owner, and write this session's text into each
/// pipe GNOME hands over when something pastes it, until told to stop.
async fn serve_clipboard(
    path: String,
    shared: Arc<Mutex<ClipState>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    listening: std::sync::mpsc::Sender<bool>,
) {
    use futures_lite::StreamExt;
    enum Heard {
        Owner(
            Session<RemoteDesktop>,
            ashpd::desktop::clipboard::SelectionOwnerChanged,
        ),
        Transfer(Session<RemoteDesktop>, u32),
        Quiet,
        Ended,
    }
    let Ok(portal) = Clipboard::new().await else {
        let _ = listening.send(false);
        return;
    };
    let (Ok(owners), Ok(transfers)) = (
        portal
            .receive_selection_owner_changed::<RemoteDesktop>()
            .await,
        portal.receive_selection_transfer::<RemoteDesktop>().await,
    ) else {
        let _ = listening.send(false);
        return;
    };
    let _ = listening.send(true);
    let mut owners = std::pin::pin!(owners);
    let mut transfers = std::pin::pin!(transfers);
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        let heard = futures_lite::future::or(
            async {
                match owners.next().await {
                    Some((s, o)) => Heard::Owner(s, o),
                    None => Heard::Ended,
                }
            },
            futures_lite::future::or(
                async {
                    match transfers.next().await {
                        Some((s, _, serial)) => Heard::Transfer(s, serial),
                        None => Heard::Ended,
                    }
                },
                async {
                    async_io::Timer::after(Duration::from_millis(250)).await;
                    Heard::Quiet
                },
            ),
        )
        .await;
        match heard {
            Heard::Owner(session, changed) if session_path(&session).as_ref() == Some(&path) => {
                shared
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .owner_changed(
                        changed.mime_types(),
                        changed.session_is_owner() == Some(true),
                    );
            }
            Heard::Transfer(session, serial) if session_path(&session).as_ref() == Some(&path) => {
                let text = shared
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .serving
                    .clone();
                let written = match (&text, portal.selection_write(&session, serial).await) {
                    (Some(text), Ok(fd)) => {
                        use std::io::Write;
                        let mut pipe = std::fs::File::from(OwnedFd::from(fd));
                        pipe.write_all(text.as_bytes()).is_ok()
                    }
                    _ => false,
                };
                let _ = portal.selection_write_done(&session, serial, written).await;
            }
            Heard::Ended => return,
            _ => {}
        }
    }
}

impl Remote {
    /// Whether the person let this session send input at all.
    pub fn controls(&self) -> bool {
        controls(self.granted)
    }
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
        set_left_out(None);
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

/// What to do with a grant the portal started a session on.
#[derive(Debug, PartialEq, Eq)]
enum Grant {
    /// Control was allowed: use it, and keep its token for next time.
    Keep,
    /// The person was asked just now and left Allow Remote Interaction off:
    /// use it for this session only, so the next one asks again.
    Once,
    /// A remembered grant came back without control: drop it and ask the
    /// person, who otherwise never sees the prompt that could fix it.
    Again,
}
/// GNOME ticks Remember This Selection by default, and a token restores what
/// was allowed when it was saved without showing anything. One approval with
/// Allow Remote Interaction off was then every later session view only,
/// helpers with control included. The portal says in its Start answer which
/// devices it granted, and Support always asks for the pointer and keyboard,
/// so a restored grant without them is the wrong one.
fn grant(restored: bool, granted: BitFlags<DeviceType>) -> Grant {
    if granted.contains(DeviceType::Pointer | DeviceType::Keyboard) {
        Grant::Keep
    } else if restored {
        Grant::Again
    } else {
        Grant::Once
    }
}

/// Whether a grant takes any input. GNOME grants the pointer and keyboard
/// together or neither; a portal that grants one alone still takes that one.
fn controls(granted: BitFlags<DeviceType>) -> bool {
    !granted.is_empty()
}

/// One RemoteDesktop session with the screen cast on it.
async fn remote(token: Option<&str>) -> Result<(Held, OwnedFd, PortalStream), ashpd::Error> {
    if let Some(token) = token {
        match remote_with(Some(token)).await? {
            Some(found) => return Ok(found),
            None => forget_token(),
        }
    }
    // Asked without a token, the answer is always used, so this is never
    // `None`; said as an error rather than a panic all the same.
    remote_with(None).await?.ok_or_else(|| {
        ashpd::Error::Portal(ashpd::PortalError::Failed("No screen was shared".into()))
    })
}

/// [`remote`] with one token, or none. `None` when a restored grant lacked
/// control and was closed, for the caller to ask again without it.
async fn remote_with(
    token: Option<&str>,
) -> Result<Option<(Held, OwnedFd, PortalStream)>, ashpd::Error> {
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
    // Only before Start: GNOME 50 answers "Invalid state" after it. Asked
    // on a restored grant too, which brings back what the person allowed;
    // a grant remembered before DeskVNC asked for the clipboard comes back
    // with it off and is kept, so unattended access goes on as it was.
    let clipboard = ask_clipboard(&session).await;
    let asked = clipboard.is_some();
    let started = within(
        ANSWER,
        portal.start(&session, None, StartOptions::default()),
    )
    .await?
    .response()?;
    let enabled = started.is_clipboard_enabled();
    let clipboard = clipboard.and_then(|c| c.started(enabled));
    let restored = token.is_some();
    match grant(restored, started.devices()) {
        Grant::Keep => {
            set_left_out(left_out(restored, asked, enabled, grant_asked_clipboard()));
            save_token(started.restore_token());
            // A restored grant is the one remembered, whatever it was asked.
            if !restored {
                note_asked(asked);
            }
        }
        Grant::Once => {
            set_left_out(None);
            forget_token();
        }
        Grant::Again => {
            let _ = session.close().await;
            return Ok(None);
        }
    }
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
        clipboard,
    };
    Ok(Some((Held::Remote(Arc::new(remote)), fd, stream)))
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
    // No clipboard on a screen cast alone, and none to ask for again.
    set_left_out(None);
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
    fn a_grant_without_devices_takes_no_input() {
        // What GNOME 50 answered with Allow Remote Interaction off.
        assert!(!controls(BitFlags::empty()));
        assert!(controls(DeviceType::Pointer | DeviceType::Keyboard));
        assert!(controls(BitFlags::from_flag(DeviceType::Keyboard)));
    }

    #[test]
    fn a_grant_from_0_34_says_why_the_clipboard_is_missing() {
        // GNOME 50 restoring a token Support 0.34 saved: the portal has a
        // clipboard, it was asked for, and Start said it was off.
        assert_eq!(left_out(true, true, false, false), Some(OLD_GRANT));
        // Remembered from a prompt that asked, with the switch left off.
        assert_eq!(left_out(true, true, false, true), Some(LEFT_OFF));
        // Restored with it on.
        assert_eq!(left_out(true, true, true, false), None);
        assert_eq!(left_out(true, true, true, true), None);
        // Asked just now: off is what the person chose, nothing to fix.
        assert_eq!(left_out(false, true, false, false), None);
        // A portal without a clipboard has none to give, shared again or not.
        assert_eq!(left_out(true, false, false, false), None);
    }

    #[test]
    fn whether_a_grant_asked_is_kept_beside_its_token() {
        let token = std::path::Path::new("/state/deskvnc/portal-restore-token");
        assert_eq!(
            asked_path(token),
            std::path::Path::new("/state/deskvnc/portal-restore-token.clipboard")
        );
    }

    #[test]
    fn a_remembered_grant_without_control_is_asked_again() {
        // What GNOME 50 answered when a token saved with Allow Remote
        // Interaction off was restored: devices 0, and no prompt shown.
        let none = BitFlags::<DeviceType>::empty();
        let both = DeviceType::Pointer | DeviceType::Keyboard;
        assert_eq!(grant(true, none), Grant::Again);
        assert_eq!(
            grant(true, BitFlags::from_flag(DeviceType::Pointer)),
            Grant::Again
        );
        // A token saved with it on came back with devices 3.
        assert_eq!(grant(true, both), Grant::Keep);
        assert_eq!(grant(false, both), Grant::Keep);
        // Asked just now and left off: this session watches, and the next
        // one asks again rather than remembering it.
        assert_eq!(grant(false, none), Grant::Once);
    }

    /// The owner changes GNOME 50 sent, in order, and what a poll after each
    /// one did.
    #[test]
    fn what_was_copied_before_the_session_is_never_sent() {
        let mut state = ClipState::default();
        let mut watch = Watch::default();
        // Right after Start: whatever the person copied earlier.
        state.owner_changed(&["text/plain;charset=utf-8".into()], false);
        assert_eq!(watch.look(state.changes), Look::First);
        watch.last = Some("an old password".into());
        assert_eq!(watch.look(state.changes), Look::Nothing);
        // The person copies in a program running under Xwayland.
        state.owner_changed(&["text/plain".into(), "UTF8_STRING".into()], false);
        assert_eq!(watch.look(state.changes), Look::Read);
        assert_eq!(
            watch.report(Some("copied now".into())).as_deref(),
            Some("copied now")
        );
        // The program quits: an empty owner, then GNOME holding the same
        // text. A change, with nothing new to send.
        state.owner_changed(&[], false);
        state.owner_changed(&["text/plain;charset=utf-8".into()], false);
        assert_eq!(watch.look(state.changes), Look::Read);
        assert_eq!(watch.report(Some("copied now".into())), None);
    }

    #[test]
    fn a_session_that_polls_first_after_a_copy_still_sends_nothing_old() {
        // The first look comes after some changes were counted already.
        let mut state = ClipState::default();
        state.owner_changed(&["text/plain;charset=utf-8".into()], false);
        state.owner_changed(&["text/plain;charset=utf-8".into()], false);
        let mut watch = Watch::default();
        assert_eq!(watch.look(state.changes), Look::First);
        assert_eq!(watch.look(state.changes), Look::Nothing);
    }

    #[test]
    fn text_this_session_set_is_not_a_change() {
        let mut state = ClipState {
            serving: Some("from the helper".into()),
            ..Default::default()
        };
        let mut watch = Watch::default();
        watch.look(state.changes);
        watch.last = Some("from the helper".into());
        // GNOME names this session as the owner after SetSelection.
        state.owner_changed(
            &TEXT_TYPES.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
            true,
        );
        assert_eq!(watch.look(state.changes), Look::Nothing);
        assert_eq!(state.serving.as_deref(), Some("from the helper"));
        // The person copies: this session no longer serves its text.
        state.owner_changed(&["text/plain;charset=utf-8".into()], false);
        assert_eq!(state.serving, None);
        assert_eq!(watch.look(state.changes), Look::Read);
        // Copying the helper's text again is not news either.
        assert_eq!(watch.report(Some("from the helper".into())), None);
    }

    #[test]
    fn something_that_is_not_text_is_not_read() {
        assert_eq!(text_type(None), Some("text/plain;charset=utf-8"));
        let image = ["image/png".to_string()];
        assert_eq!(text_type(Some(&image)), None);
        assert_eq!(text_type(Some(&[])), None);
        // What a GTK program under Xwayland offered.
        let x11: Vec<String> = [
            "text/plain",
            "text/plain;charset=utf-8",
            "STRING",
            "UTF8_STRING",
        ]
        .iter()
        .map(|t| t.to_string())
        .collect();
        assert_eq!(text_type(Some(&x11)), Some("text/plain;charset=utf-8"));
        let latin = ["STRING".to_string()];
        assert_eq!(text_type(Some(&latin)), Some("STRING"));
    }

    /// Against the real portal of the desktop this runs in, with another
    /// program reading and setting the clipboard:
    /// `DESKVNC_CLIPBOARD_PEER="<get command>|<set command taking the text last>"
    /// cargo test -p boundary-platform real_portal -- --ignored`.
    /// Asks the person to share unless a grant was remembered.
    #[test]
    #[ignore]
    fn a_real_portal_carries_the_clipboard_both_ways() {
        let peer = std::env::var("DESKVNC_CLIPBOARD_PEER").expect("DESKVNC_CLIPBOARD_PEER");
        let (get, set) = peer.split_once('|').unwrap();
        let run = |cmd: &str, arg: Option<&str>| {
            let mut c = std::process::Command::new("sh");
            c.arg("-c").arg(match arg {
                Some(_) => format!("{cmd} \"$1\""),
                None => cmd.to_owned(),
            });
            c.arg("sh");
            if let Some(a) = arg {
                c.arg(a);
            }
            String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned()
        };
        let screen = Screen::open().unwrap();
        let remote = screen.remote().expect("a remote desktop session");
        assert!(remote.has_clipboard(), "Allow Clipboard Access was off");
        assert_eq!(remote.clipboard_changed().unwrap(), None, "first look");
        assert_eq!(remote.clipboard_changed().unwrap(), None);

        let from_helper = format!("from the helper é {}", std::process::id());
        remote.set_clipboard(&from_helper).unwrap();
        let pasted = run(get, None);
        assert!(pasted.contains(&from_helper), "pasted {pasted:?}");
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(remote.clipboard_changed().unwrap(), None, "no echo");

        let copied = format!("the person copied ✓ {}", std::process::id());
        run(set, Some(&copied));
        let deadline = Instant::now() + Duration::from_secs(5);
        let seen = loop {
            if let Some(text) = remote.clipboard_changed().unwrap() {
                break text;
            }
            assert!(Instant::now() < deadline, "the copy was never seen");
            std::thread::sleep(Duration::from_millis(100));
        };
        assert_eq!(seen, copied);
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(remote.clipboard_changed().unwrap(), None, "seen once");
        drop(remote);
        drop(screen);
        // GNOME keeps the text after the session ends.
        assert!(run(get, None).contains(&copied));
    }

    #[test]
    fn a_clipboard_owner_that_stalls_is_given_up_on() {
        let (read, write) = std::io::pipe().unwrap();
        let started = Instant::now();
        let r = async_io::block_on(within_read(OwnedFd::from(read)));
        assert!(r.is_err());
        assert!(started.elapsed() < READ_WAIT + Duration::from_secs(1));
        drop(write);
    }

    #[test]
    fn a_clipboard_larger_than_a_session_carries_is_cut_one_byte_past_it() {
        let (read, mut write) = std::io::pipe().unwrap();
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            let _ = write.write_all(&vec![b'a'; 2 * 1024 * 1024]);
        });
        let bytes = async_io::block_on(within_read(OwnedFd::from(read))).unwrap();
        assert_eq!(bytes.len() as u64, READ_LIMIT);
        drop(bytes);
        let _ = writer.join();
    }

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
