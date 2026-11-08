// No console window behind the app on Windows.
#![cfg_attr(windows, windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod attention;
mod codes;
mod install;
mod journal;
mod launcher;
mod login;
mod network;
mod theme;
mod tray;
mod unattended;
mod wake;

use boundary_session::{
    Abilities, Approval, Button, ClipboardRights, Event, HostOptions, Input, Key, Session,
    unattended::SecretKey,
};
use eframe::egui::{self, Margin, RichText};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| args.iter().any(|a| a == name);
    // Answered before anything else: these never open a window, so they
    // work in a terminal with no display, as they do for any other program.
    if let Some(text) = information(&args) {
        print!("{text}");
        return Ok(());
    }
    if let Some(code) = other_mode(&args) {
        std::process::exit(code);
    }
    let background = flag("--background");
    boundary_platform::set_app_id(APP_ID);
    // A copy started at sign in steps aside for one already running. Two
    // copies would listen as the same machine ID and keep pushing each other
    // off the relay, so neither could be reached. A copy that is quitting
    // holds the lock a moment longer, so this waits before giving up.
    let _instance = match only_instance() {
        Some(lock) => Some(lock),
        None if background => {
            let waited = (0..30).find_map(|_| {
                std::thread::sleep(Duration::from_secs(1));
                only_instance()
            });
            match waited {
                Some(lock) => Some(lock),
                None => return Ok(()),
            }
        }
        None => None,
    };
    let runtime = tokio::runtime::Runtime::new().expect("Cannot start the connection runtime");
    let _guard = runtime.enter();
    let fallback = std::env::var_os(FALLBACK_RENDERER).is_some();
    let result = eframe::run_native(
        APP_NAME,
        eframe::NativeOptions {
            viewport: viewport(background),
            event_loop_builder: background_policy(background),
            renderer: if fallback {
                eframe::Renderer::Wgpu
            } else {
                eframe::Renderer::Glow
            },
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    );
    // The window closing dropped the listener, which tells each helper still
    // connected that this computer went away. Those close frames go out from
    // the runtime's tasks, so they get a moment before the runtime stops.
    runtime.block_on(tokio::time::sleep(Duration::from_millis(500)));
    runtime.shutdown_timeout(Duration::from_secs(3));
    // A display with no graphics driver behind it, as in a virtual machine,
    // a Remote Desktop session or a virtual monitor, offers OpenGL 1.1 and
    // the window never opened. Direct3D has a software device everywhere.
    // A process gets one event loop, so a fresh copy draws with it.
    if !fallback
        && matches!(result, Err(eframe::Error::OpenGL(_)))
        && let Ok(exe) = std::env::current_exe()
    {
        drop(_instance);
        if std::process::Command::new(exe)
            .args(&args[1..])
            .env(FALLBACK_RENDERER, "1")
            .spawn()
            .is_ok()
        {
            return Ok(());
        }
    }
    result
}
/// The name a person sees, in the title bar, the dock and notifications.
const APP_NAME: &str = "DeskVNC Support";
/// The Wayland app ID and X11 class, which match `deskvnc-support.desktop`,
/// so the dock finds that file and shows the app's name and icon.
const APP_ID: &str = "deskvnc-support";

/// The window as the system sees it: its title, the app ID the dock pairs
/// with the .desktop file, and its icon where a window can carry one.
fn viewport(background: bool) -> egui::ViewportBuilder {
    let builder = egui::ViewportBuilder::default()
        .with_title(APP_NAME)
        .with_app_id(APP_ID)
        .with_inner_size([980.0, 660.0])
        .with_min_inner_size([820.0, 600.0])
        // Started at sign in, the window waits hidden behind the tray
        // icon. Where there is no tray it is minimized instead.
        .with_visible(!background || !TRAY);
    match eframe::icon_data::from_png_bytes(launcher::ICON) {
        Ok(icon) => builder.with_icon(icon),
        Err(_) => builder,
    }
}
/// Set for a copy that draws with wgpu because OpenGL was too old.
const FALLBACK_RENDERER: &str = "DESKVNC_SUPPORT_WGPU";
/// Whether this platform has a tray icon to hide the window behind.
const TRAY: bool = cfg!(any(target_os = "macos", windows));

/// Started at sign in on macOS, the app keeps out of the Dock and the app
/// switcher: the menu bar icon is how it is reached.
#[cfg(target_os = "macos")]
fn background_policy(background: bool) -> Option<eframe::EventLoopBuilderHook> {
    use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
    background.then(|| -> eframe::EventLoopBuilderHook {
        Box::new(|builder| {
            builder.with_activation_policy(ActivationPolicy::Accessory);
        })
    })
}
#[cfg(not(target_os = "macos"))]
fn background_policy(_: bool) -> Option<eframe::EventLoopBuilderHook> {
    None
}

/// The modes with no window: the copy at the sign in screen, the Windows
/// service that starts it, and setting that service up as an administrator.
/// `Some(exit code)` when this run was one of them.
fn other_mode(args: &[String]) -> Option<i32> {
    let after = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .map(|i| args.get(i + 1).cloned().unwrap_or_default())
    };
    let result = if args.iter().any(|a| a == "--login-screen") {
        login::host()
    } else if cfg!(windows) && args.iter().any(|a| a == "--service") {
        #[cfg(windows)]
        let result = login::service();
        #[cfg(not(windows))]
        let result = Ok(());
        result
    } else if let Some(owner) = after("--install-service") {
        #[cfg(windows)]
        let result = login::install(&owner);
        #[cfg(not(windows))]
        let result = {
            let _ = owner;
            Ok(())
        };
        result
    } else if cfg!(target_os = "linux") && args.iter().any(|a| a == "--install") {
        // Put the app in the menu and give the dock its icon, for this
        // person only: `./deskvnc-support --install` after unpacking.
        launcher::install().map(|(entry, program)| {
            println!("Installed {}", program.display());
            println!("Added {} to the app menu", entry.display());
            println!("The folder you unpacked it from can be deleted.");
        })
    } else if args.iter().any(|a| a == "--uninstall-service") {
        #[cfg(windows)]
        let result = login::uninstall();
        #[cfg(not(windows))]
        let result = Ok(());
        result
    } else {
        return None;
    };
    Some(match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error:#}");
            1
        }
    })
}

/// What `--help` and `--version` print, or `None` for a run that opens the
/// app. Only the first argument counts, so a flag meant for another mode is
/// never read as one of these.
fn information(args: &[String]) -> Option<String> {
    match args.get(1).map(String::as_str)? {
        "--version" | "-V" => Some(format!("{APP_NAME} {}\n", env!("CARGO_PKG_VERSION"))),
        "--help" | "-h" => Some(format!(
            "{APP_NAME} {}\n\
             Let someone you trust see this computer and help you, or help someone else.\n\
             \n\
             Usage: deskvnc-support [OPTION]\n\
             \n\
             With no option, the app opens its window.\n\
             \n\
             Options:\n\
             {INSTALL_HELP}\
             \x20 --background   Start out of the way, as at sign in, for unattended access\n\
             \x20 -h, --help     Print this help and exit\n\
             \x20 -V, --version  Print the version and exit\n",
            env!("CARGO_PKG_VERSION")
        )),
        _ => None,
    }
}
/// The line about `--install` in the help, on Linux where it exists.
const INSTALL_HELP: &str = if cfg!(target_os = "linux") {
    "  --install      Add DeskVNC Support to your app menu, for you only\n"
} else {
    ""
};
/// A lock held for as long as this copy runs, or `None` when another copy
/// holds it already.
fn only_instance() -> Option<std::fs::File> {
    lock_file("running.lock")
}
fn lock_file(name: &str) -> Option<std::fs::File> {
    let dir = boundary_provision::platform::data_dir().ok()?;
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(name);
    // The copy at the sign in screen runs as root on macOS, and a lock file
    // it created cannot be opened for writing by the person afterwards. A
    // lock needs no writing.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .or_else(|_| std::fs::File::open(&path))
        .ok()?;
    file.try_lock().ok()?;
    Some(file)
}
struct Pending {
    name: String,
    peer: String,
    /// The helper can send commands and file requests, so the person is
    /// asked about those too.
    tools: bool,
    /// What the person ticked for them. Off until they tick it.
    allow_tools: bool,
    /// The helper can take text this computer copies, and this computer can
    /// give it, so the person is asked whether it may.
    clipboard: bool,
    /// Off until they tick it: whatever they copy may be a password.
    allow_clipboard: bool,
    answer: oneshot::Sender<Approval>,
}
/// How many lines of what a helper's tools did the sharing screen keeps.
const ACTIVITY_LINES: usize = 8;
/// What the window shows when no session is on screen.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Home,
    Settings,
}
struct App {
    codes: codes::Codes,
    session: Option<Session>,
    hosting: bool,
    connected: bool,
    control: bool,
    /// Whether this helper can send commands and file requests at all.
    tools_offered: bool,
    /// Whether the person allows them now.
    tools: bool,
    /// Whether this helper can be shown what the person copies at all.
    clipboard_offered: bool,
    /// Whether the person lets them see it now.
    clipboard: bool,
    /// On the helper's side: what the host lets this copy do with clipboards.
    rights: ClipboardRights,
    /// On the helper's side: the last text the person at the other computer
    /// copied, kept until this helper chooses to copy it.
    copied: Option<String>,
    /// What they did, newest last.
    activity: Vec<String>,
    invitation: String,
    /// When this computer's invitation stops working, while it waits for a
    /// helper, so the status line can count down to it.
    expires: Option<Instant>,
    ticket: String,
    password: String,
    name: String,
    status: String,
    error: bool,
    page: Page,
    pending: Option<Pending>,
    texture: Option<egui::TextureHandle>,
    displays: Vec<boundary_platform::Display>,
    display: usize,
    network: network::Profile,
    network_error: Option<String>,
    wizard: network::Wizard,
    screen_permission: bool,
    input_permission: bool,
    /// The real app, when macOS runs a translocated copy of it.
    translocated: Option<std::path::PathBuf>,
    permission_check: Instant,
    remote_focus: bool,
    modifiers: egui::Modifiers,
    unattended: unattended::Unattended,
    /// This copy's lasting identity as a helper, so a computer that pairs it
    /// recognises it later. Without one, pairing is not offered.
    helper_key: Option<SecretKey>,
    /// The helper in the current attended session, as (name, key), so the
    /// person can choose to let them come back unattended.
    helper: Option<(String, String)>,
    approved_name: String,
    /// A computer that let this helper in any time, as (ID, name).
    paired: Option<(String, String)>,
    /// Set when this copy closes on purpose, for a moved copy to take over.
    quitting: bool,
    tray: Option<tray::Tray>,
    /// Frames left in which to hide the window at a background start. eframe
    /// shows the window once its first frame is drawn, whatever it was built
    /// with, so it has to be hidden again after that.
    hide_frames: u8,
    /// Whether the window had focus when last drawn, for the session's
    /// events, which are read off the window's thread.
    focused: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        // Started at sign in for unattended access: out of the way, in the
        // tray. The window comes forward only for a question somebody has to
        // answer, never just because a paired helper connected.
        if std::env::args().any(|a| a == "--background") && !TRAY {
            cc.egui_ctx
                .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
        // launchd stops the app with SIGTERM to restart or update it. Left to
        // the default, that kills the process before a connected helper is
        // told, and the helper waits out a timeout before connecting again.
        #[cfg(unix)]
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let ctx = cc.egui_ctx.clone();
            tokio::spawn(async move {
                term.recv().await;
                TERMINATED.store(true, std::sync::atomic::Ordering::Relaxed);
                ctx.request_repaint();
            });
        }
        let (displays, status, error) = match boundary_platform::displays() {
            Ok(displays) => (displays, "Ready to connect".into(), false),
            Err(error) => (vec![], format!("Could not list displays: {error:#}"), true),
        };
        let (network, network_error) = match network::load() {
            Ok(profile) => (profile, None),
            Err(error) => (network::Profile::default(), Some(error.to_string())),
        };
        let data_dir = boundary_provision::platform::data_dir().ok();
        let helper_key = data_dir.as_ref().and_then(|dir| {
            boundary_session::unattended::load_or_create_key(&dir.join("helper.key")).ok()
        });
        let name = data_dir
            .as_ref()
            .and_then(|dir| std::fs::read_to_string(dir.join("helper-name.txt")).ok())
            .map(|n| n.trim().to_owned())
            .unwrap_or_default();
        Self {
            codes: codes::Codes::default(),
            session: None,
            hosting: false,
            connected: false,
            control: false,
            tools_offered: false,
            tools: false,
            clipboard_offered: false,
            clipboard: false,
            rights: ClipboardRights::default(),
            copied: None,
            activity: Vec::new(),
            invitation: String::new(),
            expires: None,
            ticket: String::new(),
            password: String::new(),
            name,
            status,
            error,
            page: Page::Home,
            pending: None,
            texture: None,
            displays,
            display: 0,
            network,
            network_error,
            wizard: network::Wizard::default(),
            screen_permission: boundary_platform::screen_permission(),
            input_permission: boundary_platform::input_permission(),
            translocated: install::translocated(),
            permission_check: Instant::now(),
            remote_focus: false,
            modifiers: egui::Modifiers::default(),
            unattended: unattended::Unattended::new(&cc.egui_ctx),
            helper_key,
            helper: None,
            approved_name: String::new(),
            paired: None,
            quitting: false,
            tray: tray::Tray::new(&cc.egui_ctx),
            hide_frames: if std::env::args().any(|a| a == "--background") && TRAY {
                3
            } else {
                0
            },
            focused: Default::default(),
        }
    }
    fn network_options(&self) -> HostOptions {
        self.network.options()
    }
    fn remember_name(&self) {
        if let Ok(dir) = boundary_provision::platform::data_dir() {
            let _ = std::fs::write(dir.join("helper-name.txt"), self.name.trim());
        }
    }
    fn stop(&mut self) {
        self.codes.clear();
        if let Some(session) = self.session.take() {
            session.stop();
        }
        self.pending = None;
        self.connected = false;
        self.control = false;
        self.tools_offered = false;
        self.tools = false;
        self.clipboard_offered = false;
        self.clipboard = false;
        self.rights = ClipboardRights::default();
        self.copied = None;
        self.activity.clear();
        self.invitation.clear();
        self.expires = None;
        self.texture = None;
        self.remote_focus = false;
        self.modifiers = egui::Modifiers::default();
        self.helper = None;
        self.status = "Session ended. Ready to connect".into();
        self.error = false;
    }
    fn send(&mut self, event: Input) {
        if let Some(session) = self.session.as_ref()
            && let Err(error) = session.input(event)
        {
            self.status = error.to_string();
            self.error = true;
        }
    }
    /// Put text on the other computer's clipboard and paste it there with
    /// V under the modifier the helper is holding, which reached it already,
    /// so the paste lands where it would have been typed.
    fn paste_there(&mut self, text: String) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        if let Err(error) = session.send_clipboard(text) {
            self.status = format!("{error:#}");
            self.error = true;
            return;
        }
        self.send(Input::Key {
            key: Key::Letter('v'),
            down: true,
        });
        self.send(Input::Key {
            key: Key::Letter('v'),
            down: false,
        });
    }
    /// Share this computer: a host session whose invitation becomes the code
    /// on the home screen.
    fn share(&mut self, ctx: &egui::Context) {
        let Some(display) = self.displays.get(self.display) else {
            return;
        };
        let id = display.id;
        self.hosting = true;
        self.error = false;
        self.status = "Creating your code".into();
        let mut session =
            boundary_session::host(self.network_options(), move || boundary_platform::open(id));
        // Read off the window's thread, so a question gets to the person
        // even while the window draws nothing.
        let (_, stand_in) = tokio::sync::mpsc::channel(1);
        let events = std::mem::replace(&mut session.events, stand_in);
        session.events =
            attention::forward(events, ctx.clone(), self.focused.clone(), attention::notify);
        wake::on_change(session.connectivity.clone(), ctx.clone());
        self.session = Some(session);
    }
    /// Connect to whatever is in the partner field: a short code, a full
    /// invitation, or an unattended computer's ID.
    fn connect(&mut self) {
        let target = self.ticket.trim().to_owned();
        let name = self.name.trim().to_owned();
        self.remember_name();
        self.hosting = false;
        self.error = false;
        if target.starts_with("boundary1:") {
            self.session = Some(boundary_session::viewer_with(
                target,
                name,
                self.network_options(),
                self.helper_key.clone(),
                abilities(),
            ));
        } else if boundary_session::unattended::validate_machine_id(&target).is_ok() {
            let Some(key) = self.helper_key.clone() else {
                self.status = "This copy of DeskVNC Support has no helper identity, so it cannot connect to an unattended computer".into();
                self.error = true;
                return;
            };
            let password = Some(self.password.clone()).filter(|p| !p.is_empty());
            self.status = "Connecting to the computer".into();
            self.session = Some(boundary_session::unattended::connect_with(
                target,
                name,
                password,
                key,
                self.network_options(),
                abilities(),
            ));
        } else {
            self.codes.resolve(target);
        }
        self.ticket.clear();
        self.password.clear();
    }
    /// What the window has going on, for how often it draws.
    fn load(&self) -> wake::Load {
        let session = self.session.is_some() && !self.connected;
        wake::Load {
            connected: self.connected,
            connecting: session && !self.hosting,
            waiting: session && self.hosting,
            codes: self.codes.busy(),
            helpers: !self.unattended.active.is_empty(),
            // macOS has no event for a permission being granted in System
            // Settings, and the lock screen has none for handing back the ID.
            checks: !(self.screen_permission && self.input_permission)
                || self.unattended.needs_checks(),
        }
    }
    fn poll(&mut self, ctx: &egui::Context) {
        let helpers_before = self.unattended.connections;
        if self.unattended.poll() {
            attention::raise(ctx);
        }
        // A helper connecting unattended is a new session too: what the
        // last one ended with is old news beside the banner saying who is in.
        if self.unattended.connections != helpers_before && self.session.is_none() && self.error {
            self.status = "Ready to connect".into();
            self.error = false;
        }
        self.codes.private_required = !matches!(self.network, network::Profile::Automatic);
        if let Some(ticket) = self.codes.poll() {
            self.hosting = false;
            self.error = false;
            self.session = Some(boundary_session::viewer_with(
                ticket,
                self.name.trim().to_owned(),
                self.network_options(),
                self.helper_key.clone(),
                abilities(),
            ));
        }
        if self.permission_check.elapsed() > Duration::from_secs(1) {
            self.screen_permission = boundary_platform::screen_permission();
            self.input_permission = boundary_platform::input_permission();
            self.permission_check = Instant::now();
        }
        let mut finished = None;
        if let Some(session) = self.session.as_mut() {
            while let Ok(event) = session.events.try_recv() {
                match event {
                    Event::Status(status) => {
                        // Something newer than the countdown, such as the
                        // screen starting to be shared once a helper is let in.
                        self.expires = None;
                        self.status = status;
                        self.error = false;
                    }
                    Event::Invitation(ticket) => {
                        // With a code service, the invitation becomes a short
                        // code on its own, so the code is simply there, the
                        // way people expect.
                        if self.codes.available() {
                            self.codes.publish(ticket.clone());
                        }
                        let left = boundary_session::Invitation::decode(&ticket)
                            .map(|invite| invite.expires.saturating_sub(unix_now()))
                            .unwrap_or(0);
                        self.expires = Some(Instant::now() + Duration::from_secs(left));
                        self.invitation = ticket;
                    }
                    Event::Approval {
                        name,
                        peer,
                        tools,
                        clipboard,
                        answer,
                    } => {
                        self.approved_name = name.clone();
                        self.pending = Some(Pending {
                            name,
                            peer,
                            tools,
                            allow_tools: false,
                            clipboard,
                            allow_clipboard: false,
                            answer,
                        });
                        attention::raise(ctx);
                    }
                    Event::Connected { peer, control } => {
                        self.expires = None;
                        self.codes.clear();
                        self.pending = None;
                        self.connected = true;
                        self.control = control;
                        self.invitation.clear();
                        self.status = format!("Connected to {}", &peer[..16.min(peer.len())]);
                        self.helper = Some((self.approved_name.clone(), peer));
                    }
                    Event::Control(control) => {
                        self.control = control;
                    }
                    // On the helper's side. This app sends no commands of its
                    // own, so there is nothing to show.
                    Event::Tools(_) => {}
                    Event::ClipboardRights(rights) => self.rights = rights,
                    // Kept for a button, never put on this computer's
                    // clipboard unasked: that would replace what the helper
                    // copied themselves.
                    Event::ClipboardText(text) => self.copied = Some(text),
                    Event::Activity(line) => {
                        self.activity.push(line);
                        let excess = self.activity.len().saturating_sub(ACTIVITY_LINES);
                        self.activity.drain(..excess);
                    }
                    Event::Paired { machine, name } => {
                        self.status = format!(
                            "{name} lets you connect any time. Its ID is kept on the home screen"
                        );
                        self.paired = Some((machine, name));
                    }
                    Event::Finished(result) => {
                        finished = Some(result);
                    }
                }
            }
            if session.frames.has_changed().unwrap_or(false)
                && let Some(frame) = session.frames.borrow_and_update().as_ref()
            {
                let image = egui::ColorImage::from_rgba_unmultiplied(
                    [frame.width as usize, frame.height as usize],
                    &frame.rgba,
                );
                if let Some(texture) = self.texture.as_mut() {
                    texture.set(image, egui::TextureOptions::LINEAR);
                } else {
                    self.texture = Some(ctx.load_texture(
                        "remote screen",
                        image,
                        egui::TextureOptions::LINEAR,
                    ));
                }
            }
        }
        if self.pending.as_ref().is_some_and(|p| p.answer.is_closed()) {
            self.pending = None;
        }
        // Said again on every frame, which is once a second while waiting,
        // so the minutes left go down instead of staying at ten.
        if let Some(expires) = self.expires {
            self.status = waiting(
                self.codes.available(),
                expires.saturating_duration_since(Instant::now()),
            );
            self.error = false;
        }
        if let Some(result) = finished {
            // On this side of a shared screen, a session that ends without
            // an error was ended by the helper: the person ends theirs with
            // End session, which stops it before it can finish.
            let shared = self.hosting && self.connected;
            self.stop();
            if let Some((status, error)) = ended_status(shared, &result) {
                self.status = status;
                self.error = error;
            }
        }
    }
    /// The home screen: this computer on the left, a remote one on the right.
    /// Offer to move the app to Applications when macOS is running a
    /// translocated copy, which breaks sign in and hides updates.
    fn move_banner(&mut self, ui: &mut egui::Ui) {
        let Some(source) = self.translocated.clone() else {
            return;
        };
        theme::card(ui, |ui| {
            ui.label(RichText::new("Move DeskVNC Support to Applications").strong());
            theme::muted(
                ui,
                "It is running from your Downloads, so macOS runs a temporary copy. Unattended access will not start after a restart, and a newer download is not used until it is moved.",
            );
            ui.add_space(6.0);
            if ui.button("Move to Applications and reopen").clicked() {
                match install::move_to_applications(&source) {
                    Ok(_) => {
                        self.quitting = true;
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    Err(error) => self.status = format!("{error:#}"),
                }
            }
        });
        ui.add_space(10.0);
    }
    fn home(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.columns(2, |columns| {
            self.share_card(&mut columns[0]);
            self.connect_card(&mut columns[1]);
        });
    }
    /// Allow remote control: the code this computer is reached by.
    fn share_card(&mut self, ui: &mut egui::Ui) {
        theme::card(ui, |ui| {
            ui.set_min_height(ui.available_height().max(360.0));
            theme::title(ui, "Allow remote control");
            theme::muted(
                ui,
                "Give the person helping you this code. They see nothing until you approve them on this screen.",
            );
            ui.add_space(14.0);
            let with_codes = self.codes.available();
            theme::caption(
                ui,
                if with_codes {
                    "Your code"
                } else {
                    "Your invitation"
                },
            );
            ui.add_space(2.0);
            let idle = self.session.is_none();
            if idle {
                if !self.screen_permission {
                    theme::muted(ui, "Screen Recording permission is needed to share.");
                    if ui.button("Allow screen recording").clicked() {
                        boundary_platform::request_screen_permission();
                    }
                    theme::small(
                        ui,
                        "After granting it, quit and reopen DeskVNC Support if sharing still fails.",
                    );
                } else if self.displays.is_empty() {
                    ui.colored_label(theme::pal(ui.ctx()).danger, "No display found to share.");
                } else {
                    let can = !self.codes.busy() && self.network_error.is_none();
                    let label = if with_codes {
                        "Get a code"
                    } else {
                        "Create invitation"
                    };
                    if ui
                        .add_enabled(
                            can,
                            theme::primary(ui, label)
                                .min_size(egui::vec2(ui.available_width(), 46.0)),
                        )
                        .clicked()
                    {
                        self.share(ui.ctx());
                    }
                    theme::small(ui, share_words(with_codes).expiry);
                }
            } else if self.invitation.is_empty() || self.codes.publishing() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    theme::muted(
                        ui,
                        if self.invitation.is_empty() {
                            share_words(with_codes).creating
                        } else {
                            "Getting your code"
                        },
                    );
                });
                if !self.invitation.is_empty()
                    && ui.small_button("Use the full invitation instead").clicked()
                {
                    self.codes.clear();
                }
            } else if let Some(code) = self.codes.code() {
                if theme::value_box(ui, &code, 26.0) {
                    ui.ctx().copy_text(code.clone());
                }
                theme::small(
                    ui,
                    "Read it out or send it. Your helper enters it, and you approve them here.",
                );
                if ui
                    .small_button("Copy the full invitation instead")
                    .clicked()
                {
                    ui.ctx().copy_text(self.invitation.clone());
                }
            } else {
                egui::ScrollArea::vertical()
                    .max_height(84.0)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.invitation.as_str())
                                .font(egui::TextStyle::Small)
                                .desired_rows(3)
                                .desired_width(f32::INFINITY),
                        );
                    });
                if ui
                    .add(
                        theme::primary(ui, "Copy invitation")
                            .min_size(egui::vec2(ui.available_width(), 42.0)),
                    )
                    .clicked()
                {
                    ui.ctx().copy_text(self.invitation.clone());
                }
                theme::small(
                    ui,
                    "Send it in any chat and keep it private. It is valid for one session.",
                );
                if !self.codes.message().is_empty() {
                    ui.colored_label(theme::pal(ui.ctx()).danger, self.codes.message());
                }
            }
            if !idle && self.hosting && ui.small_button("Cancel").clicked() {
                self.stop();
            }
            if self.displays.len() > 1 && idle {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    theme::small(ui, "Sharing");
                    egui::ComboBox::from_id_salt("display")
                        .selected_text(
                            self.displays
                                .get(self.display)
                                .map(|d| d.name.as_str())
                                .unwrap_or(""),
                        )
                        .show_ui(ui, |ui| {
                            for (index, display) in self.displays.iter().enumerate() {
                                ui.selectable_value(&mut self.display, index, &display.name);
                            }
                        });
                });
            }
            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                theme::caption(ui, "Unattended access");
                if self.unattended.enabled() {
                    ui.colored_label(theme::pal(ui.ctx()).success, self.unattended.label());
                } else {
                    theme::muted(ui, "Off");
                }
                if ui.small_button("Change").clicked() {
                    self.page = Page::Settings;
                }
            });
            if self.unattended.enabled() {
                ui.horizontal(|ui| {
                    theme::small(ui, "This computer's ID");
                    ui.monospace(unattended::short(self.unattended.machine_id()));
                    if ui.small_button("Copy ID").clicked() {
                        ui.ctx().copy_text(self.unattended.machine_id().to_owned());
                    }
                });
            }
        });
    }
    /// Control remote computer: where the other side's code goes.
    fn connect_card(&mut self, ui: &mut egui::Ui) {
        theme::card(ui, |ui| {
            ui.set_min_height(ui.available_height().max(360.0));
            theme::title(ui, "Control remote computer");
            theme::muted(
                ui,
                "Enter the code the other person gives you, or the ID of a computer with unattended access.",
            );
            ui.add_space(14.0);
            let idle = self.session.is_none() && !self.codes.busy();
            ui.add_enabled_ui(idle, |ui| {
                theme::caption(ui, "Partner code or ID");
                ui.add(
                    theme::field(&mut self.ticket, "1234 5678 9012")
                        .font(egui::FontId::monospace(17.0))
                        .char_limit(16384),
                );
                let machine =
                    boundary_session::unattended::validate_machine_id(self.ticket.trim()).is_ok();
                if machine {
                    ui.add_space(6.0);
                    theme::caption(ui, "Unattended password");
                    ui.add(
                        theme::field(&mut self.password, "Not needed if that computer paired you")
                            .password(true),
                    );
                }
                ui.add_space(6.0);
                theme::caption(ui, "Your name");
                ui.add(
                    theme::field(&mut self.name, "Shown to the person you are helping")
                        .char_limit(80),
                );
                ui.add_space(14.0);
                let ready = !self.name.trim().is_empty() && !self.ticket.trim().is_empty();
                if ui
                    .add_enabled(
                        ready,
                        theme::primary(ui, "Connect")
                            .min_size(egui::vec2(ui.available_width(), 46.0)),
                    )
                    .clicked()
                {
                    self.connect();
                }
            });
            if self.codes.resolving() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    theme::muted(ui, "Looking up the code");
                    if ui.small_button("Cancel").clicked() {
                        self.codes.clear();
                    }
                });
            }
            if !self.hosting && !self.codes.message().is_empty() {
                ui.colored_label(theme::pal(ui.ctx()).danger, self.codes.message());
            }
            if let Some((machine, name)) = self.paired.clone() {
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    theme::small(ui, format!("{name} lets you connect any time."));
                    if idle && ui.small_button("Use its ID").clicked() {
                        self.ticket = machine;
                    }
                });
            }
        });
    }
    /// The Settings page: everything that is not the two things people came
    /// for.
    fn settings(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(6.0);
            theme::card(ui, |ui| {
                theme::title(ui, "Screen to share");
                ui.add_space(6.0);
                egui::ComboBox::from_id_salt("display-settings")
                    .selected_text(
                        self.displays
                            .get(self.display)
                            .map(|d| d.name.as_str())
                            .unwrap_or("No display found"),
                    )
                    .show_ui(ui, |ui| {
                        for (index, display) in self.displays.iter().enumerate() {
                            ui.selectable_value(&mut self.display, index, &display.name);
                        }
                    });
                if !self.screen_permission {
                    theme::muted(ui, "Screen Recording permission is needed to share.");
                    if ui.button("Allow screen recording").clicked() {
                        boundary_platform::request_screen_permission();
                    }
                }
                if !self.input_permission {
                    theme::muted(ui, "Accessibility permission is needed for a helper to control this computer. Viewing works without it.");
                    if ui.button("Open Accessibility settings").clicked() {
                        let _ = boundary_platform::open_input_settings();
                    }
                }
            });
            ui.add_space(12.0);
            theme::card(ui, |ui| {
                theme::title(ui, "Unattended access");
                ui.add_space(6.0);
                self.unattended.settings(ui);
            });
            ui.add_space(12.0);
            theme::card(ui, |ui| {
                theme::title(ui, "Connection");
                ui.add_space(6.0);
                theme::muted(ui, self.network.label());
                if let Some(error) = &self.network_error {
                    ui.colored_label(theme::pal(ui.ctx()).danger, error);
                }
                if ui
                    .add_enabled(
                        self.session.is_none() && !self.codes.busy(),
                        egui::Button::new("Set up my infrastructure"),
                    )
                    .clicked()
                {
                    self.wizard.begin(&self.network);
                }
            });
            ui.add_space(12.0);
            theme::card(ui, |ui| {
                theme::title(ui, "Short codes");
                ui.add_space(6.0);
                self.codes.settings(ui);
            });
            ui.add_space(12.0);
            theme::small(
                ui,
                format!(
                    "DeskVNC Support {} · Attended and unattended support · No DeskVNC installation required",
                    env!("CARGO_PKG_VERSION")
                ),
            );
            ui.add_space(6.0);
        });
    }
    /// End this session, forget the permission the desktop remembered, and
    /// share again, so the desktop asks once more with its clipboard switch.
    fn share_again(&mut self, ctx: &egui::Context) {
        boundary_platform::forget_screen_grant();
        self.stop();
        self.share(ctx);
        self.status = SHARE_AGAIN_STATUS.into();
    }
    fn sharing(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        let mut again = false;
        theme::card(ui, |ui| {
            theme::title(ui, "Your screen is being shared");
            theme::muted(
                ui,
                "The helper can see the selected display, including notifications and this window.",
            );
            ui.add_space(14.0);
            let before = self.control;
            ui.add_enabled(
                self.input_permission,
                egui::Checkbox::new(
                    &mut self.control,
                    "Allow the helper to control my mouse and keyboard",
                ),
            );
            if before != self.control
                && let Some(session) = &self.session
            {
                session.set_control(self.control);
            }
            if !self.input_permission {
                theme::muted(
                    ui,
                    "Control needs Accessibility permission. Viewing works without it.",
                );
                if ui.button("Open Accessibility settings").clicked() {
                    let _ = boundary_platform::open_input_settings();
                }
            }
            if self.tools_offered {
                let before = self.tools;
                ui.checkbox(
                    &mut self.tools,
                    "Allow the helper's tools to run commands and copy files",
                );
                if before != self.tools
                    && let Some(session) = &self.session
                {
                    session.set_tools(self.tools);
                }
            }
            if self.clipboard_offered {
                let before = self.clipboard;
                ui.checkbox(&mut self.clipboard, SEE_WHAT_I_COPY);
                if before != self.clipboard
                    && let Some(session) = &self.session
                {
                    session.set_clipboard_read(self.clipboard);
                }
            }
            if let Some(note) = clipboard_note(
                self.clipboard_offered,
                boundary_platform::clipboard_left_out(),
            ) {
                theme::small(ui, note);
                again = ui
                    .button("Share again")
                    .on_hover_text(SHARE_AGAIN_HOVER)
                    .clicked();
            }
            if self.tools_offered || self.clipboard_offered {
                activity(ui, &self.activity);
            }
            ui.add_space(14.0);
            if let (Some((name, peer)), Some(session)) =
                (self.helper.clone(), self.session.as_ref())
            {
                if self.unattended.is_paired(&peer) {
                    theme::muted(ui, format!("{name} can connect to this computer any time. Remove them under Settings, Unattended access, to stop it."));
                } else if ui
                    .button(format!("Let {name} connect any time, even when I am away"))
                    .on_hover_text("They are remembered by their connection's key. You can remove them later under Settings.")
                    .clicked()
                {
                    // What they may do later starts as what they may do now.
                    self.unattended
                        .pair(session, &peer, &name, self.tools, self.clipboard);
                }
            }
            ui.add_space(14.0);
            theme::small(
                ui,
                "Use End session above to disconnect. Closing DeskVNC Support also ends sharing.",
            );
        });
        if again {
            self.share_again(ui.ctx());
        }
    }
    fn remote(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            theme::small(ui, remote_hint(self.control, self.rights));
            if let Some(text) = self.copied.as_ref() {
                let count = text.chars().count();
                if ui
                    .button("Copy what they copied")
                    .on_hover_text(format!(
                        "{count} characters. Puts them on your clipboard, replacing what is there."
                    ))
                    .clicked()
                {
                    ui.ctx().copy_text(text.clone());
                    self.status =
                        format!("Your clipboard now has the {count} characters they copied");
                    self.error = false;
                }
            }
        });
        let Some(texture) = self.texture.as_ref() else {
            ui.spinner();
            ui.label("Waiting for the first screen");
            return;
        };
        let size = texture.size_vec2();
        let available = ui.available_size();
        let factor = (available.x / size.x)
            .min(available.y / size.y)
            .clamp(0.1, 1.0);
        let response = ui.add(
            egui::Image::new((texture.id(), size * factor)).sense(egui::Sense::click_and_drag()),
        );
        if response.clicked()
            || (response.contains_pointer() && ui.ctx().input(|i| i.pointer.any_pressed()))
        {
            response.request_focus();
        }
        if response.has_focus() {
            ui.memory_mut(|memory| {
                memory.set_focus_lock_filter(
                    response.id,
                    egui::EventFilter {
                        tab: true,
                        horizontal_arrows: true,
                        vertical_arrows: true,
                        escape: true,
                    },
                )
            });
        }
        let active = self.control && response.has_focus() && ui.ctx().input(|i| i.focused);
        if self.remote_focus && !active {
            self.send(Input::Release);
            self.modifiers = egui::Modifiers::default();
        }
        self.remote_focus = active;
        if !active {
            return;
        }
        let (events, modifiers) = ui.ctx().input(|i| (i.events.clone(), i.modifiers));
        for (old, new, key) in [
            (self.modifiers.ctrl, modifiers.ctrl, Key::Control),
            (self.modifiers.shift, modifiers.shift, Key::Shift),
            (self.modifiers.alt, modifiers.alt, Key::Alt),
            (self.modifiers.mac_cmd, modifiers.mac_cmd, Key::Meta),
        ] {
            if old != new {
                self.send(Input::Key { key, down: new });
            }
        }
        self.modifiers = modifiers;
        for event in events {
            match event {
                egui::Event::PointerMoved(pos)
                    if response.rect.contains(pos) || response.dragged() =>
                {
                    self.send(Input::Move {
                        x: ((pos.x - response.rect.left()) / response.rect.width()).clamp(0.0, 1.0),
                        y: ((pos.y - response.rect.top()) / response.rect.height()).clamp(0.0, 1.0),
                    });
                }
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    ..
                } if response.rect.contains(pos) || !pressed => {
                    let button = match button {
                        egui::PointerButton::Primary => Some(Button::Left),
                        egui::PointerButton::Secondary => Some(Button::Right),
                        egui::PointerButton::Middle => Some(Button::Middle),
                        _ => None,
                    };
                    if let Some(button) = button {
                        if pressed {
                            self.send(Input::Move {
                                x: ((pos.x - response.rect.left()) / response.rect.width())
                                    .clamp(0.0, 1.0),
                                y: ((pos.y - response.rect.top()) / response.rect.height())
                                    .clamp(0.0, 1.0),
                            });
                        }
                        self.send(Input::Button {
                            button,
                            down: pressed,
                        });
                    }
                }
                egui::Event::Text(text) if !modifiers.ctrl && !modifiers.mac_cmd => {
                    self.send(Input::Text(text));
                }
                egui::Event::Paste(text) => match paste(text, self.rights) {
                    Paste::Clipboard(text) => self.paste_there(text),
                    Paste::Typed(chunks) => {
                        // The Control or Command of the paste reached the
                        // other computer already. Typing under it turns the
                        // text into shortcuts there (an "a" selects all), so
                        // it is let go first. Still held here, it goes down
                        // again on the next frame.
                        for key in held_for_shortcuts(self.modifiers) {
                            self.send(Input::Key { key, down: false });
                        }
                        self.modifiers.ctrl = false;
                        self.modifiers.alt = false;
                        self.modifiers.mac_cmd = false;
                        for chunk in chunks {
                            self.send(Input::Text(chunk));
                        }
                    }
                },
                egui::Event::Key {
                    key,
                    pressed,
                    modifiers,
                    ..
                } => {
                    if let Some(key) = remote_key(
                        key,
                        modifiers.ctrl || modifiers.mac_cmd || modifiers.alt || !pressed,
                    ) {
                        self.send(Input::Key { key, down: pressed });
                    }
                }
                egui::Event::MouseWheel { delta, .. } if response.hovered() && delta.y != 0.0 => {
                    self.send(Input::Scroll {
                        lines: if delta.y > 0.0 { -3 } else { 3 },
                    });
                }
                _ => {}
            }
        }
    }
}
/// Bring the window back from the tray, the Dock or the taskbar.
fn show(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
}
/// Set when the system asked the app to stop, so the next frame quits.
static TERMINATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if TERMINATED.load(std::sync::atomic::Ordering::Relaxed) && !self.quitting {
            self.quitting = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        // With unattended access on, the window closing must not take the
        // listener with it: that left a computer unreachable until somebody
        // opened the app again by hand. It goes to the Dock instead.
        if ctx.input(|i| i.viewport().close_requested())
            && self.unattended.enabled()
            && !self.quitting
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
            self.status = "Still running, so helpers can reach this computer. Turn off unattended access to quit.".into();
        }
        self.focused.store(
            ctx.input(|i| i.focused),
            std::sync::atomic::Ordering::Relaxed,
        );
        if self.hide_frames > 0 {
            self.hide_frames -= 1;
            // A question that came in during these first frames already
            // raised the window. Hiding it again would leave the question
            // waiting where nobody can see it.
            if attention::may_hide(self.pending.is_some() || self.unattended.asking()) {
                if self.tray.is_some() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                } else {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                }
            }
        }
        if let Some(tray) = self.tray.as_mut() {
            match tray.poll() {
                Some(tray::Action::Show) => show(ctx),
                Some(tray::Action::Quit) => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                None => {}
            }
            let line = match self.unattended.active.as_slice() {
                [one] => format!("{} is connected", one.name),
                [] if self.unattended.enabled() => "Waiting for helpers".to_owned(),
                [] => "Unattended access is off".to_owned(),
                many => format!("{} helpers are connected", many.len()),
            };
            tray.say(&line);
        }
        self.poll(ctx);
        if self.hide_frames > 0 {
            ctx.request_repaint();
        }
        wake::schedule(ctx, self.load());
    }
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(theme::pal(ui.ctx()).surface)
                    .inner_margin(Margin::symmetric(24, 10)),
            )
            .show(ui, |ui| self.status_bar(ui));
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::pal(ui.ctx()).canvas)
                    .inner_margin(Margin::symmetric(24, 14)),
            )
            .show(ui, |ui| self.content(ui));
    }
}
impl App {
    /// The bar every remote support tool has at the bottom: a dot, and what
    /// is going on.
    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let color = if self.error {
            theme::pal(ui.ctx()).danger
        } else if self.connected || self.session.is_none() {
            theme::pal(ui.ctx()).success
        } else {
            theme::pal(ui.ctx()).warning
        };
        let session = self.session.as_ref();
        let connected = self.connected;
        status_line(ui, color, &self.status, &self.network.label(), |ui| {
            let Some(session) = session else {
                return;
            };
            let connectivity = session.connectivity.borrow();
            if let Some(warning) = &connectivity.warning {
                ui.add(
                    egui::Label::new(RichText::new(warning).color(theme::pal(ui.ctx()).warning))
                        .wrap(),
                );
            }
            if connected && let Some(route) = connectivity.route {
                let label = match route {
                    boundary_session::Route::Direct => "Direct connection",
                    boundary_session::Route::Relay => "Relayed connection",
                    boundary_session::Route::Unknown => "Checking connection path",
                };
                let timing = connectivity
                    .rtt
                    .map(|rtt| format!(", round trip {} ms", rtt.as_millis()))
                    .unwrap_or_default();
                theme::small(ui, format!("{label}{timing}"));
            }
        });
    }
    fn content(&mut self, ui: &mut egui::Ui) {
        if let Some(profile) = self.wizard.show(ui.ctx()) {
            self.network = profile;
            self.network_error = None;
            self.status = "Network settings saved. Get a code to test with DeskVNC".into();
        }
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(APP_NAME)
                    .font(egui::FontId::new(
                        20.0,
                        egui::FontFamily::Name("system-bold".into()),
                    ))
                    .color(theme::pal(ui.ctx()).text),
            );
            ui.add_space(4.0);
            theme::muted(ui, "Remote support");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.session.is_some() {
                    if ui.add(theme::danger(ui, "End session")).clicked() {
                        self.stop();
                    }
                } else if self.page == Page::Settings {
                    if ui.button("Done").clicked() {
                        self.page = Page::Home;
                    }
                } else if ui.button("Settings").clicked() {
                    self.page = Page::Settings;
                }
            });
        });
        ui.add_space(10.0);
        self.move_banner(ui);
        self.unattended.login_notice(ui);
        self.unattended.banner(ui);
        self.unattended.prompt(ui.ctx(), self.input_permission);
        if self.connected && self.hosting {
            self.sharing(ui);
        } else if self.connected {
            self.remote(ui);
        } else if self.page == Page::Settings {
            self.settings(ui);
        } else {
            self.home(ui);
        }
        if let Some(pending) = self.pending.as_mut() {
            let mut decision = None;
            egui::Window::new("Approve this helper?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ui.ctx(), |ui| {
                    ui.set_width(420.0);
                    ui.label(
                        RichText::new(format!("{} wants to see your screen.", pending.name))
                            .size(15.0),
                    );
                    theme::small(ui, "The name is supplied by the helper. Confirm it with the person you invited.");
                    ui.add_space(6.0);
                    theme::caption(ui, "Helper connection identity");
                    ui.monospace(&pending.peer);
                    if pending.tools {
                        ui.add_space(10.0);
                        ui.checkbox(
                            &mut pending.allow_tools,
                            "Also let their tools run commands and copy files on this computer",
                        );
                        theme::small(ui, "Their tools act as you, outside what the screen shows. Leave this off unless you asked for it. You can turn it off at any time, and each command shows here as it runs.");
                    }
                    if pending.clipboard {
                        ui.add_space(10.0);
                        ui.checkbox(&mut pending.allow_clipboard, SEE_WHAT_I_COPY);
                        theme::small(ui, SEE_WHAT_I_COPY_NOTE);
                    }
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                self.input_permission,
                                theme::primary(ui, "Allow viewing and control"),
                            )
                            .clicked()
                        {
                            decision = Some(Approval::Control);
                        }
                        if ui.button("Allow viewing").clicked() {
                            decision = Some(Approval::View);
                        }
                        if ui.button("Decline").clicked() {
                            decision = Some(Approval::Deny);
                        }
                    });
                    if !self.input_permission {
                        theme::small(ui, "Accessibility permission is needed for control. You can allow viewing now.");
                    } else if let Some(hint) = boundary_platform::control_hint() {
                        theme::small(ui, hint);
                    }
                });
            if let Some(decision) = decision
                && let Some(pending) = self.pending.take()
            {
                let allow = pending.allow_tools && !matches!(decision, Approval::Deny);
                let read = clipboard_read(&pending, &decision);
                if let Some(session) = &self.session {
                    // Set before the answer, so the grant the helper reads
                    // already says it.
                    session.set_tools(allow);
                    session.set_clipboard_read(read);
                }
                self.tools_offered = pending.tools;
                self.tools = allow;
                self.clipboard_offered = pending.clipboard;
                self.clipboard = read;
                let _ = pending.answer.send(decision);
            }
        }
    }
}
/// The tick that lets a helper see what the person copies, in the approval
/// prompt and on the sharing screen.
pub(crate) const SEE_WHAT_I_COPY: &str = "Also let them see what I copy";
pub(crate) const SEE_WHAT_I_COPY_NOTE: &str = "Text you copy while they are connected goes to them, and that is sometimes a password. Leave this off unless you need it. You can turn it off at any time.";
/// The line under the clipboard tick when the desktop's remembered sharing
/// permission leaves the clipboard out, as a GNOME grant saved by Support
/// 0.34 does. Only for a helper that can use the clipboard at all, and only
/// on this screen, which is the one the person at the computer sees: an
/// unattended session keeps the old grant, since nobody is there to answer
/// the prompt again.
fn clipboard_note(offered: bool, left_out: Option<&'static str>) -> Option<&'static str> {
    left_out.filter(|_| offered)
}
const SHARE_AGAIN_HOVER: &str = "Ends this session and forgets the permission your desktop remembered, so it asks again. Your helper connects again with the new code.";
const SHARE_AGAIN_STATUS: &str = "Sharing again. Give your helper the new code. When your desktop asks which screen to share, leave Allow Clipboard Access on";
/// What this copy of Support says it can do when it connects as a helper:
/// take and give clipboard text, which the person there still has to allow.
fn abilities() -> Abilities {
    Abilities {
        clipboard: true,
        ..Abilities::default()
    }
}
/// Whether the person's answer lets the helper see what they copy: only
/// when the helper can take it, the person ticked it, and they let them in.
fn clipboard_read(pending: &Pending, decision: &Approval) -> bool {
    pending.clipboard && pending.allow_clipboard && !matches!(decision, Approval::Deny)
}
/// The line over the remote screen: what this helper may do there.
fn remote_hint(control: bool, rights: ClipboardRights) -> &'static str {
    match (control, rights.write, rights.read) {
        (true, true, true) => {
            "Control allowed. Click the remote screen to send input. Click outside it to release input. Pasting puts your text on their clipboard, and what they copy comes to you."
        }
        (true, true, false) => {
            "Control allowed. Click the remote screen to send input. Click outside it to release input. Pasting puts your text on their clipboard."
        }
        (true, false, true) => {
            "Control allowed. Click the remote screen to send input. Click outside it to release input. What they copy comes to you."
        }
        (true, false, false) => {
            "Control allowed. Click the remote screen to send input. Click outside it to release input."
        }
        (false, _, true) => {
            "View only. The person sharing can allow control from their window. What they copy comes to you."
        }
        (false, _, false) => "View only. The person sharing can allow control from their window.",
    }
}
/// What a paste into the remote screen becomes.
#[derive(Debug, PartialEq, Eq)]
enum Paste {
    /// Put on their clipboard, then pasted there with the keys the helper
    /// pressed. Only while they let this helper write their clipboard.
    Clipboard(String),
    /// Typed into whatever has focus there, in pieces, as before clipboards
    /// were shared.
    Typed(Vec<String>),
}
fn paste(text: String, rights: ClipboardRights) -> Paste {
    if rights.write {
        Paste::Clipboard(text)
    } else {
        Paste::Typed(
            text.chars()
                .collect::<Vec<_>>()
                .chunks(200)
                .map(|chunk| chunk.iter().collect())
                .collect(),
        )
    }
}
/// The modifiers the other computer holds down for this helper that turn
/// typed letters into shortcuts.
fn held_for_shortcuts(modifiers: egui::Modifiers) -> Vec<Key> {
    [
        (modifiers.ctrl, Key::Control),
        (modifiers.alt, Key::Alt),
        (modifiers.mac_cmd, Key::Meta),
    ]
    .into_iter()
    .filter_map(|(held, key)| held.then_some(key))
    .collect()
}
/// What the sharing card says about what the person gives their helper.
struct ShareWords {
    creating: &'static str,
    expiry: &'static str,
}
/// The words for a short code when a code service is set, and for the full
/// invitation otherwise. No release build names a shared code service, so
/// without one set in Settings the person gets an invitation, and the card
/// said "Creating your code" and "One code per session" over it.
fn share_words(code: bool) -> ShareWords {
    if code {
        ShareWords {
            creating: "Creating your code",
            expiry: "One code per session. It expires after 10 minutes if nobody connects.",
        }
    } else {
        ShareWords {
            creating: "Creating your invitation",
            expiry: "One invitation per session. It expires after 10 minutes if nobody connects.",
        }
    }
}
/// The status line while this computer waits for a helper, with `left`
/// until its code or invitation expires.
fn waiting(code: bool, left: Duration) -> String {
    let what = if code { "code" } else { "invitation" };
    // Rounded up: "1 minute" lasts until it has gone, never "0 minutes".
    match left.as_secs().div_ceil(60) {
        0 => format!("Waiting for your helper. The {what} has expired"),
        1 => format!("Waiting for your helper. The {what} expires in less than a minute"),
        minutes => format!("Waiting for your helper. The {what} expires in {minutes} minutes"),
    }
}
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
/// The status line: a dot, what is going on, then `more`, with the network
/// setting at the right. The setting is laid out first and the rest wraps in
/// the space left of it, so a long error goes onto more lines instead of
/// running over the setting and out of the window. Returns where the status
/// and the setting were drawn.
fn status_line(
    ui: &mut egui::Ui,
    color: egui::Color32,
    status: &str,
    setting: &str,
    more: impl FnOnce(&mut egui::Ui),
) -> (egui::Rect, egui::Rect) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
        let setting = ui
            .label(
                RichText::new(setting)
                    .size(12.0)
                    .color(theme::pal(ui.ctx()).text_tertiary),
            )
            .rect;
        ui.add_space(16.0);
        let status = ui
            .with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
                // Beside the first line, however many lines the status takes.
                theme::dot(ui, color);
                ui.vertical(|ui| {
                    let status = ui
                        .add(
                            egui::Label::new(
                                RichText::new(status).color(theme::pal(ui.ctx()).text),
                            )
                            .wrap(),
                        )
                        .rect;
                    ui.horizontal_wrapped(more);
                    status
                })
                .inner
            })
            .inner;
        (status, setting)
    })
    .inner
}
/// What a helper's tools did, and the clipboard text that went either way
/// (its length only), newest last, so the person at the computer can see it.
pub(crate) fn activity(ui: &mut egui::Ui, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    ui.add_space(6.0);
    theme::caption(ui, "What they did");
    for line in lines {
        theme::small(ui, line);
    }
}
fn remote_key(key: egui::Key, shortcut: bool) -> Option<Key> {
    use egui::Key as E;
    Some(match key {
        E::Enter => Key::Enter,
        E::Tab => Key::Tab,
        E::Escape => Key::Escape,
        E::Backspace => Key::Backspace,
        E::Delete => Key::Delete,
        E::ArrowLeft => Key::Left,
        E::ArrowRight => Key::Right,
        E::ArrowUp => Key::Up,
        E::ArrowDown => Key::Down,
        E::Home => Key::Home,
        E::End => Key::End,
        E::PageUp => Key::PageUp,
        E::PageDown => Key::PageDown,
        _ if shortcut => {
            let name = key.name();
            if name.len() != 1 {
                return None;
            }
            let c = name.chars().next()?.to_ascii_lowercase();
            if !c.is_ascii_alphanumeric() {
                return None;
            }
            Key::Letter(c)
        }
        _ => return None,
    })
}

/// What the status bar says when a session finishes on its own, and whether
/// in red: `None` keeps what stopping it said. `shared` is whether this
/// computer's screen was being shared with a helper who was in.
fn ended_status(shared: bool, result: &anyhow::Result<()>) -> Option<(String, bool)> {
    match result {
        Err(error) => Some((format!("{error:#}"), true)),
        Ok(()) if shared => Some(("They ended the session. Ready to connect".into(), false)),
        Ok(()) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A helper ending the session is said plainly and not in red; only a
    /// session that failed is an error.
    #[test]
    fn a_session_the_helper_ends_is_not_an_error() {
        assert_eq!(
            ended_status(true, &Ok(())),
            Some(("They ended the session. Ready to connect".into(), false))
        );
        assert_eq!(ended_status(false, &Ok(())), None);
        let (status, error) = ended_status(
            true,
            &Err(anyhow::anyhow!("This computer stopped taking input")),
        )
        .unwrap();
        assert!(error);
        assert_eq!(status, "This computer stopped taking input");
    }

    #[test]
    fn an_old_grant_is_explained_beside_the_clipboard_tick() {
        let line = "This computer's sharing permission is from an older version";
        assert_eq!(clipboard_note(true, Some(line)), Some(line));
        // A helper that cannot use the clipboard has no tick to explain.
        assert_eq!(clipboard_note(false, Some(line)), None);
        // The grant has the clipboard, or the desktop has none to give.
        assert_eq!(clipboard_note(true, None), None);
    }

    fn args(list: &[&str]) -> Vec<String> {
        std::iter::once("deskvnc-support")
            .chain(list.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn help_and_version_print_instead_of_opening_the_window() {
        let version = format!("DeskVNC Support {}\n", env!("CARGO_PKG_VERSION"));
        assert_eq!(information(&args(&["--version"])), Some(version.clone()));
        assert_eq!(information(&args(&["-V"])), Some(version.clone()));
        for flag in ["--help", "-h"] {
            let help = information(&args(&[flag])).expect("help is printed");
            assert!(help.starts_with(&version), "{help}");
            assert!(help.contains("--version"));
            assert!(help.contains("--background"));
            assert_eq!(help.contains("--install"), cfg!(target_os = "linux"));
        }
    }

    #[test]
    fn other_runs_still_open_the_app() {
        assert_eq!(information(&args(&[])), None);
        assert_eq!(information(&args(&["--background"])), None);
        assert_eq!(information(&args(&["--install"])), None);
        // Only the first argument counts.
        assert_eq!(information(&args(&["--background", "--help"])), None);
    }

    #[test]
    fn an_invitation_is_never_called_a_code() {
        let invitation = share_words(false);
        for line in [invitation.creating, invitation.expiry] {
            assert!(!line.contains("code"), "{line}");
            assert!(line.contains("invitation"), "{line}");
        }
        let code = share_words(true);
        for line in [code.creating, code.expiry] {
            assert!(line.contains("code"), "{line}");
        }
    }

    #[test]
    fn the_waiting_line_counts_down_to_expiry() {
        let at = |seconds| waiting(false, Duration::from_secs(seconds));
        assert_eq!(
            at(600),
            "Waiting for your helper. The invitation expires in 10 minutes"
        );
        // Eight minutes in, as the person saw it still saying ten.
        assert_eq!(
            at(120),
            "Waiting for your helper. The invitation expires in 2 minutes"
        );
        assert_eq!(
            at(61),
            "Waiting for your helper. The invitation expires in 2 minutes"
        );
        assert_eq!(
            at(60),
            "Waiting for your helper. The invitation expires in less than a minute"
        );
        assert_eq!(at(0), "Waiting for your helper. The invitation has expired");
        assert_eq!(
            waiting(true, Duration::from_secs(300)),
            "Waiting for your helper. The code expires in 5 minutes"
        );
    }

    #[test]
    fn a_long_status_wraps_beside_the_network_setting_instead_of_over_it() {
        // The error a helper saw for a computer that could not be found.
        let status = "Cannot reach the computer: No addressing information available: \
            All address lookup services failed or produced no results. \
            Service 'pkarr' failed: Error resolving http request. \
            Service 'dns' failed: no calls succeeded: Failed to resolve TXT record";
        let ctx = egui::Context::default();
        let mut drawn = None;
        for _ in 0..2 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(820.0, 600.0),
                )),
                ..Default::default()
            };
            let mut output = ctx.run_ui(input, |ui| {
                egui::Panel::bottom("status").show(ui, |ui| {
                    drawn = Some(status_line(
                        ui,
                        egui::Color32::RED,
                        status,
                        "Automatic connection with relay fallback",
                        |_| {},
                    ));
                });
            });
            // No renderer here to upload the font atlas to.
            output.textures_delta.clear();
        }
        let (status, setting) = drawn.expect("the status line was drawn");
        assert!(
            !status.intersects(setting),
            "status {status:?} runs into the setting {setting:?}"
        );
        assert!(status.max.x <= 820.0, "status {status:?} leaves the window");
        assert!(
            setting.max.x <= 820.0,
            "setting {setting:?} leaves the window"
        );
        // All of it is there, on more than one line.
        assert!(status.height() > 30.0, "status {status:?} was cut short");
        assert!(status.height() < 100.0, "status {status:?} spread out");
    }

    #[test]
    fn the_window_says_deskvnc_support_and_pairs_with_its_desktop_file() {
        let window = viewport(false);
        assert_eq!(window.title.as_deref(), Some("DeskVNC Support"));
        // The dock matches this to deskvnc-support.desktop for the icon.
        assert_eq!(window.app_id.as_deref(), Some("deskvnc-support"));
        let icon = window.icon.expect("the window carries the app's icon");
        assert_eq!((icon.width, icon.height), (256, 256));
    }

    fn asked(clipboard: bool) -> Pending {
        Pending {
            name: "Sam".into(),
            peer: "peer".into(),
            tools: false,
            allow_tools: false,
            clipboard,
            allow_clipboard: false,
            answer: oneshot::channel().0,
        }
    }

    #[test]
    fn what_i_copy_stays_private_until_the_person_ticks_it() {
        // The prompt opens with the tick off, so letting a helper in, even
        // with control, does not hand them what the person copies.
        let mut pending = asked(true);
        assert!(!pending.allow_clipboard);
        assert!(!clipboard_read(&pending, &Approval::Control));
        assert!(!clipboard_read(&pending, &Approval::View));
        pending.allow_clipboard = true;
        assert!(clipboard_read(&pending, &Approval::Control));
        assert!(clipboard_read(&pending, &Approval::View));
        // Declining lets nothing through, whatever was ticked.
        assert!(!clipboard_read(&pending, &Approval::Deny));
        // A helper that cannot take clipboard text is never offered it.
        let mut old = asked(false);
        old.allow_clipboard = true;
        assert!(!clipboard_read(&old, &Approval::Control));
    }

    #[test]
    fn a_paste_goes_as_clipboard_only_while_they_let_this_helper_write() {
        let text = "x".repeat(450);
        let write = ClipboardRights {
            write: true,
            read: false,
        };
        assert_eq!(paste(text.clone(), write), Paste::Clipboard(text.clone()));
        // Being shown what they copy is not leave to change their clipboard.
        for rights in [
            ClipboardRights::default(),
            ClipboardRights {
                write: false,
                read: true,
            },
        ] {
            let Paste::Typed(chunks) = paste(text.clone(), rights) else {
                panic!("without write the paste is typed, as before");
            };
            assert_eq!(
                chunks.iter().map(|c| c.chars().count()).collect::<Vec<_>>(),
                [200, 200, 50]
            );
            assert_eq!(chunks.concat(), text);
        }
    }

    #[test]
    fn support_as_a_helper_says_it_can_carry_clipboard_text() {
        let abilities = abilities();
        assert!(abilities.clipboard);
        // Nothing else it does not do: it sends no commands and draws no video.
        assert!(!abilities.tools);
        assert!(!abilities.video);
    }

    #[test]
    fn the_helper_is_told_what_happens_to_a_paste() {
        let none = ClipboardRights::default();
        let write = ClipboardRights {
            write: true,
            read: false,
        };
        assert!(!remote_hint(true, none).contains("clipboard"));
        assert!(remote_hint(true, write).contains("Pasting puts your text on their clipboard"));
        assert!(remote_hint(false, write).starts_with("View only"));
        assert!(!remote_hint(false, write).contains("Pasting"));
    }

    #[test]
    fn a_typed_paste_lets_go_of_control_first_so_letters_stay_letters() {
        // Ctrl+V on Linux and Windows, Cmd+V on a Mac: either is down on the
        // other computer when the paste arrives.
        let ctrl = egui::Modifiers {
            ctrl: true,
            command: true,
            ..Default::default()
        };
        assert_eq!(held_for_shortcuts(ctrl), [Key::Control]);
        let cmd = egui::Modifiers {
            mac_cmd: true,
            command: true,
            ..Default::default()
        };
        assert_eq!(held_for_shortcuts(cmd), [Key::Meta]);
        // Shift changes no letter into a shortcut, so it stays down.
        assert!(held_for_shortcuts(egui::Modifiers::SHIFT).is_empty());
    }
}
