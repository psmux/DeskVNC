//! Get help: this computer shared over Boundary, from inside DeskVNC.
//!
//! Everything DeskVNC Support does for the person being helped is here too,
//! so someone who already has DeskVNC needs nothing else: a code or an
//! invitation, approving the helper, control and their tools as separate
//! choices, what the tools did, pairing, and unattended access with its
//! helpers, password and start at sign in.
//!
//! Both apps keep their files in the same Boundary data folder. A computer
//! with both has one ID, one list of paired helpers and one connection mode,
//! and a lock lets only one of them answer unattended connections at a time.
//!
//! The model is polled, the way the Support app's window polls it: a task
//! drains the session, the listener and the code service every 150 ms, and
//! the main window is sent a fresh [`View`] whenever it changed. Every
//! command polls and sends straight after it acts, so nothing waits a tick.

use boundary_provision::{autostart, network::Profile};
use boundary_session::{
    unattended::{self, Access, Listener, Notice, SecretKey, MIN_PASSWORD},
    Approval, Event, Session,
};
use parking_lot::Mutex;
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

/// The event the main window listens on for a new [`View`].
pub const SUPPORT_EVENT: &str = "support://state";
/// How many lines of what a helper's tools did are kept on screen.
const ACTIVITY_LINES: usize = 8;
/// DeskVNC's own sign in entry, separate from DeskVNC Support's.
const AUTOSTART: autostart::Entry = autostart::Entry {
    name: "DeskVNC",
    label: "com.deskvncviewer.desktop.background",
    file: "deskvnc",
};
/// How often a switched on but stopped listener tries again, for when
/// DeskVNC Support held the lock and has since quit.
const RETRY: Duration = Duration::from_secs(15);

pub struct Support {
    model: Mutex<Model>,
    /// The last view sent, so an unchanged one is not sent again.
    sent: Mutex<serde_json::Value>,
}

struct Pending {
    name: String,
    peer: String,
    tools: bool,
    answer: oneshot::Sender<Approval>,
}

/// A helper connected with nobody's approval, held so the person at the
/// computer can see it and end it.
struct Active {
    /// Stays the same for the whole session, so a click lands on the helper
    /// it was meant for even if another one left in the meantime.
    id: u64,
    name: String,
    control: bool,
    tools: bool,
    activity: Vec<String>,
    session: Session,
}

/// A helper that is not paired, and has no password, asking to come in by
/// this computer's ID. Nobody answering within a minute turns them away.
struct Ask {
    name: String,
    peer: String,
    tools: bool,
    answer: oneshot::Sender<unattended::Asked>,
}

struct Codes {
    lease: Option<boundary_codes::Lease>,
    pending: Option<(
        JoinHandle<()>,
        oneshot::Receiver<anyhow::Result<boundary_codes::Lease>>,
    )>,
    message: String,
}
impl Codes {
    fn clear(&mut self) {
        if let Some((task, _)) = self.pending.take() {
            task.abort();
        }
        self.lease = None;
        self.message.clear();
    }
}

struct Model {
    displays: Vec<boundary_platform::Display>,
    display: Option<u32>,
    screen_permission: bool,
    input_permission: bool,
    permission_check: Instant,
    network: Profile,
    network_error: Option<String>,
    code_service: String,
    codes: Codes,
    session: Option<Session>,
    connected: bool,
    control: bool,
    tools_offered: bool,
    tools: bool,
    activity: Vec<String>,
    invitation: String,
    status: String,
    error: bool,
    pending: Option<Pending>,
    approved_name: String,
    helper: Option<(String, String)>,
    // Unattended access.
    access_path: PathBuf,
    machine: String,
    key: Option<SecretKey>,
    access: Access,
    listener: Option<Listener>,
    claim: Option<std::fs::File>,
    /// Every helper in unattended right now; up to the listener's limit.
    active: Vec<Active>,
    next_active: u64,
    ask: Option<Ask>,
    reachable: bool,
    message: String,
    message_error: bool,
    autostart: bool,
    last_start: Option<Instant>,
}

/// What the window shows. Rebuilt from the model on every poll.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    displays: Vec<DisplayView>,
    display: Option<u32>,
    screen_permission: bool,
    input_permission: bool,
    status: String,
    error: bool,
    /// A session of ours is running: creating, waiting or connected.
    sharing: bool,
    connected: bool,
    invitation: Option<String>,
    code: Option<String>,
    code_busy: bool,
    codes_available: bool,
    code_message: String,
    code_service: String,
    pending: Option<PendingView>,
    helper: Option<HelperView>,
    control: bool,
    tools_offered: bool,
    tools: bool,
    activity: Vec<String>,
    route: Option<String>,
    warning: Option<String>,
    network: Profile,
    network_label: String,
    network_error: Option<String>,
    unattended: UnattendedView,
}
#[derive(Serialize)]
struct DisplayView {
    id: u32,
    name: String,
}
#[derive(Serialize)]
struct PendingView {
    name: String,
    peer: String,
    tools: bool,
}
#[derive(Serialize)]
struct HelperView {
    name: String,
    peer: String,
    paired: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnattendedView {
    enabled: bool,
    reachable: bool,
    machine_id: String,
    autostart: bool,
    helpers: Vec<unattended::Helper>,
    has_password: bool,
    min_password: usize,
    message: String,
    error: bool,
    active: Vec<ActiveView>,
    ask: Option<PendingView>,
}
#[derive(Serialize)]
struct ActiveView {
    id: u64,
    name: String,
    control: bool,
    tools: bool,
    activity: Vec<String>,
}

fn keep(activity: &mut Vec<String>, line: String) {
    activity.push(line);
    let excess = activity.len().saturating_sub(ACTIVITY_LINES);
    activity.drain(..excess);
}

impl Model {
    fn new() -> Self {
        let (displays, status, error) = match boundary_platform::displays() {
            Ok(displays) => (displays, "Ready".to_string(), false),
            Err(error) => (vec![], format!("Could not list displays: {error:#}"), true),
        };
        let (network, network_error) = match boundary_provision::network::load() {
            Ok(profile) => (profile, None),
            Err(error) => (Profile::default(), Some(error.to_string())),
        };
        let mut model = Self {
            display: displays.first().map(|d| d.id),
            displays,
            screen_permission: boundary_platform::screen_permission(),
            input_permission: boundary_platform::input_permission(),
            permission_check: Instant::now(),
            network,
            network_error,
            code_service: String::new(),
            codes: Codes {
                lease: None,
                pending: None,
                message: String::new(),
            },
            session: None,
            connected: false,
            control: false,
            tools_offered: false,
            tools: false,
            activity: Vec::new(),
            invitation: String::new(),
            status,
            error,
            pending: None,
            approved_name: String::new(),
            helper: None,
            access_path: PathBuf::new(),
            machine: String::new(),
            key: None,
            access: Access::default(),
            listener: None,
            claim: None,
            active: Vec::new(),
            next_active: 0,
            ask: None,
            reachable: false,
            message: String::new(),
            message_error: false,
            autostart: autostart::enabled(AUTOSTART),
            last_start: None,
        };
        match load_unattended() {
            Ok((path, key, access)) => {
                model.machine = unattended::machine_id(&key);
                model.access_path = path;
                model.key = Some(key);
                model.access = access;
            }
            Err(error) => model.fail(format!("{error:#}")),
        }
        model
    }

    fn fail(&mut self, message: String) {
        self.message = message;
        self.message_error = true;
    }
    fn say(&mut self, message: impl Into<String>) {
        self.message = message.into();
        self.message_error = false;
    }

    // ---- attended ----

    /// Whether a code service can be used at all: the shared one, or the
    /// private one the person set. Private infrastructure never falls back
    /// to the shared service.
    fn codes_available(&self) -> bool {
        if self.code_service.trim().is_empty() {
            matches!(self.network, Profile::Automatic)
                && !boundary_codes::default_service().is_empty()
        } else {
            true
        }
    }
    fn publish_code(&mut self, ticket: String) {
        let client = match boundary_codes::Client::new(&self.code_service) {
            Ok(client) => client,
            Err(error) => {
                self.codes.message = error.to_string();
                return;
            }
        };
        let (send, reply) = oneshot::channel();
        self.codes.message.clear();
        let task = tokio::spawn(async move {
            let _ = send.send(client.register(ticket).await);
        });
        self.codes.pending = Some((task, reply));
    }
    fn share(&mut self) -> Result<(), String> {
        if self.session.is_some() {
            return Err("This computer is already being shared".into());
        }
        if let Some(error) = &self.network_error {
            return Err(error.clone());
        }
        if !self.screen_permission {
            return Err("Screen Recording permission is needed to share".into());
        }
        let id = self
            .display
            .filter(|id| self.displays.iter().any(|d| d.id == *id))
            .ok_or("No display found to share")?;
        self.error = false;
        self.status = "Creating your code".into();
        self.session = Some(boundary_session::host(self.network.options(), move || {
            boundary_platform::open(id)
        }));
        Ok(())
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
        self.activity.clear();
        self.invitation.clear();
        self.helper = None;
        self.status = "Session ended".into();
        self.error = false;
    }
    fn answer(&mut self, decision: Approval, allow_tools: bool) -> Result<(), String> {
        let pending = self
            .pending
            .take()
            .ok_or("Nobody is waiting for an answer")?;
        let allow = pending.tools && allow_tools && !matches!(decision, Approval::Deny);
        if let Some(session) = &self.session {
            // Set before the answer, so the grant the helper reads already
            // says it.
            session.set_tools(allow);
        }
        self.tools_offered = pending.tools;
        self.tools = allow;
        self.approved_name = pending.name;
        let _ = pending.answer.send(decision);
        Ok(())
    }
    fn pair(&mut self) -> Result<(), String> {
        let (name, peer) = self.helper.clone().ok_or("No helper is connected")?;
        if self.session.is_none() {
            return Err("No helper is connected".into());
        }
        self.access
            .trust(&peer, &name, true)
            .map_err(|e| format!("{e:#}"))?;
        // What they may do later starts as what they may do now.
        self.access.allow_tools(&peer, self.tools);
        self.access.enabled = true;
        self.save()?;
        self.session
            .as_ref()
            .ok_or("No helper is connected")?
            .offer_pairing(
                self.machine.clone(),
                boundary_provision::platform::computer_name(),
            )
            .map_err(|e| format!("{e:#}"))?;
        self.start_listener();
        self.say(format!(
            "{name} can now connect to this computer any time. Remove them under Unattended access to stop it"
        ));
        Ok(())
    }

    // ---- unattended ----

    fn save(&mut self) -> Result<(), String> {
        self.access.save(&self.access_path).map_err(|error| {
            let message = format!("{error:#}");
            self.fail(message.clone());
            message
        })
    }
    fn start_listener(&mut self) {
        let Some(key) = self.key.clone() else { return };
        if self.listener.is_some() {
            return;
        }
        self.last_start = Some(Instant::now());
        // The primary display: nobody is there to pick another.
        let Some(display) = self.displays.first().map(|d| d.id) else {
            self.fail("No display found to share unattended".into());
            return;
        };
        match boundary_provision::platform::claim_unattended() {
            Ok(Some(claim)) => self.claim = Some(claim),
            Ok(None) => {
                self.fail("DeskVNC Support on this computer is already answering unattended connections. DeskVNC takes over when it quits".into());
                return;
            }
            Err(error) => {
                self.fail(format!("{error:#}"));
                return;
            }
        }
        self.listener = Some(unattended::listen(
            boundary_session::HostOptions::default(),
            key,
            self.access_path.clone(),
            move || boundary_platform::open(display),
        ));
        self.say("Starting unattended access");
    }
    fn halt(&mut self) {
        self.listener = None;
        self.claim = None;
        self.active.clear();
        // Dropping the answer turns the helper away.
        self.ask = None;
        self.reachable = false;
    }
    fn set_unattended(&mut self, enabled: bool) -> Result<(), String> {
        self.access.enabled = enabled;
        self.save()?;
        if enabled {
            self.start_listener();
        } else {
            self.halt();
            self.say("Unattended access is off. Nobody can connect without your approval");
        }
        Ok(())
    }

    // ---- polling ----

    /// Drain everything. `true` when the window should come forward: a
    /// helper is asking to be let in, or came in unattended.
    fn poll(&mut self) -> bool {
        let mut raise = false;
        if self.permission_check.elapsed() > Duration::from_secs(1) {
            self.screen_permission = boundary_platform::screen_permission();
            self.input_permission = boundary_platform::input_permission();
            self.permission_check = Instant::now();
        }
        if let Some((_, reply)) = self.codes.pending.as_mut() {
            match reply.try_recv() {
                Ok(result) => {
                    self.codes.pending = None;
                    match result {
                        Ok(lease) => self.codes.lease = Some(lease),
                        Err(error) => self.codes.message = error.to_string(),
                    }
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.codes.pending = None;
                    self.codes.message = "Code request stopped".into();
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        let mut finished = None;
        let mut invitation = None;
        if let Some(session) = self.session.as_mut() {
            while let Ok(event) = session.events.try_recv() {
                match event {
                    Event::Status(status) => {
                        self.status = status;
                        self.error = false;
                    }
                    Event::Invitation(ticket) => invitation = Some(ticket),
                    Event::Approval {
                        name,
                        peer,
                        tools,
                        answer,
                    } => {
                        self.pending = Some(Pending {
                            name,
                            peer,
                            tools,
                            answer,
                        });
                        raise = true;
                    }
                    Event::Connected { peer, control } => {
                        self.codes.clear();
                        self.pending = None;
                        self.connected = true;
                        self.control = control;
                        self.invitation.clear();
                        self.status = format!("Connected to {}", &peer[..16.min(peer.len())]);
                        self.helper = Some((self.approved_name.clone(), peer));
                    }
                    Event::Control(control) => self.control = control,
                    // On the helper's side only.
                    Event::Tools(_) | Event::Paired { .. } => {}
                    Event::Activity(line) => keep(&mut self.activity, line),
                    Event::Finished(result) => finished = Some(result),
                }
            }
        }
        if let Some(ticket) = invitation {
            // With a code service the invitation becomes a short code on its
            // own, so the code is simply there.
            let codes = self.codes_available();
            if codes {
                self.publish_code(ticket.clone());
            }
            self.invitation = ticket;
            self.status = if codes {
                "Waiting for your helper. The code expires in 10 minutes".into()
            } else {
                "Waiting for your helper. The invitation expires in 10 minutes".into()
            };
        }
        if self.pending.as_ref().is_some_and(|p| p.answer.is_closed()) {
            self.pending = None;
        }
        if let Some(result) = finished {
            self.stop();
            if let Err(error) = result {
                self.status = format!("{error:#}");
                self.error = true;
            }
        }
        raise |= self.poll_unattended();
        raise
    }

    fn poll_unattended(&mut self) -> bool {
        let mut arrived = false;
        let mut finished = None;
        if let Some(listener) = self.listener.as_mut() {
            while let Ok(notice) = listener.notices.try_recv() {
                match notice {
                    Notice::Ready { .. } => {
                        self.reachable = true;
                        self.message =
                            "Unattended access is on. Paired helpers can connect any time".into();
                        self.message_error = false;
                    }
                    Notice::Status(status) => {
                        self.message = status;
                        self.message_error = false;
                    }
                    Notice::Connected {
                        name,
                        control,
                        session,
                        ..
                    } => {
                        // A helper the person just chose to pair was saved
                        // before it was let in; show the list as it now is.
                        if let Ok(access) = Access::load(&self.access_path) {
                            self.access = access;
                        }
                        self.next_active += 1;
                        self.active.push(Active {
                            id: self.next_active,
                            name,
                            control,
                            tools: session.tools_allowed(),
                            activity: Vec::new(),
                            session,
                        });
                        arrived = true;
                    }
                    Notice::Ask {
                        name,
                        peer,
                        tools,
                        answer,
                    } => {
                        self.ask = Some(Ask {
                            name,
                            peer,
                            tools,
                            answer,
                        });
                        arrived = true;
                    }
                    Notice::Refused { name, reason, .. } => {
                        self.message = format!("Turned away {name}: {reason}");
                        self.message_error = false;
                    }
                    Notice::Finished(result) => finished = Some(result),
                }
            }
        }
        if self.ask.as_ref().is_some_and(|ask| ask.answer.is_closed()) {
            // The helper gave up, or nobody answered in time.
            self.ask = None;
        }
        self.active.retain_mut(|active| loop {
            match active.session.events.try_recv() {
                Ok(Event::Control(control)) => active.control = control,
                Ok(Event::Activity(line)) => keep(&mut active.activity, line),
                Ok(Event::Finished(_)) | Err(mpsc::error::TryRecvError::Disconnected) => {
                    break false;
                }
                Ok(_) => {}
                Err(mpsc::error::TryRecvError::Empty) => break true,
            }
        });
        if let Some(result) = finished {
            self.halt();
            if let Err(error) = result {
                self.fail(format!("Unattended access stopped: {error:#}"));
            }
        }
        if self.access.enabled
            && self.listener.is_none()
            && self.last_start.is_none_or(|t| t.elapsed() > RETRY)
        {
            self.start_listener();
        }
        arrived
    }

    fn view(&self) -> View {
        let connectivity = self
            .session
            .as_ref()
            .map(|s| s.connectivity.borrow().clone())
            .unwrap_or_default();
        let route = connectivity.route.filter(|_| self.connected).map(|route| {
            let label = match route {
                boundary_session::Route::Direct => "Direct connection",
                boundary_session::Route::Relay => "Relayed connection",
                boundary_session::Route::Unknown => "Checking connection path",
            };
            match connectivity.rtt {
                Some(rtt) => format!("{label}, round trip {} ms", rtt.as_millis()),
                None => label.to_string(),
            }
        });
        View {
            displays: self
                .displays
                .iter()
                .map(|d| DisplayView {
                    id: d.id,
                    name: d.name.clone(),
                })
                .collect(),
            display: self.display,
            screen_permission: self.screen_permission,
            input_permission: self.input_permission,
            status: self.status.clone(),
            error: self.error,
            sharing: self.session.is_some(),
            connected: self.connected,
            invitation: Some(self.invitation.clone()).filter(|i| !i.is_empty()),
            code: self.codes.lease.as_ref().map(|lease| lease.display()),
            code_busy: self.codes.pending.is_some(),
            codes_available: self.codes_available(),
            code_message: self.codes.message.clone(),
            code_service: self.code_service.clone(),
            pending: self.pending.as_ref().map(|p| PendingView {
                name: p.name.clone(),
                peer: p.peer.clone(),
                tools: p.tools,
            }),
            helper: self.helper.as_ref().map(|(name, peer)| HelperView {
                name: name.clone(),
                peer: peer.clone(),
                paired: self.access.helpers.iter().any(|h| &h.id == peer),
            }),
            control: self.control,
            tools_offered: self.tools_offered,
            tools: self.tools,
            activity: self.activity.clone(),
            route,
            warning: connectivity.warning,
            network: self.network.clone(),
            network_label: self.network.label(),
            network_error: self.network_error.clone(),
            unattended: UnattendedView {
                enabled: self.access.enabled,
                reachable: self.reachable,
                machine_id: self.machine.clone(),
                autostart: self.autostart,
                helpers: self.access.helpers.clone(),
                has_password: self.access.has_password(),
                min_password: MIN_PASSWORD,
                message: self.message.clone(),
                error: self.message_error,
                active: self
                    .active
                    .iter()
                    .map(|a| ActiveView {
                        id: a.id,
                        name: a.name.clone(),
                        control: a.control,
                        tools: a.tools,
                        activity: a.activity.clone(),
                    })
                    .collect(),
                ask: self.ask.as_ref().map(|a| PendingView {
                    name: a.name.clone(),
                    peer: a.peer.clone(),
                    tools: a.tools,
                }),
            },
        }
    }
}

fn load_unattended() -> anyhow::Result<(PathBuf, SecretKey, Access)> {
    use anyhow::Context;
    let dir = boundary_provision::platform::data_dir()?;
    let key = unattended::load_or_create_key(&dir.join("machine.key"))
        .context("Cannot load this computer's identity")?;
    let path = dir.join("access.json");
    let access = Access::load(&path)?;
    Ok((path, key, access))
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

impl Support {
    /// Poll, send the view if it changed, and bring the window forward when
    /// someone needs an answer.
    fn refresh(&self, app: &AppHandle) {
        let (raise, view) = {
            let mut model = self.model.lock();
            let raise = model.poll();
            (raise, model.view())
        };
        if raise {
            show_main(app);
        }
        let Ok(value) = serde_json::to_value(&view) else {
            return;
        };
        let mut sent = self.sent.lock();
        if *sent != value {
            let _ = app.emit(SUPPORT_EVENT, &value);
            *sent = value;
        }
    }
    /// Act on the model, then refresh at once.
    fn act<T>(
        &self,
        app: &AppHandle,
        action: impl FnOnce(&mut Model) -> Result<T, String>,
    ) -> Result<T, String> {
        let result = action(&mut self.model.lock());
        self.refresh(app);
        result
    }
}

/// Make the model and start polling. Unattended access, if the person
/// switched it on, starts on the first poll.
pub fn install(app: &AppHandle) {
    let support = Arc::new(Support {
        model: Mutex::new(Model::new()),
        sent: Mutex::new(serde_json::Value::Null),
    });
    app.manage(support.clone());
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            support.refresh(&app);
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    });
}

type Shared<'a> = State<'a, Arc<Support>>;

#[tauri::command]
pub async fn support_state(support: Shared<'_>) -> Result<View, String> {
    Ok(support.model.lock().view())
}
#[tauri::command]
pub async fn support_refresh_displays(app: AppHandle, support: Shared<'_>) -> Result<(), String> {
    support.act(&app, |m| {
        let displays = boundary_platform::displays().map_err(|e| format!("{e:#}"))?;
        if !m
            .display
            .is_some_and(|id| displays.iter().any(|d| d.id == id))
        {
            m.display = displays.first().map(|d| d.id);
        }
        m.displays = displays;
        Ok(())
    })
}
#[tauri::command]
pub async fn support_set_display(
    app: AppHandle,
    support: Shared<'_>,
    id: u32,
) -> Result<(), String> {
    support.act(&app, |m| {
        if !m.displays.iter().any(|d| d.id == id) {
            return Err("That display is no longer connected".into());
        }
        m.display = Some(id);
        Ok(())
    })
}
#[tauri::command]
pub async fn support_set_code_service(
    app: AppHandle,
    support: Shared<'_>,
    url: String,
) -> Result<(), String> {
    support.act(&app, |m| {
        if m.codes.lease.is_some() || m.codes.pending.is_some() {
            return Err("Change the code service when no code is showing".into());
        }
        if !url.trim().is_empty() {
            boundary_codes::Client::new(url.trim()).map_err(|e| e.to_string())?;
        }
        m.code_service = url.trim().to_string();
        Ok(())
    })
}
#[tauri::command]
pub async fn support_share(app: AppHandle, support: Shared<'_>) -> Result<(), String> {
    support.act(&app, Model::share)
}
#[tauri::command]
pub async fn support_stop(app: AppHandle, support: Shared<'_>) -> Result<(), String> {
    support.act(&app, |m| {
        m.stop();
        Ok(())
    })
}
/// Show the full invitation instead of waiting for, or showing, a code.
#[tauri::command]
pub async fn support_full_invitation(app: AppHandle, support: Shared<'_>) -> Result<(), String> {
    support.act(&app, |m| {
        m.codes.clear();
        Ok(())
    })
}
#[tauri::command]
pub async fn support_answer(
    app: AppHandle,
    support: Shared<'_>,
    decision: String,
    allow_tools: bool,
) -> Result<(), String> {
    let decision = match decision.as_str() {
        "control" => Approval::Control,
        "view" => Approval::View,
        "deny" => Approval::Deny,
        _ => return Err("Unknown answer".into()),
    };
    support.act(&app, |m| {
        if matches!(decision, Approval::Control) && !m.input_permission {
            return Err(
                "Accessibility permission is needed for control. You can allow viewing now".into(),
            );
        }
        m.answer(decision, allow_tools)
    })
}
#[tauri::command]
pub async fn support_set_control(
    app: AppHandle,
    support: Shared<'_>,
    allowed: bool,
) -> Result<(), String> {
    support.act(&app, |m| {
        let session = m.session.as_ref().ok_or("No helper is connected")?;
        if allowed && !m.input_permission {
            return Err("Control needs Accessibility permission".into());
        }
        session.set_control(allowed);
        m.control = allowed;
        Ok(())
    })
}
#[tauri::command]
pub async fn support_set_tools(
    app: AppHandle,
    support: Shared<'_>,
    allowed: bool,
) -> Result<(), String> {
    support.act(&app, |m| {
        if !m.tools_offered {
            return Err("This helper sends no commands".into());
        }
        let session = m.session.as_ref().ok_or("No helper is connected")?;
        session.set_tools(allowed);
        m.tools = allowed;
        Ok(())
    })
}
#[tauri::command]
pub async fn support_pair(app: AppHandle, support: Shared<'_>) -> Result<(), String> {
    support.act(&app, Model::pair)
}
#[tauri::command]
pub async fn support_set_unattended(
    app: AppHandle,
    support: Shared<'_>,
    enabled: bool,
) -> Result<(), String> {
    support.act(&app, |m| m.set_unattended(enabled))
}
#[tauri::command]
pub async fn support_set_helper(
    app: AppHandle,
    support: Shared<'_>,
    id: String,
    control: bool,
    tools: bool,
) -> Result<(), String> {
    support.act(&app, |m| {
        let helper = m
            .access
            .helpers
            .iter_mut()
            .find(|h| h.id == id)
            .ok_or("That helper is no longer paired")?;
        helper.control = control;
        helper.tools = tools;
        m.save()
    })
}
#[tauri::command]
pub async fn support_remove_helper(
    app: AppHandle,
    support: Shared<'_>,
    id: String,
) -> Result<(), String> {
    support.act(&app, |m| {
        let name = m
            .access
            .helpers
            .iter()
            .find(|h| h.id == id)
            .map(|h| h.name.clone())
            .ok_or("That helper is no longer paired")?;
        m.access.forget(&id);
        m.save()?;
        m.say(format!("{name} can no longer connect unattended"));
        Ok(())
    })
}
#[tauri::command]
pub async fn support_set_password(
    app: AppHandle,
    support: Shared<'_>,
    password: Option<String>,
) -> Result<(), String> {
    // Argon2 takes a moment, so it runs off the runtime's worker.
    let mut access = support.model.lock().access.clone();
    let removing = password.is_none();
    access = tokio::task::spawn_blocking(move || {
        access.set_password(password.as_deref()).map(|()| access)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("{e:#}"))?;
    support.act(&app, |m| {
        m.access = access;
        m.save()?;
        m.say(if removing {
            "Unattended password removed"
        } else {
            "Unattended password set"
        });
        Ok(())
    })
}
#[tauri::command]
pub async fn support_set_autostart(
    app: AppHandle,
    support: Shared<'_>,
    enabled: bool,
) -> Result<(), String> {
    support.act(&app, |m| {
        autostart::set(AUTOSTART, enabled).map_err(|e| format!("{e:#}"))?;
        m.autostart = enabled;
        Ok(())
    })
}
/// End one unattended helper's session.
#[tauri::command]
pub async fn support_end_unattended(
    app: AppHandle,
    support: Shared<'_>,
    id: u64,
) -> Result<(), String> {
    support.act(&app, |m| {
        if let Some(index) = m.active.iter().position(|a| a.id == id) {
            let active = m.active.remove(index);
            active.session.stop();
            m.say(format!("Ended {}'s session", active.name));
        }
        Ok(())
    })
}
/// Answer a helper who is not paired and asked to come in by this
/// computer's ID. `pair` lets them connect later without asking.
#[tauri::command]
pub async fn support_answer_ask(
    app: AppHandle,
    support: Shared<'_>,
    decision: String,
    allow_tools: bool,
    pair: bool,
) -> Result<(), String> {
    let approval = match decision.as_str() {
        "control" => Approval::Control,
        "view" => Approval::View,
        "deny" => Approval::Deny,
        _ => return Err("Unknown answer".into()),
    };
    support.act(&app, |m| {
        if matches!(approval, Approval::Control) && !m.input_permission {
            return Err(
                "Accessibility permission is needed for control. You can allow viewing now".into(),
            );
        }
        let ask = m.ask.take().ok_or("Nobody is asking to connect")?;
        let allowed = !matches!(approval, Approval::Deny);
        let tools = allowed && allow_tools && ask.tools;
        let pair = allowed && pair;
        ask.answer
            .send(unattended::Asked {
                approval,
                tools,
                pair,
            })
            .map_err(|_| format!("{} stopped waiting", ask.name))?;
        // The listener saves a pairing before it lets the helper in, and the
        // list is reloaded when they arrive; reading it here would race it.
        Ok(())
    })
}
/// Stop one unattended helper's commands for the rest of their session.
#[tauri::command]
pub async fn support_stop_unattended_tools(
    app: AppHandle,
    support: Shared<'_>,
    id: u64,
) -> Result<(), String> {
    support.act(&app, |m| {
        let Some(active) = m.active.iter_mut().find(|a| a.id == id) else {
            return Ok(());
        };
        active.session.set_tools(false);
        active.tools = false;
        let name = active.name.clone();
        m.say(format!(
            "{name}'s tools can no longer run commands in this session"
        ));
        Ok(())
    })
}
#[tauri::command]
pub async fn support_request_screen_permission() -> Result<(), String> {
    boundary_platform::request_screen_permission();
    Ok(())
}
#[tauri::command]
pub async fn support_open_input_settings() -> Result<(), String> {
    boundary_platform::open_input_settings().map_err(|e| format!("{e:#}"))
}
#[tauri::command]
pub async fn support_save_network(
    app: AppHandle,
    support: Shared<'_>,
    profile: Profile,
) -> Result<(), String> {
    support.act(&app, |m| {
        if m.session.is_some() {
            return Err("End the session before changing how this computer connects".into());
        }
        profile.check_local().map_err(|e| e.to_string())?;
        boundary_provision::network::save(&profile)
            .map_err(|e| format!("Could not save settings: {e}"))?;
        m.network = profile;
        m.network_error = None;
        m.status = "Connection settings saved".into();
        m.error = false;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_keeps_the_newest_lines() {
        let mut lines = Vec::new();
        for n in 0..(ACTIVITY_LINES + 3) {
            keep(&mut lines, n.to_string());
        }
        assert_eq!(lines.len(), ACTIVITY_LINES);
        assert_eq!(lines.first().map(String::as_str), Some("3"));
    }

    /// Poll the model until `done` says so.
    async fn until(model: &mut Model, what: &str, mut done: impl FnMut(&mut Model) -> bool) {
        for _ in 0..300 {
            model.poll();
            if done(model) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for {what}. Status: {}", model.status);
    }

    /// The whole attended path on this computer's real screen: share, a
    /// helper with tools knocks, the person allows viewing and their tools,
    /// a command runs and shows in the activity, then stopping the tools
    /// stops the next command and ending the session ends it.
    ///
    /// Ignored by default because it captures the real display, which a
    /// headless CI runner does not have. Run it with `--ignored`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn a_helper_is_approved_runs_a_command_and_is_stopped() {
        use boundary_session::tools::{Reply, Request};
        let mut model = Model::new();
        // Loopback only: no relay, no code service, nothing leaves this
        // computer. `options` does not validate, so loopback is allowed here.
        model.network = Profile::Private {
            address: "127.0.0.1".parse().unwrap(),
        };
        model.network_error = None;
        model.share().unwrap();
        until(&mut model, "the invitation", |m| !m.invitation.is_empty()).await;
        assert!(
            !model.codes_available(),
            "a private network uses no code service"
        );

        let helper = boundary_session::viewer_with_tools(
            model.invitation.clone(),
            "Test helper".into(),
            boundary_session::HostOptions {
                relay: false,
                relay_url: None,
                bind_ip: None,
            },
            None,
        );
        until(&mut model, "the approval", |m| m.pending.is_some()).await;
        let pending = model.view().pending.unwrap();
        assert_eq!(pending.name, "Test helper");
        assert!(pending.tools);
        model.answer(Approval::View, true).unwrap();
        until(&mut model, "the connection", |m| m.connected).await;
        assert!(model.tools && model.tools_offered && !model.control);

        let client = {
            let mut client = None;
            for _ in 0..100 {
                client = helper.tools();
                if client.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            client.expect("the helper got no tools client")
        };
        let run = Request::Run {
            command: "echo get-help-works".into(),
            cwd: None,
            env: vec![],
            timeout_ms: 20_000,
            max_output: 65_536,
        };
        let (reply, body) = client
            .call(&run, &[], Duration::from_secs(30))
            .await
            .unwrap();
        assert!(
            matches!(reply, Reply::Ran { code: Some(0), .. }),
            "{reply:?}"
        );
        assert!(String::from_utf8_lossy(&body).contains("get-help-works"));
        until(&mut model, "the activity line", |m| {
            m.activity.iter().any(|l| l.contains("get-help-works"))
        })
        .await;

        model.session.as_ref().unwrap().set_tools(false);
        model.tools = false;
        let (reply, _) = client
            .call(&run, &[], Duration::from_secs(30))
            .await
            .unwrap();
        assert!(matches!(reply, Reply::Refused(_)), "{reply:?}");

        model.stop();
        assert!(model.session.is_none() && !model.connected);
        drop(helper);
    }
}
