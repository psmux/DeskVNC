//! Unattended access in the support app: the settings a person sees, the
//! listener that runs while it is on, and the window that says so whenever a
//! helper is connected.
//!
//! Everything lives beside the network settings in the app's data folder:
//! `machine.key`, this computer's lasting identity, and `access.json`, who may
//! come in. The listener reads `access.json` again on every connection, so a
//! change here applies at once.

use anyhow::{Context, Result};
use boundary_session::{
    Approval, Session,
    unattended::{self, Access, Asked, Listener, MIN_PASSWORD, Notice},
};
use eframe::egui;
use std::path::PathBuf;

use crate::theme;

/// A helper connected with nobody's approval, held so the person at the
/// computer can see it and end it.
pub struct Active {
    pub name: String,
    pub control: bool,
    /// Whether their tools may run commands and copy files.
    pub tools: bool,
    /// Whether they are shown what the person here copies.
    pub clipboard: bool,
    /// What their tools did, and clipboard text that went either way, newest
    /// last.
    pub activity: Vec<String>,
    pub session: Session,
}

/// A helper that is not paired asking to come in by this computer's ID.
pub struct Ask {
    name: String,
    peer: String,
    tools: bool,
    allow_tools: bool,
    /// The helper can carry clipboard text, so the person is asked.
    clipboard: bool,
    /// Off until they tick it.
    allow_clipboard: bool,
    pair: bool,
    answer: tokio::sync::oneshot::Sender<Asked>,
}

pub struct Unattended {
    access_path: PathBuf,
    machine: String,
    key: Option<boundary_session::unattended::SecretKey>,
    pub access: Access,
    listener: Option<Listener>,
    /// Held while listening, so DeskVNC on this computer does not listen
    /// as the same ID at the same time.
    claim: Option<std::fs::File>,
    /// Helpers connected unattended now, in the order they came in.
    pub active: Vec<Active>,
    /// How many helpers have connected unattended since the app started,
    /// so the window can tell a new session from the same ones.
    pub connections: u64,
    ask: Option<Ask>,
    reachable: bool,
    password: String,
    confirm: String,
    message: String,
    error: bool,
    autostart: bool,
    /// Whether the copy at the sign in screen is set up.
    login: bool,
    /// Setting that up or taking it away, which waits on an administrator.
    login_change: Option<std::sync::mpsc::Receiver<(bool, Result<()>)>>,
    /// The person said no to the notice offering the copy at the sign in
    /// screen, or took that copy away themselves.
    login_notice_dismissed: bool,
    /// Not listening for now, because another copy is: the one at the sign
    /// in or lock screen. Picked up again when it hands over.
    handed_over: bool,
    checked: std::time::Instant,
    /// The window, woken when the listener has something to say.
    ctx: egui::Context,
}

impl Unattended {
    /// Whether a helper who is not paired is waiting for an answer.
    pub fn asking(&self) -> bool {
        self.ask.is_some()
    }
    pub fn new(ctx: &egui::Context) -> Self {
        let mut this = Self {
            access_path: PathBuf::new(),
            machine: String::new(),
            key: None,
            access: Access::default(),
            listener: None,
            claim: None,
            active: Vec::new(),
            connections: 0,
            ask: None,
            reachable: false,
            password: String::new(),
            confirm: String::new(),
            message: String::new(),
            error: false,
            autostart: autostart::enabled(),
            login: crate::login::enabled(),
            login_change: None,
            login_notice_dismissed: notice_dismissed(),
            handed_over: false,
            checked: std::time::Instant::now(),
            ctx: ctx.clone(),
        };
        // Rewrite an existing sign in entry, so one written by an older copy
        // picks up what this one adds (a restart after a crash on macOS) and
        // points at where this copy is now.
        if this.autostart {
            let _ = autostart::set(true);
        }
        match Self::load() {
            Ok((path, key, access)) => {
                this.machine = unattended::machine_id(&key);
                this.access_path = path;
                this.key = Some(key);
                this.access = access;
                if this.access.enabled {
                    this.start();
                }
            }
            Err(error) => this.fail(format!("{error:#}")),
        }
        this
    }
    fn load() -> Result<(PathBuf, boundary_session::unattended::SecretKey, Access)> {
        let dir = boundary_provision::platform::data_dir()?;
        let key = unattended::load_or_create_key(&dir.join("machine.key"))
            .context("Cannot load this computer's identity")?;
        let path = dir.join("access.json");
        let access = Access::load(&path)?;
        Ok((path, key, access))
    }
    fn fail(&mut self, message: String) {
        self.message = message;
        self.error = true;
    }
    fn say(&mut self, message: impl Into<String>) {
        self.message = message.into();
        self.error = false;
    }
    fn save(&mut self) -> bool {
        match self.access.save(&self.access_path) {
            Ok(()) => true,
            Err(error) => {
                self.fail(format!("{error:#}"));
                false
            }
        }
    }
    /// Start listening, if there is an identity to listen as.
    fn start(&mut self) {
        let Some(key) = self.key.clone() else { return };
        if self.listener.is_some() {
            return;
        }
        // One answerer per computer: DeskVNC, this app, or the copy at the
        // sign in or lock screen. Whoever holds the claim has the ID; this
        // copy keeps asking and takes over when the holder lets go.
        match boundary_provision::platform::claim_unattended() {
            Ok(Some(claim)) => {
                self.claim = Some(claim);
                self.handed_over = false;
            }
            Ok(None) => {
                if !self.handed_over {
                    self.say("DeskVNC, or the copy at the sign in or lock screen, is answering unattended connections for this computer. This app takes over when it stops");
                }
                self.handed_over = true;
                return;
            }
            Err(error) => {
                self.fail(format!("{error:#}"));
                return;
            }
        }
        let mut listener = unattended::listen(
            boundary_session::HostOptions::default(),
            key,
            self.access_path.clone(),
            // The primary display, found when a helper arrives: nobody is
            // there to pick another, and a sleeping screen lists none now.
            boundary_platform::open_primary,
        );
        // A helper asking to come in wakes the window, which otherwise draws
        // nothing while it waits.
        let (_, stand_in) = tokio::sync::mpsc::channel(1);
        let notices = std::mem::replace(&mut listener.notices, stand_in);
        listener.notices = crate::wake::relay(notices, self.ctx.clone());
        self.listener = Some(listener);
        self.say("Starting unattended access");
    }
    fn halt(&mut self) {
        self.listener = None;
        self.claim = None;
        self.active.clear();
        self.reachable = false;
        self.handed_over = false;
    }
    /// Hand this computer's ID to the copy the service starts at the lock
    /// screen, which can see it, and take it back after.
    fn hand_over(&mut self) {
        if self.checked.elapsed() < std::time::Duration::from_secs(1) {
            return;
        }
        self.checked = std::time::Instant::now();
        if !self.access.enabled {
            return;
        }
        if self.login && screen_locked() {
            if self.listener.is_some() {
                self.halt();
                self.handed_over = true;
                self.say("The screen is locked. The copy at the lock screen answers helpers until it is unlocked");
            }
        } else if self.handed_over && self.listener.is_none() {
            self.start();
        }
    }
    /// Let the helper of the current attended session in any time, and tell
    /// them this computer's ID so they can save it.
    /// What they may do later starts as what they may do now, so `tools`
    /// and `clipboard` are what the person allows in this session.
    pub fn pair(
        &mut self,
        session: &Session,
        peer: &str,
        name: &str,
        tools: bool,
        clipboard: bool,
    ) {
        if let Err(error) = self.access.trust(peer, name, true) {
            self.fail(format!("{error:#}"));
            return;
        }
        self.access.allow_tools(peer, tools);
        self.access.allow_clipboard(peer, clipboard);
        let was_enabled = self.access.enabled;
        self.access.enabled = true;
        if !self.save() {
            return;
        }
        self.start();
        if !was_enabled {
            self.reachable_before_sign_in();
        }
        match session.offer_pairing(self.machine.clone(), computer_name()) {
            Ok(()) => self.say(format!(
                "{name} can now connect to this computer any time. Remove them under Unattended access to stop it"
            )),
            Err(error) => self.fail(format!("{error:#}")),
        }
    }
    pub fn is_paired(&self, peer: &str) -> bool {
        self.access.helpers.iter().any(|h| h.id == peer)
    }
    pub fn enabled(&self) -> bool {
        self.access.enabled
    }
    /// Whether the window has to look once a second for the lock screen
    /// copy to hand the ID back, which sends no event.
    pub fn needs_checks(&self) -> bool {
        self.access.enabled && (self.login || self.handed_over)
    }
    /// This computer's lasting ID, the one a helper saves.
    pub fn machine_id(&self) -> &str {
        &self.machine
    }
    /// The word beside "Unattended access" on the home screen.
    pub fn label(&self) -> &'static str {
        label(self.access.enabled, self.reachable, self.handed_over)
    }
    /// Drain the listener. `true` when a helper has just come in, so the
    /// caller brings the window forward.
    /// Take in what the listener reported. True when a question arrived that
    /// somebody at this computer has to answer, so the window should show.
    pub fn poll(&mut self) -> bool {
        self.hand_over();
        let mut arrived = false;
        let mut finished = None;
        if let Some(listener) = self.listener.as_mut() {
            while let Ok(notice) = listener.notices.try_recv() {
                match notice {
                    Notice::Ready { .. } => {
                        log(&self.access_path, "listening");
                        self.reachable = true;
                        self.message =
                            "Unattended access is on. Paired helpers can connect any time".into();
                        self.error = false;
                    }
                    Notice::Status(status) => {
                        log(&self.access_path, &status);
                        self.message = status;
                        self.error = false;
                    }
                    Notice::Connected {
                        name,
                        control,
                        session,
                        ..
                    } => {
                        log(&self.access_path, &format!("{name} connected"));
                        self.connections += 1;
                        if let Some(message) = after_connect(&self.message, &name) {
                            self.message = message;
                            self.error = false;
                        }
                        self.active.push(Active {
                            name,
                            control,
                            tools: session.tools_allowed(),
                            clipboard: session.clipboard_read_allowed(),
                            activity: Vec::new(),
                            session,
                        });
                        // A paired helper needs no answer, so the window stays
                        // where it is; the tray icon says who is connected.
                    }
                    Notice::Ask {
                        name,
                        peer,
                        tools,
                        clipboard,
                        answer,
                    } => {
                        self.ask = Some(Ask {
                            name,
                            peer,
                            tools,
                            allow_tools: false,
                            clipboard,
                            allow_clipboard: false,
                            pair: false,
                            answer,
                        });
                        arrived = true;
                    }
                    Notice::Refused { name, reason, .. } => {
                        log(&self.access_path, &format!("turned away {name}: {reason}"));
                        self.message = format!("Turned away {name}: {reason}");
                        self.error = false;
                    }
                    Notice::Finished(result) => {
                        log(&self.access_path, &format!("stopped listening: {result:?}"));
                        finished = Some(result);
                    }
                }
            }
        }
        let mut ended = Vec::new();
        for (index, active) in self.active.iter_mut().enumerate() {
            while let Ok(event) = active.session.events.try_recv() {
                match event {
                    boundary_session::Event::Control(control) => active.control = control,
                    boundary_session::Event::Activity(line) => {
                        active.activity.push(line);
                        let excess = active.activity.len().saturating_sub(crate::ACTIVITY_LINES);
                        active.activity.drain(..excess);
                    }
                    boundary_session::Event::Finished(result) => {
                        log(
                            &self.access_path,
                            &format!("{}'s session ended: {result:?}", active.name),
                        );
                        ended.push(index);
                        break;
                    }
                    _ => {}
                }
            }
        }
        for index in ended.into_iter().rev() {
            self.active.remove(index);
        }
        if let Some(result) = finished {
            self.halt();
            if let Err(error) = result {
                self.fail(format!("Unattended access stopped: {error:#}"));
            }
        }
        arrived
    }
    /// Ask the person about a helper who connected by this computer's ID
    /// without being paired. `control_ok` is whether this app may control
    /// the computer at all.
    pub fn prompt(&mut self, ctx: &egui::Context, control_ok: bool) {
        if self.ask.as_ref().is_some_and(|ask| ask.answer.is_closed()) {
            // The helper gave up, or nobody answered in time.
            self.ask = None;
        }
        let Some(ask) = self.ask.as_mut() else {
            return;
        };
        let mut decision = None;
        egui::Window::new("Approve this helper?")
            .id(egui::Id::new("unattended ask"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.set_width(420.0);
                ui.label(
                    egui::RichText::new(format!(
                        "{} is connecting with this computer's ID and wants to see your screen.",
                        ask.name
                    ))
                    .size(15.0),
                );
                theme::small(ui, "They are not paired with this computer. The name is supplied by the helper, so only allow someone you expect.");
                ui.add_space(6.0);
                theme::caption(ui, "Helper connection identity");
                ui.monospace(&ask.peer);
                if ask.tools {
                    ui.add_space(10.0);
                    ui.checkbox(
                        &mut ask.allow_tools,
                        "Also let their tools run commands and copy files on this computer",
                    );
                    theme::small(ui, "Their tools act as you, outside what the screen shows. Leave this off unless you asked for it.");
                }
                if ask.clipboard {
                    ui.add_space(10.0);
                    ui.checkbox(&mut ask.allow_clipboard, crate::SEE_WHAT_I_COPY);
                    theme::small(ui, crate::SEE_WHAT_I_COPY_NOTE);
                }
                ui.add_space(6.0);
                ui.checkbox(
                    &mut ask.pair,
                    "Let them connect any time without asking me again",
                );
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(control_ok, theme::primary(ui, "Allow viewing and control"))
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
                if !control_ok {
                    theme::small(ui, "Accessibility permission is needed for control. You can allow viewing now.");
                } else if let Some(hint) = boundary_platform::control_hint() {
                    theme::small(ui, hint);
                }
            });
        if let Some(approval) = decision
            && let Some(ask) = self.ask.take()
        {
            let allowed = !matches!(approval, Approval::Deny);
            let pair = allowed && ask.pair;
            let asked = answer(&ask, approval);
            let _ = ask.answer.send(asked);
            if pair {
                // The listener saved them; show the list as it now is.
                if let Ok(access) = Access::load(&self.access_path) {
                    self.access = access;
                }
            }
        }
    }
    /// A banner for each helper connected unattended, shown on top of
    /// everything. The person at the computer always sees who is in and can
    /// end any of them with one click.
    /// Offer the copy at the sign in screen when unattended access is on and
    /// that copy is missing, which is how a computer that switched unattended
    /// access on before it was set up automatically finds itself after an
    /// upgrade. Only the button asks for an administrator: Support never
    /// raises an administrator prompt on its own when it starts.
    pub fn login_notice(&mut self, ui: &mut egui::Ui) {
        if !show_login_notice(
            crate::login::SUPPORTED,
            self.access.enabled,
            self.login,
            self.login_notice_dismissed,
            self.login_change.is_some(),
        ) {
            return;
        }
        theme::card(ui, |ui| {
            ui.label(
                egui::RichText::new("Unattended access stops when this computer restarts").strong(),
            );
            theme::muted(
                ui,
                "Until somebody signs in, paired helpers cannot reach it. Setting that up asks for an administrator once.",
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Set it up").clicked() {
                    self.set_login(true);
                }
                if ui.button("Not now").clicked() {
                    self.dismiss_login_notice();
                }
            });
        });
        ui.add_space(10.0);
    }
    fn dismiss_login_notice(&mut self) {
        self.login_notice_dismissed = true;
        if let Some(path) = notice_path() {
            let _ = std::fs::write(path, b"");
        }
    }
    pub fn banner(&mut self, ui: &mut egui::Ui) {
        let mut end = None;
        let mut stop_tools = None;
        let mut stop_clipboard = None;
        for (index, active) in self.active.iter().enumerate() {
            let name = &active.name;
            let tools = active.tools;
            let clipboard = active.clipboard;
            egui::Frame::new()
                .fill(theme::pal(ui.ctx()).danger)
                .inner_margin(14.0)
                .corner_radius(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "{name} is connected to this computer{}",
                                if active.control {
                                    " and can use the mouse and keyboard"
                                } else {
                                    ", watching"
                                }
                            ))
                            .color(egui::Color32::WHITE)
                            .strong(),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("End their session").clicked() {
                                end = Some(index);
                            }
                            if tools && ui.button("Stop their commands").clicked() {
                                stop_tools = Some(index);
                            }
                            if clipboard && ui.button("Stop showing what I copy").clicked() {
                                stop_clipboard = Some(index);
                            }
                        });
                    });
                    if tools {
                        ui.label(
                            egui::RichText::new(
                                "Their tools can run commands and copy files on this computer.",
                            )
                            .color(egui::Color32::WHITE),
                        );
                    }
                    if clipboard {
                        ui.label(
                            egui::RichText::new("They see the text you copy on this computer.")
                                .color(egui::Color32::WHITE),
                        );
                    }
                    for line in &active.activity {
                        ui.label(
                            egui::RichText::new(line)
                                .color(egui::Color32::WHITE)
                                .small(),
                        );
                    }
                });
            ui.add_space(8.0);
        }
        if let Some(active) = stop_tools.and_then(|i| self.active.get_mut(i)) {
            active.session.set_tools(false);
            active.tools = false;
            let name = active.name.clone();
            self.say(format!(
                "{name}'s tools can no longer run commands in this session"
            ));
        }
        if let Some(active) = stop_clipboard.and_then(|i| self.active.get_mut(i)) {
            active.session.set_clipboard_read(false);
            active.clipboard = false;
            let name = active.name.clone();
            self.say(format!(
                "{name} no longer sees what you copy in this session"
            ));
        }
        if let Some(index) = end.filter(|&i| i < self.active.len()) {
            let active = self.active.remove(index);
            active.session.stop();
            self.say(format!("Ended {}'s session", active.name));
        }
    }
    /// The Unattended access settings, drawn inside a card on the Settings
    /// page.
    pub fn settings(&mut self, ui: &mut egui::Ui) {
        theme::muted(
            ui,
            "Let people you trust connect to this computer when nobody is here to approve. Off unless you switch it on.",
        );
        ui.add_space(6.0);
        let mut enabled = self.access.enabled;
        if ui
            .checkbox(&mut enabled, "Allow unattended access to this computer")
            .changed()
        {
            self.access.enabled = enabled;
            if self.save() {
                if enabled {
                    self.start();
                    self.reachable_before_sign_in();
                } else {
                    self.halt();
                    self.say("Unattended access is off. Nobody can connect without your approval");
                }
            }
        }
        if self.access.enabled {
            ui.add_space(4.0);
            theme::caption(
                ui,
                if self.reachable {
                    "This computer's ID, reachable now"
                } else {
                    "This computer's ID"
                },
            );
            if theme::value_box(ui, &short(&self.machine), 16.0) {
                ui.ctx().copy_text(self.machine.clone());
            }
            theme::small(
                ui,
                "Copy gives the whole ID. A helper enters it as the partner ID, with the unattended password unless they were paired here.",
            );
        }
        let mut autostart = self.autostart;
        if ui
            .checkbox(
                &mut autostart,
                "Start DeskVNC Support when I sign in, so it is ready",
            )
            .changed()
        {
            match autostart::set(autostart) {
                Ok(()) => self.autostart = autostart,
                Err(error) => self.fail(format!("{error:#}")),
            }
        }
        if crate::login::SUPPORTED && self.access.enabled {
            self.login_setting(ui);
        }
        ui.add_space(10.0);
        theme::caption(ui, "Paired helpers");
        if self.access.helpers.is_empty() {
            theme::small(
                ui,
                "None yet. During a support session, choose Let them connect any time to pair the helper.",
            );
        }
        let mut remove = None;
        let mut changed = false;
        for (index, helper) in self.access.helpers.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                ui.label(&helper.name);
                ui.small(short(&helper.id));
                changed |= ui.checkbox(&mut helper.control, "may control").changed();
                changed |= ui
                    .checkbox(&mut helper.tools, "may run commands and copy files")
                    .on_hover_text("For a helper whose tools, such as DeskVNC's agents, work on this computer while you are away. Commands run as you.")
                    .changed();
                changed |= ui
                    .checkbox(&mut helper.clipboard, "may see what I copy")
                    .on_hover_text("Text copied on this computer while they are connected goes to them, and that is sometimes a password. Never at the sign in screen.")
                    .changed();
                if ui.button("Remove").clicked() {
                    remove = Some(index);
                }
            });
        }
        if let Some(index) = remove {
            let gone = self.access.helpers.remove(index);
            changed = true;
            self.say(format!("{} can no longer connect unattended", gone.name));
        }
        if changed {
            self.save();
        }
        ui.add_space(10.0);
        theme::caption(ui, "Unattended password");
        theme::small(
            ui,
            format!(
                "Optional. Lets a helper who was never paired connect with this computer's ID and the password. At least {MIN_PASSWORD} characters. Five wrong tries pause it for 15 minutes."
            ),
        );
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.password)
                    .password(true)
                    .hint_text("New password")
                    .desired_width(180.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.confirm)
                    .password(true)
                    .hint_text("Repeat it")
                    .desired_width(180.0),
            );
            if ui.button("Set password").clicked() {
                if self.password != self.confirm {
                    self.fail("The two passwords differ".into());
                } else {
                    match self.access.set_password(Some(&self.password)) {
                        Ok(()) => {
                            if self.save() {
                                self.say("Unattended password set");
                            }
                        }
                        Err(error) => self.fail(format!("{error:#}")),
                    }
                }
                self.password.clear();
                self.confirm.clear();
            }
        });
        if self.access.has_password() && ui.button("Remove the password").clicked() {
            let _ = self.access.set_password(None);
            if self.save() {
                self.say("Unattended password removed");
            }
        }
        if !self.message.is_empty() {
            ui.colored_label(
                if self.error {
                    theme::pal(ui.ctx()).danger
                } else {
                    theme::pal(ui.ctx()).success
                },
                &self.message,
            );
        }
    }
}

impl Unattended {
    /// Reachable before anyone signs in, after a restart for instance.
    fn login_setting(&mut self, ui: &mut egui::Ui) {
        if let Some(change) = self.login_change.as_ref() {
            match change.try_recv() {
                Ok((on, Ok(()))) => {
                    self.login = on;
                    self.login_change = None;
                    // Taken away on purpose: the notice would only ask again.
                    if !on {
                        self.dismiss_login_notice();
                    }
                    self.say(if on {
                        "Paired helpers can now connect at the sign in screen too"
                    } else {
                        "Helpers can connect only once somebody signs in"
                    });
                }
                Ok((_, Err(error))) => {
                    self.login_change = None;
                    self.fail(format!("{error:#}"));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(250));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.login_change = None,
            }
        }
        let mut login = self.login;
        let changed = ui
            .add_enabled(
                self.login_change.is_none(),
                egui::Checkbox::new(
                    &mut login,
                    "Also before anyone signs in, such as after a restart",
                ),
            )
            .on_hover_text("Asks for an administrator. At the sign in screen only paired helpers and the unattended password get in, and helpers' tools cannot run commands.")
            .changed();
        if changed {
            self.set_login(login);
        }
    }
    /// Set the copy at the sign in screen up, or take it away, on a thread,
    /// since it waits for an administrator.
    fn set_login(&mut self, on: bool) {
        if !crate::login::SUPPORTED || self.login_change.is_some() {
            return;
        }
        // The app in the tray takes over once somebody signs in.
        if on && !self.autostart && autostart::set(true).is_ok() {
            self.autostart = true;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send((on, crate::login::set(on)));
        });
        self.login_change = Some(rx);
        self.say("Waiting for an administrator to allow it");
    }
    /// Unattended access that stops at a restart until somebody signs in is
    /// not what anyone switching it on expects, so switching it on sets up
    /// the copy at the sign in screen too. The checkbox below still turns
    /// that part off.
    fn reachable_before_sign_in(&mut self) {
        if !self.login {
            self.set_login(true);
        }
    }
}

/// Whether to offer setting up the copy at the sign in screen.
/// The person's answer to a helper who is not paired: nothing beyond
/// viewing and control unless they ticked it, and nothing at all when they
/// declined.
fn answer(ask: &Ask, approval: Approval) -> Asked {
    let allowed = !matches!(approval, Approval::Deny);
    Asked {
        approval,
        tools: allowed && ask.tools && ask.allow_tools,
        clipboard: allowed && ask.clipboard && ask.allow_clipboard,
        pair: allowed && ask.pair,
    }
}
fn show_login_notice(
    supported: bool,
    unattended_on: bool,
    copy_present: bool,
    dismissed: bool,
    changing: bool,
) -> bool {
    supported && unattended_on && !copy_present && !dismissed && !changing
}

/// The empty file that remembers the notice was answered with Not now. It
/// sits beside the machine ID and is never part of `access.json`.
fn notice_path() -> Option<PathBuf> {
    boundary_provision::platform::data_dir()
        .ok()
        .map(|dir| dir.join("sign-in-screen-notice-dismissed"))
}

fn notice_dismissed() -> bool {
    notice_path().is_some_and(|path| path.exists())
}

/// Whether this session is on the physical screen and locked.
#[cfg(windows)]
fn screen_locked() -> bool {
    use boundary_platform::system;
    system::console().is_some_and(|c| c.locked && Some(c.session) == system::own_session())
}
#[cfg(not(windows))]
fn screen_locked() -> bool {
    false
}

/// Write to `unattended.log` beside the machine ID and `access.json`.
fn log(access_path: &std::path::Path, line: &str) {
    if let Some(dir) = access_path.parent() {
        crate::journal::note(dir, "unattended.log", line);
    }
}

/// The state of unattended access in a word or two.
///
/// When DeskVNC, or the copy at the sign in or lock screen, holds the claim,
/// this app does not listen and never becomes reachable itself, but helpers
/// still get in through that copy, so it is on.
/// What the unattended status says once `name` connects, when what it said
/// before is about their last session ending. A helper whose link dropped
/// comes straight back, and "Helper stopped responding" stayed under their
/// banner for as long as the new session ran. `None` keeps what it says.
fn after_connect(message: &str, name: &str) -> Option<String> {
    message
        .starts_with(&format!("{name}'s session ended"))
        .then(|| format!("{name} connected again"))
}

fn label(enabled: bool, reachable: bool, handed_over: bool) -> &'static str {
    match (enabled, reachable, handed_over) {
        (false, _, _) => "Off",
        (true, true, _) => "On",
        (true, false, true) => "On, answered by DeskVNC",
        (true, false, false) => "Starting",
    }
}

/// An ID shortened for display; the Copy button gives the whole one.
pub fn short(id: &str) -> String {
    if id.len() > 16 {
        format!("{}…{}", &id[..8], &id[id.len() - 8..])
    } else {
        id.to_string()
    }
}

/// What to call this computer when a helper saves it.
pub fn computer_name() -> String {
    boundary_provision::platform::computer_name()
}

/// Starting the app, in the background, when the person signs in.
pub mod autostart {
    use anyhow::Result;
    use boundary_provision::autostart::{self, Entry};

    const ENTRY: Entry = Entry {
        name: "DeskVNC Support",
        label: "com.psmux.deskvnc.support",
        file: "deskvnc-support",
    };
    pub fn enabled() -> bool {
        autostart::enabled(ENTRY)
    }
    pub fn set(on: bool) -> Result<()> {
        // A translocated copy's path is gone after a restart. Always None
        // off macOS.
        anyhow::ensure!(
            !on || crate::install::translocated().is_none(),
            "Move DeskVNC Support to Applications first, so it can start when you sign in"
        );
        autostart::set(ENTRY, on)
    }
}

#[cfg(test)]
mod tests {
    use super::{Ask, after_connect, answer, label, show_login_notice};
    use boundary_session::{
        Approval,
        unattended::{Access, Helper},
    };

    fn knock(clipboard: bool) -> Ask {
        Ask {
            name: "Sam".into(),
            peer: "peer".into(),
            tools: false,
            allow_tools: false,
            clipboard,
            allow_clipboard: false,
            pair: false,
            answer: tokio::sync::oneshot::channel().0,
        }
    }

    #[test]
    fn a_helper_asking_by_id_sees_nothing_copied_unless_the_person_ticks_it() {
        let mut ask = knock(true);
        assert!(!answer(&ask, Approval::Control).clipboard);
        ask.allow_clipboard = true;
        assert!(answer(&ask, Approval::View).clipboard);
        assert!(!answer(&ask, Approval::Deny).clipboard);
        let mut old = knock(false);
        old.allow_clipboard = true;
        assert!(!answer(&old, Approval::Control).clipboard);
    }

    struct Fake;
    impl boundary_session::Desktop for Fake {
        fn capture(&mut self) -> anyhow::Result<boundary_session::Frame> {
            Ok(boundary_session::Frame {
                width: 2,
                height: 2,
                rgba: vec![200; 16],
            })
        }
        fn input(&mut self, _: boundary_session::Input) -> anyhow::Result<()> {
            Ok(())
        }
        fn release(&mut self) {}
        fn has_clipboard(&self) -> bool {
            true
        }
    }

    /// Whether a paired helper allowed to see what is copied, connecting as
    /// this app does, is let see it by a listener at the sign in screen
    /// (`login`) or in a signed in session.
    async fn sees_copies(login: bool) -> bool {
        use boundary_session::unattended::{self as u, Notice};
        let dir = std::env::temp_dir().join(format!(
            "support-clipboard-{}-{login}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let machine = u::load_or_create_key(&dir.join("machine.key")).unwrap();
        let friend = u::load_or_create_key(&dir.join("friend.key")).unwrap();
        let access_path = dir.join("access.json");
        let mut access = Access::default();
        access.enabled = true;
        let id = friend.public().to_string();
        access.trust(&id, "Friend", true).unwrap();
        access.allow_clipboard(&id, true);
        access.save(&access_path).unwrap();
        let local = boundary_session::HostOptions {
            relay: false,
            relay_url: None,
            bind_ip: None,
        };
        let desktop = || Ok(Box::new(Fake) as Box<dyn boundary_session::Desktop>);
        let mut listener = if login {
            u::listen_at_login(local.clone(), machine, access_path, desktop)
        } else {
            u::listen(local.clone(), machine, access_path, desktop)
        };
        let address = loop {
            match listener.notices.recv().await {
                Some(Notice::Ready { address, .. }) => break address,
                Some(Notice::Finished(result)) => panic!("listener ended: {result:?}"),
                _ => {}
            }
        };
        let _helper = u::connect_to_with(
            Ok(address),
            "Friend".into(),
            None,
            friend,
            local,
            crate::abilities(),
        );
        let seen = loop {
            match listener.notices.recv().await {
                Some(Notice::Connected { session, .. }) => break session.clipboard_read_allowed(),
                Some(Notice::Refused { reason, .. }) => panic!("refused: {reason}"),
                Some(Notice::Finished(result)) => panic!("listener ended: {result:?}"),
                _ => {}
            }
        };
        let _ = std::fs::remove_dir_all(&dir);
        seen
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sign_in_screen_never_shows_a_helper_what_is_copied() {
        // On Windows a listener on the machine's own addresses raises a
        // firewall prompt for each test build, as boundary-session's own
        // unattended tests note.
        if cfg!(windows) && std::env::var_os("BOUNDARY_LAN_TESTS").is_none() {
            return;
        }
        let wait = std::time::Duration::from_secs(60);
        // The same helper, with the same saved setting, sees copies once
        // somebody has signed in, so the check below is not empty.
        let signed_in = tokio::time::timeout(wait, sees_copies(false))
            .await
            .expect("timed out");
        assert!(signed_in, "the person allowed it for this helper");
        let at_login = tokio::time::timeout(wait, sees_copies(true))
            .await
            .expect("timed out");
        assert!(
            !at_login,
            "nobody signed in is there to copy anything for them"
        );
    }

    #[test]
    fn saved_helpers_do_not_see_what_is_copied_until_the_person_says_so() {
        // An access file written before the setting existed.
        let old: Access = serde_json::from_str(
            r#"{"enabled":true,"helpers":[{"id":"x","name":"Sam","control":true,"tools":true,"added":1}]}"#,
        )
        .unwrap();
        assert!(!old.helpers[0].clipboard);
        // A helper paired now starts with it off too.
        let mut access = Access::default();
        let id = boundary_session::unattended::machine_id(
            &boundary_session::unattended::SecretKey::generate(),
        );
        access.trust(&id, "Sam", true).unwrap();
        let Helper { clipboard, .. } = &access.helpers[0];
        assert!(!clipboard);
        assert!(access.allow_clipboard(&id, true));
        assert!(access.helpers[0].clipboard);
    }

    #[test]
    fn a_helper_coming_back_clears_the_news_of_their_last_session_ending() {
        // What the listener said when the helper's link went quiet.
        let ended = "Drive helper's session ended: Helper stopped responding: deadline has elapsed";
        assert_eq!(
            after_connect(ended, "Drive helper").as_deref(),
            Some("Drive helper connected again")
        );
        // Anything else, or another helper's session, stays as it was.
        assert_eq!(after_connect(ended, "Sam"), None);
        assert_eq!(
            after_connect(
                "Port 5940 is taken, so helpers must connect by machine ID",
                "Drive helper"
            ),
            None
        );
        assert_eq!(after_connect("", "Drive helper"), None);
    }

    #[test]
    fn the_sign_in_screen_notice_shows_only_while_the_copy_is_missing() {
        // Unattended on and no copy at the sign in screen: offer it.
        assert!(show_login_notice(true, true, false, false, false));
        // The copy is there, or the person said Not now: say nothing.
        assert!(!show_login_notice(true, true, true, false, false));
        assert!(!show_login_notice(true, true, false, true, false));
        // Unattended off, a platform with no sign in screen copy, or the
        // administrator prompt already open: nothing to offer.
        assert!(!show_login_notice(true, false, false, false, false));
        assert!(!show_login_notice(false, true, false, false, false));
        assert!(!show_login_notice(true, true, false, false, true));
    }

    #[test]
    fn another_copy_answering_is_not_shown_as_starting() {
        // DeskVNC, or the copy at the sign in screen, holds the claim, so
        // this app never listens. It used to say Starting for as long as
        // that copy ran, which read as stuck.
        assert_eq!(label(true, false, true), "On, answered by DeskVNC");
        assert_eq!(label(true, false, false), "Starting");
        assert_eq!(label(true, true, false), "On");
        assert_eq!(label(false, false, false), "Off");
    }
}
