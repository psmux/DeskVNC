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
    /// What their tools did, newest last.
    pub activity: Vec<String>,
    pub session: Session,
}

/// A helper that is not paired asking to come in by this computer's ID.
pub struct Ask {
    name: String,
    peer: String,
    tools: bool,
    allow_tools: bool,
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
    pub active: Option<Active>,
    ask: Option<Ask>,
    reachable: bool,
    password: String,
    confirm: String,
    message: String,
    error: bool,
    autostart: bool,
}

impl Unattended {
    pub fn new() -> Self {
        let mut this = Self {
            access_path: PathBuf::new(),
            machine: String::new(),
            key: None,
            access: Access::default(),
            listener: None,
            claim: None,
            active: None,
            ask: None,
            reachable: false,
            password: String::new(),
            confirm: String::new(),
            message: String::new(),
            error: false,
            autostart: autostart::enabled(),
        };
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
        // The primary display: nobody is there to pick another.
        let display = boundary_platform::displays()
            .ok()
            .and_then(|all| all.first().map(|d| d.id));
        let Some(display) = display else {
            self.fail("No display found to share unattended".into());
            return;
        };
        match boundary_provision::platform::claim_unattended() {
            Ok(Some(claim)) => self.claim = Some(claim),
            Ok(None) => {
                self.fail("DeskVNC on this computer is already answering unattended connections. Quit it, or leave unattended access to it".into());
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
        self.active = None;
        self.reachable = false;
    }
    /// Let the helper of the current attended session in any time, and tell
    /// them this computer's ID so they can save it.
    pub fn pair(&mut self, session: &Session, peer: &str, name: &str, tools: bool) {
        if let Err(error) = self.access.trust(peer, name, true) {
            self.fail(format!("{error:#}"));
            return;
        }
        self.access.allow_tools(peer, tools);
        self.access.enabled = true;
        if !self.save() {
            return;
        }
        self.start();
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
    /// This computer's lasting ID, the one a helper saves.
    pub fn machine_id(&self) -> &str {
        &self.machine
    }
    /// Whether the listener has confirmed it can be found by that ID.
    pub fn reachable(&self) -> bool {
        self.reachable
    }
    /// Drain the listener. `true` when a helper has just come in, so the
    /// caller brings the window forward.
    pub fn poll(&mut self) -> bool {
        let mut arrived = false;
        let mut finished = None;
        if let Some(listener) = self.listener.as_mut() {
            while let Ok(notice) = listener.notices.try_recv() {
                match notice {
                    Notice::Ready { .. } => {
                        self.reachable = true;
                        self.message =
                            "Unattended access is on. Paired helpers can connect any time".into();
                        self.error = false;
                    }
                    Notice::Status(status) => {
                        self.message = status;
                        self.error = false;
                    }
                    Notice::Connected {
                        name,
                        control,
                        session,
                        ..
                    } => {
                        self.active = Some(Active {
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
                            allow_tools: false,
                            pair: false,
                            answer,
                        });
                        arrived = true;
                    }
                    Notice::Refused { name, reason, .. } => {
                        self.message = format!("Turned away {name}: {reason}");
                        self.error = false;
                    }
                    Notice::Finished(result) => finished = Some(result),
                }
            }
        }
        if let Some(active) = self.active.as_mut() {
            while let Ok(event) = active.session.events.try_recv() {
                match event {
                    boundary_session::Event::Control(control) => active.control = control,
                    boundary_session::Event::Activity(line) => {
                        active.activity.push(line);
                        let excess = active.activity.len().saturating_sub(crate::ACTIVITY_LINES);
                        active.activity.drain(..excess);
                    }
                    boundary_session::Event::Finished(_) => {
                        self.active = None;
                        break;
                    }
                    _ => {}
                }
            }
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
                }
            });
        if let Some(approval) = decision
            && let Some(ask) = self.ask.take()
        {
            let allowed = !matches!(approval, Approval::Deny);
            let _ = ask.answer.send(Asked {
                approval,
                tools: allowed && ask.allow_tools,
                pair: allowed && ask.pair,
            });
            if allowed && ask.pair {
                // The listener saved them; show the list as it now is.
                if let Ok(access) = Access::load(&self.access_path) {
                    self.access = access;
                }
            }
        }
    }
    /// The banner shown on top of everything while a helper is connected
    /// unattended. The person at the computer always sees who is in and can
    /// end it with one click.
    pub fn banner(&mut self, ui: &mut egui::Ui) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let name = active.name.clone();
        let control = active.control;
        let tools = active.tools;
        let activity = active.activity.clone();
        let mut end = false;
        let mut stop_tools = false;
        egui::Frame::new()
            .fill(theme::pal(ui.ctx()).danger)
            .inner_margin(14.0)
            .corner_radius(10.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "{name} is connected to this computer{}",
                            if control {
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
                            end = true;
                        }
                        if tools && ui.button("Stop their commands").clicked() {
                            stop_tools = true;
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
                for line in &activity {
                    ui.label(
                        egui::RichText::new(line)
                            .color(egui::Color32::WHITE)
                            .small(),
                    );
                }
            });
        ui.add_space(8.0);
        if stop_tools && let Some(active) = self.active.as_mut() {
            active.session.set_tools(false);
            active.tools = false;
            self.say(format!(
                "{name}'s tools can no longer run commands in this session"
            ));
        }
        if end {
            if let Some(active) = self.active.take() {
                active.session.stop();
            }
            self.say(format!("Ended {name}'s session"));
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
                "Start Boundary when I sign in, so it is ready",
            )
            .changed()
        {
            match autostart::set(autostart) {
                Ok(()) => self.autostart = autostart,
                Err(error) => self.fail(format!("{error:#}")),
            }
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
