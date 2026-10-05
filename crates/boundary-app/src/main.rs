// No console window behind the app on Windows.
#![cfg_attr(windows, windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod codes;
mod network;
mod theme;
mod unattended;

use boundary_session::{
    Approval, Button, Event, HostOptions, Input, Key, Session, unattended::SecretKey,
};
use eframe::egui::{self, Margin, RichText};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

fn main() -> eframe::Result {
    let runtime = tokio::runtime::Runtime::new().expect("Cannot start the connection runtime");
    let _guard = runtime.enter();
    let result = eframe::run_native(
        "Boundary",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([980.0, 660.0])
                .with_min_inner_size([820.0, 600.0]),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    );
    runtime.shutdown_timeout(Duration::from_secs(3));
    result
}
struct Pending {
    name: String,
    peer: String,
    answer: oneshot::Sender<Approval>,
}
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
    invitation: String,
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
}
impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        // Started at sign in for unattended access: out of the way until a
        // helper connects, when the window comes forward to say so.
        if std::env::args().any(|a| a == "--background") {
            cc.egui_ctx
                .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
        let context = cc.egui_ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                context.request_repaint();
            }
        });
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
            invitation: String::new(),
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
            permission_check: Instant::now(),
            remote_focus: false,
            modifiers: egui::Modifiers::default(),
            unattended: unattended::Unattended::new(),
            helper_key,
            helper: None,
            approved_name: String::new(),
            paired: None,
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
        self.invitation.clear();
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
    /// Share this computer: a host session whose invitation becomes the code
    /// on the home screen.
    fn share(&mut self) {
        let Some(display) = self.displays.get(self.display) else {
            return;
        };
        let id = display.id;
        self.hosting = true;
        self.error = false;
        self.status = "Creating your code".into();
        self.session = Some(boundary_session::host(self.network_options(), move || {
            boundary_platform::open(id)
        }));
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
            self.session = Some(boundary_session::viewer_as(
                target,
                name,
                self.network_options(),
                self.helper_key.clone(),
            ));
        } else if boundary_session::unattended::validate_machine_id(&target).is_ok() {
            let Some(key) = self.helper_key.clone() else {
                self.status = "This copy of Boundary has no helper identity, so it cannot connect to an unattended computer".into();
                self.error = true;
                return;
            };
            let password = Some(self.password.clone()).filter(|p| !p.is_empty());
            self.status = "Connecting to the computer".into();
            self.session = Some(boundary_session::unattended::connect(
                target,
                name,
                password,
                key,
                self.network_options(),
            ));
        } else {
            self.codes.resolve(target);
        }
        self.ticket.clear();
        self.password.clear();
    }
    fn poll(&mut self, ctx: &egui::Context) {
        if self.unattended.poll() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        self.codes.private_required = !matches!(self.network, network::Profile::Automatic);
        if let Some(ticket) = self.codes.poll() {
            self.hosting = false;
            self.error = false;
            self.session = Some(boundary_session::viewer_as(
                ticket,
                self.name.trim().to_owned(),
                self.network_options(),
                self.helper_key.clone(),
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
                        self.invitation = ticket;
                        self.status =
                            "Waiting for your helper. The code expires in 10 minutes".into();
                    }
                    Event::Approval { name, peer, answer } => {
                        self.approved_name = name.clone();
                        self.pending = Some(Pending { name, peer, answer });
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
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
                    Event::Control(control) => {
                        self.control = control;
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
        if let Some(result) = finished {
            self.stop();
            if let Err(error) = result {
                self.status = format!("{error:#}");
                self.error = true;
            }
        }
    }
    /// The home screen: this computer on the left, a remote one on the right.
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
            ui.set_min_height(360.0);
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
                        "After granting it, quit and reopen Boundary if sharing still fails.",
                    );
                } else if self.displays.is_empty() {
                    ui.colored_label(theme::BAD, "No display found to share.");
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
                            theme::primary(label).min_size(egui::vec2(ui.available_width(), 46.0)),
                        )
                        .clicked()
                    {
                        self.share();
                    }
                    theme::small(
                        ui,
                        "One code per session. It expires after 10 minutes if nobody connects.",
                    );
                }
            } else if self.invitation.is_empty() || self.codes.publishing() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    theme::muted(
                        ui,
                        if self.invitation.is_empty() {
                            "Creating your code"
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
                if theme::value_box(ui, &code, 30.0) {
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
                ui.add(
                    egui::TextEdit::multiline(&mut self.invitation.as_str())
                        .font(egui::TextStyle::Small)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                if ui
                    .add(
                        theme::primary("Copy invitation")
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
                    ui.colored_label(theme::BAD, self.codes.message());
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
                    ui.colored_label(
                        theme::GOOD,
                        if self.unattended.reachable() {
                            "On"
                        } else {
                            "Starting"
                        },
                    );
                    ui.monospace(unattended::short(self.unattended.machine_id()));
                    if ui.small_button("Copy ID").clicked() {
                        ui.ctx().copy_text(self.unattended.machine_id().to_owned());
                    }
                } else {
                    theme::muted(ui, "Off");
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Change").clicked() {
                        self.page = Page::Settings;
                    }
                });
            });
        });
    }
    /// Control remote computer: where the other side's code goes.
    fn connect_card(&mut self, ui: &mut egui::Ui) {
        theme::card(ui, |ui| {
            ui.set_min_height(360.0);
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
                        .font(egui::FontId::monospace(20.0))
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
                        theme::primary("Connect").min_size(egui::vec2(ui.available_width(), 46.0)),
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
                ui.colored_label(theme::BAD, self.codes.message());
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
                    ui.colored_label(theme::BAD, error);
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
                    "Boundary {} · Attended and unattended support · No DeskVNC installation required",
                    env!("CARGO_PKG_VERSION")
                ),
            );
            ui.add_space(6.0);
        });
    }
    fn sharing(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
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
                    self.unattended.pair(session, &peer, &name);
                }
            }
            ui.add_space(14.0);
            theme::small(
                ui,
                "Use End session above to disconnect. Closing Boundary also ends sharing.",
            );
        });
    }
    fn remote(&mut self, ui: &mut egui::Ui) {
        theme::small(
            ui,
            if self.control {
                "Control allowed. Click the remote screen to send input. Click outside it to release input."
            } else {
                "View only. The person sharing can allow control from their window."
            },
        );
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
                egui::Event::Paste(text) => {
                    for chunk in text.chars().collect::<Vec<_>>().chunks(200) {
                        self.send(Input::Text(chunk.iter().collect()));
                    }
                }
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
impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.poll(ctx);
    }
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(theme::CARD)
                    .inner_margin(Margin::symmetric(24, 10)),
            )
            .show(ui, |ui| self.status_bar(ui));
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::PAGE)
                    .inner_margin(Margin::symmetric(24, 14)),
            )
            .show(ui, |ui| self.content(ui));
    }
}
impl App {
    /// The bar every remote support tool has at the bottom: a dot, and what
    /// is going on.
    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let color = if self.error {
                theme::BAD
            } else if self.connected || self.session.is_none() {
                theme::GOOD
            } else {
                theme::WARN
            };
            theme::dot(ui, color);
            ui.label(RichText::new(&self.status).color(theme::TEXT));
            if let Some(session) = &self.session {
                let connectivity = session.connectivity.borrow();
                if let Some(warning) = &connectivity.warning {
                    ui.colored_label(theme::WARN, warning);
                }
                if self.connected
                    && let Some(route) = connectivity.route
                {
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
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                theme::small(ui, self.network.label());
            });
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
                RichText::new("Boundary")
                    .size(26.0)
                    .strong()
                    .color(theme::TEXT),
            );
            ui.add_space(4.0);
            theme::muted(ui, "Remote support");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.session.is_some() {
                    if ui.add(theme::danger("End session")).clicked() {
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
        self.unattended.banner(ui);
        if self.connected && self.hosting {
            self.sharing(ui);
        } else if self.connected {
            self.remote(ui);
        } else if self.page == Page::Settings {
            self.settings(ui);
        } else {
            self.home(ui);
        }
        if let Some(pending) = self.pending.as_ref() {
            let mut decision = None;
            egui::Window::new("Approve this helper?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ui.ctx(), |ui| {
                    ui.set_width(420.0);
                    ui.label(
                        RichText::new(format!("{} wants to see your screen.", pending.name))
                            .size(17.0),
                    );
                    theme::small(ui, "The name is supplied by the helper. Confirm it with the person you invited.");
                    ui.add_space(6.0);
                    theme::caption(ui, "Helper connection identity");
                    ui.monospace(&pending.peer);
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                self.input_permission,
                                theme::primary("Allow viewing and control"),
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
                    }
                });
            if let Some(decision) = decision
                && let Some(pending) = self.pending.take()
            {
                let _ = pending.answer.send(decision);
            }
        }
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
