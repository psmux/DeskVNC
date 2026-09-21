#![forbid(unsafe_code)]

mod codes;
mod network;

use boundary_session::{Approval, Button, Event, HostOptions, Input, Key, Session};
use eframe::egui;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

fn main() -> eframe::Result {
    let runtime = tokio::runtime::Runtime::new().expect("Cannot start the connection runtime");
    let _guard = runtime.enter();
    let result = eframe::run_native(
        "Boundary",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1040.0, 740.0])
                .with_min_inner_size([760.0, 580.0]),
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
struct App {
    codes: codes::Codes,
    session: Option<Session>,
    hosting: bool,
    connected: bool,
    control: bool,
    invitation: String,
    ticket: String,
    name: String,
    status: String,
    error: bool,
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
}
impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        let context = cc.egui_ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                context.request_repaint();
            }
        });
        let (displays, status, error) = match boundary_platform::displays() {
            Ok(displays) => (displays, "Ready when you are".into(), false),
            Err(error) => (vec![], format!("Could not list displays: {error:#}"), true),
        };
        let (network, network_error) = match network::load() {
            Ok(profile) => (profile, None),
            Err(error) => (network::Profile::default(), Some(error.to_string())),
        };
        Self {
            codes: codes::Codes::default(),
            session: None,
            hosting: false,
            connected: false,
            control: false,
            invitation: String::new(),
            ticket: String::new(),
            name: String::new(),
            status,
            error,
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
        }
    }
    fn network_options(&self) -> HostOptions {
        self.network.options()
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
        self.status = "Session ended. The invitation is no longer usable".into();
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
    fn poll(&mut self, ctx: &egui::Context) {
        self.codes.private_required = !matches!(self.network, network::Profile::Automatic);
        if let Some(ticket) = self.codes.poll() {
            self.hosting = false;
            self.error = false;
            self.session = Some(boundary_session::viewer(
                ticket,
                self.name.trim().to_owned(),
                self.network_options(),
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
                        self.invitation = ticket;
                        self.status =
                            "Waiting for a helper. Invitation expires in 10 minutes".into();
                    }
                    Event::Approval { name, peer, answer } => {
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
                    }
                    Event::Control(control) => {
                        self.control = control;
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
    fn home(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);
        ui.columns(2, |columns| {
            columns[0].group(|ui| {
                ui.set_min_height(280.0);
                ui.set_width(ui.available_width());
                ui.heading("Get support");
                ui.label("Share an invitation with someone you trust. You approve their connection before they can see your screen.");
                ui.add_space(16.0);
                egui::ComboBox::from_id_salt("display").selected_text(self.displays.get(self.display).map(|d| d.name.as_str()).unwrap_or("No display found")).show_ui(ui, |ui| {
                    for (index, display) in self.displays.iter().enumerate() { ui.selectable_value(&mut self.display, index, &display.name); }
                });
                if !self.screen_permission {
                    ui.label("Screen Recording permission is needed to share.");
                    if ui.button("Allow screen recording").clicked() { boundary_platform::request_screen_permission(); }
                    ui.small("After granting permission, quit and reopen Boundary if sharing still fails.");
                }
                ui.add_space(12.0);
                if ui.add_enabled(self.session.is_none() && !self.codes.busy() && self.network_error.is_none() && !self.displays.is_empty() && self.screen_permission, egui::Button::new("Create invitation").min_size(egui::vec2(180.0, 38.0))).clicked() {
                    let id = self.displays[self.display].id;
                    self.hosting = true;
                    self.error = false;
                    self.session = Some(boundary_session::host(self.network_options(), move || boundary_platform::open(id)));
                }
                if !self.invitation.is_empty() {
                    ui.add_space(12.0);
                    self.codes.invitation(ui, &self.invitation);
                    if ui.button("Copy invitation").clicked() { ui.ctx().copy_text(self.invitation.clone()); }
                    ui.small("Send it in your existing chat. Keep it private. It is valid for one accepted session.");
                    ui.add(egui::TextEdit::multiline(&mut self.invitation.as_str()).desired_rows(3).desired_width(f32::INFINITY));
                }
            });
            columns[1].group(|ui| {
                ui.set_min_height(280.0);
                ui.set_width(ui.available_width());
                ui.heading("Help someone");
                ui.label("Ask them to open Boundary and send you an invitation.");
                ui.add_space(16.0);
                ui.add_enabled_ui(self.session.is_none() && !self.codes.busy() && self.network_error.is_none(), |ui| {
                    ui.label("Your name, shown to the person you are helping");
                    ui.add(egui::TextEdit::singleline(&mut self.name).char_limit(80).desired_width(f32::INFINITY));
                    ui.add_space(8.0);
                    ui.label("Their support code or full invitation");
                    ui.add(egui::TextEdit::multiline(&mut self.ticket).hint_text("1234 5678 9012 or boundary1:…").char_limit(16384).desired_rows(4).desired_width(f32::INFINITY));
                    ui.add_space(12.0);
                    if ui.add_enabled(!self.name.trim().is_empty() && !self.ticket.trim().is_empty(), egui::Button::new("Connect").min_size(egui::vec2(140.0, 38.0))).clicked() {
                        self.hosting = false;
                        self.error = false;
                        if self.ticket.trim().starts_with("boundary1:") {
                            self.session = Some(boundary_session::viewer(self.ticket.trim().to_owned(), self.name.trim().to_owned(), self.network_options()));
                        } else {
                            self.codes.resolve(self.ticket.trim().to_owned());
                        }
                        self.ticket.clear();
                    }
                });
            });
        });
        ui.add_space(18.0);
        self.codes.settings(ui);
        ui.label(self.network.label());
        if let Some(error) = &self.network_error {
            ui.colored_label(egui::Color32::DARK_RED, error);
        }
        if ui
            .add_enabled(
                self.session.is_none() && !self.codes.busy(),
                egui::Button::new("Set up my infrastructure…"),
            )
            .clicked()
        {
            self.wizard.begin(&self.network);
        }
        ui.add_space(12.0);
        ui.small("macOS preview · Attended sessions only · No DeskVNC installation required");
    }
    fn sharing(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        ui.heading("Your screen is being shared");
        ui.label(
            "The helper can see the selected display, including notifications and this window.",
        );
        ui.add_space(16.0);
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
            ui.label("Control needs Accessibility permission. Viewing works without it.");
            if ui.button("Open Accessibility settings").clicked() {
                let _ = boundary_platform::open_input_settings();
            }
        }
        ui.add_space(16.0);
        ui.label("Use End session above to disconnect. Closing Boundary also ends sharing.");
    }
    fn remote(&mut self, ui: &mut egui::Ui) {
        ui.label(if self.control { "Control allowed. Click the remote screen to send input. Click outside it to release input." } else { "View only. The person sharing can allow control from their window." });
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
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(246, 248, 249))
                    .inner_margin(20),
            )
            .show(ui, |ui| self.content(ui));
    }
}
impl App {
    fn content(&mut self, ui: &mut egui::Ui) {
        if let Some(profile) = self.wizard.show(ui.ctx()) {
            self.network = profile;
            self.network_error = None;
            self.status =
                "Network settings saved. Create an invitation to test with DeskVNC".into();
        }
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.heading(egui::RichText::new("Boundary").size(30.0));
            ui.add_space(10.0);
            ui.label("Remote support");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.session.is_some()
                    && ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("End session").color(egui::Color32::WHITE),
                            )
                            .fill(egui::Color32::from_rgb(170, 40, 40))
                            .min_size(egui::vec2(140.0, 36.0)),
                        )
                        .clicked()
                {
                    self.stop();
                }
            });
        });
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);
        ui.colored_label(
            if self.error {
                egui::Color32::from_rgb(170, 40, 40)
            } else {
                egui::Color32::from_rgb(30, 90, 80)
            },
            &self.status,
        );
        if let Some(session) = &self.session {
            let connectivity = session.connectivity.borrow();
            if let Some(warning) = &connectivity.warning {
                ui.colored_label(egui::Color32::from_rgb(150, 85, 0), warning);
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
                    .map(|rtt| format!(" · round trip {} ms", rtt.as_millis()))
                    .unwrap_or_default();
                ui.small(format!("{label}{timing}"));
            }
        }
        if self.connected && self.hosting {
            self.sharing(ui);
        } else if self.connected {
            self.remote(ui);
        } else {
            self.home(ui);
        }
        if let Some(pending) = self.pending.as_ref() {
            let mut decision = None;
            egui::Window::new("Approve this helper?").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO).show(ui.ctx(), |ui| {
                ui.label(format!("{} wants to see your screen.", pending.name));
                ui.small("The name is supplied by the helper. Confirm it with the person you invited.");
                ui.label("Helper connection identity:");
                ui.monospace(&pending.peer);
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Decline").clicked() { decision = Some(Approval::Deny); }
                    if ui.button("Allow viewing").clicked() { decision = Some(Approval::View); }
                    if ui.add_enabled(self.input_permission, egui::Button::new("Allow viewing and control")).clicked() { decision = Some(Approval::Control); }
                });
                if !self.input_permission { ui.small("Accessibility permission is needed for control. You can allow viewing now."); }
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
