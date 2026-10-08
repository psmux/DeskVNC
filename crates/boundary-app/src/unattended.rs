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
    Session,
    unattended::{self, Access, Listener, MIN_PASSWORD, Notice},
};
use eframe::egui;
use std::path::PathBuf;

use crate::theme;

/// A helper connected with nobody's approval, held so the person at the
/// computer can see it and end it.
pub struct Active {
    pub name: String,
    pub control: bool,
    pub session: Session,
}

pub struct Unattended {
    access_path: PathBuf,
    machine: String,
    key: Option<boundary_session::unattended::SecretKey>,
    pub access: Access,
    listener: Option<Listener>,
    pub active: Option<Active>,
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
            active: None,
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
        self.active = None;
        self.reachable = false;
    }
    /// Let the helper of the current attended session in any time, and tell
    /// them this computer's ID so they can save it.
    pub fn pair(&mut self, session: &Session, peer: &str, name: &str) {
        if let Err(error) = self.access.trust(peer, name, true) {
            self.fail(format!("{error:#}"));
            return;
        }
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
                            session,
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
    /// The banner shown on top of everything while a helper is connected
    /// unattended. The person at the computer always sees who is in and can
    /// end it with one click.
    pub fn banner(&mut self, ui: &mut egui::Ui) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let name = active.name.clone();
        let control = active.control;
        let mut end = false;
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
                    });
                });
            });
        ui.add_space(8.0);
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
    let name = if cfg!(target_os = "macos") {
        std::process::Command::new("scutil")
            .args(["--get", "ComputerName"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else if cfg!(windows) {
        std::env::var("COMPUTERNAME").ok()
    } else {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
    };
    name.filter(|n| !n.is_empty() && n.len() <= 80)
        .unwrap_or_else(|| "This computer".into())
}

/// Starting the app, in the background, when the person signs in.
pub mod autostart {
    use anyhow::{Context, Result};

    // The entry's name on Windows and Linux; macOS names its agent by label.
    #[cfg(not(target_os = "macos"))]
    const NAME: &str = "DeskVNC Support";

    fn exe() -> Result<std::path::PathBuf> {
        std::env::current_exe().context("This app cannot find itself")
    }

    #[cfg(windows)]
    pub fn enabled() -> bool {
        std::process::Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                NAME,
            ])
            .output()
            .is_ok_and(|o| o.status.success())
    }
    #[cfg(windows)]
    pub fn set(on: bool) -> Result<()> {
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let status = if on {
            let value = format!("\"{}\" --background", exe()?.display());
            std::process::Command::new("reg")
                .args(["add", key, "/v", NAME, "/t", "REG_SZ", "/d", &value, "/f"])
                .output()?
                .status
        } else {
            std::process::Command::new("reg")
                .args(["delete", key, "/v", NAME, "/f"])
                .output()?
                .status
        };
        anyhow::ensure!(
            status.success(),
            "Windows did not accept the sign in setting"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn plist() -> Result<std::path::PathBuf> {
        Ok(
            std::path::PathBuf::from(std::env::var_os("HOME").context("No home folder")?)
                .join("Library/LaunchAgents/com.psmux.deskvnc.support.plist"),
        )
    }
    #[cfg(target_os = "macos")]
    pub fn enabled() -> bool {
        plist().is_ok_and(|p| p.exists())
    }
    #[cfg(target_os = "macos")]
    pub fn set(on: bool) -> Result<()> {
        let path = plist()?;
        if !on {
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.psmux.deskvnc.support</string>
<key>ProgramArguments</key><array><string>{}</string><string>--background</string></array>
<key>RunAtLoad</key><true/>
<key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>
"#,
            exe()?.display()
        );
        std::fs::create_dir_all(path.parent().context("No LaunchAgents folder")?)?;
        std::fs::write(&path, body)?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn desktop_file() -> Result<std::path::PathBuf> {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
            })
            .context("No configuration folder")?;
        Ok(config.join("autostart/deskvnc-support.desktop"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    pub fn enabled() -> bool {
        desktop_file().is_ok_and(|p| p.exists())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    pub fn set(on: bool) -> Result<()> {
        let path = desktop_file()?;
        if !on {
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }
        // An AppImage runs from a mount that goes when it quits; start the
        // AppImage file itself.
        let exe = std::env::var_os("APPIMAGE")
            .map(std::path::PathBuf::from)
            .map_or_else(exe, Ok)?;
        let body = format!(
            "[Desktop Entry]\nType=Application\nName={NAME}\nExec=\"{}\" --background\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n",
            exe.display()
        );
        std::fs::create_dir_all(path.parent().context("No autostart folder")?)?;
        std::fs::write(&path, body)?;
        Ok(())
    }
}
