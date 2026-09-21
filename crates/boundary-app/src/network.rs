use anyhow::{Context, Result, ensure};
use boundary_provision::{Provider, Setup, SetupRequest};
use boundary_session::HostOptions;
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf};

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", deny_unknown_fields)]
pub enum Profile {
    #[default]
    Automatic,
    Private {
        address: IpAddr,
    },
    Relay {
        url: String,
    },
}
impl Profile {
    pub fn options(&self) -> HostOptions {
        match self {
            Self::Automatic => HostOptions::default(),
            Self::Private { address } => HostOptions {
                relay: false,
                relay_url: None,
                bind_ip: Some(*address),
            },
            Self::Relay { url } => HostOptions {
                relay: true,
                relay_url: Some(url.clone()),
                bind_ip: None,
            },
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Private { address } => ensure!(
                !address.is_unspecified() && !address.is_multicast() && !address.is_loopback(),
                "Choose an address on your private network interface"
            ),
            Self::Relay { url } => boundary_session::validate_relay_url(url)?,
            Self::Automatic => {}
        }
        Ok(())
    }
    pub fn label(&self) -> String {
        match self {
            Self::Automatic => "Automatic connection with relay fallback".into(),
            Self::Private { address } => {
                format!("Private interface {address}. Public relay fallback is off")
            }
            Self::Relay { .. } => "Your compatible relay. No default public relay is added".into(),
        }
    }
}
fn config_path() -> Result<PathBuf> {
    Ok(boundary_provision::platform::data_dir()?.join("network.json"))
}
pub fn load() -> Result<Profile> {
    let path = config_path()?;
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Profile::default()),
        Err(error) => return Err(error.into()),
    };
    let profile: Profile = serde_json::from_slice(&bytes)
        .context("Saved network settings are invalid. Choose and save a connection mode again")?;
    profile.validate()?;
    Ok(profile)
}
fn save(profile: &Profile) -> Result<()> {
    use std::io::Write;
    profile.validate()?;
    let path = config_path()?;
    let parent = path.parent().context("Invalid settings path")?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&serde_json::to_vec_pretty(profile)?)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .map_err(|error| anyhow::anyhow!("Could not save network settings: {}", error.error))?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Choice {
    Automatic,
    Tailscale,
    Cloudflare,
    Private,
    Relay,
}
pub struct Wizard {
    pub open: bool,
    choice: Choice,
    address: String,
    relay: String,
    message: String,
    checked: Option<IpAddr>,
    pending: Option<Setup>,
    token: zeroize::Zeroizing<String>,
    account: String,
    team: String,
    emails: String,
    configure: bool,
    consent: bool,
    remove: bool,
    review: Option<Profile>,
}
impl Default for Wizard {
    fn default() -> Self {
        Self {
            open: false,
            choice: Choice::Automatic,
            address: String::new(),
            relay: String::new(),
            message: String::new(),
            checked: None,
            pending: None,
            token: String::new().into(),
            account: String::new(),
            team: String::new(),
            emails: String::new(),
            configure: false,
            consent: false,
            remove: false,
            review: None,
        }
    }
}
impl Wizard {
    pub fn begin(&mut self, profile: &Profile) {
        self.open = true;
        self.review = None;
        self.message.clear();
        self.checked = None;
        match profile {
            Profile::Automatic => self.choice = Choice::Automatic,
            Profile::Private { address } => {
                self.choice = Choice::Private;
                self.address = address.to_string();
            }
            Profile::Relay { url } => {
                self.choice = Choice::Relay;
                self.relay = url.clone();
            }
        }
    }
    pub fn show(&mut self, ctx: &egui::Context) -> Option<Profile> {
        if !self.open {
            return None;
        }
        if let Some(pending) = &self.pending {
            let progress = pending.progress.borrow().clone();
            self.message = progress.message;
            if progress.finished {
                self.checked = progress.address;
                if let Some(ip) = progress.address {
                    self.address = ip.to_string();
                }
                self.pending = None;
            } else {
                ctx.request_repaint_after(std::time::Duration::from_millis(200));
            }
        }
        let mut applied = None;
        let mut open = self.open;
        egui::Window::new("Set up your connection").open(&mut open).collapsible(false).resizable(false).default_width(570.0).show(ctx, |ui| {
            if let Some(profile) = self.review.clone() {
                ui.heading("Review connection settings");
                ui.label(profile.label());
                ui.label("These settings are saved on this device. Existing sessions are unchanged.");
                ui.label("This checks local configuration only. A successful DeskVNC session verifies the complete path. Sharing still needs approval.");
                if matches!(profile, Profile::Private { .. }) {
                    ui.label("If this network is unavailable or your address changes, connection will fail instead of using a public relay. Run setup again to select the new address.");
                }
                ui.horizontal(|ui| {
                    if ui.button("Back").clicked() { self.review = None; }
                    if ui.button("Save connection settings").clicked() {
                        match save(&profile) {
                            Ok(()) => applied = Some(profile),
                            Err(error) => self.message = format!("Could not save settings: {error}"),
                        }
                    }
                });
            } else {
                ui.label("Keep the defaults, or use infrastructure you already control.");
                let before = self.choice;
                ui.radio_value(&mut self.choice, Choice::Automatic, "Automatic (recommended for a support call)");
                ui.radio_value(&mut self.choice, Choice::Tailscale, "Set up my Tailscale network");
                ui.radio_value(&mut self.choice, Choice::Private, "Use another existing private network");
                ui.radio_value(&mut self.choice, Choice::Relay, "Use my compatible relay server");
                ui.radio_value(&mut self.choice, Choice::Cloudflare, "Set up my private Cloudflare network");
                if before != self.choice { self.message.clear(); self.checked = None; self.pending = None; self.token = Default::default(); self.consent = false; self.remove = false; }
                ui.separator();
                match self.choice {
                    Choice::Automatic => { ui.label("Tries direct connectivity with encrypted relay fallback. No provider account is needed. Public relays have capacity limits and no uptime guarantee."); },
                    Choice::Tailscale | Choice::Cloudflare => {
                        self.provider_form(ui);
                    },
                    Choice::Private => {
                        ui.label("For an existing Headscale, WireGuard, Cloudflare private network or other routed network. Enter this device's local interface IP. Both machines need a permitted route; entering an IP does not enroll either device.");
                        ui.label("Local interface IP address");
                        ui.text_edit_singleline(&mut self.address);
                    },
                    Choice::Relay => {
                        ui.label("Enter a compatible iroh relay URL. The invitation carries it to DeskVNC. This can run on your own server; this wizard does not deploy that server.");
                        ui.text_edit_singleline(&mut self.relay);
                        ui.hyperlink_to("Relay hosting options", "https://www.iroh.computer/services/hosting");
                    },
                }
                let enabled = self.pending.is_none() && (!matches!(self.choice, Choice::Tailscale | Choice::Cloudflare) || self.checked.is_some());
                if ui.add_enabled(enabled, egui::Button::new("Review settings")).clicked() {
                    let result = self.selected_profile().and_then(|profile| {
                        profile.validate()?;
                        if let Profile::Private { address } = &profile {
                            let _socket = std::net::UdpSocket::bind((*address, 0)).context("This IP is not available on this device. Connect your private network and check its address")?;
                        }
                        Ok(profile)
                    });
                    match result { Ok(profile) => { self.review = Some(profile); self.message.clear(); }, Err(error) => self.message = error.to_string() }
                }
            }
            if !self.message.is_empty() { ui.separator(); ui.label(&self.message); }
        });
        self.open = open && applied.is_none();
        if !self.open {
            self.pending = None;
            self.token = Default::default();
        }
        applied
    }
    fn provider_form(&mut self, ui: &mut egui::Ui) {
        let cloudflare = self.choice == Choice::Cloudflare;
        ui.label("Boundary installs the official client if missing, then enrolls this device. Complete the provider login and operating system prompts when they appear. Windows setup adds a UDP firewall rule limited to this app and the private provider network. Run setup on the helper device too.");
        if cloudflare {
            ui.label("Cloudflare team name");
            ui.text_edit_singleline(&mut self.team);
            ui.checkbox(
                &mut self.configure,
                "Configure my Cloudflare account through its API",
            );
            if self.configure {
                ui.label("Account ID");
                ui.text_edit_singleline(&mut self.account);
                ui.label("Enrollment email addresses, separated by commas");
                ui.text_edit_singleline(&mut self.emails);
                ui.label("Scoped API token");
                ui.add(egui::TextEdit::singleline(&mut *self.token).password(true));
                ui.label("Creates an email enrollment policy and a private Mesh device profile. Enables device connectivity for the account. Existing account access policies still apply.");
            }
        } else {
            ui.label("Device auth key (optional, leave empty for browser login)");
            ui.add(egui::TextEdit::singleline(&mut *self.token).password(true));
        }
        ui.checkbox(
            &mut self.consent,
            "Install the provider client and apply the setup described above",
        );
        if ui
            .add_enabled(
                self.consent && self.pending.is_none(),
                egui::Button::new("Install and connect"),
            )
            .clicked()
        {
            self.checked = None;
            self.pending = Some(boundary_provision::start(SetupRequest {
                provider: if cloudflare {
                    Provider::Cloudflare
                } else {
                    Provider::Tailscale
                },
                auth_key: std::mem::take(&mut self.token),
                account_id: self.account.trim().into(),
                team: self.team.trim().into(),
                emails: self
                    .emails
                    .split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(String::from)
                    .collect(),
                configure_account: cloudflare && self.configure,
            }));
        }
        if cloudflare && self.configure && self.pending.is_none() {
            ui.checkbox(&mut self.remove, "Remove this deployment's Cloudflare enrollment policy and device profile. This can interrupt access.");
            if ui
                .add_enabled(
                    self.remove,
                    egui::Button::new("Remove Boundary account resources"),
                )
                .clicked()
            {
                self.checked = None;
                self.pending = Some(boundary_provision::start_cleanup(
                    self.account.trim().into(),
                    std::mem::take(&mut self.token),
                ));
                self.remove = false;
            }
        }
        if self.pending.is_some() && ui.button("Cancel setup").clicked() {
            self.pending = None;
            self.message =
                "Setup cancelled. Completed provider changes are retained for resume.".into();
        }
    }
    fn selected_profile(&self) -> Result<Profile> {
        Ok(match self.choice {
            Choice::Automatic => Profile::Automatic,
            Choice::Tailscale | Choice::Cloudflare => Profile::Private {
                address: self.checked.context("Complete provider setup first")?,
            },
            Choice::Private => Profile::Private {
                address: self
                    .address
                    .trim()
                    .parse()
                    .context("Enter an IPv4 or IPv6 address")?,
            },
            Choice::Relay => Profile::Relay {
                url: self.relay.trim().to_owned(),
            },
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_settings_never_enable_relay() {
        let profile = Profile::Private {
            address: "100.100.1.2".parse().unwrap(),
        };
        let restored: Profile =
            serde_json::from_slice(&serde_json::to_vec(&profile).unwrap()).unwrap();
        assert!(!restored.options().relay);
        assert_eq!(
            restored.options().bind_ip,
            Some("100.100.1.2".parse().unwrap())
        );
        assert!(
            serde_json::from_str::<Profile>(r#"{"mode":"Private","address":"0.0.0.0"}"#)
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(serde_json::from_str::<Profile>(r#"{"mode":"unexpected"}"#).is_err());
    }
}
