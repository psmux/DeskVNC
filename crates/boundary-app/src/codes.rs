use eframe::egui;
use tokio::{sync::oneshot, task::JoinHandle};

enum Reply {
    Published(boundary_codes::Lease),
    Resolved(String),
}
struct Pending {
    task: JoinHandle<()>,
    reply: oneshot::Receiver<anyhow::Result<Reply>>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[derive(Default)]
pub struct Codes {
    pub private_required: bool,
    url: String,
    lease: Option<boundary_codes::Lease>,
    pending: Option<Pending>,
    message: String,
}
impl Codes {
    pub fn busy(&self) -> bool {
        self.pending.is_some()
    }
    pub fn clear(&mut self) {
        self.pending = None;
        self.lease = None;
        self.message.clear();
    }
    pub fn resolve(&mut self, value: String) {
        self.start(value, false);
    }
    fn start(&mut self, value: String, publish: bool) {
        if self.private_required && self.url.trim().is_empty() {
            self.message = "Your infrastructure mode requires an explicit private code service URL. Use the full invitation if you have no private code service".into();
            return;
        }
        let client = match boundary_codes::Client::new(&self.url) {
            Ok(client) => client,
            Err(error) => {
                self.message = error.to_string();
                return;
            }
        };
        let (send, reply) = oneshot::channel();
        self.message.clear();
        self.pending = Some(Pending {
            reply,
            task: tokio::spawn(async move {
                let result = if publish {
                    client.register(value).await.map(Reply::Published)
                } else {
                    client.resolve(&value).await.map(Reply::Resolved)
                };
                let _ = send.send(result);
            }),
        });
    }
    pub fn poll(&mut self) -> Option<String> {
        if let Some(pending) = self.pending.as_mut() {
            match pending.reply.try_recv() {
                Ok(result) => {
                    self.pending = None;
                    match result {
                        Ok(Reply::Published(lease)) => self.lease = Some(lease),
                        Ok(Reply::Resolved(ticket)) => return Some(ticket),
                        Err(error) => self.message = error.to_string(),
                    }
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.pending = None;
                    self.message = "Code request stopped".into();
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        None
    }
    pub fn invitation(&mut self, ui: &mut egui::Ui, ticket: &str) {
        ui.small("The code service receives this invitation. Use a service you trust.");
        if let Some(lease) = &self.lease {
            ui.heading(lease.display());
            if ui.button("Copy support code").clicked() {
                ui.ctx().copy_text(lease.display());
            }
            ui.small("Share privately. One lookup, expires with this invitation. The helper must use the same code service.");
        } else if ui
            .add_enabled(
                (!self.url.trim().is_empty() || !boundary_codes::default_service().is_empty())
                    && !self.busy(),
                egui::Button::new("Create numeric support code"),
            )
            .clicked()
        {
            self.start(ticket.to_owned(), true);
        }
    }
    pub fn settings(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Numeric support codes (optional)", |ui| {
            ui.label("Private code service URL (optional override)");
            ui.small("Leave empty for the shared Boundary service. Private infrastructure mode requires an explicit service override.");
            ui.add_enabled(self.lease.is_none() && !self.busy(), egui::TextEdit::singleline(&mut self.url).hint_text("https://codes.example.com"));
            ui.small("Both people use the same trusted service. Creating a code uploads the invitation to it. The service can read and replace invitations. Full invitations work without it.");
        });
        if self.busy() {
            ui.label("Contacting support code service…");
            if ui.button("Cancel code request").clicked() {
                self.clear();
            }
        }
        if !self.message.is_empty() {
            ui.colored_label(egui::Color32::DARK_RED, &self.message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_mode_never_uses_implicit_shared_service() {
        let mut codes = Codes {
            private_required: true,
            ..Default::default()
        };
        codes.resolve("123456789012".into());
        assert!(!codes.busy());
        assert!(codes.message.contains("explicit private code service"));
    }
}
