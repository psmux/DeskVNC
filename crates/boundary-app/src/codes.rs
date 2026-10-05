use eframe::egui;
use tokio::{sync::oneshot, task::JoinHandle};

use crate::theme;

enum Reply {
    Published(boundary_codes::Lease),
    Resolved(String),
}
struct Pending {
    publish: bool,
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
    /// A code is being created for this computer's invitation.
    pub fn publishing(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| p.publish)
    }
    /// A code typed by the helper is being looked up.
    pub fn resolving(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| !p.publish)
    }
    /// The numeric code for this computer, as four digit groups.
    pub fn code(&self) -> Option<String> {
        self.lease.as_ref().map(|lease| lease.display())
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    /// Whether a code service can be used at all: the shared one, or the
    /// private one a person set. Private infrastructure never falls back to
    /// the shared service.
    pub fn available(&self) -> bool {
        if self.url.trim().is_empty() {
            !self.private_required && !boundary_codes::default_service().is_empty()
        } else {
            true
        }
    }
    pub fn clear(&mut self) {
        self.pending = None;
        self.lease = None;
        self.message.clear();
    }
    pub fn resolve(&mut self, value: String) {
        self.start(value, false);
    }
    /// Turn this computer's invitation into a short code.
    pub fn publish(&mut self, ticket: String) {
        self.start(ticket, true);
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
            publish,
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
    /// The code service setting, on the Settings page.
    pub fn settings(&mut self, ui: &mut egui::Ui) {
        theme::muted(
            ui,
            "A short code is easier to read out than a full invitation. Both people must use the same code service, and it can read the invitations it is given, so use one you trust.",
        );
        ui.add_space(6.0);
        theme::caption(ui, "Code service URL");
        ui.add_enabled(
            self.lease.is_none() && !self.busy(),
            theme::field(&mut self.url, "https://codes.example.com"),
        );
        theme::small(
            ui,
            if boundary_codes::default_service().is_empty() {
                "Leave empty to use full invitations only."
            } else {
                "Leave empty for the shared Boundary service. Private infrastructure needs its own service here."
            },
        );
        if !self.message.is_empty() {
            ui.colored_label(theme::pal(ui.ctx()).danger, &self.message);
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
        assert!(!codes.available());
        codes.resolve("123456789012".into());
        assert!(!codes.busy());
        assert!(codes.message.contains("explicit private code service"));
    }
}
