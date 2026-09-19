#![forbid(unsafe_code)]

use anyhow::{anyhow, ensure, Result};
use boundary_session::{Button, Event, HostOptions, Input, Invitation, Key, Session};
use parking_lot::Mutex;
use remote_core::{
    ClientCommand, ConnectOptions, DecodedRect, OptionsMismatch, ProtocolDriver, ProtocolKind,
    Rect, RectPayload, SessionEvent, SessionHandle, SessionState,
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct Pending {
    ticket: String,
    helper: String,
    created: Instant,
}
#[derive(Default)]
pub struct BoundaryDriver {
    pending: std::sync::Arc<Mutex<HashMap<String, Pending>>>,
}
impl BoundaryDriver {
    /// Register a short lived, single use invitation without putting its secret in window URLs.
    pub fn prepare(&self, ticket: String, helper: String) -> Result<String> {
        Invitation::decode(&ticket)?;
        ensure!(
            !helper.trim().is_empty()
                && helper.len() <= 80
                && !helper.chars().any(char::is_control),
            "Enter a helper name of at most 80 bytes"
        );
        let mut pending = self.pending.lock();
        pending.retain(|_, value| value.created.elapsed() < Duration::from_secs(60));
        ensure!(pending.len() < 32, "Too many pending support connections");
        let id = format!("boundary-{}", uuid::Uuid::new_v4());
        pending.insert(
            id.clone(),
            Pending {
                ticket,
                helper,
                created: Instant::now(),
            },
        );
        drop(pending);
        let expiry_map = self.pending.clone();
        let expiry_id = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            expiry_map.lock().remove(&expiry_id);
        });
        Ok(id)
    }
    pub fn forget(&self, id: &str) {
        self.pending.lock().remove(id);
    }
}
impl ProtocolDriver for BoundaryDriver {
    fn kind(&self) -> ProtocolKind {
        ProtocolKind::Boundary
    }
    fn spawn(
        &self,
        id: String,
        options: ConnectOptions,
        events: mpsc::Sender<SessionEvent>,
    ) -> std::result::Result<SessionHandle, OptionsMismatch> {
        if options.kind() != self.kind() {
            return Err(OptionsMismatch {
                expected: self.kind(),
                actual: options.kind(),
            });
        }
        let pending = self.pending.lock().remove(&options.host);
        let (commands, mut receiver) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            let work = async {
                let pending = pending.ok_or_else(|| anyhow!("This support invitation is no longer available. Paste a new invitation in the Library"))?;
                ensure!(
                    pending.created.elapsed() < Duration::from_secs(60),
                    "Support connection expired before the window opened"
                );
                let mut session = boundary_session::viewer(
                    pending.ticket,
                    pending.helper,
                    HostOptions::default(),
                );
                drive(&mut session, &mut receiver, &events, options.view_only).await
            };
            let result = tokio::select! {
                biased;
                _ = token.cancelled() => Ok(()),
                result = work => result,
            };
            let reason = match result {
                Ok(()) => "Support session ended".into(),
                Err(error) => error.to_string(),
            };
            let _ = events
                .send(SessionEvent::StateChanged(SessionState::Disconnected {
                    reason,
                    can_retry: false,
                    symbol: None,
                }))
                .await;
        });
        Ok(SessionHandle {
            id,
            kind: ProtocolKind::Boundary,
            commands,
            cancel,
        })
    }
}
async fn emit(events: &mpsc::Sender<SessionEvent>, event: SessionEvent) -> Result<()> {
    events
        .send(event)
        .await
        .map_err(|_| anyhow!("Session window closed"))
}
async fn permission(events: &mpsc::Sender<SessionEvent>, allowed: bool) -> Result<()> {
    emit(
        events,
        SessionEvent::Protocol(remote_core::ProtocolEvent::Boundary { control: allowed }),
    )
    .await
}
async fn drive(
    session: &mut Session,
    commands: &mut mpsc::Receiver<ClientCommand>,
    events: &mpsc::Sender<SessionEvent>,
    mut view_only: bool,
) -> Result<()> {
    let mut size = (0u16, 0u16);
    let mut input = InputState::default();
    let mut allowed = false;
    emit(events, SessionEvent::StateChanged(SessionState::Connecting)).await?;
    loop {
        tokio::select! {
            event = session.events.recv() => match event {
                Some(Event::Status(status)) => emit(events, SessionEvent::StateChanged(SessionState::Authenticating { method: status })).await?,
                Some(Event::Connected { control, .. }) => {
                    allowed = control;
                    emit(events, SessionEvent::DesktopName("Boundary support".into())).await?;
                    permission(events, allowed).await?;
                    emit(events, SessionEvent::StateChanged(SessionState::Connected)).await?;
                }
                Some(Event::Control(control)) => {
                    allowed = control;
                    input = InputState::default();
                    session.input(Input::Release)?;
                    permission(events, allowed).await?;
                }
                Some(Event::Finished(result)) => return result,
                None => return Ok(()),
                _ => {},
            },
            frame = session.frames.changed() => {
                frame?;
                let frame = session.frames.borrow_and_update().clone();
                if let Some(frame) = frame {
                    let current = (frame.width as u16, frame.height as u16);
                    if size != current {
                        size = current;
                        emit(events, SessionEvent::DesktopResize { width: size.0, height: size.1 }).await?;
                    }
                    let rect = Rect { x: 0, y: 0, width: size.0, height: size.1 };
                    emit(events, SessionEvent::FramebufferUpdate { rects: vec![DecodedRect { rect, payload: RectPayload::Rgba(frame.rgba.clone()) }], damage: rect }).await?;
                }
            },
            command = commands.recv() => match command {
                None | Some(ClientCommand::Disconnect) | Some(ClientCommand::CancelCredentials) => return Ok(()),
                Some(ClientCommand::SetViewOnly(value)) => {
                    view_only = value;
                    input = InputState::default();
                    session.input(Input::Release)?;
                }
                Some(ClientCommand::ReleaseAllKeys) => { input = InputState::default(); session.input(Input::Release)?; }
                Some(command @ (ClientCommand::Pointer { .. } | ClientCommand::Key { .. })) if allowed && !view_only => {
                    for event in input.translate(command, size) { session.input(event)?; }
                }
                Some(ClientCommand::Agent(intent)) => { emit(events, SessionEvent::AgentRefused(intent.refuse("Boundary does not implement this agent capability"))).await?; }
                _ => {},
            }
        }
    }
}
#[derive(Default)]
struct InputState {
    buttons: u16,
    modifiers: u8,
}
impl InputState {
    fn translate(&mut self, command: ClientCommand, size: (u16, u16)) -> Vec<Input> {
        let mut out = Vec::new();
        match command {
            ClientCommand::Pointer { x, y, button_mask } if size.0 > 0 && size.1 > 0 => {
                out.push(Input::Move {
                    x: x.min(size.0 - 1) as f32 / size.0.saturating_sub(1).max(1) as f32,
                    y: y.min(size.1 - 1) as f32 / size.1.saturating_sub(1).max(1) as f32,
                });
                for (mask, button) in [(1, Button::Left), (2, Button::Middle), (4, Button::Right)] {
                    if (self.buttons ^ button_mask) & mask != 0 {
                        out.push(Input::Button {
                            button,
                            down: button_mask & mask != 0,
                        });
                    }
                }
                if button_mask & 8 != 0 && self.buttons & 8 == 0 {
                    out.push(Input::Scroll { lines: -3 });
                }
                if button_mask & 16 != 0 && self.buttons & 16 == 0 {
                    out.push(Input::Scroll { lines: 3 });
                }
                self.buttons = button_mask;
            }
            ClientCommand::Key { keysym, down, .. } => {
                let special = match keysym {
                    0xff0d => Some(Key::Enter),
                    0xff09 => Some(Key::Tab),
                    0xff1b => Some(Key::Escape),
                    0xff08 => Some(Key::Backspace),
                    0xffff => Some(Key::Delete),
                    0xff51 => Some(Key::Left),
                    0xff53 => Some(Key::Right),
                    0xff52 => Some(Key::Up),
                    0xff54 => Some(Key::Down),
                    0xff50 => Some(Key::Home),
                    0xff57 => Some(Key::End),
                    0xff55 => Some(Key::PageUp),
                    0xff56 => Some(Key::PageDown),
                    0xffe1 | 0xffe2 => Some(Key::Shift),
                    0xffe3 | 0xffe4 => Some(Key::Control),
                    0xffe9 | 0xffea => Some(Key::Alt),
                    0xffeb | 0xffec | 0xffe7 | 0xffe8 => Some(Key::Meta),
                    _ => None,
                };
                if let Some(key) = special {
                    let mask = match key {
                        Key::Control => 1,
                        Key::Alt => 2,
                        Key::Meta => 4,
                        _ => 0,
                    };
                    if down {
                        self.modifiers |= mask;
                    } else {
                        self.modifiers &= !mask;
                    }
                    out.push(Input::Key { key, down });
                } else {
                    let code = if keysym & 0xff000000 == 0x01000000 {
                        keysym & 0x00ffffff
                    } else {
                        keysym
                    };
                    if let Some(c) = char::from_u32(code).filter(|c| !c.is_control()) {
                        if c.is_ascii_alphanumeric() && (self.modifiers != 0 || !down) {
                            out.push(Input::Key {
                                key: Key::Letter(c.to_ascii_lowercase()),
                                down,
                            });
                        } else if down {
                            out.push(Input::Text(c.to_string()));
                        }
                    }
                }
            }
            _ => {}
        }
        out
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coordinates_buttons_and_unicode_are_translated() {
        let mut state = InputState::default();
        let events = state.translate(
            ClientCommand::Pointer {
                x: 639,
                y: 359,
                button_mask: 1,
            },
            (640, 360),
        );
        assert!(matches!(events[0], Input::Move { x: 1.0, y: 1.0 }));
        assert!(matches!(
            events[1],
            Input::Button {
                button: Button::Left,
                down: true
            }
        ));
        let events = state.translate(
            ClientCommand::Key {
                keysym: 0x010003bb,
                keycode: None,
                down: true,
            },
            (640, 360),
        );
        assert!(matches!(&events[0], Input::Text(s) if s == "λ"));
    }
    #[test]
    fn bad_invitation_is_never_registered() {
        let driver = BoundaryDriver::default();
        assert!(driver.prepare("bad".into(), "Helper".into()).is_err());
        assert!(driver.pending.lock().is_empty());
    }
}
