#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, ensure, Result};
use boundary_session::{
    tools::{Client, Reply, Request},
    unattended::{self, SecretKey},
    Button, Event, HostOptions, Input, Invitation, Key, Session,
};
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
/// Told when a person being helped lets this helper come back any time:
/// the machine's ID and its name, to save in the Library.
pub type OnPaired = std::sync::Arc<dyn Fn(String, String) + Send + Sync>;
/// The tools client of every live session whose host serves them, by
/// session ID.
type Registry = std::sync::Arc<Mutex<HashMap<String, Client>>>;
#[derive(Default)]
pub struct BoundaryDriver {
    pending: std::sync::Arc<Mutex<HashMap<String, Pending>>>,
    identity: std::sync::Arc<Mutex<Option<SecretKey>>>,
    paired: std::sync::Arc<Mutex<Option<OnPaired>>>,
    tools: Registry,
}
impl BoundaryDriver {
    /// How to send commands and file requests to the computer behind
    /// `session_id`, while that session lasts. `None` when there is no such
    /// session, it has not connected yet, or the computer's DeskVNC Support
    /// is too old to serve them. Whether the person there allows them is
    /// [`Client::allowed`], and the computer checks again on every request.
    pub fn tools(&self, session_id: &str) -> Option<Client> {
        self.tools.lock().get(session_id).cloned()
    }
    /// This helper's lasting identity. Without it every session uses a fresh
    /// one, so a pairing could never be recognised later.
    pub fn set_identity(&self, key: SecretKey) {
        *self.identity.lock() = Some(key);
    }
    /// What to do when a session tells this helper it was paired.
    pub fn on_paired(&self, paired: OnPaired) {
        *self.paired.lock() = Some(paired);
    }
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
        // A saved machine is opened by its ID; an invitation by the one use
        // token `prepare` handed out. Only a saved machine can be retried.
        let unattended =
            pending.is_none() && unattended::validate_machine_id(&options.host).is_ok();
        let identity = self.identity.lock().clone();
        let paired = self.paired.lock().clone();
        let registry = self.tools.clone();
        let session_id = id.clone();
        let (commands, mut receiver) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            let work = async {
                let mut session = match pending {
                    Some(pending) => {
                        ensure!(
                            pending.created.elapsed() < Duration::from_secs(60),
                            "Support connection expired before the window opened"
                        );
                        // With tools declared, so the person is asked about
                        // commands and files and an agent can use them once
                        // they say yes.
                        boundary_session::viewer_with_tools(
                            pending.ticket,
                            pending.helper,
                            HostOptions::default(),
                            identity,
                        )
                    }
                    None if unattended => {
                        let key = identity.ok_or_else(|| anyhow!("This copy of DeskVNC has no helper identity, so it cannot be recognised by a computer it was paired with"))?;
                        let name = options
                            .credentials
                            .username
                            .clone()
                            .filter(|n| !n.trim().is_empty())
                            .unwrap_or_else(helper_name);
                        unattended::connect_with_tools(
                            options.host.clone(),
                            name,
                            options.credentials.password.clone().filter(|p| !p.is_empty()),
                            key,
                            HostOptions::default(),
                        )
                    }
                    None => bail!("This support invitation is no longer available. Paste a new invitation in the Library"),
                };
                drive(
                    &mut session,
                    &mut receiver,
                    &events,
                    options.view_only,
                    paired,
                    Tools {
                        registry,
                        session_id,
                    },
                )
                .await
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
                    can_retry: unattended,
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
async fn permission(events: &mpsc::Sender<SessionEvent>, allowed: bool, tools: bool) -> Result<()> {
    emit(
        events,
        SessionEvent::Protocol(remote_core::ProtocolEvent::Boundary {
            control: allowed,
            tools,
        }),
    )
    .await
}
/// Said when the person at the computer has not allowed commands and files.
pub const NOT_ALLOWED: &str = "the person at that computer has not allowed commands and files for this session. Ask them to tick Allow the helper's tools to run commands and copy files in DeskVNC Support, or, for an unattended computer, to allow it for this helper under Settings, Unattended access. Nothing ran";
/// Said when the computer's support app predates commands and files.
pub const TOO_OLD: &str = "that computer's DeskVNC Support is older than commands and files over Boundary, so it cannot run a command. Ask them to update it from the latest release. Nothing ran";
/// Where this session's tools client is published, and taken back from.
struct Tools {
    registry: Registry,
    session_id: String,
}
impl Drop for Tools {
    fn drop(&mut self) {
        self.registry.lock().remove(&self.session_id);
    }
}

/// Run one command on the computer, and answer the intent with what running
/// it produced. Spawned, so a long command never holds up the screen.
///
/// Nothing here invents a status. A command the computer refused or could
/// not start is a refusal, because nothing ran. A link lost after the
/// request went out is a served answer saying so, because the command may
/// well have run.
fn exec(
    client: Client,
    intent: remote_core::intent::AgentIntent,
    events: mpsc::Sender<SessionEvent>,
) {
    use remote_core::intent::{
        CommandExit, CommandRun, Dropped, ExitTier, IntentKind, ServedAnswer, Truncation,
        Unanswered,
    };
    tokio::spawn(async move {
        let IntentKind::Exec { spec } = &intent.kind else {
            return;
        };
        let request = Request::Run {
            command: spec.command.clone(),
            cwd: spec.cwd.clone(),
            env: spec.env.clone(),
            timeout_ms: spec.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
            max_output: spec.max_output_bytes.unwrap_or(0),
        };
        let stdin = spec.stdin.as_deref().unwrap_or_default();
        let started = Instant::now();
        let event = match client
            .call(&request, stdin, spec.timeout + Duration::from_secs(15))
            .await
        {
            Ok((
                Reply::Ran {
                    code,
                    signal,
                    timed_out,
                    stdout,
                    cap,
                    stdout_dropped,
                    stdout_dropped_lines,
                    stderr_dropped,
                    stderr_dropped_lines,
                    duration_ms,
                },
                body,
            )) => {
                let split = (stdout as usize).min(body.len());
                let unanswered = if timed_out {
                    Some(Unanswered::Deadline)
                } else if code.is_none() && signal.is_none() {
                    Some(Unanswered::Tier)
                } else {
                    None
                };
                SessionEvent::AgentServed(intent.serve(ServedAnswer::Ran(CommandRun {
                    status: CommandExit {
                        // The process's own exit status, read by the computer
                        // that ran it, which is what the exec tier means.
                        code: if timed_out { None } else { code },
                        signal: if timed_out { None } else { signal },
                        source: ExitTier::Exec,
                        unanswered,
                    },
                    stdout: body[..split].to_vec().into(),
                    stderr: body[split..].to_vec().into(),
                    dropped: Truncation {
                        cap,
                        stdout: Dropped {
                            bytes: stdout_dropped,
                            lines: stdout_dropped_lines,
                        },
                        stderr: Dropped {
                            bytes: stderr_dropped,
                            lines: stderr_dropped_lines,
                        },
                    },
                    duration: Duration::from_millis(duration_ms),
                })))
            }
            Ok((Reply::Refused(why) | Reply::Failed(why), _)) => {
                SessionEvent::AgentRefused(intent.refuse(why))
            }
            Ok(_) => SessionEvent::AgentRefused(intent.refuse(
                "the computer answered that command with something other than a run, so nothing is reported rather than a guessed status",
            )),
            // The error's own words are not put in stderr: that field is what
            // the far side printed, and these are ours.
            Err(_) => SessionEvent::AgentServed(intent.serve(ServedAnswer::Ran(CommandRun {
                status: CommandExit {
                    code: None,
                    signal: None,
                    source: ExitTier::Exec,
                    unanswered: Some(Unanswered::LinkLost),
                },
                stdout: Vec::new().into(),
                stderr: Vec::new().into(),
                dropped: Truncation {
                    cap: 0,
                    stdout: Dropped::default(),
                    stderr: Dropped::default(),
                },
                duration: started.elapsed(),
            }))),
        };
        let _ = events.send(event).await;
    });
}
/// The name a helper is shown by when none was given: the account name.
fn helper_name() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .ok()
        .filter(|n| !n.trim().is_empty() && n.len() <= 80)
        .unwrap_or_else(|| "DeskVNC helper".into())
}
async fn drive(
    session: &mut Session,
    commands: &mut mpsc::Receiver<ClientCommand>,
    events: &mpsc::Sender<SessionEvent>,
    mut view_only: bool,
    paired: Option<OnPaired>,
    published: Tools,
) -> Result<()> {
    let mut size = (0u16, 0u16);
    let mut input = InputState::default();
    let mut allowed = false;
    let mut tools_allowed = false;
    emit(events, SessionEvent::StateChanged(SessionState::Connecting)).await?;
    loop {
        tokio::select! {
            event = session.events.recv() => match event {
                Some(Event::Status(status)) => emit(events, SessionEvent::StateChanged(SessionState::Authenticating { method: status })).await?,
                Some(Event::Connected { control, .. }) => {
                    allowed = control;
                    if let Some(client) = session.tools() {
                        tools_allowed = client.allowed();
                        published.registry.lock().insert(published.session_id.clone(), client);
                    }
                    emit(events, SessionEvent::DesktopName("Boundary support".into())).await?;
                    permission(events, allowed, tools_allowed).await?;
                    emit(events, SessionEvent::StateChanged(SessionState::Connected)).await?;
                }
                Some(Event::Control(control)) => {
                    allowed = control;
                    input = InputState::default();
                    session.input(Input::Release)?;
                    permission(events, allowed, tools_allowed).await?;
                }
                Some(Event::Tools(value)) => {
                    tools_allowed = value;
                    permission(events, allowed, tools_allowed).await?;
                }
                Some(Event::Paired { machine, name }) => {
                    if let Some(paired) = paired.as_ref() { paired(machine, name); }
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
                Some(ClientCommand::Agent(intent)) => {
                    let is_exec = matches!(intent.kind, remote_core::intent::IntentKind::Exec { .. });
                    match session.tools() {
                        Some(client) if is_exec && client.allowed() => exec(client, intent, events.clone()),
                        client => {
                            let why = match (is_exec, client) {
                                (true, Some(_)) => NOT_ALLOWED,
                                (true, None) => TOO_OLD,
                                _ => "Boundary serves exec natively and nothing else; the other intents are lowered to input by the plane",
                            };
                            emit(events, SessionEvent::AgentRefused(intent.refuse(why))).await?;
                        }
                    }
                }
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
