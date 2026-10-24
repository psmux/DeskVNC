//! The agent plane, as the shell and the webview see it.
//!
//! Two commands and two functions, and they are the only place `crate::agent`
//! meets Tauri. Everything below this file is testable without a running
//! application, which is what lets the socket's own verbs be proved against a
//! real [`crate::state::SessionEntry`] in a unit test.
//!
//! ## Why the webview gets a command as well as an event
//!
//! Tauri events are fire and forget: anything emitted before a window's
//! `listen()` registration completes is dropped. A pane that mounts a moment
//! after an agent attached would show no badge at all, which is the same
//! failure `pending_credential_request` already exists to fix. So a pane seeds
//! from [`agent_status`] on mount and follows `agent://event` after that.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager, State};

use crate::agent::{self, AgentPlane};
use crate::state::AppState;

/// How long the opener waits for the library webview to claim a session it
/// was asked to open before opening a window itself. A claim needs one event
/// delivery and one `open_session_window` round trip; under load a round trip
/// measured about half a second, so this is several of those, not one.
const AGENT_OPEN_CLAIM_WINDOW: Duration = Duration::from_secs(5);

/// Build the context the socket answers requests from.
///
/// The emitter is a closure over the `AppHandle` rather than the handle
/// itself, so `crate::agent::server` names no Tauri type and stays unit
/// testable.
fn ctx_for(app: &AppHandle, state: &AppState) -> Arc<agent::server::Ctx> {
    Arc::new(agent::server::Ctx {
        sessions: state.sessions.clone(),
        store: state.store.clone(),
        plane: state.agent.clone(),
        emit: emitter(app),
        files: filer(app),
    })
}

/// How a `files.*` verb reaches the SFTP sidecar.
///
/// The same shape as the opener below and for the same reason: the sidecar
/// lives behind `State<'_, FilesState>`, `Ctx` holds no `AppHandle`, and this
/// is one of the two places in the application that does. The work is spawned
/// on the application's runtime and the outcome comes back on a channel,
/// because `State` is not something a future can hold across an await.
///
/// A closure per `Ctx` rather than a process global, which is the difference
/// from `install_opener`: a global installed by one test is still installed
/// for the next, and the file verbs are the ones whose interesting behaviour
/// is what they do when there is NO sidecar.
fn filer(app: &AppHandle) -> agent::server::Filer {
    let app = app.clone();
    Arc::new(move |session_id, ask, tell| {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let answer = crate::commands::files::serve_agent(&app, &session_id, ask).await;
            // The receiver is gone when the socket task that asked has already
            // given up on its deadline. Nothing to do about it here: the
            // transfer either happened or did not, and the plane's own
            // timeout sentence says so rather than inventing an outcome.
            let _ = tell.send(answer);
        });
    })
}

/// Where an `agent://event` goes.
///
/// App wide, like `sessions://event`: the pane that renders the badge is not
/// necessarily the window that owns the session, and in tabbed view several of
/// them share one window. The status bar's counts are app wide by nature.
fn emitter(app: &AppHandle) -> Arc<dyn Fn(serde_json::Value) + Send + Sync> {
    let app = app.clone();
    // How many requests the last `requests` event carried, so a system
    // notification goes only when the list goes from empty to not.
    let shown = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Arc::new(move |value| {
        if value["type"] == "requests" {
            let count = value["requests"].as_array().map_or(0, Vec::len);
            let before = shown.swap(count, std::sync::atomic::Ordering::Relaxed);
            if before == 0 && count > 0 {
                notify_requests(&app, &value);
            }
        }
        let _ = app.emit(agent::AGENT_EVENT, value);
    })
}

/// One system notification when agents start asking for a machine the person
/// is using and no DeskVNCViewer window is in front.
///
/// Never more than one: it goes when the list of requests goes from empty to
/// not, and not again until the list has emptied. Agents that join while it
/// is up are in the panel, which is where the answer is given. With a window
/// in front the panel is already on screen and a notification would only
/// repeat it.
fn notify_requests(app: &AppHandle, event: &serde_json::Value) {
    use tauri_plugin_notification::NotificationExt;
    let in_front = app
        .webview_windows()
        .values()
        .any(|window| window.is_focused().unwrap_or(false));
    if in_front {
        return;
    }
    let first = &event["requests"][0];
    let agent = first["agent"].as_str().unwrap_or("An agent");
    let body = match first["reason"].as_str() {
        Some(reason) => format!("{agent} wants to use a machine you are using: {reason}"),
        None => format!("{agent} wants to use a machine you are using."),
    };
    let _ = app
        .notification()
        .builder()
        .title("An agent is asking for a machine")
        .body(body)
        .show();
}

/// Start or stop the plane to match the setting.
///
/// Called once at startup and again whenever the setting is written, so
/// switching the plane on does not need a restart. Off is the default and off
/// is total: no socket, no task, no file.
pub fn apply(app: &AppHandle, enabled: bool) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let plane: Arc<AgentPlane> = state.agent.clone();
    if !enabled {
        agent::stop(&plane);
        let _ = app.emit(
            agent::AGENT_EVENT,
            serde_json::json!({ "type": "plane", "enabled": false, "socket": null }),
        );
        return;
    }
    // How an agent gets a machine opened, installed here because this is the
    // one place that holds an `AppHandle`. `Ctx` deliberately does not: the
    // socket is written against the session registry rather than against tauri,
    // which is what keeps the plane reachable from a headless binary
    // (PRDAgentPlug/03 §1), so the ability to open a window is handed in rather
    // than reached for.
    //
    // It goes through `open_session_window`, the same call a person's click
    // makes, rather than reaching for `connect_session` underneath it. That is
    // not deference for its own sake: `connect_session` takes a channel
    // captured from a webview because that channel is where decoded frames go,
    // and a socket has none to give it. Asking for the window the person would
    // have got means the agent's machine appears in the grid, with a pane, a
    // badge and a take the wheel control, which is the whole point of an agent
    // driven session being an ordinary session (PRDAgentPlug/01 §5).
    //
    // The credential is never in the ask. It is resolved from the keychain on
    // the far side of this call exactly as it is for a click, so an agent names
    // a machine and never a secret (`00 R19`, `09 §4`).
    {
        let app = app.clone();
        agent::server::install_opener(std::sync::Arc::new(
            move |ask: agent::server::OpenAsk, tell| {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let Some(state) = app.try_state::<AppState>() else {
                        let _ = tell.send(Err("the application is shutting down".into()));
                        return;
                    };
                    // The person's own path first. The shell cannot build a
                    // tab: the tab strip lives in the library webview, and so
                    // does the tab-or-window preference, in browser storage
                    // the shell cannot read. So rather than guess, ask that
                    // webview to open the machine exactly as a click would.
                    // It honours the preference, de-duplicates, mounts the
                    // viewer, and its `open_session_window` call claims the
                    // session, which is how the id is found here afterwards:
                    // by machine, with the same lookup the window rule uses.
                    //
                    // From 0.23.0 to 0.26.0 this closure asked for a tab
                    // directly and got the tab parameters back, which it had
                    // no webview to hand to, so nothing was ever dialled.
                    // 0.26.1 opened a window instead, which worked and put
                    // every agent session outside the person's tab strip.
                    let kind =
                        match crate::commands::session::resolve_protocol(Some(&ask.protocol), None)
                        {
                            Ok(kind) => kind,
                            Err(why) => {
                                let _ = tell.send(Err(why));
                                return;
                            }
                        };
                    let key = crate::state::MachineKey::new(
                        kind,
                        ask.host_id.as_deref(),
                        &ask.address,
                        ask.port,
                    );
                    let exists = {
                        let app = app.clone();
                        move |label: &str| app.get_webview_window(label).is_some()
                    };
                    if let Some(main) = app.get_webview_window(crate::windows::MAIN_WINDOW_LABEL) {
                        // Already open: report it, exactly as a click would be
                        // told, without asking the webview to do anything.
                        if let Some(found) =
                            state.existing_window_for_machine(&key, Instant::now(), &exists)
                        {
                            let _ = tell.send(Ok(agent::server::Opened {
                                session_id: found.session_id,
                                reused: true,
                            }));
                            return;
                        }
                        let _ = main.emit(
                            crate::commands::session::AGENT_OPEN_EVENT,
                            serde_json::json!({
                                "hostId": ask.host_id,
                                "address": ask.address,
                                "port": ask.port,
                                "protocol": ask.protocol,
                                // Open it behind whatever the person is
                                // looking at: an agent's machine must not
                                // take the screen or the keyboard.
                                "background": true,
                            }),
                        );
                        // The webview's open claims the session within a few
                        // IPC round trips; the wait only has to outlast a busy
                        // one. Past it, fall through and open a window rather
                        // than fail: an agent with the library minimised or
                        // mid-reload still gets its machine.
                        let deadline = Instant::now() + AGENT_OPEN_CLAIM_WINDOW;
                        while Instant::now() < deadline {
                            if let Some(found) =
                                state.existing_window_for_machine(&key, Instant::now(), &exists)
                            {
                                let _ = tell.send(Ok(agent::server::Opened {
                                    session_id: found.session_id,
                                    reused: false,
                                }));
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        tracing::warn!(
                            address = %ask.address,
                            "the library webview did not claim the session in time; opening a window"
                        );
                    }
                    let done = crate::commands::session::open_session_window(
                        app.clone(),
                        state,
                        None,
                        ask.host_id,
                        Some(ask.address),
                        Some(ask.port),
                        None,
                        Some(ask.protocol),
                        None,
                        None,
                        Some(true),
                    )
                    .await;
                    let _ = tell.send(done.map(|out| agent::server::Opened {
                        session_id: out.session_id,
                        reused: out.reused,
                    }));
                });
            },
        ));
    }

    let ctx = ctx_for(app, &state);
    let path = agent::socket_path();
    // A panic here must not reach `setup`. `setup` cannot unwind, so a panic
    // crossing it aborts the process before the first window is drawn, and the
    // setting that started the plane is still stored as on, so the next launch
    // does exactly the same thing. That is not a broken feature, it is an
    // application somebody can no longer open, and the only way back is a
    // reinstall or a terminal.
    //
    // So the blast radius is the plane and nothing wider. An agent plane that
    // panicked on the way up is reported the same way one that returned an
    // error is: switched off, with the reason on the event. The interactive
    // product is untouched either way, which is the whole justification for
    // catching this rather than letting it through (`00 R40`).
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        agent::start(&plane, ctx, path.clone())
    }))
    .unwrap_or_else(|payload| {
        let why = panic_text(&payload);
        tracing::error!(socket = %path.display(), "the agent plane panicked while starting: {why}");
        Err(std::io::Error::other(why))
    });
    match started {
        Ok(()) => {
            let _ = app.emit(
                agent::AGENT_EVENT,
                serde_json::json!({
                    "type": "plane",
                    "enabled": true,
                    "socket": path.display().to_string(),
                }),
            );
            wire_agents_in_background();
        }
        Err(e) => {
            // Non fatal, and loud. The interactive product is unaffected by a
            // plane that could not start, and an agent that cannot find the
            // socket already has a sentence from `dvv doctor` telling it so.
            tracing::warn!(socket = %path.display(), "the agent plane could not start: {e}");
            let _ = app.emit(
                agent::AGENT_EVENT,
                serde_json::json!({
                    "type": "plane",
                    "enabled": false,
                    "socket": null,
                    "error": e.to_string(),
                }),
            );
        }
    }
}

/// Get the message out of a caught panic payload.
///
/// The two shapes `panic!` actually produces, and a named fallback for anything
/// else, because "the agent plane panicked" with no sentence after it sends
/// somebody to a debugger for a message that was right there.
fn panic_text(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "the agent plane panicked with a payload that carried no message".to_string()
}

/// The file `dvv` reads to find the app it should start. Shared with
/// `crates/dvv/src/launch.rs`; if one moves, move the other.
const APP_PATH_FILE: &str = "app-path";

/// Write where this executable is, so `dvv` starts this app and not some
/// other copy.
///
/// `dvv` starts the app when an agent needs it, and a copy of `dvv` on PATH
/// has no app beside it to find. Guessing install folders found a stale
/// install on a machine that also had a newer one, so the app that ran last
/// says where it is instead. A failure is logged and changes nothing else.
fn record_app_path(app: &AppHandle) {
    use tauri::Manager as _;
    // An AppImage runs from a mount that is gone once it quits, so what to
    // start next time is the AppImage file itself, which its runtime names.
    let exe = std::env::var_os("APPIMAGE")
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_exe, Ok);
    let (Ok(dir), Ok(exe)) = (app.path().app_data_dir(), exe) else {
        return;
    };
    if let Err(e) = std::fs::write(dir.join(APP_PATH_FILE), exe.to_string_lossy().as_bytes()) {
        tracing::debug!("could not record where the app is for dvv: {e}");
    }
}

/// Read the setting at startup and apply it.
pub fn install(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    record_app_path(app);
    // Before the switch is read, and whether or not it is on. Two of the three
    // counts are zero with the plane off but the live session total is not,
    // and a person switching the plane off has to watch the other two fall
    // rather than find out on their next window.
    state
        .agent
        .wire_counts(state.sessions.clone(), emitter(app));
    let raw = state
        .store
        .get_setting(agent::AGENT_PLANE_ENABLED_KEY)
        .unwrap_or_default();
    if !agent::plane_enabled(raw.as_deref()) {
        // Deliberately nothing at all, not even a directory. `AGENT_BRIEF` D2
        // and `00 R40`: an ordinary install is unchanged by this feature
        // existing.
        tracing::debug!("the agent plane is off");
        return;
    }
    apply(app, true);
}

/// Where the plane is and who is attached, for a pane that has just mounted.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatus {
    /// True only while the socket really exists.
    pub enabled: bool,
    /// The socket's path, so a person can compare it with what `dvv doctor`
    /// prints without reading either program's source.
    pub socket: Option<String>,
    /// The absolute path of the `dvv` that shipped inside this app bundle, or
    /// `null` in a development build, which has no bundle.
    ///
    /// The connect instructions are meant to be copied and pasted, so they
    /// have to name the binary that is really on the machine reading them.
    /// `null` is the honest answer for a `cargo tauri dev` build and the
    /// webview shows a placeholder for it.
    pub binary: Option<String>,
    /// One `lease` shaped payload per attached session, identical to what
    /// `agent://event` carries, so a pane has one renderer and not two.
    pub attachments: Vec<serde_json::Value>,
    /// `agentsConnected`, `sessionsDriven` and `sessionsLive`, flattened so
    /// they sit beside `enabled` here and carry the same names they carry on
    /// the `counts` event. A window that opened late seeds the status bar from
    /// this: Tauri events are fire and forget, which is the same reason
    /// `pending_credential_request` exists.
    #[serde(flatten)]
    pub counts: agent::AgentCounts,
}

#[tauri::command]
pub fn agent_status(state: State<'_, AppState>) -> Result<AgentStatus, String> {
    // The registry first and the plane's own tables under it, which is the one
    // lock order anything on this surface takes them in.
    let counts = {
        let sessions = state.sessions.lock();
        state.agent.counts(&sessions)
    };
    Ok(AgentStatus {
        enabled: state.agent.is_running(),
        socket: state.agent.socket().map(|path| path.display().to_string()),
        binary: agent::bundled_dvv().map(|path| path.display().to_string()),
        attachments: state.agent.snapshot(),
        counts,
    })
}

/// Register the bundled `dvv` with Claude Code, for the person pressing the
/// button (`PRDAgentPlug/00 R41`).
///
/// A button and not a line to paste. The instructions in the modal are correct
/// and nobody wants to read them: this runs
/// `claude mcp add --scope user deskvnc -- <bundled dvv> mcp --stdio` on their
/// behalf and answers what happened, tagged, so the modal can show a tick, an
/// install link or the tool's own refusal rather than a shrug.
///
/// `spawn_blocking` because it waits on a child process, and a synchronous
/// command would do that on the main thread with the window frozen behind it.
#[tauri::command]
pub async fn agent_register_with_claude() -> Result<agent::RegistrationOutcome, String> {
    let outcome = tauri::async_runtime::spawn_blocking(agent::register_with_claude)
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!(?outcome, "MCP registration attempted");
    Ok(outcome)
}

/// Wire the bundled `dvv` into every agent installed here: OpenCode, Pi,
/// Codex and Claude Code. Runs `dvv setup`, which owns the knowledge of each
/// agent's config, and hands back what it printed, line for line.
#[tauri::command]
pub async fn agent_setup_agents() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(run_setup)
        .await
        .map_err(|e| e.to_string())?
}

/// Run the bundled `dvv setup` and hand back what it printed.
///
/// Blocking: it waits on `dvv`, which in turn may wait on `claude mcp add`.
fn run_setup() -> Result<String, String> {
    let dvv = agent::bundled_dvv().ok_or("this build has no dvv beside it")?;
    let mut command = std::process::Command::new(dvv);
    command.arg("setup");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // No console window flashing up behind the app on every launch.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let output = command
        .output()
        .map_err(|e| format!("dvv setup could not run: {e}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    tracing::info!(ok = output.status.success(), "dvv setup ran");
    Ok(text.trim().to_string())
}

/// Wire every installed agent to this build, in the background.
///
/// Run each time the plane comes up, so nobody has to press anything: an agent
/// installed since the last launch is picked up, and one still pointing at the
/// `dvv` of a previous version is pointed at this one. `dvv setup` leaves a
/// config that already names this `dvv` untouched, so a launch with nothing to
/// do changes no file. A build with no `dvv` beside it wires nothing.
fn wire_agents_in_background() {
    if agent::bundled_dvv().is_none() {
        return;
    }
    tauri::async_runtime::spawn_blocking(|| match run_setup() {
        Ok(text) => tracing::info!("agents wired at launch:\n{text}"),
        Err(e) => tracing::warn!("could not wire agents at launch: {e}"),
    });
}

/// A person takes the wheel of a session an agent is driving (D5, `04 §5.4`),
/// from the take the wheel or stop control on a pane.
///
/// The agent is fenced at once: its next pointer event or key press is
/// refused and the keys it held are released. It is a person's input on the
/// shared lease and lasts exactly as long as one, so agents may ask again
/// once the person has sent nothing for the person idle time. Before, this
/// was a flag nothing ever cleared, and one press stopped an agent for good.
///
/// The session is untouched. An agent that had a build running should not
/// take the build with it.
#[tauri::command]
pub fn agent_take_the_wheel(
    app: AppHandle,
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    crate::windows::validate_session_id(&session_id)?;
    let event = state.agent.person_takes(&session_id);
    // The board emits on change through its own wiring; this is for a
    // window that pressed the control on a session nothing had changed on.
    let _ = app.emit(agent::AGENT_EVENT, event);
    Ok(())
}

/// The agents waiting for machines a person is using, and the mute, for a
/// window that has just mounted the request panel. The same object as the
/// `requests` event.
#[tauri::command]
pub fn agent_requests(state: State<'_, AppState>) -> serde_json::Value {
    state.agent.requests_event()
}

/// A person's answer to one request, or to every request when `session_id`
/// is absent: `"allow"` lets that agent use the machine now, `"not-now"`
/// refuses it.
#[tauri::command]
pub fn agent_request_answer(
    state: State<'_, AppState>,
    session_id: Option<String>,
    attachment_id: Option<String>,
    answer: String,
) -> Result<(), String> {
    if let Some(session_id) = &session_id {
        crate::windows::validate_session_id(session_id)?;
    }
    match (answer.as_str(), session_id, attachment_id) {
        ("allow", Some(session), Some(attachment)) => {
            state.agent.allow_request(&session, &attachment);
        }
        ("not-now", Some(session), Some(attachment)) => {
            state.agent.decline_request(&session, &attachment);
        }
        ("allow", None, None) => {
            state.agent.allow_all_requests();
        }
        ("not-now", None, None) => state.agent.decline_all_requests(),
        (other, _, _) => {
            return Err(format!(
                "{other:?} with those ids is not an answer; it is \"allow\" or \"not-now\", for one request (sessionId and attachmentId) or for all (neither)"
            ))
        }
    }
    Ok(())
}

/// Mute requests from agents for `minutes`, or until the person stops using
/// every machine when `minutes` is absent.
#[tauri::command]
pub fn agent_requests_mute(state: State<'_, AppState>, minutes: Option<u64>) {
    state
        .agent
        .mute_requests(minutes.map(|m| m.clamp(1, 24 * 60)));
}

/// Show requests again.
#[tauri::command]
pub fn agent_requests_unmute(state: State<'_, AppState>) {
    state.agent.unmute_requests();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command and the event carry the same three keys with the same three
    /// values.
    ///
    /// A window seeds the bar from `agent_status` and follows `agent://event`
    /// after that, so a difference of one letter between the two shapes is a
    /// bar that reads zero until something moves. `AgentStatus` flattens
    /// [`agent::AgentCounts`] and the event is built from the same struct,
    /// which is what this holds them to.
    #[test]
    fn the_command_and_the_event_carry_the_same_numbers() {
        let counts = agent::AgentCounts {
            agents_connected: 2,
            sessions_driven: 3,
            sessions_live: 11,
        };
        let status = serde_json::to_value(AgentStatus {
            enabled: true,
            socket: Some("/tmp/agent.sock".into()),
            binary: Some("/Applications/DeskVNCViewer.app/Contents/MacOS/dvv".into()),
            attachments: Vec::new(),
            counts,
        })
        .expect("the status serializes");
        let event = counts.event();

        for key in ["agentsConnected", "sessionsDriven", "sessionsLive"] {
            assert_eq!(status[key], event[key], "{key}");
            assert!(!status[key].is_null(), "{key} is missing from agent_status");
        }
        assert_eq!(event["type"], "counts");
        assert_eq!(status["enabled"], true, "the old fields are still there");
        assert_eq!(status["socket"], "/tmp/agent.sock");
        assert_eq!(
            status["binary"], "/Applications/DeskVNCViewer.app/Contents/MacOS/dvv",
            "the modal pastes this path, so it has to be on the status"
        );
        assert!(status["attachments"].is_array());
    }

    /// A build with no bundle answers `null` for the binary and still answers
    /// everything else.
    ///
    /// `null` and not an empty string: the webview tells the two apart to
    /// decide between a path and a placeholder, and `""` would be rendered as
    /// a path of no characters.
    #[test]
    fn a_build_with_no_bundle_says_so_rather_than_inventing_a_path() {
        let status = serde_json::to_value(AgentStatus {
            enabled: false,
            socket: None,
            binary: None,
            attachments: Vec::new(),
            counts: agent::AgentCounts::default(),
        })
        .expect("the status serializes");
        assert!(status["binary"].is_null());
        assert_eq!(status["enabled"], false);
    }
}
