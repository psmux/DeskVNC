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

use tauri::{AppHandle, Emitter, Manager, State};

use crate::agent::{self, AgentPlane};
use crate::state::AppState;

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
    })
}

/// Where an `agent://event` goes.
///
/// App wide, like `sessions://event`: the pane that renders the badge is not
/// necessarily the window that owns the session, and in tabbed view several of
/// them share one window. The status bar's counts are app wide by nature.
fn emitter(app: &AppHandle) -> Arc<dyn Fn(serde_json::Value) + Send + Sync> {
    let app = app.clone();
    Arc::new(move |value| {
        let _ = app.emit(agent::AGENT_EVENT, value);
    })
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
                        // As a tab rather than its own window: a person watching
                        // several machines an agent is driving wants them in one
                        // grid, and `00 B7`'s de-duplication is a window rule, so
                        // a tab is also where the existing session is found.
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

/// Read the setting at startup and apply it.
pub fn install(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
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

/// A person takes the wheel of a session an agent is driving (D5, `04 §5.4`).
///
/// A revocation and not a request. The agent's next command is refused with
/// `LEASE_REVOKED` and nothing further of its reaches the wire, and there is
/// no grace window: two seconds of a button labelled stop doing nothing is the
/// failure this exists to prevent.
///
/// The session is untouched. A revoked agent that had a build running should
/// not take the build with it.
#[tauri::command]
pub fn agent_take_the_wheel(
    app: AppHandle,
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    crate::windows::validate_session_id(&session_id)?;
    match state.agent.revoke(&session_id) {
        Some(event) => {
            let _ = app.emit(agent::AGENT_EVENT, event);
            tracing::info!(session = %session_id, "a person took the wheel from an agent");
            Ok(())
        }
        // Not an error: a person pressing "take the wheel" on a machine no
        // agent is driving has got what they asked for.
        None => Ok(()),
    }
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
