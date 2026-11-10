//! Session events as the phone UI reads them.
//!
//! The JSON is the desktop `session://event` table, flat, with `sessionId`
//! and `type` (`src-tauri/FRAME_FORMAT.md`). The desktop builds it in
//! `event_json` inside `src-tauri/src/commands/session.rs`, a private
//! function in a module tied to windows, the agent plane and the desktop's
//! credential store, so it cannot be shared without reshaping the desktop
//! shell. This is the minimum copy: the same keys for every event the phone
//! handles, plus the few small ones it may show later. Events that are for
//! the agent plane, audio and terminal bytes are dropped, as on the desktop.

use remote_core::{ProtocolEvent, RdpEvent, SessionEvent, SessionState};
use serde_json::{json, Value};

/// The JSON for one event, or `None` for an event that travels on the binary
/// channel or is not for the UI. Server supplied strings are passed through
/// as JSON strings; the UI renders them as text only.
pub fn event_json(session_id: &str, event: &SessionEvent) -> Option<Value> {
    let mut value = match event {
        SessionEvent::StateChanged(s) => json!({ "type": "state-changed", "state": s }),
        SessionEvent::DesktopResize { width, height } => {
            json!({ "type": "desktop-resize", "width": width, "height": height })
        }
        SessionEvent::DesktopName(name) => json!({ "type": "desktop-name", "name": name }),
        SessionEvent::CursorPosition { x, y } => {
            json!({ "type": "cursor-position", "x": x, "y": y })
        }
        SessionEvent::ClipboardText(text) => json!({ "type": "clipboard-text", "text": text }),
        SessionEvent::ClipboardNotify { formats } => {
            json!({ "type": "clipboard-notify", "formats": formats })
        }
        SessionEvent::Bell => json!({ "type": "bell" }),
        SessionEvent::CertificatePrompt {
            fingerprint,
            subject,
            is_change,
            scheme,
            certificate,
        } => json!({
            "type": "certificate-prompt",
            "fingerprint": fingerprint,
            "subject": subject,
            "isChange": is_change,
            "certificate": certificate,
            "scheme": scheme,
        }),
        SessionEvent::CredentialsRequired(req) => {
            json!({ "type": "credentials-required", "request": req })
        }
        SessionEvent::Stats(stats) => json!({ "type": "stats", "stats": stats }),
        SessionEvent::Error(message) => json!({ "type": "error", "message": message }),
        SessionEvent::ScreenLayout { screens } => json!({
            "type": "screen-layout",
            "screens": screens.iter().map(|s| json!({
                "id": s.id, "x": s.x, "y": s.y, "width": s.width, "height": s.height,
            })).collect::<Vec<_>>(),
        }),
        SessionEvent::Protocol(ProtocolEvent::Rdp(RdpEvent::LogonError { message, .. })) => {
            json!({ "type": "logon-error", "message": message })
        }
        SessionEvent::Protocol(ProtocolEvent::Rdp(RdpEvent::ErrorInfo {
            code,
            symbol,
            message,
        })) => json!({
            "type": "error-info",
            "code": code,
            "symbol": symbol,
            "message": message,
        }),
        SessionEvent::Protocol(ProtocolEvent::Rdp(RdpEvent::LicenseWarning { message })) => {
            json!({ "type": "license-warning", "message": message })
        }
        SessionEvent::Protocol(ProtocolEvent::Boundary { control, tools }) => {
            json!({ "type": "boundary-control", "control": control, "tools": tools })
        }
        SessionEvent::Protocol(ProtocolEvent::BoundaryClipboard { write, read }) => {
            json!({ "type": "boundary-clipboard", "write": write, "read": read })
        }
        _ => return None,
    };
    if let Value::Object(map) = &mut value {
        map.insert("sessionId".into(), json!(session_id));
    }
    Some(value)
}

/// A Boundary session's progress, in the words the phone UI keys on.
///
/// `boundary-driver` reports each step of a Boundary connect as
/// `authenticating` with the sentence the session printed as `method`. The
/// phone UI shows its own copy and keys on `method: "approval"` while the
/// other side decides, so the two waiting sentences become that, and the
/// earlier progress sentences (finding the computer, preparing) become plain
/// `connecting`. Every other state passes through untouched.
pub fn boundary_state(state: SessionState) -> SessionState {
    match state {
        SessionState::Authenticating { method }
            if method == boundary_session::ATTENDED_WAIT
                || method == boundary_session::UNATTENDED_WAIT =>
        {
            SessionState::Authenticating {
                method: "approval".into(),
            }
        }
        SessionState::Authenticating { .. } => SessionState::Connecting,
        other => other,
    }
}

/// A `state-changed` the phone itself raises, for the background timeout.
pub fn disconnected(session_id: &str, reason: &str) -> Value {
    json!({
        "sessionId": session_id,
        "type": "state-changed",
        "state": { "state": "disconnected", "reason": reason, "can_retry": true },
    })
}

pub fn ended(session_id: &str, duration_s: u64) -> Value {
    json!({ "sessionId": session_id, "type": "ended", "durationS": duration_s })
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_core::{CredentialKind, CredentialRequest};

    #[test]
    fn boundary_waiting_is_approval() {
        let wait = |m: &str| SessionState::Authenticating { method: m.into() };
        for m in [
            boundary_session::ATTENDED_WAIT,
            boundary_session::UNATTENDED_WAIT,
        ] {
            assert_eq!(
                boundary_state(wait(m)),
                SessionState::Authenticating {
                    method: "approval".into()
                }
            );
        }
        assert_eq!(
            boundary_state(wait("Finding the computer")),
            SessionState::Connecting
        );
        assert_eq!(
            boundary_state(SessionState::Connected),
            SessionState::Connected
        );
    }

    #[test]
    fn events_are_flat_with_the_contract_keys() {
        let v = event_json("s1", &SessionEvent::StateChanged(SessionState::Connected)).unwrap();
        assert_eq!(v["sessionId"], "s1");
        assert_eq!(v["type"], "state-changed");
        assert_eq!(v["state"]["state"], "connected");

        let v = event_json(
            "s1",
            &SessionEvent::CredentialsRequired(CredentialRequest {
                method: "vnc".into(),
                kind: CredentialKind::PasswordOnly,
                attempt: 1,
                error: None,
                truncates_password: true,
                username_hint: None,
            }),
        )
        .unwrap();
        assert_eq!(v["request"]["kind"], "password-only");
        assert_eq!(v["request"]["truncatesPassword"], true);
        assert!(v["request"].get("usernameHint").is_some());

        let v = event_json(
            "s1",
            &SessionEvent::DesktopResize {
                width: 1920,
                height: 1080,
            },
        )
        .unwrap();
        assert_eq!(
            (v["width"].as_u64(), v["height"].as_u64()),
            (Some(1920), Some(1080))
        );
    }

    #[test]
    fn our_own_events() {
        let v = disconnected("s", "gone");
        assert_eq!(v["state"]["state"], "disconnected");
        assert_eq!(v["state"]["can_retry"], true);
        assert_eq!(ended("s", 7)["durationS"], 7);
    }
}
