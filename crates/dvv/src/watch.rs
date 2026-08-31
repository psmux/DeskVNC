//! The live view a person keeps while an agent drives.
//!
//! An agent drives several machines of different kinds at once and a person
//! watches and can take over. The GUI shows that in panes; this is the same
//! thing for somebody who is in a terminal, and for a shell driven agent that
//! wants to pipe it (`04 §7.2`: machine readable output on everything, because
//! a shell agent is a consumer too).
//!
//! ## Why this is a broadcast and not a log
//!
//! Every event here is already produced somewhere: a lease transition comes
//! back from `agent-lease` as data, and a settlement comes back from
//! `AttachedLimb::dispatch`. What was missing is a place for a SECOND reader to
//! stand. `08 §5.5` makes the lease view a safety property rather than a
//! nicety, and a safety property only one caller can see is not one.
//!
//! A lagging reader is told how far it lagged rather than being silently
//! caught up, which is `00 R24`'s rule reaching the watch path: the plane never
//! drops anything without saying how much it dropped.

use serde::Serialize;

/// How many events a watcher may fall behind before it is told it lagged.
///
/// Two hundred and fifty six, which is a second of a busy agent at four limbs
/// and is the same order as BrowserGlass's 200 entry diagnostics ring. It is a
/// guess and it is marked as one; nothing measures it.
pub const WATCH_BUFFER: usize = 256;

/// One thing worth telling a watcher about.
///
/// Serialised flat with a `type` discriminator beside the fields, matching the
/// shape `session://event` already uses, so a consumer that reads the webview's
/// events reads these with the same code (`04 §2.5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum WatchEvent {
    /// A limb came under the plane.
    Attached {
        limb_id: String,
        protocol: String,
        host: String,
    },
    /// A limb left it. The session it was driving may still be running: `04
    /// §5.4` is explicit that revocation does not close the limbs an
    /// attachment opened, because a revoked agent that had a build running
    /// should not take the build with it.
    Detached { limb_id: String },
    /// Who is driving, after a change.
    ///
    /// `holder_kind` is the field a watcher acts on and `human_took_over` is
    /// spelled out beside it rather than left to be derived, for `04 §4.4`'s
    /// reason: the reader has to get one decision right and only one.
    LeaseChanged {
        limb_id: String,
        phase: String,
        holder_kind: Option<String>,
        holder_label: Option<String>,
        human_took_over: bool,
        queue_depth: usize,
        /// What the plane owed the limb, and whether it went. A lease change
        /// that owes a release and did not send one is the bug `00 R11` exists
        /// to prevent, so it is visible here rather than only in a log.
        released: Vec<String>,
    },
    /// An intent is on the wire.
    IntentStarted {
        limb_id: String,
        intent: u64,
        kind: String,
        at: u64,
    },
    /// The one settlement that intent gets.
    Settled {
        limb_id: String,
        intent: u64,
        kind: String,
        outcome: String,
        /// `None` when nothing was refused.
        code: Option<String>,
        /// What the plane put on the wire, in the plane's own words.
        progress: String,
        /// Set when something was dropped that will not repair itself.
        lost_state: bool,
        at: u64,
    },
    /// The stop path ran (`00 R13`). A revocation, not a request.
    Stopped {
        limb_id: String,
        /// What went on the wire, in order. The assertion a person wants after
        /// pressing a button labelled stop is that the buttons came up before
        /// the keys did, and this is where they can see it.
        released: Vec<String>,
        at: u64,
    },
}

impl WatchEvent {
    /// The one line a human sees without `--json`.
    ///
    /// Deliberately not the JSON pretty printed. `04 §7.2`: the human format is
    /// for humans and may change between releases, and the JSON is the plane's
    /// own object and is a contract.
    pub fn human(&self) -> String {
        match self {
            WatchEvent::Attached {
                limb_id,
                protocol,
                host,
            } => format!("{limb_id}  attached   {protocol} {host}"),
            WatchEvent::Detached { limb_id } => {
                format!("{limb_id}  detached   the session it opened is still running")
            }
            WatchEvent::LeaseChanged {
                limb_id,
                phase,
                holder_kind,
                holder_label,
                human_took_over,
                queue_depth,
                released,
            } => {
                let who = match (holder_kind, holder_label) {
                    (Some(kind), Some(label)) => format!("{kind} \"{label}\""),
                    _ => "nobody".to_string(),
                };
                let took_over = if *human_took_over {
                    "  A PERSON TOOK THE WHEEL"
                } else {
                    ""
                };
                format!(
                    "{limb_id}  lease      {phase}, held by {who}, {queue_depth} waiting, released {}{took_over}",
                    released.len()
                )
            }
            WatchEvent::IntentStarted {
                limb_id,
                intent,
                kind,
                ..
            } => format!("{limb_id}  intent {intent:<5} {kind} on the wire"),
            WatchEvent::Settled {
                limb_id,
                intent,
                kind,
                outcome,
                code,
                progress,
                lost_state,
                ..
            } => {
                let code = code.as_deref().unwrap_or("");
                let lost = if *lost_state { "  LOST STATE" } else { "" };
                format!("{limb_id}  intent {intent:<5} {kind} {outcome} {code} ({progress}){lost}")
            }
            WatchEvent::Stopped {
                limb_id, released, ..
            } => format!(
                "{limb_id}  STOPPED    revoked, released: {}",
                released.join(" then ")
            ),
        }
    }
}

/// The name of a command, for a watcher, with no payload in it.
///
/// A watch line is a diagnostic and a diagnostic is a second delivery path for
/// anything printed into it, which is the reasoning `Untrusted`'s own `Debug`
/// already follows one layer down. So a `TerminalInput` shows as its name and
/// never as its bytes, and clipboard text never appears at all.
pub fn command_name(command: &limb_core::ClientCommand) -> String {
    use limb_core::ClientCommand as C;
    match command {
        C::Pointer { x, y, button_mask } => format!("pointer({x},{y},mask={button_mask})"),
        C::Key { down, .. } => {
            if *down {
                "key down".to_string()
            } else {
                "key up".to_string()
            }
        }
        C::ReleaseAllKeys => "release all keys".to_string(),
        C::ClipboardText(_) => "clipboard text".to_string(),
        C::ClipboardRequest { .. } => "clipboard request".to_string(),
        C::SetQuality(_) => "set quality".to_string(),
        C::RequestResize { width, height } => format!("request resize({width}x{height})"),
        C::Refresh => "refresh".to_string(),
        C::SetAlwaysRefresh(_) => "set always refresh".to_string(),
        C::SetViewOnly(_) => "set view only".to_string(),
        C::SetPreferScancodes(_) => "set prefer scancodes".to_string(),
        C::TrustCertificate { .. } => "trust certificate".to_string(),
        C::ProvideCredentials { .. } => "provide credentials".to_string(),
        C::CancelCredentials => "cancel credentials".to_string(),
        C::ReconnectNow => "reconnect now".to_string(),
        C::Disconnect => "disconnect".to_string(),
        C::TerminalInput(bytes) => format!("terminal input({} bytes)", bytes.len()),
        C::ResizeTerminal { cols, rows } => format!("resize terminal({cols}x{rows})"),
        // The intents a driver serves itself (`00 R28`). Named by the intent's
        // own name and its id, and never by its payload: a `type` intent
        // carries the text somebody is typing and a watch line is a
        // diagnostic, not a transcript.
        C::Agent(intent) => format!("agent intent {} ({})", intent.id, intent.kind.name()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_watch_line_never_carries_a_payload() {
        // The failure this guards: somebody adds a variant and prints the
        // clipboard into a diagnostic, and the diagnostic becomes a second way
        // into a model.
        let text = command_name(&limb_core::ClientCommand::ClipboardText(
            "hunter2 is the password".to_string(),
        ));
        assert_eq!(text, "clipboard text");

        let creds = command_name(&limb_core::ClientCommand::ProvideCredentials {
            username: Some("gj".to_string()),
            password: "hunter2".to_string(),
            save: false,
        });
        assert_eq!(creds, "provide credentials");
    }

    #[test]
    fn a_person_taking_the_wheel_is_spelled_out_in_the_human_line() {
        let event = WatchEvent::LeaseChanged {
            limb_id: "lmb_vnc_0123456789ab_0".to_string(),
            phase: "held".to_string(),
            holder_kind: Some("human".to_string()),
            holder_label: Some("Godwin".to_string()),
            human_took_over: true,
            queue_depth: 0,
            released: vec!["pointer(0,0,mask=0)".to_string()],
        };
        assert!(event.human().contains("A PERSON TOOK THE WHEEL"));
    }
}
