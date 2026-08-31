//! A limb and a session that exist to be asserted against, not to be run.
//!
//! There is no server anywhere in this crate's tests and there must not be
//! one. `SessionHandle` is a plain struct over an `mpsc::Sender`
//! (`crates/remote-core/src/driver.rs:99`), so a test builds one with its own
//! channel and reads exactly what the plane put on the wire, in order. That is
//! the whole reason the lowering in this crate is pure and the dispatcher is
//! the only thing that sends: the rules can be asserted without a runtime, a
//! network or a machine.
//!
//! `11 §5` and `00 R26` are why this matters more here than in most crates.
//! Plane correctness is deterministic and gates in CI; agent capability is
//! statistical and never gates. Everything in this directory is the first
//! kind.

#![allow(dead_code)]

use agent_plane::{Attach, AttachedLimb, Grant, LimbRegistry, PlaneConfig};
use limb_core::capability::{Capability, RoleBundle};
use limb_core::identity::{MachineKey, Slot};
use limb_core::intent::{AgentIntent, IntentKind};
use limb_core::limb::{
    Confidence, Degraded, Grounding, Limb, LimbDescription, LimbLimits, PerceptionSet, Preference,
    QuiescencePolicy, QuiescenceSignal, Support,
};
use limb_core::{ClientCommand, IntentName, SessionStats};
use remote_core::driver::{OptionsMismatch, ProtocolDriver, ProtocolKind, SessionHandle};
use remote_core::events::SessionEvent;
use remote_core::options::ConnectOptions;
use remote_core::state::SessionState;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A desktop limb that offers everything, so a test can choose which refusal
/// it is exercising rather than tripping over an unrelated one.
///
/// It is deliberately more generous than any real limb: a VNC desktop offers
/// no `exec` and no `terminal.write`, and this one does, because a test for
/// the missing `ClientCommand::Agent` variant needs an intent that gets past
/// the capability check to reach the lowering. A real limb narrows this and
/// `CapabilitySet::intersect` does the rest, which is the whole of
/// "capabilities per limb".
pub struct TestLimb {
    pub grounding: Grounding,
    pub max_slots: Option<u16>,
    /// Which intents this limb claims to serve itself, so a test can reach the
    /// `NO_NATIVE_VARIANT` path.
    pub native: &'static [IntentName],
}

impl TestLimb {
    pub fn desktop() -> TestLimb {
        TestLimb {
            grounding: Grounding::Pixels,
            max_slots: Some(4),
            native: &[IntentName::Declare, IntentName::Exec, IntentName::PtyRun],
        }
    }

    pub fn terminal() -> TestLimb {
        TestLimb {
            grounding: Grounding::Cells,
            max_slots: None,
            native: &[IntentName::Exec, IntentName::PtyRun],
        }
    }
}

impl ProtocolDriver for TestLimb {
    fn kind(&self) -> ProtocolKind {
        ProtocolKind::Vnc
    }

    fn spawn(
        &self,
        _id: String,
        _options: ConnectOptions,
        _events: mpsc::Sender<SessionEvent>,
    ) -> Result<SessionHandle, OptionsMismatch> {
        unimplemented!("this limb exists to be dispatched at, not to be run")
    }
}

impl Limb for TestLimb {
    fn describe(&self) -> LimbDescription {
        LimbDescription {
            what: "A test limb with no machine behind it.",
            coordinates: "Framebuffer pixels, with one space for the whole desktop.",
            settling: "Settled means no damage for the quiet window, which is inferred.",
            preference: Preference::Fallback,
            preference_reason: "Pixels cost more than text and say less.",
            steer_away: Some("If this machine also answers over SSH, read there."),
        }
    }

    fn capabilities(&self) -> &'static [Capability] {
        &[
            Capability::View,
            Capability::Capture,
            Capability::Control,
            Capability::Open,
            Capability::Close,
            Capability::HostsRead,
            Capability::ClipboardRead,
            Capability::ClipboardWrite,
            Capability::TerminalRead,
            Capability::TerminalWrite,
            Capability::Exec,
        ]
    }

    fn supports(&self, intent: IntentName) -> Support {
        if self.native.contains(&intent) {
            return Support::Native;
        }
        use IntentName::*;
        match intent {
            Type | Press | Move | Click | Drag | Scroll | Tune | ClipboardGet | ClipboardSet
            | SendBytes => Support::Lowered,
            Wait | ReadScreen | Capture | Cancel => Support::Observed,
            Scancode => Support::Unsupported {
                because: "this limb refuses raw scancodes outright, whatever the grant carries",
            },
            _ => Support::Unsupported {
                because: "this limb was written before that intent existed",
            },
        }
    }

    fn perception(&self) -> PerceptionSet {
        PerceptionSet {
            frames: matches!(self.grounding, Grounding::Pixels),
            cells: matches!(self.grounding, Grounding::Cells),
            structure: false,
        }
    }

    fn grounding(&self) -> Grounding {
        self.grounding
    }

    fn quiescence(&self) -> QuiescencePolicy {
        QuiescencePolicy {
            signal: QuiescenceSignal::Damage,
            default_quiet: Duration::from_millis(750),
            confidence: Confidence::Inferred,
        }
    }

    fn limits(&self) -> LimbLimits {
        LimbLimits {
            max_in_flight: 1,
            pointer_per_sec: 60,
            keys_per_sec: 60,
            bytes_per_sec: 1_000_000,
            max_slots: self.max_slots,
        }
    }

    fn degraded(&self, _stats: &SessionStats) -> Option<Degraded> {
        None
    }
}

/// A session with nothing on the other end but a receiver a test can read.
pub fn fake_session(id: &str, capacity: usize) -> (SessionHandle, mpsc::Receiver<ClientCommand>) {
    let (commands, rx) = mpsc::channel(capacity);
    (
        SessionHandle {
            id: id.to_string(),
            kind: ProtocolKind::Vnc,
            commands,
            cancel: CancellationToken::new(),
        },
        rx,
    )
}

/// Everything the plane has put on the wire so far, in order.
pub fn drain(rx: &mut mpsc::Receiver<ClientCommand>) -> Vec<ClientCommand> {
    let mut out = Vec::new();
    while let Ok(command) = rx.try_recv() {
        out.push(command);
    }
    out
}

/// An operator grant over one host.
pub fn operator(id: &str, host: &str) -> Grant {
    Grant::from_bundle(id, RoleBundle::Operator, [host.to_string()]).expect("a legal grant")
}

/// A registry, a connected limb, and the receiver its commands land in.
pub fn connected(
    config: PlaneConfig,
    grant: &Grant,
    host: &str,
    limb: TestLimb,
    capacity: usize,
) -> (LimbRegistry, AttachedLimb, mpsc::Receiver<ClientCommand>) {
    let registry = LimbRegistry::new(config);
    let (handle, rx) = fake_session(host, capacity);
    let attached = registry
        .attach(
            grant,
            Attach {
                driver: Arc::new(limb),
                machine: MachineKey::endpoint(ProtocolKind::Vnc, host, 5900),
                slot: Slot::ATTACH,
                host: host.to_string(),
                handle,
                size: (1280, 720),
                frames: None,
            },
        )
        .expect("the grant names this host and the slot is legal");
    attached.note_state(SessionState::Connected);
    (registry, attached, rx)
}

/// An intent with no geometry fence, for the intents that carry no coordinate.
pub fn intent(limb: &AttachedLimb, grant: &Grant, kind: IntentKind) -> AgentIntent {
    AgentIntent {
        id: limb.mint(),
        grant: grant.id().clone(),
        deadline: None,
        fence: None,
        kind,
    }
}

/// An intent fenced at the limb's current generation, for the four that carry
/// a coordinate.
pub fn fenced(limb: &AttachedLimb, grant: &Grant, kind: IntentKind) -> AgentIntent {
    AgentIntent {
        fence: Some(limb.generation()),
        ..intent(limb, grant, kind)
    }
}

/// An `exec` of one command, with the timeout `05 §4.1` requires and nothing
/// else set.
///
/// A helper because every native path test needs one and the spec has six
/// fields, five of which are noise for what is being asserted. The timeout is
/// the command's own, on the far side of the driver, and it is unrelated to
/// how long the plane waits for the driver's answer.
pub fn exec(command: &str) -> IntentKind {
    IntentKind::Exec {
        spec: limb_core::intent::CommandSpec {
            command: command.to_string(),
            cwd: None,
            env: Vec::new(),
            timeout: Duration::from_secs(5),
            stdin: None,
            max_output_bytes: None,
        },
    }
}

/// The intent inside an agent command, for a test that asserts what the driver
/// was handed rather than what the plane said about it.
pub fn as_agent(command: &ClientCommand) -> Option<&AgentIntent> {
    match command {
        ClientCommand::Agent(intent) => Some(intent),
        _ => None,
    }
}

/// The keysym, keycode and direction of a key command, for an assertion that
/// reads like the rule it is checking.
pub fn as_key(command: &ClientCommand) -> Option<(u32, Option<u32>, bool)> {
    match command {
        ClientCommand::Key {
            keysym,
            keycode,
            down,
        } => Some((*keysym, *keycode, *down)),
        _ => None,
    }
}

/// The coordinates and mask of a pointer command.
pub fn as_pointer(command: &ClientCommand) -> Option<(u16, u16, u16)> {
    match command {
        ClientCommand::Pointer { x, y, button_mask } => Some((*x, *y, *button_mask)),
        _ => None,
    }
}
