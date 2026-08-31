//! A limb with nothing behind it but a recorder.
//!
//! ## Why this ships rather than living in `tests/`
//!
//! `agent-plane` has no live sessions to drive: the shell wiring that would
//! hand it a `SessionHandle` off `ProtocolRegistry` does not exist yet. Without
//! something here, the only way to exercise the MCP round trip would be by hand
//! against a running application, which is exactly the kind of verification
//! that stops happening.
//!
//! So `dvv mcp --stdio --fake` and `dvv --fake <verb>` run the whole surface
//! against this, and the integration tests drive the same code path a user
//! would. `SessionHandle` is a plain struct over an `mpsc::Sender`
//! (`crates/remote-core/src/driver.rs`), so a fake session is a channel and a
//! `Vec`, and the test reads exactly what the plane put on the wire, in order.
//! That is the whole reason the lowering in `agent-plane` is pure and the
//! dispatcher is the only thing that sends.
//!
//! It is deliberately more generous than any real limb, for the reason
//! `agent-plane`'s own test limb gives: a test for one refusal should not trip
//! over an unrelated one. A real limb narrows the capability list and
//! `CapabilitySet::intersect` does the rest.

use crate::error::ToolError;
use crate::plane::{HostRecord, OpenRequest, SessionSource};
use agent_plane::{Attach, Damage, Frame, FrameSource, LimbRegistry, PerceptionUnavailable};
use limb_core::capability::Capability;
use limb_core::fence::GeometryGeneration;
use limb_core::identity::{LimbId, MachineKey, Slot};
use limb_core::limb::{
    Confidence, Degraded, Grounding, Limb, LimbDescription, LimbLimits, PerceptionSet, Preference,
    QuiescencePolicy, QuiescenceSignal, Support,
};
use limb_core::observation::Timestamp;
use limb_core::{ClientCommand, IntentName, ProtocolKind, Rect, SessionStats};
use remote_core::driver::{OptionsMismatch, ProtocolDriver, SessionHandle};
use remote_core::events::SessionEvent;
use remote_core::options::ConnectOptions;
use remote_core::state::SessionState;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::mpsc;

/// How many commands a fake session's channel holds.
///
/// Two hundred and fifty six, matching VNC's own intent channel, because the
/// plane reserves half of whatever it is handed for the webview's input path
/// and a smaller number here would make the plane shed in a test for reasons
/// the test is not about.
const CHANNEL: usize = 256;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Everything the plane put on this limb's wire, in order.
///
/// Drained on demand rather than by a background task, so there is no timing in
/// it: a test that calls [`Recorder::commands`] after an awaited dispatch sees
/// everything that dispatch sent and nothing that has not been sent yet.
pub struct Recorder {
    receiver: Mutex<mpsc::Receiver<ClientCommand>>,
    seen: Mutex<Vec<ClientCommand>>,
}

impl Recorder {
    fn new(receiver: mpsc::Receiver<ClientCommand>) -> Recorder {
        Recorder {
            receiver: Mutex::new(receiver),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn pump(&self) {
        let mut receiver = lock(&self.receiver);
        let mut seen = lock(&self.seen);
        while let Ok(command) = receiver.try_recv() {
            seen.push(command);
        }
    }

    /// Every command so far, in order.
    pub fn commands(&self) -> Vec<ClientCommand> {
        self.pump();
        lock(&self.seen).clone()
    }

    /// The same, as the names a watch line would print.
    ///
    /// The assertion most tests want reads better this way: `["pointer(...)",
    /// "release all keys"]` says the rule out loud where a match over an enum
    /// does not.
    pub fn names(&self) -> Vec<String> {
        self.commands()
            .iter()
            .map(crate::watch::command_name)
            .collect()
    }

    /// Forget everything so far, so a later assertion is about one action.
    pub fn clear(&self) {
        self.pump();
        lock(&self.seen).clear();
    }
}

/// A framebuffer that reports whatever a test told it to.
///
/// A mirror with no decoder behind it. It answers a read with a small encoded
/// blob and answers damage from a queue, so `dvv_wait` has something to settle
/// on and `dvv_screen` has something to return, and neither needs a server.
pub struct FakeFrames {
    size: (u16, u16),
    pending: Mutex<Vec<Rect>>,
}

impl FakeFrames {
    /// A mirror over a framebuffer of this size, with nothing changing.
    pub fn new(size: (u16, u16)) -> FakeFrames {
        FakeFrames {
            size,
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Tell the mirror something changed. The next [`FrameSource::damage`] call
    /// reports it and the one after that reports nothing, which is how a real
    /// damage log behaves: a read advances a per reader cursor.
    pub fn damaged(&self, rect: Rect) {
        lock(&self.pending).push(rect);
    }
}

impl FrameSource for FakeFrames {
    fn frame(
        &self,
        region: Option<Rect>,
        _scale: Option<f32>,
        _at: Timestamp,
    ) -> Result<Frame, PerceptionUnavailable> {
        let covers = region.unwrap_or(Rect::new(0, 0, self.size.0, self.size.1));
        // A description rather than pixels. Nothing in this build decodes a
        // framebuffer, and returning bytes that look like an image would be a
        // fake that lies in the one direction that matters: an agent cannot
        // tell a picture of a blank screen from a picture that was never taken.
        let described = format!(
            "{{\"fake\":true,\"covers\":{{\"x\":{},\"y\":{},\"w\":{},\"h\":{}}}}}",
            covers.x, covers.y, covers.width, covers.height
        );
        Ok(Frame {
            bytes: crate::into_bytes(described.into_bytes()),
            covers,
            generation: GeometryGeneration::FIRST,
            complete: true,
        })
    }

    fn damage(&self) -> Option<Damage> {
        let rects: Vec<Rect> = lock(&self.pending).drain(..).collect();
        if rects.is_empty() {
            return None;
        }
        let bounds = rects
            .iter()
            .fold(Rect::new(0, 0, 0, 0), |acc, r| acc.union(r));
        Some(Damage {
            bounds,
            coverage: 1.0,
            rects,
            generation: GeometryGeneration::FIRST,
        })
    }
}

/// A limb that answers a card and takes commands.
pub struct FakeLimb {
    kind: ProtocolKind,
    grounding: Grounding,
    max_slots: Option<u16>,
}

impl FakeLimb {
    /// A desktop, addressed in framebuffer pixels.
    pub fn desktop() -> FakeLimb {
        FakeLimb {
            kind: ProtocolKind::Vnc,
            grounding: Grounding::Pixels,
            max_slots: Some(4),
        }
    }

    /// A terminal, addressed in character cells.
    pub fn terminal() -> FakeLimb {
        FakeLimb {
            kind: ProtocolKind::Ssh,
            grounding: Grounding::Cells,
            max_slots: None,
        }
    }
}

impl ProtocolDriver for FakeLimb {
    fn kind(&self) -> ProtocolKind {
        self.kind
    }

    fn spawn(
        &self,
        id: String,
        _options: ConnectOptions,
        _events: mpsc::Sender<SessionEvent>,
    ) -> Result<SessionHandle, OptionsMismatch> {
        // A handle with a receiver nobody holds, which fills and then reports
        // the channel full. Implemented rather than left as `unimplemented!()`
        // because `Limb` is a supertrait of `ProtocolDriver` and a panic in a
        // required method is a landmine for the first caller who reaches it.
        let (commands, _receiver) = mpsc::channel(CHANNEL);
        Ok(SessionHandle {
            id,
            kind: self.kind,
            commands,
            // `CancellationToken::default()` is `new()`. Built through
            // `Default` because this crate's manifest does not carry
            // `tokio-util` and does not need to: nothing here cancels anything.
            cancel: Default::default(),
        })
    }
}

impl Limb for FakeLimb {
    fn describe(&self) -> LimbDescription {
        match self.grounding {
            Grounding::Cells => LimbDescription {
                what: "A login shell on a PTY, with no machine behind it.",
                coordinates: "Character cells, columns and rows.",
                settling: "Settled means no output for the quiet window, which is exact about the wire and silent about whether the far side is thinking.",
                preference: Preference::Preferred,
                preference_reason: "Text is the one modality where an agent is not guessing.",
                steer_away: None,
            },
            _ => LimbDescription {
                what: "A remote desktop over RFB, with no machine behind it.",
                coordinates: "Framebuffer pixels, one space for the whole desktop, origin top left.",
                settling: "Settled means no damage for the quiet window, which is inferred from rectangles the server chose to send.",
                preference: Preference::Fallback,
                preference_reason: "Pixels cost more than text and say less.",
                steer_away: Some(
                    "If this machine also answers over SSH, read there and act here.",
                ),
            },
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
        use IntentName::*;
        match intent {
            Type | Press | Tune | ClipboardGet | ClipboardSet | SendBytes => Support::Lowered,
            Move | Click | Drag | Scroll => match self.grounding {
                Grounding::Pixels => Support::Lowered,
                _ => Support::Unsupported {
                    because: "a PTY has no pointer; type instead, or act on the desktop limb for the same machine",
                },
            },
            Wait | ReadScreen | Capture | Cancel => Support::Observed,
            Scancode => Support::Unsupported {
                because: "this limb refuses raw scancodes outright, whatever the grant carries: a scancode types what the remote layout says that key is, and nothing anywhere reports the difference",
            },
            Exec | PtyRun | Declare => Support::Native,
            // `IntentName` is `#[non_exhaustive]`. An intent added after this
            // build is refused with a sentence rather than accepted and
            // dropped, because an intent that ends silently makes an agent wait
            // rather than retry.
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
            signal: match self.grounding {
                Grounding::Cells => QuiescenceSignal::OutputBytes,
                _ => QuiescenceSignal::Damage,
            },
            default_quiet: Duration::from_millis(750),
            // Nothing in this tree can report exact quiescence on a
            // framebuffer, and a fake that claimed to would train a reader to
            // trust a number that is inferred everywhere else.
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

/// One machine this source can open, as a person would have saved it.
#[derive(Debug, Clone)]
pub struct FakeHost {
    pub host_id: String,
    pub address: String,
    pub port: u16,
    pub protocol: ProtocolKind,
    pub size: (u16, u16),
    /// Whether this limb gets a framebuffer mirror. A terminal never does.
    pub mirror: bool,
}

impl FakeHost {
    /// A desktop at this address.
    pub fn desktop(host_id: &str, address: &str) -> FakeHost {
        FakeHost {
            host_id: host_id.to_string(),
            address: address.to_string(),
            port: 5900,
            protocol: ProtocolKind::Vnc,
            size: (1280, 720),
            mirror: true,
        }
    }

    /// A shell at this address.
    pub fn terminal(host_id: &str, address: &str) -> FakeHost {
        FakeHost {
            host_id: host_id.to_string(),
            address: address.to_string(),
            port: 22,
            protocol: ProtocolKind::Ssh,
            size: (120, 40),
            mirror: false,
        }
    }
}

/// A source that opens fake limbs.
pub struct FakeSource {
    hosts: Vec<FakeHost>,
    recorders: Mutex<BTreeMap<String, Arc<Recorder>>>,
    /// The sending half of each limb's channel, so reopening the same machine
    /// at the same slot reuses the session rather than replacing it.
    channels: Mutex<BTreeMap<String, mpsc::Sender<ClientCommand>>>,
    mirrors: Mutex<BTreeMap<String, Arc<FakeFrames>>>,
    states: Mutex<BTreeMap<String, SessionState>>,
}

impl FakeSource {
    /// A source over these machines.
    pub fn new(hosts: Vec<FakeHost>) -> FakeSource {
        FakeSource {
            hosts,
            recorders: Mutex::new(BTreeMap::new()),
            channels: Mutex::new(BTreeMap::new()),
            mirrors: Mutex::new(BTreeMap::new()),
            states: Mutex::new(BTreeMap::new()),
        }
    }

    /// One desktop and one terminal, which is the smallest set that exercises
    /// both groundings and the steer away sentence between them.
    pub fn two_machines() -> FakeSource {
        FakeSource::new(vec![
            FakeHost::desktop("h_lab01", "10.0.0.5"),
            FakeHost::terminal("h_lab02", "10.0.0.6"),
        ])
    }

    /// What the plane put on this limb's wire.
    pub fn recorder(&self, limb: &str) -> Option<Arc<Recorder>> {
        lock(&self.recorders).get(limb).cloned()
    }

    /// This limb's mirror, so a test can say that something changed.
    pub fn mirror(&self, limb: &str) -> Option<Arc<FakeFrames>> {
        lock(&self.mirrors).get(limb).cloned()
    }

    /// Move a limb to another lifecycle state, the way the shell's event pump
    /// will.
    pub fn set_state(&self, limb: &str, state: SessionState) {
        lock(&self.states).insert(limb.to_string(), state);
    }

    /// What a machine at a slot would be called, without opening it.
    pub fn limb_id(&self, host_id: &str, slot: Slot) -> Option<LimbId> {
        let host = self.hosts.iter().find(|h| h.host_id == host_id)?;
        Some(LimbRegistry::resolve(
            host.protocol,
            &MachineKey::profile(&host.host_id),
            slot,
        ))
    }
}

impl SessionSource for FakeSource {
    fn hosts(&self) -> Result<Vec<HostRecord>, ToolError> {
        Ok(self
            .hosts
            .iter()
            .map(|host| HostRecord {
                host_id: host.host_id.clone(),
                label: host.host_id.clone(),
                address: host.address.clone(),
                port: host.port,
                protocol: host.protocol.to_string(),
                // False, always. There is no keychain behind this source and a
                // fake that claimed a credential was stored would make the one
                // field an agent uses to predict a pause say the wrong thing.
                credential_stored: false,
                discovered: false,
            })
            .collect())
    }

    fn open(&self, request: &OpenRequest) -> Result<Attach, ToolError> {
        let (host, machine) = match (&request.host_id, &request.address) {
            (Some(id), _) => {
                let host = self
                    .hosts
                    .iter()
                    .find(|h| &h.host_id == id)
                    .ok_or_else(|| {
                        ToolError::bad_request(format!(
                            "no saved machine is called {id}; call dvv_hosts for the ids"
                        ))
                    })?
                    .clone();
                let machine = MachineKey::profile(&host.host_id);
                (host, machine)
            }
            (None, Some(address)) => {
                let protocol = request.protocol.ok_or_else(|| {
                    ToolError::bad_request(
                        "protocol is required with address: a value this build does not know is a hard error and never a fallback, because falling back to VNC would dial the wrong protocol at an endpoint somebody configured for something else",
                    )
                })?;
                let port = request.port.unwrap_or_else(|| protocol.default_port());
                // Already normalised by the caller. An un-normalised name does
                // not fail here: it produces a DIFFERENT limb id for the same
                // machine, which is the failure `MachineKey::endpoint`'s own
                // doc comment exists to prevent somebody discovering.
                let address = address.trim().trim_end_matches('.').to_ascii_lowercase();
                let host = FakeHost {
                    host_id: address.clone(),
                    address: address.clone(),
                    port,
                    protocol,
                    size: match protocol {
                        ProtocolKind::Ssh => (120, 40),
                        _ => (1280, 720),
                    },
                    mirror: !matches!(protocol, ProtocolKind::Ssh),
                };
                let machine = MachineKey::endpoint(protocol, address, port);
                (host, machine)
            }
            (None, None) => {
                return Err(ToolError::bad_request(
                    "dvv_open needs a hostId from dvv_hosts, or an address with a protocol",
                ))
            }
        };

        let id = LimbRegistry::resolve(host.protocol, &machine, request.slot);

        // Reopening the same machine at the same slot is the SAME session, and
        // this is where that has to be true rather than merely stated. The
        // plane asks its source for an `Attach` before it consults the
        // registry, and the registry then hands back the limb it already has,
        // discarding what the source built. A source that minted a fresh
        // channel each time would leave the live limb writing into the
        // previous one and a caller reading a recorder that never sees
        // anything, which looks exactly like a plane that stopped sending.
        let commands = {
            let mut channels = lock(&self.channels);
            match channels.get(id.as_str()) {
                Some(sender) => sender.clone(),
                None => {
                    let (sender, receiver) = mpsc::channel(CHANNEL);
                    channels.insert(id.to_string(), sender.clone());
                    lock(&self.recorders).insert(id.to_string(), Arc::new(Recorder::new(receiver)));
                    sender
                }
            }
        };

        let frames: Option<Arc<dyn FrameSource>> = if host.mirror && request.perceive {
            let mut mirrors = lock(&self.mirrors);
            let mirror = mirrors
                .entry(id.to_string())
                .or_insert_with(|| Arc::new(FakeFrames::new(host.size)))
                .clone();
            Some(mirror)
        } else {
            None
        };

        // A freshly opened fake reaches `Connected` at once. A real one does
        // not, which is why `dvv_open` returns as soon as the session task is
        // spawned and an agent polls `dvv_status` or calls `dvv_wait` with
        // until connected.
        lock(&self.states).insert(id.to_string(), SessionState::Connected);

        let driver: Arc<dyn Limb> = match host.protocol {
            ProtocolKind::Ssh => Arc::new(FakeLimb::terminal()),
            _ => Arc::new(FakeLimb::desktop()),
        };
        Ok(Attach {
            driver,
            machine,
            slot: request.slot,
            host: host.address.clone(),
            handle: SessionHandle {
                id: id.to_string(),
                kind: host.protocol,
                commands,
                cancel: Default::default(),
            },
            size: host.size,
            frames,
        })
    }

    fn state(&self, limb: &LimbId) -> Option<SessionState> {
        lock(&self.states).get(limb.as_str()).cloned()
    }

    fn describe(&self) -> &'static str {
        "a fake limb with a recorder on the other end of its command channel, for proving the round trip with no server anywhere"
    }
}
