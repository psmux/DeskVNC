//! The limb registry: which machines this process is driving, at which slots.
//!
//! ## Why the plane keeps its own registry
//!
//! `00 R47a`. `02 §1.1` rules that `ProtocolDriver` gains
//! `fn limb(&self) -> Option<&dyn Limb>`, defaulted to `None`, so the shell can
//! ask an `Arc<dyn ProtocolDriver>` whether it has agent support without a
//! downcast. That method cannot be written: it has to live in `remote-core`,
//! and `remote-core` cannot name `Limb` without depending on `limb-core`,
//! which depends on `remote-core`. A cycle. The accessor is owed, not designed
//! away, and until it lands the plane reaches limbs through this map. That is
//! why [`Attach`] carries the `Arc<dyn Limb>` explicitly rather than reading it
//! off a handle.
//!
//! ## Both halves of slot semantics are built here
//!
//! `00 B7` is the trap this module exists to avoid, and it is easy to walk
//! into because the de-duplication is visible in the running product.
//! `AppState::existing_window_for_machine` is defined at
//! `src-tauri/src/state.rs:367` and called from exactly one place,
//! `open_session_window` (`src-tauri/src/commands/session.rs:1851`).
//! **`connect_session` never consults it.** So a limb the plane opens is de
//! duplicated by nothing at all, and slot 0 attaching to a live session is
//! code written here rather than behaviour inherited from the shell.
//!
//! The mechanism is [`LimbId::derive`] plus this map and nothing else. An id
//! is a pure function of the protocol, the machine and the slot, so the same
//! machine at the same slot resolves to the same id on this run and on next
//! week's, which is `00 R31`'s reproducibility. Slot 0 therefore collapses onto
//! whatever is already attached, and a slot above zero derives its own id and
//! can never adopt. Two rules, one derivation, no second map.
//!
//! ## Admission control
//!
//! `00 R21`. Four, refused by name rather than degraded silently. See
//! [`crate::config::MAX_DRIVEN_LIMBS`] for where the number came from and why
//! it is not eight.

use crate::backpressure::Gaps;
use crate::config::PlaneConfig;
use crate::error::PlaneError;
use crate::grant::Grant;
use crate::lowering::LowerContext;
use crate::perception::{FrameSource, Observatory};
use agent_lease::{Lease, LeaseConfig};
use limb_core::capability::{Capability, CapabilitySet};
use limb_core::fence::GeometryFence;
use limb_core::identity::{LimbId, MachineKey, Slot};
use limb_core::intent::{IntentId, IntentSequence};
use limb_core::limb::Limb;
use limb_core::party::GrantId;
use remote_core::driver::{ProtocolKind, SessionHandle};
use remote_core::state::SessionState;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;

/// Take a lock, recovering from poisoning rather than panicking.
///
/// A panic while one of these is held would otherwise take every subsequent
/// caller down with it, including the arbitration path, and `agent-lease`
/// already records why that is the wrong trade: a panic in an arbitration path
/// takes the plane down with it, and the recovery is the same thing the
/// invariant says should happen. What is behind these locks is bookkeeping
/// (the last button mask, a counter, a map) and none of it is left in a state
/// a reader cannot make sense of.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Everything needed to bring one machine under the plane.
///
/// Not `#[non_exhaustive]`: a caller outside this crate constructs it, which
/// is the shape `00 R47b` says the attribute is backwards for.
pub struct Attach {
    /// The driver, which is also the limb: `Limb` is a supertrait of
    /// `ProtocolDriver` so that identity cannot disagree with itself
    /// (`00 R47a`, and `src-tauri/src/state.rs:242` took the same decision
    /// with the words "the two can never disagree").
    pub driver: Arc<dyn Limb>,
    /// Which machine, as the shell already understands the word.
    pub machine: MachineKey,
    /// Which concurrent session against that machine this is.
    pub slot: Slot,
    /// The host name the grant has to name, ALREADY NORMALISED by the caller.
    ///
    /// The normalisation belongs to `vnc_store::normalize_address` and this
    /// crate cannot reach it without dragging a database into the plane, which
    /// is the same sharp edge `MachineKey::endpoint` documents. An
    /// un-normalised name here does not fail: it produces a host that a grant
    /// does not match, which is a refusal rather than a wrong machine, and
    /// that is the direction this is meant to fail in.
    pub host: String,
    /// The live session. The plane sends into `handle.commands` and never
    /// spawns anything itself.
    pub handle: SessionHandle,
    /// The framebuffer size, in whatever unit `Limb::grounding` names.
    pub size: (u16, u16),
    /// The mirror, if this limb has one. `None` for a limb with no
    /// framebuffer, and for a limb whose grant never asked for pixels.
    pub frames: Option<Arc<dyn FrameSource>>,
}

/// One limb's live state.
///
/// Everything mutable sits behind its own lock rather than one lock over the
/// whole struct, because the release path (`00 R11`) has to be able to run
/// while a dispatch is between two of its commands. A single lock held for a
/// whole drag would make `15 §4.5`'s interruption case unreachable, which
/// would look like the design working and would be the design not being
/// tested.
pub(crate) struct LimbInner {
    pub(crate) id: LimbId,
    pub(crate) machine: MachineKey,
    pub(crate) slot: Slot,
    pub(crate) host: String,
    pub(crate) driver: Arc<dyn Limb>,
    pub(crate) handle: SessionHandle,
    pub(crate) config: PlaneConfig,
    pub(crate) lease: Mutex<Lease>,
    pub(crate) input: Mutex<InputState>,
    pub(crate) seq: Mutex<IntentSequence>,
    pub(crate) running: Mutex<BTreeMap<IntentId, RunningIntent>>,
    pub(crate) observatory: Observatory,
}

/// An intent that is dispatching right now.
///
/// Held so that two things are possible, and neither is achievable without it.
///
/// `08 §7.3`: one in flight intent batch per (grant, limb). Two concurrent
/// batches to one limb have no defined interleaving, and an agent that
/// believes it typed `hello` and then `world` would get either, or a mix, and
/// could not tell which.
///
/// `02 §2.4`: `Cancel { target }` withdraws an earlier intent, and a
/// withdrawal that cannot reach the thing it withdraws is a no-op with a
/// success on it. The token is the reach.
pub(crate) struct RunningIntent {
    pub(crate) grant: GrantId,
    pub(crate) cancel: CancellationToken,
}

/// What the plane remembers about what it put on the wire.
///
/// The button mask is the load bearing field and `00 B8` is why it exists at
/// this layer. The VNC pointer path encodes whatever mask arrived and
/// remembers nothing, so an RFB server holds the last button state it was told
/// until a `PointerEvent` clears the bit, and there is no state anywhere in
/// `vnc-core` to release from. The plane is the only thing that knows.
pub(crate) struct InputState {
    pub(crate) fence: GeometryFence,
    pub(crate) ctx: LowerContext,
    /// Cumulative since attach (`08 §4.6`), so an agent that missed a
    /// settlement can still see the total.
    pub(crate) gaps: Gaps,
    /// The last button mask the plane put on the wire (`15 §4.5` WA-5).
    ///
    /// Held here rather than derived, because there is nowhere else to derive
    /// it from: the VNC pointer arm encodes whatever mask arrived and
    /// remembers nothing, so the plane is the only party in the process that
    /// knows what the server was last told.
    pub(crate) last_mask: u16,
    /// The last lifecycle state the caller reported.
    ///
    /// `SessionState` is not extended and never will be: its serde
    /// representation is a contract with `ui/src/lib/types.ts` and `01 §5 I1`
    /// forbids changing what an existing consumer sees (`02 §6.1`). The plane
    /// holds a copy so it can refuse an intent while the limb is negotiating,
    /// with the retry time in the refusal, rather than putting a click on a
    /// socket that is reconnecting.
    pub(crate) state: SessionState,
}

/// A limb the plane is driving.
///
/// Cheap to clone: it is an `Arc` over the state above, so a caller may hold
/// one across an await while another caller preempts the lease. That is the
/// point rather than an accident.
#[derive(Clone)]
pub struct AttachedLimb {
    pub(crate) inner: Arc<LimbInner>,
}

/// Identity and nothing else.
///
/// Hand written rather than derived, and what it omits is the point: no
/// session handle, no lease holder, no last coordinate. A limb in a log line
/// is there to be identified, and printing where somebody's pointer is or who
/// is driving their machine into a diagnostic is a second delivery path for
/// information nobody asked to publish. The same reasoning as `Untrusted`'s
/// `Debug`, one layer up.
impl std::fmt::Debug for AttachedLimb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachedLimb")
            .field("id", &self.inner.id.as_str())
            .field("protocol", &self.protocol())
            .field("slot", &self.inner.slot)
            .finish_non_exhaustive()
    }
}

impl AttachedLimb {
    /// The limb's name, which is also its session id (`02 §4.3`).
    pub fn id(&self) -> &LimbId {
        &self.inner.id
    }

    /// Which machine.
    pub fn machine(&self) -> &MachineKey {
        &self.inner.machine
    }

    /// Which slot.
    pub fn slot(&self) -> Slot {
        self.inner.slot
    }

    /// The normalised host name a grant has to name.
    pub fn host(&self) -> &str {
        &self.inner.host
    }

    /// The protocol.
    pub fn protocol(&self) -> ProtocolKind {
        self.inner.driver.kind()
    }

    /// The limb itself, for `describe`, `supports` and the rest of the card.
    pub fn limb(&self) -> &dyn Limb {
        self.inner.driver.as_ref()
    }

    /// The observation half.
    pub fn observatory(&self) -> &Observatory {
        &self.inner.observatory
    }

    /// Every capability this limb can EVER offer, as a set.
    ///
    /// The intersection of this and the grant's set is what an attachment may
    /// actually do, which is the whole of "capabilities per limb": the plane
    /// needs no table keyed on `ProtocolKind`, so the MCP layer stays free of
    /// a `match kind` (`01 §5 I2`).
    pub fn offered(&self) -> CapabilitySet {
        CapabilitySet::of(self.inner.driver.capabilities())
    }

    /// What was dropped on this limb since it was attached.
    pub fn gaps(&self) -> Gaps {
        lock(&self.inner.input).gaps
    }

    /// The last button mask the plane put on the wire for this limb.
    pub fn last_mask(&self) -> u16 {
        lock(&self.inner.input).last_mask
    }

    /// The geometry generation an observation assembled right now would carry.
    pub fn generation(&self) -> limb_core::fence::GeometryGeneration {
        lock(&self.inner.input).fence.current()
    }

    /// Record a geometry change and return what to tell the agent.
    ///
    /// The notice has to reach the agent BEFORE the state change out of
    /// reconnecting: an agent that sees `ready` and clicks before it sees this
    /// has clicked at a coordinate from the previous connection (`02 §6.2`).
    /// Returning the change rather than swallowing it is `GeometryFence`'s own
    /// design and this method passes it straight through so the caller cannot
    /// bump the counter without emitting the notice.
    pub fn geometry_changed(
        &self,
        why: limb_core::fence::GeometryChange,
        size: (u16, u16),
    ) -> limb_core::observation::Observation {
        let mut input = lock(&self.inner.input);
        let (generation, why) = input.fence.changed(why);
        input.ctx.size = size;
        limb_core::observation::Observation::GeometryChanged {
            geometry_generation: generation,
            why,
        }
    }

    /// Report a lifecycle change the caller saw on the session's event
    /// stream.
    ///
    /// The plane does not subscribe to `SessionEvent` itself, and that is a
    /// deliberate limit rather than an omission: the shell already owns that
    /// stream and a second subscriber inside this crate would be a second
    /// opinion about what state a limb is in. What the plane needs is the
    /// current state, so the caller reports it and the plane refuses intents
    /// against a limb that is not `Connected` with the retry time in the
    /// refusal (`02 §6.1`).
    pub fn note_state(&self, state: SessionState) {
        lock(&self.inner.input).state = state;
    }

    /// The last lifecycle state reported.
    pub fn state(&self) -> SessionState {
        lock(&self.inner.input).state.clone()
    }

    /// A read only view of the lease for one party (`08 §5.5`).
    ///
    /// A pane renders it and an agent reads it to decide whether to retry. It
    /// carries the holder's kind and label and never the holder's id, and the
    /// recipient's own queue position rather than the queue.
    pub fn lease_view(&self, party: &GrantId) -> agent_lease::LeaseView {
        lock(&self.inner.lease).view_for(party)
    }
}

/// Which limbs this process is driving.
pub struct LimbRegistry {
    config: PlaneConfig,
    limbs: Mutex<BTreeMap<LimbId, AttachedLimb>>,
}

impl LimbRegistry {
    /// A registry on the given settings.
    pub fn new(config: PlaneConfig) -> LimbRegistry {
        LimbRegistry {
            config,
            limbs: Mutex::new(BTreeMap::new()),
        }
    }

    /// The settings in force.
    pub fn config(&self) -> &PlaneConfig {
        &self.config
    }

    /// What a machine at a slot WOULD be called.
    ///
    /// Exposed because reproducibility is only useful if a caller can compute
    /// the name without attaching: the MCP revision of 2026-07-28 removed
    /// protocol level sessions, so a caller keeps no handle between turns and
    /// the limb id is the whole mechanism by which it addresses a machine on
    /// turn forty (`02 §4`).
    pub fn resolve(protocol: ProtocolKind, machine: &MachineKey, slot: Slot) -> LimbId {
        LimbId::derive(protocol, machine, slot)
    }

    /// How many limbs are attached.
    pub fn len(&self) -> usize {
        lock(&self.limbs).len()
    }

    /// Is nothing attached?
    pub fn is_empty(&self) -> bool {
        lock(&self.limbs).is_empty()
    }

    /// The limb under this id, if there is one.
    pub fn get(&self, id: &LimbId) -> Option<AttachedLimb> {
        lock(&self.limbs).get(id).cloned()
    }

    /// Every attached limb, in id order.
    pub fn list(&self) -> Vec<AttachedLimb> {
        lock(&self.limbs).values().cloned().collect()
    }

    /// Bring a machine under the plane, or hand back the limb that is already
    /// driving it.
    ///
    /// The order of the checks is deliberate and each one has to come before
    /// the next.
    ///
    /// 1. **The host.** `00 R19`. Before anything else, because the whole
    ///    value of the control is that it fires before the model's decision
    ///    reaches a socket.
    /// 2. **The capability.** `open` is what attaching costs (`02 §5.2`), and
    ///    the `agent` bundle deliberately carries neither `open` nor `close`:
    ///    an agent drives what it was given, and an agent that opens its own
    ///    machines is an operator and the person granting that should have to
    ///    say so.
    /// 3. **The slot.** `Limb::admits_slot`. Without this refusal an agent
    ///    asking for eight RDP limbs on one Windows box discovers the server's
    ///    session policy by watching seven of them disconnect the eighth.
    /// 4. **The existing limb.** `00 R31` and `00 B7`. Same machine, same
    ///    slot, same id, same limb.
    /// 5. **Admission.** `00 R21`, and only now, because a re-attach that
    ///    resolves to a limb already in the map has not added a session and
    ///    must not be refused for a limit it does not consume.
    ///
    /// # Errors
    ///
    /// [`PlaneError`], each naming what the caller can do about it.
    pub fn attach(&self, grant: &Grant, request: Attach) -> Result<AttachedLimb, PlaneError> {
        if !grant.allows_host(&request.host) {
            return Err(PlaneError::HostNotInGrant {
                grant: grant.id().to_string(),
                host: request.host,
            });
        }
        let needed = CapabilitySet::of(&[Capability::Open]);
        let missing = grant.missing(needed);
        if !missing.is_empty() {
            return Err(PlaneError::MissingCapability {
                grant: grant.id().to_string(),
                operation: "attaching a limb",
                missing: missing.iter().map(ToString::to_string).collect(),
            });
        }
        request.driver.admits_slot(request.slot)?;

        let protocol = request.driver.kind();
        let id = LimbId::derive(protocol, &request.machine, request.slot);

        let mut limbs = lock(&self.limbs);
        if let Some(existing) = limbs.get(&id) {
            // The digest is 48 bits and a collision is DETECTED rather than
            // acted on, which is the promise `LimbId::derive` makes and this
            // is where it is kept: the machine is held beside the id and
            // compared before anything is reused.
            if existing.machine() != &request.machine {
                return Err(PlaneError::IdentityCollision { id: id.to_string() });
            }
            // Slot 0 adopting a live session, and a re-attach after a crashed
            // agent restarted, are the same code path and the same id. That is
            // the reproducibility `02 §4` needs and it is why an agent's next
            // run is cheap.
            return Ok(existing.clone());
        }

        if limbs.len() >= self.config.max_driven_limbs {
            return Err(PlaneError::TooManyLimbs {
                limit: self.config.max_driven_limbs,
                attached: limbs.len(),
            });
        }

        let grounding = request.driver.grounding();
        let observatory = match request.frames {
            Some(frames) => Observatory::with_frames(id.clone(), frames),
            None => Observatory::blind(id.clone()),
        };
        // The lease is keyed on the limb id through `LimbId::lease_key`, which
        // is the one conversion between the two crates' spellings, so the
        // lease and the limb are keyed on the same characters and a trace can
        // join them.
        let lease = Lease::new(id.lease_key(), self.lease_config())?;
        let limb = AttachedLimb {
            inner: Arc::new(LimbInner {
                id: id.clone(),
                machine: request.machine,
                slot: request.slot,
                host: request.host,
                driver: request.driver,
                handle: request.handle,
                config: self.config.clone(),
                lease: Mutex::new(lease),
                input: Mutex::new(InputState {
                    fence: GeometryFence::new(),
                    ctx: LowerContext::new(grounding, request.size, &self.config),
                    gaps: Gaps::default(),
                    last_mask: 0,
                    // Attached is not connected. A caller that never reports a
                    // state gets every intent refused with `NOT_READY`, which
                    // is the right way round: the plane has been told nothing
                    // and says so, rather than assuming a machine is there.
                    state: SessionState::Idle,
                }),
                seq: Mutex::new(IntentSequence::new()),
                running: Mutex::new(BTreeMap::new()),
                observatory,
            }),
        };
        limbs.insert(id, limb.clone());
        Ok(limb)
    }

    /// Take a limb out of the registry.
    ///
    /// The caller is responsible for what `02 §6.2` owes on a close: every
    /// outstanding intent settles `Cancelled`, the lease is released, and the
    /// limb id stops resolving. Only the last of those is this method's, and
    /// the other two are the caller's because this crate does not own the
    /// agent's transport and cannot deliver a settlement over it.
    ///
    /// Reopening the same machine at the same slot produces the same id, which
    /// is the property that makes a crashed agent's next run cheap.
    ///
    /// # Errors
    ///
    /// [`PlaneError::NoSuchLimb`] if nothing is attached under that id, and
    /// [`PlaneError::MissingCapability`] if the grant does not carry `close`.
    pub fn detach(&self, grant: &Grant, id: &LimbId) -> Result<AttachedLimb, PlaneError> {
        let missing = grant.missing(CapabilitySet::of(&[Capability::Close]));
        if !missing.is_empty() {
            return Err(PlaneError::MissingCapability {
                grant: grant.id().to_string(),
                operation: "detaching a limb",
                missing: missing.iter().map(ToString::to_string).collect(),
            });
        }
        lock(&self.limbs)
            .remove(id)
            .ok_or_else(|| PlaneError::NoSuchLimb { id: id.to_string() })
    }

    fn lease_config(&self) -> LeaseConfig {
        self.config.lease
    }
}
