//! The framebuffer mirrors the plane keeps, one per session that asked for
//! one, and the `00 R6` negotiation that has to happen before any of them is
//! worth reading.
//!
//! ## The trap this module is built around
//!
//! `Framebuffer::apply`'s H.264 arm is a documented no-op
//! (`crates/vnc-core/src/pixel/framebuffer.rs:90`) and the webview decodes
//! those rectangles itself. A framebuffer mirror built beside it therefore
//! holds stale pixels in exactly the region that is moving, with no error
//! anywhere, and an agent looking at that sees a video player that never
//! started. That is worse than having no screenshot at all, because there is
//! no signal to act on.
//!
//! `encodings_for` puts `OPEN_H264` in the SetEncodings list whenever
//! `settings.allow_h264 && caps.supports_h264`
//! (`crates/vnc-core/src/quality/mod.rs:373`), `supports_h264` is true for
//! nearly every server, and Auto, Medium and Low all set `allow_h264: true`.
//! So the DEFAULT preset on a capable server gets H.264.
//! [`agent_perception::mirror_safety`] is the predicate that says so and
//! [`negotiation`] is the sequence that answers it.
//!
//! Two mechanisms answer the trap and both are load bearing.
//!
//! 1. **Negotiate it away first.** [`priming_order`] is what goes on the wire
//!    the moment a mirror is attached: on VNC the preset moves to
//!    [`QualityPreset::High`], which is the only preset that clears
//!    `allow_h264` without dropping the session to a palette, and then a
//!    `Refresh` repaints every region a live decoder context owned.
//! 2. **Poison what arrives anyway.** A renegotiation is not instant and a
//!    server may keep an in flight H.264 rectangle coming. `agent-perception`
//!    marks the region of every H.264 rectangle stale as it is applied, and a
//!    read of a stale region refuses with `STALE_REGION` rather than handing
//!    back the pixels that were underneath. Neither mechanism alone is enough:
//!    the first closes the window and the second is what makes the window
//!    itself safe.
//!
//! ## What renegotiating costs the PERSON, stated once and honestly
//!
//! A pane somebody is watching is a session, and the session has one quality
//! preset. Attaching a mirror to it moves that preset to High, so a person
//! watching sees the picture get SHARPER and the bandwidth go UP, and on a
//! link that was on Auto because it needed to be they may see the frame rate
//! drop. It is not a black screen and it is not a colour loss: `Low` and
//! `BlackAndWhite` also clear `allow_h264` and both cost colour, which is why
//! `03 §3.4` names High.
//!
//! So it happens **only when a mirror is actually requested**, and
//! [`Mirrors::detach`] hands back the preset to restore. `AGENT_BRIEF` D2 is
//! the rule that forces both halves: the interactive product does not regress
//! because an agent looked once.
//!
//! **The restore is honest about what it can know.** The shell keeps no record
//! of the preset a live session is currently on: `SessionFacts` carries the
//! lifecycle state and the framebuffer size and nothing else, and a person's
//! quality change goes straight from the toolbar to
//! `commands::session::set_quality` without passing through here. So the
//! preset restored is the one the session CONNECTED with, read from the saved
//! profile's `quality_pref`, or Auto for an ad-hoc connect. A person who
//! picked Medium by hand mid session and then had an agent attach and detach
//! ends up back on their profile's preset rather than on Medium. That is a
//! real gap, it is named in the attach reply as `restoreOnDetach` so nobody
//! has to guess, and closing it needs a field on `SessionFacts`.

use std::collections::HashMap;

use agent_perception::{
    mirror_safety, DamageDelta, DamageLog, MirrorBudget, MirrorSafety, MirrorSlot, PerceptionError,
    Read, ReadRequest, ReaderId,
};
use limb_core::observation::Timestamp;
use parking_lot::Mutex;
use remote_core::geometry::GeometryGeneration;
use vnc_core::{ClientCommand, DecodedRect, ProtocolKind, QualityPreset, Rect};

/// What a caller asked for when it attached.
///
/// Three values rather than a boolean because `00 R5` splits perception in two
/// and the split is not a convenience: damage rectangles leak geometry and
/// timing and no content at all, and `03 §9 A5` makes it an acceptance
/// criterion that a client which only watches for change has **nothing
/// allocated on its behalf**. [`Perceive::Damage`] is that client, and it
/// costs a rectangle log and not a framebuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Perceive {
    /// No mirror and no damage log. The default, and the only setting that
    /// changes nothing about the session a person is watching.
    #[default]
    None,
    /// Rung 1 only. Costs no framebuffer and sends no command.
    Damage,
    /// Rungs 2 to 4. Allocates a mirror and renegotiates the session.
    Frames,
}

impl Perceive {
    /// Read the `perceive` parameter, which is a boolean or one of three
    /// words.
    ///
    /// Anything unrecognised is [`Perceive::None`], on the same reasoning as
    /// [`crate::agent::plane_enabled`]: a surface that drives other people's
    /// machines lands a malformed setting on the cheapest, quietest value.
    pub fn parse(value: Option<&serde_json::Value>) -> Perceive {
        match value {
            Some(serde_json::Value::Bool(true)) => Perceive::Frames,
            Some(serde_json::Value::String(word)) => match word.as_str() {
                "frames" | "true" => Perceive::Frames,
                "damage" => Perceive::Damage,
                _ => Perceive::None,
            },
            _ => Perceive::None,
        }
    }

    pub fn wants_mirror(self) -> bool {
        matches!(self, Perceive::Frames)
    }
}

/// The commands that have to go out, in order, before a mirror may be
/// attached to a VNC session.
///
/// `03 §3.4` fixes the order and the order is the whole of it: clear
/// `allow_h264`, send SetEncodings, send `Refresh`. Turning H.264 off without
/// the refresh leaves every region a live decoder context owned holding
/// whatever the mirror last put there, which is black.
///
/// [`ClientCommand::SetQuality`] is how those first two steps are spelled from
/// the shell, because there is no command that sets `allow_h264` on its own:
/// the flag lives inside a preset, the preset drives `encodings_for`, and
/// changing the preset is what makes SetEncodings go out again.
/// [`QualityPreset::High`] is the only preset that clears the flag without
/// also dropping the session to a palette, so it is the one this returns, and
/// that is a real cost to whoever is watching the window: `Low` and
/// `BlackAndWhite` clear it too and both cost colour.
///
/// `None` when nothing needs to be done, which is a session already on a
/// preset with `allow_h264` false, or a server that never offered it.
pub fn negotiation(allow_h264: bool, server_supports_h264: bool) -> Option<[ClientCommand; 2]> {
    match mirror_safety(allow_h264, server_supports_h264) {
        MirrorSafety::Safe => None,
        MirrorSafety::H264Advertised => Some([
            ClientCommand::SetQuality(QualityPreset::High),
            ClientCommand::Refresh,
        ]),
    }
}

/// Everything that goes on one session's wire when a mirror is attached to it.
///
/// The H.264 half is asked for in its WORST case on VNC, and that is
/// deliberate rather than lazy. [`mirror_safety`] wants the session's
/// `allow_h264` and the server's `supports_h264`, and the shell records
/// neither: the quality preset lives inside the session task and
/// `ServerCapabilities` never leaves the handshake. Guessing "safe" would be
/// guessing in the direction `00 R6` says is silent, so this guesses in the
/// direction that costs the person some bandwidth and nothing else.
///
/// RDP and SSH get no `SetQuality`. No RDP encoder in this build produces
/// `RectPayload::H264` and a terminal has no framebuffer at all, so the preset
/// change would be a cost with nothing bought by it.
///
/// The `Refresh` is on every protocol and is not optional. A mirror allocated
/// against a session that has been connected for ten minutes starts as opaque
/// black; only a full non incremental update fills it, and until it does every
/// read refuses with [`PerceptionError::Priming`] rather than returning the
/// black (`03 §9 A3`).
pub fn priming_order(kind: ProtocolKind) -> Vec<ClientCommand> {
    match kind {
        ProtocolKind::Vnc => negotiation(true, true)
            .map(|steps| steps.to_vec())
            .unwrap_or_else(|| vec![ClientCommand::Refresh]),
        _ => vec![ClientCommand::Refresh],
    }
}

/// The `03 §3.4` sequence, named, for a refusal to carry.
///
/// Put on the wire rather than left in a comment because the refusal is read
/// by a model: an agent learns that pixels here are not free and that a
/// session which refuses them is refusing for a reason it can name. Computed
/// from [`negotiation`] so the sentence cannot drift from the code.
pub fn required_order() -> Vec<&'static str> {
    negotiation(true, true)
        .map(|steps| steps.iter().map(step_name).collect())
        .unwrap_or_default()
}

fn step_name(command: &ClientCommand) -> &'static str {
    match command {
        ClientCommand::SetQuality(_) => {
            "set the quality preset to high, which clears allow_h264 and makes SetEncodings go out again"
        }
        ClientCommand::Refresh => {
            "refresh, so every region a live decoder context owned is repainted rather than left black"
        }
        _ => "an unnamed step, which means negotiation() grew one and this list did not",
    }
}

/// A mirror was not attached, with the tag an agent branches on.
///
/// A sentence and a tag rather than a bare string, because `04 §4.4`'s rule is
/// that the code is what an agent matches on and the sentence beside it is
/// what an agent acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRefused {
    pub tag: &'static str,
    pub why: String,
}

/// What an attach still owes the session it attached to.
///
/// What the caller GOT is [`Mirrors::status`], deliberately: a second
/// description of the same mirror computed at a different instant is how the
/// two come to disagree, and the one that matters here is `primed`, which
/// changes underneath both of them the moment the refresh lands.
#[derive(Debug)]
pub struct MirrorAttached {
    /// The `03 §3.4` order, to be put on this session's wire by the caller.
    /// The caller sends it rather than this module because the command channel
    /// lives on the session registry and this module holds no registry.
    pub negotiate: Vec<ClientCommand>,
    /// The preset [`Mirrors::detach`] will hand back.
    pub restore: QualityPreset,
}

/// One session's mirror, its damage log, and what it owes the person.
#[derive(Debug)]
struct SessionMirror {
    slot: MirrorSlot,
    damage: DamageLog,
    reader: ReaderId,
    /// The framebuffer rectangle, kept here as well as in the mirror because a
    /// damage only subscriber has no mirror to read it off (`03 §9 A5`).
    size: (u16, u16),
    generation: GeometryGeneration,
    /// The preset to put back, and `None` when nothing was changed and there
    /// is therefore nothing to put back.
    restore: Option<QualityPreset>,
}

impl SessionMirror {
    fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.size.0, self.size.1)
    }
}

/// Every mirror this process holds.
///
/// The budget is applied across the set and not per session, which is the
/// half of `00 R5` a per session ceiling alone does not cover: twelve mirrored
/// 4K sessions is 380 MiB and each one of them is individually admissible.
#[derive(Debug, Default)]
pub struct Mirrors {
    inner: Mutex<HashMap<String, SessionMirror>>,
    budget: MirrorBudget,
    next_reader: std::sync::atomic::AtomicU64,
}

impl Mirrors {
    /// Attach, or say why not.
    ///
    /// `size` is [`crate::state::SessionFacts::size`], which is `None` until
    /// the first `DesktopResize`. A mirror cannot be sized without it and this
    /// refuses rather than guessing a resolution, because a mirror of the
    /// wrong size composites every rectangle at the wrong offset and reports
    /// full coverage while doing it.
    ///
    /// # Errors
    ///
    /// A [`MirrorRefused`] naming what would make it work: a terminal session,
    /// a session that has not reported its geometry yet, or a framebuffer over
    /// the pixel budget. **Never a smaller mirror than was asked for**
    /// (`00 R5`).
    pub fn attach(
        &self,
        session_id: &str,
        want: Perceive,
        kind: ProtocolKind,
        size: Option<(u16, u16)>,
        restore: QualityPreset,
        now: Timestamp,
    ) -> Result<MirrorAttached, MirrorRefused> {
        let (width, height) = match (want, size) {
            (Perceive::None, _) => {
                return Ok(MirrorAttached {
                    negotiate: Vec::new(),
                    restore,
                })
            }
            (_, Some(size)) => size,
            (_, None) => {
                return Err(MirrorRefused {
                    tag: "NO_FRAMEBUFFER",
                    why: format!(
                        "{session_id} has reported no framebuffer size, so a mirror cannot be sized. A terminal session never reports one and never will: read it with terminal.read instead. A desktop session reports one as part of connecting, so if this is a desktop, wait for limb.status to carry a size and attach again"
                    ),
                })
            }
        };

        let mut mirrors = self.inner.lock();
        // Every OTHER mirror, which is what the budget wants: this session's
        // own is either absent or about to be replaced by one the same size.
        let others: u64 = mirrors
            .iter()
            .filter(|(id, _)| id.as_str() != session_id)
            .map(|(_, held)| held.slot.bytes())
            .sum();

        let reader = ReaderId(
            self.next_reader
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let held = mirrors.entry(session_id.to_string()).or_insert_with(|| {
            let mut damage = DamageLog::default();
            // Subscribed here rather than at the first read, because a reader
            // that subscribes late is told nothing was dropped when in fact
            // everything before it was.
            damage.subscribe(reader);
            SessionMirror {
                slot: MirrorSlot::new(self.budget),
                damage,
                reader,
                size: (width, height),
                generation: GeometryGeneration::FIRST,
                restore: None,
            }
        });
        held.size = (width, height);

        if !want.wants_mirror() {
            return Ok(MirrorAttached {
                negotiate: Vec::new(),
                restore,
            });
        }

        let generation = held.generation;
        held.slot
            .attach(width, height, generation, others, now)
            .map_err(|e| MirrorRefused {
                tag: budget_tag(&e),
                why: e.to_string(),
            })?;

        // Recorded only when this is the attach that allocated, so a second
        // attach on the same session cannot overwrite the preset the first one
        // is holding for the person.
        let negotiate = if held.restore.is_none() {
            held.restore = Some(restore);
            priming_order(kind)
        } else {
            // Already renegotiated and already primed or priming. Sending the
            // preset again would be a second SetEncodings and a second full
            // repaint for nothing.
            Vec::new()
        };

        Ok(MirrorAttached { negotiate, restore })
    }

    /// Feed one coalesced `SessionEvent::FramebufferUpdate` in.
    ///
    /// **This is the seam.** The plane is the SECOND consumer of that stream
    /// and the webview is the first (`00 R22`), so the shell's own event pump
    /// calls this beside the binary frame it already sends to the window. A
    /// session nobody asked to perceive is not in the map and pays a hash
    /// lookup and nothing else, which is `03 §9 A5`.
    ///
    /// Rect by rect and in order, which is the only order that composites
    /// correctly: a `CopyRect` reads pixels an earlier rect in the same update
    /// wrote. `agent-perception` does that part; this is the plumbing.
    // Reached only from [`crate::agent::AgentPlane::feed`], which nothing in
    // this build calls yet. That method's doc comment names the two lines
    // `commands::session::forward_events` needs and why they are not written
    // here.
    #[allow(dead_code)]
    pub fn feed(&self, session_id: &str, rects: &[DecodedRect], at: Timestamp) {
        let mut mirrors = self.inner.lock();
        let Some(held) = mirrors.get_mut(session_id) else {
            return;
        };
        let bounds = held.bounds();
        held.slot.apply(rects);
        held.damage.record(rects, bounds, at);
    }

    /// The remote desktop changed resolution.
    ///
    /// The generation is bumped whether or not a mirror is attached, because
    /// `00 R10` is about a coordinate computed against a screen that no longer
    /// exists and a damage only reader hands out coordinates too.
    // Unreached for the same reason [`Mirrors::feed`] is: it hangs off the
    // `SessionEvent::DesktopResize` arm of the shell's event pump.
    #[allow(dead_code)]
    pub fn resize(&self, session_id: &str, width: u16, height: u16) {
        let mut mirrors = self.inner.lock();
        let others: u64 = mirrors
            .iter()
            .filter(|(id, _)| id.as_str() != session_id)
            .map(|(_, held)| held.slot.bytes())
            .sum();
        let Some(held) = mirrors.get_mut(session_id) else {
            return;
        };
        held.size = (width, height);
        held.generation = held.generation.next();
        let generation = held.generation;
        if let Err(e) = held.slot.resize(width, height, generation, others) {
            // The mirror was dropped rather than kept: a session that resizes
            // to something over budget must not go on serving reads from the
            // old picture (`00 R5`). The next read answers `NO_MIRROR`, which
            // says exactly that.
            tracing::warn!(
                session = %session_id,
                "the mirror was freed on resize to {width}x{height}: {e}"
            );
        }
    }

    /// Answer one read.
    ///
    /// # Errors
    ///
    /// A [`PerceptionError`]. `PRIMING` and `STALE_REGION` are the two that
    /// matter and they are deliberately different: priming resolves on its own
    /// once the refresh lands, and staleness resolves only when the session
    /// stops advertising H.264, which is the plane's job and not the agent's.
    pub fn read(
        &self,
        session_id: &str,
        request: &ReadRequest,
        now: Timestamp,
    ) -> Result<Read, PerceptionError> {
        let mut mirrors = self.inner.lock();
        let held = mirrors
            .get_mut(session_id)
            .ok_or(PerceptionError::NoMirror)?;
        let damage = &mut held.damage;
        held.slot.read(request, damage, now)
    }

    /// This session's reader id, so a rung 4 read names the right cursor.
    pub fn reader(&self, session_id: &str) -> Option<ReaderId> {
        self.inner.lock().get(session_id).map(|held| held.reader)
    }

    /// The damage since this reader last looked, consumed.
    ///
    /// Costs no framebuffer, which is the point of it (`00 R5`, `03 §9 A5`).
    pub fn take_damage(&self, session_id: &str) -> Option<(DamageDelta, Rect, GeometryGeneration)> {
        let mut mirrors = self.inner.lock();
        let held = mirrors.get_mut(session_id)?;
        let bounds = held.bounds();
        let generation = held.generation;
        Some((held.damage.take(held.reader), bounds, generation))
    }

    /// What a caller should be told about this session's pixels right now.
    pub fn status(&self, session_id: &str) -> MirrorStatus {
        let mirrors = self.inner.lock();
        match mirrors.get(session_id) {
            None => MirrorStatus::default(),
            Some(held) => MirrorStatus {
                subscribed: true,
                mirror: held.slot.is_attached(),
                primed: held.slot.get().is_some_and(|m| m.is_primed()),
                bytes: held.slot.bytes(),
                width: held.size.0,
                height: held.size.1,
                generation: held.generation,
                h264_rects: held.slot.get().map_or(0, |m| m.signals().h264_rects()),
            },
        }
    }

    /// Free this session's mirror and hand back the preset to restore.
    ///
    /// `None` when nothing was renegotiated, which is a session that was never
    /// mirrored or that only ever watched for damage. The caller puts the
    /// preset on the wire; this module holds no command channel.
    pub fn detach(&self, session_id: &str) -> Option<QualityPreset> {
        self.inner
            .lock()
            .remove(session_id)
            .and_then(|held| held.restore)
    }

    /// Free every mirror and hand back every preset that is owed.
    ///
    /// The plane was switched off, or the application is closing. Sessions
    /// outlive both: switching the plane off closes the socket and leaves
    /// every pane exactly where it was, so a person whose session was
    /// renegotiated for a mirror that no longer exists must be given their
    /// preset back here or nowhere.
    pub fn detach_all(&self) -> Vec<(String, QualityPreset)> {
        let mut mirrors = self.inner.lock();
        let owed = mirrors
            .iter()
            .filter_map(|(id, held)| held.restore.map(|preset| (id.clone(), preset)))
            .collect();
        mirrors.clear();
        owed
    }

    /// Bytes every mirror in this process holds together, for `session.stats`
    /// (`03 §2.7` item 4: an operator can answer "why is this process holding
    /// 380 MB" without a profiler).
    pub fn bytes_in_use(&self) -> u64 {
        self.inner
            .lock()
            .values()
            .map(|held| held.slot.bytes())
            .sum()
    }

    /// Free every mirror nothing has read for the idle timeout (`00 R5`).
    ///
    /// The damage log and the subscription survive: a reader that only watches
    /// for change costs nothing to keep and losing its cursor would report the
    /// next change as "everything since the beginning".
    pub fn reap(&self, now: Timestamp) -> u64 {
        self.inner
            .lock()
            .values_mut()
            .map(|held| held.slot.reap(now))
            .sum()
    }

    /// Forget a session that has ended.
    pub fn forget(&self, session_id: &str) {
        self.inner.lock().remove(session_id);
    }
}

/// What `limb.attach` and `limb.status` report about one session's pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorStatus {
    /// This session has a damage subscription, with or without a mirror.
    pub subscribed: bool,
    /// A framebuffer mirror is allocated.
    pub mirror: bool,
    /// Every tile has been painted, so a read can be answered.
    pub primed: bool,
    pub bytes: u64,
    pub width: u16,
    pub height: u16,
    pub generation: GeometryGeneration,
    /// How many H.264 rectangles have reached this mirror and poisoned their
    /// region. Reported because a non zero count on a session that was
    /// renegotiated is the one number that says the renegotiation did not
    /// take, and nothing else in the response would show it.
    pub h264_rects: u64,
}

/// Nothing is subscribed. Hand written rather than derived because
/// [`GeometryGeneration`] has no `Default` on purpose: a defaulted, never
/// initialised zero in somebody else's struct must not be mistakable for a
/// live generation, so this names `FIRST` explicitly.
impl Default for MirrorStatus {
    fn default() -> Self {
        MirrorStatus {
            subscribed: false,
            mirror: false,
            primed: false,
            bytes: 0,
            width: 0,
            height: 0,
            generation: GeometryGeneration::FIRST,
            h264_rects: 0,
        }
    }
}

fn budget_tag(error: &PerceptionError) -> &'static str {
    match error {
        PerceptionError::Budget(_) => "BUDGET_REFUSED",
        _ => "NO_FRAMEBUFFER",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_perception::{ImageFormat, ReadKind};
    use remote_core::events::RectPayload;

    fn now() -> Timestamp {
        Timestamp(1_000)
    }

    fn rgba(rect: Rect, colour: [u8; 4]) -> DecodedRect {
        DecodedRect {
            rect,
            payload: RectPayload::Rgba(colour.repeat(rect.width as usize * rect.height as usize)),
        }
    }

    fn h264(rect: Rect) -> DecodedRect {
        DecodedRect {
            rect,
            payload: RectPayload::H264 {
                // Non empty: a zero length payload is a pure control message
                // that changes no pixels and poisons nothing.
                data: vec![0, 0, 0, 1, 0x65],
                flags: 0,
                context_id: 0,
                reset: false,
                keyframe: true,
            },
        }
    }

    /// A mirror that has been fully painted and can answer a read.
    ///
    /// The reader is caught up on the priming paint, which is what a real
    /// attach produces too: the `Refresh` repaints the whole screen, so a rung
    /// 4 read straight after it would see the whole screen as "changed".
    fn primed(mirrors: &Mirrors, id: &str, size: (u16, u16)) {
        mirrors
            .attach(
                id,
                Perceive::Frames,
                ProtocolKind::Vnc,
                Some(size),
                QualityPreset::Auto,
                now(),
            )
            .expect("these test geometries are inside every budget");
        mirrors.feed(
            id,
            &[rgba(Rect::new(0, 0, size.0, size.1), [10, 20, 30, 255])],
            now(),
        );
        mirrors.take_damage(id);
    }

    /// The default preset on a capable server is the case, and it is the one
    /// that has to produce a sequence rather than a shrug.
    #[test]
    fn the_default_preset_on_a_capable_server_has_to_renegotiate() {
        let steps = negotiation(true, true).expect("Auto and Medium both allow H.264");
        assert!(
            matches!(steps[0], ClientCommand::SetQuality(QualityPreset::High)),
            "the flag is cleared first, and High is the only preset that clears it without costing colour"
        );
        assert!(
            matches!(steps[1], ClientCommand::Refresh),
            "the refresh comes second: without it every region a live decoder context owned stays black"
        );
    }

    #[test]
    fn a_session_that_never_offered_h264_is_left_alone() {
        assert!(negotiation(true, false).is_none());
        assert!(negotiation(false, true).is_none());
        assert!(negotiation(false, false).is_none());
    }

    /// The order travels with the refusal, so it cannot be lost between this
    /// file and whoever reads a refusal.
    #[test]
    fn the_order_a_negotiation_would_take_is_nameable() {
        let order = required_order();
        assert_eq!(order.len(), 2);
        assert!(order[0].contains("allow_h264"), "{}", order[0]);
        assert!(order[1].starts_with("refresh"), "{}", order[1]);
    }

    /// Only VNC pays for the preset change, and every protocol pays for the
    /// refresh, because a mirror that is never refreshed is opaque black.
    #[test]
    fn only_vnc_gets_the_preset_change_and_everything_gets_the_refresh() {
        let vnc = priming_order(ProtocolKind::Vnc);
        assert_eq!(vnc.len(), 2);
        assert!(matches!(
            vnc[0],
            ClientCommand::SetQuality(QualityPreset::High)
        ));
        assert!(matches!(vnc[1], ClientCommand::Refresh));

        let rdp = priming_order(ProtocolKind::Rdp);
        assert_eq!(rdp.len(), 1, "no RDP encoder in this build emits H.264");
        assert!(matches!(rdp[0], ClientCommand::Refresh));
    }

    /// `03 §9 A3`. A mirror allocated against a session that has been
    /// connected for ten minutes is opaque black, and the black is refused
    /// rather than handed back as a screenshot.
    #[test]
    fn a_mirror_that_has_not_been_painted_refuses_rather_than_serving_black() {
        let mirrors = Mirrors::default();
        let attached = mirrors
            .attach(
                "s1",
                Perceive::Frames,
                ProtocolKind::Vnc,
                Some((64, 64)),
                QualityPreset::Auto,
                now(),
            )
            .expect("attached");
        assert_eq!(attached.negotiate.len(), 2, "the 03 §3.4 order goes out");
        let status = mirrors.status("s1");
        assert!(status.mirror);
        assert!(!status.primed, "nothing has been painted yet");

        let refused = mirrors
            .read("s1", &ReadRequest::frame(), now())
            .expect_err("the black is not a screenshot");
        assert_eq!(refused.as_str(), "PRIMING");
        assert!(
            refused.is_transient(),
            "priming resolves on its own once the refresh lands, and an agent has to be able to tell that from a dead end"
        );
    }

    /// **The test this whole module exists for.**
    ///
    /// An H.264 rectangle reaches an attached mirror. The pixels underneath it
    /// are whatever was there before, so the read must refuse or say the
    /// region is stale, and must never hand back a clean frame.
    #[test]
    fn an_h264_rect_is_refused_or_reported_stale_and_never_returned_clean() {
        let mirrors = Mirrors::default();
        primed(&mirrors, "s1", (64, 64));
        // …the picture is trustworthy at this point.
        let clean = mirrors
            .read("s1", &ReadRequest::frame(), now())
            .expect("a fully painted mirror answers");
        match clean {
            Read::Frame(observation) => assert!(
                observation.coverage.is_complete(),
                "nothing has poisoned it yet"
            ),
            other => panic!("expected a frame, got {other:?}"),
        }

        // …and then a video rectangle arrives, which the mirror cannot
        // composite because the decoder is in the webview.
        mirrors.feed("s1", &[h264(Rect::new(16, 16, 32, 32))], now());

        let refused = mirrors
            .read("s1", &ReadRequest::frame(), now())
            .expect_err("00 R6: the moving region is stale and the read must say so");
        assert_eq!(refused.as_str(), "STALE_REGION");
        assert!(
            !refused.is_transient(),
            "staleness resolves only when the session stops advertising H.264, which is the plane's job and not the agent's"
        );

        // The only other permitted answer is a frame that NAMES the stale
        // rectangles. There is no third answer where the pixels come back
        // clean.
        let annotated = mirrors
            .read("s1", &ReadRequest::frame().annotating_stale(), now())
            .expect("annotating is the other half of 00 R6");
        match annotated {
            Read::Frame(observation) => assert!(
                !observation.coverage.is_complete(),
                "an annotated frame over a poisoned region must not claim complete coverage"
            ),
            other => panic!("expected a frame, got {other:?}"),
        }

        let status = mirrors.status("s1");
        assert_eq!(
            status.h264_rects, 1,
            "the count is what says a renegotiation did not take"
        );
    }

    /// A zero length H.264 payload is a pure control message: it changes no
    /// pixels, so it must not poison a region either. Getting this wrong would
    /// make every session that resets a decoder context unreadable forever.
    #[test]
    fn an_empty_h264_control_message_poisons_nothing() {
        let mirrors = Mirrors::default();
        primed(&mirrors, "s1", (64, 64));
        mirrors.feed(
            "s1",
            &[DecodedRect {
                rect: Rect::new(0, 0, 64, 64),
                payload: RectPayload::H264 {
                    data: Vec::new(),
                    flags: 1,
                    context_id: 0,
                    reset: true,
                    keyframe: false,
                },
            }],
            now(),
        );
        assert!(mirrors.read("s1", &ReadRequest::frame(), now()).is_ok());
    }

    /// `03 §9 A5`. A client that only watches for change has nothing
    /// allocated on its behalf, and it still gets its rectangles.
    #[test]
    fn watching_for_change_allocates_no_framebuffer() {
        let mirrors = Mirrors::default();
        mirrors
            .attach(
                "s1",
                Perceive::Damage,
                ProtocolKind::Vnc,
                Some((3840, 2160)),
                QualityPreset::Auto,
                now(),
            )
            .expect("a damage subscription is admitted whatever the size");
        assert_eq!(mirrors.bytes_in_use(), 0, "not one byte of framebuffer");

        mirrors.feed(
            "s1",
            &[rgba(Rect::new(4, 8, 16, 16), [1, 2, 3, 255])],
            now(),
        );
        let (delta, _, _) = mirrors.take_damage("s1").expect("subscribed");
        assert_eq!(delta.rects, vec![Rect::new(4, 8, 16, 16)]);

        // …and no pixels, because none were paid for.
        assert!(matches!(
            mirrors.read("s1", &ReadRequest::frame(), now()),
            Err(PerceptionError::NoMirror)
        ));
    }

    /// `00 R5`. Over the budget it refuses and names the number. It does not
    /// allocate something smaller, and there is no variant of the answer that
    /// could.
    #[test]
    fn a_framebuffer_over_the_pixel_budget_is_refused_rather_than_shrunk() {
        let mirrors = Mirrors::default();
        let refused = mirrors
            .attach(
                "s1",
                Perceive::Frames,
                ProtocolKind::Vnc,
                Some((10000, 10000)),
                QualityPreset::Auto,
                now(),
            )
            .expect_err("100 megapixels is over every budget");
        assert_eq!(refused.tag, "BUDGET_REFUSED");
        assert!(
            refused.why.contains("no smaller image was substituted"),
            "{}",
            refused.why
        );
        assert_eq!(mirrors.bytes_in_use(), 0);
    }

    /// A session that has not said how big it is cannot be mirrored, and the
    /// refusal says which kind of session will never say.
    #[test]
    fn a_session_with_no_geometry_is_refused_by_name() {
        let mirrors = Mirrors::default();
        let refused = mirrors
            .attach(
                "s1",
                Perceive::Frames,
                ProtocolKind::Ssh,
                None,
                QualityPreset::Auto,
                now(),
            )
            .expect_err("a PTY has no framebuffer");
        assert_eq!(refused.tag, "NO_FRAMEBUFFER");
        assert!(refused.why.contains("terminal.read"), "{}", refused.why);
    }

    /// The person gets their session back. The preset handed to `attach` is
    /// the one `detach` returns, and detaching twice does not ask for a second
    /// preset change.
    #[test]
    fn detaching_hands_back_the_preset_to_restore_exactly_once() {
        let mirrors = Mirrors::default();
        mirrors
            .attach(
                "s1",
                Perceive::Frames,
                ProtocolKind::Vnc,
                Some((64, 64)),
                QualityPreset::Medium,
                now(),
            )
            .expect("attached");
        assert_eq!(mirrors.detach("s1"), Some(QualityPreset::Medium));
        assert_eq!(
            mirrors.detach("s1"),
            None,
            "a cleanup path has to be safe to call twice, and a second SetQuality would be a second repaint for nothing"
        );
        assert_eq!(mirrors.bytes_in_use(), 0);
    }

    /// A damage only subscriber never changed the preset, so it owes the
    /// person nothing on the way out.
    #[test]
    fn watching_for_change_costs_the_person_no_preset_change() {
        let mirrors = Mirrors::default();
        let attached = mirrors
            .attach(
                "s1",
                Perceive::Damage,
                ProtocolKind::Vnc,
                Some((64, 64)),
                QualityPreset::Auto,
                now(),
            )
            .expect("attached");
        assert!(attached.negotiate.is_empty());
        assert_eq!(mirrors.detach("s1"), None);
    }

    /// `00 R5`'s idle half: a mirror nobody has read for the timeout is freed,
    /// and freeing it does not lose the damage cursor.
    #[test]
    fn an_idle_mirror_is_freed_and_the_damage_subscription_survives() {
        let mirrors = Mirrors::default();
        primed(&mirrors, "s1", (64, 64));
        assert!(mirrors.bytes_in_use() > 0);

        let freed = mirrors.reap(Timestamp(now().0 + 60_001));
        assert_eq!(freed, 64 * 64 * 4);
        assert_eq!(mirrors.bytes_in_use(), 0);

        mirrors.feed("s1", &[rgba(Rect::new(0, 0, 8, 8), [4, 5, 6, 255])], now());
        let (delta, _, _) = mirrors.take_damage("s1").expect("still subscribed");
        assert_eq!(delta.rects, vec![Rect::new(0, 0, 8, 8)]);
    }

    /// `00 R10`. A read fenced against a generation the session has moved past
    /// is refused: the caller is asking about a screen that no longer exists.
    #[test]
    fn a_read_fenced_against_a_screen_that_has_gone_is_refused() {
        let mirrors = Mirrors::default();
        primed(&mirrors, "s1", (64, 64));
        let first = mirrors.status("s1").generation;

        mirrors.resize("s1", 128, 128);
        assert_ne!(mirrors.status("s1").generation, first);

        let refused = mirrors
            .read("s1", &ReadRequest::frame().fenced_at(first), now())
            .expect_err("that screen is gone");
        assert_eq!(refused.as_str(), "GEOMETRY_CHANGED");
    }

    /// Rung 4 crops around what changed, and it does it from the rect LIST.
    /// `Rect::union` is a bounding box, so two changes in opposite corners
    /// union to the whole screen (`00 R39b`).
    #[test]
    fn the_default_read_is_a_crop_around_what_changed() {
        // 512 square rather than 64, because rung 4 falls back to a
        // downscaled full frame when the crop would cover more than a quarter
        // of the screen (`03 §9 A10`), and an 8x8 change plus a 64 pixel
        // margin is more than a quarter of a 64 square desktop.
        let mirrors = Mirrors::default();
        primed(&mirrors, "s1", (512, 512));
        let reader = mirrors.reader("s1").expect("subscribed");

        mirrors.feed(
            "s1",
            &[rgba(Rect::new(100, 100, 8, 8), [200, 0, 0, 255])],
            now(),
        );

        let read = mirrors
            .read("s1", &ReadRequest::change(reader), now())
            .expect("a crop around the change");
        match read {
            Read::Frame(observation) => {
                assert_eq!(observation.rung.as_str(), "change");
                assert_eq!(
                    observation.damage,
                    vec![Rect::new(100, 100, 8, 8)],
                    "the LIST travels, not a union"
                );
                assert!(
                    observation.image.space.region.width < 512,
                    "a crop, not the whole screen: {:?}",
                    observation.image.space.region
                );
                assert!(observation.image.space.is_unscaled(), "rung 4 is scale 1.0");
                assert_eq!(observation.image.format, ImageFormat::Png);
            }
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    /// Rung 4 with nothing to show is an ANSWER and not an error. An agent
    /// that receives an error for "nothing changed" retries immediately rather
    /// than waiting, which turns the cheapest rung into a spin loop.
    #[test]
    fn nothing_changed_is_an_answer() {
        let mirrors = Mirrors::default();
        primed(&mirrors, "s1", (64, 64));
        let reader = mirrors.reader("s1").expect("subscribed");

        let read = mirrors
            .read("s1", &ReadRequest::change(reader), now())
            .expect("unchanged is not a failure");
        assert!(matches!(read, Read::Unchanged { .. }));
    }

    /// A region outside the framebuffer is refused and never clamped: a
    /// clamped region is a picture of somewhere else.
    #[test]
    fn a_region_off_the_screen_is_refused_rather_than_clamped() {
        let mirrors = Mirrors::default();
        primed(&mirrors, "s1", (64, 64));
        let refused = mirrors
            .read("s1", &ReadRequest::region(Rect::new(40, 40, 64, 64)), now())
            .expect_err("half of that rectangle is off the screen");
        assert_eq!(refused.as_str(), "OUT_OF_BOUNDS");
    }

    /// A session nobody asked to perceive is not in the map, so feeding it is
    /// a hash lookup and nothing else (`03 §9 A5`).
    #[test]
    fn a_session_nobody_perceives_costs_a_lookup() {
        let mirrors = Mirrors::default();
        mirrors.feed(
            "never-attached",
            &[rgba(Rect::new(0, 0, 8, 8), [0; 4])],
            now(),
        );
        assert_eq!(mirrors.bytes_in_use(), 0);
        assert_eq!(mirrors.status("never-attached"), MirrorStatus::default());
    }

    #[test]
    fn perceive_parses_the_boolean_and_the_three_words() {
        use serde_json::json;
        assert_eq!(Perceive::parse(None), Perceive::None);
        assert_eq!(Perceive::parse(Some(&json!(false))), Perceive::None);
        assert_eq!(Perceive::parse(Some(&json!(true))), Perceive::Frames);
        assert_eq!(Perceive::parse(Some(&json!("frames"))), Perceive::Frames);
        assert_eq!(Perceive::parse(Some(&json!("damage"))), Perceive::Damage);
        assert_eq!(
            Perceive::parse(Some(&json!("everything"))),
            Perceive::None,
            "a surface that drives other people's machines lands a malformed setting on the quietest value"
        );
    }

    /// The read kinds a caller can ask for all reach the mirror, and each one
    /// reports which rung answered it.
    #[test]
    fn every_rung_reports_which_rung_answered_it() {
        let mirrors = Mirrors::default();
        primed(&mirrors, "s1", (512, 512));
        let reader = mirrors.reader("s1").expect("subscribed");
        mirrors.feed("s1", &[rgba(Rect::new(8, 8, 4, 4), [7, 7, 7, 255])], now());
        for (request, rung) in [
            (ReadRequest::frame(), "frame"),
            (ReadRequest::region(Rect::new(0, 0, 16, 16)), "region"),
            (
                ReadRequest {
                    kind: ReadKind::Change { reader, margin: 0 },
                    ..ReadRequest::change(reader)
                },
                "change",
            ),
        ] {
            match mirrors.read("s1", &request, now()).expect("answered") {
                Read::Frame(observation) => assert_eq!(observation.rung.as_str(), rung),
                Read::Unchanged { .. } => panic!("{rung} had something to show"),
            }
        }
    }
}
