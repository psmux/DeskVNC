//! `00 R5`'s capability split, which is the whole of the observation path's
//! enforcement.
//!
//! A FRAME is content: whatever is on somebody's screen, leaving the process.
//! DAMAGE is geometry and timing and no content at all: an agent watching it
//! learns that something in the lower right is repainting at 1 Hz and learns
//! nothing about what it says. So `perceive.damage` is a separate and weaker
//! capability that does not imply `perceive.frame`, and `00 R20` settles the
//! spellings: `02 §5` is canonical, so those are `view` and `capture` and
//! `07`'s placeholders map one for one.

mod common;

use agent_lease::LeaseInstant;
use agent_plane::{
    Attach, Damage, Frame, FrameSource, Grant, LimbRegistry, PerceptionUnavailable, PlaneConfig,
    RefusalReason,
};
use common::{fake_session, intent, TestLimb};
use limb_core::capability::{Capability, CapabilitySet};
use limb_core::fence::GeometryGeneration;
use limb_core::identity::{MachineKey, Slot};
use limb_core::intent::{CaptureForm, IntentKind, ReadForm};
use limb_core::observation::{Outcome, RefusalCode, Timestamp};
use limb_core::Rect;
use remote_core::driver::ProtocolKind;
use remote_core::state::SessionState;
use std::sync::{Arc, Mutex};

/// A mirror that always has one frame, with whatever damage it was given.
///
/// It records what it was ASKED for, which is the only way to see `00 R39b`
/// from outside: a damage crop that reaches the pixels as the whole
/// framebuffer has already lost, and the returned bytes look identical either
/// way.
struct StubMirror {
    rects: Vec<Rect>,
    asked: Mutex<Vec<Option<Rect>>>,
}

impl StubMirror {
    fn with_damage(rects: Vec<Rect>) -> StubMirror {
        StubMirror {
            rects,
            asked: Mutex::new(Vec::new()),
        }
    }

    /// The one rectangle a read was sized from, or `None` for a whole frame.
    fn last_ask(&self) -> Option<Rect> {
        *self
            .asked
            .lock()
            .expect("no test panics while holding this")
            .last()
            .expect("the mirror was read at least once")
    }
}

impl Default for StubMirror {
    fn default() -> StubMirror {
        StubMirror::with_damage(vec![Rect::new(10, 10, 4, 4)])
    }
}

impl FrameSource for StubMirror {
    fn frame(
        &self,
        region: Option<Rect>,
        _scale: Option<f32>,
        _at: Timestamp,
    ) -> Result<Frame, PerceptionUnavailable> {
        self.asked
            .lock()
            .expect("no test panics while holding this")
            .push(region);
        Ok(Frame {
            bytes: bytes::Bytes::from_static(b"pixels"),
            covers: region.unwrap_or(Rect::new(0, 0, 1280, 720)),
            generation: GeometryGeneration::FIRST,
            complete: true,
        })
    }

    fn damage(&self) -> Option<Damage> {
        if self.rects.is_empty() {
            return None;
        }
        let bounds = self
            .rects
            .iter()
            .fold(Rect::new(0, 0, 0, 0), |acc, r| acc.union(r));
        Some(Damage {
            rects: self.rects.clone(),
            bounds,
            coverage: 0.01,
            generation: GeometryGeneration::FIRST,
        })
    }
}

fn watcher(id: &str, caps: &[Capability]) -> Grant {
    Grant::issue(id, CapabilitySet::of(caps), ["desk.example".to_string()]).expect("a legal grant")
}

fn attach(registry: &LimbRegistry, grant: &Grant) -> agent_plane::AttachedLimb {
    attach_to(registry, grant, Arc::new(StubMirror::default()))
}

fn attach_to(
    registry: &LimbRegistry,
    grant: &Grant,
    frames: Arc<StubMirror>,
) -> agent_plane::AttachedLimb {
    let (handle, rx) = fake_session("desk.example", 64);
    std::mem::forget(rx);
    let limb = registry
        .attach(
            grant,
            Attach {
                driver: Arc::new(TestLimb::desktop()),
                machine: MachineKey::endpoint(ProtocolKind::Vnc, "desk.example", 5900),
                slot: Slot::ATTACH,
                host: "desk.example".to_string(),
                handle,
                size: (1280, 720),
                frames: Some(frames),
            },
        )
        .expect("attached");
    limb.note_state(SessionState::Connected);
    limb
}

#[tokio::test]
async fn perceive_damage_does_not_imply_perceive_frame() {
    // `view` plus `open`, which is what an attachment that may watch a machine
    // and not photograph it carries.
    let grant = watcher("att_damage", &[Capability::View, Capability::Open]);
    let registry = LimbRegistry::new(PlaneConfig::default());
    let limb = attach(&registry, &grant);
    let now = LeaseInstant::from_millis(1_000);

    // A text read costs `view` alone and is the parameter dependent rule
    // `PARAM_RULES[0]` describes, so this grant gets past the capability check
    // and is refused for a different reason, which is what proves the split is
    // where it says it is.
    let refused = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::Capture {
                    form: CaptureForm::Full,
                    region: None,
                    scale: None,
                },
            ),
            now,
        )
        .await;
    assert_eq!(
        refused.reason,
        Some(RefusalReason::Limb(RefusalCode::MissingCapability)),
        "pixels cost capture, and a grant holding only view does not get them"
    );
    let because = match &refused.outcome {
        Outcome::Refused { because, .. } => because.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert!(
        because.contains("capture"),
        "the refusal names what is missing: {because}"
    );
}

#[tokio::test]
async fn perceive_frame_returns_the_pixels_wrapped_as_untrusted() {
    let grant = watcher(
        "att_frame",
        &[Capability::View, Capability::Capture, Capability::Open],
    );
    let registry = LimbRegistry::new(PlaneConfig::default());
    let limb = attach(&registry, &grant);
    let now = LeaseInstant::from_millis(1_000);

    let settlement = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::ReadScreen {
                    form: ReadForm::Pixels,
                    region: Some(Rect::new(0, 0, 320, 240)),
                },
            ),
            now,
        )
        .await;

    assert!(!settlement.refused(), "{:?}", settlement.outcome);
    assert_eq!(settlement.payload.len(), 1);
    match &settlement.payload[0] {
        limb_core::observation::Observation::Read { payload, .. } => {
            // Everything a remote screen says is data and never instruction.
            // The generation travels INSIDE the wrapper, because a payload
            // outlives the geometry it was read against: a screenshot read at
            // generation 7 and acted on at generation 8 is a misclick, and the
            // only place that can be noticed is where the two numbers sit side
            // by side.
            assert_eq!(payload.geometry_generation(), limb.generation());
            assert_eq!(payload.origin(), limb.id());
            assert_eq!(payload.bytes(), 6);
        }
        other => panic!("a pixel read is a Read observation: {other:?}"),
    }
}

#[tokio::test]
async fn a_limb_with_no_mirror_refuses_rather_than_returning_an_empty_frame() {
    // `00 R5` and `00 R6`. A perception layer that quietly gives you something
    // other than what you asked for produces agents that click in the wrong
    // place and nobody can reproduce it.
    let grant = watcher(
        "att_blind",
        &[Capability::View, Capability::Capture, Capability::Open],
    );
    let registry = LimbRegistry::new(PlaneConfig::default());
    let (handle, rx) = fake_session("desk.example", 64);
    std::mem::forget(rx);
    let limb = registry
        .attach(
            &grant,
            Attach {
                driver: Arc::new(TestLimb::desktop()),
                machine: MachineKey::endpoint(ProtocolKind::Vnc, "desk.example", 5900),
                slot: Slot::ATTACH,
                host: "desk.example".to_string(),
                handle,
                size: (1280, 720),
                frames: None,
            },
        )
        .expect("attached");
    limb.note_state(SessionState::Connected);

    let settlement = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::Capture {
                    form: CaptureForm::Full,
                    region: None,
                    scale: None,
                },
            ),
            LeaseInstant::from_millis(1_000),
        )
        .await;
    assert!(settlement.refused());
    assert!(settlement.payload.is_empty());
}

/// `00 R39b`, at the one place it can be observed from outside.
///
/// `Rect::union` is a BOUNDING BOX. Two eight pixel changes in opposite
/// corners of a 1280x720 desktop union to 1280x720, so a crop sized from the
/// union re-reads the whole screen to find 128 moved pixels, which is the
/// exact opposite of what `damage-crop` is for. The returned bytes look
/// identical either way, so what is asserted is what the mirror was ASKED
/// for.
#[tokio::test]
async fn a_damage_crop_of_two_opposite_corners_is_not_the_whole_framebuffer() {
    let mirror = Arc::new(StubMirror::with_damage(vec![
        Rect::new(0, 0, 8, 8),
        Rect::new(1272, 712, 8, 8),
    ]));
    let grant = watcher(
        "att_crop",
        &[Capability::View, Capability::Capture, Capability::Open],
    );
    let registry = LimbRegistry::new(PlaneConfig::default());
    let limb = attach_to(&registry, &grant, mirror.clone());

    let settlement = limb
        .dispatch(
            &grant,
            intent(
                &limb,
                &grant,
                IntentKind::Capture {
                    form: CaptureForm::DamageCrop,
                    region: None,
                    scale: None,
                },
            ),
            LeaseInstant::from_millis(1_000),
        )
        .await;
    assert!(!settlement.refused(), "{:?}", settlement.outcome);

    let whole = Rect::new(0, 0, 1280, 720);
    let asked = mirror.last_ask().expect(
        "a damage crop reads a rectangle, and a whole frame read is the union trap by another name",
    );
    assert_ne!(
        asked, whole,
        "the crop is the whole desktop, which is the union of the two corners and not a crop at all"
    );
    assert!(
        asked.area() * 8 < whole.area(),
        "{asked:?} is most of {whole:?}: a crop that expensive is the union trap surviving in a smaller form"
    );
}

/// `00 R10`, on the path where it used to be a constant.
///
/// The generation rides every perception response so a caller can tell a fresh
/// read from a stale one. `MirrorSource::damage` used to answer
/// `GeometryGeneration::FIRST` whatever the mirror was at, which is not a
/// generation, it is a number that cannot disagree with anything: the shell's
/// own `screen.damage` has always returned the mirror's real one, so the two
/// sources of the same fact said different things.
#[test]
fn a_damage_read_carries_the_mirrors_own_generation_and_a_stale_crop_is_refused() {
    use agent_plane::perception::MirrorSource;
    use remote_core::events::{DecodedRect, RectPayload};

    // Two resizes in, so `FIRST` is a wrong answer rather than an accidentally
    // right one.
    let current = GeometryGeneration::FIRST.next().next();
    let framebuffer = Rect::new(0, 0, 1280, 720);
    let mut slot = agent_perception::MirrorSlot::new(agent_perception::MirrorBudget::default());
    slot.attach(1280, 720, current, 0, Timestamp(0))
        .expect("a 1280x720 mirror is inside the default budget");
    let source = MirrorSource::new(
        slot,
        agent_perception::DamageLog::default(),
        agent_perception::ReaderId(1),
    );

    let painted = |x: u16, y: u16, w: u16, h: u16| DecodedRect {
        rect: Rect::new(x, y, w, h),
        payload: RectPayload::Rgba(vec![0x20; w as usize * h as usize * 4]),
    };

    // Prime the corner the crop will land in. A mirror starts as opaque black
    // and every read of a region nobody has painted refuses rather than
    // returning the black (`03 §9 A3`), so this is the full refresh a real
    // session sends on connect, cut down to what this test reads.
    source.apply(&[painted(0, 0, 160, 160)], framebuffer, Timestamp(1));
    source.damage().expect("the priming paint is damage too");

    source.apply(
        &[painted(0, 0, 8, 8), painted(1272, 712, 8, 8)],
        framebuffer,
        Timestamp(2),
    );
    let damage = source.damage().expect("two rectangles arrived");
    assert_eq!(damage.rects.len(), 2);
    assert_eq!(
        damage.generation, current,
        "the damage read reports the mirror's own generation and not a constant"
    );

    // And the crop chosen from that list is a crop, not the union of the two
    // corners.
    let frame = source
        .changed(&damage, None, Timestamp(3))
        .expect("the corner was primed, so the crop reads");
    let described: serde_json::Value =
        serde_json::from_slice(&frame.bytes).expect("the frame describes itself");
    let region = &described["image"]["space"]["region"];
    assert_eq!(region["x"], 0);
    assert_eq!(region["y"], 0);
    assert!(
        region["width"].as_u64().expect("a width") < 1280,
        "the crop spans the desktop: {region}"
    );
    assert_eq!(frame.generation, current);

    // A crop computed from changes observed two generations ago describes a
    // screen that no longer exists, and the fence is only worth anything
    // because the generation above is now the real one.
    let stale = Damage {
        generation: GeometryGeneration::FIRST,
        ..damage
    };
    let refused = source.changed(&stale, None, Timestamp(4)).expect_err(
        "a stale crop is refused rather than answered with a picture of somewhere else",
    );
    assert!(
        refused.0.contains("geometry generation"),
        "the refusal names the fence: {refused}"
    );
}
