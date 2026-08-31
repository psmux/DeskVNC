//! The acceptance criteria of `03 §9` and the rulings they come from, as
//! tests.
//!
//! Each test below is named for the failure it prevents rather than for the
//! function it calls, because the failures are the point: a mirror that goes
//! stale in the moving region, a budget that quietly gives back something
//! smaller, a damage union that turns two moved pixels into a 4K read, a
//! coordinate that is half a pixel out on a triple head, and a screenshot of a
//! screen that no longer exists.

use agent_perception::{
    mirror_bytes, mirror_safety, BudgetRefused, DamageLog, FrameCoverage, ImageSpace, MirrorBudget,
    MirrorSafety, MirrorSlot, PerceptionError, Read, ReadRequest, ReaderId, Rung, ScreenFacts,
    StaleReason,
};
use limb_core::fence::{GeometryFence, GeometryGeneration};
use limb_core::observation::Timestamp;
use remote_core::events::{DecodedRect, RectPayload};
use remote_core::geometry::Rect;

fn rgba(x: u16, y: u16, w: u16, h: u16, colour: [u8; 4]) -> DecodedRect {
    DecodedRect {
        rect: Rect::new(x, y, w, h),
        payload: RectPayload::Rgba(colour.repeat(w as usize * h as usize)),
    }
}

fn h264(x: u16, y: u16, w: u16, h: u16) -> DecodedRect {
    DecodedRect {
        rect: Rect::new(x, y, w, h),
        payload: RectPayload::H264 {
            data: vec![0, 0, 0, 1, 0x65, 0x88],
            flags: 0,
            context_id: 0,
            reset: false,
            keyframe: true,
        },
    }
}

/// A mirror with every tile painted once, which is what a `Refresh` produces.
fn primed(width: u16, height: u16) -> (MirrorSlot, DamageLog) {
    let mut slot = MirrorSlot::default();
    slot.attach(
        width,
        height,
        GeometryGeneration::FIRST,
        0,
        Timestamp(1_000),
    )
    .expect("within the default budget");
    slot.apply(&[rgba(0, 0, width, height, [200, 30, 30, 255])]);
    (slot, DamageLog::default())
}

// ---------------------------------------------------------------------------
// 00 R5, the memory arithmetic and the refusal.
// ---------------------------------------------------------------------------

/// The table `03 §2.2` publishes and four documents quote.
#[test]
fn memory_is_exactly_what_the_document_says_at_the_four_resolutions() {
    assert_eq!(mirror_bytes(1280, 720), 3_686_400);
    assert_eq!(mirror_bytes(1920, 1080), 8_294_400);
    assert_eq!(mirror_bytes(2560, 1440), 14_745_600);
    assert_eq!(mirror_bytes(3840, 2160), 33_177_600);

    // The scaled figures the pane work makes routine, in MiB.
    let mib = |bytes: u64| bytes as f64 / (1024.0 * 1024.0);
    assert!((mib(mirror_bytes(1920, 1080) * 12) - 94.9).abs() < 0.1);
    assert!((mib(mirror_bytes(3840, 2160) * 12) - 379.7).abs() < 0.1);
}

/// `00 R5`: over the per session budget it refuses, and it does not allocate
/// something smaller and call it an answer.
#[test]
fn a_mirror_over_the_pixel_budget_is_an_error_and_not_a_smaller_image() {
    let mut slot = MirrorSlot::default();
    let refused = slot
        .attach(4096, 2560, GeometryGeneration::FIRST, 0, Timestamp(0))
        .expect_err("10.5 megapixels is over the 8.3 megapixel default");

    match refused {
        PerceptionError::Budget(BudgetRefused::Pixels { pixels, budget, .. }) => {
            assert_eq!(pixels, 4096 * 2560);
            assert_eq!(budget, agent_perception::DEFAULT_MAX_MIRROR_PIXELS);
        }
        other => panic!("expected a pixel budget refusal, got {other:?}"),
    }
    // The whole ruling in one assertion: nothing was allocated, so there is no
    // smaller image anywhere for a caller to be handed by mistake.
    assert!(!slot.is_attached());
    assert_eq!(slot.bytes(), 0);
    assert!(matches!(
        slot.read(
            &ReadRequest::frame(),
            &mut DamageLog::default(),
            Timestamp(0)
        ),
        Err(PerceptionError::NoMirror)
    ));
}

/// The total ceiling is the one that catches twelve 4K sessions.
#[test]
fn the_total_budget_refuses_the_fourth_four_k_mirror() {
    let mut slot = MirrorSlot::default();
    let three_already_out = mirror_bytes(3840, 2160) * 3;
    let refused = slot
        .attach(
            3840,
            2160,
            GeometryGeneration::FIRST,
            three_already_out,
            Timestamp(0),
        )
        .expect_err("96 MiB holds three 4K mirrors and not four");
    assert!(matches!(
        refused,
        PerceptionError::Budget(BudgetRefused::TotalBytes { .. })
    ));
    assert!(!slot.is_attached());
}

/// `00 R5`: freed after an idle timeout with no reads.
#[test]
fn an_idle_mirror_is_freed_and_a_read_afterwards_says_so() {
    let budget = MirrorBudget::default();
    let (mut slot, mut damage) = primed(320, 240);
    assert!(slot.is_attached());

    // A read keeps it alive.
    let just_before = Timestamp(1_000 + budget.idle_timeout_ms - 1);
    assert_eq!(slot.reap(just_before), 0);
    assert!(slot.is_attached());
    slot.read(&ReadRequest::frame(), &mut damage, just_before)
        .expect("primed");

    // The timer runs from the last read and not from the attach.
    assert_eq!(slot.reap(Timestamp(just_before.0 + 1)), 0);
    let freed = slot.reap(Timestamp(just_before.0 + budget.idle_timeout_ms));
    assert_eq!(freed, mirror_bytes(320, 240));
    assert!(!slot.is_attached());
    assert_eq!(slot.bytes(), 0);

    assert!(matches!(
        slot.read(&ReadRequest::frame(), &mut damage, Timestamp(999_999)),
        Err(PerceptionError::NoMirror)
    ));
}

// ---------------------------------------------------------------------------
// 00 R6, the H.264 hazard. The tests this crate exists for.
// ---------------------------------------------------------------------------

/// The predicate the plane negotiates with, before a byte is allocated.
#[test]
fn h264_advertised_by_default_is_reported_as_unsafe_to_mirror() {
    // The shipping default: the client advertises H.264 to every server except
    // Apple Screen Sharing, and Medium, Auto and Low all allow it.
    assert_eq!(mirror_safety(true, true), MirrorSafety::H264Advertised);
    // What `00 R6` asks the plane to arrange before attaching.
    assert!(mirror_safety(false, true).is_safe());
    // Apple Screen Sharing, which never offered it.
    assert!(mirror_safety(true, false).is_safe());
}

/// **The one that matters.** An H.264 rect poisons its region, and no later
/// read can hand those pixels back as if they were current.
#[test]
fn an_h264_rect_poisons_the_region_and_no_read_returns_stale_pixels_silently() {
    let (mut slot, mut damage) = primed(320, 240);
    let mirror = slot.get_mut().unwrap();
    assert!(mirror.is_primed());

    // The screen keeps moving in one window, and the server encodes it as
    // H.264 because that is what the default preset negotiated.
    mirror.apply(&[h264(64, 64, 64, 64)]);

    let moving = Rect::new(64, 64, 64, 64);
    let elsewhere = Rect::new(0, 0, 32, 32);
    let now = Timestamp(2_000);

    // Refusing is the default, and the refusal names the repair.
    match slot.read(&ReadRequest::region(moving), &mut damage, now) {
        Err(PerceptionError::Stale { stale_regions, .. }) => {
            assert!(!stale_regions.is_empty());
            assert!(stale_regions.iter().all(|s| s.why == StaleReason::H264));
        }
        other => panic!("a poisoned region must not be served: {other:?}"),
    }

    // A whole frame read is refused for the same reason, so an agent cannot
    // reach the stale pixels by asking a different question.
    assert!(matches!(
        slot.read(&ReadRequest::frame(), &mut damage, now),
        Err(PerceptionError::Stale { .. })
    ));

    // Annotating returns the frame WITH the region named. The pixels really
    // are the old ones, which is the whole hazard: without the annotation this
    // read is a confident lie about the only part of the screen that moved.
    let annotated = slot
        .read(
            &ReadRequest::region(moving).annotating_stale(),
            &mut damage,
            now,
        )
        .expect("annotating is the other half of R6");
    match annotated {
        Read::Frame(frame) => match &frame.coverage {
            FrameCoverage::Partial { stale_regions } => {
                assert_eq!(stale_regions.len(), 1);
                assert_eq!(stale_regions[0].rect, moving);
                assert_eq!(stale_regions[0].why, StaleReason::H264);
            }
            FrameCoverage::Complete => panic!("this frame is not complete and must not say it is"),
        },
        Read::Unchanged { .. } => panic!("a region read is never unchanged"),
    }
    let pixels = slot.get().unwrap().as_rgba();
    let at = |x: usize, y: usize| &pixels[(y * 320 + x) * 4..(y * 320 + x) * 4 + 4];
    assert_eq!(
        at(80, 80),
        &[200, 30, 30, 255],
        "the stale pixels are there"
    );

    // Everywhere else is untouched and still answers normally.
    let clean = slot
        .read(&ReadRequest::region(elsewhere), &mut damage, now)
        .expect("a clean region is still readable");
    match clean {
        Read::Frame(frame) => assert!(frame.coverage.is_complete()),
        Read::Unchanged { .. } => panic!("a region read is never unchanged"),
    }

    // And the count is visible for `session.stats` (`03 §9 A6`).
    assert_eq!(slot.get().unwrap().signals().h264_rects(), 1);
}

/// Scrolling a poisoned region drags the poison with it. A per rect check
/// would see a `CopyRect`, which this crate composites perfectly, and call the
/// destination fresh.
#[test]
fn a_copy_rect_from_a_poisoned_source_poisons_its_destination() {
    let (mut slot, mut damage) = primed(320, 240);
    let mirror = slot.get_mut().unwrap();
    mirror.apply(&[h264(0, 0, 32, 32)]);
    mirror.apply(&[DecodedRect {
        rect: Rect::new(128, 128, 32, 32),
        payload: RectPayload::CopyRect { src_x: 0, src_y: 0 },
    }]);
    assert!(matches!(
        slot.read(
            &ReadRequest::region(Rect::new(128, 128, 32, 32)),
            &mut damage,
            Timestamp(3_000)
        ),
        Err(PerceptionError::Stale { .. })
    ));
}

/// `03 §9 A3`: a mirror attached to a session that has been connected for ten
/// minutes is black, and it says priming rather than returning the black.
#[test]
fn a_priming_mirror_refuses_rather_than_returning_its_opaque_black() {
    let mut slot = MirrorSlot::default();
    slot.attach(320, 240, GeometryGeneration::FIRST, 0, Timestamp(0))
        .unwrap();
    let mut damage = DamageLog::default();
    match slot.read(&ReadRequest::frame(), &mut damage, Timestamp(1)) {
        Err(err @ PerceptionError::Priming { .. }) => {
            // Priming resolves on its own; staleness does not. An agent that
            // cannot tell them apart will wait forever or give up too early.
            assert!(err.is_transient());
            assert_eq!(err.as_str(), "PRIMING");
        }
        other => panic!("expected a priming refusal, got {other:?}"),
    }
    assert!(!slot.get().unwrap().is_primed());
}

// ---------------------------------------------------------------------------
// 00 R39b, the union trap.
// ---------------------------------------------------------------------------

/// Two changes in opposite corners union to the whole screen. The default
/// perception call must not read the whole screen because of it.
#[test]
fn two_opposite_corner_changes_do_not_produce_a_full_screen_read() {
    let (mut slot, mut damage) = primed(1920, 1080);
    let reader = ReaderId(1);
    damage.subscribe(reader);

    // A clock ticking in the bottom right corner and a dialog opening in the
    // top left, which is `00 R39b`'s example.
    let clock_and_dialog = [
        rgba(1904, 1064, 8, 8, [1, 1, 1, 255]),
        rgba(4, 4, 8, 8, [2, 2, 2, 255]),
    ];
    damage.record(
        &clock_and_dialog,
        Rect::new(0, 0, 1920, 1080),
        Timestamp(5_000),
    );

    // The trap, demonstrated first so the assertion below has something to be
    // measured against: the bounding box really is very nearly the whole
    // desktop, and sizing a read from it would move 8 MB of pixels to look at
    // two 8x8 squares.
    let union = damage.peek(reader).bounding_box();
    assert_eq!(union, Rect::new(4, 4, 1908, 1068));
    assert!(union.area() * 100 > Rect::new(0, 0, 1920, 1080).area() * 98);

    let read = slot
        .read(&ReadRequest::change(reader), &mut damage, Timestamp(5_001))
        .expect("primed and something changed");
    let frame = match read {
        Read::Frame(f) => f,
        Read::Unchanged { .. } => panic!("two rectangles changed"),
    };
    assert_eq!(frame.rung, Rung::Change);

    let region = frame.image.space.region;
    let screen = Rect::new(0, 0, 1920, 1080).area();
    assert!(
        region.area() * 20 < screen,
        "a crop of {region:?} is not a full screen read"
    );
    // The change it did not cover is reported rather than dropped.
    assert_eq!(frame.remaining_changes, 1);
    assert_eq!(frame.damage.len(), 1);
    // Scale 1.0, so a coordinate read off it needs only the offset added.
    assert!(frame.image.space.is_unscaled());
}

/// Nothing changed is an answer, not an error.
#[test]
fn a_change_read_with_nothing_changed_is_an_answer() {
    let (mut slot, mut damage) = primed(320, 240);
    let reader = ReaderId(9);
    damage.subscribe(reader);
    match slot.read(&ReadRequest::change(reader), &mut damage, Timestamp(10)) {
        Ok(Read::Unchanged { generation, .. }) => {
            assert_eq!(generation, GeometryGeneration::FIRST)
        }
        other => panic!("expected an unchanged answer, got {other:?}"),
    }
}

/// Two readers do not consume each other's deltas.
#[test]
fn one_reader_taking_a_delta_does_not_steal_it_from_another() {
    let mut damage = DamageLog::default();
    let (a, b) = (ReaderId(1), ReaderId(2));
    damage.subscribe(a);
    damage.subscribe(b);
    damage.record(
        &[rgba(0, 0, 8, 8, [0, 0, 0, 255])],
        Rect::new(0, 0, 320, 240),
        Timestamp(1),
    );
    assert_eq!(damage.take(a).rects.len(), 1);
    assert_eq!(damage.take(b).rects.len(), 1, "b's delta was not stolen");
    assert!(damage.take(a).is_empty());
}

/// A refusal must not eat the changes it refused to show.
#[test]
fn a_refused_change_read_leaves_the_reader_where_it_was() {
    let (mut slot, mut damage) = primed(320, 240);
    let reader = ReaderId(3);
    damage.subscribe(reader);
    slot.get_mut().unwrap().apply(&[h264(0, 0, 64, 64)]);
    damage.record(
        &[Rect::new(0, 0, 64, 64)]
            .iter()
            .map(|r| rgba(r.x, r.y, r.width, r.height, [3, 3, 3, 255]))
            .collect::<Vec<_>>(),
        Rect::new(0, 0, 320, 240),
        Timestamp(20),
    );
    assert!(slot
        .read(&ReadRequest::change(reader), &mut damage, Timestamp(21))
        .is_err());
    assert_eq!(
        damage.peek(reader).rects.len(),
        1,
        "the change is still there to be read once the region is trustworthy"
    );
}

/// `03 §9 A5`: damage costs no mirror and no allocation.
#[test]
fn damage_needs_no_mirror_at_all() {
    let slot = MirrorSlot::default();
    let mut damage = DamageLog::default();
    let reader = ReaderId(4);
    damage.subscribe(reader);
    damage.record(
        &[rgba(10, 10, 4, 4, [0, 0, 0, 255])],
        Rect::new(0, 0, 320, 240),
        Timestamp(1),
    );
    assert_eq!(damage.take(reader).rects.len(), 1);
    assert!(!slot.is_attached());
    assert_eq!(slot.bytes(), 0);
    assert!(!Rung::Damage.needs_mirror());
    assert!(!Rung::StateAndStats.needs_mirror());
}

// ---------------------------------------------------------------------------
// 00 R43, the half pixel.
// ---------------------------------------------------------------------------

/// At scale 1.0 the transform is addition, exactly, at every pixel.
#[test]
fn the_transform_is_exact_at_scale_one() {
    let space = ImageSpace::unscaled(Rect::new(1920, 340, 400, 200));
    for mx in 0..400u32 {
        for my in [0u32, 99, 199] {
            let p = space.to_framebuffer(mx, my).unwrap();
            assert_eq!((p.x, p.y), (1920 + mx as u16, 340 + my as u16));
        }
    }
}

/// And it round trips at every scale a downscale can produce.
#[test]
fn the_transform_round_trips_at_every_scale() {
    for (src, out) in [(1920u32, 1456u32), (3840, 1456), (800, 400), (1000, 333)] {
        let scale = f64::from(out) / f64::from(src);
        let space = ImageSpace {
            region: Rect::new(64, 32, src as u16, 64),
            width: out,
            height: 64,
            scale,
        };
        for mx in 0..out {
            let fb = space.to_framebuffer(mx, 0).unwrap();
            assert!(
                fb.x >= 64 && u32::from(fb.x) < 64 + src,
                "{mx} at scale {scale} left the region"
            );
            assert_eq!(
                space.to_image(fb).unwrap().0,
                mx,
                "{mx} at scale {scale} did not round trip"
            );
        }
    }
}

/// The bias itself, which is what would be dropped by a careless rewrite.
#[test]
fn dropping_the_half_pixel_would_change_the_answer() {
    let space = ImageSpace {
        region: Rect::new(0, 0, 5760, 1080),
        width: 1456,
        height: 273,
        scale: 1456.0 / 5760.0,
    };
    let with_bias = space.to_framebuffer(1000, 0).unwrap().x;
    let without_bias = (1000.0 / (1456.0 / 5760.0)) as u16;
    assert_eq!(with_bias, 3958);
    assert_eq!(without_bias, 3956);
    // Two pixels on a triple head, at every coordinate, in the same direction.
    // Small enough to survive review and large enough to miss a scrollbar.
    assert_eq!(with_bias - without_bias, 2);
}

// ---------------------------------------------------------------------------
// 00 R10, the geometry fence.
// ---------------------------------------------------------------------------

/// A read computed against a screen that no longer exists is refused.
#[test]
fn a_read_fenced_against_a_stale_generation_is_rejected() {
    let (mut slot, mut damage) = primed(320, 240);
    let mut fence = GeometryFence::new();
    assert_eq!(fence.current(), GeometryGeneration::FIRST);

    // Fenced at the current generation, it answers.
    assert!(slot
        .read(
            &ReadRequest::frame().fenced_at(fence.current()),
            &mut damage,
            Timestamp(100)
        )
        .is_ok());

    let (generation, _why) = fence.changed(limb_core::fence::GeometryChange::DesktopResize {
        width: 640,
        height: 480,
    });
    slot.resize(640, 480, generation, slot.bytes()).unwrap();

    match slot.read(
        &ReadRequest::frame().fenced_at(GeometryGeneration::FIRST),
        &mut damage,
        Timestamp(200),
    ) {
        Err(PerceptionError::Geometry(rejected)) => {
            assert_eq!(
                rejected,
                limb_core::fence::GeometryRejected::Stale {
                    fenced_at: GeometryGeneration::FIRST,
                    current: generation,
                }
            );
        }
        other => panic!("expected a geometry rejection, got {other:?}"),
    }

    // And the resize did not carry the old coverage across, so an unfenced
    // read of the new geometry is priming rather than a picture of the old
    // desktop stretched into the new one.
    assert!(matches!(
        slot.read(&ReadRequest::frame(), &mut damage, Timestamp(201)),
        Err(PerceptionError::Priming { .. })
    ));
}

// ---------------------------------------------------------------------------
// 00 R34 and R42, availability. 03 §9 A8, self describing responses.
// ---------------------------------------------------------------------------

/// Every response carries what a coordinate read off it needs, and a signal
/// the server never offered is absent rather than defaulted.
#[test]
fn a_response_is_self_describing_and_an_absent_signal_has_no_value_key() {
    let (mut slot, mut damage) = primed(320, 240);
    slot.get_mut()
        .unwrap()
        .layout_changed(ScreenFacts::absent(), GeometryGeneration::FIRST);
    let read = slot
        .read(&ReadRequest::frame(), &mut damage, Timestamp(7))
        .unwrap();
    let frame = match read {
        Read::Frame(f) => f,
        Read::Unchanged { .. } => panic!("a frame read is never unchanged"),
    };

    let json: serde_json::Value = serde_json::to_value(&*frame).unwrap();
    for key in [
        "space",
        "coverage",
        "geometry_generation",
        "captured_at",
        "screens",
        "primary_known",
        "rung",
    ] {
        assert!(json.get(key).is_some(), "a response without {key} is a bug");
    }
    assert!(json["image"]["space"]["scale"].is_number());
    assert_eq!(json["coverage"], "complete");
    assert_eq!(json["space"]["width"], 320);

    // `00 R42` (WA-3): no `value` key unless the availability is live, so a
    // consumer that forgets to check gets a missing key and not a plausible
    // empty list of monitors.
    assert_eq!(json["screens"]["availability"], "absent");
    assert!(json["screens"].get("value").is_none());
    assert!(json["screens"]["reason"].is_string());
    assert_eq!(json["primary_known"], false);
}

/// `00 R39a`: the content hint does not reach the seam, so it is absent and
/// the plane never guesses.
#[test]
fn the_content_hint_is_absent_and_every_rgba_rect_is_unknown() {
    use agent_perception::{ContentHint, PerceptionSignals};
    use limb_core::availability::{SignalReport, SignalState};

    let mut signals = PerceptionSignals::new();
    signals.observe(&[
        rgba(0, 0, 4, 4, [0, 0, 0, 255]),
        DecodedRect {
            rect: Rect::new(8, 8, 4, 4),
            payload: RectPayload::CopyRect { src_x: 0, src_y: 0 },
        },
    ]);

    let mut report = SignalReport::default();
    signals.fill(&mut report);
    assert!(matches!(report.content_hint, SignalState::Absent { .. }));
    assert!(report.copy_rect.is_live());

    assert_eq!(
        ContentHint::of(&RectPayload::Rgba(vec![0; 16])),
        ContentHint::Unknown
    );

    // `00 R42` (WA-4): window structure is an explicit absence with no value
    // of the type that says anything else.
    let json = serde_json::to_value(report.window_structure).unwrap();
    assert_eq!(json["availability"], "absent");
    assert!(json.get("value").is_none());
}
