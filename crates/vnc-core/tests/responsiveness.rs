//! The run loop stays responsive while the server is streaming.
//!
//! THE BUG. With a video playing or a window animating on the remote screen,
//! input control felt enormously delayed. Three defects in the run loop all
//! pointed the same way, and each has a test here:
//!
//! 1. The main `select!` is `biased` with the socket read ahead of the
//!    command channel and the 1 s tick, and the reader sits behind a 128 KiB
//!    `BufReader`. Under a continuous update stream the read branch is ready
//!    on essentially every poll, so the tick never ran, and the tick is the
//!    only caller of `AutoTuner::observe` and the only place a quality change
//!    is applied. The client's one mechanism for reducing incoming load was
//!    switched off exactly when the load was highest.
//! 2. Input was serviced only after a DATA rect, so an update made of pseudo
//!    rects serviced none at all, and the `emit` of the finished update
//!    blocked the whole loop whenever the event consumer fell behind.
//! 3. ContinuousUpdates was switched on the moment the server advertised it
//!    and never switched off anywhere in the client, so the server
//!    free-ran and the client had no rate lever at all.

mod common;

use std::time::Duration;

use common::*;

use vnc_core::types::{ClientCommand, Rect, SessionEvent};

const RED: Rgb = [255, 0, 0];
const BLUE: Rgb = [0, 0, 255];

/// The mock desktop.
const MOCK_SCREEN: Rect = Rect {
    x: 0,
    y: 0,
    width: 640,
    height: 480,
};

// ---------------------------------------------------------------------------
// Hand-built wire fragments
//
// These tests need to push an update at a moment of their choosing, and to
// leave one OPEN across several client actions, which the mock's
// request-driven queue cannot express.
// ---------------------------------------------------------------------------

fn rect_header(out: &mut Vec<u8>, x: u16, y: u16, w: u16, h: u16, enc: i32) {
    out.extend_from_slice(&x.to_be_bytes());
    out.extend_from_slice(&y.to_be_bytes());
    out.extend_from_slice(&w.to_be_bytes());
    out.extend_from_slice(&h.to_be_bytes());
    out.extend_from_slice(&enc.to_be_bytes());
}

/// A FramebufferUpdate header using the 0xffff rect-count sentinel: the
/// update stays open until a LastRect arrives, so the test decides when it
/// ends and can act while the client is still inside its rect loop.
fn open_update_header() -> Vec<u8> {
    vec![0u8, 0u8, 0xff, 0xff]
}

/// One RichCursor (-239) pseudo rect, fully opaque: a pseudo rect that
/// produces a visible event, so a test can tell when the client has consumed
/// it and gone back to waiting for the next one.
fn cursor_rect(w: u16, h: u16, colour: Rgb) -> Vec<u8> {
    let mut out = Vec::new();
    rect_header(&mut out, 0, 0, w, h, -239);
    for _ in 0..(w as usize * h as usize) {
        out.extend_from_slice(&[colour[2], colour[1], colour[0], 0]);
    }
    let mask_row = (w as usize).div_ceil(8);
    out.extend(std::iter::repeat_n(0xffu8, mask_row * h as usize));
    out
}

/// LastRect (-224): closes an update opened with the sentinel.
fn last_rect() -> Vec<u8> {
    let mut out = Vec::new();
    rect_header(&mut out, 0, 0, 0, 0, -224);
    out
}

/// A complete one-rect Raw FramebufferUpdate.
fn raw_update(rect: Rect, colour: Rgb) -> Vec<u8> {
    let mut out = vec![0u8, 0u8];
    out.extend_from_slice(&1u16.to_be_bytes());
    rect_header(&mut out, rect.x, rect.y, rect.width, rect.height, 0);
    for _ in 0..rect.area() {
        out.extend_from_slice(&[colour[2], colour[1], colour[0], 0]);
    }
    out
}

fn pointer_events(server: &MockServer) -> usize {
    server.pointer_events().len()
}

// ---------------------------------------------------------------------------
// Defect 2: input keeps flowing through an update
// ---------------------------------------------------------------------------

/// REGRESSION: input was drained only after a DATA rect. An update made
/// entirely of pseudo rects took the `continue` above that drain and serviced
/// nothing, so for as long as such an update lasted the remote pointer was
/// frozen. Cursor shapes are pseudo rects, and a server that pushes them
/// during a drag sends a stream of them, which is precisely when the user is
/// moving the mouse.
#[tokio::test]
async fn input_flows_during_an_update_made_only_of_pseudo_rects() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // Open an update, put one cursor pseudo rect in it, and leave it open.
    let mut bytes = open_update_header();
    bytes.extend_from_slice(&cursor_rect(4, 4, RED));
    server.send_raw(bytes);
    // The cursor event proves the client has consumed that rect and is back
    // at the top of the rect loop, inside the update, waiting for more.
    events
        .wait(DEFAULT_TIMEOUT, "CursorUpdate", |e| {
            matches!(e, SessionEvent::CursorUpdate(_)).then_some(())
        })
        .await;

    let before = pointer_events(&server);
    for i in 0..3u16 {
        send(
            &handle,
            ClientCommand::Pointer {
                x: 10 + i,
                y: 20,
                button_mask: 0,
            },
        )
        .await;
    }

    // Keep the pseudo rects coming while we wait. Servicing input BETWEEN
    // rects is all any of this can do: a client parked on a socket read has
    // nothing to service input from, so the case that matters (and the case
    // the user hits) is a stream of them arriving, not one rect and silence.
    let mut arrived = false;
    for _ in 0..50 {
        server.send_raw(cursor_rect(4, 4, BLUE));
        if server.with_recorded(|r| {
            r.messages
                .iter()
                .filter(|m| matches!(m, ClientMessage::PointerEvent { .. }))
                .count()
                >= before + 3
        }) {
            arrived = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        arrived,
        "pointer events must reach the server while an all-pseudo update streams"
    );

    // Close the update so the session unwinds through the normal path.
    server.send_raw(last_rect());
    handle.shutdown();
}

/// REGRESSION: the `emit` of a finished update awaits room in the event
/// channel, and that await parked the entire run loop. A renderer that falls
/// behind (which is what a video playing on the remote screen does to it)
/// therefore held every queued keystroke and pointer move behind a frame
/// nobody was ready to look at.
#[tokio::test]
async fn input_flows_while_the_event_consumer_is_stalled() {
    let server = MockServer::start(MockConfig::new()).await;
    // Two slots, and nothing reads them after the connect: the third update
    // below leaves the session waiting for room that never comes.
    let (handle, mut events) = spawn_session_with_event_capacity(options(server.port()), 2);
    events.wait_connected(DEFAULT_TIMEOUT).await;

    for _ in 0..4 {
        server.send_raw(raw_update(Rect::new(0, 0, 8, 8), BLUE));
    }
    // Nothing observable happens when the channel fills (that is the point:
    // the consumer is gone), so give the session time to reach the stall
    // before asking anything of it.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let before = pointer_events(&server);
    for i in 0..3u16 {
        send(
            &handle,
            ClientCommand::Pointer {
                x: 100 + i,
                y: 50,
                button_mask: 0,
            },
        )
        .await;
    }
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| r
                .messages
                .iter()
                .filter(|m| matches!(m, ClientMessage::PointerEvent { .. }))
                .count()
                >= before + 3)
            .await,
        "pointer events must reach the server while the event consumer is stalled"
    );

    // `events` must outlive the assertions: dropping it closes the channel,
    // which would release the stall this test depends on.
    drop(events);
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Defect 3: continuous updates are not a one-way door
// ---------------------------------------------------------------------------

/// A server that ends continuous updates of its own accord hands the rate
/// back to the client, and the pipeline must resume with EXACTLY one
/// outstanding request: none and the picture never updates again, two and the
/// server encodes the screen twice for nothing.
#[tokio::test]
async fn the_request_pipeline_resumes_with_one_request_when_continuous_updates_end() {
    // No queued updates: every update in this test is pushed unprompted, the
    // way a continuous-updates server sends them, so nothing the client asks
    // for is ever answered and the request count says exactly what the client
    // did rather than what the mock's queue provoked.
    let server = MockServer::start(MockConfig::new().advertise_continuous_updates()).await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // The client answers the advertisement by switching continuous updates on.
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| r.messages.iter().any(|m| matches!(
                m,
                ClientMessage::EnableContinuousUpdates { enable: true }
            )))
            .await,
        "the client should enable continuous updates when the server offers them"
    );

    // Two pushes: the first answers the priming request, the second arrives
    // with nothing outstanding at all, which is the state a free-running
    // stream leaves the client in.
    server.send_raw(raw_update(Rect::new(0, 0, 8, 8), RED));
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    server.send_raw(raw_update(Rect::new(8, 0, 8, 8), BLUE));
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    events.drain_for(Duration::from_millis(200)).await;

    // Full-screen incremental requests only. The client's own priming request
    // is non-incremental, and the round-trip probe asks for a single pixel;
    // neither is the pipeline.
    let pipeline_requests = |r: &Recorded| {
        r.messages
            .iter()
            .filter(|m| {
                matches!(
                    m,
                    ClientMessage::FramebufferUpdateRequest {
                        incremental: true,
                        rect,
                    } if *rect == MOCK_SCREEN
                )
            })
            .count()
    };
    assert_eq!(
        server.with_recorded(pipeline_requests),
        0,
        "nothing should be requested while the server is free-running"
    );

    // The server stops pushing.
    server.send_raw(vec![150u8]);
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| pipeline_requests(r) >= 1)
            .await,
        "the client must start requesting again once the stream ends"
    );
    // Long enough that a second request provoked by the transition would have
    // gone out. Nothing answers the first one, so nothing may follow it.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        server.with_recorded(pipeline_requests),
        1,
        "exactly one request may be outstanding across the transition"
    );
    handle.shutdown();
}

/// REGRESSION, and the defect at the root of the complaint: under a
/// continuous update stream the 1 s tick never ran.
///
/// The main `select!` is `biased` with the socket read first, and the reader
/// sits behind a 128 KiB `BufReader`, so while the server streams there is
/// always a buffered byte waiting and the tick branch is never polled
/// (`MissedTickBehavior::Skip` then throws the missed ticks away rather than
/// catching them up). The tick is the ONLY caller of `AutoTuner::observe` and
/// the only place an Auto quality change is applied, so the client's single
/// mechanism for reducing incoming load was switched off exactly when the
/// load was highest.
///
/// Stats events are the visible proxy: one per tick, and none at all while
/// the tick is starved.
#[tokio::test]
async fn the_observation_tick_keeps_running_under_a_continuous_flood() {
    let server = MockServer::start(
        MockConfig::new()
            // Streamed with no gap at all, which is the condition that
            // starved the tick: the reader is then ready on every poll of the
            // biased select and the later branches never run. Only a quarter
            // of the screen, because the point is a socket that is never
            // empty rather than the largest possible number of megabytes
            // through the loopback and the event channel.
            .flood(
                vec![RectSpec::Raw {
                    rect: Rect::new(0, 0, 320, 240),
                    colour: RED,
                }],
                Duration::ZERO,
            ),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // The flood produces events far faster than any assertion loop, so the
    // consumer has to keep draining: a full channel is a different failure
    // (see the stalled-consumer test above) and would mask this one.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut ticks = 0usize;
    while tokio::time::Instant::now() < deadline && ticks < 3 {
        events.drain_for(Duration::from_millis(100)).await;
        // Framebuffer events carry a megabyte of pixels each; only the stats
        // are worth keeping.
        events.seen.retain(|e| matches!(e, SessionEvent::Stats(_)));
        ticks = events.seen.len();
    }
    assert!(
        ticks >= 3,
        "the stats tick must keep running while the server streams: saw {ticks}"
    );

    // And the duty cycle it reports must actually show the saturation, since
    // that reading is what the tuner acts on.
    let busiest = events
        .seen
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Stats(s) => Some(s.server_duty_cycle),
            _ => None,
        })
        .fold(0.0f32, f32::max);
    assert!(
        busiest > 0.5,
        "a flooded session should report a high duty cycle, got {busiest}"
    );
    handle.shutdown();
}
