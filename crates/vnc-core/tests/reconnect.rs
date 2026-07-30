//! Auto-retry and fast reconnect against a real socket (PRD/05 §6).
//!
//! These are the tests that protect the single most user-visible resilience
//! promise in the product: "if the connection is lost, auto-retry and reconnect
//! quickly", and its safety counterpart, "a wrong password does not enter a
//! retry loop".

mod common;

use std::time::{Duration, Instant};

use common::mock_server::*;
use common::*;

use vnc_core::types::{ClientCommand, QualityPreset, Rect, SessionEvent, SessionState};

const RED: Rgb = [255, 0, 0];
const TEAL: Rgb = [17, 136, 136];

/// Wait for a `Reconnecting` state, returning `(attempt, next_retry_ms, reason)`.
async fn wait_reconnecting(events: &mut Events, within: Duration) -> (u32, u64, String) {
    events
        .wait_state(within, "SessionState::Reconnecting", |s| match s {
            SessionState::Reconnecting {
                attempt,
                next_retry_ms,
                reason,
            } => Some((*attempt, *next_retry_ms, reason.clone())),
            _ => None,
        })
        .await
}

// ---------------------------------------------------------------------------
// The headline behaviour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_drop_mid_session_reconnects_automatically() {
    let rect = Rect::new(0, 0, 8, 8);
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![RectSpec::Raw { rect, colour: RED }])
            .drop_after_n_updates(1)
            .max_drops(1),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let (attempt, next_retry_ms, reason) = wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;
    assert_eq!(attempt, 1, "the first retry is attempt 1");
    assert_eq!(next_retry_ms, 100, "the configured first backoff");
    assert!(
        !reason.is_empty(),
        "the UI needs a reason to show in the scrim"
    );

    // ...and we come back up.
    events.wait_connected(DEFAULT_TIMEOUT).await;
    assert!(server.wait_for_connections(2, DEFAULT_TIMEOUT).await);

    // The reconnected session is fully functional again.
    let (rects, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(rects[0].rect, rect);
    handle.shutdown();
}

#[tokio::test]
async fn the_first_retry_happens_in_milliseconds_not_seconds() {
    // The shipping default policy: 250 ms first retry with ±20% jitter.
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![RectSpec::Raw {
                rect: Rect::new(0, 0, 4, 4),
                colour: RED,
            }])
            .drop_after_n_updates(1)
            .max_drops(1),
    )
    .await;

    let (handle, mut events) = spawn_session(options_default_policy(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let (attempt, next_retry_ms, _) = wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;
    let dropped_at = Instant::now();
    assert_eq!(attempt, 1);
    assert!(
        (200..=300).contains(&next_retry_ms),
        "first retry must be ~250 ms (±20% jitter), got {next_retry_ms} ms"
    );

    events.wait_connected(DEFAULT_TIMEOUT).await;
    let elapsed = dropped_at.elapsed();
    assert!(
        elapsed < Duration::from_millis(1500),
        "reconnect took {elapsed:?}; a blip must recover in well under a second"
    );
    handle.shutdown();
}

#[tokio::test]
async fn backoff_grows_across_failures_and_is_capped() {
    // Every connection is accepted and immediately closed, so the client keeps
    // failing and we can watch the whole backoff ladder.
    let server = MockServer::start(MockConfig::new().refuse_first_n_connections(20)).await;

    let mut opts = options(server.port()); // 100 ms -> x2 -> capped at 400 ms, no jitter
    opts.reconnect.max_attempts = Some(5);
    let (handle, mut events) = spawn_session(opts);

    let mut delays = Vec::new();
    for _ in 0..5 {
        let (attempt, ms, _) = wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;
        assert_eq!(attempt as usize, delays.len() + 1, "attempts count up");
        delays.push(ms);
    }
    assert_eq!(
        delays,
        vec![100, 200, 400, 400, 400],
        "exponential growth then a hard cap"
    );

    // max_attempts is honoured: the session stops instead of retrying forever.
    let can_retry = events
        .wait_state(DEFAULT_TIMEOUT, "terminal Disconnected", |s| match s {
            SessionState::Disconnected { can_retry, .. } => Some(*can_retry),
            _ => None,
        })
        .await;
    assert!(can_retry, "the UI may still offer a manual reconnect");
    handle.shutdown();
}

#[tokio::test]
async fn reconnect_now_interrupts_the_backoff_and_resets_the_attempt_counter() {
    // Two refusals, then success. The backoff is an hour, so only ReconnectNow
    // can move things along, and each one must reset the counter to zero.
    let server = MockServer::start(MockConfig::new().refuse_first_n_connections(2)).await;

    let mut opts = options(server.port());
    opts.reconnect.initial_delay_ms = 3_600_000;
    opts.reconnect.max_delay_ms = 3_600_000;
    opts.reconnect.multiplier = 1.0;
    let (handle, mut events) = spawn_session(opts);

    let (attempt, ms, _) = wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;
    assert_eq!(attempt, 1);
    assert_eq!(ms, 3_600_000);

    let clicked = Instant::now();
    send(&handle, ClientCommand::ReconnectNow).await;

    // The second failure must report attempt 1 again, the counter was reset,
    // otherwise the user would be pushed further up the backoff ladder for
    // pressing "Retry now".
    let (attempt2, _, _) = wait_reconnecting(&mut events, Duration::from_secs(5)).await;
    assert_eq!(attempt2, 1, "ReconnectNow must reset the attempt counter");
    assert!(
        clicked.elapsed() < Duration::from_secs(3),
        "ReconnectNow must not wait out the backoff"
    );

    send(&handle, ClientCommand::ReconnectNow).await;
    events.wait_connected(Duration::from_secs(5)).await;
    assert!(server.connection_count() >= 3);
    handle.shutdown();
}

#[tokio::test]
async fn refusing_the_first_two_connections_still_ends_in_a_connection() {
    let server = MockServer::start(MockConfig::new().refuse_first_n_connections(2)).await;

    let (handle, mut events) = spawn_session(options(server.port()));

    let (a1, _, _) = wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;
    assert_eq!(a1, 1);
    let (a2, _, _) = wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;
    assert_eq!(a2, 2);

    events.wait_connected(DEFAULT_TIMEOUT).await;
    assert_eq!(server.connection_count(), 3);
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Never retry on credentials
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_failure_stops_the_supervisor_dead() {
    let server = MockServer::start(
        MockConfig::new()
            .security(&[SEC_VNC_AUTH])
            .password("the-real-one"),
    )
    .await;

    // 10 ms backoff and unlimited attempts: a retry loop would be obvious.
    let mut opts = with_password(options(server.port()), "not-the-real-one");
    opts.reconnect.initial_delay_ms = 10;
    opts.reconnect.max_delay_ms = 10;
    opts.reconnect.max_attempts = None;

    let (handle, mut events) = spawn_session(opts);
    let can_retry = events
        .wait_state(DEFAULT_TIMEOUT, "terminal Disconnected", |s| match s {
            SessionState::Disconnected { can_retry, .. } => Some(*can_retry),
            _ => None,
        })
        .await;
    assert!(!can_retry);
    assert!(
        !events
            .states()
            .iter()
            .any(|s| matches!(s, SessionState::Reconnecting { .. })),
        "an auth rejection must never schedule a retry: {:?}",
        events.states()
    );

    events.drain_for(Duration::from_millis(600)).await;
    assert_eq!(
        server.connection_count(),
        1,
        "exactly one connection, a retry loop here locks accounts out"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancelling_during_a_backoff_wait_ends_the_session_promptly() {
    let server = MockServer::start(MockConfig::new().refuse_first_n_connections(20)).await;

    let mut opts = options(server.port());
    opts.reconnect.initial_delay_ms = 3_600_000;
    opts.reconnect.max_delay_ms = 3_600_000;
    let (handle, mut events) = spawn_session(opts);

    wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;

    let cancelled_at = Instant::now();
    handle.shutdown();
    events
        .wait_state(Duration::from_secs(3), "Disconnected after cancel", |s| {
            matches!(s, SessionState::Disconnected { .. }).then_some(())
        })
        .await;
    assert!(
        cancelled_at.elapsed() < Duration::from_secs(1),
        "cancellation must not wait out the backoff timer (took {:?})",
        cancelled_at.elapsed()
    );
}

#[tokio::test]
async fn disconnect_command_during_a_backoff_wait_stops_the_session() {
    let server = MockServer::start(MockConfig::new().refuse_first_n_connections(20)).await;

    let mut opts = options(server.port());
    opts.reconnect.initial_delay_ms = 3_600_000;
    opts.reconnect.max_delay_ms = 3_600_000;
    let (handle, mut events) = spawn_session(opts);

    wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;
    let sent_at = Instant::now();
    send(&handle, ClientCommand::Disconnect).await;
    events
        .wait_state(Duration::from_secs(3), "Disconnected", |s| {
            matches!(s, SessionState::Disconnected { .. }).then_some(())
        })
        .await;
    assert!(sent_at.elapsed() < Duration::from_secs(1));
}

// ---------------------------------------------------------------------------
// Session state preservation (PRD/05 §6.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quality_and_view_only_survive_a_reconnect() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let encodings_before = server.encoding_lists().len();

    send(&handle, ClientCommand::SetQuality(QualityPreset::Low)).await;
    send(&handle, ClientCommand::SetViewOnly(true)).await;

    // A quality change is expressed as a fresh SetEncodings carrying the new
    // JPEG-quality pseudo-encoding. (It does NOT re-send SetPixelFormat here:
    // this server has no Fence support, so a mid-stream format switch cannot be
    // synchronised, see `a_server_without_fence_never_gets_a_format_switch`.)
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| {
                let lists: Vec<&Vec<i32>> = r
                    .messages
                    .iter()
                    .filter_map(|m| match m {
                        ClientMessage::SetEncodings { encodings } => Some(encodings),
                        _ => None,
                    })
                    .collect();
                lists.len() > encodings_before
                    && lists
                        .last()
                        .is_some_and(|l| l.contains(&vnc_core::types::encoding::jpeg_quality(2)))
            })
            .await,
        "the quality change should have re-sent SetEncodings at the Low JPEG quality"
    );

    // Yank the connection from the server side.
    server.disconnect_now();
    wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;
    events.wait_connected(DEFAULT_TIMEOUT).await;
    assert!(server.wait_for_connections(2, DEFAULT_TIMEOUT).await);

    // The fresh connection must come up already in Low, not back at Auto.
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| {
                r.messages
                    .iter()
                    .filter_map(|m| match m {
                        ClientMessage::SetEncodings { encodings } => Some(encodings),
                        _ => None,
                    })
                    .next_back()
                    .is_some_and(|l| l.contains(&vnc_core::types::encoding::jpeg_quality(2)))
            })
            .await,
        "the reconnected session should re-apply the Low quality preset"
    );

    // View-only must also survive: input sent now must not reach the server.
    let pointer_before = server.pointer_events();
    send(
        &handle,
        ClientCommand::Pointer {
            x: 10,
            y: 10,
            button_mask: 1,
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        server.pointer_events(),
        pointer_before,
        "view-only must survive the reconnect and keep suppressing input"
    );
}

/// The safety property behind the user-visible bug "decoder error in tight:
/// decompressed data exceeds cap". Without Fence there is no way to know which
/// side of a `SetPixelFormat` an in-flight rectangle was encoded on, so the
/// client must never switch format mid-session on such a server, decoding a
/// 3-byte-TPIXEL rect as 1-byte palette makes the expected size 3x too small
/// and the inflate overruns.
#[tokio::test]
async fn a_server_without_fence_never_gets_a_format_switch() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // Let the handshake's own SetPixelFormat land before sampling, or the
    // baseline races it and the initial format looks like a mid-stream switch.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let baseline = server.pixel_formats().len();
    assert_eq!(
        baseline, 1,
        "exactly one format is set during the handshake"
    );

    // Low resolves to an 8bpp palette format, the switch that must NOT happen.
    send(&handle, ClientCommand::SetQuality(QualityPreset::Low)).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    let after = server.pixel_formats().len();
    assert_eq!(
        after, baseline,
        "a server without Fence must never receive a mid-stream SetPixelFormat"
    );
}

#[tokio::test]
async fn a_reconnect_starts_with_fresh_decoder_state() {
    // zlib rects are decoded through a stream that lives for the whole
    // connection. If a reconnect reused the old stream, the second connection's
    // rect (produced by a brand new deflate stream) would fail to inflate.
    let rect = Rect::new(0, 0, 16, 16);
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![RectSpec::Zlib { rect, colour: TEAL }])
            .drop_after_n_updates(1)
            .max_drops(1),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (first, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(first[0].rect, rect);

    wait_reconnecting(&mut events, DEFAULT_TIMEOUT).await;
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let (second, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(second[0].rect, rect);
    match &second[0].payload {
        vnc_core::types::RectPayload::Rgba(px) => {
            assert_eq!(&px[0..4], &[TEAL[0], TEAL[1], TEAL[2], 255]);
        }
        other => panic!("expected Rgba, got {other:?}"),
    }
    assert!(
        !events.any(|e| matches!(e, SessionEvent::Error(m) if m.contains("zlib"))),
        "no decode errors after the reconnect: {:?}",
        events.errors()
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Dead-peer detection (PRD/05 §6.4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_silent_peer_is_probed_with_a_fence() {
    // The server advertises Fence, sends one update, then goes silent without
    // closing the socket. The client must start probing rather than sitting
    // there forever.
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![
                RectSpec::FenceCapable,
                RectSpec::Raw {
                    rect: Rect::new(0, 0, 4, 4),
                    colour: RED,
                },
            ])
            .hang_after_n_updates(1),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    let probed = server
        .wait_until(Duration::from_secs(5), |r| {
            r.messages.iter().any(
                |m| matches!(m, ClientMessage::ClientFence { flags, .. } if flags & (1 << 31) != 0),
            )
        })
        .await;
    assert!(probed, "the client must send an RTT/liveness fence probe");
    handle.shutdown();
}

#[tokio::test]
async fn an_unanswered_probe_declares_the_peer_dead_and_reconnects() {
    // Slow by construction: the run loop gives an unanswered fence probe 10 s
    // before it declares the connection gone.
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![
                RectSpec::FenceCapable,
                RectSpec::Raw {
                    rect: Rect::new(0, 0, 4, 4),
                    colour: RED,
                },
            ])
            .hang_after_n_updates(1),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let (attempt, _, reason) = wait_reconnecting(&mut events, Duration::from_secs(25)).await;
    assert_eq!(attempt, 1);
    assert!(
        reason.contains("did not respond"),
        "expected a timeout reason, got {reason:?}"
    );
    // ...and it recovers on its own.
    events.wait_connected(Duration::from_secs(10)).await;
    assert!(server.connection_count() >= 2);
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Policy switches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_disabled_policy_never_reconnects() {
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![RectSpec::Raw {
                rect: Rect::new(0, 0, 4, 4),
                colour: RED,
            }])
            .drop_after_n_updates(1),
    )
    .await;

    let mut opts = options(server.port());
    opts.reconnect.enabled = false;
    let (handle, mut events) = spawn_session(opts);
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let can_retry = events
        .wait_state(DEFAULT_TIMEOUT, "terminal Disconnected", |s| match s {
            SessionState::Disconnected { can_retry, .. } => Some(*can_retry),
            _ => None,
        })
        .await;
    assert!(can_retry, "the UI may still offer a manual reconnect");
    events.drain_for(Duration::from_millis(400)).await;
    assert_eq!(server.connection_count(), 1);
    handle.shutdown();
}

#[tokio::test]
async fn the_shell_dropping_the_event_channel_tears_the_session_down() {
    // If nobody is listening any more the session must not keep a socket (and
    // a retry timer) alive forever.
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    drop(events);

    assert!(
        server
            .wait_until(Duration::from_secs(5), |r| r.messages.is_empty()
                || r.connections.len() == 1)
            .await
    );
    handle.shutdown();
}
