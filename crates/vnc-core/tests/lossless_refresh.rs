//! Auto lossless refresh (PRD/09 §3.2): a lossily-painted region is
//! re-fetched sharp once the screen settles, then the adaptive encodings are
//! restored.
//!
//! REGRESSION: the sharp SetEncodings, the non-incremental request, and the
//! restore-to-adaptive SetEncodings used to go out back to back. A server
//! that processes SetEncodings synchronously but queues the update request
//! applies the adaptive (lossy) list again before it ever answers the sharp
//! request, so the "sharp" refresh comes back lossy and immediately
//! re-queues, repeating every ALR_COOLDOWN forever on an otherwise idle
//! screen. The fix withholds the restore until the update ANSWERING the
//! refresh request has been fully consumed.

mod common;

use std::time::Duration;

use common::*;

use vnc_core::types::{encoding, Rect};

/// Hand-build a one-rect FramebufferUpdate carrying an Open H.264 (50) rect
/// with an empty (control-message) payload: enough to exercise the
/// "painted lossily" bookkeeping without needing a real encoded frame, and
/// without touching `tests/common/mock_server.rs`'s private encoder helpers.
fn raw_h264_update(rect: Rect) -> Vec<u8> {
    let mut out = vec![0u8, 0u8]; // FramebufferUpdate, padding
    out.extend_from_slice(&1u16.to_be_bytes()); // one rect
    out.extend_from_slice(&rect.x.to_be_bytes());
    out.extend_from_slice(&rect.y.to_be_bytes());
    out.extend_from_slice(&rect.width.to_be_bytes());
    out.extend_from_slice(&rect.height.to_be_bytes());
    out.extend_from_slice(&encoding::OPEN_H264.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // data length 0
    out.extend_from_slice(&0u32.to_be_bytes()); // flags 0
    out
}

fn set_encodings_count(server: &MockServer) -> usize {
    server
        .messages()
        .into_iter()
        .filter(|m| matches!(m, ClientMessage::SetEncodings { .. }))
        .count()
}

#[tokio::test]
async fn the_adaptive_encodings_are_restored_only_after_the_refresh_is_answered() {
    let rect = Rect::new(0, 0, 4, 4);
    // Two queued updates: the priming one, and the one the client's own
    // pipelining immediately requests next (see `handle_framebuffer_update`).
    // Both painted with H.264 (counts as lossy, see item 4(b)), so
    // `lossy_damage` is non-empty by the time the queue runs dry and the
    // session goes idle.
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![RectSpec::H264 {
                rect,
                flags: 0,
                data: vec![],
            }])
            .update(vec![RectSpec::H264 {
                rect,
                flags: 0,
                data: vec![],
            }]),
    )
    .await;

    let (_handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await; // priming update
    events.wait_framebuffer(DEFAULT_TIMEOUT).await; // the auto-pipelined one

    // The mock's update queue is now exhausted: no further updates arrive
    // automatically, so the idle timer can run out and nothing but our own
    // `send_raw` calls below will produce another update.
    //
    // Wait specifically for a SetEncodings list that lacks H.264: the
    // connection's OWN priming request is already non-incremental (see
    // `connection::run_once`), so watching for "a non-incremental request"
    // alone would match that instead of the refresh.
    let baseline = set_encodings_count(&server);
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| {
                r.messages
                    .iter()
                    .filter_map(|m| match m {
                        ClientMessage::SetEncodings { encodings } => Some(encodings),
                        _ => None,
                    })
                    .nth(baseline)
                    .is_some_and(|l| !l.contains(&encoding::OPEN_H264))
            })
            .await,
        "the lossless refresh should have sent a sharp (no-H.264) SetEncodings"
    );
    // Exactly ONE new SetEncodings must exist right now: the sharp one. A
    // buggy implementation that sends the restore back-to-back with the
    // request does so synchronously, within microseconds, so by the time
    // `wait_until`'s poll even notices the sharp list both are already on
    // the wire; checking the count only AFTER a sleep would miss that (the
    // poll's own latency already hides the back-to-back send).
    let encodings_at_refresh = set_encodings_count(&server);
    assert_eq!(
        encodings_at_refresh,
        baseline + 1,
        "only the sharp SetEncodings must exist yet, not also the restore"
    );
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| {
                r.messages.iter().any(
                    |m| matches!(m, ClientMessage::FramebufferUpdateRequest { incremental, rect: req_rect } if !incremental && *req_rect == rect)
                )
            })
            .await,
        "the lossless refresh should have requested the lossy region non-incrementally"
    );

    // The restore must NOT have gone out yet: it is withheld until the
    // answer to this request has been fully consumed. Give it a real window
    // to (wrongly) appear.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        set_encodings_count(&server),
        encodings_at_refresh,
        "the restore must wait for the answering update, not fire back-to-back with the request"
    );

    // Deliver the answer. Still lossy (H.264), as if the server ignored the
    // sharp request or the two simply raced: this must not immediately
    // re-queue the region (item 4's guard (a)).
    server.send_raw(raw_h264_update(rect));
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    // Now the restore must follow.
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| {
                r.messages
                    .iter()
                    .filter(|m| matches!(m, ClientMessage::SetEncodings { .. }))
                    .count()
                    > encodings_at_refresh
            })
            .await,
        "the adaptive SetEncodings must be restored once the answer is consumed"
    );

    // And the still-lossy answer must not have re-queued the region: past a
    // full ALR_COOLDOWN of further idle time, no second refresh cycle
    // (another sharp SetEncodings) must appear.
    let encodings_after_restore = set_encodings_count(&server);
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        set_encodings_count(&server),
        encodings_after_restore,
        "a still-lossy answer to the refresh must not re-queue the region for another cycle"
    );
}
