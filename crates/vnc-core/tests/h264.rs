//! Open H.264 (encoding 50), end to end.
//!
//! The mock server emits byte-accurate encoding-50 payloads
//! (`U32 length + U32 flags + Annex-B`) and these tests assert the client
//! parses the framing and derives the decoder-context bookkeeping the webview
//! needs: one context per rect geometry, 64 of them, LRU-evicted, with the
//! reset flags and IDR detection honoured (PRD/02 §2.3).
//!
//! The Annex-B bytes are synthetic, no encoder is involved. Nothing here
//! decodes video; the point is that every *protocol-visible* decision the
//! client makes is correct.

mod common;

use common::mock_server::*;
use common::*;

use vnc_core::encodings::{decode_rect, DecoderState};
use vnc_core::quality::{encodings_for, settings_for};
use vnc_core::types::{
    encoding, DecodedRect, PixelFormat, QualityPreset, Rect, RectPayload, ServerCapabilities,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The H.264 metadata of a decoded rect: `(data, flags, context_id, reset,
/// keyframe)`.
fn h264_of(d: &DecodedRect) -> (&[u8], u32, u32, bool, bool) {
    match &d.payload {
        RectPayload::H264 {
            data,
            flags,
            context_id,
            reset,
            keyframe,
        } => (data, *flags, *context_id, *reset, *keyframe),
        other => panic!("expected an H264 payload, got {other:?}"),
    }
}

/// Feed one encoding-50 rect straight through the dispatcher, exactly as it
/// would arrive on the wire.
async fn feed(state: &mut DecoderState, rect: Rect, flags: u32, data: &[u8]) -> DecodedRect {
    let mut wire = Vec::with_capacity(8 + data.len());
    wire.extend_from_slice(&(data.len() as u32).to_be_bytes());
    wire.extend_from_slice(&flags.to_be_bytes());
    wire.extend_from_slice(data);
    let mut r: &[u8] = &wire;
    let out = decode_rect(state, &mut r, rect, encoding::OPEN_H264)
        .await
        .expect("h264 rect must decode")
        .expect("encoding 50 is a real encoding, not a pseudo one");
    assert!(r.is_empty(), "the whole payload must be consumed");
    out
}

/// `(context_id, reset, keyframe)` for a rect fed through the dispatcher.
async fn meta(state: &mut DecoderState, rect: Rect, flags: u32, data: &[u8]) -> (u32, bool, bool) {
    let d = feed(state, rect, flags, data).await;
    let (_, _, ctx, reset, key) = h264_of(&d);
    (ctx, reset, key)
}

fn new_state() -> DecoderState {
    DecoderState::new(PixelFormat::bgra8888())
}

// ---------------------------------------------------------------------------
// Wire framing against the mock server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn h264_rect_survives_the_wire_with_context_metadata() {
    let rect = Rect::new(16, 32, 128, 64);
    let frame = annexb_idr(0xAB);
    let server = MockServer::start(MockConfig::new().update(vec![RectSpec::H264 {
        rect,
        flags: 0,
        data: frame.clone(),
    }]))
    .await;

    let (_handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, damage) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    assert_eq!(rects.len(), 1);
    assert_eq!(rects[0].rect, rect, "geometry must survive the round trip");
    assert_eq!(damage, rect);
    let (data, flags, ctx, reset, keyframe) = h264_of(&rects[0]);
    assert_eq!(data, &frame[..], "Annex-B bytes must arrive verbatim");
    assert_eq!(flags, 0);
    assert_eq!(ctx, 0, "the first geometry gets the first context slot");
    assert!(reset, "a brand-new context needs a fresh VideoDecoder");
    assert!(keyframe, "SPS + PPS + IDR is a keyframe");
}

#[tokio::test]
async fn h264_stream_of_frames_keeps_one_context_per_geometry() {
    let left = Rect::new(0, 0, 64, 64);
    let right = Rect::new(64, 0, 64, 64);
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![
                RectSpec::H264 {
                    rect: left,
                    flags: 0,
                    data: annexb_idr(1),
                },
                RectSpec::H264 {
                    rect: right,
                    flags: 0,
                    data: annexb_idr(2),
                },
            ])
            .update(vec![
                RectSpec::H264 {
                    rect: left,
                    flags: 0,
                    data: annexb_delta(3),
                },
                RectSpec::H264 {
                    rect: right,
                    flags: 0,
                    data: annexb_delta(4),
                },
            ]),
    )
    .await;

    let (_handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let (first, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(first.len(), 2);
    let (_, _, left_ctx, left_reset, left_key) = h264_of(&first[0]);
    let (_, _, right_ctx, _, _) = h264_of(&first[1]);
    assert!(left_reset && left_key);
    assert_ne!(
        left_ctx, right_ctx,
        "distinct geometries, distinct contexts"
    );

    let (second, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(second.len(), 2);
    let (_, _, ctx0, reset0, key0) = h264_of(&second[0]);
    let (_, _, ctx1, reset1, _) = h264_of(&second[1]);
    assert_eq!(ctx0, left_ctx, "the same rect keeps its decoder");
    assert_eq!(ctx1, right_ctx);
    assert!(!reset0, "an established context is not reset");
    assert!(!reset1);
    assert!(!key0, "a delta frame is not a keyframe");
}

#[tokio::test]
async fn h264_zero_length_payload_is_a_control_message() {
    let rect = Rect::new(0, 0, 32, 32);
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![RectSpec::H264 {
                rect,
                flags: 0,
                data: annexb_idr(7),
            }])
            // Reset-all with no data at all: pure control message.
            .update(vec![RectSpec::H264 {
                rect,
                flags: H264_RESET_ALL_CONTEXTS,
                data: Vec::new(),
            }])
            .update(vec![RectSpec::H264 {
                rect,
                flags: 0,
                data: annexb_idr(8),
            }]),
    )
    .await;

    let (_handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let (first, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    let (_, _, _, reset, _) = h264_of(&first[0]);
    assert!(reset);

    let (ctrl, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(ctrl.len(), 1);
    let (data, flags, _, ctrl_reset, ctrl_key) = h264_of(&ctrl[0]);
    assert!(data.is_empty(), "a control message carries no frame");
    assert_eq!(flags, H264_RESET_ALL_CONTEXTS);
    assert!(ctrl_reset, "the context was dropped, so it must be rebuilt");
    assert!(!ctrl_key);

    // The next real frame still reports reset: nothing decodable arrived in
    // between, so the webview must build a decoder for it.
    let (after, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    let (_, _, _, after_reset, after_key) = h264_of(&after[0]);
    assert!(after_reset);
    assert!(after_key);
}

/// A frame may legitimately be larger than the rect (the encoder pads to
/// macroblock boundaries); the client must pass the bytes through untouched
/// and leave the crop to the renderer.
#[tokio::test]
async fn h264_frame_larger_than_the_rect_is_passed_through() {
    let rect = Rect::new(0, 0, 6, 6); // 6x6 -> encoder pads to 16x16
    let mut frame = annexb_idr(9);
    frame.extend(std::iter::repeat_n(0x5Au8, 4096)); // more data than 6*6 pixels
    let server = MockServer::start(MockConfig::new().update(vec![RectSpec::H264 {
        rect,
        flags: 0,
        data: frame.clone(),
    }]))
    .await;

    let (_handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    let (data, _, _, _, keyframe) = h264_of(&rects[0]);
    assert_eq!(data.len(), frame.len());
    assert_eq!(data, &frame[..]);
    assert_eq!(rects[0].rect, rect, "the rect is unchanged by the padding");
    assert!(keyframe);
}

#[tokio::test]
async fn h264_reset_flags_arrive_verbatim() {
    let rect = Rect::new(0, 0, 48, 48);
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![RectSpec::H264 {
                rect,
                flags: 0,
                data: annexb_idr(1),
            }])
            .update(vec![RectSpec::H264 {
                rect,
                flags: H264_RESET_CONTEXT,
                data: annexb_idr(2),
            }])
            .update(vec![RectSpec::H264 {
                rect,
                flags: H264_RESET_CONTEXT | H264_RESET_ALL_CONTEXTS,
                data: annexb_idr(3),
            }]),
    )
    .await;

    let (_handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    let (one, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    let (_, flags, _, reset, _) = h264_of(&one[0]);
    assert_eq!(flags, H264_RESET_CONTEXT, "server flags pass through");
    assert!(reset);

    let (two, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    let (_, flags, _, reset, _) = h264_of(&two[0]);
    assert_eq!(flags, H264_RESET_CONTEXT | H264_RESET_ALL_CONTEXTS);
    assert!(reset);
}

// ---------------------------------------------------------------------------
// Context bookkeeping through the real dispatcher
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_created_per_geometry_and_reused() {
    let mut s = new_state();
    let a = Rect::new(0, 0, 64, 64);
    let b = Rect::new(0, 64, 64, 64);

    let (ctx_a, reset_a, key_a) = meta(&mut s, a, 0, &annexb_idr(1)).await;
    assert!(reset_a && key_a);
    let (ctx_b, reset_b, _) = meta(&mut s, b, 0, &annexb_idr(2)).await;
    assert!(reset_b);
    assert_ne!(ctx_a, ctx_b);
    assert_eq!(s.h264_context_count(), 2);

    // Same geometry -> same context, no reset.
    assert_eq!(
        meta(&mut s, a, 0, &annexb_delta(3)).await,
        (ctx_a, false, false)
    );
    assert_eq!(
        meta(&mut s, b, 0, &annexb_delta(4)).await,
        (ctx_b, false, false)
    );
    assert_eq!(s.h264_context_count(), 2);

    // A rect at the same size but a different position is a different context.
    let moved = Rect::new(128, 0, 64, 64);
    let (ctx_moved, reset_moved, _) = meta(&mut s, moved, 0, &annexb_idr(5)).await;
    assert!(reset_moved);
    assert_ne!(ctx_moved, ctx_a);
    assert_eq!(s.h264_context_count(), 3);
}

#[tokio::test]
async fn a_new_context_must_start_with_an_idr() {
    let mut s = new_state();
    let r = Rect::new(0, 0, 32, 32);

    // Joining mid-GOP: every delta frame keeps reporting "reset" because the
    // webview still has nothing it can configure a decoder with.
    for tag in 0..3u8 {
        let (_, reset, keyframe) = meta(&mut s, r, 0, &annexb_delta(tag)).await;
        assert!(reset, "still waiting for an IDR");
        assert!(!keyframe);
    }
    // The IDR arrives: it is the frame that starts the decoder.
    let (_, reset, keyframe) = meta(&mut s, r, 0, &annexb_idr(9)).await;
    assert!(reset);
    assert!(keyframe);
    // ...and from then on the context is established.
    let (_, reset, keyframe) = meta(&mut s, r, 0, &annexb_delta(10)).await;
    assert!(!reset);
    assert!(!keyframe);
}

#[tokio::test]
async fn reset_context_rebuilds_only_that_context() {
    let mut s = new_state();
    let a = Rect::new(0, 0, 16, 16);
    let b = Rect::new(16, 0, 16, 16);
    meta(&mut s, a, 0, &annexb_idr(1)).await;
    meta(&mut s, b, 0, &annexb_idr(2)).await;

    let (_, reset, _) = meta(&mut s, a, H264_RESET_CONTEXT, &annexb_idr(3)).await;
    assert!(reset, "ResetContext forces a new decoder for this rect");
    let (_, reset_b, _) = meta(&mut s, b, 0, &annexb_delta(4)).await;
    assert!(!reset_b, "the other context is untouched");
    assert_eq!(s.h264_context_count(), 2, "reset recycles, never leaks");
}

#[tokio::test]
async fn reset_all_contexts_rebuilds_every_context() {
    let mut s = new_state();
    let rects: Vec<Rect> = (0..4).map(|i| Rect::new(i * 16, 0, 16, 16)).collect();
    for (i, r) in rects.iter().enumerate() {
        meta(&mut s, *r, 0, &annexb_idr(i as u8)).await;
    }
    assert_eq!(s.h264_context_count(), 4);

    // Reset-all on one rect wipes the table for all of them.
    let (_, reset, _) = meta(&mut s, rects[0], H264_RESET_ALL_CONTEXTS, &annexb_idr(9)).await;
    assert!(reset);
    assert_eq!(s.h264_context_count(), 1, "only the current rect survives");
    for r in &rects[1..] {
        let (_, reset, _) = meta(&mut s, *r, 0, &annexb_idr(0)).await;
        assert!(reset, "every other context was dropped too");
    }
}

#[tokio::test]
async fn sixty_four_contexts_then_lru_eviction() {
    let mut s = new_state();
    let rect_at = |i: u16| Rect::new(i * 8, 0, 8, 8);

    let mut ids = Vec::new();
    for i in 0..64u16 {
        let (id, reset, _) = meta(&mut s, rect_at(i), 0, &annexb_idr(1)).await;
        assert!(reset);
        ids.push(id);
    }
    assert_eq!(s.h264_context_count(), 64, "64 simultaneous contexts");
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 64, "every context id is distinct");

    // Re-touch the oldest so it is no longer the LRU victim.
    let (id0, reset0, _) = meta(&mut s, rect_at(0), 0, &annexb_delta(2)).await;
    assert!(!reset0);

    // The 65th geometry must evict the least-recently-used context (rect 1).
    let (evicting_id, reset, _) = meta(&mut s, rect_at(64), 0, &annexb_idr(3)).await;
    assert!(reset);
    assert_eq!(
        s.h264_context_count(),
        64,
        "the table never grows past 64 contexts"
    );

    // rect 1 was the victim: it comes back as a brand-new context.
    let (_, reset_evicted, _) = meta(&mut s, rect_at(1), 0, &annexb_idr(4)).await;
    assert!(reset_evicted, "the evicted geometry needs a fresh decoder");

    // rect 0, which we touched, kept its decoder.
    let (id0_again, reset0_again, _) = meta(&mut s, rect_at(0), 0, &annexb_delta(5)).await;
    assert_eq!(id0_again, id0);
    assert!(!reset0_again, "the most-recently-used context survived");
    assert_ne!(evicting_id, id0);
    assert_eq!(s.h264_context_count(), 64);
}

#[tokio::test]
async fn context_ids_stay_within_the_supported_range() {
    let mut s = new_state();
    for i in 0..200u16 {
        let (id, _, _) = meta(&mut s, Rect::new(i, 0, 8, 8), 0, &annexb_idr(1)).await;
        assert!(
            (id as usize) < 64,
            "context id {id} must index one of the 64 decoder slots"
        );
    }
    assert_eq!(s.h264_context_count(), 64);
}

#[tokio::test]
async fn reconnect_forgets_every_h264_context() {
    let mut s = new_state();
    let r = Rect::new(0, 0, 64, 64);
    meta(&mut s, r, 0, &annexb_idr(1)).await;
    assert!(!meta(&mut s, r, 0, &annexb_delta(2)).await.1);
    s.reset();
    assert_eq!(s.h264_context_count(), 0);
    assert!(
        meta(&mut s, r, 0, &annexb_idr(3)).await.1,
        "after a reconnect every decoder is rebuilt"
    );
}

// ---------------------------------------------------------------------------
// Advertising encoding 50
// ---------------------------------------------------------------------------

#[test]
fn encoding_50_is_advertised_only_when_the_server_supports_it() {
    let settings = settings_for(QualityPreset::Medium);
    assert!(settings.allow_h264);

    let unsupported = ServerCapabilities::default();
    assert!(!encodings_for(&settings, &unsupported).contains(&encoding::OPEN_H264));

    let supported = ServerCapabilities {
        supports_h264: true,
        ..Default::default()
    };
    let list = encodings_for(&settings, &supported);
    assert!(list.contains(&encoding::OPEN_H264));
    assert_eq!(list[1], encoding::OPEN_H264, "ranked right after Tight");

    // The quality preset can veto it even when the server supports it.
    let high = settings_for(QualityPreset::High);
    assert!(!high.allow_h264);
    assert!(!encodings_for(&high, &supported).contains(&encoding::OPEN_H264));
}

#[tokio::test]
async fn client_advertises_encoding_50_to_a_modern_server() {
    let server = MockServer::start(MockConfig::new().banner(RFB_38)).await;
    let (_handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| r
                .messages
                .iter()
                .any(|m| matches!(m, ClientMessage::SetEncodings { .. })))
            .await,
        "the client must send SetEncodings"
    );
    let list = server.encoding_lists().remove(0);
    assert!(
        list.contains(&encoding::OPEN_H264),
        "encoding 50 must be offered to a server that may support it: {list:?}"
    );
}

/// macOS Screen Sharing offers third parties only Raw/CopyRect/zlib/Hextile/
/// ZRLE (PRD/02 §6), advertising H.264 to it is dead weight, so the banner
/// quirk must switch the capability off.
#[tokio::test]
async fn client_does_not_advertise_encoding_50_to_macos_screen_sharing() {
    let server = MockServer::start(MockConfig::new().banner(RFB_APPLE)).await;
    let (_handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| r
                .messages
                .iter()
                .any(|m| matches!(m, ClientMessage::SetEncodings { .. })))
            .await,
        "the client must send SetEncodings"
    );
    let list = server.encoding_lists().remove(0);
    assert!(
        !list.contains(&encoding::OPEN_H264),
        "encoding 50 must not be offered to macOS Screen Sharing: {list:?}"
    );
    assert!(
        list.contains(&encoding::ZRLE),
        "ZRLE is still the preferred macOS encoding: {list:?}"
    );
}
