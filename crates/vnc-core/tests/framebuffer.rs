//! Framebuffer decoding, end to end.
//!
//! For every encoding the client advertises, the mock server emits genuinely
//! wire-correct data and the test asserts the decoded RGBA matches the colours
//! that were encoded. This is the real proof the decoders work against a
//! server rather than only against hand-written unit-test fixtures.

mod common;

use std::time::Duration;

use common::mock_server::*;
use common::*;

use vnc_core::types::{DecodedRect, Rect, RectPayload, SessionEvent};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rgba_of(d: &DecodedRect) -> &[u8] {
    match &d.payload {
        RectPayload::Rgba(px) => px,
        other => panic!("expected an RGBA payload, got {other:?}"),
    }
}

/// The decoded pixel at `(x, y)` within `d`.
fn px(d: &DecodedRect, x: usize, y: usize) -> [u8; 4] {
    let w = d.rect.width as usize;
    let data = rgba_of(d);
    assert_eq!(
        data.len(),
        w * d.rect.height as usize * 4,
        "payload size must be width * height * 4"
    );
    let o = (y * w + x) * 4;
    [data[o], data[o + 1], data[o + 2], data[o + 3]]
}

/// Assert every pixel of `d` equals `colour`.
fn assert_solid(d: &DecodedRect, colour: Rgb) {
    let want = expect_rgba(colour);
    for chunk in rgba_of(d).chunks_exact(4) {
        assert_eq!(
            chunk, want,
            "rect {:?} should be a solid {colour:?}",
            d.rect
        );
    }
}

const RED: Rgb = [255, 0, 0];
const GREEN: Rgb = [0, 255, 0];
const BLUE: Rgb = [0, 0, 255];
const AMBER: Rgb = [240, 170, 20];
const TEAL: Rgb = [17, 136, 136];

// ---------------------------------------------------------------------------
// Raw (0)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn raw_rect_decodes_to_the_encoded_colours() {
    let rect = Rect::new(4, 8, 3, 2);
    let pixels = vec![RED, GREEN, BLUE, AMBER, TEAL, [1, 2, 3]];
    let server = MockServer::start(MockConfig::new().update(vec![RectSpec::RawPixels {
        rect,
        pixels: pixels.clone(),
    }]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, damage) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    assert_eq!(rects.len(), 1);
    assert_eq!(rects[0].rect, rect, "geometry must survive the round trip");
    assert_eq!(damage, rect);
    for (i, want) in pixels.iter().enumerate() {
        let (x, y) = (i % 3, i / 3);
        assert_eq!(px(&rects[0], x, y), expect_rgba(*want), "pixel {x},{y}");
    }
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// CopyRect (1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn copy_rect_carries_the_source_position() {
    let rect = Rect::new(100, 50, 32, 16);
    let server = MockServer::start(MockConfig::new().update(vec![RectSpec::CopyRect {
        rect,
        src_x: 10,
        src_y: 20,
    }]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, damage) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    assert_eq!(rects.len(), 1);
    assert_eq!(rects[0].rect, rect);
    assert_eq!(damage, rect);
    match rects[0].payload {
        RectPayload::CopyRect { src_x, src_y } => {
            assert_eq!((src_x, src_y), (10, 20));
        }
        ref other => panic!("expected CopyRect, got {other:?}"),
    }
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Hextile (5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hextile_rect_decodes_and_persists_the_background_across_tiles() {
    // 48x32 spans six 16x16 tiles; only the first specifies a background, so
    // the whole rect is only correct if the colour persists across tiles.
    let rect = Rect::new(0, 0, 48, 32);
    let server = MockServer::start(MockConfig::new().update(vec![RectSpec::Hextile {
        rect,
        bg: AMBER,
        fg: None,
        subrects: Vec::new(),
    }]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    assert_eq!(rects.len(), 1);
    assert_eq!(rects[0].rect, rect);
    assert_solid(&rects[0], AMBER);
    handle.shutdown();
}

#[tokio::test]
async fn hextile_subrects_decode_over_the_background() {
    let rect = Rect::new(16, 16, 16, 16);
    let server = MockServer::start(MockConfig::new().update(vec![RectSpec::Hextile {
        rect,
        bg: BLUE,
        fg: Some(RED),
        // (x, y, w, h) inside the tile.
        subrects: vec![(2, 3, 4, 5)],
    }]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    let d = &rects[0];
    assert_eq!(d.rect, rect);
    assert_eq!(px(d, 0, 0), expect_rgba(BLUE), "background");
    assert_eq!(px(d, 2, 3), expect_rgba(RED), "subrect top-left");
    assert_eq!(px(d, 5, 7), expect_rgba(RED), "subrect bottom-right");
    assert_eq!(px(d, 6, 3), expect_rgba(BLUE), "just right of the subrect");
    assert_eq!(px(d, 2, 8), expect_rgba(BLUE), "just below the subrect");
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// zlib (6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn zlib_rects_decode_through_one_persistent_stream() {
    // Two updates on the same connection. The second only inflates if the
    // decoder kept the zlib stream alive across rects (PRD/02 §9).
    let a = Rect::new(0, 0, 8, 8);
    let b = Rect::new(8, 0, 8, 8);
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![RectSpec::Zlib {
                rect: a,
                colour: TEAL,
            }])
            .update(vec![RectSpec::Zlib {
                rect: b,
                colour: AMBER,
            }]),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let (first, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(first[0].rect, a);
    assert_solid(&first[0], TEAL);

    let (second, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(second[0].rect, b);
    assert_solid(&second[0], AMBER);
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Tight (7)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tight_fill_and_palette_rects_decode() {
    let fill = Rect::new(0, 0, 6, 4);
    let pal = Rect::new(8, 0, 8, 4);
    // 8 pixels per row, 1 packed byte per row, MSB = leftmost pixel.
    let rows = vec![vec![0b1010_1010u8]; 4];

    let server = MockServer::start(MockConfig::new().update(vec![
        RectSpec::TightFill {
            rect: fill,
            colour: AMBER,
        },
        RectSpec::TightPalette {
            rect: pal,
            colour0: RED,
            colour1: BLUE,
            rows,
        },
    ]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, damage) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    assert_eq!(rects.len(), 2, "both Tight rects arrive in one event");
    assert_eq!(rects[0].rect, fill);
    assert_solid(&rects[0], AMBER);

    let p = &rects[1];
    assert_eq!(p.rect, pal);
    for y in 0..4 {
        for x in 0..8 {
            let want = if x % 2 == 0 { BLUE } else { RED };
            assert_eq!(px(p, x, y), expect_rgba(want), "palette pixel {x},{y}");
        }
    }
    assert_eq!(damage, Rect::new(0, 0, 16, 4));
    handle.shutdown();
}

#[tokio::test]
async fn tight_basic_compression_decodes_through_the_persistent_stream() {
    // 4x2 = 8 TPIXELs = 24 bytes, past Tight's 12-byte threshold, so this
    // genuinely exercises zlib stream 0.
    let rect = Rect::new(2, 2, 4, 2);
    let pixels = vec![
        RED,
        GREEN,
        BLUE,
        AMBER,
        TEAL,
        [9, 9, 9],
        [1, 2, 3],
        [4, 5, 6],
    ];
    let server = MockServer::start(MockConfig::new().update(vec![RectSpec::TightCompressed {
        rect,
        pixels: pixels.clone(),
    }]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    let d = &rects[0];
    assert_eq!(d.rect, rect);
    for (i, want) in pixels.iter().enumerate() {
        assert_eq!(px(d, i % 4, i / 4), expect_rgba(*want), "pixel index {i}");
    }
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// ZRLE (16)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn zrle_solid_tiles_decode() {
    // 128x64 spans four 64x64 tiles, each sent as a solid CPIXEL.
    let rect = Rect::new(0, 0, 128, 64);
    let server = MockServer::start(
        MockConfig::new().update(vec![RectSpec::ZrleSolid { rect, colour: TEAL }]),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, damage) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    assert_eq!(rects.len(), 1);
    assert_eq!(rects[0].rect, rect);
    assert_eq!(damage, rect);
    assert_solid(&rects[0], TEAL);
    handle.shutdown();
}

#[tokio::test]
async fn zrle_packed_palette_tile_decodes() {
    let rect = Rect::new(0, 0, 8, 3);
    let rows = vec![
        vec![0b1111_0000u8], // c1 c1 c1 c1 c0 c0 c0 c0
        vec![0b0000_1111u8],
        vec![0b1100_1100u8],
    ];
    let server = MockServer::start(MockConfig::new().update(vec![RectSpec::ZrlePalette {
        rect,
        colour0: RED,
        colour1: BLUE,
        rows,
    }]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    let d = &rects[0];
    assert_eq!(d.rect, rect);
    let bits = [0b1111_0000u8, 0b0000_1111, 0b1100_1100];
    for (y, byte) in bits.iter().enumerate() {
        for x in 0..8usize {
            let one = (byte >> (7 - x)) & 1 == 1;
            let want = if one { BLUE } else { RED };
            assert_eq!(px(d, x, y), expect_rgba(want), "pixel {x},{y}");
        }
    }
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Coalescing (PRD/02 §5): one update -> one event
// ---------------------------------------------------------------------------

#[tokio::test]
async fn all_rects_of_one_update_coalesce_into_one_event_with_a_unioned_damage() {
    let a = Rect::new(0, 0, 4, 4);
    let b = Rect::new(20, 10, 6, 6);
    let c = Rect::new(300, 200, 8, 8);
    let server = MockServer::start(MockConfig::new().update(vec![
        RectSpec::Raw {
            rect: a,
            colour: RED,
        },
        RectSpec::Hextile {
            rect: b,
            bg: GREEN,
            fg: None,
            subrects: Vec::new(),
        },
        RectSpec::ZrleSolid {
            rect: c,
            colour: BLUE,
        },
    ]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, damage) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    assert_eq!(rects.len(), 3, "three rects must arrive in a single event");
    assert_eq!(rects[0].rect, a);
    assert_eq!(rects[1].rect, b);
    assert_eq!(rects[2].rect, c);
    assert_solid(&rects[0], RED);
    assert_solid(&rects[1], GREEN);
    assert_solid(&rects[2], BLUE);

    // union((0,0,4,4), (20,10,6,6), (300,200,8,8)) = (0,0,308,208)
    assert_eq!(damage, Rect::new(0, 0, 308, 208));

    // And emphatically NOT one event per rect.
    let before = events.seen.len();
    events.drain_for(Duration::from_millis(300)).await;
    let extra_updates = events.seen[before..]
        .iter()
        .filter(|e| matches!(e, SessionEvent::FramebufferUpdate { .. }))
        .count();
    assert_eq!(
        extra_updates, 0,
        "the renderer must be told to present once"
    );
    handle.shutdown();
}

#[tokio::test]
async fn last_rect_sentinel_terminates_an_update_of_unknown_length() {
    let a = Rect::new(0, 0, 4, 4);
    let server = MockServer::start(MockConfig::new().update(vec![
        RectSpec::Raw {
            rect: a,
            colour: GREEN,
        },
        RectSpec::LastRect,
    ]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let (rects, damage) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(rects.len(), 1);
    assert_eq!(damage, a);
    assert_solid(&rects[0], GREEN);
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Pseudo-encodings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn extended_desktop_size_emits_a_desktop_resize() {
    let server = MockServer::start(
        MockConfig::new()
            .size(640, 480)
            .update(vec![RectSpec::ExtendedDesktopSize {
                width: 1280,
                height: 800,
                reason: 0,
                status: 0,
            }])
            // A data rect at the new geometry proves the framebuffer bounds
            // were widened too (it would be rejected at 640x480).
            .update(vec![RectSpec::Raw {
                rect: Rect::new(1200, 780, 40, 20),
                colour: RED,
            }]),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let (w, h) = events
        .wait(DEFAULT_TIMEOUT, "DesktopResize to 1280x800", |e| match e {
            SessionEvent::DesktopResize { width, height } if *width == 1280 => {
                Some((*width, *height))
            }
            _ => None,
        })
        .await;
    assert_eq!((w, h), (1280, 800));

    let (rects, _) = events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    assert_eq!(rects[0].rect, Rect::new(1200, 780, 40, 20));
    assert_solid(&rects[0], RED);
    handle.shutdown();
}

#[tokio::test]
async fn a_multi_monitor_layout_is_reported_once_per_change() {
    let screens = vec![(1u32, 0u16, 0u16, 640u16, 800u16), (2, 640, 0, 640, 800)];
    let server = MockServer::start(
        MockConfig::new()
            .size(1280, 800)
            .update(vec![RectSpec::ExtendedDesktopSizeScreens {
                width: 1280,
                height: 800,
                screens: screens.clone(),
            }])
            // The same layout again: not a change, must not be re-reported.
            .update(vec![RectSpec::ExtendedDesktopSizeScreens {
                width: 1280,
                height: 800,
                screens: screens.clone(),
            }])
            // Sentinel: once this lands, both EDS rects have been processed.
            .update(vec![RectSpec::DesktopName("sentinel".into())]),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let layout = events
        .wait(DEFAULT_TIMEOUT, "ScreenLayout", |e| match e {
            SessionEvent::ScreenLayout { screens } => Some(screens.clone()),
            _ => None,
        })
        .await;
    assert_eq!(layout.len(), 2);
    assert_eq!((layout[0].id, layout[0].x, layout[0].width), (1, 0, 640));
    assert_eq!((layout[1].id, layout[1].x, layout[1].width), (2, 640, 640));

    events
        .wait(DEFAULT_TIMEOUT, "sentinel rename", |e| match e {
            SessionEvent::DesktopName(n) if n == "sentinel" => Some(()),
            _ => None,
        })
        .await;
    let reports = events
        .seen
        .iter()
        .filter(|e| matches!(e, SessionEvent::ScreenLayout { .. }))
        .count();
    assert_eq!(reports, 1, "an unchanged layout was re-reported");
    handle.shutdown();
}

#[tokio::test]
async fn desktop_name_pseudo_rect_emits_a_rename() {
    let server = MockServer::start(
        MockConfig::new()
            .name("Before")
            .update(vec![RectSpec::DesktopName("After Rename".into())]),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events
        .wait(DEFAULT_TIMEOUT, "DesktopName(After Rename)", |e| match e {
            SessionEvent::DesktopName(n) if n == "After Rename" => Some(()),
            _ => None,
        })
        .await;
    handle.shutdown();
}

#[tokio::test]
async fn rich_cursor_pseudo_rect_emits_a_cursor_update() {
    let server = MockServer::start(MockConfig::new().update(vec![RectSpec::RichCursor {
        width: 4,
        height: 4,
        hotspot_x: 1,
        hotspot_y: 2,
        colour: AMBER,
    }]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let shape = events
        .wait(DEFAULT_TIMEOUT, "CursorUpdate", |e| match e {
            SessionEvent::CursorUpdate(c) => Some(c.clone()),
            _ => None,
        })
        .await;
    assert_eq!((shape.width, shape.height), (4, 4));
    assert_eq!((shape.hotspot_x, shape.hotspot_y), (1, 2));
    assert_eq!(shape.pixels.len(), 4 * 4 * 4);
    assert_eq!(&shape.pixels[0..4], &expect_rgba(AMBER));
    handle.shutdown();
}

#[tokio::test]
async fn bell_message_is_surfaced() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    server.send_bell();
    events
        .wait(DEFAULT_TIMEOUT, "Bell", |e| {
            matches!(e, SessionEvent::Bell).then_some(())
        })
        .await;
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Update pipelining (PRD/02 §7.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn one_incremental_request_stays_outstanding() {
    let server = MockServer::start(
        MockConfig::new()
            .update(vec![RectSpec::Raw {
                rect: Rect::new(0, 0, 4, 4),
                colour: RED,
            }])
            .update(vec![RectSpec::Raw {
                rect: Rect::new(4, 0, 4, 4),
                colour: BLUE,
            }]),
    )
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    events.drain_for(Duration::from_millis(150)).await;

    let requests: Vec<_> = server
        .messages()
        .into_iter()
        .filter_map(|m| match m {
            ClientMessage::FramebufferUpdateRequest { incremental, .. } => Some(incremental),
            _ => None,
        })
        .collect();
    assert_eq!(
        requests.first(),
        Some(&false),
        "the first request primes the pipeline non-incrementally"
    );
    assert!(
        requests[1..].iter().all(|&i| i),
        "subsequent requests must be incremental: {requests:?}"
    );
    assert_eq!(
        requests.len(),
        3,
        "exactly one request outstanding at a time: {requests:?}"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Resize follow-up requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_desktop_grow_requests_an_update_for_the_new_geometry() {
    let server = MockServer::start(MockConfig::new().size(640, 480).update(vec![
        RectSpec::ExtendedDesktopSize {
            width: 1280,
            height: 800,
            reason: 0,
            status: 0,
        },
    ]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events
        .wait(DEFAULT_TIMEOUT, "DesktopResize to 1280x800", |e| match e {
            SessionEvent::DesktopResize { width: 1280, .. } => Some(()),
            _ => None,
        })
        .await;

    // The pipelined request preceding the resize covered the OLD rect. If the
    // server has no damage inside that rect it sends nothing further, no new
    // request is ever generated, and the grown strip stays blank forever, so
    // the resize itself must request the new geometry.
    let seen = server
        .wait_until(DEFAULT_TIMEOUT, |r| {
            r.messages.iter().any(|m| {
                matches!(m,
                    ClientMessage::FramebufferUpdateRequest { incremental: true, rect }
                        if rect.width == 1280 && rect.height == 800)
            })
        })
        .await;
    assert!(
        seen,
        "no incremental request covering the grown geometry: {:?}",
        server.messages()
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Hostile-server bounds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_sentinel_update_with_endless_empty_rects_is_rejected() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // FramebufferUpdate with the 0xffff sentinel count, then a stream of 0x0
    // Raw rects and never a LastRect. Zero-area rects decode to zero bytes,
    // so the per-update BYTE budget never trips; only a bound on the header
    // count can end this.
    let mut flood = vec![0u8, 0, 0xff, 0xff];
    for _ in 0..70_000u32 {
        flood.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // x, y, w, h
        flood.extend_from_slice(&0i32.to_be_bytes()); // Raw
    }
    server.send_raw(flood);

    // Protocol errors are fatal (retrying the same server won't help), so the
    // abandonment surfaces as an error event rather than a re-dial.
    events
        .wait(
            DEFAULT_TIMEOUT,
            "protocol error for the rect flood",
            |e| match e {
                SessionEvent::Error(m) if m.contains("65535 rects") => Some(()),
                _ => None,
            },
        )
        .await;
    handle.shutdown();
}
