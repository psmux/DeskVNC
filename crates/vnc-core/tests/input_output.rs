//! Input and clipboard, end to end.
//!
//! Asserts the exact bytes that reach the server for key/pointer events, that
//! the stuck-modifier safety net really releases every held key, and that
//! clipboard text flows correctly in both directions.

mod common;

use std::time::Duration;

use common::*;

use vnc_core::types::{ClientCommand, Rect, SessionEvent, SessionState};

const RED: Rgb = [255, 0, 0];

/// Round-trip marker: a quality change produces a SetEncodings, so waiting
/// for the Nth one proves every command queued before it has been processed.
/// One goes out during the handshake, so the first marker is the 2nd.
///
/// This used to send a Refresh and count non-incremental
/// FramebufferUpdateRequests. That stopped being a barrier when the manual
/// Refresh was put behind the always-refresh throttle: a second press while
/// the server still owes us the last full screen is now deliberately dropped,
/// so the count would never reach the 3rd marker. Quality is the one lever
/// nothing in this file asserts on, and `nth` alternates the preset because
/// `apply_quality` sends nothing when the settings already match.
async fn flush(handle: &vnc_core::SessionHandle, server: &MockServer, nth: usize) {
    let preset = if nth % 2 == 0 {
        vnc_core::types::QualityPreset::High
    } else {
        vnc_core::types::QualityPreset::Medium
    };
    send(handle, ClientCommand::SetQuality(preset)).await;
    let ok = server
        .wait_until(DEFAULT_TIMEOUT, |r| {
            r.messages
                .iter()
                .filter(|m| matches!(m, ClientMessage::SetEncodings { .. }))
                .count()
                >= nth
        })
        .await;
    assert!(ok, "the session stopped processing commands");
}

// ---------------------------------------------------------------------------
// Keyboard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn key_events_arrive_byte_correct() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(
        &handle,
        ClientCommand::Key {
            keysym: 0xffe1,
            keycode: None,
            down: true,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::Key {
            keysym: 0x61,
            keycode: None,
            down: true,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::Key {
            keysym: 0x61,
            keycode: None,
            down: false,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::Key {
            keysym: 0xffe1,
            keycode: None,
            down: false,
        },
    )
    .await;
    flush(&handle, &server, 2).await;

    let raws: Vec<Vec<u8>> = server
        .messages()
        .into_iter()
        .filter_map(|m| match m {
            ClientMessage::KeyEvent { raw, .. } => Some(raw),
            _ => None,
        })
        .collect();
    assert_eq!(
        raws,
        vec![
            vec![4, 1, 0, 0, 0x00, 0x00, 0xff, 0xe1], // Shift_L down
            vec![4, 1, 0, 0, 0x00, 0x00, 0x00, 0x61], // 'a' down
            vec![4, 0, 0, 0, 0x00, 0x00, 0x00, 0x61], // 'a' up
            vec![4, 0, 0, 0, 0x00, 0x00, 0xff, 0xe1], // Shift_L up
        ],
        "KeyEvent (message 4) must be [4, down, pad, pad, keysym:u32] big-endian"
    );
    handle.shutdown();
}

#[tokio::test]
async fn release_all_keys_sends_exactly_one_key_up_per_held_key() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    for keysym in [0xffe3u32, 0xffe9, 0x74] {
        send(
            &handle,
            ClientCommand::Key {
                keysym,
                keycode: None,
                down: true,
            },
        )
        .await;
    }
    send(&handle, ClientCommand::ReleaseAllKeys).await;
    flush(&handle, &server, 2).await;

    let (downs, ups): (Vec<_>, Vec<_>) =
        server.key_events().into_iter().partition(|(_, down)| *down);
    assert_eq!(downs.len(), 3);
    assert_eq!(ups.len(), 3, "exactly three key-ups, no more and no fewer");

    let mut up_keys: Vec<u32> = ups.into_iter().map(|(k, _)| k).collect();
    up_keys.sort_unstable();
    assert_eq!(up_keys, vec![0x74, 0xffe3, 0xffe9]);

    // Releasing again must be a no-op: nothing is held any more.
    send(&handle, ClientCommand::ReleaseAllKeys).await;
    flush(&handle, &server, 3).await;
    assert_eq!(server.key_events().len(), 6, "no duplicate key-ups");
    handle.shutdown();
}

#[tokio::test]
async fn disconnecting_releases_every_held_key() {
    // Keyboard safety (PRD/05 §6.3): a reconnect must never inherit stuck
    // modifiers, so the run loop unwinds pressed keys on the way out.
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    for keysym in [0xffe3u32, 0xffe9] {
        send(
            &handle,
            ClientCommand::Key {
                keysym,
                keycode: None,
                down: true,
            },
        )
        .await;
    }
    flush(&handle, &server, 2).await;
    send(&handle, ClientCommand::Disconnect).await;

    events
        .wait_state(DEFAULT_TIMEOUT, "Disconnected", |s| {
            matches!(s, SessionState::Disconnected { .. }).then_some(())
        })
        .await;

    let released = server
        .wait_until(DEFAULT_TIMEOUT, |r| {
            r.messages
                .iter()
                .filter(|m| matches!(m, ClientMessage::KeyEvent { down: false, .. }))
                .count()
                == 2
        })
        .await;
    let ups: Vec<u32> = server
        .key_events()
        .into_iter()
        .filter(|(_, down)| !*down)
        .map(|(k, _)| k)
        .collect();
    assert!(released, "both modifiers must be released: {ups:?}");
    assert_eq!(ups.len(), 2);
}

#[tokio::test]
async fn qemu_extended_key_events_are_used_once_the_server_advertises_them() {
    let server = MockServer::start(MockConfig::new().update(vec![
        RectSpec::QemuExtKeyCapable,
        RectSpec::Raw {
            rect: Rect::new(0, 0, 4, 4),
            colour: RED,
        },
    ]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    send(
        &handle,
        ClientCommand::Key {
            keysym: 0xffea,
            keycode: Some(0xb8),
            down: true,
        },
    )
    .await;
    flush(&handle, &server, 2).await;

    let qemu: Vec<_> = server
        .messages()
        .into_iter()
        .filter_map(|m| match m {
            ClientMessage::QemuKeyEvent {
                down,
                keysym,
                keycode,
            } => Some((down, keysym, keycode)),
            _ => None,
        })
        .collect();
    assert_eq!(qemu, vec![(true, 0xffea, 0xb8)]);
    assert!(
        server.key_events().is_empty(),
        "a keycode-carrying key must not also go out as a plain KeyEvent"
    );
    handle.shutdown();
}

#[tokio::test]
async fn match_local_layout_suppresses_scancodes() {
    // "Match my local layout": a server honouring QEMU Extended Key Event
    // applies its OWN keymap to the scancode and ignores the keysym, so a
    // German ö (code Semicolon) types ';' on an en-US server. Turning the
    // preference off must fall back to layout-aware keysyms even though the
    // server advertises the extension.
    let server = MockServer::start(MockConfig::new().update(vec![
        RectSpec::QemuExtKeyCapable,
        RectSpec::Raw {
            rect: Rect::new(0, 0, 4, 4),
            colour: RED,
        },
    ]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    send(&handle, ClientCommand::SetPreferScancodes(false)).await;
    send(
        &handle,
        ClientCommand::Key {
            keysym: 0xf6, // ö
            keycode: Some(0x27),
            down: true,
        },
    )
    .await;
    flush(&handle, &server, 2).await;

    assert_eq!(
        server.key_events(),
        vec![(0xf6, true)],
        "with scancodes off the keysym must go out as a plain KeyEvent"
    );
    let qemu = server
        .messages()
        .into_iter()
        .filter(|m| matches!(m, ClientMessage::QemuKeyEvent { .. }))
        .count();
    assert_eq!(qemu, 0, "no QemuKeyEvent may be sent in local-layout mode");
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Pointer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pointer_events_arrive_byte_correct() {
    let server = MockServer::start(MockConfig::new().size(1024, 768)).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(
        &handle,
        ClientCommand::Pointer {
            x: 0x1234,
            y: 0x0203,
            button_mask: 1,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::Pointer {
            x: 0x1234,
            y: 0x0203,
            button_mask: 0,
        },
    )
    .await;
    flush(&handle, &server, 2).await;

    let raws: Vec<Vec<u8>> = server
        .messages()
        .into_iter()
        .filter_map(|m| match m {
            ClientMessage::PointerEvent { raw, .. } => Some(raw),
            _ => None,
        })
        .collect();
    assert_eq!(
        raws,
        vec![
            vec![5, 0x01, 0x12, 0x34, 0x02, 0x03],
            vec![5, 0x00, 0x12, 0x34, 0x02, 0x03],
        ],
        "PointerEvent (message 5) must be [5, mask:u8, x:u16, y:u16] big-endian"
    );
    handle.shutdown();
}

/// REGRESSION: the release path drained the held-key map and nothing else,
/// and nothing anywhere remembered the pointer mask. A PointerEvent carries
/// the WHOLE button state (RFB 3.8 §7.5.5), so the server goes on holding
/// whatever it was last told: a button held at the moment focus went away
/// stayed held, with no state anywhere to release it from. The interrupted
/// drag then COMPLETED at wherever the next pointer event landed instead of
/// being cancelled, which is how a dragged file ends up dropped somewhere
/// nobody chose.
///
/// The order is half the fix: a modifier still held while the button goes up
/// is what the server saw when it went down, so the gesture has to end the
/// way it began. `rdp-core` learned this first, see `release_all` there.
#[tokio::test]
async fn releasing_input_lifts_a_held_button_before_it_lifts_keys() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // Ctrl held and the left button down, dragged across the desktop: the
    // shape of a copy-drag in any file manager.
    send(
        &handle,
        ClientCommand::Key {
            keysym: 0xffe3,
            keycode: None,
            down: true,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::Pointer {
            x: 100,
            y: 50,
            button_mask: 1,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::Pointer {
            x: 220,
            y: 140,
            button_mask: 1,
        },
    )
    .await;
    // Focus goes away mid-drag. This is what blur sends.
    send(&handle, ClientCommand::ReleaseAllKeys).await;
    flush(&handle, &server, 2).await;

    let msgs = server.messages();
    let lift = msgs
        .iter()
        .position(|m| {
            matches!(
                m,
                ClientMessage::PointerEvent {
                    button_mask: 0,
                    x: 220,
                    y: 140,
                    ..
                }
            )
        })
        .unwrap_or_else(|| {
            panic!("no zero-mask PointerEvent: the button is still held on the server {msgs:?}")
        });
    let key_up = msgs
        .iter()
        .position(|m| matches!(m, ClientMessage::KeyEvent { down: false, .. }))
        .expect("the held key must still be released");
    assert!(
        lift < key_up,
        "the button must go up before the modifier does: {msgs:?}"
    );

    // At the last known position, not the origin: a lift somewhere else is a
    // drag the user did not make, ending wherever we invented.
    let masks: Vec<(u16, u16, u8)> = server.pointer_events();
    assert_eq!(
        masks.last(),
        Some(&(220, 140, 0)),
        "the button must be lifted where the user left it"
    );
    handle.shutdown();
}

/// The other half of the same fix: once the mask is cleared it must stay
/// cleared, and a genuine press afterwards must still reach the server.
///
/// `rdp-core` documents the trap this guards: a stale mask there made the next
/// press no longer a transition, so it produced nothing at all and only the
/// release went out. RFB sends an absolute mask rather than transitions, so
/// the press cannot be swallowed the same way, but a mask left set would make
/// the next release send a button-up for a button nobody is holding.
#[tokio::test]
async fn a_cleared_button_mask_does_not_resurrect() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(
        &handle,
        ClientCommand::Pointer {
            x: 10,
            y: 20,
            button_mask: 4,
        },
    )
    .await;
    send(&handle, ClientCommand::ReleaseAllKeys).await;
    send(&handle, ClientCommand::ReleaseAllKeys).await;
    flush(&handle, &server, 2).await;
    assert_eq!(
        server.pointer_events(),
        vec![(10, 20, 4), (10, 20, 0)],
        "a second release has nothing left to lift and must send nothing"
    );

    // ...and the next real press is still a press.
    send(
        &handle,
        ClientCommand::Pointer {
            x: 30,
            y: 40,
            button_mask: 1,
        },
    )
    .await;
    send(&handle, ClientCommand::ReleaseAllKeys).await;
    flush(&handle, &server, 3).await;
    assert_eq!(
        server.pointer_events(),
        vec![(10, 20, 4), (10, 20, 0), (30, 40, 1), (30, 40, 0)],
        "a press after a release must still go out, and still be releasable"
    );
    handle.shutdown();
}

/// Turning view only on is one of the release path's callers, and it has to
/// lift the button that was down when the switch was thrown: from that moment
/// nothing else will ever be sent that could.
#[tokio::test]
async fn switching_view_only_on_mid_drag_lifts_the_button() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(
        &handle,
        ClientCommand::Pointer {
            x: 64,
            y: 32,
            button_mask: 1,
        },
    )
    .await;
    send(&handle, ClientCommand::SetViewOnly(true)).await;
    flush(&handle, &server, 2).await;

    assert_eq!(
        server.pointer_events(),
        vec![(64, 32, 1), (64, 32, 0)],
        "the drag must be cancelled, not left held on the server"
    );
    handle.shutdown();
}

#[tokio::test]
async fn view_only_suppresses_all_input() {
    let server = MockServer::start(MockConfig::new()).await;
    let mut opts = options(server.port());
    opts.view_only = true;
    let (handle, mut events) = spawn_session(opts);
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(
        &handle,
        ClientCommand::Key {
            keysym: 0x61,
            keycode: None,
            down: true,
        },
    )
    .await;
    send(
        &handle,
        ClientCommand::Pointer {
            x: 1,
            y: 2,
            button_mask: 1,
        },
    )
    .await;
    flush(&handle, &server, 2).await;

    assert!(server.key_events().is_empty());
    assert!(server.pointer_events().is_empty());
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Clipboard: client -> server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clipboard_text_reaches_the_server_as_a_valid_client_cut_text() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(
        &handle,
        ClientCommand::ClipboardText("hello clipboard".into()),
    )
    .await;
    flush(&handle, &server, 2).await;

    let bodies = server.cut_text_bodies();
    assert_eq!(
        bodies.len(),
        1,
        "exactly one ClientCutText (message type 6)"
    );
    let body = &bodies[0];
    assert_eq!(&body[0..3], &[0, 0, 0], "three padding bytes");
    let len = i32::from_be_bytes([body[3], body[4], body[5], body[6]]);
    assert_eq!(len, 15, "positive length = legacy Latin-1 text");
    assert_eq!(&body[7..], b"hello clipboard");
    handle.shutdown();
}

#[tokio::test]
async fn clipboard_text_is_transliterated_to_latin1_on_the_legacy_path() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(
        &handle,
        ClientCommand::ClipboardText("“smart” — dash".into()),
    )
    .await;
    flush(&handle, &server, 2).await;

    let bodies = server.cut_text_bodies();
    assert_eq!(bodies.len(), 1);
    let body = &bodies[0];
    let len = i32::from_be_bytes([body[3], body[4], body[5], body[6]]) as usize;
    let text: String = body[7..7 + len].iter().map(|&b| b as char).collect();
    assert_eq!(text, "\"smart\" - dash");
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Clipboard: server -> client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_cut_text_is_surfaced_to_the_shell() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    server.send_server_cut_text("copied on the remote side");
    let text = events
        .wait(
            DEFAULT_TIMEOUT,
            "SessionEvent::ClipboardText",
            |e| match e {
                SessionEvent::ClipboardText(t) => Some(t.clone()),
                _ => None,
            },
        )
        .await;
    assert_eq!(text, "copied on the remote side");
    handle.shutdown();
}

#[tokio::test]
async fn server_cut_text_normalises_line_endings_and_strips_the_trailing_nul() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // Latin-1 bytes with CRLF endings and the trailing NUL some servers add.
    let payload = b"caf\xe9\r\nline two\0";
    let mut body = vec![0u8, 0, 0];
    body.extend_from_slice(&(payload.len() as i32).to_be_bytes());
    body.extend_from_slice(payload);
    server.send_cut_text_body(body);

    let text = events
        .wait(
            DEFAULT_TIMEOUT,
            "SessionEvent::ClipboardText",
            |e| match e {
                SessionEvent::ClipboardText(t) => Some(t.clone()),
                _ => None,
            },
        )
        .await;
    assert_eq!(text, "café\nline two");
    handle.shutdown();
}

#[tokio::test]
async fn extended_clipboard_provide_delivers_utf8() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    server.send_cut_text_body(vnc_core::clipboard::encode_provide_text("émoji 😀\nsecond"));
    let text = events
        .wait(
            DEFAULT_TIMEOUT,
            "SessionEvent::ClipboardText",
            |e| match e {
                SessionEvent::ClipboardText(t) => Some(t.clone()),
                _ => None,
            },
        )
        .await;
    assert_eq!(text, "émoji 😀\nsecond");
    handle.shutdown();
}

#[tokio::test]
async fn extended_clipboard_notify_is_surfaced() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let flags = vnc_core::clipboard::ACTION_NOTIFY | vnc_core::clipboard::FORMAT_TEXT;
    let mut body = vec![0u8, 0, 0];
    body.extend_from_slice(&(-4i32).to_be_bytes());
    body.extend_from_slice(&flags.to_be_bytes());
    server.send_cut_text_body(body);

    let formats = events
        .wait(
            DEFAULT_TIMEOUT,
            "SessionEvent::ClipboardNotify",
            |e| match e {
                SessionEvent::ClipboardNotify { formats } => Some(*formats),
                _ => None,
            },
        )
        .await;
    assert_eq!(formats, vnc_core::clipboard::FORMAT_TEXT);
    handle.shutdown();
}

/// A notify carries no data, so it has to be answered with a request or the
/// text the user copied on the remote never crosses the wire.
#[tokio::test]
async fn extended_clipboard_notify_is_answered_with_a_request() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let flags = vnc_core::clipboard::ACTION_NOTIFY | vnc_core::clipboard::FORMAT_TEXT;
    let mut body = vec![0u8, 0, 0];
    body.extend_from_slice(&(-4i32).to_be_bytes());
    body.extend_from_slice(&flags.to_be_bytes());
    server.send_cut_text_body(body);
    flush(&handle, &server, 2).await;

    let bodies = server.cut_text_bodies();
    assert_eq!(bodies.len(), 1, "exactly one ClientCutText, the request");
    let sent = u32::from_be_bytes([bodies[0][7], bodies[0][8], bodies[0][9], bodies[0][10]]);
    assert_eq!(
        sent,
        vnc_core::clipboard::ACTION_REQUEST | vnc_core::clipboard::FORMAT_TEXT
    );
    handle.shutdown();
}

/// The flags word of an extended (negative-length) ClientCutText body, or
/// `None` for a legacy one.
fn ext_flags(body: &[u8]) -> Option<u32> {
    let len = i32::from_be_bytes([body[3], body[4], body[5], body[6]]);
    if len >= 0 || body.len() < 11 {
        return None;
    }
    Some(u32::from_be_bytes([body[7], body[8], body[9], body[10]]))
}

/// Announce server caps, which is what puts the client into Extended
/// Clipboard mode; `flushes` tracks the cumulative SetEncodings count that
/// [`flush`] counts up to.
async fn negotiate_extended_clipboard(
    handle: &vnc_core::SessionHandle,
    server: &MockServer,
    flushes: &mut usize,
) {
    let flags = vnc_core::clipboard::ACTION_CAPS
        | vnc_core::clipboard::ACTION_REQUEST
        | vnc_core::clipboard::ACTION_NOTIFY
        | vnc_core::clipboard::ACTION_PROVIDE
        | vnc_core::clipboard::FORMAT_TEXT;
    let mut body = vec![0u8, 0, 0];
    body.extend_from_slice(&(-8i32).to_be_bytes());
    body.extend_from_slice(&flags.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    server.send_cut_text_body(body);
    *flushes += 1;
    flush(handle, server, *flushes).await;
}

/// REGRESSION: a server that advertised it accepts nothing unsolicited drops
/// a bare `provide` and asks for the text with a `request` instead. That
/// request was never answered, so against those servers nothing the user
/// copied locally ever arrived, however many times they pressed paste.
#[tokio::test]
async fn a_server_request_is_answered_with_the_text_on_offer() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let mut flushes = 1; // the SetEncodings sent during the handshake

    negotiate_extended_clipboard(&handle, &server, &mut flushes).await;
    send(
        &handle,
        ClientCommand::ClipboardText("from the client pc".into()),
    )
    .await;
    flushes += 1;
    flush(&handle, &server, flushes).await;

    // Everything sent so far, so the assertions below can only be satisfied
    // by a message sent in ANSWER to the request. Without this the unsolicited
    // provide from the send above already carries the right text and the test
    // passes whether or not requests are answered at all.
    let before = server.cut_text_bodies().len();

    // The server now asks for what we announced.
    let flags = vnc_core::clipboard::ACTION_REQUEST | vnc_core::clipboard::FORMAT_TEXT;
    let mut body = vec![0u8, 0, 0];
    body.extend_from_slice(&(-4i32).to_be_bytes());
    body.extend_from_slice(&flags.to_be_bytes());
    server.send_cut_text_body(body);
    flushes += 1;
    flush(&handle, &server, flushes).await;

    let bodies = server.cut_text_bodies();
    assert!(
        bodies.len() > before,
        "the request went unanswered: nothing was sent after it"
    );
    let reply = &bodies[before];
    assert_ne!(
        ext_flags(reply).expect("extended") & vnc_core::clipboard::ACTION_PROVIDE,
        0,
        "the request must be answered with a provide"
    );
    // Decode it the way the server would.
    let mut rx = vnc_core::clipboard::ClipboardState::new();
    assert_eq!(
        vnc_core::clipboard::handle_server_cut_text(&mut rx, reply).as_deref(),
        Some("from the client pc"),
        "the provide must carry the text that was on offer"
    );
    handle.shutdown();
}

/// The announcement is the only thing a strict server acts on, so it goes out
/// with the data rather than only when the server happens to ask first.
#[tokio::test]
async fn an_extended_send_announces_the_text_as_well_as_pushing_it() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    let mut flushes = 1;

    negotiate_extended_clipboard(&handle, &server, &mut flushes).await;
    let before = server.cut_text_bodies().len();

    send(&handle, ClientCommand::ClipboardText("announce me".into())).await;
    flushes += 1;
    flush(&handle, &server, flushes).await;

    let bodies = server.cut_text_bodies();
    let sent: Vec<u32> = bodies[before..]
        .iter()
        .filter_map(|b| ext_flags(b))
        .collect();
    assert!(
        sent.iter()
            .any(|f| f & vnc_core::clipboard::ACTION_NOTIFY != 0),
        "a notify tells a server that wants no unsolicited data to ask: {sent:?}"
    );
    assert!(
        sent.iter()
            .any(|f| f & vnc_core::clipboard::ACTION_PROVIDE != 0),
        "the data still goes out for servers that accept it: {sent:?}"
    );
    handle.shutdown();
}

/// Neither peer may send an extended message before it has both sent and
/// received a caps announcement, so the server's caps must be answered.
#[tokio::test]
async fn server_clipboard_caps_are_answered_once_with_ours() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // A server caps message: flags word plus one size per advertised format.
    let server_caps = || {
        let flags = vnc_core::clipboard::ACTION_CAPS
            | vnc_core::clipboard::ACTION_REQUEST
            | vnc_core::clipboard::ACTION_NOTIFY
            | vnc_core::clipboard::ACTION_PROVIDE
            | vnc_core::clipboard::FORMAT_TEXT;
        let mut body = vec![0u8, 0, 0];
        body.extend_from_slice(&(-8i32).to_be_bytes());
        body.extend_from_slice(&flags.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body
    };
    server.send_cut_text_body(server_caps());
    server.send_cut_text_body(server_caps());
    flush(&handle, &server, 2).await;

    let bodies = server.cut_text_bodies();
    assert_eq!(bodies.len(), 1, "our caps go out once per connection");
    let body = &bodies[0];
    let len = i32::from_be_bytes([body[3], body[4], body[5], body[6]]);
    assert!(len < 0, "caps are an extended message (negative length)");
    let flags = u32::from_be_bytes([body[7], body[8], body[9], body[10]]);
    assert_ne!(flags & vnc_core::clipboard::ACTION_CAPS, 0);
    assert_ne!(flags & vnc_core::clipboard::ACTION_NOTIFY, 0);
    assert_ne!(flags & vnc_core::clipboard::FORMAT_TEXT, 0);

    // Caps advertise every supported action, notify included. Reading that as
    // an offer of data would announce a remote clipboard that does not exist.
    events.drain_for(Duration::from_millis(50)).await;
    assert!(
        !events.any(|e| matches!(e, SessionEvent::ClipboardNotify { .. })),
        "a caps announcement is not a notify"
    );
    handle.shutdown();
}

#[tokio::test]
async fn an_oversized_server_cut_text_is_rejected_as_a_protocol_error() {
    // Hostile-server hygiene: a 100 MiB claim must not be allocated.
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    let mut msg = vec![3u8, 0, 0, 0];
    msg.extend_from_slice(&(100 * 1024 * 1024i32).to_be_bytes());
    server.send_raw(msg);

    // The session tears the connection down rather than trusting the length.
    events
        .wait_state(DEFAULT_TIMEOUT, "a non-connected state", |s| match s {
            SessionState::Reconnecting { .. } | SessionState::Disconnected { .. } => Some(()),
            _ => None,
        })
        .await;
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Resize requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resize_requests_are_only_sent_once_the_server_proves_support() {
    let server = MockServer::start(MockConfig::new().size(640, 480).update(vec![
        RectSpec::ExtendedDesktopSize {
            width: 640,
            height: 480,
            reason: 0,
            status: 0,
        },
    ]))
    .await;

    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // Nothing has advertised ExtendedDesktopSize yet on this update pass, but
    // by the time the pseudo rect has been processed a request must go out.
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| r
                .messages
                .iter()
                .any(|m| matches!(m, ClientMessage::SetEncodings { .. })))
            .await
    );
    send(
        &handle,
        ClientCommand::RequestResize {
            width: 1440,
            height: 900,
        },
    )
    .await;

    let got = server
        .wait_until(DEFAULT_TIMEOUT, |r| {
            r.messages.iter().any(|m| {
                matches!(
                    m,
                    ClientMessage::SetDesktopSize {
                        width: 1440,
                        height: 900
                    }
                )
            })
        })
        .await;
    assert!(
        got,
        "SetDesktopSize must reach the server: {:?}",
        server.messages()
    );
    handle.shutdown();
}

#[tokio::test]
async fn resize_requests_are_dropped_when_the_server_never_advertised_support() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(
        &handle,
        ClientCommand::RequestResize {
            width: 1440,
            height: 900,
        },
    )
    .await;
    flush(&handle, &server, 2).await;
    events.drain_for(Duration::from_millis(100)).await;

    assert!(
        !server
            .messages()
            .iter()
            .any(|m| matches!(m, ClientMessage::SetDesktopSize { .. })),
        "no SetDesktopSize without an ExtendedDesktopSize rect first"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Quality switches
// ---------------------------------------------------------------------------

/// The manual staleness override: while it is on, the client re-fetches the
/// WHOLE screen every tick and stops depending on the server to say what
/// changed. This exists for servers whose damage tracking cannot be trusted,
/// so it must be unconditional: no settle detection, no cooldown, no
/// inference of ours may gate it.
#[tokio::test]
async fn always_refresh_keeps_requesting_full_updates() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    send(&handle, ClientCommand::SetAlwaysRefresh(true)).await;
    let before = server.messages().len();

    // FOUR full requests, unprompted, with no activity whatsoever: one per
    // stats tick. The bar is this high deliberately. Two is reachable without
    // the per-tick loop at all (the immediate apply-now request, plus a
    // settle refresh), and a test satisfied by those passes with the feature
    // deleted, which the first version of this test did.
    let got = server
        .wait_until(Duration::from_secs(8), |r| {
            r.messages[before..]
                .iter()
                .filter(|m| {
                    matches!(
                        m,
                        ClientMessage::FramebufferUpdateRequest {
                            incremental: false,
                            ..
                        }
                    )
                })
                .count()
                >= 4
        })
        .await;
    assert!(got, "always-refresh must keep re-fetching the whole screen");

    // ...and switching it off must stop them, or the bandwidth cost would be
    // permanent for anyone who ever tried the switch.
    send(&handle, ClientCommand::SetAlwaysRefresh(false)).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let quiet_from = server.messages().len();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after: usize = server.messages()[quiet_from..]
        .iter()
        .filter(|m| {
            matches!(
                m,
                ClientMessage::FramebufferUpdateRequest {
                    incremental: false,
                    ..
                }
            )
        })
        .count();
    assert_eq!(after, 0, "switching it off must stop the full re-fetches");
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Full-screen refresh throttle
// ---------------------------------------------------------------------------

/// The mock desktop, which is what a full-screen re-fetch asks for.
const MOCK_SCREEN: Rect = Rect {
    x: 0,
    y: 0,
    width: 640,
    height: 480,
};

/// Non-incremental requests for the WHOLE desktop.
///
/// The rect test is not decoration: the Fence-less round-trip probe asks for
/// a single pixel non-incrementally once a tick, so counting on the
/// incremental flag alone counts probes as re-fetches.
fn full_screen_refreshes(msgs: &[ClientMessage]) -> usize {
    msgs.iter()
        .filter(|m| {
            matches!(
                m,
                ClientMessage::FramebufferUpdateRequest {
                    incremental: false,
                    rect,
                } if *rect == MOCK_SCREEN
            )
        })
        .count()
}

/// A one-rect Raw FramebufferUpdate, built by hand so a test can push an
/// update at a moment of its choosing rather than in answer to a request.
fn raw_update(rect: Rect, colour: Rgb) -> Vec<u8> {
    let mut out = vec![0u8, 0u8]; // FramebufferUpdate, padding
    out.extend_from_slice(&1u16.to_be_bytes()); // one rect
    out.extend_from_slice(&rect.x.to_be_bytes());
    out.extend_from_slice(&rect.y.to_be_bytes());
    out.extend_from_slice(&rect.width.to_be_bytes());
    out.extend_from_slice(&rect.height.to_be_bytes());
    out.extend_from_slice(&0i32.to_be_bytes()); // Raw
    for _ in 0..rect.area() {
        out.extend_from_slice(&[colour[2], colour[1], colour[0], 0]);
    }
    out
}

/// REGRESSION: the manual Refresh arm called `send_full_refresh` directly
/// while its comment claimed it went through the always-refresh accounting.
/// A user leaning on the button queued one whole-screen re-fetch per press
/// (130 to 180 ms of the server's SHARED encoder each, which is what took
/// another client of the same server from 3 ms to 398 ms median typing
/// latency), and every press also overwrote the outstanding-request clock,
/// which suppressed the automatic always-refresh and deferred the 10 s
/// abandon for as long as the pressing went on.
#[tokio::test]
async fn hammering_the_refresh_button_does_not_queue_a_re_fetch_per_press() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    // The priming request, so the baseline below is not racing it.
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| full_screen_refreshes(&r.messages) >= 1)
            .await
    );
    let before = full_screen_refreshes(&server.messages());

    for _ in 0..5 {
        send(&handle, ClientCommand::Refresh).await;
    }
    // Proves all five presses have been processed, so the count below is
    // final rather than merely early.
    flush(&handle, &server, 2).await;

    let sent = full_screen_refreshes(&server.messages()) - before;
    assert_eq!(
        sent, 1,
        "the first press goes out, the rest wait for the server to answer it"
    );
    handle.shutdown();
}

/// REGRESSION: the outstanding-refresh clock was closed by whatever update
/// arrived first. On the pipelined path an incremental request is ALWAYS
/// already outstanding, so on a busy desktop the server answers that one
/// first (a few dirty tiles, ~10 ms) and that update was recorded as the
/// answer to the full-screen request, with a 10 ms cost. A 10 ms cooldown is
/// long expired by the next tick, so the throttle degraded back to the
/// once-per-second full-screen cadence it exists to prevent, on exactly the
/// busy server it was written for.
#[tokio::test]
async fn a_few_dirty_tiles_do_not_close_the_full_refresh_clock() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| full_screen_refreshes(&r.messages) >= 1)
            .await
    );
    let before = full_screen_refreshes(&server.messages());

    send(&handle, ClientCommand::Refresh).await;
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| full_screen_refreshes(&r.messages)
                > before)
            .await,
        "the first press must go out"
    );

    // Something else entirely comes back: 16x16 of damage, 0.08% of the
    // desktop, nothing like the answer to a whole-screen non-incremental
    // request.
    server.send_raw(raw_update(Rect::new(8, 8, 16, 16), RED));
    events.wait_framebuffer(DEFAULT_TIMEOUT).await;

    // Long enough that a cooldown started by mis-attributing that update
    // would have expired (it would have been charged at the few milliseconds
    // between the request and the update), and far short of the 10 s at which
    // a genuinely unanswered request is written off.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    send(&handle, ClientCommand::Refresh).await;
    flush(&handle, &server, 2).await;

    let sent = full_screen_refreshes(&server.messages()) - before;
    assert_eq!(
        sent, 1,
        "the server still owes us the whole screen, so nothing new may go out"
    );
    handle.shutdown();
}
