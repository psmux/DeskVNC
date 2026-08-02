//! Input and clipboard, end to end.
//!
//! Asserts the exact bytes that reach the server for key/pointer events, that
//! the stuck-modifier safety net really releases every held key, and that
//! clipboard text flows correctly in both directions.

mod common;

use std::time::Duration;

use common::mock_server::*;
use common::*;

use vnc_core::types::{ClientCommand, Rect, SessionEvent, SessionState};

const RED: Rgb = [255, 0, 0];

/// Round-trip marker: a Refresh produces a non-incremental
/// FramebufferUpdateRequest, so waiting for the Nth one proves every command
/// queued before it has been processed.
async fn flush(handle: &vnc_core::SessionHandle, server: &MockServer, nth: usize) {
    send(handle, ClientCommand::Refresh).await;
    let ok = server
        .wait_until(DEFAULT_TIMEOUT, |r| {
            r.messages
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
/// Clipboard mode; `flushes` tracks the cumulative non-incremental
/// FramebufferUpdateRequest count that [`flush`] counts up to.
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
    let mut flushes = 1; // the priming request sent at connect

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

/// REGRESSION: a mid-session SetEncodings must be chased by a full
/// non-incremental FramebufferUpdateRequest.
///
/// RealVNC drops coalesced damage while it re-configures its encoder
/// pipeline on a SetEncodings: regions that changed around the switch are
/// marked delivered but never sent, and they stay stale until something
/// else touches them. Measured live (fb_probe, twelve window animations
/// against a RealVNC server): 1076 of 3600 tiles permanently wrong without
/// the resync, 0 with it. The user-visible form was ghosted text and blocky
/// patches that healed only under the mouse.
#[tokio::test]
async fn a_quality_switch_resyncs_with_a_full_update_request() {
    let server = MockServer::start(MockConfig::new()).await;
    let (handle, mut events) = spawn_session(options(server.port()));
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // Everything the connect handshake sent (its own SetEncodings and the
    // priming full request) is history; only what follows the switch counts.
    // Two contamination hazards make the marker placement load-bearing:
    // `flush` sends a Refresh whose own full request would satisfy the
    // assertion, so it is not used before it; and `wait_connected` fires on
    // the CLIENT's state before the server has necessarily READ the priming
    // request, so the marker must wait for the handshake traffic to be
    // recorded or the priming request itself lands after the marker. Either
    // mistake makes this test pass with the resync deleted.
    assert!(
        server
            .wait_until(DEFAULT_TIMEOUT, |r| {
                r.messages.iter().any(|m| {
                    matches!(
                        m,
                        ClientMessage::FramebufferUpdateRequest {
                            incremental: false,
                            ..
                        }
                    )
                }) && r
                    .messages
                    .iter()
                    .any(|m| matches!(m, ClientMessage::SetEncodings { .. }))
            })
            .await,
        "handshake traffic must be recorded before the marker"
    );
    let before = server.messages().len();

    send(
        &handle,
        ClientCommand::SetQuality(vnc_core::types::QualityPreset::High),
    )
    .await;
    let arrived = server
        .wait_until(DEFAULT_TIMEOUT, |r| {
            r.messages[before..].iter().any(|m| {
                matches!(
                    m,
                    ClientMessage::FramebufferUpdateRequest {
                        incremental: false,
                        ..
                    }
                )
            })
        })
        .await;
    assert!(
        arrived,
        "SetEncodings must be chased by a non-incremental request; without it          a server that drops damage across the switch leaves stale regions"
    );

    let after: Vec<ClientMessage> = server.messages().drain(before..).collect();
    let set_enc = after
        .iter()
        .position(|m| matches!(m, ClientMessage::SetEncodings { .. }))
        .expect("a quality change must send SetEncodings");
    let resync = after[set_enc..].iter().find_map(|m| match m {
        ClientMessage::FramebufferUpdateRequest {
            incremental: false,
            rect,
        } => Some(*rect),
        _ => None,
    });
    let rect = resync.expect("the full request must come AFTER the SetEncodings");
    assert_eq!(
        (rect.x, rect.y, rect.width, rect.height),
        (0, 0, 640, 480),
        "the resync must cover the whole screen"
    );
    handle.shutdown();
}

/// REGRESSION: after a burst of updates goes quiet, the client must request
/// one full non-incremental repaint on its own.
///
/// This is the client enforcing eventual consistency rather than trusting
/// server damage tracking: wayvnc (every Wayland Raspberry Pi) loses track
/// of damaged regions when the client applies backpressure during window
/// animations, and the lost regions are never sent. Reproduced in the real
/// app against a real wayvnc with NO SetEncodings in flight, so the
/// switch-time resync above cannot cover it.
///
/// The quality preset is pinned (tuner disabled) so the ONLY thing that can
/// produce a post-burst full request is the settle refresh; with the tuner
/// active its own switch resync could satisfy the assertion and mask the
/// regression.
#[tokio::test]
async fn a_settled_burst_is_followed_by_a_full_consistency_refresh() {
    let rect = Rect::new(0, 0, 4, 4);
    let mut cfg = MockConfig::new().size(8, 8);
    for _ in 0..12 {
        cfg = cfg.update(vec![RectSpec::Raw { rect, colour: RED }]);
    }
    let server = MockServer::start(cfg).await;

    let mut o = options(server.port());
    o.quality = vnc_core::types::QualityPreset::High;
    let (handle, mut events) = spawn_session(o);
    events.wait_connected(DEFAULT_TIMEOUT).await;

    // The pipeline drains the queued updates back-to-back: a burst.
    for _ in 0..12 {
        events.wait_framebuffer(DEFAULT_TIMEOUT).await;
    }
    let before = server.messages().len();

    // Quiet from here. The full request must arrive unprompted.
    let got = server
        .wait_until(Duration::from_secs(6), |r| {
            r.messages[before..].iter().any(|m| {
                matches!(
                    m,
                    ClientMessage::FramebufferUpdateRequest {
                        incremental: false,
                        rect,
                    } if rect.x == 0 && rect.y == 0 && rect.width == 8 && rect.height == 8
                )
            })
        })
        .await;
    assert!(
        got,
        "a settled burst must be followed by a full consistency refresh, or \
         regions a server lost track of stay stale forever"
    );
    handle.shutdown();
}

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
