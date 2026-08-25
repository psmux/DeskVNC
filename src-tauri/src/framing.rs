//! Binary IPC framing between the shell and the webview renderer.
//!
//! The byte-exact contract lives in `src-tauri/FRAME_FORMAT.md`; keep the two
//! in sync. **Everything multi-byte is little-endian**, the JS side reads
//! with `DataView(... littleEndian = true)`.
//!
//! ## msg_type = 1, framebuffer update
//!
//! ```text
//! header (12 bytes):
//!   [u8 msg_type=1][u8 reserved=0][u16 rect_count]
//!   [u16 damage_x][u16 damage_y][u16 damage_w][u16 damage_h]
//! per rect:
//!   [u16 x][u16 y][u16 w][u16 h][u8 format][u8 reserved=0]
//!   [u32 payload_len][payload...]
//! format: 0 = RGBA raw (w*h*4 bytes)
//!         1 = JPEG (complete image)
//!         2 = CopyRect (payload = [u16 src_x][u16 src_y])
//!         3 = H.264 (payload = [u32 flags][u32 context_id][u32 ctx_flags]
//!                              [Annex-B data])
//!             flags, verbatim from the server: bit0 ResetContext,
//!                         bit1 ResetAllContexts
//!             context_id- decoder context slot (0..64), keyed by rect geometry
//!             ctx_flags, bit0 = rebuild the decoder for this context first,
//!                         bit1 = the data contains an IDR (can start a decoder)
//!             The Annex-B data may be empty: that is a control message
//!             (apply the flags, decode nothing).
//! ```
//!
//! ## msg_type = 2, cursor shape
//!
//! ```text
//!   [u8 msg_type=2][u8 reserved=0][u16 w][u16 h]
//!   [u16 hotspot_x][u16 hotspot_y][w*h*4 bytes RGBA]
//! ```
//!
//! ## msg_type = 3, PTY bytes
//!
//! Raw terminal output, remote to webview. Unlike a framebuffer rect this
//! has no natural record boundary of its own: a shell can emit one byte or
//! sixty-four kilobytes in a single read, so the header exists only to say
//! how many payload bytes follow. Kept binary end to end (see `ssh.rs` for
//! why the older base64-in-JSON path still exists for the ordinary case);
//! this channel exists for the fast-scrolling case, where base64's 33%
//! inflation, JSON string escaping, and a `serde_json::Value` allocation
//! per chunk actually show up.
//!
//! ```text
//!   [u8 msg_type=3][u8 stream][u16 reserved=0][u32 len][payload...]
//! stream: 0 = normal output, 1 = terminal reset (see
//!   crates/ssh-core/src/modes.rs: the bytes that undo whatever DEC private
//!   modes, alternate screen, etc. a dead session left on. Distinct from
//!   output so the webview can apply it even mid-escape-sequence without
//!   it being mistaken for something the remote program actually printed.)
//! ```
//! The header is 8 bytes (not 6) so `payload` starts on a 4-byte boundary
//! even though nothing in `len`'s own encoding requires it, matching the
//! rect and cursor headers above.
//!
//! ## Input events (JS -> Rust, `send_input` raw body)
//!
//! ```text
//! kind 0 pointer:      [u8 0][u16 x][u16 y][u16 button_mask]        (7 bytes)
//! kind 1 key:          [u8 1][u8 down][u32 keysym][u32 keycode]     (10 bytes)
//! kind 2 release-all:  [u8 2]                                        (1 byte)
//! kind 3 terminal input: [u8 3][u32 len][payload...]      (5 + len bytes)
//! kind 4 terminal resize: [u8 4][u16 cols][u16 rows]                (5 bytes)
//! ```

use bytes::Bytes;
use vnc_core::{ClientCommand, CursorShape, DecodedRect, Rect, RectPayload};

pub const MSG_FRAME: u8 = 1;
pub const MSG_CURSOR: u8 = 2;
pub const MSG_PTY: u8 = 3;

pub const FMT_RGBA: u8 = 0;
pub const FMT_JPEG: u8 = 1;
pub const FMT_COPY_RECT: u8 = 2;
pub const FMT_H264: u8 = 3;

/// `msg_type = 3` `stream` value: ordinary bytes read from the PTY.
pub const PTY_STREAM_OUTPUT: u8 = 0;
/// `msg_type = 3` `stream` value: a synthesized terminal-reset sequence, not
/// remote output. See the module-level doc comment above and
/// `crates/ssh-core/src/modes.rs`.
pub const PTY_STREAM_RESET: u8 = 1;

const FRAME_HEADER_LEN: usize = 12;
const RECT_HEADER_LEN: usize = 14;
/// `[u32 flags][u32 context_id][u32 ctx_flags]` ahead of the Annex-B data.
const H264_PREFIX_LEN: usize = 12;
const PTY_HEADER_LEN: usize = 8;

/// `ctx_flags` bit 0: the webview must rebuild this context's `VideoDecoder`.
pub const H264_CTX_RESET: u32 = 1 << 0;
/// `ctx_flags` bit 1: the payload contains an IDR access unit.
pub const H264_CTX_KEYFRAME: u32 = 1 << 1;

/// Largest single terminal-input payload we will decode.
///
/// 64 KiB is generous for a paste (a whole source file, easily) while
/// keeping a hostile or buggy webview from making the shell allocate an
/// unbounded amount of memory off one `send_input` call: without a cap, a
/// `len` field is just a promise the sender can lie about arbitrarily far.
const MAX_TERMINAL_INPUT_LEN: usize = 64 * 1024;

/// Encode one coalesced framebuffer update (msg_type = 1).
pub fn encode_frame(rects: &[DecodedRect], damage: &Rect) -> Vec<u8> {
    let payload_total: usize = rects
        .iter()
        .map(|r| {
            RECT_HEADER_LEN
                + match &r.payload {
                    RectPayload::Rgba(b) => b.len(),
                    RectPayload::Jpeg(b) => b.len(),
                    RectPayload::CopyRect { .. } => 4,
                    RectPayload::H264 { data, .. } => H264_PREFIX_LEN + data.len(),
                }
        })
        .sum();

    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload_total);
    out.push(MSG_FRAME);
    out.push(0); // reserved
    out.extend_from_slice(&(rects.len() as u16).to_le_bytes());
    out.extend_from_slice(&damage.x.to_le_bytes());
    out.extend_from_slice(&damage.y.to_le_bytes());
    out.extend_from_slice(&damage.width.to_le_bytes());
    out.extend_from_slice(&damage.height.to_le_bytes());

    for r in rects {
        out.extend_from_slice(&r.rect.x.to_le_bytes());
        out.extend_from_slice(&r.rect.y.to_le_bytes());
        out.extend_from_slice(&r.rect.width.to_le_bytes());
        out.extend_from_slice(&r.rect.height.to_le_bytes());
        match &r.payload {
            RectPayload::Rgba(bytes) => {
                out.push(FMT_RGBA);
                out.push(0);
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            RectPayload::Jpeg(bytes) => {
                out.push(FMT_JPEG);
                out.push(0);
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            RectPayload::CopyRect { src_x, src_y } => {
                out.push(FMT_COPY_RECT);
                out.push(0);
                out.extend_from_slice(&4u32.to_le_bytes());
                out.extend_from_slice(&src_x.to_le_bytes());
                out.extend_from_slice(&src_y.to_le_bytes());
            }
            RectPayload::H264 {
                data,
                flags,
                context_id,
                reset,
                keyframe,
            } => {
                out.push(FMT_H264);
                out.push(0);
                out.extend_from_slice(&((data.len() + H264_PREFIX_LEN) as u32).to_le_bytes());
                out.extend_from_slice(&flags.to_le_bytes());
                out.extend_from_slice(&context_id.to_le_bytes());
                let ctx_flags = (u32::from(*reset) * H264_CTX_RESET)
                    | (u32::from(*keyframe) * H264_CTX_KEYFRAME);
                out.extend_from_slice(&ctx_flags.to_le_bytes());
                out.extend_from_slice(data);
            }
        }
    }
    out
}

/// Encode a cursor-shape update (msg_type = 2).
pub fn encode_cursor(shape: &CursorShape) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + shape.pixels.len());
    out.push(MSG_CURSOR);
    out.push(0); // reserved
    out.extend_from_slice(&shape.width.to_le_bytes());
    out.extend_from_slice(&shape.height.to_le_bytes());
    out.extend_from_slice(&shape.hotspot_x.to_le_bytes());
    out.extend_from_slice(&shape.hotspot_y.to_le_bytes());
    out.extend_from_slice(&shape.pixels);
    out
}

/// Encode a chunk of PTY bytes (msg_type = 3). `stream` is
/// [`PTY_STREAM_OUTPUT`] or [`PTY_STREAM_RESET`].
pub fn encode_pty(stream: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PTY_HEADER_LEN + payload.len());
    out.push(MSG_PTY);
    out.push(stream);
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a `send_input` body into session commands.
///
/// Rejects the whole body on the first malformed event so a bad frontend
/// can't smuggle partial input through.
pub fn decode_input(body: &[u8]) -> Result<Vec<ClientCommand>, String> {
    let mut commands = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        match body[i] {
            0 => {
                // pointer: [u16 x][u16 y][u16 button_mask]
                if body.len() < i + 7 {
                    return Err("truncated pointer event".into());
                }
                let x = u16::from_le_bytes([body[i + 1], body[i + 2]]);
                let y = u16::from_le_bytes([body[i + 3], body[i + 4]]);
                let button_mask = u16::from_le_bytes([body[i + 5], body[i + 6]]);
                commands.push(ClientCommand::Pointer { x, y, button_mask });
                i += 7;
            }
            1 => {
                // key: [u8 down][u32 keysym][u32 keycode]
                if body.len() < i + 10 {
                    return Err("truncated key event".into());
                }
                let down = body[i + 1] != 0;
                let keysym =
                    u32::from_le_bytes([body[i + 2], body[i + 3], body[i + 4], body[i + 5]]);
                let keycode =
                    u32::from_le_bytes([body[i + 6], body[i + 7], body[i + 8], body[i + 9]]);
                commands.push(ClientCommand::Key {
                    keysym,
                    keycode: if keycode == 0 { None } else { Some(keycode) },
                    down,
                });
                i += 10;
            }
            2 => {
                commands.push(ClientCommand::ReleaseAllKeys);
                i += 1;
            }
            3 => {
                // terminal input: [u32 len][payload...]
                if body.len() < i + 5 {
                    return Err("truncated terminal input length".into());
                }
                let len = u32::from_le_bytes([body[i + 1], body[i + 2], body[i + 3], body[i + 4]])
                    as usize;
                // Checked before touching `body` again: a caller that lies
                // about `len` must not get the chance to make us slice past
                // the end of the buffer, and must not get an unbounded
                // allocation even if the body happens to be that long.
                if len > MAX_TERMINAL_INPUT_LEN {
                    return Err(format!(
                        "terminal input payload too large: {len} bytes (max {MAX_TERMINAL_INPUT_LEN})"
                    ));
                }
                let payload_start = i + 5;
                if body.len() < payload_start + len {
                    return Err("truncated terminal input payload".into());
                }
                let payload = &body[payload_start..payload_start + len];
                commands.push(ClientCommand::TerminalInput(Bytes::copy_from_slice(
                    payload,
                )));
                i = payload_start + len;
            }
            4 => {
                // terminal resize: [u16 cols][u16 rows]
                if body.len() < i + 5 {
                    return Err("truncated terminal resize event".into());
                }
                let cols = u16::from_le_bytes([body[i + 1], body[i + 2]]);
                let rows = u16::from_le_bytes([body[i + 3], body[i + 4]]);
                commands.push(ClientCommand::ResizeTerminal { cols, rows });
                i += 5;
            }
            other => return Err(format!("unknown input event kind: {other}")),
        }
    }
    Ok(commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_layout() {
        let rects = vec![
            DecodedRect {
                rect: Rect::new(1, 2, 2, 1),
                payload: RectPayload::Rgba(vec![0xAA; 8]),
            },
            DecodedRect {
                rect: Rect::new(10, 20, 30, 40),
                payload: RectPayload::CopyRect { src_x: 7, src_y: 9 },
            },
        ];
        let damage = Rect::new(1, 2, 39, 58);
        let buf = encode_frame(&rects, &damage);

        assert_eq!(buf[0], MSG_FRAME);
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 2); // rect_count
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 1); // damage_x
        assert_eq!(u16::from_le_bytes([buf[10], buf[11]]), 58); // damage_h
                                                                // first rect header at 12
        assert_eq!(u16::from_le_bytes([buf[12], buf[13]]), 1); // x
        assert_eq!(buf[20], FMT_RGBA);
        assert_eq!(u32::from_le_bytes([buf[22], buf[23], buf[24], buf[25]]), 8);
        // second rect follows 8-byte payload
        let r2 = 12 + 14 + 8;
        assert_eq!(u16::from_le_bytes([buf[r2], buf[r2 + 1]]), 10);
        assert_eq!(buf[r2 + 8], FMT_COPY_RECT);
        assert_eq!(
            u16::from_le_bytes([buf[r2 + 14], buf[r2 + 15]]),
            7 // src_x
        );
        assert_eq!(buf.len(), r2 + 14 + 4);
    }

    /// The H.264 rect payload is `[u32 flags][u32 context_id][u32 ctx_flags]`
    /// followed by the Annex-B bytes, all little-endian.
    #[test]
    fn h264_rect_layout() {
        let annexb = vec![0u8, 0, 0, 1, 0x65, 0x88];
        let rects = vec![DecodedRect {
            rect: Rect::new(0, 0, 64, 32),
            payload: RectPayload::H264 {
                data: annexb.clone(),
                flags: 2,
                context_id: 7,
                reset: true,
                keyframe: true,
            },
        }];
        let buf = encode_frame(&rects, &Rect::new(0, 0, 64, 32));
        let p = 12; // rect header offset
        assert_eq!(buf[p + 8], FMT_H264);
        let payload_len = u32::from_le_bytes([buf[p + 10], buf[p + 11], buf[p + 12], buf[p + 13]]);
        assert_eq!(payload_len as usize, H264_PREFIX_LEN + annexb.len());
        let body = &buf[p + 14..];
        assert_eq!(u32::from_le_bytes(body[0..4].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(body[4..8].try_into().unwrap()), 7);
        assert_eq!(
            u32::from_le_bytes(body[8..12].try_into().unwrap()),
            H264_CTX_RESET | H264_CTX_KEYFRAME
        );
        assert_eq!(&body[12..], &annexb[..]);

        // A zero-length control message still carries the 12-byte prefix.
        let ctrl = vec![DecodedRect {
            rect: Rect::new(0, 0, 64, 32),
            payload: RectPayload::H264 {
                data: Vec::new(),
                flags: 3,
                context_id: 0,
                reset: true,
                keyframe: false,
            },
        }];
        let buf = encode_frame(&ctrl, &Rect::new(0, 0, 64, 32));
        assert_eq!(buf.len(), 12 + 14 + H264_PREFIX_LEN);
    }

    #[test]
    fn input_decode() {
        let mut body = vec![0u8];
        body.extend_from_slice(&100u16.to_le_bytes());
        body.extend_from_slice(&200u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(1);
        body.push(1);
        body.extend_from_slice(&0xFF0Du32.to_le_bytes()); // keysym Return
        body.extend_from_slice(&0u32.to_le_bytes()); // no keycode
        body.push(2);

        let cmds = decode_input(&body).expect("valid body");
        assert_eq!(cmds.len(), 3);
        assert!(matches!(
            cmds[0],
            ClientCommand::Pointer {
                x: 100,
                y: 200,
                button_mask: 1
            }
        ));
        assert!(matches!(
            cmds[1],
            ClientCommand::Key {
                keysym: 0xFF0D,
                keycode: None,
                down: true
            }
        ));
        assert!(matches!(cmds[2], ClientCommand::ReleaseAllKeys));
        assert!(decode_input(&[9]).is_err());
        assert!(decode_input(&[0, 1]).is_err());
    }

    /// Byte-for-byte replicas of what `ui/src/render/input.ts` writes. These
    /// pin the layouts the webview actually emits, in particular that a
    /// pointer event is 7 bytes with NO padding byte after `kind`.
    #[test]
    fn decodes_exact_webview_packets() {
        // sendWheel(): one 14-byte body = two concatenated 7-byte pointer
        // events (button press, then release back to the resting mask).
        let wheel: [u8; 14] = [
            0, 0x2C, 0x01, 0x90, 0x01, 0x08, 0x00, // x=300 y=400 mask=1<<3
            0, 0x2C, 0x01, 0x90, 0x01, 0x00, 0x00, // same point, mask=0
        ];
        let cmds = decode_input(&wheel).expect("wheel body");
        assert_eq!(cmds.len(), 2, "a 14-byte body must be exactly two events");
        assert!(matches!(
            cmds[0],
            ClientCommand::Pointer {
                x: 300,
                y: 400,
                button_mask: 8
            }
        ));
        assert!(matches!(
            cmds[1],
            ClientCommand::Pointer {
                x: 300,
                y: 400,
                button_mask: 0
            }
        ));

        // releaseAllLocal(): kind 2 followed by a pointer reset = 8 bytes.
        let release: [u8; 8] = [2, 0, 0x0A, 0x00, 0x14, 0x00, 0x00, 0x00];
        let cmds = decode_input(&release).expect("release body");
        assert_eq!(cmds.len(), 2);
        assert!(matches!(cmds[0], ClientCommand::ReleaseAllKeys));
        assert!(matches!(
            cmds[1],
            ClientCommand::Pointer {
                x: 10,
                y: 20,
                button_mask: 0
            }
        ));

        // The old 8-byte padded pointer layout must NOT round-trip: the stray
        // pad byte shifts every field and leaves a trailing unknown kind.
        let padded: [u8; 8] = [0, 0, 0x2C, 0x01, 0x90, 0x01, 0x01, 0x00];
        match decode_input(&padded) {
            Err(_) => {}
            Ok(cmds) => assert!(
                !matches!(
                    cmds.first(),
                    Some(ClientCommand::Pointer {
                        x: 300,
                        y: 400,
                        button_mask: 1
                    })
                ),
                "the padded layout must not decode to the intended pointer"
            ),
        }
    }

    #[test]
    fn pty_frame_roundtrip_layout() {
        let payload = b"hello from the shell\n";
        let buf = encode_pty(PTY_STREAM_OUTPUT, payload);

        assert_eq!(buf[0], MSG_PTY);
        assert_eq!(buf[1], PTY_STREAM_OUTPUT);
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0); // reserved
        assert_eq!(
            u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            payload.len() as u32
        );
        assert_eq!(buf.len(), PTY_HEADER_LEN + payload.len());
        assert_eq!(&buf[PTY_HEADER_LEN..], &payload[..]);
    }

    #[test]
    fn pty_reset_stream_is_distinguishable_from_output_stream() {
        let payload = b"\x1b[!p\x1b(B\x1b[0m\x1b[r";
        let output = encode_pty(PTY_STREAM_OUTPUT, payload);
        let reset = encode_pty(PTY_STREAM_RESET, payload);

        assert_eq!(output[1], PTY_STREAM_OUTPUT);
        assert_eq!(reset[1], PTY_STREAM_RESET);
        assert_ne!(output[1], reset[1]);
        // Everything else about the two frames is identical: only the
        // `stream` byte tells the webview this is a reset, not output.
        assert_eq!(output[0], reset[0]);
        assert_eq!(&output[PTY_HEADER_LEN..], &reset[PTY_HEADER_LEN..]);
    }

    #[test]
    fn pty_empty_payload_encodes_and_decodes_cleanly() {
        let buf = encode_pty(PTY_STREAM_OUTPUT, &[]);
        assert_eq!(buf.len(), PTY_HEADER_LEN);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 0);
    }

    #[test]
    fn terminal_input_decodes_to_client_command_with_exact_payload() {
        let payload = b"echo hi\n";
        let mut body = vec![3u8];
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        body.extend_from_slice(payload);

        let cmds = decode_input(&body).expect("valid terminal input body");
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            ClientCommand::TerminalInput(bytes) => assert_eq!(&bytes[..], &payload[..]),
            other => panic!("expected TerminalInput, got {other:?}"),
        }
    }

    #[test]
    fn terminal_resize_decodes_to_cols_and_rows() {
        let mut body = vec![4u8];
        body.extend_from_slice(&80u16.to_le_bytes());
        body.extend_from_slice(&24u16.to_le_bytes());

        let cmds = decode_input(&body).expect("valid resize body");
        assert_eq!(cmds.len(), 1);
        assert!(matches!(
            cmds[0],
            ClientCommand::ResizeTerminal { cols: 80, rows: 24 }
        ));
    }

    /// A terminal-input event sandwiched between a pointer and a key event
    /// must not desynchronize the walk: the loop has to advance by exactly
    /// `5 + len` bytes for kind 3, not some fixed width.
    #[test]
    fn several_commands_concatenated_including_a_terminal_one_all_decode() {
        let mut body = vec![0u8]; // pointer
        body.extend_from_slice(&5u16.to_le_bytes());
        body.extend_from_slice(&6u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());

        body.push(3); // terminal input, 3-byte payload
        let payload = b"ls\n";
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        body.extend_from_slice(payload);

        body.push(1); // key
        body.push(1);
        body.extend_from_slice(&0x61u32.to_le_bytes()); // keysym 'a'
        body.extend_from_slice(&0u32.to_le_bytes());

        body.push(4); // resize
        body.extend_from_slice(&132u16.to_le_bytes());
        body.extend_from_slice(&43u16.to_le_bytes());

        let cmds = decode_input(&body).expect("valid concatenated body");
        assert_eq!(cmds.len(), 4);
        assert!(matches!(
            cmds[0],
            ClientCommand::Pointer {
                x: 5,
                y: 6,
                button_mask: 0
            }
        ));
        match &cmds[1] {
            ClientCommand::TerminalInput(bytes) => assert_eq!(&bytes[..], &payload[..]),
            other => panic!("expected TerminalInput, got {other:?}"),
        }
        assert!(matches!(
            cmds[2],
            ClientCommand::Key {
                keysym: 0x61,
                keycode: None,
                down: true
            }
        ));
        assert!(matches!(
            cmds[3],
            ClientCommand::ResizeTerminal {
                cols: 132,
                rows: 43
            }
        ));
    }

    #[test]
    fn truncated_terminal_input_body_returns_err_not_panic() {
        // kind byte plus a full u32 len, but the promised payload is missing
        // entirely.
        let mut body = vec![3u8];
        body.extend_from_slice(&10u32.to_le_bytes());
        assert!(decode_input(&body).is_err());

        // kind byte with not even a full length field.
        assert!(decode_input(&[3, 1, 0]).is_err());
    }

    #[test]
    fn terminal_input_len_larger_than_remaining_body_returns_err_not_panic() {
        let mut body = vec![3u8];
        body.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes
        body.extend_from_slice(b"only nine"); // actually provides 9
        assert!(decode_input(&body).is_err());
    }

    #[test]
    fn oversized_terminal_input_payload_is_rejected() {
        let mut body = vec![3u8];
        let len = (MAX_TERMINAL_INPUT_LEN + 1) as u32;
        body.extend_from_slice(&len.to_le_bytes());
        // Don't bother actually allocating the (huge) claimed payload: the
        // length check must reject this before the body is even sliced.
        assert!(decode_input(&body).is_err());
    }

    /// The whole point of a binary channel over base64 JSON: raw 0xff bytes
    /// and embedded NUL bytes, neither of which survives a JSON string,
    /// must come through byte-exact.
    #[test]
    fn binary_payload_with_0xff_bytes_and_embedded_nulls_survives_exactly() {
        let payload: Vec<u8> = vec![0xFF, 0x00, 0x01, 0xFF, 0x00, 0x80, 0xFF, 0x00];
        let mut body = vec![3u8];
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        body.extend_from_slice(&payload);

        let cmds = decode_input(&body).expect("valid binary payload");
        match &cmds[0] {
            ClientCommand::TerminalInput(bytes) => assert_eq!(&bytes[..], &payload[..]),
            other => panic!("expected TerminalInput, got {other:?}"),
        }

        // Same bytes through encode_pty, the outbound direction.
        let buf = encode_pty(PTY_STREAM_OUTPUT, &payload);
        assert_eq!(&buf[PTY_HEADER_LEN..], &payload[..]);
    }
}
