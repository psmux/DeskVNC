# Binary IPC formats (shell ⇄ webview)

This file is the byte-exact contract between `src-tauri` (encoder, see
`src/framing.rs`) and the `ui/` renderer. **All multi-byte integers are
little-endian**, read them with `DataView` using `littleEndian = true`
(e.g. `view.getUint16(off, true)`), which is also the native byte order on
every platform we ship.

## Transport overview

| Direction | Data | Mechanism |
|---|---|---|
| Rust → JS | framebuffer updates, cursor shapes | `tauri::ipc::Channel` passed as the `onEvent` argument of `connect_session`; each message arrives as an `ArrayBuffer` (`InvokeResponseBody::Raw`) |
| Rust → JS | PTY bytes | same binary `msg_type`-prefixed format as the row above, over the session's own `tauri::ipc::Channel` |
| Rust → JS | control events (state, resize, clipboard, bell, cert prompt, stats, errors) | JSON event `session://event` emitted to the session's window via `emit_to` |
| Rust → JS | discovery events | JSON event `discovery://event` (app-wide), `discovery://scan-complete` when a scan ends |
| JS → Rust | pointer/key input, terminal input, terminal resize | `invoke("send_input", <ArrayBuffer>, { headers: { "x-session-id": id } })`, raw body, format below |
| JS → Rust | thumbnail capture | `invoke("capture_thumbnail", <ArrayBuffer of raw RGBA8888>, { headers: { "x-session-id": id, "x-width": w, "x-height": h } })`, body length must be exactly `w*h*4`; Rust does the downscale + PNG encode |

Every channel message starts with a 1-byte `msg_type`. Unknown `msg_type`
values must be ignored (forward compatibility).

## msg_type = 1, framebuffer update

One message per coalesced `FramebufferUpdate`. The renderer uploads every
rect, then presents **once** per message (never per rect).

```
header (12 bytes):
  [u8  msg_type = 1]
  [u8  reserved  = 0]
  [u16 rect_count]
  [u16 damage_x]  [u16 damage_y]  [u16 damage_w]  [u16 damage_h]

then rect_count rects, each:
  [u16 x] [u16 y] [u16 w] [u16 h]
  [u8  format]
  [u8  reserved = 0]
  [u32 payload_len]
  [payload_len bytes of payload]
```

`damage_*` is the union bounding box of all rects in this update (may be
0,0,0,0 when rect_count is 0).

### Rect formats

| `format` | Meaning | Payload |
|---|---|---|
| 0 | RGBA raw | tightly packed RGBA8888, exactly `w * h * 4` bytes; upload with `texSubImage2D` |
| 1 | JPEG | a complete JPEG image of the rect; decode with `createImageBitmap(new Blob([payload]))` |
| 2 | CopyRect | 4 bytes: `[u16 src_x][u16 src_y]`, copy a `w`×`h` region from (src_x, src_y) of the *current* framebuffer to (x, y) |
| 3 | H.264 | `[u32 flags][u32 context_id][u32 ctx_flags][Annex-B data]`, `flags` is verbatim from the server (bit0 = ResetContext, bit1 = ResetAllContexts). `context_id` is the decoder-context slot (`0..63`), keyed by rect geometry and LRU-evicted, so the frontend's decoder map is bounded by construction. `ctx_flags` bit0 = rebuild this context's decoder before feeding it, bit1 = the data contains an IDR. **The Annex-B data may be empty**, that is a control message: apply the flags, decode nothing. Frames may be larger than the rect; crop bottom/right. |

> **Note:** an earlier revision of this table documented format 3 as `[u32 flags][Annex-B data]`
> with "bit 0 = keyframe". That was wrong on both counts, per RFB, `flags` bit0 is ResetContext,
> not a keyframe marker, and the payload prefix is now 12 bytes, not 4.

Rects must be applied strictly in order (CopyRect depends on the framebuffer
state produced by earlier rects).

## msg_type = 2, cursor shape

Sent when the remote cursor shape changes (client-side cursor rendering,
PRD/01 §3.5). Cursor *position* updates arrive as JSON (`cursor-position`)
because they are tiny and infrequent relative to frames.

```
  [u8  msg_type = 2]
  [u8  reserved = 0]
  [u16 width] [u16 height]
  [u16 hotspot_x] [u16 hotspot_y]
  [width * height * 4 bytes RGBA8888]
```

A 0×0 cursor means "hide the client-rendered cursor".

> Cursor pixels are **only** ever sent this way. There is no
> `cursor-update` JSON event and no base64 pixel path, the renderer must
> dispatch on the channel's `msg_type` byte, not on a JSON event.

## Input events (JS → Rust, body of `send_input`)

A body is one or more events concatenated; each starts with a 1-byte `kind`.

```
kind 0, pointer (7 bytes total):
  [u8 kind = 0] [u16 x] [u16 y] [u16 button_mask]
    x, y            framebuffer-pixel coordinates
    button_mask     RFB layout: bit0 = left, bit1 = middle, bit2 = right,
                    bits 3-6 = wheel up/down/left/right, higher bits per
                    the ExtendedMouseButtons extension

kind 1, key (10 bytes total):
  [u8 kind = 1] [u8 down] [u32 keysym] [u32 keycode]
    down       1 = press, 0 = release
    keysym     X11 keysym (0 allowed when only a scancode is known)
    keycode    XT/QEMU scancode for the QEMU Extended Key Event path;
               0 = none

kind 2, release all keys (1 byte):
  [u8 kind = 2]
    Safety escape used on window blur / before disconnect.
```

A malformed body (unknown kind, truncated event) rejects the whole invoke
with an error; nothing before the malformed event is applied.

Note there is **no padding byte** after `kind`, a pointer event is 7 bytes,
not 8. `framing::decode_input` walks the buffer by these exact widths, so an
extra byte desynchronizes every following event in the same body.

## JSON control events (`session://event`)

The payload is **flat**: `sessionId` and the `type` discriminator sit on the
same object, i.e. `{ "sessionId": "…", "type": "bell" }`. There is no nested
`event` field.

| `type` | Extra fields |
|---|---|
| `state-changed` | `state`, vnc-core `SessionState`, internally tagged on `state`, kebab-case |
| `desktop-resize` | `width`, `height` |
| `desktop-name` | `name`, **untrusted server string, render as text only, never HTML** |
| `cursor-position` | `x`, `y` (framebuffer pixels) |
| `clipboard-text` | `text`, untrusted |
| `clipboard-notify` | `formats` (u32 bitmask) |
| `bell` |, |
| `certificate-prompt` | `fingerprint`, `subject`, `isChange` (**camelCase**) |
| `stats` | `stats`, vnc-core `SessionStats`; its fields are **snake_case** (no `rename_all`) |
| `error` | `message` |
| `ended` | `durationS`, the session task finished; close or show reconnect UI |

Events are emitted with `emit_to(window_label, …)`, so only the session's own
window receives them.

The full command surface (arguments, return types, the `discovery://` events)
is documented in `src-tauri/IPC_CONTRACT.md`.

## Unknown message types and unknown JSON event types

The binary channel already says a receiver must ignore a `msg_type` it does
not know. The same rule holds for the JSON `session://event` table in
`IPC_CONTRACT.md`, and it is written down there for the same reason: it is
what lets the shell and the webview ship a new event in separate commits.

Nothing in this file changes for RDP. Decoded RDP bitmaps arrive as rect
format 0 (RGBA), an EGFX AVC420 frame as rect format 3 (H.264 Annex B), and
a pointer shape as `msg_type = 2`, exactly as for VNC. There is one path for
pixels and there is not going to be a second.

## msg_type = 3, PTY bytes

Raw terminal output for a remote shell session, remote to webview. Where the
framebuffer and cursor messages above describe a screen, this one describes
a byte stream with no record boundary of its own: a shell read can hand back
one byte or sixty-four kilobytes, so the header's only job is to say how
many payload bytes follow.

```
  [u8  msg_type = 3]
  [u8  stream]
  [u16 reserved  = 0]
  [u32 len]
  [len bytes of payload]
```

`stream`:

| Value | Meaning |
|---|---|
| 0 | normal output, bytes read from the PTY, verbatim |
| 1 | a terminal reset: the bytes the client must write to undo whatever DEC private modes, alternate screen, or bracketed paste a dead session left switched on (see `crates/ssh-core/src/modes.rs`). Kept on a separate `stream` value, not folded into output, so the webview can apply it unconditionally on reconnect without it being mistaken for something the remote program actually printed |

The header is 8 bytes, one longer than the 7 a `msg_type`, `stream`, and
`len` alone would need, so `payload` starts 4-byte aligned, matching the
rect and cursor headers above.

This message exists because base64-in-JSON (see the JSON control events
below and `src-tauri/src/commands/ssh.rs`) is fine for ordinary typing and
command output, but costs a real amount of CPU and bandwidth on a
fast-scrolling stream such as a build log: roughly 33% size inflation from
base64 itself, JSON string escaping on top of that, and a `serde_json::Value`
allocation per chunk. This channel is the same fix the framebuffer path
already uses for the same reason, applied to PTY bytes.

## Input events (JS → Rust, body of `send_input`), continued

Two more event kinds, for a remote shell session, added after the pointer,
key, and release-all kinds documented above:

```
kind 3, terminal input:
  [u8 kind = 3] [u32 len] [len bytes of payload]
    payload    raw bytes to write to the PTY (keystrokes, a paste, an
               IME commit); may contain any byte value, including NUL
    len        capped at 64 KiB (65536); a larger len is rejected, so a
               hostile or buggy webview cannot make the shell allocate
               without bound off a single event

kind 4, terminal resize (5 bytes total):
  [u8 kind = 4] [u16 cols] [u16 rows]
    cols, rows  new terminal size in character cells, not pixels; this is
                deliberately not expressed as a pixel resize, 80 columns is
                not 80 pixels and reusing the desktop-resize path would be a
                silent unit mismatch
```

These follow the same bounds-checking rule as kinds 0-2: every length is
checked against what remains of the body before any slicing happens, a
truncated or lying `len` returns an error rather than panicking or reading
out of bounds, and they participate in the same concatenated-events loop, so
a terminal-input event can appear between, say, two pointer events in one
`send_input` call.

