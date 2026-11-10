# Mobile IPC contract

The UI calls these through `@tauri-apps/api/core` `invoke`. The TypeScript
shape lives in `mobile/ui/src/api/contract.ts` and is the source of truth for
field names. `mobile/ui/src/api/mock.ts` implements it in the browser so the
UI can be built and screenshotted with no Rust at all. The Rust side lives in
`mobile/src-tauri/src/commands/`.

Field names are camelCase on the wire. Unknown event `type` values are ignored
by the UI, and unknown optional fields are ignored by Rust.

## Hosts

| Command | Args | Returns |
|---|---|---|
| `hosts_list` | none | `Host[]` |
| `hosts_save` | `{ host: HostDraft }` | `Host` |
| `hosts_delete` | `{ id }` | nothing |
| `hosts_set_secret` | `{ id, username?, password? }` | nothing. Stored in the iOS Keychain or the Android Keystore, never in the hosts file |
| `hosts_thumbnail` | `{ id }` | `string \| null`, a `data:image/jpeg;base64,...` URL, about 480 px wide |

## Discovery

| Command | Args | Returns |
|---|---|---|
| `scan_start` | `{ onEvent: Channel<ScanEvent> }` | nothing |
| `scan_stop` | none | nothing |

`ScanEvent` is `{ type: "found", item: FoundComputer }`, `{ type: "progress",
done, total }` or `{ type: "complete" }`.

## Sessions

| Command | Args | Returns |
|---|---|---|
| `session_connect` | `{ target: ConnectTarget, onFrame: Channel<ArrayBuffer>, onEvent: Channel<SessionEvent> }` | `{ sessionId }` |
| `boundary_resolve` | `{ code }` | `{ invitation }`. Accepts `1234 5678 9012`, `123456789012` or a full `boundary1:` invitation |
| `session_input` | raw body, headers `x-session-id`, `x-input-seq` | nothing. Body format is the desktop `send_input` format |
| `session_text` | `{ sessionId, text }` | nothing. Types a string, used by the phone keyboard |
| `session_key_combo` | `{ sessionId, combo: KeyCombo }` | nothing |
| `session_credentials` | `{ sessionId, username?, password?, save }` | nothing. Answers `credentials-required` |
| `session_trust` | `{ sessionId, fingerprint, scheme, accept }` | nothing. Answers `certificate-prompt` |
| `session_quality` | `{ sessionId, quality: "auto" \| "speed" \| "balanced" \| "quality" }` | nothing |
| `session_clipboard` | `{ sessionId, text }` | nothing |
| `session_snapshot` | `{ sessionId, rgba, width, height }` raw body | nothing. Saves the thumbnail for the host card |
| `session_disconnect` | `{ sessionId }` | nothing |

`ConnectTarget` has a fourth kind, `{ kind: "demo" }`, the built in demo
computer that store reviewers (and anyone curious) can try with no network.
It is handled purely in the UI: `src/api/index.ts` routes it, and every later
`session_*` call for its session id, to the in browser mock session from
`src/api/mock.ts`. Rust never sees it and needs no code for it.

`onFrame` carries `msg_type` 1 (framebuffer) and 2 (cursor) messages in the
exact byte layout of `src-tauri/FRAME_FORMAT.md`.

`onEvent` carries the JSON events of the desktop `session://event` table,
flat, with `sessionId` and `type`. The phone UI handles at least:
`state-changed`, `desktop-resize`, `desktop-name`, `cursor-position`,
`clipboard-text`, `certificate-prompt`, `credentials-required`, `stats`,
`error`, `ended`.

## App lifecycle

When the app goes to the background, Rust keeps the session for up to 30
seconds (iOS gives about that much) and pauses frame updates. Coming back
within that window resumes. After it, the session ends and the UI offers a
one tap reconnect from the session screen.
