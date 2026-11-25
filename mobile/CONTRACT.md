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
| `identify` | `{ address, port? }` | `FoundComputer[]`. What answers at one typed name or address, for the quick connect field |

`ScanEvent` is `{ type: "found", item: FoundComputer }`, `{ type: "progress",
done, total }` or `{ type: "complete" }`.

`identify` runs `vnc_discovery::identify`: with no `port` it tries 5900 and
5901 (the RFB banner), 3389 (the RDP negotiation) and 5940 (the Boundary
greeting) at once, next to the name lookups (reverse DNS, NetBIOS and the
RDP certificate). With a `port` it tries only that port, reading first and
sending the RDP negotiation only when nothing spoke. It returns one row per
service that answered, Remote Desktop first, each with the machine's best
name and OS guess. A Boundary row's `address` carries the machine ID in front
(`<id>@192.0.2.7`), as a Boundary host is saved. Nothing answering, or a name
that does not resolve, gives `[]`, not an error. It never authenticates.

## Sessions

| Command | Args | Returns |
|---|---|---|
| `session_connect` | `{ target: ConnectTarget, onFrame: Channel<ArrayBuffer>, onEvent: Channel<SessionEvent>, neverRelay?: boolean }` | `{ sessionId }`. `neverRelay` is the Never use relays setting: Boundary then uses no relay and no address directory |
| `boundary_resolve` | `{ code }` | `{ invitation }`. Accepts `1234 5678 9012`, `123456789012` or a full `boundary1:` invitation |
| `session_input` | binary body (raw, or on Android the JSON array of numbers Tauri makes of it), headers `x-session-id`, `x-input-seq` | nothing. Body format is the desktop `send_input` format |
| `session_text` | `{ sessionId, text }` | nothing. Types a string, used by the phone keyboard |
| `session_key_combo` | `{ sessionId, combo: KeyCombo }` | nothing |
| `session_credentials` | `{ sessionId, username?, password?, save }` | nothing. Answers `credentials-required` |
| `session_trust` | `{ sessionId, fingerprint, scheme, accept }` | nothing. Answers `certificate-prompt` |
| `session_quality` | `{ sessionId, quality: "auto" \| "speed" \| "balanced" \| "quality" }` | nothing |
| `session_clipboard` | `{ sessionId, text }` | nothing |
| `session_snapshot` | RGBA body (raw, or base64 text on Android), headers `x-session-id`, `x-width`, `x-height` | nothing. Saves the thumbnail for the host card |
| `session_disconnect` | `{ sessionId }` | nothing |
| `session_save_host` | `{ sessionId, host: HostDraft }` | `Host`. Saves the computer an `adhoc` session reached and makes the session that host's. Refused until the session reached `connected` |

`session_save_host` is how a computer connected to with no saved entry is
added to Your computers. A password typed at the sign in prompt with
Remember on (`session_credentials` with `save`) is held in memory once the
computer accepts it, and goes to the vault for the new host only here. The
session's card picture, taken when it closes, is kept for the new host.
The `id` of the draft is ignored: it always makes a new host.

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
`error`, `ended`, and for Boundary `boundary-route`, `{ route: "direct" | "relay" }`,
and `boundary-input`, `{ trouble: string | null }`: why the computer is not taking
taps and keys (a Mac at its lock screen, say), or null once it does again.

## App lifecycle

When the app goes to the background, Rust keeps the session for up to 30
seconds (iOS gives about that much) and pauses frame updates. Coming back
within that window resumes. After it, the session ends and the UI offers a
one tap reconnect from the session screen.

## Local network permission (Android 17)

| Command | Args | Returns |
|---|---|---|
| `local_network_state` | none | `"granted" \| "denied"`. Whether DeskVNC holds `ACCESS_LOCAL_NETWORK` (Nearby devices in Settings). Always `"granted"` on iOS and before Android 17 |
| `local_network_ask` | none | `"granted" \| "denied"`. Shows Android's own prompt when Android still allows one, and answers with what the person chose |
| `app_settings_open` | none | nothing. Opens DeskVNC's page in Android settings |

When the permission is missing and the computer is plainly on this network
(a `.local` name, a link local address, or a private address inside one of
the phone's own subnets), `session_connect` fails at once with
`LOCAL_NETWORK_REFUSED` from `contract.ts` instead of dialing and timing out.
The session then calls `local_network_ask` and dials again on a yes. The
Nearby tab calls it before a scan. The Kotlin side is
`gen/android/app/src/main/java/com/psmux/deskvnc/mobile/LocalNetworkPlugin.kt`.

## Status bar icons (iOS)

| Command | Args | Returns |
|---|---|---|
| `system_bars` | `icons: "light" \| "dark"` | nothing. Light icons for a dark backdrop, dark ones for a light backdrop. Does nothing on Android and desktop |

The page picks the icons from what it draws under the bars
(`ui/src/lib/systemBars.ts`): light over the session's black stage in any
theme, otherwise whatever suits the theme. On Android it hands the answer to
`window.DeskVNCSystemBars.set()`, which MainActivity adds, and that sets the
navigation bar icons too.
