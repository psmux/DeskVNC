# IPC contract (shell ⇄ webview)

Every Tauri command, its exact JS call signature, and every event payload.
This file plus [`FRAME_FORMAT.md`](./FRAME_FORMAT.md) (the byte-exact binary
framing) are the contract of record. **If you change a Rust signature or a
serde attribute, change this file and `ui/src/lib/types.ts` in the same
commit.**

## Rules that bite

1. **Argument names.** Tauri converts camelCase JS keys to snake_case Rust
   parameters. A Rust `host_id: String` is invoked as `{ hostId }`. Sending
   the wrong key is not a type error on either side, it fails at runtime with
   "invalid args".
2. **Casing of returned data.** Everything in `vnc_store::models` is
   `#[serde(rename_all = "camelCase")]`. `vnc_core::SessionStats` is **not**, its fields stay snake_case. `vnc_core::SessionState` and `QualityPreset`
   are `rename_all = "kebab-case"`.
3. **Whole structs, not patches.** `save_host` / `save_group` / `save_tag`
   deserialize a *complete* struct. A partial object is rejected; build from
   `blankHostProfile()` in `ui/src/lib/types.ts`.
4. **Binary bodies.** `send_input` and `capture_thumbnail` take a raw
   `ArrayBuffer` as the invoke *body* with metadata in **headers**, not a JSON
   argument object.
5. **Errors.** Every command returns `Result<_, String>`; a rejection surfaces
   as a thrown string in JS. `safeInvoke` swallows these, `mustInvoke` does not.

---

## Hosts / library, `commands/hosts.rs`

| Command | JS call | Returns |
|---|---|---|
| `list_hosts` | `invoke("list_hosts")` | `HostProfile[]` |
| `get_host` | `invoke("get_host", { hostId })` | `HostProfile \| null` |
| `save_host` | `invoke("save_host", { profile })` | `HostProfile` (echoes the input) |
| `delete_host` | `invoke("delete_host", { hostId })` | `void` |
| `touch_connected` | `invoke("touch_connected", { hostId })` | `void` |
| `list_groups` | `invoke("list_groups")` | `HostGroup[]` |
| `save_group` | `invoke("save_group", { group })` | `HostGroup` |
| `delete_group` | `invoke("delete_group", { groupId })` | `void` |
| `list_tags` | `invoke("list_tags")` | `HostTag[]` |
| `save_tag` | `invoke("save_tag", { tag })` | `HostTag` |
| `delete_tag` | `invoke("delete_tag", { tagId })` | `void` |
| `set_host_tags` | `invoke("set_host_tags", { hostId, tagIds })` | `void` |
| `list_history` | `invoke("list_history", { hostId? limit? })` | `HistoryEntry[]` (newest first, `limit` defaults to 100) |
| `get_thumbnail` | `invoke("get_thumbnail", { hostId })` | `ArrayBuffer`, raw PNG bytes, **empty** when there is no thumbnail |

`get_thumbnail` returns `tauri::ipc::Response`, so the webview receives an
`ArrayBuffer`, not base64. Build a blob URL and **revoke it** when it is
replaced or the component unmounts:

```ts
const buf = await invoke<ArrayBuffer>("get_thumbnail", { hostId });
const url = buf.byteLength ? URL.createObjectURL(new Blob([buf], { type: "image/png" })) : null;
// … later: if (url) URL.revokeObjectURL(url);
```

### `HostProfile` (`vnc_store::HostProfile`, camelCase)

`id`, `friendlyName`, `address`, `port`, `groupId`, `osHint`, `serverHint`,
`securityPref`, `qualityPref`, `colorDepth`, `scalingMode`, `keyboardMode`,
`passthrough`, `viewOnly`, `sshTunnel`, `wolMac`, `wolBroadcast`, `networkId`,
`certPin`, `hasPassword`, `thumbnailAt`, `lastConnected`, `connectCount`,
`tags` (tag ids joined from `host_tags`), `createdAt`, `updatedAt`.

The UI additionally carries **`favorite`** and **`online`**. Neither is a
column in the `hosts` table nor a field on the Rust struct, they are
client-side only and are stripped before `save_host`. Adding either to the
backend means a schema migration plus a `models.rs` field.

`qualityPref` uses the stored shorthand `"auto" | "high" | "medium" | "low" |
"bw"`. This is **not** the same spelling as the `QualityPreset` enum on the
wire, see `set_quality` below.

Other models: `HostGroup` = `{ id, name, parentId, sort }`; `HostTag` =
`{ id, name, color }`; `HistoryEntry` =
`{ id, hostId, connectedAt, durationS? securityType? disconnectReason? }`
(the last three are nullable).

---

## Credentials, `commands/credentials.rs`

| Command | JS call | Returns |
|---|---|---|
| `save_password` | `invoke("save_password", { hostId, creds })` | `void` |
| `has_password` | `invoke("has_password", { hostId })` | `boolean` |
| `delete_password` | `invoke("delete_password", { hostId })` | `void` |
| `credential_backend` | `invoke("credential_backend")` | `"OsKeychain" \| "EncryptedFile" \| "Locked"` |
| `unlock_credentials` | `invoke("unlock_credentials", { masterPassword })` | `void` |

`creds` is a `StoredCredentials`:
`{ vncPassword? vencryptUser? vencryptPass? sshPassphrase? }`.

`save_password` **merges per field**: only the fields present (non-null) in
`creds` are overwritten, so saving a VNC password never disturbs a stored SSH
passphrase and vice versa. Clearing everything is `delete_password`.

**SECURITY INVARIANT: passwords only travel JS → Rust.** There is deliberately
no `get_password` command. Stored credentials are loaded inside
`connect_session` on a blocking thread and never cross back into the webview.

`StoredCredentials` is also the at-rest keychain/vault JSON. It keeps
snake_case `serde(alias = …)`es on every field so blobs written before the
camelCase switch still deserialize.

---

## Discovery, `commands/discovery.rs`

| Command | JS call | Returns |
|---|---|---|
| `start_discovery` | `invoke("start_discovery")` | `void` (idempotent mDNS browse) |
| `stop_discovery` | `invoke("stop_discovery")` | `void` |
| `scan_network` | `invoke("scan_network", { subnets? })` | `void`, `subnets` is a list of CIDR strings; omit for the safe local interfaces. Errors if a scan is already running. |
| `deep_probe` | `invoke("deep_probe", { address, port })` | `{ securityTypes: number[] }` |
| `local_subnets` | `invoke("local_subnets")` | `string[]` of CIDRs (VPN/tunnel interfaces excluded) |
| `wake_host` | `invoke("wake_host", { profileId })` | `void`, note **`profileId`**, not `hostId` |

Results stream as events; these commands do not return hosts.

---

## Sessions, `commands/session.rs`

| Command | JS call | Returns |
|---|---|---|
| `open_session_window` | `invoke("open_session_window", { profileId })` or `{ address, port }` | `string`, the session id the new window will use |
| `connect_session` | `invoke("connect_session", { sessionId? profileId? address, port, acceptSshHostKey? onEvent })` | `SessionConnectOutcome`, see below |
| `disconnect_session` | `invoke("disconnect_session", { sessionId })` | `void` |
| `send_input` | raw body, see below | `void` |
| `set_quality` | `invoke("set_quality", { sessionId, preset })` | `void` |
| `request_resize` | `invoke("request_resize", { sessionId, width, height })` | `void` |
| `refresh_session` | `invoke("refresh_session", { sessionId })` | `void` |
| `set_view_only` | `invoke("set_view_only", { sessionId, viewOnly })` | `void` |
| `send_clipboard` | `invoke("send_clipboard", { sessionId, text })` | `void` |
| `reconnect_now` | `invoke("reconnect_now", { sessionId })` | `void` |
| `release_all_keys` | `invoke("release_all_keys", { sessionId })` | `void` |
| `capture_thumbnail` | raw body, see below | `void` |
| `trust_certificate` | `invoke("trust_certificate", { sessionId, fingerprint, permanent })` | `void` |
| `provide_credentials` | `invoke("provide_credentials", { sessionId, username, password, save })` | `void` |
| `cancel_credentials` | `invoke("cancel_credentials", { sessionId })` | `void` |
| `fullscreen_session` | `invoke("fullscreen_session", { sessionId, fullscreen, monitorIndex? })` | `void` |
| `list_active_sessions` | `invoke("list_active_sessions")` | `ActiveSession[]`, see below |

### `open_session_window`

Accepts `{ sessionId? profileId? address? port? title? }`. For a saved
host, pass only `profileId`, the shell resolves the endpoint and display name
from the store. For an ad-hoc connect, pass `address` and `port`. A missing
`sessionId` is generated as a uuid.

The window (label `session-<id>`) loads
`index.html?sessionId=…&address=…&port=…&name=…[&profileId=…]`, which
`readSessionParams()` in `ui/src/hooks/useSession.ts` reads back. **Those query
keys are part of this contract**, the session window connects itself from
them.

### `connect_session`

`onEvent` is a `Channel` and becomes the binary framebuffer/cursor transport
(see `FRAME_FORMAT.md`). Control events go to the *invoking window*, so this
must be called from the session window, not the library.

Returns a `SessionConnectOutcome`, tagged on `status`:

- `{ status: "started", sessionId }` — the session task is running; progress
  arrives as events. This is the only outcome for a profile without an
  enabled SSH tunnel.
- `{ status: "ssh-host-key-prompt", host, port, keyType, fingerprint }` —
  the profile's SSH tunnel gateway presented a key we have no pin for
  (first contact). Show the fingerprint; if the user accepts, call
  `connect_session` again with `acceptSshHostKey` set to that fingerprint.
  No session was spawned.
- `{ status: "ssh-host-key-changed", host, port, expected, actual }` — the
  pinned gateway key changed. **Hard stop**: there is deliberately no way to
  accept this from the UI; recovery is "Forget saved key" in the Files/host
  UI, exactly as for the SFTP sidecar.

The tunnel itself is configured per host in the `hosts.ssh_tunnel` JSON blob
(`{ enabled, host, port, user, auth, keyPath }`, camelCase; `auth` is the
Files panel's `"stored" | "key-file" | "agent"`). An empty `host` means "the
profile's VNC address"; an empty `user` means the local username. The SSH
host-key pin store is shared with the Files panel. Secrets never appear in
the blob: `stored` auth reads the profile's saved SSH passphrase/password
from the keychain in Rust.

### `set_quality`

`preset` is a `vnc_core::QualityPreset` with `rename_all = "kebab-case"`:
`"auto" | "high" | "medium" | "low" | "black-and-white"`.

⚠️ The stored `qualityPref` shorthand for black-and-white is `"bw"`, which is
**not** accepted here. The UI maps it in `wireQuality()`.

### `provide_credentials` / `cancel_credentials`

The answer to a `credentials-required` event (PRD/10 §3.4). The session is
**paused inside the handshake** until one of these arrives, it does not fail
the connection and ask afterwards.

- `username` is `null` for `kind: "password-only"`; send the typed value for
  `"username-and-password"`.
- `save` is the "remember this" checkbox. It does **not** write anything at
  call time: the shell keeps the credential in memory
  (`AppState::pending_credentials`, keyed by session id) and writes it to the
  keychain only when that session reaches `SessionState::Connected`. A password
  the server rejects, a cancelled prompt, a failed connect and a closed session
  all drop the intent unwritten. **A password is never persisted until it has
  been proven to work.**
- On success the shell writes a `StoredCredentials` merged over whatever the
  host already had (so an SSH passphrase survives): `vencryptUser`/
  `vencryptPass` when a username was supplied, otherwise `vncPassword`. It also
  flips the profile's `hasPassword` flag via `save_host`.
- **Ad-hoc sessions (no `profileId`) have nowhere to attach a credential.**
  `save: true` is then honoured in memory for the life of the session only, and
  is **not** an error.
- `cancel_credentials` abandons the connection attempt and clears any pending
  intent.

**SECURITY INVARIANT: passwords only travel JS → Rust**, exactly as with
`save_password`. Neither command returns anything, and there is still no
`get_password`.

### `send_input` (raw binary body)

```ts
invoke("send_input", packet /* Uint8Array */, {
  headers: { "x-session-id": sessionId },
});
```

Body layout is in `FRAME_FORMAT.md` §"Input events": pointer is
`[u8 0][u16 x][u16 y][u16 mask]` = **7 bytes with no pad byte**, key is
`[u8 1][u8 down][u32 keysym][u32 keycode]` = 10 bytes, release-all is
`[u8 2]` = 1 byte, little-endian, concatenable. A malformed body rejects the
whole invoke and applies nothing.

### `capture_thumbnail` (raw binary body)

```ts
invoke("capture_thumbnail", rgba /* Uint8Array */, {
  headers: {
    "x-session-id": sessionId,
    "x-width": String(width),
    "x-height": String(height),
  },
});
```

The body must be tightly packed, top-down RGBA8888 of **exactly**
`width * height * 4` bytes, or the command errors. Dimensions are capped at
16384. Rust does the downscale and PNG encode. Produce the body with
`WebGLRenderer.readFramebufferRGBA()`, it reads back the frame texture through
an FBO, so rows already come out top-down and must not be flipped.

Two cases are a **silent no-op** (`Ok`, nothing stored), not an error:

- the session has no `profileId` (ad-hoc connect, nothing to attach it to);
- another capture for the same session landed less than 500 ms ago
  (`thumbnail::MIN_CAPTURE_GAP`), so a renderer looping per frame cannot make
  the shell re-encode a PNG per frame.

The host id is resolved from the live session registry, never from the request,
so a session window can only ever write its own host's thumbnail.

On a successful write the shell broadcasts
[`library://thumbnail`](#librarythumbnail--app-wide-json).

### `list_active_sessions`

Every session currently registered **and still live**, entries that are
already unwinding are filtered out (they announce themselves as `ended`
moments later). Returns `ActiveSession[]` (**camelCase**):

```ts
{ sessionId: string; profileId: string | null; address: string; port: number }
```

`profileId` is `null` for an ad-hoc connect. This is the seed for the
Library's connected-machine map; changes after the call arrive as
[`sessions://event`](#sessionsevent--app-wide-json) /
[`sessions://stats`](#sessionsstats--app-wide-json) broadcasts.

---

## Keyboard capture, `commands/capture.rs`

Native shortcut pass-through (PRD/06 §3 Tier 2). Wrapped by typed helpers in
`ui/src/lib/tauri.ts`; prefer those over raw `invoke`.

| Command | JS call | Returns |
|---|---|---|
| `capture_start` | `invoke("capture_start", { sessionId })` | `CaptureStatus` |
| `capture_stop` | `invoke("capture_stop", { sessionId })` | `CaptureStatus` |
| `capture_status` | `invoke("capture_status")` | `CaptureStatus` |
| `capture_permission_granted` | `invoke("capture_permission_granted")` | `boolean`, never prompts |
| `capture_request_permission` | `invoke("capture_request_permission")` | `void`, non-blocking; macOS only |

### `CaptureStatus`

`vnc_input_capture::CaptureStatus`, **internally tagged on `state`,
kebab-case**, the same shape convention as `SessionState`:

```ts
| { state: "active" }
| { state: "inactive" }
| { state: "permission-required" }
| { state: "unsupported"; reason: string }
```

⚠️ **`permission-required` and `unsupported` are returned as `Ok`, not as
rejections.** They are states the UI renders (the Accessibility explainer, the
Wayland/secure-input note), not failures. Only a genuine backend fault rejects.

`unsupported` is not only Wayland: macOS reports it while another process holds
secure keyboard entry, because the event tap then receives nothing. `reason` is
a human-readable sentence, render as text.

### Ownership and auto-release

Capture is global (one hook per process) but owned by one session at a time.

- `capture_start` takes ownership over from another session; it is idempotent
  for the same one.
- `capture_stop` from a session that does **not** own capture is a no-op, not
  an error.
- The shell releases capture without being asked on session-window blur, window
  close/destroy, app exit, and the `Ctrl+Alt+Shift+Esc` global shortcut. Blur
  only *disarms*, focusing the window again re-arms if the user still has
  pass-through switched on. Everything else clears the intent.
- Intercepted keys are injected into the session as `ClientCommand::Key` with
  the XT scancode in `keycode`, i.e. the same path `send_input` uses. They are
  **not** echoed back to the webview.

`capture_request_permission` must only ever be called from an explicit user
action, after the explanation, PRD/06 §3 forbids demanding Accessibility at
launch.

---

## Events

### `session://event`, per-session control (JSON)

Emitted with `emit_to(window_label, …)`, so only the session's own window
receives it. **The payload is flat**, `sessionId` sits alongside the `type`
discriminator, there is no nested `event` object.

```jsonc
{ "sessionId": "…", "type": "desktop-resize", "width": 1920, "height": 1080 }
```

| `type` | Extra fields |
|---|---|
| `state-changed` | `state`, `SessionState`, internally tagged on `state`, kebab-case |
| `desktop-resize` | `width`, `height` |
| `desktop-name` | `name`, **untrusted**, render as text only |
| `cursor-position` | `x`, `y` (framebuffer pixels) |
| `clipboard-text` | `text`, **untrusted** |
| `clipboard-notify` | `formats` (u32 bitmask) |
| `bell` |, |
| `certificate-prompt` | `fingerprint`, `subject`, `isChange` (**camelCase**) |
| `credentials-required` | `request`, a `CredentialRequest` (**camelCase**); the session is PAUSED until `provide_credentials`/`cancel_credentials` |
| `stats` | `stats`, `SessionStats`, fields **snake_case** |
| `error` | `message` |
| `ended` | `durationS`, the session task is fully gone |

`SessionState` variants (tag `state`): `idle`, `resolving`, `connecting`,
`authenticating` + `method`, `negotiating`, `connected`, `reconnecting` +
`{ attempt, next_retry_ms, reason }`, `disconnected` + `{ reason, can_retry }`.
The inner field names are snake_case.

`SessionStats`: `rtt_ms`, `throughput_bps`, `throughput_up_bps`, `fps`,
`decode_ms`, `bytes_received`, `bytes_sent`, `rects_decoded`,
`current_encoding`, `jpeg_quality`. The `*_up`/`_sent` pair is the TX mirror
of the RX numbers: `bytes_sent` is cumulative bytes written to the transport
(plaintext side, same layer as `bytes_received`) and `throughput_up_bps` the
TX bits/sec over the 1 s stats tick.

`CredentialRequest` (`vnc_core::CredentialRequest`, camelCase):

```ts
{
  method: string;            // "VNC Authentication", "VeNCrypt (X509Plain)", untrusted text
  kind: "password-only" | "username-and-password";   // kebab-case
  attempt: number;           // 1-based; > 1 means the previous answer was rejected
  error: string | null;      // why the previous attempt failed, untrusted text
  truncatesPassword: boolean;// DES methods truncate to 8 chars; the UI MUST warn
  usernameHint: string | null;
}
```

The prompt must render **above** the connecting overlay, the handshake is
still in `authenticating`, so that scrim is up while the dialog is showing.

**Cursor shapes are not here.** They arrive as binary `msg_type = 2` on the
`connect_session` channel. There is no `cursor-update` JSON event.

### `sessions://event`, app-wide (JSON)

Session lifecycle, broadcast with `emit` (every window) **in addition to** the
per-window `session://event` above, so the Library can track which machines
are connected without owning any session window. Flat payloads on a `type`
discriminator, top-level keys **camelCase**:

| Payload | When |
|---|---|
| `{ type: "started", sessionId, profileId, address, port }` | `connect_session` registered the session (`profileId` is `null` for ad-hoc) |
| `{ type: "state", sessionId, state }` | every state change; `state` is **only the kebab-case tag** (`"connecting"`, `"connected"`, `"reconnecting"`, `"disconnected"`, …), never the full `SessionState` object |
| `{ type: "ended", sessionId }` | the session task is fully gone and its registry entry removed |

Seed initial state with [`list_active_sessions`](#list_active_sessions), anything broadcast before the listener registered is lost.

### `sessions://stats`, app-wide (JSON)

Broadcast with `emit` once per stats tick (1 Hz per connected session), in
addition to the per-window `stats` event:

```jsonc
{ "sessionId": "…", "profileId": "…|null", "address": "…", "port": 5900,
  "stats": { /* full SessionStats, fields snake_case, see above */ } }
```

Top-level keys are **camelCase**; the `stats` object keeps its snake_case
fields, exactly as in `session://event`.

### `library://live-previews` / `library://preview`, app-wide (JSON, webview-emitted)

The live-tile-preview pair. Unlike everything above, **both are emitted from
JS** (`emit` in `@tauri-apps/api/event`), the shell never sends them; it only
grants `core:event:default` so they can cross windows. Constants and payload
types live in `ui/src/state/SessionsContext.tsx`.

- `library://live-previews`, `{ enabled: boolean }`. The Library broadcasts it
  when the "Live previews" toggle flips. The persisted source of truth is the
  app-setting key **`livePreviews`** (`"1"` / `"0"`, default off, PRD/03 §3.1)
  via `get_app_setting`/`set_app_setting`; session windows read the setting
  once at startup (they have `allow-get-app-setting` for exactly this) and
  follow this event thereafter.
- `library://preview`, one downscaled frame from a session window's publisher
  (`ui/src/hooks/useLivePreview.ts`, ~2 fps while enabled + connected):

  ```jsonc
  { "sessionId": "…",
    "key": "…",          // profileId, or "discovered:<address>:<port>", // the same key the thumbnail store uses
    "address": "…", "port": 5900,
    "dataUrl": "data:image/jpeg;base64,…",   // ≤360 px wide
    "width": 360, "height": 225 }
  ```

  The publisher must never run while a credential/certificate prompt is up
  (PRD/03 §3.2, a login screen must not leak onto a Library tile), and the
  Library must accept only `data:image/…` URLs from this event before putting
  one in an `<img src>`.

### `capture://event`, app-wide (JSON)

```jsonc
{ "status": { "state": "active" }, "sessionId": "…" }
```

Emitted with `emit` (not `emit_to`) so every window's capture indicator agrees.
`sessionId` is the session the change concerns, or **`null` for a broadcast
force-release** (the `Ctrl+Alt+Shift+Esc` escape hatch, focus moving to a
non-session window, app exit). A `null` + `inactive` payload means "capture was
taken away from whoever had it", the UI must flip its own pass-through toggle
back off on that, or it will claim pass-through is on while nothing is grabbed.

`status` is the same `CaptureStatus` the commands return.

### `library://thumbnail`, app-wide (JSON)

```jsonc
{ "hostId": "…", "capturedAt": 1753747200 }
```

Emitted with `emit` (not `emit_to`) after `capture_thumbnail` writes a PNG: the
session that captured it lives in its own window, and the Library that has to
repaint the tile lives in another. `capturedAt` is unix seconds and matches the
host's new `thumbnailAt`.

The Library keeps tile images in a per-host cache, so on this event it must
**revoke the old blob URL, drop the cache entry and re-read `get_thumbnail`**, and also move that host's `thumbnailAt`, since a host that never had a
thumbnail would otherwise never ask for one. See
`ui/src/state/HostsContext.tsx`.

### `discovery://event`, app-wide (JSON)

`vnc_discovery::DiscoveryEvent` is an externally-tagged Rust enum
(`{"Found":{…}}`) whose host struct has no stable id and uses `IpAddr` /
`SystemTime` field types. The shell **normalizes** it in
`commands/discovery.rs::event_json`; the webview only ever sees this shape:

| Payload | Meaning |
|---|---|
| `{ type: "found", host }` | new host |
| `{ type: "updated", host }` | details changed |
| `{ type: "lost", id }` | host gone (mDNS removal / TTL), **or absorbed into another row**, see de-duplication below |
| `{ type: "scan-progress", done, total }` | Rust's `scanned` is renamed `done` |
| `{ type: "scan-complete", found }` | `found` = servers discovered |
| `{ type: "error", message }` | non-fatal |

`host` is a `DiscoveredHost`:

```ts
{ id, name, address, port, osHint, serverHint, securityHint,
  security, securityTypes, source, mac, alternateMacs, nameSource,
  savedHostId }
```

- `id` is `"<address>:<port>"`, derived, because `lost` carries only an
  address and port.
- `osHint` is `macos` | `windows` | `linux` | `qemu` | `unknown`; cosmetic
  only. It is **proof first, guess second**: when `nameSource` is one of the
  three Windows-only services it is `windows` outright, and only otherwise does
  it fall back to sniffing substrings out of `serverHint`/`name` (which is what
  used to mislabel a Windows box running TigerVNC as Linux).
- `nameSource` is which rung of the resolution ladder produced `name`, or
  `null`. One of:

  | `nameSource` | Proves Windows? |
  |---|---|
  | `netbios` | **yes**, NetBIOS node status, UDP 137 |
  | `msrpc-epm` | **yes**, MSRPC endpoint mapper, TCP 135 |
  | `rdp-cert` | **yes**, the RDP certificate `CN`, TCP 3389 |
  | `mdns-ptr` | no, Avahi answers it on every Linux desktop |
  | `llmnr` | no, `systemd-resolved` implements it too |
  | `reverse-dns` | no, that is the DHCP server talking |
  | `null` | no, the name came from the mDNS `_rfb._tcp` browse, or there is no name |

- `mac` is the primary MAC and `alternateMacs` the rest (usually `[]`). A
  dual-homed machine is **one row with one MAC per adapter**, and Wake-on-LAN
  may need either, so nothing is dropped when two rows are collapsed.
- `security` is `verified` | `unverified` | `unencrypted` | `unknown`, derived
  from `securityTypes`. Only a `deep_probe` fills `securityTypes`, so an
  un-probed host is `unknown`, never optimistically "secure".
- `savedHostId` is always `null` from the shell; the UI de-dupes discovered
  entries against its own host list.
- `name` / `serverHint` are **server-derived and untrusted**, text only.
- A scanned host is emitted the moment its banner is read, so its first
  `found` usually has `name` equal to the address and `mac`/`nameSource`
  `null`. Hostname resolution (mDNS PTR / reverse DNS / NetBIOS / LLMNR /
  MSRPC / RDP certificate) runs alongside the scan and lands ~0.5 s later as an
  `updated` event on the **same `id`**, which is where `name`, `mac` and
  `nameSource` typically appear. Hosts on locked-down firewalls answer none of
  it and keep showing their address.

**One machine is one row, and a row can disappear into another.** Everything is
de-duplicated by `vnc_discovery::HostRegistry` before it is emitted. A late
name is what reveals that two already-listed rows are one dual-homed machine
(wired + wireless, two addresses, two MACs, one name), and collapsing them
emits **two events for one sighting, in order**:

1. `{ type: "lost", id }` for the absorbed row, then
2. `{ type: "updated", host }` for the survivor, which **keeps the `id` it
   already had**, the tile the user is looking at is never deleted and
   re-added, and inherits the other row's address and MAC.

So a `lost` is not necessarily a machine going away; treat it purely as "remove
this id from the list".

### `discovery://scan-complete`, app-wide (JSON)

Payload is `string | null`: an error message, or `null` on success. Emitted
once when a `scan_network` run finishes, in addition to the
`{ type: "scan-complete" }` event above.

---

## File transfer, `commands/files.rs`

SFTP sidecar (PRD/08 §2.1): a **second** connection to the same host over SSH,
independent of the VNC session, because there is no interoperable RFB file
transfer. Commands live on the session window only.

| Command | JS call | Returns |
|---|---|---|
| `files_probe` | `invoke("files_probe", { host, port? })` | `boolean`, never rejects; `port` defaults to 22 |
| `files_connect` | `invoke("files_connect", { sessionId, config, acceptHostKey? })` | `ConnectOutcome` |
| `files_disconnect` | `invoke("files_disconnect", { sessionId })` | `void` |
| `files_status` | `invoke("files_status", { sessionId })` | `FilesStatus` |
| `files_home` | `invoke("files_home", { sessionId })` | `string` |
| `files_list` | `invoke("files_list", { sessionId, path })` | `RemoteEntry[]` |
| `files_mkdir` | `invoke("files_mkdir", { sessionId, path })` | `void` |
| `files_remove` | `invoke("files_remove", { sessionId, path, recursive? })` | `void` |
| `files_rename` | `invoke("files_rename", { sessionId, from, to })` | `void` |
| `files_upload` | `invoke("files_upload", { sessionId, localPaths, remoteDir })` | `string[]`, one transfer id per path |
| `files_download` | `invoke("files_download", { sessionId, remotePaths, localDir })` | `string[]` |
| `files_cancel` | `invoke("files_cancel", { sessionId, transferId })` | `boolean`, false if the id is already finished |
| `files_local_home` | `invoke("files_local_home")` | `string` |
| `files_local_list` | `invoke("files_local_list", { path? })` | `LocalEntry[]` |
| `files_local_mkdir` | `invoke("files_local_mkdir", { path })` | `void` |
| `files_local_rename` | `invoke("files_local_rename", { from, to })` | `void` |
| `files_local_remove` | `invoke("files_local_remove", { path, recursive? })` | `void` |

The `files_local_*` commands exist because the **fs plugin is deliberately not
enabled** (PRD/08 §4). They take absolute paths only, refuse a filesystem root,
and the paths come from the native dialog or from a listing the user navigated
to, never from a remote directory listing.

### `files_connect`

`config` is a `FilesConnectRequest`:
`{ host, port? username, auth? keyPath? profileId? defaultRemoteDir? conflict? }`.

- `auth` is `"stored" | "key-file" | "agent"` (default `"stored"`).
- **SECURITY INVARIANT: no secret is ever part of `config`.** The webview picks
  an auth *kind*; the passphrase/password is read from the keychain inside
  `files_connect` on a blocking thread. `vnc_files::SshAuth` implements
  `Deserialize` but **not** `Serialize`, so it cannot travel back out.
- An empty `username` means "the same user as this machine".
- `conflict` is `"resume" | "skip" | "overwrite" | "rename"` (default
  `"resume"`, the only policy that satisfies "an interrupted transfer resumes
  rather than restarting").

`ConnectOutcome` is internally tagged on **`status`**, kebab-case:

| `status` | Fields | Meaning |
|---|---|---|
| `connected` | `host`, `port`, `username`, `home` | ready |
| `host-key-prompt` | `host`, `port`, `keyType`, `fingerprint` | first contact, show the fingerprint, then call `files_connect` again with `acceptHostKey` set to it |
| `host-key-changed` | `host`, `port`, `expected`, `actual` | **hard stop**; `acceptHostKey` cannot override it |

Host-key pins live in `<appData>/ssh_host_keys.json`
(`vnc_files::HostKeyStore`, camelCase), the SSH analogue of the `cert_pins`
table used for TLS TOFU.

`FilesStatus` = `{ connected, host, port, username, home, activeTransfers, queueLimit }`.

`RemoteEntry` = `{ name, path, isDir, size, modified, mode, isSymlink }`, **server-supplied and untrusted**, render as text. `LocalEntry` is the same
minus `mode`.

### `files://event`, per-session transfer progress (JSON)

Emitted with `emit_to(window_label, …)` like `session://event`, with the same
flat shape: `sessionId` sits alongside a kebab-case `type` discriminator.

```jsonc
{ "sessionId": "…", "type": "progress", "id": "…", "transferred": 5242880,
  "total": 10485760, "bytesPerSec": 1048576.0 }
```

| `type` | Extra fields |
|---|---|
| `started` | `id`, `name`, `total`, `direction` (`"upload" \| "download"`) |
| `progress` | `id`, `transferred`, `total`, `bytesPerSec`, throttled to ~10/sec per transfer |
| `completed` | `id` |
| `failed` | `id`, `error` |
| `cancelled` | `id` |

Exactly one terminal event (`completed`/`failed`/`cancelled`) per `id`. At most
3 transfers run at once; files inside one folder tree run sequentially.
