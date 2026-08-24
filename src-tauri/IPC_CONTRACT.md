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
6. **Where the types live.** The protocol agnostic half of the contract
   (`SessionState`, `SessionEvent`, `SessionStats`, `ClientCommand`,
   `CredentialRequest`, `QualityPreset`, `PinScheme`, `Rect`) moved from
   `vnc-core` into the `remote-core` crate, and pixel conversion moved into
   `remote-pixel`, so a second protocol can share them. Both are re-exported
   at their old `vnc_core::` paths, so every name in this document still
   resolves where it did. **Nothing on the wire changed**: the same JSON keys,
   the same kebab-case tags, the same snake_case `SessionStats`. The shell now
   spawns a session through `ProtocolRegistry` in `src-tauri/src/state.rs`
   rather than calling `Session::spawn` directly; a lookup for a protocol this
   build does not implement returns `None` and `connect_session` rejects with
   a message.

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
| `set_hosts_group` | `invoke("set_hosts_group", { hostIds, groupId? })` | `void` |
| `add_tag_to_hosts` | `invoke("add_tag_to_hosts", { hostIds, tagId })` | `void` |
| `remove_tag_from_hosts` | `invoke("remove_tag_from_hosts", { hostIds, tagId })` | `void` |
| `list_history` | `invoke("list_history", { hostId? limit? })` | `HistoryEntry[]` (newest first, `limit` defaults to 100) |
| `get_thumbnail` | `invoke("get_thumbnail", { hostId })` | `ArrayBuffer`, raw PNG bytes, **empty** when there is no thumbnail |

`set_hosts_group`, `add_tag_to_hosts` and `remove_tag_from_hosts` are the
bulk counterparts to `save_host` and `set_host_tags`, for a multi-selection
drag in the Library. Each runs as one database transaction: either every host
in `hostIds` is updated, or (on error, e.g. an unknown `groupId`) none is. An
empty `hostIds` is a no-op, not an error. `groupId` omitted or `null` on
`set_hosts_group` removes every host in the selection from its group.
`add_tag_to_hosts`/`remove_tag_from_hosts` touch only the one tag named by
`tagId`, every other tag already on each host is left alone, unlike
`set_host_tags`, which replaces a single host's whole tag set.

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
`tags` (tag ids joined from `host_tags`), `createdAt`, `updatedAt`,
`protocol`, `rdpSettings`.

`protocol` is `"vnc"` (the default) or `"rdp"`. It is text rather than an
enum so a protocol a future build adds is a row and not a schema change, and
so a value this build does not recognise stays listable, editable and
deletable rather than becoming a tile that vanished. `connect_session`
refuses to dial such a profile, with a message, rather than falling back to
VNC.

`rdpSettings` is a nullable JSON blob of RDP-only options, `null` for a VNC
host. `null` and `"{}"` are different and must stay different: "not an RDP
profile" is not "an RDP profile with nothing set". The store never parses it,
so a malformed blob cannot break the library; `connect_session` is where it
is read, and there a parse failure **fails the connect** rather than
substituting defaults, because defaulting would turn a deliberate "network
level authentication required" into whatever this build happens to default
to. See [the `rdpSettings` blob](#the-rdpsettings-blob).

Both fields carry `#[serde(default)]` on the Rust side, which is not
decoration: `save_host` deserializes a **whole** `HostProfile`, so without
them a webview build predating these fields would fail every save with
"invalid args".

The UI additionally carries **`favorite`** and **`online`**. Neither is a
column in the `hosts` table nor a field on the Rust struct, they are
client-side only and are stripped before `save_host`. Adding either to the
backend means a schema migration plus a `models.rs` field.

`qualityPref` uses the stored shorthand `"auto" | "high" | "medium" | "low" |
"bw"`. This is **not** the same spelling as the `QualityPreset` enum on the
wire, see `set_quality` below.

Other models: `HostGroup` = `{ id, name, parentId, sort }`; `HostTag` =
`{ id, name, color }`; `HistoryEntry` =
`{ id, hostId, connectedAt, durationS? securityType? disconnectReason?,
protocol }` (the three `?` fields are nullable). `protocol` is `"vnc"` or
`"rdp"`; rows written before the column existed read `"vnc"`, which is what
they were. For an RDP row the `securityType` vocabulary is `nla-ntlm`, `tls`
and, from phase 3, `nla-kerberos`, the same tokens the `authenticating`
state carries.

### The `rdpSettings` blob

camelCase JSON, mirroring `vnc_store::RdpSettings`, which flattens
`remote_core::RdpOptions` into itself so the blob is one flat field list
rather than two nested ones.

```jsonc
{ "v": 1,                                  // blob version, absent means 1
  "clipboard": true, "microphone": false,
  "consoleSession": false, "restrictedAdmin": false,
  // …RdpOptions, flattened:
  "serverName": null, "domain": "CORP",
  "nla": "required",                       // "required" | "allow-fallback"
  "legacyTls": false,
  "colorDepth": "auto",                    // "auto"|"bpp15"|"bpp16"|"bpp24"|"bpp32"
  "codecs": { "uncompressed": true, "interleavedRle": true, "planar": true,
              "nscodec": true, "remotefx": true, "clearcodec": true,
              "progressive": true, "avc420": true, "avc444": true },
  "audio": "play-locally",                 // "play-locally"|"leave-at-server"|"off"
  "monitors": "primary",                   // "primary" | "all" | { "selected": [0,1] }
  "dynamicResolution": true,
  "keyboardLayout": 0, "clientName": "",
  "performance": { "disableWallpaper": false, "disableFullWindowDrag": false,
                   "disableMenuAnimations": false, "disableTheming": false,
                   "disableCursorShadow": false, "disableCursorBlinking": false,
                   "enableFontSmoothing": false, "enableDesktopComposition": false },
  "gateway": null, "autologon": true, "kdcProxyUrl": null,
  "sendMstshashCookie": false, "allowAutoReconnect": true,
  "desktopScaleFactor": 100 }
```

**No secret ever appears in this blob.** The domain does, because a domain is
not a secret and belongs with the connection configuration; the user name and
password live in the keychain. That is the same rule `sshTunnel` states.

Unknown fields are ignored, so a blob written by a newer build still parses.
What a newer build cannot do is change what an existing field *means* without
bumping `v`, and a blob whose `v` exceeds what this build understands is an
error rather than a downgrade. Field level defaults handle a field being
added or removed; `v` handles a field whose meaning changed, which is on the
roadmap for the codec set and the gateway block.

An editor that round trips this blob **must re-emit fields it does not
recognise**. Parsing into a typed object and writing a fresh one drops a
newer build's fields silently, and the one that matters is `legacyTls`: the
host quietly stops being reachable. Losing a relaxation fails in the safe
direction, but it still fails.

---

## Credentials, `commands/credentials.rs`

| Command | JS call | Returns |
|---|---|---|
| `save_password` | `invoke("save_password", { hostId, creds })` | `void` |
| `has_password` | `invoke("has_password", { hostId, protocol? })` | `boolean` |
| `delete_password` | `invoke("delete_password", { hostId })` | `void` |
| `credential_backend` | `invoke("credential_backend")` | `"OsKeychain" \| "EncryptedFile" \| "Locked"` |
| `unlock_credentials` | `invoke("unlock_credentials", { masterPassword })` | `void` |

`creds` is a `StoredCredentials`:
`{ vncPassword? vencryptUser? vencryptPass? sshPassphrase? rdpUser? rdpDomain?
rdpPassword? }`.

`has_password`'s `protocol` narrows the question to "a credential this
protocol could use": `"rdp"` asks for `rdpPassword`, `"vnc"` for
`vncPassword` or `vencryptPass`. Omit it and the answer is "any credential at
all", which is what the key icon has always meant and stays the behaviour for
a caller that predates the argument. With two protocols the coarse answer
starts lying: a host holding only an SSH passphrase would claim to have what
it needs.

The three `rdp*` fields carry no snake_case `alias`, unlike the four above
them. Those aliases exist for one specific reason, blobs written before the
camelCase switch, and no such blob can contain a field that did not exist
then.

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
| `deep_probe` | `invoke("deep_probe", { address, port, protocol? })` | `{ protocol: "vnc", securityTypes: number[] }` or `{ protocol: "rdp", rdp: RdpCaps }` |
| `local_subnets` | `invoke("local_subnets")` | `string[]` of CIDRs (VPN/tunnel interfaces excluded) |
| `wake_host` | `invoke("wake_host", { profileId })` | `void`, note **`profileId`**, not `hostId` |

`deep_probe` dispatches on `protocol`, which the caller passes and the shell
never infers from the port. A port number says nothing about what is behind
it, and sending an RFB handshake at something else is the mistake
`connect_session` already refuses to make. Absent means `"vnc"`, which is
what every caller predating the argument meant. The VNC probe completes the
RFB version handshake and reads the offered security types, closing before it
authenticates. The RDP probe sends a second X.224 negotiation advertising
`PROTOCOL_SSL` alone, which is the only way to learn whether NLA is
*required* rather than merely available.

`scan_network` reads two settings out of the store's KV table, both defaulting
on: `probe_other_services` (names disclosed by MSRPC on 135 and the RDP
certificate on 3389) and `probe_rdp` (one extra connection per address, to
3389, without which an RDP-only machine is invisible to the scan). Both take
the same politeness permit as every RFB probe, so the rate cap stays a cap on
the total rather than becoming one per service.

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

Accepts `{ sessionId? profileId? address? port? title? protocol? }`. For a
saved host, pass only `profileId`, the shell resolves the endpoint, the
display name and the protocol from the store. For an ad-hoc connect, pass
`address` and `port`, and `protocol` when it is not VNC. A missing
`sessionId` is generated as a uuid. A missing `port` falls back to the
protocol's default port, which the registry answers (5900 or 3389) rather
than a literal in this command.

The window (label `session-<id>`) loads
`index.html?sessionId=…&address=…&port=…&name=…[&profileId=…][&protocol=rdp]`,
which
`readSessionParams()` in `ui/src/hooks/useSession.ts` reads back. **Those query
keys are part of this contract**, the session window connects itself from
them. `protocol` is appended **only when it is not `vnc`**, so every URL an
older build produces still parses and every URL a newer build produces for a
VNC session is byte identical to today's.

For a tab (`asTab: true`) no window is built and the same parameters come
back as `params`, a `SessionTabParams`:
`{ profileId, address, port, name, protocol }`. `protocol` is unconditional
there, being a fresh JSON payload with no legacy readers.

### `connect_session`

Accepts `{ profileId? address, port, sessionId? protocol?
ignoreStoredCredentials? acceptSshHostKey? onEvent }`.

`protocol` is the ad-hoc path: quick connect typed `rdp://box`, so there is
no profile to read it from. The shell resolves the protocol from this
argument, then the profile's `protocol` column, then VNC, so a webview build
that omits the key still invokes successfully. A value this build does not
know is a **hard error with a message for the user**, never a fallback:
falling back to VNC would dial the wrong protocol at an endpoint the user
configured for something else.

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

An RDP session works over the same tunnel with no extra configuration, with
one difference that is deliberate. A tunnel sets `allowInsecure` for VNC,
because the SSH layer already encrypts the path and the classic tunnelled
setup is a loopback-only server offering security type None. It does **not**
for RDP: network level authentication authenticates the *server*, and an SSH
gateway proves the identity of the gateway, not of the Windows machine
reached through it, which may be a different box. An RDP session still does
full TLS and NLA inside the tunnel, and the name used for SNI, the
certificate pin and the Kerberos service name is the address on the profile,
never the loopback endpoint the tunnel hands back.

### `set_quality`

`preset` is a `vnc_core::QualityPreset` with `rename_all = "kebab-case"`:
`"auto" | "high" | "medium" | "low" | "black-and-white"`.

⚠️ The stored `qualityPref` shorthand for black-and-white is `"bw"`, which is
**not** accepted here. The UI maps it in `wireQuality()`.

### `provide_credentials` / `cancel_credentials`

The answer to a `credentials-required` event (PRD/10 §3.4). The session is
**paused inside the handshake** until one of these arrives, it does not fail
the connection and ask afterwards.

Accepts `{ sessionId, username?, domain?, password, save }`.

- `username` is `null` for `kind: "password-only"`; send the typed value for
  `"username-and-password"`.
- `domain` is the logon domain, `null` for every VNC method and for an RDP
  logon with no domain (a local account, or a UPN in `username`). Being
  optional, a webview build that omits the key still invokes successfully;
  that is the whole compatibility story for this command. The shell stores
  the domain and the user separately in the keychain, and folds them back
  into `DOMAIN\user` for the driver. A name that already carries a domain is
  left alone, and so is a UPN: an RDP server accepts `alice@corp.example`
  with an empty domain, and pinning a NetBIOS domain in front of one fails
  against Entra ID and against any forest whose NetBIOS name is not the DNS
  label.
- `save` is the "remember this" checkbox. It does **not** write anything at
  call time: the shell keeps the credential in memory
  (`AppState::pending_credentials`, keyed by session id) and writes it to the
  keychain only when that session reaches `SessionState::Connected`. A password
  the server rejects, a cancelled prompt, a failed connect and a closed session
  all drop the intent unwritten. **A password is never persisted until it has
  been proven to work.**
- On success the shell writes a `StoredCredentials` merged over whatever the
  host already had (so an SSH passphrase, and the other protocol's password,
  survive). For VNC: `vencryptUser`/`vencryptPass` when a username was
  supplied, otherwise `vncPassword`. For RDP: `rdpUser`, `rdpDomain` and
  `rdpPassword`, replaced as a triple rather than merged field by field,
  because the three were proven together and keeping an old domain beside a
  new username would store a credential that has never worked anywhere. It
  also flips the profile's `hasPassword` flag via `save_host`.
- **For RDP, reaching `connected` is not always proof.** With NLA on it is:
  CredSSP either authenticates or the connection fails. With NLA off the
  credentials go out in the Client Info PDU and Windows evaluates them inside
  the session, so the connection completes whether the password was right or
  wrong. The shell therefore holds such an intent past `connected` and
  settles it on the server's own `logon-info` event instead. Every terminal
  state still drops it unwritten.
- An ad-hoc RDP session that asks to be remembered is adopted as a profile
  **with its own protocol**: quick connecting `rdp://box`, ticking remember
  and getting a saved host that says VNC would be a bug, and that profile
  would dial the wrong protocol for ever after.
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
{ sessionId: string; profileId: string | null; address: string; port: number;
  protocol: "vnc" | "rdp" }
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
| `certificate-prompt` | `fingerprint`, `subject`, `isChange`, `scheme` (**camelCase**). `scheme` is `"tls"` (VeNCrypt X.509), `"ra2"` (RealVNC RSA) or `"rdp-tls"` (an RDP server's own certificate). It is plumbing, not copy: the UI hands it back to `trust_certificate` unchanged so the pin lands under the key the user actually looked at. One host can serve VNC over VeNCrypt and RDP on 3389 with two unrelated certificates, and sharing one row would mean a certificate approved for one protocol silently vouching for the other |
| `credentials-required` | `request`, a `CredentialRequest` (**camelCase**); the session is PAUSED until `provide_credentials`/`cancel_credentials` |
| `stats` | `stats`, `SessionStats`, fields **snake_case** |
| `error` | `message` |
| `ended` | `durationS`, the session task is fully gone |
| `logon-info` | `domain`, `user`, `remoteSessionId`. RDP only. Who the server says is signed in. Both strings **untrusted**, render as text only |
| `logon-error` | `notificationType`, `notificationData`, `message`. RDP only. The driver derived the sentence, so the UI owns no code table |
| `error-info` | `code`, `symbol`, `message`. RDP only. The server ended the session and said why; `symbol` is the specification's constant name, empty when this build does not recognise `code`, and `code` is always the raw value so a bug report can carry it |
| `redirect` | `target`, `remoteSessionId`. RDP only. Informational: the driver performs the redirect itself, the UI just stops naming the old host |
| `auto-reconnect-armed` | none, deliberately. A fast reconnect is now possible; the cookie itself is a bearer secret and never crosses IPC |
| `license-warning` | `message`. RDP only |
| `audio-format` | `sampleRate`, `channels`. Emitted once, and again only when the server changes format, never per packet |

**Unknown `type` values must be ignored.** The webview's handler already ends
in a `default: break`, so a shell emitting an event a given UI build predates
does nothing, silently and correctly. That is what lets the shell and the UI
ship a new event in separate commits, and it is stated here rather than left
as an accident. The mirror image is also safe: a new `case` arm never fires
against an old shell.

**Audio samples are not here and never will be.** A JSON array of PCM is the
audio equivalent of shipping a whole framebuffer across IPC. What the UI is
told is the *format*; the samples go to the audio device.

`SessionState` variants (tag `state`): `idle`, `resolving`, `connecting`,
`authenticating` + `method`, `negotiating`, `connected`, `reconnecting` +
`{ attempt, next_retry_ms, reason }`, `disconnected` + `{ reason, can_retry }`.
The inner field names are snake_case.

`authenticating`'s `method` is a **stable identifier the UI maps to its own
copy**, not a sentence to display. For RDP the three values are `nla-ntlm`
(CredSSP with NTLMv2, all a phase 1 or phase 2 build can produce), `tls`
(the `allow-fallback` policy fired and there is no network level
authentication) and `nla-kerberos` (reserved, phase 3). The same three tokens
go in the history table's `securityType` column and in the log lines, so
there is one vocabulary rather than two. VNC keeps its own descriptive
strings. An unrecognised value falls back to the UI's generic "the server's
method" copy rather than to a blank.

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
| `{ type: "started", sessionId, profileId, address, port, protocol }` | `connect_session` registered the session (`profileId` is `null` for ad-hoc) |
| `{ type: "host-adopted", sessionId, profileId, address, port, protocol }` | an ad-hoc session that asked to be remembered just gained a host profile; the Library re-reads its host list on it |
| `{ type: "state", sessionId, state }` | every state change; `state` is **only the kebab-case tag** (`"connecting"`, `"connected"`, `"reconnecting"`, `"disconnected"`, …), never the full `SessionState` object |
| `{ type: "ended", sessionId }` | the session task is fully gone and its registry entry removed |

Seed initial state with [`list_active_sessions`](#list_active_sessions), anything broadcast before the listener registered is lost.

### `sessions://stats`, app-wide (JSON)

Broadcast with `emit` once per stats tick (1 Hz per connected session), in
addition to the per-window `stats` event:

```jsonc
{ "sessionId": "…", "profileId": "…|null", "address": "…", "port": 5900,
  "protocol": "vnc",
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
  protocol, rdp, savedHostId }
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
- `protocol` is `"vnc"` or `"rdp"` and says what answers on **this row's
  port**, not what the machine runs. A machine running both produces two
  rows; joining them is the interface's job, not the registry's.
- `rdp` is what the X.224 negotiation learned, `null` for a VNC row:

  ```ts
  { tls, nla, nlaRequired: boolean | null, gfx, extendedClientData,
    restrictedAdmin, redirectedAuth, standardOnly,
    failureCode: number | null, selectedProtocol }
  ```

  `nlaRequired` is nullable because one negotiation cannot answer it. A
  server that permits both TLS and NLA selects the stronger, which proves NLA
  is *available* and says nothing about whether TLS alone would have been
  refused; learning that needs the on-demand `deep_probe`. `null` means "not
  asked", and an unprobed host must read that way rather than as an
  optimistic `false`. `standardOnly` marks a server that offered no
  `rdpNegData` at all, so it speaks only standard RDP security, which this
  client does not support: such a host is listed and marked rather than
  hidden, because "there is an RDP server here that this client cannot talk
  to" is more useful than silence.

  Note what is deliberately **not** in there: a TLS version. The probe never
  completes a handshake, so the only honest way to learn that a server tops
  out at TLS 1.1 is to fail a connection to it.
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

---

## `.rdp` file import, `commands/rdpfile.rs`

| Command | JS call | Returns |
|---|---|---|
| `import_rdp_file` | `invoke("import_rdp_file", { path })` | `RdpImport` |
| `import_rdp_files` | `invoke("import_rdp_files", { paths })` | `RdpFileImport[]` |

**The webview sends a path, never file content.** The parser is pure and
takes bytes, so the shell does the reading: a `.rdp` file may carry a
`password 51:b:` line, which is a DPAPI blob rather than plaintext but is
still a secret, and keeping the bytes on the Rust side is one fewer place it
can be logged. It also means the one megabyte size cap is enforced from the
file's metadata, before the read, rather than after the webview has already
pulled a gigabyte off disk.

`RdpImport` is `{ profile, username?, mapped[], ignored[], unparseable,
warnings[], desktopSize? }`. `profile` is a whole draft `HostProfile` with
`protocol: "rdp"`, because `save_host` deserializes a whole one and a draft
missing a field would be rejected at save time, which is a confusing place to
find out. `mapped`, `ignored` and `warnings` are **key names and sentences
only**; no value from the file ever appears in them.

Nothing here writes. The draft goes to the host editor and the user saves it
through the ordinary `save_host`, so an import is reviewable before it
becomes a profile, and an imported profile's password is still only stored
after a server has accepted it.

`import_rdp_files` never fails as a whole: one refused file among ten must
not lose the other nine, so each row carries either an `import` or an
`error`, in the order the paths were given.

Errors, for a file that must not become a profile at all: unreadable, over
the size cap, or one that launches a RemoteApp, which does something
materially different from opening a desktop. Everything else is a warning on
an otherwise usable draft, because a file the user chose to import should not
be refused over one setting this app does not have.

---

## Mismatched builds

The shell and the webview ship together, so a mismatch is a development
accident (a stale `ui/dist` against a rebuilt shell, or a hot reloading vite
server) rather than something a user meets. It still has to not corrupt data.

### An old UI against a new shell

* `list_hosts` returns two extra keys. The old UI's interface lacks them,
  TypeScript does not check at runtime, and they are carried around
  untouched.
* `save_host` is the dangerous one and it is safe **because** of that
  carrying. `HostsContext.saveHost` builds the payload as
  `{ ...(existing ?? blankHostProfile()), ...host }` where `existing` came
  from `list_hosts`, so the two unknown keys survive the round trip. An RDP
  host edited by an old UI stays an RDP host.
* The failure mode that would exist without `#[serde(default)]` on the two
  new Rust fields is a *new* host, where `blankHostProfile()` supplies no
  `protocol` and `save_host` would reject the whole struct with "invalid
  args". The defaults make it succeed and produce a VNC host, which is the
  right answer.
* `provide_credentials` without `domain`, `connect_session` without
  `protocol`, `has_password` without `protocol` and `deep_probe` without
  `protocol` all deserialize to `None`, because Tauri allows an `Option<T>`
  argument to be absent. Each falls back to exactly what it did before.
* New `session://event` types hit the webview's `default: break`.
* `list_active_sessions` and the `sessions://` broadcasts carry an extra
  `protocol` key, which the old UI ignores.
* One case is worse than the rest and is worth naming. The `rdpSettings`
  blob is carried opaquely by `save_host`, so it survives that round trip,
  but an **editor** that parses it into a typed object and writes a fresh one
  does not: a UI build predating a field drops it. See the re-emit rule under
  [the blob](#the-rdpsettings-blob).

### A new UI against an old shell

It degrades to "RDP does not exist" rather than to anything broken.

* `save_host` sends two extra keys. `HostProfile` has no
  `deny_unknown_fields`, so serde ignores them and the profile saves as VNC,
  silently. Acceptable for a development mismatch, but worth knowing: the
  symptom is "I set it to RDP and it saved as VNC".
* `connect_session` with `protocol: "rdp"` fails with Tauri's "invalid args"
  for the unknown argument. Loud, which is right.
* `provide_credentials` with `domain` fails the same way, so the credential
  prompt does nothing on an old shell. Noted so nobody loses an afternoon.
* `import_rdp_file` does not exist, so the importer's entry point errors
  rather than half working.
* The new `PinScheme` includes `"rdp-tls"`, which an old shell's parser
  rejects. Unreachable in practice, since an old shell never raises an
  `rdp-tls` prompt.

The rule that follows: **the shell lands first.** Every shell side addition
goes in before any UI change that depends on it, and the UI change ships in
the same release.
