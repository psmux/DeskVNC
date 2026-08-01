# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version stays below 1.0, minor releases may contain breaking changes
to stored data and to the IPC contract between the Rust core and the frontend.

## [Unreleased]

### Added

- **Tabbed view.** Connected computers can be shown as tabs across the top of
  the library window and switched between like browser tabs, instead of each
  one opening a window of its own. Turn it on in Preferences ▸ Connections,
  "Show sessions as tabs in one window"; it is off by default, so nothing
  changes unless you ask for it.
  - The library is the first tab and cannot be closed. Every session tab
    carries a status dot, the name the server reports for that desktop, and a
    close button; middle-click closes one too.
  - `Ctrl+Tab` and `Ctrl+Shift+Tab` move between tabs, `Cmd/Ctrl+1…9` jump
    straight to one (1 being the library), `Cmd/Ctrl+Shift+W` closes the tab in
    front and `Cmd/Ctrl+Shift+L` returns to the library. The first two and the
    last two are real menu items under Window, which is what makes them work
    while shortcut pass-through is sending everything else to the remote
    machine. The palette (`Cmd/Ctrl+K`) also lists every open session.
  - Only the tab you are looking at draws, holds the keyboard, or answers
    dropped files. The others stay connected and keep their picture up to date,
    so switching back shows the desktop as it is now, not as it was.
  - The preference decides where the *next* session goes. Sessions already
    running stay where they are, in a window or in a tab, because a live
    picture cannot be moved between the two without reconnecting. Connecting to
    a machine that is already open still finds it either way and brings it
    forward rather than starting a second session.
  - Closing the library window with tabs open shuts those sessions down
    cleanly, but skips the parting thumbnail refresh; closing a tab does not.

### Fixed

- Keyboard capture (shortcut pass-through) is now released and re-armed based
  on which window actually asked for it, rather than on the window's name. The
  old rule read the session id back out of a `session-<id>` window label, which
  meant nothing owned capture in a window hosting several sessions, and focusing
  any window that was not a session window force-released the grab.

- SSH host-key pins are keyed on one canonical spelling of the host, so `::1`,
  `[::1]`, `studio.local` and the mDNS-qualified `studio.local.` are one
  machine rather than up to four. Previously each spelling earned its own
  trust prompt and its own pin. Both sides are normalized at lookup time
  rather than only on write, so pins already on disk keep matching and no
  migration is needed. A store that already holds duplicates is folded on
  load, keeping the most recently seen pin: without that, forgetting a key
  would leave a shadow pin behind that answers the next connection, and a
  disagreeing fingerprint there is a hard stop with no way through it.

## [0.1.2] - 2026-07-31

### Added

- **QuickConnect address bar**, always visible under the library toolbar. Type
  an address, press Enter, and you are connected without saving anything first.
  The feature existed before as a dialog behind `Cmd/Ctrl+T` with no visible
  entry point anywhere in the window, so in practice it could not be found.
  - Suggestions as you type, drawn from saved hosts, machines found by
    discovery, and the addresses you last quick-connected to. The last of those
    are kept in the settings blob rather than the store's `history` table,
    because that table is keyed by host id and a quick connect has no host.
  - Typing an address that a saved host already covers connects through that
    host, so its quality, view-only setting and stored password still apply.
  - `Cmd/Ctrl+T` and File -> Connect to… now focus the bar.
- **"Remember this password" now works on a quick connect.** Credentials are
  keyed by host id, so a session with no host profile had nowhere to put one:
  the tick was silently discarded and the password was asked for again on the
  next connection. Ticking it now adopts the endpoint as a saved host, stores
  the password against it, and the new tile appears in the Library while the
  session is still open. A quick connect that saves nothing still leaves no
  trace, and a repeat connect to the same endpoint reuses the host it already
  made rather than adding a second tile.

### Fixed

- An IPv6 address given as a bare literal could not be connected to. `resolve`
  joined the host and port as `{host}:{port}`, so `::1` became `::1:5900`,
  which is not a parseable address. Bare literals are now bracketed before the
  lookup.
- The same fault in the SFTP sidecar: the connection label, the SSH session
  label, and three user-visible error messages (`Connect`, `HostKeyUnknown`,
  `HostKeyChanged`) all joined host and port the same way. Its mirror image
  was there too: `russh::client::connect` and `TcpStream::connect` take
  `(host, port)` as a tuple, which accepts neither a bracketed literal nor a
  DNS name spelled that way, so a host saved as `[::1]` would connect over VNC
  while its Files panel reported the machine unreachable. Brackets are now
  added where a string is built and removed where a resolver is called.
- Matching a typed address against the saved hosts now normalizes case and a
  trailing dot on both sides, so `Studio.local`, `studio.local` and the
  mDNS-qualified `studio.local.` are one machine rather than three. There is
  one definition of that rule (`vnc_store::normalize_address`) instead of the
  session layer and the store each having their own.
- The native `Cmd/Ctrl+T` and `Cmd/Ctrl+N` menu accelerators did nothing. Both
  emitted `menu://action` to the focused window and no window listened for
  them. They are now routed to the library window and handled there, so they
  also work while a session window is in front.
- Address parsing was duplicated between the host dialog and quick connect, and
  both copies mangled IPv6: `[::1]:5901` parsed to a host of `[` or `[::1]`
  depending on the copy. There is now one parser (`ui/src/lib/address.ts`),
  which also understands `host::5901`, `vnc://` links, and rejects out-of-range
  ports instead of passing them to an IPC call that only takes a `u16`.
- The host dialog reported "address is required" for everything. It now shows
  the specific reason the address cannot be used.

## [0.1.1] - 2026-07-31

### Fixed

- Text copied on the remote never reached the local clipboard. Two independent
  faults, both on that path:
  - The Extended Clipboard handshake was half implemented. The client
    advertised the pseudo-encoding but never answered the server's capabilities
    message with its own, and never answered a `notify` (which carries no data)
    with a `request`, so servers using the modern flow had no way to hand the
    text over. A capabilities announcement also sets the notify bit, so it was
    additionally being read as an offer of data.
  - The delivery into the OS clipboard went through `navigator.clipboard`.
    WebKit only honours it while a user gesture is live, and remote clipboard
    text arrives from the socket, so the write was rejected and the rejection
    swallowed. Both directions now go through the shell
    (`set_local_clipboard` / `read_local_clipboard`).

## [0.1.0] - 2026-07-30

Everything below shipped in the `v0.1.0` build. The entries were still filed
under "Unreleased" when that tag was cut; they are grouped here rather than
moved into `0.1.1`, which contains only the clipboard fix above.

### Added

- `#![forbid(unsafe_code)]` on `vnc-core`, `vnc-transport`, and `vnc-store`,
  making the existing absence of `unsafe` compiler enforced rather than a review
  convention. `vnc-discovery` and `vnc-files` already declared it.
- In-app **About and Help** dialog with version, author, license, keyboard
  shortcut reference, and troubleshooting notes. Reachable from the command
  palette, the Help menu, and the macOS application menu.
- macOS code signing and notarization tooling under `scripts/`: self-signed
  identity setup for local development, a linker shim that keeps the code
  identity stable across rebuilds, and a packaging script that signs, notarizes,
  and staples both the `.app` and the `.dmg`.
- `docs/MACOS_SIGNING.md` explaining why an ad-hoc signed build loses keychain
  and TCC grants on every rebuild, and how a stable signing identity fixes it.
- Project documentation for public release: `LICENSE-MIT`, `LICENSE-APACHE`,
  `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, and this changelog.

### Fixed

- Text copied on the remote never reached the local clipboard. Two independent
  faults, both on that path:
  - The Extended Clipboard handshake was half implemented. The client
    advertised the pseudo-encoding but never answered the server's capabilities
    message with its own, and never answered a `notify` (which carries no data)
    with a `request`, so servers using the modern flow had no way to hand the
    text over. A capabilities announcement also sets the notify bit, so it was
    additionally being read as an offer of data.
  - The delivery into the OS clipboard went through `navigator.clipboard`.
    WebKit only honours it while a user gesture is live, and remote clipboard
    text arrives from the socket, so the write was rejected and the rejection
    swallowed. Both directions now go through the shell
    (`set_local_clipboard` / `read_local_clipboard`).
- Native menu items were inert. `menu.rs` emitted a `menu://action` event for
  every custom item, but nothing in the frontend listened for it, so
  **Settings** and **Help** did nothing when selected. The frontend now routes
  those events.
- Notarization stapled the ticket to the disk image only. An app dragged out of
  the DMG carried no ticket of its own, so its first launch on a machine without
  network access would fail Gatekeeper. The `.app` is now notarized and stapled
  before the DMG is assembled, giving both layers a ticket.

### Changed

- Dependency refresh. Rust: `russh` 0.49 to 0.62 (see Security), `rusqlite`
  0.32 to 0.40, `keyring` 3 to 4, `netdev` 0.31 to 0.45, `mdns-sd` 0.11 to
  0.20, `directories` 5 to 6, `zune-jpeg` 0.4 to 0.5, `fast_image_resize` 5 to
  6, `webpki-roots` 0.26 to 1.0. Frontend: React 18 to 19, Vite 6 to 8,
  TypeScript 5 to 7, `@vitejs/plugin-react` 4 to 6.
- CI and the documented prerequisite move to Node 22, which Vite 8 requires
  (`^20.19.0 || >=22.12.0`).
- `rand` stays at 0.8 on purpose. rand 0.9+ implements the rand_core 0.9/0.10
  traits while `rsa` 0.9 requires rand_core 0.6, and the RA2 handshake passes
  an RNG straight into `RsaPrivateKey::new`. Moving forward needs `rsa` 0.10,
  which is still a release candidate. Recorded in `.cargo/audit.toml`.
- The macOS About panel is populated with name, version, author, copyright,
  license, and project URL. It previously used `AboutMetadata::default()` and
  showed only the bundle name.
- `.gitignore` now covers `*.key`, `*.cer`, `*.p8`, `*.pfx`,
  `*.certSigningRequest`, `*.mobileprovision`, and editor directories. It
  previously covered only `*.pem` and `*.p12`.

### Security

- **Upgraded `russh` 0.49 to 0.62**, which fixes RUSTSEC-2026-0154 (unbounded
  32-bit allocation) and RUSTSEC-2026-0153 (unchecked `CryptoVec` allocation),
  both reachable from a hostile SSH peer during file transfer. Patched upstream
  in 0.60.3. The ignore entries for these were removed rather than retained, so
  a regression fails the build.
- Migrated `vnc-files` to the russh 0.62 API: `Handler` now uses
  return-position `impl Future` instead of `#[async_trait]`, authentication
  returns `AuthResult` (which distinguishes full success from partial success)
  rather than a bare bool, `PrivateKeyWithHashAlg::new` is infallible, and the
  agent hands back `AgentIdentity` values that may wrap a certificate.
- `rsa` RUSTSEC-2023-0071 (Marvin) remains accepted and documented. There is
  still no fixed release; the only newer publication is a release candidate
  carrying the same advisory. It is now present twice, directly for RA2 and
  transitively through `ssh-key`.
- Test fixtures no longer embed a real machine name captured from a developer's
  network. The mDNS packet fixture in `crates/vnc-discovery/src/dnsmsg.rs` was
  rewritten with a same-length placeholder label so all wire length fields stay
  valid and the packet remains byte exact.
- Personal signing identifiers and an Apple ID address were removed from
  `docs/MACOS_SIGNING.md`, which now reads as generic setup instructions.

### Initial implementation

Core capability at this point:

- Pure Rust RFB implementation covering protocol versions 3.3 through 3.8.
- Encodings: Raw, CopyRect, RRE, Hextile, Zlib, ZRLE, Tight, and H.264.
- Pseudo-encodings including Cursor, Cursor With Alpha, Desktop Size, Extended
  Desktop Size, Desktop Name, Extended Clipboard, Fence, Continuous Updates,
  LastRect, Extended Mouse Buttons, and the QEMU key, LED, and pointer
  extensions.
- Authentication: None, VncAuth, VeNCrypt, RealVNC RSA-AES (RA2), Apple
  Diffie-Hellman, MS-Logon, and Tight security negotiation.
- TLS through rustls with trust-on-first-use certificate pinning.
- Host library backed by SQLite, with groups, tags, thumbnails, and history.
- Credential storage in the OS keychain, with an encrypted-file fallback using
  XChaCha20-Poly1305 under an Argon2id derived key.
- LAN discovery over mDNS plus a rate-limited subnet scan with RFB banner
  fingerprinting, and hostname resolution over mDNS, LLMNR, NetBIOS, and MS-RPC.
- Wake-on-LAN.
- SFTP file transfer with a dual-pane browser and drag and drop.
- Adaptive quality presets, remote desktop resize, and automatic reconnect with
  backoff and jitter.

[Unreleased]: https://github.com/psmux/DeskVNC/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/psmux/DeskVNC/releases/tag/v0.1.0
