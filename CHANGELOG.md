# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the version stays below 1.0, minor releases may contain breaking changes
to stored data and to the IPC contract between the Rust core and the frontend.

## [Unreleased]

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

- Native menu items were inert. `menu.rs` emitted a `menu://action` event for
  every custom item, but nothing in the frontend listened for it, so
  **Settings** and **Help** did nothing when selected. The frontend now routes
  those events.
- Notarization stapled the ticket to the disk image only. An app dragged out of
  the DMG carried no ticket of its own, so its first launch on a machine without
  network access would fail Gatekeeper. The `.app` is now notarized and stapled
  before the DMG is assembled, giving both layers a ticket.

### Changed

- The macOS About panel is populated with name, version, author, copyright,
  license, and project URL. It previously used `AboutMetadata::default()` and
  showed only the bundle name.
- `.gitignore` now covers `*.key`, `*.cer`, `*.p8`, `*.pfx`,
  `*.certSigningRequest`, `*.mobileprovision`, and editor directories. It
  previously covered only `*.pem` and `*.p12`.

### Security

- Test fixtures no longer embed a real machine name captured from a developer's
  network. The mDNS packet fixture in `crates/vnc-discovery/src/dnsmsg.rs` was
  rewritten with a same-length placeholder label so all wire length fields stay
  valid and the packet remains byte exact.
- Personal signing identifiers and an Apple ID address were removed from
  `docs/MACOS_SIGNING.md`, which now reads as generic setup instructions.

## [0.1.0] - Unreleased

Initial development version. Not yet released.

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
