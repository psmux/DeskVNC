# DeskVNCViewer

A fast, native VNC viewer for Windows, macOS, and Linux, built with Rust and
Tauri 2.

The RFB implementation is pure Rust with no `unsafe` and no C dependencies. The
interface is React with a WebGL2 renderer. Decoded pixels reach the screen as
binary dirty-rect messages rather than serialised frames, so a full framebuffer
never crosses the IPC boundary.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **Status: pre-1.0, under active development.** The protocol core is well
> covered by tests and interoperability work is ongoing. Stored data and the
> IPC contract may change between minor versions. See
> [CHANGELOG.md](CHANGELOG.md).

## Installing

Prebuilt binaries for macOS, Windows and Linux are on the
[latest release](https://github.com/psmux/DeskVNC/releases/latest).

The **macOS** build is signed and notarized, so it opens normally. The
**Windows** installer is unsigned, so SmartScreen shows "Windows protected your
PC"; continue with **More info** then **Run anyway**, or verify the published
checksum first, or build from source. **Linux** packages are unsigned.

Full details, including checksum verification and the permissions the app asks
for, are in [docs/INSTALL.md](docs/INSTALL.md).

## Features

### Protocol

- **RFB 3.3 through 3.8**, with version negotiation.
- **Encodings**: Raw, CopyRect, RRE, Hextile, Zlib, ZRLE, Tight, and Open H.264.
- **Pseudo-encodings**: Cursor, Cursor With Alpha, X Cursor, VMware Cursor,
  Desktop Size, Extended Desktop Size, Desktop Name, Extended Clipboard, Fence,
  Continuous Updates, LastRect, Extended Mouse Buttons, and the QEMU key, LED
  state, and pointer motion extensions.
- **Adaptive quality**: Auto, High, Medium, Low, and Black and White presets.
  Auto tunes JPEG quality and subsampling against measured throughput.
- **Remote resize** through Extended Desktop Size, so the server follows your
  window.

H.264 framing and decoder-context bookkeeping live in Rust; the video decode
itself runs in the webview through WebCodecs, which gets hardware acceleration
via VideoToolbox, D3D11, or VAAPI.

### Authentication and transport

- **None**, **VncAuth**, **VeNCrypt** (including the X509 subtypes),
  **RealVNC RSA-AES (RA2)**, **Apple Diffie-Hellman** for macOS Screen Sharing,
  **MS-Logon**, and Tight security negotiation.
- **TLS through rustls** with trust-on-first-use certificate pinning. A changed
  certificate is surfaced rather than silently accepted.

VncAuth is DES based and truncates passwords to 8 characters. That is a flaw in
the protocol, not this client. Prefer VeNCrypt or RA2 where the server offers
them.

### Credentials

- **OS keychain** storage: Keychain Services on macOS, Credential Manager on
  Windows, Secret Service on Linux.
- **Encrypted-file fallback** for headless or locked-keyring environments, using
  XChaCha20-Poly1305 under an Argon2id derived key, with the KDF parameters
  bound as additional authenticated data so they cannot be downgraded.
- Secrets never touch the profile database. A test asserts that saving a host
  writes nothing sensitive into the SQLite file or its write-ahead log.

### Discovery

- **mDNS** browsing for `_rfb._tcp` and `_ard._tcp`.
- **Subnet scan** with RFB banner fingerprinting, rate limited to stay polite on
  shared networks.
- **Name resolution** over mDNS, LLMNR, NetBIOS, and MS-RPC, so hosts show up
  with real names instead of bare addresses.
- **Wake-on-LAN**, including during reconnect attempts.

Every discovery response is parsed as hostile input. Any host on the network can
answer these queries and the result is rendered in the interface.

### Session and interface

- **Host library** on SQLite with friendly names, groups, tags, live
  thumbnails, connection history, and double-click connect.
- **QuickConnect** address bar: type `host`, `host:1`, `host:5901`, `host::5901`,
  `[::1]:5901`, or a `vnc://` link and press Enter. Nothing has to be saved
  first, and typing the address of a host you did save connects through that
  profile so its settings and password still apply.
- **Command palette** for keyboard-driven navigation.
- **Windows or tabs**: each session opens in a window of its own, or, with
  "Show sessions as tabs in one window" in Preferences, as a tab in the library
  window that you switch between the way you switch browser tabs.
- **Display modes**: fit, aspect-fit, 1:1, and custom zoom, all HiDPI correct.
- **Input**: full mouse and keyboard, scancode mode via the QEMU extension,
  and three-tier shortcut pass-through so host and guest shortcuts coexist.
  Global capture uses platform APIs and needs Accessibility permission on macOS.
- **Extended Clipboard** with UTF-8, RTF, and HTML, falling back to Latin-1 for
  older servers.
- **File transfer** over SFTP with a dual-pane browser and drag and drop.
  Remote filenames are validated before they are used to build local paths.
- **Automatic reconnect** with fast first retry, then backoff with jitter, while
  preserving session state.
- **System tray** and global shortcuts.

### Not yet implemented

Being explicit so nobody files an issue against a feature that was never there:

- **SSH tunnelling for the RFB connection.** Host profiles carry an `ssh_tunnel`
  field and an `ssh_passphrase` credential slot, and `vnc-files` speaks SSH for
  SFTP, but nothing routes the protocol stream through a tunnel yet.
- **Signed Windows and Linux installers.** Windows needs an Authenticode
  certificate, which is a paid commercial product, so SmartScreen warns on
  first run. See [docs/INSTALL.md](docs/INSTALL.md). macOS release builds
  *are* signed and notarized in CI.

Note that `scripts/package-macos.sh` builds for the host architecture only. The
release workflow builds a universal macOS binary covering both.

## Architecture

```
crates/
  vnc-core/            RFB protocol, encodings, security, input, clipboard, session, reconnect
  vnc-transport/       TCP and TLS (rustls) with trust-on-first-use pinning
  vnc-discovery/       mDNS, subnet scan, banner fingerprint, name resolution, Wake-on-LAN
  vnc-store/           SQLite host profiles, keychain credentials, thumbnails
  vnc-files/           SFTP file transfer (russh)
  vnc-input-capture/   Platform global input capture
src-tauri/             Tauri 2 shell: commands, framebuffer channel, windows, menus, tray
ui/                    React, TypeScript, Tailwind v4, WebGL2 renderer
```

Two invariants hold the design together:

**`vnc-core` does not depend on Tauri.** The protocol layer is interface
agnostic, so the frontend can be replaced without touching protocol code. It
also means `cargo test -p vnc-core` runs without a system webview, which makes
it the fastest place to work.

**Whole framebuffers never cross IPC.** Decoded pixels travel as binary
dirty-rect messages over a Tauri channel and are uploaded into a single WebGL2
texture.

Every crate that parses bytes from a remote peer declares
`#![forbid(unsafe_code)]`: `vnc-core`, `vnc-transport`, `vnc-discovery`,
`vnc-store`, and `vnc-files`. `unsafe` appears only in `vnc-input-capture`,
which wraps platform input APIs and sees no network data.

Source comments cite an internal specification as `PRD/NN §S`. Those documents
are not part of this repository. The citations record why a decision was made,
so treat them as provenance rather than links. Public technical notes live in
`docs/`.

## Building

Prerequisites: **Rust 1.82 or newer**, **Node 22 or newer**, and the
[Tauri 2 system dependencies](https://v2.tauri.app/start/prerequisites/) for
your platform.

```sh
npm install --prefix ui
cargo install tauri-cli --version "^2"   # if you do not have it

cargo tauri dev      # development, with hot reload
cargo tauri build    # production bundle
```

### Workspace checks

These are what CI runs:

```sh
cargo fmt --all -- --check
cargo clippy -p vnc-core -p vnc-transport -p vnc-discovery -p vnc-store -- -D warnings
cargo test -p vnc-core -p vnc-transport -p vnc-discovery -p vnc-store
(cd ui && npx tsc --noEmit)
```

Tests that touch the real OS keychain or a live VNC server are marked
`#[ignore]`. Run them deliberately with `cargo test -- --ignored`.

### Packaging on macOS

```sh
./scripts/package-macos.sh
```

This builds the `.app`, signs it, notarizes and staples both the app and the
disk image when notarization credentials are available, and produces a DMG.

Two notes on why it exists rather than just calling `cargo tauri build`:

Tauri's DMG bundler shells out to `create-dmg`, which drives Finder over
AppleScript. In any non-interactive session (SSH, CI without a GUI session, or
when Automation permission has not been granted) that fails with
`AppleEvent timed out (-1712)`. This script uses `hdiutil`, which needs no
Finder. The result is cosmetically plainer and functionally identical.

An ad-hoc signed macOS build also loses its keychain and permission grants on
every rebuild, because the code identity is a hash of the binary. Clicking
"Always Allow" appears to do nothing. See
[docs/MACOS_SIGNING.md](docs/MACOS_SIGNING.md) for why, and for the setup that
fixes it.

## Contributing

Bug reports, interoperability findings, and pull requests are all welcome. If
you have hit a server this client mishandles, an issue naming the server and its
version is genuinely useful on its own.

Start with [CONTRIBUTING.md](CONTRIBUTING.md).

For security issues, do not open a public issue. See
[SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
