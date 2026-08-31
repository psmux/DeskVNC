# DeskVNC

One place for every machine you connect to. A fast, native client for **VNC,
RDP and SSH**, built in Rust and Tauri 2, for Windows, macOS and Linux. Your
hosts live in one library with groups, tags and live thumbnails, and the three
protocols mix freely: a Windows desktop over RDP, a Linux box over VNC and a
server shell over SSH can sit side by side in the same window.

It is also the first remote desktop client an **AI agent can drive** over the
same connections, with a person able to take the wheel back at any moment.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

> **Status: pre-1.0, under active development.** The protocol cores are well
> covered by tests and interoperability work is ongoing. Stored data and the
> IPC contract may change between minor versions. See
> [CHANGELOG.md](CHANGELOG.md).

## Why DeskVNC

Most people who manage more than a handful of machines end up paying for a
connection manager: Remote Desktop Manager, Royal TS, mRemoteNG on a runtime
that security teams increasingly block. DeskVNC is a native, memory-safe
alternative that keeps all three protocols and your whole host library in one
tool, stores secrets in the OS keychain rather than a shared database, and does
not lock features behind a bundle you did not want.

- **Three protocols, one library.** VNC (RFB 3.3 to 3.8, every common
  encoding), RDP (Windows desktops, RemoteApp resolution control), and SSH (a
  real terminal, SFTP file transfer, and tunnelling). Saved hosts carry their
  protocol, credentials and settings, and connect on a double click.
- **Secrets stay in the keychain.** Keychain Services on macOS, Credential
  Manager on Windows, Secret Service on Linux, with an encrypted-file fallback
  for headless boxes. A test asserts that saving a host writes nothing
  sensitive into the profile database.
- **Discovery built in.** mDNS browsing, polite subnet scanning with banner
  fingerprinting, name resolution over mDNS, LLMNR, NetBIOS and MS-RPC, and
  Wake-on-LAN.
- **Fast by construction.** Whole framebuffers never cross the IPC boundary;
  decoded pixels travel as binary dirty-rect messages into a single WebGL2
  texture. H.264 decode runs in the webview with hardware acceleration.

The complete protocol feature list, the security model and the crate layout are
in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## The agent control plane

DeskVNC ships an optional control plane so an existing AI agent can observe and
act on the machines you already connect to, over VNC, RDP or SSH, with **nothing
installed on the target**. The connection is the ordinary one you would make by
hand.

- **An MCP server (`dvv`)** over stdio and HTTP. Point Claude Code, or any agent
  that speaks MCP, at it. There is a one-click button that registers it with
  Claude Code for you.
- **The agent drives the same session you would.** It can open one of your saved
  machines, read your host library (never the stored passwords), take a
  screenshot, and send input. A badge shows when an agent is driving a pane.
- **A human takes the wheel back instantly.** Control is leased. Grab it with
  one click and the agent is fenced out of that session until you hand it back.
  This is arbitration built into the protocol layer, not application glue.

Why this matters: the funded tools that let an agent drive a Windows box all
install a driver on the target, which is refused on Citrix, VDI, jump hosts and
client-owned machines. DeskVNC reaches those over the protocol they already
speak. If you are building agent automation for legacy or locked-down desktops,
see [the integration notes](docs/AGENTS.md) and get in touch (below).

## Installing

Prebuilt binaries for macOS, Windows and Linux are on the
[latest release](https://github.com/psmux/DeskVNC/releases/latest).

The **macOS** build is signed and notarized, so it opens normally. The
**Windows** installer is unsigned today, so SmartScreen shows "Windows protected
your PC"; continue with **More info** then **Run anyway**, or verify the
published checksum first, or build from source. **Linux** packages are unsigned.

Full details, including checksum verification and the permissions the app asks
for, are in [docs/INSTALL.md](docs/INSTALL.md).

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

The workspace checks CI runs, the macOS packaging path, and the reasons behind
both are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Support and commercial use

DeskVNC is free and open source, and stays that way. It is built and maintained
by one engineer. Two ways to keep it moving and get what you need:

- **Sponsor the project** on [GitHub Sponsors](https://github.com/sponsors/psmux).
  It funds the roadmap and signed Windows builds.
- **Commercial support, integration and consulting.** If your company depends on
  DeskVNC, or you want the agent control plane built into your own product (a
  no-install tier for driving legacy or locked-down Windows desktops, a hardened
  `dvv` for your agents, or protocol work on the Rust RDP, VNC and SSH cores),
  email **godwin@altrosyn.com**. Paid priority support and fixed-scope
  contracts are available.

## Contributing

Bug reports, interoperability findings, and pull requests are all welcome. If
you have hit a server this client mishandles, an issue naming the server and its
version is genuinely useful on its own. Start with
[CONTRIBUTING.md](CONTRIBUTING.md).

For security issues, do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
