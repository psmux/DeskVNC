# Contributing to DeskVNCViewer

Thanks for considering it. This document covers what you need to build the
project and what a reviewable change looks like.

For security problems, do not open an issue. See [SECURITY.md](SECURITY.md).

## Getting set up

Prerequisites:

- **Rust 1.82 or newer** (the workspace sets `rust-version = "1.82"`)
- **Node 22 or newer**
- The [Tauri 2 system dependencies](https://v2.tauri.app/start/prerequisites/)
  for your platform

```sh
npm install --prefix ui
cargo install tauri-cli --version "^2"   # if you do not have it
cargo tauri dev
```

The protocol crates build and test without any Tauri or system webview
dependency, which makes them the fastest place to work:

```sh
cargo test -p vnc-core
```

## Before you open a pull request

Run what CI runs. All four must pass:

```sh
cargo fmt --all -- --check
cargo clippy -p vnc-core -p vnc-transport -p vnc-discovery -p vnc-store -- -D warnings
cargo test -p vnc-core -p vnc-transport -p vnc-discovery -p vnc-store
(cd ui && npx tsc --noEmit)
```

Some tests are marked `#[ignore]` because they touch the real OS keychain or a
live VNC server. Run those deliberately with `cargo test -- --ignored` when you
are changing that code, and say in the PR whether you did.

## How the code is organised

```
crates/
  remote-core/         Protocol neutral session contract: options, events, commands,
                       stats, the ProtocolDriver trait. Depends on no protocol crate.
  remote-pixel/        Pixel format conversion and resampling. No dependencies at all,
                       so a codec crate can take it without acquiring tokio.
  rdp-pdu/             RDP wire formats: Reader/Writer, BER, PER, DER, X.224, MCS, GCC,
                       security headers, capability sets, fast path framing. No I/O.
  rdp-codecs/          RDP bitmap decoders as pure functions over caller owned buffers.
  rdp-auth/            CredSSP, SPNEGO, NTLMv2. Pure state machines over byte slices.
  rdp-core/            RDP session, connection state machine, channels, lifecycle.
  vnc-core/            RFB protocol, encodings, security, input, clipboard, session
  vnc-transport/       TCP, TLS with trust-on-first-use pinning, SSH tunnel
  vnc-discovery/       mDNS, subnet scan, banner fingerprint, name resolution, Wake-on-LAN
  vnc-store/           SQLite host profiles, keychain credentials, thumbnails
  vnc-files/           SFTP file transfer
  vnc-input-capture/   Platform global input capture
src-tauri/             Tauri shell: commands, framebuffer channel, windows, menus, tray
ui/                    React, TypeScript, Tailwind, WebGL2 renderer
```

Two boundaries are worth preserving:

- **No protocol crate has a Tauri dependency.** The protocol layer is UI agnostic
  so the frontend can be replaced without touching protocol code. Please do not
  introduce one. `rdp-pdu`, `rdp-codecs` and `rdp-auth` go further and carry no
  tokio either, so they build and test in about a second and can be fuzzed without
  a runtime. `crates/rdp-pdu/tests/workspace_rules.rs` enforces both.

- **The RDP stack is written here, the cryptography never is.** No third party
  RDP, CredSSP, SPNEGO, NTLM or Kerberos crate may be depended on, vendored or
  copied from. Every cipher, hash, MAC and key derivation is a call into a vetted
  crate; what this workspace owns is the order those calls happen in. A
  construction with no vetted crate behind it is a question for the maintainers,
  not something to write.
- **Decoded pixels never cross the IPC boundary as whole frames.** They travel
  as binary dirty-rect messages over a Tauri channel and are uploaded into a
  single WebGL2 texture. Changes that serialise full framebuffers through IPC
  will regress performance badly.

Source comments cite an internal specification as `PRD/NN §S`. Those documents
are not in this repository. The citations record why a decision was made; treat
them as provenance, and do not feel obliged to add new ones.

## Style

- Rust is formatted with `cargo fmt`. No hand formatting.
- Clippy runs with `-D warnings` on the library crates. Fix the lint rather than
  allowing it, unless you can explain why in a comment.
- **Do not use em dashes or en dashes** in code, comments, documentation, or
  commit messages. Use commas, colons, parentheses, or separate sentences. Use a
  plain hyphen for numeric ranges.
- Comments should say *why*, not restate *what*. The existing code leans on this
  heavily, particularly around protocol quirks and platform workarounds. Match
  that.
- Keep the parsers boring. See the invariants in
  [SECURITY.md](SECURITY.md#notes-for-reviewers) before touching decoders.

## Changes that need tests

- **Any decoder or parser change.** Add a case with real or hand built bytes.
  `crates/vnc-discovery/src/dnsmsg.rs` shows the pattern for wire format
  fixtures, including how to keep length fields consistent when you edit them.
- **Any credential or storage change.** `crates/vnc-store/src/creds.rs` has
  round-trip and negative tests, plus one asserting that secrets never reach the
  SQLite file.
- **Any protocol handshake change.** `crates/vnc-core/tests/` drives a mock
  server.

Bug fixes should come with a test that fails before the fix.

## Pull requests

- One logical change per PR. Split refactors away from behaviour changes.
- Explain what a reviewer should look at, and what you tested. If you could not
  test something (no Windows machine, no server that speaks RA2), say so
  plainly. That is much more useful than silence.
- Interoperability reports are welcome on their own. If you find a server this
  client mishandles, an issue naming the server, its version, and what went
  wrong is a real contribution.

## Licensing of contributions

Contributions are dual licensed under Apache-2.0 and MIT, matching the project.
Submitting a pull request means you agree to that. There is no CLA.

## Reporting bugs

Include your platform and OS version, the app version, the VNC server and its
version, and what you expected against what happened. For connection or
rendering problems, logs help:

```sh
RUST_LOG=debug cargo tauri dev
```

Scrub hostnames, addresses, and credentials before pasting logs into a public
issue.
