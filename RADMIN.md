# Native Rust Radmin integration

This experimental integration adds **Radmin (Radmin security)** through the same
compiled-in `remote_core::ProtocolDriver` interface used by VNC and RDP.

[Radmin](https://www.radmin.com/) is Famatech's remote administration product.
It normally uses a Viewer on the local computer and Radmin Server on the remote
Windows computer. This integration lets DeskVNC act as the desktop client for
existing Radmin Server installations, alongside its VNC, RDP and SSH connections.
It does not implement Radmin VPN or replace the server.

## Official product references

- [Radmin website](https://www.radmin.com/)
- [Official downloads, including Radmin Server and Viewer](https://www.radmin.com/download/)
- [Installation guide, security modes, permissions and TCP port 4899](https://helpdesk.radmin.com/kb/faq.php?id=289)
- [Radmin support center](https://helpdesk.radmin.com/)
- [Vendor Ctrl+Alt+Delete troubleshooting](https://helpdesk.radmin.com/kb/faq.php?id=318)
- [Microsoft software Secure Attention Sequence policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-winlogon#softwaresasgeneration)

These links describe the product and its configuration. They are not a published
wire-protocol specification or an endorsement of this independent client.

## Architecture

The complete connection implementation is in `crates/radmin-core/src`:

| Module | Responsibility |
| --- | --- |
| `auth.rs` | Pinned SRP-6a group, UTF-16 credentials, mutual proofs and session key |
| `channel.rs` | Persistent AES-256-CBC directions, native checksum/padding, bounded records |
| `desktop.rs` | Persistent raw DEFLATE, validated BGR images and dirty-span updates |
| `input.rs` | Physical PC keyboard, pointer/buttons, wheel, held-input release |
| `cursor.rs` | Cursor bitmap conversion and bounded per-session cache |
| `clipboard.rs` | Bounded Unicode text clipboard records |
| `lib.rs` | Async transport, protocol negotiation and shared DeskVNC commands/events |

The implementation runs in-process in Rust. It uses RustCrypto's AES/CBC, SHA-1
and MD4 implementations, the existing big-integer dependency, flate2 and Tokio.
No new registry package is introduced. The crate is `#![forbid(unsafe_code)]`.
No Python runtime, helper executable or vendor binary is included.

DeskVNC supplies the host library, login prompts, credential vault, tabs/windows,
GPU rendering, fullscreen/scaling, screenshots and input capture. Radmin has
separate credentials in the existing vault. The native driver also accepts the
existing `StreamConnector`, including DeskVNC's SSH-tunnel transport.

The decoder retains one RGBA desktop. It validates an entire delta before
mutating the desktop, converts only the changed spans, and emits damage through
the existing framebuffer event path. Encrypted reads have a dedicated async
owner with a bounded queue so mouse/keyboard events cannot interrupt a partially
read TCP record. Idle connections wait for data; partial records have a deadline.

## Connect

**Network discovery:** Preferences → Network → **Look for Radmin while scanning**
is enabled by default. **Scan network** checks TCP 4899 alongside the existing
VNC/RDP probes. A host is listed as Radmin only after its pre-authentication
greeting matches; the scan never sends credentials. Found hosts use the normal
Nearby **Add host** and **Connect** actions and retain the Radmin protocol.
The scan shares the existing rate limit, concurrency limit and cancellation.

1. Run a DeskVNC build containing this integration.
2. Add a computer and select **Radmin (Radmin security)**.
3. Enter its hostname/IP and port, normally **4899**.
4. Enter the account configured in **Radmin Server → Permissions → Radmin security**,
   or leave credentials empty to use the connection-time prompt.
5. Connect. The remote desktop opens in the normal DeskVNC session view.

Quick Connect accepts `radmin://computer` and `radmin://[IPv6-address]:4899`.
Enter the username in the profile/login prompt; Quick Connect does not forward
URL userinfo to that prompt. Port 4899 presets the Radmin chip for bare endpoints.

**Connect in view-only mode** negotiates server-enforced viewing. To gain control,
disable that saved option and reconnect. On a control connection, the toolbar's
view-only switch temporarily blocks input and releases held keys/buttons.

## Native build and launch

Install Rust 1.95+ and Node 22+. On Ubuntu install the normal Tauri dependencies:

```sh
sudo apt install build-essential pkg-config libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev librsvg2-dev patchelf libssl-dev libdbus-1-dev
npm ci --prefix ui
npm run build --prefix ui
npx --yes @tauri-apps/cli@2 build --no-bundle
./target/release/deskvncviewer
```

To make an installer, omit `--no-bundle` and use `--bundles deb` on Linux or
`--bundles nsis` on Windows. There is no Radmin-specific bundle configuration.
Build on the target operating system using Tauri's normal native prerequisites.

```sh
cargo test -p radmin-core -p remote-core -p vnc-store
cargo test -p vnc-discovery --lib --test radmin_probe --test rdp_probe
cargo clippy -p radmin-core -p vnc-core -p vnc-transport -p vnc-discovery -p vnc-store --all-targets -- -D warnings
cargo check -p deskvncviewer --all-targets
npm run typecheck --prefix ui
npm test --prefix ui
```

## Compatibility

The port follows the existing independently recovered implementation targeting
**Radmin Server 3.5.2.1, Radmin-security authentication**. Windows/NTLM login is not
implemented. Physical keys follow the remote Windows layout; Unicode/IME injection
and horizontal wheel are not implemented. Clipboard support is explicit Unicode
text send/get. Display is lossless 24-bit colour.

The menu/toolbar's **Ctrl+Alt+Delete** sends Radmin's dedicated secure-attention
event in control mode. Its wire encoding is derived from the original Viewer;
see [the recovery notes](crates/radmin-core/SECURE_ATTENTION.md). Server permissions
and Windows policy still determine whether the server performs the request.
**Its live result remains unresolved:** the tester reported failure in both this
client and the official Radmin Viewer on the same machine. That comparison suggests
a server-side restriction, but no policy diagnosis has been confirmed. The vendor's
[troubleshooting article](https://helpdesk.radmin.com/kb/faq.php?id=318) describes the
Windows policy to inspect. The integration does not change that policy.

RGBA and non-inverting mask cursors are supported. Animated definitions use their
first representable frame. Destination-XOR shapes cannot be represented by the
shared RGBA cursor layer. Radmin-specific file transfer, terminal, audio, power
control, monitor switching, dynamic remote resolution
and automatic reconnect are outside this desktop integration. DeskVNC's existing
SSH file/terminal facilities still require a separate SSH service.

## Verification status

| Area | Evidence and scope |
| --- | --- |
| Linux | Native release build and desktop startup on Ubuntu 26.04, x86_64 |
| Live desktop/input | Tester confirmed a real remote desktop and ordinary menu shortcuts during development; not a comprehensive interop matrix |
| Authentication | Fixed cross-language SRP transcript, independent server-side SRP equation over loopback TCP, invalid-proof rejection |
| Encryption/codec | Native padding fixtures, NIST AES-CBC vector, state continuity, full/delta pixels and malformed-input tests |
| Input/clipboard/cursor | Literal key fixtures, modifier identity/release, clipboard parsing, cursor/cache tests |
| Ctrl+Alt+Delete | Static command recovery and encrypted loopback delivery; live transition unresolved as described above |
| Discovery | Loopback tests for greeting recognition, false positives, timeout, disabling and cancellation |
| Windows/macOS | Native execution and installer behavior have not been verified for this integration |

No broad server-version compatibility, complete international-keyboard support or
cryptographic audit is claimed. The SRP big-integer arithmetic is not claimed to
be constant-time. Radmin's legacy checksum/padding is implemented for wire
compatibility; it is not represented as a modern authenticated-encryption scheme.

### Reviewer guide

Start with `crates/radmin-core/src/lib.rs` for lifecycle and view-only enforcement,
then `auth.rs`, `channel.rs` and `desktop.rs` for the untrusted-byte boundaries.
`integration.rs` contains the synthetic TCP server and command-delivery tests.
The shell changes register the driver and select its existing credential fields;
the UI changes add protocol selection, profile editing and ordered secure attention.
`crates/vnc-discovery/tests/radmin_probe.rs` covers the pre-authentication scan.

Radmin credentials use separate `radminUser`/`radminPassword` vault fields. Missing
fields in old credential blobs default to `None`; no host database schema migration
is required. Tests cover redacted Debug output, zeroization, vault lock/unlock
round-trips and absence of credential sentinels in database/WAL/plaintext files.

## Attribution

The protocol algorithms and fixtures were ported from the MIT-licensed
[radmin-compatible-viewer reference implementation](https://github.com/hassidan/radmin-compatible-viewer/tree/b485f85db0e81ad57707d3962523bbfd066ca58c).
Its notice is retained in [the attribution license](crates/radmin-core/LICENSE-MIT).
The Rust integration follows the workspace's MIT OR Apache-2.0 licensing, with
the reference implementation's MIT notice preserved. No proprietary executables,
DLLs, screenshots, credentials or packet captures are distributed in this change.
Radmin is a third-party trademark. This project is not affiliated with or endorsed
by Famatech and requires a separately installed/licensed Radmin Server.
