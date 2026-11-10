# Patched crates

Copies of crates.io releases with a small fix each, applied through
`[patch.crates-io]` in the workspace `Cargo.toml`. Everything else in each
folder is the published crate, unchanged.

Why: since libc 0.2.190, libc declares `in6_ifreq` and the routing socket
constants (`RTM_*`, `RTAX_*`, `RTA_IFP`, `RTF_GATEWAY`, `RTF_IFSCOPE`) for
macOS only. iOS runs the same XNU kernel with the same values, but netdev
and netwatch still read them from libc on iOS and stop compiling. Patching
them keeps libc, and everything else, on current releases.

| Folder | Fix |
|---|---|
| `netdev-0.47.0` | `src/os/darwin/ipv6_addr_flags.rs` declares its own `In6Ifreq` (288 bytes, the Darwin layout) |
| `netdev-0.46.3` | same fix; netwatch 0.19.3 needs netdev 0.46 |
| `netwatch-0.19.3` | `src/libc_ios.rs` re-exports libc and adds the missing constants on iOS; `src/interfaces/bsd.rs`, `src/interfaces/bsd/macos.rs` and `src/netmon/bsd.rs` use it on iOS only |

netwatch 0.19.3 is the newest version iroh 1.4.1 accepts. macOS, Windows,
Linux and Android builds compile the same code as the published crates.

Remove a folder and its `[patch.crates-io]` line once the upstream crate
builds for iOS against the current libc. To check:
`cargo check --target aarch64-apple-ios -p deskvnc-mobile`.
