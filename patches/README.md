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

## russh

`russh-0.65.1` is a different case. The published crate pins
`rsa = "=0.10.0-rc.18"`, `pkcs1 = "=0.8.0-rc.4"` and
`ssh-key = "=0.7.0-rc.11"`. A prerelease and the final 0.10.0 are the same
semver line to Cargo, so it will not put both in one graph, and vnc-core
(RA2 and Apple RSA logins) is on rsa 0.10.0. The copy applies upstream
russh PR 821 (Eugeny/russh, commit e82790e) and nothing else:
`Cargo.toml` and `Cargo.toml.orig` take rsa 0.10, pkcs1 0.8 and ssh-key
0.7.0-rc.12, `src/keys/format/mod.rs` and `src/keys/format/pkcs8.rs` use
`rsa::PrivateKey` and `pkcs1::RsaPrivateKeyRef`, and `src/keys/key.rs`
updates one test for ssh-key rc.12 refusing a certificate as a CA key.
The published `Cargo.lock` is left out. Remove the folder and its
`[patch.crates-io]` line once a russh release accepts rsa 0.10.
