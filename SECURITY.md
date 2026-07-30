# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately to **godwin@cdtech.in**. If you use GitHub, the
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
tab on this repository works too and is preferred, since it keeps the discussion
attached to the code.

Useful things to include, as far as you have them:

- The affected version, commit, or release artifact.
- Your platform and OS version.
- What an attacker gains, and what access they need to start.
- A reproduction: a packet capture, a malicious server script, or step by step
  instructions. A failing test is ideal.

You should get an acknowledgement within 5 working days. This is a small project
without a paid security team, so please be patient with fix timelines. Nothing
here restricts your right to disclose; a heads up before you publish is
appreciated so a fix can land alongside it.

There is no bug bounty.

## What is in scope

Anything that lets a remote party read, corrupt, or execute beyond what the RFB
session should allow. The parsing surface is the most valuable place to look.

Concretely, the code treats these inputs as hostile:

- **Framebuffer updates.** Every decoder in `crates/vnc-core/src/encodings/`
  (Raw, CopyRect, RRE, Hextile, Zlib, ZRLE, Tight, H.264) parses
  server-controlled bytes. Rectangle geometry, sub-encoding tags, palette
  indices, and compressed lengths all come from the wire.
- **Discovery responses.** `crates/vnc-discovery/src/dnsmsg.rs` decodes mDNS,
  LLMNR, and NetBIOS replies. Any host on the LAN can answer, and the resulting
  name is rendered in the UI. Compression pointers, label lengths, and record
  counts are all attacker chosen.
- **Handshake and authentication.** `crates/vnc-core/src/security/` implements
  VncAuth, VeNCrypt, RA2, Apple Diffie-Hellman, MS-Logon, and the Tight
  security negotiation. Version strings, security type lists, challenge blobs,
  and RSA parameters arrive before any trust is established.
- **Clipboard transfers.** Extended Clipboard payloads are attacker sized and
  attacker encoded.
- **File transfer.** SFTP directory listings and file metadata, including
  filenames used to build local paths.
- **TLS certificates.** Trust-on-first-use pinning decisions in
  `crates/vnc-transport/src/tls.rs`.

Reports about credential storage are also in scope: `crates/vnc-store/src/creds.rs`
holds passwords in the OS keychain with an encrypted-file fallback
(XChaCha20-Poly1305 under an Argon2id derived key). A test asserts that saving a
host profile never writes a secret into the SQLite file or its write-ahead log.

## What is out of scope

- **VNC protocol weaknesses that are not ours.** VncAuth is DES based with an
  8 character password limit. That is a defect in the protocol, and the UI warns
  about it. Use VeNCrypt, RA2, or an SSH tunnel when the server offers one.
- **A malicious server seeing your screen or input.** That is what connecting to
  a VNC server means.
- **Local attackers already running as your user.** Someone with your user
  account can read your keychain through the OS.
- **Missing hardening you would like to see.** Valuable, but file it as a normal
  issue rather than a vulnerability report.
- **Vulnerabilities in dependencies** with no exploitable path through this
  code. Report those upstream. `cargo audit` runs in CI.

## Supported versions

Pre-1.0. Only the latest release and the `main` branch receive fixes.

## Notes for reviewers

The parsers are written to be boring on purpose. If you find a place where these
properties do not hold, that is a bug worth reporting even without a working
exploit:

- Every crate that touches remote bytes declares `#![forbid(unsafe_code)]`:
  `vnc-core`, `vnc-transport`, `vnc-discovery`, `vnc-store`, and `vnc-files`.
  The compiler rejects `unsafe` there, so this is not a review convention that
  can quietly lapse. Verify with
  `grep -rn "forbid(unsafe_code)" crates --include="*.rs"`.
  `unsafe` is confined to `vnc-input-capture`, which wraps platform input APIs
  (`SetWindowsHookExW` on Windows, `CGEventTap` on macOS). That crate handles
  local keyboard events, not network input.
- Every read from a wire buffer is bounds checked. Decoders return an error
  rather than panicking, because a panic in the session task is a denial of
  service.
- Name decoding replaces anything outside printable ASCII, so a hostile answer
  cannot smuggle control characters into the UI.
- Compression pointers may only point strictly backwards, and are capped.
- Rectangle bounds are validated against the framebuffer before any write.

Panics reachable from network input are treated as security bugs, not
robustness bugs.
