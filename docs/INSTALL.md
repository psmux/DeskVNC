# Installing DeskVNCViewer

Download the file for your platform from the
[latest release](https://github.com/psmux/DeskVNC/releases/latest).

| Platform | File |
|---|---|
| macOS 12 or newer, Apple Silicon or Intel | `DeskVNCViewer_<version>_universal.dmg` |
| Windows 10 or 11, x64 | `DeskVNCViewer_<version>_x64-setup.exe` |
| Windows, for deployment tooling | `DeskVNCViewer_<version>_x64_en-US.msi` |
| Debian, Ubuntu | `DeskVNCViewer_<version>_amd64.deb` |
| Fedora, RHEL | `DeskVNCViewer-<version>-1.x86_64.rpm` |
| Any x64 Linux | `DeskVNCViewer_<version>_amd64.AppImage` |

## macOS

Open the DMG and drag the app to Applications.

The build is signed with a Developer ID certificate and notarized by Apple, so
it opens normally. There is no "damaged and can't be opened" dialog and no
right-click-to-Open workaround. The binary is universal, so it runs natively on
both Apple Silicon and Intel.

Check it yourself if you want:

```sh
spctl -a -vv -t exec /Applications/DeskVNCViewer.app
# source=Notarized Developer ID
# origin=Developer ID Application: Godwin Josh (LCYYV8JHN6)
```

On first use the app asks for two permissions:

- **Local Network**, for mDNS discovery and the subnet scan. Decline it and you
  can still connect by typing an address.
- **Accessibility**, only if you turn on global input capture, which lets
  system shortcuts reach the remote machine instead of your Mac.

## Windows

**The installer is not code signed**, so Windows SmartScreen shows a blue
dialog reading "Windows protected your PC" and "Windows Defender SmartScreen
prevented an unrecognised app from starting".

To install anyway: click **More info**, then **Run anyway**.

That warning means the publisher is unrecognised, not that anything harmful was
detected. SmartScreen builds reputation from an Authenticode certificate plus
download volume, and this project has neither yet. Signing requires a
commercial certificate, and an Extended Validation certificate to skip the
reputation-building period entirely.

If clicking through an unknown-publisher warning is not acceptable in your
environment, the honest options are:

1. **Verify the checksum first** against the value published with the release,
   then decide. `certutil -hashfile DeskVNCViewer_<version>_x64-setup.exe SHA256`
2. **Build from source.** See the README. You get the same binary, compiled by
   you.
3. **Wait for a signed release.** Tracked, but not scheduled.

The MSI is provided for Group Policy and other deployment tooling. It is
equally unsigned.

## Linux

```sh
sudo apt install ./DeskVNCViewer_<version>_amd64.deb      # Debian, Ubuntu
sudo dnf install ./DeskVNCViewer-<version>-1.x86_64.rpm   # Fedora, RHEL

chmod +x DeskVNCViewer_<version>_amd64.AppImage           # anywhere else
./DeskVNCViewer_<version>_amd64.AppImage
```

Packages are unsigned and not in any repository, so your package manager may
warn about an untrusted origin.

The AppImage needs FUSE. On a system without it, extract instead:

```sh
./DeskVNCViewer_<version>_amd64.AppImage --appimage-extract
./squashfs-root/AppRun
```

Credentials go to the Secret Service (GNOME Keyring, KWallet). On a headless or
minimal system with no Secret Service running, the app falls back to an
encrypted file protected by a master password you choose.

## Verifying a download

Every release lists SHA-256 checksums.

```sh
shasum -a 256 <file>                      # macOS, Linux
certutil -hashfile <file> SHA256          # Windows
```

Compare the result to the value in the release notes. A mismatch means the file
is corrupt or has been tampered with; do not run it.

## Building from source

If you would rather not trust a prebuilt binary, the README has the full build
instructions. You need Rust 1.82 or newer, Node 22 or newer, and the Tauri 2
system dependencies for your platform.
