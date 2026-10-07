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
# origin=Developer ID Application: <certificate holder> (<team ID>)
```

The macOS releases from v0.27.1 through v0.27.4 omitted the `dvv` executable.
If the **AI Agents** panel says “This build has no dvv inside it to register”,
the Claude Code registration button cannot work, even though the viewer itself
works. Install v0.27.5 or newer for the bundled executable. If you must stay
on an older release, build `dvv` from source with
`cargo build -p dvv` and register the absolute path to `target/debug/dvv`
manually as described in [the agent integration notes](AGENTS.md). Reinstalling
one of those releases will not fix it.

On Windows and Linux, releases before v0.27.6 shipped no `dvv` at all, and on
Windows the agent plane could not start. Install v0.27.6 or newer to drive
machines from an agent on either platform.

On first use the app asks for two permissions:

- **Local Network**, for mDNS discovery and the subnet scan. Decline it and you
  can still connect by typing an address.
- **Accessibility**, only if you turn on global input capture, which lets
  system shortcuts reach the remote machine instead of your Mac.

## Windows

From 0.27.10 the installer, the MSI and the app inside them are code signed by
**Open Source Developer Godwin Josh**, with a certificate from Certum. Windows
shows that name as the publisher when it asks to install.

The certificate is new, and SmartScreen builds reputation from a certificate
plus download volume. Until it has seen enough downloads it may still show
"Windows protected your PC". The publisher line in that dialog should read
Open Source Developer Godwin Josh. Click **More info**, then **Run anyway**.

To check a download yourself, right click it, open **Properties**, then
**Digital Signatures**, or compare the checksum published with the release:
`certutil -hashfile DeskVNCViewer_<version>_x64-setup.exe SHA256`

The MSI is provided for Group Policy and other deployment tooling, and is
signed the same way. Releases before 0.27.10 are unsigned.

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
