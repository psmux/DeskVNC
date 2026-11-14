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
| Raspberry Pi 4 or 5 (64-bit Raspberry Pi OS), ARM64 Debian or Ubuntu | `DeskVNCViewer_<version>_arm64.deb` |
| ARM64 Fedora, RHEL | `DeskVNCViewer-<version>-1.aarch64.rpm` |
| Any ARM64 Linux | `DeskVNCViewer_<version>_aarch64.AppImage` |
| Arch Linux, x64 or ARM64 | PKGBUILD in the repository, see [Arch Linux](#arch-linux) |

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
sudo apt install ./DeskVNCViewer_<version>_arm64.deb      # Raspberry Pi OS 64-bit, ARM64
sudo dnf install ./DeskVNCViewer-<version>-1.x86_64.rpm   # Fedora, RHEL

chmod +x DeskVNCViewer_<version>_amd64.AppImage           # anywhere else
./DeskVNCViewer_<version>_amd64.AppImage
```

The ARM64 packages need a 64-bit system. On a Raspberry Pi, `uname -m` prints
`aarch64` on 64-bit Raspberry Pi OS; the older 32-bit system (`armv7l`) cannot
run them.

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

DeskVNC Support for Linux is a tarball with the program, its app menu entry and
its icon. It runs from wherever you unpack it:

```sh
tar -xzf DeskVNC-Support-Linux-x86_64.tar.gz      # or -aarch64 on ARM64
./deskvnc-support --install    # once: adds it to your app menu with its icon
./deskvnc-support
```

`--install` copies the program to `~/.local/share/deskvnc-support/`, writes
`deskvnc-support.desktop` and the icon under `~/.local/share`, and points the
menu entry at that copy. It needs no administrator, and the folder you unpacked
the tarball into can be deleted afterwards. Run it again from a newer tarball to
update the installed copy.

## Arch Linux

The repository carries a PKGBUILD for `deskvncviewer-bin`, which repackages the
release `.deb` for x86_64 or aarch64. It is not on the AUR yet, so build it with
makepkg from a clone:

```sh
git clone https://github.com/psmux/DeskVNC.git
cd DeskVNC/packaging/aur/deskvncviewer-bin
makepkg -si
```

makepkg downloads the `.deb` from the release and checks it against the
SHA-256 in the PKGBUILD, which comes from the release's `SHA256SUMS.txt`. The
package puts `deskvncviewer` and the `dvv` command in `/usr/bin`, adds the menu
entry and icons, and pulls in webkit2gtk-4.1, gtk3 and the other runtime
libraries. `sudo pacman -R deskvncviewer-bin` removes it.

Releases after 0.36.1 also carry the PKGBUILD as an asset. To write one for
any release yourself, run `scripts/aur-update.sh <version>` from the repository
root.

## Android

Every release carries the phone app as `DeskVNC-Android-<version>.apk`.

1. Open the [latest release](https://github.com/psmux/DeskVNC/releases/latest)
   on the phone and tap the `.apk` to download it.
2. Open the downloaded file. The first time, Android asks you to allow
   installs from your browser or file manager. Allow it, then go back and
   tap **Install**.
3. To update, install the newer release's `.apk` the same way. It installs
   over the old one and keeps your saved computers.

Every release APK is signed with the same key, so updates install in place.
Its SHA-256 is in `SHA256SUMS.txt` on the release, like the desktop files.

The iPhone and iPad app is coming to the App Store.

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
