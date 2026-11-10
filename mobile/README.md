# DeskVNC for iPhone, iPad and Android

The phone and tablet app. It lives in the same repository as the desktop app
and shares its protocol crates, but it has its own Tauri crate, its own UI and
its own build workflows, so a desktop release never waits on a mobile one and
the other way round.

## What it does in version 1

* Connect to a computer over VNC, RDP or Boundary from a phone or tablet.
* Keep a visual library of saved computers, each a large card with a live
  thumbnail, the operating system's artwork and a colour per protocol.
* Find computers on the same network with a radar style scan.
* Help someone with a Boundary code: a big number pad, the code fills in as
  four digit groups, then one press to connect.
* Drive the remote desktop by touch. Two modes: trackpad (a pointer you push
  around, like a laptop trackpad) and direct touch (tap where you want to
  click). Pinch to zoom, two finger scroll, long press for right click, a key
  bar with Ctrl, Alt, Win/Cmd, Esc, Tab, arrows and Ctrl+Alt+Del.

SSH terminals, file transfer and the agent plane stay desktop only for now.

## Layout

```
mobile/
  README.md          this file
  CONTRACT.md        the commands and events between the UI and Rust
  src-tauri/         Tauri 2 app crate `deskvnc-mobile` (iOS and Android)
  ui/                React + Vite + Tailwind touch UI
  store/             store listings, screenshots, privacy policy, review notes
.github/workflows/
  mobile-android.yml signed AAB and APK, optional Play upload
  mobile-ios.yml     signed IPA, optional TestFlight upload
```

## Identity

* Display name: DeskVNC
* Bundle id and Android package: `com.psmux.deskvnc.mobile`
* Version follows the mobile tags `mobile-v*`, separate from desktop `v*`.

## Rules for anyone working here

* Do not change the desktop app's behaviour. If a shared crate needs a change
  to build for iOS or Android, gate it behind `cfg(target_os = ...)` or a
  feature, and keep desktop builds byte for byte the same in behaviour.
* The frame and input byte formats are the desktop ones, verbatim:
  `src-tauri/FRAME_FORMAT.md` and the `send_input` section of
  `src-tauri/IPC_CONTRACT.md`.
* No dash punctuation in user visible copy, docs or commits.
