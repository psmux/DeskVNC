# App Store listing

Paste each field into App Store Connect, App Information and the version page.
Limits are Apple's; `mobile/scripts/check-copy.mjs` counts them and looks for
dash punctuation.

## App Information

| Field | Value |
|---|---|
| Name (30) | DeskVNC |
| Subtitle (30) | VNC and RDP for your computers |
| Primary category | Utilities |
| Secondary category | Productivity |
| Bundle ID | com.psmux.deskvnc.mobile |
| SKU | deskvnc-mobile |
| Content rights | Does not contain, show or access third party content |
| Price | Free |
| Support URL | https://github.com/psmux/DeskVNC/issues |
| Marketing URL | https://deskvnc.ripeflow.com |
| Privacy Policy URL | https://deskvnc.ripeflow.com/privacy |

## Promotional text (170)

<!-- field: promo -->
See and drive your Windows PC, Mac or Linux box from your phone. Saved computers show their last screen, so you know which is which before you tap.
<!-- end -->

## Keywords (100, commas, no spaces after them)

<!-- field: keywords -->
vnc,rdp,remote desktop,remote access,screen sharing,raspberry pi,windows,mac,linux,support,viewer
<!-- end -->

## Description (4000)

<!-- field: description -->
DeskVNC connects your iPhone or iPad to the computers you already have. It speaks VNC and RDP, so it works with Screen Sharing on a Mac, with Windows Remote Desktop, and with the VNC servers people run on Linux machines and Raspberry Pis.

Each saved computer gets a large card with the last picture of its screen, the operating system's artwork and a colour you pick. The office PC and the one under the TV stop looking alike.

On the same network, Nearby looks for computers that answer on the VNC and RDP ports and lists them with their names. Tap one to connect, and save it if you want it back later.

Helping someone works with a code. They open DeskVNC Support on their computer and read you the twelve digit number. You type it on the number pad and press Connect. They still approve the session on their side, and they can end it whenever they like. When your phone and their computer cannot reach each other directly, the session goes through the Boundary relay.

On the remote screen you choose how touch behaves. In trackpad mode you push a pointer around like on a laptop. In direct mode you tap exactly where you want to click. Pinch to zoom, scroll with two fingers, long press for a right click. A key bar above the keyboard has Ctrl, Alt, the Windows or Command key, Esc, Tab, the arrows and Ctrl+Alt+Del.

There is no account. The app does not collect analytics or track you. Passwords you save stay in the iOS Keychain on your device.

Want to try it before setting anything up? The demo computer on the main screen opens a sample desktop that runs inside the app with no network.

DeskVNC is open source under the MIT and Apache 2.0 licences. The code, the desktop apps and the issue tracker are on GitHub.
<!-- end -->

## What's New (4000)

Apple rejects metadata that names another phone platform, so this stays
separate from `mobile/store/whats-new.txt`, the Play text the Android workflow
sends. For the first version:

<!-- field: whatsnew -->
First release for iPhone and iPad.
<!-- end -->

## Notes

* SSH, file transfer and the agent tools are desktop only in this version. The
  description does not mention them, so a reviewer will not look for them.
* Apple's guideline 2.3.10 bars naming other mobile platforms (Android) in
  App Store metadata. Naming Windows, macOS and Linux as the computers you
  connect to is normal for remote desktop apps (check against current review
  practice if a rejection cites it).
