# Google Play listing

Paste into Play Console, Grow users, Store presence, Main store listing, and
Store settings. `mobile/scripts/check-copy.mjs` counts the limits and looks for
dash punctuation.

## Store settings

| Field | Value |
|---|---|
| App name (30) | DeskVNC |
| Package | com.psmux.deskvnc.mobile |
| App or game | App |
| Category | Tools (Play has no Utilities category; Productivity is the other fit) |
| Tags | Remote desktop, Productivity (pick the closest Play offers, check) |
| Free or paid | Free |
| Contains ads | No |
| Email | a support address on the publishing account (Play requires one; it is shown publicly) |
| Website | https://deskvnc.ripeflow.com |
| Privacy policy | https://deskvnc.ripeflow.com/privacy |

The developer contact email is required and public. Use an address made for
this, not a personal one, and do not write it into this repository.

## Short description (80)

<!-- field: short -->
Reach your Windows PC, Mac or Linux box from your phone, over VNC or RDP
<!-- end -->

## Full description (4000)

<!-- field: full -->
DeskVNC connects your phone or tablet to the computers you already have. It speaks VNC and RDP, so it works with Windows Remote Desktop, with Screen Sharing on a Mac, and with the VNC servers people run on Linux machines and Raspberry Pis.

Each saved computer gets a large card with the last picture of its screen, the operating system's artwork and a colour you pick. The office PC and the one under the TV stop looking alike.

On the same network, Nearby looks for computers that answer on the VNC and RDP ports and lists them with their names. Tap one to connect, and save it if you want it back later.

Helping someone works with a code. They open DeskVNC Support on their computer and read you the twelve digit number. You type it on the number pad and press Connect. They still approve the session on their side, and they can end it whenever they like. When your phone and their computer cannot reach each other directly, the session goes through the Boundary relay.

On the remote screen you choose how touch behaves. In trackpad mode you push a pointer around like on a laptop. In direct mode you tap exactly where you want to click. Pinch to zoom, scroll with two fingers, long press for a right click. A key bar above the keyboard has Ctrl, Alt, the Windows or Command key, Esc, Tab, the arrows and Ctrl+Alt+Del.

There is no account. The app does not collect analytics or track you. Passwords you save stay in the Android Keystore on your device.

DeskVNC does not use the Accessibility service and does not ask for your location. It only reaches the computers you connect to.

Want to try it before setting anything up? The demo computer on the main screen opens a sample desktop that runs inside the app with no network.

DeskVNC is open source under the MIT and Apache 2.0 licences. The code, the desktop apps and the issue tracker are on GitHub.
<!-- end -->

## Release notes (500)

Kept in `mobile/store/whats-new.txt`. The Android workflow sends that file with
each upload to the internal track.

## Graphics

| Asset | Size | File |
|---|---|---|
| App icon | 512 x 512 PNG, 32 bit | `mobile/icons/out/store/play-icon-512.png` |
| Feature graphic | 1024 x 500 PNG or JPEG, no alpha | `mobile/store/art/out/feature-graphic.png` |
| Phone screenshots | 2 to 8, 1080 x 1920 | `mobile/store/screenshots/out/android-phone/` |
| 7 inch tablet | up to 8, 1200 x 1920 | `mobile/store/screenshots/out/android-tablet-7/` |
| 10 inch tablet | up to 8, 1600 x 2560 | `mobile/store/screenshots/out/android-tablet-10/` |
