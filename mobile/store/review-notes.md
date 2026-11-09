# Notes for app review

DeskVNC is a remote desktop client, so its main screen needs a computer on the
other end. Reviewers do not have one, and Apple and Google both reject an app
they cannot exercise. The app answers that with a built in demo computer: a
"Try a demo computer" card on the Computers screen opens a sample desktop that
runs inside the app, with no network and no account. The session screen,
touch modes, zoom, the key bar and the keyboard all work against it exactly as
they do against a real computer.

What the app needs for this (owned by the Rust and UI agents, listed so the
notes stay true):

* The demo card is always present on Computers, including on a fresh install
  with no saved computers. It cannot be deleted, only hidden in Settings.
* The demo desktop draws a believable desktop (windows, a text field, a few
  buttons) and reacts to clicks, typing and scrolling, so a reviewer sees the
  input path do something.
* It sends nothing over the network, so it works in airplane mode.

## App Store Connect: App Review Information

Sign-in required: **No.**

Notes (paste into the Notes field, 4000 characters at most):

<!-- field: apple-review -->
DeskVNC connects to the user's own computers over VNC and RDP, and to a helper's computer with a twelve digit Boundary code. There is no account and no sign in.

To try a full session without a computer of your own:
1. Open the app. The Computers screen shows a card named "Try a demo computer".
2. Tap it. A sample desktop opens inside the app. It runs on the device and uses no network, so it also works in airplane mode.
3. Drag on the screen to move the pointer (trackpad mode is the default). Tap to click. Use the mode button in the toolbar to switch to direct touch, where a tap clicks where your finger is.
4. Pinch to zoom, drag with two fingers to scroll, long press for a right click.
5. Tap the keyboard button and type into the text box on the sample desktop. The key bar above the keyboard sends Ctrl, Alt, Command or Windows, Esc, Tab, the arrow keys and Ctrl+Alt+Del.
6. Tap Disconnect to return to Computers.

Nearby scans the local network for computers that accept VNC or RDP. On a network with none it reports that nothing was found. The Help tab takes a Boundary code from someone running DeskVNC Support on their computer; without such a person the code is refused, which is expected.

The app asks for Local Network access only when you open Nearby or connect to a computer on your network. It collects no data and has no in app purchases or ads.
<!-- end -->

Contact information: the account owner's name, phone and email go in App
Store Connect only. Do not add them here.

If a reviewer still wants a live server: we can run a public demo VNC server
with a read only view of a throwaway desktop and give its address here. That
costs a machine and attracts abuse, so it is the fallback, not the plan.

## Google Play: App access

Play Console, App content, App access: choose **All functionality is available
without special access**. Then, under instructions (optional but read by
reviewers):

<!-- field: play-access -->
No sign in is needed. To see a remote session without your own computer, tap "Try a demo computer" on the Computers screen. It opens a sample desktop that runs inside the app with no network. Drag to move the pointer, tap to click, pinch to zoom, two fingers to scroll, long press for a right click, and the keyboard button brings up the keyboard and the key bar. Nearby and the Help code screen need real computers on the other end and show an empty or refused result without them.
<!-- end -->

## Export compliance (Apple)

DeskVNC uses encryption: TLS (rustls) for RDP and for VNC over TLS, the VNC
and Apple Remote Desktop authentication schemes (DES challenge, Diffie
Hellman with AES), and the Boundary transport (QUIC with TLS 1.3, check). Every
algorithm is standard and published; nothing is proprietary. The encryption
protects the user's own sessions and logins and is not offered as a
cryptographic service to other apps.

That is the mass market case that Apple treats as exempt from uploading
export documents. The plan:

* Set `ITSAppUsesNonExemptEncryption` to **false** in the iOS Info.plist (note
  for the Rust agent: `mobile/src-tauri/Info.ios.plist` or the generated
  `gen/apple/deskvnc-mobile_iOS/Info.plist`, whichever the crate uses), so App
  Store Connect does not ask on every build.
* In App Store Connect the first time it asks, answer that the app uses
  encryption and qualifies for the exemption for standard algorithms used in a
  mass market product (check the wording of the current questions; if it
  insists on documentation for France, the answer is the same, standard
  algorithms only).
* (check) Whether a self classification report to the US Bureau of Industry
  and Security is still required for mass market 5D992.c software. The 2021
  EAR change removed it for most cases. This is a legal call for the account
  owner, not something CI decides.

Google Play asks nothing about export at upload. The app is distributed from
the US to all countries Play supports (check against current sanctions lists,
which Play applies on its own).
