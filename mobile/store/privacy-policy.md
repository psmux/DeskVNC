# DeskVNC privacy policy

Effective 10 November 2026. This covers the DeskVNC app for iPhone, iPad and
Android phones and tablets.

## The short version

DeskVNC collects nothing about you. There is no account, no analytics, no
advertising and no tracking. The app talks to the computers you tell it to
connect to, and to the Boundary services only when you use a Boundary code or
when a direct path to a computer fails.

## What stays on your device

* The list of computers you save: names, addresses, ports, user names, the
  colour and artwork you pick for each card.
* A small picture of each computer's screen from your last session, used on
  its card.
* Passwords you choose to save. These go into the iOS Keychain or the Android
  Keystore, which the operating system encrypts. They are never written to the
  app's own files and never leave the device except to log in to the computer
  they belong to.
* Your settings.

Deleting a computer from the app deletes its picture and saved password.
Deleting the app removes its files. iOS keeps Keychain entries after an app is
removed, so DeskVNC clears any it finds left over the first time it starts
after a new install (check with the app's current build). None of it is backed
up to us, because we have no server that holds it.

## Where the app connects

* To the computers you connect to, over VNC or RDP, directly from your phone.
  What you see and type in a session goes between your phone and that computer.
* When you press Nearby, the app looks for computers on your local network.
  It does not report what it finds to anyone.
* When you enter a Boundary code, the app asks the Boundary code service which
  invitation the code stands for. A code works once and expires.
* For a Boundary session, the app first tries to reach the other computer
  directly. If the networks between you do not allow that, the session passes
  through the Boundary relay. The relay forwards encrypted traffic between the
  two ends. It does not keep the contents of sessions. Like any internet
  service it sees the network addresses of both ends while the session is
  open.

None of these services ask for your name, email address or any other personal
detail. We do not sell or share data, because we do not hold any.

## Permissions the app asks for

* Local network (iOS) so Nearby can find computers on your Wi-Fi and so you can
  connect to them. On Android this is the ordinary network permission.
* Nothing else. The app does not use your location, contacts, photos, camera,
  microphone or the Android Accessibility service.

## Children

DeskVNC is a tool for adults who manage their own computers. It is not aimed
at children and does not knowingly collect anything from them; it collects
nothing from anyone.

## Changes

If this policy changes, the new version will be posted at
https://deskvnc.ripeflow.com/privacy with a new effective date. The history of
this file is public in the DeskVNC repository on GitHub.

## Contact

Write to support@ripeflow.com, or open an issue at
https://github.com/psmux/DeskVNC/issues.
