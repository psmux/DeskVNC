# deskvnc-mobile: notes for whoever builds and ships it

The Rust side of the phone app. Commands are the ones in `mobile/CONTRACT.md`,
field names follow `mobile/ui/src/api/contract.ts`.

## Identity and config

* Crate `deskvnc-mobile`, lib `deskvnc_mobile_lib` (staticlib, cdylib, rlib),
  entry point `run()` with `tauri::mobile_entry_point`.
* `tauri.conf.json`: productName DeskVNC, identifier
  `com.psmux.deskvnc.mobile`, version 0.1.0, frontendDist `../ui/dist`,
  devUrl `http://localhost:5174`, beforeBuildCommand
  `npm run build --prefix ../ui` (the same shape as the desktop's).
  iOS minimum 15.0, Android minSdk 26.
* Icons are copies of the desktop ones in `icons/`. Replace freely.
* `capabilities/default.json` grants `core:default` and exactly the
  contract's commands to the `main` window. `build.rs` declares them, so a
  command added later needs a line in both places.

## Native projects (`gen/`)

`gen/apple` and `gen/android` come from `tauri ios init` and
`tauri android init` (run by `.github/workflows/mobile-core-check.yml` with
`init: true`, then committed). What was set by hand after generating:

* iOS `Info.plist`:
  * `NSLocalNetworkUsageDescription`: why the app reaches computers on the
    local network.
  * `NSBonjourServices`: `_rfb._tcp`, `_rdp._tcp`, `_boundary._udp`,
    `_ard._tcp`, `_workstation._tcp` (the last two are what the mDNS browse in
    `vnc-discovery` also asks for).
* Android `AndroidManifest.xml`: `INTERNET`, `ACCESS_NETWORK_STATE`,
  `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`.

## Things that differ from the desktop, and why

* Secrets: iOS Keychain through `apple-native-keyring-store` (protected data
  store, the only one iOS has). Android: `android-native-keyring-store`, AES
  key in the Android Keystore, ciphertext in private preferences. It finds the
  Android context through `ndk-context`, which Tauri's activity sets up. A
  desktop build of this crate keeps secrets in memory only, it exists for
  checks and tests.
* mDNS on iOS: raw multicast sockets need Apple's multicast entitlement
  (`com.apple.developer.networking.multicast`), which has to be requested from
  Apple. Without it the mDNS half of the scan finds nothing on iOS, and the
  TCP sweep of the subnet (5900, 5901, 3389, 5940) still works once the person
  allows local network access. Android takes a Wi-Fi multicast lock for the
  length of a scan (`src/android.rs`).
* The Boundary code service is compiled in: set
  `BOUNDARY_DEFAULT_CODE_SERVICE` in the build environment of a release, as
  the desktop release does, or `boundary_resolve` with a code says no service
  is configured. A full `boundary1:` invitation works without it.
* Building needs `mobile/ui/dist` to exist (`tauri::generate_context!`). The
  check workflow writes a placeholder `index.html` when the UI is not built.

## Small contract details the UI relies on

* `session_input` and `session_snapshot` take a raw body with headers:
  `x-session-id` and `x-input-seq`, or `x-session-id`, `x-width` and
  `x-height`. The body length of a snapshot must be `width * height * 4`.
* `hosts_set_secret`: a missing or null `username` or `password` leaves that
  value as it is, an empty string clears it.
* `session_credentials` with both `username` and `password` missing cancels
  the prompt and abandons the attempt. `save` only applies to a saved host,
  and is written only after the server accepts the credential.
* `session_trust` with `accept: false` ends the session.
* `scan_start` may send `found` again for a computer it already reported,
  when a better name arrives; key rows by `address` and `port`.
* Background: frames pause at once; within 30 seconds the session resumes
  with a full repaint; after that each session gets a `state-changed` to
  `disconnected` with `can_retry: true` and then `ended`.
* RDP asks for the server's default desktop size, since `ConnectTarget` has no
  viewport. A phone sized desktop needs a `viewportWidth` and
  `viewportHeight` on the target later.
