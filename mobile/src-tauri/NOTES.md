# deskvnc-mobile: notes for whoever builds and ships it

The Rust side of the phone app. Commands are the ones in `mobile/CONTRACT.md`,
field names follow `mobile/ui/src/api/contract.ts`.

## Identity and config

* Crate `deskvnc-mobile`, lib `deskvnc_mobile_lib` (staticlib, cdylib, rlib),
  entry point `run()` with `tauri::mobile_entry_point`.
* `tauri.conf.json`: productName DeskVNC, identifier
  `com.psmux.deskvnc.mobile`, version 0.1.0, frontendDist `../ui/dist`,
  devUrl `http://localhost:5174`, beforeDevCommand and beforeBuildCommand
  `npm run dev` and `npm run build` with `cwd: "ui"`. The Tauri CLI resolves
  a hook's `cwd` against the folder it was started in, so run it from
  `mobile/`, as the mobile workflows do. Without an explicit `cwd` it runs the
  hook in the first folder below with a `package.json`, which from `mobile/`
  is `mobile/scripts`, not the UI.
  iOS minimum 15.0, Android minSdk 26.
* Icons are copies of the desktop ones in `icons/`. Replace freely.
* `capabilities/default.json` grants `core:default` and exactly the
  contract's commands to the `main` window. `build.rs` declares them, so a
  command added later needs a line in both places.

## Native projects (`gen/`)

`gen/apple` and `gen/android` come from `cargo tauri ios init --ci` and
`cargo tauri android init --ci`, run from `mobile/` by
`.github/workflows/mobile-core-check.yml` with `init: true`, so the Xcode
build phase and the Gradle task call `cargo tauri` like the CI builds. What
was set after generating (then `xcodegen generate` in `gen/apple`, with empty
`Externals` and `assets` folders present, to add the privacy manifest to the
Xcode project):

* iOS `ITSAppUsesNonExemptEncryption` false: the app only uses the
  encryption built into TLS and QUIC, which is exempt.
* iOS `PrivacyInfo.xcprivacy` in `gen/apple/deskvnc-mobile_iOS`: no tracking,
  no collected data, and three required reason APIs: system boot time 35F9.1
  (`std::time::Instant`), file timestamp C617.1 (files in the app container),
  user defaults CA92.1 (the web view and runtime).
* iOS `Info.plist` (`gen/apple/deskvnc-mobile_iOS/Info.plist`, and the same
  keys in `gen/apple/project.yml`, since xcodegen rewrites the plist from it,
  and in `Info.ios.plist`, which the Tauri CLI merges in, so they survive a
  fresh `ios init`):
  * `NSLocalNetworkUsageDescription`: why the app reaches computers on the
    local network.
  * `NSBonjourServices`: `_rfb._tcp`, `_rdp._tcp`, `_boundary._udp`,
    `_ard._tcp`, `_workstation._tcp` (the last two are what the mDNS browse in
    `vnc-discovery` also asks for).
* Android `AndroidManifest.xml`: `INTERNET`, `ACCESS_NETWORK_STATE`,
  `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`.

## Things that differ from the desktop, and why

* libc is pinned to 0.2.189 (in this crate's iOS dependencies, which pins
  the whole workspace). 0.2.190 and 0.2.191 declare `in6_ifreq` and the
  routing socket constants for macOS only, and netdev (via vnc-discovery and
  iroh's netwatch) and netwatch then fail to compile for iOS. Lift the pin
  once those crates and libc agree.
* Boundary progress: `boundary-driver` reports each step as `authenticating`
  with a sentence. The phone turns the two waiting sentences into
  `method: "approval"` and the earlier steps into `connecting`.
* Frames are held back until a session has sent `desktop-resize`; a held
  frame is replaced by a full repaint.

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
