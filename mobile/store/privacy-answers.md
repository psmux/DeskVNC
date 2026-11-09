# Privacy answers for both stores

The answers follow from `privacy-policy.md`. If the app ever adds crash
reporting, analytics, an account or a cloud sync, every answer here changes.

## Apple: App Privacy ("nutrition label")

App Store Connect, the app, App Privacy, Get Started.

* Do you or your third party partners collect data from this app? **No.**
* The label then reads "Data Not Collected".

Why that holds under Apple's definition: Apple counts data as collected when
it leaves the device in a way that lets the developer or a partner get at it
for longer than it takes to serve the request in real time. In DeskVNC:

* Session traffic goes to the user's own computer, which we do not run.
* A Boundary code lookup is answered and the code expires after one use.
* Relayed Boundary traffic is forwarded in real time and not kept. (check:
  confirm the relay keeps no logs of addresses beyond what is needed to run
  the session, and keep it that way.)
* No SDK in the app sends anything home. (check: the Rust agent confirms no
  crash reporter or analytics crate in `mobile/src-tauri`.)

Privacy Policy URL: https://deskvnc.ripeflow.com/privacy

Tracking: the app does not track, so there is no App Tracking Transparency
prompt and no `NSUserTrackingUsageDescription`.

### Privacy manifest (PrivacyInfo.xcprivacy)

Apple wants a privacy manifest in the app bundle, and required reason API
declarations for some system calls. A note for whoever owns
`mobile/src-tauri/gen/apple`:

* `NSPrivacyTracking` false, `NSPrivacyTrackingDomains` empty,
  `NSPrivacyCollectedDataTypes` empty.
* `NSPrivacyAccessedAPITypes`: the WebView and the Rust standard library read
  file timestamps (`NSPrivacyAccessedAPICategoryFileTimestamp`, reason
  `C617.1`) and the app keeps settings in `UserDefaults` only if the Tauri
  store plugin or WebKit does (`NSPrivacyAccessedAPICategoryUserDefaults`,
  reason `CA92.1`). Check the build's report: App Store Connect emails a list
  of missing reasons after the first upload.

## Google Play: Data safety

Play Console, App content, Data safety.

| Question | Answer |
|---|---|
| Does your app collect or share any of the required user data types? | **No** |
| Is all of the user data collected by your app encrypted in transit? | Not asked once the answer above is No (check) |
| Do you provide a way for users to request that their data is deleted? | Not asked once the answer above is No (check) |

Reasoning, in the terms Google uses:

* Google exempts data that is processed only on the device, and data that is
  sent end to end encrypted so nobody in the middle can read it.
* Saved computers, thumbnails and passwords stay on the device.
* Screen pictures and input go from the phone to the user's own computer over
  the protocol the user picked. We are not a party to that transfer.
* Boundary sessions are encrypted between the phone and the other computer, and
  the relay only forwards the encrypted stream. (check: the Rust agent
  confirms the Boundary transport is encrypted end to end, with keys the relay
  never holds. If it is not, declare "App activity, Other actions" as
  collected, processed ephemerally, not shared, required for app
  functionality.)

## Google Play: other App content answers

| Section | Answer |
|---|---|
| Privacy policy | https://deskvnc.ripeflow.com/privacy |
| Ads | No, the app does not contain ads |
| App access | Some functionality is restricted? **No.** Everything can be reached without signing in. The demo computer covers the session screen; see `review-notes.md` |
| Content rating | See `ratings-and-policy.md` |
| Target audience | 18 and over (see `ratings-and-policy.md`) |
| News app | No |
| COVID-19 contact tracing or status | No |
| Government app | No |
| Financial features | None |
| Health | None |
| Data safety | As above |
| Advertising ID | The app does not use the advertising ID. Answer No, and the manifest must not declare `com.google.android.gms.permission.AD_ID` (check the merged manifest after the first build) |
