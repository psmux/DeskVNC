# Age ratings, audience and store policy

## Apple: Age Rating

App Store Connect, App Information, Age Rating, Edit. Every content question is
answered **None** or **No**:

| Question | Answer |
|---|---|
| Cartoon or fantasy violence | None |
| Realistic violence | None |
| Prolonged graphic or sadistic realistic violence | None |
| Profanity or crude humour | None |
| Mature or suggestive themes | None |
| Horror or fear themes | None |
| Medical or treatment information | None |
| Alcohol, tobacco or drug use or references | None |
| Simulated gambling | None |
| Sexual content or nudity | None |
| Graphic sexual content and nudity | None |
| Contests | None |
| Unrestricted web access | **No** (check, see below) |
| User generated content, messaging or chat | No |
| Gambling | No |
| Loot boxes | No |
| Parental controls, age assurance | No (asked in the 2025 questionnaire, check) |

Expected result: 4+ (Apple's 2025 scheme maps this to 4+ as well, check).

Unrestricted web access: DeskVNC shows the screen of a computer the user
owns, which may have a browser on it. Remote desktop apps on the store answer
No here because the app itself has no browser. If a reviewer pushes back, the
fallback answer is Yes, which moves the rating to 18+ (17+ in the old scheme);
that changes nothing for an adult audience.

## Google Play: content rating (IARC)

Play Console, App content, Content rating, Start questionnaire.

* Email: the account's contact address (entered in Play Console only).
* Category: **All other app types** (not a game, not social, not a
  reference or news app).
* Answers, in the order the questionnaire asks (check, the form changes):

| Question | Answer |
|---|---|
| Violence of any kind | No |
| Sexuality or nudity | No |
| Language | No |
| Controlled substances | No |
| Crude humour | No |
| Gambling or simulated gambling | No |
| Does the app allow users to interact or exchange content with each other? | No. A session connects the user to a computer, not to other users. Boundary help is between two people who already know each other and read a code to each other; there is no directory, chat or content sharing in the app (check whether IARC wants Yes for this; if it does, the rating stays Everyone with a "Users Interact" notice) |
| Does the app share the user's current physical location? | No |
| Does the app allow purchase of digital goods? | No |
| Is the app a web browser or search engine? | No |
| Does the app contain unrestricted internet content? | No |

Expected rating: Everyone / PEGI 3 / USK 0.

## Google Play: target audience and content

* Target age groups: **18 and over** only. Picking anything under 13 pulls the
  app into the Families policy, which needs more review and nothing here
  benefits from it. 16 to 17 can be added later without harm.
* Could the app unintentionally appeal to children? **No.**
* Ads: **No ads.** No ad SDK is in the app.
* In app purchases: none.

## Google Play: policy notes for a remote access app

Play looks hard at remote access and remote control apps, mostly because of
fraud apps that drive someone else's phone. DeskVNC is the other direction:
the phone controls a computer. The points to keep true and to state when asked:

* Accessibility API: not used. The app declares no
  `AccessibilityService`, so the Accessibility declaration form does not apply.
  If a later version adds one, it needs the Accessibility declaration and a
  prominent disclosure, and remote control of the phone itself is restricted.
* Location: not used, foreground or background. Nearby scans the local
  network with ordinary sockets, which does not need `ACCESS_FINE_LOCATION` on
  Android. (check: if the Rust agent reads the Wi-Fi SSID for display, that
  needs location on Android 10 and later. Do not add it.)
* Nearby Wi-Fi devices: `NEARBY_WIFI_DEVICES` is not needed for plain IP
  scanning. Do not declare it unless the app starts using Wi-Fi Direct.
* Foreground service: none in version 1. The session pauses when the app
  goes to the background (see `mobile/CONTRACT.md`). A future background
  session would need a foreground service of type `connectedDevice` or
  `dataSync` and the matching declaration (check the type list when it
  happens).
* Query all packages, SMS, call log, contacts, storage: none.
* **Permissions** expected in the merged manifest: `INTERNET`,
  `ACCESS_NETWORK_STATE`, possibly `ACCESS_WIFI_STATE` and
  `CHANGE_WIFI_MULTICAST_STATE` if Nearby uses mDNS. Anything else should be
  questioned before release. CI prints the merged manifest's permissions
  (planned, check the Android workflow's log once the real crate builds).
* Deceptive behaviour: the listing names the protocols and says plainly
  that a computer on the other end is needed. The demo computer is labelled as
  a demo.
* Financial or support scams: Boundary help sessions always need the
  person at the computer to approve the session, and they can end it at any
  time. That is in the description so a reviewer reading for scam risk sees it.

## Apple: guideline notes

* 2.1 (completeness): the demo computer lets a reviewer exercise the session.
  See `review-notes.md`.
* 2.5.2 (no downloaded code): the app runs no code it receives. A remote
  screen is pixels.
* 4.2 (minimum functionality): VNC, RDP, discovery and help codes are well past
  a wrapped website.
* 5.1.1 (data collection): no account, nothing collected.
* Local network: iOS shows its own prompt the first time the app touches the
  local network. The Info.plist needs `NSLocalNetworkUsageDescription`, for
  example "DeskVNC looks for computers on your network and connects to the
  ones you choose." and, if Nearby uses Bonjour, `NSBonjourServices` listing
  `_rfb._tcp` and any other service types it browses (note for the Rust
  agent).
