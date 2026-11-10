# Going live on Google Play and the App Store

The steps in order, for both stores. Each one says who does it:

* CI: a workflow does it with no one watching.
* Owner: the account owner signs in and clicks. These are things an API
  key or a script cannot do, or should not.
* Repo: a change in this repository, by whoever works on the app.

"(check)" marks a fact I could not confirm. Look at the console before
relying on it.

The publishing accounts are the owner's personal Apple developer team (the
one that signs the desktop app) and the owner's personal Google Play
developer account. Neither is named in this repository. Their ids reach CI as
secrets only.

## 0. Before either store

1. Repo: the app builds on both workflows (`mobile-android.yml`,
   `mobile-ios.yml`) with no secrets, producing a debug signed APK, an
   unsigned AAB and a simulator build.
2. Repo: the "Try a demo computer" card and its sample desktop work with
   no network. Review depends on it (`review-notes.md`).
3. Repo: iOS Info.plist has `ITSAppUsesNonExemptEncryption` false,
   `NSLocalNetworkUsageDescription`, and `NSBonjourServices` if Nearby uses
   Bonjour. A `PrivacyInfo.xcprivacy` is in the app bundle
   (`privacy-answers.md`).
4. Repo: the merged Android manifest asks for nothing beyond
   `ratings-and-policy.md` lists. No `AD_ID`, no location, no Accessibility
   service.
5. Owner: publish `mobile/store/privacy.html` at
   https://deskvnc.ripeflow.com/privacy. Both stores fetch the URL during
   review.
6. Repo: run `node mobile/scripts/store-screenshots.mjs --serve` against
   the finished UI and `mobile/scripts/export-store-art.sh`. Look at every
   image before uploading.

## 1. Google Play

A personal developer account created after November 2023 has to run a closed
test with at least 12 testers who stay opted in for 14 days in a row before
Play lets it apply for production. Plan for about three weeks from the first
closed test build to a production release, plus review time.

### One time setup

1. Owner: confirm the Play Console account is verified (identity, and the
   Android device check in the Play Console app). (check: Play asks for
   device verification on personal accounts.)
2. Owner: on this Mac, run
   `mobile/scripts/make-android-upload-key.sh` to make the upload key outside
   the repo. Store the keystore and its password in the password manager.
3. Owner: Play Console, Create app. Name DeskVNC, default language English
   (United States), App, Free. Accept the declarations.
4. Owner: Play Console, Setup, API access. Link a Google Cloud project,
   create a service account, download its JSON key. Then Users and
   permissions, invite the service account's email with permission to
   release to testing tracks for DeskVNC only.
5. Owner: set the secrets:
   ```sh
   mobile/scripts/set-mobile-secrets.sh psmux/DeskVNC \
     --android-keystore ~/.config/deskvnc-mobile/upload.jks \
     --android-alias upload \
     --play-json /path/to/service-account.json
   ```
6. Owner: App content, answer every section from `privacy-answers.md` and
   `ratings-and-policy.md`: privacy policy URL, ads (none), app access (all
   available, with the demo note), content rating questionnaire, target
   audience (18 and over), data safety (no data collected), news, government
   and financial features (no).
7. Owner: Store presence, Main store listing. Copy from
   `listing-google-play.md`, icon, feature graphic and screenshots. Store
   settings, contact details: email support@ripeflow.com, website
   https://deskvnc.ripeflow.com.

### Internal testing (days 1 to 2)

8. Repo: tag a release, for example `git tag mobile-v0.1.0 && git push
   origin mobile-v0.1.0`.
9. CI: `mobile-android.yml` builds, signs the AAB with the upload key and
   sends it to the internal track with `mobile/store/whats-new.txt` as the
   release notes. A new app only takes draft releases until its first
   review, and the script falls back to a draft in that case.
10. Owner: if Play refuses the very first upload through the API, upload
    the signed AAB from the workflow's artifacts by hand once in Testing,
    Internal testing, Create new release. Later uploads go through CI.
    (check: whether the API takes a first bundle for a brand new app.)
11. Owner: Play App Signing is on by default for new apps. Accept it. The
    upload key's SHA-256 shown under App integrity should match the one the
    key script printed.
12. Owner: add internal testers (a Google Group or email list), roll out
    the draft, and install from the opt in link on a phone.

### Closed testing (14 days or more)

13. Owner: Testing, Closed testing, create a track. Add at least 12
    testers (a Google Group is easiest; more than 12 gives slack for people
    who drop out). Promote the internal build to it. Closed testing builds go
    through a review, usually a few days for the first one (check).
14. Owner: send testers the opt in link. Count the 14 days from when the
    12th tester opted in. Ask them to open the app on a few days, not just
    once; Google asks about tester engagement when you apply (check).
15. CI: each further `mobile-v*` tag lands on internal. Promote to closed
    testing in Play Console when a build is worth testing.

### Production

16. Owner: Dashboard, Apply for production. Answer the questions about the
    closed test (what testers found, what changed). Google takes up to about
    7 days to decide (check).
17. Owner: once approved, Production, Create new release from the latest
    closed testing build, choose countries, start the rollout (a staged
    percentage is fine).
18. Owner: review takes from hours to several days for a new app. Answer
    any policy email from the account's inbox; remote access apps sometimes
    get a question about Accessibility, and the answer is in
    `ratings-and-policy.md`.

## 2. App Store

The App Store Connect API key the owner already has carries the Developer
role. That is enough to upload builds and manage TestFlight builds, but not to
create the app record or the distribution certificate in the cloud, so those
are owner steps and CI signs with a certificate and profile from secrets.

### One time setup

1. Owner: Apple Developer Program membership active, and in App Store
   Connect, Business, the latest Apple Developer Program License Agreement
   accepted. A free app does not need the Paid Apps agreement.
2. Owner: developer.apple.com, Certificates, Identifiers and Profiles,
   Identifiers, +, App IDs, App. Bundle ID explicit:
   `com.psmux.deskvnc.mobile`, description DeskVNC Mobile. No extra
   capabilities are needed for version 1.
3. Owner: Certificates, +, Apple Distribution. Make the CSR on the Mac
   that will hold the key (Keychain Access, Certificate Assistant), download
   the certificate, then export certificate and key as a `.p12` with a
   password. If an Apple Distribution certificate already exists for this
   team, reuse it rather than making another (there is a limit per team).
4. Owner: Profiles, +, App Store Connect (distribution), pick the App ID
   and the certificate, name it "DeskVNC Mobile App Store", download the
   `.mobileprovision`. It expires with the certificate; renew both together.
5. Owner: App Store Connect, Apps, +, New App. Platform iOS, name DeskVNC,
   primary language English (U.S.), bundle ID from step 2, SKU
   `deskvnc-mobile`, full access. This needs the Account Holder, Admin or App
   Manager role, which is why the Developer API key cannot do it.
6. Owner: set the secrets:
   ```sh
   mobile/scripts/set-mobile-secrets.sh psmux/DeskVNC \
     --apple-p12 /path/to/distribution.p12 \
     --apple-profile /path/to/DeskVNC_Mobile_App_Store.mobileprovision \
     --apple-team-id <TEAMID> \
     --asc-key /path/to/AuthKey_<KEYID>.p8 \
     --asc-issuer-id <ISSUER>
   ```
   The script asks for the `.p12` password without echoing it.
7. Owner: App Information: subtitle, categories (Utilities, then
   Productivity), content rights, age rating (`ratings-and-policy.md`).
   App Privacy: Data Not Collected (`privacy-answers.md`), privacy policy URL.
   Pricing and Availability: free, all countries the owner wants.
8. Owner: EU Digital Services Act trader status, under Business. A
   trader's address, phone and email are shown on the EU store page. This is
   the owner's call (check what applies to a free app from an individual).

### TestFlight

9. Repo: tag `mobile-v0.1.0` (the same tag as Play, if both are ready).
10. CI: `mobile-ios.yml` builds and signs an IPA with the distribution
    certificate and profile, then uploads it with `xcrun altool` and the API
    key. The build number is the workflow run number.
11. Owner: wait for processing (minutes to an hour). If App Store Connect
    asks about encryption, the Info.plist key from step 0.3 is missing; answer
    from `review-notes.md`, Export compliance.
12. Owner: TestFlight, internal group with the owner's own Apple ID, and
    install on an iPhone and an iPad. Internal testing needs no review.
13. Owner (optional): an external TestFlight group. The first build goes
    through Beta App Review, which uses the same review notes.

### Review and release

14. Owner: on the 1.0 version page: screenshots for 6.9 inch iPhone and
    13 inch iPad, promotional text, description, keywords, support and
    marketing URLs, what's new (`listing-app-store.md`).
15. Owner: App Review Information: sign in not required; paste the notes
    from `review-notes.md`; contact email support@ripeflow.com, with the
    owner's name and phone (kept in App Store Connect only).
16. Owner: choose the build from TestFlight, choose manual release, Add for
    Review, Submit. Review usually takes a day or two (check).
17. Owner: if rejected, reply in Resolution Center. The usual causes for a
    remote desktop app are 2.1 (could not test, hence the demo computer) and
    metadata naming another phone platform (2.3.10).
18. Owner: release when approved.

## 3. After launch

* CI: every `mobile-v*` tag builds both apps, uploads to Play internal and
  to TestFlight. Promotion to closed testing, production or App Store review
  stays a human step.
* Repo: update `mobile/store/whats-new.txt` (Play) and the What's New
  field in `listing-app-store.md` (Apple) before tagging.
* Owner: the Apple distribution certificate and profile expire after a
  year. Renew both, then rerun `set-mobile-secrets.sh` with the new files.
* Owner: the Play upload key does not expire for 25 years. If it is lost,
  ask for an upload key reset in Play Console, App integrity.
* Repo: if the app ever adds analytics, crash reporting, accounts or
  cloud sync, redo the privacy answers on both stores before that build
  ships.
