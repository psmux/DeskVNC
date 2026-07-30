# macOS code signing, keychain prompts, and permission grants

## The problem

An unsigned DeskVNCViewer build re-asks for keychain access on every launch,
and clicking **Always Allow** does not help. The same happens to the Local
Network and Accessibility permissions.

This is not a bug in `crates/vnc-store/src/creds.rs`. It is a consequence of
how macOS identifies applications.

When you click Always Allow, macOS appends a *trusted application* entry to
the keychain item's ACL. That entry stores the app's **designated
requirement**, a rule describing which code is allowed in. For a build with
no signing certificate, the linker applies an ad-hoc signature, and the
designated requirement degrades to a pin on the binary's own hash:

```
$ codesign -d -r- target/release/bundle/macos/DeskVNCViewer.app
# designated => cdhash H"7d9582c92f2afed265a09bed01f79147a455353f"
```

Every rebuild relinks the binary, which changes the hash, which makes the ACL
entry match nothing. The grant was recorded, it just points at a binary that
no longer exists. TCC (Local Network, Accessibility, Screen Recording) keys off
the same requirement, so those grants reset for the same reason.

Signing with a real certificate replaces the hash pin with a rule that holds
across rebuilds:

```
# designated => identifier "com.deskvncviewer.desktop" and certificate leaf = H"da51d1b2…"
```

Neither the bundle identifier nor the certificate changes when you rebuild, so
the ACL entry keeps matching and the prompt is answered once, permanently.

## Local development (this Mac only)

```sh
scripts/macos-codesign-setup.sh     # one time
scripts/macos-reset-credentials.sh  # drop entries with unrepairable ACLs
scripts/package-macos.sh            # build + sign + DMG
```

`macos-codesign-setup.sh` creates a self-signed code-signing certificate
(`DeskVNCViewer Local Dev`) in your login keychain and writes
`.cargo/config.toml`, which routes macOS links through
`scripts/codesign-linker.sh`. That shim re-signs the app binary after every
relink, so `cargo tauri dev` builds carry the same identity as the bundled app
and share its keychain ACL entries.

Two things worth knowing:

- The certificate is deliberately **not** installed as a trusted root. codesign
  signs with an untrusted self-signed certificate without complaint, and the
  ACL rule above is a literal hash comparison that never consults trust
  settings. Trust only governs Gatekeeper, which does not evaluate locally
  built apps. Consequently `security find-identity -v -p codesigning` will not
  list it, use `security find-identity -p codesigning` (no `-v`). Pass
  `--trust` to the setup script if you want it listed anyway.
- If you skip the optional keychain-password step, codesign will prompt once
  for access to the private key. Approve it with Always Allow; that grant does
  persist, because `/usr/bin/codesign` is Apple-signed and has a stable
  designated requirement.

**This certificate is valid on this machine only.** A build signed with it will
not launch on anyone else's Mac.

## Distribution to other Macs

You need a **Developer ID Application** certificate, which requires a paid
Apple Developer Program membership. Create it at
developer.apple.com → Certificates, Identifiers & Profiles → Certificates → **+**,
choosing **Developer ID Application** and the **G2 Sub-CA** profile type, the
portal preselects "Previous Sub-CA", whose certificates expire 2027-02-01.

Generate the signing request on the machine that will hold the key:

```sh
openssl req -new -newkey rsa:2048 -nodes \
    -keyout devid.key -out devid.certSigningRequest \
    -subj "/emailAddress=<you>/CN=<Your Name>/C=<CC>"
```

Upload the `.certSigningRequest`, download the issued `.cer`, then pair it back
with the key and install both it and Apple's intermediate:

```sh
openssl x509 -inform DER -in developerID_application.cer -out devid.pem
openssl pkcs12 -export -inkey devid.key -in devid.pem -out devid.p12
security import devid.p12 -k ~/Library/Keychains/login.keychain-db \
    -T /usr/bin/codesign -T /usr/bin/security
curl -O https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
security import DeveloperIDG2CA.cer -k ~/Library/Keychains/login.keychain-db
```

Without that last intermediate the identity imports but reports
`CSSMERR_TP_NOT_TRUSTED` and `codesign` refuses to use it. Confirm with
`security find-identity -v -p codesigning`, then build normally, the scripts
prefer a Developer ID over the local self-signed identity automatically:

```sh
scripts/package-macos.sh
```

**Back up `devid.p12` and its password off the machine.** Apple cannot re-issue
a private key, and an account is limited to five Developer ID Application
certificates. Moving to a new Mac means exporting the existing identity
(Keychain Access → right-click → Export), not minting another certificate.

`sign-macos.sh` automatically switches on hardened runtime, a secure
timestamp, and `src-tauri/entitlements.plist` when the identity is Apple-issued,
because notarization requires all three. Override the choice with
`APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"`.

Signing alone is not enough for other people's Macs. A DMG they download gets
a quarantine attribute, and since macOS 10.15 Gatekeeper rejects quarantined
software that is not **notarized**.

`package-macos.sh` notarizes automatically when a credential profile exists,
and skips it (with a warning) when one does not, so local builds still work.
Create the profile once, in a terminal, it prompts for the password with
hidden input and stores it in the keychain, so the secret never appears in
shell history or process arguments:

```sh
xcrun notarytool store-credentials "deskvnc-notary" \
    --apple-id <your-apple-id> --team-id <TEAMID>
```

The password it asks for is an **app-specific password** from
account.apple.com → Sign-In & Security → App-Specific Passwords, not your
Apple ID password. Override the profile name with `NOTARY_PROFILE=...`.

Order matters, and the script enforces it: the `.app` is notarized and
stapled *before* the DMG is built. Staple only the DMG and the ticket lives on
the disk image alone, dragging the app to /Applications leaves it with no
ticket of its own, and its first launch fails on a machine that is offline.
Both layers need their own ticket.

Verify the way a download is actually assessed. A plain `spctl -a` on a file
that was never quarantined is lenient and will pass even unnotarized builds:

```sh
cp DeskVNCViewer_0.1.0_aarch64.dmg /tmp/t.dmg
xattr -w com.apple.quarantine "0083;0;Safari;" /tmp/t.dmg
spctl -a -vv -t open --context context:primary-signature /tmp/t.dmg
# want: source=Notarized Developer ID
```

With a Developer ID the requirement is team-anchored:

```
# designated => identifier "com.deskvncviewer.desktop" and anchor apple generic
#               and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */
#               and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */
#               and certificate leaf[subject.OU] = <TEAMID>
```

It pins the *team*, not the certificate, so it survives rebuilds, version
upgrades, and certificate renewal. A user who clicks Always Allow once is
never asked again, including across app updates.

## Verifying

```sh
codesign -d -r- /Applications/DeskVNCViewer.app     # must NOT say cdhash
codesign --verify --strict /Applications/DeskVNCViewer.app
```

`sign-macos.sh` performs this check itself and fails if the requirement is
still a cdhash pin.

## Opting out

Delete `.cargo/config.toml`, or set `DESKVNC_CODESIGN=0` in the environment to
make the linker shim a pass-through.
