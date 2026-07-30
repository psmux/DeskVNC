#!/usr/bin/env bash
# Build DeskVNCViewer.app and package it into a DMG.
#
# Tauri's built-in DMG bundler (create-dmg) drives Finder over AppleScript to
# lay out the disk-image window. That fails with "AppleEvent timed out (-1712)"
# in any non-interactive session (SSH, CI without a GUI session, or when
# Automation permission has not been granted to the terminal). This script
# builds the .app with Tauri and then makes the DMG with hdiutil, which needs
# no Finder. The result is cosmetically plainer and functionally identical.
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
ARCH=$(uname -m); [ "$ARCH" = "arm64" ] && ARCH=aarch64
OUT="target/release/bundle/dmg/DeskVNCViewer_${VERSION}_${ARCH}.dmg"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

APP="target/release/bundle/macos/DeskVNCViewer.app"

echo "==> Building app bundle"
# Tauri would ad-hoc sign the bundle; sign-macos.sh re-signs it below with a
# real identity, which is what makes keychain "Always Allow" and TCC grants
# survive rebuilds. Keep Tauri out of it so there is exactly one signing step.
env -u APPLE_SIGNING_IDENTITY cargo tauri build --bundles app

echo "==> Signing app bundle"
scripts/sign-macos.sh "$APP"

# Notarization is skipped when no credential profile exists, so local builds
# still work. Create one with:
#   xcrun notarytool store-credentials "deskvnc-notary" \
#       --apple-id <you> --team-id <TEAM>
NOTARY_PROFILE="${NOTARY_PROFILE:-deskvnc-notary}"
NOTARIZE=0
if xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
    NOTARIZE=1
else
    echo "==> No '$NOTARY_PROFILE' credential profile; skipping notarization."
    echo "    The DMG will be signed but Gatekeeper will reject it once"
    echo "    downloaded, because a quarantined app must be notarized."
fi

# The .app must be notarized and stapled BEFORE the DMG is built, otherwise
# the ticket lives only on the disk image: dragging the app to /Applications
# leaves it without one, and its first launch fails on a machine that is
# offline. Both layers get their own ticket here.
if [ "$NOTARIZE" = 1 ]; then
    echo "==> Notarizing app bundle"
    ditto -c -k --keepParent "$APP" "$STAGE/app.zip"
    xcrun notarytool submit "$STAGE/app.zip" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$APP"
    rm -f "$STAGE/app.zip"
fi

echo "==> Staging"
# cp -R carries the _CodeSignature directory across, so the DMG copy stays
# signed; verify rather than assume.
cp -R "$APP" "$STAGE/"
codesign --verify --strict "$STAGE/DeskVNCViewer.app"
ln -s /Applications "$STAGE/Applications"

echo "==> Creating $OUT"
mkdir -p "$(dirname "$OUT")"
hdiutil create -volname DeskVNCViewer -srcfolder "$STAGE" -ov -format UDZO "$OUT"

echo "==> Signing DMG"
scripts/sign-macos.sh "$OUT" >/dev/null

if [ "$NOTARIZE" = 1 ]; then
    echo "==> Notarizing DMG"
    xcrun notarytool submit "$OUT" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$OUT"

    echo "==> Verifying as a downloaded copy would be assessed"
    # spctl is lenient on files that were never quarantined, so assert against
    # the primary signature explicitly rather than trusting a bare `spctl -a`.
    spctl -a -vv -t open --context context:primary-signature "$OUT"
fi

echo "==> Done: $OUT"
