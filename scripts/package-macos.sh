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

# The agent binary the AI Agents modal tells people to run. Without it in the
# bundle, every instruction that modal prints names a program that is not on
# the machine, and `agent_status` has no path to answer with.
#
# Copied here rather than declared as tauri's `bundle.externalBin`, and the
# difference is only in who does the copy: `tauri-build` copies a sidecar
# during `cargo build` and FAILS the build when the file is not already
# there, so declaring it would break `cargo build --workspace`,
# `cargo test --workspace` and `cargo tauri dev` on a fresh checkout. The
# resulting bundle is identical either way: `Contents/MacOS/dvv`, beside the
# main executable, signed with it and removed with it.
echo "==> Building the dvv agent binary"
cargo build --release -p dvv
cp target/release/dvv "$APP/Contents/MacOS/dvv"

# Inside out, which is the order codesign requires: a nested Mach-O carries its
# own signature and the bundle then seals it. Signing the bundle first would
# leave dvv unsigned inside a sealed bundle, and notarization rejects that.
echo "==> Signing the dvv agent binary"
scripts/sign-macos.sh "$APP/Contents/MacOS/dvv"

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

# The agent binary, asserted rather than hoped for. Every line the AI Agents
# modal prints names this path, and `agent_status` reads it to fill them in, so
# a DMG that shipped without it would hand people instructions pointing at a
# program that is not there. Running it is the check: a file that exists but
# will not execute fails the same way from a user's point of view.
"$STAGE/DeskVNCViewer.app/Contents/MacOS/dvv" version >/dev/null
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
