#!/usr/bin/env bash
# Build, sign, notarize and staple the DeskVNC Support recipient app.
#
# This app is downloaded by the person receiving help, which means it always
# arrives quarantined from a browser. A quarantined bundle that is only ad-hoc
# signed is refused outright by Gatekeeper, so signing and notarization are the
# difference between a working download and one nobody can open.
#
#   scripts/build-boundary-macos.sh
#
# Credentials are resolved in this order, and each layer degrades on its own:
#   signing       APPLE_SIGNING_IDENTITY, else any identity in the keychain,
#                 else an ad-hoc signature that runs on this Mac only
#   notarization  APPLE_ID + APPLE_PASSWORD + APPLE_TEAM_ID (CI), else the
#                 NOTARY_PROFILE keychain profile (local), else skipped
#
# Set BOUNDARY_REQUIRE_SIGNING=1 to turn the degraded paths into failures, which
# is what a release build does rather than shipping something unopenable.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/macos-identity.sh
. scripts/macos-identity.sh

profile="${BOUNDARY_PROFILE:-release}"
case "$profile" in
  release) cargo_profile_flags=(--release) ;;
  debug) cargo_profile_flags=() ;;
  *) echo 'BOUNDARY_PROFILE must be release or debug' >&2; exit 1 ;;
esac

require="${BOUNDARY_REQUIRE_SIGNING:-0}"
version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
bundle="dist/DeskVNC Support.app"

fail_or_warn() {
    if [ "$require" = 1 ]; then
        echo "::error::$1" >&2
        exit 1
    fi
    echo "WARNING: $1" >&2
}

# The viewer ships as a universal binary, so an Intel Mac that can run the
# viewer must not be handed a support app it cannot launch. Build both slices
# when both targets are installed and lipo them; fall back to a host-only build
# so a plain `cargo build` checkout still works.
targets=()
for candidate in aarch64-apple-darwin x86_64-apple-darwin; do
    if rustup target list --installed 2>/dev/null | grep -qx "$candidate"; then
        targets+=("$candidate")
    fi
done

slices=()
if [ "${#targets[@]}" -gt 0 ]; then
    for target in "${targets[@]}"; do
        echo "==> Building boundary for $target"
        cargo build --locked ${cargo_profile_flags[@]+"${cargo_profile_flags[@]}"} \
            -p boundary --target "$target"
        slices+=("target/$target/$profile/boundary")
    done
else
    echo "==> Building boundary for the host architecture"
    cargo build --locked ${cargo_profile_flags[@]+"${cargo_profile_flags[@]}"} -p boundary
    slices+=("target/$profile/boundary")
fi

rm -rf "$bundle"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"

if [ "${#slices[@]}" -gt 1 ]; then
    echo "==> Creating a universal binary from ${#slices[@]} slices"
    lipo -create -output "$bundle/Contents/MacOS/boundary" "${slices[@]}"
else
    fail_or_warn "only one architecture was built; this app will not run on Intel Macs"
    cp "${slices[0]}" "$bundle/Contents/MacOS/boundary"
fi

cat > "$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.psmux.deskvnc.support</string>
<key>CFBundleName</key><string>DeskVNC Support</string>
<key>CFBundleDisplayName</key><string>DeskVNC Support</string>
<key>CFBundleExecutable</key><string>boundary</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>${version}</string>
<key>CFBundleVersion</key><string>${version}</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSLocalNetworkUsageDescription</key><string>Boundary connects to the person you invite for remote support.</string>
<key>NSScreenCaptureUsageDescription</key><string>DeskVNC Support shares your screen after you approve a support session.</string>
<key>NSAccessibilityUsageDescription</key><string>DeskVNC Support sends keyboard and mouse input only after you approve control.</string>
</dict></plist>
PLIST

# sign-macos.sh applies hardened runtime, a secure timestamp and the network
# entitlements whenever the identity is one Apple issued. Notarization rejects a
# bundle without hardened runtime, so this step is what makes the next one
# possible.
if identity=$(resolve_signing_identity); then
    echo "==> Signing with: $identity"
    scripts/sign-macos.sh "$bundle"
    if ! is_apple_identity "$identity"; then
        fail_or_warn "signed with '$identity', which other Macs will not accept"
    fi
else
    fail_or_warn "no signing identity found; falling back to an ad-hoc signature"
    codesign --force --sign - "$bundle"
    codesign --verify --strict "$bundle"
fi

NOTARY_PROFILE="${NOTARY_PROFILE:-deskvnc-notary}"
notary_auth=()
if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_PASSWORD:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ]; then
    notary_auth=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID")
elif xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
    notary_auth=(--keychain-profile "$NOTARY_PROFILE")
fi

if [ "${#notary_auth[@]}" -gt 0 ]; then
    stage=$(mktemp -d)
    trap 'rm -rf "$stage"' EXIT
    echo "==> Notarizing $bundle"
    # Apple takes a zip for submission but the ticket is stapled to the .app,
    # so the zip that ships has to be made after this, not before.
    ditto -c -k --sequesterRsrc --keepParent "$bundle" "$stage/submit.zip"
    xcrun notarytool submit "$stage/submit.zip" "${notary_auth[@]}" --wait
    xcrun stapler staple "$bundle"

    echo "==> Verifying as a quarantined download would be assessed"
    xcrun stapler validate "$bundle"
    spctl -a -vv -t exec "$bundle"
else
    fail_or_warn "no notarization credentials; Gatekeeper will refuse this once downloaded"
fi

echo "Built $bundle ($version)"
