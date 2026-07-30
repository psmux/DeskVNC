#!/usr/bin/env bash
# Sign a DeskVNCViewer .app bundle or bare binary with a stable code identity.
#
#   scripts/sign-macos.sh target/release/bundle/macos/DeskVNCViewer.app
#   scripts/sign-macos.sh target/debug/deskvncviewer
#
# Why this exists: an unsigned (linker ad-hoc) build has a designated
# requirement of `cdhash H"..."` -- a pin on the exact bytes of the binary.
# macOS keychain ACLs and TCC grants key off that requirement, so every
# rebuild invalidates every "Always Allow" and every permission grant. Signing
# with a real certificate replaces the cdhash pin with
#
#   identifier "com.deskvncviewer.desktop" and certificate leaf = H"<cert>"
#
# which survives rebuilds, so the keychain prompt is answered once and stays
# answered.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/macos-identity.sh
. scripts/macos-identity.sh

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "usage: $0 <path-to-.app-or-binary>" >&2
    exit 2
fi
if [ ! -e "$TARGET" ]; then
    echo "error: no such path: $TARGET" >&2
    exit 1
fi

if ! IDENTITY=$(resolve_signing_identity); then
    cat >&2 <<'EOF'
error: no code-signing identity found.

  * For this Mac only:  scripts/macos-codesign-setup.sh
  * For distribution:   install a "Developer ID Application" certificate from
                        your Apple Developer account, or set
                        APPLE_SIGNING_IDENTITY to its exact name.
EOF
    exit 1
fi

OPTS=(--force --sign "$IDENTITY")
if is_apple_identity "$IDENTITY"; then
    # Hardened runtime is mandatory for notarization, and a secure timestamp
    # keeps the signature valid after the certificate expires. Neither is
    # available to a self-signed certificate.
    OPTS+=(--options runtime --timestamp --entitlements src-tauri/entitlements.plist)
else
    OPTS+=(--timestamp=none)
fi

echo "==> Identity: $IDENTITY"

if [ -d "$TARGET" ]; then
    # Bundle: sign nested Mach-O code inside-out, then the bundle itself.
    # (--deep is deprecated by Apple and skips some nested code.)
    while IFS= read -r inner; do
        echo "==> Signing nested $inner"
        codesign "${OPTS[@]}" "$inner"
    done < <(find "$TARGET/Contents" \( -name '*.dylib' -o -name '*.so' -o -name '*.framework' \) -print 2>/dev/null)
    echo "==> Signing $TARGET"
    # The identifier comes from CFBundleIdentifier in Info.plist, which is
    # already the stable com.deskvncviewer.desktop.
    codesign "${OPTS[@]}" "$TARGET"
else
    echo "==> Signing $TARGET"
    # A bare binary has no Info.plist, so codesign would derive the identifier
    # from the filename. Force the bundle id instead, so a `cargo tauri dev`
    # build presents the same identity as the installed .app and shares its
    # keychain ACL entries.
    codesign "${OPTS[@]}" --identifier "$BUNDLE_ID" "$TARGET"
fi

echo
echo "==> Designated requirement (this is what the keychain ACL pins to):"
# codesign prints an explicit embedded requirement plainly, but comments out
# one it had to synthesise ("# designated => cdhash ..."), and splits its
# report across stdout and stderr. Accept both forms from both streams.
REQ=$(codesign -d -r- "$TARGET" 2>&1 | sed -n 's/^#* *designated => //p')
echo "    ${REQ:-<none>}"

if [ -z "$REQ" ] || [ "${REQ#*cdhash}" != "$REQ" ]; then
    echo
    echo "WARNING: the requirement is still a cdhash pin -- it will break on the" >&2
    echo "         next rebuild and keychain prompts will come back." >&2
    exit 1
fi

echo
echo "==> Stable across rebuilds. Signing complete."
