#!/usr/bin/env bash
# Publish the macOS signing material to GitHub Actions secrets, so the release
# workflow can produce a signed and notarized build.
#
# Run this yourself. Every password is typed into your own terminal or a macOS
# dialog and piped straight into `gh secret set`; nothing is echoed, written to
# disk unencrypted, or kept in shell history.
#
# What it sets:
#   APPLE_CERTIFICATE           base64 of a .p12 holding the Developer ID
#                               certificate and its private key
#   APPLE_CERTIFICATE_PASSWORD  the password protecting that .p12
#   APPLE_ID                    Apple account used for notarization
#   APPLE_PASSWORD              an app-specific password, NOT the Apple ID one
#   APPLE_TEAM_ID               the 10-character team identifier
#
# Read SECURITY.md "Release signing" for the trust model before running this.
set -euo pipefail

cd "$(dirname "$0")/.."

REPO="${REPO:-psmux/DeskVNC}"
IDENTITY="${IDENTITY:-Developer ID Application: Godwin Josh (LCYYV8JHN6)}"
TEAM_ID="${TEAM_ID:-LCYYV8JHN6}"

command -v gh >/dev/null || { echo "error: gh CLI not found" >&2; exit 1; }

echo "==> Target repository: $REPO"
echo "    Signing identity:  $IDENTITY"
echo
echo "    You must be authenticated as an account with admin rights on that"
echo "    repository. Current: $(gh api user --jq .login 2>/dev/null || echo unknown)"
echo

if ! security find-identity -v -p codesigning | grep -qF "$IDENTITY"; then
    echo "error: signing identity not found in the login keychain:" >&2
    echo "       $IDENTITY" >&2
    echo "       See docs/MACOS_SIGNING.md to create or import it." >&2
    exit 1
fi

STAGE=$(mktemp -d)
chmod 700 "$STAGE"
# Shred the exported key even if this exits early.
trap 'rm -f "$STAGE"/devid.p12 "$STAGE"/devid.b64 2>/dev/null; rmdir "$STAGE" 2>/dev/null || true' EXIT

echo "==> Exporting the Developer ID identity"
echo "    macOS will ask you to choose a password for the exported file, and"
echo "    may ask for your login keychain password to release the private key."
echo "    Pick something you can retype in a moment; you will need it twice."
echo
security export -k ~/Library/Keychains/login.keychain-db \
    -t identities -f pkcs12 -o "$STAGE/devid.p12"

if [ ! -s "$STAGE/devid.p12" ]; then
    echo "error: export produced no file" >&2
    exit 1
fi
echo "    Exported $(wc -c < "$STAGE/devid.p12" | tr -d ' ') bytes."

# `security export` writes every identity in the keychain. That is fine here
# (the local dev certificate is harmless), but say so rather than surprise
# anyone reading the secret later.
echo
echo "==> Identities contained in that export:"
security find-identity -v -p codesigning | sed -n 's/.*) [0-9A-F]* "\([^"]*\)".*/      \1/p'

base64 < "$STAGE/devid.p12" > "$STAGE/devid.b64"
echo
echo "==> Uploading APPLE_CERTIFICATE ($(wc -c < "$STAGE/devid.b64" | tr -d ' ') base64 chars)"
gh secret set APPLE_CERTIFICATE --repo "$REPO" < "$STAGE/devid.b64"

echo
echo "==> Now retype the SAME password you just chose for the export."
printf '    .p12 password: '
read -rs P12PW; echo
[ -n "$P12PW" ] || { echo "error: empty password" >&2; exit 1; }
printf '%s' "$P12PW" | gh secret set APPLE_CERTIFICATE_PASSWORD --repo "$REPO"
unset P12PW
echo "    APPLE_CERTIFICATE_PASSWORD set."

echo
echo "==> Notarization credentials."
printf '    Apple ID email: '
read -r APPLE_ID_VALUE
[ -n "$APPLE_ID_VALUE" ] || { echo "error: empty Apple ID" >&2; exit 1; }
printf '%s' "$APPLE_ID_VALUE" | gh secret set APPLE_ID --repo "$REPO"

echo
echo "    App-specific password from account.apple.com ->"
echo "    Sign-In & Security -> App-Specific Passwords."
echo "    This is NOT your Apple ID password."
printf '    App-specific password: '
read -rs ASP; echo
[ -n "$ASP" ] || { echo "error: empty app-specific password" >&2; exit 1; }
printf '%s' "$ASP" | gh secret set APPLE_PASSWORD --repo "$REPO"
unset ASP

printf '%s' "$TEAM_ID" | gh secret set APPLE_TEAM_ID --repo "$REPO"
printf '%s' "$IDENTITY" | gh secret set APPLE_SIGNING_IDENTITY --repo "$REPO"

echo
echo "==> Secrets now present on $REPO:"
gh secret list --repo "$REPO" | sed 's/^/      /'

cat <<'EOF'

Done. The exported .p12 and its base64 have been deleted from the temporary
directory.

Next: push a version tag to build a signed release.

    git tag v0.1.0 && git push origin v0.1.0

Rotating or revoking later:
    gh secret delete APPLE_CERTIFICATE --repo <repo>     (and the others)
    Revoke the certificate at developer.apple.com, and the app-specific
    password at account.apple.com. Revoking the app-specific password is
    instant and costs nothing, so do that first if you suspect exposure.
EOF
