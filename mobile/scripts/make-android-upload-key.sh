#!/usr/bin/env bash
# Make the Android upload key for Google Play, once.
#
#   mobile/scripts/make-android-upload-key.sh [path/to/upload.jks] [alias]
#
# The default path is ~/.config/deskvnc-mobile/upload.jks, outside the repo.
# The script refuses to write inside a git work tree, so the key cannot be
# committed by accident.
#
# With Play App Signing, Google holds the key that signs what users install.
# This one only proves an upload came from us. If it is lost, the account
# owner can ask Google for a reset in Play Console, so it is not fatal, but
# back it up with its password anyway (a password manager is fine).
#
# keytool asks for the password twice and nothing is echoed. Afterwards the
# script prints the SHA-256 and SHA-1 fingerprints, which Play Console shows
# under App integrity so you can match them.
set -euo pipefail

path=${1:-$HOME/.config/deskvnc-mobile/upload.jks}
alias=${2:-upload}

command -v keytool >/dev/null || { echo "keytool not found. Install a JDK 17 (brew install openjdk@17)."; exit 1; }

dir=$(dirname "$path")
mkdir -p "$dir"
chmod 700 "$dir" 2>/dev/null || true

if git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Refusing: $dir is inside a git work tree. Pick a path outside any repo."
  exit 1
fi
if [ -e "$path" ]; then
  echo "Refusing: $path already exists. Move it away first if you really want a new key."
  exit 1
fi

# 25 years: Play asks for a validity that runs past 22 October 2033 (check).
keytool -genkeypair -v \
  -keystore "$path" -storetype PKCS12 \
  -alias "$alias" -keyalg RSA -keysize 4096 -validity 9125 \
  -dname "CN=DeskVNC upload key"

chmod 600 "$path"

echo
echo "Upload key written to $path (alias $alias)."
keytool -list -v -keystore "$path" -alias "$alias" </dev/tty \
  | grep -E '^\s*(SHA256|SHA1):' || echo "Run: keytool -list -v -keystore $path -alias $alias"
echo
echo "Next: mobile/scripts/set-mobile-secrets.sh OWNER/REPO --android-keystore $path --android-alias $alias"
