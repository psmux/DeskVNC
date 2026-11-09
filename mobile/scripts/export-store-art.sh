#!/usr/bin/env bash
# Export the store artwork in mobile/store/art to PNG.
#
#   mobile/scripts/export-store-art.sh
#
# feature-graphic.png  1024 x 500, 24 bit with no alpha, as Google Play wants
# promo-banner.png     1200 x 630, for link previews and announcements
#
# Text in the SVGs uses the system UI font, so render on a Mac for the look in
# the repository (rsvg-convert falls back to another sans font elsewhere).
set -euo pipefail
art=$(cd "$(dirname "$0")/../store/art" && pwd)
command -v rsvg-convert >/dev/null || { echo "rsvg-convert is missing (brew install librsvg)"; exit 1; }
if command -v magick >/dev/null; then IM=magick; else IM=convert; fi
mkdir -p "$art/out"
for name in feature-graphic promo-banner; do
  rsvg-convert "$art/$name.svg" -o "$art/out/$name.png"
  "$IM" "$art/out/$name.png" -background '#1447AD' -alpha remove -alpha off "PNG24:$art/out/$name.png"
  "$IM" identify -format "%f %wx%h %[channels]\n" "$art/out/$name.png"
done
