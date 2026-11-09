#!/usr/bin/env bash
# Render every phone and tablet icon from the SVG masters in this folder.
#
#   mobile/icons/build-icons.sh                 render into mobile/icons/out
#   mobile/icons/build-icons.sh --install       render, then copy into
#                                               mobile/src-tauri/gen (iOS and
#                                               Android projects) if they exist
#   mobile/icons/build-icons.sh --tauri         render master-1024.png, then
#                                               let `tauri icon` make its own set
#
# Needs rsvg-convert (brew install librsvg, apt install librsvg2-bin) and
# ImageMagick 7 (`magick`) or 6 (`convert`) to drop the alpha channel.
#
# Sources:
#   master.svg      full bleed square, iOS icons, Play 512, legacy Android
#   foreground.svg  Android adaptive foreground (glyph in the 66 dp safe zone)
#   background.svg  Android adaptive background
#   monochrome.svg  Android 13 themed icon
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
mobile=$(cd "$here/.." && pwd)
out="$here/out"
mode=${1:-}

command -v rsvg-convert >/dev/null || { echo "rsvg-convert is missing (brew install librsvg)"; exit 1; }
if command -v magick >/dev/null; then IM=magick; elif command -v convert >/dev/null; then IM=convert; else
  echo "ImageMagick is missing (brew install imagemagick)"; exit 1; fi

# Render an SVG to a square PNG of side $3. Opaque icons get their alpha
# channel removed, which App Store Connect insists on for the 1024 icon.
render() { # svg out size [opaque]
  rsvg-convert -w "$3" -h "$3" "$here/$1" -o "$2"
  if [ "${4:-}" = opaque ]; then
    "$IM" "$2" -background '#1447AD' -alpha remove -alpha off "$2"
  fi
}

rm -rf "$out"
mkdir -p "$out/ios/AppIcon.appiconset" "$out/android" "$out/store"

# iOS. name:size pairs; Contents.json below lists the same files.
ios_set="
20:20 20@2x:40 20@3x:60
29:29 29@2x:58 29@3x:87
40:40 40@2x:80 40@3x:120
60@2x:120 60@3x:180
76:76 76@2x:152
83.5@2x:167
1024:1024
"
for pair in $ios_set; do
  name=${pair%%:*}; size=${pair##*:}
  render master.svg "$out/ios/AppIcon.appiconset/AppIcon-$name.png" "$size" opaque
done

cat > "$out/ios/AppIcon.appiconset/Contents.json" <<'JSON'
{
  "images" : [
    { "idiom" : "iphone", "size" : "20x20", "scale" : "2x", "filename" : "AppIcon-20@2x.png" },
    { "idiom" : "iphone", "size" : "20x20", "scale" : "3x", "filename" : "AppIcon-20@3x.png" },
    { "idiom" : "iphone", "size" : "29x29", "scale" : "2x", "filename" : "AppIcon-29@2x.png" },
    { "idiom" : "iphone", "size" : "29x29", "scale" : "3x", "filename" : "AppIcon-29@3x.png" },
    { "idiom" : "iphone", "size" : "40x40", "scale" : "2x", "filename" : "AppIcon-40@2x.png" },
    { "idiom" : "iphone", "size" : "40x40", "scale" : "3x", "filename" : "AppIcon-40@3x.png" },
    { "idiom" : "iphone", "size" : "60x60", "scale" : "2x", "filename" : "AppIcon-60@2x.png" },
    { "idiom" : "iphone", "size" : "60x60", "scale" : "3x", "filename" : "AppIcon-60@3x.png" },
    { "idiom" : "ipad", "size" : "20x20", "scale" : "1x", "filename" : "AppIcon-20.png" },
    { "idiom" : "ipad", "size" : "20x20", "scale" : "2x", "filename" : "AppIcon-20@2x.png" },
    { "idiom" : "ipad", "size" : "29x29", "scale" : "1x", "filename" : "AppIcon-29.png" },
    { "idiom" : "ipad", "size" : "29x29", "scale" : "2x", "filename" : "AppIcon-29@2x.png" },
    { "idiom" : "ipad", "size" : "40x40", "scale" : "1x", "filename" : "AppIcon-40.png" },
    { "idiom" : "ipad", "size" : "40x40", "scale" : "2x", "filename" : "AppIcon-40@2x.png" },
    { "idiom" : "ipad", "size" : "76x76", "scale" : "1x", "filename" : "AppIcon-76.png" },
    { "idiom" : "ipad", "size" : "76x76", "scale" : "2x", "filename" : "AppIcon-76@2x.png" },
    { "idiom" : "ipad", "size" : "83.5x83.5", "scale" : "2x", "filename" : "AppIcon-83.5@2x.png" },
    { "idiom" : "ios-marketing", "size" : "1024x1024", "scale" : "1x", "filename" : "AppIcon-1024.png" }
  ],
  "info" : { "version" : 1, "author" : "xcode" }
}
JSON

# Android. Legacy launcher icons are 48 dp, adaptive layers 108 dp.
for d in mdpi:1 hdpi:1.5 xhdpi:2 xxhdpi:3 xxxhdpi:4; do
  name=${d%%:*}; scale=${d##*:}
  legacy=$(awk "BEGIN{print int(48*$scale)}")
  layer=$(awk "BEGIN{print int(108*$scale)}")
  dir="$out/android/mipmap-$name"
  mkdir -p "$dir"
  render master.svg "$dir/ic_launcher.png" "$legacy" opaque
  # The round legacy icon: the same art cut to a circle.
  rsvg-convert -w "$legacy" -h "$legacy" "$here/master.svg" -o "$dir/round-src.png"
  "$IM" "$dir/round-src.png" \
    \( -size "${legacy}x${legacy}" xc:none -fill white -draw "circle $((legacy/2)),$((legacy/2)) $((legacy/2)),0" \) \
    -compose CopyOpacity -composite "$dir/ic_launcher_round.png"
  rm "$dir/round-src.png"
  render foreground.svg "$dir/ic_launcher_foreground.png" "$layer"
  render background.svg "$dir/ic_launcher_background.png" "$layer" opaque
  render monochrome.svg "$dir/ic_launcher_monochrome.png" "$layer"
done

mkdir -p "$out/android/mipmap-anydpi-v26"
for f in ic_launcher ic_launcher_round; do
  cat > "$out/android/mipmap-anydpi-v26/$f.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@mipmap/ic_launcher_background" />
    <foreground android:drawable="@mipmap/ic_launcher_foreground" />
    <monochrome android:drawable="@mipmap/ic_launcher_monochrome" />
</adaptive-icon>
XML
done

# Store icons: Play wants 512 x 512 as a 32 bit PNG (alpha channel kept, every
# pixel opaque); App Store takes the 1024
# from the asset catalogue. Both kept here so they can be uploaded by hand.
render master.svg "$out/store/play-icon-512.png" 512
render master.svg "$out/store/master-1024.png" 1024 opaque

echo "Icons written to $out"

case "$mode" in
  --install)
    gen="$mobile/src-tauri/gen"
    ios_set_dir="$gen/apple/Assets.xcassets/AppIcon.appiconset"
    res="$gen/android/app/src/main/res"
    if [ -d "$gen/apple/Assets.xcassets" ]; then
      rm -rf "$ios_set_dir"
      cp -R "$out/ios/AppIcon.appiconset" "$ios_set_dir"
      echo "Installed the iOS icon set in $ios_set_dir"
    else
      echo "No iOS project at $gen/apple yet (run tauri ios init first), skipped."
    fi
    if [ -d "$res" ]; then
      for dir in "$out"/android/mipmap-*; do
        mkdir -p "$res/$(basename "$dir")"
        cp "$dir"/* "$res/$(basename "$dir")/"
      done
      echo "Installed the Android icons in $res"
    else
      echo "No Android project at $res yet (run tauri android init first), skipped."
    fi
    ;;
  --tauri)
    # tauri icon makes its own names and sizes from one 1024 PNG, writing into
    # mobile/src-tauri/icons and into the gen projects when they exist.
    (cd "$mobile/src-tauri" && cargo tauri icon "$out/store/master-1024.png")
    ;;
  "") ;;
  *) echo "Unknown option $mode"; exit 2 ;;
esac
