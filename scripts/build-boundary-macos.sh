#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
profile="${BOUNDARY_PROFILE:-release}"
case "$profile" in
  release) cargo build --locked --release -p boundary ;;
  debug) cargo build --locked -p boundary ;;
  *) echo 'BOUNDARY_PROFILE must be release or debug' >&2; exit 1 ;;
esac
bundle="dist/DeskVNC Support.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp "target/$profile/boundary" "$bundle/Contents/MacOS/boundary"
cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.psmux.deskvnc.support</string>
<key>CFBundleName</key><string>DeskVNC Support</string>
<key>CFBundleDisplayName</key><string>DeskVNC Support</string>
<key>CFBundleExecutable</key><string>boundary</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSLocalNetworkUsageDescription</key><string>Boundary connects to the person you invite for remote support.</string>
<key>NSScreenCaptureUsageDescription</key><string>DeskVNC Support shares your screen after you approve a support session.</string>
<key>NSAccessibilityUsageDescription</key><string>DeskVNC Support sends keyboard and mouse input only after you approve control.</string>
</dict></plist>
PLIST
codesign --force --sign "${BOUNDARY_SIGN_IDENTITY:--}" "$bundle"
codesign --verify --strict "$bundle"
echo "Built $bundle"
