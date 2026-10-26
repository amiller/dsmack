#!/bin/bash
# Unsigned, reproducible build of build/DsmackRunner.app. Usage: build.sh <dir containing libdsmack_hvf_returning.a>
# Set PROFILE to embed a provisioning profile.
set -euo pipefail
cd "$(dirname "$0")"
archive_dir="$(cd "${1:?archive dir}" && pwd)"
app="$PWD/build/DsmackRunner.app"
# -Xlinker -S drops the debug map, which records build-directory object paths.
(cd ../app-src && DSMACK_V3_ARCHIVE_DIR="$archive_dir" swift build -c release --product mar \
  -Xlinker -S)
mkdir -p "$app/Contents/MacOS"
cp ../app-src/.build/release/mar "$app/Contents/MacOS/dsmack-runner"
if [ -n "${PROFILE:-}" ]; then cp "$PROFILE" "$app/Contents/embedded.provisionprofile"; fi
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.dsmack.provider</string>
<key>CFBundleExecutable</key><string>dsmack-runner</string>
<key>CFBundleName</key><string>DsmackRunner</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
echo "$app"
